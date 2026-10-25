-- New domain only. Historical IAM, workflow and approval facts are retained.
ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_kind_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata','workflow-policy-metadata','iam-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_kind_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata','workflow-policy-metadata','iam-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries','configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs','toolbox_operations','workspace_migration_plans','governance_metadata_requests','workflow_policy_requests','entity_change_intents','iam_metadata_requests'));

CREATE TABLE iam_change_intents (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 authoring_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,workflow_id uuid NOT NULL UNIQUE,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),material_secret text NOT NULL CHECK(m6_encrypted(material_secret)),
 credential_epoch bigint NOT NULL CHECK(credential_epoch>0),permission_version text NOT NULL CHECK(length(permission_version) BETWEEN 1 AND 256),
 issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '24 hours'),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(actor_id,idempotency_key),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT
);
CREATE TABLE iam_metadata_requests (
 id uuid PRIMARY KEY REFERENCES iam_change_intents(id) ON DELETE RESTRICT,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,workflow_id uuid NOT NULL UNIQUE,idempotency_key text NOT NULL,
 request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(actor_id,idempotency_key),
 FOREIGN KEY(cluster_id,workspace_id,id) REFERENCES iam_change_intents(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE iam_workflow_mutation_facts (
 operation_id uuid PRIMARY KEY REFERENCES iam_operations(id) ON DELETE RESTRICT,intent_id uuid NOT NULL UNIQUE REFERENCES iam_metadata_requests(id) ON DELETE RESTRICT,
 workflow_id uuid NOT NULL,execution_id uuid NOT NULL UNIQUE REFERENCES workflow_executions(id) ON DELETE RESTRICT,step_id uuid NOT NULL UNIQUE REFERENCES workflow_steps(id) ON DELETE RESTRICT,
 workflow_cluster_id uuid NOT NULL,workflow_workspace_id uuid NOT NULL,cluster_id uuid,workspace_id uuid,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,plan_revision integer NOT NULL CHECK(plan_revision>0),plan_hash text NOT NULL CHECK(m8_hex64(plan_hash)),
 before_permission_version text NOT NULL,after_permission_version text NOT NULL,before_iam_epoch bigint NOT NULL CHECK(before_iam_epoch>0),after_iam_epoch bigint NOT NULL CHECK(after_iam_epoch>=before_iam_epoch),
 result_hmac text NOT NULL CHECK(m8_hex64(result_hmac)),created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(workflow_cluster_id,workflow_workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(workflow_cluster_id,workflow_workspace_id,intent_id) REFERENCES iam_metadata_requests(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL)
);
CREATE FUNCTION m11_validate_iam_intent_author() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s auth_sessions%ROWTYPE;u users%ROWTYPE;epoch bigint;
BEGIN
 SELECT * INTO s FROM auth_sessions WHERE id=NEW.authoring_session_id;
 SELECT * INTO u FROM users WHERE id=NEW.actor_id;SELECT version INTO epoch FROM iam_epoch WHERE singleton=true;
 IF s.id IS NULL OR u.id IS NULL OR epoch IS NULL OR s.user_id<>NEW.actor_id OR s.revoked_at IS NOT NULL OR s.expires_at<=now()
  OR s.credential_epoch<>u.credential_epoch OR NEW.credential_epoch<>u.credential_epoch OR u.status<>'active' OR u.deleted_at IS NOT NULL OR u.force_password_change
  OR NEW.expires_at>s.expires_at OR NEW.permission_version IS DISTINCT FROM (u.id::text||':'||u.permissions_epoch::text||':'||epoch::text)
 THEN RAISE EXCEPTION 'IAM intention requires its real current original author session and epochs' USING ERRCODE='23514';END IF;RETURN NEW;
END;$$;
CREATE TRIGGER iam_intent_original_author BEFORE INSERT ON iam_change_intents FOR EACH ROW EXECUTE FUNCTION m11_validate_iam_intent_author();
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['iam_change_intents','iam_metadata_requests','iam_workflow_mutation_facts'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
  EXECUTE format('REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON %I FROM PUBLIC',tab);
 END LOOP;
END;$$;

-- Delegate only the newly introduced kind to its strict domain graph trigger.
DO $$DECLARE definition text;BEGIN
 definition=pg_get_functiondef('m6_validate_workflow_subject()'::regprocedure);
 definition=regexp_replace(definition,'\mBEGIN\M',E'BEGIN\n IF NEW.kind=''iam-metadata'' THEN RETURN NULL;END IF;');
 EXECUTE definition;
END;$$;
CREATE FUNCTION m11_validate_iam_workflow_graph() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;r iam_metadata_requests%ROWTYPE;i iam_change_intents%ROWTYPE;s workflow_steps%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='iam_metadata_requests' THEN SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 ELSIF TG_TABLE_NAME='workflow_steps' THEN SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 ELSE SELECT * INTO w FROM workflows WHERE id=NEW.id;END IF;
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF w.kind<>'iam-metadata' THEN
  IF w.subject_type='iam_metadata_requests' OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=w.id AND handler='iam.metadata') THEN
   RAISE EXCEPTION 'IAM metadata requires its dedicated zero-native kind' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
 SELECT * INTO r FROM iam_metadata_requests WHERE id=w.subject_id AND cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id;
 SELECT * INTO i FROM iam_change_intents WHERE id=r.id;SELECT * INTO s FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision;
 IF r.id IS NULL OR i.id IS NULL OR i.actor_id<>r.actor_id OR i.workflow_id<>w.id OR i.material_hmac<>r.material_hmac OR i.request_hmac<>r.request_hmac
  OR i.cluster_id<>w.cluster_id OR i.workspace_id<>w.workspace_id OR w.subject_type<>'iam_metadata_requests' OR w.requester_type<>'console' OR w.requester_user_id<>i.actor_id
  OR r.idempotency_key IS DISTINCT FROM ('iam-'||i.id::text) OR w.execution_mode<>'approval' OR NOT w.approval_required OR w.approval_format<>2 OR w.idempotency_key<>r.idempotency_key OR w.expires_at<>i.expires_at
  OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision)<>1 OR s.kind<>'metadata' OR s.handler IS DISTINCT FROM 'iam.metadata'
  OR s.entity_type<>'iam_metadata_requests' OR s.entity_id IS DISTINCT FROM i.id OR s.step_key<>'iam.metadata' OR s.step_order<>1 OR s.dependencies<>'{}'::uuid[]
  OR s.native_requests<>'[]'::jsonb OR s.operation_id IS NOT NULL OR s.cluster_id<>w.cluster_id OR s.workspace_id<>w.workspace_id OR s.plan_hash<>w.plan_hash
 THEN RAISE EXCEPTION 'IAM workflow must bind its immutable intention and exact V2 metadata step' USING ERRCODE='23514';END IF;
 IF w.state='succeeded' AND NOT EXISTS(SELECT 1 FROM iam_workflow_mutation_facts f JOIN iam_operations o ON o.id=f.operation_id
   WHERE f.intent_id=i.id AND f.workflow_id=w.id AND f.step_id=s.id AND f.plan_hash=w.plan_hash AND f.plan_revision=w.plan_revision
    AND f.actor_id=i.actor_id AND f.session_id=i.authoring_session_id AND o.state='succeeded' AND o.remote_completed AND s.state='succeeded') THEN
  RAISE EXCEPTION 'IAM terminal workflow requires its committed exact mutation receipt' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER iam_metadata_requests_graph AFTER INSERT ON iam_metadata_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_iam_workflow_graph();
CREATE CONSTRAINT TRIGGER workflows_iam_graph AFTER INSERT OR UPDATE ON workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_iam_workflow_graph();
CREATE CONSTRAINT TRIGGER workflow_steps_iam_graph AFTER INSERT OR UPDATE ON workflow_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_iam_workflow_graph();
CREATE FUNCTION m11_validate_iam_mutation_fact() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;e workflow_executions%ROWTYPE;s workflow_steps%ROWTYPE;i iam_change_intents%ROWTYPE;o iam_operations%ROWTYPE;
BEGIN
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;SELECT * INTO e FROM workflow_executions WHERE id=NEW.execution_id;
 SELECT * INTO s FROM workflow_steps WHERE id=NEW.step_id;SELECT * INTO i FROM iam_change_intents WHERE id=NEW.intent_id;SELECT * INTO o FROM iam_operations WHERE id=NEW.operation_id;
 IF w.id IS NULL OR e.id IS NULL OR s.id IS NULL OR i.id IS NULL OR o.id IS NULL OR w.kind<>'iam-metadata' OR w.subject_id<>i.id
  OR w.state<>'succeeded' OR e.state<>'succeeded' OR s.state<>'succeeded' OR e.workflow_id<>w.id OR s.workflow_id<>w.id
  OR e.cluster_id<>NEW.workflow_cluster_id OR e.workspace_id<>NEW.workflow_workspace_id OR e.plan_hash<>NEW.plan_hash OR e.plan_revision<>NEW.plan_revision
  OR s.plan_hash<>e.plan_hash OR s.plan_revision<>e.plan_revision OR e.execution_actor_id<>NEW.actor_id OR e.approval_format<>2
  OR e.approval_set_id IS DISTINCT FROM w.approval_set_id OR e.approval_set_hmac IS DISTINCT FROM w.approval_set_hmac
  OR NEW.actor_id<>i.actor_id OR NEW.session_id<>i.authoring_session_id OR o.actor_id<>NEW.actor_id OR o.state<>'succeeded' OR NOT o.remote_completed
  OR o.cluster_id IS DISTINCT FROM NEW.cluster_id OR o.workspace_id IS DISTINCT FROM NEW.workspace_id OR o.result_secret IS NULL
  OR o.idempotency_key IS DISTINCT FROM ('iam-approved-'||e.id::text) OR s.handler IS DISTINCT FROM 'iam.metadata' OR s.kind<>'metadata' OR s.native_requests<>'[]'::jsonb
  OR NEW.workflow_cluster_id<>w.cluster_id OR NEW.workflow_workspace_id<>w.workspace_id OR e.plan_hash<>w.plan_hash OR e.plan_revision<>w.plan_revision
  OR NEW.after_iam_epoch IS DISTINCT FROM (SELECT version FROM iam_epoch WHERE singleton=true)
  OR NEW.after_permission_version IS DISTINCT FROM (SELECT u.id::text||':'||u.permissions_epoch::text||':'||NEW.after_iam_epoch::text FROM users u WHERE u.id=NEW.actor_id)
  OR split_part(NEW.before_permission_version,':',1)<>NEW.actor_id::text OR split_part(NEW.before_permission_version,':',3)<>NEW.before_iam_epoch::text
 THEN RAISE EXCEPTION 'IAM mutation fact must retain its exact completed original metadata transaction' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER iam_mutation_fact_complete AFTER INSERT ON iam_workflow_mutation_facts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_iam_mutation_fact();
