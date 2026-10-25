-- Console-owned entity annotations. No Kong DB/table/source is changed.
-- Preserve original migrations, including the control-clock 034 repair.
ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_kind_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata','workflow-policy-metadata','iam-metadata','metrics-setup','control-metadata','entity-annotation'));
ALTER TABLE workflows DROP CONSTRAINT workflows_kind_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata','workflow-policy-metadata','iam-metadata','metrics-setup','control-metadata','entity-annotation'));
ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries','configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs','toolbox_operations','workspace_migration_plans','governance_metadata_requests','workflow_policy_requests','entity_change_intents','iam_metadata_requests','metrics_setup_requests','control_metadata_requests','entity_annotation_requests'));
CREATE TABLE annotation_change_intents (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 authoring_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,workflow_id uuid NOT NULL UNIQUE,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),material_secret text NOT NULL CHECK(m6_encrypted(material_secret)),
 credential_epoch bigint NOT NULL CHECK(credential_epoch>0),permission_version text NOT NULL CHECK(length(permission_version) BETWEEN 1 AND 256),
 entity_type text NOT NULL CHECK(entity_type IN('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis')),entity_id uuid NOT NULL,
 operation text NOT NULL CHECK(operation IN('set','remove','restore')),before_revision integer NOT NULL CHECK(before_revision>=0 AND before_revision<2147483647),
 before_config_hmac text NOT NULL CHECK(m8_hex64(before_config_hmac)),native_proof_hmac text NOT NULL CHECK(m8_hex64(native_proof_hmac)),
 issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '24 hours'),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(actor_id,idempotency_key),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK(operation='set' OR before_revision>0)
);
CREATE TABLE entity_annotation_requests (
 id uuid PRIMARY KEY REFERENCES annotation_change_intents(id) ON DELETE RESTRICT,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,workflow_id uuid NOT NULL UNIQUE,idempotency_key text NOT NULL,
 submit_key text NOT NULL CHECK(length(submit_key) BETWEEN 1 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(cluster_id,workspace_id,id),UNIQUE(actor_id,submit_key),
 FOREIGN KEY(cluster_id,workspace_id,id) REFERENCES annotation_change_intents(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE annotation_workflow_mutation_facts (
 id uuid PRIMARY KEY,intent_id uuid NOT NULL UNIQUE REFERENCES entity_annotation_requests(id) ON DELETE RESTRICT,
 workflow_id uuid NOT NULL,execution_id uuid NOT NULL UNIQUE REFERENCES workflow_executions(id) ON DELETE RESTRICT,
 step_id uuid NOT NULL UNIQUE REFERENCES workflow_steps(id) ON DELETE RESTRICT,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
 plan_revision integer NOT NULL CHECK(plan_revision>0),plan_hash text NOT NULL CHECK(m8_hex64(plan_hash)),permission_version text NOT NULL,
 before_config_hmac text NOT NULL CHECK(m8_hex64(before_config_hmac)),after_config_hmac text NOT NULL CHECK(m8_hex64(after_config_hmac)),
 result_hmac text NOT NULL CHECK(m8_hex64(result_hmac)),result_secret text NOT NULL CHECK(m6_encrypted(result_secret)),native_proof_hmac text NOT NULL CHECK(m8_hex64(native_proof_hmac)),
 audit_id uuid NOT NULL UNIQUE REFERENCES audit_events(id) ON DELETE RESTRICT,audit_action text NOT NULL CHECK(audit_action IN('annotation.metadata.created','annotation.metadata.updated','annotation.metadata.deleted','annotation.metadata.restored')),
 entity_type text NOT NULL CHECK(entity_type IN('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis')),entity_id uuid NOT NULL,
 operation text NOT NULL CHECK(operation IN('set','remove','restore')),before_revision integer NOT NULL CHECK(before_revision>=0),after_revision integer NOT NULL CHECK(after_revision=before_revision+1),
 created_at timestamptz NOT NULL DEFAULT now(),FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,intent_id) REFERENCES entity_annotation_requests(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,execution_id,workflow_id,plan_revision,plan_hash) REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,step_id,workflow_id,plan_revision,plan_hash) REFERENCES workflow_steps(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT
);
CREATE FUNCTION m11_validate_annotation_intent_author() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE u users%ROWTYPE;s auth_sessions%ROWTYPE;c clusters%ROWTYPE;ws workspaces%ROWTYPE;a entity_annotations%ROWTYPE;epoch bigint;
BEGIN
 SELECT * INTO u FROM users WHERE id=NEW.actor_id;SELECT * INTO s FROM auth_sessions WHERE id=NEW.authoring_session_id;
 SELECT * INTO c FROM clusters WHERE id=NEW.cluster_id;SELECT * INTO ws FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=NEW.workspace_id;
 SELECT * INTO a FROM entity_annotations WHERE cluster_id=NEW.cluster_id AND entity_type=NEW.entity_type AND kong_id=NEW.entity_id;
 SELECT version INTO epoch FROM iam_epoch WHERE singleton=true;
 IF u.id IS NULL OR s.id IS NULL OR c.id IS NULL OR ws.id IS NULL OR epoch IS NULL OR u.status<>'active' OR u.deleted_at IS NOT NULL OR u.force_password_change
  OR s.user_id IS DISTINCT FROM u.id OR s.revoked_at IS NOT NULL OR s.expires_at<=clock_timestamp() OR s.credential_epoch IS DISTINCT FROM u.credential_epoch
  OR NEW.credential_epoch IS DISTINCT FROM u.credential_epoch OR NEW.expires_at>s.expires_at OR NEW.issued_at>clock_timestamp()
  OR NEW.permission_version IS DISTINCT FROM (u.id::text||':'||u.permissions_epoch::text||':'||epoch::text)
  OR c.deleted_at IS NOT NULL OR c.status='disabled' OR c.execution_mode<>'approval' OR ws.status<>'active' OR ws.deleted_at IS NOT NULL
  OR COALESCE(a.revision,0) IS DISTINCT FROM NEW.before_revision OR (NEW.operation IN('set','remove') AND a.status='deleted')
  OR (NEW.operation='remove' AND a.kong_id IS NULL) OR (NEW.operation='restore' AND (a.kong_id IS NULL OR a.status IS DISTINCT FROM 'deleted'))
 THEN RAISE EXCEPTION 'Annotation intention requires its original current author, revision and exact approval workspace' USING ERRCODE='23514';END IF;RETURN NEW;
END;$$;
CREATE TRIGGER annotation_intent_original_author BEFORE INSERT ON annotation_change_intents FOR EACH ROW EXECUTE FUNCTION m11_validate_annotation_intent_author();
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['annotation_change_intents','entity_annotation_requests','annotation_workflow_mutation_facts'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
  EXECUTE format('REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON %I FROM PUBLIC',tab);
 END LOOP;
END;$$;
-- A single new-kind branch, preserving all previous domain validation code.
DO $$DECLARE definition text;BEGIN
 definition=pg_get_functiondef('m6_validate_workflow_subject()'::regprocedure);
 definition=regexp_replace(definition,'\mBEGIN\M',E'BEGIN\n IF NEW.kind=''entity-annotation'' THEN RETURN NULL;END IF;');EXECUTE definition;
END;$$;
CREATE FUNCTION m11_validate_annotation_workflow_graph() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;r entity_annotation_requests%ROWTYPE;i annotation_change_intents%ROWTYPE;s workflow_steps%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='entity_annotation_requests' OR TG_TABLE_NAME='workflow_steps' THEN SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 ELSE SELECT * INTO w FROM workflows WHERE id=NEW.id;END IF;IF NOT FOUND THEN RETURN NULL;END IF;
 IF w.kind<>'entity-annotation' THEN
  IF w.subject_type='entity_annotation_requests' OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=w.id AND handler='entity.annotation') THEN
   RAISE EXCEPTION 'Annotation handler requires its dedicated metadata-only kind' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
 SELECT * INTO r FROM entity_annotation_requests WHERE id=w.subject_id AND cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id;
 SELECT * INTO i FROM annotation_change_intents WHERE id=r.id;SELECT * INTO s FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision;
 IF r.id IS NULL OR i.id IS NULL OR s.id IS NULL OR i.actor_id IS DISTINCT FROM r.actor_id OR i.workflow_id IS DISTINCT FROM w.id OR i.material_hmac IS DISTINCT FROM r.material_hmac OR i.request_hmac IS DISTINCT FROM r.request_hmac
  OR i.cluster_id IS DISTINCT FROM w.cluster_id OR i.workspace_id IS DISTINCT FROM w.workspace_id OR w.subject_type IS DISTINCT FROM 'entity_annotation_requests' OR w.requester_type IS DISTINCT FROM 'console' OR w.requester_user_id IS DISTINCT FROM i.actor_id
  OR r.idempotency_key IS DISTINCT FROM ('annotation-'||i.id::text) OR w.idempotency_key IS DISTINCT FROM r.idempotency_key OR w.execution_mode IS DISTINCT FROM 'approval' OR NOT w.approval_required OR w.approval_format IS DISTINCT FROM 2 OR w.expires_at IS DISTINCT FROM i.expires_at
  OR (SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision)<>1
  OR EXISTS(SELECT 1 FROM workflow_steps historical WHERE historical.workflow_id=w.id AND(historical.kind IS DISTINCT FROM 'metadata' OR historical.handler IS DISTINCT FROM 'entity.annotation' OR historical.native_requests IS DISTINCT FROM '[]'::jsonb OR historical.operation_id IS NOT NULL))
  OR s.kind IS DISTINCT FROM 'metadata' OR s.handler IS DISTINCT FROM 'entity.annotation' OR s.entity_type IS DISTINCT FROM 'entity_annotation_requests' OR s.entity_id IS DISTINCT FROM i.id OR s.step_key IS DISTINCT FROM 'entity.annotation' OR s.step_order IS DISTINCT FROM 1
  OR s.dependencies IS DISTINCT FROM '{}'::uuid[] OR s.native_requests IS DISTINCT FROM '[]'::jsonb OR s.operation_id IS NOT NULL OR s.parent_id IS NOT NULL OR s.credential_kind IS NOT NULL
  OR s.cluster_id IS DISTINCT FROM w.cluster_id OR s.workspace_id IS DISTINCT FROM w.workspace_id OR s.plan_hash IS DISTINCT FROM w.plan_hash OR s.plan_revision IS DISTINCT FROM w.plan_revision
  OR s.execution_mode IS DISTINCT FROM 'approval' OR NOT s.approval_required OR s.metadata_revision IS DISTINCT FROM i.before_revision OR s.metadata_before_hmac IS DISTINCT FROM i.before_config_hmac
  OR s.permission_action IS DISTINCT FROM (CASE WHEN i.operation='remove' THEN 'delete' ELSE 'write' END)
 THEN RAISE EXCEPTION 'Annotation workflow must bind its original immutable intent and exact metadata step' USING ERRCODE='23514';END IF;
 IF w.state='succeeded' AND NOT EXISTS(SELECT 1 FROM annotation_workflow_mutation_facts f WHERE f.intent_id=i.id AND f.workflow_id=w.id AND f.step_id=s.id AND f.plan_hash=w.plan_hash AND f.plan_revision=w.plan_revision AND f.actor_id=i.actor_id AND f.session_id=i.authoring_session_id AND s.state='succeeded') THEN
  RAISE EXCEPTION 'Annotation success requires its original committed mutation fact' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER entity_annotation_requests_graph AFTER INSERT ON entity_annotation_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_annotation_workflow_graph();
CREATE CONSTRAINT TRIGGER workflows_annotation_graph AFTER INSERT OR UPDATE ON workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_annotation_workflow_graph();
CREATE CONSTRAINT TRIGGER workflow_steps_annotation_graph AFTER INSERT OR UPDATE ON workflow_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_annotation_workflow_graph();
CREATE FUNCTION m11_validate_annotation_mutation_fact() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;e workflow_executions%ROWTYPE;s workflow_steps%ROWTYPE;i annotation_change_intents%ROWTYPE;a audit_events%ROWTYPE;
 c clusters%ROWTYPE;ws workspaces%ROWTYPE;annotation entity_annotations%ROWTYPE;author users%ROWTYPE;sid auth_sessions%ROWTYPE;epoch bigint;
BEGIN
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;SELECT * INTO e FROM workflow_executions WHERE id=NEW.execution_id;SELECT * INTO s FROM workflow_steps WHERE id=NEW.step_id;
 SELECT * INTO i FROM annotation_change_intents WHERE id=NEW.intent_id;SELECT * INTO a FROM audit_events WHERE id=NEW.audit_id;SELECT * INTO c FROM clusters WHERE id=NEW.cluster_id;
 SELECT * INTO ws FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=NEW.workspace_id;SELECT * INTO annotation FROM entity_annotations WHERE cluster_id=NEW.cluster_id AND entity_type=NEW.entity_type AND kong_id=NEW.entity_id;
 SELECT * INTO author FROM users WHERE id=NEW.actor_id;SELECT * INTO sid FROM auth_sessions WHERE id=NEW.session_id;SELECT version INTO epoch FROM iam_epoch WHERE singleton=true;
 IF w.id IS NULL OR e.id IS NULL OR s.id IS NULL OR i.id IS NULL OR a.id IS NULL OR c.id IS NULL OR ws.id IS NULL OR annotation.kong_id IS NULL OR author.id IS NULL OR sid.id IS NULL OR epoch IS NULL
  OR w.kind IS DISTINCT FROM 'entity-annotation' OR w.subject_type IS DISTINCT FROM 'entity_annotation_requests' OR w.subject_id IS DISTINCT FROM i.id
  OR w.state IS DISTINCT FROM 'succeeded' OR e.state IS DISTINCT FROM 'succeeded' OR s.state IS DISTINCT FROM 'succeeded'
  OR e.workflow_id IS DISTINCT FROM w.id OR s.workflow_id IS DISTINCT FROM w.id OR w.cluster_id IS DISTINCT FROM NEW.cluster_id OR w.workspace_id IS DISTINCT FROM NEW.workspace_id
  OR e.cluster_id IS DISTINCT FROM NEW.cluster_id OR e.workspace_id IS DISTINCT FROM NEW.workspace_id OR s.cluster_id IS DISTINCT FROM NEW.cluster_id OR s.workspace_id IS DISTINCT FROM NEW.workspace_id
  OR w.plan_hash IS DISTINCT FROM NEW.plan_hash OR e.plan_hash IS DISTINCT FROM NEW.plan_hash OR s.plan_hash IS DISTINCT FROM NEW.plan_hash
  OR w.plan_revision IS DISTINCT FROM NEW.plan_revision OR e.plan_revision IS DISTINCT FROM NEW.plan_revision OR s.plan_revision IS DISTINCT FROM NEW.plan_revision
  OR e.execution_actor_id IS DISTINCT FROM NEW.actor_id OR NEW.actor_id IS DISTINCT FROM i.actor_id OR NEW.session_id IS DISTINCT FROM i.authoring_session_id
  OR e.approval_format IS DISTINCT FROM 2 OR w.approval_format IS DISTINCT FROM 2 OR e.execution_mode IS DISTINCT FROM 'approval' OR NOT e.approval_required
  OR e.approval_set_id IS NULL OR e.approval_set_hmac IS NULL OR e.approval_set_id IS DISTINCT FROM w.approval_set_id OR e.approval_set_hmac IS DISTINCT FROM w.approval_set_hmac
  OR s.kind IS DISTINCT FROM 'metadata' OR s.handler IS DISTINCT FROM 'entity.annotation' OR s.native_requests IS DISTINCT FROM '[]'::jsonb OR s.operation_id IS NOT NULL
  OR i.cluster_id IS DISTINCT FROM NEW.cluster_id OR i.workspace_id IS DISTINCT FROM NEW.workspace_id OR i.workflow_id IS DISTINCT FROM w.id
  OR i.entity_type IS DISTINCT FROM NEW.entity_type OR i.entity_id IS DISTINCT FROM NEW.entity_id OR i.operation IS DISTINCT FROM NEW.operation
  OR i.before_revision IS DISTINCT FROM NEW.before_revision OR i.before_config_hmac IS DISTINCT FROM NEW.before_config_hmac OR i.native_proof_hmac IS DISTINCT FROM NEW.native_proof_hmac
  OR i.permission_version IS DISTINCT FROM NEW.permission_version OR NEW.permission_version IS DISTINCT FROM (author.id::text||':'||author.permissions_epoch::text||':'||epoch::text)
  OR author.status<>'active' OR author.deleted_at IS NOT NULL OR author.force_password_change OR sid.user_id IS DISTINCT FROM author.id OR sid.revoked_at IS NOT NULL OR sid.expires_at<=clock_timestamp()
  OR sid.credential_epoch IS DISTINCT FROM author.credential_epoch OR i.credential_epoch IS DISTINCT FROM author.credential_epoch OR i.expires_at<=clock_timestamp()
  OR c.deleted_at IS NOT NULL OR c.status='disabled' OR c.execution_mode<>'approval' OR ws.status<>'active' OR ws.deleted_at IS NOT NULL
  OR annotation.revision IS DISTINCT FROM NEW.after_revision OR (NEW.operation='remove' AND annotation.status IS DISTINCT FROM 'deleted') OR (NEW.operation<>'remove' AND annotation.status IS DISTINCT FROM 'active')
  OR NEW.audit_action IS DISTINCT FROM (CASE WHEN NEW.operation='remove' THEN 'annotation.metadata.deleted' WHEN NEW.operation='restore' THEN 'annotation.metadata.restored' WHEN NEW.before_revision=0 THEN 'annotation.metadata.created' ELSE 'annotation.metadata.updated' END)
  OR a.actor_id IS DISTINCT FROM NEW.actor_id OR a.actor_type IS DISTINCT FROM 'user' OR a.cluster_id IS DISTINCT FROM NEW.cluster_id OR a.workspace_id IS DISTINCT FROM NEW.workspace_id
  OR a.workflow_id IS DISTINCT FROM NEW.workflow_id OR a.entity_type IS DISTINCT FROM NEW.entity_type OR a.entity_id IS DISTINCT FROM NEW.entity_id::text OR a.action IS DISTINCT FROM NEW.audit_action OR a.result IS DISTINCT FROM 'success'
 THEN RAISE EXCEPTION 'Annotation mutation fact requires its exact original completed metadata transaction and audit' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER annotation_mutation_fact_graph AFTER INSERT ON annotation_workflow_mutation_facts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_annotation_mutation_fact();
