-- Console-owned control metadata only. Historical migrations 000-032 and
-- their domain validators remain unchanged; this is not Kong DB migration.
ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_kind_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata','workflow-policy-metadata','iam-metadata','metrics-setup','control-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_kind_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata','workflow-policy-metadata','iam-metadata','metrics-setup','control-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries','configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs','toolbox_operations','workspace_migration_plans','governance_metadata_requests','workflow_policy_requests','entity_change_intents','iam_metadata_requests','metrics_setup_requests','control_metadata_requests'));

CREATE TABLE control_change_intents (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 authoring_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,workflow_id uuid NOT NULL UNIQUE,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),material_secret text NOT NULL CHECK(m6_encrypted(material_secret)),
 credential_epoch bigint NOT NULL CHECK(credential_epoch>0),permission_version text NOT NULL CHECK(length(permission_version) BETWEEN 1 AND 256),
 resource text NOT NULL CHECK(resource IN('clusters','data-sources','workspaces')),resource_id uuid NOT NULL,
 operation text NOT NULL CHECK(operation IN('create','update','deactivate','archive','restore')),
 before_revision integer NOT NULL CHECK(before_revision>=0),before_config_hmac text NOT NULL CHECK(m8_hex64(before_config_hmac)),
 issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '24 hours'),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(actor_id,idempotency_key),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK((resource='clusters' AND resource_id=cluster_id AND operation IN('update','deactivate'))
  OR(resource='data-sources' AND operation IN('create','update','deactivate'))
  OR(resource='workspaces' AND operation IN('create','update','archive','restore'))),
 CHECK((operation='create' AND before_revision=0) OR(operation<>'create' AND before_revision>0))
);
CREATE TABLE control_metadata_requests (
 id uuid PRIMARY KEY REFERENCES control_change_intents(id) ON DELETE RESTRICT,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,workflow_id uuid NOT NULL UNIQUE,idempotency_key text NOT NULL,
 submit_key text NOT NULL CHECK(length(submit_key) BETWEEN 1 AND 128),
 request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(actor_id,submit_key),
 FOREIGN KEY(cluster_id,workspace_id,id) REFERENCES control_change_intents(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE control_workflow_mutation_facts (
 id uuid PRIMARY KEY,intent_id uuid NOT NULL UNIQUE REFERENCES control_metadata_requests(id) ON DELETE RESTRICT,
 workflow_id uuid NOT NULL,execution_id uuid NOT NULL UNIQUE REFERENCES workflow_executions(id) ON DELETE RESTRICT,
 step_id uuid NOT NULL UNIQUE REFERENCES workflow_steps(id) ON DELETE RESTRICT,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
 plan_revision integer NOT NULL CHECK(plan_revision>0),plan_hash text NOT NULL CHECK(m8_hex64(plan_hash)),
 before_permission_version text NOT NULL,after_permission_version text NOT NULL,
 before_config_hmac text NOT NULL CHECK(m8_hex64(before_config_hmac)),after_config_hmac text NOT NULL CHECK(m8_hex64(after_config_hmac)),
 result_hmac text NOT NULL CHECK(m8_hex64(result_hmac)),result_secret text NOT NULL CHECK(m6_encrypted(result_secret)),
 audit_id uuid NOT NULL UNIQUE REFERENCES audit_events(id) ON DELETE RESTRICT,
 resource text NOT NULL CHECK(resource IN('clusters','data-sources','workspaces')),resource_id uuid NOT NULL,
 operation text NOT NULL CHECK(operation IN('create','update','deactivate','archive','restore')),
 before_revision integer NOT NULL CHECK(before_revision>=0),after_revision integer NOT NULL CHECK(after_revision=before_revision+1),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,intent_id) REFERENCES control_metadata_requests(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,execution_id,workflow_id,plan_revision,plan_hash)
  REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,step_id,workflow_id,plan_revision,plan_hash)
  REFERENCES workflow_steps(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT
);

-- Preparation freezes an actual existing approval cluster and an original
-- live author session. Neither a new cluster nor a made-up source row qualifies.
CREATE FUNCTION m11_validate_control_intent_author() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE u users%ROWTYPE;s auth_sessions%ROWTYPE;c clusters%ROWTYPE;anchor workspaces%ROWTYPE;ds data_sources%ROWTYPE;target workspaces%ROWTYPE;epoch bigint;
BEGIN
 SELECT * INTO u FROM users WHERE id=NEW.actor_id;SELECT * INTO s FROM auth_sessions WHERE id=NEW.authoring_session_id;
 SELECT * INTO c FROM clusters WHERE id=NEW.cluster_id;SELECT * INTO anchor FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=NEW.workspace_id;
 SELECT version INTO epoch FROM iam_epoch WHERE singleton=true;
 IF u.id IS NULL OR s.id IS NULL OR c.id IS NULL OR anchor.id IS NULL OR epoch IS NULL OR u.status<>'active' OR u.deleted_at IS NOT NULL OR u.force_password_change
  OR s.user_id IS DISTINCT FROM u.id OR s.revoked_at IS NOT NULL OR s.expires_at<=now() OR s.credential_epoch IS DISTINCT FROM u.credential_epoch
  OR NEW.credential_epoch IS DISTINCT FROM u.credential_epoch OR NEW.expires_at>s.expires_at OR NEW.issued_at>now()
  OR NEW.permission_version IS DISTINCT FROM (u.id::text||':'||u.permissions_epoch::text||':'||epoch::text)
  OR c.deleted_at IS NOT NULL OR c.status='disabled' OR c.execution_mode<>'approval' OR anchor.status<>'active' OR anchor.deleted_at IS NOT NULL
 THEN RAISE EXCEPTION 'Control intention requires its genuine current original author and existing approval scope' USING ERRCODE='23514';END IF;
 IF NEW.resource='clusters' THEN
  IF NEW.resource_id IS DISTINCT FROM c.id OR NEW.before_revision IS DISTINCT FROM c.revision THEN
   RAISE EXCEPTION 'Cluster intention must freeze its actual original configuration revision' USING ERRCODE='23514';END IF;
 ELSIF NEW.resource='data-sources' THEN
  SELECT * INTO ds FROM data_sources WHERE cluster_id=c.id AND id=NEW.resource_id;
  IF (NEW.operation='create' AND ds.id IS NOT NULL)
   OR(NEW.operation<>'create' AND(ds.id IS NULL OR ds.deleted_at IS NOT NULL OR ds.revision IS DISTINCT FROM NEW.before_revision)) THEN
   RAISE EXCEPTION 'Data source intention must freeze its actual original object or genuine absence' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO target FROM workspaces WHERE cluster_id=c.id AND id=NEW.resource_id;
  IF (NEW.operation='create' AND target.id IS NOT NULL)
   OR(NEW.operation<>'create' AND(target.id IS NULL OR target.revision IS DISTINCT FROM NEW.before_revision))
   OR(NEW.operation IN('update','archive') AND(target.deleted_at IS NOT NULL OR target.status='deleted'))
   OR(NEW.operation='restore' AND(target.deleted_at IS NULL OR target.status IS DISTINCT FROM 'deleted'))
   OR(NEW.operation='archive' AND target.is_default) THEN
   RAISE EXCEPTION 'Workspace intention must freeze its actual original live or archived object' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END;$$;
CREATE TRIGGER control_intent_original_author BEFORE INSERT ON control_change_intents FOR EACH ROW EXECUTE FUNCTION m11_validate_control_intent_author();

DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['control_change_intents','control_metadata_requests','control_workflow_mutation_facts'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
  EXECUTE format('REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON %I FROM PUBLIC',tab);
 END LOOP;
END;$$;
-- Preserve the entire existing subject validator, including IAM and metrics.
-- Only the new kind delegates to its additional exact graph checks below.
DO $$DECLARE definition text;BEGIN
 definition=pg_get_functiondef('m6_validate_workflow_subject()'::regprocedure);
 definition=regexp_replace(definition,'\mBEGIN\M',E'BEGIN\n IF NEW.kind=''control-metadata'' THEN RETURN NULL;END IF;');EXECUTE definition;
END;$$;

CREATE FUNCTION m11_validate_control_workflow_graph() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;r control_metadata_requests%ROWTYPE;i control_change_intents%ROWTYPE;s workflow_steps%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='control_metadata_requests' OR TG_TABLE_NAME='workflow_steps' THEN SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 ELSE SELECT * INTO w FROM workflows WHERE id=NEW.id;END IF;
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF w.kind<>'control-metadata' THEN
  IF w.subject_type='control_metadata_requests' OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=w.id AND handler='control.metadata') THEN
   RAISE EXCEPTION 'Control metadata requires its dedicated zero-native kind' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
 SELECT * INTO r FROM control_metadata_requests WHERE id=w.subject_id AND cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id;
 SELECT * INTO i FROM control_change_intents WHERE id=r.id;SELECT * INTO s FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision;
 IF r.id IS NULL OR i.id IS NULL OR s.id IS NULL OR i.actor_id IS DISTINCT FROM r.actor_id OR i.workflow_id IS DISTINCT FROM w.id
  OR i.material_hmac IS DISTINCT FROM r.material_hmac OR i.request_hmac IS DISTINCT FROM r.request_hmac OR i.cluster_id IS DISTINCT FROM w.cluster_id OR i.workspace_id IS DISTINCT FROM w.workspace_id
  OR w.subject_type IS DISTINCT FROM 'control_metadata_requests' OR w.requester_type IS DISTINCT FROM 'console' OR w.requester_user_id IS DISTINCT FROM i.actor_id
  OR r.idempotency_key IS DISTINCT FROM ('control-'||i.id::text) OR w.idempotency_key IS DISTINCT FROM r.idempotency_key
  OR w.execution_mode IS DISTINCT FROM 'approval' OR NOT w.approval_required OR w.approval_format IS DISTINCT FROM 2 OR w.plan_revision<=0 OR w.expires_at IS DISTINCT FROM i.expires_at
  OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision)<>1
  OR EXISTS(SELECT 1 FROM workflow_steps historical WHERE historical.workflow_id=w.id AND(historical.kind IS DISTINCT FROM 'metadata'
   OR historical.handler IS DISTINCT FROM 'control.metadata' OR historical.native_requests IS DISTINCT FROM '[]'::jsonb OR historical.operation_id IS NOT NULL))
  OR s.kind IS DISTINCT FROM 'metadata' OR s.handler IS DISTINCT FROM 'control.metadata'
  OR s.entity_type IS DISTINCT FROM 'control_metadata_requests' OR s.entity_id IS DISTINCT FROM i.id OR s.step_key IS DISTINCT FROM 'control.metadata' OR s.step_order IS DISTINCT FROM 1
  OR s.dependencies IS DISTINCT FROM '{}'::uuid[] OR s.native_requests IS DISTINCT FROM '[]'::jsonb OR s.operation_id IS NOT NULL OR s.parent_id IS NOT NULL OR s.credential_kind IS NOT NULL
  OR s.cluster_id IS DISTINCT FROM w.cluster_id OR s.workspace_id IS DISTINCT FROM w.workspace_id OR s.plan_hash IS DISTINCT FROM w.plan_hash OR s.plan_revision IS DISTINCT FROM w.plan_revision
  OR s.execution_mode IS DISTINCT FROM 'approval' OR NOT s.approval_required OR s.metadata_revision IS DISTINCT FROM i.before_revision OR s.metadata_before_hmac IS DISTINCT FROM i.before_config_hmac
  OR s.permission_action IS DISTINCT FROM (CASE WHEN i.operation IN('deactivate','archive') THEN 'delete' ELSE 'write' END)
 THEN RAISE EXCEPTION 'Control workflow must bind its immutable intention and exact V2 metadata step' USING ERRCODE='23514';END IF;
 IF w.state='succeeded' AND NOT EXISTS(SELECT 1 FROM control_workflow_mutation_facts f WHERE f.intent_id=i.id AND f.workflow_id=w.id AND f.step_id=s.id
  AND f.plan_hash=w.plan_hash AND f.plan_revision=w.plan_revision AND f.actor_id=i.actor_id AND f.session_id=i.authoring_session_id AND s.state='succeeded') THEN
  RAISE EXCEPTION 'Control terminal workflow requires its committed exact mutation receipt' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER control_metadata_requests_graph AFTER INSERT ON control_metadata_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_control_workflow_graph();
CREATE CONSTRAINT TRIGGER workflows_control_graph AFTER INSERT OR UPDATE ON workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_control_workflow_graph();
CREATE CONSTRAINT TRIGGER workflow_steps_control_graph AFTER INSERT OR UPDATE ON workflow_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_control_workflow_graph();

-- This deferred check certifies only the original completed metadata action.
-- It does not confer permission after a mode switch, archive or cluster disable.
-- Keyed configuration digests and encrypted results are verified by the fixed
-- business delegate; SQL independently checks identities and live row versions.
CREATE FUNCTION m11_validate_control_mutation_fact() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;e workflow_executions%ROWTYPE;s workflow_steps%ROWTYPE;i control_change_intents%ROWTYPE;a audit_events%ROWTYPE;
 c clusters%ROWTYPE;anchor workspaces%ROWTYPE;target workspaces%ROWTYPE;ds data_sources%ROWTYPE;author users%ROWTYPE;sid auth_sessions%ROWTYPE;epoch bigint;
BEGIN
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;SELECT * INTO e FROM workflow_executions WHERE id=NEW.execution_id;
 SELECT * INTO s FROM workflow_steps WHERE id=NEW.step_id;SELECT * INTO i FROM control_change_intents WHERE id=NEW.intent_id;
 SELECT * INTO a FROM audit_events WHERE id=NEW.audit_id;SELECT * INTO c FROM clusters WHERE id=NEW.cluster_id;
 SELECT * INTO anchor FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=NEW.workspace_id;
 SELECT * INTO author FROM users WHERE id=NEW.actor_id;SELECT * INTO sid FROM auth_sessions WHERE id=NEW.session_id;SELECT version INTO epoch FROM iam_epoch WHERE singleton=true;
 IF w.id IS NULL OR e.id IS NULL OR s.id IS NULL OR i.id IS NULL OR a.id IS NULL OR c.id IS NULL OR anchor.id IS NULL OR author.id IS NULL OR sid.id IS NULL OR epoch IS NULL
  OR w.kind IS DISTINCT FROM 'control-metadata' OR w.subject_type IS DISTINCT FROM 'control_metadata_requests' OR w.subject_id IS DISTINCT FROM i.id
  OR w.state IS DISTINCT FROM 'succeeded' OR e.state IS DISTINCT FROM 'succeeded' OR s.state IS DISTINCT FROM 'succeeded'
  OR e.workflow_id IS DISTINCT FROM w.id OR s.workflow_id IS DISTINCT FROM w.id OR w.cluster_id IS DISTINCT FROM NEW.cluster_id OR w.workspace_id IS DISTINCT FROM NEW.workspace_id
  OR e.cluster_id IS DISTINCT FROM NEW.cluster_id OR e.workspace_id IS DISTINCT FROM NEW.workspace_id OR s.cluster_id IS DISTINCT FROM NEW.cluster_id OR s.workspace_id IS DISTINCT FROM NEW.workspace_id
  OR w.plan_hash IS DISTINCT FROM NEW.plan_hash OR e.plan_hash IS DISTINCT FROM NEW.plan_hash OR s.plan_hash IS DISTINCT FROM NEW.plan_hash
  OR w.plan_revision IS DISTINCT FROM NEW.plan_revision OR e.plan_revision IS DISTINCT FROM NEW.plan_revision OR s.plan_revision IS DISTINCT FROM NEW.plan_revision
  OR e.execution_actor_id IS DISTINCT FROM NEW.actor_id OR NEW.actor_id IS DISTINCT FROM i.actor_id OR NEW.session_id IS DISTINCT FROM i.authoring_session_id
  OR e.approval_format IS DISTINCT FROM 2 OR w.approval_format IS DISTINCT FROM 2 OR e.execution_mode IS DISTINCT FROM 'approval' OR NOT e.approval_required
  OR e.approval_set_id IS NULL OR e.approval_set_hmac IS NULL OR e.approval_set_id IS DISTINCT FROM w.approval_set_id OR e.approval_set_hmac IS DISTINCT FROM w.approval_set_hmac
  OR s.kind IS DISTINCT FROM 'metadata' OR s.handler IS DISTINCT FROM 'control.metadata' OR s.native_requests IS DISTINCT FROM '[]'::jsonb OR s.operation_id IS NOT NULL
  OR i.cluster_id IS DISTINCT FROM NEW.cluster_id OR i.workspace_id IS DISTINCT FROM NEW.workspace_id OR i.workflow_id IS DISTINCT FROM w.id
  OR i.resource IS DISTINCT FROM NEW.resource OR i.resource_id IS DISTINCT FROM NEW.resource_id OR i.operation IS DISTINCT FROM NEW.operation
  OR i.before_revision IS DISTINCT FROM NEW.before_revision OR i.before_config_hmac IS DISTINCT FROM NEW.before_config_hmac
  OR i.permission_version IS DISTINCT FROM NEW.before_permission_version OR NEW.after_permission_version IS DISTINCT FROM (author.id::text||':'||author.permissions_epoch::text||':'||epoch::text)
  OR author.status<>'active' OR author.deleted_at IS NOT NULL OR author.force_password_change OR sid.user_id IS DISTINCT FROM author.id OR sid.revoked_at IS NOT NULL OR sid.expires_at<=now()
  OR sid.credential_epoch IS DISTINCT FROM author.credential_epoch OR i.credential_epoch IS DISTINCT FROM author.credential_epoch
  OR a.actor_id IS DISTINCT FROM NEW.actor_id OR a.actor_type IS DISTINCT FROM 'user' OR a.cluster_id IS DISTINCT FROM NEW.cluster_id OR a.workspace_id IS DISTINCT FROM NEW.workspace_id
  OR a.workflow_id IS DISTINCT FROM NEW.workflow_id OR a.entity_type IS DISTINCT FROM NEW.resource OR a.entity_id IS DISTINCT FROM NEW.resource_id::text
  OR a.action IS DISTINCT FROM 'control.metadata' OR a.result IS DISTINCT FROM 'success'
 THEN RAISE EXCEPTION 'Control mutation fact must retain its exact completed original metadata transaction and audit' USING ERRCODE='23514';END IF;
 IF NEW.resource='clusters' THEN
  IF NEW.resource_id IS DISTINCT FROM c.id OR c.revision IS DISTINCT FROM NEW.after_revision
   OR(NEW.operation='update' AND c.deleted_at IS NOT NULL)
   OR(NEW.operation='deactivate' AND(c.deleted_at IS NULL OR c.status IS DISTINCT FROM 'disabled')) THEN
   RAISE EXCEPTION 'Cluster completion requires its actual original update or soft deactivation' USING ERRCODE='23514';END IF;
 ELSE
  IF c.deleted_at IS NOT NULL OR c.status='disabled' OR c.execution_mode IS DISTINCT FROM 'approval' THEN
   RAISE EXCEPTION 'Non-cluster completion cannot change its original cluster registry' USING ERRCODE='23514';END IF;
  IF NEW.resource='data-sources' THEN
   SELECT * INTO ds FROM data_sources WHERE cluster_id=NEW.cluster_id AND id=NEW.resource_id;
   IF ds.id IS NULL OR ds.revision IS DISTINCT FROM NEW.after_revision
    OR(NEW.operation IN('create','update') AND ds.deleted_at IS NOT NULL)
    OR(NEW.operation='deactivate' AND(ds.deleted_at IS NULL OR ds.enabled)) THEN
    RAISE EXCEPTION 'Data source completion requires its actual original write or soft deactivation' USING ERRCODE='23514';END IF;
  ELSE
   SELECT * INTO target FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=NEW.resource_id;
   IF target.id IS NULL OR target.revision IS DISTINCT FROM NEW.after_revision
    OR(NEW.operation IN('create','restore') AND(target.status IS DISTINCT FROM 'active' OR target.deleted_at IS NOT NULL OR target.retention_until IS NOT NULL))
    OR(NEW.operation='update' AND(target.status NOT IN('active','disabled') OR target.deleted_at IS NOT NULL))
    OR(NEW.operation='archive' AND(target.status IS DISTINCT FROM 'deleted' OR target.deleted_at IS NULL OR target.retention_until IS NULL OR target.is_default)) THEN
    RAISE EXCEPTION 'Workspace completion requires its actual original create update archive or restore' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 IF NOT(NEW.resource='workspaces' AND NEW.resource_id=NEW.workspace_id AND NEW.operation IN('update','archive'))
  AND(anchor.status<>'active' OR anchor.deleted_at IS NOT NULL) THEN
  RAISE EXCEPTION 'Control completion cannot change an unrelated authorization workspace' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER control_mutation_fact_complete AFTER INSERT ON control_workflow_mutation_facts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_control_mutation_fact();
