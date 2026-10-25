-- SQL043 rollback: refuse while scheduled evidence exists; restore session-only validators.
DO $$BEGIN
 IF EXISTS(SELECT 1 FROM control_workflow_mutation_facts WHERE execution_origin='scheduled')
  OR EXISTS(SELECT 1 FROM iam_workflow_mutation_facts WHERE execution_origin='scheduled')
 THEN RAISE EXCEPTION 'SQL043 rollback refused: scheduled mutation facts still present';END IF;
END;$$;

CREATE OR REPLACE FUNCTION m11_validate_control_mutation_fact() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE w workflows%ROWTYPE;e workflow_executions%ROWTYPE;s workflow_steps%ROWTYPE;i control_change_intents%ROWTYPE;a audit_events%ROWTYPE;
 c clusters%ROWTYPE;anchor workspaces%ROWTYPE;target workspaces%ROWTYPE;ds data_sources%ROWTYPE;author users%ROWTYPE;sid auth_sessions%ROWTYPE;epoch bigint;r recycle_entries%ROWTYPE;
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
  ELSIF NEW.resource='recycle-bin' THEN
   PERFORM m11_require_recycle_read_committed();
   SELECT * INTO r FROM recycle_entries WHERE cluster_id=NEW.cluster_id AND id=NEW.resource_id;
   IF NEW.operation<>'purge' OR r.id IS NULL OR r.revision IS DISTINCT FROM NEW.after_revision
    OR r.state IS DISTINCT FROM 'purged' OR r.payload_secret IS NOT NULL OR r.purged_at IS NULL THEN
    RAISE EXCEPTION 'Purge completion requires its exact versioned payload tombstone' USING ERRCODE='23514';END IF;
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

CREATE OR REPLACE FUNCTION m11_validate_iam_mutation_fact() RETURNS trigger LANGUAGE plpgsql AS $$
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

ALTER TABLE control_workflow_mutation_facts DROP CONSTRAINT control_fact_origin_claim,DROP COLUMN schedule_claim_id,DROP COLUMN execution_origin;
ALTER TABLE iam_workflow_mutation_facts DROP CONSTRAINT iam_fact_origin_claim,DROP COLUMN schedule_claim_id,DROP COLUMN execution_origin;
DELETE FROM schema_migrations WHERE name='043_m11_control_iam_scheduled_identity.sql';
