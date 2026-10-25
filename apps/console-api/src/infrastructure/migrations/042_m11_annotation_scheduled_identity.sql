-- SQL042: scheduled execution identity for entity-annotation (owner decision 2026-10-24).
-- A scheduled run has no live HTTP session. Its mutation fact keeps the requester's
-- authoring-session snapshot (session_id = intent.authoring_session_id, same user and
-- credential epoch) but liveness of that session is NOT required; instead the fact must be
-- bound to the exact SQL026 workflow_execution_origins row of the claim that ran it.
-- Everything else (active user, current permission/iam version equal to the intent's,
-- credential epoch, cluster/workspace state, audit) is rechecked exactly as for HTTP.
-- HTTP-session facts ('session') are unchanged: live, unrevoked, unexpired session required.
-- Rollback: deploy/db-rollback/042_m11_annotation_scheduled_identity.down.sql
ALTER TABLE annotation_workflow_mutation_facts
 ADD COLUMN execution_origin text NOT NULL DEFAULT 'session' CHECK(execution_origin IN('session','scheduled')),
 ADD COLUMN schedule_claim_id uuid NULL UNIQUE REFERENCES workflow_schedule_claims(id) ON DELETE RESTRICT,
 ADD CONSTRAINT annotation_fact_origin_claim CHECK((execution_origin='scheduled')=(schedule_claim_id IS NOT NULL));
CREATE OR REPLACE FUNCTION m11_validate_annotation_mutation_fact() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE w workflows%ROWTYPE;e workflow_executions%ROWTYPE;s workflow_steps%ROWTYPE;i annotation_change_intents%ROWTYPE;a audit_events%ROWTYPE;
 c clusters%ROWTYPE;ws workspaces%ROWTYPE;annotation entity_annotations%ROWTYPE;author users%ROWTYPE;sid auth_sessions%ROWTYPE;epoch bigint;o workflow_execution_origins%ROWTYPE;
BEGIN
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;SELECT * INTO e FROM workflow_executions WHERE id=NEW.execution_id;SELECT * INTO s FROM workflow_steps WHERE id=NEW.step_id;
 SELECT * INTO i FROM annotation_change_intents WHERE id=NEW.intent_id;SELECT * INTO a FROM audit_events WHERE id=NEW.audit_id;SELECT * INTO c FROM clusters WHERE id=NEW.cluster_id;
 SELECT * INTO ws FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=NEW.workspace_id;SELECT * INTO annotation FROM entity_annotations WHERE cluster_id=NEW.cluster_id AND entity_type=NEW.entity_type AND kong_id=NEW.entity_id;
 SELECT * INTO author FROM users WHERE id=NEW.actor_id;SELECT * INTO sid FROM auth_sessions WHERE id=NEW.session_id;SELECT version INTO epoch FROM iam_epoch WHERE singleton=true;
 IF NEW.execution_origin='scheduled' THEN SELECT * INTO o FROM workflow_execution_origins WHERE execution_id=NEW.execution_id; END IF;
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
  OR author.status<>'active' OR author.deleted_at IS NOT NULL OR author.force_password_change OR sid.user_id IS DISTINCT FROM author.id OR (NEW.execution_origin='session' AND (NEW.schedule_claim_id IS NOT NULL OR sid.revoked_at IS NOT NULL OR sid.expires_at<=clock_timestamp()))
  OR (NEW.execution_origin='scheduled' AND (o.id IS NULL OR NEW.schedule_claim_id IS NULL OR o.claim_id IS DISTINCT FROM NEW.schedule_claim_id OR o.executor_id IS DISTINCT FROM NEW.actor_id
   OR o.workflow_id IS DISTINCT FROM NEW.workflow_id OR o.workflow_plan_hash IS DISTINCT FROM NEW.plan_hash OR o.workflow_plan_revision IS DISTINCT FROM NEW.plan_revision
   OR o.cluster_id IS DISTINCT FROM NEW.cluster_id OR o.workspace_id IS DISTINCT FROM NEW.workspace_id))
  OR sid.credential_epoch IS DISTINCT FROM author.credential_epoch OR i.credential_epoch IS DISTINCT FROM author.credential_epoch OR i.expires_at<=clock_timestamp()
  OR c.deleted_at IS NOT NULL OR c.status='disabled' OR c.execution_mode<>'approval' OR ws.status<>'active' OR ws.deleted_at IS NOT NULL
  OR annotation.revision IS DISTINCT FROM NEW.after_revision OR (NEW.operation='remove' AND annotation.status IS DISTINCT FROM 'deleted') OR (NEW.operation<>'remove' AND annotation.status IS DISTINCT FROM 'active')
  OR NEW.audit_action IS DISTINCT FROM (CASE WHEN NEW.operation='remove' THEN 'annotation.metadata.deleted' WHEN NEW.operation='restore' THEN 'annotation.metadata.restored' WHEN NEW.before_revision=0 THEN 'annotation.metadata.created' ELSE 'annotation.metadata.updated' END)
  OR a.actor_id IS DISTINCT FROM NEW.actor_id OR a.actor_type IS DISTINCT FROM 'user' OR a.cluster_id IS DISTINCT FROM NEW.cluster_id OR a.workspace_id IS DISTINCT FROM NEW.workspace_id
  OR a.workflow_id IS DISTINCT FROM NEW.workflow_id OR a.entity_type IS DISTINCT FROM NEW.entity_type OR a.entity_id IS DISTINCT FROM NEW.entity_id::text OR a.action IS DISTINCT FROM NEW.audit_action OR a.result IS DISTINCT FROM 'success'
 THEN RAISE EXCEPTION 'Annotation mutation fact requires its exact original completed metadata transaction and audit' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
