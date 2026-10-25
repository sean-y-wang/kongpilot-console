-- A new permission fact belongs to the actual newly inserted execution.
-- Historical HTTP executions remain NULL. No backfill, invented authority or
-- change to 000--027 is permitted; an old NULL row cannot acquire this fact.
ALTER TABLE workflow_executions ADD COLUMN permission_version text;
ALTER TABLE workflow_executions ADD CONSTRAINT workflow_execution_permission_shape
 CHECK(permission_version IS NULL OR permission_version ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:[1-9][0-9]*:[1-9][0-9]*$');

-- Preserve every M6 captured identity column and its DELETE refusal. Only the
-- new permission fact joins the same existing immutable-identity contract.
DROP TRIGGER workflow_executions_identity ON workflow_executions;
CREATE TRIGGER workflow_executions_identity BEFORE UPDATE OR DELETE ON workflow_executions FOR EACH ROW
 EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,claim_token_hash,request_id,idempotency_key,expires_at,started_at,permission_version');

-- This supplements, never replaces, SQL 026 workflow_business_origin and its
-- live claim/progress/lease checks. SQL 019 approval facts, M6 snapshots,
-- progress, physical reservations and all foreign keys continue to execute.
-- IAM is locked before reading the current principal, matching claim lock
-- order. Equality with actual IAM epochs rejects NULL, caller-invented and
-- stale permission strings. It does not confer an entity or secret grant.
CREATE FUNCTION m11_business_origin_permission() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE s workflow_schedules%ROWTYPE;c workflow_schedule_claims%ROWTYPE;e workflow_executions%ROWTYPE;w workflows%ROWTYPE;u users%ROWTYPE;registry clusters%ROWTYPE;
  current_iam bigint;expected_permission text;
 BEGIN
 SELECT version INTO current_iam FROM iam_epoch WHERE singleton=true FOR SHARE;
 SELECT * INTO s FROM workflow_schedules WHERE id=NEW.schedule_id;
 SELECT * INTO c FROM workflow_schedule_claims WHERE id=NEW.claim_id;
 SELECT * INTO e FROM workflow_executions WHERE id=NEW.execution_id;
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 SELECT * INTO u FROM users WHERE id=NEW.executor_id FOR SHARE;
 SELECT * INTO registry FROM clusters WHERE id=NEW.cluster_id AND deleted_at IS NULL FOR SHARE;
 expected_permission=u.id::text||':'||u.permissions_epoch::text||':'||current_iam::text;
 IF current_iam IS NULL OR s.id IS NULL OR c.id IS NULL OR e.id IS NULL OR w.id IS NULL OR u.id IS NULL OR registry.id IS NULL
  OR u.status IS DISTINCT FROM 'active' OR u.deleted_at IS NOT NULL OR u.force_password_change
  OR u.credential_epoch IS DISTINCT FROM s.executor_credential_epoch
  OR s.owner_id IS DISTINCT FROM s.executor_id OR s.owner_credential_epoch IS DISTINCT FROM s.executor_credential_epoch
  OR NEW.executor_id IS DISTINCT FROM s.executor_id OR e.execution_actor_id IS DISTINCT FROM s.executor_id
  OR e.permission_version IS DISTINCT FROM expected_permission
  OR ROW(s.cluster_id,s.workspace_id,s.workflow_id,s.workflow_plan_revision,s.workflow_plan_hash)
   IS DISTINCT FROM ROW(NEW.cluster_id,NEW.workspace_id,NEW.workflow_id,NEW.workflow_plan_revision,NEW.workflow_plan_hash)
  OR ROW(c.cluster_id,c.workspace_id,c.schedule_id,c.workflow_id,c.workflow_plan_revision,c.workflow_plan_hash)
   IS DISTINCT FROM ROW(s.cluster_id,s.workspace_id,s.id,s.workflow_id,s.workflow_plan_revision,s.workflow_plan_hash)
  OR ROW(e.cluster_id,e.workspace_id,e.workflow_id,e.plan_revision,e.plan_hash)
   IS DISTINCT FROM ROW(s.cluster_id,s.workspace_id,s.workflow_id,s.workflow_plan_revision,s.workflow_plan_hash)
  OR ROW(w.cluster_id,w.workspace_id,w.id,w.plan_revision,w.plan_hash,w.kind)
   IS DISTINCT FROM ROW(s.cluster_id,s.workspace_id,s.workflow_id,s.workflow_plan_revision,s.workflow_plan_hash,s.kind)
  OR w.state NOT IN('approved','executing') OR e.state NOT IN('claimed','executing')
  OR e.execution_mode IS DISTINCT FROM w.execution_mode OR w.execution_mode IS DISTINCT FROM registry.execution_mode
  OR registry.status IN('disabled','incompatible')
  OR s.kind='configuration_v2' AND w.execution_mode IS DISTINCT FROM 'approval'
  OR s.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')
  OR e.approval_required IS DISTINCT FROM true OR w.approval_required IS DISTINCT FROM true
  OR clock_timestamp()<s.not_before OR clock_timestamp()<s.window_start OR clock_timestamp()>=s.window_end
  OR s.expires_at<=clock_timestamp() OR c.authority_expires_at<=clock_timestamp()
  OR e.started_at<c.issued_at OR e.expires_at>least(c.authority_expires_at,s.window_end,s.expires_at,w.expires_at)
  OR s.requester_type='developer' AND NOT EXISTS(SELECT 1 FROM portal_developers d WHERE d.cluster_id=s.cluster_id AND d.workspace_id=s.workspace_id
   AND d.id=s.requester_id AND d.status='active' AND d.deleted_at IS NULL AND NOT d.must_change_password AND d.credential_epoch=s.requester_credential_epoch)
 THEN RAISE EXCEPTION 'Scheduled wrapper requires its actual current immutable permission fact' USING ERRCODE='23514';END IF;
 RETURN NEW;
 END;
$$;
CREATE TRIGGER workflow_business_origin_permission BEFORE INSERT ON workflow_execution_origins FOR EACH ROW EXECUTE FUNCTION m11_business_origin_permission();

-- Existing table-level runtime SELECT/INSERT privileges cover the new column;
-- no new UPDATE, DELETE, TRUNCATE, function definer or PUBLIC grant is needed.
