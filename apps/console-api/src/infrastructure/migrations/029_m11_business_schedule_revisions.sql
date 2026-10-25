-- A first business schedule is sealed as a fresh approval-plan revision before
-- any vote or execution. Previous immutable plans/candidates/stages are kept.
-- SQL 000--028 are unchanged. Source must additionally retain its genuine
-- authoring HTTP SID, live permissions, encrypted subject seal and audit.
CREATE FUNCTION m11_business_schedule_revision_unused(fid uuid) RETURNS boolean LANGUAGE sql AS $$
 SELECT NOT EXISTS(SELECT 1 FROM workflow_approvals WHERE workflow_id=fid)
  AND NOT EXISTS(SELECT 1 FROM workflow_approval_sets WHERE workflow_id=fid)
  AND NOT EXISTS(SELECT 1 FROM workflow_approval_set_members WHERE workflow_id=fid)
  AND NOT EXISTS(SELECT 1 FROM workflow_executions WHERE workflow_id=fid)
  AND NOT EXISTS(SELECT 1 FROM mutation_operations WHERE workflow_id=fid)
  AND NOT EXISTS(SELECT 1 FROM configuration_executions WHERE workflow_id=fid)
  AND NOT EXISTS(SELECT 1 FROM workflow_execution_origins WHERE workflow_id=fid)
  AND NOT EXISTS(SELECT 1 FROM workflow_configuration_execution_origins WHERE workflow_id=fid)
  AND NOT EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=fid
    AND(state IS DISTINCT FROM 'pending' OR operation_id IS NOT NULL OR receipt_secret IS NOT NULL OR started_at IS NOT NULL OR completed_at IS NOT NULL));
$$;

-- This narrow predicate is called only from the existing workflows approval
-- binding trigger. The proposed intermediate NULL candidate pointer is not a
-- commit-valid workflow: the deferred completion guard below requires the
-- same-transaction 026 draft and a complete freshly frozen V2 candidate graph.
CREATE FUNCTION m11_business_schedule_pointer_advance(old_workflow workflows,new_workflow workflows) RETURNS boolean LANGUAGE plpgsql AS $$
 BEGIN
 PERFORM version FROM iam_epoch WHERE singleton=true FOR SHARE;
 IF NOT FOUND OR old_workflow.approval_format IS DISTINCT FROM 2 OR new_workflow.approval_format IS DISTINCT FROM 2
  OR old_workflow.state IS DISTINCT FROM 'pending' OR new_workflow.state IS DISTINCT FROM 'pending'
  OR old_workflow.kind NOT IN('configuration_v2','portal-credential-issue')
  OR old_workflow.execution_mode IS DISTINCT FROM new_workflow.execution_mode
  OR old_workflow.kind='configuration_v2' AND old_workflow.execution_mode IS DISTINCT FROM 'approval'
  OR old_workflow.kind='portal-credential-issue' AND old_workflow.execution_mode NOT IN('direct','approval')
  OR old_workflow.approval_required IS DISTINCT FROM true OR new_workflow.approval_required IS DISTINCT FROM true
  OR old_workflow.candidate_version IS NULL OR old_workflow.candidate_manifest_hmac IS NULL
  OR new_workflow.candidate_version IS NOT NULL OR new_workflow.candidate_manifest_hmac IS NOT NULL
  OR old_workflow.approval_set_id IS NOT NULL OR old_workflow.approval_set_hmac IS NOT NULL
  OR new_workflow.approval_set_id IS NOT NULL OR new_workflow.approval_set_hmac IS NOT NULL
  OR old_workflow.approved_by IS NOT NULL OR old_workflow.approved_at IS NOT NULL OR new_workflow.approved_by IS NOT NULL OR new_workflow.approved_at IS NOT NULL
  OR new_workflow.plan_revision IS DISTINCT FROM old_workflow.plan_revision+1 OR new_workflow.revision IS DISTINCT FROM old_workflow.revision+1
  OR new_workflow.plan_hash IS NOT DISTINCT FROM old_workflow.plan_hash OR NOT m8_hex64(new_workflow.plan_hash)
  OR old_workflow.not_before IS NOT NULL OR old_workflow.window_start IS NOT NULL OR old_workflow.window_end IS NOT NULL
  OR new_workflow.not_before IS NULL OR new_workflow.window_start IS NULL OR new_workflow.window_end IS NULL
  OR new_workflow.window_start>new_workflow.not_before OR new_workflow.not_before>=new_workflow.window_end
  OR new_workflow.window_end>old_workflow.expires_at OR new_workflow.window_end<=clock_timestamp() OR new_workflow.updated_at<old_workflow.updated_at
  OR(to_jsonb(new_workflow)-ARRAY['plan_revision','plan_hash','revision','updated_at','not_before','window_start','window_end','candidate_version','candidate_manifest_hmac'])
    IS DISTINCT FROM(to_jsonb(old_workflow)-ARRAY['plan_revision','plan_hash','revision','updated_at','not_before','window_start','window_end','candidate_version','candidate_manifest_hmac'])
  OR NOT m11_business_schedule_revision_unused(old_workflow.id)
  OR EXISTS(SELECT 1 FROM workflow_schedules WHERE workflow_id=old_workflow.id)
  OR EXISTS(SELECT 1 FROM workflow_versions WHERE workflow_id=old_workflow.id AND plan_revision=new_workflow.plan_revision)
  OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=old_workflow.id AND plan_revision=new_workflow.plan_revision)
  OR EXISTS(SELECT 1 FROM workflow_stages WHERE workflow_id=old_workflow.id AND plan_revision=new_workflow.plan_revision)
  OR EXISTS(SELECT 1 FROM workflow_candidate_versions WHERE workflow_id=old_workflow.id AND plan_revision=new_workflow.plan_revision)
 THEN RETURN false;END IF;
 RETURN true;
 END;
$$;

-- The three original SQL019 protections are preserved. Only the workflows
-- candidate reassignment branch recognizes the exact first-schedule advance;
-- workflow_executions still uses its original format/assigned-set protections.
CREATE OR REPLACE FUNCTION m11_guard_approval_bindings() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF NEW.approval_format<>OLD.approval_format THEN RAISE EXCEPTION 'Approval format is immutable' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='workflows' THEN
  IF OLD.candidate_version IS NOT NULL AND ROW(NEW.candidate_version,NEW.candidate_manifest_hmac) IS DISTINCT FROM ROW(OLD.candidate_version,OLD.candidate_manifest_hmac)
   AND NOT m11_business_schedule_pointer_advance(OLD::workflows,NEW::workflows)
  THEN RAISE EXCEPTION 'Candidate manifest is assigned once' USING ERRCODE='23514';END IF;
 END IF;
 IF OLD.approval_set_id IS NOT NULL AND ROW(NEW.approval_set_id,NEW.approval_set_hmac) IS DISTINCT FROM ROW(OLD.approval_set_id,OLD.approval_set_hmac)
 THEN RAISE EXCEPTION 'Approval set is assigned once' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;$$;

CREATE FUNCTION m11_business_schedule_revision_complete() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE w workflows%ROWTYPE;s workflow_schedules%ROWTYPE;d workflow_executor_delegations%ROWTYPE;p workflow_schedule_progress%ROWTYPE;
  v workflow_versions%ROWTYPE;c workflow_candidate_versions%ROWTYPE;u users%ROWTYPE;registry clusters%ROWTYPE;current_iam bigint;
 BEGIN
 IF OLD.candidate_version IS NULL OR NEW.candidate_version IS NOT NULL
  OR ROW(NEW.candidate_version,NEW.candidate_manifest_hmac) IS NOT DISTINCT FROM ROW(OLD.candidate_version,OLD.candidate_manifest_hmac) THEN RETURN NULL;END IF;
 SELECT version INTO current_iam FROM iam_epoch WHERE singleton=true FOR SHARE;
 SELECT * INTO w FROM workflows WHERE id=NEW.id;
 SELECT * INTO s FROM workflow_schedules WHERE workflow_id=NEW.id AND workflow_plan_revision=NEW.plan_revision;
 SELECT * INTO d FROM workflow_executor_delegations WHERE id=s.delegation_id;
 SELECT * INTO p FROM workflow_schedule_progress WHERE schedule_id=s.id;
 SELECT * INTO v FROM workflow_versions WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision;
 SELECT * INTO c FROM workflow_candidate_versions WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision AND candidate_version=1;
 SELECT * INTO u FROM users WHERE id=s.owner_id FOR SHARE;
 SELECT * INTO registry FROM clusters WHERE id=w.cluster_id AND deleted_at IS NULL FOR SHARE;
 IF current_iam IS NULL OR w.id IS NULL OR s.id IS NULL OR d.id IS NULL OR p.schedule_id IS NULL OR v.workflow_id IS NULL OR c.workflow_id IS NULL OR u.id IS NULL OR registry.id IS NULL
  OR (to_jsonb(w)-ARRAY['candidate_version','candidate_manifest_hmac']) IS DISTINCT FROM(to_jsonb(NEW)-ARRAY['candidate_version','candidate_manifest_hmac'])
  OR w.state IS DISTINCT FROM 'pending' OR w.approval_format IS DISTINCT FROM 2 OR w.approval_required IS DISTINCT FROM true
  OR w.candidate_version IS DISTINCT FROM 1 OR w.candidate_manifest_hmac IS NULL OR w.candidate_manifest_hmac IS NOT DISTINCT FROM OLD.candidate_manifest_hmac
  OR w.approved_by IS NOT NULL OR w.approved_at IS NOT NULL OR w.approval_set_id IS NOT NULL OR w.approval_set_hmac IS NOT NULL
  OR NOT m11_business_schedule_revision_unused(w.id)
  OR (SELECT count(*) FROM workflow_schedules WHERE workflow_id=w.id)<>1
  OR (SELECT count(*) FROM workflow_executor_delegations WHERE workflow_id=w.id)<>1
  OR s.base_plan_hash IS DISTINCT FROM d.base_plan_hash OR NOT m8_hex64(s.base_plan_hash) OR s.base_plan_hash IS NOT DISTINCT FROM OLD.plan_hash
  OR w.execution_mode IS DISTINCT FROM registry.execution_mode OR registry.status IN('disabled','incompatible')
  OR w.kind='configuration_v2' AND w.execution_mode IS DISTINCT FROM 'approval'
  OR w.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')
  OR ROW(s.cluster_id,s.workspace_id,s.workflow_id,s.workflow_plan_revision,s.workflow_plan_hash,s.kind,s.definition_id,s.definition_version,s.not_before,s.window_start,s.window_end,s.expires_at)
    IS DISTINCT FROM ROW(w.cluster_id,w.workspace_id,w.id,w.plan_revision,w.plan_hash,w.kind,w.definition_id,w.definition_version,w.not_before,w.window_start,w.window_end,w.expires_at)
  OR ROW(v.cluster_id,v.workspace_id,v.workflow_id,v.plan_revision,v.plan_hash,v.execution_mode,v.approval_required,v.approval_format,v.expires_at,v.created_by)
    IS DISTINCT FROM ROW(w.cluster_id,w.workspace_id,w.id,w.plan_revision,w.plan_hash,w.execution_mode,w.approval_required,w.approval_format,w.expires_at,s.owner_id)
  OR v.created_by_developer_id IS NOT NULL
  OR ROW(c.cluster_id,c.workspace_id,c.workflow_id,c.plan_revision,c.plan_hash,c.definition_id,c.definition_version,c.policy_hash,c.manifest_hmac)
    IS DISTINCT FROM ROW(w.cluster_id,w.workspace_id,w.id,w.plan_revision,w.plan_hash,w.definition_id,w.definition_version,s.policy_hash,w.candidate_manifest_hmac)
  OR p.state IS DISTINCT FROM 'pending-approval' OR p.claim_id IS NOT NULL OR p.revision<>1
  OR EXISTS(SELECT 1 FROM workflow_schedule_activations WHERE schedule_id=s.id)
  OR EXISTS(SELECT 1 FROM workflow_schedule_claims WHERE schedule_id=s.id)
  OR EXISTS(SELECT 1 FROM workflow_schedule_outcomes WHERE schedule_id=s.id)
  OR u.status IS DISTINCT FROM 'active' OR u.deleted_at IS NOT NULL OR u.force_password_change
  OR u.credential_epoch IS DISTINCT FROM s.owner_credential_epoch OR s.owner_id IS DISTINCT FROM s.executor_id
  OR s.owner_credential_epoch IS DISTINCT FROM s.executor_credential_epoch
  OR s.requester_type IS DISTINCT FROM w.requester_type
  OR s.requester_id IS DISTINCT FROM (CASE WHEN w.requester_type='console' THEN w.requester_user_id ELSE w.requester_developer_id END)
  OR s.requester_type='console' AND(s.requester_id IS DISTINCT FROM s.owner_id OR s.requester_credential_epoch IS DISTINCT FROM s.owner_credential_epoch)
  OR s.requester_type='developer' AND NOT EXISTS(SELECT 1 FROM portal_developers developer WHERE developer.id=s.requester_id
    AND developer.cluster_id=s.cluster_id AND developer.workspace_id=s.workspace_id AND developer.status='active' AND developer.deleted_at IS NULL
    AND NOT developer.must_change_password AND developer.credential_epoch=s.requester_credential_epoch)
  OR s.window_start>s.not_before OR s.not_before>=s.window_end OR s.window_end>s.expires_at OR s.window_end<=clock_timestamp()
 THEN RAISE EXCEPTION 'First scheduled revision requires a complete fresh unvoted business draft and candidate graph' USING ERRCODE='23514';END IF;
 -- All existing normalized policy/manifest/stage/threshold/distinctness checks
 -- still run, including current exact V2 policy and zero-vote pending stages.
 PERFORM m11_assert_approval_facts(w.id,w.plan_revision,w.plan_hash);
 RETURN NULL;
 END;
$$;
CREATE CONSTRAINT TRIGGER workflows_business_schedule_revision_complete AFTER UPDATE ON workflows
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_business_schedule_revision_complete();

-- No table/row is deleted, no history is backfilled, and no privilege or
-- Native authority is granted. The existing immutable table triggers remain.
