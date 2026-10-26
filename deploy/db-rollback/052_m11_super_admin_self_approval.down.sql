-- Rollback SQL052. Refused while any self-approval fact exists.
BEGIN;
DO $d$ BEGIN
 IF EXISTS(SELECT 1 FROM workflow_approvals WHERE is_self_approval) OR EXISTS(SELECT 1 FROM workflows WHERE self_approved) THEN
  RAISE EXCEPTION 'SQL052 rollback refused: self-approval facts exist';END IF;
END $d$;
DO $m$
DECLARE fn text;src text;pairs text[][];i integer;
BEGIN
  FOREACH fn IN ARRAY ARRAY['m11_assert_vote_stage()','m11_assert_approval_facts(uuid,integer,text)','m6_validate_approval_fact()'] LOOP
    src:=pg_get_functiondef(fn::regprocedure);
    pairs:=ARRAY[ARRAY['(NEW.approver_id IS NOT DISTINCT FROM w.requester_user_id AND NOT NEW.is_self_approval)','NEW.approver_id IS NOT DISTINCT FROM w.requester_user_id'],
                 ARRAY['(aid IS NOT DISTINCT FROM w.requester_user_id AND NOT w.self_approved)','aid IS NOT DISTINCT FROM w.requester_user_id'],
                 ARRAY['(a.approver_id IS NOT DISTINCT FROM w.requester_user_id AND NOT a.is_self_approval)','a.approver_id IS NOT DISTINCT FROM w.requester_user_id']];
    FOR i IN 1..3 LOOP src:=replace(src,pairs[i][1],pairs[i][2]);END LOOP;
    EXECUTE src;
  END LOOP;
END $m$;
ALTER TABLE workflows DROP CONSTRAINT workflows_approved_by_not_requester;
ALTER TABLE workflows ADD CHECK(approved_by IS NULL OR approved_by IS DISTINCT FROM requester_user_id);
DROP TRIGGER workflows_self_approved ON workflows;DROP FUNCTION m11_guard_workflow_self_approved();
DROP TRIGGER workflow_approvals_self_approval ON workflow_approvals;DROP FUNCTION m11_guard_self_approval_vote();
DROP FUNCTION m11_self_approval_permitted(uuid);
ALTER TABLE workflows DROP COLUMN self_approved;
ALTER TABLE workflow_approvals DROP COLUMN is_self_approval;
DROP TABLE workflow_self_approval_settings;
DELETE FROM schema_migrations WHERE name='052_m11_super_admin_self_approval.sql';
COMMIT;
