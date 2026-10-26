-- Reverts SQL053 (restores the SQL019 real-candidate minimum). Fails if any V2
-- self-approval vote exists, since those facts would no longer validate.
BEGIN;
DO $m$ DECLARE def text;BEGIN
  IF EXISTS(SELECT 1 FROM workflow_approvals a JOIN workflows w ON w.id=a.workflow_id WHERE a.is_self_approval AND w.approval_format=2)
  THEN RAISE EXCEPTION 'V2 self-approval facts exist; refusing to revert SQL053';END IF;
  def:=pg_get_functiondef('m11_assert_approval_facts(uuid,integer,text)'::regprocedure);
  def:=regexp_replace(def,'OR n NOT BETWEEN 0 AND 100 OR\(s\.stage_mode=''all'' AND n<1\) OR n\+\(CASE .*? END\)<GREATEST\(s\.required_approvals,1\)','OR n NOT BETWEEN 1 AND 100 OR n<s.required_approvals');
  EXECUTE def;
END $m$;
DROP TRIGGER workflow_approvals_candidate_ref ON workflow_approvals;
DROP FUNCTION m11_validate_approval_candidate();
ALTER TABLE workflow_approvals ADD CONSTRAINT workflow_approvals_candidate_fk FOREIGN KEY (cluster_id, workspace_id, workflow_id, plan_revision, plan_hash, candidate_version, candidate_manifest_hmac, level, approver_id) REFERENCES workflow_candidates(cluster_id, workspace_id, workflow_id, plan_revision, plan_hash, candidate_version, manifest_hmac, level, user_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
DELETE FROM schema_migrations WHERE name='053_m11_self_approval_v2_stages.sql';
COMMIT;
