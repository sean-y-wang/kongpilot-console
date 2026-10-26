-- SQL053: extend the SQL052 super-admin self-approval override to V2
-- (multi-stage, candidate-manifest) workflows. SQL052 already relaxed the
-- requester-vote predicates; this relaxes only the frozen stage's
-- minimum-real-candidate count by one virtual requester slot, while the
-- override is permitted, a marked self vote exists in that stage, or the
-- workflow is terminal without approval. Candidate manifests stay
-- free of the requester; 'all' stages still require >=1 real candidate.
DO $m$ DECLARE def text;nxt text;BEGIN
  def:=pg_get_functiondef('m11_assert_approval_facts(uuid,integer,text)'::regprocedure);
  nxt:=replace(def,'OR n NOT BETWEEN 1 AND 100 OR n<s.required_approvals',
    'OR n NOT BETWEEN 0 AND 100 OR(s.stage_mode=''all'' AND n<1) OR n+(CASE WHEN s.stage_mode<>''all'' AND w.requester_type=''console'' AND(m11_self_approval_permitted(w.requester_user_id) OR w.state IN(''cancelled'',''expired'',''rejected'') OR EXISTS(SELECT 1 FROM workflow_approvals sa WHERE sa.workflow_id=fid AND sa.plan_revision=rev AND sa.level=s.level AND sa.is_self_approval)) THEN 1 ELSE 0 END)<GREATEST(s.required_approvals,1)');
  IF nxt=def THEN RAISE EXCEPTION 'SQL053: candidate-count anchor not found';END IF;EXECUTE nxt;
END $m$;

-- Marked self votes are not frozen candidates, so the composite candidate FK
-- becomes a deferred constraint trigger that exempts only is_self_approval rows
-- (whose validity SQL052 guards at insert). Candidate rows are already immutable (workflow_candidates_immutable).
ALTER TABLE workflow_approvals DROP CONSTRAINT workflow_approvals_candidate_fk;
CREATE FUNCTION m11_validate_approval_candidate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.candidate_version IS NULL OR NEW.candidate_manifest_hmac IS NULL OR NEW.is_self_approval THEN RETURN NULL;END IF;
  IF NOT EXISTS(SELECT 1 FROM workflow_candidates c WHERE c.cluster_id=NEW.cluster_id AND c.workspace_id=NEW.workspace_id AND c.workflow_id=NEW.workflow_id
      AND c.plan_revision=NEW.plan_revision AND c.plan_hash=NEW.plan_hash AND c.candidate_version=NEW.candidate_version AND c.manifest_hmac=NEW.candidate_manifest_hmac
      AND c.level=NEW.level AND c.user_id=NEW.approver_id) THEN
    RAISE EXCEPTION 'V2 vote must reference its frozen candidate' USING ERRCODE='23503';END IF;
  RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER workflow_approvals_candidate_ref AFTER INSERT OR UPDATE ON workflow_approvals DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_approval_candidate();
