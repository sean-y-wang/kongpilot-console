-- SQL052: optional super-admin self-approval (default OFF).
-- A requester may approve their own console workflow only when ALL hold at
-- vote time: the DB-persisted platform setting is on, the voter is the
-- requester, the voter is an active super_admin, and the vote row carries the
-- explicit is_self_approval marker. Workflow definitions keep
-- allow_self_approval=false; the exception is a platform override, recorded
-- per vote and per workflow so historical facts re-validate even after the
-- setting is switched off again.

CREATE TABLE workflow_self_approval_settings (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  super_admin_self_approval boolean NOT NULL DEFAULT false,
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  updated_by uuid REFERENCES users(id) ON DELETE RESTRICT,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO workflow_self_approval_settings(singleton) VALUES(true);

ALTER TABLE workflow_approvals ADD COLUMN is_self_approval boolean NOT NULL DEFAULT false;
ALTER TABLE workflows ADD COLUMN self_approved boolean NOT NULL DEFAULT false;

CREATE FUNCTION m11_self_approval_permitted(uid uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT COALESCE((SELECT super_admin_self_approval FROM workflow_self_approval_settings WHERE singleton),false)
    AND EXISTS(SELECT 1 FROM users u WHERE u.id=uid AND u.super_admin AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change)
$$;

-- Marker can only be set at insert, only by the requester, only when permitted.
CREATE FUNCTION m11_guard_self_approval_vote() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;
BEGIN
  SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
  IF NEW.is_self_approval THEN
    IF w.requester_type<>'console' OR NEW.approver_id IS DISTINCT FROM w.requester_user_id OR NEW.decision<>'approve'
      OR NOT m11_self_approval_permitted(NEW.approver_id) THEN
      RAISE EXCEPTION 'Self-approval requires the enabled super-admin override' USING ERRCODE='23514';
    END IF;
  ELSIF NEW.approver_id IS NOT DISTINCT FROM w.requester_user_id THEN
    RAISE EXCEPTION 'Workflow approval must be a distinct real console decision' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;$$;
CREATE TRIGGER workflow_approvals_self_approval BEFORE INSERT ON workflow_approvals FOR EACH ROW EXECUTE FUNCTION m11_guard_self_approval_vote();

-- workflows.self_approved: monotonic, and only with a recorded self vote by approved_by.
CREATE FUNCTION m11_guard_workflow_self_approved() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='UPDATE' AND OLD.self_approved AND NOT NEW.self_approved THEN
    RAISE EXCEPTION 'self_approved is immutable once recorded' USING ERRCODE='23514';END IF;
  IF NEW.self_approved AND (NEW.approved_by IS DISTINCT FROM NEW.requester_user_id OR NOT EXISTS(
      SELECT 1 FROM workflow_approvals a WHERE a.workflow_id=NEW.id AND a.plan_revision=NEW.plan_revision AND a.plan_hash=NEW.plan_hash
        AND a.approver_id=NEW.approved_by AND a.decision='approve' AND a.is_self_approval)) THEN
    RAISE EXCEPTION 'self_approved requires a recorded super-admin self-approval vote' USING ERRCODE='23514';END IF;
  RETURN NEW;
END;$$;
CREATE TRIGGER workflows_self_approved BEFORE INSERT OR UPDATE OF self_approved,approved_by ON workflows FOR EACH ROW EXECUTE FUNCTION m11_guard_workflow_self_approved();

-- Relax the table CHECK (008) to accept a recorded self-approval.
DO $m$ DECLARE c record;n integer:=0;BEGIN
  FOR c IN SELECT conname FROM pg_constraint WHERE conrelid='workflows'::regclass AND contype='c'
    AND pg_get_constraintdef(oid) ILIKE '%approved_by IS DISTINCT FROM requester_user_id%' LOOP
    EXECUTE format('ALTER TABLE workflows DROP CONSTRAINT %I',c.conname);n:=n+1;END LOOP;
  IF n<>1 THEN RAISE EXCEPTION 'SQL052 expected exactly one approved_by/requester CHECK, found %',n;END IF;
END;$m$;
ALTER TABLE workflows ADD CONSTRAINT workflows_approved_by_not_requester
  CHECK(approved_by IS NULL OR approved_by IS DISTINCT FROM requester_user_id OR self_approved);

-- Patch the requester!=approver predicates in the current trigger functions
-- (008/019). Each replacement must match exactly once or the migration fails.
DO $m$
DECLARE fn text;src text;out text;pairs text[][];i integer;
BEGIN
  FOREACH fn IN ARRAY ARRAY['m11_assert_vote_stage()','m11_assert_approval_facts(uuid,integer,text)','m6_validate_approval_fact()'] LOOP
    src:=pg_get_functiondef(fn::regprocedure);out:=src;
    IF fn='m11_assert_vote_stage()' THEN
      pairs:=ARRAY[ARRAY['OR NEW.approver_id IS NOT DISTINCT FROM w.requester_user_id OR NOT w.approval_required','OR (NEW.approver_id IS NOT DISTINCT FROM w.requester_user_id AND NOT NEW.is_self_approval) OR NOT w.approval_required']];
    ELSIF fn='m6_validate_approval_fact()' THEN
      pairs:=ARRAY[ARRAY['OR NEW.approver_id IS NOT DISTINCT FROM w.requester_user_id OR NEW.decided_at','OR (NEW.approver_id IS NOT DISTINCT FROM w.requester_user_id AND NOT NEW.is_self_approval) OR NEW.decided_at'],
                   ARRAY['OR aid IS NOT DISTINCT FROM w.requester_user_id','OR (aid IS NOT DISTINCT FROM w.requester_user_id AND NOT w.self_approved)']];
    ELSE
      pairs:=ARRAY[ARRAY['OR a.approver_id IS NOT DISTINCT FROM w.requester_user_id OR a.decided_at','OR (a.approver_id IS NOT DISTINCT FROM w.requester_user_id AND NOT a.is_self_approval) OR a.decided_at']];
    END IF;
    FOR i IN 1..array_length(pairs,1) LOOP
      IF (length(out)-length(replace(out,pairs[i][1],'')))/length(pairs[i][1])<>1 THEN
        RAISE EXCEPTION 'SQL052 predicate % not found exactly once in %',i,fn;END IF;
      out:=replace(out,pairs[i][1],pairs[i][2]);
    END LOOP;
    EXECUTE out;
  END LOOP;
END;$m$;
