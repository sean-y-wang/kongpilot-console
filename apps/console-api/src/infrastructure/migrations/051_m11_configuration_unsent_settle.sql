-- SQL051: audited settle for uncertain schedule-origin configuration_v2 jobs
-- that NEVER opened a remote mutation (no mutation_operations row; remote send
-- never started). Closes via verified-not-applied (single approval-level
-- readback) or abandoned (two-person) with mutation_id NULL. Fresh Kong
-- readback only — never writes Kong. Fails closed if a mutation later appears.
-- Rollback: deploy/db-rollback/051_m11_configuration_unsent_settle.down.sql

CREATE TABLE workflow_unsent_result_abandon_requests (
 id uuid PRIMARY KEY,
 cluster_id uuid NOT NULL,
 workspace_id uuid NOT NULL,
 workflow_id uuid NOT NULL,
 workflow_execution_id uuid NOT NULL REFERENCES workflow_executions(id) ON DELETE RESTRICT,
 configuration_job_id uuid NOT NULL REFERENCES configuration_jobs(id) ON DELETE RESTRICT,
 requester_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 session_id uuid NOT NULL,
 reason_hmac text NOT NULL CHECK(m8_hex64(reason_hmac)),
 ticket text NOT NULL CHECK(length(ticket) BETWEEN 1 AND 200),
 observation_hmac text NOT NULL CHECK(m8_hex64(observation_hmac)),
 audit_id uuid NOT NULL UNIQUE,
 audit_event_hash text NOT NULL CHECK(m8_hex64(audit_event_hash)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz NULL,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours'),
 FOREIGN KEY(session_id,requester_id) REFERENCES auth_sessions(id,user_id) ON DELETE RESTRICT,
 FOREIGN KEY(audit_id,audit_event_hash) REFERENCES audit_events(id,event_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX workflow_unsent_result_abandon_open ON workflow_unsent_result_abandon_requests(workflow_execution_id) WHERE consumed_at IS NULL;

CREATE FUNCTION m11_unsent_result_abandon_request_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE e workflow_executions%ROWTYPE; j configuration_jobs%ROWTYPE; a audit_events%ROWTYPE; o workflow_execution_origins%ROWTYPE;
BEGIN
 IF TG_OP='INSERT' THEN
  SELECT * INTO e FROM workflow_executions WHERE id=NEW.workflow_execution_id FOR SHARE;
  SELECT * INTO o FROM workflow_execution_origins WHERE execution_id=NEW.workflow_execution_id FOR SHARE;
  SELECT * INTO j FROM configuration_jobs WHERE id=NEW.configuration_job_id FOR SHARE;
  SELECT * INTO a FROM audit_events WHERE id=NEW.audit_id;
  IF e.id IS NULL OR o.id IS NULL OR j.id IS NULL OR a.id IS NULL
   OR e.state IS DISTINCT FROM 'uncertain' OR e.cluster_id IS DISTINCT FROM NEW.cluster_id OR e.workspace_id IS DISTINCT FROM NEW.workspace_id
   OR e.workflow_id IS DISTINCT FROM NEW.workflow_id
   OR j.cluster_id IS DISTINCT FROM NEW.cluster_id OR j.workspace_id IS DISTINCT FROM NEW.workspace_id
   OR j.workflow_id IS DISTINCT FROM NEW.workflow_id OR j.state NOT IN('running','uncertain')
   OR j.remote_started IS DISTINCT FROM false
   OR EXISTS(SELECT 1 FROM mutation_operations m WHERE m.workflow_id=NEW.workflow_id)
   OR EXISTS(SELECT 1 FROM mutation_operations m WHERE m.configuration_job_id=NEW.configuration_job_id)
   OR NEW.consumed_at IS NOT NULL
   OR a.actor_id IS DISTINCT FROM NEW.requester_id OR a.action IS DISTINCT FROM 'workflow.unsent-result.abandon-requested'
   OR a.after->>'requestId' IS DISTINCT FROM NEW.id::text OR a.after->>'nativeRequestsSent' IS DISTINCT FROM '0'
   OR a.after->>'knownNoNativeSend' IS DISTINCT FROM 'true'
  THEN RAISE EXCEPTION 'Unsent abandon request requires an uncertain schedule-origin execution with a never-sent configuration job and its audit' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' AND OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL
  AND (to_jsonb(NEW)-'consumed_at')=(to_jsonb(OLD)-'consumed_at') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Unsent abandon requests are immutable evidence' USING ERRCODE='23514';
END;$$;
CREATE TRIGGER workflow_unsent_result_abandon_request_guard
 BEFORE INSERT OR UPDATE OR DELETE ON workflow_unsent_result_abandon_requests FOR EACH ROW EXECUTE FUNCTION m11_unsent_result_abandon_request_guard();
CREATE TRIGGER workflow_unsent_result_abandon_request_truncate
 BEFORE TRUNCATE ON workflow_unsent_result_abandon_requests FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();

ALTER TABLE workflow_unknown_result_dispositions
 ADD COLUMN unsent_abandon_request_id uuid NULL UNIQUE REFERENCES workflow_unsent_result_abandon_requests(id) ON DELETE RESTRICT;
ALTER TABLE workflow_unknown_result_dispositions DROP CONSTRAINT workflow_unknown_result_abandon_binding;
ALTER TABLE workflow_unknown_result_dispositions ADD CONSTRAINT workflow_unknown_result_abandon_binding
 CHECK((disposition='abandoned')=((abandon_request_id IS NOT NULL) OR (unsent_abandon_request_id IS NOT NULL))
   AND NOT(abandon_request_id IS NOT NULL AND unsent_abandon_request_id IS NOT NULL));
ALTER TABLE workflow_unknown_result_dispositions ADD CONSTRAINT workflow_unknown_result_unsent_abandon_null_mutation
 CHECK(unsent_abandon_request_id IS NULL OR mutation_id IS NULL);
-- SQL044 required original_remote_started for every non-rejected disposition.
-- Never-sent settles have no mutation receipt; allow NULL remote flags then.
ALTER TABLE workflow_unknown_result_dispositions DROP CONSTRAINT workflow_unknown_result_dispositions_check2;
ALTER TABLE workflow_unknown_result_dispositions ADD CONSTRAINT workflow_unknown_result_dispositions_check2
 CHECK(disposition='verification-rejected' OR original_remote_started IS NOT NULL
   OR (mutation_id IS NULL AND disposition IN('verified-not-applied','abandoned')));

CREATE OR REPLACE FUNCTION m11_validate_unknown_result_disposition(p_row workflow_unknown_result_dispositions) RETURNS void
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE e workflow_executions%ROWTYPE; o workflow_execution_origins%ROWTYPE; c workflow_schedule_claims%ROWTYPE;
 s workflow_schedules%ROWTYPE; m mutation_operations%ROWTYPE; a audit_events%ROWTYPE;
 u users%ROWTYPE; sid auth_sessions%ROWTYPE; r workflow_unknown_result_abandon_requests%ROWTYPE;
 ur workflow_unsent_result_abandon_requests%ROWTYPE; expected text;
BEGIN
 SELECT * INTO e FROM workflow_executions WHERE id=p_row.workflow_execution_id FOR SHARE;
 SELECT * INTO o FROM workflow_execution_origins WHERE execution_id=p_row.workflow_execution_id FOR SHARE;
 SELECT * INTO c FROM workflow_schedule_claims WHERE id=p_row.claim_id FOR SHARE;
 SELECT * INTO s FROM workflow_schedules WHERE id=p_row.schedule_id FOR SHARE;
 SELECT * INTO a FROM audit_events WHERE id=p_row.audit_id;
 SELECT * INTO u FROM users WHERE id=p_row.actor_id FOR SHARE;
 SELECT * INTO sid FROM auth_sessions WHERE id=p_row.session_id AND user_id=p_row.actor_id FOR SHARE;
 IF p_row.mutation_id IS NOT NULL THEN SELECT * INTO m FROM mutation_operations WHERE id=p_row.mutation_id FOR SHARE; END IF;
 IF e.id IS NULL OR o.id IS NULL OR c.id IS NULL OR s.id IS NULL OR a.id IS NULL OR u.id IS NULL OR sid.id IS NULL
  OR e.state IS DISTINCT FROM 'uncertain' OR e.cluster_id IS DISTINCT FROM p_row.cluster_id OR e.workspace_id IS DISTINCT FROM p_row.workspace_id
  OR e.workflow_id IS DISTINCT FROM p_row.workflow_id OR e.plan_revision IS DISTINCT FROM p_row.workflow_plan_revision OR e.plan_hash IS DISTINCT FROM p_row.workflow_plan_hash
  OR o.claim_id IS DISTINCT FROM p_row.claim_id OR o.schedule_id IS DISTINCT FROM p_row.schedule_id OR o.workflow_id IS DISTINCT FROM p_row.workflow_id
  OR o.cluster_id IS DISTINCT FROM p_row.cluster_id OR o.workspace_id IS DISTINCT FROM p_row.workspace_id
  OR o.workflow_plan_revision IS DISTINCT FROM p_row.workflow_plan_revision OR o.workflow_plan_hash IS DISTINCT FROM p_row.workflow_plan_hash
  OR c.schedule_id IS DISTINCT FROM p_row.schedule_id OR s.cluster_id IS DISTINCT FROM p_row.cluster_id OR s.workspace_id IS DISTINCT FROM p_row.workspace_id
  OR u.status<>'active' OR u.deleted_at IS NOT NULL OR u.force_password_change
  OR sid.revoked_at IS NOT NULL OR sid.expires_at<=clock_timestamp() OR sid.credential_epoch IS DISTINCT FROM u.credential_epoch
  OR sid.credential_epoch IS DISTINCT FROM p_row.credential_epoch OR u.credential_epoch IS DISTINCT FROM p_row.credential_epoch
 THEN RAISE EXCEPTION 'Unknown-result disposition requires the live operator session and exact schedule-origin uncertain execution' USING ERRCODE='23514';END IF;
 IF p_row.mutation_id IS NOT NULL AND (
   m.id IS NULL OR m.cluster_id IS DISTINCT FROM p_row.cluster_id OR m.workspace_id IS DISTINCT FROM p_row.workspace_id
   OR NOT (m.workflow_execution_id IS NOT DISTINCT FROM p_row.workflow_execution_id OR (m.workflow_execution_id IS NULL AND EXISTS(
     SELECT 1 FROM workflow_configuration_execution_origins x JOIN configuration_executions ce ON ce.id=x.configuration_execution_id
     WHERE x.configuration_execution_id=m.configuration_execution_id AND x.workflow_execution_id=p_row.workflow_execution_id
      AND x.claim_id=p_row.claim_id AND x.workflow_id=p_row.workflow_id AND x.cluster_id=p_row.cluster_id AND x.workspace_id=p_row.workspace_id
      AND x.workflow_plan_revision=p_row.workflow_plan_revision AND x.workflow_plan_hash=p_row.workflow_plan_hash
      AND ce.cluster_id=m.cluster_id AND ce.workspace_id=m.workspace_id AND ce.state='uncertain'))) OR m.state IS DISTINCT FROM 'uncertain'
   OR m.state IS DISTINCT FROM p_row.original_mutation_state
   OR m.remote_started IS DISTINCT FROM p_row.original_remote_started OR m.remote_completed IS DISTINCT FROM p_row.original_remote_completed
   OR m.error_code IS DISTINCT FROM p_row.original_error_code
 ) THEN RAISE EXCEPTION 'Unknown-result disposition cannot rewrite or mismatch the original mutation receipt' USING ERRCODE='23514';END IF;
 -- SQL051: closing without a mutation must prove the workflow still has none.
 IF p_row.mutation_id IS NULL AND p_row.disposition IN('verified-not-applied','abandoned')
  AND EXISTS(SELECT 1 FROM mutation_operations mo WHERE mo.workflow_id=p_row.workflow_id)
 THEN RAISE EXCEPTION 'Unsent disposition refuses because a mutation later appeared' USING ERRCODE='23514';END IF;
 IF p_row.disposition='abandoned' THEN
  IF p_row.unsent_abandon_request_id IS NOT NULL THEN
   SELECT * INTO ur FROM workflow_unsent_result_abandon_requests WHERE id=p_row.unsent_abandon_request_id FOR UPDATE;
   IF ur.id IS NULL OR p_row.mutation_id IS NOT NULL OR ur.workflow_execution_id IS DISTINCT FROM p_row.workflow_execution_id
    OR ur.workflow_id IS DISTINCT FROM p_row.workflow_id OR ur.cluster_id IS DISTINCT FROM p_row.cluster_id OR ur.workspace_id IS DISTINCT FROM p_row.workspace_id
    OR ur.requester_id=p_row.actor_id OR ur.consumed_at IS NOT NULL OR ur.expires_at<=clock_timestamp()
    OR a.after->>'unsentAbandonRequestId' IS DISTINCT FROM ur.id::text OR a.after->>'requesterId' IS DISTINCT FROM ur.requester_id::text
    OR a.after->>'knownNoNativeSend' IS DISTINCT FROM 'true'
   THEN RAISE EXCEPTION 'Unsent abandoned disposition requires an open unsent request by a different approver' USING ERRCODE='23514';END IF;
  ELSIF p_row.abandon_request_id IS NOT NULL THEN
   SELECT * INTO r FROM workflow_unknown_result_abandon_requests WHERE id=p_row.abandon_request_id FOR UPDATE;
   IF r.id IS NULL OR p_row.mutation_id IS NULL OR m.workflow_execution_id IS NOT NULL OR r.mutation_id IS DISTINCT FROM p_row.mutation_id
    OR r.cluster_id IS DISTINCT FROM p_row.cluster_id OR r.workspace_id IS DISTINCT FROM p_row.workspace_id
    OR r.workflow_execution_id IS DISTINCT FROM p_row.workflow_execution_id OR r.requester_id=p_row.actor_id
    OR r.consumed_at IS NOT NULL OR r.expires_at<=clock_timestamp()
    OR a.after->>'abandonRequestId' IS DISTINCT FROM r.id::text OR a.after->>'requesterId' IS DISTINCT FROM r.requester_id::text
   THEN RAISE EXCEPTION 'Abandoned disposition requires an open request by a different approver' USING ERRCODE='23514';END IF;
  ELSE
   RAISE EXCEPTION 'Abandoned disposition requires an abandon request' USING ERRCODE='23514';
  END IF;
 ELSIF p_row.abandon_request_id IS NOT NULL OR p_row.unsent_abandon_request_id IS NOT NULL THEN
  RAISE EXCEPTION 'Only abandoned dispositions may reference an abandon request' USING ERRCODE='23514';
 END IF;
 IF p_row.mutation_id IS NULL AND (p_row.original_mutation_state IS NOT NULL OR p_row.original_remote_started IS NOT NULL OR p_row.original_remote_completed IS NOT NULL OR p_row.original_error_code IS NOT NULL)
 THEN RAISE EXCEPTION 'Unknown-result disposition without mutation cannot carry mutation receipt fields' USING ERRCODE='23514';END IF;
 -- verified-applied without a mutation is never legal (send ledger missing).
 IF p_row.disposition='verified-applied' AND p_row.mutation_id IS NULL
 THEN RAISE EXCEPTION 'Verified-applied disposition requires a mutation receipt' USING ERRCODE='23514';END IF;
 expected=CASE p_row.disposition
  WHEN 'verified-applied' THEN 'succeeded'
  WHEN 'verified-not-applied' THEN 'failed'
  WHEN 'abandoned' THEN 'failed'
  ELSE 'uncertain' END;
 IF a.actor_id IS DISTINCT FROM p_row.actor_id OR a.cluster_id IS DISTINCT FROM p_row.cluster_id OR a.workspace_id IS DISTINCT FROM p_row.workspace_id
  OR a.workflow_id IS DISTINCT FROM p_row.workflow_id OR a.entity_type IS DISTINCT FROM 'workflows' OR a.entity_id IS DISTINCT FROM p_row.workflow_id::text
  OR a.action IS DISTINCT FROM 'workflow.unknown-result.disposed' OR a.result IS DISTINCT FROM 'success'
  OR a.event_hash IS DISTINCT FROM p_row.audit_event_hash
  OR a.after->>'dispositionId' IS DISTINCT FROM p_row.id::text OR a.after->>'disposition' IS DISTINCT FROM p_row.disposition
  OR a.after->>'claimId' IS DISTINCT FROM p_row.claim_id::text OR a.after->>'executionId' IS DISTINCT FROM p_row.workflow_execution_id::text
  OR a.after->>'evidenceHmac' IS DISTINCT FROM p_row.evidence_hmac OR a.after->>'requestHmac' IS DISTINCT FROM p_row.request_hmac
  OR a.after->>'nativeRequestsSent' IS DISTINCT FROM '0' OR a.after->>'expectedMetadataState' IS DISTINCT FROM expected
 THEN RAISE EXCEPTION 'Unknown-result disposition requires its scoped audit with zero native sends' USING ERRCODE='23514';END IF;
END;$$;

CREATE OR REPLACE FUNCTION m11_unknown_result_disposition_insert() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('workflow-unknown-result:'||NEW.claim_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('workflow-schedule-claim:'||NEW.claim_id::text,0));
 PERFORM m11_validate_unknown_result_disposition(NEW);
 IF NEW.disposition='abandoned' THEN
  IF NEW.abandon_request_id IS NOT NULL THEN
   UPDATE workflow_unknown_result_abandon_requests SET consumed_at=clock_timestamp() WHERE id=NEW.abandon_request_id AND consumed_at IS NULL;
  END IF;
  IF NEW.unsent_abandon_request_id IS NOT NULL THEN
   UPDATE workflow_unsent_result_abandon_requests SET consumed_at=clock_timestamp() WHERE id=NEW.unsent_abandon_request_id AND consumed_at IS NULL;
  END IF;
 END IF;
 RETURN NEW;
END;$$;

REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON workflow_unsent_result_abandon_requests FROM PUBLIC;
