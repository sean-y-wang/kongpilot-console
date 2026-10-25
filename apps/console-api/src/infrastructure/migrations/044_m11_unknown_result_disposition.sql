-- KP-003 / historical SQL042 unknown-result disposition (lands as 044; repo 042 is annotation identity).
-- Additive certified dispositions for schedule-origin uncertain executions/mutations.
-- Never rewrites sent-unknown events, never sends Native, never invents KnownNotSent.
-- Rollback: deploy/db-rollback/044_m11_unknown_result_disposition.down.sql
CREATE TABLE workflow_unknown_result_dispositions (
 id uuid PRIMARY KEY,
 cluster_id uuid NOT NULL,
 workspace_id uuid NOT NULL,
 schedule_id uuid NOT NULL,
 claim_id uuid NOT NULL,
 workflow_id uuid NOT NULL,
 workflow_execution_id uuid NOT NULL,
 workflow_plan_revision integer NOT NULL CHECK(workflow_plan_revision>0),
 workflow_plan_hash text NOT NULL CHECK(m8_hex64(workflow_plan_hash)),
 mutation_id uuid NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 session_id uuid NOT NULL,
 credential_epoch bigint NOT NULL CHECK(credential_epoch>0),
 disposition text NOT NULL CHECK(disposition IN('verified-applied','verified-not-applied','verification-rejected')),
 original_execution_state text NOT NULL CHECK(original_execution_state='uncertain'),
 original_mutation_state text NULL CHECK(original_mutation_state IS NULL OR original_mutation_state='uncertain'),
 original_remote_started boolean NULL,
 original_remote_completed boolean NULL,
 original_error_code text NULL,
 evidence_hmac text NOT NULL CHECK(m8_hex64(evidence_hmac)),
 request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 audit_id uuid NOT NULL UNIQUE,
 audit_event_hash text NOT NULL CHECK(m8_hex64(audit_event_hash)),
 observed_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,schedule_id) REFERENCES workflow_schedules(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(claim_id) REFERENCES workflow_schedule_claims(id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash)
  REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(session_id,actor_id) REFERENCES auth_sessions(id,user_id) ON DELETE RESTRICT,
 FOREIGN KEY(audit_id,audit_event_hash) REFERENCES audit_events(id,event_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(observed_at<=created_at AND created_at-observed_at<=interval '5 minutes'),
 CHECK((disposition='verification-rejected') OR (mutation_id IS NOT NULL)=(original_mutation_state IS NOT NULL)),
 CHECK(disposition='verification-rejected' OR original_remote_started IS NOT NULL)
);
CREATE UNIQUE INDEX workflow_unknown_result_closing_claim
 ON workflow_unknown_result_dispositions(claim_id)
 WHERE disposition IN('verified-applied','verified-not-applied');
CREATE INDEX workflow_unknown_result_execution_idx ON workflow_unknown_result_dispositions(workflow_execution_id);

CREATE OR REPLACE FUNCTION m11_validate_unknown_result_disposition(p_row workflow_unknown_result_dispositions) RETURNS void
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE e workflow_executions%ROWTYPE; o workflow_execution_origins%ROWTYPE; c workflow_schedule_claims%ROWTYPE;
 s workflow_schedules%ROWTYPE; m mutation_operations%ROWTYPE; a audit_events%ROWTYPE;
 u users%ROWTYPE; sid auth_sessions%ROWTYPE; expected text;
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
   OR m.workflow_execution_id IS DISTINCT FROM p_row.workflow_execution_id OR m.state IS DISTINCT FROM 'uncertain'
   OR m.state IS DISTINCT FROM p_row.original_mutation_state
   OR m.remote_started IS DISTINCT FROM p_row.original_remote_started OR m.remote_completed IS DISTINCT FROM p_row.original_remote_completed
   OR m.error_code IS DISTINCT FROM p_row.original_error_code
 ) THEN RAISE EXCEPTION 'Unknown-result disposition cannot rewrite or mismatch the original mutation receipt' USING ERRCODE='23514';END IF;
 IF p_row.mutation_id IS NULL AND (p_row.original_mutation_state IS NOT NULL OR p_row.original_remote_started IS NOT NULL OR p_row.original_remote_completed IS NOT NULL OR p_row.original_error_code IS NOT NULL)
 THEN RAISE EXCEPTION 'Unknown-result disposition without mutation cannot carry mutation receipt fields' USING ERRCODE='23514';END IF;
 expected=CASE p_row.disposition
  WHEN 'verified-applied' THEN 'succeeded'
  WHEN 'verified-not-applied' THEN 'failed'
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

CREATE FUNCTION m11_unknown_result_disposition_insert() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('workflow-unknown-result:'||NEW.claim_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('workflow-schedule-claim:'||NEW.claim_id::text,0));
 PERFORM m11_validate_unknown_result_disposition(NEW);
 RETURN NEW;
END;$$;
CREATE TRIGGER workflow_unknown_result_disposition_guard
 BEFORE INSERT ON workflow_unknown_result_dispositions FOR EACH ROW EXECUTE FUNCTION m11_unknown_result_disposition_insert();

-- Schedule-origin uncertain → succeeded/failed requires a closing disposition.
-- Target SQL027 observations keep their own guard and are explicitly excluded.
CREATE OR REPLACE FUNCTION m11_unknown_result_state_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE d workflow_unknown_result_dispositions%ROWTYPE; origin_id uuid; expected text;
BEGIN
 IF OLD.state IS DISTINCT FROM 'uncertain' OR NEW.state NOT IN('succeeded','failed') THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='workflow_executions' THEN
  SELECT o.id INTO origin_id FROM workflow_execution_origins o WHERE o.execution_id=OLD.id;
  IF origin_id IS NULL THEN RETURN NEW; END IF;
  IF EXISTS(SELECT 1 FROM entity_change_target_result_observations t WHERE t.workflow_execution_id=OLD.id) THEN RETURN NEW; END IF;
  expected=CASE WHEN NEW.state='succeeded' THEN 'verified-applied' ELSE 'verified-not-applied' END;
  SELECT * INTO d FROM workflow_unknown_result_dispositions
   WHERE workflow_execution_id=OLD.id AND disposition=expected;
  IF d.id IS NULL OR d.cluster_id IS DISTINCT FROM OLD.cluster_id OR d.workspace_id IS DISTINCT FROM OLD.workspace_id
   OR d.workflow_id IS DISTINCT FROM OLD.workflow_id
   OR (to_jsonb(NEW)-ARRAY['state','revision','updated_at','safe_result','completed_at','error_code'])
      IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','revision','updated_at','safe_result','completed_at','error_code'])
  THEN RAISE EXCEPTION 'Schedule-origin uncertain closure requires its exact unknown-result disposition' USING ERRCODE='23514';END IF;
  RETURN NEW;
 ELSIF TG_TABLE_NAME='mutation_operations' THEN
  IF OLD.workflow_execution_id IS NULL THEN RETURN NEW; END IF;
  SELECT o.id INTO origin_id FROM workflow_execution_origins o WHERE o.execution_id=OLD.workflow_execution_id;
  IF origin_id IS NULL THEN RETURN NEW; END IF;
  IF EXISTS(SELECT 1 FROM entity_change_target_result_observations t WHERE t.operation_id=OLD.id) THEN RETURN NEW; END IF;
  expected=CASE WHEN NEW.state='succeeded' THEN 'verified-applied' ELSE 'verified-not-applied' END;
  SELECT * INTO d FROM workflow_unknown_result_dispositions
   WHERE mutation_id=OLD.id AND disposition=expected;
  IF d.id IS NULL OR d.workflow_execution_id IS DISTINCT FROM OLD.workflow_execution_id
   OR d.original_remote_started IS DISTINCT FROM OLD.remote_started
   OR d.original_remote_completed IS DISTINCT FROM OLD.remote_completed
   OR d.original_error_code IS DISTINCT FROM OLD.error_code
   OR (to_jsonb(NEW)-ARRAY['state','updated_at','safe_result','error_code','recovery_revision'])
      IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','updated_at','safe_result','error_code','recovery_revision'])
  THEN RAISE EXCEPTION 'Schedule-origin uncertain mutation closure requires its exact unknown-result disposition' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 RETURN NEW;
END;$$;
CREATE TRIGGER workflow_executions_unknown_result_guard
 BEFORE UPDATE ON workflow_executions FOR EACH ROW EXECUTE FUNCTION m11_unknown_result_state_guard();
CREATE TRIGGER mutation_operations_unknown_result_guard
 BEFORE UPDATE ON mutation_operations FOR EACH ROW EXECUTE FUNCTION m11_unknown_result_state_guard();

CREATE TRIGGER workflow_unknown_result_dispositions_immutable
 BEFORE UPDATE OR DELETE ON workflow_unknown_result_dispositions FOR EACH ROW EXECUTE FUNCTION m8_immutable();
CREATE TRIGGER workflow_unknown_result_dispositions_no_truncate
 BEFORE TRUNCATE ON workflow_unknown_result_dispositions FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON workflow_unknown_result_dispositions FROM PUBLIC;
