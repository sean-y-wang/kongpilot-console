-- SQL049: unknown-result dispositions for schedule-origin configuration_v2 mutations.
-- Such mutations have workflow_execution_id NULL and link to their workflow
-- execution only via workflow_configuration_execution_origins. SQL044 refused
-- to dispose them (no supported way out of an uncertain transport fence) and
-- its state guard left them unguarded. This replaces both functions so the
-- exact origin link is accepted AND uncertain->terminal requires the closing
-- disposition. Native-binding triggers are untouched: closure is state-only.
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

CREATE OR REPLACE FUNCTION m11_unknown_result_state_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE d workflow_unknown_result_dispositions%ROWTYPE; origin_id uuid; linked uuid; expected text;
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
  IF OLD.workflow_execution_id IS NULL THEN
   -- SQL049: schedule-origin configuration_v2 mutations carry no workflow_execution_id;
   -- their exact link is workflow_configuration_execution_origins.
   SELECT x.workflow_execution_id INTO linked FROM workflow_configuration_execution_origins x
    WHERE OLD.configuration_execution_id IS NOT NULL AND x.configuration_execution_id=OLD.configuration_execution_id;
   IF linked IS NULL THEN RETURN NEW; END IF;
  ELSE
   linked=OLD.workflow_execution_id;
   SELECT o.id INTO origin_id FROM workflow_execution_origins o WHERE o.execution_id=OLD.workflow_execution_id;
   IF origin_id IS NULL THEN RETURN NEW; END IF;
  END IF;
  IF EXISTS(SELECT 1 FROM entity_change_target_result_observations t WHERE t.operation_id=OLD.id) THEN RETURN NEW; END IF;
  expected=CASE WHEN NEW.state='succeeded' THEN 'verified-applied' ELSE 'verified-not-applied' END;
  SELECT * INTO d FROM workflow_unknown_result_dispositions
   WHERE mutation_id=OLD.id AND disposition=expected;
  IF d.id IS NULL OR d.workflow_execution_id IS DISTINCT FROM linked
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
