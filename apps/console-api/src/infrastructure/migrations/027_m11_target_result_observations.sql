-- An authenticated observation of an already-saved Target append response.
-- This grants no native authority, Source, lease, retry or recovery permission.
-- SQL validates real normalized identities; Root alone verifies AEAD/HMAC,
-- the frozen original producer's 201-before-response-HMAC branch, and genuine
-- bounded current parent/history/effective observations. NULL old status is
-- never rewritten into a native201 receipt. Old 000--026 facts/guards stay intact.
CREATE TABLE entity_change_target_result_observations (
 id uuid PRIMARY KEY,version integer NOT NULL DEFAULT 1 CHECK(version=1),
 proof_kind text NOT NULL DEFAULT 'target-weight-zero-original-response-v1' CHECK(proof_kind='target-weight-zero-original-response-v1'),
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,transport_scope text NOT NULL CHECK(m8_hex64(transport_scope)),
 cluster_revision integer NOT NULL CHECK(cluster_revision>0),workspace_revision integer NOT NULL CHECK(workspace_revision>0),
 source_id uuid NOT NULL UNIQUE,source_hmac text NOT NULL CHECK(m8_hex64(source_hmac)),
 intent_id uuid NOT NULL,intent_revision integer NOT NULL CHECK(intent_revision>0),
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),change_digest text NOT NULL CHECK(m8_hex64(change_digest)),packet_manifest_hmac text NOT NULL CHECK(m8_hex64(packet_manifest_hmac)),
 workflow_id uuid NOT NULL UNIQUE,workflow_plan_revision integer NOT NULL CHECK(workflow_plan_revision>0),workflow_plan_hash text NOT NULL CHECK(m8_hex64(workflow_plan_hash)),
 workflow_execution_id uuid NOT NULL UNIQUE,workflow_step_id uuid NOT NULL UNIQUE,
 execution_actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,credential_epoch bigint NOT NULL CHECK(credential_epoch>0),
 metadata_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,permission_version_hmac text NOT NULL CHECK(m8_hex64(permission_version_hmac)),
 original_execution_key text NOT NULL CHECK(length(original_execution_key) BETWEEN 8 AND 128),operation_key text NOT NULL CHECK(length(operation_key) BETWEEN 8 AND 128),
 request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 workflow_revision_before integer NOT NULL CHECK(workflow_revision_before>0),execution_revision_before integer NOT NULL CHECK(execution_revision_before>0),step_revision_before integer NOT NULL CHECK(step_revision_before>0),
 baseline_id uuid NOT NULL,baseline_hmac text NOT NULL CHECK(m8_hex64(baseline_hmac)),object_manifest_hmac text NOT NULL CHECK(m8_hex64(object_manifest_hmac)),pin_id uuid NOT NULL,
 attempt_id uuid NOT NULL UNIQUE,packet_key text NOT NULL CHECK(length(packet_key) BETWEEN 1 AND 160),packet_order integer NOT NULL DEFAULT 1 CHECK(packet_order=1),operation_id uuid NOT NULL UNIQUE,
 method text NOT NULL DEFAULT 'POST' CHECK(method='POST'),native_type text NOT NULL DEFAULT 'targets' CHECK(native_type='targets'),
 permission_action text NOT NULL DEFAULT 'write' CHECK(permission_action='write'),mutation_action text NOT NULL DEFAULT 'update' CHECK(mutation_action='update'),
 parent_id uuid NOT NULL,original_native_id uuid NOT NULL,native_id uuid NOT NULL,weight integer NOT NULL DEFAULT 0 CHECK(weight=0),
 path_hmac text NOT NULL CHECK(m8_hex64(path_hmac)),body_hmac text NOT NULL CHECK(m8_hex64(body_hmac)),before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),
 target_address_hmac text NOT NULL CHECK(m8_hex64(target_address_hmac)),result_hmac text NOT NULL CHECK(m8_hex64(result_hmac)),
 send_event_id uuid NOT NULL UNIQUE REFERENCES entity_change_packet_events(id) ON DELETE RESTRICT,send_fact_hmac text NOT NULL CHECK(m8_hex64(send_fact_hmac)),
 outcome_event_id uuid NOT NULL UNIQUE REFERENCES entity_change_packet_events(id) ON DELETE RESTRICT,outcome_fact_hmac text NOT NULL CHECK(m8_hex64(outcome_fact_hmac)),
 approval_set_id uuid NOT NULL,approval_set_hmac text NOT NULL CHECK(m8_hex64(approval_set_hmac)),
 history_proof_hmac text NOT NULL CHECK(m8_hex64(history_proof_hmac)),producer_attestation_hmac text NOT NULL CHECK(m8_hex64(producer_attestation_hmac)),
 current_observation_hmac text NOT NULL CHECK(m8_hex64(current_observation_hmac)),observation_hmac text NOT NULL CHECK(m8_hex64(observation_hmac)),
 observation_ciphertext text NOT NULL CHECK(m6_encrypted(observation_ciphertext,12582912)),
 certified_native_status integer NOT NULL DEFAULT 201 CHECK(certified_native_status=201),
 audit_id uuid NOT NULL UNIQUE,audit_event_hash text NOT NULL CHECK(m8_hex64(audit_event_hash)),
 current_observed_at timestamptz NOT NULL,observed_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(cluster_id,workspace_id,source_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,
  workflow_id,workflow_plan_revision,workflow_plan_hash,workflow_execution_id,execution_actor_id,credential_epoch)
 REFERENCES entity_change_execution_sources(cluster_id,workspace_id,id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,
  workflow_id,workflow_plan_revision,workflow_plan_hash,workflow_execution_id,execution_actor_id,credential_epoch) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,baseline_id,source_id,workflow_execution_id,baseline_hmac,object_manifest_hmac)
 REFERENCES entity_change_baselines(cluster_id,workspace_id,id,source_id,workflow_execution_id,baseline_hmac,object_manifest_hmac) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,pin_id,baseline_id,source_id,workflow_execution_id)
 REFERENCES entity_change_baseline_pins(cluster_id,workspace_id,id,baseline_id,source_id,workflow_execution_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,attempt_id,source_id,baseline_id,pin_id,workflow_execution_id)
 REFERENCES entity_change_packet_attempts(cluster_id,workspace_id,id,source_id,baseline_id,pin_id,workflow_execution_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,intent_id,intent_revision,packet_key,packet_order,material_hmac,change_digest,packet_manifest_hmac,
  method,path_hmac,native_type,native_id,permission_action,mutation_action,body_hmac,before_hmac)
 REFERENCES entity_change_intent_packets(cluster_id,workspace_id,intent_id,intent_revision,packet_key,packet_order,material_hmac,change_digest,packet_manifest_hmac,
  method,path_hmac,native_type,native_id,permission_action,mutation_action,body_hmac,before_hmac) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,operation_id) REFERENCES mutation_operations(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash)
 REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_step_id,workflow_id,workflow_plan_revision,workflow_plan_hash)
 REFERENCES workflow_steps(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,approval_set_id,approval_set_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash)
 REFERENCES workflow_approval_sets(cluster_id,workspace_id,id,set_hmac,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(audit_id,audit_event_hash) REFERENCES audit_events(id,event_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(original_native_id<>native_id AND send_event_id<>outcome_event_id),
 CHECK(current_observed_at<=observed_at AND observed_at<=created_at AND observed_at-current_observed_at<=interval '5 minutes')
);

-- Root appends the scoped audit first, then the observation while every mutable
-- state is still uncertain, then performs the four original-row CAS updates.
-- The seal/AAD excludes audit ID/hash to avoid a circular observation/audit seal:
-- entity-change-target-result-observation:<cid>:<wid>:<observation-id>:material.
CREATE FUNCTION m11_validate_target_result_observation(p_observation entity_change_target_result_observations,p_phase text) RETURNS void LANGUAGE plpgsql AS $$
 DECLARE v_source entity_change_execution_sources%ROWTYPE;v_version entity_change_intent_versions%ROWTYPE;
  v_baseline entity_change_baselines%ROWTYPE;v_pin entity_change_baseline_pins%ROWTYPE;v_attempt entity_change_packet_attempts%ROWTYPE;
  v_packet entity_change_intent_packets%ROWTYPE;v_mutation mutation_operations%ROWTYPE;v_workflow workflows%ROWTYPE;v_execution workflow_executions%ROWTYPE;v_step workflow_steps%ROWTYPE;
  v_send entity_change_packet_events%ROWTYPE;v_outcome entity_change_packet_events%ROWTYPE;v_audit audit_events%ROWTYPE;v_audit_scope audit_event_scopes%ROWTYPE;
  v_session auth_sessions%ROWTYPE;v_user users%ROWTYPE;v_cluster clusters%ROWTYPE;v_workspace workspaces%ROWTYPE;
  v_expected_state text;v_increment integer;
 BEGIN
 IF p_phase NOT IN('insert','complete') THEN RAISE EXCEPTION 'Invalid Target observation phase' USING ERRCODE='23514';END IF;
 v_expected_state=CASE WHEN p_phase='insert' THEN 'uncertain' ELSE 'succeeded' END;v_increment=CASE WHEN p_phase='insert' THEN 0 ELSE 1 END;
 SELECT * INTO v_source FROM entity_change_execution_sources WHERE id=p_observation.source_id;
 SELECT * INTO v_version FROM entity_change_intent_versions WHERE cluster_id=p_observation.cluster_id AND workspace_id=p_observation.workspace_id AND intent_id=p_observation.intent_id AND intent_revision=p_observation.intent_revision;
 SELECT * INTO v_baseline FROM entity_change_baselines WHERE id=p_observation.baseline_id;
 SELECT * INTO v_pin FROM entity_change_baseline_pins WHERE id=p_observation.pin_id;
 SELECT * INTO v_attempt FROM entity_change_packet_attempts WHERE id=p_observation.attempt_id;
 SELECT * INTO v_packet FROM entity_change_intent_packets WHERE cluster_id=p_observation.cluster_id AND workspace_id=p_observation.workspace_id AND intent_id=p_observation.intent_id AND intent_revision=p_observation.intent_revision AND packet_key=p_observation.packet_key;
 SELECT * INTO v_mutation FROM mutation_operations WHERE id=p_observation.operation_id;
 SELECT * INTO v_workflow FROM workflows WHERE id=p_observation.workflow_id;
 SELECT * INTO v_execution FROM workflow_executions WHERE id=p_observation.workflow_execution_id;
 SELECT * INTO v_step FROM workflow_steps WHERE id=p_observation.workflow_step_id;
 SELECT * INTO v_send FROM entity_change_packet_events WHERE id=p_observation.send_event_id;
 SELECT * INTO v_outcome FROM entity_change_packet_events WHERE id=p_observation.outcome_event_id;
 SELECT * INTO v_audit FROM audit_events WHERE id=p_observation.audit_id;
 SELECT * INTO v_audit_scope FROM audit_event_scopes WHERE audit_event_id=p_observation.audit_id;
 SELECT * INTO v_session FROM auth_sessions WHERE id=p_observation.metadata_session_id FOR SHARE;
 SELECT * INTO v_user FROM users WHERE id=p_observation.execution_actor_id FOR SHARE;
 SELECT * INTO v_cluster FROM clusters WHERE id=p_observation.cluster_id FOR SHARE;
 SELECT * INTO v_workspace FROM workspaces WHERE id=p_observation.workspace_id AND cluster_id=p_observation.cluster_id FOR SHARE;
 IF v_source.id IS NULL OR v_version.intent_id IS NULL OR v_baseline.id IS NULL OR v_pin.id IS NULL OR v_attempt.id IS NULL OR v_packet.packet_key IS NULL
  OR v_mutation.id IS NULL OR v_workflow.id IS NULL OR v_execution.id IS NULL OR v_step.id IS NULL OR v_send.id IS NULL OR v_outcome.id IS NULL
  OR v_source.origin_type<>'http' OR v_source.session_id IS NULL OR v_source.expires_at>clock_timestamp()
  OR v_source.permission_version_hmac IS DISTINCT FROM p_observation.permission_version_hmac
  OR v_version.packet_count<>1 OR v_version.requester_id IS DISTINCT FROM p_observation.execution_actor_id
  OR v_version.execution_mode<>'approval' OR v_baseline.readiness<>'ready' OR v_baseline.object_count<>3 OR v_baseline.graph_count<>1
  OR v_baseline.capture_hmac IS NULL OR v_pin.pin_version<>1 OR v_pin.previous_pin_id IS NOT NULL
  OR (SELECT count(*) FROM entity_change_intent_packets WHERE cluster_id=v_source.cluster_id AND workspace_id=v_source.workspace_id AND intent_id=v_source.intent_id AND intent_revision=v_source.intent_revision)<>1
  OR (SELECT count(*) FROM entity_change_packet_attempts WHERE source_id=v_source.id)<>1
  OR (SELECT count(*) FROM mutation_operations WHERE entity_change_source_id=v_source.id)<>1
  OR (SELECT count(*) FROM entity_change_packet_events WHERE source_id=v_source.id)<>2
 THEN RAISE EXCEPTION 'Observation requires one original HTTP Target attempt and complete frozen before facts' USING ERRCODE='23514';END IF;
 IF ROW(v_attempt.parent_id,v_attempt.original_native_id,v_attempt.credential_kind,v_packet.parent_id,v_packet.original_native_id,v_packet.credential_kind)
  IS DISTINCT FROM ROW(p_observation.parent_id,p_observation.original_native_id,NULL::text,p_observation.parent_id,p_observation.original_native_id,NULL::text)
  OR ROW(v_attempt.packet_order,v_attempt.method,v_attempt.native_type,v_attempt.permission_action,v_attempt.mutation_action,v_attempt.body_hmac,v_attempt.before_hmac,v_attempt.path_hmac)
   IS DISTINCT FROM ROW(1,'POST'::text,'targets'::text,'write'::text,'update'::text,p_observation.body_hmac,p_observation.before_hmac,p_observation.path_hmac)
  OR v_packet.dependencies<>'{}'::text[]
  OR NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects old_target WHERE old_target.baseline_id=v_baseline.id AND old_target.native_type='targets'
    AND old_target.native_id=p_observation.original_native_id AND old_target.parent_id=p_observation.parent_id AND old_target.credential_kind IS NULL
    AND old_target.affected AND old_target.present AND old_target.recovery='complete' AND old_target.before_hmac=p_observation.before_hmac)
  OR NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects allocated_target WHERE allocated_target.baseline_id=v_baseline.id AND allocated_target.native_type='targets'
    AND allocated_target.native_id=p_observation.native_id AND allocated_target.parent_id=p_observation.parent_id AND allocated_target.credential_kind IS NULL
    AND allocated_target.affected AND NOT allocated_target.present AND allocated_target.recovery='absent')
  OR NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects parent_object WHERE parent_object.baseline_id=v_baseline.id AND parent_object.native_type='upstreams'
    AND parent_object.native_id=p_observation.parent_id AND parent_object.parent_id IS NULL AND NOT parent_object.affected AND parent_object.present AND parent_object.recovery='reference')
 THEN RAISE EXCEPTION 'Observation is confined to the exact allocated Target append and its original parent/before/absence' USING ERRCODE='23514';END IF;
 IF ROW(v_mutation.cluster_id,v_mutation.workspace_id,v_mutation.workflow_id,v_mutation.actor_id,v_mutation.entity_change_source_id,v_mutation.entity_change_baseline_id,v_mutation.entity_change_attempt_id,v_mutation.entity_change_packet_key)
  IS DISTINCT FROM ROW(p_observation.cluster_id,p_observation.workspace_id,p_observation.workflow_id,p_observation.execution_actor_id,p_observation.source_id,p_observation.baseline_id,p_observation.attempt_id,p_observation.packet_key)
  OR v_mutation.state IS DISTINCT FROM v_expected_state OR v_mutation.entity_type<>'targets' OR v_mutation.action<>'update'
  OR v_mutation.parent_id IS DISTINCT FROM p_observation.parent_id::text OR v_mutation.entity_id IS DISTINCT FROM p_observation.native_id::text OR v_mutation.credential_kind IS NOT NULL
  OR v_mutation.transport_scope IS DISTINCT FROM p_observation.transport_scope OR v_mutation.idempotency_key IS DISTINCT FROM p_observation.operation_key
  OR p_observation.operation_key IS DISTINCT FROM 'entity-'||p_observation.workflow_execution_id::text||'-1'
  OR NOT v_mutation.remote_started OR NOT v_mutation.remote_completed OR v_mutation.result_secret IS NULL OR v_mutation.before_secret IS NULL OR v_mutation.payload_secret IS NULL
  OR v_mutation.error_code IS DISTINCT FROM 'KONG_VALIDATION_ERROR'
  OR num_nonnulls(v_mutation.workflow_execution_id,v_mutation.workflow_plan_revision,v_mutation.workflow_plan_hash,v_mutation.workflow_step_id,
    v_mutation.configuration_job_id,v_mutation.configuration_execution_id,v_mutation.configuration_step_id,v_mutation.configuration_plan_revision,v_mutation.configuration_plan_hash)<>0
 THEN RAISE EXCEPTION 'Observation cannot change the original V3 ledger identity, saved response or namespace' USING ERRCODE='23514';END IF;
 IF ROW(v_workflow.cluster_id,v_workflow.workspace_id,v_workflow.id,v_workflow.plan_revision,v_workflow.plan_hash,v_workflow.kind,v_workflow.subject_type,v_workflow.subject_id,v_workflow.requester_type,v_workflow.requester_user_id)
  IS DISTINCT FROM ROW(p_observation.cluster_id,p_observation.workspace_id,p_observation.workflow_id,p_observation.workflow_plan_revision,p_observation.workflow_plan_hash,'native-change'::text,'entity_change_intents'::text,p_observation.intent_id,'console'::text,p_observation.execution_actor_id)
  OR v_workflow.state IS DISTINCT FROM v_expected_state OR v_execution.state IS DISTINCT FROM v_expected_state OR v_step.state IS DISTINCT FROM v_expected_state
  OR v_workflow.revision<>p_observation.workflow_revision_before+v_increment OR v_execution.revision<>p_observation.execution_revision_before+v_increment OR v_step.revision<>p_observation.step_revision_before+v_increment
  OR v_execution.execution_actor_id IS DISTINCT FROM p_observation.execution_actor_id OR v_execution.idempotency_key IS DISTINCT FROM p_observation.original_execution_key
  OR NOT v_workflow.approval_required OR NOT v_execution.approval_required OR v_workflow.approval_format<>2 OR v_execution.approval_format<>2
  OR v_workflow.approval_set_id IS DISTINCT FROM p_observation.approval_set_id OR v_workflow.approval_set_hmac IS DISTINCT FROM p_observation.approval_set_hmac
  OR v_execution.approval_set_id IS DISTINCT FROM p_observation.approval_set_id OR v_execution.approval_set_hmac IS DISTINCT FROM p_observation.approval_set_hmac
  OR v_execution.snapshot_state<>'ready' OR v_execution.snapshot_id IS DISTINCT FROM p_observation.baseline_id OR v_execution.completed_at IS NULL
  OR v_step.kind<>'metadata' OR v_step.handler IS DISTINCT FROM 'entity.change' OR v_step.entity_type<>'entity_change_intents' OR v_step.entity_id IS DISTINCT FROM p_observation.intent_id
  OR v_step.step_order<>1 OR v_step.step_key<>'entity.change' OR v_step.dependencies<>'{}'::uuid[] OR v_step.native_requests<>'[]'::jsonb
  OR v_step.operation_id IS NOT NULL OR v_step.receipt_secret IS NOT NULL OR v_step.completed_at IS NULL
  OR (SELECT count(*) FROM workflow_steps WHERE workflow_id=v_workflow.id AND plan_revision=v_workflow.plan_revision)<>1
 THEN RAISE EXCEPTION 'All original metadata states and CAS revisions must describe the same approved execution' USING ERRCODE='23514';END IF;
 IF ROW(v_send.cluster_id,v_send.workspace_id,v_send.attempt_id,v_send.source_id,v_send.baseline_id,v_send.pin_id,v_send.workflow_execution_id,v_send.event_kind,v_send.fact_hmac)
  IS DISTINCT FROM ROW(p_observation.cluster_id,p_observation.workspace_id,p_observation.attempt_id,p_observation.source_id,p_observation.baseline_id,p_observation.pin_id,p_observation.workflow_execution_id,'send-intent'::text,p_observation.send_fact_hmac)
  OR v_send.outcome IS NOT NULL OR v_send.native_status IS NOT NULL OR v_send.error_code IS NOT NULL
  OR ROW(v_outcome.cluster_id,v_outcome.workspace_id,v_outcome.attempt_id,v_outcome.source_id,v_outcome.baseline_id,v_outcome.pin_id,v_outcome.workflow_execution_id,v_outcome.event_kind,v_outcome.fact_hmac)
   IS DISTINCT FROM ROW(p_observation.cluster_id,p_observation.workspace_id,p_observation.attempt_id,p_observation.source_id,p_observation.baseline_id,p_observation.pin_id,p_observation.workflow_execution_id,'outcome'::text,p_observation.outcome_fact_hmac)
  OR v_outcome.outcome IS DISTINCT FROM 'sent-unknown' OR v_outcome.native_status IS NOT NULL OR v_outcome.error_code IS DISTINCT FROM 'MUTATION_RESULT_UNCERTAIN'
  OR v_send.observed_at>v_outcome.observed_at OR v_outcome.observed_at>p_observation.current_observed_at
 THEN RAISE EXCEPTION 'Original sent-unknown events and NULL native status must remain untouched' USING ERRCODE='23514';END IF;
 IF v_user.id IS NULL OR v_session.id IS NULL OR v_cluster.id IS NULL OR v_workspace.id IS NULL
  OR v_user.status<>'active' OR v_user.deleted_at IS NOT NULL OR v_user.force_password_change OR v_user.credential_epoch IS DISTINCT FROM p_observation.credential_epoch
  OR v_session.user_id IS DISTINCT FROM p_observation.execution_actor_id OR v_session.credential_epoch IS DISTINCT FROM p_observation.credential_epoch OR v_session.revoked_at IS NOT NULL OR v_session.expires_at<=clock_timestamp()
  OR v_cluster.deleted_at IS NOT NULL OR v_cluster.status IN('disabled','incompatible') OR v_cluster.version IS NULL OR v_cluster.version!~'^1\.5\.[0-9]+$'
  -- A NULL registered scope uses transportScopeFor(admin_url) in Root's
  -- authenticated scope verifier; SQL must not confuse NULL with that digest.
  OR v_cluster.revision<>p_observation.cluster_revision OR v_cluster.transport_scope IS NOT NULL AND v_cluster.transport_scope IS DISTINCT FROM p_observation.transport_scope
  OR v_cluster.execution_mode<>'approval' OR v_workspace.deleted_at IS NOT NULL OR v_workspace.status<>'active' OR v_workspace.revision<>p_observation.workspace_revision
 THEN RAISE EXCEPTION 'Metadata observation requires the real current original actor and unchanged scope' USING ERRCODE='23514';END IF;
 IF v_audit.id IS NULL OR v_audit_scope.audit_event_id IS NULL OR v_audit.event_hash IS DISTINCT FROM p_observation.audit_event_hash
  OR ROW(v_audit.cluster_id,v_audit.workspace_id,v_audit.workflow_id,v_audit.actor_id,v_audit.entity_type,v_audit.entity_id,v_audit.action,v_audit.result)
   IS DISTINCT FROM ROW(p_observation.cluster_id,p_observation.workspace_id,p_observation.workflow_id,p_observation.execution_actor_id,'workflows'::text,p_observation.workflow_id::text,'workflow.execute.target-result-reconciled'::text,'success'::text)
  OR v_audit_scope.cluster_id IS DISTINCT FROM p_observation.cluster_id OR v_audit_scope.workspace_id IS DISTINCT FROM p_observation.workspace_id OR v_audit_scope.audit_event_hash IS DISTINCT FROM p_observation.audit_event_hash
  OR v_audit_scope.scope->>'quality' IS DISTINCT FROM 'verified' OR v_audit_scope.scope->>'module' IS DISTINCT FROM 'workflows'
  OR v_audit_scope.scope->'subject'->>'type' IS DISTINCT FROM 'workflows' OR v_audit_scope.scope->'subject'->>'id' IS DISTINCT FROM p_observation.workflow_id::text
  OR v_audit.after->>'observationId' IS DISTINCT FROM p_observation.id::text OR v_audit.after->>'observationHmac' IS DISTINCT FROM p_observation.observation_hmac
  OR v_audit.after->>'requestHmac' IS DISTINCT FROM p_observation.request_hmac OR v_audit.after->>'executionId' IS DISTINCT FROM p_observation.workflow_execution_id::text
  OR v_audit.after->>'sourceId' IS DISTINCT FROM p_observation.source_id::text OR v_audit.after->>'attemptId' IS DISTINCT FROM p_observation.attempt_id::text OR v_audit.after->>'operationId' IS DISTINCT FROM p_observation.operation_id::text
  OR v_audit.after->>'proofHmac' IS DISTINCT FROM p_observation.history_proof_hmac OR v_audit.after->>'producerAttestationHmac' IS DISTINCT FROM p_observation.producer_attestation_hmac
  OR v_audit.after->>'currentObservationHmac' IS DISTINCT FROM p_observation.current_observation_hmac OR v_audit.after->>'resultHmac' IS DISTINCT FROM p_observation.result_hmac
  OR v_audit.after->>'originalOutcome' IS DISTINCT FROM 'sent-unknown' OR v_audit.after->'nativeStatusRecorded' IS DISTINCT FROM 'null'::jsonb
  OR v_audit.after->'certifiedNativeStatus' IS DISTINCT FROM '201'::jsonb OR v_audit.after->'nativeRequestsSent' IS DISTINCT FROM '0'::jsonb OR v_audit.after->'metadataReconciled' IS DISTINCT FROM 'true'::jsonb
  OR v_audit.after->>'workflowState' IS DISTINCT FROM 'succeeded' OR v_audit.after->>'executionState' IS DISTINCT FROM 'succeeded'
  OR v_audit.after->>'operationState' IS DISTINCT FROM 'succeeded' OR v_audit.after->>'stepState' IS DISTINCT FROM 'succeeded'
  OR (SELECT count(*) FROM audit_events a WHERE a.cluster_id=p_observation.cluster_id AND a.workspace_id=p_observation.workspace_id AND a.workflow_id=p_observation.workflow_id
    AND a.actor_id=p_observation.execution_actor_id AND a.action='workflow.execute.target-result-reconciled' AND a.after->>'requestHmac'=p_observation.request_hmac)<>1
 THEN RAISE EXCEPTION 'A unique scoped audit and authenticated observation must commit with the original states' USING ERRCODE='23514';END IF;
 END;
$$;

CREATE FUNCTION m11_target_result_observation_insert() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||NEW.transport_scope,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('entity-change-attempt:'||NEW.attempt_id::text,0));
 PERFORM m11_validate_target_result_observation(NEW,'insert');RETURN NEW;
 END;
$$;
CREATE TRIGGER entity_target_result_observation_guard BEFORE INSERT ON entity_change_target_result_observations FOR EACH ROW EXECUTE FUNCTION m11_target_result_observation_insert();

-- A row alone is never native authority. This additive guard confines only
-- V3/native-change uncertain -> succeeded metadata transitions. Other existing
-- state transitions remain governed by their unchanged original constraints.
CREATE FUNCTION m11_target_result_state_guard() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE v_observation entity_change_target_result_observations%ROWTYPE;v_revision integer;
 BEGIN
 IF OLD.state<>'uncertain' OR NEW.state<>'succeeded' THEN RETURN NEW;END IF;
 IF TG_TABLE_NAME='mutation_operations' THEN
  IF OLD.entity_change_attempt_id IS NULL THEN RETURN NEW;END IF;
  SELECT * INTO v_observation FROM entity_change_target_result_observations WHERE operation_id=OLD.id AND attempt_id=OLD.entity_change_attempt_id;
  IF v_observation.id IS NULL OR v_observation.source_id IS DISTINCT FROM OLD.entity_change_source_id OR v_observation.baseline_id IS DISTINCT FROM OLD.entity_change_baseline_id
   OR v_observation.packet_key IS DISTINCT FROM OLD.entity_change_packet_key OR NOT OLD.remote_started OR NOT OLD.remote_completed OR OLD.result_secret IS NULL
   OR OLD.entity_id IS DISTINCT FROM v_observation.native_id::text OR OLD.entity_type<>'targets' OR OLD.action<>'update'
   OR (to_jsonb(NEW)-ARRAY['state','updated_at','safe_result']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','updated_at','safe_result'])
  THEN RAISE EXCEPTION 'V3 known-result closure requires its exact saved Target observation without altering the ledger' USING ERRCODE='23514';END IF;
  RETURN NEW;
 ELSIF TG_TABLE_NAME='workflow_executions' THEN
  IF NOT EXISTS(SELECT 1 FROM entity_change_execution_sources WHERE workflow_execution_id=OLD.id) THEN RETURN NEW;END IF;
  SELECT * INTO v_observation FROM entity_change_target_result_observations WHERE workflow_execution_id=OLD.id;
  v_revision=v_observation.execution_revision_before;
 ELSIF TG_TABLE_NAME='workflow_steps' THEN
  IF OLD.handler IS DISTINCT FROM 'entity.change' THEN RETURN NEW;END IF;
  SELECT * INTO v_observation FROM entity_change_target_result_observations WHERE workflow_step_id=OLD.id;
  v_revision=v_observation.step_revision_before;
 ELSE
  IF OLD.kind<>'native-change' THEN RETURN NEW;END IF;
  SELECT * INTO v_observation FROM entity_change_target_result_observations WHERE workflow_id=OLD.id;
  v_revision=v_observation.workflow_revision_before;
 END IF;
 IF v_observation.id IS NULL OR v_observation.cluster_id IS DISTINCT FROM OLD.cluster_id OR v_observation.workspace_id IS DISTINCT FROM OLD.workspace_id
  OR OLD.revision IS DISTINCT FROM v_revision OR NEW.revision<>OLD.revision+1
  OR (to_jsonb(NEW)-ARRAY['state','revision','updated_at','safe_result']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','revision','updated_at','safe_result'])
 THEN RAISE EXCEPTION 'Only the original observed metadata state and one CAS revision may advance' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER mutation_operations_target_result_guard BEFORE UPDATE ON mutation_operations FOR EACH ROW EXECUTE FUNCTION m11_target_result_state_guard();
CREATE TRIGGER workflow_executions_target_result_guard BEFORE UPDATE ON workflow_executions FOR EACH ROW EXECUTE FUNCTION m11_target_result_state_guard();
CREATE TRIGGER workflow_steps_target_result_guard BEFORE UPDATE ON workflow_steps FOR EACH ROW EXECUTE FUNCTION m11_target_result_state_guard();
CREATE TRIGGER workflows_target_result_guard BEFORE UPDATE ON workflows FOR EACH ROW EXECUTE FUNCTION m11_target_result_state_guard();

CREATE FUNCTION m11_target_result_observation_complete() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE v_observation entity_change_target_result_observations%ROWTYPE;
 BEGIN
 IF TG_TABLE_NAME='entity_change_target_result_observations' THEN v_observation=NEW;
 ELSIF TG_TABLE_NAME='mutation_operations' THEN SELECT * INTO v_observation FROM entity_change_target_result_observations WHERE operation_id=NEW.id;
 ELSIF TG_TABLE_NAME='workflow_executions' THEN SELECT * INTO v_observation FROM entity_change_target_result_observations WHERE workflow_execution_id=NEW.id;
 ELSIF TG_TABLE_NAME='workflow_steps' THEN SELECT * INTO v_observation FROM entity_change_target_result_observations WHERE workflow_step_id=NEW.id;
 ELSE SELECT * INTO v_observation FROM entity_change_target_result_observations WHERE workflow_id=NEW.id;END IF;
 IF v_observation.id IS NOT NULL THEN PERFORM m11_validate_target_result_observation(v_observation,'complete');END IF;RETURN NULL;
 END;
$$;
CREATE CONSTRAINT TRIGGER entity_target_result_observation_complete AFTER INSERT ON entity_change_target_result_observations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_target_result_observation_complete();
CREATE CONSTRAINT TRIGGER mutation_target_result_observation_complete AFTER UPDATE ON mutation_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_target_result_observation_complete();
CREATE CONSTRAINT TRIGGER execution_target_result_observation_complete AFTER UPDATE ON workflow_executions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_target_result_observation_complete();
CREATE CONSTRAINT TRIGGER step_target_result_observation_complete AFTER UPDATE ON workflow_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_target_result_observation_complete();
CREATE CONSTRAINT TRIGGER workflow_target_result_observation_complete AFTER UPDATE ON workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_target_result_observation_complete();
CREATE TRIGGER entity_target_result_observations_immutable BEFORE UPDATE OR DELETE ON entity_change_target_result_observations FOR EACH ROW EXECUTE FUNCTION m8_immutable();
CREATE TRIGGER entity_target_result_observations_no_truncate BEFORE TRUNCATE ON entity_change_target_result_observations FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_target_result_observations FROM PUBLIC;
-- Root adds this literal table to provisionRuntimeRole's SELECT/INSERT-only
-- allowlist AFTER broad grants; this PUBLIC revoke does not replace that step.
