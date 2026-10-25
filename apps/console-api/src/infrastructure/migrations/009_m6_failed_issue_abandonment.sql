-- Additive M6 repair. Failed execution/native/key history remains unchanged.
-- This certificate is a dedicated durable metadata receipt, never an approval
-- capability, native result, credential revocation, or a replacement ledger.
CREATE TABLE portal_failed_issue_abandonments (
  id uuid PRIMARY KEY,
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  workflow_id uuid NOT NULL,
  execution_id uuid NOT NULL,
  plan_revision integer NOT NULL CHECK(plan_revision>0),
  plan_hash text NOT NULL CHECK(plan_hash ~ '^[a-f0-9]{64}$'),
  failed_step_id uuid NOT NULL,
  failed_operation_id uuid NOT NULL,
  credential_id uuid NOT NULL,
  actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
  original_execution_key text NOT NULL CHECK(length(original_execution_key) BETWEEN 8 AND 128),
  request_hash text NOT NULL CHECK(request_hash ~ '^[a-f0-9]{64}$'),
  transport_scope text NOT NULL CHECK(transport_scope ~ '^[a-f0-9]{64}$'),
  original_grant_revision integer NOT NULL CHECK(original_grant_revision>0),
  facts_hash text NOT NULL CHECK(facts_hash ~ '^[a-f0-9]{64}$'),
  reserved_impact jsonb NOT NULL CHECK(jsonb_typeof(reserved_impact)='object' AND octet_length(reserved_impact::text)<=8192),
  key_cipher_hmac text NOT NULL CHECK(key_cipher_hmac ~ '^[a-f0-9]{64}$'),
  proof_secret text NOT NULL CHECK(m6_encrypted(proof_secret,65536)),
  proof_hmac text NOT NULL CHECK(proof_hmac ~ '^[a-f0-9]{64}$'),
  absence_observed_at timestamptz NOT NULL,
  audit_event_id uuid NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
  audit_event_hash text NOT NULL CHECK(audit_event_hash ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(grant_id),
  UNIQUE(execution_id),
  UNIQUE(failed_operation_id),
  UNIQUE(audit_event_id),
  UNIQUE(cluster_id,workspace_id,actor_id,original_execution_key),
  FOREIGN KEY(cluster_id,workspace_id,grant_id) REFERENCES portal_application_grants(cluster_id,workspace_id,id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,execution_id,workflow_id,plan_revision,plan_hash) REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,failed_step_id,workflow_id,plan_revision,plan_hash,failed_operation_id) REFERENCES workflow_steps(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash,operation_id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,failed_step_id,workflow_id,plan_revision,plan_hash,failed_operation_id) REFERENCES mutation_operations(cluster_id,workspace_id,workflow_step_id,workflow_id,workflow_plan_revision,workflow_plan_hash,id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,grant_id,credential_id) REFERENCES portal_credentials(cluster_id,workspace_id,grant_id,id) ON DELETE RESTRICT,
  CHECK(absence_observed_at<=created_at+interval '1 second' AND absence_observed_at>=created_at-interval '15 seconds')
);
CREATE INDEX portal_failed_issue_abandonments_scope ON portal_failed_issue_abandonments(cluster_id,workspace_id,workflow_id);
CREATE TRIGGER portal_failed_issue_abandonments_append_only BEFORE UPDATE OR DELETE ON portal_failed_issue_abandonments
  FOR EACH ROW EXECUTE FUNCTION m6_reject_history_mutation();
CREATE TRIGGER portal_failed_issue_abandonments_no_truncate BEFORE TRUNCATE ON portal_failed_issue_abandonments
  FOR EACH STATEMENT EXECUTE FUNCTION m6_reject_history_mutation();
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON portal_failed_issue_abandonments FROM PUBLIC;

-- HMAC identity arrays are produced only by the server. Unknown/old key IDs
-- and malformed historical impacts are conservatively considered overlapping.
CREATE FUNCTION m6_rejected_impact_collision(observed jsonb,reserved jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN observed IS NULL OR reserved IS NULL
  OR observed->>'keyId' IS DISTINCT FROM reserved->>'keyId'
  OR jsonb_typeof(observed->'keys') IS DISTINCT FROM 'array'
  OR jsonb_typeof(observed->'wildcards') IS DISTINCT FROM 'array'
  OR jsonb_typeof(observed->'domains') IS DISTINCT FROM 'array'
  OR jsonb_typeof(reserved->'keys') IS DISTINCT FROM 'array'
  OR jsonb_typeof(reserved->'wildcards') IS DISTINCT FROM 'array'
  OR jsonb_typeof(reserved->'domains') IS DISTINCT FROM 'array' THEN true ELSE
   EXISTS(SELECT 1 FROM jsonb_array_elements_text(observed->'keys') token WHERE reserved->'keys' ? token)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(observed->'wildcards') token WHERE reserved->'domains' ? token)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(reserved->'wildcards') token WHERE observed->'domains' ? token)
 END;
$$;

CREATE FUNCTION m6_assert_rejected_issue_candidate(grant_identity uuid, reserved_impact jsonb DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
DECLARE g portal_application_grants%ROWTYPE; w workflows%ROWTYPE; e workflow_executions%ROWTYPE;
 v workflow_versions%ROWTYPE; s workflow_steps%ROWTYPE; op mutation_operations%ROWTYPE; c portal_credentials%ROWTYPE;
BEGIN
 SELECT * INTO g FROM portal_application_grants WHERE id=grant_identity FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Failed issue identity is unavailable' USING ERRCODE='23514';END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'Failed issue proof requires fresh read-committed facts' USING ERRCODE='25001';END IF;
 SELECT * INTO w FROM workflows WHERE id=g.workflow_id;
 SELECT * INTO v FROM workflow_versions WHERE workflow_id=w.id AND cluster_id=g.cluster_id AND workspace_id=g.workspace_id AND plan_revision=w.plan_revision AND plan_hash=w.plan_hash;
 SELECT * INTO e FROM workflow_executions WHERE workflow_id=w.id AND plan_revision=w.plan_revision;
 SELECT * INTO s FROM workflow_steps WHERE workflow_id=w.id AND step_order=1 AND plan_revision=w.plan_revision;
 SELECT * INTO op FROM mutation_operations WHERE id=s.operation_id;
 SELECT * INTO c FROM portal_credentials WHERE grant_id=g.id;
 IF g.state NOT IN('pending','disabled') OR g.current_generation<>0 OR g.current_credential_id IS NOT NULL OR g.acl_credential_ref_id IS NOT NULL
  OR w.id IS NULL OR w.cluster_id IS DISTINCT FROM g.cluster_id OR w.workspace_id IS DISTINCT FROM g.workspace_id
  OR w.kind IS DISTINCT FROM 'portal-credential-issue' OR w.subject_type IS DISTINCT FROM 'portal_application_grants' OR w.subject_id IS DISTINCT FROM g.id
  OR w.state IS DISTINCT FROM 'failed' OR NOT coalesce(w.approval_required,false)
  OR v.workflow_id IS NULL OR v.step_count<>4 OR v.native_request_count<>3
  OR e.id IS NULL OR e.cluster_id IS DISTINCT FROM g.cluster_id OR e.workspace_id IS DISTINCT FROM g.workspace_id OR e.plan_hash IS DISTINCT FROM w.plan_hash
  OR e.state IS DISTINCT FROM 'failed' OR e.snapshot_state IS DISTINCT FROM 'ready' OR e.completed_at IS NULL OR NOT e.approval_required
  OR s.id IS NULL OR s.kind IS DISTINCT FROM 'native' OR s.entity_type IS DISTINCT FROM 'consumers'
  OR s.entity_id IS NOT NULL OR s.parent_id IS NOT NULL OR s.credential_kind IS NOT NULL
  OR s.mutation_action IS DISTINCT FROM 'create' OR s.permission_action IS DISTINCT FROM 'write' OR s.state IS DISTINCT FROM 'failed'
  OR s.error_code IS DISTINCT FROM 'KONG_VALIDATION_ERROR'
  OR s.safe_result->>'nativeOperationId' IS DISTINCT FROM s.operation_id::text OR s.safe_result->>'remoteStarted' IS DISTINCT FROM 'true' OR s.safe_result->>'remoteCompleted' IS DISTINCT FROM 'false'
  OR s.receipt_secret IS NOT NULL OR s.after_fingerprint IS NOT NULL OR s.recycle_entry_id IS NOT NULL OR s.started_at IS NULL OR s.completed_at IS NULL
  OR jsonb_array_length(s.native_requests)<>1 OR s.native_requests->0->>'method' IS DISTINCT FROM 'POST'
  OR s.native_requests->0->>'native_type' IS DISTINCT FROM 'consumers' OR s.native_requests->0->>'native_id' IS DISTINCT FROM g.consumer_id::text
  OR op.id IS NULL OR op.cluster_id IS DISTINCT FROM g.cluster_id OR op.workspace_id IS DISTINCT FROM g.workspace_id
  OR op.workflow_id IS DISTINCT FROM w.id OR op.workflow_execution_id IS DISTINCT FROM e.id OR op.workflow_step_id IS DISTINCT FROM s.id
  OR op.workflow_plan_revision IS DISTINCT FROM w.plan_revision OR op.workflow_plan_hash IS DISTINCT FROM w.plan_hash
  OR op.actor_id IS DISTINCT FROM e.execution_actor_id OR op.action IS DISTINCT FROM 'create' OR op.entity_type IS DISTINCT FROM 'consumers'
  OR op.entity_id IS NOT NULL OR op.parent_id IS NOT NULL OR op.credential_kind IS NOT NULL OR op.transport_scope IS DISTINCT FROM g.transport_scope
  OR op.state IS DISTINCT FROM 'failed' OR op.error_code IS DISTINCT FROM 'KONG_VALIDATION_ERROR'
  OR NOT coalesce(op.remote_started,false) OR coalesce(op.remote_completed,true) OR op.result_secret IS NOT NULL
  OR op.before_secret IS NULL OR op.payload_secret IS NULL
  OR op.idempotency_key IS DISTINCT FROM s.mutation_idempotency_key
  OR c.id IS NULL OR c.cluster_id IS DISTINCT FROM g.cluster_id OR c.workspace_id IS DISTINCT FROM g.workspace_id
  OR c.workflow_id IS DISTINCT FROM w.id OR c.consumer_id IS DISTINCT FROM g.consumer_id OR c.generation<>1 OR c.previous_credential_id IS NOT NULL
  OR c.state IS DISTINCT FROM 'pending' OR c.credential_ref_id IS NOT NULL OR c.issue_operation_id IS NOT NULL OR c.revoke_workflow_id IS NOT NULL
  OR c.revoke_operation_id IS NOT NULL OR c.recycle_entry_id IS NOT NULL OR c.last_revealed_at IS NOT NULL
  OR c.revoked_at IS NOT NULL OR c.deleted_at IS NOT NULL OR c.retention_until IS NOT NULL
  OR (SELECT count(*) FROM portal_credentials WHERE grant_id=g.id)<>1
  OR (SELECT count(*) FROM workflows WHERE cluster_id=g.cluster_id AND workspace_id=g.workspace_id AND subject_type='portal_application_grants' AND subject_id=g.id)<>1
  OR (SELECT count(*) FROM workflow_executions WHERE workflow_id=w.id)<>1
  OR (SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id)<>4
  OR EXISTS(SELECT 1 FROM workflow_steps later WHERE later.workflow_id=w.id AND later.step_order>1 AND (
    later.state<>'pending' OR later.operation_id IS NOT NULL OR later.receipt_secret IS NOT NULL OR later.safe_result<>'{}'::jsonb
    OR later.started_at IS NOT NULL OR later.completed_at IS NOT NULL OR later.after_fingerprint IS NOT NULL OR later.recycle_entry_id IS NOT NULL OR later.error_code IS NOT NULL))
  OR NOT EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=w.id AND step_order=2 AND kind='native' AND entity_type='credentials' AND credential_kind='acls' AND mutation_action='create' AND parent_id=g.consumer_id AND native_requests->0->>'native_id'=g.acl_id::text)
  OR NOT EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=w.id AND step_order=3 AND kind='native' AND entity_type='credentials' AND credential_kind='key-auth' AND mutation_action='create' AND parent_id=g.consumer_id AND native_requests->0->>'native_id'=c.kong_id::text)
  OR NOT EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=w.id AND step_order=4 AND kind='metadata' AND handler='portal.credential.activate' AND entity_type='portal_application_grants' AND entity_id=g.id AND native_requests='[]'::jsonb)
  OR EXISTS(SELECT 1 FROM credential_refs r WHERE m6_portal_scope_alias(r.cluster_id,g.transport_scope,g.cluster_id) AND (r.consumer_id=g.consumer_id OR r.kong_id=g.acl_id OR r.kong_id=c.kong_id))
  OR EXISTS(
   SELECT 1 FROM mutation_operations other WHERE other.id<>op.id AND (
    other.workflow_id=w.id OR (
     m6_portal_scope_alias(other.cluster_id,g.transport_scope,g.cluster_id) AND (
      (other.entity_type='consumers' AND other.entity_id=g.consumer_id::text)
      OR (other.entity_type='credentials' AND(other.parent_id=g.consumer_id::text OR other.entity_id IN(g.acl_id::text,c.kong_id::text)))
      OR (other.entity_type IN('consumers','credentials') AND other.entity_id IS NULL AND other.action='create' AND (
       (reserved_impact IS NULL AND other.state IN('pending','running','uncertain'))
       OR (reserved_impact IS NOT NULL AND m6_rejected_impact_collision(other.impact,reserved_impact))
      ))
     )
    )
   )
  ) THEN
  RAISE EXCEPTION 'Failed issue abandonment requires exactly one rejected Consumer CREATE and pristine unused children' USING ERRCODE='23514';
 END IF;
END;$$;

-- Canonical server-side digest includes the original encrypted plan, snapshot,
-- failed receipt and pending key bytes. Never returned as a credential view.
CREATE FUNCTION m6_rejected_issue_facts_hash(grant_identity uuid) RETURNS text LANGUAGE sql STABLE SET TimeZone='UTC' AS $$
 SELECT encode(sha256(convert_to(jsonb_build_object(
  'identity',jsonb_build_object('id',g.id,'cluster_id',g.cluster_id,'workspace_id',g.workspace_id,'transport_scope',g.transport_scope,
   'application_id',g.application_id,'publication_id',g.publication_id,'developer_id',g.developer_id,'consumer_id',g.consumer_id,'acl_group',g.acl_group,'acl_id',g.acl_id,'workflow_id',g.workflow_id),
  'workflow',to_jsonb(w),'version',to_jsonb(v),'execution',to_jsonb(e),'credential',to_jsonb(c),
  'steps',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.step_order) FROM workflow_steps s WHERE s.workflow_id=w.id),
  'operations',(SELECT jsonb_agg(to_jsonb(op) ORDER BY op.id) FROM mutation_operations op WHERE op.workflow_id=w.id)
 )::text,'UTF8')),'hex')
 FROM portal_application_grants g JOIN workflows w ON w.id=g.workflow_id
 JOIN workflow_versions v ON v.workflow_id=w.id AND v.plan_revision=w.plan_revision
 JOIN workflow_executions e ON e.workflow_id=w.id AND e.plan_revision=w.plan_revision
 JOIN portal_credentials c ON c.grant_id=g.id WHERE g.id=grant_identity;
$$;

CREATE FUNCTION m6_assert_certified_failed_issue(grant_identity uuid) RETURNS void LANGUAGE plpgsql AS $$
DECLARE g portal_application_grants%ROWTYPE; cert portal_failed_issue_abandonments%ROWTYPE;
 w workflows%ROWTYPE;e workflow_executions%ROWTYPE;s workflow_steps%ROWTYPE;c portal_credentials%ROWTYPE;a audit_events%ROWTYPE;
BEGIN
 SELECT * INTO g FROM portal_application_grants WHERE id=grant_identity FOR UPDATE;
 SELECT * INTO cert FROM portal_failed_issue_abandonments WHERE grant_id=g.id;
 IF cert.id IS NULL THEN RAISE EXCEPTION 'Failed issue release requires a certificate' USING ERRCODE='23514';END IF;
 PERFORM m6_assert_rejected_issue_candidate(g.id,cert.reserved_impact);
 SELECT * INTO w FROM workflows WHERE id=g.workflow_id; SELECT * INTO e FROM workflow_executions WHERE id=cert.execution_id;
 SELECT * INTO s FROM workflow_steps WHERE id=cert.failed_step_id;SELECT * INTO c FROM portal_credentials WHERE id=cert.credential_id;
 SELECT * INTO a FROM audit_events WHERE id=cert.audit_event_id;
 IF g.reservation_released_at IS NULL OR g.state<>'disabled' OR g.revision<>cert.original_grant_revision+1
  OR cert.cluster_id IS DISTINCT FROM g.cluster_id OR cert.workspace_id IS DISTINCT FROM g.workspace_id
  OR cert.transport_scope IS DISTINCT FROM g.transport_scope OR cert.workflow_id IS DISTINCT FROM w.id
  OR cert.execution_id IS DISTINCT FROM e.id OR cert.plan_revision IS DISTINCT FROM w.plan_revision OR cert.plan_hash IS DISTINCT FROM w.plan_hash
  OR cert.failed_operation_id IS DISTINCT FROM s.operation_id OR cert.actor_id IS DISTINCT FROM e.execution_actor_id
  OR cert.original_execution_key IS DISTINCT FROM e.idempotency_key OR cert.credential_id IS DISTINCT FROM c.id
  OR cert.facts_hash IS DISTINCT FROM m6_rejected_issue_facts_hash(g.id)
  OR a.id IS NULL OR a.actor_id IS DISTINCT FROM cert.actor_id OR a.actor_type IS DISTINCT FROM 'user'
  OR a.cluster_id IS DISTINCT FROM g.cluster_id OR a.workspace_id IS DISTINCT FROM g.workspace_id OR a.workflow_id IS DISTINCT FROM w.id
  OR a.entity_type IS DISTINCT FROM 'portal_application_grants' OR a.entity_id IS DISTINCT FROM g.id::text
  OR a.action IS DISTINCT FROM 'portal.issue.abandon-rejected' OR a.result IS DISTINCT FROM 'success' OR a.event_hash IS DISTINCT FROM cert.audit_event_hash
  OR a.before->>'id' IS DISTINCT FROM g.id::text OR a.before->>'state' IS DISTINCT FROM 'pending'
  OR (a.before->>'revision')::integer IS DISTINCT FROM cert.original_grant_revision
  OR a.after->>'id' IS DISTINCT FROM g.id::text OR a.after->>'state' IS DISTINCT FROM 'disabled'
  OR (a.after->>'revision')::integer IS DISTINCT FROM g.revision OR a.after->>'reservationReleased' IS DISTINCT FROM 'true' THEN
  RAISE EXCEPTION 'Failed issue certificate must retain exact original facts and successful scoped audit receipt' USING ERRCODE='23514';
 END IF;
END;$$;

CREATE FUNCTION m6_validate_failed_issue_certificate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM m6_assert_certified_failed_issue(NEW.grant_id);
 IF NEW.absence_observed_at<clock_timestamp()-interval '15 seconds' OR NEW.absence_observed_at>clock_timestamp()+interval '1 second'
  OR NOT EXISTS(SELECT 1 FROM auth_sessions sess JOIN users u ON u.id=sess.user_id WHERE sess.id=NEW.session_id AND u.id=NEW.actor_id
    AND u.status='active' AND u.deleted_at IS NULL AND u.force_password_change=false AND sess.revoked_at IS NULL AND sess.expires_at>clock_timestamp() AND sess.credential_epoch=u.credential_epoch) THEN
  RAISE EXCEPTION 'Certificate requires fresh original console actor/session and absence proof' USING ERRCODE='23514';END IF;
 RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER portal_failed_issue_abandonments_proof AFTER INSERT ON portal_failed_issue_abandonments
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_failed_issue_certificate();

CREATE FUNCTION m6_assert_never_executed_reservation(grant_identity uuid) RETURNS void LANGUAGE plpgsql AS $$
DECLARE g portal_application_grants%ROWTYPE; w workflows%ROWTYPE;
BEGIN
  -- Lock BEFORE testing release state, including an unreleased row. Concurrent
  -- facts and release therefore serialize instead of trusting a stale filter.
  SELECT * INTO g FROM portal_application_grants WHERE id=grant_identity FOR UPDATE;
  IF NOT FOUND OR g.reservation_released_at IS NULL THEN RETURN; END IF;
  -- The runtime uses READ COMMITTED. A repeatable-read snapshot could otherwise
  -- miss a fact committed by a transaction that held this lock first.
  IF current_setting('transaction_isolation')<>'read committed' THEN
    RAISE EXCEPTION 'Reservation proof requires fresh read-committed facts' USING ERRCODE='25001';
  END IF;
  SELECT * INTO w FROM workflows WHERE id=g.workflow_id;
  IF g.state<>'disabled' OR g.current_generation<>0 OR g.current_credential_id IS NOT NULL
    OR g.acl_credential_ref_id IS NOT NULL OR g.workflow_id IS NULL
    OR w.cluster_id IS DISTINCT FROM g.cluster_id OR w.workspace_id IS DISTINCT FROM g.workspace_id
    OR w.kind IS DISTINCT FROM 'portal-credential-issue' OR w.subject_type IS DISTINCT FROM 'portal_application_grants'
    OR w.subject_id IS DISTINCT FROM g.id OR w.state NOT IN ('cancelled','rejected','expired')
    OR EXISTS(SELECT 1 FROM workflows history WHERE history.cluster_id=g.cluster_id AND history.workspace_id=g.workspace_id
      AND history.subject_type='portal_application_grants' AND history.subject_id=g.id
      AND(history.kind<>'portal-credential-issue' OR history.state NOT IN ('cancelled','rejected','expired')))
    OR EXISTS(SELECT 1 FROM workflow_executions e JOIN workflows history ON history.id=e.workflow_id
      WHERE history.cluster_id=g.cluster_id AND history.workspace_id=g.workspace_id
      AND history.subject_type='portal_application_grants' AND history.subject_id=g.id)
    OR EXISTS(SELECT 1 FROM workflow_steps s JOIN workflows history ON history.id=s.workflow_id
      WHERE history.cluster_id=g.cluster_id AND history.workspace_id=g.workspace_id
      AND history.subject_type='portal_application_grants' AND history.subject_id=g.id
      AND(s.state<>'pending' OR s.operation_id IS NOT NULL OR s.receipt_secret IS NOT NULL
        OR s.safe_result<>'{}'::jsonb OR s.started_at IS NOT NULL OR s.completed_at IS NOT NULL
        OR s.after_fingerprint IS NOT NULL OR s.recycle_entry_id IS NOT NULL))
    OR EXISTS(SELECT 1 FROM portal_credentials c WHERE c.grant_id=g.id
      AND(c.state<>'pending' OR c.credential_ref_id IS NOT NULL OR c.issue_operation_id IS NOT NULL
        OR c.revoke_workflow_id IS NOT NULL OR c.revoke_operation_id IS NOT NULL OR c.recycle_entry_id IS NOT NULL
        OR c.last_revealed_at IS NOT NULL OR c.revoked_at IS NOT NULL OR c.deleted_at IS NOT NULL OR c.retention_until IS NOT NULL
        OR NOT EXISTS(SELECT 1 FROM workflows issue WHERE issue.id=c.workflow_id AND issue.cluster_id=g.cluster_id
          AND issue.workspace_id=g.workspace_id AND issue.kind='portal-credential-issue'
          AND issue.subject_type='portal_application_grants' AND issue.subject_id=g.id
          AND issue.state IN ('cancelled','rejected','expired'))))
    OR EXISTS(SELECT 1 FROM credential_refs r WHERE m6_portal_scope_alias(r.cluster_id,g.transport_scope,g.cluster_id)
      AND(r.consumer_id=g.consumer_id OR r.kong_id=g.acl_id
        OR EXISTS(SELECT 1 FROM portal_credentials c WHERE c.grant_id=g.id AND c.kong_id=r.kong_id)))
    OR EXISTS(SELECT 1 FROM mutation_operations op WHERE
      EXISTS(SELECT 1 FROM workflows history WHERE history.id=op.workflow_id AND history.cluster_id=g.cluster_id
        AND history.workspace_id=g.workspace_id AND history.subject_type='portal_application_grants' AND history.subject_id=g.id)
      OR(m6_portal_scope_alias(op.cluster_id,g.transport_scope,g.cluster_id) AND(
        (op.entity_type='consumers' AND op.entity_id=g.consumer_id::text)
        OR(op.entity_type='credentials' AND(op.parent_id=g.consumer_id::text OR op.entity_id=g.acl_id::text
          OR EXISTS(SELECT 1 FROM portal_credentials c WHERE c.grant_id=g.id AND op.entity_id=c.kong_id::text)))))) THEN
    RAISE EXCEPTION 'Reservation release requires terminal, never-executed and fact-free issue history' USING ERRCODE='23514';
  END IF;
END;
$$;

-- Existing never-executed policy is preserved verbatim above; only an exact
-- durable certificate enables the separate known-rejected execution branch.
CREATE OR REPLACE FUNCTION m6_assert_unused_reservation(grant_identity uuid) RETURNS void LANGUAGE plpgsql AS $$
DECLARE g portal_application_grants%ROWTYPE;
BEGIN
 SELECT * INTO g FROM portal_application_grants WHERE id=grant_identity FOR UPDATE;
 IF NOT FOUND OR g.reservation_released_at IS NULL THEN RETURN;END IF;
 IF EXISTS(SELECT 1 FROM portal_failed_issue_abandonments WHERE grant_id=g.id) THEN
  PERFORM m6_assert_certified_failed_issue(g.id);
 ELSE
  PERFORM m6_assert_never_executed_reservation(g.id);
 END IF;
END;$$;

CREATE FUNCTION m6_validate_failed_issue_null_native_fact() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE document jsonb;documents jsonb[];grant_identity uuid;
BEGIN
 IF TG_OP='INSERT' THEN documents:=ARRAY[to_jsonb(NEW)];
 ELSIF TG_OP='DELETE' THEN documents:=ARRAY[to_jsonb(OLD)];
 ELSE documents:=ARRAY[to_jsonb(OLD),to_jsonb(NEW)];END IF;
 FOREACH document IN ARRAY documents LOOP
  IF document->>'entity_type' IN('consumers','credentials') AND document->>'action'='create' AND document->>'entity_id' IS NULL THEN
   FOR grant_identity IN SELECT g.id FROM portal_application_grants g JOIN portal_failed_issue_abandonments cert ON cert.grant_id=g.id
    WHERE m6_portal_scope_alias((document->>'cluster_id')::uuid,g.transport_scope,g.cluster_id) ORDER BY g.id
   LOOP PERFORM m6_assert_certified_failed_issue(grant_identity);END LOOP;
  END IF;
 END LOOP;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER mutation_operations_failed_issue_null_evidence AFTER INSERT OR UPDATE OR DELETE ON mutation_operations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_failed_issue_null_native_fact();

-- Attaching an already-populated registry alias must not make previously hidden
-- native facts bypass a certified release. Only affected captured scopes are
-- rechecked; aliases are exact registered identities, never DNS/IP inference.
CREATE FUNCTION m6_validate_failed_issue_alias_membership() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE document jsonb;documents jsonb[];candidate_cluster uuid;grant_identity uuid;
BEGIN
 IF TG_OP='INSERT' THEN documents:=ARRAY[to_jsonb(NEW)];ELSE documents:=ARRAY[to_jsonb(OLD),to_jsonb(NEW)];END IF;
 FOREACH document IN ARRAY documents LOOP
  candidate_cluster:=CASE WHEN TG_TABLE_NAME='clusters' THEN(document->>'id')::uuid ELSE(document->>'cluster_id')::uuid END;
  FOR grant_identity IN SELECT cert.grant_id FROM portal_failed_issue_abandonments cert WHERE
   cert.transport_scope=document->>'transport_scope'
   OR m6_portal_scope_alias(candidate_cluster,cert.transport_scope,cert.cluster_id)
   ORDER BY cert.grant_id
  LOOP PERFORM m6_assert_certified_failed_issue(grant_identity);END LOOP;
 END LOOP;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER clusters_failed_issue_alias AFTER INSERT OR UPDATE OF admin_url,transport_scope ON clusters
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_failed_issue_alias_membership();
CREATE CONSTRAINT TRIGGER portal_publications_failed_issue_alias AFTER INSERT ON portal_publications
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_failed_issue_alias_membership();
CREATE CONSTRAINT TRIGGER portal_grants_failed_issue_alias AFTER INSERT ON portal_application_grants
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_failed_issue_alias_membership();
CREATE CONSTRAINT TRIGGER metrics_nodes_failed_issue_alias AFTER INSERT OR UPDATE OF cluster_id,transport_scope ON metrics_nodes
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_failed_issue_alias_membership();
