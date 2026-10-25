-- Scheduled entity changes use an explicit owner delegation, never an HTTP
-- session substitute. This migration changes no V1 plan or old source bytes.
ALTER TABLE entity_change_intent_versions ADD CONSTRAINT entity_intent_schedule_owner_tuple UNIQUE(
 cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,
 requester_id,credential_epoch,policy_hash,expires_at);

CREATE TABLE entity_change_owner_delegations (
 id uuid PRIMARY KEY,version integer NOT NULL CHECK(version=1),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 intent_id uuid NOT NULL,intent_revision integer NOT NULL,material_hmac text NOT NULL,change_digest text NOT NULL,packet_manifest_hmac text NOT NULL,
 policy_hash text NOT NULL,owner_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,executor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 owner_credential_epoch bigint NOT NULL CHECK(owner_credential_epoch>0),executor_credential_epoch bigint NOT NULL CHECK(executor_credential_epoch>0),
 spec_hmac text NOT NULL CHECK(m8_hex64(spec_hmac)),delegation_hmac text NOT NULL CHECK(m8_hex64(delegation_hmac)),
 delegation_ciphertext text NOT NULL CHECK(m6_encrypted(delegation_ciphertext,65536)),issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,id,version,delegation_hmac,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,owner_id,owner_credential_epoch,spec_hmac,expires_at),
 FOREIGN KEY(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,owner_id,owner_credential_epoch,policy_hash,expires_at)
  REFERENCES entity_change_intent_versions(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,requester_id,credential_epoch,policy_hash,expires_at) ON DELETE RESTRICT,
 CHECK(owner_id=executor_id AND owner_credential_epoch=executor_credential_epoch),
 CHECK(issued_at<=created_at AND expires_at>issued_at AND expires_at<=issued_at+interval '168 hours')
);
CREATE TABLE entity_change_schedules (
 id uuid PRIMARY KEY,version integer NOT NULL CHECK(version=1),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 intent_id uuid NOT NULL,intent_revision integer NOT NULL,material_hmac text NOT NULL,change_digest text NOT NULL,packet_manifest_hmac text NOT NULL,
 owner_id uuid NOT NULL,owner_credential_epoch bigint NOT NULL,delegation_id uuid NOT NULL,delegation_version integer NOT NULL,delegation_hmac text NOT NULL,
 spec_hmac text NOT NULL,spec jsonb NOT NULL CHECK(m7_object(spec,4096)),not_before timestamptz NOT NULL,window_start timestamptz NOT NULL,window_end timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,occurrence_id uuid NOT NULL UNIQUE,transport_scope text NOT NULL CHECK(m8_hex64(transport_scope)),
 impact_hmac text NOT NULL CHECK(m8_hex64(impact_hmac)),impact jsonb NOT NULL CHECK(m7_object(impact,8388608)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,intent_id,intent_revision),UNIQUE(cluster_id,workspace_id,id,version),
 UNIQUE(cluster_id,workspace_id,id,version,occurrence_id,owner_id,owner_credential_epoch,delegation_id,delegation_version,delegation_hmac,spec_hmac,window_start,window_end),
 FOREIGN KEY(cluster_id,workspace_id,delegation_id,delegation_version,delegation_hmac,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,owner_id,owner_credential_epoch,spec_hmac,expires_at)
  REFERENCES entity_change_owner_delegations(cluster_id,workspace_id,id,version,delegation_hmac,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,owner_id,owner_credential_epoch,spec_hmac,expires_at) ON DELETE RESTRICT,
 CHECK(window_start<=not_before AND not_before<window_end AND window_end<=expires_at),
 CHECK(spec->>'version' IS NOT DISTINCT FROM '1' AND spec->>'executorId' IS NOT DISTINCT FROM owner_id::text
  AND jsonb_typeof(spec->'notBefore') IS NOT DISTINCT FROM 'string' AND jsonb_typeof(spec->'windowStart') IS NOT DISTINCT FROM 'string' AND jsonb_typeof(spec->'windowEnd') IS NOT DISTINCT FROM 'string'
  AND (spec->>'notBefore')::timestamptz IS NOT DISTINCT FROM not_before AND (spec->>'windowStart')::timestamptz IS NOT DISTINCT FROM window_start AND (spec->>'windowEnd')::timestamptz IS NOT DISTINCT FROM window_end),
 CHECK(impact->>'version' IS NOT DISTINCT FROM '1' AND m8_hex64(impact->>'keyId') IS TRUE
  AND jsonb_typeof(impact->'keys') IS NOT DISTINCT FROM 'array' AND jsonb_typeof(impact->'domains') IS NOT DISTINCT FROM 'array' AND jsonb_typeof(impact->'wildcards') IS NOT DISTINCT FROM 'array')
);
CREATE TABLE entity_change_schedule_activations (
 schedule_id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_version integer NOT NULL,
 intent_id uuid NOT NULL,intent_revision integer NOT NULL,material_hmac text NOT NULL,change_digest text NOT NULL,packet_manifest_hmac text NOT NULL,
 workflow_id uuid NOT NULL UNIQUE,workflow_plan_revision integer NOT NULL,workflow_plan_hash text NOT NULL,
 approval_format smallint NOT NULL CHECK(approval_format IN(1,2)),approval_required boolean NOT NULL,
 approval_set_id uuid,approval_set_hmac text,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,schedule_id,schedule_version,workflow_id,workflow_plan_revision,workflow_plan_hash),
 FOREIGN KEY(cluster_id,workspace_id,schedule_id,schedule_version) REFERENCES entity_change_schedules(cluster_id,workspace_id,id,version) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash)
  REFERENCES entity_change_submissions(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,approval_set_id,approval_set_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash)
  REFERENCES workflow_approval_sets(cluster_id,workspace_id,id,set_hmac,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 CHECK((approval_format=1 AND approval_set_id IS NULL AND approval_set_hmac IS NULL)
  OR(approval_format=2 AND((NOT approval_required AND approval_set_id IS NULL AND approval_set_hmac IS NULL)
   OR(approval_required AND approval_set_id IS NOT NULL AND approval_set_hmac IS NOT NULL AND m8_hex64(approval_set_hmac)))))
);
CREATE TABLE entity_change_schedule_claims (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid NOT NULL,schedule_version integer NOT NULL,
 occurrence_id uuid NOT NULL UNIQUE,generation integer NOT NULL CHECK(generation=1),worker_owner_hmac text NOT NULL CHECK(m8_hex64(worker_owner_hmac)),
 workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL,workflow_plan_hash text NOT NULL,
 owner_id uuid NOT NULL,owner_credential_epoch bigint NOT NULL,delegation_id uuid NOT NULL,delegation_version integer NOT NULL,delegation_hmac text NOT NULL,
 spec_hmac text NOT NULL,window_start timestamptz NOT NULL,window_end timestamptz NOT NULL,
 issued_at timestamptz NOT NULL,authority_expires_at timestamptz NOT NULL,initial_lease_until timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(schedule_id),
 UNIQUE(cluster_id,workspace_id,id,schedule_id,schedule_version),
 UNIQUE(cluster_id,workspace_id,id,generation,worker_owner_hmac),
 UNIQUE(cluster_id,workspace_id,id,schedule_id,schedule_version,occurrence_id,generation,worker_owner_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,owner_id,owner_credential_epoch,delegation_id,delegation_version,delegation_hmac,spec_hmac,window_start,window_end),
 FOREIGN KEY(cluster_id,workspace_id,schedule_id,schedule_version,workflow_id,workflow_plan_revision,workflow_plan_hash)
  REFERENCES entity_change_schedule_activations(cluster_id,workspace_id,schedule_id,schedule_version,workflow_id,workflow_plan_revision,workflow_plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,schedule_id,schedule_version,occurrence_id,owner_id,owner_credential_epoch,delegation_id,delegation_version,delegation_hmac,spec_hmac,window_start,window_end)
  REFERENCES entity_change_schedules(cluster_id,workspace_id,id,version,occurrence_id,owner_id,owner_credential_epoch,delegation_id,delegation_version,delegation_hmac,spec_hmac,window_start,window_end) ON DELETE RESTRICT,
 CHECK(window_start<=issued_at AND issued_at<window_end AND issued_at<=created_at AND authority_expires_at>issued_at
  AND authority_expires_at<=issued_at+interval '5 minutes' AND authority_expires_at<=window_end
  AND initial_lease_until>issued_at AND initial_lease_until<=authority_expires_at)
);
CREATE TABLE entity_change_schedule_leases (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,claim_id uuid NOT NULL,generation integer NOT NULL,worker_owner_hmac text NOT NULL,
 lease_version integer NOT NULL CHECK(lease_version>0),previous_id uuid REFERENCES entity_change_schedule_leases(id) ON DELETE RESTRICT,lease_until timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(claim_id,lease_version),
 FOREIGN KEY(cluster_id,workspace_id,claim_id,generation,worker_owner_hmac) REFERENCES entity_change_schedule_claims(cluster_id,workspace_id,id,generation,worker_owner_hmac) ON DELETE RESTRICT,
 CHECK((lease_version=1 AND previous_id IS NULL) OR(lease_version>1 AND previous_id IS NOT NULL)),CHECK(lease_until>created_at)
);
CREATE TABLE entity_change_schedule_progress (
 schedule_id uuid PRIMARY KEY REFERENCES entity_change_schedules(id) ON DELETE RESTRICT,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_version integer NOT NULL,
 state text NOT NULL DEFAULT 'pending-approval' CHECK(state IN('pending-approval','active','claimed','running','succeeded','partial','failed','uncertain','blocked','cancelled','expired')),
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),claim_id uuid UNIQUE REFERENCES entity_change_schedule_claims(id) ON DELETE RESTRICT,
 reason_code text CHECK(reason_code IS NULL OR reason_code~'^[A-Z0-9_]{1,128}$'),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(cluster_id,workspace_id,schedule_id,schedule_version) REFERENCES entity_change_schedules(cluster_id,workspace_id,id,version) ON DELETE RESTRICT,
 CHECK((state IN('pending-approval','active','blocked','cancelled','expired') AND claim_id IS NULL) OR(state IN('claimed','running','succeeded','partial','failed','uncertain') AND claim_id IS NOT NULL)),
 CHECK(updated_at>=created_at)
);
CREATE INDEX entity_change_schedule_due ON entity_change_schedule_progress(state,schedule_id) WHERE state='active';
CREATE TABLE entity_change_schedule_events (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid NOT NULL,schedule_version integer NOT NULL,
 event_kind text NOT NULL CHECK(event_kind IN('draft','activated','claimed','lease-extended','blocked','cancelled','expired','succeeded','partial','failed','uncertain')),
 actor_id uuid REFERENCES users(id) ON DELETE RESTRICT,claim_id uuid,
 reason_code text CHECK(reason_code IS NULL OR reason_code~'^[A-Z0-9_]{1,128}$'),occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(cluster_id,workspace_id,schedule_id,schedule_version) REFERENCES entity_change_schedules(cluster_id,workspace_id,id,version) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,claim_id,schedule_id,schedule_version) REFERENCES entity_change_schedule_claims(cluster_id,workspace_id,id,schedule_id,schedule_version) ON DELETE RESTRICT,
 CHECK((event_kind IN('draft','activated','blocked','cancelled','expired') AND claim_id IS NULL) OR(event_kind IN('claimed','lease-extended','succeeded','partial','failed','uncertain') AND claim_id IS NOT NULL))
);

CREATE FUNCTION m11_validate_schedule_storage() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE s entity_change_schedules%ROWTYPE;p entity_change_schedule_progress%ROWTYPE;a entity_change_schedule_activations%ROWTYPE;c entity_change_schedule_claims%ROWTYPE;w workflows%ROWTYPE;v entity_change_intent_versions%ROWTYPE;
 BEGIN
 IF TG_TABLE_NAME='entity_change_schedules' THEN SELECT * INTO s FROM entity_change_schedules WHERE id=NEW.id;
 ELSIF TG_TABLE_NAME='entity_change_schedule_leases' THEN SELECT * INTO s FROM entity_change_schedules WHERE id=(SELECT schedule_id FROM entity_change_schedule_claims WHERE id=NEW.claim_id);
 ELSE SELECT * INTO s FROM entity_change_schedules WHERE id=NEW.schedule_id;END IF;
 IF s.id IS NULL THEN RAISE EXCEPTION 'Schedule identity missing' USING ERRCODE='23514';END IF;
 SELECT * INTO p FROM entity_change_schedule_progress WHERE schedule_id=s.id;
 SELECT * INTO a FROM entity_change_schedule_activations WHERE schedule_id=s.id;
 SELECT * INTO c FROM entity_change_schedule_claims WHERE schedule_id=s.id;
 SELECT * INTO v FROM entity_change_intent_versions WHERE cluster_id=s.cluster_id AND workspace_id=s.workspace_id AND intent_id=s.intent_id AND intent_revision=s.intent_revision;
 IF p.schedule_id IS NULL OR p.cluster_id IS DISTINCT FROM s.cluster_id OR p.workspace_id IS DISTINCT FROM s.workspace_id OR p.schedule_version IS DISTINCT FROM s.version
  OR v.intent_id IS NULL OR s.owner_id IS DISTINCT FROM v.requester_id OR s.owner_credential_epoch IS DISTINCT FROM v.credential_epoch
 THEN RAISE EXCEPTION 'Schedule must retain its exact requester and progress identity' USING ERRCODE='23514';END IF;
 IF a.schedule_id IS NOT NULL THEN
  SELECT * INTO w FROM workflows WHERE id=a.workflow_id;
  IF ROW(a.intent_id,a.intent_revision,a.material_hmac,a.change_digest,a.packet_manifest_hmac) IS DISTINCT FROM ROW(s.intent_id,s.intent_revision,s.material_hmac,s.change_digest,s.packet_manifest_hmac)
   OR w.id IS NULL OR w.kind<>'native-change' OR w.requester_user_id IS DISTINCT FROM s.owner_id OR w.plan_revision IS DISTINCT FROM a.workflow_plan_revision OR w.plan_hash IS DISTINCT FROM a.workflow_plan_hash
   OR w.approval_format IS DISTINCT FROM a.approval_format OR w.approval_required IS DISTINCT FROM a.approval_required
   OR w.approval_set_id IS DISTINCT FROM a.approval_set_id OR w.approval_set_hmac IS DISTINCT FROM a.approval_set_hmac
  THEN RAISE EXCEPTION 'Schedule activation requires its exact submitted approval facts' USING ERRCODE='23514';END IF;
  IF p.state='pending-approval' THEN RAISE EXCEPTION 'Activation and effective progress must commit together' USING ERRCODE='23514';END IF;
 END IF;
 IF p.state IN('active','claimed','running','succeeded','partial','failed','uncertain') AND a.schedule_id IS NULL THEN
  RAISE EXCEPTION 'Unapproved draft cannot be due or executed' USING ERRCODE='23514';END IF;
 IF (c.id IS NULL) IS DISTINCT FROM (p.claim_id IS NULL) OR c.id IS DISTINCT FROM p.claim_id THEN
  RAISE EXCEPTION 'Occurrence claim cannot be detached or replaced' USING ERRCODE='23514';END IF;
 IF c.id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM entity_change_schedule_leases stored_lease WHERE stored_lease.claim_id=c.id AND stored_lease.lease_version=1 AND stored_lease.lease_until=c.initial_lease_until) THEN
  RAISE EXCEPTION 'Once claim requires its immutable initial lease' USING ERRCODE='23514';END IF;
 RETURN NULL;
 END;
$$;
CREATE FUNCTION m11_guard_schedule_progress() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Schedule progress cannot be deleted' USING ERRCODE='23514';END IF;
 IF ROW(NEW.schedule_id,NEW.cluster_id,NEW.workspace_id,NEW.schedule_version,NEW.created_at) IS DISTINCT FROM ROW(OLD.schedule_id,OLD.cluster_id,OLD.workspace_id,OLD.schedule_version,OLD.created_at)
  OR NEW.revision<>OLD.revision+1 OR OLD.claim_id IS NOT NULL AND NEW.claim_id IS DISTINCT FROM OLD.claim_id
  OR OLD.state IN('succeeded','partial','failed','uncertain','blocked','cancelled','expired')
  OR NOT(OLD.state='pending-approval' AND NEW.state IN('active','blocked','cancelled','expired')
    OR OLD.state='active' AND NEW.state IN('claimed','blocked','cancelled','expired')
    OR OLD.state='claimed' AND NEW.state IN('claimed','running','succeeded','partial','failed','uncertain')
    OR OLD.state='running' AND NEW.state IN('running','succeeded','partial','failed','uncertain'))
 THEN RAISE EXCEPTION 'Schedule identity, once claim and terminal state are fenced' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER entity_schedule_progress_identity BEFORE UPDATE OR DELETE ON entity_change_schedule_progress FOR EACH ROW EXECUTE FUNCTION m11_guard_schedule_progress();
CREATE TRIGGER entity_schedule_progress_no_truncate BEFORE TRUNCATE ON entity_change_schedule_progress FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();
CREATE FUNCTION m11_validate_schedule_draft() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('entity-change-submit:'||NEW.cluster_id::text||':'||NEW.workspace_id::text||':'||NEW.intent_id::text||':'||NEW.intent_revision::text,0));
 IF EXISTS(SELECT 1 FROM entity_change_submissions submitted WHERE submitted.cluster_id=NEW.cluster_id AND submitted.workspace_id=NEW.workspace_id AND submitted.intent_id=NEW.intent_id AND submitted.intent_revision=NEW.intent_revision) THEN
  RAISE EXCEPTION 'Schedule must be sealed before submission and cannot attach to historical approval' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER entity_schedule_draft_unsubmitted BEFORE INSERT ON entity_change_schedules FOR EACH ROW EXECUTE FUNCTION m11_validate_schedule_draft();
CREATE FUNCTION m11_fence_scheduled_submission() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('entity-change-submit:'||NEW.cluster_id::text||':'||NEW.workspace_id::text||':'||NEW.intent_id::text||':'||NEW.intent_revision::text,0));
 RETURN NEW;
 END;
$$;
CREATE TRIGGER entity_submissions_schedule_fence BEFORE INSERT ON entity_change_submissions FOR EACH ROW EXECUTE FUNCTION m11_fence_scheduled_submission();
CREATE FUNCTION m11_validate_schedule_activation() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE s entity_change_schedules%ROWTYPE;w workflows%ROWTYPE;
 BEGIN
 SELECT * INTO s FROM entity_change_schedules WHERE id=NEW.schedule_id;
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 IF s.id IS NULL OR w.id IS NULL OR w.kind<>'native-change' OR w.requester_user_id IS DISTINCT FROM s.owner_id
  OR (w.approval_required AND w.state<>'approved') OR (NOT w.approval_required AND w.state<>'pending') OR clock_timestamp()>=s.window_end
 THEN RAISE EXCEPTION 'Only the exact approved or direct current workflow activates its schedule' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||s.transport_scope,0));
 IF EXISTS(SELECT 1 FROM entity_change_schedules other JOIN entity_change_schedule_progress p ON p.schedule_id=other.id JOIN entity_change_schedule_activations a ON a.schedule_id=other.id
   WHERE other.id<>s.id AND other.transport_scope=s.transport_scope AND p.state IN('active','claimed','running','uncertain')
   AND (p.state='uncertain' OR s.window_start<other.window_end AND other.window_start<s.window_end) AND m6_rejected_impact_collision(other.impact,s.impact)) THEN
  RAISE EXCEPTION 'Physical impact is reserved by an overlapping window or unresolved occurrence' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER entity_schedule_activation_current BEFORE INSERT ON entity_change_schedule_activations FOR EACH ROW EXECUTE FUNCTION m11_validate_schedule_activation();
CREATE FUNCTION m11_validate_schedule_claim() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE s entity_change_schedules%ROWTYPE;p entity_change_schedule_progress%ROWTYPE;w workflows%ROWTYPE;u users%ROWTYPE;
 BEGIN
 SELECT * INTO s FROM entity_change_schedules WHERE id=NEW.schedule_id;
 SELECT * INTO p FROM entity_change_schedule_progress WHERE schedule_id=NEW.schedule_id FOR UPDATE;
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 SELECT * INTO u FROM users WHERE id=NEW.owner_id;
 IF s.id IS NULL OR p.schedule_id IS NULL OR p.state<>'active' OR p.claim_id IS NOT NULL OR w.id IS NULL OR u.id IS NULL
  OR NEW.issued_at<s.not_before OR NEW.issued_at>clock_timestamp() OR NEW.authority_expires_at<=clock_timestamp() OR NEW.authority_expires_at>s.expires_at
  OR u.status<>'active' OR u.deleted_at IS NOT NULL OR u.force_password_change OR u.credential_epoch IS DISTINCT FROM NEW.owner_credential_epoch
  OR (w.approval_required AND w.state<>'approved') OR (NOT w.approval_required AND w.state<>'pending')
 THEN RAISE EXCEPTION 'Due claim requires the current active owner, approval and UTC window' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||s.transport_scope,0));
 IF EXISTS(SELECT 1 FROM mutation_operations m WHERE m.state IN('pending','running','uncertain')
  AND (m.transport_scope=s.transport_scope OR m.transport_scope IS NULL AND m.cluster_id=s.cluster_id) AND m6_rejected_impact_collision(m.impact,s.impact)) THEN
  RAISE EXCEPTION 'Unresolved physical mutation blocks the due claim' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER entity_schedule_claim_current BEFORE INSERT ON entity_change_schedule_claims FOR EACH ROW EXECUTE FUNCTION m11_validate_schedule_claim();
CREATE FUNCTION m11_validate_schedule_lease() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE c entity_change_schedule_claims%ROWTYPE;p entity_change_schedule_leases%ROWTYPE;progress entity_change_schedule_progress%ROWTYPE;
 BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('entity-schedule-claim:'||NEW.claim_id::text,0));
 SELECT * INTO c FROM entity_change_schedule_claims WHERE id=NEW.claim_id;
 SELECT * INTO p FROM entity_change_schedule_leases WHERE claim_id=NEW.claim_id ORDER BY lease_version DESC LIMIT 1;
 SELECT * INTO progress FROM entity_change_schedule_progress WHERE schedule_id=c.schedule_id;
 IF c.id IS NULL OR NEW.lease_until>c.authority_expires_at OR NEW.lease_until<=clock_timestamp()
  OR p.id IS NOT NULL AND(progress.state NOT IN('claimed','running') OR progress.claim_id IS DISTINCT FROM c.id)
  OR p.id IS NULL AND(NEW.lease_version<>1 OR NEW.previous_id IS NOT NULL OR NEW.lease_until IS DISTINCT FROM c.initial_lease_until)
  OR p.id IS NOT NULL AND(NEW.lease_version<>p.lease_version+1 OR NEW.previous_id IS DISTINCT FROM p.id OR p.lease_until<=clock_timestamp() OR NEW.lease_until<=p.lease_until)
 THEN RAISE EXCEPTION 'Lease must extend the same live generation without stealing an expired claim' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER entity_schedule_lease_current BEFORE INSERT ON entity_change_schedule_leases FOR EACH ROW EXECUTE FUNCTION m11_validate_schedule_lease();

ALTER TABLE entity_change_execution_sources ADD COLUMN origin_type text NOT NULL DEFAULT 'http' CHECK(origin_type IN('http','scheduled-entity'));
ALTER TABLE entity_change_execution_sources ADD COLUMN schedule_id uuid,ADD COLUMN schedule_version integer,ADD COLUMN spec_hmac text,
 ADD COLUMN delegation_id uuid,ADD COLUMN delegation_version integer,ADD COLUMN delegation_hmac text,
 ADD COLUMN occurrence_id uuid,ADD COLUMN claim_id uuid,ADD COLUMN claim_generation integer,ADD COLUMN worker_owner_hmac text,
 ADD COLUMN window_start timestamptz,ADD COLUMN window_end timestamptz;
ALTER TABLE entity_change_execution_sources ALTER COLUMN session_id DROP NOT NULL;
ALTER TABLE entity_change_execution_sources ADD CONSTRAINT entity_sources_origin_check CHECK(
 (origin_type='http' AND session_id IS NOT NULL AND num_nonnulls(schedule_id,schedule_version,spec_hmac,delegation_id,delegation_version,delegation_hmac,occurrence_id,claim_id,claim_generation,worker_owner_hmac,window_start,window_end)=0)
 OR(origin_type='scheduled-entity' AND session_id IS NULL AND num_nonnulls(schedule_id,schedule_version,spec_hmac,delegation_id,delegation_version,delegation_hmac,occurrence_id,claim_id,claim_generation,worker_owner_hmac,window_start,window_end)=12
  AND schedule_version=1 AND delegation_version=1 AND claim_generation=1 AND m8_hex64(spec_hmac) AND m8_hex64(delegation_hmac) AND m8_hex64(worker_owner_hmac)
  AND window_start<=issued_at AND issued_at<window_end AND expires_at<=window_end));
ALTER TABLE entity_change_execution_sources ADD CONSTRAINT entity_sources_schedule_claim_fk FOREIGN KEY(
 cluster_id,workspace_id,claim_id,schedule_id,schedule_version,occurrence_id,claim_generation,worker_owner_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,
 execution_actor_id,credential_epoch,delegation_id,delegation_version,delegation_hmac,spec_hmac,window_start,window_end)
 REFERENCES entity_change_schedule_claims(cluster_id,workspace_id,id,schedule_id,schedule_version,occurrence_id,generation,worker_owner_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,
 owner_id,owner_credential_epoch,delegation_id,delegation_version,delegation_hmac,spec_hmac,window_start,window_end) ON DELETE RESTRICT;
CREATE FUNCTION m11_validate_scheduled_execution_source(src entity_change_execution_sources) RETURNS entity_change_execution_sources LANGUAGE plpgsql AS $$
 DECLARE s entity_change_schedules%ROWTYPE;c entity_change_schedule_claims%ROWTYPE;p entity_change_schedule_progress%ROWTYPE;l entity_change_schedule_leases%ROWTYPE;
  e workflow_executions%ROWTYPE;w workflows%ROWTYPE;u users%ROWTYPE;
 BEGIN
 SELECT * INTO s FROM entity_change_schedules WHERE id=src.schedule_id;
 SELECT * INTO c FROM entity_change_schedule_claims WHERE id=src.claim_id;
 SELECT * INTO p FROM entity_change_schedule_progress WHERE schedule_id=src.schedule_id;
 SELECT * INTO l FROM entity_change_schedule_leases WHERE claim_id=src.claim_id ORDER BY lease_version DESC LIMIT 1;
 SELECT * INTO e FROM workflow_executions WHERE id=src.workflow_execution_id;
 SELECT * INTO w FROM workflows WHERE id=src.workflow_id;
 SELECT * INTO u FROM users WHERE id=src.execution_actor_id;
 IF s.id IS NULL OR c.id IS NULL OR p.schedule_id IS NULL OR l.id IS NULL OR e.id IS NULL OR w.id IS NULL OR u.id IS NULL
  OR src.session_id IS NOT NULL OR p.claim_id IS DISTINCT FROM c.id OR p.state NOT IN('claimed','running') OR e.state<>'executing' OR w.state<>'executing'
  OR src.execution_actor_id IS DISTINCT FROM s.owner_id OR e.execution_actor_id IS DISTINCT FROM s.owner_id OR w.requester_user_id IS DISTINCT FROM s.owner_id
  OR u.status<>'active' OR u.deleted_at IS NOT NULL OR u.force_password_change OR u.credential_epoch IS DISTINCT FROM src.credential_epoch
  OR ROW(src.intent_id,src.intent_revision,src.material_hmac,src.change_digest,src.packet_manifest_hmac) IS DISTINCT FROM ROW(s.intent_id,s.intent_revision,s.material_hmac,s.change_digest,s.packet_manifest_hmac)
  OR src.issued_at<c.issued_at OR src.issued_at<s.not_before OR src.issued_at>clock_timestamp() OR src.expires_at<=clock_timestamp()
  OR src.expires_at>c.authority_expires_at OR src.expires_at>l.lease_until OR src.expires_at>s.expires_at OR src.expires_at>e.expires_at OR l.lease_until<=clock_timestamp()
 THEN RAISE EXCEPTION 'Scheduled source requires its real delegation, once claim, live lease and requester execution without SID' USING ERRCODE='23514';END IF;RETURN src;
 END;
$$;
-- Preserve the latest HTTP guard verbatim, including its actual auth_sessions
-- lookup and every pre-023 condition. Only the new fixed origin branches away.
DO $m11_schedule$ DECLARE definition text;BEGIN
 definition=pg_get_functiondef('m11_validate_execution_source()'::regprocedure);
 IF strpos(definition,'m11_validate_scheduled_execution_source')>0 THEN RAISE EXCEPTION 'Scheduled source guard already installed';END IF;
 definition=regexp_replace(definition,'\mBEGIN\M',E'BEGIN\n IF NEW.origin_type=''scheduled-entity'' THEN RETURN m11_validate_scheduled_execution_source(NEW);END IF;');
 EXECUTE definition;
END;$m11_schedule$;
CREATE FUNCTION m11_validate_source_schedule_origin() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 IF NEW.origin_type='http' AND EXISTS(SELECT 1 FROM entity_change_schedules sealed WHERE sealed.cluster_id=NEW.cluster_id AND sealed.workspace_id=NEW.workspace_id AND sealed.intent_id=NEW.intent_id AND sealed.intent_revision=NEW.intent_revision) THEN
  RAISE EXCEPTION 'Scheduled intent cannot borrow an HTTP execution origin' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER entity_sources_scheduled_intent_origin BEFORE INSERT ON entity_change_execution_sources FOR EACH ROW EXECUTE FUNCTION m11_validate_source_schedule_origin();

DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['entity_change_schedules','entity_change_schedule_activations','entity_change_schedule_claims','entity_change_schedule_progress','entity_change_schedule_leases'] LOOP
  EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT%s ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_schedule_storage()',tab||'_complete',CASE WHEN tab='entity_change_schedule_progress' THEN ' OR UPDATE' ELSE '' END,tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['entity_change_owner_delegations','entity_change_schedules','entity_change_schedule_activations','entity_change_schedule_claims','entity_change_schedule_leases','entity_change_schedule_events'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
END;$$;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_owner_delegations,entity_change_schedules,entity_change_schedule_activations,entity_change_schedule_claims,entity_change_schedule_leases,entity_change_schedule_events FROM PUBLIC;
REVOKE DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_schedule_progress FROM PUBLIC;
