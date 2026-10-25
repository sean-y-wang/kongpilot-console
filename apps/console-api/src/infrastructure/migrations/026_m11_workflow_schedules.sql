-- Candidate M11 business schedules. No runtime adapter is installed by SQL.
-- A final immutable plan commits scheduling before its first vote. Developer
-- requester, accepting Console executor and original once claim stay separate.
CREATE TABLE workflow_executor_delegations (
 id uuid PRIMARY KEY,version integer NOT NULL DEFAULT 1 CHECK(version=1),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL CHECK(workflow_plan_revision>0),base_plan_hash text NOT NULL CHECK(m8_hex64(base_plan_hash)),
 kind text NOT NULL CHECK(kind IN('configuration_v2','portal-credential-issue')),subject_type text NOT NULL,subject_id uuid NOT NULL,
 requester_type text NOT NULL CHECK(requester_type IN('console','developer')),requester_id uuid NOT NULL,requester_credential_epoch bigint NOT NULL CHECK(requester_credential_epoch>0),
 owner_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,executor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 owner_credential_epoch bigint NOT NULL CHECK(owner_credential_epoch>0),executor_credential_epoch bigint NOT NULL CHECK(executor_credential_epoch>0),
 spec_hmac text NOT NULL CHECK(m8_hex64(spec_hmac)),delegation_hmac text NOT NULL CHECK(m8_hex64(delegation_hmac)),
 delegation_ciphertext text NOT NULL CHECK(m6_encrypted(delegation_ciphertext,65536)),policy_hash text NOT NULL CHECK(m8_hex64(policy_hash)),subject_seal_hmac text NOT NULL CHECK(m8_hex64(subject_seal_hmac)),
 issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,id,delegation_hmac,workflow_id,workflow_plan_revision,base_plan_hash,owner_id,executor_id,owner_credential_epoch,executor_credential_epoch,
  requester_type,requester_id,requester_credential_epoch,spec_hmac,policy_hash,subject_seal_hmac,expires_at),
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,workflow_plan_revision) REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(owner_id=executor_id AND owner_credential_epoch=executor_credential_epoch),
 CHECK((kind='configuration_v2' AND subject_type='configuration_jobs' AND requester_type='console' AND requester_id=owner_id AND requester_credential_epoch=owner_credential_epoch)
  OR(kind='portal-credential-issue' AND subject_type='portal_application_grants' AND requester_type='developer')),
 CHECK(issued_at<=created_at AND issued_at<expires_at AND expires_at<=issued_at+interval '168 hours')
);
CREATE TABLE workflow_schedules (
 id uuid PRIMARY KEY,version integer NOT NULL DEFAULT 1 CHECK(version=1),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL,workflow_plan_hash text NOT NULL CHECK(m8_hex64(workflow_plan_hash)),base_plan_hash text NOT NULL,
 kind text NOT NULL CHECK(kind IN('configuration_v2','portal-credential-issue')),delegation_id uuid NOT NULL,delegation_hmac text NOT NULL,spec_hmac text NOT NULL,
 owner_id uuid NOT NULL,executor_id uuid NOT NULL,owner_credential_epoch bigint NOT NULL,executor_credential_epoch bigint NOT NULL,
 requester_type text NOT NULL,requester_id uuid NOT NULL,requester_credential_epoch bigint NOT NULL,policy_hash text NOT NULL,subject_seal_hmac text NOT NULL,
 definition_id uuid NOT NULL,definition_version integer NOT NULL CHECK(definition_version>0),
 spec jsonb NOT NULL CHECK(m7_object(spec,4096)),not_before timestamptz NOT NULL,window_start timestamptz NOT NULL,window_end timestamptz NOT NULL,expires_at timestamptz NOT NULL,
 occurrence_id uuid NOT NULL UNIQUE,transport_scope text NOT NULL CHECK(m8_hex64(transport_scope)),impact_hmac text NOT NULL CHECK(m8_hex64(impact_hmac)),impact jsonb NOT NULL CHECK(m7_object(impact,8388608)),
 draft_hmac text NOT NULL CHECK(m8_hex64(draft_hmac)),draft_ciphertext text NOT NULL CHECK(m6_encrypted(draft_ciphertext,12582912)),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(workflow_id,workflow_plan_revision),UNIQUE(cluster_id,workspace_id,id),
 UNIQUE(cluster_id,workspace_id,id,occurrence_id,workflow_id,workflow_plan_revision,workflow_plan_hash),
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,definition_id,definition_version) REFERENCES workflow_definition_versions(cluster_id,workspace_id,definition_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,delegation_id,delegation_hmac,workflow_id,workflow_plan_revision,base_plan_hash,owner_id,executor_id,owner_credential_epoch,executor_credential_epoch,
  requester_type,requester_id,requester_credential_epoch,spec_hmac,policy_hash,subject_seal_hmac,expires_at)
  REFERENCES workflow_executor_delegations(cluster_id,workspace_id,id,delegation_hmac,workflow_id,workflow_plan_revision,base_plan_hash,owner_id,executor_id,owner_credential_epoch,executor_credential_epoch,
  requester_type,requester_id,requester_credential_epoch,spec_hmac,policy_hash,subject_seal_hmac,expires_at) ON DELETE RESTRICT,
 CHECK(window_start<=not_before AND not_before<window_end AND window_end<=expires_at),
 CHECK(spec->>'version' IS NOT DISTINCT FROM '1' AND spec->>'executorId' IS NOT DISTINCT FROM executor_id::text
  AND jsonb_typeof(spec->'notBefore') IS NOT DISTINCT FROM 'string' AND jsonb_typeof(spec->'windowStart') IS NOT DISTINCT FROM 'string' AND jsonb_typeof(spec->'windowEnd') IS NOT DISTINCT FROM 'string'
  AND (spec->>'notBefore')::timestamptz IS NOT DISTINCT FROM not_before AND (spec->>'windowStart')::timestamptz IS NOT DISTINCT FROM window_start AND (spec->>'windowEnd')::timestamptz IS NOT DISTINCT FROM window_end),
 CHECK(impact->>'version' IS NOT DISTINCT FROM '1' AND m8_hex64(impact->>'keyId') IS TRUE
  AND jsonb_typeof(impact->'keys') IS NOT DISTINCT FROM 'array' AND jsonb_typeof(impact->'domains') IS NOT DISTINCT FROM 'array' AND jsonb_typeof(impact->'wildcards') IS NOT DISTINCT FROM 'array')
);
CREATE TABLE workflow_schedule_activations (
 schedule_id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL,workflow_plan_hash text NOT NULL,
 approval_format smallint NOT NULL CHECK(approval_format IN(1,2)),approval_required boolean NOT NULL DEFAULT true CHECK(approval_required),approval_set_id uuid,approval_set_hmac text,
 activation jsonb NOT NULL CHECK(m7_object(activation,4096)),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,schedule_id,workflow_id,workflow_plan_revision,workflow_plan_hash),
 FOREIGN KEY(cluster_id,workspace_id,schedule_id) REFERENCES workflow_schedules(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,approval_set_id,approval_set_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_approval_sets(cluster_id,workspace_id,id,set_hmac,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 CHECK((approval_format=1 AND approval_set_id IS NULL AND approval_set_hmac IS NULL) OR(approval_format=2 AND approval_set_id IS NOT NULL AND approval_set_hmac IS NOT NULL AND m8_hex64(approval_set_hmac))),
 CHECK(activation->>'workflowId' IS NOT DISTINCT FROM workflow_id::text AND activation->>'workflowPlanRevision' IS NOT DISTINCT FROM workflow_plan_revision::text
  AND activation->>'workflowPlanHash' IS NOT DISTINCT FROM workflow_plan_hash AND activation->>'approvalRequired' IS NOT DISTINCT FROM 'true'
  AND activation->>'approvalFormat' IS NOT DISTINCT FROM approval_format::text AND activation->>'approvalSetId' IS NOT DISTINCT FROM approval_set_id::text AND activation->>'approvalSetHmac' IS NOT DISTINCT FROM approval_set_hmac)
);
CREATE TABLE workflow_schedule_claims (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid NOT NULL UNIQUE,schedule_version integer NOT NULL DEFAULT 1 CHECK(schedule_version=1),
 occurrence_id uuid NOT NULL UNIQUE,generation integer NOT NULL CHECK(generation=1),worker_owner_hmac text NOT NULL CHECK(m8_hex64(worker_owner_hmac)),
 workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL,workflow_plan_hash text NOT NULL,
 issued_at timestamptz NOT NULL,authority_expires_at timestamptz NOT NULL,initial_lease_until timestamptz NOT NULL,
 claim jsonb NOT NULL CHECK(m7_object(claim,8192)),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,id,schedule_id),UNIQUE(cluster_id,workspace_id,id,generation,worker_owner_hmac),
 UNIQUE(cluster_id,workspace_id,id,schedule_id,workflow_id,workflow_plan_revision,workflow_plan_hash),
 FOREIGN KEY(cluster_id,workspace_id,schedule_id,occurrence_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_schedules(cluster_id,workspace_id,id,occurrence_id,workflow_id,workflow_plan_revision,workflow_plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,schedule_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_schedule_activations(cluster_id,workspace_id,schedule_id,workflow_id,workflow_plan_revision,workflow_plan_hash) ON DELETE RESTRICT,
 CHECK(issued_at<=created_at AND issued_at<authority_expires_at AND authority_expires_at<=issued_at+interval '5 minutes' AND issued_at<initial_lease_until AND initial_lease_until<=authority_expires_at),
 CHECK(claim->>'id' IS NOT DISTINCT FROM id::text AND claim->>'scheduleId' IS NOT DISTINCT FROM schedule_id::text AND claim->>'scheduleVersion' IS NOT DISTINCT FROM '1'
  AND claim->>'occurrenceId' IS NOT DISTINCT FROM occurrence_id::text AND claim->>'generation' IS NOT DISTINCT FROM '1' AND claim->>'workerOwnerHmac' IS NOT DISTINCT FROM worker_owner_hmac
  AND claim->>'workflowId' IS NOT DISTINCT FROM workflow_id::text AND claim->>'workflowPlanRevision' IS NOT DISTINCT FROM workflow_plan_revision::text AND claim->>'workflowPlanHash' IS NOT DISTINCT FROM workflow_plan_hash
  AND jsonb_typeof(claim->'issuedAt') IS NOT DISTINCT FROM 'string' AND (claim->>'issuedAt')::timestamptz IS NOT DISTINCT FROM issued_at
  AND jsonb_typeof(claim->'authorityExpiresAt') IS NOT DISTINCT FROM 'string' AND (claim->>'authorityExpiresAt')::timestamptz IS NOT DISTINCT FROM authority_expires_at
  AND jsonb_typeof(claim->'initialLeaseUntil') IS NOT DISTINCT FROM 'string' AND (claim->>'initialLeaseUntil')::timestamptz IS NOT DISTINCT FROM initial_lease_until)
);
CREATE TABLE workflow_schedule_leases (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,claim_id uuid NOT NULL,generation integer NOT NULL,worker_owner_hmac text NOT NULL,
 lease_version integer NOT NULL CHECK(lease_version>0),previous_id uuid REFERENCES workflow_schedule_leases(id) ON DELETE RESTRICT,lease_until timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(claim_id,lease_version),
 FOREIGN KEY(cluster_id,workspace_id,claim_id,generation,worker_owner_hmac) REFERENCES workflow_schedule_claims(cluster_id,workspace_id,id,generation,worker_owner_hmac) ON DELETE RESTRICT,
 CHECK((lease_version=1 AND previous_id IS NULL) OR(lease_version>1 AND previous_id IS NOT NULL)),CHECK(lease_until>created_at)
);
CREATE TABLE workflow_schedule_progress (
 schedule_id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 state text NOT NULL DEFAULT 'pending-approval' CHECK(state IN('pending-approval','active','claimed','running','succeeded','partial','failed','uncertain','blocked','cancelled','expired')),
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),claim_id uuid UNIQUE,reason_code text CHECK(reason_code IS NULL OR reason_code~'^[A-Z0-9_]{1,128}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(cluster_id,workspace_id,schedule_id) REFERENCES workflow_schedules(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,claim_id,schedule_id) REFERENCES workflow_schedule_claims(cluster_id,workspace_id,id,schedule_id) ON DELETE RESTRICT,
 CHECK((state IN('pending-approval','active','blocked','cancelled','expired') AND claim_id IS NULL) OR(state IN('claimed','running','succeeded','partial','failed','uncertain') AND claim_id IS NOT NULL)),CHECK(updated_at>=created_at)
);
CREATE INDEX workflow_schedule_due ON workflow_schedule_progress(state,schedule_id) WHERE state='active';
CREATE TABLE workflow_schedule_outcomes (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid NOT NULL,claim_id uuid NOT NULL UNIQUE,
 outcome text NOT NULL CHECK(outcome IN('succeeded','partial','failed','uncertain')),provenance text NOT NULL CHECK(provenance IN('original-execution','callback-not-entered')),
 evidence_hmac text NOT NULL CHECK(m8_hex64(evidence_hmac)),occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(cluster_id,workspace_id,claim_id,schedule_id) REFERENCES workflow_schedule_claims(cluster_id,workspace_id,id,schedule_id) ON DELETE RESTRICT,
 CHECK(provenance<>'callback-not-entered' OR outcome='failed')
);
CREATE TABLE workflow_schedule_events (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid NOT NULL,
 event_kind text NOT NULL CHECK(event_kind IN('draft','activated','claimed','running','lease-extended','blocked','cancelled','expired','succeeded','partial','failed','uncertain')),
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,claim_id uuid,reason_code text CHECK(reason_code IS NULL OR reason_code~'^[A-Z0-9_]{1,128}$'),occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(cluster_id,workspace_id,schedule_id) REFERENCES workflow_schedules(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,claim_id,schedule_id) REFERENCES workflow_schedule_claims(cluster_id,workspace_id,id,schedule_id) ON DELETE RESTRICT,
 CHECK((event_kind IN('draft','activated','blocked','cancelled','expired') AND claim_id IS NULL) OR(event_kind IN('claimed','running','lease-extended','succeeded','partial','failed','uncertain') AND claim_id IS NOT NULL))
);
-- Wrapper and nested configuration origins are separate immutable facts. The
-- second is appended only after a genuine configuration execution exists.
CREATE TABLE workflow_execution_origins (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid NOT NULL,claim_id uuid NOT NULL UNIQUE,
 workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL,workflow_plan_hash text NOT NULL,execution_id uuid NOT NULL UNIQUE,
 executor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,id,claim_id,execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash),
 FOREIGN KEY(cluster_id,workspace_id,claim_id,schedule_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_schedule_claims(cluster_id,workspace_id,id,schedule_id,workflow_id,workflow_plan_revision,workflow_plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT
);
CREATE TABLE workflow_configuration_execution_origins (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,wrapper_origin_id uuid NOT NULL UNIQUE,claim_id uuid NOT NULL,
 workflow_execution_id uuid NOT NULL,workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL,workflow_plan_hash text NOT NULL,
 configuration_execution_id uuid NOT NULL UNIQUE,configuration_job_id uuid NOT NULL,configuration_plan_id uuid NOT NULL,configuration_plan_revision integer NOT NULL,configuration_plan_hash text NOT NULL,
 workflow_step_id uuid NOT NULL REFERENCES workflow_steps(id) ON DELETE RESTRICT,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(cluster_id,workspace_id,wrapper_origin_id,claim_id,workflow_execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_execution_origins(cluster_id,workspace_id,id,claim_id,execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,configuration_execution_id,configuration_job_id,configuration_plan_revision,configuration_plan_hash) REFERENCES configuration_executions(cluster_id,workspace_id,id,job_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,configuration_plan_id,configuration_plan_revision,configuration_plan_hash) REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) ON DELETE RESTRICT
);

CREATE FUNCTION m11_business_schedule_draft() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE w workflows%ROWTYPE;d workflow_executor_delegations%ROWTYPE;v workflow_versions%ROWTYPE;
 BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('workflow:'||NEW.workflow_id::text,0));
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id FOR UPDATE;
 SELECT * INTO d FROM workflow_executor_delegations WHERE id=NEW.delegation_id;
 SELECT * INTO v FROM workflow_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND workflow_id=NEW.workflow_id AND plan_revision=NEW.workflow_plan_revision;
 IF w.id IS NULL OR d.id IS NULL OR v.workflow_id IS NULL OR w.state NOT IN('draft','pending') OR NOT w.approval_required OR NOT v.approval_required
  OR ROW(w.cluster_id,w.workspace_id,w.plan_revision,w.plan_hash,w.kind,w.subject_type,w.subject_id,w.requester_type,w.definition_id,w.definition_version,w.expires_at)
   IS DISTINCT FROM ROW(NEW.cluster_id,NEW.workspace_id,NEW.workflow_plan_revision,NEW.workflow_plan_hash,NEW.kind,d.subject_type,d.subject_id,NEW.requester_type,NEW.definition_id,NEW.definition_version,NEW.expires_at)
  OR d.kind IS DISTINCT FROM NEW.kind OR coalesce(w.requester_user_id,w.requester_developer_id) IS DISTINCT FROM NEW.requester_id OR v.plan_hash IS DISTINCT FROM NEW.workflow_plan_hash
  OR NOT EXISTS(SELECT 1 FROM workflow_definition_versions dv WHERE dv.cluster_id=NEW.cluster_id AND dv.workspace_id=NEW.workspace_id AND dv.definition_id=NEW.definition_id AND dv.version=NEW.definition_version AND dv.policy_hash=NEW.policy_hash)
  OR EXISTS(SELECT 1 FROM workflow_approvals WHERE workflow_id=NEW.workflow_id AND plan_revision=NEW.workflow_plan_revision)
  OR EXISTS(SELECT 1 FROM workflow_approval_sets WHERE workflow_id=NEW.workflow_id AND plan_revision=NEW.workflow_plan_revision)
  OR EXISTS(SELECT 1 FROM workflow_executions WHERE workflow_id=NEW.workflow_id AND plan_revision=NEW.workflow_plan_revision)
 THEN RAISE EXCEPTION 'Business scheduling must be sealed before the first vote of this exact plan' USING ERRCODE='23514';END IF;
 RETURN NEW;
 END;
$$;
CREATE TRIGGER workflow_business_schedule_pre_vote BEFORE INSERT ON workflow_schedules FOR EACH ROW EXECUTE FUNCTION m11_business_schedule_draft();
-- Serialize the first vote with draft sealing; do not alter prior vote facts.
CREATE FUNCTION m11_business_vote_fence() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM pg_advisory_xact_lock(hashtextextended('workflow:'||NEW.workflow_id::text,0));RETURN NEW;END;
$$;
CREATE TRIGGER workflow_business_vote_fence BEFORE INSERT ON workflow_approvals FOR EACH ROW EXECUTE FUNCTION m11_business_vote_fence();

CREATE FUNCTION m11_business_physical_reservation(p_scope text,p_impact jsonb,p_start_at timestamptz,p_end_at timestamptz,own_business uuid DEFAULT NULL,own_entity uuid DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
 BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||p_scope,0));
 IF EXISTS(SELECT 1 FROM workflow_schedules s JOIN workflow_schedule_progress p ON p.schedule_id=s.id
   WHERE s.id IS DISTINCT FROM own_business AND s.transport_scope=p_scope AND p.state IN('active','claimed','running','uncertain')
    AND(p.state='uncertain' OR p_start_at<s.window_end AND s.window_start<p_end_at) AND m6_rejected_impact_collision(s.impact,p_impact))
  OR EXISTS(SELECT 1 FROM entity_change_schedules s JOIN entity_change_schedule_progress p ON p.schedule_id=s.id
   WHERE s.id IS DISTINCT FROM own_entity AND s.transport_scope=p_scope AND p.state IN('active','claimed','running','uncertain')
    AND(p.state='uncertain' OR p_start_at<s.window_end AND s.window_start<p_end_at) AND m6_rejected_impact_collision(s.impact,p_impact))
 THEN RAISE EXCEPTION 'Physical effect reserved by a scheduled or unresolved occurrence' USING ERRCODE='23514';END IF;
 END;
$$;
CREATE FUNCTION m11_business_activation() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE s workflow_schedules%ROWTYPE;w workflows%ROWTYPE;p workflow_schedule_progress%ROWTYPE;
 BEGIN
 SELECT * INTO s FROM workflow_schedules WHERE id=NEW.schedule_id;SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id FOR UPDATE;
 SELECT * INTO p FROM workflow_schedule_progress WHERE schedule_id=NEW.schedule_id FOR UPDATE;
 IF s.id IS NULL OR p.schedule_id IS NULL OR p.state<>'pending-approval' OR p.claim_id IS NOT NULL OR w.id IS NULL OR w.state<>'approved' OR NOT w.approval_required
  OR ROW(w.cluster_id,w.workspace_id,w.id,w.plan_revision,w.plan_hash,w.approval_format,w.approval_set_id,w.approval_set_hmac)
   IS DISTINCT FROM ROW(NEW.cluster_id,NEW.workspace_id,NEW.workflow_id,NEW.workflow_plan_revision,NEW.workflow_plan_hash,NEW.approval_format,NEW.approval_set_id,NEW.approval_set_hmac)
  OR ROW(s.workflow_id,s.workflow_plan_revision,s.workflow_plan_hash) IS DISTINCT FROM ROW(NEW.workflow_id,NEW.workflow_plan_revision,NEW.workflow_plan_hash) OR clock_timestamp()>=s.window_end
 THEN RAISE EXCEPTION 'Activation needs the current exact approved business plan' USING ERRCODE='23514';END IF;
 PERFORM m11_business_physical_reservation(s.transport_scope,s.impact,s.window_start,s.window_end,s.id,NULL);RETURN NEW;
 END;
$$;
CREATE TRIGGER workflow_business_activation BEFORE INSERT ON workflow_schedule_activations FOR EACH ROW EXECUTE FUNCTION m11_business_activation();
-- Reciprocal protection: an entity schedule cannot reserve over a business
-- schedule. Existing 024 guard and old facts remain unchanged.
CREATE FUNCTION m11_entity_business_reservation() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE s entity_change_schedules%ROWTYPE;
 BEGIN SELECT * INTO s FROM entity_change_schedules WHERE id=NEW.schedule_id;
 PERFORM m11_business_physical_reservation(s.transport_scope,s.impact,s.window_start,s.window_end,NULL,s.id);RETURN NEW;END;
$$;
CREATE TRIGGER entity_schedule_business_reservation BEFORE INSERT ON entity_change_schedule_activations FOR EACH ROW EXECUTE FUNCTION m11_entity_business_reservation();

CREATE FUNCTION m11_business_claim() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE s workflow_schedules%ROWTYPE;p workflow_schedule_progress%ROWTYPE;w workflows%ROWTYPE;u users%ROWTYPE;
 BEGIN
 PERFORM version FROM iam_epoch WHERE singleton=true FOR SHARE;
 SELECT * INTO s FROM workflow_schedules WHERE id=NEW.schedule_id;SELECT * INTO p FROM workflow_schedule_progress WHERE schedule_id=NEW.schedule_id FOR UPDATE;
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id FOR UPDATE;SELECT * INTO u FROM users WHERE id=s.executor_id;
 IF s.id IS NULL OR p.schedule_id IS NULL OR p.state<>'active' OR p.claim_id IS NOT NULL OR w.id IS NULL OR w.state<>'approved'
  OR ROW(w.plan_revision,w.plan_hash) IS DISTINCT FROM ROW(NEW.workflow_plan_revision,NEW.workflow_plan_hash)
  OR u.id IS NULL OR u.status<>'active' OR u.deleted_at IS NOT NULL OR u.force_password_change OR u.credential_epoch IS DISTINCT FROM s.executor_credential_epoch
  OR NEW.issued_at<s.not_before OR NEW.issued_at<s.window_start OR NEW.issued_at>clock_timestamp() OR NEW.authority_expires_at>least(s.window_end,s.expires_at,w.expires_at)
  OR NEW.authority_expires_at<=clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM workflow_schedule_activations a WHERE a.schedule_id=s.id AND a.workflow_id=w.id AND a.workflow_plan_revision=w.plan_revision AND a.workflow_plan_hash=w.plan_hash
    AND a.approval_format=w.approval_format AND a.approval_required=w.approval_required AND a.approval_set_id IS NOT DISTINCT FROM w.approval_set_id AND a.approval_set_hmac IS NOT DISTINCT FROM w.approval_set_hmac)
  OR s.requester_type='developer' AND NOT EXISTS(SELECT 1 FROM portal_developers d WHERE d.cluster_id=s.cluster_id AND d.workspace_id=s.workspace_id AND d.id=s.requester_id AND d.status='active' AND d.deleted_at IS NULL AND NOT d.must_change_password AND d.credential_epoch=s.requester_credential_epoch)
 THEN RAISE EXCEPTION 'Due occurrence requires live exact owner and independent requester credentials' USING ERRCODE='23514';END IF;
 PERFORM m11_business_physical_reservation(s.transport_scope,s.impact,s.window_start,s.window_end,s.id,NULL);
 IF EXISTS(SELECT 1 FROM mutation_operations m WHERE m.state IN('pending','running','uncertain') AND(m.transport_scope=s.transport_scope OR m.transport_scope IS NULL AND m.cluster_id=s.cluster_id) AND m6_rejected_impact_collision(m.impact,s.impact)) THEN
  RAISE EXCEPTION 'Unresolved physical operation blocks a new claim' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER workflow_business_claim BEFORE INSERT ON workflow_schedule_claims FOR EACH ROW EXECUTE FUNCTION m11_business_claim();
CREATE FUNCTION m11_business_lease() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE c workflow_schedule_claims%ROWTYPE;l workflow_schedule_leases%ROWTYPE;p workflow_schedule_progress%ROWTYPE;
 BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('workflow-schedule-claim:'||NEW.claim_id::text,0));SELECT * INTO c FROM workflow_schedule_claims WHERE id=NEW.claim_id;
 SELECT * INTO l FROM workflow_schedule_leases WHERE claim_id=NEW.claim_id ORDER BY lease_version DESC LIMIT 1;SELECT * INTO p FROM workflow_schedule_progress WHERE schedule_id=c.schedule_id;
 IF c.id IS NULL OR NEW.lease_until>c.authority_expires_at OR NEW.lease_until<=clock_timestamp()
  OR l.id IS NULL AND(NEW.lease_version<>1 OR NEW.previous_id IS NOT NULL OR NEW.lease_until IS DISTINCT FROM c.initial_lease_until)
  OR l.id IS NOT NULL AND(p.state NOT IN('claimed','running') OR p.claim_id IS DISTINCT FROM c.id OR NEW.lease_version<>l.lease_version+1 OR NEW.previous_id IS DISTINCT FROM l.id OR l.lease_until<=clock_timestamp() OR NEW.lease_until<=l.lease_until)
 THEN RAISE EXCEPTION 'A lease extends only the same still-live claim, never a replacement generation' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER workflow_business_lease BEFORE INSERT ON workflow_schedule_leases FOR EACH ROW EXECUTE FUNCTION m11_business_lease();
CREATE FUNCTION m11_business_progress() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Business schedule progress cannot be deleted' USING ERRCODE='23514';END IF;
 IF ROW(NEW.schedule_id,NEW.cluster_id,NEW.workspace_id,NEW.created_at) IS DISTINCT FROM ROW(OLD.schedule_id,OLD.cluster_id,OLD.workspace_id,OLD.created_at)
  OR NEW.revision<>OLD.revision+1 OR OLD.claim_id IS NOT NULL AND NEW.claim_id IS DISTINCT FROM OLD.claim_id
  OR OLD.state IN('succeeded','partial','failed','uncertain','blocked','cancelled','expired')
  OR NOT(OLD.state='pending-approval' AND NEW.state IN('active','blocked','cancelled','expired') OR OLD.state='active' AND NEW.state IN('claimed','blocked','cancelled','expired')
    OR OLD.state IN('claimed','running') AND NEW.state IN('running','succeeded','partial','failed','uncertain'))
 THEN RAISE EXCEPTION 'Once claim and terminal state cannot be reset or replaced' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER workflow_business_progress BEFORE UPDATE OR DELETE ON workflow_schedule_progress FOR EACH ROW EXECUTE FUNCTION m11_business_progress();
CREATE TRIGGER workflow_business_progress_no_truncate BEFORE TRUNCATE ON workflow_schedule_progress FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();

CREATE FUNCTION m11_business_origin() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE s workflow_schedules%ROWTYPE;c workflow_schedule_claims%ROWTYPE;p workflow_schedule_progress%ROWTYPE;e workflow_executions%ROWTYPE;l workflow_schedule_leases%ROWTYPE;
 BEGIN
 SELECT * INTO s FROM workflow_schedules WHERE id=NEW.schedule_id;SELECT * INTO c FROM workflow_schedule_claims WHERE id=NEW.claim_id;
 SELECT * INTO p FROM workflow_schedule_progress WHERE schedule_id=NEW.schedule_id;SELECT * INTO e FROM workflow_executions WHERE id=NEW.execution_id;
 SELECT * INTO l FROM workflow_schedule_leases WHERE claim_id=NEW.claim_id ORDER BY lease_version DESC LIMIT 1;
 IF s.id IS NULL OR c.id IS NULL OR p.claim_id IS DISTINCT FROM c.id OR p.state NOT IN('claimed','running') OR e.id IS NULL OR e.state NOT IN('claimed','executing')
  OR NEW.executor_id IS DISTINCT FROM s.executor_id OR e.execution_actor_id IS DISTINCT FROM s.executor_id OR e.started_at<c.issued_at
  OR e.expires_at>c.authority_expires_at OR l.id IS NULL OR l.lease_until<=clock_timestamp()
 THEN RAISE EXCEPTION 'Origin requires the actual wrapper execution of the original live claim' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER workflow_business_origin BEFORE INSERT ON workflow_execution_origins FOR EACH ROW EXECUTE FUNCTION m11_business_origin();
CREATE FUNCTION m11_business_configuration_origin() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE o workflow_execution_origins%ROWTYPE;s workflow_schedules%ROWTYPE;e configuration_executions%ROWTYPE;j configuration_jobs%ROWTYPE;step workflow_steps%ROWTYPE;
 BEGIN
 SELECT * INTO o FROM workflow_execution_origins WHERE id=NEW.wrapper_origin_id;SELECT * INTO s FROM workflow_schedules WHERE id=o.schedule_id;
 SELECT * INTO e FROM configuration_executions WHERE id=NEW.configuration_execution_id;SELECT * INTO j FROM configuration_jobs WHERE id=NEW.configuration_job_id;
 SELECT * INTO step FROM workflow_steps WHERE id=NEW.workflow_step_id;
 IF o.id IS NULL OR s.kind IS DISTINCT FROM 'configuration_v2' OR e.id IS NULL OR j.id IS NULL OR step.id IS NULL OR e.state NOT IN('claimed','executing')
  OR e.actor_id IS DISTINCT FROM s.executor_id OR e.plan_id IS DISTINCT FROM NEW.configuration_plan_id
  OR ROW(e.workflow_id,e.approved_version,e.workflow_plan_hash) IS DISTINCT FROM ROW(o.workflow_id,o.workflow_plan_revision,o.workflow_plan_hash)
  OR j.workflow_id IS DISTINCT FROM o.workflow_id OR j.id IS DISTINCT FROM (SELECT subject_id FROM workflows WHERE id=o.workflow_id)
  OR ROW(step.cluster_id,step.workspace_id,step.workflow_id,step.plan_revision,step.plan_hash,step.kind,step.handler,step.entity_id)
   IS DISTINCT FROM ROW(o.cluster_id,o.workspace_id,o.workflow_id,o.workflow_plan_revision,o.workflow_plan_hash,'metadata'::text,'configuration_v2'::text,j.id)
 THEN RAISE EXCEPTION 'Nested origin must link the genuine configuration metadata step and exact job/plan' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER workflow_business_configuration_origin BEFORE INSERT ON workflow_configuration_execution_origins FOR EACH ROW EXECUTE FUNCTION m11_business_configuration_origin();

CREATE FUNCTION m11_business_event() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE p workflow_schedule_progress%ROWTYPE;
 BEGIN
 SELECT * INTO p FROM workflow_schedule_progress WHERE schedule_id=NEW.schedule_id;
 IF p.schedule_id IS NULL OR p.claim_id IS DISTINCT FROM NEW.claim_id OR p.reason_code IS DISTINCT FROM NEW.reason_code
  OR NEW.event_kind='draft' AND p.state<>'pending-approval' OR NEW.event_kind='activated' AND p.state<>'active'
  OR NEW.event_kind='lease-extended' AND p.state NOT IN('claimed','running')
  OR NEW.event_kind NOT IN('draft','activated','lease-extended') AND NEW.event_kind IS DISTINCT FROM p.state
 THEN RAISE EXCEPTION 'Schedule event must describe the actual current committed transition and original claim' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER workflow_business_event BEFORE INSERT ON workflow_schedule_events FOR EACH ROW EXECUTE FUNCTION m11_business_event();

CREATE FUNCTION m11_business_storage_complete() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE sid uuid;s workflow_schedules%ROWTYPE;p workflow_schedule_progress%ROWTYPE;c workflow_schedule_claims%ROWTYPE;a workflow_schedule_activations%ROWTYPE;o workflow_schedule_outcomes%ROWTYPE;
  origin workflow_execution_origins%ROWTYPE;e workflow_executions%ROWTYPE;w workflows%ROWTYPE;co workflow_configuration_execution_origins%ROWTYPE;ce configuration_executions%ROWTYPE;has_unresolved boolean;has_success boolean;
 BEGIN
 IF TG_TABLE_NAME='workflow_schedules' THEN sid=NEW.id;ELSIF TG_TABLE_NAME='workflow_schedule_leases' THEN SELECT schedule_id INTO sid FROM workflow_schedule_claims WHERE id=NEW.claim_id;ELSE sid=NEW.schedule_id;END IF;
 SELECT * INTO s FROM workflow_schedules WHERE id=sid;SELECT * INTO p FROM workflow_schedule_progress WHERE schedule_id=sid;
 SELECT * INTO c FROM workflow_schedule_claims WHERE schedule_id=sid;SELECT * INTO a FROM workflow_schedule_activations WHERE schedule_id=sid;SELECT * INTO o FROM workflow_schedule_outcomes WHERE schedule_id=sid;
 IF s.id IS NULL OR p.schedule_id IS NULL OR p.cluster_id IS DISTINCT FROM s.cluster_id OR p.workspace_id IS DISTINCT FROM s.workspace_id
  OR (p.claim_id IS NULL) IS DISTINCT FROM (c.id IS NULL) OR p.claim_id IS DISTINCT FROM c.id
  OR a.schedule_id IS NOT NULL AND p.state='pending-approval' OR p.state IN('active','claimed','running','succeeded','partial','failed','uncertain') AND a.schedule_id IS NULL
  OR c.id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM workflow_schedule_leases l WHERE l.claim_id=c.id AND l.lease_version=1 AND l.lease_until=c.initial_lease_until)
  OR p.state IN('succeeded','partial','failed','uncertain') AND(o.id IS NULL OR o.claim_id IS DISTINCT FROM c.id OR o.outcome IS DISTINCT FROM p.state)
  OR o.id IS NOT NULL AND(o.claim_id IS DISTINCT FROM c.id OR o.outcome IS DISTINCT FROM p.state)
 THEN RAISE EXCEPTION 'Business schedule, approval, once claim, lease and truthful terminal fact must commit together' USING ERRCODE='23514';END IF;
 IF o.id IS NOT NULL THEN
  SELECT * INTO origin FROM workflow_execution_origins WHERE claim_id=c.id;
  SELECT * INTO w FROM workflows WHERE id=s.workflow_id;
  IF o.provenance='callback-not-entered' THEN
   -- Only the private original Root claim can attest callback absence; this
   -- SQL fence additionally requires every real execution footprint absent.
   IF o.outcome<>'failed' OR origin.id IS NOT NULL
    OR EXISTS(SELECT 1 FROM workflow_executions actual WHERE actual.workflow_id=s.workflow_id AND actual.plan_revision=s.workflow_plan_revision)
    OR EXISTS(SELECT 1 FROM configuration_executions actual WHERE actual.workflow_id=s.workflow_id OR s.kind='configuration_v2' AND actual.job_id=w.subject_id)
    OR EXISTS(SELECT 1 FROM mutation_operations actual WHERE actual.workflow_id=s.workflow_id OR s.kind='configuration_v2' AND actual.configuration_job_id=w.subject_id)
   THEN RAISE EXCEPTION 'No-callback outcome cannot hide any actual execution or physical effect' USING ERRCODE='23514';END IF;
  ELSE
   SELECT * INTO e FROM workflow_executions WHERE id=origin.execution_id;
   SELECT * INTO co FROM workflow_configuration_execution_origins WHERE wrapper_origin_id=origin.id;
   SELECT * INTO ce FROM configuration_executions WHERE id=co.configuration_execution_id;
   SELECT EXISTS(SELECT 1 FROM mutation_operations m WHERE(m.workflow_execution_id=e.id OR co.id IS NOT NULL AND m.configuration_execution_id=co.configuration_execution_id) AND m.state IN('pending','running','uncertain')),
     EXISTS(SELECT 1 FROM mutation_operations m WHERE(m.workflow_execution_id=e.id OR co.id IS NOT NULL AND m.configuration_execution_id=co.configuration_execution_id) AND m.state='succeeded') INTO has_unresolved,has_success;
   IF origin.id IS NULL OR e.id IS NULL OR w.id IS NULL OR e.completed_at IS NULL OR e.execution_actor_id IS DISTINCT FROM s.executor_id OR origin.executor_id IS DISTINCT FROM s.executor_id
    OR e.state NOT IN('succeeded','partial','failed','uncertain') OR w.state IS DISTINCT FROM e.state
    OR o.outcome='succeeded' AND(e.state<>'succeeded' OR has_unresolved OR s.kind='configuration_v2' AND(ce.id IS NULL OR ce.state<>'succeeded'))
    OR o.outcome='failed' AND(e.state<>'failed' OR has_unresolved OR has_success OR ce.id IS NOT NULL AND ce.state<>'failed')
    OR o.outcome='partial' AND(e.state NOT IN('failed','partial') OR has_unresolved OR ce.id IS NOT NULL AND ce.state='uncertain' OR NOT has_success AND(ce.id IS NULL OR ce.state NOT IN('succeeded','partial')))
    OR o.outcome<>'uncertain' AND(e.state='uncertain' OR ce.id IS NOT NULL AND ce.state='uncertain')
    OR ce.id IS NOT NULL AND ce.completed_at IS NULL
    OR s.kind='configuration_v2' AND EXISTS(SELECT 1 FROM configuration_executions actual WHERE actual.workflow_id=s.workflow_id AND actual.id IS DISTINCT FROM ce.id)
    OR s.kind='portal-credential-issue' AND co.id IS NOT NULL
   THEN RAISE EXCEPTION 'Terminal outcome requires genuine scoped wrapper/nested execution facts with conservative observed effects' USING ERRCODE='23514';END IF;
  END IF;
 END IF;RETURN NULL;
 END;
$$;
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['workflow_schedules','workflow_schedule_activations','workflow_schedule_claims','workflow_schedule_leases','workflow_schedule_progress','workflow_schedule_outcomes'] LOOP
  EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT%s ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_business_storage_complete()',tab||'_complete',CASE WHEN tab='workflow_schedule_progress' THEN ' OR UPDATE' ELSE '' END,tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['workflow_executor_delegations','workflow_schedules','workflow_schedule_activations','workflow_schedule_claims','workflow_schedule_leases','workflow_schedule_outcomes','workflow_schedule_events','workflow_execution_origins','workflow_configuration_execution_origins'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
END;$$;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON workflow_executor_delegations,workflow_schedules,workflow_schedule_activations,workflow_schedule_claims,workflow_schedule_leases,workflow_schedule_outcomes,workflow_schedule_events,workflow_execution_origins,workflow_configuration_execution_origins FROM PUBLIC;
REVOKE DELETE,TRUNCATE,REFERENCES,TRIGGER ON workflow_schedule_progress FROM PUBLIC;
