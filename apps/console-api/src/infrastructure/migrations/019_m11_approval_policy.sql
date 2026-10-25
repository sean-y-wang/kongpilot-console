-- Approval policy V2 is independent of the immutable WorkflowPlanV1 envelope.
-- Existing V1 rows retain single / level=1 / one vote without backfilled facts.
ALTER TABLE workflow_definition_versions ADD COLUMN approval_format smallint NOT NULL DEFAULT 1 CHECK(approval_format IN(1,2));
ALTER TABLE workflow_definition_versions DROP CONSTRAINT workflow_definition_versions_mode_check;
ALTER TABLE workflow_definition_versions ADD CONSTRAINT workflow_definition_versions_mode_check
 CHECK((approval_format=1 AND mode='single') OR(approval_format=2 AND mode IN('single','multi','quorum')));
ALTER TABLE workflow_definition_versions ADD CONSTRAINT workflow_definition_versions_policy_identity
 UNIQUE(cluster_id,workspace_id,definition_id,version,policy_hash,approval_format);

ALTER TABLE workflow_definition_stages ADD COLUMN approval_format smallint NOT NULL DEFAULT 1 CHECK(approval_format IN(1,2));
ALTER TABLE workflow_definition_stages ADD COLUMN stage_mode text NOT NULL DEFAULT 'any' CHECK(stage_mode IN('any','quorum','all'));
ALTER TABLE workflow_definition_stages DROP CONSTRAINT workflow_definition_stages_level_check;
ALTER TABLE workflow_definition_stages DROP CONSTRAINT workflow_definition_stages_required_approvals_check;
ALTER TABLE workflow_definition_stages ALTER COLUMN required_approvals DROP NOT NULL;
ALTER TABLE workflow_definition_stages ADD CONSTRAINT workflow_definition_stages_format_check CHECK(
 (approval_format=1 AND level=1 AND stage_mode='any' AND required_approvals IS NOT NULL AND required_approvals=1)
 OR(approval_format=2 AND level BETWEEN 1 AND 8 AND(
  (stage_mode='any' AND required_approvals IS NOT NULL AND required_approvals=1) OR(stage_mode='quorum' AND required_approvals IS NOT NULL AND required_approvals BETWEEN 1 AND 100)
  OR(stage_mode='all' AND required_approvals IS NULL))));

ALTER TABLE workflows ADD COLUMN approval_format smallint NOT NULL DEFAULT 1 CHECK(approval_format IN(1,2));
ALTER TABLE workflows ADD COLUMN candidate_version integer;
ALTER TABLE workflows ADD COLUMN candidate_manifest_hmac text;
ALTER TABLE workflows ADD COLUMN approval_set_id uuid;
ALTER TABLE workflows ADD COLUMN approval_set_hmac text;
ALTER TABLE workflows ADD CONSTRAINT workflows_candidate_tuple CHECK(
 (candidate_version IS NULL AND candidate_manifest_hmac IS NULL)
 OR(approval_format=2 AND approval_required AND candidate_version IS NOT NULL AND candidate_version>0 AND candidate_manifest_hmac IS NOT NULL AND m8_hex64(candidate_manifest_hmac)));
ALTER TABLE workflows ADD CONSTRAINT workflows_approval_set_tuple CHECK(
 (approval_set_id IS NULL AND approval_set_hmac IS NULL)
 OR(approval_format=2 AND approval_required AND approval_set_id IS NOT NULL AND approval_set_hmac IS NOT NULL AND m8_hex64(approval_set_hmac)));
ALTER TABLE workflow_versions ADD COLUMN approval_format smallint NOT NULL DEFAULT 1 CHECK(approval_format IN(1,2));
ALTER TABLE workflow_stages ADD COLUMN approval_format smallint NOT NULL DEFAULT 1 CHECK(approval_format IN(1,2));
ALTER TABLE workflow_stages ADD COLUMN stage_mode text NOT NULL DEFAULT 'any' CHECK(stage_mode IN('any','quorum','all'));
ALTER TABLE workflow_stages ADD COLUMN candidate_version integer;
ALTER TABLE workflow_stages ADD COLUMN candidate_manifest_hmac text;
ALTER TABLE workflow_stages ADD COLUMN revision integer NOT NULL DEFAULT 1 CHECK(revision>0);
ALTER TABLE workflow_stages DROP CONSTRAINT workflow_stages_level_check;
ALTER TABLE workflow_stages DROP CONSTRAINT workflow_stages_required_approvals_check;
ALTER TABLE workflow_stages ADD CONSTRAINT workflow_stages_format_check CHECK(
 (approval_format=1 AND level=1 AND required_approvals=1 AND stage_mode='any' AND candidate_version IS NULL AND candidate_manifest_hmac IS NULL)
 OR(approval_format=2 AND level BETWEEN 1 AND 8 AND required_approvals BETWEEN 1 AND 100
  AND candidate_version IS NOT NULL AND candidate_version>0 AND candidate_manifest_hmac IS NOT NULL AND m8_hex64(candidate_manifest_hmac) AND(stage_mode<>'any' OR required_approvals=1)));
ALTER TABLE workflow_stages ADD CONSTRAINT workflow_stages_candidates_identity
 UNIQUE(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,candidate_version,candidate_manifest_hmac);
ALTER TABLE workflow_approvals ADD COLUMN candidate_version integer;
ALTER TABLE workflow_approvals ADD COLUMN candidate_manifest_hmac text;
ALTER TABLE workflow_approvals ADD COLUMN stage_revision integer;
ALTER TABLE workflow_approvals DROP CONSTRAINT workflow_approvals_level_check;
ALTER TABLE workflow_approvals ADD CONSTRAINT workflow_approvals_level_check CHECK(level BETWEEN 1 AND 8);
ALTER TABLE workflow_approvals ADD CONSTRAINT workflow_approvals_candidates_tuple CHECK(
 (candidate_version IS NULL AND candidate_manifest_hmac IS NULL AND stage_revision IS NULL AND level=1)
 OR(candidate_version IS NOT NULL AND candidate_version>0 AND candidate_manifest_hmac IS NOT NULL AND m8_hex64(candidate_manifest_hmac) AND stage_revision IS NOT NULL AND stage_revision>0));
ALTER TABLE workflow_approvals ADD CONSTRAINT workflow_approvals_full_identity
 UNIQUE(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash,level,approver_id,candidate_version,candidate_manifest_hmac);
ALTER TABLE workflow_executions ADD COLUMN approval_format smallint NOT NULL DEFAULT 1 CHECK(approval_format IN(1,2));
ALTER TABLE workflow_executions ADD COLUMN approval_set_id uuid;
ALTER TABLE workflow_executions ADD COLUMN approval_set_hmac text;
ALTER TABLE workflow_executions ADD CONSTRAINT workflow_executions_approval_set_tuple CHECK(
 (approval_format=1 AND approval_set_id IS NULL AND approval_set_hmac IS NULL)
 OR(approval_format=2 AND((NOT approval_required AND approval_set_id IS NULL AND approval_set_hmac IS NULL)
  OR(approval_required AND approval_set_id IS NOT NULL AND approval_set_hmac IS NOT NULL AND m8_hex64(approval_set_hmac)))));

CREATE TABLE workflow_candidate_versions (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,workflow_id uuid NOT NULL,
 plan_revision integer NOT NULL CHECK(plan_revision>0),plan_hash text NOT NULL CHECK(m8_hex64(plan_hash)),
 candidate_version integer NOT NULL CHECK(candidate_version>0),definition_id uuid NOT NULL,definition_version integer NOT NULL,
 policy_hash text NOT NULL CHECK(m8_hex64(policy_hash)),approval_format smallint NOT NULL DEFAULT 2 CHECK(approval_format=2),
 manifest_hmac text NOT NULL CHECK(m8_hex64(manifest_hmac)),
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=1048576),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,workflow_id,plan_revision,candidate_version),
 UNIQUE(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,manifest_hmac),
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash)
  REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,definition_id,definition_version,policy_hash,approval_format)
  REFERENCES workflow_definition_versions(cluster_id,workspace_id,definition_id,version,policy_hash,approval_format) ON DELETE RESTRICT
);
CREATE TABLE workflow_candidates (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,workflow_id uuid NOT NULL,
 plan_revision integer NOT NULL,plan_hash text NOT NULL,candidate_version integer NOT NULL,manifest_hmac text NOT NULL,
 level integer NOT NULL CHECK(level BETWEEN 1 AND 8),user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 credential_epoch bigint NOT NULL CHECK(credential_epoch>0),
 provenance jsonb NOT NULL CHECK(jsonb_typeof(provenance)='array' AND jsonb_array_length(provenance) BETWEEN 1 AND 300 AND octet_length(provenance::text)<=65536),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,workflow_id,plan_revision,candidate_version,level,user_id),
 UNIQUE(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,manifest_hmac,level,user_id),
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,manifest_hmac)
  REFERENCES workflow_candidate_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,manifest_hmac) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,candidate_version,manifest_hmac)
  REFERENCES workflow_stages(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,candidate_version,candidate_manifest_hmac) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE workflows ADD CONSTRAINT workflows_candidate_manifest_fk
 FOREIGN KEY(cluster_id,workspace_id,id,plan_revision,plan_hash,candidate_version,candidate_manifest_hmac)
 REFERENCES workflow_candidate_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,manifest_hmac) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE workflow_approvals ADD CONSTRAINT workflow_approvals_candidate_fk
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,candidate_manifest_hmac,level,approver_id)
 REFERENCES workflow_candidates(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,manifest_hmac,level,user_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE workflow_approval_sets (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,workflow_id uuid NOT NULL,
 plan_revision integer NOT NULL,plan_hash text NOT NULL CHECK(m8_hex64(plan_hash)),policy_hash text NOT NULL CHECK(m8_hex64(policy_hash)),
 candidate_version integer NOT NULL,candidate_manifest_hmac text NOT NULL,set_hmac text NOT NULL CHECK(m8_hex64(set_hmac)),
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=262144),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(workflow_id,plan_revision),
 UNIQUE(cluster_id,workspace_id,id,set_hmac,workflow_id,plan_revision,plan_hash),
 UNIQUE(cluster_id,workspace_id,id,set_hmac,workflow_id,plan_revision,plan_hash,candidate_version,candidate_manifest_hmac),
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,candidate_manifest_hmac)
  REFERENCES workflow_candidate_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,candidate_version,manifest_hmac) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE workflow_approval_set_members (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,set_id uuid NOT NULL,set_hmac text NOT NULL,workflow_id uuid NOT NULL,
 plan_revision integer NOT NULL,plan_hash text NOT NULL,approval_id uuid NOT NULL,level integer NOT NULL,user_id uuid NOT NULL,
 candidate_version integer NOT NULL,candidate_manifest_hmac text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(set_id,approval_id),UNIQUE(approval_id),UNIQUE(set_id,level,user_id),
 FOREIGN KEY(cluster_id,workspace_id,set_id,set_hmac,workflow_id,plan_revision,plan_hash,candidate_version,candidate_manifest_hmac)
  REFERENCES workflow_approval_sets(cluster_id,workspace_id,id,set_hmac,workflow_id,plan_revision,plan_hash,candidate_version,candidate_manifest_hmac) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,approval_id,workflow_id,plan_revision,plan_hash,level,user_id,candidate_version,candidate_manifest_hmac)
  REFERENCES workflow_approvals(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash,level,approver_id,candidate_version,candidate_manifest_hmac) ON DELETE RESTRICT
);
CREATE TABLE workflow_approval_invalidations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),set_id uuid NOT NULL,approval_id uuid NOT NULL,
 reason text NOT NULL CHECK(reason IN('account_disabled','credential_epoch_changed','selector_revoked','scope_revoked','policy_invalid')),
 request_id text CHECK(request_id IS NULL OR length(request_id)<=128),created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(set_id,approval_id,reason),FOREIGN KEY(set_id,approval_id) REFERENCES workflow_approval_set_members(set_id,approval_id) ON DELETE RESTRICT
);
ALTER TABLE workflows ADD CONSTRAINT workflows_approval_set_fk
 FOREIGN KEY(cluster_id,workspace_id,approval_set_id,approval_set_hmac,id,plan_revision,plan_hash)
 REFERENCES workflow_approval_sets(cluster_id,workspace_id,id,set_hmac,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE workflow_executions ADD CONSTRAINT workflow_executions_approval_set_fk
 FOREIGN KEY(cluster_id,workspace_id,approval_set_id,approval_set_hmac,workflow_id,plan_revision,plan_hash)
 REFERENCES workflow_approval_sets(cluster_id,workspace_id,id,set_hmac,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT;

DROP TRIGGER workflow_stages_identity ON workflow_stages;
CREATE TRIGGER workflow_stages_identity BEFORE UPDATE OR DELETE ON workflow_stages FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,required_approvals,approval_format,stage_mode,candidate_version,candidate_manifest_hmac,created_at');
CREATE FUNCTION m11_guard_approval_bindings() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF NEW.approval_format<>OLD.approval_format THEN RAISE EXCEPTION 'Approval format is immutable' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='workflows' THEN
  IF OLD.candidate_version IS NOT NULL AND ROW(NEW.candidate_version,NEW.candidate_manifest_hmac) IS DISTINCT FROM ROW(OLD.candidate_version,OLD.candidate_manifest_hmac)
  THEN RAISE EXCEPTION 'Candidate manifest is assigned once' USING ERRCODE='23514';END IF;
 END IF;
 IF OLD.approval_set_id IS NOT NULL AND ROW(NEW.approval_set_id,NEW.approval_set_hmac) IS DISTINCT FROM ROW(OLD.approval_set_id,OLD.approval_set_hmac)
 THEN RAISE EXCEPTION 'Approval set is assigned once' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;$$;
CREATE TRIGGER workflows_approval_bindings BEFORE UPDATE ON workflows FOR EACH ROW EXECUTE FUNCTION m11_guard_approval_bindings();
CREATE TRIGGER workflow_executions_approval_bindings BEFORE UPDATE ON workflow_executions FOR EACH ROW EXECUTE FUNCTION m11_guard_approval_bindings();
CREATE FUNCTION m11_guard_stage_progress() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF OLD.approval_format=2 THEN
  IF NEW.revision<>OLD.revision+1 OR(OLD.state IN('approved','rejected','skipped') AND NEW.state<>OLD.state)
  THEN RAISE EXCEPTION 'V2 approval stage progress requires a monotonic version and cannot reopen' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END;$$;
CREATE TRIGGER workflow_stages_progress BEFORE UPDATE ON workflow_stages FOR EACH ROW EXECUTE FUNCTION m11_guard_stage_progress();

CREATE FUNCTION m11_assert_vote_stage() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE w workflows%ROWTYPE;s workflow_stages%ROWTYPE;p jsonb;
 BEGIN
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id FOR UPDATE;
 IF w.approval_format=1 THEN
  IF NEW.level<>1 OR NEW.candidate_version IS NOT NULL OR NEW.candidate_manifest_hmac IS NOT NULL OR NEW.stage_revision IS NOT NULL THEN
   RAISE EXCEPTION 'V1 votes cannot acquire V2 candidate facts' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 SELECT * INTO s FROM workflow_stages WHERE workflow_id=w.id AND plan_revision=NEW.plan_revision AND level=NEW.level FOR UPDATE;
 SELECT policy INTO p FROM workflow_definition_versions WHERE cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND definition_id=w.definition_id AND version=w.definition_version;
 IF w.state<>'pending' OR s.state<>'active' OR s.revision<>NEW.stage_revision OR NEW.plan_hash<>w.plan_hash
  OR NEW.candidate_version<>w.candidate_version OR NEW.candidate_manifest_hmac<>w.candidate_manifest_hmac
  OR NEW.approver_id IS NOT DISTINCT FROM w.requester_user_id OR NOT w.approval_required
  OR EXISTS(SELECT 1 FROM workflow_stages previous WHERE previous.workflow_id=w.id AND previous.plan_revision=NEW.plan_revision AND previous.level<NEW.level AND previous.state<>'approved')
  OR(NOT EXISTS(SELECT 1 FROM users u WHERE u.id=NEW.approver_id AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change))
  OR((p->>'distinctAcrossStages')::boolean AND EXISTS(SELECT 1 FROM workflow_approvals a WHERE a.workflow_id=w.id AND a.plan_revision=NEW.plan_revision AND a.approver_id=NEW.approver_id))
 THEN RAISE EXCEPTION 'V2 vote must target the exact current stage and distinct candidate' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;$$;
CREATE TRIGGER workflow_approvals_current_stage BEFORE INSERT ON workflow_approvals FOR EACH ROW EXECUTE FUNCTION m11_assert_vote_stage();

DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['workflow_candidate_versions','workflow_candidates','workflow_approval_sets','workflow_approval_set_members','workflow_approval_invalidations'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
END;$$;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON workflow_candidate_versions,workflow_candidates,workflow_approval_sets,workflow_approval_set_members,workflow_approval_invalidations FROM PUBLIC;

-- This fixed administration kind is assessed under its sealed old definition;
-- it never carries a native packet or changes any existing kind's subject guard.
ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_kind_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata','workflow-policy-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_kind_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata','workflow-policy-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries','configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs','toolbox_operations','workspace_migration_plans','governance_metadata_requests','workflow_policy_requests'));
CREATE TABLE workflow_policy_requests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,definition_id uuid NOT NULL,
 operation text NOT NULL CHECK(operation IN('version','archive','restore')),workflow_id uuid NOT NULL,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),payload_secret text NOT NULL CHECK(m6_encrypted(payload_secret)),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(actor_id,idempotency_key),UNIQUE(workflow_id),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id,definition_id) REFERENCES workflow_definitions(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER workflow_policy_requests_immutable BEFORE UPDATE OR DELETE ON workflow_policy_requests FOR EACH ROW EXECUTE FUNCTION m8_immutable();
CREATE TRIGGER workflow_policy_requests_no_truncate BEFORE TRUNCATE ON workflow_policy_requests FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON workflow_policy_requests FROM PUBLIC;
DO $m11$ DECLARE definition text;BEGIN
 definition=pg_get_functiondef('m6_validate_workflow_subject()'::regprocedure);
 definition=regexp_replace(definition,'\mBEGIN\M',E'BEGIN\n IF NEW.kind=''workflow-policy-metadata'' THEN RETURN NULL;END IF;');
 EXECUTE definition;
END;$m11$;
CREATE FUNCTION m11_validate_policy_subject() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE w workflows%ROWTYPE;r workflow_policy_requests%ROWTYPE;s workflow_steps%ROWTYPE;
 BEGIN
 IF TG_TABLE_NAME='workflow_policy_requests' THEN SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 ELSIF TG_TABLE_NAME='workflow_steps' THEN SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 ELSE SELECT * INTO w FROM workflows WHERE id=NEW.id;END IF;
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF w.kind<>'workflow-policy-metadata' THEN
  IF w.subject_type='workflow_policy_requests' OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=w.id AND handler='workflow.policy') THEN
   RAISE EXCEPTION 'Policy requests require the exact zero-native administration kind' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
 SELECT * INTO r FROM workflow_policy_requests WHERE id=w.subject_id AND cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id;
 SELECT * INTO s FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision;
 IF r.id IS NULL OR w.subject_type<>'workflow_policy_requests' OR w.requester_type<>'console' OR w.requester_user_id<>r.actor_id OR w.execution_mode<>'approval' OR NOT w.approval_required OR w.idempotency_key<>r.idempotency_key
  OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision)<>1
  OR s.cluster_id<>w.cluster_id OR s.workspace_id<>w.workspace_id OR s.plan_hash<>w.plan_hash OR s.kind<>'metadata' OR s.handler IS DISTINCT FROM 'workflow.policy'
  OR s.entity_type<>'workflow_policy_requests' OR s.entity_id<>r.id OR s.step_order<>1 OR s.step_key<>'workflow.policy' OR s.dependencies<>'{}'::uuid[] OR s.native_requests<>'[]'::jsonb OR s.operation_id IS NOT NULL
  OR s.permission_action<>(CASE WHEN r.operation='archive' THEN 'delete' ELSE 'write' END)
 THEN RAISE EXCEPTION 'Policy administration must retain its exact scoped immutable request and metadata step' USING ERRCODE='23514';END IF;RETURN NULL;
 END;
$$;
CREATE CONSTRAINT TRIGGER workflow_policy_requests_complete AFTER INSERT ON workflow_policy_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_policy_subject();
CREATE CONSTRAINT TRIGGER workflows_policy_complete AFTER INSERT OR UPDATE ON workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_policy_subject();
CREATE CONSTRAINT TRIGGER workflow_steps_policy_complete AFTER INSERT OR UPDATE ON workflow_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_policy_subject();

CREATE FUNCTION m11_assert_approval_facts(fid uuid,rev integer,ph text) RETURNS void LANGUAGE plpgsql AS $$
 DECLARE w workflows%ROWTYPE;v workflow_versions%ROWTYPE;c workflow_candidate_versions%ROWTYPE;
  p workflow_definition_versions%ROWTYPE;s workflow_stages%ROWTYPE;aset workflow_approval_sets%ROWTYPE;
  n integer;approved integer;rejected integer;item jsonb;candidate jsonb;member record;
 BEGIN
 SELECT * INTO w FROM workflows WHERE id=fid;
 SELECT * INTO v FROM workflow_versions WHERE workflow_id=fid AND plan_revision=rev AND plan_hash=ph;
 IF NOT FOUND OR v.approval_format<>2 THEN RETURN;END IF;
 SELECT * INTO p FROM workflow_definition_versions WHERE cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND definition_id=w.definition_id AND version=w.definition_version;
 IF w.approval_format<>2 OR p.approval_format<>2 OR w.plan_hash<>ph OR w.plan_revision<>rev THEN
  RAISE EXCEPTION 'V2 approval requires its exact workflow policy format' USING ERRCODE='23514';END IF;
 IF NOT v.approval_required THEN
  IF w.candidate_version IS NOT NULL OR w.approval_set_id IS NOT NULL OR EXISTS(SELECT 1 FROM workflow_approvals WHERE workflow_id=fid AND plan_revision=rev)
  THEN RAISE EXCEPTION 'Direct workflow cannot contain approval facts' USING ERRCODE='23514';END IF;RETURN;
 END IF;
 SELECT * INTO c FROM workflow_candidate_versions WHERE cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=fid AND plan_revision=rev AND plan_hash=ph AND candidate_version=w.candidate_version AND manifest_hmac=w.candidate_manifest_hmac;
 IF NOT FOUND OR c.definition_id<>w.definition_id OR c.definition_version<>w.definition_version OR c.policy_hash<>p.policy_hash
  OR c.manifest->>'version'<>'1' OR c.manifest->>'clusterId' IS DISTINCT FROM w.cluster_id::text OR c.manifest->>'workspaceId' IS DISTINCT FROM w.workspace_id::text
  OR c.manifest->>'workflowId' IS DISTINCT FROM fid::text OR c.manifest->>'planRevision' IS DISTINCT FROM rev::text OR c.manifest->>'planHash' IS DISTINCT FROM ph
  OR c.manifest->>'definitionId' IS DISTINCT FROM w.definition_id::text OR c.manifest->>'definitionVersion' IS DISTINCT FROM w.definition_version::text
  OR c.manifest->>'policyHash' IS DISTINCT FROM p.policy_hash OR c.manifest->>'candidateVersion' IS DISTINCT FROM w.candidate_version::text
  OR jsonb_typeof(c.manifest->'stages') IS DISTINCT FROM 'array' OR jsonb_array_length(c.manifest->'stages')<>jsonb_array_length(p.policy->'stages')
 THEN RAISE EXCEPTION 'Candidate version must bind its complete policy and plan manifest' USING ERRCODE='23514';END IF;
 FOR s IN SELECT * FROM workflow_stages WHERE workflow_id=fid AND plan_revision=rev ORDER BY level LOOP
  item=c.manifest->'stages'->(s.level-1);
  SELECT count(*)::integer INTO n FROM workflow_candidates WHERE workflow_id=fid AND plan_revision=rev AND candidate_version=c.candidate_version AND level=s.level;
  IF s.approval_format<>2 OR s.candidate_version<>c.candidate_version OR s.candidate_manifest_hmac<>c.manifest_hmac
   OR item->>'level' IS DISTINCT FROM s.level::text OR item->>'mode' IS DISTINCT FROM s.stage_mode OR item->>'threshold' IS DISTINCT FROM s.required_approvals::text
   OR jsonb_typeof(item->'candidates') IS DISTINCT FROM 'array' OR n NOT BETWEEN 1 AND 100 OR n<s.required_approvals
  OR jsonb_array_length(item->'candidates')<>n OR(SELECT count(DISTINCT proof->>'userId') FROM jsonb_array_elements(item->'candidates') proof)<>n OR(s.stage_mode='all' AND s.required_approvals<>n)
  THEN RAISE EXCEPTION 'Frozen candidate stage must retain its complete real candidate count' USING ERRCODE='23514';END IF;
  FOR candidate IN SELECT value FROM jsonb_array_elements(item->'candidates') LOOP
   IF NOT EXISTS(SELECT 1 FROM workflow_candidates cand WHERE cand.cluster_id=w.cluster_id AND cand.workspace_id=w.workspace_id AND cand.workflow_id=fid AND cand.plan_revision=rev AND cand.plan_hash=ph AND cand.candidate_version=c.candidate_version AND cand.manifest_hmac=c.manifest_hmac
     AND cand.level=s.level AND cand.user_id::text=candidate->>'userId' AND cand.credential_epoch::text=candidate->>'credentialEpoch' AND cand.provenance=candidate->'provenance' AND cand.user_id IS DISTINCT FROM w.requester_user_id)
   THEN RAISE EXCEPTION 'Frozen candidate manifest and normalized rows must agree' USING ERRCODE='23514';END IF;
  END LOOP;
  IF EXISTS(SELECT 1 FROM workflow_approvals a WHERE a.workflow_id=fid AND a.plan_revision=rev AND a.level=s.level
    AND(a.plan_hash<>ph OR a.candidate_version IS DISTINCT FROM c.candidate_version OR a.candidate_manifest_hmac IS DISTINCT FROM c.manifest_hmac
      OR a.approver_id IS NOT DISTINCT FROM w.requester_user_id OR a.decided_at<w.created_at OR a.stage_revision IS NULL OR a.stage_revision>=s.revision))
  THEN RAISE EXCEPTION 'V2 votes must retain the exact candidate and stage revision' USING ERRCODE='23514';END IF;
  SELECT count(*) FILTER(WHERE decision='approve')::integer,count(*) FILTER(WHERE decision='reject')::integer INTO approved,rejected FROM workflow_approvals WHERE workflow_id=fid AND plan_revision=rev AND level=s.level;
  IF approved>s.required_approvals OR rejected>1 OR(s.state='approved' AND(approved<>s.required_approvals OR rejected<>0))
   OR(s.state='pending' AND(approved<>0 OR rejected<>0)) OR(s.state='active' AND(approved>=s.required_approvals OR rejected<>0))
   OR(s.state='rejected' AND rejected<>1)
   OR(s.state IN('active','approved','rejected') AND EXISTS(SELECT 1 FROM workflow_stages previous WHERE previous.workflow_id=fid AND previous.plan_revision=rev AND previous.level<s.level AND previous.state<>'approved'))
  THEN RAISE EXCEPTION 'V2 approval stages must progress sequentially with exact distinct votes' USING ERRCODE='23514';END IF;
 END LOOP;
 IF(p.policy->>'distinctAcrossStages')::boolean AND EXISTS(SELECT 1 FROM workflow_approvals WHERE workflow_id=fid AND plan_revision=rev GROUP BY approver_id HAVING count(*)>1)
 THEN RAISE EXCEPTION 'V2 policy forbids cross-stage reviewer reuse' USING ERRCODE='23514';END IF;
 IF w.state='pending' AND(SELECT count(*) FROM workflow_stages WHERE workflow_id=fid AND plan_revision=rev AND state='active')<>1 THEN
  RAISE EXCEPTION 'Pending V2 workflow requires exactly one active sequential stage' USING ERRCODE='23514';END IF;
 IF w.approval_set_id IS NULL THEN
  IF w.approved_by IS NOT NULL OR w.state IN('approved','executing','succeeded','partial','failed','uncertain') THEN
   RAISE EXCEPTION 'Approved V2 workflow requires a complete immutable approval set' USING ERRCODE='23514';END IF;RETURN;
 END IF;
 SELECT * INTO aset FROM workflow_approval_sets WHERE id=w.approval_set_id AND set_hmac=w.approval_set_hmac AND cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=fid AND plan_revision=rev AND plan_hash=ph AND policy_hash=p.policy_hash AND candidate_version=c.candidate_version AND candidate_manifest_hmac=c.manifest_hmac;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM workflow_stages WHERE workflow_id=fid AND plan_revision=rev AND state<>'approved')
  OR EXISTS(SELECT 1 FROM workflow_approvals WHERE workflow_id=fid AND plan_revision=rev AND decision='reject')
  OR NOT EXISTS(SELECT 1 FROM workflow_approval_set_members m WHERE m.set_id=aset.id AND m.user_id=w.approved_by AND m.level=jsonb_array_length(p.policy->'stages'))
 THEN RAISE EXCEPTION 'V2 terminal reviewer is display metadata for an exact complete set' USING ERRCODE='23514';END IF;
 SELECT count(*)::integer INTO n FROM workflow_approval_set_members WHERE set_id=aset.id;
 IF n<>(SELECT count(*) FROM workflow_approvals WHERE workflow_id=fid AND plan_revision=rev) OR jsonb_typeof(aset.manifest->'reviewers') IS DISTINCT FROM 'array' OR jsonb_array_length(aset.manifest->'reviewers')<>n
  OR aset.manifest->>'version' IS DISTINCT FROM '1' OR aset.manifest->>'clusterId' IS DISTINCT FROM w.cluster_id::text OR aset.manifest->>'workspaceId' IS DISTINCT FROM w.workspace_id::text
  OR aset.manifest->>'workflowId' IS DISTINCT FROM fid::text OR aset.manifest->>'planRevision' IS DISTINCT FROM rev::text OR aset.manifest->>'planHash' IS DISTINCT FROM ph
  OR aset.manifest->>'policyHash' IS DISTINCT FROM p.policy_hash OR aset.manifest->>'candidateVersion' IS DISTINCT FROM c.candidate_version::text OR aset.manifest->>'candidateManifestHmac' IS DISTINCT FROM c.manifest_hmac
 THEN RAISE EXCEPTION 'Approval set requires all exact decisions and its complete manifest' USING ERRCODE='23514';END IF;
 FOR member IN SELECT * FROM workflow_approval_set_members WHERE set_id=aset.id LOOP
  IF NOT EXISTS(SELECT 1 FROM workflow_approvals a WHERE a.id=member.approval_id AND a.decision='approve')
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(aset.manifest->'reviewers') proof WHERE proof->>'approvalId'=member.approval_id::text AND proof->>'userId'=member.user_id::text AND proof->>'level'=member.level::text AND proof->>'candidateVersion'=member.candidate_version::text)
  THEN RAISE EXCEPTION 'Approval set cannot substitute or omit an actual decision' USING ERRCODE='23514';END IF;
 END LOOP;
 END;
$$;
CREATE FUNCTION m11_validate_approval_graph() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE fid uuid;rev integer;ph text;
 BEGIN
 IF TG_TABLE_NAME='workflow_approval_set_members' THEN fid=NEW.workflow_id;rev=NEW.plan_revision;ph=NEW.plan_hash;
 ELSE fid=NEW.workflow_id;rev=NEW.plan_revision;ph=NEW.plan_hash;END IF;
 PERFORM m11_assert_approval_facts(fid,rev,ph);RETURN NULL;
 END;
$$;
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['workflow_candidate_versions','workflow_candidates','workflow_approval_sets','workflow_approval_set_members'] LOOP
  EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_approval_graph()',tab||'_complete',tab);
 END LOOP;
END;$$;
CREATE CONSTRAINT TRIGGER workflow_stages_approval_graph AFTER INSERT OR UPDATE ON workflow_stages DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_approval_graph();
CREATE CONSTRAINT TRIGGER workflow_versions_approval_graph AFTER INSERT ON workflow_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_approval_graph();

-- Preserve all original step-manifest/DAG checks; only approval branches differ.
CREATE OR REPLACE FUNCTION m6_validate_version_graph() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cid uuid;wid uuid;fid uuid;rev integer;v workflow_versions%ROWTYPE;
  w workflows%ROWTYPE;s workflow_steps%ROWTYPE;dep uuid;dep_order integer;
  actual_count integer;request_count integer;stage_count integer;
BEGIN
  cid=NEW.cluster_id;wid=NEW.workspace_id;fid=NEW.workflow_id;rev=NEW.plan_revision;
  SELECT * INTO v FROM workflow_versions WHERE cluster_id=cid AND workspace_id=wid AND workflow_id=fid AND plan_revision=rev;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT * INTO w FROM workflows WHERE cluster_id=cid AND workspace_id=wid AND id=fid;
  IF w.approval_format<>v.approval_format OR NOT EXISTS(SELECT 1 FROM workflow_definition_versions d WHERE d.cluster_id=cid AND d.workspace_id=wid AND d.definition_id=w.definition_id AND d.version=w.definition_version AND d.approval_format=v.approval_format) THEN
    RAISE EXCEPTION 'Workflow format must equal its exact version and definition' USING ERRCODE='23514';END IF;
  SELECT count(*)::integer,coalesce(sum(jsonb_array_length(native_requests)),0)::integer INTO actual_count,request_count
    FROM workflow_steps WHERE cluster_id=cid AND workspace_id=wid AND workflow_id=fid AND plan_revision=rev;
  IF actual_count<>v.step_count OR request_count<>v.native_request_count THEN
    RAISE EXCEPTION 'Workflow normalized step manifest is incomplete' USING ERRCODE='23514';
  END IF;
  IF EXISTS(SELECT 1 FROM workflow_steps WHERE cluster_id=cid AND workspace_id=wid AND workflow_id=fid AND plan_revision=rev AND step_order>actual_count) THEN
    RAISE EXCEPTION 'Workflow step ordering must be contiguous' USING ERRCODE='23514';
  END IF;
  FOR s IN SELECT * FROM workflow_steps WHERE cluster_id=cid AND workspace_id=wid AND workflow_id=fid AND plan_revision=rev LOOP
    IF cardinality(s.dependencies)<>(SELECT count(DISTINCT d)::integer FROM unnest(s.dependencies) AS d) THEN
      RAISE EXCEPTION 'Workflow dependencies cannot repeat' USING ERRCODE='23514';
    END IF;
    FOREACH dep IN ARRAY s.dependencies LOOP
      SELECT step_order INTO dep_order FROM workflow_steps WHERE cluster_id=cid AND workspace_id=wid AND workflow_id=fid AND plan_revision=rev AND id=dep;
      IF NOT FOUND OR dep_order>=s.step_order THEN
        RAISE EXCEPTION 'Workflow dependencies must precede a same-version step' USING ERRCODE='23514';
      END IF;
    END LOOP;
  END LOOP;
  SELECT count(*)::integer INTO stage_count FROM workflow_stages WHERE cluster_id=cid AND workspace_id=wid AND workflow_id=fid AND plan_revision=rev;
  IF v.approval_format=1 THEN
    IF w.approval_format<>1 OR(v.approval_required AND stage_count<>1) OR(NOT v.approval_required AND stage_count<>0) THEN
      RAISE EXCEPTION 'Workflow stages do not match approval requirement' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM workflow_stages st WHERE st.cluster_id=cid AND st.workspace_id=wid AND st.workflow_id=fid AND st.plan_revision=rev
      AND NOT EXISTS(SELECT 1 FROM workflow_definition_stages ds WHERE ds.cluster_id=cid AND ds.workspace_id=wid AND ds.definition_id=w.definition_id AND ds.definition_version=w.definition_version AND ds.level=st.level AND ds.required_approvals=st.required_approvals AND ds.approval_format=1)) THEN
      RAISE EXCEPTION 'Workflow stage must match its immutable definition' USING ERRCODE='23514';
    END IF;
  ELSE
    IF w.approval_format<>2 OR(v.approval_required AND(stage_count<1 OR stage_count>8 OR w.candidate_version IS NULL)) OR(NOT v.approval_required AND stage_count<>0)
      OR NOT EXISTS(SELECT 1 FROM workflow_definition_versions d WHERE d.cluster_id=cid AND d.workspace_id=wid AND d.definition_id=w.definition_id AND d.version=w.definition_version AND d.approval_format=2)
      OR(v.approval_required AND stage_count<>(SELECT count(*) FROM workflow_definition_stages d WHERE d.cluster_id=cid AND d.workspace_id=wid AND d.definition_id=w.definition_id AND d.definition_version=w.definition_version)) THEN
      RAISE EXCEPTION 'V2 workflow requires its complete frozen approval stages' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM workflow_stages st WHERE st.cluster_id=cid AND st.workspace_id=wid AND st.workflow_id=fid AND st.plan_revision=rev
      AND(st.level>stage_count OR st.approval_format<>2 OR st.candidate_version IS DISTINCT FROM w.candidate_version OR st.candidate_manifest_hmac IS DISTINCT FROM w.candidate_manifest_hmac
        OR NOT EXISTS(SELECT 1 FROM workflow_definition_stages ds WHERE ds.cluster_id=cid AND ds.workspace_id=wid AND ds.definition_id=w.definition_id AND ds.definition_version=w.definition_version AND ds.level=st.level AND ds.approval_format=2 AND ds.stage_mode=st.stage_mode AND(ds.stage_mode='all' OR ds.required_approvals=st.required_approvals)))) THEN
      RAISE EXCEPTION 'V2 workflow stages must match their exact policy and candidate tuple' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;
CREATE OR REPLACE FUNCTION m6_validate_definition_stages() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ver integer;v workflow_definition_versions%ROWTYPE;n integer;
BEGIN
  IF TG_TABLE_NAME='workflow_definition_versions' THEN ver=NEW.version;ELSE ver=NEW.definition_version;END IF;
  SELECT * INTO v FROM workflow_definition_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND definition_id=NEW.definition_id AND version=ver;
  SELECT count(*)::integer INTO n FROM workflow_definition_stages WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND definition_id=NEW.definition_id AND definition_version=ver;
  IF v.approval_format=1 THEN
    IF n<>1 OR EXISTS(SELECT 1 FROM workflow_definition_stages d WHERE d.cluster_id=v.cluster_id AND d.workspace_id=v.workspace_id AND d.definition_id=v.definition_id AND d.definition_version=v.version AND(d.approval_format<>1 OR d.level<>1 OR d.required_approvals IS DISTINCT FROM 1)) THEN
      RAISE EXCEPTION 'M6 workflow definition requires one immutable approval stage' USING ERRCODE='23514';
    END IF;
  ELSE
    IF n NOT BETWEEN 1 AND 8 OR v.policy->>'version' IS DISTINCT FROM '2' OR v.policy->>'allowSelfApproval' IS DISTINCT FROM 'false'
      OR jsonb_typeof(v.policy->'distinctAcrossStages') IS DISTINCT FROM 'boolean'
      OR jsonb_typeof(v.policy->'stages') IS DISTINCT FROM 'array' OR jsonb_array_length(v.policy->'stages')<>n
      OR jsonb_typeof(v.policy->'intentTtlHours') IS DISTINCT FROM 'number' OR NOT((v.policy->>'intentTtlHours')::integer BETWEEN 1 AND 168)
      OR EXISTS(SELECT 1 FROM workflow_definition_stages d WHERE d.cluster_id=v.cluster_id AND d.workspace_id=v.workspace_id AND d.definition_id=v.definition_id AND d.definition_version=v.version AND(d.approval_format<>2 OR d.level>n))
      OR EXISTS(SELECT 1 FROM jsonb_array_elements(v.policy->'stages') WITH ORDINALITY item(stage,level)
        WHERE item.stage->>'level' IS DISTINCT FROM item.level::text OR NOT EXISTS(SELECT 1 FROM workflow_definition_stages d WHERE d.cluster_id=v.cluster_id AND d.workspace_id=v.workspace_id AND d.definition_id=v.definition_id AND d.definition_version=v.version
          AND d.level=item.level AND d.name=item.stage->>'name' AND d.stage_mode=item.stage->>'mode' AND d.selector=item.stage->'selector'
          AND((d.stage_mode='all' AND item.stage->'threshold'='null'::jsonb AND d.required_approvals IS NULL) OR(d.required_approvals=(item.stage->>'threshold')::integer)))) THEN
      RAISE EXCEPTION 'V2 definition requires its exact contiguous immutable policy graph' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;
CREATE OR REPLACE FUNCTION m6_validate_approval_fact() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE; v workflow_versions%ROWTYPE; aid uuid;rev integer;ph text;
BEGIN
  IF TG_TABLE_NAME='workflows' THEN
    SELECT * INTO w FROM workflows WHERE id=NEW.id;rev=w.plan_revision;ph=w.plan_hash;aid=w.approved_by;
  ELSE
    SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;rev=NEW.plan_revision;ph=NEW.plan_hash;
    IF TG_TABLE_NAME='workflow_approvals' THEN aid=NEW.approver_id;ELSE aid=NEW.approved_by;END IF;
  END IF;
  SELECT * INTO v FROM workflow_versions WHERE cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id AND plan_revision=rev AND plan_hash=ph;
  IF NOT FOUND THEN RETURN NULL;END IF;
  IF v.approval_format=2 THEN
    PERFORM m11_assert_approval_facts(w.id,rev,ph);
    IF TG_TABLE_NAME='workflow_executions' THEN
      IF NEW.approval_format<>2 OR NEW.approval_set_id IS DISTINCT FROM w.approval_set_id OR NEW.approval_set_hmac IS DISTINCT FROM w.approval_set_hmac THEN
        RAISE EXCEPTION 'Execution must use the exact complete V2 approval set' USING ERRCODE='23514';END IF;
    END IF;
    RETURN NULL;
  END IF;
  IF TG_TABLE_NAME='workflow_executions' THEN
    IF NEW.approval_format<>1 THEN RAISE EXCEPTION 'V1 execution cannot acquire V2 approval facts' USING ERRCODE='23514';END IF;
  END IF;
  IF TG_TABLE_NAME='workflow_approvals' THEN
    IF NOT v.approval_required OR NEW.approver_id IS NOT DISTINCT FROM w.requester_user_id OR NEW.decided_at<w.created_at THEN
      RAISE EXCEPTION 'Workflow approval must be a distinct real console decision' USING ERRCODE='23514';
    END IF;
  ELSIF aid IS NOT NULL THEN
    IF NOT v.approval_required OR aid IS NOT DISTINCT FROM w.requester_user_id
      OR NOT EXISTS(SELECT 1 FROM workflow_approvals WHERE cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id AND plan_revision=rev AND plan_hash=ph AND approver_id=aid AND decision='approve')
      OR EXISTS(SELECT 1 FROM workflow_approvals WHERE cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id AND plan_revision=rev AND plan_hash=ph AND decision='reject') THEN
      RAISE EXCEPTION 'Execution requires the exact committed approval fact' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;
