-- Candidate ordinary durable-registration rejection receipt.
-- Only the fixed genuine provider may classify freshDiffChanged before publish.
-- SQL proves stored identities and mutually exclusive durable publication; it
-- neither proves that an HTTP request existed nor that no baseline was captured.
-- SQL038 and all existing history remain byte-for-byte unchanged.
CREATE TABLE configuration_durable_rejections (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 owner_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 authoring_session_id uuid NOT NULL,credential_epoch bigint NOT NULL CHECK(credential_epoch>0),
 permission_version text NOT NULL CHECK(length(permission_version) BETWEEN 1 AND 256),
 source_job_id uuid NOT NULL,source_plan_id uuid NOT NULL,source_plan_revision integer NOT NULL CHECK(source_plan_revision>0),
 source_plan_hash text NOT NULL CHECK(m8_hex64(source_plan_hash)),source_kind text NOT NULL CHECK(source_kind IN('import','rollback')),
 prepare_key text NOT NULL CHECK(length(prepare_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 fresh_plan_hmac text NOT NULL CHECK(m8_hex64(fresh_plan_hmac)),
 baseline_snapshot_id uuid NOT NULL,baseline_version integer NOT NULL CHECK(baseline_version>0),baseline_manifest_hmac text NOT NULL CHECK(m8_hex64(baseline_manifest_hmac)),
 admission_issued_at timestamptz NOT NULL,admission_expires_at timestamptz NOT NULL,
 -- Derived by the service from SELECT clock_timestamp() in this transaction,
 -- never from an HTTP field; included in rejection_hmac before this INSERT.
 rejected_at timestamptz NOT NULL,rejection_hmac text NOT NULL CHECK(m8_hex64(rejection_hmac)),
 code text GENERATED ALWAYS AS('CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED') STORED,
 effect_scope text GENERATED ALWAYS AS('durable-registration') STORED,
 UNIQUE(owner_id,prepare_key),UNIQUE(cluster_id,workspace_id,id),
 UNIQUE(source_job_id,source_plan_id,source_plan_revision),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(authoring_session_id,owner_id) REFERENCES auth_sessions(id,user_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,source_job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,source_plan_id,source_plan_revision,source_plan_hash,source_job_id)
  REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,source_job_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,baseline_snapshot_id,baseline_version,baseline_manifest_hmac)
  REFERENCES config_snapshot_versions(cluster_id,workspace_id,snapshot_id,version,manifest_hmac) ON DELETE RESTRICT,
 CHECK(admission_issued_at<=rejected_at AND rejected_at<admission_expires_at
  AND admission_expires_at<=admission_issued_at+interval '5 minutes')
);

-- A command key is reserved globally for this owner by the durable domain.
-- Existing generic job keys remain scoped; this non-unique index makes the
-- cross-scope collision proof bounded by its exact owner/key lookup.
CREATE INDEX configuration_jobs_durable_command_lookup ON configuration_jobs(actor_id,idempotency_key);

-- One fixed implementation for both tables makes the mutex order explicit.
-- New issues are also checked by SQL038's existing issuance/completion guards.
-- A new transaction must re-read dispositions after acquiring both locks.
CREATE FUNCTION m11_guard_durable_registration_disposition() RETURNS trigger
 LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
 DECLARE source_job configuration_jobs%ROWTYPE;source_plan configuration_plans%ROWTYPE;
  source_version configuration_plan_versions%ROWTYPE;actor users%ROWTYPE;sid auth_sessions%ROWTYPE;
  baseline config_snapshot_versions%ROWTYPE;capture_job configuration_jobs%ROWTYPE;
 BEGIN
 IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
 THEN RAISE EXCEPTION 'Durable registration disposition requires READ COMMITTED' USING ERRCODE='23514';END IF;
 -- Generic job inserts have no source_plan_id or owner_id fields. Handle
 -- this table first, before accessing any disposition-only NEW record field.
 IF TG_TABLE_NAME='configuration_jobs' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('configuration-durable-command:'||NEW.actor_id::text||':'||NEW.idempotency_key,0));
  IF EXISTS(SELECT 1 FROM configuration_durable_rejections r WHERE r.owner_id=NEW.actor_id AND r.prepare_key=NEW.idempotency_key)
   OR EXISTS(SELECT 1 FROM configuration_durable_issues i WHERE i.owner_id=NEW.actor_id AND i.prepare_key=NEW.idempotency_key AND i.job_id IS DISTINCT FROM NEW.id)
  THEN RAISE EXCEPTION 'Configuration job cannot shadow an original durable registration key' USING ERRCODE='23514';END IF;
  -- The exact new durable issue's J may be inserted after that issue in the
  -- same transaction. SQL038 still proves its complete reciprocal graph.
  RETURN NEW;
 END IF;
 IF TG_TABLE_NAME NOT IN('configuration_durable_issues','configuration_durable_rejections')
 THEN RAISE EXCEPTION 'Unsupported durable registration disposition table' USING ERRCODE='23514';END IF;
 -- These spellings must be identical in publication, rejection and the
 -- existing legacy source-plan guard. UUID ::text provides canonical case.
 PERFORM pg_advisory_xact_lock(hashtextextended('configuration-source-plan:'||NEW.source_plan_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('configuration-durable-command:'||NEW.owner_id::text||':'||NEW.prepare_key,0));
 -- Durable registration keys are reserved across the owner's whole console,
 -- even when a pre-existing ordinary job belongs to a different tenant.
 -- The issue INSERT precedes its exact new J; any J already present here is
 -- a conflicting older command. Rejection never owns a newly published J.
 IF EXISTS(SELECT 1 FROM configuration_jobs j WHERE j.actor_id=NEW.owner_id AND j.idempotency_key=NEW.prepare_key)
 THEN RAISE EXCEPTION 'Existing configuration job already owns this durable registration key' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='configuration_durable_issues' THEN
  IF EXISTS(SELECT 1 FROM configuration_durable_rejections r
    WHERE (r.owner_id=NEW.owner_id AND r.prepare_key=NEW.prepare_key)
     OR r.source_plan_id=NEW.source_plan_id)
  THEN RAISE EXCEPTION 'Original durable registration key or source was permanently rejected' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF TG_TABLE_NAME IS DISTINCT FROM 'configuration_durable_rejections'
 THEN RAISE EXCEPTION 'Unsupported durable registration disposition table' USING ERRCODE='23514';END IF;
 -- Check any already published issue, including another key for this source.
 -- A same-transaction pending issue is visible here too and forbids a receipt.
 IF EXISTS(SELECT 1 FROM configuration_durable_issues i
   WHERE (i.owner_id=NEW.owner_id AND i.prepare_key=NEW.prepare_key)
    OR i.source_plan_id=NEW.source_plan_id)
 THEN RAISE EXCEPTION 'Published durable registration cannot be certified rejected' USING ERRCODE='23514';END IF;
 SELECT * INTO actor FROM users WHERE id=NEW.owner_id FOR SHARE;
 SELECT * INTO sid FROM auth_sessions WHERE id=NEW.authoring_session_id AND user_id=NEW.owner_id FOR SHARE;
 SELECT * INTO source_job FROM configuration_jobs WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.source_job_id FOR UPDATE;
 SELECT * INTO source_plan FROM configuration_plans WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.source_plan_id FOR UPDATE;
 SELECT * INTO source_version FROM configuration_plan_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND plan_id=NEW.source_plan_id AND plan_revision=NEW.source_plan_revision;
 SELECT * INTO baseline FROM config_snapshot_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND snapshot_id=NEW.baseline_snapshot_id AND version=NEW.baseline_version;
 SELECT * INTO capture_job FROM configuration_jobs WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=baseline.source_job_id;
 IF actor.id IS NULL OR sid.id IS NULL OR source_job.id IS NULL OR source_plan.id IS NULL OR source_version.plan_id IS NULL
  OR baseline.version_id IS NULL OR capture_job.id IS NULL
  OR actor.status IS DISTINCT FROM 'active' OR actor.deleted_at IS NOT NULL OR actor.force_password_change
  OR actor.locked_until>clock_timestamp() OR actor.credential_epoch IS DISTINCT FROM NEW.credential_epoch
  OR sid.credential_epoch IS DISTINCT FROM NEW.credential_epoch OR sid.revoked_at IS NOT NULL OR sid.expires_at<=clock_timestamp()
  OR NEW.rejected_at>clock_timestamp() OR NEW.rejected_at<clock_timestamp()-interval '30 seconds'
  OR NEW.admission_issued_at>clock_timestamp() OR NEW.admission_expires_at<=clock_timestamp()
  OR source_job.actor_id IS DISTINCT FROM NEW.owner_id OR source_job.origin_type IS DISTINCT FROM 'http'
  OR source_job.origin_session_id IS DISTINCT FROM NEW.authoring_session_id OR source_job.state IS DISTINCT FROM 'succeeded'
  OR source_job.credential_epoch IS DISTINCT FROM NEW.credential_epoch OR source_job.permission_version IS DISTINCT FROM NEW.permission_version
  OR source_job.authority_expires_at<=clock_timestamp() OR source_job.expires_at<=clock_timestamp()
  OR source_job.authority_domain IS NOT NULL OR source_job.durable_issue_id IS NOT NULL
  OR source_job.required_origin_kind IS NOT NULL OR source_job.required_origin_id IS NOT NULL OR source_job.required_origin_hmac IS NOT NULL
  OR source_job.workflow_id IS NOT NULL OR source_job.remote_started OR source_job.remote_completed
  OR ROW(source_job.plan_id,source_job.plan_revision,source_job.plan_hash) IS DISTINCT FROM ROW(NEW.source_plan_id,NEW.source_plan_revision,NEW.source_plan_hash)
  OR source_plan.source_job_id IS DISTINCT FROM source_job.id OR source_plan.created_by IS DISTINCT FROM NEW.owner_id
  OR source_plan.state IS DISTINCT FROM 'ready' OR source_plan.current_revision IS DISTINCT FROM NEW.source_plan_revision
  OR ROW(source_version.plan_hash,source_version.source_job_id) IS DISTINCT FROM ROW(NEW.source_plan_hash,source_job.id)
  OR source_version.expires_at<=clock_timestamp() OR NOT source_version.recovery_complete
  OR NOT EXISTS(SELECT 1 FROM configuration_materials material
   WHERE material.cluster_id=NEW.cluster_id AND material.workspace_id=NEW.workspace_id
    AND material.id=source_version.material_id AND material.job_id=source_job.id
    AND material.artifact_kind='plan' AND material.artifact_id=source_version.artifact_id
    AND material.state='available' AND material.wrapped_key_secret IS NOT NULL FOR SHARE)
  OR NOT EXISTS(SELECT 1 FROM config_snapshots snapshot JOIN configuration_materials material
   ON material.cluster_id=snapshot.cluster_id AND material.workspace_id=snapshot.workspace_id
    AND material.id=baseline.material_id AND material.job_id=baseline.source_job_id
    AND material.artifact_kind='snapshot' AND material.artifact_id=baseline.version_id
   WHERE snapshot.cluster_id=NEW.cluster_id AND snapshot.workspace_id=NEW.workspace_id
    AND snapshot.id=baseline.snapshot_id AND snapshot.state='ready' AND snapshot.current_version=NEW.baseline_version
    AND material.state='available' AND material.wrapped_key_secret IS NOT NULL FOR SHARE OF snapshot,material)
  OR baseline.manifest_hmac IS DISTINCT FROM NEW.baseline_manifest_hmac OR baseline.completeness IS DISTINCT FROM 'complete'
  OR baseline.consistency IS DISTINCT FROM 'console_fenced_best_effort' OR baseline.permission_version IS DISTINCT FROM NEW.permission_version
  OR baseline.observed_from<NEW.admission_issued_at OR baseline.observed_until>NEW.rejected_at
  OR capture_job.id=source_job.id OR capture_job.kind IS DISTINCT FROM 'capture' OR capture_job.state IS DISTINCT FROM 'succeeded'
  OR capture_job.actor_id IS DISTINCT FROM NEW.owner_id OR capture_job.origin_session_id IS DISTINCT FROM NEW.authoring_session_id
  OR capture_job.credential_epoch IS DISTINCT FROM NEW.credential_epoch OR capture_job.permission_version IS DISTINCT FROM NEW.permission_version
  OR(NEW.source_kind='import' AND(source_job.kind IS DISTINCT FROM 'import' OR source_plan.mode NOT IN('merge','sync')))
  OR(NEW.source_kind='rollback' AND(source_job.kind IS DISTINCT FROM 'compare' OR source_plan.mode IS DISTINCT FROM 'rollback'))
  OR EXISTS(SELECT 1 FROM configuration_job_origin_bindings WHERE job_id=source_job.id)
  OR EXISTS(SELECT 1 FROM configuration_plan_origin_bindings WHERE plan_id=source_plan.id)
  OR EXISTS(SELECT 1 FROM configuration_executions WHERE job_id=source_job.id OR plan_id=source_plan.id)
  OR EXISTS(SELECT 1 FROM mutation_operations operation LEFT JOIN configuration_job_steps step ON step.id=operation.configuration_step_id
   WHERE operation.configuration_job_id=source_job.id OR(step.plan_id=source_plan.id AND step.plan_revision=NEW.source_plan_revision))
 THEN RAISE EXCEPTION 'Durable rejection requires its current original ordinary unexecuted source and authoring identity' USING ERRCODE='23514';END IF;
 -- Encrypted legacy apply/rollback lineage is intentionally NOT claimed to be
 -- proved by this trigger. The fixed provider must run assertUnconsumedSource
 -- across the complete tenant under this same source-plan lock and transaction.
 RETURN NEW;
 END;
$$;
-- PostgreSQL runs same-time triggers alphabetically. This fence runs before
-- SQL038's configuration_durable_issues_issuance; it never replaces that guard.
CREATE TRIGGER configuration_jobs_durable_disposition BEFORE INSERT ON configuration_jobs
 FOR EACH ROW EXECUTE FUNCTION m11_guard_durable_registration_disposition();
CREATE TRIGGER configuration_durable_issues_00_disposition BEFORE INSERT ON configuration_durable_issues
 FOR EACH ROW EXECUTE FUNCTION m11_guard_durable_registration_disposition();
CREATE TRIGGER configuration_durable_rejections_disposition BEFORE INSERT ON configuration_durable_rejections
 FOR EACH ROW EXECUTE FUNCTION m11_guard_durable_registration_disposition();
-- Re-run only initial rejection insertion at the natural transaction tail.
-- The function checks existing issues, not rejection self-existence, so the
-- original receipt is not mistaken for a competing disposition. Old receipt
-- reads never re-run current SID/source/admission deadline requirements.
CREATE CONSTRAINT TRIGGER configuration_durable_rejections_complete AFTER INSERT ON configuration_durable_rejections
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_guard_durable_registration_disposition();
CREATE TRIGGER configuration_durable_rejections_immutable BEFORE UPDATE OR DELETE ON configuration_durable_rejections
 FOR EACH ROW EXECUTE FUNCTION m8_immutable();
CREATE TRIGGER configuration_durable_rejections_no_truncate BEFORE TRUNCATE ON configuration_durable_rejections
 FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON configuration_durable_rejections FROM PUBLIC;
-- Add configuration_durable_rejections to migrate.ts's append-only allowlist
-- AFTER its broad runtime grants. Runtime receives SELECT/INSERT only.
