-- Candidate durable ordinary M8 configuration domain. This migration neither
-- upgrades old rows nor grants an HTTP frame, Native permit, or execution claim.
-- The fixed provider must prove the genuine authoring HTTP frame and recompile
-- fresh materials before atomically inserting the new J/P/W graph below.
-- Runtime bootstrap must add both new tables to migrate.ts's append-only
-- allowlist after its broad grants; SQL triggers also protect the owner role.
ALTER TABLE configuration_jobs
 ADD COLUMN authority_domain text,
 ADD COLUMN durable_issue_id uuid,
 ADD CONSTRAINT configuration_jobs_durable_shape CHECK(
  (authority_domain IS NULL AND durable_issue_id IS NULL) OR
  (authority_domain IS NOT NULL AND durable_issue_id IS NOT NULL
   AND authority_domain='durable-configuration-v1'
   AND kind IN('apply','rollback') AND origin_type='http'
   AND origin_session_id IS NOT NULL AND execution_mode='approval' AND approval_required
   AND required_origin_kind IS NULL AND required_origin_id IS NULL AND required_origin_hmac IS NULL)),
 ADD CONSTRAINT configuration_jobs_durable_identity UNIQUE(cluster_id,workspace_id,id,authority_domain,durable_issue_id);

-- Source previews may be consumed by any currently authorized actor. This
-- partial index bounds the whole-workspace encrypted lineage scan without
-- changing legacy apply authorization or treating an actor filter as safety.
CREATE INDEX configuration_jobs_durable_source_history
 ON configuration_jobs(cluster_id,workspace_id,created_at,id)
 WHERE kind IN('apply','rollback');

CREATE TABLE configuration_durable_issues (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,
 owner_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 authoring_session_id uuid NOT NULL,credential_epoch bigint NOT NULL CHECK(credential_epoch>0),
 permission_version text NOT NULL CHECK(length(permission_version) BETWEEN 1 AND 256),
 source_job_id uuid NOT NULL,source_plan_id uuid NOT NULL,source_plan_revision integer NOT NULL CHECK(source_plan_revision>0),
 source_plan_hash text NOT NULL CHECK(m8_hex64(source_plan_hash)),source_kind text NOT NULL CHECK(source_kind IN('import','rollback')),
 prepare_key text NOT NULL CHECK(length(prepare_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,admission_expires_at timestamptz NOT NULL,
 definition_id uuid NOT NULL,definition_version integer NOT NULL CHECK(definition_version>0),
 policy_hash text NOT NULL CHECK(m8_hex64(policy_hash)),intent_ttl_hours integer NOT NULL CHECK(intent_ttl_hours BETWEEN 1 AND 168),
 authority_domain text GENERATED ALWAYS AS('durable-configuration-v1') STORED,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,job_id),UNIQUE(owner_id,prepare_key),
 UNIQUE(source_job_id,source_plan_id,source_plan_revision),
 UNIQUE(cluster_id,workspace_id,id,job_id),
 UNIQUE(cluster_id,workspace_id,job_id,authority_domain,id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(authoring_session_id,owner_id) REFERENCES auth_sessions(id,user_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,source_job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,source_plan_id,source_plan_revision,source_plan_hash,source_job_id)
  REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,source_job_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,definition_id,definition_version)
  REFERENCES workflow_definition_versions(cluster_id,workspace_id,definition_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,job_id,authority_domain,id)
  REFERENCES configuration_jobs(cluster_id,workspace_id,id,authority_domain,durable_issue_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(job_id<>source_job_id),
 CHECK(issued_at<=created_at AND expires_at=issued_at+intent_ttl_hours*interval '1 hour'
  AND admission_expires_at>issued_at AND admission_expires_at<=issued_at+interval '5 minutes' AND admission_expires_at<=expires_at)
);
ALTER TABLE configuration_jobs ADD CONSTRAINT configuration_jobs_durable_issue_fk
 FOREIGN KEY(cluster_id,workspace_id,id,authority_domain,durable_issue_id)
 REFERENCES configuration_durable_issues(cluster_id,workspace_id,job_id,authority_domain,id)
 ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

-- FKs bind the original workflow revision, rather than its mutable current
-- pointer. SQL029 may later seal a new scheduled revision with its own facts.
ALTER TABLE config_snapshot_versions ADD CONSTRAINT config_snapshot_versions_durable_identity
 UNIQUE(cluster_id,workspace_id,snapshot_id,version,manifest_hmac);
CREATE TABLE configuration_durable_bindings (
 issue_id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,
 plan_id uuid NOT NULL,plan_revision integer NOT NULL CHECK(plan_revision>0),plan_hash text NOT NULL CHECK(m8_hex64(plan_hash)),
 workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL CHECK(workflow_plan_revision>0),workflow_plan_hash text NOT NULL CHECK(m8_hex64(workflow_plan_hash)),
 baseline_snapshot_id uuid NOT NULL,baseline_version integer NOT NULL CHECK(baseline_version>0),baseline_manifest_hmac text NOT NULL CHECK(m8_hex64(baseline_manifest_hmac)),
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),envelope_ciphertext text NOT NULL CHECK(m6_encrypted(envelope_ciphertext)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,issue_id,job_id),UNIQUE(cluster_id,workspace_id,job_id),UNIQUE(workflow_id),UNIQUE(plan_id,plan_revision),
 FOREIGN KEY(cluster_id,workspace_id,issue_id,job_id) REFERENCES configuration_durable_issues(cluster_id,workspace_id,id,job_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,job_id)
  REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,source_job_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,workflow_plan_revision,workflow_plan_hash)
  REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,baseline_snapshot_id,baseline_version,baseline_manifest_hmac)
  REFERENCES config_snapshot_versions(cluster_id,workspace_id,snapshot_id,version,manifest_hmac) ON DELETE RESTRICT
);
ALTER TABLE configuration_durable_issues ADD CONSTRAINT configuration_durable_issues_binding_fk
 FOREIGN KEY(cluster_id,workspace_id,id,job_id)
 REFERENCES configuration_durable_bindings(cluster_id,workspace_id,issue_id,job_id)
 ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION m11_guard_durable_configuration_marker() RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$BEGIN
 IF ROW(NEW.authority_domain,NEW.durable_issue_id) IS DISTINCT FROM ROW(OLD.authority_domain,OLD.durable_issue_id)
 THEN RAISE EXCEPTION 'Durable configuration authority markers are immutable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;$$;
CREATE TRIGGER configuration_jobs_durable_marker BEFORE UPDATE ON configuration_jobs
 FOR EACH ROW EXECUTE FUNCTION m11_guard_durable_configuration_marker();

-- New legacy inserts retain the old short domain. Existing historical rows
-- are neither scanned by a new CHECK nor rewritten by this INSERT-only fence.
CREATE FUNCTION m11_guard_configuration_short_domain() RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$BEGIN
 IF NEW.authority_domain IS NULL AND (NEW.authority_expires_at>NEW.created_at+interval '15 minutes'
  OR NEW.expires_at>NEW.created_at+interval '15 minutes')
 THEN RAISE EXCEPTION 'Legacy configuration jobs retain their original short authority domain' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;$$;
CREATE TRIGGER configuration_jobs_short_domain BEFORE INSERT ON configuration_jobs
 FOR EACH ROW EXECUTE FUNCTION m11_guard_configuration_short_domain();

-- This is an issuance-time SQL fence, not proof of an HTTP request. In
-- particular, its source deadline is never reused as the new business expiry,
-- and it is never rechecked later to extend or invalidate historical evidence.
CREATE FUNCTION m11_validate_durable_configuration_issue() RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
 DECLARE source_job configuration_jobs%ROWTYPE;source_plan configuration_plans%ROWTYPE;source_version configuration_plan_versions%ROWTYPE;
  actor users%ROWTYPE;sid auth_sessions%ROWTYPE;definition workflow_definitions%ROWTYPE;policy workflow_definition_versions%ROWTYPE;
 BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('configuration-source-plan:'||NEW.source_plan_id::text,0));
 SELECT * INTO actor FROM users WHERE id=NEW.owner_id FOR SHARE;
 SELECT * INTO sid FROM auth_sessions WHERE id=NEW.authoring_session_id AND user_id=NEW.owner_id FOR SHARE;
 SELECT * INTO source_job FROM configuration_jobs WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.source_job_id FOR UPDATE;
 SELECT * INTO source_plan FROM configuration_plans WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.source_plan_id FOR UPDATE;
 SELECT * INTO source_version FROM configuration_plan_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND plan_id=NEW.source_plan_id AND plan_revision=NEW.source_plan_revision;
 SELECT * INTO definition FROM workflow_definitions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.definition_id FOR SHARE;
 SELECT * INTO policy FROM workflow_definition_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND definition_id=NEW.definition_id AND version=NEW.definition_version;
 IF actor.id IS NULL OR sid.id IS NULL OR source_job.id IS NULL OR source_plan.id IS NULL OR source_version.plan_id IS NULL OR definition.id IS NULL OR policy.definition_id IS NULL
  OR actor.status IS DISTINCT FROM 'active' OR actor.deleted_at IS NOT NULL OR actor.force_password_change
  OR actor.locked_until>clock_timestamp() OR actor.credential_epoch IS DISTINCT FROM NEW.credential_epoch
  OR sid.credential_epoch IS DISTINCT FROM NEW.credential_epoch OR sid.revoked_at IS NOT NULL OR sid.expires_at<=clock_timestamp()
  OR NEW.issued_at>clock_timestamp() OR NEW.issued_at<clock_timestamp()-interval '5 minutes' OR NEW.expires_at<=clock_timestamp() OR NEW.admission_expires_at<=clock_timestamp()
  OR source_job.actor_id IS DISTINCT FROM NEW.owner_id OR source_job.origin_type IS DISTINCT FROM 'http'
  OR source_job.origin_session_id IS DISTINCT FROM NEW.authoring_session_id OR source_job.state IS DISTINCT FROM 'succeeded'
  OR source_job.authority_expires_at<=clock_timestamp() OR source_job.expires_at<=clock_timestamp()
  OR source_job.authority_domain IS NOT NULL OR source_job.durable_issue_id IS NOT NULL
  OR source_job.required_origin_kind IS NOT NULL OR source_job.required_origin_id IS NOT NULL OR source_job.required_origin_hmac IS NOT NULL
  OR source_job.workflow_id IS NOT NULL OR source_job.remote_started OR source_job.remote_completed
  OR source_job.credential_epoch IS DISTINCT FROM NEW.credential_epoch OR source_job.permission_version IS DISTINCT FROM NEW.permission_version
  OR (NEW.source_kind='import' AND(source_job.kind IS DISTINCT FROM 'import' OR source_plan.mode NOT IN('merge','sync')))
  OR (NEW.source_kind='rollback' AND(source_job.kind IS DISTINCT FROM 'compare' OR source_plan.mode IS DISTINCT FROM 'rollback'))
  OR source_plan.source_job_id IS DISTINCT FROM source_job.id OR source_plan.state IS DISTINCT FROM 'ready'
  OR source_plan.created_by IS DISTINCT FROM NEW.owner_id OR source_plan.current_revision IS DISTINCT FROM NEW.source_plan_revision
  OR ROW(source_job.plan_id,source_job.plan_revision,source_job.plan_hash) IS DISTINCT FROM ROW(NEW.source_plan_id,NEW.source_plan_revision,NEW.source_plan_hash)
  OR source_version.plan_hash IS DISTINCT FROM NEW.source_plan_hash OR source_version.source_job_id IS DISTINCT FROM source_job.id
  OR source_version.expires_at<=clock_timestamp() OR NOT source_version.recovery_complete
  OR NOT EXISTS(SELECT 1 FROM clusters c WHERE c.id=NEW.cluster_id AND c.deleted_at IS NULL AND c.execution_mode='approval')
  OR definition.kind IS DISTINCT FROM 'configuration_v2' OR definition.code IS DISTINCT FROM 'configuration_v2'
  OR definition.status IS DISTINCT FROM 'active' OR definition.deleted_at IS NOT NULL OR definition.current_version IS DISTINCT FROM NEW.definition_version
  OR policy.approval_format IS DISTINCT FROM 2 OR policy.policy_hash IS DISTINCT FROM NEW.policy_hash
  OR policy.policy->>'intentTtlHours' IS DISTINCT FROM NEW.intent_ttl_hours::text
  OR EXISTS(SELECT 1 FROM configuration_executions WHERE job_id=source_job.id OR plan_id=source_plan.id)
  OR EXISTS(SELECT 1 FROM mutation_operations operation LEFT JOIN configuration_job_steps step ON step.id=operation.configuration_step_id
   WHERE operation.configuration_job_id=source_job.id OR(step.plan_id=source_plan.id AND step.plan_revision=NEW.source_plan_revision))
  OR EXISTS(SELECT 1 FROM configuration_job_origin_bindings WHERE job_id=source_job.id)
  OR EXISTS(SELECT 1 FROM configuration_plan_origin_bindings WHERE plan_id=source_plan.id)
 THEN RAISE EXCEPTION 'Durable configuration issue requires a current unexecuted ordinary source and exact live V2 configuration policy' USING ERRCODE='23514';END IF;
 RETURN NEW;
 END;
$$;
CREATE TRIGGER configuration_durable_issues_issuance BEFORE INSERT ON configuration_durable_issues
 FOR EACH ROW EXECUTE FUNCTION m11_validate_durable_configuration_issue();

-- Immutable complete-graph validation. Current user/SID/source-preview expiry
-- belongs exclusively to issuance above; later scheduling keeps the original
-- issue deadline and original workflow_versions, without renewing old facts.
CREATE FUNCTION m11_assert_durable_configuration_graph(iid uuid,initial_graph boolean) RETURNS void LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
 DECLARE issue configuration_durable_issues%ROWTYPE;b configuration_durable_bindings%ROWTYPE;j configuration_jobs%ROWTYPE;
  p configuration_plans%ROWTYPE;v configuration_plan_versions%ROWTYPE;w workflows%ROWTYPE;wv workflow_versions%ROWTYPE;
  current_wv workflow_versions%ROWTYPE;baseline config_snapshot_versions%ROWTYPE;policy workflow_definition_versions%ROWTYPE;
 BEGIN
 SELECT * INTO issue FROM configuration_durable_issues WHERE id=iid;
 SELECT * INTO b FROM configuration_durable_bindings WHERE issue_id=iid;
 SELECT * INTO j FROM configuration_jobs WHERE id=issue.job_id;
 SELECT * INTO p FROM configuration_plans WHERE id=b.plan_id;
 SELECT * INTO v FROM configuration_plan_versions WHERE cluster_id=b.cluster_id AND workspace_id=b.workspace_id AND plan_id=b.plan_id AND plan_revision=b.plan_revision;
 SELECT * INTO w FROM workflows WHERE id=b.workflow_id;
 SELECT * INTO wv FROM workflow_versions WHERE cluster_id=b.cluster_id AND workspace_id=b.workspace_id AND workflow_id=b.workflow_id AND plan_revision=b.workflow_plan_revision;
 SELECT * INTO current_wv FROM workflow_versions WHERE cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id AND plan_revision=w.plan_revision;
 SELECT * INTO baseline FROM config_snapshot_versions WHERE cluster_id=b.cluster_id AND workspace_id=b.workspace_id AND snapshot_id=b.baseline_snapshot_id AND version=b.baseline_version;
 SELECT * INTO policy FROM workflow_definition_versions WHERE cluster_id=issue.cluster_id AND workspace_id=issue.workspace_id AND definition_id=issue.definition_id AND version=issue.definition_version;
 IF issue.id IS NULL OR b.issue_id IS NULL OR j.id IS NULL OR p.id IS NULL OR v.plan_id IS NULL OR w.id IS NULL OR wv.workflow_id IS NULL OR current_wv.workflow_id IS NULL OR baseline.version_id IS NULL OR policy.definition_id IS NULL
  OR ROW(b.cluster_id,b.workspace_id,b.job_id) IS DISTINCT FROM ROW(issue.cluster_id,issue.workspace_id,issue.job_id)
  OR ROW(j.cluster_id,j.workspace_id,j.authority_domain,j.durable_issue_id,j.actor_id,j.origin_session_id,j.credential_epoch,j.permission_version,j.idempotency_key,j.request_hmac,j.authority_expires_at,j.expires_at)
   IS DISTINCT FROM ROW(issue.cluster_id,issue.workspace_id,'durable-configuration-v1'::text,issue.id,issue.owner_id,issue.authoring_session_id,issue.credential_epoch,issue.permission_version,issue.prepare_key,issue.request_hmac,issue.expires_at,issue.expires_at)
  OR j.origin_type IS DISTINCT FROM 'http' OR j.execution_mode IS DISTINCT FROM 'approval' OR j.approval_required IS DISTINCT FROM true
  OR j.kind IS DISTINCT FROM(CASE WHEN issue.source_kind='rollback' THEN 'rollback' ELSE 'apply' END)
  OR j.required_origin_kind IS NOT NULL OR j.required_origin_id IS NOT NULL OR j.required_origin_hmac IS NOT NULL
  OR ROW(j.plan_id,j.plan_revision,j.plan_hash,j.workflow_id) IS DISTINCT FROM ROW(b.plan_id,b.plan_revision,b.plan_hash,b.workflow_id)
  OR ROW(p.cluster_id,p.workspace_id,p.created_by,p.source_job_id,p.current_revision) IS DISTINCT FROM ROW(issue.cluster_id,issue.workspace_id,issue.owner_id,j.id,b.plan_revision)
  OR p.id=issue.source_plan_id OR j.id=issue.source_job_id OR w.id=j.id OR w.id=issue.source_job_id
  OR (issue.source_kind='rollback' AND p.mode IS DISTINCT FROM 'rollback') OR(issue.source_kind='import' AND p.mode NOT IN('merge','sync'))
  OR ROW(v.cluster_id,v.workspace_id,v.source_job_id,v.plan_hash,v.expires_at,v.baseline_manifest_hmac,v.permission_version,v.cluster_revision,v.workspace_revision)
   IS DISTINCT FROM ROW(issue.cluster_id,issue.workspace_id,j.id,b.plan_hash,issue.expires_at,b.baseline_manifest_hmac,issue.permission_version,j.cluster_revision,j.workspace_revision)
  OR NOT v.recovery_complete OR v.native_packet_count>500
  OR ROW(w.cluster_id,w.workspace_id,w.kind,w.subject_type,w.subject_id,w.requester_type,w.requester_user_id,w.definition_id,w.definition_version,w.approval_format,w.execution_mode,w.approval_required,w.expires_at)
   IS DISTINCT FROM ROW(issue.cluster_id,issue.workspace_id,'configuration_v2'::text,'configuration_jobs'::text,j.id,'console'::text,issue.owner_id,issue.definition_id,issue.definition_version,2::smallint,'approval'::text,true,issue.expires_at)
  OR w.requester_developer_id IS NOT NULL OR w.plan_revision<b.workflow_plan_revision
  OR ROW(wv.plan_hash,wv.expires_at,wv.created_by,wv.execution_mode,wv.approval_required,wv.approval_format,wv.step_count,wv.native_request_count)
   IS DISTINCT FROM ROW(b.workflow_plan_hash,issue.expires_at,issue.owner_id,'approval'::text,true,2::smallint,1,0)
  OR wv.created_by_developer_id IS NOT NULL
  OR ROW(current_wv.plan_hash,current_wv.expires_at,current_wv.created_by,current_wv.execution_mode,current_wv.approval_required,current_wv.approval_format,current_wv.step_count,current_wv.native_request_count)
   IS DISTINCT FROM ROW(w.plan_hash,issue.expires_at,issue.owner_id,'approval'::text,true,2::smallint,1,0)
  OR current_wv.created_by_developer_id IS NOT NULL
  OR (SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=b.workflow_plan_revision)<>1
  OR NOT EXISTS(SELECT 1 FROM workflow_steps s WHERE s.cluster_id=issue.cluster_id AND s.workspace_id=issue.workspace_id AND s.workflow_id=w.id
   AND s.plan_revision=b.workflow_plan_revision AND s.plan_hash=b.workflow_plan_hash AND s.kind='metadata' AND s.handler='configuration_v2'
   AND s.entity_type='configuration_jobs' AND s.entity_id=j.id AND s.native_requests='[]'::jsonb)
  OR (SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision)<>1
  OR NOT EXISTS(SELECT 1 FROM workflow_steps s WHERE s.cluster_id=issue.cluster_id AND s.workspace_id=issue.workspace_id AND s.workflow_id=w.id
   AND s.plan_revision=w.plan_revision AND s.plan_hash=w.plan_hash AND s.kind='metadata' AND s.handler='configuration_v2'
   AND s.entity_type='configuration_jobs' AND s.entity_id=j.id AND s.native_requests='[]'::jsonb)
  OR ROW(baseline.cluster_id,baseline.workspace_id,baseline.manifest_hmac,baseline.permission_version)
   IS DISTINCT FROM ROW(issue.cluster_id,issue.workspace_id,b.baseline_manifest_hmac,issue.permission_version)
  OR baseline.completeness IS DISTINCT FROM 'complete' OR baseline.consistency IS DISTINCT FROM 'console_fenced_best_effort'
  OR j.safe_progress->>'baselineSnapshotId' IS DISTINCT FROM b.baseline_snapshot_id::text
  OR j.safe_progress->>'baselineVersion' IS DISTINCT FROM b.baseline_version::text
  OR policy.approval_format IS DISTINCT FROM 2 OR policy.policy_hash IS DISTINCT FROM issue.policy_hash
  OR policy.policy->>'intentTtlHours' IS DISTINCT FROM issue.intent_ttl_hours::text
 THEN RAISE EXCEPTION 'Durable configuration graph must retain its exact tenant material, policy, snapshot and wrapper identities' USING ERRCODE='23514';END IF;
 -- Deferred commit-time natural-expiry check applies only to the newly
 -- issued graph. An old preview/admission is not revalidated as authority for
 -- subsequent long-window approvals, schedules or genuine execution claims.
 IF initial_graph AND(issue.admission_expires_at<=clock_timestamp() OR NOT EXISTS(
  SELECT 1 FROM users actor JOIN auth_sessions sid ON sid.id=issue.authoring_session_id AND sid.user_id=actor.id
  JOIN configuration_jobs source_job ON source_job.id=issue.source_job_id AND source_job.cluster_id=issue.cluster_id AND source_job.workspace_id=issue.workspace_id
  JOIN configuration_plan_versions source_version ON source_version.cluster_id=issue.cluster_id AND source_version.workspace_id=issue.workspace_id
   AND source_version.plan_id=issue.source_plan_id AND source_version.plan_revision=issue.source_plan_revision AND source_version.plan_hash=issue.source_plan_hash AND source_version.source_job_id=source_job.id
  JOIN configuration_materials source_material ON source_material.id=source_version.material_id AND source_material.cluster_id=issue.cluster_id AND source_material.workspace_id=issue.workspace_id
  JOIN workflow_definitions current_policy ON current_policy.id=issue.definition_id AND current_policy.cluster_id=issue.cluster_id AND current_policy.workspace_id=issue.workspace_id
  WHERE actor.id=issue.owner_id AND actor.status='active' AND actor.deleted_at IS NULL AND NOT actor.force_password_change
   AND(actor.locked_until IS NULL OR actor.locked_until<=clock_timestamp()) AND actor.credential_epoch=issue.credential_epoch
   AND sid.credential_epoch=issue.credential_epoch AND sid.revoked_at IS NULL AND sid.expires_at>clock_timestamp()
   AND source_job.state='succeeded' AND source_job.authority_expires_at>clock_timestamp() AND source_job.expires_at>clock_timestamp()
   AND source_version.expires_at>clock_timestamp() AND source_material.state='available'
   AND current_policy.status='active' AND current_policy.deleted_at IS NULL AND current_policy.current_version=issue.definition_version
   AND EXISTS(SELECT 1 FROM clusters c WHERE c.id=issue.cluster_id AND c.deleted_at IS NULL AND c.execution_mode='approval' AND c.revision=j.cluster_revision)))
 THEN RAISE EXCEPTION 'New durable configuration issuance crossed its original live admission or source deadline' USING ERRCODE='23514';END IF;
 IF initial_graph AND(
  j.state IS DISTINCT FROM 'waiting_approval' OR j.remote_started OR j.remote_completed OR j.started_at IS NOT NULL
  OR j.completed_at IS NOT NULL OR j.lease_owner_hash IS NOT NULL OR j.lease_until IS NOT NULL
  OR p.state IS DISTINCT FROM 'pending_approval' OR w.state IS DISTINCT FROM 'pending'
  OR w.plan_revision IS DISTINCT FROM b.workflow_plan_revision OR w.plan_hash IS DISTINCT FROM b.workflow_plan_hash
  OR w.approval_set_id IS NOT NULL OR w.approved_by IS NOT NULL OR w.approved_at IS NOT NULL
  OR issue.expires_at<=clock_timestamp()
  OR EXISTS(SELECT 1 FROM workflow_approvals WHERE workflow_id=w.id)
  OR EXISTS(SELECT 1 FROM workflow_approval_sets WHERE workflow_id=w.id)
  OR EXISTS(SELECT 1 FROM workflow_executions WHERE workflow_id=w.id)
  OR EXISTS(SELECT 1 FROM configuration_executions WHERE job_id=j.id OR plan_id=p.id)
  OR EXISTS(SELECT 1 FROM mutation_operations operation LEFT JOIN configuration_job_steps step ON step.id=operation.configuration_step_id
   WHERE operation.configuration_job_id=j.id OR step.plan_id=p.id)
  OR EXISTS(SELECT 1 FROM workflow_schedules WHERE workflow_id=w.id)
  OR EXISTS(SELECT 1 FROM workflow_execution_origins WHERE workflow_id=w.id)
  OR EXISTS(SELECT 1 FROM workflow_configuration_execution_origins WHERE configuration_job_id=j.id)
 ) THEN RAISE EXCEPTION 'New durable configuration graph must be freshly compiled, unvoted, unclaimed and unexecuted' USING ERRCODE='23514';END IF;
 IF initial_graph THEN PERFORM m11_assert_approval_facts(w.id,w.plan_revision,w.plan_hash);END IF;
 END;
$$;

CREATE FUNCTION m11_validate_durable_configuration_graph() RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
 DECLARE iid uuid;initial_graph boolean:=false;
 BEGIN
 IF TG_TABLE_NAME='configuration_durable_issues' THEN iid=NEW.id;initial_graph=true;
 ELSIF TG_TABLE_NAME='configuration_durable_bindings' THEN iid=NEW.issue_id;initial_graph=true;
 ELSIF TG_TABLE_NAME='configuration_jobs' THEN iid=NEW.durable_issue_id;initial_graph=(TG_OP='INSERT');
 ELSIF TG_TABLE_NAME='workflows' THEN SELECT durable_issue_id INTO iid FROM configuration_jobs WHERE id=NEW.subject_id AND NEW.subject_type='configuration_jobs';
 ELSIF TG_TABLE_NAME='configuration_plans' THEN SELECT durable_issue_id INTO iid FROM configuration_jobs WHERE id=NEW.source_job_id;
 ELSE RAISE EXCEPTION 'Unsupported durable configuration graph trigger' USING ERRCODE='23514';END IF;
 IF iid IS NOT NULL THEN PERFORM m11_assert_durable_configuration_graph(iid,initial_graph);END IF;
 RETURN NULL;
 END;
$$;
CREATE CONSTRAINT TRIGGER configuration_durable_issues_complete AFTER INSERT ON configuration_durable_issues
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_durable_configuration_graph();
CREATE CONSTRAINT TRIGGER configuration_durable_bindings_complete AFTER INSERT ON configuration_durable_bindings
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_durable_configuration_graph();
CREATE CONSTRAINT TRIGGER configuration_jobs_durable_complete AFTER INSERT OR UPDATE ON configuration_jobs
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_durable_configuration_graph();
CREATE CONSTRAINT TRIGGER workflows_durable_configuration_complete AFTER INSERT OR UPDATE ON workflows
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_durable_configuration_graph();
CREATE CONSTRAINT TRIGGER configuration_plans_durable_complete AFTER INSERT OR UPDATE ON configuration_plans
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_durable_configuration_graph();

DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['configuration_durable_issues','configuration_durable_bindings'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
END;$$;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON configuration_durable_issues,configuration_durable_bindings FROM PUBLIC;
-- No legacy deadline, status, claim, schedule, execution or origin is rewritten.
-- AEAD/material HMAC/real HTTP provenance/capture freshness are mandatory
-- provider checks; this SQL alone intentionally supplies no Native authority.
