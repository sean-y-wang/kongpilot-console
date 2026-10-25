-- Promote remains a source-authorized operation after it becomes a target M8
-- plan. Nullable legacy markers preserve existing M8 jobs without upgrading
-- them to source authority. All marked jobs require immutable exact bindings.
ALTER TABLE configuration_jobs
 ADD COLUMN required_origin_kind text,
 ADD COLUMN required_origin_id uuid,
 ADD COLUMN required_origin_hmac text,
 ADD CONSTRAINT configuration_jobs_origin_shape CHECK(
  num_nonnulls(required_origin_kind,required_origin_id,required_origin_hmac)=0 OR
  (num_nonnulls(required_origin_kind,required_origin_id,required_origin_hmac)=3
   AND required_origin_kind='governance-promote' AND m8_hex64(required_origin_hmac)
   AND origin_type='http' AND kind IN('import','apply','reconcile'))),
 ADD CONSTRAINT configuration_jobs_origin_unique UNIQUE(cluster_id,workspace_id,id,required_origin_kind,required_origin_id,required_origin_hmac);
ALTER TABLE governance_promotions ADD CONSTRAINT governance_promotions_origin_unique
 UNIQUE(cluster_id,workspace_id,id,target_cluster_id,target_workspace_id,comparison_id);
ALTER TABLE configuration_plan_versions ADD CONSTRAINT configuration_plan_versions_origin_unique
 UNIQUE(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,source_job_id);

CREATE TABLE configuration_job_origin_bindings (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,
 origin_kind text NOT NULL CHECK(origin_kind='governance-promote'),origin_id uuid NOT NULL,
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),
 source_cluster_id uuid NOT NULL,source_workspace_id uuid NOT NULL,comparison_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,job_id),
 UNIQUE(cluster_id,workspace_id,job_id,origin_kind,origin_id,material_hmac),
 FOREIGN KEY(cluster_id,workspace_id,job_id,origin_kind,origin_id,material_hmac)
  REFERENCES configuration_jobs(cluster_id,workspace_id,id,required_origin_kind,required_origin_id,required_origin_hmac) ON DELETE RESTRICT,
 FOREIGN KEY(source_cluster_id,source_workspace_id,origin_id,cluster_id,workspace_id,comparison_id)
  REFERENCES governance_promotions(cluster_id,workspace_id,id,target_cluster_id,target_workspace_id,comparison_id) ON DELETE RESTRICT,
 FOREIGN KEY(source_cluster_id,source_workspace_id,comparison_id)
  REFERENCES governance_comparisons(cluster_id,workspace_id,id) ON DELETE RESTRICT
);
ALTER TABLE configuration_jobs ADD CONSTRAINT configuration_jobs_required_origin_fk
 FOREIGN KEY(cluster_id,workspace_id,id,required_origin_kind,required_origin_id,required_origin_hmac)
 REFERENCES configuration_job_origin_bindings(cluster_id,workspace_id,job_id,origin_kind,origin_id,material_hmac)
 ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE configuration_plan_origin_bindings (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,plan_id uuid NOT NULL,
 plan_revision integer NOT NULL CHECK(plan_revision>0),plan_hash text NOT NULL CHECK(m8_hex64(plan_hash)),
 job_id uuid NOT NULL,origin_kind text NOT NULL CHECK(origin_kind='governance-promote'),origin_id uuid NOT NULL,
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,plan_id,plan_revision,plan_hash),
 FOREIGN KEY(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,job_id)
  REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,source_job_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,job_id,origin_kind,origin_id,material_hmac)
  REFERENCES configuration_job_origin_bindings(cluster_id,workspace_id,job_id,origin_kind,origin_id,material_hmac) ON DELETE RESTRICT
);

CREATE FUNCTION m10_guard_configuration_origin_marker() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF ROW(NEW.required_origin_kind,NEW.required_origin_id,NEW.required_origin_hmac)
  IS DISTINCT FROM ROW(OLD.required_origin_kind,OLD.required_origin_id,OLD.required_origin_hmac)
 THEN RAISE EXCEPTION 'Configuration source origin is immutable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;$$;
CREATE TRIGGER configuration_jobs_origin_marker BEFORE UPDATE ON configuration_jobs
 FOR EACH ROW EXECUTE FUNCTION m10_guard_configuration_origin_marker();

CREATE FUNCTION m10_validate_configuration_origin_plan() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE j configuration_jobs%ROWTYPE;b configuration_plan_origin_bindings%ROWTYPE;
 BEGIN
 SELECT * INTO j FROM configuration_jobs WHERE id=NEW.source_job_id AND cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id;
 IF j.required_origin_kind IS NULL THEN
  IF EXISTS(SELECT 1 FROM configuration_plan_origin_bindings p WHERE p.cluster_id=NEW.cluster_id AND p.workspace_id=NEW.workspace_id
   AND p.plan_id=NEW.plan_id AND p.plan_revision=NEW.plan_revision AND p.plan_hash=NEW.plan_hash)
  THEN RAISE EXCEPTION 'Legacy plan cannot contain a forged source origin' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO b FROM configuration_plan_origin_bindings p WHERE p.cluster_id=NEW.cluster_id AND p.workspace_id=NEW.workspace_id
  AND p.plan_id=NEW.plan_id AND p.plan_revision=NEW.plan_revision AND p.plan_hash=NEW.plan_hash
  AND p.job_id=j.id AND p.origin_kind=j.required_origin_kind AND p.origin_id=j.required_origin_id AND p.material_hmac=j.required_origin_hmac;
 IF NOT FOUND THEN RAISE EXCEPTION 'Marked configuration plan requires its complete immutable origin binding' USING ERRCODE='23503';END IF;
 IF j.kind='import' AND NOT EXISTS(SELECT 1 FROM governance_promotions p WHERE p.id=b.origin_id AND p.target_cluster_id=j.cluster_id
  AND p.target_workspace_id=j.workspace_id AND p.configuration_job_id=j.id AND p.plan_id=b.plan_id
  AND p.plan_revision=b.plan_revision AND p.plan_hash=b.plan_hash AND p.state='ready')
 THEN RAISE EXCEPTION 'Initial Promote plan must atomically seal its actual governance result' USING ERRCODE='23503';END IF;
 RETURN NEW;
END;$$;
CREATE CONSTRAINT TRIGGER configuration_plan_versions_origin_complete AFTER INSERT ON configuration_plan_versions
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m10_validate_configuration_origin_plan();

-- Explicit sensitive Promote has a separate recoverable source snapshot. It
-- never turns ordinary sanitized governance inventory into secret material.
ALTER TABLE config_snapshot_versions ADD CONSTRAINT config_snapshot_versions_promote_recovery_unique
 UNIQUE(cluster_id,workspace_id,snapshot_id,version,manifest_hmac,source_job_id);
CREATE TABLE promotion_recovery_bindings (
 promotion_id uuid PRIMARY KEY,source_cluster_id uuid NOT NULL,source_workspace_id uuid NOT NULL,
 source_job_id uuid NOT NULL,snapshot_id uuid NOT NULL,snapshot_version integer NOT NULL CHECK(snapshot_version>0),
 manifest_hmac text NOT NULL CHECK(m8_hex64(manifest_hmac)),recovery_hmac text NOT NULL CHECK(m8_hex64(recovery_hmac)),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(source_cluster_id,source_workspace_id,promotion_id)
  REFERENCES governance_promotions(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(source_cluster_id,source_workspace_id,snapshot_id,snapshot_version,manifest_hmac,source_job_id)
  REFERENCES config_snapshot_versions(cluster_id,workspace_id,snapshot_id,version,manifest_hmac,source_job_id) ON DELETE RESTRICT
);
CREATE FUNCTION m10_validate_promotion_recovery_source() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF NOT EXISTS(SELECT 1 FROM governance_promotions p JOIN configuration_jobs j
  ON j.cluster_id=p.cluster_id AND j.workspace_id=p.workspace_id AND j.actor_id=p.actor_id
  JOIN config_snapshot_versions v ON v.cluster_id=j.cluster_id AND v.workspace_id=j.workspace_id AND v.source_job_id=j.id
  WHERE p.id=NEW.promotion_id AND p.cluster_id=NEW.source_cluster_id AND p.workspace_id=NEW.source_workspace_id
   AND p.state='planning' AND j.id=NEW.source_job_id AND j.kind='capture' AND j.origin_type='http'
   AND j.origin_session_id IS NOT NULL AND j.state='succeeded' AND j.safe_progress->>'snapshotId'=NEW.snapshot_id::text
   AND v.snapshot_id=NEW.snapshot_id AND v.version=NEW.snapshot_version AND v.manifest_hmac=NEW.manifest_hmac)
 THEN RAISE EXCEPTION 'Sensitive Promote requires its real owner-bound sealed source capture' USING ERRCODE='23503';END IF;
 RETURN NEW;
END;$$;
CREATE TRIGGER promotion_recovery_bindings_source BEFORE INSERT ON promotion_recovery_bindings
 FOR EACH ROW EXECUTE FUNCTION m10_validate_promotion_recovery_source();

DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['configuration_job_origin_bindings','configuration_plan_origin_bindings','promotion_recovery_bindings'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
END;$$;
