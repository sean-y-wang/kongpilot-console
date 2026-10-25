-- Console-owned telemetry metadata. No Kong database connection or native writes.
CREATE TABLE metrics_settings (
  cluster_id uuid PRIMARY KEY REFERENCES clusters(id) ON DELETE RESTRICT,
  active_source_id uuid,
  enabled boolean NOT NULL DEFAULT false,
  collector_enabled boolean NOT NULL DEFAULT false,
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  credential_generation integer NOT NULL DEFAULT 0 CHECK(credential_generation>=0),
  catalog_revision bigint NOT NULL DEFAULT 0 CHECK(catalog_revision>=0),
  catalog_status text NOT NULL DEFAULT 'uninitialized' CHECK(catalog_status IN ('uninitialized','ready','partial','stale','blocked','error')),
  last_verified_at timestamptz,
  max_age_ms integer NOT NULL DEFAULT 15000 CHECK(max_age_ms BETWEEN 1 AND 15000),
  safe_capabilities jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(safe_capabilities)='object'),
  created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(cluster_id,active_source_id) REFERENCES data_sources(cluster_id,id) ON DELETE RESTRICT
);
CREATE TABLE metrics_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
  purpose text NOT NULL CHECK(purpose IN ('native_scrape','collector_scrape','collector_catalog','collector_ingest')),
  audience text NOT NULL CHECK(audience IN ('bff','collector')),
  generation integer NOT NULL CHECK(generation>0),
  token_secret text NOT NULL CHECK(token_secret LIKE 'v1.%'),
  token_fingerprint text NOT NULL CHECK(token_fingerprint ~ '^[a-f0-9]{64}$'),
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),revoked_at timestamptz,retention_until timestamptz,
  CHECK((purpose IN ('native_scrape','collector_catalog') AND audience='bff') OR
    (purpose IN ('collector_scrape','collector_ingest') AND audience='collector')),
  CHECK((status='active' AND revoked_at IS NULL AND retention_until IS NULL) OR
    (status='revoked' AND revoked_at IS NOT NULL AND retention_until IS NOT NULL)),
  UNIQUE(cluster_id,id),UNIQUE(cluster_id,purpose,generation),UNIQUE(cluster_id,generation,token_fingerprint)
);
CREATE UNIQUE INDEX metrics_credentials_active ON metrics_credentials(cluster_id,purpose) WHERE status='active';
CREATE TABLE metrics_nodes (
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
  node_id text NOT NULL CHECK(node_id ~ '^[a-f0-9]{64}$'),
  transport_scope text NOT NULL CHECK(transport_scope ~ '^[a-f0-9]{64}$'),
  observed_kong_node_id text CHECK(length(observed_kong_node_id)<=256),
  last_seen_at timestamptz NOT NULL,status text NOT NULL DEFAULT 'verified' CHECK(status IN ('verified','stale','blocked')),
  created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(cluster_id,node_id),CHECK(node_id=transport_scope)
);
CREATE INDEX metrics_nodes_transport ON metrics_nodes(transport_scope,cluster_id);
CREATE TABLE metrics_assignment_epochs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,node_id text NOT NULL,
  entity_type text NOT NULL CHECK(entity_type IN ('services','routes','consumers')),entity_id uuid NOT NULL,
  workspace_id uuid NOT NULL,service_id uuid,route_id uuid,consumer_id uuid,
  business_tags text[] NOT NULL DEFAULT '{}',
  tags_fingerprint text NOT NULL CHECK(tags_fingerprint ~ '^[a-f0-9]{64}$'),
  config_fingerprint text NOT NULL CHECK(config_fingerprint ~ '^[a-f0-9]{64}$'),
  source_pair_hash text NOT NULL CHECK(source_pair_hash ~ '^[a-f0-9]{64}$'),
  service_label text CHECK(length(service_label)<=2048),route_label text CHECK(length(route_label)<=2048),
  valid_from timestamptz NOT NULL,last_verified_at timestamptz NOT NULL,verified_until timestamptz NOT NULL,
  closed_at timestamptz,close_reason text CHECK(length(close_reason)<=128),
  retention_until timestamptz,
  FOREIGN KEY(cluster_id,node_id) REFERENCES metrics_nodes(cluster_id,node_id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK((entity_type='services' AND entity_id=service_id AND route_id IS NULL AND consumer_id IS NULL AND service_label IS NOT NULL AND route_label IS NULL) OR
    (entity_type='routes' AND entity_id=route_id AND service_id IS NOT NULL AND consumer_id IS NULL AND service_label IS NOT NULL AND route_label IS NOT NULL) OR
    (entity_type='consumers' AND entity_id=consumer_id AND service_id IS NULL AND route_id IS NULL AND service_label IS NULL AND route_label IS NULL)),
  CHECK(last_verified_at>=valid_from AND verified_until>=last_verified_at AND verified_until<=last_verified_at+interval '15 seconds'),
  CHECK((closed_at IS NULL AND close_reason IS NULL AND retention_until IS NULL) OR
    (closed_at IS NOT NULL AND closed_at>=valid_from AND close_reason IS NOT NULL AND retention_until>=closed_at+interval '7 days'))
);
CREATE UNIQUE INDEX metrics_assignment_current ON metrics_assignment_epochs(cluster_id,node_id,entity_type,source_pair_hash) WHERE closed_at IS NULL;
CREATE INDEX metrics_assignment_identity ON metrics_assignment_epochs(cluster_id,entity_type,entity_id,valid_from DESC,id DESC);
CREATE INDEX metrics_assignment_scope ON metrics_assignment_epochs(cluster_id,workspace_id,closed_at,verified_until);
CREATE INDEX metrics_assignment_retention ON metrics_assignment_epochs(retention_until) WHERE closed_at IS NOT NULL;
-- Hashed source identities are diagnostics only. They never grant a series its attribution.
CREATE TABLE metrics_label_issues (
  cluster_id uuid NOT NULL,node_id text NOT NULL,entity_type text NOT NULL CHECK(entity_type IN ('services','routes','consumers')),
  source_pair_hash text NOT NULL CHECK(source_pair_hash ~ '^[a-f0-9]{64}$'),
  quality text NOT NULL CHECK(quality IN ('unknown','ambiguous')),reason_code text NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 128),
  last_verified_at timestamptz NOT NULL,verified_until timestamptz NOT NULL,
  PRIMARY KEY(cluster_id,node_id,entity_type,source_pair_hash),
  FOREIGN KEY(cluster_id,node_id) REFERENCES metrics_nodes(cluster_id,node_id) ON DELETE RESTRICT
);
CREATE INDEX metrics_label_issues_current ON metrics_label_issues(cluster_id,verified_until);
CREATE UNIQUE INDEX mutation_operations_cluster_id_id ON mutation_operations(cluster_id,id);
CREATE TABLE metrics_write_fences (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,
  transport_scope text NOT NULL CHECK(transport_scope ~ '^[a-f0-9]{64}$'),
  operation_id uuid NOT NULL,request_fingerprint text NOT NULL CHECK(request_fingerprint ~ '^[a-f0-9]{64}$'),
  entity_type text NOT NULL CHECK(length(entity_type) BETWEEN 1 AND 64),entity_id text CHECK(length(entity_id)<=256),
  method text NOT NULL CHECK(method IN ('POST','PUT','PATCH','DELETE')),path_hash text NOT NULL CHECK(path_hash ~ '^[a-f0-9]{64}$'),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','acknowledged','rejected','uncertain')),
  closed_count integer NOT NULL DEFAULT 0 CHECK(closed_count>=0),cluster_ids uuid[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),settled_at timestamptz,
  FOREIGN KEY(cluster_id,operation_id) REFERENCES mutation_operations(cluster_id,id) ON DELETE RESTRICT,
  UNIQUE(operation_id,request_fingerprint),CHECK((state='pending' AND settled_at IS NULL) OR(state<>'pending' AND settled_at IS NOT NULL))
);
CREATE INDEX metrics_write_fences_transport ON metrics_write_fences(transport_scope,operation_id);

CREATE FUNCTION metrics_epoch_immutable() RETURNS trigger LANGUAGE plpgsql AS $m5_epoch$
BEGIN
  IF TG_OP='DELETE' THEN
    IF OLD.closed_at IS NULL OR OLD.retention_until IS NULL OR OLD.retention_until>now() THEN
      RAISE EXCEPTION 'metric epoch cannot be deleted before its closed retention expires';
    END IF;
    RETURN OLD;
  END IF;
  IF ROW(NEW.id,NEW.cluster_id,NEW.node_id,NEW.entity_type,NEW.entity_id,NEW.workspace_id,NEW.service_id,NEW.route_id,
    NEW.consumer_id,NEW.business_tags,NEW.tags_fingerprint,NEW.config_fingerprint,NEW.source_pair_hash,NEW.service_label,NEW.route_label,NEW.valid_from)
    IS DISTINCT FROM ROW(OLD.id,OLD.cluster_id,OLD.node_id,OLD.entity_type,OLD.entity_id,OLD.workspace_id,OLD.service_id,OLD.route_id,
    OLD.consumer_id,OLD.business_tags,OLD.tags_fingerprint,OLD.config_fingerprint,OLD.source_pair_hash,OLD.service_label,OLD.route_label,OLD.valid_from) THEN
    RAISE EXCEPTION 'metric attribution identity and opened interval are immutable';
  END IF;
  IF OLD.closed_at IS NOT NULL AND ROW(NEW.closed_at,NEW.close_reason,NEW.retention_until,NEW.last_verified_at,NEW.verified_until)
    IS DISTINCT FROM ROW(OLD.closed_at,OLD.close_reason,OLD.retention_until,OLD.last_verified_at,OLD.verified_until) THEN
    RAISE EXCEPTION 'closed metric epoch cannot be changed or reopened';
  END IF;
  IF NEW.last_verified_at<OLD.last_verified_at OR NEW.verified_until<OLD.verified_until THEN
    RAISE EXCEPTION 'metric verification validity cannot move backwards';
  END IF;
  RETURN NEW;
END;
$m5_epoch$;
CREATE TRIGGER metrics_epoch_immutable_guard BEFORE UPDATE OR DELETE ON metrics_assignment_epochs FOR EACH ROW EXECUTE FUNCTION metrics_epoch_immutable();

CREATE FUNCTION metrics_credential_immutable() RETURNS trigger LANGUAGE plpgsql AS $m5_credential$
BEGIN
  IF TG_OP='DELETE' THEN
    IF OLD.status='active' OR OLD.retention_until>now() THEN RAISE EXCEPTION 'metric credential must be revoked and retained before deletion';END IF;
    RETURN OLD;
  END IF;
  IF ROW(NEW.id,NEW.cluster_id,NEW.purpose,NEW.audience,NEW.generation,NEW.token_secret,NEW.token_fingerprint,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.id,OLD.cluster_id,OLD.purpose,OLD.audience,OLD.generation,OLD.token_secret,OLD.token_fingerprint,OLD.created_at)
    OR OLD.status='revoked' AND ROW(NEW.status,NEW.revoked_at,NEW.retention_until) IS DISTINCT FROM ROW(OLD.status,OLD.revoked_at,OLD.retention_until) THEN
    RAISE EXCEPTION 'metric credential identity is immutable and revoked keys cannot reactivate';
  END IF;
  RETURN NEW;
END;
$m5_credential$;
CREATE TRIGGER metrics_credential_immutable_guard BEFORE UPDATE OR DELETE ON metrics_credentials FOR EACH ROW EXECUTE FUNCTION metrics_credential_immutable();

CREATE FUNCTION metrics_credential_family_complete() RETURNS trigger LANGUAGE plpgsql AS $m5_family$
DECLARE cid uuid; gen integer; active_count integer; wrong_generation integer;
BEGIN
  cid:=CASE WHEN TG_OP='DELETE' THEN OLD.cluster_id ELSE NEW.cluster_id END;
  SELECT credential_generation INTO gen FROM metrics_settings WHERE cluster_id=cid;
  SELECT count(*),count(*) FILTER(WHERE generation IS DISTINCT FROM gen) INTO active_count,wrong_generation
    FROM metrics_credentials WHERE cluster_id=cid AND status='active';
  IF(gen IS NULL AND active_count<>0) OR(gen=0 AND active_count<>0) OR(gen>0 AND(active_count<>4 OR wrong_generation<>0)) THEN
    RAISE EXCEPTION 'metric credential family must have four active keys in its current generation';
  END IF;
  RETURN NULL;
END;
$m5_family$;
CREATE CONSTRAINT TRIGGER metrics_credential_family_keys AFTER INSERT OR UPDATE OR DELETE ON metrics_credentials
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION metrics_credential_family_complete();
CREATE CONSTRAINT TRIGGER metrics_credential_family_settings AFTER INSERT OR UPDATE ON metrics_settings
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION metrics_credential_family_complete();

CREATE FUNCTION metrics_cluster_connection_invalidates() RETURNS trigger LANGUAGE plpgsql AS $m5_cluster$
BEGIN
  IF ROW(NEW.admin_url,NEW.transport_scope,NEW.connection_secret,NEW.version,NEW.deleted_at)
    IS DISTINCT FROM ROW(OLD.admin_url,OLD.transport_scope,OLD.connection_secret,OLD.version,OLD.deleted_at)
    OR(NEW.status IN ('disabled','incompatible')) IS DISTINCT FROM(OLD.status IN ('disabled','incompatible'))
    OR('prometheus'=ANY(NEW.enabled_plugins)) IS DISTINCT FROM('prometheus'=ANY(OLD.enabled_plugins)) THEN
    UPDATE metrics_assignment_epochs SET closed_at=GREATEST(now(),valid_from),close_reason='cluster_connection_changed',
      retention_until=GREATEST(now(),valid_from)+interval '8 days' WHERE cluster_id=NEW.id AND closed_at IS NULL;
    UPDATE metrics_nodes SET status='blocked' WHERE cluster_id=NEW.id;
    UPDATE metrics_label_issues SET verified_until=LEAST(verified_until,now()) WHERE cluster_id=NEW.id;
    UPDATE metrics_settings SET catalog_status='stale',catalog_revision=catalog_revision+1,updated_at=now() WHERE cluster_id=NEW.id;
  END IF;
  RETURN NEW;
END;
$m5_cluster$;
CREATE TRIGGER metrics_cluster_connection_guard AFTER UPDATE ON clusters FOR EACH ROW EXECUTE FUNCTION metrics_cluster_connection_invalidates();
