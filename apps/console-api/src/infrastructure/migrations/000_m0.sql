CREATE TABLE users (
  id uuid PRIMARY KEY,
  username text NOT NULL UNIQUE,
  email text,
  password_hash text NOT NULL,
  super_admin boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  locked_until timestamptz,
  password_changed_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_username_lower_unique ON users(lower(username));

CREATE TABLE auth_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  refresh_token_hash text,
  csrf_token_hash text,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  ip text,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at)
);
CREATE INDEX auth_sessions_user_active ON auth_sessions(user_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE clusters (
  id uuid PRIMARY KEY,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  environment text NOT NULL DEFAULT 'default',
  admin_url text NOT NULL CHECK (admin_url ~ '^https?://'),
  labels text[] NOT NULL DEFAULT '{}',
  execution_mode text NOT NULL DEFAULT 'direct' CHECK (execution_mode IN ('direct', 'approval')),
  connection_secret text,
  status text NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'healthy', 'unhealthy', 'incompatible', 'disabled', 'probing')),
  version text,
  capabilities jsonb NOT NULL DEFAULT '{}',
  enabled_plugins text[] NOT NULL DEFAULT '{}',
  last_probed_at timestamptz,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revision integer NOT NULL DEFAULT 1 CHECK (revision > 0)
);
CREATE UNIQUE INDEX clusters_live_name_unique ON clusters(environment, lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX clusters_labels_index ON clusters USING gin(labels);
CREATE INDEX clusters_status_index ON clusters(status, created_at) WHERE deleted_at IS NULL;

CREATE TABLE cluster_probes (
  id uuid PRIMARY KEY,
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
  version text,
  adapter text,
  capabilities jsonb NOT NULL DEFAULT '{}',
  enabled_plugins text[] NOT NULL DEFAULT '{}',
  status text NOT NULL,
  latency_ms integer CHECK (latency_ms >= 0),
  error_code text,
  safe_error text,
  probed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cluster_probes_history ON cluster_probes(cluster_id, probed_at DESC);

CREATE TABLE data_sources (
  id uuid PRIMARY KEY,
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  type text NOT NULL CHECK (type IN ('prometheus', 'loki')),
  base_url text NOT NULL CHECK (base_url ~ '^https?://'),
  auth_secret text,
  enabled boolean NOT NULL DEFAULT true,
  last_status text NOT NULL DEFAULT 'unknown',
  last_probed_at timestamptz,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
  UNIQUE(cluster_id, id)
);
CREATE UNIQUE INDEX data_sources_live_name_unique ON data_sources(cluster_id, lower(name)) WHERE deleted_at IS NULL;
CREATE INDEX data_sources_cluster_index ON data_sources(cluster_id, created_at) WHERE deleted_at IS NULL;

CREATE TABLE data_source_probes (
  id uuid PRIMARY KEY,
  cluster_id uuid NOT NULL,
  data_source_id uuid NOT NULL,
  status text NOT NULL,
  latency_ms integer CHECK (latency_ms >= 0),
  safe_error text,
  probed_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (cluster_id, data_source_id) REFERENCES data_sources(cluster_id, id) ON DELETE RESTRICT
);
CREATE INDEX data_source_probes_history ON data_source_probes(cluster_id, data_source_id, probed_at DESC);

CREATE TABLE mutation_operations (
  id uuid PRIMARY KEY,
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
  actor_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  action text NOT NULL,
  idempotency_key text NOT NULL,
  request_hash text NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'running', 'succeeded', 'failed', 'uncertain', 'blocked')),
  workflow_id uuid,
  request_id text,
  safe_result jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id, idempotency_key)
);
CREATE INDEX mutation_operations_state_index ON mutation_operations(cluster_id, state, created_at);

CREATE TABLE audit_chain_heads (
  chain_scope text PRIMARY KEY,
  last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
  last_hash text NOT NULL DEFAULT 'GENESIS'
);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY,
  chain_scope text NOT NULL REFERENCES audit_chain_heads(chain_scope) ON DELETE RESTRICT,
  sequence bigint NOT NULL CHECK (sequence > 0),
  actor_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  actor_type text NOT NULL DEFAULT 'user',
  source_ip text,
  cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,
  workspace_id uuid,
  entity_type text NOT NULL,
  entity_id text,
  action text NOT NULL,
  before jsonb,
  after jsonb,
  json_patch jsonb NOT NULL DEFAULT '[]',
  workflow_id uuid,
  result text NOT NULL DEFAULT 'success',
  request_id text,
  prev_hash text NOT NULL,
  event_hash text NOT NULL CHECK (event_hash ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL,
  UNIQUE(chain_scope, sequence),
  UNIQUE(event_hash)
);
CREATE INDEX audit_events_cluster_time ON audit_events(cluster_id, occurred_at DESC);
CREATE INDEX audit_events_actor_time ON audit_events(actor_id, occurred_at DESC);
CREATE INDEX audit_events_entity_time ON audit_events(cluster_id, entity_type, entity_id, occurred_at DESC);

CREATE FUNCTION kongos_reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = '42501';
END;
$$;
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION kongos_reject_audit_mutation();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION kongos_reject_audit_mutation();
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC;
