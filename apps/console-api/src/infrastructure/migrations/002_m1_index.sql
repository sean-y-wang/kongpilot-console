CREATE TABLE entity_index (
 cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
 entity_type text NOT NULL CHECK(entity_type IN ('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis')),
 kong_id text NOT NULL,
 name text NOT NULL DEFAULT '',
 tags text[] NOT NULL DEFAULT '{}',
 document jsonb NOT NULL,
 content_hash text NOT NULL,
 kong_created_at bigint NOT NULL DEFAULT 0,
 observed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,entity_type,kong_id)
);
CREATE INDEX entity_index_name ON entity_index(cluster_id,entity_type,name,kong_id);
CREATE INDEX entity_index_created ON entity_index(cluster_id,entity_type,kong_created_at,kong_id);
CREATE INDEX entity_index_tags ON entity_index USING gin(tags);
CREATE TABLE index_sync_state (
 cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
 entity_type text NOT NULL,
 cursor text,
 started_at timestamptz,
 completed_at timestamptz,
 last_run_at timestamptz,
 last_error text,
 PRIMARY KEY(cluster_id,entity_type)
);
