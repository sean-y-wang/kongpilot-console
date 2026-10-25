ALTER TABLE mutation_operations ADD COLUMN entity_type text NOT NULL DEFAULT 'unknown';
ALTER TABLE mutation_operations ADD COLUMN entity_id text;
ALTER TABLE mutation_operations ADD COLUMN before_secret text;
ALTER TABLE mutation_operations ADD COLUMN payload_secret text;
ALTER TABLE mutation_operations ADD COLUMN result_secret text;
ALTER TABLE mutation_operations ADD COLUMN remote_started boolean NOT NULL DEFAULT false;
ALTER TABLE mutation_operations ADD COLUMN remote_completed boolean NOT NULL DEFAULT false;
ALTER TABLE mutation_operations ADD COLUMN error_code text;

CREATE TABLE credential_refs (
  id uuid PRIMARY KEY,
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
  consumer_id uuid NOT NULL,
  credential_type text NOT NULL CHECK (credential_type IN ('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')),
  kong_id uuid NOT NULL,
  payload_secret text NOT NULL,
  masked_summary jsonb NOT NULL DEFAULT '{}',
  recovery_capability text NOT NULL,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,consumer_id,credential_type,kong_id)
);
CREATE INDEX credential_refs_consumer_index ON credential_refs(cluster_id,consumer_id,state);

CREATE TABLE recycle_entries (
  id uuid PRIMARY KEY,
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
  actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  root_type text NOT NULL,
  original_id text NOT NULL,
  root_name text NOT NULL,
  parent_id text,
  credential_kind text,
  state text NOT NULL DEFAULT 'archived' CHECK (state IN ('archived','deleting','deleted','partially_deleted','restoring','partially_restored','restored','purged')),
  node_count integer NOT NULL CHECK (node_count > 0),
  payload_secret text,
  mutation_id uuid REFERENCES mutation_operations(id) ON DELETE RESTRICT,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  restored_at timestamptz,
  purged_at timestamptz,
  UNIQUE(cluster_id,id),
  CHECK ((state='purged' AND payload_secret IS NULL AND purged_at IS NOT NULL) OR (state<>'purged' AND payload_secret IS NOT NULL))
);
CREATE INDEX recycle_entries_list_index ON recycle_entries(cluster_id,created_at DESC,id DESC) WHERE state <> 'purged';
CREATE INDEX recycle_entries_expiry_index ON recycle_entries(cluster_id,expires_at) WHERE state IN ('deleted','partially_deleted');

CREATE TABLE recycle_nodes (
  entry_id uuid NOT NULL REFERENCES recycle_entries(id) ON DELETE RESTRICT,
  node_key text NOT NULL,
  entity_type text NOT NULL,
  original_id text NOT NULL,
  affected boolean NOT NULL,
  dependencies text[] NOT NULL DEFAULT '{}',
  delete_state text NOT NULL DEFAULT 'pending' CHECK (delete_state IN ('pending','deleted','failed','uncertain','reference')),
  restore_state text NOT NULL DEFAULT 'pending' CHECK (restore_state IN ('pending','restored','failed','uncertain','reference')),
  restored_id text,
  safe_error text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(entry_id,node_key)
);
