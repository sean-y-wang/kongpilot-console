CREATE TABLE workspaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
  code text NOT NULL CHECK (code ~ '^[a-z][a-z0-9_-]{0,47}$'),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  owner_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  description text NOT NULL DEFAULT '' CHECK (length(description) <= 8192),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','deleted')),
  is_default boolean NOT NULL DEFAULT false,
  revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
  deleted_at timestamptz,
  retention_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,id),
  UNIQUE(cluster_id,code),
  CHECK (is_default = (code='default')),
  CHECK (NOT is_default OR (status='active' AND deleted_at IS NULL)),
  CHECK ((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL)
    OR (status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE UNIQUE INDEX workspaces_one_default ON workspaces(cluster_id) WHERE is_default;
CREATE INDEX workspaces_list ON workspaces(cluster_id,status,created_at DESC,id DESC);
INSERT INTO workspaces(cluster_id,code,name,is_default)
  SELECT id,'default','默认工作区',true FROM clusters WHERE deleted_at IS NULL;

CREATE TABLE entity_annotations (
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
  entity_type text NOT NULL CHECK (entity_type IN ('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis')),
  kong_id uuid NOT NULL,
  description text NOT NULL DEFAULT '' CHECK (length(description) <= 8192),
  owner_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  metadata jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(metadata)='object'),
  revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','deleted')),
  deleted_at timestamptz,
  retention_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(cluster_id,entity_type,kong_id),
  CHECK ((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL)
    OR (status='active' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE INDEX entity_annotations_owner ON entity_annotations(cluster_id,owner_user_id,entity_type) WHERE status='active';

ALTER TABLE mutation_operations ADD CONSTRAINT mutation_operations_cluster_id_id_unique UNIQUE(cluster_id,id);
ALTER TABLE mutation_operations ADD COLUMN workspace_id uuid;
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_operations_workspace_fk
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT;
CREATE INDEX mutation_operations_workspace ON mutation_operations(cluster_id,workspace_id,created_at DESC,id DESC);
ALTER TABLE recycle_entries ADD COLUMN workspace_id uuid;
ALTER TABLE recycle_entries ADD CONSTRAINT recycle_entries_workspace_fk
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT;
CREATE INDEX recycle_entries_workspace ON recycle_entries(cluster_id,workspace_id,created_at DESC,id DESC) WHERE state<>'purged';
-- Existing encrypted legacy archives/operations remain NULL until their actual root is classified.
-- Old immutable audit rows are deliberately never rewritten.
ALTER TABLE audit_events ADD CONSTRAINT audit_events_workspace_fk
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_workspace_requires_cluster
  CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL);
CREATE INDEX audit_events_workspace ON audit_events(cluster_id,workspace_id,occurred_at DESC);

CREATE TABLE workspace_migration_plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
  actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  source_workspace_id uuid,
  target_workspace_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'planned' CHECK (state IN ('planned','running','partial','succeeded','failed','expired')),
  plan_hash text NOT NULL CHECK (plan_hash ~ '^[a-f0-9]{64}$'),
  payload_secret text NOT NULL,
  steps jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(steps)='array'),
  operation_id uuid,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,id),
  FOREIGN KEY(cluster_id,source_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,target_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,operation_id) REFERENCES mutation_operations(cluster_id,id) ON DELETE RESTRICT
);
CREATE INDEX workspace_migration_plans_actor ON workspace_migration_plans(cluster_id,actor_id,created_at DESC,id DESC);
CREATE INDEX workspace_migration_plans_state ON workspace_migration_plans(cluster_id,state,expires_at);

-- Progress is normalized so each applied object updates one row instead of rewriting
-- a potentially 10,000-object JSON array. The plan payload remains encrypted.
CREATE TABLE workspace_migration_steps (
  cluster_id uuid NOT NULL,
  plan_id uuid NOT NULL,
  object_key text NOT NULL CHECK (length(object_key) BETWEEN 1 AND 2048),
  type text NOT NULL CHECK (type IN ('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis',
    'targets','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')),
  kong_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','succeeded','failed','uncertain')),
  after_fingerprint text CHECK (after_fingerprint IS NULL OR after_fingerprint ~ '^[a-f0-9]{64}$'),
  error_code text CHECK (error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(cluster_id,plan_id,object_key),
  FOREIGN KEY(cluster_id,plan_id) REFERENCES workspace_migration_plans(cluster_id,id) ON DELETE RESTRICT
);
CREATE INDEX workspace_migration_steps_status ON workspace_migration_steps(cluster_id,plan_id,status);
