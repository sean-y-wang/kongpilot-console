ALTER TABLE users ADD COLUMN display_name text NOT NULL DEFAULT '' CHECK(length(display_name)<=128);
ALTER TABLE users ADD COLUMN locale text NOT NULL DEFAULT 'zh-CN' CHECK(locale IN ('zh-CN','en-US'));
ALTER TABLE users ADD COLUMN timezone text NOT NULL DEFAULT 'UTC' CHECK(length(timezone) BETWEEN 1 AND 128);
ALTER TABLE users ADD COLUMN revision integer NOT NULL DEFAULT 1 CHECK(revision>0);
ALTER TABLE users ADD COLUMN permissions_epoch bigint NOT NULL DEFAULT 1 CHECK(permissions_epoch>0);
ALTER TABLE users ADD COLUMN credential_epoch bigint NOT NULL DEFAULT 1 CHECK(credential_epoch>0);
ALTER TABLE users ADD COLUMN force_password_change boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN auth_source text NOT NULL DEFAULT 'local' CHECK(auth_source IN ('local','ldap','oidc'));
ALTER TABLE users ADD COLUMN deleted_at timestamptz;
ALTER TABLE users ADD COLUMN retention_until timestamptz;
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check CHECK(status IN ('active','disabled','deleted'));
ALTER TABLE users ADD CONSTRAINT users_soft_state CHECK((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL)
  OR(status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL));
UPDATE users SET display_name=username;
CREATE INDEX users_directory ON users(status,created_at DESC,id DESC);

ALTER TABLE auth_sessions ADD COLUMN credential_epoch bigint NOT NULL DEFAULT 1 CHECK(credential_epoch>0);
ALTER TABLE auth_sessions ADD COLUMN family_id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE auth_sessions ADD COLUMN refresh_generation integer NOT NULL DEFAULT 0 CHECK(refresh_generation>=0);
CREATE INDEX auth_sessions_family ON auth_sessions(family_id) WHERE revoked_at IS NULL;
CREATE TABLE auth_refresh_history (
  session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
  token_hash text NOT NULL CHECK(token_hash ~ '^[a-f0-9]{64}$'),
  generation integer NOT NULL CHECK(generation>=0),
  used_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY(session_id,token_hash)
);
CREATE INDEX auth_refresh_history_expiry ON auth_refresh_history(expires_at);
CREATE TABLE auth_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  provider_type text NOT NULL CHECK(provider_type IN ('local','ldap','oidc')),
  provider_key text NOT NULL CHECK(length(provider_key) BETWEEN 1 AND 512),
  subject text NOT NULL CHECK(length(subject) BETWEEN 1 AND 1024),
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  revoked_at timestamptz,
  retention_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(provider_type,provider_key,subject),
  CHECK((status='active' AND revoked_at IS NULL AND retention_until IS NULL)
    OR(status='revoked' AND revoked_at IS NOT NULL AND retention_until IS NOT NULL))
);
CREATE INDEX auth_identities_user ON auth_identities(user_id,status);

CREATE TABLE iam_epoch (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO iam_epoch(singleton) VALUES(true);
CREATE TABLE teams (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text NOT NULL CHECK(code ~ '^[a-z][a-z0-9_-]{0,63}$'),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
  description text NOT NULL DEFAULT '' CHECK(length(description)<=8192),
  cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,
  workspace_id uuid,
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','deleted')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  deleted_at timestamptz,
  retention_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL)
    OR(status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE UNIQUE INDEX teams_code_scope ON teams(coalesce(cluster_id,'00000000-0000-0000-0000-000000000000'::uuid),coalesce(workspace_id,'00000000-0000-0000-0000-000000000000'::uuid),code);
CREATE INDEX teams_directory ON teams(cluster_id,workspace_id,status,created_at DESC,id DESC);
CREATE TABLE team_members (
  team_id uuid NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  joined_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  retention_until timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(team_id,user_id),
  CHECK((status='active' AND revoked_at IS NULL AND retention_until IS NULL)
    OR(status='revoked' AND revoked_at IS NOT NULL AND retention_until IS NOT NULL))
);
CREATE INDEX team_members_user ON team_members(user_id,team_id) WHERE status='active';
CREATE TABLE roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text NOT NULL CHECK(code ~ '^[a-z][a-z0-9_-]{0,63}$'),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
  description text NOT NULL DEFAULT '' CHECK(length(description)<=8192),
  cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,
  workspace_id uuid,
  builtin_kind text CHECK(builtin_kind IN ('super-admin','admin','read-only','workspace-super-admin','workspace-admin','workspace-read-only')),
  protected boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','deleted')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  deleted_at timestamptz,
  retention_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL),
  CHECK(protected=(builtin_kind IS NOT NULL)),
  CHECK(builtin_kind IS NULL OR builtin_kind=code),
  CHECK(builtin_kind IS NULL OR (builtin_kind IN ('super-admin','admin','read-only') AND cluster_id IS NULL AND workspace_id IS NULL)
    OR(builtin_kind IN ('workspace-super-admin','workspace-admin','workspace-read-only') AND cluster_id IS NOT NULL AND workspace_id IS NOT NULL)),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL)
    OR(status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE UNIQUE INDEX roles_code_scope ON roles(coalesce(cluster_id,'00000000-0000-0000-0000-000000000000'::uuid),coalesce(workspace_id,'00000000-0000-0000-0000-000000000000'::uuid),code);
CREATE INDEX roles_directory ON roles(cluster_id,workspace_id,status,created_at DESC,id DESC);
CREATE TABLE role_permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
  module text NOT NULL CHECK(module IN ('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','clusters','data-sources','workspaces','annotations','overview','mutations','recycle-bin','secrets','users','teams','roles','permissions','monitoring','portal','developers','applications','audit','events','notifications','snapshots','gitops','toolbox','batches','drafts','governance','lint','drift','promote','workflows')),
  action text NOT NULL CHECK(action IN ('read','write','delete','approve')),
  scope_type text NOT NULL CHECK(scope_type IN ('global','workspace','tag_group','entity')),
  cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,
  workspace_id uuid,
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  revoked_at timestamptz,
  retention_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK((scope_type='global' AND cluster_id IS NULL AND workspace_id IS NULL)
    OR(scope_type='workspace' AND cluster_id IS NOT NULL AND workspace_id IS NOT NULL)
    OR(scope_type IN ('tag_group','entity') AND cluster_id IS NOT NULL)),
  CHECK((status='active' AND revoked_at IS NULL AND retention_until IS NULL)
    OR(status='revoked' AND revoked_at IS NOT NULL AND retention_until IS NOT NULL))
);
CREATE INDEX role_permissions_role ON role_permissions(role_id) WHERE status='active';
CREATE TABLE role_permission_tags (
  permission_id uuid NOT NULL REFERENCES role_permissions(id) ON DELETE RESTRICT,
  logical_tag text NOT NULL CHECK(length(logical_tag) BETWEEN 1 AND 128 AND logical_tag NOT LIKE 'workspace:%'),
  physical_tag text NOT NULL CHECK(length(physical_tag) BETWEEN 1 AND 128 AND physical_tag ~ '^[A-Za-z0-9._~-]+$' AND physical_tag NOT LIKE 'kos-ws-%'),
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  revoked_at timestamptz,
  retention_until timestamptz,
  PRIMARY KEY(permission_id,physical_tag),
  CHECK((status='active' AND revoked_at IS NULL AND retention_until IS NULL)
    OR(status='revoked' AND revoked_at IS NOT NULL AND retention_until IS NOT NULL))
);
CREATE TABLE role_permission_entities (
  permission_id uuid NOT NULL REFERENCES role_permissions(id) ON DELETE RESTRICT,
  entity_type text NOT NULL CHECK(entity_type IN ('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','targets','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')),
  entity_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  revoked_at timestamptz,
  retention_until timestamptz,
  PRIMARY KEY(permission_id,entity_type,entity_id),
  CHECK((status='active' AND revoked_at IS NULL AND retention_until IS NULL)
    OR(status='revoked' AND revoked_at IS NOT NULL AND retention_until IS NOT NULL))
);
CREATE TABLE user_role_bindings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
  cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,
  workspace_id uuid,
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  expires_at timestamptz,
  granted_by uuid REFERENCES users(id) ON DELETE RESTRICT,
  revoked_at timestamptz,
  retention_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK((status='active' AND revoked_at IS NULL AND retention_until IS NULL)
    OR(status='revoked' AND revoked_at IS NOT NULL AND retention_until IS NOT NULL))
);
CREATE UNIQUE INDEX user_role_bindings_active ON user_role_bindings(user_id,role_id,coalesce(cluster_id,'00000000-0000-0000-0000-000000000000'::uuid),coalesce(workspace_id,'00000000-0000-0000-0000-000000000000'::uuid)) WHERE status='active';
CREATE INDEX user_role_bindings_user ON user_role_bindings(user_id,created_at DESC,id DESC);
CREATE TABLE auth_identity_bindings (
  identity_id uuid NOT NULL REFERENCES auth_identities(id) ON DELETE RESTRICT,
  binding_id uuid NOT NULL REFERENCES user_role_bindings(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(identity_id,binding_id)
);
CREATE TABLE team_role_bindings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
  cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,
  workspace_id uuid,
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  expires_at timestamptz,
  granted_by uuid REFERENCES users(id) ON DELETE RESTRICT,
  revoked_at timestamptz,
  retention_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK((status='active' AND revoked_at IS NULL AND retention_until IS NULL)
    OR(status='revoked' AND revoked_at IS NOT NULL AND retention_until IS NOT NULL))
);
CREATE UNIQUE INDEX team_role_bindings_active ON team_role_bindings(team_id,role_id,coalesce(cluster_id,'00000000-0000-0000-0000-000000000000'::uuid),coalesce(workspace_id,'00000000-0000-0000-0000-000000000000'::uuid)) WHERE status='active';
CREATE INDEX team_role_bindings_team ON team_role_bindings(team_id,created_at DESC,id DESC);

CREATE TABLE iam_operations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
  request_hash text NOT NULL CHECK(request_hash ~ '^[a-f0-9]{64}$'),
  module text NOT NULL,
  action text NOT NULL,
  target_id uuid,
  cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,
  workspace_id uuid,
  state text NOT NULL DEFAULT 'running' CHECK(state IN ('running','succeeded','failed','uncertain')),
  remote_completed boolean NOT NULL DEFAULT false,
  payload_secret text NOT NULL,
  result_secret text,
  safe_result jsonb,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(actor_id,idempotency_key),
  CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL),
  CHECK(state NOT IN ('running','uncertain') OR remote_completed=false),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT
);
CREATE INDEX iam_operations_actor ON iam_operations(actor_id,created_at DESC,id DESC);
ALTER TABLE mutation_operations ADD COLUMN transport_scope text CHECK(transport_scope IS NULL OR transport_scope ~ '^[a-f0-9]{64}$');
ALTER TABLE mutation_operations ADD COLUMN impact jsonb CHECK(impact IS NULL OR jsonb_typeof(impact)='object');
ALTER TABLE mutation_operations ADD COLUMN parent_id text;
ALTER TABLE mutation_operations ADD COLUMN credential_kind text CHECK(credential_kind IS NULL OR credential_kind IN ('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'));
ALTER TABLE clusters ADD COLUMN transport_scope text CHECK(transport_scope IS NULL OR transport_scope ~ '^[a-f0-9]{64}$');
CREATE INDEX mutation_operations_unresolved_transport ON mutation_operations(transport_scope,state) WHERE state IN ('running','uncertain');

CREATE FUNCTION iam_validate_role_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r roles%ROWTYPE;t teams%ROWTYPE;
BEGIN
  SELECT * INTO r FROM roles WHERE id=NEW.role_id;
  IF r.workspace_id IS NOT NULL AND (NEW.cluster_id IS DISTINCT FROM r.cluster_id OR NEW.workspace_id IS DISTINCT FROM r.workspace_id) THEN
    RAISE EXCEPTION 'workspace role binding must match its owner' USING ERRCODE='23514';
  END IF;
  IF TG_TABLE_NAME='team_role_bindings' THEN
    IF r.builtin_kind='super-admin' THEN RAISE EXCEPTION 'super-admin cannot be team-bound' USING ERRCODE='23514';END IF;
    SELECT * INTO t FROM teams WHERE id=NEW.team_id;
    IF (t.cluster_id IS NOT NULL AND NEW.cluster_id IS DISTINCT FROM t.cluster_id)
      OR(t.workspace_id IS NOT NULL AND NEW.workspace_id IS DISTINCT FROM t.workspace_id) THEN
      RAISE EXCEPTION 'team binding exceeds its owner scope' USING ERRCODE='23514';
    END IF;
  ELSIF r.builtin_kind='super-admin' AND (NEW.cluster_id IS NOT NULL OR NEW.workspace_id IS NOT NULL OR NEW.expires_at IS NOT NULL) THEN
    RAISE EXCEPTION 'super-admin binding must be platform-wide and durable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;$$;
CREATE TRIGGER user_role_bindings_scope BEFORE INSERT OR UPDATE ON user_role_bindings FOR EACH ROW EXECUTE FUNCTION iam_validate_role_scope();
CREATE TRIGGER team_role_bindings_scope BEFORE INSERT OR UPDATE ON team_role_bindings FOR EACH ROW EXECUTE FUNCTION iam_validate_role_scope();
CREATE FUNCTION iam_validate_permission_values() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p role_permissions%ROWTYPE;r roles%ROWTYPE;pid uuid;nt integer;ne integer;
BEGIN
  IF TG_TABLE_NAME='role_permissions' THEN pid=NEW.id;ELSE pid=NEW.permission_id;END IF;
  SELECT * INTO p FROM role_permissions WHERE id=pid;
  IF NOT FOUND OR p.status<>'active' THEN RETURN NULL;END IF;
  SELECT * INTO r FROM roles WHERE id=p.role_id;
  IF r.workspace_id IS NOT NULL AND (p.cluster_id IS DISTINCT FROM r.cluster_id OR p.workspace_id IS DISTINCT FROM r.workspace_id OR p.scope_type='global') THEN
    RAISE EXCEPTION 'workspace role permission exceeds its owner' USING ERRCODE='23514';
  END IF;
  SELECT count(*) INTO nt FROM role_permission_tags WHERE permission_id=pid AND status='active';
  SELECT count(*) INTO ne FROM role_permission_entities WHERE permission_id=pid AND status='active';
  IF (p.scope_type='tag_group' AND (nt=0 OR ne<>0)) OR(p.scope_type='entity' AND (ne=0 OR nt<>0))
    OR(p.scope_type IN ('global','workspace') AND (nt<>0 OR ne<>0)) THEN
    RAISE EXCEPTION 'permission values do not match the complete scope tuple' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER role_permissions_values AFTER INSERT OR UPDATE ON role_permissions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam_validate_permission_values();
CREATE CONSTRAINT TRIGGER role_permission_tags_values AFTER INSERT OR UPDATE ON role_permission_tags DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam_validate_permission_values();
CREATE CONSTRAINT TRIGGER role_permission_entities_values AFTER INSERT OR UPDATE ON role_permission_entities DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam_validate_permission_values();

CREATE FUNCTION iam_bump_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE iam_epoch SET version=version+1,updated_at=now() WHERE singleton;
  RETURN NULL;
END;$$;
DO $$DECLARE tab text;BEGIN
  FOREACH tab IN ARRAY ARRAY['teams','team_members','roles','role_permissions','role_permission_tags','role_permission_entities','user_role_bindings','team_role_bindings','auth_identities'] LOOP
    EXECUTE format('CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH STATEMENT EXECUTE FUNCTION iam_bump_epoch()',tab||'_epoch',tab);
  END LOOP;
END;$$;
CREATE TRIGGER users_iam_epoch AFTER UPDATE OF status,super_admin,permissions_epoch ON users FOR EACH STATEMENT EXECUTE FUNCTION iam_bump_epoch();

CREATE VIEW iam_effective_grants AS
WITH bindings AS (
  SELECT id AS binding_id,user_id,role_id,cluster_id,workspace_id,'user'::text AS binding_source FROM user_role_bindings
    WHERE status='active' AND(expires_at IS NULL OR expires_at>now())
  UNION ALL
  SELECT b.id,m.user_id,b.role_id,b.cluster_id,b.workspace_id,'team'::text FROM team_role_bindings b
    JOIN teams t ON t.id=b.team_id AND t.status='active'
    JOIN team_members m ON m.team_id=t.id AND m.status='active'
    WHERE b.status='active' AND(b.expires_at IS NULL OR b.expires_at>now())
), valued_permissions AS (
  SELECT p.*,CASE p.scope_type
    WHEN 'tag_group' THEN coalesce((SELECT jsonb_agg(v.physical_tag ORDER BY v.physical_tag) FROM role_permission_tags v WHERE v.permission_id=p.id AND v.status='active'),'[]'::jsonb)
    WHEN 'entity' THEN coalesce((SELECT jsonb_agg(jsonb_build_object('entity_type',v.entity_type,'entity_id',v.entity_id) ORDER BY v.entity_type,v.entity_id) FROM role_permission_entities v WHERE v.permission_id=p.id AND v.status='active'),'[]'::jsonb)
    WHEN 'workspace' THEN jsonb_build_array(p.workspace_id)
    ELSE '[]'::jsonb END AS scope_values FROM role_permissions p WHERE p.status='active'
)
SELECT u.id AS user_id,r.id AS role_id,r.code AS role_code,p.id AS permission_id,b.binding_id,b.binding_source,
  coalesce(p.cluster_id,b.cluster_id,r.cluster_id) AS cluster_id,coalesce(p.workspace_id,b.workspace_id,r.workspace_id) AS workspace_id,
  p.module,p.action,p.scope_type,p.scope_values
FROM bindings b JOIN users u ON u.id=b.user_id AND u.status='active'
  JOIN roles r ON r.id=b.role_id AND r.status='active' JOIN valued_permissions p ON p.role_id=r.id
WHERE(p.cluster_id IS NULL OR b.cluster_id IS NULL OR p.cluster_id=b.cluster_id)
  AND(r.cluster_id IS NULL OR b.cluster_id IS NULL OR r.cluster_id=b.cluster_id)
  AND(r.cluster_id IS NULL OR p.cluster_id IS NULL OR r.cluster_id=p.cluster_id)
  AND(p.workspace_id IS NULL OR b.workspace_id IS NULL OR p.workspace_id=b.workspace_id)
  AND(r.workspace_id IS NULL OR b.workspace_id IS NULL OR r.workspace_id=b.workspace_id)
  AND(r.workspace_id IS NULL OR p.workspace_id IS NULL OR r.workspace_id=p.workspace_id)
  AND(p.scope_type NOT IN ('tag_group','entity') OR jsonb_array_length(p.scope_values)>0);

CREATE FUNCTION iam_seed_roles(cid uuid,wid uuid) RETURNS void LANGUAGE plpgsql AS $$
DECLARE item text;rid uuid;mod text;act text;mods text[]:=ARRAY['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','clusters','data-sources','workspaces','annotations','overview','mutations','recycle-bin','secrets','users','teams','roles','permissions','monitoring','portal','developers','applications','audit','events','notifications','snapshots','gitops','toolbox','batches','drafts','governance','lint','drift','promote','workflows'];
BEGIN
  FOREACH item IN ARRAY CASE WHEN wid IS NULL THEN ARRAY['super-admin','admin','read-only'] ELSE ARRAY['workspace-super-admin','workspace-admin','workspace-read-only'] END LOOP
    INSERT INTO roles(code,name,cluster_id,workspace_id,builtin_kind,protected) VALUES(item,item,cid,wid,item,true) RETURNING id INTO rid;
    FOREACH mod IN ARRAY mods LOOP
      IF wid IS NOT NULL AND mod IN ('clusters','data-sources','users') THEN CONTINUE;END IF;
      IF item IN ('read-only','workspace-read-only') AND mod='secrets' THEN CONTINUE;END IF;
      IF item IN ('admin','workspace-admin') AND mod='secrets' THEN CONTINUE;END IF;
      FOREACH act IN ARRAY ARRAY['read','write','delete','approve'] LOOP
        IF item IN ('read-only','workspace-read-only') AND act<>'read' THEN CONTINUE;END IF;
        IF mod='secrets' AND act<>'read' THEN CONTINUE;END IF;
        IF item IN ('admin','workspace-admin') AND act='approve' THEN CONTINUE;END IF;
        INSERT INTO role_permissions(role_id,module,action,scope_type,cluster_id,workspace_id)
          VALUES(rid,mod,act,CASE WHEN wid IS NULL THEN 'global' ELSE 'workspace' END,cid,wid);
      END LOOP;
    END LOOP;
  END LOOP;
END;$$;
SELECT iam_seed_roles(NULL,NULL);
SELECT iam_seed_roles(cluster_id,id) FROM workspaces;
INSERT INTO user_role_bindings(user_id,role_id,granted_by)
  SELECT u.id,r.id,u.id FROM users u CROSS JOIN roles r WHERE u.super_admin AND r.builtin_kind='super-admin';
CREATE FUNCTION iam_seed_new_workspace_roles() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM iam_seed_roles(NEW.cluster_id,NEW.id);RETURN NEW;END;$$;
CREATE TRIGGER workspaces_iam_roles AFTER INSERT ON workspaces FOR EACH ROW EXECUTE FUNCTION iam_seed_new_workspace_roles();
CREATE FUNCTION iam_bind_bootstrap_admin() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.super_admin THEN
    INSERT INTO user_role_bindings(user_id,role_id,granted_by)
      SELECT NEW.id,id,NEW.id FROM roles WHERE builtin_kind='super-admin';
  END IF;
  RETURN NEW;
END;$$;
CREATE TRIGGER users_bootstrap_super_role AFTER INSERT ON users FOR EACH ROW EXECUTE FUNCTION iam_bind_bootstrap_admin();
CREATE FUNCTION iam_reject_physical_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'IAM resources must be soft-deleted or revoked' USING ERRCODE='42501';END;$$;
DO $$DECLARE tab text;BEGIN
  FOREACH tab IN ARRAY ARRAY['users','teams','team_members','roles','role_permissions','role_permission_tags','role_permission_entities','user_role_bindings','team_role_bindings','auth_identities'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE DELETE ON %I FOR EACH ROW EXECUTE FUNCTION iam_reject_physical_delete()',tab||'_soft_delete_only',tab);
  END LOOP;
END;$$;
