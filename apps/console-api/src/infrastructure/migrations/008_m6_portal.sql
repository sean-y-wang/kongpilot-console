-- M6 independent developer portal and durable single-level workflow foundation.
-- CID aliases never transfer historical native ownership: transport_scope is captured.
-- Existing 000--007 are intentionally unchanged. All circular FK are deferred.

CREATE FUNCTION m6_encrypted(value text, max_bytes integer DEFAULT 3145728)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT value IS NOT NULL AND octet_length(value) <= max_bytes
    AND value ~ '^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]+$';
$$;

CREATE FUNCTION m6_native_request_manifest(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE item jsonb; field text;
BEGIN
  IF value IS NULL OR jsonb_typeof(value)<>'array' OR jsonb_array_length(value)>32
    OR octet_length(value::text)>131072 THEN RETURN false; END IF;
  FOR item IN SELECT v FROM jsonb_array_elements(value) AS e(v) LOOP
    IF jsonb_typeof(item)<>'object' THEN RETURN false; END IF;
    FOR field IN SELECT jsonb_object_keys(item) LOOP
      IF field NOT IN ('method','path_hash','native_type','native_id','parent_id','credential_kind','body_hmac','before_hmac') THEN RETURN false; END IF;
    END LOOP;
    FOREACH field IN ARRAY ARRAY['method','path_hash','native_type','body_hmac'] LOOP
      IF jsonb_typeof(item->field) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
    END LOOP;
    IF NOT (item ?& ARRAY['method','path_hash','native_type','body_hmac'])
      OR coalesce(item->>'method','') NOT IN ('POST','PUT','PATCH','DELETE')
      OR coalesce(item->>'native_type','') NOT IN ('services','routes','consumers','plugins','upstreams','targets','certificates','ca_certificates','snis','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')
      OR coalesce(item->>'path_hash','') !~ '^[a-f0-9]{64}$'
      OR coalesce(item->>'body_hmac','') !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
    FOREACH field IN ARRAY ARRAY['native_id','parent_id'] LOOP
      IF item ? field AND item->field<>'null'::jsonb AND coalesce(item->>field,'') !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' THEN RETURN false; END IF;
    END LOOP;
    IF item ? 'before_hmac' AND item->'before_hmac'<>'null'::jsonb AND coalesce(item->>'before_hmac','') !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
    IF item ? 'credential_kind' AND item->'credential_kind'<>'null'::jsonb AND coalesce(item->>'credential_kind','') NOT IN ('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls') THEN RETURN false; END IF;
  END LOOP;
  RETURN true;
END;
$$;

CREATE FUNCTION m6_portal_branding(value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE field text;item jsonb;
BEGIN
  IF value IS NULL OR jsonb_typeof(value)<>'object' OR octet_length(value::text)>8192 THEN RETURN false;END IF;
  FOR field,item IN SELECT * FROM jsonb_each(value) LOOP
    IF field NOT IN ('primaryColor','logoText','welcomeText') OR jsonb_typeof(item)<>'string' OR length(item#>>'{}')>1024 THEN RETURN false;END IF;
    IF field='primaryColor' AND (item#>>'{}') !~ '^#[A-Fa-f0-9]{6}$' THEN RETURN false;END IF;
    IF (item#>>'{}') ~ '[<>]' OR (item#>>'{}') ~* '(javascript|data)[[:space:]]*:' THEN RETURN false;END IF;
  END LOOP;
  RETURN true;
END;
$$;

CREATE TABLE portal_settings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  slug text NOT NULL CHECK(slug ~ '^[a-z0-9][a-z0-9-]{0,79}$'),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
  description text NOT NULL DEFAULT '' CHECK(length(description)<=8192),
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','deleted')),
  published boolean NOT NULL DEFAULT false,
  registration_enabled boolean NOT NULL DEFAULT false,
  public_proxy_origin text CHECK(public_proxy_origin IS NULL OR (length(public_proxy_origin)<=2048 AND public_proxy_origin ~ '^https?://[^/@?#[:space:]]+/?$')),
  branding jsonb NOT NULL DEFAULT '{}' CHECK(m6_portal_branding(branding)),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  retention_until timestamptz,
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(cluster_id,workspace_id),
  UNIQUE(slug),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK(updated_at>=created_at),
  CHECK((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL AND retention_until>=deleted_at AND NOT published)
    OR(status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE INDEX portal_settings_public_tenants ON portal_settings(created_at DESC,id DESC) WHERE status='active' AND published;

CREATE TABLE portal_developers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  username text NOT NULL CHECK(username ~ '^[a-z0-9._-]{3,64}$'),
  email text NOT NULL CHECK(length(email) BETWEEN 3 AND 254 AND email=lower(email) AND email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'),
  display_name text NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
  password_hash text NOT NULL CHECK(password_hash ~ '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$'),
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','disabled','rejected','deleted')),
  credential_epoch bigint NOT NULL DEFAULT 1 CHECK(credential_epoch>0),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  failed_attempts integer NOT NULL DEFAULT 0 CHECK(failed_attempts>=0),
  locked_until timestamptz,
  must_change_password boolean NOT NULL DEFAULT false,
  reviewed_by uuid REFERENCES users(id) ON DELETE RESTRICT,
  reviewed_at timestamptz,
  review_reason text NOT NULL DEFAULT '' CHECK(length(review_reason)<=2048),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  retention_until timestamptz,
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(cluster_id,workspace_id,username),
  UNIQUE(cluster_id,workspace_id,email),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK((reviewed_by IS NULL)=(reviewed_at IS NULL)),
  CHECK(updated_at>=created_at),
  CHECK((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL AND retention_until>=deleted_at)
    OR(status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE INDEX portal_developers_directory ON portal_developers(cluster_id,workspace_id,status,created_at DESC,id DESC);

CREATE TABLE portal_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  developer_id uuid NOT NULL,
  family_id uuid NOT NULL,
  credential_epoch bigint NOT NULL CHECK(credential_epoch>0),
  refresh_token_hash text NOT NULL CHECK(refresh_token_hash ~ '^[a-f0-9]{64}$'),
  csrf_token_hash text NOT NULL CHECK(csrf_token_hash ~ '^[a-f0-9]{64}$'),
  refresh_generation integer NOT NULL DEFAULT 0 CHECK(refresh_generation>=0),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  ip text CHECK(ip IS NULL OR length(ip)<=128),
  user_agent text CHECK(user_agent IS NULL OR length(user_agent)<=1024),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,workspace_id,id),
  FOREIGN KEY(cluster_id,workspace_id,developer_id) REFERENCES portal_developers(cluster_id,workspace_id,id) ON DELETE RESTRICT,
  CHECK(expires_at>created_at AND updated_at>=created_at),
  CHECK(revoked_at IS NULL OR revoked_at>=created_at)
);
CREATE INDEX portal_sessions_active_developer ON portal_sessions(cluster_id,workspace_id,developer_id,expires_at) WHERE revoked_at IS NULL;
CREATE INDEX portal_sessions_family ON portal_sessions(cluster_id,workspace_id,developer_id,family_id);

CREATE TABLE portal_refresh_history (
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  session_id uuid NOT NULL,
  token_hash text NOT NULL CHECK(token_hash ~ '^[a-f0-9]{64}$'),
  generation integer NOT NULL CHECK(generation>=0),
  used_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY(session_id,token_hash),
  UNIQUE(session_id,generation),
  FOREIGN KEY(cluster_id,workspace_id,session_id) REFERENCES portal_sessions(cluster_id,workspace_id,id) ON DELETE RESTRICT,
  CHECK(expires_at>used_at)
);
CREATE INDEX portal_refresh_history_expiry ON portal_refresh_history(expires_at);

CREATE TABLE portal_applications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  developer_id uuid NOT NULL,
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
  description text NOT NULL DEFAULT '' CHECK(length(description)<=8192),
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','deleted')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  retention_until timestamptz,
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(cluster_id,workspace_id,id,developer_id),
  UNIQUE(cluster_id,workspace_id,developer_id,name),
  FOREIGN KEY(cluster_id,workspace_id,developer_id) REFERENCES portal_developers(cluster_id,workspace_id,id) ON DELETE RESTRICT,
  CHECK(updated_at>=created_at),
  CHECK((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL AND retention_until>=deleted_at)
    OR(status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE INDEX portal_applications_owner ON portal_applications(cluster_id,workspace_id,developer_id,status,created_at DESC,id DESC);

CREATE TABLE portal_publications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  transport_scope text NOT NULL CHECK(transport_scope ~ '^[a-f0-9]{64}$'),
  slug text NOT NULL CHECK(slug ~ '^[a-z0-9][a-z0-9-]{0,79}$'),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
  description text NOT NULL DEFAULT '' CHECK(length(description)<=8192),
  category text CHECK(category IS NULL OR length(category)<=128),
  service_id uuid NOT NULL,
  acl_group text NOT NULL,
  key_auth_plugin_id uuid,
  acl_plugin_id uuid,
  current_revision integer NOT NULL DEFAULT 1 CHECK(current_revision>0),
  published_revision integer CHECK(published_revision IS NULL OR published_revision>0),
  workflow_id uuid,
  state text NOT NULL DEFAULT 'draft' CHECK(state IN ('draft','pending','published','suspended','deleted')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  updated_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  retention_until timestamptz,
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(cluster_id,workspace_id,id,acl_group,transport_scope),
  UNIQUE(cluster_id,workspace_id,id,transport_scope),
  UNIQUE(cluster_id,workspace_id,id,service_id),
  UNIQUE(cluster_id,workspace_id,slug),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK(acl_group='kos-portal-api-'||id::text),
  CHECK(published_revision IS NULL OR published_revision<=current_revision),
  CHECK(state<>'published' OR (published_revision IS NOT NULL AND key_auth_plugin_id IS NOT NULL AND acl_plugin_id IS NOT NULL)),
  CHECK(key_auth_plugin_id IS NULL OR acl_plugin_id IS NULL OR key_auth_plugin_id<>acl_plugin_id),
  CHECK(updated_at>=created_at),
  CHECK((state='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL AND retention_until>=deleted_at AND published_revision IS NULL)
    OR(state<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE UNIQUE INDEX portal_publications_live_service ON portal_publications(cluster_id,workspace_id,service_id) WHERE state<>'deleted';
CREATE UNIQUE INDEX portal_publications_physical_service ON portal_publications(transport_scope,service_id) WHERE state<>'deleted';
CREATE INDEX portal_publications_directory ON portal_publications(cluster_id,workspace_id,state,created_at DESC,id DESC);

CREATE TABLE portal_publication_revisions (
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  publication_id uuid NOT NULL,
  revision integer NOT NULL CHECK(revision>0),
  service_id uuid NOT NULL,
  title text NOT NULL CHECK(length(title) BETWEEN 1 AND 128),
  version_label text NOT NULL CHECK(length(version_label) BETWEEN 1 AND 64),
  description text NOT NULL DEFAULT '' CHECK(length(description)<=8192),
  categories text[] NOT NULL DEFAULT '{}' CHECK(cardinality(categories)<=20 AND coalesce(array_ndims(categories),1)=1 AND array_position(categories,NULL) IS NULL),
  openapi_document jsonb NOT NULL CHECK(jsonb_typeof(openapi_document)='object' AND octet_length(openapi_document::text)<=3145728),
  document_hash text NOT NULL CHECK(document_hash ~ '^[a-f0-9]{64}$'),
  source_secret text CHECK(source_secret IS NULL OR m6_encrypted(source_secret,4194304)),
  validation_report jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(validation_report)='object' AND octet_length(validation_report::text)<=65536),
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(cluster_id,workspace_id,publication_id,revision),
  FOREIGN KEY(cluster_id,workspace_id,publication_id,service_id) REFERENCES portal_publications(cluster_id,workspace_id,id,service_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE portal_content (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  slug text NOT NULL CHECK(slug ~ '^[a-z0-9][a-z0-9-]{0,79}$'),
  title text NOT NULL CHECK(length(title) BETWEEN 1 AND 128),
  current_revision integer NOT NULL DEFAULT 1 CHECK(current_revision>0),
  published_revision integer CHECK(published_revision IS NULL OR published_revision>0),
  workflow_id uuid,
  state text NOT NULL DEFAULT 'draft' CHECK(state IN ('draft','published','deleted')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  updated_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  retention_until timestamptz,
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(cluster_id,workspace_id,slug),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK(published_revision IS NULL OR published_revision<=current_revision),
  CHECK(state<>'published' OR published_revision IS NOT NULL),
  CHECK(updated_at>=created_at),
  CHECK((state='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL AND retention_until>=deleted_at AND published_revision IS NULL)
    OR(state<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE INDEX portal_content_directory ON portal_content(cluster_id,workspace_id,state,created_at DESC,id DESC);

CREATE TABLE portal_content_revisions (
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  content_id uuid NOT NULL,
  revision integer NOT NULL CHECK(revision>0),
  title text NOT NULL CHECK(length(title) BETWEEN 1 AND 128),
  markdown text NOT NULL CHECK(octet_length(markdown)<=262144),
  content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(cluster_id,workspace_id,content_id,revision),
  FOREIGN KEY(cluster_id,workspace_id,content_id) REFERENCES portal_content(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE workflow_definitions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  code text NOT NULL CHECK(code ~ '^[a-z][a-z0-9-]{0,79}$'),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
  kind text NOT NULL CHECK(kind IN ('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change')),
  current_version integer NOT NULL DEFAULT 1 CHECK(current_version>0),
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','deleted')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  retention_until timestamptz,
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(cluster_id,workspace_id,id,kind),
  UNIQUE(cluster_id,workspace_id,code),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  CHECK(updated_at>=created_at),
  CHECK((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL AND retention_until>=deleted_at)
    OR(status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE INDEX workflow_definitions_directory ON workflow_definitions(cluster_id,workspace_id,status,created_at DESC,id DESC);

CREATE TABLE workflow_definition_versions (
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  definition_id uuid NOT NULL,
  version integer NOT NULL CHECK(version>0),
  mode text NOT NULL DEFAULT 'single' CHECK(mode IN ('single','multi','quorum') AND mode='single'),
  allow_self_approval boolean NOT NULL DEFAULT false CHECK(NOT allow_self_approval),
  policy jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(policy)='object' AND octet_length(policy::text)<=65536),
  policy_hash text NOT NULL CHECK(policy_hash ~ '^[a-f0-9]{64}$'),
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(cluster_id,workspace_id,definition_id,version),
  FOREIGN KEY(cluster_id,workspace_id,definition_id) REFERENCES workflow_definitions(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE workflow_definition_stages (
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  definition_id uuid NOT NULL,
  definition_version integer NOT NULL CHECK(definition_version>0),
  level integer NOT NULL CHECK(level=1),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
  required_approvals integer NOT NULL DEFAULT 1 CHECK(required_approvals=1),
  approver_module text NOT NULL DEFAULT 'workflows' CHECK(approver_module='workflows'),
  approver_action text NOT NULL DEFAULT 'approve' CHECK(approver_action='approve'),
  selector jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(selector)='object' AND octet_length(selector::text)<=65536),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(cluster_id,workspace_id,definition_id,definition_version,level),
  FOREIGN KEY(cluster_id,workspace_id,definition_id,definition_version) REFERENCES workflow_definition_versions(cluster_id,workspace_id,definition_id,version) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE workflows (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  kind text NOT NULL CHECK(kind IN ('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change')),
  subject_type text NOT NULL CHECK(subject_type IN ('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants')),
  subject_id uuid NOT NULL,
  requester_type text NOT NULL CHECK(requester_type IN ('developer','console')),
  requester_developer_id uuid,
  requester_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  definition_id uuid NOT NULL,
  definition_version integer NOT NULL CHECK(definition_version>0),
  plan_revision integer NOT NULL DEFAULT 1 CHECK(plan_revision>0),
  plan_hash text NOT NULL CHECK(plan_hash ~ '^[a-f0-9]{64}$'),
  execution_mode text NOT NULL CHECK(execution_mode IN ('direct','approval')),
  approval_required boolean NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('draft','pending','approved','executing','succeeded','partial','failed','uncertain','rejected','cancelled','expired')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  request_hash text NOT NULL CHECK(request_hash ~ '^[a-f0-9]{64}$'),
  idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),
  approved_by uuid REFERENCES users(id) ON DELETE RESTRICT,
  approved_at timestamptz,
  not_before timestamptz,
  window_start timestamptz,
  window_end timestamptz,
  expires_at timestamptz NOT NULL,
  cancelled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,workspace_id,id),
  FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,requester_developer_id) REFERENCES portal_developers(cluster_id,workspace_id,id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,definition_id,kind) REFERENCES workflow_definitions(cluster_id,workspace_id,id,kind) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,definition_id,definition_version) REFERENCES workflow_definition_versions(cluster_id,workspace_id,definition_id,version) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK((requester_type='developer' AND requester_developer_id IS NOT NULL AND requester_user_id IS NULL)
    OR(requester_type='console' AND requester_user_id IS NOT NULL AND requester_developer_id IS NULL)),
  CHECK(execution_mode<>'approval' OR approval_required),
  CHECK(kind NOT IN ('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') OR approval_required),
  CHECK(approval_required OR (approved_by IS NULL AND approved_at IS NULL AND state<>'approved')),
  CHECK((approved_by IS NULL)=(approved_at IS NULL)),
  CHECK(approved_by IS NULL OR approved_by IS DISTINCT FROM requester_user_id),
  CHECK((window_start IS NULL AND window_end IS NULL) OR (window_start IS NOT NULL AND window_end IS NOT NULL AND window_end>window_start AND window_end<=expires_at)),
  CHECK(not_before IS NULL OR not_before<expires_at),
  CHECK(expires_at>created_at AND updated_at>=created_at),
  CHECK(cancelled_at IS NULL OR cancelled_at>=created_at),
  CHECK(state<>'cancelled' OR cancelled_at IS NOT NULL)
);
CREATE UNIQUE INDEX workflows_console_idempotency ON workflows(cluster_id,workspace_id,requester_user_id,idempotency_key) WHERE requester_type='console';
CREATE UNIQUE INDEX workflows_developer_idempotency ON workflows(cluster_id,workspace_id,requester_developer_id,idempotency_key) WHERE requester_type='developer';
CREATE INDEX workflows_directory ON workflows(cluster_id,workspace_id,state,created_at DESC,id DESC);
CREATE INDEX workflows_developer ON workflows(cluster_id,workspace_id,requester_developer_id,created_at DESC,id DESC);
CREATE INDEX workflows_subject ON workflows(cluster_id,workspace_id,subject_type,subject_id,state);

CREATE TABLE workflow_versions (
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  workflow_id uuid NOT NULL,
  plan_revision integer NOT NULL CHECK(plan_revision>0),
  plan_hash text NOT NULL CHECK(plan_hash ~ '^[a-f0-9]{64}$'),
  execution_mode text NOT NULL CHECK(execution_mode IN ('direct','approval')),
  approval_required boolean NOT NULL,
  payload_secret text NOT NULL CHECK(m6_encrypted(payload_secret)),
  policy_version integer NOT NULL CHECK(policy_version>0),
  step_count integer NOT NULL CHECK(step_count BETWEEN 1 AND 16),
  native_request_count integer NOT NULL CHECK(native_request_count BETWEEN 0 AND 32),
  steps_hash text NOT NULL CHECK(steps_hash ~ '^[a-f0-9]{64}$'),
  safe_diff jsonb NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(safe_diff)='array' AND octet_length(safe_diff::text)<=262144),
  safe_impact jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(safe_impact)='object' AND octet_length(safe_impact::text)<=131072),
  expires_at timestamptz NOT NULL,
  created_by uuid REFERENCES users(id) ON DELETE RESTRICT,
  created_by_developer_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(cluster_id,workspace_id,workflow_id,plan_revision),
  UNIQUE(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash),
  UNIQUE(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required),
  FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(cluster_id,workspace_id,created_by_developer_id) REFERENCES portal_developers(cluster_id,workspace_id,id) ON DELETE RESTRICT,
  CHECK((created_by IS NULL)<>(created_by_developer_id IS NULL)),
  CHECK(execution_mode<>'approval' OR approval_required),
  CHECK(expires_at>created_at)
);

CREATE TABLE workflow_stages (
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  workflow_id uuid NOT NULL,
  plan_revision integer NOT NULL CHECK(plan_revision>0),
  plan_hash text NOT NULL CHECK(plan_hash ~ '^[a-f0-9]{64}$'),
  level integer NOT NULL CHECK(level=1),
  required_approvals integer NOT NULL DEFAULT 1 CHECK(required_approvals=1),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','active','approved','rejected','skipped')),
  activated_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(cluster_id,workspace_id,workflow_id,plan_revision,level),
  UNIQUE(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level),
  FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK(updated_at>=created_at),
  CHECK(completed_at IS NULL OR completed_at>=created_at)
);

CREATE TABLE workflow_approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  workflow_id uuid NOT NULL,
  plan_revision integer NOT NULL CHECK(plan_revision>0),
  plan_hash text NOT NULL CHECK(plan_hash ~ '^[a-f0-9]{64}$'),
  level integer NOT NULL CHECK(level=1),
  approver_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  decision text NOT NULL CHECK(decision IN ('approve','reject')),
  reason text NOT NULL DEFAULT '' CHECK(length(reason)<=2048),
  request_id text CHECK(request_id IS NULL OR length(request_id)<=128),
  idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),
  decided_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(workflow_id,plan_revision,level,approver_id),
  UNIQUE(cluster_id,workspace_id,approver_id,idempotency_key),
  FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level) REFERENCES workflow_stages(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX workflow_approvals_version ON workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,decision);

CREATE TABLE workflow_steps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  workflow_id uuid NOT NULL,
  plan_revision integer NOT NULL CHECK(plan_revision>0),
  plan_hash text NOT NULL CHECK(plan_hash ~ '^[a-f0-9]{64}$'),
  execution_mode text NOT NULL CHECK(execution_mode IN ('direct','approval')),
  approval_required boolean NOT NULL,
  step_key text NOT NULL CHECK(length(step_key) BETWEEN 1 AND 160),
  step_order integer NOT NULL CHECK(step_order BETWEEN 1 AND 16),
  kind text NOT NULL CHECK(kind IN ('native','metadata')),
  handler text CHECK(handler IS NULL OR (length(handler) BETWEEN 1 AND 160 AND handler ~ '^[a-z][a-z0-9_.:-]*$')),
  entity_type text NOT NULL CHECK(length(entity_type) BETWEEN 1 AND 80),
  entity_id uuid,
  parent_id uuid,
  credential_kind text CHECK(credential_kind IS NULL OR credential_kind IN ('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')),
  permission_action text NOT NULL CHECK(permission_action IN ('write','delete')),
  mutation_action text CHECK(mutation_action IS NULL OR mutation_action IN ('create','update','delete','restore')),
  mutation_payload_hmac text CHECK(mutation_payload_hmac IS NULL OR mutation_payload_hmac ~ '^[a-f0-9]{64}$'),
  mutation_idempotency_key text CHECK(mutation_idempotency_key IS NULL OR length(mutation_idempotency_key) BETWEEN 8 AND 128),
  before_fingerprint text CHECK(before_fingerprint IS NULL OR before_fingerprint ~ '^[a-f0-9]{64}$'),
  native_requests jsonb NOT NULL DEFAULT '[]' CHECK(m6_native_request_manifest(native_requests)),
  metadata_before_hmac text CHECK(metadata_before_hmac IS NULL OR metadata_before_hmac ~ '^[a-f0-9]{64}$'),
  metadata_revision integer CHECK(metadata_revision IS NULL OR metadata_revision>=0),
  metadata_payload_hmac text CHECK(metadata_payload_hmac IS NULL OR metadata_payload_hmac ~ '^[a-f0-9]{64}$'),
  dependencies uuid[] NOT NULL DEFAULT '{}' CHECK(cardinality(dependencies)<=15 AND coalesce(array_ndims(dependencies),1)=1 AND array_position(dependencies,NULL) IS NULL),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','running','succeeded','failed','uncertain','skipped')),
  operation_id uuid,
  recycle_entry_id uuid,
  safe_result jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(safe_result)='object' AND octet_length(safe_result::text)<=131072),
  receipt_secret text CHECK(receipt_secret IS NULL OR m6_encrypted(receipt_secret)),
  after_fingerprint text CHECK(after_fingerprint IS NULL OR after_fingerprint ~ '^[a-f0-9]{64}$'),
  error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(cluster_id,workspace_id,workflow_id,plan_revision,step_key),
  UNIQUE(cluster_id,workspace_id,workflow_id,plan_revision,step_order),
  UNIQUE(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash),
  UNIQUE(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash,operation_id),
  UNIQUE(operation_id),
  FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required) REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK(execution_mode<>'approval' OR approval_required),
  CHECK((kind='native' AND handler IS NULL AND mutation_action IS NOT NULL AND mutation_payload_hmac IS NOT NULL AND mutation_idempotency_key IS NOT NULL AND jsonb_array_length(native_requests)>0 AND metadata_before_hmac IS NULL AND metadata_revision IS NULL AND metadata_payload_hmac IS NULL)
    OR(kind='metadata' AND handler IS NOT NULL AND mutation_action IS NULL AND mutation_payload_hmac IS NULL AND mutation_idempotency_key IS NULL AND native_requests='[]'::jsonb AND operation_id IS NULL AND metadata_before_hmac IS NOT NULL AND metadata_revision IS NOT NULL AND metadata_payload_hmac IS NOT NULL)),
  CHECK(operation_id IS NULL OR(kind='native' AND approval_required)),
  CHECK(mutation_action IS NULL OR (permission_action='delete')=(mutation_action='delete')),
  CHECK(updated_at>=created_at),
  CHECK(started_at IS NULL OR started_at>=created_at),
  CHECK(completed_at IS NULL OR(started_at IS NOT NULL AND completed_at>=started_at))
);
CREATE INDEX workflow_steps_version ON workflow_steps(cluster_id,workspace_id,workflow_id,plan_revision,step_order);

CREATE TABLE workflow_executions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  workflow_id uuid NOT NULL,
  plan_revision integer NOT NULL CHECK(plan_revision>0),
  plan_hash text NOT NULL CHECK(plan_hash ~ '^[a-f0-9]{64}$'),
  execution_mode text NOT NULL CHECK(execution_mode IN ('direct','approval')),
  approval_required boolean NOT NULL,
  approved_by uuid REFERENCES users(id) ON DELETE RESTRICT,
  execution_actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  state text NOT NULL DEFAULT 'claimed' CHECK(state IN ('claimed','executing','succeeded','partial','failed','uncertain')),
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  snapshot_state text NOT NULL DEFAULT 'pending' CHECK(snapshot_state IN ('pending','ready','failed')),
  snapshot_secret text CHECK(snapshot_secret IS NULL OR m6_encrypted(snapshot_secret)),
  snapshot_hash text CHECK(snapshot_hash IS NULL OR snapshot_hash ~ '^[a-f0-9]{64}$'),
  snapshot_id uuid,
  claim_token_hash text NOT NULL CHECK(claim_token_hash ~ '^[a-f0-9]{64}$'),
  request_id text CHECK(request_id IS NULL OR length(request_id)<=128),
  idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),
  expires_at timestamptz NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(workflow_id,plan_revision),
  UNIQUE(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash),
  UNIQUE(cluster_id,workspace_id,execution_actor_id,idempotency_key),
  FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required) REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK(execution_mode<>'approval' OR approval_required),
  CHECK(approval_required=(approved_by IS NOT NULL)),
  CHECK((snapshot_state='ready' AND snapshot_secret IS NOT NULL AND snapshot_hash IS NOT NULL)
    OR(snapshot_state<>'ready' AND snapshot_secret IS NULL AND snapshot_hash IS NULL AND snapshot_id IS NULL)),
  CHECK(expires_at>started_at AND updated_at>=started_at),
  CHECK(completed_at IS NULL OR completed_at>=started_at)
);
CREATE INDEX workflow_executions_state ON workflow_executions(cluster_id,workspace_id,state,started_at DESC,id DESC);

CREATE TABLE portal_operations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  developer_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),
  request_hash text NOT NULL CHECK(request_hash ~ '^[a-f0-9]{64}$'),
  module text NOT NULL CHECK(module IN ('applications','credentials','profile','password')),
  action text NOT NULL CHECK(length(action) BETWEEN 1 AND 80),
  target_id uuid,
  workflow_id uuid,
  state text NOT NULL DEFAULT 'running' CHECK(state IN ('running','succeeded','failed','uncertain')),
  remote_started boolean NOT NULL DEFAULT false,
  remote_completed boolean NOT NULL DEFAULT false,
  payload_secret text CHECK(payload_secret IS NULL OR m6_encrypted(payload_secret)),
  result_secret text CHECK(result_secret IS NULL OR m6_encrypted(result_secret)),
  safe_result jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(safe_result)='object' AND octet_length(safe_result::text)<=131072),
  error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(developer_id,idempotency_key),
  FOREIGN KEY(cluster_id,workspace_id,developer_id) REFERENCES portal_developers(cluster_id,workspace_id,id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK(module<>'password' OR(payload_secret IS NULL AND result_secret IS NULL)),
  CHECK(NOT remote_completed OR remote_started),
  CHECK(state NOT IN ('running','uncertain') OR NOT remote_completed),
  CHECK(updated_at>=created_at)
);
CREATE INDEX portal_operations_owner ON portal_operations(cluster_id,workspace_id,developer_id,created_at DESC,id DESC);

CREATE TABLE portal_publication_proofs (
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  publication_id uuid NOT NULL,
  publication_revision integer NOT NULL CHECK(publication_revision>0),
  transport_scope text NOT NULL CHECK(transport_scope ~ '^[a-f0-9]{64}$'),
  publication_proof_secret text NOT NULL CHECK(m6_encrypted(publication_proof_secret)),
  publication_proof_hmac text NOT NULL CHECK(publication_proof_hmac ~ '^[a-f0-9]{64}$'),
  workflow_id uuid NOT NULL,
  workflow_execution_id uuid NOT NULL,
  workflow_plan_revision integer NOT NULL CHECK(workflow_plan_revision>0),
  workflow_plan_hash text NOT NULL CHECK(workflow_plan_hash ~ '^[a-f0-9]{64}$'),
  verified_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(cluster_id,workspace_id,publication_id,publication_revision),
  FOREIGN KEY(cluster_id,workspace_id,publication_id,publication_revision) REFERENCES portal_publication_revisions(cluster_id,workspace_id,publication_id,revision) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(cluster_id,workspace_id,publication_id,transport_scope) REFERENCES portal_publications(cluster_id,workspace_id,id,transport_scope) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,workflow_execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK(verified_at>='2020-01-01T00:00:00Z'::timestamptz)
);

CREATE TABLE portal_application_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  transport_scope text NOT NULL CHECK(transport_scope ~ '^[a-f0-9]{64}$'),
  application_id uuid NOT NULL,
  publication_id uuid NOT NULL,
  developer_id uuid NOT NULL,
  consumer_id uuid NOT NULL,
  acl_group text NOT NULL CHECK(length(acl_group)<=128),
  acl_id uuid NOT NULL,
  -- Internal generated discriminator supplies the full CredentialStore FK.
  acl_credential_kind text GENERATED ALWAYS AS ('acls'::text) STORED,
  acl_credential_ref_id uuid,
  current_generation integer NOT NULL DEFAULT 0 CHECK(current_generation>=0),
  current_credential_id uuid,
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','active','partial','rotating','revoking','revoked','uncertain','disabled')),
  workflow_id uuid,
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  -- A cancelled/rejected/expired never-executed reservation is retained forever,
  -- but no longer prevents a fresh application/publication grant identity.
  reservation_released_at timestamptz,
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(cluster_id,workspace_id,id,developer_id,consumer_id),
  UNIQUE(cluster_id,consumer_id),
  UNIQUE(transport_scope,consumer_id),
  FOREIGN KEY(cluster_id,workspace_id,application_id,developer_id) REFERENCES portal_applications(cluster_id,workspace_id,id,developer_id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,publication_id,acl_group,transport_scope) REFERENCES portal_publications(cluster_id,workspace_id,id,acl_group,transport_scope) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,developer_id) REFERENCES portal_developers(cluster_id,workspace_id,id) ON DELETE RESTRICT,
  FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK((current_credential_id IS NULL)=(current_generation=0)),
  CHECK(state<>'active' OR(current_generation>0 AND current_credential_id IS NOT NULL AND acl_credential_ref_id IS NOT NULL)),
  CHECK((state='revoked')=(revoked_at IS NOT NULL)),
  CHECK(reservation_released_at IS NULL OR(state='disabled' AND current_generation=0
    AND current_credential_id IS NULL AND acl_credential_ref_id IS NULL AND workflow_id IS NOT NULL
    AND reservation_released_at>=created_at)),
  CHECK(updated_at>=created_at),
  CHECK(revoked_at IS NULL OR revoked_at>=created_at)
);
CREATE UNIQUE INDEX portal_grants_live_pair ON portal_application_grants(cluster_id,workspace_id,application_id,publication_id)
  WHERE state<>'revoked' AND reservation_released_at IS NULL;
CREATE INDEX portal_grants_application ON portal_application_grants(cluster_id,workspace_id,application_id,state,created_at DESC,id DESC);
CREATE INDEX portal_grants_publication ON portal_application_grants(cluster_id,workspace_id,publication_id,state,created_at DESC,id DESC);
CREATE INDEX portal_grants_physical_ownership ON portal_application_grants(transport_scope,publication_id,consumer_id);

CREATE TABLE portal_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  developer_id uuid NOT NULL,
  consumer_id uuid NOT NULL,
  credential_kind text NOT NULL DEFAULT 'key-auth' CHECK(credential_kind='key-auth'),
  kong_id uuid NOT NULL,
  credential_ref_id uuid,
  generation integer NOT NULL CHECK(generation>0),
  previous_credential_id uuid,
  key_secret text NOT NULL CHECK(m6_encrypted(key_secret,16384)),
  key_fingerprint text NOT NULL CHECK(key_fingerprint ~ '^[a-f0-9]{64}$'),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','active','rotating','revoking','revoked','uncertain','deleted')),
  workflow_id uuid NOT NULL,
  issue_operation_id uuid,
  revoke_workflow_id uuid,
  revoke_operation_id uuid,
  recycle_entry_id uuid,
  last_revealed_at timestamptz,
  revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  deleted_at timestamptz,
  retention_until timestamptz,
  UNIQUE(cluster_id,workspace_id,id),
  UNIQUE(cluster_id,workspace_id,grant_id,id),
  UNIQUE(cluster_id,workspace_id,grant_id,id,generation,consumer_id),
  UNIQUE(cluster_id,workspace_id,grant_id,generation),
  UNIQUE(cluster_id,consumer_id,kong_id),
  FOREIGN KEY(cluster_id,workspace_id,grant_id,developer_id,consumer_id) REFERENCES portal_application_grants(cluster_id,workspace_id,id,developer_id,consumer_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(cluster_id,workspace_id,previous_credential_id) REFERENCES portal_credentials(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(cluster_id,workspace_id,grant_id,previous_credential_id) REFERENCES portal_credentials(cluster_id,workspace_id,grant_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(cluster_id,workspace_id,revoke_workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK(previous_credential_id IS DISTINCT FROM id),
  CHECK(revoke_operation_id IS NULL OR revoke_workflow_id IS NOT NULL),
  CHECK(state<>'active' OR(credential_ref_id IS NOT NULL AND issue_operation_id IS NOT NULL)),
  CHECK(state NOT IN ('revoked','deleted') OR revoked_at IS NOT NULL),
  CHECK(updated_at>=created_at),
  CHECK(revoked_at IS NULL OR revoked_at>=created_at),
  CHECK(last_revealed_at IS NULL OR last_revealed_at>=created_at),
  CHECK((state='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL AND retention_until>=deleted_at)
    OR(state<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE UNIQUE INDEX portal_credentials_one_active ON portal_credentials(grant_id) WHERE state='active';
CREATE INDEX portal_credentials_grant ON portal_credentials(cluster_id,workspace_id,grant_id,state,generation DESC);

CREATE TABLE workflow_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cluster_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  workflow_id uuid NOT NULL,
  plan_revision integer NOT NULL CHECK(plan_revision>0),
  plan_hash text NOT NULL CHECK(plan_hash ~ '^[a-f0-9]{64}$'),
  execution_id uuid,
  step_id uuid,
  actor_type text NOT NULL CHECK(actor_type IN ('developer','user','system')),
  actor_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  developer_id uuid,
  action text NOT NULL CHECK(length(action) BETWEEN 1 AND 80),
  result text NOT NULL CHECK(length(result) BETWEEN 1 AND 80),
  error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),
  safe_metadata jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(safe_metadata)='object' AND octet_length(safe_metadata::text)<=65536),
  request_id text CHECK(request_id IS NULL OR length(request_id)<=128),
  operation_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(cluster_id,workspace_id,id),
  FOREIGN KEY(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(cluster_id,workspace_id,execution_id,workflow_id,plan_revision,plan_hash) REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(cluster_id,workspace_id,step_id,workflow_id,plan_revision,plan_hash) REFERENCES workflow_steps(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(cluster_id,workspace_id,developer_id) REFERENCES portal_developers(cluster_id,workspace_id,id) ON DELETE RESTRICT,
  CHECK((actor_type='developer' AND developer_id IS NOT NULL AND actor_id IS NULL)
    OR(actor_type='user' AND actor_id IS NOT NULL AND developer_id IS NULL)
    OR(actor_type='system' AND actor_id IS NULL AND developer_id IS NULL)),
  CHECK(operation_id IS NULL OR(step_id IS NOT NULL AND execution_id IS NOT NULL))
);
CREATE INDEX workflow_events_timeline ON workflow_events(cluster_id,workspace_id,workflow_id,created_at,id);

-- Complete FK targets for legacy native ledgers; NULL legacy scope is retained.
ALTER TABLE credential_refs ADD CONSTRAINT credential_refs_portal_complete_unique UNIQUE(cluster_id,consumer_id,credential_type,kong_id,id);
ALTER TABLE recycle_entries ADD CONSTRAINT recycle_entries_portal_scope_unique UNIQUE(cluster_id,workspace_id,id);
ALTER TABLE mutation_operations ADD COLUMN workflow_execution_id uuid;
ALTER TABLE mutation_operations ADD COLUMN workflow_plan_revision integer CHECK(workflow_plan_revision IS NULL OR workflow_plan_revision>0);
ALTER TABLE mutation_operations ADD COLUMN workflow_plan_hash text CHECK(workflow_plan_hash IS NULL OR workflow_plan_hash ~ '^[a-f0-9]{64}$');
ALTER TABLE mutation_operations ADD COLUMN workflow_step_id uuid;
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_operations_portal_binding_complete CHECK(
  num_nonnulls(workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id)=0
  OR(num_nonnulls(workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id)=4 AND workflow_id IS NOT NULL AND workspace_id IS NOT NULL));
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_operations_portal_scope_unique UNIQUE(cluster_id,workspace_id,id);
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_operations_portal_workflow_unique UNIQUE(cluster_id,workspace_id,workflow_id,id);
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_operations_portal_step_unique UNIQUE(workflow_step_id);
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_operations_portal_reciprocal_unique UNIQUE(cluster_id,workspace_id,workflow_step_id,workflow_id,workflow_plan_revision,workflow_plan_hash,id);
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_operations_portal_execution_fk
  FOREIGN KEY(cluster_id,workspace_id,workflow_execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_operations_portal_step_fk
  FOREIGN KEY(cluster_id,workspace_id,workflow_step_id,workflow_id,workflow_plan_revision,workflow_plan_hash,id) REFERENCES workflow_steps(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash,operation_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE workflow_steps ADD CONSTRAINT workflow_steps_portal_operation_fk
  FOREIGN KEY(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash,operation_id) REFERENCES mutation_operations(cluster_id,workspace_id,workflow_step_id,workflow_id,workflow_plan_revision,workflow_plan_hash,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE workflow_steps ADD CONSTRAINT workflow_steps_recycle_fk FOREIGN KEY(cluster_id,workspace_id,recycle_entry_id) REFERENCES recycle_entries(cluster_id,workspace_id,id) ON DELETE RESTRICT;
ALTER TABLE portal_application_grants ADD CONSTRAINT portal_grants_acl_ref_fk
  FOREIGN KEY(cluster_id,consumer_id,acl_credential_kind,acl_id,acl_credential_ref_id) REFERENCES credential_refs(cluster_id,consumer_id,credential_type,kong_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE portal_credentials ADD CONSTRAINT portal_credentials_native_ref_fk
  FOREIGN KEY(cluster_id,consumer_id,credential_kind,kong_id,credential_ref_id) REFERENCES credential_refs(cluster_id,consumer_id,credential_type,kong_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE portal_credentials ADD CONSTRAINT portal_credentials_recycle_fk FOREIGN KEY(cluster_id,workspace_id,recycle_entry_id) REFERENCES recycle_entries(cluster_id,workspace_id,id) ON DELETE RESTRICT;
ALTER TABLE portal_credentials ADD CONSTRAINT portal_credentials_issue_operation_fk
  FOREIGN KEY(cluster_id,workspace_id,workflow_id,issue_operation_id) REFERENCES mutation_operations(cluster_id,workspace_id,workflow_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE portal_credentials ADD CONSTRAINT portal_credentials_revoke_operation_fk
  FOREIGN KEY(cluster_id,workspace_id,revoke_workflow_id,revoke_operation_id) REFERENCES mutation_operations(cluster_id,workspace_id,workflow_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE portal_application_grants ADD CONSTRAINT portal_grants_current_credential_fk
  FOREIGN KEY(cluster_id,workspace_id,id,current_credential_id,current_generation,consumer_id) REFERENCES portal_credentials(cluster_id,workspace_id,grant_id,id,generation,consumer_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE workflows ADD CONSTRAINT workflows_current_version_fk
  FOREIGN KEY(cluster_id,workspace_id,id,plan_revision,plan_hash,execution_mode,approval_required) REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_current_version_fk
  FOREIGN KEY(cluster_id,workspace_id,id,current_version) REFERENCES workflow_definition_versions(cluster_id,workspace_id,definition_id,version) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE portal_publications ADD CONSTRAINT portal_publications_current_revision_fk
  FOREIGN KEY(cluster_id,workspace_id,id,current_revision) REFERENCES portal_publication_revisions(cluster_id,workspace_id,publication_id,revision) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE portal_publications ADD CONSTRAINT portal_publications_published_revision_fk
  FOREIGN KEY(cluster_id,workspace_id,id,published_revision) REFERENCES portal_publication_revisions(cluster_id,workspace_id,publication_id,revision) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE portal_publications ADD CONSTRAINT portal_publications_workflow_fk FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE portal_content ADD CONSTRAINT portal_content_current_revision_fk
  FOREIGN KEY(cluster_id,workspace_id,id,current_revision) REFERENCES portal_content_revisions(cluster_id,workspace_id,content_id,revision) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE portal_content ADD CONSTRAINT portal_content_published_revision_fk
  FOREIGN KEY(cluster_id,workspace_id,id,published_revision) REFERENCES portal_content_revisions(cluster_id,workspace_id,content_id,revision) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE portal_content ADD CONSTRAINT portal_content_workflow_fk FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE workflow_events ADD CONSTRAINT workflow_events_operation_fk
  FOREIGN KEY(cluster_id,workspace_id,step_id,workflow_id,plan_revision,plan_hash,operation_id) REFERENCES mutation_operations(cluster_id,workspace_id,workflow_step_id,workflow_id,workflow_plan_revision,workflow_plan_hash,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

-- Never rewrite immutable legacy audit records to guess an unresolved workflow.
-- NOT VALID applies to old rows only; all new workflow audit tuples must be complete.
ALTER TABLE audit_events ADD CONSTRAINT audit_events_portal_workflow_scope CHECK(workflow_id IS NULL OR(cluster_id IS NOT NULL AND workspace_id IS NOT NULL)) NOT VALID;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_portal_workflow_fk
  FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT NOT VALID;

CREATE FUNCTION m6_reject_history_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'M6 historical records are append-only' USING ERRCODE='42501';
END;
$$;
DO $$DECLARE tab text;BEGIN
  FOREACH tab IN ARRAY ARRAY['workflow_definition_versions','workflow_definition_stages','workflow_versions','workflow_approvals','workflow_events','portal_publication_revisions','portal_publication_proofs','portal_content_revisions'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m6_reject_history_mutation()',tab||'_append_only',tab);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m6_reject_history_mutation()',tab||'_no_truncate',tab);
    EXECUTE format('REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON %I FROM PUBLIC',tab);
  END LOOP;
END;$$;

CREATE FUNCTION m6_guard_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE column_name text; old_row jsonb; new_row jsonb;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'M6 resources require soft deletion or revocation' USING ERRCODE='42501'; END IF;
  old_row=to_jsonb(OLD);new_row=to_jsonb(NEW);
  FOREACH column_name IN ARRAY string_to_array(TG_ARGV[0],',') LOOP
    IF old_row->column_name IS DISTINCT FROM new_row->column_name THEN
      RAISE EXCEPTION 'M6 captured identity cannot change' USING ERRCODE='23514';
    END IF;
  END LOOP;
  RETURN NEW;
END;
$$;
CREATE TRIGGER portal_settings_identity BEFORE UPDATE OR DELETE ON portal_settings FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,slug,created_at');
CREATE TRIGGER portal_developers_identity BEFORE UPDATE OR DELETE ON portal_developers FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,username,email,created_at');
CREATE TRIGGER portal_sessions_identity BEFORE UPDATE OR DELETE ON portal_sessions FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,developer_id,family_id,credential_epoch,created_at');
CREATE TRIGGER portal_applications_identity BEFORE UPDATE OR DELETE ON portal_applications FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,developer_id,created_at');
CREATE TRIGGER portal_publications_identity BEFORE UPDATE OR DELETE ON portal_publications FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,transport_scope,slug,service_id,acl_group,created_by,created_at');
CREATE TRIGGER portal_content_identity BEFORE UPDATE OR DELETE ON portal_content FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,slug,created_by,created_at');
CREATE TRIGGER portal_grants_identity BEFORE UPDATE OR DELETE ON portal_application_grants FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,transport_scope,application_id,publication_id,developer_id,consumer_id,acl_group,acl_id,created_at');
CREATE TRIGGER portal_credentials_identity BEFORE UPDATE OR DELETE ON portal_credentials FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,grant_id,developer_id,consumer_id,credential_kind,kong_id,generation,previous_credential_id,key_secret,key_fingerprint,workflow_id,created_at');
CREATE TRIGGER portal_operations_identity BEFORE UPDATE OR DELETE ON portal_operations FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,developer_id,idempotency_key,request_hash,module,action,target_id,payload_secret,created_at');
CREATE TRIGGER workflow_definitions_identity BEFORE UPDATE OR DELETE ON workflow_definitions FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,code,kind,created_by,created_at');
CREATE TRIGGER workflows_identity BEFORE UPDATE OR DELETE ON workflows FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,kind,subject_type,subject_id,requester_type,requester_developer_id,requester_user_id,definition_id,definition_version,request_hash,idempotency_key,expires_at,created_at');
CREATE TRIGGER workflow_stages_identity BEFORE UPDATE OR DELETE ON workflow_stages FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,required_approvals,created_at');
CREATE TRIGGER workflow_steps_identity BEFORE UPDATE OR DELETE ON workflow_steps FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,step_key,step_order,kind,handler,entity_type,entity_id,parent_id,credential_kind,permission_action,mutation_action,mutation_payload_hmac,mutation_idempotency_key,before_fingerprint,native_requests,metadata_before_hmac,metadata_revision,metadata_payload_hmac,dependencies,created_at');
CREATE TRIGGER workflow_executions_identity BEFORE UPDATE OR DELETE ON workflow_executions FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,claim_token_hash,request_id,idempotency_key,expires_at,started_at');

CREATE FUNCTION m6_guard_progress() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE column_name text;
BEGIN
  IF TG_TABLE_NAME='workflow_steps' THEN
    IF OLD.operation_id IS NOT NULL AND NEW.operation_id IS DISTINCT FROM OLD.operation_id THEN
      RAISE EXCEPTION 'Approved native operation is bound once' USING ERRCODE='23514';
    END IF;
    IF OLD.receipt_secret IS NOT NULL AND NEW.receipt_secret IS DISTINCT FROM OLD.receipt_secret THEN
      RAISE EXCEPTION 'Native recovery receipt is sealed once' USING ERRCODE='23514';
    END IF;
    IF OLD.state IN ('succeeded','skipped') AND NEW.state<>OLD.state THEN
      RAISE EXCEPTION 'Terminal workflow step cannot reopen' USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='workflow_executions' THEN
    IF OLD.snapshot_state<>'pending' AND
      ROW(NEW.snapshot_state,NEW.snapshot_secret,NEW.snapshot_hash,NEW.snapshot_id) IS DISTINCT FROM ROW(OLD.snapshot_state,OLD.snapshot_secret,OLD.snapshot_hash,OLD.snapshot_id) THEN
      RAISE EXCEPTION 'Execution snapshot is sealed once' USING ERRCODE='23514';
    END IF;
    IF OLD.state='succeeded' AND NEW.state<>'succeeded' THEN
      RAISE EXCEPTION 'Successful execution cannot reopen' USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='portal_sessions' THEN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
      RAISE EXCEPTION 'Revoked portal session cannot reactivate' USING ERRCODE='23514';
    END IF;
    IF NEW.refresh_generation<OLD.refresh_generation OR NEW.expires_at>OLD.expires_at
      OR(NEW.refresh_token_hash<>OLD.refresh_token_hash AND NEW.refresh_generation<>OLD.refresh_generation+1)
      OR(NEW.refresh_generation<>OLD.refresh_generation AND NEW.refresh_token_hash=OLD.refresh_token_hash) THEN
      RAISE EXCEPTION 'Portal refresh must advance its captured session once' USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='portal_developers' THEN
    IF NEW.credential_epoch<OLD.credential_epoch
      OR(NEW.password_hash<>OLD.password_hash AND NEW.credential_epoch<=OLD.credential_epoch)
      OR(NEW.status<>OLD.status AND NEW.credential_epoch<=OLD.credential_epoch) THEN
      RAISE EXCEPTION 'Developer security changes must advance credential epoch' USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='portal_credentials' THEN
    FOREACH column_name IN ARRAY ARRAY['credential_ref_id','issue_operation_id','revoke_workflow_id','revoke_operation_id','recycle_entry_id'] LOOP
      IF to_jsonb(OLD)->column_name<>'null'::jsonb AND to_jsonb(NEW)->column_name IS DISTINCT FROM to_jsonb(OLD)->column_name THEN
        RAISE EXCEPTION 'Credential recovery identity is bound once' USING ERRCODE='23514';
      END IF;
    END LOOP;
    IF OLD.state IN ('revoked','deleted') AND NEW.state NOT IN ('revoked','deleted') THEN
      RAISE EXCEPTION 'Historical portal key cannot reactivate' USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='portal_application_grants' THEN
    IF OLD.state='revoked' AND NEW.state<>'revoked' THEN
      RAISE EXCEPTION 'Revoked grant history cannot reactivate or reopen' USING ERRCODE='23514';
    END IF;
    IF OLD.reservation_released_at IS NOT NULL AND
      ROW(NEW.reservation_released_at,NEW.workflow_id) IS DISTINCT FROM ROW(OLD.reservation_released_at,OLD.workflow_id) THEN
      RAISE EXCEPTION 'Unused reservation release and its terminal issue parent are immutable' USING ERRCODE='23514';
    END IF;
    IF OLD.acl_credential_ref_id IS NOT NULL AND NEW.acl_credential_ref_id IS DISTINCT FROM OLD.acl_credential_ref_id THEN
      RAISE EXCEPTION 'Grant ACL recovery identity is bound once' USING ERRCODE='23514';
    END IF;
    IF NEW.current_generation<OLD.current_generation THEN
      RAISE EXCEPTION 'Grant generation cannot move backwards' USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='portal_operations' THEN
    IF OLD.state='succeeded' AND NEW IS DISTINCT FROM OLD THEN
      RAISE EXCEPTION 'Successful portal receipt cannot be overwritten' USING ERRCODE='23514';
    END IF;
    IF OLD.workflow_id IS NOT NULL AND NEW.workflow_id IS DISTINCT FROM OLD.workflow_id THEN
      RAISE EXCEPTION 'Portal receipt cannot change workflow' USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='workflows' THEN
    IF OLD.state IN ('succeeded','rejected','cancelled','expired') AND NEW.state<>OLD.state THEN
      RAISE EXCEPTION 'Terminal workflow cannot reopen' USING ERRCODE='23514';
    END IF;
    IF NEW.plan_revision<OLD.plan_revision THEN
      RAISE EXCEPTION 'Workflow current version cannot move backwards' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
DO $$DECLARE tab text;BEGIN
  FOREACH tab IN ARRAY ARRAY['workflow_steps','workflow_executions','portal_sessions','portal_developers','portal_credentials','portal_application_grants','portal_operations','workflows'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION m6_guard_progress()',tab||'_progress_guard',tab);
  END LOOP;
END;$$;

CREATE FUNCTION m6_guard_mutation_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF ROW(NEW.cluster_id,NEW.workspace_id,NEW.id,NEW.workflow_id,NEW.workflow_execution_id,NEW.workflow_plan_revision,NEW.workflow_plan_hash,NEW.workflow_step_id)
    IS DISTINCT FROM ROW(OLD.cluster_id,OLD.workspace_id,OLD.id,OLD.workflow_id,OLD.workflow_execution_id,OLD.workflow_plan_revision,OLD.workflow_plan_hash,OLD.workflow_step_id)
    AND(OLD.workflow_step_id IS NOT NULL OR NEW.workflow_step_id IS NOT NULL) THEN
    RAISE EXCEPTION 'Approved native ledger binding must be allocated immutably' USING ERRCODE='23514';
  END IF;
  IF OLD.workflow_step_id IS NOT NULL AND
    ROW(NEW.actor_id,NEW.action,NEW.entity_type,NEW.parent_id,NEW.credential_kind,NEW.idempotency_key,NEW.request_hash,NEW.before_secret,NEW.payload_secret,NEW.transport_scope)
    IS DISTINCT FROM ROW(OLD.actor_id,OLD.action,OLD.entity_type,OLD.parent_id,OLD.credential_kind,OLD.idempotency_key,OLD.request_hash,OLD.before_secret,OLD.payload_secret,OLD.transport_scope) THEN
    RAISE EXCEPTION 'Approved native ledger logical identity cannot change' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER mutation_operations_portal_immutable BEFORE UPDATE ON mutation_operations FOR EACH ROW EXECUTE FUNCTION m6_guard_mutation_binding();

CREATE FUNCTION m6_validate_native_binding() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE op mutation_operations%ROWTYPE;s workflow_steps%ROWTYPE;e workflow_executions%ROWTYPE;
BEGIN
  SELECT * INTO op FROM mutation_operations WHERE id=NEW.id;
  IF op.workflow_step_id IS NULL THEN RETURN NULL;END IF;
  SELECT * INTO s FROM workflow_steps WHERE id=op.workflow_step_id;
  SELECT * INTO e FROM workflow_executions WHERE id=op.workflow_execution_id;
  IF op.actor_id IS DISTINCT FROM e.execution_actor_id OR op.action IS DISTINCT FROM s.mutation_action
    OR op.entity_type IS DISTINCT FROM s.entity_type OR op.parent_id IS DISTINCT FROM s.parent_id::text
    OR op.credential_kind IS DISTINCT FROM s.credential_kind
    OR(op.entity_id IS NOT NULL AND s.entity_id IS NOT NULL AND op.entity_id<>s.entity_id::text) THEN
    RAISE EXCEPTION 'Native ledger must retain exact executor and logical step identity' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER mutation_operations_portal_binding AFTER INSERT OR UPDATE ON mutation_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_native_binding();

CREATE FUNCTION m6_validate_version_graph() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cid uuid;wid uuid;fid uuid;rev integer;v workflow_versions%ROWTYPE;
  w workflows%ROWTYPE;s workflow_steps%ROWTYPE;dep uuid;dep_order integer;
  actual_count integer;request_count integer;stage_count integer;
BEGIN
  cid=NEW.cluster_id;wid=NEW.workspace_id;fid=NEW.workflow_id;rev=NEW.plan_revision;
  SELECT * INTO v FROM workflow_versions WHERE cluster_id=cid AND workspace_id=wid AND workflow_id=fid AND plan_revision=rev;
  IF NOT FOUND THEN RETURN NULL; END IF;
  SELECT * INTO w FROM workflows WHERE cluster_id=cid AND workspace_id=wid AND id=fid;
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
  IF(v.approval_required AND stage_count<>1) OR(NOT v.approval_required AND stage_count<>0) THEN
    RAISE EXCEPTION 'Workflow stages do not match approval requirement' USING ERRCODE='23514';
  END IF;
  IF EXISTS(SELECT 1 FROM workflow_stages st WHERE st.cluster_id=cid AND st.workspace_id=wid AND st.workflow_id=fid AND st.plan_revision=rev
    AND NOT EXISTS(SELECT 1 FROM workflow_definition_stages ds WHERE ds.cluster_id=cid AND ds.workspace_id=wid AND ds.definition_id=w.definition_id AND ds.definition_version=w.definition_version AND ds.level=st.level AND ds.required_approvals=st.required_approvals)) THEN
    RAISE EXCEPTION 'Workflow stage must match its immutable definition' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER workflow_versions_complete AFTER INSERT ON workflow_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_version_graph();
CREATE CONSTRAINT TRIGGER workflow_steps_complete AFTER INSERT OR UPDATE ON workflow_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_version_graph();
CREATE CONSTRAINT TRIGGER workflow_stages_complete AFTER INSERT OR UPDATE ON workflow_stages DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_version_graph();

CREATE FUNCTION m6_validate_definition_stages() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ver integer;
BEGIN
  IF TG_TABLE_NAME='workflow_definition_versions' THEN ver=NEW.version;ELSE ver=NEW.definition_version;END IF;
  IF (SELECT count(*) FROM workflow_definition_stages WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND definition_id=NEW.definition_id AND definition_version=ver)<>1 THEN
    RAISE EXCEPTION 'M6 workflow definition requires one immutable approval stage' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER workflow_definition_versions_complete AFTER INSERT ON workflow_definition_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_definition_stages();
CREATE CONSTRAINT TRIGGER workflow_definition_stages_complete AFTER INSERT ON workflow_definition_stages DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_definition_stages();

CREATE FUNCTION m6_validate_workflow_subject() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE subject_exists boolean; owner_id uuid;
BEGIN
  IF NOT((NEW.kind='portal-publication' AND NEW.subject_type='portal_publications')
    OR(NEW.kind IN ('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND NEW.subject_type='portal_application_grants')
    OR(NEW.kind='portal-developer-review' AND NEW.subject_type='portal_developers')
    OR(NEW.kind='portal-metadata' AND NEW.subject_type IN ('portal_settings','portal_developers','portal_applications','portal_publications','portal_content'))
    OR NEW.kind='native-change') THEN
    RAISE EXCEPTION 'Workflow subject type does not match its fixed kind' USING ERRCODE='23514';
  END IF;
  -- subject_type is constrained to a fixed table-name allowlist, never a client SQL name.
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3)',NEW.subject_type)
    INTO subject_exists USING NEW.cluster_id,NEW.workspace_id,NEW.subject_id;
  IF NOT subject_exists THEN RAISE EXCEPTION 'Workflow subject must exist in the complete tenant scope' USING ERRCODE='23503';END IF;
  IF NEW.requester_type='developer' THEN
    IF NEW.kind NOT IN ('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') THEN
      RAISE EXCEPTION 'Developer workflows are restricted to their credential grants' USING ERRCODE='23514';
    END IF;
    SELECT developer_id INTO owner_id FROM portal_application_grants WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.subject_id;
    IF owner_id IS DISTINCT FROM NEW.requester_developer_id THEN
      RAISE EXCEPTION 'Developer workflow subject must retain its owner' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER workflows_subject_scope AFTER INSERT OR UPDATE ON workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_workflow_subject();

CREATE FUNCTION m6_validate_approval_fact() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE CONSTRAINT TRIGGER workflow_approvals_fact AFTER INSERT ON workflow_approvals DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_approval_fact();
CREATE CONSTRAINT TRIGGER workflows_approval_fact AFTER INSERT OR UPDATE ON workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_approval_fact();
CREATE CONSTRAINT TRIGGER workflow_executions_approval_fact AFTER INSERT OR UPDATE ON workflow_executions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_approval_fact();

CREATE FUNCTION m6_validate_session_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d portal_developers%ROWTYPE;s portal_sessions%ROWTYPE;
BEGIN
  IF TG_TABLE_NAME='portal_sessions' THEN
    SELECT * INTO s FROM portal_sessions WHERE id=NEW.id;
    SELECT * INTO d FROM portal_developers WHERE cluster_id=s.cluster_id AND workspace_id=s.workspace_id AND id=s.developer_id;
    IF s.revoked_at IS NULL AND(d.status<>'active' OR s.credential_epoch<>d.credential_epoch) THEN
      RAISE EXCEPTION 'Portal session requires an active current developer epoch' USING ERRCODE='23514';
    END IF;
  ELSE
    SELECT * INTO d FROM portal_developers WHERE id=NEW.id;
    IF EXISTS(SELECT 1 FROM portal_sessions WHERE cluster_id=d.cluster_id AND workspace_id=d.workspace_id AND developer_id=d.id AND revoked_at IS NULL AND(d.status<>'active' OR credential_epoch<>d.credential_epoch)) THEN
      RAISE EXCEPTION 'Developer security changes must revoke all stale sessions atomically' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER portal_sessions_epoch AFTER INSERT OR UPDATE ON portal_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_session_epoch();
CREATE CONSTRAINT TRIGGER portal_developers_epoch AFTER UPDATE ON portal_developers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_session_epoch();

CREATE FUNCTION m6_validate_visible_state() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p portal_publications%ROWTYPE;c portal_credentials%ROWTYPE;g portal_application_grants%ROWTYPE;
  proof portal_publication_proofs%ROWTYPE;e workflow_executions%ROWTYPE;w workflows%ROWTYPE;op mutation_operations%ROWTYPE;
BEGIN
  IF TG_TABLE_NAME='portal_publication_proofs' THEN
    SELECT * INTO proof FROM portal_publication_proofs WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND publication_id=NEW.publication_id AND publication_revision=NEW.publication_revision;
    SELECT * INTO e FROM workflow_executions WHERE id=proof.workflow_execution_id;
    SELECT * INTO w FROM workflows WHERE id=proof.workflow_id;
    IF e.state<>'succeeded' OR w.state<>'succeeded' OR w.kind<>'portal-publication'
      OR w.subject_type<>'portal_publications' OR w.subject_id<>proof.publication_id THEN
      RAISE EXCEPTION 'Successful publication proof must commit with its parent terminal state' USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='portal_publications' THEN
    SELECT * INTO p FROM portal_publications WHERE id=NEW.id;
    IF p.published_revision IS NOT NULL AND NOT EXISTS(SELECT 1 FROM portal_publication_proofs WHERE cluster_id=p.cluster_id AND workspace_id=p.workspace_id AND publication_id=p.id AND publication_revision=p.published_revision AND transport_scope=p.transport_scope) THEN
      RAISE EXCEPTION 'Public publication revision requires a sealed successful proof' USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='portal_application_grants' THEN
    SELECT * INTO g FROM portal_application_grants WHERE id=NEW.id;
    IF g.state='active' THEN
      SELECT * INTO c FROM portal_credentials WHERE id=g.current_credential_id;
      SELECT * INTO w FROM workflows WHERE id=g.workflow_id;
      IF c.state IS DISTINCT FROM 'active' OR w.state IS DISTINCT FROM 'succeeded' THEN
        RAISE EXCEPTION 'Active grant requires its active key and terminal workflow' USING ERRCODE='23514';
      END IF;
    END IF;
    IF g.state='revoked' THEN
      SELECT * INTO w FROM workflows WHERE id=g.workflow_id;
      IF w.state IS DISTINCT FROM 'succeeded' OR w.kind IS DISTINCT FROM 'portal-credential-revoke'
        OR w.subject_type IS DISTINCT FROM 'portal_application_grants' OR w.subject_id IS DISTINCT FROM g.id
        OR NOT EXISTS(SELECT 1 FROM portal_credentials pc WHERE pc.grant_id=g.id AND pc.issue_operation_id IS NOT NULL)
        OR EXISTS(SELECT 1 FROM portal_credentials pc WHERE pc.grant_id=g.id AND pc.state NOT IN ('revoked','deleted')) THEN
        RAISE EXCEPTION 'Revoked grant requires all issued keys revoked and its terminal revoke workflow' USING ERRCODE='23514';
      END IF;
    END IF;
  ELSIF TG_TABLE_NAME='portal_credentials' THEN
    SELECT * INTO c FROM portal_credentials WHERE id=NEW.id;
    IF c.issue_operation_id IS NOT NULL THEN
      SELECT * INTO op FROM mutation_operations WHERE id=c.issue_operation_id;
      IF op.workflow_step_id IS NULL OR op.entity_type<>'credentials' OR op.credential_kind<>c.credential_kind
        OR op.parent_id IS DISTINCT FROM c.consumer_id::text OR op.action<>'create'
        OR(op.entity_id IS NOT NULL AND op.entity_id<>c.kong_id::text) THEN
        RAISE EXCEPTION 'Portal key issue receipt must bind its exact native credential' USING ERRCODE='23514';
      END IF;
    END IF;
    IF c.revoke_operation_id IS NOT NULL THEN
      SELECT * INTO op FROM mutation_operations WHERE id=c.revoke_operation_id;
      IF op.workflow_step_id IS NULL OR op.entity_type<>'credentials' OR op.credential_kind<>c.credential_kind
        OR op.parent_id IS DISTINCT FROM c.consumer_id::text OR op.action<>'delete' OR op.entity_id IS DISTINCT FROM c.kong_id::text THEN
        RAISE EXCEPTION 'Portal key revoke receipt must bind its exact native credential' USING ERRCODE='23514';
      END IF;
    END IF;
    IF c.previous_credential_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM portal_credentials pc WHERE pc.id=c.previous_credential_id AND pc.generation<c.generation) THEN
      RAISE EXCEPTION 'Portal rotation must advance the same grant generation' USING ERRCODE='23514';
    END IF;
    IF c.state='active' THEN
      SELECT * INTO w FROM workflows WHERE id=c.workflow_id;
      SELECT * INTO op FROM mutation_operations WHERE id=c.issue_operation_id;
      IF w.state IS DISTINCT FROM 'succeeded' OR op.state IS DISTINCT FROM 'succeeded'
        OR op.entity_id IS DISTINCT FROM c.kong_id::text OR NOT op.remote_completed THEN
        RAISE EXCEPTION 'Key activation requires exact terminal native and workflow receipts' USING ERRCODE='23514';
      END IF;
    END IF;
    IF c.state IN ('revoked','deleted') THEN
      SELECT * INTO w FROM workflows WHERE id=c.revoke_workflow_id;
      SELECT * INTO op FROM mutation_operations WHERE id=c.revoke_operation_id;
      IF c.revoke_workflow_id IS NULL OR c.revoke_operation_id IS NULL
        OR w.state IS DISTINCT FROM 'succeeded' OR w.kind NOT IN ('portal-credential-revoke','portal-credential-rotate')
        OR w.subject_type IS DISTINCT FROM 'portal_application_grants' OR w.subject_id IS DISTINCT FROM c.grant_id
        OR op.state IS DISTINCT FROM 'succeeded' OR NOT coalesce(op.remote_completed,false)
        OR op.workflow_step_id IS NULL OR op.action IS DISTINCT FROM 'delete' OR op.entity_type IS DISTINCT FROM 'credentials'
        OR op.credential_kind IS DISTINCT FROM c.credential_kind OR op.parent_id IS DISTINCT FROM c.consumer_id::text
        OR op.entity_id IS DISTINCT FROM c.kong_id::text OR op.workflow_id IS DISTINCT FROM c.revoke_workflow_id THEN
        RAISE EXCEPTION 'Historical key revocation requires exact terminal native DELETE and workflow receipts' USING ERRCODE='23514';
      END IF;
    END IF;
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER portal_publication_proofs_terminal AFTER INSERT ON portal_publication_proofs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_visible_state();
CREATE CONSTRAINT TRIGGER portal_publications_proof AFTER INSERT OR UPDATE ON portal_publications DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_visible_state();
CREATE CONSTRAINT TRIGGER portal_grants_visible AFTER INSERT OR UPDATE ON portal_application_grants DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_visible_state();
CREATE CONSTRAINT TRIGGER portal_credentials_visible AFTER INSERT OR UPDATE ON portal_credentials DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_visible_state();

-- Only registered/captured physical aliases participate. DNS/IP guesses are
-- deliberately excluded; an unregistered alias must declare its shared scope.
CREATE FUNCTION m6_portal_scope_alias(candidate_cluster uuid,captured_scope text,owner_cluster uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT candidate_cluster=owner_cluster
    OR EXISTS(SELECT 1 FROM clusters c WHERE c.id=candidate_cluster AND c.transport_scope=captured_scope)
    OR EXISTS(SELECT 1 FROM portal_publications p WHERE p.cluster_id=candidate_cluster AND p.transport_scope=captured_scope)
    OR EXISTS(SELECT 1 FROM portal_application_grants g WHERE g.cluster_id=candidate_cluster AND g.transport_scope=captured_scope)
    OR EXISTS(SELECT 1 FROM metrics_nodes n WHERE n.cluster_id=candidate_cluster AND n.transport_scope=captured_scope)
    OR EXISTS(SELECT 1 FROM clusters c JOIN clusters owner ON owner.id=owner_cluster
      WHERE c.id=candidate_cluster AND rtrim(c.admin_url,'/')=rtrim(owner.admin_url,'/'));
$$;
CREATE INDEX mutation_operations_portal_workflow_evidence ON mutation_operations(workflow_id) WHERE workflow_id IS NOT NULL;
CREATE INDEX mutation_operations_portal_parent_evidence ON mutation_operations(parent_id,cluster_id) WHERE parent_id IS NOT NULL;
CREATE INDEX mutation_operations_portal_entity_evidence ON mutation_operations(entity_type,entity_id,cluster_id) WHERE entity_id IS NOT NULL;
CREATE INDEX portal_grants_reserved_acl ON portal_application_grants(acl_id);
CREATE INDEX portal_credentials_reserved_key ON portal_credentials(kong_id);

CREATE FUNCTION m6_assert_unused_reservation(grant_identity uuid) RETURNS void LANGUAGE plpgsql AS $$
DECLARE g portal_application_grants%ROWTYPE; w workflows%ROWTYPE;
BEGIN
  -- Lock BEFORE testing release state, including an unreleased row. Concurrent
  -- facts and release therefore serialize instead of trusting a stale filter.
  SELECT * INTO g FROM portal_application_grants WHERE id=grant_identity FOR UPDATE;
  IF NOT FOUND OR g.reservation_released_at IS NULL THEN RETURN; END IF;
  -- The runtime uses READ COMMITTED. A repeatable-read snapshot could otherwise
  -- miss a fact committed by a transaction that held this lock first.
  IF current_setting('transaction_isolation')<>'read committed' THEN
    RAISE EXCEPTION 'Reservation proof requires fresh read-committed facts' USING ERRCODE='25001';
  END IF;
  SELECT * INTO w FROM workflows WHERE id=g.workflow_id;
  IF g.state<>'disabled' OR g.current_generation<>0 OR g.current_credential_id IS NOT NULL
    OR g.acl_credential_ref_id IS NOT NULL OR g.workflow_id IS NULL
    OR w.cluster_id IS DISTINCT FROM g.cluster_id OR w.workspace_id IS DISTINCT FROM g.workspace_id
    OR w.kind IS DISTINCT FROM 'portal-credential-issue' OR w.subject_type IS DISTINCT FROM 'portal_application_grants'
    OR w.subject_id IS DISTINCT FROM g.id OR w.state NOT IN ('cancelled','rejected','expired')
    OR EXISTS(SELECT 1 FROM workflows history WHERE history.cluster_id=g.cluster_id AND history.workspace_id=g.workspace_id
      AND history.subject_type='portal_application_grants' AND history.subject_id=g.id
      AND(history.kind<>'portal-credential-issue' OR history.state NOT IN ('cancelled','rejected','expired')))
    OR EXISTS(SELECT 1 FROM workflow_executions e JOIN workflows history ON history.id=e.workflow_id
      WHERE history.cluster_id=g.cluster_id AND history.workspace_id=g.workspace_id
      AND history.subject_type='portal_application_grants' AND history.subject_id=g.id)
    OR EXISTS(SELECT 1 FROM workflow_steps s JOIN workflows history ON history.id=s.workflow_id
      WHERE history.cluster_id=g.cluster_id AND history.workspace_id=g.workspace_id
      AND history.subject_type='portal_application_grants' AND history.subject_id=g.id
      AND(s.state<>'pending' OR s.operation_id IS NOT NULL OR s.receipt_secret IS NOT NULL
        OR s.safe_result<>'{}'::jsonb OR s.started_at IS NOT NULL OR s.completed_at IS NOT NULL
        OR s.after_fingerprint IS NOT NULL OR s.recycle_entry_id IS NOT NULL))
    OR EXISTS(SELECT 1 FROM portal_credentials c WHERE c.grant_id=g.id
      AND(c.state<>'pending' OR c.credential_ref_id IS NOT NULL OR c.issue_operation_id IS NOT NULL
        OR c.revoke_workflow_id IS NOT NULL OR c.revoke_operation_id IS NOT NULL OR c.recycle_entry_id IS NOT NULL
        OR c.last_revealed_at IS NOT NULL OR c.revoked_at IS NOT NULL OR c.deleted_at IS NOT NULL OR c.retention_until IS NOT NULL
        OR NOT EXISTS(SELECT 1 FROM workflows issue WHERE issue.id=c.workflow_id AND issue.cluster_id=g.cluster_id
          AND issue.workspace_id=g.workspace_id AND issue.kind='portal-credential-issue'
          AND issue.subject_type='portal_application_grants' AND issue.subject_id=g.id
          AND issue.state IN ('cancelled','rejected','expired'))))
    OR EXISTS(SELECT 1 FROM credential_refs r WHERE m6_portal_scope_alias(r.cluster_id,g.transport_scope,g.cluster_id)
      AND(r.consumer_id=g.consumer_id OR r.kong_id=g.acl_id
        OR EXISTS(SELECT 1 FROM portal_credentials c WHERE c.grant_id=g.id AND c.kong_id=r.kong_id)))
    OR EXISTS(SELECT 1 FROM mutation_operations op WHERE
      EXISTS(SELECT 1 FROM workflows history WHERE history.id=op.workflow_id AND history.cluster_id=g.cluster_id
        AND history.workspace_id=g.workspace_id AND history.subject_type='portal_application_grants' AND history.subject_id=g.id)
      OR(m6_portal_scope_alias(op.cluster_id,g.transport_scope,g.cluster_id) AND(
        (op.entity_type='consumers' AND op.entity_id=g.consumer_id::text)
        OR(op.entity_type='credentials' AND(op.parent_id=g.consumer_id::text OR op.entity_id=g.acl_id::text
          OR EXISTS(SELECT 1 FROM portal_credentials c WHERE c.grant_id=g.id AND op.entity_id=c.kong_id::text)))))) THEN
    RAISE EXCEPTION 'Reservation release requires terminal, never-executed and fact-free issue history' USING ERRCODE='23514';
  END IF;
END;
$$;

CREATE FUNCTION m6_validate_reservation_history() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE document jsonb; documents jsonb[]; grant_identity uuid; column_name text;
BEGIN
  IF TG_OP='INSERT' THEN documents:=ARRAY[to_jsonb(NEW)];
  ELSIF TG_OP='DELETE' THEN documents:=ARRAY[to_jsonb(OLD)];
  ELSE documents:=ARRAY[to_jsonb(OLD),to_jsonb(NEW)]; END IF;
  FOREACH document IN ARRAY documents LOOP
    FOR grant_identity IN
      SELECT g.id FROM portal_application_grants g WHERE
        (TG_TABLE_NAME='portal_application_grants' AND g.id::text=document->>'id')
        OR(TG_TABLE_NAME='portal_credentials' AND g.id::text=document->>'grant_id')
        OR(TG_TABLE_NAME='workflows' AND document->>'subject_type'='portal_application_grants' AND g.id::text=document->>'subject_id')
        OR(TG_TABLE_NAME IN ('workflow_executions','workflow_steps') AND EXISTS(SELECT 1 FROM workflows w
          WHERE w.id::text=document->>'workflow_id' AND w.subject_type='portal_application_grants' AND w.subject_id=g.id))
        OR(TG_TABLE_NAME='mutation_operations' AND(
          EXISTS(SELECT 1 FROM workflows w WHERE w.id::text=document->>'workflow_id' AND w.subject_type='portal_application_grants' AND w.subject_id=g.id)
          OR(m6_portal_scope_alias((document->>'cluster_id')::uuid,g.transport_scope,g.cluster_id) AND(
            (document->>'entity_type'='consumers' AND document->>'entity_id'=g.consumer_id::text)
            OR(document->>'entity_type'='credentials' AND(document->>'parent_id'=g.consumer_id::text OR document->>'entity_id'=g.acl_id::text
              OR EXISTS(SELECT 1 FROM portal_credentials c WHERE c.grant_id=g.id AND c.kong_id::text=document->>'entity_id')))))))
        OR(TG_TABLE_NAME='credential_refs' AND m6_portal_scope_alias((document->>'cluster_id')::uuid,g.transport_scope,g.cluster_id)
          AND(document->>'consumer_id'=g.consumer_id::text OR document->>'kong_id'=g.acl_id::text
            OR EXISTS(SELECT 1 FROM portal_credentials c WHERE c.grant_id=g.id AND c.kong_id::text=document->>'kong_id')))
      ORDER BY g.id
    LOOP
      IF TG_OP='DELETE' AND TG_TABLE_NAME IN ('mutation_operations','credential_refs') THEN
        RAISE EXCEPTION 'Reserved portal native evidence must be retained' USING ERRCODE='42501';
      END IF;
      IF TG_OP='UPDATE' AND document=to_jsonb(OLD) AND TG_TABLE_NAME IN ('mutation_operations','credential_refs') THEN
        FOREACH column_name IN ARRAY CASE WHEN TG_TABLE_NAME='credential_refs'
          THEN ARRAY['cluster_id','consumer_id','kong_id','credential_type']
          ELSE ARRAY['cluster_id','entity_type','entity_id','parent_id','credential_kind','workflow_id','workflow_step_id','workflow_execution_id','transport_scope'] END
        LOOP
          IF to_jsonb(OLD)->column_name IS NOT NULL AND to_jsonb(OLD)->column_name<>'null'::jsonb
            AND to_jsonb(NEW)->column_name IS DISTINCT FROM to_jsonb(OLD)->column_name THEN
            RAISE EXCEPTION 'Reserved portal native evidence identity cannot be replaced' USING ERRCODE='23514';
          END IF;
        END LOOP;
      END IF;
      PERFORM m6_assert_unused_reservation(grant_identity);
    END LOOP;
  END LOOP;
  RETURN NULL;
END;
$$;
DO $$DECLARE tab text;BEGIN
  FOREACH tab IN ARRAY ARRAY['portal_application_grants','portal_credentials','workflows','workflow_executions','workflow_steps','mutation_operations','credential_refs'] LOOP
    EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m6_validate_reservation_history()',tab||'_reservation_history',tab);
  END LOOP;
END;$$;

CREATE FUNCTION m6_reject_released_reservation_allocations() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE grant_identity uuid; released_at timestamptz;
BEGIN
  IF TG_TABLE_NAME='portal_credentials' THEN grant_identity:=NEW.grant_id;
  ELSIF NEW.subject_type='portal_application_grants' THEN grant_identity:=NEW.subject_id;
  ELSE RETURN NEW; END IF;
  SELECT reservation_released_at INTO released_at FROM portal_application_grants WHERE id=grant_identity FOR UPDATE;
  IF released_at IS NOT NULL THEN
    RAISE EXCEPTION 'Released reservation cannot allocate another workflow or key identity' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;$$;
CREATE TRIGGER portal_credentials_no_released_allocation BEFORE INSERT ON portal_credentials
  FOR EACH ROW EXECUTE FUNCTION m6_reject_released_reservation_allocations();
CREATE TRIGGER workflows_no_released_allocation BEFORE INSERT ON workflows
  FOR EACH ROW EXECUTE FUNCTION m6_reject_released_reservation_allocations();

CREATE FUNCTION m6_expired_refresh_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='UPDATE' OR OLD.expires_at>clock_timestamp() THEN
    RAISE EXCEPTION 'Used refresh history cannot change before expiry' USING ERRCODE='42501';
  END IF;
  RETURN OLD;
END;
$$;
CREATE TRIGGER portal_refresh_history_immutable BEFORE UPDATE OR DELETE ON portal_refresh_history FOR EACH ROW EXECUTE FUNCTION m6_expired_refresh_cleanup();
CREATE TRIGGER portal_refresh_history_no_truncate BEFORE TRUNCATE ON portal_refresh_history FOR EACH STATEMENT EXECUTE FUNCTION m6_reject_history_mutation();

-- Runtime role provisioning must repeat these restrictions after its broad grants.
-- Triggers also protect history when a role is accidentally granted CRUD.
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON workflow_definition_versions,workflow_definition_stages,workflow_versions,workflow_approvals,workflow_events,portal_publication_revisions,portal_publication_proofs,portal_content_revisions FROM PUBLIC;
