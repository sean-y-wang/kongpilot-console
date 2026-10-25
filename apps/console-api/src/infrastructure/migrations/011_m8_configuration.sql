-- Configuration content is encrypted per artifact. Finalized content is append-only,
-- including for the migration owner. Ciphertext remains after wrapped-DEK destruction.
CREATE FUNCTION m8_hex64(v text) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT v ~ '^[a-f0-9]{64}$' $$;
CREATE FUNCTION m8_cipher(v text) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT v ~ '^c1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' AND octet_length(v)<=50332000 $$;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_m8_user_unique UNIQUE(id,user_id);
-- A configuration wrapper contains one fixed metadata handler. Its approved DAG
-- lives in SQL011; all existing V1 step/packet CHECK constraints stay unchanged.
ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_kind_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata'));
ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_code_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_code_check CHECK(code ~ '^[a-z][a-z0-9-]{0,79}$' OR(code='configuration_v2' AND kind='configuration_v2'));
ALTER TABLE workflows DROP CONSTRAINT workflows_kind_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries','configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs'));

CREATE TABLE configuration_jobs (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,transport_scope text NOT NULL CHECK(m8_hex64(transport_scope)),
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,origin_type text NOT NULL DEFAULT 'http' CHECK(origin_type IN('http','schedule','pipeline')),
 origin_session_id uuid,authority_expires_at timestamptz NOT NULL,kind text NOT NULL CHECK(kind IN('capture','import','compare','export','apply','rollback','reconcile')),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 request_id text CHECK(length(request_id)<=128),scope_kind text NOT NULL CHECK(scope_kind IN('cluster','workspace','services')),
 root_ids uuid[] NOT NULL DEFAULT '{}' CHECK(cardinality(root_ids)<=100 AND array_position(root_ids,NULL) IS NULL),
 input_secret text CHECK(input_secret IS NULL OR m6_encrypted(input_secret)),permission_version text NOT NULL CHECK(length(permission_version) BETWEEN 1 AND 256),
 credential_epoch integer NOT NULL CHECK(credential_epoch>0),cluster_revision integer NOT NULL CHECK(cluster_revision>0),workspace_revision integer NOT NULL CHECK(workspace_revision>0),
 capture_epoch text NOT NULL CHECK(length(capture_epoch) BETWEEN 1 AND 256),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','running','waiting_approval','succeeded','partial','failed','uncertain','cancelled','expired')),
 execution_mode text NOT NULL CHECK(execution_mode IN('direct','approval')),approval_required boolean NOT NULL DEFAULT false,
 plan_id uuid,plan_revision integer,plan_hash text CHECK(plan_hash IS NULL OR m8_hex64(plan_hash)),workflow_id uuid,
 lease_owner_hash text CHECK(lease_owner_hash IS NULL OR m8_hex64(lease_owner_hash)),lease_generation integer NOT NULL DEFAULT 1 CHECK(lease_generation>0),lease_until timestamptz,
 remote_started boolean NOT NULL DEFAULT false,remote_completed boolean NOT NULL DEFAULT false,
 safe_progress jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(safe_progress)='object' AND octet_length(safe_progress::text)<=131072),
 error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),started_at timestamptz,completed_at timestamptz,
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,id,actor_id),UNIQUE(cluster_id,workspace_id,actor_id,idempotency_key),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(origin_session_id,actor_id) REFERENCES auth_sessions(id,user_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK((origin_type='schedule' AND kind='capture' AND origin_session_id IS NULL) OR(origin_type<>'schedule' AND origin_session_id IS NOT NULL)),
 CHECK((scope_kind='services')=(cardinality(root_ids)>0)),CHECK(num_nonnulls(plan_id,plan_revision,plan_hash) IN(0,3)),
 CHECK(NOT remote_completed OR remote_started),CHECK(state<>'uncertain' OR NOT remote_completed),
 CHECK(expires_at>created_at AND authority_expires_at>created_at AND updated_at>=created_at)
);
CREATE INDEX configuration_jobs_actor ON configuration_jobs(cluster_id,workspace_id,actor_id,created_at DESC,id DESC);
CREATE TABLE configuration_materials (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,
 artifact_kind text NOT NULL CHECK(artifact_kind IN('snapshot','plan','import','export')),artifact_id uuid NOT NULL,
 wrapped_key_secret text CHECK(wrapped_key_secret IS NULL OR m6_encrypted(wrapped_key_secret)),
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),state text NOT NULL DEFAULT 'available' CHECK(state IN('available','destroyed')),
 created_at timestamptz NOT NULL DEFAULT now(),destroyed_at timestamptz,
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,job_id,artifact_id,artifact_kind,id),
 FOREIGN KEY(cluster_id,workspace_id,job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK((state='available' AND wrapped_key_secret IS NOT NULL AND destroyed_at IS NULL) OR(state='destroyed' AND wrapped_key_secret IS NULL AND destroyed_at IS NOT NULL))
);
CREATE TABLE config_snapshots (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,transport_scope text NOT NULL CHECK(m8_hex64(transport_scope)),
 created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),description text NOT NULL DEFAULT '' CHECK(length(description)<=8192),
 scope_kind text NOT NULL CHECK(scope_kind IN('cluster','workspace','services')),root_ids uuid[] NOT NULL DEFAULT '{}',
 current_version integer CHECK(current_version IS NULL OR current_version>0),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 state text NOT NULL DEFAULT 'capturing' CHECK(state IN('capturing','ready','incomplete','failed','deleted','expired')),
 deleted_at timestamptz,retention_until timestamptz,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK((state='deleted')=(deleted_at IS NOT NULL)),CHECK((scope_kind='services')=(cardinality(root_ids)>0))
);
CREATE INDEX config_snapshots_list ON config_snapshots(cluster_id,workspace_id,created_at DESC,id DESC);
CREATE TABLE config_snapshot_versions (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,snapshot_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),version_id uuid NOT NULL UNIQUE,
 source_job_id uuid NOT NULL,material_id uuid NOT NULL,artifact_kind text GENERATED ALWAYS AS('snapshot') STORED,
 manifest_hmac text NOT NULL CHECK(m8_hex64(manifest_hmac)),manifest_ciphertext text NOT NULL CHECK(m8_cipher(manifest_ciphertext)),
 completeness text NOT NULL CHECK(completeness='complete'),consistency text NOT NULL CHECK(consistency='console_fenced_best_effort'),
 observed_from timestamptz NOT NULL,observed_until timestamptz NOT NULL,kong_version text NOT NULL CHECK(kong_version ~ '^1\.5\.\d+$'),
 adapter_version text NOT NULL,schema_hmac text NOT NULL CHECK(m8_hex64(schema_hmac)),permission_version text NOT NULL,capture_epoch text NOT NULL,
 object_count integer NOT NULL CHECK(object_count BETWEEN 0 AND 10000),secret_count integer NOT NULL CHECK(secret_count BETWEEN 0 AND 10000),
 page_count integer NOT NULL CHECK(page_count BETWEEN 1 AND 100),record_count integer NOT NULL CHECK(record_count BETWEEN 0 AND 10000),
 byte_count bigint NOT NULL CHECK(byte_count BETWEEN 0 AND 33554432),native_call_count integer NOT NULL CHECK(native_call_count BETWEEN 1 AND 500),
 stored_page_count integer NOT NULL CHECK(stored_page_count BETWEEN 1 AND page_count),stored_record_count integer NOT NULL CHECK(stored_record_count BETWEEN 0 AND record_count),
 stored_byte_count bigint NOT NULL CHECK(stored_byte_count BETWEEN 0 AND byte_count),
 required_collections text[] NOT NULL CHECK(cardinality(required_collections) BETWEEN 1 AND 10000),
 recovery_summary jsonb NOT NULL CHECK(jsonb_typeof(recovery_summary)='object'),warning_codes text[] NOT NULL DEFAULT '{}',created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,snapshot_id,version),UNIQUE(cluster_id,workspace_id,version_id),UNIQUE(cluster_id,workspace_id,version_id,manifest_hmac),
 FOREIGN KEY(cluster_id,workspace_id,snapshot_id) REFERENCES config_snapshots(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,source_job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,source_job_id,version_id,artifact_kind,material_id) REFERENCES configuration_materials(cluster_id,workspace_id,job_id,artifact_id,artifact_kind,id) ON DELETE RESTRICT,
 CHECK(observed_until>=observed_from AND observed_until-observed_from<=interval '120 seconds')
);
ALTER TABLE config_snapshots ADD CONSTRAINT config_snapshots_current_fk FOREIGN KEY(cluster_id,workspace_id,id,current_version)
 REFERENCES config_snapshot_versions(cluster_id,workspace_id,snapshot_id,version) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE configuration_job_pages (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,collection_key text NOT NULL CHECK(length(collection_key) BETWEEN 1 AND 256),
 page_no integer NOT NULL CHECK(page_no BETWEEN 1 AND 100),query_hmac text NOT NULL CHECK(m8_hex64(query_hmac)),cursor_hmac text NOT NULL CHECK(m8_hex64(cursor_hmac)),
 next_cursor_ciphertext text CHECK(next_cursor_ciphertext IS NULL OR m8_cipher(next_cursor_ciphertext)),page_ciphertext text NOT NULL CHECK(m8_cipher(page_ciphertext)),
 record_count integer NOT NULL CHECK(record_count BETWEEN 0 AND 100),byte_count integer NOT NULL CHECK(byte_count BETWEEN 0 AND 33554432),terminal_observed boolean NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(cluster_id,workspace_id,job_id,collection_key,page_no),
 FOREIGN KEY(cluster_id,workspace_id,job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK(terminal_observed=(next_cursor_ciphertext IS NULL))
);
CREATE TABLE configuration_staged_objects (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,object_key text NOT NULL CHECK(length(object_key) BETWEEN 1 AND 256),
 entity_type text NOT NULL CHECK(entity_type IN('services','routes','consumers','plugins','upstreams','targets','certificates','ca_certificates','snis','credentials')),
 native_id uuid NOT NULL,parent_type text,parent_id uuid,credential_kind text CHECK(credential_kind IS NULL OR credential_kind IN('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')),
 object_workspace_id uuid NOT NULL,reference_only boolean NOT NULL,affected boolean NOT NULL,dependencies text[] NOT NULL,
 payload_ciphertext text NOT NULL CHECK(m8_cipher(payload_ciphertext)),before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),schema_hmac text NOT NULL CHECK(m8_hex64(schema_hmac)),
 recovery_state text NOT NULL CHECK(recovery_state IN('complete','requires_secret_input','requires_rotation','nonrestorable')),created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,job_id,object_key),UNIQUE(cluster_id,workspace_id,job_id,entity_type,parent_id,credential_kind,native_id),
 FOREIGN KEY(cluster_id,workspace_id,job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,object_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK((entity_type='credentials' AND parent_type='consumers' AND parent_id IS NOT NULL AND credential_kind IS NOT NULL)
 OR(entity_type='targets' AND parent_type='upstreams' AND parent_id IS NOT NULL AND credential_kind IS NULL)
 OR(entity_type NOT IN('credentials','targets') AND credential_kind IS NULL)),CHECK(NOT reference_only OR NOT affected)
);
CREATE TABLE configuration_staged_collections (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,collection_key text NOT NULL,
 entity_type text NOT NULL,parent_id uuid,credential_kind text,query_hmac text NOT NULL CHECK(m8_hex64(query_hmac)),page_size integer NOT NULL CHECK(page_size BETWEEN 1 AND 100),
 page_count integer NOT NULL CHECK(page_count BETWEEN 1 AND 100),record_count integer NOT NULL CHECK(record_count BETWEEN 0 AND 10000),terminal_observed boolean NOT NULL CHECK(terminal_observed),
 cursor_chain_hmac text NOT NULL CHECK(m8_hex64(cursor_chain_hmac)),coverage_hmac text NOT NULL CHECK(m8_hex64(coverage_hmac)),created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,job_id,collection_key),FOREIGN KEY(cluster_id,workspace_id,job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT
);
CREATE TABLE config_snapshot_collections (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,version_id uuid NOT NULL,collection_key text NOT NULL,
 entity_type text NOT NULL,parent_id uuid,credential_kind text,query_hmac text NOT NULL CHECK(m8_hex64(query_hmac)),page_size integer NOT NULL CHECK(page_size BETWEEN 1 AND 100),
 page_count integer NOT NULL CHECK(page_count BETWEEN 1 AND 100),record_count integer NOT NULL CHECK(record_count BETWEEN 0 AND 10000),terminal_observed boolean NOT NULL CHECK(terminal_observed),
 cursor_chain_hmac text NOT NULL CHECK(m8_hex64(cursor_chain_hmac)),coverage_hmac text NOT NULL CHECK(m8_hex64(coverage_hmac)),created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,version_id,collection_key),FOREIGN KEY(cluster_id,workspace_id,version_id) REFERENCES config_snapshot_versions(cluster_id,workspace_id,version_id) ON DELETE RESTRICT
);
CREATE TABLE config_snapshot_objects (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,version_id uuid NOT NULL,object_key text NOT NULL,
 entity_type text NOT NULL,native_id uuid NOT NULL,parent_type text,parent_id uuid,credential_kind text,
 object_workspace_id uuid NOT NULL,reference_only boolean NOT NULL,affected boolean NOT NULL,dependencies text[] NOT NULL,
 payload_ciphertext text NOT NULL CHECK(m8_cipher(payload_ciphertext)),before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),schema_hmac text NOT NULL CHECK(m8_hex64(schema_hmac)),
 recovery_state text NOT NULL CHECK(recovery_state IN('complete','requires_secret_input','requires_rotation','nonrestorable')),created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,version_id,object_key),FOREIGN KEY(cluster_id,workspace_id,version_id) REFERENCES config_snapshot_versions(cluster_id,workspace_id,version_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,object_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,CHECK(NOT reference_only OR NOT affected)
);

CREATE TABLE configuration_plans (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,transport_scope text NOT NULL CHECK(m8_hex64(transport_scope)),
 created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,source_job_id uuid NOT NULL,mode text NOT NULL CHECK(mode IN('merge','sync','rollback')),
 current_revision integer NOT NULL DEFAULT 1 CHECK(current_revision>0),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 state text NOT NULL DEFAULT 'ready' CHECK(state IN('draft','ready','pending_approval','approved','executing','succeeded','partial','failed','uncertain','cancelled','expired')),
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id,source_job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT
);
CREATE TABLE configuration_plan_versions (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,plan_id uuid NOT NULL,plan_revision integer NOT NULL CHECK(plan_revision>0),plan_hash text NOT NULL CHECK(m8_hex64(plan_hash)),
 source_job_id uuid NOT NULL,material_id uuid NOT NULL,artifact_id uuid NOT NULL,artifact_kind text GENERATED ALWAYS AS('plan') STORED,
 manifest_ciphertext text NOT NULL CHECK(m8_cipher(manifest_ciphertext)),input_hmac text NOT NULL CHECK(m8_hex64(input_hmac)),steps_hmac text NOT NULL CHECK(m8_hex64(steps_hmac)),
 source_manifest_hmac text NOT NULL CHECK(m8_hex64(source_manifest_hmac)),baseline_manifest_hmac text NOT NULL CHECK(m8_hex64(baseline_manifest_hmac)),
 cluster_revision integer NOT NULL CHECK(cluster_revision>0),workspace_revision integer NOT NULL CHECK(workspace_revision>0),permission_version text NOT NULL,
 kong_version text NOT NULL CHECK(kong_version ~ '^1\.5\.\d+$'),schema_hmac text NOT NULL CHECK(m8_hex64(schema_hmac)),
 step_count integer NOT NULL CHECK(step_count BETWEEN 0 AND 10000),native_packet_count integer NOT NULL CHECK(native_packet_count BETWEEN 0 AND 500),delete_count integer NOT NULL CHECK(delete_count BETWEEN 0 AND step_count),
 recovery_complete boolean NOT NULL,expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,plan_id,plan_revision),UNIQUE(cluster_id,workspace_id,plan_id,plan_revision,plan_hash),
 FOREIGN KEY(cluster_id,workspace_id,plan_id) REFERENCES configuration_plans(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,source_job_id,artifact_id,artifact_kind,material_id) REFERENCES configuration_materials(cluster_id,workspace_id,job_id,artifact_id,artifact_kind,id) ON DELETE RESTRICT
);
ALTER TABLE configuration_plans ADD CONSTRAINT configuration_plans_current_fk FOREIGN KEY(cluster_id,workspace_id,id,current_revision)
 REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE configuration_jobs ADD CONSTRAINT configuration_jobs_plan_fk FOREIGN KEY(cluster_id,workspace_id,plan_id,plan_revision,plan_hash)
 REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE configuration_plan_objects (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,plan_id uuid NOT NULL,plan_revision integer NOT NULL,plan_hash text NOT NULL,step_id uuid NOT NULL,
 step_order integer NOT NULL CHECK(step_order BETWEEN 1 AND 10000),object_key text NOT NULL,entity_type text NOT NULL,object_workspace_id uuid NOT NULL,native_id uuid,allocated_native_id uuid,
 parent_type text,parent_id uuid,credential_kind text,permission_action text NOT NULL CHECK(permission_action IN('write','delete')),
 mutation_action text NOT NULL CHECK(mutation_action IN('create','update','delete')),body_hmac text NOT NULL CHECK(m8_hex64(body_hmac)),before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),
 dependencies uuid[] NOT NULL DEFAULT '{}' CHECK(cardinality(dependencies)<=10000 AND array_position(dependencies,NULL) IS NULL),
 payload_ciphertext text NOT NULL CHECK(m8_cipher(payload_ciphertext)),native_requests jsonb NOT NULL CHECK(jsonb_typeof(native_requests)='array' AND jsonb_array_length(native_requests)<=32),
 reference_only boolean NOT NULL,blocker_codes text[] NOT NULL DEFAULT '{}',masked_diff jsonb NOT NULL CHECK(jsonb_typeof(masked_diff)='array' AND octet_length(masked_diff::text)<=131072),
 created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(cluster_id,workspace_id,plan_id,plan_revision,step_id),UNIQUE(cluster_id,workspace_id,plan_id,plan_revision,step_order),
 UNIQUE(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,step_id),
 UNIQUE(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,step_id,object_workspace_id),
 FOREIGN KEY(cluster_id,object_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 CHECK((permission_action='delete')=(mutation_action='delete')),CHECK(NOT reference_only OR jsonb_array_length(native_requests)=0)
);
CREATE TABLE configuration_executions (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,plan_id uuid NOT NULL,plan_revision integer NOT NULL,plan_hash text NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,workflow_id uuid,approved_version integer,workflow_plan_hash text,
 execution_mode text NOT NULL CHECK(execution_mode IN('direct','approval')),claim_hash text NOT NULL CHECK(m8_hex64(claim_hash)),
 state text NOT NULL DEFAULT 'claimed' CHECK(state IN('claimed','executing','succeeded','partial','failed','uncertain')),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 permission_version text NOT NULL,before_snapshot_id uuid NOT NULL,before_snapshot_version integer NOT NULL,lease_generation integer NOT NULL CHECK(lease_generation>0),
 expires_at timestamptz NOT NULL,started_at timestamptz NOT NULL DEFAULT now(),completed_at timestamptz,
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,id,job_id,plan_revision,plan_hash),
 UNIQUE(cluster_id,id,job_id,plan_revision,plan_hash),
 UNIQUE(cluster_id,workspace_id,job_id),
 FOREIGN KEY(cluster_id,workspace_id,job_id,actor_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id,actor_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,before_snapshot_id,before_snapshot_version) REFERENCES config_snapshot_versions(cluster_id,workspace_id,snapshot_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,approved_version,workflow_plan_hash) REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 CHECK((execution_mode='direct' AND num_nonnulls(workflow_id,approved_version,workflow_plan_hash)=0) OR(execution_mode='approval' AND num_nonnulls(workflow_id,approved_version,workflow_plan_hash)=3))
);
CREATE TABLE configuration_job_steps (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,execution_id uuid NOT NULL,
 plan_id uuid NOT NULL,plan_revision integer NOT NULL,plan_hash text NOT NULL,plan_step_id uuid NOT NULL,step_order integer NOT NULL,object_workspace_id uuid NOT NULL,
 approval_required boolean NOT NULL,state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','running','succeeded','failed','uncertain','skipped')),
 operation_id uuid UNIQUE,receipt_operation_id uuid,receipt_ciphertext text CHECK(receipt_ciphertext IS NULL OR m8_cipher(receipt_ciphertext)),recycle_entry_id uuid,
 before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),after_hmac text CHECK(after_hmac IS NULL OR m8_hex64(after_hmac)),original_native_id uuid,effective_native_id uuid,
 safe_result jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(safe_result)='object' AND octet_length(safe_result::text)<=131072),error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),created_at timestamptz NOT NULL DEFAULT now(),started_at timestamptz,completed_at timestamptz,
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,object_workspace_id,id,job_id,execution_id,plan_revision,plan_hash,operation_id),
 UNIQUE(cluster_id,workspace_id,job_id,execution_id,plan_step_id),
 FOREIGN KEY(cluster_id,workspace_id,execution_id,job_id,plan_revision,plan_hash) REFERENCES configuration_executions(cluster_id,workspace_id,id,job_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,plan_step_id,object_workspace_id) REFERENCES configuration_plan_objects(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,step_id,object_workspace_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,recycle_entry_id) REFERENCES recycle_entries(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,receipt_operation_id) REFERENCES mutation_operations(cluster_id,id) ON DELETE RESTRICT,
 CHECK(operation_id IS NULL OR approval_required),CHECK(state<>'succeeded' OR(receipt_ciphertext IS NOT NULL AND after_hmac IS NOT NULL))
);
CREATE TABLE configuration_job_attempts (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,execution_id uuid,step_id uuid,
 attempt_no integer NOT NULL CHECK(attempt_no>0),lease_generation integer NOT NULL CHECK(lease_generation>0),phase text NOT NULL CHECK(phase ~ '^[a-z_]{1,64}$'),
 result text NOT NULL CHECK(result IN('started','succeeded','failed','uncertain')),error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),duration_ms integer CHECK(duration_ms>=0),created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(cluster_id,workspace_id,job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,execution_id) REFERENCES configuration_executions(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,step_id) REFERENCES configuration_job_steps(cluster_id,workspace_id,id) ON DELETE RESTRICT
);

CREATE TABLE configuration_exports (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,artifact_id uuid NOT NULL,material_id uuid NOT NULL,
 artifact_kind text GENERATED ALWAYS AS('export') STORED,source_snapshot_id uuid,source_version integer,
 format text NOT NULL CHECK(format IN('deck-1.1','review-json')),mode text NOT NULL CHECK(mode IN('review','deployment')),manifest_hmac text NOT NULL CHECK(m8_hex64(manifest_hmac)),
 payload_ciphertext text NOT NULL CHECK(m8_cipher(payload_ciphertext)),byte_count integer NOT NULL CHECK(byte_count BETWEEN 0 AND 33554432),
 expires_at timestamptz NOT NULL,state text NOT NULL DEFAULT 'ready' CHECK(state IN('ready','expired','destroyed')),created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),FOREIGN KEY(cluster_id,workspace_id,job_id,artifact_id,artifact_kind,material_id) REFERENCES configuration_materials(cluster_id,workspace_id,job_id,artifact_id,artifact_kind,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,source_snapshot_id,source_version) REFERENCES config_snapshot_versions(cluster_id,workspace_id,snapshot_id,version) ON DELETE RESTRICT,
 CHECK(num_nonnulls(source_snapshot_id,source_version) IN(0,2))
);
CREATE TABLE configuration_imports (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,artifact_id uuid NOT NULL,material_id uuid NOT NULL,
 artifact_kind text GENERATED ALWAYS AS('import') STORED,manifest_hmac text NOT NULL CHECK(m8_hex64(manifest_hmac)),payload_ciphertext text NOT NULL CHECK(m8_cipher(payload_ciphertext)),created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,job_id,artifact_id),FOREIGN KEY(cluster_id,workspace_id,job_id,artifact_id,artifact_kind,material_id)
 REFERENCES configuration_materials(cluster_id,workspace_id,job_id,artifact_id,artifact_kind,id) ON DELETE RESTRICT
);
CREATE TABLE configuration_download_grants (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,export_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,session_id uuid NOT NULL,
 artifact_hmac text NOT NULL CHECK(m8_hex64(artifact_hmac)),permission_version text NOT NULL,token_hash text NOT NULL CHECK(m8_hex64(token_hash)),
 state text NOT NULL DEFAULT 'ready' CHECK(state IN('ready','consumed','revoked','expired')),expires_at timestamptz NOT NULL,consumed_at timestamptz,created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(cluster_id,workspace_id,export_id) REFERENCES configuration_exports(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(session_id,actor_id) REFERENCES auth_sessions(id,user_id) ON DELETE RESTRICT,CHECK((state='consumed')=(consumed_at IS NOT NULL))
);
CREATE TABLE configuration_deck_sessions (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,transport_scope text NOT NULL CHECK(m8_hex64(transport_scope)),actor_id uuid NOT NULL,session_id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose IN('read','write')),token_hash text NOT NULL CHECK(m8_hex64(token_hash)),credential_epoch integer NOT NULL CHECK(credential_epoch>0),permission_version text NOT NULL,
 job_id uuid NOT NULL,plan_id uuid,plan_revision integer,plan_hash text,revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 state text NOT NULL DEFAULT 'active' CHECK(state IN('active','revoked','expired','budget_exceeded')),expires_at timestamptz NOT NULL,revoked_at timestamptz,
 budget_pages integer NOT NULL DEFAULT 0 CHECK(budget_pages BETWEEN 0 AND 100),budget_records integer NOT NULL DEFAULT 0 CHECK(budget_records BETWEEN 0 AND 10000),
 budget_bytes bigint NOT NULL DEFAULT 0 CHECK(budget_bytes BETWEEN 0 AND 33554432),budget_calls integer NOT NULL DEFAULT 0 CHECK(budget_calls BETWEEN 0 AND 500),created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),FOREIGN KEY(cluster_id,workspace_id,job_id,actor_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id,actor_id) ON DELETE RESTRICT,
 FOREIGN KEY(session_id,actor_id) REFERENCES auth_sessions(id,user_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) REFERENCES configuration_plan_versions(cluster_id,workspace_id,plan_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 CHECK((purpose='read' AND num_nonnulls(plan_id,plan_revision,plan_hash)=0) OR(purpose='write' AND num_nonnulls(plan_id,plan_revision,plan_hash)=3))
);
CREATE TABLE configuration_gitops_runs (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,job_id uuid NOT NULL,created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 repository_label text NOT NULL CHECK(repository_label ~ '^[A-Za-z0-9_. /-]{1,128}$'),commit_sha text NOT NULL CHECK(commit_sha ~ '^([a-f0-9]{40}|[a-f0-9]{64})$'),
 pipeline_reference text NOT NULL CHECK(length(pipeline_reference) BETWEEN 1 AND 256 AND pipeline_reference ~ '^[A-Za-z0-9_. /:#-]+$'),created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(cluster_id,workspace_id,job_id,created_by) REFERENCES configuration_jobs(cluster_id,workspace_id,id,actor_id) ON DELETE RESTRICT
);
CREATE TABLE config_snapshot_schedules (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,transport_scope text NOT NULL CHECK(m8_hex64(transport_scope)),name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,current_version integer NOT NULL DEFAULT 1 CHECK(current_version>0),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 state text NOT NULL DEFAULT 'active' CHECK(state IN('active','paused','deleted')),next_run_at timestamptz NOT NULL,deleted_at timestamptz,purged_at timestamptz,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,CHECK((state='deleted')=(deleted_at IS NOT NULL)),CHECK(purged_at IS NULL OR state='deleted')
);
CREATE TABLE config_snapshot_schedule_versions (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),scope_kind text NOT NULL CHECK(scope_kind IN('cluster','workspace','services')),
 root_ids uuid[] NOT NULL DEFAULT '{}',interval_minutes integer NOT NULL CHECK(interval_minutes BETWEEN 5 AND 10080),timezone text NOT NULL DEFAULT 'UTC',retention_days integer NOT NULL CHECK(retention_days BETWEEN 1 AND 3650),
 policy_hmac text NOT NULL CHECK(m8_hex64(policy_hmac)),created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,schedule_id,version),FOREIGN KEY(cluster_id,workspace_id,schedule_id) REFERENCES config_snapshot_schedules(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK((scope_kind='services')=(cardinality(root_ids)>0))
);
ALTER TABLE config_snapshot_schedules ADD CONSTRAINT config_snapshot_schedules_current_fk FOREIGN KEY(cluster_id,workspace_id,id,current_version)
 REFERENCES config_snapshot_schedule_versions(cluster_id,workspace_id,schedule_id,version) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE config_snapshot_schedule_runs (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,schedule_id uuid NOT NULL,schedule_version integer NOT NULL,scheduled_at timestamptz NOT NULL,
 creator_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,job_id uuid,state text NOT NULL CHECK(state IN('pending','running','succeeded','failed','paused')),
 reason_code text CHECK(reason_code IS NULL OR reason_code ~ '^[A-Z0-9_]{1,128}$'),permission_version text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),completed_at timestamptz,
 UNIQUE(cluster_id,workspace_id,schedule_id,schedule_version,scheduled_at),FOREIGN KEY(cluster_id,workspace_id,schedule_id,schedule_version) REFERENCES config_snapshot_schedule_versions(cluster_id,workspace_id,schedule_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,job_id,creator_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id,actor_id) ON DELETE RESTRICT
);

CREATE FUNCTION m8_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Configuration content is append only' USING ERRCODE='23514'; END; $$;
DO $$DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['configuration_job_pages','configuration_staged_objects','configuration_staged_collections',
 'config_snapshot_versions','config_snapshot_collections','config_snapshot_objects','configuration_plan_versions','configuration_plan_objects','configuration_job_attempts','configuration_gitops_runs','config_snapshot_schedule_versions','configuration_imports']
 LOOP EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);END LOOP;END;$$;
CREATE FUNCTION m8_guard_material() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Material history cannot be deleted' USING ERRCODE='23514';END IF;
 IF ROW(NEW.id,NEW.cluster_id,NEW.workspace_id,NEW.job_id,NEW.artifact_kind,NEW.artifact_id,NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.cluster_id,OLD.workspace_id,OLD.job_id,OLD.artifact_kind,OLD.artifact_id,OLD.created_at)
 OR OLD.state<>'available' OR NEW.state<>'destroyed' OR NEW.wrapped_key_secret IS NOT NULL OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'Material can only destroy its wrapped key once' USING ERRCODE='23514';END IF;RETURN NEW;END;$$;
CREATE TRIGGER configuration_materials_guard BEFORE UPDATE OR DELETE ON configuration_materials FOR EACH ROW EXECUTE FUNCTION m8_guard_material();
CREATE FUNCTION m8_guard_staging() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE j configuration_jobs%ROWTYPE;BEGIN
 SELECT * INTO j FROM configuration_jobs WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.job_id FOR UPDATE;
 IF j.id IS NULL OR j.kind<>'capture' OR j.state NOT IN('pending','running') OR j.expires_at<=now() THEN RAISE EXCEPTION 'Capture staging is already sealed or unavailable' USING ERRCODE='23514';END IF;RETURN NEW;END;$$;
DO $$DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['configuration_job_pages','configuration_staged_objects','configuration_staged_collections'] LOOP
 EXECUTE format('CREATE TRIGGER %I BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION m8_guard_staging()',tab||'_seal_guard',tab);END LOOP;END;$$;
CREATE FUNCTION m8_guard_final_insert() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE j configuration_jobs%ROWTYPE;v config_snapshot_versions%ROWTYPE;BEGIN
 SELECT * INTO v FROM config_snapshot_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND version_id=NEW.version_id;
 SELECT * INTO j FROM configuration_jobs WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND id=v.source_job_id FOR UPDATE;
 IF j.id IS NULL OR j.state NOT IN('pending','running') THEN RAISE EXCEPTION 'Final snapshot manifest cannot grow after publication' USING ERRCODE='23514';END IF;RETURN NEW;END;$$;
CREATE TRIGGER config_snapshot_collections_freeze BEFORE INSERT ON config_snapshot_collections FOR EACH ROW EXECUTE FUNCTION m8_guard_final_insert();
CREATE TRIGGER config_snapshot_objects_freeze BEFORE INSERT ON config_snapshot_objects FOR EACH ROW EXECUTE FUNCTION m8_guard_final_insert();
CREATE FUNCTION m8_validate_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE v config_snapshot_versions%ROWTYPE;n integer;p integer;r integer;k text;dep text;o record;BEGIN
 IF TG_TABLE_NAME='config_snapshot_versions' THEN v=NEW;ELSE SELECT * INTO v FROM config_snapshot_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND version_id=NEW.version_id;END IF;
 SELECT count(*)::integer INTO n FROM config_snapshot_objects WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND version_id=v.version_id;
 SELECT coalesce(sum(page_count),0)::integer,coalesce(sum(record_count),0)::integer INTO p,r FROM config_snapshot_collections WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND version_id=v.version_id;
 IF n<>v.object_count OR p<>v.stored_page_count OR r<>v.stored_record_count THEN RAISE EXCEPTION 'Snapshot normalized counts do not match its sealed manifest' USING ERRCODE='23514';END IF;
 FOREACH k IN ARRAY v.required_collections LOOP IF NOT EXISTS(SELECT 1 FROM config_snapshot_collections WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND version_id=v.version_id AND collection_key=k AND terminal_observed) THEN RAISE EXCEPTION 'Snapshot collection EOF is missing' USING ERRCODE='23514';END IF;END LOOP;
 FOR o IN SELECT dependencies FROM config_snapshot_objects WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND version_id=v.version_id LOOP FOREACH dep IN ARRAY o.dependencies LOOP
 IF NOT EXISTS(SELECT 1 FROM config_snapshot_objects WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND version_id=v.version_id AND object_key=dep) THEN RAISE EXCEPTION 'Snapshot dependency proof is missing' USING ERRCODE='23514';END IF;END LOOP;END LOOP;
 RETURN NULL;END;$$;
DO $$DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['config_snapshot_versions','config_snapshot_collections','config_snapshot_objects'] LOOP
 EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m8_validate_snapshot()',tab||'_complete',tab);END LOOP;END;$$;
CREATE FUNCTION m8_validate_plan() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE v configuration_plan_versions%ROWTYPE;n integer;p integer;s record;dep uuid;ord integer;BEGIN
 SELECT * INTO v FROM configuration_plan_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND plan_id=NEW.plan_id AND plan_revision=NEW.plan_revision;
 SELECT count(*)::integer,coalesce(sum(jsonb_array_length(native_requests)),0)::integer INTO n,p FROM configuration_plan_objects WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND plan_id=v.plan_id AND plan_revision=v.plan_revision;
 IF n<>v.step_count OR p<>v.native_packet_count THEN RAISE EXCEPTION 'Configuration DAG manifest count mismatch' USING ERRCODE='23514';END IF;
 FOR s IN SELECT step_order,dependencies FROM configuration_plan_objects WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND plan_id=v.plan_id AND plan_revision=v.plan_revision LOOP
 IF s.step_order>n THEN RAISE EXCEPTION 'Configuration steps are not contiguous' USING ERRCODE='23514';END IF;
 FOREACH dep IN ARRAY s.dependencies LOOP SELECT step_order INTO ord FROM configuration_plan_objects WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND plan_id=v.plan_id AND plan_revision=v.plan_revision AND step_id=dep;
 IF ord IS NULL OR ord>=s.step_order THEN RAISE EXCEPTION 'Configuration dependency must precede its step' USING ERRCODE='23514';END IF;END LOOP;END LOOP;RETURN NULL;END;$$;
CREATE CONSTRAINT TRIGGER configuration_plan_versions_complete AFTER INSERT ON configuration_plan_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m8_validate_plan();
CREATE CONSTRAINT TRIGGER configuration_plan_objects_complete AFTER INSERT ON configuration_plan_objects DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m8_validate_plan();
CREATE FUNCTION m8_guard_plan_append() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM configuration_plans WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.plan_id AND state='draft') THEN RAISE EXCEPTION 'Ready configuration plan cannot gain steps' USING ERRCODE='23514';END IF;RETURN NEW;END;$$;
CREATE TRIGGER configuration_plan_objects_freeze BEFORE INSERT ON configuration_plan_objects FOR EACH ROW EXECUTE FUNCTION m8_guard_plan_append();

ALTER TABLE mutation_operations ADD COLUMN configuration_job_id uuid;
ALTER TABLE mutation_operations ADD COLUMN configuration_execution_id uuid;
ALTER TABLE mutation_operations ADD COLUMN configuration_step_id uuid;
ALTER TABLE mutation_operations ADD COLUMN configuration_plan_revision integer CHECK(configuration_plan_revision IS NULL OR configuration_plan_revision>0);
ALTER TABLE mutation_operations ADD COLUMN configuration_plan_hash text CHECK(configuration_plan_hash IS NULL OR m8_hex64(configuration_plan_hash));
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_m8_binding_complete CHECK(num_nonnulls(configuration_job_id,configuration_execution_id,configuration_step_id,configuration_plan_revision,configuration_plan_hash)=0
 OR(num_nonnulls(configuration_job_id,configuration_execution_id,configuration_step_id,configuration_plan_revision,configuration_plan_hash)=5 AND workspace_id IS NOT NULL AND workflow_id IS NOT NULL
 AND num_nonnulls(workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id)=0));
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_m8_step_unique UNIQUE(configuration_step_id);
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_m8_reciprocal_unique UNIQUE(cluster_id,workspace_id,configuration_step_id,configuration_job_id,configuration_execution_id,configuration_plan_revision,configuration_plan_hash,id);
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_m8_execution_fk FOREIGN KEY(cluster_id,configuration_execution_id,configuration_job_id,configuration_plan_revision,configuration_plan_hash)
 REFERENCES configuration_executions(cluster_id,id,job_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_m8_step_fk FOREIGN KEY(cluster_id,workspace_id,configuration_step_id,configuration_job_id,configuration_execution_id,configuration_plan_revision,configuration_plan_hash,id)
 REFERENCES configuration_job_steps(cluster_id,object_workspace_id,id,job_id,execution_id,plan_revision,plan_hash,operation_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE configuration_job_steps ADD CONSTRAINT configuration_job_steps_operation_fk FOREIGN KEY(cluster_id,object_workspace_id,id,job_id,execution_id,plan_revision,plan_hash,operation_id)
 REFERENCES mutation_operations(cluster_id,workspace_id,configuration_step_id,configuration_job_id,configuration_execution_id,configuration_plan_revision,configuration_plan_hash,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION m8_guard_mutation_binding() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE p configuration_plan_objects%ROWTYPE;s configuration_job_steps%ROWTYPE;BEGIN
 IF num_nonnulls(OLD.configuration_job_id,OLD.configuration_execution_id,OLD.configuration_step_id,NEW.configuration_job_id,NEW.configuration_execution_id,NEW.configuration_step_id)>0 AND
 ROW(NEW.id,NEW.cluster_id,NEW.workspace_id,NEW.workflow_id,NEW.configuration_job_id,NEW.configuration_execution_id,NEW.configuration_step_id,NEW.configuration_plan_revision,NEW.configuration_plan_hash,
 NEW.actor_id,NEW.action,NEW.entity_type,NEW.parent_id,NEW.credential_kind,NEW.idempotency_key,NEW.request_hash,NEW.before_secret,NEW.payload_secret,NEW.transport_scope)
 IS DISTINCT FROM ROW(OLD.id,OLD.cluster_id,OLD.workspace_id,OLD.workflow_id,OLD.configuration_job_id,OLD.configuration_execution_id,OLD.configuration_step_id,OLD.configuration_plan_revision,OLD.configuration_plan_hash,
 OLD.actor_id,OLD.action,OLD.entity_type,OLD.parent_id,OLD.credential_kind,OLD.idempotency_key,OLD.request_hash,OLD.before_secret,OLD.payload_secret,OLD.transport_scope)
 THEN RAISE EXCEPTION 'Configuration native identity must be allocated once at insert' USING ERRCODE='23514';END IF;
 IF OLD.configuration_step_id IS NOT NULL AND NEW.entity_id IS DISTINCT FROM OLD.entity_id THEN
  SELECT * INTO s FROM configuration_job_steps WHERE id=OLD.configuration_step_id;
  SELECT * INTO p FROM configuration_plan_objects WHERE cluster_id=s.cluster_id AND workspace_id=s.workspace_id AND plan_id=s.plan_id AND plan_revision=s.plan_revision AND step_id=s.plan_step_id;
  IF NOT(OLD.state='running' AND OLD.remote_started AND NOT OLD.remote_completed AND NEW.remote_completed AND NEW.result_secret IS NOT NULL
   AND NEW.entity_id=p.allocated_native_id::text AND p.allocated_native_id IS NOT NULL
   AND((p.entity_type='targets' AND p.mutation_action='update' AND OLD.entity_id=p.native_id::text)
     OR(p.mutation_action='create' AND OLD.entity_id IS NULL))) THEN RAISE EXCEPTION 'Configuration native result ID does not match its preallocated identity' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;END;$$;
CREATE TRIGGER mutation_operations_m8_immutable BEFORE UPDATE ON mutation_operations FOR EACH ROW EXECUTE FUNCTION m8_guard_mutation_binding();
CREATE FUNCTION m8_validate_native_binding() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE op mutation_operations%ROWTYPE;e configuration_executions%ROWTYPE;s configuration_job_steps%ROWTYPE;p configuration_plan_objects%ROWTYPE;j configuration_jobs%ROWTYPE;BEGIN
 SELECT * INTO op FROM mutation_operations WHERE id=NEW.id;IF op.configuration_step_id IS NULL THEN RETURN NULL;END IF;
 SELECT * INTO e FROM configuration_executions WHERE id=op.configuration_execution_id;SELECT * INTO s FROM configuration_job_steps WHERE id=op.configuration_step_id;
 SELECT * INTO j FROM configuration_jobs WHERE id=op.configuration_job_id;SELECT * INTO p FROM configuration_plan_objects WHERE cluster_id=s.cluster_id AND workspace_id=s.workspace_id AND plan_id=s.plan_id AND plan_revision=s.plan_revision AND step_id=s.plan_step_id;
 IF e.execution_mode<>'approval' OR NOT s.approval_required OR op.workflow_id IS DISTINCT FROM e.workflow_id OR op.actor_id IS DISTINCT FROM e.actor_id OR op.action IS DISTINCT FROM p.mutation_action
 OR op.entity_type IS DISTINCT FROM p.entity_type OR op.workspace_id IS DISTINCT FROM p.object_workspace_id OR op.parent_id IS DISTINCT FROM p.parent_id::text OR op.credential_kind IS DISTINCT FROM p.credential_kind OR op.transport_scope IS DISTINCT FROM j.transport_scope
 OR(op.entity_id IS NULL AND(p.mutation_action<>'create' OR op.remote_completed))
 OR(op.entity_id IS NOT NULL AND op.entity_id IS DISTINCT FROM
  CASE WHEN p.entity_type='targets' AND p.mutation_action='update' AND op.remote_completed THEN p.allocated_native_id::text ELSE coalesce(p.native_id,p.allocated_native_id)::text END)
 THEN RAISE EXCEPTION 'Configuration native operation does not match its immutable logical step' USING ERRCODE='23514';END IF;RETURN NULL;END;$$;
CREATE CONSTRAINT TRIGGER mutation_operations_m8_binding AFTER INSERT OR UPDATE ON mutation_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m8_validate_native_binding();
CREATE FUNCTION m8_guard_step_identity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF ROW(NEW.id,NEW.cluster_id,NEW.workspace_id,NEW.job_id,NEW.execution_id,NEW.plan_id,NEW.plan_revision,NEW.plan_hash,NEW.plan_step_id,NEW.step_order,NEW.object_workspace_id,NEW.approval_required,NEW.before_hmac)
 IS DISTINCT FROM ROW(OLD.id,OLD.cluster_id,OLD.workspace_id,OLD.job_id,OLD.execution_id,OLD.plan_id,OLD.plan_revision,OLD.plan_hash,OLD.plan_step_id,OLD.step_order,OLD.object_workspace_id,OLD.approval_required,OLD.before_hmac)
 OR(OLD.operation_id IS NOT NULL AND NEW.operation_id IS DISTINCT FROM OLD.operation_id)
 OR(OLD.receipt_operation_id IS NOT NULL AND NEW.receipt_operation_id IS DISTINCT FROM OLD.receipt_operation_id)
 OR(OLD.state IN('succeeded','skipped') AND NEW IS DISTINCT FROM OLD) THEN RAISE EXCEPTION 'Configuration execution step identity cannot change' USING ERRCODE='23514';END IF;RETURN NEW;END;$$;
CREATE TRIGGER configuration_job_steps_identity BEFORE UPDATE ON configuration_job_steps FOR EACH ROW EXECUTE FUNCTION m8_guard_step_identity();
CREATE FUNCTION m8_guard_job_identity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF ROW(NEW.id,NEW.cluster_id,NEW.workspace_id,NEW.transport_scope,NEW.actor_id,NEW.origin_type,NEW.origin_session_id,NEW.authority_expires_at,NEW.kind,NEW.idempotency_key,NEW.request_hmac,
  NEW.request_id,NEW.scope_kind,NEW.root_ids,NEW.input_secret,NEW.permission_version,NEW.credential_epoch,NEW.cluster_revision,NEW.workspace_revision,NEW.capture_epoch,NEW.execution_mode,NEW.approval_required,NEW.expires_at,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.cluster_id,OLD.workspace_id,OLD.transport_scope,OLD.actor_id,OLD.origin_type,OLD.origin_session_id,OLD.authority_expires_at,OLD.kind,OLD.idempotency_key,OLD.request_hmac,
  OLD.request_id,OLD.scope_kind,OLD.root_ids,OLD.input_secret,OLD.permission_version,OLD.credential_epoch,OLD.cluster_revision,OLD.workspace_revision,OLD.capture_epoch,OLD.execution_mode,OLD.approval_required,OLD.expires_at,OLD.created_at)
 OR(OLD.plan_id IS NOT NULL AND ROW(NEW.plan_id,NEW.plan_revision,NEW.plan_hash) IS DISTINCT FROM ROW(OLD.plan_id,OLD.plan_revision,OLD.plan_hash))
 OR(OLD.workflow_id IS NOT NULL AND NEW.workflow_id IS DISTINCT FROM OLD.workflow_id) OR NEW.revision<>OLD.revision+1 OR NEW.lease_generation<OLD.lease_generation
 THEN RAISE EXCEPTION 'Configuration job identity and once-bound plan cannot change' USING ERRCODE='23514';END IF;
 IF OLD.state IN('succeeded','cancelled','expired') AND NEW.state IS DISTINCT FROM OLD.state THEN RAISE EXCEPTION 'Terminal configuration job cannot be restarted' USING ERRCODE='23514';END IF;RETURN NEW;END;$$;
CREATE TRIGGER configuration_jobs_identity BEFORE UPDATE ON configuration_jobs FOR EACH ROW EXECUTE FUNCTION m8_guard_job_identity();
CREATE FUNCTION m8_guard_schedule_identity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF ROW(NEW.id,NEW.cluster_id,NEW.workspace_id,NEW.transport_scope,NEW.owner_user_id,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.cluster_id,OLD.workspace_id,OLD.transport_scope,OLD.owner_user_id,OLD.created_at)
 OR NEW.revision<>OLD.revision+1 OR NEW.current_version<OLD.current_version OR OLD.purged_at IS NOT NULL
 THEN RAISE EXCEPTION 'Schedule identity and irreversible archive cannot change' USING ERRCODE='23514';END IF;RETURN NEW;END;$$;
CREATE TRIGGER config_snapshot_schedules_identity BEFORE UPDATE ON config_snapshot_schedules FOR EACH ROW EXECUTE FUNCTION m8_guard_schedule_identity();
CREATE FUNCTION m8_validate_execution_terminal() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE e configuration_executions%ROWTYPE;v configuration_plan_versions%ROWTYPE;n integer;BEGIN
 SELECT * INTO e FROM configuration_executions WHERE id=NEW.id;IF e.state<>'succeeded' THEN RETURN NULL;END IF;
 SELECT * INTO v FROM configuration_plan_versions WHERE cluster_id=e.cluster_id AND workspace_id=e.workspace_id AND plan_id=e.plan_id AND plan_revision=e.plan_revision;
 SELECT count(*)::integer INTO n FROM configuration_job_steps WHERE execution_id=e.id;
 IF n<>v.step_count OR EXISTS(SELECT 1 FROM configuration_job_steps WHERE execution_id=e.id AND state NOT IN('succeeded','skipped')) THEN RAISE EXCEPTION 'Configuration execution cannot finish without every durable step' USING ERRCODE='23514';END IF;RETURN NULL;END;$$;
CREATE CONSTRAINT TRIGGER configuration_executions_terminal AFTER INSERT OR UPDATE ON configuration_executions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m8_validate_execution_terminal();
CREATE FUNCTION m8_no_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Configuration metadata must be archived with history retained' USING ERRCODE='23514';END;$$;
DO $$DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['configuration_jobs','config_snapshots','configuration_plans','configuration_executions','configuration_job_steps','configuration_exports','configuration_download_grants','configuration_deck_sessions','config_snapshot_schedules','config_snapshot_schedule_runs'] LOOP
 EXECUTE format('CREATE TRIGGER %I BEFORE DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_no_delete()',tab||'_no_delete',tab);END LOOP;END;$$;

CREATE OR REPLACE FUNCTION m6_validate_workflow_subject() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE subject_exists boolean;owner_id uuid;j configuration_jobs%ROWTYPE;
BEGIN
 IF NEW.kind='event-metadata' THEN
  IF NEW.requester_type<>'console' OR NEW.subject_type NOT IN('notification_channels','event_subscriptions','event_deliveries') THEN RAISE EXCEPTION 'Event metadata is a fixed console workflow' USING ERRCODE='23514';END IF;
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3)',NEW.subject_type) INTO subject_exists USING NEW.cluster_id,NEW.workspace_id,NEW.subject_id;
  IF NOT subject_exists THEN RAISE EXCEPTION 'Event metadata subject is foreign' USING ERRCODE='23503';END IF;
  IF EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=NEW.id AND(kind<>'metadata' OR operation_id IS NOT NULL OR native_requests<>'[]'::jsonb OR handler NOT IN('event.channel.save','event.channel.status','event.channel.delete','event.channel.restore','event.channel.test','event.subscription.save','event.subscription.delete','event.subscription.restore','event.delivery.replay'))) THEN RAISE EXCEPTION 'Event workflow cannot claim native authority' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
 IF NEW.kind='configuration-metadata' THEN
  IF NEW.requester_type<>'console' OR NEW.subject_type NOT IN('config_snapshots','config_snapshot_schedules','configuration_gitops_runs') THEN RAISE EXCEPTION 'Configuration metadata has a fixed console subject' USING ERRCODE='23514';END IF;
  IF(SELECT count(*) FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision)<>1
    OR NOT EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision AND plan_hash=NEW.plan_hash AND kind='metadata' AND handler='configuration.metadata' AND entity_type=NEW.subject_type AND entity_id=NEW.subject_id AND operation_id IS NULL AND native_requests='[]'::jsonb)
    THEN RAISE EXCEPTION 'Configuration metadata cannot contain native authority' USING ERRCODE='23514';END IF;
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3)',NEW.subject_type) INTO subject_exists USING NEW.cluster_id,NEW.workspace_id,NEW.subject_id;
  IF NOT subject_exists AND NOT EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision AND metadata_revision=0)
    THEN RAISE EXCEPTION 'Configuration metadata subject is foreign' USING ERRCODE='23503';END IF;RETURN NULL;
 END IF;
 IF NEW.kind='configuration_v2' THEN
  IF NEW.subject_type<>'configuration_jobs' OR NEW.requester_type<>'console' THEN RAISE EXCEPTION 'Configuration wrapper requires a console-owned configuration job' USING ERRCODE='23514';END IF;
  SELECT * INTO j FROM configuration_jobs WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.subject_id;
  IF j.id IS NULL OR j.actor_id IS DISTINCT FROM NEW.requester_user_id OR j.execution_mode IS DISTINCT FROM NEW.execution_mode OR j.approval_required IS DISTINCT FROM NEW.approval_required
    OR j.plan_id IS NULL THEN RAISE EXCEPTION 'Configuration wrapper must retain its exact job and executor policy' USING ERRCODE='23514';END IF;
  IF NOT EXISTS(SELECT 1 FROM workflow_steps s WHERE s.cluster_id=NEW.cluster_id AND s.workspace_id=NEW.workspace_id AND s.workflow_id=NEW.id AND s.plan_revision=NEW.plan_revision AND s.plan_hash=NEW.plan_hash
    AND s.kind='metadata' AND s.handler='configuration_v2' AND s.entity_type='configuration_jobs' AND s.entity_id=j.id)
    OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision)<>1
    OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision AND(kind<>'metadata' OR jsonb_array_length(native_requests)<>0))
    THEN RAISE EXCEPTION 'Configuration wrapper contains exactly one fixed metadata step' USING ERRCODE='23514';END IF;
  RETURN NULL;
 END IF;
 IF NOT((NEW.kind='portal-publication' AND NEW.subject_type='portal_publications')
   OR(NEW.kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND NEW.subject_type='portal_application_grants')
   OR(NEW.kind='portal-developer-review' AND NEW.subject_type='portal_developers')
   OR(NEW.kind='portal-metadata' AND NEW.subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content')) OR(NEW.kind='native-change' AND NEW.subject_type NOT IN('configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs')))
   THEN RAISE EXCEPTION 'Workflow subject type does not match its fixed kind' USING ERRCODE='23514';END IF;
 -- NEW.subject_type remains constrained to the fixed server-owned table list.
 EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3)',NEW.subject_type) INTO subject_exists USING NEW.cluster_id,NEW.workspace_id,NEW.subject_id;
 IF NOT subject_exists THEN RAISE EXCEPTION 'Workflow subject must exist in the complete tenant scope' USING ERRCODE='23503';END IF;
 IF NEW.requester_type='developer' THEN
  IF NEW.kind NOT IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') THEN RAISE EXCEPTION 'Developer workflows are restricted to their credential grants' USING ERRCODE='23514';END IF;
  SELECT developer_id INTO owner_id FROM portal_application_grants WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.subject_id;
  IF owner_id IS DISTINCT FROM NEW.requester_developer_id THEN RAISE EXCEPTION 'Developer workflow subject must retain its owner' USING ERRCODE='23514';END IF;
 END IF;RETURN NULL;
END;$$;
