-- M7 console-owned audit scopes, events, durable fanout/delivery and notifications.
-- This migration never changes an existing audit body/hash or any Kong database.
-- Nullable historical scope is validated against the actual immutable source.

CREATE FUNCTION m7_hex64(value text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT value IS NOT NULL AND value ~ '^[a-f0-9]{64}$';
$$;
CREATE FUNCTION m7_object(value jsonb, max_bytes integer) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT value IS NOT NULL AND jsonb_typeof(value)='object' AND octet_length(value::text)<=max_bytes;
$$;
CREATE FUNCTION m7_native_type(value text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT value IN ('services','routes','consumers','plugins','upstreams','targets','certificates','ca_certificates','snis','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls');
$$;
CREATE FUNCTION m7_filter(types text[], native_type text, ids uuid[], tags text[]) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE item text;
BEGIN
 IF types IS NULL OR cardinality(types) NOT BETWEEN 1 AND 32 OR coalesce(array_ndims(types),1)<>1 OR array_position(types,NULL) IS NOT NULL
  OR ids IS NULL OR cardinality(ids)>256 OR coalesce(array_ndims(ids),1)<>1 OR array_position(ids,NULL) IS NOT NULL
  OR tags IS NULL OR cardinality(tags)>256 OR coalesce(array_ndims(tags),1)<>1 OR array_position(tags,NULL) IS NOT NULL
  OR (native_type IS NOT NULL AND NOT m7_native_type(native_type)) OR (cardinality(ids)>0 AND native_type IS NULL) THEN RETURN false;END IF;
 FOREACH item IN ARRAY types LOOP IF item !~ '^[a-z][a-z0-9_.-]{0,127}$' THEN RETURN false;END IF;END LOOP;
 FOREACH item IN ARRAY tags LOOP IF octet_length(item) NOT BETWEEN 1 AND 128 OR item ~ '[[:cntrl:]]' OR item LIKE 'kos-ws-%' OR item LIKE 'workspace:%' THEN RETURN false;END IF;END LOOP;
 RETURN octet_length(jsonb_build_array(to_jsonb(types),to_jsonb(tags))::text)<=65536;
END;$$;
CREATE FUNCTION m7_historical_scope(value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE field text;side jsonb;tag jsonb;
BEGIN
 IF NOT m7_object(value,65536) OR value->>'version' IS DISTINCT FROM '1' OR value->>'quality' NOT IN ('verified','legacy_unknown')
  OR jsonb_typeof(value->'module') IS DISTINCT FROM 'string' OR length(value->>'module') NOT BETWEEN 1 AND 80
  OR NOT(value ?& ARRAY['version','quality','module','before','after']) THEN RETURN false;END IF;
 FOR field IN SELECT jsonb_object_keys(value) LOOP
  IF field NOT IN ('version','quality','module','nativeType','nativeId','parentId','credentialKind','before','after','subject') THEN RETURN false;END IF;
 END LOOP;
 IF value ? 'nativeType' AND NOT m7_native_type(value->>'nativeType') THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['nativeId','parentId'] LOOP
  IF value ? field AND coalesce(value->>field,'') !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' THEN RETURN false;END IF;
 END LOOP;
 IF (value ? 'nativeType')<>(value ? 'nativeId') THEN RETURN false;END IF;
 IF value ? 'credentialKind' AND value->>'credentialKind' NOT IN ('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls') THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['before','after'] LOOP
  side:=value->field;
  IF side='null'::jsonb THEN CONTINUE;END IF;
  IF jsonb_typeof(side)<>'object' OR NOT(side ?& ARRAY['workspaceId','physicalTags']) OR (SELECT count(*) FROM jsonb_object_keys(side))<>2
   OR (side->'workspaceId'<>'null'::jsonb AND coalesce(side->>'workspaceId','') !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
   OR jsonb_typeof(side->'physicalTags')<>'array' OR jsonb_array_length(side->'physicalTags')>256 THEN RETURN false;END IF;
  FOR tag IN SELECT v FROM jsonb_array_elements(side->'physicalTags') e(v) LOOP
   IF jsonb_typeof(tag)<>'string' OR octet_length(tag#>>'{}') NOT BETWEEN 1 AND 128 OR (tag#>>'{}') ~ '[[:cntrl:]]' THEN RETURN false;END IF;
  END LOOP;
 END LOOP;
 IF value ? 'subject' AND (NOT m7_object(value->'subject',1024) OR (SELECT count(*) FROM jsonb_object_keys(value->'subject'))<>2
  OR NOT(value->'subject' ?& ARRAY['type','id']) OR jsonb_typeof(value->'subject'->'type')<>'string'
  OR coalesce(value->'subject'->>'id','') !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') THEN RETURN false;END IF;
 RETURN true;
EXCEPTION WHEN others THEN RETURN false;
END;$$;
CREATE FUNCTION m7_observation_value(detector text, quality text, value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE parsed timestamptz;
BEGIN
 IF quality<>'verified' THEN RETURN value IS NULL;END IF;
 IF NOT m7_object(value,8192) OR (SELECT count(*) FROM jsonb_object_keys(value))<>2 THEN RETURN false;END IF;
 IF detector='certificate.expiry.v1' THEN
  IF value->>'kind' IS DISTINCT FROM 'certificate_expiry' OR coalesce(value->>'expiresAt','') !~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$' THEN RETURN false;END IF;
  parsed:=(value->>'expiresAt')::timestamptz;RETURN isfinite(parsed);
 END IF;
 RETURN detector='upstream.health.v1' AND value->>'kind'='upstream_health' AND value->>'health' IN ('healthy','unhealthy','degraded','checks_off');
EXCEPTION WHEN others THEN RETURN false;
END;$$;

CREATE FUNCTION m7_event_payload(value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE k text;parsed timestamptz;
BEGIN
 IF NOT m7_object(value,8192) OR NOT(value ?& ARRAY['version','title','summary','eventType','phase','result','subject']) OR value->>'version' IS DISTINCT FROM '1' THEN RETURN false;END IF;
 FOR k IN SELECT jsonb_object_keys(value) LOOP IF k NOT IN ('version','title','summary','eventType','phase','result','subject','observedAt','quality','expiry','health') THEN RETURN false;END IF;END LOOP;
 IF jsonb_typeof(value->'title') IS DISTINCT FROM 'string' OR length(value->>'title') NOT BETWEEN 1 AND 256 OR jsonb_typeof(value->'summary') IS DISTINCT FROM 'string' OR octet_length(value->>'summary')>4096 OR coalesce(value->>'eventType','') !~ '^[a-z][a-z0-9_.-]{0,127}$' OR value->>'phase' NOT IN ('requested','node','aggregate','terminal','observation') OR jsonb_typeof(value->'result') IS DISTINCT FROM 'string' THEN RETURN false;END IF;
 IF value->'subject'<>'null'::jsonb AND (NOT m7_object(value->'subject',1024) OR(SELECT count(*) FROM jsonb_object_keys(value->'subject'))<>2 OR jsonb_typeof(value->'subject'->'type') IS DISTINCT FROM 'string' OR coalesce(value->'subject'->>'id','') !~ '^[a-f0-9-]{36}$') THEN RETURN false;END IF;
 IF value?'observedAt' THEN parsed:=(value->>'observedAt')::timestamptz;IF NOT isfinite(parsed) THEN RETURN false;END IF;END IF;
 IF value?'quality' AND value->>'quality' NOT IN ('verified','partial','unavailable','invalid','stale') THEN RETURN false;END IF;
 IF value?'expiry' THEN IF NOT m7_object(value->'expiry',1024) OR(SELECT count(*) FROM jsonb_object_keys(value->'expiry'))<>2 OR value->'expiry'->>'bucket' NOT IN ('normal','30d','7d','1d','expired') THEN RETURN false;END IF;parsed:=(value->'expiry'->>'expiresAt')::timestamptz;IF NOT isfinite(parsed) THEN RETURN false;END IF;END IF;
 IF value?'health' AND (NOT m7_object(value->'health',1024) OR(SELECT count(*) FROM jsonb_object_keys(value->'health'))<>2 OR value->'health'->>'before' NOT IN ('healthy','unhealthy','degraded','checks_off') OR value->'health'->>'after' NOT IN ('healthy','unhealthy','degraded','checks_off')) THEN RETURN false;END IF;
 RETURN true;
EXCEPTION WHEN others THEN RETURN false;END;$$;

ALTER TABLE audit_events ADD CONSTRAINT audit_events_id_hash_m7 UNIQUE(id,event_hash);
CREATE TABLE audit_event_scopes (
 audit_event_id uuid PRIMARY KEY REFERENCES audit_events(id) ON DELETE RESTRICT,
 audit_event_hash text NOT NULL CHECK(m7_hex64(audit_event_hash)),
 cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT, workspace_id uuid,
 scope jsonb NOT NULL CHECK(m7_historical_scope(scope)), scope_hmac text NOT NULL CHECK(m7_hex64(scope_hmac)),
 created_at timestamptz NOT NULL DEFAULT now(), CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL),
 FOREIGN KEY(audit_event_id,audit_event_hash) REFERENCES audit_events(id,event_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT
);
CREATE TABLE event_detection_observations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 detector_key text NOT NULL,subject_type text NOT NULL,subject_id uuid NOT NULL,
 transport_scope text NOT NULL CHECK(m7_hex64(transport_scope)),observed_node_id text CHECK(observed_node_id IS NULL OR octet_length(observed_node_id) BETWEEN 1 AND 256),
 cluster_revision integer NOT NULL CHECK(cluster_revision>0),workspace_revision integer NOT NULL CHECK(workspace_revision>0),
 config_fingerprint text NOT NULL CHECK(m7_hex64(config_fingerprint)),scope_epoch text NOT NULL CHECK(m7_hex64(scope_epoch)),
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at) AND observed_at=date_trunc('milliseconds',observed_at)),
 quality text NOT NULL CHECK(quality IN ('verified','partial','unavailable','invalid','stale')),
 source_scope jsonb NOT NULL CHECK(m7_historical_scope(source_scope)),source_scope_hmac text NOT NULL CHECK(m7_hex64(source_scope_hmac)),
 observation_safe jsonb,observation_hmac text NOT NULL CHECK(m7_hex64(observation_hmac)),occurrence_key text NOT NULL CHECK(m7_hex64(occurrence_key)),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,id,detector_key,subject_type,subject_id),
 UNIQUE(cluster_id,workspace_id,detector_key,subject_type,subject_id,occurrence_key),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK((detector_key='certificate.expiry.v1' AND subject_type IN ('certificates','ca_certificates')) OR(detector_key='upstream.health.v1' AND subject_type='upstreams')),
 CHECK(m7_observation_value(detector_key,quality,observation_safe)),
 CHECK(detector_key<>'upstream.health.v1' OR quality<>'verified' OR observed_node_id IS NOT NULL),
 CHECK(source_scope->>'quality'='verified' AND source_scope->>'module'='events' AND source_scope->>'nativeType'=subject_type AND source_scope->>'nativeId'=subject_id::text
  AND source_scope->'before' IS DISTINCT FROM 'null'::jsonb AND source_scope->'before'=source_scope->'after'
  AND source_scope->'before'->>'workspaceId'=workspace_id::text),
 CHECK(created_at>=observed_at)
);
CREATE TABLE event_detection_state (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,detector_key text NOT NULL,subject_type text NOT NULL,subject_id uuid NOT NULL,
 transport_scope text NOT NULL CHECK(m7_hex64(transport_scope)),observed_node_id text CHECK(observed_node_id IS NULL OR octet_length(observed_node_id) BETWEEN 1 AND 256),
 config_fingerprint text NOT NULL CHECK(m7_hex64(config_fingerprint)),scope_epoch text NOT NULL CHECK(m7_hex64(scope_epoch)),
 last_observation_id uuid NOT NULL,last_observation_safe jsonb NOT NULL CHECK(m7_object(last_observation_safe,8192)),
 observation_fingerprint text NOT NULL CHECK(m7_hex64(observation_fingerprint)),last_observed_at timestamptz NOT NULL CHECK(isfinite(last_observed_at)),
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),PRIMARY KEY(cluster_id,workspace_id,detector_key,subject_type,subject_id),
 FOREIGN KEY(cluster_id,workspace_id,last_observation_id,detector_key,subject_type,subject_id) REFERENCES event_detection_observations(cluster_id,workspace_id,id,detector_key,subject_type,subject_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE event_records (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,workspace_id uuid,
 event_type text NOT NULL CHECK(event_type ~ '^[a-z][a-z0-9_.-]{0,127}$'),phase text NOT NULL CHECK(phase IN ('requested','node','aggregate','terminal','observation')),
 source_kind text NOT NULL CHECK(source_kind IN ('audit','workflow','mutation','iam','portal','observation')),source_id uuid NOT NULL,
 audit_event_id uuid REFERENCES audit_events(id) ON DELETE RESTRICT,observation_id uuid REFERENCES event_detection_observations(id) ON DELETE RESTRICT,
 workflow_id uuid REFERENCES workflows(id) ON DELETE RESTRICT,mutation_id uuid REFERENCES mutation_operations(id) ON DELETE RESTRICT,
 iam_operation_id uuid REFERENCES iam_operations(id) ON DELETE RESTRICT,portal_operation_id uuid REFERENCES portal_operations(id) ON DELETE RESTRICT,
 workflow_execution_id uuid,workflow_plan_revision integer CHECK(workflow_plan_revision IS NULL OR workflow_plan_revision>0),
 workflow_plan_hash text CHECK(workflow_plan_hash IS NULL OR m7_hex64(workflow_plan_hash)),workflow_step_id uuid,queue_request_hmac text CHECK(queue_request_hmac IS NULL OR m7_hex64(queue_request_hmac)),
 actor_type text NOT NULL CHECK(actor_type IN ('user','developer','system')),actor_id uuid REFERENCES users(id) ON DELETE RESTRICT,developer_id uuid,
 entity_type text CHECK(entity_type IS NULL OR length(entity_type) BETWEEN 1 AND 80),entity_id uuid,
 source_scope jsonb NOT NULL CHECK(m7_historical_scope(source_scope)),source_scope_hmac text NOT NULL CHECK(m7_hex64(source_scope_hmac)),
 payload_safe jsonb NOT NULL CHECK(m7_event_payload(payload_safe)),payload_digest text NOT NULL CHECK(m7_hex64(payload_digest)),
 occurrence_key text NOT NULL CHECK(octet_length(occurrence_key) BETWEEN 1 AND 256),occurred_at timestamptz NOT NULL CHECK(isfinite(occurred_at) AND occurred_at=date_trunc('milliseconds',occurred_at)),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(cluster_id,workspace_id,id),UNIQUE(source_kind,source_id,event_type,phase,occurrence_key),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,developer_id) REFERENCES portal_developers(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,workflow_step_id,workflow_id,workflow_plan_revision,workflow_plan_hash) REFERENCES workflow_steps(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,observation_id) REFERENCES event_detection_observations(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL),
 CHECK((actor_type='user' AND actor_id IS NOT NULL AND developer_id IS NULL) OR(actor_type='developer' AND actor_id IS NULL AND developer_id IS NOT NULL AND cluster_id IS NOT NULL AND workspace_id IS NOT NULL) OR(actor_type='system' AND actor_id IS NULL AND developer_id IS NULL)),
 CHECK((source_kind='audit' AND audit_event_id IS NOT NULL AND source_id=audit_event_id AND observation_id IS NULL) OR(source_kind='workflow' AND workflow_id IS NOT NULL AND source_id=workflow_id AND observation_id IS NULL) OR(source_kind='mutation' AND mutation_id IS NOT NULL AND source_id=mutation_id AND observation_id IS NULL) OR(source_kind='iam' AND iam_operation_id IS NOT NULL AND source_id=iam_operation_id AND observation_id IS NULL) OR(source_kind='portal' AND portal_operation_id IS NOT NULL AND source_id=portal_operation_id AND observation_id IS NULL) OR(source_kind='observation' AND observation_id IS NOT NULL AND source_id=observation_id AND phase='observation' AND audit_event_id IS NULL AND workflow_id IS NULL AND mutation_id IS NULL AND iam_operation_id IS NULL AND portal_operation_id IS NULL AND actor_type='system')),
 CHECK((workflow_execution_id IS NULL AND workflow_plan_revision IS NULL AND workflow_plan_hash IS NULL AND workflow_step_id IS NULL) OR(workflow_execution_id IS NOT NULL AND workflow_plan_revision IS NOT NULL AND workflow_plan_hash IS NOT NULL AND workflow_step_id IS NOT NULL AND workflow_id IS NOT NULL AND iam_operation_id IS NULL)),
 CHECK(queue_request_hmac IS NULL OR(audit_event_id IS NOT NULL AND actor_type='user' AND cluster_id IS NOT NULL AND workspace_id IS NOT NULL AND ((iam_operation_id IS NOT NULL AND workflow_execution_id IS NULL) OR(iam_operation_id IS NULL AND workflow_execution_id IS NOT NULL))))
);
CREATE UNIQUE INDEX event_records_audit_occurrence ON event_records(audit_event_id,event_type,phase,occurrence_key) WHERE audit_event_id IS NOT NULL;
CREATE TABLE event_outbox (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),event_id uuid NOT NULL UNIQUE REFERENCES event_records(id) ON DELETE RESTRICT,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','dispatching','dispatched','failed')),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 lease_owner_hash text CHECK(lease_owner_hash IS NULL OR m7_hex64(lease_owner_hash)),lease_generation integer NOT NULL DEFAULT 0 CHECK(lease_generation>=0),lease_until timestamptz,
 next_attempt_at timestamptz NOT NULL DEFAULT now(),attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 8),error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),
 subscription_upper_bound bigint CHECK(subscription_upper_bound IS NULL OR subscription_upper_bound>=0),personal_upper_bound bigint CHECK(personal_upper_bound IS NULL OR personal_upper_bound>=0),
 subscription_cursor jsonb CHECK(subscription_cursor IS NULL OR m7_object(subscription_cursor,8192)),personal_cursor jsonb CHECK(personal_cursor IS NULL OR m7_object(personal_cursor,8192)),
 subscription_complete boolean NOT NULL DEFAULT false,personal_complete boolean NOT NULL DEFAULT false,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK(updated_at>=created_at),CHECK((state='dispatching' AND lease_owner_hash IS NOT NULL AND lease_until IS NOT NULL AND lease_generation>0) OR(state<>'dispatching' AND lease_owner_hash IS NULL AND lease_until IS NULL)),
 CHECK((subscription_upper_bound IS NULL)=(personal_upper_bound IS NULL)),CHECK(state<>'dispatched' OR(subscription_complete AND personal_complete AND subscription_upper_bound IS NOT NULL))
);
CREATE TABLE notification_channels (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 type text NOT NULL CHECK(type IN ('webhook','email','slack','feishu')),status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','disabled','deleted')),
 endpoint_secret text CHECK(endpoint_secret IS NULL OR m6_encrypted(endpoint_secret,65536)),auth_secret text CHECK(auth_secret IS NULL OR m6_encrypted(auth_secret,65536)),options_safe jsonb NOT NULL DEFAULT '{}' CHECK(m7_object(options_safe,8192)),
 credential_generation integer NOT NULL DEFAULT 1 CHECK(credential_generation>0),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,updated_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,workflow_id uuid,
 deleted_at timestamptz,retention_until timestamptz,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,name),FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(status<>'active' OR endpoint_secret IS NOT NULL),CHECK(updated_at>=created_at),
 CHECK((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL AND retention_until>=deleted_at) OR(status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE TABLE notification_channel_versions (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,channel_id uuid NOT NULL,revision integer NOT NULL CHECK(revision>0),status text NOT NULL CHECK(status IN ('pending','active','disabled','deleted')),
 type text NOT NULL CHECK(type IN ('webhook','email','slack','feishu')),endpoint_secret text CHECK(endpoint_secret IS NULL OR m6_encrypted(endpoint_secret,65536)),auth_secret text CHECK(auth_secret IS NULL OR m6_encrypted(auth_secret,65536)),options_safe jsonb NOT NULL CHECK(m7_object(options_safe,8192)),
 credential_generation integer NOT NULL CHECK(credential_generation>0),created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,channel_id,revision),UNIQUE(cluster_id,workspace_id,channel_id,revision,credential_generation),
 FOREIGN KEY(cluster_id,workspace_id,channel_id) REFERENCES notification_channels(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(status<>'active' OR endpoint_secret IS NOT NULL)
);
CREATE TABLE event_subscriptions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,channel_id uuid NOT NULL,name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 event_types text[] NOT NULL,native_type text,native_ids uuid[] NOT NULL DEFAULT '{}',physical_tags text[] NOT NULL DEFAULT '{}',status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','disabled','deleted')),
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,updated_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,workflow_id uuid,
 deleted_at timestamptz,retention_until timestamptz,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,name),FOREIGN KEY(cluster_id,workspace_id,channel_id) REFERENCES notification_channels(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(m7_filter(event_types,native_type,native_ids,physical_tags)),CHECK(updated_at>=created_at),
 CHECK((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL AND retention_until>=deleted_at) OR(status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE TABLE event_subscription_versions (
 sequence bigserial NOT NULL UNIQUE,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,subscription_id uuid NOT NULL,revision integer NOT NULL CHECK(revision>0),channel_id uuid NOT NULL,
 status text NOT NULL CHECK(status IN ('pending','active','disabled','deleted')),event_types text[] NOT NULL,native_type text,native_ids uuid[] NOT NULL DEFAULT '{}',physical_tags text[] NOT NULL DEFAULT '{}',
 created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(cluster_id,workspace_id,subscription_id,revision),
 UNIQUE(cluster_id,workspace_id,subscription_id,revision,channel_id),FOREIGN KEY(cluster_id,workspace_id,subscription_id) REFERENCES event_subscriptions(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,channel_id) REFERENCES notification_channels(cluster_id,workspace_id,id) ON DELETE RESTRICT,CHECK(m7_filter(event_types,native_type,native_ids,physical_tags))
);
CREATE TABLE event_deliveries (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,event_id uuid NOT NULL REFERENCES event_records(id) ON DELETE RESTRICT,
 delivery_kind text NOT NULL CHECK(delivery_kind IN ('subscription','test')),subscription_id uuid,subscription_revision integer,channel_id uuid NOT NULL,channel_revision integer NOT NULL CHECK(channel_revision>0),credential_generation integer NOT NULL CHECK(credential_generation>0),
 creator_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,replay_generation integer NOT NULL DEFAULT 0 CHECK(replay_generation>=0),parent_delivery_id uuid,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','claimed','sending','retrying','uncertain','paused_authority','succeeded','exhausted','cancelled')),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 lease_owner_hash text CHECK(lease_owner_hash IS NULL OR m7_hex64(lease_owner_hash)),lease_generation integer NOT NULL DEFAULT 0 CHECK(lease_generation>=0),lease_until timestamptz,
 intent_attempt_no integer CHECK(intent_attempt_no IS NULL OR intent_attempt_no BETWEEN 1 AND 8),intent_lease_generation integer,intent_started_at timestamptz,
 next_attempt_at timestamptz NOT NULL DEFAULT now(),attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 8),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),payload_safe jsonb NOT NULL CHECK(m7_event_payload(payload_safe)),payload_digest text NOT NULL CHECK(m7_hex64(payload_digest)),
 error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(event_id,subscription_id,subscription_revision,replay_generation),
 FOREIGN KEY(cluster_id,workspace_id,subscription_id,subscription_revision,channel_id) REFERENCES event_subscription_versions(cluster_id,workspace_id,subscription_id,revision,channel_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,channel_id,channel_revision,credential_generation) REFERENCES notification_channel_versions(cluster_id,workspace_id,channel_id,revision,credential_generation) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,parent_delivery_id) REFERENCES event_deliveries(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK((delivery_kind='test' AND subscription_id IS NULL AND subscription_revision IS NULL) OR(delivery_kind='subscription' AND subscription_id IS NOT NULL AND subscription_revision>0)),
 CHECK((replay_generation=0 AND parent_delivery_id IS NULL) OR(replay_generation>0 AND parent_delivery_id IS NOT NULL)),
 CHECK((state IN ('claimed','sending') AND lease_owner_hash IS NOT NULL AND lease_until IS NOT NULL AND lease_generation>0) OR(state NOT IN ('claimed','sending') AND lease_owner_hash IS NULL AND lease_until IS NULL)),
 CHECK((state='sending' AND intent_attempt_no=attempt_count+1 AND intent_lease_generation=lease_generation AND intent_started_at IS NOT NULL) OR(state<>'sending' AND intent_attempt_no IS NULL AND intent_lease_generation IS NULL AND intent_started_at IS NULL)),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours' AND updated_at>=created_at)
);
CREATE UNIQUE INDEX event_deliveries_test_unique ON event_deliveries(event_id,channel_id,replay_generation) WHERE delivery_kind='test';
CREATE TABLE event_delivery_attempts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,delivery_id uuid NOT NULL,attempt_no integer NOT NULL CHECK(attempt_no BETWEEN 1 AND 8),lease_generation integer NOT NULL CHECK(lease_generation>0),
 started_at timestamptz NOT NULL,finished_at timestamptz NOT NULL,outcome text NOT NULL CHECK(outcome IN ('succeeded','failed','uncertain')),send_started boolean NOT NULL,http_status integer CHECK(http_status IS NULL OR http_status BETWEEN 100 AND 599),
 duration_ms integer NOT NULL CHECK(duration_ms>=0),error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),retryable boolean NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(delivery_id,attempt_no),FOREIGN KEY(cluster_id,workspace_id,delivery_id) REFERENCES event_deliveries(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK(isfinite(started_at) AND isfinite(finished_at) AND finished_at>=started_at),CHECK(outcome<>'uncertain' OR send_started),CHECK(outcome<>'succeeded' OR(send_started AND NOT retryable))
);
CREATE TABLE user_notification_subscriptions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 event_types text[] NOT NULL,native_type text,native_ids uuid[] NOT NULL DEFAULT '{}',physical_tags text[] NOT NULL DEFAULT '{}',in_app_enabled boolean NOT NULL DEFAULT true,
 status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','deleted')),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),deleted_at timestamptz,retention_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(cluster_id,workspace_id,id),UNIQUE(cluster_id,workspace_id,id,user_id),UNIQUE(user_id,cluster_id,workspace_id,name),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,CHECK(m7_filter(event_types,native_type,native_ids,physical_tags)),CHECK(updated_at>=created_at),
 CHECK((status='deleted' AND deleted_at IS NOT NULL AND retention_until IS NOT NULL AND retention_until>=deleted_at) OR(status<>'deleted' AND deleted_at IS NULL AND retention_until IS NULL))
);
CREATE TABLE user_notification_subscription_versions (
 sequence bigserial NOT NULL UNIQUE,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,subscription_id uuid NOT NULL,revision integer NOT NULL CHECK(revision>0),user_id uuid NOT NULL,name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
 event_types text[] NOT NULL,native_type text,native_ids uuid[] NOT NULL DEFAULT '{}',physical_tags text[] NOT NULL DEFAULT '{}',in_app_enabled boolean NOT NULL,status text NOT NULL CHECK(status IN ('active','disabled','deleted')),created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,subscription_id,revision),FOREIGN KEY(cluster_id,workspace_id,subscription_id,user_id) REFERENCES user_notification_subscriptions(cluster_id,workspace_id,id,user_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(m7_filter(event_types,native_type,native_ids,physical_tags))
);
CREATE TABLE user_notifications (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,workspace_id uuid,event_id uuid NOT NULL REFERENCES event_records(id) ON DELETE RESTRICT,
 title text NOT NULL CHECK(length(title) BETWEEN 1 AND 256),summary_safe text NOT NULL CHECK(octet_length(summary_safe)<=4096),link_kind text NOT NULL CHECK(link_kind IN ('none','event','audit','workflow','entity')),link_id uuid,
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),read_at timestamptz,dismissed_at timestamptz,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(user_id,event_id),
 CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL),FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK((link_kind='none' AND link_id IS NULL) OR(link_kind<>'none' AND link_id IS NOT NULL)),CHECK(read_at IS NULL OR read_at>=created_at),CHECK(dismissed_at IS NULL OR dismissed_at>=created_at)
);
CREATE TABLE audit_export_jobs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT,workspace_id uuid,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),request_hash text NOT NULL CHECK(m7_hex64(request_hash)),format text NOT NULL CHECK(format IN ('ndjson','csv')),
 filter_safe jsonb NOT NULL CHECK(m7_object(filter_safe,8192)),upper_bounds jsonb NOT NULL CHECK(m7_object(upper_bounds,65536)),permission_version text NOT NULL CHECK(octet_length(permission_version) BETWEEN 1 AND 1024),
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','running','succeeded','incomplete','failed','cancelled','expired')),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),row_count integer NOT NULL DEFAULT 0 CHECK(row_count BETWEEN 0 AND 100000),bytes_count integer NOT NULL DEFAULT 0 CHECK(bytes_count BETWEEN 0 AND 33554432),
 digest text CHECK(digest IS NULL OR m7_hex64(digest)),output_secret text CHECK(output_secret IS NULL OR m6_encrypted(output_secret,50331648)),
 lease_owner_hash text CHECK(lease_owner_hash IS NULL OR m7_hex64(lease_owner_hash)),lease_generation integer NOT NULL DEFAULT 0 CHECK(lease_generation>=0),lease_until timestamptz,
 error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(actor_id,idempotency_key),FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,CHECK(workspace_id IS NULL OR cluster_id IS NOT NULL),CHECK(expires_at>created_at AND updated_at>=created_at),
 CHECK((state='running' AND lease_owner_hash IS NOT NULL AND lease_until IS NOT NULL AND lease_generation>0) OR(state<>'running' AND lease_owner_hash IS NULL AND lease_until IS NULL)),
 CHECK(state NOT IN ('succeeded','incomplete') OR(output_secret IS NOT NULL AND digest IS NOT NULL)),CHECK(state<>'expired' OR output_secret IS NULL)
);

-- Historical and configuration-version facts are immutable for owner and runtime alike.
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['audit_event_scopes','event_records','notification_channel_versions','event_subscription_versions','user_notification_subscription_versions','event_delivery_attempts','event_detection_observations'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m6_reject_history_mutation()',tab||'_append_only',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m6_reject_history_mutation()',tab||'_no_truncate',tab);
  EXECUTE format('REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON %I FROM PUBLIC',tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['event_outbox','notification_channels','event_subscriptions','event_deliveries','user_notification_subscriptions','user_notifications','event_detection_state','audit_export_jobs'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m6_reject_history_mutation()',tab||'_no_truncate',tab);
 END LOOP;
END;$$;
CREATE TRIGGER event_outbox_identity BEFORE UPDATE OR DELETE ON event_outbox FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,event_id,created_at');
CREATE TRIGGER notification_channels_identity BEFORE UPDATE OR DELETE ON notification_channels FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,name,type,created_by,created_at');
CREATE TRIGGER event_subscriptions_identity BEFORE UPDATE OR DELETE ON event_subscriptions FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,channel_id,name,created_by,created_at');
CREATE TRIGGER event_deliveries_identity BEFORE UPDATE OR DELETE ON event_deliveries FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,cluster_id,workspace_id,event_id,delivery_kind,subscription_id,subscription_revision,channel_id,channel_revision,credential_generation,creator_id,replay_generation,parent_delivery_id,idempotency_key,payload_safe,payload_digest,expires_at,created_at');
CREATE TRIGGER notification_preferences_identity BEFORE UPDATE OR DELETE ON user_notification_subscriptions FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,user_id,cluster_id,workspace_id,name,created_at');
CREATE TRIGGER user_notifications_identity BEFORE UPDATE OR DELETE ON user_notifications FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,user_id,cluster_id,workspace_id,event_id,title,summary_safe,link_kind,link_id,created_at');
CREATE TRIGGER event_detection_state_identity BEFORE UPDATE OR DELETE ON event_detection_state FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('cluster_id,workspace_id,detector_key,subject_type,subject_id');
CREATE TRIGGER audit_export_jobs_identity BEFORE UPDATE OR DELETE ON audit_export_jobs FOR EACH ROW EXECUTE FUNCTION m6_guard_identity('id,actor_id,cluster_id,workspace_id,idempotency_key,request_hash,format,filter_safe,upper_bounds,permission_version,expires_at,created_at');
ALTER TABLE notification_channels ADD CONSTRAINT channel_current_version FOREIGN KEY(cluster_id,workspace_id,id,revision) REFERENCES notification_channel_versions(cluster_id,workspace_id,channel_id,revision) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE event_subscriptions ADD CONSTRAINT subscription_current_version FOREIGN KEY(cluster_id,workspace_id,id,revision) REFERENCES event_subscription_versions(cluster_id,workspace_id,subscription_id,revision) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE user_notification_subscriptions ADD CONSTRAINT personal_current_version FOREIGN KEY(cluster_id,workspace_id,id,revision) REFERENCES user_notification_subscription_versions(cluster_id,workspace_id,subscription_id,revision) DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION m7_validate_current_version() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE root jsonb;ver jsonb;rid uuid;field text;fields text[];
BEGIN
 IF TG_TABLE_NAME IN ('notification_channels','notification_channel_versions') THEN
  IF TG_TABLE_NAME='notification_channels' THEN rid:=NEW.id;ELSE rid:=NEW.channel_id;END IF;
  SELECT to_jsonb(c) INTO root FROM notification_channels c WHERE id=rid;
  SELECT to_jsonb(v) INTO ver FROM notification_channel_versions v WHERE channel_id=rid AND revision=(root->>'revision')::integer;
  fields:=ARRAY['cluster_id','workspace_id','revision','status','type','endpoint_secret','auth_secret','options_safe','credential_generation'];
  IF ver->>'created_by' IS DISTINCT FROM root->>'updated_by' THEN RAISE EXCEPTION 'Channel version author mismatch' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME IN ('event_subscriptions','event_subscription_versions') THEN
  IF TG_TABLE_NAME='event_subscriptions' THEN rid:=NEW.id;ELSE rid:=NEW.subscription_id;END IF;
  SELECT to_jsonb(c) INTO root FROM event_subscriptions c WHERE id=rid;
  SELECT to_jsonb(v) INTO ver FROM event_subscription_versions v WHERE subscription_id=rid AND revision=(root->>'revision')::integer;
  fields:=ARRAY['cluster_id','workspace_id','revision','channel_id','status','event_types','native_type','native_ids','physical_tags'];
  IF ver->>'created_by' IS DISTINCT FROM root->>'updated_by' THEN RAISE EXCEPTION 'Subscription version author mismatch' USING ERRCODE='23514';END IF;
 ELSE
  IF TG_TABLE_NAME='user_notification_subscriptions' THEN rid:=NEW.id;ELSE rid:=NEW.subscription_id;END IF;
  SELECT to_jsonb(c) INTO root FROM user_notification_subscriptions c WHERE id=rid;
  SELECT to_jsonb(v) INTO ver FROM user_notification_subscription_versions v WHERE subscription_id=rid AND revision=(root->>'revision')::integer;
  fields:=ARRAY['cluster_id','workspace_id','revision','user_id','name','status','event_types','native_type','native_ids','physical_tags','in_app_enabled'];
 END IF;
 IF root IS NULL OR ver IS NULL THEN RAISE EXCEPTION 'Current immutable version missing' USING ERRCODE='23514';END IF;
 FOREACH field IN ARRAY fields LOOP IF root->field IS DISTINCT FROM ver->field THEN RAISE EXCEPTION 'Current version does not describe actual root' USING ERRCODE='23514';END IF;END LOOP;RETURN NULL;
END;$$;
DO $$DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['notification_channels','notification_channel_versions','event_subscriptions','event_subscription_versions','user_notification_subscriptions','user_notification_subscription_versions'] LOOP EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m7_validate_current_version()',tab||'_version_complete',tab);END LOOP;END;$$;
CREATE FUNCTION m7_guard_progress() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE n jsonb:=to_jsonb(NEW);o jsonb:=to_jsonb(OLD);
BEGIN
 IF NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'Progress must advance exact revision' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='notification_channels' AND ((n->'endpoint_secret') IS DISTINCT FROM (o->'endpoint_secret') OR (n->'auth_secret') IS DISTINCT FROM (o->'auth_secret')) AND (n->'credential_generation')<>to_jsonb((o->>'credential_generation')::integer+1) THEN RAISE EXCEPTION 'Changed channel material requires a new generation' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='notification_channels' AND (n->'endpoint_secret') IS NOT DISTINCT FROM (o->'endpoint_secret') AND (n->'auth_secret') IS NOT DISTINCT FROM (o->'auth_secret') AND (n->'credential_generation')<>(o->'credential_generation') THEN RAISE EXCEPTION 'Unchanged channel material retains generation' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='event_deliveries' AND o->>'state' IN ('succeeded','exhausted','cancelled') THEN RAISE EXCEPTION 'Terminal delivery cannot reopen' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='event_deliveries' AND ((n->'attempt_count')<(o->'attempt_count') OR (n->'lease_generation')<(o->'lease_generation')) THEN RAISE EXCEPTION 'Delivery progress cannot rewind' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='user_notifications' AND (((o->'read_at')<>'null'::jsonb AND (n->'read_at') IS DISTINCT FROM (o->'read_at')) OR((o->'dismissed_at')<>'null'::jsonb AND (n->'dismissed_at') IS DISTINCT FROM (o->'dismissed_at'))) THEN RAISE EXCEPTION 'Notification owner marker cannot rewind' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;$$;
DO $$DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['notification_channels','event_subscriptions','user_notification_subscriptions','user_notifications','event_deliveries','event_outbox','audit_export_jobs','event_detection_state'] LOOP EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION m7_guard_progress()',tab||'_progress',tab);END LOOP;END;$$;
CREATE FUNCTION m7_validate_audit_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a audit_events%ROWTYPE;side jsonb;
BEGIN
 SELECT * INTO a FROM audit_events WHERE id=NEW.audit_event_id;
 IF NOT FOUND OR a.event_hash IS DISTINCT FROM NEW.audit_event_hash OR a.cluster_id IS DISTINCT FROM NEW.cluster_id OR a.workspace_id IS DISTINCT FROM NEW.workspace_id THEN RAISE EXCEPTION 'Audit annotation must bind the original hash and scope' USING ERRCODE='23514';END IF;
 FOR side IN SELECT s FROM jsonb_array_elements(jsonb_build_array(NEW.scope->'before',NEW.scope->'after')) v(s) LOOP
  IF side<>'null'::jsonb AND side->>'workspaceId' IS NOT NULL AND NOT EXISTS(SELECT 1 FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=(side->>'workspaceId')::uuid) THEN RAISE EXCEPTION 'Historical side workspace is foreign' USING ERRCODE='23514';END IF;
 END LOOP;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER audit_scope_source AFTER INSERT ON audit_event_scopes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m7_validate_audit_scope();
CREATE FUNCTION m7_assert_event_source(eid uuid) RETURNS void LANGUAGE plpgsql AS $$
DECLARE e event_records%ROWTYPE;a audit_events%ROWTYPE;ann audit_event_scopes%ROWTYPE;o event_detection_observations%ROWTYPE;j jsonb;p jsonb;w workflows%ROWTYPE;x workflow_executions%ROWTYPE;s workflow_steps%ROWTYPE;
BEGIN
 SELECT * INTO e FROM event_records WHERE id=eid;IF NOT FOUND THEN RETURN;END IF;
 IF e.audit_event_id IS NOT NULL THEN
  SELECT * INTO a FROM audit_events WHERE id=e.audit_event_id;SELECT * INTO ann FROM audit_event_scopes WHERE audit_event_id=e.audit_event_id;
  IF a.id IS NULL OR ann.audit_event_id IS NULL OR a.cluster_id IS DISTINCT FROM e.cluster_id OR a.workspace_id IS DISTINCT FROM e.workspace_id OR a.actor_id IS DISTINCT FROM e.actor_id OR ann.scope IS DISTINCT FROM e.source_scope OR a.occurred_at IS DISTINCT FROM e.occurred_at THEN RAISE EXCEPTION 'Event audit pointer is not the exact source' USING ERRCODE='23514';END IF;
 END IF;
 IF e.source_kind='observation' THEN
  SELECT * INTO o FROM event_detection_observations WHERE id=e.observation_id;
  IF o.id IS NULL OR o.cluster_id IS DISTINCT FROM e.cluster_id OR o.workspace_id IS DISTINCT FROM e.workspace_id OR o.subject_type IS DISTINCT FROM e.entity_type OR o.subject_id IS DISTINCT FROM e.entity_id OR o.source_scope IS DISTINCT FROM e.source_scope OR o.observed_at IS DISTINCT FROM e.occurred_at OR o.quality<>'verified' THEN RAISE EXCEPTION 'Observation event needs an exact verified source' USING ERRCODE='23514';END IF;
 ELSIF e.source_kind<>'audit' THEN
  IF e.source_kind='iam' THEN SELECT to_jsonb(r) INTO j FROM iam_operations r WHERE id=e.iam_operation_id;
  ELSIF e.source_kind='mutation' THEN SELECT to_jsonb(r) INTO j FROM mutation_operations r WHERE id=e.mutation_id;
  ELSIF e.source_kind='portal' THEN SELECT to_jsonb(r) INTO j FROM portal_operations r WHERE id=e.portal_operation_id;
  ELSE SELECT to_jsonb(r) INTO j FROM workflows r WHERE id=e.workflow_id;END IF;
  IF j IS NULL OR j->>'cluster_id' IS DISTINCT FROM e.cluster_id::text OR j->>'workspace_id' IS DISTINCT FROM e.workspace_id::text THEN RAISE EXCEPTION 'Event typed source is foreign' USING ERRCODE='23514';END IF;
 END IF;
 IF e.queue_request_hmac IS NOT NULL THEN
  p:=a.after->'operationProof';
  IF a.result<>'success' OR a.action NOT IN ('event.channel.test','event.delivery.replay') OR p->>'version' IS DISTINCT FROM '1' OR p->>'handler' IS DISTINCT FROM a.action OR p->>'requestHmac' IS DISTINCT FROM e.queue_request_hmac OR a.entity_type IS DISTINCT FROM e.entity_type OR a.entity_id IS DISTINCT FROM e.entity_id::text OR a.after->'result' IS DISTINCT FROM '{"queued":true}'::jsonb THEN RAISE EXCEPTION 'Queue requires the exact actual business audit' USING ERRCODE='23514';END IF;
  IF e.iam_operation_id IS NOT NULL THEN
   IF p->>'iamOperationId' IS DISTINCT FROM e.iam_operation_id::text OR p?'workflow' OR j->>'actor_id' IS DISTINCT FROM e.actor_id::text OR j->>'module' IS DISTINCT FROM 'events' OR j->>'action' IS DISTINCT FROM 'write' OR j->>'target_id' IS DISTINCT FROM e.entity_id::text OR j->>'state' IS DISTINCT FROM 'succeeded' OR j->>'remote_completed' IS DISTINCT FROM 'true' OR j->>'request_hash' IS DISTINCT FROM e.queue_request_hmac THEN RAISE EXCEPTION 'Queue IAM transaction did not succeed' USING ERRCODE='23514';END IF;
  ELSE
   SELECT * INTO w FROM workflows WHERE id=e.workflow_id;SELECT * INTO x FROM workflow_executions WHERE id=e.workflow_execution_id;SELECT * INTO s FROM workflow_steps WHERE id=e.workflow_step_id;
   IF w.state<>'succeeded' OR x.state<>'succeeded' OR s.state<>'succeeded' OR s.kind<>'metadata' OR s.operation_id IS NOT NULL OR s.native_requests<>'[]'::jsonb OR s.handler IS DISTINCT FROM a.action OR s.entity_type IS DISTINCT FROM e.entity_type OR s.entity_id IS DISTINCT FROM e.entity_id OR x.execution_actor_id IS DISTINCT FROM e.actor_id OR s.metadata_payload_hmac IS DISTINCT FROM e.queue_request_hmac OR p->>'beforeHmac' IS DISTINCT FROM s.metadata_before_hmac OR p->>'payloadHmac' IS DISTINCT FROM s.metadata_payload_hmac OR p->'workflow'->>'id' IS DISTINCT FROM w.id::text OR p->'workflow'->>'executionId' IS DISTINCT FROM x.id::text OR p->'workflow'->>'stepId' IS DISTINCT FROM s.id::text OR p->'workflow'->>'planHash' IS DISTINCT FROM s.plan_hash OR p->'workflow'->>'planRevision' IS DISTINCT FROM s.plan_revision::text THEN RAISE EXCEPTION 'Queue workflow tuple did not commit terminal success' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
END;$$;
CREATE FUNCTION m7_validate_event_source() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM m7_assert_event_source(NEW.id);RETURN NULL;END;$$;
CREATE CONSTRAINT TRIGGER event_source_actual AFTER INSERT ON event_records DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m7_validate_event_source();
CREATE FUNCTION m7_recheck_queue_sources() RETURNS trigger LANGUAGE plpgsql AS $$DECLARE e record;BEGIN FOR e IN SELECT id FROM event_records WHERE queue_request_hmac IS NOT NULL AND(iam_operation_id=NEW.id OR workflow_id=NEW.id OR workflow_execution_id=NEW.id OR workflow_step_id=NEW.id) LOOP PERFORM m7_assert_event_source(e.id);END LOOP;RETURN NULL;END;$$;
DO $$DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['iam_operations','workflows','workflow_executions','workflow_steps'] LOOP EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m7_recheck_queue_sources()',tab||'_m7_queue_guard',tab);END LOOP;END;$$;
CREATE FUNCTION m7_validate_delivery_source() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d event_deliveries%ROWTYPE;e event_records%ROWTYPE;c notification_channel_versions%ROWTYPE;s event_subscription_versions%ROWTYPE;a event_delivery_attempts%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='event_deliveries' THEN SELECT * INTO d FROM event_deliveries WHERE id=NEW.id;ELSE SELECT * INTO d FROM event_deliveries WHERE id=NEW.delivery_id;END IF;
 SELECT * INTO e FROM event_records WHERE id=d.event_id;SELECT * INTO c FROM notification_channel_versions WHERE channel_id=d.channel_id AND revision=d.channel_revision;
 IF e.id IS NULL OR e.cluster_id IS DISTINCT FROM d.cluster_id OR e.workspace_id IS DISTINCT FROM d.workspace_id OR e.payload_safe IS DISTINCT FROM d.payload_safe OR e.payload_digest IS DISTINCT FROM d.payload_digest OR c.status<>'active' THEN RAISE EXCEPTION 'Delivery is not scoped to its actual event/configuration' USING ERRCODE='23514';END IF;
 IF d.delivery_kind='subscription' AND d.replay_generation=0 THEN SELECT * INTO s FROM event_subscription_versions WHERE subscription_id=d.subscription_id AND revision=d.subscription_revision;IF s.status<>'active' OR s.created_by IS DISTINCT FROM d.creator_id THEN RAISE EXCEPTION 'Delivery creator must be the subscription version author' USING ERRCODE='23514';END IF;END IF;
 IF TG_TABLE_NAME='event_delivery_attempts' THEN IF d.attempt_count<NEW.attempt_no OR d.lease_generation<NEW.lease_generation THEN RAISE EXCEPTION 'Attempt completion must advance its durable delivery' USING ERRCODE='23514';END IF;END IF;
 IF d.replay_generation>0 AND NOT EXISTS(SELECT 1 FROM event_deliveries prior WHERE prior.id=d.parent_delivery_id AND prior.cluster_id=d.cluster_id AND prior.workspace_id=d.workspace_id AND prior.event_id=d.event_id AND prior.state IN('succeeded','exhausted','cancelled','paused_authority') AND prior.replay_generation<d.replay_generation AND NOT EXISTS(SELECT 1 FROM event_delivery_attempts last_attempt WHERE last_attempt.delivery_id=prior.id AND last_attempt.outcome='uncertain' AND last_attempt.attempt_no=(SELECT max(attempt_no) FROM event_delivery_attempts WHERE delivery_id=prior.id))) THEN RAISE EXCEPTION 'Replay cannot bypass an unresolved source delivery' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER delivery_source_actual AFTER INSERT OR UPDATE ON event_deliveries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m7_validate_delivery_source();
CREATE CONSTRAINT TRIGGER delivery_attempt_actual AFTER INSERT ON event_delivery_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m7_validate_delivery_source();
CREATE FUNCTION m7_validate_notification_source() RETURNS trigger LANGUAGE plpgsql AS $$DECLARE e event_records%ROWTYPE;BEGIN SELECT * INTO e FROM event_records WHERE id=NEW.event_id;IF e.id IS NULL OR e.cluster_id IS DISTINCT FROM NEW.cluster_id OR e.workspace_id IS DISTINCT FROM NEW.workspace_id OR e.payload_safe->>'title' IS DISTINCT FROM NEW.title OR e.payload_safe->>'summary' IS DISTINCT FROM NEW.summary_safe THEN RAISE EXCEPTION 'Notification must retain its actual scoped source' USING ERRCODE='23514';END IF;RETURN NULL;END;$$;
CREATE CONSTRAINT TRIGGER notification_source_actual AFTER INSERT OR UPDATE ON user_notifications DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m7_validate_notification_source();
CREATE FUNCTION m7_validate_detector_state() RETURNS trigger LANGUAGE plpgsql AS $$DECLARE s event_detection_state%ROWTYPE;o event_detection_observations%ROWTYPE;part jsonb;ref event_detection_observations%ROWTYPE;BEGIN
 SELECT * INTO s FROM event_detection_state WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND detector_key=NEW.detector_key AND subject_type=NEW.subject_type AND subject_id=NEW.subject_id;
 SELECT * INTO o FROM event_detection_observations WHERE id=s.last_observation_id;
 IF o.id IS NULL OR o.transport_scope IS DISTINCT FROM s.transport_scope OR o.observed_node_id IS DISTINCT FROM s.observed_node_id OR o.config_fingerprint IS DISTINCT FROM s.config_fingerprint OR o.scope_epoch IS DISTINCT FROM s.scope_epoch OR o.observed_at IS DISTINCT FROM s.last_observed_at OR s.last_observation_safe->>'version' IS DISTINCT FROM '1' OR NOT(s.last_observation_safe ?& ARRAY['version','baseline','candidate']) OR(SELECT count(*) FROM jsonb_object_keys(s.last_observation_safe))<>3 THEN RAISE EXCEPTION 'Baseline must retain exact actual observation context' USING ERRCODE='23514';END IF;
 FOR part IN SELECT v FROM jsonb_array_elements(jsonb_build_array(s.last_observation_safe->'baseline',s.last_observation_safe->'candidate')) x(v) LOOP
  IF part='null'::jsonb THEN CONTINUE;END IF;
  SELECT * INTO ref FROM event_detection_observations WHERE id=(part->>'observationId')::uuid;
  IF ref.id IS NULL OR ref.quality<>'verified' OR ref.cluster_id IS DISTINCT FROM s.cluster_id OR ref.workspace_id IS DISTINCT FROM s.workspace_id OR ref.detector_key IS DISTINCT FROM s.detector_key OR ref.subject_id IS DISTINCT FROM s.subject_id OR ref.transport_scope IS DISTINCT FROM s.transport_scope OR ref.observed_node_id IS DISTINCT FROM s.observed_node_id OR ref.config_fingerprint IS DISTINCT FROM s.config_fingerprint OR ref.scope_epoch IS DISTINCT FROM s.scope_epoch OR ref.observation_safe IS DISTINCT FROM part->'value' OR ref.observed_at>s.last_observed_at THEN RAISE EXCEPTION 'Baseline pointer is not a verified same-context historical observation' USING ERRCODE='23514';END IF;
 END LOOP;RETURN NULL;END;$$;
CREATE CONSTRAINT TRIGGER detector_state_actual AFTER INSERT OR UPDATE ON event_detection_state DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m7_validate_detector_state();
-- Append-only facts retain read privileges; pending mutable rows are the only locked rows.
CREATE INDEX event_records_scope_time ON event_records(cluster_id,workspace_id,occurred_at DESC,id DESC);
CREATE INDEX event_outbox_due ON event_outbox(next_attempt_at,id) WHERE state IN ('pending','dispatching');
CREATE INDEX deliveries_due ON event_deliveries(next_attempt_at,id) WHERE state IN ('pending','retrying','uncertain');
CREATE INDEX notifications_owner_page ON user_notifications(user_id,created_at DESC,id DESC);
CREATE INDEX detection_observations_subject ON event_detection_observations(cluster_id,workspace_id,detector_key,subject_id,observed_at DESC);
CREATE INDEX audit_export_jobs_owner ON audit_export_jobs(actor_id,created_at DESC,id DESC);

ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_kind_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_kind_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata'));
ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries'));
CREATE OR REPLACE FUNCTION m6_validate_workflow_subject() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE subject_exists boolean; owner_id uuid;
BEGIN
  IF NEW.kind='event-metadata' THEN
    IF NEW.requester_type<>'console' OR NEW.subject_type NOT IN ('notification_channels','event_subscriptions','event_deliveries') THEN RAISE EXCEPTION 'Event metadata is a fixed console workflow' USING ERRCODE='23514';END IF;
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3)',NEW.subject_type) INTO subject_exists USING NEW.cluster_id,NEW.workspace_id,NEW.subject_id;
    IF NOT subject_exists THEN RAISE EXCEPTION 'Event metadata subject is foreign' USING ERRCODE='23503';END IF;
    IF EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=NEW.id AND(kind<>'metadata' OR operation_id IS NOT NULL OR native_requests<>'[]'::jsonb OR handler NOT IN ('event.channel.save','event.channel.status','event.channel.delete','event.channel.restore','event.channel.test','event.subscription.save','event.subscription.delete','event.subscription.restore','event.delivery.replay'))) THEN RAISE EXCEPTION 'Event workflow cannot claim native authority' USING ERRCODE='23514';END IF;RETURN NULL;
  END IF;
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
