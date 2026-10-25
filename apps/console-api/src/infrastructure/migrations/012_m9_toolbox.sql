-- M9 console-only editing materials, exact batches and node-local cache operations.
-- Kong remains unchanged. SQL000--011 and immutable historical evidence stay intact.
ALTER TABLE clusters ADD COLUMN proxy_origin text CHECK(proxy_origin IS NULL OR (length(proxy_origin)<=2048 AND proxy_origin ~ '^https?://[^/@?#[:space:]]+/?$'));
CREATE TABLE toolbox_metadata_operations (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 action text NOT NULL CHECK(action IN('draft.create','draft.update','draft.archive','draft.restore','proxy.configure')),
 subject_id uuid NOT NULL,result_secret text NOT NULL CHECK(m6_encrypted(result_secret)),created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(actor_id,idempotency_key),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT
);
CREATE TABLE configuration_drafts (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),entity_type text NOT NULL CHECK(entity_type IN('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis')),
 native_id uuid,current_version integer NOT NULL CHECK(current_version>0),revision integer NOT NULL DEFAULT 1 CHECK(revision>0),
 state text NOT NULL DEFAULT 'active' CHECK(state IN('active','deleted')),deleted_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK((state='deleted')=(deleted_at IS NOT NULL))
);
CREATE TABLE configuration_draft_versions (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,draft_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),
 payload_secret text NOT NULL CHECK(m6_encrypted(payload_secret)),payload_hmac text NOT NULL CHECK(m8_hex64(payload_hmac)),
 operation_id uuid NOT NULL,created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,draft_id,version),
 FOREIGN KEY(cluster_id,workspace_id,draft_id) REFERENCES configuration_drafts(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(cluster_id,workspace_id,operation_id) REFERENCES toolbox_metadata_operations(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE configuration_drafts ADD CONSTRAINT configuration_draft_current_version_fk FOREIGN KEY(cluster_id,workspace_id,id,current_version)
 REFERENCES configuration_draft_versions(cluster_id,workspace_id,draft_id,version) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX configuration_drafts_owner_page ON configuration_drafts(cluster_id,workspace_id,owner_user_id,created_at DESC,id DESC);
ALTER TABLE configuration_drafts ADD CONSTRAINT configuration_draft_owner_tuple UNIQUE(cluster_id,workspace_id,id,owner_user_id);
ALTER TABLE toolbox_metadata_operations ADD CONSTRAINT toolbox_metadata_origin_tuple UNIQUE(cluster_id,workspace_id,id,actor_id,subject_id);
ALTER TABLE configuration_draft_versions ADD CONSTRAINT configuration_draft_version_owner_fk FOREIGN KEY(cluster_id,workspace_id,draft_id,created_by)
 REFERENCES configuration_drafts(cluster_id,workspace_id,id,owner_user_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE configuration_draft_versions ADD CONSTRAINT configuration_draft_version_operation_fk FOREIGN KEY(cluster_id,workspace_id,operation_id,created_by,draft_id)
 REFERENCES toolbox_metadata_operations(cluster_id,workspace_id,id,actor_id,subject_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE toolbox_batches (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 configuration_job_id uuid NOT NULL,plan_id uuid NOT NULL,kind text NOT NULL CHECK(kind IN('tags','plugin-enabled','delete')),
 selection_hmac text NOT NULL CHECK(m8_hex64(selection_hmac)),selected_count integer NOT NULL CHECK(selected_count BETWEEN 1 AND 50),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(cluster_id,workspace_id,id),UNIQUE(configuration_job_id),
 FOREIGN KEY(cluster_id,workspace_id,configuration_job_id) REFERENCES configuration_jobs(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,plan_id) REFERENCES configuration_plans(cluster_id,workspace_id,id) ON DELETE RESTRICT
);
CREATE TABLE toolbox_debug_runs (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 kind text NOT NULL CHECK(kind IN('route-simulation','proxy-probe')),input_hmac text NOT NULL CHECK(m8_hex64(input_hmac)),
 quality text NOT NULL CHECK(quality IN('complete','partial','unsupported')),safe_result jsonb NOT NULL CHECK(jsonb_typeof(safe_result)='object' AND octet_length(safe_result::text)<=262144),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT
);
CREATE FUNCTION m9_validate_batch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF NOT EXISTS(SELECT 1 FROM configuration_jobs j JOIN configuration_plans p ON p.source_job_id=j.id AND p.cluster_id=j.cluster_id AND p.workspace_id=j.workspace_id
 WHERE j.id=NEW.configuration_job_id AND j.cluster_id=NEW.cluster_id AND j.workspace_id=NEW.workspace_id AND j.actor_id=NEW.actor_id AND j.plan_id=NEW.plan_id AND p.id=NEW.plan_id)
 THEN RAISE EXCEPTION 'Batch must retain its real owner job and immutable plan' USING ERRCODE='23503';END IF;RETURN NEW;END;$$;
CREATE TRIGGER toolbox_batches_origin BEFORE INSERT ON toolbox_batches FOR EACH ROW EXECUTE FUNCTION m9_validate_batch();
CREATE TABLE toolbox_operations (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,transport_scope text NOT NULL CHECK(m8_hex64(transport_scope)),
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),
 kind text NOT NULL CHECK(kind='cache-invalidate'),cache_key text NOT NULL CHECK(cache_key ~ '^[A-Za-z0-9_.:-]{1,256}$' AND cache_key NOT IN('.','..')),
 request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),before_secret text NOT NULL CHECK(m6_encrypted(before_secret)),
 cluster_revision integer NOT NULL,workspace_revision integer NOT NULL,execution_mode text NOT NULL CHECK(execution_mode IN('direct','approval')),
 workflow_id uuid,execution_actor_id uuid REFERENCES users(id) ON DELETE RESTRICT,
 state text NOT NULL DEFAULT 'planned' CHECK(state IN('planned','pending-approval','running','succeeded','failed','uncertain')),
 remote_started boolean NOT NULL DEFAULT false,remote_completed boolean NOT NULL DEFAULT false,
 revision integer NOT NULL DEFAULT 1 CHECK(revision>0),safe_result jsonb NOT NULL DEFAULT '{}',error_code text,
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL,
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(actor_id,idempotency_key),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK(NOT remote_completed OR remote_started),CHECK(state<>'succeeded' OR remote_completed)
);
CREATE FUNCTION m9_guard_draft() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF ROW(NEW.id,NEW.cluster_id,NEW.workspace_id,NEW.owner_user_id,NEW.entity_type,NEW.native_id,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.cluster_id,OLD.workspace_id,OLD.owner_user_id,OLD.entity_type,OLD.native_id,OLD.created_at)
 OR NEW.revision<>OLD.revision+1 OR NEW.current_version<OLD.current_version THEN RAISE EXCEPTION 'Draft identity cannot change' USING ERRCODE='23514';END IF;RETURN NEW;END;$$;
CREATE TRIGGER configuration_drafts_identity BEFORE UPDATE ON configuration_drafts FOR EACH ROW EXECUTE FUNCTION m9_guard_draft();
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['toolbox_metadata_operations','configuration_draft_versions','toolbox_batches','toolbox_debug_runs'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['configuration_drafts','toolbox_operations'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_no_delete()',tab||'_no_delete',tab);
 END LOOP;
END;$$;

CREATE FUNCTION m9_guard_cache_operation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF ROW(NEW.id,NEW.cluster_id,NEW.workspace_id,NEW.transport_scope,NEW.actor_id,NEW.idempotency_key,NEW.kind,NEW.cache_key,NEW.request_hmac,NEW.before_hmac,NEW.before_secret,NEW.cluster_revision,NEW.workspace_revision,NEW.execution_mode,NEW.workflow_id,NEW.created_at,NEW.expires_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.cluster_id,OLD.workspace_id,OLD.transport_scope,OLD.actor_id,OLD.idempotency_key,OLD.kind,OLD.cache_key,OLD.request_hmac,OLD.before_hmac,OLD.before_secret,OLD.cluster_revision,OLD.workspace_revision,OLD.execution_mode,OLD.workflow_id,OLD.created_at,OLD.expires_at)
 OR NEW.revision<>OLD.revision+1 OR(OLD.remote_started AND NOT NEW.remote_started) OR(OLD.remote_completed AND NOT NEW.remote_completed)
 OR(OLD.execution_actor_id IS NOT NULL AND NEW.execution_actor_id IS DISTINCT FROM OLD.execution_actor_id)
 OR(OLD.state IN('succeeded','failed','uncertain') AND NEW IS DISTINCT FROM OLD) THEN RAISE EXCEPTION 'Cache operation identity and terminal fact cannot change' USING ERRCODE='23514';END IF;RETURN NEW;END;$$;
CREATE TRIGGER toolbox_operations_identity BEFORE UPDATE ON toolbox_operations FOR EACH ROW EXECUTE FUNCTION m9_guard_cache_operation();
ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_kind_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation'));
ALTER TABLE workflows DROP CONSTRAINT workflows_kind_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation'));
ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries','configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs','toolbox_operations'));

-- Preserve all prior subject validation branches, with one sealed operational wrapper.
CREATE OR REPLACE FUNCTION m6_validate_workflow_subject() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE subject_exists boolean;owner_id uuid;j configuration_jobs%ROWTYPE;
BEGIN

 IF NEW.subject_type='toolbox_operations' AND NEW.kind<>'toolbox-operation' THEN RAISE EXCEPTION 'Cache subjects require their exact operational wrapper' USING ERRCODE='23514';END IF;
 IF NEW.kind='toolbox-operation' THEN
  IF NEW.subject_type<>'toolbox_operations' OR NEW.requester_type<>'console'
   OR NOT EXISTS(SELECT 1 FROM toolbox_operations o WHERE o.cluster_id=NEW.cluster_id AND o.workspace_id=NEW.workspace_id AND o.id=NEW.subject_id AND o.actor_id=NEW.requester_user_id AND o.workflow_id=NEW.id AND o.execution_mode=NEW.execution_mode AND (TG_OP<>'INSERT' OR o.state='pending-approval'))
   OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision)<>1
   OR NOT EXISTS(SELECT 1 FROM workflow_steps WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND workflow_id=NEW.id AND plan_revision=NEW.plan_revision AND plan_hash=NEW.plan_hash AND kind='metadata' AND handler='toolbox.execute' AND entity_type='toolbox_operations' AND entity_id=NEW.subject_id AND native_requests='[]'::jsonb AND operation_id IS NULL)
   THEN RAISE EXCEPTION 'Cache wrapper must retain its exact scoped operation and handler' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
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
