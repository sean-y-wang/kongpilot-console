-- Long review intent is immutable business evidence, not HTTP/SID authority.
-- All facts below are append-only. No worker, permit or native endpoint opens.
CREATE TABLE entity_change_intents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 requester_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,credential_epoch bigint NOT NULL CHECK(credential_epoch>0),
 prepare_key text NOT NULL CHECK(length(prepare_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(requester_id,prepare_key),UNIQUE(cluster_id,workspace_id,id),
 UNIQUE(cluster_id,workspace_id,id,requester_id,credential_epoch,issued_at,expires_at),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '168 hours' AND issued_at<=created_at)
);
CREATE TABLE entity_change_intent_versions (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,intent_id uuid NOT NULL,intent_revision integer NOT NULL CHECK(intent_revision>0),
 requester_id uuid NOT NULL,credential_epoch bigint NOT NULL CHECK(credential_epoch>0),issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
 execution_mode text NOT NULL CHECK(execution_mode IN('direct','approval')),
 definition_id uuid NOT NULL,definition_version integer NOT NULL CHECK(definition_version>0),policy_hash text NOT NULL CHECK(m8_hex64(policy_hash)),
 change_digest text NOT NULL CHECK(m8_hex64(change_digest)),material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),
 packet_manifest_hmac text NOT NULL CHECK(m8_hex64(packet_manifest_hmac)),packet_count integer NOT NULL CHECK(packet_count BETWEEN 1 AND 1000),
 packet_manifest jsonb NOT NULL CHECK(jsonb_typeof(packet_manifest)='array' AND octet_length(packet_manifest::text)<=2097152),
 envelope_ciphertext text NOT NULL CHECK(m6_encrypted(envelope_ciphertext)),safe_review jsonb NOT NULL CHECK(m7_object(safe_review,2097152)),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,intent_id,intent_revision),
 UNIQUE(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac),
 FOREIGN KEY(cluster_id,workspace_id,intent_id,requester_id,credential_epoch,issued_at,expires_at)
  REFERENCES entity_change_intents(cluster_id,workspace_id,id,requester_id,credential_epoch,issued_at,expires_at) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,definition_id,definition_version)
  REFERENCES workflow_definition_versions(cluster_id,workspace_id,definition_id,version) ON DELETE RESTRICT
);
CREATE TABLE entity_change_intent_packets (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,intent_id uuid NOT NULL,intent_revision integer NOT NULL,
 material_hmac text NOT NULL,change_digest text NOT NULL,packet_manifest_hmac text NOT NULL,
 packet_key text NOT NULL CHECK(length(packet_key) BETWEEN 1 AND 160),packet_order integer NOT NULL CHECK(packet_order BETWEEN 1 AND 1000),
 dependencies text[] NOT NULL CHECK(cardinality(dependencies)<=1000 AND coalesce(array_ndims(dependencies),1)=1 AND array_position(dependencies,NULL) IS NULL),
 method text NOT NULL CHECK(method IN('POST','PATCH','DELETE')),path_hmac text NOT NULL CHECK(m8_hex64(path_hmac)),
 native_type text NOT NULL CHECK(m7_native_type(native_type)),native_id uuid NOT NULL,parent_id uuid,credential_kind text CHECK(credential_kind IS NULL OR credential_kind IN('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')),
 original_native_id uuid,mutation_action text NOT NULL CHECK(mutation_action IN('create','update','delete','restore','mark_healthy','mark_unhealthy')),
 permission_action text NOT NULL CHECK(permission_action IN('write','delete')),body_hmac text NOT NULL CHECK(m8_hex64(body_hmac)),before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,workspace_id,intent_id,intent_revision,packet_key),
 UNIQUE(cluster_id,workspace_id,intent_id,intent_revision,packet_order),
 FOREIGN KEY(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac)
  REFERENCES entity_change_intent_versions(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac) ON DELETE RESTRICT,
 CHECK((native_type IN('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls') AND credential_kind IS NOT NULL AND credential_kind=native_type AND parent_id IS NOT NULL)
  OR(native_type='targets' AND parent_id IS NOT NULL AND credential_kind IS NULL)
  OR(native_type IN('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis') AND parent_id IS NULL AND credential_kind IS NULL)),
 CHECK((mutation_action='delete' AND method='DELETE' AND permission_action='delete') OR(mutation_action<>'delete' AND method<>'DELETE' AND permission_action='write'))
);
CREATE TABLE entity_change_submissions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,intent_id uuid NOT NULL,intent_revision integer NOT NULL,
 material_hmac text NOT NULL,change_digest text NOT NULL,packet_manifest_hmac text NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,submit_key text NOT NULL CHECK(length(submit_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL CHECK(workflow_plan_revision>0),workflow_plan_hash text NOT NULL CHECK(m8_hex64(workflow_plan_hash)),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(actor_id,submit_key),UNIQUE(cluster_id,workspace_id,intent_id,intent_revision),UNIQUE(workflow_id),
 UNIQUE(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash),
 FOREIGN KEY(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac)
  REFERENCES entity_change_intent_versions(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id,workflow_plan_revision,workflow_plan_hash)
  REFERENCES workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

-- Reserved for Root's independently verified short HTTP source adapter. A row
-- or copied shape alone never authorizes a job, mutation or native packet.
CREATE TABLE entity_change_execution_sources (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,intent_id uuid NOT NULL,intent_revision integer NOT NULL,
 material_hmac text NOT NULL,change_digest text NOT NULL,packet_manifest_hmac text NOT NULL,
 workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL,workflow_plan_hash text NOT NULL,workflow_execution_id uuid NOT NULL,
 execution_actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,credential_epoch bigint NOT NULL CHECK(credential_epoch>0),
 session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,permission_version_hmac text NOT NULL CHECK(m8_hex64(permission_version_hmac)),
 issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(workflow_execution_id),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash)
  REFERENCES entity_change_submissions(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash)
  REFERENCES workflow_executions(cluster_id,workspace_id,id,workflow_id,plan_revision,plan_hash) ON DELETE RESTRICT,
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes' AND issued_at<=created_at)
);

ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries','configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs','toolbox_operations','workspace_migration_plans','governance_metadata_requests','workflow_policy_requests','entity_change_intents'));
DO $m11$ DECLARE definition text;BEGIN
 definition=pg_get_functiondef('m6_validate_workflow_subject()'::regprocedure);
 definition=regexp_replace(definition,'\mBEGIN\M',E'BEGIN\n IF NEW.kind=''native-change'' THEN RETURN NULL;END IF;');
 EXECUTE definition;
END;$m11$;

CREATE FUNCTION m11_validate_intent_graph() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE v entity_change_intent_versions%ROWTYPE;p entity_change_intent_packets%ROWTYPE;n integer;dep text;ord integer;item jsonb;policy workflow_definition_versions%ROWTYPE;
 BEGIN
 SELECT * INTO v FROM entity_change_intent_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND intent_id=NEW.intent_id AND intent_revision=NEW.intent_revision;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT * INTO policy FROM workflow_definition_versions WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND definition_id=v.definition_id AND version=v.definition_version;
 IF policy.policy_hash<>v.policy_hash OR NOT EXISTS(SELECT 1 FROM workflow_definitions d WHERE d.id=v.definition_id AND d.cluster_id=v.cluster_id AND d.workspace_id=v.workspace_id AND d.kind='native-change') THEN
  RAISE EXCEPTION 'Durable intent must bind the exact native change policy' USING ERRCODE='23514';END IF;
 IF policy.approval_format=2 AND v.expires_at>v.issued_at+(policy.policy->>'intentTtlHours')::integer*interval '1 hour' THEN
  RAISE EXCEPTION 'Durable intent deadline exceeds its immutable policy limit' USING ERRCODE='23514';END IF;
 SELECT count(*)::integer INTO n FROM entity_change_intent_packets WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND intent_id=v.intent_id AND intent_revision=v.intent_revision;
 IF n<>v.packet_count OR jsonb_array_length(v.packet_manifest)<>n THEN RAISE EXCEPTION 'Durable intent packet graph must be complete' USING ERRCODE='23514';END IF;
 FOR p IN SELECT * FROM entity_change_intent_packets WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND intent_id=v.intent_id AND intent_revision=v.intent_revision ORDER BY packet_order LOOP
  item=v.packet_manifest->(p.packet_order-1);
  IF p.packet_order>n OR item IS NULL OR cardinality(p.dependencies)<>(SELECT count(DISTINCT value)::integer FROM unnest(p.dependencies) value)
   OR item->>'key' IS DISTINCT FROM p.packet_key OR item->>'order' IS DISTINCT FROM p.packet_order::text OR item->'dependencies' IS DISTINCT FROM to_jsonb(p.dependencies)
   OR item->>'method' IS DISTINCT FROM p.method OR item->>'pathHmac' IS DISTINCT FROM p.path_hmac OR item->>'nativeType' IS DISTINCT FROM p.native_type OR item->>'nativeId' IS DISTINCT FROM p.native_id::text
   OR item->>'parentId' IS DISTINCT FROM p.parent_id::text OR item->>'credentialKind' IS DISTINCT FROM p.credential_kind OR item->>'originalNativeId' IS DISTINCT FROM p.original_native_id::text
   OR item->>'mutationAction' IS DISTINCT FROM p.mutation_action OR item->>'permissionAction' IS DISTINCT FROM p.permission_action OR item->>'bodyHmac' IS DISTINCT FROM p.body_hmac OR item->>'beforeHmac' IS DISTINCT FROM p.before_hmac
  THEN RAISE EXCEPTION 'Durable intent normalized packet must equal its immutable manifest' USING ERRCODE='23514';END IF;
  FOREACH dep IN ARRAY p.dependencies LOOP
   SELECT packet_order INTO ord FROM entity_change_intent_packets WHERE cluster_id=v.cluster_id AND workspace_id=v.workspace_id AND intent_id=v.intent_id AND intent_revision=v.intent_revision AND packet_key=dep;
   IF NOT FOUND OR ord>=p.packet_order THEN RAISE EXCEPTION 'Durable intent dependencies must precede the same exact version' USING ERRCODE='23514';END IF;
  END LOOP;
 END LOOP;RETURN NULL;
 END;
$$;
CREATE CONSTRAINT TRIGGER entity_change_versions_complete AFTER INSERT ON entity_change_intent_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_intent_graph();
CREATE CONSTRAINT TRIGGER entity_change_packets_complete AFTER INSERT ON entity_change_intent_packets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_intent_graph();

CREATE FUNCTION m11_validate_entity_change_subject() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE w workflows%ROWTYPE;i entity_change_intents%ROWTYPE;v entity_change_intent_versions%ROWTYPE;b entity_change_submissions%ROWTYPE;s workflow_steps%ROWTYPE;
 BEGIN
 IF TG_TABLE_NAME='workflows' THEN SELECT * INTO w FROM workflows WHERE id=NEW.id;ELSE SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;END IF;
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF w.kind<>'native-change' THEN
  IF w.subject_type='entity_change_intents' OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=w.id AND handler='entity.change') THEN
   RAISE EXCEPTION 'Entity change intent requires the exact fixed wrapper' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
 SELECT * INTO b FROM entity_change_submissions WHERE cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id AND workflow_plan_revision=w.plan_revision AND workflow_plan_hash=w.plan_hash;
 SELECT * INTO i FROM entity_change_intents WHERE id=b.intent_id AND cluster_id=w.cluster_id AND workspace_id=w.workspace_id;
 SELECT * INTO v FROM entity_change_intent_versions WHERE intent_id=i.id AND cluster_id=i.cluster_id AND workspace_id=i.workspace_id AND intent_revision=b.intent_revision;
 SELECT * INTO s FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision;
 IF b.id IS NULL OR i.id IS NULL OR v.intent_id IS NULL OR w.subject_type<>'entity_change_intents' OR w.subject_id<>i.id OR w.requester_type<>'console' OR w.requester_user_id<>i.requester_id OR b.actor_id<>i.requester_id
  OR w.idempotency_key<>b.submit_key OR w.definition_id<>v.definition_id OR w.definition_version<>v.definition_version OR w.expires_at<>v.expires_at OR w.execution_mode<>v.execution_mode OR w.approval_required<>(v.execution_mode='approval')
  OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision)<>1
  OR s.cluster_id<>w.cluster_id OR s.workspace_id<>w.workspace_id OR s.plan_hash<>w.plan_hash OR s.kind<>'metadata' OR s.handler IS DISTINCT FROM 'entity.change' OR s.entity_type<>'entity_change_intents' OR s.entity_id IS DISTINCT FROM i.id
  OR s.step_key<>'entity.change' OR s.step_order<>1 OR s.dependencies<>'{}'::uuid[] OR s.native_requests<>'[]'::jsonb OR s.operation_id IS NOT NULL OR s.permission_action<>'write' OR s.metadata_revision IS DISTINCT FROM v.intent_revision
  OR s.parent_id IS NOT NULL OR s.credential_kind IS NOT NULL OR s.before_fingerprint IS NOT NULL
 THEN RAISE EXCEPTION 'Entity change wrapper must retain its exact immutable intent source without native authority' USING ERRCODE='23514';END IF;RETURN NULL;
 END;
$$;
CREATE CONSTRAINT TRIGGER entity_change_submissions_complete AFTER INSERT ON entity_change_submissions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_entity_change_subject();
CREATE CONSTRAINT TRIGGER workflows_entity_change_complete AFTER INSERT OR UPDATE ON workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_entity_change_subject();
CREATE CONSTRAINT TRIGGER workflow_steps_entity_change_complete AFTER INSERT OR UPDATE ON workflow_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_entity_change_subject();

CREATE FUNCTION m11_validate_execution_source() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE v entity_change_intent_versions%ROWTYPE;e workflow_executions%ROWTYPE;session auth_sessions%ROWTYPE;u users%ROWTYPE;
 BEGIN
 SELECT * INTO v FROM entity_change_intent_versions WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND intent_id=NEW.intent_id AND intent_revision=NEW.intent_revision;
 SELECT * INTO e FROM workflow_executions WHERE id=NEW.workflow_execution_id;
 SELECT * INTO session FROM auth_sessions WHERE id=NEW.session_id;
 SELECT * INTO u FROM users WHERE id=NEW.execution_actor_id;
 IF v.intent_id IS NULL OR e.id IS NULL OR session.id IS NULL OR u.id IS NULL OR e.execution_actor_id<>NEW.execution_actor_id OR NEW.execution_actor_id<>v.requester_id
  OR session.user_id<>NEW.execution_actor_id OR session.revoked_at IS NOT NULL OR session.expires_at<=clock_timestamp() OR NEW.expires_at<=clock_timestamp() OR NEW.issued_at>clock_timestamp()
  OR session.credential_epoch<>NEW.credential_epoch OR u.credential_epoch<>NEW.credential_epoch OR v.credential_epoch<>NEW.credential_epoch
  OR u.status<>'active' OR u.deleted_at IS NOT NULL OR u.force_password_change OR e.state<>'executing' OR NEW.expires_at>v.expires_at OR NEW.expires_at>e.expires_at OR NEW.expires_at>session.expires_at
 THEN RAISE EXCEPTION 'Short entity change source requires the real current requester execution and session' USING ERRCODE='23514';END IF;RETURN NEW;
 END;
$$;
CREATE TRIGGER entity_change_execution_sources_current BEFORE INSERT ON entity_change_execution_sources FOR EACH ROW EXECUTE FUNCTION m11_validate_execution_source();
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['entity_change_intents','entity_change_intent_versions','entity_change_intent_packets','entity_change_submissions','entity_change_execution_sources'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
END;$$;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_intents,entity_change_intent_versions,entity_change_intent_packets,entity_change_submissions,entity_change_execution_sources FROM PUBLIC;
