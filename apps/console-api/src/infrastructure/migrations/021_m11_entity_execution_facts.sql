-- Entity-scoped recovery evidence. Rows are facts, never native authority.
-- Root's genuine source/capture/packet verifiers remain mandatory in runtime.
ALTER TABLE entity_change_execution_sources ADD CONSTRAINT entity_change_sources_full_tuple UNIQUE(
 cluster_id,workspace_id,id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,
 workflow_id,workflow_plan_revision,workflow_plan_hash,workflow_execution_id,execution_actor_id,credential_epoch);
ALTER TABLE entity_change_intent_packets ADD CONSTRAINT entity_change_packets_full_tuple UNIQUE(
 cluster_id,workspace_id,intent_id,intent_revision,packet_key,packet_order,material_hmac,change_digest,packet_manifest_hmac,
 method,path_hmac,native_type,native_id,permission_action,mutation_action,body_hmac,before_hmac);

CREATE TABLE entity_change_baselines (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,source_id uuid NOT NULL UNIQUE,
 intent_id uuid NOT NULL,intent_revision integer NOT NULL,material_hmac text NOT NULL,change_digest text NOT NULL,packet_manifest_hmac text NOT NULL,
 workflow_id uuid NOT NULL,workflow_plan_revision integer NOT NULL,workflow_plan_hash text NOT NULL,workflow_execution_id uuid NOT NULL UNIQUE,
 execution_actor_id uuid NOT NULL,credential_epoch bigint NOT NULL,
 readiness text NOT NULL DEFAULT 'ready' CHECK(readiness='ready'),
 baseline_hmac text NOT NULL CHECK(m8_hex64(baseline_hmac)),capture_hmac text NOT NULL CHECK(m8_hex64(capture_hmac)),
 object_manifest_hmac text NOT NULL CHECK(m8_hex64(object_manifest_hmac)),object_manifest jsonb NOT NULL CHECK(jsonb_typeof(object_manifest)='array' AND octet_length(object_manifest::text)<=8388608),
 object_count integer NOT NULL CHECK(object_count BETWEEN 1 AND 10000),graph_count integer NOT NULL CHECK(graph_count BETWEEN 0 AND 1000),
 material_ciphertext text NOT NULL CHECK(m6_encrypted(material_ciphertext,50331648)),
 observed_from timestamptz NOT NULL,observed_until timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,id,object_manifest_hmac),
 UNIQUE(cluster_id,workspace_id,id,source_id,workflow_execution_id,baseline_hmac,object_manifest_hmac),
 FOREIGN KEY(cluster_id,workspace_id,source_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,
  workflow_id,workflow_plan_revision,workflow_plan_hash,workflow_execution_id,execution_actor_id,credential_epoch)
 REFERENCES entity_change_execution_sources(cluster_id,workspace_id,id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,
  workflow_id,workflow_plan_revision,workflow_plan_hash,workflow_execution_id,execution_actor_id,credential_epoch) ON DELETE RESTRICT,
 CHECK(observed_until>=observed_from AND observed_until<=created_at AND observed_until-observed_from<=interval '5 minutes')
);
CREATE TABLE entity_change_baseline_objects (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,baseline_id uuid NOT NULL,object_manifest_hmac text NOT NULL,
 object_key text NOT NULL CHECK(length(object_key) BETWEEN 1 AND 160),object_order integer NOT NULL CHECK(object_order BETWEEN 1 AND 10000),
 native_type text NOT NULL CHECK(m7_native_type(native_type)),native_id uuid NOT NULL,parent_id uuid,
 credential_kind text CHECK(credential_kind IS NULL OR credential_kind IN('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')),
 affected boolean NOT NULL,present boolean NOT NULL,
 dependencies text[] NOT NULL CHECK(cardinality(dependencies)<=10000 AND coalesce(array_ndims(dependencies),1)=1 AND array_position(dependencies,NULL) IS NULL),
 before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),restore_hmac text CHECK(restore_hmac IS NULL OR m8_hex64(restore_hmac)),
 schema_hmac text NOT NULL CHECK(m8_hex64(schema_hmac)),provenance_hmac text NOT NULL CHECK(m8_hex64(provenance_hmac)),
 recovery text NOT NULL CHECK(recovery IN('complete','absent','reference')),
 PRIMARY KEY(baseline_id,object_key),UNIQUE(baseline_id,object_order),
 FOREIGN KEY(cluster_id,workspace_id,baseline_id,object_manifest_hmac)
 REFERENCES entity_change_baselines(cluster_id,workspace_id,id,object_manifest_hmac) ON DELETE RESTRICT,
 CHECK((native_type IN('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls') AND parent_id IS NOT NULL AND credential_kind IS NOT NULL AND credential_kind=native_type)
  OR(native_type='targets' AND parent_id IS NOT NULL AND credential_kind IS NULL)
  OR(native_type IN('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis') AND parent_id IS NULL AND credential_kind IS NULL)),
 CHECK((affected AND present AND recovery='complete' AND restore_hmac IS NOT NULL)
  OR(affected AND NOT present AND recovery='absent' AND restore_hmac IS NULL)
  OR(NOT affected AND present AND recovery='reference' AND restore_hmac IS NULL))
);
CREATE TABLE entity_change_baseline_pins (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,baseline_id uuid NOT NULL,source_id uuid NOT NULL,workflow_execution_id uuid NOT NULL,
 baseline_hmac text NOT NULL,object_manifest_hmac text NOT NULL,pin_version integer NOT NULL CHECK(pin_version>0),
 previous_pin_id uuid REFERENCES entity_change_baseline_pins(id) ON DELETE RESTRICT,protected_until timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(baseline_id,pin_version),
 UNIQUE(cluster_id,workspace_id,id,baseline_id,source_id,workflow_execution_id),
 FOREIGN KEY(cluster_id,workspace_id,baseline_id,source_id,workflow_execution_id,baseline_hmac,object_manifest_hmac)
 REFERENCES entity_change_baselines(cluster_id,workspace_id,id,source_id,workflow_execution_id,baseline_hmac,object_manifest_hmac) ON DELETE RESTRICT,
 CHECK((pin_version=1 AND previous_pin_id IS NULL) OR(pin_version>1 AND previous_pin_id IS NOT NULL))
);
CREATE TABLE entity_change_packet_attempts (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,source_id uuid NOT NULL,baseline_id uuid NOT NULL,pin_id uuid NOT NULL,workflow_execution_id uuid NOT NULL,
 intent_id uuid NOT NULL,intent_revision integer NOT NULL,material_hmac text NOT NULL,change_digest text NOT NULL,packet_manifest_hmac text NOT NULL,
 packet_key text NOT NULL,packet_order integer NOT NULL,method text NOT NULL,path_hmac text NOT NULL,
 native_type text NOT NULL,native_id uuid NOT NULL,parent_id uuid,credential_kind text,original_native_id uuid,
 permission_action text NOT NULL,mutation_action text NOT NULL,body_hmac text NOT NULL,before_hmac text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(source_id,packet_key),UNIQUE(workflow_execution_id,packet_key),
 UNIQUE(cluster_id,workspace_id,id,source_id,baseline_id,pin_id,workflow_execution_id),
 FOREIGN KEY(cluster_id,workspace_id,pin_id,baseline_id,source_id,workflow_execution_id)
 REFERENCES entity_change_baseline_pins(cluster_id,workspace_id,id,baseline_id,source_id,workflow_execution_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,intent_id,intent_revision,packet_key,packet_order,material_hmac,change_digest,packet_manifest_hmac,
  method,path_hmac,native_type,native_id,permission_action,mutation_action,body_hmac,before_hmac)
 REFERENCES entity_change_intent_packets(cluster_id,workspace_id,intent_id,intent_revision,packet_key,packet_order,material_hmac,change_digest,packet_manifest_hmac,
  method,path_hmac,native_type,native_id,permission_action,mutation_action,body_hmac,before_hmac) ON DELETE RESTRICT
);
ALTER TABLE entity_change_packet_attempts ADD CONSTRAINT entity_change_attempt_mutation_tuple UNIQUE(cluster_id,workspace_id,id,source_id,baseline_id,packet_key);
-- V3 has its own namespace. V1 portal reciprocal FKs/unique step and V2
-- configuration bindings remain untouched, including their NULL semantics.
ALTER TABLE mutation_operations ADD COLUMN entity_change_source_id uuid;
ALTER TABLE mutation_operations ADD COLUMN entity_change_baseline_id uuid;
ALTER TABLE mutation_operations ADD COLUMN entity_change_attempt_id uuid;
ALTER TABLE mutation_operations ADD COLUMN entity_change_packet_key text;
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_entity_change_binding_complete CHECK(
 num_nonnulls(entity_change_source_id,entity_change_baseline_id,entity_change_attempt_id,entity_change_packet_key)=0
 OR(num_nonnulls(entity_change_source_id,entity_change_baseline_id,entity_change_attempt_id,entity_change_packet_key)=4
  AND workspace_id IS NOT NULL AND workflow_id IS NOT NULL
  AND num_nonnulls(workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id)=0
  AND num_nonnulls(configuration_job_id,configuration_execution_id,configuration_step_id,configuration_plan_revision,configuration_plan_hash)=0));
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_entity_change_attempt_unique UNIQUE(entity_change_attempt_id);
ALTER TABLE mutation_operations ADD CONSTRAINT mutation_entity_change_attempt_fk
 FOREIGN KEY(cluster_id,workspace_id,entity_change_attempt_id,entity_change_source_id,entity_change_baseline_id,entity_change_packet_key)
 REFERENCES entity_change_packet_attempts(cluster_id,workspace_id,id,source_id,baseline_id,packet_key) ON DELETE RESTRICT;
CREATE TABLE entity_change_packet_events (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,attempt_id uuid NOT NULL,source_id uuid NOT NULL,baseline_id uuid NOT NULL,pin_id uuid NOT NULL,workflow_execution_id uuid NOT NULL,
 event_kind text NOT NULL CHECK(event_kind IN('send-intent','outcome')),
 outcome text CHECK(outcome IS NULL OR outcome IN('succeeded','native-rejected','sent-unknown','rejected-before-send','failed-known-not-sent')),
 native_status integer CHECK(native_status IS NULL OR native_status BETWEEN 100 AND 599),error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'),
 fact_hmac text NOT NULL CHECK(m8_hex64(fact_hmac)),fact_ciphertext text NOT NULL CHECK(m6_encrypted(fact_ciphertext,6291456)),
 observed_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(attempt_id,event_kind),
 FOREIGN KEY(cluster_id,workspace_id,attempt_id,source_id,baseline_id,pin_id,workflow_execution_id)
 REFERENCES entity_change_packet_attempts(cluster_id,workspace_id,id,source_id,baseline_id,pin_id,workflow_execution_id) ON DELETE RESTRICT,
 CHECK((event_kind='send-intent' AND outcome IS NULL AND native_status IS NULL AND error_code IS NULL)
  OR(event_kind='outcome' AND outcome IS NOT NULL AND(
   (outcome='succeeded' AND native_status IS NOT NULL AND native_status BETWEEN 200 AND 299 AND error_code IS NULL)
   OR(outcome='native-rejected' AND native_status IS NOT NULL AND native_status BETWEEN 400 AND 499)
   OR(outcome='sent-unknown')
   OR(outcome IN('rejected-before-send','failed-known-not-sent') AND native_status IS NULL)))),
 CHECK(observed_at<=created_at)
);
CREATE TABLE entity_change_recovery_links (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,baseline_id uuid NOT NULL,pin_id uuid NOT NULL,source_id uuid NOT NULL,workflow_execution_id uuid NOT NULL,
 new_intent_id uuid NOT NULL,new_intent_revision integer NOT NULL,new_material_hmac text NOT NULL,new_change_digest text NOT NULL,new_packet_manifest_hmac text NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(actor_id,idempotency_key),UNIQUE(new_intent_id,new_intent_revision),
 FOREIGN KEY(cluster_id,workspace_id,pin_id,baseline_id,source_id,workflow_execution_id)
 REFERENCES entity_change_baseline_pins(cluster_id,workspace_id,id,baseline_id,source_id,workflow_execution_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,new_intent_id,new_intent_revision,new_material_hmac,new_change_digest,new_packet_manifest_hmac)
 REFERENCES entity_change_intent_versions(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac) ON DELETE RESTRICT
);

CREATE FUNCTION m11_validate_baseline_graph() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE b entity_change_baselines%ROWTYPE;o entity_change_baseline_objects%ROWTYPE;s entity_change_execution_sources%ROWTYPE;n integer;item jsonb;dep text;ord integer;
 BEGIN
 IF TG_TABLE_NAME='entity_change_baselines' THEN SELECT * INTO b FROM entity_change_baselines WHERE id=NEW.id;
 ELSE SELECT * INTO b FROM entity_change_baselines WHERE id=NEW.baseline_id;END IF;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT * INTO s FROM entity_change_execution_sources WHERE id=b.source_id;
 IF b.observed_from<s.issued_at OR b.observed_until>s.expires_at THEN RAISE EXCEPTION 'Baseline capture must occur within its exact short source' USING ERRCODE='23514';END IF;
 SELECT count(*)::integer INTO n FROM entity_change_baseline_objects WHERE baseline_id=b.id;
 IF n<>b.object_count OR jsonb_array_length(b.object_manifest)<>n THEN RAISE EXCEPTION 'Baseline graph evidence must be complete' USING ERRCODE='23514';END IF;
 FOR o IN SELECT * FROM entity_change_baseline_objects WHERE baseline_id=b.id ORDER BY object_order LOOP
  item=b.object_manifest->(o.object_order-1);
  IF o.object_order>n OR item IS NULL OR cardinality(o.dependencies)<>(SELECT count(DISTINCT value)::integer FROM unnest(o.dependencies) value)
   OR item->>'key' IS DISTINCT FROM o.object_key OR item->>'nativeType' IS DISTINCT FROM o.native_type OR item->>'nativeId' IS DISTINCT FROM o.native_id::text
   OR item->>'parentId' IS DISTINCT FROM o.parent_id::text OR item->>'credentialKind' IS DISTINCT FROM o.credential_kind
   OR item->'affected' IS DISTINCT FROM to_jsonb(o.affected) OR item->'present' IS DISTINCT FROM to_jsonb(o.present) OR item->'dependencies' IS DISTINCT FROM to_jsonb(o.dependencies)
   OR item->>'beforeHmac' IS DISTINCT FROM o.before_hmac OR item->>'restoreHmac' IS DISTINCT FROM o.restore_hmac OR item->>'schemaHmac' IS DISTINCT FROM o.schema_hmac
   OR item->>'provenanceHmac' IS DISTINCT FROM o.provenance_hmac OR item->>'recovery' IS DISTINCT FROM o.recovery
  THEN RAISE EXCEPTION 'Baseline normalized objects must equal the complete immutable manifest' USING ERRCODE='23514';END IF;
  FOREACH dep IN ARRAY o.dependencies LOOP
   SELECT object_order INTO ord FROM entity_change_baseline_objects WHERE baseline_id=b.id AND object_key=dep;
   IF NOT FOUND OR ord>=o.object_order THEN RAISE EXCEPTION 'Baseline dependencies must precede the same complete graph' USING ERRCODE='23514';END IF;
  END LOOP;
 END LOOP;
 IF EXISTS(SELECT 1 FROM entity_change_intent_packets p WHERE p.cluster_id=b.cluster_id AND p.workspace_id=b.workspace_id AND p.intent_id=b.intent_id AND p.intent_revision=b.intent_revision
  AND(p.mutation_action IN('mark_healthy','mark_unhealthy') OR NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects o WHERE o.baseline_id=b.id AND o.affected
   AND o.native_type=p.native_type AND o.native_id=p.native_id AND o.parent_id IS NOT DISTINCT FROM p.parent_id AND o.credential_kind IS NOT DISTINCT FROM p.credential_kind
   AND o.present=(p.method<>'POST'))
   OR(p.original_native_id IS NOT NULL AND p.mutation_action<>'restore' AND NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects old WHERE old.baseline_id=b.id AND old.affected AND old.present
    AND old.native_type=p.native_type AND old.native_id=p.original_native_id AND old.parent_id IS NOT DISTINCT FROM p.parent_id))))
 THEN RAISE EXCEPTION 'Every executable packet requires its complete real before or absence baseline; health remains blocked' USING ERRCODE='23514';END IF;
 RETURN NULL;END;
$$;
CREATE CONSTRAINT TRIGGER entity_change_baselines_complete AFTER INSERT ON entity_change_baselines DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_baseline_graph();
CREATE CONSTRAINT TRIGGER entity_change_baseline_objects_complete AFTER INSERT ON entity_change_baseline_objects DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_baseline_graph();

CREATE FUNCTION m11_validate_baseline_pin() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE b entity_change_baselines%ROWTYPE;p entity_change_baseline_pins%ROWTYPE;
 BEGIN
 SELECT * INTO b FROM entity_change_baselines WHERE id=NEW.baseline_id;
 IF b.id IS NULL OR NEW.protected_until<b.created_at+interval '30 days' THEN RAISE EXCEPTION 'Recovery material requires at least thirty days of protection' USING ERRCODE='23514';END IF;
 IF NEW.pin_version>1 THEN
  SELECT * INTO p FROM entity_change_baseline_pins WHERE id=NEW.previous_pin_id;
  IF p.id IS NULL OR p.baseline_id IS DISTINCT FROM NEW.baseline_id OR p.pin_version+1<>NEW.pin_version OR NEW.protected_until<=p.protected_until
  THEN RAISE EXCEPTION 'A recovery pin can only append a longer protection interval' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;END;
$$;
CREATE TRIGGER entity_change_baseline_pins_guard BEFORE INSERT ON entity_change_baseline_pins FOR EACH ROW EXECUTE FUNCTION m11_validate_baseline_pin();

CREATE FUNCTION m11_validate_packet_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE b entity_change_baselines%ROWTYPE;p entity_change_intent_packets%ROWTYPE;s entity_change_execution_sources%ROWTYPE;e workflow_executions%ROWTYPE;
 BEGIN
 SELECT * INTO b FROM entity_change_baselines WHERE id=NEW.baseline_id;SELECT * INTO s FROM entity_change_execution_sources WHERE id=NEW.source_id;SELECT * INTO e FROM workflow_executions WHERE id=NEW.workflow_execution_id;
 SELECT * INTO p FROM entity_change_intent_packets WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND intent_id=NEW.intent_id AND intent_revision=NEW.intent_revision AND packet_key=NEW.packet_key;
 IF b.id IS NULL OR s.id IS NULL OR e.id IS NULL OR p.packet_key IS NULL OR b.source_id IS DISTINCT FROM NEW.source_id OR b.workflow_execution_id IS DISTINCT FROM NEW.workflow_execution_id
  OR ROW(b.intent_id,b.intent_revision,b.material_hmac,b.change_digest,b.packet_manifest_hmac) IS DISTINCT FROM ROW(NEW.intent_id,NEW.intent_revision,NEW.material_hmac,NEW.change_digest,NEW.packet_manifest_hmac)
  OR ROW(p.parent_id,p.credential_kind,p.original_native_id) IS DISTINCT FROM ROW(NEW.parent_id,NEW.credential_kind,NEW.original_native_id)
  OR s.expires_at<=clock_timestamp() OR e.state<>'executing'
 THEN RAISE EXCEPTION 'A packet attempt requires its exact ready baseline, current source and native tuple' USING ERRCODE='23514';END IF;RETURN NEW;END;
$$;
CREATE TRIGGER entity_change_packet_attempts_guard BEFORE INSERT ON entity_change_packet_attempts FOR EACH ROW EXECUTE FUNCTION m11_validate_packet_attempt();

CREATE FUNCTION m11_validate_entity_mutation_binding() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE a entity_change_packet_attempts%ROWTYPE;s entity_change_execution_sources%ROWTYPE;e workflow_executions%ROWTYPE;typ text;
 BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.entity_change_attempt_id IS NOT NULL THEN RAISE EXCEPTION 'Entity mutation evidence cannot be deleted' USING ERRCODE='23514';END IF;RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' AND ROW(OLD.entity_change_source_id,OLD.entity_change_baseline_id,OLD.entity_change_attempt_id,OLD.entity_change_packet_key)
  IS DISTINCT FROM ROW(NEW.entity_change_source_id,NEW.entity_change_baseline_id,NEW.entity_change_attempt_id,NEW.entity_change_packet_key)
 THEN RAISE EXCEPTION 'Entity mutation source identity is immutable' USING ERRCODE='23514';END IF;
 IF NEW.entity_change_attempt_id IS NULL THEN RETURN NEW;END IF;
 IF TG_OP='UPDATE' AND ROW(OLD.id,OLD.cluster_id,OLD.workspace_id,OLD.actor_id,OLD.workflow_id,OLD.entity_type,OLD.action,OLD.parent_id,OLD.credential_kind,
    OLD.idempotency_key,OLD.request_hash,OLD.before_secret,OLD.payload_secret,OLD.transport_scope,OLD.created_at)
  IS DISTINCT FROM ROW(NEW.id,NEW.cluster_id,NEW.workspace_id,NEW.actor_id,NEW.workflow_id,NEW.entity_type,NEW.action,NEW.parent_id,NEW.credential_kind,
    NEW.idempotency_key,NEW.request_hash,NEW.before_secret,NEW.payload_secret,NEW.transport_scope,NEW.created_at)
 THEN RAISE EXCEPTION 'Entity mutation actor and native identity are immutable' USING ERRCODE='23514';END IF;
 SELECT * INTO a FROM entity_change_packet_attempts WHERE id=NEW.entity_change_attempt_id;SELECT * INTO s FROM entity_change_execution_sources WHERE id=NEW.entity_change_source_id;
 SELECT * INTO e FROM workflow_executions WHERE id=s.workflow_execution_id;
 typ=CASE WHEN a.credential_kind IS NOT NULL THEN 'credentials' ELSE a.native_type END;
 IF a.id IS NULL OR s.id IS NULL OR e.id IS NULL OR NEW.cluster_id IS DISTINCT FROM s.cluster_id OR NEW.workspace_id IS DISTINCT FROM s.workspace_id
  OR NEW.workflow_id IS DISTINCT FROM s.workflow_id OR NEW.actor_id IS DISTINCT FROM s.execution_actor_id OR NEW.entity_type IS DISTINCT FROM typ OR NEW.action IS DISTINCT FROM a.mutation_action
  OR NEW.parent_id IS DISTINCT FROM a.parent_id::text OR NEW.credential_kind IS DISTINCT FROM a.credential_kind
  OR(NEW.entity_id IS DISTINCT FROM a.native_id::text AND NOT(a.native_type='targets' AND a.original_native_id IS NOT NULL AND NEW.entity_id IS NOT DISTINCT FROM a.original_native_id::text))
  OR(TG_OP='INSERT' AND(s.expires_at<=clock_timestamp() OR e.state<>'executing'))
 THEN RAISE EXCEPTION 'Entity mutation must retain its exact source, actor and packet tuple' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.entity_id IS DISTINCT FROM OLD.entity_id AND NOT(OLD.state='running' AND OLD.remote_started AND NOT OLD.remote_completed
   AND NEW.remote_completed AND NEW.result_secret IS NOT NULL AND a.native_type='targets' AND a.original_native_id IS NOT NULL
   AND OLD.entity_id IS NOT DISTINCT FROM a.original_native_id::text AND NEW.entity_id IS NOT DISTINCT FROM a.native_id::text)
  THEN RAISE EXCEPTION 'Entity mutation result identity can only advance to its exact allocated Target once' USING ERRCODE='23514';END IF;
  IF OLD.remote_started AND NOT NEW.remote_started OR OLD.remote_completed AND(NOT NEW.remote_completed OR NEW.result_secret IS DISTINCT FROM OLD.result_secret)
  THEN RAISE EXCEPTION 'Observed entity native result cannot be erased or replaced' USING ERRCODE='23514';END IF;
 END IF;
 -- Parent/kind/logical Target identity is the immutable packet FK tuple.
 -- The genuine runtime verifier additionally checks the encrypted request's
 -- canonical path/body against it before native send; a row is not authority.
 RETURN NEW;END;
$$;
CREATE TRIGGER mutation_operations_entity_change_binding BEFORE INSERT OR UPDATE OR DELETE ON mutation_operations FOR EACH ROW EXECUTE FUNCTION m11_validate_entity_mutation_binding();

CREATE FUNCTION m11_validate_packet_event() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE a entity_change_packet_attempts%ROWTYPE;s entity_change_execution_sources%ROWTYPE;e workflow_executions%ROWTYPE;sent entity_change_packet_events%ROWTYPE;
 BEGIN
 SELECT * INTO a FROM entity_change_packet_attempts WHERE id=NEW.attempt_id;SELECT * INTO s FROM entity_change_execution_sources WHERE id=NEW.source_id;SELECT * INTO e FROM workflow_executions WHERE id=NEW.workflow_execution_id;
 SELECT * INTO sent FROM entity_change_packet_events WHERE attempt_id=NEW.attempt_id AND event_kind='send-intent';
 IF a.id IS NULL OR NEW.observed_at<a.created_at THEN RAISE EXCEPTION 'Packet event must retain its real attempt chronology' USING ERRCODE='23514';END IF;
 IF NEW.event_kind='send-intent' THEN
  IF s.id IS NULL OR e.id IS NULL OR s.expires_at<=clock_timestamp() OR e.state<>'executing' OR NEW.observed_at>s.expires_at
   OR EXISTS(SELECT 1 FROM entity_change_packet_events WHERE attempt_id=a.id AND event_kind='outcome')
   OR EXISTS(SELECT 1 FROM entity_change_intent_packets p WHERE p.cluster_id=a.cluster_id AND p.workspace_id=a.workspace_id AND p.intent_id=a.intent_id AND p.intent_revision=a.intent_revision AND p.packet_order<a.packet_order
    AND NOT EXISTS(SELECT 1 FROM entity_change_packet_attempts prior JOIN entity_change_packet_events result ON result.attempt_id=prior.id AND result.event_kind='outcome' AND result.outcome='succeeded'
     WHERE prior.source_id=a.source_id AND prior.packet_key=p.packet_key))
  THEN RAISE EXCEPTION 'Sending requires current source and all earlier exact packets acknowledged successful' USING ERRCODE='23514';END IF;
 ELSE
  IF NEW.outcome IN('succeeded','native-rejected','sent-unknown') AND(sent.id IS NULL OR NEW.observed_at<sent.observed_at)
   OR NEW.outcome='rejected-before-send' AND sent.id IS NOT NULL
  THEN RAISE EXCEPTION 'Packet outcome must distinguish never-sent and genuine sent results' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;END;
$$;
CREATE TRIGGER entity_change_packet_events_guard BEFORE INSERT ON entity_change_packet_events FOR EACH ROW EXECUTE FUNCTION m11_validate_packet_event();

CREATE FUNCTION m11_entity_baseline_pin_active(baseline uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM entity_change_baseline_pins p WHERE p.baseline_id=baseline AND p.protected_until>statement_timestamp())
  OR EXISTS(SELECT 1 FROM entity_change_baselines b JOIN workflow_executions e ON e.id=b.workflow_execution_id WHERE b.id=baseline AND e.state NOT IN('succeeded','partial','failed'))
  OR EXISTS(SELECT 1 FROM entity_change_packet_attempts a WHERE a.baseline_id=baseline AND NOT EXISTS(SELECT 1 FROM entity_change_packet_events result WHERE result.attempt_id=a.id AND result.event_kind='outcome'))
  OR EXISTS(SELECT 1 FROM entity_change_packet_events result WHERE result.baseline_id=baseline AND result.outcome='sent-unknown');
$$;
CREATE FUNCTION m11_validate_entity_recovery_link() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE b entity_change_baselines%ROWTYPE;e workflow_executions%ROWTYPE;i entity_change_intents%ROWTYPE;
 BEGIN
 SELECT * INTO b FROM entity_change_baselines WHERE id=NEW.baseline_id;SELECT * INTO e FROM workflow_executions WHERE id=NEW.workflow_execution_id;
 SELECT * INTO i FROM entity_change_intents WHERE id=NEW.new_intent_id AND cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id;
 IF b.id IS NULL OR e.id IS NULL OR i.id IS NULL OR i.requester_id IS DISTINCT FROM NEW.actor_id OR NEW.new_intent_id=b.intent_id OR e.state NOT IN('succeeded','partial','failed')
  OR EXISTS(SELECT 1 FROM entity_change_packet_events WHERE baseline_id=b.id AND outcome='sent-unknown')
  OR EXISTS(SELECT 1 FROM entity_change_packet_attempts a WHERE a.baseline_id=b.id AND NOT EXISTS(SELECT 1 FROM entity_change_packet_events result WHERE result.attempt_id=a.id AND result.event_kind='outcome'))
 THEN RAISE EXCEPTION 'Recovery requires a new current-owner intent and closed original outcomes' USING ERRCODE='23514';END IF;RETURN NEW;END;
$$;
CREATE TRIGGER entity_change_recovery_links_guard BEFORE INSERT ON entity_change_recovery_links FOR EACH ROW EXECUTE FUNCTION m11_validate_entity_recovery_link();
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['entity_change_baselines','entity_change_baseline_objects','entity_change_baseline_pins','entity_change_packet_attempts','entity_change_packet_events','entity_change_recovery_links'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
END;$$;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_baselines,entity_change_baseline_objects,entity_change_baseline_pins,entity_change_packet_attempts,entity_change_packet_events,entity_change_recovery_links FROM PUBLIC;
