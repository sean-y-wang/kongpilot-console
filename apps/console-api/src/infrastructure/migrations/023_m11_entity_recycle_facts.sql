-- Candidate: independent V3 recycle origin and per-packet completion facts.
-- No legacy aggregate mutation is invented. These rows are evidence, not
-- permits; Root's private source/approval/packet/result verifier is mandatory.
CREATE TABLE entity_change_recycle_archives (
 entry_id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 source_id uuid NOT NULL,baseline_id uuid NOT NULL,pin_id uuid NOT NULL,workflow_execution_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,root_key text NOT NULL CHECK(length(root_key) BETWEEN 1 AND 160),
 graph_hmac text NOT NULL CHECK(m8_hex64(graph_hmac)),payload_hmac text NOT NULL CHECK(m8_hex64(payload_hmac)),
 node_manifest_hmac text NOT NULL CHECK(m8_hex64(node_manifest_hmac)),
 node_manifest jsonb NOT NULL CHECK(jsonb_typeof(node_manifest)='array' AND octet_length(node_manifest::text)<=2097152),
 node_count integer NOT NULL CHECK(node_count BETWEEN 1 AND 1000),packet_count integer NOT NULL CHECK(packet_count BETWEEN 1 AND 1000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(cluster_id,workspace_id,entry_id),UNIQUE(source_id,graph_hmac),
 FOREIGN KEY(cluster_id,workspace_id,entry_id) REFERENCES recycle_entries(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,pin_id,baseline_id,source_id,workflow_execution_id)
 REFERENCES entity_change_baseline_pins(cluster_id,workspace_id,id,baseline_id,source_id,workflow_execution_id) ON DELETE RESTRICT,
 CHECK(graph_hmac=payload_hmac AND packet_count<=node_count)
);
CREATE TABLE entity_change_recycle_nodes (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,entry_id uuid NOT NULL,node_key text NOT NULL CHECK(length(node_key) BETWEEN 1 AND 160),
 node_order integer NOT NULL CHECK(node_order BETWEEN 1 AND 1000),native_type text NOT NULL CHECK(m7_native_type(native_type)),native_id uuid NOT NULL,
 parent_id uuid,credential_kind text CHECK(credential_kind IS NULL OR credential_kind IN('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')),
 affected boolean NOT NULL,dependencies text[] NOT NULL CHECK(cardinality(dependencies)<=1000 AND coalesce(array_ndims(dependencies),1)=1 AND array_position(dependencies,NULL) IS NULL),
 path_hmac text NOT NULL CHECK(m8_hex64(path_hmac)),data_hmac text NOT NULL CHECK(m8_hex64(data_hmac)),
 restore_hmac text CHECK(restore_hmac IS NULL OR m8_hex64(restore_hmac)),
 PRIMARY KEY(entry_id,node_key),UNIQUE(entry_id,node_order),UNIQUE(cluster_id,workspace_id,entry_id,node_key),
 FOREIGN KEY(cluster_id,workspace_id,entry_id) REFERENCES entity_change_recycle_archives(cluster_id,workspace_id,entry_id) ON DELETE RESTRICT,
 FOREIGN KEY(entry_id,node_key) REFERENCES recycle_nodes(entry_id,node_key) ON DELETE RESTRICT,
 CHECK((native_type IN('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls') AND parent_id IS NOT NULL AND credential_kind IS NOT NULL AND credential_kind=native_type)
  OR(native_type='targets' AND parent_id IS NOT NULL AND credential_kind IS NULL)
  OR(native_type IN('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis') AND parent_id IS NULL AND credential_kind IS NULL)),
 CHECK((affected AND restore_hmac IS NOT NULL) OR(NOT affected AND restore_hmac IS NULL))
);
CREATE TABLE entity_change_recycle_packets (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,source_id uuid NOT NULL,baseline_id uuid NOT NULL,pin_id uuid NOT NULL,workflow_execution_id uuid NOT NULL,
 entry_id uuid NOT NULL,node_key text NOT NULL,direction text NOT NULL CHECK(direction IN('delete','restore')),
 intent_id uuid NOT NULL,intent_revision integer NOT NULL,material_hmac text NOT NULL,change_digest text NOT NULL,packet_manifest_hmac text NOT NULL,
 packet_key text NOT NULL,packet_order integer NOT NULL,method text NOT NULL,path_hmac text NOT NULL,
 native_type text NOT NULL,native_id uuid NOT NULL,parent_id uuid,credential_kind text,original_native_id uuid,
 permission_action text NOT NULL,mutation_action text NOT NULL,body_hmac text NOT NULL,before_hmac text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(source_id,packet_key),UNIQUE(source_id,entry_id,node_key),
 UNIQUE(cluster_id,workspace_id,source_id,baseline_id,pin_id,workflow_execution_id,packet_key,entry_id,node_key),
 FOREIGN KEY(cluster_id,workspace_id,entry_id,node_key) REFERENCES entity_change_recycle_nodes(cluster_id,workspace_id,entry_id,node_key) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,pin_id,baseline_id,source_id,workflow_execution_id)
 REFERENCES entity_change_baseline_pins(cluster_id,workspace_id,id,baseline_id,source_id,workflow_execution_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,intent_id,intent_revision,packet_key,packet_order,material_hmac,change_digest,packet_manifest_hmac,
  method,path_hmac,native_type,native_id,permission_action,mutation_action,body_hmac,before_hmac)
 REFERENCES entity_change_intent_packets(cluster_id,workspace_id,intent_id,intent_revision,packet_key,packet_order,material_hmac,change_digest,packet_manifest_hmac,
  method,path_hmac,native_type,native_id,permission_action,mutation_action,body_hmac,before_hmac) ON DELETE RESTRICT,
 CHECK((direction='delete' AND method='DELETE' AND mutation_action='delete' AND permission_action='delete')
  OR(direction='restore' AND method='POST' AND mutation_action='restore' AND permission_action='write'))
);
CREATE TABLE entity_change_recycle_receipts (
 attempt_id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,source_id uuid NOT NULL,baseline_id uuid NOT NULL,pin_id uuid NOT NULL,workflow_execution_id uuid NOT NULL,
 entry_id uuid NOT NULL,node_key text NOT NULL,packet_key text NOT NULL,operation_id uuid NOT NULL UNIQUE,
 operation_key text NOT NULL CHECK(operation_key ~ '^[a-zA-Z0-9_.:-]{1,128}$'),native_id uuid NOT NULL,
 direction text NOT NULL CHECK(direction IN('delete','restore')),result_hmac text NOT NULL CHECK(m8_hex64(result_hmac)),
 verification_hmac text CHECK(verification_hmac IS NULL OR m8_hex64(verification_hmac)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(source_id,packet_key),
 FOREIGN KEY(cluster_id,workspace_id,attempt_id,source_id,baseline_id,pin_id,workflow_execution_id)
 REFERENCES entity_change_packet_attempts(cluster_id,workspace_id,id,source_id,baseline_id,pin_id,workflow_execution_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,source_id,baseline_id,pin_id,workflow_execution_id,packet_key,entry_id,node_key)
 REFERENCES entity_change_recycle_packets(cluster_id,workspace_id,source_id,baseline_id,pin_id,workflow_execution_id,packet_key,entry_id,node_key) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,operation_id) REFERENCES mutation_operations(cluster_id,id) ON DELETE RESTRICT,
 CHECK((direction='delete' AND verification_hmac IS NOT NULL) OR direction='restore')
);
CREATE INDEX entity_change_recycle_receipts_nodes ON entity_change_recycle_receipts(entry_id,node_key,direction);

CREATE FUNCTION m11_validate_recycle_archive() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE e recycle_entries%ROWTYPE;s entity_change_execution_sources%ROWTYPE;x workflow_executions%ROWTYPE;
 BEGIN
 SELECT * INTO e FROM recycle_entries WHERE id=NEW.entry_id;SELECT * INTO s FROM entity_change_execution_sources WHERE id=NEW.source_id;
 SELECT * INTO x FROM workflow_executions WHERE id=NEW.workflow_execution_id;
 IF e.id IS NULL OR s.id IS NULL OR x.id IS NULL OR e.state<>'archived' OR e.mutation_id IS NOT NULL OR e.payload_secret IS NULL
  OR e.actor_id IS DISTINCT FROM NEW.actor_id OR s.execution_actor_id IS DISTINCT FROM NEW.actor_id
  OR e.cluster_id IS DISTINCT FROM NEW.cluster_id OR e.workspace_id IS DISTINCT FROM NEW.workspace_id OR e.node_count<>NEW.node_count
  OR s.workflow_execution_id IS DISTINCT FROM NEW.workflow_execution_id OR s.expires_at<=clock_timestamp() OR x.state<>'executing'
 THEN RAISE EXCEPTION 'Recycle archive requires its real current source and an independently stored complete entry' USING ERRCODE='23514';END IF;
 RETURN NEW;END;
$$;
CREATE TRIGGER entity_change_recycle_archives_guard BEFORE INSERT ON entity_change_recycle_archives FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_archive();

CREATE FUNCTION m11_validate_recycle_packet() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE n entity_change_recycle_nodes%ROWTYPE;a entity_change_recycle_archives%ROWTYPE;s entity_change_execution_sources%ROWTYPE;p entity_change_intent_packets%ROWTYPE;x workflow_executions%ROWTYPE;
 BEGIN
 SELECT * INTO n FROM entity_change_recycle_nodes WHERE entry_id=NEW.entry_id AND node_key=NEW.node_key;
 SELECT * INTO a FROM entity_change_recycle_archives WHERE entry_id=NEW.entry_id;SELECT * INTO s FROM entity_change_execution_sources WHERE id=NEW.source_id;
 SELECT * INTO x FROM workflow_executions WHERE id=NEW.workflow_execution_id;
 SELECT * INTO p FROM entity_change_intent_packets WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND intent_id=NEW.intent_id AND intent_revision=NEW.intent_revision AND packet_key=NEW.packet_key;
 IF n.node_key IS NULL OR a.entry_id IS NULL OR s.id IS NULL OR p.packet_key IS NULL OR x.id IS NULL OR NOT n.affected
  OR s.workflow_execution_id IS DISTINCT FROM NEW.workflow_execution_id OR s.expires_at<=clock_timestamp() OR x.state<>'executing'
  OR ROW(s.intent_id,s.intent_revision,s.material_hmac,s.change_digest,s.packet_manifest_hmac) IS DISTINCT FROM ROW(NEW.intent_id,NEW.intent_revision,NEW.material_hmac,NEW.change_digest,NEW.packet_manifest_hmac)
  OR ROW(p.parent_id,p.credential_kind,p.original_native_id) IS DISTINCT FROM ROW(NEW.parent_id,NEW.credential_kind,NEW.original_native_id)
  OR ROW(n.native_type,n.parent_id,n.credential_kind) IS DISTINCT FROM ROW(NEW.native_type,NEW.parent_id,NEW.credential_kind)
  OR coalesce(NEW.original_native_id,NEW.native_id) IS DISTINCT FROM n.native_id
  OR(NEW.original_native_id IS NOT NULL AND NOT(NEW.native_type='targets' AND NEW.direction='restore' AND NEW.original_native_id<>NEW.native_id))
  OR(NEW.direction='delete' AND a.source_id IS DISTINCT FROM NEW.source_id)
  OR(NEW.direction='restore' AND a.source_id=NEW.source_id)
 THEN RAISE EXCEPTION 'Recycle packet must bind the exact affected archived node and actual new source' USING ERRCODE='23514';END IF;
 RETURN NEW;END;
$$;
CREATE TRIGGER entity_change_recycle_packets_guard BEFORE INSERT ON entity_change_recycle_packets FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_packet();

CREATE FUNCTION m11_validate_recycle_manifest() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE a entity_change_recycle_archives%ROWTYPE;n entity_change_recycle_nodes%ROWTYPE;legacy recycle_nodes%ROWTYPE;item jsonb;dep text;ord integer;c integer;
 BEGIN
 SELECT * INTO a FROM entity_change_recycle_archives WHERE entry_id=NEW.entry_id;IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT count(*)::integer INTO c FROM entity_change_recycle_nodes WHERE entry_id=a.entry_id;
 IF c<>a.node_count OR jsonb_array_length(a.node_manifest)<>c
  OR(SELECT count(*) FROM recycle_nodes WHERE entry_id=a.entry_id)<>a.node_count
  OR(SELECT count(*) FROM entity_change_recycle_nodes WHERE entry_id=a.entry_id AND affected)<>a.packet_count
  OR(SELECT count(*) FROM entity_change_recycle_packets WHERE entry_id=a.entry_id AND source_id=a.source_id AND direction='delete')<>a.packet_count
  OR NOT EXISTS(SELECT 1 FROM entity_change_recycle_nodes root_node JOIN recycle_entries e ON e.id=root_node.entry_id WHERE root_node.entry_id=a.entry_id AND root_node.node_key=a.root_key AND root_node.affected
   AND root_node.native_id::text=e.original_id AND root_node.native_type=CASE WHEN e.root_type='credentials' THEN e.credential_kind ELSE e.root_type END)
 THEN RAISE EXCEPTION 'Recycle archive must include its whole immutable node and delete packet set' USING ERRCODE='23514';END IF;
 FOR n IN SELECT * FROM entity_change_recycle_nodes WHERE entry_id=a.entry_id ORDER BY node_order LOOP
  item=a.node_manifest->(n.node_order-1);SELECT * INTO legacy FROM recycle_nodes WHERE entry_id=n.entry_id AND node_key=n.node_key;
  IF item IS NULL OR legacy.node_key IS NULL OR item->>'key' IS DISTINCT FROM n.node_key OR item->'order' IS DISTINCT FROM to_jsonb(n.node_order)
   OR item->>'nativeType' IS DISTINCT FROM n.native_type OR item->>'nativeId' IS DISTINCT FROM n.native_id::text OR item->>'parentId' IS DISTINCT FROM n.parent_id::text
   OR item->>'credentialKind' IS DISTINCT FROM n.credential_kind OR item->'affected' IS DISTINCT FROM to_jsonb(n.affected) OR item->'dependencies' IS DISTINCT FROM to_jsonb(n.dependencies)
   OR item->>'pathHmac' IS DISTINCT FROM n.path_hmac OR item->>'dataHmac' IS DISTINCT FROM n.data_hmac OR item->>'restoreHmac' IS DISTINCT FROM n.restore_hmac
   OR legacy.entity_type IS DISTINCT FROM n.native_type OR legacy.original_id IS DISTINCT FROM n.native_id::text OR legacy.affected IS DISTINCT FROM n.affected
   OR legacy.dependencies IS DISTINCT FROM n.dependencies OR cardinality(n.dependencies)<>(SELECT count(DISTINCT value)::integer FROM unnest(n.dependencies) value)
  THEN RAISE EXCEPTION 'Recycle manifest must equal every exact native and legacy node tuple' USING ERRCODE='23514';END IF;
  FOREACH dep IN ARRAY n.dependencies LOOP
   SELECT node_order INTO ord FROM entity_change_recycle_nodes WHERE entry_id=n.entry_id AND node_key=dep;
   IF NOT FOUND OR ord>=n.node_order THEN RAISE EXCEPTION 'Recycle node dependencies must precede the same complete graph' USING ERRCODE='23514';END IF;
  END LOOP;
 END LOOP;RETURN NULL;END;
$$;
CREATE CONSTRAINT TRIGGER entity_change_recycle_archives_complete AFTER INSERT ON entity_change_recycle_archives DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_manifest();
CREATE CONSTRAINT TRIGGER entity_change_recycle_nodes_complete AFTER INSERT ON entity_change_recycle_nodes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_manifest();
CREATE CONSTRAINT TRIGGER entity_change_recycle_packets_complete AFTER INSERT ON entity_change_recycle_packets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_manifest();

CREATE FUNCTION m11_validate_recycle_packet_set() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE p entity_change_recycle_packets%ROWTYPE;n entity_change_recycle_nodes%ROWTYPE;a entity_change_recycle_archives%ROWTYPE;dep text;ord integer;
 BEGIN
 SELECT * INTO a FROM entity_change_recycle_archives WHERE entry_id=NEW.entry_id;
 -- Gate3 fixed restore supports all-missing graphs. Matching live/adopted
 -- objects need distinct genuine observed-present facts, never fake receipts.
 IF(SELECT count(*) FROM entity_change_recycle_packets WHERE source_id=NEW.source_id AND entry_id=NEW.entry_id AND direction=NEW.direction)<>a.packet_count
 THEN RAISE EXCEPTION 'Recycle execution requires its complete affected packet set before first send' USING ERRCODE='23514';END IF;
 FOR p IN SELECT * FROM entity_change_recycle_packets WHERE source_id=NEW.source_id AND entry_id=NEW.entry_id AND direction=NEW.direction LOOP
  SELECT * INTO n FROM entity_change_recycle_nodes WHERE entry_id=p.entry_id AND node_key=p.node_key;
  FOREACH dep IN ARRAY n.dependencies LOOP
   SELECT parent.packet_order INTO ord FROM entity_change_recycle_packets parent WHERE parent.source_id=p.source_id AND parent.entry_id=p.entry_id AND parent.node_key=dep;
   IF FOUND AND((p.direction='delete' AND ord<=p.packet_order) OR(p.direction='restore' AND ord>=p.packet_order))
   THEN RAISE EXCEPTION 'Delete children must precede parents; restore parents must precede children' USING ERRCODE='23514';END IF;
  END LOOP;
 END LOOP;RETURN NULL;END;
$$;
CREATE CONSTRAINT TRIGGER entity_change_recycle_packet_set_complete AFTER INSERT ON entity_change_recycle_packets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_packet_set();

CREATE FUNCTION m11_validate_recycle_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE p entity_change_recycle_packets%ROWTYPE;a entity_change_packet_attempts%ROWTYPE;m mutation_operations%ROWTYPE;s entity_change_execution_sources%ROWTYPE;o entity_change_packet_events%ROWTYPE;
 BEGIN
 SELECT * INTO p FROM entity_change_recycle_packets WHERE source_id=NEW.source_id AND packet_key=NEW.packet_key;
 SELECT * INTO a FROM entity_change_packet_attempts WHERE id=NEW.attempt_id;SELECT * INTO m FROM mutation_operations WHERE id=NEW.operation_id;
 SELECT * INTO s FROM entity_change_execution_sources WHERE id=NEW.source_id;SELECT * INTO o FROM entity_change_packet_events WHERE attempt_id=NEW.attempt_id AND event_kind='outcome';
 IF p.packet_key IS NULL OR a.id IS NULL OR m.id IS NULL OR s.id IS NULL OR o.id IS NULL OR o.outcome<>'succeeded' OR o.native_status NOT BETWEEN 200 AND 299
  OR NOT EXISTS(SELECT 1 FROM entity_change_packet_events WHERE attempt_id=a.id AND event_kind='send-intent')
  OR m.state<>'succeeded' OR NOT m.remote_completed OR NOT m.remote_started OR m.result_secret IS NULL OR m.idempotency_key IS DISTINCT FROM NEW.operation_key
  OR ROW(m.entity_change_source_id,m.entity_change_baseline_id,m.entity_change_attempt_id,m.entity_change_packet_key) IS DISTINCT FROM ROW(NEW.source_id,NEW.baseline_id,NEW.attempt_id,NEW.packet_key)
  OR ROW(a.packet_key,a.native_id,a.parent_id,a.credential_kind,a.original_native_id) IS DISTINCT FROM ROW(p.packet_key,p.native_id,p.parent_id,p.credential_kind,p.original_native_id)
  OR m.cluster_id IS DISTINCT FROM NEW.cluster_id OR m.workspace_id IS DISTINCT FROM NEW.workspace_id OR m.actor_id IS DISTINCT FROM s.execution_actor_id
  OR m.action IS DISTINCT FROM p.mutation_action OR m.entity_type IS DISTINCT FROM (CASE WHEN p.credential_kind IS NOT NULL THEN 'credentials' ELSE p.native_type END)
  OR m.entity_id IS DISTINCT FROM p.native_id::text OR m.parent_id IS DISTINCT FROM p.parent_id::text OR m.credential_kind IS DISTINCT FROM p.credential_kind
  OR NEW.native_id IS DISTINCT FROM p.native_id OR NEW.direction IS DISTINCT FROM p.direction
  OR NEW.direction='delete' AND o.native_status<>204
 THEN RAISE EXCEPTION 'Recycle completion requires the original succeeded operation, actual packet attempt and acknowledged native outcome' USING ERRCODE='23514';END IF;
 -- HMACs are keyed: the genuine Root verifier binds the actual encrypted
 -- result and fixed GET404 proof. SQL rows alone never mint that proof.
 RETURN NEW;END;
$$;
CREATE TRIGGER entity_change_recycle_receipts_guard BEFORE INSERT ON entity_change_recycle_receipts FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_receipt();

CREATE FUNCTION m11_guard_recycle_node_projection() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 IF NOT EXISTS(SELECT 1 FROM entity_change_recycle_archives WHERE entry_id=OLD.entry_id) THEN IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Source-bound recycle node identity is immutable' USING ERRCODE='23514';END IF;
 IF ROW(OLD.entry_id,OLD.node_key,OLD.entity_type,OLD.original_id,OLD.affected,OLD.dependencies) IS DISTINCT FROM ROW(NEW.entry_id,NEW.node_key,NEW.entity_type,NEW.original_id,NEW.affected,NEW.dependencies)
  OR NOT OLD.affected AND ROW(NEW.delete_state,NEW.restore_state,NEW.restored_id) IS DISTINCT FROM ROW('reference'::text,'reference'::text,NULL::text)
  OR NEW.delete_state='deleted' AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_receipts WHERE entry_id=NEW.entry_id AND node_key=NEW.node_key AND direction='delete')
  OR NEW.restore_state='restored' AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_receipts WHERE entry_id=NEW.entry_id AND node_key=NEW.node_key AND direction='restore' AND native_id::text=NEW.restored_id)
  OR OLD.delete_state='deleted' AND NEW.delete_state<>'deleted'
  OR OLD.restore_state='restored' AND ROW(NEW.restore_state,NEW.restored_id) IS DISTINCT FROM ROW(OLD.restore_state,OLD.restored_id)
 THEN RAISE EXCEPTION 'Recycle node projection requires its immutable identity and actual completion receipt' USING ERRCODE='23514';END IF;
 RETURN NEW;END;
$$;
CREATE TRIGGER recycle_nodes_entity_change_projection BEFORE UPDATE OR DELETE ON recycle_nodes FOR EACH ROW EXECUTE FUNCTION m11_guard_recycle_node_projection();

CREATE FUNCTION m11_guard_recycle_node_append() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 IF EXISTS(SELECT 1 FROM entity_change_recycle_archives WHERE entry_id=NEW.entry_id)
 THEN RAISE EXCEPTION 'Source-bound recycle graph cannot acquire additional nodes' USING ERRCODE='23514';END IF;
 RETURN NEW;END;
$$;
CREATE TRIGGER recycle_nodes_entity_change_no_append BEFORE INSERT ON recycle_nodes FOR EACH ROW EXECUTE FUNCTION m11_guard_recycle_node_append();

CREATE FUNCTION m11_guard_recycle_entry_projection() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE a entity_change_recycle_archives%ROWTYPE;
 BEGIN
 SELECT * INTO a FROM entity_change_recycle_archives WHERE entry_id=OLD.id;
 IF NOT FOUND THEN IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Source-bound recycle origin cannot be deleted' USING ERRCODE='23514';END IF;
 IF ROW(OLD.id,OLD.cluster_id,OLD.workspace_id,OLD.actor_id,OLD.root_type,OLD.original_id,OLD.root_name,OLD.parent_id,OLD.credential_kind,OLD.node_count,OLD.mutation_id,OLD.expires_at,OLD.created_at)
  IS DISTINCT FROM ROW(NEW.id,NEW.cluster_id,NEW.workspace_id,NEW.actor_id,NEW.root_type,NEW.original_id,NEW.root_name,NEW.parent_id,NEW.credential_kind,NEW.node_count,NEW.mutation_id,NEW.expires_at,NEW.created_at)
  OR NEW.payload_secret IS DISTINCT FROM OLD.payload_secret AND NOT(NEW.state='purged' AND NEW.payload_secret IS NULL AND NEW.purged_at IS NOT NULL
   AND NOT m11_entity_baseline_pin_active(a.baseline_id)
   AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_packets p WHERE p.entry_id=a.entry_id AND m11_entity_baseline_pin_active(p.baseline_id)))
  OR OLD.state='restored' AND NEW.state NOT IN('restored','purged')
  OR NEW.state='deleted' AND EXISTS(SELECT 1 FROM recycle_nodes WHERE entry_id=NEW.id AND affected AND delete_state<>'deleted')
  OR NEW.state='restored' AND EXISTS(SELECT 1 FROM recycle_nodes WHERE entry_id=NEW.id AND affected AND restore_state<>'restored')
 THEN RAISE EXCEPTION 'Recycle entry must preserve its actual source and complete protected recovery graph' USING ERRCODE='23514';END IF;
 RETURN NEW;END;
$$;
CREATE TRIGGER recycle_entries_entity_change_projection BEFORE UPDATE OR DELETE ON recycle_entries FOR EACH ROW EXECUTE FUNCTION m11_guard_recycle_entry_projection();
DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['entity_change_recycle_archives','entity_change_recycle_nodes','entity_change_recycle_packets','entity_change_recycle_receipts'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
 END LOOP;
END;$$;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_recycle_archives,entity_change_recycle_nodes,entity_change_recycle_packets,entity_change_recycle_receipts FROM PUBLIC;
