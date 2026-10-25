-- Node-local Target health observations are immutable evidence, never permits.
-- Existing baseline graph/configuration recovery guards remain unchanged;
-- a present health POST additionally requires a typed exact original fact.
CREATE TABLE entity_change_target_health_baselines (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,baseline_id uuid NOT NULL,object_manifest_hmac text NOT NULL,
 object_key text NOT NULL,packet_key text NOT NULL CHECK(length(packet_key) BETWEEN 1 AND 128),
 native_id uuid NOT NULL,upstream_id uuid NOT NULL,before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),
 provenance_hmac text NOT NULL CHECK(m8_hex64(provenance_hmac)),node_id text NOT NULL CHECK(octet_length(node_id) BETWEEN 1 AND 256),
 health text NOT NULL CHECK(health IN('HEALTHY','UNHEALTHY')),
 health_row_hmac text NOT NULL CHECK(m8_hex64(health_row_hmac)),observation_hmac text NOT NULL CHECK(m8_hex64(observation_hmac)),
 override_recoverable boolean NOT NULL DEFAULT false CHECK(override_recoverable=false),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(baseline_id,packet_key),UNIQUE(baseline_id,object_key),
 FOREIGN KEY(cluster_id,workspace_id,baseline_id,object_manifest_hmac)
 REFERENCES entity_change_baselines(cluster_id,workspace_id,id,object_manifest_hmac) ON DELETE RESTRICT,
 FOREIGN KEY(baseline_id,object_key) REFERENCES entity_change_baseline_objects(baseline_id,object_key) ON DELETE RESTRICT
);
CREATE FUNCTION m11_validate_target_health_baseline() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE b entity_change_baselines%ROWTYPE;o entity_change_baseline_objects%ROWTYPE;p entity_change_intent_packets%ROWTYPE;
 BEGIN
 SELECT * INTO b FROM entity_change_baselines WHERE id=NEW.baseline_id;
 SELECT * INTO o FROM entity_change_baseline_objects WHERE baseline_id=NEW.baseline_id AND object_key=NEW.object_key;
 SELECT * INTO p FROM entity_change_intent_packets WHERE cluster_id=b.cluster_id AND workspace_id=b.workspace_id
  AND intent_id=b.intent_id AND intent_revision=b.intent_revision AND packet_key=NEW.packet_key;
 IF b.id IS NULL OR o.object_key IS NULL OR p.packet_key IS NULL OR p.material_hmac IS DISTINCT FROM b.material_hmac
  OR p.change_digest IS DISTINCT FROM b.change_digest OR p.packet_manifest_hmac IS DISTINCT FROM b.packet_manifest_hmac
  OR NEW.cluster_id IS DISTINCT FROM b.cluster_id OR NEW.workspace_id IS DISTINCT FROM b.workspace_id
  OR NEW.object_manifest_hmac IS DISTINCT FROM b.object_manifest_hmac OR o.cluster_id IS DISTINCT FROM b.cluster_id
  OR o.workspace_id IS DISTINCT FROM b.workspace_id OR o.object_manifest_hmac IS DISTINCT FROM b.object_manifest_hmac
  OR p.native_type<>'targets' OR p.method<>'POST' OR p.permission_action<>'write'
  OR p.mutation_action NOT IN('mark_healthy','mark_unhealthy') OR p.original_native_id IS NOT NULL OR p.credential_kind IS NOT NULL
  OR o.native_type<>'targets' OR NOT o.affected OR NOT o.present OR o.recovery<>'complete' OR o.restore_hmac IS NULL
  OR NEW.native_id IS DISTINCT FROM p.native_id OR NEW.native_id IS DISTINCT FROM o.native_id
  OR NEW.upstream_id IS DISTINCT FROM p.parent_id OR NEW.upstream_id IS DISTINCT FROM o.parent_id
  OR NEW.before_hmac IS DISTINCT FROM p.before_hmac OR NEW.before_hmac IS DISTINCT FROM o.before_hmac
  OR NEW.provenance_hmac IS DISTINCT FROM o.provenance_hmac OR NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects parent
   WHERE parent.baseline_id=b.id AND parent.object_key=ANY(o.dependencies) AND parent.native_type='upstreams'
    AND parent.native_id=NEW.upstream_id AND parent.present AND parent.object_order<o.object_order)
 THEN RAISE EXCEPTION 'Health requires its complete exact present Target, upstream and non-reversible node observation' USING ERRCODE='23514';END IF;
 RETURN NEW;END;
$$;
CREATE TRIGGER entity_change_target_health_baselines_bound BEFORE INSERT ON entity_change_target_health_baselines
 FOR EACH ROW EXECUTE FUNCTION m11_validate_target_health_baseline();
CREATE TRIGGER entity_change_target_health_baselines_immutable BEFORE UPDATE OR DELETE ON entity_change_target_health_baselines
 FOR EACH ROW EXECUTE FUNCTION m8_immutable();
CREATE TRIGGER entity_change_target_health_baselines_no_truncate BEFORE TRUNCATE ON entity_change_target_health_baselines
 FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_target_health_baselines FROM PUBLIC;

CREATE OR REPLACE FUNCTION m11_validate_baseline_graph() RETURNS trigger LANGUAGE plpgsql AS $$
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
  AND(NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects o WHERE o.baseline_id=b.id AND o.affected
   AND o.native_type=p.native_type AND o.native_id=p.native_id AND o.parent_id IS NOT DISTINCT FROM p.parent_id AND o.credential_kind IS NOT DISTINCT FROM p.credential_kind
   AND o.present=(p.method<>'POST' OR p.mutation_action IN('mark_healthy','mark_unhealthy')))
   OR(p.mutation_action IN('mark_healthy','mark_unhealthy') AND NOT EXISTS(SELECT 1 FROM entity_change_target_health_baselines h
    WHERE h.baseline_id=b.id AND h.cluster_id=b.cluster_id AND h.workspace_id=b.workspace_id AND h.packet_key=p.packet_key
     AND p.method='POST' AND p.native_type='targets' AND p.permission_action='write' AND p.parent_id IS NOT NULL
     AND p.original_native_id IS NULL AND p.credential_kind IS NULL AND h.native_id=p.native_id AND h.upstream_id=p.parent_id AND h.before_hmac=p.before_hmac))
   OR(p.original_native_id IS NOT NULL AND p.mutation_action<>'restore' AND NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects old WHERE old.baseline_id=b.id AND old.affected AND old.present
    AND old.native_type=p.native_type AND old.native_id=p.original_native_id AND old.parent_id IS NOT DISTINCT FROM p.parent_id))))
 THEN RAISE EXCEPTION 'Every executable packet requires its complete real before or absence baseline; health additionally requires exact non-reversible node facts' USING ERRCODE='23514';END IF;
 RETURN NULL;END;
$$;
