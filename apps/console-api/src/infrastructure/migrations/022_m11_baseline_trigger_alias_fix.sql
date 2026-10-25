-- Preserve SQL021 and all baseline checks; avoid PL/pgSQL row-variable alias ambiguity.
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
  AND(p.mutation_action IN('mark_healthy','mark_unhealthy') OR NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects candidate_object WHERE candidate_object.baseline_id=b.id AND candidate_object.affected
   AND candidate_object.native_type=p.native_type AND candidate_object.native_id=p.native_id AND candidate_object.parent_id IS NOT DISTINCT FROM p.parent_id AND candidate_object.credential_kind IS NOT DISTINCT FROM p.credential_kind
   AND candidate_object.present=(p.method<>'POST'))
   OR(p.original_native_id IS NOT NULL AND p.mutation_action<>'restore' AND NOT EXISTS(SELECT 1 FROM entity_change_baseline_objects previous_object WHERE previous_object.baseline_id=b.id AND previous_object.affected AND previous_object.present
    AND previous_object.native_type=p.native_type AND previous_object.native_id=p.original_native_id AND previous_object.parent_id IS NOT DISTINCT FROM p.parent_id))))
 THEN RAISE EXCEPTION 'Every executable packet requires its complete real before or absence baseline; health remains blocked' USING ERRCODE='23514';END IF;
 RETURN NULL;END;
$$;
