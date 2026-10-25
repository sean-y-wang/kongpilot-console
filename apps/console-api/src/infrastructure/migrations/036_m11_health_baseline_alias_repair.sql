-- SQL022 repaired the original baseline SQL aliases. SQL031 subsequently
-- replaced the complete validator to add exact Target-health facts and
-- reintroduced aliases "o" (the local object row) and "old" (the trigger
-- record). Repair only those two original SQL031 subqueries, retaining the
-- current function/OID, all baseline checks and the added health conditions.
DO $$
DECLARE
 definition text;
 repaired text;
 candidate_before text := $candidate_before$FROM entity_change_baseline_objects o WHERE o.baseline_id=b.id AND o.affected
   AND o.native_type=p.native_type AND o.native_id=p.native_id AND o.parent_id IS NOT DISTINCT FROM p.parent_id AND o.credential_kind IS NOT DISTINCT FROM p.credential_kind
   AND o.present=(p.method<>'POST' OR p.mutation_action IN('mark_healthy','mark_unhealthy')))$candidate_before$;
 candidate_after text := $candidate_after$FROM entity_change_baseline_objects baseline_candidate_object_036 WHERE baseline_candidate_object_036.baseline_id=b.id AND baseline_candidate_object_036.affected
   AND baseline_candidate_object_036.native_type=p.native_type AND baseline_candidate_object_036.native_id=p.native_id AND baseline_candidate_object_036.parent_id IS NOT DISTINCT FROM p.parent_id AND baseline_candidate_object_036.credential_kind IS NOT DISTINCT FROM p.credential_kind
   AND baseline_candidate_object_036.present=(p.method<>'POST' OR p.mutation_action IN('mark_healthy','mark_unhealthy')))$candidate_after$;
 previous_before text := $previous_before$FROM entity_change_baseline_objects old WHERE old.baseline_id=b.id AND old.affected AND old.present
    AND old.native_type=p.native_type AND old.native_id=p.original_native_id AND old.parent_id IS NOT DISTINCT FROM p.parent_id)$previous_before$;
 previous_after text := $previous_after$FROM entity_change_baseline_objects baseline_previous_object_036 WHERE baseline_previous_object_036.baseline_id=b.id AND baseline_previous_object_036.affected AND baseline_previous_object_036.present
    AND baseline_previous_object_036.native_type=p.native_type AND baseline_previous_object_036.native_id=p.original_native_id AND baseline_previous_object_036.parent_id IS NOT DISTINCT FROM p.parent_id)$previous_after$;
BEGIN
 definition := pg_get_functiondef('public.m11_validate_baseline_graph()'::regprocedure);
 IF length(definition)-length(replace(definition,candidate_before,''))<>length(candidate_before)
  OR length(definition)-length(replace(definition,previous_before,''))<>length(previous_before)
  OR position('FROM entity_change_target_health_baselines h' IN definition)=0
  OR position('o entity_change_baseline_objects%ROWTYPE' IN definition)=0
  OR position('FOR o IN SELECT * FROM entity_change_baseline_objects' IN definition)=0
  OR position('baseline_candidate_object_036' IN definition)>0
  OR position('baseline_previous_object_036' IN definition)>0 THEN
  RAISE EXCEPTION 'Baseline alias repair requires the exact two original SQL031 subqueries and existing health guards' USING ERRCODE='23514';
 END IF;
 repaired := replace(replace(definition,candidate_before,candidate_after),previous_before,previous_after);
 IF repaired=definition
  OR position(candidate_before IN repaired)>0 OR position(previous_before IN repaired)>0
  OR position('FROM entity_change_baseline_objects o WHERE' IN repaired)>0
  OR position('FROM entity_change_baseline_objects old WHERE' IN repaired)>0
  OR replace(replace(repaired,candidate_after,candidate_before),previous_after,previous_before) IS DISTINCT FROM definition THEN
  RAISE EXCEPTION 'Baseline alias repair must preserve every original validator byte outside the two SQL aliases' USING ERRCODE='23514';
 END IF;
 EXECUTE repaired;
END;
$$;
