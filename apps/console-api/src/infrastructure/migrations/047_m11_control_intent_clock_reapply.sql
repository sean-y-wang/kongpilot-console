-- SQL040 re-created m11_validate_control_intent_author() from the SQL033 text
-- and thereby reintroduced the transaction-start issuance guard that SQL034
-- had repaired ('NEW.issued_at>now()'). now() is the transaction start, while
-- a prepared control intent is issued after its validators and scope reads,
-- so every control-change preparation (data sources, cluster metadata,
-- workspaces, recycle purge) on an approval-mode cluster was rejected with
-- 23514. Re-apply the SQL034 repair to the current definition only; every
-- identity, epoch, scope and configuration guard is retained unchanged.
DO $$
DECLARE definition text; marker text := 'NEW.issued_at>now()'; repaired text := 'NEW.issued_at>clock_timestamp()';
BEGIN
 definition := pg_get_functiondef('m11_validate_control_intent_author()'::regprocedure);
 IF position(marker IN definition)=0 AND length(definition)-length(replace(definition,repaired,''))=length(repaired) THEN
  RETURN; -- already repaired
 END IF;
 IF length(definition)-length(replace(definition,marker,''))<>length(marker) OR position(repaired IN definition)>0 THEN
  RAISE EXCEPTION 'Control intent clock re-repair requires the exact single transaction-start issuance guard' USING ERRCODE='23514';
 END IF;
 EXECUTE replace(definition,marker,repaired);
END;
$$;
