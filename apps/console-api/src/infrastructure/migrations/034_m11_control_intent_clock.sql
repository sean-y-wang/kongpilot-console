-- Keep the already-applied 033 checksum unchanged. PostgreSQL now() denotes
-- transaction start, whereas a prepared intent is issued after its original
-- validators and current-scope reads. Compare issuance to the observation
-- clock; retain every identity, epoch, scope and configuration guard.
DO $$
DECLARE definition text; marker text := 'NEW.issued_at>now()';
BEGIN
 definition := pg_get_functiondef('m11_validate_control_intent_author()'::regprocedure);
 IF length(definition)-length(replace(definition,marker,''))<>length(marker) THEN
  RAISE EXCEPTION 'Control intent clock repair requires the exact original single issuance guard' USING ERRCODE='23514';
 END IF;
 EXECUTE replace(definition,marker,'NEW.issued_at>clock_timestamp()');
END;
$$;
