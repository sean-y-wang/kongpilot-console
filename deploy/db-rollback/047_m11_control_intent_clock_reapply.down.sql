-- Rollback of SQL047: restores the SQL040 definition (transaction-start
-- issuance guard). Note this re-introduces the control-change preparation
-- defect on approval-mode clusters; only use together with rolling back the
-- application release.
DO $$
DECLARE definition text; marker text := 'NEW.issued_at>clock_timestamp()';
BEGIN
 definition := pg_get_functiondef('m11_validate_control_intent_author()'::regprocedure);
 IF length(definition)-length(replace(definition,marker,''))<>length(marker) THEN
  RAISE EXCEPTION 'SQL047 rollback requires the exact single repaired issuance guard' USING ERRCODE='23514';
 END IF;
 EXECUTE replace(definition,marker,'NEW.issued_at>now()');
END;
$$;
