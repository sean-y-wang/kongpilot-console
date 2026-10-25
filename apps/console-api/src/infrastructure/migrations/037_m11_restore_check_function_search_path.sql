-- pg_restore loads rows with an empty session search_path. These four pure
-- CHECK wrappers resolve application helpers in public; preserve their OIDs,
-- bodies, constraints and historical rows while fixing only that resolution.
-- Keep pg_catalog first and pg_temp explicitly last to avoid implicit first
-- temporary relation/type lookup. No other workflow or authority function is
-- altered, and a missing signature fails the normal migration transaction.
ALTER FUNCTION public.m7_historical_scope(jsonb)
 SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.m7_filter(text[], text, uuid[], text[])
 SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.m7_observation_value(text, text, jsonb)
 SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.m7_event_payload(jsonb)
 SET search_path = pg_catalog, public, pg_temp;
