-- SQL045: admit portal-credential-rotate / portal-credential-revoke to
-- business schedules (SQL026/SQL041 allowlists). Same subject binding as
-- issue: developer requester + portal_application_grants. Execution mode
-- remains direct|approval. Functions rewritten by exact counted substitution
-- with search_path pinned (pg_catalog, public, pg_temp) like SQL041.
ALTER TABLE workflow_executor_delegations DROP CONSTRAINT workflow_executor_delegations_kind_check;
ALTER TABLE workflow_executor_delegations ADD CONSTRAINT workflow_executor_delegations_kind_check
 CHECK(kind IN('configuration_v2','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'));
ALTER TABLE workflow_schedules DROP CONSTRAINT workflow_schedules_kind_check;
ALTER TABLE workflow_schedules ADD CONSTRAINT workflow_schedules_kind_check
 CHECK(kind IN('configuration_v2','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'));

-- Widen the original SQL026 portal/config subject CHECK (auto-named) to rotate/revoke.
DO $s045$
DECLARE
 c record; n integer := 0;
BEGIN
 FOR c IN SELECT conname, pg_get_constraintdef(oid) AS definition FROM pg_constraint
  WHERE conrelid='workflow_executor_delegations'::regclass AND contype='c' LOOP
  IF c.definition LIKE '%portal-credential-issue%'
     AND c.definition LIKE '%portal_application_grants%'
     AND c.definition LIKE '%configuration_jobs%'
     AND c.definition NOT LIKE '%portal-credential-rotate%'
     AND c.conname NOT LIKE '%kind_check%'
     AND c.conname NOT LIKE '%metadata_subject%' THEN
   EXECUTE format('ALTER TABLE workflow_executor_delegations DROP CONSTRAINT %I', c.conname);
   n := n + 1;
  END IF;
 END LOOP;
 IF n <> 1 THEN RAISE EXCEPTION 'SQL045 expected exactly one portal/config subject CHECK on workflow_executor_delegations, found %', n USING ERRCODE='55000'; END IF;
 ALTER TABLE workflow_executor_delegations ADD CONSTRAINT workflow_executor_delegations_portal_subject_check
  CHECK((kind='configuration_v2' AND subject_type='configuration_jobs' AND requester_type='console' AND requester_id=owner_id AND requester_credential_epoch=owner_credential_epoch)
   OR(kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND subject_type='portal_application_grants' AND requester_type='developer'));
END
$s045$;

DO $m045$
DECLARE
 rewrites constant jsonb := jsonb_build_array(
  jsonb_build_object('fn','m11_business_schedule_pointer_advance(workflows,workflows)',
   'from',$f$OR old_workflow.kind NOT IN('configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata')$f$,
   'to',$t$OR old_workflow.kind NOT IN('configuration_v2','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata')$t$),
  jsonb_build_object('fn','m11_business_schedule_pointer_advance(workflows,workflows)',
   'from',$f$OR old_workflow.kind='portal-credential-issue' AND old_workflow.execution_mode NOT IN('direct','approval')$f$,
   'to',$t$OR old_workflow.kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND old_workflow.execution_mode NOT IN('direct','approval')$t$),
  jsonb_build_object('fn','m11_business_schedule_revision_complete()',
   'from',$f$OR w.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')$f$,
   'to',$t$OR w.kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND w.execution_mode NOT IN('direct','approval')$t$),
  jsonb_build_object('fn','m11_business_origin_permission()',
   'from',$f$OR s.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')$f$,
   'to',$t$OR s.kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND w.execution_mode NOT IN('direct','approval')$t$),
  jsonb_build_object('fn','m11_business_storage_complete()',
   'from',$f$OR s.kind='portal-credential-issue' AND co.id IS NOT NULL$f$,
   'to',$t$OR s.kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND co.id IS NOT NULL$t$));
 r jsonb; def text; hits integer;
BEGIN
 FOR r IN SELECT * FROM jsonb_array_elements(rewrites) LOOP
  def := pg_get_functiondef(('public.'||(r->>'fn'))::regprocedure);
  hits := (length(def)-length(replace(def,r->>'from','')))/length(r->>'from');
  IF hits<>1 THEN RAISE EXCEPTION 'SQL045 expected exactly one fragment in %, found %',r->>'fn',hits USING ERRCODE='55000';END IF;
  EXECUTE replace(def,r->>'from',r->>'to');
  EXECUTE format('ALTER FUNCTION public.%s SET search_path = pg_catalog, public, pg_temp',r->>'fn');
 END LOOP;
END
$m045$;
