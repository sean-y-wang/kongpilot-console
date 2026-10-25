-- Rollback of SQL045 / KP-006 scheduled portal-credential rotate|revoke.
-- Refuses while any rotate/revoke schedule or delegation row exists.
DO $$BEGIN
 IF EXISTS(SELECT 1 FROM workflow_schedules WHERE kind IN('portal-credential-rotate','portal-credential-revoke'))
  OR EXISTS(SELECT 1 FROM workflow_executor_delegations WHERE kind IN('portal-credential-rotate','portal-credential-revoke'))
 THEN RAISE EXCEPTION 'SQL045 rollback refused: portal-credential rotate/revoke schedules exist' USING ERRCODE='55000';END IF;
END;$$;

ALTER TABLE workflow_executor_delegations DROP CONSTRAINT IF EXISTS workflow_executor_delegations_portal_subject_check;
ALTER TABLE workflow_executor_delegations DROP CONSTRAINT IF EXISTS workflow_executor_delegations_kind_check;
ALTER TABLE workflow_executor_delegations ADD CONSTRAINT workflow_executor_delegations_kind_check
 CHECK(kind IN('configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'));
ALTER TABLE workflow_executor_delegations ADD CONSTRAINT workflow_executor_delegations_check
 CHECK((kind='configuration_v2' AND subject_type='configuration_jobs' AND requester_type='console' AND requester_id=owner_id AND requester_credential_epoch=owner_credential_epoch)
  OR(kind='portal-credential-issue' AND subject_type='portal_application_grants' AND requester_type='developer'));

ALTER TABLE workflow_schedules DROP CONSTRAINT workflow_schedules_kind_check;
ALTER TABLE workflow_schedules ADD CONSTRAINT workflow_schedules_kind_check
 CHECK(kind IN('configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'));

-- Restore pre-SQL045 portal fragments (exact reverse of counted substitution).
DO $m045d$
DECLARE
 rewrites constant jsonb := jsonb_build_array(
  jsonb_build_object('fn','m11_business_schedule_pointer_advance(workflows,workflows)',
   'from',$f$OR old_workflow.kind NOT IN('configuration_v2','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata')$f$,
   'to',$t$OR old_workflow.kind NOT IN('configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata')$t$),
  jsonb_build_object('fn','m11_business_schedule_pointer_advance(workflows,workflows)',
   'from',$f$OR old_workflow.kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND old_workflow.execution_mode NOT IN('direct','approval')$f$,
   'to',$t$OR old_workflow.kind='portal-credential-issue' AND old_workflow.execution_mode NOT IN('direct','approval')$t$),
  jsonb_build_object('fn','m11_business_schedule_revision_complete()',
   'from',$f$OR w.kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND w.execution_mode NOT IN('direct','approval')$f$,
   'to',$t$OR w.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')$t$),
  jsonb_build_object('fn','m11_business_origin_permission()',
   'from',$f$OR s.kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND w.execution_mode NOT IN('direct','approval')$f$,
   'to',$t$OR s.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')$t$),
  jsonb_build_object('fn','m11_business_storage_complete()',
   'from',$f$OR s.kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND co.id IS NOT NULL$f$,
   'to',$t$OR s.kind='portal-credential-issue' AND co.id IS NOT NULL$t$));
 r jsonb; def text; hits integer;
BEGIN
 FOR r IN SELECT * FROM jsonb_array_elements(rewrites) LOOP
  def := pg_get_functiondef(('public.'||(r->>'fn'))::regprocedure);
  hits := (length(def)-length(replace(def,r->>'from','')))/length(r->>'from');
  IF hits<>1 THEN RAISE EXCEPTION 'SQL045 down expected exactly one fragment in %, found %',r->>'fn',hits USING ERRCODE='55000';END IF;
  EXECUTE replace(def,r->>'from',r->>'to');
  EXECUTE format('ALTER FUNCTION public.%s SET search_path = pg_catalog, public, pg_temp',r->>'fn');
 END LOOP;
END
$m045d$;
DELETE FROM schema_migrations WHERE name='045_m11_portal_credential_change_schedules.sql';
