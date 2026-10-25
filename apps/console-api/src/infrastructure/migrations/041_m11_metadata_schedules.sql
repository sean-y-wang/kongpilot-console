-- SQL041: business scheduling for the nine metadata-only approval kinds
-- (entity-annotation, control-, configuration-, governance-, workflow-policy-,
-- iam-, portal-metadata, portal-developer-review, event-metadata).
-- All are approval mode only; the Console requester equals owner/executor with
-- the same credential epoch, exactly like configuration_v2; each kind is bound
-- to the exact subject types its SQL010-040 workflow validator accepts.
-- Existing kinds, rows and validation bodies are preserved: functions are
-- rewritten by exact, counted text substitution and the migration fails if any
-- expected fragment is missing. Rewritten functions pin search_path with
-- pg_catalog first and pg_temp explicitly last (see SQL037 / C042-R1).
-- Not yet deployed anywhere: slice 1 (entity-annotation) was widened in place.
ALTER TABLE workflow_executor_delegations DROP CONSTRAINT workflow_executor_delegations_kind_check;
ALTER TABLE workflow_executor_delegations ADD CONSTRAINT workflow_executor_delegations_kind_check
 CHECK(kind IN('configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'));
ALTER TABLE workflow_schedules DROP CONSTRAINT workflow_schedules_kind_check;
ALTER TABLE workflow_schedules ADD CONSTRAINT workflow_schedules_kind_check
 CHECK(kind IN('configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'));
ALTER TABLE workflow_executor_delegations ADD CONSTRAINT workflow_executor_delegations_metadata_subject_check
 CHECK(kind NOT IN('entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata') OR(requester_type='console' AND requester_id=owner_id AND requester_credential_epoch=owner_credential_epoch AND(
  (kind='entity-annotation' AND subject_type='entity_annotation_requests')
  OR(kind='control-metadata' AND subject_type='control_metadata_requests')
  OR(kind='configuration-metadata' AND subject_type IN('config_snapshots','config_snapshot_schedules','configuration_gitops_runs'))
  OR(kind='governance-metadata' AND subject_type='governance_metadata_requests')
  OR(kind='workflow-policy-metadata' AND subject_type='workflow_policy_requests')
  OR(kind='iam-metadata' AND subject_type='iam_metadata_requests')
  OR(kind='portal-metadata' AND subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content'))
  OR(kind='portal-developer-review' AND subject_type='portal_developers')
  OR(kind='event-metadata' AND subject_type IN('notification_channels','event_subscriptions','event_deliveries')))));

DO $m041$
DECLARE
 rewrites constant jsonb := jsonb_build_array(
  jsonb_build_object('fn','m11_business_schedule_pointer_advance(workflows,workflows)',
   'from',$f$OR old_workflow.kind NOT IN('configuration_v2','portal-credential-issue')$f$,
   'to',$t$OR old_workflow.kind NOT IN('configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata')
  OR old_workflow.kind IN('entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata') AND old_workflow.execution_mode IS DISTINCT FROM 'approval'$t$),
  jsonb_build_object('fn','m11_business_schedule_revision_complete()',
   'from',$f$OR w.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')$f$,
   'to',$t$OR w.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')
  OR w.kind IN('entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata') AND w.execution_mode IS DISTINCT FROM 'approval'$t$),
  jsonb_build_object('fn','m11_business_origin_permission()',
   'from',$f$OR s.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')$f$,
   'to',$t$OR s.kind='portal-credential-issue' AND w.execution_mode NOT IN('direct','approval')
  OR s.kind IN('entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata') AND w.execution_mode IS DISTINCT FROM 'approval'
  OR s.kind IN('entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata') AND s.requester_type IS DISTINCT FROM 'console'$t$));
 r jsonb; def text; hits integer;
BEGIN
 FOR r IN SELECT * FROM jsonb_array_elements(rewrites) LOOP
  def := pg_get_functiondef(('public.'||(r->>'fn'))::regprocedure);
  hits := (length(def)-length(replace(def,r->>'from','')))/length(r->>'from');
  IF hits<>1 THEN RAISE EXCEPTION 'SQL041 expected exactly one fragment in %, found %',r->>'fn',hits USING ERRCODE='55000';END IF;
  EXECUTE replace(def,r->>'from',r->>'to');
  EXECUTE format('ALTER FUNCTION public.%s SET search_path = pg_catalog, public, pg_temp',r->>'fn');
 END LOOP;
END
$m041$;
