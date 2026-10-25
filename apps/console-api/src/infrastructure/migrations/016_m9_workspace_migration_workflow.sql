-- M9 fixed approval wrapper for M3 tag migration. All historical migrations stay immutable.
ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_kind_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration'));
ALTER TABLE workflows DROP CONSTRAINT workflows_kind_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration'));
ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries','configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs','toolbox_operations','workspace_migration_plans'));
ALTER TABLE workflow_steps DROP CONSTRAINT workflow_steps_mutation_action_check;
ALTER TABLE workflow_steps ADD CONSTRAINT workflow_steps_mutation_action_check CHECK(mutation_action IS NULL OR mutation_action IN('create','update','delete','restore','migrate'));
ALTER TABLE workflow_steps ADD CONSTRAINT workflow_steps_migration_fixed CHECK(mutation_action IS DISTINCT FROM 'migrate' OR(kind='native' AND handler IS NULL AND entity_type='workspace_migration' AND entity_id IS NOT NULL AND parent_id IS NULL AND credential_kind IS NULL AND permission_action='write' AND jsonb_array_length(native_requests) BETWEEN 1 AND 32));

CREATE TABLE workspace_migration_workflow_bindings(
 cluster_id uuid NOT NULL,
 source_workspace_id uuid NOT NULL,
 target_workspace_id uuid NOT NULL,
 migration_plan_id uuid NOT NULL,
 workflow_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 migration_plan_hash text NOT NULL CHECK(migration_plan_hash~'^[a-f0-9]{64}$'),
 material_hmac text NOT NULL CHECK(material_hmac~'^[a-f0-9]{64}$'),
 request_hash text NOT NULL CHECK(request_hash~'^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cluster_id,migration_plan_id),
 UNIQUE(cluster_id,source_workspace_id,workflow_id),
 CHECK(source_workspace_id<>target_workspace_id),
 FOREIGN KEY(cluster_id,migration_plan_id) REFERENCES workspace_migration_plans(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,source_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,target_workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,source_workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER workspace_migration_workflow_bindings_immutable BEFORE UPDATE OR DELETE ON workspace_migration_workflow_bindings FOR EACH ROW EXECUTE FUNCTION m8_immutable();
CREATE TRIGGER workspace_migration_workflow_bindings_no_truncate BEFORE TRUNCATE ON workspace_migration_workflow_bindings FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();
CREATE FUNCTION m9_guard_bound_migration() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM workspace_migration_workflow_bindings WHERE cluster_id=OLD.cluster_id AND migration_plan_id=OLD.id) AND
 (TG_OP='DELETE' OR NEW.id IS DISTINCT FROM OLD.id OR NEW.cluster_id IS DISTINCT FROM OLD.cluster_id OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
  OR NEW.source_workspace_id IS DISTINCT FROM OLD.source_workspace_id OR NEW.target_workspace_id IS DISTINCT FROM OLD.target_workspace_id
  OR NEW.plan_hash IS DISTINCT FROM OLD.plan_hash OR NEW.payload_secret IS DISTINCT FROM OLD.payload_secret OR NEW.expires_at IS DISTINCT FROM OLD.expires_at)
 THEN RAISE EXCEPTION 'An approval-bound migration cannot rebase or replace its frozen material' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END;$$;
CREATE TRIGGER workspace_migration_plans_bound_identity BEFORE UPDATE OR DELETE ON workspace_migration_plans FOR EACH ROW EXECUTE FUNCTION m9_guard_bound_migration();
CREATE FUNCTION m9_validate_migration_wrapper() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='workspace_migration_workflow_bindings' THEN
  SELECT * INTO w FROM workflows WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.source_workspace_id AND id=NEW.workflow_id;
  IF w.id IS NULL OR w.kind<>'workspace-migration' OR w.subject_type<>'workspace_migration_plans' OR w.subject_id<>NEW.migration_plan_id OR w.requester_user_id<>NEW.actor_id
   OR NOT EXISTS(SELECT 1 FROM workspace_migration_plans p WHERE p.cluster_id=NEW.cluster_id AND p.id=NEW.migration_plan_id AND p.source_workspace_id=NEW.source_workspace_id AND p.target_workspace_id=NEW.target_workspace_id AND p.actor_id=NEW.actor_id AND p.plan_hash=NEW.migration_plan_hash)
   THEN RAISE EXCEPTION 'Migration approval source must match the complete durable tenant tuple' USING ERRCODE='23503';END IF;
 ELSE
  SELECT * INTO w FROM workflows WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.workflow_id;
  IF(NEW.mutation_action='migrate' OR NEW.entity_type='workspace_migration') AND(w.id IS NULL OR w.kind<>'workspace-migration' OR w.subject_type<>'workspace_migration_plans' OR w.subject_id IS DISTINCT FROM NEW.entity_id)
   THEN RAISE EXCEPTION 'Migration native authority is restricted to its own exact wrapper' USING ERRCODE='23514';END IF;
 END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER workspace_migration_workflow_bindings_source AFTER INSERT ON workspace_migration_workflow_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m9_validate_migration_wrapper();
CREATE CONSTRAINT TRIGGER workflow_steps_migration_source AFTER INSERT OR UPDATE ON workflow_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m9_validate_migration_wrapper();

CREATE OR REPLACE FUNCTION m6_validate_workflow_subject() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE subject_exists boolean;owner_id uuid;j configuration_jobs%ROWTYPE;
BEGIN

 IF NEW.subject_type='workspace_migration_plans' AND NEW.kind<>'workspace-migration' THEN RAISE EXCEPTION 'Migration subjects require the fixed native migration wrapper' USING ERRCODE='23514';END IF;
 IF NEW.kind='workspace-migration' THEN
  IF NEW.subject_type<>'workspace_migration_plans' OR NEW.requester_type<>'console' OR NEW.execution_mode<>'approval' OR NOT NEW.approval_required
   OR NOT EXISTS(SELECT 1 FROM workspace_migration_workflow_bindings b JOIN workspace_migration_plans p ON p.cluster_id=b.cluster_id AND p.id=b.migration_plan_id
    WHERE b.cluster_id=NEW.cluster_id AND b.source_workspace_id=NEW.workspace_id AND b.migration_plan_id=NEW.subject_id AND b.workflow_id=NEW.id
    AND b.actor_id=NEW.requester_user_id AND p.actor_id=b.actor_id AND p.source_workspace_id=b.source_workspace_id AND p.target_workspace_id=b.target_workspace_id AND p.plan_hash=b.migration_plan_hash)
   OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision)<>1
   OR NOT EXISTS(SELECT 1 FROM workflow_steps WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND workflow_id=NEW.id AND plan_revision=NEW.plan_revision AND plan_hash=NEW.plan_hash
    AND kind='native' AND handler IS NULL AND step_key='workspace-migration' AND entity_type='workspace_migration' AND entity_id=NEW.subject_id AND mutation_action='migrate'
    AND permission_action='write' AND parent_id IS NULL AND credential_kind IS NULL AND dependencies='{}'::uuid[] AND jsonb_array_length(native_requests) BETWEEN 1 AND 32
    AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(native_requests) packet WHERE packet->>'method'<>'PATCH' OR packet->>'native_type' NOT IN('services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')))
   THEN RAISE EXCEPTION 'Migration wrapper must bind its exact source target owner and tag-only plan' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;

 IF NEW.subject_type='toolbox_operations' AND NEW.kind<>'toolbox-operation' THEN RAISE EXCEPTION 'Cache subjects require their exact operational wrapper' USING ERRCODE='23514';END IF;
 IF NEW.kind='toolbox-operation' THEN
  IF NEW.subject_type<>'toolbox_operations' OR NEW.requester_type<>'console'
   OR NOT EXISTS(SELECT 1 FROM toolbox_operations o WHERE o.cluster_id=NEW.cluster_id AND o.workspace_id=NEW.workspace_id AND o.id=NEW.subject_id AND o.actor_id=NEW.requester_user_id AND o.workflow_id=NEW.id AND o.execution_mode=NEW.execution_mode AND (TG_OP<>'INSERT' OR o.state='pending-approval'))
   OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision)<>1
   OR NOT EXISTS(SELECT 1 FROM workflow_steps WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND workflow_id=NEW.id AND plan_revision=NEW.plan_revision AND plan_hash=NEW.plan_hash AND kind='metadata' AND handler='toolbox.execute' AND entity_type='toolbox_operations' AND entity_id=NEW.subject_id AND native_requests='[]'::jsonb AND operation_id IS NULL)
   THEN RAISE EXCEPTION 'Cache wrapper must retain its exact scoped operation and handler' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
 IF NEW.kind='event-metadata' THEN
  IF NEW.requester_type<>'console' OR NEW.subject_type NOT IN('notification_channels','event_subscriptions','event_deliveries') THEN RAISE EXCEPTION 'Event metadata is a fixed console workflow' USING ERRCODE='23514';END IF;
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3)',NEW.subject_type) INTO subject_exists USING NEW.cluster_id,NEW.workspace_id,NEW.subject_id;
  IF NOT subject_exists THEN RAISE EXCEPTION 'Event metadata subject is foreign' USING ERRCODE='23503';END IF;
  IF EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=NEW.id AND(kind<>'metadata' OR operation_id IS NOT NULL OR native_requests<>'[]'::jsonb OR handler NOT IN('event.channel.save','event.channel.status','event.channel.delete','event.channel.restore','event.channel.test','event.subscription.save','event.subscription.delete','event.subscription.restore','event.delivery.replay'))) THEN RAISE EXCEPTION 'Event workflow cannot claim native authority' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
 IF NEW.kind='configuration-metadata' THEN
  IF NEW.requester_type<>'console' OR NEW.subject_type NOT IN('config_snapshots','config_snapshot_schedules','configuration_gitops_runs') THEN RAISE EXCEPTION 'Configuration metadata has a fixed console subject' USING ERRCODE='23514';END IF;
  IF(SELECT count(*) FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision)<>1
    OR NOT EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision AND plan_hash=NEW.plan_hash AND kind='metadata' AND handler='configuration.metadata' AND entity_type=NEW.subject_type AND entity_id=NEW.subject_id AND operation_id IS NULL AND native_requests='[]'::jsonb)
    THEN RAISE EXCEPTION 'Configuration metadata cannot contain native authority' USING ERRCODE='23514';END IF;
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3)',NEW.subject_type) INTO subject_exists USING NEW.cluster_id,NEW.workspace_id,NEW.subject_id;
  IF NOT subject_exists AND NOT EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision AND metadata_revision=0)
    THEN RAISE EXCEPTION 'Configuration metadata subject is foreign' USING ERRCODE='23503';END IF;RETURN NULL;
 END IF;
 IF NEW.kind='configuration_v2' THEN
  IF NEW.subject_type<>'configuration_jobs' OR NEW.requester_type<>'console' THEN RAISE EXCEPTION 'Configuration wrapper requires a console-owned configuration job' USING ERRCODE='23514';END IF;
  SELECT * INTO j FROM configuration_jobs WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.subject_id;
  IF j.id IS NULL OR j.actor_id IS DISTINCT FROM NEW.requester_user_id OR j.execution_mode IS DISTINCT FROM NEW.execution_mode OR j.approval_required IS DISTINCT FROM NEW.approval_required
    OR j.plan_id IS NULL THEN RAISE EXCEPTION 'Configuration wrapper must retain its exact job and executor policy' USING ERRCODE='23514';END IF;
  IF NOT EXISTS(SELECT 1 FROM workflow_steps s WHERE s.cluster_id=NEW.cluster_id AND s.workspace_id=NEW.workspace_id AND s.workflow_id=NEW.id AND s.plan_revision=NEW.plan_revision AND s.plan_hash=NEW.plan_hash
    AND s.kind='metadata' AND s.handler='configuration_v2' AND s.entity_type='configuration_jobs' AND s.entity_id=j.id)
    OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision)<>1
    OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=NEW.id AND plan_revision=NEW.plan_revision AND(kind<>'metadata' OR jsonb_array_length(native_requests)<>0))
    THEN RAISE EXCEPTION 'Configuration wrapper contains exactly one fixed metadata step' USING ERRCODE='23514';END IF;
  RETURN NULL;
 END IF;
 IF NOT((NEW.kind='portal-publication' AND NEW.subject_type='portal_publications')
   OR(NEW.kind IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') AND NEW.subject_type='portal_application_grants')
   OR(NEW.kind='portal-developer-review' AND NEW.subject_type='portal_developers')
   OR(NEW.kind='portal-metadata' AND NEW.subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content')) OR(NEW.kind='native-change' AND NEW.subject_type NOT IN('configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs')))
   THEN RAISE EXCEPTION 'Workflow subject type does not match its fixed kind' USING ERRCODE='23514';END IF;
 -- NEW.subject_type remains constrained to the fixed server-owned table list.
 EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3)',NEW.subject_type) INTO subject_exists USING NEW.cluster_id,NEW.workspace_id,NEW.subject_id;
 IF NOT subject_exists THEN RAISE EXCEPTION 'Workflow subject must exist in the complete tenant scope' USING ERRCODE='23503';END IF;
 IF NEW.requester_type='developer' THEN
  IF NEW.kind NOT IN('portal-credential-issue','portal-credential-rotate','portal-credential-revoke') THEN RAISE EXCEPTION 'Developer workflows are restricted to their credential grants' USING ERRCODE='23514';END IF;
  SELECT developer_id INTO owner_id FROM portal_application_grants WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.subject_id;
  IF owner_id IS DISTINCT FROM NEW.requester_developer_id THEN RAISE EXCEPTION 'Developer workflow subject must retain its owner' USING ERRCODE='23514';END IF;
 END IF;RETURN NULL;
END;$$;
