-- A new console-owned domain. No Kong database change, old migration edit,
-- trigger disable, credential issuance or generic native-authority shortcut.
ALTER TABLE workflow_definitions DROP CONSTRAINT workflow_definitions_kind_check;
ALTER TABLE workflow_definitions ADD CONSTRAINT workflow_definitions_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata','workflow-policy-metadata','iam-metadata','metrics-setup'));
ALTER TABLE workflows DROP CONSTRAINT workflows_kind_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_kind_check CHECK(kind IN('portal-publication','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','portal-developer-review','portal-metadata','native-change','event-metadata','configuration_v2','configuration-metadata','toolbox-operation','workspace-migration','governance-metadata','workflow-policy-metadata','iam-metadata','metrics-setup'));
ALTER TABLE workflows DROP CONSTRAINT workflows_subject_type_check;
ALTER TABLE workflows ADD CONSTRAINT workflows_subject_type_check CHECK(subject_type IN('portal_settings','portal_developers','portal_applications','portal_publications','portal_content','portal_application_grants','notification_channels','event_subscriptions','event_deliveries','configuration_jobs','config_snapshots','config_snapshot_schedules','configuration_gitops_runs','toolbox_operations','workspace_migration_plans','governance_metadata_requests','workflow_policy_requests','entity_change_intents','iam_metadata_requests','metrics_setup_requests'));

CREATE TABLE metrics_setup_intents (
 id uuid PRIMARY KEY,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 authoring_session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,workflow_id uuid NOT NULL UNIQUE,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 128),request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),material_secret text NOT NULL CHECK(m6_encrypted(material_secret)),
 credential_epoch bigint NOT NULL CHECK(credential_epoch>0),permission_version text NOT NULL CHECK(length(permission_version) BETWEEN 1 AND 256),
 mode text NOT NULL CHECK(mode IN('native_prometheus','collector')),source_id uuid NOT NULL,source_revision integer NOT NULL CHECK(source_revision>0),
 settings_revision integer NOT NULL CHECK(settings_revision>=0),credential_generation integer NOT NULL CHECK(credential_generation>=0),
 issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '24 hours'),
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(actor_id,idempotency_key),UNIQUE(cluster_id,workspace_id,id),
 FOREIGN KEY(cluster_id,workspace_id) REFERENCES workspaces(cluster_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,source_id) REFERENCES data_sources(cluster_id,id) ON DELETE RESTRICT,
 CHECK(mode<>'collector' OR credential_generation>0)
);
CREATE TABLE metrics_setup_plugin_material (
 intent_id uuid NOT NULL,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,name text NOT NULL CHECK(name IN('prometheus','http-log')),
 step_order integer NOT NULL CHECK(step_order IN(1,2)),action text NOT NULL CHECK(action IN('create','update')),native_id uuid NOT NULL,
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),before_hmac text NOT NULL CHECK(m8_hex64(before_hmac)),
 payload_hmac text NOT NULL CHECK(m8_hex64(payload_hmac)),schema_hmac text NOT NULL CHECK(m8_hex64(schema_hmac)),path_hmac text NOT NULL CHECK(m8_hex64(path_hmac)),
 created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(intent_id,name),UNIQUE(intent_id,step_order),UNIQUE(intent_id,native_id),
 FOREIGN KEY(cluster_id,workspace_id,intent_id) REFERENCES metrics_setup_intents(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK((step_order=1 AND name='prometheus') OR(step_order=2 AND name='http-log'))
);
CREATE TABLE metrics_setup_requests (
 id uuid PRIMARY KEY REFERENCES metrics_setup_intents(id) ON DELETE RESTRICT,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,workflow_id uuid NOT NULL UNIQUE,idempotency_key text NOT NULL,submit_key text NOT NULL CHECK(length(submit_key) BETWEEN 8 AND 128),
 request_hmac text NOT NULL CHECK(m8_hex64(request_hmac)),material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(cluster_id,workspace_id,id),UNIQUE(actor_id,submit_key),
 FOREIGN KEY(cluster_id,workspace_id,id) REFERENCES metrics_setup_intents(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE metrics_setup_completion_facts (
 intent_id uuid PRIMARY KEY REFERENCES metrics_setup_requests(id) ON DELETE RESTRICT,cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,workflow_id uuid NOT NULL,
 execution_id uuid NOT NULL UNIQUE REFERENCES workflow_executions(id) ON DELETE RESTRICT,step_id uuid NOT NULL UNIQUE REFERENCES workflow_steps(id) ON DELETE RESTRICT,
 actor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE RESTRICT,
 plan_hash text NOT NULL CHECK(m8_hex64(plan_hash)),material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),
 native_operation_ids uuid[] NOT NULL CHECK(cardinality(native_operation_ids) IN(1,2) AND array_ndims(native_operation_ids)=1 AND array_position(native_operation_ids,NULL) IS NULL),
 before_settings_revision integer NOT NULL CHECK(before_settings_revision>=0),after_settings_revision integer NOT NULL,
 credential_generation integer NOT NULL CHECK(credential_generation>=0),result_hmac text NOT NULL CHECK(m8_hex64(result_hmac)),created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(cluster_id,workspace_id,workflow_id) REFERENCES workflows(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,intent_id) REFERENCES metrics_setup_requests(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 CHECK(after_settings_revision=CASE WHEN before_settings_revision=0 THEN 2 ELSE before_settings_revision+1 END)
);

CREATE FUNCTION m11_validate_metrics_setup_author() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE u users%ROWTYPE;s auth_sessions%ROWTYPE;c clusters%ROWTYPE;wid workspaces%ROWTYPE;ds data_sources%ROWTYPE;epoch bigint;
BEGIN
 SELECT * INTO u FROM users WHERE id=NEW.actor_id;SELECT * INTO s FROM auth_sessions WHERE id=NEW.authoring_session_id;
 SELECT * INTO c FROM clusters WHERE id=NEW.cluster_id;SELECT * INTO wid FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=NEW.workspace_id;
 SELECT * INTO ds FROM data_sources WHERE cluster_id=NEW.cluster_id AND id=NEW.source_id;SELECT version INTO epoch FROM iam_epoch WHERE singleton=true;
 IF u.id IS NULL OR s.id IS NULL OR c.id IS NULL OR wid.id IS NULL OR ds.id IS NULL OR epoch IS NULL OR NOT u.super_admin OR u.status<>'active' OR u.deleted_at IS NOT NULL OR u.force_password_change
  OR s.user_id<>u.id OR s.revoked_at IS NOT NULL OR s.expires_at<=now() OR s.credential_epoch<>u.credential_epoch OR NEW.credential_epoch<>u.credential_epoch OR NEW.expires_at>s.expires_at
  OR NEW.permission_version IS DISTINCT FROM (u.id::text||':'||u.permissions_epoch::text||':'||epoch::text) OR c.deleted_at IS NOT NULL OR c.status='disabled' OR c.execution_mode<>'approval'
  OR NOT wid.is_default OR wid.status<>'active' OR wid.deleted_at IS NOT NULL OR ds.type<>'prometheus' OR NOT ds.enabled OR ds.deleted_at IS NOT NULL OR ds.revision<>NEW.source_revision
  OR coalesce((SELECT revision FROM metrics_settings WHERE cluster_id=c.id),0)<>NEW.settings_revision
  OR coalesce((SELECT credential_generation FROM metrics_settings WHERE cluster_id=c.id),0)<>NEW.credential_generation
  OR(NEW.mode='collector' AND NOT EXISTS(SELECT 1 FROM metrics_credentials WHERE cluster_id=c.id AND generation=NEW.credential_generation AND purpose='collector_ingest' AND audience='collector' AND status='active'))
 THEN RAISE EXCEPTION 'Monitoring intention requires its actual current author, default scope, source and existing generation' USING ERRCODE='23514';END IF;RETURN NEW;
END;$$;
CREATE TRIGGER metrics_setup_intent_author BEFORE INSERT ON metrics_setup_intents FOR EACH ROW EXECUTE FUNCTION m11_validate_metrics_setup_author();

CREATE FUNCTION m11_validate_metrics_setup_material() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE i metrics_setup_intents%ROWTYPE;count_plugins integer;
BEGIN
 IF TG_TABLE_NAME='metrics_setup_intents' THEN SELECT * INTO i FROM metrics_setup_intents WHERE id=NEW.id;
 ELSE SELECT * INTO i FROM metrics_setup_intents WHERE id=NEW.intent_id;END IF;
 SELECT count(*) INTO count_plugins FROM metrics_setup_plugin_material WHERE intent_id=i.id;
 IF i.id IS NULL OR count_plugins<>(CASE WHEN i.mode='collector' THEN 2 ELSE 1 END)
  OR EXISTS(SELECT 1 FROM metrics_setup_plugin_material WHERE intent_id=i.id AND (cluster_id<>i.cluster_id OR workspace_id<>i.workspace_id OR material_hmac<>i.material_hmac))
 THEN RAISE EXCEPTION 'Monitoring material requires its complete immutable one or two plugin manifest' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER metrics_setup_intent_material AFTER INSERT ON metrics_setup_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_metrics_setup_material();
CREATE CONSTRAINT TRIGGER metrics_setup_plugin_material_complete AFTER INSERT ON metrics_setup_plugin_material DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_metrics_setup_material();

DO $$DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['metrics_setup_intents','metrics_setup_plugin_material','metrics_setup_requests','metrics_setup_completion_facts'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION m8_immutable()',tab||'_immutable',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()',tab||'_no_truncate',tab);
  EXECUTE format('REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON %I FROM PUBLIC',tab);
 END LOOP;
END;$$;
-- Preserve every existing subject branch, including SQL030 IAM. Only this new
-- kind is delegated to the additional strict graph validator below.
DO $$DECLARE definition text;BEGIN
 definition=pg_get_functiondef('m6_validate_workflow_subject()'::regprocedure);
 definition=regexp_replace(definition,'\mBEGIN\M',E'BEGIN\n IF NEW.kind=''metrics-setup'' THEN RETURN NULL;END IF;');EXECUTE definition;
END;$$;
CREATE FUNCTION m11_validate_metrics_setup_graph() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;r metrics_setup_requests%ROWTYPE;i metrics_setup_intents%ROWTYPE;s workflow_steps%ROWTYPE;p metrics_setup_plugin_material%ROWTYPE;native_count integer;
BEGIN
 IF TG_TABLE_NAME='metrics_setup_requests' OR TG_TABLE_NAME='workflow_steps' THEN SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 ELSE SELECT * INTO w FROM workflows WHERE id=NEW.id;END IF;
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF w.kind<>'metrics-setup' THEN
  IF w.subject_type='metrics_setup_requests' OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=w.id AND handler='metrics.setup.settings') THEN
   RAISE EXCEPTION 'Monitoring settings require their dedicated metrics setup kind' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
 SELECT * INTO r FROM metrics_setup_requests WHERE id=w.subject_id AND cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id;
 SELECT * INTO i FROM metrics_setup_intents WHERE id=r.id;native_count=(CASE WHEN i.mode='collector' THEN 2 ELSE 1 END);
 IF r.id IS NULL OR i.id IS NULL OR w.subject_type<>'metrics_setup_requests' OR w.requester_type<>'console' OR w.requester_user_id<>i.actor_id OR r.actor_id<>i.actor_id
  OR i.workflow_id<>w.id OR i.cluster_id<>w.cluster_id OR i.workspace_id<>w.workspace_id OR r.material_hmac<>i.material_hmac OR r.request_hmac<>i.request_hmac
  OR r.idempotency_key IS DISTINCT FROM ('metrics-'||i.id::text) OR w.idempotency_key<>r.idempotency_key OR w.execution_mode<>'approval' OR NOT w.approval_required OR w.approval_format<>2
  OR w.plan_revision<>1 OR w.expires_at<>i.expires_at OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=1)<>native_count+1
 THEN RAISE EXCEPTION 'Monitoring workflow must bind its immutable original intention and full V2 plan' USING ERRCODE='23514';END IF;
 FOR s IN SELECT * FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=1 ORDER BY step_order LOOP
  IF s.cluster_id<>w.cluster_id OR s.workspace_id<>w.workspace_id OR s.plan_hash<>w.plan_hash OR s.permission_action<>'write' OR s.parent_id IS NOT NULL OR s.credential_kind IS NOT NULL
  THEN RAISE EXCEPTION 'Monitoring steps cannot change scope or acquire other entity permissions' USING ERRCODE='23514';END IF;
  IF s.step_order<=native_count THEN
   SELECT * INTO p FROM metrics_setup_plugin_material WHERE intent_id=i.id AND step_order=s.step_order;
   IF p.intent_id IS NULL OR s.kind<>'native' OR s.handler IS NOT NULL OR s.entity_type<>'plugins' OR s.entity_id IS DISTINCT FROM p.native_id
    OR s.step_key IS DISTINCT FROM ('metrics.setup.'||p.name) OR s.mutation_action<>p.action OR s.before_fingerprint<>p.before_hmac OR s.mutation_payload_hmac<>p.payload_hmac
    OR s.mutation_idempotency_key IS DISTINCT FROM ('metrics-approved-'||i.id::text||'-'||p.name) OR jsonb_array_length(s.native_requests)<>1
    OR(s.native_requests->0->>'method') IS DISTINCT FROM (CASE WHEN p.action='create' THEN 'POST' ELSE 'PATCH' END)
    OR(s.native_requests->0->>'native_type') IS DISTINCT FROM 'plugins' OR(s.native_requests->0->>'native_id') IS DISTINCT FROM p.native_id::text
    OR(s.native_requests->0->>'path_hash') IS DISTINCT FROM p.path_hmac OR(s.native_requests->0->>'body_hmac') IS DISTINCT FROM p.payload_hmac
    OR(s.native_requests->0->>'before_hmac') IS DISTINCT FROM p.before_hmac OR(s.native_requests->0->>'parent_id') IS NOT NULL OR(s.native_requests->0->>'credential_kind') IS NOT NULL
   THEN RAISE EXCEPTION 'Monitoring native step must retain its original fixed plugin packet manifest' USING ERRCODE='23514';END IF;
  ELSE
   IF s.kind<>'metadata' OR s.handler IS DISTINCT FROM 'metrics.setup.settings' OR s.entity_type<>'metrics_setup_requests' OR s.entity_id IS DISTINCT FROM i.id
    OR s.step_key<>'metrics.setup.settings' OR s.native_requests<>'[]'::jsonb OR s.operation_id IS NOT NULL OR s.metadata_revision<>i.settings_revision
   THEN RAISE EXCEPTION 'Monitoring final step must remain its zero-native settings CAS' USING ERRCODE='23514';END IF;
  END IF;
  IF s.step_order=1 THEN
   IF s.dependencies<>'{}'::uuid[] THEN RAISE EXCEPTION 'Monitoring first packet cannot have hidden dependencies' USING ERRCODE='23514';END IF;
  ELSIF cardinality(s.dependencies)<>1 OR s.dependencies[1] IS DISTINCT FROM (SELECT id FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=1 AND step_order=s.step_order-1) THEN
   RAISE EXCEPTION 'Monitoring packet order and settings dependency must remain exact' USING ERRCODE='23514';END IF;
 END LOOP;
 IF w.state='succeeded' AND NOT EXISTS(SELECT 1 FROM metrics_setup_completion_facts WHERE intent_id=i.id AND workflow_id=w.id AND plan_hash=w.plan_hash) THEN
  RAISE EXCEPTION 'Monitoring terminal success requires its committed exact completion facts' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER metrics_setup_requests_graph AFTER INSERT ON metrics_setup_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_metrics_setup_graph();
CREATE CONSTRAINT TRIGGER workflows_metrics_setup_graph AFTER INSERT OR UPDATE ON workflows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_metrics_setup_graph();
CREATE CONSTRAINT TRIGGER workflow_steps_metrics_setup_graph AFTER INSERT OR UPDATE ON workflow_steps DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_metrics_setup_graph();
CREATE FUNCTION m11_validate_metrics_setup_completion() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w workflows%ROWTYPE;e workflow_executions%ROWTYPE;s workflow_steps%ROWTYPE;i metrics_setup_intents%ROWTYPE;settings metrics_settings%ROWTYPE;ds data_sources%ROWTYPE;native_count integer;observed uuid[];
BEGIN
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;SELECT * INTO e FROM workflow_executions WHERE id=NEW.execution_id;
 SELECT * INTO s FROM workflow_steps WHERE id=NEW.step_id;SELECT * INTO i FROM metrics_setup_intents WHERE id=NEW.intent_id;
 SELECT * INTO settings FROM metrics_settings WHERE cluster_id=NEW.cluster_id;SELECT * INTO ds FROM data_sources WHERE cluster_id=NEW.cluster_id AND id=i.source_id;
 native_count=(CASE WHEN i.mode='collector' THEN 2 ELSE 1 END);
 SELECT array_agg(m.id ORDER BY ns.step_order) INTO observed FROM workflow_steps ns JOIN mutation_operations m ON m.id=ns.operation_id
  JOIN metrics_setup_plugin_material p ON p.intent_id=i.id AND p.step_order=ns.step_order
  WHERE ns.workflow_id=w.id AND ns.plan_revision=1 AND ns.kind='native' AND ns.state='succeeded' AND ns.plan_hash=NEW.plan_hash
   AND m.workflow_id=w.id AND m.workflow_execution_id=e.id AND m.workflow_step_id=ns.id AND m.workflow_plan_revision=1 AND m.workflow_plan_hash=NEW.plan_hash
   AND m.cluster_id=NEW.cluster_id AND m.workspace_id=NEW.workspace_id AND m.actor_id=NEW.actor_id AND m.entity_type='plugins' AND m.entity_id=p.native_id::text
   AND m.action=p.action AND m.state='succeeded' AND m.remote_started AND m.remote_completed AND m.result_secret IS NOT NULL AND m.payload_secret IS NOT NULL AND m.before_secret IS NOT NULL
   AND m.idempotency_key IS NOT DISTINCT FROM ('metrics-approved-'||i.id::text||'-'||p.name);
 IF w.id IS NULL OR e.id IS NULL OR s.id IS NULL OR i.id IS NULL OR settings.cluster_id IS NULL OR ds.id IS NULL
  OR w.kind<>'metrics-setup' OR w.subject_id<>i.id OR w.subject_type<>'metrics_setup_requests' OR w.state<>'succeeded' OR e.state<>'succeeded' OR s.state<>'succeeded'
  OR w.cluster_id<>NEW.cluster_id OR w.workspace_id<>NEW.workspace_id OR e.cluster_id<>NEW.cluster_id OR e.workspace_id<>NEW.workspace_id OR s.cluster_id<>NEW.cluster_id OR s.workspace_id<>NEW.workspace_id
  OR e.workflow_id<>w.id OR s.workflow_id<>w.id OR e.plan_hash<>NEW.plan_hash OR w.plan_hash<>NEW.plan_hash OR s.plan_hash<>NEW.plan_hash OR e.plan_revision<>1 OR s.plan_revision<>1
  OR e.execution_actor_id<>NEW.actor_id OR NEW.actor_id<>i.actor_id OR NEW.session_id<>i.authoring_session_id OR NEW.material_hmac<>i.material_hmac
  OR e.approval_format<>2 OR e.approval_set_id IS DISTINCT FROM w.approval_set_id OR e.approval_set_hmac IS DISTINCT FROM w.approval_set_hmac
  OR s.kind<>'metadata' OR s.handler IS DISTINCT FROM 'metrics.setup.settings' OR s.entity_type<>'metrics_setup_requests' OR s.entity_id<>i.id OR s.operation_id IS NOT NULL
  OR cardinality(NEW.native_operation_ids)<>native_count OR observed IS DISTINCT FROM NEW.native_operation_ids
  OR NEW.before_settings_revision<>i.settings_revision OR settings.revision<>NEW.after_settings_revision OR settings.credential_generation<>NEW.credential_generation OR NEW.credential_generation<>i.credential_generation
  OR settings.active_source_id IS DISTINCT FROM i.source_id OR NOT settings.enabled OR(i.mode='collector' AND NOT settings.collector_enabled)
  OR NOT ds.enabled OR ds.deleted_at IS NOT NULL OR ds.type<>'prometheus' OR ds.revision<>i.source_revision
 THEN RAISE EXCEPTION 'Monitoring success requires actual acknowledged native packets and the same committed settings CAS' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER metrics_setup_completion_exact AFTER INSERT ON metrics_setup_completion_facts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_metrics_setup_completion();
