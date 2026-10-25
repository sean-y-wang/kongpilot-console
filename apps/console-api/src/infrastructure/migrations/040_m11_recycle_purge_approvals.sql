-- Append-only platform migration; never edit already applied SQL000-039.
-- Purge destroys only the selected recovery payload. Immutable archive/node/
-- packet/receipt/control/audit facts and the entry tombstone are retained.
ALTER TABLE recycle_entries ADD COLUMN revision integer NOT NULL DEFAULT 1 CHECK(revision>0);

-- PostgreSQL RR/serializable keep an older transaction snapshot even after
-- waiting for a row-share holder. VOLATILE does not refresh that snapshot.
-- This write protocol is deliberately read-committed only; reject, never
-- silently change the caller's transaction or infer a serialization failure.
CREATE FUNCTION m11_require_recycle_read_committed() RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$BEGIN
 IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN
  RAISE EXCEPTION 'Recovery payload reference/purge writes require read committed isolation' USING ERRCODE='25001';END IF;
END;$$;

CREATE TABLE entity_change_recycle_payload_references(
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,intent_id uuid NOT NULL,intent_revision integer NOT NULL,
 material_hmac text NOT NULL CHECK(m8_hex64(material_hmac)),change_digest text NOT NULL CHECK(m8_hex64(change_digest)),
 packet_manifest_hmac text NOT NULL CHECK(m8_hex64(packet_manifest_hmac)),entry_id uuid NOT NULL,
 entry_revision integer NOT NULL CHECK(entry_revision>0),payload_hmac text NOT NULL CHECK(m8_hex64(payload_hmac)),graph_hmac text NOT NULL CHECK(m8_hex64(graph_hmac)),
 created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(intent_id,intent_revision,entry_id),
 FOREIGN KEY(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac)
  REFERENCES entity_change_intent_versions(cluster_id,workspace_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,entry_id) REFERENCES recycle_entries(cluster_id,workspace_id,id) ON DELETE RESTRICT
);
CREATE INDEX entity_change_recycle_payload_references_entry ON entity_change_recycle_payload_references(entry_id,intent_id,intent_revision);
CREATE FUNCTION m11_validate_recycle_payload_reference() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE r recycle_entries%ROWTYPE;BEGIN
 PERFORM m11_require_recycle_read_committed();
 SELECT * INTO r FROM recycle_entries WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id AND id=NEW.entry_id FOR SHARE;
 IF r.id IS NULL OR r.state='purged' OR r.payload_secret IS NULL OR r.revision IS DISTINCT FROM NEW.entry_revision THEN
  RAISE EXCEPTION 'Recovery reference requires its exact original available source revision' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;$$;
CREATE TRIGGER recycle_payload_reference_original BEFORE INSERT ON entity_change_recycle_payload_references FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_payload_reference();
CREATE TRIGGER recycle_payload_reference_immutable BEFORE UPDATE OR DELETE ON entity_change_recycle_payload_references FOR EACH ROW EXECUTE FUNCTION m8_immutable();
CREATE TRIGGER recycle_payload_reference_no_truncate BEFORE TRUNCATE ON entity_change_recycle_payload_references FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_recycle_payload_references FROM PUBLIC;

-- A common row lock orders a new restoration/configuration reference against
-- destruction of its source payload. Runtime has no DDL/owner privilege.
CREATE FUNCTION m11_recycle_purge_available(p_cluster uuid,p_entry uuid) RETURNS boolean LANGUAGE sql VOLATILE SET search_path = pg_catalog, public, pg_temp AS $$
 SELECT current_setting('transaction_isolation')='read committed' AND EXISTS(SELECT 1 FROM recycle_entries r WHERE r.cluster_id=p_cluster AND r.id=p_entry
  AND r.workspace_id IS NOT NULL AND r.payload_secret IS NOT NULL AND r.purged_at IS NULL AND r.state IN('deleted','restored')
  AND NOT EXISTS(SELECT 1 FROM recycle_nodes n WHERE n.entry_id=r.id AND n.affected
   AND ((r.state='deleted' AND n.delete_state<>'deleted') OR(r.state='restored' AND n.restore_state<>'restored')))
  AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_archives a WHERE a.entry_id=r.id AND m11_entity_baseline_pin_active(a.baseline_id))
  AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_packets p WHERE p.entry_id=r.id AND m11_entity_baseline_pin_active(p.baseline_id))
  AND NOT EXISTS(SELECT 1 FROM mutation_operations m WHERE m.id=r.mutation_id AND(m.state IN('pending','running','uncertain') OR(m.remote_started AND NOT m.remote_completed)))
  AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_packets p JOIN entity_change_execution_sources s ON s.id=p.source_id
   JOIN workflow_executions e ON e.id=s.workflow_execution_id WHERE p.entry_id=r.id AND e.state NOT IN('succeeded','partial','failed'))
  AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_packets p JOIN mutation_operations m ON m.entity_change_source_id=p.source_id AND m.entity_change_packet_key=p.packet_key
   WHERE p.entry_id=r.id AND(m.state IN('pending','running','uncertain') OR(m.remote_started AND NOT m.remote_completed)))
  AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_packets p JOIN entity_change_packet_attempts a ON a.source_id=p.source_id AND a.packet_key=p.packet_key
   LEFT JOIN entity_change_packet_events o ON o.attempt_id=a.id AND o.event_kind='outcome'
   WHERE p.entry_id=r.id AND (o.id IS NULL OR o.outcome='sent-unknown'))
  AND NOT EXISTS(SELECT 1 FROM configuration_recycle_graphs g JOIN configuration_jobs j ON j.id=g.job_id
   JOIN configuration_executions e ON e.id=g.execution_id WHERE
    (g.recycle_entry_id=r.id OR EXISTS(SELECT 1 FROM configuration_recycle_components c WHERE c.graph_id=g.id AND c.recycle_entry_id=r.id))
    AND(j.state IN('pending','running','waiting_approval','uncertain') OR e.state IN('claimed','executing','uncertain')))
  AND NOT EXISTS(SELECT 1 FROM configuration_job_steps s WHERE s.recycle_entry_id=r.id AND s.state IN('pending','running','uncertain'))
  AND NOT EXISTS(SELECT 1 FROM configuration_job_steps s JOIN configuration_jobs j ON j.id=s.job_id
   JOIN configuration_executions e ON e.id=s.execution_id WHERE s.recycle_entry_id=r.id
    AND(j.state IN('pending','running','waiting_approval','uncertain') OR e.state IN('claimed','executing','uncertain')))
  AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_payload_references ref JOIN entity_change_intents i ON i.id=ref.intent_id
   LEFT JOIN entity_change_submissions sub ON sub.intent_id=i.id AND sub.intent_revision=ref.intent_revision LEFT JOIN workflows w ON w.id=sub.workflow_id
   WHERE ref.entry_id=r.id AND((w.id IS NULL AND i.expires_at>now()) OR(w.state IN('pending','approved') AND w.expires_at>now()) OR w.state IN('executing','uncertain')))
  AND NOT EXISTS(SELECT 1 FROM entity_change_intent_packets p JOIN entity_change_intents i ON i.id=p.intent_id
   LEFT JOIN entity_change_submissions sub ON sub.intent_id=i.id AND sub.intent_revision=p.intent_revision
   LEFT JOIN workflows w ON w.id=sub.workflow_id
   JOIN recycle_nodes n ON n.entry_id=r.id AND n.entity_type=p.native_type AND n.original_id=coalesce(p.original_native_id,p.native_id)::text
   WHERE p.cluster_id=r.cluster_id AND p.mutation_action='restore' AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_payload_references exact WHERE exact.intent_id=p.intent_id AND exact.intent_revision=p.intent_revision)
    AND((w.id IS NULL AND i.expires_at>now()) OR(w.state IN('pending','approved') AND w.expires_at>now()) OR w.state IN('executing','uncertain')))
 );
$$;

CREATE FUNCTION m11_recycle_entry_version_and_tombstone() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$BEGIN
 IF OLD.state='purged' THEN RAISE EXCEPTION 'Purged recovery tombstone cannot be changed or resurrected' USING ERRCODE='23514';END IF;
 IF NEW.revision NOT IN(OLD.revision,OLD.revision+1) THEN RAISE EXCEPTION 'Recovery revision must advance exactly once' USING ERRCODE='23514';END IF;
 IF NEW.payload_secret IS NULL AND OLD.payload_secret IS NOT NULL THEN
  PERFORM m11_require_recycle_read_committed();
  IF NEW.state<>'purged' OR NEW.purged_at IS NULL OR NOT m11_recycle_purge_available(OLD.cluster_id,OLD.id) THEN
   RAISE EXCEPTION 'Recovery payload still has an unresolved or active owner' USING ERRCODE='23514';END IF;
 END IF;
 NEW.revision=OLD.revision+1;RETURN NEW;
END;$$;
CREATE TRIGGER recycle_entry_version_and_tombstone BEFORE UPDATE ON recycle_entries FOR EACH ROW EXECUTE FUNCTION m11_recycle_entry_version_and_tombstone();
CREATE TRIGGER recycle_entry_no_delete BEFORE DELETE ON recycle_entries FOR EACH ROW EXECUTE FUNCTION m8_immutable();
CREATE TRIGGER recycle_entry_no_truncate BEFORE TRUNCATE ON recycle_entries FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();

CREATE FUNCTION m11_recycle_reference_payload_lock() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE r recycle_entries%ROWTYPE;entry uuid;cid uuid;BEGIN
 IF TG_TABLE_NAME='entity_change_recycle_packets' THEN entry=NEW.entry_id;cid=NEW.cluster_id;
 ELSE entry=NEW.recycle_entry_id;cid=NEW.cluster_id;END IF;
 IF entry IS NULL THEN RETURN NEW;END IF;
 PERFORM m11_require_recycle_read_committed();
 SELECT * INTO r FROM recycle_entries WHERE cluster_id=cid AND id=entry FOR SHARE;
 IF r.id IS NULL OR r.state='purged' OR r.payload_secret IS NULL THEN
  RAISE EXCEPTION 'A new recovery reference cannot adopt a purged source' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;$$;
CREATE TRIGGER recycle_packet_payload_lock BEFORE INSERT ON entity_change_recycle_packets FOR EACH ROW EXECUTE FUNCTION m11_recycle_reference_payload_lock();
CREATE TRIGGER configuration_recycle_graph_payload_lock BEFORE INSERT ON configuration_recycle_graphs FOR EACH ROW EXECUTE FUNCTION m11_recycle_reference_payload_lock();
CREATE TRIGGER configuration_recycle_component_payload_lock BEFORE INSERT ON configuration_recycle_components FOR EACH ROW EXECUTE FUNCTION m11_recycle_reference_payload_lock();
CREATE TRIGGER configuration_step_recycle_payload_lock BEFORE INSERT OR UPDATE ON configuration_job_steps FOR EACH ROW EXECUTE FUNCTION m11_recycle_reference_payload_lock();

CREATE FUNCTION m11_recycle_restore_intent_payload_lock() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE ref entity_change_recycle_payload_references%ROWTYPE;r recycle_entries%ROWTYPE;BEGIN
 IF NEW.mutation_action<>'restore' THEN RETURN NEW;END IF;
 PERFORM m11_require_recycle_read_committed();
 FOR ref IN SELECT * FROM entity_change_recycle_payload_references WHERE cluster_id=NEW.cluster_id AND workspace_id=NEW.workspace_id
  AND intent_id=NEW.intent_id AND intent_revision=NEW.intent_revision ORDER BY entry_id LOOP
  SELECT * INTO r FROM recycle_entries WHERE cluster_id=ref.cluster_id AND id=ref.entry_id FOR SHARE;
  IF r.id IS NULL OR r.state='purged' OR r.payload_secret IS NULL OR r.revision<>ref.entry_revision THEN
   RAISE EXCEPTION 'Restoration packet requires its exact original available payload' USING ERRCODE='23514';END IF;
 END LOOP;
 IF NOT FOUND THEN RAISE EXCEPTION 'Restoration packet requires its exact immutable source reference' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;$$;
CREATE TRIGGER restore_intent_recycle_payload_lock BEFORE INSERT ON entity_change_intent_packets FOR EACH ROW EXECUTE FUNCTION m11_recycle_restore_intent_payload_lock();

-- Replace only the narrow old resource/operation discriminants. All identity,
-- FK, before-version and immutable-fact constraints remain in place.
DO $$DECLARE tab text;c record;n integer;BEGIN
 FOREACH tab IN ARRAY ARRAY['control_change_intents','control_workflow_mutation_facts'] LOOP
  n=0;
  FOR c IN SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid=tab::regclass AND contype='c' LOOP
   IF c.definition ~ '\mresource\M' OR(c.definition ~ '\moperation\M' AND c.definition !~ '\mbefore_revision\M') THEN
    EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I',tab,c.conname);n=n+1;
   END IF;
  END LOOP;
  IF n<>(CASE WHEN tab='control_change_intents' THEN 3 ELSE 2 END) THEN RAISE EXCEPTION 'Unexpected pre040 control discriminants';END IF;
  EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK(resource IN(''clusters'',''data-sources'',''workspaces'',''recycle-bin''))',tab,tab||'_resource_040');
  EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK(operation IN(''create'',''update'',''deactivate'',''archive'',''restore'',''purge''))',tab,tab||'_operation_040');
 END LOOP;
END;$$;
ALTER TABLE control_change_intents ADD CONSTRAINT control_change_intents_resource_operation_040 CHECK(
 (resource='clusters' AND resource_id=cluster_id AND operation IN('update','deactivate'))
 OR(resource='data-sources' AND operation IN('create','update','deactivate'))
 OR(resource='workspaces' AND operation IN('create','update','archive','restore'))
 OR(resource='recycle-bin' AND operation='purge'));

CREATE OR REPLACE FUNCTION m11_validate_control_intent_author() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE u users%ROWTYPE;s auth_sessions%ROWTYPE;c clusters%ROWTYPE;anchor workspaces%ROWTYPE;ds data_sources%ROWTYPE;target workspaces%ROWTYPE;epoch bigint;r recycle_entries%ROWTYPE;
BEGIN
 SELECT * INTO u FROM users WHERE id=NEW.actor_id;SELECT * INTO s FROM auth_sessions WHERE id=NEW.authoring_session_id;
 SELECT * INTO c FROM clusters WHERE id=NEW.cluster_id;SELECT * INTO anchor FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=NEW.workspace_id;
 SELECT version INTO epoch FROM iam_epoch WHERE singleton=true;
 IF u.id IS NULL OR s.id IS NULL OR c.id IS NULL OR anchor.id IS NULL OR epoch IS NULL OR u.status<>'active' OR u.deleted_at IS NOT NULL OR u.force_password_change
  OR s.user_id IS DISTINCT FROM u.id OR s.revoked_at IS NOT NULL OR s.expires_at<=now() OR s.credential_epoch IS DISTINCT FROM u.credential_epoch
  OR NEW.credential_epoch IS DISTINCT FROM u.credential_epoch OR NEW.expires_at>s.expires_at OR NEW.issued_at>now()
  OR NEW.permission_version IS DISTINCT FROM (u.id::text||':'||u.permissions_epoch::text||':'||epoch::text)
  OR c.deleted_at IS NOT NULL OR c.status='disabled' OR c.execution_mode<>'approval' OR anchor.status<>'active' OR anchor.deleted_at IS NOT NULL
 THEN RAISE EXCEPTION 'Control intention requires its genuine current original author and existing approval scope' USING ERRCODE='23514';END IF;
 IF NEW.resource='clusters' THEN
  IF NEW.resource_id IS DISTINCT FROM c.id OR NEW.before_revision IS DISTINCT FROM c.revision THEN
   RAISE EXCEPTION 'Cluster intention must freeze its actual original configuration revision' USING ERRCODE='23514';END IF;
 ELSIF NEW.resource='data-sources' THEN
  SELECT * INTO ds FROM data_sources WHERE cluster_id=c.id AND id=NEW.resource_id;
  IF (NEW.operation='create' AND ds.id IS NOT NULL)
   OR(NEW.operation<>'create' AND(ds.id IS NULL OR ds.deleted_at IS NOT NULL OR ds.revision IS DISTINCT FROM NEW.before_revision)) THEN
   RAISE EXCEPTION 'Data source intention must freeze its actual original object or genuine absence' USING ERRCODE='23514';END IF;
 ELSIF NEW.resource='recycle-bin' THEN
  PERFORM m11_require_recycle_read_committed();
  SELECT * INTO r FROM recycle_entries WHERE cluster_id=c.id AND id=NEW.resource_id FOR SHARE;
  IF NEW.operation<>'purge' OR r.id IS NULL OR r.revision IS DISTINCT FROM NEW.before_revision
   OR NOT m11_recycle_purge_available(c.id,r.id) THEN
   RAISE EXCEPTION 'Purge intention must freeze an actual available terminal recovery entry' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO target FROM workspaces WHERE cluster_id=c.id AND id=NEW.resource_id;
  IF (NEW.operation='create' AND target.id IS NOT NULL)
   OR(NEW.operation<>'create' AND(target.id IS NULL OR target.revision IS DISTINCT FROM NEW.before_revision))
   OR(NEW.operation IN('update','archive') AND(target.deleted_at IS NOT NULL OR target.status='deleted'))
   OR(NEW.operation='restore' AND(target.deleted_at IS NULL OR target.status IS DISTINCT FROM 'deleted'))
   OR(NEW.operation='archive' AND target.is_default) THEN
   RAISE EXCEPTION 'Workspace intention must freeze its actual original live or archived object' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END;$$;

CREATE OR REPLACE FUNCTION m11_validate_control_workflow_graph() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE w workflows%ROWTYPE;r control_metadata_requests%ROWTYPE;i control_change_intents%ROWTYPE;s workflow_steps%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='control_metadata_requests' OR TG_TABLE_NAME='workflow_steps' THEN SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;
 ELSE SELECT * INTO w FROM workflows WHERE id=NEW.id;END IF;
 IF NOT FOUND THEN RETURN NULL;END IF;
 IF w.kind<>'control-metadata' THEN
  IF w.subject_type='control_metadata_requests' OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=w.id AND handler='control.metadata') THEN
   RAISE EXCEPTION 'Control metadata requires its dedicated zero-native kind' USING ERRCODE='23514';END IF;RETURN NULL;
 END IF;
 SELECT * INTO r FROM control_metadata_requests WHERE id=w.subject_id AND cluster_id=w.cluster_id AND workspace_id=w.workspace_id AND workflow_id=w.id;
 SELECT * INTO i FROM control_change_intents WHERE id=r.id;SELECT * INTO s FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision;
 IF r.id IS NULL OR i.id IS NULL OR s.id IS NULL OR i.actor_id IS DISTINCT FROM r.actor_id OR i.workflow_id IS DISTINCT FROM w.id
  OR i.material_hmac IS DISTINCT FROM r.material_hmac OR i.request_hmac IS DISTINCT FROM r.request_hmac OR i.cluster_id IS DISTINCT FROM w.cluster_id OR i.workspace_id IS DISTINCT FROM w.workspace_id
  OR w.subject_type IS DISTINCT FROM 'control_metadata_requests' OR w.requester_type IS DISTINCT FROM 'console' OR w.requester_user_id IS DISTINCT FROM i.actor_id
  OR r.idempotency_key IS DISTINCT FROM ('control-'||i.id::text) OR w.idempotency_key IS DISTINCT FROM r.idempotency_key
  OR w.execution_mode IS DISTINCT FROM 'approval' OR NOT w.approval_required OR w.approval_format IS DISTINCT FROM 2 OR w.plan_revision<=0 OR w.expires_at IS DISTINCT FROM i.expires_at
  OR(SELECT count(*) FROM workflow_steps WHERE workflow_id=w.id AND plan_revision=w.plan_revision)<>1
  OR EXISTS(SELECT 1 FROM workflow_steps historical WHERE historical.workflow_id=w.id AND(historical.kind IS DISTINCT FROM 'metadata'
   OR historical.handler IS DISTINCT FROM 'control.metadata' OR historical.native_requests IS DISTINCT FROM '[]'::jsonb OR historical.operation_id IS NOT NULL))
  OR s.kind IS DISTINCT FROM 'metadata' OR s.handler IS DISTINCT FROM 'control.metadata'
  OR s.entity_type IS DISTINCT FROM 'control_metadata_requests' OR s.entity_id IS DISTINCT FROM i.id OR s.step_key IS DISTINCT FROM 'control.metadata' OR s.step_order IS DISTINCT FROM 1
  OR s.dependencies IS DISTINCT FROM '{}'::uuid[] OR s.native_requests IS DISTINCT FROM '[]'::jsonb OR s.operation_id IS NOT NULL OR s.parent_id IS NOT NULL OR s.credential_kind IS NOT NULL
  OR s.cluster_id IS DISTINCT FROM w.cluster_id OR s.workspace_id IS DISTINCT FROM w.workspace_id OR s.plan_hash IS DISTINCT FROM w.plan_hash OR s.plan_revision IS DISTINCT FROM w.plan_revision
  OR s.execution_mode IS DISTINCT FROM 'approval' OR NOT s.approval_required OR s.metadata_revision IS DISTINCT FROM i.before_revision OR s.metadata_before_hmac IS DISTINCT FROM i.before_config_hmac
  OR s.permission_action IS DISTINCT FROM (CASE WHEN i.operation IN('deactivate','archive','purge') THEN 'delete' ELSE 'write' END)
 THEN RAISE EXCEPTION 'Control workflow must bind its immutable intention and exact V2 metadata step' USING ERRCODE='23514';END IF;
 IF w.state='succeeded' AND NOT EXISTS(SELECT 1 FROM control_workflow_mutation_facts f WHERE f.intent_id=i.id AND f.workflow_id=w.id AND f.step_id=s.id
  AND f.plan_hash=w.plan_hash AND f.plan_revision=w.plan_revision AND f.actor_id=i.actor_id AND f.session_id=i.authoring_session_id AND s.state='succeeded') THEN
  RAISE EXCEPTION 'Control terminal workflow requires its committed exact mutation receipt' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;

CREATE OR REPLACE FUNCTION m11_validate_control_mutation_fact() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE w workflows%ROWTYPE;e workflow_executions%ROWTYPE;s workflow_steps%ROWTYPE;i control_change_intents%ROWTYPE;a audit_events%ROWTYPE;
 c clusters%ROWTYPE;anchor workspaces%ROWTYPE;target workspaces%ROWTYPE;ds data_sources%ROWTYPE;author users%ROWTYPE;sid auth_sessions%ROWTYPE;epoch bigint;r recycle_entries%ROWTYPE;
BEGIN
 SELECT * INTO w FROM workflows WHERE id=NEW.workflow_id;SELECT * INTO e FROM workflow_executions WHERE id=NEW.execution_id;
 SELECT * INTO s FROM workflow_steps WHERE id=NEW.step_id;SELECT * INTO i FROM control_change_intents WHERE id=NEW.intent_id;
 SELECT * INTO a FROM audit_events WHERE id=NEW.audit_id;SELECT * INTO c FROM clusters WHERE id=NEW.cluster_id;
 SELECT * INTO anchor FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=NEW.workspace_id;
 SELECT * INTO author FROM users WHERE id=NEW.actor_id;SELECT * INTO sid FROM auth_sessions WHERE id=NEW.session_id;SELECT version INTO epoch FROM iam_epoch WHERE singleton=true;
 IF w.id IS NULL OR e.id IS NULL OR s.id IS NULL OR i.id IS NULL OR a.id IS NULL OR c.id IS NULL OR anchor.id IS NULL OR author.id IS NULL OR sid.id IS NULL OR epoch IS NULL
  OR w.kind IS DISTINCT FROM 'control-metadata' OR w.subject_type IS DISTINCT FROM 'control_metadata_requests' OR w.subject_id IS DISTINCT FROM i.id
  OR w.state IS DISTINCT FROM 'succeeded' OR e.state IS DISTINCT FROM 'succeeded' OR s.state IS DISTINCT FROM 'succeeded'
  OR e.workflow_id IS DISTINCT FROM w.id OR s.workflow_id IS DISTINCT FROM w.id OR w.cluster_id IS DISTINCT FROM NEW.cluster_id OR w.workspace_id IS DISTINCT FROM NEW.workspace_id
  OR e.cluster_id IS DISTINCT FROM NEW.cluster_id OR e.workspace_id IS DISTINCT FROM NEW.workspace_id OR s.cluster_id IS DISTINCT FROM NEW.cluster_id OR s.workspace_id IS DISTINCT FROM NEW.workspace_id
  OR w.plan_hash IS DISTINCT FROM NEW.plan_hash OR e.plan_hash IS DISTINCT FROM NEW.plan_hash OR s.plan_hash IS DISTINCT FROM NEW.plan_hash
  OR w.plan_revision IS DISTINCT FROM NEW.plan_revision OR e.plan_revision IS DISTINCT FROM NEW.plan_revision OR s.plan_revision IS DISTINCT FROM NEW.plan_revision
  OR e.execution_actor_id IS DISTINCT FROM NEW.actor_id OR NEW.actor_id IS DISTINCT FROM i.actor_id OR NEW.session_id IS DISTINCT FROM i.authoring_session_id
  OR e.approval_format IS DISTINCT FROM 2 OR w.approval_format IS DISTINCT FROM 2 OR e.execution_mode IS DISTINCT FROM 'approval' OR NOT e.approval_required
  OR e.approval_set_id IS NULL OR e.approval_set_hmac IS NULL OR e.approval_set_id IS DISTINCT FROM w.approval_set_id OR e.approval_set_hmac IS DISTINCT FROM w.approval_set_hmac
  OR s.kind IS DISTINCT FROM 'metadata' OR s.handler IS DISTINCT FROM 'control.metadata' OR s.native_requests IS DISTINCT FROM '[]'::jsonb OR s.operation_id IS NOT NULL
  OR i.cluster_id IS DISTINCT FROM NEW.cluster_id OR i.workspace_id IS DISTINCT FROM NEW.workspace_id OR i.workflow_id IS DISTINCT FROM w.id
  OR i.resource IS DISTINCT FROM NEW.resource OR i.resource_id IS DISTINCT FROM NEW.resource_id OR i.operation IS DISTINCT FROM NEW.operation
  OR i.before_revision IS DISTINCT FROM NEW.before_revision OR i.before_config_hmac IS DISTINCT FROM NEW.before_config_hmac
  OR i.permission_version IS DISTINCT FROM NEW.before_permission_version OR NEW.after_permission_version IS DISTINCT FROM (author.id::text||':'||author.permissions_epoch::text||':'||epoch::text)
  OR author.status<>'active' OR author.deleted_at IS NOT NULL OR author.force_password_change OR sid.user_id IS DISTINCT FROM author.id OR sid.revoked_at IS NOT NULL OR sid.expires_at<=now()
  OR sid.credential_epoch IS DISTINCT FROM author.credential_epoch OR i.credential_epoch IS DISTINCT FROM author.credential_epoch
  OR a.actor_id IS DISTINCT FROM NEW.actor_id OR a.actor_type IS DISTINCT FROM 'user' OR a.cluster_id IS DISTINCT FROM NEW.cluster_id OR a.workspace_id IS DISTINCT FROM NEW.workspace_id
  OR a.workflow_id IS DISTINCT FROM NEW.workflow_id OR a.entity_type IS DISTINCT FROM NEW.resource OR a.entity_id IS DISTINCT FROM NEW.resource_id::text
  OR a.action IS DISTINCT FROM 'control.metadata' OR a.result IS DISTINCT FROM 'success'
 THEN RAISE EXCEPTION 'Control mutation fact must retain its exact completed original metadata transaction and audit' USING ERRCODE='23514';END IF;
 IF NEW.resource='clusters' THEN
  IF NEW.resource_id IS DISTINCT FROM c.id OR c.revision IS DISTINCT FROM NEW.after_revision
   OR(NEW.operation='update' AND c.deleted_at IS NOT NULL)
   OR(NEW.operation='deactivate' AND(c.deleted_at IS NULL OR c.status IS DISTINCT FROM 'disabled')) THEN
   RAISE EXCEPTION 'Cluster completion requires its actual original update or soft deactivation' USING ERRCODE='23514';END IF;
 ELSE
  IF c.deleted_at IS NOT NULL OR c.status='disabled' OR c.execution_mode IS DISTINCT FROM 'approval' THEN
   RAISE EXCEPTION 'Non-cluster completion cannot change its original cluster registry' USING ERRCODE='23514';END IF;
  IF NEW.resource='data-sources' THEN
   SELECT * INTO ds FROM data_sources WHERE cluster_id=NEW.cluster_id AND id=NEW.resource_id;
   IF ds.id IS NULL OR ds.revision IS DISTINCT FROM NEW.after_revision
    OR(NEW.operation IN('create','update') AND ds.deleted_at IS NOT NULL)
    OR(NEW.operation='deactivate' AND(ds.deleted_at IS NULL OR ds.enabled)) THEN
    RAISE EXCEPTION 'Data source completion requires its actual original write or soft deactivation' USING ERRCODE='23514';END IF;
  ELSIF NEW.resource='recycle-bin' THEN
   PERFORM m11_require_recycle_read_committed();
   SELECT * INTO r FROM recycle_entries WHERE cluster_id=NEW.cluster_id AND id=NEW.resource_id;
   IF NEW.operation<>'purge' OR r.id IS NULL OR r.revision IS DISTINCT FROM NEW.after_revision
    OR r.state IS DISTINCT FROM 'purged' OR r.payload_secret IS NOT NULL OR r.purged_at IS NULL THEN
    RAISE EXCEPTION 'Purge completion requires its exact versioned payload tombstone' USING ERRCODE='23514';END IF;
  ELSE
   SELECT * INTO target FROM workspaces WHERE cluster_id=NEW.cluster_id AND id=NEW.resource_id;
   IF target.id IS NULL OR target.revision IS DISTINCT FROM NEW.after_revision
    OR(NEW.operation IN('create','restore') AND(target.status IS DISTINCT FROM 'active' OR target.deleted_at IS NOT NULL OR target.retention_until IS NOT NULL))
    OR(NEW.operation='update' AND(target.status NOT IN('active','disabled') OR target.deleted_at IS NOT NULL))
    OR(NEW.operation='archive' AND(target.status IS DISTINCT FROM 'deleted' OR target.deleted_at IS NULL OR target.retention_until IS NULL OR target.is_default)) THEN
    RAISE EXCEPTION 'Workspace completion requires its actual original create update archive or restore' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 IF NOT(NEW.resource='workspaces' AND NEW.resource_id=NEW.workspace_id AND NEW.operation IN('update','archive'))
  AND(anchor.status<>'active' OR anchor.deleted_at IS NOT NULL) THEN
  RAISE EXCEPTION 'Control completion cannot change an unrelated authorization workspace' USING ERRCODE='23514';END IF;RETURN NULL;
END;$$;

-- A runtime UPDATE cannot substitute for the approved transaction on an
-- approval cluster. The existing deferred fact validator verifies W/E/step,
-- original actor/SID, current V2 approval set, versions and append-only audit.
CREATE FUNCTION m11_recycle_purge_approval_complete() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$BEGIN
 IF NEW.state='purged' AND OLD.state<>'purged' THEN PERFORM m11_require_recycle_read_committed();END IF;
 IF NEW.state='purged' AND OLD.state<>'purged' AND EXISTS(SELECT 1 FROM clusters WHERE id=NEW.cluster_id AND execution_mode='approval')
  AND NOT EXISTS(SELECT 1 FROM control_workflow_mutation_facts f JOIN control_change_intents i ON i.id=f.intent_id
   WHERE f.cluster_id=NEW.cluster_id AND f.resource='recycle-bin' AND f.resource_id=NEW.id AND f.operation='purge'
    AND f.before_revision=OLD.revision AND f.after_revision=NEW.revision AND i.resource=f.resource AND i.resource_id=f.resource_id AND i.operation=f.operation)
 THEN RAISE EXCEPTION 'Purge requires its original committed approval mutation fact' USING ERRCODE='23514';END IF;
 RETURN NULL;
END;$$;
CREATE CONSTRAINT TRIGGER recycle_purge_approval_complete AFTER UPDATE ON recycle_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_recycle_purge_approval_complete();
