-- Candidate, source/unit review only: fixed Consumer + six-credential partial
-- restore evidence. Never alter the original SQL023 seven-node archive, mint a
-- native permit, or manufacture attempts, outcomes or completion receipts.
-- Root's genuine current-source/approval/packet verifier and authenticated
-- historical closure/current GET/Basic custody verifier remain mandatory.
CREATE TABLE entity_change_recycle_restore_present_facts (
 cluster_id uuid NOT NULL,workspace_id uuid NOT NULL,source_id uuid NOT NULL,baseline_id uuid NOT NULL,pin_id uuid NOT NULL,workflow_execution_id uuid NOT NULL,
 entry_id uuid NOT NULL,node_key text NOT NULL,direction text NOT NULL DEFAULT 'restore' CHECK(direction='restore'),
 baseline_object_key text NOT NULL,object_manifest_hmac text NOT NULL CHECK(m8_hex64(object_manifest_hmac)),
 native_type text NOT NULL CHECK(native_type IN('consumers','key-auth','basic-auth','jwt','oauth2')),native_id uuid NOT NULL,parent_id uuid,credential_kind text,
 prior_attempt_id uuid NOT NULL REFERENCES entity_change_recycle_receipts(attempt_id) ON DELETE RESTRICT,
 prior_operation_id uuid NOT NULL,prior_source_id uuid NOT NULL,prior_packet_key text NOT NULL,
 observed_before_hmac text NOT NULL CHECK(m8_hex64(observed_before_hmac)),prior_result_hmac text NOT NULL CHECK(m8_hex64(prior_result_hmac)),
 closed_source_hmac text NOT NULL CHECK(m8_hex64(closed_source_hmac)),fact_hmac text NOT NULL CHECK(m8_hex64(fact_hmac)),
 fact_ciphertext text NOT NULL CHECK(m6_encrypted(fact_ciphertext,6291456)),
 basic_custody_hmac text CHECK(basic_custody_hmac IS NULL OR m8_hex64(basic_custody_hmac)),
 observed_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(source_id,entry_id,node_key),UNIQUE(source_id,baseline_object_key),UNIQUE(source_id,prior_attempt_id),
 FOREIGN KEY(cluster_id,workspace_id,pin_id,baseline_id,source_id,workflow_execution_id)
 REFERENCES entity_change_baseline_pins(cluster_id,workspace_id,id,baseline_id,source_id,workflow_execution_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,entry_id,node_key)
 REFERENCES entity_change_recycle_nodes(cluster_id,workspace_id,entry_id,node_key) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,baseline_id,object_manifest_hmac)
 REFERENCES entity_change_baselines(cluster_id,workspace_id,id,object_manifest_hmac) ON DELETE RESTRICT,
 FOREIGN KEY(baseline_id,baseline_object_key)
 REFERENCES entity_change_baseline_objects(baseline_id,object_key) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,workspace_id,prior_source_id)
 REFERENCES entity_change_execution_sources(cluster_id,workspace_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,prior_operation_id) REFERENCES mutation_operations(cluster_id,id) ON DELETE RESTRICT,
 CHECK(source_id<>prior_source_id AND observed_before_hmac=prior_result_hmac),
 CHECK((native_type='consumers' AND parent_id IS NULL AND credential_kind IS NULL)
  OR(native_type<>'consumers' AND parent_id IS NOT NULL AND credential_kind=native_type)),
 CHECK((native_type='basic-auth')=(basic_custody_hmac IS NOT NULL)),CHECK(observed_at<=created_at)
);
CREATE INDEX entity_change_restore_present_prior ON entity_change_recycle_restore_present_facts(entry_id,prior_source_id);

CREATE FUNCTION m11_validate_recycle_restore_present_fact() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE n entity_change_recycle_nodes%ROWTYPE;archive entity_change_recycle_archives%ROWTYPE;
  b entity_change_baselines%ROWTYPE;object_row entity_change_baseline_objects%ROWTYPE;s entity_change_execution_sources%ROWTYPE;x workflow_executions%ROWTYPE;
  r entity_change_recycle_receipts%ROWTYPE;prior entity_change_execution_sources%ROWTYPE;prior_x workflow_executions%ROWTYPE;prior_w workflows%ROWTYPE;
  p entity_change_recycle_packets%ROWTYPE;attempt entity_change_packet_attempts%ROWTYPE;m mutation_operations%ROWTYPE;outcome_row entity_change_packet_events%ROWTYPE;
 BEGIN
 SELECT * INTO n FROM entity_change_recycle_nodes WHERE entry_id=NEW.entry_id AND node_key=NEW.node_key;
 SELECT * INTO archive FROM entity_change_recycle_archives WHERE entry_id=NEW.entry_id;
 SELECT * INTO b FROM entity_change_baselines WHERE id=NEW.baseline_id;
 SELECT * INTO object_row FROM entity_change_baseline_objects WHERE baseline_id=NEW.baseline_id AND object_key=NEW.baseline_object_key;
 SELECT * INTO s FROM entity_change_execution_sources WHERE id=NEW.source_id;SELECT * INTO x FROM workflow_executions WHERE id=NEW.workflow_execution_id;
 SELECT * INTO r FROM entity_change_recycle_receipts WHERE attempt_id=NEW.prior_attempt_id;
 SELECT * INTO prior FROM entity_change_execution_sources WHERE id=NEW.prior_source_id;
 SELECT * INTO prior_x FROM workflow_executions WHERE id=prior.workflow_execution_id;SELECT * INTO prior_w FROM workflows WHERE id=prior.workflow_id;
 SELECT * INTO p FROM entity_change_recycle_packets WHERE source_id=NEW.prior_source_id AND packet_key=NEW.prior_packet_key;
 SELECT * INTO attempt FROM entity_change_packet_attempts WHERE id=NEW.prior_attempt_id;
 SELECT * INTO m FROM mutation_operations WHERE id=NEW.prior_operation_id;
 SELECT * INTO outcome_row FROM entity_change_packet_events WHERE attempt_id=NEW.prior_attempt_id AND event_kind='outcome';
 IF n.node_key IS NULL OR archive.entry_id IS NULL OR b.id IS NULL OR object_row.object_key IS NULL OR s.id IS NULL OR x.id IS NULL
  OR r.attempt_id IS NULL OR prior.id IS NULL OR prior_x.id IS NULL OR prior_w.id IS NULL OR p.packet_key IS NULL OR attempt.id IS NULL OR m.id IS NULL OR outcome_row.id IS NULL
  OR NOT n.affected OR archive.source_id=NEW.source_id OR archive.source_id=NEW.prior_source_id
  OR s.workflow_execution_id IS DISTINCT FROM NEW.workflow_execution_id OR s.expires_at<=clock_timestamp() OR x.state<>'executing'
  OR ROW(b.cluster_id,b.workspace_id,b.source_id,b.workflow_execution_id,b.object_manifest_hmac)
   IS DISTINCT FROM ROW(NEW.cluster_id,NEW.workspace_id,NEW.source_id,NEW.workflow_execution_id,NEW.object_manifest_hmac)
  OR ROW(n.native_type,n.native_id,n.parent_id,n.credential_kind)
   IS DISTINCT FROM ROW(NEW.native_type,NEW.native_id,NEW.parent_id,NEW.credential_kind)
  OR ROW(object_row.cluster_id,object_row.workspace_id,object_row.object_manifest_hmac,object_row.native_type,object_row.native_id,object_row.parent_id,object_row.credential_kind)
   IS DISTINCT FROM ROW(NEW.cluster_id,NEW.workspace_id,NEW.object_manifest_hmac,NEW.native_type,NEW.native_id,NEW.parent_id,NEW.credential_kind)
  OR NOT object_row.present OR object_row.affected OR object_row.recovery<>'reference' OR object_row.restore_hmac IS NOT NULL
  OR object_row.before_hmac IS DISTINCT FROM NEW.observed_before_hmac OR object_row.dependencies IS DISTINCT FROM n.dependencies
  OR NEW.observed_at<b.observed_from OR NEW.observed_at>b.observed_until
  OR ROW(r.cluster_id,r.workspace_id,r.source_id,r.entry_id,r.node_key,r.packet_key,r.operation_id,r.native_id,r.direction,r.result_hmac)
   IS DISTINCT FROM ROW(NEW.cluster_id,NEW.workspace_id,NEW.prior_source_id,NEW.entry_id,NEW.node_key,NEW.prior_packet_key,NEW.prior_operation_id,NEW.native_id,'restore'::text,NEW.prior_result_hmac)
  OR ROW(p.cluster_id,p.workspace_id,p.baseline_id,p.pin_id,p.workflow_execution_id,p.entry_id,p.node_key,p.native_type,p.native_id,p.parent_id,p.credential_kind,p.direction)
   IS DISTINCT FROM ROW(r.cluster_id,r.workspace_id,r.baseline_id,r.pin_id,r.workflow_execution_id,r.entry_id,r.node_key,NEW.native_type,NEW.native_id,NEW.parent_id,NEW.credential_kind,'restore'::text)
  OR ROW(attempt.cluster_id,attempt.workspace_id,attempt.source_id,attempt.baseline_id,attempt.pin_id,attempt.workflow_execution_id,attempt.packet_key,attempt.native_type,attempt.native_id,attempt.parent_id,attempt.credential_kind)
   IS DISTINCT FROM ROW(r.cluster_id,r.workspace_id,r.source_id,r.baseline_id,r.pin_id,r.workflow_execution_id,r.packet_key,NEW.native_type,NEW.native_id,NEW.parent_id,NEW.credential_kind)
  OR prior.workflow_execution_id IS DISTINCT FROM r.workflow_execution_id OR prior_x.state NOT IN('succeeded','partial','failed') OR prior_w.state NOT IN('succeeded','partial','failed')
  OR prior_x.completed_at IS NULL OR prior_x.completed_at>NEW.observed_at
  OR outcome_row.outcome<>'succeeded' OR outcome_row.native_status<>201
  OR ROW(outcome_row.cluster_id,outcome_row.workspace_id,outcome_row.source_id,outcome_row.baseline_id,outcome_row.pin_id,outcome_row.workflow_execution_id)
   IS DISTINCT FROM ROW(r.cluster_id,r.workspace_id,r.source_id,r.baseline_id,r.pin_id,r.workflow_execution_id)
  OR NOT EXISTS(SELECT 1 FROM entity_change_packet_events sent WHERE sent.attempt_id=NEW.prior_attempt_id AND sent.event_kind='send-intent')
  OR m.state<>'succeeded' OR NOT m.remote_started OR NOT m.remote_completed OR m.result_secret IS NULL
  OR ROW(m.cluster_id,m.workspace_id,m.entity_change_source_id,m.entity_change_baseline_id,m.entity_change_attempt_id,m.entity_change_packet_key,m.idempotency_key,m.actor_id,m.workflow_id)
   IS DISTINCT FROM ROW(r.cluster_id,r.workspace_id,r.source_id,r.baseline_id,r.attempt_id,r.packet_key,r.operation_key,prior.execution_actor_id,prior.workflow_id)
  OR m.action<>'restore' OR m.entity_type IS DISTINCT FROM (CASE WHEN NEW.credential_kind IS NULL THEN NEW.native_type ELSE 'credentials' END)
  OR m.entity_id IS DISTINCT FROM NEW.native_id::text OR m.parent_id IS DISTINCT FROM NEW.parent_id::text OR m.credential_kind IS DISTINCT FROM NEW.credential_kind
 THEN RAISE EXCEPTION 'Observed present restore fact requires its exact current baseline and original acknowledged Native201 receipt from a closed source' USING ERRCODE='23514';END IF;
 -- The keyed HMACs and AEAD facts require Root verification. SQL validates
 -- identity and chronology, never decodes credentials or grants authority.
 RETURN NEW;END;
$$;
CREATE TRIGGER entity_change_restore_present_guard BEFORE INSERT ON entity_change_recycle_restore_present_facts FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_restore_present_fact();

CREATE OR REPLACE FUNCTION m11_validate_recycle_packet_set() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE p entity_change_recycle_packets%ROWTYPE;n entity_change_recycle_nodes%ROWTYPE;a entity_change_recycle_archives%ROWTYPE;
  b entity_change_baselines%ROWTYPE;root_node entity_change_recycle_nodes%ROWTYPE;dep text;ord integer;packet_total integer;present_total integer;prior_source uuid;
 BEGIN
 SELECT * INTO a FROM entity_change_recycle_archives WHERE entry_id=NEW.entry_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Recycle execution requires its immutable archive' USING ERRCODE='23514';END IF;
 SELECT count(*)::integer INTO packet_total FROM entity_change_recycle_packets WHERE source_id=NEW.source_id AND entry_id=NEW.entry_id AND direction=NEW.direction;
 SELECT count(*)::integer INTO present_total FROM entity_change_recycle_restore_present_facts WHERE source_id=NEW.source_id AND entry_id=NEW.entry_id;
 IF NEW.direction='delete' OR present_total=0 THEN
  -- Preserve SQL023 delete and all-missing restore's whole affected set.
  IF packet_total<>a.packet_count OR NEW.direction='delete' AND present_total<>0
  THEN RAISE EXCEPTION 'Recycle execution requires its complete affected packet set before first send' USING ERRCODE='23514';END IF;
 ELSE
  -- This exception is deliberately only the fixed five-success/two-missing
  -- Consumer + six DAO graph. It does not adopt arbitrary live entities.
  SELECT * INTO b FROM entity_change_baselines WHERE id=NEW.baseline_id;
  SELECT * INTO root_node FROM entity_change_recycle_nodes WHERE entry_id=NEW.entry_id AND node_key=a.root_key;
  IF NEW.direction<>'restore' OR packet_total<>2 OR present_total<>5 OR a.node_count<>7 OR a.packet_count<>7
   OR b.id IS NULL OR b.source_id IS DISTINCT FROM NEW.source_id OR b.workflow_execution_id IS DISTINCT FROM NEW.workflow_execution_id OR b.object_count<>7
   OR root_node.native_type<>'consumers' OR root_node.parent_id IS NOT NULL OR cardinality(root_node.dependencies)<>0
   OR(SELECT count(*) FROM entity_change_recycle_nodes WHERE entry_id=a.entry_id)<>7
   OR(SELECT count(DISTINCT native_type) FROM entity_change_recycle_nodes WHERE entry_id=a.entry_id)<>7
   OR EXISTS(SELECT 1 FROM entity_change_recycle_nodes node WHERE node.entry_id=a.entry_id AND(NOT node.affected
    OR node.native_type NOT IN('consumers','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')
    OR node.native_type<>'consumers' AND(node.parent_id IS DISTINCT FROM root_node.native_id OR node.credential_kind IS DISTINCT FROM node.native_type OR node.dependencies IS DISTINCT FROM ARRAY[a.root_key])))
   OR(SELECT count(DISTINCT native_type) FROM entity_change_recycle_packets WHERE source_id=NEW.source_id AND entry_id=a.entry_id)<>2
   OR EXISTS(SELECT 1 FROM entity_change_recycle_packets packet WHERE packet.source_id=NEW.source_id AND packet.entry_id=a.entry_id
    AND(packet.direction<>'restore' OR packet.native_type NOT IN('hmac-auth','acls') OR packet.baseline_id IS DISTINCT FROM NEW.baseline_id OR packet.pin_id IS DISTINCT FROM NEW.pin_id OR packet.workflow_execution_id IS DISTINCT FROM NEW.workflow_execution_id))
   OR(SELECT count(DISTINCT native_type) FROM entity_change_recycle_restore_present_facts WHERE source_id=NEW.source_id AND entry_id=a.entry_id)<>5
   OR(SELECT count(DISTINCT prior_source_id) FROM entity_change_recycle_restore_present_facts WHERE source_id=NEW.source_id AND entry_id=a.entry_id)<>1
   OR EXISTS(SELECT 1 FROM entity_change_recycle_restore_present_facts fact WHERE fact.source_id=NEW.source_id AND fact.entry_id=a.entry_id
    AND(fact.baseline_id IS DISTINCT FROM NEW.baseline_id OR fact.pin_id IS DISTINCT FROM NEW.pin_id OR fact.workflow_execution_id IS DISTINCT FROM NEW.workflow_execution_id))
   OR EXISTS(SELECT 1 FROM entity_change_recycle_packets packet JOIN entity_change_recycle_restore_present_facts fact
    ON fact.source_id=packet.source_id AND fact.entry_id=packet.entry_id AND fact.node_key=packet.node_key WHERE packet.source_id=NEW.source_id AND packet.entry_id=a.entry_id)
   OR EXISTS(SELECT 1 FROM entity_change_recycle_nodes node WHERE node.entry_id=a.entry_id AND node.affected
    AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_packets packet WHERE packet.source_id=NEW.source_id AND packet.entry_id=node.entry_id AND packet.node_key=node.node_key AND packet.direction='restore')
    AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_restore_present_facts fact WHERE fact.source_id=NEW.source_id AND fact.entry_id=node.entry_id AND fact.node_key=node.node_key))
   OR EXISTS(SELECT 1 FROM entity_change_recycle_nodes node WHERE node.entry_id=a.entry_id AND NOT EXISTS(
    SELECT 1 FROM entity_change_baseline_objects object_row WHERE object_row.baseline_id=b.id
     AND ROW(object_row.cluster_id,object_row.workspace_id,object_row.native_type,object_row.native_id,object_row.parent_id,object_row.credential_kind,object_row.dependencies)
      IS NOT DISTINCT FROM ROW(node.cluster_id,node.workspace_id,node.native_type,node.native_id,node.parent_id,node.credential_kind,node.dependencies)
     AND((node.native_type IN('hmac-auth','acls') AND object_row.affected AND NOT object_row.present AND object_row.recovery='absent' AND object_row.restore_hmac IS NULL
       AND EXISTS(SELECT 1 FROM entity_change_recycle_packets packet WHERE packet.source_id=NEW.source_id AND packet.entry_id=node.entry_id AND packet.node_key=node.node_key AND packet.before_hmac=object_row.before_hmac))
      OR(node.native_type IN('consumers','key-auth','basic-auth','jwt','oauth2') AND NOT object_row.affected AND object_row.present AND object_row.recovery='reference' AND object_row.restore_hmac IS NULL
       AND EXISTS(SELECT 1 FROM entity_change_recycle_restore_present_facts fact WHERE fact.source_id=NEW.source_id AND fact.entry_id=node.entry_id AND fact.node_key=node.node_key AND fact.observed_before_hmac=object_row.before_hmac AND fact.prior_result_hmac=object_row.before_hmac)))))
  THEN RAISE EXCEPTION 'Partial restore requires exactly two missing packets and five authentic observed-present facts covering the original seven affected nodes and full baseline' USING ERRCODE='23514';END IF;
  SELECT prior_source_id INTO prior_source FROM entity_change_recycle_restore_present_facts WHERE source_id=NEW.source_id AND entry_id=a.entry_id LIMIT 1;
  -- HMAC has a genuine failed-known-not-sent outcome and closed mutation.
  -- Its original send-intent reservation and remote_started=true are retained;
  -- neither means wire send happened nor justifies inventing a receipt.
  IF NOT EXISTS(SELECT 1 FROM entity_change_recycle_packets historical
    JOIN entity_change_packet_attempts attempt ON attempt.source_id=historical.source_id AND attempt.packet_key=historical.packet_key
    JOIN entity_change_packet_events result ON result.attempt_id=attempt.id AND result.event_kind='outcome'
    JOIN mutation_operations operation ON operation.entity_change_attempt_id=attempt.id
    WHERE historical.source_id=prior_source AND historical.entry_id=a.entry_id AND historical.direction='restore' AND historical.native_type='hmac-auth'
     AND result.outcome='failed-known-not-sent' AND result.native_status IS NULL AND result.error_code IS NOT NULL
     AND EXISTS(SELECT 1 FROM entity_change_packet_events reservation WHERE reservation.attempt_id=attempt.id AND reservation.event_kind='send-intent' AND reservation.observed_at<=result.observed_at)
     AND operation.state='failed' AND operation.remote_started AND NOT operation.remote_completed AND operation.result_secret IS NULL
     AND operation.error_code IS NOT DISTINCT FROM result.error_code
     AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_receipts receipt WHERE receipt.attempt_id=attempt.id))
   OR EXISTS(SELECT 1 FROM entity_change_recycle_packets historical
    LEFT JOIN entity_change_packet_attempts attempt ON attempt.source_id=historical.source_id AND attempt.packet_key=historical.packet_key
    LEFT JOIN mutation_operations operation ON operation.entity_change_source_id=historical.source_id AND operation.entity_change_packet_key=historical.packet_key
    LEFT JOIN entity_change_recycle_receipts receipt ON receipt.source_id=historical.source_id AND receipt.packet_key=historical.packet_key
    WHERE historical.source_id=prior_source AND historical.entry_id=a.entry_id AND historical.native_type='acls'
     AND(attempt.id IS NOT NULL OR operation.id IS NOT NULL OR receipt.attempt_id IS NOT NULL))
   OR NOT EXISTS(SELECT 1 FROM entity_change_recycle_packets historical WHERE historical.source_id=prior_source AND historical.entry_id=a.entry_id AND historical.direction='restore' AND historical.native_type='acls')
   OR EXISTS(SELECT 1 FROM entity_change_packet_events current_result WHERE current_result.source_id=NEW.source_id AND current_result.outcome='sent-unknown')
   OR EXISTS(SELECT 1 FROM entity_change_recycle_packets foreign_packet
    LEFT JOIN entity_change_execution_sources foreign_source ON foreign_source.id=foreign_packet.source_id
    LEFT JOIN workflow_executions foreign_execution ON foreign_execution.id=foreign_source.workflow_execution_id
    LEFT JOIN workflows foreign_workflow ON foreign_workflow.id=foreign_source.workflow_id
    LEFT JOIN entity_change_packet_attempts attempt ON attempt.source_id=foreign_packet.source_id AND attempt.packet_key=foreign_packet.packet_key
    LEFT JOIN entity_change_packet_events result ON result.attempt_id=attempt.id AND result.event_kind='outcome'
    WHERE foreign_packet.entry_id=a.entry_id AND foreign_packet.source_id<>NEW.source_id
     AND(foreign_source.id IS NULL OR foreign_execution.id IS NULL OR foreign_workflow.id IS NULL
      OR foreign_execution.state NOT IN('succeeded','partial','failed') OR foreign_workflow.state NOT IN('succeeded','partial','failed')
      OR result.outcome='sent-unknown' OR attempt.id IS NOT NULL AND result.id IS NULL))
   OR EXISTS(SELECT 1 FROM mutation_operations operation JOIN entity_change_recycle_packets foreign_packet
    ON foreign_packet.source_id=operation.entity_change_source_id AND foreign_packet.packet_key=operation.entity_change_packet_key
    WHERE foreign_packet.entry_id=a.entry_id AND foreign_packet.source_id<>NEW.source_id AND operation.state IN('pending','running','uncertain'))
  THEN RAISE EXCEPTION 'Partial restore requires authenticated closed HMAC no-send, unattempted ACL and no unresolved foreign history' USING ERRCODE='23514';END IF;
 END IF;
 -- Keep the original exact dependency ordering for both execution modes.
 FOR p IN SELECT * FROM entity_change_recycle_packets WHERE source_id=NEW.source_id AND entry_id=NEW.entry_id AND direction=NEW.direction LOOP
  SELECT * INTO n FROM entity_change_recycle_nodes WHERE entry_id=p.entry_id AND node_key=p.node_key;
  FOREACH dep IN ARRAY n.dependencies LOOP
   SELECT parent.packet_order INTO ord FROM entity_change_recycle_packets parent WHERE parent.source_id=p.source_id AND parent.entry_id=p.entry_id AND parent.node_key=dep;
   IF FOUND AND((p.direction='delete' AND ord<=p.packet_order) OR(p.direction='restore' AND ord>=p.packet_order))
   THEN RAISE EXCEPTION 'Delete children must precede parents; restore parents must precede children' USING ERRCODE='23514';END IF;
  END LOOP;
 END LOOP;RETURN NULL;END;
$$;
CREATE CONSTRAINT TRIGGER entity_change_restore_present_packet_set AFTER INSERT ON entity_change_recycle_restore_present_facts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_packet_set();
CREATE TRIGGER entity_change_restore_present_immutable BEFORE UPDATE OR DELETE ON entity_change_recycle_restore_present_facts FOR EACH ROW EXECUTE FUNCTION m8_immutable();
CREATE TRIGGER entity_change_restore_present_no_truncate BEFORE TRUNCATE ON entity_change_recycle_restore_present_facts FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable();
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_recycle_restore_present_facts FROM PUBLIC;
