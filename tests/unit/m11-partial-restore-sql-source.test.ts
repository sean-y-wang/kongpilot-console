import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const directory = resolve(process.cwd(), 'apps/console-api/src/infrastructure/migrations');
const sql = readFileSync(resolve(directory, '025_m11_partial_recycle_restore.sql'), 'utf8');
const code = sql.replace(/--[^\n]*/g, '').replace(/\s+/g, ' ').trim();
const table = code.slice(code.indexOf('CREATE TABLE'), code.indexOf('CREATE INDEX'));
function functionBody(name: string): string {
  const start = code.indexOf(`FUNCTION ${name}()`);
  if (start < 0) throw new Error(`Missing SQL function ${name}`);
  const opening = code.indexOf('AS $$', start);
  const closing = code.indexOf('$$;', opening + 5);
  if (opening < 0 || closing < 0) throw new Error(`Unclosed SQL function ${name}`);
  return code.slice(opening + 5, closing);
}
const factGuard = functionBody('m11_validate_recycle_restore_present_fact');
const packetSet = functionBody('m11_validate_recycle_packet_set');
const fixedBranch = packetSet.slice(packetSet.indexOf(' ELSE '), packetSet.indexOf(' FOR p IN SELECT'));

/** Static source contracts only. These assertions do not execute DDL, trial a
 * rollback, prove runtime admission or inspect any existing private evidence. */
describe('SQL025 partial restore candidate source contracts (no database execution)', () => {
  it('keeps the historical baseline and seven-node archive migration bytes unchanged', () => {
    const digests = [
      ['021_m11_entity_execution_facts.sql', '133756b722dae11085d20e1a419378e821fcae0c66e7a721350344e63b4a2956'],
      ['023_m11_entity_recycle_facts.sql', '9960455dd685da0e528f9f6f2280a4a18b80e812090182742341b9e831ea36eb'],
    ];
    for (const [name, digest] of digests) {
      expect(createHash('sha256').update(readFileSync(resolve(directory, name))).digest('hex')).toBe(digest);
    }
    expect(code).not.toMatch(/\bALTER TABLE\b|\bUPDATE\s+(?:entity_change_|recycle_|workflow_|mutation_)/i);
    expect(code.match(/CREATE (?:OR REPLACE )?FUNCTION /g)).toHaveLength(2);
    expect(code).not.toContain('FUNCTION m11_validate_recycle_receipt(');
    expect(code).not.toContain('FUNCTION m11_guard_recycle_node_projection(');
  });

  it('stores observation evidence with exact current and original identities, keyed digests and encrypted material', () => {
    for (const field of [
      'cluster_id uuid NOT NULL', 'workspace_id uuid NOT NULL', 'source_id uuid NOT NULL', 'baseline_id uuid NOT NULL',
      'pin_id uuid NOT NULL', 'workflow_execution_id uuid NOT NULL', 'entry_id uuid NOT NULL', 'node_key text NOT NULL',
      'baseline_object_key text NOT NULL', 'object_manifest_hmac text NOT NULL', 'prior_attempt_id uuid NOT NULL',
      'prior_operation_id uuid NOT NULL', 'prior_source_id uuid NOT NULL', 'prior_packet_key text NOT NULL',
      'observed_before_hmac text NOT NULL', 'prior_result_hmac text NOT NULL', 'closed_source_hmac text NOT NULL',
      'fact_hmac text NOT NULL', 'fact_ciphertext text NOT NULL', 'basic_custody_hmac text',
    ]) expect(table).toContain(field);
    expect(table).toContain('CHECK(m6_encrypted(fact_ciphertext,6291456))');
    expect(table).toContain('PRIMARY KEY(source_id,entry_id,node_key)');
    expect(table).toContain('UNIQUE(source_id,baseline_object_key)');
    expect(table).toContain('UNIQUE(source_id,prior_attempt_id)');
    expect(table).not.toMatch(/(?:password|secret|credential_payload)\s+(?:text|jsonb)/);
  });

  it('anchors the current source to its complete pin, baseline manifest, baseline object and archived node FKs', () => {
    expect(table).toContain('REFERENCES entity_change_baseline_pins(cluster_id,workspace_id,id,baseline_id,source_id,workflow_execution_id) ON DELETE RESTRICT');
    expect(table).toContain('REFERENCES entity_change_baselines(cluster_id,workspace_id,id,object_manifest_hmac) ON DELETE RESTRICT');
    expect(table).toContain('REFERENCES entity_change_baseline_objects(baseline_id,object_key) ON DELETE RESTRICT');
    expect(table).toContain('REFERENCES entity_change_recycle_nodes(cluster_id,workspace_id,entry_id,node_key) ON DELETE RESTRICT');
    expect(table).toContain('REFERENCES entity_change_recycle_receipts(attempt_id) ON DELETE RESTRICT');
    expect(table).toContain('REFERENCES entity_change_execution_sources(cluster_id,workspace_id,id) ON DELETE RESTRICT');
    expect(table).toContain('REFERENCES mutation_operations(cluster_id,id) ON DELETE RESTRICT');
  });

  it('requires the exact matching current object and trusted Basic custody rather than an arbitrary adopted entity', () => {
    expect(table).toContain('source_id<>prior_source_id AND observed_before_hmac=prior_result_hmac');
    expect(table).not.toContain('node_key=baseline_object_key');
    expect(table).toContain("CHECK((native_type='basic-auth')=(basic_custody_hmac IS NOT NULL))");
    expect(factGuard).toContain("s.expires_at<=clock_timestamp() OR x.state<>'executing'");
    expect(factGuard).toContain('archive.source_id=NEW.source_id OR archive.source_id=NEW.prior_source_id');
    expect(factGuard).toContain("NOT object_row.present OR object_row.affected OR object_row.recovery<>'reference'");
    expect(factGuard).toContain('object_row.before_hmac IS DISTINCT FROM NEW.observed_before_hmac');
    expect(factGuard).toContain('object_row.dependencies IS DISTINCT FROM n.dependencies');
    expect(factGuard).toContain('NEW.observed_at<b.observed_from OR NEW.observed_at>b.observed_until');
  });

  it('binds the five observations to genuine prior Native201 receipt, attempt, mutation and closed workflow evidence', () => {
    expect(factGuard).toContain('ROW(r.cluster_id,r.workspace_id,r.source_id,r.entry_id,r.node_key,r.packet_key,r.operation_id,r.native_id,r.direction,r.result_hmac)');
    expect(factGuard).toContain('ROW(attempt.cluster_id,attempt.workspace_id,attempt.source_id,attempt.baseline_id,attempt.pin_id,attempt.workflow_execution_id,attempt.packet_key,attempt.native_type,attempt.native_id,attempt.parent_id,attempt.credential_kind)');
    expect(factGuard).toContain("outcome_row.outcome<>'succeeded' OR outcome_row.native_status<>201");
    expect(factGuard).toContain("sent.attempt_id=NEW.prior_attempt_id AND sent.event_kind='send-intent'");
    expect(factGuard).toContain("m.state<>'succeeded' OR NOT m.remote_started OR NOT m.remote_completed OR m.result_secret IS NULL");
    expect(factGuard).toContain("prior_x.state NOT IN('succeeded','partial','failed') OR prior_w.state NOT IN('succeeded','partial','failed')");
    expect(factGuard).toContain('prior_x.completed_at IS NULL OR prior_x.completed_at>NEW.observed_at');
  });

  it('parenthesizes comparison CASE expressions inside PL/pgSQL IF conditions', () => {
    // PostgreSQL's PL/pgSQL IF scanner must not mistake the inner CASE THEN
    // for the outer IF THEN. This source guard is not a database parse trial.
    expect(factGuard).toContain("m.entity_type IS DISTINCT FROM (CASE WHEN NEW.credential_kind IS NULL THEN NEW.native_type ELSE 'credentials' END)");
    expect(code).not.toMatch(/\bIS\s+(?:NOT\s+)?DISTINCT\s+FROM\s+CASE\b/i);
    expect(code).not.toMatch(/(?:<>|!=|<=|>=|=|<|>)\s*CASE\b/i);
  });

  it('preserves complete delete and all-missing restore packet cardinality plus the existing dependency ordering', () => {
    expect(packetSet).toContain("IF NEW.direction='delete' OR present_total=0 THEN");
    expect(packetSet).toContain("IF packet_total<>a.packet_count OR NEW.direction='delete' AND present_total<>0");
    expect(packetSet).toContain("(p.direction='delete' AND ord<=p.packet_order) OR(p.direction='restore' AND ord>=p.packet_order)");
    expect(packetSet).toContain('FOREACH dep IN ARRAY n.dependencies LOOP');
  });

  it('limits partial admission to the fixed Consumer plus six DAO graph with two missing packets and five observed objects', () => {
    expect(fixedBranch).toContain("NEW.direction<>'restore' OR packet_total<>2 OR present_total<>5 OR a.node_count<>7 OR a.packet_count<>7");
    expect(fixedBranch).toContain("root_node.native_type<>'consumers'");
    expect(fixedBranch).toContain("node.native_type NOT IN('consumers','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')");
    expect(fixedBranch).toContain('node.dependencies IS DISTINCT FROM ARRAY[a.root_key]');
    expect(fixedBranch).toContain("packet.native_type NOT IN('hmac-auth','acls')");
    expect(fixedBranch).toContain('count(DISTINCT prior_source_id)');
    expect(table).toContain("native_type IN('consumers','key-auth','basic-auth','jwt','oauth2')");
  });

  it('enforces disjoint complete archived coverage and seven baseline objects with original dependencies and exact raw digests', () => {
    expect(fixedBranch).toContain('b.object_count<>7');
    expect(fixedBranch).toContain('fact.source_id=packet.source_id AND fact.entry_id=packet.entry_id AND fact.node_key=packet.node_key');
    expect(fixedBranch).toContain('AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_packets packet');
    expect(fixedBranch).toContain('AND NOT EXISTS(SELECT 1 FROM entity_change_recycle_restore_present_facts fact');
    expect(fixedBranch).not.toContain('object_row.object_key=node.node_key');
    expect(fixedBranch).toContain('object_row.native_type,object_row.native_id,object_row.parent_id,object_row.credential_kind');
    expect(fixedBranch).toContain('object_row.credential_kind,object_row.dependencies)');
    expect(fixedBranch).toContain("object_row.affected AND NOT object_row.present AND object_row.recovery='absent'");
    expect(fixedBranch).toContain("NOT object_row.affected AND object_row.present AND object_row.recovery='reference'");
    expect(fixedBranch).toContain('fact.observed_before_hmac=object_row.before_hmac AND fact.prior_result_hmac=object_row.before_hmac');
  });

  it('requires the original HMAC known-not-sent outcome without erasing its real reservation or remote-start evidence', () => {
    expect(fixedBranch).toContain("historical.native_type='hmac-auth'");
    expect(fixedBranch).toContain("result.outcome='failed-known-not-sent' AND result.native_status IS NULL AND result.error_code IS NOT NULL");
    expect(fixedBranch).toContain("operation.state='failed' AND operation.remote_started AND NOT operation.remote_completed AND operation.result_secret IS NULL");
    expect(fixedBranch).toContain('operation.error_code IS NOT DISTINCT FROM result.error_code');
    expect(fixedBranch).toContain("reservation.attempt_id=attempt.id AND reservation.event_kind='send-intent' AND reservation.observed_at<=result.observed_at");
    expect(fixedBranch).toContain('NOT EXISTS(SELECT 1 FROM entity_change_recycle_receipts receipt WHERE receipt.attempt_id=attempt.id)');
    expect(fixedBranch).not.toContain('NOT operation.remote_started');
    expect(fixedBranch).not.toMatch(/NOT EXISTS\(SELECT 1 FROM entity_change_packet_events[^)]*send-intent/);
  });

  it('requires ACL to remain unattempted and blocks every unresolved foreign source or sent-unknown outcome', () => {
    expect(fixedBranch).toContain("historical.native_type='acls'");
    expect(fixedBranch).toContain('attempt.id IS NOT NULL OR operation.id IS NOT NULL OR receipt.attempt_id IS NOT NULL');
    expect(fixedBranch).toContain("foreign_execution.state NOT IN('succeeded','partial','failed') OR foreign_workflow.state NOT IN('succeeded','partial','failed')");
    expect(fixedBranch).toContain("result.outcome='sent-unknown' OR attempt.id IS NOT NULL AND result.id IS NULL");
    expect(fixedBranch).toContain("current_result.source_id=NEW.source_id AND current_result.outcome='sent-unknown'");
    expect(fixedBranch).toContain("foreign_packet.source_id<>NEW.source_id AND operation.state IN('pending','running','uncertain')");
  });

  it('validates packet and observed-fact inserts together at commit and makes observations append-only', () => {
    expect(code).toContain('AFTER INSERT ON entity_change_recycle_restore_present_facts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION m11_validate_recycle_packet_set()');
    expect(code).toContain('BEFORE UPDATE OR DELETE ON entity_change_recycle_restore_present_facts FOR EACH ROW EXECUTE FUNCTION m8_immutable()');
    expect(code).toContain('BEFORE TRUNCATE ON entity_change_recycle_restore_present_facts FOR EACH STATEMENT EXECUTE FUNCTION m8_immutable()');
    expect(code).toContain('REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON entity_change_recycle_restore_present_facts FROM PUBLIC');
    expect(code).not.toMatch(/\bINSERT INTO\s+(?:entity_change_recycle_receipts|entity_change_packet_attempts|entity_change_packet_events|mutation_operations)\b/);
    expect(code).not.toMatch(/CREATE (?:OR REPLACE )?FUNCTION [\w]*(?:permit|authority|approval|source_creator)[\w]*\(/);
  });

  it('has balanced SQL expression parentheses outside quoted strings and comments', () => {
    const expressions = sql.replace(/--[^\n]*/g, '').replace(/'(?:''|[^'])*'/g, "''");
    let depth = 0;
    for (const character of expressions) {
      if (character === '(') depth++;
      if (character === ')') depth--;
      expect(depth).toBeGreaterThanOrEqual(0);
    }
    expect(depth).toBe(0);
    expect(sql.match(/\$\$/g)).toHaveLength(4);
  });
});
