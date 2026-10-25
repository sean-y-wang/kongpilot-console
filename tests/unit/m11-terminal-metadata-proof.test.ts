import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { certifyTerminalRecycleMetadata } from '../../apps/console-api/src/modules/workflows/entity-change-terminal-metadata-proof';
import { entityPacketFactAad } from '../../apps/console-api/src/modules/workflows/entity-change-execution-facts.service';
import { terminalMetadataFixture } from './helpers/terminal-metadata-fixture';

const invalid = { response: { code: 'ENTITY_CHANGE_TERMINAL_METADATA_PROOF_INVALID' } };
const unsupported = { response: { code: 'ENTITY_CHANGE_TERMINAL_METADATA_SHAPE_UNSUPPORTED' } };
describe('M11 exact Consumer credential restore terminal metadata proof (synthetic SELECT fixture)', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'c7'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());
  it('certifies original five native201 successes, send-intent plus known-not-sent sixth, and unattempted ACL without writes', async () => {
    const f = terminalMetadataFixture(), before = structuredClone(f.rows);
    const receipt = await certifyTerminalRecycleMetadata(f.input);
    expect(receipt).toMatchObject({ entryId: f.entryId, failedNodeKey: f.graph.nodes[5].key, failedOperationId: f.rows.mutation_operations[5].id,
      failedAttemptId: f.rows.entity_change_packet_attempts[5].id, alreadyClosed: false, nativeSuccesses: 5, knownNotSent: 1, unattempted: 1 });
    expect(receipt.proofHmac).toMatch(/^[a-f\d]{64}$/); expect(Object.isFrozen(receipt)).toBe(true);
    expect(f.rows).toEqual(before); expect(f.txMock.exec).not.toHaveBeenCalled(); expect(f.txMock.transaction).not.toHaveBeenCalled();
    expect(f.rows.entity_change_packet_attempts.every(row => !Object.hasOwn(row, 'dependencies'))).toBe(true);
    expect(f.rows.entity_change_recycle_packets.every(row => !Object.hasOwn(row, 'dependencies'))).toBe(true);
    expect([...f.txMock.one.mock.calls, ...f.txMock.query.mock.calls].every(([sql]) => /^SELECT\s/.test(sql) && !/FOR\s+(UPDATE|SHARE)/.test(sql))).toBe(true);
  });
  it('accepts current contextual graph keys as well as the exact legacy archive keys; baseline keys remain contextual', async () => {
    for (const parentAwareGraphKeys of [false, true]) {
      const f = terminalMetadataFixture({ parentAwareGraphKeys });
      expect(f.baselineEnvelope.capture.objects.filter((object: any) => object.parentId).every((object: any) => object.key.includes(f.consumerId))).toBe(true);
      expect((await certifyTerminalRecycleMetadata(f.input)).nativeSuccesses).toBe(5);
    }
  });
  it('keeps identical immutable proofHmac after exact initial-to-closed metadata projection', async () => {
    const f = terminalMetadataFixture(), originalFacts = structuredClone(f.rows.entity_change_packet_events);
    const first = await certifyTerminalRecycleMetadata(f.input); f.closeProjection();
    const replay = await certifyTerminalRecycleMetadata(f.input);
    expect(replay).toEqual({ ...first, alreadyClosed: true }); expect(f.rows.entity_change_packet_events).toEqual(originalFacts);
    const event = f.rows.entity_change_packet_events.find(e => e.id === replay.outcomeEventId)!;
    const fact: any = f.secrets.decrypt(event.fact_ciphertext, entityPacketFactAad(f.source.clusterId, f.source.workspaceId, replay.failedAttemptId, 'outcome'));
    expect(fact.evidence).toMatchObject({ mutationState: 'uncertain', remoteCompleted: false, metadataComplete: false }); expect(fact.evidence.wireSpent).toBeUndefined();
  });
  it('retains original metadataComplete:false success facts when actual SQL023 receipts and nodes prove completion', async () => {
    const f = terminalMetadataFixture(); f.rewriteFact(0, 'outcome', fact => { fact.evidence.metadataComplete = false; });
    expect((await certifyTerminalRecycleMetadata(f.input)).nativeSuccesses).toBe(5);
  });
  it('rejects coherently signed invalid transport scope shapes', async () => {
    const f = terminalMetadataFixture();
    expect(f.plan.scope.transportScope).toMatch(/^[a-f\d]{64}$/);
    f.plan.scope.transportScope = 'synthetic-invalid-scope'; f.envelope.prepared.scope.transportScope = f.plan.scope.transportScope; f.resignEnvelope();
    await expect(certifyTerminalRecycleMetadata(f.input)).rejects.toMatchObject(invalid);
  });
  it.each([
    ['wrong current actor', (f: any) => { f.actor.user.id = randomUUID(); }],
    ['wrong workspace', (f: any) => { f.actor.workspaceId = randomUUID(); }],
    ['altered source', (f: any) => { f.sourceRow.workflow_execution_id = randomUUID(); }],
    ['altered intent packet parent', (f: any) => { f.rows.entity_change_intent_packets[5].parent_id = randomUUID(); }],
    ['altered real SQL020 DAG', (f: any) => { f.rows.entity_change_intent_packets[5].dependencies = []; }],
    ['altered baseline object HMAC', (f: any) => { f.rows.entity_change_baseline_objects[5].before_hmac = '0'.repeat(64); }],
    ['altered pin', (f: any) => { f.rows.entity_change_baseline_pins[0].object_manifest_hmac = '0'.repeat(64); }],
    ['wrong archive scope', (f: any) => { f.rows.entity_change_recycle_archives[0].workspace_id = randomUUID(); }],
    ['same archive and restore source', (f: any) => { f.rows.entity_change_recycle_archives[0].source_id = f.source.id; }],
    ['legacy aggregate origin', (f: any) => { f.rows.recycle_entries[0].mutation_id = randomUUID(); }],
    ['wrong archive node HMAC', (f: any) => { f.rows.entity_change_recycle_nodes[5].restore_hmac = '0'.repeat(64); }],
    ['wrong restore packet', (f: any) => { f.rows.entity_change_recycle_packets[5].native_id = randomUUID(); }],
    ['altered fact HMAC', (f: any) => { f.rows.entity_change_packet_events[11].fact_hmac = '0'.repeat(64); }],
    ['mismatched packet six native UUID', (f: any) => { f.rows.mutation_operations[5].entity_id = null; }],
    ['wrong sixth credential parent', (f: any) => { f.rows.mutation_operations[5].parent_id = randomUUID(); }],
    ['manufactured remote completion', (f: any) => { f.rows.mutation_operations[5].remote_completed = true; }],
    ['failed-before-start flags', (f: any) => { f.rows.mutation_operations[5].remote_started = false; }],
    ['invented sixth result', (f: any) => { const m = f.rows.mutation_operations[5]; m.result_secret = f.secrets.encrypt(null, `mutation:${m.id}:result`); }],
    ['foreign active chain', (f: any) => { f.foreign.unresolved = true; }],
  ])('rejects %s', async (_label, change) => {
    const f = terminalMetadataFixture(); change(f); await expect(certifyTerminalRecycleMetadata(f.input)).rejects.toMatchObject(invalid); expect(f.txMock.exec).not.toHaveBeenCalled();
  });
  it.each([
    ['missing original outcome', (f: any) => { f.rows.entity_change_packet_events.pop(); }],
    ['missing send-intent', (f: any) => { f.rows.entity_change_packet_events.splice(10, 1); }],
    ['missing successful receipt', (f: any) => { f.rows.entity_change_recycle_receipts.pop(); }],
    ['extra attempted ACL', (f: any) => { f.rows.entity_change_packet_attempts.push({ ...f.rows.entity_change_packet_attempts[5], id: randomUUID(), packet_key: 'packet-7', packet_order: 7 }); }],
    ['extra mutation', (f: any) => { f.rows.mutation_operations.push({ ...f.rows.mutation_operations[5], id: randomUUID() }); }],
    ['extra receipt', (f: any) => { f.rows.entity_change_recycle_receipts.push({ ...f.rows.entity_change_recycle_receipts[0], attempt_id: f.rows.entity_change_packet_attempts[5].id }); }],
    ['extra legacy node', (f: any) => { f.rows.recycle_nodes.push({ ...f.rows.recycle_nodes[6], node_key: 'foreign' }); }],
    ['altered successful receipt result', (f: any) => { f.rows.entity_change_recycle_receipts[1].result_hmac = '0'.repeat(64); }],
    ['missing successful node state', (f: any) => { f.rows.recycle_nodes[4].restore_state = 'pending'; }],
    ['untouched ACL changed', (f: any) => { f.rows.recycle_nodes[6].restore_state = 'failed'; }],
    ['mixed closed state', (f: any) => { f.rows.mutation_operations[5].state = 'failed'; }],
    ['closed entry alone', (f: any) => { f.rows.recycle_entries[0].state = 'partially_restored'; }],
    ['restored sixth node', (f: any) => { f.rows.recycle_nodes[5].restore_state = 'restored'; f.rows.recycle_nodes[5].restored_id = f.graph.nodes[5].id; }],
  ])('refuses unresolved or inconsistent history: %s', async (_label, change) => {
    const f = terminalMetadataFixture(); change(f); await expect(certifyTerminalRecycleMetadata(f.input)).rejects.toMatchObject(invalid);
  });
  it.each([
    ['sent-unknown', (fact: any) => { fact.outcome = 'sent-unknown'; }],
    ['asserted native status', (fact: any) => { fact.nativeStatus = 201; }],
    ['invented wireSpent evidence', (fact: any) => { fact.evidence.wireSpent = false; }],
    ['rewritten historical mutation state', (fact: any) => { fact.evidence.mutationState = 'failed'; }],
    ['wrong original operation', (fact: any) => { fact.evidence.operationId = randomUUID(); }],
    ['known success replacement', (fact: any) => { fact.outcome = 'succeeded'; fact.nativeStatus = 201; delete fact.errorCode; }],
  ])('rejects coherent re-encryption of sixth %s', async (_label, modify) => {
    const f = terminalMetadataFixture(); f.rewriteFact(5, 'outcome', modify); await expect(certifyTerminalRecycleMetadata(f.input)).rejects.toMatchObject(invalid);
  });
  it('rejects raw credential/result corruption even when its stored result HMAC and outcome are re-signed together', async () => {
    const f = terminalMetadataFixture(), m = f.rows.mutation_operations[2], raw: any = f.secrets.decrypt(m.result_secret, `mutation:${m.id}:result`);
    raw.password = 'a'.repeat(40); m.result_secret = f.secrets.encrypt(raw, `mutation:${m.id}:result`);
    f.rewriteFact(2, 'outcome', fact => { fact.evidence.responseHmac = f.secrets.fingerprint(raw); });
    f.rows.entity_change_recycle_receipts[2].result_hmac = f.secrets.fingerprint(raw);
    await expect(certifyTerminalRecycleMetadata(f.input)).rejects.toMatchObject(invalid);
  });
  it.each(['username', 'tags'])('checks Basic raw %s against the original body after coherent result/outcome/receipt re-signing', async field => {
    const f = terminalMetadataFixture(), m = f.rows.mutation_operations[2], raw: any = f.secrets.decrypt(m.result_secret, `mutation:${m.id}:result`);
    raw[field] = field === 'tags' ? ['kos-ws-foreign'] : 'synthetic-wrong-username';
    m.result_secret = f.secrets.encrypt(raw, `mutation:${m.id}:result`);
    f.rewriteFact(2, 'outcome', fact => { fact.evidence.responseHmac = f.secrets.fingerprint(raw); });
    f.rows.entity_change_recycle_receipts[2].result_hmac = f.secrets.fingerprint(raw);
    await expect(certifyTerminalRecycleMetadata(f.input)).rejects.toMatchObject(invalid);
  });
  it('rejects wrong AEAD contexts and returns a safe fixed code for ciphertext/database errors', async () => {
    const f = terminalMetadataFixture(), row = f.rows.entity_change_packet_events[11]; row.fact_ciphertext = f.rows.entity_change_packet_events[9].fact_ciphertext;
    await expect(certifyTerminalRecycleMetadata(f.input)).rejects.toMatchObject(invalid);
    const g = terminalMetadataFixture(); g.txMock.one.mockRejectedValueOnce(new Error('secret connection string / SQL credentials'));
    try { await certifyTerminalRecycleMetadata(g.input); expect.fail('Expected safe failure'); } catch (error: any) {
      expect(error.getResponse()).toEqual(invalid.response); expect(JSON.stringify(error)).not.toContain('credentials');
    }
  });
  it.each([
    ['different packet count', (f: any) => { f.envelope.prepared.packets.pop(); }],
    ['different native packet ordering', (f: any) => { f.envelope.prepared.packets[5].nativeType = 'acls'; }],
    ['different graph shape', (f: any) => { f.graph.nodes.pop(); }],
  ])('clearly declines generalized repair shapes: %s', async (_label, modify) => {
    const f = terminalMetadataFixture(); modify(f); f.resignEnvelope(); await expect(certifyTerminalRecycleMetadata(f.input)).rejects.toMatchObject(unsupported);
  });
  it('fails if inputs mutate across historical authority awaits', async () => {
    const f = terminalMetadataFixture(), original = f.facts.historicalProjection.bind(f.facts);
    vi.spyOn(f.facts, 'historicalProjection').mockImplementation(async (...args) => { const result = await original(...args); f.actor.requestId = 'changed'; return result; });
    await expect(certifyTerminalRecycleMetadata(f.input)).rejects.toMatchObject(invalid);
  });
  it('contains no native/network client, SQL mutation, private registry or source/permit creation', () => {
    const source = readFileSync('apps/console-api/src/modules/workflows/entity-change-terminal-metadata-proof.ts', 'utf8');
    expect(source).not.toMatch(/@Injectable|@Controller|KongService|ExecutionContextService|WeakMap|WeakSet|\.exec\(|\.encrypt\(|\bfetch\(|\b(?:INSERT INTO|UPDATE\s+\w+\s+SET|DELETE FROM)\b/);
    expect(source).toContain('facts.historicalProjection');
  });
});
