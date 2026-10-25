import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';
import { EntityRecycleOriginReaderService } from '../../apps/console-api/src/modules/recycle-bin/entity-recycle-origin-reader.service';
import { auditCanonicalRecord } from '../../apps/console-api/src/modules/audit/audit-integrity.service';
import { certifyTerminalRecycleMetadata } from '../../apps/console-api/src/modules/workflows/entity-change-terminal-metadata-proof';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { terminalMetadataFixture } from './helpers/terminal-metadata-fixture';

/** Isolated SELECT-only historical coverage tests. Real AEAD/HMAC, production
 * terminal certificate and audit hashing run against synthetic rows. Calling
 * the private reader isolates this new historical half; readClosedOrigin still
 * validates the complete original DELETE archive first. No SQL is executed,
 * Kong or private ledger contacted, runtime authority issued or wire inferred. */
async function fixture(parentAwareGraphKeys = false) {
  const f = terminalMetadataFixture({ parentAwareGraphKeys }); f.closeProjection();
  const certificate = await certifyTerminalRecycleMetadata(f.input);
  const rows = f.rows, source = f.source, envelope = f.envelope, plan = f.plan;
  const common = { cluster_id: source.clusterId, workspace_id: source.workspaceId };
  const tuple = { ...common, intent_id: source.intentId, intent_revision: source.intentRevision, material_hmac: source.materialHmac,
    change_digest: source.changeDigest, packet_manifest_hmac: source.packetManifestHmac };
  rows.entity_change_intents = [{ ...common, id: source.intentId, requester_id: source.executionActorId, credential_epoch: source.credentialEpoch,
    issued_at: envelope.issuedAt, expires_at: envelope.expiresAt }];
  Object.assign(rows.entity_change_intent_versions[0], { requester_id: source.executionActorId, credential_epoch: source.credentialEpoch,
    issued_at: envelope.issuedAt, expires_at: envelope.expiresAt, safe_review: envelope.review, execution_mode: envelope.executionMode,
    definition_id: envelope.definition.id, definition_version: envelope.definition.version, policy_hash: envelope.definition.policyHash });
  rows.workflows = [{ ...common, id: source.workflowId, state: 'partial', kind: 'native-change', subject_type: 'entity_change_intents', subject_id: source.intentId,
    requester_type: 'console', requester_user_id: source.executionActorId, plan_revision: source.workflowPlanRevision, plan_hash: source.workflowPlanHash }];
  Object.assign(rows.workflow_executions[0], { execution_actor_id: source.executionActorId, plan_revision: source.workflowPlanRevision, plan_hash: source.workflowPlanHash });
  rows.workflow_versions = [{ ...common, workflow_id: source.workflowId, plan_revision: source.workflowPlanRevision, plan_hash: source.workflowPlanHash,
    payload_secret: f.secrets.encrypt(plan, planAad(source.clusterId, source.workspaceId, source.workflowId, source.workflowPlanRevision)) }];
  rows.entity_change_submissions = [{ ...tuple, workflow_id: source.workflowId, actor_id: source.executionActorId,
    workflow_plan_revision: source.workflowPlanRevision, workflow_plan_hash: source.workflowPlanHash }];
  const after = { executionId: source.workflowExecutionId, sourceId: source.id, entryId: f.entryId, operationId: certificate.failedOperationId,
    outcomeEventId: certificate.outcomeEventId, outcomeFactHmac: certificate.outcomeFactHmac, proofHmac: certificate.proofHmac,
    requestHmac: f.secrets.fingerprint('synthetic-original-metadata-request'), workflowState: 'partial', executionState: 'partial', operationState: 'failed',
    entryState: 'partially_restored', nodeRestoreState: 'failed', nativeSuccesses: 5, knownNotSent: 1, unattempted: 1, nativeRequestsSent: 0, metadataReconciled: true };
  const audit: any = { ...common, id: randomUUID(), chain_scope: `cluster:${source.clusterId}`, sequence: '1', actor_id: source.executionActorId,
    actor_type: 'user', source_ip: '127.0.0.1', entity_type: 'workflows', entity_id: source.workflowId, workflow_id: source.workflowId,
    action: 'workflow.execute.terminal-metadata-reconciled', result: 'failed', request_id: 'synthetic-original-request', prev_hash: 'GENESIS',
    before: { operationState: 'uncertain', entryState: 'restoring', nodeRestoreState: 'pending' }, after, json_patch: [],
    occurred_at: new Date().toISOString(), event_hash: '0'.repeat(64), millisecond_precision: true };
  const rehashAudit = () => { audit.event_hash = createHash('sha256').update(canonicalJson(auditCanonicalRecord(audit))).digest('hex'); };
  rehashAudit(); rows.audit_events = [audit];
  const select = (sql: string, params: any[]) => {
    if (!/^SELECT\s/i.test(sql) || /FOR\s+(UPDATE|SHARE)/i.test(sql)) throw new Error('Synthetic coverage adapter permits SELECT only');
    if (sql.startsWith('SELECT EXISTS(')) return [f.foreign];
    const table = /\bFROM\s+(\w+)/i.exec(sql)?.[1]; if (!table || !rows[table]) throw new Error('Unexpected synthetic coverage SELECT');
    if(table==='entity_change_recycle_nodes')return structuredClone(rows[table].filter(r=>r.entry_id===params[0]).sort((a,b)=>a.node_order-b.node_order));
    if(table==='recycle_entries')return structuredClone(rows[table].filter(r=>r.cluster_id===params[0]&&r.workspace_id===params[1]&&r.id===params[2]));
    if(table==='entity_change_recycle_archives')return structuredClone(rows[table].filter(r=>r.cluster_id===params[0]&&r.workspace_id===params[1]&&r.entry_id===params[2]));
    if (sql.startsWith('SELECT DISTINCT source_id')) {
      const ids = rows[table].filter(r => r.cluster_id === params[0] && r.workspace_id === params[1] && r.entry_id === params[2]
        && r.direction === 'restore' && r.source_id !== params[3]).map(r => r.source_id);
      return [...new Set(ids)].map(source_id => ({ source_id }));
    }
    let selected = rows[table];
    if (table === 'entity_change_baseline_pins') selected = selected.filter(r => r.id === params[0] && r.baseline_id === params[1]);
    else if (table === 'entity_change_baseline_objects') selected = selected.filter(r => r.baseline_id === params[0]).sort((a, b) => a.object_order - b.object_order);
    else {
      selected = selected.filter(r => r.cluster_id === params[0] && r.workspace_id === params[1]);
      if (['entity_change_execution_sources', 'entity_change_intents', 'entity_change_baselines', 'workflows', 'workflow_executions'].includes(table)) selected = selected.filter(r => r.id === params[2]);
      else if (table === 'workflow_versions') selected = selected.filter(r => r.workflow_id === params[2] && r.plan_revision === params[3]);
      else if (table === 'entity_change_submissions') selected = selected.filter(r => r.workflow_id === params[2]);
      else if (table === 'entity_change_intent_versions' || table === 'entity_change_intent_packets') selected = selected.filter(r => r.intent_id === params[2] && r.intent_revision === params[3]);
      else if (table === 'audit_events') selected = selected.filter(r => r.workflow_id === params[2] && r.actor_id === params[3] && r.after.sourceId === params[4] && r.after.entryId === params[5]);
      else if (table === 'mutation_operations') selected = selected.filter(r => r.entity_change_source_id === params[2]);
      else selected = selected.filter(r => r.source_id === params[2] && (params.length < 4 || r.entry_id === params[3]));
    }
    return structuredClone(selected.sort((a, b) => (a.packet_order ?? 0) - (b.packet_order ?? 0)));
  };
  const db: any = { one: vi.fn(async (sql: string, params: any[] = []) => select(sql, params)[0] ?? null), query: vi.fn(async (sql: string, params: any[] = []) => select(sql, params)),
    exec: vi.fn(async () => { throw new Error('No SQL exec permitted'); }), transaction: vi.fn(async (fn: any) => fn(db)) };
  const reader = new EntityRecycleOriginReaderService(db, f.secrets), delegate = { assertCurrentScope: vi.fn(async () => undefined), assertFrozenSubject: vi.fn(async () => undefined) };
  reader.installFixedDelegate(delegate);
  const input = { clusterId: source.clusterId, workspaceId: source.workspaceId, entryId: f.entryId, actor: f.actor, subjectAction: 'write' as const };
  const read = (active: string | null = null) => (reader as any).closedRestoreCoverage(input, rows.entity_change_recycle_archives[0], f.graph, rows.recycle_entries[0], rows.recycle_nodes, db, active);
  const noWrites = () => { expect(db.exec).not.toHaveBeenCalled(); expect(f.txMock.exec).not.toHaveBeenCalled(); };
  return { ...f, db, reader, delegate, input, read, audit, rehashAudit, certificate, noWrites };
}

const invalid = { response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } };
describe('M11 read-only original seven-node restore coverage', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ad'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());
  it.each([false, true])('returns five historical receipts and two closed remaining facts with parent-aware keys=%s', async parentAware => {
    const f = await fixture(parentAware), before = structuredClone(f.rows), coverage = await f.read();
    expect(coverage).toMatchObject({ version: 1, clusterId: f.source.clusterId, entryId: f.entryId, sourceId: f.source.id,
      baselineId: f.baseline.id, graphHmac: f.secrets.fingerprint(f.graph), terminalMetadataAudit: { proofHmac: f.certificate.proofHmac } });
    expect(coverage.presentNodes.map((n: any) => n.nativeType)).toEqual(['consumers', 'key-auth', 'basic-auth', 'jwt', 'oauth2']);
    expect(coverage.remainingNodes.map((n: any) => [n.nativeType, n.classification])).toEqual([['hmac-auth', 'failed-known-not-sent'], ['acls', 'unattempted']]);
    const { coverageHmac, ...summary } = coverage; expect(coverageHmac).toBe(f.secrets.fingerprint(summary));
    expect(Object.isFrozen(coverage)).toBe(true); expect(Object.isFrozen(coverage.presentNodes)).toBe(true);
    expect(JSON.stringify(coverage)).not.toMatch(/synthetic-api-key|synthetic-basic-plaintext|synthetic-jwt-secret|synthetic-client-secret|sessionId|wireSpent/);
    expect(f.rows).toEqual(before); expect(f.delegate.assertFrozenSubject).toHaveBeenCalledOnce(); f.noWrites();
  });
  it('preserves the genuine send reservation and original uncertain fact after metadata-only closure', async () => {
    const f = await fixture(), originalFacts = structuredClone(f.rows.entity_change_packet_events), coverage = await f.read();
    const failed = coverage.remainingNodes[0]; expect(failed.operationId).toBe(f.rows.mutation_operations[5].id);
    expect(f.rows.mutation_operations[5]).toMatchObject({ state: 'failed', remote_started: true, remote_completed: false, result_secret: null });
    expect(f.rows.entity_change_packet_events).toEqual(originalFacts); expect(originalFacts).toHaveLength(12); f.noWrites();
  });
  it.each([
    ['missing success receipt', (f: any) => f.rows.entity_change_recycle_receipts.pop()],
    ['wrong receipt scope', (f: any) => { f.rows.entity_change_recycle_receipts[0].workspace_id = randomUUID(); }],
    ['old workflow still executing', (f: any) => { f.rows.workflows[0].state = 'executing'; }],
    ['old execution changed', (f: any) => { f.rows.workflow_executions[0].plan_hash = '1'.repeat(64); }],
    ['baseline object missing', (f: any) => f.rows.entity_change_baseline_objects.pop()],
    ['pin wrong source', (f: any) => { f.rows.entity_change_baseline_pins[0].source_id = randomUUID(); }],
    ['sixth still uncertain', (f: any) => { f.rows.mutation_operations[5].state = 'uncertain'; }],
    ['sixth remote completed', (f: any) => { f.rows.mutation_operations[5].remote_completed = true; }],
    ['sixth invented result', (f: any) => { f.rows.mutation_operations[5].result_secret = f.secrets.encrypt(null, `mutation:${f.rows.mutation_operations[5].id}:result`); }],
    ['ACL attempt added', (f: any) => f.rows.entity_change_packet_attempts.push({ ...f.rows.entity_change_packet_attempts[5], id: randomUUID(), packet_key: f.packets[6].key })],
    ['foreign pending or unknown', (f: any) => { f.foreign.unresolved = true; }],
    ['original seven graph truncated', (f: any) => { f.graph.nodes.pop(); }],
    ['forged present projection', (f: any) => { f.rows.recycle_nodes[0].restore_state = 'pending'; }],
    ['absent metadata audit', (f: any) => { f.rows.audit_events = []; }],
    ['duplicate metadata audit', (f: any) => f.rows.audit_events.push(structuredClone(f.audit))],
    ['audit content hash changed', (f: any) => { f.audit.event_hash = '0'.repeat(64); }],
    ['wrong audit counts even rehashed', (f: any) => { f.audit.after.nativeSuccesses = 6; f.rehashAudit(); }],
    ['wrong audit proof even rehashed', (f: any) => { f.audit.after.proofHmac = '0'.repeat(64); f.rehashAudit(); }],
  ])('fails closed: %s', async (_name, mutate) => {
    const f = await fixture(); mutate(f); await expect(f.read()).rejects.toMatchObject(invalid); f.noWrites();
  });
  it('rejects invented wireSpent or edited original no-send outcome instead of treating it as authority', async () => {
    const f = await fixture(); f.rewriteFact(5, 'outcome', fact => { fact.evidence.wireSpent = false; });
    await expect(f.read()).rejects.toMatchObject(invalid); f.noWrites();
    const g = await fixture(); g.rewriteFact(5, 'outcome', fact => { fact.evidence.mutationState = 'failed'; });
    await expect(g.read()).rejects.toMatchObject(invalid); g.noWrites();
  });
  it('checks raw successful ciphertext, Basic hash/password association, and swapped event AEAD', async () => {
    const f = await fixture(), m = f.rows.mutation_operations[2], raw: any = f.secrets.decrypt(m.result_secret, `mutation:${m.id}:result`);
    raw.password = '0'.repeat(40); m.result_secret = f.secrets.encrypt(raw, `mutation:${m.id}:result`);
    await expect(f.read()).rejects.toMatchObject(invalid); f.noWrites();
    const g = await fixture(); g.rows.entity_change_packet_events[2].fact_ciphertext = g.rows.entity_change_packet_events[0].fact_ciphertext;
    await expect(g.read()).rejects.toThrow(); g.noWrites();
  });
  it('admits restoring projection only with the independently supplied genuine active private source and preserves foreign blockers', async () => {
    const f = await fixture(); f.rows.recycle_entries[0].state = 'restoring'; await expect(f.read()).rejects.toMatchObject(invalid);
    await expect(f.read(randomUUID())).resolves.toMatchObject({ sourceId: f.source.id });
    f.foreign.unresolved = true; await expect(f.read(randomUUID())).rejects.toMatchObject(invalid); f.noWrites();
  });
  it('retains full original DELETE checks before optional coverage and exposes no mutator/kernel dependency', () => {
    const source = readFileSync('apps/console-api/src/modules/recycle-bin/entity-recycle-origin-reader.service.ts', 'utf8');
    const body = source.slice(source.indexOf('async readClosedOrigin('));
    expect(body.indexOf('await this.actualPackets(')).toBeLessThan(body.indexOf('await this.closedRestoreCoverage('));
    expect(body).toContain('await this.storedBaseline(source, archive, graph, tx)');
    expect(source).not.toMatch(/INSERT INTO|UPDATE (?:mutation|recycle|entity_change)|\.kong\.|issueNative|privateLedger/);
    expect(source).toContain("s.id IS NULL OR x.id IS NULL OR o.outcome='sent-unknown'");
  });
  it('revalidates immutable prior history after own later progress without adopting mutable projections or refreshing old grants',async()=>{
    const f=await fixture(),coverage=await f.read(),currentSourceId=randomUUID();f.delegate.assertFrozenSubject.mockClear();
    f.rows.recycle_entries[0].state='restored';f.rows.recycle_entries[0].restored_at=new Date().toISOString();
    f.rows.recycle_nodes[5].restore_state='restored';f.rows.recycle_nodes[5].restored_id=f.graph.nodes[5].id;
    f.rows.recycle_nodes[6].restore_state='restored';f.rows.recycle_nodes[6].restored_id=f.graph.nodes[6].id;
    await expect(f.read()).rejects.toMatchObject(invalid);
    await expect(f.reader.verifyFrozenRestoreCoverage(f.input,coverage,currentSourceId,f.db)).resolves.toBeUndefined();
    expect(f.delegate.assertFrozenSubject).not.toHaveBeenCalled();expect(f.delegate.assertCurrentScope).not.toHaveBeenCalled();
    f.foreign.unresolved=true;await expect(f.reader.verifyFrozenRestoreCoverage(f.input,coverage,currentSourceId,f.db)).rejects.toMatchObject(invalid);f.noWrites();
  });
  it('does not accept a copied current-source UUID or edited old audit as immutable-history authentication',async()=>{
    const f=await fixture(),coverage=await f.read();
    await expect(f.reader.verifyFrozenRestoreCoverage(f.input,coverage,f.source.id,f.db)).rejects.toMatchObject(invalid);
    f.audit.after.knownNotSent=2;f.rehashAudit();await expect(f.reader.verifyFrozenRestoreCoverage(f.input,coverage,randomUUID(),f.db)).rejects.toMatchObject(invalid);f.noWrites();
  });
});
