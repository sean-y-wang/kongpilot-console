import 'reflect-metadata';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { RecycleService } from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import { EntityChangeRecycleExecutionService } from '../../apps/console-api/src/modules/recycle-bin/entity-change-recycle-execution.service';
import { EntityChangeRecycleFactsService } from '../../apps/console-api/src/modules/recycle-bin/entity-change-recycle-facts.service';
import { EntityChangeBaselineCapturerService } from '../../apps/console-api/src/modules/workflows/entity-change-baseline-capturer.service';
import { derivePreparedRecyclePackets, preparedRecycleNodeManifest } from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.service';
import { PARTIAL_RECYCLE_FACTS_MIGRATION, partialBasicCustodyHmac, partialRestoreObservationAad, validatePartialRecycleRestoreSelection } from '../../apps/console-api/src/modules/recycle-bin/partial-recycle-restore';
import { executionFixture } from './execution-test-fixture';
import { payWorkspaceId, workspaceFixture } from './workspace-test-fixture';

/** Controlled source/domain fixtures only. Real SecretService HMA/AEAD and
 * planner code are exercised; fake historical delegates are NOT authenticated
 * SQL025 evidence, private Root authority, real Kong GETs or native receipts. */
function fixture() {
  const secrets = new SecretService(), cid = randomUUID(), wid = payWorkspaceId, parentId = randomUUID(), entryId = randomUUID();
  const actor: any = { user: { id: randomUUID(), username: 'source-unit', superAdmin: false }, workspaceId: wid };
  const plain = 'synthetic-unit-basic-plaintext', kinds = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
  const consumer = { id: parentId, username: 'synthetic-consumer-b', tags: ['kos-ws-pay'], created_at: 10 };
  const rootKey = `consumers:${parentId}`;
  const graph: any = { purpose: 'recycle', complete: true, capturedAt: '2026-10-13T12:00:00.000Z', rootKey,
    nodes: [{ key: rootKey, type: 'consumers', id: parentId, path: `/consumers/${parentId}`, data: consumer,
      restoreData: consumer, restorable: true, affected: true, dependencies: [] }] };
  for (const kind of kinds) {
    const id = randomUUID(), data: any = { id, consumer: { id: parentId }, tags: consumer.tags, created_at: 10 };
    if (kind === 'key-auth') data.key = 'synthetic-unit-key';
    if (kind === 'basic-auth') { data.username = 'synthetic-basic'; data.password = createHash('sha1').update(plain + parentId).digest('hex'); }
    if (kind === 'jwt') Object.assign(data, { key: 'synthetic-jwt', secret: 'synthetic-jwt-secret', algorithm: 'HS256' });
    if (kind === 'oauth2') Object.assign(data, { name: 'synthetic-oauth', client_id: 'synthetic-client', client_secret: 'synthetic-oauth-secret', redirect_uris: ['https://unit.invalid/callback'] });
    if (kind === 'hmac-auth') Object.assign(data, { username: 'synthetic-hmac', secret: 'synthetic-hmac-secret' });
    if (kind === 'acls') data.group = 'synthetic-group';
    graph.nodes.push({ key: `${kind}:${parentId}:${id}`, type: kind, id, path: `/consumers/${parentId}/${kind}/${id}`, data,
      restoreData: { ...data, ...(kind === 'basic-auth' ? { password: plain } : {}) }, restorable: true, affected: true, dependencies: [rootKey] });
  }
  const current = new Map<string, any>(graph.nodes.slice(0, 5).map((node: any) => [node.path, { ...node.data, created_at: 20 }]));
  const basic = graph.nodes[2], remembered = { credential: structuredClone(current.get(basic.path)), rawInput: { id: basic.id, username: basic.data.username, password: plain } };
  const sourceId = randomUUID(), history: any = { version: 1, clusterId: cid, workspaceId: wid, entryId, graphHmac: secrets.fingerprint(graph),
    nodeManifestHmac: secrets.fingerprint(preparedRecycleNodeManifest(graph, secrets)), sourceId, intentId: randomUUID(), intentRevision: 1,
    baselineId: randomUUID(), pinId: randomUUID(), workflowId: randomUUID(), workflowExecutionId: randomUUID(),
    materialHmac: secrets.fingerprint('synthetic-intent'), changeDigest: secrets.fingerprint('synthetic-change'), packetManifestHmac: secrets.fingerprint('synthetic-packets'),
    terminalMetadataAudit: { id: randomUUID(), eventHash: secrets.fingerprint('synthetic-audit'), proofHmac: secrets.fingerprint('synthetic-proof'),
      outcomeEventId: randomUUID(), outcomeFactHmac: secrets.fingerprint('synthetic-known-not-sent'), requestHmac: secrets.fingerprint('synthetic-request') },
    presentNodes: graph.nodes.slice(0, 5).map((node: any, index: number) => ({ nodeKey: node.key, nativeType: node.type, nativeId: node.id,
      parentId: index ? parentId : null, credentialKind: index ? node.type : null, packetKey: `prior-${index + 1}`, attemptId: randomUUID(), operationId: randomUUID(),
      operationKey: `prior-operation-${index + 1}`, resultHmac: secrets.fingerprint(current.get(node.path)), outcomeFactHmac: secrets.fingerprint(`synthetic-success-${index}`) })),
    remainingNodes: graph.nodes.slice(5).map((node: any, index: number) => ({ nodeKey: node.key, nativeType: node.type, nativeId: node.id, parentId, credentialKind: node.type,
      classification: index ? 'unattempted' : 'failed-known-not-sent', packetKey: `prior-${index + 6}`, attemptId: index ? null : randomUUID(),
      operationId: index ? null : randomUUID(), outcomeFactHmac: index ? null : secrets.fingerprint('synthetic-known-not-sent') })) };
  history.coverageHmac = secrets.fingerprint(history);
  const partition: any = { version: 1, history, presentNodes: history.presentNodes.map((item: any) => ({ nodeKey: item.nodeKey, beforeHmac: item.resultHmac,
    ...(item.nativeType === 'basic-auth' ? { basicCustodyHmac: partialBasicCustodyHmac(basic, current.get(basic.path), remembered, parentId, secrets) } : {}) })),
    remainingNodeKeys: history.remainingNodes.map((item: any) => item.nodeKey) };
  const selection: any = { ...partition, selectionHmac: secrets.fingerprint(partition) };
  const packets: any[] = graph.nodes.slice(5).map((node: any, index: number) => {
    const { created_at, ...body } = node.restoreData;
    return { key: `remaining-${index + 1}`, order: index + 1, dependencies: [], method: 'POST', canonicalPath: node.path.replace(/\/[^/]+$/, ''),
      nativeType: node.type, nativeId: node.id, parentId, credentialKind: node.type, permissionAction: 'write', mutationAction: 'restore', body, before: null,
      bodyHmac: secrets.fingerprint(body), beforeHmac: secrets.fingerprint(null) };
  });
  const obligation: any = { kind: 'recycle-restore', entryId, graph, graphHmac: secrets.fingerprint(graph), packetKeys: packets.map(packet => packet.key), partialRestore: selection,
    sealedEntry: { entryId, clusterId: cid, workspaceId: wid, payloadHmac: secrets.fingerprint(graph), state: 'partially_restored' } };
  const material: any = { version: 1, clusterId: cid, workspaceId: wid, requesterId: actor.user.id, packets, metadataObligations: [obligation], schemas: [],
    prerequisites: graph.nodes.map((node: any) => ({ type: node.type, path: node.path, nativeId: node.id, ...(node.type === 'consumers' ? {} : { parentId }),
      before: current.get(node.path) ?? null, absent: !current.has(node.path), fingerprint: secrets.fingerprint(current.get(node.path) ?? null), permissionAction: 'write' })) };
  const reseal = () => { const { coverageHmac, ...old } = history; history.coverageHmac = secrets.fingerprint(old);
    const { selectionHmac, ...newPartition } = selection; selection.selectionHmac = secrets.fingerprint(newPartition); };
  return { secrets, cid, wid, parentId, entryId, actor, plain, graph, current, remembered, history, selection, packets, obligation, material, reseal };
}

function preparation(f: ReturnType<typeof fixture>) {
  const statuses = f.graph.nodes.map((node: any, index: number) => ({ node_key: node.key, entity_type: node.type, original_id: node.id, affected: true,
    dependencies: node.dependencies, delete_state: 'deleted', restore_state: index < 5 ? 'restored' : index === 5 ? 'failed' : 'pending', restored_id: index < 5 ? node.id : null }));
  const entry: any = { id: f.entryId, cluster_id: f.cid, workspace_id: f.wid, root_type: 'consumers', original_id: f.parentId, root_name: f.graph.nodes[0].data.username,
    state: 'partially_restored', payload_secret: f.secrets.encrypt(f.graph, `recycle:${f.entryId}`), mutation_id: null, node_count: 7, expires_at: new Date(Date.now() + 86400000) };
  const db: any = { one: vi.fn(async (sql: string) => sql.includes('FROM recycle_entries') ? entry : null), query: vi.fn(async (sql: string) => sql.includes('FROM recycle_nodes') ? statuses : []),
    exec: vi.fn(() => { throw Error('No source unit SQL writes'); }), transaction: vi.fn(() => { throw Error('No source unit SQL transactions'); }) };
  const credentials: any = { get: vi.fn(async () => f.remembered), save: vi.fn(), remove: vi.fn() };
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => {
    assertGet(method); if (!f.current.has(path)) throw new NotFoundException(); return structuredClone(f.current.get(path));
  }), prepareSchema: vi.fn(async (_cid: string, path: string, body: any) => ({ canonicalPath: path, payloadHmac: f.secrets.fingerprint(body), schemaMaterial: { entity: { schema: { fields: [] } } } })) };
  const authz: any = { assertArchivedEntity: vi.fn(), assertEntity: vi.fn(), assertNestedParentScope: vi.fn() }, audit: any = { append: vi.fn() }, mutations: any = { execute: vi.fn() };
  const recycle = new RecycleService(db, f.secrets, kong, mutations, {} as any, authz, audit, credentials, {} as any, workspaceFixture(f.cid).resolver, executionFixture());
  const origin = { kind: 'entity-change', id: randomUUID(), workspace_id: f.wid, state: 'succeeded', workflow_id: randomUUID(), workflow_state: 'succeeded', execution_state: 'succeeded',
    unresolved_steps: false, graphHmac: f.history.graphHmac, nodeManifestHmac: f.history.nodeManifestHmac, sourceFactsHmac: f.secrets.fingerprint('synthetic-delete-facts'), closedRestoreCoverage: f.history } as any;
  recycle.installEntityOriginLookup({ readClosedOrigin: vi.fn(async () => origin) });
  const request: any = { kind: 'recycle', action: 'restore', entryId: f.entryId, confirmed: true, confirm_name: entry.root_name };
  return { recycle, db, kong, credentials, authz, audit, mutations, origin, entry, statuses, request };
}
function assertGet(method: string) { if (method !== 'GET') throw Error('No source unit native sends'); }
function legacyArchiveKeys(f:ReturnType<typeof fixture>):any[]{
  const currentNodes=structuredClone(f.graph.nodes);
  for(let index=1;index<7;index++)f.graph.nodes[index].key=`${f.graph.nodes[index].type}:${f.graph.nodes[index].id}`;
  f.history.presentNodes.forEach((item:any,index:number)=>item.nodeKey=f.graph.nodes[index].key);
  f.history.remainingNodes.forEach((item:any,index:number)=>item.nodeKey=f.graph.nodes[index+5].key);
  f.selection.presentNodes.forEach((item:any,index:number)=>item.nodeKey=f.graph.nodes[index].key);
  f.selection.remainingNodeKeys=f.graph.nodes.slice(5).map((node:any)=>node.key);
  f.obligation.graphHmac=f.secrets.fingerprint(f.graph);f.history.graphHmac=f.obligation.graphHmac;
  f.history.nodeManifestHmac=f.secrets.fingerprint(preparedRecycleNodeManifest(f.graph,f.secrets));f.reseal();return currentNodes;
}

describe('M11 fixed partial recycle source contracts (controlled evidence only)', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '34'.repeat(32))); afterEach(() => vi.unstubAllEnvs());
  it('emits only HMAC and ACL packets, retaining the complete original graph and original IDs', () => {
    const f = fixture(), before = f.secrets.fingerprint(f.graph);
    const plan = derivePreparedRecyclePackets(f.obligation, f.packets, f.secrets);
    expect(plan.map(item => item.node.type)).toEqual(['hmac-auth', 'acls']); expect(plan.map(item => item.packet.nativeId)).toEqual(f.graph.nodes.slice(5).map((node: any) => node.id));
    expect(plan.every(item => item.packet.dependencies.length === 0 && item.parentId === f.parentId)).toBe(true);
    expect(f.graph.nodes).toHaveLength(7); expect(f.secrets.fingerprint(f.graph)).toBe(before);
  });
  it('rejects a two-packet subset with no authenticated partition-shaped sealed material', () => {
    const f = fixture(), { partialRestore, ...without } = f.obligation;
    expect(() => derivePreparedRecyclePackets(without, f.packets, f.secrets)).toThrow();
  });
  it.each(['duplicate-present', 'overlap', 'wrong-parent', 'non-HMAC-missing', 'missing-custody', 'wrong-current-hash', 'ACL-attempt'])('rejects resealed malformed coverage: %s', fault => {
    const f = fixture();
    if (fault === 'duplicate-present') f.selection.presentNodes[1] = { ...f.selection.presentNodes[0] };
    if (fault === 'overlap') f.selection.remainingNodeKeys[0] = f.history.presentNodes[0].nodeKey;
    if (fault === 'wrong-parent') f.history.presentNodes[1].parentId = randomUUID();
    if (fault === 'non-HMAC-missing') f.history.remainingNodes[0].classification = 'unattempted';
    if (fault === 'missing-custody') delete f.selection.presentNodes[2].basicCustodyHmac;
    if (fault === 'wrong-current-hash') f.selection.presentNodes[0].beforeHmac = f.secrets.fingerprint('different');
    if (fault === 'ACL-attempt') f.history.remainingNodes[1].attemptId = randomUUID();
    f.reseal(); expect(() => validatePartialRecycleRestoreSelection(f.graph, f.selection, f.secrets)).toThrow();
  });
  it('does not accept replaying an already successful Consumer as one of the new two packets', () => {
    const f = fixture(); f.packets[0].nativeType = 'consumers'; f.packets[0].nativeId = f.parentId;
    expect(() => derivePreparedRecyclePackets(f.obligation, f.packets, f.secrets)).toThrow();
  });
  it('keeps partial execution closed without the new original-handle private Root verifier', () => {
    const f = fixture(), coordinator = new EntityChangeRecycleExecutionService({} as any, {} as any, {} as any, {} as any, {} as any, {} as any, f.secrets, {} as any, {} as any);
    expect(coordinator.supports(f.material)).toBe(false);
  });
  it('never treats a matching Basic hash as custody of the immutable original plaintext', () => {
    const f = fixture(), node = f.graph.nodes[2];
    expect(partialBasicCustodyHmac(node, f.current.get(node.path), f.remembered, f.parentId, f.secrets)).toBe(f.selection.presentNodes[2].basicCustodyHmac);
    expect(() => partialBasicCustodyHmac(node, f.current.get(node.path), { ...f.remembered, rawInput: { password: 'replacement' } }, f.parentId, f.secrets)).toThrow();
    expect(() => partialBasicCustodyHmac(node, f.current.get(node.path), null, f.parentId, f.secrets)).toThrow();
  });
  it('pins source readiness to the exact new SQL025 without editing the old ledger migration', () => {
    const bytes = readFileSync(new URL('../../apps/console-api/src/infrastructure/migrations/025_m11_partial_recycle_restore.sql', import.meta.url));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(PARTIAL_RECYCLE_FACTS_MIGRATION.checksum);
  });
  it('prepares a server-only five-present/two-absent partition without any writes', async () => {
    const f = fixture(), p = preparation(f), prepared = await p.recycle.prepareEntityChange(f.cid, p.request, f.actor);
    expect(prepared.packets.map(packet => packet.nativeType)).toEqual(['hmac-auth', 'acls']);
    expect(prepared.prerequisites.filter(item => !item.absent)).toHaveLength(5); expect(prepared.prerequisites.filter(item => item.absent)).toHaveLength(2);
    const obligation = prepared.metadataObligations.find(item => item.kind === 'recycle-restore') as any;
    expect(obligation.graph.nodes).toHaveLength(7); expect(obligation.partialRestore.history.coverageHmac).toBe(f.history.coverageHmac);
    expect(p.credentials.save).not.toHaveBeenCalled(); expect(p.credentials.remove).not.toHaveBeenCalled(); expect(p.db.exec).not.toHaveBeenCalled();
    expect(p.mutations.execute).not.toHaveBeenCalled(); expect(p.audit.append).not.toHaveBeenCalled();
    expect(p.kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
  });
  it('rejects a live match without source-bound history and rejects drift after the prior Native201', async () => {
    const f = fixture(), p = preparation(f); delete p.origin.closedRestoreCoverage;
    await expect(p.recycle.prepareEntityChange(f.cid, p.request, f.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_RECYCLE_PARTIAL_HISTORY_REQUIRED' } });
    p.origin.closedRestoreCoverage = f.history; f.current.get(f.graph.nodes[0].path).created_at = 999;
    await expect(p.recycle.prepareEntityChange(f.cid, p.request, f.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_RECYCLE_PRESENT_RESULT_CHANGED' } });
    expect(p.mutations.execute).not.toHaveBeenCalled(); expect(p.db.exec).not.toHaveBeenCalled();
  });
  it.each([false,true])('captures seven current objects and a complete five-node live graph without confusing legacy archive keys=%s', async legacy => {
    const f = fixture(), context = executionFixture(), credentials: any = { get: vi.fn(async () => f.remembered) };
    const currentNodes=legacy?legacyArchiveKeys(f):f.graph.nodes;
    const currentGraph: any = { ...f.graph, purpose: 'baseline', nodes: currentNodes.slice(0, 5).map((node: any) => ({ ...node, data: structuredClone(f.current.get(node.path)) })) };
    const graphs: any = { capture: vi.fn(async () => structuredClone(currentGraph)) };
    const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => { assertGet(method); if (!f.current.has(path)) throw new NotFoundException(); return structuredClone(f.current.get(path)); }),
      prepareSchema: vi.fn(async (_cid: string, path: string, body: any) => ({ canonicalPath: path, payloadHmac: f.secrets.fingerprint(body), schemaMaterial: { entity: { schema: { fields: [] } } } })) };
    f.material.schemas = await Promise.all(f.packets.map(packet => kong.prepareSchema(f.cid, packet.canonicalPath, packet.body)));
    const capturer = new EntityChangeBaselineCapturerService(kong, context, graphs, credentials, { revalidateStored: vi.fn() } as any, f.secrets);
    const baseline = await capturer.capture(f.material, f.actor);
    expect(baseline.objects).toHaveLength(7); expect(baseline.objects.filter(item => item.present)).toHaveLength(5); expect(baseline.objects.filter(item => item.affected && !item.present)).toHaveLength(2);
    for (const object of baseline.objects) expect(object.dependencies).toEqual(f.graph.nodes.find((node: any) => node.type === object.nativeType&&node.id===object.nativeId).dependencies);
    if(legacy){expect(baseline.objects.find(item=>item.nativeType==='basic-auth')?.key).toBe(currentNodes[2].key);
      expect(baseline.objects.find(item=>item.nativeType==='basic-auth')?.key).not.toBe(f.graph.nodes[2].key);}
    expect(baseline.objects.find(item => item.nativeType === 'basic-auth')?.trustedProvenance).toMatchObject({ kind: 'closed-restore-current-present', basicCustodyHmac: f.selection.presentNodes[2].basicCustodyHmac });
    expect(baseline.graphs).toHaveLength(1); expect(graphs.capture).toHaveBeenCalledTimes(2); expect(kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
    currentGraph.nodes.push({ ...f.graph.nodes[5], data: { ...f.graph.nodes[5].data } });
    await expect(capturer.capture(f.material, f.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_RECYCLE_CURRENT_GRAPH_CHANGED' } });
  });
  it('stores only five new encrypted present observations and binds them to prior receipts and the complete current baseline', async () => {
    const f = fixture(), currentSource = randomUUID(), observedAt = '2026-10-13T12:00:01.000Z';
    const currentNodes=legacyArchiveKeys(f);
    const capture: any = { version: 1, observedUntil: observedAt, objects: f.graph.nodes.map((node: any, index: number) => {
      const prior = f.history.presentNodes.find((item: any) => item.nodeKey === node.key), selected = f.selection.presentNodes.find((item: any) => item.nodeKey === node.key);
      return { key: currentNodes[index].key, nativeType: node.type, nativeId: node.id, ...(index ? { parentId: f.parentId, credentialKind: node.type } : {}),
        present: index < 5, affected: index >= 5, recovery: index < 5 ? 'reference' : 'absent', dependencies: node.dependencies,
        before: f.current.get(node.path) ?? null, trustedProvenance: index < 5 ? { kind: 'closed-restore-current-present', nodeKey: node.key, historyCoverageHmac: f.history.coverageHmac,
          priorSourceId: f.history.sourceId, priorAttemptId: prior.attemptId, priorOperationId: prior.operationId, priorResultHmac: prior.resultHmac, beforeHmac: selected.beforeHmac,
          ...(selected.basicCustodyHmac ? { basicCustodyHmac: selected.basicCustodyHmac } : {}) } : { kind: 'native-get-404' } };
    }) };
    const input: any = { source: { id: currentSource, clusterId: f.cid, workspaceId: f.wid, workflowExecutionId: randomUUID() },
      baseline: { sourceId: currentSource, baselineId: randomUUID(), pinId: randomUUID(), objectCount: 7, objectManifestHmac: f.secrets.fingerprint('synthetic-current-manifest') },
      entryId: f.entryId, obligation: f.obligation, packets: f.packets };
    const prior = f.history.presentNodes.map((item: any) => ({ attempt_id: item.attemptId, cluster_id: f.cid, workspace_id: f.wid, source_id: f.history.sourceId,
      entry_id: f.entryId, node_key: item.nodeKey, packet_key: item.packetKey, operation_id: item.operationId, operation_key: item.operationKey,
      native_id: item.nativeId, direction: 'restore', result_hmac: item.resultHmac }));
    let migration: any = PARTIAL_RECYCLE_FACTS_MIGRATION;
    const db: any = { one: vi.fn(async (sql: string, args: any[]) => sql.includes('schema_migrations') ? migration : prior.find((item: any) => item.attempt_id === args[0])),
      query: vi.fn(async () => []), exec: vi.fn(async () => 1) };
    const service: any = new EntityChangeRecycleFactsService(db, f.secrets);
    // Private normalizer exercised directly in controlled fixtures; this is
    // deliberately NOT a Root handle, proof, complete SQL transaction or send.
    const expected = await service.presentRows(db, input, capture);
    await service.persistPresentFacts(db, input, capture);
    expect(db.exec).toHaveBeenCalledTimes(5);
    expect(db.exec.mock.calls.every(([sql]: any[]) => sql.startsWith('INSERT INTO entity_change_recycle_restore_present_facts('))).toBe(true);
    const stored = expected.map((item: any, index: number) => ({ ...item.row, created_at: new Date(), fact_ciphertext: db.exec.mock.calls[index][1].at(-1) }));
    expect(JSON.stringify(db.exec.mock.calls)).not.toContain('synthetic-unit-key');
    for (const item of stored) {
      const opened: any = f.secrets.decrypt(item.fact_ciphertext, partialRestoreObservationAad(f.cid, f.wid, currentSource, f.entryId, item.node_key));
      expect(f.secrets.fingerprint(opened)).toBe(item.fact_hmac);
      expect(item.observed_before_hmac).toBe(item.prior_result_hmac);
      if(item.native_type!=='consumers')expect(item.baseline_object_key).not.toBe(item.node_key);
      expect(() => f.secrets.decrypt(item.fact_ciphertext, partialRestoreObservationAad(f.cid, f.wid, randomUUID(), f.entryId, item.node_key))).toThrow();
    }
    await service.assertPresentRows(input, expected, stored);
    const changed = structuredClone(stored); changed[0].prior_operation_id = randomUUID();
    await expect(service.assertPresentRows(input, expected, changed)).rejects.toBeDefined();
    const replaced = structuredClone(stored); replaced[0].fact_ciphertext = f.secrets.encrypt({ fabricated: true }, partialRestoreObservationAad(f.cid, f.wid, currentSource, f.entryId, replaced[0].node_key));
    await expect(service.assertPresentRows(input, expected, replaced)).rejects.toBeDefined();
    capture.objects[0].before.created_at = 999;
    await expect(service.presentRows(db, input, capture)).rejects.toBeDefined();
    migration = null; db.exec.mockClear(); await expect(service.persistPresentFacts(db, input, capture)).rejects.toMatchObject({ response: { code: 'ENTITY_RECYCLE_PARTIAL_SCHEMA_UNAVAILABLE' } });
    expect(db.exec).not.toHaveBeenCalled();
  });
});
