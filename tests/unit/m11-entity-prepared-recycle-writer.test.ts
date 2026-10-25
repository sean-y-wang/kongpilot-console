import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { EntityPreparedRecycleWriterService } from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.service';
import type { RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import type { EntityChangePacket } from '../../apps/console-api/src/modules/entities/entity-change.types';
import type { PreparedRecycleObligation, EntityPreparedRecycleWriterDelegate, EntityPreparedRecycleArchiveGrant,
  EntityPreparedRecycleArchiveHandle, EntityPreparedRecyclePacketGrant, EntityPreparedRecyclePacketHandle,
  EntityPreparedRecycleRepairGrant, EntityPreparedRecycleRepairHandle } from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.types';

const cid = 'a949b292-2e4a-4326-b30d-3a883b5ef3d7', wid = '306a8d36-d1f9-4542-8972-9b30aa1bd67c';
const actorId = 'cc2019b5-8061-4a3c-bc19-f24c586e00fa', serviceId = '35b60072-927d-4f3b-bba1-dbc31bd345e4';
const routeId = 'c6439d99-75a0-4f2b-b6d7-a2d3f0c87177', consumerId = 'f02f0f79-03bb-4494-9b2c-f3fa4a28a28a';
const sourceId = '230d1596-a1a3-4e15-ab89-90f254bb52ea', baselineId = 'e05a8c85-6e79-4e01-b9b5-6f5a1302a8ea';
const pinId = '5c1f22a1-f228-41de-a3ad-cb2a9ef16b51', executionId = 'd933aefa-851b-4d42-bc29-d79770f2c8c1';
const entryId = '25ed6944-c79e-4b46-8c48-d5d6e716121d', operationId = 'f8cae52b-226e-4b39-a157-13a4a743441b';
const pluginId = '8c959ac4-58b8-4b81-9d59-b1d2297a765c';
const consumerSecret = 'unit-trusted-basic-password';

function serviceGraph(): RecycleGraph {
  const service = { id: serviceId, name: 'unit-service', host: 'echo.example', tags: ['kos-ws-pay', 'kos-tag-dGVhbTpwYXk'] };
  const route = { id: routeId, name: 'unit-route', service: { id: serviceId }, paths: ['/unit'], tags: service.tags };
  const plugin = { id: pluginId, name: 'key-auth', route: { id: routeId }, service: null, consumer: null, config: { key_names: ['apikey'] }, tags: service.tags };
  return { complete: true, purpose: 'recycle', capturedAt: '2026-10-13T12:00:00Z', rootKey: `services:${serviceId}`, nodes: [
    { key: `services:${serviceId}`, type: 'services', id: serviceId, path: `/services/${serviceId}`, data: service, affected: true, dependencies: [], restorable: true, restoreData: service },
    { key: `routes:${routeId}`, type: 'routes', id: routeId, path: `/routes/${routeId}`, data: route, affected: true, dependencies: [`services:${serviceId}`], restorable: true, restoreData: route },
    { key: `plugins:${pluginId}`, type: 'plugins', id: pluginId, path: `/plugins/${pluginId}`, data: plugin, affected: true, dependencies: [`routes:${routeId}`], restorable: true, restoreData: plugin },
  ] };
}

function consumerGraph(): RecycleGraph {
  const consumer = { id: consumerId, username: 'unit-consumer', tags: ['kos-ws-pay'] };
  const kinds = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
  const graph: RecycleGraph = { complete: true, purpose: 'recycle', capturedAt: '2026-10-13T12:00:00Z', rootKey: `consumers:${consumerId}`, nodes: [
    { key: `consumers:${consumerId}`, type: 'consumers', id: consumerId, path: `/consumers/${consumerId}`, data: consumer, affected: true, dependencies: [], restorable: true, restoreData: consumer },
  ] };
  kinds.forEach((kind, index) => {
    const id = `70000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`, data: any = { id, consumer: { id: consumerId }, tags: consumer.tags };
    if (kind === 'key-auth') data.key = 'unit-original-key';
    if (kind === 'basic-auth') { data.username = 'unit-basic'; data.password = createHash('sha1').update(consumerSecret + consumerId).digest('hex'); }
    if (kind === 'oauth2') { data.name = 'unit-oauth'; data.client_id = 'unit-client'; data.client_secret = 'unit-original-oauth-plaintext'; }
    if (kind === 'jwt') { data.key = 'unit-jwt-key'; data.secret = 'unit-jwt-secret'; data.algorithm = 'HS256'; }
    if (kind === 'hmac-auth') { data.username = 'unit-hmac'; data.secret = 'unit-hmac-secret'; }
    if (kind === 'acls') data.group = 'unit-group';
    graph.nodes.push({ key: `${kind}:${consumerId}:${id}`, type: kind, id, path: `/consumers/${consumerId}/${kind}/${id}`, data, affected: true,
      dependencies: [graph.rootKey], restorable: true, restoreData: { ...data, ...(kind === 'basic-auth' ? { password: consumerSecret } : {}) } });
  });
  return graph;
}

function fixture() {
  const secrets = new SecretService(), archiveHandles = new WeakMap<object, EntityPreparedRecycleArchiveGrant>();
  const packetHandles = new WeakMap<object, EntityPreparedRecyclePacketGrant>(), repairHandles = new WeakMap<object, EntityPreparedRecycleRepairGrant>();
  const committed: Array<{ sql: string; params: any[] }> = [], calls: string[] = [];
  let staged: Array<{ sql: string; params: any[] }> | undefined, failMetadata = false;
  const tx: any = { exec: vi.fn(async (sql: string, params: any[]) => { calls.push(sql.startsWith('INSERT INTO recycle_entries') ? 'archive-entry' : 'sql'); (staged ?? committed).push({ sql, params }); return 1; }) };
  const db: any = { transaction: vi.fn(async (callback: any) => { staged = []; try { const result = await callback(tx); committed.push(...staged!); return result; } finally { staged = undefined; } }) };
  const audit = { append: vi.fn(async (_event: any, receivedTx: any) => { expect(receivedTx).toBe(tx); calls.push('audit'); if (failMetadata) throw new Error('private error unit-trusted-basic-password'); }) };
  const kong = { request: vi.fn(async (_cid: string, method: string, _path: string, body: any) => {
    calls.push(`native-${method}`);
    if (method === 'GET') throw new NotFoundException();
    if (method === 'DELETE') return null;
    return { ...body, ...(body?.username === 'unit-basic' ? { password: createHash('sha1').update(body.password + consumerId).digest('hex') } : {}) };
  }) };
  const mutations = { execute: vi.fn(async (context: any, callback: any) => { context.operationId = operationId; calls.push('mutation'); return callback(); }) };
  const writer = new EntityPreparedRecycleWriterService(db, mutations as any, kong as any, secrets, audit as any);
  const assertIssued = (handle: object) => { if (!packetHandles.has(handle)) throw new ForbiddenException({ code: 'TEST_UNISSUED_PACKET' }); };
  // Controlled routing/storage fixture only, not a genuine Root approval,
  // current permission, native permit, SQL constraint or durable receipt proof.
  const delegate: EntityPreparedRecycleWriterDelegate = {
    runArchive: async (handle, callback) => { const grant = archiveHandles.get(handle); if (!grant) throw new ForbiddenException({ code: 'TEST_UNISSUED_ARCHIVE' }); return callback(grant); },
    runPacket: async (handle, callback) => { const grant = packetHandles.get(handle); if (!grant) throw new ForbiddenException({ code: 'TEST_UNISSUED_PACKET' }); return callback(grant); },
    runRepair: async (handle, callback) => { const grant = repairHandles.get(handle); if (!grant) throw new ForbiddenException({ code: 'TEST_UNISSUED_REPAIR' }); return callback(grant); },
    linkArchive: vi.fn(async (_handle, _receipt, receivedTx) => { expect(receivedTx).toBe(tx); calls.push('link-archive'); }),
    verifyCurrentRestore:async()=>undefined, // Explicit controlled readback adapter; no current witness authority claimed.
    runVerifiedDelete: async (handle, id, callback) => { assertIssued(handle); expect(id).toBe(operationId); calls.push('verified-delete'); return callback(); },
    runVerificationRead: async (handle, id, callback) => { assertIssued(handle); expect(id).toBe(operationId); calls.push('verified-get'); return callback(); },
    recordTargetDeletePoststate: () => { calls.push('target-poststate'); },
    linkNodeReceipt: vi.fn(async (handle, _receipt, receivedTx) => {
      if (!packetHandles.has(handle) && !repairHandles.has(handle)) throw new ForbiddenException();
      expect(receivedTx).toBe(tx); calls.push('link-node');
    }),
  };
  const binding: any = { source: { id: sourceId, clusterId: cid, workspaceId: wid, workflowId: sourceId, workflowExecutionId: executionId, executionActorId: actorId },
    baseline: { baselineId, sourceId, pinId }, actor: { user: { id: actorId, username: 'unit', superAdmin: true }, workspaceId: wid } };
  function plan(graph = serviceGraph(), restoring = false): { obligation: PreparedRecycleObligation; packets: EntityChangePacket[] } {
    const nodes = restoring ? graph.nodes.filter(node => node.affected) : graph.nodes.filter(node => node.affected).reverse(), packetByNode = new Map<string, string>();
    const packets = nodes.map((node, index): EntityChangePacket => {
      const parentId = node.type.includes('auth') || ['jwt', 'oauth2', 'acls'].includes(node.type) ? consumerId : undefined;
      const packet: any = { key: `packet-${index + 1}`, order: index + 1, nativeType: node.type, nativeId: node.id,
        ...(parentId ? { parentId, credentialKind: node.type } : {}), method: restoring ? 'POST' : 'DELETE', canonicalPath: restoring ? node.path.replace(/\/[^/]+$/, '') : node.path,
        mutationAction: restoring ? 'restore' : 'delete', permissionAction: restoring ? 'write' : 'delete', before: restoring ? null : node.data,
        ...(restoring ? { body: node.restoreData } : {}), dependencies: restoring ? node.dependencies.flatMap(dep => packetByNode.get(dep) ?? [])
          : graph.nodes.filter(child => child.affected && child.dependencies.includes(node.key)).flatMap(child => packetByNode.get(child.key) ?? []) };
      packet.bodyHmac = secrets.fingerprint(packet.body ?? null); packet.beforeHmac = secrets.fingerprint(packet.before);
      packetByNode.set(node.key, packet.key); return packet;
    });
    const common = { graph, graphHmac: secrets.fingerprint(graph), packetKeys: packets.map(packet => packet.key) };
    return { packets, obligation: restoring ? { kind: 'recycle-restore', entryId, ...common,
      sealedEntry: { clusterId: cid, workspaceId: wid, entryId, state: 'deleted', expiresAt: '2099-01-01T00:00:00Z', payloadHmac: common.graphHmac, nodeManifestHmac: '0'.repeat(64), restoreMaterialHmac: '1'.repeat(64) } }
      : { kind: 'recycle-archive', ...common } };
  }
  const issueArchive = (prepared = plan()) => { const handle = Object.freeze({}) as EntityPreparedRecycleArchiveHandle;
    archiveHandles.set(handle, { ...binding, entryId, expiresAt: '2099-01-01T00:00:00Z', ...prepared } as EntityPreparedRecycleArchiveGrant); return handle; };
  const issuePacket = (prepared = plan(), index = 0) => {
    const handle = Object.freeze({}) as EntityPreparedRecyclePacketHandle, packet = prepared.packets[index], graph = prepared.obligation.graph;
    const node = graph.nodes.find(item => item.id === packet.nativeId)!;
    const grant = { ...binding, entryId, nodeKey: node.key, operationKey: `source-packet-${index + 1}`, packet, ...prepared };
    packetHandles.set(handle, grant); return { handle, grant };
  };
  const issueRepair = (grant: EntityPreparedRecyclePacketGrant, nativeResult: unknown) => {
    const handle = Object.freeze({}) as EntityPreparedRecycleRepairHandle;
    repairHandles.set(handle, { ...grant, originalOperationId: operationId, knownNativeComplete: true, nativeResult }); return handle;
  };
  return { writer, delegate, secrets, db, tx, kong, mutations, audit, committed, calls, plan, issueArchive, issuePacket, issueRepair,
    failMetadata: () => { failMetadata = true; }, enableMetadata: () => { failMetadata = false; } };
}

describe('M11 fixed Recycle writer, unregistered source boundary', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'de'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());
  it('fails closed without bootstrap, rejects replacement and never accepts client shaped or forged handles', async () => {
    const f = fixture(); await expect(f.writer.archive({} as any)).rejects.toMatchObject({ response: { code: 'ENTITY_PREPARED_RECYCLE_UNAVAILABLE' } });
    f.writer.installExecutionDelegate(f.delegate); expect(() => f.writer.installExecutionDelegate(f.delegate)).toThrow();
    await expect(f.writer.execute({ approved: true, sourceId } as any)).rejects.toMatchObject({ response: { code: 'TEST_UNISSUED_PACKET' } });
    await expect(f.writer.repair({ knownNativeComplete: true } as any)).rejects.toMatchObject({ response: { code: 'TEST_UNISSUED_REPAIR' } });
    expect(f.db.transaction).not.toHaveBeenCalled(); expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('stores the full encrypted Service→Route→Plugin archive independently before any actual mutation', async () => {
    const f = fixture(), plan = f.plan(); f.writer.installExecutionDelegate(f.delegate);
    const receipt = await f.writer.archive(f.issueArchive(plan));
    expect(receipt).toMatchObject({ entryId, nodeCount: 3, packetCount: 3, graphHmac: plan.obligation.graphHmac });
    const entry = f.committed.find(item => item.sql.startsWith('INSERT INTO recycle_entries'))!;
    expect(entry.sql).toContain('NULL)'); expect(entry.params).not.toContain(operationId);
    expect(f.secrets.decrypt(entry.params[10], `recycle:${entryId}`)).toEqual(plan.obligation.graph);
    expect(f.committed.filter(item => item.sql.startsWith('INSERT INTO recycle_nodes'))).toHaveLength(3);
    expect(f.calls.indexOf('link-archive')).toBeGreaterThan(f.calls.indexOf('archive-entry'));
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
    expect(JSON.stringify(receipt)).not.toContain('echo.example');
  });
  it('rejects missing graph packets, modified wire bytes, wrong native paths and unsupported implicit effects before writes', async () => {
    const f = fixture(); f.writer.installExecutionDelegate(f.delegate);
    const incomplete = f.plan(); incomplete.packets.pop(); (incomplete.obligation as any).packetKeys.pop();
    await expect(f.writer.archive(f.issueArchive(incomplete))).rejects.toMatchObject({ response: { code: 'ENTITY_PREPARED_RECYCLE_UNSUPPORTED' } });
    const adopted = f.plan(serviceGraph(), true); adopted.packets.pop(); adopted.obligation.packetKeys.pop();
    await expect(f.writer.execute(f.issuePacket(adopted).handle)).rejects.toMatchObject({ response: { code: 'ENTITY_PREPARED_RECYCLE_UNSUPPORTED' } });
    const wrongPath = f.plan(); wrongPath.packets[0].canonicalPath = `/services/${serviceId}`;
    await expect(f.writer.archive(f.issueArchive(wrongPath))).rejects.toMatchObject({ response: { code: 'ENTITY_PREPARED_RECYCLE_INVALID' } });
    const tampered = f.plan(serviceGraph(), true); tampered.packets[0].body!.tags = ['client-reencoded-tag'];
    await expect(f.writer.execute(f.issuePacket(tampered).handle)).rejects.toMatchObject({ response: { code: 'ENTITY_PREPARED_RECYCLE_INVALID' } });
    const special = f.plan(); special.obligation.graph.nodes[0].type = 'certificates'; special.obligation.graph.nodes[0].path = `/certificates/${serviceId}`;
    special.obligation.graphHmac = f.secrets.fingerprint(special.obligation.graph);
    // Relabeling a Service/Route/Plugin graph as a Certificate root violates the
    // KP-004 ordinary member catalog before the certificate shape unsupported path.
    await expect(f.writer.archive(f.issueArchive(special))).rejects.toMatchObject({ response: { code: 'ENTITY_ORDINARY_RECYCLE_CONTRACT_INVALID' } });
    expect(f.db.transaction).not.toHaveBeenCalled(); expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('keeps DELETE204 raw null, verifies the sole fixed GET404, and records node/index/audit only after native completion', async () => {
    const f = fixture(); f.writer.installExecutionDelegate(f.delegate); const { handle, grant } = f.issuePacket();
    const receipt = await f.writer.execute(handle);
    expect(f.kong.request.mock.calls).toEqual([[cid, 'DELETE', grant.packet.canonicalPath], [cid, 'GET', grant.packet.canonicalPath]]);
    expect(await f.mutations.execute.mock.results[0].value).toBeNull();
    expect(receipt).toMatchObject({ entryId, operationId, nativeId: pluginId, metadata: 'complete' });
    expect(f.calls.indexOf('link-node')).toBeGreaterThan(f.calls.indexOf('native-GET'));
    expect(f.committed.some(item => item.sql.startsWith('DELETE FROM entity_index'))).toBe(true);
    expect(f.audit.append).toHaveBeenCalledOnce();
  });
  it('reaches the final native guard and does not project a delete when its verification remains unknown', async () => {
    const f = fixture(); f.writer.installExecutionDelegate(f.delegate);
    f.kong.request.mockRejectedValueOnce(new ForbiddenException({ code: 'TEST_FINAL_NATIVE_GUARD_DENIED' }));
    await expect(f.writer.execute(f.issuePacket().handle)).rejects.toMatchObject({ response: { code: 'TEST_FINAL_NATIVE_GUARD_DENIED' } });
    f.kong.request.mockResolvedValueOnce(null).mockResolvedValueOnce({ id: pluginId });
    await expect(f.writer.execute(f.issuePacket().handle)).rejects.toMatchObject({ response: { code: 'ENTITY_RECYCLE_DELETE_NOT_VERIFIED' } });
    expect(f.delegate.linkNodeReceipt).not.toHaveBeenCalled(); expect(f.committed).toHaveLength(0);
  });
  it('restores Consumer plus all six fixed credential DAOs with original IDs, exact parent/body and trusted Basic plaintext', async () => {
    const f = fixture(), plan = f.plan(consumerGraph(), true); f.writer.installExecutionDelegate(f.delegate);
    for (let index = 0; index < plan.packets.length; index++) await f.writer.execute(f.issuePacket(plan, index).handle);
    expect(f.kong.request).toHaveBeenCalledTimes(7); expect(f.delegate.linkNodeReceipt).toHaveBeenCalledTimes(7);
    expect(f.mutations.execute.mock.calls[0][0].before).toBeUndefined();
    const credentials = f.committed.filter(item => item.sql.startsWith('INSERT INTO credential_refs')); expect(credentials).toHaveLength(6);
    for (const row of credentials) {
      const [, cluster, parent, kind, id, cipher] = row.params;
      const stored: any = f.secrets.decrypt(cipher, `credential:${cluster}:${parent}:${kind}:${id}`), packet = plan.packets.find(item => item.nativeId === id)!;
      expect(stored.rawInput).toEqual(packet.body); expect(stored.rawInput.consumer.id).toBe(consumerId);
      expect(f.secrets.fingerprint(stored.rawInput)).toBe(packet.bodyHmac);
      if (kind === 'basic-auth') { expect(stored.rawInput.password).toBe(consumerSecret); expect(stored.credential.password).toHaveLength(40); }
      expect(JSON.stringify(row.params[6])).not.toContain('unit-original-oauth-plaintext');
    }
    const hashesAsPlain = f.plan(consumerGraph(), true), basic = hashesAsPlain.obligation.graph.nodes.find(node => node.type === 'basic-auth')!;
    basic.restoreData.password = basic.data.password; hashesAsPlain.obligation.graphHmac = f.secrets.fingerprint(hashesAsPlain.obligation.graph);
    // Keep sealed payloadHmac aligned so the ordinary sealed-match assert does not
    // mask the Basic hash-as-plaintext rejection inside prepared packet derivation.
    (hashesAsPlain.obligation as any).sealedEntry.payloadHmac = hashesAsPlain.obligation.graphHmac;
    const packet = hashesAsPlain.packets.find(item => item.nativeType === 'basic-auth')!;
    packet.body = { ...packet.body!, password: basic.data.password }; packet.bodyHmac = f.secrets.fingerprint(packet.body);
    await expect(f.writer.execute(f.issuePacket(hashesAsPlain).handle)).rejects.toMatchObject({ response: { code: 'ENTITY_PREPARED_RECYCLE_INVALID' } });
    expect(f.kong.request).toHaveBeenCalledTimes(7);
  });
  it('rolls metadata back safely, accepts only privately issued original-result repair, and never calls native from repair', async () => {
    const f = fixture(), prepared = f.plan(consumerGraph(), true), { handle, grant } = f.issuePacket(prepared, 2);
    f.writer.installExecutionDelegate(f.delegate); f.failMetadata(); let failure: any;
    try { await f.writer.execute(handle); } catch (error) { failure = error; }
    expect(failure.getResponse()).toMatchObject({ code: 'ENTITY_RECYCLE_METADATA_INCOMPLETE', knownNativeComplete: true, operationId });
    expect(JSON.stringify(failure.getResponse())).not.toContain(consumerSecret); expect(f.committed).toHaveLength(0);
    const originalResult = { ...grant.packet.body, password: createHash('sha1').update(consumerSecret + consumerId).digest('hex') };
    f.enableMetadata(); const repair = await f.writer.repair(f.issueRepair(grant, originalResult));
    expect(repair).toMatchObject({ operationId, nativeId: grant.packet.nativeId, metadata: 'complete' });
    expect(f.mutations.execute).toHaveBeenCalledOnce(); expect(f.kong.request).toHaveBeenCalledOnce();
    expect(f.committed.filter(item => item.sql.startsWith('INSERT INTO credential_refs'))).toHaveLength(1);
  });
  it('does not use a completed Mutation replay return as private native proof and never resends', async () => {
    const f = fixture(); f.writer.installExecutionDelegate(f.delegate);
    f.mutations.execute.mockImplementationOnce(async () => null);
    await expect(f.writer.execute(f.issuePacket().handle)).rejects.toMatchObject({ response: { code: 'ENTITY_RECYCLE_METADATA_RECOVERY_REQUIRED' } });
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.delegate.linkNodeReceipt).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled();
  });
  it('rejects actual-result credential mismatches even on an issued metadata-only repair handle', async () => {
    const f = fixture(), prepared = f.plan(consumerGraph(), true); f.writer.installExecutionDelegate(f.delegate);
    for (const kind of ['basic-auth', 'oauth2']) {
      const index = prepared.packets.findIndex(packet => packet.nativeType === kind), { grant } = f.issuePacket(prepared, index);
      const result = { ...grant.packet.body, ...(kind === 'basic-auth' ? { password: 'a'.repeat(40) } : { client_secret: 'different-original-response' }) };
      await expect(f.writer.repair(f.issueRepair(grant, result))).rejects.toMatchObject({ response: { code: 'ENTITY_RECYCLE_CREDENTIAL_RESULT_MISMATCH', knownNativeComplete: true } });
    }
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.mutations.execute).not.toHaveBeenCalled();
    expect(f.delegate.linkNodeReceipt).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled();
  });
});
