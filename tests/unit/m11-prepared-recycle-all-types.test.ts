import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { EntityPreparedRecycleWriterService, derivePreparedRecyclePackets, preparedRecycleNodeManifest } from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.service';
import type { GraphNode, RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import type { EntityChangePacket } from '../../apps/console-api/src/modules/entities/entity-change.types';
import { RecycleService, recycleName } from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import { entityForPath } from '../../apps/console-api/src/infrastructure/kong/policy';
import { executionFixture } from './execution-test-fixture';
import { defaultWorkspaceId, workspaceFixture } from './workspace-test-fixture';
import type { PreparedRecycleObligation } from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.types';

// Controlled fixed-writer fixtures only. No real SQL, current approval, SDK
// transport, V2 poststate or native authority is claimed by this suite.
const cid = randomUUID(), wid = randomUUID(), actorId = randomUUID(), sourceId = randomUUID(), entryId = randomUUID();
const upstreamId = randomUUID(), targetId = randomUUID(), certificateId = randomUUID(), sniId = randomUUID();
const coreTypes = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis'] as const;
const node = (type: string, id: string, body: any, affected = true, dependencies: string[] = [], parent?: string): GraphNode => ({
  key: `${type}:${id}`, type, id, path: parent ? `/upstreams/${parent}/targets/${id}` : `/${type}/${id}`,
  data: { id, ...body }, restoreData: { id, ...body }, restorable: true, affected, dependencies,
});
function graph(type: string, children = true): RecycleGraph {
  let nodes: GraphNode[];
  if (type === 'targets' || type === 'upstreams') {
    const parent = node('upstreams', upstreamId, { name: 'upstream.example', tags: ['kos-ws-default'] }, type === 'upstreams');
    const target = node('targets', targetId, { target: 'echo.example:80', weight: 100, upstream: { id: upstreamId } }, true, [parent.key], upstreamId);
    nodes = type === 'upstreams' && !children ? [parent] : [parent, target];
    return { complete: true, purpose: 'recycle', capturedAt: new Date().toISOString(), rootKey: type === 'targets' ? target.key : parent.key, nodes,
      ...(type === 'upstreams' ? { targetHistory: [{ upstreamId, items: [{ ...target.data }] }] } : {}) };
  }
  if (type === 'certificates' || type === 'snis') {
    const parent = node('certificates', certificateId, { cert: 'unit-cert-pem', key: 'unit-private-key', snis: ['api.example'], tags: [] }, type === 'certificates');
    const sni = node('snis', sniId, { name: 'api.example', certificate: { id: certificateId }, tags: [] }, true, [parent.key]);
    nodes = type === 'certificates' && !children ? [parent] : [parent, sni];
    if (type === 'certificates' && !children) { parent.data.snis = []; parent.restoreData.snis = []; }
    return { complete: true, purpose: 'recycle', capturedAt: new Date().toISOString(), rootKey: type === 'snis' ? sni.key : parent.key, nodes };
  }
  const id = randomUUID(), body = type === 'ca_certificates' ? { cert: 'unit-ca-pem', tags: [] }
    : type === 'services' ? { name: 'service', host: 'echo.example', retries: 5, tags: [] }
      : type === 'routes' ? { name: 'route', paths: ['/unit'], tags: [] }
        : type === 'consumers' ? { username: 'consumer', tags: [] }
          : { name: 'cors', config: {}, tags: [] };
  const root = node(type, id, body);
  return { complete: true, purpose: 'recycle', capturedAt: new Date().toISOString(), rootKey: root.key, nodes: [root] };
}
function ordered(g: RecycleGraph): GraphNode[] {
  const result: GraphNode[] = [], seen = new Set<string>();
  const visit = (n: GraphNode) => { if (seen.has(n.key)) return; for (const key of n.dependencies) visit(g.nodes.find(x => x.key === key)!); seen.add(n.key); result.push(n); };
  g.nodes.forEach(visit); return result;
}
function prepare(g: RecycleGraph, restoring: boolean, secrets: SecretService, replacement?: string) {
  const affected = ordered(g).filter(n => n.affected), keys = new Map<string, string>();
  const packets: EntityChangePacket[] = (restoring ? affected : [...affected].reverse()).map((n, i) => {
    const parentId = n.type === 'targets' ? upstreamId : undefined;
    const newId = replacement && n.type === 'targets' ? replacement : n.id;
    const before = restoring ? null : structuredClone(n.data);
    if (!restoring && n.type === 'certificates') {
      const removed = new Set(g.nodes.filter(child => child.affected && child.type === 'snis' && child.dependencies.includes(n.key) && keys.has(child.key)).map(child => child.data.name));
      before.snis = before.snis.filter((name: string) => !removed.has(name));
    }
    const body = restoring ? structuredClone(n.restoreData) : undefined;
    if (body) { delete body.created_at; delete body.updated_at; delete body.ttl;
      if (n.type === 'certificates') delete body.snis;
      if (n.type === 'targets') { body.id = newId; delete body.upstream; } }
    const packet: EntityChangePacket = { key: `packet-${i + 1}`, order: i + 1, nativeType: n.type, nativeId: newId,
      ...(parentId ? { parentId } : {}), ...(newId !== n.id ? { originalNativeId: n.id } : {}), method: restoring ? 'POST' : 'DELETE',
      canonicalPath: restoring ? n.path.replace(/\/[^/]+$/, '') : n.path, permissionAction: restoring ? 'write' : 'delete', mutationAction: restoring ? 'restore' : 'delete',
      before, ...(body ? { body } : {}), beforeHmac: secrets.fingerprint(before), bodyHmac: secrets.fingerprint(body ?? null),
      dependencies: restoring ? n.dependencies.flatMap(dep => keys.get(dep) ?? []) : g.nodes.filter(child => child.affected && child.dependencies.includes(n.key)).flatMap(child => keys.get(child.key) ?? []) };
    keys.set(n.key, packet.key); return packet;
  });
  const common = { graph: g, graphHmac: secrets.fingerprint(g), packetKeys: packets.map(p => p.key) };
  const obligation: PreparedRecycleObligation = restoring ? { ...common, kind: 'recycle-restore', entryId, sealedEntry: {
    clusterId: cid, workspaceId: wid, entryId, state: 'deleted', expiresAt: '2099-01-01T00:00:00Z', payloadHmac: common.graphHmac,
    nodeManifestHmac: secrets.fingerprint(preparedRecycleNodeManifest(g, secrets)), restoreMaterialHmac: 'a'.repeat(64) } } : { ...common, kind: 'recycle-archive' };
  return { obligation, packets };
}
function fixture() {
  const secrets = new SecretService(), statements: { sql: string; params: any[] }[] = [], archiveHandles = new WeakMap<object, any>(), packetHandles = new WeakMap<object, any>();
  const operationId = randomUUID(), tx: any = { exec: vi.fn(async (sql, params) => { statements.push({ sql, params }); return 1; }) };
  const db: any = { transaction: vi.fn(async fn => fn(tx)) }, audit = { append: vi.fn(async () => undefined) };
  const kong = { request: vi.fn(async (_cid: string, method: string, path: string, body?: any) => {
    if (method === 'DELETE') return null;
    if (method === 'GET') throw new NotFoundException();
    return { ...body, ...(path.endsWith('/targets') ? { upstream: { id: upstreamId } } : {}), ...(path === '/certificates' ? { snis: [] } : {}) };
  }),
    // Kong 1.5 Target DELETE poststate: native-pruned empty history/effective EOF.
    list: vi.fn(async (_cid: string, _path: string, q: any) => ({ items: [], size: q.size, nextCursor: null })),
  };
  const mutations = { execute: vi.fn(async (context: any, fn: any) => { context.operationId = operationId; return fn(); }) };
  const writer = new EntityPreparedRecycleWriterService(db, mutations as any, kong as any, secrets, audit as any);
  const readGrant = (map: WeakMap<object, any>, handle: object) => { const grant = map.get(handle); if (!grant) throw new Error('UNISSUED_HANDLE'); return grant; };
  const delegate: any = { runArchive: async (h, fn) => fn(readGrant(archiveHandles, h)), runPacket: async (h, fn) => fn(readGrant(packetHandles, h)),
    runRepair: async () => { throw new Error('UNISSUED_HANDLE'); }, linkArchive: vi.fn(async () => undefined),
    verifyCurrentRestore:async()=>undefined, // Explicit controlled readback adapter; no current witness authority claimed.
    runVerifiedDelete: async (h, _id, fn) => { readGrant(packetHandles, h); return fn(); }, runVerificationRead: async (h, _id, fn) => { readGrant(packetHandles, h); return fn(); },
    recordTargetDeletePoststate: () => undefined,
    linkNodeReceipt: vi.fn(async () => undefined) };
  writer.installExecutionDelegate(delegate);
  const binding = { source: { id: sourceId, clusterId: cid, workspaceId: wid, workflowId: randomUUID(), workflowExecutionId: randomUUID(), executionActorId: actorId },
    baseline: { baselineId: randomUUID(), sourceId, pinId: randomUUID() }, actor: { user: { id: actorId }, workspaceId: wid } };
  function issue(prepared: ReturnType<typeof prepare>, index?: number) {
    const handle = Object.freeze({}), shared = { ...binding, entryId, ...prepared };
    if (index === undefined) archiveHandles.set(handle, { ...shared, expiresAt: '2099-01-01T00:00:00Z' });
    else { const packet = prepared.packets[index], n = prepared.obligation.graph.nodes.find(n => n.type === packet.nativeType && n.id === (packet.originalNativeId ?? packet.nativeId)) ?? prepared.obligation.graph.nodes.find(n => n.key === prepared.obligation.graph.rootKey)!;
      packetHandles.set(handle, { ...shared, packet, nodeKey: n.key, operationKey: `original-${index + 1}` }); }
    return handle as any;
  }
  return { secrets, writer, issue, statements, db, kong, mutations, delegate };
}

async function actualPreparation(g: RecycleGraph, restoring: boolean, secrets: SecretService) {
  const root = g.nodes.find(n => n.key === g.rootKey)!, remote = new Map(g.nodes.map(n => [n.path, structuredClone(n.data)]));
  if (restoring) {
    for (const n of g.nodes) if (n.affected) remote.delete(n.path);
    // A surviving parent Certificate has already lost the archived SNI.
    for (const n of g.nodes) if (n.type === 'certificates' && !n.affected) remote.get(n.path).snis = [];
  }
  const restoreEntryId = randomUUID(), oldMutationId = randomUUID(), entry = { id: restoreEntryId, cluster_id: cid,
    workspace_id: defaultWorkspaceId, root_type: root.type, original_id: root.id, root_name: recycleName(root), state: 'deleted',
    parent_id: root.type === 'targets' ? upstreamId : null, credential_kind: null, mutation_id: oldMutationId,
    node_count: g.nodes.length, created_at: new Date(), expires_at: new Date(Date.now() + 86400000),
    payload_secret: secrets.encrypt(g, `recycle:${restoreEntryId}`) };
  const statuses = g.nodes.map(n => ({ node_key: n.key, entity_type: n.type, original_id: n.id, affected: n.affected,
    dependencies: n.dependencies, delete_state: n.affected ? 'deleted' : 'reference', restore_state: n.affected ? 'pending' : 'reference', restored_id: null }));
  const db: any = { one: vi.fn(async (sql: string) => sql.includes('FROM clusters') ? { admin_url: 'http://kong:8001', transport_scope: 'fixed', revision: 1, version: '1.5.1', status: 'healthy' }
    : sql.includes('FROM recycle_entries') ? entry : null),
    query: vi.fn(async (sql: string) => sql.includes('FROM recycle_nodes') ? statuses
      : sql.includes("'mutation'::text AS kind") ? [{ kind: 'mutation', id: oldMutationId, state: 'succeeded', workspace_id: defaultWorkspaceId,
        workflow_id: null, workflow_state: null, execution_state: null, unresolved_steps: false }] : []),
    exec: vi.fn(async () => { throw new Error('Unexpected business write'); }), transaction: vi.fn(async () => { throw new Error('Unexpected business transaction'); }) };
  const schema = { fields: [{ id: { type: 'string' } }] }, kong: any = {
    request: vi.fn(async (_cid: string, method: string, path: string) => { if (method !== 'GET') throw new Error('Unexpected native write');
      if (!remote.has(path)) throw new NotFoundException(); return structuredClone(remote.get(path)); }),
    list: vi.fn(async (_cid: string, path: string) => ({ items: restoring ? [] : [...remote.entries()]
      .filter(([key, value]) => key.startsWith(path + '/') && value.weight > 0).map(([, value]) => structuredClone(value)), nextCursor: null, size: 100 })),
    schema: vi.fn(async () => schema), pluginSchema: vi.fn(async () => schema),
    prepareSchema: vi.fn(async (_cid: string, path: string, body: unknown) => ({ version: 1, clusterId: cid, canonicalPath: path,
      nativeType: entityForPath(path), kongVersion: '1.5.1', adapter: 'kong-oss-1.5-v1', clusterRevision: 1, payloadHmac: secrets.fingerprint(body ?? null),
      schemaMaterial: { entity: { name: entityForPath(path), canonicalPath: `/schemas/${entityForPath(path)}`, schema } } })) };
  const authz: any = { assertEntity: vi.fn(), assertArchivedEntity: vi.fn(), assertNestedParentScope: vi.fn() }, capturer: any = { capture: vi.fn(async () => structuredClone(g)) };
  const unused: any = {}, workspaces = workspaceFixture(cid), recycle = new RecycleService(db, secrets, kong, unused, capturer, authz, unused, unused, unused,
    workspaces.resolver, executionFixture());
  const actor: any = { user: { id: actorId, username: 'owner', superAdmin: true }, workspaceId: defaultWorkspaceId };
  const request: any = restoring ? { kind: 'recycle', action: 'restore', entryId: restoreEntryId, confirmed: true, confirm_name: recycleName(root) }
    : { kind: 'recycle', action: 'delete', entityType: root.type, entityId: root.id, ...(root.type === 'targets' ? { parentId: upstreamId } : {}),
      confirmed: true, confirm_name: recycleName(root) };
  const prepared = await recycle.prepareEntityChange(cid, request, actor);
  expect(kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
  expect(db.exec).not.toHaveBeenCalled(); expect(db.transaction).not.toHaveBeenCalled();
  return { obligation: prepared.metadataObligations.find(o => o.kind === (restoring ? 'recycle-restore' : 'recycle-archive'))! as PreparedRecycleObligation,
    packets: prepared.packets };
}

describe('M11 prepared recycle complete entity set, fixed explicit packets', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());
  for (const type of [...coreTypes, 'targets']) {
    for (const restoring of [false, true]) it(`${type}: actual RecycleService ${restoring ? 'restore' : 'delete'} compiler output is accepted without any authority or wire write`, async () => {
      const f = fixture(), prepared = await actualPreparation(graph(type), restoring, f.secrets);
      expect(derivePreparedRecyclePackets(prepared.obligation, prepared.packets, f.secrets).map(x => x.packet)).toEqual(prepared.packets);
    });
    it(`${type}: accepts only the complete original archive graph before any mutation`, async () => {
      const f = fixture(), p = prepare(graph(type), false, f.secrets);
      const result = await f.writer.archive(f.issue(p));
      expect(result.packetCount).toBe(p.packets.length);
      expect(f.kong.request).not.toHaveBeenCalled(); expect(f.mutations.execute).not.toHaveBeenCalled();
      const stored = f.statements.find(s => s.sql.startsWith('INSERT INTO recycle_entries'))!;
      expect(f.secrets.decrypt(stored.params[10], `recycle:${entryId}`)).toEqual(p.obligation.graph);
      expect(f.statements.filter(s => s.sql.startsWith('INSERT INTO recycle_nodes'))).toHaveLength(p.obligation.graph.nodes.length);
    });
    it(`${type}: DELETE has raw 204 then Target poststate lists or GET404 before completion`, async () => {
      const f = fixture(), p = prepare(graph(type), false, f.secrets);
      for (let i = 0; i < p.packets.length; i++) await f.writer.execute(f.issue(p, i));
      expect(f.delegate.linkNodeReceipt).toHaveBeenCalledTimes(p.packets.length);
      const deletes = f.kong.request.mock.calls.filter((c: any[]) => c[1] === 'DELETE');
      expect(deletes).toHaveLength(p.packets.length);
      for (let i = 0; i < p.packets.length; i++) {
        expect(deletes[i].slice(1)).toEqual(['DELETE', p.packets[i].canonicalPath]);
        if (p.packets[i].nativeType === 'targets') {
          // Four parent-scoped list EOFs; never certify Target DELETE via GET404.
          expect(f.kong.list).toHaveBeenCalled();
          expect(f.kong.request.mock.calls.some((c: any[]) => c[1] === 'GET' && c[2] === p.packets[i].canonicalPath)).toBe(false);
        } else {
          expect(f.kong.request.mock.calls.some((c: any[]) => c[1] === 'GET' && c[2] === p.packets[i].canonicalPath)).toBe(true);
        }
      }
      if (p.packets.some(packet => packet.nativeType === 'targets')) {
        expect(f.kong.list.mock.calls.length).toBe(p.packets.filter(packet => packet.nativeType === 'targets').length * 4);
      }
    });
    it(`${type}: restores explicit members in dependency order with their sealed native IDs`, async () => {
      const f = fixture(), p = prepare(graph(type), true, f.secrets);
      for (let i = 0; i < p.packets.length; i++) await f.writer.execute(f.issue(p, i));
      expect(f.kong.request).toHaveBeenCalledTimes(p.packets.length);
      for (let i = 0; i < p.packets.length; i++) expect(f.kong.request.mock.calls[i]).toEqual([cid, 'POST', p.packets[i].canonicalPath, p.packets[i].body]);
      expect(f.delegate.linkNodeReceipt).toHaveBeenCalledTimes(p.packets.length);
    });
  }
  it('certificate: child SNI DELETE precedes parent, and only those completed names leave the sealed before', () => {
    const f = fixture(), p = prepare(graph('certificates'), false, f.secrets);
    const parsed = derivePreparedRecyclePackets(p.obligation, p.packets, f.secrets);
    expect(parsed.map(x => x.packet.nativeType)).toEqual(['snis', 'certificates']);
    expect(parsed[1].packet.before).toMatchObject({ snis: [] });
    expect(p.obligation.graph.nodes.find(n => n.type === 'certificates')!.data.snis).toEqual(['api.example']);
    p.packets[1].before = { ...p.packets[1].before, snis: ['api.example'] }; p.packets[1].beforeHmac = f.secrets.fingerprint(p.packets[1].before);
    expect(() => derivePreparedRecyclePackets(p.obligation, p.packets, f.secrets)).toThrow();
  });
  it('certificate: restore never supplies implicit SNI create effects', () => {
    const f = fixture(), p = prepare(graph('certificates'), true, f.secrets);
    expect(p.packets.map(p => p.nativeType)).toEqual(['certificates', 'snis']); expect(p.packets[0].body).not.toHaveProperty('snis');
    p.packets[0].body!.snis = ['client-invented.example']; p.packets[0].bodyHmac = f.secrets.fingerprint(p.packets[0].body);
    expect(() => derivePreparedRecyclePackets(p.obligation, p.packets, f.secrets)).toThrow();
  });
  it('Target replacement keeps original graph UUID but returns only its sealed newly allocated native ID', async () => {
    const f = fixture(), replacement = randomUUID(), p = prepare(graph('targets'), true, f.secrets, replacement);
    const parsed = derivePreparedRecyclePackets(p.obligation, p.packets, f.secrets);
    expect(parsed[0].node.id).toBe(targetId); expect(parsed[0].packet.nativeId).toBe(replacement); expect(parsed[0].packet.originalNativeId).toBe(targetId);
    const result = await f.writer.execute(f.issue(p, 0)); expect(result.nativeId).toBe(replacement);
    expect(f.kong.request.mock.calls[0][3]).toMatchObject({ id: replacement, target: 'echo.example:80', weight: 100 });
    expect(f.kong.request.mock.calls[0][3]).not.toHaveProperty('upstream');
    expect(f.statements.some(s => /(?:INSERT INTO|DELETE FROM) entity_index/.test(s.sql))).toBe(false);
    expect(f.statements.find(s => s.sql.startsWith('UPDATE recycle_nodes'))!.params[2]).toBe(replacement);
  });
  it('Target archive uses target address for confirmation and retains history privately', async () => {
    const f = fixture(), p = prepare(graph('targets'), false, f.secrets); await f.writer.archive(f.issue(p));
    expect(f.statements.find(s => s.sql.startsWith('INSERT INTO recycle_entries'))!.params[6]).toBe('echo.example:80');
  });
  it('Target result checks upstream relation instead of consumer relation and rejects wrong parents before metadata', async () => {
    const f = fixture(), p = prepare(graph('targets'), true, f.secrets, randomUUID());
    f.kong.request.mockResolvedValueOnce({ ...p.packets[0].body, upstream: { id: randomUUID() }, consumer: { id: upstreamId } });
    await expect(f.writer.execute(f.issue(p, 0))).rejects.toMatchObject({ response: { code: 'ENTITY_RECYCLE_NATIVE_RESULT_MISMATCH' } });
    expect(f.delegate.linkNodeReceipt).not.toHaveBeenCalled(); expect(f.db.transaction).not.toHaveBeenCalled();
  });
  for (const flaw of ['foreign-parent', 'foreign-original', 'delete-replacement', 'certificate-hidden-field', 'wrong-packet-order', 'omitted-child', 'unaffected-parent-deletion']) {
    it(`rejects ${flaw} without making any native call`, async () => {
      const f = fixture(), cert = flaw.startsWith('certificate') || flaw === 'wrong-packet-order' || flaw === 'omitted-child';
      const p = prepare(graph(cert ? 'certificates' : 'targets'), flaw !== 'delete-replacement', f.secrets, flaw === 'foreign-original' ? randomUUID() : undefined);
      if (flaw === 'foreign-parent') p.packets[0].parentId = randomUUID();
      if (flaw === 'foreign-original') p.packets[0].originalNativeId = randomUUID();
      if (flaw === 'delete-replacement') p.packets[0].originalNativeId = targetId;
      if (flaw === 'certificate-hidden-field') { p.packets[0].body!.snis = []; p.packets[0].bodyHmac = f.secrets.fingerprint(p.packets[0].body); }
      if (flaw === 'wrong-packet-order') p.packets.reverse();
      if (flaw === 'omitted-child') { p.packets.pop(); p.obligation.packetKeys.pop(); }
      if (flaw === 'unaffected-parent-deletion') { p.obligation.graph.nodes[0].affected = true; p.obligation.graphHmac = f.secrets.fingerprint(p.obligation.graph); }
      await expect(f.writer.execute(f.issue(p, 0))).rejects.toThrow(); expect(f.kong.request).not.toHaveBeenCalled(); expect(f.mutations.execute).not.toHaveBeenCalled();
    });
  }
  for (const flaw of ['sni-certificate', 'target-address', 'target-weight', 'target-restore-parent']) {
    it(`rejects ${flaw} drift in encrypted restoration data even with resealed body and graph hashes`, () => {
      const f = fixture(), g = graph(flaw === 'sni-certificate' ? 'snis' : 'targets');
      const affected = g.nodes.find(n => n.key === g.rootKey)!;
      if (flaw === 'sni-certificate') affected.restoreData.certificate = { id: randomUUID() };
      if (flaw === 'target-address') affected.restoreData.target = 'different.example:80';
      if (flaw === 'target-weight') affected.restoreData.weight = 0;
      if (flaw === 'target-restore-parent') affected.restoreData.upstream = { id: randomUUID() };
      const p = prepare(g, true, f.secrets);
      expect(() => derivePreparedRecyclePackets(p.obligation, p.packets, f.secrets)).toThrow();
    });
  }
  it('never adopts a parent204 as a child completion or silently accepts an unissued handle', async () => {
    const f = fixture(); await expect(f.writer.execute({} as any)).rejects.toThrow('UNISSUED_HANDLE');
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.delegate.linkNodeReceipt).not.toHaveBeenCalled();
  });
});
