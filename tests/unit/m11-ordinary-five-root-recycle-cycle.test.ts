import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { EntityPreparedRecycleWriterService } from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.service';
import {
  ORDINARY_CREDENTIAL_KINDS, ORDINARY_RECYCLE_ROOT_TYPES,
  assertOrdinaryDeleteRestorePacketCoverage, assertOrdinarySealedRestoreMatchesArchive,
  isOrdinaryCredentialKind,
} from '../../apps/console-api/src/modules/recycle-bin/ordinary-recycle-contract';
import type { RecycleGraph, GraphNode } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import type { EntityChangePacket } from '../../apps/console-api/src/modules/entities/entity-change.types';
import type {
  PreparedRecycleObligation, EntityPreparedRecycleWriterDelegate,
  EntityPreparedRecycleArchiveGrant, EntityPreparedRecycleArchiveHandle,
  EntityPreparedRecyclePacketGrant, EntityPreparedRecyclePacketHandle,
} from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.types';
import { preparedRecycleNodeManifest } from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.service';

/**
 * KP-004: joint five-root delete→archive→original-ID restore through the
 * prepared writer with Kong mocks (no live Kong). Intent packets + archive
 * receipt + native DELETE + Target poststate/GET404 + restore POST + credential custody readback.
 */

const cid = 'a949b292-2e4a-4326-b30d-3a883b5ef3d7';
const wid = '306a8d36-d1f9-4542-8972-9b30aa1bd67c';
const actorId = 'cc2019b5-8061-4a3c-bc19-f24c586e00fa';
const sourceId = '230d1596-a1a3-4e15-ab89-90f254bb52ea';
const baselineId = 'e05a8c85-6e79-4e01-b9b5-6f5a1302a8ea';
const pinId = '5c1f22a1-f228-41de-a3ad-cb2a9ef16b51';
const executionId = 'd933aefa-851b-4d42-bc29-d79770f2c8c1';
const entryId = '25ed6944-c79e-4b46-8c48-d5d6e716121d';
const operationId = 'f8cae52b-226e-4b39-a157-13a4a743441b';
const consumerSecret = 'unit-trusted-basic-password';

function node(type: string, id: string, body: Record<string, unknown>, deps: string[] = [], parent?: { type: string; id: string }): GraphNode {
  const path = parent
    ? `/${parent.type === 'upstreams' ? 'upstreams' : 'consumers'}/${parent.id}/${type === 'targets' ? 'targets' : type}/${id}`
    : `/${type}/${id}`;
  return {
    key: parent ? `${type}:${parent.id}:${id}` : `${type}:${id}`, type, id, path,
    data: { id, ...body }, restoreData: { id, ...body }, restorable: true, affected: true, dependencies: deps,
  };
}

function ordinaryGraph(type: typeof ORDINARY_RECYCLE_ROOT_TYPES[number]): RecycleGraph {
  if (type === 'consumers') {
    const consumerId = randomUUID();
    const root = node('consumers', consumerId, { username: 'cycle-consumer', tags: ['kos-ws-pay'] });
    const nodes: GraphNode[] = [root];
    ORDINARY_CREDENTIAL_KINDS.forEach((kind, index) => {
      const id = `70000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`;
      const data: Record<string, unknown> = { consumer: { id: consumerId }, tags: root.data.tags };
      if (kind === 'key-auth') data.key = 'cycle-key';
      if (kind === 'basic-auth') {
        data.username = 'cycle-basic';
        data.password = createHash('sha1').update(consumerSecret + consumerId).digest('hex');
      }
      if (kind === 'jwt') { data.key = 'cycle-jwt'; data.secret = 'cycle-jwt-secret'; data.algorithm = 'HS256'; }
      if (kind === 'oauth2') { data.name = 'cycle-oauth'; data.client_id = 'cid'; data.client_secret = 'cycle-oauth-plain'; }
      if (kind === 'hmac-auth') { data.username = 'cycle-hmac'; data.secret = 'cycle-hmac-secret'; }
      if (kind === 'acls') data.group = 'cycle-group';
      const child = node(kind, id, data, [root.key], { type: 'consumers', id: consumerId });
      if (kind === 'basic-auth') child.restoreData = { ...child.restoreData, password: consumerSecret };
      nodes.push(child);
    });
    return { complete: true, purpose: 'recycle', capturedAt: '2026-10-24T04:00:00Z', rootKey: root.key, nodes };
  }
  if (type === 'upstreams') {
    const upstreamId = randomUUID(), targetId = randomUUID();
    const parent = node('upstreams', upstreamId, { name: 'cycle-up', tags: [] });
    const target = node('targets', targetId, { target: 'echo:80', weight: 100, upstream: { id: upstreamId } }, [parent.key], { type: 'upstreams', id: upstreamId });
    return { complete: true, purpose: 'recycle', capturedAt: '2026-10-24T04:00:00Z', rootKey: parent.key, nodes: [parent, target],
      targetHistory: [{ upstreamId, items: [{ ...target.data }] }] };
  }
  if (type === 'certificates') {
    const certificateId = randomUUID(), sniId = randomUUID();
    const parent = node('certificates', certificateId, { cert: 'CERT', key: 'KEY', snis: ['cycle.example'], tags: [] });
    const sni = node('snis', sniId, { name: 'cycle.example', certificate: { id: certificateId }, tags: [] }, [parent.key]);
    return { complete: true, purpose: 'recycle', capturedAt: '2026-10-24T04:00:00Z', rootKey: parent.key, nodes: [parent, sni] };
  }
  if (type === 'services') {
    const serviceId = randomUUID(), routeId = randomUUID(), pluginId = randomUUID();
    const service = node('services', serviceId, { name: 'cycle-svc', host: 'echo.example', tags: [] });
    const route = node('routes', routeId, { name: 'cycle-rt', paths: ['/cycle'], service: { id: serviceId }, tags: [] }, [service.key]);
    const plugin = node('plugins', pluginId, { name: 'cors', service: { id: serviceId }, config: {}, tags: [] }, [service.key]);
    return { complete: true, purpose: 'recycle', capturedAt: '2026-10-24T04:00:00Z', rootKey: service.key, nodes: [service, route, plugin] };
  }
  const routeId = randomUUID(), pluginId = randomUUID(), serviceId = randomUUID();
  const service = { ...node('services', serviceId, { name: 'shared', host: 'echo', tags: [] }), affected: false, restoreData: undefined as any };
  delete (service as any).restoreData;
  const route = node('routes', routeId, { name: 'cycle-route', paths: ['/r'], service: { id: serviceId }, tags: [] }, [service.key]);
  const plugin = node('plugins', pluginId, { name: 'key-auth', route: { id: routeId }, config: { key_names: ['apikey'] }, tags: [] }, [route.key]);
  return { complete: true, purpose: 'recycle', capturedAt: '2026-10-24T04:00:00Z', rootKey: route.key, nodes: [service, route, plugin] };
}

function ordered(g: RecycleGraph): GraphNode[] {
  const result: GraphNode[] = [], seen = new Set<string>();
  const visit = (n: GraphNode) => { if (seen.has(n.key)) return; for (const key of n.dependencies) visit(g.nodes.find(x => x.key === key)!); seen.add(n.key); result.push(n); };
  g.nodes.forEach(visit); return result;
}

function plan(secrets: SecretService, graph: RecycleGraph, restoring: boolean): { obligation: PreparedRecycleObligation; packets: EntityChangePacket[] } {
  const affected = ordered(graph).filter(n => n.affected), keys = new Map<string, string>();
  const packets: EntityChangePacket[] = (restoring ? affected : [...affected].reverse()).map((n, i) => {
    const parentId = n.type === 'targets' || isOrdinaryCredentialKind(n.type)
      ? (n.type === 'targets' ? graph.nodes.find(x => x.type === 'upstreams')!.id : graph.nodes.find(x => x.type === 'consumers')!.id)
      : undefined;
    const before = restoring ? null : structuredClone(n.data);
    if (!restoring && n.type === 'certificates') {
      const removed = new Set(graph.nodes.filter(child => child.affected && child.type === 'snis' && child.dependencies.includes(n.key) && keys.has(child.key)).map(child => child.data.name));
      before.snis = before.snis.filter((name: string) => !removed.has(name));
    }
    const body = restoring ? structuredClone(n.restoreData) : undefined;
    if (body) {
      delete body.created_at; delete body.updated_at; delete body.ttl;
      if (n.type === 'certificates') delete body.snis;
      if (n.type === 'targets') delete body.upstream;
    }
    const packet: EntityChangePacket = {
      key: `packet-${i + 1}`, order: i + 1, nativeType: n.type, nativeId: n.id,
      ...(parentId ? { parentId } : {}), ...(isOrdinaryCredentialKind(n.type) ? { credentialKind: n.type } : {}),
      method: restoring ? 'POST' : 'DELETE',
      canonicalPath: restoring ? n.path.replace(/\/[^/]+$/, '') : n.path,
      permissionAction: restoring ? 'write' : 'delete', mutationAction: restoring ? 'restore' : 'delete',
      before, ...(body ? { body } : {}), beforeHmac: secrets.fingerprint(before), bodyHmac: secrets.fingerprint(body ?? null),
      dependencies: restoring
        ? n.dependencies.flatMap(dep => keys.get(dep) ?? [])
        : graph.nodes.filter(child => child.affected && child.dependencies.includes(n.key)).flatMap(child => keys.get(child.key) ?? []),
    };
    keys.set(n.key, packet.key); return packet;
  });
  const common = { graph, graphHmac: secrets.fingerprint(graph), packetKeys: packets.map(p => p.key) };
  const obligation: PreparedRecycleObligation = restoring
    ? { ...common, kind: 'recycle-restore', entryId, sealedEntry: {
      clusterId: cid, workspaceId: wid, entryId, state: 'deleted', expiresAt: '2099-01-01T00:00:00Z',
      payloadHmac: common.graphHmac, nodeManifestHmac: secrets.fingerprint(preparedRecycleNodeManifest(graph, secrets)), restoreMaterialHmac: 'a'.repeat(64) } }
    : { ...common, kind: 'recycle-archive' };
  return { obligation, packets };
}

function fixture() {
  const secrets = new SecretService();
  const archiveHandles = new WeakMap<object, EntityPreparedRecycleArchiveGrant>();
  const packetHandles = new WeakMap<object, EntityPreparedRecyclePacketGrant>();
  const committed: Array<{ sql: string; params: any[] }> = [], calls: string[] = [];
  let staged: Array<{ sql: string; params: any[] }> | undefined;
  const tx: any = { exec: vi.fn(async (sql: string, params: any[]) => { calls.push(sql.startsWith('INSERT INTO recycle_entries') ? 'archive-entry' : 'sql'); (staged ?? committed).push({ sql, params }); return 1; }) };
  const db: any = { transaction: vi.fn(async (callback: any) => { staged = []; try { const result = await callback(tx); committed.push(...staged!); return result; } finally { staged = undefined; } }) };
  const audit = { append: vi.fn(async (_event: any, receivedTx: any) => { expect(receivedTx).toBe(tx); calls.push('audit'); }) };
  const kong = { request: vi.fn(async (_c: string, method: string, path: string, body: any) => {
    calls.push(`native-${method}`);
    if (method === 'GET') throw new NotFoundException();
    if (method === 'DELETE') return null;
    const result = { ...body };
    // Kong returns Basic password as SHA1(password+consumerId).
    if (body?.username === 'cycle-basic' && typeof body.password === 'string' && body.consumer?.id) {
      result.password = createHash('sha1').update(body.password + body.consumer.id).digest('hex');
    }
    // Target create responses always include the parent upstream reference.
    const targetParent = path.match(/^\/upstreams\/([^/]+)\/targets$/);
    if (targetParent) result.upstream = { id: targetParent[1] };
    return result;
  }),
    list: vi.fn(async (_c: string, _path: string, q: any) => { calls.push('native-list'); return { items: [], size: q.size, nextCursor: null }; }),
  };
  const mutations = { execute: vi.fn(async (context: any, callback: any) => { context.operationId = operationId; calls.push('mutation'); return callback(); }) };
  const writer = new EntityPreparedRecycleWriterService(db, mutations as any, kong as any, secrets, audit as any);
  const assertIssued = (handle: object) => { if (!packetHandles.has(handle)) throw new ForbiddenException({ code: 'TEST_UNISSUED_PACKET' }); };
  const delegate: EntityPreparedRecycleWriterDelegate = {
    runArchive: async (handle, callback) => { const grant = archiveHandles.get(handle); if (!grant) throw new ForbiddenException({ code: 'TEST_UNISSUED_ARCHIVE' }); return callback(grant); },
    runPacket: async (handle, callback) => { const grant = packetHandles.get(handle); if (!grant) throw new ForbiddenException({ code: 'TEST_UNISSUED_PACKET' }); return callback(grant); },
    runRepair: async () => { throw new ForbiddenException({ code: 'TEST_NO_REPAIR' }); },
    linkArchive: vi.fn(async (_h, _r, receivedTx) => { expect(receivedTx).toBe(tx); calls.push('link-archive'); }),
    verifyCurrentRestore: async () => undefined,
    runVerifiedDelete: async (handle, id, callback) => { assertIssued(handle); expect(id).toBe(operationId); calls.push('verified-delete'); return callback(); },
    runVerificationRead: async (handle, id, callback) => { assertIssued(handle); expect(id).toBe(operationId); calls.push('verified-get'); return callback(); },
    recordTargetDeletePoststate: () => { calls.push('target-poststate'); },
    linkNodeReceipt: vi.fn(async (handle, _r, receivedTx) => {
      if (!packetHandles.has(handle)) throw new ForbiddenException();
      expect(receivedTx).toBe(tx); calls.push('link-node');
    }),
  };
  const binding: any = {
    source: { id: sourceId, clusterId: cid, workspaceId: wid, workflowId: sourceId, workflowExecutionId: executionId, executionActorId: actorId },
    baseline: { baselineId, sourceId, pinId }, actor: { user: { id: actorId, username: 'unit', superAdmin: true }, workspaceId: wid },
  };
  const issueArchive = (prepared: ReturnType<typeof plan>) => {
    const handle = Object.freeze({}) as EntityPreparedRecycleArchiveHandle;
    archiveHandles.set(handle, { ...binding, entryId, expiresAt: '2099-01-01T00:00:00Z', ...prepared } as EntityPreparedRecycleArchiveGrant);
    return handle;
  };
  const issuePacket = (prepared: ReturnType<typeof plan>, index: number) => {
    const handle = Object.freeze({}) as EntityPreparedRecyclePacketHandle;
    const packet = prepared.packets[index];
    const graph = prepared.obligation.graph;
    const node = graph.nodes.find(item => item.id === packet.nativeId || item.id === packet.originalNativeId)!;
    packetHandles.set(handle, { ...binding, entryId, nodeKey: node.key, operationKey: `source-packet-${index + 1}`, packet, ...prepared });
    return handle;
  };
  return { writer, delegate, secrets, kong, committed, calls, issueArchive, issuePacket };
}

describe('KP-004 ordinary five-root delete→archive→original-ID restore cycle (mocks)', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'de'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());

  it.each([...ORDINARY_RECYCLE_ROOT_TYPES])('cycles %s: archive then DELETE/poststate-or-GET404 then restore POST original IDs', async (type) => {
    const f = fixture();
    f.writer.installExecutionDelegate(f.delegate);
    const graph = ordinaryGraph(type);
    const del = plan(f.secrets, graph, false);
    const rest = plan(f.secrets, graph, true);

    expect(() => assertOrdinaryDeleteRestorePacketCoverage(graph, del.packets, rest.packets)).not.toThrow();
    expect(() => assertOrdinarySealedRestoreMatchesArchive(del.obligation, rest.obligation as any, { clusterId: cid, workspaceId: wid, entryId })).not.toThrow();

    const receipt = await f.writer.archive(f.issueArchive(del));
    expect(receipt).toMatchObject({ entryId, graphHmac: del.obligation.graphHmac, packetCount: del.packets.length });
    expect(f.calls).toContain('archive-entry');
    expect(f.calls).toContain('link-archive');
    expect(f.kong.request).not.toHaveBeenCalled();

    for (let i = 0; i < del.packets.length; i++) {
      const packet = del.packets[i];
      const listBefore = f.kong.list.mock.calls.length;
      await f.writer.execute(f.issuePacket(del, i));
      const deletes = f.kong.request.mock.calls.filter((c: any[]) => c[1] === 'DELETE');
      expect(deletes[i]).toEqual([cid, 'DELETE', packet.canonicalPath]);
      if (packet.nativeType === 'targets') {
        expect(f.kong.list.mock.calls.length - listBefore).toBe(4);
        expect(f.kong.request.mock.calls.some((c: any[]) => c[1] === 'GET' && c[2] === packet.canonicalPath)).toBe(false);
      } else {
        expect(f.kong.request.mock.calls.some((c: any[]) => c[1] === 'GET' && c[2] === packet.canonicalPath)).toBe(true);
      }
    }
    expect(f.kong.request.mock.calls.filter((c: any[]) => c[1] === 'DELETE')).toHaveLength(del.packets.length);

    f.kong.request.mockClear();
    for (let i = 0; i < rest.packets.length; i++) {
      const packet = rest.packets[i];
      const result = await f.writer.execute(f.issuePacket(rest, i));
      expect(result.nativeId).toBe(packet.nativeId);
      expect(f.kong.request.mock.calls[i]).toEqual([cid, 'POST', packet.canonicalPath, packet.body]);
      expect(packet.body?.id).toBe(packet.nativeId);
    }

    if (type === 'consumers') {
      const credentials = f.committed.filter(item => item.sql.startsWith('INSERT INTO credential_refs'));
      expect(credentials).toHaveLength(6);
      expect(new Set(credentials.map(row => row.params[3]))).toEqual(new Set(ORDINARY_CREDENTIAL_KINDS));
    }
  });

  it('rejects sealed restore that swaps archive graphHmac or entry', () => {
    const secrets = new SecretService();
    const graph = ordinaryGraph('services');
    const del = plan(secrets, graph, false);
    const rest = plan(secrets, graph, true);
    (rest.obligation as any).sealedEntry.payloadHmac = 'b'.repeat(64);
    expect(() => assertOrdinarySealedRestoreMatchesArchive(del.obligation, rest.obligation as any, { clusterId: cid, workspaceId: wid, entryId }))
      .toThrow(/ENTITY_RECYCLE_SEALED_ENTRY_INVALID|ENTITY_ORDINARY_RECYCLE_CONTRACT_INVALID|普通对象回收/);
    const other = ordinaryGraph('routes');
    const foreign = plan(secrets, other, true);
    expect(() => assertOrdinarySealedRestoreMatchesArchive(del.obligation, foreign.obligation as any, { clusterId: cid, workspaceId: wid, entryId }))
      .toThrow(/ENTITY_RECYCLE_ARCHIVE_RESTORE_MISMATCH|ENTITY_ORDINARY_RECYCLE_CONTRACT_INVALID|普通对象回收/);
  });

  it('rejects delete/restore coverage when a restore packet rewrites an ordinary ID', () => {
    const secrets = new SecretService();
    const graph = ordinaryGraph('certificates');
    const del = plan(secrets, graph, false);
    const rest = plan(secrets, graph, true);
    rest.packets[0].nativeId = randomUUID();
    rest.packets[0].body = { ...rest.packets[0].body!, id: rest.packets[0].nativeId };
    expect(() => assertOrdinaryDeleteRestorePacketCoverage(graph, del.packets, rest.packets)).toThrow();
  });
});
