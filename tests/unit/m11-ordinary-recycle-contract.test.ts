import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import {
  ORDINARY_CREDENTIAL_KINDS, ORDINARY_RECYCLE_MEMBER_TYPES, ORDINARY_RECYCLE_ROOT_TYPES,
  assertOrdinaryRecycleArchiveContract, assertOrdinaryRestoreOriginalIds,
  assertOrdinarySealedRestoreMatchesArchive, assertOrdinaryDeleteRestorePacketCoverage,
  isOrdinaryCredentialKind, isOrdinaryRecycleRoot,
} from '../../apps/console-api/src/modules/recycle-bin/ordinary-recycle-contract';
import { requiresRecycleDeleteClosure } from '../../apps/console-api/src/modules/recycle-bin/entity-recycle-current-delete-graph';
import { derivePreparedRecyclePackets, preparedRecycleNodeManifest } from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.service';
import type { GraphNode, RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import type { EntityChangePacket } from '../../apps/console-api/src/modules/entities/entity-change.types';
import type { PreparedRecycleObligation } from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.types';

let secrets: SecretService;
const entryId = randomUUID(), cid = randomUUID(), wid = randomUUID();
beforeEach(() => {
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '7b'.repeat(32));
  vi.stubEnv('APP_SECRET', 'ordinary-kp004-unit-'.repeat(3));
  secrets = new SecretService();
});
afterEach(() => vi.unstubAllEnvs());

const node = (type: string, id: string, body: Record<string, unknown>, deps: string[] = [], parent?: { type: string; id: string }): GraphNode => {
  const path = parent
    ? `/${parent.type === 'upstreams' ? 'upstreams' : 'consumers'}/${parent.id}/${type}/${id}`
    : `/${type}/${id}`;
  return {
    key: parent ? `${type}:${parent.id}:${id}` : `${type}:${id}`, type, id, path,
    data: { id, ...body }, restoreData: { id, ...body }, restorable: true, affected: true, dependencies: deps,
  };
};

function consumerGraph(allCredentials = true): RecycleGraph {
  const consumerId = randomUUID();
  const root = node('consumers', consumerId, { username: 'ordinary-consumer', tags: [] });
  const nodes: GraphNode[] = [root];
  if (allCredentials) {
    for (const kind of ORDINARY_CREDENTIAL_KINDS) {
      const id = randomUUID();
      const body: Record<string, unknown> = { consumer: { id: consumerId }, tags: [] };
      if (kind === 'key-auth') body.key = 'k';
      if (kind === 'basic-auth') {
        body.username = 'u';
        body.password = createHash('sha1').update('unit-password' + consumerId).digest('hex');
      }
      if (kind === 'jwt') { body.key = 'j'; body.secret = 's'; body.algorithm = 'HS256'; }
      if (kind === 'oauth2') { body.name = 'app'; body.client_id = 'c'; body.client_secret = 'cs'; }
      if (kind === 'hmac-auth') { body.username = 'h'; body.secret = 'hs'; }
      if (kind === 'acls') body.group = 'g';
      const child = node(kind, id, body, [root.key], { type: 'consumers', id: consumerId });
      if (kind === 'basic-auth') child.restoreData = { ...child.restoreData, password: 'unit-password' };
      nodes.push(child);
    }
  }
  return { complete: true, purpose: 'recycle', capturedAt: new Date().toISOString(), rootKey: root.key, nodes };
}

function ordinaryRootGraph(type: typeof ORDINARY_RECYCLE_ROOT_TYPES[number]): RecycleGraph {
  if (type === 'consumers') return consumerGraph(true);
  if (type === 'upstreams') {
    const upstreamId = randomUUID(), targetId = randomUUID();
    const parent = node('upstreams', upstreamId, { name: 'up', tags: [] });
    const target = node('targets', targetId, { target: 'echo:80', weight: 100, upstream: { id: upstreamId } }, [parent.key], { type: 'upstreams', id: upstreamId });
    return { complete: true, purpose: 'recycle', capturedAt: new Date().toISOString(), rootKey: parent.key, nodes: [parent, target],
      targetHistory: [{ upstreamId, items: [{ ...target.data }] }] };
  }
  if (type === 'certificates') {
    const certificateId = randomUUID(), sniId = randomUUID();
    const parent = node('certificates', certificateId, { cert: 'c', key: 'k', snis: ['api.example'], tags: [] });
    const sni = node('snis', sniId, { name: 'api.example', certificate: { id: certificateId }, tags: [] }, [parent.key]);
    return { complete: true, purpose: 'recycle', capturedAt: new Date().toISOString(), rootKey: parent.key, nodes: [parent, sni] };
  }
  if (type === 'services') {
    const serviceId = randomUUID(), routeId = randomUUID(), pluginId = randomUUID();
    const service = node('services', serviceId, { name: 'svc', host: 'echo', tags: [] });
    const route = node('routes', routeId, { name: 'rt', paths: ['/'], service: { id: serviceId }, tags: [] }, [service.key]);
    const plugin = node('plugins', pluginId, { name: 'cors', service: { id: serviceId }, config: {}, tags: [] }, [service.key]);
    return { complete: true, purpose: 'recycle', capturedAt: new Date().toISOString(), rootKey: service.key, nodes: [service, route, plugin] };
  }
  const routeId = randomUUID(), pluginId = randomUUID(), serviceId = randomUUID();
  const service = { ...node('services', serviceId, { name: 'svc', host: 'echo', tags: [] }), affected: false, restoreData: undefined };
  const route = node('routes', routeId, { name: 'rt', paths: ['/'], service: { id: serviceId }, tags: [] }, [service.key]);
  const plugin = node('plugins', pluginId, { name: 'cors', route: { id: routeId }, config: {}, tags: [] }, [route.key]);
  return { complete: true, purpose: 'recycle', capturedAt: new Date().toISOString(), rootKey: route.key, nodes: [service, route, plugin] };
}

function ordered(g: RecycleGraph): GraphNode[] {
  const result: GraphNode[] = [], seen = new Set<string>();
  const visit = (n: GraphNode) => { if (seen.has(n.key)) return; for (const key of n.dependencies) visit(g.nodes.find(x => x.key === key)!); seen.add(n.key); result.push(n); };
  g.nodes.forEach(visit); return result;
}

function packetsFor(g: RecycleGraph, restoring: boolean, replacement?: string): { obligation: PreparedRecycleObligation; packets: EntityChangePacket[] } {
  const affected = ordered(g).filter(n => n.affected), keys = new Map<string, string>();
  const packets: EntityChangePacket[] = (restoring ? affected : [...affected].reverse()).map((n, i) => {
    const parentId = n.type === 'targets' || isOrdinaryCredentialKind(n.type)
      ? (n.type === 'targets' ? g.nodes.find(x => x.type === 'upstreams')!.id : g.nodes.find(x => x.type === 'consumers')!.id)
      : undefined;
    const newId = replacement && n.type === 'targets' ? replacement : n.id;
    const before = restoring ? null : structuredClone(n.data);
    if (!restoring && n.type === 'certificates') {
      const removed = new Set(g.nodes.filter(child => child.affected && child.type === 'snis' && child.dependencies.includes(n.key) && keys.has(child.key)).map(child => child.data.name));
      before.snis = before.snis.filter((name: string) => !removed.has(name));
    }
    const body = restoring ? structuredClone(n.restoreData) : undefined;
    if (body) {
      delete body.created_at; delete body.updated_at; delete body.ttl;
      if (n.type === 'certificates') delete body.snis;
      if (n.type === 'targets') { body.id = newId; delete body.upstream; }
    }
    const packet: EntityChangePacket = {
      key: `packet-${i + 1}`, order: i + 1, nativeType: n.type, nativeId: newId,
      ...(parentId ? { parentId } : {}), ...(isOrdinaryCredentialKind(n.type) ? { credentialKind: n.type } : {}),
      ...(newId !== n.id ? { originalNativeId: n.id } : {}),
      method: restoring ? 'POST' : 'DELETE',
      canonicalPath: restoring ? n.path.replace(/\/[^/]+$/, '') : n.path,
      permissionAction: restoring ? 'write' : 'delete', mutationAction: restoring ? 'restore' : 'delete',
      before, ...(body ? { body } : {}), beforeHmac: secrets.fingerprint(before), bodyHmac: secrets.fingerprint(body ?? null),
      dependencies: restoring
        ? n.dependencies.flatMap(dep => keys.get(dep) ?? [])
        : g.nodes.filter(child => child.affected && child.dependencies.includes(n.key)).flatMap(child => keys.get(child.key) ?? []),
    };
    keys.set(n.key, packet.key); return packet;
  });
  const common = { graph: g, graphHmac: secrets.fingerprint(g), packetKeys: packets.map(p => p.key) };
  const obligation: PreparedRecycleObligation = restoring
    ? { ...common, kind: 'recycle-restore', entryId, sealedEntry: {
      clusterId: cid, workspaceId: wid, entryId, state: 'deleted', expiresAt: '2099-01-01T00:00:00Z',
      payloadHmac: common.graphHmac, nodeManifestHmac: secrets.fingerprint(preparedRecycleNodeManifest(g, secrets)), restoreMaterialHmac: 'a'.repeat(64) } }
    : { ...common, kind: 'recycle-archive' };
  return { obligation, packets };
}

describe('KP-004 ordinary recycle contract (five roots + six credentials)', () => {
  it('catalogs exactly five ordinary roots and six credential kinds', () => {
    expect([...ORDINARY_RECYCLE_ROOT_TYPES]).toEqual(['services', 'routes', 'consumers', 'certificates', 'upstreams']);
    expect([...ORDINARY_CREDENTIAL_KINDS]).toEqual(['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls']);
    for (const type of ORDINARY_RECYCLE_ROOT_TYPES) {
      expect(isOrdinaryRecycleRoot(type)).toBe(true);
      expect(requiresRecycleDeleteClosure(type)).toBe(true);
      expect(ORDINARY_RECYCLE_MEMBER_TYPES[type].length).toBeGreaterThan(0);
    }
    expect(isOrdinaryRecycleRoot('plugins')).toBe(false);
    expect(requiresRecycleDeleteClosure('plugins')).toBe(false);
    expect(isOrdinaryCredentialKind('jwt')).toBe(true);
    expect(isOrdinaryCredentialKind('ldap-auth')).toBe(false);
  });

  it.each([...ORDINARY_RECYCLE_ROOT_TYPES])('accepts archive-ready %s graph and original-ID restore packets', type => {
    const g = ordinaryRootGraph(type);
    expect(() => assertOrdinaryRecycleArchiveContract(g)).not.toThrow();
    const del = packetsFor(g, false);
    expect(() => derivePreparedRecyclePackets(del.obligation, del.packets, secrets)).not.toThrow();
    const rest = packetsFor(g, true);
    expect(() => assertOrdinaryRestoreOriginalIds(g, rest.packets)).not.toThrow();
    expect(() => derivePreparedRecyclePackets(rest.obligation, rest.packets, secrets)).not.toThrow();
  });

  it('requires restoreData on every affected node before ordinary delete archive', () => {
    const g = ordinaryRootGraph('services');
    const route = g.nodes.find(n => n.type === 'routes')!;
    delete route.restoreData;
    expect(() => assertOrdinaryRecycleArchiveContract(g)).toThrow(/ENTITY_RECYCLE_ARCHIVE_MATERIAL_REQUIRED|ENTITY_ORDINARY_RECYCLE_CONTRACT_INVALID|普通对象回收/);
  });

  it('rejects unknown member types under an ordinary root', () => {
    const g = ordinaryRootGraph('consumers');
    g.nodes.push(node('services', randomUUID(), { name: 'foreign', tags: [] }));
    expect(() => assertOrdinaryRecycleArchiveContract(g)).toThrow();
  });

  it('rejects restore packets that rewrite ordinary original IDs', () => {
    const g = ordinaryRootGraph('consumers');
    const rest = packetsFor(g, true);
    rest.packets[0].nativeId = randomUUID();
    rest.packets[0].body = { ...rest.packets[0].body!, id: rest.packets[0].nativeId };
    rest.packets[0].bodyHmac = secrets.fingerprint(rest.packets[0].body);
    expect(() => assertOrdinaryRestoreOriginalIds(g, rest.packets)).toThrow(/ENTITY_RECYCLE_ORIGINAL_ID_REQUIRED|ENTITY_ORDINARY_RECYCLE_CONTRACT_INVALID|普通对象回收/);
  });

  it('allows Target replacement only with sealed originalNativeId', () => {
    const g = ordinaryRootGraph('upstreams');
    const replacement = randomUUID();
    const rest = packetsFor(g, true, replacement);
    expect(() => assertOrdinaryRestoreOriginalIds(g, rest.packets)).not.toThrow();
    expect(() => derivePreparedRecyclePackets(rest.obligation, rest.packets, secrets)).not.toThrow();
  });

  it('skips non-ordinary roots (plugins-as-root) without applying the five-root contract', () => {
    const id = randomUUID();
    const root = node('plugins', id, { name: 'cors', config: {}, tags: [] });
    const g: RecycleGraph = { complete: true, purpose: 'recycle', capturedAt: new Date().toISOString(), rootKey: root.key, nodes: [root] };
    expect(() => assertOrdinaryRecycleArchiveContract(g)).not.toThrow();
    delete root.restoreData;
    // Still no-op for non-ordinary; specialist writer path keeps its own rules.
    expect(() => assertOrdinaryRecycleArchiveContract(g)).not.toThrow();
  });

  it('consumer archive covers all six credential kinds through prepared recycle', () => {
    const g = consumerGraph(true);
    expect(g.nodes.filter(n => isOrdinaryCredentialKind(n.type)).map(n => n.type).sort())
      .toEqual([...ORDINARY_CREDENTIAL_KINDS].sort());
    const del = packetsFor(g, false);
    const fixed = derivePreparedRecyclePackets(del.obligation, del.packets, secrets);
    expect(fixed.filter(p => isOrdinaryCredentialKind(p.node.type))).toHaveLength(6);
    const rest = packetsFor(g, true);
    const restored = derivePreparedRecyclePackets(rest.obligation, rest.packets, secrets);
    expect(restored.every(p => p.packet.nativeId === p.node.id || p.node.type === 'targets')).toBe(true);
  });

  it('sealed restore must match archive graphHmac/entry for ordinary roots', () => {
    const g = ordinaryRootGraph('upstreams');
    const del = packetsFor(g, false);
    const rest = packetsFor(g, true);
    expect(() => assertOrdinarySealedRestoreMatchesArchive(del.obligation, rest.obligation as any, { clusterId: cid, workspaceId: wid, entryId })).not.toThrow();
    expect(() => assertOrdinaryDeleteRestorePacketCoverage(g, del.packets, rest.packets)).not.toThrow();
    (rest.obligation as any).sealedEntry.entryId = randomUUID();
    expect(() => assertOrdinarySealedRestoreMatchesArchive(del.obligation, rest.obligation as any, { clusterId: cid, workspaceId: wid, entryId })).toThrow();
  });

  it('delete/restore coverage requires matching affected native IDs both ways', () => {
    const g = ordinaryRootGraph('services');
    const del = packetsFor(g, false);
    const rest = packetsFor(g, true);
    expect(() => assertOrdinaryDeleteRestorePacketCoverage(g, del.packets, rest.packets)).not.toThrow();
    rest.packets.pop();
    expect(() => assertOrdinaryDeleteRestorePacketCoverage(g, del.packets, rest.packets)).toThrow();
  });


  it('rejects sealed restore when entry state is purged', () => {
    const g = ordinaryRootGraph('routes');
    const del = packetsFor(g, false);
    const rest = packetsFor(g, true);
    (rest.obligation as any).sealedEntry.state = 'purged';
    expect(() => assertOrdinarySealedRestoreMatchesArchive(del.obligation, rest.obligation as any, { clusterId: cid, workspaceId: wid, entryId })).toThrow();
    (rest.obligation as any).sealedEntry.state = 'partially_restored';
    expect(() => assertOrdinarySealedRestoreMatchesArchive(del.obligation, rest.obligation as any, { clusterId: cid, workspaceId: wid, entryId })).not.toThrow();
  });

});
