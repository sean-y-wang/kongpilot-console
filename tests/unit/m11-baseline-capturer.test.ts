import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { entityForPath } from '../../apps/console-api/src/infrastructure/kong/policy';
import { CredentialStoreService } from '../../apps/console-api/src/modules/credentials/credential-store.service';
import { GraphCapturerService, type RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import { EntityChangeBaselineCapturerService } from '../../apps/console-api/src/modules/workflows/entity-change-baseline-capturer.service';
import type { EntityChangePacket, PreparedEntityChange } from '../../apps/console-api/src/modules/entities/entity-change.types';
import { executionFixture } from './execution-test-fixture';

/** Real graph capture, baseline normalization and encrypted CredentialStore;
 * GET/list/schema/compiler/context adapters are controlled domain fixtures.
 * This suite proves no real SQL/session/grant/approval/native authority. */
function fixture() {
  const cid = randomUUID(), wid = randomUUID(), nativeId = randomUUID(), consumerId = randomUUID(), routeId = randomUUID();
  const actor = { user: { id: randomUUID(), username: 'unit-baseline', superAdmin: false }, workspaceId: wid };
  const secrets = new SecretService(), remote = new Map<string, any>(), collections = new Map<string, any[]>(), remembered = new Map<string, any>();
  const context = executionFixture(), db: any = { one: vi.fn(async (_sql: string, args: string[]) => {
    const value = remembered.get(`${args[1]}:${args[2]}:${args[3]}`);
    return value ? { payload_secret: secrets.encrypt(value, `credential:${cid}:${args[1]}:${args[2]}:${args[3]}`) } : null;
  }), exec: vi.fn(async () => { throw new Error('Unexpected SQL write'); }) };
  const credentials = new CredentialStoreService(db, secrets);
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => {
    if (method !== 'GET') throw new Error('Unexpected native write');
    if (!remote.has(path)) throw new NotFoundException(); return structuredClone(remote.get(path));
  }), list: vi.fn(async (_cid: string, path: string) => ({ items: structuredClone(collections.get(path) ?? []), size: 100, nextCursor: null })),
  prepareSchema: vi.fn(async (_cid: string, path: string, body: any) => ({ version: 1, clusterId: cid, canonicalPath: path,
    nativeType: entityForPath(path), kongVersion: '1.5.1', adapter: 'kong-oss-1.5-v1', clusterRevision: 1, payloadHmac: secrets.fingerprint(body ?? null),
    schemaMaterial: { entity: { name: entityForPath(path), canonicalPath: `/schemas/${entityForPath(path)}`, schema: { fields: [{ id: { type: 'string', uuid: true } }] } } } })) };
  const compiler: any = { revalidateStored: vi.fn() }, graphs = new GraphCapturerService(kong, credentials, context);
  const capturer = new EntityChangeBaselineCapturerService(kong, context, graphs, credentials, compiler, secrets);
  const packet = (type = 'services', overrides: Partial<EntityChangePacket> = {}): EntityChangePacket => {
    const id = overrides.nativeId ?? nativeId, before = remote.get(`/${type}/${id}`) ?? null;
    const result = { key: 'packet-0', order: 1, dependencies: [], method: before ? 'PATCH' : 'POST', canonicalPath: before ? `/${type}/${id}` : `/${type}`,
      nativeType: type, nativeId: id, permissionAction: 'write', mutationAction: before ? 'update' : 'create', before,
      body: before ? { host: 'after.example' } : { id, host: 'create.example' }, ...overrides } as EntityChangePacket;
    result.bodyHmac = secrets.fingerprint(result.body ?? null); result.beforeHmac = secrets.fingerprint(result.before ?? null); return result;
  };
  const material = async (packets: EntityChangePacket[], prerequisites: any[] = [], metadataObligations: any[] = []): Promise<PreparedEntityChange> => {
    const schemas = await Promise.all(packets.filter(p => p.body !== undefined).map(p => kong.prepareSchema(cid, p.canonicalPath, p.body)));
    const value: any = { version: 1, clusterId: cid, workspaceId: wid, requesterId: actor.user.id, permissionVersion: 'original-preparation-version',
      scope: { transportScope: 'aa'.repeat(32), clusterRevision: 1, workspaceRevision: 1, kongVersion: '1.5.1', adapter: 'kong-oss-1.5-v1' },
      request: { kind: 'entity', action: 'create', entityType: 'services', body: {} }, prerequisites, schemas, packets, metadataObligations,
      recovery: { state: 'baseline-required', blockerCodes: ['EXECUTION_BASELINE_REQUIRED'], objects: [] }, impact: {} };
    return { ...value, changeDigest: secrets.fingerprint(value) };
  };
  const service = () => {
    const value = { id: nativeId, name: 'unit-service', host: '192.0.2.10', tags: ['kos-ws-unit'] };
    remote.set(`/services/${nativeId}`, value); return value;
  };
  const basic = (password = 'unit-trusted-plaintext') => {
    const hash = createHash('sha1').update(password + consumerId).digest('hex');
    const consumer = { id: consumerId, username: 'private-parent-name', tags: ['kos-ws-unit'] };
    const value = { id: nativeId, username: 'unit-basic', password: hash, consumer: { id: consumerId }, tags: ['kos-ws-unit'] };
    remote.set(`/consumers/${consumerId}`, consumer); remote.set(`/consumers/${consumerId}/basic-auth/${nativeId}`, value);
    remembered.set(`${consumerId}:basic-auth:${nativeId}`, { credential: value, rawInput: { username: value.username, password } });
    return { value, password, hash, packet: packet('basic-auth', { before: value, canonicalPath: `/consumers/${consumerId}/basic-auth/${nativeId}`,
      parentId: consumerId, credentialKind: 'basic-auth', method: 'PATCH', mutationAction: 'update', body: { username: 'after-basic' } }) };
  };
  const noWrites = () => { expect(db.exec).not.toHaveBeenCalled(); expect(kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true); };
  return { cid, wid, nativeId, consumerId, routeId, actor, secrets, remote, collections, remembered, context, db, credentials,
    kong, compiler, graphs, capturer, packet, material, service, basic, noWrites };
}

describe('M11 private baseline capturer domain contracts', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'de'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());
  it('seals real GET 404 absence, including actual credential DAO schema material', async () => {
    for (const credential of [false, true]) {
      const f = fixture();
      const packet = credential ? f.packet('key-auth', { canonicalPath: `/consumers/${f.consumerId}/key-auth`, parentId: f.consumerId,
        credentialKind: 'key-auth', body: { id: f.nativeId, key: 'unit-create-key' } }) : f.packet();
      const parent = { id: f.consumerId, username: 'parent' };
      if (credential) f.remote.set(`/consumers/${f.consumerId}`, parent);
      const prerequisites = credential ? [{ type: 'consumers', nativeId: f.consumerId, path: `/consumers/${f.consumerId}`, before: parent,
        absent: false, fingerprint: f.secrets.fingerprint(parent), permissionAction: 'write', purpose: 'private-parent' }] : [];
      const capture = await f.capturer.capture(await f.material([packet], prerequisites), f.actor);
      const object = capture.objects.find(item => item.nativeId === f.nativeId)!;
      expect(object).toMatchObject({ affected: true, present: false, before: null, recovery: 'absent', trustedProvenance: { kind: 'native-get-404' } });
      expect(capture.graphs).toEqual([]); expect(Array.isArray(object.schemaMaterial)).toBe(true);
      expect(object.schemaMaterial).toHaveLength(1);
      expect((object.schemaMaterial as any[])[0].nativeType).toBe(credential ? 'keyauth_credentials' : 'services');
      expect(f.kong.request).toHaveBeenCalledWith(f.cid, 'GET', credential ? `/consumers/${f.consumerId}/key-auth/${f.nativeId}` : `/services/${f.nativeId}`);
      expect(f.compiler.revalidateStored).toHaveBeenCalledTimes(2); f.noWrites();
    }
  });
  it('captures an existing Service full Route and bound Plugin graph beyond the single approved packet', async () => {
    const f = fixture(), service = f.service(), pluginId = randomUUID();
    const route = { id: f.routeId, name: 'unit-route', service: { id: service.id }, paths: ['/unit'] };
    const plugin = { id: pluginId, name: 'cors', route: { id: route.id }, config: { origins: ['https://unit.example'] } };
    f.remote.set(`/routes/${route.id}`, route); f.remote.set(`/plugins/${pluginId}`, plugin);
    f.collections.set(`/services/${service.id}/routes`, [route]); f.collections.set('/plugins', [plugin]);
    const capture = await f.capturer.capture(await f.material([f.packet()]), f.actor);
    expect(capture.graphs).toHaveLength(1); expect(capture.graphs[0].purpose).toBe('baseline');
    expect(capture.objects.filter(item => item.affected).map(item => item.nativeType)).toEqual(['services', 'routes', 'plugins']);
    expect(capture.objects.find(item => item.nativeType === 'routes')?.restorePayload).toEqual(route);
    expect(capture.objects.find(item => item.nativeType === 'plugins')?.dependencies).toEqual([`routes:${route.id}`]); f.noWrites();
  });
  it('keeps schema planning in the caller frame while graph reads use bounded internal capabilities', async () => {
    const f = fixture(); f.service();
    const material = await f.material([f.packet()]);
    let internalDepth = 0;
    const internal = f.context.runInternalRead.bind(f.context);
    vi.spyOn(f.context, 'runInternalRead').mockImplementation(async (cid, purpose, fn, options) => {
      internalDepth++;
      try { return await internal(cid, purpose, fn, options); }
      finally { internalDepth--; }
    });
    const schema = f.kong.prepareSchema.getMockImplementation();
    f.kong.prepareSchema.mockImplementation(async (...args: any[]) => {
      expect(internalDepth).toBe(0);
      return schema(...args);
    });
    const capture = await f.capturer.capture(material, f.actor);
    expect(capture.objects).toHaveLength(1);
    expect(f.context.runInternalRead).toHaveBeenCalled();
    expect(f.kong.prepareSchema).toHaveBeenCalledTimes(2);
    f.noWrites();
  });
  it('verifies Basic plaintext plus real Consumer UUID SHA1 and rejects a remembered native hash used as plaintext', async () => {
    const f = fixture(), basic = f.basic();
    const capture = await f.capturer.capture(await f.material([basic.packet]), f.actor);
    const object = capture.objects.find(item => item.nativeType === 'basic-auth')!;
    expect(object.before).toMatchObject({ password: basic.hash }); expect(object.restorePayload).toMatchObject({ password: basic.password });
    expect(object.trustedProvenance).toMatchObject({ kind: 'credential-store-sha1-verified', nativeHashHmac: f.secrets.fingerprint(basic.hash), plaintextHmac: f.secrets.fingerprint(basic.password) });
    f.remembered.set(`${f.consumerId}:basic-auth:${f.nativeId}`, { credential: basic.value, rawInput: { password: basic.hash } });
    await expect(f.capturer.capture(await f.material([basic.packet]), f.actor)).rejects.toMatchObject({ response: { code: 'BASIC_AUTH_NOT_RECOVERABLE' } }); f.noWrites();
  });
  it('rejects a changed object on the second point observation', async () => {
    const f = fixture(), service = f.service(), request = f.kong.request.getMockImplementation(); let reads = 0;
    f.kong.request.mockImplementation(async (cid: string, method: string, path: string) => {
      // Initial complete capture + complete graph recapture agree. The next
      // point read independently detects a change after both enumerations.
      if (path === `/services/${service.id}` && ++reads > 2) return { ...service, host: 'changed-during-capture.example' };
      return request(cid, method, path);
    });
    await expect(f.capturer.capture(await f.material([f.packet()]), f.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_BASELINE_CHANGED' } }); f.noWrites();
  });
  it('rejects a new child on the complete second graph observation', async () => {
    const f = fixture(), service = f.service(), child = { id: f.routeId, service: { id: service.id }, paths: ['/raced'] };
    f.remote.set(`/routes/${child.id}`, child); let observations = 0;
    f.kong.list.mockImplementation(async (_cid: string, path: string) => ({ items: path === `/services/${service.id}/routes` && ++observations > 1 ? [child] : [], nextCursor: null, size: 100 }));
    await expect(f.capturer.capture(await f.material([f.packet()]), f.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_BASELINE_GRAPH_CHANGED' } });
    expect(observations).toBeGreaterThan(1); f.noWrites();
  });
  it('rejects missing trusted credential recovery and missing affected restore material before any write', async () => {
    const f = fixture(), basic = f.basic(); f.remembered.clear();
    await expect(f.capturer.capture(await f.material([basic.packet]), f.actor)).rejects.toMatchObject({ response: { code: 'BASIC_AUTH_NOT_RECOVERABLE' } }); f.noWrites();
    const g = fixture(); g.service(); const capture = await g.graphs.capture(g.cid, 'services', g.nativeId, { purpose: 'baseline' });
    delete capture.nodes.find(node => node.affected)!.restoreData;
    vi.spyOn(g.graphs, 'capture').mockResolvedValue(capture);
    await expect(g.capturer.capture(await g.material([g.packet()]), g.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_RECOVERY_MATERIAL_MISSING' } }); g.noWrites();
  });
  it('blocks malformed node health facts before any native reads or writes', async () => {
    const f = fixture(), packet = f.packet('targets', { method: 'POST', canonicalPath: `/upstreams/${f.consumerId}/targets/${f.nativeId}/healthy`,
      parentId: f.consumerId, before: { id: f.nativeId, target: 'echo.example:80' }, mutationAction: 'mark_healthy', body: undefined });
    await expect(f.capturer.capture(await f.material([packet]), f.actor)).rejects.toMatchObject({ response: { code: 'TARGET_HEALTH_NATIVE_ROW_INVALID' } });
    expect(f.compiler.revalidateStored).toHaveBeenCalledOnce(); expect(f.kong.request).not.toHaveBeenCalled(); f.noWrites();
  });
  it('captures real node-health facts separately from target configuration and explicitly marks the health packet non-reversible',async()=>{
    const f=fixture(),parent={id:f.consumerId,name:'fixture-upstream',tags:[]},target={id:f.nativeId,target:'echo.internal:80',weight:100,tags:[],created_at:1,upstream:{id:f.consumerId}},
      collection=`/upstreams/${parent.id}/targets`,path=`${collection}/${target.id}`;
    f.remote.set('/',{version:'1.5.1',node_id:'fixture-node'});f.remote.set(`/upstreams/${parent.id}`,parent);f.remote.set(path,target);
    f.collections.set(collection,[target]);f.collections.set(`${collection}/all`,[target]);f.collections.set(`/upstreams/${parent.id}/health`,[{...target,health:'HEALTHY'}]);
    const packet=f.packet('targets',{parentId:parent.id,before:target,nativeId:target.id,method:'POST',canonicalPath:`${path}/unhealthy`,mutationAction:'mark_unhealthy',body:undefined}),
      capture=await f.capturer.capture(await f.material([packet]),f.actor),object=capture.objects.find(item=>item.nativeType==='targets')!;
    const {created_at:_,...restore}=target;
    expect(object.before).toEqual(target);expect((object.before as any).health).toBeUndefined();expect(object.restorePayload).toEqual(restore);
    expect(object.trustedProvenance).toMatchObject({kind:'target-health-observed',overrideRecovery:'unavailable',healthBefore:{nodeId:'fixture-node',health:'HEALTHY',recoverableOverride:false}});
    expect(capture.nonreversiblePacketKeys).toEqual([packet.key]);expect(capture.blockerCodes).toEqual([]);f.noWrites();
  });
  it('keeps shared parent references private and never assigns them affected restore payloads', async () => {
    const f = fixture(), basic = f.basic(), capture = await f.capturer.capture(await f.material([basic.packet]), f.actor);
    const parent = capture.objects.find(item => item.nativeType === 'consumers')!;
    expect(parent).toMatchObject({ affected: false, present: true, recovery: 'reference' }); expect(parent).not.toHaveProperty('restorePayload');
    // capture is a private store input, deliberately not a public projection.
    // The repository's public historical projection must omit reference data;
    // no HTTP/public authority claim is made by this domain fixture.
    expect(Object.isFrozen(capture)).toBe(true); expect(Object.isFrozen(parent)).toBe(true); f.noWrites();
  });
  it('uses live 404 for restore absence and never treats an original archive as an observed live graph', async () => {
    const f = fixture(), archived: RecycleGraph = { rootKey: `services:${f.nativeId}`, purpose: 'recycle', complete: true, capturedAt: new Date().toISOString(),
      nodes: [{ key: `services:${f.nativeId}`, type: 'services', id: f.nativeId, path: `/services/${f.nativeId}`, affected: true,
        data: { id: f.nativeId, host: 'historical.example' }, dependencies: [], restorable: true, restoreData: { id: f.nativeId, host: 'historical.example' } }] };
    const packet = f.packet('services', { mutationAction: 'restore', body: archived.nodes[0].restoreData });
    const material = await f.material([packet], [], [{ kind: 'recycle-restore', entryId: randomUUID(), graph: archived, graphHmac: f.secrets.fingerprint(archived), packetKeys: [packet.key] }]);
    const graphSpy = vi.spyOn(f.graphs, 'capture'), capture = await f.capturer.capture(material, f.actor);
    expect(capture.graphs).toEqual([]); expect(graphSpy).not.toHaveBeenCalled(); expect(capture.objects[0]).toMatchObject({ present: false, before: null, recovery: 'absent' });
    f.remote.set(`/services/${f.nativeId}`, archived.nodes[0].data);
    await expect(f.capturer.capture(material, f.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_BASELINE_EXPECTED_ABSENCE' } }); f.noWrites();
  });
});
