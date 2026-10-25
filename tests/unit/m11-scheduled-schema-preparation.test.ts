import 'reflect-metadata';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {immutableJson} from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
import {EntityScheduledNamespaceService} from '../../apps/console-api/src/modules/workflows/entity-scheduled-namespace.service';
import {nativeTransportContext} from './kong-native-test-fixture';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({outboundJson: vi.fn()}));
const transport = vi.mocked(outboundJson);
/** Production Namespace and Context allocate/check the original private
 * handles, ancestors and read tickets. Authority/SQL/native transport are
 * explicit source-only adapters, not actual scheduled execution authority. */
function fixture() {
  const cid = randomUUID(), wid = randomUUID(), owner = randomUUID(), secrets = new SecretService(), context = nativeTransportContext();
  const actor = {id: owner, username: 'scheduled-schema-owner', superAdmin: false}, expiresAt = new Date(Date.now() + 60000).toISOString();
  const cluster: any = {id: cid, admin_url: 'http://kong:8001', connection_secret: null, version: '1.5.1', execution_mode: 'approval', status: 'healthy', revision: 1, capabilities: {}, enabled_plugins: ['key-auth']};
  const state: any = {executing: false, lease: false, ownerActive: true, namespaceHandle: null, transportHook: null};
  const originalAuthority = Object.freeze({}), authorityHandles = new WeakSet<object>([originalAuthority]);
  const envelope: any = {version: 2, intentId: randomUUID(), revision: 1, clusterId: cid, workspaceId: wid, requesterId: owner, credentialEpoch: '1', expiresAt, executionMode: 'approval',
    prepared: {scope: {transportScope: transportScopeFor(cluster.admin_url), clusterRevision: 1, workspaceRevision: 1}},
    scheduling: {specHmac: 'a'.repeat(64), delegationHmac: 'b'.repeat(64), delegation: {id: randomUUID(), ownerId: owner, executorId: owner, ownerCredentialEpoch: '1', executorCredentialEpoch: '1'}}};
  const plan: any = {workflowId: randomUUID(), planRevision: 1, clusterId: cid, workspaceId: wid, kind: 'native-change', requester: {type: 'console', id: owner}, executionMode: 'approval', approvalRequired: true, expiresAt};
  const scheduleId = randomUUID(), inspection: any = {version: 1, envelope, plan, principal: actor, permissionVersion: `${owner}:1:1`, authorityExpiresAt: expiresAt, leaseUntil: expiresAt,
    draft: {scheduleId, binding: {clusterId: cid, workspaceId: wid, materialHmac: 'c'.repeat(64), changeDigest: 'd'.repeat(64), packetManifestHmac: 'e'.repeat(64)},
      spec: {windowStart: new Date(Date.now() - 1000).toISOString(), windowEnd: expiresAt}},
    claim: {id: randomUUID(), scheduleId, scheduleVersion: 1, occurrenceId: randomUUID(), generation: 1, workerOwnerHmac: 'f'.repeat(64), issuedAt: new Date().toISOString(), authorityExpiresAt: expiresAt,
      initialLeaseUntil: expiresAt, workflowId: plan.workflowId, workflowPlanRevision: 1, workflowPlanHash: secrets.fingerprint(plan)},
    approvalSet: {format: 2, policyHash: '1'.repeat(64), setId: randomUUID(), setHmac: '2'.repeat(64), reviewers: [{approvalId: randomUUID(), userId: randomUUID(), level: 1, candidateVersion: 1}]}};
  const authority: any = {verifyClaim: vi.fn(async (h: object) => {
    if (!authorityHandles.has(h) || !state.executing || !state.lease || !state.ownerActive) throw new ForbiddenException({code: 'CURRENT_ORIGINAL_AUTHORITY_REQUIRED'});
    return immutableJson(inspection);
  }), inspect: vi.fn(async (h: object) => {if (!authorityHandles.has(h)) throw new ForbiddenException(); return immutableJson(inspection);})};
  const redis: any = {rateLimit: vi.fn(async () => ({allowed: true})), withLock: vi.fn(),
    assertLeaseActive: vi.fn(() => {if (!state.lease) throw new ForbiddenException({code: 'LEASE_CLOSED'});}),
    assertLeaseOwnership: vi.fn(async () => {if (!state.lease) throw new ForbiddenException({code: 'LEASE_CLOSED'});})};
  const namespace = new EntityScheduledNamespaceService(authority, secrets, redis);
  namespace.installContextRunner({assertNoFrame: () => {if (context.peek()) throw new ForbiddenException();}, run: (h, fn) => {
    state.namespaceHandle = h; return context.runEntityScheduledNamespace(h, fn);
  }});
  context.installEntityScheduledNamespacePolicy({verifyHandle: (h, p) => namespace.verifyHandle(h, p), assertLive: h => namespace.assertLive(h)});
  const db: any = {one: vi.fn(async () => structuredClone(cluster)), query: vi.fn(), exec: vi.fn()}, audit: any = {append: vi.fn()};
  const kong = new KongService(db, redis, secrets, audit, context);
  transport.mockImplementation(async (_base, path, method) => {
    if (method !== 'GET') throw new Error('Schema preparation attempted a native write');
    if (state.transportHook) await state.transportHook();
    const schema = path === '/schemas/plugins' ? {fields: [{name: {type: 'string'}}, {config: {type: 'record'}}]}
      : path === '/plugins/schema/key-auth' ? {fields: [{key_names: {type: 'array', elements: {type: 'string'}}}]}
      : {fields: [{username: {type: 'string'}}, {tags: {type: 'set', elements: {type: 'string'}}}]};
    return {status: 200, body: schema};
  });
  const run = async <T>(fn: () => Promise<T>): Promise<T> => {state.executing = true; state.lease = true; try {return await namespace.runOriginalClaim(originalAuthority, fn);} finally {state.executing = false; state.lease = false;}};
  const http = <T>(sid: string | undefined, fn: () => Promise<T>): Promise<T> => context.runHttp({}, async () => {
    context.bindHttpActor(actor, sid); const close = context.captureHttpCloser();
    try {return await context.runActor({actor, clusterId: cid, workspaceId: wid, module: 'workflows', action: 'write'}, fn);} finally {close();}
  });
  const prepare = (input: unknown = {username: 'planned-client'}) => kong.prepareSchema(cid, '/consumers', input);
  const noWrites = () => {expect(transport.mock.calls.every(call => call[2] === 'GET')).toBe(true); expect(db.exec).not.toHaveBeenCalled(); expect(audit.append).not.toHaveBeenCalled(); expect(redis.withLock).not.toHaveBeenCalled();};
  return {cid, wid, actor, context, namespace, originalAuthority, inspection, cluster, state, authority, db, redis, audit, kong, secrets, run, http, prepare, noWrites};
}
beforeEach(() => {vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '4e'.repeat(32)); vi.stubEnv('KONG_RATE_WAIT_MS', '0'); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T17:30:00.000Z')); transport.mockReset();});
afterEach(() => {vi.useRealTimers(); vi.unstubAllEnvs();});
describe('M11 schema planning in original scheduled namespace (source-only)', () => {
  it('prepares immutable schema/body evidence through genuine original namespace and actor frames without SID', async () => {
    const f = fixture(), input = {username: 'planned-client'};
    f.state.transportHook = () => {input.username = 'caller-mutated-value';};
    await f.run(async () => {
      const result = await f.context.runActor({actor: f.actor, clusterId: f.cid, workspaceId: f.wid, module: 'workflows', action: 'write'}, () => f.prepare(input));
      expect(result).toMatchObject({version: 1, clusterId: f.cid, canonicalPath: '/consumers', nativeType: 'consumers', kongVersion: '1.5.1', clusterRevision: 1,
        payloadHmac: f.secrets.fingerprint({username: 'planned-client'})});
      expect(Object.isFrozen(result.schemaMaterial.entity.schema)).toBe(true); expect(f.context.current().sessionId).toBeUndefined();
    }); expect(transport.mock.calls.map(call => call[1])).toEqual(['/schemas/consumers']); f.noWrites();
  });
  it('retains the SID HTTP route and refuses ordinary no-SID actors before schema or cluster reads', async () => {
    const f = fixture(); await f.http(undefined, () => expect(f.prepare()).rejects.toMatchObject({response: {code: 'KONG_SCHEMA_PREPARATION_CONTEXT_REQUIRED'}}));
    expect(f.db.one).not.toHaveBeenCalled(); expect(transport).not.toHaveBeenCalled();
    await f.http(randomUUID(), async () => {expect((await f.prepare()).nativeType).toBe('consumers');});
    expect(f.authority.verifyClaim).not.toHaveBeenCalled(); f.noWrites();
  });
  it('does not extend the SID exemption to system reads or internal reads even under a real namespace', async () => {
    const f = fixture(); await f.context.runSystemRead(f.cid, 'probe', () => expect(f.prepare()).rejects.toMatchObject({response: {code: 'KONG_SCHEMA_PREPARATION_CONTEXT_REQUIRED'}}));
    await f.run(async () => {
      await f.context.runInternalRead(f.cid, 'capture', () => expect(f.prepare()).rejects.toMatchObject({response: {code: 'KONG_SCHEMA_PREPARATION_CONTEXT_REQUIRED'}}), {workspaceId: f.wid, paths: ['/schemas/consumers']});
      expect((await f.prepare()).nativeType).toBe('consumers');
    }); f.noWrites();
  });
  it('refuses copied original handles/proofs and cannot adopt them into a fresh Context', async () => {
    const f = fixture(); let proof: any, handle: any;
    await f.run(async () => {handle = f.state.namespaceHandle; proof = await f.context.verifyEntityScheduledNamespace('capture');});
    for (const copied of [{...handle}, {...proof}, {...proof.actor}])
      await expect(f.context.runEntityScheduledNamespace(copied, () => f.prepare())).rejects.toMatchObject({response: {code: 'ENTITY_SCHEDULE_NAMESPACE_ORIGINAL_HANDLE_REQUIRED'}});
    expect(transport).not.toHaveBeenCalled(); f.noWrites();
  });
  it('binds current CID/WID, cluster revision and transport scope before any schema read', async () => {
    for (const change of [{revision: 2}, {admin_url: 'http://different-kong:8001'}, {transport_scope: '9'.repeat(64)}]) {
      const f = fixture(); await f.run(async () => {Object.assign(f.cluster, change); await expect(f.prepare()).rejects.toMatchObject({response: {code: 'KONG_SCHEMA_PREPARATION_CHANGED'}});});
      expect(transport).not.toHaveBeenCalled(); f.noWrites(); transport.mockReset();
    }
    const g = fixture(); await g.run(() => expect(g.kong.prepareSchema(randomUUID(), '/consumers', {})).rejects.toMatchObject({response: {code: 'KONG_SCHEMA_PREPARATION_CONTEXT_REQUIRED'}}));
    expect(transport).not.toHaveBeenCalled(); g.noWrites();
  });
  it('revalidates current original proof after asynchronous GET and rejects changed permissions/claim/owner', async () => {
    for (const mutate of [(f: ReturnType<typeof fixture>) => {f.inspection.permissionVersion += ':changed';},
      (f: ReturnType<typeof fixture>) => {f.inspection.claim.occurrenceId = randomUUID();}, (f: ReturnType<typeof fixture>) => {f.state.ownerActive = false;}]) {
      const f = fixture(); f.state.transportHook = () => mutate(f);
      await f.run(() => expect(f.prepare()).rejects.toMatchObject({status: 403})); expect(transport).toHaveBeenCalledOnce(); f.noWrites(); transport.mockReset();
    }
  });
  it('rechecks the original namespace after cached schema authorization too', async () => {
    const f = fixture(); await f.run(async () => {
      await f.prepare(); await f.prepare(); expect(transport).toHaveBeenCalledOnce();
      f.inspection.permissionVersion += ':revoked'; await expect(f.prepare()).rejects.toMatchObject({response: {code: 'ENTITY_SCHEDULE_NAMESPACE_FACTS_CHANGED'}});
    }); expect(transport).toHaveBeenCalledOnce(); f.noWrites();
  });
  it('rejects expiry/lease loss during async schema reads without returning prepared material', async () => {
    for (const lose of [(f: ReturnType<typeof fixture>) => vi.setSystemTime(new Date(f.inspection.authorityExpiresAt)), (f: ReturnType<typeof fixture>) => {f.state.lease = false;}]) {
      const f = fixture(); f.state.transportHook = () => lose(f); await f.run(() => expect(f.prepare()).rejects.toMatchObject({status: 403})); f.noWrites();
      vi.setSystemTime(new Date('2026-10-13T17:30:00.000Z')); transport.mockReset();
    }
  });
  it('keeps old plugin schema endpoint/unknown-field and version guards without issuing any write', async () => {
    const f = fixture(); await f.run(async () => {
      const plugin = await f.kong.prepareSchema(f.cid, '/plugins', {name: 'key-auth', config: {key_names: ['apikey']}});
      expect(plugin.schemaMaterial.plugin?.canonicalPath).toBe('/plugins/schema/key-auth');
      await expect(f.kong.prepareSchema(f.cid, '/plugins', {name: 'key-auth', config: {unknown_2x: true}})).rejects.toMatchObject({status: 400, response: {code: 'KONG_UNKNOWN_FIELD'}});
    }); expect(transport.mock.calls.map(call => call[1])).toEqual(['/schemas/plugins', '/plugins/schema/key-auth']); f.noWrites();
    const g = fixture(); await g.run(async () => {g.cluster.version = '2.8.0'; await expect(g.prepare()).rejects.toMatchObject({status: 409, response: {code: 'KONG_VERSION_INCOMPATIBLE'}});}); g.noWrites();
  });
});
