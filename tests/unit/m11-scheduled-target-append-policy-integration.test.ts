import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { immutableJson } from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { EntityScheduledNamespaceService } from '../../apps/console-api/src/modules/workflows/entity-scheduled-namespace.service';
import { scheduledTargetWeightPacket } from '../../apps/console-api/src/modules/workflows/entity-scheduled-target-weight-packet';
import { DEFAULT_WORKSPACE_ID as wid, workspaceTestResolver } from './workspace-test-helper';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn(), outboundText: vi.fn() }));
// Destination checks stay real, while all DNS/HTTP are source-only adapters.
vi.mock('node:dns/promises', () => ({ lookup: vi.fn(async () => []) }));
const transport = vi.mocked(outboundJson);

/** Real Namespace, Context, SDK and NativePolicy registries. Current SQL roles,
 * original Authority and packet/source/baseline verifiers plus outbound transport
 * are explicit Source adapters. This does not prove real SQL024 or Native facts,
 * and no Kernel private registry is seeded. Runtime acceptance belongs to Root. */
function fixture(weight = 80) {
  const secrets = new SecretService(), context = new KongExecutionContextService();
  const cid = randomUUID(), sessionId = randomUUID(), operationId = randomUUID(), upstreamId = randomUUID(), oldId = randomUUID(), nativeId = randomUUID();
  const sourceId = randomUUID(), baselineId = randomUUID(), attemptId = randomUUID(), workflowId = randomUUID();
  const actor = { id: randomUUID(), username: 'source-owner', superAdmin: false };
  const tags = ['owner-pay'];
  const before = { id: oldId, target: '192.0.2.10:8080', weight: 100, tags, upstream: { id: upstreamId }, created_at: 1 };
  const body: any = { id: nativeId, target: before.target, weight, tags: [...tags] };
  const parent: any = { id: upstreamId, name: 'unit-upstream', tags: [] };
  const collection = `/upstreams/${upstreamId}/targets`, scope = transportScopeFor('http://kong:8001');
  const cluster: any = { id: cid, admin_url: 'http://kong:8001', connection_secret: null, transport_scope: null, version: '1.5.1', execution_mode: 'approval', revision: 1, status: 'healthy', capabilities: {} };
  const originalOperationKey = 'original-target-weight-key';
  const operation: any = { id: operationId, cluster_id: cid, workspace_id: wid, actor_id: actor.id, entity_id: oldId,
    entity_type: 'targets', action: 'update', state: 'running', remote_started: true, remote_completed: false, workflow_id: workflowId,
    parent_id: upstreamId, credential_kind: null, idempotency_key: originalOperationKey,
    entity_change_source_id: sourceId, entity_change_baseline_id: baselineId, entity_change_attempt_id: attemptId, entity_change_packet_key: 'packet-1',
    before_secret: secrets.encrypt(before, `mutation:${operationId}:before`), payload_secret: secrets.encrypt(body, `mutation:${operationId}:payload`) };
  const baseline = { ready: true, oldPresent: true, newAbsent: true, parentReference: upstreamId,
    beforeHmac: secrets.fingerprint(before), bodyHmac: secrets.fingerprint(body) };
  let permissionVersion = 'source-permissions-v1', sessionActive = true, sourceActive = true, originalSourceSession: string | null = null;
  let nextCursor: string | null = null, current: any[] = [before], writeResult: any = { ...body, upstream: { id: upstreamId }, created_at: 2 };
  let writeStatus = 201, wireSpent = false, sendReserved = false;
  let observed: any, readHook: ((path: string, query: any) => Promise<void>) | undefined, postHook: (() => void) | undefined;
  const handle = Object.freeze({}), authentic = new WeakSet<object>([handle]);
  const deny = (code: string) => new ForbiddenException({ code });
  const binding = { version: 3, workflowId, executionId: randomUUID(), planRevision: 1, planHash: secrets.fingerprint('source-plan'), stepId: randomUUID(),
    sourceId, baselineId, attemptId, packetKey: 'packet-1', nativeId, beforeHmac: baseline.beforeHmac };
  const sourcePolicy: any = {
    verifyHandle: vi.fn(async value => {
      if (!authentic.has(value)) throw deny('SOURCE_ORIGINAL_HANDLE_REQUIRED');
      const frame = context.current();
      if (!sourceActive || !sessionActive || frame.actor?.id !== actor.id || (frame.sessionId ?? null) !== originalSourceSession || !context.hasEntityScheduledNamespace()
        || frame.clusterId !== cid || frame.workspaceId !== wid) throw deny('SOURCE_CURRENT_SESSION_REQUIRED');
      if (!baseline.ready || !baseline.oldPresent || !baseline.newAbsent || baseline.parentReference !== upstreamId) throw deny('SOURCE_BASELINE_REQUIRED');
      return { sourceId, baselineId, packetKey: 'packet-1', workflowId, executionId: binding.executionId, stepId: binding.stepId,
        actorId: actor.id, sessionId: null, origin: 'scheduled-entity', clusterId: cid, workspaceId: wid, transportScope: scope,
        permissionVersion: 'source-permissions-v1', expiresAt: Date.now() + 300000 };
    }),
    mutationBinding: vi.fn(async (value, input) => {
      await sourcePolicy.verifyHandle(value);
      if (input.entityId !== oldId || input.parentId !== upstreamId || input.actor.id !== actor.id || input.action !== 'update'
        || input.entityType !== 'targets' || input.idempotencyKey !== originalOperationKey
        || secrets.fingerprint(input.before) !== baseline.beforeHmac || secrets.fingerprint(input.payload) !== baseline.bodyHmac) throw deny('SOURCE_MUTATION_PACKET_MISMATCH');
      return { ...binding };
    }), bindOperation: vi.fn(),
    assertNative: vi.fn(async (value, input, stage) => {
      await sourcePolicy.verifyHandle(value);
      if (context.requireEntityChangePacketFrame(input.frame) !== handle || input.operationId !== operationId || input.transportScope !== scope
        || input.method !== 'POST' || input.canonicalPath !== collection || input.parentId !== upstreamId
        || input.mutationAction !== 'update' || Object.keys(input.query).length || permissionVersion !== 'source-permissions-v1'
        || secrets.fingerprint(input.before) !== baseline.beforeHmac || secrets.fingerprint(input.body) !== baseline.bodyHmac) throw deny('SOURCE_NATIVE_PACKET_MISMATCH');
      if (stage === 'response' && (!wireSpent || observed?.status !== 201 || input.result?.id !== nativeId
        || secrets.fingerprint(input.result) !== observed.responseHmac)) throw deny('SOURCE_NATIVE_RECEIPT_REQUIRED');
    }),
    beforeNativeSend: vi.fn(async (value, input) => { await sourcePolicy.assertNative(value, input, 'before-send'); sendReserved = true; }),
    spendTransport: vi.fn((_value, _input) => { if (!sendReserved || wireSpent) throw deny('SOURCE_ONE_SEND_REQUIRED'); wireSpent = true; }),
    observeTransportResponse: vi.fn((_value, input, status, raw) => {
      if (!wireSpent) throw deny('SOURCE_REAL_SEND_REQUIRED');
      observed = { status, responseHmac: secrets.fingerprint(raw), raw: structuredClone(raw), operationId: input.operationId, before: input.before };
    }),
  };
  context.installEntityChangePacketPolicy(sourcePolicy);
  const db: any = { one: vi.fn(async (sql, values) => {
    if (sql.includes('FROM mutation_operations')) return values[0] === operationId ? operation : null;
    if (sql.includes('FROM clusters')) return values[0] === cid ? cluster : null;
    if (sql.includes('destination_policies')) return { allowed_hosts: [], allowed_cidrs: ['192.0.2.0/24'] };
    return null;
  }), query: vi.fn(async () => []), exec: vi.fn(async () => 1) };
  const redis: any = { withLock: vi.fn(async (_key, fn) => fn()), assertLeaseActive: vi.fn(), assertLeaseOwnership: vi.fn(async () => undefined),
    rateLimit: vi.fn(async () => ({ allowed: true, retryAfterMs: 0 })) };
  const authz: any = { snapshot: vi.fn(async () => ({ user: actor, grants: [{ cluster_id: cid }], version: permissionVersion })),
    permissionVersion: vi.fn(async () => permissionVersion), assertCluster: vi.fn(), assertEntity: vi.fn(), assertNestedParentScope: vi.fn() };
  const kong = new KongService(db, redis, secrets, {} as any, context), resolver = workspaceTestResolver(cid).resolver;
  const policy = new NativeKongPolicyService(db, secrets, kong, context, authz, resolver); policy.install();
  const expiry = new Date(Date.now() + 60000).toISOString(), authorityHandle = Object.freeze({}), authorityOriginals = new WeakSet<object>([authorityHandle]);
  let authorityLive = false, authorityEligible = true;
  const packet: any = { key: 'packet-1', order: 1, dependencies: [], method: 'POST', canonicalPath: collection, nativeType: 'targets', nativeId,
    originalNativeId: oldId, parentId: upstreamId, mutationAction: 'update', permissionAction: 'write', before, body,
    bodyHmac: secrets.fingerprint(body), beforeHmac: secrets.fingerprint(before) };
  const plan: any = { kind: 'native-change', workflowId, planRevision: 1, clusterId: cid, workspaceId: wid,
    requester: { type: 'console', id: actor.id }, executionMode: 'approval', approvalRequired: true, expiresAt: expiry };
  const inspection: any = { version: 1, principal: actor, permissionVersion: 'source-permissions-v1', authorityExpiresAt: expiry, leaseUntil: expiry, plan,
    envelope: { version: 2, clusterId: cid, workspaceId: wid, requesterId: actor.id, intentId: randomUUID(), revision: 1, credentialEpoch: '1', executionMode: 'approval', expiresAt: expiry,
      prepared: { scope: { transportScope: scope, clusterRevision: 1, workspaceRevision: 1 }, packets: [packet] },
      scheduling: { specHmac: 'a'.repeat(64), delegationHmac: 'b'.repeat(64), delegation: { id: randomUUID(), ownerId: actor.id, executorId: actor.id, ownerCredentialEpoch: '1', executorCredentialEpoch: '1' } } },
    draft: { scheduleId: randomUUID(), binding: { clusterId: cid, workspaceId: wid, materialHmac: 'c'.repeat(64), changeDigest: 'd'.repeat(64), packetManifestHmac: 'e'.repeat(64) },
      spec: { windowStart: new Date(Date.now() - 1000).toISOString(), windowEnd: expiry } },
    approvalSet: { format: 2, setId: randomUUID(), setHmac: 'f'.repeat(64), reviewers: [{ userId: randomUUID() }] } };
  inspection.claim = { id: randomUUID(), scheduleId: inspection.draft.scheduleId, generation: 1, scheduleVersion: 1, workflowId,
    workflowPlanRevision: 1, workflowPlanHash: secrets.fingerprint(plan), authorityExpiresAt: expiry };
  const currentAuthority = async (h: object) => {
    if (!authorityOriginals.has(h) || !authorityLive || !authorityEligible) throw deny('CONTROLLED_SCHEDULED_AUTHORITY_REQUIRED');
    return immutableJson(inspection);
  };
  const authority: any = { verifyClaim: vi.fn(currentAuthority), inspect: vi.fn(currentAuthority), verifyTargetWeightPacket: vi.fn(async (h: object, key: string) => {
    const observed = await currentAuthority(h); return { inspection: observed, packet: scheduledTargetWeightPacket(observed, key, secrets) };
  }) };
  const namespace = new EntityScheduledNamespaceService(authority, secrets, redis);
  namespace.installContextRunner({ assertNoFrame: () => { if (context.peek()) throw deny('NO_INHERITED_FRAME'); },
    run: (h, fn) => context.runEntityScheduledNamespace(h, fn), requireCurrentHandle: () => context.requireEntityScheduledNamespaceHandle() });
  context.installEntityScheduledNamespacePolicy(namespace);
  policy.installScheduledTargetAppendBridge({ verifyOriginalPacket: async (h, p, key) => {
    await sourcePolicy.verifyHandle(p);
    if (context.requireEntityScheduledNamespaceHandle() !== h || p !== handle || key !== 'packet-1') throw deny('CONTROLLED_SCHEDULED_PACKET_REQUIRED');
    return namespace.verifyTargetWeightPacket(h, key);
  } });
  transport.mockImplementation(async (_base, path, method, payload, query, _auth, _timeout, fence, prepare) => {
    if (prepare) await prepare(); fence?.();
    if (method === 'POST') { postHook?.(); return { status: writeStatus, body: structuredClone(writeResult), bytes: 200 }; }
    if (readHook) await readHook(path, query);
    if (path === `/upstreams/${upstreamId}`) return { status: 200, body: structuredClone(parent), bytes: 80 };
    if (path === collection) return { status: 200, body: { data: structuredClone(query?.offset ? [] : current), next: !query?.offset && nextCursor ? `${collection}?offset=${nextCursor}&size=100` : null }, bytes: 200 };
    if (path === '/schemas/targets') return { status: 200, body: { fields: [{ id: { type: 'string' } }, { target: { type: 'string', required: true } },
      { weight: { type: 'integer', between: [0, 1000] } }, { tags: { type: 'set', elements: { type: 'string' } } }] }, bytes: 200 };
    return { status: 404, body: { message: 'Not found' }, bytes: 20 };
  });
  const run = async (options: { packetHandle?: object; suppliedBody?: any; copiedFrame?: boolean } = {}) => {
    authorityLive = true;
    try { return await namespace.runOriginalClaim(authorityHandle, () => context.runEntityChangePacket(options.packetHandle ?? handle, () =>
      context.runOperation({ actor, clusterId: cid, workspaceId: wid, operationId, entityType: 'targets', entityId: oldId, action: 'update', parentId: upstreamId }, () => {
        if (options.copiedFrame) return policy.authorizeRequest({ ...context.current() }, cluster, 'POST', collection, options.suppliedBody ?? body, {});
        return kong.request(cid, 'POST', collection, options.suppliedBody ?? body);
      })));
    } finally { authorityLive = false; }
  };
  return { context, policy, kong, sourcePolicy, run, body, before, parent, operation, baseline, binding, handle, secrets, db, authz, cid, collection, nativeId, oldId, sessionId, upstreamId,
    observation: () => ({ observed, wireSpent, sendReserved }), state: {
      revokeAuthority: () => { authorityEligible = false; },
      permissions: (value: string) => { permissionVersion = value; }, revokeSession: () => { sessionActive = false; }, expireSource: () => { sourceActive = false; },
      sourceSession: (value: string) => { originalSourceSession = value; }, current: (value: any[]) => { current = value; }, next: (value: string) => { nextCursor = value; },
      raw: (value: any) => { writeResult = value; }, status: (value: number) => { writeStatus = value; },
      read: (value: typeof readHook) => { readHook = value; }, posted: (value: () => void) => { postHook = value; },
    } };
}
const posts = () => transport.mock.calls.filter(call => call[2] === 'POST');
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'b8'.repeat(32)); vi.stubEnv('CURSOR_SIGNING_KEY', 'source-only-target-cursor-key-'.repeat(2)); vi.stubEnv('KONG_RATE_WAIT_MS', '0'); transport.mockReset(); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
describe('Scheduled Target append NativePolicy Source integration, with SID null', () => {
  it.each([100, 80, 0])('supports weight %s using original NS and packet with a full scoped EOF and one controlled POST', async weight => {
    const f = fixture(weight); f.state.next('page-2'); const raw = await f.run();
    expect(raw).toMatchObject({ id: f.nativeId, weight, upstream: { id: f.upstreamId } }); expect(posts()).toHaveLength(1);
    expect(f.sourcePolicy.verifyHandle.mock.results.length).toBeGreaterThan(0);
    expect(f.sourcePolicy.assertNative.mock.calls.every(([, input]) => input.frame.sessionId == null)).toBe(true);
    expect(transport.mock.calls.filter(call => call[2] === 'GET' && call[1] === f.collection).some(call => call[4]?.offset === 'page-2')).toBe(true);
    expect(transport.mock.calls.some(call => call[1] === f.collection + '/' + f.oldId)).toBe(false);
  });
  it('a copied original packet cannot borrow the actual scheduled frame', async () => {
    const f = fixture(); await expect(f.run({ packetHandle: { ...f.handle } })).rejects.toMatchObject({ response: { code: 'SOURCE_ORIGINAL_HANDLE_REQUIRED' } }); expect(posts()).toHaveLength(0);
  });
  it('rejects a SQL packet-key substitution before any controlled Native request', async () => {
    const f = fixture(); f.operation.entity_change_packet_key = 'foreign-packet'; await expect(f.run()).rejects.toMatchObject({ response: { code: 'TARGET_APPEND_PACKET_BINDING_INVALID' } }); expect(posts()).toHaveLength(0);
  });
  it('rechecks actual current old and new UUID grants independently, never extending old-ID-only authority', async () => {
    const f = fixture(); f.authz.assertEntity.mockImplementation(async (_actor, _cid, type, _action, entity) => { if (type === 'targets' && entity.id !== f.oldId) throw new ForbiddenException({ code: 'ENTITY_WHITELIST_DENIED' }); });
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'ENTITY_WHITELIST_DENIED' } }); expect(posts()).toHaveLength(0);
  });
  it('revocation during collection EOF blocks the pending send instead of borrowing the original role', async () => {
    const f = fixture(); f.state.read(async path => { if (path === f.collection) f.state.revokeAuthority(); }); await expect(f.run()).rejects.toMatchObject({ response: { code: 'CONTROLLED_SCHEDULED_AUTHORITY_REQUIRED' } }); expect(posts()).toHaveLength(0);
  });
  it('a changed effective old Target is not replaced by a historical UUID or sealed before object', async () => {
    const f = fixture(); f.state.current([{ ...f.before, weight: 101 }]); await expect(f.run()).rejects.toMatchObject({ response: { code: 'TARGET_APPEND_BEFORE_CHANGED' } }); expect(posts()).toHaveLength(0);
  });
  it('an invalid actual response stays a controlled sent result, never an unsent claim or a second POST', async () => {
    const f = fixture(); f.state.raw({ ...f.body, id: randomUUID(), upstream: { id: f.upstreamId } }); await expect(f.run()).rejects.toThrow(); expect(posts()).toHaveLength(1);
    await expect(f.run()).rejects.toThrow(); expect(posts()).toHaveLength(1);
  });
});
