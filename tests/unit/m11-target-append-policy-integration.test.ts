import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { EntityChangeExecutionService } from '../../apps/console-api/src/modules/workflows/entity-change-execution.service';
import { DEFAULT_WORKSPACE_ID as wid, workspaceTestResolver } from './workspace-test-helper';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn(), outboundText: vi.fn() }));
// Destination checks stay real, while all DNS/HTTP are source-only adapters.
vi.mock('node:dns/promises', () => ({ lookup: vi.fn(async () => []) }));
const transport = vi.mocked(outboundJson);

/** Real HTTP/context/ticket registries, NativePolicy, workspace resolver,
 * crypto, KongService and transport observation. SQL/current grants and the
 * fixed packet/source/baseline verifier are explicit source adapters, NOT a
 * real Root-issued weight handle or runtime approval/source/SQL evidence.
 * Kernel.canExecute stays closed until its owner integrates the final bridge.
 * The separate real-Kernel negatives never seed its private registries. */
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
  let permissionVersion = 'source-permissions-v1', sessionActive = true, sourceActive = true, originalSourceSession = sessionId;
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
      if (!sourceActive || !sessionActive || frame.actor?.id !== actor.id || frame.sessionId !== originalSourceSession
        || frame.clusterId !== cid || frame.workspaceId !== wid) throw deny('SOURCE_CURRENT_SESSION_REQUIRED');
      if (!baseline.ready || !baseline.oldPresent || !baseline.newAbsent || baseline.parentReference !== upstreamId) throw deny('SOURCE_BASELINE_REQUIRED');
      return { sourceId, baselineId, packetKey: 'packet-1', workflowId, executionId: binding.executionId, stepId: binding.stepId,
        actorId: actor.id, sessionId: originalSourceSession, clusterId: cid, workspaceId: wid, transportScope: scope,
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
  const run = (options: { packet?: boolean; packetHandle?: object; copiedFrame?: boolean; suppliedBody?: any; httpSession?: string; noSession?: boolean } = {}) => context.runHttp({}, async () => {
    context.bindHttpActor(actor, options.noSession ? undefined : options.httpSession ?? sessionId);
    const close = context.captureHttpCloser();
    try { return await context.runActor({ actor, clusterId: cid, workspaceId: wid, module: 'workflows', action: 'write' }, async () => {
      const execute = () => context.runOperation({ actor, clusterId: cid, workspaceId: wid, operationId, entityType: 'targets', entityId: oldId, action: 'update', parentId: upstreamId }, async () => {
        if (options.copiedFrame) return policy.authorizeRequest({ ...context.current() }, cluster, 'POST', collection, options.suppliedBody ?? body, {});
        return kong.request(cid, 'POST', collection, options.suppliedBody ?? body);
      });
      return options.packet === false ? execute() : context.runEntityChangePacket(options.packetHandle ?? handle, execute);
    }); } finally { close(); }
  });
  return { context, policy, kong, sourcePolicy, run, body, before, parent, operation, baseline, binding, handle, secrets, db, authz, cid, collection, nativeId, oldId, sessionId, upstreamId,
    observation: () => ({ observed, wireSpent, sendReserved }), state: {
      permissions: (value: string) => { permissionVersion = value; }, revokeSession: () => { sessionActive = false; }, expireSource: () => { sourceActive = false; },
      sourceSession: (value: string) => { originalSourceSession = value; }, current: (value: any[]) => { current = value; }, next: (value: string) => { nextCursor = value; },
      raw: (value: any) => { writeResult = value; }, status: (value: number) => { writeStatus = value; },
      read: (value: typeof readHook) => { readHook = value; }, posted: (value: () => void) => { postHook = value; },
    } };
}
const posts = () => transport.mock.calls.filter(call => call[2] === 'POST');
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'b8'.repeat(32)); vi.stubEnv('CURSOR_SIGNING_KEY', 'source-only-target-cursor-key-'.repeat(2)); vi.stubEnv('KONG_RATE_WAIT_MS', '0'); transport.mockReset(); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe('M11 Target append NativePolicy/context/transport source integration', () => {
  it('passes the actual full fresh before through authorize/before-send/response, with separate old/new permissions and one observed201', async () => {
    const f = fixture(); f.state.next('page-2');
    const raw = await f.run();
    expect(raw).toMatchObject({ id: f.nativeId, target: f.body.target, weight: 80, upstream: { id: f.upstreamId } });
    expect(posts()).toHaveLength(1); expect(posts()[0][1]).toBe(f.collection); expect(posts()[0][3]).toEqual(f.body);
    expect(f.sourcePolicy.assertNative.mock.calls.every(([, input]) => f.secrets.fingerprint(input.before) === f.secrets.fingerprint(f.before))).toBe(true);
    expect(f.sourcePolicy.assertNative.mock.calls.some(([, , stage]) => stage === 'response')).toBe(true);
    const old = f.authz.assertEntity.mock.calls.filter(call => call[4]?.id === f.oldId), prospective = f.authz.assertEntity.mock.calls.filter(call => call[4]?.id === f.nativeId);
    expect(old.length).toBeGreaterThanOrEqual(3); expect(prospective.length).toBeGreaterThanOrEqual(3);
    const reads = transport.mock.calls.filter(call => call[2] === 'GET' && call[1] === f.collection);
    expect(reads.some(call => call[4]?.offset === 'page-2')).toBe(true);
    expect(transport.mock.calls.some(call => call[1] === `${f.collection}/${f.oldId}`)).toBe(false);
    expect(f.observation()).toMatchObject({ wireSpent: true, observed: { status: 201, operationId: f.operation.id, responseHmac: f.secrets.fingerprint(raw) } });
    expect(f.db.exec.mock.calls.every(([sql]) => !sql.includes('entity_change_packet_events'))).toBe(true);
  });

  it('supports weight0 raw201 without claiming an effective collection member or replaying POST', async () => {
    const f = fixture(0); expect(await f.run()).toMatchObject({ id: f.nativeId, weight: 0 });
    expect(posts()).toHaveLength(1); expect(f.observation().observed.status).toBe(201);
    expect(transport.mock.calls.filter(call => call[1] === f.collection && call[2] === 'GET').every(call => !call[4]?.id)).toBe(true);
  });

  it.each(['ready', 'oldPresent', 'newAbsent'] as const)('requires the original fixed baseline %s before NativePolicy can authorize', async field => {
    const f = fixture(); f.baseline[field] = false;
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'SOURCE_BASELINE_REQUIRED' } }); expect(posts()).toHaveLength(0);
  });

  it('rejects all SQL V3 columns without the original packet and copied/shaped handles/frames', async () => {
    const f = fixture();
    await expect(f.run({ packet: false })).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_PACKET_CONTEXT_INVALID' } });
    for (const packetHandle of [{ ...f.handle }, { sourceId: f.binding.sourceId, baselineId: f.binding.baselineId, approved: true }]) {
      await expect(f.run({ packetHandle })).rejects.toMatchObject({ response: { code: 'SOURCE_ORIGINAL_HANDLE_REQUIRED' } });
    }
    await expect(f.run({ copiedFrame: true })).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
    expect(posts()).toHaveLength(0);
  });

  it('does not borrow the source SID or retain revoked session/source authority', async () => {
    const f = fixture();
    await expect(f.run({ noSession: true })).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_PACKET_CONTEXT_INVALID' } });
    await expect(f.run({ httpSession: randomUUID() })).rejects.toMatchObject({ response: { code: 'SOURCE_CURRENT_SESSION_REQUIRED' } });
    f.state.revokeSession(); await expect(f.run()).rejects.toMatchObject({ response: { code: 'SOURCE_CURRENT_SESSION_REQUIRED' } }); expect(posts()).toHaveLength(0);
    const expired = fixture(); expired.state.expireSource(); await expect(expired.run()).rejects.toMatchObject({ response: { code: 'SOURCE_CURRENT_SESSION_REQUIRED' } });
    expect(posts()).toHaveLength(0);
  });

  it.each(['entity_change_source_id', 'entity_change_baseline_id', 'entity_change_attempt_id', 'entity_change_packet_key'])(
    'checks the original Root binding against the durable %s, not a helper DTO', async field => {
      const f = fixture(); f.operation[field] = field === 'entity_change_packet_key' ? 'packet-foreign' : randomUUID();
      await expect(f.run()).rejects.toMatchObject({ response: { code: 'TARGET_APPEND_PACKET_BINDING_INVALID' } }); expect(posts()).toHaveLength(0);
    });

  it('rejects incomplete V3, completed mutations and legacy step columns rather than falling back', async () => {
    for (const patch of [{ entity_change_baseline_id: null }, { remote_completed: true }, { workflow_step_id: randomUUID() }]) {
      const f = fixture(); Object.assign(f.operation, patch);
      await expect(f.run()).rejects.toMatchObject({ response: { code: 'TARGET_APPEND_HTTP_SOURCE_REQUIRED' } }); expect(posts()).toHaveLength(0);
    }
  });

  it('decrypts before only with exact mutation AAD and requires the frozen complete packet body', async () => {
    const f = fixture(); f.operation.before_secret = f.secrets.encrypt(f.before, `mutation:${randomUUID()}:before`);
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'TARGET_APPEND_MUTATION_SECRETS_INVALID' } }); expect(posts()).toHaveLength(0);
    const changed = fixture();
    await expect(changed.run({ suppliedBody: { ...changed.body, weight: 81 } })).rejects.toMatchObject({ response: { code: 'TARGET_APPEND_PACKET_INVALID' } }); expect(posts()).toHaveLength(0);
  });

  it('does not adopt a replacement operation key or a payload encrypted under another mutation AAD', async () => {
    const f = fixture(); f.operation.idempotency_key = 'replacement-operation-key';
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'SOURCE_MUTATION_PACKET_MISMATCH' } }); expect(posts()).toHaveLength(0);
    const wrongAad = fixture(); wrongAad.operation.payload_secret = wrongAad.secrets.encrypt(wrongAad.body, `mutation:${randomUUID()}:payload`);
    await expect(wrongAad.run()).rejects.toThrow(); expect(posts()).toHaveLength(0);
  });

  it('rejects a historical/wrong or changed effective before, including drift during the last before-send refresh', async () => {
    const f = fixture(); f.state.current([{ ...f.before, id: f.nativeId }]);
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'TARGET_APPEND_BEFORE_CHANGED' } }); expect(posts()).toHaveLength(0);
    const drift = fixture(); let effectiveReads = 0;
    drift.state.read(async path => { if (path === drift.collection && ++effectiveReads === 3) drift.state.current([{ ...drift.before, weight: 101 }]); });
    await expect(drift.run()).rejects.toMatchObject({ response: { code: 'TARGET_APPEND_BEFORE_CHANGED' } }); expect(posts()).toHaveLength(0);
    expect(drift.observation().wireSpent).toBe(false);
  });

  it('keeps old-ID-only authorization closed for the new UUID before transport', async () => {
    const f = fixture(); f.authz.assertEntity.mockImplementation(async (_actor, _cid, type, _action, entity) => {
      if (type === 'targets' && entity.id !== f.oldId) throw new ForbiddenException({ code: 'ENTITY_WHITELIST_DENIED' });
    });
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'ENTITY_WHITELIST_DENIED' } }); expect(posts()).toHaveLength(0);
  });

  it('does not authorize an empty-tag new POST using old business tags, including null/omission', async () => {
    for (const nullTags of [false, true]) {
      const f = fixture(); if (nullTags) f.body.tags = null; else delete f.body.tags;
      f.operation.payload_secret = f.secrets.encrypt(f.body, `mutation:${f.operation.id}:payload`); f.baseline.bodyHmac = f.secrets.fingerprint(f.body);
      f.authz.assertEntity.mockImplementation(async (_actor, _cid, type, _action, entity) => {
        if (type === 'targets' && !entity.tags?.includes('owner-pay')) throw new ForbiddenException({ code: 'TAG_GROUP_DENIED' });
      });
      await expect(f.run()).rejects.toMatchObject({ response: { code: 'TAG_GROUP_DENIED' } }); expect(posts()).toHaveLength(0);
    }
  });

  it('checks actual parent workspace membership before either UUID write authorization', async () => {
    const f = fixture(); f.parent.tags = ['kos-ws-pay'];
    await expect(f.run()).rejects.toMatchObject({ status: 403 }); expect(posts()).toHaveLength(0);
  });

  it('retains exact finite read scope and cannot acquire unrelated paths while fetching effective pages', async () => {
    const f = fixture(); f.state.read(async path => {
      if (path === f.collection) await f.kong.request(f.cid, 'GET', `/upstreams/${randomUUID()}`);
    });
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'KONG_INTERNAL_PATH_FORBIDDEN' } }); expect(posts()).toHaveLength(0);
  });

  it('rejects current permission version changes after an awaited effective lookup', async () => {
    const f = fixture(); f.state.read(async path => { if (path === f.collection) f.state.permissions('source-permissions-v2'); });
    await expect(f.run()).rejects.toMatchObject({ status: 403 }); expect(posts()).toHaveLength(0);
  });

  it.each([{ weight: 100 }, { target: '192.0.2.11:8080' }, { tags: ['owner-other'] }, { upstream: { id: randomUUID() } }, { id: randomUUID() }])(
    'retains actual sent201/raw HMAC if reflected native fields mismatch %j, without treating it as not-sent', async patch => {
      const f = fixture(); const raw = { ...f.body, upstream: { id: f.upstreamId }, ...patch }; f.state.raw(raw);
      await expect(f.run()).rejects.toMatchObject({ response: { code: 'KONG_WRITE_AUTHORIZATION_CHANGED' } });
      expect(posts()).toHaveLength(1); expect(f.observation()).toMatchObject({ wireSpent: true, sendReserved: true,
        observed: { status: 201, raw, responseHmac: f.secrets.fingerprint(raw) } });
      expect(f.db.exec.mock.calls.every(([sql]) => !sql.includes('entity_change_packet_events'))).toBe(true);
    });

  it('does not unwrap a manufactured entity envelope into an accepted raw201 row', async () => {
    const f = fixture(), wrapper = { entity: { ...f.body, upstream: { id: f.upstreamId } } }; f.state.raw(wrapper);
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'KONG_WRITE_AUTHORIZATION_CHANGED' } });
    expect(posts()).toHaveLength(1); expect(f.observation()).toMatchObject({ wireSpent: true, observed: { status: 201, raw: wrapper } });
  });

  it('retains the raw transport observation when authority is revoked after a real send', async () => {
    const f = fixture(); f.state.posted(() => f.state.revokeSession());
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'KONG_WRITE_AUTHORIZATION_CHANGED' } });
    expect(posts()).toHaveLength(1); expect(f.observation()).toMatchObject({ wireSpent: true, observed: { status: 201 } });
  });

  it('does not accept a non201 response as a new native receipt in the fixed source verifier', async () => {
    const f = fixture(); f.state.status(200);
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'KONG_WRITE_AUTHORIZATION_CHANGED' } });
    expect(posts()).toHaveLength(1); expect(f.observation().observed.status).toBe(200);
  });

  it('preserves the direct legacy update path without granting it an M11 packet', async () => {
    const f = fixture();
    for (const key of ['entity_change_source_id', 'entity_change_baseline_id', 'entity_change_attempt_id', 'entity_change_packet_key']) f.operation[key] = null;
    // SQL cluster adapter remains a real direct-mode gate in this test.
    const read = f.db.one.getMockImplementation()!;
    f.db.one.mockImplementation(async (sql: string, values: any[]) => { const row = await read(sql, values); return sql.includes('FROM clusters') ? { ...row, execution_mode: 'direct' } : row; });
    expect(await f.run({ packet: false })).toMatchObject({ id: f.nativeId });
    expect(posts()).toHaveLength(1); expect(f.sourcePolicy.mutationBinding).not.toHaveBeenCalled();
  });
});

describe('M11 Target NativePolicy integration does not replace real Root authority', () => {
  it('real Kernel refuses shaped/copied handles before SQL, native policy or transport can authorize', async () => {
    const f = fixture(), context = new KongExecutionContextService(), db: any = { one: vi.fn(), query: vi.fn(), exec: vi.fn() };
    const kernel = new EntityChangeExecutionService(db, {} as any, f.secrets, context, {} as any, {} as any, {} as any, {} as any,
      {} as any, {} as any, { installFixedDelegate: vi.fn() } as any, {} as any, { installExecutionDelegate: vi.fn() } as any, {} as any);
    context.installEntityChangePacketPolicy(kernel);
    for (const value of [{ ...f.handle }, { sourceId: f.binding.sourceId, baselineId: f.binding.baselineId, packetKey: 'packet-1', approved: true }]) {
      await expect(kernel.verifyHandle(value)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_EXECUTION_PROOF_INVALID' } });
    }
    expect(db.one).not.toHaveBeenCalled(); expect(posts()).toHaveLength(0);
  });
});
