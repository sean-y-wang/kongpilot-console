import 'reflect-metadata';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {immutableJson} from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {EntityChangeBoundaryService} from '../../apps/console-api/src/modules/entities/entity-change-boundary.service';
import {EntityScheduledNamespaceService} from '../../apps/console-api/src/modules/workflows/entity-scheduled-namespace.service';

/** Real Context/Namespace private registries and real authorization policy;
 * SQL, original Authority execution and Portal remain source-only adapters.
 * No private map is seeded and no frame/proof DTO is installed as authority. */
function fixture(expiryMs = 240000) {
  const secrets = new SecretService(), context = new KongExecutionContextService(), owner = randomUUID(), cid = randomUUID(), wid = randomUUID(), nativeId = randomUUID();
  const expiresAt = new Date(Date.now() + expiryMs).toISOString(), originalAuthority = Object.freeze({}), issued = new WeakSet<object>([originalAuthority]);
  const state: any = {executing: false, lease: false, ownerActive: true, credentialEpoch: '1', iam: '1', clusterRevision: 1, workspaceRevision: 1,
    workspaceStatus: 'active', transportScope: 'a'.repeat(64), grants: true, passwordChange: false, revokeNamespace: false, portalHook: null};
  const user = {id: owner, username: 'sql-owner', superAdmin: false}, actor = {user, workspaceId: wid};
  const before = {id: nativeId, username: 'before', tags: []}, body = {username: 'after'};
  const packet: any = {key: 'p1', order: 1, dependencies: [], method: 'PATCH', canonicalPath: `/consumers/${nativeId}`, nativeType: 'consumers', nativeId,
    permissionAction: 'write', mutationAction: 'update', before, body, bodyHmac: secrets.fingerprint(body), beforeHmac: secrets.fingerprint(before)};
  const payload: any = {version: 1, clusterId: cid, workspaceId: wid, requesterId: owner, permissionVersion: `${owner}:1:1`,
    scope: {transportScope: state.transportScope, clusterRevision: 1, workspaceRevision: 1, kongVersion: '1.5.1', adapter: 'kong-oss-1.5-v1'},
    request: {kind: 'entity', action: 'update', entityType: 'consumers', entityId: nativeId, body}, prerequisites: [], schemas: [], packets: [packet], metadataObligations: [],
    recovery: {state: 'baseline-required', blockerCodes: [], objects: []}, impact: {changedObjects: 1}};
  const material: any = immutableJson({...payload, changeDigest: secrets.fingerprint(payload)});
  const envelope: any = immutableJson({version: 2, intentId: randomUUID(), revision: 1, clusterId: cid, workspaceId: wid, requesterId: owner,
    credentialEpoch: '1', issuedAt: new Date().toISOString(), expiresAt, ttlHours: 24, executionMode: 'approval', definition: {}, packetManifestHmac: 'b'.repeat(64), prepared: material, review: {},
    scheduling: {specHmac: 'c'.repeat(64), delegationHmac: 'd'.repeat(64), delegation: {id: randomUUID(), ownerId: owner, executorId: owner, ownerCredentialEpoch: '1', executorCredentialEpoch: '1'}}});
  const plan: any = immutableJson({workflowId: randomUUID(), planRevision: 1, kind: 'native-change', clusterId: cid, workspaceId: wid,
    requester: {type: 'console', id: owner}, executionMode: 'approval', approvalRequired: true, expiresAt, steps: []});
  const scheduleId = randomUUID(), inspection: any = immutableJson({version: 1, envelope, plan, principal: user, permissionVersion: `${owner}:1:1`, authorityExpiresAt: expiresAt, leaseUntil: expiresAt,
    draft: {scheduleId, binding: {clusterId: cid, workspaceId: wid, materialHmac: secrets.fingerprint(envelope), changeDigest: material.changeDigest, packetManifestHmac: envelope.packetManifestHmac},
      spec: {windowStart: new Date(Date.now() - 1000).toISOString(), windowEnd: expiresAt}},
    claim: {id: randomUUID(), scheduleId, scheduleVersion: 1, occurrenceId: randomUUID(), generation: 1, workerOwnerHmac: 'e'.repeat(64), issuedAt: new Date().toISOString(),
      authorityExpiresAt: expiresAt, initialLeaseUntil: expiresAt, workflowId: plan.workflowId, workflowPlanRevision: 1, workflowPlanHash: secrets.fingerprint(plan)},
    approvalSet: {format: 2, policyHash: 'f'.repeat(64), setId: randomUUID(), setHmac: '1'.repeat(64), reviewers: [{approvalId: randomUUID(), userId: randomUUID(), level: 1, candidateVersion: 1}]}});
  const authority: any = {verifyClaim: vi.fn(async (h: object) => {
    if (!issued.has(h) || !state.executing || !state.lease || state.revokeNamespace) throw new ForbiddenException({code: 'ORIGINAL_AUTHORITY_EXECUTION_REQUIRED'});
    return inspection;
  }), inspect: vi.fn(async (h: object) => {if (!issued.has(h)) throw new ForbiddenException(); return inspection;})};
  const redis: any = {assertLeaseActive: vi.fn(() => {if (!state.lease) throw new ForbiddenException({code: 'LEASE_CLOSED'});}),
    assertLeaseOwnership: vi.fn(async () => {if (!state.lease) throw new ForbiddenException({code: 'LEASE_CLOSED'});})};
  const namespace = new EntityScheduledNamespaceService(authority, secrets, redis);
  namespace.installContextRunner({assertNoFrame: () => {if (context.peek()) throw new ForbiddenException({code: 'EXISTING_FRAME'});}, run: (h, fn) => context.runEntityScheduledNamespace(h, fn)});
  context.installEntityScheduledNamespacePolicy({verifyHandle: (h, p) => namespace.verifyHandle(h, p), assertLive: h => namespace.assertLive(h)});
  const row = () => ({id: owner, username: user.username, super_admin: false, permissions_epoch: '1', credential_epoch: state.credentialEpoch,
    force_password_change: state.passwordChange, revision: 1});
  const db: any = {one: vi.fn(async (sql: string, args: any[] = []) => {
    if (sql.includes('FROM users')) return args[0] === owner && state.ownerActive && (!sql.includes('NOT force_password_change') || !state.passwordChange) ? row() : null;
    if (sql.includes('FROM iam_epoch')) return {version: state.iam};
    if (sql.includes('FROM clusters')) return {id: cid, revision: state.clusterRevision};
    if (sql.includes('FROM auth_sessions')) return {id: args[0]};
    throw new Error(`Unexpected read ${sql}`);
  }), query: vi.fn(async (sql: string) => {
    if (!sql.includes('iam_effective_grants')) throw new Error(`Unexpected list ${sql}`);
    return state.grants ? ['consumers', 'workflows'].map(module => ({module, action: 'write', scope_type: 'entity', cluster_id: cid, workspace_id: wid,
      scope_values: [{entity_type: 'consumers', entity_id: nativeId}]})) : [];
  }), exec: vi.fn(async () => {throw new Error('Boundary must not write SQL');})};
  const workspaces: any = {get: vi.fn(async () => ({id: wid, cluster_id: cid, code: 'default', is_default: true, status: state.workspaceStatus, revision: state.workspaceRevision}))};
  const kong: any = {transportScope: vi.fn(async () => state.transportScope), request: vi.fn(async () => {throw new Error('Unexpected Admin API request');}), list: vi.fn()};
  const authz = new AuthorizationService(db, workspaces, kong, context), portal: any = {assertPreparedChange: vi.fn(async () => {if (state.portalHook) await state.portalHook();})};
  const boundary = new EntityChangeBoundaryService(db, secrets, context, authz, workspaces, kong, {} as any, portal);
  const run = async <T>(fn: () => Promise<T>): Promise<T> => {state.executing = true; state.lease = true; try {return await namespace.runOriginalClaim(originalAuthority, fn);} finally {state.executing = false; state.lease = false;}};
  const http = <T>(sid: string | undefined, fn: () => Promise<T>): Promise<T> => context.runHttp({}, async () => {
    context.bindHttpActor(user, sid); const close = context.captureHttpCloser();
    try {return await context.runActor({actor: user, clusterId: cid, workspaceId: wid, module: 'workflows', action: 'write'}, fn);} finally {close();}
  });
  const subject = (m = material, a = actor) => boundary.assertStoredSubject({material: m, actor: a, action: 'write', mode: 'fresh'});
  const checkPacket = (override: any = {}) => boundary.assertPacket({clusterId: cid, workspaceId: wid, transportScope: material.scope.transportScope, packet, actor, phase: 'revalidate', action: 'write', ...override});
  return {boundary, namespace, context, authz, authority, inspection, originalAuthority, material, envelope, actor, packet, state, db, portal, kong, secrets, run, http, subject, checkPacket};
}
beforeEach(() => {vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '9a'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T17:20:00.000Z'));});
afterEach(() => {vi.useRealTimers(); vi.unstubAllEnvs();});
describe('M11 scheduled entity boundary (source-only original namespace fixtures)', () => {
  it('refuses a no-SID ordinary actor, even with owner IDs and a copied scheduled proof', async () => {
    const f = fixture(); await f.http(undefined, async () => {
      expect(await f.context.verifyEntityScheduledNamespace('capture')).toBeNull();
      await expect(f.subject()).rejects.toMatchObject({response: {code: 'ENTITY_CHANGE_ACTOR_CONTEXT_REQUIRED'}});
      await expect(f.checkPacket()).rejects.toMatchObject({response: {code: 'ENTITY_CHANGE_ACTOR_CONTEXT_REQUIRED'}});
      await expect(f.boundary.assertIntentSubject(f.envelope, f.actor.user.id, 'write')).rejects.toMatchObject({status: 403});
    });
    await expect(f.context.runEntityScheduledNamespace({...f.inspection}, async () => true)).rejects.toMatchObject({response: {code: 'ENTITY_SCHEDULE_NAMESPACE_ORIGINAL_HANDLE_REQUIRED'}});
    expect(f.portal.assertPreparedChange).not.toHaveBeenCalled();
  });
  it('uses the original private namespace for stored subject, exact V2 intent and packet without runActor or native writes', async () => {
    const f = fixture(), runActor = vi.spyOn(f.context, 'runActor');
    await f.run(async () => {
      expect(f.context.current().sessionId).toBeUndefined();
      await f.subject(); await f.boundary.assertIntentSubject(f.envelope, f.actor.user.id, 'write'); await f.checkPacket();
      const h = f.context.requireEntityScheduledNamespaceHandle(), proof = await f.context.verifyEntityScheduledNamespace('capture');
      await expect(f.context.runEntityScheduledNamespace({...h}, async () => true)).rejects.toMatchObject({response: {code: 'ENTITY_SCHEDULE_EXISTING_CONTEXT_FORBIDDEN'}});
      await expect(f.namespace.verifyHandle({...proof}, 'packet')).rejects.toMatchObject({response: {code: 'ENTITY_SCHEDULE_NAMESPACE_ORIGINAL_HANDLE_REQUIRED'}});
    });
    expect(runActor).not.toHaveBeenCalled(); expect(f.portal.assertPreparedChange).toHaveBeenCalledOnce(); expect(f.kong.request).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('retains ordinary HTTP SID behavior without querying scheduled authority', async () => {
    const f = fixture(); await f.http(randomUUID(), async () => {await f.subject(); await f.checkPacket(); await f.boundary.assertIntentSubject(f.envelope, f.actor.user.id, 'write');});
    expect(f.authority.verifyClaim).not.toHaveBeenCalled(); expect(f.db.one.mock.calls.some(([sql]: any[]) => sql.includes('FROM auth_sessions'))).toBe(true);
  });
  it('rejects different owner/CID/WID/transport input inside a genuine namespace', async () => {
    const f = fixture(); await f.run(async () => {
      await expect(f.subject(f.material, {...f.actor, user: {...f.actor.user, id: randomUUID()}})).rejects.toMatchObject({status: 403});
      for (const override of [{clusterId: randomUUID()}, {workspaceId: randomUUID()}, {transportScope: '0'.repeat(64)}, {actor: {...f.actor, workspaceId: randomUUID()}}])
        await expect(f.checkPacket(override)).rejects.toMatchObject({response: {code: 'ENTITY_CHANGE_ACTOR_CONTEXT_REQUIRED'}});
    }); expect(f.portal.assertPreparedChange).not.toHaveBeenCalled();
  });
  it('checks current SQL owner credential epoch, cluster/workspace revision and active workspace', async () => {
    for (const [key, value] of [['ownerActive', false], ['credentialEpoch', '2'], ['clusterRevision', 2], ['workspaceRevision', 2], ['workspaceStatus', 'disabled'], ['transportScope', '2'.repeat(64)]]) {
      const f = fixture(); await f.run(async () => {f.state[key as any] = value; await expect(f.subject()).rejects.toMatchObject({response: {code: 'ENTITY_SCHEDULE_BOUNDARY_SCOPE_CHANGED'}});});
      expect(f.portal.assertPreparedChange).not.toHaveBeenCalled();
    }
  });
  it('checks actual current permissions and rejects forged or differently sealed material/envelope', async () => {
    const f = fixture(); await f.run(async () => {
      f.state.grants = false; await expect(f.subject()).rejects.toMatchObject({response: {code: 'ENTITY_CHANGE_SUBJECT_SCOPE_DENIED'}}); f.state.grants = true;
      // The real AuthorizationService can reject this proof/current SQL
      // mismatch before the boundary's additional permission-version fence.
      f.state.iam = '2'; await expect(f.subject()).rejects.toMatchObject({response: {code: 'PERMISSION_DENIED'}}); f.state.iam = '1';
      await expect(f.subject({...f.material, request: {...f.material.request, body: {username: 'tampered'}}})).rejects.toMatchObject({response: {code: 'ENTITY_SCHEDULE_BOUNDARY_MATERIAL_CHANGED'}});
      for (const change of [{revision: 2}, {intentId: randomUUID()}, {credentialEpoch: '2'}, {packetManifestHmac: '0'.repeat(64)}, {version: 1}, {review: {caller: true}}])
        await expect(f.boundary.assertIntentSubject({...f.envelope, ...change}, f.actor.user.id, 'write')).rejects.toMatchObject({response: {code: 'ENTITY_SCHEDULE_BOUNDARY_MATERIAL_CHANGED'}});
    });
  });
  it('rechecks namespace and current SQL identity after managed Portal preparation', async () => {
    for (const [key, value, code] of [['credentialEpoch', '2', 'PERMISSION_DENIED'], ['iam', '2', 'PERMISSION_DENIED'], ['revokeNamespace', true, 'ORIGINAL_AUTHORITY_EXECUTION_REQUIRED']]) {
      const f = fixture(); f.state.portalHook = () => {f.state[key as any] = value;};
      await f.run(() => expect(f.checkPacket()).rejects.toMatchObject({response: {code}}));
      expect(f.portal.assertPreparedChange).toHaveBeenCalledOnce(); expect(f.kong.request).not.toHaveBeenCalled();
    }
  });
  it('keeps packet bytes and the Portal boundary mandatory, with a final expiry fence', async () => {
    const f = fixture(); await f.run(async () => {
      await expect(f.checkPacket({packet: {...f.packet, body: {username: 'different'}}})).rejects.toMatchObject({response: {code: 'ENTITY_CHANGE_PACKET_INVALID'}});
      f.portal.assertPreparedChange = undefined; await expect(f.checkPacket()).rejects.toMatchObject({response: {code: 'ENTITY_CHANGE_PORTAL_PREPARATION_UNAVAILABLE'}});
    });
    // Use a shorter namespace deadline here, so its half-open expiry is
    // reached before Context's independent 120s execution budget expires.
    const g = fixture(60000); g.state.portalHook = () => vi.setSystemTime(new Date(g.inspection.authorityExpiresAt));
    await g.run(() => expect(g.checkPacket()).rejects.toMatchObject({response: {code: 'ENTITY_SCHEDULE_NAMESPACE_EXPIRED'}}));
  });
  it('validates reviewers from SQL while preserving the original executor frame', async () => {
    const f = fixture(), reviewer = randomUUID(), original = f.db.one.getMockImplementation()!;
    f.db.one.mockImplementation(async (sql: string, args: any[]) => sql.includes('FROM users') && args?.[0] === reviewer ? {id: reviewer, super_admin: true} : original(sql, args));
    const runActor = vi.spyOn(f.context, 'runActor'); await f.run(async () => {const frame = f.context.current(); await f.boundary.assertReviewer(reviewer, f.material); expect(f.context.current()).toBe(frame);});
    expect(runActor).not.toHaveBeenCalled();
  });
});
