import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { immutableJson } from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { EntityScheduledNamespaceService } from '../../apps/console-api/src/modules/workflows/entity-scheduled-namespace.service';
import { PortalAuthBoundaryService } from '../../apps/console-api/src/modules/portal-boundary/portal-auth-boundary.service';

/** Real Namespace issuance/Context ancestry with original opaque authority
 * references from a controlled domain adapter. Portal history and bounded
 * Kong reads are fixtures, never runtime SQL/native authority evidence. No
 * Namespace/Kernel WeakMap is manually seeded and no native call exists. */
function fixture() {
  const secrets = new SecretService(), context = new KongExecutionContextService(), now = Date.now();
  const cid = randomUUID(), wid = randomUUID(), owner = randomUUID(), nativeId = randomUUID(), transportScope = 'a'.repeat(64);
  const authorityHandle = Object.freeze({}), originals = new WeakSet<object>([authorityHandle]);
  const expiresAt = new Date(now + 240000).toISOString(), principal = { id: owner, username: 'controlled-portal-owner', superAdmin: false };
  const plan: any = { workflowId: randomUUID(), planRevision: 1, kind: 'native-change', clusterId: cid, workspaceId: wid,
    requester: { type: 'console', id: owner }, executionMode: 'approval', approvalRequired: true, expiresAt, steps: [] };
  const envelope: any = { version: 2, intentId: randomUUID(), revision: 1, requesterId: owner, clusterId: cid, workspaceId: wid,
    credentialEpoch: '1', executionMode: 'approval', expiresAt, prepared: { scope: { transportScope, clusterRevision: 1, workspaceRevision: 1 } },
    scheduling: { specHmac: 'b'.repeat(64), delegationHmac: 'c'.repeat(64), delegation: { id: randomUUID(), ownerId: owner,
      executorId: owner, ownerCredentialEpoch: '1', executorCredentialEpoch: '1' } } };
  const inspection: any = { version: 1, envelope, plan, principal, permissionVersion: `${owner}:1:1`, leaseUntil: expiresAt,
    authorityExpiresAt: expiresAt, draft: { scheduleId: randomUUID(), binding: { clusterId: cid, workspaceId: wid,
      materialHmac: secrets.fingerprint(envelope), changeDigest: 'd'.repeat(64), packetManifestHmac: 'e'.repeat(64) },
      spec: { windowStart: new Date(now - 1000).toISOString(), windowEnd: expiresAt } },
    approvalSet: { format: 2, setId: randomUUID(), setHmac: 'f'.repeat(64), policyHash: '1'.repeat(64),
      reviewers: [{ approvalId: randomUUID(), userId: randomUUID(), level: 1, candidateVersion: 1 }] } };
  inspection.claim = { id: randomUUID(), scheduleId: inspection.draft.scheduleId, scheduleVersion: 1, occurrenceId: randomUUID(), generation: 1,
    workerOwnerHmac: '2'.repeat(64), issuedAt: new Date(now).toISOString(), authorityExpiresAt: expiresAt, initialLeaseUntil: expiresAt,
    workflowId: plan.workflowId, workflowPlanRevision: 1, workflowPlanHash: secrets.fingerprint(plan) };
  const before = { id: nativeId, name: 'controlled-service', protocol: 'http', retries: 5, tags: [] };
  const input: any = { clusterId: cid, workspaceId: wid, transportScope, nativeId, method: 'PATCH', canonicalPath: `/services/${nativeId}`,
    mutationAction: 'update', before, body: { retries: 4 } };
  const state: any = { live: false, ownerActive: true, publications: [], grants: [], credentials: [], changedAtQuery: null,
    services: [before], routes: [], plugins: [], consumers: {}, acls: {}, callbackReadFrames: [], namespaceHandle: null };
  const authority: any = { inspect: vi.fn(async (handle: object) => {
    if (!originals.has(handle)) throw new ForbiddenException({ code: 'CONTROLLED_ORIGINAL_AUTHORITY_REQUIRED' }); return immutableJson(inspection);
  }), verifyClaim: vi.fn(async (handle: object) => {
    if (!originals.has(handle) || !state.live) throw new ForbiddenException({ code: 'CONTROLLED_ORIGINAL_AUTHORITY_REQUIRED' });
    if (!state.ownerActive) throw new ForbiddenException({ code: 'CONTROLLED_OWNER_REVOKED' }); return immutableJson(inspection);
  }) };
  const redis: any = { assertLeaseOwnership: vi.fn(async () => { if (!state.live) throw new ForbiddenException({ code: 'CONTROLLED_LEASE_REQUIRED' }); }),
    assertLeaseActive: vi.fn(() => { if (!state.live) throw new ForbiddenException({ code: 'CONTROLLED_LEASE_REQUIRED' }); }) };
  const namespace = new EntityScheduledNamespaceService(authority, secrets, redis);
  context.installEntityScheduledNamespacePolicy(namespace);
  namespace.installContextRunner({ assertNoFrame: () => { if (context.peek()) throw new ForbiddenException({ code: 'CONTROLLED_EXISTING_FRAME' }); },
    run: (handle, fn) => { state.namespaceHandle = handle; return context.runEntityScheduledNamespace(handle, fn); } });
  const db: any = { query: vi.fn(async (sql: string) => {
    state.changedAtQuery?.();
    if (sql.includes('FROM portal_publications')) return structuredClone(state.publications);
    if (sql.includes('FROM portal_application_grants')) return structuredClone(state.grants);
    if (sql.includes('FROM portal_credentials')) return structuredClone(state.credentials);
    throw new Error('Unexpected controlled Portal query');
  }) };
  const read = () => { const frame = context.current(); state.callbackReadFrames.push({ kind: frame.kind, actorId: frame.actor?.id,
    sessionId: frame.sessionId ?? null, namespace: context.hasEntityScheduledNamespace() }); };
  const kong: any = { list: vi.fn(async (_cid: string, path: string) => {
    read(); const rows = path === '/services' ? state.services : path === '/routes' ? state.routes : path === '/plugins' ? state.plugins : state.acls[path];
    if (!rows) throw new Error('Unexpected controlled bounded collection read'); return { items: structuredClone(rows), nextCursor: null };
  }), request: vi.fn(async (_cid: string, method: string, path: string) => {
    expect(method).toBe('GET'); read(); const entity = state.consumers[path]; if (!entity) throw new Error('Unexpected controlled point read'); return structuredClone(entity);
  }), schema: vi.fn(), pluginSchema: vi.fn() };
  const workspaces: any = { listScope: vi.fn(async () => ({ workspaceId: wid })), matches: vi.fn(() => true) };
  const service = new PortalAuthBoundaryService(db, secrets, kong, context, workspaces);
  const scheduled = async <T>(fn: () => Promise<T>) => { state.live = true; try { return await namespace.runOriginalClaim(authorityHandle, fn); } finally { state.live = false; } };
  const http = <T>(withSid: boolean, fn: () => Promise<T>) => context.runHttp({}, async () => {
    context.bindHttpActor(principal, withSid ? randomUUID() : undefined);
    return context.runActor({ actor: principal, clusterId: cid, workspaceId: wid }, fn);
  });
  const publication = () => {
    const id = randomUUID(), serviceId = randomUUID();
    state.publications.push({ id, cluster_id: cid, workspace_id: wid, service_id: serviceId, acl_group: `kos-portal-api-${id}`, state: 'pending', published_revision: null });
    state.services.push({ id: serviceId, protocol: 'http', name: 'controlled-pending-portal', tags: [] }); return { id, serviceId };
  };
  return { service, context, namespace, authority, authorityHandle, state, db, kong, workspaces, principal, input, inspection, cid, wid, scheduled, http, publication };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T19:00:00.000Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('M11 genuine scheduled Portal preparation boundary (source-only)', () => {
  it('retains ordinary HTTP SID requirements and accepts the existing authenticated HTTP path', async () => {
    const f = fixture(); await f.http(false, () => expect(f.service.assertPreparedChange(f.input)).rejects.toMatchObject({ response: { code: 'PORTAL_PREPARATION_CONTEXT_REQUIRED' } }));
    expect(f.db.query).not.toHaveBeenCalled();
    await f.http(true, () => expect(f.service.assertPreparedChange(f.input)).resolves.toBeUndefined());
    expect(f.db.query).toHaveBeenCalledTimes(3); expect(f.authority.verifyClaim).not.toHaveBeenCalled(); expect(f.kong.list).not.toHaveBeenCalled();
  });
  it('accepts a genuine original scheduled namespace with NULL SID and checks actual Portal ownership history', async () => {
    const f = fixture(); await f.scheduled(async () => {
      expect(f.context.current().sessionId).toBeUndefined(); expect(f.context.hasEntityScheduledNamespace()).toBe(true);
      await expect(f.service.assertPreparedChange(f.input)).resolves.toBeUndefined();
    });
    expect(f.db.query).toHaveBeenCalledTimes(3); expect(f.authority.verifyClaim.mock.calls.some(call => call[1] === 'packet')).toBe(true);
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.kong.list).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });
  it('rejects copied namespace/proof identity instead of adopting a NULL-SID actor', async () => {
    const f = fixture(); let proof: any, handle: object;
    await f.scheduled(async () => { proof = await f.context.verifyEntityScheduledNamespace('packet'); handle = f.context.requireEntityScheduledNamespaceHandle(); });
    for (const copy of [{ ...handle! }, { ...proof }, { origin: 'scheduled-entity', sessionId: null, actor: f.principal }])
      await expect(f.context.runEntityScheduledNamespace(copy, () => f.service.assertPreparedChange(f.input))).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_ORIGINAL_HANDLE_REQUIRED' } });
    expect(f.db.query).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });
  it.each(['clusterId', 'workspaceId', 'transportScope'])('rejects a mismatched %s before any Portal history query', async field => {
    const f = fixture(), input = { ...f.input, [field]: field === 'transportScope' ? '3'.repeat(64) : randomUUID() };
    await f.scheduled(() => expect(f.service.assertPreparedChange(input)).rejects.toMatchObject({ response: { code: 'PORTAL_PREPARATION_CONTEXT_REQUIRED' } }));
    expect(f.db.query).not.toHaveBeenCalled(); expect(f.kong.list).not.toHaveBeenCalled();
  });
  it('revalidates current owner on the empty-history early return and retains no native capability', async () => {
    const f = fixture(); f.state.changedAtQuery = () => { f.state.ownerActive = false; };
    await expect(f.scheduled(() => f.service.assertPreparedChange(f.input))).rejects.toMatchObject({ response: { code: 'CONTROLLED_OWNER_REVOKED' } });
    expect(f.db.query).toHaveBeenCalledTimes(3); expect(f.kong.request).not.toHaveBeenCalled(); expect(f.kong.list).not.toHaveBeenCalled();
    expect(f.context.peek()).toBeNull();
  });
  it('rejects an authorization/material change across graph awaits using the same sealed proof identity', async () => {
    const f = fixture(); let mutated = false; f.state.changedAtQuery = () => { if (!mutated) { mutated = true; f.inspection.permissionVersion += ':changed'; } };
    await expect(f.scheduled(() => f.service.assertPreparedChange(f.input))).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_FACTS_CHANGED' } });
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });
  it('retains historical managed Consumer protection under a genuine scheduled namespace', async () => {
    const f = fixture(), consumerId = randomUUID(); f.state.grants = [{ id: randomUUID(), consumer_id: consumerId, state: 'revoked', reservation_released_at: new Date().toISOString() }];
    const input = { ...f.input, nativeId: consumerId, canonicalPath: `/consumers/${consumerId}`, before: { id: consumerId }, body: { username: 'unmanaged-copy' } };
    await f.scheduled(() => expect(f.service.assertPreparedChange(input)).rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } }));
    expect(f.db.query).toHaveBeenCalledTimes(3); expect(f.kong.list).not.toHaveBeenCalled();
  });
  it('performs the full bounded service/route/plugin capture and prospective authentication check when Portal history exists', async () => {
    const f = fixture(); f.publication();
    await f.scheduled(() => expect(f.service.assertPreparedChange(f.input)).resolves.toBeUndefined());
    expect(f.kong.list.mock.calls.map(call => call[1])).toEqual(['/services', '/routes', '/plugins']);
    expect(f.db.query).toHaveBeenCalledTimes(6);
    expect(f.state.callbackReadFrames).toHaveLength(3);
    expect(f.state.callbackReadFrames.every(frame => frame.kind === 'internal-read' && frame.namespace && frame.actorId === f.principal.id && frame.sessionId === null)).toBe(true);
    expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('still rejects an unsafe authentication graph and cannot bypass managed checks with scheduled origin', async () => {
    const f = fixture(); f.publication();
    f.state.plugins = [{ id: randomUUID(), name: 'key-auth', enabled: true, protocols: ['http', 'https'], config: { key_names: ['apikey'] }, service: null, route: null, consumer: null }];
    await f.scheduled(() => expect(f.service.assertPreparedChange(f.input)).rejects.toMatchObject({ response: { code: 'PORTAL_UNMANAGED_AUTH_BOUNDARY' } }));
    expect(f.kong.list).toHaveBeenCalledTimes(3); expect(f.context.peek()).toBeNull();
  });
  it('keeps the immutable published revision proof checks for scheduled preparation', async () => {
    const f = fixture(); f.publication(); f.state.publications[0].published_revision = 1;
    await f.scheduled(() => expect(f.service.assertPreparedChange(f.input)).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_PROOF_INVALID' } }));
    expect(f.kong.list).toHaveBeenCalledTimes(3); expect(f.context.peek()).toBeNull();
  });
});
