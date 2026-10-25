import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { EntityService } from '../../apps/console-api/src/modules/entities/entities.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import type { EffectiveGrant } from '../../apps/console-api/src/common/authorization.types';
import { workspaceFixture, payWorkspaceId } from './workspace-test-fixture';

const cid = 'a66ac958-2ca3-4ca7-bc47-dc6e7ed20320';
const uid = '1844a41f-1e2a-4f0b-905e-df4a72c27b57';
const sessionId = '8753c080-40a1-477e-b49a-3f34ac74e220';
const sid = '171d1bd2-e21f-479b-a5a0-45aa85bf619b';
const otherSid = 'f5e02d55-1c4e-4526-bc4e-661f72497b85';
const rid = '0d93fdb4-0a58-4879-880a-00ffcc34077c';
const relatedId = '6a28f6f6-0e73-4c82-aac0-5e9fb2c1e4e1';
const routePluginId = 'ab9605d9-041e-4332-a4c3-0072465b0e6e';
const comboPluginId = '2bafaf5e-ab5a-4b1e-bb1a-f5b535cebd3e';
const actor = { user: { id: uid, username: 'scoped', superAdmin: false }, workspaceId: payWorkspaceId };
const tags = ['kos-ws-pay'];
const grant = (module: string, action: any, type: string, id: string): EffectiveGrant => ({ module, action, scope_type: 'entity', cluster_id: cid, workspace_id: payWorkspaceId, scope_values: [{ entity_type: type, entity_id: id }] });

// Actual AuthorizationService, EntityService, resolver and ALS capabilities;
// repository grants and native transport are controlled integration fixtures.
function fixture(initial: EffectiveGrant[]) {
  let grants = initial, epoch = 1, session = true;
  const execution = new KongExecutionContextService(), workspace = workspaceFixture(cid);
  const row = { id: uid, username: 'scoped', super_admin: false, status: 'active', permissions_epoch: 1, credential_epoch: 1, revision: 1 };
  const db: any = { one: vi.fn(async (sql: string, params: any[]) => sql.includes('FROM users') ? row : sql.includes('FROM auth_sessions') ? session ? { id: sessionId } : null : sql.includes('FROM iam_epoch') ? { version: epoch } : sql.includes('FROM clusters') && params[0] === cid ? { id: cid } : null), query: vi.fn(async (sql: string) => sql.includes('iam_effective_grants') ? structuredClone(grants) : []) };
  const remote = new Map<string, any>([
    [`/services/${sid}`, { id: sid, name: 'authorized-service', host: 'business.test', tags }],
    [`/services/${otherSid}`, { id: otherSid, name: 'unrelated-service', host: 'unrelated.test', tags }],
    [`/routes/${rid}`, { id: rid, name: 'private-route', headers: { authorization: ['private-route-config'] }, service: { id: sid }, tags }],
    [`/consumers/${relatedId}`, { id: relatedId, username: 'consumer', tags }],
    [`/snis/${relatedId}`, { id: relatedId, name: 'sni.test', certificate: { id: sid }, tags }],
    [`/certificates/${sid}`, { id: sid, cert: 'invalid-fixture-certificate', key: 'private-fixture-key', tags }],
    [`/plugins/${relatedId}`, { id: relatedId, name: 'cors', config: {}, service: { id: sid }, tags }],
    [`/plugins/${routePluginId}`, { id: routePluginId, name: 'cors', config: {}, route: { id: rid }, tags }],
    [`/plugins/${comboPluginId}`, { id: comboPluginId, name: 'cors', config: {}, service: { id: sid }, consumer: { id: relatedId }, tags }],
    [`/services/${otherSid}/routes`, { data: [], next: null }],
  ]);
  const reads: Array<{ path: string; purpose?: string; kind: string }> = [];
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string, body?: any) => {
    const frame = execution.current(); reads.push({ path, kind: frame.kind, purpose: frame.purpose });
    if (method === 'PATCH' && remote.has(path)) { const value = { ...remote.get(path), ...body }; remote.set(path, value); return structuredClone(value); }
    if (method === 'POST' && path === '/plugins') return { id: routePluginId, ...structuredClone(body) };
    if (!remote.has(path)) throw new NotFoundException(); return structuredClone(remote.get(path));
  }), list: vi.fn(async (_cid: string, _path: string, query: any) => ({ items: [], nextCursor: null, size: query.size })) };
  const authz = new AuthorizationService(db, workspace.resolver, kong, execution);
  const mutations: any = { execute: vi.fn(async (context: any, fn: () => Promise<any>) => execution.runOperation({ actor: context.actor, clusterId: cid, workspaceId: payWorkspaceId, entityType: context.entityType, entityId: context.entityId, operationId: 'controlled-domain-ledger-fixture', action: context.action }, fn)) };
  const entities = new EntityService(kong, authz, mutations, {} as any, {} as any, new SecretService(), { append: vi.fn() } as any, { upsert: vi.fn() } as any, workspace.resolver, execution);
  const run = <T>(fn: () => Promise<T>) => execution.runHttp({}, async () => {
    execution.bindHttpActor(actor.user, sessionId); const close = execution.captureHttpCloser();
    try { return await fn(); } finally { close(); }
  });
  return { run, entities, authz, kong, remote, reads, mutations, revokeGrants: () => { grants = []; epoch++; }, revokeSession: () => { session = false; }, bumpEpoch: () => { epoch++; } };
}
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('actual inherited detail permissions and optional relation projection', () => {
  it('lets a Route-write-only user read only its real Service without exposing route configuration or inventing Route.read', async () => {
    const f = fixture([grant('routes', 'write', 'routes', rid)]);
    const result = await f.run(() => f.entities.get(cid, 'services', sid, {}, actor));
    expect(result.entity).toMatchObject({ id: sid, host: 'business.test' });
    expect(result.relations.routes).toEqual({ availability: 'forbidden', items: [], total: null });
    expect(result.relations.plugins).toEqual({ availability: 'forbidden', items: [], total: null });
    expect(JSON.stringify(result)).not.toContain('private-route-config');
    expect(f.kong.list).not.toHaveBeenCalled();
    expect(f.reads.filter(read => read.path === `/routes/${rid}`).every(read => read.kind === 'internal-read' && read.purpose === 'authorization')).toBe(true);
    await expect(f.run(() => f.entities.get(cid, 'services', otherSid, {}, actor))).rejects.toMatchObject({ status: 403 });
    await expect(f.run(() => f.entities.relation(cid, 'services', sid, 'routes', {}, actor))).rejects.toMatchObject({ status: 403 });
    await expect(f.run(() => f.entities.get(cid, 'routes', rid, {}, actor))).rejects.toMatchObject({ status: 403 });
  });
  it('returns the authorized Service for a pure Service-read grant even without Route.read', async () => {
    const f = fixture([grant('services', 'read', 'services', sid)]);
    const result = await f.run(() => f.entities.get(cid, 'services', sid, {}, actor));
    expect(result.entity.id).toBe(sid); expect(result.relations.routes.availability).toBe('forbidden');
    await expect(f.run(() => f.entities.relation(cid, 'services', sid, 'routes', {}, actor))).rejects.toMatchObject({ status: 403 });
  });
  it.each([
    { type: 'routes', id: rid, relation: 'plugins' },
    { type: 'consumers', id: relatedId, relation: 'plugins' },
    { type: 'certificates', id: sid, relation: 'snis' },
  ])('independently projects unavailable automatic collections for $type', async ({ type, id, relation }) => {
    const f = fixture([grant(type, 'read', type, id)]);
    f.kong.list.mockRejectedValue(new ForbiddenException());
    const result = await f.run(() => f.entities.get(cid, type, id, {}, actor));
    expect(result.entity.id).toBe(id); expect(result.relations[relation]).toEqual({ availability: 'forbidden', items: [], total: null });
  });
  it('omits private parent configuration and navigation identifiers on a singular forbidden relation', async () => {
    const f = fixture([grant('snis', 'read', 'snis', relatedId)]);
    const result = await f.run(() => f.entities.get(cid, 'snis', relatedId, {}, actor));
    expect(result.relations.certificate).toEqual({ availability: 'forbidden', reason: 'permission_denied' });
    expect(result.relations.certificate).not.toHaveProperty('id'); expect(JSON.stringify(result)).not.toContain('private-fixture-key');
  });
  it('projects a genuinely missing parent without swallowing a provider outage', async () => {
    const f = fixture([grant('snis', 'read', 'snis', relatedId), grant('certificates', 'read', 'certificates', sid)]);
    f.remote.delete(`/certificates/${sid}`);
    const result = await f.run(() => f.entities.get(cid, 'snis', relatedId, {}, actor));
    expect(result.relations.certificate).toEqual({ availability: 'missing', reason: 'not_found' });
    f.kong.request.mockImplementation(async (_cid: string, _method: string, path: string) => {
      if (path.startsWith('/certificates/')) throw new ServiceUnavailableException(); return structuredClone(f.remote.get(path));
    });
    await expect(f.run(() => f.entities.get(cid, 'snis', relatedId, {}, actor))).rejects.toMatchObject({ status: 503 });
  });
  it.each(['root-grants', 'session', 'unrelated-epoch'])('cannot hide %s revocation while an optional relationship is pending', async change => {
    const f = fixture([grant('services', 'read', 'services', sid)]);
    let entered!: () => void, release!: () => void;
    const began = new Promise<void>(resolve => { entered = resolve; });
    const blocked = new Promise<void>(resolve => { release = resolve; });
    f.kong.list.mockImplementation(async () => { entered(); await blocked; throw new ForbiddenException(); });
    const result = f.run(() => f.entities.get(cid, 'services', sid, {}, actor));
    await began;
    if (change === 'session') f.revokeSession(); else if (change === 'root-grants') f.revokeGrants(); else f.bumpEpoch();
    release();
    await expect(result).rejects.toMatchObject(change === 'session' ? { status: 401 } : { status: 403, response: { code: 'PERMISSIONS_CHANGED' } });
  });
  it('permits inherited Route and singly bound Plugin edits for Service-write-only without public parent read', async () => {
    const f = fixture([grant('services', 'write', 'services', sid)]);
    await expect(f.run(() => f.entities.update(cid, 'routes', rid, { name: 'changed-route' }, {}, actor))).resolves.toMatchObject({ entity: { id: rid, name: 'changed-route' } });
    for (const id of [relatedId, routePluginId]) {
      const result = await f.run(() => f.entities.update(cid, 'plugins', id, { enabled: false }, {}, actor));
      expect(result.entity).toMatchObject({ id, enabled: false }); expect(JSON.stringify(result)).not.toContain('private-route-config');
    }
    await expect(f.run(() => f.entities.get(cid, 'services', sid, {}, actor))).rejects.toMatchObject({ status: 403 });
    await expect(f.run(() => f.entities.get(cid, 'routes', rid, {}, actor))).rejects.toMatchObject({ status: 403 });
    expect(f.reads.filter(read => read.path === `/services/${sid}`).every(read => read.kind === 'internal-read')).toBe(true);
    expect(f.mutations.execute).toHaveBeenCalledTimes(3);
  });
  it('permits bound Plugin creation using a private parent write identity, never parent configuration', async () => {
    const f = fixture([grant('services', 'write', 'services', sid)]);
    const result = await f.run(() => f.entities.create(cid, 'plugins', { name: 'cors', service: { id: sid }, config: { origins: ['*'] } }, {}, actor));
    expect(result.entity.service.id).toBe(sid); expect(JSON.stringify(result)).not.toContain('business.test');
    expect(f.mutations.execute).toHaveBeenCalledTimes(1);
    await expect(f.run(() => f.entities.get(cid, 'services', sid, {}, actor))).rejects.toMatchObject({ status: 403 });
  });
  it('denies a combined Plugin binding without every parent grant before entering the ledger or sending a native write', async () => {
    const f = fixture([grant('services', 'write', 'services', sid)]);
    await expect(f.run(() => f.entities.update(cid, 'plugins', comboPluginId, { enabled: false }, {}, actor))).rejects.toMatchObject({ status: 403 });
    await expect(f.run(() => f.entities.create(cid, 'plugins', { name: 'cors', service: { id: sid }, consumer: { id: relatedId }, config: {} }, {}, actor))).rejects.toMatchObject({ status: 403 });
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.kong.request.mock.calls.some(call => ['POST', 'PATCH'].includes(call[1]))).toBe(false);
  });
  it('does not substitute certificate write for its independent reference read requirement', async () => {
    const f = fixture([grant('snis', 'write', 'snis', relatedId), grant('certificates', 'write', 'certificates', sid)]);
    await expect(f.run(() => f.entities.update(cid, 'snis', relatedId, { name: 'changed-sni.test' }, {}, actor))).rejects.toMatchObject({ status: 403 });
    expect(f.mutations.execute).not.toHaveBeenCalled();
  });
});
