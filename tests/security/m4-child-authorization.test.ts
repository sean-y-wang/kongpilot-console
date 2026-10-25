import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { encodeTag } from '../../apps/console-api/src/infrastructure/kong/tags';
import type { EffectiveGrant } from '../../apps/console-api/src/common/authorization.types';
import { workspaceFixture, payWorkspaceId } from '../unit/workspace-test-fixture';

const cid = '7530297b-364c-41d9-aeb5-9e2d119843b4';
const actor = { id: '35a0f472-ef45-4af5-9bf6-a93d2a0fe5e3', username: 'fixture', superAdmin: true };
const consumer = { id: '3f600157-d5bd-4600-a505-381f34321285', tags: ['kos-ws-pay', encodeTag('team:pay')] };
const key = { id: '9d0043e1-576e-4ad2-a397-2b9da0e6ce11', consumer: { id: consumer.id }, tags: [...consumer.tags] };
const jwt = { ...key, id: '78aa2f7e-683c-46bf-ae1f-15577727a3f0' };
const upstream = { id: '9486f880-ecbe-4a04-a765-e1be2d2b75d9', tags: [...consumer.tags] };
const target = { id: '633dca8e-7bd0-48d7-b5f1-1a94b78e0af6', target: 'echo.test:8081', upstream: { id: upstream.id }, tags: [...consumer.tags] };
const typed = (module: string, entity_type: string, entity_id: string, action: 'read' | 'write' = 'read'): EffectiveGrant => ({ module, action, cluster_id: cid, workspace_id: payWorkspaceId, scope_type: 'entity', scope_values: [{ entity_type, entity_id }] });
const tags = (module: string, action: 'read' | 'write' = 'read'): EffectiveGrant => ({ module, action, cluster_id: cid, workspace_id: payWorkspaceId, scope_type: 'tag_group', scope_values: [encodeTag('team:pay')] });
function fixture(grants: EffectiveGrant[]) {
  const contexts = new KongExecutionContextService(), ws = workspaceFixture(cid);
  const state = { grants, active: true, session: true, epoch: 1 };
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('FROM users')) return state.active ? { ...actor, super_admin: false, permissions_epoch: state.epoch, credential_epoch: 1, status: 'active' } : null;
    if (sql.includes('FROM auth_sessions')) return state.session ? { id: 'session' } : null;
    if (sql.includes('FROM iam_epoch')) return { version: state.epoch };
    if (sql.includes('FROM clusters')) return { id: cid };
    return null;
  }), query: vi.fn(async () => state.grants) };
  const raw = new Map([
    [`/consumers/${consumer.id}`, consumer], [`/consumers/${consumer.id}/key-auth/${key.id}`, key], [`/consumers/${consumer.id}/jwt/${jwt.id}`, jwt],
    [`/upstreams/${upstream.id}`, upstream], [`/upstreams/${upstream.id}/targets/${target.id}`, target],
  ]);
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => { if (method !== 'GET') throw new Error('authorization fixture has no write transport'); if (!raw.has(path)) throw new NotFoundException(); return raw.get(path); }) };
  const authz = new AuthorizationService(db, ws.resolver, kong, contexts);
  const run = <T>(fn: () => Promise<T>) => contexts.runHttp({}, async () => {
    contexts.bindHttpActor(actor, 'validated-session'); const close = contexts.captureHttpCloser();
    try { return await contexts.runActor({ actor, clusterId: cid, workspaceId: payWorkspaceId }, fn); } finally { close(); }
  });
  return { authz, run, state, raw, db, kong };
}

describe('M4 independent actual AuthorizationService child contracts', () => {
  it.each(['write', 'delete', 'approve'] as const)('grants necessary Service read and context discovery from exact Route %s, without inventing native read/write authority', async action => {
    const service = { id: consumer.id, host: 'echo.test', tags: [...consumer.tags] };
    const route = { id: jwt.id, service: { id: service.id }, tags: [...consumer.tags] };
    const f = fixture([{ ...typed('routes', 'routes', route.id), action }]);
    f.raw.set(`/services/${service.id}`, service); f.raw.set(`/routes/${route.id}`, route);
    await f.run(async () => {
      await expect(f.authz.assertCluster(actor, cid, 'clusters', 'read')).resolves.toBeUndefined();
      await expect(f.authz.assertCluster(actor, cid, 'workspaces', 'read', payWorkspaceId)).resolves.toBeUndefined();
      await expect(f.authz.assertEntity(actor, cid, 'services', 'read', service, payWorkspaceId)).resolves.toBeUndefined();
      await expect(f.authz.assertEntity(actor, cid, 'routes', 'read', route, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      await expect(f.authz.assertEntity(actor, cid, 'services', 'write', service, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
    });
  });
  it('allows an exact credential-ID grant to use parent identity privately, without granting parent public read', async () => {
    const f = fixture([typed('consumers', 'key-auth', key.id)]);
    await f.run(async () => {
      await expect(f.authz.assertNestedParentScope(actor, cid, 'consumers', consumer, 'key-auth', 'read', payWorkspaceId, key)).resolves.toBeUndefined();
      await expect(f.authz.assertEntity(actor, cid, 'key-auth', 'read', key, payWorkspaceId)).resolves.toBeUndefined();
      await expect(f.authz.assertEntity(actor, cid, 'consumers', 'read', consumer, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      await expect(f.authz.assertEntity(actor, cid, 'jwt', 'read', jwt, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
    });
  });
  it('finds an authorized child through an exact bounded parent path for list checks', async () => {
    const f = fixture([typed('consumers', 'key-auth', key.id)]);
    await f.run(() => f.authz.assertNestedParentScope(actor, cid, 'consumers', consumer, 'key-auth', 'read', payWorkspaceId));
    expect(f.kong.request.mock.calls.some(call => call[2] === `/consumers/${consumer.id}/key-auth/${key.id}`)).toBe(true);
  });
  it('intentionally inherits all credential kinds from a parent Consumer read grant', async () => {
    const f = fixture([typed('consumers', 'consumers', consumer.id)]);
    await f.run(async () => {
      await expect(f.authz.assertEntity(actor, cid, 'key-auth', 'read', key, payWorkspaceId)).resolves.toBeUndefined();
      await expect(f.authz.assertEntity(actor, cid, 'jwt', 'read', jwt, payWorkspaceId)).resolves.toBeUndefined();
    });
  });
  it('requires the credential child business-tag intersection in addition to the authorized parent', async () => {
    const f = fixture([tags('consumers')]);
    await f.run(async () => {
      await expect(f.authz.assertEntity(actor, cid, 'key-auth', 'read', key, payWorkspaceId)).resolves.toBeUndefined();
      await expect(f.authz.assertEntity(actor, cid, 'key-auth', 'read', { ...key, tags: ['kos-ws-pay'] }, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
    });
  });
  it('permits exact existing credential-ID writes but does not grant creation or a sibling ID', async () => {
    const f = fixture([typed('consumers', 'key-auth', key.id, 'write')]);
    await f.run(async () => {
      await expect(f.authz.assertNestedParentScope(actor, cid, 'consumers', consumer, 'key-auth', 'write', payWorkspaceId, key)).resolves.toBeUndefined();
      await expect(f.authz.assertEntity(actor, cid, 'key-auth', 'write', key, payWorkspaceId)).resolves.toBeUndefined();
      await expect(f.authz.assertEntity(actor, cid, 'key-auth', 'write', { consumer: key.consumer, tags: key.tags }, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      await expect(f.authz.assertEntity(actor, cid, 'key-auth', 'write', { ...key, id: jwt.id }, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
    });
  });
  it('does not let a child grant accept a different existing parent ID', async () => {
    const f = fixture([typed('consumers', 'key-auth', key.id)]);
    await f.run(() => expect(f.authz.assertNestedParentScope(actor, cid, 'consumers', { ...consumer, id: jwt.id }, 'key-auth', 'read', payWorkspaceId, key)).rejects.toMatchObject({ status: 403 }));
  });
  it('keeps exact Target-ID scope separate from public Upstream and new immutable history IDs', async () => {
    const f = fixture([typed('upstreams', 'targets', target.id), typed('upstreams', 'targets', target.id, 'write')]);
    await f.run(async () => {
      await expect(f.authz.assertNestedParentScope(actor, cid, 'upstreams', upstream, 'targets', 'read', payWorkspaceId, target)).resolves.toBeUndefined();
      await expect(f.authz.assertEntity(actor, cid, 'targets', 'write', target, payWorkspaceId)).resolves.toBeUndefined();
      await expect(f.authz.assertEntity(actor, cid, 'upstreams', 'read', upstream, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      await expect(f.authz.assertEntity(actor, cid, 'targets', 'write', { ...target, id: key.id }, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      await expect(f.authz.assertEntity(actor, cid, 'targets', 'write', { upstream: target.upstream, target: target.target, tags: target.tags }, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
    });
  });
  it('combines independent typed secrets.read with exact child read, never with only parent identity', async () => {
    const onlySecret = fixture([typed('secrets', 'key-auth', key.id)]);
    await onlySecret.run(() => expect(onlySecret.authz.assertSecretRead(actor, cid, 'key-auth', key, payWorkspaceId)).rejects.toMatchObject({ status: 403 }));
    const f = fixture([typed('secrets', 'key-auth', key.id), typed('consumers', 'key-auth', key.id)]);
    await f.run(async () => {
      await expect(f.authz.assertSecretRead(actor, cid, 'key-auth', key, payWorkspaceId)).resolves.toBeUndefined();
      await expect(f.authz.assertSecretRead(actor, cid, 'jwt', jwt, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      await expect(f.authz.assertSecretRead(actor, cid, 'consumers', consumer, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
    });
  });
  it('does not honor cached actor.superAdmin after a grant is revoked', async () => {
    const f = fixture([typed('consumers', 'key-auth', key.id)]);
    await f.run(async () => {
      await expect(f.authz.assertEntity(actor, cid, 'key-auth', 'read', key, payWorkspaceId)).resolves.toBeUndefined();
      f.state.grants = []; f.state.epoch++;
      await expect(f.authz.assertEntity(actor, cid, 'key-auth', 'read', key, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
      expect(await f.authz.isPlatformAdmin(actor)).toBe(false);
    });
  });
  it.each(['active', 'session'] as const)('fails closed on a revoked %s even with a cached privileged actor', async field => {
    const f = fixture([typed('consumers', 'key-auth', key.id)]); f.state[field] = false;
    await f.run(() => expect(f.authz.assertEntity(actor, cid, 'key-auth', 'read', key, payWorkspaceId)).rejects.toMatchObject({ status: 401 }));
  });
});
