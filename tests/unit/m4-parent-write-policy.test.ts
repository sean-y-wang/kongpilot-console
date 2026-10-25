import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { encodeTag } from '../../apps/console-api/src/infrastructure/kong/tags';
import { payWorkspaceId, workspaceFixture } from './workspace-test-fixture';
import type { EffectiveGrant } from '../../apps/console-api/src/common/authorization.types';

const cid = '507c95fa-a741-4698-a4dc-80f1f3d58f69';
const uid = 'b512e051-e823-4c81-b3ad-f81e456fef28';
const sid = '27814a38-1f72-4c2b-b7c5-f15a6d17b6c2';
const serviceId = '071c3768-a727-49a5-9751-c82ed1098d80';
const otherServiceId = '5815a1bb-5516-45b5-85bb-e8b3f0629d70';
const routeId = '4b85fe9b-f0c2-4b4f-8f81-2cb93a5c72c1';
const pluginId = 'aa0d674c-c2cb-4962-ade7-6705a708a993';
const consumerId = 'a2b8a85f-2ce9-4a55-9aad-c0992f188f15';
const opId = 'a4c2a47b-16c7-4b80-b945-5c008d431892';
const actor = { id: uid, username: 'parent-write-only', superAdmin: false };
const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct' };
const businessTag = encodeTag('team:pay');

// Actual current-grant AuthorizationService, private execution context and
// NativeKongPolicy. Only PostgreSQL rows and Kong raw GETs are fixture data;
// these checks characterize policy behavior, not live HTTP/DB execution.
function fixture(type: 'routes' | 'plugins', binding: 'service' | 'route' = 'service') {
  const execution = new KongExecutionContextService(), secrets = new SecretService();
  const tags = ['kos-ws-pay', businessTag];
  const service = { id: serviceId, name: 'private-service', host: 'private-config.example', tags };
  const route = { id: routeId, name: 'child-route', service: { id: serviceId }, tags };
  const plugin = { id: pluginId, name: 'cors', config: { origins: ['https://app.example'] },
    service: binding === 'service' ? { id: serviceId } : null,
    route: binding === 'route' ? { id: routeId } : null, consumer: null as any, tags };
  const entity: any = type === 'routes' ? route : plugin;
  const patch: any = type === 'routes' ? { name: 'updated-child-route' } : { config: { origins: ['https://other.example'] } };
  const grants: EffectiveGrant[] = [{ module: 'services', action: 'write', scope_type: 'entity',
    cluster_id: cid, workspace_id: payWorkspaceId,
    scope_values: [{ entity_type: 'services', entity_id: serviceId }] }];
  const operation: any = { id: opId, actor_id: uid, cluster_id: cid, workspace_id: payWorkspaceId,
    entity_type: type, entity_id: entity.id, action: 'update', state: 'running', remote_started: true,
    payload_secret: secrets.encrypt(patch, `mutation:${opId}:payload`),
    before_secret: secrets.encrypt(entity, `mutation:${opId}:before`) };
  const raw = new Map<string, any>([[`/services/${serviceId}`, service], [`/routes/${routeId}`, route], [`/plugins/${pluginId}`, plugin],
    [`/services/${otherServiceId}`, { ...service, id: otherServiceId, name: 'other-private-service' }],
    [`/consumers/${consumerId}`, { id: consumerId, username: 'private-consumer', tags }]]);
  const db: any = {
    one: vi.fn(async (sql: string, params: any[]) => {
      if (sql.includes('FROM mutation_operations')) return params[0] === opId ? operation : null;
      if (sql.includes('FROM users')) return { id: uid, username: actor.username, super_admin: false, status: 'active', permissions_epoch: 1, credential_epoch: 1 };
      if (sql.includes('FROM auth_sessions')) return { id: sid };
      if (sql.includes('FROM iam_epoch')) return { version: 1 };
      if (sql.includes('FROM clusters')) return params[0] === cid ? cluster : null;
      return null;
    }),
    query: vi.fn(async (sql: string) => sql.includes('iam_effective_grants') ? structuredClone(grants) : []),
    exec: vi.fn(async () => 1),
  };
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => {
    expect(method).toBe('GET');
    expect(execution.current().kind).toBe('internal-read');
    expect(execution.current().purpose).toBe('authorization');
    const found = raw.get(path); if (!found) throw new NotFoundException(); return structuredClone(found);
  }) };
  const workspace = workspaceFixture(cid);
  const authz = new AuthorizationService(db, workspace.resolver, kong, execution);
  const native = new NativeKongPolicyService(db, secrets, kong, execution, authz, workspace.resolver);
  native.install();
  const run = <T>(fn: () => Promise<T>, withOperation = false): Promise<T> => execution.runHttp({}, async () => {
    execution.bindHttpActor(actor, sid); const close = execution.captureHttpCloser();
    try { return await execution.runActor({ actor, clusterId: cid, workspaceId: payWorkspaceId, module: type, action: 'write' },
      () => withOperation ? execution.runOperation({ actor, clusterId: cid, workspaceId: payWorkspaceId,
        operationId: opId, entityType: type, entityId: entity.id, action: 'update' }, fn) : fn()); }
    finally { close(); }
  });
  const persistBefore = () => { operation.before_secret = secrets.encrypt(entity, `mutation:${opId}:before`); };
  const persistPatch = () => { operation.payload_secret = secrets.encrypt(patch, `mutation:${opId}:payload`); };
  const replaceGrants = (next: EffectiveGrant[]) => { grants.splice(0, grants.length, ...next); };
  return { execution, authz, kong, service, entity, patch, run, persistBefore, persistPatch, replaceGrants };
}

beforeEach(() => { vi.stubEnv('APP_SECRET', 'parent-write-fixture-private-key-minimum-32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '91'.repeat(32)); });
afterEach(() => vi.unstubAllEnvs());

describe('Service write-only inheritance crosses the real native policy boundary', () => {
  it.each([['routes', 'service'], ['plugins', 'service'], ['plugins', 'route']] as const)
    ('permits an existing %s write through %s without granting public parent configuration read', async (type, binding) => {
      const f = fixture(type, binding);
      await f.run(async () => {
        await f.authz.assertEntity(actor, cid, type, 'write', f.entity, payWorkspaceId);
        await f.authz.assertEntity(actor, cid, type, 'write', { ...f.entity, ...f.patch }, payWorkspaceId);
        await expect(f.authz.assertEntity(actor, cid, 'services', 'read', f.service, payWorkspaceId)).rejects.toMatchObject({ status: 403 });
        await expect(f.execution.authorizeRequest(cluster, 'GET', `/services/${serviceId}`, undefined, {})).rejects.toMatchObject({ status: 403 });
      });
      const result = await f.run(async () => {
        const ticket = await f.execution.authorizeRequest(cluster, 'PATCH', `/${type}/${f.entity.id}`, f.patch, {});
        expect(Object.keys(ticket)).toEqual([]);
        return f.execution.authorizeResponse(ticket, { ...f.entity, ...f.patch });
      }, true);
      expect(result).toEqual({ ...f.entity, ...f.patch });
      expect(JSON.stringify(result)).not.toContain(f.service.host);
      expect(f.kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
    });

  it('still denies an additional Consumer binding without that Consumer write grant', async () => {
    const f = fixture('plugins'); f.entity.consumer = { id: consumerId }; f.persistBefore();
    await expect(f.run(() => f.authz.assertEntity(actor, cid, 'plugins', 'write', f.entity, payWorkspaceId))).rejects.toMatchObject({ status: 403 });
    await expect(f.run(() => f.execution.authorizeRequest(cluster, 'PATCH', `/plugins/${pluginId}`, f.patch, {}), true)).rejects.toMatchObject({ status: 403 });
  });

  it.each(['routes', 'plugins'] as const)('retains %s own tag intersection for inherited tag-group writes', async type => {
    const f = fixture(type);
    f.replaceGrants([{ module: 'services', action: 'write', scope_type: 'tag_group', cluster_id: cid,
      workspace_id: payWorkspaceId, scope_values: [businessTag] }]);
    await f.run(() => f.execution.authorizeRequest(cluster, 'PATCH', `/${type}/${f.entity.id}`, f.patch, {}), true);
    f.entity.tags = ['kos-ws-pay', encodeTag('team:other')]; f.persistBefore();
    await expect(f.run(() => f.execution.authorizeRequest(cluster, 'PATCH', `/${type}/${f.entity.id}`, f.patch, {}), true))
      .rejects.toMatchObject({ response: { code: 'PERMISSION_DENIED' } });
  });

  it('does not let an entity-only Route writer reparent to an unauthorized Service', async () => {
    const f = fixture('routes');
    f.replaceGrants([{ module: 'routes', action: 'write', scope_type: 'entity', cluster_id: cid,
      workspace_id: payWorkspaceId, scope_values: [{ entity_type: 'routes', entity_id: routeId }] }]);
    f.patch.service = { id: otherServiceId }; f.persistPatch();
    // Route identity still matches its direct grant, but the newly selected
    // parent has neither necessary current Route-derived read nor write.
    await f.run(() => f.authz.assertEntity(actor, cid, 'routes', 'write', { ...f.entity, ...f.patch }, payWorkspaceId));
    await expect(f.run(() => f.execution.authorizeRequest(cluster, 'PATCH', `/routes/${routeId}`, f.patch, {}), true))
      .rejects.toMatchObject({ response: { code: 'PERMISSION_DENIED' } });
  });
});
