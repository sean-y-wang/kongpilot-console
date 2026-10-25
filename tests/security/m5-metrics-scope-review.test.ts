import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { MetricsScopeService } from '../../apps/console-api/src/modules/vitals/metrics-scope.service';
import { opsWorkspaceId, payWorkspaceId, workspaceFixture } from '../unit/workspace-test-fixture';

const cid = 'a0c05a03-0e83-4e6f-9a5f-c4136287c4b4', uid = '023bf70d-0d08-49c4-96bc-57a8e232e353';
const serviceId = 'bb0cde73-87d5-47ef-8a58-b4bbf843af94', otherId = '341401f9-bd2f-4364-8434-f94e65e0c2e9';
const actor = { user: { id: uid, username: 'monitor-only', superAdmin: false } };
const resource = { id: serviceId, name: 'visible-name', host: 'private-host.example', tags: ['kos-ws-pay'], key: 'SYNTHETIC-PRIVATE-CONFIG' };
const epoch = (id = serviceId, wid = payWorkspaceId) => ({ epoch_id: id, cluster_id: cid, node_id: 'a'.repeat(64), entity_type: 'services', entity_id: id, workspace_id: wid, service_id: id, route_id: null, consumer_id: null, tags: [], service_label: id === serviceId ? 'visible-name' : 'ops-visible', route_label: null, valid_from: new Date().toISOString(), verified_until: new Date(Date.now()+15000).toISOString(), closed_at: null, quality: 'verified' });
const workspaceGrant = { module: 'monitoring', action: 'read', scope_type: 'workspace', scope_values: [payWorkspaceId], cluster_id: cid, workspace_id: payWorkspaceId };
const wholeGrant = { module: 'monitoring', action: 'read', scope_type: 'global', scope_values: [], cluster_id: cid, workspace_id: null };
function fixture(grants: any[] = [workspaceGrant]) {
  const state = { permissionEpoch: 1, items: [epoch()] as any[], afterInventory: undefined as (() => void) | undefined };
  const execution = new KongExecutionContextService(), workspace = workspaceFixture(cid);
  const raw = new Map([[serviceId, structuredClone(resource)], [otherId, { ...structuredClone(resource), id: otherId, name: 'ops-visible', tags: ['kos-ws-ops'] }]]);
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('FROM users')) return { id: uid, username: actor.user.username, status: 'active', super_admin: false, permissions_epoch: state.permissionEpoch, credential_epoch: 1 };
    if (sql.includes('FROM auth_sessions')) return { id: 'test-session' }; if (sql.includes('FROM iam_epoch')) return { version: state.permissionEpoch };
    if (sql.includes('FROM clusters')) return { id: cid }; return null;
  }), query: vi.fn(async () => grants) };
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => { expect(method).toBe('GET'); const item = raw.get(path.split('/').at(-1)!); if (!item) throw new NotFoundException(); return structuredClone(item); }),
    list: vi.fn(async () => { state.afterInventory?.(); return { items: [...raw.values()], nextCursor: null, size: 20 }; }) };
  const repository: any = { currentAllowedEpochs: vi.fn(async () => ({ items: state.items, catalogRevision: 1, blocked: false, warnings: [] })) };
  const authz = new AuthorizationService(db, workspace.resolver, kong, execution), service = new MetricsScopeService(authz, workspace.resolver, kong, execution, repository);
  const run = <T>(fn: () => Promise<T>) => execution.runHttp({}, async () => { execution.bindHttpActor(actor.user, 'test-session'); const close = execution.captureHttpCloser(); try { return await execution.runActor({ actor: actor.user, clusterId: cid, workspaceId: payWorkspaceId, module: 'monitoring', action: 'read' }, fn); } finally { close(); } });
  return { state, service, authz, kong, repository, workspace, raw, run };
}
beforeEach(() => { vi.stubEnv('APP_SECRET', 'metrics-scope-independent-test-private-key-32'); });
afterEach(() => vi.unstubAllEnvs());

describe('M5 independent actual metrics scope service and current grants', () => {
  it('restricts a Service plus Route drilldown to the selected Route rather than unioning sibling traffic', async () => {
    const f = fixture(), routeId = 'a2a8e889-b27c-4bb9-8b18-e0e4223f0bab';
    const route = { id: routeId, name: 'selected-route', service: { id: serviceId }, tags: ['kos-ws-pay'] };
    f.raw.set(routeId, route as any);
    const pair = { ...epoch(), entity_type: 'routes', entity_id: routeId, route_id: routeId,
      service_id: serviceId, service_label: 'visible-name', route_label: route.name };
    f.repository.currentAllowedEpochs.mockImplementation(async (_cid: string, options: any) => ({
      items: options.authorizedServiceIds ? [epoch(), pair] : [pair], catalogRevision: 1, blocked: false, warnings: [],
    }));
    const selected = await f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId, serviceId, routeId }, actor, 1));
    expect(selected.epochs.map(e => e.entity_id)).toEqual([routeId]);
    expect(f.repository.currentAllowedEpochs.mock.calls.at(-1)?.[1]).not.toHaveProperty('authorizedServiceIds');
    const serviceOnly = await f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId, serviceId }, actor, 1));
    expect(serviceOnly.epochs.map(e => e.entity_id)).toEqual([serviceId, routeId]);
    route.service.id = otherId;
    f.repository.currentAllowedEpochs.mockClear();
    await expect(f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId, serviceId, routeId }, actor, 1)))
      .rejects.toMatchObject({ response: { code: 'METRICS_ROUTE_SERVICE_MISMATCH' } });
    expect(f.repository.currentAllowedEpochs).not.toHaveBeenCalled();
  });
  it('admits monitoring-only current workspace epochs while native configuration remains unauthorized', async () => {
    const f = fixture();
    const result = await f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId } as any, actor, 1));
    expect(result.epochs).toHaveLength(1); expect(result.serviceNames.get(serviceId)).toBe('visible-name'); expect(result.wholeCluster).toBe(false);
    await expect(f.run(() => f.authz.assertEntity(actor.user, cid, 'services', 'read', resource, payWorkspaceId))).rejects.toMatchObject({ status: 403 });
  });
  it('rejects cluster aggregation for a workspace grant before repository or native inventory queries', async () => {
    const f = fixture();
    await expect(f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId, scope: 'cluster' } as any, actor, 1))).rejects.toMatchObject({ response: { code: 'METRICS_CLUSTER_SCOPE_DENIED' } });
    expect(f.repository.currentAllowedEpochs).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled(); expect(f.kong.list).not.toHaveBeenCalled();
    await expect(f.run(() => f.service.identities(cid, { workspaceId: payWorkspaceId, type: 'services', scope: 'cluster' }, actor))).rejects.toMatchObject({ status: 403 }); expect(f.kong.list).not.toHaveBeenCalled();
  });
  it('requires a complete whole-cluster grant before combining current epochs across verified workspaces', async () => {
    const f = fixture([wholeGrant]); f.state.items.push(epoch(otherId, opsWorkspaceId));
    const result = await f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId, scope: 'cluster' } as any, actor, 1));
    expect(result.mode).toBe('cluster'); expect(result.wholeCluster).toBe(true); expect(result.epochs.map(item => item.entity_id)).toEqual([serviceId, otherId]);
    expect(f.repository.currentAllowedEpochs.mock.calls[0][1]).toMatchObject({ expectedCatalogRevision: 1, workspaceId: undefined });
    expect(f.repository.currentAllowedEpochs.mock.calls[0][1].platformHistory).toBeUndefined();
  });
  it('filters minimal identity lists by actual current workspace and never returns configuration/secret fields', async () => {
    const f = fixture(); const page = await f.run(() => f.service.identities(cid, { workspaceId: payWorkspaceId, type: 'services' }, actor));
    expect(page.items).toEqual([{ id: serviceId, name: 'visible-name' }]); expect(page.total).toBeNull(); expect(JSON.stringify(page)).not.toContain('private-host'); expect(JSON.stringify(page)).not.toContain('SYNTHETIC-PRIVATE');
    expect(f.kong.list).toHaveBeenCalledTimes(1);
  });
  it.each(['service', 'route'] as const)('keeps an unnamed Service native host private in %s-authorized display names', async kind => {
    const routeId = 'a2a8e889-b27c-4bb9-8b18-e0e4223f0bab';
    const f = fixture(kind === 'service' ? [workspaceGrant] : [{ ...workspaceGrant, scope_type: 'entity',
      scope_values: [{ entity_type: 'routes', entity_id: routeId }] }]);
    const actual: any = f.raw.get(serviceId); actual.name = null;
    const route: any = { id: routeId, name: 'visible-route', service: { id: serviceId }, tags: ['kos-ws-pay'] }; f.raw.set(routeId, route);
    const pair = { ...epoch(), entity_type: 'routes', entity_id: routeId, route_id: routeId, service_id: serviceId,
      service_label: actual.host, route_label: route.name };
    f.state.items = kind === 'service' ? [{ ...epoch(), service_label: actual.host }, pair] : [pair];
    const result = await f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId } as any, actor, 1));
    expect(result.epochs).toHaveLength(kind === 'service' ? 2 : 1);
    expect(result.serviceNames.get(serviceId)).toBe(serviceId); expect([...result.serviceNames.values()]).not.toContain(actual.host);
    if (kind === 'service') {
      const page = await f.run(() => f.service.identities(cid, { workspaceId: payWorkspaceId, type: 'services' }, actor));
      expect(page.items[0]).toEqual({ id: serviceId, name: serviceId }); expect(JSON.stringify(page)).not.toContain(actual.host);
    }
  });
  it('permits a Service-only monitoring aggregate over verified children while Route selectors and configuration remain denied', async () => {
    const routeId = 'a2a8e889-b27c-4bb9-8b18-e0e4223f0bab';
    const f = fixture([{ module: 'monitoring', action: 'read', scope_type: 'entity', scope_values: [{ entity_type: 'services', entity_id: serviceId }], cluster_id: cid, workspace_id: payWorkspaceId }]);
    const route: any = { id: routeId, name: 'private-child-route', service: { id: serviceId }, tags: ['kos-ws-pay'] }; f.raw.set(routeId, route);
    f.state.items.push({ ...epoch(), entity_type: 'routes', entity_id: routeId, route_id: routeId, service_id: serviceId, service_label: 'visible-name', route_label: 'private-child-route' });
    const result = await f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId, serviceId } as any, actor, 1));
    expect(result.epochs.map(row => row.entity_type)).toEqual(['services', 'routes']);
    await expect(f.run(() => f.authz.assertScopedResource(actor.user, cid, 'monitoring', 'read', 'routes', route, payWorkspaceId))).rejects.toMatchObject({ status: 403 });
    await expect(f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId, routeId } as any, actor, 1))).rejects.toMatchObject({ status: 403 });
    route.tags = ['kos-ws-ops']; expect((await f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId, serviceId } as any, actor, 1))).epochs).toHaveLength(1);
  });
  it('does not reuse old epochs after an external native rename or same-workspace business-tag change', async () => {
    for (const change of [{ name: 'renamed-after-proof' }, { tags: ['kos-ws-pay', 'new-owner'] }]) {
      const f = fixture(); Object.assign(f.raw.get(serviceId)!, change);
      expect((await f.run(() => f.service.resolve(cid, { workspaceId: payWorkspaceId } as any, actor, 1))).epochs).toEqual([]);
    }
  });
  it('keeps disabled workspaces readable and rejects invalid/structured scopes before inventory', async () => {
    const f = fixture(); f.workspace.rows[1].status = 'disabled';
    expect((await f.run(() => f.service.identities(cid, { workspaceId: payWorkspaceId, type: 'services' }, actor))).items).toHaveLength(1);
    f.kong.list.mockClear(); for (const scope of [['cluster'], 'global', { scope: 'workspace' }]) await expect(f.run(() => f.service.identities(cid, { workspaceId: payWorkspaceId, type: 'services', scope }, actor))).rejects.toMatchObject({ status: 400 }); expect(f.kong.list).not.toHaveBeenCalled();
  });
  it('rejects a successful inventory response if the effective permission version changed in flight', async () => {
    const f = fixture(); f.state.afterInventory = () => f.state.permissionEpoch++;
    await expect(f.run(() => f.service.identities(cid, { workspaceId: payWorkspaceId, type: 'services' }, actor))).rejects.toMatchObject({ response: { code: 'PERMISSIONS_CHANGED' } });
  });
});
