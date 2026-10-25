import 'reflect-metadata';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from '../../apps/console-api/src/modules/entities/entities.service';
import { AuthorizationController } from '../../apps/console-api/src/modules/authorization/authorization.controller';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { executionFixture } from './execution-test-fixture';
import { PAY_WORKSPACE_ID as wid, workspaceTestResolver } from './workspace-test-helper';

const cid = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c', upstream = 'd0350b4a-f011-4c8a-9eb3-5e65479e4d6b';
const oldId = '109621c2-cf81-4e25-b87b-4cdecc148ad5', currentId = 'b06ca9f4-98cf-49de-aa71-f58220d5375b';
const actor = { user: { id: 'history-reader', username: 'reader', superAdmin: false }, workspaceId: wid };
const parent = { id: upstream, name: 'pay-upstream', tags: ['kos-ws-pay'] };
const target = (id = oldId, weight = 100, tags = ['owner-pay']) => ({ id, target: 'echo:8080', weight, tags, upstream: { id: upstream }, created_at: 1 });

function fixture() {
  const { resolver } = workspaceTestResolver(cid), secrets = new SecretService();
  const kong: any = { request: vi.fn(async (_cid, method, path) => {
    expect(method).toBe('GET'); expect(path).toBe(`/upstreams/${upstream}`); return structuredClone(parent);
  }), list: vi.fn(async () => ({ items: [target(), target(currentId, 0)], nextCursor: null, size: 20 })) };
  const authz: any = { assertCluster: vi.fn(), assertNestedParentScope: vi.fn(), assertEntity: vi.fn(),
    scopeTags: vi.fn(async (_u, _c, _w, tags) => tags), permissionVersion: vi.fn(async () => 'history-version-1'),
    filterEntities: vi.fn(async (_u, _c, _t, items) => items) };
  const mutations: any = { execute: vi.fn() }, recycle: any = { archiveAndDelete: vi.fn() };
  const service = new EntityService(kong, authz, mutations, recycle, {} as any, secrets, {} as any, {} as any, resolver, executionFixture());
  return { kong, authz, mutations, recycle, service, resolver, secrets };
}
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'b8'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('M11 bounded read-only Target history', () => {
  it('uses only the current parent and Kong1.5 targets/all, preserving old/disabled rows and their original tags', async () => {
    const f = fixture(), old = target(oldId, 100, ['kos-ws-ops', 'owner-pay']), retired = target(currentId, 0);
    f.kong.list.mockResolvedValue({ items: [old, retired], nextCursor: 'opaque-next', size: 20 });
    const result = await f.service.targetHistory(cid, upstream, { workspaceId: wid, size: 20 }, actor);
    expect(f.kong.request).toHaveBeenCalledOnce();
    expect(f.authz.assertNestedParentScope).toHaveBeenCalledWith(actor.user, cid, 'upstreams', parent, 'targets', 'read', wid, undefined);
    expect(f.kong.list).toHaveBeenCalledWith(cid, `/upstreams/${upstream}/targets/all`, { size: 20 }, undefined, expect.stringContaining(`target-history:${upstream}`));
    expect(f.authz.filterEntities).toHaveBeenCalledWith(actor.user, cid, 'targets', [old, retired], wid);
    expect(result.items.map(item => item.id)).toEqual([oldId, currentId]);
    expect(result.items[0].tags).toContain('workspace:ops'); expect(result.items[1].weight).toBe(0);
    expect(result).toMatchObject({ nextCursor: 'opaque-next', total: null, current_selection: false, selection: 'history', workspace_inheritance: 'upstream' });
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.recycle.archiveAndDelete).not.toHaveBeenCalled();
  });

  it('checks current upstream workspace/permission before accessing the historical collection', async () => {
    const f = fixture(); f.authz.assertNestedParentScope.mockRejectedValue(new ForbiddenException());
    await expect(f.service.targetHistory(cid, upstream, {}, actor)).rejects.toMatchObject({ status: 403 }); expect(f.kong.list).not.toHaveBeenCalled();
    const foreign = fixture(); foreign.kong.request.mockResolvedValue({ ...parent, tags: ['kos-ws-ops'] });
    await expect(foreign.service.targetHistory(cid, upstream, {}, actor)).rejects.toMatchObject({ status: 403 }); expect(foreign.kong.list).not.toHaveBeenCalled();
  });

  it('keeps history in a distinct signed-cursor subject and never applies stale workspace tags as native filters', async () => {
    const f = fixture(); await f.service.targetHistory(cid, upstream, { cursor: 'cursor-history', tags: 'owner-pay' }, actor);
    const history = f.kong.list.mock.calls[0]; f.kong.list.mockClear();
    await f.service.targets(cid, upstream, {}, actor); const effective = f.kong.list.mock.calls[0];
    expect(history[3]).toBe('cursor-history'); expect(history[4]).not.toBe(effective[4]);
    expect(history[2]).toEqual({ size: 20 }); expect(effective[1]).toBe(`/upstreams/${upstream}/targets`);
  });

  it('authorizes each exact historical row and removes rows outside the requested parent before granting visibility', async () => {
    const f = fixture(), permitted = target(), denied = target(currentId, 80, ['owner-other']);
    f.kong.list.mockResolvedValue({ items: [permitted, denied, { ...target(), upstream: { id: currentId } }, { ...target(), upstream: null }], nextCursor: null, size: 20 });
    f.authz.filterEntities.mockImplementation(async (_u, _c, _t, items) => items.filter(item => item.tags.includes('owner-pay')));
    const result = await f.service.targetHistory(cid, upstream, {}, actor);
    expect(f.authz.filterEntities.mock.calls[0][3]).toEqual([permitted, denied]); expect(result.items).toHaveLength(1);
    expect(result.items[0].id).toBe(oldId); expect(f.authz.assertEntity).not.toHaveBeenCalled();
  });

  it('returns the next cursor after at most five unauthorized/filtered native pages instead of scanning the whole history', async () => {
    const f = fixture(); f.kong.list.mockResolvedValue({ items: [target()], nextCursor: 'next-page', size: 2 });
    f.authz.filterEntities.mockResolvedValue([]);
    const result = await f.service.targetHistory(cid, upstream, { size: 2 }, actor);
    expect(f.kong.list).toHaveBeenCalledTimes(5); expect(result).toMatchObject({ items: [], nextCursor: 'next-page', scan_budget_exhausted: true });
    expect(f.kong.list.mock.calls.every(call => call[2].size === 2)).toBe(true);
  });

  it('does not turn visibility of an old UUID into an ordinary weight update permission/current selection', async () => {
    const f = fixture(); await f.service.targetHistory(cid, upstream, {}, actor);
    f.kong.request.mockImplementation(async (_cid, method, path) => {
      if (path === `/upstreams/${upstream}`) return parent;
      if (path === `/upstreams/${upstream}/targets/${oldId}`) return target();
      throw new NotFoundException();
    });
    f.kong.list.mockResolvedValue({ items: [target(currentId, 80)], nextCursor: null, size: 20 });
    f.authz.entityCapabilities = vi.fn(async () => ({ read: true, write: true, delete: true, approve: true, reveal: true }));
    const capabilities = new AuthorizationController(f.authz, f.kong, executionFixture(), f.resolver, {} as any, f.secrets);
    const result = await capabilities.entityCapabilities(cid, wid, { entities: [{ type: 'targets', id: oldId, parent_id: upstream }] }, actor);
    expect(result.items).toEqual([{ type: 'targets', id: oldId, read: false, write: false, delete: false, approve: false, reveal: false }]);
    expect(f.authz.entityCapabilities).not.toHaveBeenCalled(); expect(f.mutations.execute).not.toHaveBeenCalled();
    expect(f.kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
  });
});
