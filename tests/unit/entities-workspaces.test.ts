import { executionFixture } from './execution-test-fixture';
import 'reflect-metadata';
import { ForbiddenException, HttpException, NotFoundException } from '@nestjs/common';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from '../../apps/console-api/src/modules/entities/entities.service';
import { PluginCenterService } from '../../apps/console-api/src/modules/plugin-center/plugin-center.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { DEFAULT_WORKSPACE_ID, PAY_WORKSPACE_ID, OPS_WORKSPACE_ID, workspaceTestResolver } from './workspace-test-helper';
const cid = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const actor = { user: { id: 'admin', username: 'admin', superAdmin: true }, idempotencyKey: 'm3-test', workspaceId: PAY_WORKSPACE_ID };
const pay = { id: 's-pay', name: 'pay', tags: ['kos-ws-pay'] };
const ops = { id: 's-ops', name: 'ops', tags: ['kos-ws-ops'] };

describe('M3 authoritative workspace isolation through core and nested APIs', () => {
  let kong: any, authz: any, mutations: any, recycle: any, credentialStore: any, audit: any, index: any, service: EntityService, resolver: any, rows: any[], native: Map<string, any>;
  beforeEach(() => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
    ({ resolver, rows } = workspaceTestResolver(cid));
    native = new Map([['/services/s-pay', pay], ['/services/s-ops', ops], ['/consumers/c-pay', { id: 'c-pay', tags: ['kos-ws-pay'] }], ['/upstreams/u-pay', { id: 'u-pay', tags: ['kos-ws-pay'] }]]);
    kong = {
      request: vi.fn().mockImplementation(async (_cid, method, path, body) => {
        if (method === 'GET') { const entity = native.get(path); if (!entity) throw new NotFoundException(); return structuredClone(entity); }
        return { id: 'new', ...body };
      }), list: vi.fn().mockResolvedValue({ items: [], nextCursor: null, size: 20 }), schema: vi.fn().mockResolvedValue({ fields: [] }), pluginSchema: vi.fn().mockResolvedValue({ fields: [] }),
    };
    authz = { assertNestedParentScope: vi.fn().mockResolvedValue(undefined), isPlatformAdmin: vi.fn().mockImplementation(async (u:any)=>!!u.superAdmin), assertCluster: vi.fn(), assertEntity: vi.fn(), assertSecretRead: vi.fn(), scopeTags: vi.fn().mockImplementation(async (_u, _cid, _wid, tags) => tags), permissionVersion: vi.fn().mockResolvedValue('permissions-v1'), filterEntities: vi.fn().mockImplementation(async (_u, _cid, _type, items) => items) };
    mutations = { execute: vi.fn().mockImplementation(async (_context, callback) => callback()), completed: vi.fn().mockResolvedValue(null) };
    recycle = { archiveAndDelete: vi.fn().mockResolvedValue({ entry_id: 'bin' }) };
    credentialStore = { get: vi.fn(), save: vi.fn() }; audit = { append: vi.fn() }; index = { upsert: vi.fn(), search: vi.fn() };
    service = new EntityService(kong, authz, mutations, recycle, credentialStore, new SecretService(), audit, index, resolver, executionFixture());
  });
  afterEach(() => vi.unstubAllEnvs());
  it('checks the operation permission before resolving untrusted workspace IDs and preserves write-only create grants', async () => {
    const resolve = vi.spyOn(resolver, 'resolve');
    authz.assertCluster.mockRejectedValueOnce(new ForbiddenException());
    await expect(service.create(cid, 'consumers', { username: 'new' }, { workspaceId: OPS_WORKSPACE_ID }, actor)).rejects.toMatchObject({ status: 403 });
    expect(resolve).not.toHaveBeenCalled(); expect(kong.request).not.toHaveBeenCalled();
    authz.assertCluster.mockImplementation(async (_u, _cid, _module, action) => { if (action !== 'write') throw new ForbiddenException(); });
    await expect(service.create(cid, 'consumers', { username: 'new' }, {}, actor)).resolves.toMatchObject({ entity: { username: 'new' } });
    expect(authz.assertCluster.mock.calls.every((call: any[]) => call[3] === 'write')).toBe(true);
  });
  it('does not let a module-level secret grant reveal an entity without its actual scoped secret permission', async () => {
    kong.list.mockResolvedValue({ items: [{ id: 'not-secret-granted', tags: ['kos-ws-pay'], key: 'concealed-value' }], nextCursor: null, size: 20 });
    authz.assertSecretRead.mockRejectedValue(new ForbiddenException('secret scope denied'));
    await expect(service.list(cid, 'consumers', { reveal: true }, actor)).rejects.toMatchObject({ status: 403 });
    expect(authz.assertSecretRead).toHaveBeenCalledWith(actor.user, cid, 'consumers', expect.objectContaining({ id: 'not-secret-granted' }), PAY_WORKSPACE_ID);
    expect(audit.append).not.toHaveBeenCalled();
  });
  it('requires the actual Consumer parent secret grant separately from its credential grant', async () => {
    native.set('/consumers/c-pay/basic-auth/b1', { id: 'b1', consumer: { id: 'c-pay' }, password: 'native-hash', tags: ['kos-ws-pay'] });
    authz.assertNestedParentScope.mockRejectedValue(new ForbiddenException('parent scope denied'));
    await expect(service.getCredential(cid, 'c-pay', 'basic-auth', 'b1', { reveal: true }, actor)).rejects.toMatchObject({ status: 403 });
    expect(authz.assertNestedParentScope).toHaveBeenCalledWith(actor.user, cid, 'consumers', expect.objectContaining({ id: 'c-pay' }), 'basic-auth', 'read', PAY_WORKSPACE_ID, expect.objectContaining({ id: 'b1' }));
    expect(authz.assertSecretRead).not.toHaveBeenCalled();
    expect(credentialStore.get).not.toHaveBeenCalled(); expect(audit.append).not.toHaveBeenCalled();
  });
  it('keeps default membership negative and quarantines unknown or multiple reserved tags', async () => {
    kong.list.mockResolvedValue({ items: [{ id: 'legacy' }, { id: 'explicit', tags: ['kos-ws-default'] }, pay, ops, { id: 'unknown', tags: ['kos-ws-retired'] }, { id: 'ambiguous', tags: ['kos-ws-default', 'kos-ws-pay'] }], nextCursor: null, size: 20 });
    const result = await service.list(cid, 'services', {}, { ...actor, workspaceId: undefined });
    expect(result.items.map((item: any) => item.id)).toEqual(['legacy', 'explicit']);
    expect(result.workspace_id).toBe(DEFAULT_WORKSPACE_ID);
    expect(authz.filterEntities).toHaveBeenCalledWith(actor.user, cid, 'services', expect.any(Array), DEFAULT_WORKSPACE_ID);
  });
  it('combines workspace AND business-OR via postfilter and bounds empty-page traversal', async () => {
    kong.list.mockResolvedValueOnce({ items: [{ ...pay, tags: ['kos-ws-pay', 'other'] }, { ...ops, tags: ['kos-ws-ops', 'alpha'] }], nextCursor: 'page-two', size: 2 })
      .mockResolvedValueOnce({ items: [{ ...pay, tags: ['kos-ws-pay', 'beta'] }], nextCursor: 'page-three', size: 2 });
    const result = await service.list(cid, 'services', { workspaceId: PAY_WORKSPACE_ID, tags: 'alpha/beta', size: 2 }, actor);
    expect(result.items.map((item: any) => item.id)).toEqual(['s-pay']);
    expect(kong.list.mock.calls[0][2]).toEqual({ size: 2, tags: 'kos-ws-pay' });
    expect(kong.list.mock.calls[1][3]).toBe('page-two');
    const originalBinding = kong.list.mock.calls[0][4];
    rows[1].revision++;
    await service.list(cid, 'services', { workspaceId: PAY_WORKSPACE_ID, tags: 'alpha/beta', size: 2 }, actor);
    expect(kong.list.mock.calls[2][4]).not.toBe(originalBinding);
    kong.list.mockClear(); kong.list.mockResolvedValue({ items: [ops], nextCursor: 'continue', size: 2 });
    const empty = await service.list(cid, 'services', { workspaceId: PAY_WORKSPACE_ID }, actor);
    expect(empty).toMatchObject({ items: [], nextCursor: 'continue', scan_budget_exhausted: true });
    expect(kong.list).toHaveBeenCalledTimes(5);
  });
  it('blocks cross-workspace detail/update/delete before relations or mutations and isolates metadata schemas by cluster', async () => {
    await expect(service.get(cid, 'services', ops.id, {}, actor)).rejects.toMatchObject({ status: 403 });
    await expect(service.update(cid, 'services', ops.id, { name: 'hijacked' }, {}, actor)).rejects.toMatchObject({ status: 403 });
    await expect(service.delete(cid, 'services', ops.id, { confirmed: true, confirm_name: ops.name }, actor)).rejects.toMatchObject({ status: 403 });
    expect(mutations.execute).not.toHaveBeenCalled(); expect(recycle.archiveAndDelete).not.toHaveBeenCalled(); expect(kong.list).not.toHaveBeenCalled();
    await expect(service.schema(cid, 'services', { ...actor, workspaceId: 'e59e3e9c-037c-4a82-9e9a-df2b8bb02f15' })).rejects.toMatchObject({ status: 403 });
    expect(kong.schema).not.toHaveBeenCalled();
    await service.schema(cid, 'services', actor);
    expect(authz.assertCluster).toHaveBeenCalledWith(actor.user, cid, 'services', 'read', PAY_WORKSPACE_ID);
  });
  it('injects the selected physical tag and prevents ordinary tag edits from changing workspace membership', async () => {
    await service.create(cid, 'consumers', { username: 'new', tags: ['team:pay'] }, {}, actor);
    expect(kong.request).toHaveBeenCalledWith(cid, 'POST', '/consumers', { username: 'new', tags: ['kos-tag-dGVhbTpwYXk', 'kos-ws-pay'] });
    expect(mutations.execute.mock.calls[0][0].workspaceId).toBe(PAY_WORKSPACE_ID);
    await service.update(cid, 'services', pay.id, { tags: [] }, {}, actor);
    expect(kong.request).toHaveBeenCalledWith(cid, 'PATCH', '/services/s-pay', { tags: ['kos-ws-pay'] });
    mutations.execute.mockClear();
    await expect(service.update(cid, 'services', pay.id, { tags: ['workspace:ops'] }, {}, actor)).rejects.toMatchObject({ status: 400, response: { code: 'WORKSPACE_TAG_IMMUTABLE' } });
    expect(mutations.execute).not.toHaveBeenCalled();
  });
  it('rejects cross-workspace references both in preflight and after another mutation moves a parent', async () => {
    await expect(service.create(cid, 'routes', { service: { id: ops.id }, paths: ['/'] }, {}, actor)).rejects.toMatchObject({ status: 403 });
    expect(mutations.execute).not.toHaveBeenCalled();
    mutations.execute.mockImplementation(async (_context, callback) => { native.set('/services/s-pay', { ...pay, tags: ['kos-ws-ops'] }); return callback(); });
    await expect(service.create(cid, 'routes', { service: { id: pay.id }, paths: ['/'] }, {}, actor)).rejects.toMatchObject({ status: 403 });
    expect(kong.request.mock.calls.some((call: any[]) => call[1] === 'POST')).toBe(false);
  });
  it('allows ordinary DNS Service hosts but forbids matching an existing Upstream from another workspace', async () => {
    await service.create(cid, 'services', { host: 'dns.example.test' }, {}, actor);
    expect(kong.request).toHaveBeenCalledWith(cid, 'POST', '/services', expect.objectContaining({ host: 'dns.example.test' }));
    native.set('/upstreams/ops-upstream', { id: 'u-ops', tags: ['kos-ws-ops'] });
    mutations.execute.mockClear();
    await expect(service.create(cid, 'services', { host: 'ops-upstream' }, {}, actor)).rejects.toMatchObject({ status: 403 });
    expect(mutations.execute).not.toHaveBeenCalled();
  });
  it.each(['10.80.1.30', '2001:db8::10', '[2001:db8::10]'])('does not confuse literal Service host %s with an Upstream name', async host => {
    kong.request.mockImplementation(async (_cid: string, method: string, path: string, body: any) => {
      if (method === 'GET' && path.startsWith('/upstreams/')) throw new HttpException({ code: 'KONG_VALIDATION_ERROR', upstreamStatus: 400 }, 400);
      return { id: 'new', ...body };
    });
    await expect(service.create(cid, 'services', { host }, {}, actor)).resolves.toMatchObject({ entity: { host } });
    expect(kong.request.mock.calls.some((call: any[]) => call[1] === 'GET' && call[2].startsWith('/upstreams/'))).toBe(false);
  });
  it.each([400, 503])('still propagates real DNS-name Upstream lookup failure %s before entering the mutation ledger', async status => {
    kong.request.mockRejectedValue(new HttpException({ code: 'KONG_VALIDATION_ERROR' }, status));
    await expect(service.create(cid, 'services', { host: 'business.example' }, {}, actor)).rejects.toMatchObject({ status });
    expect(mutations.execute).not.toHaveBeenCalled();
    expect(kong.request).toHaveBeenCalledWith(cid, 'GET', '/upstreams/business.example');
  });
  it('inherits credential visibility from Consumer while rejecting every reparent form before writes', async () => {
    native.set('/consumers/c-pay/key-auth/k1', { id: 'k1', key: 'hidden-key', consumer: { id: 'c-pay' }, tags: ['kos-ws-ops'] });
    kong.list.mockResolvedValue({ items: [native.get('/consumers/c-pay/key-auth/k1')], nextCursor: null, size: 20 });
    const result = await service.credentials(cid, 'c-pay', 'key-auth', {}, actor);
    expect(result.items[0].id).toBe('k1'); expect(result.workspace_inheritance).toBe('consumer');
    expect(JSON.stringify(result)).not.toContain('hidden-key');
    for (const consumer of [null, 'c-pay', { id: 'c-ops' }, { id: 'c-pay', username: 'unexpected' }]) {
      await expect(service.updateCredential(cid, 'c-pay', 'key-auth', 'k1', { consumer }, {}, actor)).rejects.toMatchObject({ status: 400, response: { code: 'PARENT_REFERENCE_IMMUTABLE' } });
    }
    expect(mutations.execute).not.toHaveBeenCalled();
    await service.updateCredential(cid, 'c-pay', 'key-auth', 'k1', { tags: ['owner:test'] }, {}, actor);
    const patch = kong.request.mock.calls.find((call: any[]) => call[1] === 'PATCH')[3];
    expect(patch.tags).toEqual(['kos-tag-b3duZXI6dGVzdA', 'kos-ws-pay']); expect(patch).not.toHaveProperty('consumer');
  });
  it('stamps all six credential creations and never rewrites an existing Basic password during tag edits', async () => {
    for (const kind of ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls']) await service.createCredential(cid, 'c-pay', kind, { tags: ['fixture'] }, {}, actor);
    expect(kong.request.mock.calls.filter((call: any[]) => call[1] === 'POST').every((call: any[]) => call[3].tags.includes('kos-ws-pay'))).toBe(true);
    native.set('/consumers/c-pay/basic-auth/b1', { id: 'b1', password: 'original-kong-hash', consumer: { id: 'c-pay' }, tags: ['kos-ws-pay'] });
    await service.updateCredential(cid, 'c-pay', 'basic-auth', 'b1', { tags: ['owner:test'] }, {}, actor);
    const patch = kong.request.mock.calls.find((call: any[]) => call[1] === 'PATCH')[3];
    expect(patch).not.toHaveProperty('password');
  });
  it('derives Target scope from Upstream and removes stale child tags only on an ordinary weight-history append', async () => {
    native.set('/upstreams/u-pay/targets/t1', { id: 't1', target: 'host:8080', weight: 10, upstream: { id: 'u-pay' }, tags: ['kos-ws-ops', 'business'] });
    kong.list.mockResolvedValue({ items: [native.get('/upstreams/u-pay/targets/t1')], nextCursor: null, size: 20 });
    const result = await service.targets(cid, 'u-pay', {}, actor);
    expect(result).toMatchObject({ effective_workspace_id: PAY_WORKSPACE_ID, workspace_inheritance: 'upstream', historical_tags_may_differ: true });
    await expect(service.updateTarget(cid, 'u-pay', 't1', { upstream: { id: 'u-ops' } }, actor)).rejects.toMatchObject({ status: 400 });
    const updated = await service.updateTarget(cid, 'u-pay', 't1', { weight: 20 }, actor);
    expect(kong.request).toHaveBeenCalledWith(cid, 'POST', '/upstreams/u-pay/targets', { target: 'host:8080', weight: 20, tags: ['business', 'kos-ws-pay'] });
    expect(updated).toMatchObject({ original_id: 't1', effective_id: 'new' });
  });
  it('requires platform permission for resulting global bindings, including PATCH that clears a parent', async () => {
    const restricted = { ...actor, user: { ...actor.user, superAdmin: false } };
    await expect(service.create(cid, 'plugins', { name: 'request-termination', config: {} }, {}, restricted)).rejects.toMatchObject({ status: 403 });
    native.set('/plugins/p1', { id: 'p1', name: 'request-termination', service: { id: pay.id }, tags: ['kos-ws-pay'] });
    await expect(service.update(cid, 'plugins', 'p1', { service: null }, {}, restricted)).rejects.toMatchObject({ status: 403 });
    expect(mutations.execute).not.toHaveBeenCalled();
    const global = await service.create(cid, 'plugins', { name: 'request-termination', config: {} }, {}, actor);
    expect(global.entity.console_scope_notice).toContain('整个集群');
  });
  it('rejects implicit SNI removal and audits newly created association workspace stamps', async () => {
    kong.list.mockResolvedValue({ items: [{ id: 'sni-old', name: 'old.example', tags: ['kos-ws-pay'] }], nextCursor: null });
    await expect((service as any).certificateAssociations(cid, 'cert1', { snis: [] }, actor)).rejects.toMatchObject({ status: 409, response: { code: 'SNI_RECYCLE_REQUIRED' } });
    expect(kong.request).not.toHaveBeenCalled();
    native.set('/snis/new.example', { id: 'sni-new', name: 'new.example', tags: ['business'], certificate: { id: 'cert1' } });
    await (service as any).stampCertificateSnis(cid, { id: 'cert1' }, { snis: ['new.example'] }, actor);
    expect(kong.request).toHaveBeenCalledWith(cid, 'PATCH', '/snis/sni-new', { tags: ['business', 'kos-ws-pay'] });
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ workspaceId: PAY_WORKSPACE_ID, entityType: 'snis', entityId: 'sni-new', action: 'workspace_stamp' }));
    native.set('/snis/new.example', { id: 'sni-new', certificate: { id: 'other-cert' } });
    await expect((service as any).stampCertificateSnis(cid, { id: 'cert1' }, { snis: ['new.example'] }, actor)).rejects.toMatchObject({ status: 503, response: { code: 'SNI_STAMP_RESULT_UNCERTAIN' } });
  });
});

describe('M3 PluginCenter workspace-safe projections', () => {
  let kong: any, db: any, authz: any, resolver: any, rows: any[], service: PluginCenterService;
  beforeEach(() => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); ({ resolver, rows } = workspaceTestResolver(cid));
    kong = { request: vi.fn().mockResolvedValue(ops), list: vi.fn().mockResolvedValue({ items: [], nextCursor: null, size: 20 }) };
    db = { one: vi.fn().mockImplementation(async sql => sql.includes('index_sync_state') ? { completed_at: 'now' } : { enabled_plugins: ['jwt'] }), query: vi.fn().mockResolvedValue([]) };
    authz = { assertNestedParentScope: vi.fn().mockResolvedValue(undefined), isPlatformAdmin: vi.fn().mockImplementation(async (u:any)=>!!u.superAdmin), assertCluster: vi.fn(), assertEntity: vi.fn(), scopeTags: vi.fn().mockImplementation(async (_u, _cid, _wid, tags) => tags), permissionVersion: vi.fn().mockResolvedValue('p1'), filterEntities: vi.fn().mockImplementation(async (_u, _cid, _type, items) => items) };
    service = new PluginCenterService(db, kong, authz, new SecretService(), { update: vi.fn() } as any, resolver, executionFixture());
  });
  afterEach(() => vi.unstubAllEnvs());
  it('applies workspace SQL membership and business OR independently for index statistics', async () => {
    await service.catalog(cid, { workspaceId: PAY_WORKSPACE_ID, tags: 'a/b' }, actor);
    expect(db.query.mock.calls[0][1]).toEqual([cid, ['kos-ws-pay'], ['a', 'b']]);
    expect(db.query.mock.calls[0][0]).toContain('tags @> $2'); expect(db.query.mock.calls[0][0]).toContain('tags && $3');
  });
  it('blocks cross-workspace context parents and excludes other-workspace plugin instances', async () => {
    await expect(service.context(cid, { workspaceId: PAY_WORKSPACE_ID, serviceId: ops.id }, actor)).rejects.toMatchObject({ status: 403 });
    expect(kong.list).not.toHaveBeenCalled();
    kong.list.mockResolvedValue({ items: [{ id: 'p-pay', name: 'jwt', tags: ['kos-ws-pay'] }, { id: 'p-ops', name: 'jwt', tags: ['kos-ws-ops'] }], nextCursor: null, size: 20 });
    const result = await service.instances(cid, { workspaceId: PAY_WORKSPACE_ID }, actor);
    expect(result.items.map((item: any) => item.id)).toEqual(['p-pay']);
    const binding = kong.list.mock.calls[0][4]; rows[1].revision++;
    await service.instances(cid, { workspaceId: PAY_WORKSPACE_ID }, actor);
    expect(kong.list.mock.calls[1][4]).not.toBe(binding);
  });
  it('never claims a full default runtime chain when an excluded global plugin can execute', async () => {
    kong.list.mockResolvedValue({ items: [{ id: 'p-default', name: 'jwt', tags: ['kos-ws-default'] }, { id: 'p-secret', name: 'request-termination', config: { secret: 'excluded-config' }, tags: ['kos-ws-ops'] }], nextCursor: null, size: 20 });
    const result = await service.context(cid, {}, { ...actor, workspaceId: undefined });
    expect(result.complete).toBe(false); expect(result.selected).toEqual([]); expect(result.candidates).toHaveLength(1);
    expect(JSON.stringify(result)).not.toContain('p-secret'); expect(JSON.stringify(result)).not.toContain('excluded-config'); expect(result.warnings.join()).toContain('全局插件');
  });
});
