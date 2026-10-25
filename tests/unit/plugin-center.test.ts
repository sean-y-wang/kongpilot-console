import { executionFixture } from './execution-test-fixture';
import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { PluginCenterService } from '../../apps/console-api/src/modules/plugin-center/plugin-center.service';
import { augmentFormSchema, BINDING_SCOPES, bindingScope, executionPriority, pluginMetadata } from '../../apps/console-api/src/modules/plugin-center/plugin-metadata';
import { validatePluginBindings, validatePluginConfiguration } from '../../apps/console-api/src/modules/plugin-center/plugin-validation';
import { validateKnownFields } from '../../apps/console-api/src/infrastructure/kong/schema';
import { DEFAULT_WORKSPACE_ID, workspaceTestResolver } from './workspace-test-helper';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
const load = (name: string) => JSON.parse(readFileSync(new URL(`../fixtures/kong-1.5.1/plugin-schema-${name}.json`, import.meta.url), 'utf8'));
const examples: Record<string, any[]> = JSON.parse(readFileSync(new URL('../fixtures/plugin-validation-examples.json', import.meta.url), 'utf8'));
const cid = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const actor = { user: { id: 'admin', username: 'admin', superAdmin: true }, requestId: 'm2', idempotencyKey: 'm2-unit' };

describe('M2 fixed 1.5 source metadata and recursive rule checks', () => {
  it('covers exactly the actual 34 loaded plugins with two valid schema examples each', () => {
    const enabled = JSON.parse(readFileSync(new URL('../fixtures/kong-1.5.1/plugins-enabled.json', import.meta.url), 'utf8')).enabled_plugins;
    expect(Object.keys(examples).sort()).toEqual([...enabled].sort());
    for (const name of enabled) for (const config of examples[name]) {
      const schema = load(name);
      expect(pluginMetadata(name).known).toBe(true);
      expect(() => validateKnownFields(config, schema, 'config'), name).not.toThrow();
      expect(() => validatePluginConfiguration(name, config, schema), name).not.toThrow();
    }
  });
  it('keeps same-name binding precedence distinct from actual handler execution order', () => {
    const fixtures = [7, 5, 6, 3, 4, 1, 2, 0].map(mask => ({ ...(mask & 4 ? { consumer: { id: 'c' } } : {}), ...(mask & 1 ? { route: { id: 'r' } } : {}), ...(mask & 2 ? { service: { id: 's' } } : {}) }));
    expect(fixtures.map(bindingScope)).toEqual(BINDING_SCOPES);
    expect(executionPriority('pre-function')).toBe(Infinity);
    expect(pluginMetadata('pre-function')).toMatchObject({ priority: null, priority_label: '∞' });
    expect(executionPriority('zipkin')).toBe(100000);
    expect(executionPriority('post-function')).toBe(-1000);
    expect(pluginMetadata('custom-plugin')).toMatchObject({ known: false, priority: null, constraints: { known: false, consumer: null } });
  });
  it('enforces source binding and protocol constraints without inventing restrictions', () => {
    expect(() => validatePluginBindings('key-auth', { consumer: { id: 'c' } })).toThrow();
    expect(() => validatePluginBindings('pre-function', { consumer: { id: 'c' } })).toThrow();
    expect(() => validatePluginBindings('kubernetes-sidecar-injector', { service: { id: 's' } })).toThrow();
    expect(() => validatePluginBindings('jwt', { consumer: { id: 'c' }, protocols: ['grpc'] })).not.toThrow();
    expect(() => validatePluginBindings('prometheus', { protocols: ['tcp', 'tls'] })).not.toThrow();
    expect(() => validatePluginBindings('cors', { protocols: ['tcp'] })).toThrow();
    expect(() => validatePluginBindings('custom-plugin', { consumer: { id: 'c' }, protocols: ['custom'] })).not.toThrow();
  });
  it('restores root source rules on a clone without altering the sanitized wire schema', () => {
    const wire = load('rate-limiting');
    expect(wire.entity_checks).toBeUndefined();
    expect(augmentFormSchema('rate-limiting', wire).entity_checks).toHaveLength(4);
    expect(wire.entity_checks).toBeUndefined();
  });
  it('matches nonempty semantics for whitelist/blacklist rather than mere presence', () => {
    expect(() => validatePluginConfiguration('acl', { whitelist: ['fixture'], blacklist: [] }, load('acl'))).not.toThrow();
    expect(() => validatePluginConfiguration('acl', { whitelist: [] }, load('acl'))).toThrow();
    expect(() => validatePluginConfiguration('acl', { whitelist: ['a'], blacklist: ['b'] }, load('acl'))).toThrow();
  });
  it('evaluates defaults for Redis rules without changing the caller configuration', () => {
    const config = { second: 10, policy: 'redis', redis_host: 'redis' };
    expect(() => validatePluginConfiguration('rate-limiting', config, load('rate-limiting'))).not.toThrow();
    expect(config).not.toHaveProperty('redis_port');
    expect(() => validatePluginConfiguration('rate-limiting', { second: 10, policy: 'redis' }, load('rate-limiting'))).toThrow();
    expect(() => validatePluginConfiguration('rate-limiting', { second: 10, minute: 9 }, load('rate-limiting'))).toThrow();
  });
  it('validates each nested array record and each map value in its local record context', () => {
    expect(() => validatePluginConfiguration('datadog', { metrics: [{ name: 'unique_users', stat_type: 'counter', sample_rate: 1, consumer_identifier: 'consumer_id' }] }, load('datadog'))).toThrow();
    expect(() => validatePluginConfiguration('datadog', { metrics: [{ name: 'unique_users', stat_type: 'set', consumer_identifier: 'consumer_id' }] }, load('datadog'))).not.toThrow();
    expect(() => validatePluginConfiguration('response-ratelimiting', { limits: { valid: { minute: 10 }, invalid: {} } }, load('response-ratelimiting'))).toThrow();
    expect(() => validatePluginConfiguration('response-ratelimiting', { limits: { invalid: { second: 10, minute: 1 } } }, load('response-ratelimiting'))).toThrow();
  });
  it('checks OAuth flows and scopes while leaving unsupported Lua predicates remote', () => {
    expect(() => validatePluginConfiguration('oauth2', {}, load('oauth2'))).toThrow();
    expect(() => validatePluginConfiguration('oauth2', { enable_client_credentials: true, mandatory_scope: true }, load('oauth2'))).toThrow();
    const schema = { fields: [{ condition: { type: 'string' } }, { extra: { type: 'string' } }], entity_checks: [{ conditional: { if_field: 'condition', if_match: { custom_validator: 'lua_function' }, then_field: 'extra', then_match: { required: true } } }] };
    expect(() => validatePluginConfiguration('custom-plugin', { condition: 'value' }, schema)).not.toThrow();
  });
});

describe('M2 plugin-center authorization, bounded cursor queries, index counts and selection', () => {
  let db: any, kong: any, authz: any, entities: any, service: PluginCenterService;
  beforeEach(() => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
    db = { one: vi.fn().mockImplementation(async (sql: string) => sql.includes('index_sync_state') ? { completed_at: 'observed', last_error: null } : { enabled_plugins: ['jwt', 'request-termination', 'pre-function', 'custom-plugin'], version: '1.5.1' }), query: vi.fn().mockResolvedValue([]) };
    kong = { request: vi.fn().mockImplementation(async (_cid, _method, path) => path.startsWith('/routes/') ? { id: 'r', service: { id: 's' } } : path.startsWith('/services/') ? { id: 's' } : { id: 'c' }), list: vi.fn().mockResolvedValue({ items: [], nextCursor: null, size: 20 }), pluginSchema: vi.fn() };
    authz = { isPlatformAdmin: vi.fn().mockImplementation(async (u:any)=>!!u.superAdmin), assertCluster: vi.fn().mockResolvedValue(undefined), assertEntity: vi.fn().mockResolvedValue(undefined), scopeTags: vi.fn().mockImplementation(async (_actor, _cid, _workspace, tags) => tags), permissionVersion: vi.fn().mockResolvedValue('perm-v1'), filterEntities: vi.fn().mockImplementation(async (_actor, _cid, _type, items) => items) };
    entities = { update: vi.fn().mockResolvedValue({ entity: { id: 'p', enabled: false } }) };
    service = new PluginCenterService(db, kong, authz, new SecretService(), entities, workspaceTestResolver(cid).resolver, executionFixture());
  });
  afterEach(() => vi.unstubAllEnvs());
  it('checks cluster permissions before querying any provider or index', async () => {
    authz.assertCluster.mockRejectedValue(new ForbiddenException());
    await expect(service.catalog(cid, {}, actor)).rejects.toMatchObject({ status: 403 });
    expect(db.one).not.toHaveBeenCalled();
    expect(kong.list).not.toHaveBeenCalled();
  });
  it('does not expose unrestricted counts from a stale cached superAdmin principal', async () => {
    authz.isPlatformAdmin.mockResolvedValue(false);
    const result = await service.catalog(cid, {}, actor);
    expect(result.items.every((item: any) => item.counts === null)).toBe(true);
    expect(db.query).not.toHaveBeenCalled();
  });
  it('rejects inventory statistics if permission epochs change before their response', async () => {
    authz.permissionVersion.mockResolvedValueOnce('before').mockResolvedValueOnce('after');
    await expect(service.catalog(cid, {}, actor)).rejects.toMatchObject({ status: 403, response: { code: 'PERMISSIONS_CHANGED' } });
  });
  it('returns sanitized wire and independently augmented form schemas', async () => {
    kong.pluginSchema.mockResolvedValue({ fields: [{ secret: { type: 'string', default: 'actual-worker-secret' } }] });
    const result = await service.schema(cid, 'session', actor);
    expect(result.remote_authoritative).toBe(true);
    expect(result.wire_schema.fields[0].secret).not.toHaveProperty('default');
    expect(JSON.stringify(result)).not.toContain('actual-worker-secret');
    expect(kong.pluginSchema).toHaveBeenCalledWith(cid, 'session');
  });
  it('reports completed index counts with all8 binding scopes and refuses unrestricted counts to restricted actors', async () => {
    db.query.mockResolvedValue([{ name: 'jwt', scope: 'consumer', total: 2, enabled: 1 }]);
    const result = await service.catalog(cid, { tags: 'team:pay' }, actor);
    expect(result.items.find((item: any) => item.name === 'jwt').counts).toMatchObject({ total: 2, enabled: 1, by_scope: { consumer: { total: 2, enabled: 1 }, global: { total: 0, enabled: 0 } } });
    expect(db.query.mock.calls[0][1]).toEqual([cid, ['kos-tag-dGVhbTpwYXk']]);
    db.query.mockClear();
    const restricted = await service.catalog(cid, {}, { user: { ...actor.user, superAdmin: false } });
    expect(restricted.items.every((item: any) => item.counts === null)).toBe(true);
    expect(db.query).not.toHaveBeenCalled();
  });
  it('does not turn an unfinished index into fabricated zero counts', async () => {
    db.one.mockImplementation(async (sql: string) => sql.includes('index_sync_state') ? { completed_at: null } : { enabled_plugins: ['jwt'] });
    const result = await service.catalog(cid, {}, actor);
    expect(result.items[0].counts).toBeNull();
    expect(result.observed_at).toBeNull();
    expect(db.query).not.toHaveBeenCalled();
  });
  it('binds cursor subjects to caller, permissions, filter and resolved parent IDs', async () => {
    kong.list.mockResolvedValue({ items: [{ id: 'p1', name: 'jwt', consumer: { id: 'c' }, config: { secret: 'sensitive' } }], nextCursor: 'next', size: 20 });
    const result = await service.instances(cid, { name: 'jwt', binding_scope: 'consumer', consumerId: 'alice', cursor: 'initial' }, actor);
    expect(kong.list).toHaveBeenCalledWith(cid, '/plugins', { size: 20 }, 'initial', expect.stringMatching(/^admin:perm-v1:plugins:/));
    expect(authz.assertEntity).toHaveBeenCalledWith(actor.user, cid, 'consumers', 'read', { id: 'c' }, DEFAULT_WORKSPACE_ID);
    expect(result.items[0].config.secret).toMatch(/^\[REDACTED:/);
    const oldSubject = kong.list.mock.calls[0][4];
    await service.instances(cid, { name: 'jwt', binding_scope: 'global', consumerId: 'alice' }, actor);
    expect(kong.list.mock.calls[1][4]).not.toBe(oldSubject);
  });
  it('stops low-selectivity searches at5pages and returns a continuation cursor', async () => {
    kong.list.mockResolvedValue({ items: [{ name: 'cors' }], nextCursor: 'next', size: 20 });
    const result = await service.instances(cid, { name: 'jwt' }, actor);
    expect(result.items).toEqual([]);
    expect(result.scan_budget_exhausted).toBe(true);
    expect(result.nextCursor).toBe('next');
    expect(kong.list).toHaveBeenCalledTimes(5);
  });
  it('selects an accurate default-workspace winner after a complete native scan with no outside applicable plugin', async () => {
    const plugins = [7, 5, 6, 3, 4, 1, 2, 0].map((mask, i) => ({ id: `p${i}`, name: 'request-termination', enabled: i !== 0, config: { status_code: 500 + i }, ...(mask & 4 ? { consumer: { id: 'c' } } : {}), ...(mask & 1 ? { route: { id: 'r' } } : {}), ...(mask & 2 ? { service: { id: 's' } } : {}) }));
    kong.list.mockResolvedValue({ items: [...plugins, { id: 'pre', name: 'pre-function', enabled: true }], nextCursor: null });
    const result = await service.context(cid, { routeId: 'r', consumerId: 'c' }, actor);
    expect(result.complete).toBe(true);
    expect(result.selected.find((plugin: any) => plugin.name === 'request-termination')).toMatchObject({ scope: 'consumer-route', entity: { id: 'p1' } });
    expect(result.execution_chain[0].name).toBe('pre-function');
    expect(result.candidates.filter((plugin: any) => plugin.name === 'request-termination').map((plugin: any) => plugin.scope)).toEqual(BINDING_SCOPES);
  });
  it('does not claim a winner when the scan or permission projection is incomplete', async () => {
    kong.list.mockResolvedValue({ items: [{ name: 'jwt', enabled: true }], nextCursor: 'more' });
    const result = await service.context(cid, {}, actor);
    expect(result.complete).toBe(false);
    expect(result.selected).toEqual([]);
    expect(kong.list).toHaveBeenCalledTimes(5);
  });
  it('rejects mismatched Route/Service context rather than deriving a fictitious combination', async () => {
    kong.request.mockImplementation(async (_cid, _method, path) => path.startsWith('/services/') ? { id: 'wrong' } : { id: 'r', service: { id: 's' } });
    await expect(service.context(cid, { routeId: 'r', serviceId: 'wrong' }, actor)).rejects.toMatchObject({ status: 400, response: { code: 'ROUTE_SERVICE_MISMATCH' } });
    expect(kong.list).not.toHaveBeenCalled();
  });
  it('delegates toggles to the audited mutation path and rejects unknown query fields', async () => {
    await service.toggle(cid, 'p', { enabled: false }, actor);
    expect(entities.update).toHaveBeenCalledWith(cid, 'plugins', 'p', { enabled: false }, { workspaceId: DEFAULT_WORKSPACE_ID }, { ...actor, workspaceId: DEFAULT_WORKSPACE_ID });
    await expect(service.toggle(cid, 'p', { enabled: true, name: 'cors' }, actor)).rejects.toMatchObject({ status: 400 });
    await expect(service.instances(cid, { unsupported: 'x' } as any, actor)).rejects.toMatchObject({ status: 400 });
  });
});
