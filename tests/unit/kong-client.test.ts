import { nativeTransportContext, scopedNativeTransport } from './kong-native-test-fixture';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { assertKongPath } from '../../apps/console-api/src/infrastructure/kong/policy';
import { validateKnownFields } from '../../apps/console-api/src/infrastructure/kong/schema';
import { decodeTag, encodeTag, workspaceTag } from '../../apps/console-api/src/infrastructure/kong/tags';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { ForbiddenException, Logger } from '@nestjs/common';

// Keep the destination policy hermetic: fake-IP resolvers (198.18.0.0/15)
// would otherwise classify the documentation host as a reserved address.
vi.mock('node:dns/promises', async importOriginal => {
  const actual: any = await importOriginal();
  const lookup = async (host: string, options?: any) => host === 'example.com' ? (options?.all ? [{ address: '93.184.215.14', family: 4 }] : { address: '93.184.215.14', family: 4 }) : actual.lookup(host, options);
  // The destination policy prefers c-ares; answer the documentation host and let
  // every other name fall back (definitive NXDOMAIN) to the lookup above.
  class Resolver { async resolve4(host: string) { if (host === 'example.com') return ['93.184.215.14']; throw Object.assign(new Error('nf'), { code: 'ENOTFOUND' }); } async resolve6(): Promise<string[]> { throw Object.assign(new Error('nf'), { code: 'ENODATA' }); } }
  return { ...actual, lookup, Resolver, default: { ...actual, lookup, Resolver } };
});
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn() }));
const transport = vi.mocked(outboundJson);
const clusterId = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const otherCluster = 'a3ea3b8c-aa2b-48ae-9d7a-d8e8123b978b';

describe('Kong 1.5 allowlist and physical tags', () => {
  it.each(['/clustering', '/vaults', '/keys', '/key-sets', '/event-hooks', '/schemas/plugins/cors', '/services/../keys', '/services/%2e%2e', '/services/%', '//services', '/services/a%2fb', '/plugins/schema/cors?secret=x'])('rejects forbidden or ambiguous path %s', path => {
    expect(() => assertKongPath('GET', path)).toThrow();
  });
  it('allows the legacy plugin schema and private metrics exception while enforcing the strict user endpoint allowlist', () => {
    expect(() => assertKongPath('GET', '/plugins/schema/cors')).not.toThrow();
    expect(() => assertKongPath('GET', '/endpoints')).toThrow();
    for (const path of ['/key-auths', '/basic-auths', '/jwts', '/oauth2', '/hmac-auths', '/acls']) {
      expect(() => assertKongPath('GET', path)).not.toThrow();
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) expect(() => assertKongPath(method, path)).toThrow();
      expect(() => assertKongPath('GET', `${path}/00000000-0000-4000-8000-000000000001`)).toThrow();
    }
    expect(() => assertKongPath('GET', '/metrics')).toThrow();
    expect(() => assertKongPath('GET', '/metrics', true)).not.toThrow();
    expect(() => assertKongPath('DELETE', '/status')).toThrow();
  });
  it('encodes workspace and business tags without forbidden colon or collisions', () => {
    expect(workspaceTag('pay')).toBe('kos-ws-pay');
    for (const tag of ['team:pay', '负责人:张三', 'kos-tag-special', 'workspace:pay', 'safe-tag']) {
      expect(encodeTag(tag)).toMatch(/^[A-Za-z0-9._~-]+$/);
      expect(decodeTag(encodeTag(tag))).toBe(tag);
    }
    expect(() => workspaceTag('bad:code')).toThrow();
  });
  it('rejects unsupported nested fields in arrays, sets and foreign references', () => {
    const schema = { fields: [{ sources: { type: 'set', elements: { type: 'record', fields: [{ ip: { type: 'string' } }, { port: { type: 'integer' } }] } } }, { service: { type: 'foreign' } }] };
    expect(() => validateKnownFields({ sources: [{ ip: '10.0.0.1', expression: true }] }, schema)).toThrow();
    expect(() => validateKnownFields({ service: { id: 'id', workspace: 'hidden' } }, schema)).toThrow();
    expect(() => validateKnownFields({ sources: [{ ip: '10.0.0.1', port: 8000 }], service: { id: 'id' } }, schema)).not.toThrow();
  });
});

describe('M0 Kong client reliability, version gating and scoped pagination', () => {
  let db: any;
  let redis: any;
  let audit: any;
  let kong: KongService;
  let cluster: any;
  let context: ReturnType<typeof nativeTransportContext>;
  beforeEach(() => {
    vi.stubEnv('APP_SECRET', 'unit-cursor-signature-key-at-least-32-characters');
    vi.stubEnv('KONG_RATE_WAIT_MS', '0');
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
    cluster = { id: clusterId, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct', connection_secret: null, capabilities: {}, status: 'healthy', revision: 1 };
    db = { query: vi.fn().mockResolvedValue([]), one: vi.fn().mockImplementation(async () => cluster), exec: vi.fn().mockResolvedValue(1), transaction: vi.fn() };
    db.transaction.mockImplementation((fn: any) => fn(db));
    redis = { assertLeaseOwnership: vi.fn().mockResolvedValue(undefined), assertLeaseActive: vi.fn(), rateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 119, retryAfterMs: 0 }), withLock: vi.fn().mockImplementation((_key: string, fn: any) => fn()) };
    audit = { append: vi.fn().mockResolvedValue(undefined) };
    context = nativeTransportContext();
    kong = scopedNativeTransport(new KongService(db, redis, { redact: (v: unknown) => v, redactError: (v: unknown) => v, decrypt: () => ({ type: 'none' }) } as any, audit, context), context, clusterId);
    transport.mockReset();
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

  it.each(['10.80.1.30', '2001:db8::10', '[2001:db8::10]'])('checks literal destination %s without a 1.5-invalid Upstream lookup', async host => {
    transport.mockImplementation(async (_base, path, method, body) => {
      if (path.startsWith('/upstreams/')) return { status: 400, body: { code: 10, name: 'invalid unique name' } };
      if (path === '/schemas/services') return { status: 200, body: { fields: [{ host: { type: 'string' } }, { port: { type: 'integer' } }] } };
      return { status: 201, body: { id: 'service', ...(body as any) } };
    });
    await expect(kong.request(clusterId, 'POST', '/services', { host, port: 8080 })).resolves.toMatchObject({ host });
    expect(transport.mock.calls.some(call => call[1].startsWith('/upstreams/'))).toBe(false);
    expect(transport.mock.calls.filter(call => call[2] === 'POST')).toHaveLength(1);
  });
  it('still blocks a literal loopback Admin destination before any native write', async () => {
    transport.mockImplementation(async (_base, path) => path.startsWith('/upstreams/')
      ? { status: 400, body: { code: 10, name: 'invalid unique name' } }
      : { status: 200, body: { fields: [{ host: { type: 'string' } }, { port: { type: 'integer' } }] } });
    await expect(kong.request(clusterId, 'POST', '/services', { host: '127.0.0.1', port: 8001 })).rejects.toMatchObject({ status: 403, response: { code: 'PROTECTED_PROXY_DESTINATION' } });
    expect(transport.mock.calls.some(call => call[1].startsWith('/upstreams/') || call[2] !== 'GET')).toBe(false);
  });

  it('retries GET 503 but never sends a forbidden path', async () => {
    transport.mockResolvedValueOnce({ status: 503, body: {} }).mockResolvedValueOnce({ status: 200, body: { database: { reachable: true } } });
    await expect(kong.request(clusterId, 'GET', '/status')).resolves.toMatchObject({ database: { reachable: true } });
    expect(transport).toHaveBeenCalledTimes(2);
    await expect(kong.request(clusterId, 'GET', '/vaults')).rejects.toMatchObject({ status: 403 });
    expect(transport).toHaveBeenCalledTimes(2);
  });
  it('does not retry GET connection errors or validation errors', async () => {
    transport.mockRejectedValueOnce(Object.assign(new Error('connection refused'), { code: 'ECONNREFUSED' }));
    await expect(kong.request(clusterId, 'GET', '/status')).rejects.toMatchObject({ status: 503 });
    expect(transport).toHaveBeenCalledTimes(1);
    transport.mockResolvedValueOnce({ status: 400, body: { message: 'schema violation', fields: { host: 'required', healthchecks: { active: { timeout: 'must be positive' } } } } });
    await expect(kong.request(clusterId, 'GET', '/services')).rejects.toMatchObject({ status: 400, response: { fields: { host: 'required', 'healthchecks.active.timeout': 'must be positive' } } });
    expect(transport).toHaveBeenCalledTimes(2);
  });
  it('never retries a write and serializes writes by physical registered endpoint', async () => {
    transport.mockImplementation(async (_base, path, method) => path === '/schemas/services' ? { status: 200, body: { fields: [{ host: { type: 'string' } }] } } : method === 'GET' ? { status: 404, body: {} } : { status: 503, body: {} });
    await expect(kong.request(clusterId, 'POST', '/services', { host: 'example.com' })).rejects.toMatchObject({ status: 503 });
    expect(transport.mock.calls.filter(call => call[2] === 'POST')).toHaveLength(1);
    expect(redis.withLock).toHaveBeenCalledWith(`kong:${transportScopeFor(cluster.admin_url)}:write`, expect.any(Function));
  });
  it('blocks incompatible versions and approval mode before any upstream mutation', async () => {
    cluster.version = '3.9.0';
    await expect(kong.request(clusterId, 'POST', '/services', { host: 'example.com' })).rejects.toMatchObject({ status: 409, response: { code: 'KONG_VERSION_INCOMPATIBLE' } });
    cluster.version = '1.5.1'; cluster.execution_mode = 'approval';
    await expect(kong.request(clusterId, 'DELETE', '/services/object')).rejects.toMatchObject({ status: 409, response: { code: 'APPROVAL_REQUIRED' } });
    expect(transport).not.toHaveBeenCalled();
  });
  it('rejects unknown Service fields before a Kong write', async () => {
    transport.mockResolvedValue({ status: 200, body: { fields: [{ host: { type: 'string' } }, { name: { type: 'string' } }] } });
    await expect(kong.request(clusterId, 'POST', '/services', { host: 'example.com', tls_verify: true })).rejects.toMatchObject({ status: 400, response: { code: 'KONG_UNKNOWN_FIELD' } });
    expect(transport.mock.calls.map(call => call[1])).toEqual(['/schemas/services']);
  });
  it('dynamically validates plugin config with the old schema path', async () => {
    transport.mockImplementation(async (_base, path) => ({ status: 200, body: path === '/schemas/plugins' ? { fields: [{ name: { type: 'string' } }, { config: { type: 'record' } }] } : { fields: { key_names: { type: 'array', elements: { type: 'string' } } } } }));
    await expect(kong.request(clusterId, 'POST', '/plugins', { name: 'key-auth', config: { nonexistent: true } })).rejects.toMatchObject({ status: 400 });
    expect(transport.mock.calls.map(call => call[1])).toEqual(['/schemas/plugins', '/plugins/schema/key-auth']);
  });
  it('scrubs credentials echoed inside unlabelled Kong validation messages', async () => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
    context = nativeTransportContext();
    kong = scopedNativeTransport(new KongService(db, redis, new SecretService(), audit, context), context, clusterId);
    transport.mockResolvedValueOnce({ status: 200, body: { fields: [{ username: { type: 'string' } }, { password: { type: 'string' } }] } }).mockResolvedValueOnce({ status: 400, body: { message: 'schema violation: rejected sensitive-password-value', fields: { other: 'bad sensitive-password-value' } } });
    let response: any;
    try { await kong.request(clusterId, 'POST', '/consumers/consumer/basic-auth', { username: 'alice', password: 'sensitive-password-value' }); }
    catch (error: any) { response = error.getResponse(); }
    expect(response.code).toBe('KONG_VALIDATION_ERROR');
    expect(JSON.stringify(response)).not.toContain('sensitive-password-value');
    expect(response.message).toContain('[REDACTED]');
  });
  it('rejects arbitrary Kong query parameters and never follows next URLs', async () => {
    transport.mockResolvedValueOnce({ status: 200, body: { data: [{ id: 'one' }], next: 'http://untrusted.example/services?offset=opaque-offset&size=20' } });
    const first = await kong.list(clusterId, '/services', { tags: 'kos-ws-pay' }, undefined, 'user:permissions-v1');
    expect(first.nextCursor).toBeTruthy();
    transport.mockResolvedValueOnce({ status: 200, body: { data: [{ id: 'two' }], next: null } });
    const second = await kong.list(clusterId, '/services', { tags: 'kos-ws-pay' }, first.nextCursor!, 'user:permissions-v1');
    expect(second.items[0].id).toBe('two');
    expect(transport.mock.calls[1][0]).toBe('http://kong:8001');
    expect(transport.mock.calls[1][4]).toMatchObject({ offset: 'opaque-offset', size: 20 });
    await expect(kong.list(clusterId, '/services', { sort: 'name' })).rejects.toMatchObject({ status: 400 });
  });
  it('binds signed cursors to cluster, entity, filter and caller', async () => {
    transport.mockResolvedValue({ status: 200, body: { data: [], next: '/services?offset=opaque-offset' } });
    const first = await kong.list(clusterId, '/services', { tags: 'tag-a' }, undefined, 'alice');
    await expect(kong.list(otherCluster, '/services', { tags: 'tag-a' }, first.nextCursor!, 'alice')).rejects.toMatchObject({ status: 400 });
    await expect(kong.list(clusterId, '/routes', { tags: 'tag-a' }, first.nextCursor!, 'alice')).rejects.toMatchObject({ status: 400 });
    await expect(kong.list(clusterId, '/services', { tags: 'tag-b' }, first.nextCursor!, 'alice')).rejects.toMatchObject({ status: 400 });
    await expect(kong.list(clusterId, '/services', { tags: 'tag-a' }, first.nextCursor!, 'bob')).rejects.toMatchObject({ status: 400 });
    await expect(kong.list(clusterId, '/services', { tags: 'tag-a' }, `${first.nextCursor!.slice(0, -4)}aaaa`, 'alice')).rejects.toMatchObject({ status: 400 });
    expect(transport).toHaveBeenCalledTimes(1);
  });
  it('does not read the entire dataset and rejects malformed pagination paths', async () => {
    transport.mockResolvedValue({ status: 200, body: { data: [], next: '/keys?offset=evil' } });
    await expect(kong.list(clusterId, '/services')).rejects.toMatchObject({ status: 502 });
    expect(transport).toHaveBeenCalledTimes(1);
  });
  it('enforces Redis rate limiting before upstream calls', async () => {
    redis.rateLimit.mockResolvedValue({ allowed: false, remaining: 0, retryAfterMs: 100 });
    await expect(kong.request(clusterId, 'GET', '/status')).rejects.toMatchObject({ status: 429 });
    expect(transport).not.toHaveBeenCalled();
  });
  it('may wait for a rate slot before transport while still sending a write only once', async () => {
    vi.stubEnv('KONG_RATE_WAIT_MS', '40');
    redis.rateLimit.mockResolvedValueOnce({ allowed: false, remaining: 0, retryAfterMs: 10 }).mockResolvedValue({ allowed: true, remaining: 1, retryAfterMs: 0 });
    transport.mockResolvedValue({ status: 200, body: {} });
    await kong.request(clusterId, 'DELETE', '/services/s1');
    expect(redis.rateLimit).toHaveBeenCalledTimes(2);
    expect(transport).toHaveBeenCalledTimes(1);
    expect(transport.mock.calls[0][2]).toBe('DELETE');
  });
  it('returns429 when the local rate-wait budget expires without sending a mutation', async () => {
    vi.useFakeTimers();
    vi.stubEnv('KONG_RATE_WAIT_MS', '20');
    redis.rateLimit.mockResolvedValue({ allowed: false, remaining: 0, retryAfterMs: 1000 });
    const denied = expect(kong.request(clusterId, 'DELETE', '/services/s1')).rejects.toMatchObject({ status: 429, response: { code: 'KONG_RATE_LIMITED' } });
    await vi.advanceTimersByTimeAsync(20);
    await denied;
    expect(redis.rateLimit).toHaveBeenCalledTimes(1);
    expect(transport).not.toHaveBeenCalled();
  });
  it('opens the per-cluster circuit after repeated connection failures', async () => {
    transport.mockRejectedValue(Object.assign(new Error('unavailable'), { code: 'ECONNREFUSED' }));
    for (let i = 0; i < 5; i++) await expect(kong.request(clusterId, 'GET', '/status')).rejects.toMatchObject({ status: 503 });
    await expect(kong.request(clusterId, 'GET', '/status')).rejects.toMatchObject({ response: { code: 'KONG_CIRCUIT_OPEN' } });
    expect(transport).toHaveBeenCalledTimes(5);
  });
  it('probes and persists version, legacy schema capabilities, plugin list and append-only audit', async () => {
    transport.mockImplementation(async (_base, path) => ({ status: 200, body: path === '/' ? { version: '1.5.1' } : path === '/plugins/enabled' ? { enabled_plugins: ['key-auth', 'cors'] } : path.startsWith('/schemas/') ? { fields: [{ id: { type: 'string' } }] } : {} }));
    const result = await kong.probe(clusterId, { id: 'actor' });
    expect(result.status).toBe('healthy');
    expect(result.capabilities.plugins_schema_path).toBe('/plugins/schema/{name}');
    expect(result.capabilities.native_workspaces).toBe(false);
    expect(result.capabilities).toMatchObject({ endpoint_discovery: false, endpoint_discovery_source: 'unavailable', endpoints: null, derived_capability_source: 'fixed-allowlist-and-schemas' });
    expect(result.capabilities.derived_endpoints).toContain('/services');
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ actorId: 'actor', action: 'probe', clusterId }), db);
    expect(db.exec).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO cluster_probes'), expect.any(Array));
    expect(transport.mock.calls[0][1]).toBe('/');
    expect(transport.mock.calls.some(call => call[1] === '/plugins/enabled')).toBe(true);
    expect(transport.mock.calls.some(call => call[1] === '/endpoints')).toBe(false);
  });
  it('uses only the actual root endpoints field when supplied without a separate discovery request', async () => {
    const endpoints = ['/services', '/plugins/schema/:name'];
    transport.mockImplementation(async (_base, path) => ({ status: 200, body: path === '/' ? { version: '1.5.1', endpoints } : path === '/plugins/enabled' ? { enabled_plugins: [] } : path.startsWith('/schemas/') ? { fields: [] } : {} }));
    const result = await kong.probe(clusterId);
    expect(result.capabilities).toMatchObject({ endpoints, endpoint_discovery: true, endpoint_discovery_source: 'root' });
    expect(transport.mock.calls.some(call => call[1] === '/endpoints')).toBe(false);
  });
  it('warns about a newer version without requesting its entity schemas', async () => {
    transport.mockImplementation(async (_base, path) => ({ status: 200, body: path === '/' ? { version: '3.9.0' } : path === '/plugins/enabled' ? { enabled_plugins: ['key-auth'] } : {} }));
    const result = await kong.probe(clusterId);
    expect(result.status).toBe('incompatible');
    expect(result.capabilities.write_enabled).toBe(false);
    expect(result.capabilities.warnings).toHaveLength(1);
    expect(transport.mock.calls.some(call => call[1].startsWith('/schemas/'))).toBe(false);
  });
  it('keeps the policy and wire JSON identical when the caller mutates its own input during authorization', async () => {
    let release!: () => void, began!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const entered = new Promise<void>(resolve => { began = resolve; });
    const seen: any[] = [];
    context = nativeTransportContext({ authorizeRequest: async (_frame, _cluster, method, _path, body) => {
      if (method === 'POST') { seen.push(body); began(); await gate; }
      return { platformAdmin: true };
    }, authorizeResponse: async (_ticket, result) => result });
    kong = scopedNativeTransport(new KongService(db, redis, new SecretService(), audit, context), context, clusterId);
    transport.mockImplementation(async (_base, path, method, body) => path === '/schemas/consumers' ? { status: 200, body: { fields: [{ username: { type: 'string' } }, { tags: { type: 'array', elements: { type: 'string' } } }] } } : { status: 200, body: { id: 'c1', ...(body as any) } });
    const body = { username: 'original', tags: ['original-tag'] };
    const submitted = kong.request(clusterId, 'POST', '/consumers', body);
    await entered; body.username = 'changed'; body.tags.push('changed-tag'); release();
    await expect(submitted).resolves.toMatchObject({ username: 'original', tags: ['original-tag'] });
    expect(seen.every(value => Object.isFrozen(value) && Object.isFrozen(value.tags))).toBe(true);
    expect(transport.mock.calls.find(call => call[2] === 'POST')?.[3]).toEqual({ username: 'original', tags: ['original-tag'] });
  });
  it('rechecks schema-cache permissions without contacting Kong after a role is revoked', async () => {
    let granted = true;
    context = nativeTransportContext({ authorizeRequest: async () => { if (!granted) throw new ForbiddenException(); return {}; }, authorizeResponse: async (_ticket, result) => result });
    kong = scopedNativeTransport(new KongService(db, redis, new SecretService(), audit, context), context, clusterId);
    transport.mockResolvedValue({ status: 200, body: { fields: [] } });
    await kong.schema(clusterId, 'consumers'); granted = false;
    await expect(kong.schema(clusterId, 'consumers')).rejects.toMatchObject({ status: 403 });
    expect(transport).toHaveBeenCalledTimes(1);
  });
  it('stops before native POST when authorization is revoked during schema validation', async () => {
    let revoked = false;
    context = nativeTransportContext({ authorizeRequest: async (_frame, _cluster, method) => {
      if (method === 'POST' && revoked) throw new ForbiddenException({ code: 'REVOKED_AT_FINAL_GUARD' });
      return { platformAdmin: true };
    }, authorizeResponse: async (_ticket, result) => result });
    kong = scopedNativeTransport(new KongService(db, redis, new SecretService(), audit, context), context, clusterId);
    transport.mockImplementation(async () => { revoked = true; return { status: 200, body: { fields: [{ username: { type: 'string' } }] } }; });
    await expect(kong.request(clusterId, 'POST', '/consumers', { username: 'alice' })).rejects.toMatchObject({ status: 403, response: { code: 'REVOKED_AT_FINAL_GUARD' } });
    expect(transport.mock.calls.every(call => call[2] === 'GET')).toBe(true);
  });
  it('rejects Lua if the fresh send-time policy no longer grants platform privilege', async () => {
    let revoked = false;
    context = nativeTransportContext({ authorizeRequest: async () => ({ platformAdmin: !revoked }), authorizeResponse: async (_ticket, result) => result });
    kong = scopedNativeTransport(new KongService(db, redis, new SecretService(), audit, context), context, clusterId);
    transport.mockImplementation(async (_base, path) => {
      if (path === '/schemas/plugins') return { status: 200, body: { fields: [{ name: { type: 'string' } }, { config: { type: 'record' } }] } };
      revoked = true; return { status: 200, body: { fields: { functions: { type: 'array', elements: { type: 'string' } } } } };
    });
    await expect(kong.request(clusterId, 'POST', '/plugins', { name: 'pre-function', config: { functions: ['return'] } })).rejects.toMatchObject({ status: 403, response: { code: 'PLUGIN_PLATFORM_EXECUTION_REQUIRED' } });
    expect(transport.mock.calls.every(call => call[2] === 'GET')).toBe(true);
  });
  it('reports uncertain after a successful write whose response authorization is revoked', async () => {
    const diagnostic = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    context = nativeTransportContext({ authorizeRequest: async () => ({}), authorizeResponse: async (_ticket, result) => { if (result?.id) throw new ForbiddenException({code:'PERMISSIONS_CHANGED',message:'private-response-marker'}); return result; } });
    kong = scopedNativeTransport(new KongService(db, redis, new SecretService(), audit, context), context, clusterId);
    transport.mockImplementation(async (_base, path) => path === '/schemas/consumers' ? { status: 200, body: { fields: [{ username: { type: 'string' } }] } } : { status: 201, body: { id: 'c1' } });
    await expect(kong.request(clusterId, 'POST', '/consumers', { username: 'alice' })).rejects.toMatchObject({ status: 503, response: { code: 'KONG_WRITE_AUTHORIZATION_CHANGED' } });
    expect(transport.mock.calls.filter(call => call[2] === 'POST')).toHaveLength(1);
    expect(diagnostic).toHaveBeenCalledWith(expect.objectContaining({event:'kong_write_response_authorization_failed',stage:'sdk-response',code:'PERMISSIONS_CHANGED',retryAllowed:false}));
    expect(JSON.stringify(diagnostic.mock.calls)).not.toContain('private-response-marker');
  });
  it('retains unknown result and a single send even when the diagnostic logger fails', async () => {
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => { throw Error('broken sink'); });
    context = nativeTransportContext({ authorizeRequest: async () => ({}), authorizeResponse: async (_ticket, result) => { if (result?.id) throw new ForbiddenException(); return result; } });
    kong = scopedNativeTransport(new KongService(db, redis, new SecretService(), audit, context), context, clusterId);
    transport.mockImplementation(async (_base, path) => path === '/schemas/consumers' ? { status: 200, body: { fields: [{ username: { type: 'string' } }] } } : { status: 201, body: { id: 'c1' } });
    await expect(kong.request(clusterId, 'POST', '/consumers', { username: 'alice' })).rejects.toMatchObject({status:503,response:{code:'KONG_WRITE_AUTHORIZATION_CHANGED'}});
    expect(transport.mock.calls.filter(call => call[2] === 'POST')).toHaveLength(1);
  });
  it('shares the transport rate key and circuit across aliases to the same Admin endpoint', async () => {
    db.one.mockImplementation(async (_sql: string, params: string[]) => ({ ...cluster, id: params[0], admin_url: params[0] === otherCluster ? 'http://KONG:8001/' : 'http://kong:8001' }));
    transport.mockRejectedValue(Object.assign(new Error('unavailable'), { code: 'ECONNREFUSED' }));
    for (let index = 0; index < 5; index++) await expect(kong.request(clusterId, 'GET', '/status')).rejects.toMatchObject({ status: 503 });
    await expect(kong.request(otherCluster, 'GET', '/status')).rejects.toMatchObject({ response: { code: 'KONG_CIRCUIT_OPEN' } });
    expect(new Set(redis.rateLimit.mock.calls.map((call: any[]) => call[0])).size).toBe(1);
    expect(transport).toHaveBeenCalledTimes(5);
  });
  it('stops a direct write if the cluster switches to approval mode during schema validation', async () => {
    // Production DbService returns independent row snapshots per query.
    db.one.mockImplementation(async () => ({ ...cluster }));
    transport.mockImplementation(async () => { cluster.execution_mode = 'approval'; return { status: 200, body: { fields: [{ username: { type: 'string' } }] } }; });
    await expect(kong.request(clusterId, 'POST', '/consumers', { username: 'alice' })).rejects.toMatchObject({ status: 409, response: { code: 'APPROVAL_REQUIRED' } });
    expect(transport.mock.calls.every(call => call[2] === 'GET')).toBe(true);
  });
  it('separates pure capability inspection from atomic SQL/audit persistence', async () => {
    transport.mockImplementation(async (_base, path) => ({ status: 200, body: path === '/' ? { version: '1.5.1' } : path === '/plugins/enabled' ? { enabled_plugins: ['cors'] } : path.startsWith('/schemas/') ? { fields: [] } : {} }));
    const inspection = await kong.inspectProbe(clusterId);
    expect(inspection.status).toBe('healthy'); expect(Object.isFrozen(inspection.capabilities)).toBe(true);
    expect(db.exec).not.toHaveBeenCalled(); expect(audit.append).not.toHaveBeenCalled();
    const calls = transport.mock.calls.length;
    await kong.persistProbe(clusterId, inspection, { id: 'trusted-actor' }, db);
    expect(transport).toHaveBeenCalledTimes(calls);
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ actorId: 'trusted-actor', action: 'probe' }), db);
    db.exec.mockClear();
    await expect(kong.persistProbe(clusterId, structuredClone(inspection), {}, db)).rejects.toMatchObject({ status: 400, response: { code: 'PROBE_INSPECTION_REQUIRED' } });
    expect(db.exec).not.toHaveBeenCalled();
  });
  it('rejects probe registry conflicts without writing a misleading outage or audit', async () => {
    transport.mockImplementation(async (_base, path) => ({ status: 200, body: path === '/' ? { version: '1.5.1' } : path === '/plugins/enabled' ? { enabled_plugins: [] } : path.startsWith('/schemas/') ? { fields: [] } : {} }));
    const inspection = await kong.inspectProbe(clusterId); db.exec.mockResolvedValue(0);
    await expect(kong.persistProbe(clusterId, inspection, {}, db)).rejects.toMatchObject({ status: 409, response: { code: 'PROBE_CONFIG_CHANGED' } });
    expect(db.exec).toHaveBeenCalledTimes(1); expect(audit.append).not.toHaveBeenCalled();
  });
  it('does not convert authorization failures into persisted unhealthy probe records', async () => {
    context = nativeTransportContext({ authorizeRequest: async () => { throw new ForbiddenException(); }, authorizeResponse: async (_ticket, result) => result });
    kong = scopedNativeTransport(new KongService(db, redis, new SecretService(), audit, context), context, clusterId);
    await expect(kong.inspectProbe(clusterId)).rejects.toMatchObject({ status: 403 });
    expect(transport).not.toHaveBeenCalled(); expect(db.exec).not.toHaveBeenCalled(); expect(audit.append).not.toHaveBeenCalled();
  });
});
