import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { nativeTransportContext } from './kong-native-test-fixture';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn() }));
const transport = vi.mocked(outboundJson);
const cid = 'ed4b6a43-b3b8-4723-af70-d4edf3e24de2';
const wid = 'a1e5fc07-f10d-45ba-b075-271e4be63502';
const actor = { id: 'e0fd3de3-3072-4931-8216-987e01639bcb', username: 'planner', superAdmin: true };

describe('M11 schema preparation, synthetic transport only', () => {
  let cluster: any, db: any, redis: any, audit: any, secrets: SecretService, context: ReturnType<typeof nativeTransportContext>, kong: KongService;
  const scoped = <T>(fn: () => Promise<T>, workspaceId: string | null = wid) => context.runHttp({ requestId: 'schema-planning-unit' }, async () => {
    context.bindHttpActor(actor, 'synthetic-planning-session');
    return context.runActor({ actor, clusterId: cid, workspaceId: workspaceId ?? undefined, module: 'entities', action: 'write' }, fn);
  });
  beforeEach(() => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
    vi.stubEnv('APP_SECRET', 'synthetic-planning-session-secret-at-least-32-characters');
    vi.stubEnv('KONG_RATE_WAIT_MS', '0');
    cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'approval', connection_secret: null, capabilities: {}, status: 'healthy', revision: 1 };
    db = { one: vi.fn(async () => structuredClone(cluster)), query: vi.fn(async () => []), exec: vi.fn() };
    redis = { rateLimit: vi.fn(async () => ({ allowed: true })), withLock: vi.fn(), assertLeaseOwnership: vi.fn(), assertLeaseActive: vi.fn() };
    audit = { append: vi.fn() }; secrets = new SecretService(); context = nativeTransportContext();
    kong = new KongService(db, redis, secrets, audit, context);
    transport.mockReset();
  });
  afterEach(() => vi.unstubAllEnvs());

  it('prepares approval-mode changes using GET only, preserving immutable exact schema/body evidence without a mutation or audit', async () => {
    const schema = { fields: [{ name: { type: 'string' } }, { host: { type: 'string' } }] };
    const body = { name: 'payments', host: 'example.org' };
    transport.mockImplementation(async (_base, path, method) => {
      expect(method).toBe('GET'); expect(path).toBe('/schemas/services');
      body.host = 'changed-by-caller.example.org'; return { status: 200, body: schema };
    });
    const material = await scoped(() => kong.prepareSchema(cid, '/services', body));
    expect(material).toMatchObject({ version: 1, kongVersion: '1.5.1', adapter: 'kong-oss-1.5-v1', clusterRevision: 1,
      schemaMaterial: { entity: { name: 'services', canonicalPath: '/schemas/services', schema } },
      payloadHmac: secrets.fingerprint({ name: 'payments', host: 'example.org' }) });
    expect(Object.isFrozen(material.schemaMaterial.entity.schema)).toBe(true);
    expect(db.exec).not.toHaveBeenCalled(); expect(audit.append).not.toHaveBeenCalled(); expect(redis.withLock).not.toHaveBeenCalled();
    expect(transport.mock.calls.every(call => call[2] === 'GET')).toBe(true);
  });

  it('uses the legacy plugin schema for defaults as well as explicit config and rejects unknown config without a write', async () => {
    transport.mockImplementation(async (_base, path, method) => {
      expect(method).toBe('GET');
      return { status: 200, body: path === '/schemas/plugins'
        ? { fields: [{ name: { type: 'string' } }, { config: { type: 'record' } }] }
        : { fields: { key_names: { type: 'array', elements: { type: 'string' } } } } };
    });
    const material = await scoped(() => kong.prepareSchema(cid, '/plugins', { name: 'key-auth' }));
    expect(material.schemaMaterial.plugin?.canonicalPath).toBe('/plugins/schema/key-auth');
    await expect(scoped(() => kong.prepareSchema(cid, '/plugins', { name: 'key-auth', config: { unknown_2x_field: true } })))
      .rejects.toMatchObject({ status: 400, response: { code: 'KONG_UNKNOWN_FIELD' } });
    expect(transport.mock.calls.map(call => call[1])).toEqual(['/schemas/plugins', '/plugins/schema/key-auth']);
    expect(transport.mock.calls.every(call => call[2] === 'GET')).toBe(true);
  });

  it('prepares a credential DAO and node-local health action without sending either operation', async () => {
    transport.mockImplementation(async (_base, path, method) => {
      expect(method).toBe('GET');
      return { status: 200, body: { fields: path === '/schemas/basicauth_credentials'
        ? [{ username: { type: 'string' } }, { password: { type: 'string' } }] : [{ target: { type: 'string' } }] } };
    });
    const material = await scoped(() => kong.prepareSchema(cid, '/consumers/consumer-id/basic-auth', { username: 'client', password: 'SyntheticCredentialPassword' }));
    expect(material.schemaMaterial.entity.canonicalPath).toBe('/schemas/basicauth_credentials');
    const health = await scoped(() => kong.prepareSchema(cid, '/upstreams/upstream-id/targets/target-id/healthy', undefined));
    expect(health.nativeType).toBe('targets'); expect(health.payloadHmac).toBe(secrets.fingerprint(null));
    await expect(scoped(() => kong.prepareSchema(cid, '/upstreams/upstream-id/targets/target-id/healthy', { weight: 50 }))).rejects.toMatchObject({ status: 400 });
    expect(transport.mock.calls.map(call => call[1])).toEqual(['/schemas/basicauth_credentials', '/schemas/targets']);
  });

  it('refuses missing scope, unsupported versions and cluster changes before returning planning evidence', async () => {
    await expect(scoped(() => kong.prepareSchema(cid, '/services', {}), null)).rejects.toMatchObject({ status: 403 });
    cluster.version = '2.8.0';
    await expect(scoped(() => kong.prepareSchema(cid, '/services', {}))).rejects.toMatchObject({ status: 409 });
    expect(transport).not.toHaveBeenCalled(); cluster.version = '1.5.1';
    transport.mockImplementation(async () => { cluster.revision++; return { status: 200, body: { fields: [] } }; });
    await expect(scoped(() => kong.prepareSchema(cid, '/services', {}))).rejects.toMatchObject({ status: 409, response: { code: 'KONG_SCHEMA_PREPARATION_CHANGED' } });
    expect(transport.mock.calls.every(call => call[2] === 'GET')).toBe(true);
  });
});
