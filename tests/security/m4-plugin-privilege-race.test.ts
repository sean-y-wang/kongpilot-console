import 'reflect-metadata';
import { afterEach, describe, expect, it, vi } from 'vitest';

const transport = vi.hoisted(() => ({ outbound: vi.fn(), lookup: vi.fn(), http: vi.fn() }));
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: transport.outbound }));
vi.mock('node:dns/promises', () => ({ lookup: transport.lookup }));
vi.mock('node:http', () => ({ request: transport.http }));

import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

const cid = '00efafc8-6184-480c-87ba-0e57c67a2e9d';
const wid = '99c652ed-1789-45b6-9c5f-0a6d3a001f52';
const pid = 'b0999a67-42f3-4e12-bdfa-dc83017b80f1';

describe('M4 independent platform-only plugin revocation during transport preparation', () => {
  afterEach(() => vi.unstubAllEnvs());

  it.each([
    { plugin: 'grpc-gateway', label: 'retained proto in the existing plugin', before: { proto: 'synthetic.proto' }, patch: { enabled: true } },
    { plugin: 'grpc-gateway', label: 'new proto in the submitted configuration', before: {}, patch: { config: { proto: 'synthetic.proto' } } },
    { plugin: 'file-log', label: 'retained log path in the existing plugin', before: { path: '/tmp/synthetic.log' }, patch: { enabled: true } },
    { plugin: 'file-log', label: 'new log path in the submitted configuration', before: {}, patch: { config: { path: '/tmp/synthetic.log' } } },
  ])('stops $label when current platform privilege is revoked while DNS awaits', async ({ plugin, before, patch }) => {
    vi.stubEnv('OUTBOUND_ALLOWED_HOSTS', 'kong');
    vi.stubEnv('KONG_RATE_WAIT_MS', '0');
    const actual = await vi.importActual<typeof import('../../apps/console-api/src/infrastructure/kong/outbound')>('../../apps/console-api/src/infrastructure/kong/outbound');
    let platformAdmin = true, entered!: () => void, release!: () => void;
    const dnsEntered = new Promise<void>(resolve => { entered = resolve; });
    const dnsRelease = new Promise<void>(resolve => { release = resolve; });
    transport.lookup.mockImplementation(async () => { entered(); await dnsRelease; return [{ address: '172.28.11.20', family: 4 }]; });
    transport.outbound.mockImplementation(async (...args: Parameters<typeof actual.outboundJson>) => {
      if (args[2] !== 'GET') return actual.outboundJson(...args);
      if (args[1] === '/schemas/plugins') return { status: 200, body: { fields: [{ name: { type: 'string' } }, { enabled: { type: 'boolean' } }] } };
      if (args[1] === `/plugins/schema/${plugin}`) return { status: 200, body: { fields: [{ proto: { type: 'string' } }, { path: { type: 'string' } }] } };
      return { status: 200, body: { id: pid, name: plugin, config: before } };
    });
    // The actual ALS, Kong write pipeline, pinned DNS transport and final send
    // fence execute. The DB authorization decision and Redis lease are explicit
    // in-memory fixtures; no gateway HTTP request is performed by this test.
    const execution = new KongExecutionContextService();
    const authorizeRequest = vi.fn(async () => ({ platformAdmin, before: { id: pid, name: plugin, config: before } }));
    execution.installPolicy({ authorizeRequest, authorizeResponse: async (_ticket, value) => value });
    const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct', connection_secret: null, revision: 1 };
    const redis = { rateLimit: vi.fn(async () => ({ allowed: true })), withLock: async (_key: string, fn: () => Promise<any>) => fn(), assertLeaseOwnership: vi.fn(async () => undefined), assertLeaseActive: vi.fn() };
    const kong = new KongService({ one: vi.fn(async () => cluster) } as any, redis as any, {} as any, {} as any, execution);
    const actor = { id: 'synthetic-plugin-writer', username: 'unit', superAdmin: true };
    const pending = execution.runHttp({ requestId: 'plugin-revocation' }, async () => {
      execution.bindHttpActor(actor, 'synthetic-session');
      const close = execution.captureHttpCloser();
      try {
        return await execution.runActor({ actor, clusterId: cid, workspaceId: wid, module: 'plugins', action: 'write' }, () => execution.runOperation({ actor, clusterId: cid, workspaceId: wid, operationId: 'synthetic-durable-plugin-operation', entityType: 'plugins', action: 'update' }, () => kong.request(cid, 'PATCH', `/plugins/${pid}`, patch)));
      } finally { close(); }
    });
    await dnsEntered;
    platformAdmin = false;
    // grpc-gateway is not bundled in the recorded 1.5.1 metadata. The current
    // custom-plugin rule already requires platform privilege; a future known
    // adapter can report the narrower local-file permission error instead.
    const rejected = expect(pending).rejects.toMatchObject({ status: 403, response: { code: expect.stringMatching(/^PLUGIN_(PLATFORM_EXECUTION|LOCAL_FILE_PERMISSION)_REQUIRED$/) } });
    release();
    await rejected;
    expect(authorizeRequest.mock.calls.length).toBeGreaterThanOrEqual(3);
    expect(transport.http).not.toHaveBeenCalled();
    expect(transport.outbound.mock.calls.filter(call => call[2] !== 'GET')).toHaveLength(1);
  });
});
