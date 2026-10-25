import { nativeTransportContext, scopedNativeTransport } from './kong-native-test-fixture';
import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
const memory = vi.hoisted(() => ({ owners: new Map<string, string>(), set: vi.fn(), eval: vi.fn(), lookup: vi.fn(), http: vi.fn(), onRateLimit: undefined as (() => void) | undefined }));
vi.mock('ioredis', () => ({ default: class {
  set = memory.set; eval = memory.eval; get = async (key: string) => memory.owners.get(key) || null;
  on() {} connect() {} ping() {} quit() {} disconnect() {} status = 'ready';
} }));
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn() }));
vi.mock('node:dns/promises', () => ({ lookup: memory.lookup }));
vi.mock('node:http', () => ({ request: memory.http }));
import { RedisService } from '../../apps/console-api/src/infrastructure/redis.service';
import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { ForbiddenException } from '@nestjs/common';
const transport = vi.mocked(outboundJson);
const cid = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';

describe('M3 trusted nested lease contexts stop subsequent Kong mutations', () => {
  let redis: RedisService, kong: KongService;
  const writes = () => transport.mock.calls.filter(call => call[2] !== 'GET');
  beforeEach(() => {
    vi.stubEnv('REDIS_URL', 'redis://test:6379'); vi.stubEnv('KONG_RATE_WAIT_MS', '0'); vi.stubEnv('APP_SECRET', 'test-cursor-key-with-more-than-32-characters');
    memory.owners.clear(); memory.onRateLimit = undefined; vi.clearAllMocks();
    memory.set.mockImplementation(async (key, owner) => { if (memory.owners.has(key)) return null; memory.owners.set(key, owner); return 'OK'; });
    memory.eval.mockImplementation(async (script: string, _n: number, key: string, owner: string) => {
      if (script.includes("redis.call('INCR'")) { memory.onRateLimit?.(); return [1, 1000]; }
      if (memory.owners.get(key) !== owner) return 0;
      if (script.includes("redis.call('DEL'")) memory.owners.delete(key);
      return 1;
    });
    redis = new RedisService();
    const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct', connection_secret: null, revision: 1 };
    const context = nativeTransportContext();
    kong = scopedNativeTransport(new KongService({ one: vi.fn().mockResolvedValue(cluster), query: vi.fn().mockResolvedValue([]) } as any, redis, { decrypt: vi.fn(), redactError: (v: any) => v } as any, { append: vi.fn() } as any, context), context, cid);
    transport.mockImplementation(async (_base, path, method, body) => method === 'GET' && path.startsWith('/upstreams/') ? { status: 404, body: {} } : method === 'GET' && path.startsWith('/schemas/') ? { status: 200, body: { fields: [{ host: { type: 'string' } }] } } : { status: 200, body: { id: 's1', ...(body as any) } });
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

  it('stops a multi-step operation after renewal loses its outer owner, before the next native PATCH', async () => {
    vi.useFakeTimers();
    await expect(redis.withLock(`mutation:${cid}`, async () => {
      await kong.request(cid, 'POST', '/services', { host: 'first.example' });
      const outerKey = memory.set.mock.calls[0][0];
      memory.owners.delete(outerKey);
      await vi.advanceTimersByTimeAsync(10000);
      await kong.request(cid, 'PATCH', '/services/s1', { host: 'must-not-write.example' });
    })).rejects.toMatchObject({ response: { code: 'LOCK_LOST' } });
    expect(writes().map(call => call[2])).toEqual(['POST']);
    expect(memory.set).toHaveBeenCalledTimes(2); // outer plus first native write only
  });

  it('detects ownership replacement between short steps and never deletes the replacement lock', async () => {
    let outerKey = '';
    await expect(redis.withLock(`mutation:${cid}`, async () => {
      await kong.request(cid, 'POST', '/services', { host: 'first.example' });
      outerKey = memory.set.mock.calls[0][0]; memory.owners.set(outerKey, 'replacement-owner');
      await kong.request(cid, 'DELETE', '/services/s1');
    })).rejects.toMatchObject({ response: { code: 'LOCK_LOST' } });
    expect(writes().map(call => call[2])).toEqual(['POST']);
    expect(memory.owners.get(outerKey)).toBe('replacement-owner');
  });

  it('rechecks the outer lease after a rate-slot wait and sends zero native writes when it disappears', async () => {
    memory.onRateLimit = () => { if (memory.owners.size === 2) memory.owners.delete(memory.set.mock.calls[0][0]); };
    await expect(redis.withLock(`mutation:${cid}`, () => kong.request(cid, 'POST', '/services', { host: 'must-not-write.example' }))).rejects.toMatchObject({ response: { code: 'LOCK_LOST' } });
    expect(writes()).toEqual([]);
  });

  it('retains trusted parents for distinct nested locks and explicitly rejects same-lock reentrancy', async () => {
    await expect(redis.withLock('outer', () => redis.withLock('inner', async () => {
      await redis.assertLeaseOwnership(); return memory.owners.size;
    }))).resolves.toBe(2);
    expect(memory.owners.size).toBe(0);
    const inner = vi.fn();
    await expect(redis.withLock('same', () => redis.withLock('same', inner))).rejects.toMatchObject({ response: { code: 'LOCK_REENTRANCY_FORBIDDEN' } });
    expect(inner).not.toHaveBeenCalled(); expect(memory.owners.size).toBe(0);
  });

  it('blocks async continuations that outlive their closed operation lease', async () => {
    let release!: () => void, continuation!: Promise<any>;
    const gate = new Promise<void>(resolve => { release = resolve; });
    await redis.withLock('outer', async () => {
      continuation = gate.then(() => kong.request(cid, 'DELETE', '/services/s1'));
    });
    const denied = expect(continuation).rejects.toMatchObject({ response: { code: 'LOCK_LOST' } });
    release(); await denied;
    expect(writes()).toEqual([]); expect(memory.set).toHaveBeenCalledTimes(1);
  });

  it('rejects a successful but delayed Redis verification that returns after its callback has closed', async () => {
    let entered!: () => void, release!: () => void, continuation!: Promise<any>;
    const began = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    const nativeWrite = vi.fn();
    const evaluate = memory.eval.getMockImplementation()!;
    memory.eval.mockImplementation(async (...args: any[]) => {
      const result = await evaluate(...args);
      if (String(args[0]).includes("redis.call('PEXPIRE'")) { entered(); await gate; }
      return result;
    });
    await redis.withLock('outer', async () => {
      continuation = redis.assertLeaseOwnership().then(nativeWrite);
      await began;
    });
    const denied = expect(continuation).rejects.toMatchObject({ response: { code: 'LOCK_LOST' } });
    release(); await denied;
    expect(nativeWrite).not.toHaveBeenCalled(); expect(memory.owners.size).toBe(0);
  });

  it('fences the actual HTTP send after delayed DNS even when Redis verification originally succeeded', async () => {
    const actual = await vi.importActual<typeof import('../../apps/console-api/src/infrastructure/kong/outbound')>('../../apps/console-api/src/infrastructure/kong/outbound');
    transport.mockImplementation(actual.outboundJson);
    vi.stubEnv('OUTBOUND_ALLOWED_HOSTS', 'kong');
    let entered!: () => void, release!: () => void, continuation!: Promise<any>;
    const began = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    memory.lookup.mockImplementation(async () => { entered(); await gate; return [{ address: '127.0.0.1', family: 4 }]; });
    await redis.withLock('outer', async () => {
      continuation = kong.request(cid, 'DELETE', '/services/s1');
      await began;
    });
    const denied = expect(continuation).rejects.toMatchObject({ response: { code: 'LOCK_LOST' } });
    release(); await denied;
    expect(memory.http).not.toHaveBeenCalled(); expect(memory.owners.size).toBe(0);
  });

  it('requires a trusted lease context and fails closed on Redis verification errors', async () => {
    await expect(redis.assertLeaseOwnership()).rejects.toMatchObject({ response: { code: 'LOCK_CONTEXT_REQUIRED' } });
    await expect(redis.withLock('outer', async () => {
      memory.eval.mockRejectedValueOnce(new Error('verification disconnected'));
      await redis.assertLeaseOwnership();
    })).rejects.toMatchObject({ response: { code: 'LOCK_LOST' } });
  });
  it('sends zero HTTP writes when grants are revoked while DNS resolution is awaiting', async () => {
    const actual = await vi.importActual<typeof import('../../apps/console-api/src/infrastructure/kong/outbound')>('../../apps/console-api/src/infrastructure/kong/outbound');
    transport.mockImplementation(actual.outboundJson); vi.stubEnv('OUTBOUND_ALLOWED_HOSTS', 'kong');
    let revoked = false, entered!: () => void, release!: () => void;
    const began = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    memory.lookup.mockImplementation(async () => { entered(); await gate; return [{ address: '172.28.11.20', family: 4 }]; });
    const context = nativeTransportContext({ authorizeRequest: async () => { if (revoked) throw new ForbiddenException({ code: 'GRANT_REVOKED_DURING_DNS' }); return {}; }, authorizeResponse: async (_ticket, result) => result });
    const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct', connection_secret: null, revision: 1 };
    kong = scopedNativeTransport(new KongService({ one: vi.fn().mockResolvedValue(cluster) } as any, redis, {} as any, {} as any, context), context, cid);
    const pending = redis.withLock('outer', () => kong.request(cid, 'DELETE', '/services/s1'));
    await began; revoked = true;
    const denied = expect(pending).rejects.toMatchObject({ status: 403, response: { code: 'GRANT_REVOKED_DURING_DNS' } });
    release(); await denied;
    expect(memory.http).not.toHaveBeenCalled(); expect(memory.owners.size).toBe(0);
  });
});
