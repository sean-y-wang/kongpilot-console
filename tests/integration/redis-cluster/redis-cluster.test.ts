import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Cluster } from 'ioredis';
import { RedisService } from '../../../apps/console-api/src/infrastructure/redis.service';

const nodes = process.env.REDIS_CLUSTER_TEST_NODES;
const password = process.env.REDIS_CLUSTER_TEST_PASSWORD || 'kongpilot-cluster-test';
const prefix = 'hf-kong-dev:';

describe.skipIf(!nodes)('RedisService against a real Redis Cluster with key prefix', () => {
  let service: RedisService;
  let raw: Cluster;
  beforeAll(async () => {
    process.env.REDIS_MODE = 'cluster';
    process.env.REDIS_CLUSTER_NODES = nodes;
    process.env.REDIS_PASSWORD = password;
    process.env.REDIS_KEY_PREFIX = prefix;
    delete process.env.REDIS_URL;
    service = new RedisService();
    await service.onModuleInit();
    raw = new Cluster(nodes!.split(',').map(n => ({ host: n.split(':')[0], port: Number(n.split(':')[1]) })), { redisOptions: { password } });
    await raw.ping();
  });
  afterAll(async () => { await service?.onModuleDestroy(); await raw?.quit(); });

  async function allKeys(): Promise<string[]> {
    const keys: string[] = [];
    for (const node of raw.nodes('master')) keys.push(...await node.keys('*'));
    return keys;
  }

  it('reports cluster mode and answers health pings', async () => {
    expect(service.config.mode).toBe('cluster');
    expect(await service.client.ping()).toBe('PONG');
    expect(raw.nodes('master').length).toBe(3);
  });

  it('rate limits atomically via EVAL with the prefixed key', async () => {
    const results = [];
    for (let i = 0; i < 4; i++) results.push(await service.rateLimit('cluster-test-rl', 3, 5000));
    expect(results.map(r => r.allowed)).toEqual([true, true, true, false]);
    expect(results[3].retryAfterMs).toBeGreaterThan(0);
  });

  it('acquires, renews, rejects contention and releases distributed locks across slots', async () => {
    const ids = Array.from({ length: 20 }, (_, i) => `cluster-lock-${i}`);
    await Promise.all(ids.map(id => service.withLock(id, async () => {
      await expect(service.withLock(id, async () => 1)).rejects.toMatchObject({ response: { code: 'LOCK_REENTRANCY_FORBIDDEN' } });
      await service.assertLeaseOwnership();
      return id;
    })));
    // A second instance (another API replica) must see the lock as held.
    const replica = new RedisService();
    await replica.onModuleInit();
    let inner: any;
    await service.withLock('contended', async () => { inner = await replica.withLock('contended', async () => 1).catch(e => e); });
    expect(inner?.response?.code).toBe('RESOURCE_LOCKED');
    expect(await replica.withLock('contended', async () => 'free')).toBe('free');
    await replica.onModuleDestroy();
    expect((await allKeys()).filter(k => k.includes(':lock:'))).toEqual([]);
  });

  it('stores sessions and OIDC state with the prefix (SET EX / GETDEL / DEL)', async () => {
    await service.client.set('auth:session:cluster-sid', 'user-1', 'EX', 60);
    await service.client.set('auth:oidc:state:abc', '{}', 'EX', 60, 'NX');
    expect(await service.client.get('auth:session:cluster-sid')).toBe('user-1');
    expect(await raw.get(`${prefix}auth:session:cluster-sid`)).toBe('user-1');
    expect(await service.client.getdel('auth:oidc:state:abc')).toBe('{}');
    await service.client.del('auth:session:cluster-sid');
    expect(await raw.exists(`${prefix}auth:session:cluster-sid`)).toBe(0);
  });

  it('never writes an unprefixed key', async () => {
    const keys = await allKeys();
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.every(k => k.startsWith(prefix))).toBe(true);
  });
});
