import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ set: vi.fn(), get: vi.fn(), eval: vi.fn(), on: vi.fn(),
  connect: vi.fn(), ping: vi.fn(), quit: vi.fn(), disconnect: vi.fn() }));
vi.mock('ioredis', () => ({ default: class {
  set = mocks.set; get = mocks.get; eval = mocks.eval; on = mocks.on;
  connect = mocks.connect; ping = mocks.ping; quit = mocks.quit; disconnect = mocks.disconnect;
  status = 'ready';
} }));
import { RedisService } from '../../apps/console-api/src/infrastructure/redis.service';

describe('RedisService atomic rate limit and lock ownership', () => {
  beforeEach(() => {
    vi.stubEnv('REDIS_URL', 'redis://localhost:6379');
    vi.clearAllMocks();
    mocks.set.mockResolvedValue('OK');
    mocks.eval.mockResolvedValue(1);
    mocks.get.mockImplementation(async () => mocks.set.mock.calls[0]?.[1]);
  });
  afterEach(() => vi.unstubAllEnvs());

  it('returns remaining allowance and denial TTL from the atomic counter', async () => {
    const redis = new RedisService();
    mocks.eval.mockResolvedValueOnce([2, 900]).mockResolvedValueOnce([4, 800]);
    expect(await redis.rateLimit('cluster-one', 3, 1000)).toEqual({ allowed: true, remaining: 1, retryAfterMs: 0 });
    expect(await redis.rateLimit('cluster-one', 3, 1000)).toEqual({ allowed: false, remaining: 0, retryAfterMs: 800 });
    expect(mocks.eval.mock.calls[0][2]).toBe(mocks.eval.mock.calls[1][2]);
  });

  it('fails closed when Redis cannot account for a request', async () => {
    mocks.eval.mockRejectedValueOnce(new Error('Redis disconnected'));
    await expect(new RedisService().rateLimit('key', 10, 1000)).rejects.toMatchObject({ status: 503 });
  });

  it('holds a random-owner lock and releases it via owner-checked Lua', async () => {
    const redis = new RedisService();
    expect(await redis.withLock('cluster-one/service-a', async () => 42)).toBe(42);
    expect(mocks.set.mock.calls[0].slice(2)).toEqual(['PX', 30000, 'NX']);
    expect(mocks.eval.mock.calls[0][3]).toBe(mocks.set.mock.calls[0][1]);
    expect(mocks.eval.mock.calls[0][0]).toContain("redis.call('GET', KEYS[1]) == ARGV[1]");
  });

  it('refuses contention without entering the write callback', async () => {
    mocks.set.mockResolvedValueOnce(null);
    const callback = vi.fn();
    await expect(new RedisService().withLock('same-object', callback)).rejects.toMatchObject({ status: 409 });
    expect(callback).not.toHaveBeenCalled();
    expect(mocks.eval).not.toHaveBeenCalled();
  });

  it('releases after callback failure and does not report success after losing ownership', async () => {
    const redis = new RedisService();
    await expect(redis.withLock('error-object', async () => { throw new Error('write failed'); })).rejects.toThrow('write failed');
    expect(mocks.eval).toHaveBeenCalledTimes(1);
    mocks.get.mockResolvedValueOnce('another-owner');
    await expect(redis.withLock('lost-object', async () => 'performed')).rejects.toMatchObject({ status: 503 });
  });
});
