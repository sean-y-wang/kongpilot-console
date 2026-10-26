import { ConflictException, Injectable, OnModuleDestroy, OnModuleInit, ServiceUnavailableException } from '@nestjs/common';
import Redis, { Cluster } from 'ioredis';
import { clusterOptions, parseRedisConfig, RedisConfig, standaloneOptions } from './redis-config';
import { createHash, randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';

export interface RateLimitResult { allowed: boolean; remaining: number; retryAfterMs: number; }
interface ActiveLease { key: string; owner: string; ttlMs: number; lost: boolean; closed: boolean; renewal?: Promise<void>; }

const RELEASE_LOCK = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end`;
const RENEW_LOCK = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE', KEYS[1], ARGV[2]) else return 0 end`;
const RATE_LIMIT = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); ttl = tonumber(ARGV[1]) end
return {count, ttl}`;

/** Kong writes serialize per gateway cluster (transport scope), not per object,
 * so a conflict there must not claim the same object is being changed. */
export function lockedConflict(key: string): ConflictException {
  const cluster = /^(?:mutation:|index:)/.test(key) || /^kong:.*:write$/.test(key);
  return new ConflictException(cluster
    ? { code: 'RESOURCE_LOCKED', lockScope: 'cluster', message: '该网关集群正在执行其他变更（集群级写锁），请稍后重试' }
    : { code: 'RESOURCE_LOCKED', lockScope: 'object', message: '同一对象正在变更，请稍后重试' });
}
@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  /** Standalone or Cluster client. All callers must use single-key commands
   * (or hash-tagged keys) so every operation is cluster-safe. */
  readonly client: Redis | Cluster;
  readonly config: RedisConfig;
  private readonly activeLeases = new AsyncLocalStorage<ActiveLease[]>();

  constructor() {
    this.config = parseRedisConfig();
    if (this.config.mode === 'cluster') {
      const { nodes, options } = clusterOptions(this.config);
      this.client = new Cluster(nodes, options);
    } else {
      this.client = new Redis(this.config.url!, standaloneOptions(this.config));
    }
    // Connection errors are returned by callers; do not log URLs or credentials.
    this.client.on('error', () => undefined);
  }

  async onModuleInit(): Promise<void> {
    await this.client.connect();
    await this.client.ping();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.client.status === 'ready') await this.client.quit();
    else this.client.disconnect();
  }

  private key(namespace: string, key: string): string {
    if (!key || key.length > 4096) throw new Error('Invalid Redis operation key');
    return `kongos:${namespace}:${createHash('sha256').update(key).digest('hex')}`;
  }

  async rateLimit(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isSafeInteger(windowMs) || windowMs < 1) {
      throw new Error('Rate limit and window must be positive integers');
    }
    try {
      const result = await this.client.eval(RATE_LIMIT, 1, this.key('ratelimit', key), windowMs) as [number, number];
      const [count, ttl] = result.map(Number);
      if (!Number.isFinite(count) || !Number.isFinite(ttl)) throw new Error('Invalid Redis rate-limit result');
      return { allowed: count <= limit, remaining: Math.max(0, limit - count), retryAfterMs: count > limit ? ttl : 0 };
    } catch {
      throw new ServiceUnavailableException({ code: 'REDIS_UNAVAILABLE', message: '限流存储不可用，操作已停止' });
    }
  }

  async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const redisKey = this.key('lock', key);
    const parents = this.activeLeases.getStore() || [];
    if (parents.length) await this.assertLeaseOwnership();
    if (parents.some(lease => lease.key === redisKey)) throw new ConflictException({ code: 'LOCK_REENTRANCY_FORBIDDEN', message: '不能在当前变更锁内再次获取同一把锁' });
    const owner = randomUUID();
    const ttlMs = 30000;
    let acquired: string | null;
    try { acquired = await this.client.set(redisKey, owner, 'PX', ttlMs, 'NX'); }
    catch { throw new ServiceUnavailableException({ code: 'REDIS_UNAVAILABLE', message: '分布式锁存储不可用，操作已停止' }); }
    if (acquired !== 'OK') throw lockedConflict(key);
    const lease: ActiveLease = { key: redisKey, owner, ttlMs, lost: false, closed: false };
    const timer = setInterval(() => {
      if (lease.renewal || lease.lost || lease.closed) return;
      lease.renewal = this.client.eval(RENEW_LOCK, 1, redisKey, owner, ttlMs)
        .then(result => { if (Number(result) !== 1) lease.lost = true; })
        .catch(() => { lease.lost = true; })
        .finally(() => { lease.renewal = undefined; });
    }, ttlMs / 3);
    timer.unref();
    try {
      const result = await this.activeLeases.run([...parents, lease], fn);
      // The callback has finished. Async work it did not await cannot extend
      // the operation's lifetime while final ownership verification runs.
      lease.closed = true;
      if (lease.renewal) await lease.renewal;
      if (lease.lost || parents.some(parent => parent.lost || parent.closed)) throw this.lostLease();
      // Verify ownership even for operations shorter than the renewal interval.
      const currentOwner = await this.client.get(redisKey).catch(() => null);
      if (currentOwner !== owner) { lease.lost = true; throw this.lostLease(); }
      return result;
    } catch (error) {
      lease.closed = true;
      if (lease.renewal) await lease.renewal;
      if (lease.lost || parents.some(parent => parent.lost || parent.closed)) throw this.lostLease();
      throw error;
    } finally {
      lease.closed = true;
      clearInterval(timer);
      if (lease.renewal) await lease.renewal;
      // An expired/replaced lock can never be deleted by its old owner.
      await this.client.eval(RELEASE_LOCK, 1, redisKey, owner).catch(() => undefined);
    }
  }

  private lostLease(): ServiceUnavailableException { return new ServiceUnavailableException({ code: 'LOCK_LOST', message: '执行锁失效，变更结果需要核验，后续网关写入已停止' }); }

  /** Synchronous fence used immediately before native transport, including
   * after asynchronous DNS resolution. It cannot acquire or renew a lease. */
  assertLeaseActive(): void {
    const leases = this.activeLeases.getStore();
    if (!leases?.length) throw new ServiceUnavailableException({ code: 'LOCK_CONTEXT_REQUIRED', message: '网关写入缺少有效执行锁上下文' });
    if (leases.some(lease => lease.lost || lease.closed)) throw this.lostLease();
  }

  /** Context cannot be supplied by an HTTP caller. Nested gateway locks retain
   * every outer operation lease, including leases lost during rate-limit waits.
   * Compare-and-renew is atomic and supplies a fresh full TTL before transport. */
  async assertLeaseOwnership(): Promise<void> {
    this.assertLeaseActive();
    const leases = this.activeLeases.getStore();
    for (const lease of leases!) {
      if (lease.renewal) await lease.renewal;
      this.assertLeaseActive();
      let renewed: unknown;
      try { renewed = await this.client.eval(RENEW_LOCK, 1, lease.key, lease.owner, lease.ttlMs); }
      catch { lease.lost = true; throw this.lostLease(); }
      if (Number(renewed) !== 1) { lease.lost = true; throw this.lostLease(); }
      // A successful Redis result can arrive after the callback (or a parent)
      // closed. Compare success does not grant an orphan continuation a lease.
      this.assertLeaseActive();
    }
    this.assertLeaseActive();
  }
}
