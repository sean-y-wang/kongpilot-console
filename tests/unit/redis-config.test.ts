import { describe, expect, it } from 'vitest';
import { clusterOptions, parseRedisConfig, redisProtectedHosts, standaloneOptions } from '../../apps/console-api/src/infrastructure/redis-config';

describe('Redis configuration', () => {
  it('defaults to standalone REDIS_URL with no key prefix (backward compatible)', () => {
    const config = parseRedisConfig({ REDIS_URL: 'redis://:secret@redis:6379/0' });
    expect(config).toMatchObject({ mode: 'standalone', url: 'redis://:secret@redis:6379/0', keyPrefix: '', tls: false });
    const options = standaloneOptions(config);
    expect(options).not.toHaveProperty('keyPrefix');
    expect(options).not.toHaveProperty('password');
    expect(options.enableOfflineQueue).toBe(false);
  });

  it('requires REDIS_URL in standalone mode and rejects unknown modes', () => {
    expect(() => parseRedisConfig({})).toThrow('REDIS_URL is required');
    expect(() => parseRedisConfig({ REDIS_MODE: 'sentinel', REDIS_URL: 'redis://x' })).toThrow('REDIS_MODE');
    expect(() => parseRedisConfig({ REDIS_URL: 'http://x' })).toThrow('redis://');
  });

  it('applies REDIS_KEY_PREFIX in standalone mode', () => {
    expect(standaloneOptions(parseRedisConfig({ REDIS_URL: 'redis://r:6379', REDIS_KEY_PREFIX: 'hf-kong-dev:' })).keyPrefix).toBe('hf-kong-dev:');
  });

  it('rejects prefixes that would break hash-slot routing', () => {
    expect(() => parseRedisConfig({ REDIS_URL: 'redis://r', REDIS_KEY_PREFIX: '{x}:' })).toThrow('REDIS_KEY_PREFIX');
    expect(() => parseRedisConfig({ REDIS_URL: 'redis://r', REDIS_KEY_PREFIX: 'a b' })).toThrow('REDIS_KEY_PREFIX');
  });

  it('parses cluster nodes, password, username and TLS', () => {
    const config = parseRedisConfig({ REDIS_MODE: 'cluster', REDIS_CLUSTER_NODES: 'a.example:6379, b.example:6380,[fd00::1]:7000',
      REDIS_PASSWORD: 'p@ss', REDIS_USERNAME: 'app', REDIS_TLS: 'true', REDIS_KEY_PREFIX: 'hf-kong-dev:' });
    expect(config.nodes).toEqual([{ host: 'a.example', port: 6379 }, { host: 'b.example', port: 6380 }, { host: 'fd00::1', port: 7000 }]);
    const { nodes, options } = clusterOptions(config);
    expect(nodes).toHaveLength(3);
    expect(options.keyPrefix).toBe('hf-kong-dev:');
    expect(options.redisOptions).toMatchObject({ password: 'p@ss', username: 'app', tls: {} });
    expect(options.enableOfflineQueue).toBe(false);
    let resolved: string | undefined;
    options.dnsLookup!('svc.dbaas.private', (_e, address) => { resolved = address; });
    expect(resolved).toBe('svc.dbaas.private');
  });

  it('derives the cluster seed from REDIS_URL, including its credentials', () => {
    const config = parseRedisConfig({ REDIS_MODE: 'cluster', REDIS_URL: 'redis://:pw%25x@redis.dbaas.private:6379' });
    expect(config.nodes).toEqual([{ host: 'redis.dbaas.private', port: 6379 }]);
    expect(config.password).toBe('pw%x');
    expect(parseRedisConfig({ REDIS_MODE: 'cluster', REDIS_URL: 'rediss://h:1' }).tls).toBe(true);
    expect(() => parseRedisConfig({ REDIS_MODE: 'cluster', REDIS_URL: 'redis://h:1/3' })).toThrow('database 0');
    expect(() => parseRedisConfig({ REDIS_MODE: 'cluster' })).toThrow('REDIS_CLUSTER_NODES or REDIS_URL');
    expect(() => parseRedisConfig({ REDIS_MODE: 'cluster', REDIS_CLUSTER_NODES: 'bad host:x' })).toThrow('host:port');
  });

  it('never leaks the password in errors', () => {
    try { parseRedisConfig({ REDIS_MODE: 'cluster', REDIS_URL: 'redis://:topsecret@h:1/9' }); } catch (error) { expect(String(error)).not.toContain('topsecret'); }
  });

  it('exposes cluster node hosts as protected destinations', () => {
    expect(redisProtectedHosts({ REDIS_MODE: 'cluster', REDIS_CLUSTER_NODES: 'r1:6379,r2:6379' })).toEqual(['r1', 'r2']);
    expect(redisProtectedHosts({ REDIS_URL: 'redis://x:1' })).toEqual([]);
  });
});
