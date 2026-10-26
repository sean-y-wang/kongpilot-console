import type { ClusterNode, ClusterOptions, RedisOptions } from 'ioredis';

export type RedisMode = 'standalone' | 'cluster';

export interface RedisConfig {
  mode: RedisMode;
  /** Standalone connection URL (also the fallback seed for cluster mode). */
  url?: string;
  /** Cluster seed nodes. */
  nodes: { host: string; port: number }[];
  username?: string;
  password?: string;
  tls: boolean;
  /** Applied by ioredis to every key argument (including EVAL KEYS). */
  keyPrefix: string;
}

type Env = Record<string, string | undefined>;

function truthy(value: string | undefined): boolean {
  return /^(?:1|true|yes|on)$/i.test((value ?? '').trim());
}

function parseNode(raw: string): { host: string; port: number } {
  const value = raw.trim();
  const match = /^(?:\[([^\]]+)\]|([^:\s]+)):(\d{1,5})$/.exec(value) ?? /^(?:\[([^\]]+)\]|([^:\s]+))$/.exec(value);
  if (!match) throw new Error('REDIS_CLUSTER_NODES must be a comma-separated list of host:port');
  const host = match[1] ?? match[2];
  const port = match[3] ? Number(match[3]) : 6379;
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('REDIS_CLUSTER_NODES must be a comma-separated list of host:port');
  return { host, port };
}

/** Parses Redis settings. Defaults preserve the historical standalone
 * behaviour: REDIS_URL only, no key prefix. Never includes secrets in errors. */
export function parseRedisConfig(env: Env = process.env): RedisConfig {
  const modeRaw = (env.REDIS_MODE ?? '').trim().toLowerCase() || 'standalone';
  if (modeRaw !== 'standalone' && modeRaw !== 'cluster') throw new Error('REDIS_MODE must be standalone or cluster');
  const mode = modeRaw as RedisMode;
  const url = env.REDIS_URL?.trim() || undefined;
  const keyPrefix = env.REDIS_KEY_PREFIX ?? '';
  if (/[\s{}]/.test(keyPrefix) || keyPrefix.length > 128) throw new Error('REDIS_KEY_PREFIX must not contain whitespace or braces and must be at most 128 characters');
  let parsed: URL | undefined;
  if (url) {
    try { parsed = new URL(url); } catch { throw new Error('REDIS_URL is not a valid URL'); }
    if (parsed.protocol !== 'redis:' && parsed.protocol !== 'rediss:') throw new Error('REDIS_URL must use redis:// or rediss://');
  }
  const username = env.REDIS_USERNAME || (parsed?.username ? decodeURIComponent(parsed.username) : undefined) || undefined;
  const password = (mode === 'cluster' ? env.REDIS_PASSWORD || undefined : undefined) || (parsed?.password ? decodeURIComponent(parsed.password) : undefined);
  const tls = env.REDIS_TLS !== undefined && env.REDIS_TLS !== '' ? truthy(env.REDIS_TLS) : parsed?.protocol === 'rediss:';
  if (mode === 'standalone') {
    if (!url) throw new Error('REDIS_URL is required');
    return { mode, url, nodes: [], username, password, tls, keyPrefix };
  }
  const nodesRaw = (env.REDIS_CLUSTER_NODES ?? '').split(',').map(v => v.trim()).filter(Boolean);
  const nodes = nodesRaw.length ? nodesRaw.map(parseNode)
    : parsed ? [{ host: parsed.hostname.replace(/^\[|\]$/g, ''), port: parsed.port ? Number(parsed.port) : 6379 }] : [];
  if (!nodes.length) throw new Error('REDIS_CLUSTER_NODES or REDIS_URL is required when REDIS_MODE=cluster');
  if (parsed && parsed.pathname && parsed.pathname !== '/' && parsed.pathname !== '/0') throw new Error('Redis Cluster only supports database 0; remove the database number from REDIS_URL');
  return { mode, url, nodes, username, password, tls, keyPrefix };
}

/** Hosts that must be treated as protected internal destinations. */
export function redisProtectedHosts(env: Env = process.env): string[] {
  try { const config = parseRedisConfig(env); return config.nodes.map(node => node.host); } catch { return []; }
}

const BASE: RedisOptions = { lazyConnect: true, enableReadyCheck: true, enableOfflineQueue: false,
  maxRetriesPerRequest: 1, connectTimeout: 5000, commandTimeout: 5000,
  retryStrategy: attempts => Math.min(attempts * 100, 2000) };

/** Standalone keeps ioredis' own REDIS_URL parsing (credentials, db, rediss://). */
export function standaloneOptions(config: RedisConfig): RedisOptions {
  return { ...BASE, ...(config.keyPrefix ? { keyPrefix: config.keyPrefix } : {}),
    ...(config.tls && !config.url?.startsWith('rediss:') ? { tls: {} } : {}) };
}

export function clusterOptions(config: RedisConfig): { nodes: ClusterNode[]; options: ClusterOptions } {
  return {
    nodes: config.nodes,
    options: {
      lazyConnect: true, enableReadyCheck: true, enableOfflineQueue: false,
      maxRedirections: 16, retryDelayOnFailover: 200, retryDelayOnClusterDown: 300, retryDelayOnTryAgain: 200,
      slotsRefreshTimeout: 2000, slotsRefreshInterval: 10000,
      clusterRetryStrategy: attempts => Math.min(attempts * 100, 2000),
      // DBaaS endpoints are often hostnames behind TLS/SNI; keep them as-is.
      dnsLookup: (address, callback) => callback(null, address),
      keyPrefix: config.keyPrefix || undefined,
      redisOptions: { connectTimeout: 5000, commandTimeout: 5000, maxRetriesPerRequest: 1,
        ...(config.username ? { username: config.username } : {}),
        ...(config.password ? { password: config.password } : {}),
        ...(config.tls ? { tls: {} } : {}) },
    },
  };
}
