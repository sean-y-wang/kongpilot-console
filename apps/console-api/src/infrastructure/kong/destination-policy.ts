import { BadGatewayException, ForbiddenException } from '@nestjs/common';
import { lookup, Resolver } from 'node:dns/promises';
import { isIP } from 'node:net';
import { readFile } from 'node:fs/promises';
import type { DbService } from '../db.service';
import { pluginMetadata } from '../../modules/plugin-center/plugin-metadata';

type HostPort = { host: string; port: number };
const prohibited = () => new ForbiddenException({ code: 'PROTECTED_PROXY_DESTINATION', message: '网关不能将请求发送至管理端、控制台存储或系统保留地址' });
const unavailable = () => new BadGatewayException({ code: 'DESTINATION_POLICY_UNAVAILABLE', message: '无法核验受保护目标地址，变更已停止' });
function hostName(value: string): string {
  if (typeof value !== 'string') return '';
  let host = value.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  // The proxy resolver can accept alternate IPv4 spellings. Normalize them
  // before checking loopback/link-local, including decimal and hexadecimal IPs.
  if (/^(?:0x[0-9a-f]+|[\d.]+)$/.test(host)) {
    try { host = new URL(`http://${host}`).hostname; } catch { return ''; }
  }
  if (isIP(host) === 6) {
    try { host = new URL(`http://[${host}]`).hostname.slice(1, -1); } catch { return ''; }
  }
  return host;
}
function systemAddress(host: string): boolean {
  const value = hostName(host);
  return value === 'localhost' || value.endsWith('.localhost') || value.startsWith('0.') || value === '255.255.255.255' || value === '::' || value === '::1' || value.startsWith('127.') || value.startsWith('169.254.') || value.startsWith('::ffff:') || isIP(value) === 6 && (/^fe[89ab]/.test(value) || value.startsWith('ff')) || /^22[4-9]\.|^23\d\./.test(value);
}
function parseUrl(value: string): HostPort {
  const url = new URL(value);
  return { host: hostName(url.hostname), port: Number(url.port || (url.protocol === 'https:' ? 443 : url.protocol === 'redis:' ? 6379 : url.protocol === 'postgres:' || url.protocol === 'postgresql:' ? 5432 : 80)) };
}
// getaddrinfo cannot be cancelled. Without upstream DNS a lookup of an absent
// hostname hangs ~8 s, and concurrent hung getaddrinfo calls were observed to
// delay unrelated getaddrinfo (e.g. the Kong Admin hostname past its 5 s budget)
// even with threadpool capacity left. Protected-host probes therefore use the
// asynchronous c-ares resolver (no threadpool, hard 1 s timeout). Only a
// definitive negative answer falls back to getaddrinfo (for /etc/hosts entries),
// and that fallback is single-flight per host and capped in concurrency.
// Only resolver timeouts are (negatively) cached.
const LOOKUP_BUDGET_MS = 1000, MAX_INFLIGHT_LOOKUPS = 2, NEGATIVE_TTL_MS = 30_000;
type LookupFn = (host: string) => Promise<string[]>;
async function hostsFile(host: string): Promise<string[]> {
  try {
    const text = await readFile(process.env.DESTINATION_HOSTS_FILE || '/etc/hosts', 'utf8');
    return text.split('\n').map(line => line.replace(/#.*/, '').trim().split(/\s+/)).filter(row => row.length > 1 && isIP(row[0]) && row.slice(1).some(name => hostName(name) === host)).map(row => row[0]);
  } catch { return []; }
}
const DEFINITIVE_NEGATIVE = new Set(['ENOTFOUND', 'ENODATA', 'ENONAME', 'NOTFOUND', 'NODATA']);
class ResolverTimeout extends Error {}
const defaultLookup: LookupFn = async host => {
  const pinned = await hostsFile(host);
  if (pinned.length) return pinned;
  let answers: PromiseSettledResult<string[]>[] | undefined;
  try {
    const resolver = new Resolver({ timeout: LOOKUP_BUDGET_MS, tries: 1 });
    answers = await Promise.allSettled([resolver.resolve4(host), resolver.resolve6(host)]);
  } catch { answers = undefined; } // resolver unavailable: use the bounded system path
  if (answers) {
    const found = answers.flatMap(row => row.status === 'fulfilled' ? row.value : []);
    if (found.length) return found;
    const definitive = answers.every(row => row.status === 'rejected' && DEFINITIVE_NEGATIVE.has((row.reason as any)?.code));
    // Timeout / unreachable resolver: never start a hung getaddrinfo.
    if (!definitive) throw new ResolverTimeout(host);
  }
  return (await lookup(host, { all: true })).map(row => row.address);
};
let systemLookup: LookupFn = defaultLookup;
const inflight = new Map<string, Promise<string[]>>(), cache = new Map<string, { until: number; value: string[] }>();
let active = 0;
function startLookup(host: string): Promise<string[]> | undefined {
  const running = inflight.get(host);
  if (running) return running;
  if (active >= MAX_INFLIGHT_LOOKUPS) return undefined;
  active++;
  // Only an unreachable-resolver timeout is cached (negatively); answers are
  // never cached, so DNS proofs always reflect the current resolver state.
  const task = systemLookup(host).then(rows => rows.map(hostName), error => {
    if (error instanceof ResolverTimeout) cache.set(host, { until: Date.now() + NEGATIVE_TTL_MS, value: [] });
    return [] as string[];
  }).finally(() => { active--; inflight.delete(host); });
  inflight.set(host, task);
  return task;
}
async function addresses(host: string): Promise<string[]> {
  if (isIP(host)) return [host];
  const cached = cache.get(host);
  if (cached && cached.until > Date.now()) return cached.value;
  // Business DNS can be resolvable only from Kong's network; a lookup that does
  // not complete within the budget (including time spent waiting for a lookup
  // slot) is treated like an unresolvable name, as before.
  const deadline = Date.now() + LOOKUP_BUDGET_MS;
  for (;;) {
    const task = startLookup(host);
    const remaining = deadline - Date.now();
    if (remaining <= 0) return [];
    let timer: NodeJS.Timeout | undefined;
    const expired = new Promise<null>(resolve => { timer = setTimeout(() => resolve(null), remaining); });
    try {
      if (task) return (await Promise.race([task, expired])) ?? [];
      // Wait for any running lookup to release its slot, then retry.
      if (await Promise.race([Promise.race([...inflight.values()]).then(() => true), expired]) === null) return [];
    } finally { if (timer) clearTimeout(timer); }
    const settled = cache.get(host);
    if (settled && settled.until > Date.now()) return settled.value;
  }
}
/** Test seam only. */
export function __setDestinationLookupForTests(fn?: LookupFn): void {
  systemLookup = fn ?? defaultLookup;
  inflight.clear(); cache.clear(); active = 0;
}

/** Static validation complements Kong's exact-source Admin ACL. Runtime DNS
 * changes cannot be fenced by a configuration-time lookup alone. */
export async function assertProxyDestination(db: Pick<DbService, 'query'>, candidate: HostPort): Promise<void> {
  const normalized = hostName(candidate.host), port = Number(candidate.port);
  // OpenResty connect() also accepts Unix socket syntax. Native plugin schemas
  // can expose an unconstrained string, so DNS failure must never make a socket
  // path or authority suffix into an accepted ordinary business hostname.
  if (!normalized || !isIP(normalized) && !/^[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?$/.test(normalized) || !Number.isInteger(port) || port < 1 || port > 65535 || systemAddress(normalized)) throw prohibited();
  const rows = await db.query<any>('SELECT admin_url FROM clusters WHERE deleted_at IS NULL');
  const sources = await db.query<any>('SELECT base_url FROM data_sources WHERE deleted_at IS NULL');
  const admins: HostPort[] = [], privateHosts = new Set(['console-api', 'console-web', 'console-db', 'kong-db', 'kong-secondary-db', 'redis', 'telemetry-collector', 'metrics-collector']);
  try {
    for (const row of rows) admins.push(parseUrl(row.admin_url));
    for (const row of sources) privateHosts.add(parseUrl(row.base_url).host);
    for (const value of [process.env.DATABASE_URL ?? process.env.CONSOLE_DATABASE_URL, process.env.REDIS_URL, process.env.CONSOLE_INTERNAL_URL]) if (value) privateHosts.add(parseUrl(value).host);
    for (const host of (process.env.PROTECTED_DESTINATION_HOSTS || '').split(',').filter(Boolean)) privateHosts.add(hostName(host.trim()));
  } catch { throw unavailable(); }
  if (privateHosts.has(normalized) || admins.some(row => row.host === normalized && row.port === port)) throw prohibited();
  const resolved = await addresses(normalized);
  if (resolved.some(systemAddress)) throw prohibited();
  // Resolve protected endpoints too, so an attacker-owned DNS alias pointing
  // at their known address cannot evade the hostname comparison.
  const protectedRows = [...admins.filter(row => row.port === port).map(row => row.host), ...privateHosts];
  const protectedAddresses = new Set((await Promise.all(protectedRows.map(addresses))).flat());
  if ((isIP(normalized) ? [normalized] : resolved).some(address => protectedAddresses.has(address))) throw prohibited();
}
export async function assertProxyUrl(db: Pick<DbService, 'query'>, value: unknown): Promise<void> {
  if (typeof value !== 'string') throw prohibited();
  let url: URL;
  try { url = new URL(value); } catch { throw prohibited(); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw prohibited();
  await assertProxyDestination(db, parseUrl(url.toString()));
}

/** Called only after KongService has proved the private managed provision (or
 * an unchanged existing platform-owned endpoint) and its current DB token.
 * The collector is itself protected from ordinary gateway destinations. Its
 * dedicated channel may exclude that one deployment host/address, never the
 * Admin, BFF, storage or data-source origins, even if their DNS aliases overlap.
 * Kong resolves this fixed hostname on its own proxy network; this check does
 * not claim to pin Kong's later runtime DNS result. */
export async function assertManagedCollectorDestination(db: Pick<DbService, 'query'>, clusterId: string, value: string): Promise<void> {
  if (!/^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(clusterId)
    || value !== `http://telemetry-collector:9093/ingest/${clusterId}`) throw prohibited();
  const collectorIp = hostName(process.env.COLLECTOR_TELEMETRY_IP || '172.28.31.30');
  if (!isIP(collectorIp) || systemAddress(collectorIp)) throw unavailable();
  const selfRows = (process.env.COLLECTOR_SELF_IPS || '').split(',').map(row => hostName(row.trim()));
  if (!selfRows.length || selfRows.length > 8 || selfRows.some(address => !isIP(address) || systemAddress(address)) || !selfRows.includes(collectorIp)) throw unavailable();
  const selfIps = new Set(selfRows);
  const rows = await db.query<any>('SELECT admin_url FROM clusters WHERE deleted_at IS NULL');
  const sources = await db.query<any>('SELECT base_url FROM data_sources WHERE deleted_at IS NULL');
  const hardHosts = new Set(['console-api', 'console-web', 'console-db', 'kong-db', 'kong-secondary-db', 'redis', 'metrics-bff']);
  try {
    // Unlike an ordinary Service using Kong's proxy port, this channel has no
    // reason to share an Admin endpoint IP on any port.
    for (const row of rows) hardHosts.add(parseUrl(row.admin_url).host);
    for (const row of sources) hardHosts.add(parseUrl(row.base_url).host);
    for (const value of [process.env.DATABASE_URL ?? process.env.CONSOLE_DATABASE_URL, process.env.REDIS_URL, process.env.CONSOLE_INTERNAL_URL]) if (value) hardHosts.add(parseUrl(value).host);
  } catch { throw unavailable(); }
  if (hardHosts.has('telemetry-collector') || hardHosts.has('metrics-collector') || [...selfIps].some(address => hardHosts.has(address))) throw prohibited();
  for (const host of (process.env.PROTECTED_DESTINATION_HOSTS || '').split(',').filter(Boolean)) {
    const normalized = hostName(host.trim());
    if (normalized !== 'telemetry-collector' && normalized !== 'metrics-collector' && !selfIps.has(normalized)) hardHosts.add(normalized);
  }
  // This alias exists solely on the collector's telemetry network. It supplies
  // positive self-identity even when the shared native hostname has additional
  // proxy/observability interfaces visible to the BFF. No arbitrary business
  // address may stand in for the registered collector identity.
  const provenance = await addresses('metrics-collector');
  if (!provenance.length || provenance.some(address => address !== collectorIp)) throw unavailable();
  const resolved = await addresses('telemetry-collector');
  // An unknown private collector address is not a legitimate business-DNS
  // exception. No managed packet may leave without a positive address proof.
  if (!resolved.length) throw unavailable();
  if (resolved.some(systemAddress)) throw prohibited();
  if (resolved.some(address => !selfIps.has(address))) throw prohibited();
  const protectedAddresses = new Set((await Promise.all([...hardHosts].map(addresses))).flat());
  // Every registered interface must remain disjoint from hard management
  // origins, even when Docker happens to return only another self interface.
  if ([...selfIps, ...resolved, ...provenance].some(address => protectedAddresses.has(address))) throw prohibited();
}
export async function assertTargetDestination(db: Pick<DbService, 'query'>, target: unknown): Promise<void> {
  if (typeof target !== 'string') throw prohibited();
  let url: URL;
  try { url = new URL(`http://${target}`); } catch { throw prohibited(); }
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw prohibited();
  await assertProxyDestination(db, { host: hostName(url.hostname), port: Number(url.port || 8000) });
}
export function assertPluginExecutionPrivilege(name: string, config: any, platformAdmin: boolean): void {
  if ((['pre-function', 'post-function'].includes(name) || !pluginMetadata(name).known) && !platformAdmin) throw new ForbiddenException({ code: 'PLUGIN_PLATFORM_EXECUTION_REQUIRED', message: 'Serverless 或自定义插件需当前平台超级管理员权限' });
  if ((name === 'grpc-gateway' && config?.proto || name === 'file-log') && !platformAdmin) throw new ForbiddenException({ code: 'PLUGIN_LOCAL_FILE_PERMISSION_REQUIRED', message: '读取或写入网关本地文件需要平台超级管理员权限' });
}
export async function assertPluginDestinations(db: Pick<DbService, 'query'>, name: string, config: any, platformAdmin: boolean): Promise<void> {
  assertPluginExecutionPrivilege(name, config, platformAdmin);
  await assertPluginDestinationSafety(db, name, config);
}
/** Destination facts can be reviewed without claiming execution privilege. */
export async function assertPluginDestinationSafety(db: Pick<DbService, 'query'>, name: string, config: any): Promise<void> {
  if (name === 'http-log' && config?.http_endpoint) await assertProxyUrl(db, config.http_endpoint);
  if (name === 'zipkin' && config?.http_endpoint) await assertProxyUrl(db, config.http_endpoint);
  if (['tcp-log', 'udp-log', 'syslog', 'datadog', 'statsd', 'ldap-auth', 'loggly'].includes(name) && config?.host) await assertProxyDestination(db, { host: config.host, port: Number(config.port || (name === 'ldap-auth' ? 389 : 514)) });
  // Verified 1.5.1 azure-functions handler constructs this literal host and
  // selects only the standard HTTP(S) port; it does not accept a separate URL.
  if (name === 'azure-functions' && typeof config?.appname === 'string') await assertProxyDestination(db, { host: `${config.appname}.${config.hostdomain ?? 'azurewebsites.net'}`, port: config.https === false ? 80 : 443 });
  if (name === 'ldap-auth' && config?.ldap_host) await assertProxyDestination(db, { host: config.ldap_host, port: Number(config.ldap_port || 389) });
  if (config?.redis_host) await assertProxyDestination(db, { host: config.redis_host, port: Number(config.redis_port || 6379) });
  // Existing source/data stores use URLs or broker lists; validate each explicit
  // network endpoint without pretending that arbitrary Lua can be statically inspected.
  if (name === 'kafka-log') for (const broker of config?.bootstrap_servers || []) if (broker?.host) await assertProxyDestination(db, { host: broker.host, port: Number(broker.port || 9092) });
  if (name === 'degraphql' && config?.graphql_server) await assertProxyUrl(db, config.graphql_server);
}
