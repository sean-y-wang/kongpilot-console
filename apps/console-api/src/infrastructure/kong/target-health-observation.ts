import { ConflictException } from '@nestjs/common';
import { isIP } from 'node:net';
import type { SecretService } from '../secret.service';
import type { KongService } from './kong.service';
import { immutableJson } from './immutable-json';

export type TargetHealthObservation = Readonly<{
  version: 1;
  kind: 'kong-1.5-target-health-observation';
  upstreamId: string;
  targetId: string;
  targetAddress: string;
  nodeId: string;
  health: 'HEALTHY' | 'UNHEALTHY';
  targetRow: Readonly<Record<string, unknown>>;
  targetHmac: string;
  nodeScope: 'current_admin_node';
  /** A health GET reports effective status, not the previous override command. */
  recoverableOverride: false;
  observationHmac: string;
}>;

export type TargetHealthObservationInput = Readonly<{
  clusterId: string;
  upstreamId: string;
  /** Original effective Target, including its native upstream and physical tags. */
  target: Readonly<Record<string, unknown>>;
}>;

export type TargetHealthObservationBudgets = Readonly<{
  /** Aggregate limits across both complete health scans and the two node fences. */
  maxPages?: number;
  maxRecords?: number;
  maxBytes?: number;
  maxCalls?: number;
  pageSize?: number;
}>;

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const targetFields = new Set(['id', 'target', 'weight', 'upstream', 'tags', 'created_at']);
const defaults = { maxPages: 20, maxRecords: 2000, maxBytes: 4 * 1024 * 1024, maxCalls: 22, pageSize: 100 };
const ceilings = { maxPages: 100, maxRecords: 10000, maxBytes: 32 * 1024 * 1024, maxCalls: 102, pageSize: 1000 };
const closed = (code: string): ConflictException => new ConflictException({ code,
  message: code==='TARGET_HEALTH_CHECKS_DISABLED'
    ?'当前目标未启用健康检查，无法核验健康置位；请先配置主动或被动健康检查并刷新当前节点状态'
    :'目标健康状态无法完整核验；请检查当前 Admin 节点和目标配置' });

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function exact(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function nonnegativeWeight(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function addressName(value: unknown): value is string {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > 254) return false;
  if (isIP(value)) return true;
  const hostname = value.endsWith('.') ? value.slice(0, -1) : value;
  return hostname.length > 0 && hostname.length <= 253 && hostname.split('.').every(label => /^[a-z\d_](?:[a-z\d_-]{0,61}[a-z\d_])?$/i.test(label));
}

/** Kong 1.5.1 decorates the row with lua-resty-dns-client 4.1.2 host:getStatus().
 * DNS SRV addresses can contain names, different ports and weights above the
 * configured Target weight. They are diagnostics, never replacement identity. */
function healthData(value: unknown, target: Record<string, unknown>): boolean {
  if (!exact(value, ['host', 'port', 'weight', 'nodeWeight', 'addresses'])
    || typeof value.host !== 'string' || !value.host.length || Buffer.byteLength(value.host) > 512
    || !Number.isInteger(value.port) || Number(value.port) < 1 || Number(value.port) > 65535
    || value.nodeWeight !== target.weight
    || !exact(value.weight, ['total', 'available', 'unavailable'])
    || !nonnegativeWeight(value.weight.total) || !nonnegativeWeight(value.weight.available) || !nonnegativeWeight(value.weight.unavailable)
    || value.weight.available + value.weight.unavailable !== value.weight.total
    || !Array.isArray(value.addresses) || value.addresses.length > 10000) return false;
  const address = String(target.target), separator = address.lastIndexOf(':'), port = address.slice(separator + 1);
  if (separator < 1 || !/^\d{1,5}$/.test(port) || address.slice(0, separator) !== value.host || Number(port) !== value.port) return false;
  let total = 0, available = 0, healthy = false, unhealthy = false, off = false;
  for (const entry of value.addresses) {
    if (!exact(entry, ['ip', 'port', 'health', 'weight']) || !addressName(entry.ip)
      || !Number.isInteger(entry.port) || Number(entry.port) < 1 || Number(entry.port) > 65535
      || !nonnegativeWeight(entry.weight) || typeof entry.health !== 'string' || !['HEALTHY', 'UNHEALTHY', 'HEALTHCHECKS_OFF'].includes(entry.health)) return false;
    total += entry.weight;
    if (!Number.isSafeInteger(total)) return false;
    if (entry.health === 'HEALTHY') { healthy = true; available += entry.weight; }
    else if (entry.health === 'UNHEALTHY') unhealthy = true;
    else off = true;
  }
  if (total !== value.weight.total || off && (healthy || unhealthy)) return false;
  if (!off && (available !== value.weight.available || total - available !== value.weight.unavailable)) return false;
  const observed = healthy ? 'HEALTHY' : unhealthy ? 'UNHEALTHY' : value.addresses.length ? 'HEALTHCHECKS_OFF' : 'DNS_ERROR';
  return target.health === observed;
}

/** Strict native configuration view. Only the health endpoint's validated
 * `health`/`data` decorations may be removed from this configuration HMAC. */
function targetConfiguration(value: unknown, upstreamId: string, withHealth: boolean): Record<string, unknown> {
  if (!object(value) || Object.keys(value).some(key => !targetFields.has(key) && !(withHealth && (key === 'health' || key === 'data')))
    || Object.values(value).some(item => item === undefined)
    || typeof value.id !== 'string' || !uuid.test(value.id)
    || typeof value.target !== 'string' || !value.target.length || Buffer.byteLength(value.target) > 512
    || !Number.isInteger(value.weight) || Number(value.weight) < 0 || Number(value.weight) > 1000
    || !object(value.upstream) || Object.keys(value.upstream).length !== 1 || value.upstream.id !== upstreamId
    || typeof value.created_at !== 'number' || !Number.isFinite(value.created_at) || value.created_at < 0
    || value.tags !== undefined && value.tags !== null && (!Array.isArray(value.tags) || value.tags.length > 1000
      || value.tags.some(tag => typeof tag !== 'string' || !tag.length || Buffer.byteLength(tag) > 1024))
    || withHealth && (typeof value.health !== 'string' || !value.health.length || Buffer.byteLength(value.health) > 128
      || Object.hasOwn(value, 'data') && !healthData(value.data, value))) {
    throw closed('TARGET_HEALTH_NATIVE_ROW_INVALID');
  }
  const { health: _health, data: _data, ...configuration } = value;
  return configuration;
}

/** Checks a sealed fact's content only. It does not prove that a GET occurred,
 * mint current read authority, or make the prior override recoverable. */
export function assertTargetHealthObservation(
  value: unknown,
  expected: Readonly<{ upstreamId: string; target: Readonly<Record<string, unknown>> }>,
  secrets: Pick<SecretService, 'fingerprint'>,
): TargetHealthObservation {
  const keys = ['version', 'kind', 'upstreamId', 'targetId', 'targetAddress', 'nodeId', 'health',
    'targetRow', 'targetHmac', 'nodeScope', 'recoverableOverride', 'observationHmac'];
  if (!object(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))
    || value.version !== 1 || value.kind !== 'kong-1.5-target-health-observation'
    || !expected || typeof expected.upstreamId !== 'string' || !uuid.test(expected.upstreamId)
    || value.upstreamId !== expected.upstreamId || value.nodeScope !== 'current_admin_node'
    || value.recoverableOverride !== false || typeof value.nodeId !== 'string' || !value.nodeId.length || Buffer.byteLength(value.nodeId) > 256
    || value.health !== 'HEALTHY' && value.health !== 'UNHEALTHY'
    || typeof value.targetHmac !== 'string' || !/^[a-f0-9]{64}$/.test(value.targetHmac)
    || typeof value.observationHmac !== 'string' || !/^[a-f0-9]{64}$/.test(value.observationHmac)) {
    throw closed('TARGET_HEALTH_OBSERVATION_INVALID');
  }
  const original = targetConfiguration(expected.target, expected.upstreamId, false);
  const observed = targetConfiguration(value.targetRow, expected.upstreamId, true);
  if (value.targetId !== original.id || value.targetAddress !== original.target
    || !object(value.targetRow) || value.targetRow.health !== value.health
    || secrets.fingerprint(original) !== value.targetHmac || secrets.fingerprint(observed) !== value.targetHmac) {
    throw closed('TARGET_HEALTH_TARGET_CHANGED');
  }
  const { observationHmac, ...facts } = value;
  if (secrets.fingerprint(facts) !== observationHmac) throw closed('TARGET_HEALTH_OBSERVATION_INVALID');
  return immutableJson(value) as TargetHealthObservation;
}

/** Bounded real GET reader only. It grants no permit and does not translate
 * observed status into evidence of a reversible prior manual override.
 * Two complete scans prevent a pagination tail or changing status from being
 * silently accepted. The caller must run it under its genuine read authority. */
export async function readTargetHealthObservation(
  kong: Pick<KongService, 'request' | 'list'>,
  secrets: Pick<SecretService, 'fingerprint'>,
  input: TargetHealthObservationInput,
  options: TargetHealthObservationBudgets = {},
): Promise<TargetHealthObservation> {
  const limits = { ...defaults, ...options };
  if (Object.keys(options).some(key => !(key in defaults))
    || Object.entries(limits).some(([key, value]) => !Number.isInteger(value) || value < 1 || value > ceilings[key as keyof typeof ceilings])
    || limits.maxPages < 2 || limits.maxCalls < 4) throw closed('TARGET_HEALTH_READ_BUDGET_INVALID');
  if (!input || typeof input.clusterId !== 'string' || !uuid.test(input.clusterId)
    || typeof input.upstreamId !== 'string' || !uuid.test(input.upstreamId)) throw closed('TARGET_HEALTH_SCOPE_INVALID');

  const clusterId = input.clusterId, upstreamId = input.upstreamId;
  const original = immutableJson(targetConfiguration(input.target, upstreamId, false));
  const targetId = original.id as string, targetAddress = original.target as string;
  const targetHmac = secrets.fingerprint(original);
  const path = `/upstreams/${upstreamId}/health`;
  let calls = 0, pages = 0, records = 0, bytes = 0;
  const accountCall = (): void => { if (++calls > limits.maxCalls) throw closed('TARGET_HEALTH_READ_BUDGET_EXCEEDED'); };
  const snapshot = <T>(value: T): T => {
    let encoded: string | undefined;
    try { encoded = JSON.stringify(value); } catch { throw closed('TARGET_HEALTH_RESPONSE_INVALID'); }
    if (encoded === undefined) throw closed('TARGET_HEALTH_RESPONSE_INVALID');
    if ((bytes += Buffer.byteLength(encoded)) > limits.maxBytes) throw closed('TARGET_HEALTH_READ_BUDGET_EXCEEDED');
    return immutableJson(JSON.parse(encoded)) as T;
  };
  const root = async (): Promise<{ nodeId: string; version: string }> => {
    accountCall();
    const response: unknown = snapshot(await kong.request(clusterId, 'GET', '/'));
    if (!object(response) || typeof response.version !== 'string' || !/^1\.5\.\d+$/.test(response.version)) throw closed('TARGET_HEALTH_KONG_VERSION_UNSUPPORTED');
    if (response.console_permission_projection) throw closed('TARGET_HEALTH_NODE_UNVERIFIABLE');
    if (typeof response.node_id !== 'string' || !response.node_id.length || Buffer.byteLength(response.node_id) > 256) throw closed('TARGET_HEALTH_NODE_ID_UNAVAILABLE');
    return { nodeId: response.node_id, version: response.version };
  };
  const scan = async (): Promise<{ selected: Readonly<Record<string, unknown>>; collectionHmac: string }> => {
    const rows: Readonly<Record<string, unknown>>[] = [], ids = new Set<string>(), addresses = new Set<string>(), cursors = new Set<string>();
    let cursor: string | undefined, selected: Readonly<Record<string, unknown>> | undefined;
    for (;;) {
      if (++pages > limits.maxPages) throw closed('TARGET_HEALTH_READ_BUDGET_EXCEEDED');
      accountCall();
      const page = snapshot(await kong.list(clusterId, path, { size: limits.pageSize }, cursor, 'target-health-observation'));
      if (!object(page) || !Array.isArray(page.items) || page.console_permission_projection
        || page.items.length > limits.pageSize || page.size !== limits.pageSize
        || page.nextCursor !== null && (typeof page.nextCursor !== 'string' || !page.nextCursor.length || Buffer.byteLength(page.nextCursor) > 16384)) {
        throw closed('TARGET_HEALTH_MEMBERSHIP_INCOMPLETE');
      }
      if ((records += page.items.length) > limits.maxRecords) throw closed('TARGET_HEALTH_READ_BUDGET_EXCEEDED');
      for (const row of page.items) {
        const configuration = targetConfiguration(row, upstreamId, true);
        const id = configuration.id as string, address = configuration.target as string;
        if (ids.has(id.toLowerCase()) || addresses.has(address.toLowerCase())) throw closed('TARGET_HEALTH_MEMBERSHIP_AMBIGUOUS');
        ids.add(id.toLowerCase()); addresses.add(address.toLowerCase()); rows.push(row);
        if (id === targetId) {
          if (address !== targetAddress || secrets.fingerprint(configuration) !== targetHmac) throw closed('TARGET_HEALTH_TARGET_CHANGED');
          selected = row;
        } else if (address === targetAddress) throw closed('TARGET_HEALTH_TARGET_CHANGED');
      }
      if (page.nextCursor === null) break;
      if (!page.items.length || cursors.has(page.nextCursor)) throw closed('TARGET_HEALTH_CURSOR_STALLED');
      cursors.add(page.nextCursor); cursor = page.nextCursor;
    }
    if (!selected) throw closed('TARGET_HEALTH_TARGET_ABSENT');
    if (selected.health === 'HEALTHCHECKS_OFF') throw closed('TARGET_HEALTH_CHECKS_DISABLED');
    if (selected.health !== 'HEALTHY' && selected.health !== 'UNHEALTHY') throw closed('TARGET_HEALTH_STATE_UNVERIFIABLE');
    rows.sort((left, right) => String(left.id) < String(right.id) ? -1 : String(left.id) > String(right.id) ? 1 : 0);
    return { selected, collectionHmac: secrets.fingerprint(rows) };
  };

  const beforeNode = await root(), first = await scan(), second = await scan(), afterNode = await root();
  if (beforeNode.nodeId !== afterNode.nodeId || beforeNode.version !== afterNode.version) throw closed('TARGET_HEALTH_NODE_CHANGED');
  if (first.collectionHmac !== second.collectionHmac) throw closed('TARGET_HEALTH_READ_RACE');
  const facts = { version: 1 as const, kind: 'kong-1.5-target-health-observation' as const,
    upstreamId, targetId, targetAddress, nodeId: afterNode.nodeId,
    health: second.selected.health as 'HEALTHY' | 'UNHEALTHY', targetRow: second.selected, targetHmac,
    nodeScope: 'current_admin_node' as const, recoverableOverride: false as const };
  return immutableJson({ ...facts, observationHmac: secrets.fingerprint(facts) });
}
