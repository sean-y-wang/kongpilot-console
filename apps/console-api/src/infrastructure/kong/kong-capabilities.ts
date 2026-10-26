/**
 * Single source of truth for which Kong OSS versions KongPilot supports and
 * which features are available per version. Every former hard-coded
 * `/^1\.5\.\d+$/` gate goes through this table. Mirrored verbatim in
 * packages/contracts/src/kong-capabilities.ts (a unit test keeps them equal).
 *
 * Policy: unsupported features are hidden, never emulated.
 */
export type KongLine = '1.3' | '1.4' | '1.5';
export interface KongCapabilities {
  /** Matched release line, or null when the version is not supported at all. */
  line: KongLine | null;
  /** Version is in a supported line (1.3.x / 1.4.x / 1.5.x). */
  supported: boolean;
  /** Full, tested support (1.5.x); other lines are "limited support". */
  full: boolean;
  /** Admin API reads: probe, entity browse, health, inspection, export. */
  read: boolean;
  /** Entity configuration writes (unknown fields are stripped by schema). */
  write: boolean;
  /** Prometheus metrics scrape. */
  metrics: boolean;
  /** Credentials (key-auth, basic-auth, jwt, ...) accept `tags` (Kong >= 1.4). */
  credentialTags: boolean;
  /** Portal credential issuance; requires credential tags for workspace isolation. */
  portalCredentials: boolean;
  /** Credential import/export in config transfer and workspace migration. */
  credentialTransfer: boolean;
  /** Route simulator semantics verified against this line. */
  routeSimulation: boolean;
  /** Entity fields that do not exist on this line, per entity. */
  unsupportedFields: Record<string, string[]>;
}

const FIELDS_ADDED: Array<{ entity: string; field: string; since: KongLine }> = [
  { entity: 'routes', field: 'path_handling', since: '1.5' },
  { entity: 'upstreams', field: 'host_header', since: '1.4' },
];
const ORDER: KongLine[] = ['1.3', '1.4', '1.5'];

export function kongLine(version: string | null | undefined): KongLine | null {
  const m = /^1\.([345])\.\d+$/.exec(version ?? '');
  return m ? (`1.${m[1]}` as KongLine) : null;
}

export function kongCapabilities(version: string | null | undefined): KongCapabilities {
  const line = kongLine(version);
  const at = line ? ORDER.indexOf(line) : -1;
  const since = (l: KongLine) => at >= ORDER.indexOf(l);
  const unsupportedFields: Record<string, string[]> = {};
  if (line) for (const f of FIELDS_ADDED) if (!since(f.since)) (unsupportedFields[f.entity] ??= []).push(f.field);
  const ok = line !== null;
  return {
    line, supported: ok, full: line === '1.5', read: ok, write: ok, metrics: ok,
    credentialTags: ok && since('1.4'), portalCredentials: ok && since('1.4'), credentialTransfer: ok && since('1.4'),
    routeSimulation: line === '1.5', unsupportedFields,
  };
}

/** Drop-in replacement for the old `/^1\.5\.\d+$/.test(version)` gate. */
export function isSupportedKong(version: string | null | undefined): boolean { return kongLine(version) !== null; }

/** Remove fields the target Kong line does not understand before a write. */
export function stripUnsupportedFields<T extends Record<string, unknown>>(entity: string, body: T, version: string | null | undefined): T {
  const drop = kongCapabilities(version).unsupportedFields[entity];
  if (!drop?.length || !body || typeof body !== 'object') return body;
  const out: Record<string, unknown> = { ...body };
  for (const f of drop) delete out[f];
  return out as T;
}

/** SQL fragment equivalent of isSupportedKong for queries. */
export const SUPPORTED_KONG_SQL_REGEX = '^1\\.[345]\\.[0-9]+$';
