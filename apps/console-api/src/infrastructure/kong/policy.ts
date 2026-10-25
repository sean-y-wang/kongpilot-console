import { BadRequestException, ForbiddenException } from '@nestjs/common';

export const ENTITIES = ['services', 'routes', 'consumers', 'plugins', 'certificates', 'ca_certificates', 'snis', 'upstreams'] as const;
const CREDENTIALS = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
const SCHEMAS = [...ENTITIES, 'targets', 'keyauth_credentials', 'basicauth_credentials', 'jwt_secrets', 'oauth2_credentials', 'hmacauth_credentials', 'acls'];
/** Kong 1.5 global credential list path -> consumer-scoped credential kind. */
export const GLOBAL_CREDENTIAL_COLLECTIONS: Readonly<Record<string, string>> = Object.freeze({
  'key-auths': 'key-auth', 'basic-auths': 'basic-auth', jwts: 'jwt', oauth2: 'oauth2', 'hmac-auths': 'hmac-auth', acls: 'acls' });
export const GLOBAL_CREDENTIAL_PATHS: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(Object.entries(GLOBAL_CREDENTIAL_COLLECTIONS).map(([path, kind]) => [kind, `/${path}`])));
const CRUD = new Set(['GET', 'POST', 'PATCH', 'PUT', 'DELETE']);

/** Explicit 1.5 paths. This is deliberately not a general Admin API passthrough. */
export function assertKongPath(method: string, path: string, metrics = false): void {
  let decodedSegments: string[];
  try { decodedSegments = path.split('/').map(part => decodeURIComponent(part)); }
  catch { throw new BadRequestException({ code: 'INVALID_KONG_PATH', message: '无效的网关路径编码' }); }
  if (!path.startsWith('/') || path.includes('//') || path.includes('?') || path.includes('#') || path.includes('\\') || /%2f|%5c|%00/i.test(path) || decodedSegments.some(s => s === '.' || s === '..' || /[\\/\u0000]/.test(s))) {
    throw new BadRequestException({ code: 'INVALID_KONG_PATH', message: '无效的网关路径' });
  }
  const parts = path.split('/').filter(Boolean);
  const safe = parts.every(part => /^[A-Za-z0-9._~%:@+-]+$/.test(part));
  let valid = false;
  if (!parts.length) valid = method === 'GET';
  else if (['status', 'tags'].includes(parts[0]) && parts.length === 1) valid = method === 'GET';
  else if (parts[0] === 'metrics' && parts.length === 1) valid = metrics && method === 'GET';
  else if (parts[0] === 'cache' && parts.length <= 2) valid = ['GET', 'DELETE'].includes(method);
  else if (parts[0] === 'schemas' && parts.length === 2) valid = method === 'GET' && SCHEMAS.includes(parts[1] as any);
  else if (parts[0] === 'plugins' && parts[1] === 'enabled' && parts.length === 2) valid = method === 'GET';
  // Kong 1.5 global, paged credential collections. Read-only: credentials are created/changed only
  // through their parent Consumer path.
  else if (parts.length === 1 && Object.hasOwn(GLOBAL_CREDENTIAL_COLLECTIONS, parts[0])) valid = method === 'GET';
  else if (parts[0] === 'plugins' && parts[1] === 'schema' && parts.length === 3) valid = method === 'GET';
  else if ((ENTITIES as readonly string[]).includes(parts[0])) {
    if (parts.length === 1) valid = ['GET', 'POST'].includes(method);
    if (parts.length === 2) valid = ['GET', 'PATCH', 'PUT', 'DELETE'].includes(method);
    if (parts[0] === 'services' && parts.length === 3 && parts[2] === 'routes') valid = ['GET', 'POST'].includes(method);
    if (parts[0] === 'routes' && parts.length === 3 && parts[2] === 'service') valid = ['GET', 'PATCH', 'PUT', 'DELETE'].includes(method);
    if (parts[0] === 'plugins' && parts.length === 3 && ['service', 'route', 'consumer'].includes(parts[2])) valid = method === 'GET';
    if (parts[0] === 'certificates' && parts.length === 3 && parts[2] === 'snis') valid = ['GET', 'POST'].includes(method);
    if (parts[0] === 'consumers' && parts.length >= 3 && CREDENTIALS.includes(parts[2])) {
      valid = parts.length === 3 ? ['GET', 'POST'].includes(method) : parts.length === 4 && ['GET', 'PATCH', 'PUT', 'DELETE'].includes(method);
    }
    if (parts[0] === 'upstreams' && parts.length === 3 && parts[2] === 'health') valid = method === 'GET';
    if (parts[0] === 'upstreams' && parts[2] === 'targets') {
      if (parts.length === 3) valid = ['GET', 'POST'].includes(method);
      if (parts.length === 4 && parts[3] === 'all') valid = method === 'GET';
      if (parts.length === 4 && parts[3] !== 'all') valid = ['GET', 'DELETE'].includes(method);
      if (parts.length === 5 && ['healthy', 'unhealthy'].includes(parts[4])) valid = method === 'POST';
    }
  }
  if (!CRUD.has(method) || !safe || !valid) throw new ForbiddenException({ code: 'KONG_ENDPOINT_FORBIDDEN', message: `Kong 1.5 适配层不允许 ${method} ${path}` });
}

export function entityForPath(path: string): string | null {
  const parts = path.split('/').filter(Boolean);
  if (parts[0] === 'consumers' && parts[2]) return ({ 'key-auth': 'keyauth_credentials', 'basic-auth': 'basicauth_credentials', jwt: 'jwt_secrets', oauth2: 'oauth2_credentials', 'hmac-auth': 'hmacauth_credentials', acls: 'acls' } as Record<string, string>)[parts[2]] || null;
  if (parts[0] === 'upstreams' && parts[2] === 'targets') return 'targets';
  if (parts[0] === 'services' && parts[2] === 'routes') return 'routes';
  if (parts[0] === 'certificates' && parts[2] === 'snis') return 'snis';
  if (parts[0] === 'routes' && parts[2] === 'service') return 'services';
  return (ENTITIES as readonly string[]).includes(parts[0]) ? parts[0] : null;
}

export function validateQuery(query: Record<string, string | number>): void {
  for (const [key, value] of Object.entries(query)) {
    if (!['size', 'offset', 'tags'].includes(key)) throw new BadRequestException({ code: 'INVALID_KONG_QUERY', message: `不支持的查询参数 ${key}` });
    if (key === 'size' && (!Number.isInteger(Number(value)) || Number(value) < 1 || Number(value) > 1000)) throw new BadRequestException({ code: 'INVALID_PAGE_SIZE', message: '分页大小必须在 1–1000 之间' });
    if (String(value).length > 8192) throw new BadRequestException({ code: 'INVALID_KONG_QUERY', message: '查询参数过长' });
  }
}
