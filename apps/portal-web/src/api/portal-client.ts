import type { Developer, PortalReceipt, PortalScope } from './types';
export interface PortalIdentity extends PortalScope { id: string; }
export interface PortalRecovery extends PortalScope { actorId: string; idempotencyKey: string; createdAt: string; state: string; }
export class PortalError extends Error { constructor(message: string, public status: number, public code?: string, public requestId?: string, public recovery?: PortalRecovery) { super(message); this.name = 'PortalError'; } }
let identity: PortalIdentity | undefined, csrf = '', activeScope: PortalScope | undefined, generation = 0, transitions = 0, refreshing: Promise<void> | undefined;
export function validId(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value); }
export function samePortalScope(a?: PortalScope, b?: PortalScope) { return !!a && !!b && a.clusterId === b.clusterId && a.workspaceId === b.workspaceId; }
export function getPortalIdentity() { return identity; }
export function getPortalScope() { return activeScope; }
export function setPortalIdentity(value?: PortalIdentity) { if (identity?.id !== value?.id || !samePortalScope(identity, value)) generation++; identity = value; }
export function setPortalScope(value?: PortalScope) { if (!samePortalScope(activeScope, value)) { generation++; activeScope = value; identity = undefined; csrf = ''; } }
export function setPortalCsrf(value: string) { csrf = value; }
export function clearPortalSession() { generation++; identity = undefined; csrf = ''; }
export function portalKey() { if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID(); const bytes = new Uint8Array(16); if (!globalThis.crypto?.getRandomValues) throw new PortalError('浏览器不支持安全随机数，请使用受支持浏览器。', 0, 'SECURE_RANDOM_REQUIRED'); crypto.getRandomValues(bytes); bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128; const s = [...bytes].map(n => n.toString(16).padStart(2, '0')).join(''); return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`; }
export function portalPath(path: string, scope?: PortalScope) { if (!path.startsWith('/') || path.startsWith('//') || /[\\\r\n#]/.test(path)) throw new PortalError('门户请求地址无效。', 0, 'INVALID_PORTAL_PATH'); const url = new URL(path, 'https://portal.local'); if (scope) { if (!validId(scope.clusterId) || !validId(scope.workspaceId)) throw new PortalError('门户租户范围无效。', 0, 'INVALID_PORTAL_SCOPE'); url.searchParams.set('clusterId', scope.clusterId); url.searchParams.set('workspaceId', scope.workspaceId); } return `/api/v1/portal${url.pathname}${url.search}`; }
function changed() { return new PortalError('账号或门户租户已切换，请重新发起请求。', 401, 'PORTAL_SESSION_CHANGED'); }
function event(name: string, detail?: unknown) { if (typeof window !== 'undefined') window.dispatchEvent(new CustomEvent(name, { detail })); }
function unknown(error: PortalError) { if (error.recovery && identity?.id === error.recovery.actorId && samePortalScope(identity, error.recovery)) event('portal:uncertain', error.recovery); return error; }
async function refresh(scope: PortalScope, actor: PortalIdentity | undefined, epoch: number) {
  if (!refreshing) refreshing = (async () => {
    if (transitions || generation !== epoch || identity?.id !== actor?.id || !samePortalScope(activeScope, scope)) throw changed();
    if (!csrf) { const nonce = await portalRequest<{ csrfToken: string }>('/auth/csrf', scope, {}, false); if (transitions || generation !== epoch || identity?.id !== actor?.id || !samePortalScope(activeScope, scope)) throw changed(); csrf = nonce.csrfToken; }
    const session = await portalWrite<{ developer: Developer; csrfToken: string }>('/auth/refresh', scope, {}, 'POST', false);
    if (generation !== epoch || identity?.id !== actor?.id || !samePortalScope(session.developer, scope) || actor && session.developer.id !== actor.id) throw changed();
    csrf = session.csrfToken;
  })().finally(() => { refreshing = undefined; });
  await refreshing;
}
export async function portalRequest<T>(path: string, scope?: PortalScope, options: RequestInit = {}, privateRequest = true, retried = false): Promise<T> {
  const actor = identity && { ...identity }, epoch = generation;
  if (privateRequest && (!scope || !samePortalScope(activeScope, scope))) throw changed();
  const check = () => { if (privateRequest && (generation !== epoch || identity?.id !== actor?.id || !samePortalScope(activeScope, scope))) throw changed(); };
  const method = (options.method ?? 'GET').toUpperCase(), writing = !['GET', 'HEAD', 'OPTIONS'].includes(method), auth = path.split('?')[0].startsWith('/auth/');
  const secretRead = /\/credentials\/[^/]+\/reveal$/.test(path.split('?')[0]);
  const persistent = writing && !secretRead && (!auth || /^\/auth\/(?:me|password)$/.test(path.split('?')[0]));
  const headers = new Headers(options.headers); headers.set('Accept', 'application/json'); if (options.body) headers.set('Content-Type', 'application/json');
  if (writing) { if (!headers.has('X-Idempotency-Key')) headers.set('X-Idempotency-Key', portalKey()); if (csrf) headers.set('X-Portal-CSRF', csrf); }
  const recovery = persistent && actor && scope ? { ...scope, actorId: actor.id, idempotencyKey: headers.get('X-Idempotency-Key')!, createdAt: new Date().toISOString(), state: 'uncertain' } : undefined;
  let response: Response;
  try { response = await fetch(portalPath(path, scope), { ...options, method, headers, credentials: 'same-origin', cache: 'no-store' }); }
  catch (error) { if (options.signal?.aborted && !recovery) throw new DOMException('请求已取消', 'AbortError'); check(); if (recovery) throw unknown(new PortalError('响应中断，执行结果待核验。请保留原操作标识，避免重复提交。', 0, 'PORTAL_WRITE_UNKNOWN', undefined, recovery)); throw new PortalError('门户服务暂时无法连接。', 0, 'PORTAL_NETWORK_ERROR'); }
  let body: any; try { body = await response.json(); } catch { body = undefined; }
  check();
  if (response.status === 401 && privateRequest && (!auth || path.startsWith('/auth/me'))) {
    if (transitions || generation !== epoch || identity?.id !== actor?.id) throw changed();
    if (!retried && scope) { try { await refresh(scope, actor, epoch); } catch (error) { if (generation !== epoch || identity?.id !== actor?.id) throw changed(); if (actor) event('portal:expired', actor); throw error; } check(); return portalRequest<T>(path, scope, { ...options, headers }, privateRequest, true); }
    if (actor) event('portal:expired', actor);
  }
  if (!response.ok || !body || typeof body !== 'object') {
    const isUnknown = !!recovery && ([502, 504].includes(response.status) || response.ok && !body || ['uncertain', 'partial', 'running'].includes(body?.error?.state));
    const error = new PortalError(isUnknown ? '执行结果尚未得到完整证明，请先核验原操作。' : typeof body?.error?.message === 'string' ? body.error.message.slice(0, 400) : `请求未完成（HTTP ${response.status}）`, response.status, isUnknown ? 'PORTAL_WRITE_UNKNOWN' : body?.error?.code ?? 'PORTAL_REQUEST_FAILED', body?.meta?.requestId, isUnknown ? recovery : undefined);
    throw isUnknown ? unknown(error) : error;
  }
  return ('data' in body ? body.data : body) as T;
}
export function portalWrite<T>(path: string, scope: PortalScope, body: Record<string, unknown>, method = 'POST', privateRequest = true, key?: string) { return portalRequest<T>(path, scope, { method, body: JSON.stringify({ ...body, clusterId: scope.clusterId, workspaceId: scope.workspaceId }), headers: key ? { 'X-Idempotency-Key': key } : undefined }, privateRequest); }
export async function portalLogin(scope: PortalScope, username: string, password: string) {
  if (transitions) throw new PortalError('登录已在进行中，请稍候。', 0, 'PORTAL_LOGIN_IN_PROGRESS'); transitions++;
  try {
    if (refreshing) await refreshing.catch(() => undefined);
    if (!samePortalScope(activeScope, scope)) throw changed();
    const epoch = generation; const token = await portalRequest<{ csrfToken: string }>('/auth/csrf', scope, {}, false); if (epoch !== generation || !samePortalScope(activeScope, scope)) throw changed(); csrf = token.csrfToken;
    const result = await portalWrite<{ developer: Developer; csrfToken: string }>('/auth/login', scope, { username, password }, 'POST', false);
    if (epoch !== generation || !samePortalScope(activeScope, scope)) throw changed(); csrf = result.csrfToken;
    const me = await portalRequest<Developer>('/auth/me', scope, {}, false);
    if (!validId(me.id) || me.status !== 'active' || !result.csrfToken || result.developer.id !== me.id || !samePortalScope(me, scope) || !samePortalScope(activeScope, scope)) throw changed();
    setPortalIdentity(me); csrf = result.csrfToken; return me;
  } finally { transitions--; }
}
export const portalRecoveryStorageKey = 'kongos.portal.recovery';
export function safePortalRecoveries(value: unknown, actor: PortalIdentity, now = Date.now()): PortalRecovery[] { if (!Array.isArray(value)) return []; return value.flatMap((r: any) => { const age = now - Date.parse(r?.createdAt); return r && r.actorId === actor.id && samePortalScope(r, actor) && validId(r.clusterId) && validId(r.workspaceId) && validId(r.idempotencyKey) && Number.isFinite(age) && age >= 0 && age < 86400_000 ? [{ actorId: actor.id, clusterId: actor.clusterId, workspaceId: actor.workspaceId, idempotencyKey: r.idempotencyKey, createdAt: r.createdAt, state: 'uncertain' }] : []; }).slice(-30); }
export function portalReceiptComplete(receipt: PortalReceipt, reference: PortalRecovery) { return !!receipt && validId(receipt.id) && receipt.clusterId === reference.clusterId && receipt.workspaceId === reference.workspaceId && (!receipt.idempotencyKey || receipt.idempotencyKey === reference.idempotencyKey) && ['succeeded', 'failed'].includes(receipt.state) && receipt.remoteCompleted === true; }

export async function portalLogout(scope: PortalScope) { if (transitions) throw changed(); transitions++; try { if (refreshing) await refreshing.catch(() => undefined); if (!samePortalScope(activeScope, scope)) throw changed(); await portalWrite('/auth/logout', scope, {}); clearPortalSession(); } finally { transitions--; } }
