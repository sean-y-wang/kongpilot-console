import { newIdempotencyKey } from './idempotency';
import { canonicalId, type RecoveryKind, type RecoveryScope } from './workspace-scope';
import type { ConfigurationAbandonmentIntent } from '../features/m8.types';

let csrfToken = '';
let refreshInFlight: Promise<void> | undefined;
let currentActorId: string | undefined;
let sessionTransitions = 0;

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string,
    public fields?: Record<string, unknown>,
    public requestId?: string,
    public recovery?: { operationId?: string; entryId?: string; state?: string; idempotencyKey?: string; clusterId?: string; workspaceId?: string; domain?: 'iam'; kind?: RecoveryKind; scope?: RecoveryScope; originalJobId?: string; originalJobKey?: string; abandonmentIntent?: ConfigurationAbandonmentIntent },
  ) { super(message); this.name = 'ApiError'; }
}

export function setCsrfToken(value: string) { csrfToken = value; }
export function setApiActorId(value?: string) { currentActorId = value; }
export function getApiActorId() { return currentActorId; }
export function beginSessionTransition() {
  sessionTransitions += 1;
  return () => { sessionTransitions -= 1; };
}
export async function awaitPendingSessionRefresh() {
  const pending = refreshInFlight;
  if (pending) await pending.catch(() => undefined);
}
function raised(error: ApiError, actorId?: string): ApiError {
  if (error.recovery?.idempotencyKey && (error.recovery.domain === 'iam' || error.recovery.clusterId && error.recovery.workspaceId || ['notifications', 'audit-export', 'audit-global-export'].includes(error.recovery.kind ?? '')) && (error.recovery.state === 'uncertain' || !!error.recovery.kind && ['partial', 'running'].includes(error.recovery.state ?? '') || /UNCERTAIN|UNKNOWN/.test(error.code ?? ''))) window.dispatchEvent(new CustomEvent('kongos:mutation-uncertain', { detail: { actorId, error } }));
  return error;
}

async function refreshSession() {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      if (!csrfToken) {
        const result = await api<{ csrfToken: string }>('/auth/csrf');
        if (!result.csrfToken) throw new ApiError('登录会话已失效，请重新登录。', 401, 'SESSION_EXPIRED');
        setCsrfToken(result.csrfToken);
      }
      await post('/auth/refresh');
    })().finally(() => { refreshInFlight = undefined; });
  }
  return refreshInFlight;
}

export async function api<T>(path: string, options: RequestInit = {}, retried = false, download = false, abandon?: { originalJobKey: string; intent: ConfigurationAbandonmentIntent }): Promise<T> {
  const originalActorId = currentActorId;
  const method = options.method ?? 'GET';
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase()) && !headers.has('X-Idempotency-Key')) headers.set('X-Idempotency-Key', newIdempotencyKey());
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase()) && csrfToken && !headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', csrfToken);
  const writing = !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase());
  const toolboxProbe = method.toUpperCase() === 'POST' && /^\/clusters\/[^/]+\/toolbox\/probes(?:\?|$)/.test(path);
  const reviewing = method.toUpperCase() === 'POST' && /^\/clusters\/[^/]+\/(?:workspace-migrations\/(?:plan|[0-9a-f-]{36}\/reconcile)|mutations\/[0-9a-f-]{36}\/reconcile|configuration\/plans\/[0-9a-f-]{36}\/reconcile|inventory\/refresh|authorization\/entity-capabilities|toolbox\/routes\/debug)(?:\?|$)/i.test(path);
  const reviewInterrupted = (status: number) => new ApiError(path.includes('/inventory/refresh') ? '索引同步响应中断，可重新读取统计或再次同步；此操作不修改网关配置。' : '预览或核验响应中断，可重新获取状态或核验；此操作不修改网关配置。', status, 'NETWORK_REVIEW_INTERRUPTED');
  const params = new URL(path, 'http://console.local').searchParams;
  const personalWrite = /^\/notifications(?:\/|$)/.test(path);
  const originalClusterId = path.match(/^\/clusters\/([^/?]+)/)?.[1] ?? (personalWrite ? params.get('clusterId') ?? undefined : undefined);
  const originalWorkspaceId = params.get('workspaceId') ?? undefined;
  const pathname = path.split('?')[0];
  const abandonMatch = pathname.match(/^\/clusters\/([^/]+)\/configuration\/jobs\/([^/]+)\/abandon$/);
  // This one metadata operation does not create a configuration job. Keep its
  // original job anchor, and never silently refresh/replay its POST on a 401.
  const originalAbandonJobId = method.toUpperCase() === 'POST' && abandonMatch && canonicalId(abandonMatch[1]) === abandonMatch[1] && canonicalId(abandonMatch[2]) === abandonMatch[2]
    && !path.includes('#') && [...params.keys()].every(name => name === 'workspaceId') && params.getAll('workspaceId').length === 1 && canonicalId(originalWorkspaceId) === originalWorkspaceId ? abandonMatch[2] : undefined;
  const setupWrite = method.toUpperCase() === 'POST' && /^\/clusters\/[^/]+\/vitals\/setup$/.test(pathname);
  const portalWrite = /^\/clusters\/[^/]+\/portal(?:\/|$)/.test(pathname);
  const workflowWrite = /^\/clusters\/[^/]+\/workflows(?:\/|$)/.test(pathname) || method.toUpperCase() === 'POST' && /^\/clusters\/[^/]+\/workspace-migrations\/[0-9a-f-]{36}\/submit$/i.test(pathname);
  const eventsWrite = /^\/clusters\/[^/]+\/events(?:\/|$)/.test(pathname);
  const governanceRequest = /^\/clusters\/[^/]+\/governance(?:\/|$)/.test(pathname);
  const configurationRequest = governanceRequest || /^\/clusters\/[^/]+\/(?:configuration|snapshots)(?:\/|$)/.test(pathname) || /^\/clusters\/[^/]+\/batches\/plan$/.test(pathname);
  const toolboxWrite = /^\/clusters\/[^/]+\/toolbox\/cache\/invalidate$/.test(pathname);
  const draftWrite = /^\/clusters\/[^/]+\/drafts(?:\/|$)/.test(pathname);
  // These metadata preparations and schedule commands have no native Mutation or
  // workflow by-key receipt. Their feature owns an original-key-only journal;
  // never misroute an interrupted preparation to a made-up native receipt.
  const ownedEntityPreparation = method.toUpperCase() === 'POST' && (/^\/clusters\/[^/]+\/entity-changes\/prepare(?:-scheduled)?$/.test(pathname)
    || /^\/clusters\/[^/]+\/configuration\/plans\/[0-9a-f-]{36}\/durable-submissions$/i.test(pathname)
    || /^\/clusters\/[^/]+\/annotation-changes\/(?:prepare|[0-9a-f-]{36}\/submit)$/i.test(pathname)
    || /^\/clusters\/[^/]+\/entity-schedules\/[0-9a-f-]{36}\/(?:activate|cancel)$/i.test(pathname)
    || /^\/clusters\/[^/]+\/workflows\/[0-9a-f-]{36}\/rollback-prepare$/i.test(pathname));
  const auditExportWrite = method.toUpperCase() === 'POST' && /^\/clusters\/[^/]+\/audit\/exports$/.test(pathname);
  const globalAuditExportWrite = method.toUpperCase() === 'POST' && pathname === '/audit/global/exports';
  const registryWrite = method.toUpperCase() === 'POST' && pathname === '/clusters'
    || ['PATCH', 'DELETE'].includes(method.toUpperCase()) && /^\/clusters\/[^/]+$/.test(pathname)
    || method.toUpperCase() === 'POST' && /^\/clusters\/[^/]+\/(?:probe|test|deactivate)$/.test(pathname)
    || method.toUpperCase() === 'POST' && /^\/clusters\/[^/]+\/data-sources$/.test(pathname)
    || ['PATCH', 'DELETE'].includes(method.toUpperCase()) && /^\/clusters\/[^/]+\/data-sources\/[^/]+$/.test(pathname)
    || method.toUpperCase() === 'POST' && /^\/clusters\/[^/]+\/data-sources\/[^/]+\/(?:probe|test|deactivate)$/.test(pathname);
  const writeRecovery = writing && !reviewing && !toolboxProbe && !ownedEntityPreparation ? registryWrite || /^\/iam\//.test(path) ? { idempotencyKey: headers.get('X-Idempotency-Key') ?? undefined, domain: 'iam' as const } : globalAuditExportWrite || personalWrite || originalClusterId ? { idempotencyKey: headers.get('X-Idempotency-Key') ?? undefined, clusterId: originalClusterId, workspaceId: originalWorkspaceId, ...(globalAuditExportWrite ? { kind: 'audit-global-export' as const, scope: 'global' as const } : auditExportWrite ? { kind: 'audit-export' as const, scope: (originalWorkspaceId ? 'workspace' : 'cluster') as RecoveryScope } : personalWrite ? { kind: 'notifications' as const, scope: (originalWorkspaceId ? 'workspace' : originalClusterId ? 'cluster' : 'global') as RecoveryScope } : toolboxWrite ? { kind: 'toolbox' as const, scope: 'workspace' as const } : draftWrite ? { kind: 'drafts' as const, scope: 'workspace' as const } : governanceRequest ? { kind: 'governance' as const, scope: 'workspace' as const } : configurationRequest ? { kind: 'configuration' as const, scope: 'workspace' as const } : eventsWrite ? { kind: 'events' as const } : setupWrite ? { kind: 'vitals-setup' as const } : portalWrite ? { kind: 'portal' as const } : workflowWrite || /^\/clusters\/[^/]+\/entity-changes\/[0-9a-f-]{36}\/submit$/i.test(pathname) ? { kind: 'workflow' as const } : {}) } : undefined : undefined;
  if (writeRecovery && originalAbandonJobId) Object.assign(writeRecovery, { originalJobId: originalAbandonJobId });
  if (writeRecovery && originalAbandonJobId && abandon) Object.assign(writeRecovery, { originalJobKey: abandon.originalJobKey, abandonmentIntent: abandon.intent });
  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, { ...options, method, headers, credentials: 'include' });
  } catch {
    if (toolboxProbe) throw new ApiError('代理探测结果未确认，不会自动重发业务请求。', 0, 'PROBE_RESULT_UNKNOWN');
    if (reviewing) throw reviewInterrupted(0);
    if (writeRecovery) throw raised(new ApiError('写入响应中断，执行结果尚未确认。请先核验原操作，避免重复提交。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { ...writeRecovery, state: 'uncertain' }), originalActorId);
    throw new ApiError('无法连接控制台后端，请检查服务是否已启动。', 0, 'NETWORK_ERROR');
  }
  if (response.ok && download) {
    let blob: Blob;
    try { blob = await boundedDownload(response, originalActorId, options.signal ?? undefined); }
    catch (error) { if (configurationRequest && writeRecovery) throw raised(new ApiError('文件传输中断，请核验原下载请求，不会自动重发。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { ...writeRecovery, state: 'uncertain' }), originalActorId); throw error; }
    if (currentActorId !== originalActorId) throw new ApiError('登录账号已切换，请重新下载。', 401, 'SESSION_CHANGED');
    if (blob.size > 32 * 1024 * 1024) throw new ApiError('导出文件超过下载上限。', 413, 'EXPORT_SIZE_LIMIT');
    return { blob, contentDisposition: response.headers.get('content-disposition'), contentType: response.headers.get('content-type') } as T;
  }
  let payload: any;
  let parsed = false;
  try { payload = await response.json(); parsed = true; }
  catch { payload = {}; }
  if (payload === null || typeof payload !== 'object') { parsed = false; payload = {}; }
  if (!response.ok) {
    if (response.status === 403 && currentActorId === originalActorId) window.dispatchEvent(new CustomEvent('kongos:permission-stale', { detail: { actorId: originalActorId } }));
    if (reviewing && [502, 504].includes(response.status)) throw reviewInterrupted(response.status);
    const canRefresh = !toolboxProbe && !originalAbandonJobId && !['/auth/login', '/auth/refresh', '/auth/csrf'].includes(path) && !/^\/auth\/(?:ldap\/[^/]+\/login|oidc\/[^/]+\/(?:start|callback))(?:\?|$)/.test(path);
    if (response.status === 401 && canRefresh && sessionTransitions > 0) throw new ApiError('登录账号正在切换，请重新发起当前账号的请求。', 401, 'SESSION_CHANGED');
    if (response.status === 401 && !retried && canRefresh) {
      if (currentActorId !== originalActorId) throw new ApiError('登录账号已切换，请重新发起当前账号的请求。', 401, 'SESSION_CHANGED');
      let refreshed = false;
      try {
        await refreshSession();
        refreshed = true;
      } catch {
        if (currentActorId !== originalActorId) throw new ApiError('登录账号已切换，请重新发起当前账号的请求。', 401, 'SESSION_CHANGED');
        window.dispatchEvent(new Event('kongos:session-expired'));
      }
      if (refreshed && currentActorId !== originalActorId) throw new ApiError('登录账号已切换，请重新发起当前账号的请求。', 401, 'SESSION_CHANGED');
      if (refreshed) return api<T>(path, { ...options, headers }, true, download);
    } else if (response.status === 401 && retried) {
      if (currentActorId !== originalActorId) throw new ApiError('登录账号已切换，请重新发起当前账号的请求。', 401, 'SESSION_CHANGED');
      window.dispatchEvent(new Event('kongos:session-expired'));
    }
    if (response.status === 401 && originalAbandonJobId) window.dispatchEvent(new Event('kongos:session-expired'));
    const error = payload.error ?? payload;
    const message = Array.isArray(error.message) ? error.message.join('；') : error.message;
    const unknown = !!writeRecovery && (configurationRequest ? response.status >= 500 : [502, 504].includes(response.status));
    const safeCode = configurationRequest && !/^[A-Z0-9_]{1,100}$/.test(error.code ?? '') ? undefined : error.code;
    const safeState = configurationRequest ? ['uncertain', 'partial', 'running', 'succeeded', 'failed', 'cancelled'].includes(error.state) ? error.state : undefined : error.state;
    const requestId = payload.meta?.requestId ?? error.requestId;
    throw raised(new ApiError(unknown ? '写入响应未送达，执行结果尚未确认。请先核验原操作。' : configurationRequest ? `${governanceRequest ? '治理' : '配置'}请求未完成（HTTP ${response.status}${safeCode ? ` · ${safeCode}` : ''}）。请检查格式、权限与当前配置。` : message ?? `请求失败（HTTP ${response.status}）`, response.status, unknown ? 'WRITE_RESULT_UNKNOWN' : safeCode, configurationRequest ? undefined : error.fields, configurationRequest ? canonicalId(requestId) : requestId, { ...writeRecovery, operationId: configurationRequest ? canonicalId(error.operationId) : error.operationId, entryId: configurationRequest ? canonicalId(error.entryId) : error.entryId, state: unknown ? 'uncertain' : safeState }), originalActorId);
  }
  if (!parsed) {
    if (reviewing) throw reviewInterrupted(response.status);
    if (writeRecovery) throw raised(new ApiError('写入响应无法读取，执行结果尚未确认。请先核验原操作。', response.status, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { ...writeRecovery, state: 'uncertain' }), originalActorId);
    throw new ApiError('控制台响应无法读取，请刷新核验服务状态。', response.status, 'INVALID_RESPONSE');
  }
  return ('data' in payload ? payload.data : payload) as T;
}

export interface AuthenticatedDownload { blob: Blob; contentDisposition: string | null; contentType: string | null; }
async function boundedDownload(response: Response, actor: string | undefined, signal?: AbortSignal): Promise<Blob> {
  const limit = 32 * 1024 * 1024, advertised = Number(response.headers.get('content-length'));
  if (advertised > limit) { await response.body?.cancel(); throw new ApiError('导出文件超过下载上限。', 413, 'EXPORT_SIZE_LIMIT'); }
  if (!response.body) { const blob = await response.blob(); if (blob.size > limit) throw new ApiError('导出文件超过下载上限。', 413, 'EXPORT_SIZE_LIMIT'); return blob; }
  const reader = response.body.getReader(), chunks: Uint8Array[] = []; let bytes = 0;
  try { while (true) { if (signal?.aborted || currentActorId !== actor) throw new ApiError('账号或下载范围已变化，下载已取消。', 409, 'SESSION_CHANGED'); const part = await reader.read(); if (part.done) break; bytes += part.value.byteLength; if (bytes > limit) throw new ApiError('导出文件超过下载上限。', 413, 'EXPORT_SIZE_LIMIT'); chunks.push(part.value); } return new Blob(chunks, { type: response.headers.get('content-type') ?? 'application/octet-stream' }); }
  catch (error) { await reader.cancel().catch(() => undefined); throw error; }
  finally { reader.releaseLock(); }
}
/** Only same-origin, fixed audit-export resources; uses the same single refresh as api(). */
export function apiBlob(path: string, signal?: AbortSignal): Promise<AuthenticatedDownload> {
  const pathname = path.split('?')[0];
  if (!/^\/(?:clusters\/[a-f\d-]{36}\/audit|audit\/global)\/exports\/[a-f\d-]{36}\/download$/i.test(pathname) || path.includes('#')) throw new Error('下载地址不属于审计导出。');
  return api<AuthenticatedDownload>(path, { signal }, false, true);
}
/** Configuration material is fetched only after an explicit POST confirmation, never a secret URL. */
export function apiConfigurationBlob(path: string, body: { revision: number; confirmed: true; confirm_name: string }, key: string, signal?: AbortSignal): Promise<AuthenticatedDownload> {
  const [pathname, query = ''] = path.split('?'), params = new URLSearchParams(query);
  const match = pathname.match(/^\/clusters\/([^/]+)\/configuration\/exports\/([^/]+)\/download$/);
  if (!match || !canonicalId(match[1]) || !canonicalId(match[2]) || path.includes('#') || [...params.keys()].some(name => name !== 'workspaceId') || params.getAll('workspaceId').length !== 1 || !canonicalId(params.get('workspaceId')) || !canonicalId(key) || body.confirmed !== true || !Number.isSafeInteger(body.revision) || body.revision < 1) throw new Error('下载标识或原操作范围无效。');
  return api<AuthenticatedDownload>(path, { method: 'POST', body: JSON.stringify(body), headers: { 'X-Idempotency-Key': key }, signal }, false, true);
}

/** One abandon packet only. Neither an auth retry nor a new-job by-key resolver is valid here. */
export function apiConfigurationAbandon<T>(path: string, body: { revision: number; executionId: string; executionRevision: number; planRevision: number; planHash: string; leaseGeneration: number; workflowExecutionId: string | null; confirmed: true; confirm_name: string }, key: string, original: { originalJobKey: string; intent: ConfigurationAbandonmentIntent }, signal?: AbortSignal): Promise<T> {
  const [pathname, query = ''] = path.split('?'), params = new URLSearchParams(query), match = pathname.match(/^\/clusters\/([^/]+)\/configuration\/jobs\/([^/]+)\/abandon$/);
  const fields = ['revision', 'executionId', 'executionRevision', 'planRevision', 'planHash', 'leaseGeneration', 'workflowExecutionId', 'confirmed', 'confirm_name'];
  if (!match || canonicalId(match[1]) !== match[1] || canonicalId(match[2]) !== match[2] || path.includes('#') || [...params.keys()].some(name => name !== 'workspaceId') || params.getAll('workspaceId').length !== 1 || canonicalId(params.get('workspaceId')) !== params.get('workspaceId')
    || !canonicalId(key) || !body || Object.keys(body).length !== fields.length || fields.some(name => !Object.hasOwn(body, name)) || !canonicalId(body.executionId)
    || ![body.revision, body.executionRevision, body.planRevision, body.leaseGeneration].every(value => Number.isSafeInteger(value) && value > 0)
    || !/^[a-f\d]{64}$/i.test(body.planHash ?? '') || body.workflowExecutionId !== null && !canonicalId(body.workflowExecutionId) || body.confirmed !== true || body.confirm_name !== `abandon:${match[2]}`
    || !canonicalId(original?.originalJobKey) || original?.intent?.jobId !== match[2] || original.intent.confirmationName !== body.confirm_name || ['revision', 'executionId', 'executionRevision', 'planRevision', 'planHash', 'leaseGeneration', 'workflowExecutionId'].some(name => original.intent[name as keyof ConfigurationAbandonmentIntent] !== body[name as keyof typeof body])) throw new Error('原执行收口请求标识、元组或确认值无效。');
  return api<T>(path, { method: 'POST', body: JSON.stringify(body), headers: { 'X-Idempotency-Key': key }, signal }, false, false, original);
}

export function post<T>(path: string, body: unknown = {}) {
  return api<T>(path, { method: 'POST', body: JSON.stringify(body) });
}

export function patch<T>(path: string, body: unknown) {
  return api<T>(path, { method: 'PATCH', body: JSON.stringify(body) });
}

export const NO_ELIGIBLE_APPROVER_MESSAGE = '没有可用的审批人：每个审批阶段都需要申请人以外、具备审批角色的用户。请在「访问控制」中为其他用户授予审批角色。';
/** Approval policy has no eligible reviewer besides the requester. */
export function isNoEligibleApprover(error: unknown) {
  return error instanceof ApiError && error.code === 'WORKFLOW_APPROVAL_CANDIDATES_UNSATISFIABLE';
}

export function errorMessage(error: unknown) {
  if (isNoEligibleApprover(error)) return NO_ELIGIBLE_APPROVER_MESSAGE;
  if (error instanceof ApiError && error.fields) {
    const fields = Object.entries(error.fields).slice(0, 5).map(([field, message]) => `${field}: ${String(message)}`).join('；');
    return fields ? `${error.message} · ${fields}` : error.message;
  }
  return error instanceof Error ? error.message : '操作失败，请稍后重试。';
}

export function authWriteNeedsVerification(error: unknown) {
  return error instanceof ApiError && (error.status === 0 || error.status >= 500 || error.code === 'INVALID_RESPONSE');
}
