import { api, ApiError, getApiActorId } from './client';
import { canonicalId } from './workspace-scope';
import type { Session } from './types';
import { controlDirectCommand, controlReceiptMatches, normalizeControlChange, normalizeControlReceipt, validControlIdentity, type ControlAttempt, type ControlChange, type ControlIdentity, type ControlReceipt } from './control-changes.model';

export const controlNeedsVerification = (e: unknown) => e instanceof ApiError && /UNKNOWN|UNCERTAIN/.test(e.code ?? '');
export async function freshControlSession(identity: ControlIdentity): Promise<Session> {
  if (!validControlIdentity(identity) || getApiActorId() !== identity.actor) throw new ApiError('账号已变化，请重新审阅。', 409, 'CONTROL_SESSION_CHANGED');
  const row = await api<Session>('/auth/me', {}, true);
  if (getApiActorId() !== identity.actor || row?.user?.id !== identity.actor || row.user.permissionsVersion !== identity.version || row.user.forcePasswordChange || typeof row.csrfToken !== 'string' || row.csrfToken.length < 16 || row.csrfToken.length > 128) throw new ApiError('账号或权限已变化，请重新审阅。', 409, 'CONTROL_SESSION_CHANGED');
  return row;
}
/** Fixed same-origin packets; a write never refreshes its session or POSTs twice. */
async function once(identity: ControlIdentity, path: string, method: string, input: unknown, key: string, csrf: string) {
  if (!validControlIdentity(identity) || getApiActorId() !== identity.actor || canonicalId(key) !== key || typeof csrf !== 'string' || csrf.length < 16 || csrf.length > 128) throw new Error('会话或原请求键无效。');
  let response: Response; try { response = await fetch(`/api/v1${path}`, { method, credentials: 'include', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'X-Idempotency-Key': key }, body: JSON.stringify(input) }); }
  catch { throw new ApiError('配置请求结果待核验。', 0, 'CONTROL_RESULT_UNKNOWN'); }
  let raw: any; try { raw = await response.json(); } catch { throw new ApiError('配置响应无法读取，请核验原请求。', response.status, 'CONTROL_RESULT_UNKNOWN'); }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new ApiError('配置响应不完整，请核验原请求。', response.status, 'CONTROL_RESULT_UNKNOWN');
  if (!response.ok) {
    const code = typeof raw.error?.code === 'string' && /^[A-Z0-9_]{1,100}$/.test(raw.error.code) ? raw.error.code : undefined;
    throw new ApiError(`配置操作未完成（HTTP ${response.status}${code ? ` · ${code}` : ''}）。`, response.status, response.status >= 500 || /UNKNOWN|UNCERTAIN/.test(code ?? '') || ['uncertain', 'running', 'partial'].includes(raw.error?.state) ? 'CONTROL_RESULT_UNKNOWN' : code);
  }
  if (getApiActorId() !== identity.actor || !Object.hasOwn(raw, 'data') || !raw.data || typeof raw.data !== 'object' || Array.isArray(raw.data)) throw new ApiError('配置响应不完整，请由原账号核验。', 200, 'CONTROL_RESULT_UNKNOWN');
  return raw.data;
}
export async function writeControlDirectOnce(identity: ControlIdentity, request: ControlChange, cid: string | null, targetWorkspaceId: string | null, key: string, csrf: string) {
  const command = controlDirectCommand(request, cid, targetWorkspaceId), result = await once(identity, command.path, command.method, command.body, key, csrf);
  const entity = request.operation === 'archive' ? result.workspace : result;
  if (request.resource === 'recycle-bin' ? result.id !== request.resourceId || result.purged !== true : request.operation === 'deactivate' ? result.id !== request.resourceId || result.deactivated !== true
    : !entity || canonicalId(entity.id) !== entity.id || request.resourceId !== undefined && entity.id !== request.resourceId || !Number.isSafeInteger(entity.revision) || entity.revision < 1
      || request.resource === 'workspaces' && (entity.cluster_id !== cid || request.operation === 'archive' && result.state !== 'deleted')
      || request.resource === 'data-sources' && entity.cluster_id !== cid) throw new ApiError('配置操作回执不完整，请核验原请求。', 200, 'CONTROL_RESULT_UNKNOWN');
  return result;
}
export async function prepareControlOnce(identity: ControlIdentity, request: ControlChange, attempt: ControlAttempt, csrf: string): Promise<ControlReceipt> {
  const change = normalizeControlChange(request); if (attempt.phase !== 'prepare' || canonicalId(attempt.clusterId) !== attempt.clusterId) throw new Error('原配置请求范围无效。');
  const raw = await once(identity, `/clusters/${attempt.clusterId}/control-changes/prepare`, 'POST', change, attempt.key, csrf);
  try { const row = normalizeControlReceipt(raw); if (!controlReceiptMatches(row, attempt) || row.state !== 'prepared' || row.workflowId !== null || !row.preview) throw new Error(); return row; }
  catch { throw new ApiError('配置预览与原请求不一致，请核验原请求。', 200, 'CONTROL_RESULT_UNKNOWN'); }
}
export async function submitControlOnce(identity: ControlIdentity, original: ControlReceipt, attempt: ControlAttempt, csrf: string): Promise<ControlReceipt> {
  if (attempt.phase !== 'submit' || !controlReceiptMatches(original, { ...attempt, phase: 'prepared' }) || original.state !== 'prepared' || !original.preview || original.workflowId !== null || Date.parse(original.expiresAt) <= Date.now()) throw new Error('当前配置意图不可提交。');
  const raw = await once(identity, `/clusters/${original.clusterId}/control-changes/${original.intentId}/submit`, 'POST', { confirmed: true, materialHmac: original.materialHmac }, attempt.key, csrf);
  try { const row = normalizeControlReceipt(raw); if (!controlReceiptMatches(row, attempt)) throw new Error(); return row; }
  catch { throw new ApiError('工单回执与原请求不一致，请核验原请求。', 200, 'CONTROL_RESULT_UNKNOWN'); }
}
export async function readControlOriginal(identity: ControlIdentity, attempt: ControlAttempt): Promise<ControlReceipt | any> {
  if (!validControlIdentity(identity) || getApiActorId() !== identity.actor || identity.actor !== attempt.actor || canonicalId(attempt.key) !== attempt.key) throw new Error('请由原账号核验。');
  const path = attempt.phase === 'direct' ? ['workspaces','recycle-bin'].includes(attempt.resource) ? controlWorkspaceReceiptPath(attempt) : `/iam/operations/by-key/${attempt.key}`
    : `/clusters/${attempt.clusterId}/control-changes/${attempt.intentId ?? `by-key/${attempt.key}`}`;
  if (attempt.phase !== 'direct' && canonicalId(attempt.clusterId) !== attempt.clusterId || attempt.intentId !== undefined && canonicalId(attempt.intentId) !== attempt.intentId) throw new Error('原配置意图无效。');
  const raw = await api(path, {}, true); if (getApiActorId() !== identity.actor) throw new ApiError('账号已变化，请由原账号核验。', 409, 'CONTROL_SESSION_CHANGED');
  return attempt.phase === 'direct' ? raw : normalizeControlReceipt(raw);
}
function controlWorkspaceReceiptPath(attempt: ControlAttempt) { if (canonicalId(attempt.clusterId) !== attempt.clusterId || canonicalId(attempt.targetWorkspaceId) !== attempt.targetWorkspaceId) throw new Error('原工作区请求范围无效。'); return `/clusters/${attempt.clusterId}/mutations/by-key/${attempt.key}?workspaceId=${attempt.targetWorkspaceId}`; }
export function controlDirectReceiptCompleted(raw: any, attempt: ControlAttempt) {
  if (!raw || canonicalId(raw.id) !== raw.id || !['succeeded', 'failed'].includes(raw.state) || raw.remote_completed !== true) return false;
  if (attempt.resource === 'recycle-bin') return raw.actor_id === attempt.actor && raw.cluster_id === attempt.clusterId && raw.workspace_id === attempt.targetWorkspaceId && raw.entity_type === 'recycle_entries' && raw.action === 'purge' && raw.entity_id === attempt.resourceId;
  if (attempt.resource === 'workspaces') return raw.actor_id === attempt.actor && raw.cluster_id === attempt.clusterId && raw.workspace_id === attempt.targetWorkspaceId && raw.entity_type === 'workspaces'
    && raw.action === (attempt.operation === 'archive' ? 'delete' : attempt.operation) && (attempt.resourceId === null || raw.entity_id === attempt.resourceId);
  return raw.module === attempt.resource && raw.action === (attempt.operation === 'deactivate' ? 'delete' : 'write') && raw.workspace_id === null
    && raw.cluster_id === (attempt.resource === 'clusters' ? null : attempt.clusterId) && (attempt.resourceId === null ? raw.target_id === null : raw.target_id === attempt.resourceId);
}
