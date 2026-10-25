import { api, ApiError, getApiActorId } from './client';
import { canonicalId } from './workspace-scope';
import type { Session } from './types';
import { iamDirectCommand, normalizeIamChangeReceipt, normalizeIamChangeRequest, validIamIdentity, type IamChangeAttempt, type IamChangeIdentity, type IamChangeReceipt, type IamChangeRequest } from './iam-changes.model';

export function iamWriteNeedsVerification(error: unknown): boolean { return error instanceof ApiError && /UNKNOWN|UNCERTAIN/.test(error.code ?? ''); }

export async function freshIamSession(identity: IamChangeIdentity, signal?: AbortSignal): Promise<Session> {
  if (!validIamIdentity(identity) || getApiActorId() !== identity.actor) throw new ApiError('账号已切换，请重新审阅。', 409, 'IAM_CHANGE_SESSION_CHANGED');
  const current = await api<Session>('/auth/me', { signal }, true);
  if (signal?.aborted || getApiActorId() !== identity.actor || current?.user?.id !== identity.actor || current.user.permissionsVersion !== identity.version || current.user.forcePasswordChange
    || typeof current.csrfToken !== 'string' || current.csrfToken.length < 16 || current.csrfToken.length > 128) throw new ApiError('账号或权限已变化，请重新审阅。', 409, 'IAM_CHANGE_SESSION_CHANGED');
  return current;
}
/** Only the original transport key or immutable intent may be read during recovery. A missing receipt is not permission to repeat a command. */
export async function readIamChangeReceipt(identity: IamChangeIdentity, attempt: IamChangeAttempt): Promise<IamChangeReceipt | unknown> {
  if (!validIamIdentity(identity) || identity.actor !== attempt.actor || getApiActorId() !== identity.actor || canonicalId(attempt.key) !== attempt.key) throw new Error('原身份请求范围无效。');
  const path = attempt.phase === 'direct' ? `/iam/operations/by-key/${attempt.key}` : attempt.intentId ? `/iam/changes/${attempt.intentId}` : `/iam/changes/by-key/${attempt.key}`;
  if (attempt.intentId !== undefined && canonicalId(attempt.intentId) !== attempt.intentId) throw new Error('原身份意图无效。');
  const raw = await api(path, {}, true);
  if (getApiActorId() !== identity.actor) throw new ApiError('账号已切换，请由原账号核验。', 409, 'IAM_CHANGE_SESSION_CHANGED');
  return attempt.phase === 'direct' ? raw : normalizeIamChangeReceipt(raw);
}
export async function readIamPrepared(identity: IamChangeIdentity, id: string): Promise<IamChangeReceipt> {
  if (!validIamIdentity(identity) || canonicalId(id) !== id || getApiActorId() !== identity.actor) throw new Error('身份意图范围无效。');
  const row = normalizeIamChangeReceipt(await api(`/iam/changes/${id}`, {}, true));
  if (getApiActorId() !== identity.actor || row.intentId !== id) throw new ApiError('账号或身份意图已变化。', 409, 'IAM_CHANGE_SESSION_CHANGED'); return row;
}
/** A single same-origin packet, including Direct IAM writes. Never refresh or repeat a write on 401. */
async function writeOnce(identity: IamChangeIdentity, path: string, method: string, body: unknown, key: string, csrf: string): Promise<unknown> {
  if (!validIamIdentity(identity) || getApiActorId() !== identity.actor || canonicalId(key) !== key || typeof csrf !== 'string' || csrf.length < 16 || csrf.length > 128) throw new Error('真实会话或原请求键无效。');
  let response: Response;
  try { response = await fetch(`/api/v1${path}`, { method, credentials: 'include', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'X-Idempotency-Key': key }, body: JSON.stringify(body) }); }
  catch { throw new ApiError('身份请求结果待核验，请查看原回执。', 0, 'IAM_CHANGE_RESULT_UNKNOWN'); }
  let raw: any; try { raw = await response.json(); } catch { throw new ApiError('身份响应无法读取，请核验原回执。', response.status, 'IAM_CHANGE_RESULT_UNKNOWN'); }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new ApiError('身份响应无法读取，请核验原回执。', response.status, 'IAM_CHANGE_RESULT_UNKNOWN');
  if (!response.ok) {
    const code = typeof raw.error?.code === 'string' && /^[A-Z0-9_]{1,100}$/.test(raw.error.code) ? raw.error.code : undefined;
    const uncertain = response.status >= 500 || /UNKNOWN|UNCERTAIN/.test(code ?? '') || ['uncertain', 'running', 'partial'].includes(raw.error?.state);
    throw new ApiError(`身份操作未完成（HTTP ${response.status}${code ? ` · ${code}` : ''}）。`, response.status, uncertain ? 'IAM_CHANGE_RESULT_UNKNOWN' : code);
  }
  if (getApiActorId() !== identity.actor) throw new ApiError('账号已切换，请由原账号核验原请求。', 409, 'IAM_CHANGE_RESULT_UNKNOWN');
  if (!Object.hasOwn(raw, 'data') || !raw.data || typeof raw.data !== 'object' || Array.isArray(raw.data)) throw new ApiError('身份操作响应不完整，请核验原回执。', response.status, 'IAM_CHANGE_RESULT_UNKNOWN');
  return raw.data;
}
export async function writeIamDirectOnce(identity: IamChangeIdentity, change: IamChangeRequest, key: string, csrf: string): Promise<unknown> { const command = iamDirectCommand(change); return writeOnce(identity, command.path, command.method, command.body, key, csrf); }
export async function prepareIamChangeOnce(identity: IamChangeIdentity, raw: IamChangeRequest, key: string, csrf: string): Promise<IamChangeReceipt> {
  const change = normalizeIamChangeRequest(raw); if (change.resource === 'users' && !change.operation.startsWith('binding.')) throw new Error('账号资料请使用用户目录操作。');
  const response = await writeOnce(identity, '/iam/changes/prepare', 'POST', change, key, csrf);
  let row: IamChangeReceipt; try { row = normalizeIamChangeReceipt(response); } catch { throw new ApiError('身份意图响应不完整，请核验原回执。', 200, 'IAM_CHANGE_RESULT_UNKNOWN'); }
  if (row.resource !== change.resource || row.operation !== change.operation || row.resourceId !== (change.resourceId ?? null) || row.state !== 'prepared' || row.workflowId !== null || !row.preview) throw new ApiError('身份意图响应不匹配，请核验原回执。', 200, 'IAM_CHANGE_RESULT_UNKNOWN'); return row;
}
export async function submitIamChangeOnce(identity: IamChangeIdentity, original: IamChangeReceipt, key: string, csrf: string): Promise<IamChangeReceipt> {
  if (canonicalId(original.intentId) !== original.intentId || !/^[a-f\d]{64}$/.test(original.materialHmac) || original.state !== 'prepared' || original.workflowId !== null || !original.preview || Date.parse(original.expiresAt) <= Date.now()) throw new Error('当前意图不可提交，请重新核验。');
  const response = await writeOnce(identity, `/iam/changes/${original.intentId}/submit`, 'POST', { confirmed: true, materialHmac: original.materialHmac }, key, csrf);
  let row: IamChangeReceipt; try { row = normalizeIamChangeReceipt(response); } catch { throw new ApiError('工单响应不完整，请核验原回执。', 200, 'IAM_CHANGE_RESULT_UNKNOWN'); }
  if (row.intentId !== original.intentId || row.materialHmac !== original.materialHmac || row.clusterId !== original.clusterId || row.workspaceId !== original.workspaceId || row.workflowId === null || row.state === 'prepared') throw new ApiError('工单响应不完整，请核验原回执。', 200, 'IAM_CHANGE_RESULT_UNKNOWN'); return row;
}
