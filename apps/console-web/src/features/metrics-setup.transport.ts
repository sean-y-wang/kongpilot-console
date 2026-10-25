import { api, ApiError, getApiActorId } from '../api/client';
import type { Session } from '../api/types';
import { canonicalId } from '../api/workspace-scope';
import { metricsSetupPath, normalizeMetricsSetupReceipt, normalizeMetricsSetupRequest, normalizeMetricsSetupSubmission, validMetricsSetupIdentity, type MetricsSetupAttempt, type MetricsSetupIdentity, type MetricsSetupReceipt, type MetricsSetupRequest, type MetricsSetupSubmission } from './metrics-setup.model';

export function metricsSetupNeedsVerification(error: unknown): boolean { return error instanceof ApiError && /UNKNOWN|UNCERTAIN/.test(error.code ?? ''); }
export async function freshMetricsSetupSession(identity: MetricsSetupIdentity): Promise<Session> {
  if (!validMetricsSetupIdentity(identity) || getApiActorId() !== identity.actor) throw new ApiError('账号已切换，请重新审阅。', 409, 'METRICS_SETUP_SESSION_CHANGED');
  const current = await api<Session>('/auth/me', {}, true);
  if (getApiActorId() !== identity.actor || current?.user?.id !== identity.actor || current.user.permissionsVersion !== identity.version || current.user.forcePasswordChange || typeof current.csrfToken !== 'string' || current.csrfToken.length < 16 || current.csrfToken.length > 128) throw new ApiError('账号或权限已变化，请重新审阅。', 409, 'METRICS_SETUP_SESSION_CHANGED');
  return current;
}
/** One same-origin BFF command. Neither a 401 nor an interrupted response refreshes or repeats this packet. */
async function writeOnce(identity: MetricsSetupIdentity, path: string, body: unknown, key: string, csrf: string): Promise<any> {
  if (!validMetricsSetupIdentity(identity) || getApiActorId() !== identity.actor || typeof key !== 'string' || canonicalId(key) !== key || typeof csrf !== 'string' || csrf.length < 16 || csrf.length > 128) throw new Error('真实会话或原请求键无效。');
  let response: Response;
  try { response = await fetch(`/api/v1${path}`, { method: 'POST', credentials: 'include', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'X-Idempotency-Key': key }, body: JSON.stringify(body) }); }
  catch { throw new ApiError('监控请求结果待核验，请读取原回执。', 0, 'METRICS_SETUP_RESULT_UNKNOWN'); }
  let raw: any; try { raw = await response.json(); } catch { throw new ApiError('监控响应无法读取，请核验原回执。', response.status, 'METRICS_SETUP_RESULT_UNKNOWN'); }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new ApiError('监控响应无法读取，请核验原回执。', response.status, 'METRICS_SETUP_RESULT_UNKNOWN');
  if (!response.ok) {
    const code = typeof raw.error?.code === 'string' && /^[A-Z0-9_]{1,100}$/.test(raw.error.code) ? raw.error.code : undefined;
    const uncertain = response.status >= 500 || /UNKNOWN|UNCERTAIN/.test(code ?? '') || ['uncertain', 'running', 'partial'].includes(raw.error?.state) || raw.error?.setupReceipt === true;
    throw new ApiError(`监控配置未完成（HTTP ${response.status}${code ? ` · ${code}` : ''}）。`, response.status, uncertain ? 'METRICS_SETUP_RESULT_UNKNOWN' : code);
  }
  if (getApiActorId() !== identity.actor || !Object.hasOwn(raw, 'data') || !raw.data || typeof raw.data !== 'object' || Array.isArray(raw.data)) throw new ApiError('监控配置响应不完整，请由原账号核验原请求。', response.status, 'METRICS_SETUP_RESULT_UNKNOWN');
  return raw.data;
}
export async function writeMetricsSetupDirectOnce(identity: MetricsSetupIdentity, raw: MetricsSetupRequest, key: string, csrf: string): Promise<{ sourceId: string; mode: MetricsSetupRequest['mode'] }> {
  const request = normalizeMetricsSetupRequest(raw), result = await writeOnce(identity, metricsSetupPath(identity, 'setup'), request, key, csrf);
  if (result.sourceId !== request.sourceId || result.mode !== request.mode || typeof result.pluginId !== 'string' || canonicalId(result.pluginId) !== result.pluginId || !Number.isSafeInteger(result.settingsRevision) || result.settingsRevision < 1 || request.mode === 'collector' && (typeof result.collectorPluginId !== 'string' || canonicalId(result.collectorPluginId) !== result.collectorPluginId)) throw new ApiError('监控配置响应不完整，请核验原回执。', 200, 'METRICS_SETUP_RESULT_UNKNOWN');
  return { sourceId: result.sourceId, mode: result.mode };
}
export async function prepareMetricsSetupOnce(identity: MetricsSetupIdentity, raw: MetricsSetupRequest, key: string, csrf: string): Promise<MetricsSetupReceipt> {
  const request = normalizeMetricsSetupRequest(raw), response = await writeOnce(identity, metricsSetupPath(identity, 'prepare'), request, key, csrf);
  let row: MetricsSetupReceipt; try { row = normalizeMetricsSetupReceipt(response); } catch { throw new ApiError('监控意图响应不完整，请核验原回执。', 200, 'METRICS_SETUP_RESULT_UNKNOWN'); }
  if (row.clusterId !== identity.clusterId || row.workspaceId !== identity.workspaceId || row.sourceId !== request.sourceId || row.mode !== request.mode || row.state !== 'prepared' || row.workflowId !== null || row.preview?.confirmationName !== request.confirm_name) throw new ApiError('监控意图与原请求不匹配，请核验原回执。', 200, 'METRICS_SETUP_RESULT_UNKNOWN'); return row;
}
export async function submitMetricsSetupOnce(identity: MetricsSetupIdentity, original: MetricsSetupReceipt, key: string, csrf: string): Promise<MetricsSetupSubmission> {
  const reviewed = normalizeMetricsSetupReceipt(original);
  if (reviewed.clusterId !== identity.clusterId || reviewed.workspaceId !== identity.workspaceId || reviewed.state !== 'prepared' || reviewed.workflowId !== null || !reviewed.preview || Date.parse(reviewed.expiresAt) <= Date.now()) throw new Error('监控配置意图已变化或过期，请重新核验。');
  const response = await writeOnce(identity, metricsSetupPath(identity, 'submit', reviewed.intentId), { revision: reviewed.revision, confirmed: true, materialHmac: reviewed.materialHmac, confirm_name: reviewed.preview.confirmationName }, key, csrf);
  let row: MetricsSetupSubmission; try { row = normalizeMetricsSetupSubmission(response, reviewed); } catch { throw new ApiError('监控工单响应不完整，请核验原回执。', 200, 'METRICS_SETUP_RESULT_UNKNOWN'); }
  if (row.workflowId === null || row.state !== 'submitted') throw new ApiError('监控工单响应不匹配，请核验原回执。', 200, 'METRICS_SETUP_RESULT_UNKNOWN'); return row;
}
export async function readMetricsSetupPrepared(identity: MetricsSetupIdentity, id: string): Promise<MetricsSetupReceipt> {
  if (getApiActorId() !== identity.actor) throw new Error('请由原账号核验原监控意图。');
  const row = normalizeMetricsSetupReceipt(await api(metricsSetupPath(identity, 'intent', id), {}, true));
  if (getApiActorId() !== identity.actor || row.intentId !== id || row.clusterId !== identity.clusterId || row.workspaceId !== identity.workspaceId) throw new ApiError('账号或监控意图已变化，请重新核验。', 409, 'METRICS_SETUP_SESSION_CHANGED'); return row;
}
/** Recovery reads only the original key or immutable intent. A missing receipt never permits another write. */
export async function readMetricsSetupReceipt(identity: MetricsSetupIdentity, attempt: MetricsSetupAttempt): Promise<MetricsSetupReceipt | any> {
  if (!validMetricsSetupIdentity(identity) || identity.actor !== attempt.actor || identity.clusterId !== attempt.clusterId || identity.workspaceId !== attempt.workspaceId || getApiActorId() !== identity.actor) throw new Error('请切回原账号、集群与工作区核验。');
  const path = metricsSetupPath(identity, attempt.phase === 'direct' ? 'direct-key' : attempt.phase === 'submit' ? 'submit-receipt' : attempt.intentId ? 'intent' : 'intent-key', attempt.intentId ?? attempt.key);
  const raw = await api<any>(path, {}, true);
  if (getApiActorId() !== identity.actor) throw new ApiError('账号已切换，请由原账号核验。', 409, 'METRICS_SETUP_SESSION_CHANGED');
  if (attempt.phase === 'submit') return normalizeMetricsSetupSubmission(raw, { intentId: attempt.intentId!, clusterId: attempt.clusterId, workspaceId: attempt.workspaceId, materialHmac: attempt.materialHmac! });
  if (attempt.phase !== 'direct') { const row = normalizeMetricsSetupReceipt(raw); if (row.clusterId !== attempt.clusterId || row.workspaceId !== attempt.workspaceId) throw new Error('回执不属于原监控范围。'); return row; }
  if (!raw || raw.clusterId !== attempt.clusterId || raw.workspaceId !== attempt.workspaceId || raw.idempotencyKey !== attempt.key || !['not_sent', 'succeeded', 'failed', 'partial', 'uncertain'].includes(raw.parentState) || !Array.isArray(raw.steps) || raw.steps.length > 3) throw new Error('监控回执与原请求不一致。');
  return raw;
}
export function metricsSetupDirectReceiptCompleted(raw: any): boolean {
  if (!raw || raw.parentState !== 'succeeded' || !Array.isArray(raw.steps) || typeof raw.result?.sourceId !== 'string' || canonicalId(raw.result.sourceId) !== raw.result.sourceId || !['native_prometheus', 'collector'].includes(raw.result.mode) || typeof raw.result.pluginId !== 'string' || canonicalId(raw.result.pluginId) !== raw.result.pluginId || !Number.isSafeInteger(raw.result.settingsRevision) || raw.result.settingsRevision < 1) return false;
  const names = raw.result.mode === 'collector' ? ['prometheus', 'http-log', 'settings'] : ['prometheus', 'settings'];
  return raw.steps.length === names.length && new Set(raw.steps.map((s: any) => s?.id)).size === names.length && names.every(name => raw.steps.filter((s: any) => s?.name === name).length === 1)
    && raw.steps.every((step: any) => step && typeof step.id === 'string' && canonicalId(step.id) === step.id && step.state === 'succeeded' && step.remoteCompleted === true)
    && (raw.result.mode !== 'collector' || typeof raw.result.collectorPluginId === 'string' && canonicalId(raw.result.collectorPluginId) === raw.result.collectorPluginId);
}
