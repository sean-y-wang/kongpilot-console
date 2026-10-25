import { api, ApiError, getApiActorId } from '../api/client';
import { canonicalId } from '../api/workspace-scope';
import type { Session } from '../api/types';
import { configurationDetailEntity, configurationPath, configurationReceiptPath } from './m8.model';
import { configurationWorkflowReceiptPointer, configurationWorkflowRegisteredPlanMatches, configurationWorkflowRejection, configurationWorkflowSourceWasRejected, readConfigurationWorkflowAttempt, storeConfigurationWorkflowAttempt, validConfigurationWorkflowIdentity,
  type ConfigurationWorkflowAttempt, type ConfigurationWorkflowIdentity, type ConfigurationWorkflowPlan, type ConfigurationWorkflowRejection } from './configuration-workflow.model';

function assertActor(identity: ConfigurationWorkflowIdentity): void {
  if (!validConfigurationWorkflowIdentity(identity) || getApiActorId() !== identity.actor) throw new ApiError('当前账号或配置范围已变化，请重新审阅。', 409, 'CONFIGURATION_WORKFLOW_SCOPE_CHANGED');
}
export async function freshConfigurationWorkflowSession(identity: ConfigurationWorkflowIdentity): Promise<Session> {
  assertActor(identity); const session = await api<Session>('/auth/me', {}, true); assertActor(identity);
  if (session?.user?.id !== identity.actor || session.user.permissionsVersion !== identity.version || session.user.forcePasswordChange
    || typeof session.csrfToken !== 'string' || session.csrfToken.length < 16 || session.csrfToken.length > 128) throw new ApiError('账号、权限或登录会话已变化，请重新审阅。', 409, 'CONFIGURATION_WORKFLOW_SCOPE_CHANGED');
  return session;
}
export async function fetchConfigurationWorkflowPlan(identity: ConfigurationWorkflowIdentity, id: string): Promise<ConfigurationWorkflowPlan> {
  assertActor(identity); if (typeof id !== 'string' || canonicalId(id) !== id) throw new Error('配置计划标识无效。');
  const raw = await api<unknown>(configurationPath(identity, `configuration/plans/${id}`), {}, true); assertActor(identity);
  return configurationDetailEntity<ConfigurationWorkflowPlan>(raw, identity, id);
}
/** The caller persists the original journal before this one request. A 401
 * never refreshes or replays a configuration submission. */
export async function postConfigurationWorkflowOnce(original: ConfigurationWorkflowAttempt, body: unknown, csrf: string): Promise<void> {
  assertActor(original); const pending = readConfigurationWorkflowAttempt(original), value = body as Record<string, unknown>;
  if (configurationWorkflowSourceWasRejected(original, original.sourcePlanId)) throw new Error('原配置计划已被拒绝，请重新预览后创建配置工单。');
  const fields = ['planRevision', 'planHash', 'confirmed', 'confirm_name', ...(value?.confirm_deletes === true ? ['confirm_deletes'] : [])];
  if (!pending || pending.state !== 'pending' || JSON.stringify(pending) !== JSON.stringify(original) || !value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field)) || value.planRevision !== original.sourcePlanRevision || value.planHash !== original.sourcePlanHash
    || value.confirmed !== true || value.confirm_name !== `配置计划 ${original.sourcePlanId}` || typeof csrf !== 'string' || csrf.length < 16 || csrf.length > 128) throw new Error('原配置计划、确认信息或请求记录无效。');
  // Spend the local send opportunity synchronously. Until the original receipt
  // is checked, even a second caller or a page reload can only read it.
  storeConfigurationWorkflowAttempt({ ...original, state: 'unknown' });
  await api<unknown>(configurationPath(original, `configuration/plans/${original.sourcePlanId}/durable-submissions`), {
    method: 'POST', body: JSON.stringify(value), headers: { 'X-Idempotency-Key': original.key, 'X-CSRF-Token': csrf },
  }, true);
  assertActor(original);
}
/** Reads the original metadata receipt and the actual newly published Diff.
 * It neither repeats the POST nor grants approval or native execution. */
export async function readConfigurationWorkflowRegistration(original: ConfigurationWorkflowAttempt, assertCurrent: () => void) {
  const result = await readConfigurationWorkflowDisposition(original, assertCurrent);
  if (result.kind !== 'registered') throw new Error('原配置工单登记已拒绝，请重新预览后创建配置工单。');
  return { proof: result.proof, plan: result.plan };
}
/** The original-key GET is the deciding observation. A POST status/code only
 * permits this read; it never proves rejection, clears a journal or retries. */
export async function readConfigurationWorkflowDisposition(original: ConfigurationWorkflowAttempt, assertCurrent: () => void) {
  assertCurrent(); assertActor(original);
  const raw = await api<unknown>(configurationReceiptPath({ kind: 'configuration', clusterId: original.cid, workspaceId: original.wid, actorId: original.actor, idempotencyKey: original.key }), {}, true);
  assertCurrent(); assertActor(original);
  if (raw && typeof raw === 'object' && !Array.isArray(raw) && (raw as Record<string, unknown>).receiptKind === 'durable-submission-rejected-v1') {
    const rejection: ConfigurationWorkflowRejection = configurationWorkflowRejection(raw, original);
    return { kind: 'rejected' as const, rejection };
  }
  const proof = configurationWorkflowReceiptPointer(raw, original);
  const plan = await fetchConfigurationWorkflowPlan(original, proof.planId); assertCurrent();
  if (!configurationWorkflowRegisteredPlanMatches(proof, plan)) throw new Error('原工单与新配置差异尚未匹配，请继续核验原请求。');
  return { kind: 'registered' as const, proof, plan };
}
