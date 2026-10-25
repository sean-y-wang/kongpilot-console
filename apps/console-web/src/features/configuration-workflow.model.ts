import { canonicalId } from '../api/workspace-scope';
import { configurationConfirmation } from './m8.model';
import type { ConfigurationIdentity, ConfigurationPlan } from './m8.types';

export type ConfigurationWorkflowPlan = ConfigurationPlan & {
  authorityDomain?: string | null;
  durableIssueId?: string | null;
  sourcePlanId?: string | null;
  capabilities: ConfigurationPlan['capabilities'] & { durableSubmit?: boolean };
};
export interface ConfigurationWorkflowIdentity {
  actor: string; version: string; cid: string; wid: string;
}
export interface ConfigurationWorkflowAttempt extends ConfigurationWorkflowIdentity {
  key: string; sourcePlanId: string; sourceJobId: string;
  sourceRevision: number; sourcePlanRevision: number; sourcePlanHash: string;
  state: 'pending' | 'unknown';
}
export interface ConfigurationWorkflowRegistration {
  actorId: string; clusterId: string; workspaceId: string;
  sourcePlanId: string; jobId: string; planId: string; workflowId: string; issueId: string;
  expiresAt: string; state: string; registrationOnly: true;
}
export interface ConfigurationWorkflowRejection {
  domain: 'configuration'; authorityDomain: 'durable-configuration-v1'; receiptKind: 'durable-submission-rejected-v1';
  result: 'rejected'; commandCompleted: true; registrationCompleted: false; registrationRejected: true; submissionCompleted: false;
  knownNoEffect: true; effectScope: 'durable-registration'; nativeWrites: 'none'; newPreviewRequired: true;
  idempotencyKey: string; actorId: string; clusterId: string; workspaceId: string;
  sourceJobId: string; sourcePlanId: string; sourcePlanRevision: number; sourcePlanHash: string;
  rejectionId: string; rejectedAt: string; code: 'CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED';
}
export interface ConfigurationWorkflowSettledRejection {
  version: 1; state: 'settled-rejected'; original: ConfigurationWorkflowAttempt; receipt: ConfigurationWorkflowRejection;
}
const positive = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f\d]{64}$/.test(value);
const invalid = () => new Error('原配置工单请求记录或范围无效，请核验原请求。');
export function validConfigurationWorkflowIdentity(value: ConfigurationIdentity): boolean {
  return ['actor', 'cid', 'wid'].every(field => typeof value[field as keyof ConfigurationIdentity] === 'string' && canonicalId(value[field as keyof ConfigurationIdentity]) === value[field as keyof ConfigurationIdentity])
    && typeof value.version === 'string' && value.version.length > 0 && value.version.length <= 256;
}
export function configurationCanCreateWorkflow(plan: ConfigurationWorkflowPlan, identity: ConfigurationIdentity, now = Date.now()): boolean {
  return !!plan && validConfigurationWorkflowIdentity(identity) && typeof plan.id === 'string' && canonicalId(plan.id) === plan.id && typeof plan.jobId === 'string' && canonicalId(plan.jobId) === plan.jobId
    && plan.clusterId === identity.cid && plan.workspaceId === identity.wid && positive(plan.revision) && positive(plan.planRevision) && hash(plan.planHash)
    && plan.name === `配置计划 ${plan.id}` && plan.state === 'ready' && Date.parse(plan.expiresAt) > now
    && plan.capabilities?.durableSubmit === true && plan.authorityDomain === 'legacy-http-v1' && plan.durableIssueId == null && plan.sourcePlanId == null
    && plan.executionMode === 'approval' && plan.approvalRequired === true
    && !plan.workflowId && plan.recoveryComplete === true && Array.isArray(plan.blockers) && plan.blockers.length === 0
    && ['merge', 'sync', 'rollback'].includes(plan.mode) && Number.isSafeInteger(plan.deleteCount) && plan.deleteCount >= 0;
}
export function configurationWorkflowConfirmation(plan: ConfigurationWorkflowPlan, identity: ConfigurationIdentity, name: string, deletion?: string) {
  if (!configurationCanCreateWorkflow(plan, identity)) throw new Error('当前计划不可创建配置工单，请重新读取原计划与权限。');
  return configurationConfirmation(plan, name, deletion);
}
export function configurationWorkflowAttempt(identity: ConfigurationIdentity, plan: ConfigurationWorkflowPlan, key: string): ConfigurationWorkflowAttempt {
  if (!configurationCanCreateWorkflow(plan, identity) || typeof key !== 'string' || canonicalId(key) !== key) throw invalid();
  return { actor: identity.actor!, version: identity.version!, cid: identity.cid!, wid: identity.wid!, key,
    sourcePlanId: plan.id, sourceJobId: plan.jobId, sourceRevision: plan.revision,
    sourcePlanRevision: plan.planRevision, sourcePlanHash: plan.planHash, state: 'pending' };
}
export function configurationWorkflowSourceMatches(attempt: ConfigurationWorkflowAttempt, plan: ConfigurationWorkflowPlan): boolean {
  try {
    const original = cleanAttempt(attempt);
    return plan.id === original.sourcePlanId && plan.jobId === original.sourceJobId && plan.clusterId === original.cid && plan.workspaceId === original.wid
      && plan.revision === original.sourceRevision && plan.planRevision === original.sourcePlanRevision && plan.planHash === original.sourcePlanHash;
  } catch { return false; }
}
function keyFor(identity: ConfigurationIdentity): string {
  if (!validConfigurationWorkflowIdentity(identity)) throw invalid();
  return `kongpilot.configurationWorkflowAttempt:${identity.actor}:${identity.cid}:${identity.wid}`;
}
function cleanAttempt(value: any): ConfigurationWorkflowAttempt {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !validConfigurationWorkflowIdentity(value) || !['key', 'sourcePlanId', 'sourceJobId'].every(field => typeof value[field] === 'string' && canonicalId(value[field]) === value[field])
    || !positive(value.sourceRevision) || !positive(value.sourcePlanRevision) || !hash(value.sourcePlanHash) || !['pending', 'unknown'].includes(value.state)) throw invalid();
  return { actor: value.actor, version: value.version, cid: value.cid, wid: value.wid, key: value.key,
    sourcePlanId: value.sourcePlanId, sourceJobId: value.sourceJobId, sourceRevision: value.sourceRevision,
    sourcePlanRevision: value.sourcePlanRevision, sourcePlanHash: value.sourcePlanHash, state: value.state };
}
/** Permission changes preserve the original request; they never revive its write authority. */
export function readConfigurationWorkflowAttempt(identity: ConfigurationIdentity): ConfigurationWorkflowAttempt | undefined {
  const raw = sessionStorage.getItem(keyFor(identity)); if (raw === null) return;
  let attempt: ConfigurationWorkflowAttempt;
  try { attempt = cleanAttempt(JSON.parse(raw)); } catch { throw invalid(); }
  if (attempt.actor !== identity.actor || attempt.cid !== identity.cid || attempt.wid !== identity.wid) throw invalid();
  return attempt;
}
export function storeConfigurationWorkflowAttempt(value: ConfigurationWorkflowAttempt): void {
  const safe = cleanAttempt(value), previous = readConfigurationWorkflowAttempt(value);
  if (previous && JSON.stringify({ ...previous, state: 'pending' }) !== JSON.stringify({ ...safe, state: 'pending' })) throw new Error('原配置工单请求尚未核验，不能替换计划或请求键。');
  if (previous?.state === 'unknown' && safe.state === 'pending') throw new Error('原配置工单请求结果尚未确认，只能核验原回执。');
  sessionStorage.setItem(keyFor(safe), JSON.stringify(safe));
}
/** Called only after the feature verifies the original by-key receipt. */
export function clearConfigurationWorkflowAttempt(original: ConfigurationWorkflowAttempt): void {
  const previous = readConfigurationWorkflowAttempt(original);
  if (!previous || JSON.stringify({ ...previous, state: 'pending' }) !== JSON.stringify({ ...cleanAttempt(original), state: 'pending' })) throw invalid();
  sessionStorage.removeItem(keyFor(original));
}
const record = (value: unknown): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value);
const exactId = (value: unknown): value is string => typeof value === 'string' && canonicalId(value) === value;
const instant = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const rejectionFields = ['domain', 'authorityDomain', 'receiptKind', 'result', 'commandCompleted', 'registrationCompleted', 'registrationRejected', 'submissionCompleted',
  'knownNoEffect', 'effectScope', 'nativeWrites', 'newPreviewRequired', 'idempotencyKey', 'actorId', 'clusterId', 'workspaceId',
  'sourceJobId', 'sourcePlanId', 'sourcePlanRevision', 'sourcePlanHash', 'rejectionId', 'rejectedAt', 'code'] as const;
/** Only this exact original-key GET shape is a durable-registration refusal.
 * It says nothing about prior console captures or unrelated native writes. */
export function configurationWorkflowRejection(raw: unknown, original: ConfigurationWorkflowAttempt): ConfigurationWorkflowRejection {
  const attempt = cleanAttempt(original);
  if (!record(raw) || Object.keys(raw).length !== rejectionFields.length || rejectionFields.some(field => !Object.hasOwn(raw, field))
    || raw.domain !== 'configuration' || raw.authorityDomain !== 'durable-configuration-v1' || raw.receiptKind !== 'durable-submission-rejected-v1'
    || raw.result !== 'rejected' || raw.commandCompleted !== true || raw.registrationCompleted !== false || raw.registrationRejected !== true
    || raw.submissionCompleted !== false || raw.knownNoEffect !== true || raw.effectScope !== 'durable-registration' || raw.nativeWrites !== 'none'
    || raw.newPreviewRequired !== true || raw.code !== 'CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED'
    || raw.idempotencyKey !== attempt.key || raw.actorId !== attempt.actor || raw.clusterId !== attempt.cid || raw.workspaceId !== attempt.wid
    || raw.sourceJobId !== attempt.sourceJobId || raw.sourcePlanId !== attempt.sourcePlanId || raw.sourcePlanRevision !== attempt.sourcePlanRevision
    || raw.sourcePlanHash !== attempt.sourcePlanHash || !exactId(raw.rejectionId) || !instant(raw.rejectedAt)) throw invalid();
  return Object.freeze(Object.fromEntries(rejectionFields.map(field => [field, raw[field]]))) as unknown as ConfigurationWorkflowRejection;
}
function rejectionArchiveKey(original: ConfigurationWorkflowAttempt): string {
  const safe = cleanAttempt(original);
  return `kongpilot.configurationWorkflowRejected:${safe.actor}:${safe.cid}:${safe.wid}:${safe.sourcePlanId}`;
}
/** Preserve the original key and verified receipt before releasing only the
 * matching active transaction. Storage failure or a replaced journal blocks
 * release; neither path clears another intent or mints a replacement key. */
export function settleConfigurationWorkflowRejection(original: ConfigurationWorkflowAttempt, raw: unknown): ConfigurationWorkflowSettledRejection {
  const safe = cleanAttempt(original), receipt = configurationWorkflowRejection(raw, safe), previous = readConfigurationWorkflowAttempt(safe);
  if (!previous || previous.state !== 'unknown' || JSON.stringify({ ...previous, state: 'pending' }) !== JSON.stringify({ ...safe, state: 'pending' })) throw invalid();
  const entry: ConfigurationWorkflowSettledRejection = { version: 1, state: 'settled-rejected', original: { ...safe, state: 'unknown' }, receipt };
  const key = rejectionArchiveKey(safe), old = sessionStorage.getItem(key);
  if (old !== null && old !== JSON.stringify(entry)) throw invalid();
  sessionStorage.setItem(key, JSON.stringify(entry));
  clearConfigurationWorkflowAttempt(safe);
  return entry;
}
/** This retained public receipt only blocks reuse of its old source. It never
 * authorizes a write or substitutes for a current authenticated receipt read. */
function readRejectionArchive(identity: ConfigurationIdentity, sourcePlanId: string): ConfigurationWorkflowSettledRejection | undefined {
  if (!validConfigurationWorkflowIdentity(identity) || !exactId(sourcePlanId)) throw invalid();
  const raw = sessionStorage.getItem(`kongpilot.configurationWorkflowRejected:${identity.actor}:${identity.cid}:${identity.wid}:${sourcePlanId}`);
  if (raw === null) return;
  let entry: any; try { entry = JSON.parse(raw); } catch { throw invalid(); }
  if (!record(entry) || entry.version !== 1 || entry.state !== 'settled-rejected' || Object.keys(entry).length !== 4) throw invalid();
  const original = cleanAttempt(entry.original), receipt = configurationWorkflowRejection(entry.receipt, original);
  if (original.actor !== identity.actor || original.cid !== identity.cid || original.wid !== identity.wid || original.sourcePlanId !== sourcePlanId) throw invalid();
  return { version: 1, state: 'settled-rejected', original, receipt };
}
export function configurationWorkflowSourceWasRejected(identity: ConfigurationIdentity, sourcePlanId: string): boolean {
  return !!readRejectionArchive(identity, sourcePlanId);
}
export function readConfigurationWorkflowRejectedSource(identity: ConfigurationIdentity, plan: ConfigurationWorkflowPlan): ConfigurationWorkflowSettledRejection | undefined {
  const entry = readRejectionArchive(identity, plan.id);
  if (entry && !configurationWorkflowSourceMatches(entry.original, plan)) throw invalid();
  return entry;
}
/** The durable issue plus original by-key receipt prove registration only.
 * A later failed/unknown execution is kept as its actual state, never success. */
export function configurationWorkflowReceiptPointer(raw: unknown, original: ConfigurationWorkflowAttempt): ConfigurationWorkflowRegistration {
  const attempt = cleanAttempt(original);
  if (!record(raw) || !record(raw.job) || !record(raw.job.safeProgress)) throw invalid();
  const job = raw.job, progress = job.safeProgress;
  if (raw.domain !== 'configuration' || raw.durable !== true || raw.registrationCompleted !== true || raw.submissionCompleted !== true
    || raw.idempotencyKey !== attempt.key || raw.clusterId !== attempt.cid || raw.workspaceId !== attempt.wid || raw.actorId !== attempt.actor
    || job.clusterId !== attempt.cid || job.workspaceId !== attempt.wid || job.actorId !== attempt.actor
    || !record(raw.originalScope) || raw.originalScope.clusterId !== attempt.cid || raw.originalScope.workspaceId !== attempt.wid
    || !exactId(job.id) || raw.id !== job.id || raw.jobId !== job.id || job.id === attempt.sourceJobId
    || !exactId(job.planId) || raw.planId !== job.planId || job.planId === attempt.sourcePlanId
    || !exactId(job.workflowId) || raw.workflowId !== job.workflowId
    || raw.executionMode !== 'approval' || job.executionMode !== 'approval' || raw.approvalRequired !== true || job.approvalRequired !== true
    || !['apply', 'rollback'].includes(job.kind) || raw.kind !== job.kind || raw.state !== job.state
    || !['waiting_approval', 'pending', 'running', 'succeeded', 'failed', 'partial', 'uncertain', 'cancelled'].includes(job.state)
    || raw.authorityDomain !== 'durable-configuration-v1' || job.authorityDomain !== raw.authorityDomain || progress.authorityDomain !== raw.authorityDomain
    || !exactId(raw.durableIssueId) || job.durableIssueId !== raw.durableIssueId || progress.durableIssueId !== raw.durableIssueId
    || raw.sourcePlanId !== attempt.sourcePlanId || job.sourcePlanId !== attempt.sourcePlanId || progress.sourcePlanId !== attempt.sourcePlanId
    || !instant(raw.expiresAt) || job.expiresAt !== raw.expiresAt || progress.expiresAt !== raw.expiresAt) throw invalid();
  return { actorId: attempt.actor, clusterId: attempt.cid, workspaceId: attempt.wid, sourcePlanId: attempt.sourcePlanId, jobId: job.id, planId: job.planId, workflowId: job.workflowId, issueId: raw.durableIssueId,
    expiresAt: raw.expiresAt, state: job.state, registrationOnly: true };
}
export function configurationWorkflowRegisteredPlanMatches(proof: ConfigurationWorkflowRegistration, plan: ConfigurationWorkflowPlan): boolean {
  return !!plan && proof.registrationOnly === true && exactId(proof.planId) && exactId(proof.jobId) && exactId(proof.workflowId)
    && plan.clusterId === proof.clusterId && plan.workspaceId === proof.workspaceId && plan.id === proof.planId && plan.jobId === proof.jobId && plan.workflowId === proof.workflowId
    && plan.authorityDomain === 'durable-configuration-v1' && plan.durableIssueId === proof.issueId && plan.expiresAt === proof.expiresAt
    && plan.executionMode === 'approval' && plan.approvalRequired === true && positive(plan.planRevision) && hash(plan.planHash)
    && plan.capabilities?.apply === false && plan.capabilities.durableSubmit === false;
}
