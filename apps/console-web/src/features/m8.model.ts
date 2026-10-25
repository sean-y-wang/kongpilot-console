import { canonicalId, scopeQuery } from '../api/workspace-scope';
import type { RecoveryReference } from '../api/workspace-scope';
import { redactForDisplay } from '../api/redaction';
import { isSensitiveSchemaName } from '../components/kong-schema-rules';
import { jsonPointerParts } from './m7.redaction';
import { grantMatches } from '../api/permissions';
import type { User } from '../api/types';
import type { ConfigurationIdentity, ConfigurationSelection, ConfigurationReceipt, ConfigurationJob, SnapshotSchedule, ConfigurationPlan, ConfigurationObservation, ConfigurationReconciliation, ConfigurationAbandonmentIntent, ConfigurationAbandonmentResult } from './m8.types';
export const MAX_CONFIGURATION_UPLOAD_BYTES = 8 * 1024 * 1024;
const durableSubmitReasons = Object.freeze({
  CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED: '当前配置的 Target 权重变更封存包不完整，暂不能创建配置工单',
  CONFIGURATION_DURABLE_SOURCE_REJECTED: '当前配置已变化，原计划已拒绝，请重新预览后创建配置工单',
  CONFIGURATION_DURABLE_SOURCE_ALREADY_SUBMITTED: '原计划已创建配置工单，请核验原请求并查看对应工单',
});
/** Only fixed public reasons are rendered; server strings never become UI copy. */
export function configurationDurableSubmitBlocker(value: unknown): Readonly<{code: keyof typeof durableSubmitReasons; reason: string}> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const caps = value as Record<string, unknown>, code = caps.durableSubmitBlockerCode;
  if (caps.durableSubmit !== false || typeof code !== 'string' || !Object.hasOwn(durableSubmitReasons, code)
    || typeof caps.durableSubmitReason !== 'string' || !caps.durableSubmitReason.trim() || caps.durableSubmitReason.length > 256) return undefined;
  return Object.freeze({code: code as keyof typeof durableSubmitReasons, reason: durableSubmitReasons[code as keyof typeof durableSubmitReasons]});
}
/** A disposed original source cannot expose the legacy action in a fresh tab. */
export function configurationDurableSourceBlocked(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const caps = value as Record<string, unknown>;
  return caps.durableSubmit === false
    && (caps.durableSubmitBlockerCode === 'CONFIGURATION_DURABLE_SOURCE_REJECTED' || caps.durableSubmitBlockerCode === 'CONFIGURATION_DURABLE_SOURCE_ALREADY_SUBMITTED');
}
export function sameConfigurationIdentity(a: ConfigurationIdentity, b: ConfigurationIdentity): boolean { return a.actor === b.actor && a.version === b.version && a.cid === b.cid && a.wid === b.wid; }
export function configurationQueryIdentity(identity: ConfigurationIdentity, resource: string, filters: Record<string, string> = {}): string { return JSON.stringify([identity.actor, identity.version, identity.cid, identity.wid, resource, Object.entries(filters).sort(([a], [b]) => a.localeCompare(b))]); }
export function configurationSelection(value: ConfigurationSelection): ConfigurationSelection {
  if (!['workspace', 'cluster', 'services'].includes(value.scope)) throw new Error('配置范围无效。');
  // rc-field-form validates mounted fields only. Workspace/cluster forms do
  // not mount the Services picker, so its missing field means no Service roots.
  const supplied = value.serviceIds === undefined && value.scope !== 'services' ? [] : value.serviceIds;
  if (!Array.isArray(supplied)) throw new Error('请选择合法的 Service ID 列表。');
  const ids = supplied.map(id => canonicalId(id));
  if (ids.some(id => !id) || new Set(ids).size !== ids.length || ids.length > 100 || value.scope === 'services' && ids.length === 0 || value.scope !== 'services' && ids.length !== 0) throw new Error('请选择合法且不重复的 Service ID。');
  return { scope: value.scope, serviceIds: (ids as string[]).sort() };
}
export function configurationSelectionQuery(value: ConfigurationSelection): Record<string, string> {
  const selected = configurationSelection(value);
  return { scope: selected.scope, ...(selected.serviceIds.length ? { serviceIds: selected.serviceIds.join(',') } : {}) };
}
export function snapshotScheduleUpdate(row: SnapshotSchedule, paused: boolean) {
  if (!Number.isSafeInteger(row.revision) || row.revision < 1 || !['active', 'paused'].includes(row.state)) throw new Error('定时策略不能在当前状态修改。');
  return { ...configurationSelection({ scope: row.scopeKind, serviceIds: row.rootIds }), name: row.name, intervalMinutes: row.intervalMinutes, timezone: row.timezone, retentionDays: row.retentionDays, revision: row.revision, paused, confirmed: true as const, confirm_name: row.name };
}
/** An artifact revision is not its job's metadata revision. No guessed version is sent. */
export function configurationDownloadIntent(job: ConfigurationJob) {
  const id = canonicalId(job.exportId);
  if (!id || job.state !== 'succeeded' || job.capabilities?.download !== true || !Number.isSafeInteger(job.exportRevision) || job.exportRevision! < 1 || typeof job.confirmationName !== 'string' || !job.confirmationName || !['deck-1.1', 'review-json'].includes(job.format ?? '')) return undefined;
  return { id, revision: job.exportRevision!, name: job.confirmationName, format: job.format as 'deck-1.1' | 'review-json' };
}
const abandonmentFields = ['jobId', 'revision', 'executionId', 'executionRevision', 'planRevision', 'planHash', 'leaseGeneration', 'workflowExecutionId', 'confirmationName'] as const;
export interface ConfigurationAbandonmentAuthority { writable: boolean; snapshotsWrite: boolean; workflowsWrite: boolean; }
export function configurationAbandonmentAuthority(user: User, identity: ConfigurationIdentity, writable: boolean): ConfigurationAbandonmentAuthority {
  const current = user.id === identity.actor && !!identity.version && user.permissionsVersion === identity.version;
  const whole = (module: string) => current && (!!user.capabilities?.platformAdmin || !!user.capabilities?.grants.some(grant => ['global', 'workspace'].includes(grant.scope_type) && grantMatches(grant, module, 'write', { clusterId: identity.cid, workspaceId: identity.wid })));
  return { writable: writable && current, snapshotsWrite: whole('snapshots'), workflowsWrite: whole('workflows') };
}
/** The server supplies the current lease/execution tuple. Never infer one from progress or a timeout. */
export function configurationAbandonmentIntent(job: ConfigurationJob, identity: ConfigurationIdentity, authority: ConfigurationAbandonmentAuthority): ConfigurationAbandonmentIntent | undefined {
  const intent = job.abandonmentIntent;
  if (!authority.writable || !authority.snapshotsWrite || !identity.version || !canonicalId(identity.actor) || !canonicalId(identity.cid) || !canonicalId(identity.wid)
    || job.clusterId !== identity.cid || job.workspaceId !== identity.wid || job.actorId !== identity.actor || !canonicalId(job.id) || !canonicalId(job.idempotencyKey)
    || job.state !== 'running' || !['apply', 'rollback'].includes(job.kind) || job.capabilities?.abandon !== true || !intent || typeof intent !== 'object'
    || Object.keys(intent).length !== abandonmentFields.length || abandonmentFields.some(name => !Object.hasOwn(intent, name))
    || intent.jobId !== job.id || intent.revision !== job.revision || intent.confirmationName !== `abandon:${job.id}`
    || !canonicalId(intent.executionId) || !['revision', 'executionRevision', 'planRevision', 'leaseGeneration'].every(name => Number.isSafeInteger(intent[name as keyof ConfigurationAbandonmentIntent]) && Number(intent[name as keyof ConfigurationAbandonmentIntent]) > 0)
    || !/^[a-f\d]{64}$/i.test(intent.planHash ?? '')
    || job.executionMode === 'approval' && (!authority.workflowsWrite || !canonicalId(intent.workflowExecutionId))
    || job.executionMode === 'direct' && intent.workflowExecutionId !== null || !['direct', 'approval'].includes(job.executionMode ?? '')) return undefined;
  return Object.fromEntries(abandonmentFields.map(name => [name, intent[name]])) as unknown as ConfigurationAbandonmentIntent;
}
/** Repeat the entire captured identity/tuple check immediately before the one POST. */
export function configurationAbandonmentBody(job: ConfigurationJob, captured: ConfigurationIdentity, current: ConfigurationIdentity, expected: ConfigurationAbandonmentIntent, authority: ConfigurationAbandonmentAuthority, confirmation: string) {
  const actual = configurationAbandonmentIntent(job, current, authority);
  if (!sameConfigurationIdentity(captured, current) || !actual || abandonmentFields.some(name => actual[name] !== expected[name]) || confirmation !== actual.confirmationName) throw new Error('原作业、执行元组、权限或确认名称已变化，请读取原状态；不会重发。');
  return { revision: actual.revision, executionId: actual.executionId, executionRevision: actual.executionRevision, planRevision: actual.planRevision, planHash: actual.planHash, leaseGeneration: actual.leaseGeneration, workflowExecutionId: actual.workflowExecutionId, confirmed: true as const, confirm_name: actual.confirmationName };
}
export function configurationAbandonmentResult(value: unknown, job: ConfigurationJob, intent: ConfigurationAbandonmentIntent): ConfigurationAbandonmentResult {
  const row = value as ConfigurationAbandonmentResult | null;
  if (!row || row.jobId !== job.id || row.executionId !== intent.executionId || row.clusterId !== job.clusterId || row.workspaceId !== job.workspaceId || row.state !== 'uncertain'
    || row.terminalFailureRecorded !== true || row.abandoned !== true || row.originalWorkflowUnchanged !== true || row.originalNativeReceiptsUnchanged !== true
    || ![row.completedSteps, row.unresolvedSteps].every(count => Number.isSafeInteger(count) && count >= 0)) throw new Error('原作业失败记账回执尚未得到证明；保留原作业并只读核验。');
  return { jobId: row.jobId, executionId: row.executionId, clusterId: row.clusterId, workspaceId: row.workspaceId, state: 'uncertain', completedSteps: row.completedSteps, unresolvedSteps: row.unresolvedSteps, terminalFailureRecorded: true, abandoned: true, originalWorkflowUnchanged: true, originalNativeReceiptsUnchanged: true };
}
export function configurationPath(identity: ConfigurationIdentity, resource: string, filters: Record<string, string> = {}): string {
  const cid = canonicalId(identity.cid), wid = canonicalId(identity.wid);
  if (!cid || !wid || !/^(snapshots|configuration)(?:\/|$)/.test(resource) || /(?:\?|#|\.\.|https?:)/i.test(resource)) throw new Error('原配置范围或资源无效。');
  const params = new URLSearchParams(filters); if (params.has('workspaceId') && canonicalId(params.get('workspaceId')) !== wid) throw new Error('工作区不能被当前筛选条件替换。');
  return scopeQuery(`/clusters/${cid}/${resource}${params.size ? `?${params}` : ''}`, cid, wid);
}
export interface ConfigurationReference { kind?: string; clusterId?: string; workspaceId?: string; idempotencyKey?: string; actorId?: string; originalJobId?: string; originalJobKey?: string; abandonmentIntent?: ConfigurationAbandonmentIntent; }
export function configurationOriginalJobPath(ref: ConfigurationReference): string {
  if (ref.kind !== 'configuration' || !canonicalId(ref.originalJobId) || !canonicalId(ref.idempotencyKey)) throw new Error('原作业引用不完整，不能使用新请求键替代。');
  return configurationPath({ cid: ref.clusterId, wid: ref.workspaceId }, `configuration/jobs/${ref.originalJobId}`);
}
/** Factual terminal accounting never proves unresolved Native outcomes or releases their block. */
export function configurationOriginalJobResult(value: unknown, ref: ConfigurationReference) {
  const identity = { actor: ref.actorId, cid: ref.clusterId, wid: ref.workspaceId };
  const row = configurationDetailEntity<ConfigurationJob>(value, identity, ref.originalJobId!);
  if (!canonicalId(ref.actorId) || row.actorId !== ref.actorId || !canonicalId(row.idempotencyKey)) throw new Error('原作业账号或执行键不匹配，仍保留写入阻止。');
  return { complete: false as const, success: false as const, jobId: row.id, label: row.safeProgress?.abandoned === true && row.state === 'uncertain' ? '原作业已记录过期执行事实；未知结果和原范围写入阻止仍保留' : '仅已读取原作业；原未决结果仍须核验，不会重发收口请求' };
}
/** Only an explicit stop-retrying confirmation can consume this proof. Native uncertainty stays recorded. */
export function configurationAbandonmentReadback(value: unknown, ref: ConfigurationReference, current: ConfigurationIdentity, authority: ConfigurationAbandonmentAuthority): ConfigurationJob {
  const row = configurationDetailEntity<ConfigurationJob>(value, current, ref.originalJobId!), intent = ref.abandonmentIntent, progress = row.safeProgress;
  const typed = intent && configurationAbandonmentIntent({ ...row, state: 'running', revision: intent.revision, capabilities: { abandon: true }, abandonmentIntent: intent }, current, authority);
  if (!authority.writable || !authority.snapshotsWrite || current.actor !== ref.actorId || current.cid !== ref.clusterId || current.wid !== ref.workspaceId || !current.version
    || !intent || !typed || intent.jobId !== ref.originalJobId || intent.confirmationName !== `abandon:${ref.originalJobId}` || !canonicalId(ref.originalJobKey) || row.idempotencyKey !== ref.originalJobKey
    || row.actorId !== current.actor || row.abandonmentSessionMatches !== true || row.state !== 'uncertain' || !['apply', 'rollback'].includes(row.kind)
    || row.executionMode === 'approval' && (!authority.workflowsWrite || !canonicalId(intent.workflowExecutionId)) || row.executionMode === 'direct' && intent.workflowExecutionId !== null || !['direct', 'approval'].includes(row.executionMode ?? '')
    || row.revision !== intent.revision + 1 || progress?.abandoned !== true || progress.terminalFailureRecorded !== true || progress.executionId !== intent.executionId
    || progress.executionRevision !== intent.executionRevision + 1 || progress.planRevision !== intent.planRevision || progress.planHash !== intent.planHash
    || progress.leaseGeneration !== intent.leaseGeneration || progress.workflowExecutionId !== intent.workflowExecutionId) throw new Error('原作业、当前会话/权限或收口证明不匹配，保留这一条原请求阻止。');
  return row;
}
export function configurationAbandonmentReferencesToResolve(references: RecoveryReference[], value: unknown, ref: ConfigurationReference, current: ConfigurationIdentity, authority: ConfigurationAbandonmentAuthority, confirmation: string): RecoveryReference[] {
  const row = configurationAbandonmentReadback(value, ref, current, authority);
  if (confirmation !== `abandon:${row.id}`) throw new Error('必须明确确认停止重试这一条原请求。');
  return references.filter(item => item.actor_id === current.actor && item.kind === 'configuration' && item.domain === undefined && item.cid === row.clusterId && item.wid === row.workspaceId
    && (item.idempotencyKey === row.idempotencyKey && (!item.originalJobId || item.originalJobId === row.id)
      || item.idempotencyKey === ref.idempotencyKey && item.originalJobId === row.id && item.originalJobKey === row.idempotencyKey));
}
export function isConfigurationKind(kind?: string): boolean { return kind === 'configuration'; }
export function configurationReceiptPath(ref: ConfigurationReference): string { const cid = canonicalId(ref.clusterId), wid = canonicalId(ref.workspaceId), key = canonicalId(ref.idempotencyKey); if (ref.kind !== 'configuration' || !cid || !wid || !key) throw new Error('原操作账号与范围标识不完整，不能用当前选择替代。'); return configurationPath({ cid, wid }, `configuration/jobs/by-key/${key}`); }
export function configurationReceiptResult(value: unknown, ref: ConfigurationReference): { complete: boolean; success: boolean; label: string; workflowId?: string; jobId?: string; pending?: boolean } {
  const row = value as ConfigurationReceipt | null, unknown = { complete: false, success: false, label: '配置结果仍待核验，保留原键并阻止新写' };
  if (!row || row.domain !== 'configuration' || row.idempotencyKey !== ref.idempotencyKey || row.clusterId !== ref.clusterId || row.workspaceId !== ref.workspaceId || row.durable !== true || !canonicalId(row.job?.id) || row.job.clusterId !== ref.clusterId || row.job.workspaceId !== ref.workspaceId || ref.actorId && row.job.actorId !== ref.actorId || row.state !== row.job.state) return unknown;
  if (row.submissionCompleted === true && canonicalId(row.workflowId) && row.executionCompleted !== true && ['waiting_approval', 'pending_approval', 'submitted'].includes(row.state) && row.job.approvalRequired === true && row.job.executionMode === 'approval') return { complete: true, success: true, label: '工单已登记，尚未执行网关变更', workflowId: row.workflowId!, jobId: row.job.id };
  if (row.executionCompleted === true && ['succeeded', 'failed', 'cancelled'].includes(row.state)) return { complete: true, success: row.state === 'succeeded', label: row.state !== 'succeeded' ? '父作业已结束，请检查失败结果' : ['apply', 'rollback'].includes(row.job.kind) ? '父作业已完成；逐对象验证结果见详情' : '配置作业已完成，未执行网关变更', jobId: row.job.id };
  if (row.submissionCompleted === true && ['apply', 'rollback'].includes(row.job.kind) && ['pending', 'running'].includes(row.state)) return { complete: false, success: false, pending: true, label: '执行作业已登记，等待全部逐对象结果；当前范围的新写保持阻止', jobId: row.job.id };
  if (row.submissionCompleted === true && ['capturing', 'planning', 'ready', 'pending', 'running'].includes(row.state) && !['apply', 'rollback'].includes(row.job.kind)) return { complete: true, success: true, label: '任务已持久登记，完整性与生成结果见任务详情', jobId: row.job.id };
  return unknown;
}
/** Observation is independent of the original write's causal outcome and never releases its block. */
export function configurationReconcileResult(value: unknown, ref: ConfigurationReference, plan: Pick<ConfigurationPlan, 'id' | 'stepCount'>): ConfigurationReconciliation {
  const receipt = value as ConfigurationReceipt | null, proof = configurationReceiptResult(value, ref), progress = receipt?.job?.safeProgress;
  const invalid = () => new Error('原范围的只读核验回执尚未完成或与计划不一致。');
  if (!proof.complete || !proof.success || receipt?.state !== 'succeeded' || receipt.executionCompleted !== true || receipt.job.kind !== 'reconcile' || progress?.reconciledPlanId !== plan.id || progress.readOnly !== true || progress.executionChanged !== false || !Array.isArray(progress.observations) || progress.observations.length !== plan.stepCount || progress.observations.length > 10000) throw invalid();
  const types = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'targets', 'certificates', 'ca_certificates', 'snis', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
  const seen = new Set<string>(), observations = progress.observations.map((item: unknown): ConfigurationObservation => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw invalid();
    const row = item as ConfigurationObservation;
    if (!canonicalId(row.planStepId) || seen.has(row.planStepId) || !types.includes(row.type) || !['create', 'update', 'delete'].includes(row.action) || row.originalId !== null && !canonicalId(row.originalId) || !canonicalId(row.effectiveId) || typeof row.present !== 'boolean' || typeof row.expectedFieldsMatch !== 'boolean' || row.causalOutcomeUnproven !== true || typeof row.observedAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(row.observedAt) || !Number.isFinite(Date.parse(row.observedAt))) throw invalid();
    seen.add(row.planStepId);
    return { planStepId: row.planStepId, type: row.type, action: row.action, originalId: row.originalId, effectiveId: row.effectiveId, present: row.present, expectedFieldsMatch: row.expectedFieldsMatch, causalOutcomeUnproven: true, observedAt: row.observedAt };
  });
  return { jobId: receipt.job.id, observations };
}
export function assertConfigurationEntity<T extends { id: string; clusterId: string; workspaceId: string }>(row: T, identity: ConfigurationIdentity, id: string): T { if (!row || row.id !== canonicalId(id) || row.clusterId !== identity.cid || row.workspaceId !== identity.wid) throw new Error('配置对象与请求的原范围不一致。'); return row; }
export function configurationDetailEntity<T extends { id: string; clusterId: string; workspaceId: string }>(value: unknown, identity: ConfigurationIdentity, id: string): T {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('配置详情响应无效。');
  const wrapper = value as Record<string, unknown>, source = Object.hasOwn(wrapper, 'entity') ? wrapper.entity : wrapper;
  if (!source || typeof source !== 'object' || Array.isArray(source)) throw new Error('配置详情摘要无效。');
  const row = { ...source } as T & { capabilities?: unknown };
  const rawCapabilities = Object.hasOwn(wrapper, 'entity') && Object.hasOwn(wrapper, 'capabilities') ? wrapper.capabilities : row.capabilities;
  if (rawCapabilities !== undefined) {
    const source = rawCapabilities && typeof rawCapabilities === 'object' && !Array.isArray(rawCapabilities) ? rawCapabilities as Record<string, unknown> : {};
    const capabilities: Record<string, unknown> = Object.fromEntries(Object.entries(source).filter(([name, flag]) => typeof flag === 'boolean' && name !== 'durableSubmitReason' && name !== 'durableSubmitBlockerCode'));
    const blocker = configurationDurableSubmitBlocker(source);
    if (blocker) { capabilities.durableSubmitReason = blocker.reason; capabilities.durableSubmitBlockerCode = blocker.code; }
    row.capabilities = capabilities;
  }
  return assertConfigurationEntity(row, identity, id);
}
export function configurationConfirmation(plan: { planRevision: number; planHash: string; name: string; deleteCount: number; deleteConfirmName: string | null }, name: string, deletion?: string) {
  if (!Number.isSafeInteger(plan.planRevision) || plan.planRevision < 1 || !Number.isSafeInteger(plan.deleteCount) || plan.deleteCount < 0 || !/^[a-f\d]{64}$/i.test(plan.planHash) || name !== plan.name || plan.deleteCount > 0 && (!plan.deleteConfirmName || deletion !== plan.deleteConfirmName)) throw new Error('确认名称或删除确认值不匹配。');
  return { planRevision: plan.planRevision, planHash: plan.planHash, confirmed: true as const, confirm_name: name, ...(plan.deleteCount > 0 ? { confirm_deletes: true as const } : {}) };
}
export function basicPasswordIntentMap(rows?: Array<{ key: string; intent: 'keep' | 'replace' }>): Record<string, 'keep' | 'replace'> {
  if (!rows) return {};
  if (!Array.isArray(rows) || rows.length > 256) throw new Error('密码意图最多 256 项。');
  const entries = rows.map(row => { const key = row.key?.trim(); if (!key || !/^(?:consumers\[\d+\]\.basicauth_credentials\[\d+\]|credentials:basic-auth:[a-f\d-]{36}:[a-f\d-]{36})$/i.test(key) || !['keep', 'replace'].includes(row.intent)) throw new Error('请填写 Basic 凭证的确切结构路径或对象标识，以及保留/替换意图。'); return [key, row.intent] as const; });
  if (new Set(entries.map(([key]) => key)).size !== entries.length) throw new Error('同一 Basic 凭证不能重复指定密码意图。');
  return Object.fromEntries(entries);
}
export function safeConfigurationValue(field: { path: string; secret?: boolean; secretChange?: string }, value: unknown): string {
  let names: string[]; try { names = field.path.startsWith('/') ? jsonPointerParts(field.path) : field.path.split('.'); } catch { return '[字段路径无效]'; }
  if (field.secret || names.some(name => isSensitiveSchemaName(name, typeof value))) return field.secretChange === 'provided' ? '已提供新值' : field.secretChange === 'preserved' ? '保留现有值' : field.secretChange === 'unavailable' ? '来源不可恢复' : '秘密值已隐藏';
  const out = JSON.stringify(redactConfigurationValue(value)); return out === undefined ? '（字段缺失）' : out.length > 4096 ? `${out.slice(0, 4096)}…` : out;
}
/** The BFF masks connection userinfo too; this keeps the display defense identical. */
export function redactConfigurationValue(value: unknown): unknown {
  const visit = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(visit);
    if (item && typeof item === 'object') return Object.fromEntries(Object.entries(item).map(([name, child]) => [name, visit(child)]));
    if (typeof item === 'string' && /^[a-z][a-z\d+.-]*:\/\/[^/\s]*@/i.test(item)) {
      try { const url = new URL(item); if (url.username || url.password) { url.username = 'REDACTED'; url.password = ''; return url.toString(); } } catch { return '[REDACTED]'; }
    }
    return item;
  };
  return visit(redactForDisplay(value));
}
export function safeConfigurationPreview(value: unknown): string { const text = JSON.stringify(redactConfigurationValue(value), null, 2) ?? 'null'; return text.length > 65536 ? text.slice(0, 65536) + '\n…（显示上限 64KiB）' : text; }
export function gitOpsMetadata(values: { repositoryLabel: string; commitSha: string; pipelineReference: string; jobId: string }) {
  const name = values.repositoryLabel.trim(), ref = values.pipelineReference.trim(), sha = values.commitSha.trim();
  if (!canonicalId(values.jobId) || !/^(?:[a-f\d]{40}|[a-f\d]{64})$/i.test(sha) || !/^[A-Za-z0-9 _./-]{1,128}$/.test(name) || !/^[A-Za-z0-9._:/-]{1,256}$/.test(ref) || /(?:[a-z][a-z\d+.-]*:\/\/|https?:|@|[?&#=]|(?:token|password|secret|authorization|api[_-]?key)[:=])/i.test(ref)) throw new Error('仅允许英文仓库显示名、commit SHA 与不含 URL/token 的流水线引用。');
  return { jobId: values.jobId, repositoryLabel: name, commitSha: sha.toLowerCase(), pipelineReference: ref };
}
