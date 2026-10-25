import { canonicalId } from '../api/workspace-scope';
import type { Capabilities, PermissionAction } from '../api/types';
import type { GovernanceCredentialKind, GovernanceFixAction, GovernanceOperationKind, GovernancePlanLink, GovernanceReceipt, GovernanceSourceObject } from './governance.types';

export type GovernanceModule = 'governance' | 'lint' | 'drift' | 'promote';
export interface GovernanceIdentity { actor?: string; version?: string; cid?: string; wid?: string; }
export interface GovernanceEnvironment { clusterId: string; workspaceId: string; scope: 'workspace' | 'services'; serviceIds: string[]; }
export interface GovernancePairIdentity { actor?: string; version?: string; source: GovernanceEnvironment; target: GovernanceEnvironment; }

export function sameGovernanceIdentity(a: GovernanceIdentity, b: GovernanceIdentity) {
  return a.actor === b.actor && a.version === b.version && a.cid === b.cid && a.wid === b.wid;
}
export function governanceIdentityKey(identity: GovernanceIdentity, resource: string, filters: Record<string, string> = {}) {
  return JSON.stringify([identity.actor, identity.version, identity.cid, identity.wid, resource, Object.entries(filters).sort(([a], [b]) => a.localeCompare(b))]);
}
export function governanceEnvironment(input: unknown): GovernanceEnvironment {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('请选择有效的环境范围。');
  const value = input as Record<string, unknown>, clusterId = canonicalId(value.clusterId), workspaceId = canonicalId(value.workspaceId);
  if (!clusterId || !workspaceId || !['workspace', 'services'].includes(String(value.scope))) throw new Error('请选择集群、工作区与配置范围。');
  const ids = value.serviceIds ?? [];
  if (!Array.isArray(ids) || ids.length > 100 || ids.some(id => !canonicalId(id))) throw new Error('Service 范围无效。');
  const serviceIds = [...new Set(ids.map(id => canonicalId(id)!))].sort();
  if (value.scope === 'services' && !serviceIds.length || value.scope === 'workspace' && serviceIds.length) throw new Error('Service 选择与配置范围不一致。');
  return { clusterId, workspaceId, scope: value.scope as GovernanceEnvironment['scope'], serviceIds };
}
export function governancePair(source: unknown, target: unknown, actor?: string, version?: string): GovernancePairIdentity {
  const pair = { actor, version, source: governanceEnvironment(source), target: governanceEnvironment(target) };
  if (!canonicalId(actor) || !version || pair.source.clusterId === pair.target.clusterId && pair.source.workspaceId === pair.target.workspaceId) throw new Error('请选择两个不同的授权环境。');
  return pair;
}
export function sameGovernancePair(a: GovernancePairIdentity, b: GovernancePairIdentity) {
  return a.actor === b.actor && a.version === b.version && JSON.stringify(a.source) === JSON.stringify(b.source) && JSON.stringify(a.target) === JSON.stringify(b.target);
}
export function governancePath(identity: GovernanceIdentity, resource: string, filters: Record<string, string> = {}) {
  if (!canonicalId(identity.cid) || !canonicalId(identity.wid) || !/^[a-z][a-z0-9/-]*$/.test(resource) || resource.includes('//') || resource.includes('..')) throw new Error('治理请求范围无效。');
  const query = new URLSearchParams(filters); query.set('workspaceId', identity.wid!);
  return `/clusters/${identity.cid}/governance/${resource}?${query}`;
}
/** Coarse UX gate only; the server still proves every object and both environments. */
export function governanceCan(capabilities: Capabilities | undefined, module: GovernanceModule, action: PermissionAction, environment: { clusterId?: string; workspaceId?: string }, whole = false) {
  if (!environment.clusterId || !environment.workspaceId || !capabilities) return false;
  if (capabilities.platformAdmin) return true;
  return capabilities.grants.some(grant => grant.module === module && grant.action === action && (!grant.cluster_id || grant.cluster_id === environment.clusterId) && (!grant.workspace_id || grant.workspace_id === environment.workspaceId)
    && (grant.scope_type === 'global' || grant.scope_type === 'workspace' && grant.scope_values.includes(environment.workspaceId!) || !whole && ['tag_group', 'entity'].includes(grant.scope_type) && grant.scope_values.length > 0));
}
export function governancePairCan(capabilities: Capabilities | undefined, module: 'drift' | 'promote', action: PermissionAction, pair: GovernancePairIdentity) {
  return governanceCan(capabilities, module, 'read', pair.source) && governanceCan(capabilities, module, action, pair.target);
}
export function governanceObjectLink(type: string, id: unknown, parentId?: unknown): string | undefined {
  const nativeId = canonicalId(id), parent = canonicalId(parentId);
  if (!nativeId) return;
  if (['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis'].includes(type)) return `/entities/${type}/${nativeId}`;
  if (type === 'targets' && parent) return `/entities/upstreams/${parent}`;
}
export function governanceTypedConfirmation(name: unknown, input: unknown) {
  if (typeof name !== 'string' || !name.trim() || name.length > 200 || input !== name) throw new Error('确认名称不一致。');
  return { confirmed: true as const, confirm_name: name };
}
export function governanceRuleDocument(text: unknown): Record<string, unknown> {
  if (typeof text !== 'string' || new TextEncoder().encode(text).byteLength > 16384) throw new Error('JSON 配置超过大小限制。');
  let value: unknown; try { value = JSON.parse(text); } catch { throw new Error('JSON 配置格式无效。'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('JSON 配置必须为对象。');
  let nodes = 0;
  const inspect = (item: unknown, depth: number) => { if (depth > 16 || ++nodes > 512) throw new Error('JSON 配置嵌套或字段超过限制。'); if (item && typeof item === 'object') for (const [key, nested] of Object.entries(item)) { if (['__proto__', 'constructor', 'prototype', '$ref'].includes(key)) throw new Error('JSON 配置包含不允许的字段。'); inspect(nested, depth + 1); } }; inspect(value, 0);
  return value as Record<string, unknown>;
}

export interface GovernanceOperationReference { actorId: string; clusterId: string; workspaceId: string; idempotencyKey: string; kind?: GovernanceOperationKind; }
export function governanceRecoveryReference(recovery: { kind?: string; domain?: string; clusterId?: string; workspaceId?: string; idempotencyKey?: string }, actorId?: string): GovernanceOperationReference {
  if (recovery.kind !== 'governance' || recovery.domain !== undefined || !canonicalId(actorId) || !canonicalId(recovery.clusterId) || !canonicalId(recovery.workspaceId) || !canonicalId(recovery.idempotencyKey)) throw new Error('原治理操作范围无效。');
  return { actorId: actorId!, clusterId: recovery.clusterId!, workspaceId: recovery.workspaceId!, idempotencyKey: recovery.idempotencyKey! };
}
export function governanceReceiptPath(reference: GovernanceOperationReference) {
  if (![reference.actorId, reference.clusterId, reference.workspaceId, reference.idempotencyKey].every(value => canonicalId(value))) throw new Error('原治理操作标识无效。');
  return governancePath({ actor: reference.actorId, cid: reference.clusterId, wid: reference.workspaceId }, `operations/by-key/${reference.idempotencyKey}`);
}
export function governanceReceiptResult(value: unknown, reference: GovernanceOperationReference): { complete: boolean; success: boolean; receipt: GovernanceReceipt; label: string } {
  governanceReceiptPath(reference);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('尚未读取到可信的原操作回执。');
  const receipt = value as GovernanceReceipt;
  if (receipt.actorId !== reference.actorId || receipt.clusterId !== reference.clusterId || receipt.workspaceId !== reference.workspaceId || receipt.idempotencyKey !== reference.idempotencyKey || reference.kind && receipt.kind !== reference.kind || !canonicalId(receipt.id) || !['governance', 'iam', 'workflow'].includes(receipt.domain) || !['inspection', 'comparison', 'promotion-plan', 'fix-plan', 'rule-change', 'schedule-change'].includes(receipt.kind) || receipt.nativeExecutionRequested !== false) throw new Error('原操作回执与账号、范围或操作不一致。');
  const failed = ['failed', 'cancelled', 'rejected', 'blocked'].includes(receipt.state);
  const nativePlanRegistered = !['promotion-plan', 'fix-plan'].includes(receipt.kind) || receipt.domain !== 'governance' || failed || !!canonicalId(receipt.jobId);
  const metadataFixSealed = receipt.kind !== 'fix-plan' || receipt.domain === 'governance' || receipt.governanceRequestId === receipt.id && receipt.metadataOnlyResult === true && !!canonicalId(receipt.metadataOperationId) && receipt.metadataChildKey === `governance-fix-${receipt.id}` && (receipt.governanceState === 'ready' || failed && receipt.governanceState === 'blocked');
  const registrationState = ['succeeded', 'complete', 'incomplete', 'failed', 'cancelled', 'rejected', 'blocked', 'ready', 'pending_approval', 'waiting_approval', 'awaiting_approval', 'submitted', 'approved', 'active', 'deleted', 'restored'].includes(receipt.state) || receipt.domain === 'workflow' && receipt.state === 'pending';
  const complete = receipt.registrationCompleted === true && registrationState && nativePlanRegistered && metadataFixSealed && receipt.metadataReconciliationPending !== true
    && (receipt.domain !== 'workflow' || receipt.submissionCompleted === true && !!canonicalId(receipt.workflowId))
    && (receipt.domain !== 'iam' || failed || receipt.configurationCommitted === true && receipt.executionCompleted === true);
  const success = complete && !failed;
  return { receipt, complete, success, label: !complete ? '原治理操作尚待核验' : !success ? '原治理操作未成功，请查看结果' : receipt.domain === 'workflow' && receipt.executionCompleted !== true ? '已提交审批' : receipt.kind === 'promotion-plan' || receipt.kind === 'fix-plan' && receipt.domain === 'governance' ? '变更预览已生成，尚未执行网关变更' : receipt.kind === 'fix-plan' && receipt.metadataOnlyResult ? '对象说明已保存' : receipt.kind === 'inspection' || receipt.kind === 'comparison' ? '检查结果已保存' : '治理配置已保存' };
}
export function governancePlanLink(receipt: GovernanceReceipt, expected?: GovernanceEnvironment): GovernancePlanLink | undefined {
  if (!['promotion-plan', 'fix-plan'].includes(receipt.kind) || receipt.nativeExecutionRequested !== false || !canonicalId(receipt.jobId)) return;
  if (receipt.planId && !canonicalId(receipt.planId)) throw new Error('目标计划标识无效。');
  const cid = canonicalId(receipt.targetClusterId) ?? receipt.clusterId, wid = canonicalId(receipt.targetWorkspaceId) ?? receipt.workspaceId;
  if (!canonicalId(cid) || !canonicalId(wid) || expected && (cid !== expected.clusterId || wid !== expected.workspaceId)) throw new Error('目标作业与所选发布环境不一致。');
  return { jobId: receipt.jobId!, planId: receipt.planId, state: receipt.state, targetClusterId: cid, targetWorkspaceId: wid };
}
export function governanceReconcileConfirmation(receipt: GovernanceReceipt, reference: GovernanceOperationReference, confirmation: unknown) {
  governanceReceiptResult(receipt, reference);
  const metadataChild = receipt.metadataOnlyResult === true && ['iam', 'workflow'].includes(receipt.domain) && !!canonicalId(receipt.metadataOperationId) && receipt.metadataChildKey === `governance-fix-${receipt.id}`;
  if (receipt.kind !== 'fix-plan' || receipt.governanceRequestId !== receipt.id || receipt.metadataReconciliationPending !== true || !canonicalId(receipt.jobId) && !metadataChild) throw new Error('尚未证明可关联的原子结果，保留原请求。');
  return governanceTypedConfirmation(`reconcile:${reference.idempotencyKey}`, confirmation);
}
export const governanceCredentialKinds: readonly GovernanceCredentialKind[] = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
export function governanceCredentialSelection(includeCredentials: boolean, value: unknown): GovernanceCredentialKind[] | undefined {
  if (includeCredentials !== true) return;
  if (value === undefined || Array.isArray(value) && value.length === 0) return;
  if (!Array.isArray(value) || value.length > 6 || value.some(kind => !governanceCredentialKinds.includes(kind)) || new Set(value).size !== value.length) throw new Error('凭证类型只能选择六类 Kong 1.5 Consumer 凭证。');
  return [...value] as GovernanceCredentialKind[];
}
export function governanceSourceObjectKey(object: GovernanceSourceObject): string | undefined {
  if (object.referenceOnly || object.eligible !== true || !canonicalId(object.nativeId) || !canonicalId(object.objectWorkspaceId)) return;
  if (!['services', 'routes', 'consumers', 'plugins', 'upstreams', 'targets', 'certificates', 'ca_certificates', 'snis'].includes(object.entityType)) return;
  const key = object.entityType === 'targets' ? canonicalId(object.parentId) && `targets:${object.parentId}:${object.nativeId}` : `${object.entityType}:${object.nativeId}`;
  return key && key === object.objectKey ? key : undefined;
}
/** Form shape mirrors only the fixed backend registry; it grants no operation permission. */
export const governanceFixedForms: readonly GovernanceFixAction[] = [
  { code: 'owner_tag_add', name: '补充 owner 标签', fields: [{ name: 'ownerTag', label: 'owner 标签', required: true, type: 'string' }] },
  { code: 'route_https_only', name: '仅使用安全协议', fields: [{ name: 'protocols', label: '协议', required: true, type: 'array', enum: ['https', 'grpcs', 'tls'] }] },
  { code: 'service_timeouts_set', name: '设置 Service 超时', fields: [{ name: 'connectTimeout', label: '连接超时（毫秒）', required: true, type: 'number' }, { name: 'writeTimeout', label: '写入超时（毫秒）', required: true, type: 'number' }, { name: 'readTimeout', label: '读取超时（毫秒）', required: true, type: 'number' }] },
  { code: 'entity_rename', name: '修订对象名称', fields: [{ name: 'name', label: '新名称', required: true, type: 'string' }] },
  { code: 'reference_replace_or_clear', name: '替换或清空无效引用', fields: [{ name: 'operation', label: '操作', required: true, enum: ['replace', 'clear'] }, { name: 'replacementId', label: '替换对象 ID', type: 'entity' }, { name: 'replacementIds', label: '替换 CA IDs', type: 'array' }] },
  { code: 'unused_certificate_archive', name: '归档未使用证书', fields: [] },
  { code: 'baseline_plugin_configure', name: '配置安全基线插件', fields: [{ name: 'pluginName', label: '插件名称', required: true, type: 'string' }, { name: 'config', label: '插件配置', required: true, type: 'object' }, { name: 'ownerTag', label: 'owner 标签', type: 'string' }] },
  { code: 'annotation_description_set', name: '补充对象说明', fields: [{ name: 'description', label: '说明', required: true, type: 'string' }] },
];

const secretName = /(?:password|secret|token|authorization|cookie|credential|private.?key|client.?secret|api.?key|pem|cert$|^key$)/i;
/** Never reflect full inventory, runtime handles or secret material into public forms/previews. */
export function governanceSafeValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[省略]';
  if (typeof value === 'string') return /-----BEGIN |\bBearer\s+\S+|\bBasic\s+\S+|:\/\/[^\s/]+@/i.test(value) ? '[已隐藏]' : value.slice(0, 2000);
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 100).map(item => governanceSafeValue(item, depth + 1));
  if (!value || typeof value !== 'object') return undefined;
  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value).slice(0, 100)) {
    if (['__proto__', 'constructor', 'prototype', 'sourceProof', 'approved', 'authority', 'transportScope', 'materialHmac', 'payloadHmac'].includes(key)) continue;
    output[key] = secretName.test(key) ? '[已隐藏]' : governanceSafeValue(item, depth + 1);
  }
  return output;
}
