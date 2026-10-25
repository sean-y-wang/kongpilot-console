import { canonicalId } from '../api/workspace-scope';
import { redactForDisplay } from '../api/redaction';
import { workflowReceiptMatches, workflowReceiptProvesCompletion } from '../api/workflow-recovery';
import type { Workflow } from './portal.types';
import type { Capabilities } from '../api/types';
import { normalizeScheduledIntentSpec, type ScheduledIntentSpec } from './entity-schedules.model';

export interface WorkflowIdentity { actor?: string; version?: string; cid?: string; wid?: string; mode?: 'direct' | 'approval'; }
export interface EntityChangeIntent {
  id: string; revision: number; materialHmac: string; executionMode: 'direct' | 'approval'; issuedAt: string; expiresAt: string;
  workflowId?: string | null; nativeExecutionAvailable: boolean; capabilities: { submit: boolean; scheduleSubmit?: boolean }; schedule?: ScheduledIntentSpec;
  review: { changes: Array<{ entityType: string; nativeId: string; originalNativeId?: string; action: string; before: unknown; after: unknown }>;
    impact: { changedObjects: number; nativePackets: number; trafficAvailability: string; globalPlugin: boolean };
    recovery: { state: string; blockerCodes: string[] } };
}
export interface NativeChangeHistory {
  intentId?: string;
  executionId?: string;
  targetResultReconciliationAvailable?: boolean;
  baseline: null | { baseline: { baselineId: string; sourceId: string; pinId: string; objectCount: number; graphCount: number; protectedUntil: string };
    observedFrom: string; observedUntil: string; recovery: { state: string; nonreversiblePacketKeys?: string[]; rollbackUnavailableReason?: string; totalObjects: number; affectedObjects: number; presentObjects: number; absentObjects: number; referenceObjects: number }; nativeAuthority: false };
  packets: Array<{ key: string; order: number; entityType: string; entityId: string; operationId: string | null; state: string; nativeStatus: number | null; errorCode: string | null;
    targetResultObservation?: { id: string; auditId: string; eventHash: string; observedAt: string; kind: 'target-weight-zero-original-response-v1';
      operationId: string; workflowStepId: string; operationState: 'succeeded'; nativeRequestsSent: 0; originalNativeStatus: null } }>;
}
export interface NativeChangePreflight { objects: number; graphs: number; recoverable: boolean; nonreversiblePacketKeys: string[]; rollbackUnavailableReason?: string; }
export interface WorkflowWriteAttempt extends WorkflowIdentity {
  subject: string; action: 'prepare' | 'submit' | 'approve' | 'reject' | 'cancel' | 'execute' | 'rollbackPrepare' | 'scheduleActivate' | 'scheduleCancel';
  key: string; revision?: number; planHash?: string; intentId?: string; state: 'pending' | 'unknown' | 'failed';
}
const object = (value: unknown): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value);
const integer = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0;
const hex = (value: unknown): value is string => typeof value === 'string' && /^[a-f\d]{64}$/i.test(value);
export const targetHealthRollbackUnavailableReason = 'TARGET_HEALTH_OVERRIDE_ROLLBACK_UNAVAILABLE';
const reasonCode = (value: unknown): value is string => typeof value === 'string' && /^[A-Z0-9_]{1,128}$/.test(value);
function recoveryRestrictions(raw: Record<string, any>, required = false): { nonreversiblePacketKeys?: string[]; rollbackUnavailableReason?: string } {
  const keys = raw.nonreversiblePacketKeys;
  if (keys === undefined && !required && raw.rollbackUnavailableReason === undefined && raw.state !== 'contains-nonreversible') return {};
  if (!Array.isArray(keys) || keys.length > 1000 || keys.some(key => typeof key !== 'string' || !/^[a-zA-Z\d_.:-]{1,128}$/.test(key)) || new Set(keys).size !== keys.length
    || raw.rollbackUnavailableReason !== undefined && !reasonCode(raw.rollbackUnavailableReason)
    || keys.length > 0 && !reasonCode(raw.rollbackUnavailableReason) || keys.length === 0 && raw.rollbackUnavailableReason !== undefined
    || raw.state === 'complete' && keys.length > 0 || raw.state === 'contains-nonreversible' && keys.length === 0) throw new Error('不可回滚操作的摘要不完整，请重新读取工单。');
  return { nonreversiblePacketKeys: [...keys], ...(raw.rollbackUnavailableReason ? { rollbackUnavailableReason: raw.rollbackUnavailableReason } : {}) };
}
export function normalizeNativeChangePreflight(raw: unknown): NativeChangePreflight {
  if (!object(raw) || raw.ready !== true || raw.nativeRequestsSent !== 0 || raw.baselinePersisted !== false || !integer(raw.objects) || !integer(raw.graphs) || typeof raw.recoverable !== 'boolean') throw new Error('执行前检查结果不完整，请重新读取工单。');
  const restrictions = recoveryRestrictions(raw, true);
  if (raw.recoverable !== (restrictions.nonreversiblePacketKeys!.length === 0)) throw new Error('恢复能力摘要不一致，请重新读取工单。');
  return { objects: raw.objects, graphs: raw.graphs, recoverable: raw.recoverable, nonreversiblePacketKeys: restrictions.nonreversiblePacketKeys!, ...(restrictions.rollbackUnavailableReason ? { rollbackUnavailableReason: restrictions.rollbackUnavailableReason } : {}) };
}
export function sameWorkflowIdentity(a: WorkflowIdentity, b: WorkflowIdentity) { return a.actor === b.actor && a.version === b.version && a.cid === b.cid && a.wid === b.wid && a.mode === b.mode; }
export function workflowAttemptStorageKey(identity: WorkflowIdentity, subject: string) {
  if (![identity.actor, identity.cid, identity.wid].every(value => canonicalId(value)) || subject !== 'prepare' && !canonicalId(subject)) throw new Error('变更范围尚未就绪。');
  // Permission changes do not erase an unknown attempt. New reads still use
  // current authenticated scope and never revive a past write authority.
  return `kongpilot.workflow-attempt:${identity.actor}:${identity.cid}:${identity.wid}:${subject}`;
}
export function readWorkflowAttempt(identity: WorkflowIdentity, subject: string): WorkflowWriteAttempt | undefined {
  try {
    const value = JSON.parse(sessionStorage.getItem(workflowAttemptStorageKey(identity, subject)) ?? 'null');
    if (!object(value) || value.actor !== identity.actor || value.cid !== identity.cid || value.wid !== identity.wid || value.subject !== subject
      || !canonicalId(value.key) || !['prepare', 'submit', 'approve', 'reject', 'cancel', 'execute', 'rollbackPrepare', 'scheduleActivate', 'scheduleCancel'].includes(value.action)
      || !['pending', 'unknown', 'failed'].includes(value.state)) return;
    return { actor: value.actor, cid: value.cid, wid: value.wid, version: typeof value.version === 'string' ? value.version : undefined,
      subject, action: value.action, key: value.key, state: value.state,
      ...(value.mode === 'direct' || value.mode === 'approval' ? { mode: value.mode } : {}),
      ...(integer(value.revision) && value.revision > 0 ? { revision: value.revision } : {}), ...(hex(value.planHash) ? { planHash: value.planHash } : {}),
      ...(canonicalId(value.intentId) ? { intentId: value.intentId } : {}) };
  } catch { return undefined; }
}
export function storeWorkflowAttempt(value: WorkflowWriteAttempt) {
  if (!canonicalId(value.key) || !['prepare', 'submit', 'approve', 'reject', 'cancel', 'execute', 'rollbackPrepare', 'scheduleActivate', 'scheduleCancel'].includes(value.action)
    || !['pending', 'unknown', 'failed'].includes(value.state)) throw new Error('原变更请求记录格式无效。');
  const safe = { actor: value.actor, cid: value.cid, wid: value.wid, subject: value.subject, action: value.action, key: value.key, state: value.state,
    ...(typeof value.version === 'string' ? { version: value.version.slice(0, 256) } : {}), ...(integer(value.revision) && value.revision! > 0 ? { revision: value.revision } : {}),
    ...(value.mode === 'direct' || value.mode === 'approval' ? { mode: value.mode } : {}),
    ...(hex(value.planHash) ? { planHash: value.planHash } : {}), ...(canonicalId(value.intentId) ? { intentId: value.intentId } : {}) };
  sessionStorage.setItem(workflowAttemptStorageKey(value, value.subject), JSON.stringify(safe));
}
/** A server answer that proves the action was refused without effect: an
 * explicit 4xx from the action POST itself, not timeout/rate-limit, not an
 * idempotency replay/in-progress signal and not carrying an uncertain/partial/
 * running state. Only such answers may clear the unknown-result journal; every
 * other failure (network, 5xx, unreadable body, post-response receipt gap)
 * keeps the original key for read-only verification. */
export function workflowRejectionIsDefinitive(cause: unknown): boolean {
  if (!object(cause) || typeof cause.status !== 'number') return false;
  const status = cause.status, code = typeof cause.code === 'string' ? cause.code : '';
  const recovery = object(cause.recovery) ? cause.recovery : undefined, state = recovery && typeof recovery.state === 'string' ? recovery.state : undefined;
  if (status < 400 || status >= 500 || status === 408 || status === 429) return false;
  if (/UNKNOWN|UNCERTAIN|IDEMPOTENCY|IN_PROGRESS|PARTIAL|SESSION_CHANGED/.test(code)) return false;
  if (state && ['uncertain', 'partial', 'running'].includes(state)) return false;
  return true;
}
export function clearWorkflowAttempt(value: WorkflowWriteAttempt) { sessionStorage.removeItem(workflowAttemptStorageKey(value, value.subject)); }
/** Coarse entry gate from real server-authenticated grants; actual object
 * scope/schema/bindings remain the BFF preparer's mandatory checks. */
export function workflowCanPrepare(capabilities: Capabilities | undefined, identity: WorkflowIdentity) {
  if (!capabilities || !canonicalId(identity.cid) || !canonicalId(identity.wid)) return false;
  if (capabilities.platformAdmin) return true;
  return capabilities.grants.some(grant => grant.module === 'workflows' && grant.action === 'write' && (!grant.cluster_id || grant.cluster_id === identity.cid)
    && (!grant.workspace_id || grant.workspace_id === identity.wid) && (grant.scope_type === 'global' || grant.scope_type === 'workspace' && grant.scope_values.includes(identity.wid!)
      || ['tag_group', 'entity'].includes(grant.scope_type) && grant.scope_values.length > 0));
}

export function normalizeEntityChangeIntent(raw: unknown): EntityChangeIntent {
  if (!object(raw) || !canonicalId(raw.id) || !integer(raw.revision) || raw.revision < 1 || !hex(raw.materialHmac)
    || !['direct', 'approval'].includes(raw.executionMode) || !Number.isFinite(Date.parse(raw.issuedAt)) || !Number.isFinite(Date.parse(raw.expiresAt))
    || raw.workflowId != null && !canonicalId(raw.workflowId) || !object(raw.review) || !Array.isArray(raw.review.changes) || raw.review.changes.length > 1000
    || !object(raw.review.impact) || !integer(raw.review.impact.changedObjects) || !integer(raw.review.impact.nativePackets)
    || !object(raw.review.recovery) || !Array.isArray(raw.review.recovery.blockerCodes)) throw new Error('变更准备回执不完整，请保留原请求键核验。');
  const changes = raw.review.changes.map((change: any) => {
    if (!object(change) || !canonicalId(change.nativeId) || typeof change.entityType !== 'string' || typeof change.action !== 'string'
      || change.originalNativeId !== undefined && !canonicalId(change.originalNativeId)) throw new Error('变更对象回执格式无效。');
    return { entityType: change.entityType, nativeId: change.nativeId, action: change.action,
      ...(change.originalNativeId ? { originalNativeId: change.originalNativeId } : {}), before: redactForDisplay(change.before), after: redactForDisplay(change.after) };
  });
  const schedule = raw.schedule === undefined ? undefined : normalizeScheduledIntentSpec(raw.schedule);
  if (schedule && (raw.executionMode !== 'approval' || raw.nativeExecutionAvailable !== false)) throw new Error('定时变更没有有效的审批模式预览。');
  return { id: raw.id, revision: raw.revision, materialHmac: raw.materialHmac, executionMode: raw.executionMode,
    issuedAt: raw.issuedAt, expiresAt: raw.expiresAt, workflowId: raw.workflowId ?? null,
    nativeExecutionAvailable: raw.nativeExecutionAvailable === true, capabilities: { submit: raw.capabilities?.submit === true, ...(schedule ? { scheduleSubmit: raw.capabilities?.scheduleSubmit === true } : {}) },
    ...(schedule ? { schedule } : {}),
    review: { changes, impact: { changedObjects: raw.review.impact.changedObjects, nativePackets: raw.review.impact.nativePackets,
      trafficAvailability: typeof raw.review.impact.trafficAvailability === 'string' ? raw.review.impact.trafficAvailability : 'unavailable', globalPlugin: raw.review.impact.globalPlugin === true },
      recovery: { state: String(raw.review.recovery.state ?? 'baseline-required'), blockerCodes: raw.review.recovery.blockerCodes.filter((code: unknown) => typeof code === 'string' && /^[A-Z0-9_]{1,128}$/.test(code)).slice(0, 1000) } } };
}

/** Allowlist projection: no raw baseline objects, graphs, reference configs,
 * request bodies, secret ciphertext or arbitrary server fields reach the UI. */
export function normalizeNativeChangeHistory(raw: unknown): NativeChangeHistory | undefined {
  if (raw === undefined) return undefined;
  if (!object(raw) || !Array.isArray(raw.packets) || raw.packets.length > 1000) throw new Error('执行证明响应格式无效。');
  let baseline: NativeChangeHistory['baseline'] = null;
  if (raw.baseline != null) {
    const value = raw.baseline, receipt = value.baseline, recovery = value.recovery;
    if (!object(value) || value.nativeAuthority !== false || !object(receipt) || ![receipt.baselineId, receipt.sourceId, receipt.pinId].every(value => canonicalId(value))
      || !integer(receipt.objectCount) || !integer(receipt.graphCount) || !Number.isFinite(Date.parse(receipt.protectedUntil)) || !object(recovery)
      || !['totalObjects', 'affectedObjects', 'presentObjects', 'absentObjects', 'referenceObjects'].every(name => integer(recovery[name]))) throw new Error('执行前恢复基线响应不完整。');
    baseline = { baseline: { baselineId: receipt.baselineId, sourceId: receipt.sourceId, pinId: receipt.pinId, objectCount: receipt.objectCount, graphCount: receipt.graphCount, protectedUntil: receipt.protectedUntil },
      observedFrom: String(value.observedFrom ?? ''), observedUntil: String(value.observedUntil ?? ''), recovery: { state: String(recovery.state ?? ''), ...recoveryRestrictions(recovery),
        totalObjects: recovery.totalObjects, affectedObjects: recovery.affectedObjects, presentObjects: recovery.presentObjects, absentObjects: recovery.absentObjects, referenceObjects: recovery.referenceObjects }, nativeAuthority: false };
  }
  const packets = raw.packets.map((packet: any) => {
    if (!object(packet) || typeof packet.key !== 'string' || packet.key.length > 160 || !integer(packet.order) || !canonicalId(packet.entityId)
      || typeof packet.entityType !== 'string' || !['succeeded', 'native-rejected', 'sent-unknown', 'rejected-before-send', 'failed-known-not-sent', 'not_sent', 'uncertain'].includes(packet.state)
      || packet.operationId != null && !canonicalId(packet.operationId) || packet.nativeStatus != null && (!integer(packet.nativeStatus) || packet.nativeStatus < 100 || packet.nativeStatus > 599)) throw new Error('逐步执行回执格式无效。');
    let targetResultObservation: NativeChangeHistory['packets'][number]['targetResultObservation'];
    if (packet.targetResultObservation !== undefined) {
      const proof = packet.targetResultObservation;
      if (!object(proof) || ![proof.id, proof.auditId, proof.operationId, proof.workflowStepId].every(value => typeof value === 'string' && canonicalId(value) === value)
        || !hex(proof.eventHash) || typeof proof.observedAt !== 'string' || !Number.isFinite(Date.parse(proof.observedAt)) || proof.kind !== 'target-weight-zero-original-response-v1'
        || proof.operationState !== 'succeeded' || proof.nativeRequestsSent !== 0 || proof.originalNativeStatus !== null
        || proof.operationId !== packet.operationId || packet.entityType !== 'targets' || packet.nativeStatus !== null
        || !['sent-unknown', 'uncertain'].includes(packet.state)) throw new Error('Target 原结果核验记录格式无效。');
      targetResultObservation = { id: proof.id, auditId: proof.auditId, eventHash: proof.eventHash, observedAt: proof.observedAt,
        kind: proof.kind, operationId: proof.operationId, workflowStepId: proof.workflowStepId, operationState: 'succeeded', nativeRequestsSent: 0, originalNativeStatus: null };
    }
    return { key: packet.key, order: packet.order, entityType: packet.entityType, entityId: packet.entityId, operationId: packet.operationId ?? null, state: packet.state,
      nativeStatus: packet.nativeStatus ?? null, errorCode: typeof packet.errorCode === 'string' && /^[A-Z0-9_]{1,128}$/.test(packet.errorCode) ? packet.errorCode : null,
      ...(targetResultObservation ? { targetResultObservation } : {}) };
  });
  if (baseline?.recovery.nonreversiblePacketKeys?.some(key => !packets.some(packet => packet.key === key))) throw new Error('不可回滚操作与原执行记录不一致。');
  return { ...(canonicalId(raw.intentId) ? { intentId: raw.intentId } : {}), ...(canonicalId(raw.executionId) ? { executionId: raw.executionId } : {}),
    ...(raw.targetResultReconciliationAvailable !== undefined ? { targetResultReconciliationAvailable: raw.targetResultReconciliationAvailable === true } : {}), baseline, packets };
}
export function nativeWorkflowCan(row: Workflow, action: 'execute' | 'entityPreflight' | 'rollbackPrepare') {
  if (row.kind !== 'native-change' || row.capabilities?.[action] !== true) return false;
  if (action === 'rollbackPrepare') return ['succeeded', 'partial', 'failed'].includes(row.state) && !!canonicalId(row.nativeChange?.executionId)
    && row.nativeChange?.baseline?.recovery.state === 'complete' && !nativeRollbackUnavailableReason(row)
    && !row.nativeChange.packets.some(packet => ['uncertain', 'sent-unknown'].includes(packet.state));
  return (row.state === 'approved' || row.state === 'pending' && !row.approvalRequired)
    && !row.nativeChange?.packets.some(packet => ['uncertain', 'sent-unknown'].includes(packet.state));
}
export function nativeRollbackUnavailableReason(row: Workflow): string | undefined {
  const recovery = row.nativeChange?.baseline?.recovery;
  if (!recovery || recovery.state !== 'contains-nonreversible' && !recovery.nonreversiblePacketKeys?.length && !recovery.rollbackUnavailableReason) return;
  return recovery.rollbackUnavailableReason ?? 'NONREVERSIBLE_OPERATION_ROLLBACK_UNAVAILABLE';
}
export function entityChangeSubmitPayload(intent: EntityChangeIntent) {
  if (intent.capabilities.submit !== true || intent.schedule && intent.capabilities.scheduleSubmit !== true || intent.workflowId || Date.parse(intent.expiresAt) <= Date.now()) throw new Error('此准备记录当前不可提交，请刷新权限与状态。');
  return { revision: intent.revision, materialHmac: intent.materialHmac, confirmed: true, confirm_name: 'native-change' };
}
export function nativeRollbackPayload(row: Workflow) {
  if (!nativeWorkflowCan(row, 'rollbackPrepare')) throw new Error('当前原执行尚不具备回滚准备条件。');
  return { revision: row.revision, planHash: row.planHash, executionId: row.nativeChange!.executionId!, confirmed: true, confirm_name: 'native-change' };
}
export function workflowActionReceiptComplete(raw: unknown, attempt: WorkflowWriteAttempt) {
  if (!['approve', 'reject', 'cancel', 'execute', 'submit'].includes(attempt.action)) return false;
  const ref = { clusterId: attempt.cid, workspaceId: attempt.wid, idempotencyKey: attempt.key, kind: 'workflow' as const };
  return workflowReceiptMatches(raw, ref) && raw.workflowId === attempt.subject && (!attempt.planHash || raw.planHash === attempt.planHash)
    && raw.action === attempt.action && workflowReceiptProvesCompletion(raw, ref);
}
/** A closed original-key read can be verified even when a health override has
 * no rollback. Releasing this tab's local fence never grants another execute. */
export function workflowExecutionReceiptClosed(raw: unknown, attempt: WorkflowWriteAttempt, row: Workflow) {
  const ref = { clusterId: attempt.cid, workspaceId: attempt.wid, idempotencyKey: attempt.key, kind: 'workflow' as const };
  const healthClosed = row.kind === 'native-change' && nativeRollbackUnavailableReason(row) === targetHealthRollbackUnavailableReason
    && ['succeeded', 'partial', 'failed'].includes(row.state) && !!canonicalId(row.nativeChange?.executionId)
    && !!row.nativeChange?.baseline?.recovery.nonreversiblePacketKeys?.length
    && row.nativeChange.baseline.recovery.nonreversiblePacketKeys.every(key => row.nativeChange!.packets.some(packet => packet.key === key && packet.entityType === 'targets'))
    && !row.nativeChange.packets.some(packet => ['uncertain', 'sent-unknown'].includes(packet.state));
  return attempt.action === 'execute' && (nativeWorkflowCan(row, 'rollbackPrepare') || healthClosed) && workflowReceiptMatches(raw, ref)
    && raw.action === 'execute' && raw.workflowId === row.id && row.id === attempt.subject && raw.planHash === attempt.planHash
    && raw.executionId === row.nativeChange?.executionId && row.clusterId === attempt.cid && row.workspaceId === attempt.wid && raw.state === row.state && ['succeeded', 'partial', 'failed'].includes(raw.state);
}
