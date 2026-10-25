export type ConfigurationScopeKind = 'workspace' | 'cluster' | 'services';
export interface ConfigurationSelection { scope: ConfigurationScopeKind; serviceIds: string[]; }
export interface ConfigurationIdentity { actor?: string; version?: string; cid?: string; wid?: string; }
export interface ConfigurationPage<T> { items: T[]; nextCursor: string | null; size: number; total: null; }
export interface ConfigurationQuality { complete: boolean; consistency: string; warnings: string[]; }
export interface CredentialRecovery { complete: boolean; recoverable: number; unavailable: number; reasons?: string[]; }
export interface ConfigurationCapabilities { read?: boolean; compare?: boolean; rollback?: boolean; write?: boolean; delete?: boolean; restore?: boolean; purge?: boolean; export?: boolean; download?: boolean; apply?: boolean; reconcile?: boolean; abandon?: boolean; durableSubmit?: boolean; durableSubmitReason?: string | null; durableSubmitBlockerCode?: string | null; }
export interface ConfigurationAbandonmentIntent {
  jobId: string; revision: number; executionId: string; executionRevision: number; planRevision: number;
  planHash: string; leaseGeneration: number; workflowExecutionId: string | null; confirmationName: string;
}
export interface ConfigurationAbandonmentResult {
  jobId: string; executionId: string; clusterId: string; workspaceId: string; state: 'uncertain';
  completedSteps: number; unresolvedSteps: number; terminalFailureRecorded: true; abandoned: true;
  originalWorkflowUnchanged: true; originalNativeReceiptsUnchanged: true;
}
export interface SnapshotSummary {
  id: string; clusterId: string; workspaceId: string; name: string; description?: string | null; revision: number; version?: number;
  state: 'capturing' | 'ready' | 'incomplete' | 'failed' | 'deleted' | 'expired'; scopeKind: ConfigurationScopeKind; rootIds?: string[];
  createdAt: string; updatedAt: string; retentionUntil?: string | null; currentVersion: number | null; versionId?: string;
  objectCount: number; pageCount: number; recordCount: number; byteCount: number; completeness: 'complete' | 'incomplete' | null; consistency: string | null;
  recovery: Record<'complete' | 'requires_secret_input' | 'requires_rotation' | 'nonrestorable', number>; warningCodes: readonly string[];
  sharedReferences?: number; kongVersion?: string; capabilities?: ConfigurationCapabilities; jobId?: string;
}
export interface SnapshotObject { objectKey: string; entityType: string; nativeId: string; parentId: string | null; credentialKind: string | null; objectWorkspaceId: string; referenceOnly: boolean; recovery: string; blockerCodes: string[]; payload: Record<string, unknown>; }
export interface ConfigurationJob {
  id: string; clusterId: string; workspaceId: string; name?: string; kind: string;
  revision: number; planHash?: string | null; state: string; executionMode?: 'direct' | 'approval'; approvalRequired?: boolean;
  createdAt: string; completedAt: string | null; safeProgress: Record<string, unknown>; quality?: ConfigurationQuality; credentialRecovery?: CredentialRecovery;
  registrationCompleted?: boolean; submissionCompleted?: boolean; executionCompleted?: boolean;
  progress?: { processed: number; succeeded: number; failed: number; remaining: number }; capabilities?: ConfigurationCapabilities;
  actorId?: string; confirmationName?: string | null;
  planId?: string | null; snapshotId?: string | null; workflowId?: string | null; exportId?: string | null; errorCode?: string | null;
  format?: 'deck-1.1' | 'review-json'; mode?: 'review' | 'deployment' | 'merge' | 'sync' | 'rollback'; bytes?: number; expiresAt?: string;
  formatOmissionCount?: number; exportRevision?: number;
  idempotencyKey?: string; abandonmentIntent?: ConfigurationAbandonmentIntent;
  abandonmentSessionMatches?: boolean;
}
export interface ConfigurationPlan {
  id: string; clusterId: string; workspaceId: string; name: string; jobId: string; revision: number; planRevision: number; planHash: string;
  mode: 'merge' | 'sync' | 'rollback'; scope: ConfigurationScopeKind; serviceIds?: string[]; state: string; expiresAt: string;
  executionMode: 'direct' | 'approval'; approvalRequired: boolean; quality?: ConfigurationQuality; credentialRecovery?: CredentialRecovery;
  stepCount: number; nativePacketCount: number; deleteCount: number; recoveryComplete: boolean;
  counts?: { create: number; update: number; delete: number; unchanged: number; conflict: number };
  blockers: string[]; sharedReferences?: number; deleteConfirmName: string | null; capabilities: ConfigurationCapabilities;
  baselineSnapshotId?: string | null; sourceSnapshotId?: string | null; workflowId?: string | null;
  authorityDomain?: 'legacy-http-v1' | 'durable-configuration-v1'; durableIssueId?: string | null;
}
export interface ConfigurationChange {
  objectKey: string; entityType: string; nativeId: string | null; allocatedNativeId?: string | null; credentialKind: string | null; action: 'create' | 'update' | 'delete';
  parentId: string | null; dependencies?: string[]; referenceOnly?: boolean;
  patch: Array<{ op: string; path: string; from?: string; value?: unknown }>; blockerCodes: string[]; recovery?: string | null; clearMap?: string[];
}
export interface ConfigurationObservation {
  planStepId: string; type: string; action: 'create' | 'update' | 'delete'; originalId: string | null; effectiveId: string;
  present: boolean; expectedFieldsMatch: boolean; causalOutcomeUnproven: true; observedAt: string;
}
export interface ConfigurationReconciliation { jobId: string; observations: ConfigurationObservation[]; }
export interface ConfigurationStepResult {
  id: string; executionId: string; planStepId: string; stepOrder: number; objectWorkspaceId: string; state: string; errorCode: string | null;
  objectId?: string; type?: string; action?: string; originalId?: string | null; effectiveId?: string | null;
  operationId: string | null; recycleEntryId: string | null; verified?: boolean; result: unknown; revision: number; startedAt: string | null; completedAt: string | null;
  completeRecycleEntryId?: string; recycleWorkspaceId?: string;
}
export interface SnapshotSchedule {
  id: string; clusterId: string; workspaceId: string; name: string; revision: number; state: 'active' | 'paused' | 'deleted';
  scopeKind: ConfigurationScopeKind; rootIds: string[]; timezone: string; intervalMinutes: number; retentionDays: number;
  ownerUserId: string; currentVersion: number; nextRunAt: string | null; createdAt: string; updatedAt: string;
  purgedAt?: string | null; capabilities?: ConfigurationCapabilities;
}
export interface GitOpsRun { id: string; clusterId: string; workspaceId: string; jobId: string; createdBy: string; repositoryLabel: string; commitSha: string; pipelineReference: string; createdAt: string; state: string; }
export interface ConfigurationReceipt {
  domain: 'configuration'; idempotencyKey: string; clusterId: string; workspaceId: string; durable: boolean;
  submissionCompleted: boolean; executionCompleted: boolean; state: string; job: ConfigurationJob;
  workflowId?: string | null; entity?: SnapshotSummary | SnapshotSchedule | GitOpsRun | ConfigurationPlan;
}
export interface ConfigurationEntityPage<T> extends ConfigurationPage<T> { entity: unknown; capabilities?: ConfigurationCapabilities; }
export interface SnapshotComparison { readOnly: true; blockerCodes: string[]; changes: { mode: string; changeCount: number; unchangedCount: number; referenceCount: number; recoveryComplete: boolean; blockerCodes: string[]; changes: ConfigurationChange[] }; }
export const m8Labels: Record<string, string> = { new: '新对象', complete: '可完整恢复', requires_secret_input: '需要原秘密输入', requires_rotation: '需要轮换', nonrestorable: '不可恢复', capturing: '捕获中', planning: '生成计划', ready: '准备完成', incomplete: '不完整', pending: '等待处理', waiting_approval: '等待审批', pending_approval: '等待审批', submitted: '已提交审批', approved: '已批准', running: '执行中', succeeded: '已成功', partial: '部分完成', failed: '失败', uncertain: '结果待核验', cancelled: '已取消', deleted: '回收站', expired: '已过期', purged: '恢复材料已销毁', active: '启用', paused: '暂停', workspace: '当前工作区', cluster: '完整集群', services: '指定 Services', merge: '合并（不删除缺失对象）', sync: '同步（显式核对删除）', rollback: '回滚差异', create: '新增', update: '修改', delete: '删除', unchanged: '未变', conflict: '冲突', console_fenced_best_effort: '控制台变更围栏内尽力一致，非原子快照' };
