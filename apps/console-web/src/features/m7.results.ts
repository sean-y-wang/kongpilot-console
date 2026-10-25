import { canonicalId, type RecoveryKind, type RecoveryScope } from '../api/workspace-scope';
export interface M7Reference { kind?: RecoveryKind; clusterId?: string; workspaceId?: string; idempotencyKey?: string; scope?: RecoveryScope; }
export function isM7Kind(kind?: string): boolean { return ['events', 'notifications', 'audit-export', 'audit-global-export'].includes(kind ?? ''); }
export function m7ReceiptPath(ref: M7Reference): string {
  const key = canonicalId(ref.idempotencyKey), cid = canonicalId(ref.clusterId), wid = canonicalId(ref.workspaceId);
  if (!key || !isM7Kind(ref.kind)) throw new Error('原操作标识无效。');
  if (ref.kind === 'audit-global-export' && ref.scope === 'global' && !cid && !wid) return `/audit/global/exports/by-key/${key}`;
  if (ref.kind === 'notifications') {
    if (ref.scope === 'global' && !cid && !wid) return `/notifications/operations/by-key/${key}`;
    if (cid && (ref.scope === 'cluster' && !wid || ref.scope === 'workspace' && wid)) return `/notifications/operations/by-key/${key}?${new URLSearchParams({ clusterId: cid, ...(wid ? { workspaceId: wid } : {}) })}`;
  }
  if (ref.kind === 'audit-export' && cid && (ref.scope === 'cluster' && !wid || ref.scope === 'workspace' && wid)) return `/clusters/${cid}/audit/exports/by-key/${key}?${new URLSearchParams(wid ? { workspaceId: wid } : { scope: 'cluster' })}`;
  if (ref.kind === 'events' && cid && wid) return `/clusters/${cid}/events/operations/by-key/${key}?workspaceId=${wid}`;
  throw new Error('原操作范围不完整，不能使用当前范围代替。');
}
export interface M7Result { label: string; complete: boolean; success: boolean; workflowId?: string; }
export function assertM7Entity<T extends { id: string; clusterId: string | null; workspaceId: string | null }>(entity: T, expected: { id: string; clusterId: string | null; workspaceId: string | null }): T { if (!entity || !canonicalId(entity.id) || entity.id !== expected.id || entity.clusterId !== expected.clusterId || entity.workspaceId !== expected.workspaceId) throw new Error('详情与原对象范围不一致'); return entity; }
export function m7ReceiptResult(value: unknown, ref: M7Reference): M7Result {
  const result = value as Record<string, any> | null;
  const unknown = { label: '执行结果仍待核验', complete: false, success: false };
  if (!result || !canonicalId(ref.idempotencyKey)) return unknown;
  if (ref.kind === 'audit-export' || ref.kind === 'audit-global-export') {
    if (result.domain === 'audit-export' && result.durable === true && canonicalId(result.jobId) && result.job?.id === result.jobId) return { label: '导出任务已创建；文件生成状态另行显示', complete: true, success: true };
    return unknown;
  }
  if (ref.kind === 'notifications') {
    if (canonicalId(result.id) && result.clusterId === (ref.clusterId ?? null) && result.workspaceId === (ref.workspaceId ?? null) && result.remote_completed === true && ['succeeded', 'failed'].includes(result.state)) return { label: result.state === 'succeeded' ? '本人通知操作已保存' : '通知操作失败', complete: true, success: result.state === 'succeeded' };
    return unknown;
  }
  if (result.idempotencyKey !== ref.idempotencyKey || result.clusterId !== (ref.clusterId ?? null) || result.workspaceId !== (ref.workspaceId ?? null)) return unknown;
  if (ref.kind === 'events') {
    if (result.domain === 'workflow' && result.submissionCompleted === true && canonicalId(result.workflowId)) return { label: result.executionCompleted === true ? '工作流执行已完成' : '变更工单已登记，等待审批与执行', complete: true, success: result.executionCompleted !== true || result.state === 'succeeded', workflowId: result.workflowId };
    if (result.domain === 'iam' && result.executionCompleted === true) return { label: result.configurationCommitted === true ? result.queued === true ? '配置已提交，投递已排队；远端结果请查看投递记录' : '配置已提交' : '执行结束，请核对结果', complete: true, success: result.state === 'succeeded' };
  }
  return unknown;
}
