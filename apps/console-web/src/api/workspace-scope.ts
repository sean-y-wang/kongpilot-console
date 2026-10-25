import type { ConfigurationAbandonmentIntent } from '../features/m8.types';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function canonicalId(value: unknown): string | undefined { return typeof value === 'string' && uuid.test(value) ? value.toLowerCase() : undefined; }
export function workspaceSelectionForScope(selected: Record<string, string>, registeredClusterIds: readonly string[], clusterId: unknown, workspaceId: unknown): Record<string, string> {
  const cid = canonicalId(clusterId), wid = canonicalId(workspaceId);
  if (!cid || !wid || !registeredClusterIds.includes(cid)) throw new Error('目标集群或工作区标识无效。');
  return { ...selected, [cid]: wid };
}

/** Capture the selected scope when constructing a request; never read mutable selectors here. */
export function scopeQuery(path: string, clusterId: string | undefined, workspaceId: string | undefined): string {
  const cid = canonicalId(clusterId), wid = canonicalId(workspaceId);
  if (!cid || !wid || !path.startsWith(`/clusters/${cid}/`)) throw new Error('集群或工作区尚未就绪，请重新选择后继续。');
  const [pathname, query = ''] = path.split('?');
  const params = new URLSearchParams(query);
  const existing = params.get('workspaceId');
  if (existing && canonicalId(existing) !== wid) throw new Error('请求工作区与已捕获的操作范围不一致。');
  params.set('workspaceId', wid);
  return `${pathname}?${params}`;
}

export function workspacePath(clusterId: string | undefined, workspaceId: string | undefined, resource: string, query?: URLSearchParams): string {
  return scopeQuery(`/clusters/${clusterId}/${resource.replace(/^\//, '')}${query?.size ? `?${query}` : ''}`, clusterId, workspaceId);
}

export type RecoveryKind = 'vitals-setup' | 'portal' | 'workflow' | 'events' | 'notifications' | 'audit-export' | 'audit-global-export' | 'configuration' | 'toolbox' | 'drafts' | 'governance';
export type RecoveryScope = 'workspace' | 'cluster' | 'global';
export interface RecoveryReference { actor_id: string; cid?: string; wid?: string; domain?: 'iam'; kind?: RecoveryKind; scope?: RecoveryScope; idempotencyKey: string; operationId?: string; originalJobId?: string; originalJobKey?: string; abandonmentIntent?: ConfigurationAbandonmentIntent; created_at: string; state: string; }
function safeAbandonmentHint(item: any): { originalJobKey: string; abandonmentIntent: ConfigurationAbandonmentIntent } | undefined {
  const intent = item.abandonmentIntent;
  if (!intent && item.originalJobKey === undefined) return undefined;
  if (!canonicalId(item.originalJobKey) || !intent || intent.jobId !== item.originalJobId || !canonicalId(intent.executionId) || intent.confirmationName !== `abandon:${item.originalJobId}`
    || ![intent.revision, intent.executionRevision, intent.planRevision, intent.leaseGeneration].every(value => Number.isSafeInteger(value) && value > 0)
    || !/^[a-f\d]{64}$/i.test(intent.planHash ?? '') || intent.workflowExecutionId !== null && !canonicalId(intent.workflowExecutionId)) return undefined;
  return { originalJobKey: canonicalId(item.originalJobKey)!, abandonmentIntent: { jobId: intent.jobId, revision: intent.revision, executionId: intent.executionId, executionRevision: intent.executionRevision, planRevision: intent.planRevision, planHash: intent.planHash, leaseGeneration: intent.leaseGeneration, workflowExecutionId: intent.workflowExecutionId, confirmationName: intent.confirmationName } };
}
export function validRecoveryScope(item: { domain?: string; kind?: string; cid?: string; wid?: string; scope?: string }): boolean {
  if (item.scope !== undefined && !['workspace', 'cluster', 'global'].includes(item.scope)) return false;
  if (item.domain === 'iam') return item.kind === undefined;
  if (item.kind === 'configuration' || item.kind === 'governance') return (item.scope === undefined || item.scope === 'workspace') && !!canonicalId(item.cid) && !!canonicalId(item.wid);
  if (item.kind === 'audit-global-export') return item.scope === 'global' && item.cid === undefined && item.wid === undefined;
  if (item.kind === 'audit-export') return !!canonicalId(item.cid) && (item.scope === 'cluster' && item.wid === undefined || item.scope === 'workspace' && !!canonicalId(item.wid));
  if (item.kind === 'notifications') return item.scope === 'global' && item.cid === undefined && item.wid === undefined || item.scope === 'cluster' && !!canonicalId(item.cid) && item.wid === undefined || item.scope === 'workspace' && !!canonicalId(item.cid) && !!canonicalId(item.wid);
  return !!canonicalId(item.cid) && !!canonicalId(item.wid);
}
export const recoveryStorageKey = 'kongos.uncertainOperations';
export function safeRecoveryReferences(value: unknown, actorId: string, now = Date.now()): RecoveryReference[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap(item => {
    if (!item || (item.domain !== undefined && item.domain !== 'iam') || (item.kind !== undefined && !['vitals-setup', 'portal', 'workflow', 'events', 'notifications', 'audit-export', 'audit-global-export', 'configuration', 'toolbox', 'drafts', 'governance'].includes(item.kind)) || item.actor_id !== actorId || !canonicalId(item.actor_id) || !canonicalId(item.idempotencyKey) || !validRecoveryScope(item)) return [];
    if (item.originalJobId !== undefined && (item.domain !== undefined || item.kind !== 'configuration' || !canonicalId(item.originalJobId))) return [];
    const abandonment = safeAbandonmentHint(item);
    if ((item.originalJobKey !== undefined || item.abandonmentIntent !== undefined) && (!item.originalJobId || !abandonment)) return [];
    const created = Date.parse(item.created_at);
    if (!Number.isFinite(created) || created > now + 60_000 || now - created > 86_400_000) return [];
    return [{ actor_id: item.actor_id, ...(item.domain === 'iam' ? { domain: 'iam' as const } : { ...(canonicalId(item.cid) ? { cid: canonicalId(item.cid)! } : {}), ...(canonicalId(item.wid) ? { wid: canonicalId(item.wid)! } : {}), ...(item.kind ? { kind: item.kind as RecoveryReference['kind'] } : {}), ...(item.scope ? { scope: item.scope as RecoveryScope } : {}) }), idempotencyKey: canonicalId(item.idempotencyKey)!, ...(canonicalId(item.operationId) ? { operationId: canonicalId(item.operationId)! } : {}), ...(item.originalJobId ? { originalJobId: canonicalId(item.originalJobId)! } : {}), ...abandonment, created_at: new Date(created).toISOString(), state: ['uncertain', 'running', 'failed', 'partial'].includes(item.state) ? item.state : 'uncertain' }];
  }).slice(-30);
}
export function receiptProvesCompletion(receipt: any): boolean { return !!receipt && ['succeeded', 'failed'].includes(receipt.state) && receipt.remote_completed === true; }
