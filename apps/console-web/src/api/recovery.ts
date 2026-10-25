import type { ApiError } from './client';
import { canonicalId, scopeQuery } from './workspace-scope';

type Recovery = NonNullable<ApiError['recovery']>;
export interface VitalsSetupReceipt {
  clusterId: string; workspaceId: string; idempotencyKey: string;
  parentState: 'not_sent' | 'partial' | 'uncertain' | 'failed' | 'succeeded';
  steps: Array<{ name: 'prometheus' | 'http-log' | 'settings'; id: string | null; state: string; remoteCompleted: boolean; errorCode?: string; workspaceId?: string }>;
  result?: Record<string, unknown>;
}

/** Setup uses hashed child keys: its original key belongs to this parent receipt. */
export function vitalsSetupReceiptPath(recovery: Recovery): string {
  const cid = canonicalId(recovery.clusterId), wid = canonicalId(recovery.workspaceId), key = canonicalId(recovery.idempotencyKey);
  if (recovery.kind !== 'vitals-setup' || recovery.domain !== undefined || !cid || !wid || !key) throw new Error('原监控配置范围或幂等键缺失，请保留原操作标识。');
  return scopeQuery(`/clusters/${cid}/vitals/setup/receipts/by-key/${key}`, cid, wid);
}

export function isVitalsSetupReceipt(receipt: unknown, recovery: Recovery): receipt is VitalsSetupReceipt {
  const value = receipt as VitalsSetupReceipt | null;
  return recovery.kind === 'vitals-setup' && recovery.domain === undefined && !!value && canonicalId(value.clusterId) === canonicalId(recovery.clusterId) && !!canonicalId(value.clusterId)
    && canonicalId(value.workspaceId) === canonicalId(recovery.workspaceId) && !!canonicalId(value.workspaceId)
    && value.idempotencyKey === recovery.idempotencyKey
    && ['not_sent', 'partial', 'uncertain', 'failed', 'succeeded'].includes(value.parentState)
    && Array.isArray(value.steps) && value.steps.length <= 3
    && new Set(value.steps.map(step => step?.name)).size === value.steps.length
    && value.steps.every(step => !!step && ['prometheus', 'http-log', 'settings'].includes(step.name)
      && (step.id === null || !!canonicalId(step.id)) && typeof step.state === 'string' && typeof step.remoteCompleted === 'boolean');
}

export function vitalsSetupReceiptProvesCompletion(receipt: unknown, recovery: Recovery): boolean {
  return isVitalsSetupReceipt(receipt, recovery) && receipt.parentState === 'succeeded'
    && receipt.steps.some(step => step.name === 'prometheus') && receipt.steps.some(step => step.name === 'settings')
    && receipt.steps.every(step => !!canonicalId(step.id) && step.state === 'succeeded' && step.remoteCompleted === true);
}

export function recycleReceiptMatchesEntry(receipt: any, entry: any, clusterId: string, workspaceId: string): boolean {
  return !!canonicalId(receipt?.id) && !!canonicalId(entry?.id)
    && receipt.cluster_id === clusterId && receipt.workspace_id === workspaceId
    && receipt.entity_type === entry.root_type && receipt.entity_id === entry.original_id
    && ['delete', 'restore'].includes(receipt.action) && receipt.state === 'uncertain';
}
