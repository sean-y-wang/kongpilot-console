import { useState } from 'react';
import { Alert, App, Button, Space, Typography } from 'antd';
import { useQueries } from '@tanstack/react-query';
import { api, ApiError, getApiActorId, post } from '../api/client';
import { recycleReceiptMatchesEntry } from '../api/recovery';
import { canonicalId, receiptProvesCompletion, scopeQuery } from '../api/workspace-scope';
import { useAuth } from '../app/AuthContext';
import { usePermissions } from '../app/Permissions';
import { useWorkspace } from '../app/WorkspaceContext';
import { mutationConfirm } from '../components/MutationConfirm';
import { QueryError } from '../components/Shared';

/** Reconciliation observes an archived graph; it never retries DELETE/restore. */
export function RecycleReconciliation({ entry, clusterId, workspaceId, approval, onResult }: {
  entry: any; clusterId: string; workspaceId: string; approval: boolean; onResult: (result: unknown) => Promise<void>;
}) {
  const permission = usePermissions(), workspace = useWorkspace(), { user } = useAuth(), { modal, message } = App.useApp();
  const [working, setWorking] = useState(false), [error, setError] = useState<unknown>();
  const references = workspace.references.filter(ref => !ref.kind && !ref.domain && ref.cid === clusterId && ref.wid === workspaceId);
  const endpoints = [...new Set([
    ...(canonicalId(entry.mutation_id) ? [entry.mutation_id] : []),
    ...references.map(ref => ref.operationId ?? `by-key/${ref.idempotencyKey}`),
  ])].slice(0, 31);
  const queries = useQueries({ queries: endpoints.map(endpoint => ({
    queryKey: ['recycle-recovery-receipt', user?.id, permission.version, clusterId, workspaceId, entry.id, endpoint],
    queryFn: async () => {
      const originalActor = getApiActorId();
      const receipt = await api<any>(scopeQuery(`/clusters/${clusterId}/mutations/${endpoint}`, clusterId, workspaceId));
      if (getApiActorId() !== originalActor) throw new ApiError('登录账号已切换，请重新核验。', 401, 'SESSION_CHANGED');
      return receipt;
    },
    enabled: permission.platformAdmin && entry.state !== 'purged', retry: false, staleTime: 0, gcTime: 0,
  })) });
  const receipts = [...new Map(queries.flatMap(query => recycleReceiptMatchesEntry(query.data, entry, clusterId, workspaceId) ? [[query.data.id, query.data] as const] : [])).values()];
  if (!permission.platformAdmin || !receipts.length) return null;
  function reconcile(receipt: any) {
    const actorId = getApiActorId(), captured = { clusterId, workspaceId, id: receipt.id, name: entry.root_name };
    mutationConfirm(modal, { title: '核验未知删除或恢复结果', expected: captured.name, danger: false, okText: '确认核验', description: '只读取 Kong 当前完整对象图并记录核验结论，不重发删除或恢复。操作必须已停止发送至少 15 秒；配置已变化或证据不完整时保留未知状态。', onConfirm: async () => {
      setWorking(true); setError(undefined);
      try {
        const result = await post<any>(scopeQuery(`/clusters/${captured.clusterId}/mutations/${captured.id}/reconcile`, captured.clusterId, captured.workspaceId), { confirmed: true, confirm_name: captured.name });
        const verified = await api<any>(scopeQuery(`/clusters/${captured.clusterId}/mutations/${captured.id}`, captured.clusterId, captured.workspaceId));
        if (getApiActorId() !== actorId) throw new ApiError('登录账号已切换，请重新读取核验状态。', 401, 'SESSION_CHANGED');
        if (verified.id !== captured.id || verified.cluster_id !== captured.clusterId || verified.workspace_id !== captured.workspaceId || !receiptProvesCompletion(verified)) throw new ApiError('尚未取得完整执行回执，仍保留原写入阻止。', 0, 'RECONCILIATION_PROOF_INCOMPLETE');
        for (const reference of references) if (reference.operationId === captured.id || queries.some((query, index) => query.data?.id === captured.id && endpoints[index] === `by-key/${reference.idempotencyKey}`)) workspace.resolveReference(reference);
        window.dispatchEvent(new CustomEvent('kongos:receipt-verified', { detail: { cid: captured.clusterId, wid: captured.workspaceId, operationId: captured.id, completed: true, state: verified.state } }));
        await onResult(result); void message.success('核验结论已记录，原操作未重发');
      } catch (e) { setError(e); throw e; } finally { setWorking(false); }
    } });
  }
  return <Alert type="warning" showIcon message="归档关联操作的结果尚未确认" style={{ margin: '16px 0' }} description={<>
    <Typography.Paragraph>平台管理员可核验当前对象图。核验只观察已归档配置，完整证据落库后才解除原范围的写入阻止。</Typography.Paragraph>
    {receipts.map(receipt => <Space wrap key={receipt.id}><Typography.Text className="mono">{receipt.id}</Typography.Text><Button disabled={working || approval} loading={working} onClick={() => reconcile(receipt)}>核验结果</Button></Space>)}
    {approval && <p>审批集群的核验状态变更需要工作流。</p>}{error ? <QueryError error={error} /> : null}
  </>} />;
}
