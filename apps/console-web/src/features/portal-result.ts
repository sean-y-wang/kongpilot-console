import { canonicalId } from '../api/workspace-scope';

const states = {
  pending: { type: 'info', message: '变更已提交，等待审批' },
  approved: { type: 'info', message: '变更已批准，等待执行' },
  executing: { type: 'info', message: '变更执行中' },
  running: { type: 'info', message: '变更执行中' },
  succeeded: { type: 'success', message: '变更执行完成，配置生效中' },
  failed: { type: 'error', message: '变更执行失败，请查看回执' },
  partial: { type: 'warning', message: '变更部分完成，请核验原操作' },
  uncertain: { type: 'warning', message: '变更结果待核验，请保留原操作标识' },
  rejected: { type: 'info', message: '变更已驳回' },
  cancelled: { type: 'info', message: '变更已撤销' },
  expired: { type: 'warning', message: '变更已过期' },
} as const;

/** Business object identity never substitutes for the parent workflow identity. */
export function portalWorkflowNotice(result: unknown, canReadWorkflow: boolean) {
  if (!result || typeof result !== 'object') return undefined;
  const value = result as Record<string, any>;
  const row = value.workflow ?? value.entity ?? value;
  const receipt = value.receipt;
  const workflowId = canonicalId(value.workflowId)
    ?? canonicalId(receipt?.workflowId)
    ?? canonicalId(row?.workflowId)
    ?? (typeof row?.kind === 'string' && row.kind.startsWith('portal-') ? canonicalId(row.id) : undefined);
  if (!workflowId) return undefined;
  const state = receipt?.state ?? value.state ?? row?.state;
  const status = typeof state === 'string' && Object.hasOwn(states, state)
    ? states[state as keyof typeof states]
    : { type: 'info' as const, message: '变更已登记，请核验执行状态' };
  return { workflowId, ...status, ...(canReadWorkflow ? { href: `/workflows/${workflowId}` } : {}) };
}
