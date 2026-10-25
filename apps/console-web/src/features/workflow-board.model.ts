import type { Workflow } from './portal.types';

export const workflowBoardColumns = [
  { key: 'pending', title: '待审批' },
  { key: 'approved', title: '待执行' },
  { key: 'executing', title: '执行中' },
  { key: 'closed', title: '执行结果' },
] as const;
export type WorkflowBoardColumn = typeof workflowBoardColumns[number]['key'];

export function workflowBoardColumn(state: string): WorkflowBoardColumn {
  return state === 'pending' || state === 'approved' || state === 'executing' ? state : 'closed';
}

/** An overdue reminder never rewrites the server's execution state. */
export function workflowOverdue(row: Pick<Workflow, 'state' | 'expiresAt'>, now: number): boolean {
  const expires = Date.parse(row.expiresAt);
  return ['pending', 'approved'].includes(row.state) && Number.isFinite(expires) && expires <= now;
}
