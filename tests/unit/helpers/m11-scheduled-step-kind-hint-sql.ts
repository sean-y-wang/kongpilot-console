/** Exact controlled row adapter for Source tests. It models only this
 * read-only association query; unrelated SQL remains the original fixture's
 * responsibility and never receives a permissive SELECT fallback. */
export const STEP_KIND_HINT_SQL = `SELECT s.kind FROM workflow_steps s
  JOIN workflow_executions e ON e.cluster_id=s.cluster_id AND e.workspace_id=s.workspace_id
  AND e.workflow_id=s.workflow_id AND e.plan_revision=s.plan_revision AND e.plan_hash=s.plan_hash
  WHERE e.id=$1 AND e.workflow_id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4 AND s.id=$5`;
export const normalizedHintSql = (sql: string) => sql.replace(/\s+/g, ' ').trim();
export function scheduledStepKindHintRow(sql: string, args: any[], execution: any, rows: any[]): { kind: unknown } | null {
  if (normalizedHintSql(sql) !== normalizedHintSql(STEP_KIND_HINT_SQL)) throw Error('UNPLANNED_STEP_KIND_HINT_SQL');
  if (args.length !== 5 || execution.id !== args[0] || execution.workflow_id !== args[1]
    || execution.cluster_id !== args[2] || execution.workspace_id !== args[3]) return null;
  const step = rows.find(row => row.id === args[4] && row.workflow_id === execution.workflow_id
    && row.cluster_id === execution.cluster_id && row.workspace_id === execution.workspace_id
    && row.plan_revision === execution.plan_revision && row.plan_hash === execution.plan_hash);
  return step ? { kind: step.kind } : null;
}
