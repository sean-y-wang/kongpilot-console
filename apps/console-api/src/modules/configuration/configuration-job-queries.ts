/** Receipt identity comes from the persisted execution, bound to the current
 * job's actor, scope and complete immutable plan tuple. No progress JSON ID is
 * accepted as execution authority. The caller supplies an authorized handle. */
export const CONFIGURATION_JOB_PROJECTION_QUERY = `SELECT j.idempotency_key,j.workflow_id,j.plan_id,j.actor_id,j.origin_session_id,j.execution_mode,j.approval_required,e.id AS execution_id
 FROM configuration_jobs j LEFT JOIN configuration_executions e
 ON e.job_id=j.id AND e.cluster_id=j.cluster_id AND e.workspace_id=j.workspace_id AND e.actor_id=j.actor_id
 AND e.plan_id=j.plan_id AND e.plan_revision=j.plan_revision AND e.plan_hash=j.plan_hash
 WHERE j.id=$1 AND j.cluster_id=$2 AND j.workspace_id=$3 AND j.actor_id=$4`;
