// Fixed SQL011 approval bindings. Exporting the exact queries lets the
// isolated PostgreSQL check exercise the runtime role and actual aliases.
export const APPROVAL_WORKFLOW_CONTEXT_QUERY = `SELECT w.state,w.plan_revision,w.plan_hash,w.approved_by,e.state AS execution_state,e.execution_actor_id,e.plan_hash AS execution_plan_hash,s.state AS step_state
  FROM workflows w JOIN workflow_executions e ON e.workflow_id=w.id AND e.id=$2
  AND e.cluster_id=w.cluster_id AND e.workspace_id=w.workspace_id AND e.plan_revision=w.plan_revision AND e.plan_hash=w.plan_hash
  JOIN workflow_steps s ON s.workflow_id=w.id AND s.id=$3 AND s.cluster_id=w.cluster_id AND s.workspace_id=w.workspace_id AND s.plan_revision=e.plan_revision AND s.plan_hash=e.plan_hash
  WHERE w.id=$1 AND w.cluster_id=$4 AND w.workspace_id=$5 FOR SHARE OF w,e,s`;

export const APPROVAL_CONFIGURATION_PLAN_QUERY = `UPDATE configuration_plans p SET state='approved',revision=p.revision+1,updated_at=now()
  FROM configuration_plan_versions v,configuration_jobs j WHERE p.id=$1 AND p.source_job_id=$2 AND p.current_revision=$3 AND p.state='pending_approval'
  AND p.cluster_id=$4 AND p.workspace_id=$5 AND v.plan_id=p.id AND v.cluster_id=p.cluster_id AND v.workspace_id=p.workspace_id AND v.plan_revision=$3 AND v.plan_hash=$6
  AND j.id=p.source_job_id AND j.workflow_id=$7 AND j.plan_id=p.id AND j.plan_hash=v.plan_hash AND j.cluster_id=p.cluster_id AND j.workspace_id=p.workspace_id`;
