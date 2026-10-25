/** Fixed SQL for a separately armed, same-process, known-unsent initialization
 * failure. These statements grant no execution or recovery capability. */
export const CONFIGURATION_INITIALIZATION_ANCHOR_QUERY = `SELECT row_to_json(j) AS job,row_to_json(v) AS version,
 row_to_json(p) AS plan,row_to_json(w) AS workflow,row_to_json(we) AS wrapper,
 row_to_json(o) AS wrapper_origin,row_to_json(s) AS workflow_step
 FROM configuration_jobs j
 JOIN configuration_plan_versions v ON v.cluster_id=j.cluster_id AND v.workspace_id=j.workspace_id
 AND v.plan_id=j.plan_id AND v.plan_revision=j.plan_revision AND v.plan_hash=j.plan_hash
 JOIN configuration_plans p ON p.cluster_id=v.cluster_id AND p.workspace_id=v.workspace_id AND p.id=v.plan_id
 JOIN workflows w ON w.id=j.workflow_id AND w.cluster_id=j.cluster_id AND w.workspace_id=j.workspace_id
 JOIN workflow_executions we ON we.workflow_id=w.id AND we.cluster_id=w.cluster_id AND we.workspace_id=w.workspace_id AND we.id=$4
 JOIN workflow_execution_origins o ON o.execution_id=we.id AND o.workflow_id=w.id AND o.cluster_id=w.cluster_id AND o.workspace_id=w.workspace_id
 JOIN workflow_steps s ON s.workflow_id=w.id AND s.cluster_id=w.cluster_id AND s.workspace_id=w.workspace_id
 AND s.plan_revision=w.plan_revision AND s.plan_hash=w.plan_hash AND s.kind='metadata' AND s.handler='configuration_v2'
 AND s.entity_type='configuration_jobs' AND s.entity_id=j.id
 WHERE j.cluster_id=$1 AND j.workspace_id=$2 AND j.id=$3 FOR UPDATE OF j`;

export const CONFIGURATION_INITIALIZATION_FOOTPRINT_QUERY = `SELECT
 (SELECT count(*)::integer FROM configuration_executions e WHERE e.job_id=$3 OR e.workflow_id=$4) AS execution_count,
 (SELECT count(*)::integer FROM mutation_operations m WHERE m.configuration_job_id=$3 OR m.workflow_id=$4
  OR m.workflow_execution_id=$5 OR m.configuration_execution_id IN(SELECT id FROM configuration_executions WHERE job_id=$3)
  OR m.idempotency_key LIKE 'configuration-'||$3::text||'-%') AS operation_count,
 (SELECT count(*)::integer FROM metrics_write_fences f JOIN mutation_operations m ON m.id=f.operation_id
  WHERE m.configuration_job_id=$3 OR m.workflow_id=$4 OR m.workflow_execution_id=$5
  OR m.configuration_execution_id IN(SELECT id FROM configuration_executions WHERE job_id=$3)
  OR m.idempotency_key LIKE 'configuration-'||$3::text||'-%') AS fence_count,
 (SELECT count(*)::integer FROM configuration_job_steps s WHERE s.job_id=$3) AS step_count
 WHERE $1::uuid IS NOT NULL AND $2::uuid IS NOT NULL`;

export const CONFIGURATION_INITIALIZATION_PLAN_OBJECTS_QUERY = `SELECT * FROM configuration_plan_objects
 WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5 ORDER BY step_order`;

export const CONFIGURATION_INITIALIZATION_CHILD_QUERY = `SELECT row_to_json(e) AS execution,row_to_json(o) AS origin
 FROM configuration_executions e LEFT JOIN workflow_configuration_execution_origins o ON o.configuration_execution_id=e.id
 WHERE e.cluster_id=$1 AND e.workspace_id=$2 AND e.job_id=$3 FOR UPDATE OF e`;

export const CONFIGURATION_INITIALIZATION_STEPS_QUERY = `SELECT * FROM configuration_job_steps
 WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3 ORDER BY step_order FOR UPDATE`;

// [CID,WID,job,execution,plan,planRevision,planHash,leaseGeneration,actor,SID,
//  jobRevision,executionRevision,claimHash,leaseOwnerHash,errorCode,progress].
export const CONFIGURATION_INITIALIZATION_JOB_CAS = `UPDATE configuration_jobs j SET state='failed',
 safe_progress=$16::jsonb,error_code=$15,remote_completed=false,completed_at=clock_timestamp(),
 revision=revision+1,updated_at=clock_timestamp(),lease_until=NULL
 WHERE j.cluster_id=$1 AND j.workspace_id=$2 AND j.id=$3 AND j.plan_id=$5
 AND j.plan_revision=$6 AND j.plan_hash=$7 AND j.lease_generation=$8 AND j.actor_id=$9
 AND j.origin_session_id=$10 AND j.revision=$11 AND j.state='running' AND j.lease_owner_hash=$14
 AND j.remote_started=false AND j.remote_completed=false
 AND EXISTS(SELECT 1 FROM configuration_executions e WHERE e.cluster_id=j.cluster_id AND e.workspace_id=j.workspace_id
  AND e.id=$4 AND e.job_id=j.id AND e.plan_id=j.plan_id AND e.plan_revision=j.plan_revision AND e.plan_hash=j.plan_hash
  AND e.actor_id=j.actor_id AND e.lease_generation=j.lease_generation AND e.claim_hash=$13 AND e.revision=$12 AND e.state IN('claimed','executing'))
 AND NOT EXISTS(SELECT 1 FROM mutation_operations m WHERE m.configuration_job_id=j.id OR m.workflow_id=j.workflow_id
  OR m.configuration_execution_id=$4 OR m.idempotency_key LIKE 'configuration-'||j.id::text||'-%')`;

export const CONFIGURATION_INITIALIZATION_EXECUTION_CAS = `UPDATE configuration_executions e SET state='failed',
 revision=revision+1,completed_at=clock_timestamp()
 WHERE e.cluster_id=$1 AND e.workspace_id=$2 AND e.job_id=$3 AND e.id=$4 AND e.plan_id=$5
 AND e.plan_revision=$6 AND e.plan_hash=$7 AND e.lease_generation=$8 AND e.actor_id=$9
 AND e.revision=$12 AND e.state IN('claimed','executing') AND e.claim_hash=$13
 AND EXISTS(SELECT 1 FROM configuration_jobs j WHERE j.cluster_id=e.cluster_id AND j.workspace_id=e.workspace_id
  AND j.id=e.job_id AND j.origin_session_id=$10 AND j.state='failed' AND j.revision=$11+1
  AND j.plan_id=e.plan_id AND j.plan_revision=e.plan_revision AND j.plan_hash=e.plan_hash
  AND j.lease_generation=e.lease_generation AND j.lease_owner_hash=$14)`;
