/** Fixed ledger-only SQL. No query creates/replays a mutation or changes a
 * workflow/native receipt. Parameter order is shared with isolated PG tests. */
export const CONFIGURATION_FAILURE_ANCHOR_QUERY = `SELECT
 j.id AS job_id,j.cluster_id,j.workspace_id,j.actor_id,j.origin_session_id,j.transport_scope,j.kind,
 j.state AS job_state,j.revision AS job_revision,j.plan_id,j.plan_revision,j.plan_hash,j.workflow_id,
 j.execution_mode,j.permission_version,j.credential_epoch,j.lease_generation,j.lease_owner_hash,j.lease_until,
 j.safe_progress,j.request_id AS job_request_id,
 e.id AS execution_id,e.state AS execution_state,e.revision AS execution_revision,e.claim_hash,
 e.actor_id AS execution_actor_id,e.workflow_id AS execution_workflow_id,e.approved_version,e.workflow_plan_hash,
 e.execution_mode AS execution_mode_actual,e.permission_version AS execution_permission_version,
 e.lease_generation AS execution_lease_generation,e.plan_id AS execution_plan_id,
 e.plan_revision AS execution_plan_revision,e.plan_hash AS execution_plan_hash,
 v.step_count,v.plan_hash AS version_plan_hash,p.current_revision,
 w.kind AS workflow_kind,w.state AS workflow_state,w.subject_id,w.subject_type,w.requester_user_id,
 w.plan_revision AS workflow_plan_revision,w.plan_hash AS current_workflow_plan_hash,
 we.id AS workflow_execution_id,we.state AS workflow_execution_state,we.snapshot_state,
 we.execution_actor_id AS workflow_execution_actor_id,we.request_id AS workflow_request_id,
 we.plan_revision AS workflow_execution_plan_revision,we.plan_hash AS workflow_execution_plan_hash
 FROM configuration_jobs j
 JOIN configuration_executions e ON e.cluster_id=j.cluster_id AND e.workspace_id=j.workspace_id AND e.job_id=j.id
 JOIN configuration_plan_versions v ON v.cluster_id=e.cluster_id AND v.workspace_id=e.workspace_id
   AND v.plan_id=e.plan_id AND v.plan_revision=e.plan_revision AND v.plan_hash=e.plan_hash
 JOIN configuration_plans p ON p.cluster_id=v.cluster_id AND p.workspace_id=v.workspace_id AND p.id=v.plan_id
 LEFT JOIN workflows w ON w.cluster_id=j.cluster_id AND w.workspace_id=j.workspace_id AND w.id=j.workflow_id
 LEFT JOIN workflow_executions we ON we.cluster_id=w.cluster_id AND we.workspace_id=w.workspace_id
   AND we.workflow_id=w.id AND we.id=$5::uuid
 WHERE j.cluster_id=$1 AND j.workspace_id=$2 AND j.id=$3 AND e.id=$4
 FOR UPDATE OF j,e`;

export const CONFIGURATION_FAILURE_STEPS_QUERY = `SELECT s.id,s.state,s.revision,s.step_order,
 s.plan_step_id,s.object_workspace_id,s.operation_id,s.receipt_operation_id,s.after_hmac,
 (s.receipt_ciphertext IS NOT NULL) AS receipt_present,
 p.entity_type,p.permission_action,p.mutation_action,p.parent_id,p.credential_kind,p.allocated_native_id,p.native_id,
 o.id AS native_operation_id,o.entity_id AS native_entity_id,o.workflow_id AS native_workflow_id,
 o.state AS native_state,o.remote_started,o.remote_completed,(o.result_secret IS NOT NULL) AS native_result_present,
 o.cluster_id AS native_cluster_id,o.workspace_id AS native_workspace_id,o.actor_id AS native_actor_id,
 o.transport_scope AS native_transport_scope,o.action AS native_action,o.entity_type AS native_entity_type,
 o.parent_id AS native_parent_id,o.credential_kind AS native_credential_kind,o.idempotency_key AS native_key,
 o.configuration_job_id,o.configuration_execution_id,o.configuration_step_id,
 o.configuration_plan_revision,o.configuration_plan_hash,
 o.workflow_execution_id,o.workflow_step_id,o.workflow_plan_revision,o.workflow_plan_hash,
 (SELECT count(*)::integer FROM metrics_write_fences f WHERE f.operation_id=o.id) AS fence_count
 FROM configuration_job_steps s JOIN configuration_plan_objects p ON p.cluster_id=s.cluster_id AND p.workspace_id=s.workspace_id
 AND p.plan_id=s.plan_id AND p.plan_revision=s.plan_revision AND p.plan_hash=s.plan_hash
 AND p.step_id=s.plan_step_id AND p.object_workspace_id=s.object_workspace_id
 LEFT JOIN mutation_operations o ON o.cluster_id=s.cluster_id AND o.workspace_id=s.object_workspace_id
 AND o.actor_id=$8 AND o.idempotency_key='configuration-'||s.job_id::text||'-'||s.id::text
 WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.job_id=$3 AND s.execution_id=$4
 AND s.plan_id=$5 AND s.plan_revision=$6 AND s.plan_hash=$7
 ORDER BY s.step_order FOR UPDATE OF s`;

// [CID,WID,job,execution,plan,planRevision,planHash,leaseGeneration,actor,SID,
//  expectedRevision,state,safeProgress,errorCode,leaseOwnerHash,claimHash]. The reciprocal anchor is
//  locked first; this CAS cannot attach a different execution/authority.
export const CONFIGURATION_FAILURE_JOB_CAS = `UPDATE configuration_jobs j SET state=$12,
 safe_progress=$13::jsonb,error_code=$14,remote_completed=false,completed_at=clock_timestamp(),
 revision=revision+1,updated_at=clock_timestamp(),lease_until=NULL
 WHERE j.cluster_id=$1 AND j.workspace_id=$2 AND j.id=$3 AND j.plan_id=$5
 AND j.plan_revision=$6 AND j.plan_hash=$7 AND j.lease_generation=$8 AND j.actor_id=$9
 AND j.origin_session_id=$10 AND j.revision=$11 AND j.state='running' AND j.lease_owner_hash=$15
 AND $12 IN('failed','partial','uncertain')
 AND EXISTS(SELECT 1 FROM configuration_executions e WHERE e.cluster_id=j.cluster_id AND e.workspace_id=j.workspace_id
   AND e.id=$4 AND e.job_id=j.id AND e.plan_id=j.plan_id AND e.plan_revision=j.plan_revision AND e.plan_hash=j.plan_hash
   AND e.actor_id=j.actor_id AND e.lease_generation=j.lease_generation AND e.claim_hash=$16 AND e.state='executing')`;

// Same first ten identity params, then expectedExecutionRevision/state/leaseOwnerHash/claimHash.
export const CONFIGURATION_FAILURE_EXECUTION_CAS = `UPDATE configuration_executions e SET state=$12,
 revision=revision+1,completed_at=clock_timestamp()
 WHERE e.cluster_id=$1 AND e.workspace_id=$2 AND e.job_id=$3 AND e.id=$4 AND e.plan_id=$5
 AND e.plan_revision=$6 AND e.plan_hash=$7 AND e.lease_generation=$8 AND e.actor_id=$9
 AND e.revision=$11 AND e.state='executing' AND e.claim_hash=$14 AND $12 IN('failed','partial','uncertain')
 AND EXISTS(SELECT 1 FROM configuration_jobs j WHERE j.cluster_id=e.cluster_id AND j.workspace_id=e.workspace_id
   AND j.id=e.job_id AND j.origin_session_id=$10 AND j.state=$12 AND j.plan_id=e.plan_id
   AND j.plan_revision=e.plan_revision AND j.plan_hash=e.plan_hash AND j.lease_generation=e.lease_generation AND j.lease_owner_hash=$13)`;

// [CID,WID,job,execution,plan,planRevision,planHash,step,revision,state,code].
export const CONFIGURATION_FAILURE_STEP_CAS = `UPDATE configuration_job_steps SET state=$10,
 error_code=$11,revision=revision+1,completed_at=clock_timestamp()
 WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3 AND execution_id=$4 AND plan_id=$5
 AND plan_revision=$6 AND plan_hash=$7 AND id=$8 AND revision=$9 AND state IN('pending','running')
 AND $10 IN('failed','uncertain')`;

export const CONFIGURATION_ABANDON_CURRENT_IDENTITY_QUERY = `SELECT u.id,s.id AS session_id
 FROM users u JOIN auth_sessions s ON s.user_id=u.id
 JOIN clusters c ON c.id=$3 AND c.deleted_at IS NULL AND c.status NOT IN('disabled','incompatible')
 JOIN workspaces w ON w.cluster_id=c.id AND w.id=$4 AND w.status='active'
 WHERE u.id=$1 AND u.status='active' AND u.deleted_at IS NULL AND u.force_password_change=false
 AND s.id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
 AND s.credential_epoch=u.credential_epoch AND u.credential_epoch=$5::bigint FOR SHARE OF u,s,c,w`;

export const CONFIGURATION_ABANDON_EXECUTION_REFERENCE_QUERY = `SELECT e.id AS execution_id,we.id AS workflow_execution_id
 FROM configuration_executions e
 LEFT JOIN workflow_executions we ON we.cluster_id=e.cluster_id AND we.workspace_id=e.workspace_id
 AND we.workflow_id=e.workflow_id AND we.execution_actor_id=e.actor_id
 AND we.plan_revision=e.approved_version AND we.plan_hash=e.workflow_plan_hash
 AND we.state IN('failed','uncertain')
 WHERE e.cluster_id=$1 AND e.workspace_id=$2 AND e.job_id=$3 AND e.actor_id=$4
 AND e.state='executing' LIMIT 2`;
