import { execFileSync, spawnSync } from 'node:child_process';
import { M8_COMPOSE, sha256 } from './m8-harness.mjs';
export const M8_PREPARATION_STOPPED = Object.freeze({ count:98, prefix:'2467d175f01c85c818d2d462cbe11f78af3724c66851f9a80d126f40259767aa',
 failureSha256:'41a883bf30d2975c6fa025cd1695cfb4a6ac6b2837fd659af2a67f38ad77d854',diagnosisSha256:'383b91facea0479d59a5e2eba336edf1c3d1d1fcaaeeadf21dd388f79daf39b6',
 workflowId:'80b3b831-5522-44e5-ac2d-a538b032a0a2',jobId:'f514b7da-b84c-459e-94ee-d10e77b33d1b',planId:'8e2ffe7b-4586-4302-aa76-2a487b9321a7',
 executionId:'aed3661d-2989-4f64-8cad-4bfc01b5f775',stepId:'276edc84-b731-4850-bfca-813ad863f0b1',requestId:'01514f40-ccd8-4f85-829b-0f67ae15da64',key:'ff91b089-3109-4de4-8b02-6758231d0e00' });
export function assertM8PreparationRepairCheckpoint(r,failureBytes,diagnosisBytes){
 const c=M8_PREPARATION_STOPPED,failed=JSON.parse(failureBytes),d=JSON.parse(diagnosisBytes),p=r.requests?.[97],source=r.requests?.[93],submission=r.requests?.[94];
 if(sha256(failureBytes)!==c.failureSha256||sha256(diagnosisBytes)!==c.diagnosisSha256||failed.passed!==1073||failed.failed!==1||failed.unknownWrites!==0
  ||r.requests?.length!==c.count||sha256(JSON.stringify(r.requests))!==c.prefix||r.phase!=='stopped-failure'||r.inFlight!==null||r.v2PreparationRepairTail||r.approvalTransfer||r.c2ModeRestored
  ||!r.directTransfer||r.fiveClassRecovery?.length!==5||r.cliIntents?.length||r.requests.some(v=>v.state!=='response_observed')
  ||p.status!==503||p.errorCode!=='WORKFLOW_EXECUTION_FAILED'||p.key!==c.key||p.requestId!==c.requestId
  ||submission.status!==201||submission.responseData?.jobId!==c.jobId||submission.responseData.workflowId!==c.workflowId
  ||r.requests[96].status!==201||r.requests[96].responseData?.entity?.state!=='approved'
  ||source.status!==201||source.responseData?.counts?.create!==17||source.body?.mode!=='merge'||source.body?.scope!=='workspace'||typeof source.body?.yaml!=='string'
  ||d.currentPrefix98!==c.prefix||d.sql?.ok!==true||d.sql.workflow?.id!==c.workflowId||d.sql.workflow.state!=='uncertain'
  ||d.sql.job?.id!==c.jobId||d.sql.job.state!=='waiting_approval'||d.sql.job.remote_started||d.sql.job.remote_completed
  ||d.sql.plan?.id!==c.planId||d.sql.plan.state!=='pending_approval'||d.sql.executions.length||d.sql.steps.length||d.sql.operations.length
  ||d.sql.workflowExecutions.length!==1||d.sql.workflowExecutions[0].id!==c.executionId||d.sql.workflowExecutions[0].state!=='uncertain'
  ||d.sql.workflowSteps.length!==1||d.sql.workflowSteps[0].id!==c.stepId||d.sql.workflowSteps[0].state!=='uncertain'||d.sql.workflowSteps[0].native_request_count!==0)
  throw Error('M8_EXACT_STOPPED_APPROVAL_PREPARATION_REQUIRED');
 return{failed,diagnosis:d,source,submission,execute:p};
}
export function assertM8OriginalApprovalNoNative(row){
 const c=M8_PREPARATION_STOPPED;
 if(!row||row.workflow_id!==c.workflowId||row.job_id!==c.jobId||row.plan_id!==c.planId||row.execution_id!==c.executionId||row.step_id!==c.stepId
  ||row.workflow_state!=='uncertain'||row.execution_state!=='uncertain'||row.step_state!=='uncertain'||row.snapshot_state!=='ready'||row.job_state!=='waiting_approval'||row.plan_state!=='pending_approval'
  ||row.remote_started!==false||row.remote_completed!==false||row.same_request!==true||row.same_key!==true||row.same_actor!==true||row.same_sid!==true||row.same_plan_hash!==true||row.same_workflow_tuple!==true
  ||row.handler!=='configuration_v2'||row.kind!=='metadata'||row.native_request_count!==0||row.operation_id!==null||row.configuration_execution_count!==0||row.configuration_step_count!==0||row.native_operation_count!==0)
  throw Error('M8_CURRENT_ORIGINAL_UNCERTAIN_WITH_ZERO_NATIVE_REQUIRED');
 return row;
}
export async function m8CurrentStoppedApprovalProof(h,actor,area){
 const c=M8_PREPARATION_STOPPED,env={...process.env};for(const k of['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[k];
 const container=execFileSync('docker',['--host=unix:///var/run/docker.sock',...M8_COMPOSE,'ps','-q','console-api'],{env,encoding:'utf8'}).trim();if(!/^[a-f\d]{64}$/.test(container))throw Error('M8_API_CONTAINER_REQUIRED');
 const program=`const{Client}=require('pg');let text='';process.stdin.on('data',b=>text+=b);process.stdin.on('end',async()=>{const p=JSON.parse(text),db=new Client({connectionString:process.env.DATABASE_URL});try{await db.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const who=(await db.query('SELECT current_user AS role,current_database() AS name')).rows[0];if(who.role!=='kongos_app'||who.name!=='kongos')throw Error('NONOWNER_REQUIRED');const row=(await db.query(\`SELECT w.id AS workflow_id,w.state AS workflow_state,j.id AS job_id,j.state AS job_state,j.remote_started,j.remote_completed,j.origin_session_id=$9::uuid AS same_sid,j.actor_id=$8::uuid AS same_actor,p.id AS plan_id,p.state AS plan_state,v.plan_hash=$10 AS same_plan_hash,(w.kind='configuration_v2' AND w.subject_type='configuration_jobs' AND w.subject_id=j.id AND w.requester_user_id=$8::uuid AND e.execution_actor_id=$8::uuid AND e.plan_revision=w.plan_revision AND e.plan_hash=w.plan_hash AND s.plan_revision=e.plan_revision AND s.plan_hash=e.plan_hash AND w.plan_hash=$11 AND e.completed_at IS NOT NULL) AS same_workflow_tuple,e.id AS execution_id,e.state AS execution_state,e.snapshot_state,e.request_id=$6 AS same_request,e.idempotency_key=$7 AS same_key,s.id AS step_id,s.state AS step_state,s.handler,s.kind,s.operation_id,jsonb_array_length(s.native_requests) AS native_request_count,(SELECT count(*)::integer FROM configuration_executions x WHERE x.cluster_id=j.cluster_id AND x.workspace_id=j.workspace_id AND x.job_id=j.id) AS configuration_execution_count,(SELECT count(*)::integer FROM configuration_job_steps x WHERE x.cluster_id=j.cluster_id AND x.workspace_id=j.workspace_id AND x.job_id=j.id) AS configuration_step_count,(SELECT count(*)::integer FROM mutation_operations x WHERE x.cluster_id=j.cluster_id AND (x.configuration_job_id=j.id OR x.workflow_id=w.id OR x.request_id=$6)) AS native_operation_count FROM workflows w JOIN configuration_jobs j ON j.workflow_id=w.id AND j.cluster_id=w.cluster_id AND j.workspace_id=w.workspace_id JOIN configuration_plans p ON p.id=j.plan_id AND p.cluster_id=j.cluster_id AND p.workspace_id=j.workspace_id JOIN configuration_plan_versions v ON v.plan_id=p.id AND v.plan_revision=p.current_revision AND v.cluster_id=p.cluster_id AND v.workspace_id=p.workspace_id JOIN workflow_executions e ON e.workflow_id=w.id AND e.cluster_id=w.cluster_id AND e.workspace_id=w.workspace_id AND e.id=$4 JOIN workflow_steps s ON s.workflow_id=w.id AND s.cluster_id=w.cluster_id AND s.workspace_id=w.workspace_id AND s.id=$5 WHERE w.cluster_id=$1 AND w.workspace_id=$2 AND w.id=$3\`,[p.cid,p.wid,p.workflowId,p.executionId,p.stepId,p.requestId,p.key,p.actorId,p.sid,p.planHash,p.workflowPlanHash])).rows[0];await db.query('COMMIT');console.log(JSON.stringify({ok:true,nonOwnerReadOnly:true,row}));}catch(e){try{await db.query('ROLLBACK');}catch{}console.log(JSON.stringify({ok:false,errorCode:/^[A-Z0-9_]{2,80}$/.test(e.code||'')?e.code:'READONLY_FAILED'}));process.exitCode=1;}finally{await db.end();}});`;
 const child=spawnSync('docker',['--host=unix:///var/run/docker.sock','exec','-i',container,'node','-e',program],{env,input:JSON.stringify({...c,cid:area.cid,wid:area.wid,actorId:actor.user.id,sid:actor.sid,planHash:h.state.requests[94].responseData.planHash,workflowPlanHash:h.state.requests[96].responseData.entity.planHash}),encoding:'utf8',maxBuffer:32768,timeout:30000});
 let proof;try{proof=JSON.parse(child.stdout);}catch{throw Error('M8_ORIGINAL_APPROVAL_READONLY_PROOF_UNKNOWN');}
 h.check(child.status===0&&proof.ok===true&&proof.nonOwnerReadOnly===true,'original uncertain approval is verified through current exact console nonowner read-only metadata');
 assertM8OriginalApprovalNoNative(proof.row);return{performedAt:new Date().toISOString(),nonOwnerReadOnly:true,...proof.row};
}
