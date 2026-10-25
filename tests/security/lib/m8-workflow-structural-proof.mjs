import{execFileSync}from'node:child_process';
import{M8_COMPOSE}from'./m8-harness.mjs';
/** The public workflow DTO deliberately omits handler/native packets. This
 * reads only exact immutable structural columns, never plan plaintext or a
 * capability, through the current console's non-owner READ ONLY transaction. */
export async function m8WorkflowStructuralProof(h,actor,area,summary,step,expectedHandler){
 const env={...process.env};for(const name of['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[name];
 const container=execFileSync('docker',['--host=unix:///var/run/docker.sock',...M8_COMPOSE,'ps','-q','console-api'],{env,encoding:'utf8',timeout:15000,maxBuffer:1024}).trim();
 h.check(/^[a-f\d]{64}$/.test(container),'workflow structural proof selects only the canonical console API container');
 const program=`const{Client}=require('pg');let input='';process.stdin.on('data',b=>input+=b);process.stdin.on('end',async()=>{const p=JSON.parse(input),db=new Client({connectionString:process.env.DATABASE_URL});try{await db.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const who=(await db.query('SELECT current_user AS role,current_database() AS name')).rows[0];if(who.role!=='kongos_app'||who.name!=='kongos')throw Error('NONOWNER_REQUIRED');const w=(await db.query('SELECT w.id,w.kind,w.state,w.cluster_id,w.workspace_id,w.subject_type,w.subject_id,w.requester_user_id=$4::uuid AS requester_matches,w.plan_hash=$5 AS public_hash_matches,v.plan_hash=w.plan_hash AS version_hash_matches FROM workflows w JOIN workflow_versions v ON v.cluster_id=w.cluster_id AND v.workspace_id=w.workspace_id AND v.workflow_id=w.id AND v.plan_revision=w.plan_revision WHERE w.cluster_id=$1 AND w.workspace_id=$2 AND w.id=$3',[p.cid,p.wid,p.workflowId,p.actorId,p.planHash])).rows[0];const steps=(await db.query('SELECT s.id,s.kind,s.handler,s.entity_type,s.entity_id,s.operation_id,jsonb_array_length(s.native_requests)::integer AS native_request_count,s.plan_hash=w.plan_hash AS current_hash_matches FROM workflow_steps s JOIN workflows w ON w.cluster_id=s.cluster_id AND w.workspace_id=s.workspace_id AND w.id=s.workflow_id AND w.plan_revision=s.plan_revision WHERE w.cluster_id=$1 AND w.workspace_id=$2 AND w.id=$3 ORDER BY s.step_order',[p.cid,p.wid,p.workflowId])).rows;await db.query('COMMIT');console.log(JSON.stringify({ok:true,actualNonOwnerReadOnly:true,workflow:w,steps}));}catch(e){try{await db.query('ROLLBACK');}catch{}console.log(JSON.stringify({ok:false,errorCode:/^[A-Z0-9_]{2,80}$/.test(e.code||'')?e.code:'WORKFLOW_STRUCTURAL_READ_FAILED'}));process.exitCode=1;}finally{await db.end();}});`;
 const proof=JSON.parse(execFileSync('docker',['--host=unix:///var/run/docker.sock','exec','-i',container,'node','-e',program],{env,input:JSON.stringify({cid:area.cid,wid:area.wid,workflowId:summary.id,actorId:actor.user.id,planHash:summary.planHash}),encoding:'utf8',timeout:30000,maxBuffer:65536}));
 assertM8WorkflowStructuralProof(h,proof,{actor,area,summary,step,expectedHandler});
 h.state.workflowStructuralProofs??=[];h.state.workflowStructuralProofs.push(proof);h.save();return proof;
}
export function assertM8WorkflowStructuralProof(h,p,{actor,area,summary,step,expectedHandler}){
 const w=p?.workflow,s=p?.steps?.[0];
 h.check(p?.ok===true&&p.actualNonOwnerReadOnly===true&&w?.id===summary.id&&w.cluster_id===area.cid&&w.workspace_id===area.wid
  &&w.kind===summary.kind&&w.state===summary.state&&w.requester_matches===true&&w.public_hash_matches===true&&w.version_hash_matches===true
  &&p.steps.length===1&&s.id===step.id&&s.kind==='metadata'&&s.handler===expectedHandler&&s.native_request_count===0
  &&s.operation_id===null&&s.current_hash_matches===true&&s.entity_type===w.subject_type&&s.entity_id===w.subject_id
  &&(expectedHandler==='configuration_v2'?w.subject_type==='configuration_jobs':expectedHandler==='configuration.metadata'&&['config_snapshots','config_snapshot_schedules','configuration_gitops_runs'].includes(w.subject_type)),
  'actual exact workflow structural columns prove one fixed metadata handler and zero V1 Native packets');
}
