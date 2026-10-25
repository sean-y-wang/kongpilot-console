import{readFileSync}from'node:fs';
import{execFileSync,spawnSync}from'node:child_process';
import{parse}from'yaml';
import{M8Harness,M8_COMPOSE,readM8Reference,durableJson,sha256,scope,entity}from'./lib/m8-harness.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true')throw Error('M8_READONLY_HANDOFF_REQUIRED');
const r=readM8Reference(),prefix='c998bb14dfb49dd1527e18244063330de2225fc12a58fe6a6483f29cec579f40',path='artifacts/M8/v2-edge-timeout-objects-timing-readonly.json';
const priorPath='artifacts/M8/v2-edge-timeout-readonly-diagnosis.json',priorBytes=readFileSync(priorPath);
if(r.requests.length!==121||sha256(JSON.stringify(r.requests))!==prefix||r.inFlight!==null||r.phase!=='stopped-failure'||r.v2EdgeTimeoutObjectProof
 ||sha256(priorBytes)!=='553bf8a503b9f89dbe99c18c71543faec1885a35f56dae494be9531cf75d4b7d')throw Error('M8_EXACT_TIMEOUT_CHECKPOINT_REQUIRED');
const prior=JSON.parse(priorBytes),area=r.scopes.approval,actor=r.sessions.admin,expected=parse(r.requests[116].body.yaml).services;
if(prior.sql.steps.length!==17||prior.sql.operations.length!==17||expected.length!==17||expected.some((s,i)=>s.name!==`${r.testTag}-v2-${i}`))throw Error('M8_EXACT_SEVENTEEN_SERVICES_REQUIRED');
const h=new M8Harness({resume:true,reference:r}),details=[];let authorized=true;
for(const step of prior.sql.steps){const op=prior.sql.operations.find(o=>o.id===step.operation_id);
 if(!op||op.entity_type!=='services'||op.workspace_id!==area.wid)throw Error('M8_EXACT_SERVICE_OPERATION_REQUIRED');
 const response=await h.request(actor,scope(area.cid,area.wid,`entities/services/${op.entity_id}`),'GET',undefined,{expected:[200,401,403,404],renew:false});
 const current=entity(response.payload?.data),wanted=expected[step.step_order-1];
 details.push({stepOrder:step.step_order,stepId:step.id,operationId:op.id,entityId:op.entity_id,status:response.status,requestId:response.requestId,
  exists:response.status===200,identityMatches:response.status===200&&current?.id===op.entity_id,
  fieldsMatch:response.status===200&&['name','host','port','protocol','retries'].every(k=>current?.[k]===wanted[k]),
  logicalTagsMatch:response.status===200&&Array.isArray(current?.tags)&&wanted.tags.every(t=>current.tags.includes(t)),
  requestedOriginalScope:true});
 if([401,403].includes(response.status)){authorized=false;break;}
}
const pages=[];let cursor;
if(authorized)for(let page=0;page<3;page++){
 const response=await h.request(actor,scope(area.cid,area.wid,'entities/services',{size:10,...(cursor?{cursor}:{})}),'GET',undefined,{expected:[200,401,403],renew:false});
 if(response.status!==200){pages.push({page:page+1,status:response.status,requestId:response.requestId});authorized=false;break;}
 const data=response.payload.data;if(!Array.isArray(data.items)||data.items.length>10)throw Error('M8_BOUNDED_ACTUAL_PAGE_REQUIRED');
 pages.push({page:page+1,status:response.status,requestId:response.requestId,ids:data.items.map(v=>v.id),nextPresent:!!data.nextCursor});cursor=data.nextCursor;if(!cursor)break;
}
const env={...process.env};for(const k of['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[k];
const container=execFileSync('docker',['--host=unix:///var/run/docker.sock',...M8_COMPOSE,'ps','-q','console-api'],{env,encoding:'utf8'}).trim();if(!/^[a-f\d]{64}$/.test(container))throw Error('M8_API_CONTAINER_REQUIRED');
const program=`const{Client}=require('pg');let t='';process.stdin.on('data',b=>t+=b);process.stdin.on('end',async()=>{const p=JSON.parse(t),db=new Client({connectionString:process.env.DATABASE_URL});try{await db.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const who=(await db.query('SELECT current_user AS role,current_database() AS name')).rows[0];if(who.role!=='kongos_app'||who.name!=='kongos')throw Error('NONOWNER_REQUIRED');const operations=(await db.query('SELECT o.id,o.entity_id,o.state,o.error_code,o.remote_started,o.remote_completed,o.created_at,o.updated_at,s.step_order,s.id AS step_id,s.state AS step_state FROM mutation_operations o JOIN configuration_job_steps s ON s.operation_id=o.id AND s.cluster_id=o.cluster_id AND s.workspace_id=o.workspace_id AND s.job_id=o.configuration_job_id AND s.execution_id=o.configuration_execution_id WHERE o.cluster_id=$1 AND o.workspace_id=$2 AND o.configuration_job_id=$3 AND o.id=ANY($4::uuid[]) ORDER BY s.step_order',[p.cid,p.wid,p.jobId,p.ids])).rows;const fences=(await db.query('SELECT id,operation_id,state,method,created_at,settled_at FROM metrics_write_fences WHERE cluster_id=$1 AND operation_id=ANY($2::uuid[]) ORDER BY created_at',[p.cid,p.ids])).rows;const audits=(await db.query('SELECT id,action,result,entity_id,occurred_at,request_id,source_ip IS NOT NULL AS source_ip_present FROM audit_events WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND request_id=$4 ORDER BY occurred_at',[p.cid,p.wid,p.workflowId,p.requestId])).rows;const steps=(await db.query('SELECT id,state,step_order,updated_at FROM configuration_job_steps WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3 ORDER BY step_order',[p.cid,p.wid,p.jobId])).rows;await db.query('COMMIT');console.log(JSON.stringify({ok:true,nonOwnerReadOnly:true,operations,fences,audits,steps}));}catch(e){try{await db.query('ROLLBACK');}catch{}console.log(JSON.stringify({ok:false,errorCode:/^[A-Z0-9_]{2,80}$/.test(e.code||'')?e.code:'READONLY_FAILED'}));process.exitCode=1;}finally{await db.end();}});`;
const child=spawnSync('docker',['--host=unix:///var/run/docker.sock','exec','-i',container,'node','-e',program],{env,input:JSON.stringify({cid:area.cid,wid:area.wid,jobId:prior.jobId,workflowId:prior.workflowId,ids:prior.sql.operations.map(o=>o.id),requestId:prior.sql.workflowExecutions[0].request_id}),encoding:'utf8',timeout:30000,maxBuffer:131072});
let sql;try{sql=JSON.parse(child.stdout);}catch{sql={ok:false,errorCode:'READONLY_TRANSPORT_FAILED'};}
if(sql.ok)for(const o of sql.operations)o.durationMs=Date.parse(o.updated_at)-Date.parse(o.created_at);
const logs=spawnSync('docker',['--host=unix:///var/run/docker.sock','logs','--since',r.requests[120].startedAt,container],{env,encoding:'utf8',timeout:15000,maxBuffer:8*1024*1024});
const safeLogs=[];for(const line of`${logs.stdout??''}\n${logs.stderr??''}`.split('\n')){let row;try{row=JSON.parse(line);}catch{continue;}if(row.requestId!==prior.sql.workflowExecutions[0].request_id&&row.jobId!==prior.jobId)continue;
 safeLogs.push(Object.fromEntries(['time','timestamp','level','event','requestId','jobId','errorType','code','causeCode','status'].filter(k=>typeof row[k]==='string'||typeof row[k]==='number').map(k=>[k,row[k]])));}
if(sha256(JSON.stringify(r.requests))!==prefix)throw Error('M8_ORIGINAL_PACKETS_CHANGED');
const report={performedAt:new Date().toISOString(),actual:true,nonOwnerReadOnly:sql.nonOwnerReadOnly===true,originalPrefix121:prefix,originalDiagnosisPath:priorPath,originalDiagnosisSha256:sha256(priorBytes),scope:area,jobId:prior.jobId,workflowId:prior.workflowId,authorized,details,pages,sql,safeLogs,
 causalClaims:{objectAbsenceProvesNoWrite:false,remoteStartedProvesPacketSent:false,fenceProvesBeforeTransportBoundaryOnly:true},newBusinessWrites:0,newAuthWrites:0,newNativeWrites:0};
durableJson(path,report,0o644,true);r.v2EdgeTimeoutObjectProof={path,sha256:sha256(JSON.stringify(report,null,2)+'\n')};h.save();
console.log(JSON.stringify({path,sha256:r.v2EdgeTimeoutObjectProof.sha256,authorized,details:details.map(v=>({order:v.stepOrder,id:v.entityId,status:v.status,fieldsMatch:v.fieldsMatch,tagsMatch:v.logicalTagsMatch})),pages:pages.map(v=>({page:v.page,status:v.status,count:v.ids?.length,next:v.nextPresent})),sqlOk:sql.ok,operations:sql.operations?.map(o=>({order:o.step_order,state:o.state,durationMs:o.durationMs,remoteCompleted:o.remote_completed})),fenceCounts:sql.fences?.reduce((a,f)=>(a[f.state]=(a[f.state]??0)+1,a),{}),safeLogCount:safeLogs.length,newBusinessWrites:0,newAuthWrites:0,newNativeWrites:0}));
