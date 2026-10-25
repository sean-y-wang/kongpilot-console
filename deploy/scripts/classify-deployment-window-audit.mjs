import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {existsSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

// Fixed projection deliberately excludes before/after/JSON patch/payload/IP.
export const AUDIT_WINDOW_QUERY=String.raw`SELECT id,sequence,occurred_at,actor_type,actor_id,cluster_id,workspace_id,entity_type,entity_id,action,result,request_id,event_hash
 FROM audit_events WHERE occurred_at BETWEEN $1::timestamptz AND $2::timestamptz ORDER BY occurred_at,id LIMIT 21`;
export const AUDIT_WINDOW_PROGRAM=String.raw`
const{Pool}=require('pg'),{createHash}=require('node:crypto'),fs=require('node:fs');
const inputBytes=fs.readFileSync(0);if(inputBytes.length>2048)process.exit(1);const input=JSON.parse(inputBytes);
if(Object.keys(input).sort().join(',')!=='afterAt,beforeAt'||!Number.isFinite(Date.parse(input.beforeAt))||!Number.isFinite(Date.parse(input.afterAt))||Date.parse(input.beforeAt)>Date.parse(input.afterAt))process.exit(1);
const sha=value=>createHash('sha256').update(String(value)).digest('hex'),uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const allowed={actor_type:new Set(['system','user','anonymous','external','developer']),entity_type:new Set(['cluster','clusters','authentication','auth_sessions','workflows','portal_credentials','portal_application_grants','monitoring']),
 action:new Set(['probe','cluster.bootstrap','create','update','deactivate','login','logout','refresh','settings.configure','workflow.submit','workflow.approve','workflow.reject','workflow.execute','workflow.reconcile-metadata','portal.credential.reveal']),result:new Set(['success','failure','failed','denied','locked','pending','uncertain'])};
const safe=row=>{const output={};
 for(const key of ['id','actor_id','cluster_id','workspace_id','entity_id','request_id']){const v=row[key];if(v==null||uuid(v))output[key]=v;else output[key+'_sha256']=sha(v);}
 for(const key of ['actor_type','entity_type','action','result']){if(allowed[key].has(row[key]))output[key]=row[key];else output[key+'_sha256']=sha(row[key]);}
 if(typeof row.sequence==='string'&&/^[0-9]{1,20}$/.test(row.sequence))output.sequence=row.sequence;
 if(row.occurred_at instanceof Date&&Number.isFinite(row.occurred_at.getTime()))output.occurred_at=row.occurred_at.toISOString();
 if(typeof row.event_hash==='string'&&/^[a-f0-9]{64}$/.test(row.event_hash))output.event_hash=row.event_hash;
 return output;};
(async()=>{const pool=new Pool({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:5000,query_timeout:10000});let db;try{
 db=await pool.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await db.query("SET LOCAL TIME ZONE 'UTC'");await db.query("SET LOCAL statement_timeout='10s'");await db.query("SET LOCAL lock_timeout='1s'");
 const role=(await db.query("SELECT rolsuper,rolcreatedb,rolcreaterole,current_setting('transaction_read_only') AS read_only FROM pg_roles WHERE rolname=current_user")).rows[0];
 if(!role||role.rolsuper||role.rolcreatedb||role.rolcreaterole||role.read_only!=='on')throw new Error('RUNTIME_ROLE_INVALID');
 const args=[input.beforeAt,input.afterAt],count=Number((await db.query('SELECT count(*) AS count FROM audit_events WHERE occurred_at BETWEEN $1::timestamptz AND $2::timestamptz',args)).rows[0].count);
 const rows=(await db.query(AUDIT_WINDOW_QUERY,args)).rows.map(safe);await db.query('COMMIT');
 process.stdout.write(JSON.stringify({actualQueryExecuted:true,count,bounded:count<=21,rows,runtimeNonSuperuser:true,repeatableReadReadOnly:true}));
 }finally{if(db){try{await db.query('ROLLBACK');}catch{}db.release();}await pool.end();}})().catch(error=>{process.stdout.write(JSON.stringify({actualQueryExecuted:false,reason:'AUDIT_CLASSIFICATION_READ_FAILED',...(typeof error.code==='string'&&/^[0-9A-Z]{5}$/.test(error.code)?{sqlState:error.code}:{})}));process.exitCode=1;});
`.replace("const inputBytes=",'const AUDIT_WINDOW_QUERY='+JSON.stringify(AUDIT_WINDOW_QUERY)+';const inputBytes=');

export function classifyDeploymentWindowAudit(){
 const output='artifacts/M6/deployment-window-audit-classification.json';if(existsSync(output))throw new Error('AUDIT_CLASSIFICATION_ALREADY_RECORDED');
 const continuityPath='artifacts/M6/portal-metadata-restore-repair-continuity.json',bytes=readFileSync(continuityPath),sealed=JSON.parse(bytes);
 const sha=value=>createHash('sha256').update(value).digest('hex');
 if(sha(bytes)!=='4c0356e4d11c7676a5db7bf99e8ac292ef90fc41d381d1ad3670af729463f00e'||sealed.allPassed!==false)throw new Error('SEALED_CONTINUITY_CHANGED');
 const before=sealed.before.foundation.core,after=sealed.after.foundation.core;
 if(!/^[a-f0-9]{64}$/.test(after.api.id))throw new Error('SEALED_CONTAINER_INVALID');
 const deploymentPath='artifacts/M6/portal-metadata-restore-deployment.json',deploymentBytes=readFileSync(deploymentPath),deployment=JSON.parse(deploymentBytes);
 const restart=deployment.steps.find(row=>row.step==='same-console-api-container-process-restart');
 const readiness=deployment.steps.find(row=>row.step==='existing-m6-startup-and-boundaries-verify-only');
 if(!restart||restart.exitCode!==0||!readiness||readiness.exitCode!==0||!Number.isFinite(Date.parse(restart.startedAt))||!Number.isFinite(Date.parse(readiness.completedAt)))throw new Error('RESTART_EVIDENCE_INVALID');
 const startedAt=new Date().toISOString();let actual;
 try{const env={...process.env};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[key];
  actual=JSON.parse(execFileSync('docker',['--host=unix:///var/run/docker.sock','exec','-i',after.api.id,'node','-e',AUDIT_WINDOW_PROGRAM],
   {env,input:JSON.stringify({beforeAt:before.observedAt,afterAt:after.observedAt}),encoding:'utf8',stdio:['pipe','pipe','pipe'],maxBuffer:65536,timeout:15000}));
 }catch{actual={actualQueryExecuted:false,count:null,reason:'AUDIT_CLASSIFICATION_EXECUTION_FAILED'};}
 const row=actual.count===1&&actual.rows?.length===1?actual.rows[0]:null;
 const sameCluster=row?.cluster_id==='dff45535-ed8d-4851-b7a6-6376feac7f59'&&row.entity_id===row.cluster_id;
 // onModuleInit starts an asynchronous probe. Docker restart can return before
 // that callback finishes; use the recorded restart-through-readiness window.
 const withinRestart=!!row?.occurred_at&&Date.parse(row.occurred_at)>=Date.parse(restart.startedAt)&&Date.parse(row.occurred_at)<=Date.parse(readiness.completedAt);
 const systemProbe=!!row&&row.actor_type==='system'&&row.actor_id===null&&row.workspace_id===null&&row.request_id===null
  &&row.entity_type==='cluster'&&row.action==='probe'&&row.result==='success'&&sameCluster&&withinRestart;
 const allPassed=actual.actualQueryExecuted===true&&actual.runtimeNonSuperuser===true&&actual.repeatableReadReadOnly===true&&actual.count===1&&systemProbe;
 const sources=['apps/console-api/src/modules/clusters/clusters.service.ts','apps/console-api/src/infrastructure/kong/kong.service.ts','apps/console-api/src/modules/audit/audit.service.ts'];
 const report={stage:'M6',label:'deployment-window-audit-classification',startedAt,endedAt:new Date().toISOString(),
  sourceSHA256:sha(readFileSync(fileURLToPath(import.meta.url))),programSHA256:sha(AUDIT_WINDOW_PROGRAM),
  allPassed,classification:systemProbe?'AUTOMATIC_STARTUP_CAPABILITY_PROBE':'UNPROVEN',
  ...actual,sameCanonicalCluster:sameCluster,withinAuthorizedApiRestartReadiness:withinRestart,
  exactFieldProjection:true,rawBodiesRead:false,epochsRead:false,settingsRead:false,privateFilesRead:false,
  businessWrites:0,nativeWrites:0,builds:0,restarts:0,migrations:0,
  existingEvidence:[{path:continuityPath,sha256:sha(bytes)},{path:deploymentPath,sha256:sha(deploymentBytes)},
   {path:'artifacts/M6/portal-metadata-restore-metrics-readonly-diagnostic.json',sha256:sha(readFileSync('artifacts/M6/portal-metadata-restore-metrics-readonly-diagnostic.json'))},
   ...sources.map(path=>({path,sha256:sha(readFileSync(path))}))],
  sourceReason:systemProbe?'ClustersService.onModuleInit invokes actor-free Kong.probe; inspection uses Admin GET reads and persistProbe appends system cluster/probe audit. Exact fields and timestamp match the authorized API restart.':'Actual fixed fields do not establish the expected startup probe; no further reads attempted.',
  historicalFailedReportsChanged:false};
 const text=JSON.stringify(report,null,2)+'\n';if(Buffer.byteLength(text)>65536)throw new Error('OUTPUT_BOUND_EXCEEDED');writeFileSync(output,text,{flag:'wx'});
 console.log(JSON.stringify({allPassed,classification:report.classification,actualQueryExecuted:actual.actualQueryExecuted,count:actual.count,output}));if(!allPassed)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{if(process.argv.length!==2)throw new Error('ARGUMENTS_INVALID');classifyDeploymentWindowAudit();}
 catch{console.error('AUDIT_CLASSIFICATION_FAILED; raw errors withheld.');process.exitCode=1;}
}
