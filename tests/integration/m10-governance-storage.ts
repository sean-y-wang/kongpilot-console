import 'reflect-metadata';
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync,readdirSync,mkdirSync,writeFileSync} from 'node:fs';
import {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {provisionRuntimeRole} from '../../apps/console-api/src/infrastructure/migrate';
import {GovernanceRepositoryService} from '../../apps/console-api/src/modules/governance/governance-repository.service';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import type {WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';

const dockerEnv={...process.env,GOMAXPROCS:'2'};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete (dockerEnv as any)[key];
const docker=(args:string[])=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env:dockerEnv,encoding:'utf8',stdio:['pipe','pipe','pipe']});
const name='kongpilot-m10-storage-'+randomUUID().slice(0,8),checks:Array<{name:string;passed:boolean;code?:string}>=[];
const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(error:any){checks.push({name,passed:false,code:error.code??'ASSERTION_FAILED'});throw error;}};
const rejected=async(fn:()=>Promise<unknown>,code:string)=>{let failure:any;try{await fn();}catch(error){failure=error;}assert(failure,'Expected SQL rejection');assert.equal(failure.code,code);};
let owner:DbService|undefined,runtime:DbService|undefined,passed=false,started=false;
async function main(){try{
 docker(['run','-d','--pull=never','--name',name,'--label','kongpilot.test=m10-storage','--memory','512m','--pids-limit','128','--tmpfs','/var/lib/postgresql/data:rw,size=201326592','-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine']);started=true;
 const port=docker(['port',name,'5432']).trim().split(':').at(-1);
 process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;process.env.CONSOLE_ENCRYPTION_KEY='6d'.repeat(32);process.env.BOOTSTRAP_ADMIN_USERNAME='m10-storage-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!M10Storage2026';
 owner=new DbService();for(let attempt=0;attempt<100;attempt++){try{await owner.one('SELECT 1');break;}catch{if(attempt===99)throw new Error('SQL_READINESS_FAILED');await new Promise(resolve=>setTimeout(resolve,100));}}
 await check('all shipped SQL through M10 initializes and repeat migration retains exact source checksums',async()=>{
  const expected=readdirSync('apps/console-api/src/infrastructure/migrations').filter(file=>file.endsWith('.sql')).sort();assert(expected.includes('017_m10_governance.sql'));
  await owner!.migrateAndSeed();const rows=await owner!.query<any>('SELECT * FROM schema_migrations ORDER BY name');assert.deepEqual(rows.map(row=>row.name),expected);
  for(const row of rows)assert.equal(row.checksum,createHash('sha256').update(readFileSync('apps/console-api/src/infrastructure/migrations/'+row.name)).digest('hex'));
  await owner!.migrateAndSeed();assert.deepEqual(await owner!.query('SELECT * FROM schema_migrations ORDER BY name'),rows);
 });
 process.env.CONSOLE_DB_RUNTIME_USER='m10_runtime';process.env.CONSOLE_DB_RUNTIME_PASSWORD='Synthetic!M10Runtime2026';await provisionRuntimeRole(owner);
 process.env.DATABASE_URL=`postgres://m10_runtime@127.0.0.1:${port}/postgres`;runtime=new DbService();const db=runtime,secrets=new SecretService(),repo=new GovernanceRepositoryService(db,secrets);
 await check('runtime starts using only checksum validation and existing administrator, without migration-owner DDL',async()=>{process.env.SKIP_MIGRATIONS='true';try{await db.onModuleInit();}finally{delete process.env.SKIP_MIGRATIONS;}});
 const actor=(await db.one<any>('SELECT id FROM users LIMIT 1'))!.id,otherActor=randomUUID(),sid=randomUUID(),cid=randomUUID(),wid=randomUUID(),otherWid=randomUUID(),targetCid=randomUUID(),targetWid=randomUUID(),physical=transportScopeFor('http://synthetic-source:8001');
 await db.exec("INSERT INTO users(id,username,password_hash,status) VALUES($1,'m10-storage-other',$2,'active')",[otherActor,'$2b$12$'+'a'.repeat(53)]);
 await db.exec("INSERT INTO auth_sessions(id,user_id,expires_at) VALUES($1,$2,now()+interval '1 hour')",[sid,actor]);
 await db.exec("INSERT INTO clusters(id,name,admin_url,execution_mode,version,status,transport_scope) VALUES($1,'M10 source','http://synthetic-source:8001','direct','1.5.1','healthy',$2),($3,'M10 target','http://synthetic-target:8001','direct','1.5.1','healthy',$4)",[cid,physical,targetCid,transportScopeFor('http://synthetic-target:8001')]);
 await db.exec("INSERT INTO workspaces(id,cluster_id,code,name,status) VALUES($1,$2,'m10','M10','active'),($3,$2,'m10-other','M10 other','active'),($4,$5,'m10-target','M10 target','active')",[wid,cid,otherWid,targetWid,targetCid]);
 const ruleId=randomUUID(),scheduleId=randomUUID(),rule={code:'synthetic-owner',name:'Owner rule',description:'Synthetic typed rule',severity:'warn',given:{collection:'services'},then:{predicate:'required',path:'name'},enabled:true};
 await check('rule root and current immutable version are saved by exact repository transaction',async()=>{await db.transaction(tx=>repo.saveResource('governance_rules',ruleId,cid,wid,actor,'create',null,rule,physical,tx));const row=await repo.resource('governance_rules',ruleId,cid,wid);assert.equal(row.current_version,1);assert.deepEqual(row.content,rule);});
 await check('rule current-version deferred FK rejects absent version and a foreign tenant',async()=>{
  await rejected(()=>db.exec("INSERT INTO governance_rules(id,cluster_id,workspace_id,code,name,owner_user_id) VALUES($1,$2,$3,'missing-version','Missing',$4)",[randomUUID(),cid,wid,actor]),'23503');
  await rejected(()=>db.exec("INSERT INTO governance_rules(id,cluster_id,workspace_id,code,name,owner_user_id) VALUES($1,$2,$3,'foreign-scope','Foreign',$4)",[randomUUID(),targetCid,wid,actor]),'23503');
 });
 await check('accepted 96-character rule code boundary is consistent between DTO and durable policy identity',async()=>{
  const id=randomUUID(),content={...rule,code:'r'+'a'.repeat(95)};await db.transaction(tx=>repo.saveResource('governance_rules',id,cid,wid,actor,'create',null,content,physical,tx));assert.equal((await repo.resource('governance_rules',id,cid,wid)).code.length,96);
 });
 await check('root identity and owner cannot change, even under migration-owner role',async()=>{await rejected(()=>owner!.exec('UPDATE governance_rules SET owner_user_id=$2,revision=revision+1 WHERE id=$1',[ruleId,otherActor]),'23514');await rejected(()=>owner!.exec('DELETE FROM governance_rules WHERE id=$1',[ruleId]),'23514');});
 await check('archive and restore use new immutable versions with revision CAS, never physical deletion',async()=>{
  let before=await repo.resource('governance_rules',ruleId,cid,wid);await db.transaction(tx=>repo.saveResource('governance_rules',ruleId,cid,wid,actor,'archive',before,{revision:before.revision},physical,tx));
  before=await repo.resource('governance_rules',ruleId,cid,wid);assert.equal(before.state,'deleted');assert.equal(before.current_version,2);assert.equal(before.revision,2);
  await db.transaction(tx=>repo.saveResource('governance_rules',ruleId,cid,wid,actor,'restore',before,{revision:before.revision},physical,tx));assert.equal((await repo.resource('governance_rules',ruleId,cid,wid)).current_version,3);
  assert.equal(await db.exec('UPDATE governance_rules SET revision=revision+1 WHERE id=$1 AND revision=1',[ruleId]),0);
 });
 const inventory={id:randomUUID(),scope:{clusterId:cid,workspaceId:wid,kind:'workspace',rootIds:[],transportScope:physical},objects:[],projection:false,completeness:'complete',coverage:{},reasonCodes:[],observedFrom:new Date().toISOString(),observedUntil:new Date().toISOString()},reportId=randomUUID(),findingId=randomUUID(),nativeId=randomUUID();
 const findings=[{id:findingId,ruleCode:'synthetic-owner',severity:'warn',entityType:'services',nativeId,objectWorkspaceId:otherWid,fieldPath:'/tags',reasonCode:'OWNER_REQUIRED',description:'Synthetic owner finding',safeEvidence:{status:'confirmed'},fixActions:['owner_tag_add']}];
 let run:any;
 await check('inspection run, full ordered findings, immutable report and terminal receipt commit atomically',async()=>{
  await db.transaction(async tx=>{run=(await repo.beginRun({clusterId:cid,workspaceId:wid,actorId:actor,sessionId:sid,origin:'http',key:randomUUID(),kind:'inspection',request:{}},tx)).row;
   await repo.saveReport({id:reportId,run,inventory,result:{complete:true,ruleResults:[],reasonCodes:[]},rulesHmac:secrets.fingerprint([]),engineVersion:'m10-synthetic-test',findings},tx);await repo.finishRun(run.id,'succeeded',undefined,tx);});
  assert.equal((await repo.report(reportId,cid,wid)).finding_count,1);assert.deepEqual(repo.inventory(await repo.report(reportId,cid,wid)),inventory);
 });
 await check('missing or excess findings cannot seal a complete report, nor can successful run omit evidence',async()=>{
  await rejected(()=>db.transaction(async tx=>{const r=(await repo.beginRun({clusterId:cid,workspaceId:wid,actorId:actor,sessionId:sid,origin:'http',key:randomUUID(),kind:'inspection',request:{}},tx)).row;await repo.finishRun(r.id,'succeeded',undefined,tx);}),'23514');
  await rejected(()=>db.transaction(async tx=>{const r=(await repo.beginRun({clusterId:cid,workspaceId:wid,actorId:actor,sessionId:sid,origin:'http',key:randomUUID(),kind:'inspection',request:{}},tx)).row;await tx.exec(`INSERT INTO governance_reports(id,cluster_id,workspace_id,run_id,inventory_secret,inventory_hmac,engine_version,rules_hmac,quality,projection,object_count,finding_count,counts,coverage,rule_results,observed_from,observed_until) VALUES($1,$2,$3,$4,$5,$6,'synthetic',$6,'complete',false,0,1,'{"error":0,"warn":1,"info":0}','{}','[]',now(),now())`,[randomUUID(),cid,wid,r.id,secrets.encrypt({}),secrets.fingerprint({})]);await repo.finishRun(r.id,'succeeded',undefined,tx);}),'23514');
  await rejected(()=>db.exec(`INSERT INTO governance_findings(id,cluster_id,workspace_id,report_id,finding_order,rule_code,severity,entity_type,native_id,field_path,reason_code,description,safe_evidence,fix_actions) VALUES($1,$2,$3,$4,2,'synthetic','warn','services',$5,'/tags','OWNER','Extra','{}','[]')`,[randomUUID(),cid,wid,reportId,nativeId]),'23514');
 });
 await check('foreign report/finding tenant references and origin-session impersonation are rejected',async()=>{
  await rejected(()=>db.exec(`INSERT INTO governance_findings(id,cluster_id,workspace_id,report_id,finding_order,rule_code,severity,entity_type,native_id,field_path,reason_code,description,safe_evidence,fix_actions) VALUES($1,$2,$3,$4,2,'synthetic','warn','services',$5,'/tags','OWNER','Foreign','{}','[]')`,[randomUUID(),cid,otherWid,reportId,nativeId]),'23503');
  await rejected(()=>repo.beginRun({clusterId:cid,workspaceId:wid,actorId:otherActor,sessionId:sid,origin:'http',key:randomUUID(),kind:'inspection',request:{}}),'23503');
 });
 await check('same actor key cannot silently create a different analysis or different workspace',async()=>{await assert.rejects(()=>repo.beginRun({clusterId:cid,workspaceId:otherWid,actorId:actor,sessionId:sid,origin:'http',key:run.idempotency_key,kind:'inspection',request:{}}),(error:any)=>error.getResponse?.().code==='IDEMPOTENCY_CONFLICT');const original=await repo.runByKey(actor,run.idempotency_key);assert.equal(original.id,run.id);});
 await check('every immutable governance and origin table denies runtime update delete truncate',async()=>{
  for(const table of ['governance_rule_versions','governance_schedule_versions','governance_reports','governance_findings','governance_comparisons','governance_fix_links','governance_metadata_requests','configuration_job_origin_bindings','configuration_plan_origin_bindings','promotion_recovery_bindings'])for(const verb of ['DELETE FROM','TRUNCATE'])await rejected(()=>db.exec(`${verb} ${table}`),'42501');
  await rejected(()=>db.exec('UPDATE governance_reports SET finding_count=0 WHERE id=$1',[reportId]),'42501');await rejected(()=>owner!.exec('UPDATE governance_reports SET finding_count=0 WHERE id=$1',[reportId]),'23514');
 });
 await check('actual schedule root/version and due occurrence claim advance revision without rewriting immutable policy',async()=>{
  await db.transaction(tx=>repo.saveResource('governance_schedules',scheduleId,cid,wid,actor,'create',null,{name:'Synthetic inspection',kind:'inspection',scope:'workspace',intervalMinutes:5,timezone:'UTC'},physical,tx));
  await db.exec("UPDATE governance_schedules SET next_run_at=now()-interval '1 minute',revision=revision+1 WHERE id=$1",[scheduleId]);
  const row=(await repo.dueSchedules()).find(r=>r.id===scheduleId),claim=await db.transaction(tx=>repo.claimSchedule(row,tx));assert(claim);assert.equal(claim.locator.revision,row.revision+1);assert.equal(claim.locator.version,1);
  await db.transaction(async tx=>{const reg=await repo.beginRun({clusterId:cid,workspaceId:wid,actorId:actor,origin:'schedule',scheduleRunId:claim.locator.runId,key:randomUUID(),kind:'inspection',request:{}},tx),id=randomUUID();await repo.saveReport({id,run:reg.row,inventory,result:{complete:true},rulesHmac:secrets.fingerprint([]),engineVersion:'synthetic',findings:[]},tx);await repo.finishRun(reg.row.id,'succeeded',undefined,tx);await repo.finishSchedule(claim.locator,'succeeded',reg.row.id,undefined,tx);});
  await rejected(()=>owner!.exec('UPDATE governance_schedule_runs SET creator_id=$2 WHERE id=$1',[claim.locator.runId,otherActor]),'23514');
  await rejected(()=>owner!.exec("UPDATE governance_schedule_runs SET state='running',completed_at=NULL WHERE id=$1",[claim.locator.runId]),'23514');
 });
 await check('stale running or uncertain occurrence blocks later timer claims across immutable policy versions',async()=>{
  const id=randomUUID(),occurrence=randomUUID(),content={name:'Synthetic stale timer',kind:'inspection',scope:'workspace',intervalMinutes:5,timezone:'UTC'};
  await db.transaction(tx=>repo.saveResource('governance_schedules',id,cid,wid,actor,'create',null,content,physical,tx));
  await db.exec(`INSERT INTO governance_schedule_runs(id,cluster_id,workspace_id,schedule_id,schedule_version,scheduled_at,creator_id,lease_generation,lease_until,state,created_at) VALUES($1,$2,$3,$4,1,now()-interval '10 minutes',$5,1,now()-interval '5 minutes','running',now()-interval '10 minutes')`,[occurrence,cid,wid,id,actor]);
  const before=await repo.resource('governance_schedules',id,cid,wid);await db.transaction(tx=>repo.saveResource('governance_schedules',id,cid,wid,actor,'update',before,{revision:before.revision,name:'Updated stale timer'},physical,tx));
  await db.exec("UPDATE governance_schedules SET next_run_at=now()-interval '1 minute',revision=revision+1 WHERE id=$1",[id]);
  assert(!(await repo.dueSchedules()).some(row=>row.id===id));const root=await repo.resource('governance_schedules',id,cid,wid);assert.equal(await db.transaction(tx=>repo.claimSchedule(root,tx)),null);
  const expired=(await repo.expiredScheduleRuns()).find(row=>row.id===occurrence);assert(expired);assert.equal(await db.transaction(tx=>repo.markExpiredScheduleRun({...expired,lease_generation:2},tx)),false);assert.equal(await db.transaction(tx=>repo.markExpiredScheduleRun(expired,tx)),true);
  assert.equal((await repo.scheduleExecutionStatus(id,2)).blockingState,'uncertain');assert.equal(await db.transaction(tx=>repo.claimSchedule(root,tx)),null);assert.equal((await db.one<any>('SELECT count(*)::int AS count FROM governance_schedule_runs WHERE schedule_id=$1',[id]))!.count,1);
 });
 await check('paused-authority policy needs an explicit new version and cannot be resumed by a mere due-time update',async()=>{
  const id=randomUUID(),occurrence=randomUUID(),content={name:'Synthetic paused timer',kind:'inspection',scope:'workspace',intervalMinutes:5,timezone:'UTC'};
  await db.transaction(tx=>repo.saveResource('governance_schedules',id,cid,wid,actor,'create',null,content,physical,tx));
  await db.exec(`INSERT INTO governance_schedule_runs(id,cluster_id,workspace_id,schedule_id,schedule_version,scheduled_at,creator_id,lease_generation,lease_until,state,created_at,completed_at) VALUES($1,$2,$3,$4,1,now()-interval '10 minutes',$5,1,now()-interval '5 minutes','paused_authority',now()-interval '10 minutes',now()-interval '9 minutes')`,[occurrence,cid,wid,id,actor]);
  await db.exec("UPDATE governance_schedules SET next_run_at=now()-interval '1 minute',revision=revision+1 WHERE id=$1",[id]);let root=await repo.resource('governance_schedules',id,cid,wid);assert.equal(await db.transaction(tx=>repo.claimSchedule(root,tx)),null);
  await db.transaction(tx=>repo.saveResource('governance_schedules',id,cid,wid,actor,'update',root,{revision:root.revision,name:'Explicit new paused policy'},physical,tx));await db.exec("UPDATE governance_schedules SET next_run_at=now()-interval '1 minute',revision=revision+1 WHERE id=$1",[id]);root=await repo.resource('governance_schedules',id,cid,wid);
  assert.equal((await repo.scheduleExecutionStatus(id,2)).executionBlocked,false);const claim=await db.transaction(tx=>repo.claimSchedule(root,tx));assert(claim);assert.equal(claim.locator.version,2);await db.transaction(tx=>repo.finishSchedule(claim.locator,'failed',undefined,new Error('synthetic fixture only'),tx));
 });
 const comparisonId=randomUUID(),targetInventory={...inventory,id:randomUUID(),scope:{...inventory.scope,clusterId:targetCid,workspaceId:targetWid,transportScope:transportScopeFor('http://synthetic-target:8001')}};
 await check('actual dual-environment comparison preserves both inventory identities and cannot claim threshold from incomplete evidence',async()=>{
  await db.transaction(async tx=>{const reg=await repo.beginRun({clusterId:cid,workspaceId:wid,actorId:actor,sessionId:sid,origin:'http',key:randomUUID(),kind:'comparison',request:{}},tx);await repo.saveComparison({id:comparisonId,run:reg.row,source:inventory,target:targetInventory,policy:{},result:{completeness:'complete',counts:{added:0,modified:0,removed:0,unchanged:0},threshold:{exceeded:false},changes:[]},threshold:0},tx);await repo.finishRun(reg.row.id,'succeeded',undefined,tx);});
  const pair=repo.comparisonInventories(await repo.comparison(comparisonId,cid,wid));assert.equal(pair.target.scope.clusterId,targetCid);assert.equal(pair.source.scope.clusterId,cid);
  await rejected(()=>db.transaction(async tx=>{const reg=await repo.beginRun({clusterId:cid,workspaceId:wid,actorId:actor,sessionId:sid,origin:'http',key:randomUUID(),kind:'comparison',request:{}},tx);await repo.saveComparison({id:randomUUID(),run:reg.row,source:inventory,target:targetInventory,policy:{},result:{completeness:'incomplete',counts:{},threshold:{exceeded:true},changes:[]},threshold:0},tx);await repo.finishRun(reg.row.id,'incomplete',undefined,tx);}),'23514');
 });
 const fixId=randomUUID(),fixKey=randomUUID(),iamId=randomUUID(),childKey=`governance-fix-${fixId}`;
 await check('fix parent freezes original report anchor separately from actual target workspace and child key',async()=>{
  await db.exec(`INSERT INTO governance_fix_requests(id,cluster_id,workspace_id,target_workspace_id,report_id,finding_id,actor_id,idempotency_key,request_hmac,input_secret) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[fixId,cid,wid,otherWid,reportId,findingId,actor,fixKey,secrets.fingerprint({}),secrets.encrypt({})]);
  await db.exec("UPDATE governance_fix_requests SET child_kind='metadata',child_request_hmac=$2,child_request_secret=$3 WHERE id=$1",[fixId,secrets.fingerprint({}),secrets.encrypt({domain:'metadata'})]);
  await db.exec(`INSERT INTO iam_operations(id,actor_id,idempotency_key,request_hash,module,action,target_id,cluster_id,workspace_id,state,remote_completed,payload_secret) VALUES($1,$2,$3,$4,'annotations','write',$5,$6,$7,'succeeded',true,$8)`,[iamId,actor,childKey,secrets.fingerprint({}),nativeId,cid,otherWid,secrets.encrypt({})]);
  await db.transaction(async tx=>{await tx.exec("UPDATE governance_fix_requests SET state='ready',metadata_domain='iam',metadata_operation_id=$2 WHERE id=$1",[fixId,iamId]);await tx.exec(`INSERT INTO governance_fix_links(id,cluster_id,workspace_id,target_workspace_id,report_id,finding_id,actor_id,idempotency_key,request_hmac,metadata_domain,metadata_operation_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'iam',$10)`,[randomUUID(),cid,wid,otherWid,reportId,findingId,actor,fixKey,secrets.fingerprint({}),iamId]);});
  assert.equal((await db.one<any>('SELECT target_workspace_id FROM governance_fix_requests WHERE id=$1',[fixId]))!.target_workspace_id,otherWid);
 });
 await check('fix child substitution, original input mutation and terminal replay fail at storage boundary',async()=>{
  await rejected(()=>owner!.exec('UPDATE governance_fix_requests SET input_secret=$2 WHERE id=$1',[fixId,secrets.encrypt({changed:true})]),'23514');await rejected(()=>owner!.exec("UPDATE governance_fix_requests SET state='planning' WHERE id=$1",[fixId]),'23514');
  const bad=randomUUID();await rejected(()=>db.transaction(async tx=>{await tx.exec(`INSERT INTO governance_fix_requests(id,cluster_id,workspace_id,target_workspace_id,report_id,finding_id,actor_id,idempotency_key,request_hmac,input_secret,child_kind,child_request_hmac,child_request_secret) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'metadata',$9,$10)`,[bad,cid,wid,otherWid,reportId,findingId,actor,randomUUID(),secrets.fingerprint({}),secrets.encrypt({})]);await tx.exec("UPDATE governance_fix_requests SET state='ready',metadata_domain='iam',metadata_operation_id=$2 WHERE id=$1",[bad,iamId]);}),'23503');
  await rejected(()=>owner!.exec('UPDATE governance_fix_requests SET child_request_hmac=$2 WHERE id=$1',[fixId,secrets.fingerprint({other:true})]),'23514');
  await rejected(()=>db.exec(`INSERT INTO governance_fix_requests(id,cluster_id,workspace_id,target_workspace_id,report_id,finding_id,actor_id,idempotency_key,request_hmac,input_secret) VALUES($1,$2,$3,$3,$4,$5,$6,$7,$8,$9)`,[randomUUID(),cid,wid,reportId,findingId,actor,randomUUID(),secrets.fingerprint({}),secrets.encrypt({})]),'23503');
 });
 await check('known child receipt may settle uncertain fix by SQL only, while immutable child descriptor and actual target stay fixed',async()=>{
  const id=randomUUID(),key=randomUUID(),child=randomUUID(),descriptor={domain:'metadata',requestHmac:secrets.fingerprint({})};
  await db.exec(`INSERT INTO governance_fix_requests(id,cluster_id,workspace_id,target_workspace_id,report_id,finding_id,actor_id,idempotency_key,request_hmac,input_secret) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[id,cid,wid,otherWid,reportId,findingId,actor,key,secrets.fingerprint({}),secrets.encrypt({})]);
  await db.transaction(tx=>repo.bindFixChild(id,'metadata',descriptor,tx));await db.exec("UPDATE governance_fix_requests SET state='uncertain',error_code='SYNTHETIC_METADATA_PENDING' WHERE id=$1",[id]);
  await db.exec(`INSERT INTO iam_operations(id,actor_id,idempotency_key,request_hash,module,action,target_id,cluster_id,workspace_id,state,remote_completed,payload_secret) VALUES($1,$2,$3,$4,'annotations','write',$5,$6,$7,'succeeded',true,$8)`,[child,actor,`governance-fix-${id}`,secrets.fingerprint({}),nativeId,cid,otherWid,secrets.encrypt({})]);
  const row=await db.one<any>('SELECT * FROM governance_fix_requests WHERE id=$1',[id]);await db.transaction(tx=>repo.completeFix(row,{metadataOperationId:child,metadataDomain:'iam'},tx));
  assert.equal((await db.one<any>('SELECT state FROM governance_fix_requests WHERE id=$1',[id]))!.state,'ready');
  await rejected(()=>owner!.exec('UPDATE governance_fix_requests SET target_workspace_id=$2 WHERE id=$1',[id,wid]),'23514');
 });
 await check('workflow fixed metadata intent commits with real plan repository, exact owner and no native packets',async()=>{
  const workflows=new WorkflowPlansService(db,secrets,{append:async()=>({})} as any);workflows.installGovernanceMetadataDelegate({verifyIntent:async()=>{},assertSubject:async()=>{},verifyReviewer:async()=>{}});
  const wfId=randomUUID(),intentId=randomUUID(),resourceId=randomUUID(),key=randomUUID(),request={resourceType:'governance_rules',operation:'create',resourceId},payload={...rule},metadata={intentId,resourceType:'governance_rules',resourceId,operation:'create',payloadHmac:secrets.fingerprint(payload)};
  await db.transaction(async tx=>{await workflows.definitions(cid,wid,actor,tx);const definition=await workflows.definition(cid,wid,'governance-metadata',tx);
   await repo.insertIntent({id:intentId,clusterId:cid,workspaceId:wid,actorId:actor,resourceType:'governance_rules',resourceId,operation:'create',idempotencyKey:key,requestHmac:secrets.fingerprint(request),payload,before:null,scope:{clusterId:cid,workspaceId:wid,transportScope:physical,clusterRevision:1,workspaceRevision:1,executionMode:'approval',permissionVersion:'synthetic-epoch'},workflowId:wfId},tx);
   const plan:WorkflowPlanV1={version:1,kind:'governance-metadata',clusterId:cid,workspaceId:wid,workflowId:wfId,planRevision:1,executionMode:'approval',approvalRequired:true,subject:{type:'governance_metadata_requests',id:intentId},requester:{type:'console',id:actor},definition,issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+600000).toISOString(),scope:{transportScope:physical,clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[{id:randomUUID(),key:'governance.metadata',order:1,kind:'metadata',handler:'governance.metadata',entityType:'governance_metadata_requests',entityId:intentId,permissionAction:'write',dependencies:[],nativeRequests:[],before:null,metadataRevision:0,metadataBeforeHmac:secrets.fingerprint(null),metadata,metadataPayloadHmac:secrets.fingerprint(metadata)}]};
   await workflows.persist(plan,key,request,tx,{requestId:randomUUID(),ip:'127.0.0.1'});
  });
  assert.equal((await db.one<any>('SELECT native_request_count FROM workflow_versions WHERE workflow_id=$1',[wfId]))!.native_request_count,0);
  await rejected(()=>owner!.exec("UPDATE workflow_steps SET handler='configuration_v2' WHERE workflow_id=$1",[wfId]),'23514');
 });
 passed=true;
}catch(error:any){process.stderr.write(JSON.stringify({event:'m10.storage.failed',code:error.code??'ASSERTION_FAILED',constraint:error.constraint??null,message:String(error.message??'').slice(0,250).replace(/postgres(?:ql)?:\/\/[^\s]+/g,'[REDACTED_CONNECTION]')})+'\n');}
finally{await runtime?.onModuleDestroy();await owner?.onModuleDestroy();if(started)docker(['rm','-f',name]);mkdirSync('artifacts/M10',{recursive:true});writeFileSync('artifacts/M10/storage-verification.json',JSON.stringify({passed,environment:'isolated-postgresql16-tmpfs',nativeKongRequests:false,productionDeploymentChanged:false,checks},null,2)+'\n');process.stdout.write(JSON.stringify({passed,checks:checks.length})+'\n');if(!passed)process.exitCode=1;}}
void main();
