import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {AuditService} from '../../apps/console-api/src/modules/audit/audit.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {PortalNativeService} from '../../apps/console-api/src/modules/portal/portal-native.service';
import {PortalAdminService} from '../../apps/console-api/src/modules/portal/portal-admin.service';
import {PortalDocumentService} from '../../apps/console-api/src/modules/portal/portal-document.service';
import {publicationRetryProof} from '../../apps/console-api/src/modules/portal/portal-publication-recovery';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import {WorkflowService} from '../../apps/console-api/src/modules/workflows/workflow.service';
import {snapshotAad,type WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';
import type {EntityActor} from '../../apps/console-api/src/modules/entities/entities.types';

/** Real SQL/schema/plan/service test. Gateway, current authorization and HTTP
 * capability frames are explicit fakes; it makes no native network requests. */
async function main():Promise<void>{
 const container=`kongos-m6-recovery-${randomUUID().slice(0,8)}`;
 const runId=new Date().toISOString().replace(/[:.]/g,'-');
 const checks:Array<{name:string;passed:boolean;errorCode?:string}>=[];
 let db:DbService|undefined,wireWrites=0;
 const safeCode=(error:any)=>String(error?.code??error?.getResponse?.()?.code??'ASSERTION_FAILED').replace(/[^A-Z0-9_]/gi,'_').slice(0,128);
 const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(error){checks.push({name,passed:false,errorCode:safeCode(error)});throw error;}};
 const rejected=async(fn:()=>Promise<unknown>,code?:string)=>{try{await fn();}catch(error:any){if(code)assert.equal(error?.getResponse?.()?.code??error?.code,code);return;}throw new Error('EXPECTED_REJECTION');};
 try{
  execFileSync('docker',['run','-d','--name',container,'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine'],{stdio:'ignore'});
  const port=execFileSync('docker',['port',container,'5432'],{encoding:'utf8'}).trim().split(':').pop();
  process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;
  process.env.CONSOLE_ENCRYPTION_KEY='e7'.repeat(32);
  process.env.APP_SECRET='SyntheticPublicationRecoverySigningKey2026!';
  process.env.BOOTSTRAP_ADMIN_USERNAME='recovery-bootstrap';
  process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!Recovery2026Password';
  db=new DbService();
  for(let n=0;n<80;n++){try{await db.one('SELECT 1');break;}catch{if(n===79)throw new Error('ISOLATED_DATABASE_UNAVAILABLE');await new Promise(resolve=>setTimeout(resolve,100));}}
  await db.migrateAndSeed();
  const sql=db,secrets=new SecretService(),audit=new AuditService(sql,secrets,new AuditOutboxWriter(sql,secrets)),resolver=new WorkspaceResolverService(sql),plans=new WorkflowPlansService(sql,secrets,audit),registry=new WorkflowRegistryService();
  const user=(await sql.one<any>('SELECT id,username FROM users WHERE super_admin'))!,approver=randomUUID(),cid=randomUUID(),wid=randomUUID(),transport='c'.repeat(64);
  await sql.exec("INSERT INTO users(id,username,password_hash) VALUES($1,'recovery-approver',$2)",[approver,`$2b$12$${'a'.repeat(53)}`]);
  await sql.exec("INSERT INTO clusters(id,name,admin_url,transport_scope,execution_mode,version,status) VALUES($1,'isolated-recovery','http://recovery-fixture.invalid:8001',$2,'approval','1.5.1','healthy')",[cid,transport]);
  await sql.exec("INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,'pay','Recovery pay')",[wid,cid]);
  await sql.transaction(tx=>plans.definitions(cid,wid,user.id,tx));
  const services=new Map<string,any>();
  const context:any={runActor:async(_input:any,fn:()=>Promise<any>)=>fn(),runInternalRead:async(_cid:string,_purpose:string,fn:()=>Promise<any>)=>fn()};
  const authz:any={assertCluster:async()=>{},assertWholeWorkspace:async()=>{},assertScopedResource:async()=>{},assertEntity:async()=>{},permissionVersion:async()=> 'isolated-authorization-epoch'};
  const kong:any={transportScope:async()=>transport,request:async(_cid:string,method:string,path:string)=>{
   if(method!=='GET'){wireWrites++;throw new Error('NATIVE_NETWORK_FORBIDDEN');}
   if(path.startsWith('/services/'))return structuredClone(services.get(path.split('/')[2]));
   if(path==='/plugins')return{data:[],next:null};
   if(path.startsWith('/schemas/'))return{fields:[]};
   throw new Error('UNEXPECTED_SYNTHETIC_READ');
  }};
  const native=new PortalNativeService(sql,secrets,kong,context,authz,resolver),approved:any={assertSubject:async()=>{}},redis:any={},iam:any={completed:async()=>null};
  const workflow=new WorkflowService(sql,redis,secrets,kong,context,authz,audit,{}as any,{}as any,iam,resolver,plans,registry,approved);
  const admin=new PortalAdminService(sql,secrets,authz,audit,iam,{}as any,resolver,approved,plans,registry,workflow,native,new PortalDocumentService(secrets));admin.onModuleInit();
  const actor:EntityActor={user:{id:user.id,username:user.username,superAdmin:true},workspaceId:wid,requestId:randomUUID(),ip:'192.0.2.17'};
  interface Fixture{publication:any;plan:WorkflowPlanV1;hash:string;executionId:string;key:string;}
  const fixture=async(approval=false):Promise<Fixture>=>{
   const id=randomUUID(),serviceId=randomUUID(),workflowId=randomUUID(),executionId=randomUUID(),key=`original-${workflowId}`;
   const service={id:serviceId,name:`recovery-${serviceId}`,protocol:'http',host:'echo.fixture.invalid',port:8080,tags:['kos-ws-pay']};services.set(serviceId,service);
   let plan!:WorkflowPlanV1,hash='';
   await sql.transaction(async tx=>{
    await tx.exec("INSERT INTO portal_publications(id,cluster_id,workspace_id,transport_scope,slug,name,service_id,acl_group,created_by,updated_by) VALUES($1,$2,$3,$4,$5,'Recovery publication',$6,$7,$8,$8)",[id,cid,wid,transport,`api-${id}`,serviceId,`kos-portal-api-${id}`,user.id]);
    await tx.exec("INSERT INTO portal_publication_revisions(cluster_id,workspace_id,publication_id,revision,service_id,title,version_label,openapi_document,document_hash,created_by) VALUES($1,$2,$3,1,$4,'Recovery API','1.0',$5::jsonb,$6,$7)",[cid,wid,id,serviceId,JSON.stringify({openapi:'3.0.3',info:{title:'Recovery',version:'1.0'},paths:{}}),secrets.fingerprint({document:true}),user.id]);
    await tx.exec("UPDATE portal_publications SET state='pending',workflow_id=$2,revision=revision+1 WHERE id=$1",[id,workflowId]);
    const before=await tx.one<any>('SELECT * FROM portal_publications WHERE id=$1',[id]);
    const first=native.nativeStep(1,'plugins','create',{id:randomUUID(),name:'acl',service:{id:serviceId},config:{whitelist:[before.acl_group]},tags:['kos-ws-pay']},null,{workflowId});
    const second=native.nativeStep(2,'plugins','create',{id:randomUUID(),name:'key-auth',service:{id:serviceId},config:{key_names:['apikey']},tags:['kos-ws-pay']},null,{workflowId,dependencies:[first.id]});
    const third=native.metadataStep(3,'portal.publication.publish','portal_publications',id,before,{publicationRevision:1,service,aclGroup:before.acl_group,aclPluginId:first.nativeRequests[0].nativeId,keyAuthPluginId:second.nativeRequests[0].nativeId,schemas:{consumers:{},acls:{},keyAuth:{}},definitions:{}},[second.id]);
    plan={version:1,clusterId:cid,workspaceId:wid,workflowId,planRevision:1,kind:'portal-publication',executionMode:approval?'approval':'direct',approvalRequired:approval,subject:{type:'portal_publications',id},requester:{type:'console',id:user.id},definition:await plans.definition(cid,wid,'portal-publication',tx),issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString(),scope:{transportScope:transport,clusterRevision:1,workspaceRevision:1},prerequisites:[{type:'services',id:serviceId,path:`/services/${serviceId}`,fingerprint:secrets.fingerprint(service),before:service}],steps:[first,second,third]};
    const row=await plans.persist(plan,key,{publicationId:id,revision:1,publish:true},tx,{requestId:randomUUID(),ip:'192.0.2.17'});hash=row.plan_hash;
    if(approval){await tx.exec("INSERT INTO workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,approver_id,decision,idempotency_key) VALUES($1,$2,$3,1,$4,1,$5,'approve',$6)",[cid,wid,workflowId,hash,approver,`approval-${workflowId}`]);await tx.exec("UPDATE workflows SET approved_by=$2,approved_at=now() WHERE id=$1",[workflowId,approver]);}
    const snapshot={version:1,workflowId,executionId,clusterId:cid,workspaceId:wid,planRevision:1,planHash:hash,capturedAt:new Date().toISOString(),objects:[]};
    await tx.exec(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,snapshot_state,snapshot_secret,snapshot_hash,claim_token_hash,idempotency_key,expires_at,completed_at)
      VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,'failed','ready',$10,$11,$12,$13,now()+interval '30 minutes',now())`,[executionId,cid,wid,workflowId,hash,plan.executionMode,approval,approval?approver:null,approver,secrets.encrypt(snapshot,snapshotAad(cid,wid,workflowId,executionId)),secrets.fingerprint(snapshot),secrets.fingerprint({claim:executionId}),`execute-${executionId}`]);
    await tx.exec("UPDATE workflows SET state='failed',revision=revision+1 WHERE id=$1",[workflowId]);
   });
   return{publication:await sql.one<any>('SELECT * FROM portal_publications WHERE id=$1',[id]),plan,hash,executionId,key};
  };
  const proof=(f:Fixture)=>publicationRetryProof(sql,secrets,cid,wid,f.publication);
  const failedOperation=async(f:Fixture,options:{state?:string;completed?:boolean;wrongHash?:boolean}={})=>{
   const expected=f.plan.steps[0],id=randomUUID(),binding=f.plan.approvalRequired?{workflowId:f.plan.workflowId,executionId:f.executionId,planRevision:1,planHash:f.hash,stepId:expected.id,beforeHmac:expected.beforeFingerprint}:null;
   const requestHash=secrets.fingerprint({actor:approver,clusterId:cid,workspaceId:wid,entityType:expected.entityType,entityId:null,action:expected.mutationAction,payload:expected.mutationPayload,parentId:null,credentialKind:null,...(binding?{approvedWorkflow:binding}:{})});
   await sql.transaction(async tx=>{
    await tx.exec(`INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,transport_scope,entity_type,entity_id,before_secret,payload_secret,remote_started,remote_completed,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id)
     VALUES($1,$2,$3,$4,'create',$5,$6,$7,$8,'plugins',$9,$10,$11,true,$12,$13,$14,$15,$16,$17)`,[id,cid,wid,approver,expected.mutationIdempotencyKey,options.wrongHash?'d'.repeat(64):requestHash,options.state??'failed',transport,(expected.mutationPayload as any).id,secrets.encrypt(null,`mutation:${id}:before`),secrets.encrypt(expected.mutationPayload,`mutation:${id}:payload`),options.completed??false,binding?.workflowId??null,binding?.executionId??null,binding?.planRevision??null,binding?.planHash??null,binding?.stepId??null]);
    await tx.exec("UPDATE workflow_steps SET state='failed',operation_id=$2,safe_result=$3::jsonb,started_at=now(),completed_at=now(),revision=revision+1 WHERE id=$1",[expected.id,binding?id:null,JSON.stringify({nativeOperationId:id,remoteStarted:true,remoteCompleted:options.completed??false})]);
   });return id;
  };

  await check('actual PostgreSQL16 applies unchanged migrations through SQL008',async()=>{assert.equal((await sql.one<any>("SELECT count(*)::int AS n FROM schema_migrations WHERE name='008_m6_portal.sql'"))!.n,1);});
  await check('workflow executions really have started_at and lack the formerly queried created_at',async()=>{const rows=await sql.query<any>("SELECT column_name FROM information_schema.columns WHERE table_name='workflow_executions'");assert(rows.some(row=>row.column_name==='started_at'));assert(!rows.some(row=>row.column_name==='created_at'));await rejected(()=>sql.query('SELECT * FROM workflow_executions ORDER BY created_at'),'42703');});
  const pristine=await fixture();
  await check('real persisted three-step encrypted plan loads and normalized manifest is complete',async()=>{const loaded=await plans.load(cid,wid,pristine.plan.workflowId);assert.deepEqual(loaded.plan,JSON.parse(JSON.stringify(pristine.plan)));assert.equal(loaded.version.step_count,3);assert.equal(loaded.version.native_request_count,2);assert.equal((await sql.query('SELECT id FROM workflow_steps WHERE workflow_id=$1',[pristine.plan.workflowId])).length,3);});
  await check('known failed execution with pristine pending steps proves zero completed or unknown native writes',async()=>{assert.equal((await proof(pristine)).allowed,true);assert.equal((await sql.query('SELECT id FROM mutation_operations WHERE cluster_id=$1',[cid])).length,0);});
  await check('actual Admin detail and directory capability SQL permit explicit pending-publication replan without native writes',async()=>{assert.equal((await admin.publication(cid,pristine.publication.id,{...actor})).entity.capabilities.publish,true);const list=await admin.publications(cid,{workspaceId:wid,size:20},{...actor});assert.equal(list.items.find((row:any)=>row.id===pristine.publication.id)?.capabilities.publish,true);assert.equal(wireWrites,0);});
  await check('legacy failed-step state with zero operation remains safely recoverable',async()=>{const f=await fixture();await sql.exec("UPDATE workflow_steps SET state='failed',started_at=now(),completed_at=now(),error_code='KNOWN_BEFORE_SEND_FAILURE' WHERE id=$1",[f.plan.steps[0].id]);assert.equal((await proof(f)).allowed,true);});
  await check('direct known failed exact encrypted native receipt passes the current plan request hash',async()=>{const f=await fixture();await failedOperation(f);assert.equal((await proof(f)).allowed,true);});
  await check('approved known failed operation uses actual approval and reciprocal native binding FK',async()=>{const f=await fixture(true);const operation=await failedOperation(f);assert.equal((await proof(f)).allowed,true);assert.equal((await sql.one<any>('SELECT operation_id FROM workflow_steps WHERE id=$1',[f.plan.steps[0].id])).operation_id,operation);});
  for(const state of ['running','uncertain','succeeded'])await check(`${state} native operation never permits replan`,async()=>{const f=await fixture();await failedOperation(f,{state});assert.equal((await proof(f)).allowed,false);});
  await check('failed operation with remote completed evidence is blocked rather than treated as zero change',async()=>{const f=await fixture();await failedOperation(f,{completed:true});assert.equal((await proof(f)).allowed,false);});
  await check('exact request hash mismatch is rejected even with failed operation state',async()=>{const f=await fixture();await failedOperation(f,{wrongHash:true});assert.equal((await proof(f)).allowed,false);});
  await check('uncertain execution state and unknown parent state independently block retry',async()=>{const f=await fixture();await sql.exec("UPDATE workflow_executions SET state='uncertain' WHERE id=$1",[f.executionId]);assert.equal((await proof(f)).allowed,false);await sql.exec("UPDATE workflow_executions SET state='failed' WHERE id=$1",[f.executionId]);await sql.exec("UPDATE workflows SET state='uncertain' WHERE id=$1",[f.plan.workflowId]);assert.equal((await proof(f)).allowed,false);});
  await check('post-native after fingerprint is actual SQL evidence and blocks replan',async()=>{const f=await fixture();await sql.exec('UPDATE workflow_steps SET after_fingerprint=$2 WHERE id=$1',[f.plan.steps[0].id,secrets.fingerprint({native:true})]);assert.equal((await proof(f)).allowed,false);});
  await check('non-pristine metadata IAM operation blocks retry even when its parent execution failed',async()=>{const f=await fixture(),execution=await sql.one<any>('SELECT idempotency_key FROM workflow_executions WHERE id=$1',[f.executionId]),last=f.plan.steps[2],key=`metadata-${secrets.fingerprint({id:f.plan.workflowId,step:last.id,key:execution.idempotency_key}).slice(0,48)}`;await sql.exec("INSERT INTO iam_operations(actor_id,idempotency_key,request_hash,module,action,target_id,cluster_id,workspace_id,state,payload_secret) VALUES($1,$2,$3,'portal','write',$4,$5,$6,'failed',$7)",[approver,key,secrets.fingerprint({metadata:true}),f.publication.id,cid,wid,secrets.encrypt({},'recovery-test')]);assert.equal((await proof(f)).allowed,false);});
  await check('cross-workspace and cross-publication proof cannot authorize another pending identity',async()=>{const f=await fixture();assert.equal((await publicationRetryProof(sql,secrets,cid,randomUUID(),f.publication)).allowed,false);assert.equal((await publicationRetryProof(sql,secrets,cid,wid,{...f.publication,id:randomUUID()})).allowed,false);});
  await check('actual original-key receipt returns old failure and does not allocate a new publication plan',async()=>{const f=await fixture();const before=Number((await sql.one<any>('SELECT count(*) AS n FROM workflows')).n),receipt=await workflow.receiptByKey(cid,f.key,{...actor});assert.equal(receipt.workflowId,f.plan.workflowId);assert.equal(receipt.state,'failed');assert.equal(receipt.steps.length,3);assert.equal(Number((await sql.one<any>('SELECT count(*) AS n FROM workflows')).n),before);assert.equal(wireWrites,0);});
  await check('two explicit new-key replans on the same failed publication commit one CAS winner',async()=>{const f=await fixture(true),body={revision:f.publication.revision,confirmed:true,confirm_name:f.publication.name};const outcomes=await Promise.allSettled([admin.publish(cid,f.publication.id,body,{...actor,idempotencyKey:`retry-a-${randomUUID()}`}),admin.publish(cid,f.publication.id,body,{...actor,idempotencyKey:`retry-b-${randomUUID()}`})]);assert.equal(outcomes.filter(row=>row.status==='fulfilled').length,1);const error=(outcomes.find(row=>row.status==='rejected')as PromiseRejectedResult).reason;assert.equal(error.getStatus(),409);const current=await sql.one<any>('SELECT workflow_id FROM portal_publications WHERE id=$1',[f.publication.id]);assert.notEqual(current.workflow_id,f.plan.workflowId);assert.equal((await sql.query('SELECT id FROM workflows WHERE subject_id=$1',[f.publication.id])).length,2);assert.equal(wireWrites,0);});
  await check('new replan is pending approval with sealed three-step manifest and original failed history retained',async()=>{const rows=await sql.query<any>("SELECT p.workflow_id FROM portal_publications p JOIN workflows w ON w.id=p.workflow_id WHERE w.state='pending'");assert(rows.length>=1);const loaded=await plans.load(cid,wid,rows[0].workflow_id);assert.equal(loaded.plan.approvalRequired,true);assert.equal(loaded.plan.steps.length,3);assert.equal((await sql.query('SELECT level FROM workflow_stages WHERE workflow_id=$1',[loaded.row.id])).length,1);assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM portal_publication_proofs')).n,0);assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM portal_application_grants')).n,0);assert.equal(wireWrites,0);});
 }finally{
  mkdirSync('artifacts/M6',{recursive:true});
  const passed=checks.filter(check=>check.passed).length;
  writeFileSync(`artifacts/M6/portal-publication-recovery-postgres-${runId}.json`,JSON.stringify({milestone:'M6',database:'disposable PostgreSQL16; unchanged migrations000-008',actual:['SQL constraints','WorkflowPlansService definitions/persist/load','PortalNativeService step construction','publicationRetryProof','PortalAdminService publication/detail/directory/replan','WorkflowService original-key receipt'],explicitFakes:['Gateway GET responses, no Kong network','current Authorization decisions','HTTP/private execution contexts'],nativeWireWrites:wireWrites,passed,failed:checks.length-passed,checks},null,2),{flag:'wx'});
  await db?.onModuleDestroy();execFileSync('docker',['rm','-f',container],{stdio:'ignore'});
 }
 process.stdout.write(`M6 isolated publication recovery: ${checks.length}/${checks.length} passed\n`);
}
main().catch(error=>{const missingColumn=String(error?.message??'').match(/column "([a-z_][a-z0-9_.]*)" does not exist/i)?.[1];process.stderr.write(`M6 isolated publication recovery failed: ${String(error?.code??error?.getResponse?.()?.code??'ASSERTION_FAILED').replace(/[^A-Z0-9_]/gi,'_').slice(0,128)}${missingColumn?` missingColumn=${missingColumn}`:''}\n`);process.exitCode=1;});
