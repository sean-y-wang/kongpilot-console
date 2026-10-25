import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {compileFunction,Script} from 'node:vm';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import {provisionRuntimeRole} from '../../apps/console-api/src/infrastructure/migrate';
import {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {ApprovedWorkflowExecutionService} from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import {WorkflowService} from '../../apps/console-api/src/modules/workflows/workflow.service';
import {PortalAuthBoundaryService} from '../../apps/console-api/src/modules/portal-boundary/portal-auth-boundary.service';
import {CredentialStoreService} from '../../apps/console-api/src/modules/credentials/credential-store.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import {AuditService} from '../../apps/console-api/src/modules/audit/audit.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {PortalAuthService} from '../../apps/console-api/src/modules/portal-auth/portal-auth.service';
import type {PortalPrincipal} from '../../apps/console-api/src/modules/portal-auth/portal-auth.types';
import {PortalCredentialsService} from '../../apps/console-api/src/modules/portal/portal-credentials.service';
import {PortalNativeService} from '../../apps/console-api/src/modules/portal/portal-native.service';
import {loadPortalIssueNativeEvidence,loadPortalGrantNativeEvidence} from '../../apps/console-api/src/modules/portal/portal-native-evidence';
import {decodePublicationProof,publicationProofAad,portalKeyAad,type PortalPublicationProofV1} from '../../apps/console-api/src/modules/portal/portal-proof';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import {snapshotAad,type WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Actual scanner SQL/program against disposable PostgreSQL16 and untouched
 * migrations000-009. Production compiler, plan persistence, metadata activation,
 * Portal login/authentication and audit run as the genuine runtime DB role.
 * Redis and read-only Gateway objects are explicit synthetic fixtures; no HTTP,
 * browser, current environment/private reference or native packet is accessed. */
async function main():Promise<void>{
 const container=`kongos-m6-keyscan-${randomUUID().slice(0,8)}`,runId=new Date().toISOString().replace(/[:.]/g,'-');
 const checks:Array<{name:string;passed:boolean;errorCode?:string;column?:string}>=[];
 let db:DbService|undefined,owner:DbService|undefined,nativeWrites=0,nativeReads=0,failureCode:string|undefined;
 let runtimeUrl='',serverVersion='',programRuns=0,queryRuns=0,cookieReaderRuns=0;
 let sourceHash='',runnerHash='',queryHash='',programHash='',readerHash='';
 const portalSecret='SyntheticPortalKeyScannerSigningKey2026!Independent';
 const hash=(v:string)=>createHash('sha256').update(v).digest('hex');
 const docker=(args:string[])=>execFileSync('env',['-u','DOCKER_HOST','-u','DOCKER_CONTEXT','-u','DOCKER_TLS','-u','DOCKER_TLS_VERIFY','-u','DOCKER_CERT_PATH','docker','--host=unix:///var/run/docker.sock',...args],{encoding:'utf8',stdio:['ignore','pipe','pipe']});
 let migrations:Array<{name:string;checksum:string}>=[];
 const safeCode=(error:any)=>String(error?.getResponse?.()?.code??error?.code??'ASSERTION_FAILED').replace(/[^A-Z0-9_]/gi,'_').slice(0,128);
 const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(error:any){checks.push({name,passed:false,errorCode:safeCode(error),...(typeof error?.column==='string'?{column:error.column}: {})});throw error;}};
 const rejected=async(fn:()=>Promise<unknown>,code:string)=>{try{await fn();}catch(error:any){assert.equal(safeCode(error),code);return;}throw new Error('EXPECTED_REJECTION');};
 try{
  docker(['run','-d','--pull=never','--name',container,'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine']);
  const port=docker(['port',container,'5432']).trim().split(':').pop();
  process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;
  process.env.CONSOLE_ENCRYPTION_KEY='cd'.repeat(32);process.env.APP_SECRET='SyntheticConsoleKeyScannerSigningKey2026!';
  process.env.PORTAL_SECRET=portalSecret;process.env.PORTAL_PUBLIC_ORIGINS='https://portal.synthetic.invalid';
  process.env.BOOTSTRAP_ADMIN_USERNAME='credential-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!Credential2026Password';
  owner=new DbService();for(let n=0;n<80;n++){try{await owner.one('SELECT 1');break;}catch{if(n===79)throw new Error('ISOLATED_DATABASE_UNAVAILABLE');await new Promise(resolve=>setTimeout(resolve,100));}}
  await owner.migrateAndSeed();
  process.env.CONSOLE_DB_RUNTIME_USER='m6_keyscan_runtime';process.env.CONSOLE_DB_RUNTIME_PASSWORD='Synthetic!KeyscanRuntime2026Password';
  await provisionRuntimeRole(owner);runtimeUrl=`postgres://m6_keyscan_runtime@127.0.0.1:${port}/postgres`;process.env.DATABASE_URL=runtimeUrl;db=new DbService();
  const sql=db,secrets=new SecretService(),audit=new AuditService(sql,secrets,new AuditOutboxWriter(sql,secrets)),workspaces=new WorkspaceResolverService(sql),plans=new WorkflowPlansService(sql,secrets,audit),registry=new WorkflowRegistryService();
  const admin=(await sql.one<any>('SELECT id FROM users WHERE super_admin'))!;
  const redis:any={rateLimit:async()=>({allowed:true}),withLock:async(_key:string,fn:()=>Promise<any>)=>fn(),assertLeaseOwnership:async()=>{}};
  const objects=new Map<string,any>();
  const kong:any={request:async(cid:string,method:string,path:string)=>{if(method!=='GET'){nativeWrites++;throw new Error('NATIVE_WRITE_FORBIDDEN');}nativeReads++;const row=objects.get(`${cid}:${path}`);assert(row,'FIXTURE_NATIVE_OBJECT_MISSING');return structuredClone(row);},
   list:async(cid:string,path:string)=>{nativeReads++;const prefix=`${cid}:${path}/`,items=[...objects.entries()].filter(([key])=>key.startsWith(prefix)&&!key.slice(prefix.length).includes('/')).map(([,value])=>structuredClone(value));return{items,nextCursor:null};}};
  const execution=new KongExecutionContextService();
  const authz=new AuthorizationService(sql,workspaces,kong,execution);
  const native=new PortalNativeService(sql,secrets,kong,execution,authz,workspaces);
  const auth=new PortalAuthService(sql,redis,secrets,audit,authz,{assertStep:async()=>{throw new Error('APPROVED_CAPABILITY_FORBIDDEN');}});
  auth.onModuleInit();
  const developerPassword='Synthetic!KeyscanDeveloper2026Password',developerPasswordHash=await bcrypt.hash(developerPassword,12);
  const store=new CredentialStoreService(sql,secrets),approved=new ApprovedWorkflowExecutionService(sql,secrets,authz,workspaces,kong,redis,execution);
  approved.onModuleInit();
  const credentials=new PortalCredentialsService(sql,secrets,authz,audit,auth,store,approved,plans,registry,native);
  credentials.onModuleInit();
  const recordedSchemas=JSON.parse(readFileSync('artifacts/M2/credential-schema-capabilities.json','utf8')).schemas;
  const consumerSchema=JSON.parse(readFileSync('tests/fixtures/kong-1.5.1/schema-consumers.json','utf8'));
  interface Fixture{cid:string;wid:string;appId:string;publicationId:string;adminUrl:string;scope:string;proof:PortalPublicationProofV1;principal:PortalPrincipal;login:any;loginRequestId:string;claims:jwt.JwtPayload;}
  const fixture=async(registeredScope:string|null=null):Promise<Fixture>=>{
   const cid=randomUUID(),wid=randomUUID(),developerId=randomUUID(),appId=randomUUID(),publicationId=randomUUID(),serviceId=randomUUID(),workflowId=randomUUID(),executionId=randomUUID();
   const adminUrl=`http://fixture-${cid}.invalid:8001`,scope=transportScopeFor(adminUrl,registeredScope),aclId=randomUUID(),keyId=randomUUID();
   const service={id:serviceId,name:`service-${serviceId}`,protocol:'http',host:'echo.fixture.invalid',port:8080,tags:['kos-ws-pay']};
   const aclPlugin={id:aclId,name:'acl',service:{id:serviceId},protocols:['http','https'],enabled:true,config:{whitelist:[`kos-portal-api-${publicationId}`]},tags:['kos-ws-pay']},keyPlugin={id:keyId,name:'key-auth',service:{id:serviceId},protocols:['http','https'],enabled:true,config:{key_names:['apikey']},tags:['kos-ws-pay']};
   let proof!:PortalPublicationProofV1;
   await sql.transaction(async tx=>{
    await tx.exec("INSERT INTO clusters(id,name,admin_url,transport_scope,execution_mode,version,status) VALUES($1,$2,$3,$4,'direct','1.5.1','healthy')",[cid,`registration-${cid}`,adminUrl,registeredScope]);
    await tx.exec("INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,'pay','Credential pay')",[wid,cid]);
    await tx.exec("INSERT INTO portal_settings(cluster_id,workspace_id,slug,name,status,published) VALUES($1,$2,$3,'Credential portal','active',true)",[cid,wid,`tenant-${cid}`]);
    await tx.exec("INSERT INTO portal_developers(id,cluster_id,workspace_id,username,email,display_name,password_hash,status) VALUES($1,$2,$3,$4,$5,'Synthetic developer',$6,'active')",[developerId,cid,wid,`dev-${developerId}`,`${developerId}@example.test`,developerPasswordHash]);
    await tx.exec("INSERT INTO portal_applications(id,cluster_id,workspace_id,developer_id,name) VALUES($1,$2,$3,$4,'Synthetic application')",[appId,cid,wid,developerId]);
    await tx.exec("INSERT INTO portal_publications(id,cluster_id,workspace_id,transport_scope,slug,name,service_id,acl_group,created_by,updated_by) VALUES($1,$2,$3,$4,$5,'Synthetic publication',$6,$7,$8,$8)",[publicationId,cid,wid,scope,`api-${publicationId}`,serviceId,`kos-portal-api-${publicationId}`,admin.id]);
    await tx.exec("INSERT INTO portal_publication_revisions(cluster_id,workspace_id,publication_id,revision,service_id,title,version_label,openapi_document,document_hash,created_by) VALUES($1,$2,$3,1,$4,'Synthetic API','1.0',$5::jsonb,$6,$7)",[cid,wid,publicationId,serviceId,JSON.stringify({openapi:'3.0.3',info:{title:'Synthetic API',version:'1.0'},paths:{}}),secrets.fingerprint({document:true}),admin.id]);
    await plans.definitions(cid,wid,admin.id,tx);
    const before=await tx.one<any>('SELECT * FROM portal_publications WHERE id=$1',[publicationId]);
    const first=native.nativeStep(1,'plugins','create',aclPlugin,null,{workflowId}),second=native.nativeStep(2,'plugins','create',keyPlugin,null,{workflowId,dependencies:[first.id]});
    const definitions:any={};for(const kind of ['portal-credential-issue','portal-credential-rotate','portal-credential-revoke']as const)definitions[kind]=await plans.definition(cid,wid,kind,tx);
    const schemas={consumers:consumerSchema,acls:recordedSchemas.acls.schema,keyAuth:recordedSchemas.keyauth_credentials.schema};
    const last=native.metadataStep(3,'portal.publication.publish','portal_publications',publicationId,before,{publicationRevision:1,service,aclGroup:before.acl_group,aclPluginId:aclId,keyAuthPluginId:keyId,schemas,definitions},[second.id]);
    const plan:WorkflowPlanV1={version:1,clusterId:cid,workspaceId:wid,workflowId,planRevision:1,kind:'portal-publication',executionMode:'direct',approvalRequired:false,subject:{type:'portal_publications',id:publicationId},requester:{type:'console',id:admin.id},definition:await plans.definition(cid,wid,'portal-publication',tx),issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString(),scope:{transportScope:scope,clusterRevision:1,workspaceRevision:1},prerequisites:[{type:'services',id:serviceId,path:`/services/${serviceId}`,before:service,fingerprint:secrets.fingerprint(service)}],steps:[first,second,last]};
    const row=await plans.persist(plan,`publication-${workflowId}`,{publicationId,revision:1},tx,{requestId:randomUUID(),ip:'192.0.2.17'}),snapshot={version:1,workflowId,executionId,clusterId:cid,workspaceId:wid,planRevision:1,planHash:row.plan_hash,capturedAt:new Date().toISOString(),objects:[]};
    await tx.exec(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,snapshot_state,snapshot_secret,snapshot_hash,claim_token_hash,idempotency_key,expires_at,completed_at)
     VALUES($1,$2,$3,$4,1,$5,'direct',false,NULL,$6,'succeeded','ready',$7,$8,$9,$10,now()+interval '30 minutes',now())`,[executionId,cid,wid,workflowId,row.plan_hash,admin.id,secrets.encrypt(snapshot,snapshotAad(cid,wid,workflowId,executionId)),secrets.fingerprint(snapshot),secrets.fingerprint({claim:executionId}),`execution-${executionId}`]);
    await tx.exec("UPDATE workflow_steps SET state='succeeded',started_at=now(),completed_at=now(),revision=revision+1 WHERE workflow_id=$1",[workflowId]);
    await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1 WHERE id=$1",[workflowId]);
    proof={version:1,clusterId:cid,workspaceId:wid,publicationId,publicationRevision:1,transportScope:scope,clusterRevision:1,workspaceRevision:1,executionMode:'direct',workflowId,executionId,planRevision:1,planHash:row.plan_hash,verifiedAt:new Date().toISOString(),serviceId,aclGroup:before.acl_group,aclPluginId:aclId,keyAuthPluginId:keyId,service,aclPlugin,keyAuthPlugin:keyPlugin,schemas,definitions};
    await tx.exec(`INSERT INTO portal_publication_proofs(cluster_id,workspace_id,publication_id,publication_revision,transport_scope,publication_proof_secret,publication_proof_hmac,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,1,$9)`,[cid,wid,publicationId,scope,secrets.encrypt(proof,publicationProofAad(cid,wid,publicationId,1)),secrets.fingerprint(proof),workflowId,executionId,row.plan_hash]);
    await tx.exec("UPDATE portal_publications SET state='published',published_revision=1,workflow_id=$2,key_auth_plugin_id=$3,acl_plugin_id=$4,revision=revision+1 WHERE id=$1",[publicationId,workflowId,keyId,aclId]);
   });
   objects.set(`${cid}:/services/${serviceId}`,service);
   objects.set(`${cid}:/plugins/${aclId}`,aclPlugin);objects.set(`${cid}:/plugins/${keyId}`,keyPlugin);
   const loginRequestId=randomUUID(),login=await auth.login({clusterId:cid,workspaceId:wid},{username:`dev-${developerId}`,password:developerPassword},{requestId:loginRequestId,ip:'127.0.0.1',userAgent:'disposable-keyscan-fixture'});
   const claims=jwt.decode(login.accessToken) as jwt.JwtPayload,principal=await auth.authenticate(login.accessToken);
   return{cid,wid,appId,publicationId,adminUrl,scope,proof,principal,login,loginRequestId,claims};
  };
  const request=(f:Fixture,key=`credential-${randomUUID()}`)=>credentials.request(f.principal,{clusterId:f.cid,workspaceId:f.wid,applicationId:f.appId,publicationId:f.publicationId,reason:'Synthetic integration request'},{idempotencyKey:key,requestId:randomUUID(),ip:'192.0.2.17'});
  const counts=async(f:Fixture)=>(await sql.one<any>(`SELECT (SELECT count(*)::int FROM portal_application_grants WHERE application_id=$1) AS grants,(SELECT count(*)::int FROM portal_credentials WHERE developer_id=$2) AS credentials,(SELECT count(*)::int FROM workflows WHERE requester_developer_id=$2) AS workflows,(SELECT count(*)::int FROM mutation_operations WHERE cluster_id=$3) AS mutations`,[f.appId,f.principal.developerId,f.cid]))!;

  const seedIssue=async()=>{
  const base=await fixture();
  const submitted=await request(base,`activation-request-${randomUUID()}`),loaded=await plans.load(base.cid,base.wid,submitted.workflowId);
  const plan=loaded.plan,executionId=randomUUID(),metadata=plan.steps.at(-1)!;
  const sessionId=randomUUID();await sql.exec("INSERT INTO auth_sessions(id,user_id,credential_epoch,expires_at) VALUES($1,$2,1,now()+interval '1 hour')",[sessionId,admin.id]);
  const actor:any={user:{id:admin.id,username:'credential-bootstrap',superAdmin:true},workspaceId:base.wid,idempotencyKey:`activation-execute-${randomUUID()}`,requestId:'isolated-activation'};
  let originalCredential:any;
  const nativeObjects=plan.steps.filter(step=>step.kind==='native').map(step=>{
   const body:any=step.mutationPayload;
   return{step,result:{...body,created_at:Math.floor(Date.now()/1000),...(step.parentId?{consumer:{id:step.parentId}}:{})}};
  });
  {
   assert.equal(plan.kind,'portal-credential-issue');assert.equal(plan.approvalRequired,true);assert.equal(plan.steps.length,4);
   originalCredential=await sql.one<any>('SELECT * FROM portal_credentials WHERE grant_id=$1',[submitted.grant.id]);
   assert.deepEqual(Object.keys(secrets.decrypt<any>(originalCredential.key_secret,portalKeyAad(base.cid,base.wid,originalCredential.id,1))),['key']);
   assert.equal(originalCredential.state,'pending');assert.equal(originalCredential.issue_operation_id,null);
   assert.deepEqual(await counts(base),{grants:1,credentials:1,workflows:1,mutations:0});
  }
  {
   await sql.transaction(async tx=>{
    await tx.exec("INSERT INTO workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,approver_id,decision,idempotency_key) VALUES($1,$2,$3,1,$4,1,$5,'approve',$6)",[base.cid,base.wid,plan.workflowId,loaded.row.plan_hash,admin.id,`approval-${executionId}`]);
    await tx.exec("UPDATE workflow_stages SET state='approved',completed_at=now(),updated_at=now() WHERE workflow_id=$1",[plan.workflowId]);
    await tx.exec("UPDATE workflows SET state='executing',approved_by=$2,approved_at=now(),revision=revision+1,updated_at=now() WHERE id=$1",[plan.workflowId,admin.id]);
    const snapshot={version:1,workflowId:plan.workflowId,executionId,clusterId:base.cid,workspaceId:base.wid,planRevision:1,planHash:loaded.row.plan_hash,capturedAt:new Date().toISOString(),objects:[...plan.prerequisites.map(item=>({type:item.type,id:item.id,path:item.path,before:item.before,absent:false,fingerprint:item.fingerprint})),...plan.steps.flatMap(item=>item.nativeRequests.map(request=>({type:request.nativeType,id:request.nativeId!,path:`${request.canonicalPath}/${request.nativeId}`,before:null,absent:true,fingerprint:secrets.fingerprint(null)})))]};
    await tx.exec(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,snapshot_state,snapshot_secret,snapshot_hash,claim_token_hash,idempotency_key,expires_at)
     VALUES($1,$2,$3,$4,1,$5,'direct',true,$6,$6,'executing','ready',$7,$8,$9,$10,now()+interval '30 minutes')`,[executionId,base.cid,base.wid,plan.workflowId,loaded.row.plan_hash,admin.id,secrets.encrypt(snapshot,snapshotAad(base.cid,base.wid,plan.workflowId,executionId)),secrets.fingerprint(snapshot),secrets.fingerprint({claim:executionId}),actor.idempotencyKey]);
    for(const {step,result} of nativeObjects){
     const operationId=randomUUID(),requestHash=secrets.fingerprint({actor:admin.id,clusterId:base.cid,workspaceId:base.wid,entityType:step.entityType,entityId:null,action:step.mutationAction,payload:step.mutationPayload,parentId:step.parentId??null,credentialKind:step.credentialKind??null,approvedWorkflow:{workflowId:plan.workflowId,executionId,planRevision:1,planHash:loaded.row.plan_hash,stepId:step.id,beforeHmac:step.beforeFingerprint}});
     await tx.exec(`INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,entity_type,entity_id,parent_id,credential_kind,transport_scope,before_secret,payload_secret,result_secret,remote_started,remote_completed,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id)
      VALUES($1,$2,$3,$4,'create',$5,$6,'succeeded',$7,$8,$9,$10,$11,$12,$13,$14,true,true,$15,$16,1,$17,$18)`,[operationId,base.cid,base.wid,admin.id,step.mutationIdempotencyKey,requestHash,step.entityType,result.id,step.parentId??null,step.credentialKind??null,base.scope,secrets.encrypt(null,`mutation:${operationId}:before`),secrets.encrypt(step.mutationPayload,`mutation:${operationId}:payload`),secrets.encrypt(result,`mutation:${operationId}:result`),plan.workflowId,executionId,loaded.row.plan_hash,step.id]);
     await tx.exec("UPDATE workflow_steps SET state='succeeded',operation_id=$2,receipt_secret=$3,after_fingerprint=$4,safe_result=$5::jsonb,started_at=now(),completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1",[step.id,operationId,secrets.encrypt({operationId,entity:result},`workflow:${executionId}:${step.id}:receipt`),secrets.fingerprint(result),JSON.stringify({nativeOperationId:operationId,entityId:result.id,remoteStarted:true,remoteCompleted:true})]);
     const path=step.entityType==='consumers'?`/consumers/${result.id}`:`/consumers/${step.parentId}/${step.credentialKind}/${result.id}`;
     objects.set(`${base.cid}:${path}`,result);
    }
    await tx.exec("UPDATE workflow_steps SET state='running',started_at=now(),revision=revision+1,updated_at=now() WHERE id=$1",[metadata.id]);
   });
   for(const {step,result}of nativeObjects)if(step.credentialKind)await store.save(base.cid,step.parentId!,step.credentialKind,result,step.mutationPayload as any);
   assert.equal((await sql.query("SELECT id FROM credential_refs WHERE cluster_id=$1 AND state='active'",[base.cid])).length,2);
   assert.equal((await sql.query("SELECT id FROM mutation_operations WHERE workflow_id=$1 AND state='succeeded' AND remote_completed",[plan.workflowId])).length,3);
  }
  return{base,submitted,loaded,plan,executionId,metadata,actor,sessionId,originalCredential,nativeObjects};
  };
  type Issue=Awaited<ReturnType<typeof seedIssue>>;
  const handler=registry.get('portal.credential.activate');
  const http=<T>(f:Issue,fn:()=>Promise<T>,key=f.actor.idempotencyKey)=>execution.runHttp({requestId:'isolated-activation-recovery',idempotencyKey:key},()=>{
   execution.bindHttpActor(f.actor.user,f.sessionId);return execution.runActor({actor:f.actor.user,clusterId:f.base.cid,workspaceId:f.base.wid,module:'workflows',action:'write'},fn);
  });
  const input=(f:Issue)=>({plan:f.plan,step:f.metadata,actor:f.actor,executionId:f.executionId});
  const pending=async(f:Issue,parent='executing')=>{
   const key=await sql.one<any>('SELECT * FROM portal_credentials WHERE id=$1',[f.originalCredential.id]),grant=await sql.one<any>('SELECT * FROM portal_application_grants WHERE id=$1',[f.submitted.grant.id]);
   assert.equal(key.state,'pending');assert.equal(key.key_secret,f.originalCredential.key_secret);assert.equal(key.credential_ref_id,null);assert.equal(key.issue_operation_id,null);assert.equal(key.revision,1);
   assert.equal(grant.state,'pending');assert.equal(grant.current_generation,0);assert.equal(grant.current_credential_id,null);assert.equal(grant.acl_credential_ref_id,null);
   assert.equal((await sql.one<any>('SELECT state FROM workflows WHERE id=$1',[f.plan.workflowId])).state,parent);
   assert.equal((await sql.one<any>('SELECT state FROM workflow_executions WHERE id=$1',[f.executionId])).state,parent);
   assert.equal((await sql.query("SELECT id FROM mutation_operations WHERE workflow_id=$1 AND state='succeeded' AND remote_completed",[f.plan.workflowId])).length,3);
  };
  const finalize=async(f:Issue,tx:DbService)=>{
   assert.equal(await tx.exec("UPDATE workflow_steps SET state='succeeded',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='running'",[f.metadata.id]),1);
   assert.equal(await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing'",[f.executionId]),1);
   assert.equal(await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing'",[f.plan.workflowId]),1);
  };
  const activate=async(f:Issue,terminal=true)=>http(f,()=>approved.runApprovedExecution(f.executionId,()=>execution.runApprovedStep(f.metadata.id,async()=>{
   await handler.prepare!(input(f));
   return sql.transaction(async tx=>{
    const inspected=await handler.inspect(input(f),tx);
    assert.equal(inspected.revision,f.metadata.metadataRevision);assert.equal(secrets.fingerprint(inspected.before),f.metadata.metadataBeforeHmac);
    await approved.assertStep({handler:f.metadata.handler!,actor:f.actor.user,clusterId:f.base.cid,workspaceId:f.base.wid,entityType:f.metadata.entityType,entityId:f.metadata.entityId!,before:inspected.before,revision:inspected.revision,payload:f.metadata.metadata},tx);
    const result=await handler.apply({...input(f),transaction:tx});if(terminal)await finalize(f,tx);return result;
   });
  })));
  const active=async(f:Issue)=>{
   const key=await sql.one<any>('SELECT * FROM portal_credentials WHERE id=$1',[f.originalCredential.id]),grant=await sql.one<any>('SELECT * FROM portal_application_grants WHERE id=$1',[f.submitted.grant.id]);
   assert.equal(key.state,'active');assert.equal(key.key_secret,f.originalCredential.key_secret);assert.equal(key.revision,2);assert(key.credential_ref_id);assert(key.issue_operation_id);
   assert.equal(grant.state,'active');assert.equal(grant.current_generation,1);assert.equal(grant.current_credential_id,key.id);assert(grant.acl_credential_ref_id);
   assert.equal((await sql.one<any>('SELECT state FROM workflows WHERE id=$1',[f.plan.workflowId])).state,'succeeded');assert.equal((await sql.one<any>('SELECT state FROM workflow_executions WHERE id=$1',[f.executionId])).state,'succeeded');
   const native=await sql.query<any>("SELECT * FROM mutation_operations WHERE workflow_id=$1 ORDER BY created_at,id",[f.plan.workflowId]);assert.equal(native.length,3);assert(native.every(row=>row.state==='succeeded'&&row.remote_completed===true));
  };

  const helperPath='tests/security/lib/m6-browser-key-scan.mjs',runnerPath='tests/security/capture-m6-browser-key.mjs';
  const helper=readFileSync(helperPath,'utf8'),runner=readFileSync(runnerPath,'utf8');sourceHash=hash(helper);runnerHash=hash(runner);
  assert.equal(sourceHash,'55d8ae2d50f035bb5b4cccd4ba03e80955d19ab6a1587b14e61bf104ac904598','FROZEN_HELPER_CHANGED');
  assert.equal(runnerHash,'2f696777294dae61b97e7abe10d02617a8d25916ce67b08f5cf5b3b19bba1f3c','FROZEN_RUNNER_CHANGED');
  const queryInitializer=/export const BROWSER_KEY_SCAN_SQL=(`[^`]*`);/.exec(helper)?.[1],programInitializer=/const program=(`[^`]*`);/.exec(runner)?.[1];
  assert(queryInitializer&&programInitializer,'ACTUAL_SOURCE_INITIALIZERS_REQUIRED');
  const query=compileFunction(`return ${queryInitializer};`)() as string;
  const program=compileFunction(`return ${programInitializer};`,['BROWSER_KEY_SCAN_SQL'])(query) as string;new Script(program);
  queryHash=hash(query);programHash=hash(program);assert.equal(queryHash,'aade72bcf3bac4f717bfd3e945832422171cca7ba3bdafc833c6ad3c2c5258ff');assert.equal(programHash,'e5a2e1f42822325578e749ebc869850e2a30fee6cf1c26ae3b409aa85c20cbfe');
  const actualUuid=/const uuid=(.*);/.exec(helper)?.[1],actualAssertion=/function assertProof\(row,context\)\{[\s\S]*?\n\}/.exec(helper)?.[0];assert(actualUuid&&actualAssertion);
  const uuid=compileFunction(`return (${actualUuid});`)(),assertProof=compileFunction(`return (${actualAssertion});`,['uuid'])(uuid) as (row:any,context:any)=>void;
  const readerSource=readFileSync('tests/security/lib/m6-browser-remaining.mjs','utf8');readerHash=hash(readerSource);assert.equal(readerHash,'e3b09ac5276a74082b54670f3c73f4e501fbc86f3d9c92416923899ae9230ae0');
  const cookieQueryInit=/export const BROWSER_COOKIE_SESSION_SQL=(`[^`]*`);/.exec(readerSource)?.[1],cookieProgramInit=/export const BROWSER_COOKIE_READER_PROGRAM=(`[^`]*`);/.exec(readerSource)?.[1];assert(cookieQueryInit&&cookieProgramInit);
  const cookieQuery=compileFunction(`return ${cookieQueryInit};`)(),cookieProgram=compileFunction(`return ${cookieProgramInit};`,['BROWSER_COOKIE_SESSION_SQL'])(cookieQuery) as string;
  const subprocess=(code:string,input:unknown)=>{
   try{return{status:0,stdout:execFileSync(process.execPath,['-e',code],{cwd:resolve('apps/console-api'),env:{PATH:process.env.PATH,DATABASE_URL:runtimeUrl,PORTAL_SECRET:portalSecret},input:JSON.stringify(input),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:15000,maxBuffer:65536}),stderr:''};}
   catch(error:any){return{status:Number(error.status),stdout:String(error.stdout??''),stderr:String(error.stderr??'')};}
  };
  const programRows=(args:unknown[])=>{programRuns++;const result=subprocess(program,args);assert.equal(result.status,0);assert.equal(result.stderr,'');const rows=JSON.parse(result.stdout);assert(Array.isArray(rows));return rows;};
  const read=async(f:Issue,tx=sql,args:unknown[]=[f.plan.workflowId,f.base.cid,f.base.wid,f.actor.idempotencyKey,null])=>{queryRuns++;return tx.query<any>(query,args);};
  const context=(f:Issue)=>({workflowId:f.plan.workflowId,fixture:{clusterId:f.base.cid,workspaceId:f.base.wid,publicationId:f.base.publicationId},applicationId:f.base.appId,ownerId:f.base.principal.developerId,executorId:admin.id});
  const deniedProof=(rows:any[],f:Issue)=>{if(rows.length!==1){assert.equal(rows.length,0);return;}assert.throws(()=>assertProof(rows[0],context(f)));};
  const rollback=async(fn:(tx:DbService)=>Promise<void>)=>{const marker=new Error('INTENTIONAL_DISPOSABLE_FAULT_ROLLBACK');try{await sql.transaction(async tx=>{await fn(tx);throw marker;});}catch(error){if(error!==marker)throw error;}};
  const mutateAndDeny=async(f:Issue,statement:string,args:unknown[])=>rollback(async tx=>{await tx.exec(statement,args);deniedProof(await read(f,tx),f);});
  const cookieInput=(f:Issue)=>({expected:{ownerId:f.base.principal.developerId,clusterId:f.base.cid,workspaceId:f.base.wid,loginRequestId:f.base.loginRequestId,issuedAt:f.base.claims.iat},candidates:[f.base.login.accessToken,f.base.login.refreshToken,f.base.login.csrfToken]});
  const validCookieProof=(f:Issue)=>{cookieReaderRuns++;const input=cookieInput(f),result=subprocess(cookieProgram,input);assert.equal(result.status,0);assert.equal(result.stderr,'');const proof=JSON.parse(result.stdout);assert.equal(proof.sessionId,f.base.principal.sessionId);assert.equal(proof.accessIndex,0);assert.equal(proof.refreshIndex,1);assert.equal(proof.csrfIndex,2);assert.equal(proof.originalLoginAudited,true);assert.equal(proof.currentSessionVerified,true);assert.equal(proof.accessExpired,false);for(const v of input.candidates)assert(!result.stdout.includes(v));};
  const rejectedCookieProof=(input:unknown)=>{cookieReaderRuns++;const result=subprocess(cookieProgram,input);assert.equal(result.status,2);assert.equal(result.stdout,'');assert.equal(result.stderr,'');};

  await check('01 PostgreSQL16 applies unchanged migrations000-009 and actual scanner runtime is non-owner non-superuser',async()=>{
   serverVersion=(await sql.one<any>('SHOW server_version')).server_version;assert.match(serverVersion,/^16\./);
   migrations=await sql.query('SELECT name,checksum FROM schema_migrations ORDER BY name');assert.equal(migrations.length,10);
   for(const row of migrations)assert.equal(hash(readFileSync(`apps/console-api/src/infrastructure/migrations/${row.name}`,'utf8')),row.checksum);
   const role=await sql.one<any>('SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user');assert.equal(role.rolsuper,false);assert.equal(role.rolcreatedb,false);assert.equal(role.rolcreaterole,false);
   assert.equal((await sql.one<any>("SELECT count(*)::int AS n FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE r.rolname=current_user AND c.relname IN('workflows','workflow_steps','workflow_executions','mutation_operations','audit_events')")).n,0);
   for(const privilege of ['SELECT','INSERT'])assert.equal((await sql.one<any>("SELECT has_table_privilege(current_user,'audit_events',$1) AS allowed",[privilege])).allowed,true);
   for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])assert.equal((await sql.one<any>("SELECT has_table_privilege(current_user,'audit_events',$1) AS allowed",[privilege])).allowed,false);
  });
  const normal=await seedIssue();await activate(normal);await active(normal);
  let baseline:any;
  await check('02 production compiler Plan.persist and approved activation yield NULL CREATE logical IDs with exact native3 refs2 active generation1',async()=>{
   const steps=await sql.query<any>("SELECT entity_id,native_requests FROM workflow_steps WHERE workflow_id=$1 AND kind='native' ORDER BY step_order",[normal.plan.workflowId]);assert.equal(steps.length,3);assert(steps.every(s=>s.entity_id===null));
   const rows=await read(normal);assert.equal(rows.length,1);baseline=rows[0];assertProof(baseline,context(normal));assert.equal(baseline.last_revealed_at,null);assert.equal(baseline.scanner_reveal_audited,false);
   assert.deepEqual(baseline.native_bindings.map((b:any)=>b.id),normal.nativeObjects.map(n=>n.result.id));assert.deepEqual(baseline.native_bindings.map((b:any)=>b.parentId),[null,normal.nativeObjects[0].result.id,normal.nativeObjects[0].result.id]);
   for(let i=0;i<3;i++){assert.equal(steps[i].native_requests[0].native_id,normal.nativeObjects[i].result.id);assert.equal(steps[i].native_requests[0].method,'POST');}
  });
  await check('03 actual exported runner executes original SQL READ ONLY; legacy logical-ID comparison loses all ACK bindings',async()=>{
   const rows=programRows([normal.plan.workflowId,normal.base.cid,normal.base.wid,normal.actor.idempotencyKey,null]);assert.equal(rows.length,1);assertProof(rows[0],context(normal));
   const legacy=query.replace("m.entity_id=s.native_requests->0->>'native_id'",'m.entity_id=s.entity_id::text');assert.notEqual(legacy,query);const oldRows=await sql.query<any>(legacy,[normal.plan.workflowId,normal.base.cid,normal.base.wid,normal.actor.idempotencyKey,null]);assert.equal(oldRows.length,1);assert.deepEqual(oldRows[0].native_bindings,[]);deniedProof(oldRows,normal);
  });
  await check('04 immutable sealed native manifest and logical type reject tampering without disabling original constraints',async()=>{
   for(const [statement,args]of[
    ["UPDATE workflow_steps SET native_requests=jsonb_set(native_requests,'{0,native_id}',to_jsonb($2::text)) WHERE id=$1",[normal.plan.steps[0].id,randomUUID()]],
    ["UPDATE workflow_steps SET native_requests=jsonb_set(native_requests,'{0,parent_id}',to_jsonb($2::text)) WHERE id=$1",[normal.plan.steps[1].id,randomUUID()]],
    ["UPDATE workflow_steps SET native_requests=jsonb_set(native_requests,'{0,method}','\"PATCH\"'::jsonb) WHERE id=$1",[normal.plan.steps[2].id]],
    ["UPDATE workflow_steps SET entity_type='services' WHERE id=$1",[normal.plan.steps[0].id]],
   ]as Array<[string,unknown[]]>)await rejected(()=>sql.transaction(tx=>tx.exec(statement,args)),'23514');
  });
  await check('05 wrong completed native receipt UUID is rejected by actual SQL in an explicitly rolled-back fault snapshot',async()=>{
   await mutateAndDeny(normal,'UPDATE mutation_operations SET entity_id=$2 WHERE workflow_step_id=$1',[normal.plan.steps[0].id,randomUUID()]);
   await mutateAndDeny(normal,'UPDATE mutation_operations SET entity_id=$2 WHERE workflow_step_id=$1',[normal.plan.steps[2].id,randomUUID()]);
   await rejected(()=>sql.transaction(tx=>tx.exec("UPDATE mutation_operations SET parent_id=$2 WHERE workflow_step_id=$1",[normal.plan.steps[2].id,randomUUID()])),'23514');
  });
  await check('06 actual fixed query and runner fail closed on wrong workflow CID WID execution key and malformed UUID',async()=>{
   const original=[normal.plan.workflowId,normal.base.cid,normal.base.wid,normal.actor.idempotencyKey,null];
   for(const index of [0,1,2,3]){const args=[...original];args[index]=randomUUID();assert.deepEqual(programRows(args),[]);}
   programRuns++;const bad=subprocess(program,['not-a-uuid',...original.slice(1)]);assert.equal(bad.status,2);assert.equal(bad.stdout,'');assert.equal(bad.stderr,'');
  });
  await check('07 incomplete remote ACK missing result or uncertain operation cannot authorize a scanner reveal',async()=>{
   await mutateAndDeny(normal,'UPDATE mutation_operations SET remote_completed=false WHERE workflow_step_id=$1',[normal.plan.steps[2].id]);
   await mutateAndDeny(normal,'UPDATE mutation_operations SET result_secret=NULL WHERE workflow_step_id=$1',[normal.plan.steps[1].id]);
   await mutateAndDeny(normal,"UPDATE mutation_operations SET state='uncertain',remote_completed=false WHERE workflow_step_id=$1",[normal.plan.steps[0].id]);
  });
  await check('08 actual proof rejects advanced generation inactive grant or credential in rollback-only fault snapshots',async()=>{
   await mutateAndDeny(normal,'UPDATE portal_application_grants SET current_generation=2 WHERE id=$1',[normal.submitted.grant.id]);
   await mutateAndDeny(normal,"UPDATE portal_application_grants SET state='uncertain' WHERE id=$1",[normal.submitted.grant.id]);
   await mutateAndDeny(normal,"UPDATE portal_credentials SET state='uncertain' WHERE id=$1",[normal.originalCredential.id]);
  });
  await check('09 exact ACL and key credential refs both must remain active for actual SQL/proof',async()=>{
   for(const kind of ['acls','key-auth'])await mutateAndDeny(normal,"UPDATE credential_refs SET state='revoked' WHERE cluster_id=$1 AND consumer_id=$2 AND credential_type=$3",[normal.base.cid,baseline.consumer_id,kind]);
  });
  await check('10 actual login Audit and signed sameSID reader verify current session and reject a foreign SID or missing original audit',async()=>{
   validCookieProof(normal);const input=cookieInput(normal);rejectedCookieProof({...input,expected:{...input.expected,loginRequestId:randomUUID()}});
   const foreign=jwt.sign({...normal.base.claims,sid:randomUUID()},portalSecret,{algorithm:'HS256'});rejectedCookieProof({...input,candidates:[foreign,normal.base.login.refreshToken,normal.base.login.csrfToken]});
  });
  await check('11 actual owner reveal audit binds request ID and leaves key ciphertext native tuple and refs unchanged',async()=>{
   const requestId=randomUUID(),key=await sql.one<any>('SELECT revision FROM portal_credentials WHERE id=$1',[normal.originalCredential.id]);
   const result=await credentials.reveal(normal.base.principal,normal.base.appId,normal.submitted.grant.id,normal.originalCredential.id,{clusterId:normal.base.cid,workspaceId:normal.base.wid,revision:key.revision},{requestId,ip:'127.0.0.1'});
   assert.equal(typeof result.key,'string');assert.equal(result.credentialId,normal.originalCredential.id);
   const after=programRows([normal.plan.workflowId,normal.base.cid,normal.base.wid,normal.actor.idempotencyKey,requestId]);assert.equal(after.length,1);assertProof(after[0],context(normal));assert.equal(after[0].scanner_reveal_audited,true);assert(after[0].last_revealed_at);assert.equal(after[0].cipher_sha,baseline.cipher_sha);assert.deepEqual(after[0].native_bindings,baseline.native_bindings);assert.equal(after[0].active_refs,2);assert(!JSON.stringify(after).includes(result.key));
   const wrong=programRows([normal.plan.workflowId,normal.base.cid,normal.base.wid,normal.actor.idempotencyKey,randomUUID()]);assert.equal(wrong[0].scanner_reveal_audited,false);validCookieProof(normal);
  });
  await check('12 revoked sameSID fails closed while fixed query executions preserve immutable plans receipts ciphertext and migrations',async()=>{
   await sql.exec('UPDATE portal_sessions SET revoked_at=now(),updated_at=now() WHERE id=$1',[normal.base.principal.sessionId]);rejectedCookieProof(cookieInput(normal));
   const final=await read(normal);assert.equal(final.length,1);assertProof(final[0],context(normal));assert.equal(final[0].cipher_sha,baseline.cipher_sha);assert.deepEqual(final[0].native_bindings,baseline.native_bindings);
   assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM schema_migrations')).n,10);assert.equal(hash(readFileSync(helperPath,'utf8')),sourceHash);assert.equal(hash(readFileSync(runnerPath,'utf8')),runnerHash);assert.equal(nativeWrites,0);
  });
 }catch(error){failureCode=safeCode(error);throw error;}finally{
  mkdirSync('artifacts/M6',{recursive:true});const artifact=`artifacts/M6/browser-key-scan-postgres-${runId}.json`;
  writeFileSync(artifact,JSON.stringify({performedAt:new Date().toISOString(),milestone:'M6',status:failureCode?'FAIL':'PASS',failureCode,database:'disposable PostgreSQL16, original000-009, genuine non-owner runtime role',serverVersion,migrations,helperSha256:sourceHash,runnerSha256:runnerHash,querySha256:queryHash,programSha256:programHash,cookieReaderSha256:readerHash,queryRuns,programRuns,cookieReaderRuns,nativeWrites,businessHttpRequests:0,browserActions:0,currentDatabaseReads:0,privateReferenceReads:0,environmentFileReads:0,syntheticGatewayReadCalls:nativeReads,fixtures:['production PortalAuth.login/authenticate and Audit produce in-memory synthetic sameSID tokens','production Credentials.request/WorkflowPlans.persist produce sealed immutable NULL logical CREATE and normalized native IDs','production approved metadata activation completes synthetic ACK ledger and exact credential refs under runtime role','Redis leases/rate limiter and Gateway GET object lookup are explicit fixture dependencies; no native transport','fault mutations that violate deferred visible state run in explicit rolled-back disposable transactions, never commit','immutable manifest/type/parent tampering exercises original23514 guards; no constraints disabled'],checks,passed:checks.filter(c=>c.passed).length,total:checks.length,limitations:['isolated SQL/proof/program verification; does not replace actual browser HTTP or gateway credential usability evidence','query rows, keys, token hashes and driver error messages remain private memory and are never serialized']},null,2)+'\n',{flag:'wx'});
  await db?.onModuleDestroy();await owner?.onModuleDestroy();try{docker(['rm','-f',container]);}catch{}
  process.stdout.write(JSON.stringify({artifact,status:failureCode?'FAIL':'PASS',passed:checks.filter(c=>c.passed).length,total:checks.length,nativeWrites,businessHttpRequests:0})+'\n');
 }
}
main().catch(()=>{process.stderr.write('Isolated browser Key scanner proof failed; safe artifact retained.\n');process.exitCode=1;});

