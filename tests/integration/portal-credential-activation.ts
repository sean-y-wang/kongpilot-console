import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
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

/** Disposable PostgreSQL and actual compiler, ledger, authorization, private
 * execution capability, graph policy and activation/recovery handlers.
 * Developer identity validation, Redis leases and read-only Gateway responses
 * are explicit fixtures. This does not replace real HTTP authentication or Kong. */
async function main():Promise<void>{
 const container=`kongos-m6-recovery-${randomUUID().slice(0,8)}`,runId=new Date().toISOString().replace(/[:.]/g,'-');
 const checks:Array<{name:string;passed:boolean;errorCode?:string;column?:string}>=[];
 let db:DbService|undefined,nativeWrites=0,nativeReads=0,failureCode:string|undefined;
 let migrations:Array<{name:string;checksum:string}>=[];
 const safeCode=(error:any)=>String(error?.getResponse?.()?.code??error?.code??'ASSERTION_FAILED').replace(/[^A-Z0-9_]/gi,'_').slice(0,128);
 const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(error:any){checks.push({name,passed:false,errorCode:safeCode(error),...(typeof error?.column==='string'?{column:error.column}: {})});throw error;}};
 const rejected=async(fn:()=>Promise<unknown>,code:string)=>{try{await fn();}catch(error:any){assert.equal(safeCode(error),code);return;}throw new Error('EXPECTED_REJECTION');};
 try{
  execFileSync('docker',['run','-d','--name',container,'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine'],{stdio:'ignore'});
  const port=execFileSync('docker',['port',container,'5432'],{encoding:'utf8'}).trim().split(':').pop();
  process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;
  process.env.CONSOLE_ENCRYPTION_KEY='ed'.repeat(32);process.env.APP_SECRET='SyntheticCredentialRequestSigningKey2026!';
  process.env.BOOTSTRAP_ADMIN_USERNAME='credential-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!Credential2026Password';
  db=new DbService();for(let n=0;n<80;n++){try{await db.one('SELECT 1');break;}catch{if(n===79)throw new Error('ISOLATED_DATABASE_UNAVAILABLE');await new Promise(resolve=>setTimeout(resolve,100));}}
  await db.migrateAndSeed();
  const sql=db,secrets=new SecretService(),audit=new AuditService(sql,secrets,new AuditOutboxWriter(sql,secrets)),workspaces=new WorkspaceResolverService(sql),plans=new WorkflowPlansService(sql,secrets,audit),registry=new WorkflowRegistryService();
  const admin=(await sql.one<any>('SELECT id FROM users WHERE super_admin'))!;
  const redis:any={withLock:async(_key:string,fn:()=>Promise<any>)=>fn(),assertLeaseOwnership:async()=>{}};
  const objects=new Map<string,any>();
  const kong:any={request:async(cid:string,method:string,path:string)=>{if(method!=='GET'){nativeWrites++;throw new Error('NATIVE_WRITE_FORBIDDEN');}nativeReads++;const row=objects.get(`${cid}:${path}`);assert(row,'FIXTURE_NATIVE_OBJECT_MISSING');return structuredClone(row);},
   list:async(cid:string,path:string)=>{nativeReads++;const prefix=`${cid}:${path}/`,items=[...objects.entries()].filter(([key])=>key.startsWith(prefix)&&!key.slice(prefix.length).includes('/')).map(([,value])=>structuredClone(value));return{items,nextCursor:null};}};
  const execution=new KongExecutionContextService();
  const authz=new AuthorizationService(sql,workspaces,kong,execution);
  const native=new PortalNativeService(sql,secrets,kong,execution,authz,workspaces);
  const auth=new PortalAuthService(sql,redis,secrets,audit,authz,{assertStep:async()=>{throw new Error('APPROVED_CAPABILITY_FORBIDDEN');}});
  // Explicit fake identity boundary; the inherited actual executeMetadata still
  // checks real sessions/tenant rows and persists the real durable SQL ledger.
  auth.assertCurrent=async(principal:PortalPrincipal,tx:DbService=sql)=>{
   const row=await tx.one<any>('SELECT * FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND status=\'active\'',[principal.developerId,principal.clusterId,principal.workspaceId]);
   assert(row);return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,username:row.username,email:row.email,displayName:row.display_name,status:row.status,revision:row.revision,mustChangePassword:false,createdAt:new Date(row.created_at).toISOString()};
  };
  const store=new CredentialStoreService(sql,secrets),approved=new ApprovedWorkflowExecutionService(sql,secrets,authz,workspaces,kong,redis,execution);
  approved.onModuleInit();
  const credentials=new PortalCredentialsService(sql,secrets,authz,audit,auth,store,approved,plans,registry,native);
  credentials.onModuleInit();
  const recordedSchemas=JSON.parse(readFileSync('artifacts/M2/credential-schema-capabilities.json','utf8')).schemas;
  const consumerSchema=JSON.parse(readFileSync('tests/fixtures/kong-1.5.1/schema-consumers.json','utf8'));
  interface Fixture{cid:string;wid:string;appId:string;publicationId:string;adminUrl:string;scope:string;proof:PortalPublicationProofV1;principal:PortalPrincipal;}
  const fixture=async(registeredScope:string|null=null):Promise<Fixture>=>{
   const cid=randomUUID(),wid=randomUUID(),developerId=randomUUID(),sessionId=randomUUID(),appId=randomUUID(),publicationId=randomUUID(),serviceId=randomUUID(),workflowId=randomUUID(),executionId=randomUUID();
   const adminUrl=`http://fixture-${cid}.invalid:8001`,scope=transportScopeFor(adminUrl,registeredScope),aclId=randomUUID(),keyId=randomUUID();
   const service={id:serviceId,name:`service-${serviceId}`,protocol:'http',host:'echo.fixture.invalid',port:8080,tags:['kos-ws-pay']};
   const aclPlugin={id:aclId,name:'acl',service:{id:serviceId},protocols:['http','https'],enabled:true,config:{whitelist:[`kos-portal-api-${publicationId}`]},tags:['kos-ws-pay']},keyPlugin={id:keyId,name:'key-auth',service:{id:serviceId},protocols:['http','https'],enabled:true,config:{key_names:['apikey']},tags:['kos-ws-pay']};
   let proof!:PortalPublicationProofV1;
   await sql.transaction(async tx=>{
    await tx.exec("INSERT INTO clusters(id,name,admin_url,transport_scope,execution_mode,version,status) VALUES($1,$2,$3,$4,'direct','1.5.1','healthy')",[cid,`registration-${cid}`,adminUrl,registeredScope]);
    await tx.exec("INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,'pay','Credential pay')",[wid,cid]);
    await tx.exec("INSERT INTO portal_settings(cluster_id,workspace_id,slug,name,status,published) VALUES($1,$2,$3,'Credential portal','active',true)",[cid,wid,`tenant-${cid}`]);
    await tx.exec("INSERT INTO portal_developers(id,cluster_id,workspace_id,username,email,display_name,password_hash,status) VALUES($1,$2,$3,$4,$5,'Synthetic developer',$6,'active')",[developerId,cid,wid,`dev-${developerId}`,`${developerId}@example.test`,`$2b$12$${'a'.repeat(53)}`]);
    await tx.exec("INSERT INTO portal_sessions(id,cluster_id,workspace_id,developer_id,family_id,credential_epoch,refresh_token_hash,csrf_token_hash,expires_at) VALUES($1,$2,$3,$4,$1,1,$5,$5,now()+interval '1 hour')",[sessionId,cid,wid,developerId,'a'.repeat(64)]);
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
   return{cid,wid,appId,publicationId,adminUrl,scope,proof,principal:Object.freeze({kind:'portal_developer',developerId,sessionId,credentialEpoch:1,clusterId:cid,workspaceId:wid})};
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

  await check('actual unchanged PostgreSQL16 migrations000 through008 remain the schema under test',async()=>{
   migrations=await sql.query('SELECT name,checksum FROM schema_migrations ORDER BY name');assert.equal(migrations.length,9);
   for(const row of migrations)assert.equal(createHash('sha256').update(readFileSync(`apps/console-api/src/infrastructure/migrations/${row.name}`)).digest('hex'),row.checksum);
  });
  const normal=await seedIssue();
  await check('private DB evidence validates complete approved native tuples and original raw AEAD results',async()=>{
   const evidence=await loadPortalIssueNativeEvidence(sql,secrets,{clusterId:normal.base.cid,workspaceId:normal.base.wid,grantId:normal.submitted.grant.id,executionId:normal.executionId,parentState:'executing'});
   assert.deepEqual([evidence.consumer,evidence.acl,evidence.keyCredential],normal.nativeObjects.map(item=>item.result));assert.equal(evidence.operationIds.length,3);
  });
  await check('activation without same-transaction terminal parent is rejected and entirely rolled back',async()=>{
   await rejected(()=>activate(normal,false),'23514');await pending(normal);assert.equal(nativeWrites,0);
  });
  await check('actual approved metadata activation commits exact refs with step execution and workflow terminal atomically',async()=>{
   const result=await activate(normal);assert.equal(result.state,'active');await active(normal);assert.equal(nativeWrites,0);
  });
  await check('generation-one key ciphertext remains byte-identical and its envelope contains only the original key',async()=>{
   const key=await sql.one<any>('SELECT key_secret FROM portal_credentials WHERE id=$1',[normal.originalCredential.id]);assert.equal(key.key_secret,normal.originalCredential.key_secret);
   assert.deepEqual(Object.keys(secrets.decrypt<any>(key.key_secret,portalKeyAad(normal.base.cid,normal.base.wid,normal.originalCredential.id,1))),['key']);
  });
  await check('successful first-generation evidence reconstructs Consumer and ACL without native reads',async()=>{
   const reads=nativeReads,evidence=await loadPortalGrantNativeEvidence(sql,secrets,{clusterId:normal.base.cid,workspaceId:normal.base.wid,grantId:normal.submitted.grant.id});
   assert.deepEqual(evidence.consumer,normal.nativeObjects[0].result);assert.deepEqual(evidence.acl,normal.nativeObjects[1].result);assert.equal(nativeReads,reads);
  });
  const rotation=await seedIssue();await activate(rotation);
  await check('actual rotate compiler derives original Consumer ACL from gen1 receipts and allocates a distinct key-only generation2',async()=>{
   const reads=nativeReads,old=await sql.one<any>('SELECT * FROM portal_credentials WHERE id=$1',[rotation.originalCredential.id]);
   const result=await credentials.change(rotation.base.principal,rotation.base.appId,rotation.submitted.grant.id,old.id,{clusterId:rotation.base.cid,workspaceId:rotation.base.wid,revision:old.revision,confirmed:true,confirm_name:`轮换 ${old.id}`},{idempotencyKey:`rotate-${randomUUID()}`},'rotate');
   const compiled=await plans.load(rotation.base.cid,rotation.base.wid,result.workflowId),next=await sql.one<any>('SELECT * FROM portal_credentials WHERE grant_id=$1 AND generation=2',[rotation.submitted.grant.id]);
   assert.equal(compiled.plan.kind,'portal-credential-rotate');assert.equal(compiled.plan.steps.length,3);assert.equal(compiled.plan.steps[0].credentialKind,'key-auth');assert.equal(compiled.plan.steps[0].mutationAction,'create');assert.equal(compiled.plan.steps[1].mutationAction,'delete');assert.equal(next.previous_credential_id,old.id);assert.notEqual(next.kong_id,old.kong_id);assert.deepEqual(Object.keys(secrets.decrypt<any>(next.key_secret,portalKeyAad(rotation.base.cid,rotation.base.wid,next.id,2))),['key']);
   assert.equal((await sql.one<any>('SELECT key_secret FROM portal_credentials WHERE id=$1',[old.id])).key_secret,rotation.originalCredential.key_secret);assert.equal(nativeReads,reads);assert.equal(nativeWrites,0);
  });
  const revocation=await seedIssue();await activate(revocation);
  await check('actual revoke compiler derives Consumer ACL from gen1 evidence without cached envelope objects or native reads',async()=>{
   const reads=nativeReads,old=await sql.one<any>('SELECT * FROM portal_credentials WHERE id=$1',[revocation.originalCredential.id]);
   const result=await credentials.change(revocation.base.principal,revocation.base.appId,revocation.submitted.grant.id,old.id,{clusterId:revocation.base.cid,workspaceId:revocation.base.wid,revision:old.revision,confirmed:true,confirm_name:`吊销 ${old.id}`},{idempotencyKey:`revoke-${randomUUID()}`},'revoke');
   const compiled=await plans.load(revocation.base.cid,revocation.base.wid,result.workflowId);assert.equal(compiled.plan.kind,'portal-credential-revoke');assert.equal(compiled.plan.steps.length,2);assert.equal(compiled.plan.steps[0].mutationAction,'delete');assert.equal(compiled.plan.steps[0].entityId,old.kong_id);assert.equal(compiled.plan.steps[1].handler,'portal.credential.revoke');assert.equal(nativeReads,reads);assert.equal(nativeWrites,0);
  });
  const broken=await seedIssue();
  const evidenceInput={clusterId:broken.base.cid,workspaceId:broken.base.wid,grantId:broken.submitted.grant.id,executionId:broken.executionId,parentState:'executing' as const};
  const rollbackFault=async(corrupt:(tx:DbService)=>Promise<unknown>,verify:(tx:DbService)=>Promise<void>)=>{
   const rollback=new Error('INTENTIONAL_FIXTURE_ROLLBACK');try{await sql.transaction(async tx=>{await corrupt(tx);await verify(tx);throw rollback;});}catch(error){if(error!==rollback)throw error;}await pending(broken);
  };
  await check('copied native result ciphertext with another operation AAD rejects private evidence and rolls back',async()=>{
   await rollbackFault(tx=>tx.exec(`UPDATE mutation_operations SET result_secret=(SELECT result_secret FROM mutation_operations WHERE workflow_step_id=$2) WHERE workflow_step_id=$1`,[broken.plan.steps[0].id,broken.plan.steps[1].id]),tx=>rejected(()=>loadPortalIssueNativeEvidence(tx,secrets,evidenceInput),'PORTAL_CREDENTIAL_PROOF_INVALID'));
  });
  await check('tampered native after fingerprint rejects private evidence without erasing succeeded rows',async()=>{
   await rollbackFault(tx=>tx.exec('UPDATE workflow_steps SET after_fingerprint=$2 WHERE id=$1',[broken.plan.steps[0].id,'e'.repeat(64)]),tx=>rejected(()=>loadPortalIssueNativeEvidence(tx,secrets,evidenceInput),'PORTAL_CREDENTIAL_PROOF_INVALID'));
  });
  await check('unknown native result is rejected despite two other completed native receipts',async()=>{
   await rollbackFault(tx=>tx.exec("UPDATE mutation_operations SET state='uncertain',remote_completed=false WHERE workflow_step_id=$1",[broken.plan.steps[0].id]),async tx=>{
    await rejected(()=>loadPortalIssueNativeEvidence(tx,secrets,evidenceInput),'PORTAL_CREDENTIAL_PROOF_INVALID');
   });
  });
  await check('private evidence rejects a different workspace and preserves immutable key AAD isolation',async()=>{
   await rejected(()=>loadPortalIssueNativeEvidence(sql,secrets,{...evidenceInput,workspaceId:randomUUID()}),'PORTAL_CREDENTIAL_PROOF_INVALID');
   await assert.rejects(async()=>secrets.decrypt(broken.originalCredential.key_secret,portalKeyAad(randomUUID(),broken.base.wid,broken.originalCredential.id,1)));await pending(broken);
  });
  await check('credential activation grant CAS failure rolls back newly bound key refs and state',async()=>{
   await http(broken,()=>handler.prepare!(input(broken)));
   await rollbackFault(tx=>tx.exec('UPDATE portal_application_grants SET revision=revision+1,updated_at=now() WHERE id=$1',[broken.submitted.grant.id]),tx=>rejected(()=>handler.apply({...input(broken),transaction:tx}),'REVISION_CONFLICT'));
  });
  const forbidden:any=new Proxy({},{get:()=>async()=>{nativeWrites++;throw new Error('NATIVE_DISPATCH_FORBIDDEN');}});
  const boundary=new PortalAuthBoundaryService(sql,secrets,kong,execution,workspaces,approved);
  const workflow=new WorkflowService(sql,redis,secrets,kong,execution,authz,audit,forbidden,forbidden,forbidden,workspaces,plans,registry,approved,boundary);
  const uncertain=async(f:Issue)=>{
   await sql.transaction(async tx=>{
    await tx.exec("UPDATE workflow_steps SET state='uncertain',error_code='WORKFLOW_EXECUTION_FAILED',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1",[f.metadata.id]);
    await tx.exec("UPDATE workflow_executions SET state='uncertain',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1",[f.executionId]);
    await tx.exec("UPDATE workflows SET state='uncertain',revision=revision+1,updated_at=now() WHERE id=$1",[f.plan.workflowId]);
   });
   return{revision:(await plans.load(f.base.cid,f.base.wid,f.plan.workflowId)).row.revision,planHash:f.loaded.row.plan_hash,executionId:f.executionId,confirmed:true,confirm_name:'portal-credential-issue'};
  };
  const reconcile=(f:Issue,body:any,key=f.actor.idempotencyKey)=>http(f,()=>workflow.reconcileMetadata(f.base.cid,f.plan.workflowId,body,{...f.actor,idempotencyKey:key}),key);
  const recovered=await seedIssue(),recoveryBody=await uncertain(recovered);
  await check('formal metadata recovery rejects fresh idempotency key and changed revision before any activation',async()=>{
   await rejected(()=>reconcile(recovered,recoveryBody,`fresh-${randomUUID()}`),'PORTAL_RECOVERY_REQUEST_MISMATCH');
   await rejected(()=>reconcile(recovered,{...recoveryBody,revision:recoveryBody.revision+1}),'PORTAL_RECOVERY_NOT_ELIGIBLE');await pending(recovered,'uncertain');
  });
  await check('current private recovery and full authentication boundary recover only original uncertain metadata',async()=>{
   const before=await sql.query<any>('SELECT id,state,remote_completed,result_secret FROM mutation_operations WHERE workflow_id=$1 ORDER BY id',[recovered.plan.workflowId]);
   const receipt=await reconcile(recovered,recoveryBody);assert.equal(receipt.state,'succeeded');assert.equal(receipt.executionId,recovered.executionId);assert(receipt.steps.every(step=>step.state==='succeeded'&&step.remoteCompleted));await active(recovered);
   assert.deepEqual(await sql.query('SELECT id,state,remote_completed,result_secret FROM mutation_operations WHERE workflow_id=$1 ORDER BY id',[recovered.plan.workflowId]),before);assert.equal(nativeWrites,0);
  });
  await check('same original metadata recovery request replays durable success without audit or native duplication',async()=>{
   const before=await sql.one<any>('SELECT count(*)::int AS n FROM audit_events WHERE cluster_id=$1',[recovered.base.cid]);
   const first=await reconcile(recovered,recoveryBody),second=await reconcile(recovered,recoveryBody);assert.deepEqual(second,first);
   assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM audit_events WHERE cluster_id=$1',[recovered.base.cid])).n,before.n);assert.equal((await sql.query("SELECT id FROM workflow_events WHERE workflow_id=$1 AND action='execution.reconcile-metadata'",[recovered.plan.workflowId])).length,1);assert.equal(nativeWrites,0);
  });
  await check('successful recovery cannot be claimed by a changed body or a different execution UUID',async()=>{
   await rejected(()=>reconcile(recovered,{...recoveryBody,revision:recoveryBody.revision+1}),'IDEMPOTENCY_CONFLICT');
   await rejected(()=>reconcile(recovered,{...recoveryBody,executionId:randomUUID()}),'PORTAL_RECOVERY_REQUEST_MISMATCH');await active(recovered);
  });
  const auditRollback=await seedIssue(),auditRollbackBody=await uncertain(auditRollback);
  await check('process failure after real activation audit rolls back key grant step execution workflow and audit together',async()=>{
   const append=audit.append.bind(audit),fault=new Error('SYNTHETIC_AFTER_ACTIVATION_FAULT'),before=await sql.one<any>('SELECT count(*)::int AS n FROM audit_events WHERE cluster_id=$1',[auditRollback.base.cid]);
   audit.append=async(event:any,tx?:DbService)=>{const result=await append(event,tx);if(event.action==='portal.credential.activate')throw fault;return result;};
   try{await assert.rejects(()=>reconcile(auditRollback,auditRollbackBody),error=>error===fault);}finally{audit.append=append;}
   await pending(auditRollback,'uncertain');assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM audit_events WHERE cluster_id=$1',[auditRollback.base.cid])).n,before.n);
   assert.equal((await sql.one<any>('SELECT state FROM workflow_steps WHERE id=$1',[auditRollback.metadata.id])).state,'uncertain');
  });
  await check('same failed recovery request can safely reconcile after transaction rollback without native replay',async()=>{await reconcile(auditRollback,auditRollbackBody);await active(auditRollback);assert.equal(nativeWrites,0);});
  const lostAck=await seedIssue(),lostAckBody=await uncertain(lostAck);
  await check('lost SQL commit acknowledgement preserves committed successful activation for original-key replay',async()=>{
   const transaction=sql.transaction.bind(sql),fault=new Error('SYNTHETIC_LOST_COMMIT_ACK');let injected=false;
   sql.transaction=async<T>(fn:(tx:DbService)=>Promise<T>)=>{const result=await transaction(fn);if(!injected){injected=true;throw fault;}return result;};
   try{await assert.rejects(()=>reconcile(lostAck,lostAckBody),error=>error===fault);}finally{sql.transaction=transaction;}
   assert(injected);await active(lostAck);const receipt=await reconcile(lostAck,lostAckBody);assert.equal(receipt.state,'succeeded');assert.equal(receipt.executionId,lostAck.executionId);assert.equal(nativeWrites,0);
  });
  const expiredSession=await seedIssue(),expiredBody=await uncertain(expiredSession);
  await check('revoked current console session refuses metadata recovery while original native facts remain intact',async()=>{
   await sql.exec('UPDATE auth_sessions SET revoked_at=now() WHERE id=$1',[expiredSession.sessionId]);await rejected(()=>reconcile(expiredSession,expiredBody),'SESSION_EXPIRED');await pending(expiredSession,'uncertain');
  });
  const unknownNative=await seedIssue(),unknownBody=await uncertain(unknownNative);
  await check('formal recovery refuses a genuinely uncertain native receipt without changing its durable state or activation',async()=>{
   await sql.exec("UPDATE mutation_operations SET state='uncertain',remote_completed=false WHERE workflow_step_id=$1",[unknownNative.plan.steps[0].id]);
   const before=await sql.query('SELECT id,state,remote_completed,result_secret FROM mutation_operations WHERE workflow_id=$1 ORDER BY id',[unknownNative.plan.workflowId]);
   await rejected(()=>reconcile(unknownNative,unknownBody),'PORTAL_CREDENTIAL_PROOF_INVALID');
   assert.deepEqual(await sql.query('SELECT id,state,remote_completed,result_secret FROM mutation_operations WHERE workflow_id=$1 ORDER BY id',[unknownNative.plan.workflowId]),before);
   assert.equal((await sql.one<any>('SELECT state FROM portal_credentials WHERE id=$1',[unknownNative.originalCredential.id])).state,'pending');assert.equal((await sql.one<any>('SELECT state FROM workflows WHERE id=$1',[unknownNative.plan.workflowId])).state,'uncertain');assert.equal(nativeWrites,0);
  });
  const changedRefs=await seedIssue(),changedRefsBody=await uncertain(changedRefs);
  await check('formal recovery refuses revoked current ACL recovery reference while retaining three successful native facts',async()=>{
   await sql.exec("UPDATE credential_refs SET state='revoked',updated_at=now() WHERE cluster_id=$1 AND credential_type='acls'",[changedRefs.base.cid]);
   await rejected(()=>reconcile(changedRefs,changedRefsBody),'PORTAL_RECOVERY_REF_INVALID');await pending(changedRefs,'uncertain');assert.equal(nativeWrites,0);
  });
  const otherActor=await seedIssue(),otherBody=await uncertain(otherActor);
  await check('another fully authenticated platform actor cannot recover a different original execution owner',async()=>{
   const userId=randomUUID(),sessionId=randomUUID();await sql.exec("INSERT INTO users(id,username,password_hash,super_admin,status) SELECT $1,$2,password_hash,true,'active' FROM users WHERE id=$3",[userId,`other-${userId}`,admin.id]);await sql.exec("INSERT INTO auth_sessions(id,user_id,credential_epoch,expires_at) VALUES($1,$2,1,now()+interval '1 hour')",[sessionId,userId]);
   const caller={...otherActor,sessionId,actor:{...otherActor.actor,user:{id:userId,username:`other-${userId}`,superAdmin:true}}};
   await rejected(()=>reconcile(caller,otherBody),'PORTAL_RECOVERY_REQUEST_MISMATCH');await pending(otherActor,'uncertain');assert.equal(nativeWrites,0);
  });
  await check('all activation rotation revoke and formal recovery paths send zero native mutation packets',async()=>{assert.equal(nativeWrites,0);});
 }catch(error){failureCode=safeCode(error);throw error;}finally{
  mkdirSync('artifacts/M6',{recursive:true});const artifact=`artifacts/M6/portal-credential-activation-recovery-postgres-${runId}.json`;
  writeFileSync(artifact,JSON.stringify({milestone:'M6',status:failureCode?'FAIL':'PASS',failureCode,database:'disposable PostgreSQL16; unchanged migrations000-008',migrations,actual:['WorkflowPlans.persist/load','PortalCredentials request/prepare/inspect/apply/rotate/revoke compiler','Portal native evidence decoder','AuthorizationService','KongExecutionContextService private recovery','ApprovedWorkflowExecutionService','PortalAuthBoundaryService complete graph','WorkflowService.reconcileMetadata','AES-GCM contexts','CredentialStoreService','real reciprocal native FKs','real identity/visible-state triggers','atomic transaction rollback and commit'],fixtures:['read-only native Gateway responses; Kong transport and NativeKongPolicy not exercised','developer identity validation','Redis leases','unused native dispatch stubs'],nativeWrites,nativeReads,checks,passed:checks.filter(item=>item.passed).length,total:checks.length},null,2));
  if(db)await db.onModuleDestroy();try{execFileSync('docker',['rm','-f',container],{stdio:'ignore'});}catch{}
  process.stdout.write(JSON.stringify({artifact,status:failureCode?'FAIL':'PASS',passed:checks.filter(item=>item.passed).length,total:checks.length,nativeWrites})+'\n');
 }
}
main().catch(()=>{process.stderr.write('Isolated activation recovery regression failed; safe artifact retained.\n');process.exitCode=1;});
