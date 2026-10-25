import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import assert from 'node:assert/strict';
import {ForbiddenException,HttpException,Logger} from '../../apps/console-api/node_modules/@nestjs/common';
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {compileFunction} from 'node:vm';
import {provisionRuntimeRole} from '../../apps/console-api/src/infrastructure/migrate';
import {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import {AuditService} from '../../apps/console-api/src/modules/audit/audit.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {PortalAuthService} from '../../apps/console-api/src/modules/portal-auth/portal-auth.service';
import type {PortalPrincipal} from '../../apps/console-api/src/modules/portal-auth/portal-auth.types';
import {PortalCredentialsService} from '../../apps/console-api/src/modules/portal/portal-credentials.service';
import {PortalNativeService} from '../../apps/console-api/src/modules/portal/portal-native.service';
import {deriveImpact} from '../../apps/console-api/src/modules/mutations/mutation-impact';
import {getRejectedIssueAbandonment,loadRejectedIssueAbandonmentFacts,persistRejectedIssueAbandonment,rejectedIssueProofAad} from '../../apps/console-api/src/modules/portal/portal-failed-issue-abandonment';
import {portalKeyAad,publicationProofAad,type PortalPublicationProofV1} from '../../apps/console-api/src/modules/portal/portal-proof';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WorkflowService} from '../../apps/console-api/src/modules/workflows/workflow.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import {snapshotAad,type WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Failed-issue abandonment proof uses disposable PostgreSQL with actual schema and compiler.
 * Principal identity validation, Redis leases, authorization and Gateway are
 * explicit fixtures. This does not replace real HTTP authentication or Kong. */
async function main():Promise<void>{
 Logger.overrideLogger(false);
 const container=`kongos-m6-abandon-${randomUUID().slice(0,8)}`,runId=new Date().toISOString().replace(/[:.]/g,'-');
 const runtimeBaseline=process.env.M6_ABANDONMENT_RUNTIME_BASELINE==='true';
 const checks:Array<{name:string;passed:boolean;errorCode?:string;column?:string}>=[];
 let db:DbService|undefined,runtime:DbService|undefined,nativeCalls=0,consoleContexts=0,fixtureNativeReads=0,failureCode:string|undefined,allowWorkflowAuthorization=false;
 let helperSourceHash:string|undefined,migrationSourceHash:string|undefined,serverVersion:string|undefined,failurePosition:number|undefined,failureMigrationLine:number|undefined;
 let securityQuerySourceHash:string|undefined,securityQueryHash:string|undefined;
 const runtimeTransactionErrorCodes:string[]=[];let runtimeFormalCalls=0,ownerFormalCalls=0;
 let runtimeAfterCertificateHook:((tx:DbService)=>Promise<void>)|undefined;
 const lateFenceEvidence:Array<Record<string,unknown>>=[];
 let runtimeBaselineEvidence:Record<string,unknown>|undefined;
 let runtimeRoleEvidence:Record<string,unknown>|undefined;
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
  const authz:any={},redis:any={withLock:async(_key:string,fn:()=>Promise<any>)=>fn(),assertLeaseOwnership:async()=>{}};
  const kong:any={request:async()=>{nativeCalls++;throw new Error('NATIVE_NETWORK_FORBIDDEN');},transportScope:async()=>{nativeCalls++;throw new Error('NATIVE_NETWORK_FORBIDDEN');}};
  const execution:any={runActor:async()=>{consoleContexts++;throw new Error('CONSOLE_CONTEXT_FORBIDDEN');},runInternalRead:async()=>{consoleContexts++;throw new Error('CONSOLE_CONTEXT_FORBIDDEN');}};
  const native=new PortalNativeService(sql,secrets,kong,execution,authz,workspaces);
  const auth=new PortalAuthService(sql,redis,secrets,audit,authz,{assertStep:async()=>{throw new Error('APPROVED_CAPABILITY_FORBIDDEN');}});
  // Explicit fake identity boundary; the inherited actual executeMetadata still
  // checks real sessions/tenant rows and persists the real durable SQL ledger.
  auth.assertCurrent=async(principal:PortalPrincipal,tx:DbService=sql)=>{
   const row=await tx.one<any>('SELECT * FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND status=\'active\'',[principal.developerId,principal.clusterId,principal.workspaceId]);
   assert(row);return{id:row.id,clusterId:row.cluster_id,workspaceId:row.workspace_id,username:row.username,email:row.email,displayName:row.display_name,status:row.status,revision:row.revision,mustChangePassword:false,createdAt:new Date(row.created_at).toISOString()};
  };
  const store:any={get:async()=>{throw new Error('SECRET_HISTORY_LOOKUP_FORBIDDEN');}},approved:any={assertSubject:async()=>{if(!allowWorkflowAuthorization)throw new Error('CONSOLE_APPROVAL_FORBIDDEN');},canIssueActivationRecovery:async()=>false};
  const credentials=new PortalCredentialsService(sql,secrets,authz,audit,auth,store,approved,plans,registry,native);
  const recordedSchemas=JSON.parse(readFileSync('artifacts/M2/credential-schema-capabilities.json','utf8')).schemas;
  const consumerSchema=JSON.parse(readFileSync('tests/fixtures/kong-1.5.1/schema-consumers.json','utf8'));
  interface Fixture{cid:string;wid:string;appId:string;publicationId:string;adminUrl:string;scope:string;proof:PortalPublicationProofV1;principal:PortalPrincipal;}
  const fixture=async(registeredScope:string|null=null):Promise<Fixture>=>{
   const cid=randomUUID(),wid=randomUUID(),developerId=randomUUID(),sessionId=randomUUID(),appId=randomUUID(),publicationId=randomUUID(),serviceId=randomUUID(),workflowId=randomUUID(),executionId=randomUUID();
   const adminUrl=`http://fixture-${cid}.invalid:8001`,scope=transportScopeFor(adminUrl,registeredScope),aclId=randomUUID(),keyId=randomUUID();
   const service={id:serviceId,name:`service-${serviceId}`,protocol:'http',host:'echo.fixture.invalid',port:8080,tags:['kos-ws-pay']};
   const aclPlugin={id:aclId,name:'acl',service:{id:serviceId},enabled:true,config:{whitelist:[`kos-portal-api-${publicationId}`]},tags:['kos-ws-pay']},keyPlugin={id:keyId,name:'key-auth',service:{id:serviceId},enabled:true,config:{key_names:['apikey']},tags:['kos-ws-pay']};
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
   return{cid,wid,appId,publicationId,adminUrl,scope,proof,principal:Object.freeze({kind:'portal_developer',developerId,sessionId,credentialEpoch:1,clusterId:cid,workspaceId:wid})};
  };
  const request=(f:Fixture,key=`credential-${randomUUID()}`)=>credentials.request(f.principal,{clusterId:f.cid,workspaceId:f.wid,applicationId:f.appId,publicationId:f.publicationId,reason:'Synthetic integration request'},{idempotencyKey:key,requestId:randomUUID(),ip:'192.0.2.17'});
  const counts=async(f:Fixture)=>(await sql.one<any>(`SELECT (SELECT count(*)::int FROM portal_application_grants WHERE application_id=$1) AS grants,(SELECT count(*)::int FROM portal_credentials WHERE developer_id=$2) AS credentials,(SELECT count(*)::int FROM workflows WHERE requester_developer_id=$2) AS workflows,(SELECT count(*)::int FROM mutation_operations WHERE cluster_id=$3) AS mutations`,[f.appId,f.principal.developerId,f.cid]))!;

  const seedRejectedIssue=async()=>{
   const base=await fixture(),submitted=await request(base),loaded=await plans.load(base.cid,base.wid,submitted.workflowId);
   const plan=loaded.plan,executionId=randomUUID(),operationId=randomUUID(),sessionId=randomUUID(),executionKey=`abandon-execution-${randomUUID()}`;
   assert.equal(plan.kind,'portal-credential-issue');assert.equal(plan.approvalRequired,true);assert.equal(plan.steps.length,4);
   const first=plan.steps[0];assert.equal(first.entityType,'consumers');assert.equal(first.mutationAction,'create');
   const credential=(await sql.one<any>('SELECT * FROM portal_credentials WHERE grant_id=$1',[submitted.grant.id]))!;
   assert.deepEqual(Object.keys(secrets.decrypt<any>(credential.key_secret,portalKeyAad(base.cid,base.wid,credential.id,1))),['key']);
   await sql.transaction(async tx=>{
    await tx.exec("INSERT INTO auth_sessions(id,user_id,credential_epoch,expires_at) VALUES($1,$2,1,now()+interval '1 hour')",[sessionId,admin.id]);
    await tx.exec("INSERT INTO workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,approver_id,decision,idempotency_key) VALUES($1,$2,$3,1,$4,1,$5,'approve',$6)",[base.cid,base.wid,plan.workflowId,loaded.row.plan_hash,admin.id,`approval-${executionId}`]);
    await tx.exec("UPDATE workflow_stages SET state='approved',completed_at=now(),updated_at=now() WHERE workflow_id=$1",[plan.workflowId]);
    await tx.exec("UPDATE workflows SET state='failed',approved_by=$2,approved_at=now(),revision=revision+1,updated_at=now() WHERE id=$1",[plan.workflowId,admin.id]);
    const snapshot={version:1,workflowId:plan.workflowId,executionId,clusterId:base.cid,workspaceId:base.wid,planRevision:1,planHash:loaded.row.plan_hash,capturedAt:new Date().toISOString(),objects:[...plan.prerequisites.map(item=>({type:item.type,id:item.id,path:item.path,before:item.before,absent:false,fingerprint:item.fingerprint})),...plan.steps.flatMap(item=>item.nativeRequests.map(request=>({type:request.nativeType,id:request.nativeId!,path:`${request.canonicalPath}/${request.nativeId}`,before:null,absent:true,fingerprint:secrets.fingerprint(null)})))]};
    await tx.exec(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,snapshot_state,snapshot_secret,snapshot_hash,claim_token_hash,idempotency_key,expires_at,completed_at)
     VALUES($1,$2,$3,$4,1,$5,'direct',true,$6,$6,'failed','ready',$7,$8,$9,$10,now()+interval '30 minutes',now())`,[executionId,base.cid,base.wid,plan.workflowId,loaded.row.plan_hash,admin.id,secrets.encrypt(snapshot,snapshotAad(base.cid,base.wid,plan.workflowId,executionId)),secrets.fingerprint(snapshot),secrets.fingerprint({claim:executionId}),executionKey]);
    const requestHash=secrets.fingerprint({actor:admin.id,clusterId:base.cid,workspaceId:base.wid,entityType:first.entityType,entityId:null,action:first.mutationAction,payload:first.mutationPayload,parentId:null,credentialKind:null,approvedWorkflow:{workflowId:plan.workflowId,executionId,planRevision:1,planHash:loaded.row.plan_hash,stepId:first.id,beforeHmac:first.beforeFingerprint}});
    await tx.exec(`INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,entity_type,transport_scope,before_secret,payload_secret,remote_started,remote_completed,error_code,safe_result,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id,impact)
     VALUES($1,$2,$3,$4,'create',$5,$6,'failed','consumers',$7,$8,$9,true,false,'KONG_VALIDATION_ERROR',$10::jsonb,$11,$12,1,$13,$14,$15::jsonb)`,[operationId,base.cid,base.wid,admin.id,first.mutationIdempotencyKey,requestHash,base.scope,secrets.encrypt(null,`mutation:${operationId}:before`),secrets.encrypt(first.mutationPayload,`mutation:${operationId}:payload`),JSON.stringify({code:'KONG_VALIDATION_ERROR',state:'failed'}),plan.workflowId,executionId,loaded.row.plan_hash,first.id,JSON.stringify(deriveImpact({entityType:'consumers',entityId:null,action:'create',payload:first.mutationPayload}))]);
    await tx.exec("UPDATE workflow_steps SET state='failed',operation_id=$2,error_code='KONG_VALIDATION_ERROR',safe_result=$3::jsonb,started_at=now(),completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1",[first.id,operationId,JSON.stringify({nativeOperationId:operationId,remoteStarted:true,remoteCompleted:false})]);
   });
   assert.deepEqual(await counts(base),{grants:1,credentials:1,workflows:1,mutations:1});
   assert.equal((await sql.one<any>('SELECT state FROM portal_credentials WHERE id=$1',[credential.id])).state,'pending');
   return{base,submitted,loaded,plan,executionId,operationId,sessionId,executionKey,credential};
  };
  type FailedIssue=Awaited<ReturnType<typeof seedRejectedIssue>>;
  const rawCredentialRef=async(f:FailedIssue,tx:DbService=sql)=>{
   const id=randomUUID();
   await tx.exec("INSERT INTO credential_refs(id,cluster_id,consumer_id,credential_type,kong_id,payload_secret,masked_summary,recovery_capability) VALUES($1,$2,$3,'key-auth',$4,$5,'{}'::jsonb,'fixture')",[id,f.base.cid,f.credential.consumer_id,f.credential.kong_id,secrets.encrypt({fixture:true},`credential-ref:${id}`)]);
   return id;
  };
  const rawNullCreate=async(f:FailedIssue,related:boolean,tx:DbService=sql)=>{
   const id=randomUUID(),body={id:related?f.credential.consumer_id:randomUUID(),username:`other-${randomUUID()}`};
   await tx.exec(`INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,entity_type,transport_scope,before_secret,payload_secret,remote_started,remote_completed,error_code,impact)
    VALUES($1,$2,$3,$4,'create',$5,$6,'failed','consumers',$7,$8,$9,true,false,'KONG_VALIDATION_ERROR',$10::jsonb)`,[id,f.base.cid,f.base.wid,admin.id,`null-native-${id}`,secrets.fingerprint({fixture:id}),f.base.scope,secrets.encrypt(null,`mutation:${id}:before`),secrets.encrypt(body,`mutation:${id}:payload`),JSON.stringify(deriveImpact({entityType:'consumers',entityId:null,action:'create',payload:body}))]);
   return id;
  };
  const deferred=()=>{let resolve!:()=>void;const promise=new Promise<void>(done=>{resolve=done;});return{promise,resolve};};
  const lockBlocked=async(pid:number)=>{
   for(let n=0;n<100;n++){
    const row=await sql.one<any>('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1',[pid]);if(row?.wait_event_type==='Lock')return;
    await new Promise(resolve=>setTimeout(resolve,10));
   }
   throw new Error('EXPECTED_ACTUAL_DATABASE_LOCK_WAIT');
  };
  const scope=(f:FailedIssue)=>({clusterId:f.base.cid,workspaceId:f.base.wid,grantId:f.submitted.grant.id,workflowId:f.plan.workflowId,executionId:f.executionId});
  const facts=(f:FailedIssue,tx:DbService=sql)=>loadRejectedIssueAbandonmentFacts(tx,scope(f));
  // Native absence and current caller authorization are explicitly synthetic
  // classifier inputs here. This test proves the DB constructor, not HTTP/Kong.
  const abandon=async(f:FailedIssue,tx:DbService=sql,overrides:Record<string,unknown>={})=>{
   const original=await facts(f,tx);
   assert.equal(await tx.exec("UPDATE portal_application_grants SET state='disabled',reservation_released_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND reservation_released_at IS NULL",[original.grant.id,original.grant.revision]),1);
   const receipt=await audit.append({actorId:admin.id,actorType:'user',clusterId:f.base.cid,workspaceId:f.base.wid,entityType:'portal_application_grants',entityId:original.grant.id,workflowId:f.plan.workflowId,action:'portal.issue.abandon-rejected',before:{id:original.grant.id,state:original.grant.state,revision:original.grant.revision},after:{id:original.grant.id,state:'disabled',revision:original.grant.revision+1,reservationReleased:true},result:'success',requestId:'isolated-abandonment'},tx);
   const publication=(await tx.one<any>('SELECT published_revision FROM portal_publications WHERE id=$1',[f.base.publicationId]))!;
   const publicationProof=(await tx.one<any>('SELECT publication_proof_hmac FROM portal_publication_proofs WHERE publication_id=$1 AND publication_revision=1',[f.base.publicationId]))!;
   const proof={version:1 as const,...scope(f),planRevision:f.loaded.row.plan_revision,planHash:f.loaded.row.plan_hash,actorId:admin.id,sessionId:f.sessionId,transportScope:f.base.scope,observedAt:new Date().toISOString(),consumerId:f.credential.consumer_id,consumerAbsent:true as const,aclId:original.grant.acl_id,aclAbsent:true as const,keyId:f.credential.kong_id,keyAbsent:true as const,clusterRevision:1,workspaceRevision:1,serviceId:f.base.proof.serviceId,serviceFingerprint:secrets.fingerprint(f.base.proof.service),publicationId:f.base.publicationId,publicationRevision:publication.published_revision,publicationProofHmac:publicationProof.publication_proof_hmac,factsHash:original.factsHash,...(overrides.proofChanges as object??{})};
   return persistRejectedIssueAbandonment(tx,secrets,{...scope(f),planRevision:f.loaded.row.plan_revision,planHash:f.loaded.row.plan_hash,failedStepId:f.plan.steps[0].id,failedOperationId:f.operationId,actorId:admin.id,sessionId:f.sessionId,originalExecutionKey:f.executionKey,requestHash:secrets.fingerprint({test:'abandon',...scope(f)}),expectedGrantRevision:original.grant.revision,factsHash:original.factsHash,proof,auditReceipt:receipt,...overrides} as any);
  };
  const untouched=async(f:FailedIssue)=>{
   const g=(await sql.one<any>('SELECT * FROM portal_application_grants WHERE id=$1',[f.submitted.grant.id]))!,c=(await sql.one<any>('SELECT * FROM portal_credentials WHERE id=$1',[f.credential.id]))!;
   assert.equal(g.reservation_released_at,null);assert.equal(g.state,'pending');assert.equal(g.revision,1);assert.equal(c.state,'pending');assert.equal(c.key_secret,f.credential.key_secret);assert.equal(c.credential_ref_id,null);assert.equal(c.issue_operation_id,null);
   assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM portal_failed_issue_abandonments WHERE grant_id=$1',[g.id])).n,0);
   assert.equal((await sql.one<any>("SELECT count(*)::int AS n FROM audit_events WHERE entity_id=$1 AND action='portal.issue.abandon-rejected'",[g.id])).n,0);
  };

  await check('actual PostgreSQL16 applies unchanged000-008 plus the new M6 SQL009 migration only',async()=>{
   serverVersion=(await sql.one<any>('SHOW server_version')).server_version;assert.match(serverVersion!,/^16\./);
   migrations=await sql.query<{name:string;checksum:string}>('SELECT name,checksum FROM schema_migrations ORDER BY name');
   const baseline:Record<string,string>={
    '000_m0.sql':'02f171ea1ff6dd64d12840e36681b315cec9665552aa3b8acdf72319a1c2fd96',
    '001_m1.sql':'ef2e738577ae5321ddfdbd69c315a820e7dfa2bfcbef59176a2a8b9491b3fee6',
    '002_m1_index.sql':'bd67be44dd80554872943d8ef3bac85757f2790f965e31a9ff996e380b1f7663',
    '003_m1_index_cycles.sql':'dc695f4006e0839104df4b4108fc4426ca0670d6c7fa4083b1f29032ad751bf6',
    '004_m3_workspaces.sql':'263301537a1bbbdce62fafe44bc9a40589f6b450c9f4f0c787879a252752d501',
    '005_m4_iam.sql':'1ab35fdca5b4724af18f1287936c6eced21061ae5605f19b455acabc69f06d22',
    '006_m4_child_navigation.sql':'d5e89915b7192efcdb32e3a9b729543d44c8691d3cc957fc457b9bc1a42e6c01',
    '007_m5_metrics.sql':'e301a76f25c74a72e6599e1c735b152b981bd4df20bfc6f57b3b18c2f59887bf',
    '008_m6_portal.sql':'241444c9f85ea30bc09f6a4a93ded051acc5692317068a1e68814c92d9f520bc'};
   assert.equal(migrations.length,10);assert.equal(migrations.at(-1)?.name,'009_m6_failed_issue_abandonment.sql');
   for(const migration of migrations){assert.equal(migration.checksum,createHash('sha256').update(readFileSync(`apps/console-api/src/infrastructure/migrations/${migration.name}`)).digest('hex'));if(baseline[migration.name])assert.equal(migration.checksum,baseline[migration.name]);}
   migrationSourceHash=migrations.at(-1)!.checksum;
  });
  helperSourceHash=createHash('sha256').update(readFileSync('apps/console-api/src/modules/portal/portal-failed-issue-abandonment.ts')).digest('hex');
  // Compile only the actual exported SQL literal. Importing the full live
  // helper would load its private runtime checkpoint dependencies unnecessarily.
  const securityQuerySource='tests/security/lib/m6-failed-issue-continuation.mjs';
  const securitySource=readFileSync(securityQuerySource,'utf8');
  securityQuerySourceHash=createHash('sha256').update(securitySource).digest('hex');
  const initializer=/export const FAILED_ISSUE_DATABASE_SQL\s*=\s*(`[^`]*`);/.exec(securitySource)?.[1];
  assert(initializer,'ACTUAL_EXPORTED_QUERY_LITERAL_REQUIRED');
  const securityQuery=compileFunction(`return ${initializer};`)() as string;
  assert.equal(typeof securityQuery,'string');
  assert.deepEqual([...new Set(securityQuery.match(/\$\d+/g))].sort(),['$1','$2','$3','$4','$5','$6','$7','$8','$9']);
  securityQueryHash=createHash('sha256').update(securityQuery).digest('hex');
  const actualSecurityProof=async(f:FailedIssue)=>{
   const rows=await sql.query<any>(securityQuery,[f.credential.id,f.submitted.grant.id,f.base.cid,f.base.wid,f.plan.workflowId,f.executionId,f.executionKey,[f.base.cid],[f.base.wid]]);
   assert.equal(rows.length,1);const row=rows[0];
   assert.equal(row.consumer_id,f.credential.consumer_id);assert.equal(row.acl_id,f.plan.steps[1].nativeRequests[0].nativeId);assert.equal(row.kong_id,f.credential.kong_id);
   assert.equal(row.credential_state,'pending');assert.equal(row.generation,1);
   for(const field of ['credential_ref_id','issue_operation_id','recycle_entry_id','revoked_at','last_revealed_at','current_credential_id','acl_credential_ref_id'])assert.equal(row[field],null);
   assert.equal(row.current_generation,0);assert.equal(row.workflow_state,'failed');assert.equal(row.execution_state,'failed');assert.equal(row.execution_actor_id,admin.id);assert.equal(row.plan_hash,f.loaded.row.plan_hash);assert.equal(row.workflow_revision,f.loaded.row.revision+1);
   assert.equal(row.native_operation_count,1);assert.equal(row.unexpected_native_results,0);assert.equal(row.credential_refs,0);assert.equal(row.native_unresolved,0);assert.equal(row.portal_unresolved,0);
   // This disposable tenant has only the rejected grant. The real continuation
   // separately protects its previously active first grant and expects two rows.
   assert.equal(row.scope_grants,1);assert.equal(row.scope_credentials,1);
   assert.equal(row.cipher_sha,createHash('sha256').update(f.credential.key_secret,'utf8').digest('hex'));
   return row;
  };
  const nativeHistory=(f:FailedIssue)=>sql.one<any>(`SELECT
   (SELECT row_to_json(w) FROM workflows w WHERE id=$1) AS workflow,
   (SELECT row_to_json(v) FROM workflow_versions v WHERE workflow_id=$1) AS version,
   (SELECT row_to_json(e) FROM workflow_executions e WHERE id=$2) AS execution,
   (SELECT json_agg(s ORDER BY step_order) FROM workflow_steps s WHERE workflow_id=$1) AS steps,
   (SELECT row_to_json(o) FROM mutation_operations o WHERE id=$3) AS operation,
   (SELECT row_to_json(c) FROM portal_credentials c WHERE id=$4) AS credential`,[f.plan.workflowId,f.executionId,f.operationId,f.credential.id]);
  const good=await seedRejectedIssue();let safeCertificate:any;
  const originalHistory=await nativeHistory(good);
  await check('actual approved failed Consumer CREATE candidate retains immutable pending key and three pristine children',async()=>{
   const result=await facts(good);assert.match(result.factsHash,/^[a-f0-9]{64}$/);assert.equal(result.operation.id,good.operationId);assert.equal(result.steps.length,4);assert.equal(result.credential.id,good.credential.id);
   assert.equal(result.operation.state,'failed');assert.equal(result.operation.remote_started,true);assert.equal(result.operation.remote_completed,false);assert.equal(result.operation.entity_id,null);assert.equal(result.operation.result_secret,null);
   assert(result.steps.slice(1).every((step:any)=>step.state==='pending'&&step.operation_id===null&&step.started_at===null&&step.completed_at===null));
  });
  await check('grant release without the dedicated certificate still fails at actual PostgreSQL COMMIT',async()=>{
   await rejected(()=>sql.transaction(tx=>tx.exec("UPDATE portal_application_grants SET state='disabled',reservation_released_at=now(),revision=revision+1,updated_at=now() WHERE id=$1",[good.submitted.grant.id])),'23514');await untouched(good);
  });
  await check('actual Security exported nine-bind SQL proves the rejected issue before abandonment without pgcrypto',async()=>{
   assert.equal((await sql.one<any>("SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='pgcrypto') AS installed")).installed,false);
   const row=await actualSecurityProof(good);assert.equal(row.grant_state,'pending');assert.equal(row.reservation_released_at,null);assert.equal(row.certificates,0);
   assert.deepEqual(await nativeHistory(good),originalHistory);
  });
  await check('actual release CAS, append-only audit and encrypted certificate commit atomically',async()=>{
   safeCertificate=await sql.transaction(tx=>abandon(good,tx));
   const g=(await sql.one<any>('SELECT state,reservation_released_at,revision FROM portal_application_grants WHERE id=$1',[good.submitted.grant.id]))!;assert.equal(g.state,'disabled');assert(g.reservation_released_at);assert.equal(g.revision,2);
   const cert=(await sql.one<any>('SELECT * FROM portal_failed_issue_abandonments WHERE grant_id=$1',[good.submitted.grant.id]))!;assert.equal(cert.execution_id,good.executionId);assert.equal(cert.failed_operation_id,good.operationId);assert.equal(cert.failed_step_id,good.plan.steps[0].id);assert.equal(cert.original_execution_key,good.executionKey);assert.equal(cert.actor_id,admin.id);assert.equal(cert.session_id,good.sessionId);assert.equal(cert.original_grant_revision,1);assert.match(cert.proof_secret,/^v1\./);
   const proof=secrets.decrypt<any>(cert.proof_secret,rejectedIssueProofAad(good.base.cid,good.base.wid,good.submitted.grant.id,good.executionId));assert.equal(secrets.fingerprint(proof),cert.proof_hmac);assert.equal(secrets.fingerprint(good.credential.key_secret),cert.key_cipher_hmac);assert.equal(proof.consumerAbsent,true);assert.equal(proof.aclAbsent,true);assert.equal(proof.keyAbsent,true);
   assert.deepEqual(await nativeHistory(good),originalHistory);assert.equal(nativeCalls,0);assert.equal(consoleContexts,0);
   const safeJson=JSON.stringify(safeCertificate);assert(!safeJson.includes(good.credential.key_secret));assert(!safeJson.includes('proof_secret'));assert(!safeJson.includes('key_secret'));
  });
  await check('actual Security exported nine-bind SQL proves only the grant reservation changed after abandonment',async()=>{
   const row=await actualSecurityProof(good);assert.equal(row.grant_state,'disabled');assert(row.reservation_released_at);assert.equal(row.certificates,1);
   assert.deepEqual(await nativeHistory(good),originalHistory);assert.equal(nativeCalls,0);assert.equal(consoleContexts,0);
  });
  await check('original actor execution key and unchanged body replay only the same safe certificate',async()=>{
   const exact={clusterId:good.base.cid,workspaceId:good.base.wid,workflowId:good.plan.workflowId,executionId:good.executionId,actorId:admin.id,originalExecutionKey:good.executionKey,requestHash:safeCertificate.requestHash};
   assert.deepEqual(await getRejectedIssueAbandonment(sql,secrets,exact),safeCertificate);
   assert.equal(await getRejectedIssueAbandonment(sql,secrets,{...exact,originalExecutionKey:`different-${randomUUID()}`}),null);assert.equal(await getRejectedIssueAbandonment(sql,secrets,{...exact,actorId:randomUUID()}),null);assert.equal(await getRejectedIssueAbandonment(sql,secrets,{...exact,workspaceId:randomUUID()}),null);
   await rejected(()=>getRejectedIssueAbandonment(sql,secrets,{...exact,requestHash:'f'.repeat(64)}),'IDEMPOTENCY_CONFLICT');assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM portal_failed_issue_abandonments WHERE grant_id=$1',[good.submitted.grant.id])).n,1);
  });
  await check('wrong encryption key fails closed when reading an otherwise valid immutable certificate',async()=>{
   const previous=process.env.CONSOLE_ENCRYPTION_KEY;let wrongSecrets:SecretService;
   try{process.env.CONSOLE_ENCRYPTION_KEY='cd'.repeat(32);wrongSecrets=new SecretService();}finally{process.env.CONSOLE_ENCRYPTION_KEY=previous;}
   await rejected(()=>getRejectedIssueAbandonment(sql,wrongSecrets,{clusterId:good.base.cid,workspaceId:good.base.wid,workflowId:good.plan.workflowId,executionId:good.executionId,actorId:admin.id,originalExecutionKey:good.executionKey}),'PORTAL_FAILED_ISSUE_PROOF_INVALID');assert.deepEqual(await nativeHistory(good),originalHistory);
  });
  await check('fresh request after certified abandonment allocates new grant Consumer ACL key and workflow identities',async()=>{
   const next=await request(good.base),oldGrant=(await sql.one<any>('SELECT consumer_id,acl_id FROM portal_application_grants WHERE id=$1',[good.submitted.grant.id]))!,newGrant=(await sql.one<any>('SELECT consumer_id,acl_id FROM portal_application_grants WHERE id=$1',[next.grant.id]))!,newKey=(await sql.one<any>('SELECT id,kong_id FROM portal_credentials WHERE grant_id=$1',[next.grant.id]))!;
   assert.notEqual(next.grant.id,good.submitted.grant.id);assert.notEqual(next.workflowId,good.plan.workflowId);assert.notEqual(newGrant.consumer_id,oldGrant.consumer_id);assert.notEqual(newGrant.acl_id,oldGrant.acl_id);assert.notEqual(newKey.id,good.credential.id);assert.notEqual(newKey.kong_id,good.credential.kong_id);assert.deepEqual(await nativeHistory(good),originalHistory);assert.equal(nativeCalls,0);
  });
  const negativeCases:Array<{name:string;mutate:(f:FailedIssue)=>Promise<unknown>}>=[
   {name:'unknown first native operation',mutate:f=>sql.exec("UPDATE mutation_operations SET state='uncertain',error_code='KONG_WRITE_RESULT_UNKNOWN' WHERE id=$1",[f.operationId])},
   {name:'remote completed first operation',mutate:f=>sql.exec('UPDATE mutation_operations SET remote_completed=true WHERE id=$1',[f.operationId])},
   {name:'nonvalidation first failure',mutate:f=>sql.exec("UPDATE mutation_operations SET error_code='KONG_CONFLICT' WHERE id=$1",[f.operationId])},
   {name:'first step reports a different failure code',mutate:f=>sql.exec("UPDATE workflow_steps SET error_code='KONG_WRITE_RESULT_UNKNOWN' WHERE id=$1",[f.plan.steps[0].id])},
   {name:'first step receipt reports remote completion',mutate:f=>sql.exec('UPDATE workflow_steps SET safe_result=$2::jsonb WHERE id=$1',[f.plan.steps[0].id,JSON.stringify({nativeOperationId:f.operationId,remoteStarted:true,remoteCompleted:true})])},
   {name:'first remote dispatch never started',mutate:f=>sql.exec('UPDATE mutation_operations SET remote_started=false WHERE id=$1',[f.operationId])},
   {name:'first operation has native result',mutate:f=>sql.exec('UPDATE mutation_operations SET result_secret=$2 WHERE id=$1',[f.operationId,secrets.encrypt({fixture:true},`mutation:${f.operationId}:result`)])},
   {name:'first step has after fingerprint',mutate:f=>sql.exec('UPDATE workflow_steps SET after_fingerprint=$2 WHERE id=$1',[f.plan.steps[0].id,secrets.fingerprint({fixture:true})])},
   {name:'later ACL step already started',mutate:f=>sql.exec("UPDATE workflow_steps SET state='running',started_at=now(),revision=revision+1,updated_at=now() WHERE id=$1",[f.plan.steps[1].id])},
   {name:'later metadata step has saved facts',mutate:f=>sql.exec('UPDATE workflow_steps SET safe_result=$2::jsonb WHERE id=$1',[f.plan.steps[3].id,JSON.stringify({fixture:true})])},
   {name:'pending key was revealed',mutate:f=>sql.exec('UPDATE portal_credentials SET last_revealed_at=now() WHERE id=$1',[f.credential.id])},
   {name:'issued credential reference already exists',mutate:f=>rawCredentialRef(f)},
   {name:'original execution is partial',mutate:f=>sql.exec("UPDATE workflow_executions SET state='partial' WHERE id=$1",[f.executionId])}
  ];
  for(const item of negativeCases)await check(`${item.name}: exact DB candidate rejects and cannot release`,async()=>{
   const f=await seedRejectedIssue();await item.mutate(f);await rejected(()=>sql.one('SELECT m6_assert_rejected_issue_candidate($1)',[f.submitted.grant.id]),'23514');
   await rejected(()=>sql.transaction(tx=>abandon(f,tx)),'PORTAL_FAILED_ISSUE_PROOF_INVALID');await untouched(f);
  });
  await check('cross-cluster/workspace grant lookup cannot construct a certificate',async()=>{
   const f=await seedRejectedIssue();await rejected(()=>loadRejectedIssueAbandonmentFacts(sql,{...scope(f),workspaceId:good.base.wid}),'PORTAL_FAILED_ISSUE_PROOF_INVALID');await untouched(f);
  });
  await check('wrong grant CAS revision rolls back certificate audit and release together',async()=>{
   const f=await seedRejectedIssue();await rejected(()=>sql.transaction(tx=>abandon(f,tx,{expectedGrantRevision:2})),'PORTAL_FAILED_ISSUE_PROOF_INVALID');await untouched(f);
  });
  await check('changed facts hash rolls back certificate audit and release together',async()=>{
   const f=await seedRejectedIssue();await rejected(()=>sql.transaction(tx=>abandon(f,tx,{factsHash:'f'.repeat(64)})),'PORTAL_FAILED_ISSUE_PROOF_INVALID');await untouched(f);
  });
  await check('revoked original console session rejects constructor and rolls back all metadata',async()=>{
   const f=await seedRejectedIssue();await sql.exec('UPDATE auth_sessions SET revoked_at=now() WHERE id=$1',[f.sessionId]);await rejected(()=>sql.transaction(tx=>abandon(f,tx)),'23514');await untouched(f);
  });
  for(const item of [{name:'consumer absence is not proven',changes:{consumerAbsent:false}},{name:'key absence is not proven',changes:{keyAbsent:false}},{name:'absence read is older than fifteen seconds',changes:{observedAt:new Date(Date.now()-60000).toISOString()}},{name:'publication proof has changed',changes:{publicationProofHmac:'f'.repeat(64)}}])await check(`${item.name}: constructor rejects and all metadata rolls back`,async()=>{
   const f=await seedRejectedIssue();await rejected(()=>sql.transaction(tx=>abandon(f,tx,{proofChanges:item.changes})),'PORTAL_FAILED_ISSUE_PROOF_INVALID');await untouched(f);
  });
  await check('post-certificate late native completion and later step facts are refused at COMMIT',async()=>{
   await rejected(()=>sql.transaction(tx=>tx.exec('UPDATE mutation_operations SET remote_completed=true WHERE id=$1',[good.operationId])),'23514');
   await rejected(()=>sql.transaction(tx=>tx.exec("UPDATE workflow_steps SET state='running',started_at=now() WHERE id=$1",[good.plan.steps[1].id])),'23514');
   await rejected(()=>sql.transaction(tx=>rawCredentialRef(good,tx)),'23514');assert.deepEqual(await nativeHistory(good),originalHistory);
  });
  await check('encrypted NULL-result Consumer CREATE matching a reserved identity cannot arrive after release',async()=>{
   await rejected(()=>sql.transaction(tx=>rawNullCreate(good,true,tx)),'23514');assert.deepEqual(await nativeHistory(good),originalHistory);
  });
  await check('unrelated encrypted NULL-result Consumer CREATE remains permitted in the same physical scope',async()=>{
   const id=await sql.transaction(tx=>rawNullCreate(good,false,tx));assert.equal((await sql.one<any>('SELECT entity_id FROM mutation_operations WHERE id=$1',[id])).entity_id,null);assert.deepEqual(await nativeHistory(good),originalHistory);
  });
  await check('preexisting foreign credential fact cannot be hidden and then attached to the captured transport scope',async()=>{
   const cid=randomUUID(),ref=randomUUID();await sql.exec("INSERT INTO clusters(id,name,admin_url,transport_scope,execution_mode,version,status) VALUES($1,$2,$3,NULL,'direct','1.5.1','healthy')",[cid,`foreign-${cid}`,`http://foreign-${cid}.invalid:8001`]);
   await sql.exec("INSERT INTO credential_refs(id,cluster_id,consumer_id,credential_type,kong_id,payload_secret,recovery_capability) VALUES($1,$2,$3,'key-auth',$4,$5,'fixture')",[ref,cid,good.credential.consumer_id,good.credential.kong_id,secrets.encrypt({fixture:true},`foreign-ref:${ref}`)]);
   await rejected(()=>sql.transaction(tx=>tx.exec('UPDATE clusters SET transport_scope=$2 WHERE id=$1',[cid,good.base.scope])),'23514');assert.equal((await sql.one<any>('SELECT transport_scope FROM clusters WHERE id=$1',[cid])).transport_scope,null);
   await sql.exec('UPDATE clusters SET transport_scope=$2 WHERE id=$1',[cid,secrets.fingerprint({unrelated:cid})]);assert.notEqual((await sql.one<any>('SELECT transport_scope FROM clusters WHERE id=$1',[cid])).transport_scope,good.base.scope);assert.deepEqual(await nativeHistory(good),originalHistory);
  });
  await check('repeatable-read release proof is rejected instead of trusting a stale snapshot',async()=>{
   const f=await seedRejectedIssue();await rejected(()=>sql.transaction(async tx=>{await tx.exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');await abandon(f,tx);}), '25001');await untouched(f);
  });
  await check('concurrent fact insert commits first: waiting release rechecks current facts and rejects',async()=>{
   const f=await seedRejectedIssue(),factReady=deferred(),allowFactCommit=deferred(),releaseStarted=deferred();let releasePid=0;
   const factTx=sql.transaction(async tx=>{await tx.one('SELECT id FROM portal_application_grants WHERE id=$1 FOR UPDATE',[f.submitted.grant.id]);await rawCredentialRef(f,tx);factReady.resolve();await allowFactCommit.promise;});
   await factReady.promise;
   const releaseTx=sql.transaction(async tx=>{releasePid=(await tx.one<any>('SELECT pg_backend_pid() AS pid')).pid;releaseStarted.resolve();return abandon(f,tx);});
   const releaseResult=releaseTx.then(()=>({passed:false,code:'UNEXPECTED_RELEASE'}),error=>({passed:true,code:safeCode(error)}));
   try{await releaseStarted.promise;await lockBlocked(releasePid);}finally{allowFactCommit.resolve();}
   await factTx;const result=await releaseResult;assert.equal(result.passed,true);assert.equal(result.code,'PORTAL_FAILED_ISSUE_PROOF_INVALID');await untouched(f);assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM credential_refs WHERE cluster_id=$1',[f.base.cid])).n,1);
  });
  await check('concurrent certified release commits first: waiting late fact COMMIT is refused',async()=>{
   const f=await seedRejectedIssue(),releaseReady=deferred(),allowReleaseCommit=deferred(),factStarted=deferred();let factPid=0;
   const releaseTx=sql.transaction(async tx=>{await abandon(f,tx);releaseReady.resolve();await allowReleaseCommit.promise;});
   await releaseReady.promise;
   const factTx=sql.transaction(async tx=>{factPid=(await tx.one<any>('SELECT pg_backend_pid() AS pid')).pid;factStarted.resolve();await rawCredentialRef(f,tx);});
   const factResult=factTx.then(()=>({passed:false,code:'UNEXPECTED_LATE_FACT'}),error=>({passed:true,code:safeCode(error)}));
   try{await factStarted.promise;await lockBlocked(factPid);}finally{allowReleaseCommit.resolve();}
   await releaseTx;const result=await factResult;assert.equal(result.passed,true);assert.equal(result.code,'23514');assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM credential_refs WHERE cluster_id=$1',[f.base.cid])).n,0);assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM portal_failed_issue_abandonments WHERE grant_id=$1',[f.submitted.grant.id])).n,1);
  });
  process.env.CONSOLE_DB_RUNTIME_USER='m6_abandon_runtime';process.env.CONSOLE_DB_RUNTIME_PASSWORD='Synthetic!M6AbandonRuntimePassword';await provisionRuntimeRole(sql);
  process.env.DATABASE_URL=`postgres://m6_abandon_runtime@127.0.0.1:${port}/postgres`;runtime=new DbService();
  const actualRuntimeTransaction=runtime.transaction.bind(runtime);
  // Capture only the raw PostgreSQL code at the real transaction boundary,
  // before WorkflowService converts an unclassified DB error to HTTP503.
  // The original DbService still owns BEGIN/COMMIT/ROLLBACK and the pooled tx.
  runtime.transaction=async<T>(fn:(tx:DbService)=>Promise<T>):Promise<T>=>{
   const afterCertificate=runtimeAfterCertificateHook;
   try{return await actualRuntimeTransaction(async tx=>{
    if(afterCertificate){
     const actualQuery=tx.query.bind(tx);let fired=false;
     tx.query=async<Q=any>(query:string,params:unknown[]=[]):Promise<Q[]>=>{
      const rows=await actualQuery<Q>(query,params);
      if(!fired&&query.startsWith('INSERT INTO portal_failed_issue_abandonments(')){fired=true;assert.equal(rows.length,1);await afterCertificate(tx);}
      return rows;
     };
    }
    return fn(tx);
   });}catch(error){runtimeTransactionErrorCodes.push(safeCode(error));throw error;}
  };
  await check('formal caller is genuinely non-superuser non-owner with immutable proof and certificate SELECT INSERT only',async()=>{
   const role=(await runtime!.one<any>('SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user'))!;
   assert.equal(role.rolsuper,false);assert.equal(role.rolcreatedb,false);assert.equal(role.rolcreaterole,false);
   const ownership=(await runtime!.one<any>("SELECT EXISTS(SELECT 1 FROM pg_class t JOIN pg_roles r ON r.oid=t.relowner WHERE t.relname IN('portal_publication_proofs','portal_failed_issue_abandonments') AND r.rolname=current_user) AS owns_history"))!;assert.equal(ownership.owns_history,false);
   runtimeRoleEvidence={rolsuper:role.rolsuper,rolcreatedb:role.rolcreatedb,rolcreaterole:role.rolcreaterole,ownsProofOrCertificateTable:ownership.owns_history,proofAndCertificatePrivileges:'SELECT INSERT only; UPDATE DELETE TRUNCATE REFERENCES TRIGGER denied'};
   for(const table of ['portal_publication_proofs','portal_failed_issue_abandonments']){
    for(const privilege of ['SELECT','INSERT'])assert.equal((await runtime!.one<any>('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[table,privilege])).allowed,true);
    for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])assert.equal((await runtime!.one<any>('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[table,privilege])).allowed,false);
   }
  });
  allowWorkflowAuthorization=true;credentials.onModuleInit();
  const formalWorkflow=(f:FailedIssue,callerDb:DbService=runtime!,testControl:{lateFence?:'session'|'lease'|'authority'}={})=>{
   const callerAudit=new AuditService(callerDb,secrets,new AuditOutboxWriter(callerDb,secrets)),callerPlans=new WorkflowPlansService(callerDb,secrets,callerAudit),callerWorkspaces=new WorkspaceResolverService(callerDb);
   const actor:any={user:{id:admin.id,username:'credential-bootstrap',superAdmin:true},workspaceId:f.base.wid,idempotencyKey:f.executionKey,requestId:'isolated-formal-abandonment'};
   let frame:any={actor:actor.user,sessionId:f.sessionId,idempotencyKey:f.executionKey},present=false,denyPermission=false,lateArmed=false;
   const lateState={certificateInsertReturned:false,certificateRowsBeforeFault:0};
   const currentExecution:any={runActor:async(_input:unknown,fn:()=>Promise<any>)=>fn(),runInternalRead:async(_cid:string,_purpose:string,fn:()=>Promise<any>)=>fn(),current:()=>frame};
   const readGateway:any={request:async(cid:string,method:string,path:string)=>{
    if(method!=='GET'){nativeCalls++;throw new Error('NATIVE_WRITE_FORBIDDEN');}fixtureNativeReads++;assert.equal(cid,f.base.cid);
    if(path===`/services/${f.base.proof.serviceId}`)return structuredClone(f.base.proof.service);
    const consumerPath=`/consumers/${f.credential.consumer_id}`,aclId=(f.plan.steps[1].mutationPayload as any).id,keyId=f.credential.kong_id;
    if([consumerPath,`${consumerPath}/acls/${aclId}`,`${consumerPath}/key-auth/${keyId}`].includes(path)){
     if(present&&path===consumerPath)return{id:f.credential.consumer_id};throw new HttpException({code:'KONG_ENTITY_NOT_FOUND'},404);
    }
    throw new Error('UNEXPECTED_NATIVE_READ');
   }};
   const fixedAuthorization:any={permissionVersion:async()=>{const version=String((await callerDb.one<any>('SELECT version FROM iam_epoch WHERE singleton=true')).version);return lateArmed&&testControl.lateFence==='authority'?`${version}:late-fixture`:version;},assertScopedResource:async()=>{if(denyPermission)throw new ForbiddenException({code:'SOURCE_PERMISSION_DENIED'});},assertEntity:async()=>{if(denyPermission)throw new ForbiddenException({code:'SOURCE_PERMISSION_DENIED'});}};
   const formalRedis:any={withLock:redis.withLock,assertLeaseOwnership:async()=>{if(lateArmed&&testControl.lateFence==='lease')throw new HttpException({code:'LOCK_LOST'},503);}};
   const forbidden=new Proxy({},{get:()=>()=>{throw new Error('UNUSED_NATIVE_OR_APPROVED_PATH_FORBIDDEN');}}) as any;
   const workflows=new WorkflowService(callerDb,formalRedis,secrets,readGateway,currentExecution,fixedAuthorization,callerAudit,forbidden,forbidden,forbidden,callerWorkspaces,callerPlans,registry,approved,forbidden);
   const body={revision:f.loaded.row.revision+1,planHash:f.loaded.row.plan_hash,executionId:f.executionId,confirmed:true,confirm_name:'portal-credential-issue'};
   return{actor,body,workflows,lateState,setPresent:(value:boolean)=>{present=value;},setPermissionDenied:(value:boolean)=>{denyPermission=value;},invoke:async(changes:Record<string,unknown>={},options:{actor?:any;sessionId?:string}={})=>{
    if(callerDb===runtime)runtimeFormalCalls++;else ownerFormalCalls++;
    const actualActor=options.actor??actor;frame={actor:actualActor.user,sessionId:options.sessionId??f.sessionId,idempotencyKey:actualActor.idempotencyKey};
    const previousHook=runtimeAfterCertificateHook;
    runtimeAfterCertificateHook=testControl.lateFence?async tx=>{
     lateState.certificateInsertReturned=true;
     lateState.certificateRowsBeforeFault=(await tx.one<any>('SELECT count(*)::int AS n FROM portal_failed_issue_abandonments WHERE grant_id=$1',[f.submitted.grant.id])).n;assert.equal(lateState.certificateRowsBeforeFault,1);lateArmed=true;
     if(testControl.lateFence==='session')assert.equal(await tx.exec('UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE id=$1',[f.sessionId]),1);
    }:undefined;
    try{return await workflows.abandonRejectedIssue(f.base.cid,f.plan.workflowId,{...body,...changes},actualActor);}finally{runtimeAfterCertificateHook=previousHook;}
   }};
  };
  await check(runtimeBaseline?'unchanged helper runtime baseline reproduces raw42501 HTTP503 and atomic rollback on the original key twice':'runtime-role WorkflowService abandonment verifies sealed original plan and SQL current authority then releases safely',async()=>{
   const f=await seedRejectedIssue(),formal=formalWorkflow(f),history=await nativeHistory(f);
   if(runtimeBaseline){
    assert(readFileSync('apps/console-api/src/modules/portal/portal-failed-issue-abandonment.ts','utf8').includes('FOR SHARE OF p,proof'));
    const beforeErrors=runtimeTransactionErrorCodes.length;
    for(let n=0;n<2;n++){
     let failed=false;try{await formal.invoke();}catch(error:any){assert.equal(error.getStatus?.(),503);assert.equal(safeCode(error),'PORTAL_ISSUE_ABANDONMENT_UNKNOWN');failed=true;}assert(failed);
     await untouched(f);assert.deepEqual(await nativeHistory(f),history);
    }
    assert.deepEqual(runtimeTransactionErrorCodes.slice(beforeErrors),['42501','42501']);assert.equal(nativeCalls,0);
    runtimeBaselineEvidence={rawPostgresCode:'42501',wrappedHttpStatus:503,wrappedCode:'PORTAL_ISSUE_ABANDONMENT_UNKNOWN',originalKeyAttempts:2,certificateCount:0,abandonmentAuditCount:0,grantState:'pending',grantRevision:1,ciphertextUnchanged:true,nativeWorkflowSnapshotAndStepsUnchanged:true};
    return;
   }
   const receipt=await formal.invoke();
   assert.equal(receipt.state,'failed');assert.equal(receipt.issueAbandonment?.completed,true);assert.equal(receipt.issueAbandonment?.eligible,false);assert.equal(receipt.issueAbandonment?.reservationReleased,true);assert(receipt.issueAbandonment?.certificateId);assert.deepEqual(await nativeHistory(f),history);assert.equal(nativeCalls,0);
   const before=(await sql.one<any>("SELECT count(*)::int AS n FROM audit_events WHERE entity_id=$1 AND action='portal.issue.abandon-rejected'",[f.submitted.grant.id])).n;
   const repeated=await formal.invoke();assert.deepEqual(repeated,receipt);assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM portal_failed_issue_abandonments WHERE grant_id=$1',[f.submitted.grant.id])).n,1);assert.equal((await sql.one<any>("SELECT count(*)::int AS n FROM audit_events WHERE entity_id=$1 AND action='portal.issue.abandon-rejected'",[f.submitted.grant.id])).n,before);assert.deepEqual(await nativeHistory(f),history);
   await rejected(()=>formal.invoke({revision:formal.body.revision+1}),'IDEMPOTENCY_CONFLICT');
  });
  await check('actual WorkflowService rejects stale workflow revision before constructing a certificate',async()=>{
   const f=await seedRejectedIssue(),formal=formalWorkflow(f);await rejected(()=>formal.invoke({revision:1}),'PORTAL_REJECTED_ISSUE_NOT_ELIGIBLE');await untouched(f);
  });
  await check('actual WorkflowService rejects replacement execution key even with a matching request frame',async()=>{
   const f=await seedRejectedIssue(),formal=formalWorkflow(f);await rejected(()=>formal.invoke({}, {actor:{...formal.actor,idempotencyKey:`replacement-${randomUUID()}`}}),'PORTAL_ABANDONMENT_EXECUTOR_MISMATCH');await untouched(f);
  });
  await check('actual WorkflowService rejects another active valid console actor and session',async()=>{
   const f=await seedRejectedIssue(),formal=formalWorkflow(f),otherId=randomUUID(),otherSession=randomUUID();
   await sql.exec("INSERT INTO users(id,username,password_hash,super_admin,status) SELECT $1,$2,password_hash,true,'active' FROM users WHERE id=$3",[otherId,`actor-${otherId}`,admin.id]);await sql.exec("INSERT INTO auth_sessions(id,user_id,credential_epoch,expires_at) VALUES($1,$2,1,now()+interval '1 hour')",[otherSession,otherId]);
   await rejected(()=>formal.invoke({}, {actor:{...formal.actor,user:{...formal.actor.user,id:otherId}},sessionId:otherSession}),'PORTAL_ABANDONMENT_EXECUTOR_MISMATCH');await untouched(f);
  });
  await check('actual WorkflowService rejects revoked original SQL session',async()=>{
   const f=await seedRejectedIssue(),formal=formalWorkflow(f);await sql.exec('UPDATE auth_sessions SET revoked_at=now() WHERE id=$1',[f.sessionId]);await rejected(()=>formal.invoke(),'PORTAL_ABANDONMENT_SESSION_INVALID');await untouched(f);
  });
  await check('actual WorkflowService rejects a Consumer that exists during the exact native absence probe',async()=>{
   const f=await seedRejectedIssue(),formal=formalWorkflow(f);formal.setPresent(true);await rejected(()=>formal.invoke(),'PORTAL_ABANDONMENT_NATIVE_OBJECT_EXISTS');await untouched(f);
  });
  await check('actual WorkflowService rejects revoked source authority before releasing any history',async()=>{
   const f=await seedRejectedIssue(),formal=formalWorkflow(f);formal.setPermissionDenied(true);await rejected(()=>formal.invoke(),'SOURCE_PERMISSION_DENIED');await untouched(f);
  });
  if(!runtimeBaseline)for(const item of [
   {fence:'session' as const,code:'PORTAL_ABANDONMENT_SESSION_INVALID',name:'real same-transaction session revocation'},
   {fence:'lease' as const,code:'LOCK_LOST',name:'simulated lease loss'},
   {fence:'authority' as const,code:'PERMISSIONS_CHANGED',name:'simulated current permission-version change'}
  ])await check(`late ${item.name} after real runtime certificate INSERT rolls back certificate audit grant and original history`,async()=>{
   const f=await seedRejectedIssue(),formal=formalWorkflow(f,runtime!,{lateFence:item.fence}),history=await nativeHistory(f),priorErrors=runtimeTransactionErrorCodes.length;
   await rejected(()=>formal.invoke(),item.code);assert.equal(formal.lateState.certificateInsertReturned,true);assert.equal(formal.lateState.certificateRowsBeforeFault,1);
   assert.deepEqual(runtimeTransactionErrorCodes.slice(priorErrors),[item.code]);await untouched(f);assert.deepEqual(await nativeHistory(f),history);
   assert.equal((await sql.one<any>('SELECT revoked_at FROM auth_sessions WHERE id=$1',[f.sessionId])).revoked_at,null);assert.equal(nativeCalls,0);
   lateFenceEvidence.push({fence:item.fence,code:item.code,certificateInsertReturned:true,certificateRowsInsideTransaction:1,certificateCountAfterRollback:0,abandonmentAuditCountAfterRollback:0,grantPendingAndRevisionUnchanged:true,keyCiphertextAndAllOriginalNativeHistoryUnchanged:true,sessionRevocationRolledBack:item.fence==='session'});
  });
  await check('real runtime DB role is non-superuser and certificate SELECT INSERT only',async()=>{
   assert.equal((await runtime!.one<any>('SELECT rolsuper FROM pg_roles WHERE rolname=current_user')).rolsuper,false);
   for(const privilege of ['SELECT','INSERT'])assert.equal((await runtime!.one<any>("SELECT has_table_privilege(current_user,'portal_failed_issue_abandonments',$1) AS allowed",[privilege])).allowed,true);
   for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])assert.equal((await runtime!.one<any>("SELECT has_table_privilege(current_user,'portal_failed_issue_abandonments',$1) AS allowed",[privilege])).allowed,false);
  });
  await check('real runtime UPDATE DELETE TRUNCATE and disable-trigger of certificate history are denied',async()=>{
   await rejected(()=>runtime!.exec('UPDATE portal_failed_issue_abandonments SET facts_hash=facts_hash'),'42501');await rejected(()=>runtime!.exec('DELETE FROM portal_failed_issue_abandonments'),'42501');await rejected(()=>runtime!.exec('TRUNCATE TABLE portal_failed_issue_abandonments'),'42501');await rejected(()=>runtime!.exec('ALTER TABLE portal_failed_issue_abandonments DISABLE TRIGGER ALL'),'42501');
  });
  await check('certificate history triggers resist accidentally granted runtime CRUD and truncate',async()=>{
   await sql.exec('GRANT UPDATE,DELETE,TRUNCATE ON portal_failed_issue_abandonments TO m6_abandon_runtime');
   await rejected(()=>runtime!.exec('UPDATE portal_failed_issue_abandonments SET facts_hash=facts_hash'),'42501');await rejected(()=>runtime!.exec('DELETE FROM portal_failed_issue_abandonments'),'42501');await rejected(()=>runtime!.exec('TRUNCATE TABLE portal_failed_issue_abandonments'),'42501');
  });
  await provisionRuntimeRole(sql);
  await check('runtime history privileges return to permanent SELECT INSERT only after the isolated misgrant defense test',async()=>{
   for(const table of ['portal_publication_proofs','portal_failed_issue_abandonments'])for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])assert.equal((await runtime!.one<any>('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[table,privilege])).allowed,false);
   assert.equal(ownerFormalCalls,0);assert(runtimeFormalCalls>=8);assert.deepEqual(runtimeTransactionErrorCodes,runtimeBaseline?['42501','42501']:['PORTAL_ABANDONMENT_SESSION_INVALID','LOCK_LOST','PERMISSIONS_CHANGED']);
  });
  await check('all failure history and reserved key bytes remain intact with zero native or console requests',async()=>{
   assert.deepEqual(await nativeHistory(good),originalHistory);assert.equal(nativeCalls,0);assert.equal(consoleContexts,0);
  });
 }catch(error:any){failureCode=safeCode(error);if(/^\d+$/.test(error?.position??'')){failurePosition=Number(error.position);failureMigrationLine=readFileSync('apps/console-api/src/infrastructure/migrations/009_m6_failed_issue_abandonment.sql','utf8').slice(0,failurePosition-1).split('\n').length;}throw error;}finally{
  mkdirSync('artifacts/M6',{recursive:true});const artifact=`artifacts/M6/portal-failed-issue-abandonment-${runtimeBaseline?'runtime-baseline-':''}postgres-${runId}.json`,status=failureCode?'FAIL':runtimeBaseline?'BASELINE_EXPECTED_REJECTION':'PASS';
  writeFileSync(artifact,JSON.stringify({milestone:'M6',status,failureCode,failurePosition,failureMigrationLine,database:'disposable PostgreSQL16; unchanged migrations000-008 plus additive M6 SQL009',serverVersion,migrations,helperSource:'apps/console-api/src/modules/portal/portal-failed-issue-abandonment.ts',helperSourceHash,migrationSourceHash,securityQuerySource:'tests/security/lib/m6-failed-issue-continuation.mjs',securityQueryExport:'FAILED_ISSUE_DATABASE_SQL',securityQuerySourceHash,securityQueryHash,formalCaller:{databaseRole:'actual non-superuser/non-owner m6_abandon_runtime',dependencies:'WorkflowService, AuditService, WorkflowPlansService, WorkspaceResolverService and permission-version SQL all use the same real runtime DbService',runtimeCalls:runtimeFormalCalls,ownerCalls:ownerFormalCalls,expectedBrokenQueryBaseline:runtimeBaseline},runtimeRoleEvidence,runtimeTransactionErrorCodes,runtimeBaselineEvidence,lateFenceEvidence,coverageTargets:['actual PortalCredentials request and sealed WorkflowPlans persist/load','actual PostgreSQL candidate/current facts/reciprocal native ledger constraints','actual Audit.append, grant CAS, encrypted certificate and deferred COMMIT proof','actual Security exported nine-bind SQL before and after abandonment; real PostgreSQL core SHA256 matches Node for immutable key ciphertext','actual runtime-role WorkflowService.abandonRejectedIssue verifies original sealed plan/snapshot, SQL session/approver/current scope','actual two-transaction grant-row serialization and late fact rejection','actual non-superuser runtime role provisioning and history trigger defense','late session/lease/current-authority fences after a real runtime-role certificate INSERT rollback the entire SQL transaction'],fixtures:['migration owner creates synthetic tenants/failure histories and runs external state assertions; every formal WorkflowService call uses the genuinely non-owner runtime database role','Gateway GET-only exact Service and three absent Consumer/ACL/key paths; no real network or native write','source authorization, developer identity, Kong execution frames, Redis leases, absence transport are explicit fixtures; production NativePolicy not exercised','late fault injection: session revocation uses real same-transaction SQL; lease loss and permission-version change are explicit fixtures armed only after real certificate INSERT returns','Security query fixture has one rejected grant/credential in its disposable tenant; real continuation also proves a separate first active grant and expects two scope rows','no formal HTTP abandonment route invoked and no live application environment accessed'],nativeCalls,consoleContexts,fixtureNativeReads,checks,passed:checks.filter(item=>item.passed).length,total:checks.length},null,2));
  await runtime?.onModuleDestroy();await db?.onModuleDestroy();try{execFileSync('docker',['rm','-f',container],{stdio:'ignore'});}catch{}
  process.stdout.write(JSON.stringify({artifact,status,passed:checks.filter(item=>item.passed).length,total:checks.length,nativeCalls})+'\n');
 }
}
main().catch(()=>{process.stderr.write('Isolated failed issue abandonment proof failed; safe artifact retained.\n');process.exitCode=1;});

