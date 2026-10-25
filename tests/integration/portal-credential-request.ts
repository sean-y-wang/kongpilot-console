import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import {AuditService} from '../../apps/console-api/src/modules/audit/audit.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {PortalAuthService} from '../../apps/console-api/src/modules/portal-auth/portal-auth.service';
import type {PortalPrincipal} from '../../apps/console-api/src/modules/portal-auth/portal-auth.types';
import {PortalCredentialsService} from '../../apps/console-api/src/modules/portal/portal-credentials.service';
import {PortalNativeService} from '../../apps/console-api/src/modules/portal/portal-native.service';
import {decodePublicationProof,publicationProofAad,portalKeyAad,type PortalPublicationProofV1} from '../../apps/console-api/src/modules/portal/portal-proof';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import {snapshotAad,type WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Disposable real PostgreSQL + real metadata ledger/compiler/plan/sealing.
 * Principal identity validation, Redis leases, authorization and Gateway are
 * explicit fixtures. This does not replace real HTTP authentication or Kong. */
async function main():Promise<void>{
 const container=`kongos-m6-credential-${randomUUID().slice(0,8)}`,runId=new Date().toISOString().replace(/[:.]/g,'-');
 const checks:Array<{name:string;passed:boolean;errorCode?:string;column?:string}>=[];
 let db:DbService|undefined,nativeCalls=0,consoleContexts=0,failureCode:string|undefined;
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
  const store:any={get:async()=>{throw new Error('SECRET_HISTORY_LOOKUP_FORBIDDEN');}},approved:any={assertSubject:async()=>{throw new Error('CONSOLE_APPROVAL_FORBIDDEN');}};
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

  await check('actual PostgreSQL16 applies only unchanged migrations000 through008',async()=>{assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM schema_migrations')).n,9);});
  const base=await fixture();
  await check('NULL registered transport is preserved while sealed publication uses exact computed endpoint scope',async()=>{const cluster=await sql.one<any>('SELECT admin_url,transport_scope FROM clusters WHERE id=$1',[base.cid]);assert.equal(cluster.transport_scope,null);assert.equal(transportScopeFor(cluster.admin_url,cluster.transport_scope),base.scope);const row=await sql.one<any>('SELECT * FROM portal_publication_proofs WHERE publication_id=$1',[base.publicationId]);assert.deepEqual(decodePublicationProof(row,secrets),base.proof);const loaded=await plans.load(base.cid,base.wid,base.proof.workflowId);assert.equal(loaded.row.state,'succeeded');assert.equal(loaded.plan.steps.length,3);});
  let issued:any;
  const originalKey=`credential-original-${randomUUID()}`;
  await check('real developer request on direct cluster with NULL scope commits one pending approval-required credential workflow',async()=>{issued=await request(base,originalKey);assert.equal(issued.state,'pending');assert.equal(issued.approvalRequired,true);assert.deepEqual(await counts(base),{grants:1,credentials:1,workflows:1,mutations:0});assert.equal((await sql.one<any>('SELECT transport_scope FROM clusters WHERE id=$1',[base.cid])).transport_scope,null);});
  await check('sealed request is the exact four-step Consumer ACL key metadata dependency graph',async()=>{const loaded=await plans.load(base.cid,base.wid,issued.workflowId);assert.equal(loaded.plan.executionMode,'direct');assert.equal(loaded.plan.approvalRequired,true);assert.equal(loaded.plan.requester.type,'developer');assert.equal(loaded.version.step_count,4);assert.equal(loaded.version.native_request_count,3);assert.deepEqual(loaded.plan.steps.map(step=>[step.kind,step.entityType,step.credentialKind??null]),[['native','consumers',null],['native','credentials','acls'],['native','credentials','key-auth'],['metadata','portal_application_grants',null]]);const row=await sql.one<any>('SELECT * FROM portal_credentials WHERE grant_id=$1',[issued.grant.id]);assert.equal(row.state,'pending');assert.equal(row.issue_operation_id,null);assert.equal(secrets.decrypt<any>(row.key_secret,portalKeyAad(base.cid,base.wid,row.id,row.generation)).key,loaded.plan.generated!.key);assert(!JSON.stringify(issued).includes(loaded.plan.generated!.key));assert(!row.key_secret.includes(loaded.plan.generated!.key));assert.equal((await sql.query('SELECT level FROM workflow_stages WHERE workflow_id=$1',[issued.workflowId])).length,1);assert.equal((await sql.query('SELECT id FROM workflow_approvals WHERE workflow_id=$1',[issued.workflowId])).length,0);});
  await check('same original key resolves durable SQL result without allocating another workflow or secret',async()=>{assert.deepEqual(await request(base,originalKey),issued);assert.deepEqual(await counts(base),{grants:1,credentials:1,workflows:1,mutations:0});const receipt=await auth.operation(base.principal,originalKey,true);assert.equal(receipt.state,'succeeded');assert.equal(receipt.remoteCompleted,true);});
  await check('explicit registered physical scope still supports the same DB-only compiler',async()=>{const f=await fixture('b'.repeat(64));const result=await request(f);assert.equal(result.state,'pending');assert.equal((await plans.load(f.cid,f.wid,result.workflowId)).plan.scope.transportScope,'b'.repeat(64));});
  const negativeCases:Array<{name:string;change:(f:Fixture)=>Promise<unknown>;code?:string}>=[
   {name:'changed Admin endpoint with unchanged revision',change:f=>sql.exec('UPDATE clusters SET admin_url=$2 WHERE id=$1',[f.cid,'http://changed.fixture.invalid:8001'])},
   {name:'changed explicit registered physical scope',change:f=>sql.exec('UPDATE clusters SET transport_scope=$2 WHERE id=$1',[f.cid,'f'.repeat(64)])},
   {name:'changed current cluster revision',change:f=>sql.exec('UPDATE clusters SET revision=revision+1 WHERE id=$1',[f.cid])},
   {name:'changed current workspace revision',change:f=>sql.exec('UPDATE workspaces SET revision=revision+1 WHERE id=$1',[f.wid])},
   {name:'disabled current workspace',change:f=>sql.exec("UPDATE workspaces SET status='disabled',revision=revision+1 WHERE id=$1",[f.wid])},
   {name:'disabled current cluster',change:f=>sql.exec("UPDATE clusters SET status='disabled',revision=revision+1 WHERE id=$1",[f.cid]),code:'PORTAL_NOT_AVAILABLE'},
  ];
  for(const item of negativeCases)await check(`${item.name} refuses stale publication without creating grant key workflow or native facts`,async()=>{const f=await fixture();await item.change(f);await rejected(()=>request(f),item.code??'PORTAL_PUBLICATION_REVALIDATION_REQUIRED');assert.deepEqual(await counts(f),{grants:0,credentials:0,workflows:0,mutations:0});const operations=await sql.query<any>('SELECT state,remote_completed FROM portal_operations WHERE developer_id=$1',[f.principal.developerId]);assert.equal(operations.length,1);assert.equal(operations[0].state,'failed');assert.equal(operations[0].remote_completed,true);});
  await check('wrong-context copied AEAD proof cannot be decrypted or used to publish another identity',async()=>{const row=await sql.one<any>('SELECT * FROM portal_publication_proofs WHERE publication_id=$1',[base.publicationId]);await assert.rejects(async()=>decodePublicationProof({...row,publication_id:randomUUID()},secrets));});
  await check('all real request compilation and negative paths use zero native transport and zero console execution contexts',async()=>{assert.equal(nativeCalls,0);assert.equal(consoleContexts,0);assert.equal((await sql.one<any>('SELECT count(*)::int AS n FROM mutation_operations')).n,0);});
 }catch(error){failureCode=safeCode(error);throw error;}finally{
  mkdirSync('artifacts/M6',{recursive:true});
  writeFileSync(`artifacts/M6/portal-credential-request-postgres-${runId}.json`,JSON.stringify({milestone:'M6',status:failureCode?'FAIL':'PASS',failureCode,database:'disposable PostgreSQL16; unchanged migrations000-008',actual:['schema constraints','WorkflowPlansService definitions/persist/load','PortalNativeService compiler','PortalCredentialsService.request','PortalAuthService SQL metadata ledger/receipt','AES-GCM publication proof and credential sealing'],fixtures:['explicit fake principal identity validator','Redis leases','console authorization','Gateway and console context forbidden'],nativeCalls,consoleContexts,passed:checks.filter(c=>c.passed).length,total:checks.length,checks},null,2));
  if(db)await db.onModuleDestroy().catch(()=>undefined);execFileSync('docker',['rm','-f',container],{stdio:'ignore'});
 }
 assert(checks.length&&checks.every(c=>c.passed));console.log(JSON.stringify({status:'PASS',passed:checks.length,nativeCalls,consoleContexts}));
}
main().catch((error:any)=>{console.error(JSON.stringify({status:'FAIL',code:String(error?.getResponse?.()?.code??error?.code??'ASSERTION_FAILED').replace(/[^A-Z0-9_]/gi,'_').slice(0,128),...(error?.column?{column:error.column}:{})}));process.exitCode=1;});
