import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import {provisionRuntimeRole} from '../../apps/console-api/src/infrastructure/migrate';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {AuditService} from '../../apps/console-api/src/modules/audit/audit.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {PortalAdminService} from '../../apps/console-api/src/modules/portal/portal-admin.service';
import {PortalPublicService} from '../../apps/console-api/src/modules/portal/portal-public.service';
import {PortalNativeService} from '../../apps/console-api/src/modules/portal/portal-native.service';
import {PortalDocumentService} from '../../apps/console-api/src/modules/portal/portal-document.service';
import {publicationProofAad,type PortalPublicationProofV1} from '../../apps/console-api/src/modules/portal/portal-proof';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import {snapshotAad,type WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';
import type {EntityActor} from '../../apps/console-api/src/modules/entities/entities.types';

/** Actual services/schema/RBAC with a genuine non-owner SQL caller. Native
 * objects and ACKs are explicit synthetic fixtures, never network packets. */
async function main():Promise<void>{
 const container=`kongos-m6-admincatalog-${randomUUID().slice(0,8)}`,runId=new Date().toISOString().replace(/[:.]/g,'-');
 const checks:Array<{name:string;passed:boolean;errorCode?:string}>=[];
 const sha=(v:string|Buffer)=>createHash('sha256').update(v).digest('hex');
 const code=(e:any)=>String(e?.getResponse?.()?.code??e?.code??'ASSERTION_FAILED').replace(/[^A-Z0-9_]/gi,'_').slice(0,128);
 const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(e){checks.push({name,passed:false,errorCode:code(e)});throw e;}};
 const denied=async(fn:()=>Promise<unknown>,status?:number)=>{try{await fn();}catch(e:any){if(status)assert.equal(e?.getStatus?.(),status);return code(e);}throw new Error('EXPECTED_REJECTION');};
 const dockerEnv={...process.env};for(const k of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete dockerEnv[k];
 const docker=(args:string[])=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env:dockerEnv,encoding:'utf8',stdio:['ignore','pipe','pipe']});
 let owner:DbService|undefined,runtime:DbService|undefined,failureCode:string|undefined,serverVersion:string|undefined;
 let nativeReads=0,nativeWrites=0,publishedFixtures=0,runtimeCalls=0;
 let phase="initialization",failureMetadata:Record<string,string>|undefined;
 let migrations:Array<{name:string;checksum:string}>=[],roleEvidence:Record<string,unknown>|undefined;
 const productPaths=['portal-public.service.ts','portal-admin.service.ts','portal.controller.ts'];
 const productHashes=()=>Object.fromEntries(productPaths.map(name=>[name,sha(readFileSync(`apps/console-api/src/modules/portal/${name}`))]));
 let sourceHashes:Record<string,string>|undefined;
 try{
  docker(['run','-d','--pull=never','--name',container,'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine']);
  const port=docker(['port',container,'5432']).trim().split(':').pop();
  process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;
  process.env.CONSOLE_ENCRYPTION_KEY='ab'.repeat(32);process.env.APP_SECRET='SyntheticAdminCatalogConsoleSigningKey2026!';
  process.env.BOOTSTRAP_ADMIN_USERNAME='catalog-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!CatalogBootstrap2026Password';
  owner=new DbService();for(let n=0;n<80;n++){try{await owner.one('SELECT 1');break;}catch{if(n===79)throw new Error('DISPOSABLE_DATABASE_UNAVAILABLE');await new Promise(r=>setTimeout(r,100));}}
  await owner.migrateAndSeed();process.env.CONSOLE_DB_RUNTIME_USER='m6_catalog_runtime';process.env.CONSOLE_DB_RUNTIME_PASSWORD='Synthetic!CatalogRuntime2026Password';await provisionRuntimeRole(owner);
  process.env.DATABASE_URL=`postgres://m6_catalog_runtime@127.0.0.1:${port}/postgres`;runtime=new DbService();const sql=runtime;
  const originalQuery=sql.query.bind(sql);let afterQuery:((query:string,rows:any[])=>Promise<void>)|undefined;
  sql.query=async function<T=any>(q:string,p:unknown[]=[]):Promise<T[]>{runtimeCalls++;const rows=await originalQuery<T>(q,p);await afterQuery?.(q,rows);return rows;};
  sourceHashes=productHashes();
  await check('unchanged000-009 apply on PostgreSQL16 and all services use non-owner non-super runtime DB',async()=>{
   serverVersion=(await sql.one<any>('SHOW server_version'))!.server_version;assert.match(serverVersion!,/^16\./);
   migrations=await sql.query('SELECT name,checksum FROM schema_migrations ORDER BY name');assert.equal(migrations.length,10);
   for(const row of migrations)assert.equal(row.checksum,sha(readFileSync(`apps/console-api/src/infrastructure/migrations/${row.name}`)));
   const r=await sql.one<any>('SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user');assert(Object.values(r).every(v=>v===false));
   const own=(await sql.one<any>("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relname IN('portal_publication_proofs','portal_applications','workflow_versions') AND r.rolname=current_user) AS owns"))!.owns;
   assert.equal(own,false);roleEvidence={...r,ownsFixtureTables:own};
  });
  const secrets=new SecretService(),audit=new AuditService(sql,secrets,new AuditOutboxWriter(sql,secrets)),resolver=new WorkspaceResolverService(sql),execution=new KongExecutionContextService();
  const objects=new Map<string,any>();const kong:any={request:async(cid:string,method:string,path:string)=>{if(method!=='GET'){nativeWrites++;throw new Error('NATIVE_WIRE_FORBIDDEN');}nativeReads++;const value=objects.get(`${cid}:${path}`);assert(value,'SYNTHETIC_OBJECT_MISSING');return structuredClone(value);}};
  const authz=new AuthorizationService(sql,resolver,kong,execution),native=new PortalNativeService(sql,secrets,kong,execution,authz,resolver),plans=new WorkflowPlansService(sql,secrets,audit),registry=new WorkflowRegistryService();
  const superuser=(await sql.one<any>('SELECT id,username FROM users WHERE super_admin'))!;
  const admin=new PortalAdminService(sql,secrets,authz,audit,{}as any,{}as any,resolver,{}as any,plans,registry,{}as any,native,new PortalDocumentService(secrets));admin.onModuleInit();
  const publicService=new PortalPublicService(sql,secrets);
  const asActor=(id:string,username:string,wid:string):EntityActor=>({user:{id,username,superAdmin:false},workspaceId:wid,requestId:randomUUID(),ip:'192.0.2.17'});
  const superActor=(wid:string):EntityActor=>({user:{id:superuser.id,username:superuser.username,superAdmin:true},workspaceId:wid,requestId:randomUUID(),ip:'192.0.2.17'});
  const tenant=async(cid=randomUUID(),code='pay')=>{phase='fixture.tenant';const wid=randomUUID(),developerId=randomUUID(),appId=randomUUID(),scope=secrets.fingerprint({cid});await sql.transaction(async tx=>{
   await tx.exec("INSERT INTO clusters(id,name,admin_url,transport_scope,execution_mode,version,status) VALUES($1,$2,$3,$4,'direct','1.5.1','healthy') ON CONFLICT(id) DO NOTHING",[cid,`catalog-${cid}`,`http://fixture-${cid}.invalid:8001`,scope]);
   await tx.exec('INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,$3,$4)',[wid,cid,code,`Workspace ${code}`]);
   await tx.exec("INSERT INTO portal_settings(cluster_id,workspace_id,slug,name,published,status) VALUES($1,$2,$3,'Synthetic tenant',true,'active')",[cid,wid,`tenant-${wid}`]);
   await tx.exec("INSERT INTO portal_developers(id,cluster_id,workspace_id,username,email,display_name,password_hash,status) VALUES($1,$2,$3,$4,$5,'Synthetic developer',$6,'active')",[developerId,cid,wid,`developer-${developerId}`,`${developerId}@example.test`,`$2b$12$${'a'.repeat(53)}`]);
   await tx.exec("INSERT INTO portal_applications(id,cluster_id,workspace_id,developer_id,name,description) VALUES($1,$2,$3,$4,'Synthetic application','Safe application description')",[appId,cid,wid,developerId]);
   await plans.definitions(cid,wid,superuser.id,tx);
  });return{cid,wid,developerId,appId,scope,code};};
  type Tenant=Awaited<ReturnType<typeof tenant>>;
  const a=await tenant(),b=await tenant(a.cid,'ops'),foreign=await tenant();
  const reader=async(t:Tenant,modules:string[],kind:'workspace'|'tag_group'='workspace')=>{phase='fixture.reader';const id=randomUUID(),role=randomUUID();await sql.transaction(async tx=>{
   await tx.exec('INSERT INTO users(id,username,password_hash) VALUES($1,$2,$3)',[id,`reader-${id}`,`$2b$12$${'b'.repeat(53)}`]);
   await tx.exec('INSERT INTO roles(id,code,name,cluster_id,workspace_id) VALUES($1,$2,$3,$4,$5)',[role,`r${role.replace(/-/g,'')}`,'Synthetic scoped reader',t.cid,t.wid]);
   for(const module of modules){const permission=randomUUID();await tx.exec("INSERT INTO role_permissions(id,role_id,module,action,scope_type,cluster_id,workspace_id) VALUES($1,$2,$3,'read',$4,$5,$6)",[permission,role,module,kind,t.cid,t.wid]);if(kind==='tag_group')await tx.exec("INSERT INTO role_permission_tags(permission_id,logical_tag,physical_tag) VALUES($1,'team:pay','team~pay')",[permission]);}
   await tx.exec('INSERT INTO user_role_bindings(user_id,role_id,cluster_id,workspace_id,granted_by) VALUES($1,$2,$3,$4,$5)',[id,role,t.cid,t.wid,superuser.id]);
  });return{...asActor(id,`reader-${id}`,t.wid),role};};
  const full=await reader(a,['developers','applications','portal','workflows']),apps=await reader(a,['applications']),developers=await reader(a,['developers']),restricted=await reader(a,['developers','applications','portal','workflows'],'tag_group'),otherActor=await reader(a,['developers','applications','portal','workflows']);

  const published=async(t:Tenant,info:{name:string;category:string|null;legacy?:boolean;large?:number;proofPadding?:number;createdAt?:string})=>{
   const id=randomUUID(),serviceId=randomUUID(),aclId=randomUUID(),keyId=randomUUID(),workflowId=randomUUID(),executionId=randomUUID();
   const service={id:serviceId,name:`svc-${serviceId}`,host:'fixture.example.test',protocol:'http',port:8080,tags:[`kos-ws-${t.code}`]},acl={id:aclId,name:'acl',enabled:true,protocols:['http','https'],service:{id:serviceId},config:{whitelist:[`kos-portal-api-${id}`]},tags:[`kos-ws-${t.code}`]},key={id:keyId,name:'key-auth',enabled:true,protocols:['http','https'],service:{id:serviceId},config:{key_names:['apikey']},tags:[`kos-ws-${t.code}`]};
   objects.set(`${t.cid}:/services/${serviceId}`,service);objects.set(`${t.cid}:/plugins/${aclId}`,acl);objects.set(`${t.cid}:/plugins/${keyId}`,key);
   let plan!:WorkflowPlanV1,proof!:PortalPublicationProofV1;
   await sql.transaction(async tx=>{
    // PostgreSQL now() is the transaction start. A later JavaScript timestamp
    // would violate updated_at>=created_at before this fixture reaches apply.
    phase='fixture.publication.clock';
    const createdAt=info.createdAt??new Date((await tx.one<any>('SELECT now() AS timestamp'))!.timestamp).toISOString();
    phase='fixture.publication.insert';await tx.exec('INSERT INTO portal_publications(id,cluster_id,workspace_id,transport_scope,slug,name,description,category,service_id,acl_group,created_by,updated_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$12)',[id,t.cid,t.wid,t.scope,`api-${id}`,info.name,'Published description',info.category,serviceId,`kos-portal-api-${id}`,superuser.id,createdAt]);
    const document={openapi:'3.0.3',info:{title:info.name,version:'1.0'},paths:{}};
    phase='fixture.publication.revision';await tx.exec('INSERT INTO portal_publication_revisions(cluster_id,workspace_id,publication_id,revision,service_id,title,version_label,description,openapi_document,document_hash,created_by) VALUES($1,$2,$3,1,$4,$5,\'1.0\',\'Published description\',$6::jsonb,$7,$8)',[t.cid,t.wid,id,serviceId,info.name,JSON.stringify(document),secrets.fingerprint(document),superuser.id]);
    const before=await tx.one<any>('SELECT * FROM portal_publications WHERE id=$1',[id]),first=native.nativeStep(1,'plugins','create',acl,null,{workflowId}),second=native.nativeStep(2,'plugins','create',key,null,{workflowId,dependencies:[first.id]});
    const last=native.metadataStep(3,'portal.publication.publish','portal_publications',id,before,{publicationRevision:1,service,aclGroup:before.acl_group,aclPluginId:aclId,keyAuthPluginId:keyId,schemas:{consumers:{fields:[]},acls:{fields:[]},keyAuth:{fields:[],...(info.large?{description:'X'.repeat(info.large)}:{})}},definitions:{}},[second.id]);
    plan={version:1,clusterId:t.cid,workspaceId:t.wid,workflowId,planRevision:1,kind:'portal-publication',executionMode:'direct',approvalRequired:false,subject:{type:'portal_publications',id},requester:{type:'console',id:superuser.id},definition:await plans.definition(t.cid,t.wid,'portal-publication',tx),issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString(),scope:{transportScope:t.scope,clusterRevision:1,workspaceRevision:1},prerequisites:[{type:'services',id:serviceId,path:`/services/${serviceId}`,before:service,fingerprint:secrets.fingerprint(service)}],steps:[first,second,last]};
    phase='fixture.publication.plan';const row=await plans.persist(plan,`publish-${workflowId}`,{publicationId:id,revision:1,publish:true},tx,{requestId:randomUUID(),ip:'192.0.2.17'}),snapshot={version:1,workflowId,executionId,clusterId:t.cid,workspaceId:t.wid,planRevision:1,planHash:row.plan_hash,capturedAt:new Date().toISOString(),objects:[]};
    phase="fixture.publication.execution";await tx.exec("INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,execution_actor_id,state,snapshot_state,snapshot_secret,snapshot_hash,claim_token_hash,idempotency_key,expires_at) VALUES($1,$2,$3,$4,1,$5,'direct',false,$6,'executing','ready',$7,$8,$9,$10,now()+interval '30 minutes')",[executionId,t.cid,t.wid,workflowId,row.plan_hash,superuser.id,secrets.encrypt(snapshot,snapshotAad(t.cid,t.wid,workflowId,executionId)),secrets.fingerprint(snapshot),secrets.fingerprint({claim:executionId}),`execute-${executionId}`]);
    for(const step of [first,second]){
     phase="fixture.publication.native-receipt";const op=randomUUID();await tx.exec("INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,entity_type,before_secret,payload_secret,result_secret,remote_started,remote_completed) VALUES($1,$2,$3,$4,'create',$5,$6,'succeeded','plugins',$7,$8,$9,true,true)",[op,t.cid,t.wid,superuser.id,step.mutationIdempotencyKey,secrets.fingerprint({syntheticAck:op}),secrets.encrypt(null,`mutation:${op}:before`),secrets.encrypt(step.mutationPayload,`mutation:${op}:payload`),secrets.encrypt(step.mutationPayload,`mutation:${op}:result`)]);
     await tx.exec("UPDATE workflow_steps SET state='succeeded',safe_result=$2::jsonb,started_at=now(),completed_at=now(),revision=revision+1 WHERE id=$1",[step.id,JSON.stringify({nativeOperationId:op,remoteStarted:true,remoteCompleted:true})]);
    }
    const input={plan,step:last,actor:superActor(t.wid),executionId};let result:any;
    if(info.legacy){
     proof={version:1,clusterId:t.cid,workspaceId:t.wid,publicationId:id,publicationRevision:1,transportScope:t.scope,clusterRevision:1,workspaceRevision:1,executionMode:'direct',workflowId,executionId,planRevision:1,planHash:row.plan_hash,verifiedAt:new Date().toISOString(),serviceId,aclGroup:before.acl_group,aclPluginId:aclId,keyAuthPluginId:keyId,service,aclPlugin:acl,keyAuthPlugin:key,schemas:(last.metadata as any).schemas,definitions:{}};
     if(info.proofPadding)proof.schemas.keyAuth={fields:[],historicalPadding:'X'.repeat(info.proofPadding)};
     await tx.exec('INSERT INTO portal_publication_proofs(cluster_id,workspace_id,publication_id,publication_revision,transport_scope,publication_proof_secret,publication_proof_hmac,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,1,$9)',[t.cid,t.wid,id,t.scope,secrets.encrypt(proof,publicationProofAad(t.cid,t.wid,id,1)),secrets.fingerprint(proof),workflowId,executionId,row.plan_hash]);
     await tx.exec("UPDATE portal_publications SET state='published',published_revision=1,acl_plugin_id=$2,key_auth_plugin_id=$3,workflow_id=$4,revision=revision+1 WHERE id=$1",[id,aclId,keyId,workflowId]);result={entity:{id,name:info.name,category:info.category}};
    }else{
     phase='fixture.publication.prepare-apply';const handler=registry.get('portal.publication.publish');await execution.runHttp({requestId:randomUUID(),ip:'192.0.2.17'},async()=>{execution.bindHttpActor(input.actor.user);await handler.prepare?.(input);result=await handler.apply({...input,transaction:tx});});
     proof=secrets.decrypt((await tx.one<any>('SELECT publication_proof_secret FROM portal_publication_proofs WHERE publication_id=$1',[id]))!.publication_proof_secret,publicationProofAad(t.cid,t.wid,id,1));
     await tx.exec('UPDATE portal_publications SET workflow_id=$2 WHERE id=$1',[id,workflowId]);
    }
    await tx.exec("UPDATE workflow_steps SET state='succeeded',safe_result=$2::jsonb,started_at=now(),completed_at=now(),revision=revision+1 WHERE id=$1",[last.id,JSON.stringify(secrets.redact(result))]);
    await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1 WHERE id=$1",[executionId]);
    await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1 WHERE id=$1",[workflowId]);
   });publishedFixtures++;return{id,serviceId,workflowId,executionId,plan,proof};
  };
  const x=await published(a,{name:'Published Pay API',category:'pay'}),y=await published(a,{name:'Published Ops API',category:'ops'}),legacy=await published(a,{name:'Legacy Published API',category:'draft-legacy',legacy:true});
  await published(foreign,{name:'Foreign API',category:'pay'});
  await sql.exec("UPDATE portal_publications SET name='Draft replacement name',description='Draft replacement description',category='draft-only',revision=revision+1 WHERE id=$1",[x.id]);
  const grant=randomUUID(),issue=randomUUID(),rotate=randomUUID(),credential=randomUUID(),consumer=randomUUID();
  await sql.transaction(async tx=>{
   await tx.exec('INSERT INTO portal_application_grants(id,cluster_id,workspace_id,transport_scope,application_id,publication_id,developer_id,consumer_id,acl_group,acl_id) SELECT $1,cluster_id,workspace_id,transport_scope,$2,id,$3,$4,acl_group,$5 FROM portal_publications WHERE id=$6',[grant,a.appId,a.developerId,consumer,randomUUID(),x.id]);
   const before=await tx.one<any>('SELECT * FROM portal_application_grants WHERE id=$1',[grant]);
   for(const [workflowId,kind]of [[issue,'portal-credential-issue'],[rotate,'portal-credential-rotate']]as const){const steps=kind==='portal-credential-issue'?[native.nativeStep(1,'consumers','create',{id:consumer,username:`consumer-${grant}`},null,{workflowId})]:[native.metadataStep(1,'portal.credential.rotate','portal_application_grants',grant,before,{synthetic:true},[])];
    const plan:WorkflowPlanV1={version:1,clusterId:a.cid,workspaceId:a.wid,workflowId,planRevision:1,kind,executionMode:'direct',approvalRequired:true,subject:{type:'portal_application_grants',id:grant},requester:{type:'developer',id:a.developerId},definition:await plans.definition(a.cid,a.wid,kind,tx),issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString(),scope:{transportScope:a.scope,clusterRevision:1,workspaceRevision:1},prerequisites:[],steps};await plans.persist(plan,`history-${workflowId}`,{synthetic:true},tx,{requestId:randomUUID(),ip:'192.0.2.17'});
   }
   await tx.exec('UPDATE portal_application_grants SET workflow_id=$2 WHERE id=$1',[grant,rotate]);
   await tx.exec('INSERT INTO portal_credentials(id,cluster_id,workspace_id,grant_id,developer_id,consumer_id,kong_id,generation,key_secret,key_fingerprint,workflow_id) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10)',[credential,a.cid,a.wid,grant,a.developerId,consumer,randomUUID(),secrets.encrypt({key:'SyntheticNeverExportedCatalogKey'},`portal:credential:${a.cid}:${a.wid}:${credential}:1:key`),secrets.fingerprint('SyntheticNeverExportedCatalogKey'),issue]);
  });
  const safeDto=(value:unknown)=>{const text=JSON.stringify(value);assert(!/password_hash|key_secret|publication_proof_secret|payload_secret|token_hash|SyntheticNeverExportedCatalogKey|\$2b\$12\$/.test(text));};
  const scoped={workspaceId:a.wid,size:20};
  const adminNativeReads=nativeReads;
  // Exact new method names and assertions are finalized against the owner's
  // physically published implementation; no replacement query is used here.
  await check('developer detail applies actual developers.read and returns no password/session materials',async()=>{const out=await (admin as any).developer(a.cid,a.developerId,{workspaceId:a.wid},developers);assert.equal(out.entity.id,a.developerId);safeDto(out);await denied(()=>(admin as any).developer(a.cid,a.developerId,{workspaceId:a.wid},apps),403);});
  await check('application detail applies actual applications.read without requiring developer-directory permission',async()=>{const out=await (admin as any).application(a.cid,a.appId,{workspaceId:a.wid},apps);assert.equal(out.entity.id,a.appId);safeDto(out);await denied(()=>(admin as any).application(a.cid,a.appId,{workspaceId:a.wid},developers),403);});
  await check('same native business tags cannot elevate metadata tag_group grants to whole workspace',async()=>{await denied(()=>(admin as any).developer(a.cid,a.developerId,{workspaceId:a.wid},restricted),403);await denied(()=>(admin as any).application(a.cid,a.appId,{workspaceId:a.wid},restricted),403);});
  await check('foreign cluster and workspace details do not mix identities',async()=>{await denied(()=>(admin as any).application(a.cid,foreign.appId,{workspaceId:a.wid},full),404);await denied(()=>(admin as any).developer(a.cid,b.developerId,{workspaceId:a.wid},full),404);await denied(()=>(admin as any).application(foreign.cid,foreign.appId,{workspaceId:foreign.wid},{...full,workspaceId:foreign.wid}),403);});
  await check('detail strict query requires explicit matching workspace and refuses mass-assigned owner selector',async()=>{await denied(()=>admin.application(a.cid,a.appId,{},full),400);await denied(()=>admin.developer(a.cid,a.developerId,{workspaceId:a.wid,userId:superuser.id},full),400);await denied(()=>admin.application(a.cid,a.appId,{workspaceId:b.wid},full),403);});
  await check('existing developer/application directories require explicit matching request scope',async()=>{await denied(()=>admin.developers(a.cid,{},full),400);await denied(()=>admin.applications(a.cid,{workspaceId:b.wid},full),403);});
  await check('application grants require applications plus portal whole-workspace read and mask pending key',async()=>{const out=await (admin as any).applicationGrants(a.cid,a.appId,scoped,full);assert(out.items.some((r:any)=>r.id===grant));safeDto(out);await denied(()=>(admin as any).applicationGrants(a.cid,a.appId,scoped,apps),403);});
  await check('application history follows immutable workflow subject while grant pointer refers to later rotation',async()=>{const out=await (admin as any).applicationRequests(a.cid,a.appId,scoped,full);assert(out.items.some((r:any)=>(r.id??r.workflowId)===issue));assert(out.items.some((r:any)=>(r.id??r.workflowId)===rotate));safeDto(out);await denied(()=>(admin as any).applicationRequests(a.cid,a.appId,scoped,apps),403);});
  await check('workspace portal requests follow exact subject identity rather than mutable grant workflow pointer',async()=>{const out=await (admin as any).requests(a.cid,scoped,full);assert(out.items.some((r:any)=>(r.id??r.workflowId)===issue));safeDto(out);});
  await check('foreign application nested grant/request selectors fail closed',async()=>{await denied(()=>(admin as any).applicationGrants(a.cid,b.appId,scoped,full),404);await denied(()=>(admin as any).applicationRequests(a.cid,foreign.appId,scoped,full),404);});
  await check('application capabilities reveal only current relational read permissions',async()=>{const all=await admin.application(a.cid,a.appId,{workspaceId:a.wid},full),own=await admin.application(a.cid,a.appId,{workspaceId:a.wid},apps);assert.deepEqual(all.entity.capabilities,{readGrants:true,readRequests:true});assert.deepEqual(own.entity.capabilities,{readGrants:false,readRequests:false});});
  await check('request cursor binds original actor workspace filter page size and current IAM epoch',async()=>{
   const input={workspaceId:a.wid,size:1},first=await admin.applicationRequests(a.cid,a.appId,input,full);assert(first.nextCursor);
   await denied(()=>admin.applicationRequests(a.cid,a.appId,{...input,cursor:first.nextCursor},otherActor),400);
   await denied(()=>admin.applicationRequests(a.cid,a.appId,{...input,state:'pending',cursor:first.nextCursor},full),400);
   await denied(()=>admin.applicationRequests(a.cid,a.appId,{...input,size:2,cursor:first.nextCursor},full),400);
   await sql.exec('UPDATE users SET revision=revision+1 WHERE id=$1',[full.user.id]);
   // A real permission row insertion changes the global IAM epoch; no mock
   // permissionVersion or edited cursor supplies this revocation boundary.
   await sql.exec("INSERT INTO role_permissions(role_id,module,action,scope_type,cluster_id,workspace_id) VALUES($1,'overview','read','workspace',$2,$3)",[full.role,a.cid,a.wid]);
   await denied(()=>admin.applicationRequests(a.cid,a.appId,{...input,cursor:first.nextCursor},full),400);
  });
  await check('actual database revocation after awaited grant query denies all old rows before DTO return',async()=>{
   const racing=await reader(a,['applications','portal']);let fired=false;
   afterQuery=async(q)=>{if(!fired&&q.includes('FROM portal_application_grants g JOIN portal_applications')){fired=true;await sql.exec("UPDATE role_permissions SET status='revoked',revoked_at=now(),retention_until=now()+interval '30 days',revision=revision+1 WHERE role_id=$1 AND module='portal'",[racing.role]);}};
   try{await denied(()=>admin.applicationGrants(a.cid,a.appId,scoped,racing),403);assert(fired);}finally{afterQuery=undefined;}
  });
  for(const [module,run,pattern]of [
   ['developers',(r:EntityActor)=>admin.developers(a.cid,scoped,r),'FROM portal_developers WHERE'],
   ['applications',(r:EntityActor)=>admin.applications(a.cid,scoped,r),'FROM portal_applications WHERE'],
   ['workflows',(r:EntityActor)=>admin.requests(a.cid,scoped,r),'FROM workflows w JOIN portal_application_grants'],
  ]as const)await check(`${module} list rechecks current authorization after actual SQL read`,async()=>{
   const racing=await reader(a,[module]);let fired=false;afterQuery=async(q)=>{if(!fired&&q.includes(pattern)){fired=true;await sql.exec("UPDATE role_permissions SET status='revoked',revoked_at=now(),retention_until=now()+interval '30 days',revision=revision+1 WHERE role_id=$1 AND module=$2",[racing.role,module]);}};
   try{await denied(()=>run(racing),403);assert(fired);}finally{afterQuery=undefined;}
  });
  await check('disabled workspace preserves explicitly authorized metadata history but public tenant is unavailable',async()=>{
   await sql.exec("UPDATE workspaces SET status='disabled',revision=revision+1 WHERE id=$1",[a.wid]);try{assert.equal((await admin.application(a.cid,a.appId,{workspaceId:a.wid},full)).entity.id,a.appId);await denied(()=>publicService.publications({clusterId:a.cid,workspaceId:a.wid}),404);}finally{await sql.exec("UPDATE workspaces SET status='active',revision=revision+1 WHERE id=$1",[a.wid]);}
  });
  await check('metadata details and relational histories do not make even synthetic Gateway GETs',async()=>{assert.equal(nativeReads,adminNativeReads);});
  await check('public detail uses sealed publication name/category, not subsequently edited draft fields',async()=>{const out=await publicService.publication(x.id,{clusterId:a.cid,workspaceId:a.wid});assert.equal(out.entity.name,'Published Pay API');assert.equal(out.entity.category,'pay');safeDto(out);});
  await check('catalog fills requested size with proof-verified category matches despite nonmatching candidates',async()=>{const out=await publicService.publications({clusterId:a.cid,workspaceId:a.wid,size:1,category:'pay'});assert.equal(out.items.length,1);assert.equal(out.items[0].id,x.id);safeDto(out);});
  await check('catalog search matches published proof names and excludes changed draft names',async()=>{assert((await publicService.publications({clusterId:a.cid,workspaceId:a.wid,search:'Published Pay'})).items.some((r:any)=>r.id===x.id));assert.equal((await publicService.publications({clusterId:a.cid,workspaceId:a.wid,search:'Draft replacement'})).items.length,0);});
  await check('legacy publicationInfo absence is null category and never borrows draft category',async()=>{const out=await publicService.publication(legacy.id,{clusterId:a.cid,workspaceId:a.wid});assert.equal(out.entity.category,null);assert.equal((await publicService.publications({clusterId:a.cid,workspaceId:a.wid,category:'draft-legacy'})).items.length,0);});
  await check('public cursor binds requested search/category/size/tenant and no foreign publication is returned',async()=>{const first=await publicService.publications({clusterId:a.cid,workspaceId:a.wid,size:1});assert(first.nextCursor);for(const change of [{size:2},{category:'pay'},{search:'Published'},{workspaceId:foreign.wid,clusterId:foreign.cid}])await denied(()=>publicService.publications({clusterId:a.cid,workspaceId:a.wid,size:1,cursor:first.nextCursor,...change}),400);});
  await check('public keyset continuation resumes from last processed candidate without skipping prefetched tail',async()=>{let cursor:string|undefined,seen:string[]=[];for(let n=0;n<5;n++){const out=await publicService.publications({clusterId:a.cid,workspaceId:a.wid,size:1,...(cursor?{cursor}:{})});seen.push(...out.items.map((r:any)=>r.id));if(!out.nextCursor)break;cursor=out.nextCursor;}assert.deepEqual([...seen].sort(),[x.id,y.id,legacy.id].sort());assert.equal(new Set(seen).size,seen.length);});
  const ties=await tenant(),tieTime='2026-01-01T00:00:00.123456Z';
  const tie1=await published(ties,{name:'Tie API one',category:'tie',createdAt:tieTime}),tie2=await published(ties,{name:'Tie API two',category:'tie',createdAt:tieTime});
  await check('microsecond timestamp tie uses native UUID keyset and does not round or duplicate rows',async()=>{const first=await publicService.publications({clusterId:ties.cid,workspaceId:ties.wid,size:1});assert(first.nextCursor);const second=await publicService.publications({clusterId:ties.cid,workspaceId:ties.wid,size:1,cursor:first.nextCursor});assert.equal(second.nextCursor,null);assert.deepEqual([first.items[0].id,second.items[0].id].sort(),[tie1.id,tie2.id].sort());});
  await check('public catalog rechecks tenant publication state after SQL await',async()=>{let fired=false;afterQuery=async(q)=>{if(!fired&&q.startsWith('WITH candidates AS')){fired=true;await sql.exec('UPDATE portal_settings SET published=false,revision=revision+1 WHERE cluster_id=$1 AND workspace_id=$2',[a.cid,a.wid]);}};try{await denied(()=>publicService.publications({clusterId:a.cid,workspaceId:a.wid}),404);assert(fired);}finally{afterQuery=undefined;await sql.exec('UPDATE portal_settings SET published=true,revision=revision+1 WHERE cluster_id=$1 AND workspace_id=$2',[a.cid,a.wid]);}});
  const byteTenant=await tenant(),byteTarget=await published(byteTenant,{name:'Old Byte Needle API',category:'byte',createdAt:'2025-01-01T00:00:00.000Z'});
  for(let n=0;n<28;n++)await published(byteTenant,{name:`Historical budget candidate ${n}`,category:null,legacy:true,proofPadding:1024*1024,createdAt:new Date(Date.UTC(2026,0,1,0,0,n)).toISOString()});
  await check('schema-valid ciphertext prefixes stop at aggregate32MiB and retain exact partial continuation',async()=>{const input={clusterId:byteTenant.cid,workspaceId:byteTenant.wid,size:1,search:'Byte Needle'},first=await publicService.publications(input);assert.equal(first.items.length,0);assert.equal(first.scanIncomplete,true);assert(first.nextCursor);assert(first.searchedRows>0&&first.searchedRows<28);const second=await publicService.publications({...input,cursor:first.nextCursor});assert.equal(second.items[0]?.id,byteTarget.id);assert.equal(second.scanIncomplete,false);});
  await check('SQL008 independently rejects oversized proof cipher rather than admitting an unbounded row',async()=>{const ciphertext=secrets.encrypt({historicalPadding:'X'.repeat(3*1024*1024)},'synthetic-oversized-boundary');assert.equal((await sql.one<any>('SELECT m6_encrypted($1) AS admitted',[ciphertext]))!.admitted,false);});

  // Sparse matches force an actual >500-row continuation while all candidates
  // retain real sealed manifests, immutable successful proof and SQL terminal.
  const budgetTenant=await tenant();const target=await published(budgetTenant,{name:'Old matching API',category:'needle',createdAt:'2025-01-01T00:00:00.000Z'});
  for(let n=0;n<501;n++)await published(budgetTenant,{name:`Budget candidate ${n}`,category:'other',createdAt:new Date(Date.UTC(2026,0,1,0,0,n)).toISOString()});
  await check('fixed candidate budget returns honest partial cursor and eventually finds older matching proof',async()=>{
   const input={clusterId:budgetTenant.cid,workspaceId:budgetTenant.wid,size:1,category:'needle'},first=await publicService.publications(input);assert.equal(first.items.length,0);assert.equal(first.scanIncomplete,true);assert.equal(first.searchedRows,500);assert(first.nextCursor);const next=await publicService.publications({...input,cursor:first.nextCursor});assert.equal(next.items[0]?.id,target.id);assert.equal(next.scanIncomplete,false);
  });
  await check('runtime cannot UPDATE DELETE or TRUNCATE immutable publication proofs',async()=>{for(const q of ['UPDATE portal_publication_proofs SET publication_proof_hmac=publication_proof_hmac','DELETE FROM portal_publication_proofs','TRUNCATE portal_publication_proofs']){try{await sql.exec(q);throw new Error('EXPECTED_PRIVILEGE_REJECTION');}catch(e:any){assert.equal(e.code,'42501');}}});
  await check('frozen sources and migrations remain unchanged with zero native network writes',async()=>{assert.deepEqual(productHashes(),sourceHashes);for(const row of migrations)assert.equal(row.checksum,sha(readFileSync(`apps/console-api/src/infrastructure/migrations/${row.name}`)));assert.equal(nativeWrites,0);assert(runtimeCalls>0);});
 }catch(e:any){failureCode=code(e);failureMetadata=Object.fromEntries(["constraint","table","column","routine"].filter(k=>typeof e?.[k]==="string").map(k=>[k,String(e[k]).replace(/[^A-Za-z0-9_.-]/g,"_").slice(0,128)]));throw e;}finally{
  mkdirSync('artifacts/M6',{recursive:true});const artifact=`artifacts/M6/portal-admin-catalog-postgres-${runId}.json`;
  writeFileSync(artifact,JSON.stringify({milestone:'M6',status:failureCode?'FAIL':'PASS',failureCode,failurePhase:failureCode?phase:undefined,failureMetadata,serverVersion,migrations,sourceHashes,testHash:sha(readFileSync('tests/integration/portal-admin-catalog.ts')),roleEvidence,runtimeCalls,publishedFixtures,nativeFixtureReads:nativeReads,nativeWireRequests:0,nativeWrites,businessHttpRequests:0,browserActions:0,privateReferenceReads:0,checks,passed:checks.filter(c=>c.passed).length,total:checks.length,limitations:['actual services/schema/current DB grants run with a nonowner non-superuser runtime SQL role','publication manifests are persisted by real WorkflowPlans/nativeStep and current proof generated by actual registry prepare/apply plus atomic terminal fixtures','read-only Gateway objects and native ACK SQL rows are synthetic, not real transport or proxy behavior','legacy proof is an explicitly sealed schema-valid historical fixture without publicationInfo','no current environment, application DB, private reference, business HTTP, browser, build, deployment or original production material is accessed']},null,2));
  await runtime?.onModuleDestroy();await owner?.onModuleDestroy();try{docker(['rm','-f',container]);}catch{}
  process.stdout.write(JSON.stringify({artifact,status:failureCode?'FAIL':'PASS',passed:checks.filter(c=>c.passed).length,total:checks.length,nativeWireRequests:0})+'\n');
 }
}
main().catch(()=>{process.stderr.write('Isolated Portal admin/catalog proof failed; safe artifact retained.\n');process.exitCode=1;});
