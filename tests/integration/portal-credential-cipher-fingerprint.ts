import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {compileFunction} from 'node:vm';
import {createHash,randomUUID} from 'node:crypto';
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
import {publicationProofAad,type PortalPublicationProofV1} from '../../apps/console-api/src/modules/portal/portal-proof';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import {snapshotAad,type WorkflowPlanV1} from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Query portability proof uses disposable PostgreSQL with actual schema and compiler.
 * Principal identity validation, Redis leases, authorization and Gateway are
 * explicit fixtures. This does not replace real HTTP authentication or Kong. */
async function main():Promise<void>{
 const container=`kongos-m6-cipher-${randomUUID().slice(0,8)}`,runId=new Date().toISOString().replace(/[:.]/g,'-');
 const checks:Array<{name:string;passed:boolean;errorCode?:string;column?:string}>=[];
 let db:DbService|undefined,nativeCalls=0,consoleContexts=0,failureCode:string|undefined,businessRequests=0;
 let helperSourceHash:string|undefined,queryHash:string|undefined,serverVersion:string|undefined;
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

  await check('fresh actual PostgreSQL16 and unchanged schema000-008 have no pgcrypto extension',async()=>{
   serverVersion=(await sql.one<any>('SHOW server_version')).server_version;assert.match(serverVersion!,/^16\./);assert.equal((await sql.one<any>("SELECT count(*)::int AS n FROM pg_extension WHERE extname='pgcrypto'")).n,0);
   migrations=await sql.query<{name:string;checksum:string}>('SELECT name,checksum FROM schema_migrations ORDER BY name');assert.equal(migrations.length,9);
   for(const migration of migrations)assert.equal(migration.checksum,createHash('sha256').update(readFileSync(`apps/console-api/src/infrastructure/migrations/${migration.name}`)).digest('hex'));
  });
  const base=await fixture(),submitted=await request(base),loaded=await plans.load(base.cid,base.wid,submitted.workflowId),executionId=randomUUID(),executionKey=`cipher-execution-${executionId}`;
  await sql.transaction(async tx=>{
   await tx.exec("INSERT INTO workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,approver_id,decision,idempotency_key) VALUES($1,$2,$3,1,$4,1,$5,'approve',$6)",[base.cid,base.wid,loaded.row.id,loaded.row.plan_hash,admin.id,`approval-${executionId}`]);
   await tx.exec("UPDATE workflow_stages SET state='approved',completed_at=now() WHERE workflow_id=$1",[loaded.row.id]);
   await tx.exec("UPDATE workflows SET state='executing',approved_by=$2,approved_at=now(),revision=revision+1,updated_at=now() WHERE id=$1",[loaded.row.id,admin.id]);
   await tx.exec(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,claim_token_hash,idempotency_key,expires_at)
    VALUES($1,$2,$3,$4,1,$5,'direct',true,$6,$6,'executing',$7,$8,now()+interval '30 minutes')`,[executionId,base.cid,base.wid,loaded.row.id,loaded.row.plan_hash,admin.id,secrets.fingerprint({claim:executionId}),executionKey]);
  });
  const key=(await sql.one<any>('SELECT id,key_secret FROM portal_credentials WHERE grant_id=$1',[submitted.grant.id]))!;
  const source=readFileSync('tests/security/lib/m6-metadata-recovery.mjs','utf8');helperSourceHash=createHash('sha256').update(source).digest('hex');
  const body=/function databaseProof\(h\)\{([\s\S]*?)\n\}/.exec(source)?.[1];assert(body,'ACTUAL_HARNESS_PROOF_FUNCTION_MISSING');
  const initializer=/export const METADATA_RECOVERY_DATABASE_SQL=(`[^`]*`);/.exec(source)?.[1];assert(initializer,'ACTUAL_HARNESS_SQL_EXPORT_MISSING');
  const exportedQuery=compileFunction(`return ${initializer};`)() as string;
  // Compile the owner's actual pure helper, supplying only its fixed lookup
  // tuple. The sync consoleRead adapter captures its exact SQL+binds; SQL then
  // runs through real DbService on the isolated valid M6 tuple.
  const compiled=compileFunction(body,['h','T','M6_C1','M6_C2','METADATA_RECOVERY_DATABASE_SQL']);
  let query='',params:unknown[]=[];
  compiled({referenceData:{fixtures:[{workspace:{id:base.wid}}]},consoleRead:(sqlText:string,binds:unknown[])=>{assert.equal(query,'');query=sqlText;params=binds;return[{id:key.id}];},check:(condition:boolean)=>assert(condition)},
   {credentialId:key.id,grantId:submitted.grant.id,clusterId:base.cid,workspaceId:base.wid,executionId,executionKey},base.cid,base.cid,exportedQuery);
  assert(query&&params.length===8,'ACTUAL_HARNESS_PROOF_QUERY_MISSING');assert.equal(query,exportedQuery);queryHash=createHash('sha256').update(query).digest('hex');
  const portable="encode(sha256(convert_to(c.key_secret,'UTF8')),'hex')",legacy="encode(digest(c.key_secret,'sha256'),'hex')";
  const legacyQuery=query.includes(legacy)?query:query.replace(portable,legacy);assert(legacyQuery.includes(legacy));
  await check('legacy actual proof SQL fails42883 before any simulated metadata business request',async()=>{
   await rejected(async()=>{await sql.query(legacyQuery,params);businessRequests++;},'42883');assert.equal(businessRequests,0);
  });
  await check('builtin SHA256 bytea function is available without any extension installation',async()=>{
   assert((await sql.one<any>("SELECT to_regprocedure('sha256(bytea)') AS sha,to_regprocedure('digest(text,text)') AS digest")).sha);assert.equal((await sql.one<any>("SELECT to_regprocedure('digest(text,text)') AS digest")).digest,null);
  });
  const samples=[{name:'ASCII synthetic ciphertext text',text:'v1.synthetic.ciphertext.ABC_123-xyz'},
   {name:'Unicode synthetic text',text:'密文/λ/🙂/é'},
   {name:'mixed line endings and Unicode normalization bytes',text:'line\r\n新行\ne\u0301'},
   {name:'empty string bytes',text:''},
   {name:'actual immutable Portal key AES-GCM ciphertext',text:key.key_secret}];
  for(const sample of samples)await check(`${sample.name}: native PostgreSQL UTF8 SHA256 equals Node bytes`,async()=>{
   const row=await sql.one<any>("SELECT encode(sha256(convert_to($1::text,'UTF8')),'hex') AS fingerprint",[sample.text]);assert.equal(row.fingerprint,createHash('sha256').update(sample.text,'utf8').digest('hex'));
  });
  await check('owner actual compiled databaseProof uses portable builtin query on a valid real M6 fixture',async()=>{
   assert(query.includes(portable),'OWNER_HARNESS_QUERY_NOT_YET_PORTABLE');assert(!query.includes('digest('));
   const rows=await sql.query<any>(query,params);assert.equal(rows.length,1);assert.equal(rows[0].id,key.id);assert.equal(rows[0].immutable_key_cipher_sha,createHash('sha256').update(key.key_secret,'utf8').digest('hex'));
  });
  await check('fingerprint reads leave key bytes and real workflow/native facts unchanged and send zero requests',async()=>{
   assert.equal((await sql.one<any>('SELECT key_secret FROM portal_credentials WHERE id=$1',[key.id])).key_secret,key.key_secret);
   assert.deepEqual(await counts(base),{grants:1,credentials:1,workflows:1,mutations:0});assert.equal(nativeCalls,0);assert.equal(consoleContexts,0);assert.equal(businessRequests,0);
  });
 }catch(error){failureCode=safeCode(error);throw error;}finally{
  mkdirSync('artifacts/M6',{recursive:true});const artifact=`artifacts/M6/portal-credential-cipher-fingerprint-postgres-${runId}.json`;
  writeFileSync(artifact,JSON.stringify({milestone:'M6',status:failureCode?'FAIL':'PASS',failureCode,database:'disposable PostgreSQL16; unchanged migrations000-008; no pgcrypto',serverVersion,migrations,helperSource:'tests/security/lib/m6-metadata-recovery.mjs:databaseProof/METADATA_RECOVERY_DATABASE_SQL',helperSourceHash,queryHash,actual:['real PostgreSQL builtin sha256(convert_to())','owner exported SQL initializer and compiled private databaseProof SQL+8 binds','real M6 constraints/Portal credential request/sealed plan/immutable key fixture','Node SHA256 UTF8 byte comparison'],fixtures:['Gateway/network forbidden','authorization/developer identity for fixture creation','simulated post-proof metadata business callback; no activation/reconcile call'],businessRequests,nativeCalls,consoleContexts,checks,passed:checks.filter(item=>item.passed).length,total:checks.length},null,2));
  if(db)await db.onModuleDestroy();try{execFileSync('docker',['rm','-f',container],{stdio:'ignore'});}catch{}
  process.stdout.write(JSON.stringify({artifact,status:failureCode?'FAIL':'PASS',passed:checks.filter(item=>item.passed).length,total:checks.length,businessRequests,nativeCalls})+'\n');
 }
}
main().catch(()=>{process.stderr.write('Isolated cipher fingerprint proof failed; safe artifact retained.\n');process.exitCode=1;});

