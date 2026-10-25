import { AuditOutboxWriter } from '../../apps/console-api/src/modules/event-core/audit-outbox-writer.service';
import 'reflect-metadata';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {compileFunction} from 'node:vm';
import {DbService} from '../../apps/console-api/src/infrastructure/db.service';
import {provisionRuntimeRole} from '../../apps/console-api/src/infrastructure/migrate';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {AuditService} from '../../apps/console-api/src/modules/audit/audit.service';
import {WorkflowPlansService} from '../../apps/console-api/src/modules/workflows/workflow-plans.service';
import {PortalNativeService} from '../../apps/console-api/src/modules/portal/portal-native.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {snapshotAad,type WorkflowPlanV1,type WorkflowKind} from '../../apps/console-api/src/modules/workflows/workflow.types';
import {portalKeyAad} from '../../apps/console-api/src/modules/portal/portal-proof';

/** Actual exported tenant continuity reader against unchanged migrations.
 * Only a mutable reservation pointer is changed: this is not a simulation of
 * successful native issuance, rotation or terminal generation2 revocation. */
async function main():Promise<void>{
 const runId=new Date().toISOString().replace(/[:.]/g,'-'),container=`kongos-m6-origin-${randomUUID().slice(0,8)}`;
 const sourcePath='deploy/scripts/verify-portal-tenant-static-continuity.mjs';
 const expectedProgramHash='79f48a26c6782b3aa0151e7704bc8def330528d75f1be6b2183909670eba736d';
 const sha=(value:string|Buffer)=>createHash('sha256').update(value).digest('hex');
 const safeCode=(error:any)=>String(error?.code??'ASSERTION_FAILED').replace(/[^A-Z0-9_]/gi,'_').slice(0,128);
 const checks:Array<{name:string;passed:boolean;errorCode?:string}>=[];
 let owner:DbService|undefined,runtime:DbService|undefined,failureCode:string|undefined,serverVersion:string|undefined;
 let programHash:string|undefined,grantQueryHash:string|undefined,sourceHash:string|undefined;
 let migrations:Array<{name:string;checksum:string}>=[],programRuns=0,programRejections=0,nativeRequests=0;
 let roleEvidence:Record<string,unknown>|undefined;
 const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(error){checks.push({name,passed:false,errorCode:safeCode(error)});throw error;}};
 const dockerEnv={...process.env};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete dockerEnv[key];
 const docker=(args:string[])=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env:dockerEnv,encoding:'utf8',stdio:['ignore','pipe','pipe']});
 try{
  sourceHash=sha(readFileSync(sourcePath));
  const loader=`(async()=>{const m=await import(${JSON.stringify(resolve(sourcePath))});process.stdout.write(JSON.stringify({program:m.PORTAL_TENANT_READONLY_PROGRAM}));})().catch(()=>process.exit(1));`;
  const program=JSON.parse(execFileSync(process.execPath,['-e',loader],{env:{PATH:process.env.PATH},encoding:'utf8',stdio:['ignore','pipe','pipe']})).program as string;
  assert.equal(typeof program,'string');programHash=sha(program);assert.equal(programHash,expectedProgramHash,'OWNER_FROZEN_PROGRAM_REQUIRED');assert(program.includes('REPEATABLE READ READ ONLY'));
  const queryExpression=/const grant=await rows\((.*),\[workflowId\]\);/.exec(program)?.[1];assert(queryExpression,'ACTUAL_GRANT_QUERY_REQUIRED');
  const digest=(alias:string)=>`encode(sha256(convert_to(to_jsonb(${alias})::text,'UTF8')),'hex') AS "rowSHA256"`;
  const grantQuery=compileFunction(`return ${queryExpression};`,['digest'])(digest) as string;grantQueryHash=sha(grantQuery);
  assert(grantQuery.includes('origin.subject_id=g.id'));assert(grantQuery.includes('origin.cluster_id=g.cluster_id'));assert(grantQuery.includes('origin.workspace_id=g.workspace_id'));
  docker(['run','-d','--pull=never','--name',container,'-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine']);
  const port=docker(['port',container,'5432']).trim().split(':').pop();process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;
  process.env.CONSOLE_ENCRYPTION_KEY='cd'.repeat(32);process.env.APP_SECRET='SyntheticTenantHistoryReaderKey2026!';
  process.env.BOOTSTRAP_ADMIN_USERNAME='origin-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!OriginBootstrap2026Password';
  owner=new DbService();for(let n=0;n<80;n++){try{await owner.one('SELECT 1');break;}catch{if(n===79)throw new Error('DISPOSABLE_DATABASE_UNAVAILABLE');await new Promise(done=>setTimeout(done,100));}}
  await owner.migrateAndSeed();const sql=owner;
  process.env.CONSOLE_DB_RUNTIME_USER='m6_origin_runtime';process.env.CONSOLE_DB_RUNTIME_PASSWORD='Synthetic!OriginRuntime2026Password';await provisionRuntimeRole(sql);
  const runtimeUrl=`postgres://m6_origin_runtime@127.0.0.1:${port}/postgres`;process.env.DATABASE_URL=runtimeUrl;runtime=new DbService();
  await check('unchanged000-009 and genuine non-owner non-superuser runtime caller',async()=>{
   serverVersion=(await sql.one<any>('SHOW server_version')).server_version;assert.match(serverVersion!,/^16\./);
   migrations=await sql.query('SELECT name,checksum FROM schema_migrations ORDER BY name');assert.equal(migrations.length,10);
   for(const row of migrations)assert.equal(row.checksum,sha(readFileSync(`apps/console-api/src/infrastructure/migrations/${row.name}`)));
   const role=await runtime!.one<any>('SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user');for(const value of Object.values(role))assert.equal(value,false);
   const owns=(await runtime!.one<any>("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relname IN('workflows','portal_application_grants','workflow_versions') AND r.rolname=current_user) AS owns")).owns;assert.equal(owns,false);
   roleEvidence={...role,ownsFixtureTables:owns};
  });
  const secrets=new SecretService(),audit=new AuditService(sql,secrets,new AuditOutboxWriter(sql,secrets)),plans=new WorkflowPlansService(sql,secrets,audit),admin=(await sql.one<any>('SELECT id FROM users WHERE super_admin'))!;
  const native=new PortalNativeService(sql,secrets,{request:async()=>{nativeRequests++;throw new Error('NATIVE_FORBIDDEN');}} as any,{} as any,{} as any,new WorkspaceResolverService(sql));
  const tenant=async(cid=randomUUID())=>{
   const wid=randomUUID(),did=randomUUID(),app=randomUUID(),pub=randomUUID(),grant=randomUUID(),consumer=randomUUID(),scope=secrets.fingerprint({cid});
   await sql.transaction(async tx=>{
    await tx.exec("INSERT INTO clusters(id,name,admin_url,version,status) VALUES($1,$2,$3,'1.5.1','healthy') ON CONFLICT(id) DO NOTHING",[cid,`origin-${cid}`,`http://synthetic-${cid}.invalid:8001`]);
    await tx.exec("INSERT INTO workspaces(id,cluster_id,code,name) VALUES($1,$2,$3,'Synthetic origin tenant')",[wid,cid,`w${wid.slice(0,8)}`]);
    await tx.exec("INSERT INTO portal_settings(cluster_id,workspace_id,slug,name) VALUES($1,$2,$3,'Synthetic origin portal')",[cid,wid,`origin-${wid}`]);
    await tx.exec("INSERT INTO portal_developers(id,cluster_id,workspace_id,username,email,display_name,password_hash,status) VALUES($1,$2,$3,$4,$5,'Synthetic developer',$6,'active')",[did,cid,wid,`dev-${did}`,`${did}@example.test`,`$2b$12$${'a'.repeat(53)}`]);
    await tx.exec("INSERT INTO portal_applications(id,cluster_id,workspace_id,developer_id,name) VALUES($1,$2,$3,$4,'Synthetic app')",[app,cid,wid,did]);
    await tx.exec("INSERT INTO portal_publications(id,cluster_id,workspace_id,transport_scope,slug,name,service_id,acl_group,created_by,updated_by) VALUES($1,$2,$3,$4,$5,'Synthetic API',$6,$7,$8,$8)",[pub,cid,wid,scope,`api-${pub}`,randomUUID(),`kos-portal-api-${pub}`,admin.id]);
    await tx.exec("INSERT INTO portal_publication_revisions(cluster_id,workspace_id,publication_id,revision,service_id,title,version_label,openapi_document,document_hash,created_by) SELECT cluster_id,workspace_id,id,1,service_id,'Synthetic API','1.0',$2::jsonb,$3,$4 FROM portal_publications WHERE id=$1",[pub,JSON.stringify({openapi:'3.0.3',info:{title:'Synthetic',version:'1.0'},paths:{}}),secrets.fingerprint({document:pub}),admin.id]);
    await tx.exec("INSERT INTO portal_application_grants(id,cluster_id,workspace_id,transport_scope,application_id,publication_id,developer_id,consumer_id,acl_group,acl_id) SELECT $1,cluster_id,workspace_id,transport_scope,$2,id,$3,$4,acl_group,$5 FROM portal_publications WHERE id=$6",[grant,app,did,consumer,randomUUID(),pub]);
    await plans.definitions(cid,wid,admin.id,tx);
   });return{cid,wid,did,app,pub,grant,consumer,scope};
  };
  type Tenant=Awaited<ReturnType<typeof tenant>>;
  const workflow=async(t:Tenant,kind:WorkflowKind,withExecution=false)=>{
   const id=randomUUID(),execution=randomUUID();let plan!:WorkflowPlanV1,row:any;
   await sql.transaction(async tx=>{
    const before=(await tx.one<any>('SELECT * FROM portal_application_grants WHERE id=$1',[t.grant]))!;
    const first=native.nativeStep(1,'consumers','create',{id:t.consumer,username:`native-${t.consumer}`},null,{workflowId:id});
    const step=kind==='portal-credential-issue'?first:native.metadataStep(1,kind==='portal-credential-rotate'?'portal.credential.rotate':'portal.credential.revoke','portal_application_grants',t.grant,before,{synthetic:true},[]);
    plan={version:1,clusterId:t.cid,workspaceId:t.wid,workflowId:id,planRevision:1,kind,executionMode:'direct',approvalRequired:true,subject:{type:'portal_application_grants',id:t.grant},requester:{type:'developer',id:t.did},definition:await plans.definition(t.cid,t.wid,kind,tx),issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString(),scope:{transportScope:t.scope,clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[step]};
    row=await plans.persist(plan,`origin-${id}`,{synthetic:true},tx,{requestId:randomUUID(),ip:'192.0.2.17'});
    if(withExecution){
     await tx.exec("INSERT INTO workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,approver_id,decision,idempotency_key) VALUES($1,$2,$3,1,$4,1,$5,'approve',$6)",[t.cid,t.wid,id,row.plan_hash,admin.id,`approval-${id}`]);
     await tx.exec("UPDATE workflows SET state='failed',approved_by=$2,approved_at=now(),revision=revision+1 WHERE id=$1",[id,admin.id]);
     const snapshot={version:1,workflowId:id,executionId:execution,clusterId:t.cid,workspaceId:t.wid,objects:[]};
     await tx.exec("INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,snapshot_state,snapshot_secret,snapshot_hash,claim_token_hash,idempotency_key,expires_at,completed_at) VALUES($1,$2,$3,$4,1,$5,'direct',true,$6,$6,'failed','ready',$7,$8,$9,$10,now()+interval '30 minutes',now())",[execution,t.cid,t.wid,id,row.plan_hash,admin.id,secrets.encrypt(snapshot,snapshotAad(t.cid,t.wid,id,execution)),secrets.fingerprint(snapshot),secrets.fingerprint({claim:execution}),`execution-${execution}`]);
     const op=randomUUID();await tx.exec("INSERT INTO mutation_operations(id,cluster_id,workspace_id,actor_id,action,idempotency_key,request_hash,state,entity_type,before_secret,payload_secret,remote_started,remote_completed,error_code,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id) VALUES($1,$2,$3,$4,'create',$5,$6,'failed','consumers',$7,$8,true,false,'KONG_VALIDATION_ERROR',$9,$10,1,$11,$12)",[op,t.cid,t.wid,admin.id,step.mutationIdempotencyKey,secrets.fingerprint({op}),secrets.encrypt(null,`mutation:${op}:before`),secrets.encrypt(step.mutationPayload,`mutation:${op}:payload`),id,execution,row.plan_hash,step.id]);
     await tx.exec("UPDATE workflow_steps SET state='failed',operation_id=$2,error_code='KONG_VALIDATION_ERROR',started_at=now(),completed_at=now(),revision=revision+1 WHERE id=$1",[step.id,op]);
     const credential=randomUUID(),key=`synthetic-${randomUUID()}`;
     await tx.exec("INSERT INTO portal_credentials(id,cluster_id,workspace_id,grant_id,developer_id,consumer_id,kong_id,generation,key_secret,key_fingerprint,workflow_id) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10)",[credential,t.cid,t.wid,t.grant,t.did,t.consumer,randomUUID(),secrets.encrypt({key},portalKeyAad(t.cid,t.wid,credential,1)),secrets.fingerprint(key),id]);
     await tx.exec('UPDATE portal_application_grants SET workflow_id=$2 WHERE id=$1',[t.grant,id]);
    }
   });return{id,execution,plan,row,t};
  };
  const a=await tenant(),b=await tenant(),first=await workflow(a,'portal-credential-issue',true),failed=await workflow(b,'portal-credential-issue',true);
  const ids={firstWorkflowId:first.id,firstExecutionId:first.execution,failedWorkflowId:failed.id,failedExecutionId:failed.execution};
  const runProgram=(input=ids,p=program)=>{
   programRuns++;try{return{exitCode:0,stdout:execFileSync(process.execPath,['-e',p],{cwd:resolve('apps/console-api'),env:{PATH:process.env.PATH,DATABASE_URL:runtimeUrl},input:JSON.stringify(input),encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:15000,maxBuffer:256*1024}),stderr:''};}
   catch(error:any){return{exitCode:Number(error.status),stdout:String(error.stdout??''),stderr:String(error.stderr??'')};}
  };
  const readProgram=()=>{const out=runProgram();assert.equal(out.exitCode,0);assert.equal(out.stderr,'');const value=JSON.parse(out.stdout);assert.equal(value.first.workflow[0].id,first.id);assert.equal(value.first.grant[0].id,a.grant);assert.equal(value.first.executions[0].id,first.execution);return value;};
  const denyProgram=(input:typeof ids)=>{const out=runProgram(input);assert.equal(out.exitCode,1);assert.equal(out.stdout,'');assert.equal(out.stderr,'');programRejections++;};
  const history=(v:any)=>Object.fromEntries(['workflow','versions','executions','steps','operations','approvals','events','audits'].map(key=>[key,v.first[key]]));
  let baseline:any;
  await check('actual exported reader resolves the original issue subject with runtime SQL',async()=>{baseline=readProgram();assert.equal((await runtime!.query(grantQuery,[first.id])).length,1);});
  const rotated=await workflow(a,'portal-credential-rotate');
  await check('later rotate pointer preserves original issue version execution native ledger and audit facts',async()=>{
   await runtime!.exec('UPDATE portal_application_grants SET workflow_id=$2,revision=revision+1,updated_at=now() WHERE id=$1',[a.grant,rotated.id]);
   const current=readProgram();assert.equal(current.first.grant[0].workflow_id,rotated.id);assert.deepEqual(history(current),history(baseline));
   const inherited=execFileSync(process.execPath,['-e',`(async()=>{const m=await import(${JSON.stringify(resolve('deploy/scripts/verify-failed-issue-repair-continuity.mjs'))});process.stdout.write(m.FAILED_ISSUE_READONLY_PROGRAM);})()`],{env:{PATH:process.env.PATH},encoding:'utf8',stdio:['ignore','pipe','pipe']});
   const out=runProgram(ids,inherited);assert.equal(out.exitCode,1);assert.equal(out.stdout,'');assert.equal(out.stderr,'');programRejections++;
  });
  const revoked=await workflow(a,'portal-credential-revoke');
  await check('later revoke pointer resolves the same immutable original subject without querying its current workflow',async()=>{
   await runtime!.exec('UPDATE portal_application_grants SET workflow_id=$2,revision=revision+1,updated_at=now() WHERE id=$1',[a.grant,revoked.id]);const current=readProgram();assert.equal(current.first.grant[0].workflow_id,revoked.id);assert.deepEqual(history(current),history(baseline));
  });
  await check('non-issue kind and non-grant subject cannot masquerade as the original issue',async()=>{
   denyProgram({...ids,firstWorkflowId:rotated.id});assert.equal((await runtime!.query(grantQuery,[rotated.id])).length,0);
   const id=randomUUID();await sql.transaction(async tx=>{
    const before=await tx.one<any>('SELECT * FROM portal_applications WHERE id=$1',[a.app]);
    const plan:WorkflowPlanV1={version:1,clusterId:a.cid,workspaceId:a.wid,workflowId:id,planRevision:1,kind:'portal-metadata',executionMode:'direct',approvalRequired:false,subject:{type:'portal_applications',id:a.app},requester:{type:'console',id:admin.id},definition:await plans.definition(a.cid,a.wid,'portal-metadata',tx),issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString(),scope:{transportScope:a.scope,clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[native.metadataStep(1,'portal.application.update','portal_applications',a.app,before,{synthetic:true},[])]};
    await plans.persist(plan,`metadata-${id}`,{synthetic:true},tx,{requestId:randomUUID(),ip:'192.0.2.17'});
   });assert.equal((await runtime!.query(grantQuery,[id])).length,0);denyProgram({...ids,firstWorkflowId:id});
  });
  await check('missing original workflow and wrong original execution each fail closed',async()=>{denyProgram({...ids,firstWorkflowId:randomUUID()});denyProgram({...ids,firstExecutionId:failed.execution});});
  const crossScope=async(target:Tenant)=>{
   const foreign=await workflow(target,'portal-credential-issue',true),rows=await runtime!.query<any>(grantQuery,[foreign.id]);
   assert.equal(rows.length,1);assert.equal(rows[0].id,target.grant);assert.equal(rows[0].cluster_id,target.cid);assert.equal(rows[0].workspace_id,target.wid);assert.notEqual(rows[0].id,a.grant);
   denyProgram({...ids,firstWorkflowId:foreign.id});
  };
  await check('foreign cluster subject resolves only its own grant and cannot mix the original execution',async()=>{await crossScope(await tenant());});
  await check('foreign workspace subject resolves only its own grant and cannot mix the original execution',async()=>{await crossScope(await tenant(a.cid));});
  await check('readonly executions preserve all original history and frozen source migrations',async()=>{
   assert.deepEqual(history(readProgram()),history(baseline));
   const finalProgram=JSON.parse(execFileSync(process.execPath,['-e',loader],{env:{PATH:process.env.PATH},encoding:'utf8',stdio:['ignore','pipe','pipe']})).program as string;
   assert.equal(sha(finalProgram),programHash);sourceHash=sha(readFileSync(sourcePath));assert.equal((await runtime!.one<any>('SELECT count(*)::int AS n FROM schema_migrations')).n,10);assert.equal(nativeRequests,0);
  });
 }catch(error){failureCode=safeCode(error);throw error;}finally{
  mkdirSync('artifacts/M6',{recursive:true});const artifact=`artifacts/M6/portal-tenant-history-reader-postgres-${runId}.json`;
  writeFileSync(artifact,JSON.stringify({milestone:'M6',status:failureCode?'FAIL':'PASS',failureCode,serverVersion,migrations,sourcePath,sourceHash,programHash,grantQueryHash,roleEvidence,programRuns,programRejections,nativeRequests,businessHttpRequests:0,browserActions:0,privateReferenceReads:0,checks,passed:checks.filter(c=>c.passed).length,total:checks.length,limitations:['full actual exported program and its actual grant SQL execute on real runtime-role PostgreSQL','original sealed plan/version/normalized native step/execution/knownfailed ledger/audit are real schema-constrained SQL fixtures','synthetic reservation remains pending generation0; only later rotate/revoke pointers change, no terminal generation2 or native business lifecycle is claimed','foreign committed schema-valid workflows resolve their own scoped grants; mixing original execution fails; continuity lookup is not RBAC authority','no build, business HTTP, browser, Kong endpoint, current application database/environment or private reference is used']},null,2));
  await runtime?.onModuleDestroy();await owner?.onModuleDestroy();try{docker(['rm','-f',container]);}catch{}
  process.stdout.write(JSON.stringify({artifact,status:failureCode?'FAIL':'PASS',passed:checks.filter(c=>c.passed).length,total:checks.length,nativeRequests,businessHttpRequests:0})+'\n');
 }
}
main().catch(()=>{process.stderr.write('Isolated tenant history reader proof failed; safe artifact retained.\n');process.exitCode=1;});
