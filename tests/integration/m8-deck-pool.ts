import 'reflect-metadata';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {createRequire} from 'node:module';
import ts from 'typescript';
import {provisionRuntimeRole} from '../../apps/console-api/src/infrastructure/migrate';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

const digest=(content:Buffer|string)=>createHash('sha256').update(content).digest('hex');
const manifestPath='artifacts/M8/deck-pool-beforefix-source-20261011-01/manifest.json';
const before=process.env.KONGOS_M8_DECK_POOL_MODE!=='after';
const reportPath=process.env.KONGOS_M8_DECK_POOL_REPORT??`artifacts/M8/storage-deck-pool-${before?'beforefix':'afterfix'}-postgres-20261011-01.json`;
assert(/^artifacts\/M8\/storage-[a-z0-9-]+\.json$/.test(reportPath));assert(!existsSync(reportPath),'REPORT_ALREADY_EXISTS');
const manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
const entries=manifest.files.map((entry:any)=>({...entry,loadedSha256:digest(readFileSync(before?entry.snapshotPath:entry.path))}));
if(before)for(const entry of entries)assert.equal(entry.loadedSha256,entry.sha256);
/** Isolated fixture module loader. It compiles exact preserved PUBLIC source
 * bytes with the product compiler settings and resolves only these five
 * sources to the fixture classes. Product paths/providers are never replaced. */
const NativeModule=createRequire(resolve('package.json'))('node:module'),loaded=new Map<string,any>();
function sourceClass(path:string):any{
 const absolute=resolve(path),found=loaded.get(absolute);if(found)return found.exports;
 const entry=entries.find((value:any)=>resolve(value.path)===absolute);if(!entry)return createRequire(absolute)(absolute);
 const content=readFileSync(before?entry.snapshotPath:entry.path,'utf8');assert.equal(digest(content),entry.loadedSha256);
 const compiled=ts.transpileModule(content,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,moduleResolution:ts.ModuleResolutionKind.NodeJs,esModuleInterop:true,experimentalDecorators:true,emitDecoratorMetadata:true},reportDiagnostics:true});
 assert.equal(compiled.diagnostics?.length??0,0);
 const module=new NativeModule(absolute),nativeRequire=createRequire(absolute);loaded.set(absolute,module);
 module.filename=absolute;module.paths=NativeModule._nodeModulePaths(resolve(absolute,'..'));
 module.require=(name:string)=>{const dependency=nativeRequire.resolve(name);return entries.some((value:any)=>resolve(value.path)===dependency)?sourceClass(dependency):nativeRequire(name);};
 module._compile(compiled.outputText,absolute);return module.exports;
}
const {DbService}=sourceClass('apps/console-api/src/infrastructure/db.service.ts');
const {AuthorizationService}=sourceClass('apps/console-api/src/modules/authorization/authorization.service.ts');
const {WorkspaceResolverService}=sourceClass('apps/console-api/src/modules/workspaces/workspace-resolver.service.ts');
const {ConfigurationAccessService}=sourceClass('apps/console-api/src/modules/configuration/configuration-access.service.ts');
const {ConfigurationRepositoryService}=sourceClass('apps/console-api/src/modules/config-storage/configuration-repository.service.ts');

async function main(){
 const containerName='kongos-m8-deck-pool-'+randomUUID().slice(0,8),env={...process.env};
 for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[key];
 const docker=(args:string[])=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env,encoding:'utf8',stdio:['ignore','pipe','pipe']});
 const checks:any[]=[],observations:any={};let owner:any,db:any,complete=false,isolatedContainerRemoved=false;
 const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(error:any){checks.push({name,passed:false,code:error?.getResponse?.()?.code??error?.code??'ASSERTION_FAILED'});throw error;}};
 const classify=(error:any)=>error?.message==='timeout exceeded when trying to connect'?'POOL_CONNECTION_ACQUISITION_TIMEOUT':error?.getResponse?.()?.code??error?.code??'UNCLASSIFIED';
 try{
  docker(['run','-d','--pull=never','--name',containerName,'--label','kongos.test=m8-deck-pool','--tmpfs','/var/lib/postgresql/data:rw,size=268435456','-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine']);
  const port=docker(['port',containerName,'5432']).trim().split(':').pop();
  process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;process.env.CONSOLE_ENCRYPTION_KEY='7e'.repeat(32);process.env.BOOTSTRAP_ADMIN_USERNAME='m8-deck-pool-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!DeckPoolBootstrap2026';
  owner=new DbService();for(let attempt=0;attempt<80;attempt++){try{await owner.one('SELECT 1');break;}catch{if(attempt===79)throw Error('ISOLATED_PG_UNAVAILABLE');await new Promise(resolve=>setTimeout(resolve,100));}}
  await check('unchanged SQL000-011 compile on own isolated PostgreSQL16',async()=>{await owner.migrateAndSeed();const rows=await owner.query('SELECT name,checksum FROM schema_migrations ORDER BY name');assert.equal(rows.length,12);observations.migrationSha256=Object.fromEntries(rows.map((row:any)=>{assert.equal(row.checksum,digest(readFileSync('apps/console-api/src/infrastructure/migrations/'+row.name)));return[row.name,row.checksum];}));});
  process.env.CONSOLE_DB_RUNTIME_USER='m8_deck_pool_runtime';process.env.CONSOLE_DB_RUNTIME_PASSWORD='Synthetic!DeckPoolRuntime2026';await provisionRuntimeRole(owner);process.env.DATABASE_URL=`postgres://m8_deck_pool_runtime@127.0.0.1:${port}/postgres`;db=new DbService();
  const user={id:randomUUID(),username:'deck-pool-'+randomUUID().slice(0,8),superAdmin:false},sid=randomUUID(),cid=randomUUID(),wid=randomUUID(),roleId=randomUUID(),requestId=randomUUID(),scope={clusterId:cid,workspaceId:wid,transportScope:'b'.repeat(64),kind:'workspace',rootIds:[]},secrets=new SecretService();
  await check('actual runtime role is nonowner nonsuperuser nonbypass with current SQL actor SID scoped read grants',async()=>{
   const row=await db.one('SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname=current_user');assert(Object.values(row).every(value=>value===false));
   await db.transaction(async(tx:any)=>{await tx.exec("INSERT INTO clusters(id,name,admin_url,execution_mode,version,status,transport_scope) VALUES($1,'Isolated deck pool','http://isolated.invalid:8001','direct','1.5.1','healthy',$2)",[cid,scope.transportScope]);await tx.exec("INSERT INTO workspaces(id,cluster_id,code,name,status) VALUES($1,$2,'deck-pool','Isolated deck pool','active')",[wid,cid]);await tx.exec("INSERT INTO users(id,username,password_hash,super_admin,status) VALUES($1,$2,$3,false,'active')",[user.id,user.username,secrets.fingerprint('synthetic-structural-password')]);await tx.exec("INSERT INTO auth_sessions(id,user_id,expires_at) VALUES($1,$2,clock_timestamp()+interval '1 hour')",[sid,user.id]);await tx.exec("INSERT INTO roles(id,code,name,cluster_id,workspace_id) VALUES($1,$2,'Isolated deck reader',$3,$4)",[roleId,'deck-'+roleId.slice(0,8),cid,wid]);for(const action of ['read','write'])await tx.exec("INSERT INTO role_permissions(role_id,module,action,scope_type,cluster_id,workspace_id) VALUES($1,'snapshots',$2,'workspace',$3,$4)",[roleId,action,cid,wid]);await tx.exec('INSERT INTO user_role_bindings(user_id,role_id,cluster_id,workspace_id,granted_by) VALUES($1,$2,$3,$4,$1)',[user.id,roleId,cid,wid]);});
  });
  const context=new KongExecutionContextService(),noKong={async request(){throw Error('UNEXPECTED_NATIVE_IN_DECK_POOL_TEST');}},workspaces=new WorkspaceResolverService(db),authz=new AuthorizationService(db,workspaces,noKong,context),access=new ConfigurationAccessService(db,secrets,authz,workspaces,noKong,context,{}),repo=new ConfigurationRepositoryService(db,secrets,new SnapshotCryptoService(secrets),access);
  access.onModuleInit();
  const evidence=async(tx:any,event:any)=>{assert(await tx.one('SELECT id FROM configuration_deck_sessions WHERE id=$1',[event.after.id]));};repo.installDeckEvidenceWriter({sessionChanged:evidence});
  const inFrame=<T>(fn:()=>Promise<T>,actor=user,sessionId=sid)=>context.runHttp({requestId,ip:'127.0.0.1'},async()=>{context.bindHttpActor(actor,sessionId);const close=context.captureHttpCloser();try{return await context.runActor({actor,clusterId:cid,workspaceId:wid,module:'snapshots',action:'read'},fn);}finally{close();}});
  let handle:any,job:any,session:any,frozenPlan:any,plan:any;
  await check('genuine ConfigurationAccess acquireJob and actual repository issue and serial read succeed before saturation',async()=>{
   await inFrame(async()=>{handle=await access.acquireJob({...scope,actor:user,purpose:'compare',kindOfJob:'compare',idempotencyKey:randomUUID()});const authority=await access.description(handle);job=await repo.createJob(handle,{scope,kind:'compare',idempotencyKey:authority.key,requestId,expiresAt:new Date(Date.now()+600000).toISOString(),writeEvidence:async(tx:any,_before:any,after:any)=>{assert(await tx.one('SELECT id FROM configuration_jobs WHERE id=$1',[after.id]));}});session=await repo.issueDeckSession(handle,{jobId:job.id,purpose:'read',credentialEpoch:1,expiresAt:new Date(Date.now()+120000).toISOString()});const result=await repo.readDeckSession(handle,{id:session.id,token:session.token,purpose:'read'});assert.equal(result.actorId,user.id);assert.equal(result.sessionId,sid);assert.equal(result.jobId,job.id);const current=await authz.snapshot(user);assert.equal(current.user.superAdmin,false);assert.equal(current.grants.length,2);});
  });
  if(!before)await check('afterfix current actual Access freezes and decrypts a three-step immutable DAG without native execution',async()=>{
   const permissionVersion=await inFrame(()=>authz.permissionVersion(user)),stepIds=Array.from({length:3},()=>randomUUID());
   const steps=stepIds.map((stepId,index)=>{const nativeId=randomUUID(),before={id:nativeId,username:'synthetic-before-'+index},body={username:'synthetic-after-'+index},beforeHmac=secrets.fingerprint(before),bodyHmac=secrets.fingerprint(body);return{stepId,stepOrder:index+1,objectKey:'consumers:'+nativeId,entityType:'consumers',objectWorkspaceId:wid,clearMap:[],nativeId,parentType:null,parentId:null,credentialKind:null,permissionAction:'write',mutationAction:'update',dependencies:index?[stepIds[index-1]]:[],body,before,bodyHmac,beforeHmac,nativeRequests:[{method:'PATCH',canonicalPath:'/consumers/'+nativeId,body,bodyHmac,beforeHmac}],referenceOnly:false,blockerCodes:[],maskedDiff:[{op:'replace',path:'/username',value:body.username}]};});
   plan={scope,mode:'merge',steps,sourceManifestHmac:secrets.fingerprint('synthetic-source'),baselineManifestHmac:secrets.fingerprint('synthetic-baseline'),schemaHmac:secrets.fingerprint('synthetic-schema'),permissionVersion,clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',recoveryComplete:true,expiresAt:new Date(Date.now()+600000).toISOString()};
   frozenPlan=await inFrame(()=>repo.freezePlan(handle,{jobId:job.id,plan}));assert.deepEqual(await inFrame(()=>repo.readPlan(handle,{scope,...frozenPlan})),plan);assert.equal((await db.one('SELECT count(*)::integer AS count FROM mutation_operations')).count,0);assert.equal((await db.one('SELECT count(*)::integer AS count FROM configuration_executions')).count,0);
  });
  await check(before?'beforefix sixteen actual readDeckSession calls with ten occupied real connections reproduce genuine pool timeout and same-row lock wait':'afterfix sixteen actual readDeckSession calls with ten occupied real connections all complete through the unchanged same-row lock',async()=>{
   const pool=(db as any).pool;assert.equal(pool.options.max,10);assert.equal(pool.options.connectionTimeoutMillis,5000);assert.equal(pool.options.statement_timeout,15000);
   const original=db.transaction.bind(db);let occupied=0,release!:()=>void,ready!:()=>void;const barrier=new Promise<void>(r=>release=r),allOccupied=new Promise<void>(r=>ready=r);
   db.transaction=(fn:(tx:any)=>Promise<any>)=>original(async(tx:any)=>{if(occupied<10){occupied++;if(occupied===10)ready();await barrier;}return fn(tx);});
   const start=Date.now(),calls=Array.from({length:16},()=>inFrame(async()=>{try{const result=await repo.readDeckSession(handle,{id:session.id,token:session.token,purpose:'read'});assert.equal(result.jobId,job.id);return{ok:true};}catch(error){return{ok:false,code:classify(error)};}}));
   try{
    await allOccupied;observations.barrier={occupiedTransactions:occupied,totalCount:pool.totalCount,idleCount:pool.idleCount,waitingCount:pool.waitingCount};assert.equal(pool.totalCount,10);assert.equal(pool.idleCount,0);release();
    let peakLockWaiters=0,peakPoolWaiting=0;
    for(let attempt=0;attempt<25;attempt++){const activity=await owner.one("SELECT count(*)::integer AS waiters FROM pg_stat_activity WHERE usename='m8_deck_pool_runtime' AND wait_event_type='Lock' AND query LIKE '%configuration_deck_sessions%'");peakLockWaiters=Math.max(peakLockWaiters,activity.waiters);peakPoolWaiting=Math.max(peakPoolWaiting,pool.waitingCount);if(peakLockWaiters===9)break;await new Promise(r=>setTimeout(r,20));}
    const results=await Promise.all(calls);observations.concurrent={calls:16,completed:results.filter(r=>r.ok).length,failures:results.filter(r=>!r.ok).map(r=>r.code),elapsedMs:Date.now()-start,peakSameSessionRowLockWaiters:peakLockWaiters,peakPoolWaiting,totalCount:pool.totalCount,idleCount:pool.idleCount,waitingCount:pool.waitingCount};
    assert(peakLockWaiters>=1);if(before){assert(results.some(r=>r.code==='POOL_CONNECTION_ACQUISITION_TIMEOUT'));assert(observations.concurrent.elapsedMs>=4900);assert.equal(peakLockWaiters,9);assert(peakPoolWaiting>=7);}else{assert.equal(results.filter(r=>r.ok).length,16);assert.equal(results.filter(r=>!r.ok).length,0);}assert.equal(pool.waitingCount,0);
   }finally{release();db.transaction=original;await Promise.allSettled(calls);}
  });
  if(!before){
   await check('afterfix unchanged current permission epoch revocation denies the existing genuine handle active deck token and sealed DAG read',async()=>{await db.exec("UPDATE roles SET status='disabled',revision=revision+1 WHERE id=$1",[roleId]);for(const request of [()=>repo.readDeckSession(handle,{id:session.id,token:session.token,purpose:'read'}),()=>repo.readPlan(handle,{scope,...frozenPlan})]){try{await inFrame(request);throw Error('EXPECTED_CURRENT_PERMISSION_DENIAL');}catch(error){assert.equal(classify(error),'CONFIGURATION_PERMISSIONS_CHANGED');}}try{await inFrame(()=>authz.assertWholeWorkspace(user,cid,wid,'snapshots','read'));throw Error('EXPECTED_CURRENT_GRANT_DENIAL');}catch(error){assert.equal(classify(error),'PERMISSION_DENIED');}assert.equal((await db.one('SELECT state FROM configuration_deck_sessions WHERE id=$1',[session.id])).state,'active');});
   await check('afterfix current original SID revocation denies a fresh genuine handle without widening session authority',async()=>{await db.exec("UPDATE roles SET status='active',revision=revision+1 WHERE id=$1",[roleId]);handle=await inFrame(()=>access.acquireReadJob(job.id));await db.exec('UPDATE auth_sessions SET revoked_at=now() WHERE id=$1',[sid]);try{await inFrame(()=>repo.readDeckSession(handle,{id:session.id,token:session.token,purpose:'read'}));throw Error('EXPECTED_CURRENT_SESSION_DENIAL');}catch(error){assert.equal(classify(error),'CONFIGURATION_SESSION_EXPIRED');}});
  }
  for(const entry of entries)if(!before)assert.equal(digest(readFileSync(entry.path)),entry.loadedSha256);
  complete=true;
 }catch(error:any){process.stderr.write('Isolated deck pool check stopped: '+classify(error)+'\n');}
 finally{await db?.onModuleDestroy().catch(()=>undefined);await owner?.onModuleDestroy().catch(()=>undefined);try{docker(['rm','-f','-v',containerName]);isolatedContainerRemoved=true;}catch{}mkdirSync('artifacts/M8',{recursive:true});writeFileSync(reportPath,JSON.stringify({allPassed:complete,mode:before?'beforefix':'afterfix',passed:checks.filter(c=>c.passed).length,failed:checks.filter(c=>!c.passed).length,checks,sources:entries.map((entry:any)=>({path:entry.path,loadedPath:before?entry.snapshotPath:entry.path,sha256:entry.loadedSha256})),testSource:{path:'tests/integration/m8-deck-pool.ts',sha256:digest(readFileSync('tests/integration/m8-deck-pool.ts'))},observations,realPostgres:true,poolMax:10,poolConnectionTimeoutMs:5000,queryCancellationIssued:false,authority:'actual ConfigurationAccessService opaque WeakMap, AuthorizationService, WorkspaceResolverService and local KongExecutionContext using current SQL user SID IAM grants; no mock Access authority',evidence:'synthetic server registration evidence callback; no AuditService HTTP claim',fixtures:'own structural SQL user/session/role and compare job; no real login or decK CLI invocation',nativeRequests:0,httpRequests:0,productionRuntimeTouched:false,privateEnvironmentRead:false,isolatedContainerRemoved},null,2)+'\n',{flag:'wx'});}
}
void main();
