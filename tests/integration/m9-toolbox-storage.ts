import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdirSync, writeFileSync } from 'node:fs';
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { provisionRuntimeRole } from '../../apps/console-api/src/infrastructure/migrate';

const dockerEnv={...process.env};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete dockerEnv[key];
const docker=(args:string[])=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env:dockerEnv,encoding:'utf8',stdio:['pipe','pipe','pipe']});
const name='kongpilot-m9-storage-'+randomUUID().slice(0,8),checks:Array<{name:string;passed:boolean;code?:string}>=[];
const check=async(name:string,fn:()=>Promise<void>)=>{try{await fn();checks.push({name,passed:true});}catch(error:any){checks.push({name,passed:false,code:error.code??'ASSERTION_FAILED'});throw error;}};
const rejected=async(fn:()=>Promise<unknown>,code:string)=>{try{await fn();throw new Error('EXPECTED_SQL_DENIAL');}catch(error:any){assert.equal(error.code,code);}};
async function main(){
let owner:DbService|undefined,runtime:DbService|undefined,passed=false;
try{
  docker(['run','-d','--pull=never','--name',name,'--label','kongpilot.test=m9-storage','--tmpfs','/var/lib/postgresql/data:rw,size=134217728','-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:16-alpine']);
  const port=docker(['port',name,'5432']).trim().split(':').at(-1);
  process.env.DATABASE_URL=`postgres://postgres@127.0.0.1:${port}/postgres`;process.env.CONSOLE_ENCRYPTION_KEY='9e'.repeat(32);process.env.BOOTSTRAP_ADMIN_USERNAME='m9-storage-bootstrap';process.env.BOOTSTRAP_ADMIN_PASSWORD='Synthetic!M9Storage2026';
  owner=new DbService();for(let attempt=0;attempt<100;attempt++){try{await owner.one('SELECT 1');break;}catch{if(attempt===99)throw new Error('SQL_READINESS_FAILED');await new Promise(resolve=>setTimeout(resolve,100));}}
  await check('all shipped SQL including M9 SQL016 migrate once with unchanged checksums and repeat-start continuity',async()=>{
    const expected=readdirSync('apps/console-api/src/infrastructure/migrations').filter(name=>name.endsWith('.sql')).sort();
    assert(expected.includes('016_m9_workspace_migration_workflow.sql'));
    await owner!.migrateAndSeed();const before=await owner!.query<any>('SELECT * FROM schema_migrations ORDER BY name');assert.deepEqual(before.map(row=>row.name),expected);
    for(const row of before)assert.equal(row.checksum,createHash('sha256').update(readFileSync('apps/console-api/src/infrastructure/migrations/'+row.name)).digest('hex'));
    await owner!.migrateAndSeed();assert.deepEqual(await owner!.query('SELECT * FROM schema_migrations ORDER BY name'),before);
  });
  process.env.CONSOLE_DB_RUNTIME_USER='m9_runtime';process.env.CONSOLE_DB_RUNTIME_PASSWORD='Synthetic!M9Runtime2026';await provisionRuntimeRole(owner);
  process.env.DATABASE_URL=`postgres://m9_runtime@127.0.0.1:${port}/postgres`;runtime=new DbService();const db=runtime,secrets=new SecretService();
  await check('runtime role validates exact shipped SQL checksums during real startup without owner DDL',async()=>{
    const prior=process.env.SKIP_MIGRATIONS;process.env.SKIP_MIGRATIONS='true';
    try{await runtime!.onModuleInit();}finally{if(prior===undefined)delete process.env.SKIP_MIGRATIONS;else process.env.SKIP_MIGRATIONS=prior;}
  });
  const actor=(await db.one<any>('SELECT id FROM users LIMIT 1'))!.id,foreign=randomUUID(),cid=randomUUID(),wid=randomUUID(),otherWid=randomUUID(),id=randomUUID(),operation=randomUUID(),key=randomUUID();
  await db.exec("INSERT INTO users(id,username,password_hash,status) VALUES($1,'synthetic-m9-foreign',$2,'active')",[foreign,'$2b$12$'+'a'.repeat(53)]);
  await db.exec("INSERT INTO clusters(id,name,admin_url,execution_mode,version,status,transport_scope) VALUES($1,'M9 storage','http://kong:8001','direct','1.5.1','healthy',$2)",[cid,'a'.repeat(64)]);
  await db.exec("INSERT INTO workspaces(id,cluster_id,code,name,status) VALUES($1,$2,'m9','M9','active'),($3,$2,'m9-other','M9 other','active')",[wid,cid,otherWid]);
  const payload={name:'synthetic-service',host:'service.example.com',tls_verify:false,retries:0};
  await check('draft root, immutable version and owner-bound operation commit atomically',()=>db.transaction(async tx=>{
    await tx.exec("INSERT INTO configuration_drafts(id,cluster_id,workspace_id,owner_user_id,name,entity_type,current_version) VALUES($1,$2,$3,$4,'Synthetic draft','services',1)",[id,cid,wid,actor]);
    await tx.exec("INSERT INTO configuration_draft_versions(cluster_id,workspace_id,draft_id,version,payload_secret,payload_hmac,operation_id,created_by) VALUES($1,$2,$3,1,$4,$5,$6,$7)",[cid,wid,id,secrets.encrypt(payload,`draft:${cid}:${wid}:${id}:1`),secrets.fingerprint(payload),operation,actor]);
    await tx.exec("INSERT INTO toolbox_metadata_operations(id,cluster_id,workspace_id,actor_id,idempotency_key,request_hmac,action,subject_id,result_secret) VALUES($1,$2,$3,$4,$5,$6,'draft.create',$7,$8)",[operation,cid,wid,actor,key,secrets.fingerprint(payload),id,secrets.encrypt({draftId:id},`toolbox-metadata:${operation}`)]);
  }));
  await check('false/zero public editing values round-trip inside encrypted storage',async()=>{
    const version=await db.one<any>('SELECT * FROM configuration_draft_versions WHERE draft_id=$1',[id]);assert.deepEqual(secrets.decrypt(version.payload_secret,`draft:${cid}:${wid}:${id}:1`),payload);assert(!version.payload_secret.includes('service.example.com'));
  });
  await check('runtime cannot update, delete or truncate editing history and metadata receipts',async()=>{
    for(const table of ['configuration_draft_versions','toolbox_metadata_operations','toolbox_debug_runs','toolbox_batches','configuration_recycle_graphs','configuration_recycle_components']){
      await rejected(()=>db.exec(`DELETE FROM ${table}`),'42501');await rejected(()=>db.exec(`TRUNCATE ${table}`),'42501');
    }
    await rejected(()=>db.exec('UPDATE configuration_draft_versions SET payload_hmac=$1',['0'.repeat(64)]),'42501');
  });
  await check('root owner, cluster and workspace identity cannot be reassigned',async()=>{
    for(const patch of ['owner_user_id=$2','workspace_id=$2'])await rejected(()=>db.exec(`UPDATE configuration_drafts SET ${patch},revision=revision+1 WHERE id=$1`,[id,patch.startsWith('owner')?foreign:otherWid]),'23514');
    await rejected(()=>db.exec('DELETE FROM configuration_drafts WHERE id=$1',[id]),'23514');
  });
  await check('history FK rejects a different author even within the same workspace',async()=>{
    await rejected(()=>db.transaction(async tx=>{
      await tx.exec("INSERT INTO configuration_draft_versions(cluster_id,workspace_id,draft_id,version,payload_secret,payload_hmac,operation_id,created_by) VALUES($1,$2,$3,2,$4,$5,$6,$7)",[cid,wid,id,secrets.encrypt({},`draft:${id}:2`),secrets.fingerprint({}),operation,foreign]);
    }),'23503');
  });
  await check('soft archive and restore keep the original version and enforce revision CAS',async()=>{
    assert.equal(await db.exec("UPDATE configuration_drafts SET state='deleted',deleted_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND revision=1",[id]),1);
    assert.equal(await db.exec("UPDATE configuration_drafts SET state='active',deleted_at=NULL,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=1",[id]),0);
    assert.equal(await db.exec("UPDATE configuration_drafts SET state='active',deleted_at=NULL,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=2",[id]),1);
    assert.equal((await db.one<any>('SELECT current_version FROM configuration_drafts WHERE id=$1',[id]))!.current_version,1);
  });
  await check('new capture/probe facts reject mutation even by database owner',async()=>{
    const debugId=randomUUID();await db.exec("INSERT INTO toolbox_debug_runs(id,cluster_id,workspace_id,actor_id,kind,input_hmac,quality,safe_result) VALUES($1,$2,$3,$4,'route-simulation',$5,'partial','{}')",[debugId,cid,wid,actor,secrets.fingerprint('input')]);
    await rejected(()=>owner!.exec('UPDATE toolbox_debug_runs SET safe_result=$1::jsonb WHERE id=$2',[JSON.stringify({forged:true}),debugId]),'23514');
  });
  await check('cache keys reject path injection and raw control-plane addresses reject credentials',async()=>{
    await rejected(()=>db.exec('UPDATE clusters SET proxy_origin=$2 WHERE id=$1',[cid,'http://user:password@kong:8000']),'23514');
  });
  await check('audit tables remain append-only under the same runtime role',async()=>{await rejected(()=>db.exec('UPDATE audit_events SET result=$1',['forged']),'42501');await rejected(()=>db.exec('DELETE FROM audit_events'),'42501');});
  const cacheId=randomUUID(),cacheInsert=(id:string,key:string)=>db.exec(`INSERT INTO toolbox_operations(id,cluster_id,workspace_id,transport_scope,actor_id,idempotency_key,kind,cache_key,request_hmac,before_hmac,before_secret,cluster_revision,workspace_revision,execution_mode,state,expires_at)
    VALUES($1,$2,$3,$4,$5,$6,'cache-invalidate',$7,$8,$8,$9,1,1,'direct','planned',now()+interval '14 minutes')`,[id,cid,wid,'a'.repeat(64),actor,randomUUID(),key,secrets.fingerprint({found:false}),secrets.encrypt({found:false},`toolbox-cache:${id}:before`)]);
  await check('runtime inserts real cache operation facts including the full 256-character boundary',async()=>{await cacheInsert(cacheId,'a'.repeat(256));assert.equal((await db.one<any>('SELECT state FROM toolbox_operations WHERE id=$1',[cacheId]))!.state,'planned');});
  await check('SQL cache-key constraint rejects overlong keys, paths and dot traversal',async()=>{for(const value of ['a'.repeat(257),'../services','foo/bar','.','..'])await rejected(()=>cacheInsert(randomUUID(),value),'23514');});
  await check('cache native-start and native-completion facts advance monotonically',async()=>{
    await db.exec("UPDATE toolbox_operations SET state='running',execution_actor_id=$2,revision=revision+1 WHERE id=$1",[cacheId,actor]);
    await db.exec('UPDATE toolbox_operations SET remote_started=true,revision=revision+1 WHERE id=$1',[cacheId]);
    await db.exec("UPDATE toolbox_operations SET state='succeeded',remote_completed=true,revision=revision+1 WHERE id=$1",[cacheId]);
    await rejected(()=>db.exec("UPDATE toolbox_operations SET state='planned',remote_started=false,remote_completed=false,revision=revision+1 WHERE id=$1",[cacheId]),'23514');
  });
  passed=true;
}catch(error:any){process.stderr.write(JSON.stringify({event:'m9.storage.failed',code:error.code??'ASSERTION_FAILED',constraint:error.constraint??null})+'\n');}
finally{
  await runtime?.onModuleDestroy();await owner?.onModuleDestroy();docker(['rm','-f',name]);
  mkdirSync('artifacts/M9',{recursive:true});writeFileSync('artifacts/M9/storage-verification.json',JSON.stringify({passed,environment:'isolated-postgresql16-tmpfs',nativeKongRequests:false,checks},null,2)+'\n');
  process.stdout.write(JSON.stringify({passed,checks:checks.length})+'\n');if(!passed)process.exitCode=1;
}

}
void main();
