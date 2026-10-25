import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

// M3 database-only evidence: baseline SELECTs, then constraint attempts inside
// one explicitly rolled-back transaction. Never reads credentials or Kong DB.
const baselineMode = process.argv.includes('--baseline');
const directory = resolve('artifacts/M3');
const baselinePath = resolve(directory, 'database-migration-baseline.json');
const outputPath = baselineMode ? baselinePath : resolve(directory, 'database-constraints.json');
mkdirSync(directory, { recursive: true });
if (baselineMode && existsSync(baselinePath)) throw new Error('Preserve the existing pre-migration baseline');
if (!baselineMode && !existsSync(baselinePath)) throw new Error('Capture the pre-migration baseline first');
const sql = readFileSync('apps/console-api/src/infrastructure/migrations/004_m3_workspaces.sql', 'utf8');
const sourceSha256 = createHash('sha256').update(sql).digest('hex');
const input = baselineMode ? {} : { baseline: JSON.parse(readFileSync(baselinePath, 'utf8')), sourceSha256 };
const script = String.raw`
const {Pool}=require('pg');
const {randomUUID,randomBytes,createHash}=require('node:crypto');
const {readFileSync}=require('node:fs');
const baselineMode=process.argv[1]==='baseline';
const input=JSON.parse(readFileSync(0,'utf8')||'{}');
const tables=['mutation_operations','recycle_entries','audit_events'];
const pool=new Pool({connectionString:process.env.DATABASE_URL});
const checks=[];let step='database-connection',inTransaction=false,client;
function check(name,passed,detail){checks.push({name,passed:Boolean(passed),...(detail?{detail}:{})});if(!passed)throw new Error('CHECK_FAILED');}
async function history(){
 const result={};
 for(const table of tables){
  const exists=(await client.query("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name='workspace_id') AS value",[table])).rows[0].value;
  const rows=(await client.query('SELECT id'+(exists?',workspace_id':'')+' FROM '+table+' ORDER BY id')).rows.map(r=>({id:r.id,workspace_id:r.workspace_id??null}));
  result[table]={workspaceColumnExisted:exists,rowCount:rows.length,nullWorkspaceRows:rows.filter(r=>r.workspace_id===null).length,rows};
 }
 return result;
}
async function scenario(name,expectedCode,action){
 await client.query('SAVEPOINT m3_constraint_case');let code=null,constraint;
 try{await action();}catch(error){code=error.code||'UNKNOWN';if(/^[a-z0-9_]+$/i.test(error.constraint||''))constraint=error.constraint;}
 finally{await client.query('ROLLBACK TO SAVEPOINT m3_constraint_case');await client.query('RELEASE SAVEPOINT m3_constraint_case');}
 check(name,code===expectedCode,{expectedSQLState:expectedCode,actualSQLState:code,...(constraint?{constraint}:{})});
}
(async()=>{
 client=await pool.connect();
 try{
  const role=(await client.query('SELECT current_user AS name')).rows[0].name;
  check('checks use the non-owner runtime role',role==='kongos_app');
  const applied=(await client.query('SELECT name,checksum FROM schema_migrations ORDER BY name')).rows;
  if(baselineMode){
   check('004 migration not yet applied',!applied.some(r=>r.name==='004_m3_workspaces.sql'));
   const legacy=await history();
   console.log(JSON.stringify({kind:'real-console-PostgreSQL-pre-M3-baseline',databaseRole:role,allPassed:true,readOnly:true,migrationApplied:false,appliedMigrations:applied.map(r=>r.name),legacy,secretValuesRecorded:false,kongDatabaseAccess:false}));
   return;
  }
  step='migration-checksum';
  check('004 migration applied with current source checksum',applied.some(r=>r.name==='004_m3_workspaces.sql'&&r.checksum===input.sourceSha256));
  step='legacy-workspace-history';
  const legacy=[];
  for(const table of tables){
   const old=input.baseline.legacy[table];
   const rows=(await client.query('SELECT id,workspace_id FROM '+table+' WHERE id=ANY($1::uuid[])',[old.rows.map(r=>r.id)])).rows;
   const byId=new Map(rows.map(r=>[r.id,r.workspace_id??null]));
   check(table+' historical IDs and nullable workspace assignments preserved',rows.length===old.rowCount&&old.rows.every(r=>byId.has(r.id)&&byId.get(r.id)===r.workspace_id),{historicalRows:old.rowCount,nullWorkspaceRows:old.nullWorkspaceRows});
   legacy.push({table,historicalRows:old.rowCount,nullWorkspaceRows:old.nullWorkspaceRows,unchanged:true});
  }
  step='default-seeding';
  const missing=(await client.query("SELECT count(*)::int AS count FROM clusters c WHERE c.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM workspaces w WHERE w.cluster_id=c.id AND w.code='default' AND w.is_default AND w.status='active' AND w.deleted_at IS NULL)")).rows[0].count;
  check('every live cluster has its active canonical default',missing===0);
  const fkRows=(await client.query("SELECT conrelid::regclass::text AS table_name,pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE contype='f' AND conrelid IN ('mutation_operations'::regclass,'recycle_entries'::regclass,'audit_events'::regclass,'workspace_migration_plans'::regclass) AND confrelid IN ('workspaces'::regclass,'mutation_operations'::regclass) AND pg_get_constraintdef(oid) LIKE 'FOREIGN KEY (cluster_id, %' ORDER BY conrelid,conname")).rows;
  check('six cluster-bound workspace/operation foreign keys are installed',fkRows.length===6&&fkRows.every(r=>r.definition.includes('(cluster_id, ')));
  const stepFkRows=(await client.query("SELECT conrelid::regclass::text AS table_name,pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE contype='f' AND conrelid='workspace_migration_steps'::regclass AND confrelid='workspace_migration_plans'::regclass")).rows;
  check('normalized progress has a cluster-bound plan foreign key',stepFkRows.length===1&&stepFkRows[0].definition.includes('FOREIGN KEY (cluster_id, plan_id)'));
  step='rollback-fixtures';
  const actor=(await client.query("SELECT id FROM users WHERE super_admin AND status='active' ORDER BY id LIMIT 1")).rows[0]?.id;
  check('a bootstrap administrator exists',Boolean(actor));
  const ids={clusterA:randomUUID(),clusterB:randomUUID(),defaultA:randomUUID(),defaultB:randomUUID(),workspaceA:randomUUID(),workspaceA2:randomUUID(),workspaceB:randomUUID(),operationA:randomUUID(),operationB:randomUUID(),planA:randomUUID(),planB:randomUUID(),recycle:randomUUID(),annotation:randomUUID()};
  const auditScope='m3-db-rollback:'+randomUUID(),auditIds=[],planIds=[];
  await client.query('BEGIN');inTransaction=true;
  for(const id of [ids.clusterA,ids.clusterB])await client.query("INSERT INTO clusters(id,name,environment,admin_url,status) VALUES($1,$2,'m3-db-rollback','http://kong:8001','disabled')",[id,'m3-db-'+id]);
  for(const [id,cid,code,isDefault]of[[ids.defaultA,ids.clusterA,'default',true],[ids.defaultB,ids.clusterB,'default',true],[ids.workspaceA,ids.clusterA,'alpha',false],[ids.workspaceA2,ids.clusterA,'beta',false],[ids.workspaceB,ids.clusterB,'alpha',false]])await client.query('INSERT INTO workspaces(id,cluster_id,code,name,is_default) VALUES($1,$2,$3,$3,$4)',[id,cid,code,isDefault]);
  const op=(id,cid,wid)=>client.query("INSERT INTO mutation_operations(id,cluster_id,actor_id,action,idempotency_key,request_hash,workspace_id) VALUES($1::uuid,$2,$3,'m3.db.rollback',$1::text,$4,$5)",[id,cid,actor,randomBytes(32).toString('hex'),wid]);
  await op(ids.operationA,ids.clusterA,ids.workspaceA);await op(ids.operationB,ids.clusterB,ids.workspaceB);
  const recycled=wid=>client.query("INSERT INTO recycle_entries(id,cluster_id,actor_id,root_type,original_id,root_name,node_count,payload_secret,expires_at,workspace_id) VALUES($1,$2,$3,'services',$4,'m3-rollback',1,'synthetic-rollback-payload',now()+interval '1 day',$5)",[ids.recycle,ids.clusterA,actor,randomUUID(),wid]);
  await client.query('INSERT INTO audit_chain_heads(chain_scope) VALUES($1)',[auditScope]);
  const audit=(cid,wid)=>{const id=randomUUID();auditIds.push(id);return client.query("INSERT INTO audit_events(id,chain_scope,sequence,actor_type,cluster_id,workspace_id,entity_type,action,prev_hash,event_hash,occurred_at) VALUES($1,$2,1,'synthetic-rollback',$3,$4,'m3-database-test','rollback-only','GENESIS',$5,now())",[id,auditScope,cid,wid,randomBytes(32).toString('hex')]);};
  const plan=(source,target,operation=null,cid=ids.clusterA,id=randomUUID())=>{planIds.push(id);return client.query("INSERT INTO workspace_migration_plans(id,cluster_id,actor_id,source_workspace_id,target_workspace_id,plan_hash,payload_secret,operation_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,'synthetic-rollback-payload',$7,now()+interval '1 day')",[id,cid,actor,source,target,randomBytes(32).toString('hex'),operation]);};
  const annotation=()=>client.query("INSERT INTO entity_annotations(cluster_id,entity_type,kong_id) VALUES($1,'services',$2)",[ids.clusterA,ids.annotation]);
  await plan(ids.workspaceA,ids.workspaceA2,ids.operationA,ids.clusterA,ids.planA);
  await plan(ids.workspaceB,ids.workspaceB,ids.operationB,ids.clusterB,ids.planB);
  const progress=(value={})=>client.query('INSERT INTO workspace_migration_steps(cluster_id,plan_id,object_key,type,kong_id,status,after_fingerprint,error_code) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[value.clusterId??ids.clusterA,value.planId??ids.planA,value.key??'services:'+ids.annotation,value.type??'services',value.kongId??ids.annotation,value.status??'pending',value.fingerprint??null,value.errorCode??null]);
  await scenario('mutation accepts same-cluster workspace',null,()=>op(randomUUID(),ids.clusterA,ids.workspaceA));
  await scenario('mutation rejects cross-cluster workspace','23503',()=>op(randomUUID(),ids.clusterA,ids.workspaceB));
  await scenario('recycle accepts same-cluster workspace',null,()=>recycled(ids.workspaceA));
  await scenario('recycle rejects cross-cluster workspace','23503',()=>recycled(ids.workspaceB));
  await scenario('audit accepts same-cluster workspace',null,()=>audit(ids.clusterA,ids.workspaceA));
  await scenario('audit rejects cross-cluster workspace','23503',()=>audit(ids.clusterA,ids.workspaceB));
  await scenario('global audit cannot bypass scope with NULL cluster','23514',()=>audit(null,ids.workspaceA));
  await scenario('global audit with NULL workspace remains valid',null,()=>audit(null,null));
  await scenario('plan accepts cluster-bound references',null,()=>plan(ids.workspaceA,ids.workspaceA2,ids.operationA));
  await scenario('plan rejects foreign source workspace','23503',()=>plan(ids.workspaceB,ids.workspaceA2));
  await scenario('plan rejects foreign target workspace','23503',()=>plan(ids.workspaceA,ids.workspaceB));
  await scenario('plan rejects foreign mutation operation','23503',()=>plan(ids.workspaceA,ids.workspaceA2,ids.operationB));
  await scenario('default workspace cannot be disabled','23514',()=>client.query("UPDATE workspaces SET status='disabled' WHERE id=$1",[ids.defaultA]));
  await scenario('default workspace cannot be soft deleted','23514',()=>client.query("UPDATE workspaces SET status='deleted',deleted_at=now(),retention_until=now()+interval '1 day' WHERE id=$1",[ids.defaultA]));
  await scenario('default flag cannot be removed','23514',()=>client.query('UPDATE workspaces SET is_default=false WHERE id=$1',[ids.defaultA]));
  await scenario('second default workspace is rejected','23505',()=>client.query("INSERT INTO workspaces(cluster_id,code,name,is_default) VALUES($1,'default','duplicate-default',true)",[ids.clusterA]));
  await scenario('workspace deletion requires complete retention metadata','23514',()=>client.query("UPDATE workspaces SET status='deleted',deleted_at=now() WHERE id=$1",[ids.workspaceA]));
  await scenario('active workspace cannot have a deletion timestamp','23514',()=>client.query('UPDATE workspaces SET deleted_at=now() WHERE id=$1',[ids.workspaceA]));
  await scenario('ordinary workspace allows valid soft deletion',null,()=>client.query("UPDATE workspaces SET status='deleted',deleted_at=now(),retention_until=now()+interval '1 day' WHERE id=$1",[ids.workspaceA]));
  await scenario('soft-deleted codes remain reserved','23505',async()=>{await client.query("UPDATE workspaces SET status='deleted',deleted_at=now(),retention_until=now()+interval '1 day' WHERE id=$1",[ids.workspaceA]);await client.query("INSERT INTO workspaces(cluster_id,code,name) VALUES($1,'alpha','duplicate-deleted-code')",[ids.clusterA]);});
  await annotation();
  await scenario('annotation deletion requires retention metadata','23514',()=>client.query("UPDATE entity_annotations SET status='deleted',deleted_at=now() WHERE cluster_id=$1 AND kong_id=$2",[ids.clusterA,ids.annotation]));
  await scenario('annotation permits valid soft deletion',null,()=>client.query("UPDATE entity_annotations SET status='deleted',deleted_at=now(),retention_until=now()+interval '1 day' WHERE cluster_id=$1 AND kong_id=$2",[ids.clusterA,ids.annotation]));
  await scenario('annotation metadata requires an object','23514',()=>client.query("UPDATE entity_annotations SET metadata='[]'::jsonb WHERE cluster_id=$1 AND kong_id=$2",[ids.clusterA,ids.annotation]));
  await scenario('annotation revision must be positive','23514',()=>client.query('UPDATE entity_annotations SET revision=0 WHERE cluster_id=$1 AND kong_id=$2',[ids.clusterA,ids.annotation]));
  await scenario('progress accepts a same-cluster plan',null,()=>progress({fingerprint:randomBytes(32).toString('hex'),errorCode:'SYNTHETIC_ERROR'}));
  await scenario('progress rejects a foreign-cluster plan','23503',()=>progress({planId:ids.planB}));
  await scenario('progress object key is unique per plan','23505',async()=>{await progress();await progress();});
  await scenario('progress object key cannot be empty','23514',()=>progress({key:''}));
  await scenario('progress object key is bounded','23514',()=>progress({key:'x'.repeat(2049)}));
  await scenario('progress type must be an allowed entity','23514',()=>progress({type:'vaults'}));
  await scenario('progress state must be allowed','23514',()=>progress({status:'invalid'}));
  await scenario('progress fingerprint must be hexadecimal','23514',()=>progress({fingerprint:'not-a-fingerprint'}));
  await scenario('progress error code rejects arbitrary text','23514',()=>progress({errorCode:'unsafe error text'}));
  await scenario('progress error code is bounded','23514',()=>progress({errorCode:'X'.repeat(129)}));
  await scenario('progress Kong ID must be a UUID','22P02',()=>progress({kongId:'not-a-uuid'}));
  await client.query('ROLLBACK');inTransaction=false;
  step='rollback-cleanup';
  for(const [table,column,values]of[['clusters','id',[ids.clusterA,ids.clusterB]],['workspaces','id',[ids.defaultA,ids.defaultB,ids.workspaceA,ids.workspaceA2,ids.workspaceB]],['mutation_operations','id',[ids.operationA,ids.operationB]],['recycle_entries','id',[ids.recycle]],['audit_events','id',auditIds],['workspace_migration_plans','id',planIds],['workspace_migration_steps','plan_id',planIds],['entity_annotations','kong_id',[ids.annotation]]]){
   const count=(await client.query('SELECT count(*)::int AS count FROM '+table+' WHERE '+column+'=ANY($1::uuid[])',[values])).rows[0].count;
   check(table+' rollback fixtures fully removed',count===0);
  }
  check('rollback audit chain scope fully removed',(await client.query('SELECT count(*)::int AS count FROM audit_chain_heads WHERE chain_scope=$1',[auditScope])).rows[0].count===0);
  console.log(JSON.stringify({kind:'real-console-PostgreSQL-M3-004-constraints',databaseRole:role,allPassed:true,checkCount:checks.length,checks,legacy,foreignKeys:[...fkRows,...stepFkRows],transactionRolledBack:true,auditRowsOnlyInsideRolledBackTransaction:true,fixtureClusterIds:[ids.clusterA,ids.clusterB],secretValuesRecorded:false,kongDatabaseAccess:false,kongRequests:0}));
 }finally{if(inTransaction)await client.query('ROLLBACK').catch(()=>{});client.release();await pool.end();}
})().catch(error=>{console.log(JSON.stringify({kind:'real-console-PostgreSQL-M3-004-constraints',allPassed:false,failedStep:step,checks,code:/^[A-Z0-9_]+$/.test(error.code||'')?error.code:'VERIFICATION_FAILED',secretValuesRecorded:false,kongDatabaseAccess:false}));process.exitCode=1;});
`;
let result;
try {
  result = JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '-e', script, baselineMode ? 'baseline' : 'verify'], { encoding: 'utf8', input: JSON.stringify(input), maxBuffer: 8 * 1024 * 1024 }));
} catch (error) {
  try { const value=JSON.parse(String(error.stdout));if(value.kind==='real-console-PostgreSQL-M3-004-constraints')result=value; } catch { /* Never include unexpected process output. */ }
  result ||= { kind: 'real-console-PostgreSQL-M3-004-constraints', allPassed: false, failureDetailsSuppressed: true, secretValuesRecorded: false };
}
writeFileSync(outputPath, JSON.stringify({ performedAt: new Date().toISOString(), sourceSha256, ...result }, null, 2) + '\n');
if (!result.allPassed) process.exitCode = 1;
console.log(`${baselineMode ? 'M3 pre-migration baseline' : 'M3 real PostgreSQL constraints'} ${result.allPassed ? 'passed' : 'failed'}; safe evidence ${outputPath}`);
