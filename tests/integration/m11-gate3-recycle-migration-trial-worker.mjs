import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';

// Root invokes this only in the isolated console owner-role container. All
// candidate DDL and deliberately invalid facts are rolled back. No real source,
// approval, permit, successful receipt or Kong write is manufactured here.
const candidate='023_m11_entity_recycle_facts.sql';
const checksum='9960455dd685da0e528f9f6f2280a4a18b80e812090182742341b9e831ea36eb';
const tables=['entity_change_recycle_archives','entity_change_recycle_nodes','entity_change_recycle_packets','entity_change_recycle_receipts'];
const functions=['m11_validate_recycle_archive','m11_validate_recycle_packet','m11_validate_recycle_manifest','m11_validate_recycle_packet_set','m11_validate_recycle_receipt','m11_guard_recycle_node_projection','m11_guard_recycle_node_append','m11_guard_recycle_entry_projection'];
const hash=x=>createHash('sha256').update(x).digest('hex');
const checks=[];let client,stage='environment',failure,passed=false,rolledBack=false,before,after;
const q=(sql,values=[])=>client.query(sql,values),row=async(sql,values)=>(await q(sql,values)).rows[0];
const check=async(name,fn)=>{stage=name;const result=await fn();checks.push({name,passed:true,...result});};
const ledger=async()=>(await q('SELECT name,checksum FROM schema_migrations ORDER BY name')).rows;
const catalog=async()=>(await row(`SELECT encode(sha256(convert_to(jsonb_build_object(
 'relations',(SELECT coalesce(jsonb_agg(jsonb_build_array(oid,relname,relkind,relowner,relacl) ORDER BY oid),'[]') FROM pg_class WHERE relnamespace='public'::regnamespace),
 'columns',(SELECT coalesce(jsonb_agg(jsonb_build_array(a.attrelid,a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attisdropped,a.attidentity,a.attgenerated) ORDER BY a.attrelid,a.attnum),'[]') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid WHERE c.relnamespace='public'::regnamespace AND a.attnum>0),
 'defaults',(SELECT coalesce(jsonb_agg(jsonb_build_array(d.oid,d.adrelid,d.adnum,pg_get_expr(d.adbin,d.adrelid)) ORDER BY d.oid),'[]') FROM pg_attrdef d JOIN pg_class c ON c.oid=d.adrelid WHERE c.relnamespace='public'::regnamespace),
 'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_array(oid,conrelid,conname,condeferrable,condeferred,convalidated,pg_get_constraintdef(oid,true)) ORDER BY oid),'[]') FROM pg_constraint WHERE connamespace='public'::regnamespace),
 'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_array(t.oid,t.tgrelid,t.tgname,t.tgtype,t.tgfoid,t.tgenabled,pg_get_triggerdef(t.oid,true)) ORDER BY t.oid),'[]') FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace),
 'functions',(SELECT coalesce(jsonb_agg(jsonb_build_array(oid,proname,proowner,proacl,pg_get_functiondef(oid)) ORDER BY oid),'[]') FROM pg_proc WHERE pronamespace='public'::regnamespace AND prokind IN('f','p')),
 'indexes',(SELECT coalesce(jsonb_agg(jsonb_build_array(i.indexrelid,pg_get_indexdef(i.indexrelid)) ORDER BY i.indexrelid),'[]') FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='public'::regnamespace)
)::text,'UTF8')),'hex') AS digest`)).digest;
async function blocked(name,sql,values,expected){
 await q('SAVEPOINT invalid_fact');let code;
 try{await q(sql,values);}catch(error){code=error.code;}
 await q('ROLLBACK TO SAVEPOINT invalid_fact');await q('RELEASE SAVEPOINT invalid_fact');
 assert.equal(code,expected,name);return{name,code};
}
try{
 assert.equal(process.env.RELEASE_LAB_READY,'true');
 assert.equal(process.env.RELEASE_LAB_M11_RECYCLE_DDL_TRIAL_READY,'true');
 assert.equal(process.env.RELEASE_LAB_CONTAINER,'kongpilot-release-lab-m11-recycle-ddl-trial');
 assert.equal(process.cwd(),'/app');
 const url=new URL(process.env.DATABASE_URL),owner=decodeURIComponent(url.username);
 assert.equal(url.hostname,'console-db');assert.equal(url.port,'5432');assert.equal(url.pathname,'/kongpilot');
 assert.equal(process.env.CONSOLE_DB_RUNTIME_USER,'kongpilot_lab_app');assert.notEqual(owner,'kongpilot_lab_app');
 const sql=readFileSync('/tmp/'+candidate);assert.equal(hash(sql),checksum);
 const {Client}=createRequire('/app/package.json')('pg');client=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000});
 await client.connect();await q('SET search_path=public,pg_catalog');await q('BEGIN');
 await q("SET LOCAL statement_timeout='20s'");await q("SET LOCAL lock_timeout='2s'");await q("SET LOCAL idle_in_transaction_session_timeout='45s'");
 await check('exact_isolated_console_000_through_022_frozen_ledger',async()=>{
  const current=await row('SELECT current_database() AS db,current_user AS role');assert.equal(current.db,'kongpilot');assert.equal(current.role,owner);
  const entries=await ledger();assert.equal(entries.length,23);assert.equal(entries.at(-1).name,'022_m11_baseline_trigger_alias_fix.sql');
  for(const entry of entries){assert(/^\d{3}_[a-z0-9_]+\.sql$/.test(entry.name));assert.equal(hash(readFileSync('/app/apps/console-api/dist/infrastructure/migrations/'+entry.name)),entry.checksum);}
  for(const table of tables)assert.equal((await row('SELECT to_regclass($1) IS NULL AS absent',['public.'+table])).absent,true);
  before={ledgerSha256:hash(JSON.stringify(entries)),schemaSha256:await catalog()};return{ledgerCount:23,allAppliedBytesMatch:true,candidateAbsent:true};
 });
 await check('complete_sql023_ddl_and_deferred_constraints',async()=>{await q(sql.toString('utf8'));await q('SET CONSTRAINTS ALL IMMEDIATE');return{fullDdl:true};});
 await check('four_append_only_tables_and_eight_actual_guards',async()=>{
  for(const table of tables){const result=await row(`SELECT count(*)::int AS n FROM pg_trigger WHERE tgrelid=to_regclass($1) AND tgfoid='m8_immutable()'::regprocedure AND(tgtype=27 OR tgtype=34)`,['public.'+table]);assert.equal(result.n,2);}
  for(const fn of functions)assert.equal((await row('SELECT to_regprocedure($1) IS NOT NULL AS present',['public.'+fn+'()'])).present,true);
  const fks=await row(`SELECT count(*)::int AS n,bool_and(convalidated AND confdeltype='r') AS guarded FROM pg_constraint WHERE conrelid=ANY($1::regclass[]) AND contype='f'`,[tables.map(t=>'public.'+t)]);assert(fks.n>=9&&fks.guarded);
  return{appendOnlyTables:4,guardFunctions:8,validatedRestrictForeignKeys:fks.n};
 });
 await check('actual_invalid_archive_packet_receipt_and_truncate_rejected',async()=>{
  const id=randomUUID(),h='a'.repeat(64),proofs=[];
  proofs.push(await blocked('archive_without_real_source',`INSERT INTO entity_change_recycle_archives(entry_id,cluster_id,workspace_id,source_id,baseline_id,pin_id,workflow_execution_id,actor_id,root_key,graph_hmac,payload_hmac,node_manifest_hmac,node_manifest,node_count,packet_count) VALUES($1,$1,$1,$1,$1,$1,$1,$1,'services:invalid',$2,$2,$2,'[]',1,1)`,[id,h],'23514'));
  proofs.push(await blocked('packet_without_whole_graph',`INSERT INTO entity_change_recycle_packets(cluster_id,workspace_id,source_id,baseline_id,pin_id,workflow_execution_id,entry_id,node_key,direction,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,packet_key,packet_order,method,path_hmac,native_type,native_id,permission_action,mutation_action,body_hmac,before_hmac) VALUES($1,$1,$1,$1,$1,$1,$1,'services:invalid','delete',$1,1,$2,$2,$2,'packet:invalid',1,'DELETE',$2,'services',$1,'delete','delete',$2,$2)`,[id,h],'23514'));
  proofs.push(await blocked('receipt_without_actual_send_and_outcome',`INSERT INTO entity_change_recycle_receipts(attempt_id,cluster_id,workspace_id,source_id,baseline_id,pin_id,workflow_execution_id,entry_id,node_key,packet_key,operation_id,operation_key,native_id,direction,result_hmac,verification_hmac) VALUES($1,$1,$1,$1,$1,$1,$1,$1,'services:invalid','packet:invalid',$1,'invalid',$1,'delete',$2,$2)`,[id,h],'23514'));
  proofs.push(await blocked('append_only_facts_no_truncate','TRUNCATE '+tables.join(','),[],'23514'));
  return{negativeCases:proofs};
 });
 await q('ROLLBACK');rolledBack=true;
 await check('transaction_rollback_restores_exact_schema_and_ledger',async()=>{
  after={ledgerSha256:hash(JSON.stringify(await ledger())),schemaSha256:await catalog()};assert.deepEqual(after,before);
  for(const table of tables)assert.equal((await row('SELECT to_regclass($1) IS NULL AS absent',['public.'+table])).absent,true);
  return{exactSchemaRestored:true,exactLedgerRestored:true,candidateAbsent:true};
 });passed=true;
}catch(error){failure={stage,code:/^[A-Z\d_]{1,128}$/.test(error?.code??'')?error.code:undefined,kind:error?.name==='AssertionError'?'assertion':'runtime',
 position:/^\d+$/.test(error?.position??'')?Number(error.position):undefined,
 internalPosition:/^\d+$/.test(error?.internalPosition??'')?Number(error.internalPosition):undefined};
}finally{if(client){if(!rolledBack)try{await q('ROLLBACK');rolledBack=true;}catch{}await client.end();}}
console.log(JSON.stringify({milestone:'M11',gate:3,phase:'recycle-sql023-ddl-trial',passed,candidate,candidateSha256:checksum,checks,before,after,trialRolledBack:rolledBack,businessRowsCommitted:0,nativeRequestsSent:0,executionAuthorityCreated:false,failure}));
if(!passed)process.exitCode=1;
