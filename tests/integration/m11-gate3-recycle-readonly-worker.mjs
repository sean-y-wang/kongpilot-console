import assert from 'node:assert/strict';
import {createRequire} from 'node:module';

// Read-only observation of actual HTTP-generated facts in the own lab API.
// Plaintext decrypted evidence stays inside this process; reports contain only
// IDs, hashes, states and counts, never credentials or private configuration.
const require=createRequire('/app/package.json');require('reflect-metadata');
const {Client}=require('pg');
const {SecretService}=require('/app/apps/console-api/dist/infrastructure/secret.service.js');
const {entityPacketFactAad}=require('/app/apps/console-api/dist/modules/workflows/entity-change-execution-facts.service.js');
const checks=[];let c,stage='environment',passed=false,failure;const executions=[];
const query=(sql,args=[])=>c.query(sql,args),row=async(sql,args)=>(await query(sql,args)).rows[0];
const check=async(name,fn)=>{stage=name;checks.push({name,passed:true,...await fn()});};
try{
 assert.equal(process.env.RELEASE_LAB_M11_RECYCLE_READONLY_READY,'true');assert.equal(process.cwd(),'/app');
 const cid=process.env.M11_CLUSTER_ID,wid=process.env.M11_WORKSPACE_ID,ids=(process.env.M11_RECYCLE_WORKFLOW_IDS??'').split(',');
 const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
 assert(uuid.test(cid)&&uuid.test(wid)&&ids.length>0&&ids.every(id=>uuid.test(id))&&new Set(ids).size===ids.length);
 const url=new URL(process.env.DATABASE_URL);assert.equal(url.hostname,'console-db');assert.equal(url.pathname,'/kongpilot');
 c=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:3000});await c.connect();await query('BEGIN READ ONLY');
 await query("SET LOCAL statement_timeout='15s'");
 const secrets=new SecretService();
 await check('actual_runtime_role_and_frozen_sql023',async()=>{
  assert.equal((await row('SELECT current_user AS role')).role,'kongpilot_lab_app');
  const ledger=(await query('SELECT name,checksum FROM schema_migrations ORDER BY name')).rows;assert.equal(ledger.length,24);
  assert.deepEqual(ledger.at(-1),{name:'023_m11_entity_recycle_facts.sql',checksum:'9960455dd685da0e528f9f6f2280a4a18b80e812090182742341b9e831ea36eb'});
  return{ledgerCount:24,migrationMaximum:ledger.at(-1).name};
 });
 await check('complete_actual_execution_baseline_and_three_vote_approval',async()=>{
  for(const id of ids){
   const result=await row(`SELECT w.id,w.state,e.id AS execution_id,e.state AS execution_state,s.id AS source_id,b.id AS baseline_id,p.id AS pin_id,
    b.object_count,b.graph_count,(SELECT count(*)::int FROM workflow_approvals v WHERE v.workflow_id=w.id AND v.decision='approve') AS votes
    FROM workflows w JOIN workflow_executions e ON e.workflow_id=w.id JOIN entity_change_execution_sources s ON s.workflow_execution_id=e.id
    JOIN entity_change_baselines b ON b.source_id=s.id JOIN entity_change_baseline_pins p ON p.source_id=s.id AND p.baseline_id=b.id
    WHERE w.id=$1 AND w.cluster_id=$2 AND w.workspace_id=$3`,[id,cid,wid]);
   assert(result&&result.state==='succeeded'&&result.execution_state==='succeeded');assert(result.object_count>=2);assert.equal(result.votes,3);
   executions.push(result);
  }return{executions:executions.length};
 });
 await check('exact_whole_graph_packet_attempt_send_outcome_and_receipt_closure',async()=>{
  for(const execution of executions){
   const packets=(await query(`SELECT p.*,a.id AS attempt_id,e.native_status,e.fact_hmac,e.fact_ciphertext,e.observed_at,
     r.operation_id,r.operation_key,r.result_hmac,r.verification_hmac,m.state AS mutation_state,m.remote_started,m.remote_completed,m.result_secret,
     (SELECT count(*)::int FROM entity_change_packet_events sent WHERE sent.attempt_id=a.id AND sent.event_kind='send-intent') AS sends,
     (SELECT count(*)::int FROM entity_change_packet_events done WHERE done.attempt_id=a.id AND done.event_kind='outcome' AND done.outcome='succeeded') AS outcomes
     FROM entity_change_recycle_packets p JOIN entity_change_packet_attempts a ON a.source_id=p.source_id AND a.packet_key=p.packet_key
     JOIN entity_change_packet_events e ON e.attempt_id=a.id AND e.event_kind='outcome' JOIN entity_change_recycle_receipts r ON r.attempt_id=a.id
     JOIN mutation_operations m ON m.id=r.operation_id WHERE p.source_id=$1 ORDER BY p.packet_order`,[execution.source_id])).rows;
   assert(packets.length>=2);const entries=new Set(packets.map(p=>p.entry_id));assert.equal(entries.size,1);
   const archive=await row('SELECT * FROM entity_change_recycle_archives WHERE entry_id=$1',[packets[0].entry_id]);assert.equal(packets.length,archive.packet_count);
   assert.equal((await row('SELECT count(*)::int AS n FROM entity_change_recycle_nodes WHERE entry_id=$1',[archive.entry_id])).n,archive.node_count);
   for(const p of packets){
    assert.equal(p.cluster_id,cid);assert.equal(p.workspace_id,wid);assert.equal(p.baseline_id,execution.baseline_id);assert.equal(p.pin_id,execution.pin_id);
    assert.equal(p.sends,1);assert.equal(p.outcomes,1);assert.equal(p.mutation_state,'succeeded');assert(p.remote_started&&p.remote_completed);
    assert.equal(p.operation_key,`entity-${execution.execution_id}-${p.packet_order}`);
    const fact=secrets.decrypt(p.fact_ciphertext,entityPacketFactAad(cid,wid,p.attempt_id,'outcome'));
    assert.equal(secrets.fingerprint(fact),p.fact_hmac);assert.equal(fact.outcome,'succeeded');assert.equal(fact.evidence.metadataComplete,true);
    const native=secrets.decrypt(p.result_secret,`mutation:${p.operation_id}:result`);assert.equal(secrets.fingerprint(native),p.result_hmac);
    assert.equal(fact.evidence.responseHmac,p.result_hmac);
    if(p.direction==='delete'){
     assert.equal(p.native_status,204);assert.equal(native,null);
     const proof=fact.evidence.deleteVerification;assert(proof);assert.equal(proof.status,404);
     assert.equal(proof.version,1);assert.equal(proof.clusterId,cid);assert.equal(proof.workspaceId,wid);assert.equal(proof.entryId,p.entry_id);
     assert.equal(proof.nodeKey,p.node_key);assert.equal(proof.packetKey,p.packet_key);assert.equal(proof.attemptId,p.attempt_id);
     assert.equal(proof.operationId,p.operation_id);assert.equal(proof.nativeId,p.native_id);assert.equal(secrets.fingerprint(proof.canonicalPath),p.path_hmac);
     assert.equal(secrets.fingerprint(proof),p.verification_hmac);
    }else{assert(p.native_status>=200&&p.native_status<300);assert.equal(native.id,p.native_id);assert.notEqual(archive.source_id,p.source_id);}
   }
   execution.nativePackets=packets.length;execution.entryId=archive.entry_id;execution.direction=packets[0].direction;
  }return{executions:executions.length,nativePackets:executions.reduce((n,e)=>n+e.nativePackets,0)};
 });
 await check('append_only_runtime_permissions_and_no_unresolved_mutations',async()=>{
  const facts=['entity_change_baselines','entity_change_baseline_objects','entity_change_baseline_pins','entity_change_packet_attempts','entity_change_packet_events','entity_change_recovery_links',
   'entity_change_recycle_archives','entity_change_recycle_nodes','entity_change_recycle_packets','entity_change_recycle_receipts'];
  assert.equal((await row(`SELECT count(*)::int AS n FROM unnest($1::text[]) t WHERE has_table_privilege(current_user,t,'UPDATE') OR has_table_privilege(current_user,t,'DELETE') OR has_table_privilege(current_user,t,'TRUNCATE')`,[facts])).n,0);
  assert.equal((await row("SELECT count(*)::int AS n FROM mutation_operations WHERE cluster_id=$1 AND workspace_id=$2 AND state IN('running','uncertain')",[cid,wid])).n,0);
  return{appendOnlyTables:10,unresolvedMutations:0};
 });
 await query('ROLLBACK');passed=true;
}catch(error){failure={stage,kind:error?.name==='AssertionError'?'assertion':'runtime',sqlState:/^[A-Z\d]{5}$/.test(error?.code??'')?error.code:undefined};
}finally{if(c){if(!passed)try{await query('ROLLBACK');}catch{}await c.end();}}
console.log(JSON.stringify({milestone:'M11',gate:3,phase:'actual-recycle-execution-readonly',readOnly:true,passed,checks,executions,failure}));if(!passed)process.exitCode=1;
