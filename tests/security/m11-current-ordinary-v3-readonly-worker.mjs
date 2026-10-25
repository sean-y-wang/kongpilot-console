import { createRequire } from 'node:module';
import { resolve, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ordinaryV3ReceiptProof } from './lib/ordinary-v3-readonly-proof.mjs';
const must=(c,k)=>{if(!c)throw Error(k);};
const uuid=s=>typeof s==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(s);

/** Root-only readonly audit worker, never called by the HTTP driver. stdin
 * carries exact IDs, not cookies/keys. It emits counts and keyed hashes only.
 * No authorization delegate is installed, no private handle is constructed,
 * no product writer is invoked, and no evidence row is inserted or updated. */
export async function inspectOrdinaryV3Readonly(input,db,modules) {
  must(input?.version===1&&uuid(input.clusterId)&&uuid(input.workspaceId)&&uuid(input.workflowId)&&uuid(input.executionId)
    &&uuid(input.baselineId)&&uuid(input.entryId)&&['delete','restore'].includes(input.direction)
    &&Array.isArray(input.members)&&input.members.length>0&&input.members.length<=100&&input.members.every(p=>typeof p.type==='string'&&uuid(p.id)), 'V3_READONLY_EXACT_INPUT_REQUIRED');
  const secrets=new modules.SecretService(),facts=new modules.EntityChangeExecutionFactsService(db,secrets),recycleFacts=new modules.EntityChangeRecycleFactsService(db,secrets);
  const loaded=await facts.ready(input.baselineId,db),source=loaded.envelope.source;
  must(source.clusterId===input.clusterId&&source.workspaceId===input.workspaceId&&source.workflowId===input.workflowId
    &&source.workflowExecutionId===input.executionId&&uuid(source.sessionId), 'V3_READONLY_ORDINARY_SOURCE_REQUIRED');
  const terminal=await db.one('SELECT e.state,w.state AS workflow_state FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id WHERE e.id=$1 AND e.workflow_id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4',[input.executionId,input.workflowId,input.clusterId,input.workspaceId]);
  must(terminal?.state==='succeeded'&&terminal.workflow_state==='succeeded','V3_READONLY_REAL_TERMINAL_REQUIRED');
  const bound=await recycleFacts.binding({source,baseline:loaded.receipt,actor:{user:{id:source.executionActorId},workspaceId:source.workspaceId}},db);
  const obligations=bound.material.metadataObligations.filter(o=>input.direction==='delete'?o.kind==='recycle-archive':o.kind==='recycle-restore'&&o.entryId===input.entryId);
  must(obligations.length===1,'V3_READONLY_EXACT_GRAPH_REQUIRED');const obligation=obligations[0],graph=obligation.graph;
  const entry=await db.one('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[input.clusterId,input.workspaceId,input.entryId]);
  must(entry?.state===(input.direction==='delete'?'deleted':'restored')&&entry.mutation_id===null
    &&secrets.fingerprint(secrets.decrypt(entry.payload_secret,`recycle:${input.entryId}`))===secrets.fingerprint(graph),'V3_READONLY_ARCHIVE_AEAD_REQUIRED');
  const archive=await recycleFacts.verifyStoredArchive(db,input.entryId,graph);
  const expected=input.members.map(p=>`${p.type}:${p.id}`).sort(),actual=graph.nodes.filter(n=>n.affected).map(n=>`${n.type}:${n.id}`).sort();
  must(secrets.fingerprint(expected)===secrets.fingerprint(actual),'V3_READONLY_EXACT_ORIGINAL_IDS_REQUIRED');
  const packets=bound.material.packets.filter(p=>obligation.packetKeys.includes(p.key)),canonical=recycleFacts.subset(obligation,packets);
  must(canonical.length===expected.length,'V3_READONLY_CANONICAL_PACKET_COUNT_REQUIRED');
  const attempts=await db.query('SELECT * FROM entity_change_packet_attempts WHERE source_id=$1 ORDER BY packet_order',[source.id]);
  const receipts=await db.query('SELECT * FROM entity_change_recycle_receipts WHERE source_id=$1 AND entry_id=$2 ORDER BY packet_key',[source.id,input.entryId]);
  const ledger=await db.query('SELECT * FROM entity_change_recycle_packets WHERE source_id=$1 AND entry_id=$2 ORDER BY packet_order',[source.id,input.entryId]);
  must(attempts.length===packets.length&&receipts.length===packets.length&&ledger.length===packets.length,'V3_READONLY_FULL_RECEIPT_SET_REQUIRED');
  const results=[];
  for(const {node,packet}of canonical){
    const a=attempts.find(x=>x.packet_key===packet.key),r=receipts.find(x=>x.packet_key===packet.key),p=ledger.find(x=>x.packet_key===packet.key);
    must(a&&r&&p&&r.node_key===node.key&&p.node_key===node.key&&p.direction===input.direction,'V3_READONLY_NODE_PACKET_BIJECTION_REQUIRED');
    const expectedRow=recycleFacts.packetRow({source,baseline:loaded.receipt},input.entryId,node,packet,input.direction,p.created_at);
    must(secrets.fingerprint(p)===secrets.fingerprint(expectedRow),'V3_READONLY_SQL23_PACKET_MISMATCH');
    const m=await db.one('SELECT * FROM mutation_operations WHERE entity_change_attempt_id=$1',[a.id]);
    const events=await db.query('SELECT * FROM entity_change_packet_events WHERE attempt_id=$1 ORDER BY event_kind',[a.id]);
    results.push(ordinaryV3ReceiptProof({source,baseline:loaded.receipt,packet,attempt:a,mutation:m,events,receipt:r,entryId:input.entryId},
      {fingerprint:v=>secrets.fingerprint(v),decrypt:(v,aad)=>secrets.decrypt(v,aad)}));
  }
  return {version:1,readOnly:true,configurationVerified:true,baselineAeadVerified:true,intentAeadVerified:true,archiveAeadVerified:true,
    sql23ManifestVerified:true,originalTransportAndReciprocalMutationVerified:true,sourceId:source.id,workflowId:source.workflowId,
    executionId:source.workflowExecutionId,baselineId:input.baselineId,entryId:input.entryId,graphHmac:archive.graph_hmac,
    nodeManifestHmac:archive.node_manifest_hmac,nodeCount:graph.nodes.length,affectedCount:canonical.length,receipts:results.length,
    nativeStatus:input.direction==='delete'?204:201,functionalVerification:'pending',nativeRequestsSent:0,sqlWritesSent:0};
}

async function main(){
  must(process.env.RELEASE_LAB_M11_V3_READONLY_WORKER_READY==='true'&&process.argv.length===2,'V3_ROOT_READONLY_WORKER_GATE_REQUIRED');
  const dist=process.env.RELEASE_LAB_M11_V3_API_DIST;must(typeof dist==='string'&&isAbsolute(dist),'V3_ROOT_EXACT_API_DIST_REQUIRED');
  const require=createRequire(resolve(dist,'main.js'));require('reflect-metadata');
  const {Pool}=require('pg'),modules={...require(resolve(dist,'infrastructure/secret.service.js')),
    ...require(resolve(dist,'modules/workflows/entity-change-execution-facts.service.js')),
    ...require(resolve(dist,'modules/recycle-bin/entity-change-recycle-facts.service.js'))};
  let text='';for await(const chunk of process.stdin){text+=chunk;must(Buffer.byteLength(text)<=128*1024,'V3_READONLY_INPUT_TOO_LARGE');}
  const pool=new Pool({connectionString:process.env.DATABASE_URL,max:1,connectionTimeoutMillis:10000});let client;
  try{
    client=await pool.connect();
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await client.query("SET LOCAL statement_timeout='30s'");
    const role=(await client.query("SELECT rolsuper,rolbypassrls,current_setting('transaction_read_only') AS read_only FROM pg_roles WHERE rolname=current_user")).rows[0];
    must(role?.rolsuper===false&&role.rolbypassrls===false&&role.read_only==='on','V3_NOSU_READONLY_ROLE_REQUIRED');
    const db={one:async(sql,args)=>(await client.query(sql,args)).rows[0]??null,query:async(sql,args)=>(await client.query(sql,args)).rows};
    const result=await inspectOrdinaryV3Readonly(JSON.parse(text),db,modules);await client.query('COMMIT');console.log(JSON.stringify(result));
  }catch{if(client)try{await client.query('ROLLBACK');}catch{}throw Error('V3_READONLY_VERIFICATION_STOPPED');}finally{client?.release();await pool.end();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){try{await main();}catch{console.error(JSON.stringify({passed:false,errorCode:'V3_READONLY_VERIFICATION_STOPPED',privateDetailsPublished:false}));process.exitCode=1;}}
