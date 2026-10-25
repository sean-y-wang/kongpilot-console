import { M8_COMPOSE, sha256 } from './m8-harness.mjs';
import { execFileSync } from 'node:child_process';

export const M8_CONSUMER_RETRY = Object.freeze({
  packetCount:71,prefixSha256:'1c5c9cb3888c5184300232f0b9421a247560d06956582a876d7d48fbd7f0308c',
  packetSha256:'6c21d14a0915f386f733ca26ade57bbd64a99016122ac95d0d8cc758f3a7301a',
  failurePath:'artifacts/M8/security-live-unused-transfer-continuation.json',failureSha256:'ded94f977ace818ce4e8139a5cbec05508d25d1c350acd2f3ae1844e3c888d0c',
  diagnosisPath:'artifacts/M8/consumer-restore-original-request-readonly-diagnosis.json',diagnosisSha256:'e07fedaeac73b653e4e463d8df5d53956c1b70ada075ee9a918577a87d8d723a',
  deploymentPath:'artifacts/M8/recycle-archived-authority-original-target-repair-continuity.json',deploymentSha256:'1ef5e02cea8e0e96db235d887fc5c9d0f646e55fd32de6e2fb4669564a45bac0',
  cid:'dff45535-ed8d-4851-b7a6-6376feac7f59',wid:'eb8bf868-2caf-46aa-a935-b368bf9f3105',
  actorId:'b5f796fa-9515-47de-9123-89a903a48224',sid:'81eb0903-bc6f-447b-a9a7-7cadf55faa77',
  entryId:'57e3ac7b-cc7a-4ed1-aff8-802339029411',consumerId:'34cce5e0-54bd-4d19-b5bd-0cf21e469e37',
  key:'bfec0b3c-e28e-4892-b047-f0839f504d0c',requestId:'c4722dc5-ce3a-440a-ab14-3a049698e1b2',
});
export function assertM8ConsumerRetryCheckpoint(r){
  const c=M8_CONSUMER_RETRY,p=r.requests?.[70];
  if(r.requests?.length!==c.packetCount||sha256(JSON.stringify(r.requests))!==c.prefixSha256||sha256(JSON.stringify(p))!==c.packetSha256
    ||r.inFlight!==null||r.phase!=='stopped-failure'||r.consumerPreflightRetry||r.fiveClassRecovery||r.directTransfer||r.approvalTransfer
    ||r.requests.some(v=>['prepared','response_unknown'].includes(v.state))||r.proxyChecks.some(v=>v.state==='response_unknown')
    ||r.cliIntents.length||p.key!==c.key||p.requestId!==c.requestId||p.actorId!==c.actorId||p.sessionId!==c.sid
    ||p.status!==404||p.errorCode!=='KONG_VALIDATION_ERROR'||p.method!=='POST'||p.path!==`/api/v1/clusters/${c.cid}/recycle-bin/${c.entryId}/restore`
    ||p.query!==`?workspaceId=${c.wid}`||p.bodySha256!==sha256(JSON.stringify(p.body))||p.body?.confirmed!==true
    ||r.sessions.admin.user.id!==c.actorId||r.sessions.admin.sid!==c.sid||r.scopes.direct.cid!==c.cid||r.scopes.direct.wid!==c.wid
    ||r.recycleEntries.length!==2)throw Error('M8_EXACT_CONSUMER_PREFLIGHT_ONLY_CHECKPOINT_REQUIRED');
  return p;
}
/** This safe metadata query is a fresh non-owner READ ONLY proof, not a permit.
 * Actual authorization still happens through the protected BFF and NativePolicy. */
export function readM8ConsumerRetryLedger(){
  const c=M8_CONSUMER_RETRY,environment={...process.env};
  for(const name of['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete environment[name];
  const container=execFileSync('docker',['--host=unix:///var/run/docker.sock',...M8_COMPOSE,'ps','-q','console-api'],{env:environment,encoding:'utf8'}).trim();
  if(!/^[a-f\d]{64}$/.test(container))throw Error('M8_CANONICAL_API_CONTAINER_REQUIRED');
  const program=`const{Client}=require('pg');let input='';process.stdin.on('data',b=>input+=b);process.stdin.on('end',async()=>{const p=JSON.parse(input),db=new Client({connectionString:process.env.DATABASE_URL});try{await db.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const identity=(await db.query('SELECT current_database() AS name,current_user AS role')).rows[0];if(identity.name!=='kongos'||identity.role!=='kongos_app')throw Error('READONLY_NONOWNER_REQUIRED');const entry=(await db.query('SELECT id,cluster_id,workspace_id,root_type,original_id,state,node_count,actor_id=$4::uuid AS owner_matches FROM recycle_entries WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[p.cid,p.wid,p.entryId,p.actorId])).rows[0];const nodes=(await db.query('SELECT entity_type,original_id,affected,delete_state,restore_state,restored_id FROM recycle_nodes WHERE entry_id=$1 ORDER BY entity_type,original_id',[p.entryId])).rows;const operations=(await db.query('SELECT id,state,remote_started,remote_completed FROM mutation_operations WHERE cluster_id=$1 AND idempotency_key=$2',[p.cid,p.key])).rows;const audits=(await db.query('SELECT id,action,result FROM audit_events WHERE cluster_id=$1 AND request_id=$2',[p.cid,p.requestId])).rows;await db.query('COMMIT');console.log(JSON.stringify({ok:true,nonOwnerReadOnly:true,entry,nodes,operations,audits}));}catch(e){try{await db.query('ROLLBACK');}catch{}console.log(JSON.stringify({ok:false,errorCode:/^[A-Z0-9_]{2,80}$/.test(e.code||'')?e.code:'READONLY_DIAGNOSTIC_FAILED'}));process.exitCode=1;}finally{await db.end();}});`;
  let output;try{output=execFileSync('docker',['--host=unix:///var/run/docker.sock','exec','-i',container,'node','-e',program],{env:environment,input:JSON.stringify(c),encoding:'utf8',timeout:30000,maxBuffer:65536});}
  catch{throw Error('M8_CURRENT_CONSUMER_LEDGER_READ_FAILED');}
  return JSON.parse(output);
}
export function assertM8ConsumerZeroLedger(proof,fixture){
  const c=M8_CONSUMER_RETRY,e=proof?.entry;
  if(proof?.ok!==true||proof.nonOwnerReadOnly!==true||e?.id!==c.entryId||e.cluster_id!==c.cid||e.workspace_id!==c.wid
    ||e.root_type!=='consumers'||e.original_id!==c.consumerId||e.state!=='deleted'||e.node_count!==7||e.owner_matches!==true
    ||!Array.isArray(proof.nodes)||proof.nodes.length!==7||!Array.isArray(proof.operations)||proof.operations.length!==0
    ||!Array.isArray(proof.audits)||proof.audits.length!==0)throw Error('M8_ORIGINAL_RESTORE_ZERO_LEDGER_REQUIRED');
  const expected=[['consumers',c.consumerId],...Object.entries(fixture.credentials).map(([kind,row])=>[kind,row.id])];
  if(expected.length!==7||new Set(expected.map(([type,id])=>`${type}:${id}`)).size!==7
    ||proof.nodes.some(node=>node.affected!==true||node.delete_state!=='deleted'||node.restore_state!=='pending'||node.restored_id!==null)
    ||expected.some(([type,id])=>proof.nodes.filter(n=>n.entity_type===type&&n.original_id===id).length!==1))throw Error('M8_ORIGINAL_RESTORE_ALL_SEVEN_NODES_UNTOUCHED_REQUIRED');
}
export function assertM8ConsumerProtectedPreview(preview){
  const c=M8_CONSUMER_RETRY,e=preview?.entry,n=preview?.graph?.nodes;
  // SecretService intentionally masks a node's `key` credential-shaped field;
  // use typed public entity identities, not a comparison against rootKey.
  if(e?.id!==c.entryId||e.workspace_id!==c.wid||e.cluster_id!==c.cid||e.root_type!=='consumers'||e.original_id!==c.consumerId
    ||e.state!=='deleted'||!Array.isArray(n)||n.length!==7
    ||n.filter(node=>node.type==='consumers'&&node.id===c.consumerId&&node.affected===true).length!==1
    ||preview.nodes?.length!==7)throw Error('M8_CURRENT_PROTECTED_ORIGINAL_CONSUMER_GRAPH_REQUIRED');
}
