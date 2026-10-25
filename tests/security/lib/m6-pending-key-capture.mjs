import {createDecipheriv} from 'node:crypto';
import {checkpointSha} from './m6-isolated-transition.mjs';

// This exact fixture is already created, while its final metadata is unknown.
// It is scanner material only: this helper never activates or reveals a grant.
export const PENDING_KEY_TUPLE=Object.freeze({
  clusterId:'7fc418d4-d891-4e8b-a4ec-c7a6544e886a',workspaceId:'28329ea2-83a4-4b2c-b030-a209567d3276',
  grantId:'12491546-24cc-4f35-be68-bbe6f25da3b1',credentialId:'178a5734-588b-42e0-b709-0ec1212afabc',
  consumerId:'83b54fe9-5347-4496-983d-2b656a7b9f83',aclId:'05e1cd29-3cd3-456b-a4cb-843ce00c82b9',
  nativeId:'8da4d38b-ba56-428c-bc17-cb10b724d497',workflowId:'d81b32a9-f1bb-4f9e-a378-df18ee0d33b5',
  executionId:'28dc2545-de2e-4989-af6f-3869e984b2d9',executionKey:'1e1fffa6-88cf-4dfe-9dd6-58bda37c87ad',
  consumerOperationId:'357a8ddf-17f7-46dd-ab63-9b5d7468c1b5',aclOperationId:'24bc85c3-d419-4b0d-8383-ba2e368c6207',
  keyOperationId:'3c299dfb-4df2-4826-8bec-37f1795f34ad',keyReferenceId:'d63ac3c8-1231-4a20-89e4-e11584cfb209',
  aclReferenceId:'45017af1-ccee-410a-bc86-c8d5de49f59a',metadataStepId:'0b9d97c9-08f0-43fc-b7bf-457fc497beb5',generation:1,
});

export function pendingCaptureAad(tuple=PENDING_KEY_TUPLE){
  if(JSON.stringify(tuple)!==JSON.stringify(PENDING_KEY_TUPLE))throw new Error('PENDING_KEY_CAPTURE_SCOPE_CHANGED');
  return JSON.stringify({stage:'M6',purpose:'pending-key-secret-scan-only',tuple});
}

export function decryptPendingTransfer(transfer,key,tuple=PENDING_KEY_TUPLE){
  if(!transfer||Object.keys(transfer).sort().join(',')!=='ciphertext,iv,tag,version'||transfer.version!==1||!Buffer.isBuffer(key)||key.length!==32
    ||!/^[a-f0-9]{24}$/.test(transfer.iv)||!/^[a-f0-9]{32}$/.test(transfer.tag)||typeof transfer.ciphertext!=='string'||transfer.ciphertext.length>8192)throw new Error('PENDING_KEY_CAPTURE_TRANSFER_INVALID');
  const encrypted=Buffer.from(transfer.ciphertext,'base64');
  if(encrypted.length<1||encrypted.length>6144||encrypted.toString('base64')!==transfer.ciphertext)throw new Error('PENDING_KEY_CAPTURE_TRANSFER_INVALID');
  let plaintext;
  try{
    const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(transfer.iv,'hex'));decipher.setAAD(Buffer.from(pendingCaptureAad(tuple)));decipher.setAuthTag(Buffer.from(transfer.tag,'hex'));
    plaintext=Buffer.concat([decipher.update(encrypted),decipher.final()]);const data=JSON.parse(plaintext.toString('utf8'));
    if(Object.keys(data).sort().join(',')!=='key,tuple,validated'||JSON.stringify(data.tuple)!==JSON.stringify(tuple)||data.validated!==true||typeof data.key!=='string'||!/^[A-Za-z0-9_-]{32,128}$/.test(data.key))throw new Error();
    return data;
  }catch{throw new Error('PENDING_KEY_CAPTURE_TRANSFER_INVALID');}finally{plaintext?.fill(0);}
}

export function pendingReferenceGuard(reference,tuple=PENDING_KEY_TUPLE){
  pendingCaptureAad(tuple);
  if(!reference.fixtures?.some(f=>f.cluster?.id===tuple.clusterId&&f.workspace?.id===tuple.workspaceId&&f.workspace.code?.startsWith(reference.testTag)))throw new Error('PENDING_KEY_CAPTURE_FIXTURE_CHANGED');
  const attempt=reference.writeAttempts?.find(a=>a.key===tuple.executionKey&&a.path===`/api/v1/clusters/${tuple.clusterId}/workflows/${tuple.workflowId}/execute`);
  if(!attempt||attempt.httpStatus!==503||attempt.errorCode!=='WORKFLOW_EXECUTION_FAILED'||!attempt.query?.includes(tuple.workspaceId))throw new Error('PENDING_KEY_CAPTURE_EXECUTION_CHANGED');
  for(const prior of reference.priorFixtureRuns??[])if(prior.checkpointSha256!==checkpointSha(prior.checkpoint))throw new Error('PENDING_KEY_CAPTURE_HISTORY_CHANGED');
  return true;
}

export function mergePendingCapture(reference,bundle){
  pendingReferenceGuard(reference,bundle.tuple);
  if(bundle.validated!==true||typeof bundle.key!=='string'||!/^[A-Za-z0-9_-]{32,128}$/.test(bundle.key))throw new Error('PENDING_KEY_CAPTURE_BUNDLE_INVALID');
  const next=structuredClone(reference);next.secrets=[...new Set([...(next.secrets??[]),bundle.key])];
  next.pendingCredentialScanCaptures=[...(next.pendingCredentialScanCaptures??[]).filter(item=>item.credentialId!==bundle.tuple.credentialId),{...bundle.tuple,scannerOnly:true,businessActivationPerformed:false,nativeWritesPerformed:0,consoleWritesPerformed:0,capturedAt:new Date().toISOString()}];
  return next;
}

// One-use transfer key travels through stdin only. The program performs a
// fixed bounded repeatable-read transaction, then sends GCM ciphertext only.
// No raw key is written into a container file, argv, environment or stdout.
export const PENDING_CAPTURE_PROGRAM=String.raw`
const fs=require('node:fs'),crypto=require('node:crypto'),pg=require('pg');
const {SecretService}=require('./dist/infrastructure/secret.service.js'),{portalKeyAad}=require('./dist/modules/portal/portal-proof.js');
const expected=${JSON.stringify(PENDING_KEY_TUPLE)};
let pool,client,transferKey,plain;
(async()=>{try{
 const input=fs.readFileSync(0);if(input.length>4096)throw Error();const request=JSON.parse(input);
 if(Object.keys(request).sort().join(',')!=='key,tuple'||JSON.stringify(request.tuple)!==JSON.stringify(expected)||!/^[a-f0-9]{64}$/.test(request.key))throw Error();
 transferKey=Buffer.from(request.key,'hex');pool=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL,max:1,connectionTimeoutMillis:5000,statement_timeout:5000});client=await pool.connect();
 await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 const q=await client.query(
  "SELECT c.key_secret,c.key_fingerprint,c.state AS credential_state,c.generation,c.credential_ref_id,c.issue_operation_id,g.state AS grant_state,g.current_generation,g.current_credential_id,w.state AS workflow_state,w.kind,e.state AS execution_state,e.idempotency_key,op.state AS operation_state,op.remote_completed,op.result_secret,r.state AS reference_state,r.payload_secret FROM portal_credentials c JOIN portal_application_grants g ON g.id=c.grant_id AND g.cluster_id=c.cluster_id AND g.workspace_id=c.workspace_id JOIN workflows w ON w.id=c.workflow_id AND w.cluster_id=c.cluster_id AND w.workspace_id=c.workspace_id JOIN workflow_executions e ON e.workflow_id=w.id AND e.cluster_id=w.cluster_id AND e.workspace_id=w.workspace_id AND e.plan_revision=w.plan_revision AND e.plan_hash=w.plan_hash JOIN mutation_operations op ON op.workflow_execution_id=e.id AND op.workflow_plan_revision=e.plan_revision AND op.workflow_plan_hash=e.plan_hash AND op.workflow_id=w.id AND op.cluster_id=c.cluster_id AND op.workspace_id=c.workspace_id AND op.entity_type='credentials' AND op.action='create' AND op.credential_kind='key-auth' AND op.parent_id=c.consumer_id::text AND op.entity_id=c.kong_id::text JOIN credential_refs r ON r.cluster_id=c.cluster_id AND r.consumer_id=c.consumer_id AND r.credential_type='key-auth' AND r.kong_id=c.kong_id WHERE c.id=$1 AND c.cluster_id=$2 AND c.workspace_id=$3 AND c.grant_id=$4 AND c.consumer_id=$5 AND c.kong_id=$6 AND c.generation=$7 AND w.id=$8 AND e.id=$9 AND e.idempotency_key=$10 AND op.id=$11 AND r.id=$12 AND g.acl_id=$13 AND g.workflow_id=w.id AND g.developer_id=c.developer_id LIMIT 2",
  [expected.credentialId,expected.clusterId,expected.workspaceId,expected.grantId,expected.consumerId,expected.nativeId,expected.generation,expected.workflowId,expected.executionId,expected.executionKey,expected.keyOperationId,expected.keyReferenceId,expected.aclId]);
 if(q.rows.length!==1)throw Error();const row=q.rows[0];
 if(row.credential_state!=='pending'||row.grant_state!=='pending'||row.current_generation!==0||row.current_credential_id!==null||row.credential_ref_id!==null||row.issue_operation_id!==null||row.workflow_state!=='uncertain'||row.kind!=='portal-credential-issue'||row.execution_state!=='uncertain'||row.operation_state!=='succeeded'||row.remote_completed!==true||row.reference_state!=='active')throw Error();
 const native=await client.query("SELECT s.id,s.kind,s.handler,s.state,s.operation_id,op.id AS native_operation_id,op.state AS operation_state,op.remote_completed,op.entity_type,op.entity_id,op.parent_id,op.credential_kind FROM workflow_steps s LEFT JOIN mutation_operations op ON op.id=s.operation_id AND op.workflow_step_id=s.id AND op.workflow_execution_id=$2 AND op.workflow_id=s.workflow_id AND op.cluster_id=s.cluster_id AND op.workspace_id=s.workspace_id AND op.workflow_plan_revision=s.plan_revision AND op.workflow_plan_hash=s.plan_hash WHERE s.workflow_id=$1 AND s.cluster_id=$3 AND s.workspace_id=$4 ORDER BY s.step_order LIMIT 5",[expected.workflowId,expected.executionId,expected.clusterId,expected.workspaceId]);
 const opIds=[expected.consumerOperationId,expected.aclOperationId,expected.keyOperationId],entityIds=[expected.consumerId,expected.aclId,expected.nativeId];
 if(native.rows.length!==4||native.rows.slice(0,3).some((s,index)=>s.kind!=='native'||s.state!=='succeeded'||s.operation_id!==opIds[index]||s.operation_id!==s.native_operation_id||s.operation_state!=='succeeded'||s.remote_completed!==true||s.entity_id!==entityIds[index]||s.entity_type!==(index?'credentials':'consumers')||s.parent_id!==(index?expected.consumerId:null)||s.credential_kind!==(index===1?'acls':index===2?'key-auth':null))||native.rows[3].id!==expected.metadataStepId||native.rows[3].kind!=='metadata'||native.rows[3].handler!=='portal.credential.activate'||native.rows[3].state!=='uncertain'||native.rows[3].operation_id!==null)throw Error();
 const acl=await client.query("SELECT id FROM credential_refs WHERE id=$1 AND cluster_id=$2 AND consumer_id=$3 AND credential_type='acls' AND kong_id=$4 AND state='active' LIMIT 2",[expected.aclReferenceId,expected.clusterId,expected.consumerId,expected.aclId]);if(acl.rows.length!==1)throw Error();
 const secrets=new SecretService(),envelope=secrets.decrypt(row.key_secret,portalKeyAad(expected.clusterId,expected.workspaceId,expected.credentialId,expected.generation)),key=typeof envelope==='string'?envelope:envelope.key;
 const remembered=secrets.decrypt(row.payload_secret,'credential:'+expected.clusterId+':'+expected.consumerId+':key-auth:'+expected.nativeId),result=secrets.decrypt(row.result_secret,'mutation:'+expected.keyOperationId+':result'),entity=result?.entity??result;
 if(typeof key!=='string'||!/^[A-Za-z0-9_-]{32,128}$/.test(key)||secrets.fingerprint(key)!==row.key_fingerprint||remembered?.credential?.key!==key||remembered.credential.id!==expected.nativeId||remembered.credential.consumer?.id!==expected.consumerId||entity?.key!==key||entity.id!==expected.nativeId||entity.consumer?.id!==expected.consumerId)throw Error();
 await client.query('ROLLBACK');client.release();client=null;
 plain=Buffer.from(JSON.stringify({key,tuple:expected,validated:true}));const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',transferKey,iv);cipher.setAAD(Buffer.from(JSON.stringify({stage:'M6',purpose:'pending-key-secret-scan-only',tuple:expected})));const data=Buffer.concat([cipher.update(plain),cipher.final()]);
 process.stdout.write(JSON.stringify({version:1,iv:iv.toString('hex'),tag:cipher.getAuthTag().toString('hex'),ciphertext:data.toString('base64')}));
}catch{process.stderr.write('PENDING_KEY_CAPTURE_FAILED\n');process.exitCode=2;}finally{if(client){await client.query('ROLLBACK').catch(()=>{});client.release();}await pool?.end();transferKey?.fill(0);plain?.fill(0);}})();
`;
