import {describe,expect,it} from 'vitest';
import {createCipheriv,randomBytes,randomUUID} from 'node:crypto';
import {PENDING_KEY_TUPLE,PENDING_CAPTURE_PROGRAM,pendingCaptureAad,pendingReferenceGuard,decryptPendingTransfer,mergePendingCapture} from './lib/m6-pending-key-capture.mjs';
import {checkpointSha} from './lib/m6-isolated-transition.mjs';
import {capturedPrivateSecrets} from './lib/m6-fixture-runs.mjs';

function fixture(){
 const tuple=PENDING_KEY_TUPLE,previous={testTag:'m6-security-old',secrets:[randomUUID()],writeAttempts:[{key:randomUUID(),method:'POST',path:'/old',body:{password:randomUUID()}}]},key=randomBytes(32).toString('base64url');
 const reference:any={testTag:'m6-isolated-offline',fixtures:[{cluster:{id:tuple.clusterId},workspace:{id:tuple.workspaceId,code:'m6-isolated-offline-primary'}}],secrets:[randomUUID()],writeAttempts:[{key:tuple.executionKey,path:`/api/v1/clusters/${tuple.clusterId}/workflows/${tuple.workflowId}/execute`,query:`?workspaceId=${tuple.workspaceId}`,httpStatus:503,errorCode:'WORKFLOW_EXECUTION_FAILED',body:{confirmed:true}}],tokens:[{purpose:'native_scrape',token:randomUUID()}],priorFixtureRuns:[{testTag:previous.testTag,checkpoint:previous,checkpointSha256:checkpointSha(previous)}]};
 return{reference,bundle:{key,tuple,validated:true},key};
}
function transfer(bundle:any,key:Buffer,aad=pendingCaptureAad()){
 const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(aad));const ciphertext=Buffer.concat([cipher.update(JSON.stringify(bundle)),cipher.final()]);
 return{version:1,iv:iv.toString('hex'),tag:cipher.getAuthTag().toString('hex'),ciphertext:ciphertext.toString('base64')};
}
describe('M6 exact pending-key scanner capture (offline)',()=>{
 it('accepts only the currently captured owned fixture and original failed execution',()=>{
  const{reference}=fixture();expect(pendingReferenceGuard(reference)).toBe(true);
  for(const change of[(r:any)=>r.fixtures[0].cluster.id=randomUUID(),(r:any)=>r.fixtures[0].workspace.code='baseline-unmanaged',(r:any)=>r.writeAttempts[0].key=randomUUID(),(r:any)=>r.writeAttempts[0].httpStatus=201,(r:any)=>r.writeAttempts[0].query='',(r:any)=>r.priorFixtureRuns[0].checkpoint.secrets.push('changed')]){const r=structuredClone(reference);change(r);expect(()=>pendingReferenceGuard(r)).toThrow();}
 });
 it('authenticates the complete exact tuple and scanner purpose before decrypting transfer',()=>{
  const{bundle}=fixture(),key=randomBytes(32),encrypted=transfer(bundle,key);expect(decryptPendingTransfer(encrypted,key)).toEqual(bundle);
  expect(JSON.stringify(encrypted)).not.toContain(bundle.key);
  expect(()=>decryptPendingTransfer(encrypted,randomBytes(32))).toThrow();
  expect(()=>decryptPendingTransfer({...encrypted,tag:randomBytes(16).toString('hex')},key)).toThrow();
  expect(()=>decryptPendingTransfer(transfer(bundle,key,'Portal-business-reveal'),key)).toThrow();
  expect(()=>decryptPendingTransfer(encrypted,key,{...PENDING_KEY_TUPLE,credentialId:randomUUID()})).toThrow();
 });
 it('rejects altered transfer schema, unproved tuple and oversized or non-key payloads',()=>{
  const{bundle}=fixture(),key=randomBytes(32);
  for(const value of[{...bundle,validated:false},{...bundle,tuple:{...bundle.tuple,nativeId:randomUUID()}},{...bundle,key:'not-a-key'},{...bundle,secretEscape:true}])expect(()=>decryptPendingTransfer(transfer(value,key),key)).toThrow();
  expect(()=>decryptPendingTransfer({...transfer(bundle,key),plaintext:bundle.key},key)).toThrow();
  expect(()=>decryptPendingTransfer({...transfer(bundle,key),ciphertext:'A'.repeat(10000)},key)).toThrow();
 });
 it('adds only private scanner secrets and safe capture metadata while preserving all historical checkpoints, tokens, keys and bodies',()=>{
  const{reference,bundle,key}=fixture(),before=structuredClone(reference),next=mergePendingCapture(reference,bundle);
  expect(reference).toEqual(before);expect(next.secrets).toContain(key);expect(capturedPrivateSecrets(next)).toContain(key);
  expect(next.writeAttempts).toEqual(before.writeAttempts);expect(next.tokens).toEqual(before.tokens);expect(next.priorFixtureRuns).toEqual(before.priorFixtureRuns);
  expect(next.pendingCredentialScanCaptures[0]).toMatchObject({scannerOnly:true,businessActivationPerformed:false,nativeWritesPerformed:0,consoleWritesPerformed:0});
  expect(JSON.stringify(next.pendingCredentialScanCaptures)).not.toContain(key);expect(mergePendingCapture(next,bundle).secrets.filter((s:string)=>s===key)).toHaveLength(1);
 });
 it('keeps the trusted process read-only and bounded with no native transport or raw stdout path',()=>{
  expect(()=>new Function(PENDING_CAPTURE_PROGRAM)).not.toThrow();
  expect(PENDING_CAPTURE_PROGRAM).toContain('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');expect(PENDING_CAPTURE_PROGRAM).toContain("await client.query('ROLLBACK')");
  expect(PENDING_CAPTURE_PROGRAM).not.toMatch(/\b(?:INSERT|UPDATE|DELETE|TRUNCATE|ALTER|DROP|CREATE|COPY|CALL)\b/);
  expect(PENDING_CAPTURE_PROGRAM).not.toMatch(/fetch\(|http\.request|https\.request|writeFile/);
  expect(PENDING_CAPTURE_PROGRAM).toContain('portalKeyAad(expected.clusterId,expected.workspaceId,expected.credentialId,expected.generation)');
  expect(PENDING_CAPTURE_PROGRAM).toContain('process.stdout.write(JSON.stringify({version:1');expect(PENDING_CAPTURE_PROGRAM).toContain('row.remote_completed!==true');
 });
});
