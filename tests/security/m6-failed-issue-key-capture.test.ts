import {describe,it,expect} from 'vitest';
import {createCipheriv,randomBytes,randomUUID} from 'node:crypto';
import {FAILED_ISSUE_TUPLE as T,FAILED_ISSUE_CAPTURE_PROGRAM,failedIssueCaptureAad,failedIssueCaptureReferenceGuard,decryptFailedIssueTransfer,mergeFailedIssueCapture} from './lib/m6-failed-issue-key-capture.mjs';
import {checkpointSha} from './lib/m6-isolated-transition.mjs';
import {PENDING_KEY_TUPLE as FIRST} from './lib/m6-pending-key-capture.mjs';

function reference(){
 const actor=randomUUID(),old={testTag:'m6-security-synthetic-old',secrets:[randomBytes(32).toString('base64url')]};
 return{testTag:'m6-isolated-synthetic-current',fixtures:[{cluster:{id:T.clusterId},workspace:{id:T.workspaceId,code:'m6-isolated-synthetic-current-portal'}}],consoleAdministrator:{user:{id:actor}},metadataRecovery:{phase:'metadata-succeeded-original-execution',receiptState:'succeeded',workflowId:FIRST.workflowId,executionId:FIRST.executionId,grantId:FIRST.grantId,credentialId:FIRST.credentialId},grants:[{workflowId:FIRST.workflowId,grant:{id:FIRST.grantId},credential:{id:FIRST.credentialId}}],writeAttempts:[{key:T.executionKey,method:'POST',state:'response_observed',path:`/api/v1/clusters/${T.clusterId}/workflows/${T.workflowId}/execute`,query:`?workspaceId=${T.workspaceId}`,actorId:actor,httpStatus:409,errorCode:'KONG_VALIDATION_ERROR'}],secrets:[randomBytes(32).toString('base64url')],priorFixtureRuns:[{checkpoint:old,checkpointSha256:checkpointSha(old)}],tokens:[{token:randomBytes(32).toString('base64url')}]};
}
function transfer(bundle:any,key:Buffer){
 const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(failedIssueCaptureAad()));const encrypted=Buffer.concat([cipher.update(JSON.stringify(bundle)),cipher.final()]);return{version:1,iv:iv.toString('hex'),tag:cipher.getAuthTag().toString('hex'),ciphertext:encrypted.toString('base64')};
}
describe('M6 failed issue key scanner-only capture (offline)',()=>{
 it('requires this exact original failed Consumer execute and completed first metadata checkpoint',()=>{
  const r=reference();expect(failedIssueCaptureReferenceGuard(r)).toBe(true);
  for(const mutate of[(v:any)=>v.writeAttempts[0].key=randomUUID(),(v:any)=>v.writeAttempts[0].actorId=randomUUID(),(v:any)=>v.writeAttempts[0].httpStatus=503,(v:any)=>v.metadataRecovery.phase='reconcile-request-started',(v:any)=>v.grants=[],(v:any)=>v.failedIssueContinuation={phase:'abandonment-started'},(v:any)=>v.priorFixtureRuns[0].checkpoint.secrets.push('tamper')]){const copy=structuredClone(r);mutate(copy);expect(()=>failedIssueCaptureReferenceGuard(copy)).toThrow();}
 });
 it('requires exact scope and authenticates a bounded one-use ciphertext transfer',()=>{
  const key=randomBytes(32),bundle={key:randomBytes(32).toString('base64url'),tuple:T,validated:true},encrypted=transfer(bundle,key);
  expect(decryptFailedIssueTransfer(encrypted,key)).toEqual(bundle);
  expect(()=>decryptFailedIssueTransfer(encrypted,randomBytes(32))).toThrow();expect(()=>decryptFailedIssueTransfer({...encrypted,tag:'0'.repeat(32)},key)).toThrow();
  expect(()=>failedIssueCaptureAad({...T,credentialId:randomUUID()})).toThrow();expect(()=>decryptFailedIssueTransfer({...encrypted,unexpected:true},key)).toThrow();
 });
 it('rejects authenticated but nonvalidated/foreign/oversized plaintext bundles',()=>{
  const key=randomBytes(32);for(const change of[{validated:false},{tuple:{...T,workflowId:randomUUID()}},{key:'short'},{key:'a'.repeat(9000)}]){const value={key:randomBytes(32).toString('base64url'),tuple:T,validated:true,...change};expect(()=>decryptFailedIssueTransfer(transfer(value,key),key)).toThrow();}
 });
 it('adds the generated key only to private scan secrets and preserves complete historical/current evidence',()=>{
  const r=reference(),before=structuredClone(r),key=randomBytes(32).toString('base64url'),next=mergeFailedIssueCapture(r,{key,tuple:T,validated:true});
  expect(r).toEqual(before);expect(next.secrets).toContain(key);expect(next.writeAttempts).toEqual(r.writeAttempts);expect(next.metadataRecovery).toEqual(r.metadataRecovery);expect(next.tokens).toEqual(r.tokens);expect(next.priorFixtureRuns).toEqual(r.priorFixtureRuns);
  expect(next.failedIssueCredentialScanCaptures[0]).toMatchObject({credentialId:T.credentialId,scannerOnly:true,nativeWrites:0,businessWrites:0});
  expect(JSON.stringify(next.failedIssueCredentialScanCaptures)).not.toContain(key);
 });
 it('trusted capture program has only fixed SELECT/read-only transaction and encrypted stdout, with no gateway/network mutation',()=>{
  const queries=[...FAILED_ISSUE_CAPTURE_PROGRAM.matchAll(/client\.query\(["']([^"']*)/g)].map(m=>m[1]);expect(queries.length).toBeGreaterThan(2);expect(queries.every(q=>/^(SELECT|BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY|ROLLBACK)/.test(q))).toBe(true);
  expect(FAILED_ISSUE_CAPTURE_PROGRAM).not.toMatch(/\bfetch\(|https?\.|\.exec\(|UPDATE |INSERT INTO|DELETE FROM/);
  expect(FAILED_ISSUE_CAPTURE_PROGRAM).toContain("secrets.fingerprint(plan)!==row.plan_hash");expect(FAILED_ISSUE_CAPTURE_PROGRAM).toContain("plan.generated?.key!==key");expect(FAILED_ISSUE_CAPTURE_PROGRAM).toContain("process.stdout.write(JSON.stringify({version:1");
 });
});
