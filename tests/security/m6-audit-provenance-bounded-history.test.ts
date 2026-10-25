import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {auditSecretProvenance,classifyAuditCandidates} from './lib/m6-audit-secret-provenance.mjs';
const marker='[REDACTED:0123456789abcdef]';
const clone=<T,>(value:T):T=>JSON.parse(JSON.stringify(value));
describe('bounded context-aware M6 audit history provenance',()=>{
 it('retains every real candidate through JSON-cloned complete histories exceeding 200000 physical scalar visits',()=>{
  const checkpoint={writeAttempts:[{method:'POST',path:'/safe',state:'response_observed',httpStatus:201,body:{config:{secret:'real-history-secret',unknown:marker,list:['real-array-secret']},tags:['public-a','public-b']},responseData:{key:marker}}],tokens:[{csrfToken:'actual-csrf-token'}],capturedKeys:['actual-private-key']};
  const histories=Array.from({length:12000},()=>clone(checkpoint));
  const result=auditSecretProvenance({secrets:[marker],completeHistories:histories});
  for(const value of ['real-history-secret',marker,'real-array-secret','actual-csrf-token','actual-private-key'])expect(result.actual).toContain(value);
  expect(classifyAuditCandidates([marker],result,[marker]).retained).toEqual([marker]);
 },15000);
 it('does not merge SHA-verified aggregate exemption with the exact same untrusted checkpoint content',()=>{
  const checkpoint={testTag:'old',secrets:[marker],title:'identical history'};
  const sha=createHash('sha256').update(JSON.stringify(checkpoint)).digest('hex');
  const result=auditSecretProvenance({priorFixtureRuns:[{testTag:'old',checkpoint,checkpointSha256:sha}],unknown:{checkpoint:clone(checkpoint)}});
  expect(classifyAuditCandidates([marker],result,[marker]).retained).toEqual([marker]);
 });
 it('keeps identical journal metadata separately from a protected original request key',()=>{
  const attempt={method:'POST',path:'/safe',state:'response_observed',key:marker,body:{},responseData:{}};
  const result=auditSecretProvenance({writeAttempts:[attempt],originalRequest:clone(attempt)});
  expect(result.rawKeys).toContain(marker);expect(classifyAuditCandidates([marker],result,[marker]).retained).toEqual([marker]);
 });
 it('keeps the 200000 semantic budget for genuinely different body values',()=>{
  const values=Array.from({length:200001},(_,i)=>'unique-body-secret-'+i);
  expect(()=>auditSecretProvenance({writeAttempts:[{method:'POST',path:'/safe',state:'before_send',body:{values}}]})).toThrow('Audit provenance traversal budget exceeded');
 },15000);
 it('rejects cycles before provenance traversal without skipping unknown candidates',()=>{
  const cycle:any={password:'protected'};cycle.self=cycle;
  expect(()=>auditSecretProvenance(cycle)).toThrow('Audit provenance cycle rejected');
 });
});
