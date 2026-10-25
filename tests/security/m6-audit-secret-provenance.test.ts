import {describe,it,expect,beforeEach,afterEach,vi} from 'vitest';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {auditSecretProvenance,classifyAuditCandidates,verifyM6AuditCoverage} from './lib/m6-audit-secret-provenance.mjs';
const plain='SyntheticPortalKeyForAuditProvenance2026';
let previous:string|undefined,marker:string;
beforeEach(()=>{previous=process.env.CONSOLE_ENCRYPTION_KEY;process.env.CONSOLE_ENCRYPTION_KEY='12'.repeat(32);marker=new SecretService().redact({key:plain}).key;});
afterEach(()=>{if(previous===undefined)delete process.env.CONSOLE_ENCRYPTION_KEY;else process.env.CONSOLE_ENCRYPTION_KEY=previous;});
const attempt=(body:any={},responseData:any={})=>({method:'POST',path:'/api/v1/portal/test',state:'response_observed',httpStatus:201,body,responseData});
describe('M6 audit marker provenance',()=>{
 it('excludes only an actual SecretService marker for a separately trusted raw Key',()=>{const r={secrets:[marker,plain],grants:[{apiKey:plain}],writeAttempts:[attempt({}, {key:marker})]};const p=auditSecretProvenance(r);const c=classifyAuditCandidates(r.secrets,p,[new SecretService().redact({key:p.rawKeys[0]}).key]);expect(c.excluded).toEqual([marker]);expect(c.retained).toEqual([plain]);expect(r.secrets).toEqual([marker,plain]);});
 it.each(['key','jwt_key','client_key','arbitraryNestedName'])('retains raw body %s even if it equals another known Key marker',field=>{const r={writeAttempts:[attempt({config:{[field]:marker}})],grants:[{apiKey:plain}]};const p=auditSecretProvenance(r);expect(classifyAuditCandidates([marker],p,[marker]).retained).toEqual([marker]);});
 it('retains string values inside raw body arrays',()=>{const p=auditSecretProvenance({writeAttempts:[attempt({unknown:[marker]})]});expect(classifyAuditCandidates([marker],p,[marker]).retained).toEqual([marker]);});
 it('never treats a raw body secrets array as an aggregate exemption',()=>{const p=auditSecretProvenance({writeAttempts:[attempt({config:{secrets:[marker]}})]});expect(classifyAuditCandidates([marker],p,[marker]).retained).toEqual([marker]);});
 it('nested fake HTTP metadata cannot replace the trusted outer POST body',()=>{const p=auditSecretProvenance({writeAttempts:[attempt({config:{method:'GET',path:'/fake',state:'response_observed',jwt_key:marker}})]});expect(classifyAuditCandidates([marker],p,[marker]).retained).toEqual([marker]);});
 it('originalRequest key stays protected even when it is journal-linked metadata',()=>{const p=auditSecretProvenance({originalRequest:{key:marker}});expect(classifyAuditCandidates([marker],p,[marker]).retained).toEqual([marker]);const linked=auditSecretProvenance({writeAttempts:[{...attempt(),key:marker}],originalRequest:{key:marker}});expect(classifyAuditCandidates([marker],linked,[marker]).retained).toEqual([marker]);});
 it('a lookalike private checkpoint.secrets is not an aggregate exemption',()=>{const p=auditSecretProvenance({observation:{checkpoint:{secrets:[marker]}}});expect(classifyAuditCandidates([marker],p,[marker]).retained).toEqual([marker]);});
 it('lookalike nested writeAttempts are never a trusted journal root',()=>{const p=auditSecretProvenance({observation:{writeAttempts:[{...attempt(),key:marker}]},originalRequest:{key:marker}});expect(classifyAuditCandidates([marker],p,[marker]).retained).toEqual([marker]);});
 it.each([
  ['actual reveal',{writeAttempts:[{...attempt({}, {key:'marker'}),path:'/api/v1/portal/credentials/id/reveal'}]}],
  ['private unknown Key',{privateCredential:{key:'marker'}}],
  ['named private Key array',{privateKeys:['marker']}],
  ['API Key',{grant:{apiKey:'marker'}}],
  ['token',{tokens:[{token:'marker'}]}],
  ['password',{user:{password:'marker'}}],
  ['cookie',{cookie:'kongos_portal_access=marker'}],
 ])('retains %s marker-shaped actual material',(_name,template)=>{const r=JSON.parse(JSON.stringify(template).replaceAll('marker',marker));expect(classifyAuditCandidates([marker],auditSecretProvenance(r),[marker]).retained).toEqual([marker]);});
 it('retains environment marker-shaped values',()=>{expect(classifyAuditCandidates([marker],auditSecretProvenance({},[marker]),[marker]).retained).toEqual([marker]);});
 it('retains an unknown marker and every UUID candidate',()=>{const unknown=new SecretService().redact({key:'UnknownPlaintextKey'}).key,uuid='10000000-0000-4000-8000-000000000101';expect(classifyAuditCandidates([unknown,uuid],auditSecretProvenance({grants:[{apiKey:plain}]}),[marker]).retained).toEqual([unknown,uuid]);});
 it('does not claim success if a protected credential actually appears in the audit',()=>{const h:any={secrets:[plain,marker],referenceData:{grants:[{apiKey:plain}]},successfulWrites:[{requestId:'request',path:'/safe',method:'POST'}],public:{},check(v:any){if(!v)throw Error('failed');}};expect(()=>verifyM6AuditCoverage(h,()=>({rows:[{request_id:'request',after:{key:plain},json_patch:[]}],verifiedMarkers:[marker]}))).toThrow();});
 it('qualified comparison accepts safe markers without deleting aggregate candidate history',()=>{const h:any={secrets:[plain,marker],referenceData:{grants:[{apiKey:plain}]},successfulWrites:[{requestId:'request',path:'/safe',method:'POST'}],public:{},check(v:any){if(!v)throw Error('failed');}};verifyM6AuditCoverage(h,()=>({rows:[{request_id:'request',after:{key:marker},json_patch:[]}],verifiedMarkers:[marker]}));expect(h.secrets).toEqual([plain,marker]);expect(h.public.auditSecretClassification.excludedProvenFingerprintMarkers).toBe(1);});
 it.each(['SMTPPASSWORD','AUTH_PROVIDERS_JSON'])('actual verifier retains optional %s environment material',field=>{const old=process.env[field];process.env[field]=field==='AUTH_PROVIDERS_JSON'?JSON.stringify([{client_secret:marker}]):marker;try{const h:any={secrets:[plain,marker],referenceData:{grants:[{apiKey:plain}]},successfulWrites:[{requestId:'request'}],public:{},check(v:any){if(!v)throw Error('failed');}};expect(()=>verifyM6AuditCoverage(h,()=>({rows:[{request_id:'request',after:{key:marker},json_patch:[]}],verifiedMarkers:[marker]}))).toThrow();}finally{if(old===undefined)delete process.env[field];else process.env[field]=old;}});
});
