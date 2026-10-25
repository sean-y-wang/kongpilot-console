import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createContext,runInContext} from 'node:vm';
import ts from 'typescript';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {
 auditSecretProvenance,classifyAuditCandidates,readAuditWithActualMarkerProof,verifyM6AuditCoverage,
} from './lib/m6-audit-secret-provenance.mjs';
import {
 evidenceSha,guardM6ReadonlyVerification,READONLY_CURRENT_GRANTS_SQL,
} from './lib/m6-readonly-verification.mjs';
import {
 captureHistoricalKeyCipherBeforeRetirement,expectedHistoricalKeyCipher,HISTORICAL_KEY_CIPHER_SQL,
} from './lib/m6-retired-lifecycle-continuation.mjs';
import {PENDING_KEY_TUPLE as FIRST} from './lib/m6-pending-key-capture.mjs';
import {FAILED_ISSUE_TUPLE as T} from './lib/m6-failed-issue-key-capture.mjs';
import {checkpointSha} from './lib/m6-isolated-transition.mjs';
import {verifyM6RuntimeLogs} from './lib/m6-runtime-logs.mjs';
import {M6_C1,M6_C2} from './lib/m6-harness.mjs';

const subprocess=vi.hoisted(()=>({execFileSync:vi.fn(),spawnSync:vi.fn()}));
vi.mock('node:child_process',()=>subprocess);
const raw='IndependentSyntheticCredentialSource2026';
const unknownRaw='IndependentUnknownCredentialSource2026';
let marker:string,environment:NodeJS.ProcessEnv;
const post=(body:any={},responseData:any={})=>({
 method:'POST',path:'/api/v1/portal/credentials/example/reveal',state:'response_observed',httpStatus:201,body,responseData,
});
const failClosed=(v:unknown,_id?:string,message?:string)=>{if(!v)throw Error(message??'guard rejected');};
beforeEach(()=>{
 environment={...process.env};
 process.env.CONSOLE_ENCRYPTION_KEY='67'.repeat(32);
 delete process.env.AUTH_PROVIDERS_JSON;
 marker=new SecretService().redact({key:raw}).key;
 subprocess.execFileSync.mockReset();subprocess.spawnSync.mockReset();
});
afterEach(()=>{
 for(const name of Object.keys(process.env))if(!(name in environment))delete process.env[name];
 Object.assign(process.env,environment);
});

describe('independent canonical-mask provenance boundaries',()=>{
 it('protects raw body strings even under a client-controlled HTTP-shaped object',()=>{
  const r={grants:[{apiKey:raw}],writeAttempts:[post({nested:{method:'GET',path:'/pretend',state:'response_observed',config:{jwt_key:marker,client_key:marker,items:[marker]}}})]};
  expect(classifyAuditCandidates([marker],auditSecretProvenance(r),[marker]).retained).toEqual([marker]);
 });
 it('protects nested raw body secrets arrays rather than treating them as harness aggregates',()=>{
  const r={grants:[{apiKey:raw}],writeAttempts:[post({config:{secrets:[marker]}})]};
  expect(classifyAuditCandidates([marker],auditSecretProvenance(r),[marker]).retained).toEqual([marker]);
 });
 it.each(['POST','PATCH','PUT','DELETE'])('retains every opaque %s raw-body string',method=>{
  const r={grants:[{apiKey:raw}],writeAttempts:[{...post({custom:[{arbitraryName:marker}]}),method}]};
  expect(classifyAuditCandidates([marker],auditSecretProvenance(r),[marker]).retained).toEqual([marker]);
 });
 it.each(['originalRequest','originalExecution'])('protects an unlinked %s private .key',owner=>{
  const r={grants:[{apiKey:raw}],[owner]:{key:marker}};
  expect(classifyAuditCandidates([marker],auditSecretProvenance(r),[marker]).retained).toEqual([marker]);
 });
 it('does not let a response observation invent a journal link to exempt an actual private Key',()=>{
  const r={grants:[{apiKey:raw}],originalRequest:{key:marker},observation:{writeAttempts:[{...post(),key:marker}]}};
  expect(classifyAuditCandidates([marker],auditSecretProvenance(r),[marker]).retained).toEqual([marker]);
 });
 it('never treats an arbitrary checkpoint.secrets array as trusted mixed history',()=>{
  const r={grants:[{apiKey:raw}],observation:{checkpoint:{secrets:[marker]}}};
  expect(classifyAuditCandidates([marker],auditSecretProvenance(r),[marker]).retained).toEqual([marker]);
 });
 it('permits mixed aggregates only in the root and SHA-verified immutable history',()=>{
  const prior={testTag:'m6-isolated-independent-old',secrets:[marker],grants:[{apiKey:raw}]};
  const r={secrets:[marker],priorFixtureRuns:[{testTag:prior.testTag,checkpoint:prior,checkpointSha256:checkpointSha(prior)}]};
  const p=auditSecretProvenance(r);expect(p.rawKeys).toContain(raw);
  expect(classifyAuditCandidates([marker],p,[marker]).excluded).toEqual([marker]);
  r.priorFixtureRuns[0].checkpoint.secrets.push('changed');
  expect(()=>auditSecretProvenance(r)).toThrow('SHA changed');
 });
 it('keeps original request metadata conservative even when it matches a journal key',()=>{
  const key=randomUUID(),r={originalRequest:{key},writeAttempts:[{...post(),key}],privateCredential:{key:marker},grants:[{apiKey:raw}]};
  const provenance=auditSecretProvenance(r);
  expect(provenance.actual).toContain(key);
  expect(classifyAuditCandidates([marker,key],provenance,[marker]).retained).toEqual([marker,key]);
 });
 it.each([
  ['revealed Key',()=>({writeAttempts:[post({}, {key:marker})]})],
  ['private Key',()=>({opaquePrivateCredential:{key:marker}})],
  ['JWT token',()=>({session:{accessToken:marker}})],
  ['cookie',()=>({cookie:'kongos_portal_access='+marker+'; kongos_portal_csrf='+marker})],
  ['captured Key',()=>({capturedKeys:[marker]})],
  ['API Key',()=>({application:{apiKey:marker}})],
 ])('never excludes marker-shaped actual %s',(_name,reference)=>{
  const r={grants:[{apiKey:raw}],...reference()};
  expect(classifyAuditCandidates([marker],auditSecretProvenance(r),[marker]).retained).toEqual([marker]);
 });
 it('retains unknown masks, UUID credentials and noncanonical lookalikes',()=>{
  const unknown=new SecretService().redact({key:unknownRaw}).key,uuid=randomUUID();
  const candidates=[unknown,uuid,marker.toUpperCase(),'[REDACTED]'];
  expect(classifyAuditCandidates(candidates,auditSecretProvenance({grants:[{apiKey:raw}]}),[marker,...candidates.slice(1)]).retained).toEqual(candidates);
 });
 it('only removes an actual source-class HMAC match and preserves the complete scanner candidate history',()=>{
  const r={secrets:[raw,marker],grants:[{apiKey:raw}],writeAttempts:[{...post(),path:'/api/v1/recycle-preview',responseData:{key:marker}}]};
  const before=evidenceSha(r),p=auditSecretProvenance(r);
  expect(classifyAuditCandidates(r.secrets,p,[]).excluded).toEqual([]);
  expect(classifyAuditCandidates(r.secrets,p,p.rawKeys.map(key=>new SecretService().redact({key}).key))).toEqual({retained:[raw],excluded:[marker]});
  expect(evidenceSha(r)).toBe(before);
 });
});

function auditHarness(){return{
 secrets:[raw,marker],referenceData:{grants:[{apiKey:raw}],secrets:[raw,marker]},
 successfulWrites:[{method:'POST',path:'/safe',requestId:'independent-request'}],public:{},check:failClosed,
};}
describe('actual audit verifier safeguards beyond candidate shape',()=>{
 it.each(['SMTP_PASSWORD','LDAP_BIND_PASSWORD'])('retains canonical-looking %s through the actual verification entry',name=>{
  process.env[name]=marker;const h=auditHarness();
  expect(()=>verifyM6AuditCoverage(h,()=>({rows:[{request_id:'independent-request',after:{opaque:marker},json_patch:[]}],verifiedMarkers:[marker]}))).toThrow();
 });
 it.each(['client_secret','bind_password'])('retains optional provider %s through the actual verification entry',field=>{
  process.env.AUTH_PROVIDERS_JSON=JSON.stringify([{id:'synthetic-provider',type:field==='client_secret'?'oidc':'ldap',[field]:marker}]);
  expect(()=>verifyM6AuditCoverage(auditHarness(),()=>({rows:[{request_id:'independent-request',after:{opaque:marker},json_patch:[]}],verifiedMarkers:[marker]}))).toThrow();
 });
 it('does not use a valid marker proof to cover a missing correlated audit record',()=>{
  expect(()=>verifyM6AuditCoverage(auditHarness(),()=>({rows:[],verifiedMarkers:[marker]}))).toThrow();
 });
 it('keeps genuine plaintext detection and never changes scanner secrets',()=>{
  const h=auditHarness(),before=[...h.secrets];
  expect(()=>verifyM6AuditCoverage(h,()=>({rows:[{request_id:'independent-request',after:{key:raw},json_patch:[]}],verifiedMarkers:[marker]}))).toThrow();
  expect(h.secrets).toEqual(before);
 });
 it('publishes counts alone after a proven safe-mask comparison',()=>{
  const h=auditHarness();verifyM6AuditCoverage(h,()=>({rows:[{request_id:'independent-request',after:{key:marker},json_patch:[]}],verifiedMarkers:[marker]}));
  expect(JSON.stringify(h.public)).not.toContain(marker);expect(JSON.stringify(h.public)).not.toContain(raw);
  expect(h.secrets).toEqual([raw,marker]);expect(h.public.auditSecretClassification.excludedProvenFingerprintMarkers).toBe(1);
 });
});

describe('actual fixed audit-reader program with in-memory dependencies',()=>{
 it('sends keys by stdin only and computes masks using the real SecretService class inside a read-only transaction',async()=>{
  subprocess.execFileSync.mockReturnValue(JSON.stringify({rows:[],verifiedMarkers:[]}));
  const provenance=auditSecretProvenance({grants:[{apiKey:raw}]});
  readAuditWithActualMarkerProof(['independent-request'],[marker],provenance);
  const [command,args,options]=subprocess.execFileSync.mock.calls[0];
  expect(command).toBe('docker');expect(args.slice(0,6)).toEqual(['compose','exec','-T','console-api','node','-e']);
  expect(args.join(' ')).not.toContain(raw);expect(JSON.parse(options.input).rawKeys).toEqual([raw]);
  const handlers:any={},queries:any[]=[],writes:string[]=[],release=vi.fn(),end=vi.fn();
  const client={query:vi.fn(async(sql:string,values?:any)=>{queries.push({sql,values});return{rows:sql.startsWith('SELECT')?[{request_id:'independent-request',json_patch:[]}]:[]};}),release};
  const processFake:any={env:{DATABASE_URL:'postgres://synthetic.invalid/unused'},stdin:{on(name:string,fn:any){handlers[name]=fn;}},stdout:{write(value:string){writes.push(value);}}};
  runInContext(args[6],createContext({process:processFake,require(name:string){
   if(name==='pg')return{Pool:class{connect=async()=>client;end=end;}};
   if(name==='./dist/infrastructure/secret.service.js')return{SecretService};
   throw Error('Unexpected module');
  }}));
  handlers.data(options.input);await handlers.end();
  expect(queries.map(q=>q.sql)).toEqual(['BEGIN READ ONLY','SELECT request_id,before,after,json_patch FROM audit_events WHERE request_id=ANY($1::text[])','ROLLBACK']);
  expect(queries[1].values).toEqual([['independent-request']]);
  expect(JSON.parse(writes.join('')).verifiedMarkers).toEqual([marker]);
  expect(writes.join('')).not.toContain(raw);expect(release).toHaveBeenCalledOnce();expect(end).toHaveBeenCalledOnce();
 });
 it('suppresses stdout/stderr raw database failures instead of disclosing secret-rich error text',()=>{
  subprocess.execFileSync.mockImplementation(()=>{throw Object.assign(Error(raw),{stderr:raw,stdout:marker});});
  expect(()=>readAuditWithActualMarkerProof(['id'],[marker],{actual:[raw],rawKeys:[raw]})).toThrow('private details withheld');
 });
});

function completedCheckpoint(){
 const tag='m6-isolated-independent-readonly',pub=randomUUID(),cid=T.clusterId,wid=T.workspaceId;
 const grants=Array.from({length:6},(_,i)=>({grant:{id:i?randomUUID():FIRST.grantId,publicationId:pub},credential:{id:i?randomUUID():FIRST.credentialId,generation:1},managed:{consumer_id:randomUUID(),acl_id:randomUUID(),kong_id:randomUUID()},apiKey:'InventedIndependentReadonlyKey'+i}));
 const r:any={testTag:tag,phase:'HTTP-complete',grants,fixtures:[{cluster:{id:cid},workspace:{id:wid,code:tag+'-a'},publications:[{id:pub}]},...['b','c'].map(s=>({cluster:{id:randomUUID()},workspace:{id:randomUUID(),code:tag+'-'+s},publications:[]}))],portalUsers:[{},{},{}],writeAttempts:[{method:'POST',path:'/api/v1/portal/example',key:randomUUID(),state:'response_observed'}],writeEvidence:[{requestId:'independent-completed-request',method:'POST',path:'/safe'}],secrets:grants.map(g=>g.apiKey),browser:{clusterId:cid,workspaceId:wid,activeGrantId:grants[1].grant.id,activeCredentialId:grants[1].credential.id},retiredLifecycleContinuation:{phase:'tail-actions-started'},abandonmentAcknowledgment:{phase:'certificate-verified',totalFormalPosts:2},metadataRecovery:{phase:'metadata-succeeded-original-execution'},failedIssueContinuation:{before:{cipher_sha:'c'.repeat(64)}}};
 const report:any={testTag:tag,passed:1012,failed:1,checks:[{id:'GATE',passed:false,name:'Audit/M4: current fixture audit before/after/patch contain no known password, token or gateway credential'}],auditCoverage:{distinctRequestIds:145,auditedRequestIds:145,missing:[]},fixturesForBrowser:{...r.browser},canonicalClusters:[]};
 const pin:any={writeAttemptsSha256:evidenceSha(r.writeAttempts),writeEvidenceSha256:evidenceSha(r.writeEvidence),grantsSha256:evidenceSha(r.grants),acknowledgmentSha256:checkpointSha(r.abandonmentAcknowledgment),metadataRecoverySha256:checkpointSha(r.metadataRecovery)};
 const rows=grants.map((g,i)=>({id:g.grant.id,credential_id:g.credential.id,cluster_id:cid,workspace_id:wid,consumer_id:g.managed.consumer_id,acl_id:g.managed.acl_id,kong_id:g.managed.kong_id,state:i?'active':'revoked',credential_state:i?'active':'revoked',current_generation:i?1:2,generation:1,current_credential_id:i?g.credential.id:randomUUID()}));
 const old:any={grant_state:'disabled',current_generation:0,current_credential_id:null,reservation_released_at:'2026-10-11T00:00:00.000Z',certificates:1,credential_state:'pending',generation:1,credential_ref_id:null,last_revealed_at:null,native_operation_count:1,unexpected_native_results:0,credential_refs:0,native_unresolved:0,portal_unresolved:0,cipher_sha:'c'.repeat(64),workflow_state:'failed',execution_state:'failed'};
 const h:any={referenceData:r,requireLive:vi.fn(),check:failClosed,public:{},consoleRead:vi.fn((sql:string)=>sql===READONLY_CURRENT_GRANTS_SQL?rows:[old]),request:vi.fn(()=>{throw Error('HTTP forbidden');}),portal:vi.fn(()=>{throw Error('Portal forbidden');}),saveReference:vi.fn(()=>{throw Error('Reference write forbidden');})};
 return{r,report,pin,rows,old,h};
}
describe('read-only finishing preserves failed and completed histories',()=>{
 it('reads exactly six current identities and the closed failed certificate without any replay or journal write',()=>{
  const f=completedCheckpoint(),before=evidenceSha(f.r);guardM6ReadonlyVerification(f.h,{report:f.report,pin:f.pin});
  expect(f.h.consoleRead).toHaveBeenCalledTimes(2);expect(f.h.consoleRead.mock.calls.every(([sql]:any[])=>sql.startsWith('SELECT'))).toBe(true);
  expect(evidenceSha(f.r)).toBe(before);expect(f.h.request).not.toHaveBeenCalled();expect(f.h.portal).not.toHaveBeenCalled();expect(f.h.saveReference).not.toHaveBeenCalled();
 });
 it.each([
  ['old idempotency key',(f:any)=>f.r.writeAttempts[0].key=randomUUID()],
  ['successful request ID',(f:any)=>f.r.writeEvidence[0].requestId='replacement'],
  ['extra acknowledgment',(f:any)=>f.r.abandonmentAcknowledgment.totalFormalPosts=3],
  ['changed completed Key',(f:any)=>f.r.grants[1].apiKey='replacement'],
 ])('rejects changed %s before even a SELECT',(_name,change)=>{
  const f=completedCheckpoint();change(f);expect(()=>guardM6ReadonlyVerification(f.h,{report:f.report,pin:f.pin})).toThrow();
  expect(f.h.consoleRead).not.toHaveBeenCalled();expect(f.h.request).not.toHaveBeenCalled();
 });
 it.each([
  ['first retired grant revived',(f:any)=>f.rows[0].state='active'],
  ['fresh active credential swapped',(f:any)=>f.rows[2].current_credential_id=randomUUID()],
  ['original failed Key changed',(f:any)=>f.old.cipher_sha='a'.repeat(64)],
  ['new unresolved packet',(f:any)=>f.old.native_unresolved=1],
  ['certificate missing',(f:any)=>f.old.certificates=0],
 ])('stops on %s with no repair/rearm fallback',(_name,change)=>{
  const f=completedCheckpoint();change(f);expect(()=>guardM6ReadonlyVerification(f.h,{report:f.report,pin:f.pin})).toThrow();
  expect(f.h.request).not.toHaveBeenCalled();expect(f.h.portal).not.toHaveBeenCalled();expect(f.h.saveReference).not.toHaveBeenCalled();
 });
 it('executes the actual finishing runner only with fake read-only dependencies and never writes the original failure or reference',()=>{
  const f=completedCheckpoint(),before=Buffer.from(JSON.stringify(f.r)),writes:any[]=[],referencePath='/synthetic/private-reference',calls:string[]=[];
  f.pin.privateReferenceSha256=createHash('sha256').update(before).digest('hex');
  const source=readFileSync('tests/security/finish-m6-readonly-verification.mjs','utf8');
  const code=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
  f.h.checks=[];f.h.secrets=f.r.secrets;f.h.verifyAuditCoverage=()=>calls.push('audit');f.h.verifyAppendOnlyStorage=()=>calls.push('append-only');
  const modules:any={
   'node:fs':{readFileSync(path:string){if(path===referencePath)return before;if(path.endsWith('security-live-pre-fix-retired-lifecycle-audit.json'))return JSON.stringify(f.report);if(path.endsWith('readonly-verification-reference-guard.json'))return JSON.stringify(f.pin);throw Error('Unexpected file');},writeFileSync(path:string,data:string){writes.push({path,data});}},
   'node:crypto':{createHash},'./lib/m6-harness.mjs':{M6Harness:class{constructor(){return f.h;}},M6_REFERENCE:referencePath},
   './lib/m6-readonly-verification.mjs':{guardM6ReadonlyVerification},'./lib/m6-runtime-logs.mjs':{verifyM6RuntimeLogs(){calls.push('logs');return{allPassed:true};}},'./check-artifacts.mjs':{findSecretArtifacts(values:string[]){expect(values).toEqual(expect.arrayContaining(f.r.secrets));return{leaks:[]};}},
  };
  const processFake:any={env:{M6_DEPLOYMENT_READY:'true',M6_READONLY_VERIFICATION_READY:'true'}};
  runInContext(code,createContext({exports:{},require(name:string){if(!modules[name])throw Error('Unexpected import');return modules[name];},Buffer,process:processFake,console:{log:vi.fn()}}));
  expect(processFake.exitCode).toBe(0);expect(calls).toEqual(['audit','append-only','logs']);
  expect(writes.map(w=>w.path)).toEqual(['artifacts/M6/security-live.json','artifacts/M6/http-secret-artifact-scan.json']);
  expect(writes.every(w=>!w.path.includes('pre-fix')&&w.path!==referencePath)).toBe(true);
  expect(f.h.request).not.toHaveBeenCalled();expect(f.h.portal).not.toHaveBeenCalled();expect(f.h.saveReference).not.toHaveBeenCalled();
 });
});

describe('independent fresh-run original cipher proof',()=>{
 it('captures the exact active pre-rotation tuple without requiring historical metadata recovery',()=>{
  const primary={cluster:{id:randomUUID()},workspace:{id:randomUUID()}},a={grant:{id:randomUUID()},credential:{id:randomUUID(),generation:1},managed:{consumer_id:randomUUID(),kong_id:randomUUID()}};
  const row:any={id:a.credential.id,grant_id:a.grant.id,cluster_id:primary.cluster.id,workspace_id:primary.workspace.id,consumer_id:a.managed.consumer_id,kong_id:a.managed.kong_id,state:'active',generation:1,grant_state:'active',current_credential_id:a.credential.id,cipher_sha:'a'.repeat(64)};
  const h:any={referenceData:{},check:failClosed,consoleRead:vi.fn(()=>[row]),saveReference:vi.fn(extra=>Object.assign(h.referenceData,extra))};
  const proof=captureHistoricalKeyCipherBeforeRetirement(h,{primary,a},a);
  expect(h.consoleRead).toHaveBeenCalledWith(HISTORICAL_KEY_CIPHER_SQL,[primary.cluster.id,primary.workspace.id,a.grant.id,a.credential.id,a.managed.consumer_id,a.managed.kong_id]);
  expect(expectedHistoricalKeyCipher(h,{primary,a})).toBe(proof.cipherSha256);expect(h.referenceData.metadataRecovery).toBeUndefined();
  primary.workspace.id=randomUUID();expect(()=>expectedHistoricalKeyCipher(h,{primary,a})).toThrow();
  expect(()=>captureHistoricalKeyCipherBeforeRetirement(h,{primary,a},a)).toThrow();expect(h.saveReference).toHaveBeenCalledOnce();
 });
});

function logHarness(){
 const calls:string[]=[],ids=new Map<string,string>(),primary={id:randomUUID(),adminUrl:'http://kong-portal-admin-endpoint:8001',proxyOrigin:'http://127.0.0.1:10000'};
 subprocess.execFileSync.mockImplementation((_command,args)=>{
  if(args[0]==='compose')return'a'.repeat(64);
  if(args[0]==='inspect')return'independent_kongos';
  const label=args.find((arg:string)=>arg.startsWith('label=com.docker.compose.service='));
  const service=label.split('=')[2],id=createHash('sha256').update(service).digest('hex');calls.push(service);ids.set(service,id);return id;
 });
 subprocess.spawnSync.mockReturnValue({status:0,stdout:'safe access',stderr:'safe structured error'});
 return{calls,ids,h:{secrets:[raw],referenceData:{liveStartedAt:'2026-10-11T00:00:00.000Z',tokens:[],portalTestTargets:{primary}},requireLive:vi.fn(),check:failClosed}};
}
describe('current isolated gateway log coverage retains original services',()=>{
 it('covers all seven fixed services with no caller-selected service or raw-log evidence',()=>{
  const{h,calls}=logHarness(),report=verifyM6RuntimeLogs(h);
  expect(new Set(calls)).toEqual(new Set(['kong','kong-secondary','kong-portal','console-api','console-web','portal-web','telemetry-collector']));
  expect(subprocess.spawnSync).toHaveBeenCalledTimes(7);expect(report.allPassed).toBe(true);expect(report.rawLogsPublished).toBe(false);
  expect(JSON.stringify(report)).not.toContain(raw);expect(JSON.stringify(report)).not.toContain('safe structured error');
 });
 it('detects a credential appearing only on stderr of the isolated gateway without publishing it',()=>{
  const{h,ids}=logHarness();
  subprocess.spawnSync.mockImplementation((_command,args)=>({status:0,stdout:'safe',stderr:args.at(-1)===ids.get('kong-portal')?'prefix '+raw:''}));
  let caught:Error|undefined;try{verifyM6RuntimeLogs(h);}catch(error){caught=error as Error;}
  expect(caught).toBeDefined();expect(caught!.message).not.toContain(raw);
 });
 it.each([
  ['canonical first cluster',(p:any)=>p.id=M6_C1],['canonical second cluster',(p:any)=>p.id=M6_C2],
  ['foreign endpoint',(p:any)=>p.adminUrl='http://foreign.invalid:8001'],['foreign proxy',(p:any)=>p.proxyOrigin='http://127.0.0.1:9000'],
 ])('rejects %s before any log collection',(_name,change)=>{
  const{h}=logHarness();change(h.referenceData.portalTestTargets.primary);
  expect(()=>verifyM6RuntimeLogs(h)).toThrow();expect(subprocess.spawnSync).not.toHaveBeenCalled();
 });
 it('does not mistake failed log transport for a clean credential scan',()=>{
  const{h}=logHarness();subprocess.spawnSync.mockReturnValue({status:1,stdout:'',stderr:'transport '+raw});
  let caught:Error|undefined;try{verifyM6RuntimeLogs(h);}catch(error){caught=error as Error;}
  expect(caught!.message).toContain('raw diagnostic withheld');expect(caught!.message).not.toContain(raw);
 });
});
