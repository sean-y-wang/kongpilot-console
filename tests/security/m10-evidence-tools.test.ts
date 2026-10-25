import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { m10SecretMaterial, retainedM9ScanMaterial, m10DockerEnvironment } from './lib/m10-release-evidence.mjs';
import { assertM10RequestAuditIdentity, classifyM10AuditRequest, m10MinimalAuditManifest, verifyM10AnalyticalAudit } from './lib/m10-audit-policy.mjs';
import { buildSecretMatcher } from './lib/m9-secret-scan.mjs';

const cid='11111111-1111-4111-8111-111111111111',targetCid='22222222-2222-4222-8222-222222222222',wid='33333333-3333-4333-8333-333333333333',actorId='44444444-4444-4444-8444-444444444444',key='55555555-5555-4555-8555-555555555555';
const sourceKey='SyntheticM10SourceKey!2026',targetKey='SyntheticM10TargetKey!2026';
const harness=()=>({milestone:'M10',cid,targetCid,requests:[],fixtureKeys:{source:sourceKey,target:targetKey},fixtures:{source:{key:sourceKey},target:{key:targetKey}}});
const packet=()=>({method:'POST',path:`/clusters/${cid}/governance/inspections?workspaceId=${wid}`,key,actorId,requestId:'original-request',startedAt:'2026-10-13T00:00:00.000Z',state:'response_observed',status:201,responseData:{id:'66666666-6666-4666-8666-666666666666'},body:{scope:'workspace'}});

describe('M10 actual evidence material provenance',()=>{
 it('does not inherit a different Docker endpoint or TLS context while retaining the ordinary process environment',()=>{
  const source={PATH:'/usr/bin',DOCKER_HOST:'tcp://foreign.invalid:2375',DOCKER_CONTEXT:'foreign',DOCKER_TLS_VERIFY:'1',DOCKER_CERT_PATH:'/foreign'};
  expect(m10DockerEnvironment(source)).toEqual({PATH:'/usr/bin',GOMAXPROCS:'2'});expect(source.DOCKER_CONTEXT).toBe('foreign');
 });
 it('explicitly collects both independent actual fixture key layouts and encodings while omitting only idempotency IDs',()=>{
  const native:any=harness();native.requests=[packet()];const browser={milestone:'M10',requests:[]};
  const result=m10SecretMaterial(native,browser,{},{});expect(result.explicitFixtureKeyCount).toBe(2);
  for(const actual of [sourceKey,targetKey]){expect(result.secrets.find((r:any)=>r.value===actual)?.kinds).toContain('api-key');expect(buildSecretMatcher(result.secrets).scan(Buffer.from(Buffer.from(actual).toString('base64'))).length).toBeGreaterThan(0);}
  expect(result.secrets.some((r:any)=>r.value===key)).toBe(false);
 });
 it('includes failed and unknown request passwords without a blanket rejection exception',()=>{
  const native:any=harness();native.requests=[{...packet(),status:400,body:{password:'SyntheticRejectedPassword!2026'}},{...packet(),state:'response_unknown',status:undefined,body:{password:'SyntheticUnknownPassword!2026'}}];
  const result=m10SecretMaterial(native,{requests:[]},{},{});
  expect(result.secrets.some((r:any)=>r.value==='SyntheticRejectedPassword!2026')).toBe(true);expect(result.secrets.some((r:any)=>r.value==='SyntheticUnknownPassword!2026')).toBe(true);
 });
 it('includes actual browser handoff values even when generic field heuristics would miss their array layout',()=>{
  const native:any=harness();native.browserHandoff={secretValues:['SyntheticBrowserHandoffSecret!2026']};
  expect(m10SecretMaterial(native,{requests:[]},{},{}).secrets.some((r:any)=>r.value==='SyntheticBrowserHandoffSecret!2026')).toBe(true);
 });
 it('refuses to claim two independently issued keys when their actual values are the same',()=>{
  const native:any=harness();native.fixtureKeys.target=sourceKey;native.fixtures.target.key=sourceKey;expect(()=>m10SecretMaterial(native,{requests:[]},{},{})).toThrow();
 });
 const controlled=()=>{
  const candidate='UnitM9ControlledPublicProbe2026',source=`await h.request(admin,path('drafts'),'POST',{payload:{password:'${candidate}'}},{expected:[400]});`,offset=Buffer.byteLength(source.slice(0,source.indexOf(candidate)));
  const original={milestone:'M9',requests:[{...packet(),path:`/clusters/${cid}/drafts`,status:400,errorCode:'DRAFT_SECRET_FORBIDDEN',body:{payload:{password:candidate}}}]};
  const report={passed:true,milestone:'M9',excludedNonCredentialProbes:[{index:0,requestId:'original-request',kind:'controlled-public-noncredential-draft-rejection-probe',sourceLiteralLinked:true,issuedFixtureCredentialMatch:false,originalPacketsChanged:false,genericFailedPasswordExclusion:false,sourcePath:'synthetic-native.mjs',sourceByteOffset:offset,sourceSha256:createHash('sha256').update(source).digest('hex')}]};
  return{candidate,source,original,report};
 };
 it('retains only the previously accepted source-specific controlled probe proof and leaves original bytes intact',()=>{
  const f=controlled(),before=JSON.stringify(f.original),result=retainedM9ScanMaterial(f.original,{requests:[]},{},f.report,f.source,{},harness());
  expect(JSON.stringify(f.original)).toBe(before);expect(result.material.requests[0].body.payload).not.toHaveProperty('password');expect(JSON.stringify(result.evidence)).not.toContain(f.candidate);
 });
 it('refuses the retained legacy exception when the same value is now an actually issued M10 fixture key',()=>{
  const f=controlled();expect(()=>retainedM9ScanMaterial(f.original,{requests:[]},{},f.report,f.source,{}, {credentials:{key:f.candidate}})).toThrow();
 });
 it('refuses a rewritten legacy source or unaccepted provenance report',()=>{
  const f=controlled();expect(()=>retainedM9ScanMaterial(f.original,{requests:[]},{},{...f.report,passed:false},f.source,{},{})).toThrow();
  expect(()=>retainedM9ScanMaterial(f.original,{requests:[]},{},f.report,'// Changed source\n'+f.source,{},{})).toThrow();
 });
});

describe('M10 business audit identity and original-response coverage',()=>{
 const request=()=>({requestId:'original-request',actorId,clusterId:cid,workspaceId:wid,startedAt:'2026-10-13T00:00:00.000Z',category:'governance.inspection',method:'POST',routePath:`/clusters/${cid}/governance/inspections`});
 const row=()=>({request_id:'original-request',actor_id:actorId,actor_type:'user',cluster_id:cid,workspace_id:wid,source_ip:'192.0.2.30',occurred_at:'2026-10-13T00:00:01.000Z',entity_type:'governance_runs',action:'governance.inspection.complete'});
 it('keeps every failed original available to the actual SQL completion audit instead of accepting a completion flag',()=>{
  const native:any=harness();native.requests=[packet(),{...packet(),requestId:'failed-request',status:503,resolution:{knownNativeComplete:true,responseResolved:true}}];
  const manifest=m10MinimalAuditManifest(native,{milestone:'M10',requests:[]},'2026-10-13T00:00:00.000Z');expect(manifest.requests).toHaveLength(1);expect(manifest.attempts).toHaveLength(2);expect(manifest.failedOriginalRequests[0]).toMatchObject({requestId:'failed-request',status:503,originalResponseRewritten:false});expect(manifest.failedOriginalRequests[0]).not.toHaveProperty('resolution');
  expect(JSON.stringify(manifest)).not.toContain('scope":"workspace');expect(JSON.stringify(manifest)).not.toContain('Cookie');
 });
 it('normalizes browser API prefixes and separate query fields without dropping the real workspace',()=>{
  const native:any=harness();native.requests=[packet()];const browser:any={milestone:'M10',requests:[{...packet(),path:`/api/v1/clusters/${cid}/governance/inspections`,query:`?workspaceId=${wid}`} ]};
  expect(m10MinimalAuditManifest(native,browser,'2026-10-13T00:00:00Z').requests[1].workspaceId).toBe(wid);
 });
 it('keeps an expected IDOR denial against a fabricated cluster as a failed attempt without treating it as business success',()=>{
  const native:any=harness();native.requests=[packet(),{...packet(),requestId:'denied-idor',status:403,path:`/clusters/${actorId}/governance/inspections?workspaceId=${wid}`}];
  const manifest=m10MinimalAuditManifest(native,{milestone:'M10',requests:[]},'2026-10-13T00:00:00Z');expect(manifest.requests).toHaveLength(1);expect(manifest.failedOriginalRequests[0]).toMatchObject({clusterId:actorId,status:403});
 });
 it.each(['actor','cluster','workspace','missing-ip'])('has no old milestone exception for a current %s mismatch',kind=>{
  const r:any=row();if(kind==='actor')r.actor_id=targetCid;if(kind==='cluster')r.cluster_id=targetCid;if(kind==='workspace')r.workspace_id=actorId;if(kind==='missing-ip')r.source_ip=null;
  expect(()=>assertM10RequestAuditIdentity(request(),r)).toThrow();
 });
 it('allows target child configuration rows only with an independently verified actual alternate scope',()=>{
  const r:any={...row(),cluster_id:targetCid,workspace_id:actorId,entity_type:'configuration_jobs',action:'configuration.job.complete'},alternate={clusterId:targetCid,workspaceId:actorId};
  expect(()=>assertM10RequestAuditIdentity(request(),r)).toThrow();expect(()=>assertM10RequestAuditIdentity({...request(),category:'governance.promote'},r,alternate)).not.toThrow();
  expect(()=>assertM10RequestAuditIdentity(request(),{...r,action:'governance.inspection.complete'},alternate)).toThrow();
 });
 it('will not allow a global IAM envelope to stand in for the actual cluster business event',()=>{
  const q:any={...request(),category:'cluster.metadata',method:'PATCH',workspaceId:null},r:any={...row(),cluster_id:null,workspace_id:null,entity_type:'clusters',entity_id:cid,action:'iam.write'};
  expect(()=>assertM10RequestAuditIdentity(q,r)).not.toThrow();expect(()=>assertM10RequestAuditIdentity({...q,category:'native'},r)).toThrow();
  expect(()=>assertM10RequestAuditIdentity(q,{...r,entity_id:targetCid})).toThrow();
 });
 it('refuses unclassified business requests or absolute/native API paths',()=>{
  expect(()=>classifyM10AuditRequest({...packet(),path:`/clusters/${cid}/arbitrary-write`})).toThrow();
  expect(()=>classifyM10AuditRequest({...packet(),path:'http://kong:8001/services'})).toThrow();
 });
 const analytical=()=>{
  const original={...request(),category:'governance.comparison',originalKey:key,status:403,sessionId:actorId};
  const run={id:'run',kind:'comparison',state:'succeeded',origin_type:'http',actor_id:actorId,cluster_id:cid,workspace_id:wid,idempotency_key:key,origin_session_id:actorId};
  const record={id:'comparison',run_id:'run',cluster_id:cid,workspace_id:wid};
  const audit={...row(),id:'actual-audit',entity_id:'run',action:'governance.comparison.complete',result:'success',after:{comparisonId:'comparison'}};
  return{original,run,record,audit};
 };
 it('separately verifies an immutable committed comparison without rewriting its original history-projection 403',()=>{
  const f=analytical(),proof=verifyM10AnalyticalAudit(f.original,f.run,f.record,[f.audit]);
  expect(proof).toMatchObject({originalStatus:403,runState:'succeeded',originalResponseRewritten:false,responseResolved:false,nativeExecutionRequested:false,auditId:'actual-audit'});
  expect(f.original.status).toBe(403);
 });
 it.each(['actor','key','session','record','missing-audit','duplicate-audit','wrong-audit-subject'])('does not substitute %s for the actual committed observation/audit',kind=>{
  const f:any=analytical(),audits=[f.audit];if(kind==='actor')f.run.actor_id=targetCid;if(kind==='key')f.run.idempotency_key='foreign-key';if(kind==='session')f.run.origin_session_id=targetCid;
  if(kind==='record')f.record.run_id='foreign-run';if(kind==='missing-audit')audits.length=0;if(kind==='duplicate-audit')audits.push({...f.audit});if(kind==='wrong-audit-subject')f.audit.entity_id='foreign-run';
  expect(()=>verifyM10AnalyticalAudit(f.original,f.run,f.record,audits)).toThrow();
 });
});
