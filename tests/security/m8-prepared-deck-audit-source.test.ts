// @ts-nocheck -- actual ESM predicates/helper, synthetic RAM responses only.
import {beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import jsonPatch from 'fast-json-patch';
const seals=vi.hoisted(()=>new Map());
vi.mock('./lib/m8-harness.mjs',async actual=>{const module=await actual();return{...module,sha256:value=>seals.get(typeof value==='string'?value:value.toString())??module.sha256(value)};});
import {sha256} from './lib/m8-harness.mjs';
import {M8_DECK_WIRE_BODY_CONTINUATION as c,isM8ProvenPreparedDeckClosurePacket} from './lib/m8-deck-wire-body-continuation.mjs';
import {m8AllWritesAuditAcceptance} from './lib/m8-audit-acceptance.mjs';
beforeEach(()=>seals.clear());
const check=(value,name)=>{if(!value)throw Error(name);};

/** Only an exact synthetic prefix substitutes a pinned historical digest.
 * Neither archived packets/files nor a current runtime are opened. */
function fixture(){
 const body={revision:2,executionId:c.executionId,executionRevision:1,planRevision:1,planHash:c.planHash,leaseGeneration:1,
  workflowExecutionId:null,confirmed:true,confirm_name:`abandon:${c.jobId}`};
 const intent={...body,jobId:c.jobId,confirmationName:body.confirm_name};
 const closed={domain:'configuration',durable:true,idempotencyKey:c.key,id:c.jobId,jobId:c.jobId,actorId:c.actorId,clusterId:c.cid,workspaceId:c.wid,
  kind:'apply',state:'uncertain',revision:3,workflowId:null,planId:c.executionPlanId,planRevision:1,planHash:c.planHash,
  executionId:c.executionId,executionRevision:2,workflowExecutionId:null,leaseGeneration:1,completedSteps:0,unresolvedSteps:1,
  abandoned:true,terminalFailureRecorded:true,executionCompleted:true,abandonmentSessionMatches:true,abandonRequestId:c.closeRequestId};
 const packet={index:146,method:'POST',path:`/api/v1/clusters/${c.cid}/configuration/jobs/${c.jobId}/abandon`,query:`?workspaceId=${c.wid}`,
  key:c.closeKey,actorId:c.actorId,sessionId:c.sid,clusterId:c.cid,workspaceId:c.wid,state:'response_observed',status:201,requestId:c.closeRequestId,
  body,bodySha256:sha256(JSON.stringify(body)),headers:{Cookie:'kongos_access=SOURCE_ONLY_SYNTHETIC_COOKIE','X-CSRF-Token':'SOURCE_ONLY_SYNTHETIC_CSRF','X-Idempotency-Key':c.closeKey},
  responseData:{jobId:c.jobId,executionId:c.executionId,state:'uncertain',completedSteps:0,unresolvedSteps:1,abandoned:true,originalWorkflowUnchanged:true,originalNativeReceiptsUnchanged:true}};
 const prefix=Array.from({length:145},(_,index)=>({index,synthetic:true,method:'POST',path:'/api/v1/synthetic-original-denied',state:'response_observed',status:403}));
 prefix[144]={index:144,method:'POST',path:`/api/v1/clusters/${c.cid}/configuration/plans/${c.sourcePlanId}/apply`,query:`?workspaceId=${c.wid}`,
  key:c.key,actorId:c.actorId,sessionId:c.sid,clusterId:c.cid,workspaceId:c.wid,state:'response_observed',status:201,requestId:c.requestId,
  responseData:{jobId:c.jobId,kind:'apply',state:'running',executionCompleted:false,workflowId:null,driver:'deck'}};
 seals.set(JSON.stringify(prefix),c.prefix);
 const deniedMaintenance={index:145,method:'POST',path:'/api/v1/synthetic-denied-maintenance',state:'response_observed',status:403};
 const r={requests:[...prefix,deniedMaintenance,packet],scopes:{direct:{cid:c.cid,wid:c.wid}},fixtures:[],inFlight:null,
  deckWireBodyContinuation:{state:'prepared-original-closed',originalPacketCount:145,originalPrefixSha256:c.prefix,
   originalPendingStep:{id:c.jobStepId,state:'pending',operationId:null},originalCurrentService:{id:c.serviceId,retries:0},
   originalClosure:{preparedNotIssued:true,nativeSuccessClaimed:false},
   abandonAttempt:{state:'completed',index:146,key:c.closeKey,requestId:c.closeRequestId,packetSha256:sha256(JSON.stringify(packet)),
    body,bodySha256:packet.bodySha256,intent,originalJob:closed}}};
 const before={jobId:c.jobId,executionId:c.executionId,state:'running',revision:2,executionRevision:1},after={...before,state:'uncertain',revision:3,executionRevision:2,
  planRevision:1,planHash:c.planHash,leaseGeneration:1,completedSteps:0,unresolvedSteps:1,abandoned:true};
 const view={id:randomUUID(),actorId:c.actorId,clusterId:c.cid,workspaceId:c.wid,requestId:c.closeRequestId,workflowId:null,scopeQuality:'verified',
  entityType:'configuration_jobs',entityId:c.jobId,action:'configuration.execution.abandon',result:'uncertain',before,after,jsonPatch:jsonPatch.compare(before,after)};
 const requestedAfter={id:c.jobId,kind:'apply',state:'pending'};
 const requested={...view,id:randomUUID(),requestId:c.requestId,action:'configuration.job.requested',result:'success',before:null,after:requestedAfter,
  jsonPatch:[{op:'replace',path:'',value:requestedAfter}]};
 const h={state:r,check,save:vi.fn(),data:value=>value.payload.data,request:vi.fn(async(_actor,path,method='GET')=>{
  expect(method).toBe('GET');const query=new URL(path,'http://synthetic.invalid').searchParams,requestId=query.get('requestId');
  const actual=requestId===c.closeRequestId?view:requestId===c.requestId?requested:null;
  expect(actual).not.toBeNull();expect(query.get('result')).toBe(actual.result);
  return{payload:{data:{items:[actual],total:null,nextCursor:null}}};})};
 return{h,r,packet,view,requested,closed,actors:{admin:{user:{id:c.actorId},sid:c.sid}}};
}

describe('M8 prepared-but-not-issued audit closure SOURCE proof',()=>{
 it('covers actual reservation and exact second uncertainty closure separately from Native execution',async()=>{
  const{h,r,packet,actors}=fixture();expect(isM8ProvenPreparedDeckClosurePacket(r,packet,146)).toBe(true);
  expect(await m8AllWritesAuditAcceptance(h,actors)).toMatchObject({successfulWrites:2,failureClosureWrites:1,preparedNotIssuedClosureWrites:1,
   preparedExecutionRegistrationWrites:1,successfulExecutionOrMetadataWrites:0,coveredWrites:2,allCovered:true});
  expect(h.request).toHaveBeenCalledTimes(2);expect(h.state.auditWriteCoverage.records.map(v=>[v.preparedExecutionRegistration,v.preparedNotIssuedClosure])).toEqual([[true,false],[false,true]]);
 });
 it.each(['job','sid','actor','CID','WID','body','key','requestId','headers','copy','absentProtectedRead','changedProtectedRead'])('rejects changed %s prepared closure provenance before querying its audit',async which=>{
  const{h,r,packet,actors}=fixture();
  if(which==='job')packet.path=packet.path.replace(c.jobId,randomUUID());if(which==='sid')packet.sessionId=randomUUID();if(which==='actor')packet.actorId=randomUUID();
  if(which==='CID')packet.clusterId=randomUUID();if(which==='WID')packet.workspaceId=randomUUID();if(which==='body')packet.body.planHash='f'.repeat(64);
  if(which==='key')packet.key=randomUUID();if(which==='requestId')packet.requestId=randomUUID();if(which==='headers')packet.headers.Cookie='NO_SESSION';
  if(which==='copy')expect(isM8ProvenPreparedDeckClosurePacket(r,structuredClone(packet),146)).toBe(false);
  if(which==='absentProtectedRead')delete r.deckWireBodyContinuation.abandonAttempt.originalJob;
  if(which==='changedProtectedRead')r.deckWireBodyContinuation.abandonAttempt.originalJob.completedSteps=1;
  if(which==='copy')return;
  await expect(m8AllWritesAuditAcceptance(h,actors)).rejects.toThrow();expect(h.state.auditWriteCoverage).toBeUndefined();
  expect(h.request.mock.calls.every(args=>!args[1].includes(`requestId=${c.closeRequestId}`))).toBe(true);
 });
 it.each(['subject','workflow','execution','plan','planRevision','lease','beforeRevision','afterRevision','executionRevision','completed','unresolved','actor','WID','request','result','patch'])('rejects a false %s actual immutable uncertainty audit',async which=>{
  const{h,view,actors}=fixture();if(which==='subject')view.entityId=randomUUID();if(which==='workflow')view.workflowId=randomUUID();
  if(which==='execution')view.after.executionId=randomUUID();if(which==='plan')view.after.planHash='f'.repeat(64);if(which==='planRevision')view.after.planRevision=2;
  if(which==='lease')view.after.leaseGeneration=2;if(which==='beforeRevision')view.before.revision=1;if(which==='afterRevision')view.after.revision=4;
  if(which==='executionRevision')view.after.executionRevision=3;if(which==='completed')view.after.completedSteps=1;if(which==='unresolved')view.after.unresolvedSteps=0;
  if(which==='actor')view.actorId=randomUUID();if(which==='WID')view.workspaceId=randomUUID();if(which==='request')view.requestId=randomUUID();if(which==='result')view.result='success';
  view.jsonPatch=which==='patch'?[]:jsonPatch.compare(view.before,view.after);
  await expect(m8AllWritesAuditAcceptance(h,actors)).rejects.toThrow();expect(h.state.auditWriteCoverage).toBeUndefined();
 });
 it.each(['action','subject','before','state','kind'])('a prepared apply cannot be counted as Native success through a false %s reservation audit',async which=>{
  const{h,requested,actors}=fixture();if(which==='action')requested.action='configuration.job.complete';if(which==='subject')requested.entityId=randomUUID();
  if(which==='before')requested.before={state:'running'};if(which==='state')requested.after.state='succeeded';if(which==='kind')requested.after.kind='capture';
  requested.jsonPatch=[{op:'replace',path:'',value:requested.after}];await expect(m8AllWritesAuditAcceptance(h,actors)).rejects.toThrow('registration');expect(h.state.auditWriteCoverage).toBeUndefined();
 });
 it('generic HTTP201 uncertain JSON without original marker never grants a closure exception',async()=>{
  const{h,r,actors}=fixture();delete r.deckWireBodyContinuation;await expect(m8AllWritesAuditAcceptance(h,actors)).rejects.toThrow('fixed tuple');expect(h.state.auditWriteCoverage).toBeUndefined();
 });
});
