// @ts-nocheck -- actual ESM helpers with synthetic RAM packets only.
import {describe,it,expect,vi,beforeEach} from 'vitest';
import {randomUUID} from 'node:crypto';
import jsonPatch from 'fast-json-patch';
const seals=vi.hoisted(()=>new Map());
vi.mock('./lib/m8-harness.mjs',async actual=>{const module=await actual();return{...module,sha256:v=>seals.get(typeof v==='string'?v:v.toString())??module.sha256(v)};});
import {sha256} from './lib/m8-harness.mjs';
import {M8_EXPIRED_EXECUTION as c,assertM8ExpiredExecutionCheckpoint,m8FreshBudgetServices,m8ServiceFieldsMatch,
 assertM8OriginalAbandonIntent,assertM8ClosedOriginalJob,isM8ProvenFailureClosurePacket} from './lib/m8-expired-execution-recovery.mjs';
import {m8AllWritesAuditAcceptance} from './lib/m8-audit-acceptance.mjs';
beforeEach(()=>seals.clear());
const actor={user:{id:c.actorId},sid:c.sid},area={cid:c.cid,wid:c.wid};
function original(){const intent={jobId:c.jobId,revision:5,executionId:c.executionId,executionRevision:2,planRevision:1,planHash:c.planHash,
 leaseGeneration:2,workflowExecutionId:c.workflowExecutionId,confirmationName:`abandon:${c.jobId}`};
 const job={domain:'configuration',durable:true,idempotencyKey:c.submissionKey,jobId:c.jobId,id:c.jobId,actorId:c.actorId,clusterId:c.cid,workspaceId:c.wid,
  state:'running',workflowId:c.workflowId,planId:c.planId,revision:5,capabilities:{abandon:true},abandonmentIntent:intent};return{job,intent};}
function closed(){const{job,intent}=original(),requestId=randomUUID(),done={...job,state:'uncertain',revision:6,executionId:c.executionId,executionRevision:3,planRevision:1,
 planHash:c.planHash,leaseGeneration:2,workflowExecutionId:c.workflowExecutionId,abandoned:true,terminalFailureRecorded:true,executionCompleted:true,
 abandonmentSessionMatches:true,abandonRequestId:requestId,completedSteps:16,unresolvedSteps:1};return{job,intent,done,requestId};}
/** Trust anchors are substituted only for this synthetic fixed prefix. The
 * public runtime constants remain immutable; production has no override. */
function proofPacket(){const{job,intent,done,requestId}=closed(),body={revision:5,executionId:c.executionId,executionRevision:2,planRevision:1,planHash:c.planHash,
 leaseGeneration:2,workflowExecutionId:c.workflowExecutionId,confirmed:true,confirm_name:intent.confirmationName},key=randomUUID();
 const packet={index:121,method:'POST',path:`/api/v1/clusters/${c.cid}/configuration/jobs/${c.jobId}/abandon`,query:`?workspaceId=${c.wid}`,
  key,actorId:c.actorId,sessionId:c.sid,clusterId:c.cid,workspaceId:c.wid,state:'response_observed',status:201,requestId,body,bodySha256:sha256(JSON.stringify(body)),
  headers:{Cookie:'kongos_access=SyntheticOriginalSameSidCookie','X-CSRF-Token':'SyntheticOriginalCsrf','X-Idempotency-Key':key},responseData:{jobId:c.jobId,executionId:c.executionId,state:'uncertain',abandoned:true,originalWorkflowUnchanged:true,originalNativeReceiptsUnchanged:true}};
 const prefix=Array.from({length:121},(_,index)=>({index,synthetic:true,method:'POST',path:'/api/v1/synthetic-original-denied',state:'response_observed',status:403}));seals.set(JSON.stringify(prefix),c.prefix);
 const r={requests:[...prefix,packet],expiredExecutionRecovery:{originalPrefixSha256:c.prefix,originalPacketCount:121,abandonAttempt:{state:'completed',index:121,idempotencyKey:key,
  packetSha256:sha256(JSON.stringify(packet)),requestId,bodySha256:packet.bodySha256,body:structuredClone(body),originalJob:done,intent}}};return{r,packet};}
function auditFixture(){const{r,packet}=proofPacket();Object.assign(r,{scopes:{approval:area},fixtures:[],inFlight:null});
 const before={jobId:c.jobId,executionId:c.executionId,state:'running'},after={...before,state:'uncertain',abandoned:true,planHash:c.planHash,planRevision:1,leaseGeneration:2,completedSteps:16,unresolvedSteps:1};
 const view={id:randomUUID(),actorId:c.actorId,clusterId:c.cid,workspaceId:c.wid,requestId:packet.requestId,workflowId:c.workflowId,scopeQuality:'verified',
  entityType:'configuration_jobs',entityId:c.jobId,action:'configuration.execution.abandon',result:'uncertain',before,after,jsonPatch:jsonPatch.compare(before,after)};
 const h={state:r,check:(v,n)=>{if(!v)throw Error(n);},save:vi.fn(),data:r=>r.payload.data,request:vi.fn(async(_actor,path)=>{
  expect(path).toContain(`requestId=${packet.requestId}`);expect(path).toContain('result=uncertain');return{payload:{data:{items:[view],total:null,nextCursor:null}}};})};
 return{h,packet,view,actors:{admin:actor}};
}
describe('M8 fixed expired-execution recovery SOURCE contract',()=>{
 it('rejects an invented checkpoint before any environment or packet',()=>expect(()=>assertM8ExpiredExecutionCheckpoint({requests:[]},Buffer.from('{}'),Buffer.from('{}'),Buffer.from('{}'))).toThrow('M8_EXACT_EXPIRED_EXECUTION_CHECKPOINT_REQUIRED'));
 it('preallocates seventeen new names and UUIDs, independent of every old name and ID',()=>{
  const nonce=randomUUID(),services=m8FreshBudgetServices('m8-security-0123abcd',nonce,[c.lastId],['old-original-name']);
  expect(services).toHaveLength(17);expect(new Set(services.map(v=>v.id)).size).toBe(17);expect(new Set(services.map(v=>v.name)).size).toBe(17);
  expect(services.every(v=>v.id!==c.lastId&&!v.name.includes('-v2-')&&v.host==='echo-upstream'&&v.retries===0)).toBe(true);
  expect(()=>m8FreshBudgetServices('M7-old',nonce)).toThrow();expect(()=>m8FreshBudgetServices('m8-security-0123abcd','not-an-id')).toThrow();
 });
 it('checks actual Service fields by name instead of the unrelated DAG UUID order',()=>{
  const value=m8FreshBudgetServices('m8-security-0123abcd',randomUUID())[7];expect(m8ServiceFieldsMatch({...value,tags:[...value.tags,'workspace:synthetic']},value,'m8-security-0123abcd')).toBe(true);
  for(const delta of[{id:c.lastId},{name:'another-name'},{retries:1},{host:'another-host'},{port:8000},{protocol:'https'},{tags:[]}])expect(m8ServiceFieldsMatch({...value,...delta},value,'m8-security-0123abcd')).toBe(false);
 });
 it('accepts only the original current server-owned abandon intent',()=>{const{job,intent}=original();expect(assertM8OriginalAbandonIntent(job,actor,area)).toBe(intent);});
 for(const[field,value]of[['state','succeeded'],['planId',randomUUID()],['jobId',randomUUID()],['idempotencyKey',randomUUID()],['actorId',randomUUID()],['clusterId',randomUUID()],['workspaceId',randomUUID()],['workflowId',randomUUID()],['durable',false]] as const)
  it(`rejects current original intent ${field}`,()=>{const{job}=original();expect(()=>assertM8OriginalAbandonIntent({...job,[field]:value},actor,area)).toThrow();});
 it.each(['executionId','workflowExecutionId','planHash','revision','confirmationName'])('rejects replaced intent %s',field=>{const{job}=original();job.abandonmentIntent[field]=field==='revision'?7:'foreign';expect(()=>assertM8OriginalAbandonIntent(job,actor,area)).toThrow();});
 it('rejects a new session despite the same actor, and does not treat another workspace as original',()=>{const{job}=original();expect(()=>assertM8OriginalAbandonIntent(job,{...actor,sid:randomUUID()},area)).toThrow();expect(()=>assertM8OriginalAbandonIntent(job,actor,{...area,wid:randomUUID()})).toThrow();});
 it('retains original uncertainty and sixteen successes after metadata-only close',()=>{const{job,intent,done,requestId}=closed();expect(assertM8ClosedOriginalJob(done,job,intent,actor,area,requestId)).toBe(done);expect(done.state).toBe('uncertain');});
 for(const[field,value]of[['state','succeeded'],['revision',5],['planHash','a'.repeat(64)],['executionId',randomUUID()],['executionRevision',2],['planRevision',2],['leaseGeneration',3],['workflowExecutionId',randomUUID()],['abandonmentSessionMatches',false],['abandoned',false],['terminalFailureRecorded',false],['executionCompleted',false],['completedSteps',17],['unresolvedSteps',0],['abandonRequestId',randomUUID()]] as const)
  it(`rejects false close proof ${field}`,()=>{const{job,intent,done,requestId}=closed();expect(()=>assertM8ClosedOriginalJob({...done,[field]:value},job,intent,actor,area,requestId)).toThrow();});
 it('classifies exactly the protected original closure packet separately from Native success',()=>{const{r,packet}=proofPacket();expect(isM8ProvenFailureClosurePacket(r,packet,121)).toBe(true);expect(packet.responseData.state).toBe('uncertain');});
 it.each(['body','headers','sid','CID','WID','key','requestId','status','progress','prefix','copy'])('does not exempt altered or copied %s closure provenance',which=>{
  const{r,packet}=proofPacket();if(which==='body')packet.body.executionId=randomUUID();if(which==='headers')packet.headers.Cookie='ChangedCookie';if(which==='sid')packet.sessionId=randomUUID();
  if(which==='CID')packet.clusterId=randomUUID();if(which==='WID')packet.workspaceId=randomUUID();if(which==='key')packet.key=randomUUID();if(which==='requestId')packet.requestId=randomUUID();if(which==='status')packet.status=500;
  if(which==='progress')r.expiredExecutionRecovery.abandonAttempt.originalJob.abandonmentSessionMatches=false;if(which==='prefix')r.requests[0].synthetic=false;
  expect(isM8ProvenFailureClosurePacket(r,which==='copy'?structuredClone(packet):packet,121)).toBe(false);
 });
 it('covers only the exact uncertainty-recording audit and keeps its completed accounting separate from Native success',async()=>{
  const{h,actors}=auditFixture(),result=await m8AllWritesAuditAcceptance(h,actors);
  expect(result).toMatchObject({successfulWrites:1,failureClosureWrites:1,successfulExecutionOrMetadataWrites:0,coveredWrites:1,allCovered:true});
  expect(h.request).toHaveBeenCalledTimes(1);expect(h.state.auditWriteCoverage.records[0].failureClosure).toBe(true);
 });
 it.each(['result','action','subject','request','actor','CID','WID','completed','unresolved','plan','execution','patch'])('rejects a mismatched %s immutable closure audit',async(which)=>{
  const{h,view,actors}=auditFixture();if(which==='result')view.result='success';if(which==='action')view.action='create';if(which==='subject')view.entityId=randomUUID();
  if(which==='request')view.requestId=randomUUID();if(which==='actor')view.actorId=randomUUID();if(which==='CID')view.clusterId=randomUUID();if(which==='WID')view.workspaceId=randomUUID();
  if(which==='completed')view.after.completedSteps=17;if(which==='unresolved')view.after.unresolvedSteps=0;if(which==='plan')view.after.planHash='f'.repeat(64);if(which==='execution')view.after.executionId=randomUUID();if(which==='patch')view.jsonPatch=[];
  await expect(m8AllWritesAuditAcceptance(h,actors)).rejects.toThrow();expect(h.state.auditWriteCoverage).toBeUndefined();
 });
});
