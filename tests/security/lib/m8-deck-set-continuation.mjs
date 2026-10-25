import{readFileSync}from'node:fs';
import{M8Harness,sha256}from'./m8-harness.mjs';
import{isM8ProvenConsumedUnknownDownload}from'./m8-consumed-review-download.mjs';

export const M8_DECK_SET_CHECKPOINT=Object.freeze({
 count:151,prefix:'707f40a734e0c5323e1e57d46f9aae80b07dd1547858256248d696aec4d7ded9',
 cliIndex:4,cliSha256:'513e82f1bb768144b6a728242e9f3162bd9c50bdf23f9f51658f8b10e6eb51b1',
 failurePath:'artifacts/M8/security-live-deck-wire-body.json',failureSha256:'8fe1912e075e75785a4da7deef57e8beffc79f3ee95a8ec5eb19f90e5ac8198f',
 diagnosisPath:'artifacts/M8/deck-wire-sync-original-readonly-diagnosis.json',diagnosisSha256:'81dc45db1754e085bac9b35eaae0e59622e1c766d0141be724dbfb0075b6802a',
 freezePath:'artifacts/M8/root-deck-schema-set-envelope-fix-freeze.json',freezeSha256:'daf2f061162a7952e66cf2c95ab92ca23a0f02f971e3c127dee393dc104143b7',
 actorId:'b5f796fa-9515-47de-9123-89a903a48224',sid:'81eb0903-bc6f-447b-a9a7-7cadf55faa77',
 cid:'dff45535-ed8d-4851-b7a6-6376feac7f59',wid:'eb8bf868-2caf-46aa-a935-b368bf9f3105',
 key:'26fc1771-8b18-4f6c-918f-b4930386c22f',jobId:'aeba79f9-fde5-4169-847c-f6ede3c9f92b',
 executionId:'340da2ec-249a-42fb-9035-2f54f27ef178',planId:'d7f19a98-ce89-4a86-b30f-90e12b6c24b4',
 planRevision:1,planHash:'5a5402137decd400b0c4bc8844a0dfe5e39640d4dbfcf976341ac7dca506abac',
 stepId:'0e059f2f-af0f-477c-84b2-cf627fb7ef5f',planStepId:'53e4efbd-9075-45a7-9a54-b5d0a3f7a5a9',
 serviceId:'9e5adb4a-0964-4e77-a01b-a6a4347138d7',closePath:'artifacts/M8/deck-set-original-unknown-sync-close.json',closeSha256:'18a28da1091cf28a89ad1a7341b7644bd72ab8cd78b07cce89d95ecf234974fd',
 closedCount:153,closedPrefix:'67bb19512f81f81338c6d346b588af000238b8615f25b7bab5bfc0053c425451',
 continuityPath:'artifacts/M8/deck-schema-set-api-repair-continuity.json',continuitySha256:'6c6ec9140a65cbe4890c289564efb625a1f8e3ad185240442f7df45b0c0c6246',
 successPath:'artifacts/M8/security-live-deck-schema-sets.json',
});
const c=M8_DECK_SET_CHECKPOINT;
export function isM8ProvenSetUnknownSyncClosurePacket(r,p,index){
 const m=r.deckSetContinuation,a=m?.abandonAttempt,j=a?.closedJob,s=a?.closedStep,i=a?.intent;
 if(!a||a.state!=='completed'||m.originalPacketCount!==151||m.originalPrefixSha256!==c.prefix
  ||sha256(JSON.stringify(r.requests.slice(0,151)))!==c.prefix||sha256(JSON.stringify(r.cliIntents?.[4]))!==c.cliSha256
  ||r.cliIntents[4].state!=='response_unknown'||index!==a.index||p!==r.requests[index]||sha256(JSON.stringify(p))!==a.packetSha256
  ||p.state!=='response_observed'||p.status!==201||p.actorId!==c.actorId||p.sessionId!==c.sid||p.clusterId!==c.cid||p.workspaceId!==c.wid
  ||p.method!=='POST'||p.path!==`/api/v1/clusters/${c.cid}/configuration/jobs/${c.jobId}/abandon`||p.query!==`?workspaceId=${c.wid}`
  ||p.key!==a.key||p.requestId!==a.requestId||p.bodySha256!==a.bodySha256||sha256(JSON.stringify(p.body))!==a.bodySha256||JSON.stringify(p.body)!==JSON.stringify(a.body)
  ||p.body.executionId!==c.executionId||p.body.planHash!==c.planHash||p.body.planRevision!==1||p.body.workflowExecutionId!==null
  ||p.body.revision!==i?.revision||p.body.executionRevision!==i?.executionRevision||p.body.leaseGeneration!==i?.leaseGeneration||p.body.confirmed!==true||p.body.confirm_name!==`abandon:${c.jobId}`
  ||j?.id!==c.jobId||j.idempotencyKey!==c.key||j.actorId!==c.actorId||j.clusterId!==c.cid||j.workspaceId!==c.wid||j.planId!==c.planId||j.planHash!==c.planHash||j.planRevision!==1
  ||j.executionId!==c.executionId||j.revision!==i.revision+1||j.executionRevision!==i.executionRevision+1||j.leaseGeneration!==i.leaseGeneration||j.state!=='uncertain'
  ||j.completedSteps!==0||j.unresolvedSteps!==1||j.abandoned!==true||j.executionCompleted!==true||j.abandonmentSessionMatches!==true||j.abandonRequestId!==p.requestId
  ||s?.id!==c.stepId||s.executionId!==c.executionId||s.planStepId!==c.planStepId||s.operationId!==null||s.verified!==false||s.startedAt!==null||s.state!=='uncertain'||s.completedAt===null
  ||a.originalPendingStep?.state!=='pending'||a.originalPendingStep.operationId!==null||a.originalPendingStep.startedAt!==null
  ||p.responseData?.state!=='uncertain'||p.responseData.executionId!==c.executionId||p.responseData.completedSteps!==0||p.responseData.unresolvedSteps!==1
  ||p.responseData.originalNativeReceiptsUnchanged!==true||p.responseData.originalWorkflowUnchanged!==true||!p.headers?.Cookie||!p.headers['X-CSRF-Token']||p.headers['X-Idempotency-Key']!==p.key)return false;
 return true;
}
/** Independent subsequent work is allowed only after the exact original
 * unknown CLI's execution has been explicitly closed. Any new unknown stops. */
export class M8DeckSetContinuedHarness extends M8Harness{
 assertWritable(){
  assertM8UnknownSyncOriginal(this.state);const r=this.state,a=r.deckSetContinuation?.abandonAttempt;
  if(r.phase.startsWith('stopped')||!isM8ProvenSetUnknownSyncClosurePacket(r,r.requests[a?.index],a?.index)
   ||(r.proxyChecks??[]).some(p=>p.method==='POST'&&['prepared','response_unknown'].includes(p.state)))throw Error('M8_EXPLICIT_CLOSED_ORIGINAL_SYNC_REQUIRED_NO_NEW_UNKNOWN');
 }
}
export function assertM8UnknownSyncOriginal(r){
 if(r.version!==1||r.milestone!=='M8'||r.inFlight!==null||r.requests.length<c.count||sha256(JSON.stringify(r.requests.slice(0,c.count)))!==c.prefix
  ||r.requests.some((p,index)=>(p.state!=='response_observed'||!Number.isInteger(p.status))&&!isM8ProvenConsumedUnknownDownload(r,p,index))||r.cliIntents.length<c.cliIndex+1
  ||sha256(JSON.stringify(r.cliIntents[c.cliIndex]))!==c.cliSha256||r.cliIntents[c.cliIndex].state!=='response_unknown'||r.cliIntents[c.cliIndex].command!=='sync'
  ||r.cliIntents.some((v,i)=>i!==c.cliIndex&&v.state!=='response_observed')||r.sessions.admin.user.id!==c.actorId||r.sessions.admin.sid!==c.sid
  ||r.scopes.direct.cid!==c.cid||r.scopes.direct.wid!==c.wid)throw Error('M8_EXACT_ORIGINAL_151_UNKNOWN_SYNC_REQUIRED');
 return true;
}
export function assertM8DeckSetCloseSource(r){
 assertM8UnknownSyncOriginal(r);
 if(r.phase!=='stopped-failure'||r.requests.length!==c.count||r.cliIntents.length!==5||r.deckSetContinuation)throw Error('M8_ORIGINAL_SYNC_CLOSE_ALREADY_STARTED');
 for(const[path,digest]of[[c.failurePath,c.failureSha256],[c.diagnosisPath,c.diagnosisSha256],[c.freezePath,c.freezeSha256]]){
  if(sha256(readFileSync(path))!==digest)throw Error('M8_SET_CLOSE_EXACT_EVIDENCE_REQUIRED');
 }
 const f=JSON.parse(readFileSync(c.failurePath)),d=JSON.parse(readFileSync(c.diagnosisPath)),s=JSON.parse(readFileSync(c.freezePath));
 if(f.allPassed!==false||f.passed!==1941||f.failed!==1||f.unknownWrites!==0||d.original151Unchanged!==true||d.originalCli.state!=='response_unknown'
  ||d.originalCli.privateStderrFsynced!==true||d.originalCli.stderrBytes!==171||d.job.jobId!==c.jobId||d.job.executionId!==c.executionId
  ||s.sourceOnly!==true||s.validation.apiTypecheckExitCode!==0||s.validation.apiBuildExitCode!==0)throw Error('M8_SET_CLOSE_PROOF_INVALID');
}
export function assertM8SetOriginalJob(job){
 const i=job.abandonmentIntent;
 if(job.domain!=='configuration'||job.durable!==true||job.id!==c.jobId||job.jobId!==c.jobId||job.idempotencyKey!==c.key||job.actorId!==c.actorId
  ||job.clusterId!==c.cid||job.workspaceId!==c.wid||job.state!=='running'||job.executionCompleted!==false||job.driver!=='deck'||job.workflowId!=null
  ||job.planId!==c.planId||job.planHash!==c.planHash||job.planRevision!==1||job.executionId!==c.executionId||job.capabilities?.abandon!==true
  ||i?.jobId!==c.jobId||i.executionId!==c.executionId||i.workflowExecutionId!==null||i.planHash!==c.planHash||i.planRevision!==1||i.revision!==job.revision
  ||![i.revision,i.executionRevision,i.leaseGeneration].every(v=>Number.isSafeInteger(v)&&v>0)||i.confirmationName!==`abandon:${c.jobId}`)
  throw Error('M8_EXACT_SET_ORIGINAL_ABANDON_INTENT_REQUIRED');
 return i;
}
export function assertM8SetPendingStep(page){
 const s=page.items?.[0];
 if(page.items?.length!==1||page.nextCursor!==null||s.id!==c.stepId||s.executionId!==c.executionId||s.planStepId!==c.planStepId||s.state!=='pending'
  ||s.objectWorkspaceId!==c.wid||s.type!=='services'||s.action!=='update'||s.originalId!==c.serviceId||s.operationId!==null||s.verified!==false||s.startedAt!==null||s.completedAt!==null)
  throw Error('M8_SET_EXACT_UNSTARTED_NATIVE_STEP_REQUIRED');
 return s;
}
/** The fixed original unknown CLI is preserved. This close-only harness
 * permits at most one genuine refresh and one typed explicit abandonment;
 * it cannot preview, apply, issue a token, run a CLI or mutate Kong. */
export class M8DeckSetCloseHarness extends M8Harness{
 assertWritable(){assertM8UnknownSyncOriginal(this.state);}
 async request(session,path,method='GET',body,options={}){
  if(!['GET','HEAD'].includes(method)){
   const r=this.state,m=r.deckSetContinuation;assertM8UnknownSyncOriginal(r);
   if(session?.user?.id!==c.actorId||session?.sid!==c.sid||m?.state!=='closing')throw Error('M8_SET_CLOSE_FIXED_ACTOR_REQUIRED');
   const suffix=r.requests.slice(c.count);
   if(path==='/auth/refresh'){
    if(suffix.length||JSON.stringify(body)!=='{}')throw Error('M8_SET_CLOSE_ONE_NORMAL_REFRESH_ONLY');
   }else if(path===`/clusters/${c.cid}/configuration/jobs/${c.jobId}/abandon?workspaceId=${c.wid}`){
    if(suffix.some(p=>p.path!== '/api/v1/auth/refresh')||!m.abandonAttempt||JSON.stringify(body)!==JSON.stringify(m.abandonAttempt.body)||options.key!==m.abandonAttempt.key)
     throw Error('M8_SET_CLOSE_ONE_EXACT_ABANDON_ONLY');
   }else throw Error('M8_SET_CLOSE_OTHER_WRITES_REFUSED');
  }
  return super.request(session,path,method,body,options);
 }
}
