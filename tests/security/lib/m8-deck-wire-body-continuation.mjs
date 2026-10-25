import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {parse,stringify} from 'yaml';
import {entity,scope,sha256} from './m8-harness.mjs';
import {configurationRead,configurationWrite,assertConfigurationReceipt} from './m8-configuration-acceptance.mjs';
import {assertM8DeckSession} from './m8-deck-acceptance.mjs';
import {assertM8DeckPoolRelease,runM8FixedDeckPrivateStderr} from './m8-deck-pool-continuation.mjs';
import {nativeRead,sixCredentialProxyAcceptance} from './m8-native-acceptance.mjs';

/** One original submitted apply, not a generic exception for running jobs.
 * Future release hashes remain mandatory: absent evidence cannot run. */
export const M8_DECK_WIRE_BODY_CONTINUATION=Object.freeze({
 packetCount:145,prefix:'e6109c07e5a4689e86f3a5eef2cc7655568d1d2876fbbced76b2aa0e09cfb9ac',prefix142:'aa96960f027859d138fb8c309b9e1d4422209bc07f1440876d1d9d3f419ea593',
 failurePath:'artifacts/M8/security-live-deck-record-merge.json',failureSha256:'ca83a8bd717e0719280136796ff087284d9af0300d394548abe3ad57055a680a',
 diagnosisPath:'artifacts/M8/running-deck-apply-readonly-diagnosis.json',diagnosisSha256:'8c7ec1d1d3737403fb95fe08eeffcb27d08b983a6a4b4c51e4671ff2e0d9150b',
 sdkProofPath:'artifacts/M8/deck-service-put-source-proof.json',sdkProofSha256:'b124e018f1147d70d116c3bb86e13d2e89b5d837e8c623f182145bb3ca85d28f',
 key:'de367631-8c76-4d27-b9d9-36275467c59f',requestId:'fb87bc96-6e33-4ec3-ac1c-24459b7ca950',bodySha256:'9460e1665dfd9885e04409d6d09a00bb5297565acd525973d9254e25fed8616d',
 jobId:'8f1dee53-4657-45eb-8018-dcc792660d05',sourcePlanId:'f51184e4-77ed-4d76-af58-f296b53ac8ad',executionPlanId:'ffb07cd8-018a-470a-b1c5-aadc7886fdb0',
 planRevision:1,planHash:'ee2697ae14388bdc96f2bfb545e6e5bd85c8bde76c08c26e6068a9002e840c55',
 executionId:'e681af39-c49c-40f6-bcff-549c2bec3722',jobStepId:'30828448-beca-48c4-a63b-5358993247da',planStepId:'74240988-dfbb-4a81-b3ec-e6c2e5c95185',
 actorId:'b5f796fa-9515-47de-9123-89a903a48224',sid:'81eb0903-bc6f-447b-a9a7-7cadf55faa77',
 cid:'dff45535-ed8d-4851-b7a6-6376feac7f59',wid:'eb8bf868-2caf-46aa-a935-b368bf9f3105',serviceId:'9e5adb4a-0964-4e77-a01b-a6a4347138d7',
 successPath:'artifacts/M8/security-live-deck-wire-body.json',
 closedPacketCount:147,closedPrefix:'25ac35b51693ce9cfb2bd80e35ee7b73f798485c842b9886dbbaf9bd9a724e1b',
 closeReportPath:'artifacts/M8/deck-prepared-execution-close.json',closeReportSha256:'c93b256159ab4b8486088cf64943054b483bf0ad16a5395969bce402b4dd3498',
 authPacketSha256:'7991b8526e9bd7a37af0288207ef8dae3657e7a8f574654b583ed55360417346',closePacketSha256:'1bae43be13cc87bca357dcb739b5268e1b8a89a3738dc22f06bac3a73f8da969',
 authRequestId:'91001dd3-43b5-40a3-8a01-a2c9a56d6af4',authAuditId:'fa99178f-17db-49a9-89f3-118d5a354f1f',closeRequestId:'28b86517-1c50-47fb-a009-6499738d6e52',closeKey:'90d32e3e-bd1b-4f85-b9e3-be85339c77c8',
 sourceFreezePath:'artifacts/M8/root-deck-sealed-wire-body-fix-freeze.json',sourceFreezeSha256:'99a8c42cacfb65850467886969cf309478b43724715d850a8155e6520ad45152',
 continuityPath:'artifacts/M8/deck-sealed-wire-body-api-repair-continuity.json',continuitySha256:'87329ea75d28601766aeee34326dd2fb47845b85fd683081b4b2e7ba9fab92e4',
});
const c=M8_DECK_WIRE_BODY_CONTINUATION;
const uuid=v=>typeof v==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
const positive=v=>Number.isSafeInteger(v)&&v>0;
const reject=()=>{throw Error('M8_EXACT_145_PREPARED_DECK_CHECKPOINT_REQUIRED');};
export function assertM8DeckWireBodyCheckpoint(r,failedBytes,diagnosisBytes,sdkBytes){
 const f=JSON.parse(failedBytes),d=JSON.parse(diagnosisBytes),p=r.requests?.[144],m=r.runningDeckApplyReadonlyDiagnosis;
 if(r.version!==1||r.milestone!=='M8'||r.phase!=='stopped-failure'||r.inFlight!==null||r.requests?.length!==145
  ||sha256(JSON.stringify(r.requests))!==c.prefix||sha256(JSON.stringify(r.requests.slice(0,142)))!==c.prefix142
  ||r.requests.some(v=>v.state!=='response_observed'||!Number.isInteger(v.status))||r.deckWireBodyContinuation||r.deckAcceptance||r.rbacJournal
  ||sha256(failedBytes)!==c.failureSha256||f.allPassed!==false||f.passed!==1842||f.failed!==1||f.successfulWrites!==133||f.unknownWrites!==0
  ||sha256(diagnosisBytes)!==c.diagnosisSha256||d.allPassed!==true||d.original145PrefixUnchanged!==true||d.newAuthWrites!==0||d.newBusinessWrites!==0||d.newNativeWrites!==0||d.newCliIntents!==0
  ||sha256(sdkBytes)!==c.sdkProofSha256||r.cliIntents?.length!==4||r.cliIntents.some(v=>v.state!=='response_observed')||r.cliIntents.some(v=>v.command==='sync')
  ||r.deckSessions?.length!==3||r.deckSessions.some(v=>v.purpose==='write')||!r.c2ModeRestored||r.approvalTransfer?.nativeSteps!==17)reject();
 if(p.status!==201||p.key!==c.key||p.requestId!==c.requestId||p.method!=='POST'||p.path!==`/api/v1/clusters/${c.cid}/configuration/plans/${c.sourcePlanId}/apply`
  ||p.query!==`?workspaceId=${c.wid}`||p.actorId!==c.actorId||p.sessionId!==c.sid||p.clusterId!==c.cid||p.workspaceId!==c.wid
  ||p.bodySha256!==c.bodySha256||sha256(JSON.stringify(p.body))!==c.bodySha256||p.body.driver!=='deck'||p.body.planHash!==c.planHash||p.body.planRevision!==1
  ||p.responseData?.jobId!==c.jobId||p.responseData.planId!==c.executionPlanId||p.responseData.planHash!==c.planHash||p.responseData.planRevision!==1
  ||p.responseData.state!=='running'||p.responseData.executionCompleted!==false||r.sessions?.admin?.user?.id!==c.actorId||r.sessions.admin.sid!==c.sid
  ||r.scopes?.direct?.cid!==c.cid||r.scopes.direct.wid!==c.wid||r.deckRecordMergeContinuation?.state!=='unused-direct-deck-apply')reject();
 if(m?.state!=='completed'||m.original145PrefixSha256!==c.prefix||m.originalFailedReportSha256!==c.failureSha256||m.originalApplyKey!==c.key
  ||m.actorId!==c.actorId||m.sessionId!==c.sid||m.clusterId!==c.cid||m.workspaceId!==c.wid||m.jobId!==c.jobId||m.executionPlanId!==c.executionPlanId
  ||m.planHash!==c.planHash||m.planRevision!==1||m.executionId!==c.executionId||m.jobStepId!==c.jobStepId||m.planStepId!==c.planStepId
  ||m.reads?.length!==3||m.reads.some(v=>v.method!=='GET'||v.state!=='response_observed'||v.status!==200||v.actorId!==c.actorId||v.sessionId!==c.sid))reject();
 assertM8PendingPreparedDeckStep(m.reads[1].privateData);
 return{failed:f,diagnosis:d,packet:p};
}
/** The original close is already completed. This suffix is not replayed and
 * no new marker/history may replace its original authoritative receipt. */
export function assertM8ClosedPreparedDeckCheckpoint(r,closeBytes,failedBytes,diagnosisBytes,sdkBytes){
 const report=JSON.parse(closeBytes),m=r.deckWireBodyContinuation,auth=r.requests?.[145],close=r.requests?.[146],maintenance=m?.sessionMaintenance;
 if(r.phase!=='deck-prepared-closed'||r.inFlight!==null||r.requests?.length!==147||sha256(JSON.stringify(r.requests))!==c.closedPrefix
  ||sha256(closeBytes)!==c.closeReportSha256||report.allPassed!==true||report.passed!==42||report.failed!==0||report.original145PrefixUnchanged!==true
  ||report.original145PrefixSha256!==c.prefix||report.originalFailureSha256!==c.failureSha256||report.state!=='uncertain'||report.completedSteps!==0||report.unresolvedSteps!==1
  ||report.preparedNotIssued!==true||report.nativeSuccessClaimed!==false||report.newNativeWrites!==0||report.newCliIntents!==0||report.newDeckSessions!==0||report.newPreviewOrApplyWrites!==0
  ||m?.state!=='prepared-original-closed'||m.closeOnlyReport?.path!==c.closeReportPath||m.closeOnlyReport.sha256!==c.closeReportSha256||m.closeOnlyReport.state!=='completed'
  ||maintenance?.state!=='completed'||maintenance.normalAuthenticationWrites!==1||maintenance.sameActor!==true||maintenance.sameSID!==true
  ||maintenance.requestIds?.length!==1||maintenance.requestIds[0]!==c.authRequestId||maintenance.auditEventIds?.length!==1||maintenance.auditEventIds[0]!==c.authAuditId
  ||sha256(JSON.stringify(auth))!==c.authPacketSha256||sha256(JSON.stringify(close))!==c.closePacketSha256||close.requestId!==c.closeRequestId||close.key!==c.closeKey
  ||!isM8ProvenPreparedDeckClosurePacket(r,close,146)||m.newImportKey||m.unusedTail||r.deckAcceptance||r.rbacJournal)throw Error('M8_EXACT_COMPLETED_147_PREPARED_CLOSE_REQUIRED');
 const original={...r,phase:'stopped-failure',requests:r.requests.slice(0,145),deckWireBodyContinuation:undefined};
 const result=assertM8DeckWireBodyCheckpoint(original,failedBytes,diagnosisBytes,sdkBytes);return{...result,close:report};
}
export function assertM8DeckWireBodyRelease(h){
 for(const[path,digest]of[[c.sourceFreezePath,c.sourceFreezeSha256],[c.continuityPath,c.continuitySha256]]){
  h.check(typeof digest==='string'&&/^[a-f\d]{64}$/.test(digest),'future Root source and actual runtime evidence must be frozen, not inferred from SDK-only tests');
  const bytes=readFileSync(path),v=JSON.parse(bytes);
  h.check(sha256(bytes)===digest&&(path===c.sourceFreezePath?v.sourceOnly===true&&v.validation?.apiTypecheckExitCode===0&&v.validation.apiBuildExitCode===0:v.allPassed===true),'Root source and actual continuity are exact immutable SHA-bound facts');
 }
 assertM8DeckPoolRelease(h);
}
export function assertM8PendingPreparedDeckStep(page){
 const s=page?.items?.[0];
 if(!Array.isArray(page?.items)||page.items.length!==1||page.nextCursor!==null||s.id!==c.jobStepId||s.executionId!==c.executionId||s.planStepId!==c.planStepId
  ||s.stepOrder!==1||s.state!=='pending'||s.objectWorkspaceId!==c.wid||s.type!=='services'||s.action!=='update'||s.originalId!==c.serviceId
  ||s.operationId!==null||s.verified!==false||s.startedAt!==null||s.completedAt!==null)throw Error('M8_CURRENT_EXACT_PENDING_DECK_STEP_REQUIRED');
 return s;
}
export function assertM8PreparedDeckAbandonIntent(job,actor,area){
 const i=job?.abandonmentIntent;
 if(actor.user.id!==c.actorId||actor.sid!==c.sid||area.cid!==c.cid||area.wid!==c.wid||job?.domain!=='configuration'||job.durable!==true
  ||job.id!==c.jobId||job.jobId!==c.jobId||job.idempotencyKey!==c.key||job.actorId!==c.actorId||job.clusterId!==c.cid||job.workspaceId!==c.wid
  ||job.kind!=='apply'||job.state!=='running'||job.executionCompleted!==false||job.workflowId!=null||job.executionMode!=='direct'||job.approvalRequired!==false
  ||job.planId!==c.executionPlanId||job.planRevision!==1||job.planHash!==c.planHash||job.capabilities?.abandon!==true
  ||i?.jobId!==c.jobId||i.executionId!==c.executionId||i.workflowExecutionId!==null||i.planRevision!==1||i.planHash!==c.planHash
  ||i.revision!==job.revision||!positive(i.revision)||!positive(i.executionRevision)||!positive(i.leaseGeneration)||i.confirmationName!==`abandon:${c.jobId}`)
  throw Error('M8_CURRENT_ORIGINAL_PREPARED_ABANDON_INTENT_REQUIRED');
 return i;
}
export function assertM8ClosedPreparedDeckJob(job,original,intent,requestId){
 if(job?.domain!=='configuration'||job.durable!==true||job.idempotencyKey!==c.key||job.id!==c.jobId||job.jobId!==c.jobId||job.actorId!==c.actorId
  ||job.clusterId!==c.cid||job.workspaceId!==c.wid||job.kind!=='apply'||job.state!=='uncertain'||job.revision!==original.revision+1||job.workflowId!=null
  ||job.planId!==c.executionPlanId||job.planRevision!==1||job.planHash!==c.planHash||job.executionId!==c.executionId||job.executionRevision!==intent.executionRevision+1
  ||job.workflowExecutionId!==null||job.leaseGeneration!==intent.leaseGeneration||job.completedSteps!==0||job.unresolvedSteps!==1
  ||job.abandoned!==true||job.terminalFailureRecorded!==true||job.executionCompleted!==true||job.abandonmentSessionMatches!==true||job.abandonRequestId!==requestId||!uuid(requestId))
  throw Error('M8_EXACT_PREPARED_DECK_UNCERTAIN_CLOSURE_REQUIRED');
 return job;
}
/** One explicit normal-authentication window for the original actor/SID.
 * It never logs in, creates a session, modifies an expiry, or issues a deck
 * token. A rotated cookie is persisted by the common harness before parsing. */
export async function maintainM8PreparedDeckOriginalSession(h,actor){
 const m=h.state.deckWireBodyContinuation;
 h.check(m?.state==='prepared'&&!m.sessionMaintenance&&actor.user.id===c.actorId&&actor.sid===c.sid,'only the original current session may be normally maintained once before close');
 const start=h.state.requests.length,previous={actorId:actor.user.id,sid:actor.sid,username:actor.user.username,expiresAt:actor.expiresAt};
 m.sessionMaintenance={version:1,state:'prepared',originalRequestCount:start,actorId:previous.actorId,sessionId:previous.sid,previousExpiresAt:previous.expiresAt};h.save();
 await h.renewIfNeeded(actor);
 const suffix=h.state.requests.slice(start);
 h.check(suffix.length<=1&&suffix.every(p=>p.method==='POST'&&p.path==='/api/v1/auth/refresh'&&p.state==='response_observed'&&p.status===201
  &&p.actorId===c.actorId&&p.sessionId===c.sid&&p.bodySha256===sha256('{}')&&JSON.stringify(p.body)==='{}'&&uuid(p.requestId)),
  'necessary session maintenance appends at most one real standard refresh with its original actor and SID');
 const meResponse=await h.request(actor,'/auth/me','GET',undefined,{expected:[200],renew:false}),me=h.data(meResponse);
 h.check(me.user?.id===c.actorId&&me.user.username===previous.username&&actor.user.id===c.actorId&&actor.sid===c.sid&&me.csrfToken===actor.csrf&&actor.expiresAt>Date.now()+30000,
  'protected current-user response proves the normally renewed original actor/SID remains current');
 const auditIds=[];
 for(const p of suffix){
  const page=h.data(await h.request(actor,`/audit/global?requestId=${p.requestId}&result=success&size=100`,'GET',undefined,{expected:[200],renew:false}));
  h.check(Array.isArray(page.items)&&page.items.length<=100&&page.nextCursor===null,'normal-auth audit is one bounded original-request page');
  const rows=page.items.filter(v=>v.requestId===p.requestId&&v.actorId===c.actorId&&v.entityType==='auth_sessions'&&v.entityId===c.sid&&v.action==='refresh'&&['success','succeeded'].includes(v.result));
  h.check(rows.length===1&&uuid(rows[0].id),'the normal same-SID refresh has its one actual immutable audit row');auditIds.push(rows[0].id);
 }
 Object.assign(m.sessionMaintenance,{state:'completed',normalAuthenticationWrites:suffix.length,requestIds:suffix.map(p=>p.requestId),auditEventIds:auditIds,
  packetSha256s:suffix.map(p=>sha256(JSON.stringify(p))),currentUserRequestId:meResponse.requestId,currentExpiresAt:actor.expiresAt,sameActor:true,sameSID:true});h.save();return m.sessionMaintenance;
}
/** Abandon only the already-submitted original expired execution. Current
 * permission/lease/grace is proved by the server-generated confirmation; no
 * client timestamp grants authority and no Native/session/CLI is sent here. */
export async function closeM8OriginalPreparedDeck(h,actors){
 const actor=actors.admin,area=actors.direct,m=h.state.deckWireBodyContinuation;
 h.check(m?.state==='prepared','the original prepared deck close is unused');
 const job=await configurationRead(h,actor,area,`configuration/jobs/by-key/${c.key}`),intent=assertM8PreparedDeckAbandonIntent(job,actor,area);
 const before=await configurationRead(h,actor,area,`configuration/jobs/${c.jobId}/steps`,{size:100});assertM8PendingPreparedDeckStep(before);
 h.check(!h.state.cliIntents.some(v=>v.command==='sync')&&!h.state.deckSessions.some(v=>v.purpose==='write'),'original prepared execution had no issued write session or CLI sync, independently of the pending step observation');
 const current=await nativeRead(h,actor,area,'services',c.serviceId);
 h.check(current.id===c.serviceId&&current.retries===0,'normal protected current Service confirms the original value before explicit close');
 m.originalCurrentService=structuredClone(current);m.originalPendingStep=structuredClone(before.items[0]);m.originalStepPageSha256=sha256(JSON.stringify(before));m.currentOriginalIntent=structuredClone(intent);h.save();
 const body={revision:intent.revision,executionId:intent.executionId,executionRevision:intent.executionRevision,planRevision:intent.planRevision,planHash:intent.planHash,
  leaseGeneration:intent.leaseGeneration,workflowExecutionId:null,confirmed:true,confirm_name:intent.confirmationName},key=randomUUID();
 m.state='original-abandon-once';m.abandonAttempt={key,body,bodySha256:sha256(JSON.stringify(body)),actorId:actor.user.id,sessionId:actor.sid,state:'prepared'};h.save();
 const response=await h.request(actor,scope(area.cid,area.wid,`configuration/jobs/${c.jobId}/abandon`),'POST',body,{key,expected:[201]}),ack=h.data(response),packet=h.state.requests.at(-1);
 h.check(ack.jobId===c.jobId&&ack.executionId===c.executionId&&ack.clusterId===c.cid&&ack.workspaceId===c.wid&&ack.state==='uncertain'&&ack.completedSteps===0
  &&ack.unresolvedSteps===1&&ack.abandoned===true&&ack.terminalFailureRecorded===true&&ack.originalWorkflowUnchanged===true&&ack.originalNativeReceiptsUnchanged===true,
  'explicit prepared close records uncertainty without claiming or executing a Native operation');
 const closed=await configurationRead(h,actor,area,`configuration/jobs/by-key/${c.key}`);assertM8ClosedPreparedDeckJob(closed,job,intent,response.requestId);
 const after=await configurationRead(h,actor,area,`configuration/jobs/${c.jobId}/steps`,{size:100}),s=after.items?.[0],old=before.items[0];
 h.check(after.items?.length===1&&after.nextCursor===null&&s.id===old.id&&s.executionId===old.executionId&&s.planStepId===old.planStepId&&s.state==='uncertain'
  &&s.revision===old.revision+1&&s.operationId===null&&s.verified===false&&s.startedAt===null&&s.completedAt!==null,
  'only the original pending step is closed; its Native operation remains unbound');
 Object.assign(m.abandonAttempt,{state:'completed',index:packet.index,packetSha256:sha256(JSON.stringify(packet)),requestId:response.requestId,originalJob:closed,intent});
 m.originalClosure={jobId:c.jobId,executionId:c.executionId,state:'uncertain',completedSteps:0,unresolvedSteps:1,preparedNotIssued:true,
  originalApplyReplayed:false,originalCliReplayed:false,originalFailureRetained:true,nativeSuccessClaimed:false,originalNativeUnresolvedRetained:1};m.state='prepared-original-closed';h.save();return closed;
}
/** Exact second closure, independent of the previous C2 partial-execution
 * singleton. HTTP201 or a client uncertain JSON is insufficient by itself. */
export function isM8ProvenPreparedDeckClosurePacket(r,p,index){
 const m=r.deckWireBodyContinuation,a=m?.abandonAttempt,i=a?.intent;
 if(!a||a.state!=='completed'||m.originalPacketCount!==145||m.originalPrefixSha256!==c.prefix||sha256(JSON.stringify(r.requests.slice(0,145)))!==c.prefix
  ||p!==r.requests[index]||index!==a.index||sha256(JSON.stringify(p))!==a.packetSha256||p.state!=='response_observed'||p.status!==201||p.requestId!==a.requestId
  ||p.key!==a.key||p.actorId!==c.actorId||p.sessionId!==c.sid||p.clusterId!==c.cid||p.workspaceId!==c.wid||p.method!=='POST'
  ||p.path!==`/api/v1/clusters/${c.cid}/configuration/jobs/${c.jobId}/abandon`||p.query!==`?workspaceId=${c.wid}`
  ||p.bodySha256!==a.bodySha256||sha256(JSON.stringify(p.body))!==a.bodySha256||JSON.stringify(p.body)!==JSON.stringify(a.body)
  ||p.body.executionId!==c.executionId||p.body.planRevision!==1||p.body.planHash!==c.planHash||p.body.workflowExecutionId!==null
  ||p.body.executionRevision!==i?.executionRevision||p.body.leaseGeneration!==i?.leaseGeneration||p.body.revision!==i?.revision
  ||p.body.confirmed!==true||p.body.confirm_name!==`abandon:${c.jobId}`||Object.keys(p.body).some(k=>!['revision','executionId','executionRevision','planRevision','planHash','leaseGeneration','workflowExecutionId','confirmed','confirm_name'].includes(k))
  ||typeof p.headers?.Cookie!=='string'||!/(?:^|;\s*)kongos_access=[^;\s]+(?:;|$)/.test(p.headers.Cookie)||!p.headers['X-CSRF-Token']||p.headers['X-Idempotency-Key']!==p.key
  ||m.originalPendingStep?.id!==c.jobStepId||m.originalPendingStep.state!=='pending'||m.originalPendingStep.operationId!==null||m.originalCurrentService?.id!==c.serviceId||m.originalCurrentService.retries!==0
  ||m.originalClosure?.preparedNotIssued!==true||m.originalClosure.nativeSuccessClaimed!==false
  ||p.responseData?.jobId!==c.jobId||p.responseData.executionId!==c.executionId||p.responseData.state!=='uncertain'||p.responseData.completedSteps!==0
  ||p.responseData.unresolvedSteps!==1||p.responseData.abandoned!==true||p.responseData.originalWorkflowUnchanged!==true||p.responseData.originalNativeReceiptsUnchanged!==true)return false;
 try{assertM8ClosedPreparedDeckJob(a.originalJob,{revision:p.body.revision},i,p.requestId);}catch{return false;}
 return true;
}
export function assertM8FreshRetry3Plan(value,imported,area){
 const plan=entity(value),s=value?.items?.[0];
 if(plan?.id!==imported.planId||plan.planHash!==imported.planHash||plan.planRevision!==imported.planRevision||plan.clusterId!==area.cid||plan.workspaceId!==area.wid
  ||plan.executionMode!=='direct'||plan.stepCount!==1||plan.nativePacketCount!==1||plan.deleteCount!==0||value.items?.length!==1||value.nextCursor!==null
  ||s.entityType!=='services'||s.nativeId!==c.serviceId||s.objectWorkspaceId!==area.wid||s.action!=='update'||s.referenceOnly===true||s.blockerCodes?.length
  ||s.patch?.length!==1||s.patch[0].op!=='replace'||s.patch[0].path!=='/retries'||s.patch[0].value!==3)throw Error('M8_EXACT_NEW_RETRY3_SINGLE_PLAN_REQUIRED');
 return plan;
}
async function submitFreshDeckApply(h,actor,area,imported){
 const plan=entity(await configurationRead(h,actor,area,`configuration/plans/${imported.planId}`));
 h.check(plan.id===imported.planId&&plan.planHash===imported.planHash&&plan.planRevision===imported.planRevision&&plan.capabilities?.apply===true&&plan.executionMode==='direct','new deck apply uses the current exact source plan');
 const key=randomUUID(),body={planRevision:plan.planRevision,planHash:plan.planHash,revision:plan.revision,driver:'deck',confirmed:true,confirm_name:plan.name};
 const op={key,area:{...area},path:`configuration/plans/${plan.id}/apply`,method:'POST',bodySha256:sha256(JSON.stringify(body)),actorId:actor.user.id,sessionId:actor.sid,state:'prepared'};
 h.state.configurationOperations.push(op);h.save();
 const initial=h.data(await h.request(actor,scope(area.cid,area.wid,op.path),'POST',body,{key,expected:[201]}));assertConfigurationReceipt(h,initial,{actor,area,key,kind:'apply'});
 h.check(initial.state==='running'&&initial.executionCompleted===false&&initial.driver==='deck'&&uuid(initial.executionId)&&uuid(initial.planId)
  &&initial.planId!==plan.id&&initial.planHash===plan.planHash&&initial.planRevision===plan.planRevision&&initial.jobId!==c.jobId,'new actual running receipt exposes genuine driver/execution and its immutable job-local plan');
 Object.assign(op,{jobId:initial.jobId,state:'submitted',receipt:initial});h.save();
 const page=await configurationRead(h,actor,area,`configuration/plans/${initial.planId}/changes`,{size:100}),local=assertM8FreshRetry3Plan(page,initial,area);
 const steps=await configurationRead(h,actor,area,`configuration/jobs/${initial.jobId}/steps`,{size:100}),s=steps.items?.[0];
 h.check(steps.items?.length===1&&steps.nextCursor===null&&s.executionId===initial.executionId&&uuid(s.id)&&s.planStepId===page.items[0].stepId&&s.state==='pending'
  &&s.objectWorkspaceId===area.wid&&s.originalId===c.serviceId&&s.type==='services'&&s.action==='update'&&s.operationId===null&&s.verified===false,'new execution and cloned plan are joined by one real pending typed step before any write session');
 return{receipt:initial,plan:local,operation:op,step:s};
}
export async function m8DeckFreshRetry3Acceptance(h,actors){
 h.assertWritable();const m=h.state.deckWireBodyContinuation,actor=actors.admin,area=actors.direct;
 h.check(m?.state==='prepared-original-closed'&&!h.state.deckAcceptance&&!m.newImportKey,'new retry3 intent starts only after original prepared execution is explicitly closed');
 const current=await nativeRead(h,actor,area,'services',c.serviceId);h.check(current.id===c.serviceId&&current.retries===0,'independent new Service intent begins from current BFF fields, not a replay of retries2');
 const desired=parse(h.state.baseline.yaml),service=desired.services?.find(v=>v.id===c.serviceId);h.check(service?.retries===0,'original deployment material retains the baseline value');service.retries=3;
 const importedDocument=structuredClone(desired),keep={};for(const consumer of importedDocument.consumers??[])for(const credential of consumer.basicauth_credentials??[]){delete credential.password;keep[`credentials:basic-auth:${consumer.id}:${credential.id}`]='keep';}
 const key=randomUUID(),body={scope:'workspace',mode:'merge',yaml:stringify(importedDocument),basicPasswordIntents:keep};
 m.newImportKey=key;m.newImportBodySha256=sha256(JSON.stringify(body));m.newCurrentBefore=structuredClone(current);m.state='new-retry3-preview-once';h.save();
 const imported=await configurationWrite(h,actor,area,'configuration/imports',body,{kind:'import',key});
 h.check(imported.jobId!==c.jobId&&![c.sourcePlanId,c.executionPlanId].includes(imported.planId)&&imported.counts?.create===0&&imported.counts.update===1&&imported.counts.delete===0&&imported.counts.conflict===0,'new independent retry3 preview has exactly one update and no other changes');
 assertM8FreshRetry3Plan(await configurationRead(h,actor,area,`configuration/plans/${imported.planId}/changes`,{size:100}),imported,area);
 m.newImportJobId=imported.jobId;m.state='new-retry3-direct-deck-apply';h.save();const e=await submitFreshDeckApply(h,actor,area,imported);
 m.newApplyJobId=e.receipt.jobId;m.newExecutionId=e.receipt.executionId;h.save();
 const session=assertM8DeckSession(h,h.data(await h.request(actor,scope(area.cid,area.wid,'configuration/deck-sessions'),'POST',
  {jobId:e.receipt.jobId,purpose:'write',planId:e.plan.id,planRevision:e.plan.planRevision,planHash:e.plan.planHash})),{purpose:'write',jobId:e.receipt.jobId,actor,area});
 h.state.deckSessions.push(session);h.state.fixtures.push({...area,type:'configuration_deck_sessions',id:session.id,name:session.id});m.newWriteSessionId=session.id;m.state='new-retry3-standard-sync';h.save();
 await runM8FixedDeckPrivateStderr(h,actor,area,{command:'sync',sessionId:session.id,tokenSecret:session.tokenSecret,stateYaml:stringify(desired)},{jobId:e.receipt.jobId});
 const terminal=await configurationRead(h,actor,area,`configuration/jobs/by-key/${e.receipt.idempotencyKey}`);assertConfigurationReceipt(h,terminal,{actor,area,key:e.receipt.idempotencyKey,jobId:e.receipt.jobId,kind:'apply'});
 h.check(terminal.state==='succeeded'&&terminal.executionCompleted===true&&terminal.driver==='deck'&&terminal.executionId===e.receipt.executionId&&terminal.completedSteps===1
  &&terminal.planId===e.plan.id&&terminal.planRevision===e.plan.planRevision&&terminal.planHash===e.plan.planHash,'actual terminal receipt independently proves original new CLI execution and cloned plan, beyond exit0');
 const steps=await configurationRead(h,actor,area,`configuration/jobs/${terminal.jobId}/steps`,{size:100}),s=steps.items?.[0];
 h.check(steps.items?.length===1&&steps.nextCursor===null&&s.id===e.step.id&&s.executionId===e.receipt.executionId&&s.planStepId===e.step.planStepId&&s.state==='succeeded'
  &&s.verified===true&&uuid(s.operationId)&&s.objectWorkspaceId===area.wid&&s.originalId===c.serviceId,'one exact actual verified Native step closes the new standard runner execution');
 const actual=await nativeRead(h,actor,area,'services',c.serviceId);
 h.check(actual.id===c.serviceId&&actual.retries===3&&['name','host','port','protocol','connect_timeout','read_timeout','write_timeout'].every(k=>JSON.stringify(actual[k])===JSON.stringify(current[k])),
  'current Kong Service proves retries3 and unchanged SDK extra fields');await sixCredentialProxyAcceptance(h,h.state.nativeFixture,'actual-deck-retry3-sync');
 Object.assign(e.operation,{state:'succeeded',receipt:terminal});h.save();
 const revoked=h.data(await h.request(actor,scope(area.cid,area.wid,`configuration/deck-sessions/${session.id}`),'DELETE',{revision:session.revision,confirmed:true,confirm_name:session.id}));
 h.check(revoked.revoked===true,'new actual write session is revoked by its original current-authorized owner');session.revoked=true;
 h.state.deckAcceptance={captureJobId:h.state.deckPoolContinuation.selectedCaptureJobId,importJobId:imported.jobId,applyJobId:terminal.jobId,writeSessionId:session.id,
  nativeOperationId:s.operationId,actualProxyCredentialKinds:6,desiredRetries:3,originalPreparedJobId:c.jobId,originalPreparedState:'uncertain',originalPreparedNotIssued:true};
 m.state='cli-completed';h.public??={};h.public.deckAcceptance={...h.state.deckAcceptance,toolVersion:'1.2.4',toolBinarySha256:'642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed',formatVersion:'1.1',actualDiffPreviouslyProved:true,actualSync:true,CLIExitAloneAccepted:false,nativeAdminBypassRequests:0};h.save();return h.state.deckAcceptance;
}
