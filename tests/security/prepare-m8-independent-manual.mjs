import{randomUUID}from'node:crypto';
import{readFileSync}from'node:fs';
import{readM8Reference,sha256}from'./lib/m8-harness.mjs';
import{retainM8History}from'./lib/m8-private-history.mjs';
import{M8DeckSetContinuedHarness,assertM8UnknownSyncOriginal}from'./lib/m8-deck-set-continuation.mjs';
import{M8_CONSUMED_REVIEW_DOWNLOAD as c,isM8ProvenConsumedUnknownDownload}from'./lib/m8-consumed-review-download.mjs';
import{m8AllWritesAuditAcceptance}from'./lib/m8-audit-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_INDEPENDENT_MANUAL_READY!=='true')throw Error('M8_INDEPENDENT_MANUAL_PREPARATION_RELEASE_REQUIRED');
const r=readM8Reference(),previous=JSON.parse(readFileSync('artifacts/M8/security-live-manual-edge-ready.json')),failedBytes=readFileSync('artifacts/M8/manual-ui-shared-edge.json'),failed=JSON.parse(failedBytes);
assertM8UnknownSyncOriginal(r);
if(r.phase!=='original-download-server-consumed-client-unconfirmed'||r.inFlight!==null||r.requests.length!==181||sha256(JSON.stringify(r.requests))!==c.prefixSha256
 ||sha256(failedBytes)!=='d31e9d68af10e7176049ff3c18582c2d8e562d46e303df4a3106326539033f0e'||failed.successfulUiWrites!==2||failed.unknownUiWrites!==1
 ||r.manualUiJournal?.attempts.length!==3||r.manualUiJournal.attempts[0].state!=='succeeded'||r.manualUiJournal.attempts[1].state!=='succeeded'||!isM8ProvenConsumedUnknownDownload(r,r.requests[180],180)||r.independentManualPreparation)throw Error('M8_EXACT_RECORDED_SERVER_CONSUMPTION_REQUIRED');
const h=new M8DeckSetContinuedHarness({resume:true,reference:r}),output='artifacts/M8/security-live-independent-manual-ready.json';let error;
try{
 const history=retainM8History(r,'manualConsumedDownloadOriginalHistory');r.independentManualPreparation={version:1,state:'preparing',originalCount:181,originalPrefix:c.prefixSha256,originalFailureSha256:sha256(failedBytes),completeOriginalHistory:history,originalManualJournal:structuredClone(r.manualUiJournal),originalManualHistory:structuredClone(r.manualUiHistory),originalHandoff:structuredClone(r.manualUiHandoff),originalRequestReplayed:false,clientDeliveryProven:false};
 delete r.manualUiJournal;delete r.manualUiHistory;h.save({phase:'independent-manual-preparation',inFlight:null});
 h.checks=previous.checks.filter(v=>v.passed);h.public=Object.fromEntries(Object.entries(previous).filter(([k])=>!['performedAt','checks','passed','failed','allPassed','successfulWrites','unknownWrites','businessWrites','authenticationWrites','fixtures','currentSessionHandoff'].includes(k)));
 const current=[];
 for(const[role,label]of[['admin','admin'],['owner','owner'],['readonly','read-only']]){
  const actor=r.sessions[label],prior={id:actor.user.id,sid:actor.sid},data=h.data(await h.request(actor,'/auth/refresh','POST',{}, {renew:false}));actor.user=data.user;actor.csrf=actor.cookie.split('; ').find(v=>v.startsWith('kongos_csrf='))?.slice(12);h.updateSessionIdentity(actor);h.cookies(actor.cookie);h.remember({csrfToken:actor.csrf});h.save();
  h.check(actor.user.id===prior.id&&actor.sid===prior.sid&&actor.expiresAt>Date.now()+600000,'normal same-SID maintenance grants no fabricated lifetime or new identity');const me=h.data(await h.request(actor,'/auth/me','GET',undefined,{renew:false}));h.check(me.user?.id===actor.user.id&&me.csrfToken===actor.csrf,'protected current user proves the actual independent browser actor');current.push({role,actorId:actor.user.id,sessionId:actor.sid,sessionExpiresAt:new Date(actor.expiresAt).toISOString(),remainingSeconds:Math.floor((actor.expiresAt-Date.now())/1000),currentUserProven:true});
 }
 const coverage=await m8AllWritesAuditAcceptance(h,{admin:r.sessions.admin});h.check(coverage.allCovered&&coverage.coveredWrites===coverage.successfulWrites+coverage.recoveredSuccessfulCommits+coverage.serverConsumedDeliveryUnconfirmedWrites&&coverage.serverConsumedDeliveryUnconfirmedWrites===1,'confirmed original writes and independently proven server consumption are audited separately from client delivery');
 r.manualUiHandoff={...r.independentManualPreparation.originalHandoff,manualNamePrefix:`${r.testTag}-fresh-${randomUUID().slice(0,8)}`,manualReportPath:'artifacts/M8/manual-ui-independent.json',securityReportPath:output,securityReportSha256:undefined,currentSessions:current};r.independentManualPreparation.state='current-sessions-ready';
 Object.assign(h.public,{currentSessionHandoff:current,historicalConsumedDownloadDeliveryUnconfirmed:1,unresolvedServerSideWrites:0,originalManualFailureRetained:true,originalManualIntentsReplayed:0,newIndependentTwelveIntents:true});h.save();
}catch(e){error=e;}
process.exitCode=h.finish(error,output);if(!error){r.manualUiHandoff.securityReportSha256=sha256(readFileSync(output));h.save();}
