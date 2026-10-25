import{readFileSync}from'node:fs';
import{M8Harness,readM8Reference,sha256,durableJson}from'./lib/m8-harness.mjs';
import{retainM8History}from'./lib/m8-private-history.mjs';
import{M8_DECK_WIRE_BODY_CONTINUATION,assertM8DeckWireBodyCheckpoint,maintainM8PreparedDeckOriginalSession,closeM8OriginalPreparedDeck}from'./lib/m8-deck-wire-body-continuation.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_PREPARED_DECK_CLOSE_READY!=='true')throw Error('M8_PREPARED_DECK_CLOSE_ONLY_RELEASE_REQUIRED');
const c=M8_DECK_WIRE_BODY_CONTINUATION,output='artifacts/M8/deck-prepared-execution-close.json',r=readM8Reference();
assertM8DeckWireBodyCheckpoint(r,readFileSync(c.failurePath),readFileSync(c.diagnosisPath),readFileSync(c.sdkProofPath));
const h=new M8Harness({resume:true,reference:r});let error,report;
try{
 // Close-only intentionally requires no future SDK product repair. The
 // original already-initialized ledger supports current authorized abandon.
 const history=retainM8History(r,'deckWireBodyContinuationHistory');
 r.deckWireBodyContinuation={version:1,state:'prepared',history,originalPacketCount:145,originalPrefixSha256:c.prefix,previousFailurePath:c.failurePath,previousFailureSha256:c.failureSha256,
  diagnosisPath:c.diagnosisPath,diagnosisSha256:c.diagnosisSha256,sdkProofPath:c.sdkProofPath,sdkProofSha256:c.sdkProofSha256,originalApplyReplayed:false,originalCliReplayed:false};h.save({phase:'deck-prepared-close-only',inFlight:null});
 await maintainM8PreparedDeckOriginalSession(h,r.sessions.admin);
 await closeM8OriginalPreparedDeck(h,{admin:r.sessions.admin,direct:r.scopes.direct});
 const m=r.deckWireBodyContinuation,auth=m.sessionMaintenance,abandon=m.abandonAttempt,suffix=r.requests.slice(145);
 h.check(suffix.length===auth.normalAuthenticationWrites+1&&suffix.every(p=>p.path==='/api/v1/auth/refresh'||p.path===`/api/v1/clusters/${c.cid}/configuration/jobs/${c.jobId}/abandon`),'close-only window has only necessary normal auth and the one original abandonment');
 h.check(sha256(JSON.stringify(r.requests.slice(0,145)))===c.prefix&&r.cliIntents.length===4&&r.deckSessions.length===3,'original145 packets, all original CLI intents and all issued read sessions remain unchanged');
 report={version:1,milestone:'M8',performedAt:new Date().toISOString(),allPassed:true,passed:h.checks.filter(v=>v.passed).length,failed:0,checks:h.checks,
  original145PrefixUnchanged:true,original145PrefixSha256:c.prefix,originalFailurePath:c.failurePath,originalFailureSha256:c.failureSha256,originalReadonlyDiagnosisSha256:c.diagnosisSha256,
  jobId:c.jobId,executionId:c.executionId,executionPlanId:c.executionPlanId,planRevision:1,planHash:c.planHash,state:'uncertain',completedSteps:0,unresolvedSteps:1,
  preparedNotIssued:true,nativeSuccessClaimed:false,originalNativeUnresolvedRetained:1,failureClosureWrites:1,newNativeWrites:0,newCliIntents:0,newDeckSessions:0,newPreviewOrApplyWrites:0,
  abandonRequestId:abandon.requestId,abandonKey:abandon.key,originalKey:c.key,abandonPacketSha256:abandon.packetSha256,
  normalSessionMaintenance:{normalAuthenticationWrites:auth.normalAuthenticationWrites,requestIds:auth.requestIds,auditEventIds:auth.auditEventIds,sameActor:auth.sameActor,sameSID:auth.sameSID,
   currentUserRequestId:auth.currentUserRequestId,sessionExpiresAt:new Date(auth.currentExpiresAt).toISOString(),remainingSeconds:Math.floor((auth.currentExpiresAt-Date.now())/1000)},
  originalApplyReplayed:false,originalCliReplayed:false,httpAcceptanceComplete:false,actualM8Complete:false,privateReferenceRetained:true,secretsPublished:false};
 h.save({phase:'deck-prepared-closed',inFlight:null});
}catch(e){error=e;h.save({phase:r.inFlight!==null?'stopped-unknown':'stopped-failure'});report={version:1,milestone:'M8',allPassed:false,passed:h.checks.filter(v=>v.passed).length,failed:1,
  checks:[...h.checks,{name:e.safeEvidenceMessage?e.message:'Original prepared close stopped; private original packet retained',passed:false}],original145PrefixUnchanged:sha256(JSON.stringify(r.requests.slice(0,145)))===c.prefix,
  originalFailurePath:c.failurePath,originalFailureSha256:c.failureSha256,httpAcceptanceComplete:false,actualM8Complete:false,privateReferenceRetained:true,secretsPublished:false};}
durableJson(output,report,0o644,true);
if(!error){r.deckWireBodyContinuation.closeOnlyReport={path:output,sha256:sha256(readFileSync(output)),state:'completed'};h.save();}
console.log(JSON.stringify({path:output,sha256:sha256(readFileSync(output)),allPassed:report.allPassed,passed:report.passed,failed:report.failed,normalAuthenticationWrites:report.normalSessionMaintenance?.normalAuthenticationWrites??null,failureClosureWrites:report.failureClosureWrites??null}));
if(error)process.exitCode=1;
