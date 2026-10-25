import{readFileSync}from'node:fs';
import{readM8Reference,sha256,entity}from'./lib/m8-harness.mjs';
import{retainM8History}from'./lib/m8-private-history.mjs';
import{M8DeckSetContinuedHarness,assertM8UnknownSyncOriginal}from'./lib/m8-deck-set-continuation.mjs';
import{m8AllWritesAuditAcceptance}from'./lib/m8-audit-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_UNUSED_MANUAL_AFTER_EDGE_READY!=='true')throw Error('M8_UNUSED_MANUAL_AFTER_EDGE_RELEASE_REQUIRED');
const r=readM8Reference(),oldPath='artifacts/M8/manual-ui.json',oldBytes=readFileSync(oldPath),old=JSON.parse(oldBytes),httpPath='artifacts/M8/security-live-audit-chain-final.json',httpBytes=readFileSync(httpPath),previous=JSON.parse(httpBytes);
assertM8UnknownSyncOriginal(r);
if(sha256(oldBytes)!=='cab159c335cb99be045657ceb46f7703d30605e02321665efc9bd8b262941914'||sha256(httpBytes)!=='0935ae269bf9610a44ea1476721d21ff2730f1dd380ab4dd163e18201d18ef28'
 ||old.successfulUiWrites!==0||old.unknownUiWrites!==0||old.screenshots.length!==0||r.phase!=='stopped-ui-no-replay'||r.requests.length!==175
 ||sha256(JSON.stringify(r.requests))!=='4ca583a5ebc139809fbcfd6f41cc641efb3833fedf8753c528cb292f287cbb77'||r.manualUiJournal?.attempts.length!==0||r.manualUiJournal.inFlight!==null||r.manualUiJournal.nextIndex!==0||r.unusedManualAfterEdge)throw Error('M8_EXACT_ZERO_INTENT_MANUAL_PREFLIGHT_FAILURE_REQUIRED');
const h=new M8DeckSetContinuedHarness({resume:true,reference:r}),output='artifacts/M8/security-live-manual-edge-ready.json';let error;
try{
 const history=retainM8History(r,'manualPreflightOriginalHistory');r.unusedManualAfterEdge={version:1,state:'preparing',originalCount:175,originalPrefix:sha256(JSON.stringify(r.requests)),originalFailure:{path:oldPath,sha256:sha256(oldBytes)},completeOriginalHistory:history,originalManualJournal:structuredClone(r.manualUiJournal),originalManualHistory:structuredClone(r.manualUiHistory),originalManualHandoff:structuredClone(r.manualUiHandoff),originalBusinessIntents:0,originalUnknownIntents:0};
 delete r.manualUiJournal;delete r.manualUiHistory;h.save({phase:'unused-manual-after-edge-preparation',inFlight:null});
 h.checks=previous.checks.filter(v=>v.passed);h.public=Object.fromEntries(Object.entries(previous).filter(([k])=>!['performedAt','checks','passed','failed','allPassed','successfulWrites','unknownWrites','businessWrites','authenticationWrites','fixtures','currentSessionHandoff'].includes(k)));
 const current=[];
 for(const[role,label]of[['admin','admin'],['owner','owner'],['readonly','read-only']]){
  const actor=r.sessions[label],prior={id:actor.user.id,sid:actor.sid};const data=h.data(await h.request(actor,'/auth/refresh','POST',{}, {renew:false}));actor.user=data.user;actor.csrf=actor.cookie.split('; ').find(v=>v.startsWith('kongos_csrf='))?.slice(12);h.updateSessionIdentity(actor);h.cookies(actor.cookie);h.remember({csrfToken:actor.csrf});h.save();
  h.check(actor.user.id===prior.id&&actor.sid===prior.sid&&actor.expiresAt>Date.now()+600000,'normal actual original actor SID maintained before wholly unused browser intents');const me=h.data(await h.request(actor,'/auth/me','GET',undefined,{renew:false}));h.check(me.user?.id===actor.user.id&&me.csrfToken===actor.csrf,'protected current user proves actual renewed browser actor');
  current.push({role,actorId:actor.user.id,sessionId:actor.sid,sessionExpiresAt:new Date(actor.expiresAt).toISOString(),remainingSeconds:Math.floor((actor.expiresAt-Date.now())/1000),currentUserProven:true});
 }
 const coverage=await m8AllWritesAuditAcceptance(h,{admin:r.sessions.admin});h.check(coverage.allCovered&&coverage.failureClosureWrites===3&&coverage.nativeNotStartedUnknownCliClosureWrites===1&&coverage.preparedNotIssuedClosureWrites===1&&coverage.recoveredSuccessfulCommits===1,'all original writes and three new normal renewals remain actually audited');
 r.manualUiHandoff={...r.unusedManualAfterEdge.originalManualHandoff,manualReportPath:'artifacts/M8/manual-ui-shared-edge.json',securityReportPath:output,securityReportSha256:undefined,currentSessions:current};r.unusedManualAfterEdge.state='current-sessions-ready';
 h.public.currentSessionHandoff=current;h.public.originalManualFailureRetained=true;h.public.originalManualIntentsReplayed=0;h.public.browserIntentsWhollyUnused=true;h.save();
}catch(e){error=e;}
process.exitCode=h.finish(error,output);if(!error){r.manualUiHandoff.securityReportSha256=sha256(readFileSync(output));h.save();}
