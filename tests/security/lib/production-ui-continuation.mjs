import { PRODUCTION_UI_ACTIONS } from './production-ui-fixtures.mjs';
import { canonicalUi, productionSha, productionUuid } from './production-ui-journal.mjs';
import { productionAuthNoCommitResolved } from './production-auth-transport-proof.mjs';
const requireTail=(condition,code)=>{if(!condition)throw Error(code);};
export const PRODUCTION_UI_PAUSE_CODE='PRODUCTION_SAFE_PREFIX_SESSION_WINDOW';
export function assertProductionKnownPrefix(journal){
  requireTail(Number.isInteger(journal.nextIndex)&&journal.nextIndex>=0&&journal.nextIndex<PRODUCTION_UI_ACTIONS.length&&journal.inFlight===null&&journal.armed===null
    &&journal.attempts.length===journal.nextIndex&&journal.attempts.every((row,index)=>row.index===index&&row.action===PRODUCTION_UI_ACTIONS[index]&&row.category==='dom-business'&&row.state==='succeeded'
      &&productionUuid(row.key)&&productionUuid(row.requestId)&&productionUuid(row.receiptId)&&productionUuid(row.receiptRequestId)&&row.actorId===journal.actorId&&row.sessionId===journal.sessionId&&row.clusterId===journal.cid&&row.workspaceId===journal.wid)
    &&new Set(journal.attempts.map(row=>row.key)).size===journal.attempts.length&&journal.reviews.every(row=>row.state==='succeeded'||row.state==='cancelled-readonly-no-write'&&row.category==='readonly-authorization-review'), 'PRODUCTION_ZERO_UNKNOWN_COMPLETE_PREFIX_REQUIRED');
}
export function pauseProductionUiIfNeeded(journal,persist,now=Date.now(),forceWindowCheckpoint=false){
  requireTail(journal.phase==='active'&&journal.inFlight===null&&journal.armed===null,'PRODUCTION_PAUSE_ONLY_AT_COMPLETED_DOM_BOUNDARY');
  if(!forceWindowCheckpoint&&Date.parse(journal.session.expiresAt)-now>=120000)return false;
  assertProductionKnownPrefix(journal);
  journal.phase='paused-safe-prefix';journal.stopCode=PRODUCTION_UI_PAUSE_CODE;
  journal.checkpoint={version:1,nextIndex:journal.nextIndex,attemptsSha256:productionSha(journal.attempts),reviewsSha256:productionSha(journal.reviews),bindingsSha256:productionSha(journal.bindings),progressSha256:productionSha(journal.progress),observedAt:new Date(now).toISOString(),sessionExpiresAt:journal.session.expiresAt,reason:forceWindowCheckpoint?'bounded-runner-window':'session-window'};
  persist(journal);return true;
}
export function prepareProductionUnusedTail(journal,journalBytes,oldReport,oldReportBytes,reference,renewal,renewalBytes,now=Date.now()){
  requireTail(journal.phase==='paused-safe-prefix'&&journal.stopCode===PRODUCTION_UI_PAUSE_CODE,'PRODUCTION_EXPLICIT_SESSION_PAUSE_REQUIRED');assertProductionKnownPrefix(journal);
  const checkpoint=journal.checkpoint,h=reference.uiUnusedTailHandoff,session=reference.session,generation=(journal.continuations?.length??0)+1;
  requireTail(checkpoint?.version===1&&checkpoint.nextIndex===journal.nextIndex&&checkpoint.attemptsSha256===productionSha(journal.attempts)&&checkpoint.reviewsSha256===productionSha(journal.reviews)
    &&checkpoint.bindingsSha256===productionSha(journal.bindings)&&checkpoint.progressSha256===productionSha(journal.progress)&&checkpoint.sessionExpiresAt===journal.session.expiresAt,'PRODUCTION_IMMUTABLE_CHECKPOINT_REQUIRED');
  requireTail(reference.version===1&&reference.milestone==='M0-M8-production-ui'&&reference.phase==='unused-tail-ready'&&h?.version===1&&h.phase==='ready'&&h.exclusiveRuntimeOwner==='production-ui'
    &&h.generation===generation&&generation<=32&&h.testTag===journal.tag&&h.origin===journal.origin&&h.clusterId===journal.cid&&h.workspaceId===journal.wid
    &&h.actorId===journal.actorId&&h.sessionId===journal.sessionId&&h.nextIndex===journal.nextIndex&&h.originalUiJournalSha256===productionSha(journalBytes)
    &&h.originalReportSha256===productionSha(oldReportBytes)&&canonicalUi(h.approvedActions)===canonicalUi(PRODUCTION_UI_ACTIONS.slice(journal.nextIndex)),'PRODUCTION_EXACT_UNUSED_TAIL_HANDOFF_REQUIRED');
  requireTail(oldReport.allPassed===false&&oldReport.failed===0&&oldReport.unknownUiWrites===0&&oldReport.journalPhase==='paused-safe-prefix'&&oldReport.testTag===journal.tag&&oldReport.origin===journal.origin
    &&oldReport.clusterId===journal.cid&&oldReport.workspaceId===journal.wid&&canonicalUi(oldReport.plannedActions)===canonicalUi(PRODUCTION_UI_ACTIONS),'PRODUCTION_ORIGINAL_PAUSED_REPORT_REQUIRED');
  requireTail(h.renewalReportPath===`artifacts/production/ui-original-session-maintenance-${generation}.json`&&h.renewalReportSha256===productionSha(renewalBytes)
    &&renewal.allPassed===true&&renewal.failed===0&&renewal.unknownWrites===0&&renewal.authWrites===1&&renewal.businessWrites===0&&renewal.loginWrites===0&&renewal.nativeWrites===0
    &&renewal.actorId===journal.actorId&&renewal.sessionId===journal.sessionId&&renewal.origin===journal.origin&&renewal.clusterId===journal.cid&&renewal.workspaceId===journal.wid
    &&renewal.originalUiJournalSha256===h.originalUiJournalSha256&&renewal.currentSessionVerified===true&&renewal.signedAccessVerified===true&&renewal.currentUserProven===true
    &&renewal.sessionExpiresAt===session?.expiresAt,'PRODUCTION_REAL_SAME_SID_MAINTENANCE_REQUIRED');
  requireTail(session?.user?.id===journal.actorId&&session.sid===journal.sessionId&&session.user.capabilities?.platformAdmin===true&&canonicalUi(session.user.capabilities)===canonicalUi(journal.session.user.capabilities)
    &&session.currentSessionVerified===true&&session.signedAccessVerified===true&&session.currentUserProven===true&&typeof session.cookie==='string'&&session.cookie!==journal.session.cookie
    &&typeof session.csrf==='string'&&session.csrf.length>=16&&Date.parse(session.expiresAt)-now>=300000&&Date.parse(session.expiresAt)-now<=900000,'PRODUCTION_CURRENT_RENEWED_ORIGINAL_IDENTITY_REQUIRED');
  requireTail(Array.isArray(reference.requests)&&productionSha(reference.requests.slice(0,journal.history.originalRequestCount))===journal.history.originalRequestPrefixSha256
    &&reference.requests.every(row=>!['prepared','response_unknown'].includes(row.state)||productionAuthNoCommitResolved(row,reference.authNoCommitProofs))&&Array.isArray(reference.secrets),'PRODUCTION_ORIGINAL_SECURITY_PREFIX_REQUIRED');
  const next=structuredClone(journal);next.phase='active';next.stopCode=null;next.actorProven=false;next.session=structuredClone(session);next.priorKeys=[...new Set([...journal.priorKeys,...reference.requests.map(row=>row.key)])];delete next.checkpoint;
  const marker={version:1,generation,nextIndex:journal.nextIndex,originalUiJournalSha256:h.originalUiJournalSha256,originalReportSha256:h.originalReportSha256,renewalReportPath:h.renewalReportPath,renewalReportSha256:h.renewalReportSha256,externalNormalSessionRenewalWrites:1,startedAt:new Date(now).toISOString()};
  next.continuations=[...(next.continuations??[]),marker];
  return {journal:next,marker,history:{version:1,purpose:'production-ui-unused-tail-original-history',originalJournal:structuredClone(journal),originalReport:structuredClone(oldReport),originalJournalBytesSha256:productionSha(journalBytes),originalReportBytesSha256:productionSha(oldReportBytes),renewalReport:structuredClone(renewal)}};
}
export function productionActionAlreadyCompleted(journal,action){
  const index=PRODUCTION_UI_ACTIONS.indexOf(action);requireTail(index>=0,'PRODUCTION_UNKNOWN_ACTION');
  if(index<journal.nextIndex){requireTail(journal.attempts[index]?.state==='succeeded'&&journal.attempts[index].action===action,'PRODUCTION_PRIOR_ACTION_NOT_PROVEN');return true;}
  requireTail(index===journal.nextIndex,'PRODUCTION_ONLY_NEXT_UNUSED_ACTION');return false;
}
