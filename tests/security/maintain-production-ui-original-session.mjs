import { existsSync, readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { ProductionHarness } from './lib/production-http-harness.mjs';
import { productionAuthNoCommitResolved } from './lib/production-auth-transport-proof.mjs';
import { PRODUCTION_UI_ACTIONS } from './lib/production-ui-fixtures.mjs';
import { productionSha, canonicalUi, revalidateProductionAuthority, productionReceiptPath } from './lib/production-ui-journal.mjs';
import { assertProductionKnownPrefix, pauseProductionUiIfNeeded, PRODUCTION_UI_PAUSE_CODE } from './lib/production-ui-continuation.mjs';
import { readProductionPrivateFile, readProductionUiReference, durableProductionJson, PRODUCTION_UI_JOURNAL, PRODUCTION_UI_REFERENCE } from './lib/production-ui-storage.mjs';

if(process.env.PRODUCTION_UI_MAINTENANCE_EXCLUSIVE_READY!=='true')throw Error('PRODUCTION_UI_MAINTENANCE_HANDOFF_REQUIRED');
const original=readProductionPrivateFile(PRODUCTION_UI_JOURNAL),j=original.value,ref=readProductionUiReference();
const unissuedOauthFormStop=j.phase==='stopped-without-replay'&&j.nextIndex===73&&j.attempts.length===73&&j.currentReportPath==='artifacts/production/ui-lifecycle-unused-tail-8.json'
 &&j.inFlight===null&&j.armed?.action==='plugin.oauth2.create'&&j.privateFailure?.message.includes('Received: undefined')&&!j.attempts.some(p=>p.action==='plugin.oauth2.create');
if(unissuedOauthFormStop){
 const archive='/tmp/kongos-production-ui-unissued-oauth-default-form-original.json';
 if(existsSync(archive)){if(JSON.parse(readFileSync(archive)).originalJournalSha256!==productionSha(original.bytes))throw Error('PRODUCTION_ORIGINAL_OAUTH_HISTORY_CHANGED');}
 else durableProductionJson(archive,{journal:j,reference:ref,originalJournalSha256:productionSha(original.bytes)},true);
 const abandoned=j.pluginConfigs.oauth2[0].provision_key,replacement=`prod-${randomUUID()}-${randomUUID()}`;
 j.unissuedOauthFormHistory={path:archive,originalJournalSha256:productionSha(original.bytes),originalUnsentBodySha256:productionSha(j.armed.body),nativePostIssued:false,oldUnusedTestSecretRetired:true,oldUnusedTestSecretSha256:productionSha(abandoned),newUnusedTestSecretSha256:productionSha(replacement),productionCredentialDisclosed:false,diagnosticUnusedTestSecretDisclosureRecorded:true};
 j.pluginConfigs.oauth2[0].provision_key=replacement;j.secrets.push(replacement);ref.secrets.push(replacement);j.armed=null;
}
const review=j.reviews.at(-1),cancelledReviewStop=j.phase==='stopped-without-replay'&&j.nextIndex===72&&j.currentReportPath==='artifacts/production/ui-lifecycle-unused-tail-7.json'
 &&j.reviews.filter(r=>r.state!=='succeeded').length===1&&review?.state==='response_unknown'&&review.category==='readonly-authorization-review'&&review.method==='POST'
 &&review.path===`/api/v1/clusters/${j.cid}/authorization/entity-capabilities`&&Object.keys(review.body).join()==='entities';
if(cancelledReviewStop){
 durableProductionJson('/tmp/kongos-production-ui-cancelled-capability-read-original.json',{journal:j,originalJournalSha256:productionSha(original.bytes)},true);
 j.cancelledCapabilityReadHistory={path:'/tmp/kongos-production-ui-cancelled-capability-read-original.json',originalJournalSha256:productionSha(original.bytes),originalKey:review.key,bodySha256:review.bodySha256,businessWriteHandler:false,originalResponseDeliveryProven:false,originalRequestReplayed:false};
 review.state='cancelled-readonly-no-write';review.responseDeliveryProven=false;
}
assertProductionKnownPrefix(j);
const generation=(j.continuations?.length??0)+1;
const reportPath=`artifacts/production/ui-original-session-maintenance-${generation}.json`;
if(existsSync(reportPath))throw Error('PRODUCTION_MAINTENANCE_ALREADY_USED');
const orphanStop=process.env.PRODUCTION_UI_KNOWN_ORPHAN_READY==='true'&&j.phase==='active'&&j.nextIndex===52&&j.currentReportPath==='artifacts/production/ui-lifecycle-unused-tail-5.json'
 &&JSON.parse(readFileSync('artifacts/Production/root-production-ui-known-prefix-orphan-runtime.json')).actualMatchingRunnerPids.length===0;
const fixtureStop=orphanStop||cancelledReviewStop||unissuedOauthFormStop||j.phase==='stopped-without-replay'&&(
  j.nextIndex===118&&j.currentReportPath==='artifacts/production/ui-lifecycle-unused-tail-12.json'&&j.privateFailure?.message==='PRODUCTION_ZERO_UNKNOWN_COMPLETE_PREFIX_REQUIRED'
  ||j.nextIndex===151&&j.currentReportPath==='artifacts/production/ui-lifecycle-unused-tail-16.json'&&j.privateFailure?.message.includes('下一页')&&j.privateFailure.message.includes('locator.isEnabled')
  ||
  j.nextIndex===2&&j.currentReportPath==='artifacts/production/ui-lifecycle-unused-authority-tail.json'
  &&j.privateFailure?.name==='TimeoutError'&&j.privateFailure.message.includes('ant-drawer-mask')&&j.privateFailure.message.includes('选择集群')
  ||j.nextIndex===8&&j.currentReportPath==='artifacts/production/ui-lifecycle-unused-tail-2.json'
  &&j.privateFailure?.message.includes('ant-select-dropdown')&&j.privateFailure.message.includes('rate-limiting')
  ||j.nextIndex===9&&j.currentReportPath==='artifacts/production/ui-lifecycle-unused-tail-3.json'
  &&j.privateFailure?.message.includes('strict mode violation')&&j.privateFailure.message.includes('编辑说明')
  ||j.nextIndex===12&&j.currentReportPath==='artifacts/production/ui-lifecycle-unused-tail-4.json'
  &&j.privateFailure?.message.includes('consistent-hashing')&&j.privateFailure.message.includes('round-robin'));
if(j.phase!=='paused-safe-prefix'&&!fixtureStop)throw Error('PRODUCTION_ONLY_EXACT_KNOWN_FIXTURE_STOP_OR_SESSION_PAUSE');
const oldReportBytes=readFileSync(j.currentReportPath),oldReport=JSON.parse(oldReportBytes);
if(oldReport.unknownUiWrites!==0||oldReport.origin!==j.origin||oldReport.clusterId!==j.cid||oldReport.workspaceId!==j.wid)throw Error('PRODUCTION_KNOWN_ORIGINAL_REPORT_REQUIRED');
const maintenanceHistory=`/tmp/kongos-production-ui-session-maintenance-${generation}-original.json`;
if(existsSync(maintenanceHistory)){
 const prior=JSON.parse(readFileSync(maintenanceHistory));
 if(prior.originalJournalSha256!==productionSha(original.bytes)||prior.originalReportSha256!==productionSha(oldReportBytes))throw Error('PRODUCTION_ORIGINAL_MAINTENANCE_HISTORY_CHANGED');
}else durableProductionJson(maintenanceHistory,{journal:j,reference:ref,report:oldReport,originalJournalSha256:productionSha(original.bytes),originalReportSha256:productionSha(oldReportBytes)},true);
const h=new ProductionHarness({resume:true}),actor=h.state.sessions.bootstrap;
if(actor.sid!==j.sessionId||actor.user.id!==j.actorId||h.state.requests.some(p=>p.state!=='response_observed'&&!productionAuthNoCommitResolved(p,h.state.authNoCommitProofs)))throw Error('PRODUCTION_ORIGINAL_ACTOR_REQUIRED');
const start=h.state.requests.length;
await h.refresh(actor);
const me=await h.request(actor,'/api/v1/auth/me');
// The entity catalog revision changes after a write; the full grants must not.
if(canonicalUi(me.data.user.capabilities)!==canonicalUi(j.session.user.capabilities))throw Error('PRODUCTION_ORIGINAL_GRANTS_CHANGED');
const receipts=[];
for(const a of j.attempts){
  const result=await h.request(actor,productionReceiptPath(j,a)),r=result.data,e=a.expected,id=e.entityId??a.responseData?.entity?.id;
  if(r.id!==a.receiptId||r.actor_id!==j.actorId||r.cluster_id!==j.cid||r.workspace_id!==j.wid||r.entity_type!==e.entityType||r.entity_id!==id||r.action!==e.mutationAction||r.state!=='succeeded'||!r.remote_started||!r.remote_completed||r.error_code)throw Error('PRODUCTION_ORIGINAL_RECEIPT_CHANGED');
  receipts.push({originalRequestId:a.requestId,receiptId:r.id,actualReadRequestId:result.requestId,action:a.action});
}
if(fixtureStop&&j.nextIndex===12){
 const a=j.attempts.at(-1),result=await h.request(actor,`/api/v1/clusters/${j.cid}/entities/upstreams/${a.expected.entityId}?workspaceId=${j.wid}`);
 if(result.data.entity.id!==a.expected.entityId||result.data.entity.algorithm!=='consistent-hashing')throw Error('PRODUCTION_ACTUAL_PROPAGATED_UPSTREAM_REQUIRED');
 j.bindings.upstreams={...j.bindings.upstreams,entity:result.data.entity,editRequestId:a.requestId};
}
let checkpointBytes=original.bytes;
if(fixtureStop){
  // Keep the failed report and original journal intact in their history. This
  // working checkpoint only resumes unused actions after actual receipt reads.
  j.fixtureStopHistory={path:`/tmp/kongos-production-ui-session-maintenance-${generation}-original.json`,originalJournalSha256:productionSha(original.bytes),originalReportPath:j.currentReportPath,originalReportSha256:productionSha(oldReportBytes),actualReceipts:receipts};
  j.progress={checks:oldReport.checks.filter(c=>c.passed),screenshots:oldReport.screenshots,reads:oldReport.reads,domActions:oldReport.domActions,coverage:oldReport.coverage};
  j.phase='active';j.stopCode=null;
  pauseProductionUiIfNeeded(j,()=>{},Date.now(),true);
  const path=`artifacts/production/ui-lifecycle-known-fixture-checkpoint-${generation}.json`;
  const checkpointReport={...oldReport,checks:j.progress.checks,failed:0,allPassed:false,journalPhase:'paused-safe-prefix',phase:PRODUCTION_UI_PAUSE_CODE,originalFailurePreserved:true,actualReceipts:receipts};
  durableProductionJson(path,checkpointReport,true,0o644);j.currentReportPath=path;
  durableProductionJson(PRODUCTION_UI_JOURNAL,j);checkpointBytes=readFileSync(PRODUCTION_UI_JOURNAL);
}
const currentOldReportBytes=readFileSync(j.currentReportPath);
const writes=h.state.requests.slice(start);
if(writes.length!==1||writes[0].path!=='/api/v1/auth/refresh'||writes[0].status!==201||actor.sid!==j.sessionId)throw Error('PRODUCTION_ONLY_ONE_REAL_REFRESH');
const report={performedAt:new Date().toISOString(),allPassed:true,failed:0,unknownWrites:0,authWrites:1,businessWrites:0,loginWrites:0,nativeWrites:0,actorId:j.actorId,sessionId:j.sessionId,origin:j.origin,clusterId:j.cid,workspaceId:j.wid,originalUiJournalSha256:productionSha(checkpointBytes),currentSessionVerified:true,signedAccessVerified:true,currentUserProven:true,sessionExpiresAt:actor.expiresAt,actualRefreshRequestId:writes[0].requestId,actualReceipts:receipts,originalFailedReportRetained:fixtureStop};
durableProductionJson(reportPath,report,true,0o644);
const next={...ref,phase:'unused-tail-ready',session:structuredClone(actor),requests:structuredClone(h.state.requests),authNoCommitProofs:structuredClone(h.state.authNoCommitProofs??[]),secrets:[...new Set([...ref.secrets,...h.state.secrets])],uiUnusedTailHandoff:{version:1,phase:'ready',exclusiveRuntimeOwner:'production-ui',generation,testTag:j.tag,origin:j.origin,clusterId:j.cid,workspaceId:j.wid,actorId:j.actorId,sessionId:j.sessionId,nextIndex:j.nextIndex,originalUiJournalSha256:productionSha(checkpointBytes),originalReportSha256:productionSha(currentOldReportBytes),approvedActions:PRODUCTION_UI_ACTIONS.slice(j.nextIndex),renewalReportPath:reportPath,renewalReportSha256:productionSha(readFileSync(reportPath))}};
durableProductionJson(PRODUCTION_UI_REFERENCE,next);h.save();
console.log(JSON.stringify({allPassed:true,generation,originalKnownPrefix:j.nextIndex,unusedActions:PRODUCTION_UI_ACTIONS.length-j.nextIndex,originalRequestsReplayed:0}));
