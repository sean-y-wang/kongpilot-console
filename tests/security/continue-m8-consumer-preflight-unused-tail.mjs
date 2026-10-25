import { readFileSync } from 'node:fs';
import { M8Harness,readM8Reference,sha256,scope } from './lib/m8-harness.mjs';
import { retainM8History } from './lib/m8-private-history.mjs';
import { M8_CONSUMER_RETRY,readM8ConsumerRetryLedger,assertM8ConsumerZeroLedger,assertM8ConsumerProtectedPreview } from './lib/m8-consumer-preflight-retry.mjs';
import { finishM8FiveClassRecovery,directImportRollbackAcceptance,approvalV2AndMetadataAcceptance } from './lib/m8-transfer-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_CONSUMER_UNUSED_TAIL_READY!=='true')throw Error('M8_CONSUMER_UNUSED_TAIL_RELEASE_REQUIRED');
const c=M8_CONSUMER_RETRY,failedPath='artifacts/M8/security-live-consumer-preflight-transfer-continuation.json',failedBytes=readFileSync(failedPath),previous=JSON.parse(failedBytes),r=readM8Reference(),packet=r.requests[70];
const prefix72='9747237b904068cc21ec4ce3cf87a2033098ee31dc4f2c2c3d73664b44425230';
if(sha256(failedBytes)!=='29579cc9cbc3afd2fc1064932ccfcb420df7c98b988b0489c0e09730a5ce8882'||previous.passed!==682||previous.failed!==1||previous.unknownWrites!==0
  ||r.requests.length!==72||sha256(JSON.stringify(r.requests))!==prefix72||sha256(JSON.stringify(r.requests.slice(0,71)))!==c.prefixSha256
  ||sha256(JSON.stringify(packet))!==c.packetSha256||r.inFlight!==null||r.phase!=='stopped-failure'||r.consumerPreflightRetry?.state!=='readonly-preflight'
  ||r.consumerPreflightUnusedTail||r.fiveClassRecovery||r.directTransfer||r.approvalTransfer||r.requests.some(p=>p.state!=='response_observed')
  ||r.requests[71].path!=='/api/v1/auth/refresh'||r.requests[71].status!==201||r.requests[71].actorId!==c.actorId||r.requests[71].sessionId!==c.sid
  ||r.recycleEntries.length!==2||r.sessions.admin.user.id!==c.actorId||r.sessions.admin.sid!==c.sid)throw Error('M8_EXACT_NO_BUSINESS_REPLAY_CHECKPOINT_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
 const history=retainM8History(r,'consumerPreflightUnusedTailHistory');
 r.consumerPreflightUnusedTail={version:1,state:'readonly-preflight',history,originalPacketCount:72,originalPrefixSha256:prefix72,original71PrefixSha256:c.prefixSha256,
   failurePath:failedPath,failureSha256:sha256(failedBytes),originalKey:c.key,deliberateSideEffectFreeRetry:true,unknownReplay:false};
 h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'consumer-typed-preview-unused-tail',inFlight:null});
 const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign},actor=actors.admin,area=actors.direct;
 const me=h.data(await h.request(actor,'/auth/me'));h.check(me.user.id===c.actorId&&actor.sid===c.sid,'current original actor/SID is authenticated without replacing the original restoration intent');
 const preview=h.data(await h.request(actor,scope(area.cid,area.wid,`recycle-bin/${c.entryId}`)));assertM8ConsumerProtectedPreview(preview);
 h.check(true,'current protected archive typed root and seven nodes are exact while internal node keys remain redacted');
 const proof=readM8ConsumerRetryLedger();assertM8ConsumerZeroLedger(proof,r.nativeFixture);
 r.consumerPreflightUnusedTail.currentZeroLedgerProof=proof;r.consumerPreflightUnusedTail.state='ready-original-once';h.save();
 const result=h.data(await h.request(actor,packet.path.slice('/api/v1'.length)+packet.query,'POST',packet.body,{key:packet.key}));
 h.check(result.entryId===c.entryId&&result.state==='restored'&&result.restored.length===7&&result.restored.every(row=>row.originalId===row.restoredId),'original preflight-only key restores all seven exact original Consumer and credential IDs');
 r.consumerPreflightUnusedTail.state='original-restored';r.consumerPreflightUnusedTail.receipt=result;h.save();
 h.public={actualM8Complete:false,originalFailuresRetained:[{path:c.failurePath,sha256:c.failureSha256},{path:failedPath,sha256:sha256(failedBytes)}],originalConsumerPreflight404Retained:true,
   deliberatePreflightOnlyRetry:true,originalPluginWritesReplayed:false,originalConsumerDeleteReplayed:false,originalExportPOSTReplayed:false,originalDownloadPOSTReplayed:false,
   recoveredCommittedHTTPFailures:1,naturalTimer:r.naturalTimerProven,nativeAdminBypassRequests:0,remaining:['fixed-deck11-cli','current-RBAC-IDOR-session','full-audit-events','browser','soft-cleanup-secret-scan']};
 await finishM8FiveClassRecovery(h,actors,result);
 await directImportRollbackAcceptance(h,actors);
 await approvalV2AndMetadataAcceptance(h,actors);
 h.check(sha256(JSON.stringify(r.requests.slice(0,72)))===prefix72,'all 72 original observed packets remain byte-equivalent including the initial preflight failure and normal renewal');
 r.consumerPreflightUnusedTail.state='completed';r.consumerPreflightRetry.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-consumer-typed-preview-unused-tail.json');
