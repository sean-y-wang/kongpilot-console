import { readFileSync } from 'node:fs';
import { M7Harness,sha256,scope } from './lib/m7-harness.mjs';
import { M7_LATE_ACK_FAILURE,prepareLateAckContinuation,finishOriginalLateAck } from './lib/m7-late-ack-continuation.mjs';
import { nineMetadataHandlers } from './lib/m7-event-acceptance.mjs';
import { setApprovalMode,restoreClusterMode } from './lib/m7-fixtures.mjs';
import { auditAcceptance,auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';
import { portalTerminalAuditAcceptance } from './lib/m7-portal-audit-acceptance.mjs';
if(process.env.M7_DEPLOYMENT_READY!=='true'||process.env.M7_LATE_ACK_CONTINUATION_READY!=='true')throw new Error('M7_EXACT_LATE_ACK_UNUSED_TAIL_HANDOFF_REQUIRED');
const h=new M7Harness({resume:true});let failure;
try{
 const {queued,channel,actors}=prepareLateAckContinuation(h,readFileSync(M7_LATE_ACK_FAILURE.path),readFileSync(M7_LATE_ACK_FAILURE.diagnosisPath));
 h.state.lateAckContinuation.sourceFiles=[...new Set([...h.state.sourceFiles.map(v=>v.path),'tests/security/continue-m7-late-ack-checkpoint.mjs','tests/security/lib/m7-late-ack-continuation.mjs','tests/security/lib/m7-private-history.mjs','tests/security/lib/m7-portal-audit-acceptance.mjs'])].map(path=>({path,sha256:sha256(readFileSync(path))}));h.save();
 await finishOriginalLateAck(h,actors,queued,channel);
 await h.request(actors.readonly,scope(actors.foreign.cid,actors.foreign.wid,'events/channels'),'GET',undefined,{expected:[403]});
 await h.request(actors.readonly,scope(actors.approval.cid,actors.approval.wid,'events/channels'),'GET',undefined,{expected:[403]});
 h.check(true,'exact foreign workspace and cluster IDOR fail before event data access');h.save({phase:'approval-nine-handlers'});
 await setApprovalMode(h,actors.admin,actors.approval);await nineMetadataHandlers(h,actors,actors.approval,h.state.receiverMaterials,true);await restoreClusterMode(h,actors.admin,actors.approval);
 h.save({phase:'audit-historical-terminal-export'});h.state.auditAcceptance=await auditAcceptance(h,actors);h.save();
 h.state.portalTerminalAuditAcceptance=await portalTerminalAuditAcceptance(h,actors);h.save();h.state.httpAuditWriteCoverage=await auditAllWritesCoverage(h,actors);h.save();
 h.check(sha256(JSON.stringify(h.state.requests.slice(0,186)))===h.state.lateAckContinuation.originalPacketsSha256,'all original 186 packets including known failures remain byte-equivalent');
 h.state.lateAckContinuation.state='completed';h.state.preferencePatchContinuation.state='completed';h.state.catalogContinuation.state='completed';h.save();
 h.public={...(h.public??{}),scope:'original-immutable-uncertain-intent-and-unused-HTTP-tail',failureArchives:[h.state.catalogContinuation.failureArchive,h.state.preferencePatchContinuation.failureArchive,M7_LATE_ACK_FAILURE],originalPacketsRetained:186,successfulOriginalPacketsReplayed:false,deliberateOriginalFailedSqlRetry:1,completedChecksInherited:[{path:'artifacts/M7/security-live-fanout-source-patch-failure.json',passed:1202,originalFailedCheckPreserved:true},{path:M7_LATE_ACK_FAILURE.path,passed:138,originalFailedCheckPreserved:true}],actualUiComplete:false,detectorProducerComplete:false,cleanupComplete:false,finalSecretScanComplete:false,nativeTransportWritesOutsideBff:0,originalClusterModeRestored:!h.state.c2ModeChanged||h.state.c2ModeRestored===true,terminalAuditWriteCoverage:h.state.httpAuditWriteCoverage};
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M7/security-live-late-ack-continuation.json');
