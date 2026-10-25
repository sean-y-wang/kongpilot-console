import{readFileSync}from'node:fs';
import{M8Harness,readM8Reference,sha256}from'./lib/m8-harness.mjs';
import{retainM8History}from'./lib/m8-private-history.mjs';
import{M8_EXPORT_COMMIT_CHECKPOINT}from'./lib/m8-export-commit-continuation.mjs';
import{configurationRead,downloadConfiguration,assertConfigurationReceipt}from'./lib/m8-configuration-acceptance.mjs';
import{fiveClassRecoveryAcceptance,directImportRollbackAcceptance,approvalV2AndMetadataAcceptance}from'./lib/m8-transfer-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_DOWNLOAD201_CONTINUATION_READY!=='true')throw Error('M8_DOWNLOAD201_UNUSED_TAIL_RELEASE_REQUIRED');
const failurePath='artifacts/M8/security-live-current-timer-export-continuation.json',failureBytes=readFileSync(failurePath),previous=JSON.parse(failureBytes),proofBytes=readFileSync('artifacts/M8/original-download-status201-readonly-receipt-proof.json');
if(sha256(failureBytes)!=='81877a1d1579860c8b014c510f77b9316c3d76d8ed7958d0e503e51ccfe45cdb'||previous.passed!==623||previous.failed!==1||previous.unknownWrites!==0||previous.checks.filter(v=>!v.passed).length!==1||previous.checks.find(v=>!v.passed)?.name!=='expected BFF HTTP 200 received 201'||sha256(proofBytes)!=='89a42dc87ef3647d1ad03837ba17583e0ed3a3e9c80ba1defac2dc52ccdc4872')throw Error('M8_EXACT_KNOWN_DOWNLOAD201_ASSERTION_REQUIRED');
const r=readM8Reference(),c=M8_EXPORT_COMMIT_CHECKPOINT;
if(r.requests.length!==66||sha256(JSON.stringify(r.requests))!=='29ec34b12106eed08d4afa85b5386e46dd1a45ea4db0e02739e424c73ae6f641'||r.inFlight!==null||r.requests.some(v=>['prepared','response_unknown'].includes(v.state))||r.downloadStatus201Continuation||r.baseline||r.originalDownloadObserved201?.safe?.downloadPermitConsumed!==true)throw Error('M8_EXACT_ORIGINAL_CONSUMED_DOWNLOAD_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
  const history=retainM8History(r,'downloadStatus201ContinuationHistory'),area=r.scopes.direct,actor=r.sessions.admin;
  r.downloadStatus201Continuation={version:1,state:'started',history,originalPacketCount:66,originalPacketSha256:sha256(JSON.stringify(r.requests)),failurePath,failureSha256:sha256(failureBytes),originalDownloadKey:r.requests[65].key,original201SuccessRetained:true,original201RawBytesNotRetained:true,originalDownloadPOSTReplayed:false,exportPOSTReplayed:false,readonlyReceiptProofSha256:sha256(proofBytes)};
  h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'new-download-after-known-original201-unused-transfer',inFlight:null});
  const op=r.configurationOperations.find(v=>v.key===r.exportCommitContinuation.newOperation.key),fresh=await configurationRead(h,actor,area,`configuration/jobs/by-key/${op.key}`);
  assertConfigurationReceipt(h,fresh,{actor,area,key:op.key,jobId:op.jobId,kind:'export'});
  h.check(fresh.exportId==='57ae2045-d6c3-4c81-a871-c1f3f721c618'&&fresh.state==='succeeded'&&fresh.capabilities.download===true,'same genuine available export permits a distinctly new current-authorized download');
  const before=r.requests.length,yaml=await downloadConfiguration(h,actor,area,fresh,c.confirmationName),downloadPacket=r.requests[before];
  h.check(downloadPacket.key!==r.requests[65].key&&downloadPacket.rawResponseText===yaml&&downloadPacket.responseSha256===sha256(yaml),'one distinctly new download has exact original private bytes saved before assertions');
  r.downloadStatus201Continuation.newDownload={key:downloadPacket.key,requestId:downloadPacket.requestId,jobId:r.downloads.at(-1).jobId,byteCount:Buffer.byteLength(yaml),sha256:sha256(yaml)};h.save();
  r.baseline={area,name:c.confirmationName,snapshotId:c.snapshotId,captureJobId:c.captureJobId,exportJobId:fresh.jobId,yaml,yamlSha256:sha256(yaml)};h.save();
  h.public={actualM8Complete:false,originalFailuresRetained:[{path:c.failurePath,sha256:c.failureSha256}],
    phaseScope:'original-expired-export-new-operation-first-download-and-unused-transfer',originalExportHTTPFailureRetained:true,originalExportPOSTReplayed:false,
    recoveredCommittedHTTPFailures:1,recoveredExport:{jobId:c.jobId,exportId:c.exportId,exportRevision:r.exportCommitContinuation.recoveredReceipt.exportRevision,state:'succeeded',downloadAllowed:false,naturalExpiry:true},
    newExplicitExport:{jobId:fresh.jobId,exportId:fresh.exportId,key:r.exportCommitContinuation.newOperation.key},nativeAdminBypassRequests:0,
    naturalTimer:r.naturalTimerProven,remaining:['fixed-deck11-cli','current-RBAC-IDOR-session','full-audit-events','browser','soft-cleanup-secret-scan']};
  const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign};
  await fiveClassRecoveryAcceptance(h,actors);await directImportRollbackAcceptance(h,actors);await approvalV2AndMetadataAcceptance(h,actors);
  h.check(sha256(JSON.stringify(r.requests.slice(0,c.packetCount)))===c.prefixSha256,'every original packet including the failed export remains byte-equivalent after unused tail');
  r.exportCommitContinuation.state='completed';r.timerCurrentCasContinuation.state='completed';r.downloadStatus201Continuation.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-download201-unused-transfer-continuation.json');
