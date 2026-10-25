import{readFileSync}from'node:fs';
import{M8Harness,readM8Reference,sha256}from'./lib/m8-harness.mjs';
import{retainM8History}from'./lib/m8-private-history.mjs';
import{M8_EXPORT_COMMIT_CHECKPOINT}from'./lib/m8-export-commit-continuation.mjs';
import{configurationRead,assertConfigurationReceipt}from'./lib/m8-configuration-acceptance.mjs';
import{fiveClassRecoveryAcceptance,directImportRollbackAcceptance,approvalV2AndMetadataAcceptance}from'./lib/m8-transfer-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_UNUSED_TRANSFER_READY!=='true')throw Error('M8_UNUSED_TRANSFER_RELEASE_REQUIRED');
const failurePath='artifacts/M8/security-live-download201-unused-transfer-continuation.json',failureBytes=readFileSync(failurePath),previous=JSON.parse(failureBytes),r=readM8Reference(),c=M8_EXPORT_COMMIT_CHECKPOINT;
if(sha256(failureBytes)!=='a3ae62e495bd5e38f8d4f77b2e6768a36a0b6143a67d41cb00a30ba335a68091'||previous.passed!==638||previous.failed!==1||previous.unknownWrites!==0||r.requests.length!==67||sha256(JSON.stringify(r.requests))!=='86197275f527959368d0934287954345a9d063c935b1cdd02f44f9bb699d1408'||r.inFlight!==null||r.requests.some(v=>['prepared','response_unknown'].includes(v.state))||r.unusedTransferContinuation||!r.baseline||sha256(r.baseline.yaml)!=='ce15e2ee9430283039bccf0609ec63c6813d4e9471a7bfcb15c7f9198fd47234'||r.requests[66].rawResponseText!==r.baseline.yaml||r.downloads.at(-1).jobId!=='624cbb5d-6449-44df-bb30-abb1d2372c65')throw Error('M8_EXACT_UNUSED_TRANSFER_CHECKPOINT_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
 const history=retainM8History(r,'unusedTransferContinuationHistory'),area=r.scopes.direct,actor=r.sessions.admin;
 r.unusedTransferContinuation={version:1,state:'started',history,originalPacketCount:67,originalPacketSha256:sha256(JSON.stringify(r.requests)),failurePath,failureSha256:sha256(failureBytes),originalDownloadedBytesRetained:true,downloadPOSTReplayed:false,exportPOSTReplayed:false};
 h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'unused-five-class-import-v2-tail',inFlight:null});
 const packet=r.requests[66],download=await configurationRead(h,actor,area,`configuration/jobs/by-key/${packet.key}`);
 assertConfigurationReceipt(h,download,{actor,area,key:packet.key,jobId:r.downloads.at(-1).jobId,kind:'export'});
 h.check(download.state==='succeeded'&&download.downloadPermitConsumed===true&&download.byteCount===Buffer.byteLength(r.baseline.yaml)&&download.exportId==='57ae2045-d6c3-4c81-a871-c1f3f721c618','original successfully downloaded private bytes remain bound to current immutable permit receipt');
 h.public={actualM8Complete:false,originalFailuresRetained:[{path:c.failurePath,sha256:c.failureSha256},{path:failurePath,sha256:sha256(failureBytes)}],recoveredCommittedHTTPFailures:1,originalExportHTTPFailureRetained:true,originalExportPOSTReplayed:false,originalDownload201Retained:true,originalDownloadPOSTReplayed:false,naturalTimer:r.naturalTimerProven,nativeAdminBypassRequests:0,remaining:['fixed-deck11-cli','current-RBAC-IDOR-session','full-audit-events','browser','soft-cleanup-secret-scan']};
 const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign};
 await fiveClassRecoveryAcceptance(h,actors);await directImportRollbackAcceptance(h,actors);await approvalV2AndMetadataAcceptance(h,actors);
 h.check(sha256(JSON.stringify(r.requests.slice(0,67)))==='86197275f527959368d0934287954345a9d063c935b1cdd02f44f9bb699d1408','all 67 original known packets remain byte-equivalent after unused transfer');
 r.unusedTransferContinuation.state='completed';r.exportCommitContinuation.state='completed';r.timerCurrentCasContinuation.state='completed';r.downloadStatus201Continuation.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-unused-transfer-continuation.json');
