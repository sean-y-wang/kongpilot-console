import{readFileSync}from'node:fs';
import{M8Harness,readM8Reference,sha256}from'./lib/m8-harness.mjs';
import{retainM8History}from'./lib/m8-private-history.mjs';
import{configurationRead,assertConfigurationReceipt}from'./lib/m8-configuration-acceptance.mjs';
import{finishM8ObservedDirectApplyRollback,approvalV2AndMetadataAcceptance}from'./lib/m8-transfer-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_ROLLBACK_UNUSED_TAIL_READY!=='true')throw Error('M8_ROLLBACK_UNUSED_RELEASE_REQUIRED');
const failurePath='artifacts/M8/security-live-direct-apply-unused-tail.json',failureBytes=readFileSync(failurePath),previous=JSON.parse(failureBytes);
const diagnosisPath='artifacts/M8/original-rollback-plan-readonly-diagnosis.json',diagnosisBytes=readFileSync(diagnosisPath),diagnosis=JSON.parse(diagnosisBytes);
const r=readM8Reference(),prefix='4b6716c4bb4579cccabdab28b6d8e5bb2c829bd256093c927d12ccf15f9d4d46',original=r.requests[84],source=r.requests[82],appliedPacket=r.requests[83],suffix=r.requests.slice(85);
let normalAuthSuffixValid=suffix.length===0;
if(suffix.length===1&&r.rollbackSchemaComparison?.state==='completed'){
 const diagnosticBytes=readFileSync('artifacts/M8/original-rollback-schema-bff-diagnostic.json'),diagnostic=JSON.parse(diagnosticBytes),packet=suffix[0];
 normalAuthSuffixValid=sha256(diagnosticBytes)===r.rollbackSchemaComparison.reportSha256&&diagnostic.allPassed===true&&diagnostic.failed===0
  &&diagnostic.originalPrefixCount===85&&diagnostic.originalPrefixSha256===prefix&&diagnostic.normalAuthenticationWrites===1
  &&diagnostic.authenticationRequestIds?.length===1&&diagnostic.authenticationRequestIds[0]===packet.requestId
  &&packet.path==='/api/v1/auth/refresh'&&packet.method==='POST'&&packet.state==='response_observed'&&packet.status===201
  &&packet.actorId===r.sessions.admin.user.id&&packet.sessionId===r.sessions.admin.sid;
}
if(sha256(failureBytes)!=='a63ef12cd1f007aa13962a285496f87eeecd8bc944b0e7761c27b5236b09d9c3'||sha256(diagnosisBytes)!=='e1f7a745ef0fe2e708aa5bfeb788459d4acc0c9804a52833dff760f9f0eb62d7'
 ||previous.passed!==894||previous.failed!==1||previous.unknownWrites!==0||!normalAuthSuffixValid||sha256(JSON.stringify(r.requests.slice(0,85)))!==prefix||r.inFlight!==null||r.phase!=='stopped-failure'
 ||r.rollbackUnusedTail||r.directTransfer||r.approvalTransfer||r.requests.some(p=>p.state!=='response_observed')||r.cliIntents.length||r.c2ModeChanged||r.fiveClassRecovery?.length!==5
 ||original.status!==500||original.key!=='f3c1c5bb-dc1e-4a91-ad5e-6e1a730366d8'||sha256(JSON.stringify(original))!=='43e02a454d95d24ecf0d8e039fefeeac44dc91a89dcd1298b69beb60b014d2dc'
 ||diagnosis.sql.job.state!=='failed'||diagnosis.sql.job.error_code!=='CONFIGURATION_DIFF_SCOPE_MISMATCH'||diagnosis.sql.job.remote_started||diagnosis.sql.job.remote_completed
 ||diagnosis.sql.executions.length||diagnosis.sql.steps.length||diagnosis.sql.operations.length||source.responseData?.jobId!=='88cd6cf5-8e9e-4c6e-8dff-65963a0446f6'
 ||appliedPacket.responseData?.jobId!=='62708b80-4b74-4ab7-a404-1b3167684b27'||appliedPacket.responseData.state!=='succeeded')throw Error('M8_EXACT_FAILED_ROLLBACK_AND_COMPLETED_APPLY_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
 const history=retainM8History(r,'rollbackUnusedTailHistory');r.rollbackUnusedTail={version:1,state:'original-terminal-read',history,originalPacketCount:85,originalPrefixSha256:prefix,failurePath,failureSha256:sha256(failureBytes),diagnosisPath,diagnosisSha256:sha256(diagnosisBytes),failedOriginalKey:original.key,successfulDirectApplyReplayed:false,failedRollbackPreviewReplayed:false};
 h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'rollback-new-intent-unused-tail',inFlight:null});
 const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign},area=actors.direct,actor=actors.admin;
 const failed=await configurationRead(h,actor,area,`configuration/jobs/by-key/${original.key}`);assertConfigurationReceipt(h,failed,{actor,area,key:original.key,jobId:diagnosis.sql.job.id,kind:'compare'});
 h.check(failed.state==='failed'&&failed.errorCode==='CONFIGURATION_DIFF_SCOPE_MISMATCH','historical rollback preview remains failed and is never replayed');
 const oldOperation=r.configurationOperations.find(p=>p.key===original.key);Object.assign(oldOperation,{state:'failed',jobId:failed.jobId,receipt:failed});h.save();
 const imported=await configurationRead(h,actor,area,`configuration/jobs/by-key/${source.key}`),applied=await configurationRead(h,actor,area,`configuration/jobs/by-key/${appliedPacket.key}`);
 assertConfigurationReceipt(h,imported,{actor,area,key:source.key,jobId:source.responseData.jobId,kind:'import'});assertConfigurationReceipt(h,applied,{actor,area,key:appliedPacket.key,jobId:appliedPacket.responseData.jobId,kind:'apply'});
 h.public={actualM8Complete:false,originalFailuresRetained:[{path:failurePath,sha256:sha256(failureBytes)}],fiveClassRecovery:r.fiveClassRecovery,naturalTimer:r.naturalTimerProven,successfulDirectApplyReplayed:false,failedRollbackPreviewReplayed:false,originalFiveClassRecoveryReplayed:false,originalExportPOSTReplayed:false,originalDownloadPOSTReplayed:false,recoveredCommittedHTTPFailures:1,nativeAdminBypassRequests:0,remaining:['fixed-deck11-cli','current-RBAC-IDOR-session','full-audit-events','browser','soft-cleanup-secret-scan']};
 r.rollbackUnusedTail.state='new-rollback-preview-intent';h.save();await finishM8ObservedDirectApplyRollback(h,actors,{imported,applied});await approvalV2AndMetadataAcceptance(h,actors);
 h.check(sha256(JSON.stringify(r.requests.slice(0,85)))===prefix,'all 85 original packets remain byte-equivalent including successful import/apply and failed rollback');r.rollbackUnusedTail.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-rollback-unused-tail.json');
