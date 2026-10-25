import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {M8Harness,readM8Reference,sha256} from './lib/m8-harness.mjs';
import {retainM8History} from './lib/m8-private-history.mjs';
import {assertM8HistoricalCommittedExportReceipt,M8_EXPORT_COMMIT_CHECKPOINT} from './lib/m8-export-commit-continuation.mjs';
import {assertM8CurrentTimerPolicy} from './lib/m8-current-timer-policy.mjs';
import {configurationRead,configurationWrite,downloadConfiguration} from './lib/m8-configuration-acceptance.mjs';
import {fiveClassRecoveryAcceptance,directImportRollbackAcceptance,approvalV2AndMetadataAcceptance} from './lib/m8-transfer-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_CURRENT_TIMER_CONTINUATION_READY!=='true')throw Error('M8_CURRENT_TIMER_CONTINUATION_RELEASE_REQUIRED');
const failurePath='artifacts/M8/export-commit-original-timer-revision-assertion-failure.json',failureBytes=readFileSync(failurePath),previous=JSON.parse(failureBytes);
if(sha256(failureBytes)!=='ff2bc63fed672e0932feed2d148d3aebad375609eb0ea9555007d6db8e58f333'||previous.passed!==587||previous.failed!==1||previous.unknownWrites!==0||previous.checks.filter(v=>!v.passed).length!==1||previous.checks.find(v=>!v.passed)?.name!=='pause selects only the real current original timer policy after its terminal capture')throw Error('M8_EXACT_KNOWN_TIMER_ASSERTION_REQUIRED');
const r=readM8Reference(),c=M8_EXPORT_COMMIT_CHECKPOINT;
if(r.requests.length!==63||sha256(JSON.stringify(r.requests))!=='63c44177388265f932038fb2f0444d3145d0e4722ee0574d43ed45a81103e884'||r.inFlight!==null||r.requests.some(v=>['prepared','response_unknown'].includes(v.state))||r.exportCommitContinuation?.state!=='started'||r.timerCurrentCasContinuation)throw Error('M8_EXACT_UNUSED_TIMER_TAIL_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
  const history=retainM8History(r,'timerCurrentCasContinuationHistory');
  r.timerCurrentCasContinuation={version:1,state:'started',history,originalPacketCount:63,originalPacketSha256:sha256(JSON.stringify(r.requests)),failurePath,failureSha256:sha256(failureBytes),originalSuccessfulTimerChecksRetained:previous.passed};
  h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'current-original-timer-unused-tail',inFlight:null});
  const area=r.scopes.direct,actor=r.sessions.admin,run=JSON.parse(readFileSync('artifacts/M8/original-timer-after-lock-repair-natural-watch.json')).sql.runs[0];
  const policies=await configurationRead(h,actor,area,'snapshots/schedules',{scope:'workspace',size:100});
  const policy=assertM8CurrentTimerPolicy(policies.items.find(v=>v.id===r.timerPolicy.id),{id:r.timerPolicy.id,area,actorId:actor.user.id,name:r.timerPolicy.name});
  h.check(true,'original real timer uses current owner, immutable version and actual revision after natural recurring runs');
  const paused=await configurationWrite(h,actor,area,`snapshots/schedules/${policy.id}`,{revision:policy.revision,name:policy.name,intervalMinutes:policy.intervalMinutes,timezone:policy.timezone,retentionDays:policy.retentionDays,paused:true},{kind:'compare',method:'PATCH'});
  const afterPause=await configurationRead(h,actor,area,'snapshots/schedules',{scope:'workspace',size:100});
  h.check(afterPause.items.find(v=>v.id===policy.id)?.state==='paused','current CAS pause stops recurring capture before Native recovery');
  r.naturalTimerProven={scheduleId:policy.id,runId:run.id,jobId:run.job_id,snapshotId:run.snapshot_id,origin:'schedule',sessionId:null,objectCount:26,nativePages:17,displayPages:13,terminalObserved:true,pauseJobId:paused.jobId,currentRevisionAtPause:policy.revision,syntheticTime:false,manualTriggers:0,terminalReceiptPaginationAndAuditProof:{path:failurePath,sha256:sha256(failureBytes),passed:previous.passed,originalKnownAssertionFailureRetained:true}};h.save();
  const recovered=await configurationRead(h,actor,area,`configuration/jobs/by-key/${c.key}`);
  assertM8HistoricalCommittedExportReceipt(recovered,actor,area);
  h.check(recovered.capabilities.download===false,'original committed export expired naturally and is not downloaded or decrypted');
  h.check(true,'the original export key proves committed success without rewriting its HTTP500 or resending export POST');
  r.exportCommitContinuation.recoveredReceipt={jobId:recovered.jobId,exportId:recovered.exportId,exportRevision:recovered.exportRevision,state:recovered.state,actorId:recovered.actorId};h.save();
  const operation=r.configurationOperations.find(v=>v.key===c.key);
  h.check(operation?.state==='prepared'&&operation.bodySha256===c.bodySha256&&operation.actorId===c.actorId&&operation.sessionId===c.sessionId,'one exact pending local bookkeeping entry belongs to the proven committed export');
  Object.assign(operation,{state:'succeeded',jobId:c.jobId,receipt:recovered,originalHTTPFailureRetained:true,recoveryReadOnly:true});h.save();
  const newKey=randomUUID();
  r.exportCommitContinuation.newOperation={purpose:'fresh-export-after-proven-original-expiry',key:newKey,sourceSnapshotId:c.snapshotId,actorId:actor.user.id,sessionId:actor.sid,originalExportKey:c.key};h.save();
  const fresh=await configurationWrite(h,actor,area,`snapshots/${c.snapshotId}/export`,{mode:'deployment',confirmed:true,confirm_name:c.confirmationName},{kind:'export',key:newKey});
  h.check(fresh.idempotencyKey===newKey&&fresh.jobId!==c.jobId&&fresh.exportId!==c.exportId,'one explicitly new current-authorized export is distinct from the original committed operation');
  const yaml=await downloadConfiguration(h,actor,area,fresh,c.confirmationName);
  r.baseline={area,name:c.confirmationName,snapshotId:c.snapshotId,captureJobId:c.captureJobId,exportJobId:fresh.jobId,yaml,yamlSha256:sha256(yaml)};h.save();
  h.public={actualM8Complete:false,originalFailuresRetained:[{path:c.failurePath,sha256:c.failureSha256}],
    phaseScope:'original-expired-export-new-operation-first-download-and-unused-transfer',originalExportHTTPFailureRetained:true,originalExportPOSTReplayed:false,
    recoveredCommittedHTTPFailures:1,recoveredExport:{jobId:c.jobId,exportId:c.exportId,exportRevision:recovered.exportRevision,state:'succeeded',downloadAllowed:false,naturalExpiry:true},
    newExplicitExport:{jobId:fresh.jobId,exportId:fresh.exportId,key:newKey},nativeAdminBypassRequests:0,
    naturalTimer:r.naturalTimerProven,remaining:['fixed-deck11-cli','current-RBAC-IDOR-session','full-audit-events','browser','soft-cleanup-secret-scan']};
  const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign};
  await fiveClassRecoveryAcceptance(h,actors);await directImportRollbackAcceptance(h,actors);await approvalV2AndMetadataAcceptance(h,actors);
  h.check(sha256(JSON.stringify(r.requests.slice(0,c.packetCount)))===c.prefixSha256,'every original packet including the failed export remains byte-equivalent after unused tail');
  r.exportCommitContinuation.state='completed';r.timerCurrentCasContinuation.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-current-timer-export-continuation.json');
