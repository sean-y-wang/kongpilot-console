import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { M8Harness, readM8Reference, sha256 } from './lib/m8-harness.mjs';
import { retainM8History } from './lib/m8-private-history.mjs';
import { assertM8CommittedExportCheckpoint, assertM8HistoricalCommittedExportReceipt, M8_EXPORT_COMMIT_CHECKPOINT } from './lib/m8-export-commit-continuation.mjs';
import { configurationRead, configurationWrite, downloadConfiguration, boundedSnapshotObjects } from './lib/m8-configuration-acceptance.mjs';
import { CREDENTIAL_KINDS } from './lib/m8-native-acceptance.mjs';
import { m8AuditPatchMatches } from './lib/m8-audit-acceptance.mjs';
import { fiveClassRecoveryAcceptance, directImportRollbackAcceptance, approvalV2AndMetadataAcceptance } from './lib/m8-transfer-acceptance.mjs';

if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_EXPORT_COMMIT_CONTINUATION_READY!=='true')throw Error('M8_EXPORT_REPAIR_RUNTIME_RELEASE_REQUIRED');
// Root supplies the exact independently reviewed repair artifact hash at its
// actual handoff. This verifies readiness, never authorizes a fresh export.
const deploymentPath='artifacts/M8/export-material-revision-repair-continuity.json',deploymentBytes=readFileSync(deploymentPath);
if(!/^[a-f\d]{64}$/.test(process.env.M8_EXPORT_REPAIR_REPORT_SHA256??'')||sha256(deploymentBytes)!==process.env.M8_EXPORT_REPAIR_REPORT_SHA256||JSON.parse(deploymentBytes).allPassed!==true)throw Error('M8_ACTUAL_EXPORT_REPAIR_EVIDENCE_REQUIRED');
const c=M8_EXPORT_COMMIT_CHECKPOINT,failureBytes=readFileSync(c.failurePath),proofBytes=readFileSync(c.proofPath),previous=JSON.parse(failureBytes),r=readM8Reference();
assertM8CommittedExportCheckpoint(r,failureBytes,proofBytes,readFileSync(c.authClosurePath));
const h=new M8Harness({resume:true,reference:r});let failure;
try {
  const history=retainM8History(r,'exportCommitContinuationHistory'),area=r.scopes.direct,actor=r.sessions.admin;
  r.exportCommitContinuation={version:1,state:'started',history,originalPrefixCount:c.packetCount,originalPrefixSha256:c.prefixSha256,originalPacketSha256:c.packetSha256,
    originalFailurePath:c.failurePath,originalFailureSha256:c.failureSha256,committedExportReadonlyProofSha256:c.proofSha256,originalHTTPStatus:500,exportPOSTReplayed:false,
    repairReportPath:deploymentPath,repairReportSha256:sha256(deploymentBytes)};
  h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'committed-export-original-key-unused-tail',inFlight:null});
  const timerBytes=readFileSync('artifacts/M8/original-timer-after-lock-repair-natural-watch.json');
  h.check(sha256(timerBytes)==='bddee685e557d7ee16724d13cb3c27c947c9f6a073164b5eae0ff673729e79dc','original naturally due schedule SQL proof remains immutable');
  const run=JSON.parse(timerBytes).sql.runs[0],timerKey=`schedule-${run.id}`;
  h.check(run.id==='8a4a6a51-3940-4bb4-9b82-c33a51057eb1'&&run.origin_type==='schedule'&&run.no_sid===true&&run.creator_matches&&run.job_owner_matches
    &&run.state==='succeeded'&&run.job_state==='succeeded'&&run.snapshot_state==='ready'&&run.completeness==='complete'
    &&run.scheduled_at===r.timerPolicy.nextRunAt,'real timer completed its original due run as original owner without any SID');
  const timerReceipt=await configurationRead(h,actor,area,`configuration/jobs/by-key/${timerKey}`);
  h.check(timerReceipt.jobId===run.job_id&&timerReceipt.idempotencyKey===timerKey&&timerReceipt.snapshotId===run.snapshot_id
    &&timerReceipt.actorId===actor.user.id&&timerReceipt.state==='succeeded','current protected receipt belongs to the actual SIDless timer capture');
  const timerGraph=await boundedSnapshotObjects(h,actor,area,run.snapshot_id);
  h.check(timerGraph.summary.completeness==='complete'&&timerGraph.objects.length===26&&timerGraph.objects.length===timerGraph.summary.objectCount,'real timer capture exposes its entire complete typed graph and cursor EOF');
  for(const kind of CREDENTIAL_KINDS)h.check(timerGraph.objects.some(o=>o.credentialKind===kind&&o.nativeId===r.nativeFixture.credentials[kind].id&&o.parentId===r.nativeFixture.consumer.id),'natural timer includes original credential and Consumer',{kind});
  const timerAudits=h.data(await h.request(actor,`/clusters/${area.cid}/audit?`+new URLSearchParams({scope:'cluster',requestId:timerKey,result:'success',size:'100'})));
  h.check(Array.isArray(timerAudits.items)&&timerAudits.items.length>0&&timerAudits.nextCursor===null
    &&timerAudits.items.every(v=>v.actorId===actor.user.id&&v.clusterId===area.cid&&v.workspaceId===area.wid&&v.requestId===timerKey&&m8AuditPatchMatches(v))
    &&timerAudits.items.some(v=>v.action==='snapshot.capture')&&timerAudits.items.some(v=>v.action==='configuration.capture'),'natural timer has exact original-run successful audit and independently valid complete JSON patches');
  const policies=await configurationRead(h,actor,area,'snapshots/schedules',{scope:'workspace',size:100}),policy=policies.items.find(v=>v.id===r.timerPolicy.id);
  h.check(policy?.state==='active'&&policy.revision===2&&policy.ownerUserId===actor.user.id,'pause selects only the real current original timer policy after its terminal capture');
  const paused=await configurationWrite(h,actor,area,`snapshots/schedules/${policy.id}`,{revision:policy.revision,name:policy.name,intervalMinutes:policy.intervalMinutes,timezone:policy.timezone,retentionDays:policy.retentionDays,paused:true},{kind:'compare',method:'PATCH'});
  const afterPause=await configurationRead(h,actor,area,'snapshots/schedules',{scope:'workspace',size:100});
  h.check(afterPause.items.find(v=>v.id===policy.id)?.state==='paused','normal BFF policy pause prevents another timer capture during Native recovery');
  r.naturalTimerProven={scheduleId:policy.id,runId:run.id,jobId:run.job_id,snapshotId:run.snapshot_id,origin:'schedule',sessionId:null,objectCount:26,nativePages:17,displayPages:timerGraph.pages,terminalObserved:true,
    auditEventIds:timerAudits.items.map(v=>v.id),pauseJobId:paused.jobId,syntheticTime:false,manualTriggers:0};h.save();
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
  r.exportCommitContinuation.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-export-commit-continuation.json');
