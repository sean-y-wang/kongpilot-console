import { readFileSync } from 'node:fs';
import { M8Harness,readM8Reference,sha256,scope } from './lib/m8-harness.mjs';
import { retainM8History } from './lib/m8-private-history.mjs';
import { M8_CONSUMER_RETRY,assertM8ConsumerRetryCheckpoint,readM8ConsumerRetryLedger,assertM8ConsumerZeroLedger } from './lib/m8-consumer-preflight-retry.mjs';
import { finishM8FiveClassRecovery,directImportRollbackAcceptance,approvalV2AndMetadataAcceptance } from './lib/m8-transfer-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_CONSUMER_PREFLIGHT_RETRY_READY!=='true')throw Error('M8_CONSUMER_PREFLIGHT_RELEASE_REQUIRED');
const c=M8_CONSUMER_RETRY,load=(path,hash)=>{const bytes=readFileSync(path);if(sha256(bytes)!==hash)throw Error('M8_FIXED_PUBLIC_EVIDENCE_REQUIRED');return JSON.parse(bytes);};
const previous=load(c.failurePath,c.failureSha256),diagnosis=load(c.diagnosisPath,c.diagnosisSha256),deployment=load(c.deploymentPath,c.deploymentSha256);
if(previous.passed!==669||previous.failed!==1||previous.unknownWrites!==0||deployment.allPassed!==true||deployment.checks.length!==36||diagnosis.sql.operations.length||diagnosis.sql.audits.length)throw Error('M8_ORIGINAL_FAILURE_AND_REPAIR_PROOF_REQUIRED');
const r=readM8Reference(),packet=assertM8ConsumerRetryCheckpoint(r),h=new M8Harness({resume:true,reference:r});let failure;
try{
  const history=retainM8History(r,'consumerPreflightRetryHistory');
  r.consumerPreflightRetry={version:1,state:'readonly-preflight',history,originalPacketCount:71,originalPrefixSha256:c.prefixSha256,originalFailedPacketSha256:c.packetSha256,
    originalFailurePath:c.failurePath,originalFailureSha256:c.failureSha256,readonlyDiagnosisPath:c.diagnosisPath,readonlyDiagnosisSha256:c.diagnosisSha256,
    actualDeploymentPath:c.deploymentPath,actualDeploymentSha256:c.deploymentSha256,deliberateSideEffectFreeRetry:true,unknownReplay:false,originalKey:c.key};
  h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'consumer-side-effect-free-preflight',inFlight:null});
  const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign},actor=actors.admin,area=actors.direct;
  const me=h.data(await h.request(actor,'/auth/me'));
  h.check(me.user.id===c.actorId&&actor.sid===c.sid,'current authenticated original actor and normal same-SID renewal remain exact');
  const preview=h.data(await h.request(actor,scope(area.cid,area.wid,`recycle-bin/${c.entryId}`)));
  h.check(preview.entry.id===c.entryId&&preview.entry.workspace_id===c.wid&&preview.entry.cluster_id===c.cid&&preview.entry.state==='deleted'
    &&preview.graph.nodes.find(n=>n.key===preview.graph.rootKey)?.type==='consumers'&&preview.graph.nodes.length===7,'current protected archive is authorized and retains original complete seven-node Consumer graph');
  const proof=readM8ConsumerRetryLedger();assertM8ConsumerZeroLedger(proof,r.nativeFixture);r.consumerPreflightRetry.currentZeroLedgerProof=proof;
  r.consumerPreflightRetry.state='ready-to-send-original-once';h.save();
  const result=h.data(await h.request(actor,packet.path.slice('/api/v1'.length)+packet.query,'POST',packet.body,{key:packet.key}));
  h.check(result.entryId===c.entryId&&result.state==='restored'&&result.restored.length===7
    &&result.restored.every(row=>row.originalId===row.restoredId),'deliberate original preflight-only request restores all seven original IDs');
  r.consumerPreflightRetry.state='original-restored';r.consumerPreflightRetry.receipt=result;h.save();
  h.public={actualM8Complete:false,originalFailuresRetained:[{path:c.failurePath,sha256:c.failureSha256}],originalConsumerPreflight404Retained:true,
    deliberatePreflightOnlyRetry:true,originalPluginWritesReplayed:false,originalConsumerDeleteReplayed:false,originalExportPOSTReplayed:false,originalDownloadPOSTReplayed:false,
    recoveredCommittedHTTPFailures:1,naturalTimer:r.naturalTimerProven,nativeAdminBypassRequests:0,remaining:['fixed-deck11-cli','current-RBAC-IDOR-session','full-audit-events','browser','soft-cleanup-secret-scan']};
  await finishM8FiveClassRecovery(h,actors,result);
  await directImportRollbackAcceptance(h,actors);
  await approvalV2AndMetadataAcceptance(h,actors);
  h.check(sha256(JSON.stringify(r.requests.slice(0,71)))===c.prefixSha256,'all original 71 packets including preflight failure remain byte-equivalent');
  r.consumerPreflightRetry.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-consumer-preflight-transfer-continuation.json');
