import { readFileSync } from 'node:fs';
import { M8Harness,readM8Reference,sha256,entity } from './lib/m8-harness.mjs';
import { retainM8History } from './lib/m8-private-history.mjs';
import { configurationRead,configurationWrite,assertConfigurationReceipt } from './lib/m8-configuration-acceptance.mjs';
import { finishM8DirectImportRollback,approvalV2AndMetadataAcceptance } from './lib/m8-transfer-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_DIRECT_APPLY_UNUSED_TAIL_READY!=='true')throw Error('M8_DIRECT_APPLY_UNUSED_RELEASE_REQUIRED');
const failurePath='artifacts/M8/security-live-consumer-typed-preview-unused-tail.json',failedBytes=readFileSync(failurePath),previous=JSON.parse(failedBytes);
const diagnosisPath='artifacts/M8/original-direct-apply-readonly-diagnosis.json',diagnosisBytes=readFileSync(diagnosisPath),diagnosis=JSON.parse(diagnosisBytes);
const r=readM8Reference(),prefix='17a6768de32f22d0659ddbeea6aabf83fdfd2a33d92359b350125ae5a044f96d',original=r.requests[80],source=r.requests[79];
if(sha256(failedBytes)!=='2700206b40aeda1ebd4186278ed2394498155855a1b09ad6b0f45b7b29c15079'||sha256(diagnosisBytes)!=='16b8fe02b7a26c007fb4027391a0cab04cfae414d0a49da22f32b1c1c82fc62f'
 ||previous.passed!==828||previous.failed!==1||previous.unknownWrites!==0||r.requests.length!==81||sha256(JSON.stringify(r.requests))!==prefix||r.inFlight!==null||r.phase!=='stopped-failure'
 ||r.directApplyUnusedTail||r.directTransfer||r.approvalTransfer||r.requests.some(p=>p.state!=='response_observed')||r.cliIntents.length||r.c2ModeChanged||r.fiveClassRecovery?.length!==5
 ||original.status!==500||original.key!=='a6e1418b-29a9-45ba-952b-6a48ee83958b'||sha256(JSON.stringify(original))!=='5d08108660b4c0c2b7a6c30b50ed18bdac45b0403e71eda1408844d9000a8fb5'
 ||diagnosis.sql.job.state!=='failed'||diagnosis.sql.job.remote_started||diagnosis.sql.job.remote_completed||diagnosis.sql.executions.length||diagnosis.sql.steps.length||diagnosis.sql.operations.length
 ||source.responseData?.jobId!=='c83395e3-b430-4a2f-b184-30ff7442fc93'||source.responseData.planId!=='148b10fa-fa8c-4c39-96c7-40a1c2a6d218')throw Error('M8_EXACT_FAILED_BEFORE_NATIVE_APPLY_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
 const history=retainM8History(r,'directApplyUnusedTailHistory');r.directApplyUnusedTail={version:1,state:'original-terminal-read',history,originalPacketCount:81,originalPrefixSha256:prefix,
  failurePath,failureSha256:sha256(failedBytes),diagnosisPath,diagnosisSha256:sha256(diagnosisBytes),failedOriginalKey:original.key,originalApplyReplayed:false,originalFiveClassRecoveryReplayed:false};
 h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'direct-apply-new-intent-unused-tail',inFlight:null});
 const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign},area=actors.direct,actor=actors.admin;
 const failed=await configurationRead(h,actor,area,`configuration/jobs/by-key/${original.key}`);
 assertConfigurationReceipt(h,failed,{actor,area,key:original.key,jobId:diagnosis.sql.job.id,kind:'apply'});
 h.check(failed.state==='failed'&&failed.errorCode==='23514'&&failed.completedSteps===0,'historical failed apply remains terminal and is never restarted');
 const oldOperation=r.configurationOperations.find(p=>p.key===original.key);Object.assign(oldOperation,{state:'failed',jobId:failed.jobId,receipt:failed});h.save();
 let imported=await configurationRead(h,actor,area,`configuration/jobs/by-key/${source.key}`);assertConfigurationReceipt(h,imported,{actor,area,key:source.key,jobId:source.responseData.jobId,kind:'import'});
 const currentPlan=entity(await configurationRead(h,actor,area,`configuration/plans/${imported.planId}`));
 h.check(currentPlan.id===imported.planId&&currentPlan.planHash===imported.planHash&&currentPlan.planRevision===imported.planRevision,'original successful import retains its current immutable sealed plan');
 if(currentPlan.capabilities?.apply!==true){
  h.check(Number.isFinite(Date.parse(currentPlan.expiresAt))&&Date.parse(currentPlan.expiresAt)<=Date.now(),'only an actually expired original plan permits a separately named fresh diff');
  r.directApplyUnusedTail.state='fresh-diff-expired-source-plan';h.save();
  imported=await configurationWrite(h,actor,area,'configuration/imports',source.body,{kind:'import'});r.directApplyUnusedTail.newDiffJobId=imported.jobId;h.save();
 }
 h.public={actualM8Complete:false,originalFailuresRetained:[{path:failurePath,sha256:sha256(failedBytes)}],fiveClassRecovery:r.fiveClassRecovery,naturalTimer:r.naturalTimerProven,
  originalFailedApplyRetained:true,originalFailedApplyReplayed:false,originalFiveClassRecoveryReplayed:false,originalExportPOSTReplayed:false,originalDownloadPOSTReplayed:false,
  recoveredCommittedHTTPFailures:1,nativeAdminBypassRequests:0,remaining:['fixed-deck11-cli','current-RBAC-IDOR-session','full-audit-events','browser','soft-cleanup-secret-scan']};
 r.directApplyUnusedTail.state='new-apply-intent';h.save();await finishM8DirectImportRollback(h,actors,imported);
 await approvalV2AndMetadataAcceptance(h,actors);
 h.check(sha256(JSON.stringify(r.requests.slice(0,81)))===prefix,'all 81 original observed packets remain byte-equivalent and failed Native-free apply is retained');
 r.directApplyUnusedTail.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-direct-apply-unused-tail.json');
