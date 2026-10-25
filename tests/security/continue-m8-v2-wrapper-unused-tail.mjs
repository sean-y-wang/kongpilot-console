import{readFileSync}from'node:fs';
import{M8Harness,readM8Reference,sha256,entity}from'./lib/m8-harness.mjs';
import{retainM8History}from'./lib/m8-private-history.mjs';
import{configurationRead,configurationWrite,assertConfigurationReceipt}from'./lib/m8-configuration-acceptance.mjs';
import{finishM8ObservedApprovalImport}from'./lib/m8-transfer-acceptance.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_V2_WRAPPER_UNUSED_TAIL_READY!=='true')throw Error('M8_V2_WRAPPER_UNUSED_RELEASE_REQUIRED');
const failurePath='artifacts/M8/security-live-rollback-unused-tail.json',failureBytes=readFileSync(failurePath),previous=JSON.parse(failureBytes);
const diagnosisPath='artifacts/M8/original-v2-apply-readonly-diagnosis.json',diagnosisBytes=readFileSync(diagnosisPath),diagnosis=JSON.parse(diagnosisBytes);
const prefix='65aed8c374d6dcee6e7933ab111e7323fc5ced185486aa47fbee4b4d264760cb',r=readM8Reference(),original=r.requests[91],source=r.requests[90];
if(sha256(failureBytes)!=='4fd2a476f6c0942975533e086501438153ae26da37e0c33f829ebfc5f7a0e084'
 ||sha256(diagnosisBytes)!=='ce5e54a8b26198095d0ecf54981be3fa32edfe5bb74f93ff83a52a577076e187'
 ||previous.passed!==987||previous.failed!==1||previous.unknownWrites!==0||r.requests.length!==92||sha256(JSON.stringify(r.requests))!==prefix
 ||r.inFlight!==null||r.phase!=='stopped-failure'||r.v2WrapperUnusedTail||!r.directTransfer||r.approvalTransfer||r.cliIntents.length
 ||!r.c2ModeChanged||r.c2ModeRestored||r.fiveClassRecovery?.length!==5||r.requests.some(p=>p.state!=='response_observed')
 ||sha256(JSON.stringify(original))!=='50e63b603f93a1cc1cebd016fff2bbf14c34e4399fa15b8e24a30a5abe45bbc7'
 ||original.status!==500||original.key!=='54461241-9e09-4f7b-83e6-1ca8fcb97a3b'||original.requestId!=='aa88acc0-2e59-40a0-a4b6-c4f7fe7d4c67'
 ||diagnosis.sql.job.state!=='failed'||diagnosis.sql.job.error_code!=='23503'||diagnosis.sql.job.workflow_id!==null
 ||diagnosis.sql.job.remote_started||diagnosis.sql.job.remote_completed||diagnosis.sql.executions.length||diagnosis.sql.steps.length||diagnosis.sql.operations.length
 ||diagnosis.sql.workflows.length||diagnosis.sql.workflowSteps.length||source.responseData?.kind!=='import'||source.responseData?.counts?.create!==17
 ||source.responseData.planId!=='90feb84c-a0be-4cd1-a4b0-0e916dfee898')throw Error('M8_EXACT_FAILED_V2_WRAPPER_WITH_ZERO_NATIVE_REQUIRED');
const h=new M8Harness({resume:true,reference:r});let failure;
try{
 const history=retainM8History(r,'v2WrapperUnusedTailHistory');
 r.v2WrapperUnusedTail={version:1,state:'historical-terminal-read',history,originalPacketCount:92,originalPrefixSha256:prefix,failurePath,failureSha256:sha256(failureBytes),diagnosisPath,diagnosisSha256:sha256(diagnosisBytes),failedWrapperApplyReplayed:false,successfulDirectRollbackReplayed:false,originalC2ModeChangeReplayed:false,successfulApprovalImportReplayed:false};
 h.checks=previous.checks.filter(v=>v.passed);h.save({phase:'v2-wrapper-new-intent-unused-tail',inFlight:null});
 const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign},area=actors.approval,actor=actors.admin;
 const failed=await configurationRead(h,actor,area,`configuration/jobs/by-key/${original.key}`);
 assertConfigurationReceipt(h,failed,{actor,area,key:original.key,jobId:diagnosis.sql.job.id,kind:'apply'});
 h.check(failed.state==='failed'&&failed.errorCode==='23503'&&!failed.workflowId,'original failed wrapper remains terminal without approval or Native replay');
 const old=r.configurationOperations.find(p=>p.key===original.key);h.check(!!old,'original wrapper intent remains in its durable operation journal');Object.assign(old,{state:'failed',jobId:failed.jobId,receipt:failed});h.save();
 let imported=await configurationRead(h,actor,area,`configuration/jobs/by-key/${source.key}`);
 assertConfigurationReceipt(h,imported,{actor,area,key:source.key,jobId:source.responseData.jobId,kind:'import'});
 h.check(imported.state==='succeeded'&&imported.counts?.create===17,'original approval import remains succeeded without being replayed');
 const plan=entity(await configurationRead(h,actor,area,`configuration/plans/${imported.planId}`));
 h.check(plan.id===imported.planId&&plan.planHash===imported.planHash&&plan.planRevision===imported.planRevision,'current original source plan identity is unchanged');
 const sourceExpired=Number.isFinite(Date.parse(plan.expiresAt))&&Date.parse(plan.expiresAt)<=Date.now();
 if(sourceExpired){
  h.check(plan.capabilities?.apply===false&&source.body?.mode==='merge'&&typeof source.body.yaml==='string','only a genuinely expired source plan permits an explicitly new import diff');
  r.v2WrapperUnusedTail.newDiffForExpiredOriginalPlan=true;h.save();
  imported=await configurationWrite(h,actor,area,'configuration/imports',structuredClone(source.body),{kind:'import'});
 }else h.check(plan.capabilities?.apply===true,'unexpired original approval source plan retains current apply capability');
 h.public={actualM8Complete:false,originalFailuresRetained:[{path:failurePath,sha256:sha256(failureBytes)}],directTransfer:r.directTransfer,fiveClassRecovery:r.fiveClassRecovery,naturalTimer:r.naturalTimerProven,failedWrapperApplyReplayed:false,successfulDirectRollbackReplayed:false,originalC2ModeChangeReplayed:false,successfulApprovalImportReplayed:false,recoveredCommittedHTTPFailures:1,nativeAdminBypassRequests:0,remaining:['fixed-deck11-cli','current-RBAC-IDOR-session','full-audit-events','browser','soft-cleanup-secret-scan']};
 r.v2WrapperUnusedTail.state='new-independent-wrapper-apply';h.save();await finishM8ObservedApprovalImport(h,actors,imported);
 h.check(sha256(JSON.stringify(r.requests.slice(0,92)))===prefix,'all ninety-two original packets remain byte-equivalent including successful rollback and failed V2 wrapper');
 r.v2WrapperUnusedTail.state='completed';h.save();
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-v2-wrapper-unused-tail.json');
