import {readFileSync} from 'node:fs';
import {M8Harness,readM8Reference,sha256} from './lib/m8-harness.mjs';
import {retainM8History} from './lib/m8-private-history.mjs';
import {M8_EXPIRED_EXECUTION,assertM8ExpiredExecutionCheckpoint,closeM8OriginalExpiredExecution,validateM8FreshBudget17} from './lib/m8-expired-execution-recovery.mjs';
if(process.env.M8_DEPLOYMENT_READY!=='true'||process.env.M8_RUNTIME_READY!=='true'||process.env.M8_EXPIRED_EXECUTION_RECOVERY_READY!=='true')throw Error('M8_EXPIRED_EXECUTION_RECOVERY_RELEASE_REQUIRED');
const c=M8_EXPIRED_EXECUTION,failureBytes=readFileSync(c.failurePath),diagnosisBytes=readFileSync(c.diagnosisPath),timingBytes=readFileSync(c.timingPath),r=readM8Reference();
const original=assertM8ExpiredExecutionCheckpoint(r,failureBytes,diagnosisBytes,timingBytes),h=new M8Harness({resume:true,reference:r});let failure;
try{
 const history=retainM8History(r,'expiredExecutionRecoveryHistory');r.expiredExecutionRecovery={version:1,state:'original-readonly',history,
  originalPacketCount:121,originalPrefixSha256:c.prefix,originalPrefix115Sha256:c.prefix115,failurePath:c.failurePath,failureSha256:c.failureSha256,
  diagnosisPath:c.diagnosisPath,diagnosisSha256:c.diagnosisSha256,timingPath:c.timingPath,timingSha256:c.timingSha256,originalExecutionReplayed:false,originalFailurePreserved:true};
 h.checks=original.failed.checks.filter(v=>v.passed);h.save({phase:'expired-execution-independent-validation',inFlight:null});
 const actors={...r.sessions,direct:r.scopes.direct,approval:r.scopes.approval,foreign:r.scopes.foreign};
 h.public={actualM8Complete:false,originalFailuresRetained:[{path:c.failurePath,sha256:c.failureSha256}],directTransfer:r.directTransfer,fiveClassRecovery:r.fiveClassRecovery,
  naturalTimer:r.naturalTimerProven,originalExecutionReplayed:false,originalUnknownOutcomeRetained:true,recoveredCommittedHTTPFailures:1,nativeAdminBypassRequests:0,
  remaining:['fixed-deck11-cli','current-RBAC-IDOR-session','full-audit-events','browser','soft-cleanup-secret-scan']};
 await closeM8OriginalExpiredExecution(h,actors,original);h.public.originalFailureClosure=r.expiredExecutionRecovery.originalFailureClosure;
 h.public.approvalTransfer=await validateM8FreshBudget17(h,actors);h.public.independent17Complete=true;
 h.check(sha256(JSON.stringify(r.requests.slice(0,121)))===c.prefix&&sha256(JSON.stringify(r.requests.slice(0,115)))===c.prefix115,'all original one hundred twenty-one packets and their first one hundred fifteen remain byte-equivalent');
}catch(error){failure=error;}
process.exitCode=h.finish(failure,'artifacts/M8/security-live-expired-execution-recovery.json');
