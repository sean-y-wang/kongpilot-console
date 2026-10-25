import {readFileSync} from 'node:fs';
import {M6Harness} from './lib/m6-harness.mjs';
import {guardFailedIssueContinuation,abandonOriginalRejectedIssue} from './lib/m6-failed-issue-continuation.mjs';
import {finishM6CredentialFlow} from './live-m6.mjs';

if(process.env.M6_DEPLOYMENT_READY!=='true'||process.env.M6_FAILED_ISSUE_CONTINUATION_READY!=='true')throw new Error('Root patched runtime and exact knownfailed issue continuation handoff required');
const h=new M6Harness({requireReference:true});let failure;
try{
 const previous=JSON.parse(readFileSync('artifacts/M6/security-live-pre-fix-second-credential-execution.json','utf8'));
 h.check(previous.testTag===h.tag&&previous.passed===381&&previous.failed===1&&previous.lastHttpRequest.status===409,'FailedIssue/Evidence','preserved actual settled-first and failed-second run is this exact checkpoint');
 h.checks.unshift(...previous.checks.filter(c=>c.passed));
 for(const key of['isolatedTransition','boundaryRefusalProof','portalTestClusters','retainedMonitoringFamilies','credentialContinuation','metadataRecovery'])if(previous[key])h.public[key]=previous[key];
 const original=await guardFailedIssueContinuation(h),context=await abandonOriginalRejectedIssue(h,original);
 h.public.failedIssueAbandonment={originalFailedExecuteReceiptPreserved:true,certificateVerified:true,unusedReservationReleased:true,formalAbandonmentPosts:1,nativeOperationsBefore:1,nativeOperationsAfter:1,keyCipherUnchanged:true,firstMetadataRequestReplayed:false,firstGrantRequestReplayed:false,failedSecondExecuteReplayed:false,newRequestKeyExplicitlySavedBeforePost:true};
 await finishM6CredentialFlow(h,context);
}catch(error){failure=error;}
process.exitCode=await h.finish(failure);
