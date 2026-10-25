import {readFileSync} from 'node:fs';
import {M6Harness} from './lib/m6-harness.mjs';
import {guardAbandonmentAcknowledgment,settleAbandonmentAcknowledgment} from './lib/m6-abandonment-acknowledgment.mjs';
import {finishM6CredentialFlow} from './live-m6.mjs';

if(process.env.M6_DEPLOYMENT_READY!=='true'||process.env.M6_ABANDONMENT_ACKNOWLEDGMENT_READY!=='true')throw new Error('Root exact privilege repair and original-key acknowledgment continuation handoff required');
const h=new M6Harness({requireReference:true});let failure;
try{
 const read=name=>JSON.parse(readFileSync(`artifacts/M6/${name}`,'utf8'));
 const evidence={report:read('security-live-pre-fix-failed-issue-continuation.json'),proof:read('failed-issue-abandonment-failure-proof.json'),databaseErrors:read('failed-issue-abandonment-database-permission-class.json')};
 h.check(evidence.report.testTag===h.tag&&evidence.report.passed===491&&evidence.report.failed===1,'AbandonmentAck/Evidence','this exact original request failure remains immutable evidence');
 h.checks.unshift(...evidence.report.checks.filter(c=>c.passed));
 for(const key of['isolatedTransition','boundaryRefusalProof','portalTestClusters','retainedMonitoringFamilies','credentialContinuation','metadataRecovery'])if(evidence.report[key])h.public[key]=evidence.report[key];
 const current=await guardAbandonmentAcknowledgment(h,evidence),context=await settleAbandonmentAcknowledgment(h,current),ack=h.referenceData.abandonmentAcknowledgment;
 h.public.failedIssueAbandonment={previousFailureEvidence:'security-live-pre-fix-failed-issue-continuation.json',originalFailedExecuteReceiptPreserved:true,certificateVerified:true,unusedReservationReleased:true,formalAbandonmentPosts:ack.totalFormalPosts,previousFormalPosts:1,additionalFormalPosts:ack.additionalFormalPosts,observedWithoutAdditionalPost:current.alreadyClosed,nativeOperationsBefore:1,nativeOperationsAfter:1,keyCipherUnchanged:true,firstMetadataRequestReplayed:false,firstGrantRequestReplayed:false,failedSecondExecuteReplayed:false,newRequestKeyExplicitlySavedBeforePost:true};
 await finishM6CredentialFlow(h,context);
}catch(error){failure=error;}
process.exitCode=await h.finish(failure);
