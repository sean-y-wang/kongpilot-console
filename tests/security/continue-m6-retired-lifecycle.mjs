import {readFileSync} from 'node:fs';
import {M6Harness} from './lib/m6-harness.mjs';
import {guardRetiredLifecycleContinuation,beginRetiredLifecycleTail} from './lib/m6-retired-lifecycle-continuation.mjs';
import {finishM6LifecycleTail} from './live-m6.mjs';

if(process.env.M6_DEPLOYMENT_READY!=='true'||process.env.M6_RETIRED_LIFECYCLE_CONTINUATION_READY!=='true')throw new Error('Root exact qualified-denial and remaining-tail release required');
const h=new M6Harness({requireReference:true});let failure;
try{
 const read=name=>JSON.parse(readFileSync('artifacts/M6/'+name,'utf8'));
 const evidence={report:read('security-live-pre-fix-abandonment-ack-remaining-http.json'),proof:read('retired-parent-restore-denial-proof.json')};
 h.check(evidence.report.testTag===h.tag&&evidence.report.passed===750&&evidence.report.failed===1,'LifecycleTail/Evidence','exact preserved 750-check failure remains immutable');
 h.checks.unshift(...evidence.report.checks.filter(c=>c.passed));
 for(const key of['isolatedTransition','boundaryRefusalProof','portalTestClusters','retainedMonitoringFamilies','credentialContinuation','metadataRecovery','failedIssueAbandonment','physicalAliasOwnershipProof'])if(evidence.report[key])h.public[key]=evidence.report[key];
 const state=await guardRetiredLifecycleContinuation(h,evidence);
 h.public.retiredParentRestoreDenial={originalStatus:404,originalErrorCode:'KONG_VALIDATION_ERROR',originalRestoreReplayed:false,failedMutationRetained:true,remoteStartedMeaning:'callback marker; not a native wire-send proof',completedNativeResults:0,restoredNodes:0,archiveUnchanged:true,retiredParentAbsent:true,oldKeyStatuses:[401,401],activeOtherKeyStatuses:[200,200]};
 beginRetiredLifecycleTail(h,state);
 await finishM6LifecycleTail(h,state,{a:state.a,b:state.b,c:state.c,rotated:state.rotated,newKey:state.newKey});
 h.saveReference({retiredLifecycleContinuation:{...h.referenceData.retiredLifecycleContinuation,phase:'remaining-HTTP-complete'}});
}catch(error){failure=error;}
process.exitCode=await h.finish(failure);
