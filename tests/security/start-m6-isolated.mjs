import { randomUUID } from 'node:crypto';
import { M6Harness,M6_C2 } from './lib/m6-harness.mjs';
import { guardOldIsolatedFacts,guardIsolatedTransition,isolatedReference,registerIsolatedCluster } from './lib/m6-isolated-transition.mjs';
import { runM6 } from './live-m6.mjs';

if(process.env.M6_DEPLOYMENT_READY!=='true'||process.env.M6_ISOLATED_FIXTURE_READY!=='true')throw new Error('M6 isolated deployment and explicit sole new-fixture handoff required');
const h=new M6Harness({requireReference:true});let failure;
try{
  h.check(h.referenceData.phase==='bootstrap'&&!h.referenceData.isolatedRegistration&&!h.referenceData.isolatedStart,'Isolation/Fresh','this new isolated registration has never been attempted; prior unknowns require original receipts');
  await guardOldIsolatedFacts(h);
  const tag=`m6-isolated-${randomUUID().slice(0,8)}`,adminUrl='http://kong-portal-admin-endpoint:8001';
  const cluster=await registerIsolatedCluster(h,tag);
  const targets={primary:{id:cluster.id,adminUrl,proxyOrigin:'http://127.0.0.1:10000'},secondary:{id:M6_C2,adminUrl:'http://kong-secondary:8001',proxyOrigin:'http://127.0.0.1:9000'}};
  const proof=await guardIsolatedTransition(h,h.referenceData.isolatedTransitionOldProof,targets);
  const next=isolatedReference(h.referenceData,proof,targets,tag);
  h.referenceData=next;h.tag=tag;h.saveReference();
  h.public.isolatedTransition={previousCheckpointSha256:next.isolatedStart.previousCheckpointSha256,priorAttemptsPreserved:true,oldIssuedFacts:proof.oldFacts,originalFailedPublicationState:proof.publicationReceipt.state,originalFailedAclState:proof.aclReceipt.state,newPrimaryClusterId:cluster.id,canonicalMetricsUnchanged:true,originalPostsReplayed:false};
  await runM6(h,{isolatedStart:true});
}catch(error){failure=error;}
process.exitCode=await h.finish(failure);
