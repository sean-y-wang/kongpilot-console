import {readFileSync} from 'node:fs';
import {M6Harness} from './lib/m6-harness.mjs';
import {guardMetadataRecovery,reconcileOriginalMetadata} from './lib/m6-metadata-recovery.mjs';
import {PENDING_KEY_TUPLE as T} from './lib/m6-pending-key-capture.mjs';
import {observeActivatedGrant,finishM6CredentialFlow} from './live-m6.mjs';

if(process.env.M6_DEPLOYMENT_READY!=='true'||process.env.M6_METADATA_RECOVERY_READY!=='true')throw new Error('Root actual patched runtime and exact metadata-only recovery handoff required');
const h=new M6Harness({requireReference:true});let failure;
try{
  const previous=JSON.parse(readFileSync('artifacts/M6/security-live-pre-fix-credential-execution.json','utf8'));
  h.check(previous.testTag===h.tag&&previous.passed===269&&previous.failed===1,'MetadataRecovery/Evidence','preserved actual credential execution checkpoint is this exact run');
  h.checks.unshift(...previous.checks.filter(c=>c.passed));
  for(const key of['isolatedTransition','boundaryRefusalProof','portalTestClusters','retainedMonitoringFamilies','credentialContinuation'])if(previous[key])h.public[key]=previous[key];
  const proof=JSON.parse(readFileSync('artifacts/M6/credential-execution-failure-proof.json','utf8')),context=await guardMetadataRecovery(h,proof);
  await reconcileOriginalMetadata(h,context);
  const capturedBeforeReveal=new Set(h.secrets);
  const recovered=await observeActivatedGrant(h,context.primary,context.developer,context.app,context.primary.publications[0],T.grantId,T.workflowId,T.credentialId);
  h.check(capturedBeforeReveal.has(recovered.apiKey)&&recovered.managed.consumer_id===T.consumerId&&recovered.managed.acl_id===T.aclId&&recovered.managed.kong_id===T.nativeId,'MetadataRecovery/Identity','normal active Portal reveal retains the already-captured original Key and all three allocated native IDs');
  h.public.metadataRecovery={previousFailureEvidence:'security-live-pre-fix-credential-execution.json',previousPassingChecks:269,originalExecutionKeyUsed:true,reconcilePosts:1,firstRequestRepeated:false,firstApprovalRepeated:false,firstExecutionRepeated:false,originalNativeOperations:3,immutableKeyPreserved:true};
  await finishM6CredentialFlow(h,{...context,metadataRecoveryVerified:true,recoveredFirstGrant:recovered});
}catch(error){failure=error;}
process.exitCode=await h.finish(failure);
