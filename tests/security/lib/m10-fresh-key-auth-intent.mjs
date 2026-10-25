import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const FRESH_KEY_AUTH_PREFIX='m10-optin-key-auth-after-adapter-label-fix';
const sha=value=>createHash('sha256').update(value).digest('hex');
const uuid=value=>typeof value==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const hex=value=>typeof value==='string'&&/^[a-f\d]{64}$/.test(value);

/** Root may authorize this one new cycle only after the exact old 409/blocked
 * registration is proven unsent. Neither old packets nor old proof bytes are
 * edited; a new candidate alone does not authorize a fresh credential write. */
export function validateFreshKeyAuthIntent({intent,proofBytes,diagnosticBytes,failedDeploymentBytes,phaseState,originalPacket,originalComparisonPacket,
  actorId,sourceClusterId,sourceWorkspaceId,targetClusterId,targetWorkspaceId,currentRuntimeSourceSha256,sourceRoots}) {
  assert(intent&&intent.version===1&&intent.prefix===FRESH_KEY_AUTH_PREFIX,'FIXED_ROOT_FRESH_KEY_AUTH_INTENT_REQUIRED');
  assert.equal(phaseState?.state,'stopped','ACTUAL_ORIGINAL_KEY_AUTH_PHASE_STOP_REQUIRED');assert.equal(phaseState.nativeVerified,false);
  const bytes=Buffer.from(proofBytes),proofSha256=sha(bytes);assert.equal(intent.proofSha256,proofSha256,'FRESH_KEY_AUTH_PROOF_BYTES_CHANGED');
  const proof=JSON.parse(bytes.toString('utf8'));assert.equal(proof.version,1);assert.equal(proof.kind,'key-auth-adapter-label-failure');assert.equal(proof.prefix,FRESH_KEY_AUTH_PREFIX);
  const scope={actorId,sourceClusterId,sourceWorkspaceId,targetClusterId,targetWorkspaceId};
  for(const[field,value]of Object.entries(scope)){assert(uuid(value));assert.equal(intent[field],value);assert.equal(proof[field],value);}
  for(const field of ['originalRequestId','originalKey','originalComparisonId','originalParentId','sourceSnapshotId']){assert(uuid(intent[field]));assert.equal(proof[field],intent[field]);}
  assert(hex(intent.originalBodyHash));assert.equal(proof.originalBodyHash,intent.originalBodyHash);
  assert.equal(proof.originalStatus,409);assert.equal(proof.originalErrorCode,'CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED');assert.equal(proof.originalPhase,'stopped');assert.equal(proof.parentState,'blocked');
  assert.equal(proof.originalResponseRewritten,false);assert.equal(proof.nativeReplayed,false);
  const failureBytes=Buffer.from(failedDeploymentBytes),failure=JSON.parse(failureBytes.toString('utf8'));
  assert.equal(intent.failedDeploymentSha256,sha(failureBytes));assert.equal(proof.failedDeploymentSha256,sha(failureBytes));assert.equal(failure.phase,'m10-candidate-v6');
  assert(hex(intent.failedRuntimeSourceSha256));assert.equal(failure.apiSourceSha256,intent.failedRuntimeSourceSha256);assert.equal(proof.failedRuntimeSourceSha256,intent.failedRuntimeSourceSha256);
  for(const field of ['apiBuildExit','copyExit','apiRestartExit'])assert.equal(failure[field],0);assert.equal(failure.readinessStatus,200);
  assert(hex(currentRuntimeSourceSha256));assert.equal(intent.candidateRuntimeSourceSha256,currentRuntimeSourceSha256);assert.equal(proof.candidateRuntimeSourceSha256,currentRuntimeSourceSha256);
  assert.notEqual(currentRuntimeSourceSha256,intent.failedRuntimeSourceSha256,'A_DISTINCT_OPTIN_ADAPTER_FIX_CANDIDATE_IS_REQUIRED');
  assert(originalPacket&&originalPacket.label==='m10-optin-key-auth-plan'&&originalPacket.state==='response_observed');
  for(const[field,value]of Object.entries({requestId:intent.originalRequestId,key:intent.originalKey,actorId,method:'POST',status:409,errorCode:proof.originalErrorCode,bodyHash:intent.originalBodyHash}))assert.equal(originalPacket[field],value);
  assert.equal(originalPacket.path,`/clusters/${sourceClusterId}/governance/comparisons/${intent.originalComparisonId}/promote-plan?${new URLSearchParams({workspaceId:sourceWorkspaceId})}`);
  assert.equal(sha(JSON.stringify(originalPacket.body)),intent.originalBodyHash);assert.equal(originalPacket.body.includeSecrets,true);assert.equal(originalPacket.body.includeCredentials,true);assert.deepEqual(originalPacket.body.credentialKinds,['key-auth']);
  assert(originalComparisonPacket&&originalComparisonPacket.label==='m10-optin-key-auth-comparison'&&originalComparisonPacket.state==='response_observed'&&[200,201].includes(originalComparisonPacket.status));
  assert.equal(originalComparisonPacket.actorId,actorId);assert.equal(originalComparisonPacket.method,'POST');assert.equal(originalComparisonPacket.path,`/clusters/${sourceClusterId}/governance/comparisons?${new URLSearchParams({workspaceId:sourceWorkspaceId})}`);
  assert.equal(originalComparisonPacket.responseData?.entity?.id,intent.originalComparisonId);
  const diagnosticData=Buffer.from(diagnosticBytes),diagnostic=JSON.parse(diagnosticData.toString('utf8'));
  assert.equal(intent.diagnosticSha256,sha(diagnosticData));assert.equal(proof.diagnosticSha256,sha(diagnosticData));
  for(const[field,value]of Object.entries({...scope,originalRequestId:intent.originalRequestId,originalKey:intent.originalKey,originalStatus:409,errorCode:proof.originalErrorCode,
    runtimeSourceSha256:intent.failedRuntimeSourceSha256,parentId:intent.originalParentId,parentState:'blocked',comparisonId:intent.originalComparisonId,sourceSnapshotId:intent.sourceSnapshotId,
    passed:true,consoleReadOnly:true,originalResponseRewritten:false,nativeReplayed:false,scopeEqual:true,kongVersionEqual:true,graphKongVersion:'1.5.1',completeness:'complete',consistency:'console_fenced_best_effort',manifestMatched:true,
    graphAdapterVersion:'kong-oss-1.5-v1',inventoryAdapterVersion:null,originFallbackAdapter:'kong-1.5'}))assert.equal(diagnostic[field],value);
  const roots=diagnostic.rootChecks;assert(Array.isArray(roots)&&roots.length===6&&Array.isArray(sourceRoots)&&sourceRoots.length===6);
  const identity=row=>`${row.entityType}:${row.nativeId}`;assert.equal(new Set(roots.map(identity)).size,6);assert.deepEqual(roots.map(identity).sort(),sourceRoots.map(identity).sort());
  for(const root of roots){assert(uuid(root.nativeId));assert.equal(root.present,true);assert.equal(root.beforeHmacMatches,true);assert.equal(root.payloadMatches,true);}
  const consumers=sourceRoots.filter(root=>root.entityType==='consumers');assert.equal(consumers.length,1);
  assert.deepEqual(originalPacket.body.selectedObjectKeys,[`consumers:${consumers[0].nativeId}`]);assert.equal(originalPacket.body.includeEnvironmentFields,false);
  assert.equal(originalPacket.body.confirmed,true);assert.equal(originalPacket.body.confirm_name,`PROMOTE ${intent.originalComparisonId}`);
  assert.equal(originalComparisonPacket.bodyHash,sha(JSON.stringify(originalComparisonPacket.body)));assert.equal(originalComparisonPacket.body?.scope,'workspace');
  assert.equal(originalComparisonPacket.body?.target?.clusterId,targetClusterId);assert.equal(originalComparisonPacket.body?.target?.workspaceId,targetWorkspaceId);
  assert.notEqual(originalComparisonPacket.key,intent.originalKey);
  for(const field of ['count','started','completed'])assert.equal(diagnostic.actualTargetMutationCounters?.[field],0);
  const zero=proof.actualZeroNative;assert(zero&&zero.passed===true&&zero.mode==='no-native'&&zero.consoleReadOnly===true);
  assert(hex(intent.zeroNativeRuntimeSourceSha256));assert.equal(proof.zeroNativeRuntimeSourceSha256,intent.zeroNativeRuntimeSourceSha256);
  assert([intent.failedRuntimeSourceSha256,currentRuntimeSourceSha256].includes(intent.zeroNativeRuntimeSourceSha256),'ACTUAL_ZERO_NATIVE_RUNTIME_MUST_BE_ONE_OF_THE_BOUND_DEPLOYMENTS');
  for(const[field,value]of Object.entries({requestId:intent.originalRequestId,actorId,clusterId:targetClusterId,workspaceId:targetWorkspaceId,runtimeSourceSha256:intent.zeroNativeRuntimeSourceSha256,
    configurationJobCount:0,mutationCount:0,nativeStartedCount:0,nativeCompletedCount:0,runtimeDistMatched:true,migrationChecksumsMatched:true,kongDatabaseAccess:false,independentWireLogClaim:false}))assert.equal(zero[field],value);
  return {prefix:FRESH_KEY_AUTH_PREFIX,proofSha256,originalComparisonId:intent.originalComparisonId,originalParentId:intent.originalParentId,originalKey:intent.originalKey,sourceSnapshotId:intent.sourceSnapshotId};
}
