import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const FRESH_ROLLBACK_PREFIX='m10-optin-rollback-after-schema-union-fix';
const sha=value=>createHash('sha256').update(value).digest('hex');
const uuid=value=>typeof value==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const hex=value=>typeof value==='string'&&/^[a-f\d]{64}$/.test(value);

/** A fresh preview follows an explicitly proved schema-union failure. The old
 * failed compare and successful baseline capture are both real retained jobs;
 * zero native mutations must never be mislabeled zero jobs. */
export function validateFreshRollbackIntent({intent,proofBytes,diagnosticBytes,failedDeploymentBytes,phaseState,originalPacket,priorKeyAuth,
  actorId,targetClusterId,targetWorkspaceId,currentRuntimeSourceSha256}) {
  assert(intent&&intent.version===1&&intent.prefix===FRESH_ROLLBACK_PREFIX,'FIXED_ROOT_FRESH_ROLLBACK_INTENT_REQUIRED');
  assert.equal(phaseState?.state,'stopped');assert.equal(phaseState.nativeVerified,false);
  const bytes=Buffer.from(proofBytes),proofSha256=sha(bytes);assert.equal(intent.proofSha256,proofSha256,'FRESH_ROLLBACK_PROOF_BYTES_CHANGED');
  const proof=JSON.parse(bytes.toString('utf8'));assert.equal(proof.version,1);assert.equal(proof.kind,'rollback-schema-union-failure');assert.equal(proof.prefix,FRESH_ROLLBACK_PREFIX);
  const scope={actorId,targetClusterId,targetWorkspaceId};for(const[field,value]of Object.entries(scope)){assert(uuid(value));assert.equal(intent[field],value);assert.equal(proof[field],value);}
  for(const field of ['originalRequestId','originalKey','snapshotId','failedCompareJobId','baselineCaptureJobId','baselineSnapshotId']){assert(uuid(intent[field]));assert.equal(proof[field],intent[field]);}
  assert.notEqual(intent.failedCompareJobId,intent.baselineCaptureJobId);assert.notEqual(intent.snapshotId,intent.baselineSnapshotId);
  for(const field of ['snapshotVersion','baselineSnapshotVersion']){assert(Number.isSafeInteger(intent[field])&&intent[field]>0);assert.equal(proof[field],intent[field]);}
  assert(hex(intent.originalBodyHash));assert.equal(proof.originalBodyHash,intent.originalBodyHash);
  assert.equal(proof.originalStatus,409);assert.equal(proof.originalErrorCode,'CONFIGURATION_DIFF_SCOPE_MISMATCH');
  for(const field of ['originalResponseRewritten','nativeReplayed','snapshotMaterialChanged'])assert.equal(proof[field],false);
  const failedBytes=Buffer.from(failedDeploymentBytes),failed=JSON.parse(failedBytes.toString('utf8'));
  assert.equal(intent.failedDeploymentSha256,sha(failedBytes));assert.equal(proof.failedDeploymentSha256,sha(failedBytes));assert.equal(failed.phase,'m10-candidate-v7');
  assert(hex(intent.failedRuntimeSourceSha256));assert.equal(failed.apiSourceSha256,intent.failedRuntimeSourceSha256);assert.equal(proof.failedRuntimeSourceSha256,intent.failedRuntimeSourceSha256);
  for(const field of ['apiBuildExit','copyExit','apiRestartExit'])assert.equal(failed[field],0);assert.equal(failed.readinessStatus,200);
  assert(hex(currentRuntimeSourceSha256));assert.equal(intent.candidateRuntimeSourceSha256,currentRuntimeSourceSha256);assert.equal(proof.candidateRuntimeSourceSha256,currentRuntimeSourceSha256);
  assert.notEqual(currentRuntimeSourceSha256,intent.failedRuntimeSourceSha256,'A_DISTINCT_ROLLBACK_SCHEMA_FIX_CANDIDATE_IS_REQUIRED');
  assert(originalPacket&&originalPacket.label==='m10-optin-rollback-preview'&&originalPacket.state==='response_observed');
  for(const[field,value]of Object.entries({requestId:intent.originalRequestId,key:intent.originalKey,actorId,method:'POST',status:409,errorCode:proof.originalErrorCode,bodyHash:intent.originalBodyHash}))assert.equal(originalPacket[field],value);
  assert.equal(originalPacket.path,`/clusters/${targetClusterId}/snapshots/${intent.snapshotId}/rollback-plan?${new URLSearchParams({workspaceId:targetWorkspaceId})}`);
  assert.equal(sha(JSON.stringify(originalPacket.body)),intent.originalBodyHash);assert.equal(originalPacket.body.confirmed,true);assert.equal(originalPacket.body.confirm_deletes,true);
  const baseline=priorKeyAuth?.exactBaselineProof,executed=priorKeyAuth?.executed;
  assert(baseline&&baseline.passed===true&&baseline.mode==='origin'&&baseline.consoleReadOnly===true&&baseline.immutableOriginMatched===true);
  for(const[field,value]of Object.entries({actorId,clusterId:targetClusterId,workspaceId:targetWorkspaceId,actualBaselineSnapshotId:intent.snapshotId,actualBaselineVersion:intent.snapshotVersion,kongDatabaseAccess:false}))assert.equal(baseline[field],value);
  assert.equal(baseline.actualExecutionId,executed?.proof?.executionId);assert(uuid(baseline.actualExecutionId));assert.equal(executed.baselineSnapshotId,intent.snapshotId);assert.equal(executed.baselineVersion,intent.snapshotVersion);
  assert.equal(executed.proof.state,'succeeded');assert.equal(executed.proof.executionCompleted,true);
  assert.equal(intent.keyAuthBaselineProofSha256,sha(JSON.stringify(baseline)));assert.equal(proof.keyAuthBaselineProofSha256,intent.keyAuthBaselineProofSha256);
  const dBytes=Buffer.from(diagnosticBytes),d=JSON.parse(dBytes.toString('utf8'));assert.equal(intent.diagnosticSha256,sha(dBytes));assert.equal(proof.diagnosticSha256,sha(dBytes));
  for(const[field,value]of Object.entries({...scope,originalRequestId:intent.originalRequestId,originalKey:intent.originalKey,originalStatus:409,originalErrorCode:proof.originalErrorCode,
    originalResponseRewritten:false,nativeReplayed:false,runtimeSourceSha256:intent.failedRuntimeSourceSha256,consoleReadOnly:true,oldSnapshotId:intent.snapshotId,oldVersion:intent.snapshotVersion,
    newBaselineSnapshotId:intent.baselineSnapshotId,newBaselineVersion:intent.baselineSnapshotVersion,scopeEqual:true,kongVersionEqual:true,oldKongVersion:'1.5.1',adapterEqual:true,oldAdapterVersion:'kong-oss-1.5-v1',
    enabledPluginSetEqual:true,oldComplete:'complete',newComplete:'complete',oldFenced:'console_fenced_best_effort',newFenced:'console_fenced_best_effort',oldManifestVerified:true,newManifestVerified:true}))assert.equal(d[field],value);
  const names=['acls','basicauth_credentials','ca_certificates','certificates','consumers','hmacauth_credentials','jwt_secrets','keyauth_credentials','oauth2_credentials','plugins','routes','services','snis','targets','upstreams'];
  assert(Array.isArray(d.entitySchemas)&&d.entitySchemas.length===15);assert.deepEqual(d.entitySchemas.map(row=>row.name).sort(),names.slice().sort());
  for(const row of d.entitySchemas){assert.equal(row.inOld,true);assert.equal(row.inFresh,true);assert.equal(row.sameRawDefinition,true);}
  assert(Array.isArray(d.pluginSchemas)&&d.pluginSchemas.length===3);assert.deepEqual(d.pluginSchemas.map(row=>row.name).sort(),['aws-lambda','key-auth','request-termination']);
  for(const row of d.pluginSchemas){assert.equal(row.inFresh,true);assert.equal(row.inOld,row.name!=='aws-lambda');assert.equal(row.sameRawDefinition,row.name!=='aws-lambda');}
  assert(Array.isArray(d.compareJobs)&&d.compareJobs.length===2);const compare=d.compareJobs.find(row=>row.id===intent.failedCompareJobId),capture=d.compareJobs.find(row=>row.id===intent.baselineCaptureJobId);assert(compare&&capture);
  assert.equal(compare.kind,'compare');assert.equal(compare.state,'failed');assert.equal(compare.errorCode,proof.originalErrorCode);assert.equal(capture.kind,'capture');assert.equal(capture.state,'succeeded');assert.equal(capture.errorCode,null);
  for(const job of [compare,capture]){assert.equal(job.nativeStarted,false);assert.equal(job.nativeCompleted,false);}
  for(const field of ['count','started','completed'])assert.equal(d.actualNativeCounters?.[field],0);
  return {prefix:FRESH_ROLLBACK_PREFIX,proofSha256,originalKey:intent.originalKey,snapshotId:intent.snapshotId,snapshotVersion:intent.snapshotVersion,failedCompareJobId:intent.failedCompareJobId,baselineCaptureJobId:intent.baselineCaptureJobId};
}
