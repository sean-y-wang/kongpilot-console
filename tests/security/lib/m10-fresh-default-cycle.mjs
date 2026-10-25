import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const FRESH_DEFAULT_CYCLE_LABELS = Object.freeze({
  comparisonLabel: 'm10-default-cycle-after-frame-free-verifier-comparison',
  planLabel: 'm10-default-cycle-after-frame-free-verifier-plan',
  applyLabel: 'm10-default-cycle-after-frame-free-verifier-apply',
});
const uuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const hex = value => typeof value === 'string' && /^[a-f\d]{64}$/.test(value);
const bodyHash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

export function successfulDefaultCycleDeployment(tuple, deploymentBytes) {
  assert(tuple&&hex(tuple.runtimeSourceSha256)&&hex(tuple.successfulDeploymentSha256),'ACTUAL_SUCCESSFUL_DEFAULT_DEPLOYMENT_REQUIRED');
  const bytes=Buffer.from(deploymentBytes);assert.equal(createHash('sha256').update(bytes).digest('hex'),tuple.successfulDeploymentSha256,'SUCCESSFUL_DEFAULT_DEPLOYMENT_BYTES_CHANGED');
  const receipt=JSON.parse(bytes.toString('utf8'));assert.equal(receipt.phase,'m10-candidate-v6');assert.equal(receipt.apiSourceSha256,tuple.runtimeSourceSha256);
  for(const field of ['apiBuildExit','copyExit','apiRestartExit'])assert.equal(receipt[field],0);assert.equal(receipt.readinessStatus,200);
  return receipt.apiSourceSha256;
}

export function preserveM10TimerFixtures(previous, current, actorId) {
  if(!previous)return current;
  for(const field of ['sourceClusterId','sourceWorkspaceId','targetClusterId','targetWorkspaceId','inspectionScheduleId','driftScheduleId'])assert.equal(previous[field],current[field],'ORIGINAL_TIMER_FIXTURE_IDENTITY_REQUIRED');
  if(previous.actorId!==undefined)assert.equal(previous.actorId,actorId);
  const manifest=previous.observationManifest;
  if(manifest){assert.equal(manifest.actorId,actorId);for(const field of ['sourceClusterId','sourceWorkspaceId','targetClusterId','targetWorkspaceId'])assert.equal(manifest[field],current[field]);
    for(const [kind,field]of [['inspection','inspectionScheduleId'],['drift','driftScheduleId']])assert.equal(manifest.schedules?.find(row=>row.kind===kind)?.id,current[field]);}
  if(previous.registeredAt!==undefined)assert.equal(current.registeredAt,previous.registeredAt,'ORIGINAL_TIMER_REGISTRATION_TIME_REQUIRED');
  return {...previous,...current};
}

/** Root explicitly authorizes a fresh cycle because the immutable old plan
 * expired after a known registered-but-unsent failure. One failed job is a
 * real fact, not zero jobs. This helper never alters or renews the old plan. */
export function validateFreshDefaultCycle({ intent, proofBytes, failedDeploymentBytes, originalPacket, actorId, sourceClusterId, sourceWorkspaceId, targetClusterId, targetWorkspaceId, currentRuntimeSourceSha256 }) {
  assert(intent && intent.version === 1, 'FIXED_FRESH_DEFAULT_CYCLE_INTENT_REQUIRED');
  for (const [name, label] of Object.entries(FRESH_DEFAULT_CYCLE_LABELS)) assert.equal(intent[name], label, 'FIXED_FRESH_DEFAULT_CYCLE_LABEL_REQUIRED');
  const bytes = Buffer.from(proofBytes), proofSha256 = createHash('sha256').update(bytes).digest('hex');
  assert.equal(intent.proofSha256, proofSha256, 'FRESH_DEFAULT_CYCLE_PROOF_BYTES_CHANGED');
  const proof = JSON.parse(bytes.toString('utf8'));
  assert.equal(proof.version, 1); assert.equal(proof.kind, 'failed-default-promote-origin');
  const scope = { actorId, sourceClusterId, sourceWorkspaceId, targetClusterId, targetWorkspaceId };
  for (const [name, value] of Object.entries(scope)) { assert(uuid(value)); assert.equal(intent[name], value); assert.equal(proof[name], value); }
  for (const name of ['originalRequestId','originalKey','inputPlanId','copiedPlanId','failedJobId','executionId']) {
    assert(uuid(intent[name]), 'ACTUAL_ORIGINAL_FAILURE_UUID_REQUIRED'); assert.equal(proof[name], intent[name]);
  }
  assert.notEqual(intent.inputPlanId, intent.copiedPlanId);
  assert(hex(intent.originalBodyHash)); assert.equal(proof.originalBodyHash, intent.originalBodyHash);
  assert(hex(intent.failedRuntimeSourceSha256)); assert.equal(proof.failedRuntimeSourceSha256, intent.failedRuntimeSourceSha256);
  const failedBytes=Buffer.from(failedDeploymentBytes),failedDeploymentSha256=createHash('sha256').update(failedBytes).digest('hex');
  assert.equal(intent.failedDeploymentSha256,failedDeploymentSha256);assert.equal(proof.failedDeploymentSha256,failedDeploymentSha256);
  const failedDeployment=JSON.parse(failedBytes.toString('utf8'));assert.equal(failedDeployment.phase,'m10-candidate-v5');assert.equal(failedDeployment.apiSourceSha256,intent.failedRuntimeSourceSha256);
  for(const field of ['apiBuildExit','copyExit','apiRestartExit'])assert.equal(failedDeployment[field],0);assert.equal(failedDeployment.readinessStatus,200);
  assert(hex(currentRuntimeSourceSha256)); assert.notEqual(currentRuntimeSourceSha256, intent.failedRuntimeSourceSha256, 'A_DISTINCT_DEPLOYED_FIX_IS_REQUIRED');
  assert.equal(proof.originalStatus, 403); assert.equal(proof.originalErrorCode, 'KONG_EXECUTION_CONTEXT_REQUIRED'); assert.equal(proof.originalState, 'failed');
  for (const name of ['originalResponseRewritten','nativeReplayed','planRenewed']) assert.equal(proof[name], false);
  assert.equal(proof.inputPlanExpired, true); assert(Number.isFinite(Date.parse(proof.inputPlanExpiresAt)) && Number.isFinite(Date.parse(proof.observedAt)));
  assert(Date.parse(proof.inputPlanExpiresAt) <= Date.parse(proof.observedAt), 'ACTUAL_OLD_PLAN_EXPIRY_REQUIRED');
  assert(originalPacket && originalPacket.state === 'response_observed');
  assert.equal(originalPacket.requestId, intent.originalRequestId); assert.equal(originalPacket.key, intent.originalKey); assert.equal(originalPacket.actorId, actorId);
  assert.equal(originalPacket.method, 'POST'); assert.equal(originalPacket.status, 403); assert.equal(originalPacket.errorCode, proof.originalErrorCode);
  assert.equal(originalPacket.path, `/clusters/${targetClusterId}/configuration/plans/${intent.inputPlanId}/apply?${new URLSearchParams({ workspaceId: targetWorkspaceId })}`);
  assert.equal(originalPacket.bodyHash, intent.originalBodyHash); assert.equal(bodyHash(originalPacket.body), intent.originalBodyHash);
  const actual = proof.actualZeroNative;
  assert(actual && actual.passed === true && actual.mode === 'failed-no-native' && actual.consoleReadOnly === true);
  for (const [name, value] of Object.entries({ requestId: intent.originalRequestId, actorId, clusterId: targetClusterId, workspaceId: targetWorkspaceId,
    sourceClusterId, sourceWorkspaceId, failedJobId: intent.failedJobId, inputPlanId: intent.inputPlanId, copiedPlanId: intent.copiedPlanId, executionId: intent.executionId,
    runtimeSourceSha256: currentRuntimeSourceSha256, configurationJobCount: 1, jobState: 'failed', jobErrorCode: 'KONG_EXECUTION_CONTEXT_REQUIRED',
    mutationCount: 0, nativeStartedCount: 0, nativeCompletedCount: 0, jobRemoteStarted: false, jobRemoteCompleted: false,
    inputPlanExpired: true, immutableOriginMatched: true, runtimeDistMatched: true, migrationChecksumsMatched: true, kongDatabaseAccess: false, independentWireLogClaim: false })) assert.equal(actual[name], value);
  assert.equal(actual.inputPlanExpiresAt, proof.inputPlanExpiresAt);
  assert(hex(actual.initialDigest) && actual.initialDigest === actual.finalDigest && actual.transactionSnapshotDigestMatched === true, 'ACTUAL_FAILED_ORIGIN_ROW_DIGEST_REQUIRED');
  return { ...FRESH_DEFAULT_CYCLE_LABELS, proofSha256, failedRuntimeSourceSha256: intent.failedRuntimeSourceSha256, inputPlanId: intent.inputPlanId,
    copiedPlanId: intent.copiedPlanId, failedJobId: intent.failedJobId, originalRequestId: intent.originalRequestId, originalKey: intent.originalKey };
}

export function actualDefaultCycleEvidence(state, validated, { actorId, sourceClusterId, sourceWorkspaceId, targetClusterId, targetWorkspaceId }) {
  const tuple = state.governanceFixtures?.defaultCycle; assert(tuple && tuple.proofSha256 === validated.proofSha256, 'ACTUAL_FRESH_DEFAULT_CYCLE_HANDOFF_REQUIRED');
  const one = label => { const matches=state.requests.filter(row=>row.label===label);assert.equal(matches.length,1);const packet=matches[0];assert.equal(packet.actorId,actorId);assert.equal(packet.method,'POST');assert.equal(packet.state,'response_observed');assert([200,201].includes(packet.status));assert.equal(packet.bodyHash,bodyHash(packet.body));assert.notEqual(packet.key,validated.originalKey);return packet; };
  const comparison=one(validated.comparisonLabel), promotion=one(validated.planLabel), apply=one(validated.applyLabel);
  assert(new Set([comparison.key,promotion.key,apply.key]).size===3,'FRESH_CYCLE_KEYS_MUST_BE_DISTINCT');
  assert.equal(comparison.path,`/clusters/${sourceClusterId}/governance/comparisons?${new URLSearchParams({workspaceId:sourceWorkspaceId})}`);
  const entity=comparison.responseData?.entity;assert(entity && entity.id===tuple.comparisonId);assert.notEqual(entity.id,tuple.previousComparisonId);
  assert.equal(entity.source.clusterId,sourceClusterId);assert.equal(entity.source.workspaceId,sourceWorkspaceId);assert.equal(entity.target.clusterId,targetClusterId);assert.equal(entity.target.workspaceId,targetWorkspaceId);assert.equal(entity.quality,'complete');
  const cr=tuple.comparisonReceipt;assert(cr && cr.idempotencyKey===comparison.key && cr.actorId===actorId && cr.clusterId===sourceClusterId && cr.workspaceId===sourceWorkspaceId && cr.kind==='comparison' && cr.state==='succeeded' && cr.entity?.id===entity.id && cr.nativeExecutionRequested===false);
  assert.equal(promotion.path,`/clusters/${sourceClusterId}/governance/comparisons/${entity.id}/promote-plan?${new URLSearchParams({workspaceId:sourceWorkspaceId})}`);
  for(const flag of ['includeEnvironmentFields','includeSecrets','includeCredentials'])assert.equal(promotion.body[flag],false);assert.equal(promotion.body.confirmed,true);assert.equal(promotion.body.confirm_name,`PROMOTE ${entity.id}`);
  const pr=tuple.promotionReceipt;assert(pr && pr.idempotencyKey===promotion.key && pr.actorId===actorId && pr.clusterId===sourceClusterId && pr.workspaceId===sourceWorkspaceId && pr.kind==='promotion-plan' && pr.state==='ready' && pr.nativeExecutionRequested===false);
  assert.equal(pr.targetClusterId,targetClusterId);assert.equal(pr.targetWorkspaceId,targetWorkspaceId);assert.equal(pr.planId,tuple.planId);assert.equal(pr.jobId,tuple.sourceJobId);assert.equal(pr.id,tuple.promotionId);
  assert.equal(promotion.responseData.planId,tuple.planId);assert.equal(promotion.responseData.jobId,tuple.sourceJobId);
  assert(uuid(tuple.planId));assert.notEqual(tuple.planId,validated.inputPlanId);assert.notEqual(tuple.planId,validated.copiedPlanId);
  assert.equal(apply.path,`/clusters/${targetClusterId}/configuration/plans/${tuple.planId}/apply?${new URLSearchParams({workspaceId:targetWorkspaceId})}`);
  assert.equal(tuple.applyLabel,validated.applyLabel);assert.equal(tuple.applyJobId,apply.responseData?.jobId);
  return tuple;
}
