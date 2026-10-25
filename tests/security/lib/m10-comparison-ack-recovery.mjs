import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

/** Verifies a separately observed GET acknowledgement. The old POST remains
 * forbidden, including its original status/body; no retry permission is minted. */
export function validateComparisonAcknowledgementRecovery({ recovery, intent, proofBytes, originalPacket, actorId, clusterId, workspaceId, targetClusterId, targetWorkspaceId, postPath, receiptPath, body }) {
  assert(recovery && intent && intent.label === 'm10-logical-comparison-v2-fresh-intent', 'EXPLICIT_COMPARISON_ACK_AND_FRESH_INTENT_REQUIRED');
  const hash = createHash('sha256').update(Buffer.from(proofBytes)).digest('hex'), proof = JSON.parse(Buffer.from(proofBytes).toString('utf8'));
  assert.equal(hash, recovery.proofSha256); assert.equal(hash, intent.proofSha256);
  for (const [field, expected] of Object.entries({ actorId, sourceClusterId: clusterId, sourceWorkspaceId: workspaceId, targetClusterId, targetWorkspaceId, originalStatus: 403, originalRunState: 'succeeded', quality: 'complete', actualNativeMutationCount: 0, recoveryMethod: 'GET', originalReceiptVerified: true, originalResponseRewritten: false, nativeReplayed: false, legacyMaterialVersion: 1 })) assert.equal(proof[field], expected, 'ORIGINAL_COMPARISON_PROOF_TUPLE_CHANGED');
  assert(originalPacket, 'ORIGINAL_403_POST_REQUIRED');
  for (const [field, expected] of Object.entries({ actorId, requestId: proof.originalRequestId, key: proof.originalKey, sessionId: proof.originalSessionId, method: 'POST', path: postPath, status: 403, state: 'response_observed', bodyHash: createHash('sha256').update(JSON.stringify(body)).digest('hex') })) assert.equal(originalPacket[field], expected, 'ORIGINAL_COMPARISON_POST_CHANGED');
  assert(typeof proof.originalSessionId === 'string' && proof.originalSessionId.length > 0, 'ORIGINAL_POST_SESSION_REQUIRED');
  for (const [field, expected] of Object.entries({ originalRequestId: proof.originalRequestId, originalKey: proof.originalKey, originalRunId: proof.originalRunId, comparisonId: proof.comparisonId, actorId, originalSessionId: proof.originalSessionId })) assert.equal(recovery[field], expected, 'ORIGINAL_GET_RECOVERY_LINK_CHANGED');
  for (const [field, expected] of Object.entries({ previousRequestId: proof.originalRequestId, previousKey: proof.originalKey, previousRunId: proof.originalRunId, previousComparisonId: proof.comparisonId })) assert.equal(intent[field], expected, 'FRESH_V2_INTENT_SOURCE_CHANGED');
  const get = recovery.recoveredGet; assert(get && get.method === 'GET' && get.path === receiptPath && get.status === 200 && get.actorId === actorId, 'ACTUAL_READONLY_GET_ACK_REQUIRED');
  const receipt = get.responseData;
  assert(receipt && receipt.id === proof.originalRunId && receipt.actorId === actorId && receipt.clusterId === clusterId && receipt.workspaceId === workspaceId && receipt.idempotencyKey === proof.originalKey && receipt.kind === 'comparison' && receipt.domain === 'governance' && receipt.state === 'succeeded' && receipt.registrationCompleted === true && receipt.executionCompleted === true && receipt.nativeExecutionRequested === false, 'ACTUAL_SEALED_ORIGINAL_COMPARISON_RECEIPT_REQUIRED');
  const entity = receipt.entity;
  assert(entity && entity.id === proof.comparisonId && entity.clusterId === clusterId && entity.workspaceId === workspaceId && entity.quality === 'complete' && entity.source?.clusterId === clusterId && entity.source?.workspaceId === workspaceId && entity.target?.clusterId === targetClusterId && entity.target?.workspaceId === targetWorkspaceId, 'ACTUAL_ORIGINAL_COMPARISON_ENTITY_REQUIRED');
  if (proof.confirmationName !== undefined) assert.equal(entity.confirmationName, proof.confirmationName);
  return { originalReceipt: receipt, originalKey: proof.originalKey, legacyComparisonId: proof.comparisonId, freshLabel: intent.label, proofSha256: hash };
}
