import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

/** The original failure is retained. This validates a separately authorized
 * analytical intent; it neither changes that receipt nor grants native writes. */
export function validateFreshInspectionIntent({ intent, proofBytes, originalPacket, actorId, clusterId, workspaceId, path, body }) {
  assert(intent && intent.label === 'm10-inspection-initial-after-rule-projection', 'EXPLICIT_FRESH_INSPECTION_INTENT_REQUIRED');
  const bytes = Buffer.from(proofBytes), hash = createHash('sha256').update(bytes).digest('hex');
  assert.equal(hash, intent.proofSha256, 'ORIGINAL_ZERO_NATIVE_PROOF_HASH_CHANGED');
  const proof = JSON.parse(bytes.toString('utf8'));
  assert.equal(proof.originalRequestId, intent.previousRequestId); assert.equal(proof.originalKey, intent.previousKey); assert.equal(proof.originalRunId, intent.previousRunId);
  assert.equal(proof.sourceClusterId, clusterId); assert.equal(proof.sourceWorkspaceId, workspaceId); assert.equal(proof.originalStatus, 500); assert.equal(proof.originalState, 'uncertain');
  assert.equal(proof.actualNativeMutationCount, 0); assert.equal(proof.originalReceiptVerified, true); assert.equal(proof.nativeExecutionRequested, false); assert.equal(proof.originalResponseRewritten, false); assert.equal(proof.nativeReplayed, false);
  assert(originalPacket && originalPacket.label === 'm10-inspection-initial-failed-before-rule-projection', 'ORIGINAL_FAILED_INSPECTION_PACKET_REQUIRED');
  assert.equal(originalPacket.requestId, intent.previousRequestId); assert.equal(originalPacket.key, intent.previousKey); assert.equal(originalPacket.actorId, actorId); assert.equal(originalPacket.path, path); assert.equal(originalPacket.method, 'POST'); assert.equal(originalPacket.status, 500); assert.equal(originalPacket.errorCode, proof.originalErrorCode); assert.equal(originalPacket.state, 'response_observed');
  assert.equal(originalPacket.bodyHash, createHash('sha256').update(JSON.stringify(body)).digest('hex')); assert.equal(originalPacket.resolution?.knownNoNativeSend, true);
  return { label: intent.label, originalRunId: proof.originalRunId, originalKey: proof.originalKey, originalRequestId: proof.originalRequestId, proofSha256: hash };
}
