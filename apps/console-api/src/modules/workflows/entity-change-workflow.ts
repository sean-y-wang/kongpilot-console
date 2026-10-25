import { BadRequestException } from '@nestjs/common';
import type { WorkflowPlanV1, WorkflowStep } from './workflow.types';
import type { EntityChangeNormalizedPacket, EntityChangeWorkflowPayload } from './entity-change-intent.types';
import type { PreparedEntityChange } from '../entities/entity-change.types';

const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i, digest = /^[a-f0-9]{64}$/;
/** One fixed reference wrapper. Its empty nativeRequests never authorizes the
 * separately stored packets through the legacy V1 metadata/native dispatcher. */
export function assertEntityChangeWorkflowPlan(plan: WorkflowPlanV1): WorkflowStep {
  const invalid = (): never => { throw new BadRequestException({ code: 'ENTITY_CHANGE_WORKFLOW_INVALID' }); };
  if (!plan || (plan.kind as string) !== 'native-change' || (plan.subject.type as string) !== 'entity_change_intents' || plan.requester.type !== 'console'
    || plan.steps.length !== 1 || plan.prerequisites.length || plan.generated !== undefined || plan.migration !== undefined) invalid();
  const step = plan.steps[0], payload = step.metadata as EntityChangeWorkflowPayload;
  if (step.kind !== 'metadata' || step.handler !== 'entity.change' || step.entityType !== 'entity_change_intents' || step.entityId !== plan.subject.id || step.parentId != null || step.credentialKind != null
    || step.nativeRequests.length || step.dependencies.length || step.mutationAction !== undefined || step.mutationPayload !== undefined || step.mutationIdempotencyKey !== undefined || step.beforeFingerprint !== undefined || step.permissionAction !== 'write'
    || !payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).length !== 5 || !['intentId', 'intentRevision', 'materialHmac', 'changeDigest', 'packetManifestHmac'].every(key => Object.hasOwn(payload, key))
    || payload.intentId !== plan.subject.id || !uuid.test(payload.intentId) || !Number.isSafeInteger(payload.intentRevision) || payload.intentRevision < 1
    || !digest.test(payload.materialHmac) || !digest.test(payload.changeDigest) || !digest.test(payload.packetManifestHmac) || !digest.test(step.metadataPayloadHmac ?? '') || !digest.test(step.metadataBeforeHmac ?? '') || step.metadataRevision !== payload.intentRevision) invalid();
  return step;
}
export function normalizedEntityChangePackets(material: PreparedEntityChange, secrets: { fingerprint(value: unknown): string }): EntityChangeNormalizedPacket[] {
  return material.packets.map(packet => ({ key: packet.key, order: packet.order, dependencies: [...packet.dependencies], method: packet.method, pathHmac: secrets.fingerprint(packet.canonicalPath), nativeType: packet.nativeType,
    nativeId: packet.nativeId, parentId: packet.parentId ?? null, credentialKind: packet.credentialKind ?? null, originalNativeId: packet.originalNativeId ?? null,
    mutationAction: packet.mutationAction, permissionAction: packet.permissionAction, bodyHmac: packet.bodyHmac, beforeHmac: packet.beforeHmac }));
}
export const entityChangeIntentAad = (cid: string, wid: string, intentId: string, revision: number): string => `entity-change:${cid}:${wid}:${intentId}:${revision}:material`;
