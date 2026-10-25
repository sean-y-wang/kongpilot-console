import { ConflictException } from '@nestjs/common';
import type { DbService } from '../../infrastructure/db.service';
import type { SecretService } from '../../infrastructure/secret.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import type { EntityActor } from '../entities/entities.types';
import type { EntityRecycleOriginReaderService } from '../recycle-bin/entity-recycle-origin-reader.service';
import { derivePreparedRecyclePackets } from '../recycle-bin/entity-prepared-recycle-writer.service';
import { validatePartialRecycleRestoreSelection } from '../recycle-bin/partial-recycle-restore';
import type { EntityChangeExecutionSource, EntityChangeIntentEnvelope } from './entity-change-intent.types';
import { assertEntityChangeWorkflowPlan, normalizedEntityChangePackets } from './entity-change-workflow';
import type { WorkflowPlanV1 } from './workflow.types';

export interface PartialNoSendTerminalInput {
  readonly tx: DbService; readonly secrets: SecretService;
  readonly reader: Pick<EntityRecycleOriginReaderService, 'certifyKnownNoSendPartialSource'>;
  readonly plan: WorkflowPlanV1; readonly envelope: EntityChangeIntentEnvelope;
  readonly source: EntityChangeExecutionSource; readonly actor: EntityActor;
}
export interface PartialNoSendTerminalCertificate {
  readonly entryId: string; readonly failedNodeKey: string; readonly failedPacketKey: string;
  readonly failedOperationId: string; readonly failedAttemptId: string;
  readonly outcomeEventId: string; readonly outcomeFactHmac: string;
  readonly coveredOldSourceId: string; readonly graphHmac: string; readonly proofHmac: string;
  readonly alreadyClosed: boolean;
  readonly coveredPresent: 5; readonly nativeSuccesses: 0; readonly knownNotSent: 1; readonly unattempted: 1;
}
const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const hex = /^[a-f\d]{64}$/;
const invalid = () => new ConflictException({ code: 'ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_PROOF_INVALID' });

/** SELECT-only binding of Root's sealed current execution to the fixed Reader
 * certifier. The Reader independently authenticates SQL020 intent/plan, SQL021
 * complete baseline/outcome and SQL025 five present observations, original
 * closed five-success history, one failed-known-not-sent HMAC attempt without
 * send-intent and untouched ACL. Its summary is historical evidence, never an
 * HTTP DTO, native permit, renewed SID or a reason to retry any packet.
 * Root separately owns original-key/current authority/approval/locks/audit and
 * may project only entry+HMAC-node metadata while workflow/mutation stay failed. */
export async function certifyPartialNoSendTerminalMetadata(input: PartialNoSendTerminalInput): Promise<Readonly<PartialNoSendTerminalCertificate>> {
  try { return await certify(input); }
  catch { throw invalid(); }
}
async function certify(input: PartialNoSendTerminalInput): Promise<Readonly<PartialNoSendTerminalCertificate>> {
  const { secrets } = input;
  const seed = secrets.fingerprint({ plan: input.plan, envelope: input.envelope, source: input.source, actor: input.actor });
  const { plan, envelope, source, actor } = immutableJson({ plan: input.plan, envelope: input.envelope, source: input.source, actor: input.actor });
  if (!source || 'origin' in source || !uuid.test(source.sessionId) || envelope.version !== 1
    || actor.user.id !== source.executionActorId || actor.workspaceId !== source.workspaceId
    || plan.clusterId !== source.clusterId || plan.workspaceId !== source.workspaceId || plan.workflowId !== source.workflowId
    || plan.planRevision !== source.workflowPlanRevision || secrets.fingerprint(plan) !== source.workflowPlanHash
    || plan.requester.type !== 'console' || plan.requester.id !== source.executionActorId
    || envelope.clusterId !== source.clusterId || envelope.workspaceId !== source.workspaceId || envelope.intentId !== source.intentId
    || envelope.revision !== source.intentRevision || envelope.requesterId !== source.executionActorId || envelope.credentialEpoch !== source.credentialEpoch
    || secrets.fingerprint(envelope) !== source.materialHmac || envelope.packetManifestHmac !== source.packetManifestHmac) throw invalid();
  const step = assertEntityChangeWorkflowPlan(plan), material = envelope.prepared, { changeDigest, ...original } = material;
  if (secrets.fingerprint(step.metadata) !== secrets.fingerprint({ intentId: source.intentId, intentRevision: source.intentRevision,
      materialHmac: source.materialHmac, changeDigest: source.changeDigest, packetManifestHmac: source.packetManifestHmac })
    || material.request.kind !== 'recycle' || material.request.action !== 'restore' || material.request.confirmed !== true
    || material.clusterId !== source.clusterId || material.workspaceId !== source.workspaceId || material.requesterId !== source.executionActorId
    || material.scope.transportScope !== plan.scope.transportScope || !hex.test(plan.scope.transportScope)
    || changeDigest !== source.changeDigest || secrets.fingerprint(original) !== changeDigest) throw invalid();
  const restores = material.metadataObligations.filter(item => item.kind === 'recycle-restore');
  if (restores.length !== 1 || restores[0].kind !== 'recycle-restore') throw invalid();
  const obligation = restores[0], partial = obligation.partialRestore;
  if (!partial || material.request.entryId !== obligation.entryId || !uuid.test(obligation.entryId)
    || obligation.sealedEntry.state !== 'partially_restored' || obligation.sealedEntry.clusterId !== source.clusterId
    || obligation.sealedEntry.workspaceId !== source.workspaceId || obligation.sealedEntry.entryId !== obligation.entryId) throw invalid();
  const partition = validatePartialRecycleRestoreSelection(obligation.graph, partial, secrets);
  const fixed = derivePreparedRecyclePackets(obligation, material.packets, secrets);
  if (fixed.length !== 2 || material.packets.length !== 2 || fixed[0].node.type !== 'hmac-auth' || fixed[1].node.type !== 'acls'
    || material.packets.some((packet, index) => packet.order !== index + 1 || packet.method !== 'POST' || packet.before !== null
      || packet.mutationAction !== 'restore' || packet.permissionAction !== 'write')
    || partition.present.length !== 5 || partition.remaining.length !== 2
    || secrets.fingerprint(normalizedEntityChangePackets(material, secrets)) !== source.packetManifestHmac) throw invalid();
  const footprint = await input.reader.certifyKnownNoSendPartialSource({ clusterId: source.clusterId, workspaceId: source.workspaceId,
    entryId: obligation.entryId, actor, subjectAction: 'write' }, source.id, input.tx);
  if (footprint.clusterId !== source.clusterId || footprint.workspaceId !== source.workspaceId || footprint.entryId !== obligation.entryId
    || footprint.sourceId !== source.id || footprint.sourceHmac !== secrets.fingerprint(source)
    || footprint.workflowId !== source.workflowId || footprint.workflowExecutionId !== source.workflowExecutionId
    || footprint.intentId !== source.intentId || footprint.intentRevision !== source.intentRevision || footprint.materialHmac !== source.materialHmac
    || footprint.changeDigest !== source.changeDigest || footprint.packetManifestHmac !== source.packetManifestHmac
    || footprint.oldSourceId !== partial.history.sourceId || footprint.historyCoverageHmac !== partial.history.coverageHmac
    || footprint.graphHmac !== obligation.graphHmac || footprint.graphHmac !== secrets.fingerprint(obligation.graph)
    || footprint.failedNodeKey !== fixed[0].node.key || footprint.failedPacketKey !== material.packets[0].key
    || [footprint.baselineId, footprint.pinId, footprint.operationId, footprint.attemptId, footprint.outcomeEventId].some(value => !uuid.test(value))
    || [footprint.outcomeFactHmac, footprint.proofHmac].some(value => !hex.test(value)) || typeof footprint.alreadyClosed !== 'boolean') throw invalid();
  if (seed !== secrets.fingerprint({ plan: input.plan, envelope: input.envelope, source: input.source, actor: input.actor })) throw invalid();
  return immutableJson({ entryId: obligation.entryId, failedNodeKey: footprint.failedNodeKey, failedPacketKey: footprint.failedPacketKey,
    failedOperationId: footprint.operationId, failedAttemptId: footprint.attemptId, outcomeEventId: footprint.outcomeEventId,
    outcomeFactHmac: footprint.outcomeFactHmac, coveredOldSourceId: footprint.oldSourceId, graphHmac: footprint.graphHmac,
    proofHmac: footprint.proofHmac, alreadyClosed: footprint.alreadyClosed,
    coveredPresent: 5 as const, nativeSuccesses: 0 as const, knownNotSent: 1 as const, unattempted: 1 as const });
}
