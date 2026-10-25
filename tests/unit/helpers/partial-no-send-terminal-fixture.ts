import { randomUUID } from 'node:crypto';
import { vi } from 'vitest';
import { terminalMetadataFixture } from './terminal-metadata-fixture';
import type { PartialNoSendTerminalInput } from '../../../apps/console-api/src/modules/workflows/entity-change-partial-no-send-terminal-proof';

/** Synthetic sealed-material fixture with an explicit Reader adapter. It tests
 * Root binding/projection only; Reader's own tests authenticate real schema
 * shapes and encrypted SELECT evidence. These rows are not runtime facts. */
export function partialNoSendTerminalFixture() {
  const f = terminalMetadataFixture({ parentAwareGraphKeys: true }), oldSourceId = randomUUID();
  const history: any = { version: 1, clusterId: f.source.clusterId, workspaceId: f.source.workspaceId, entryId: f.entryId,
    graphHmac: f.secrets.fingerprint(f.graph), nodeManifestHmac: f.rows.entity_change_recycle_archives[0].node_manifest_hmac,
    sourceId: oldSourceId, intentId: randomUUID(), intentRevision: 1, baselineId: randomUUID(), pinId: randomUUID(),
    workflowId: randomUUID(), workflowExecutionId: randomUUID(), materialHmac: f.secrets.fingerprint('synthetic-old-material'),
    changeDigest: f.secrets.fingerprint('synthetic-old-change'), packetManifestHmac: f.secrets.fingerprint('synthetic-old-packets'),
    terminalMetadataAudit: { id: randomUUID(), eventHash: f.secrets.fingerprint('synthetic-old-audit'), proofHmac: f.secrets.fingerprint('synthetic-old-proof'),
      outcomeEventId: randomUUID(), outcomeFactHmac: f.secrets.fingerprint('synthetic-old-outcome'), requestHmac: f.secrets.fingerprint('synthetic-old-request') },
    presentNodes: f.graph.nodes.slice(0, 5).map((node: any, index: number) => ({ nodeKey: node.key, nativeType: node.type, nativeId: node.id,
      parentId: index ? f.consumerId : null, credentialKind: index ? node.type : null, packetKey: `old:${index}`, attemptId: randomUUID(),
      operationId: randomUUID(), operationKey: `old-operation:${index}`, resultHmac: f.secrets.fingerprint(node.data), outcomeFactHmac: f.secrets.fingerprint(`old-outcome:${index}`) })),
    remainingNodes: f.graph.nodes.slice(5).map((node: any, index: number) => ({ nodeKey: node.key, nativeType: node.type, nativeId: node.id,
      parentId: f.consumerId, credentialKind: node.type, packetKey: `old-missing:${index}`, classification: index ? 'unattempted' : 'failed-known-not-sent',
      attemptId: index ? null : randomUUID(), operationId: index ? null : randomUUID(), outcomeFactHmac: index ? null : f.secrets.fingerprint('old-known0') })),
  };
  history.coverageHmac = f.secrets.fingerprint(history);
  const partition: any = { version: 1, history, presentNodes: history.presentNodes.map((node: any) => ({ nodeKey: node.nodeKey, beforeHmac: node.resultHmac,
    ...(node.nativeType === 'basic-auth' ? { basicCustodyHmac: f.secrets.fingerprint('synthetic-basic-custody') } : {}) })),
    remainingNodeKeys: history.remainingNodes.map((node: any) => node.nodeKey) };
  const partialRestore = { ...partition, selectionHmac: f.secrets.fingerprint(partition) };
  f.envelope.prepared.packets = f.packets.slice(5).map((packet: any, index: number) => ({ ...packet, order: index + 1, dependencies: [] }));
  const obligation = f.envelope.prepared.metadataObligations.find((item: any) => item.kind === 'recycle-restore');
  obligation.partialRestore = partialRestore; obligation.packetKeys = f.envelope.prepared.packets.map((p: any) => p.key); obligation.sealedEntry.state = 'partially_restored';
  f.envelope.prepared.metadataObligations = [
    ...f.envelope.prepared.packets.map((p: any) => ({ kind: 'credential-remember', packetKey: p.key, consumerId: f.consumerId, credentialKind: p.nativeType, rawInput: p.body })), obligation,
  ];
  f.envelope.executionMode = 'approval'; f.plan.executionMode = 'approval'; f.plan.approvalRequired = true; f.resignEnvelope();
  const footprint: any = { clusterId: f.source.clusterId, workspaceId: f.source.workspaceId, entryId: f.entryId, sourceId: f.source.id,
    sourceHmac: f.secrets.fingerprint(f.source), workflowId: f.source.workflowId, workflowExecutionId: f.source.workflowExecutionId,
    intentId: f.source.intentId, intentRevision: f.source.intentRevision, materialHmac: f.source.materialHmac, changeDigest: f.source.changeDigest,
    packetManifestHmac: f.source.packetManifestHmac, historyCoverageHmac: history.coverageHmac, oldSourceId,
    graphHmac: obligation.graphHmac, failedNodeKey: f.graph.nodes[5].key, failedPacketKey: f.envelope.prepared.packets[0].key,
    operationId: randomUUID(), attemptId: randomUUID(), outcomeEventId: randomUUID(), outcomeFactHmac: f.secrets.fingerprint('synthetic-outcome'),
    baselineId: f.baseline.id, pinId: f.rows.entity_change_baseline_pins[0].id, proofHmac: f.secrets.fingerprint('synthetic-static-known0-proof'), alreadyClosed: false };
  const reader = { certifyKnownNoSendPartialSource: vi.fn(async () => structuredClone(footprint)) };
  const input: PartialNoSendTerminalInput = { tx: f.txMock, secrets: f.secrets, reader, plan: f.plan, envelope: f.envelope, source: f.source, actor: f.actor };
  return { ...f, input, footprint, reader, obligation, partialRestore };
}
