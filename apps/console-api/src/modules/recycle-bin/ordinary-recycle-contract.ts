import { ConflictException } from '@nestjs/common';
import { CREDENTIAL_KINDS, type CredentialKind } from '../entities/entities.types';
import type { EntityChangePacket } from '../entities/entity-change.types';
import type { RecycleGraph } from './graph-capturer.service';

/**
 * KP-004 ordinary commercial surface: five root object graphs plus the six
 * Consumer credential DAOs. Shared by delete-closure, prepared recycle, and
 * acceptance drivers so archive-before-delete / original-ID restore stay one
 * fail-closed contract. Non-ordinary roots (plugins, ca_certificates, snis,
 * targets-as-root, leaf credentials) keep their existing specialist paths.
 */
export const ORDINARY_RECYCLE_ROOT_TYPES = ['services', 'routes', 'consumers', 'certificates', 'upstreams'] as const;
export type OrdinaryRecycleRootType = typeof ORDINARY_RECYCLE_ROOT_TYPES[number];
export const ORDINARY_CREDENTIAL_KINDS = CREDENTIAL_KINDS;
export type OrdinaryCredentialKind = CredentialKind;

/** Affected + shared-reference member types permitted under each ordinary root. */
export const ORDINARY_RECYCLE_MEMBER_TYPES: Readonly<Record<OrdinaryRecycleRootType, readonly string[]>> = {
  services: ['services', 'routes', 'plugins', 'upstreams', 'certificates', 'ca_certificates'],
  routes: ['routes', 'plugins', 'services', 'upstreams'],
  consumers: ['consumers', 'plugins', ...CREDENTIAL_KINDS],
  certificates: ['certificates', 'snis', 'services'],
  upstreams: ['upstreams', 'targets'],
};

export const isOrdinaryRecycleRoot = (type: string): type is OrdinaryRecycleRootType =>
  (ORDINARY_RECYCLE_ROOT_TYPES as readonly string[]).includes(type);

export const isOrdinaryCredentialKind = (type: string): type is OrdinaryCredentialKind =>
  (ORDINARY_CREDENTIAL_KINDS as readonly string[]).includes(type);

const denied = (code = 'ENTITY_ORDINARY_RECYCLE_CONTRACT_INVALID') =>
  new ConflictException({ code, message: '普通对象回收合同不满足：须完整归档后再删除，并按原 ID 恢复' });

/** Archive-before-delete readiness for the five ordinary roots. No-op for
 * non-ordinary roots. Requires complete recycle-purpose material with
 * restoreData on every affected node before any native DELETE may proceed. */
export function assertOrdinaryRecycleArchiveContract(graph: RecycleGraph): void {
  if (!graph || graph.complete !== true || !Array.isArray(graph.nodes) || !graph.nodes.length) throw denied('GRAPH_INCOMPLETE');
  if (graph.purpose === 'migration') throw denied('GRAPH_PURPOSE_MISMATCH');
  const root = graph.nodes.find(node => node.key === graph.rootKey);
  if (!root?.affected) throw denied('GRAPH_INCOMPLETE');
  if (!isOrdinaryRecycleRoot(root.type)) return;
  const allowed = new Set(ORDINARY_RECYCLE_MEMBER_TYPES[root.type]);
  const purpose = graph.purpose ?? 'recycle';
  for (const node of graph.nodes) {
    if (!allowed.has(node.type)) throw denied();
    if (isOrdinaryCredentialKind(node.type) && root.type !== 'consumers') throw denied();
    if (node.affected && purpose === 'recycle') {
      if (node.restorable !== true || !node.restoreData || typeof node.restoreData !== 'object'
        || Array.isArray(node.restoreData) || node.restoreData.id !== node.id) throw denied('ENTITY_RECYCLE_ARCHIVE_MATERIAL_REQUIRED');
    }
  }
}

/** Original-ID restore for ordinary roots. Targets may allocate a sealed
 * replacement UUID only when originalNativeId matches the archived node. */
export function assertOrdinaryRestoreOriginalIds(graph: RecycleGraph, packets: readonly Readonly<EntityChangePacket>[]): void {
  const root = graph.nodes.find(node => node.key === graph.rootKey);
  if (!root?.affected || !isOrdinaryRecycleRoot(root.type)) return;
  assertOrdinaryRecycleArchiveContract(graph);
  if (!Array.isArray(packets) || !packets.length) throw denied();
  for (const packet of packets) {
    if (packet.method !== 'POST' && packet.mutationAction !== 'restore') continue;
    const archivedId = packet.originalNativeId ?? packet.nativeId;
    const node = graph.nodes.find(item => item.type === packet.nativeType && item.id === archivedId && item.affected);
    if (!node) throw denied('ENTITY_RECYCLE_ORIGINAL_ID_REQUIRED');
    if (packet.nativeType === 'targets') {
      if (packet.originalNativeId !== undefined && packet.originalNativeId !== node.id) throw denied('ENTITY_RECYCLE_ORIGINAL_ID_REQUIRED');
      continue;
    }
    if (packet.nativeId !== node.id || packet.originalNativeId !== undefined) throw denied('ENTITY_RECYCLE_ORIGINAL_ID_REQUIRED');
  }
}

/** Sealed restore must bind the same entry/graph HMAC that the archive receipt
 * sealed. Prevents adopting a foreign archive or swapping graph bytes between
 * delete and restore intents for ordinary roots. */
export function assertOrdinarySealedRestoreMatchesArchive(
  archive: Readonly<{ graph: RecycleGraph; graphHmac: string }>,
  restore: Readonly<{
    entryId: string;
    graph: RecycleGraph;
    graphHmac: string;
    sealedEntry: {
      clusterId: string;
      workspaceId: string;
      entryId: string;
      payloadHmac: string;
      state?: string;
    };
  }>,
  scope: Readonly<{ clusterId: string; workspaceId: string; entryId: string }>,
): void {
  assertOrdinaryRecycleArchiveContract(archive.graph);
  assertOrdinaryRecycleArchiveContract(restore.graph);
  const archiveRoot = archive.graph.nodes.find(node => node.key === archive.graph.rootKey);
  const restoreRoot = restore.graph.nodes.find(node => node.key === restore.graph.rootKey);
  if (!archiveRoot?.affected || !restoreRoot?.affected || !isOrdinaryRecycleRoot(archiveRoot.type)) throw denied();
  if (archiveRoot.type !== restoreRoot.type || archiveRoot.id !== restoreRoot.id || archive.graph.rootKey !== restore.graph.rootKey) {
    throw denied('ENTITY_RECYCLE_ARCHIVE_RESTORE_MISMATCH');
  }
  if (archive.graphHmac !== restore.graphHmac) throw denied('ENTITY_RECYCLE_ARCHIVE_RESTORE_MISMATCH');
  const sealed = restore.sealedEntry;
  if (!sealed || restore.entryId !== scope.entryId || sealed.entryId !== scope.entryId
    || sealed.clusterId !== scope.clusterId || sealed.workspaceId !== scope.workspaceId
    || sealed.payloadHmac !== restore.graphHmac || sealed.payloadHmac !== archive.graphHmac) {
    throw denied('ENTITY_RECYCLE_SEALED_ENTRY_INVALID');
  }
  // Sealed restore binds identity + graph HMAC. Entry state machine (deleted /
  // partially_deleted / partially_restored / restoring / …) is enforced by
  // recycle_entries transitions and Root readers — not re-encoded here. Fixtures
  // may omit state.
  if (sealed.state !== undefined && sealed.state === 'purged') throw denied('ENTITY_RECYCLE_SEALED_ENTRY_INVALID');
}

/** Every affected ordinary node must appear exactly once as DELETE (archive
 * plan) and once as restore POST with original IDs (Target may carry sealed
 * originalNativeId). Order is not compared here — prepared writer enforces it. */
export function assertOrdinaryDeleteRestorePacketCoverage(
  graph: RecycleGraph,
  deletePackets: readonly Readonly<EntityChangePacket>[],
  restorePackets: readonly Readonly<EntityChangePacket>[],
): void {
  assertOrdinaryRecycleArchiveContract(graph);
  assertOrdinaryRestoreOriginalIds(graph, restorePackets);
  const affected = graph.nodes.filter(node => node.affected);
  if (!deletePackets.length || deletePackets.length !== affected.length || restorePackets.length !== affected.length) throw denied();
  for (const node of affected) {
    const del = deletePackets.find(packet => packet.nativeType === node.type && packet.nativeId === node.id);
    if (!del || del.method !== 'DELETE' || del.mutationAction !== 'delete') throw denied();
    const rest = restorePackets.find(packet => {
      if (packet.nativeType !== node.type) return false;
      if (node.type === 'targets') return (packet.originalNativeId ?? packet.nativeId) === node.id;
      return packet.nativeId === node.id;
    });
    if (!rest || rest.method !== 'POST' || rest.mutationAction !== 'restore') throw denied();
  }
}
