import { ConflictException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type { SecretService } from '../../infrastructure/secret.service';
import type { EntityPartialRecycleRestoreSelection } from '../entities/entity-change.types';
import type { GraphNode, RecycleGraph } from './graph-capturer.service';
import { entityReferenceId } from '../entities/entity-reference';

const invalid = () => new ConflictException({ code: 'ENTITY_RECYCLE_PARTIAL_SELECTION_INVALID' });
const hex = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const uuid = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
const presentTypes = ['consumers', 'key-auth', 'basic-auth', 'jwt', 'oauth2'];
const missingTypes = ['hmac-auth', 'acls'];

export const partialRestoreObservationAad = (cid: string, wid: string, sourceId: string, entryId: string, nodeKey: string): string =>
  `entity-recycle-present:${cid}:${wid}:${sourceId}:${entryId}:${nodeKey}`;

/** Archive keys are immutable history and may predate contextual child keys.
 * Match real identities; the current baseline retains its producer's key. */
export function partialRestoreNodeIdentity(node: any): string {
  const type=node.nativeType??node.type,id=node.nativeId??node.id;
  const parent=type==='consumers'?null:node.parentId??entityReferenceId(node.data?.consumer);
  const kind=type==='consumers'?null:node.credentialKind??type;
  return JSON.stringify([type,id,parent??null,kind]);
}

export const PARTIAL_RECYCLE_FACTS_MIGRATION = Object.freeze({ name: '025_m11_partial_recycle_restore.sql',
  checksum: '72b19980dfd3d5cda3370d89a05994f35d557cecf7e8ceb8218315864c419534' });

/** Read-only custody check; no plaintext escapes its keyed summary. Root must
 * independently repeat this against current custody within its genuine claim. */
export function partialBasicCustodyHmac(node: Readonly<GraphNode>, current: any, remembered: any, parentId: string, secrets: SecretService): string {
  const plain = remembered?.rawInput?.password;
  if (node.type !== 'basic-auth' || !uuid(parentId) || typeof plain !== 'string'
    || typeof current?.password !== 'string' || remembered?.credential?.password !== current.password
    || remembered?.credential?.id !== node.id || remembered?.credential?.consumer?.id !== parentId
    || node.restoreData?.password !== plain || createHash('sha1').update(plain + parentId).digest('hex') !== current.password) throw invalid();
  return secrets.fingerprint({ version: 1, nativeId: node.id, parentId,
    nativeHashHmac: secrets.fingerprint(current.password), plaintextHmac: secrets.fingerprint(plain), rememberedHmac: secrets.fingerprint(remembered) });
}

/** Fixed Consumer+six DAO shape. Structural/HMA validation is deliberately
 * not native authority and cannot establish a real GET or wire observation. */
export function validatePartialRecycleRestoreSelection(graph: Readonly<RecycleGraph>, selection: Readonly<EntityPartialRecycleRestoreSelection>, secrets: SecretService): {
  present: readonly Readonly<GraphNode>[]; remaining: readonly Readonly<GraphNode>[];
} {
  if (!graph || graph.complete !== true || graph.purpose !== 'recycle' || !Array.isArray(graph.nodes) || graph.nodes.length !== 7
    || graph.nodes.some(node => !node.affected) || !selection || selection.version !== 1) throw invalid();
  const { selectionHmac, ...partition } = selection;
  const history = selection.history, { coverageHmac, ...historyMaterial } = history ?? {} as any;
  if (!hex(selectionHmac) || selectionHmac !== secrets.fingerprint(partition) || !hex(coverageHmac)
    || coverageHmac !== secrets.fingerprint(historyMaterial) || history.version !== 1
    || !uuid(history.clusterId) || !uuid(history.workspaceId) || !uuid(history.entryId) || !uuid(history.sourceId)
    || history.graphHmac !== secrets.fingerprint(graph) || !hex(history.nodeManifestHmac)
    || !Array.isArray(selection.presentNodes) || selection.presentNodes.length !== 5
    || !Array.isArray(selection.remainingNodeKeys) || selection.remainingNodeKeys.length !== 2
    || !Array.isArray(history.presentNodes) || !Array.isArray(history.remainingNodes)
    || history.presentNodes.length !== 5 || history.remainingNodes.length !== 2) throw invalid();
  const nodes = new Map(graph.nodes.map(node => [node.key, node]));
  const root = nodes.get(graph.rootKey);
  if (nodes.size !== 7 || root?.type !== 'consumers' || !uuid(root.id)
    || new Set(graph.nodes.map(node => node.type)).size !== 7
    || [...presentTypes, ...missingTypes].some(type => !graph.nodes.some(node => node.type === type))) throw invalid();
  const seen = new Set<string>();
  const matchHistory = (value: any): Readonly<GraphNode> => {
    const node = nodes.get(value.nodeKey);
    if (!node || seen.has(node.key) || value.nativeType !== node.type || value.nativeId !== node.id
      || value.parentId !== (node.type === 'consumers' ? null : root.id)
      || value.credentialKind !== (node.type === 'consumers' ? null : node.type)
      || node.type !== 'consumers' && (node.data.consumer?.id !== root.id || !node.dependencies.includes(root.key))) throw invalid();
    seen.add(node.key); return node;
  };
  const present = history.presentNodes.map(item => {
    const node = matchHistory(item), observed = selection.presentNodes.find(value => value.nodeKey === node.key);
    if (!presentTypes.includes(node.type) || !observed || !hex(observed.beforeHmac) || observed.beforeHmac !== item.resultHmac
      || !uuid(item.attemptId) || !uuid(item.operationId) || !hex(item.outcomeFactHmac)
      || (node.type === 'basic-auth' ? !observed || !hex(observed.basicCustodyHmac) : observed?.basicCustodyHmac !== undefined)) throw invalid();
    return node;
  });
  const remaining = history.remainingNodes.map(item => {
    const node = matchHistory(item);
    if (!missingTypes.includes(node.type) || !selection.remainingNodeKeys.includes(node.key)
      || node.type === 'hmac-auth' && (item.classification !== 'failed-known-not-sent' || !uuid(item.attemptId) || !uuid(item.operationId) || !hex(item.outcomeFactHmac))
      || node.type === 'acls' && (item.classification !== 'unattempted' || item.attemptId !== null || item.operationId !== null || item.outcomeFactHmac !== null)) throw invalid();
    return node;
  });
  if (seen.size !== 7 || new Set(selection.presentNodes.map(item => item.nodeKey)).size !== 5
    || new Set(selection.remainingNodeKeys).size !== 2 || selection.presentNodes.some(item => !present.some(node => node.key === item.nodeKey))) throw invalid();
  return { present, remaining };
}
