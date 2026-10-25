import { ConflictException, ForbiddenException, HttpException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { observeTargetDeletePoststate } from '../../infrastructure/kong/target-delete-poststate';
import { assertKongPath, ENTITIES } from '../../infrastructure/kong/policy';
import { SecretService } from '../../infrastructure/secret.service';
import { AuditService } from '../audit/audit.service';
import { UUID } from '../config-transfer/schema-normalization';
import { CREDENTIAL_KINDS } from '../entities/entities.types';
import { entityReferenceId } from '../entities/entity-reference';
import type { EntityChangePacket } from '../entities/entity-change.types';
import { MutationService, type MutationContext } from '../mutations/mutation.service';
import type { GraphNode, RecycleGraph } from './graph-capturer.service';
import { validatePartialRecycleRestoreSelection } from './partial-recycle-restore';
import { assertOrdinaryRecycleArchiveContract, assertOrdinaryRestoreOriginalIds, assertOrdinarySealedRestoreMatchesArchive, isOrdinaryRecycleRoot } from './ordinary-recycle-contract';
import type {
  EntityPreparedRecycleArchiveGrant, EntityPreparedRecycleArchiveHandle, EntityPreparedRecycleArchiveReceipt,
  EntityPreparedRecycleNodeManifest, EntityPreparedRecyclePacketGrant, EntityPreparedRecyclePacketHandle,
  EntityPreparedRecyclePacketReceipt, EntityPreparedRecycleRepairGrant, EntityPreparedRecycleRepairHandle,
  EntityPreparedRecycleWriterDelegate, PreparedRecycleObligation, PreparedRecycleSourceBinding,
} from './entity-prepared-recycle-writer.types';

type Body = Record<string, any>;
type FixedRecyclePacket = { node: GraphNode; packet: Readonly<EntityChangePacket>; parentId?: string };
const object = (value: unknown): value is Body => !!value && typeof value === 'object' && !Array.isArray(value);
const uuid = (value: unknown): value is string => typeof value === 'string' && UUID.test(value);
const key = (value: unknown): value is string => typeof value === 'string' && /^[a-zA-Z\d_.:-]{1,160}$/.test(value);
const operationKey = (value: unknown): value is string => typeof value === 'string' && /^[a-zA-Z\d_.:-]{1,128}$/.test(value);
const credential = (type: string) => (CREDENTIAL_KINDS as readonly string[]).includes(type);
const core = (type: string) => (ENTITIES as readonly string[]).includes(type);
const invalid = () => new ForbiddenException({ code: 'ENTITY_PREPARED_RECYCLE_INVALID', message: '回收站封存材料或对象范围不匹配，未发送网关变更' });
const unsupported = () => new ConflictException({ code: 'ENTITY_PREPARED_RECYCLE_UNSUPPORTED', message: '此回收站对象图尚未开放固定执行' });

function orderedGraph(graph: RecycleGraph): GraphNode[] {
  if (!graph || graph.complete !== true || graph.purpose === 'migration' || graph.purpose === 'baseline'
    || !Array.isArray(graph.nodes) || !graph.nodes.length || graph.nodes.length > 1000
    || Buffer.byteLength(JSON.stringify(graph)) > 16 * 1024 * 1024) throw invalid();
  const nodes = new Map<string, GraphNode>();
  for (const node of graph.nodes) {
    if (!node || !key(node.key) || nodes.has(node.key) || !uuid(node.id) || !object(node.data) || node.data.id !== node.id
      || typeof node.affected !== 'boolean' || !Array.isArray(node.dependencies) || node.dependencies.some(dep => !key(dep))
      || new Set(node.dependencies).size !== node.dependencies.length || !core(node.type) && !credential(node.type) && node.type !== 'targets') throw invalid();
    nodes.set(node.key, node);
  }
  if (!nodes.get(graph.rootKey)?.affected) throw invalid();
  const visited = new Set<string>(), visiting = new Set<string>(), result: GraphNode[] = [];
  const visit = (nodeKey: string) => {
    if (visited.has(nodeKey)) return;
    const node = nodes.get(nodeKey); if (!node || visiting.has(nodeKey)) throw invalid();
    visiting.add(nodeKey); for (const dep of node.dependencies) visit(dep);
    visiting.delete(nodeKey); visited.add(nodeKey); result.push(node);
  };
  for (const node of graph.nodes) visit(node.key);
  return result;
}

function nativeParent(graph: RecycleGraph, node: GraphNode): string | undefined {
  if (!credential(node.type) && node.type !== 'targets') return undefined;
  const type = node.type === 'targets' ? 'upstreams' : 'consumers';
  const parentId = entityReferenceId(node.data[node.type === 'targets' ? 'upstream' : 'consumer']);
  if (!uuid(parentId) || !graph.nodes.some(parent => parent.type === type && parent.id === parentId && node.dependencies.includes(parent.key))) throw invalid();
  return parentId;
}

function pointPath(type: string, id: string, parentId?: string): string {
  return parentId ? `/${type === 'targets' ? 'upstreams' : 'consumers'}/${parentId}/${type}/${id}` : `/${type}/${id}`;
}

function restoreBody(node: GraphNode): Body {
  if (!node.restorable || !object(node.restoreData) || node.restoreData.id !== node.id || typeof node.data.ttl === 'number' && node.data.ttl > 0) throw invalid();
  const { created_at: _created, updated_at: _updated, ttl: _ttl, ...body } = node.restoreData;
  return body;
}

/** Pure normalized facts, not a scope decision or SQL/native authority. */
export function preparedRecycleNodeManifest(graph: RecycleGraph, secrets: SecretService): EntityPreparedRecycleNodeManifest[] {
  return orderedGraph(graph).map((node, index) => {
    const parentId = nativeParent(graph, node), path = pointPath(node.type, node.id, parentId);
    if (path !== node.path) throw invalid(); assertKongPath('GET', path);
    return { key: node.key, order: index + 1, nativeType: node.type, nativeId: node.id, parentId: parentId ?? null,
      credentialKind: credential(node.type) ? node.type : null, affected: node.affected, dependencies: node.dependencies,
      pathHmac: secrets.fingerprint(path), dataHmac: secrets.fingerprint(node.data),
      restoreHmac: node.affected ? secrets.fingerprint(restoreBody(node)) : null };
  });
}

/** Derive every explicit packet from the original complete graph. Certificate
 * SNIs are separate child packets; Target restoration may use only the exact
 * newly allocated ID already sealed by the compiler. This parser grants no
 * authority and never infers child completion from a parent response. */
export function derivePreparedRecyclePackets(obligation: PreparedRecycleObligation, packets: readonly Readonly<EntityChangePacket>[], secrets: SecretService): FixedRecyclePacket[] {
  if (!obligation || !['recycle-archive', 'recycle-restore'].includes(obligation.kind)
    || !Array.isArray(packets) || secrets.fingerprint(obligation.graph) !== obligation.graphHmac) throw invalid();
  const graph = obligation.graph, nodes = orderedGraph(graph), affected = nodes.filter(node => node.affected);
  preparedRecycleNodeManifest(graph, secrets);
  const ordinaryRoot = nodes.find(node => node.key === graph.rootKey);
  if (ordinaryRoot && isOrdinaryRecycleRoot(ordinaryRoot.type)) {
    assertOrdinaryRecycleArchiveContract(graph);
    if (obligation.kind === 'recycle-restore') {
      assertOrdinaryRestoreOriginalIds(graph, packets);
      if (obligation.sealedEntry) {
        assertOrdinarySealedRestoreMatchesArchive(
          { graph, graphHmac: obligation.graphHmac },
          obligation,
          { clusterId: obligation.sealedEntry.clusterId, workspaceId: obligation.sealedEntry.workspaceId, entryId: obligation.entryId },
        );
      }
    }
  }
  // Reject malformed special graphs before making them executable. In
  // particular, a caller cannot relabel a Service as a Certificate and retain
  // its old path/packets or invent a Target's nested parent.
  for (const node of affected) {
    if (node.type === 'certificates' && (typeof node.data.cert !== 'string' || typeof node.data.key !== 'string'
      || !Array.isArray(node.data.snis) || node.data.snis.some((name: unknown) => typeof name !== 'string'))) throw unsupported();
    if (node.type === 'ca_certificates' && typeof node.data.cert !== 'string') throw invalid();
    if (node.type === 'snis' && (typeof node.data.name !== 'string' || !node.data.name || !uuid(entityReferenceId(node.data.certificate))
      || !graph.nodes.some(parent => parent.type === 'certificates' && parent.id === entityReferenceId(node.data.certificate) && node.dependencies.includes(parent.key)))) throw invalid();
    if (node.type === 'upstreams' && (typeof node.data.name !== 'string' || !node.data.name)) throw invalid();
    if (node.type === 'targets' && (typeof node.data.target !== 'string' || !node.data.target
      || !Number.isInteger(node.data.weight) || node.data.weight < 0 || node.data.weight > 65535)) throw invalid();
  }
  const deleting = obligation.kind === 'recycle-archive';
  if (deleting && 'partialRestore' in obligation) throw invalid();
  const partial = obligation.kind === 'recycle-restore' ? obligation.partialRestore : undefined;
  const partition = partial ? validatePartialRecycleRestoreSelection(graph, partial, secrets) : undefined;
  const sendOrder = deleting ? [...affected].reverse() : partition ? affected.filter(node => partition.remaining.some(item => item.key === node.key)) : affected;
  // A subset alone is rejected. Only the fixed sealed 5-present/2-missing
  // partition reaches Root's independent current observation/SQL025 verifier.
  if (packets.length !== sendOrder.length) throw unsupported();
  if (!Array.isArray(obligation.packetKeys) || obligation.packetKeys.length !== packets.length || new Set(obligation.packetKeys).size !== packets.length) throw invalid();
  const keys = new Map<string, string>(), result: FixedRecyclePacket[] = []; let lastOrder = 0;
  for (let index = 0; index < sendOrder.length; index++) {
    const node = sendOrder[index], packet = packets[index], parentId = nativeParent(graph, node);
    const targetReplacement = !deleting && node.type === 'targets' && packet?.originalNativeId === node.id
      && uuid(packet.nativeId) && packet.nativeId !== node.id;
    if (!packet || !key(packet.key) || packet.key !== obligation.packetKeys[index] || !Number.isInteger(packet.order) || packet.order <= lastOrder
      || packet.nativeType !== node.type || !targetReplacement && packet.nativeId !== node.id || packet.parentId !== parentId
      || packet.credentialKind !== (credential(node.type) ? node.type : undefined) || !targetReplacement && packet.originalNativeId !== undefined
      || secrets.fingerprint(packet.body ?? null) !== packet.bodyHmac || secrets.fingerprint(packet.before ?? null) !== packet.beforeHmac) throw invalid();
    lastOrder = packet.order;
    const dependencies = deleting ? graph.nodes.filter(child => child.affected && child.dependencies.includes(node.key)).flatMap(child => keys.get(child.key) ?? [])
      : node.dependencies.flatMap(dep => keys.get(dep) ?? []);
    if (!Array.isArray(packet.dependencies) || secrets.fingerprint(packet.dependencies) !== secrets.fingerprint(dependencies)) throw invalid();
    const path = deleting ? node.path : node.path.replace(/\/[^/]+$/, '');
    if (packet.method !== (deleting ? 'DELETE' : 'POST') || packet.canonicalPath !== path
      || packet.mutationAction !== (deleting ? 'delete' : 'restore') || packet.permissionAction !== (deleting ? 'delete' : 'write')) throw invalid();
    assertKongPath(packet.method, path);
    if (deleting) {
      const before = structuredClone(node.data);
      if (node.type === 'certificates') {
        // The explicit child SNI DELETEs precede this certificate. Only those
        // exact already ordered names may disappear from the native before.
        const removed = new Set(graph.nodes.filter(child => child.affected && child.type === 'snis'
          && child.dependencies.includes(node.key) && keys.has(child.key)).map(child => child.data.name));
        before.snis = before.snis.filter((name: string) => !removed.has(name));
      }
      if (packet.body !== undefined || secrets.fingerprint(packet.before) !== secrets.fingerprint(before)) throw invalid();
    } else {
      const body = restoreBody(node);
      if (node.type === 'certificates') delete body.snis;
      if (node.type === 'targets') {
        if (entityReferenceId(body.upstream) !== parentId || body.target !== node.data.target || body.weight !== node.data.weight) throw invalid();
        body.id = packet.nativeId; delete body.upstream;
      }
      if (node.type === 'snis' && entityReferenceId(body.certificate) !== entityReferenceId(node.data.certificate)) throw invalid();
      if (packet.before !== null || !object(packet.body) || secrets.fingerprint(packet.body) !== secrets.fingerprint(body)) throw invalid();
      if (credential(node.type) && entityReferenceId(body.consumer) !== parentId) throw invalid();
    }
    if (node.type === 'basic-auth') {
      const plain = restoreBody(node).password, hash = node.data.password;
      if (typeof plain !== 'string' || typeof hash !== 'string' || !/^[\da-f]{40}$/i.test(hash)
        || createHash('sha1').update(plain + parentId).digest('hex') !== hash.toLowerCase()) throw invalid();
    }
    keys.set(node.key, packet.key); result.push({ node, packet, parentId });
  }
  return result;
}

/** Unregistered source-only adapter. No default delegate, HTTP input route,
 * recapture, archive permit minting or native recovery retry is provided. */
@Injectable()
export class EntityPreparedRecycleWriterService {
  private delegate?: Readonly<EntityPreparedRecycleWriterDelegate>;
  constructor(private readonly db: DbService, private readonly mutations: MutationService,
    private readonly kong: KongService, private readonly secrets: SecretService, private readonly audit: AuditService) {}

  installExecutionDelegate(delegate: EntityPreparedRecycleWriterDelegate): void {
    const methods = ['runArchive', 'runPacket', 'runRepair', 'linkArchive', 'runVerifiedDelete', 'runVerificationRead', 'recordTargetDeletePoststate', 'linkNodeReceipt', 'verifyCurrentRestore'] as const;
    if (this.delegate || !delegate || methods.some(method => typeof delegate[method] !== 'function')) throw new ConflictException({ code: 'ENTITY_PREPARED_RECYCLE_DELEGATE_INVALID' });
    this.delegate = Object.freeze(Object.fromEntries(methods.map(method => [method, delegate[method].bind(delegate)]))) as unknown as Readonly<EntityPreparedRecycleWriterDelegate>;
  }

  private installed(handle: object): Readonly<EntityPreparedRecycleWriterDelegate> {
    if (!this.delegate) throw new ServiceUnavailableException({ code: 'ENTITY_PREPARED_RECYCLE_UNAVAILABLE' });
    if (!handle || typeof handle !== 'object' || Array.isArray(handle)) throw invalid(); return this.delegate;
  }

  async archive(handle: EntityPreparedRecycleArchiveHandle): Promise<EntityPreparedRecycleArchiveReceipt> {
    const delegate = this.installed(handle); return delegate.runArchive(handle, grant => this.storeArchive(handle, immutableJson(grant)));
  }
  async execute(handle: EntityPreparedRecyclePacketHandle): Promise<EntityPreparedRecyclePacketReceipt> {
    const delegate = this.installed(handle); return delegate.runPacket(handle, grant => this.writePacket(handle, immutableJson(grant)));
  }
  async repair(handle: EntityPreparedRecycleRepairHandle): Promise<EntityPreparedRecyclePacketReceipt> {
    const delegate = this.installed(handle); return delegate.runRepair(handle, grant => this.repairMetadata(handle, immutableJson(grant)));
  }

  private binding(grant: PreparedRecycleSourceBinding): void {
    const { source, baseline, actor } = grant;
    if (!source || !baseline || !actor || !uuid(source.id) || !uuid(source.clusterId) || !uuid(source.workspaceId)
      || !uuid(source.workflowId) || !uuid(source.workflowExecutionId) || !uuid(baseline.baselineId) || !uuid(baseline.pinId)
      || baseline.sourceId !== source.id || actor.workspaceId !== source.workspaceId || actor.user?.id !== source.executionActorId) throw invalid();
  }

  private async storeArchive(handle: EntityPreparedRecycleArchiveHandle, grant: Readonly<EntityPreparedRecycleArchiveGrant>): Promise<EntityPreparedRecycleArchiveReceipt> {
    this.binding(grant);
    if (!uuid(grant.entryId) || grant.obligation.kind !== 'recycle-archive' || !Number.isFinite(Date.parse(grant.expiresAt)) || Date.parse(grant.expiresAt) <= Date.now()) throw invalid();
    const plan = derivePreparedRecyclePackets(grant.obligation, grant.packets, this.secrets), graph = grant.obligation.graph;
    const manifest = preparedRecycleNodeManifest(graph, this.secrets), root = graph.nodes.find(node => node.key === graph.rootKey)!;
    const parentId = nativeParent(graph, root), isCredential = credential(root.type);
    const receipt: EntityPreparedRecycleArchiveReceipt = { entryId: grant.entryId, graphHmac: grant.obligation.graphHmac,
      payloadHmac: this.secrets.fingerprint(graph), nodeManifestHmac: this.secrets.fingerprint(manifest), nodeCount: graph.nodes.length, packetCount: plan.length };
    await this.db.transaction(async tx => {
      await tx.exec(`INSERT INTO recycle_entries(id,cluster_id,workspace_id,actor_id,root_type,original_id,root_name,parent_id,credential_kind,node_count,payload_secret,expires_at,mutation_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL)`, [grant.entryId, grant.source.clusterId, grant.source.workspaceId, grant.actor.user.id,
        isCredential ? 'credentials' : root.type, root.id, String(root.data.name ?? root.data.username ?? root.data.target ?? root.id), parentId ?? null,
        isCredential ? root.type : null, graph.nodes.length, this.secrets.encrypt(graph, `recycle:${grant.entryId}`), grant.expiresAt]);
      for (const node of graph.nodes) await tx.exec(`INSERT INTO recycle_nodes(entry_id,node_key,entity_type,original_id,affected,dependencies,delete_state,restore_state)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [grant.entryId, node.key, node.type, node.id, node.affected, node.dependencies,
        node.affected ? 'pending' : 'reference', node.affected ? 'pending' : 'reference']);
      await this.delegate!.linkArchive(handle, Object.freeze(receipt), tx);
      await this.audit.append({ actorId: grant.actor.user.id, clusterId: grant.source.clusterId, workspaceId: grant.source.workspaceId,
        entityType: 'recycle_entries', entityId: grant.entryId, action: 'archive', after: { rootType: root.type, originalId: root.id, nodeCount: graph.nodes.length },
        workflowId: grant.source.workflowId, requestId: grant.actor.requestId, ip: grant.actor.ip }, tx);
      const changed = await tx.exec("UPDATE recycle_entries SET state='deleting',updated_at=now() WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND state='archived' AND mutation_id IS NULL",
        [grant.entryId, grant.source.clusterId, grant.source.workspaceId]);
      if (changed !== 1) throw invalid();
    });
    return Object.freeze(receipt);
  }

  private fixed(grant: Readonly<EntityPreparedRecyclePacketGrant>): FixedRecyclePacket {
    this.binding(grant); if (!uuid(grant.entryId) || !key(grant.nodeKey) || !operationKey(grant.operationKey)) throw invalid();
    const plan = derivePreparedRecyclePackets(grant.obligation, grant.packets, this.secrets), found = plan.find(item => item.node.key === grant.nodeKey);
    if (!found || this.secrets.fingerprint(found.packet) !== this.secrets.fingerprint(grant.packet)) throw invalid();
    if (grant.obligation.kind === 'recycle-restore') {
      const sealed = grant.obligation.sealedEntry;
      if (grant.obligation.entryId !== grant.entryId || !sealed || sealed.entryId !== grant.entryId || sealed.clusterId !== grant.source.clusterId
        || sealed.workspaceId !== grant.source.workspaceId || sealed.payloadHmac !== grant.obligation.graphHmac) throw invalid();
    }
    return found;
  }

  private async writePacket(handle: EntityPreparedRecyclePacketHandle, grant: Readonly<EntityPreparedRecyclePacketGrant>): Promise<EntityPreparedRecyclePacketReceipt> {
    const fixed = this.fixed(grant), packet = fixed.packet, deleting = packet.method === 'DELETE';
    const context: MutationContext = { clusterId: grant.source.clusterId, workspaceId: grant.source.workspaceId, actor: grant.actor.user,
      entityType: credential(packet.nativeType) ? 'credentials' : packet.nativeType, entityId: deleting ? packet.nativeId : undefined,
      action: packet.mutationAction, before: deleting ? packet.before : undefined, payload: packet.body,
      idempotencyKey: grant.operationKey, requestId: grant.actor.requestId, ip: grant.actor.ip,
      ...(fixed.parentId ? { parentId: fixed.parentId, credentialKind: packet.credentialKind } : {}) };
    let entered = false, nativeResult: unknown;
    await this.mutations.execute(context, async () => {
      if (entered || !uuid(context.operationId)) throw invalid(); entered = true;
      if (!deleting) nativeResult = await this.kong.request(grant.source.clusterId, 'POST', packet.canonicalPath, packet.body);
      else nativeResult = await this.delegate!.runVerifiedDelete(handle, context.operationId, async () => {
        const result = await this.kong.request(grant.source.clusterId, 'DELETE', packet.canonicalPath);
        if (result !== null) throw new ServiceUnavailableException({ code: 'ENTITY_RECYCLE_DELETE_RESULT_UNKNOWN' });
        await this.delegate!.runVerificationRead(handle, context.operationId!, async () => {
          // Kong 1.5 Target DELETE appends weight=0 (or may prune history); bare
          // GET404 on node.path is not a completion certificate for targets.
          if (packet.nativeType === 'targets') {
            const before = packet.before;
            if (!fixed.parentId || !before || typeof before !== 'object' || Array.isArray(before)
              || typeof (before as any).target !== 'string' || !Number.isInteger((before as any).weight)) {
              throw new ServiceUnavailableException({ code: 'ENTITY_RECYCLE_DELETE_NOT_VERIFIED' });
            }
            const observation = await observeTargetDeletePoststate(this.kong, this.secrets, {
              clusterId: grant.source.clusterId,
              upstreamId: fixed.parentId,
              originalNativeId: packet.nativeId,
              address: (before as any).target,
              weightBefore: (before as any).weight,
              archive: {
                entryId: grant.entryId,
                graphHmac: grant.obligation.graphHmac,
                nodeCount: grant.obligation.graph.nodes.length,
              },
              nativeDeleteResult: result,
              approvedBefore: before,
            });
            this.delegate!.recordTargetDeletePoststate(handle, {
              historyRetention: observation.historyRetention,
              observationHmac: this.secrets.fingerprint(observation),
              archiveGraphHmac: observation.archiveGraphHmac,
              originalNativeId: observation.originalNativeId,
              address: observation.address,
            });
            return;
          }
          try { await this.kong.request(grant.source.clusterId, 'GET', fixed.node.path); }
          catch (error) { if (error instanceof HttpException && error.getStatus() === 404) return; throw error; }
          throw new ServiceUnavailableException({ code: 'ENTITY_RECYCLE_DELETE_NOT_VERIFIED' });
        });
        return result;
      });
      return nativeResult;
    });
    if (!entered || nativeResult === undefined || !uuid(context.operationId)) throw new ConflictException({ code: 'ENTITY_RECYCLE_METADATA_RECOVERY_REQUIRED',
      message: '原操作已有回执，请核验原操作并恢复元数据，不会重发网关变更', entryId: grant.entryId, packetKey: packet.key, knownNativeComplete: true });
    if(!deleting)try{await this.delegate!.verifyCurrentRestore(handle,context.operationId,nativeResult);}
    catch{throw new ServiceUnavailableException({code:'ENTITY_RECYCLE_RESTORE_CURRENT_UNVERIFIED',message:'网关恢复已返回，当前配置尚未完整核验；请核验原操作，勿重复提交',entryId:grant.entryId,packetKey:packet.key,operationId:context.operationId,knownNativeComplete:true});}
    return this.completeMetadata(handle, grant, fixed, context.operationId, nativeResult);
  }

  private async repairMetadata(handle: EntityPreparedRecycleRepairHandle, grant: Readonly<EntityPreparedRecycleRepairGrant>): Promise<EntityPreparedRecyclePacketReceipt> {
    const fixed = this.fixed(grant);
    if (grant.knownNativeComplete !== true || !uuid(grant.originalOperationId)) throw invalid();
    return this.completeMetadata(handle, grant, fixed, grant.originalOperationId, grant.nativeResult);
  }

  private async completeMetadata(handle: EntityPreparedRecyclePacketHandle | EntityPreparedRecycleRepairHandle, grant: Readonly<EntityPreparedRecyclePacketGrant>,
    fixed: FixedRecyclePacket, operationId: string, nativeResult: unknown): Promise<EntityPreparedRecyclePacketReceipt> {
    const { packet } = fixed, deleting = packet.method === 'DELETE';
    const receipt: EntityPreparedRecyclePacketReceipt = { entryId: grant.entryId, nodeKey: fixed.node.key, packetKey: packet.key,
      operationKey: grant.operationKey, operationId, nativeId: packet.nativeId, state: 'succeeded', metadata: 'complete' };
    if (deleting ? nativeResult !== null : !object(nativeResult) || nativeResult.id !== packet.nativeId
      || fixed.parentId && entityReferenceId(nativeResult[packet.nativeType === 'targets' ? 'upstream' : 'consumer']) !== fixed.parentId) throw new ServiceUnavailableException({ code: 'ENTITY_RECYCLE_NATIVE_RESULT_MISMATCH',
        entryId: grant.entryId, packetKey: packet.key, operationId, knownNativeComplete: true });
    if (!deleting && credential(packet.nativeType)) {
      const result = nativeResult as Body, raw = packet.body!;
      // Source proves where the response came from. Recovery additionally
      // needs the exact native hash/plaintext association, including repair.
      const mismatch = packet.nativeType === 'basic-auth'
        ? typeof raw.password !== 'string' || !uuid(fixed.parentId) || typeof result.password !== 'string' || !/^[\da-f]{40}$/i.test(result.password)
          || result.password.toLowerCase() !== createHash('sha1').update(raw.password + fixed.parentId).digest('hex')
        : packet.nativeType === 'oauth2' && (typeof raw.client_secret !== 'string' || result.client_secret !== raw.client_secret);
      if (mismatch) throw new ServiceUnavailableException({ code: 'ENTITY_RECYCLE_CREDENTIAL_RESULT_MISMATCH',
        entryId: grant.entryId, packetKey: packet.key, operationId, knownNativeComplete: true });
    }
    try {
      await this.db.transaction(async tx => {
        // The genuine callback verifies operation+attempt+original result and
        // records immutable completion evidence before any mutable projection.
        await this.delegate!.linkNodeReceipt(handle, Object.freeze(receipt), tx);
        if (credential(packet.nativeType)) await this.credentialMetadata(tx, grant, fixed, nativeResult, deleting);
        else if (core(packet.nativeType)) await this.indexMetadata(tx, grant, packet, nativeResult, deleting);
        const changed = deleting
          ? await tx.exec("UPDATE recycle_nodes SET delete_state='deleted',safe_error=NULL,updated_at=now() WHERE entry_id=$1 AND node_key=$2 AND affected AND delete_state IN('pending','deleted','failed','uncertain')", [grant.entryId, fixed.node.key])
          : await tx.exec("UPDATE recycle_nodes SET restore_state='restored',restored_id=$3,safe_error=NULL,updated_at=now() WHERE entry_id=$1 AND node_key=$2 AND affected AND restore_state IN('pending','restored','failed','uncertain')", [grant.entryId, fixed.node.key, packet.nativeId]);
        if (changed !== 1) throw invalid();
        await tx.exec(`UPDATE recycle_entries SET state=CASE WHEN EXISTS(SELECT 1 FROM recycle_nodes WHERE entry_id=$1 AND affected AND ${deleting ? "delete_state<>'deleted'" : "restore_state<>'restored'"})
          THEN $4 ELSE $5 END,updated_at=now(),restored_at=CASE WHEN $5='restored' AND NOT EXISTS(SELECT 1 FROM recycle_nodes WHERE entry_id=$1 AND affected AND restore_state<>'restored') THEN now() ELSE restored_at END
          WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND mutation_id IS NULL AND state<>'purged'`,
          [grant.entryId, grant.source.clusterId, grant.source.workspaceId, deleting ? 'deleting' : 'restoring', deleting ? 'deleted' : 'restored']);
        await this.audit.append({ actorId: grant.actor.user.id, clusterId: grant.source.clusterId, workspaceId: grant.source.workspaceId,
          entityType: 'recycle_entries', entityId: grant.entryId, action: deleting ? 'delete.metadata_complete' : 'restore.metadata_complete',
          after: { nodeKey: fixed.node.key, packetKey: packet.key, operationId, nativeId: packet.nativeId }, workflowId: grant.source.workflowId,
          requestId: grant.actor.requestId, ip: grant.actor.ip }, tx);
      });
    } catch {
      throw new ServiceUnavailableException({ code: 'ENTITY_RECYCLE_METADATA_INCOMPLETE', message: '网关变更已完成，回收站元数据待恢复；请核验原操作，勿重新提交',
        entryId: grant.entryId, packetKey: packet.key, operationId, knownNativeComplete: true });
    }
    return Object.freeze(receipt);
  }

  private async indexMetadata(tx: DbService, grant: Readonly<EntityPreparedRecyclePacketGrant>, packet: Readonly<EntityChangePacket>, result: unknown, deleting: boolean): Promise<void> {
    if (deleting) { await tx.exec('DELETE FROM entity_index WHERE cluster_id=$1 AND entity_type=$2 AND kong_id=$3', [grant.source.clusterId, packet.nativeType, packet.nativeId]); return; }
    const entity = result as Body, safe = this.secrets.redact(entity);
    await tx.exec(`INSERT INTO entity_index(cluster_id,entity_type,kong_id,name,tags,document,content_hash,kong_created_at,observed_at,sync_cycle)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,now(),(SELECT cycle_id FROM index_sync_state WHERE cluster_id=$1 AND entity_type=$2))
      ON CONFLICT(cluster_id,entity_type,kong_id) DO UPDATE SET name=EXCLUDED.name,tags=EXCLUDED.tags,document=EXCLUDED.document,
      content_hash=EXCLUDED.content_hash,kong_created_at=EXCLUDED.kong_created_at,observed_at=now(),sync_cycle=EXCLUDED.sync_cycle`,
      [grant.source.clusterId, packet.nativeType, packet.nativeId, String(entity.name ?? entity.username ?? entity.custom_id ?? entity.id),
        Array.isArray(entity.tags) ? entity.tags : [], safe, createHash('sha256').update(JSON.stringify(safe)).digest('hex'), Number.isFinite(entity.created_at) ? Math.floor(entity.created_at) : 0]);
  }

  private async credentialMetadata(tx: DbService, grant: Readonly<EntityPreparedRecyclePacketGrant>, fixed: FixedRecyclePacket, result: unknown, deleting: boolean): Promise<void> {
    const { packet, parentId } = fixed;
    if (deleting) { await tx.exec("UPDATE credential_refs SET state='revoked',updated_at=now() WHERE cluster_id=$1 AND consumer_id=$2 AND credential_type=$3 AND kong_id=$4",
      [grant.source.clusterId, parentId, packet.nativeType, packet.nativeId]); return; }
    // Sealed original plaintext and actual response only. Mutable credential
    // refs and historical/public safe_result never supply recovery materials.
    const rawInput = packet.body!, credentialResult = result as Body;
    const payload = this.secrets.encrypt({ credential: credentialResult, rawInput }, `credential:${grant.source.clusterId}:${parentId}:${packet.nativeType}:${packet.nativeId}`);
    await tx.exec(`INSERT INTO credential_refs(id,cluster_id,consumer_id,credential_type,kong_id,payload_secret,masked_summary,recovery_capability)
      VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,'complete') ON CONFLICT(cluster_id,consumer_id,credential_type,kong_id) DO UPDATE SET
      payload_secret=EXCLUDED.payload_secret,masked_summary=EXCLUDED.masked_summary,recovery_capability=EXCLUDED.recovery_capability,state='active',updated_at=now()`,
      [randomUUID(), grant.source.clusterId, parentId, packet.nativeType, packet.nativeId, payload, JSON.stringify(this.secrets.redact(credentialResult))]);
  }
}
