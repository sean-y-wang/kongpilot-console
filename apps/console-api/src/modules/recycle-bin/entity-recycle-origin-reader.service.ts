import { ConflictException, ForbiddenException, HttpException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { canonicalJson, SecretService } from '../../infrastructure/secret.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { assertKongPath, ENTITIES } from '../../infrastructure/kong/policy';
import { CREDENTIAL_KINDS } from '../entities/entities.types';
import { entityReferenceId } from '../entities/entity-reference';
import { auditCanonicalRecord } from '../audit/audit-integrity.service';
import type { PreparedRecycleArchiveObligation } from './entity-prepared-recycle-writer.types';
import type { PreparedEntityChange } from '../entities/entity-change.types';
import { decodeEntityExecutionSource } from '../workflows/entity-change-source-codec';
import { assertEntityChangeWorkflowPlan, entityChangeIntentAad, normalizedEntityChangePackets } from '../workflows/entity-change-workflow';
import { planAad } from '../workflows/workflow.types';
import type { EntityChangeBaselineCapture, EntityChangeBaselineEnvelope, EntityChangeBaselineNormalizedObject } from '../workflows/entity-change-execution-facts.types';
import type { EntityChangeIntentEnvelopeV1 } from '../workflows/entity-change-intent.types';
import type { EntityExecutionSourceByOrigin } from '../workflows/entity-change-schedule.contract';
import type { GraphNode, RecycleGraph } from './graph-capturer.service';
import { PARTIAL_RECYCLE_FACTS_MIGRATION, partialRestoreObservationAad, partialRestoreNodeIdentity, validatePartialRecycleRestoreSelection } from './partial-recycle-restore';
import { derivePreparedRecyclePackets } from './entity-prepared-recycle-writer.service';
import type { EntityRecycleClosedOrigin, EntityRecycleClosedRestoreCoverage, EntityRecycleKnownNoSendPartialSource, EntityRecyclePresentNodeHistory, EntityRecycleRemainingNodeHistory, EntityRecycleDeleteVerification, EntityRecycleOriginLookup, EntityRecycleOriginReadInput, EntityRecycleOriginReaderDelegate } from './entity-recycle-origin-reader.types';

const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const key = /^[a-zA-Z\d_.:-]{1,160}$/;
const hex = /^[a-f\d]{64}$/;
const partialRestoreTypes = ['consumers', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'] as const;
const native = new Set<string>([...ENTITIES, 'targets', ...CREDENTIAL_KINDS]);
const credential = (value: string) => (CREDENTIAL_KINDS as readonly string[]).includes(value);
const closedWorkflow = new Set(['succeeded', 'partial', 'failed', 'cancelled', 'expired']);
const closedExecution = new Set(['succeeded', 'partial', 'failed']);
const invalid = () => new ConflictException({ code: 'RECYCLE_ENTITY_ORIGIN_INVALID', message: '回收记录缺少完整、已关闭的原执行证据' });
const iso = (value: unknown): string => { const date = new Date(value as any); if (!Number.isFinite(date.getTime())) throw invalid(); return date.toISOString(); };
const object = (value: any): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value);
/** Exact candidate ledger identity. Root must formally trial/apply these bytes
 * before installing the reader. A similarly named or older table is insufficient. */
export const ENTITY_RECYCLE_FACTS_MIGRATION = Object.freeze({ name: '023_m11_entity_recycle_facts.sql', checksum: '9960455dd685da0e528f9f6f2280a4a18b80e812090182742341b9e831ea36eb' });

/** Read-only historical evidence. No Kong/Mutation/kernel dependency, receipt
 * repair, SID renewal, live recapture, session replacement or native authority. */
@Injectable()
export class EntityRecycleOriginReaderService implements EntityRecycleOriginLookup {
  private delegate?: Readonly<EntityRecycleOriginReaderDelegate>;
  constructor(private readonly db: DbService, private readonly secrets: SecretService) {}

  installFixedDelegate(delegate: EntityRecycleOriginReaderDelegate): void {
    if (this.delegate || !delegate || typeof delegate.assertCurrentScope !== 'function' || typeof delegate.assertFrozenSubject !== 'function'
      || delegate.activeRestoreRevalidation !== undefined && typeof delegate.activeRestoreRevalidation !== 'function') throw new Error('Recycle origin requires one complete fixed read delegate');
    this.delegate = Object.freeze({ assertCurrentScope: delegate.assertCurrentScope.bind(delegate), assertFrozenSubject: delegate.assertFrozenSubject.bind(delegate),
      ...(delegate.activeRestoreRevalidation ? { activeRestoreRevalidation: delegate.activeRestoreRevalidation.bind(delegate) } : {}) });
  }
  private policy(): Readonly<EntityRecycleOriginReaderDelegate> {
    if (!this.delegate) throw new ServiceUnavailableException({ code: 'RECYCLE_ENTITY_ORIGIN_POLICY_UNAVAILABLE' }); return this.delegate;
  }
  private async activeRestore(input: Readonly<EntityRecycleOriginReadInput>, tx: DbService): Promise<string | null> {
    const callback = this.policy().activeRestoreRevalidation;
    if (!callback) return null;
    const sourceId = await callback(input, tx);
    if (sourceId !== null && (typeof sourceId !== 'string' || !uuid.test(sourceId))) throw invalid();
    return sourceId;
  }
  private same(value: unknown, expected: unknown): void { if (this.secrets.fingerprint(value) !== this.secrets.fingerprint(expected)) throw invalid(); }
  private scope(row: any, input: EntityRecycleOriginReadInput): void { if (!row || row.cluster_id !== input.clusterId || row.workspace_id !== input.workspaceId) throw invalid(); }
  private sourceTuple(row: any, source: EntityExecutionSourceByOrigin, archive: any): void {
    if (!row || row.cluster_id !== source.clusterId || row.workspace_id !== source.workspaceId || row.source_id !== source.id || row.baseline_id !== archive.baseline_id
      || row.pin_id !== archive.pin_id || row.workflow_execution_id !== source.workflowExecutionId) throw invalid();
  }
  private packet(row: any, dependencies?: readonly string[]): unknown {
    return { key: row.packet_key, order: row.packet_order, dependencies: row.dependencies ?? dependencies, method: row.method, pathHmac: row.path_hmac, nativeType: row.native_type,
      nativeId: row.native_id, parentId: row.parent_id, credentialKind: row.credential_kind, originalNativeId: row.original_native_id,
      mutationAction: row.mutation_action, permissionAction: row.permission_action, bodyHmac: row.body_hmac, beforeHmac: row.before_hmac };
  }
  private intentTuple(row: any, source: EntityExecutionSourceByOrigin): void {
    if (!row || row.cluster_id !== source.clusterId || row.workspace_id !== source.workspaceId || row.intent_id !== source.intentId || row.intent_revision !== source.intentRevision
      || row.material_hmac !== source.materialHmac || row.change_digest !== source.changeDigest || row.packet_manifest_hmac !== source.packetManifestHmac) throw invalid();
  }

  private orderedGraph(graph: RecycleGraph): GraphNode[] {
    if (!graph || graph.complete !== true || graph.purpose === 'migration' || !Array.isArray(graph.nodes) || !graph.nodes.length || graph.nodes.length > 1000
      || Buffer.byteLength(JSON.stringify(graph)) > 16 * 1024 * 1024) throw invalid();
    const nodes = new Map<string, GraphNode>(), identities = new Set<string>();
    for (const node of graph.nodes) {
      if (!node || !key.test(node.key) || nodes.has(node.key) || !native.has(node.type) || !uuid.test(node.id) || !object(node.data) || node.data.id !== node.id
        || typeof node.affected !== 'boolean' || !Array.isArray(node.dependencies) || node.dependencies.some(dep => !key.test(dep)) || new Set(node.dependencies).size !== node.dependencies.length) throw invalid();
      const parentId = this.parent(graph, node), path = parentId ? `/${node.type === 'targets' ? 'upstreams' : 'consumers'}/${parentId}/${node.type}/${node.id}` : `/${node.type}/${node.id}`;
      if (node.path !== path || identities.has(path)) throw invalid(); assertKongPath('GET', path); identities.add(path); nodes.set(node.key, node);
      if (node.affected) {
        if (!node.restorable || !object(node.restoreData) || node.restoreData.id !== node.id || typeof node.data.ttl === 'number' && node.data.ttl > 0) throw invalid();
        if (node.type === 'basic-auth') this.basic(node.data, node.restoreData, parentId);
      }
    }
    if (!nodes.get(graph.rootKey)?.affected) throw invalid();
    const visited = new Set<string>(), visiting = new Set<string>(), ordered: GraphNode[] = [];
    const visit = (nodeKey: string) => {
      if (visited.has(nodeKey)) return; const node = nodes.get(nodeKey); if (!node || visiting.has(nodeKey)) throw invalid();
      visiting.add(nodeKey); node.dependencies.forEach(visit); visiting.delete(nodeKey); visited.add(nodeKey); ordered.push(node);
    };
    graph.nodes.forEach(node => visit(node.key)); return ordered;
  }
  private parent(graph: RecycleGraph, node: GraphNode): string | undefined {
    if (!credential(node.type) && node.type !== 'targets') return undefined;
    const parentId = entityReferenceId(node.data[credential(node.type) ? 'consumer' : 'upstream']), type = credential(node.type) ? 'consumers' : 'upstreams';
    if (!parentId || !uuid.test(parentId) || !graph.nodes.some(parent => parent.type === type && parent.id === parentId && node.dependencies.includes(parent.key))) throw invalid(); return parentId;
  }
  private basic(before: any, restore: any, parentId?: string): void {
    if (!parentId || typeof restore.password !== 'string' || typeof before.password !== 'string' || !/^[a-f\d]{40}$/i.test(before.password)
      || createHash('sha1').update(restore.password + parentId).digest('hex') !== before.password.toLowerCase()) throw invalid();
  }
  private restore(node: GraphNode): unknown {
    const { created_at: _created, updated_at: _updated, ttl: _ttl, ...payload } = node.restoreData as any; return payload;
  }
  private manifest(graph: RecycleGraph): unknown[] {
    return this.orderedGraph(graph).map((node, index) => ({ key: node.key, order: index + 1, nativeType: node.type, nativeId: node.id, parentId: this.parent(graph, node) ?? null,
      credentialKind: credential(node.type) ? node.type : null, affected: node.affected, dependencies: node.dependencies,
      pathHmac: this.secrets.fingerprint(node.path), dataHmac: this.secrets.fingerprint(node.data), restoreHmac: node.affected ? this.secrets.fingerprint(this.restore(node)) : null }));
  }
  private baselineManifest(capture: EntityChangeBaselineCapture): EntityChangeBaselineNormalizedObject[] {
    if (!capture || capture.version !== 1 || !Array.isArray(capture.objects) || !capture.objects.length || capture.objects.length > 10000 || !Array.isArray(capture.graphs) || capture.graphs.length > 1000
      || !Array.isArray(capture.blockerCodes) || capture.blockerCodes.length || !Array.isArray(capture.nonreversiblePacketKeys) || capture.nonreversiblePacketKeys.length
      || Buffer.byteLength(JSON.stringify(capture)) > 32 * 1024 * 1024 || Date.parse(iso(capture.observedUntil)) < Date.parse(iso(capture.observedFrom))) throw invalid();
    const seen = new Set<string>(), identities = new Set<string>();
    for (const graph of capture.graphs) this.orderedGraph(graph);
    return capture.objects.map(item => {
      const nested = credential(item.nativeType) || item.nativeType === 'targets';
      if (!item || !native.has(item.nativeType) || !key.test(item.key) || seen.has(item.key) || !uuid.test(item.nativeId) || typeof item.affected !== 'boolean' || typeof item.present !== 'boolean'
        || !Array.isArray(item.dependencies) || item.dependencies.some((dep: string) => !seen.has(dep)) || new Set(item.dependencies).size !== item.dependencies.length
        || item.schemaMaterial == null || item.trustedProvenance == null || nested && (!item.parentId || !uuid.test(item.parentId)) || !nested && item.parentId !== undefined
        || credential(item.nativeType) && item.credentialKind !== item.nativeType || !credential(item.nativeType) && item.credentialKind !== undefined) throw invalid();
      const identity = `${item.nativeType}:${item.parentId ?? ''}:${item.nativeId}`; if (identities.has(identity)) throw invalid(); identities.add(identity); seen.add(item.key);
      if (item.present) {
        if (!object(item.before) || item.before.id !== item.nativeId || nested && entityReferenceId(item.before[credential(item.nativeType) ? 'consumer' : 'upstream']) !== item.parentId) throw invalid();
        if (item.affected) {
          if (item.recovery !== 'complete' || !object(item.restorePayload) || item.restorePayload.id !== item.nativeId || typeof item.before.ttl === 'number' && item.before.ttl > 0) throw invalid();
          if (item.nativeType === 'basic-auth') this.basic(item.before, item.restorePayload, item.parentId);
        } else if (item.recovery !== 'reference' || item.restorePayload !== undefined) throw invalid();
      } else if (!item.affected || item.before !== null || item.recovery !== 'absent' || item.restorePayload !== undefined) throw invalid();
      return { key: item.key, nativeType: item.nativeType, nativeId: item.nativeId, parentId: item.parentId ?? null, credentialKind: item.credentialKind ?? null, affected: item.affected, present: item.present,
        dependencies: item.dependencies, beforeHmac: this.secrets.fingerprint(item.before), restoreHmac: item.restorePayload === undefined ? null : this.secrets.fingerprint(item.restorePayload),
        schemaHmac: this.secrets.fingerprint(item.schemaMaterial), provenanceHmac: this.secrets.fingerprint(item.trustedProvenance), recovery: item.recovery };
    });
  }

  private async storedIntent(source: EntityExecutionSourceByOrigin, tx: DbService): Promise<PreparedEntityChange> {
    const args = [source.clusterId, source.workspaceId, source.intentId, source.intentRevision];
    const version = await tx.one<any>('SELECT * FROM entity_change_intent_versions WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4', args);
    const intent = await tx.one<any>('SELECT * FROM entity_change_intents WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', args.slice(0, 3));
    this.intentTuple(version, source); if (!intent) throw invalid();
    const envelope = this.secrets.decrypt<EntityChangeIntentEnvelopeV1>(version.envelope_ciphertext, entityChangeIntentAad(source.clusterId, source.workspaceId, source.intentId, source.intentRevision));
    const material = envelope.prepared, { changeDigest, ...original } = material;
    if (envelope.version !== 1 || envelope.intentId !== source.intentId || envelope.revision !== source.intentRevision || envelope.clusterId !== source.clusterId || envelope.workspaceId !== source.workspaceId
      || envelope.requesterId !== source.executionActorId || envelope.requesterId !== intent.requester_id || envelope.requesterId !== version.requester_id || envelope.requesterId !== material.requesterId
      || envelope.credentialEpoch !== source.credentialEpoch || envelope.credentialEpoch !== String(intent.credential_epoch) || envelope.credentialEpoch !== String(version.credential_epoch)
      || material.version !== 1 || material.clusterId !== source.clusterId || material.workspaceId !== source.workspaceId || this.secrets.fingerprint(envelope) !== source.materialHmac
      || this.secrets.fingerprint(original) !== changeDigest || changeDigest !== source.changeDigest || this.secrets.fingerprint(envelope.review) !== this.secrets.fingerprint(version.safe_review)
      || envelope.executionMode !== version.execution_mode || envelope.definition.id !== version.definition_id || envelope.definition.version !== version.definition_version || envelope.definition.policyHash !== version.policy_hash
      || iso(intent.issued_at) !== envelope.issuedAt || iso(intent.expires_at) !== envelope.expiresAt || iso(version.issued_at) !== envelope.issuedAt || iso(version.expires_at) !== envelope.expiresAt
      || !Number.isInteger(envelope.ttlHours) || envelope.ttlHours < 1 || envelope.ttlHours > 168 || Date.parse(envelope.expiresAt) - Date.parse(envelope.issuedAt) !== envelope.ttlHours * 3600000
      || !Array.isArray(material.packets) || !material.packets.length || material.packets.length > 1000 || !Array.isArray(material.metadataObligations)) throw invalid();
    const manifest = normalizedEntityChangePackets(material, this.secrets);
    if (manifest.length !== version.packet_count || this.secrets.fingerprint(manifest) !== source.packetManifestHmac || envelope.packetManifestHmac !== source.packetManifestHmac) throw invalid();
    this.same(version.packet_manifest, manifest);
    const rows = await tx.query<any>('SELECT * FROM entity_change_intent_packets WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4 ORDER BY packet_order', args);
    rows.forEach(row => this.intentTuple(row, source)); this.same(rows.map(row => this.packet(row)), manifest);
    const seen = new Set<string>();
    material.packets.forEach((packet, index) => {
      if (packet.order !== index + 1 || !key.test(packet.key) || seen.has(packet.key) || !uuid.test(packet.nativeId) || !native.has(packet.nativeType) || !Array.isArray(packet.dependencies)
        || packet.dependencies.some(dep => !seen.has(dep)) || new Set(packet.dependencies).size !== packet.dependencies.length || this.secrets.fingerprint(packet.body ?? null) !== packet.bodyHmac || this.secrets.fingerprint(packet.before) !== packet.beforeHmac) throw invalid();
      assertKongPath(packet.method, packet.canonicalPath); seen.add(packet.key);
    });
    return immutableJson(material);
  }

  private async storedWorkflow(source: EntityExecutionSourceByOrigin, tx: DbService): Promise<{ workflow: any; execution: any; plan: any }> {
    const args = [source.clusterId, source.workspaceId, source.workflowId];
    const workflow = await tx.one<any>('SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', args);
    const execution = await tx.one<any>('SELECT * FROM workflow_executions WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [source.clusterId, source.workspaceId, source.workflowExecutionId]);
    const version = await tx.one<any>('SELECT * FROM workflow_versions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4', [...args, source.workflowPlanRevision]);
    const submission = await tx.one<any>('SELECT * FROM entity_change_submissions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3', args);
    this.scope(workflow, { clusterId: source.clusterId, workspaceId: source.workspaceId } as any); this.scope(execution, { clusterId: source.clusterId, workspaceId: source.workspaceId } as any);
    this.intentTuple(submission, source);
    if (!closedWorkflow.has(workflow.state) || !closedExecution.has(execution.state) || workflow.kind !== 'native-change' || workflow.subject_type !== 'entity_change_intents' || workflow.subject_id !== source.intentId
      || workflow.requester_type !== 'console' || workflow.requester_user_id !== source.executionActorId || execution.execution_actor_id !== source.executionActorId || submission.actor_id !== source.executionActorId
      || workflow.plan_revision !== source.workflowPlanRevision || workflow.plan_hash !== source.workflowPlanHash || execution.workflow_id !== source.workflowId || execution.plan_revision !== source.workflowPlanRevision || execution.plan_hash !== source.workflowPlanHash
      || !version || version.plan_hash !== source.workflowPlanHash || submission.workflow_plan_revision !== source.workflowPlanRevision || submission.workflow_plan_hash !== source.workflowPlanHash) throw invalid();
    const plan = this.secrets.decrypt<any>(version.payload_secret, planAad(source.clusterId, source.workspaceId, source.workflowId, source.workflowPlanRevision));
    const step = assertEntityChangeWorkflowPlan(plan);
    if (this.secrets.fingerprint(plan) !== source.workflowPlanHash || plan.clusterId !== source.clusterId || plan.workspaceId !== source.workspaceId || plan.workflowId !== source.workflowId || plan.planRevision !== source.workflowPlanRevision || plan.requester.id !== source.executionActorId) throw invalid();
    this.same(step.metadata, { intentId: source.intentId, intentRevision: source.intentRevision, materialHmac: source.materialHmac, changeDigest: source.changeDigest, packetManifestHmac: source.packetManifestHmac });
    const unresolved = await tx.one<any>(`SELECT EXISTS(SELECT 1 FROM workflow_steps WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 AND state IN('pending','running','uncertain'))
      OR EXISTS(SELECT 1 FROM workflow_executions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND state IN('claimed','executing','uncertain')) AS unresolved`, [...args, source.workflowPlanRevision]);
    if (!unresolved || unresolved.unresolved !== false) throw invalid(); return { workflow, execution, plan };
  }

  private async storedBaseline(source: EntityExecutionSourceByOrigin, archive: any, graph: RecycleGraph, tx: DbService, direction: 'delete' | 'restore' | 'partial-restore' = 'delete'): Promise<{ row: any; pin: any; capture: EntityChangeBaselineCapture }> {
    const row = await tx.one<any>('SELECT * FROM entity_change_baselines WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [source.clusterId, source.workspaceId, archive.baseline_id]);
    this.intentTuple(row, source);
    if (row.source_id !== source.id || row.workflow_id !== source.workflowId || row.workflow_plan_revision !== source.workflowPlanRevision || row.workflow_plan_hash !== source.workflowPlanHash
      || row.workflow_execution_id !== source.workflowExecutionId || row.execution_actor_id !== source.executionActorId || String(row.credential_epoch) !== source.credentialEpoch || row.readiness !== 'ready') throw invalid();
    const envelope = this.secrets.decrypt<EntityChangeBaselineEnvelope>(row.material_ciphertext, `entity-change-baseline:${source.clusterId}:${source.workspaceId}:${row.id}:material`);
    const manifest = this.baselineManifest(envelope.capture);
    if (envelope.version !== 1 || envelope.baselineId !== row.id || this.secrets.fingerprint(envelope) !== row.baseline_hmac || this.secrets.fingerprint(envelope.capture) !== row.capture_hmac
      || this.secrets.fingerprint(manifest) !== row.object_manifest_hmac || row.object_count !== manifest.length || row.graph_count !== envelope.capture.graphs.length
      || iso(row.observed_from) !== envelope.capture.observedFrom || iso(row.observed_until) !== envelope.capture.observedUntil || Date.parse(envelope.capture.observedFrom) < Date.parse(source.issuedAt) || Date.parse(envelope.capture.observedUntil) > Date.parse(source.expiresAt)) throw invalid();
    this.same(envelope.source, source); this.same(row.object_manifest, manifest);
    const objects = await tx.query<any>('SELECT * FROM entity_change_baseline_objects WHERE baseline_id=$1 ORDER BY object_order', [row.id]);
    if (objects.length !== manifest.length || objects.some((item, index) => item.object_order !== index + 1 || item.cluster_id !== source.clusterId || item.workspace_id !== source.workspaceId || item.object_manifest_hmac !== row.object_manifest_hmac)) throw invalid();
    this.same(objects.map(item => ({ key: item.object_key, nativeType: item.native_type, nativeId: item.native_id, parentId: item.parent_id, credentialKind: item.credential_kind, affected: item.affected, present: item.present,
      dependencies: item.dependencies, beforeHmac: item.before_hmac, restoreHmac: item.restore_hmac, schemaHmac: item.schema_hmac, provenanceHmac: item.provenance_hmac, recovery: item.recovery })), manifest);
    const pin = await tx.one<any>('SELECT * FROM entity_change_baseline_pins WHERE id=$1 AND baseline_id=$2', [archive.pin_id, archive.baseline_id]);
    if (!pin || pin.id !== archive.pin_id || pin.cluster_id !== source.clusterId || pin.workspace_id !== source.workspaceId || pin.baseline_id !== archive.baseline_id || pin.source_id !== source.id || pin.workflow_execution_id !== source.workflowExecutionId
      || pin.baseline_hmac !== row.baseline_hmac || pin.object_manifest_hmac !== row.object_manifest_hmac || !Number.isInteger(pin.pin_version) || pin.pin_version < 1 || !Number.isFinite(Date.parse(iso(pin.protected_until)))) throw invalid();
    if (direction === 'partial-restore') return { row, pin, capture: envelope.capture };
    if (direction === 'restore') {
      if (envelope.capture.graphs.length !== 0 || envelope.capture.objects.length !== graph.nodes.length) throw invalid();
      for (const node of graph.nodes) {
        const parentId = this.parent(graph, node), baselineKey = parentId ? `${node.type}:${parentId}:${node.id}` : `${node.type}:${node.id}`;
        const matches = envelope.capture.objects.filter(item => item.nativeType === node.type && item.nativeId === node.id && (item.parentId ?? null) === (parentId ?? null));
        if (matches.length !== 1 || matches[0].key !== baselineKey || matches[0].present || !matches[0].affected || matches[0].before !== null || matches[0].recovery !== 'absent'
          || matches[0].restorePayload !== undefined || (matches[0].credentialKind ?? null) !== (credential(node.type) ? node.type : null)) throw invalid();
        this.same(matches[0].dependencies, node.dependencies);
      }
      return { row, pin, capture: envelope.capture };
    }
    for (const node of graph.nodes) {
      const captured = envelope.capture.objects.find(item => item.key === node.key);
      if (!captured || !captured.present || captured.nativeType !== node.type || captured.nativeId !== node.id || (captured.parentId ?? null) !== (this.parent(graph, node) ?? null)
        || node.affected && !captured.affected) throw invalid();
      this.same(captured.before, node.data); this.same(captured.dependencies, node.dependencies);
      if (node.affected) this.same(captured.restorePayload, node.restoreData);
    }
    // The matching live graph has all children, not merely the packet subset.
    const complete = envelope.capture.graphs.find(item => item.rootKey === graph.rootKey);
    if (!complete || complete.nodes.length !== graph.nodes.length) throw invalid();
    this.same([...complete.nodes].sort((a, b) => a.key.localeCompare(b.key)), [...graph.nodes].sort((a, b) => a.key.localeCompare(b.key)));
    return { row, pin, capture: envelope.capture };
  }

  private event(row: any, attempt: any, source: EntityExecutionSourceByOrigin, archive: any): any {
    this.sourceTuple(row, source, archive);
    if (row.attempt_id !== attempt.id || !['send-intent', 'outcome'].includes(row.event_kind)) throw invalid();
    const fact = this.secrets.decrypt<any>(row.fact_ciphertext, `entity-change-packet-fact:${source.clusterId}:${source.workspaceId}:${attempt.id}:${row.event_kind}`);
    if (!fact || fact.version !== 1 || fact.kind !== row.event_kind || this.secrets.fingerprint(fact) !== row.fact_hmac || fact.observedAt !== iso(row.observed_at)
      || Date.parse(fact.observedAt) < Date.parse(iso(attempt.created_at)) || Date.parse(fact.observedAt) > Date.parse(iso(row.created_at))
      || fact.kind === 'send-intent' && (Date.parse(fact.observedAt) < Date.parse(source.issuedAt) || Date.parse(fact.observedAt) > Date.parse(source.expiresAt))) throw invalid();
    this.same(fact.binding, { sourceId: source.id, baselineId: archive.baseline_id, pinId: archive.pin_id, packetKey: attempt.packet_key, attemptId: attempt.id });
    if (fact.kind === 'outcome' && (fact.outcome !== row.outcome || (fact.nativeStatus ?? null) !== row.native_status || (fact.errorCode ?? null) !== row.error_code)) throw invalid();
    return fact;
  }

  /** Fixed zero-send footprint authentication. Closed workflow state alone is
   * never sufficient to discard a foreign restore source. Every original
   * material, baseline, observation and outcome is read and authenticated. */
  private async knownNoSendPartialSource(input:EntityRecycleOriginReadInput,sourceId:string,history:EntityRecycleClosedRestoreCoverage,
    tx:DbService,requireAuditedClosure:boolean):Promise<Readonly<EntityRecycleKnownNoSendPartialSource>>{
    const source=decodeEntityExecutionSource(await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[input.clusterId,input.workspaceId,sourceId]));
    if('origin'in source||source.sessionId===null||source.id===history.sourceId||source.clusterId!==input.clusterId||source.workspaceId!==input.workspaceId)throw invalid();
    const {workflow,execution,plan}=await this.storedWorkflow(source,tx),material=await this.storedIntent(source,tx);
    if(workflow.state!=='failed'||execution.state!=='failed'||!execution.completed_at||material.packets.length!==2||material.metadataObligations.length!==3
      ||material.request.kind!=='recycle'||material.request.action!=='restore'||material.request.entryId!==input.entryId||material.request.confirmed!==true
      ||material.scope.transportScope!==plan.scope.transportScope)throw invalid();
    const obligations=material.metadataObligations.filter(o=>o.kind==='recycle-restore');
    if(obligations.length!==1||obligations[0].kind!=='recycle-restore'||!obligations[0].partialRestore)throw invalid();
    const obligation=obligations[0],selection=obligation.partialRestore!,graph=obligation.graph,seal=obligation.sealedEntry;
    this.same(selection.history,history);
    const partition=validatePartialRecycleRestoreSelection(graph,selection,this.secrets),derived=derivePreparedRecyclePackets(obligation,material.packets,this.secrets);
    if(obligation.entryId!==input.entryId||obligation.graphHmac!==history.graphHmac||!seal||seal.state!=='partially_restored'
      ||seal.clusterId!==input.clusterId||seal.workspaceId!==input.workspaceId||seal.entryId!==input.entryId||seal.payloadHmac!==history.graphHmac
      ||!hex.test(seal.nodeManifestHmac)||seal.restoreMaterialHmac!==this.secrets.fingerprint(graph.nodes.map(n=>({key:n.key,restoreData:n.restoreData})))
      ||derived.length!==2||material.packets[0].nativeType!=='hmac-auth'||material.packets[1].nativeType!=='acls')throw invalid();
    for(const packet of material.packets){const side=material.metadataObligations.filter(o=>'packetKey'in o&&o.packetKey===packet.key);
      this.same(side,[{kind:'credential-remember',packetKey:packet.key,consumerId:packet.parentId,credentialKind:packet.nativeType,rawInput:packet.body}]);}
    const args=[input.clusterId,input.workspaceId,source.id],plans=await tx.query<any>("SELECT * FROM entity_change_recycle_packets WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 AND entry_id=$4 AND direction='restore' ORDER BY packet_order",[...args,input.entryId]);
    if(plans.length!==2||!uuid.test(plans[0].baseline_id)||!uuid.test(plans[0].pin_id))throw invalid();
    const binding={baseline_id:plans[0].baseline_id,pin_id:plans[0].pin_id},normalized=normalizedEntityChangePackets(material,this.secrets);
    plans.forEach((row,index)=>{this.sourceTuple(row,source,binding);this.intentTuple(row,source);
      if(row.entry_id!==input.entryId||row.direction!=='restore'||row.node_key!==derived[index].node.key)throw invalid();this.same(this.packet(row,material.packets[index].dependencies),normalized[index]);});
    const baseline=await this.storedBaseline(source,binding,graph,tx,'partial-restore'),capture=baseline.capture,root=graph.nodes.find(n=>n.key===graph.rootKey)!;
    if(capture.objects.length!==7||capture.graphs.length!==1||capture.graphs[0].purpose!=='baseline'||capture.graphs[0].complete!==true
      ||capture.graphs[0].rootKey!==graph.rootKey||capture.graphs[0].nodes.length!==5)throw invalid();
    for(const node of graph.nodes){const objects=capture.objects.filter(o=>partialRestoreNodeIdentity(o)===partialRestoreNodeIdentity(node)),present=partition.present.some(n=>n.key===node.key);
      if(objects.length!==1)throw invalid();const current=objects[0];
      if(current.present!==present||current.affected===present||current.recovery!==(present?'reference':'absent')||current.restorePayload!==undefined
        ||current.key!==(node.type==='consumers'?node.key:`${node.type}:${root.id}:${node.id}`)||!present&&current.before!==null)throw invalid();
      this.same(current.dependencies,node.dependencies);
      if(present){const prior=history.presentNodes.find(n=>n.nodeKey===node.key)!,observed=selection.presentNodes.find(n=>n.nodeKey===node.key)!;
        if(this.secrets.fingerprint(current.before)!==observed.beforeHmac||observed.beforeHmac!==prior.resultHmac)throw invalid();
        this.same(current.trustedProvenance,{kind:'closed-restore-current-present',nodeKey:node.key,historyCoverageHmac:history.coverageHmac,priorSourceId:history.sourceId,
          priorAttemptId:prior.attemptId,priorOperationId:prior.operationId,priorResultHmac:prior.resultHmac,beforeHmac:observed.beforeHmac,
          ...(observed.basicCustodyHmac?{basicCustodyHmac:observed.basicCustodyHmac}:{})});}}
    if(new Set(capture.graphs[0].nodes.map(partialRestoreNodeIdentity)).size!==5)throw invalid();
    for(const node of capture.graphs[0].nodes){const current=capture.objects.find(o=>partialRestoreNodeIdentity(o)===partialRestoreNodeIdentity(node));
      if(!current?.present||node.path!==graph.nodes.find(n=>partialRestoreNodeIdentity(n)===partialRestoreNodeIdentity(node))?.path)throw invalid();this.same(node.data,current.before);this.same(node.dependencies,current.dependencies);}
    const migration=await tx.one<any>('SELECT name,checksum FROM schema_migrations WHERE name=$1',[PARTIAL_RECYCLE_FACTS_MIGRATION.name]);
    if(!migration||migration.checksum!==PARTIAL_RECYCLE_FACTS_MIGRATION.checksum)throw invalid();
    const observed=await tx.query<any>('SELECT * FROM entity_change_recycle_restore_present_facts WHERE source_id=$1 AND entry_id=$2 ORDER BY node_key',[source.id,input.entryId]);
    if(observed.length!==5||new Set(observed.map(o=>o.node_key)).size!==5)throw invalid();
    for(const node of partition.present){const row=observed.find(o=>o.node_key===node.key),prior=history.presentNodes.find(n=>n.nodeKey===node.key)!,selected=selection.presentNodes.find(n=>n.nodeKey===node.key)!,current=capture.objects.find(o=>partialRestoreNodeIdentity(o)===partialRestoreNodeIdentity(node))!;
      if(!row||typeof row.fact_ciphertext!=='string')throw invalid();
      const provenance=current.trustedProvenance,fact={version:1,kind:'closed-restore-current-present',sourceId:source.id,baselineId:binding.baseline_id,pinId:binding.pin_id,
        clusterId:source.clusterId,workspaceId:source.workspaceId,workflowExecutionId:source.workflowExecutionId,entryId:input.entryId,nodeKey:node.key,baselineObjectKey:current.key,
        priorHistory:prior,closedSourceHmac:history.coverageHmac,currentBefore:current.before,provenance,observedAt:capture.observedUntil};
      const expected={cluster_id:source.clusterId,workspace_id:source.workspaceId,source_id:source.id,baseline_id:binding.baseline_id,pin_id:binding.pin_id,workflow_execution_id:source.workflowExecutionId,
        entry_id:input.entryId,node_key:node.key,direction:'restore',baseline_object_key:current.key,object_manifest_hmac:baseline.row.object_manifest_hmac,
        native_type:node.type,native_id:node.id,parent_id:node.type==='consumers'?null:root.id,credential_kind:node.type==='consumers'?null:node.type,
        prior_attempt_id:prior.attemptId,prior_operation_id:prior.operationId,prior_source_id:history.sourceId,prior_packet_key:prior.packetKey,observed_before_hmac:selected.beforeHmac,
        prior_result_hmac:prior.resultHmac,closed_source_hmac:history.coverageHmac,basic_custody_hmac:selected.basicCustodyHmac??null,fact_hmac:this.secrets.fingerprint(fact),observed_at:capture.observedUntil};
      const actual={...row};delete actual.created_at;delete actual.fact_ciphertext;actual.observed_at=iso(row.observed_at);this.same(actual,expected);
      if(Date.parse(iso(row.created_at))<Date.parse(capture.observedUntil))throw invalid();
      this.same(this.secrets.decrypt(row.fact_ciphertext,partialRestoreObservationAad(source.clusterId,source.workspaceId,source.id,input.entryId,node.key)),fact);}
    const attempts=await tx.query<any>('SELECT * FROM entity_change_packet_attempts WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 ORDER BY packet_order',args),
      events=await tx.query<any>('SELECT * FROM entity_change_packet_events WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 ORDER BY attempt_id,event_kind',args),
      mutations=await tx.query<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND workspace_id=$2 AND entity_change_source_id=$3 ORDER BY id',args),
      receipts=await tx.query<any>('SELECT * FROM entity_change_recycle_receipts WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 ORDER BY packet_key',args);
    if(attempts.length!==1||events.length!==1||mutations.length!==1||receipts.length!==0)throw invalid();
    const attempt=attempts[0],event=events[0],mutation=mutations[0],packet=material.packets[0];
    this.sourceTuple(attempt,source,binding);this.intentTuple(attempt,source);this.same(this.packet(attempt,packet.dependencies),normalized[0]);this.scope(mutation,input);
    if(!uuid.test(attempt.id)||!uuid.test(event.id)||!uuid.test(mutation.id)||event.event_kind!=='outcome'||event.outcome!=='failed-known-not-sent'||event.native_status!==null
      ||mutation.state!=='failed'||mutation.remote_started!==true||mutation.remote_completed!==false||mutation.result_secret!==null
      ||mutation.actor_id!==source.executionActorId||mutation.workflow_id!==source.workflowId||mutation.entity_change_source_id!==source.id||mutation.entity_change_baseline_id!==binding.baseline_id
      ||mutation.entity_change_attempt_id!==attempt.id||mutation.entity_change_packet_key!==packet.key||mutation.entity_type!=='credentials'||mutation.entity_id!==packet.nativeId
      ||mutation.parent_id!==root.id||mutation.credential_kind!=='hmac-auth'||mutation.action!=='restore'||mutation.idempotency_key!==`entity-${source.workflowExecutionId}-1`
      ||mutation.transport_scope!==plan.scope.transportScope||!mutation.before_secret||!mutation.payload_secret
      ||['workflow_execution_id','workflow_plan_revision','workflow_plan_hash','workflow_step_id','configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash'].some(k=>mutation[k]!=null))throw invalid();
    this.same(this.secrets.decrypt(mutation.before_secret,`mutation:${mutation.id}:before`),null);this.same(this.secrets.decrypt(mutation.payload_secret,`mutation:${mutation.id}:payload`),packet.body);
    const outcome=this.event(event,attempt,source,binding);
    if(outcome.outcome!=='failed-known-not-sent'||outcome.nativeStatus!==undefined||typeof outcome.errorCode!=='string'||!/^[A-Z0-9_]{1,128}$/.test(outcome.errorCode)
      ||mutation.error_code!==outcome.errorCode||Date.parse(iso(execution.completed_at))<Date.parse(outcome.observedAt))throw invalid();
    this.same(outcome.evidence,{operationId:mutation.id,mutationState:'failed',remoteCompleted:false,responseHmac:null,metadataComplete:false});
    const entry=await tx.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[input.clusterId,input.workspaceId,input.entryId]),
      archive=await tx.one<any>('SELECT * FROM entity_change_recycle_archives WHERE cluster_id=$1 AND workspace_id=$2 AND entry_id=$3',[input.clusterId,input.workspaceId,input.entryId]);
    this.scope(entry,input);this.scope(archive,input);
    if(entry.mutation_id!==null||entry.root_type!=='consumers'||entry.original_id!==root.id||entry.node_count!==7||entry.purged_at!==null||iso(entry.expires_at)!==seal.expiresAt
      ||archive.source_id===source.id||archive.graph_hmac!==history.graphHmac||archive.payload_hmac!==history.graphHmac||archive.node_count!==7||archive.packet_count!==7
      ||archive.node_manifest_hmac!==history.nodeManifestHmac)throw invalid();
    this.same(this.secrets.decrypt(entry.payload_secret,`recycle:${input.entryId}`),graph);this.same(archive.node_manifest,this.manifest(graph));
    const legacy=await tx.query<any>('SELECT * FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key',[input.entryId]);
    if(legacy.length!==7||new Set(legacy.map(n=>n.node_key)).size!==7)throw invalid();
    for(const node of graph.nodes){const projected=legacy.find(n=>n.node_key===node.key);if(!projected||projected.entry_id!==input.entryId||projected.entity_type!==node.type||projected.original_id!==node.id||projected.affected!==true||projected.delete_state!=='deleted')throw invalid();this.same(projected.dependencies,node.dependencies);}
    const failed=legacy.find(n=>n.node_key===derived[0].node.key),acl=legacy.find(n=>n.node_key===derived[1].node.key),alreadyClosed=entry.state==='partially_restored'&&failed.restore_state==='failed'&&failed.restored_id===null;
    if(!requireAuditedClosure&&(entry.restored_at!==null||!['restoring','partially_restored'].includes(entry.state)||!['pending','failed'].includes(failed.restore_state)||failed.restored_id!==null||acl.restore_state!=='pending'||acl.restored_id!==null
      ||partition.present.some(node=>{const projected=legacy.find(n=>n.node_key===node.key);return projected.restore_state!=='restored'||projected.restored_id!==node.id;})))throw invalid();
    const immutable={version:1 as const,clusterId:source.clusterId,workspaceId:source.workspaceId,entryId:input.entryId,sourceId:source.id,sourceHmac:this.secrets.fingerprint(source),
      workflowId:source.workflowId,workflowExecutionId:source.workflowExecutionId,intentId:source.intentId,intentRevision:source.intentRevision,baselineId:binding.baseline_id,pinId:binding.pin_id,
      materialHmac:source.materialHmac,changeDigest:source.changeDigest,packetManifestHmac:source.packetManifestHmac,historyCoverageHmac:history.coverageHmac,oldSourceId:history.sourceId,
      graphHmac:history.graphHmac,failedNodeKey:derived[0].node.key,failedPacketKey:packet.key,operationId:mutation.id,attemptId:attempt.id,outcomeEventId:event.id,outcomeFactHmac:event.fact_hmac};
    const proofHmac=this.secrets.fingerprint({immutable,baselineHmac:baseline.row.baseline_hmac,captureHmac:baseline.row.capture_hmac,objectManifestHmac:baseline.row.object_manifest_hmac,
      presentFacts:observed.map(o=>({nodeKey:o.node_key,factHmac:o.fact_hmac})).sort((a,b)=>a.nodeKey.localeCompare(b.nodeKey))});
    const result=immutableJson({...immutable,proofHmac,alreadyClosed});
    if(requireAuditedClosure)await this.knownNoSendClosureAudit(input,result,event,source.executionActorId,tx);
    return result;
  }

  private async knownNoSendClosureAudit(input:EntityRecycleOriginReadInput,footprint:EntityRecycleKnownNoSendPartialSource,event:any,actorId:string,tx:DbService):Promise<void>{
    const audits=await tx.query<any>(`SELECT a.*,a.sequence::text AS sequence,(a.occurred_at=date_trunc('milliseconds',a.occurred_at)) AS millisecond_precision
      FROM audit_events a WHERE cluster_id=$1 AND workspace_id=$2 AND entity_type='workflows' AND entity_id=$3::text AND workflow_id=$3::uuid
      AND action='workflow.execute.terminal-metadata-reconciled' AND after->>'sourceId'=$4 AND after->>'entryId'=$5 ORDER BY occurred_at,id LIMIT 2`,
      [input.clusterId,input.workspaceId,footprint.workflowId,footprint.sourceId,input.entryId]);
    if(audits.length!==1)throw invalid();const audit=audits[0];this.scope(audit,input);
    if(!uuid.test(audit.id)||audit.actor_id!==actorId||audit.actor_type!=='user'||audit.entity_type!=='workflows'||audit.entity_id!==footprint.workflowId||audit.workflow_id!==footprint.workflowId
      ||audit.action!=='workflow.execute.terminal-metadata-reconciled'||audit.result!=='failed'||audit.chain_scope!==`cluster:${input.clusterId}`||!hex.test(audit.after?.requestHmac)
      ||Date.parse(iso(audit.occurred_at))<Date.parse(iso(event.created_at))||createHash('sha256').update(canonicalJson(auditCanonicalRecord(audit))).digest('hex')!==audit.event_hash)throw invalid();
    if(!['pending','failed'].includes(audit.before?.nodeRestoreState))throw invalid();
    this.same(audit.before,{operationState:'failed',entryState:'restoring',nodeRestoreState:audit.before.nodeRestoreState});
    this.same(audit.after,{shape:'partial-no-send',executionId:footprint.workflowExecutionId,sourceId:footprint.sourceId,entryId:input.entryId,operationId:footprint.operationId,
      outcomeEventId:footprint.outcomeEventId,outcomeFactHmac:footprint.outcomeFactHmac,proofHmac:footprint.proofHmac,requestHmac:audit.after.requestHmac,
      workflowState:'failed',executionState:'failed',operationState:'failed',entryState:'partially_restored',nodeRestoreState:'failed',coveredPresent:5,nativeSuccesses:0,
      knownNotSent:1,unattempted:1,nativeRequestsSent:0,metadataReconciled:true});
  }

  /** Pure historical certificate consumed by Root's metadata-only reconciler.
   * UUIDs select stored facts and never provide authority or suppress unknowns. */
  async certifyKnownNoSendPartialSource(input:EntityRecycleOriginReadInput,sourceId:string,tx?:DbService):Promise<Readonly<EntityRecycleKnownNoSendPartialSource>>{
    if(!input||[input.clusterId,input.workspaceId,input.entryId,sourceId].some(id=>!uuid.test(id))||input.actor?.workspaceId!==input.workspaceId)throw invalid();
    const certify=async(db:DbService)=>{await this.assertClosedEntrySources(input,db,null);
      const source=decodeEntityExecutionSource(await db.one<any>('SELECT * FROM entity_change_execution_sources WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[input.clusterId,input.workspaceId,sourceId])),material=await this.storedIntent(source,db);
      const restore=material.metadataObligations.find(o=>o.kind==='recycle-restore');if(restore?.kind!=='recycle-restore'||!restore.partialRestore)throw invalid();
      await this.verifyFrozenRestoreCoverage(input,restore.partialRestore.history,sourceId,db);
      return this.knownNoSendPartialSource(input,sourceId,restore.partialRestore.history,db,false);};
    if(tx)return certify(tx);return this.db.transaction(async db=>{await db.exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');return certify(db);});
  }

  /** One deliberately narrow historical 5/1/1 closure. The persisted no-send
   * classification can coexist with a send reservation and remote_started=true;
   * neither is a wire observation. Actual current wire/custody checks belong to
   * Root's private bridge, which this SELECT-only reader cannot manufacture. */
  private async closedRestoreCoverage(input: EntityRecycleOriginReadInput, archive: any, graph: RecycleGraph, entry: any,
    legacy: any[], tx: DbService, activeRestoreSourceId: string | null, immutableExpected?:EntityRecycleClosedRestoreCoverage): Promise<EntityRecycleClosedRestoreCoverage> {
    await this.assertClosedEntrySources(input, tx, activeRestoreSourceId);
    const ordered = this.orderedGraph(graph);
    if (ordered.length !== 7 || archive.packet_count !== 7 || ordered.some((node, index) => node.type !== partialRestoreTypes[index] || !node.affected)
      || graph.rootKey !== ordered[0].key || graph.targetHistory !== undefined || new Set(ordered.map(node => node.id)).size !== 7
      || entry.root_type !== 'consumers' || entry.parent_id !== null || entry.credential_kind !== null || entry.purged_at !== null
      || !immutableExpected&&(entry.restored_at !== null||entry.state !== 'partially_restored' && !(entry.state === 'restoring' && activeRestoreSourceId !== null))) throw invalid();
    const sourceIds = await tx.query<any>(`SELECT DISTINCT source_id FROM entity_change_recycle_packets WHERE cluster_id=$1 AND workspace_id=$2
      AND entry_id=$3 AND direction='restore' AND ($4::uuid IS NULL OR source_id<>$4::uuid)`, [input.clusterId, input.workspaceId, input.entryId, activeRestoreSourceId]);
    if(!sourceIds.length||sourceIds.length>32||new Set(sourceIds.map(row=>row.source_id)).size!==sourceIds.length)throw invalid();
    const originalSources:string[]=[],zeroSendSources:string[]=[];
    for(const row of sourceIds){if(!uuid.test(row.source_id)||row.source_id===archive.source_id)throw invalid();
      const candidate=decodeEntityExecutionSource(await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[input.clusterId,input.workspaceId,row.source_id])),candidateMaterial=await this.storedIntent(candidate,tx);
      if(candidateMaterial.packets.length===7)originalSources.push(candidate.id);
      else if(candidateMaterial.packets.length===2)zeroSendSources.push(candidate.id);
      else throw invalid();}
    if(originalSources.length!==1||immutableExpected&&originalSources[0]!==immutableExpected.sourceId)throw invalid();
    const source = decodeEntityExecutionSource(await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',
      [input.clusterId, input.workspaceId, originalSources[0]]));
    if (source.sessionId === null || source.clusterId !== input.clusterId || source.workspaceId !== input.workspaceId || source.id === activeRestoreSourceId) throw invalid();
    const { workflow, execution, plan } = await this.storedWorkflow(source, tx), material = await this.storedIntent(source, tx);
    if (workflow.state !== 'partial' || execution.state !== 'partial' || !hex.test(plan.scope?.transportScope) || material.scope.transportScope !== plan.scope.transportScope
      || material.request.kind !== 'recycle' || material.request.action !== 'restore' || material.request.entryId !== input.entryId || material.request.confirmed !== true
      || material.packets.length !== 7 || material.metadataObligations.length !== 8) throw invalid();
    const obligations = material.metadataObligations.filter(item => item.kind === 'recycle-restore');
    if (obligations.length !== 1 || obligations[0].kind !== 'recycle-restore') throw invalid();
    const obligation = obligations[0], seal = obligation.sealedEntry, packets = material.packets, normalized = normalizedEntityChangePackets(material, this.secrets);
    if (obligation.entryId !== input.entryId || obligation.graphHmac !== archive.graph_hmac || !seal || seal.clusterId !== input.clusterId || seal.workspaceId !== input.workspaceId
      || seal.entryId !== input.entryId || seal.state !== 'deleted' || seal.expiresAt !== iso(entry.expires_at) || !hex.test(seal.nodeManifestHmac)
      || seal.payloadHmac !== archive.graph_hmac || seal.restoreMaterialHmac !== this.secrets.fingerprint(graph.nodes.filter(node => node.affected).map(node => ({ key: node.key, restoreData: node.restoreData })))) throw invalid();
    this.same(obligation.graph, graph); this.same(obligation.packetKeys, packets.map(packet => packet.key));
    for (const [index, packet] of packets.entries()) {
      const node = ordered[index], parentId = this.parent(graph, node) ?? null;
      if (packet.order !== index + 1 || packet.method !== 'POST' || packet.mutationAction !== 'restore' || packet.permissionAction !== 'write'
        || packet.nativeType !== node.type || packet.nativeId !== node.id || packet.originalNativeId !== undefined || packet.before !== null
        || (packet.parentId ?? null) !== parentId || (packet.credentialKind ?? null) !== (index ? node.type : null)
        || packet.canonicalPath !== (index ? `/consumers/${ordered[0].id}/${node.type}` : '/consumers')) throw invalid();
      this.same(packet.body, this.restore(node)); this.same(packet.dependencies, index ? [packets[0].key] : []);
      const side = material.metadataObligations.filter(item => 'packetKey' in item && item.packetKey === packet.key);
      if (side.length !== 1) throw invalid();
      this.same(side[0], index ? { kind: 'credential-remember', packetKey: packet.key, consumerId: ordered[0].id, credentialKind: packet.nativeType, rawInput: packet.body }
        : { kind: 'entity-index', packetKey: packet.key, entityType: 'consumers' });
      const projected = legacy.find(item => item.node_key === node.key);
      if (!immutableExpected&&(!projected || projected.entry_id !== input.entryId || projected.entity_type !== node.type || projected.original_id !== node.id || projected.affected !== true
        || projected.delete_state !== 'deleted' || projected.restore_state !== (index < 5 ? 'restored' : index === 5 ? 'failed' : 'pending')
        || projected.restored_id !== (index < 5 ? node.id : null))) throw invalid();
      if(!immutableExpected)this.same(projected.dependencies, node.dependencies);
    }
    const args = [input.clusterId, input.workspaceId, source.id];
    const plans = await tx.query<any>("SELECT * FROM entity_change_recycle_packets WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 AND entry_id=$4 AND direction='restore' ORDER BY packet_order", [...args, input.entryId]);
    if (plans.length !== 7 || new Set(plans.map(row => row.node_key)).size !== 7 || !uuid.test(plans[0].baseline_id) || !uuid.test(plans[0].pin_id)) throw invalid();
    const binding = { baseline_id: plans[0].baseline_id, pin_id: plans[0].pin_id }, baseline = await this.storedBaseline(source, binding, graph, tx, 'restore');
    plans.forEach((row, index) => {
      this.sourceTuple(row, source, binding); this.intentTuple(row, source);
      if (row.entry_id !== input.entryId || row.direction !== 'restore' || row.node_key !== ordered[index].key) throw invalid();
      this.same(this.packet(row, packets[index].dependencies), normalized[index]);
    });
    const attempts = await tx.query<any>('SELECT * FROM entity_change_packet_attempts WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 ORDER BY packet_order', args);
    const events = await tx.query<any>('SELECT * FROM entity_change_packet_events WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 ORDER BY attempt_id,event_kind', args);
    const mutations = await tx.query<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND workspace_id=$2 AND entity_change_source_id=$3 ORDER BY id', args);
    const receipts = await tx.query<any>("SELECT * FROM entity_change_recycle_receipts WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 AND entry_id=$4 AND direction='restore' ORDER BY packet_key", [...args, input.entryId]);
    if (attempts.length !== 6 || events.length !== 12 || mutations.length !== 6 || receipts.length !== 5 || !immutableExpected&&legacy.length !== 7
      || new Set(attempts.map(row => row.id)).size !== 6 || new Set(attempts.map(row => row.packet_key)).size !== 6 || new Set(events.map(row => row.id)).size !== 12
      || new Set(mutations.map(row => row.id)).size !== 6 || new Set(receipts.map(row => row.attempt_id)).size !== 5) throw invalid();
    const presentNodes: EntityRecyclePresentNodeHistory[] = [], remainingNodes: EntityRecycleRemainingNodeHistory[] = [];
    const immutableFacts: any[] = [], stableMutations: any[] = []; let failedEvent: any;
    for (const [index, packet] of packets.entries()) {
      const node = ordered[index], identity = { nodeKey: node.key, nativeType: node.type, nativeId: node.id, parentId: packet.parentId ?? null, credentialKind: packet.credentialKind ?? null };
      const matching = attempts.filter(row => row.packet_key === packet.key);
      if (index === 6) {
        if (matching.length || mutations.some(row => row.entity_change_packet_key === packet.key) || receipts.some(row => row.packet_key === packet.key)) throw invalid();
        remainingNodes.push({ ...identity, classification: 'unattempted', packetKey: packet.key, attemptId: null, operationId: null, outcomeFactHmac: null }); continue;
      }
      if (matching.length !== 1) throw invalid(); const attempt = matching[0];
      if (!uuid.test(attempt.id)) throw invalid(); this.sourceTuple(attempt, source, binding); this.intentTuple(attempt, source);
      this.same(this.packet(attempt, packet.dependencies), normalized[index]);
      const matchedMutations = mutations.filter(row => row.entity_change_attempt_id === attempt.id);
      if (matchedMutations.length !== 1) throw invalid(); const mutation = matchedMutations[0]; this.scope(mutation, input);
      if (!uuid.test(mutation.id) || mutation.actor_id !== source.executionActorId || mutation.workflow_id !== source.workflowId || mutation.entity_change_source_id !== source.id
        || mutation.entity_change_baseline_id !== binding.baseline_id || mutation.entity_change_packet_key !== packet.key || mutation.entity_id !== node.id
        || mutation.entity_type !== (index ? 'credentials' : 'consumers') || mutation.parent_id !== identity.parentId || mutation.credential_kind !== identity.credentialKind
        || mutation.action !== 'restore' || mutation.idempotency_key !== `entity-${source.workflowExecutionId}-${packet.order}` || mutation.transport_scope !== plan.scope.transportScope
        || ['workflow_execution_id', 'workflow_plan_revision', 'workflow_plan_hash', 'workflow_step_id', 'configuration_job_id', 'configuration_execution_id', 'configuration_step_id', 'configuration_plan_revision', 'configuration_plan_hash'].some(field => mutation[field] != null)
        || !mutation.before_secret || !mutation.payload_secret) throw invalid();
      this.same(this.secrets.decrypt(mutation.before_secret, `mutation:${mutation.id}:before`), null);
      this.same(this.secrets.decrypt(mutation.payload_secret, `mutation:${mutation.id}:payload`), packet.body);
      const pair = events.filter(row => row.attempt_id === attempt.id);
      if (pair.length !== 2 || new Set(pair.map(row => row.event_kind)).size !== 2) throw invalid();
      const decoded: Record<string, any> = {};
      for (const row of pair) {
        if (!uuid.test(row.id)) throw invalid(); const fact = this.event(row, attempt, source, binding);
        if (fact.kind === 'send-intent') {
          if (row.outcome !== null || row.native_status !== null || row.error_code !== null) throw invalid();
          this.same(fact.evidence, { operationId: mutation.id, method: 'POST', pathHmac: normalized[index].pathHmac, bodyHmac: packet.bodyHmac, beforeHmac: packet.beforeHmac });
        }
        decoded[row.event_kind] = fact; immutableFacts.push({ id: row.id, factHmac: row.fact_hmac });
      }
      const outcome = decoded.outcome, send = decoded['send-intent'];
      if (!outcome || !send || Date.parse(outcome.observedAt) < Date.parse(send.observedAt) || !object(outcome.evidence) || typeof outcome.evidence.metadataComplete !== 'boolean') throw invalid();
      let resultHmac: string | null = null;
      if (index < 5) {
        if (mutation.state !== 'succeeded' || mutation.remote_started !== true || mutation.remote_completed !== true || typeof mutation.result_secret !== 'string'
          || outcome.outcome !== 'succeeded' || outcome.nativeStatus !== 201 || outcome.errorCode !== undefined) throw invalid();
        const raw: any = this.secrets.decrypt(mutation.result_secret, `mutation:${mutation.id}:result`);
        if (!object(raw) || raw.id !== node.id || index && entityReferenceId(raw.consumer) !== ordered[0].id) throw invalid();
        if (node.type === 'basic-auth') this.basic(raw, packet.body, ordered[0].id);
        for (const [field, value] of Object.entries(packet.body!)) {
          if (field !== 'consumer' && !(node.type === 'basic-auth' && field === 'password')) this.same(raw[field], value);
        }
        resultHmac = this.secrets.fingerprint(raw);
        this.same(outcome.evidence, { operationId: mutation.id, mutationState: 'succeeded', remoteCompleted: true, responseHmac: resultHmac, metadataComplete: outcome.evidence.metadataComplete });
        const matches = receipts.filter(row => row.attempt_id === attempt.id); if (matches.length !== 1) throw invalid(); const receipt = matches[0];
        this.sourceTuple(receipt, source, binding);
        this.same(receipt, { attempt_id: attempt.id, cluster_id: input.clusterId, workspace_id: input.workspaceId, source_id: source.id, baseline_id: binding.baseline_id,
          pin_id: binding.pin_id, workflow_execution_id: source.workflowExecutionId, entry_id: input.entryId, node_key: node.key, packet_key: packet.key,
          operation_id: mutation.id, operation_key: mutation.idempotency_key, native_id: node.id, direction: 'restore', result_hmac: resultHmac, verification_hmac: null, created_at: receipt.created_at });
        presentNodes.push({ ...identity, packetKey: packet.key, attemptId: attempt.id, operationId: mutation.id, operationKey: mutation.idempotency_key,
          resultHmac, outcomeFactHmac: this.secrets.fingerprint(outcome) });
      } else {
        if (mutation.state !== 'failed' || mutation.remote_started !== true || mutation.remote_completed !== false || mutation.result_secret !== null
          || outcome.outcome !== 'failed-known-not-sent' || outcome.nativeStatus !== undefined || typeof outcome.errorCode !== 'string' || !/^[A-Z0-9_]{1,128}$/.test(outcome.errorCode)
          || mutation.error_code !== outcome.errorCode || receipts.some(row => row.attempt_id === attempt.id || row.packet_key === packet.key)) throw invalid();
        this.same(outcome.evidence, { operationId: mutation.id, mutationState: 'uncertain', remoteCompleted: false, responseHmac: null, metadataComplete: false });
        failedEvent = pair.find(row => row.event_kind === 'outcome');
        remainingNodes.push({ ...identity, classification: 'failed-known-not-sent', packetKey: packet.key, attemptId: attempt.id, operationId: mutation.id, outcomeFactHmac: failedEvent.fact_hmac });
      }
      stableMutations.push({ operationId: mutation.id, attemptId: attempt.id, packetKey: packet.key, operationKey: mutation.idempotency_key,
        bodyHmac: packet.bodyHmac, beforeHmac: packet.beforeHmac, resultHmac });
    }
    if (events.some(row => !attempts.some(attempt => attempt.id === row.attempt_id)) || receipts.some(row => !presentNodes.some(node => node.attemptId === row.attempt_id)) || !failedEvent) throw invalid();
    // Matches the immutable terminal certificate's algorithm exactly; mutable
    // reconciliation projections and current caller identity are not its inputs.
    const proofHmac = this.secrets.fingerprint({ version: 1, source, baselineHmac: baseline.row.baseline_hmac, captureHmac: baseline.row.capture_hmac,
      objectManifestHmac: baseline.row.object_manifest_hmac, pinId: binding.pin_id, graphHmac: archive.graph_hmac, nodeManifestHmac: archive.node_manifest_hmac,
      packetManifestHmac: source.packetManifestHmac, immutableFacts: immutableFacts.sort((a, b) => a.id.localeCompare(b.id)),
      receipts: receipts.map(row => ({ attemptId: row.attempt_id, operationId: row.operation_id, resultHmac: row.result_hmac })).sort((a, b) => a.attemptId.localeCompare(b.attemptId)), stableMutations });
    const audits = await tx.query<any>(`SELECT a.*,a.sequence::text AS sequence,(a.occurred_at=date_trunc('milliseconds',a.occurred_at)) AS millisecond_precision
      FROM audit_events a WHERE cluster_id=$1 AND workspace_id=$2 AND entity_type='workflows' AND entity_id=$3::text AND workflow_id=$3::uuid
      AND actor_id=$4 AND action='workflow.execute.terminal-metadata-reconciled' AND after->>'sourceId'=$5 AND after->>'entryId'=$6 ORDER BY occurred_at,id LIMIT 2`,
      [input.clusterId, input.workspaceId, source.workflowId, source.executionActorId, source.id, input.entryId]);
    if (audits.length !== 1) throw invalid(); const audit = audits[0], failed = remainingNodes[0]; this.scope(audit, input);
    if (!uuid.test(audit.id) || audit.actor_id !== source.executionActorId || audit.actor_type !== 'user' || audit.entity_type !== 'workflows' || audit.entity_id !== source.workflowId
      || audit.workflow_id !== source.workflowId || audit.action !== 'workflow.execute.terminal-metadata-reconciled' || audit.result !== 'failed'
      || !hex.test(audit.after?.requestHmac) || audit.chain_scope !== `cluster:${input.clusterId}` || Date.parse(iso(audit.occurred_at)) < Date.parse(iso(failedEvent.created_at))
      || createHash('sha256').update(canonicalJson(auditCanonicalRecord(audit))).digest('hex') !== audit.event_hash) throw invalid();
    this.same(audit.before, { operationState: 'uncertain', entryState: 'restoring', nodeRestoreState: 'pending' });
    this.same(audit.after, { executionId: source.workflowExecutionId, sourceId: source.id, entryId: input.entryId, operationId: failed.operationId,
      outcomeEventId: failedEvent.id, outcomeFactHmac: failedEvent.fact_hmac, proofHmac, requestHmac: audit.after.requestHmac,
      workflowState: 'partial', executionState: 'partial', operationState: 'failed', entryState: 'partially_restored', nodeRestoreState: 'failed',
      nativeSuccesses: 5, knownNotSent: 1, unattempted: 1, nativeRequestsSent: 0, metadataReconciled: true });
    if(!immutableExpected)await this.policy().assertFrozenSubject({ request: input, material, sourceId: source.id, workflowId: source.workflowId,
      packetKeys: obligation.packetKeys, graphHmac: archive.graph_hmac }, tx);
    const summary = { version: 1 as const, clusterId: input.clusterId, workspaceId: input.workspaceId, entryId: input.entryId, graphHmac: archive.graph_hmac,
      nodeManifestHmac: archive.node_manifest_hmac, sourceId: source.id, intentId: source.intentId, intentRevision: source.intentRevision,
      baselineId: binding.baseline_id, pinId: binding.pin_id, workflowId: source.workflowId, workflowExecutionId: source.workflowExecutionId,
      materialHmac: source.materialHmac, changeDigest: source.changeDigest, packetManifestHmac: source.packetManifestHmac,
      terminalMetadataAudit: { id: audit.id, eventHash: audit.event_hash, proofHmac, outcomeEventId: failedEvent.id, outcomeFactHmac: failedEvent.fact_hmac, requestHmac: audit.after.requestHmac },
      presentNodes, remainingNodes };
    const coverage=immutableJson({ ...summary, coverageHmac: this.secrets.fingerprint(summary) });
    // Only independent complete zero-send evidence plus Root's authenticated
    // metadata-only audit closes a failed two-packet footprint. It never
    // becomes the five-success source or changes the original coverage seal.
    for(const sourceId of zeroSendSources)await this.knownNoSendPartialSource(input,sourceId,coverage,tx,true);
    return coverage;
  }

  /** Pure SELECT-only authentication of frozen old facts, not an authority
   * delegate. Root must separately resolve its ORIGINAL current claim and
   * check live grants/own actual progress before any new send. The only
   * current-source exclusion concerns its expected active packets; unknown
   * outcomes remain unconditional blockers. Historical outcomes survive a
   * later role/session revocation; this method creates no handle or permit. */
  async verifyFrozenRestoreCoverage(input:EntityRecycleOriginReadInput,expected:EntityRecycleClosedRestoreCoverage,currentSourceId:string,tx?:DbService):Promise<void>{
    if(!input||!expected||[input.clusterId,input.workspaceId,input.entryId,currentSourceId].some(id=>!uuid.test(id))
      ||input.actor?.workspaceId!==input.workspaceId||expected.clusterId!==input.clusterId||expected.workspaceId!==input.workspaceId
      ||expected.entryId!==input.entryId||expected.sourceId===currentSourceId)throw invalid();
    const {coverageHmac,...summary}=expected;if(!hex.test(coverageHmac)||this.secrets.fingerprint(summary)!==coverageHmac)throw invalid();
    const verify=async(db:DbService)=>{
      const args=[input.clusterId,input.workspaceId,input.entryId],entry=await db.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',args),
        archive=await db.one<any>('SELECT * FROM entity_change_recycle_archives WHERE cluster_id=$1 AND workspace_id=$2 AND entry_id=$3',args);
      this.scope(entry,input);this.scope(archive,input);
      if(entry.mutation_id!==null||!entry.payload_secret||entry.state==='purged'||archive.graph_hmac!==expected.graphHmac||archive.node_manifest_hmac!==expected.nodeManifestHmac)throw invalid();
      const graph=this.secrets.decrypt<RecycleGraph>(entry.payload_secret,`recycle:${input.entryId}`),manifest=this.manifest(graph);
      if(this.secrets.fingerprint(graph)!==expected.graphHmac||this.secrets.fingerprint(manifest)!==expected.nodeManifestHmac||archive.payload_hmac!==expected.graphHmac||archive.node_count!==graph.nodes.length)throw invalid();
      this.same(archive.node_manifest,manifest);
      const nodes=await db.query<any>('SELECT * FROM entity_change_recycle_nodes WHERE entry_id=$1 ORDER BY node_order',[input.entryId]);
      nodes.forEach(row=>this.scope(row,input));this.same(nodes.map(row=>({key:row.node_key,order:row.node_order,nativeType:row.native_type,nativeId:row.native_id,
        parentId:row.parent_id,credentialKind:row.credential_kind,affected:row.affected,dependencies:row.dependencies,pathHmac:row.path_hmac,dataHmac:row.data_hmac,restoreHmac:row.restore_hmac})),manifest);
      const actual=await this.closedRestoreCoverage(input,archive,graph,entry,[],db,currentSourceId,expected);this.same(actual,expected);
    };
    if(tx)await verify(tx);else await this.db.transaction(async db=>{await db.exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');await verify(db);});
  }

  private async actualPackets(input: EntityRecycleOriginReadInput, source: EntityExecutionSourceByOrigin, archive: any, graph: RecycleGraph, material: PreparedEntityChange, obligation: PreparedRecycleArchiveObligation, tx: DbService, activeRestoreSourceId: string | null): Promise<unknown> {
    const canonical = derivePreparedRecyclePackets(obligation,material.packets.filter(packet=>obligation.packetKeys.includes(packet.key)),this.secrets);
    const args = [source.clusterId, source.workspaceId, source.id];
    const plans = await tx.query<any>("SELECT * FROM entity_change_recycle_packets WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 AND entry_id=$4 AND direction='delete' ORDER BY packet_order", [...args, archive.entry_id]);
    const attempts = await tx.query<any>('SELECT * FROM entity_change_packet_attempts WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 ORDER BY packet_order', args);
    const events = await tx.query<any>('SELECT * FROM entity_change_packet_events WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 ORDER BY attempt_id,event_kind', args);
    const receipts = await tx.query<any>("SELECT * FROM entity_change_recycle_receipts WHERE cluster_id=$1 AND workspace_id=$2 AND source_id=$3 AND entry_id=$4 AND direction='delete' ORDER BY packet_key", [...args, archive.entry_id]);
    const mutations = await tx.query<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND workspace_id=$2 AND entity_change_source_id=$3 ORDER BY id', args);
    if (plans.length !== archive.packet_count || receipts.length !== plans.length || plans.length !== graph.nodes.filter(node => node.affected).length || new Set(plans.map(plan => plan.node_key)).size !== plans.length
      || new Set(attempts.map(attempt => attempt.packet_key)).size !== attempts.length || events.length > attempts.length * 2 || mutations.some(item => !['succeeded', 'failed', 'blocked'].includes(item.state))) throw invalid();
    const eventFacts = new Map<string, any>();
    for (const attempt of attempts) {
      this.sourceTuple(attempt, source, archive); this.intentTuple(attempt, source);
      const packet = material.packets.find(item => item.key === attempt.packet_key); if (!packet || !uuid.test(attempt.id)) throw invalid();
      this.same(this.packet(attempt, packet.dependencies), normalizedEntityChangePackets({ packets: [packet] } as any, this.secrets)[0]);
      const observed = events.filter(item => item.attempt_id === attempt.id), outcome = observed.find(item => item.event_kind === 'outcome');
      if (!outcome || outcome.outcome === 'sent-unknown' || new Set(observed.map(item => item.event_kind)).size !== observed.length) throw invalid();
      for (const item of observed) eventFacts.set(`${attempt.id}:${item.event_kind}`, this.event(item, attempt, source, archive));
      if (['succeeded', 'native-rejected'].includes(outcome.outcome) && !observed.some(item => item.event_kind === 'send-intent') || ['rejected-before-send', 'failed-known-not-sent'].includes(outcome.outcome) && observed.some(item => item.event_kind === 'send-intent')) throw invalid();
    }
    if (events.some(item => !attempts.some(attempt => attempt.id === item.attempt_id)) || mutations.some(item => !attempts.some(attempt => attempt.id === item.entity_change_attempt_id))) throw invalid();
    const exactReceipts: unknown[] = [];
    for (const plan of plans) {
      this.sourceTuple(plan, source, archive); this.intentTuple(plan, source);
      const packet = material.packets.find(item => item.key === plan.packet_key), node = graph.nodes.find(item => item.key === plan.node_key);
      if (!packet || !node?.affected || plan.direction !== 'delete' || plan.entry_id !== input.entryId || packet.method !== 'DELETE' || packet.mutationAction !== 'delete' || packet.permissionAction !== 'delete'
        || packet.canonicalPath !== node.path || packet.nativeType !== node.type || packet.nativeId !== node.id || packet.originalNativeId !== undefined || packet.body !== undefined
        || (packet.parentId ?? null) !== (this.parent(graph, node) ?? null) || (packet.credentialKind ?? null) !== (credential(node.type) ? node.type : null)) throw invalid();
      // The fixed writer's exact graph/packet parser also authenticates the
      // historical DELETE prefix. A certificate before contains only the
      // SNIs remaining after its explicit child deletes, while the archive
      // and baseline retain the complete original object.
      const expected=canonical.find(item=>item.node.key===node.key&&item.packet.key===packet.key);
      if(!expected)throw invalid();this.same(expected.packet,packet);
      this.same(this.packet(plan, packet.dependencies), normalizedEntityChangePackets({ packets: [packet] } as any, this.secrets)[0]);
      for (const dependency of node.dependencies) {
        const parent = plans.find(item => item.node_key === dependency); if (parent && parent.packet_order <= plan.packet_order) throw invalid();
      }
      const attempt = attempts.find(item => item.packet_key === packet.key), receipt = receipts.find(item => item.packet_key === packet.key);
      if (!attempt || !receipt) throw invalid(); this.sourceTuple(receipt, source, archive);
      if (receipt.attempt_id !== attempt.id || receipt.entry_id !== input.entryId || receipt.node_key !== node.key || receipt.native_id !== node.id || receipt.direction !== 'delete' || !uuid.test(receipt.operation_id)) throw invalid();
      const send = eventFacts.get(`${attempt.id}:send-intent`), outcome = eventFacts.get(`${attempt.id}:outcome`), mutation = mutations.find(item => item.id === receipt.operation_id);
      if (!send || !outcome || outcome.outcome !== 'succeeded' || outcome.nativeStatus !== 204 || !mutation) throw invalid();
      this.scope(mutation, input);
      if (mutation.state !== 'succeeded' || mutation.remote_started !== true || mutation.remote_completed !== true || mutation.actor_id !== source.executionActorId || mutation.workflow_id !== source.workflowId
        || mutation.entity_change_source_id !== source.id || mutation.entity_change_baseline_id !== archive.baseline_id || mutation.entity_change_attempt_id !== attempt.id || mutation.entity_change_packet_key !== packet.key
        || mutation.entity_id !== node.id || mutation.entity_type !== (credential(node.type) ? 'credentials' : node.type) || mutation.parent_id !== (packet.parentId ?? null) || mutation.credential_kind !== (packet.credentialKind ?? null)
        || mutation.action !== 'delete' || mutation.idempotency_key !== receipt.operation_key || receipt.operation_key !== `entity-${source.workflowExecutionId}-${packet.order}`
        || mutation.workflow_execution_id != null || mutation.workflow_step_id != null || mutation.workflow_plan_revision != null || mutation.workflow_plan_hash != null
        || mutation.configuration_job_id != null || mutation.configuration_execution_id != null || mutation.configuration_step_id != null || !mutation.result_secret || !mutation.before_secret || !mutation.payload_secret) throw invalid();
      const result = this.secrets.decrypt(mutation.result_secret, `mutation:${mutation.id}:result`), before = this.secrets.decrypt(mutation.before_secret, `mutation:${mutation.id}:before`), payload = this.secrets.decrypt(mutation.payload_secret, `mutation:${mutation.id}:payload`);
      if (result !== null || payload !== null || this.secrets.fingerprint(before) !== packet.beforeHmac || this.secrets.fingerprint(payload) !== packet.bodyHmac
        || receipt.result_hmac !== this.secrets.fingerprint(null) || outcome.evidence?.responseHmac !== receipt.result_hmac || outcome.evidence?.operationId !== mutation.id || outcome.evidence?.mutationState !== 'succeeded'
        || outcome.evidence?.remoteCompleted !== true) throw invalid();
      // The original known-native outcome is immutable, including an initial
      // metadataComplete:false. Actual receipt-only repair is proved by the
      // SQL023 receipt plus complete node projection, never by editing that
      // old fact, inventing a result or re-sending DELETE.
      this.same(send.evidence, { operationId: mutation.id, method: 'DELETE', pathHmac: this.secrets.fingerprint(packet.canonicalPath), bodyHmac: packet.bodyHmac, beforeHmac: packet.beforeHmac });
      let verification: EntityRecycleDeleteVerification;
      if (node.type === 'targets') {
        const observed = outcome.evidence?.deleteVerification;
        if (!observed || observed.status !== 'target-poststate' || observed.kind !== 'target-poststate'
          || observed.nativeId !== node.id || typeof observed.address !== 'string' || !observed.address
          || !['weight-zero-overlay', 'native-pruned'].includes(observed.historyRetention)
          || !hex.test(observed.observationHmac) || !hex.test(observed.archiveGraphHmac)) throw invalid();
        verification = { version: 1, clusterId: input.clusterId, workspaceId: input.workspaceId, entryId: input.entryId,
          nodeKey: node.key, packetKey: packet.key, attemptId: attempt.id, operationId: mutation.id,
          canonicalPath: packet.canonicalPath, nativeId: node.id, status: 'target-poststate', kind: 'target-poststate',
          historyRetention: observed.historyRetention, observationHmac: observed.observationHmac,
          archiveGraphHmac: observed.archiveGraphHmac, address: observed.address };
      } else {
        verification = { version: 1, clusterId: input.clusterId, workspaceId: input.workspaceId, entryId: input.entryId,
          nodeKey: node.key, packetKey: packet.key, attemptId: attempt.id, operationId: mutation.id,
          canonicalPath: packet.canonicalPath, nativeId: node.id, status: 404 };
      }
      this.same(outcome.evidence.deleteVerification, verification);
      if (receipt.verification_hmac !== this.secrets.fingerprint(verification) || Date.parse(outcome.observedAt) < Date.parse(send.observedAt)) throw invalid();
      exactReceipts.push({ nodeKey: node.key, packetKey: packet.key, attemptId: attempt.id, operationId: mutation.id, resultHmac: receipt.result_hmac, verificationHmac: receipt.verification_hmac, outcomeHmac: this.secrets.fingerprint(outcome) });
    }
    await this.assertClosedEntrySources(input, tx, activeRestoreSourceId);
    return exactReceipts;
  }

  private async assertClosedEntrySources(input: EntityRecycleOriginReadInput, tx: DbService, activeRestoreSourceId: string | null): Promise<void> {
    // All same-entry source chains must already be terminal. Missing tuple
    // parents and any unknown outcome remain unconditional blockers, including
    // the actual current source admitted only for its private unsent phase.
    const pending = await tx.one<any>(`SELECT EXISTS(SELECT 1 FROM entity_change_recycle_packets p
      LEFT JOIN entity_change_execution_sources s ON s.id=p.source_id LEFT JOIN workflow_executions x ON x.id=s.workflow_execution_id
      LEFT JOIN entity_change_packet_attempts a ON a.source_id=p.source_id AND a.packet_key=p.packet_key
      LEFT JOIN entity_change_packet_events o ON o.attempt_id=a.id AND o.event_kind='outcome'
      WHERE p.entry_id=$1 AND (s.id IS NULL OR x.id IS NULL OR o.outcome='sent-unknown'
        OR ($2::uuid IS NULL OR p.source_id<>$2::uuid) AND (x.state NOT IN('succeeded','partial','failed') OR a.id IS NOT NULL AND o.id IS NULL)))
      OR EXISTS(SELECT 1 FROM mutation_operations m JOIN entity_change_recycle_packets p ON p.source_id=m.entity_change_source_id AND p.packet_key=m.entity_change_packet_key
       WHERE p.entry_id=$1 AND (m.state='uncertain'
         OR ($2::uuid IS NULL OR m.entity_change_source_id<>$2::uuid) AND m.state IN('pending','running'))) AS unresolved`, [input.entryId, activeRestoreSourceId]);
    if (!pending || pending.unresolved !== false) throw invalid();
  }

  async readClosedOrigin(input: EntityRecycleOriginReadInput): Promise<EntityRecycleClosedOrigin> {
    const policy = this.policy();
    if (!input || [input.clusterId, input.workspaceId, input.entryId, input.actor?.user?.id].some(id => !uuid.test(id)) || input.actor.workspaceId !== input.workspaceId || !['read', 'write', 'approve'].includes(input.subjectAction)) throw new ForbiddenException({ code: 'RECYCLE_ENTITY_ORIGIN_SCOPE_MISMATCH' });
    const requestHmac = this.secrets.fingerprint(input), frozen = immutableJson(input);
    return this.db.transaction(async tx => {
      // Connection transaction settings are the only SQL exec in this reader;
      // the database rejects every business write in this consistent snapshot.
      await tx.exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
      await policy.assertCurrentScope(frozen, tx);
      // A self-revalidation exception comes only from the installed Root
      // private-registry callback. Caller input contains no Source UUID. The
      // original DELETE still passes its whole closed chain, and every other
      // source or any unknown fact remains an unconditional blocker.
      const activeRestoreSourceId = await this.activeRestore(frozen, tx);
      const migration = await tx.one<any>('SELECT name,checksum FROM schema_migrations WHERE name=$1', [ENTITY_RECYCLE_FACTS_MIGRATION.name]);
      if (!migration || migration.checksum !== ENTITY_RECYCLE_FACTS_MIGRATION.checksum) throw new ServiceUnavailableException({ code: 'RECYCLE_ENTITY_ORIGIN_SCHEMA_UNAVAILABLE' });
      try {
        const args = [frozen.clusterId, frozen.workspaceId, frozen.entryId];
        const entry = await tx.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', args);
        const archive = await tx.one<any>('SELECT * FROM entity_change_recycle_archives WHERE cluster_id=$1 AND workspace_id=$2 AND entry_id=$3', args);
        this.scope(entry, frozen); this.scope(archive, frozen);
        if (entry.mutation_id !== null || !entry.payload_secret || !['archived', 'deleted', 'partially_deleted', 'partially_restored'].includes(entry.state)
          && !(entry.state === 'restoring' && activeRestoreSourceId !== null) || Date.parse(iso(entry.expires_at)) <= Date.now()) throw invalid();
        const sourceRow = await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [frozen.clusterId, frozen.workspaceId, archive.source_id]);
        const source = decodeEntityExecutionSource(sourceRow);
        if (source.sessionId === null || source.clusterId !== frozen.clusterId || source.workspaceId !== frozen.workspaceId || archive.workflow_execution_id !== source.workflowExecutionId || archive.actor_id !== source.executionActorId || entry.actor_id !== source.executionActorId) throw invalid();
        if (activeRestoreSourceId === source.id) throw invalid();
        const { workflow, execution } = await this.storedWorkflow(source, tx), material = await this.storedIntent(source, tx);
        const graph = this.secrets.decrypt<RecycleGraph>(entry.payload_secret, `recycle:${frozen.entryId}`), manifest = this.manifest(graph), root = graph.nodes.find(node => node.key === graph.rootKey)!;
        if (graph.purpose !== 'recycle' || archive.root_key !== graph.rootKey || root.id !== entry.original_id || root.type !== (entry.root_type === 'credentials' ? entry.credential_kind : entry.root_type)
          || entry.node_count !== graph.nodes.length || archive.node_count !== graph.nodes.length || archive.graph_hmac !== this.secrets.fingerprint(graph) || archive.payload_hmac !== archive.graph_hmac || archive.node_manifest_hmac !== this.secrets.fingerprint(manifest)) throw invalid();
        this.same(archive.node_manifest, manifest);
        const nodes = await tx.query<any>('SELECT * FROM entity_change_recycle_nodes WHERE entry_id=$1 ORDER BY node_order', [entry.id]);
        nodes.forEach(row => this.scope(row, frozen));
        this.same(nodes.map(row => ({ key: row.node_key, order: row.node_order, nativeType: row.native_type, nativeId: row.native_id, parentId: row.parent_id, credentialKind: row.credential_kind,
          affected: row.affected, dependencies: row.dependencies, pathHmac: row.path_hmac, dataHmac: row.data_hmac, restoreHmac: row.restore_hmac })), manifest);
        const legacy = await tx.query<any>('SELECT entry_id,node_key,entity_type,original_id,affected,dependencies,delete_state,restore_state,restored_id FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key', [entry.id]);
        if (legacy.length !== manifest.length || new Set(legacy.map(row => row.node_key)).size !== legacy.length) throw invalid();
        for (const node of graph.nodes) {
          const row = legacy.find(item => item.node_key === node.key);
          if (!row || row.entity_type !== node.type || row.original_id !== node.id || row.affected !== node.affected || node.affected && (row.delete_state !== 'deleted' || !['pending', 'restored', 'failed'].includes(row.restore_state))
            || !node.affected && (row.delete_state !== 'reference' || row.restore_state !== 'reference' || row.restored_id !== null) || row.restore_state === 'restored' && row.restored_id !== node.id) throw invalid();
          this.same(row.dependencies, node.dependencies);
        }
        const obligations = material.metadataObligations.filter(item => item.kind === 'recycle-archive' && item.graphHmac === archive.graph_hmac);
        if (obligations.length !== 1 || obligations[0].kind !== 'recycle-archive') throw invalid();
        const obligation = obligations[0]; this.same(obligation.graph, graph);
        await this.storedBaseline(source, archive, graph, tx);
        const facts = await this.actualPackets(frozen, source, archive, graph, material, obligation, tx, activeRestoreSourceId);
        if (obligation.packetKeys.length !== archive.packet_count || new Set(obligation.packetKeys).size !== obligation.packetKeys.length) throw invalid();
        this.same(obligation.packetKeys, (facts as any[]).map(item => item.packetKey));
        const closedRestoreCoverage = entry.state === 'partially_restored' || entry.state === 'restoring'
          ? await this.closedRestoreCoverage(frozen, archive, graph, entry, legacy, tx, activeRestoreSourceId) : undefined;
        // Historical read closure only: the archived DELETE material does not
        // supply a new restore/write grant. Recycle preparation separately
        // checks the new operation's write, parent, schema and managed scope.
        await policy.assertFrozenSubject({ request: frozen, material, sourceId: source.id, workflowId: source.workflowId, packetKeys: obligation.packetKeys, graphHmac: archive.graph_hmac }, tx);
        // Root's final current principal/grant fence must read genuinely
        // fresh authority outside this repeatable-read evidence snapshot.
        await policy.assertCurrentScope(frozen, tx);
        if (await this.activeRestore(frozen, tx) !== activeRestoreSourceId) throw new ConflictException({ code: 'RECYCLE_ENTITY_ORIGIN_REVALIDATION_CHANGED' });
        if (this.secrets.fingerprint(input) !== requestHmac) throw invalid();
        return immutableJson({ kind: 'entity-change', id: source.id, workspace_id: frozen.workspaceId, workflow_id: source.workflowId, workflow_state: workflow.state,
          execution_state: execution.state, state: 'succeeded', unresolved_steps: false, graphHmac: archive.graph_hmac, nodeManifestHmac: archive.node_manifest_hmac,
          sourceFactsHmac: this.secrets.fingerprint({ source, baselineId: archive.baseline_id, pinId: archive.pin_id, graphHmac: archive.graph_hmac, nodeManifestHmac: archive.node_manifest_hmac, facts }),
          ...(closedRestoreCoverage ? { closedRestoreCoverage } : {}) });
      } catch (error) {
        if (error instanceof HttpException) throw error;
        // Ciphertext, SQL details, original configuration and credential data
        // cannot appear in a failed origin response or fallback branch.
        throw invalid();
      }
    });
  }
}
