import { ConflictException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type { DbService } from '../../infrastructure/db.service';
import type { SecretService } from '../../infrastructure/secret.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { entityReferenceId } from '../entities/entity-reference';
import type { EntityActor } from '../entities/entities.types';
import type { GraphNode, RecycleGraph } from '../recycle-bin/graph-capturer.service';
import type { EntityChangeBaselineEnvelope } from './entity-change-execution-facts.types';
import { entityBaselineAad, entityPacketFactAad, type EntityChangeExecutionFactsService } from './entity-change-execution-facts.service';
import type { EntityChangeExecutionSource, EntityChangeIntentEnvelope } from './entity-change-intent.types';
import { decodeEntityExecutionSource } from './entity-change-source-codec';
import { assertEntityChangeWorkflowPlan, entityChangeIntentAad, normalizedEntityChangePackets } from './entity-change-workflow';
import type { WorkflowPlanV1 } from './workflow.types';

export interface TerminalRecycleMetadataInput {
  readonly tx: DbService; readonly secrets: SecretService; readonly facts: EntityChangeExecutionFactsService;
  readonly plan: WorkflowPlanV1; readonly envelope: EntityChangeIntentEnvelope;
  readonly source: EntityChangeExecutionSource; readonly actor: EntityActor;
}
export interface TerminalRecycleMetadataCertificate {
  readonly entryId: string; readonly failedNodeKey: string; readonly failedOperationId: string;
  readonly failedAttemptId: string; readonly outcomeEventId: string; readonly outcomeFactHmac: string;
  readonly graphHmac: string; readonly proofHmac: string; readonly alreadyClosed: boolean;
  readonly nativeSuccesses: 5; readonly knownNotSent: 1; readonly unattempted: 1;
}

const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const hex = /^[a-f\d]{64}$/;
const packetKey = /^[a-zA-Z\d_.:-]{1,160}$/;
const types = ['consumers', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'] as const;
const invalid = () => new ConflictException({ code: 'ENTITY_CHANGE_TERMINAL_METADATA_PROOF_INVALID' });
const unsupported = () => new ConflictException({ code: 'ENTITY_CHANGE_TERMINAL_METADATA_SHAPE_UNSUPPORTED' });
const record = (v: any): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);
const iso = (v: any) => { const date = new Date(v); if (!Number.isFinite(date.getTime())) throw invalid(); return date.toISOString(); };
const packetTuple = (row: any) => ({ key: row.packet_key, order: row.packet_order, dependencies: row.dependencies,
  method: row.method, pathHmac: row.path_hmac, nativeType: row.native_type, nativeId: row.native_id,
  parentId: row.parent_id, credentialKind: row.credential_kind, originalNativeId: row.original_native_id,
  mutationAction: row.mutation_action, permissionAction: row.permission_action, bodyHmac: row.body_hmac, beforeHmac: row.before_hmac });
// SQL021 attempts and SQL023 recycle packets have no DAG column. SQL020 and
// the authenticated immutable intent are the sole packet dependency sources.
const withoutDependencies = <T extends { dependencies?: unknown }>(value: T) => { const { dependencies: _dependencies, ...tuple } = value; return tuple; };

/** Read-only certification of one fixed 5-success / 1-known-no-send / 1-unattempted
 * Consumer restoration. The caller owns current HTTP authority, original key,
 * terminal workflow checks and all locks. This returns historical evidence,
 * never a source, handle, transport permission, native result or repair permit.
 * It neither appends facts nor changes metadata; original outcomes stay intact. */
export async function certifyTerminalRecycleMetadata(input: TerminalRecycleMetadataInput): Promise<Readonly<TerminalRecycleMetadataCertificate>> {
  try { return await certify(input); }
  catch (error) {
    if (error instanceof ConflictException && (error.getResponse() as any)?.code === 'ENTITY_CHANGE_TERMINAL_METADATA_SHAPE_UNSUPPORTED') throw error;
    throw invalid(); // AEAD, SQL and validation details cannot enter a public error.
  }
}

async function certify(input: TerminalRecycleMetadataInput): Promise<Readonly<TerminalRecycleMetadataCertificate>> {
  const { tx, secrets, facts } = input;
  const initialHmac = secrets.fingerprint({ plan: input.plan, envelope: input.envelope, source: input.source, actor: input.actor });
  const { plan, envelope, source, actor } = immutableJson({ plan: input.plan, envelope: input.envelope, source: input.source, actor: input.actor });
  const same = (a: unknown, b: unknown) => { if (secrets.fingerprint(a) !== secrets.fingerprint(b)) throw invalid(); };
  const scope = (row: any) => { if (!row || row.cluster_id !== source.clusterId || row.workspace_id !== source.workspaceId) throw invalid(); };
  const intentTuple = (row: any) => {
    scope(row);
    if (row.intent_id !== source.intentId || row.intent_revision !== source.intentRevision || row.material_hmac !== source.materialHmac
      || row.change_digest !== source.changeDigest || row.packet_manifest_hmac !== source.packetManifestHmac) throw invalid();
  };
  if (!source || 'origin' in source || !uuid.test(source.sessionId) || envelope.version !== 1 || actor.user?.id !== source.executionActorId
    || actor.workspaceId !== source.workspaceId || plan.clusterId !== source.clusterId || plan.workspaceId !== source.workspaceId
    || plan.workflowId !== source.workflowId || plan.planRevision !== source.workflowPlanRevision || plan.requester.id !== source.executionActorId || !hex.test(plan.scope.transportScope)
    || secrets.fingerprint(plan) !== source.workflowPlanHash || envelope.clusterId !== source.clusterId || envelope.workspaceId !== source.workspaceId
    || envelope.intentId !== source.intentId || envelope.revision !== source.intentRevision || envelope.requesterId !== source.executionActorId
    || envelope.credentialEpoch !== source.credentialEpoch || secrets.fingerprint(envelope) !== source.materialHmac) throw invalid();
  const step = assertEntityChangeWorkflowPlan(plan);
  same(step.metadata, { intentId: source.intentId, intentRevision: source.intentRevision, materialHmac: source.materialHmac,
    changeDigest: source.changeDigest, packetManifestHmac: source.packetManifestHmac });
  const sourceRow = await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE id=$1', [source.id]);
  same(decodeEntityExecutionSource(sourceRow), source);
  const material = envelope.prepared, { changeDigest, ...original } = material;
  if (material.version !== 1 || material.clusterId !== source.clusterId || material.workspaceId !== source.workspaceId
    || material.requesterId !== source.executionActorId || material.scope.transportScope !== plan.scope.transportScope || changeDigest !== source.changeDigest || secrets.fingerprint(original) !== changeDigest
    || material.request.kind !== 'recycle' || material.request.action !== 'restore' || !Array.isArray(material.metadataObligations)) throw unsupported();
  const restoreObligations = material.metadataObligations.filter(item => item.kind === 'recycle-restore');
  if (restoreObligations.length !== 1 || material.metadataObligations.length !== 8) throw unsupported();
  const obligation = restoreObligations[0], entryId = obligation.entryId, graph = obligation.graph;
  if (!uuid.test(entryId) || material.request.entryId !== entryId || material.request.confirmed !== true || !record(graph)
    || graph.complete !== true || graph.purpose !== 'recycle' || !Array.isArray(graph.nodes) || graph.nodes.length !== 7
    || graph.targetHistory !== undefined || Buffer.byteLength(JSON.stringify(graph)) > 16 * 1024 * 1024) throw unsupported();
  const seal = obligation.sealedEntry;
  if (!seal || seal.clusterId !== source.clusterId || seal.workspaceId !== source.workspaceId || seal.entryId !== entryId
    || seal.state !== 'deleted' || !hex.test(seal.nodeManifestHmac) || obligation.graphHmac !== secrets.fingerprint(graph)
    || seal.payloadHmac !== obligation.graphHmac || seal.restoreMaterialHmac !== secrets.fingerprint(graph.nodes.filter(node => node.affected).map(node => ({ key: node.key, restoreData: node.restoreData })))) throw invalid();
  const ordered: GraphNode[] = [], seen = new Set<string>(), visiting = new Set<string>();
  const byKey = new Map(graph.nodes.map(node => [node.key, node]));
  if (byKey.size !== 7) throw unsupported();
  const visit = (key: string) => {
    if (seen.has(key)) return;
    const node = byKey.get(key);
    if (!node || visiting.has(key) || !Array.isArray(node.dependencies) || new Set(node.dependencies).size !== node.dependencies.length) throw invalid();
    visiting.add(key); node.dependencies.forEach(visit); visiting.delete(key); seen.add(key); ordered.push(node);
  };
  graph.nodes.forEach(node => visit(node.key));
  const consumer = ordered[0], restore = (node: GraphNode): Record<string, any> => {
    if (node.restorable !== true || !record(node.restoreData) || node.restoreData.id !== node.id || typeof node.data.ttl === 'number' && node.data.ttl > 0) throw invalid();
    const { created_at: _created, updated_at: _updated, ttl: _ttl, ...body } = node.restoreData;
    return body;
  };
  const manifest = ordered.map((node, index) => {
    const nested = index > 0, parentId = nested ? consumer.id : null;
    if (node.type !== types[index]) throw unsupported();
    if (!types.includes(node.type as any) || !uuid.test(node.id) || !packetKey.test(node.key) || node.affected !== true || !record(node.data)
      || node.data.id !== node.id || ![`${node.type}:${node.id}`, ...(nested ? [`${node.type}:${consumer.id}:${node.id}`] : [])].includes(node.key) || nested && entityReferenceId(node.data.consumer) !== consumer.id
      || node.path !== (nested ? `/consumers/${consumer.id}/${node.type}/${node.id}` : `/consumers/${node.id}`)) throw invalid();
    same(node.dependencies, nested ? [consumer.key] : []);
    const body = restore(node);
    if (nested && entityReferenceId(body.consumer) !== consumer.id) throw invalid();
    if (node.type === 'basic-auth' && (typeof body.password !== 'string' || typeof node.data.password !== 'string'
      || !/^[a-f\d]{40}$/i.test(node.data.password) || createHash('sha1').update(body.password + consumer.id).digest('hex') !== node.data.password.toLowerCase())) throw invalid();
    return { key: node.key, order: index + 1, nativeType: node.type, nativeId: node.id, parentId, credentialKind: nested ? node.type : null,
      affected: true, dependencies: node.dependencies, pathHmac: secrets.fingerprint(node.path), dataHmac: secrets.fingerprint(node.data), restoreHmac: secrets.fingerprint(body) };
  });
  if (graph.rootKey !== consumer.key || material.packets.length !== 7 || new Set(ordered.map(node => node.id)).size !== 7) throw unsupported();
  const packets = material.packets;
  packets.forEach((p, i) => {
    const node = ordered[i];
    if (p.order !== i + 1 || p.nativeType !== types[i] || p.method !== 'POST' || p.mutationAction !== 'restore') throw unsupported();
    if (!packetKey.test(p.key) || p.order !== i + 1 || p.method !== 'POST' || p.nativeType !== types[i] || p.nativeId !== node.id
      || p.mutationAction !== 'restore' || p.permissionAction !== 'write' || p.originalNativeId !== undefined || p.before !== null
      || (p.parentId ?? null) !== manifest[i].parentId || (p.credentialKind ?? null) !== manifest[i].credentialKind
      || p.canonicalPath !== (i ? `/consumers/${consumer.id}/${p.nativeType}` : '/consumers')
      || p.bodyHmac !== secrets.fingerprint(p.body ?? null) || p.beforeHmac !== secrets.fingerprint(null)) throw invalid();
    same(p.body, restore(node)); same(p.dependencies, i ? [packets[0].key] : []);
  });
  if (new Set(packets.map(p => p.key)).size !== 7) throw invalid();
  same(obligation.packetKeys, packets.map(p => p.key));
  const sideObligations = material.metadataObligations.filter(item => item.kind !== 'recycle-restore');
  for (const [i, packet] of packets.entries()) {
    const matches = sideObligations.filter(item => 'packetKey' in item && item.packetKey === packet.key);
    if (matches.length !== 1) throw invalid();
    same(matches[0], i ? { kind: 'credential-remember', packetKey: packet.key, consumerId: consumer.id, credentialKind: packet.nativeType, rawInput: packet.body }
      : { kind: 'entity-index', packetKey: packet.key, entityType: 'consumers' });
  }
  const packetManifest = normalizedEntityChangePackets(material, secrets);
  if (secrets.fingerprint(packetManifest) !== source.packetManifestHmac || envelope.packetManifestHmac !== source.packetManifestHmac) throw invalid();
  const version = await tx.one<any>('SELECT * FROM entity_change_intent_versions WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4', [source.clusterId, source.workspaceId, source.intentId, source.intentRevision]);
  intentTuple(version);
  same(secrets.decrypt(version.envelope_ciphertext, entityChangeIntentAad(source.clusterId, source.workspaceId, source.intentId, source.intentRevision)), envelope);
  if (version.packet_count !== 7) throw invalid(); same(version.packet_manifest, packetManifest);
  const storedPackets = await tx.query<any>('SELECT * FROM entity_change_intent_packets WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4 ORDER BY packet_order', [source.clusterId, source.workspaceId, source.intentId, source.intentRevision]);
  storedPackets.forEach(intentTuple); same(storedPackets.map(packetTuple), packetManifest);
  const baselines = await tx.query<any>('SELECT * FROM entity_change_baselines WHERE source_id=$1', [source.id]);
  if (baselines.length !== 1) throw invalid(); const baseline = baselines[0]; intentTuple(baseline);
  const history: any = await facts.historicalProjection(source.clusterId, source.workspaceId, baseline.id, actor, tx);
  const b: EntityChangeBaselineEnvelope = secrets.decrypt(baseline.material_ciphertext, entityBaselineAad(source.clusterId, source.workspaceId, baseline.id));
  same(b.source, source);
  if (b.version !== 1 || b.baselineId !== baseline.id || secrets.fingerprint(b) !== baseline.baseline_hmac || history.baseline.baselineId !== baseline.id
    || history.baseline.sourceId !== source.id || b.capture.objects.length !== 7 || b.capture.graphs.length !== 0) throw invalid();
  for (const [i, node] of ordered.entries()) {
    const matches = b.capture.objects.filter(object => object.nativeType === node.type && object.nativeId === node.id
      && (object.parentId ?? null) === manifest[i].parentId && (object.credentialKind ?? null) === manifest[i].credentialKind);
    if (matches.length !== 1) throw invalid(); const object = matches[0];
    const expectedBaselineKey = i ? `${node.type}:${consumer.id}:${node.id}` : `${node.type}:${node.id}`;
    if (!object || object.key !== expectedBaselineKey || object.nativeType !== node.type || object.nativeId !== node.id || !object.affected || object.present
      || object.before !== null || object.recovery !== 'absent' || object.restorePayload !== undefined
      || (object.parentId ?? null) !== manifest[i].parentId || (object.credentialKind ?? null) !== manifest[i].credentialKind) throw invalid();
    same(object.dependencies, node.dependencies);
  }
  const pinId = history.baseline.pinId;
  const executionTuple = (row: any) => {
    scope(row);
    if (row.source_id !== source.id || row.baseline_id !== baseline.id || row.pin_id !== pinId || row.workflow_execution_id !== source.workflowExecutionId) throw invalid();
  };
  const entry = await tx.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3', [source.clusterId, source.workspaceId, entryId]);
  scope(entry);
  if (entry.id !== entryId || entry.mutation_id !== null || entry.root_type !== 'consumers' || entry.original_id !== consumer.id || entry.parent_id !== null
    || entry.credential_kind !== null || entry.node_count !== 7 || entry.restored_at !== null || entry.purged_at !== null || iso(entry.expires_at) !== seal.expiresAt) throw invalid();
  same(secrets.decrypt(entry.payload_secret, `recycle:${entryId}`), graph);
  const archive = await tx.one<any>('SELECT * FROM entity_change_recycle_archives WHERE entry_id=$1', [entryId]); scope(archive);
  if (archive.entry_id !== entryId || !uuid.test(archive.source_id) || archive.source_id === source.id || archive.actor_id !== entry.actor_id
    || archive.root_key !== graph.rootKey || archive.graph_hmac !== obligation.graphHmac || archive.payload_hmac !== obligation.graphHmac
    || archive.node_manifest_hmac !== secrets.fingerprint(manifest) || archive.node_count !== 7 || archive.packet_count !== 7) throw invalid();
  same(archive.node_manifest, manifest);
  const originalSource = decodeEntityExecutionSource(await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE id=$1', [archive.source_id]));
  if ('origin' in originalSource || originalSource.clusterId !== source.clusterId || originalSource.workspaceId !== source.workspaceId
    || originalSource.executionActorId !== archive.actor_id || originalSource.workflowExecutionId !== archive.workflow_execution_id
    || !uuid.test(archive.baseline_id) || !uuid.test(archive.pin_id)) throw invalid();
  const archiveNodes = await tx.query<any>('SELECT * FROM entity_change_recycle_nodes WHERE entry_id=$1 ORDER BY node_order', [entryId]);
  archiveNodes.forEach(row => { scope(row); if (row.entry_id !== entryId) throw invalid(); });
  same(archiveNodes.map(row => ({ key: row.node_key, order: row.node_order, nativeType: row.native_type, nativeId: row.native_id, parentId: row.parent_id,
    credentialKind: row.credential_kind, affected: row.affected, dependencies: row.dependencies, pathHmac: row.path_hmac, dataHmac: row.data_hmac, restoreHmac: row.restore_hmac })), manifest);
  const recyclePackets = await tx.query<any>('SELECT * FROM entity_change_recycle_packets WHERE source_id=$1 AND entry_id=$2 ORDER BY packet_order', [source.id, entryId]);
  recyclePackets.forEach((row, i) => { executionTuple(row); intentTuple(row); if (row.entry_id !== entryId || row.direction !== 'restore' || row.node_key !== ordered[i]?.key) throw invalid(); });
  same(recyclePackets.map(row => withoutDependencies(packetTuple(row))), packetManifest.map(withoutDependencies));
  const attempts = await tx.query<any>('SELECT * FROM entity_change_packet_attempts WHERE source_id=$1 ORDER BY packet_order', [source.id]);
  const events = await tx.query<any>('SELECT * FROM entity_change_packet_events WHERE source_id=$1 ORDER BY attempt_id,event_kind', [source.id]);
  const mutations = await tx.query<any>('SELECT * FROM mutation_operations WHERE entity_change_source_id=$1 ORDER BY id', [source.id]);
  const receipts = await tx.query<any>('SELECT * FROM entity_change_recycle_receipts WHERE source_id=$1 AND entry_id=$2 ORDER BY packet_key', [source.id, entryId]);
  const legacy = await tx.query<any>('SELECT * FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key', [entryId]);
  if (attempts.length !== 6 || events.length !== 12 || mutations.length !== 6 || receipts.length !== 5 || legacy.length !== 7
    || new Set(attempts.map(a => a.id)).size !== 6 || new Set(events.map(e => e.id)).size !== 12 || new Set(mutations.map(m => m.id)).size !== 6
    || new Set(receipts.map(r => r.attempt_id)).size !== 5 || new Set(legacy.map(n => n.node_key)).size !== 7) throw invalid();
  const immutableFacts: unknown[] = [], stableMutations: unknown[] = [];
  let failedEvent: any, failedMutation: any, failedAttempt: any;
  for (let i = 0; i < 6; i++) {
    const packet = packets[i], attempt = attempts[i]; executionTuple(attempt); intentTuple(attempt); same(withoutDependencies(packetTuple(attempt)), withoutDependencies(packetManifest[i]));
    if (!uuid.test(attempt.id)) throw invalid();
    const operation = mutations.filter(m => m.entity_change_attempt_id === attempt.id); if (operation.length !== 1) throw invalid(); const m = operation[0]; scope(m);
    if (!uuid.test(m.id) || m.actor_id !== source.executionActorId || m.workflow_id !== source.workflowId || m.entity_change_source_id !== source.id
      || m.entity_change_baseline_id !== baseline.id || m.entity_change_packet_key !== packet.key || m.entity_type !== (i ? 'credentials' : 'consumers')
      || m.action !== 'restore' || m.entity_id !== packet.nativeId || m.parent_id !== (packet.parentId ?? null) || m.credential_kind !== (packet.credentialKind ?? null)
      || m.idempotency_key !== `entity-${source.workflowExecutionId}-${packet.order}` || m.transport_scope !== plan.scope.transportScope
      || ['workflow_execution_id', 'workflow_plan_revision', 'workflow_plan_hash', 'workflow_step_id', 'configuration_job_id', 'configuration_execution_id', 'configuration_step_id', 'configuration_plan_revision', 'configuration_plan_hash'].some(field => m[field] != null)) throw invalid();
    same(secrets.decrypt(m.before_secret, `mutation:${m.id}:before`), null); same(secrets.decrypt(m.payload_secret, `mutation:${m.id}:payload`), packet.body);
    const pair = events.filter(e => e.attempt_id === attempt.id); if (pair.length !== 2 || new Set(pair.map(e => e.event_kind)).size !== 2) throw invalid();
    const decoded: Record<string, any> = {};
    for (const e of pair) {
      executionTuple(e);
      if (!uuid.test(e.id) || !['send-intent', 'outcome'].includes(e.event_kind)) throw invalid();
      const fact: any = secrets.decrypt(e.fact_ciphertext, entityPacketFactAad(source.clusterId, source.workspaceId, attempt.id, e.event_kind));
      if (fact.version !== 1 || fact.kind !== e.event_kind || secrets.fingerprint(fact) !== e.fact_hmac || fact.observedAt !== iso(e.observed_at)
        || Date.parse(fact.observedAt) < Date.parse(iso(attempt.created_at)) || Date.parse(fact.observedAt) > Date.parse(iso(e.created_at))) throw invalid();
      same(fact.binding, { sourceId: source.id, baselineId: baseline.id, pinId, packetKey: packet.key, attemptId: attempt.id });
      if (fact.kind === 'send-intent') {
        if (e.outcome !== null || e.native_status !== null || e.error_code !== null || Date.parse(fact.observedAt) < Date.parse(source.issuedAt) || Date.parse(fact.observedAt) > Date.parse(source.expiresAt)) throw invalid();
        same(fact.evidence, { operationId: m.id, method: 'POST', pathHmac: packetManifest[i].pathHmac, bodyHmac: packet.bodyHmac, beforeHmac: packet.beforeHmac });
      } else if (fact.outcome !== e.outcome || (fact.nativeStatus ?? null) !== e.native_status || (fact.errorCode ?? null) !== e.error_code) throw invalid();
      decoded[e.event_kind] = fact; immutableFacts.push({ id: e.id, factHmac: e.fact_hmac });
    }
    const outcome = decoded.outcome;
    if (Date.parse(outcome.observedAt) < Date.parse(decoded['send-intent'].observedAt) || !record(outcome.evidence) || typeof outcome.evidence.metadataComplete !== 'boolean') throw invalid();
    if (i < 5) {
      if (m.state !== 'succeeded' || m.remote_started !== true || m.remote_completed !== true || m.entity_id !== packet.nativeId || typeof m.result_secret !== 'string'
        || outcome.outcome !== 'succeeded' || outcome.nativeStatus !== 201 || outcome.errorCode !== undefined) throw invalid();
      const raw: any = secrets.decrypt(m.result_secret, `mutation:${m.id}:result`);
      if (!record(raw) || raw.id !== packet.nativeId || i && entityReferenceId(raw.consumer) !== consumer.id) throw invalid();
      if (packet.nativeType === 'basic-auth') {
        if (typeof raw.password !== 'string' || !/^[a-f\d]{40}$/i.test(raw.password) || typeof packet.body?.password !== 'string'
          || raw.password.toLowerCase() !== createHash('sha1').update(packet.body.password + consumer.id).digest('hex')) throw invalid();
      }
      for (const [field, value] of Object.entries(packet.body!)) {
        if (field !== 'consumer' && !(packet.nativeType === 'basic-auth' && field === 'password')) same(raw[field], value);
      }
      const resultHmac = secrets.fingerprint(raw);
      same(outcome.evidence, { operationId: m.id, mutationState: 'succeeded', remoteCompleted: true, responseHmac: resultHmac, metadataComplete: outcome.evidence.metadataComplete });
      const matches = receipts.filter(r => r.attempt_id === attempt.id); if (matches.length !== 1) throw invalid(); const receipt = matches[0]; executionTuple(receipt);
      same(receipt, { attempt_id: attempt.id, cluster_id: source.clusterId, workspace_id: source.workspaceId, source_id: source.id, baseline_id: baseline.id,
        pin_id: pinId, workflow_execution_id: source.workflowExecutionId, entry_id: entryId, node_key: ordered[i].key, packet_key: packet.key,
        operation_id: m.id, operation_key: m.idempotency_key, native_id: packet.nativeId, direction: 'restore', result_hmac: resultHmac, verification_hmac: null, created_at: receipt.created_at });
    } else {
      if (!['uncertain', 'failed'].includes(m.state) || m.remote_started !== true || m.remote_completed !== false || m.result_secret !== null
        || outcome.outcome !== 'failed-known-not-sent' || outcome.nativeStatus !== undefined || typeof outcome.errorCode !== 'string' || !/^[A-Z0-9_]{1,128}$/.test(outcome.errorCode)
        || m.error_code !== outcome.errorCode || receipts.some(r => r.attempt_id === attempt.id)) throw invalid();
      // This is the original Root no-send classification, including its actual
      // send reservation. No persisted wireSpent field is invented or inferred.
      same(outcome.evidence, { operationId: m.id, mutationState: 'uncertain', remoteCompleted: false, responseHmac: null, metadataComplete: false });
      failedEvent = pair.find(e => e.event_kind === 'outcome'); failedMutation = m; failedAttempt = attempt;
    }
    stableMutations.push({ operationId: m.id, attemptId: attempt.id, packetKey: packet.key, operationKey: m.idempotency_key,
      bodyHmac: packet.bodyHmac, beforeHmac: packet.beforeHmac, resultHmac: i < 5 ? outcome.evidence.responseHmac : null });
  }
  if (events.some(e => !attempts.some(a => a.id === e.attempt_id)) || receipts.some(r => !attempts.slice(0, 5).some(a => a.id === r.attempt_id))) throw invalid();
  const alreadyClosed = failedMutation.state === 'failed';
  if (entry.state !== (alreadyClosed ? 'partially_restored' : 'restoring')) throw invalid();
  for (const [i, node] of ordered.entries()) {
    const row = legacy.find(n => n.node_key === node.key);
    if (!row || row.entry_id !== entryId || row.entity_type !== node.type || row.original_id !== node.id || row.affected !== true || row.delete_state !== 'deleted'
      || row.restore_state !== (i < 5 ? 'restored' : i === 5 && alreadyClosed ? 'failed' : 'pending') || row.restored_id !== (i < 5 ? node.id : null)) throw invalid();
    same(row.dependencies, node.dependencies);
  }
  const foreign = await tx.one<any>(`SELECT EXISTS(SELECT 1 FROM entity_change_recycle_packets p
    LEFT JOIN entity_change_execution_sources s ON s.id=p.source_id LEFT JOIN workflow_executions x ON x.id=s.workflow_execution_id
    LEFT JOIN entity_change_packet_attempts a ON a.source_id=p.source_id AND a.packet_key=p.packet_key
    LEFT JOIN entity_change_packet_events o ON o.attempt_id=a.id AND o.event_kind='outcome'
    WHERE p.entry_id=$1 AND p.source_id<>$2 AND (s.id IS NULL OR x.id IS NULL OR x.state NOT IN('succeeded','partial','failed') OR o.outcome='sent-unknown' OR a.id IS NOT NULL AND o.id IS NULL))
    OR EXISTS(SELECT 1 FROM mutation_operations m JOIN entity_change_recycle_packets p ON p.source_id=m.entity_change_source_id AND p.packet_key=m.entity_change_packet_key
      WHERE p.entry_id=$1 AND p.source_id<>$2 AND m.state IN('pending','running','uncertain')) AS unresolved`, [entryId, source.id]);
  if (!foreign || foreign.unresolved !== false) throw invalid();
  same({ plan: input.plan, envelope: input.envelope, source: input.source, actor: input.actor }, { plan, envelope, source, actor });
  if (secrets.fingerprint({ plan: input.plan, envelope: input.envelope, source: input.source, actor: input.actor }) !== initialHmac) throw invalid();
  const proofHmac = secrets.fingerprint({ version: 1, source, baselineHmac: baseline.baseline_hmac, captureHmac: baseline.capture_hmac,
    objectManifestHmac: baseline.object_manifest_hmac, pinId, graphHmac: obligation.graphHmac, nodeManifestHmac: archive.node_manifest_hmac,
    packetManifestHmac: source.packetManifestHmac, immutableFacts: immutableFacts.sort((a: any, b: any) => a.id.localeCompare(b.id)),
    receipts: receipts.map(r => ({ attemptId: r.attempt_id, operationId: r.operation_id, resultHmac: r.result_hmac })).sort((a, b) => a.attemptId.localeCompare(b.attemptId)), stableMutations });
  return immutableJson({ entryId, failedNodeKey: ordered[5].key, failedOperationId: failedMutation.id, failedAttemptId: failedAttempt.id,
    outcomeEventId: failedEvent.id, outcomeFactHmac: failedEvent.fact_hmac, graphHmac: obligation.graphHmac, proofHmac, alreadyClosed,
    nativeSuccesses: 5 as const, knownNotSent: 1 as const, unattempted: 1 as const });
}
