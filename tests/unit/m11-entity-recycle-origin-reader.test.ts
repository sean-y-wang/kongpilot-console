import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { EntityRecycleOriginReaderService, ENTITY_RECYCLE_FACTS_MIGRATION } from '../../apps/console-api/src/modules/recycle-bin/entity-recycle-origin-reader.service';
import { RecycleService } from '../../apps/console-api/src/modules/recycle-bin/recycle.service';
import { preparedRecycleNodeManifest } from '../../apps/console-api/src/modules/recycle-bin/entity-prepared-recycle-writer.service';
import { normalizedEntityChangePackets, entityChangeIntentAad } from '../../apps/console-api/src/modules/workflows/entity-change-workflow';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { decodeEntityExecutionSource } from '../../apps/console-api/src/modules/workflows/entity-change-source-codec';
import type { RecycleGraph } from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
import type { EntityChangePacket, PreparedEntityChange } from '../../apps/console-api/src/modules/entities/entity-change.types';
import type { EntityRecycleOriginReaderDelegate } from '../../apps/console-api/src/modules/recycle-bin/entity-recycle-origin-reader.types';

/** Real authenticated SecretService envelopes and production pure codecs;
 * database rows and current-scope delegates are controlled fixtures. These
 * tests establish neither actual SQL triggers nor runtime/native authority. */
function fixture(basic = false, expired = false, shape:'service'|'pki'|'upstream'|'target'|'ca'='service', sealedPacketChange?:(packets:EntityChangePacket[])=>void) {
  const secrets = new SecretService(), cid = randomUUID(), wid = randomUUID(), entryId = randomUUID(), intentId = randomUUID(), sourceId = randomUUID();
  const workflowId = randomUUID(), executionId = randomUUID(), baselineId = randomUUID(), pinId = randomUUID(), actorId = randomUUID(), consumerId = randomUUID();
  const rootId = basic ? consumerId : randomUUID(), childId = randomUUID(), definitionId = randomUUID();
  const actor: any = { user: { id: actorId, username: 'current-reviewer', superAdmin: false }, workspaceId: wid };
  const issue = new Date(Date.now() - (expired ? 360000 : 30000)).toISOString(), expire = new Date(Date.parse(issue) + 300000).toISOString(), observed = new Date(Date.parse(issue) + 10000).toISOString();
  const plain = 'unit-basic-trusted-plaintext', salted = createHash('sha1').update(plain + consumerId).digest('hex');
  const root: any = basic ? { id: consumerId, username: 'private-consumer-config', tags: ['kos-ws-unit'] } : { id: rootId, name: 'private-service-name', host: 'private-upstream.example', tags: ['kos-ws-unit'] };
  const child: any = basic ? { id: childId, username: 'unit-basic', password: salted, consumer: { id: consumerId } } : { id: childId, name: 'private-route-config', service: { id: rootId }, paths: ['/private'] };
  const type = basic ? 'consumers' : 'services', childType = basic ? 'basic-auth' : 'routes';
  const graph: RecycleGraph = { complete: true, purpose: 'recycle', rootKey: `${type}:${rootId}`, capturedAt: observed, nodes: [
    { key: `${type}:${rootId}`, type, id: rootId, path: `/${type}/${rootId}`, data: root, affected: true, dependencies: [], restorable: true, restoreData: root },
    { key: `${childType}:${childId}`, type: childType, id: childId, path: basic ? `/consumers/${consumerId}/basic-auth/${childId}` : `/routes/${childId}`,
      data: child, affected: true, dependencies: [`${type}:${rootId}`], restorable: true, restoreData: basic ? { ...child, password: plain } : child },
  ] };
  if(shape!=='service'){
    const rootType=shape==='pki'?'certificates':shape==='ca'?'ca_certificates':'upstreams';
    const rootData:any=shape==='pki'?{id:rootId,cert:'unit-public-certificate',key:'unit-private-key',snis:['unit.example']}:shape==='ca'?{id:rootId,cert:'unit-public-ca'}:{id:rootId,name:'unit-upstream'};
    const nestedType=shape==='pki'?'snis':'targets',nestedData:any=shape==='pki'?{id:childId,name:'unit.example',certificate:{id:rootId}}:{id:childId,target:'unit.internal:8080',weight:100,upstream:{id:rootId}};
    graph.nodes=[{key:`${rootType}:${rootId}`,type:rootType,id:rootId,path:`/${rootType}/${rootId}`,data:rootData,restoreData:rootData,affected:shape!=='target',dependencies:[],restorable:true}];
    if(shape!=='ca')graph.nodes.push({key:shape==='pki'?`snis:${childId}`:`targets:${rootId}:${childId}`,type:nestedType,id:childId,path:shape==='pki'?`/snis/${childId}`:`/upstreams/${rootId}/targets/${childId}`,data:nestedData,restoreData:nestedData,affected:true,dependencies:[graph.nodes[0].key],restorable:true});
    graph.rootKey=shape==='target'?graph.nodes[1].key:graph.nodes[0].key;
  }
  const packetByNode = new Map<string, string>();
  const packets = [...graph.nodes].reverse().filter(node=>node.affected).map((node, index): EntityChangePacket => {
    const before=structuredClone(node.data);
    if(node.type==='certificates'){const removed=new Set(graph.nodes.filter(child=>child.affected&&child.type==='snis'&&child.dependencies.includes(node.key)&&packetByNode.has(child.key)).map(child=>child.data.name));before.snis=before.snis.filter((name:string)=>!removed.has(name));}
    const packet: EntityChangePacket = { key: `packet-${index + 1}`, order: index + 1, dependencies: graph.nodes.filter(item => item.dependencies.includes(node.key)).flatMap(item => packetByNode.get(item.key) ?? []),
      method: 'DELETE', canonicalPath: node.path, nativeType: node.type, nativeId: node.id, ...(basic && node.type === 'basic-auth' ? { parentId: consumerId, credentialKind: 'basic-auth' as const } : {}),...(node.type==='targets'?{parentId:rootId}:{}),
      before, permissionAction: 'delete', mutationAction: 'delete', beforeHmac: secrets.fingerprint(before), bodyHmac: secrets.fingerprint(null) };
    packetByNode.set(node.key, packet.key); return packet;
  });
  sealedPacketChange?.(packets);
  const initial: any = { version: 1, clusterId: cid, workspaceId: wid, requesterId: actorId, permissionVersion: 'historical-permission-only', scope: {},
    request: { kind: 'recycle', action: 'delete', entityType: type, entityId: rootId, confirmed: true, confirm_name: root.name ?? root.username },
    packets, prerequisites: [], schemas: [], metadataObligations: [{ kind: 'recycle-archive', graph, graphHmac: secrets.fingerprint(graph), packetKeys: packets.map(packet => packet.key) }],
    recovery: { state: 'baseline-required', blockerCodes: [], objects: [] }, impact: {} };
  const material = { ...initial, changeDigest: secrets.fingerprint(initial) } as PreparedEntityChange;
  const normalized = normalizedEntityChangePackets(material, secrets), packetManifestHmac = secrets.fingerprint(normalized);
  const envelope: any = { version: 1, intentId, revision: 1, clusterId: cid, workspaceId: wid, requesterId: actorId, credentialEpoch: '1', issuedAt: issue,
    expiresAt: new Date(Date.parse(issue) + 86400000).toISOString(), ttlHours: 24, executionMode: 'approval', definition: { id: definitionId, version: 1, policyHash: secrets.fingerprint('policy') },
    prepared: material, review: { version: 1 }, packetManifestHmac };
  const materialHmac = secrets.fingerprint(envelope), payload = { intentId, intentRevision: 1, materialHmac, changeDigest: material.changeDigest, packetManifestHmac };
  const plan: any = { version: 1, kind: 'native-change', clusterId: cid, workspaceId: wid, workflowId, planRevision: 1, subject: { type: 'entity_change_intents', id: intentId },
    requester: { type: 'console', id: actorId }, definition: envelope.definition, executionMode: 'approval', approvalRequired: true, issuedAt: issue, expiresAt: envelope.expiresAt,
    scope: {}, prerequisites: [], steps: [{ id: randomUUID(), key: 'entity', order: 1, kind: 'metadata', handler: 'entity.change', entityType: 'entity_change_intents', entityId: intentId,
      permissionAction: 'write', dependencies: [], nativeRequests: [], metadata: payload, metadataRevision: 1, metadataPayloadHmac: secrets.fingerprint(payload), metadataBeforeHmac: secrets.fingerprint(payload) }] };
  const planHash = secrets.fingerprint(plan), common = { cluster_id: cid, workspace_id: wid }, intentTuple = { ...common, intent_id: intentId, intent_revision: 1, material_hmac: materialHmac,
    change_digest: material.changeDigest, packet_manifest_hmac: packetManifestHmac };
  const sourceRow: any = { ...intentTuple, id: sourceId, workflow_id: workflowId, workflow_plan_revision: 1, workflow_plan_hash: planHash, workflow_execution_id: executionId,
    execution_actor_id: actorId, credential_epoch: '1', permission_version_hmac: secrets.fingerprint('old-permission'), session_id: randomUUID(), issued_at: issue, expires_at: expire };
  const source = decodeEntityExecutionSource(sourceRow);
  const objects: any[] = graph.nodes.map(node => ({ key: node.key, nativeType: node.type, nativeId: node.id, ...(basic && node.type === 'basic-auth' ? { parentId: consumerId, credentialKind: 'basic-auth' } : {}),...(node.type==='targets'?{parentId:rootId}:{}),
    affected: node.affected, present: true, dependencies: node.dependencies, before: node.data, ...(node.affected?{restorePayload:node.restoreData}:{}), schemaMaterial: { schema: 'unit-real-shape' }, trustedProvenance: { kind: 'native-observed' }, recovery: node.affected?'complete':'reference' }));
  const objectManifest = objects.map(item => ({ key: item.key, nativeType: item.nativeType, nativeId: item.nativeId, parentId: item.parentId ?? null, credentialKind: item.credentialKind ?? null,
    affected: item.affected, present: true, dependencies: item.dependencies, beforeHmac: secrets.fingerprint(item.before), restoreHmac: item.restorePayload===undefined?null:secrets.fingerprint(item.restorePayload), schemaHmac: secrets.fingerprint(item.schemaMaterial), provenanceHmac: secrets.fingerprint(item.trustedProvenance), recovery: item.recovery }));
  const capture: any = { version: 1, observedFrom: observed, observedUntil: observed, graphs: [{ ...graph, purpose: 'baseline' }], objects, blockerCodes: [], nonreversiblePacketKeys: [] };
  const baselineEnvelope = { version: 1, baselineId, source, capture }, baselineHmac = secrets.fingerprint(baselineEnvelope), objectHmac = secrets.fingerprint(objectManifest);
  const binding = { ...common, source_id: sourceId, baseline_id: baselineId, pin_id: pinId, workflow_execution_id: executionId };
  const manifest = preparedRecycleNodeManifest(graph, secrets);
  const row: Record<string, any> = {
    migration: { ...ENTITY_RECYCLE_FACTS_MIGRATION },
    entry: { ...common, id: entryId, actor_id: actorId, mutation_id: null, state: 'deleted', payload_secret: secrets.encrypt(graph, `recycle:${entryId}`), root_type: graph.nodes.find(node=>node.key===graph.rootKey)!.type, original_id: graph.nodes.find(node=>node.key===graph.rootKey)!.id,
      root_name: root.name ?? root.username, node_count: graph.nodes.length, expires_at: '2099-01-01T00:00:00.000Z' },
    archive: { ...binding, entry_id: entryId, actor_id: actorId, root_key: graph.rootKey, graph_hmac: secrets.fingerprint(graph), payload_hmac: secrets.fingerprint(graph), node_manifest_hmac: secrets.fingerprint(manifest), node_manifest: manifest, node_count: manifest.length, packet_count: packets.length },
    source: sourceRow,
    workflow: { ...common, id: workflowId, state: 'succeeded', kind: 'native-change', subject_type: 'entity_change_intents', subject_id: intentId, requester_type: 'console', requester_user_id: actorId, plan_revision: 1, plan_hash: planHash },
    execution: { ...common, id: executionId, state: 'succeeded', workflow_id: workflowId, execution_actor_id: actorId, plan_revision: 1, plan_hash: planHash },
    workflowVersion: { ...common, workflow_id: workflowId, plan_revision: 1, plan_hash: planHash, payload_secret: secrets.encrypt(plan, planAad(cid, wid, workflowId, 1)) },
    submission: { ...intentTuple, workflow_id: workflowId, actor_id: actorId, workflow_plan_revision: 1, workflow_plan_hash: planHash },
    intent: { ...common, id: intentId, requester_id: actorId, credential_epoch: '1', issued_at: envelope.issuedAt, expires_at: envelope.expiresAt },
    version: { ...intentTuple, requester_id: actorId, credential_epoch: '1', issued_at: envelope.issuedAt, expires_at: envelope.expiresAt, execution_mode: 'approval', definition_id: definitionId, definition_version: 1,
      policy_hash: envelope.definition.policyHash, envelope_ciphertext: secrets.encrypt(envelope, entityChangeIntentAad(cid, wid, intentId, 1)), packet_manifest: normalized, packet_count: packets.length, safe_review: envelope.review },
    baseline: { ...intentTuple, id: baselineId, source_id: sourceId, workflow_id: workflowId, workflow_plan_revision: 1, workflow_plan_hash: planHash, workflow_execution_id: executionId, execution_actor_id: actorId,
      credential_epoch: '1', readiness: 'ready', baseline_hmac: baselineHmac, capture_hmac: secrets.fingerprint(capture), object_manifest_hmac: objectHmac, object_manifest: objectManifest,
      object_count: objects.length, graph_count: 1, observed_from: observed, observed_until: observed, material_ciphertext: secrets.encrypt(baselineEnvelope, `entity-change-baseline:${cid}:${wid}:${baselineId}:material`) },
    pin: { ...binding, id: pinId, baseline_hmac: baselineHmac, object_manifest_hmac: objectHmac, pin_version: 1, protected_until: '2099-01-01T00:00:00.000Z' },
    unresolved: { unresolved: false }, pending: { unresolved: false }, component: null,
  };
  // Controlled pending-ledger adapter applies the actual prepared SQL's
  // source parameter. This is not a Root current-execution proof issuer.
  const pendingSources: Array<{ sourceId: string; state: string; attemptPending?: boolean; outcome?: string }> = [];
  const pendingMutations: Array<{ sourceId: string; state: string }> = [];
  const packetRow = (packet: any) => ({ ...intentTuple, packet_key: packet.key, packet_order: packet.order, dependencies: packet.dependencies, method: packet.method, path_hmac: packet.pathHmac,
    native_type: packet.nativeType, native_id: packet.nativeId, parent_id: packet.parentId, credential_kind: packet.credentialKind, original_native_id: packet.originalNativeId, permission_action: packet.permissionAction,
    mutation_action: packet.mutationAction, body_hmac: packet.bodyHmac, before_hmac: packet.beforeHmac });
  const lists: Record<string, any[]> = {
    packets: normalized.map(packetRow), nodes: manifest.map(item => ({ ...common, entry_id: entryId, node_key: item.key, node_order: item.order, native_type: item.nativeType, native_id: item.nativeId,
      parent_id: item.parentId, credential_kind: item.credentialKind, affected: item.affected, dependencies: item.dependencies, path_hmac: item.pathHmac, data_hmac: item.dataHmac, restore_hmac: item.restoreHmac })),
    legacy: graph.nodes.map(node => ({ node_key: node.key, entity_type: node.type, original_id: node.id, affected: node.affected, dependencies: node.dependencies, delete_state: node.affected?'deleted':'reference', restore_state: node.affected?'pending':'reference', restored_id: null })).sort((a, b) => a.node_key.localeCompare(b.node_key)),
    objects: objectManifest.map((item, index) => ({ ...common, baseline_id: baselineId, object_manifest_hmac: objectHmac, object_order: index + 1, object_key: item.key, native_type: item.nativeType, native_id: item.nativeId, parent_id: item.parentId,
      credential_kind: item.credentialKind, affected: item.affected, present: item.present, dependencies: item.dependencies, before_hmac: item.beforeHmac, restore_hmac: item.restoreHmac, schema_hmac: item.schemaHmac, provenance_hmac: item.provenanceHmac, recovery: item.recovery })),
    archivePackets: [], attempts: [], events: [], receipts: [], mutations: [], origins: [],
  };
  const facts = new Map<string, any>();
  packets.forEach((packet, index) => {
    const attemptId = randomUUID(), operationId = randomUUID(), node = graph.nodes.find(item => item.id === packet.nativeId)!;
    const base = { ...binding, ...packetRow(normalized[index]) }; delete base.dependencies;
    lists.archivePackets.push({ ...base, entry_id: entryId, node_key: node.key, direction: 'delete' });
    lists.attempts.push({ ...base, id: attemptId, created_at: observed });
    const verification = packet.nativeType==='targets'
      ? { version: 1, clusterId: cid, workspaceId: wid, entryId, nodeKey: node.key, packetKey: packet.key, attemptId, operationId, canonicalPath: packet.canonicalPath, nativeId: node.id, status: 'target-poststate' as const, kind: 'target-poststate' as const, historyRetention: 'weight-zero-overlay' as const, observationHmac: secrets.fingerprint({target:packet.nativeId,mode:'weight-zero'}), archiveGraphHmac: secrets.fingerprint(graph), address: typeof node.data?.target==='string'?node.data.target:'unit.internal:8080' }
      : { version: 1, clusterId: cid, workspaceId: wid, entryId, nodeKey: node.key, packetKey: packet.key, attemptId, operationId, canonicalPath: packet.canonicalPath, nativeId: node.id, status: 404 as const };
    lists.receipts.push({ ...binding, attempt_id: attemptId, operation_id: operationId, entry_id: entryId, node_key: node.key, packet_key: packet.key, native_id: node.id,
      direction: 'delete', operation_key: `entity-${executionId}-${packet.order}`, result_hmac: secrets.fingerprint(null), verification_hmac: secrets.fingerprint(verification) });
    lists.mutations.push({ ...common, id: operationId, actor_id: actorId, workflow_id: workflowId, state: 'succeeded', remote_started: true, remote_completed: true, entity_change_source_id: sourceId,
      entity_change_baseline_id: baselineId, entity_change_attempt_id: attemptId, entity_change_packet_key: packet.key, entity_id: node.id, entity_type: packet.credentialKind ? 'credentials' : packet.nativeType,
      parent_id: packet.parentId ?? null, credential_kind: packet.credentialKind ?? null, action: 'delete', idempotency_key: `entity-${executionId}-${packet.order}`,
      result_secret: secrets.encrypt(null, `mutation:${operationId}:result`), before_secret: secrets.encrypt(packet.before, `mutation:${operationId}:before`), payload_secret: secrets.encrypt(null, `mutation:${operationId}:payload`) });
    for (const kind of ['send-intent', 'outcome']) {
      const fact: any = { version: 1, kind, binding: { sourceId, baselineId, pinId, packetKey: packet.key, attemptId }, observedAt: observed,
        evidence: kind === 'send-intent' ? { operationId, method: 'DELETE', pathHmac: secrets.fingerprint(packet.canonicalPath), bodyHmac: packet.bodyHmac, beforeHmac: packet.beforeHmac }
          : { operationId, mutationState: 'succeeded', remoteCompleted: true, responseHmac: secrets.fingerprint(null), metadataComplete: true, deleteVerification: verification },
        ...(kind === 'outcome' ? { outcome: 'succeeded', nativeStatus: 204 } : {}) };
      facts.set(`${attemptId}:${kind}`, fact);
      lists.events.push({ ...binding, id: randomUUID(), attempt_id: attemptId, event_kind: kind, outcome: fact.outcome ?? null, native_status: fact.nativeStatus ?? null, error_code: null,
        observed_at: observed, created_at: new Date().toISOString(), fact_hmac: secrets.fingerprint(fact), fact_ciphertext: secrets.encrypt(fact, `entity-change-packet-fact:${cid}:${wid}:${attemptId}:${kind}`) });
    }
  });
  const mutateFact = (index: number, fn: (fact: any) => void) => {
    const event = lists.events[index], fact = facts.get(`${event.attempt_id}:${event.event_kind}`); fn(fact);
    Object.assign(event, { observed_at: fact.observedAt, outcome: fact.outcome ?? null, native_status: fact.nativeStatus ?? null, error_code: fact.errorCode ?? null, fact_hmac: secrets.fingerprint(fact), fact_ciphertext: secrets.encrypt(fact, `entity-change-packet-fact:${cid}:${wid}:${event.attempt_id}:${event.event_kind}`) });
  };
  const chooseOne = (sql: string, values: any[]) => {
    if (sql.includes('FROM schema_migrations')) return row.migration;
    if (sql.includes('FROM configuration_recycle_components')) return row.component;
    if (sql.startsWith('SELECT EXISTS(SELECT 1 FROM workflow_steps')) return row.unresolved;
    if (sql.startsWith('SELECT EXISTS(SELECT 1 FROM entity_change_recycle_packets')) {
      expect(values[0]).toBe(entryId); expect(sql).toContain('p.source_id<>$2::uuid'); expect(sql).toContain('m.entity_change_source_id<>$2::uuid');
      const exception = values[1];
      return { unresolved: row.pending.unresolved || pendingSources.some(item => item.outcome === 'sent-unknown'
        || item.sourceId !== exception && (!['succeeded', 'partial', 'failed'].includes(item.state) || item.attemptPending))
        || pendingMutations.some(item => item.state === 'uncertain' || item.sourceId !== exception && ['pending', 'running'].includes(item.state)) };
    }
    for (const [table, name] of [['recycle_entries', 'entry'], ['entity_change_recycle_archives', 'archive'], ['entity_change_execution_sources', 'source'], ['workflow_executions', 'execution'], ['workflow_versions', 'workflowVersion'],
      ['entity_change_submissions', 'submission'], ['workflows', 'workflow'], ['entity_change_intent_versions', 'version'], ['entity_change_intents', 'intent'], ['entity_change_baselines', 'baseline'], ['entity_change_baseline_pins', 'pin']]) {
      if (sql.includes(`FROM ${table} WHERE`)) return row[name];
    }
    throw new Error(`Unexpected readonly fixture query: ${sql}`);
  };
  const chooseList = (sql: string) => {
    if (sql.startsWith("SELECT 'mutation'")) return lists.origins;
    for (const [table, name] of [['entity_change_intent_packets', 'packets'], ['entity_change_recycle_nodes', 'nodes'], ['recycle_nodes', 'legacy'], ['entity_change_baseline_objects', 'objects'], ['entity_change_recycle_packets', 'archivePackets'],
      ['entity_change_packet_attempts', 'attempts'], ['entity_change_packet_events', 'events'], ['entity_change_recycle_receipts', 'receipts'], ['mutation_operations', 'mutations']]) {
      if (sql.includes(`FROM ${table} WHERE`)) return lists[name];
    }
    throw new Error(`Unexpected readonly fixture list: ${sql}`);
  };
  const db: any = { one: vi.fn(async (sql: string, values: any[] = []) => structuredClone(chooseOne(sql, values))), query: vi.fn(async (sql: string) => structuredClone(chooseList(sql))),
    exec: vi.fn(async (sql: string) => { if (sql !== 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY') throw new Error('Business write forbidden'); return 0; }), transaction: vi.fn(async (callback: any) => callback(db)) };
  const reader = new EntityRecycleOriginReaderService(db, secrets), delegate: EntityRecycleOriginReaderDelegate = { assertCurrentScope: vi.fn(async () => undefined), assertFrozenSubject: vi.fn(async () => undefined) };
  const input = { clusterId: cid, workspaceId: wid, entryId, actor, subjectAction: 'write' as const };
  return { reader, secrets, row, lists, delegate, input, material, graph, envelope, capture, source, cid, wid, entryId, sourceId, baselineId, workflowId, pinId, mutateFact, db, pendingSources, pendingMutations,
    install: () => reader.installFixedDelegate(delegate), noBusinessWrites: () => expect(db.exec.mock.calls.every(([sql]: any[]) => sql === 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')).toBe(true) };
}

describe('M11 Source-bound Recycle closed origin, source-only domain fixtures', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'de'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());
  it('requires a single fixed bootstrap delegate and formally applied exact SQL023 bytes', async () => {
    const f = fixture(); await expect(f.reader.readClosedOrigin(f.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_POLICY_UNAVAILABLE' } });
    expect(f.db.transaction).not.toHaveBeenCalled(); f.install(); expect(() => f.reader.installFixedDelegate(f.delegate)).toThrow();
    f.row.migration = null; await expect(f.reader.readClosedOrigin(f.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_SCHEMA_UNAVAILABLE' } });
    expect(f.delegate.assertFrozenSubject).not.toHaveBeenCalled(); f.noBusinessWrites();
    const sql = readFileSync('apps/console-api/src/infrastructure/migrations/023_m11_entity_recycle_facts.sql', 'utf8');
    expect(createHash('sha256').update(sql).digest('hex')).toBe(ENTITY_RECYCLE_FACTS_MIGRATION.checksum);
    expect(sql).toContain('entity_change_recycle_nodes root_node'); expect(sql).not.toContain('entity_change_recycle_nodes n JOIN recycle_entries');
    expect(sql).toContain("NEW.direction='delete' AND o.native_status<>204");
  });
  it('reads full Service→Route graph, immutable baseline and actual null/204/404 receipts without exposing any original config', async () => {
    const f = fixture(); f.install(); const result = await f.reader.readClosedOrigin(f.input);
    expect(result).toMatchObject({ kind: 'entity-change', id: f.sourceId, workspace_id: f.wid, workflow_id: f.workflowId, state: 'succeeded', unresolved_steps: false });
    expect(f.delegate.assertCurrentScope).toHaveBeenCalledTimes(2); expect(f.delegate.assertFrozenSubject).toHaveBeenCalledOnce();
    expect(f.delegate.assertFrozenSubject.mock.calls[0][0].material).toEqual(f.material);
    expect(JSON.stringify(result)).not.toMatch(/private-service|private-route|upstream|password|payload|session/);
    f.noBusinessWrites();
    // Original SID expiry and original permission version are historical
    // bytes; the fixed current caller checks remain independent of them.
    expect(result.sourceFactsHmac).toMatch(/^[a-f\d]{64}$/);
  });
  for(const shape of ['pki','upstream','target','ca'] as const)it(`authenticates the complete closed ${shape} deletion through the original canonical parser`,async()=>{
    const f=fixture(false,false,shape);f.install();const result=await f.reader.readClosedOrigin(f.input);
    expect(result).toMatchObject({kind:'entity-change',id:f.sourceId,state:'succeeded',unresolved_steps:false});
    expect(f.delegate.assertFrozenSubject).toHaveBeenCalledOnce();f.noBusinessWrites();
    if(shape==='pki'){const p=f.material.packets.find(p=>p.nativeType==='certificates')!;expect(p.before).toMatchObject({snis:[]});expect(f.graph.nodes[0].data.snis).toEqual(['unit.example']);}
    expect(JSON.stringify(result)).not.toMatch(/unit-private-key|unit-public-certificate|unit.internal/);
  });
  it('rejects a self-consistently sealed historical certificate packet with an impossible SNI prefix',async()=>{
    const f=fixture(false,false,'pki',packets=>{const p=packets.find(p=>p.nativeType==='certificates')!;(p.before as any).snis=['unit.example'];p.beforeHmac=new SecretService().fingerprint(p.before);});f.install();
    await expect(f.reader.readClosedOrigin(f.input)).rejects.toBeDefined();expect(f.delegate.assertFrozenSubject).not.toHaveBeenCalled();f.noBusinessWrites();
  });
  it('keeps unknown and missing actual Target deletion receipts closed even with a valid whole graph',async()=>{
    for(const change of [(f:ReturnType<typeof fixture>)=>f.lists.receipts.pop(),(f:ReturnType<typeof fixture>)=>f.mutateFact(1,fact=>fact.outcome='sent-unknown')]){
      const f=fixture(false,false,'target');f.install();change(f);await expect(f.reader.readClosedOrigin(f.input)).rejects.toBeDefined();f.noBusinessWrites();
    }
  });
  it('requires complete normalized nodes, legacy graph and baseline recovery facts', async () => {
    for (const breakFact of [
      (f: ReturnType<typeof fixture>) => f.lists.nodes.pop(),
      (f: ReturnType<typeof fixture>) => f.lists.legacy[0].dependencies.push('not-real'),
      (f: ReturnType<typeof fixture>) => f.lists.objects[0].restore_hmac = 'a'.repeat(64),
      (f: ReturnType<typeof fixture>) => f.row.pin.source_id = randomUUID(),
      (f: ReturnType<typeof fixture>) => f.row.archive.node_manifest_hmac = 'a'.repeat(64),
    ]) {
      const f = fixture(); f.install(); breakFact(f); await expect(f.reader.readClosedOrigin(f.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } });
      expect(f.delegate.assertFrozenSubject).not.toHaveBeenCalled(); f.noBusinessWrites();
    }
  });
  it('rejects original or same-entry unresolved executions and every missing/unknown actual attempt outcome', async () => {
    for (const breakFact of [
      (f: ReturnType<typeof fixture>) => f.row.execution.state = 'executing',
      (f: ReturnType<typeof fixture>) => f.row.unresolved.unresolved = true,
      (f: ReturnType<typeof fixture>) => f.row.pending.unresolved = true,
      (f: ReturnType<typeof fixture>) => f.lists.events.splice(1, 1),
      (f: ReturnType<typeof fixture>) => f.mutateFact(1, fact => { fact.outcome = 'sent-unknown'; delete fact.nativeStatus; }),
      (f: ReturnType<typeof fixture>) => f.lists.mutations[0].state = 'uncertain',
    ]) {
      const f = fixture(); f.install(); breakFact(f); await expect(f.reader.readClosedOrigin(f.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } }); f.noBusinessWrites();
    }
  });
  it('validates authenticated DELETE204/raw null and the precise durable GET404 tuple, never a standalone hex proof', async () => {
    for (const breakFact of [
      (f: ReturnType<typeof fixture>) => f.mutateFact(1, fact => { fact.nativeStatus = 200; }),
      (f: ReturnType<typeof fixture>) => f.mutateFact(1, fact => { delete fact.evidence.deleteVerification; }),
      (f: ReturnType<typeof fixture>) => f.mutateFact(1, fact => { fact.evidence.deleteVerification.nativeId = randomUUID(); }),
      (f: ReturnType<typeof fixture>) => f.lists.receipts[0].verification_hmac = 'b'.repeat(64),
      (f: ReturnType<typeof fixture>) => { const operation = f.lists.mutations[0]; operation.result_secret = f.secrets.encrypt({ id: operation.entity_id }, `mutation:${operation.id}:result`); },
      (f: ReturnType<typeof fixture>) => f.lists.mutations[0].workspace_id = randomUUID(),
      (f: ReturnType<typeof fixture>) => f.lists.mutations[0].idempotency_key = 'replacement-key',
      (f: ReturnType<typeof fixture>) => f.row.execution.execution_actor_id = randomUUID(),
      (f: ReturnType<typeof fixture>) => f.row.workflow.requester_user_id = randomUUID(),
    ]) {
      const f = fixture(); f.install(); breakFact(f); await expect(f.reader.readClosedOrigin(f.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } }); f.noBusinessWrites();
    }
  });
  it('preserves an actual post-expiry known outcome and immutable metadata:false after genuine receipt-only completion', async () => {
    const f = fixture(false, true); f.install();
    // The original source is expired; this records historical actual results
    // only. It grants no SID renewal, retry, new key or native execution.
    f.mutateFact(1, fact => { fact.observedAt = new Date(Date.now() - 10000).toISOString(); fact.evidence.metadataComplete = false; });
    expect(Date.parse(f.row.source.expires_at)).toBeLessThan(Date.now());
    const result = await f.reader.readClosedOrigin(f.input); expect(result.state).toBe('succeeded'); f.noBusinessWrites();
    f.lists.receipts.pop(); await expect(f.reader.readClosedOrigin(f.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } });
    const sendAfterExpiry = fixture(false, true); sendAfterExpiry.install();
    sendAfterExpiry.mutateFact(0, fact => { fact.observedAt = new Date(Date.now() - 10000).toISOString(); });
    await expect(sendAfterExpiry.reader.readClosedOrigin(sendAfterExpiry.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } });
  });
  it('verifies Basic plaintext against the real Kong1.5 SHA1(plaintext + ConsumerUUID), not storedhash-as-plaintext', async () => {
    const f = fixture(true); f.install(); const receipt = await f.reader.readClosedOrigin(f.input); expect(receipt.state).toBe('succeeded');
    expect(JSON.stringify(receipt)).not.toContain('unit-basic-trusted-plaintext');
    const bad = fixture(true); bad.install(); const graph = structuredClone(bad.graph), basic = graph.nodes.find(node => node.type === 'basic-auth')!;
    basic.restoreData!.password = basic.data.password; bad.row.entry.payload_secret = bad.secrets.encrypt(graph, `recycle:${bad.entryId}`);
    bad.row.archive.graph_hmac = bad.secrets.fingerprint(graph); bad.row.archive.payload_hmac = bad.row.archive.graph_hmac;
    await expect(bad.reader.readClosedOrigin(bad.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } }); bad.noBusinessWrites();
  });
  it('keeps genuine current-scope and frozen subject denials effective before safe projection', async () => {
    const f = fixture(); f.install(); vi.mocked(f.delegate.assertCurrentScope).mockRejectedValueOnce(new ForbiddenException({ code: 'TEST_CURRENT_SCOPE_DENIED' }));
    await expect(f.reader.readClosedOrigin(f.input)).rejects.toMatchObject({ response: { code: 'TEST_CURRENT_SCOPE_DENIED' } }); expect(f.db.one).not.toHaveBeenCalled();
    const g = fixture(); g.install(); vi.mocked(g.delegate.assertFrozenSubject).mockRejectedValueOnce(new ForbiddenException({ code: 'TEST_FROZEN_SUBJECT_DENIED' }));
    await expect(g.reader.readClosedOrigin(g.input)).rejects.toMatchObject({ response: { code: 'TEST_FROZEN_SUBJECT_DENIED' } });
    const h = fixture(); h.install(); vi.mocked(h.delegate.assertCurrentScope).mockResolvedValueOnce(undefined).mockRejectedValueOnce(new ForbiddenException({ code: 'TEST_CURRENT_SCOPE_CHANGED' }));
    await expect(h.reader.readClosedOrigin(h.input)).rejects.toMatchObject({ response: { code: 'TEST_CURRENT_SCOPE_CHANGED' } });
    g.noBusinessWrites(); h.noBusinessWrites();
  });
  it('preserves old non-NULL mutation/config origins and only resolves new NULL entries through the installed fixed lookup', async () => {
    const f = fixture(), service = new RecycleService(f.db, f.secrets, ...Array(9).fill(undefined) as [any, any, any, any, any, any, any, any, any]);
    const scope: any = { workspaceId: f.wid }, lookup = { readClosedOrigin: vi.fn(async () => ({ kind: 'entity-change', id: f.sourceId, workspace_id: f.wid, workflow_id: f.workflowId, workflow_state: 'succeeded', execution_state: 'succeeded', state: 'succeeded', unresolved_steps: false, graphHmac: f.row.archive.graph_hmac, nodeManifestHmac: f.row.archive.node_manifest_hmac, sourceFactsHmac: 'a'.repeat(64) })) };
    await expect((service as any).preparedEntry(f.cid, f.entryId, scope, f.input.actor, 'write')).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_POLICY_UNAVAILABLE' } });
    service.installEntityOriginLookup(lookup as any); expect(() => service.installEntityOriginLookup(lookup as any)).toThrow();
    const loaded = await (service as any).preparedEntry(f.cid, f.entryId, scope, f.input.actor, 'write'); expect(loaded.graph).toEqual(f.graph); expect(lookup.readClosedOrigin).toHaveBeenCalledOnce();
    lookup.readClosedOrigin.mockClear(); f.row.entry.mutation_id = randomUUID();
    f.lists.origins = [{ kind: 'mutation', id: f.row.entry.mutation_id, workspace_id: f.wid, state: 'succeeded', workflow_id: null, unresolved_steps: false }];
    await (service as any).preparedEntry(f.cid, f.entryId, scope, f.input.actor, 'write'); expect(lookup.readClosedOrigin).not.toHaveBeenCalled();
    f.row.entry.mutation_id = null; f.lists.origins = [{ kind: 'configuration', id: randomUUID(), workspace_id: f.wid, state: 'succeeded', workflow_id: f.workflowId, workflow_state: 'succeeded', execution_state: 'succeeded', unresolved_steps: false }];
    await (service as any).preparedEntry(f.cid, f.entryId, scope, f.input.actor, 'approve'); expect(lookup.readClosedOrigin).not.toHaveBeenCalled();
    expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('permits only the optional fixed same-entry unsent restore source exception while retaining the full original delete proof', async () => {
    const f = fixture(), activeSource = randomUUID();
    f.delegate.activeRestoreRevalidation = vi.fn(async () => activeSource); f.install();
    f.pendingSources.push({ sourceId: activeSource, state: 'executing', attemptPending: true }); f.pendingMutations.push({ sourceId: activeSource, state: 'running' });
    const result = await f.reader.readClosedOrigin(f.input); expect(result.id).toBe(f.sourceId); expect(result.state).toBe('succeeded');
    expect(f.delegate.activeRestoreRevalidation).toHaveBeenCalledTimes(2);
    const checked = f.db.one.mock.calls.find(([sql]: any[]) => sql.startsWith('SELECT EXISTS(SELECT 1 FROM entity_change_recycle_packets'));
    expect(checked[1]).toEqual([f.entryId, activeSource]);
    f.mutateFact(1, fact => { fact.outcome = 'sent-unknown'; delete fact.nativeStatus; });
    await expect(f.reader.readClosedOrigin(f.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } }); f.noBusinessWrites();
  });
  it('keeps missing callbacks, caller supplied Source UUIDs and copied Source DTOs closed', async () => {
    const absent = fixture(), sourceId = randomUUID(); absent.install(); absent.pendingSources.push({ sourceId, state: 'executing' });
    await expect(absent.reader.readClosedOrigin({ ...absent.input, activeRestoreSourceId: sourceId } as any)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } });
    const query = absent.db.one.mock.calls.find(([sql]: any[]) => sql.startsWith('SELECT EXISTS(SELECT 1 FROM entity_change_recycle_packets')); expect(query[1]).toEqual([absent.entryId, null]);
    const copied = fixture(); copied.delegate.activeRestoreRevalidation = vi.fn(async () => ({ sourceId, approved: true })) as any; copied.install();
    await expect(copied.reader.readClosedOrigin(copied.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } });
    expect(copied.delegate.assertFrozenSubject).not.toHaveBeenCalled(); absent.noBusinessWrites(); copied.noBusinessWrites();
  });
  it('never excludes a foreign active source, unknown same-entry outcomes, or uncertain mutations', async () => {
    for (const fact of ['foreign-execution', 'foreign-unknown', 'self-unknown', 'foreign-mutation', 'self-uncertain']) {
      const f = fixture(), activeSource = randomUUID(), foreign = randomUUID(); f.delegate.activeRestoreRevalidation = vi.fn(async () => activeSource); f.install();
      f.pendingSources.push({ sourceId: activeSource, state: 'executing', attemptPending: true });
      if (fact === 'foreign-execution') f.pendingSources.push({ sourceId: foreign, state: 'executing' });
      if (fact === 'foreign-unknown' || fact === 'self-unknown') f.pendingSources.push({ sourceId: fact === 'self-unknown' ? activeSource : foreign, state: 'failed', outcome: 'sent-unknown' });
      if (fact === 'foreign-mutation' || fact === 'self-uncertain') f.pendingMutations.push({ sourceId: fact === 'self-uncertain' ? activeSource : foreign, state: fact === 'self-uncertain' ? 'uncertain' : 'running' });
      await expect(f.reader.readClosedOrigin(f.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } }); f.noBusinessWrites();
    }
  });
  it('requires the original private callback to remain live and unchanged through the final fresh scope fence', async () => {
    for (const changed of [null, randomUUID(), 'revoked']) {
      const f = fixture(), activeSource = randomUUID(), callback = vi.fn(async () => activeSource); f.delegate.activeRestoreRevalidation = callback; f.install();
      f.pendingSources.push({ sourceId: activeSource, state: 'executing' });
      if (changed === 'revoked') callback.mockResolvedValueOnce(activeSource).mockRejectedValueOnce(new ForbiddenException({ code: 'TEST_CURRENT_REVALIDATION_REVOKED' }));
      else callback.mockResolvedValueOnce(activeSource).mockResolvedValueOnce(changed as any);
      await expect(f.reader.readClosedOrigin(f.input)).rejects.toMatchObject({ response: { code: changed === 'revoked' ? 'TEST_CURRENT_REVALIDATION_REVOKED' : 'RECYCLE_ENTITY_ORIGIN_REVALIDATION_CHANGED' } });
      expect(f.delegate.assertCurrentScope).toHaveBeenCalledTimes(2); f.noBusinessWrites();
    }
  });
  it('does not waive the original delete source or turn a generic restoring entry into a readable origin', async () => {
    const original = fixture(); original.delegate.activeRestoreRevalidation = vi.fn(async () => original.sourceId); original.install();
    await expect(original.reader.readClosedOrigin(original.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } });
    const restoring = fixture(); restoring.delegate.activeRestoreRevalidation = vi.fn(async () => randomUUID()); restoring.install(); restoring.row.entry.state = 'restoring';
    await expect(restoring.reader.readClosedOrigin(restoring.input)).rejects.toMatchObject({ response: { code: 'RECYCLE_ENTITY_ORIGIN_INVALID' } }); original.noBusinessWrites(); restoring.noBusinessWrites();
  });
});
