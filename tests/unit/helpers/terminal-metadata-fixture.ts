import { vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { SecretService } from '../../../apps/console-api/src/infrastructure/secret.service';
import { EntityChangeExecutionFactsService, entityBaselineAad, entityPacketFactAad } from '../../../apps/console-api/src/modules/workflows/entity-change-execution-facts.service';
import { decodeEntityExecutionSource } from '../../../apps/console-api/src/modules/workflows/entity-change-source-codec';
import { entityChangeIntentAad, normalizedEntityChangePackets } from '../../../apps/console-api/src/modules/workflows/entity-change-workflow';
import type { TerminalRecycleMetadataInput } from '../../../apps/console-api/src/modules/workflows/entity-change-terminal-metadata-proof';

/** Explicitly synthetic signed SELECT fixture: real AES-GCM/HMAC and production
 * baseline validation, mocked rows/current historical-read policy. It is not a
 * real Kong response, applied SQL023, genuine Root proof or runtime permission. */
export function terminalMetadataFixture(options: { parentAwareGraphKeys?: boolean } = {}) {
  const secrets = new SecretService(), cid = randomUUID(), wid = randomUUID(), actorId = randomUUID();
  const entryId = randomUUID(), intentId = randomUUID(), sourceId = randomUUID(), workflowId = randomUUID(), executionId = randomUUID();
  const baselineId = randomUUID(), pinId = randomUUID(), deleteSourceId = randomUUID(), deleteWorkflowId = randomUUID(), deleteExecutionId = randomUUID();
  const consumerId = randomUUID(), sessionId = randomUUID(), transportScope = secrets.fingerprint(`synthetic-transport-scope:${cid}`);
  const fixtureNow = Date.now(), instant = (delta: number) => new Date(fixtureNow + delta).toISOString();
  const issued = instant(-600000), expires = instant(-300000), observed = instant(-590000), attempted = instant(-580000), sentAt = instant(-570000), outcomeAt = instant(-560000), created = instant(-550000);
  const plain = 'synthetic-basic-plaintext', actor: any = { user: { id: actorId, username: 'synthetic-actor', superAdmin: false }, workspaceId: wid, requestId: 'synthetic-request', ip: '127.0.0.1' };
  const nativeTypes = ['consumers', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'];
  const ids = [consumerId, ...Array.from({ length: 6 }, () => randomUUID())];
  const payloads: any[] = [
    { id: consumerId, username: 'synthetic-consumer', tags: ['kos-ws-unit'] },
    { id: ids[1], key: 'synthetic-api-key', consumer: { id: consumerId }, tags: ['kos-ws-unit'] },
    { id: ids[2], username: 'synthetic-basic', password: plain, consumer: { id: consumerId }, tags: ['kos-ws-unit'] },
    { id: ids[3], key: 'synthetic-jwt-key', algorithm: 'HS256', secret: 'synthetic-jwt-secret', consumer: { id: consumerId }, tags: ['kos-ws-unit'] },
    { id: ids[4], name: 'synthetic-oauth', client_id: 'synthetic-client-id', client_secret: 'synthetic-client-secret', redirect_uris: ['https://example.invalid/callback'], consumer: { id: consumerId }, tags: ['kos-ws-unit'] },
    { id: ids[5], username: 'synthetic-hmac', secret: 'synthetic-hmac-secret', consumer: { id: consumerId }, tags: ['kos-ws-unit'] },
    { id: ids[6], group: 'synthetic-group', consumer: { id: consumerId }, tags: ['kos-ws-unit'] },
  ];
  const nodes: any[] = nativeTypes.map((type, i) => {
    const data = { ...payloads[i], ...(i === 2 ? { password: createHash('sha1').update(plain + consumerId).digest('hex') } : {}), created_at: 100 };
    return { key: i && options.parentAwareGraphKeys ? `${type}:${consumerId}:${ids[i]}` : `${type}:${ids[i]}`, type, id: ids[i], path: i ? `/consumers/${consumerId}/${type}/${ids[i]}` : `/consumers/${consumerId}`,
      data, restoreData: { ...payloads[i], created_at: 100 }, affected: true, dependencies: i ? [`consumers:${consumerId}`] : [], restorable: true };
  });
  const graph: any = { complete: true, purpose: 'recycle', capturedAt: instant(-3600000), rootKey: nodes[0].key, nodes };
  const nodeManifest = nodes.map((node, i) => ({ key: node.key, order: i + 1, nativeType: node.type, nativeId: node.id, parentId: i ? consumerId : null,
    credentialKind: i ? node.type : null, affected: true, dependencies: node.dependencies, pathHmac: secrets.fingerprint(node.path), dataHmac: secrets.fingerprint(node.data), restoreHmac: secrets.fingerprint(payloads[i]) }));
  const packets: any[] = nodes.map((node, i) => ({ key: `graph-1:recycle:restore:${node.key}`, order: i + 1, dependencies: i ? [`graph-1:recycle:restore:${nodes[0].key}`] : [], method: 'POST',
    canonicalPath: i ? `/consumers/${consumerId}/${node.type}` : '/consumers', nativeType: node.type, nativeId: node.id,
    ...(i ? { parentId: consumerId, credentialKind: node.type } : {}), permissionAction: 'write', mutationAction: 'restore', body: payloads[i], before: null,
    bodyHmac: secrets.fingerprint(payloads[i]), beforeHmac: secrets.fingerprint(null) }));
  const seal = { clusterId: cid, workspaceId: wid, entryId, state: 'deleted', expiresAt: '2099-01-01T00:00:00.000Z', payloadHmac: secrets.fingerprint(graph),
    nodeManifestHmac: secrets.fingerprint('synthetic pre-restore pending metadata and closed DELETE origins'),
    restoreMaterialHmac: secrets.fingerprint(nodes.map(node => ({ key: node.key, restoreData: node.restoreData }))) };
  const material: any = { version: 1, clusterId: cid, workspaceId: wid, requesterId: actorId, permissionVersion: 'synthetic-permission:1',
    scope: { transportScope, clusterRevision: 1, workspaceRevision: 1, kongVersion: '1.5.1', adapter: 'kong-1.5' },
    request: { kind: 'recycle', action: 'restore', entryId, confirmed: true, confirm_name: 'synthetic-consumer' }, prerequisites: [], schemas: [], packets,
    metadataObligations: [...packets.map((p, i) => i ? { kind: 'credential-remember', packetKey: p.key, consumerId, credentialKind: p.nativeType, rawInput: p.body }
      : { kind: 'entity-index', packetKey: p.key, entityType: 'consumers' }), { kind: 'recycle-restore', entryId, graph, graphHmac: secrets.fingerprint(graph), packetKeys: packets.map(p => p.key), sealedEntry: seal }],
    recovery: { state: 'baseline-required', blockerCodes: [], objects: [] }, impact: { kind: 'entity', objects: [] } };
  material.changeDigest = secrets.fingerprint(material);
  const packetManifest = normalizedEntityChangePackets(material, secrets);
  const definition = { id: randomUUID(), version: 1, policyHash: secrets.fingerprint('synthetic policy') };
  const envelope: any = { version: 1, intentId, revision: 1, clusterId: cid, workspaceId: wid, requesterId: actorId, credentialEpoch: '1',
    issuedAt: instant(-7200000), expiresAt: instant(3600000), ttlHours: 3, executionMode: 'direct', definition,
    packetManifestHmac: secrets.fingerprint(packetManifest), prepared: material, review: { version: 1, clusterId: cid, workspaceId: wid, changeDigest: material.changeDigest } };
  const payload = { intentId, intentRevision: 1, materialHmac: secrets.fingerprint(envelope), changeDigest: material.changeDigest, packetManifestHmac: secrets.fingerprint(packetManifest) };
  const plan: any = { version: 1, clusterId: cid, workspaceId: wid, workflowId, planRevision: 1, kind: 'native-change', executionMode: 'direct', approvalRequired: false,
    subject: { type: 'entity_change_intents', id: intentId }, requester: { type: 'console', id: actorId }, definition,
    issuedAt: envelope.issuedAt, expiresAt: envelope.expiresAt, scope: { transportScope, clusterRevision: 1, workspaceRevision: 1 }, prerequisites: [],
    steps: [{ id: randomUUID(), key: 'entity-change', order: 1, kind: 'metadata', handler: 'entity.change', entityType: 'entity_change_intents', entityId: intentId,
      permissionAction: 'write', dependencies: [], nativeRequests: [], metadata: payload, metadataRevision: 1,
      metadataBeforeHmac: secrets.fingerprint(null), metadataPayloadHmac: secrets.fingerprint(payload) }] };
  const tuple: any = { cluster_id: cid, workspace_id: wid, intent_id: intentId, intent_revision: 1, material_hmac: payload.materialHmac,
    change_digest: payload.changeDigest, packet_manifest_hmac: payload.packetManifestHmac };
  const sourceRow: any = { ...tuple, id: sourceId, workflow_id: workflowId, workflow_plan_revision: 1, workflow_plan_hash: secrets.fingerprint(plan),
    workflow_execution_id: executionId, execution_actor_id: actorId, credential_epoch: '1', permission_version_hmac: secrets.fingerprint(material.permissionVersion),
    session_id: sessionId, origin_type: 'http', issued_at: issued, expires_at: expires };
  const source: any = structuredClone(decodeEntityExecutionSource(sourceRow));
  const oldSource: any = { ...sourceRow, id: deleteSourceId, intent_id: randomUUID(), workflow_id: deleteWorkflowId, workflow_execution_id: deleteExecutionId,
    workflow_plan_hash: secrets.fingerprint('synthetic original DELETE plan'), material_hmac: secrets.fingerprint('synthetic original DELETE intent') };
  const capture: any = { version: 1, observedFrom: observed, observedUntil: observed, graphs: [], objects: nodes.map((node, i) => ({ key: i ? `${node.type}:${consumerId}:${node.id}` : node.key,
    nativeType: node.type, nativeId: node.id, ...(i ? { parentId: consumerId, credentialKind: node.type } : {}), affected: true, present: false,
    dependencies: node.dependencies, before: null, schemaMaterial: { name: node.type, version: '1.5.1' }, trustedProvenance: { kind: 'synthetic-GET404' }, recovery: 'absent' })),
    blockerCodes: [], nonreversiblePacketKeys: [] };
  capture.objects = [capture.objects[0], ...capture.objects.slice(1).sort((a: any, b: any) => a.key.localeCompare(b.key))];
  const objectManifest = capture.objects.map((o: any) => ({ key: o.key, nativeType: o.nativeType, nativeId: o.nativeId, parentId: o.parentId ?? null,
    credentialKind: o.credentialKind ?? null, affected: true, present: false, dependencies: o.dependencies, beforeHmac: secrets.fingerprint(null), restoreHmac: null,
    schemaHmac: secrets.fingerprint(o.schemaMaterial), provenanceHmac: secrets.fingerprint(o.trustedProvenance), recovery: 'absent' }));
  const baselineEnvelope = { version: 1, baselineId, source, capture };
  const binding: any = { cluster_id: cid, workspace_id: wid, source_id: sourceId, baseline_id: baselineId, pin_id: pinId, workflow_execution_id: executionId };
  const baseline: any = { ...tuple, id: baselineId, source_id: sourceId, workflow_id: workflowId, workflow_plan_revision: 1, workflow_plan_hash: source.workflowPlanHash,
    workflow_execution_id: executionId, execution_actor_id: actorId, credential_epoch: '1', readiness: 'ready', baseline_hmac: secrets.fingerprint(baselineEnvelope),
    capture_hmac: secrets.fingerprint(capture), object_manifest_hmac: secrets.fingerprint(objectManifest), object_manifest: objectManifest, object_count: 7, graph_count: 0,
    material_ciphertext: secrets.encrypt(baselineEnvelope, entityBaselineAad(cid, wid, baselineId)), observed_from: observed, observed_until: observed };
  const rows: Record<string, any[]> = {
    entity_change_execution_sources: [sourceRow, oldSource], entity_change_baselines: [baseline],
    entity_change_baseline_pins: [{ ...binding, id: pinId, baseline_hmac: baseline.baseline_hmac, object_manifest_hmac: baseline.object_manifest_hmac, pin_version: 1, previous_pin_id: null, protected_until: seal.expiresAt }],
    entity_change_baseline_objects: objectManifest.map((o, i) => ({ ...binding, object_manifest_hmac: baseline.object_manifest_hmac, object_order: i + 1,
      object_key: o.key, native_type: o.nativeType, native_id: o.nativeId, parent_id: o.parentId, credential_kind: o.credentialKind, affected: true, present: false,
      dependencies: o.dependencies, before_hmac: o.beforeHmac, restore_hmac: null, schema_hmac: o.schemaHmac, provenance_hmac: o.provenanceHmac, recovery: 'absent' })),
    entity_change_intent_versions: [{ ...tuple, envelope_ciphertext: secrets.encrypt(envelope, entityChangeIntentAad(cid, wid, intentId, 1)), packet_count: 7, packet_manifest: packetManifest }],
    entity_change_intent_packets: packetManifest.map(p => ({ ...tuple, packet_key: p.key, packet_order: p.order, dependencies: p.dependencies, method: p.method,
      path_hmac: p.pathHmac, native_type: p.nativeType, native_id: p.nativeId, parent_id: p.parentId, credential_kind: p.credentialKind, original_native_id: p.originalNativeId,
      mutation_action: p.mutationAction, permission_action: p.permissionAction, body_hmac: p.bodyHmac, before_hmac: p.beforeHmac })),
    recycle_entries: [{ id: entryId, cluster_id: cid, workspace_id: wid, actor_id: actorId, mutation_id: null, root_type: 'consumers', original_id: consumerId,
      parent_id: null, credential_kind: null, node_count: 7, state: 'restoring', payload_secret: secrets.encrypt(graph, `recycle:${entryId}`), expires_at: seal.expiresAt, restored_at: null, purged_at: null }],
    entity_change_recycle_archives: [{ entry_id: entryId, cluster_id: cid, workspace_id: wid, source_id: deleteSourceId, baseline_id: randomUUID(), pin_id: randomUUID(),
      workflow_execution_id: deleteExecutionId, actor_id: actorId, root_key: graph.rootKey, graph_hmac: secrets.fingerprint(graph), payload_hmac: secrets.fingerprint(graph),
      node_manifest_hmac: secrets.fingerprint(nodeManifest), node_manifest: nodeManifest, node_count: 7, packet_count: 7 }],
    entity_change_recycle_nodes: nodeManifest.map(n => ({ cluster_id: cid, workspace_id: wid, entry_id: entryId, node_key: n.key, node_order: n.order,
      native_type: n.nativeType, native_id: n.nativeId, parent_id: n.parentId, credential_kind: n.credentialKind, affected: true, dependencies: n.dependencies,
      path_hmac: n.pathHmac, data_hmac: n.dataHmac, restore_hmac: n.restoreHmac })),
    entity_change_recycle_packets: [], entity_change_packet_attempts: [], entity_change_packet_events: [], mutation_operations: [], entity_change_recycle_receipts: [],
    recycle_nodes: nodes.map((n, i) => ({ entry_id: entryId, node_key: n.key, entity_type: n.type, original_id: n.id, affected: true, dependencies: n.dependencies,
      delete_state: 'deleted', restore_state: i < 5 ? 'restored' : 'pending', restored_id: i < 5 ? n.id : null, safe_error: null })),
    workflow_executions: [{ id: executionId, cluster_id: cid, workspace_id: wid, workflow_id: workflowId, state: 'partial' },
      { id: deleteExecutionId, cluster_id: cid, workspace_id: wid, workflow_id: deleteWorkflowId, state: 'succeeded' }],
  };
  rows.entity_change_recycle_packets = rows.entity_change_intent_packets.map((p, i) => {
    const { dependencies: _dag, ...tuple } = p;
    return { ...tuple, ...binding, entry_id: entryId, node_key: nodes[i].key, direction: 'restore', created_at: observed };
  });
  for (let i = 0; i < 6; i++) {
    const p = packets[i], attemptId = randomUUID(), operationId = randomUUID();
    const { dependencies: _dag, ...attemptTuple } = rows.entity_change_intent_packets[i];
    rows.entity_change_packet_attempts.push({ ...attemptTuple, ...binding, id: attemptId, created_at: attempted });
    const raw = i < 5 ? { ...nodes[i].data } : null;
    const m: any = { id: operationId, cluster_id: cid, workspace_id: wid, actor_id: actorId, workflow_id: workflowId, entity_type: i ? 'credentials' : 'consumers',
      entity_id: p.nativeId, action: 'restore', parent_id: p.parentId ?? null, credential_kind: p.credentialKind ?? null,
      idempotency_key: `entity-${executionId}-${p.order}`, transport_scope: transportScope, state: i < 5 ? 'succeeded' : 'uncertain', remote_started: true, remote_completed: i < 5,
      before_secret: secrets.encrypt(null, `mutation:${operationId}:before`), payload_secret: secrets.encrypt(p.body, `mutation:${operationId}:payload`),
      result_secret: i < 5 ? secrets.encrypt(raw, `mutation:${operationId}:result`) : null, error_code: i < 5 ? null : 'KONG_EXECUTION_BUDGET_EXCEEDED',
      entity_change_source_id: sourceId, entity_change_baseline_id: baselineId, entity_change_attempt_id: attemptId, entity_change_packet_key: p.key };
    rows.mutation_operations.push(m);
    const attemptBinding = { sourceId, baselineId, pinId, packetKey: p.key, attemptId };
    for (const kind of ['send-intent', 'outcome']) {
      const fact: any = { version: 1, kind, binding: attemptBinding, observedAt: kind === 'send-intent' ? sentAt : outcomeAt,
        ...(kind === 'outcome' ? { outcome: i < 5 ? 'succeeded' : 'failed-known-not-sent', ...(i < 5 ? { nativeStatus: 201 } : { errorCode: m.error_code }) } : {}),
        evidence: kind === 'send-intent' ? { operationId, method: 'POST', pathHmac: secrets.fingerprint(p.canonicalPath), bodyHmac: p.bodyHmac, beforeHmac: p.beforeHmac }
          : { operationId, mutationState: m.state, remoteCompleted: i < 5, responseHmac: i < 5 ? secrets.fingerprint(raw) : null, metadataComplete: i < 5 } };
      rows.entity_change_packet_events.push({ ...binding, id: randomUUID(), attempt_id: attemptId, event_kind: kind, outcome: fact.outcome ?? null,
        native_status: fact.nativeStatus ?? null, error_code: fact.errorCode ?? null, fact_hmac: secrets.fingerprint(fact),
        fact_ciphertext: secrets.encrypt(fact, entityPacketFactAad(cid, wid, attemptId, kind)), observed_at: fact.observedAt, created_at: created });
    }
    if (i < 5) rows.entity_change_recycle_receipts.push({ ...binding, attempt_id: attemptId, entry_id: entryId, node_key: nodes[i].key, packet_key: p.key,
      operation_id: operationId, operation_key: m.idempotency_key, native_id: p.nativeId, direction: 'restore', result_hmac: secrets.fingerprint(raw), verification_hmac: null, created_at: created });
  }
  const foreign = { unresolved: false };
  const select = (sql: string, params: any[]) => {
    if (!/^SELECT\s/i.test(sql) || /FOR\s+(UPDATE|SHARE)/i.test(sql)) throw new Error('Synthetic adapter permits SELECT only');
    if (sql.startsWith('SELECT EXISTS(')) return [foreign];
    const table = /\bFROM\s+(\w+)/i.exec(sql)?.[1]; if (!table || !rows[table]) throw new Error('Unexpected synthetic SELECT');
    let selected = rows[table];
    if (table === 'entity_change_execution_sources') selected = selected.filter(r => r.id === params[0]);
    else if (table === 'entity_change_baselines') selected = selected.filter(r => /source_id=\$1/.test(sql) ? r.source_id === params[0] : r.id === params[0]);
    else if (table === 'entity_change_baseline_pins') selected = selected.filter(r => sql.includes('id=$1 AND baseline_id=$2') ? r.id === params[0] && r.baseline_id === params[1] : r.baseline_id === params[0]).sort((a, b) => b.pin_version - a.pin_version);
    else if (table === 'entity_change_baseline_objects') selected = selected.filter(r => r.baseline_id === params[0]).sort((a, b) => a.object_order - b.object_order);
    else if (table === 'entity_change_intent_versions' || table === 'entity_change_intent_packets') selected = selected.filter(r => r.cluster_id === params[0] && r.workspace_id === params[1] && r.intent_id === params[2] && r.intent_revision === params[3]).sort((a, b) => a.packet_order - b.packet_order);
    else if (table === 'recycle_entries') selected = selected.filter(r => r.cluster_id === params[0] && r.workspace_id === params[1] && r.id === params[2]);
    else if (table === 'entity_change_recycle_archives' || table === 'entity_change_recycle_nodes' || table === 'recycle_nodes') selected = selected.filter(r => r.entry_id === params[0]).sort((a, b) => (a.node_order ?? 0) - (b.node_order ?? 0));
    else if (table === 'mutation_operations') selected = selected.filter(r => r.entity_change_source_id === params[0]);
    else selected = selected.filter(r => r.source_id === params[0] && (params.length < 2 || r.entry_id === params[1])).sort((a, b) => (a.packet_order ?? 0) - (b.packet_order ?? 0));
    return structuredClone(selected);
  };
  const txMock: any = { one: vi.fn(async (sql: string, params: any[] = []) => select(sql, params)[0] ?? null),
    query: vi.fn(async (sql: string, params: any[] = []) => select(sql, params)), exec: vi.fn(async () => { throw new Error('No SQL writes permitted'); }),
    transaction: vi.fn(async (fn: any) => fn(txMock)) };
  const facts = new EntityChangeExecutionFactsService(txMock, secrets);
  const denied = async () => { throw new Error('Synthetic fixture cannot issue Root execution authority'); };
  facts.installFixedDelegate({ verifySource: denied, verifyCapture: denied, verifyPacketFact: denied, verifyRetention: denied, verifyRecovery: denied,
    assertHistoricalRead: async (id, reader) => { if (id !== baselineId || reader.user.id !== actorId || reader.workspaceId !== wid) throw new Error('Synthetic historical subject mismatch'); } });
  const input: TerminalRecycleMetadataInput = { tx: txMock, secrets, facts, plan, envelope, source, actor };
  const closeProjection = () => { rows.mutation_operations[5].state = 'failed'; rows.recycle_entries[0].state = 'partially_restored'; rows.recycle_nodes[5].restore_state = 'failed'; };
  const rewriteFact = (index: number, kind: string, modify: (fact: any) => void) => {
    const attempt = rows.entity_change_packet_attempts[index], row = rows.entity_change_packet_events.find(e => e.attempt_id === attempt.id && e.event_kind === kind)!;
    const fact: any = secrets.decrypt(row.fact_ciphertext, entityPacketFactAad(cid, wid, attempt.id, kind)); modify(fact);
    Object.assign(row, { fact_hmac: secrets.fingerprint(fact), fact_ciphertext: secrets.encrypt(fact, entityPacketFactAad(cid, wid, attempt.id, kind)),
      observed_at: fact.observedAt, outcome: fact.outcome ?? null, native_status: fact.nativeStatus ?? null, error_code: fact.errorCode ?? null });
  };
  const resignEnvelope = () => {
    const { changeDigest: _digest, ...rest } = envelope.prepared; envelope.prepared.changeDigest = secrets.fingerprint(rest);
    envelope.packetManifestHmac = secrets.fingerprint(normalizedEntityChangePackets(envelope.prepared, secrets));
    const update = { materialHmac: secrets.fingerprint(envelope), changeDigest: envelope.prepared.changeDigest, packetManifestHmac: envelope.packetManifestHmac };
    Object.assign(plan.steps[0].metadata, update); plan.steps[0].metadataPayloadHmac = secrets.fingerprint(plan.steps[0].metadata);
    Object.assign(source, update, { workflowPlanHash: secrets.fingerprint(plan) });
    Object.assign(sourceRow, { material_hmac: update.materialHmac, change_digest: update.changeDigest, packet_manifest_hmac: update.packetManifestHmac, workflow_plan_hash: source.workflowPlanHash });
  };
  return { input, rows, secrets, sourceRow, source, envelope, plan, actor, txMock, facts, graph, packets, consumerId, baseline, baselineEnvelope,
    foreign, entryId, closeProjection, rewriteFact, resignEnvelope };
}
