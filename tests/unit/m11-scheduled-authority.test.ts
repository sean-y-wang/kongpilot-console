import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { EntityScheduledAuthorityService } from '../../apps/console-api/src/modules/workflows/entity-scheduled-authority.service';
import { EntityChangeBoundaryService } from '../../apps/console-api/src/modules/entities/entity-change-boundary.service';
import { entityChangeIntentAad, normalizedEntityChangePackets } from '../../apps/console-api/src/modules/workflows/entity-change-workflow';
import { entityDelegationAad } from '../../apps/console-api/src/modules/workflows/entity-change-schedule.repository';
import { entityPacketFactAad } from '../../apps/console-api/src/modules/workflows/entity-change-execution-facts.service';

/** SQL/lease domain adapters isolate real GCM/HMAC, current grant and original
 * handle checks. No private Root namespace, Kong send or live SQL is exercised. */
function fixture() {
  const secrets = new SecretService(), cid = randomUUID(), wid = randomUUID(), owner = randomUUID(), reviewer = randomUUID(), intentId = randomUUID(), scheduleId = randomUUID(), wfId = randomUUID(), nativeId = randomUUID(), now = Date.now();
  const adminUrl = 'http://kong.internal:8001', transportScope = transportScopeFor(adminUrl), definition = { id: randomUUID(), version: 1, policyHash: secrets.fingerprint({ policy: 'single' }) };
  const body = { host: 'after.internal' }, before = { id: nativeId, host: 'before.internal', tags: [] }, packet = { key: 'p1', order: 1, dependencies: [], method: 'PATCH', canonicalPath: `/services/${nativeId}`, nativeType: 'services', nativeId, permissionAction: 'write', mutationAction: 'update', body, before, bodyHmac: secrets.fingerprint(body), beforeHmac: secrets.fingerprint(before) };
  const original = { version: 1, clusterId: cid, workspaceId: wid, requesterId: owner, permissionVersion: 'original-pv', scope: { transportScope, clusterRevision: 1, workspaceRevision: 1, kongVersion: '1.5.1', adapter: 'kong-1.5' }, request: { kind: 'entity', action: 'update', entityType: 'services', entityId: nativeId, body }, prerequisites: [], schemas: [], packets: [packet], metadataObligations: [], recovery: { state: 'baseline-required', blockerCodes: ['EXECUTION_BASELINE_REQUIRED'], objects: [] }, impact: { version: 1, keyId: 'a'.repeat(64), keys: ['b'.repeat(64)], domains: [], wildcards: [] } };
  const prepared: any = { ...original, changeDigest: secrets.fingerprint(original) }, manifest = normalizedEntityChangePackets(prepared, secrets), packetManifestHmac = secrets.fingerprint(manifest);
  const issuedAt = new Date(now - 3600000).toISOString(), expiresAt = new Date(now + 240000).toISOString(), spec = { version: 1, executorId: owner, notBefore: new Date(now - 1000).toISOString(), windowStart: new Date(now - 10000).toISOString(), windowEnd: expiresAt };
  const delegation = { version: 1, id: randomUUID(), revision: 1, clusterId: cid, workspaceId: wid, intentId, intentRevision: 1, changeDigest: prepared.changeDigest, packetManifestHmac, policyHash: definition.policyHash, ownerId: owner, executorId: owner, ownerCredentialEpoch: '1', executorCredentialEpoch: '1', issuedAt, expiresAt, specHmac: secrets.fingerprint(spec), statement: 'execute-this-exact-approved-entity-intent-with-my-current-authority' };
  let envelope: any = { version: 2, intentId, revision: 1, clusterId: cid, workspaceId: wid, requesterId: owner, credentialEpoch: '1', issuedAt, expiresAt, ttlHours: 24, executionMode: 'approval', definition, packetManifestHmac, prepared, review: { changes: [] }, scheduling: { scheduleId, scheduleVersion: 1, spec, specHmac: secrets.fingerprint(spec), delegation, delegationHmac: secrets.fingerprint(delegation) } };
  const state: any = { ownerActive: true, reviewerActive: true, ownerGrants: true, reviewerGrants: true, ownerEpoch: '1', iam: '1', migration: true, conflict: false, leaseActive: false, ownerHttp: false, inheritedFrame: null, workflowState: 'approved', claim: null, source: null, packetFacts: [], progress: 'active', revision: 1, reason: null, lifecycleFacts: {}, failLeaseChecks: 0, noSend: false, terminalOutcome: 'succeeded' };
  const intent = { id: intentId, requester_id: owner, credential_epoch: '1', issued_at: issuedAt, expires_at: expiresAt };
  const row: any = { id: scheduleId, version: 1, cluster_id: cid, workspace_id: wid, intent_id: intentId, intent_revision: 1, owner_id: owner, owner_credential_epoch: '1', delegation_id: delegation.id, delegation_version: 1, delegation_hmac: envelope.scheduling.delegationHmac, spec_hmac: envelope.scheduling.specHmac, spec, not_before: spec.notBefore, window_start: spec.windowStart, window_end: spec.windowEnd, expires_at: expiresAt, occurrence_id: randomUUID(), transport_scope: transportScope, impact: prepared.impact, impact_hmac: secrets.fingerprint(prepared.impact), delegation_ciphertext: secrets.encrypt(delegation, entityDelegationAad(cid, wid, delegation.id)), workflow_id: wfId, workflow_plan_revision: 1, approval_format: 1, approval_required: true, approval_set_id: null, approval_set_hmac: null };
  const version: any = { requester_id: owner, credential_epoch: '1', issued_at: issuedAt, expires_at: expiresAt, execution_mode: 'approval', definition_id: definition.id, definition_version: 1, policy_hash: definition.policyHash, change_digest: prepared.changeDigest, packet_manifest_hmac: packetManifestHmac, packet_manifest: manifest, packet_count: 1, safe_review: envelope.review };
  const submission: any = { workflow_id: wfId, workflow_plan_revision: 1, change_digest: prepared.changeDigest, packet_manifest_hmac: packetManifestHmac };
  const plan: any = { version: 1, clusterId: cid, workspaceId: wid, workflowId: wfId, planRevision: 1, kind: 'native-change', executionMode: 'approval', approvalRequired: true, subject: { type: 'entity_change_intents', id: intentId }, requester: { type: 'console', id: owner }, definition, issuedAt, expiresAt, scope: { transportScope, clusterRevision: 1, workspaceRevision: 1 }, prerequisites: [], steps: [{ id: randomUUID(), key: 'entity.change', order: 1, kind: 'metadata', handler: 'entity.change', entityType: 'entity_change_intents', entityId: intentId, permissionAction: 'write', dependencies: [], nativeRequests: [], metadataRevision: 1, metadataBeforeHmac: secrets.fingerprint(null) }] };
  const seal = () => {
    version.execution_mode = envelope.executionMode;
    row.material_hmac = secrets.fingerprint(envelope); row.change_digest = prepared.changeDigest; row.packet_manifest_hmac = packetManifestHmac;
    version.material_hmac = row.material_hmac; version.envelope_ciphertext = secrets.encrypt(envelope, entityChangeIntentAad(cid, wid, intentId, 1));
    submission.material_hmac = row.material_hmac;
    plan.steps[0].metadata = { intentId, intentRevision: 1, materialHmac: row.material_hmac, changeDigest: prepared.changeDigest, packetManifestHmac };
    plan.steps[0].metadataPayloadHmac = secrets.fingerprint(plan.steps[0].metadata); submission.workflow_plan_hash = secrets.fingerprint(plan); row.workflow_plan_hash = submission.workflow_plan_hash;
  }; seal();
  const grants = (id: string) => (id === owner ? state.ownerGrants : state.reviewerGrants) ? [
    { module: 'services', action: id === owner ? 'write' : 'read', scope_type: 'entity', scope_values: [{ entity_type: 'services', entity_id: nativeId }], cluster_id: cid, workspace_id: wid },
    { module: 'workflows', action: id === owner ? 'write' : 'approve', scope_type: 'entity', scope_values: [{ entity_type: 'services', entity_id: nativeId }], cluster_id: cid, workspace_id: wid },
  ] : [];
  const db: any = { one: vi.fn(async (sql: string, p: any[] = []) => {
    if (sql.includes('AS execution,') && sql.includes('AS baseline,')) return { execution: false, source: !!state.source, baseline: false, mutation: false, packet: false, ...state.lifecycleFacts };
    if (sql.includes('FROM schema_migrations')) return state.migration ? { checksum: '3b918d1d7f328bfa4c1a5ffa72720ad755dc0aaa11cfa3393dd3b4b297f3955f' } : null;
    if (sql.includes('FROM iam_epoch')) return { version: state.iam };
    if (sql.includes('FROM clusters')) return { id: cid, revision: 1, execution_mode: envelope.executionMode, version: '1.5.1', admin_url: adminUrl, status: 'healthy' };
    if (sql.includes('FROM users')) return (p[0] === owner ? state.ownerActive : state.reviewerActive) ? { id: p[0], username: 'actual-sql-user', super_admin: false, permissions_epoch: '1', credential_epoch: p[0] === owner ? state.ownerEpoch : '1' } : null;
    if (sql.includes('FROM auth_sessions')) return state.ownerHttp ? { id: randomUUID() } : null;
    if (sql.includes('FROM entity_change_intent_versions')) return version;
    if (sql.includes('FROM entity_change_intents')) return intent;
    if (sql.includes('SELECT other.id') || sql.includes('SELECT m.id')) return state.conflict ? { id: randomUUID() } : null;
    if (sql.includes('FROM entity_change_schedules')) return { ...row, state: state.progress, revision: state.revision, reason_code: state.reason, claim_id: state.claim?.id ?? null };
    if (sql.includes('FROM entity_change_submissions')) return submission;
    if (sql.includes('FROM workflows')) return { state: state.workflowState, plan_revision: 1, plan_hash: row.workflow_plan_hash };
    if (sql.includes('FROM entity_change_schedule_claims')) return state.claim;
    if (sql.includes('FROM entity_change_schedule_leases')) return state.lease;
    throw new Error(`Unexpected authority read: ${sql}`);
  }), query: vi.fn(async (sql: string, p: any[] = []) => {
    if (sql.includes('iam_effective_grants')) return grants(p[0]);
    if (sql.includes('intent_packets')) return manifest.map(m => ({ packet_key: m.key, packet_order: m.order, dependencies: m.dependencies, method: m.method, path_hmac: m.pathHmac, native_type: m.nativeType, native_id: m.nativeId, parent_id: m.parentId, credential_kind: m.credentialKind, original_native_id: m.originalNativeId, mutation_action: m.mutationAction, permission_action: m.permissionAction, body_hmac: m.bodyHmac, before_hmac: m.beforeHmac, material_hmac: row.material_hmac, change_digest: prepared.changeDigest, packet_manifest_hmac: packetManifestHmac }));
    if (sql.includes('FROM entity_change_execution_sources')) return state.source ? [state.source] : [];
    if (sql.includes('FROM entity_change_packet_attempts')) return state.packetFacts;
    throw new Error(`Unexpected authority list: ${sql}`);
  }), exec: vi.fn(async (sql: string, values: any[] = []) => {
    if (sql.includes('pg_advisory_xact_lock')) return 1;
    if (sql.startsWith('UPDATE entity_change_schedule_progress SET reason_code=')) {
      if (state.progress !== 'claimed' || values[2] !== state.claim?.id || values[3] !== state.revision) return 0;
      state.reason = values[1]; state.revision++; return 1;
    }
    throw new Error('Authority must not write sources/native');
  }), transaction: vi.fn(async (fn: any) => fn(db)) };
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => { if (state.leaseActive) throw new Error('Lock reentry'); state.leaseActive = true; try { return await fn(); } finally { state.leaseActive = false; } }), assertLeaseOwnership: vi.fn(async () => {
    if (state.failLeaseChecks > 0) { state.failLeaseChecks--; throw new ForbiddenException({ code: 'REDIS_LEASE_EXPIRED' }); }
    if (!state.leaseActive) throw new ForbiddenException({ code: 'REDIS_LEASE_EXPIRED' });
  }), assertLeaseActive: vi.fn(() => { if (!state.leaseActive) throw new Error('Lease closed'); }) };
  const actor = { user: { id: owner, username: 'owner', superAdmin: false }, workspaceId: wid }, context: any = { peek: vi.fn(() => state.inheritedFrame ?? (state.ownerHttp ? { actor: actor.user, sessionId: randomUUID(), clusterId: cid, workspaceId: wid } : null)) };
  const workspaces: any = { get: vi.fn(async () => ({ id: wid, is_default: true, code: 'default', status: 'active', revision: 1 })) }, boundary = new EntityChangeBoundaryService(db, secrets, context, {} as any, workspaces, {} as any, {} as any, {} as any);
  let policy: any;
  const repo: any = { installFixedDelegate: vi.fn((p: any) => { policy = p; }), get: vi.fn(async () => ({ id: scheduleId, revision: state.revision, state: state.progress, nativeAuthority: false })), appendDueClaim: vi.fn(async (id: string, c: any, proof: object, tx: any) => {
    await policy.verifyClaim(id, c, proof, tx); await policy.verifyPhysicalReservation(id, proof, tx);
    state.claim = { id: c.id, cluster_id: cid, workspace_id: wid, schedule_id: id, schedule_version: 1, occurrence_id: c.occurrenceId, generation: 1, worker_owner_hmac: c.workerOwnerHmac, workflow_id: wfId, workflow_plan_revision: 1, workflow_plan_hash: c.workflowPlanHash, owner_id: owner, owner_credential_epoch: '1', delegation_id: delegation.id, delegation_version: 1, delegation_hmac: row.delegation_hmac, spec_hmac: row.spec_hmac, window_start: row.window_start, window_end: row.window_end, issued_at: c.issuedAt, authority_expires_at: c.authorityExpiresAt, initial_lease_until: c.initialLeaseUntil };
    state.lease = { claim_id: c.id, cluster_id: cid, workspace_id: wid, generation: 1, worker_owner_hmac: c.workerOwnerHmac, lease_version: 1, lease_until: c.initialLeaseUntil }; state.progress = 'claimed'; return c;
  }), appendBlocked: vi.fn(async (id: string, reason: string, proof: object) => { await policy.verifyBlocked(id, reason, proof, db); state.progress = reason === 'ENTITY_SCHEDULE_WINDOW_EXPIRED' ? 'expired' : 'blocked'; }),
    finishClaim: vi.fn(async (id: string, outcome: string, proof: object, tx: any) => { await policy.verifyOutcome(id, outcome, proof, tx); state.progress = outcome; }),
    activate: vi.fn(async (id: string, activation: any, proof: object, tx: any) => { await policy.verifyApproved(id, activation, proof, tx); await policy.verifyPhysicalReservation(id, proof, tx); state.progress = 'active'; }) };
  const plans: any = { definition: vi.fn(async () => definition), load: vi.fn(async () => ({ plan })) }, approvals: any = { verifyApprovalSet: vi.fn(async () => ({ format: 1, policyHash: definition.policyHash, setId: null, setHmac: null, reviewers: [{ approvalId: randomUUID(), userId: reviewer, level: 1, candidateVersion: null }] })) };
  const service = new EntityScheduledAuthorityService(db, secrets, redis, context, plans, approvals, repo, boundary, workspaces), completions = new WeakSet<object>();
  const executor = { executeClaim: vi.fn(async (handle: object) => {
    await service.verifyClaim(handle, 'before-send');
    if (state.noSend) { state.terminalOutcome = 'failed'; const completion = Object.freeze({}); completions.add(completion); return completion; }
    state.source = { cluster_id: cid, workspace_id: wid, workflow_id: wfId, workflow_plan_revision: 1, workflow_plan_hash: row.workflow_plan_hash, intent_id: intentId, intent_revision: 1, material_hmac: row.material_hmac, change_digest: prepared.changeDigest, packet_manifest_hmac: packetManifestHmac, execution_actor_id: owner, credential_epoch: '1', execution_state: 'succeeded', session_id: null, id: randomUUID() };
    state.packetFacts = [{ packet_key: 'p1', outcome: 'succeeded', mutation_state: 'succeeded', remote_completed: true }]; state.workflowState = 'succeeded'; const completion = Object.freeze({}); completions.add(completion); return completion;
  }), verifyCompletion: vi.fn(async (_h: object, completion: object) => { if (!completions.has(completion)) throw new ForbiddenException({ code: 'COPIED_ROOT_COMPLETION' }); return state.terminalOutcome as 'succeeded' | 'failed'; }) };
  const install = () => { service.installRepositoryPolicies(); service.installExecutor(executor); };
  return { service, state, actor, row, envelope, seal, db, repo, redis, boundary, plans, approvals, executor, install, secrets, cid, wid, policy: () => policy, changeEnvelope: (fn: (e: any) => void) => { fn(envelope); seal(); } };
}
function completeNativePartial(f: ReturnType<typeof fixture>) {
  const source = f.state.source; source.execution_state = 'partial'; source.workflow_execution_id = randomUUID();
  f.state.workflowState = 'partial'; f.state.terminalOutcome = 'partial';
  const binding = { sourceId: source.id, baselineId: randomUUID(), pinId: randomUUID(), attemptId: randomUUID(), packetKey: 'p1' }, operationId = randomUUID();
  const fact: any = { version: 1, kind: 'outcome', binding, observedAt: new Date().toISOString(), outcome: 'succeeded', nativeStatus: 200,
    evidence: { operationId, mutationState: 'succeeded', remoteCompleted: true, responseHmac: 'a'.repeat(64), metadataComplete: false } };
  const row: any = { packet_key: 'p1', attempt_id: binding.attemptId, baseline_id: binding.baselineId, pin_id: binding.pinId,
    attempt_execution_id: source.workflow_execution_id, mutation_id: operationId, outcome: 'succeeded', native_status: 200, mutation_state: 'succeeded', remote_completed: true };
  const seal = () => { row.fact_hmac = f.secrets.fingerprint(fact); row.fact_ciphertext = f.secrets.encrypt(fact, entityPacketFactAad(f.cid, f.wid, binding.attemptId, 'outcome')); };
  seal(); f.state.packetFacts = [row]; return { fact, row, seal };
}
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ce'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T15:00:00.000Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });
describe('M11 scheduled real-state metadata authority (source-only adapters)', () => {
  it('defaults unavailable, requires exact migration, rejects direct consent and never constructs a SID/source', async () => {
    const f = fixture(); await expect(f.service.acquireDueClaim(f.row.id)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_EXECUTOR_UNAVAILABLE' } }); f.install();
    expect(() => f.service.installRepositoryPolicies()).toThrow(); expect(() => f.service.installExecutor(f.executor)).toThrow();
    f.state.migration = false; await expect(f.service.acquireDueClaim(f.row.id)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_STORAGE_UNAVAILABLE' } });
    f.state.migration = true; f.changeEnvelope(e => { e.executionMode = 'direct'; });
    await expect(f.service.acquireDueClaim(f.row.id)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_DIRECT_CONSENT_UNAVAILABLE' } });
    expect(f.repo.appendDueClaim).not.toHaveBeenCalled(); expect(f.db.exec.mock.calls.every(([sql]: any[]) => sql.includes('pg_advisory_xact_lock'))).toBe(true);
  });
  it.each(['ownerActive', 'ownerGrants', 'reviewerActive', 'reviewerGrants'])('blocks actual due changes to %s without generating a claim', async key => {
    const f = fixture(); f.install(); f.state[key] = false; expect(await f.service.acquireDueClaim(f.row.id)).toBeNull(); expect(f.repo.appendDueClaim).not.toHaveBeenCalled(); expect(f.state.progress).toBe('blocked');
  });
  it('checks epoch, half-open window and physical impact against real metadata', async () => {
    const f = fixture(); f.install(); f.state.ownerEpoch = '2'; expect(await f.service.acquireDueClaim(f.row.id)).toBeNull();
    const g = fixture(); g.install(); vi.setSystemTime(new Date(g.row.window_end)); expect(await g.service.acquireDueClaim(g.row.id)).toBeNull(); expect(g.state.progress).toBe('expired');
    const h = fixture(); h.install(); h.state.conflict = true; expect(await h.service.acquireDueClaim(h.row.id)).toBeNull(); expect(h.repo.appendDueClaim).not.toHaveBeenCalled();
  });
  it('binds an original once handle to SQL claim and current eligibility but grants no active lease after acquisition', async () => {
    const f = fixture(); f.install(); const handle = (await f.service.acquireDueClaim(f.row.id))!;
    expect(await f.service.acquireDueClaim(f.row.id)).toBeNull(); expect(f.repo.appendDueClaim).toHaveBeenCalledTimes(1);
    await expect(f.service.inspect({ ...handle })).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_ORIGINAL_HANDLE_REQUIRED' } });
    const inspection = await f.service.inspect(handle); expect(inspection.principal.id).toBe(f.actor.user.id); expect(inspection.envelope.version).toBe(2); expect(inspection).not.toHaveProperty('sessionId');
    await expect(f.service.verifyClaim(handle, 'before-send')).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_EXECUTOR_CONTEXT_REQUIRED' } });
    f.state.reviewerGrants = false; await expect(f.service.inspect(handle)).rejects.toMatchObject({ status: 403 }); expect(f.executor.executeClaim).not.toHaveBeenCalled();
  });
  it('rejects substituted claim identity and expired SQL lease even with the original handle', async () => {
    const f = fixture(); f.install(); const handle = (await f.service.acquireDueClaim(f.row.id))!; f.state.claim.delegation_hmac = 'f'.repeat(64);
    await expect(f.service.inspect(handle)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_CLAIM_EXPIRED_OR_CHANGED' } });
    const g = fixture(); g.install(); const h = (await g.service.acquireDueClaim(g.row.id))!; g.state.lease.lease_until = new Date(Date.now()).toISOString();
    await expect(g.service.inspect(h)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_CLAIM_EXPIRED_OR_CHANGED' } });
  });
  it('spends the original handle once inside the Redis lease and requires original completion plus real terminal facts', async () => {
    const f = fixture(); f.install(); const handle = (await f.service.acquireDueClaim(f.row.id))!;
    await f.service.executeClaim(handle); expect(f.executor.executeClaim).toHaveBeenCalledWith(handle); expect(f.state.progress).toBe('succeeded'); expect(f.repo.finishClaim).toHaveBeenCalledTimes(1);
    await expect(f.service.executeClaim(handle)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_ORIGINAL_HANDLE_REQUIRED' } });
    expect(f.executor.executeClaim).toHaveBeenCalledTimes(1); expect(f.state.ownerHttp).toBe(false);
  });
  it('refuses arbitrary repository proofs and truthful completion claims without packet/source evidence', async () => {
    const f = fixture(); f.install(); await expect(f.policy().verifyApproved(f.row.id, {}, {}, f.db)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_GENUINE_PROOF_REQUIRED' } });
    await expect(f.policy().verifyOutcome(randomUUID(), 'succeeded', {}, f.db)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_GENUINE_COMPLETION_REQUIRED' } });
    const g = fixture(); g.install(); const original = g.executor.executeClaim.getMockImplementation()!;
    g.executor.executeClaim.mockImplementation(async h => { const completion = await original(h); g.state.packetFacts = []; return completion; });
    const handle = (await g.service.acquireDueClaim(g.row.id))!; await expect(g.service.executeClaim(handle)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_TERMINAL_PACKET_FACTS_REQUIRED' } });
    expect(g.repo.finishClaim).not.toHaveBeenCalled(); await expect(g.service.executeClaim(handle)).rejects.toMatchObject({ status: 403 });
  });
  it('closes genuine all-native success with sealed metadata failure as partial without retrying any packet', async () => {
    const f = fixture(); f.install(); const original = f.executor.executeClaim.getMockImplementation()!;
    f.executor.executeClaim.mockImplementation(async handle => { const completion = await original(handle); completeNativePartial(f); return completion; });
    const handle = (await f.service.acquireDueClaim(f.row.id))!; await f.service.executeClaim(handle);
    expect(f.state.progress).toBe('partial'); expect(f.repo.finishClaim).toHaveBeenCalledTimes(1); expect(f.executor.verifyCompletion).toHaveBeenCalledTimes(2);
    expect(f.executor.executeClaim).toHaveBeenCalledTimes(1); expect(await f.service.acquireDueClaim(f.row.id)).toBeNull();
    await expect(f.service.executeClaim(handle)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_ORIGINAL_HANDLE_REQUIRED' } });
  });
  it.each(['missing-ciphertext', 'tampered-hmac', 'wrong-binding', 'metadata-success', 'unknown', 'foreign-key'] as const)('rejects all-native partial with %s instead of genuine sealed metadata failure', async invalid => {
    const f = fixture(); f.install(); const original = f.executor.executeClaim.getMockImplementation()!;
    f.executor.executeClaim.mockImplementation(async handle => {
      const completion = await original(handle), truth = completeNativePartial(f);
      if (invalid === 'missing-ciphertext') delete truth.row.fact_ciphertext;
      if (invalid === 'tampered-hmac') truth.row.fact_hmac = '0'.repeat(64);
      if (invalid === 'wrong-binding') { truth.fact.binding.sourceId = randomUUID(); truth.seal(); }
      if (invalid === 'metadata-success') { truth.fact.evidence.metadataComplete = true; truth.seal(); }
      if (invalid === 'unknown') truth.row.outcome = 'sent-unknown';
      if (invalid === 'foreign-key') truth.row.packet_key = 'foreign-packet';
      return completion;
    });
    const handle = (await f.service.acquireDueClaim(f.row.id))!;
    await expect(f.service.executeClaim(handle)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_TERMINAL_PACKET_FACTS_REQUIRED' } });
    expect(f.state.progress).toBe('claimed'); expect(f.repo.finishClaim).not.toHaveBeenCalled(); expect(f.executor.executeClaim).toHaveBeenCalledTimes(1);
    expect(await f.service.acquireDueClaim(f.row.id)).toBeNull();
  });
  it('requires Root original no-send completion and closes a failed pre-source occurrence without replay', async () => {
    const f = fixture(); f.install(); f.state.noSend = true; const handle = (await f.service.acquireDueClaim(f.row.id))!;
    await f.service.executeClaim(handle); expect(f.state.progress).toBe('failed'); expect(f.state.source).toBeNull(); expect(f.state.workflowState).toBe('approved');
    expect(await f.service.acquireDueClaim(f.row.id)).toBeNull(); expect(f.repo.appendDueClaim).toHaveBeenCalledTimes(1);
    const g = fixture(); g.install(); g.executor.executeClaim.mockResolvedValue({}); const h = (await g.service.acquireDueClaim(g.row.id))!;
    await expect(g.service.executeClaim(h)).rejects.toMatchObject({ response: { code: 'COPIED_ROOT_COMPLETION' } }); expect(g.repo.finishClaim).not.toHaveBeenCalled();
  });
  it('rejects concurrent execution of the same original handle and preserves unresolved claims without automatic replay', async () => {
    const f = fixture(); f.install(); const handle = (await f.service.acquireDueClaim(f.row.id))!;
    const results = await Promise.allSettled([f.service.executeClaim(handle), f.service.executeClaim(handle)]);
    expect(results.map(result => result.status)).toEqual(['fulfilled', 'rejected']); expect(f.executor.executeClaim).toHaveBeenCalledTimes(1);
    const g = fixture(); g.install(); g.executor.executeClaim.mockRejectedValue(new Error('Root could not confirm outcome'));
    const h = (await g.service.acquireDueClaim(g.row.id))!; await expect(g.service.executeClaim(h)).rejects.toThrow('Root could not confirm outcome');
    expect(g.state.progress).toBe('claimed'); expect(await g.service.acquireDueClaim(g.row.id)).toBeNull(); expect(g.repo.finishClaim).not.toHaveBeenCalled();
  });
  it('requires an actual HTTP actor only for activation and cancellation, never borrows the owner session at due time', async () => {
    const f = fixture(); f.install(); f.state.progress = 'pending-approval'; await expect(f.service.activateApproved(f.row.id, f.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_ACTUAL_ACTOR_REQUIRED' } });
    f.state.ownerHttp = true; await f.service.activateApproved(f.row.id, f.actor); expect(f.repo.activate).toHaveBeenCalledTimes(1);
    f.state.ownerHttp = false; expect(await f.service.acquireDueClaim(f.row.id)).not.toBeNull();
  });
  it.each([{ sessionId: randomUUID(), actor: { id: randomUUID() } }, { actor: { id: randomUUID() }, module: 'system-read' }, {}])('requires no inherited frame at acquire and execute entry', async frame => {
    const f = fixture(); f.install(); f.state.inheritedFrame = frame;
    await expect(f.service.acquireDueClaim(f.row.id)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_BACKGROUND_CONTEXT_REQUIRED' } });
    expect(f.repo.appendDueClaim).not.toHaveBeenCalled(); expect(f.repo.appendBlocked).not.toHaveBeenCalled();
    f.state.inheritedFrame = null; const handle = (await f.service.acquireDueClaim(f.row.id))!; f.state.inheritedFrame = frame;
    await expect(f.service.executeClaim(handle)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_BACKGROUND_CONTEXT_REQUIRED' } }); expect(f.executor.executeClaim).not.toHaveBeenCalled();
    // A rejected foreground entry did not spend the original background
    // handle. It can still be consumed once with no inherited frame.
    f.state.inheritedFrame = null; await f.service.executeClaim(handle); expect(f.executor.executeClaim).toHaveBeenCalledTimes(1);
  });
  it('passes only the original live handle to the callback and refuses inspection/principal copies as authority', async () => {
    const f = fixture(); f.install(); const original = f.executor.executeClaim.getMockImplementation()!;
    f.executor.executeClaim.mockImplementation(async handle => {
      const live = await f.service.verifyClaim(handle, 'packet');
      await expect(f.service.verifyClaim({ ...handle }, 'packet')).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_ORIGINAL_HANDLE_REQUIRED' } });
      await expect(f.service.verifyClaim({ ...live.principal }, 'before-send')).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_ORIGINAL_HANDLE_REQUIRED' } });
      await expect(f.service.verifyClaim({ ...live }, 'capture')).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_ORIGINAL_HANDLE_REQUIRED' } });
      expect(f.state.leaseActive).toBe(true); return original(handle);
    });
    const handle = (await f.service.acquireDueClaim(f.row.id))!; await f.service.executeClaim(handle); expect(f.executor.executeClaim).toHaveBeenCalledWith(handle); expect(f.state.leaseActive).toBe(false);
  });
  it('rechecks live original owner, reviewers and half-open window before the executor callback', async () => {
    const cases = [{ mutate: (f: any) => { f.state.ownerGrants = false; }, code: 'ENTITY_CHANGE_SUBJECT_SCOPE_DENIED' },
      { mutate: (f: any) => { f.state.reviewerGrants = false; }, code: 'ENTITY_CHANGE_SUBJECT_SCOPE_DENIED' },
      { mutate: (f: any) => { vi.setSystemTime(new Date(f.row.window_end)); }, code: 'ENTITY_SCHEDULE_WINDOW_EXPIRED' }];
    for (const { mutate, code } of cases) {
      vi.setSystemTime(new Date('2026-10-13T15:00:00.000Z')); const f = fixture(); f.install(); const handle = (await f.service.acquireDueClaim(f.row.id))!; mutate(f);
      await expect(f.service.executeClaim(handle)).rejects.toMatchObject({ response: { code } }); expect(f.executor.executeClaim).not.toHaveBeenCalled(); expect(f.repo.finishClaim).toHaveBeenCalledTimes(1);
      expect(f.state.progress).toBe('failed'); expect(f.state.reason).toBe(code); expect(await f.service.acquireDueClaim(f.row.id)).toBeNull();
      await expect(f.service.executeClaim(handle)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_ORIGINAL_HANDLE_REQUIRED' } });
    }
  });
  it('closes only original zero-ledger pre-callback failures and retains the immutable claim without a Root completion', async () => {
    const f = fixture(); f.install(); const handle = (await f.service.acquireDueClaim(f.row.id))!, claimId = f.state.claim.id;
    f.state.failLeaseChecks = 1;
    await expect(f.service.executeClaim(handle)).rejects.toMatchObject({ response: { code: 'REDIS_LEASE_EXPIRED' } });
    expect(f.state.progress).toBe('failed'); expect(f.state.claim.id).toBe(claimId); expect(f.state.reason).toBe('REDIS_LEASE_EXPIRED');
    expect(f.executor.executeClaim).not.toHaveBeenCalled(); expect(f.executor.verifyCompletion).not.toHaveBeenCalled(); expect(f.repo.finishClaim).toHaveBeenCalledTimes(1);
    expect(f.db.exec.mock.calls.every(([sql]: any[]) => !sql.includes('INSERT'))).toBe(true); expect(await f.service.acquireDueClaim(f.row.id)).toBeNull();
  });
  it('takes the authenticated impact reservation before a no-callback progress write or terminal transition', async () => {
    const f = fixture(); f.install(); const handle = (await f.service.acquireDueClaim(f.row.id))!;
    let heldImpact = false, wroteReason = false; const exec = f.db.exec.getMockImplementation()!, finish = f.repo.finishClaim.getMockImplementation()!;
    f.db.exec.mockImplementation(async (sql: string, values: any[] = []) => {
      if (sql.includes("'entity-schedule-impact:'")) { expect(values).toEqual([f.row.transport_scope]); heldImpact = true; }
      if (sql.startsWith('UPDATE entity_change_schedule_progress')) { expect(heldImpact).toBe(true); wroteReason = true; }
      return exec(sql, values);
    });
    f.repo.finishClaim.mockImplementation(async (...args: any[]) => { expect(heldImpact).toBe(true); expect(wroteReason).toBe(true); return finish(...args); });
    f.state.ownerGrants = false;
    await expect(f.service.executeClaim(handle)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_SUBJECT_SCOPE_DENIED' } });
    expect(f.state.progress).toBe('failed'); expect(f.repo.finishClaim).toHaveBeenCalledTimes(1); expect(f.executor.executeClaim).not.toHaveBeenCalled();
  });
  it.each(['source', 'execution', 'baseline', 'mutation', 'packet'])('cannot claim no-callback closure when an actual %s fact exists', async fact => {
    const f = fixture(); f.install(); const handle = (await f.service.acquireDueClaim(f.row.id))!;
    f.state.lifecycleFacts[fact] = true; f.state.ownerGrants = false;
    await expect(f.service.executeClaim(handle)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_SUBJECT_SCOPE_DENIED' } });
    expect(f.state.progress).toBe('claimed'); expect(f.repo.finishClaim).not.toHaveBeenCalled(); expect(f.executor.executeClaim).not.toHaveBeenCalled();
    await expect(f.policy().verifyOutcome(f.state.claim.id, 'failed', {}, f.db)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_GENUINE_COMPLETION_REQUIRED' } });
  });
  it('projects genuine read-only buttons without invoking any mutation and returns false only for current validation failures', async () => {
    const f = fixture(); f.install(); f.state.ownerHttp = true; f.state.progress = 'pending-approval';
    expect(await f.service.projection(f.row.id, f.actor)).toEqual({ activate: true, cancel: true });
    f.state.ownerGrants = false; expect(await f.service.projection(f.row.id, f.actor)).toEqual({ activate: false, cancel: false });
    f.state.ownerGrants = true; f.state.reviewerGrants = false; expect(await f.service.projection(f.row.id, f.actor)).toEqual({ activate: false, cancel: true });
    f.state.reviewerGrants = true; f.state.lifecycleFacts.source = true; expect(await f.service.projection(f.row.id, f.actor)).toEqual({ activate: false, cancel: true });
    await expect(f.service.activateApproved(f.row.id, f.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_ALREADY_EXECUTED' } });
    expect(f.repo.activate).not.toHaveBeenCalled();
    f.repo.get.mockRejectedValueOnce(new Error('Storage unavailable')); await expect(f.service.projection(f.row.id, f.actor)).rejects.toThrow('Storage unavailable');
    expect(f.repo.activate).not.toHaveBeenCalled(); expect(f.repo.finishClaim).not.toHaveBeenCalled(); expect(f.repo.appendDueClaim).not.toHaveBeenCalled();
  });
});
