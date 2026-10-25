import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ConflictException, ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { immutableJson } from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { EntityChangeExecutionService } from '../../apps/console-api/src/modules/workflows/entity-change-execution.service';
import { EntityScheduledNamespaceService } from '../../apps/console-api/src/modules/workflows/entity-scheduled-namespace.service';
import type { EntityScheduledExecutorDelegate } from '../../apps/console-api/src/modules/workflows/entity-scheduled-authority.types';

/** Kernel.onModuleInit installs the real Namespace/Context runners and its
 * original completion registry. The authority/SQL/approval/domain adapters are
 * explicitly controlled fixtures. No Kernel WeakMap is seeded, no Source DTO
 * enters as authority and no native transport success is simulated. Real SQL024
 * owner/lease/approval/native acceptance remains Root's runtime gate. */
function fixture(options: { baselineFailure?: boolean; adapterUnsupported?: boolean } = {}) {
  const secrets = new SecretService(), context = new KongExecutionContextService(), now = Date.now();
  const cid = randomUUID(), wid = randomUUID(), owner = randomUUID(), intentId = randomUUID(), workflowId = randomUUID(), nativeId = randomUUID();
  const sessionId = randomUUID(), authorityHandle = Object.freeze({}), originals = new WeakSet<object>([authorityHandle]);
  const expiresAt = new Date(now + 240000).toISOString(), permissionVersion = `${owner}:1:1`;
  const cluster: any = { id: cid, admin_url: 'http://kong:8001', revision: 1, execution_mode: 'approval', version: '1.5.1' };
  const scope = { transportScope: transportScopeFor(cluster.admin_url), clusterRevision: 1, workspaceRevision: 1 };
  const user = { id: owner, username: 'controlled-scheduled-owner', superAdmin: false };
  const actor: any = { user, workspaceId: wid, idempotencyKey: 'unit-http-original' };
  const before = { id: nativeId, name: 'unit-scheduled-service', retries: 5, tags: [] }, body = { retries: 4 };
  const packet: any = { key: 'packet-1', order: 1, dependencies: [], method: 'PATCH', canonicalPath: `/services/${nativeId}`,
    nativeType: 'services', nativeId, mutationAction: 'update', permissionAction: 'write', before, body,
    beforeHmac: secrets.fingerprint(before), bodyHmac: secrets.fingerprint(body) };
  const initial = { version: 1, clusterId: cid, workspaceId: wid, requesterId: owner, scope, packets: [packet],
    metadataObligations: [{ kind: options.adapterUnsupported ? 'recycle-archive' : 'entity-index', entityType: 'services', packetKey: packet.key }] };
  const prepared: any = { ...initial, changeDigest: secrets.fingerprint(initial) };
  const delegation = { id: randomUUID(), ownerId: owner, executorId: owner, ownerCredentialEpoch: '1', executorCredentialEpoch: '1' };
  const envelope: any = { version: 2, intentId, revision: 1, clusterId: cid, workspaceId: wid, requesterId: owner,
    credentialEpoch: '1', executionMode: 'approval', expiresAt, prepared, packetManifestHmac: secrets.fingerprint([packet]),
    scheduling: { specHmac: 'b'.repeat(64), delegationHmac: 'c'.repeat(64), delegation } };
  const metadata = { intentId, intentRevision: 1, materialHmac: secrets.fingerprint(envelope), changeDigest: prepared.changeDigest,
    packetManifestHmac: envelope.packetManifestHmac };
  const plan: any = { version: 1, workflowId, planRevision: 1, kind: 'native-change', clusterId: cid, workspaceId: wid,
    executionMode: 'approval', approvalRequired: true, subject: { type: 'entity_change_intents', id: intentId },
    requester: { type: 'console', id: owner }, scope, issuedAt: new Date(now).toISOString(), expiresAt,
    definition: { id: randomUUID(), version: 1, policyHash: 'a'.repeat(64) }, prerequisites: [],
    steps: [{ id: randomUUID(), key: 'entity', order: 1, kind: 'metadata', handler: 'entity.change',
      entityType: 'entity_change_intents', entityId: intentId, permissionAction: 'write', dependencies: [], nativeRequests: [],
      metadata, metadataRevision: 1, metadataPayloadHmac: secrets.fingerprint(metadata), metadataBeforeHmac: secrets.fingerprint(null) }] };
  const workflow: any = { id: workflowId, state: 'approved', revision: 1, plan_hash: secrets.fingerprint(plan), approved_by: randomUUID() };
  const inspection: any = { version: 1, envelope, plan, principal: user, permissionVersion, authorityExpiresAt: expiresAt, leaseUntil: expiresAt,
    draft: { scheduleId: randomUUID(), binding: { clusterId: cid, workspaceId: wid, materialHmac: metadata.materialHmac,
      changeDigest: prepared.changeDigest, packetManifestHmac: envelope.packetManifestHmac },
      spec: { windowStart: new Date(now - 1000).toISOString(), windowEnd: expiresAt } },
    approvalSet: { format: 2, policyHash: 'd'.repeat(64), setId: randomUUID(), setHmac: 'e'.repeat(64),
      reviewers: [{ approvalId: randomUUID(), userId: randomUUID(), level: 1, candidateVersion: 1 }] } };
  inspection.claim = { id: randomUUID(), scheduleId: inspection.draft.scheduleId, scheduleVersion: 1, occurrenceId: randomUUID(), generation: 1,
    workerOwnerHmac: 'f'.repeat(64), issuedAt: new Date(now).toISOString(), authorityExpiresAt: expiresAt, initialLeaseUntil: expiresAt,
    workflowId, workflowPlanRevision: 1, workflowPlanHash: workflow.plan_hash };
  const state: any = { live: false, source: null, execution: null, transactionCount: 0, collision: null, planReads: [], sourceInserts: 0,
    callbackFailure: !options.baselineFailure, attemptInserts: 0, transportCalls: 0 };
  let delegate: Readonly<EntityScheduledExecutorDelegate> | undefined;
  const current = () => immutableJson(inspection);
  const authority: any = {
    installExecutor: vi.fn((value: EntityScheduledExecutorDelegate) => { if (delegate) throw new Error('once only'); delegate = Object.freeze(value); }),
    inspect: vi.fn(async (handle: object) => { if (!originals.has(handle)) throw new ForbiddenException({ code: 'CONTROLLED_ORIGINAL_AUTHORITY_REQUIRED' }); return current(); }),
    verifyClaim: vi.fn(async (handle: object) => {
      if (!originals.has(handle) || !state.live) throw new ForbiddenException({ code: 'CONTROLLED_ORIGINAL_AUTHORITY_REQUIRED' });
      return current();
    }),
  };
  const redis: any = { assertLeaseActive: vi.fn(() => { if (!state.live) throw new ForbiddenException({ code: 'CONTROLLED_LEASE_REQUIRED' }); }),
    assertLeaseOwnership: vi.fn(async () => { if (!state.live) throw new ForbiddenException({ code: 'CONTROLLED_LEASE_REQUIRED' }); }),
    withLock: vi.fn(async (_key: string, fn: () => Promise<any>) => fn()) };
  const db: any = {
    one: vi.fn(async (sql: string, values: any[] = []) => {
      if (sql.includes('SELECT s.claim_id,s.origin_type,s.session_id')) return state.source && values[0] === state.source.id ? {
        claim_id: state.source.claim_id, origin_type: state.source.origin_type, session_id: state.source.session_id,
        state: state.execution?.state, workflow_state: workflow.state,
      } : null;
      if (sql.includes('FROM entity_change_execution_sources')) return state.source && (values[0] === state.source.id || values[0] === state.source.claim_id) ? state.source : null;
      if (sql.includes('FROM workflow_executions') && sql.includes('JOIN workflows')) return state.execution ? { state: state.execution.state, workflow_state: workflow.state } : null;
      if (sql.includes('FROM workflow_executions')) return state.execution;
      if (sql.includes('FROM entity_change_packet_attempts')) return { pending: false };
      if (sql.includes('FROM auth_sessions')) return { expires_at: new Date(expiresAt), credential_epoch: '1', user_epoch: '1' };
      if (sql.includes('FROM iam_epoch')) return { version: 1 };
      if (sql.includes('FROM entity_change_schedules')) return state.collision;
      if (sql.includes('FROM clusters')) return cluster;
      if (sql.includes('FROM workspaces')) return { id: wid, revision: 1, status: 'active' };
      if (sql.includes('FROM workflows')) return workflow;
      if (sql.includes('FROM mutation_operations')) return state.operation && values[0] === state.operation.id ? state.operation : null;
      throw new Error('Unexpected controlled SQL read');
    }),
    query: vi.fn(async (sql: string) => sql.includes('entity_change_schedules') && state.collision ? [state.collision] : []),
    exec: vi.fn(async (sql: string, values: any[] = []) => {
      if (sql.startsWith('INSERT INTO entity_change_execution_sources')) {
        state.sourceInserts++;
        const common = ['id', 'cluster_id', 'workspace_id', 'intent_id', 'intent_revision', 'material_hmac', 'change_digest', 'packet_manifest_hmac',
          'workflow_id', 'workflow_plan_revision', 'workflow_plan_hash', 'workflow_execution_id', 'execution_actor_id', 'credential_epoch'];
        state.source = Object.fromEntries(common.map((key, index) => [key, values[index]]));
        Object.assign(state.source, { session_id: null, permission_version_hmac: values[14], issued_at: values[15], expires_at: values[16],
          origin_type: 'scheduled-entity', schedule_id: values[17], schedule_version: 1, spec_hmac: values[18], delegation_id: values[19],
          delegation_version: 1, delegation_hmac: values[20], occurrence_id: values[21], claim_id: values[22], claim_generation: 1,
          worker_owner_hmac: values[23], window_start: values[24], window_end: values[25] });
      } else if (sql.startsWith('INSERT INTO workflow_executions')) state.execution = { id: values[0], state: 'executing' };
      else if (sql.startsWith("UPDATE workflows SET state='executing'")) { workflow.state = 'executing'; workflow.revision++; }
      else if (sql.startsWith('UPDATE workflows SET state=$2')) workflow.state = values[1];
      else if (sql.startsWith('UPDATE workflow_executions SET state=$2')) state.execution.state = values[1];
      return 1;
    }), transaction: vi.fn(async (fn: any) => { state.transactionCount++; return fn(db); }),
  };
  const capturer: any = { capture: vi.fn(async () => { throw new ConflictException({ code: 'CONTROLLED_BASELINE_CHANGED' }); }) };
  const facts: any = { installFixedDelegate: vi.fn(), persistReady: vi.fn(), appendAttempt: vi.fn(() => { state.attemptInserts++; }), appendOutcome: vi.fn() };
  const writer: any = { installExecutionDelegate: vi.fn(), execute: vi.fn() };
  const plans: any = { load: vi.fn(async () => {
    const frame = context.current(); state.planReads.push({ kind: frame.kind, actorId: frame.actor?.id, sessionId: frame.sessionId ?? null,
      namespace: context.hasEntityScheduledNamespace(), proof: await context.verifyEntityScheduledNamespace('claim') });
    if (state.callbackFailure) throw new ConflictException({ code: 'CONTROLLED_PLAN_CHANGED' });
    return { plan, row: { ...workflow } };
  }) };
  const kong: any = { transportScope: vi.fn(async () => scope.transportScope), request: vi.fn(() => { state.transportCalls++; throw new Error('No native request allowed in this test'); }) };
  const authz: any = { permissionVersion: vi.fn(async () => permissionVersion) }, audit: any = { append: vi.fn(async () => undefined) };
  const approval: any = { verifyApprovalSet: vi.fn(async () => inspection.approvalSet) }, intents: any = { executionMaterial: vi.fn(async () => envelope) };
  const namespace = new EntityScheduledNamespaceService(authority, secrets, redis);
  const kernel = new EntityChangeExecutionService(db, redis, secrets, context, kong, authz, audit, plans, approval, intents, facts, capturer, writer,
    {} as any, undefined, authority, namespace);
  const install = () => kernel.onModuleInit();
  const invoke = async (handle: object = authorityHandle): Promise<object> => {
    if (!delegate) throw new Error('Root executor not installed');
    state.live = true;
    try { return await delegate.executeClaim(handle); } finally { state.live = false; }
  };
  const verify = (handle: object, completion: object) => delegate!.verifyCompletion(handle, completion, db);
  return { kernel, context, namespace, authority, authorityHandle, actor, cluster, cid, wid, sessionId, plan, inspection, workflow, state,
    db, redis, capturer, facts, writer, audit, approval, kong, plans, install, invoke, verify };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.stubEnv('APP_SECRET', 'controlled-unit-secret-material-only-32');
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T17:30:00.000Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('M11 scheduled Root Kernel integration (source-only, zero native transport)', () => {
  it('installs one actual Namespace/Context runner and one original Root completion verifier', () => {
    const f = fixture(); f.install(); expect(f.authority.installExecutor).toHaveBeenCalledTimes(1);
    expect(f.writer.installExecutionDelegate).toHaveBeenCalledTimes(1); expect(f.facts.installFixedDelegate).toHaveBeenCalledTimes(1);
    expect(() => f.install()).toThrow();
  });
  it('rejects inspection-shaped and copied original authority handles before SQL or any native writer', async () => {
    const f = fixture(); f.install();
    for (const copied of [{ ...f.authorityHandle }, { ...f.inspection }, { ...f.inspection.claim }, []])
      await expect(f.invoke(copied)).rejects.toMatchObject({ response: { code: 'CONTROLLED_ORIGINAL_AUTHORITY_REQUIRED' } });
    expect(f.db.one).not.toHaveBeenCalled(); expect(f.plans.load).not.toHaveBeenCalled(); expect(f.writer.execute).not.toHaveBeenCalled();
  });
  it('does not allow a copied namespace/proof to establish an ALS context', async () => {
    const f = fixture(); f.install(); f.state.live = true;
    try { for (const copied of [{}, { ...f.inspection }, { sessionId: null, origin: 'scheduled-entity', actor: f.actor.user }])
      await expect(f.context.runEntityScheduledNamespace(copied, async () => true)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_ORIGINAL_HANDLE_REQUIRED' } });
    } finally { f.state.live = false; }
    expect(f.context.peek()).toBeNull(); expect(f.authority.verifyClaim).not.toHaveBeenCalled(); expect(f.db.one).not.toHaveBeenCalled();
  });
  it.each(['http', 'internal', 'system'])('refuses inherited %s context without adopting its actor/session', async kind => {
    const f = fixture(); f.install(); const invoke = async () => {
      const previous = f.context.current(); await expect(f.invoke()).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_NAMESPACE_REQUIRED' } });
      expect(f.context.current()).toBe(previous);
    };
    if (kind === 'system') await f.context.runSystemRead(f.cid, 'probe', invoke);
    else await f.context.runHttp({}, async () => {
      f.context.bindHttpActor(f.actor.user, f.sessionId);
      if (kind === 'http') await invoke();
      else await f.context.runActor({ actor: f.actor.user, clusterId: f.cid, workspaceId: f.wid },
        () => f.context.runInternalRead(f.cid, 'entity-preflight', invoke));
    });
    expect(f.authority.inspect).not.toHaveBeenCalled(); expect(f.db.one).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });
  it('creates a genuine no-SID scheduled frame then returns a truthful zero-source failed completion', async () => {
    const f = fixture(); f.install(); const completion = await f.invoke();
    expect(f.state.planReads).toHaveLength(1); expect(f.state.planReads[0]).toMatchObject({ kind: 'scheduled-entity', actorId: f.actor.user.id, sessionId: null, namespace: true });
    expect(f.state.planReads[0].proof).toMatchObject({ origin: 'scheduled-entity', sessionId: null, claim: { id: f.inspection.claim.id } });
    expect(Object.isFrozen(completion)).toBe(true); expect(Object.keys(completion)).toEqual([]);
    expect(await f.verify(f.authorityHandle, completion)).toBe('failed');
    // Independent Authority + Repository checks must accept the SAME original
    // evidence twice; completion verification grants no new execution handle.
    expect(await f.verify(f.authorityHandle, completion)).toBe('failed');
    expect(f.state.sourceInserts).toBe(0); expect(f.state.execution).toBeNull(); expect(f.state.attemptInserts).toBe(0);
    expect(f.capturer.capture).not.toHaveBeenCalled(); expect(f.writer.execute).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
    expect(f.context.peek()).toBeNull();
    await expect(f.context.runEntityScheduledNamespace(f.state.planReads[0].proof, async () => true)).rejects.toMatchObject({ status: 403 });
  });
  it('refuses copied completion, mismatched authority, and newly contradictory durable facts', async () => {
    const f = fixture(); f.install(); const completion = await f.invoke();
    for (const copied of [{ ...completion }, { outcome: 'failed', claimId: f.inspection.claim.id }])
      await expect(f.verify(f.authorityHandle, copied)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_GENUINE_COMPLETION_REQUIRED' } });
    await expect(f.verify({ ...f.authorityHandle }, completion)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_GENUINE_COMPLETION_REQUIRED' } });
    f.state.execution = { id: randomUUID(), state: 'uncertain' };
    await expect(f.verify(f.authorityHandle, completion)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_COMPLETION_FACTS_INVALID' } });
    expect(f.writer.execute).not.toHaveBeenCalled();
  });
  it('fails closed for an unsupported recycle adapter before allocating any scheduled Source', async () => {
    const f = fixture({ adapterUnsupported: true }); f.install(); const completion = await f.invoke();
    expect(await f.verify(f.authorityHandle, completion)).toBe('failed'); expect(f.plans.load).not.toHaveBeenCalled();
    expect(f.state.sourceInserts).toBe(0); expect(f.capturer.capture).not.toHaveBeenCalled(); expect(f.writer.execute).not.toHaveBeenCalled();
  });
  it('records a real Kernel-issued scheduled Source and failed baseline without allocating any packet', async () => {
    const f = fixture({ baselineFailure: true }); f.install(); const completion = await f.invoke();
    expect(f.state.sourceInserts).toBe(1); expect(f.state.source).toMatchObject({ origin_type: 'scheduled-entity', session_id: null,
      claim_id: f.inspection.claim.id, execution_actor_id: f.actor.user.id, schedule_id: f.inspection.claim.scheduleId });
    expect(f.workflow.state).toBe('failed'); expect(f.state.execution.state).toBe('failed');
    expect(await f.verify(f.authorityHandle, completion)).toBe('failed'); expect(await f.verify(f.authorityHandle, completion)).toBe('failed');
    expect(f.capturer.capture).toHaveBeenCalledTimes(1); expect(f.facts.persistReady).not.toHaveBeenCalled();
    expect(f.facts.appendAttempt).not.toHaveBeenCalled(); expect(f.writer.execute).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
    expect(f.redis.withLock.mock.calls.map(call => call[0])).toEqual([`mutation:${f.plan.scope.transportScope}`]);
    // Changing to HTTP-looking or unknown durable evidence cannot relabel the
    // original scheduled completion, even after the namespace has closed.
    f.state.source.session_id = f.sessionId;
    await expect(f.verify(f.authorityHandle, completion)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_COMPLETION_FACTS_INVALID' } });
  });
  it('retains the existing HTTP SID guard and original actor frame on the public execute path', async () => {
    const f = fixture(); f.install(); const body = { revision: 1, planHash: f.workflow.plan_hash, confirmed: true, confirm_name: 'native-change' };
    await f.context.runHttp({}, async () => {
      f.context.bindHttpActor(f.actor.user); await f.context.runActor({ actor: f.actor.user, clusterId: f.cid, workspaceId: f.wid }, async () => {
        await expect(f.kernel.execute(f.plan, body, f.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_EXECUTION_PROOF_INVALID' } });
      });
    });
    expect(f.plans.load).not.toHaveBeenCalled();
    await f.context.runHttp({}, async () => {
      f.context.bindHttpActor(f.actor.user, f.sessionId); await f.context.runActor({ actor: f.actor.user, clusterId: f.cid, workspaceId: f.wid }, async () => {
        await expect(f.kernel.execute(f.plan, body, f.actor)).rejects.toMatchObject({ response: { code: 'CONTROLLED_PLAN_CHANGED' } });
      });
    });
    expect(f.state.planReads[0]).toMatchObject({ kind: 'actor', sessionId: f.sessionId, namespace: false, proof: null });
    expect(f.authority.inspect).not.toHaveBeenCalled(); expect(f.authority.verifyClaim).not.toHaveBeenCalled(); expect(f.state.sourceInserts).toBe(0);
  });
  it('checks an active conflicting schedule before an ordinary HTTP native send', async () => {
    const f = fixture(); f.install(); f.state.collision = { id: randomUUID() };
    const operationId = randomUUID();
    f.state.operation = { id: operationId, actor_id: f.actor.user.id, cluster_id: f.cid, state: 'running', transport_scope: f.plan.scope.transportScope };
    f.context.installPolicy({ authorizeRequest: async () => ({ before: null }), authorizeResponse: async (_decision, response) => response });
    await f.context.runHttp({}, async () => {
      f.context.bindHttpActor(f.actor.user, f.sessionId);
      await f.context.runActor({ actor: f.actor.user, clusterId: f.cid, workspaceId: f.wid }, () => f.context.runOperation({
        actor: f.actor.user, clusterId: f.cid, workspaceId: f.wid, operationId, entityType: 'services', action: 'update', entityId: randomUUID(),
      }, async () => {
        const ticket = await f.context.authorizeRequest(f.cluster, 'PATCH', `/services/${randomUUID()}`, { retries: 4 }, {});
        await expect(f.context.beforeNativeSend(ticket)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_PHYSICAL_IMPACT_CONFLICT' } });
      }));
    });
    expect(f.db.one).toHaveBeenCalledWith(expect.stringContaining('m6_rejected_impact_collision'), expect.any(Array));
    expect(f.authority.verifyClaim).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled(); expect(f.state.transportCalls).toBe(0);
  });
});
