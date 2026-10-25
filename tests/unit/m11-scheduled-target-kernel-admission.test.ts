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
function fixture(options: { baselineFailure?: boolean; adapterUnsupported?: boolean; weight?: number; create?: boolean; health?: boolean } = {}) {
  const secrets = new SecretService(), context = new KongExecutionContextService(), now = Date.now();
  const cid = randomUUID(), wid = randomUUID(), owner = randomUUID(), intentId = randomUUID(), workflowId = randomUUID(), nativeId = randomUUID();
  const sessionId = randomUUID(), authorityHandle = Object.freeze({}), originals = new WeakSet<object>([authorityHandle]);
  const expiresAt = new Date(now + 240000).toISOString(), permissionVersion = `${owner}:1:1`;
  const cluster: any = { id: cid, admin_url: 'http://kong:8001', revision: 1, execution_mode: 'approval', version: '1.5.1' };
  const scope = { transportScope: transportScopeFor(cluster.admin_url), clusterRevision: 1, workspaceRevision: 1 };
  const user = { id: owner, username: 'controlled-scheduled-owner', superAdmin: false };
  const actor: any = { user, workspaceId: wid, idempotencyKey: 'unit-http-original' };
  const upstreamId = randomUUID(), allocatedId = randomUUID();
  const before: any = options.create ? null : { id: nativeId, target: '192.0.2.10:8080', weight: 100, tags: [], upstream: { id: upstreamId }, created_at: 1 };
  const body: any = options.health ? undefined : { id: allocatedId, target: before?.target ?? '192.0.2.10:8080', weight: options.weight ?? 80, tags: [] };
  const packet: any = { key: 'packet-1', order: 1, dependencies: [], method: 'POST', canonicalPath: options.health ? `/upstreams/${upstreamId}/targets/${nativeId}/healthy` : `/upstreams/${upstreamId}/targets`,
    nativeType: 'targets', nativeId: options.health ? nativeId : allocatedId, parentId: upstreamId, ...(options.create || options.health ? {} : { originalNativeId: nativeId }), mutationAction: options.health ? 'mark_healthy' : options.create ? 'create' : 'update', permissionAction: 'write', before, body,
    beforeHmac: secrets.fingerprint(before), bodyHmac: secrets.fingerprint(body ?? null) };
  const initial = { version: 1, clusterId: cid, workspaceId: wid, requesterId: owner, scope, packets: [packet],
    metadataObligations: [] };
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

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.stubEnv('APP_SECRET', 'controlled-unit-secret-material-only-32'); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-14T07:00:00Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });
describe('Scheduled Target fixed Kernel admission, Source only with zero Native transport', () => {
  it.each([100, 80, 0])('weight %s enters the actual original-NS Source boundary and stops on the genuine capturer adapter failure', async weight => {
    const f = fixture({ baselineFailure: true, weight }); f.install(); const completion = await f.invoke();
    expect(f.state.sourceInserts).toBe(1); expect(f.state.source.session_id).toBeNull(); expect(f.state.source.origin_type).toBe('scheduled-entity');
    expect(f.capturer.capture).toHaveBeenCalledOnce(); expect(f.state.planReads.every(row => row.sessionId === null && row.namespace)).toBe(true);
    expect(await f.verify(f.authorityHandle, completion)).toBe('failed'); expect(f.writer.execute).not.toHaveBeenCalled(); expect(f.state.transportCalls).toBe(0);
  });
  it('Target create is included in the fixed allowlist without borrowing an HTTP identity', async () => {
    const f = fixture({ baselineFailure: true, create: true, weight: 100 }); f.install(); const completion = await f.invoke();
    expect(f.state.sourceInserts).toBe(1); expect(f.capturer.capture).toHaveBeenCalledOnce(); expect(await f.verify(f.authorityHandle, completion)).toBe('failed'); expect(f.state.transportCalls).toBe(0);
  });
  it('Target health remains closed before Source INSERT, capture or any write rather than pretending a node-health permission', async () => {
    const f = fixture({ baselineFailure: true, health: true }); f.install(); const completion = await f.invoke();
    expect(f.state.sourceInserts).toBe(0); expect(f.capturer.capture).not.toHaveBeenCalled(); expect(f.writer.execute).not.toHaveBeenCalled(); expect(await f.verify(f.authorityHandle, completion)).toBe('failed'); expect(f.state.transportCalls).toBe(0);
  });
});
