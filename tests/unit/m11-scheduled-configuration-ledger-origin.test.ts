import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { WorkflowScheduledConfigurationOriginService } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-configuration-origin.service';
import { workflowScheduleDraftAad } from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { immutableJson } from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import { m11LedgerIdentityFixture } from './helpers/m11-ledger-identity-fixture';

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'd8'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T16:00:00.000Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

/** Actual Origin handle minting, SQL inspection, AEAD wrapper/draft, Root and
 * normal Identity/Candidates. The native configuration-material reader is an
 * explicit controlled adapter; this is no live DB/transport/performance proof. */
function fixture() {
  const f = m11LedgerIdentityFixture(), wrapper = f.plan, payload = wrapper.steps[0].metadata;
  const ns = f.ns, c = ns.claim, draft = f.draft, now = Date.now(), wrapperId = randomUUID(), wrapperOriginId = randomUUID();
  const earlier = new Date(now - 60000).toISOString(), scheduledAt = new Date(now - 20000).toISOString();
  const job: any = { id: payload.jobId, cluster_id: f.cid, workspace_id: f.wid, actor_id: f.owner, workflow_id: wrapper.workflowId,
    origin_type: 'http', origin_session_id: randomUUID(), kind: 'apply', execution_mode: 'approval', approval_required: true,
    plan_id: payload.planId, plan_revision: payload.planRevision, plan_hash: payload.planHash, permission_version: ns.permissionVersion,
    credential_epoch: 1, cluster_revision: 1, workspace_revision: 1, transport_scope: ns.transportScope, authority_expires_at: wrapper.expiresAt,
    expires_at: wrapper.expiresAt, created_at: earlier, lease_generation: 1, lease_owner_hash: '8'.repeat(64), lease_until: ns.expiresAt,
    state: 'running', idempotency_key: 'source-original-configuration-ledger' };
  const material: any = { job, plan: { expiresAt: wrapper.expiresAt, baselineManifestHmac: '7'.repeat(64), steps: [] },
    version: { expires_at: wrapper.expiresAt, created_at: earlier }, planRow: {}, material: {}, sourceOrigin: null,
    subjectSeal: draft.binding.subjectSeal };
  const schedule: any = { id: c.scheduleId, kind: 'configuration_v2', executor_id: f.owner, owner_id: f.owner,
    workflow_id: wrapper.workflowId, workflow_plan_revision: wrapper.planRevision, workflow_plan_hash: ns.workflow.planHash,
    executor_credential_epoch: '1', owner_credential_epoch: '1', subject_seal_hmac: ns.subjectSealHmac, transport_scope: ns.transportScope,
    occurrence_id: c.occurrenceId, window_start: draft.spec.windowStart, not_before: draft.spec.notBefore, window_end: draft.spec.windowEnd,
    expires_at: draft.delegation.expiresAt, created_at: scheduledAt,
    draft_ciphertext: f.secrets.encrypt(draft, workflowScheduleDraftAad(f.cid, f.wid, c.scheduleId)), draft_hmac: f.secrets.fingerprint(draft) };
  const claim = { id: c.id, schedule_id: c.scheduleId, occurrence_id: c.occurrenceId, generation: 1, worker_owner_hmac: c.workerOwnerHmac,
    workflow_id: wrapper.workflowId, workflow_plan_revision: wrapper.planRevision, workflow_plan_hash: ns.workflow.planHash,
    issued_at: c.issuedAt, authority_expires_at: c.authorityExpiresAt };
  const progress = { claim_id: c.id, state: 'running' }, lease = { claim_id: c.id, worker_owner_hmac: c.workerOwnerHmac, lease_until: c.initialLeaseUntil };
  const wrapperOrigin: any = { id: wrapperOriginId, claim_id: c.id, schedule_id: c.scheduleId, executor_id: f.owner,
    cluster_id: f.cid, workspace_id: f.wid, workflow_id: wrapper.workflowId, workflow_plan_revision: wrapper.planRevision, workflow_plan_hash: ns.workflow.planHash };
  const wrapperExecution: any = { id: wrapperId, state: 'executing', execution_actor_id: f.owner, workflow_id: wrapper.workflowId,
    plan_revision: wrapper.planRevision, plan_hash: ns.workflow.planHash, cluster_id: f.cid, workspace_id: f.wid, expires_at: ns.expiresAt };
  const workflow = { state: 'executing', kind: 'configuration_v2', subject_type: 'configuration_jobs', subject_id: job.id,
    requester_type: 'console', requester_user_id: f.owner, plan_revision: wrapper.planRevision, plan_hash: ns.workflow.planHash };
  const wrapperVersion = { step_count: 1, native_request_count: 0, plan_hash: ns.workflow.planHash,
    steps_hash: f.secrets.fingerprint(wrapper.steps), payload_secret: f.secrets.encrypt(wrapper, planAad(f.cid, f.wid, wrapper.workflowId, wrapper.planRevision)) };
  const fullGrants = new Map<string, any[]>();
  for (const actor of [ns.actor, ...ns.approvalSet.reviewers.map((r: any) => ({ id: r.userId }))]) fullGrants.set(actor.id,
    ['workflows', 'snapshots'].flatMap(module => ['read', 'write', 'approve'].map(action => ({ user_id: actor.id, module, action,
      cluster_id: f.cid, workspace_id: f.wid, scope_type: 'global', scope_values: [] }))));
  const originalOne = f.db.one.getMockImplementation()!, originalQuery = f.db.query.getMockImplementation()!;
  let nested: any = null, nestedOrigin: any = null;
  f.db.one.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql.includes('FROM workflow_schedules')) return structuredClone(schedule);
    if (sql.includes('FROM workflow_schedule_claims')) return structuredClone(claim);
    if (sql.includes('FROM workflow_schedule_progress')) return structuredClone(progress);
    if (sql.includes('FROM workflow_schedule_leases')) return structuredClone(lease);
    if (sql.includes('FROM workflow_execution_origins')) return structuredClone(wrapperOrigin);
    if (sql.includes('FROM workflow_executions')) return structuredClone(wrapperExecution);
    if (sql.includes('FROM workflows WHERE cluster_id=')) return structuredClone(workflow);
    if (sql.includes('FROM workflow_versions WHERE cluster_id=')) return structuredClone(wrapperVersion);
    if (sql.includes('FROM workspaces WHERE cluster_id=')) return { id: f.wid, cluster_id: f.cid, status: 'active', revision: 1 };
    if (sql.includes('FROM workflow_approval_sets WHERE id=$1') && args.length === 1)
      return { set_hmac: ns.approvalSet.setHmac, workflow_id: wrapper.workflowId, plan_hash: ns.workflow.planHash };
    if (sql.includes('FROM users') && sql.includes('FOR SHARE')) return { id: args[0], status: 'active', deleted_at: null,
      force_password_change: false, super_admin: false, credential_epoch: 1, permissions_epoch: 1 };
    if (sql.includes('FROM iam_epoch') && sql.includes('FOR SHARE')) return { version: 1 };
    if (sql.includes('FROM configuration_executions')) return nested && structuredClone(nested);
    if (sql.includes('FROM workflow_configuration_execution_origins')) return nestedOrigin && structuredClone(nestedOrigin);
    if (sql.includes('FROM config_snapshot_versions')) return { completeness: 'complete', consistency: 'console_fenced_best_effort', manifest_hmac: material.plan.baselineManifestHmac };
    return originalOne(sql, args);
  });
  f.db.query.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql.includes('FROM iam_effective_grants')) return structuredClone(fullGrants.get(args[0]) ?? []);
    if (sql.includes('FROM workflow_approvals WHERE cluster_id=')) return ns.approvalSet.reviewers.map((r: any) => ({ id: r.approvalId,
      approver_id: r.userId, level: r.level, candidate_version: r.candidateVersion, created_at: new Date(now - 5000).toISOString() }));
    if (sql.includes('FROM configuration_job_steps') || sql.includes('FROM mutation_operations')) return [];
    return originalQuery(sql, args);
  });
  const namespaces: any = { assertLive: vi.fn((handle: object) => {
    if (handle !== f.nsHandle) throw Error('ORIGINAL_SOURCE_NAMESPACE_REQUIRED');
    f.context.requireWorkflowScheduledCurrentPrincipal(handle);
  }), verifyHandle: vi.fn(async (handle: object, _phase: string) => {
    if (handle !== f.nsHandle) throw Error('ORIGINAL_SOURCE_NAMESPACE_REQUIRED'); return ns;
  }) };
  const origin = new WorkflowScheduledConfigurationOriginService(f.db, f.secrets, f.redis, f.context, namespaces);
  const materialRead = vi.spyOn(origin as any, 'material').mockImplementation(async () => immutableJson(material));
  const ledger = vi.fn((handle: object, proof: any, tx: any) => f.guard(handle, proof, tx));
  const liveMaterial = vi.fn(async () => undefined), candidateRead = vi.fn(async () => undefined), candidateMaterial = vi.fn(async () => undefined);
  // These legacy tests exercise the unchanged full/ledger paths. They never
  // enter the new combined lifecycle; an accidental entry remains closed.
  const closedCheckpoint = () => { throw Error('LEGACY_FIXTURE_HAS_NO_COMBINED_CHECKPOINT_AUTHORITY'); };
  const root = { assertCandidateRead: candidateRead, assertCandidateMaterial: candidateMaterial, assertLedgerCurrent: ledger, assertLiveMaterial: liveMaterial,
    openClosedCheckpoint: async () => closedCheckpoint(), assertClosedCheckpoint: async () => closedCheckpoint(),
    assertClosedCheckpointLive: closedCheckpoint, releaseClosedCheckpoint: vi.fn() };
  origin.installRootVerifier(root);
  const run = <T>(fn: (handle: any) => Promise<T>) => f.namespace(() => origin.runOriginalJob(f.nsHandle, wrapperId, job.id,
    () => fn(origin.currentOriginalJobHandle())));
  const withNested = <T>(handle: any, fn: (original: any) => Promise<T>) => {
    const id = randomUUID(), originId = randomUUID();
    nested = { id, state: 'executing', execution_mode: 'approval', actor_id: f.owner, cluster_id: f.cid, workspace_id: f.wid,
      job_id: job.id, plan_id: job.plan_id, plan_revision: job.plan_revision, plan_hash: job.plan_hash, workflow_id: wrapper.workflowId,
      approved_version: wrapper.planRevision, workflow_plan_hash: ns.workflow.planHash, permission_version: ns.permissionVersion,
      claim_hash: '6'.repeat(64), lease_generation: 1, expires_at: ns.expiresAt, before_snapshot_id: randomUUID(), before_snapshot_version: 1 };
    nestedOrigin = { id: originId, wrapper_origin_id: wrapperOriginId, claim_id: c.id, workflow_execution_id: wrapperId,
      workflow_id: wrapper.workflowId, workflow_plan_revision: wrapper.planRevision, workflow_plan_hash: ns.workflow.planHash,
      configuration_job_id: job.id, configuration_plan_id: job.plan_id, configuration_plan_revision: job.plan_revision,
      configuration_plan_hash: job.plan_hash, cluster_id: f.cid, workspace_id: f.wid, workflow_step_id: wrapper.steps[0].id };
    return origin.runOriginalConfigurationExecution(handle, id, fn);
  };
  return { ...f, origin, namespaces, material, materialRead, ledger, liveMaterial, root, run, withNested, job, schedule, claim, progress, lease, wrapperOrigin,
    wrapperExecution, workflow, wrapperVersion, fullGrants };
}

describe('scheduled Origin ledger keeps real SQL identity without extra native subject scans', () => {
  it('rejects old, absent, partial and repeated Root installations without fallback', async () => {
    const f = fixture();
    const fresh = () => new WorkflowScheduledConfigurationOriginService(f.db, f.secrets, f.redis, f.context, f.namespaces);
    const { assertLedgerCurrent: _missing, ...oldRoot } = f.root;
    expect(() => fresh().installRootVerifier(oldRoot as any)).toThrow('One fixed complete');
    expect(() => fresh().installRootVerifier({ ...f.root, assertLedgerCurrent: undefined } as any)).toThrow('One fixed complete');
    expect(() => f.origin.installRootVerifier(f.root)).toThrow('One fixed complete');
    await expect((fresh() as any).fullApproval({ namespace: f.ns, namespaceHandle: f.nsHandle }, 'ledger', f.db))
      .rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ADAPTER_UNAVAILABLE' } });
  });
  it('calls actual Root and normal SQL identity on each ledger inspection with the original proof reference', async () => {
    const f = fixture();
    await f.run(async handle => {
      const fullBefore = f.namespaces.verifyHandle.mock.calls.length, liveBefore = f.liveMaterial.mock.calls.length;
      const first = await f.origin.verifyJobHandle(handle, 'ledger', f.db), reads = f.db.one.mock.calls.length;
      const second = await f.origin.verifyJobHandle(handle, 'ledger', f.db);
      expect(second).toEqual(first); expect(f.db.one.mock.calls.length).toBeGreaterThan(reads);
      expect(f.ledger).toHaveBeenCalledTimes(2); for (const [original, proof, tx] of f.ledger.mock.calls) {
        expect(original).toBe(f.nsHandle); expect(proof).toBe(f.ns); expect(tx).toBe(f.db);
      }
      expect(f.namespaces.verifyHandle.mock.calls.length).toBe(fullBefore); expect(f.liveMaterial.mock.calls.length).toBe(liveBefore);
      expect(first.sessionId).toBeNull(); expect(first.namespaceHandle).toBe(f.nsHandle);
      await expect(f.origin.verifyJobHandle({ ...handle }, 'ledger')).rejects.toThrow();
    }); expect(f.native).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['claim', 'capture', 'step', 'packet', 'before-send'] as const)('retains full Namespace and live native-material verification for %s', async phase => {
    const f = fixture();
    await f.run(async handle => f.withNested(handle, async () => {
      f.namespaces.verifyHandle.mockClear(); f.liveMaterial.mockClear(); f.ledger.mockClear();
      await f.origin.verifyJobHandle(handle, phase, f.db);
      expect(f.namespaces.verifyHandle).toHaveBeenCalledWith(f.nsHandle, phase);
      expect(f.liveMaterial).toHaveBeenCalledOnce(); expect(f.ledger).not.toHaveBeenCalled();
      f.liveMaterial.mockRejectedValueOnce(Error('CURRENT_NATIVE_MATERIAL_REVOKED'));
      await expect(f.origin.verifyJobHandle(handle, phase, f.db)).rejects.toThrow('CURRENT_NATIVE_MATERIAL_REVOKED');
    }));
  });
  it('keeps original execution ALS and fresh nested SQL on ledger execution proofs', async () => {
    const f = fixture();
    await f.run(async handle => f.withNested(handle, async execution => {
      const fullBefore = f.namespaces.verifyHandle.mock.calls.length, liveBefore = f.liveMaterial.mock.calls.length;
      const proof = await f.origin.verifyConfigurationExecution(execution, 'ledger', f.db);
      expect(proof.jobHandle).toBe(handle); expect(proof.namespaceHandle).toBe(f.nsHandle); expect(f.ledger).toHaveBeenCalledOnce();
      expect(f.namespaces.verifyHandle.mock.calls.length).toBe(fullBefore); expect(f.liveMaterial.mock.calls.length).toBe(liveBefore);
      await expect(f.origin.verifyConfigurationExecution({ ...execution }, 'ledger')).rejects.toThrow();
      f.job.lease_owner_hash = null;
      await expect(f.origin.verifyConfigurationExecution(execution, 'ledger')).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_NESTED_ORIGIN_INVALID' } });
    })); expect(f.native).not.toHaveBeenCalled();
  });
  it('does not let a prior ledger proof weaken the default packet checkpoint', async () => {
    const f = fixture();
    await f.run(async handle => {
      await f.origin.verifyJobHandle(handle, 'ledger');
      await expect(f.origin.verifyJobHandle(handle)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_NESTED_EXECUTION_REQUIRED' } });
      await f.withNested(handle, async () => {
        f.namespaces.verifyHandle.mockClear(); f.liveMaterial.mockClear(); f.ledger.mockClear();
        await f.origin.verifyJobHandle(handle);
        expect(f.namespaces.verifyHandle).toHaveBeenCalledWith(f.nsHandle, 'packet');
        expect(f.liveMaterial).toHaveBeenCalledOnce(); expect(f.ledger).not.toHaveBeenCalled();
      });
    }); expect(f.native).not.toHaveBeenCalled();
  });
  it.each(['subject', 'draft-hmac', 'claim', 'lease', 'wrapper', 'grant'] as const)('preserves actual Origin %s rejection before returning ledger evidence', async change => {
    const f = fixture();
    await f.run(async handle => {
      if (change === 'subject') f.job.actor_id = randomUUID();
      if (change === 'draft-hmac') f.schedule.draft_hmac = '0'.repeat(64);
      if (change === 'claim') f.progress.state = 'cancelled';
      if (change === 'lease') f.lease.lease_until = new Date(Date.now() - 1).toISOString();
      if (change === 'wrapper') f.wrapperExecution.plan_hash = '0'.repeat(64);
      if (change === 'grant') f.fullGrants.set(f.owner, []);
      await expect(f.origin.verifyJobHandle(handle, 'ledger', f.db)).rejects.toThrow();
    }); expect(f.native).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('cannot use a ledger DTO to enter the Native execution capability path', async () => {
    const f = fixture();
    await f.run(async handle => {
      const proof = await f.origin.verifyJobHandle(handle, 'ledger');
      await expect(f.origin.runOriginalConfigurationExecution(proof as any, randomUUID(), async () => undefined)).rejects.toThrow();
      await expect(f.context.runConfigurationJob(proof as any, async () => undefined)).rejects.toThrow();
    }); expect(f.native).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
});
