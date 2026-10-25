import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { WorkflowScheduledConfigurationOriginService } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-configuration-origin.service';
import { workflowScheduleDraftAad } from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { SnapshotCryptoService } from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import { immutableJson } from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import { m11LedgerIdentityFixture } from './helpers/m11-ledger-identity-fixture';

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'd8'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T16:00:00.000Z')); });
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });

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
  const rows: any[] = [], operations: any[] = [], baseline: any = { completeness: 'complete', consistency: 'console_fenced_best_effort', manifest_hmac: material.plan.baselineManifestHmac };
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
    if (sql.includes('FROM config_snapshot_versions')) return structuredClone(baseline);
    return originalOne(sql, args);
  });
  f.db.query.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql.includes('FROM iam_effective_grants')) return structuredClone(fullGrants.get(args[0]) ?? []);
    if (sql.includes('FROM workflow_approvals WHERE cluster_id=')) return ns.approvalSet.reviewers.map((r: any) => ({ id: r.approvalId,
      approver_id: r.userId, level: r.level, candidate_version: r.candidateVersion, created_at: new Date(now - 5000).toISOString() }));
    if (sql.includes('FROM configuration_job_steps')) return structuredClone(rows);
    if (sql.includes('FROM mutation_operations')) return structuredClone(operations);
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
  const liveMaterial = vi.fn(async (_inspection: any, _checkpoint: any, _tx: any) => undefined), candidateRead = vi.fn(async () => undefined), candidateMaterial = vi.fn(async () => undefined);
  // This adapter exercises Origin's one-shot comparison lifecycle. Canonical
  // ApprovalAuthority and effective-grant clock behavior have separate tests.
  const observations = new WeakMap<object, any>();
  const stamp = () => f.secrets.fingerprint([...fullGrants].sort(([a], [b]) => a.localeCompare(b)));
  const open = vi.fn(async (handle: object, proof: any, phase: string, tx: any) => {
    expect(handle).toBe(f.nsHandle); expect(proof).toBe(f.ns);
    await f.guard(handle, proof, tx);
    const token = Object.freeze({}); observations.set(token, { handle, proof, phase, tx, state: 'open', deadline: Infinity, stamp: stamp(), frame: f.context.current() }); return token;
  });
  const close = vi.fn(async (token: object, handle: object, proof: any, phase: string, tx: any) => {
    const opening = observations.get(token);
    if (!opening) throw Error('ORIGINAL_CLOSED_OBSERVATION_REQUIRED');
    if (opening.state !== 'open') { opening.state = 'poisoned'; throw Error('ORIGINAL_CLOSED_OBSERVATION_REQUIRED'); }
    opening.state = 'closing';
    try {
      if (opening.handle !== handle || opening.proof !== proof || opening.phase !== phase || opening.tx !== tx
        || opening.frame !== f.context.current()) throw Error('ORIGINAL_CLOSED_OBSERVATION_REQUIRED');
      await f.guard(handle, proof, tx);
      if (opening.stamp !== stamp()) throw Error('COMPLETE_CURRENT_GRANTS_CHANGED');
      if (opening.state !== 'closing') throw Error('ORIGINAL_CLOSED_OBSERVATION_REQUIRED');
      opening.state = 'sealed';
    } catch (error) { opening.state = 'poisoned'; throw error; }
  });
  const assertLive = vi.fn((token: object, handle: object, proof: any, phase: string, tx: any) => {
    const opening = observations.get(token);
    if (!opening) throw Error('ORIGINAL_SEALED_OBSERVATION_REQUIRED');
    try {
      if (opening.state !== 'sealed' || opening.handle !== handle || opening.proof !== proof || opening.phase !== phase
        || opening.tx !== tx || opening.frame !== f.context.current()) throw Error('ORIGINAL_SEALED_OBSERVATION_REQUIRED');
      if (opening.deadline <= Date.now()) throw Error('CURRENT_GRANT_DEADLINE_EXPIRED');
    } catch (error) { opening.state = 'poisoned'; throw error; }
  });
  const release = vi.fn((token: object) => { const opening = observations.get(token); if (opening) opening.state = 'released'; observations.delete(token); });
  const root = { assertCandidateRead: candidateRead, assertCandidateMaterial: candidateMaterial, assertLedgerCurrent: ledger,
    assertLiveMaterial: liveMaterial, openClosedCheckpoint: open, assertClosedCheckpoint: close, assertClosedCheckpointLive: assertLive, releaseClosedCheckpoint: release };
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
    wrapperExecution, workflow, wrapperVersion, fullGrants, rows, operations, baseline, open, close, assertLive, release, observations,
    get nested() { return nested; }, get nestedOrigin() { return nestedOrigin; } };
}


/** Real material parser/AEAD exercises the marker-to-source-scope invariant. */
async function sourceMaterialFixture(promoted = false) {
  const f = fixture(), now = Date.now(), cid = randomUUID(), wid = randomUUID(), jobId = randomUUID(), sourceJob = randomUUID(), planId = randomUUID();
  const materialId = randomUUID(), artifactId = randomUUID(), originId = randomUUID(), sourceCid = randomUUID(), sourceWid = randomUUID(), originHmac = 'b'.repeat(64);
  const plan: any = { scope: { clusterId: cid, workspaceId: wid, transportScope: 'a'.repeat(64), kind: 'workspace', rootIds: [] },
    permissionVersion: 'current-source-pv', clusterRevision: 1, workspaceRevision: 1, kongVersion: '1.5.1', recoveryComplete: true,
    steps: [], expiresAt: new Date(now + 60000).toISOString(), schemaHmac: 'c'.repeat(64), sourceManifestHmac: 'd'.repeat(64), baselineManifestHmac: 'e'.repeat(64),
    ...(promoted ? { originRef: { version: 1, kind: 'governance-promote', originId, materialHmac: originHmac } } : {}) };
  const job: any = { id: jobId, cluster_id: cid, workspace_id: wid, actor_id: randomUUID(), origin_type: 'http', origin_session_id: randomUUID(),
    kind: 'apply', execution_mode: 'approval', approval_required: true, plan_id: planId, workflow_id: randomUUID(), plan_revision: 1,
    plan_hash: f.secrets.fingerprint(plan), transport_scope: plan.scope.transportScope, request_hmac: 'f'.repeat(64), scope_kind: 'workspace', root_ids: [],
    permission_version: plan.permissionVersion, cluster_revision: 1, workspace_revision: 1, credential_epoch: 1,
    authority_expires_at: plan.expiresAt, expires_at: plan.expiresAt, created_at: new Date(now - 60000).toISOString(),
    ...(promoted ? { required_origin_kind: 'governance-promote', required_origin_id: originId, required_origin_hmac: originHmac } : {}) };
  const identity = { clusterId: cid, workspaceId: wid, jobId: sourceJob, materialId, artifactId, artifactKind: 'plan' as const };
  const crypto = new SnapshotCryptoService(f.secrets), wrapped = crypto.createWrappedKey(identity);
  const version: any = { plan_id: planId, plan_revision: 1, source_job_id: sourceJob, plan_hash: job.plan_hash, input_hmac: job.plan_hash,
    steps_hmac: f.secrets.fingerprint([]), step_count: 0, native_packet_count: 0, material_id: materialId, artifact_id: artifactId,
    schema_hmac: plan.schemaHmac, source_manifest_hmac: plan.sourceManifestHmac, baseline_manifest_hmac: plan.baselineManifestHmac,
    created_at: job.created_at, expires_at: plan.expiresAt,
    manifest_ciphertext: await crypto.withKey(identity, wrapped, async key => crypto.encrypt(key, identity, { section: 'manifest', key: 'plan' }, plan)) };
  const material: any = { id: materialId, job_id: sourceJob, artifact_id: artifactId, artifact_kind: 'plan', state: 'available', wrapped_key_secret: wrapped };
  const planRow = { current_revision: 1, transport_scope: job.transport_scope };
  let jobOrigin: any = promoted ? { origin_kind: 'governance-promote', origin_id: originId, material_hmac: originHmac, source_cluster_id: sourceCid, source_workspace_id: sourceWid } : null;
  let planOrigin: any = promoted ? { origin_kind: 'governance-promote', origin_id: originId, material_hmac: originHmac, job_id: sourceJob } : null;
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('FROM configuration_jobs')) return structuredClone(job);
    if (sql.includes('FROM configuration_plans')) return structuredClone(planRow);
    if (sql.includes('FROM configuration_plan_versions')) return structuredClone(version);
    if (sql.includes('FROM configuration_materials')) return structuredClone(material);
    if (sql.includes('FROM configuration_job_origin_bindings')) return jobOrigin && structuredClone(jobOrigin);
    if (sql.includes('FROM configuration_plan_origin_bindings')) return planOrigin && structuredClone(planOrigin);
    throw Error('UNEXPECTED_SOURCE_MATERIAL_SQL');
  }), query: vi.fn(async () => []), exec: vi.fn() };
  const origin = new WorkflowScheduledConfigurationOriginService(db, f.secrets, f.redis, f.context, f.namespaces);
  const read = () => (origin as any).material(jobId, db);
  const reseal = async () => { job.plan_hash = f.secrets.fingerprint(plan); version.plan_hash = job.plan_hash; version.input_hmac = job.plan_hash;
    version.manifest_ciphertext = await crypto.withKey(identity, wrapped, async key => crypto.encrypt(key, identity, { section: 'manifest', key: 'plan' }, plan)); };
  return { job, plan, sourceCid, sourceWid, read, reseal, db, setJobOrigin(value: any) { jobOrigin = value; }, setPlanOrigin(value: any) { planOrigin = value; } };
}

describe('one closed original configuration execution and job observation', () => {
  it.each(['step', 'packet', 'before-send'] as const)('performs exactly one full Native gate and a fresh complete SQL tail for %s', async phase => {
    const f = fixture();
    await f.run(async job => f.withNested(job, async execution => {
      f.namespaces.verifyHandle.mockClear(); f.liveMaterial.mockClear(); f.ledger.mockClear(); f.materialRead.mockClear();
      const pair = await f.origin.verifyOriginalExecutionAndJob(job, execution, phase, f.db);
      expect(f.namespaces.verifyHandle).toHaveBeenCalledExactlyOnceWith(f.nsHandle, phase);
      expect(f.liveMaterial).toHaveBeenCalledOnce(); expect(f.liveMaterial.mock.calls[0][2]).toBe(f.db);
      expect(f.materialRead).toHaveBeenCalledTimes(2); expect(f.ledger).toHaveBeenCalledOnce();
      expect(f.open).toHaveBeenCalledOnce(); expect(f.close).toHaveBeenCalledOnce(); expect(f.assertLive).toHaveBeenCalledTimes(3); expect(f.release).toHaveBeenCalledOnce();
      const [handle, proof, checkpoint, tx] = f.open.mock.calls[0];
      expect(Object.isFrozen(tx)).toBe(true); expect(Object.getPrototypeOf(tx)).toBeNull();
      expect(Object.keys(tx).sort()).toEqual(['exec', 'one', 'query', 'transaction']); expect(tx.pool).toBeUndefined(); expect(tx.connection).toBeUndefined();
      expect(handle).toBe(f.nsHandle); expect(proof).toBe(f.ns); expect(checkpoint).toBe(phase); expect(tx).not.toBe(f.db);
      expect(f.close.mock.calls[0]).toEqual([f.release.mock.calls[0][0], handle, proof, phase, tx]);
      expect(f.open.mock.invocationCallOrder[0]).toBeLessThan(f.namespaces.verifyHandle.mock.invocationCallOrder[0]);
      expect(f.liveMaterial.mock.invocationCallOrder[0]).toBeLessThan(f.close.mock.invocationCallOrder[0]);
      expect(pair.execution.jobHandle).toBe(job); expect(pair.job.namespaceHandle).toBe(f.nsHandle);
      expect(pair.execution.configurationExecutionId).toBe(f.nested.id); expect(pair.execution.configurationOriginId).toBe(f.nestedOrigin.id);
      expect(pair.job.jobId).toBe(pair.execution.configurationJobId); expect(pair.job.planHash).toBe(pair.execution.configurationPlanHash);
      expect(pair.job.leaseGeneration).toBe(pair.execution.leaseGeneration); expect(pair.job.expiresAt).toBe(pair.execution.expiresAt);
      expect(pair.job.expiresAt).toBeLessThanOrEqual(Date.parse(f.ns.expiresAt));
      expect(Object.isFrozen(pair) && Object.isFrozen(pair.job) && Object.isFrozen(pair.execution)).toBe(true);
      expect(f.observations.has(f.release.mock.calls[0][0])).toBe(false);
    })); expect(f.db.exec).not.toHaveBeenCalled(); expect(f.native).not.toHaveBeenCalled();
  });
  it('composes real CurrentIdentity SQL guards with the frozen Origin facade through the complete close', async () => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      f.identitySpy.mockClear(); f.repository.inspectStored.mockClear(); f.db.one.mockClear(); f.db.query.mockClear();
      const pair = await f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db);
      const facade = f.open.mock.calls[0][3];
      expect(f.identitySpy).toHaveBeenCalledTimes(3);
      for (const call of f.identitySpy.mock.calls) expect(call).toEqual([f.nsHandle, f.ns, f.owner, facade]);
      const boundaries = f.repository.inspectStored.mock.calls.map((call: any[]) => call[1]);
      expect(boundaries.length).toBeGreaterThan(0);
      for (const boundary of boundaries) {
        expect(boundary).not.toBe(facade); expect(boundary).not.toBe(f.db);
        expect(Object.getPrototypeOf(boundary)).toBeNull(); expect(Object.isFrozen(boundary)).toBe(true);
      }
      expect(f.db.one.mock.calls.some(([sql]: any[]) => sql.includes('FROM schema_migrations'))).toBe(true);
      expect(f.db.query.mock.calls.some(([sql]: any[]) => sql.includes('FROM workflow_approval_set_members'))).toBe(true);
      expect(pair.execution.jobHandle).toBe(job); expect(pair.job.namespaceHandle).toBe(f.nsHandle);
      expect(f.close).toHaveBeenCalledOnce(); expect(f.release).toHaveBeenCalledOnce();
      expect(f.db.exec).not.toHaveBeenCalled(); expect(f.native).not.toHaveBeenCalled();
    }));
  });
  it.each(['exec', 'transaction', 'one', 'query', 'multistatement'] as const)(
    'denies %s through the real nested CurrentIdentity boundary before reaching SQL', async method => {
      const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
        f.db.one.mockClear(); f.db.query.mockClear();
        f.repository.inspectStored.mockImplementationOnce(async (_schedule: string, boundary: any) => {
          const before = [f.db.one.mock.calls.length, f.db.query.mock.calls.length];
          const invoke = () => method === 'transaction' ? boundary.transaction(async () => undefined)
            : method === 'multistatement' ? boundary.one('SELECT 1; UPDATE users SET force_password_change=true')
            : boundary[method]('UPDATE users SET force_password_change=true RETURNING id');
          const denied = Promise.resolve().then(invoke);
          await expect(denied).rejects.toMatchObject({ response: { code: method === 'multistatement'
            ? 'WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_SQL_READ_ONLY' : 'WORKFLOW_BUSINESS_IDENTITY_SQL_READ_ONLY' } });
          expect([f.db.one.mock.calls.length, f.db.query.mock.calls.length]).toEqual(before);
          // Propagate the real denial; a failed observer must not return proof.
          return denied;
        });
        await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db)).rejects.toMatchObject({ response: { code:
          method === 'multistatement' ? 'WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_SQL_READ_ONLY' : 'WORKFLOW_BUSINESS_IDENTITY_SQL_READ_ONLY' } });
        expect(f.close).not.toHaveBeenCalled(); expect(f.release).not.toHaveBeenCalled();
        expect(f.db.exec).not.toHaveBeenCalled(); expect(f.native).not.toHaveBeenCalled();
      }));
    });
  it('keeps property, descriptor and prototype extraction narrow and fences all held reads after close', async () => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      let inner: any;
      const inspect = f.repository.inspectStored.getMockImplementation()!;
      f.repository.inspectStored.mockImplementationOnce(async (...args: any[]) => { inner = args[1]; return inspect(...args); });
      await f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db);
      const facade = f.open.mock.calls[0][3], held: Array<() => Promise<unknown>> = [];
      expect(inner).toBeDefined(); expect(inner).not.toBe(facade);
      for (const boundary of [facade, inner]) {
        expect(Object.isFrozen(boundary)).toBe(true); expect(Object.getPrototypeOf(boundary)).toBeNull();
        expect(Reflect.ownKeys(boundary).sort()).toEqual(['exec', 'one', 'query', 'transaction']);
        for (const name of ['pool', 'connection', 'client', 'raw', 'db', 'database', 'constructor', 'prototype', '__proto__', 'connect'])
          expect(Reflect.get(boundary, name)).toBeUndefined();
        expect(Reflect.set(boundary, 'one', f.db.one)).toBe(false);
        expect(Reflect.set(boundary, 'raw', f.db)).toBe(false);
        expect(Reflect.defineProperty(boundary, 'one', { value: f.db.one })).toBe(false);
        expect(Reflect.deleteProperty(boundary, 'one')).toBe(false);
        expect(Reflect.setPrototypeOf(boundary, f.db)).toBe(false);
        for (const method of ['one', 'query', 'exec', 'transaction']) {
          const descriptor = Object.getOwnPropertyDescriptor(boundary, method)!;
          expect(descriptor.configurable).toBe(false); expect(descriptor.set).toBeUndefined();
          expect(descriptor.value).toBeUndefined(); expect(typeof descriptor.get).toBe('function');
          const extracted = descriptor.get!.call(f.db);
          expect(extracted).toBe(descriptor.get!.call(null));
          if (method === 'one' || method === 'query') {
            held.push(() => extracted.call(f.db, 'SELECT version FROM iam_epoch WHERE singleton=true'));
            const direct = boundary[method];
            held.push(() => direct.call(f.db, 'SELECT version FROM iam_epoch WHERE singleton=true'));
          } else expect(() => extracted.call(f.db)).toThrowError(expect.objectContaining({ response: {
            code: 'WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_SQL_READ_ONLY' } }));
        }
      }
      f.db.one.mockClear(); f.db.query.mockClear();
      for (const read of held) await expect(read()).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_CONTEXT_CHANGED' } });
      expect(f.db.one).not.toHaveBeenCalled(); expect(f.db.query).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
      expect(f.release).toHaveBeenCalledOnce(); expect(f.native).not.toHaveBeenCalled();
    }));
  });
  it('reduces the actual legacy step-plus-packet full Origin gates from four to two without removing either phase', async () => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      f.namespaces.verifyHandle.mockClear(); f.liveMaterial.mockClear();
      // These are the two unchanged original methods that the old Access
      // verifier awaited separately at EACH of its step and packet gates.
      for (const phase of ['step', 'packet'] as const) {
        const original = await f.origin.verifyConfigurationExecution(execution, phase, f.db);
        const proof = await f.origin.verifyJobHandle(job, phase, f.db);
        expect(original.jobHandle).toBe(job); expect(original.configurationJobId).toBe(proof.jobId);
      }
      expect(f.namespaces.verifyHandle.mock.calls.map(call => call[1])).toEqual(['step', 'step', 'packet', 'packet']);
      expect(f.liveMaterial).toHaveBeenCalledTimes(4);
      f.namespaces.verifyHandle.mockClear(); f.liveMaterial.mockClear();
      for (const phase of ['step', 'packet'] as const) {
        const pair = await f.origin.verifyOriginalExecutionAndJob(job, execution, phase, f.db);
        expect(pair.execution.jobHandle).toBe(job); expect(pair.execution.configurationJobId).toBe(pair.job.jobId);
      }
      expect(f.namespaces.verifyHandle.mock.calls.map(call => call[1])).toEqual(['step', 'packet']);
      expect(f.liveMaterial).toHaveBeenCalledTimes(2);
    }));
  });
  it('preserves the exact original proof deadline across a real Context job frame and legitimate lease heartbeat', async () => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      const now = Date.now(), access = Object.freeze({}), wrapperHandle = Object.freeze({}), wrapperStep = f.plan.steps[0].id;
      f.job.lease_until = new Date(now + 15000).toISOString(); f.nested.expires_at = new Date(now + 25000).toISOString();
      f.wrapperExecution.expires_at = new Date(now + 30000).toISOString();
      const wrapperProof: any = Object.freeze({ executionId: f.wrapperExecution.id, workflowId: f.ns.workflow.id,
        clusterId: f.cid, workspaceId: f.wid, actorId: f.owner, sessionId: null, permissionVersion: f.ns.permissionVersion,
        expiresAt: Date.parse(f.wrapperExecution.expires_at), origin: 'scheduled-workflow', scheduleClaimId: f.ns.claim.id,
        workflowOriginId: f.wrapperOrigin.id, approvalFormat: 2, approvalSetId: f.ns.approvalSet.setId, approvalSetHmac: f.ns.approvalSet.setHmac });
      f.context.installApprovedPolicy({ verifyExecution: async (handle: any) => { if (handle !== wrapperHandle) throw Error('ORIGINAL_WRAPPER_REQUIRED'); return wrapperProof; },
        verifyWorkflowScheduledExecution: async (proof: any, namespace: any) => { expect(proof).toBe(wrapperProof); expect(namespace).toBe(f.nsHandle); },
        verifyStep: async (proof: any, stepId: string) => { expect(proof).toBe(wrapperProof); expect(stepId).toBe(wrapperStep); return Object.freeze({ execution: proof, stepId, kind: 'metadata' }); },
        mutationBinding: async () => null, bindOperation: async () => undefined, assertNative: async () => undefined, assertMetadata: async () => undefined } as any);
      const proofs: any[] = [];
      f.context.installConfigurationJobPolicy({ verifyHandle: async handle => {
        if (handle !== access) throw Error('ORIGINAL_ACCESS_REQUIRED');
        const pair = await f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db);
        expect(pair.execution.expiresAt).toBe(Date.parse(f.ns.expiresAt));
        const proof = Object.freeze({ ...pair.job, originalScheduledJobHandle: job }); proofs.push(proof); return proof;
      } });
      await f.context.runApprovedWorkflow(wrapperHandle as any, () => f.context.runApprovedStep(wrapperStep, () => f.context.runConfigurationJob(access, async () => {
        const frame = f.context.current(); expect(frame.purpose).toBe('configuration');
        await (f.context as any).assertConfigurationJob(frame, true);
        f.job.lease_until = new Date(now + 35000).toISOString(); f.job.updated_at = new Date(now + 1).toISOString();
        f.job.revision = 7; f.job.captured_object_count = 3;
        await (f.context as any).assertConfigurationJob(frame, true);
        expect(f.context.current()).toBe(frame);
      })));
      expect(proofs).toHaveLength(3); for (const proof of proofs) expect(proof.expiresAt).toBe(Date.parse(f.ns.expiresAt));
      expect(new Set(proofs.map(proof => proof.expiresAt)).size).toBe(1); expect(f.db.exec).not.toHaveBeenCalled();
    }));
  });
  it.each(['job-lease', 'nested-expiry', 'wrapper-expiry'] as const)('rejects a fresh expired %s without changing the original authority TTL', async change => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      f.liveMaterial.mockImplementationOnce(async () => {
        const expired = new Date(Date.now() - 1).toISOString();
        if (change === 'job-lease') f.job.lease_until = expired;
        if (change === 'nested-expiry') f.nested.expires_at = expired;
        if (change === 'wrapper-expiry') f.wrapperExecution.expires_at = expired;
      });
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet')).rejects.toThrow(); expect(f.release).toHaveBeenCalledOnce();
    }));
  });
  it('derives source scopes if and only if the real authenticated material carries the complete required-origin marker', async () => {
    const ordinary = await sourceMaterialFixture(false), plain = await ordinary.read();
    expect(plain.sourceOrigin).toBeNull(); expect(plain.subjectSeal.sourceScopes).toEqual([]);
    const marked = await sourceMaterialFixture(true), promoted = await marked.read();
    expect(promoted.sourceOrigin).not.toBeNull(); expect(promoted.subjectSeal.sourceScopes).toEqual([{ clusterId: marked.sourceCid, workspaceId: marked.sourceWid, materialHmac: marked.job.required_origin_hmac }]);
    expect(ordinary.db.exec).not.toHaveBeenCalled(); expect(marked.db.exec).not.toHaveBeenCalled();
  });
  it.each(['partial-marker', 'unmarked-plan-ref', 'unmarked-job-binding', 'unmarked-plan-binding', 'marked-missing-ref'] as const)(
    'rejects %s instead of returning an unmarked material with hidden source scopes', async change => {
      const f = await sourceMaterialFixture(change === 'marked-missing-ref');
      if (change === 'partial-marker') f.job.required_origin_id = randomUUID();
      if (change === 'unmarked-plan-ref') { f.plan.originRef = { version: 1, kind: 'governance-promote', originId: randomUUID(), materialHmac: 'a'.repeat(64) }; await f.reseal(); }
      if (change === 'unmarked-job-binding') f.setJobOrigin({ id: randomUUID() });
      if (change === 'unmarked-plan-binding') f.setPlanOrigin({ id: randomUUID() });
      if (change === 'marked-missing-ref') { delete f.plan.originRef; await f.reseal(); }
      await expect(f.read()).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled();
    });
  it.each(['openClosedCheckpoint', 'assertClosedCheckpoint', 'assertClosedCheckpointLive', 'releaseClosedCheckpoint'] as const)('requires mandatory %s and rejects unknown Root methods', method => {
    const f = fixture(), fresh = () => new WorkflowScheduledConfigurationOriginService(f.db, f.secrets, f.redis, f.context, f.namespaces);
    expect(() => fresh().installRootVerifier({ ...f.root, [method]: undefined } as any)).toThrow('One fixed complete');
    expect(() => fresh().installRootVerifier({ ...f.root, callerSelectedPolicy() {} } as any)).toThrow('One fixed complete');
  });
  it.each(['claim', 'capture', 'ledger', 'wrong'] as const)('rejects nonnested checkpoint %s before opening a comparison', async phase => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, phase as any)).rejects.toThrow(); expect(f.open).not.toHaveBeenCalled();
    }));
  });
  it.each(['job-copy', 'execution-copy', 'mixed-job', 'closed-execution'] as const)('rejects %s without proof or comparison', async change => {
    const f = fixture(); let oldExecution: any;
    await f.run(async job => {
      await f.withNested(job, async execution => { oldExecution = execution;
        if (change === 'closed-execution') return;
        await expect(f.origin.verifyOriginalExecutionAndJob(change === 'job-copy' ? { ...job } : change === 'mixed-job' ? Object.freeze({}) : job,
          change === 'execution-copy' ? { ...execution } : execution, 'packet')).rejects.toThrow();
      });
      if (change === 'closed-execution') await expect(f.origin.verifyOriginalExecutionAndJob(job, oldExecution, 'packet')).rejects.toThrow();
      expect(f.open).not.toHaveBeenCalled();
    });
  });
  it.each(['executor-grant', 'reviewer-grant', 'claim', 'lease', 'wrapper', 'material', 'execution', 'origin', 'baseline', 'steps', 'operation'] as const)(
    'rejects fresh %s changes during the full Native material gate and releases its comparison', async change => {
      const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
        f.liveMaterial.mockImplementationOnce(async () => {
          if (change === 'executor-grant') f.fullGrants.set(f.owner, []);
          if (change === 'reviewer-grant') f.fullGrants.set(f.ns.approvalSet.reviewers[0].userId, []);
          if (change === 'claim') f.progress.state = 'cancelled';
          if (change === 'lease') f.lease.lease_until = new Date(Date.now() - 1).toISOString();
          if (change === 'wrapper') f.wrapperExecution.plan_hash = '0'.repeat(64);
          if (change === 'material') f.material.subjectSeal = { ...f.material.subjectSeal, materialHmac: '0'.repeat(64) };
          if (change === 'execution') f.nested.state = 'uncertain';
          if (change === 'origin') f.nestedOrigin.claim_id = randomUUID();
          if (change === 'baseline') f.baseline.manifest_hmac = '0'.repeat(64);
          if (change === 'steps') f.material.plan.steps = [{}];
          if (change === 'operation') f.operations.push({ id: randomUUID(), state: 'uncertain' });
        });
        await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db)).rejects.toThrow();
        expect(f.release).toHaveBeenCalledOnce(); expect(f.observations.has(f.release.mock.calls[0][0])).toBe(false);
      }));
    });
  it.each(['executor', 'reviewer'] as const)('detects complete %s entity/secret grant loss while broad grants and permission versions remain unchanged', async role => {
    const f = fixture(), actor = role === 'executor' ? f.owner : f.ns.approvalSet.reviewers[0].userId;
    const grants = f.fullGrants.get(actor)!;
    grants.push({ user_id: actor, module: 'secrets', action: 'read', cluster_id: f.cid, workspace_id: f.wid, scope_type: 'tag', scope_values: ['sealed'] });
    await f.run(async job => f.withNested(job, async execution => {
      f.liveMaterial.mockImplementationOnce(async () => { grants.pop(); });
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'step', f.db)).rejects.toThrow('COMPLETE_CURRENT_GRANTS_CHANGED');
      expect(f.release).toHaveBeenCalledOnce();
    }));
  });
  it('rejects callback reentry and retains the original closed phase and transaction', async () => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      f.liveMaterial.mockImplementationOnce(async () => {
        await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'before-send', f.db)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_CHECKPOINT_INVALID' } });
      });
      await f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db);
      expect(f.open).toHaveBeenCalledOnce(); expect(f.close.mock.calls[0][3]).toBe('packet');
    }));
  });
  it('rejects a substituted outer Context during an awaited full reader', async () => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      const frame = f.context.current(); let replaced: any;
      f.liveMaterial.mockImplementationOnce(async () => { replaced = vi.spyOn(f.context, 'current').mockReturnValue(Object.freeze({ ...frame })); });
      try { await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db)).rejects.toThrow(); expect(f.release).toHaveBeenCalledOnce(); }
      finally { replaced?.mockRestore(); }
    }));
  });
  it.each(['expiry', 'frame-closure'] as const)('releases a minted opening token exactly once when %s fails the post-await fence', async change => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      const opening = f.open.getMockImplementation()!, startedAt = Date.now(); let issued: object | undefined, returned = false;
      f.namespaces.verifyHandle.mockClear(); f.liveMaterial.mockClear();
      f.open.mockImplementationOnce(async (handle, proof, checkpoint, tx) => {
        issued = await opening(handle, proof, checkpoint, tx);
        await Promise.resolve();
        if (change === 'expiry') vi.setSystemTime(Date.parse(f.ns.expiresAt) + 1);
        else f.values.live = false;
        return issued;
      });
      try {
        await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db).then(pair => { returned = true; return pair; })).rejects.toThrow();
        expect(returned).toBe(false); expect(issued).toBeDefined();
        expect(f.release).toHaveBeenCalledExactlyOnceWith(issued);
        expect(f.observations.has(issued!)).toBe(false); expect(f.close).not.toHaveBeenCalled();
        expect(f.namespaces.verifyHandle).not.toHaveBeenCalled(); expect(f.liveMaterial).not.toHaveBeenCalled();
      } finally { f.values.live = true; vi.setSystemTime(startedAt); }
    }));
  });
  it.each(['required_origin_kind', 'required_origin_id', 'required_origin_hmac', 'sourceOrigin', 'sourceScopes'] as const)(
    'rejects unsupported promotion marker %s on the final inspection without fallback', async marker => {
      const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
        f.liveMaterial.mockImplementationOnce(async () => {
          if (marker === 'sourceOrigin') f.material.sourceOrigin = {};
          else if (marker === 'sourceScopes') f.material.subjectSeal = { ...f.material.subjectSeal, sourceScopes: [{ clusterId: randomUUID(), workspaceId: randomUUID(), materialHmac: '3'.repeat(64) }] };
          else f.job[marker] = marker === 'required_origin_kind' ? 'governance-promote' : marker === 'required_origin_id' ? randomUUID() : '3'.repeat(64);
        });
        await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db)).rejects.toThrow(); expect(f.release).toHaveBeenCalledOnce();
      }));
    });
  it('closes on Native errors and canonical denial, and cannot reuse the consumed comparison', async () => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      f.liveMaterial.mockRejectedValueOnce(Error('NATIVE_CURRENT_READ_FAILED'));
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet')).rejects.toThrow('NATIVE_CURRENT_READ_FAILED');
      expect(f.release).toHaveBeenCalledOnce(); expect(f.close).not.toHaveBeenCalled();
      f.close.mockRejectedValueOnce(Error('CANONICAL_APPROVAL_INVALIDATED'));
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet')).rejects.toThrow('CANONICAL_APPROVAL_INVALIDATED');
      expect(f.release).toHaveBeenCalledTimes(2);
      const token = f.release.mock.calls[0][0], [handle, proof, checkpoint, tx] = f.open.mock.calls[0];
      await expect(f.root.assertClosedCheckpoint(token, handle, proof, checkpoint, tx)).rejects.toThrow('ORIGINAL_CLOSED_OBSERVATION_REQUIRED');
    }));
  });
  it('rejects known grant expiry in the close-to-Origin microtask before returning a proof', async () => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      const startedAt = Date.now(), closing = f.close.getMockImplementation()!; let returned = false;
      f.close.mockImplementationOnce(async (token, handle, proof, phase, tx) => {
        await closing(token, handle, proof, phase, tx);
        const state = f.observations.get(token); state.deadline = Date.now() + 1;
        queueMicrotask(() => vi.setSystemTime(state.deadline));
      });
      try {
        await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db).then(pair => { returned = true; return pair; }))
          .rejects.toThrow('CURRENT_GRANT_DEADLINE_EXPIRED');
        expect(returned).toBe(false); expect(f.assertLive).toHaveBeenCalledOnce(); expect(f.release).toHaveBeenCalledOnce();
        const [token] = f.release.mock.calls[0], [handle, proof, phase, tx] = f.open.mock.calls[0];
        expect(() => f.root.assertClosedCheckpointLive(token, handle, proof, phase, tx)).toThrow('ORIGINAL_SEALED_OBSERVATION_REQUIRED');
      } finally { vi.setSystemTime(startedAt); }
    }));
  });
  it.each(['grant-expiry', 'frame-closure'] as const)('fences %s between the inner callback return and outer Origin continuation', async change => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      const startedAt = Date.now(), originalLive = f.assertLive.getMockImplementation()!, frame = f.context.current();
      const frameState = (f.context as any).states.get(frame), wasClosed = frameState.closed; let liveCalls = 0, returned = false;
      f.assertLive.mockImplementation((token, handle, proof, phase, tx) => {
        originalLive(token, handle, proof, phase, tx);
        if (++liveCalls === 2) {
          const state = f.observations.get(token); state.deadline = startedAt + 1;
          queueMicrotask(() => {
            if (change === 'grant-expiry') vi.setSystemTime(state.deadline);
            else frameState.closed = true;
          });
        }
      });
      try {
        await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db).then(pair => { returned = true; return pair; })).rejects.toThrow();
        expect(returned).toBe(false); expect(f.release).toHaveBeenCalledOnce();
        expect(f.observations.has(f.release.mock.calls[0][0])).toBe(false);
        expect(f.assertLive).toHaveBeenCalledTimes(change === 'grant-expiry' ? 3 : 2);
      } finally { frameState.closed = wasClosed; vi.setSystemTime(startedAt); }
    }));
  });
  it.each(['early-sync', 'double-close'] as const)('poisons %s misuse and rejects the final combined proof', async misuse => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      const opening = f.open.getMockImplementation()!, closing = f.close.getMockImplementation()!; let returned = false, issued: object | undefined;
      if (misuse === 'early-sync') f.open.mockImplementationOnce(async (handle, proof, phase, tx) => {
        issued = await opening(handle, proof, phase, tx);
        expect(() => f.root.assertClosedCheckpointLive(issued!, handle, proof, phase, tx)).toThrow('ORIGINAL_SEALED_OBSERVATION_REQUIRED');
        expect(f.observations.get(issued!).state).toBe('poisoned'); return issued!;
      });
      else f.close.mockImplementationOnce(async (token, handle, proof, phase, tx) => {
        issued = token; await closing(token, handle, proof, phase, tx);
        await expect(f.root.assertClosedCheckpoint(token, handle, proof, phase, tx)).rejects.toThrow('ORIGINAL_CLOSED_OBSERVATION_REQUIRED');
        expect(f.observations.get(token).state).toBe('poisoned');
      });
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db).then(pair => { returned = true; return pair; })).rejects.toThrow();
      expect(returned).toBe(false); expect(f.release).toHaveBeenCalledExactlyOnceWith(issued);
      expect(f.observations.has(issued!)).toBe(false);
    }));
  });
  it('keeps canonical grant closure after the last Redis await so natural grant expiry cannot escape it', async () => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      const startedAt = Date.now(), grantDeadline = startedAt + 1000; let nestedPasses = 0, returned = false;
      const originalNested = (f.origin as any).nested.bind(f.origin);
      const nested = vi.spyOn(f.origin as any, 'nested').mockImplementation(async (...args: any[]) => {
        const inspection = await originalNested(...args);
        if (++nestedPasses === 2) f.redis.assertLeaseOwnership.mockImplementationOnce(async () => {
          await Promise.resolve(); vi.setSystemTime(grantDeadline);
        });
        return inspection;
      });
      // Explicit controlled monotonic comparison adapter; the real backend's
      // binding-clock behavior is independently covered by its focused suite.
      f.close.mockImplementationOnce(async (token: object) => {
        if (!f.observations.has(token)) throw Error('ORIGINAL_CLOSED_OBSERVATION_REQUIRED');
        f.observations.delete(token);
        if (Date.now() >= grantDeadline) throw Error('CURRENT_GRANT_DEADLINE_EXPIRED');
      });
      try {
        await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db).then(pair => { returned = true; return pair; }))
          .rejects.toThrow('CURRENT_GRANT_DEADLINE_EXPIRED');
        expect(returned).toBe(false); expect(f.close).toHaveBeenCalledOnce(); expect(f.release).toHaveBeenCalledOnce();
      } finally { nested.mockRestore(); vi.setSystemTime(startedAt); }
    }));
  });
  it.each(['exec', 'transaction', 'nonselect', 'multistatement'] as const)('keeps canonical observation SQL read-only against %s', async kind => {
    const f = fixture(); await f.run(async job => f.withNested(job, async execution => {
      f.close.mockImplementationOnce(async (_token, _handle, _proof, _phase, tx) => {
        if (kind === 'exec') return tx.exec('UPDATE users SET force_password_change=true');
        if (kind === 'transaction') return tx.transaction(async () => undefined);
        if (kind === 'multistatement') return tx.one('SELECT 1; UPDATE users SET force_password_change=true');
        return tx.one('UPDATE users SET force_password_change=true RETURNING id');
      });
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet')).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_SQL_READ_ONLY' } });
      expect(f.db.exec).not.toHaveBeenCalled(); expect(f.release).toHaveBeenCalledOnce();
    }));
  });
});
