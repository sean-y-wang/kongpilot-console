import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { configurationApprovedFixture } from '../security/m8-configuration-approved-fixture';
import { ApprovedWorkflowExecutionService } from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import { CONFIGURATION_APPROVED_OPERATION_LINK_SQL, CONFIGURATION_APPROVED_SCHEDULED_OPERATION_LINK_SQL } from '../../apps/console-api/src/modules/workflows/configuration-approved-verifier';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ba'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
const denied = (code: string) => ({ response: { code } });
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };

/** Component boundary: actual Approved private execution/step/read WeakMaps,
 * real ConfigurationVerifier SQL/AEAD/operation checks, and real Context ALS
 * Namespace/operation frames. Source adapters issue the Namespace and original
 * nested-job origin; nested Context dispatch alone is a controlled adapter.
 * No Approved private registry is seeded. This does NOT establish genuine Root
 * claim issuance, nested Context ancestry, SQL transactions, HTTP or Native send.
 * The delegate supplies a controlled observation; Runtime full-scope/SDK404
 * behavior is tested separately and is not inferred from this fixture. */
async function fixture() {
  const f = await configurationApprovedFixture();
  const namespaceHandle = Object.freeze({}), jobHandle = Object.freeze({}), executionHandle = Object.freeze({});
  const approvalSet = Object.freeze({ format: 2, setId: randomUUID(), setHmac: '5'.repeat(64), reviewers: [{ userId: randomUUID() }] });
  for (const row of [f.workflow, f.wrapperVersion, f.wrapperExecution]) Object.assign(row, {
    approval_format: 2, approval_set_id: approvalSet.setId, approval_set_hmac: approvalSet.setHmac,
  });
  f.job.origin_type = 'http';
  const scheduled: any = Object.freeze({ origin: 'workflow-scheduled-configuration', sessionId: null, namespaceHandle, jobHandle,
    claimId: randomUUID(), wrapperOriginId: randomUUID(), wrapperExecutionId: f.wrapperExecution.id, configurationOriginId: randomUUID(),
    configurationExecutionId: f.executionId, configurationJobId: f.jobId, configurationPlanId: f.job.plan_id,
    configurationPlanRevision: 1, configurationPlanHash: f.job.plan_hash, configurationClaimHash: f.claim.claimHash,
    workflowId: f.workflow.id, workflowPlanRevision: 1, workflowPlanHash: f.workflow.plan_hash, actorId: f.actor.id,
    clusterId: f.cid, workspaceId: f.wid, permissionVersion: f.claim.permissionVersion, credentialEpoch: 1, leaseGeneration: 1, expiresAt: f.claim.expiresAt });
  Object.assign(f.claim, { sessionId: null, scheduledOrigin: scheduled });
  const namespace: any = Object.freeze({ version: 1, origin: 'scheduled-workflow', sessionId: null, actor: f.actor, clusterId: f.cid,
    workspaceId: f.wid, kind: 'configuration_v2', permissionVersion: f.claim.permissionVersion, credentialEpoch: '1',
    workflow: Object.freeze({ id: f.workflow.id, planRevision: 1, planHash: f.workflow.plan_hash }), approvalSet,
    claim: Object.freeze({ id: scheduled.claimId, scheduleId: randomUUID(), generation: 1 }), expiresAt: new Date(f.claim.expiresAt).toISOString() });
  const state: any = { selectedStep: undefined, executionProof: undefined, live: true, before: null, reader: undefined, handles: [], intents: [] };
  f.context.installWorkflowScheduledNamespacePolicy({
    assertLive(handle) { if (handle !== namespaceHandle || !state.live) throw Error('SOURCE_NAMESPACE_REVOKED'); },
    async verifyHandle(handle) { if (handle !== namespaceHandle || !state.live) throw Error('SOURCE_NAMESPACE_REVOKED'); return namespace; },
  });
  const origin: any = { id: scheduled.configurationOriginId, wrapper_origin_id: scheduled.wrapperOriginId, claim_id: scheduled.claimId,
    configuration_execution_id: f.executionId, configuration_job_id: f.jobId, configuration_plan_id: f.job.plan_id,
    configuration_plan_revision: 1, configuration_plan_hash: f.job.plan_hash, cluster_id: f.cid, workspace_id: f.wid,
    workflow_id: f.workflow.id, workflow_plan_revision: 1, workflow_plan_hash: f.workflow.plan_hash,
    workflow_execution_id: f.wrapperExecution.id, wrapper_execution_id: f.wrapperExecution.id, workflow_step_id: f.wrapper.steps[0].id,
    scheduled_executor: f.actor.id, generation: 1, authority_expires_at: new Date(f.claim.expiresAt),
    worker_owner_hmac: '9'.repeat(64), progress_state: 'running', progress_claim_id: scheduled.claimId,
    lease_until: new Date(f.claim.expiresAt), lease_worker_owner_hmac: '9'.repeat(64) };
  const one = f.db.one.getMockImplementation()!, exec = f.db.exec.getMockImplementation()!;
  f.db.one.mockImplementation(async (sql: string, params: any[]) => sql.includes('FROM workflow_configuration_execution_origins') ? origin
    : sql.includes('SELECT j.origin_session_id,s.id AS wrapper_step_id') ? { origin_session_id: f.sid, wrapper_step_id: f.wrapper.steps[0].id }
      : one(sql, params));
  f.db.exec.mockImplementation(async (sql: string, params: any[]) => sql === CONFIGURATION_APPROVED_SCHEDULED_OPERATION_LINK_SQL
    ? exec(CONFIGURATION_APPROVED_OPERATION_LINK_SQL, params.slice(0, 22)) : exec(sql, params));
  (f.redis as any).assertLeaseActive = vi.fn(() => { if (!state.live) throw Error('SOURCE_LEASE_REVOKED'); });
  const approvals: any = { verifyApprovalSet: vi.fn(async () => approvalSet) };
  const verifier = new ApprovedWorkflowExecutionService(f.db, f.secrets, f.authz, {} as any, f.kong, f.redis, f.context, approvals);
  verifier.installConfigurationDelegate(f.delegate);
  const originalExecutions = new WeakMap<object, any>([[executionHandle, scheduled]]);
  verifier.installWorkflowScheduledConfigurationDelegate({ async verifyExecution(handle) {
    if (!originalExecutions.has(handle) || !state.live) throw Error('SOURCE_ORIGINAL_NESTED_EXECUTION_REQUIRED'); return scheduled;
  } });
  vi.spyOn(f.context, 'currentApprovedStep').mockImplementation(() => { if (!state.selectedStep) throw Error('SOURCE_NO_CURRENT_STEP'); return state.selectedStep; });
  vi.spyOn(f.context, 'runApprovedScheduledConfigurationWorkflow').mockImplementation(async (handle, originalJob, fn) => {
    if (originalJob !== jobHandle) throw Error('SOURCE_ORIGINAL_JOB_REQUIRED');
    state.executionProof = await verifier.verifyExecution(handle); return fn();
  });
  const reader = vi.fn(async (handle: any) => {
    state.handles.push(handle);
    const intent = await verifier.beginConfigurationNativeBeforeRead(handle, f.db); state.intents.push(intent);
    if (!state.omitLimit) verifier.limitConfigurationNativeBeforeRead(handle, f.db, performance.now() + 30000);
    if (state.reader) return state.reader(handle, intent);
    await verifier.assertConfigurationNativeBeforeRead(handle, f.db); verifier.assertConfigurationNativeBeforeReadLive(handle, f.db);
    return { before: state.before };
  });
  verifier.installWorkflowScheduledDelegate({ readConfigurationNativeBefore: reader,
    runValidationRead: async () => { throw Error('SOURCE_GENERIC_READER_MUST_NOT_BE_USED'); },
    assertConfigurationOrigin: async () => undefined });
  const run = (fn: (proof: any, input: any, operation: any) => Promise<any>) => f.context.runWorkflowScheduledNamespace(namespaceHandle, () =>
    verifier.runScheduledConfigurationExecution(jobHandle as any, executionHandle as any, f.executionId, async () => {
      state.selectedStep = await verifier.verifyStep(state.executionProof, f.jobStepId);
      try {
        const binding = await verifier.mutationBinding(state.selectedStep, f.mutation), operation = f.op(binding);
        f.operations.set(operation.id, operation); await verifier.bindOperation(state.selectedStep, f.mutation, binding, operation.id, f.db);
        operation.remote_started = true;
        return await f.context.runOperation({ ...f.mutation, operationId: operation.id }, async () => {
          const input: any = { frame: f.context.current(), cluster: f.cluster, clusterId: f.cid, workspaceId: f.wid,
            transportScope: f.job.transport_scope, operationId: operation.id, method: 'POST', canonicalPath: '/services',
            body: f.step.body, mutationAction: 'create', query: {} };
          f.kong.request.mockClear(); return fn(state.selectedStep, input, operation);
        });
      } finally { state.selectedStep = undefined; }
    }));
  return { ...f, verifier, approvals, state, scheduled, namespace, namespaceHandle, jobHandle, executionHandle, origin, reader, run };
}

describe('fixed scheduled configuration currentBefore opaque read capability', () => {
  it('mints a fresh opaque handle from the original actual Approved step and exact packet', async () => {
    const f = await fixture(); await f.run(async (proof, input) => {
      const result = await f.verifier.readConfigurationNativeBefore(proof, input);
      expect(result).toEqual({ before: null }); expect(Object.isFrozen(result)).toBe(true);
      expect(f.reader).toHaveBeenCalledOnce(); expect(Object.keys(f.state.handles[0])).toEqual([]);
      expect(Object.isFrozen(f.state.handles[0])).toBe(true);
      expect(f.state.intents[0]).toMatchObject({ namespaceHandle: f.namespaceHandle, namespace: f.namespace,
        clusterId: f.cid, workspaceId: f.step.objectWorkspaceId, jobId: f.jobId, executionId: f.executionId,
        jobStepId: f.jobStepId, planStepId: f.step.stepId, operationId: input.operationId,
        beforePath: `/services/${f.nativeId}`, bodyHmac: f.step.bodyHmac, beforeHmac: f.step.beforeHmac });
      expect(f.kong.request).not.toHaveBeenCalled(); expect((f.redis as any).assertLeaseActive).toHaveBeenCalled();
    });
  });

  it.each(['step-copy', 'execution-copy', 'foreign-service'] as const)('rejects %s instead of accepting proof-shaped DTOs', async reason => {
    const f = await fixture(), foreign = reason === 'foreign-service' ? await fixture() : undefined;
    await f.run(async (proof, input) => {
      const selected = reason === 'step-copy' ? { ...proof } : reason === 'execution-copy' ? { ...proof, execution: { ...proof.execution } } : proof;
      await expect((foreign?.verifier ?? f.verifier).readConfigurationNativeBefore(selected, input)).rejects.toBeDefined();
      expect(f.reader).not.toHaveBeenCalled(); if (foreign) expect(foreign.reader).not.toHaveBeenCalled();
    });
  });

  it.each(['frame', 'cluster', 'transport', 'operation', 'body', 'query', 'path', 'workspace', 'parent', 'credential'] as const)('retains the actual ConfigVerifier exact %s binding before entering the reader', async reason => {
    const f = await fixture(); await f.run(async (proof, input) => {
      const changed = { ...input };
      if (reason === 'frame') changed.frame = { ...input.frame };
      if (reason === 'cluster') changed.clusterId = randomUUID();
      if (reason === 'transport') changed.transportScope = '1'.repeat(64);
      if (reason === 'operation') changed.operationId = randomUUID();
      if (reason === 'body') changed.body = { ...input.body, host: 'foreign.invalid' };
      if (reason === 'query') changed.query = { size: 1 };
      if (reason === 'path') changed.canonicalPath = '/routes';
      if (reason === 'workspace') changed.workspaceId = randomUUID();
      if (reason === 'parent') changed.parentId = randomUUID();
      if (reason === 'credential') changed.credentialKind = 'key-auth';
      await expect(f.verifier.readConfigurationNativeBefore(proof, changed)).rejects.toMatchObject(denied('CONFIGURATION_APPROVED_NATIVE_MISMATCH'));
      expect(f.reader).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
    });
  });

  it.each(['ciphertext', 'before-secret', 'payload-secret', 'remote-completed'] as const)('keeps real encrypted plan/operation %s checks before issuing the handle', async reason => {
    const f = await fixture(); await f.run(async (proof, input, operation) => {
      if (reason === 'ciphertext') f.objects[0].payload_ciphertext = 'invalid';
      if (reason === 'before-secret') operation.before_secret = f.secrets.encrypt({ id: f.nativeId }, `mutation:${operation.id}:before`);
      if (reason === 'payload-secret') operation.payload_secret = f.secrets.encrypt({ id: f.nativeId, host: 'foreign.invalid' }, `mutation:${operation.id}:payload`);
      if (reason === 'remote-completed') operation.remote_completed = true;
      await expect(f.verifier.readConfigurationNativeBefore(proof, input)).rejects.toBeDefined();
      expect(f.reader).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
    });
  });

  it.each(['copy', 'foreign', 'transaction', 'double-enter'] as const)('rejects %s use of the genuine private read handle', async reason => {
    const f = await fixture(), foreign = reason === 'foreign' ? await fixture() : undefined;
    await f.run(async (proof, input) => {
      f.state.reader = async (handle: any) => {
        if (reason === 'copy') await expect(f.verifier.assertConfigurationNativeBeforeRead({ ...handle }, f.db)).rejects.toBeDefined();
        if (reason === 'foreign') await expect(foreign!.verifier.assertConfigurationNativeBeforeRead(handle, foreign!.db)).rejects.toBeDefined();
        if (reason === 'transaction') await expect(f.verifier.assertConfigurationNativeBeforeRead(handle, { ...f.db } as any)).rejects.toBeDefined();
        if (reason === 'double-enter') await expect(f.verifier.beginConfigurationNativeBeforeRead(handle, f.db)).rejects.toMatchObject(denied('CONFIGURATION_BEFORE_READ_ALREADY_ENTERED'));
        await f.verifier.assertConfigurationNativeBeforeRead(handle, f.db); return { before: null };
      };
      await expect(f.verifier.readConfigurationNativeBefore(proof, input)).resolves.toEqual({ before: null });
    });
  });

  it.each(['job', 'execution', 'step', 'operation', 'lease', 'deadline'] as const)('fresh SQL closing rejects current %s changes during the controlled observation', async reason => {
    const f = await fixture(); await f.run(async (proof, input, operation) => {
      f.state.reader = async (handle: any) => {
        if (reason === 'job') f.job.state = 'cancelled';
        if (reason === 'execution') f.execution.state = 'uncertain';
        if (reason === 'step') f.rows[0].state = 'failed';
        if (reason === 'operation') operation.idempotency_key = 'changed-original-key';
        if (reason === 'lease') f.job.lease_until = new Date(Date.now() - 1).toISOString();
        if (reason === 'deadline') f.job.authority_expires_at = new Date(Date.now() - 1).toISOString();
        await f.verifier.assertConfigurationNativeBeforeRead(handle, f.db); return { before: null };
      };
      await expect(f.verifier.readConfigurationNativeBefore(proof, input)).rejects.toBeDefined();
      expect(f.kong.request).not.toHaveBeenCalled();
    });
  });

  it('does not authorize a same-actor descendant frame and releases the read handle after callback completion', async () => {
    const f = await fixture(); let original: any;
    await f.run(async (proof, input) => {
      f.state.reader = async (handle: any) => {
        original = handle;
        await expect(f.context.runActor({ actor: f.actor, clusterId: f.cid, workspaceId: f.wid, module: 'snapshots', action: 'write' },
          () => f.verifier.assertConfigurationNativeBeforeRead(handle, f.db))).rejects.toBeDefined();
        await f.verifier.assertConfigurationNativeBeforeRead(handle, f.db); return { before: null };
      };
      await f.verifier.readConfigurationNativeBefore(proof, input);
      await expect(f.verifier.assertConfigurationNativeBeforeRead(original, f.db)).rejects.toBeDefined();
      expect(() => f.verifier.assertConfigurationNativeBeforeReadLive(original, f.db)).toThrow();
    });
  });

  it('releases a failed reader and never falls back to a normal GET', async () => {
    const f = await fixture(); let original: any;
    await f.run(async (proof, input) => {
      f.state.reader = async (handle: any) => { original = handle; throw Error('SOURCE_CONTROLLED_OBSERVATION_FAILED'); };
      await expect(f.verifier.readConfigurationNativeBefore(proof, input)).rejects.toThrow('SOURCE_CONTROLLED_OBSERVATION_FAILED');
      await expect(f.verifier.assertConfigurationNativeBeforeRead(original, f.db)).rejects.toBeDefined();
      expect(f.kong.request).not.toHaveBeenCalled(); expect(f.reader).toHaveBeenCalledOnce();
    });
  });

  it('rejects continuation after the original execution callback closes while the reader awaits', async () => {
    const f = await fixture(), entered = deferred(), gate = deferred(); let pending!: Promise<unknown>;
    await f.run(async (proof, input) => {
      f.state.reader = async () => { entered.resolve(); await gate.promise; return { before: null }; };
      pending = f.verifier.readConfigurationNativeBefore(proof, input); void pending.catch(() => undefined); await entered.promise;
    });
    gate.resolve(); await expect(pending).rejects.toBeDefined();
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each([{ result: {} }, { result: { before: null, permit: {} } }, { result: { before: null, allocatedAbsent: true } }] as const)('rejects malformed provider observation $result', async ({ result }) => {
    const f = await fixture(); await f.run(async (proof, input) => {
      f.state.reader = async () => result;
      await expect(f.verifier.readConfigurationNativeBefore(proof, input)).rejects.toMatchObject(denied('CONFIGURATION_BEFORE_RESULT_INVALID'));
      expect(f.kong.request).not.toHaveBeenCalled();
    });
  });

  it('refuses to publish when a fixed delegate omits the required finite read deadline', async () => {
    const f = await fixture(); f.state.omitLimit = true;
    await f.run(async (proof, input) => {
      await expect(f.verifier.readConfigurationNativeBefore(proof, input)).rejects.toBeDefined();
      expect(f.reader).toHaveBeenCalledOnce(); expect(f.kong.request).not.toHaveBeenCalled();
    });
  });

  it('the private monotonic read deadline only shortens and survives the delegate Promise return', async () => {
    const f = await fixture(); let mono = 1000; vi.spyOn(performance, 'now').mockImplementation(() => mono);
    await f.run(async (proof, input) => {
      f.state.reader = async (handle: any) => {
        f.verifier.limitConfigurationNativeBeforeRead(handle, f.db, mono + 10);
        f.verifier.limitConfigurationNativeBeforeRead(handle, f.db, mono + 1000);
        await f.verifier.assertConfigurationNativeBeforeRead(handle, f.db);
        mono += 11; return { before: null };
      };
      await expect(f.verifier.readConfigurationNativeBefore(proof, input)).rejects.toMatchObject(denied('CONFIGURATION_BEFORE_ORIGINAL_READ_REQUIRED'));
      expect(f.kong.request).not.toHaveBeenCalled();
    });
  });

  it.each([Infinity, NaN, -1, 40001])('rejects invalid private read deadline %s without renewing original authority', async offset => {
    const f = await fixture(); let mono = 1000; vi.spyOn(performance, 'now').mockImplementation(() => mono);
    await f.run(async (proof, input) => {
      f.state.reader = async (handle: any) => {
        expect(() => f.verifier.limitConfigurationNativeBeforeRead(handle, f.db, mono + offset)).toThrow();
        expect(() => f.verifier.limitConfigurationNativeBeforeRead({ ...handle }, f.db, mono + 10)).toThrow();
        expect(() => f.verifier.limitConfigurationNativeBeforeRead(handle, { ...f.db } as any, mono + 10)).toThrow();
        return { before: null };
      };
      await expect(f.verifier.readConfigurationNativeBefore(proof, input)).resolves.toEqual({ before: null });
    });
  });

  it('ConfigVerifier consumes the fixed observation and retains beforeHmac plus its complete post-read load', async () => {
    const f = await fixture(); await f.run(async (proof, input) => {
      f.delegate.verifyExecution.mockClear();
      await f.verifier.assertNative(proof, { ...input, before: null }, 'before-send');
      expect(f.reader).toHaveBeenCalledOnce(); expect(f.kong.request).not.toHaveBeenCalled();
      expect(f.delegate.verifyExecution.mock.calls.length).toBeGreaterThanOrEqual(3);
    });
  });

  it('ConfigVerifier rejects a changed beforeHmac and retains complete post-read permission revocation', async () => {
    const changed = await fixture(); await changed.run(async (proof, input) => {
      changed.state.before = { id: changed.nativeId, host: 'occupied.invalid' };
      await expect(changed.verifier.assertNative(proof, { ...input, before: null }, 'before-send'))
        .rejects.toMatchObject(denied('CONFIGURATION_CURRENT_BEFORE_CHANGED'));
      expect(changed.kong.request).not.toHaveBeenCalled();
    });
    const revoked = await fixture(); await revoked.run(async (proof, input) => {
      revoked.state.reader = async (handle: any) => {
        await revoked.verifier.assertConfigurationNativeBeforeRead(handle, revoked.db);
        revoked.authz.permissionVersion.mockResolvedValue('revoked-current-permission'); return { before: null };
      };
      await expect(revoked.verifier.assertNative(proof, { ...input, before: null }, 'before-send')).rejects.toBeDefined();
      expect(revoked.reader).toHaveBeenCalledOnce(); expect(revoked.kong.request).not.toHaveBeenCalled();
    });
  });
});
