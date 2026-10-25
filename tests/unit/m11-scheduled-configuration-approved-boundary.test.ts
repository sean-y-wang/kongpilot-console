import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApprovedWorkflowExecutionService } from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'e7'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

/** Focused service capability tests. Origin registry, Config verifier and
 * Context dispatch are dependency doubles; the Approved private WeakMaps,
 * cleanup, original-handle identity and cross-ledger tuple checks are real.
 * This is not evidence of SQL, Context ancestry, a timer or a native send. */
function fixture(install = true) {
  const secrets = new SecretService(), namespaceHandle = Object.freeze({}), jobHandle = Object.freeze({}), executionHandle = Object.freeze({});
  const expiry = Date.now() + 60_000, actor = { id: randomUUID(), username: 'current-console-executor', superAdmin: false };
  const origin: any = { origin: 'workflow-scheduled-configuration', sessionId: null, jobHandle, namespaceHandle,
    claimId: randomUUID(), wrapperOriginId: randomUUID(), wrapperExecutionId: randomUUID(), configurationOriginId: randomUUID(),
    configurationExecutionId: randomUUID(), configurationJobId: randomUUID(), configurationPlanId: randomUUID(),
    configurationPlanRevision: 1, configurationPlanHash: '1'.repeat(64), configurationClaimHash: '2'.repeat(64),
    workflowId: randomUUID(), workflowPlanRevision: 2, workflowPlanHash: '3'.repeat(64), actorId: actor.id,
    clusterId: randomUUID(), workspaceId: randomUUID(), permissionVersion: 'actual-epoch-1', credentialEpoch: 1, leaseGeneration: 1, expiresAt: expiry };
  const workflow: any = { id: origin.workflowId, kind: 'configuration_v2', approval_format: 2, approval_set_id: randomUUID(), approval_set_hmac: '4'.repeat(64),
    plan_revision: origin.workflowPlanRevision, plan_hash: origin.workflowPlanHash, subject_id: origin.configurationJobId,
    subject_type: 'configuration_jobs', requester_type: 'console', requester_user_id: actor.id };
  const execution: any = { id: origin.configurationExecutionId, job_id: origin.configurationJobId, plan_id: origin.configurationPlanId,
    plan_revision: origin.configurationPlanRevision, plan_hash: origin.configurationPlanHash, claim_hash: origin.configurationClaimHash,
    actor_id: actor.id, permission_version: origin.permissionVersion, lease_generation: origin.leaseGeneration,
    workflow_id: origin.workflowId, approved_version: origin.workflowPlanRevision, workflow_plan_hash: origin.workflowPlanHash,
    cluster_id: origin.clusterId, workspace_id: origin.workspaceId };
  const authoringSid = randomUUID(), job: any = { id: origin.configurationJobId, origin_session_id: authoringSid, actor_id: actor.id,
    plan_id: origin.configurationPlanId, plan_revision: origin.configurationPlanRevision, plan_hash: origin.configurationPlanHash, workflow_id: origin.workflowId };
  const state = { live: true, namespace: true, actor, sessionId: undefined as string | undefined, origin, proof: null as any, order: [] as string[] };
  const frame: any = { actor, clusterId: origin.clusterId, workspaceId: origin.workspaceId, sessionId: undefined };
  const context: any = { installApprovedPolicy: vi.fn(), hasWorkflowScheduledNamespace: () => state.namespace,
    requireWorkflowScheduledNamespaceHandle: () => { if (!state.namespace) throw Error('ORIGINAL_NAMESPACE_CLOSED'); return namespaceHandle; },
    current: () => ({ ...frame, actor: state.actor, sessionId: state.sessionId }),
    runApprovedScheduledConfigurationWorkflow: vi.fn(async (handle: any, originalJob: object, fn: () => Promise<any>) => {
      if(originalJob!==jobHandle)throw Error('ORIGINAL_JOB_HANDLE_REQUIRED');state.proof = await verifier.verifyExecution(handle); return fn(); }) };
  const db: any = { one: vi.fn(), query: vi.fn(), exec: vi.fn() }, redis: any = { assertLeaseOwnership: vi.fn(async () => undefined) };
  const verifier = new ApprovedWorkflowExecutionService(db, secrets, {} as any, {} as any, { request: vi.fn() } as any, redis, context);
  const originals = new WeakMap<object, any>(); originals.set(executionHandle, origin);
  const delegate = { verifyExecution: vi.fn(async (handle: object, checkpoint: string) => {
    state.order.push(`origin:${checkpoint}`);
    if (!state.live || !originals.has(handle)) throw Error('ORIGINAL_JOB_AUTHORITY_REVOKED');
    return state.origin;
  }) };
  if (install) verifier.installWorkflowScheduledConfigurationDelegate(delegate as any);
  const loaded: any = { execution, job, workflow, scheduledOrigin: origin, claimExpiresAt: expiry,
    rows: [], version: {}, wrapper: {}, plan: {} };
  const configuration = (verifier as any).configuration;
  const load = vi.spyOn(configuration, 'load').mockImplementation(async () => { state.order.push('configuration:load'); return loaded; });
  const cfgstep: any = { stepId: randomUUID(), beforeHmac: secrets.fingerprint(null) }, row = { id: randomUUID() };
  const step = vi.spyOn(configuration, 'step').mockImplementation(async () => ({ loaded, step: cfgstep, row }));
  const logical = vi.spyOn(configuration, 'logical').mockImplementation(() => undefined);
  const bind = vi.spyOn(configuration, 'bind').mockImplementation(async () => { state.order.push('configuration:link'); });
  const native = vi.spyOn(configuration, 'native').mockImplementation(async () => { state.order.push('configuration:native'); });
  const run = (fn: () => Promise<any>) => verifier.runScheduledConfigurationExecution(jobHandle as any, executionHandle as any, execution.id, fn);
  return { verifier, secrets, context, delegate, loaded, state, origin, namespaceHandle, jobHandle, executionHandle, execution, job, workflow, authoringSid,
    run, load, step, logical, bind, native, cfgstep, row, db };
}

describe('scheduled configuration Approved boundary keeps original nested V2 handles', () => {
  it('mints a private NULL-SID V2 proof and never adopts the saved authoring SID', async () => {
    const f = fixture(); let original: any;
    await f.run(async () => {
      original = f.state.proof;
      expect(original).toMatchObject({ origin: 'scheduled-configuration', sessionId: null, executionId: f.execution.id,
        workflowId: f.origin.workflowId, scheduleClaimId: f.origin.claimId, workflowOriginId: f.origin.wrapperOriginId, configurationOriginId: f.origin.configurationOriginId });
      expect(original.executionId).not.toBe(f.origin.wrapperExecutionId); expect(f.job.origin_session_id).toBe(f.authoringSid);
      await f.verifier.verifyWorkflowScheduledConfigurationExecution(original, f.namespaceHandle, f.jobHandle as any);
      await expect(f.verifier.verifyWorkflowScheduledConfigurationExecution({ ...original }, f.namespaceHandle, f.jobHandle as any)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED' } });
    });
    await expect(f.verifier.verifyWorkflowScheduledConfigurationExecution(original, f.namespaceHandle, f.jobHandle as any)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED' } });
    expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('requires a once-installed fixed original handle verifier before looking up a configuration', async () => {
    const f = fixture(false), dispatch = vi.fn();
    await expect(f.run(dispatch)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_APPROVED_POLICY_UNAVAILABLE' } });
    expect(f.load).not.toHaveBeenCalled(); expect(dispatch).not.toHaveBeenCalled();
    f.verifier.installWorkflowScheduledConfigurationDelegate(f.delegate as any);
    expect(() => f.verifier.installWorkflowScheduledConfigurationDelegate(f.delegate as any)).toThrow();
  });
  it('rejects a copied original execution handle rather than accepting an execution ID DTO', async () => {
    const f = fixture();
    await expect(f.verifier.runScheduledConfigurationExecution(f.jobHandle as any, { ...f.executionHandle } as any, f.execution.id, async () => undefined)).rejects.toThrow('ORIGINAL_JOB_AUTHORITY_REVOKED');
    expect(f.load).not.toHaveBeenCalled(); expect(f.context.runApprovedScheduledConfigurationWorkflow).not.toHaveBeenCalled();
  });
  it('rejects copied job and namespace handles while the real boundary is live', async () => {
    const f = fixture();
    await expect(f.verifier.runScheduledConfigurationExecution({ ...f.jobHandle } as any, f.executionHandle as any, f.execution.id, async () => undefined)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED' } });
    await f.run(async () => {
      await expect(f.verifier.verifyWorkflowScheduledConfigurationExecution(f.state.proof, { ...f.namespaceHandle }, f.jobHandle as any)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED' } });
      await expect(f.verifier.verifyWorkflowScheduledConfigurationExecution(f.state.proof, f.namespaceHandle, { ...f.jobHandle } as any)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED' } });
    });
  });
  it.each(['configurationJobId', 'configurationPlanId', 'configurationPlanHash', 'configurationClaimHash', 'workflowPlanHash', 'leaseGeneration'])('rejects a verifier claim whose %s differs from the actual nested tuple', async field => {
    const f = fixture(); f.loaded.scheduledOrigin = { ...f.origin, [field]: field.endsWith('Hash') ? '9'.repeat(64) : field === 'leaseGeneration' ? 2 : randomUUID() };
    await expect(f.run(async () => undefined)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_MISMATCH' } });
    expect(f.context.runApprovedScheduledConfigurationWorkflow).not.toHaveBeenCalled();
  });
  it.each(['origin_session_id', 'actor_id', 'plan_hash'])('preserves the SQL011 job and rejects malformed or foreign %s', async field => {
    const f = fixture(); f.job[field] = field === 'origin_session_id' ? null : field === 'plan_hash' ? '9'.repeat(64) : randomUUID();
    await expect(f.run(async () => undefined)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_MISMATCH' } });
    expect(f.context.runApprovedScheduledConfigurationWorkflow).not.toHaveBeenCalled();
  });
  it('never accepts the wrapper execution as the configuration execution', async () => {
    const f = fixture();
    await expect(f.verifier.runScheduledConfigurationExecution(f.jobHandle as any, f.executionHandle as any, f.origin.wrapperExecutionId, async () => undefined)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED' } });
    expect(f.load).not.toHaveBeenCalled();
  });
  it('does not allow an ordinary HTTP SID, a missing namespace, or expired original origin', async () => {
    for (const change of [(f: ReturnType<typeof fixture>) => { f.state.sessionId = f.authoringSid; },
      (f: ReturnType<typeof fixture>) => { f.state.namespace = false; }, (f: ReturnType<typeof fixture>) => { f.origin.expiresAt = Date.now() - 1; }]) {
      const f = fixture(); change(f); await expect(f.run(async () => undefined)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED' } });
      expect(f.load).not.toHaveBeenCalled();
    }
  });
  it('consumes the original execution boundary once and cleans it up after callback failure', async () => {
    const f = fixture(); let proof: any;
    await expect(f.run(async () => { proof = f.state.proof; throw Error('ORIGINAL_CALLBACK_FAILURE'); })).rejects.toThrow('ORIGINAL_CALLBACK_FAILURE');
    await expect(f.run(async () => undefined)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_EXECUTION_REPLAY_FORBIDDEN' } });
    await expect(f.verifier.verifyStep(proof, f.row.id)).rejects.toMatchObject({ response: { code: 'APPROVED_EXECUTION_INVALID' } });
  });
  it('keeps Native bindings V2 and rejects copied bindings before establishing a reciprocal link', async () => {
    const f = fixture();
    await f.run(async () => {
      const step = await f.verifier.verifyStep(f.state.proof, f.row.id), mutation: any = { actor: f.state.actor, operationId: undefined, payload: null, before: null };
      const binding = await f.verifier.mutationBinding(step, mutation);
      expect(binding).toMatchObject({ version: 2, configurationExecutionId: f.execution.id, configurationJobId: f.job.id, configurationStepId: f.row.id });
      expect(binding).not.toHaveProperty('executionId');
      await expect(f.verifier.bindOperation(step, mutation, { ...binding }, randomUUID(), f.db)).rejects.toMatchObject({ response: { code: 'CONFIGURATION_APPROVED_BINDING_INVALID' } });
      expect(f.bind).not.toHaveBeenCalled();
      const operationId = randomUUID(); await f.verifier.bindOperation(step, mutation, binding, operationId, f.db);
      const link = f.state.order.lastIndexOf('configuration:link'); expect(link).toBeGreaterThan(-1); expect(f.state.order.slice(link + 1)).toContain('origin:packet');
      await expect(f.verifier.assertMetadata(step, {} as any, f.db)).rejects.toMatchObject({ response: { code: 'CONFIGURATION_NATIVE_ONLY' } });
    });
  });
  it.each(['authorize', 'prepare', 'before-send', 'response'] as const)('rechecks original authority before the actual %s native policy', async stage => {
    const f = fixture();
    await f.run(async () => {
      const step = await f.verifier.verifyStep(f.state.proof, f.row.id); f.state.live = false;
      await expect(f.verifier.assertNative(step, {} as any, stage)).rejects.toThrow('ORIGINAL_JOB_AUTHORITY_REVOKED');
      expect(f.native).not.toHaveBeenCalled();
      expect(f.delegate.verifyExecution.mock.calls.at(-1)?.[1]).toBe(stage === 'before-send' ? 'before-send' : 'packet');
    });
  });
  it('stops a once-valid nested proof if the original origin changes, with no Native policy call', async () => {
    const f = fixture();
    await f.run(async () => {
      const step = await f.verifier.verifyStep(f.state.proof, f.row.id); f.state.origin = { ...f.origin, configurationOriginId: randomUUID() };
      await expect(f.verifier.assertNative(step, {} as any, 'before-send')).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_CHANGED' } });
      expect(f.native).not.toHaveBeenCalled();
    });
  });
  it('does not let an in-place origin mutation rewrite the capability snapshot', async () => {
    const f = fixture();
    await f.run(async () => {
      const step = await f.verifier.verifyStep(f.state.proof, f.row.id); f.origin.leaseGeneration = 2;
      await expect(f.verifier.assertNative(step, {} as any, 'before-send')).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGIN_CHANGED' } });
      expect(f.native).not.toHaveBeenCalled();
    });
  });
  it('rejects work that resumes after its original Approved callback has closed', async () => {
    const f = fixture(); let release!: () => void, entered!: () => void, pending!: Promise<void>;
    const gate = new Promise<void>(resolve => { release = resolve; }), started = new Promise<void>(resolve => { entered = resolve; });
    await f.run(async () => {
      f.delegate.verifyExecution.mockImplementationOnce(async () => { entered(); await gate; return f.origin; });
      pending = f.verifier.verifyWorkflowScheduledConfigurationExecution(f.state.proof, f.namespaceHandle, f.jobHandle as any);
      await started;
    });
    const loads = f.load.mock.calls.length; release();
    await expect(pending).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_ORIGINAL_EXECUTION_REQUIRED' } });
    expect(f.load).toHaveBeenCalledTimes(loads); expect(f.native).not.toHaveBeenCalled();
  });
  it.each(['authorize', 'prepare', 'before-send', 'response'] as const)('passes the original %s packet to Native after original authority, without a discarded step load', async stage => {
    const f = fixture();
    await f.run(async () => {
      const step = await f.verifier.verifyStep(f.state.proof, f.row.id), input: any = Object.freeze({ packet: Object.freeze({}) });
      f.step.mockClear(); f.state.order.length = 0;
      await f.verifier.assertNative(step, input, stage);
      expect(f.native).toHaveBeenCalledExactlyOnceWith(f.state.proof, f.row.id, input, stage, step);
      expect(f.state.order[0]).toBe(`origin:${stage === 'before-send' ? 'before-send' : 'packet'}`);
      // This double owns no Native step load. Real Native load/closing tests
      // are separate; this checks that the dispatcher supplies no extra one.
      expect(f.step).not.toHaveBeenCalled();
    });
  });
  it('rejects cloned, mixed-service and closed minted Native step capabilities', async () => {
    const f = fixture(), other = fixture(); let original: any;
    await f.run(async () => {
      original = await f.verifier.verifyStep(f.state.proof, f.row.id);
      await expect(f.verifier.assertNative({ ...original }, {} as any, 'prepare')).rejects.toThrow();
      await expect(other.verifier.assertNative(original, {} as any, 'prepare')).rejects.toThrow();
      expect(f.native).not.toHaveBeenCalled(); expect(other.native).not.toHaveBeenCalled();
    });
    await expect(f.verifier.assertNative(original, {} as any, 'prepare')).rejects.toThrow();
    expect(f.native).not.toHaveBeenCalled();
  });
  it('does not enter Native when its original Approved callback closes during the authority await', async () => {
    const f = fixture(); let release!: () => void, entered!: () => void, pending!: Promise<void>;
    const gate = new Promise<void>(resolve => { release = resolve; }), started = new Promise<void>(resolve => { entered = resolve; });
    await f.run(async () => {
      const step = await f.verifier.verifyStep(f.state.proof, f.row.id);
      f.delegate.verifyExecution.mockImplementationOnce(async () => { entered(); await gate; return f.origin; });
      pending = f.verifier.assertNative(step, {} as any, 'before-send'); await started;
    });
    const loads = f.load.mock.calls.length; release();
    await expect(pending).rejects.toThrow();
    expect(f.load).toHaveBeenCalledTimes(loads); expect(f.native).not.toHaveBeenCalled();
  });
});
