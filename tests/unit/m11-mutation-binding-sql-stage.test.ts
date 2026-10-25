import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MutationService } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';

/** Component boundary: actual Context mutation SQL-stage, ALS, original Namespace/job/nested
 * execution/step registration paths and private binding lifecycle. The fixed
 * Origin/Approved policies are controlled Source adapters, not real SQL or
 * actual Approved/Root claim minting. No product private map is seeded; no
 * HTTP, database, Docker, Native send or production execution is claimed. */
function fixture(options: { nestedVerifier?: boolean; objectWorkspace?: boolean; expiresIn?: number; nativeKind?: 'native' | 'metadata'; sqlPolicy?: boolean } = {}) {
  const context = new KongExecutionContextService(), actor: any = Object.freeze({ id: randomUUID(), username: 'actual-executor', superAdmin: false });
  const cid = randomUUID(), wid = randomUUID(), objectWid = options.objectWorkspace ? randomUUID() : wid, wf = randomUUID();
  const expiresAt = Date.now() + (options.expiresIn ?? 300_000), scope = transportScopeFor('http://kong:8001');
  const nsHandle = Object.freeze({}), accessHandle = Object.freeze({}), originalJob = Object.freeze({}), wrapperHandle = Object.freeze({}), nestedHandle = Object.freeze({});
  const wrapperStepId = randomUUID(), nativeStepId = randomUUID(), nativeId = randomUUID(), originalSid = randomUUID(), operationId = randomUUID();
  const state: any = { live: true, jobLive: true, approvedLive: true, permissionVersion: 'current-epoch-1', registryUrl: 'http://kong:8001',
    copiedNamespaceProof: false, copiedNestedProof: false, allowOtherWorkspace: false, jobProof: null as any, calls: [] as string[], proofs: [] as any[] };
  const ns: any = Object.freeze({ version: 1, origin: 'scheduled-workflow', sessionId: null, actor, clusterId: cid, workspaceId: wid,
    kind: 'configuration_v2', permissionVersion: state.permissionVersion, credentialEpoch: '1', subjectSealHmac: 'a'.repeat(64), transportScope: scope,
    clusterRevision: 1, workspaceRevision: 1, workflow: Object.freeze({ id: wf, planRevision: 2, planHash: 'b'.repeat(64) }),
    requester: Object.freeze({ type: 'console', id: actor.id, credentialEpoch: '1' }), approvalSet: Object.freeze({ format: 2, setId: randomUUID(), setHmac: 'c'.repeat(64), reviewers: [] }),
    claim: Object.freeze({ id: randomUUID(), scheduleId: randomUUID(), generation: 1 }), expiresAt: new Date(expiresAt).toISOString() });
  const wrapperProof: any = Object.freeze({ executionId: randomUUID(), workflowId: wf, clusterId: cid, workspaceId: wid,
    actorId: actor.id, sessionId: null, permissionVersion: state.permissionVersion, expiresAt, origin: 'scheduled-workflow', scheduleClaimId: ns.claim.id,
    workflowOriginId: randomUUID(), approvalFormat: 2, approvalSetId: ns.approvalSet.setId, approvalSetHmac: ns.approvalSet.setHmac });
  const nestedProof: any = Object.freeze({ ...wrapperProof, executionId: randomUUID(), origin: 'scheduled-configuration', configurationOriginId: randomUUID() });
  const jobProof: any = Object.freeze({ origin: 'workflow-scheduled-configuration', sessionId: null, actor, clusterId: cid, workspaceId: wid,
    module: 'snapshots', purpose: 'apply', jobId: randomUUID(), permissionVersion: state.permissionVersion, credentialEpoch: 1, leaseGeneration: 1,
    expiresAt, readOnly: false, namespaceHandle: nsHandle, claimId: ns.claim.id, wrapperOriginId: wrapperProof.workflowOriginId,
    wrapperExecutionId: wrapperProof.executionId, planId: randomUUID(), planRevision: 1, planHash: 'd'.repeat(64), subjectSealHmac: ns.subjectSealHmac,
    originalScheduledJobHandle: originalJob });
  state.jobProof = jobProof;
  const namespaces = new WeakMap<object, any>([[nsHandle, ns]]), jobs = new WeakMap<object, any>([[accessHandle, jobProof]]);
  const executions = new WeakMap<object, any>([[wrapperHandle, wrapperProof], [nestedHandle, nestedProof]]), authenticProofs = new WeakSet<object>([wrapperProof, nestedProof]);
  const stepRegistry = new WeakMap<object, any>(), bindings = new WeakMap<object, any>();
  const assertLive = () => { if (!state.live) throw Error('ORIGINAL_NAMESPACE_LEASE_REVOKED'); };
  const assertCurrent = () => { assertLive(); if (!state.approvedLive || state.permissionVersion !== ns.permissionVersion) throw Error('CURRENT_EXECUTOR_REVOKED'); };
  const namespacePolicy: any = {
    assertLive(handle: object) { if (!namespaces.has(handle)) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); assertLive(); },
    async verifyHandle(handle: object, checkpoint: string) { if (!namespaces.has(handle)) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); assertCurrent(); state.calls.push(`namespace:${checkpoint}`);
      return state.copiedNamespaceProof ? Object.freeze({ ...ns }) : ns; },
  };
  if (options.sqlPolicy !== false) namespacePolicy.verifySqlPreparation = vi.fn(async (handle: object, checkpoint: string) => {
    if (handle !== nsHandle || checkpoint !== 'packet') throw Error('SOURCE_ORIGINAL_SQL_NAMESPACE_REQUIRED');
    const phase = context.scheduledConfigurationPreparationPhase();
    if (!phase) throw Error('SOURCE_CURRENT_SQL_PHASE_REQUIRED');
    state.calls.push(`sql:${phase.stage}`);
    // Controlled SQL issuer must stamp a finite deadline on the actual private
    // stage. It is not a real DB-relative grant proof or commercial evidence.
    if (!state.omitSqlStamp) context.limitScheduledConfigurationPreparation(phase, performance.now() + Math.min(30000, Date.parse(ns.expiresAt) - Date.now()));
    await state.afterSql?.(phase);
    return state.copiedNamespaceProof ? Object.freeze({ ...ns }) : ns;
  });
  context.installWorkflowScheduledNamespacePolicy(namespacePolicy);
  const jobPolicy = { verifyHandle: vi.fn(async (handle: object) => {
    if (!jobs.has(handle)) throw Error('ORIGINAL_ACCESS_JOB_REQUIRED'); assertCurrent(); if (!state.jobLive) throw Error('ORIGINAL_JOB_LEASE_REVOKED');
    state.calls.push('job:verify'); return state.jobProof;
  }), beforeNativeSend: vi.fn(async (handle: object) => { if (!jobs.has(handle) || !state.jobLive) throw Error('ORIGINAL_JOB_LEASE_REVOKED'); assertCurrent(); state.calls.push('job:before-send'); }) };
  context.installConfigurationJobPolicy(jobPolicy);
  const approved: any = {
    verifyExecution: vi.fn(async (handle: object) => { assertCurrent(); if (!executions.has(handle)) throw Error('ORIGINAL_APPROVED_HANDLE_REQUIRED');
      const proof = executions.get(handle); state.proofs.push(proof); return state.copiedNestedProof && proof === nestedProof ? Object.freeze({ ...proof }) : proof; }),
    verifyWorkflowScheduledExecution: vi.fn(async (proof: object, original: object) => { assertCurrent(); if (proof !== wrapperProof || original !== nsHandle) throw Error('ORIGINAL_WRAPPER_PROOF_REQUIRED'); }),
    verifyStep: vi.fn(async (proof: object, stepId: string) => {
      assertCurrent(); if (!authenticProofs.has(proof)) throw Error('ORIGINAL_EXECUTION_PROOF_REQUIRED');
      const wrapper = proof === wrapperProof;
      if (stepId !== (wrapper ? wrapperStepId : nativeStepId)) throw Error('SEALED_STEP_REQUIRED');
      if(!wrapper&&! [wid,objectWid].includes(context.current().workspaceId!))throw Error('SEALED_OBJECT_WORKSPACE_REQUIRED');
      const step = Object.freeze({ execution: proof, stepId, kind: wrapper ? 'metadata' : options.nativeKind ?? 'native' }); stepRegistry.set(step, proof); return step;
    }),
    mutationBinding: vi.fn(async (step: object, input: any) => { assertCurrent(); if (stepRegistry.get(step) !== nestedProof) throw Error('NESTED_V2_STEP_REQUIRED');
      if (input.actor.id !== actor.id || input.clusterId !== cid || input.workspaceId !== objectWid || input.entityType !== 'services' || input.entityId !== nativeId
        || input.action !== 'update' || input.parentId != null || input.credentialKind != null || input.idempotencyKey !== `original-${nativeStepId}`
        || JSON.stringify(input.payload) !== JSON.stringify({ retries: 3 }) || JSON.stringify(input.before) !== JSON.stringify({ retries: 2 })) throw Error('SEALED_MUTATION_TUPLE_REQUIRED');
      await state.afterBinding?.();
      const binding = Object.freeze({ version: 2, workflowId: wf, configurationJobId: jobProof.jobId, configurationExecutionId: nestedProof.executionId,
        configurationStepId: nativeStepId, configurationPlanRevision: 1, configurationPlanHash: jobProof.planHash, beforeHmac: 'e'.repeat(64) });
      bindings.set(binding, step); return binding;
    }),
    bindOperation: vi.fn(async (step: object, _input: unknown, binding: object, operation: string) => {
      assertCurrent(); if (bindings.get(binding) !== step || stepRegistry.get(step) !== nestedProof || operation !== operationId) throw Error('ORIGINAL_V2_BINDING_REQUIRED');
      await state.afterBind?.();
    }),
    assertNative: vi.fn(async (step: any, input: any, stage: string) => {
      assertCurrent(); if (stepRegistry.get(step) !== nestedProof || step.execution !== nestedProof || step.kind !== 'native') throw Error('WRAPPER_V1_NATIVE_FORBIDDEN');
      if (input.clusterId !== cid || input.workspaceId !== objectWid || input.operationId !== operationId || input.frame.sessionId != null
        || input.method !== 'PATCH' || input.canonicalPath !== `/services/${nativeId}`) throw Error('SEALED_NATIVE_TUPLE_REQUIRED');
      state.calls.push(`nested-native:${stage}`);
    }),
    assertMetadata: vi.fn(async (step: any) => { assertCurrent(); if (stepRegistry.get(step) !== wrapperProof) throw Error('WRAPPER_METADATA_REQUIRED'); }),
  };
  if (options.nestedVerifier !== false) approved.verifyWorkflowScheduledConfigurationExecution = vi.fn(async (proof: object, originalNamespace: object, original: object) => {
    assertCurrent(); if (proof !== nestedProof || originalNamespace !== nsHandle || original !== originalJob) throw Error('ORIGINAL_NESTED_PROOF_REQUIRED');
    if (!state.jobLive) throw Error('ORIGINAL_JOB_LEASE_REVOKED'); state.calls.push('nested:original-proof');
  });
  context.installApprovedPolicy(approved);
  const hooks = {
    authorizeRequest: vi.fn(async (frame: any, cluster: any, method: string) => { assertCurrent(); if (cluster.id !== cid || cluster.admin_url !== state.registryUrl) throw Error('CURRENT_REGISTRY_CHANGED');
      if(method!=='GET'&&frame.workspaceId!==objectWid&&!state.allowOtherWorkspace)throw Error('SEALED_OBJECT_WORKSPACE_REQUIRED');return {}; }),
    authorizeResponse: vi.fn(async (_ticket: any, result: any) => { assertCurrent(); return result; }),
    beforeNativeSend: vi.fn(async (_frame: any, cluster: any) => { assertCurrent(); if (cluster.admin_url !== state.registryUrl) throw Error('CURRENT_REGISTRY_CHANGED'); state.calls.push('hooks:before-send'); }),
  };
  context.installPolicy(hooks);
  const cluster: any = { id: cid, admin_url: state.registryUrl, version: '1.5.1', execution_mode: 'approval', transport_scope: scope };
  const wrapper = (fn: () => Promise<any>) => context.runWorkflowScheduledNamespace(nsHandle, () => context.runApprovedWorkflow(wrapperHandle as any,
    () => context.runApprovedStep(wrapperStepId, fn)));
  const job = (fn: () => Promise<any>) => wrapper(() => context.runConfigurationJob(accessHandle, fn));
  const nested = (fn: () => Promise<any>) => job(() => context.runApprovedScheduledConfigurationWorkflow(nestedHandle as any, originalJob as any, fn));
  const native = (fn: () => Promise<any>) => nested(() => context.runApprovedStep(nativeStepId, fn));
  const mutation: any = { actor, clusterId: cid, workspaceId: objectWid, entityType: 'services', entityId: nativeId, action: 'update', payload: { retries: 3 }, before: { retries: 2 }, idempotencyKey: `original-${nativeStepId}` };
  const mutationActor = (fn: () => Promise<any>, input = mutation) => native(() => context.runMutationActor(input, fn));
  const bind = async (input = mutation, op = operationId) => { const binding = await context.approvedMutationBinding(input); await context.bindApprovedOperation(input, binding!, op, {} as any); return binding; };
  const packet = (fn: (ticket: any) => Promise<any>) => mutationActor(async () => { await bind(); return context.runOperation({ ...mutation, operationId }, async () => {
    const ticket = await context.authorizeRequest(cluster, 'PATCH', `/services/${nativeId}`, mutation.payload, {}); return fn(ticket);
  }); });
  return { context, state, ns, jobProof, wrapperProof, nestedProof, originalSid, wrapperHandle, nestedHandle, nsHandle, accessHandle, originalJob,
    wrapperStepId, nativeStepId, cid, wid, objectWid, nativeId, actor, mutation, operationId, approved, jobPolicy, hooks, cluster,
    wrapper, job, nested, native, mutationActor, bind, packet, executions, namespaces, jobs, namespacePolicy };
}


beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T22:00:00Z')); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ae'.repeat(32)); });
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });
const denied = (code: string) => ({ response: { code } });
const gate = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };

describe('private configuration mutation-binding SQL preparation stage', () => {
  it('exposes the exact frozen stage only during the original fixed policy invocation and SQL closing', async () => {
    const f = fixture(); let seen: any, returned: any;
    const original = f.approved.mutationBinding.getMockImplementation()!;
    f.approved.mutationBinding.mockImplementation(async (step: any, input: any) => {
      seen = f.context.scheduledConfigurationPreparationPhase();
      expect(seen).toMatchObject({ stage: 'mutation-binding', frame: f.context.current(), namespaceHandle: f.nsHandle,
        namespace: f.ns, originalJobHandle: f.originalJob, execution: f.nestedProof, step });
      expect(seen.operation).toBeUndefined(); expect(f.context.current().operation).toBeUndefined(); expect(Object.isFrozen(seen)).toBe(true);
      expect(Object.keys(seen).sort()).toEqual(['execution', 'frame', 'namespace', 'namespaceHandle', 'operation', 'originalJobHandle', 'stage', 'step'].sort());
      returned = await original(step, input); return returned;
    });
    await f.mutationActor(async () => {
      expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
      const value = await f.context.approvedMutationBinding(f.mutation);
      expect(value).toBe(returned); expect(value).toMatchObject({ version: 2, configurationExecutionId: f.nestedProof.executionId });
      expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
      expect(() => f.context.limitScheduledConfigurationPreparation(seen, performance.now() + 1000)).toThrow();
    });
    expect(f.approved.mutationBinding).toHaveBeenCalledOnce(); expect(f.namespacePolicy.verifySqlPreparation).toHaveBeenCalledOnce();
    expect(f.state.calls).toContain('sql:mutation-binding'); expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
  });

  it.each(['unmarked-native-step', 'copied-context', 'bound-marker', 'operation', 'missing-sql-policy'] as const)('keeps %s on the original complete binding path without a new SQL stage', async reason => {
    const f = fixture({ sqlPolicy: reason !== 'missing-sql-policy' }); const phases: any[] = [];
    const original = f.approved.mutationBinding.getMockImplementation()!;
    f.approved.mutationBinding.mockImplementation(async (step: any, input: any) => { phases.push(f.context.scheduledConfigurationPreparationPhase()); return original(step, input); });
    if (reason === 'unmarked-native-step') await f.native(() => f.context.approvedMutationBinding(f.mutation));
    else await f.mutationActor(async () => {
      if (reason === 'bound-marker' || reason === 'operation') await f.bind();
      if (reason === 'operation') await f.context.runOperation({ ...f.mutation, operationId: f.operationId }, () => f.context.approvedMutationBinding(f.mutation));
      else await f.context.approvedMutationBinding(reason === 'copied-context' ? { ...f.mutation } : f.mutation);
    });
    const selected = reason === 'bound-marker' || reason === 'operation' ? phases.slice(1) : phases;
    expect(selected).toEqual([null]);
    if (reason === 'bound-marker' || reason === 'operation') expect(phases[0]?.stage).toBe('mutation-binding');
    else if (f.namespacePolicy.verifySqlPreparation) expect(f.namespacePolicy.verifySqlPreparation).not.toHaveBeenCalled();
  });

  it('retains an ordinary non-approved mutation null result without entering a configuration stage', async () => {
    const f = fixture();
    await f.context.runHttp({}, async () => {
      f.context.bindHttpActor(f.actor, f.originalSid); const close = f.context.captureHttpCloser();
      try { await f.context.runActor({ actor: f.actor, clusterId: f.cid, workspaceId: f.wid, module: 'services', action: 'write' }, async () => {
        await expect(f.context.approvedMutationBinding(f.mutation)).resolves.toBeNull(); expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
      }); } finally { close(); }
    });
    expect(f.approved.mutationBinding).not.toHaveBeenCalled(); expect(f.namespacePolicy.verifySqlPreparation).not.toHaveBeenCalled();
  });

  it.each(['before', 'payload', 'action', 'entityId', 'parentId', 'credentialKind', 'idempotencyKey'] as const)('rejects in-place %s drift while the original fixed binding policy awaits', async field => {
    const f = fixture(); f.state.afterBinding = async () => {
      expect(f.context.scheduledConfigurationPreparationPhase()?.stage).toBe('mutation-binding');
      if (field === 'before') f.mutation.before.retries = 999;
      if (field === 'payload') f.mutation.payload.retries = 999;
      if (field === 'action') f.mutation.action = 'delete';
      if (field === 'entityId') f.mutation.entityId = randomUUID();
      if (field === 'parentId') f.mutation.parentId = randomUUID();
      if (field === 'credentialKind') f.mutation.credentialKind = 'key-auth';
      if (field === 'idempotencyKey') f.mutation.idempotencyKey = 'changed-key';
    };
    await f.mutationActor(async () => {
      await expect(f.context.approvedMutationBinding(f.mutation)).rejects.toBeDefined();
      expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
    });
    expect(f.approved.mutationBinding).toHaveBeenCalledOnce(); expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
  });

  it.each(['null', 'v1', 'job', 'execution', 'step', 'plan', 'revision'] as const)('rejects a fixed binding policy result with %s mismatch without retry or fallback', async reason => {
    const f = fixture(), original = f.approved.mutationBinding.getMockImplementation()!;
    f.approved.mutationBinding.mockImplementation(async (step: any, input: any) => {
      const value = await original(step, input);
      if (reason === 'null') return null;
      if (reason === 'v1') return { workflowId: f.wrapperProof.workflowId, executionId: f.nestedProof.executionId };
      return { ...value, ...(reason === 'job' ? { configurationJobId: randomUUID() } : reason === 'execution' ? { configurationExecutionId: randomUUID() }
        : reason === 'step' ? { configurationStepId: randomUUID() } : reason === 'plan' ? { configurationPlanHash: 'f'.repeat(64) } : { configurationPlanRevision: 2 }) };
    });
    await f.mutationActor(async () => {
      await expect(f.context.approvedMutationBinding(f.mutation)).rejects.toBeDefined(); expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
    });
    expect(f.approved.mutationBinding).toHaveBeenCalledOnce(); expect(f.hooks.authorizeRequest).not.toHaveBeenCalled();
  });

  it('shadows the SQL marker during a genuine nested GET and internal-read descendant, then restores only its original frame', async () => {
    const f = fixture(), seen: any[] = [], original = f.hooks.authorizeRequest.getMockImplementation()!;
    f.hooks.authorizeRequest.mockImplementation(async (...args: any[]) => { seen.push({ kind: f.context.current().kind, method: args[2], phase: f.context.scheduledConfigurationPreparationPhase() }); return original(...args); });
    f.state.afterBinding = async () => {
      const phase = f.context.scheduledConfigurationPreparationPhase(); expect(phase?.stage).toBe('mutation-binding');
      const first = await f.context.authorizeRequest(f.cluster, 'GET', `/services/${f.nativeId}`, undefined, {});
      await f.context.authorizeResponse(first, { id: f.nativeId }); expect(f.context.scheduledConfigurationPreparationPhase()).toBe(phase);
      await f.context.runInternalRead(f.cid, 'authorization', async () => {
        expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
        const ticket = await f.context.authorizeRequest(f.cluster, 'GET', `/services/${f.nativeId}`, undefined, {});
        await f.context.authorizeResponse(ticket, { id: f.nativeId });
      }, { paths: [`/services/${f.nativeId}`], maxCalls: 1 });
      expect(f.context.scheduledConfigurationPreparationPhase()).toBe(phase);
    };
    await f.mutationActor(() => f.context.approvedMutationBinding(f.mutation));
    expect(seen).toHaveLength(2); expect(seen.map(v => v.phase)).toEqual([null, null]);
    expect(seen.map(v => v.kind)).toEqual(['actor', 'internal-read']);
    expect(f.namespacePolicy.verifySqlPreparation).toHaveBeenCalledOnce();
  });

  it.each(['authorizeRequest', 'approved-authorize', 'approved-before-send'] as const)('does not lend mutation-binding SQL mode to the old %s Native entry', async entry => {
    const f = fixture(); f.state.afterBinding = async () => {
      const frame = f.context.current(), input: any = { clusterId: f.cid, workspaceId: f.wid, transportScope: f.cluster.transport_scope,
        operationId: f.operationId, method: 'PATCH', canonicalPath: `/services/${f.nativeId}`, body: f.mutation.payload, before: f.mutation.before,
        mutationAction: 'update', query: {} };
      if (entry === 'authorizeRequest') await f.context.authorizeRequest(f.cluster, 'PATCH', input.canonicalPath, input.body, {});
      else await f.context.assertApprovedOperation(frame, f.cluster, input, entry === 'approved-authorize' ? 'authorize' : 'before-send');
    };
    await f.mutationActor(async () => {
      await expect(f.context.approvedMutationBinding(f.mutation)).rejects.toBeDefined(); expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
    });
    expect(f.approved.mutationBinding).toHaveBeenCalledOnce(); expect(f.approved.assertNative).not.toHaveBeenCalled();
  });

  it('does not recursively re-enter the fixed binding provider under the same private SQL stage', async () => {
    const f = fixture(); f.state.afterBinding = async () => { await f.context.approvedMutationBinding(f.mutation); };
    await f.mutationActor(async () => { await expect(f.context.approvedMutationBinding(f.mutation)).rejects.toBeDefined(); expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull(); });
    expect(f.approved.mutationBinding).toHaveBeenCalledOnce();
  });

  it('refuses a fixed SQL provider that returns the same namespace without stamping its finite private closing deadline', async () => {
    const f = fixture(); f.state.omitSqlStamp = true;
    await f.mutationActor(async () => {
      await expect(f.context.approvedMutationBinding(f.mutation)).rejects.toMatchObject(denied('CONFIGURATION_MUTATION_BINDING_SQL_CLOSING_REQUIRED'));
      expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
    });
    expect(f.approved.mutationBinding).toHaveBeenCalledOnce(); expect(f.namespacePolicy.verifySqlPreparation).toHaveBeenCalledOnce();
  });

  it('closes a rejected provider invocation without retaining any stage evidence', async () => {
    const f = fixture(); let phase: any;
    f.approved.mutationBinding.mockImplementationOnce(async () => { phase = f.context.scheduledConfigurationPreparationPhase(); throw Error('SOURCE_FIXED_BINDING_POLICY_REJECTED'); });
    await f.mutationActor(async () => {
      await expect(f.context.approvedMutationBinding(f.mutation)).rejects.toThrow('SOURCE_FIXED_BINDING_POLICY_REJECTED');
      expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
      expect(() => f.context.limitScheduledConfigurationPreparation(phase, performance.now() + 1000)).toThrow();
    });
    expect(f.approved.mutationBinding).toHaveBeenCalledOnce(); expect(f.namespacePolicy.verifySqlPreparation).not.toHaveBeenCalled();
  });

  it.each(['copied-context','changed-operation-id'] as const)('rejects active-stage %s reentry before every complete-provider fallback',async reason=>{
    const f=fixture();
    f.state.afterBinding=async()=>{
      const input=reason==='copied-context'?{...f.mutation}:{...f.mutation,operationId:f.operationId};
      await expect(f.context.approvedMutationBinding(input)).rejects.toMatchObject(denied('CONFIGURATION_MUTATION_BINDING_SQL_REENTRANT'));
      // The rejected inner call cannot recurse through the complete policy or
      // consume the outer stage's SQL-only selector. The original call lives.
      expect(f.approved.mutationBinding).toHaveBeenCalledOnce();
    };
    await f.mutationActor(()=>f.context.approvedMutationBinding(f.mutation));
    expect(f.approved.mutationBinding).toHaveBeenCalledOnce();expect(f.namespacePolicy.verifySqlPreparation).toHaveBeenCalledOnce();
  });

  it('withholds a binding when its original callback closes during the fixed policy await', async () => {
    const f = fixture(), entered = gate(), release = gate(); let pending!: Promise<any>;
    f.state.afterBinding = async () => { entered.resolve(); await release.promise; };
    await f.mutationActor(async () => { pending = f.context.approvedMutationBinding(f.mutation); void pending.catch(() => undefined); await entered.promise; });
    release.resolve(); await expect(pending).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
    expect(f.namespacePolicy.verifySqlPreparation).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });

  it('checks its monotonic bound again after the ALS callback final Promise continuation', async () => {
    const f = fixture(); let mono = 1000, armed = false, queued = false;
    vi.spyOn(performance, 'now').mockImplementation(() => mono);
    const getter = f.context.scheduledConfigurationPreparationPhase.bind(f.context);
    vi.spyOn(f.context, 'scheduledConfigurationPreparationPhase').mockImplementation(() => {
      const value = getter();
      // The fixed SQL provider has returned. Advance after its final inner
      // synchronous getter, before the outer ALS await continuation returns.
      if (armed && value && !queued) { queued = true; queueMicrotask(() => { mono += 11; }); }
      return value;
    });
    f.state.afterBinding = async () => { const phase = f.context.scheduledConfigurationPreparationPhase()!; f.context.limitScheduledConfigurationPreparation(phase, mono + 10); };
    f.state.afterSql = async () => { armed = true; };
    await f.mutationActor(async () => {
      await expect(f.context.approvedMutationBinding(f.mutation)).rejects.toBeDefined();
      expect(queued).toBe(true); expect(mono).toBe(1011); expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
    });
    expect(f.approved.mutationBinding).toHaveBeenCalledOnce(); expect(f.namespacePolicy.verifySqlPreparation).toHaveBeenCalledOnce();
  });

  it('does not renew a shortened private monotonic bound through the final SQL-provider Promise continuation', async () => {
    const f = fixture(); let mono = 1000; vi.spyOn(performance, 'now').mockImplementation(() => mono);
    f.state.afterBinding = async () => { const phase = f.context.scheduledConfigurationPreparationPhase()!; f.context.limitScheduledConfigurationPreparation(phase, mono + 10); };
    f.state.afterSql = async () => { mono += 11; };
    await f.mutationActor(async () => {
      await expect(f.context.approvedMutationBinding(f.mutation)).rejects.toBeDefined(); expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();
    });
    expect(f.approved.mutationBinding).toHaveBeenCalledOnce(); expect(f.namespacePolicy.verifySqlPreparation).toHaveBeenCalledOnce();
  });
});
