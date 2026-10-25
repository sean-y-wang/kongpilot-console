import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';

/** Real Context ALS, ancestor lifecycle, private boundary and tickets. The
 * fixed SQL/Origin/Approved providers use genuine original WeakMap registries
 * in this fixture. No HTTP, database, timer, Docker or Native send is used. */
function fixture(options: { nestedVerifier?: boolean; objectWorkspace?: boolean } = {}) {
  const context = new KongExecutionContextService(), actor: any = Object.freeze({ id: randomUUID(), username: 'actual-executor', superAdmin: false });
  const cid = randomUUID(), wid = randomUUID(), objectWid = options.objectWorkspace ? randomUUID() : wid, wf = randomUUID();
  const expiresAt = Date.now() + 60_000, scope = transportScopeFor('http://kong:8001');
  const nsHandle = Object.freeze({}), accessHandle = Object.freeze({}), originalJob = Object.freeze({}), wrapperHandle = Object.freeze({}), nestedHandle = Object.freeze({});
  const wrapperStepId = randomUUID(), nativeStepId = randomUUID(), nativeId = randomUUID(), originalSid = randomUUID(), operationId = randomUUID();
  const state = { live: true, jobLive: true, approvedLive: true, permissionVersion: 'current-epoch-1', registryUrl: 'http://kong:8001',
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
  context.installWorkflowScheduledNamespacePolicy({
    assertLive(handle) { if (!namespaces.has(handle)) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); assertLive(); },
    async verifyHandle(handle, checkpoint) { if (!namespaces.has(handle)) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); assertCurrent(); state.calls.push(`namespace:${checkpoint}`);
      return state.copiedNamespaceProof ? Object.freeze({ ...ns }) : ns; },
  });
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
      const step = Object.freeze({ execution: proof, stepId, kind: wrapper ? 'metadata' : 'native' }); stepRegistry.set(step, proof); return step;
    }),
    mutationBinding: vi.fn(async (step: object, input: any) => { assertCurrent(); if (stepRegistry.get(step) !== nestedProof) throw Error('NESTED_V2_STEP_REQUIRED');
      if (input.workspaceId !== objectWid || input.entityId !== nativeId) throw Error('SEALED_OBJECT_WORKSPACE_REQUIRED');
      const binding = Object.freeze({ version: 2, workflowId: wf, configurationJobId: jobProof.jobId, configurationExecutionId: nestedProof.executionId,
        configurationStepId: nativeStepId, configurationPlanRevision: 1, configurationPlanHash: jobProof.planHash, beforeHmac: 'e'.repeat(64) });
      bindings.set(binding, step); return binding;
    }),
    bindOperation: vi.fn(async (step: object, _input: unknown, binding: object, operation: string) => {
      assertCurrent(); if (bindings.get(binding) !== step || stepRegistry.get(step) !== nestedProof || operation !== operationId) throw Error('ORIGINAL_V2_BINDING_REQUIRED');
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
  const native = (fn: () => Promise<any>) => nested(() => context.runApprovedStep(nativeStepId, () => context.runActor({ actor, clusterId: cid, workspaceId: objectWid, module: 'snapshots', action: 'write' }, fn)));
  const mutation: any = { actor, clusterId: cid, workspaceId: objectWid, entityType: 'services', entityId: nativeId, action: 'update', payload: { retries: 3 }, before: { retries: 2 }, idempotencyKey: `original-${nativeStepId}` };
  const packet = (fn: (ticket: any) => Promise<any>) => native(() => context.runOperation({ ...mutation, operationId }, async () => {
    const ticket = await context.authorizeRequest(cluster, 'PATCH', `/services/${nativeId}`, mutation.payload, {}); return fn(ticket);
  }));
  return { context, state, ns, jobProof, wrapperProof, nestedProof, originalSid, wrapperHandle, nestedHandle, nsHandle, accessHandle, originalJob,
    wrapperStepId, nativeStepId, cid, wid, objectWid, nativeId, actor, mutation, operationId, approved, jobPolicy, hooks, cluster,
    wrapper, job, nested, native, packet, executions, namespaces, jobs };
}

describe('real Context scheduled nested configuration ancestry and V2 isolation', () => {
  it('retains the real namespace, job and wrapper ancestors while shadowing the metadata step', async () => {
    const f = fixture(); let nativeProof: any;
    await f.nested(async () => {
      expect(f.context.requireWorkflowScheduledNamespaceHandle()).toBe(f.nsHandle); expect(f.context.current().sessionId).toBeUndefined();
      expect(() => f.context.currentApprovedStep()).toThrow();
      await expect(f.context.approvedMutationBinding(f.mutation)).rejects.toMatchObject({ response: { code: 'APPROVED_STEP_REQUIRED' } });
      await f.context.runApprovedStep(f.nativeStepId, async () => {
        nativeProof = f.context.currentApprovedStep(); expect(nativeProof.kind).toBe('native'); expect(nativeProof.execution).toBe(f.nestedProof);
        const binding = await f.context.approvedMutationBinding(f.mutation); expect(binding).toMatchObject({ version: 2, configurationExecutionId: f.nestedProof.executionId });
        expect(binding).not.toHaveProperty('executionId'); await f.context.bindApprovedOperation(f.mutation, binding!, f.operationId, {} as any);
        await expect(f.context.bindApprovedOperation(f.mutation, { ...binding } as any, f.operationId, {} as any)).rejects.toThrow('ORIGINAL_V2_BINDING_REQUIRED');
      });
      expect(() => f.context.currentApprovedStep()).toThrow();
    });
    expect(f.context.peek()).toBeNull(); expect(nativeProof.execution).not.toBe(f.wrapperProof);
  });
  it('runs Native policy checks at every actual ticket phase using only the nested V2 proof', async () => {
    const f = fixture();
    await f.packet(async ticket => {
      await f.context.assertApprovedNativeRequest(ticket, 'authorize'); await f.context.assertApprovedNativeRequest(ticket, 'prepare');
      await f.context.beforeNativeSend(ticket); await expect(f.context.authorizeResponse(ticket, { id: f.nativeId, retries: 3 })).resolves.toMatchObject({ retries: 3 });
    });
    for (const phase of ['authorize', 'prepare', 'before-send', 'response']) expect(f.state.calls).toContain(`nested-native:${phase}`);
    expect(f.jobPolicy.beforeNativeSend).toHaveBeenCalled(); expect(f.approved.assertNative.mock.calls.every(call => call[0].execution === f.nestedProof)).toBe(true);
  });
  it('charges reads to the original namespace through all nested ancestors', async () => {
    const f = fixture(); let usage: any;
    await f.context.runWorkflowScheduledNamespace(f.nsHandle, async () => {
      await f.context.runApprovedWorkflow(f.wrapperHandle as any, () => f.context.runApprovedStep(f.wrapperStepId, () => f.context.runConfigurationJob(f.accessHandle,
        () => f.context.runApprovedScheduledConfigurationWorkflow(f.nestedHandle as any, f.originalJob as any, () => f.context.runApprovedStep(f.nativeStepId, async () => {
          for (let index = 0; index < 2; index++) await f.context.runInternalRead(f.cid, 'authorization', async () => {
            const ticket = await f.context.authorizeRequest(f.cluster, 'GET', `/services/${f.nativeId}`, undefined, {});
            await f.context.authorizeResponse(ticket, { id: f.nativeId });
          }, { paths: [`/services/${f.nativeId}`], maxCalls: 1 });
        })))));
      usage = f.context.currentUsage();
    }); expect(usage.calls).toBe(2); expect(usage.bytes).toBeGreaterThan(0);
  });
  it.each(['namespace', 'access-job', 'wrapper', 'nested'])('rejects a copied original %s handle', async kind => {
    const f = fixture();
    const operation = kind === 'namespace' ? f.context.runWorkflowScheduledNamespace({ ...f.nsHandle }, async () => undefined)
      : kind === 'wrapper' ? f.context.runWorkflowScheduledNamespace(f.nsHandle, () => f.context.runApprovedWorkflow({ ...f.wrapperHandle } as any, async () => undefined))
      : kind === 'access-job' ? f.wrapper(() => f.context.runConfigurationJob({ ...f.accessHandle }, async () => undefined))
      : f.job(() => f.context.runApprovedScheduledConfigurationWorkflow({ ...f.nestedHandle } as any, f.originalJob as any, async () => undefined));
    await expect(operation).rejects.toThrow(/ORIGINAL_/); expect(f.hooks.beforeNativeSend).not.toHaveBeenCalled();
  });
  it('rejects a copied nested proof returned by a provider rather than accepting its field shape', async () => {
    const f = fixture(); f.state.copiedNestedProof = true;
    await expect(f.nested(async () => undefined)).rejects.toThrow('ORIGINAL_NESTED_PROOF_REQUIRED');
  });
  it('rejects original job-handle mismatch and missing nested verifier before any Native step', async () => {
    const f = fixture();
    await expect(f.job(() => f.context.runApprovedScheduledConfigurationWorkflow(f.nestedHandle as any, { ...f.originalJob } as any, async () => undefined))).rejects.toMatchObject({ response: { code: 'CONFIGURATION_SCHEDULED_NESTED_CONTEXT_REQUIRED' } });
    const missing = fixture({ nestedVerifier: false });
    await expect(missing.nested(async () => undefined)).rejects.toMatchObject({ response: { code: 'CONFIGURATION_SCHEDULED_NESTED_CONTEXT_REQUIRED' } });
    expect(missing.hooks.beforeNativeSend).not.toHaveBeenCalled();
  });
  it('keeps an ordinary NULL-SID configuration source and inherited HTTP adoption closed', async () => {
    const f = fixture();
    await expect(f.context.runConfigurationJob(f.accessHandle, async () => undefined)).rejects.toMatchObject({ response: { code: 'CONFIGURATION_JOB_AUTHORITY_INVALID' } });
    await f.context.runHttp({}, async () => { f.context.bindHttpActor(f.actor, f.originalSid);
      await expect(f.context.runWorkflowScheduledNamespace(f.nsHandle, async () => undefined)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_EXISTING_CONTEXT_FORBIDDEN' } });
    });
  });
  it('does not let the wrapper metadata step call Native or the ordinary Approved entry adopt nested authority', async () => {
    const f = fixture();
    await f.job(async () => {
      await expect(f.context.runApprovedWorkflow(f.nestedHandle as any, async () => undefined)).rejects.toMatchObject({ response: { code: 'APPROVED_EXECUTION_CONTEXT_INVALID' } });
      await expect(f.context.approvedMutationBinding(f.mutation)).rejects.toMatchObject({ response: { code: 'APPROVED_NATIVE_STEP_REQUIRED' } });
      await expect(f.context.runApprovedStep(f.nativeStepId, async () => undefined)).rejects.toMatchObject({ response: { code: 'APPROVED_STEP_REQUIRED' } });
    }); expect(f.approved.assertNative).not.toHaveBeenCalled();
  });
  it.each(['namespace-lease', 'job-lease', 'permission-version'])('fences a valid ticket when current %s is revoked before wire', async kind => {
    const f = fixture();
    await f.packet(async ticket => {
      if (kind === 'namespace-lease') f.state.live = false; else if (kind === 'job-lease') f.state.jobLive = false; else f.state.permissionVersion = 'changed-epoch-2';
      await expect(f.context.beforeNativeSend(ticket)).rejects.toThrow(/REVOKED/); expect(f.hooks.beforeNativeSend).not.toHaveBeenCalled();
    });
  });
  it('rechecks the actual registry after a ticket was allocated', async () => {
    const f = fixture();
    await f.packet(async ticket => {
      f.state.registryUrl = 'http://changed-kong:8001';
      await expect(f.context.refreshAuthorization(ticket)).rejects.toThrow('CURRENT_REGISTRY_CHANGED');
      await expect(f.context.beforeNativeSend(ticket)).rejects.toThrow('CURRENT_REGISTRY_CHANGED');
    });
  });
  it('a copied namespace proof fences a nested ticket despite identical identity fields', async () => {
    const f = fixture();
    await f.packet(async ticket => { f.state.copiedNamespaceProof = true;
      await expect(f.context.beforeNativeSend(ticket)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_NAMESPACE_SCOPE_CHANGED' } });
    });
  });
  it('rejects a detached continuation after the original nested callback closes', async () => {
    const f = fixture(); let release!: () => void, detached!: Promise<any>; const gate = new Promise<void>(resolve => { release = resolve; });
    await f.packet(async ticket => { detached = (async () => { await gate; return f.context.beforeNativeSend(ticket); })(); });
    release(); await expect(detached).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CONTEXT_EXPIRED' } });
  });
  it('permits the sealed configuration object workspace while retaining the anchor namespace', async () => {
    const f = fixture({ objectWorkspace: true });
    await f.packet(async ticket => { expect(f.context.current().workspaceId).toBe(f.objectWid); expect(f.context.requireWorkflowScheduledNamespaceHandle()).toBe(f.nsHandle);
      await f.context.beforeNativeSend(ticket); await f.context.authorizeResponse(ticket, { id: f.nativeId });
    });
  });
  it('keeps an unrelated workspace closed under a genuine nested configuration boundary', async () => {
    const f = fixture({ objectWorkspace: true }), other = randomUUID();
    await f.native(async () => {
      const attempted = () => f.context.runActor({ actor: f.actor, clusterId: f.cid, workspaceId: other, module: 'snapshots', action: 'write' },
        () => f.context.runOperation({ ...f.mutation, workspaceId: other, operationId: f.operationId },
          () => f.context.authorizeRequest(f.cluster, 'PATCH', `/services/${f.nativeId}`, f.mutation.payload, {})));
      await expect(attempted()).rejects.toThrow(); expect(f.hooks.beforeNativeSend).not.toHaveBeenCalled();
    });
  });
  it('the V2 Native policy rejects an unsealed object workspace even when its general write grant exists', async () => {
    const f = fixture({ objectWorkspace: true }), other = randomUUID(); f.state.allowOtherWorkspace = true;
    await f.native(() => f.context.runActor({ actor: f.actor, clusterId: f.cid, workspaceId: other, module: 'snapshots', action: 'write' },
      () => f.context.runOperation({ ...f.mutation, workspaceId: other, operationId: f.operationId }, async () => {
        const ticket = await f.context.authorizeRequest(f.cluster, 'PATCH', `/services/${f.nativeId}`, f.mutation.payload, {});
        await expect(f.context.beforeNativeSend(ticket)).rejects.toThrow('SEALED_NATIVE_TUPLE_REQUIRED');
        expect(f.hooks.beforeNativeSend).not.toHaveBeenCalled();
      })));
  });
  it('preserves the ordinary HTTP configuration job, Approved and Native session path', async () => {
    const context = new KongExecutionContextService(), actor: any = { id: randomUUID(), username: 'http-executor', superAdmin: false }, sid = randomUUID();
    const cid = randomUUID(), wid = randomUUID(), eid = randomUUID(), workflowId = randomUUID(), stepId = randomUUID(), nativeId = randomUUID();
    const jobHandle = Object.freeze({}), executionHandle = Object.freeze({}), expiresAt = Date.now() + 60_000;
    const jobProof: any = Object.freeze({ actor, sessionId: sid, clusterId: cid, workspaceId: wid, module: 'snapshots', purpose: 'apply',
      jobId: randomUUID(), permissionVersion: 'http-current-epoch', credentialEpoch: 1, leaseGeneration: 1, expiresAt, readOnly: false });
    const execution: any = Object.freeze({ executionId: eid, workflowId, actorId: actor.id, sessionId: sid, clusterId: cid, workspaceId: wid,
      permissionVersion: 'http-current-epoch', expiresAt });
    const originalJobs = new WeakMap<object, any>([[jobHandle, jobProof]]), originalExecutions = new WeakMap<object, any>([[executionHandle, execution]]);
    const steps = new WeakMap<object, any>(); const native = vi.fn(async (proof: any, input: any) => {
      if(steps.get(proof)!==execution||input.frame.sessionId!==sid||input.frame.actor?.id!==actor.id)throw Error('ORIGINAL_HTTP_NATIVE_REQUIRED');
    });
    context.installConfigurationJobPolicy({ async verifyHandle(handle) { const proof = originalJobs.get(handle); if(!proof)throw Error('ORIGINAL_HTTP_JOB_REQUIRED');return proof; } });
    context.installApprovedPolicy({ async verifyExecution(handle) { const proof=originalExecutions.get(handle);if(!proof)throw Error('ORIGINAL_HTTP_APPROVED_REQUIRED');return proof; },
      async verifyStep(proof,id) { if(proof!==execution||id!==stepId)throw Error('ORIGINAL_HTTP_STEP_REQUIRED');const step=Object.freeze({execution:proof,stepId:id,kind:'native' as const});steps.set(step,execution);return step; },
      async mutationBinding(){throw Error('UNUSED');},async bindOperation(){throw Error('UNUSED');},assertNative:native,async assertMetadata(){throw Error('UNUSED');} });
    context.installPolicy({async authorizeRequest(){return{};},async authorizeResponse(_decision,result){return result;}});
    const cluster: any = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'approval' };
    await context.runHttp({}, async () => { context.bindHttpActor(actor,sid);
      await context.runConfigurationJob(jobHandle, () => context.runApprovedWorkflow(executionHandle as any, () => context.runApprovedStep(stepId,
        () => context.runOperation({ actor, clusterId: cid, workspaceId: wid, entityType: 'services', entityId: nativeId, operationId: randomUUID() }, async () => {
          expect(context.current().sessionId).toBe(sid);const ticket=await context.authorizeRequest(cluster,'PATCH',`/services/${nativeId}`,{retries:3},{});
          await context.beforeNativeSend(ticket);await context.authorizeResponse(ticket,{id:nativeId});
        }))));
    });expect(native).toHaveBeenCalled();expect(native.mock.calls.every(call=>call[0].execution===execution)).toBe(true);
  });
});
