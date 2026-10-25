import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {vi} from 'vitest';
import {KongExecutionContextService} from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {transportScopeFor} from '../../../apps/console-api/src/infrastructure/kong/transport-scope';
/** Context-only adapter: genuine public Context Namespace/job/step/binding
 * registration and ALS, with controlled issuer/grant/SQL callbacks. No private
 * product registry is seeded; this fixture proves no actual SQL/SDK/claim. */
export function serviceObservationContextFixture(options: { nestedVerifier?: boolean; objectWorkspace?: boolean; expiresIn?: number; nativeKind?: 'native' | 'metadata'; sqlPolicy?: boolean } = {}) {
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