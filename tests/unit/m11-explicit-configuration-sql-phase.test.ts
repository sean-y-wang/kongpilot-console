import { randomUUID } from 'node:crypto';
import {performance} from 'node:perf_hooks';
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
    async verifySqlPreparation(handle){if(handle!==nsHandle)throw Error('ORIGINAL_NAMESPACE_REQUIRED');assertCurrent();state.calls.push('namespace:sql');
      const phase=context.scheduledConfigurationPreparationPhase();if(!phase)throw Error('SQL_PHASE_REQUIRED');
      await (state as any).onSql?.(phase);return state.copiedNamespaceProof?Object.freeze({...ns}):ns;},
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


/** Real Context frames/steps/jobs/tickets and phase storage; providers below are
 * explicit controlled adapters. Separate canonical tests exercise actual SQL
 * policy, AEAD and all-party grants. No DB/HTTP/Native receipt is claimed. */
describe('explicit scheduled configuration SQL preparation phases',()=>{
 it('limits SQL preparation to exact original write frame and ends before publishing a ticket',async()=>{
  const f=fixture();let captured:any;
  f.hooks.authorizeRequest.mockImplementation(async()=>{captured=f.context.scheduledConfigurationPreparationPhase();expect(captured).toBeTruthy();expect(Object.isFrozen(captured)).toBe(true);
   expect(captured).not.toHaveProperty('active');expect(captured).not.toHaveProperty('deadline');return{};});
  await f.packet(async ticket=>{expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();expect(captured.originalJobHandle).toBe(f.originalJob);
   expect(f.state.calls.filter(x=>x==='namespace:sql').length).toBeGreaterThanOrEqual(2);f.state.calls.length=0;
   await f.context.refreshAuthorization(ticket);expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();expect(f.state.calls).toContain('namespace:sql');});
  expect(()=>Object.assign(captured,{active:true})).toThrow();
 });
 it('retains full Native guards for a genuine nested internal GET and restores the outer SQL phase',async()=>{
  const f=fixture();let nested=false;
  f.hooks.authorizeRequest.mockImplementation(async(_frame,_cluster,method)=>{
   if(method==='GET'){expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();nested=true;return{};}
   const phase=f.context.scheduledConfigurationPreparationPhase();expect(phase).toBeTruthy();
   await f.context.runInternalRead(f.cid,'authorization',async()=>{const t=await f.context.authorizeRequest(f.cluster,'GET',`/services/${f.nativeId}`,undefined,{});await f.context.authorizeResponse(t,{id:f.nativeId});},{paths:[`/services/${f.nativeId}`],maxCalls:1});
   expect(f.context.scheduledConfigurationPreparationPhase()).toBe(phase);return{};
  });
  await f.packet(async()=>{});expect(nested).toBe(true);expect(f.state.calls.filter(x=>x==='namespace:capture').length).toBeGreaterThanOrEqual(2);
 });
 it('keeps DNS final and response Native stages, including hooks reentering authorize',async()=>{
  const f=fixture(),seen:any[]=[];
  f.approved.assertNative.mockImplementation(async(_proof:any,_input:any,stage:string)=>{seen.push({stage,phase:f.context.scheduledConfigurationPreparationPhase()});});
  f.hooks.beforeNativeSend.mockImplementation(async()=>{
   expect(f.context.scheduledConfigurationPreparationPhase()).toBeNull();const frame=f.context.current();
   await f.context.assertApprovedOperation(frame,f.cluster,{clusterId:f.cid,workspaceId:f.wid,transportScope:f.ns.transportScope,operationId:f.operationId,method:'PATCH',canonicalPath:`/services/${f.nativeId}`,body:f.mutation.payload,before:f.mutation.before,mutationAction:'update',query:{}},'authorize');
  });
  await f.packet(async ticket=>{for(let dnsRound=0;dnsRound<2;dnsRound++)await f.context.beforeNativeSend(ticket);await f.context.authorizeResponse(ticket,{id:f.nativeId});});
  expect(seen.map(x=>x.stage)).toContain('response');expect(seen.filter(x=>x.stage==='before-send').length).toBe(4);expect(seen.every(x=>x.phase===null)).toBe(true);
 });
 it.each(['before-send','response'] as const)('forbids direct %s reentry inside SQL preparation',async stage=>{
  const f=fixture();await f.packet(async old=>{
   f.hooks.authorizeRequest.mockImplementation(async()=>{await expect(f.context.assertApprovedNativeRequest(old,stage)).rejects.toMatchObject({response:{code:'CONFIGURATION_SQL_PREPARATION_NATIVE_FORBIDDEN'}});return{};});
   await f.context.refreshAuthorization(old);
  });
 });
 it('forbids same-frame second packet and differing packet fields inside preparation',async()=>{
  const f=fixture();f.hooks.authorizeRequest.mockImplementation(async()=>{
   await expect(f.context.authorizeRequest(f.cluster,'PATCH',`/services/${f.nativeId}`,f.mutation.payload,{})).rejects.toMatchObject({response:{code:'CONFIGURATION_SQL_PREPARATION_REENTRANT'}});
   const frame=f.context.current();await expect(f.context.assertApprovedOperation(frame,f.cluster,{clusterId:f.cid,workspaceId:f.wid,transportScope:f.ns.transportScope,operationId:f.operationId,method:'PATCH',canonicalPath:`/services/${f.nativeId}`,body:{retries:99},before:f.mutation.before,mutationAction:'update',query:{}},'authorize')).rejects.toMatchObject({response:{code:'CONFIGURATION_SQL_PREPARATION_REENTRANT'}});return{};});
  await f.packet(async()=>{});
 });
 it('does not publish a ticket after its closing canonical provider returns another namespace',async()=>{
  const f=fixture();f.hooks.authorizeRequest.mockImplementation(async()=>{f.state.copiedNamespaceProof=true;return{};});
  await expect(f.packet(async()=>{throw Error('TICKET_MUST_NOT_PUBLISH');})).rejects.toMatchObject({response:{code:'CONFIGURATION_SQL_PREPARATION_CONTEXT_CHANGED'}});
  expect(f.context.peek()).toBeNull();
 });
 it('preserves a provider-shortened monotonic bound through an awaited continuation, without extending it',async()=>{
  const f=fixture();let now=1000;const spy=vi.spyOn(performance,'now').mockImplementation(()=>now);
  try{f.hooks.authorizeRequest.mockImplementation(async()=>{const phase=f.context.scheduledConfigurationPreparationPhase()!;
    f.context.limitScheduledConfigurationPreparation(phase,1005);f.context.limitScheduledConfigurationPreparation(phase,9999);await Promise.resolve();now=1006;return{};});
   await expect(f.packet(async()=>{throw Error('TICKET_MUST_NOT_PUBLISH');})).rejects.toMatchObject({response:{code:'CONFIGURATION_SQL_PREPARATION_CONTEXT_CHANGED'}});
  }finally{spy.mockRestore();}
 });
 it('poisons a returned or detached phase when an early guard rejects',async()=>{
  const f=fixture();let phase:any,late!:()=>Promise<unknown>;
  f.hooks.authorizeRequest.mockImplementation(async()=>{phase=f.context.scheduledConfigurationPreparationPhase();late=async()=>f.context.limitScheduledConfigurationPreparation(phase,1);throw Error('EARLY_GUARD_REJECTED');});
  await expect(f.packet(async()=>{})).rejects.toThrow('EARLY_GUARD_REJECTED');await expect(late()).rejects.toThrow();expect(f.context.peek()).toBeNull();
 });
});
