import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MutationService } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';

/** Component boundary: actual Context ALS, original Namespace/job/nested
 * execution/step registration paths and private binding lifecycle. The fixed
 * Origin/Approved policies are controlled Source adapters, not real SQL or
 * actual Approved/Root claim minting. No product private map is seeded; no
 * HTTP, database, Docker, Native send or production execution is claimed. */
function fixture(options: { nestedVerifier?: boolean; objectWorkspace?: boolean; expiresIn?: number; nativeKind?: 'native' | 'metadata' } = {}) {
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
    wrapper, job, nested, native, mutationActor, bind, packet, executions, namespaces, jobs };
}


beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T21:00:00Z')); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ae'.repeat(32)); });
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });
const denied = (code: string) => ({ response: { code } });
const advance = (milliseconds: number) => vi.setSystemTime(Date.now() + milliseconds);

describe('private scheduled configuration mutation envelope keeps original deadlines', () => {
  it('preserves the fixed configuration envelope for the genuine same-workspace private nested step after 120 seconds', async () => {
    const f = fixture();
    await f.mutationActor(async () => {
      expect(f.context.current()).toMatchObject({ kind: 'actor', purpose: 'configuration', clusterId: f.cid, workspaceId: f.wid });
      expect(f.context.current().limits.timeoutMs).toBe(300000);
      expect(f.approved.mutationBinding).not.toHaveBeenCalled();
      advance(120001); expect(f.context.current().actor?.id).toBe(f.actor.id);
      const binding = await f.bind(); expect(binding).toMatchObject({ version: 2, configurationExecutionId: f.nestedProof.executionId });
      await f.context.runOperation({ ...f.mutation, operationId: f.operationId }, async () => {
        expect(f.context.current()).toMatchObject({ kind: 'operation', purpose: 'configuration' });
        advance(20000); expect(f.context.current().operation?.operationId).toBe(f.operationId);
      });
    });
    expect(f.context.peek()).toBeNull();
  });

  it('retains the operation envelope beyond its own first 120 seconds and still stops at the original claim boundary', async () => {
    const f = fixture({ expiresIn: 180000 }); let entered = false;
    await expect(f.mutationActor(async () => {
      await f.bind();
      await f.context.runOperation({ ...f.mutation, operationId: f.operationId }, async () => {
        entered = true; expect(f.context.current().purpose).toBe('configuration');
        expect(f.context.current().limits.timeoutMs).toBe(180000);
        advance(120001); expect(f.context.current().operation?.operationId).toBe(f.operationId);
        advance(60000); f.context.current();
      });
    })).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
    expect(entered).toBe(true); expect(f.context.peek()).toBeNull();
  });

  it.each([150000, 300000])('never extends the original %s ms claim/job/Approved bound', async expiresIn => {
    const f = fixture({ expiresIn });
    await expect(f.mutationActor(async () => {
      advance(expiresIn + 1); f.context.current();
    })).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
    expect(f.context.peek()).toBeNull();
  });

  it('does not mint a new deadline when mutation entry begins late in the original claim', async () => {
    const f = fixture({ expiresIn: 180000 });
    await expect(f.native(async () => {
      advance(110000);
      await expect(f.context.runMutationActor(f.mutation, async () => {
        advance(70001); f.context.current();
      })).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
    })).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
  });

  it('keeps an earlier ordinary actor ancestor at 120 seconds instead of reviving it', async () => {
    const f = fixture();
    await expect(f.native(() => f.context.runActor({ actor: f.actor, clusterId: f.cid, workspaceId: f.wid, module: 'snapshots', action: 'write' },
      () => f.context.runMutationActor(f.mutation, async () => {
        advance(120001); expect(() => f.context.current()).toThrow();
      })))).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
  });

  it('retains ordinary actor semantics for a legitimate other-object-workspace mutation', async () => {
    const f = fixture({ objectWorkspace: true });
    await f.mutationActor(async () => {
      expect(f.context.current().workspaceId).toBe(f.objectWid); expect(f.context.current().purpose).toBeUndefined();
      expect(f.context.current().limits.timeoutMs).toBe(120000);
      advance(120001); expect(() => f.context.current()).toThrow();
    });
    expect(f.approved.mutationBinding).not.toHaveBeenCalled();
  });

  it.each(['actor', 'cluster'] as const)('rejects a foreign %s mutation tuple before entering a privileged child frame', async field => {
    const f = fixture(), changed = { ...f.mutation, ...(field === 'actor' ? { actor: { ...f.actor, id: randomUUID() } } : { clusterId: randomUUID() }) }, enter = vi.fn();
    await expect(f.native(() => f.context.runMutationActor(changed, enter))).rejects.toBeDefined();
    expect(enter).not.toHaveBeenCalled(); expect(f.approved.mutationBinding).not.toHaveBeenCalled();
  });

  it.each(['job-with-metadata', 'no-current-step', 'internal-read', 'operation', 'archive'] as const)('does not lend a configuration envelope to %s', async kind => {
    const f = fixture(), enter = vi.fn();
    const work = kind === 'job-with-metadata' ? f.job(() => f.context.runMutationActor(f.mutation, enter))
      : kind === 'no-current-step' ? f.nested(() => f.context.runMutationActor(f.mutation, enter))
        : kind === 'internal-read' ? f.native(() => f.context.runInternalRead(f.cid, 'authorization', () => f.context.runMutationActor(f.mutation, enter), { paths: [`/services/${f.nativeId}`], maxCalls: 1 }))
          : f.mutationActor(async () => { await f.bind(); return f.context.runOperation({ ...f.mutation, operationId: f.operationId }, () => kind === 'archive'
            ? f.context.runArchiveDelete({ clusterId: f.cid, workspaceId: f.wid, operationId: f.operationId, entryId: randomUUID(), nodes: [{ type: 'services', id: f.nativeId, path: `/services/${f.nativeId}` }] } as any, () => f.context.runMutationActor(f.mutation, enter))
            : f.context.runMutationActor(f.mutation, enter)); });
    await expect(work).rejects.toMatchObject(denied(kind === 'no-current-step' ? 'APPROVED_STEP_REQUIRED' : 'CONFIGURATION_MUTATION_NATIVE_STEP_REQUIRED')); expect(enter).not.toHaveBeenCalled();
  });

  it('keeps an ordinary no-job configuration wrapper metadata call on the original 120 second path', async () => {
    const f = fixture();
    await expect(f.wrapper(() => f.context.runMutationActor(f.mutation, async () => {
      expect(f.context.current().purpose).toBeUndefined(); expect(f.context.current().limits.timeoutMs).toBe(120000);
      advance(120001); expect(() => f.context.current()).toThrow();
    }))).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
  });

  it.each(['ordinary', 'caller-configuration-purpose'] as const)('never upgrades %s HTTP entity work by a caller string', async kind => {
    const f = fixture();
    await f.context.runHttp({}, () => {
      f.context.bindHttpActor(f.actor, f.originalSid); const close = f.context.captureHttpCloser();
      return f.context.runActor({ actor: f.actor, clusterId: f.cid, workspaceId: f.wid, module: 'services', action: 'write',
        ...(kind === 'caller-configuration-purpose' ? { purpose: 'configuration' } : {}) }, () => f.context.runMutationActor(f.mutation, async () => {
          expect(f.context.current().purpose).toBeUndefined(); expect(f.context.current().limits.timeoutMs).toBe(120000);
          advance(120001); expect(() => f.context.current()).toThrow();
        })).finally(close);
    });
  });

  it('does not extend Portal namespaces beyond the unchanged 120 second envelope', async () => {
    const f = fixture(), handle = Object.freeze({}), portal = Object.freeze({ ...f.ns, kind: 'portal-credential-issue' });
    const context = new KongExecutionContextService();
    context.installWorkflowScheduledNamespacePolicy({ assertLive(h) { if (h !== handle) throw Error('SOURCE_PORTAL_NAMESPACE_REQUIRED'); },
      async verifyHandle(h) { if (h !== handle) throw Error('SOURCE_PORTAL_NAMESPACE_REQUIRED'); return portal; } });
    await expect(context.runWorkflowScheduledNamespace(handle, () => context.runMutationActor(f.mutation, async () => {
      expect(context.current().purpose).toBeUndefined(); expect(context.current().limits.timeoutMs).toBe(120000);
      advance(120001); expect(() => context.current()).toThrow();
    }))).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
  });

  it.each(['unbound', 'wrong-operation', 'wrong-scope', 'copied-binding'] as const)('requires the original successful reciprocal V2 bind before operation entry: %s', async reason => {
    const f = fixture(), enter = vi.fn();
    await f.mutationActor(async () => {
      if (reason === 'copied-binding') {
        const binding = await f.context.approvedMutationBinding(f.mutation);
        await expect(f.context.bindApprovedOperation(f.mutation, { ...binding } as any, f.operationId, {} as any)).rejects.toThrow('ORIGINAL_V2_BINDING_REQUIRED');
      } else if (reason !== 'unbound') await f.bind();
      const input = { ...f.mutation, operationId: reason === 'wrong-operation' ? randomUUID() : f.operationId,
        ...(reason === 'wrong-scope' ? { entityId: randomUUID() } : {}) };
      await expect(Promise.resolve().then(() => f.context.runOperation(input, enter))).rejects.toMatchObject(denied('CONFIGURATION_MUTATION_OPERATION_BINDING_MISMATCH')); expect(enter).not.toHaveBeenCalled();
    });
  });

  it('does not publish an operation marker when the fixed reciprocal bind rejects', async () => {
    const f = fixture(), enter = vi.fn();
    await f.mutationActor(async () => {
      f.approved.bindOperation.mockRejectedValueOnce(Error('SOURCE_RECIPROCAL_SQL_REJECTED'));
      await expect(f.bind()).rejects.toThrow('SOURCE_RECIPROCAL_SQL_REJECTED');
      await expect(Promise.resolve().then(() => f.context.runOperation({ ...f.mutation, operationId: f.operationId }, enter))).rejects.toMatchObject(denied('CONFIGURATION_MUTATION_OPERATION_BINDING_MISMATCH'));
      expect(enter).not.toHaveBeenCalled();
    });
  });

  it('retains the 1000-call scheduled configuration aggregate (user-approved 2026-10-24) across the original namespace and newly created mutation actor frames', async () => {
    const f = fixture();
    await f.native(async () => {
      await f.context.runMutationActor(f.mutation, async () => {
        await f.bind(); await f.context.runOperation({ ...f.mutation, operationId: f.operationId }, async () => {
          for (let i = 0; i < 1000; i++) {
            const ticket = await f.context.authorizeRequest(f.cluster, 'GET', `/services/${f.nativeId}`, undefined, {});
            await f.context.authorizeResponse(ticket, { id: f.nativeId });
          }
          expect(f.context.currentUsage().calls).toBe(1000);
        });
      });
      expect(f.context.currentUsage().calls).toBe(1000);
      await expect(f.context.runMutationActor(f.mutation, async () => {
        await f.context.authorizeRequest(f.cluster, 'GET', `/services/${f.nativeId}`, undefined, {});
      })).rejects.toBeDefined();
    });
    expect(f.hooks.authorizeRequest).toHaveBeenCalledTimes(1000);
  });

  it('closes the private mutation marker on callback failure and refuses detached resurrection', async () => {
    const f = fixture(); let release!: () => void, pending!: Promise<any>; const gate = new Promise<void>(done => { release = done; });
    await expect(f.mutationActor(async () => {
      await f.bind(); pending = (async () => { await gate; return f.context.runOperation({ ...f.mutation, operationId: f.operationId }, async () => undefined); })();
      throw Error('SOURCE_MUTATION_CALLBACK_FAILED');
    })).rejects.toThrow('SOURCE_MUTATION_CALLBACK_FAILED');
    release(); await expect(pending).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
    expect(f.context.peek()).toBeNull();
  });
});

describe('MutationService uses the fixed Context entry for both public mutation wrappers', () => {
  function service(f: ReturnType<typeof fixture>, one: any = vi.fn(async () => null)) {
    const db: any = { one, exec: vi.fn(), query: vi.fn() }, redis: any = {};
    const authz: any = { assertCluster: vi.fn(async () => undefined), assertEntity: vi.fn(async () => undefined) };
    const workspaces: any = { resolve: vi.fn(async () => ({ id: f.wid, status: 'active' })),
      listScope: vi.fn(async () => ({})), assertMembership: vi.fn() };
    const mutations = new MutationService(db, redis, new SecretService(), {} as any, {} as any, authz, workspaces, f.context);
    return { mutations, db, redis, authz, workspaces };
  }

  it('execute retains the real private configuration actor while its business database body is an explicit controlled seam', async () => {
    const f = fixture(), { mutations } = service(f);
    const execute = vi.spyOn(mutations as any, 'executeScoped').mockImplementation(async (_context: any, fn: any) => fn());
    const entry = vi.spyOn(f.context, 'runMutationActor');
    await f.native(() => mutations.execute(f.mutation, async () => {
      expect(f.context.current().purpose).toBe('configuration'); expect(f.context.current().limits.timeoutMs).toBe(300000);
      advance(120001); expect(f.context.current().actor?.id).toBe(f.actor.id); return 'controlled-body-result';
    }));
    expect(entry).toHaveBeenCalledExactlyOnceWith(f.mutation, expect.any(Function)); expect(execute).toHaveBeenCalledOnce();
  });

  it('inspectStepReceipt retains the original envelope while actual receipt logic performs a controlled null lookup', async () => {
    const f = fixture(), one = vi.fn(async () => {
      advance(120001); expect(f.context.current().purpose).toBe('configuration'); expect(f.context.current().actor?.id).toBe(f.actor.id); return null;
    });
    const { mutations, db } = service(f, one), entry = vi.spyOn(f.context, 'runMutationActor');
    await expect(f.native(() => mutations.inspectStepReceipt(f.mutation))).resolves.toBeNull();
    expect(entry).toHaveBeenCalledExactlyOnceWith(f.mutation, expect.any(Function)); expect(one).toHaveBeenCalledOnce(); expect(db.exec).not.toHaveBeenCalled();
  });
});

describe('private mutation operation marker pins its original scope and single entry', () => {
  it.each(['entityType', 'entityId', 'action', 'parentId', 'credentialKind', 'idempotencyKey'] as const)('does not let in-place %s mutation rewrite a successful original bind', async field => {
    const f = fixture(), enter = vi.fn();
    await f.mutationActor(async () => {
      await f.bind();
      if (field === 'entityType') f.mutation.entityType = 'routes';
      if (field === 'entityId') f.mutation.entityId = randomUUID();
      if (field === 'action') f.mutation.action = 'delete';
      if (field === 'parentId') f.mutation.parentId = randomUUID();
      if (field === 'credentialKind') f.mutation.credentialKind = 'key-auth';
      if (field === 'idempotencyKey') f.mutation.idempotencyKey = 'changed-key';
      await expect(Promise.resolve().then(() => f.context.runOperation({ ...f.mutation, operationId: f.operationId }, enter)))
        .rejects.toMatchObject(denied('CONFIGURATION_MUTATION_ACTOR_ORIGINAL_REQUIRED'));
      expect(enter).not.toHaveBeenCalled();
    });
  });

  it('requires the original MutationContext object at successful binding and records no marker for a clone', async () => {
    const f = fixture(), enter = vi.fn();
    await f.mutationActor(async () => {
      const binding = await f.context.approvedMutationBinding(f.mutation);
      await expect(f.context.bindApprovedOperation({ ...f.mutation }, binding!, f.operationId, {} as any))
        .rejects.toMatchObject(denied('CONFIGURATION_MUTATION_OPERATION_BINDING_MISMATCH'));
      await expect(Promise.resolve().then(() => f.context.runOperation({ ...f.mutation, operationId: f.operationId }, enter)))
        .rejects.toMatchObject(denied('CONFIGURATION_MUTATION_OPERATION_BINDING_MISMATCH'));
      expect(enter).not.toHaveBeenCalled();
    });
  });

  it('consumes a successfully bound operation entry once and cannot retry after its callback failed', async () => {
    const f = fixture(), enter = vi.fn();
    await f.mutationActor(async () => {
      await f.bind();
      await expect(f.context.runOperation({ ...f.mutation, operationId: f.operationId }, async () => { throw Error('SOURCE_ORIGINAL_OPERATION_FAILED'); }))
        .rejects.toThrow('SOURCE_ORIGINAL_OPERATION_FAILED');
      await expect(Promise.resolve().then(() => f.context.runOperation({ ...f.mutation, operationId: f.operationId }, enter)))
        .rejects.toMatchObject(denied('CONFIGURATION_MUTATION_OPERATION_BINDING_MISMATCH'));
      expect(enter).not.toHaveBeenCalled();
    });
  });

  it('does not adopt a copied execution proof returned for a current native step', async () => {
    const f = fixture(), original = f.approved.verifyStep.getMockImplementation()!, enter = vi.fn();
    f.approved.verifyStep.mockImplementation(async (proof: any, stepId: string) => {
      const step = await original(proof, stepId); return proof === f.nestedProof ? Object.freeze({ ...step, execution: Object.freeze({ ...proof }) }) : step;
    });
    await expect(f.native(() => f.context.runMutationActor(f.mutation, enter))).rejects.toMatchObject(denied('CONFIGURATION_MUTATION_NATIVE_STEP_REQUIRED'));
    expect(enter).not.toHaveBeenCalled();
  });
});
