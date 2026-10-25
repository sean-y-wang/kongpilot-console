import 'reflect-metadata';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { WorkflowScheduledAuthorityService } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.service';
import { WorkflowScheduledNamespaceService } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-namespace.service';
import { WorkflowBusinessRuntimeService } from '../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import type { WorkflowScheduledValidationFixedReader } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-validation-read.types';
import { WorkflowBusinessExecutionService } from '../../apps/console-api/src/modules/workflows/workflow-business-execution.service';
import { workflowSchedulePlanSeal } from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import { workflowScheduledFixture } from './helpers/workflow-scheduled-fixture';
import type { ConfigPlan } from '../../apps/console-api/src/modules/configuration/configuration.types';

const denied = (code: string) => ({ response: { code } });
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };

/** Actual Root bootstrap, private claim map, Authority, Namespace and Context.
 * SQL/approval/business-material adapters are explicit Source fixtures. Native
 * transport and business writes are closed; this is not runtime acceptance. */
function fixture(kind: 'configuration_v2' | 'portal-credential-issue' = 'configuration_v2') {
  const f = workflowScheduledFixture(kind), context = new KongExecutionContextService();
  // The Material adapter is controlled, but its configuration plan still uses
  // the complete private contract and is sealed into the real wrapper. Empty
  // or missing steps would hide the Runtime's pre-claim compatibility guard.
  let configurationPlan: ConfigPlan | undefined;
  if (kind === 'configuration_v2') {
    const nativeId = randomUUID(), body = { id: nativeId, name: 'source-unit-service', host: 'example.com', tags: [] };
    const bodyHmac = f.secrets.fingerprint(body), beforeHmac = f.secrets.fingerprint(null);
    configurationPlan = { scope: { clusterId: f.cid, workspaceId: f.wid, transportScope: f.draft.transportScope,
      kind: 'workspace', rootIds: [] }, mode: 'merge', steps: [{ stepId: randomUUID(), stepOrder: 1,
      objectKey: `services:${nativeId}`, entityType: 'services', objectWorkspaceId: f.wid, clearMap: [],
      nativeId, allocatedNativeId: nativeId, permissionAction: 'write', mutationAction: 'create', dependencies: [],
      body, before: null, bodyHmac, beforeHmac, nativeRequests: [{ method: 'POST', canonicalPath: '/services',
        body, bodyHmac, beforeHmac }], referenceOnly: false, blockerCodes: [], maskedDiff: [] }],
      sourceManifestHmac: f.secrets.fingerprint('source-unit-manifest'), baselineManifestHmac: f.secrets.fingerprint('source-unit-baseline'),
      schemaHmac: f.secrets.fingerprint('source-unit-schemas'), permissionVersion: f.state.principalVersion,
      clusterRevision: 1, workspaceRevision: 1, kongVersion: '1.5.1', recoveryComplete: true, expiresAt: f.plan.expiresAt };
    f.plan.steps[0].metadata.planHash = f.secrets.fingerprint(configurationPlan);
    f.plan.steps[0].metadataPayloadHmac = f.secrets.fingerprint(f.plan.steps[0].metadata);
  }
  if (kind === 'portal-credential-issue') {
    // The shared Namespace-only fixture does not need public step credential
    // kinds. This Business fixture must use the full genuine Portal contract.
    f.plan.steps[1].credentialKind = 'acls'; f.plan.steps[2].credentialKind = 'key-auth';
  }
  const { scheduling: _oldSeal, ...base } = f.plan, baseHash = f.secrets.fingerprint(base);
  f.draft.binding.basePlanHash = baseHash; f.draft.delegation.basePlanHash = baseHash;
  f.draft.delegationHmac = f.secrets.fingerprint(f.draft.delegation);
  f.plan.scheduling = workflowSchedulePlanSeal(f.draft); f.draft.binding.workflowPlanHash = f.secrets.fingerprint(f.plan);
  f.state.stored.activation.workflowPlanHash = f.draft.binding.workflowPlanHash;
  const authority = new WorkflowScheduledAuthorityService(f.db, f.secrets, f.redis, context, f.plans, f.approvals, f.repository);
  const namespaces = new WorkflowScheduledNamespaceService(authority, f.secrets, f.redis);
  const originalQuery = f.db.one.getMockImplementation()!;
  f.db.one.mockImplementation(async (sql: string, args: any[]) => sql.includes('FROM schema_migrations')
    ? { checksum: createHash('sha256').update(readFileSync('apps/console-api/src/infrastructure/migrations/026_m11_workflow_schedules.sql')).digest('hex') }
    : originalQuery(sql, args));
  const noNative = vi.fn(async () => { throw new Error('NO_NATIVE_OR_BUSINESS_WRITE_IN_SOURCE_FIXTURE'); });
  const closedProvider = () => ({ installStorageContract: vi.fn(), installContextRunner: vi.fn(), installBusinessPolicy: vi.fn(),
    installFixedReader: vi.fn(() => undefined),
    installAbsentResponseVerifier: vi.fn(), installParentAbsencePolicy: vi.fn(), assertOriginalHttpAcceptance: noNative,
    verifyHandle: noNative, assertLive: () => { throw new Error('NO_CANDIDATE_OR_VALIDATION_READ_IN_THIS_FIXTURE'); },
    authorizeRequest: noNative, verifyRequest: noNative, authorizeResponse: noNative });
  // Bootstrap compatibility only: this Authority fixture keeps validation
  // reads closed and supplies no optimized reader capability.
  const validation = { ...closedProvider(), installFixedReader: vi.fn((_reader: WorkflowScheduledValidationFixedReader): undefined => undefined) };
  let callback: (a: object, n: object) => Promise<void> = async () => {}, delegate: any, authorityHandle: object, namespaceHandle: object;
  const business = new WorkflowBusinessExecutionService({ db: f.db, redis: f.redis, secrets: f.secrets, context } as any);
  const workflows: any = { installBusinessScheduledDelegate(value: any) { delegate = value; business.install(value); },
    async executeBusinessScheduledClaim(a: object, n: object) { authorityHandle = a; namespaceHandle = n; await callback(a, n); return f.complete(); },
    verifyBusinessScheduledCompletion: f.executor.verifyCompletion };
  const material: any = { installScopedReadBridge: vi.fn(), businessReadPolicy: () => ({}),
    materialForPlan: vi.fn(async () => ({ kind, plan: kind === 'configuration_v2' ? configurationPlan : f.plan, subjectSeal: f.draft.binding.subjectSeal })) };
  const approved: any = { installWorkflowScheduledReviewerReadPolicy: vi.fn(), installWorkflowScheduledDelegate: vi.fn() };
  const modules: any = { get: () => ({ installWorkflowScheduledConfigurationOrigin: vi.fn(), installWorkflowScheduledOrigin: vi.fn() }) };
  const runtime = new WorkflowBusinessRuntimeService(f.db, f.redis, f.secrets, context, { request: noNative } as any,
    { installWorkflowScheduledCurrentIdentityBridge: vi.fn() } as any, f.plans, workflows, approved, f.repository, authority, namespaces,
    closedProvider() as any, validation as any, { installRootVerifier: vi.fn() } as any, material, {} as any,
    { installProposalPolicy: vi.fn(), installWorkflowOperationPolicy: vi.fn() } as any, { installFixedDelegate: vi.fn() } as any, modules, {} as any);
  // The actual Root claim/Namespace wiring runs. Business subject/native-graph
  // adapters remain controlled here, while Authority still observes current
  // SQL identity/epochs, policy, approvals, scope, claim, lease and deadlines.
  vi.spyOn(runtime as any, 'subject').mockImplementation(async (...args: any[]) => args[2] === 'approve'
    ? f.policy.assertReviewer(...args) : f.policy.assertSubject(...args));
  runtime.onModuleInit();
  const inspect = (phase = 'step') => (business as any).inspect(authorityHandle, namespaceHandle, phase, f.db);
  const run = async (fn: (a: object, n: object) => Promise<void>) => {
    callback = fn; const handle = await authority.acquireDueClaim(f.scheduleId); expect(handle).not.toBeNull(); await authority.executeClaim(handle!);
  };
  return { ...f, context, authority, namespaces, runtime, business, delegate: () => delegate, noNative, run, inspect,
    a: () => authorityHandle!, n: () => namespaceHandle! };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T13:00:00Z')); });
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('one fresh complete Authority validation per business checkpoint, Source-only', () => {
  it.each(['configuration_v2', 'portal-credential-issue'] as const)('keeps the genuine %s Root chain and invokes Authority once per checkpoint', async kind => {
    const f = fixture(kind), calls = vi.spyOn(f.authority, 'verifyClaim');
    await f.run(async (a, n) => {
      const originalProof = f.context.requireWorkflowScheduledCurrentPrincipal(n).namespace;
      for (const phase of ['claim', 'capture', 'step', 'packet', 'before-send', 'inspect']) {
        calls.mockClear(); const result = await f.inspect(phase);
        expect(calls).toHaveBeenCalledTimes(1); expect(calls).toHaveBeenCalledWith(a, phase === 'inspect' ? 'claim' : phase);
        expect(result.plan.workflowId).toBe(f.plan.workflowId); expect(result.principal.id).toBe(f.owner);
        expect(f.context.requireWorkflowScheduledCurrentPrincipal(n).namespace).toBe(originalProof);
      }
      calls.mockClear(); expect(await f.namespaces.verifyHandle(n, 'step')).toBe(originalProof);
      expect(calls).toHaveBeenCalledExactlyOnceWith(a, 'step');
    });
    expect(f.noNative).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });

  it('keeps the exact genuine inspection object rather than copying its shape', async () => {
    const f = fixture(); await f.run(async (a, n) => {
      const original = f.authority.verifyClaim.bind(f.authority); let issued: unknown;
      vi.spyOn(f.authority, 'verifyClaim').mockImplementation(async (...args) => { issued = await original(...args); return issued as any; });
      expect(await f.namespaces.inspectOriginalClaim(a, n, 'step')).toBe(issued);
    });
  });

  it.each(['copied-authority', 'foreign-authority', 'copied-namespace', 'foreign-namespace'] as const)('rejects %s before another Authority lookup', async cause => {
    const f = fixture(); await f.run(async (a, n) => {
      const calls = vi.spyOn(f.authority, 'verifyClaim');
      const originalAuthority = cause === 'copied-authority' ? { ...a } : cause === 'foreign-authority' ? Object.freeze({}) : a;
      const originalNamespace = cause === 'copied-namespace' ? { ...n } : cause === 'foreign-namespace' ? Object.freeze({}) : n;
      await expect(f.namespaces.inspectOriginalClaim(originalAuthority, originalNamespace, 'step')).rejects.toBeDefined(); expect(calls).not.toHaveBeenCalled();
      await expect(f.delegate().verifyOriginalClaim(originalAuthority, originalNamespace, 'step', f.db)).rejects.toBeDefined(); expect(calls).not.toHaveBeenCalled();
    });
  });

  it.each([
    ['principal display name', (v: any) => { v.principal.displayName = 'changed current label'; }],
    ['principal revision', (v: any) => { v.principal.revision = 2; }],
    ['principal locale', (v: any) => { v.principal.locale = 'en-US'; }],
    ['principal timezone', (v: any) => { v.principal.timezone = 'Asia/Shanghai'; }],
    ['principal username', (v: any) => { v.principal.username = 'changed-current-name'; }],
    ['complete draft', (v: any) => { v.draft.extraOriginalMaterial = 'cannot-ignore'; }],
    ['complete claim', (v: any) => { v.claim.workerOwnerHmac = '0'.repeat(64); }],
    ['frozen lease', (v: any) => { v.leaseUntil = new Date(Date.parse(v.leaseUntil) - 1000).toISOString(); }],
    ['complete approval set', (v: any) => { v.approvalSet.reviewers[0].candidateVersion++; }],
  ] as Array<[string, (value: any) => void]>)('keeps the full original Namespace digest for %s beyond the manual ID/PV comparisons', async (_name, change) => {
    const f = fixture(); await f.run(async () => {
      const original = f.authority.verifyClaim.bind(f.authority);
      vi.spyOn(f.authority, 'verifyClaim').mockImplementation(async (...args) => { const issued = structuredClone(await original(...args)); change(issued); return issued; });
      await expect(f.inspect()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_NAMESPACE_FACTS_CHANGED')); expect(f.noNative).not.toHaveBeenCalled();
    });
  });

  it('keeps the independent complete Namespace projection comparison', async () => {
    const f = fixture(); await f.run(async () => {
      const project = (f.namespaces as any).projection.bind(f.namespaces);
      vi.spyOn(f.namespaces as any, 'projection').mockImplementation((value: any) => ({ ...project(value), subjectSealHmac: '0'.repeat(64) }));
      await expect(f.inspect()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_NAMESPACE_FACTS_CHANGED'));
    });
  });

  it.each(['owner', 'epoch', 'permission-version', 'reviewer', 'subject', 'policy', 'scope', 'requester', 'lease', 'deadline'] as const)('freshly rejects current %s changes at the next checkpoint', async cause => {
    const f = fixture('portal-credential-issue'); await f.run(async () => {
      await f.inspect('step');
      if (cause === 'owner') f.state.ownerActive = false; else if (cause === 'epoch') f.state.epoch = '2';
      else if (cause === 'permission-version') f.state.principalVersion = '2'; else if (cause === 'reviewer') f.state.reviewerActive = false;
      else if (cause === 'subject') f.state.scopeAllowed = false; else if (cause === 'policy') f.state.policyChanged = true;
      else if (cause === 'scope') f.state.directMode = true; else if (cause === 'requester') f.state.requesterActive = false;
      else if (cause === 'lease') f.state.lease = false; else vi.setSystemTime(new Date(f.draft.spec.windowEnd));
      await expect(f.inspect('before-send')).rejects.toBeDefined(); expect(f.noNative).not.toHaveBeenCalled();
      // Complete only the Source test callback; never reuse a revoked claim.
      if (cause === 'lease') f.state.lease = true;
    });
  });

  it.each([['reviewer', true], ['executor', true]] as const)('retains the final synchronous %s/readOnly=%s deny gate independently of the fresh result', async (role, readOnly) => {
    const f = fixture(); await f.run(async () => {
      const original = f.context.requireWorkflowScheduledCurrentPrincipal.bind(f.context); let gate = false;
      const inspect = f.namespaces.inspectOriginalClaim.bind(f.namespaces);
      // The delegate remains genuine and fresh; only the subsequent Context
      // principal bridge is controlled to prove the new final deny conditions.
      vi.spyOn(f.namespaces, 'inspectOriginalClaim').mockImplementation(async (...args) => { const value = await inspect(...args); gate = true; return value; });
      vi.spyOn(f.context, 'requireWorkflowScheduledCurrentPrincipal').mockImplementation(handle => {
        const value = original(handle); return gate ? { ...value, role, readOnly } : value;
      });
      await expect(f.inspect()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_BUSINESS_FACTS_CHANGED')); expect(f.noNative).not.toHaveBeenCalled();
    });
  });

  it('admits the genuine Context actor child and keeps its selected workspace exact', async () => {
    // Portal reaches the independent Business workspace gate; configuration
    // has an earlier Authority scope gate covered by the next genuine case.
    const f = fixture('portal-credential-issue'); await f.run(async (_a, n) => {
      const proof = f.context.requireWorkflowScheduledCurrentPrincipal(n).namespace;
      const executionHandle = Object.freeze({}), execution = Object.freeze({ executionId: randomUUID(), workflowId: f.plan.workflowId,
        clusterId: f.cid, workspaceId: f.wid, actorId: f.owner, sessionId: null, origin: 'scheduled-workflow', scheduleClaimId: proof.claim.id,
        workflowOriginId: randomUUID(), permissionVersion: proof.permissionVersion, expiresAt: Date.parse(proof.expiresAt) });
      // The real Context constructs the approved actor child. Its execution
      // policy is an explicit private Source adapter; no Native grant is made.
      f.context.installApprovedPolicy({ verifyExecution: async handle => { if (handle !== executionHandle) throw new Error('ORIGINAL_APPROVED_HANDLE_REQUIRED'); return execution; },
        verifyWorkflowScheduledExecution: async (current: any, handle: object) => { if (current !== execution || handle !== n) throw new Error('ORIGINAL_SCHEDULED_EXECUTION_REQUIRED'); },
        verifyStep: f.noNative, assertNative: f.noNative, assertMetadata: f.noNative, mutationBinding: f.noNative, bindOperation: f.noNative } as any);
      await f.context.runApprovedWorkflow(executionHandle, async () => {
        expect(f.context.current().kind).toBe('actor'); await expect(f.inspect()).resolves.toMatchObject({ permissionVersion: proof.permissionVersion });
      });
      await f.context.runActor({ actor: proof.actor, clusterId: f.cid, workspaceId: randomUUID(), module: 'workflows', action: 'write' }, async () => {
        await expect(f.inspect()).rejects.toMatchObject(denied('WORKFLOW_SCHEDULE_BUSINESS_FACTS_CHANGED'));
      });
    });
  });

  it('admits the genuine configuration actor child and rejects a foreign workspace at its earlier Authority scope gate', async () => {
    const f = fixture(); await f.run(async (_a, n) => {
      const proof = f.context.requireWorkflowScheduledCurrentPrincipal(n).namespace;
      const executionHandle = Object.freeze({}), execution = Object.freeze({ executionId: randomUUID(), workflowId: f.plan.workflowId,
        clusterId: f.cid, workspaceId: f.wid, actorId: f.owner, sessionId: null, origin: 'scheduled-workflow', scheduleClaimId: proof.claim.id,
        workflowOriginId: randomUUID(), permissionVersion: proof.permissionVersion, expiresAt: Date.parse(proof.expiresAt) });
      f.context.installApprovedPolicy({ verifyExecution: async handle => { if (handle !== executionHandle) throw new Error('ORIGINAL_APPROVED_HANDLE_REQUIRED'); return execution; },
        verifyWorkflowScheduledExecution: async (current: any, handle: object) => { if (current !== execution || handle !== n) throw new Error('ORIGINAL_SCHEDULED_EXECUTION_REQUIRED'); },
        verifyStep: f.noNative, assertNative: f.noNative, assertMetadata: f.noNative, mutationBinding: f.noNative, bindOperation: f.noNative } as any);
      await f.context.runApprovedWorkflow(executionHandle, async () => {
        expect(f.context.current().kind).toBe('actor'); await expect(f.inspect()).resolves.toMatchObject({ permissionVersion: proof.permissionVersion });
      });
      await f.context.runActor({ actor: proof.actor, clusterId: f.cid, workspaceId: randomUUID(), module: 'workflows', action: 'write' }, async () => {
        const calls = vi.spyOn(f.authority, 'verifyClaim');
        await expect(f.inspect()).rejects.toMatchObject({ status: 403, ...denied('WORKFLOW_SCHEDULE_CONFIGURATION_FACTS_ORIGINAL_REQUIRED') });
        expect(calls).toHaveBeenCalledExactlyOnceWith(f.a(), 'step'); expect(f.noNative).not.toHaveBeenCalled();
      });
    });
    expect(f.noNative).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  });

  it.each(['authority', 'final-redis', 'business-final-redis'] as const)('cannot resurrect a Namespace closed while awaiting %s', async stage => {
    const f = fixture(), ready = deferred(), release = deferred(); let pending!: Promise<unknown>;
    await f.run(async () => {
      const original = f.authority.verifyClaim.bind(f.authority); let returned = false;
      vi.spyOn(f.authority, 'verifyClaim').mockImplementation(async (...args) => { const value = await original(...args); if (stage !== 'business-final-redis') returned = true;
        if (stage === 'authority') { ready.resolve(); await release.promise; } return value;
      });
      if (stage === 'business-final-redis') {
        const current = f.namespaces.inspectOriginalClaim.bind(f.namespaces);
        vi.spyOn(f.namespaces, 'inspectOriginalClaim').mockImplementation(async (...args) => { const value = await current(...args); returned = true; return value; });
      }
      if (stage !== 'authority') {
        const ownership = f.redis.assertLeaseOwnership.getMockImplementation()!; let blocked = false;
        f.redis.assertLeaseOwnership.mockImplementation(async () => { await ownership(); if (returned && !blocked) { blocked = true; ready.resolve(); await release.promise; } });
      }
      pending = f.inspect(); void pending.catch(() => undefined); await ready.promise;
    });
    expect(f.context.peek()).toBeNull(); release.resolve(); await expect(pending).rejects.toBeDefined(); expect(f.noNative).not.toHaveBeenCalled();
  });

  it('does not cache authority across checkpoints or extend the original claim deadline', async () => {
    const f = fixture(); await f.run(async (_a, n) => {
      const original = f.context.requireWorkflowScheduledCurrentPrincipal(n).namespace, expiresAt = original.expiresAt;
      await f.inspect('step'); vi.advanceTimersByTime(120001); const fresh = await f.inspect('before-send');
      expect(f.context.requireWorkflowScheduledCurrentPrincipal(n).namespace.expiresAt).toBe(expiresAt);
      expect(fresh.authorityExpiresAt).toBe(original.claim.authorityExpiresAt); expect(Date.parse(fresh.authorityExpiresAt) - Date.now()).toBe(119999);
    });
  });
});
