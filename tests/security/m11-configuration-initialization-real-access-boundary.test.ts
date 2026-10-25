import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { WorkflowScheduledConfigurationOriginService } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-configuration-origin.service';
import { workflowScheduleDraftAad } from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { immutableJson } from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import { ConfigurationAccessService } from '../../apps/console-api/src/modules/configuration/configuration-access.service';
import { ConfigurationFailureLedgerService } from '../../apps/console-api/src/modules/configuration/configuration-failure-ledger.service';
import { CONFIGURATION_INITIALIZATION_ANCHOR_QUERY as ANCHOR, CONFIGURATION_INITIALIZATION_FOOTPRINT_QUERY as FOOTPRINT, CONFIGURATION_INITIALIZATION_PLAN_OBJECTS_QUERY as OBJECTS } from '../../apps/console-api/src/modules/configuration/configuration-initialization-failure';
import { m11LedgerIdentityFixture } from '../unit/helpers/m11-ledger-identity-fixture';

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'd8'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T16:00:00.000Z')); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

/** Actual Access handle minting/phase selection, Origin job WeakMaps/inspection,
 * real Context ancestry and Root/current Identity/Candidates. SQL, authorization
 * snapshot/native-grants adapters and decrypted configuration-material reads
 * are controlled Source fixtures; wrapper/draft AEAD remains actual. No live DB,
 * scheduler, session, Native send, deployment or performance acceptance. */
function fixture() {
  const f = m11LedgerIdentityFixture({ layout: 'single' }), wrapper = f.plan, payload = wrapper.steps[0].metadata;
  const ns = f.ns, c = ns.claim, draft = f.draft, now = Date.now(), wrapperId = randomUUID(), wrapperOriginId = randomUUID();
  const earlier = new Date(now - 60000).toISOString(), scheduledAt = new Date(now - 20000).toISOString();
  const job: any = { id: payload.jobId, cluster_id: f.cid, workspace_id: f.wid, actor_id: f.owner, workflow_id: wrapper.workflowId,
    origin_type: 'http', origin_session_id: randomUUID(), kind: 'apply', execution_mode: 'approval', approval_required: true,
    plan_id: payload.planId, plan_revision: payload.planRevision, plan_hash: payload.planHash, permission_version: ns.permissionVersion,
    credential_epoch: 1, cluster_revision: 1, workspace_revision: 1, transport_scope: ns.transportScope, authority_expires_at: wrapper.expiresAt,
    expires_at: wrapper.expiresAt, created_at: earlier, lease_generation: 1, lease_owner_hash: '8'.repeat(64), lease_until: ns.expiresAt,
    state: 'running', revision: 3, scope_kind: 'workspace', root_ids: [], remote_started: false, remote_completed: false,
    idempotency_key: 'source-original-configuration-ledger' };
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
  const wrapperOrigin: any = { id: wrapperOriginId, execution_id: wrapperId, claim_id: c.id, schedule_id: c.scheduleId, executor_id: f.owner,
    cluster_id: f.cid, workspace_id: f.wid, workflow_id: wrapper.workflowId, workflow_plan_revision: wrapper.planRevision, workflow_plan_hash: ns.workflow.planHash };
  const wrapperExecution: any = { id: wrapperId, request_id: null, permission_version: ns.permissionVersion, snapshot_state: 'ready', state: 'executing', execution_actor_id: f.owner, workflow_id: wrapper.workflowId,
    plan_revision: wrapper.planRevision, plan_hash: ns.workflow.planHash, cluster_id: f.cid, workspace_id: f.wid, expires_at: ns.expiresAt };
  const workflow = { id: wrapper.workflowId, cluster_id: f.cid, workspace_id: f.wid, execution_mode: 'approval', approval_required: true, state: 'executing', kind: 'configuration_v2', subject_type: 'configuration_jobs', subject_id: job.id,
    requester_type: 'console', requester_user_id: f.owner, plan_revision: wrapper.planRevision, plan_hash: ns.workflow.planHash };
  const wrapperVersion = { step_count: 1, native_request_count: 0, plan_hash: ns.workflow.planHash,
    steps_hash: f.secrets.fingerprint(wrapper.steps), payload_secret: f.secrets.encrypt(wrapper, planAad(f.cid, f.wid, wrapper.workflowId, wrapper.planRevision)) };
  const fullGrants = new Map<string, any[]>();
  for (const actor of [ns.actor, ...ns.approvalSet.reviewers.map((r: any) => ({ id: r.userId }))]) fullGrants.set(actor.id,
    ['workflows', 'snapshots'].flatMap(module => ['read', 'write', 'approve'].map(action => ({ user_id: actor.id, module, action,
      cluster_id: f.cid, workspace_id: f.wid, scope_type: 'global', scope_values: [] }))));
  const originalOne = f.db.one.getMockImplementation()!, originalQuery = f.db.query.getMockImplementation()!;
  let nested: any = null, nestedOrigin: any = null;
  const common = { cluster_id: f.cid, workspace_id: f.wid };
  const workflowStep = { ...common, id: wrapper.steps[0].id, workflow_id: wrapper.workflowId, plan_revision: wrapper.planRevision,
    plan_hash: ns.workflow.planHash, kind: 'metadata', handler: 'configuration_v2', entity_type: 'configuration_jobs', entity_id: job.id,
    state: 'running', native_requests: [] };
  const anchor: any = { job, version: { ...common, plan_id: job.plan_id, plan_revision: job.plan_revision, plan_hash: job.plan_hash, step_count: 0 },
    plan: { ...common, id: job.plan_id, current_revision: job.plan_revision }, workflow, wrapper: wrapperExecution,
    wrapper_origin: wrapperOrigin, workflow_step: workflowStep };
  const control = { operations: 0, executions: 0, failSql: false, permissionVersion: ns.permissionVersion, beforeObjects: null as null | (() => void) };

  f.db.one.mockImplementation(async (sql: string, args: any[] = []) => {
    if (control.failSql) throw Error('CONTROLLED_INITIALIZATION_SQL_FAILURE');
    if (sql === ANCHOR) { expect(args).toEqual([f.cid, f.wid, job.id, wrapperId]); return structuredClone(anchor); }
    if (sql === FOOTPRINT) { expect(args).toEqual([f.cid, f.wid, job.id, workflow.id, wrapperId]);
      return { execution_count: control.executions, operation_count: control.operations, fence_count: 0, step_count: 0 }; }
    if (sql.includes('FROM metrics_write_fences f')) return { count: '0', latest_time: null, latest_id: null, unsettled: '0' };
    if (sql.includes('FROM mutation_operations WHERE') && sql.includes('count(*)')) return { count: '0' };
    if (sql.startsWith('SELECT * FROM configuration_jobs WHERE id=$1')) return structuredClone(job);

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
      username: 'actual-sql-principal', force_password_change: false, super_admin: false, credential_epoch: 1, permissions_epoch: 1 };
    if (sql.includes('FROM iam_epoch') && sql.includes('FOR SHARE')) return { version: 1 };
    if (sql.includes('FROM configuration_executions')) return nested && structuredClone(nested);
    if (sql.includes('FROM workflow_configuration_execution_origins')) return nestedOrigin && structuredClone(nestedOrigin);
    if (sql.includes('FROM config_snapshot_versions')) return { completeness: 'complete', consistency: 'console_fenced_best_effort', manifest_hmac: material.plan.baselineManifestHmac };
    return originalOne(sql, args);
  });
  f.db.query.mockImplementation(async (sql: string, args: any[] = []) => {
    if (sql === OBJECTS) { control.beforeObjects?.(); return []; }
    if (sql.includes('SELECT id,admin_url,transport_scope FROM clusters')) return [{ id: f.cid, admin_url: 'http://kong:8001' }];

    if (sql.includes('FROM iam_effective_grants')) return structuredClone(fullGrants.get(args[0]) ?? []);
    if (sql.includes('FROM workflow_approvals WHERE cluster_id=')) return ns.approvalSet.reviewers.map((r: any) => ({ id: r.approvalId,
      approver_id: r.userId, level: r.level, candidate_version: r.candidateVersion, created_at: new Date(now - 5000).toISOString() }));
    if (sql.includes('FROM configuration_job_steps') || sql.includes('FROM mutation_operations')) return [];
    return originalQuery(sql, args);
  });
  const namespaces: any = { assertLive: vi.fn((handle: object) => {
    if (handle !== f.nsHandle || !f.values.live) throw Error('ORIGINAL_SOURCE_NAMESPACE_REQUIRED');
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
  const authz: any = { snapshot: vi.fn(async () => ({ user: ns.actor, version: control.permissionVersion })),
    permissionVersion: vi.fn(async () => control.permissionVersion), assertWholeWorkspace: vi.fn(async () => undefined) };
  const access = new ConfigurationAccessService(f.db, f.secrets, authz, {} as any, f.kong, f.context, {} as any);
  access.installWorkflowScheduledConfigurationOrigin(origin);
  const audit: any = { append: vi.fn(async () => { throw Error('ARM_MUST_NOT_WRITE_AUDIT'); }) };
  const failureLedger = new ConfigurationFailureLedgerService(f.db, f.secrets, audit, access, f.context, authz);
  const wrapperHandle = Object.freeze({}), wrapperProof: any = Object.freeze({ origin: 'scheduled-workflow', sessionId: null,
    actorId: f.owner, clusterId: f.cid, workspaceId: f.wid, workflowId: wrapper.workflowId, executionId: wrapperId,
    scheduleClaimId: c.id, workflowOriginId: wrapperOriginId, permissionVersion: ns.permissionVersion, expiresAt: Date.parse(ns.expiresAt) });
  const noNative = vi.fn(async () => { throw Error('INITIALIZATION_HAS_NO_NATIVE_CAPABILITY'); });
  f.context.installApprovedPolicy({ verifyExecution: async (h: object) => {
    if (h !== wrapperHandle) throw Error('ORIGINAL_SOURCE_WRAPPER_REQUIRED'); return wrapperProof;
  }, verifyWorkflowScheduledExecution: async (p: object, h: object) => {
    if (p !== wrapperProof || h !== f.nsHandle) throw Error('ORIGINAL_SOURCE_WRAPPER_REQUIRED');
  }, verifyStep: async (p: object, s: string) => {
    if (p !== wrapperProof || s !== workflowStep.id) throw Error('ORIGINAL_SOURCE_METADATA_REQUIRED');
    return { execution: wrapperProof, stepId: s, kind: 'metadata' };
  }, mutationBinding: noNative, bindOperation: noNative, assertNative: noNative, assertMetadata: async () => undefined } as any);
  const run = <T>(fn: (handle: any, original: any) => Promise<T>) => f.namespace(() =>
    f.context.runApprovedWorkflow(wrapperHandle as any, () => f.context.runApprovedStep(workflowStep.id, () =>
      origin.runOriginalJob(f.nsHandle, wrapperId, job.id, async () => {
        const original = origin.currentOriginalJobHandle(), handle = await access.acquire(job.id); return fn(handle, original);
      }))));

  return { ...f, origin, namespaces, material, materialRead, ledger, liveMaterial, root, run, job, schedule, claim, progress, lease, wrapperOrigin,
    wrapperExecution, workflow, wrapperVersion, fullGrants, access, failureLedger, audit, anchor, control, noNative, workflowStep };
}

describe('pre-child initialization uses genuine Access/Origin ledger authority', () => {
  const claimHash = 'a'.repeat(64);
  it('exposes the former packet prerequisite, arms with no child, and still refuses default packet authority', async () => {
    const f = fixture();
    await f.run(async (handle, original) => {
      expect(f.access.originalWorkflowScheduledConfigurationJobHandle(handle)).toBe(original);
      // This is the real prerequisite formerly called by armInitialization;
      // unlike the older Access double it must reject the pre-child boundary.
      await expect(f.access.verifyHandle(handle)).rejects.toMatchObject({ response: { code: 'CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED' } });
      const before = f.ledger.mock.calls.length, identityBefore = f.identitySpy.mock.calls.length, nativeBefore = f.liveMaterial.mock.calls.length;
      const token = await f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id);
      expect(token).toBeDefined(); expect(f.ledger.mock.calls.length).toBeGreaterThan(before);
      expect(f.identitySpy.mock.calls.length).toBeGreaterThan(identityBefore);
      expect(f.liveMaterial).toHaveBeenCalledTimes(nativeBefore);
      expect(f.ledger.mock.calls.slice(before).every(([h, p, tx]) => h === f.nsHandle && p === f.ns && tx === f.db)).toBe(true);
      await expect(f.access.verifyHandle(handle)).rejects.toMatchObject({ response: { code: 'CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED' } });
      await expect(f.access.workflowScheduledConfigurationExecutionProof(handle, randomUUID())).rejects.toMatchObject({ response: { code: 'CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED' } });
      await expect(f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id)).rejects.toThrow();
      f.failureLedger.releaseInitialization(token);
    });
    expect(f.audit.append).not.toHaveBeenCalled(); expect(f.noNative).not.toHaveBeenCalled(); expect(f.native).not.toHaveBeenCalled();
    expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('rejects copied Access and original-job handles rather than interpreting UUIDs or JSON as authority', async () => {
    const f = fixture();
    await f.run(async (handle, original) => {
      await expect(f.failureLedger.armInitialization({ ...handle } as any, claimHash, f.wrapperExecution.id)).rejects.toThrow();
      await expect(f.origin.verifyJobHandle({ ...original } as any, 'ledger')).rejects.toThrow();
      await expect(f.failureLedger.armInitialization({ id: f.job.id } as any, claimHash, f.wrapperExecution.id)).rejects.toThrow();
      const token = await f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id);
      f.failureLedger.releaseInitialization(token);
    });
    expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['actor_id', 'plan_id', 'plan_hash', 'lease_owner_hash', 'lease_generation'])('keeps the SQL %s anchor tied to the original run', async field => {
    const f = fixture();
    await f.run(async handle => {
      f.anchor.job = { ...f.job, [field]: field === 'lease_generation' ? 99 : randomUUID() };
      await expect(f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id)).rejects.toThrow();
    });
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled();
  });
  it('rejects an actual SQL authoring SID change instead of adopting it as the current background SID', async () => {
    const f = fixture();
    await f.run(async handle => {
      // Both SQL reads concern the same job row. Changing only one adapter's
      // clone would model an inconsistent DB that the real transaction cannot
      // produce, rather than the actual immutable authoring-SID boundary.
      f.job.origin_session_id = randomUUID();
      await expect(f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id)).rejects.toMatchObject({ response: { code: 'CONFIGURATION_JOB_BINDING_INVALID' } });
    });
    expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['executions', 'operations'])('refuses a preexisting %s footprint without a replacement token', async field => {
    const f = fixture();
    await f.run(async handle => {
      f.control[field as 'executions' | 'operations'] = 1;
      await expect(f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id)).rejects.toMatchObject({ response: { code: 'CONFIGURATION_INITIALIZATION_NOT_FRESH' } });
      f.control[field as 'executions' | 'operations'] = 0;
      await expect(f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id)).rejects.toThrow();
    });
    expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('keeps the actual NULL background request and rejects a manufactured HTTP request', async () => {
    const f = fixture();
    await f.run(async handle => {
      expect(f.context.current().sessionId).toBeUndefined(); expect(f.wrapperExecution.request_id).toBeNull();
      f.anchor.wrapper = { ...f.wrapperExecution, request_id: 'fabricated-background-http' };
      await expect(f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id)).rejects.toThrow();
    });
    expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('requires actual current complete-set identity rather than frozen Namespace facts alone', async () => {
    const f = fixture();
    await f.run(async handle => {
      f.values.membership = false; f.candidateStages[0].candidates[0].provenance = [{ kind: 'team', selectorId: randomUUID() }];
      // Changing the frozen candidate material is rejected by the real current
      // principal verifier; the ledger path cannot silently become count-only.
      await expect(f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id)).rejects.toThrow();
    });
    expect(f.noNative).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('checks the actual author permission version at the tail after SQL awaits', async () => {
    const f = fixture();
    await f.run(async handle => {
      f.control.beforeObjects = () => { f.control.permissionVersion = 'changed-current-permission-version'; };
      await expect(f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id)).rejects.toMatchObject({ response: { code: 'CONFIGURATION_PERMISSIONS_CHANGED' } });
    });
    expect(f.audit.append).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it.each(['namespace', 'lease'])('rechecks the original %s after the SQL object read', async boundary => {
    const f = fixture();
    await f.run(async handle => {
      f.control.beforeObjects = () => { if (boundary === 'namespace') f.values.live = false; else f.state.lease = false; };
      await expect(f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id)).rejects.toThrow();
    });
    expect(f.audit.append).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('propagates a real SQL failure and never upgrades it to a successful arm or a Native operation', async () => {
    const f = fixture();
    await f.run(async handle => {
      f.control.failSql = true;
      await expect(f.failureLedger.armInitialization(handle, claimHash, f.wrapperExecution.id)).rejects.toThrow('CONTROLLED_INITIALIZATION_SQL_FAILURE');
    });
    expect(f.audit.append).not.toHaveBeenCalled(); expect(f.noNative).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
});
