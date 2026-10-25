import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { ConfigurationFailureLedgerService } from '../../apps/console-api/src/modules/configuration/configuration-failure-ledger.service';
import { ConfigurationService } from '../../apps/console-api/src/modules/configuration/configuration.service';
import { CONFIGURATION_FAILURE_STEP_CAS as STEP } from '../../apps/console-api/src/modules/configuration/configuration-failure-queries';
import { CONFIGURATION_INITIALIZATION_ANCHOR_QUERY as ANCHOR, CONFIGURATION_INITIALIZATION_FOOTPRINT_QUERY as FOOTPRINT,
 CONFIGURATION_INITIALIZATION_PLAN_OBJECTS_QUERY as OBJECTS, CONFIGURATION_INITIALIZATION_CHILD_QUERY as CHILD,
 CONFIGURATION_INITIALIZATION_STEPS_QUERY as STEPS, CONFIGURATION_INITIALIZATION_JOB_CAS as JOB,
 CONFIGURATION_INITIALIZATION_EXECUTION_CAS as EXECUTION } from '../../apps/console-api/src/modules/configuration/configuration-initialization-failure';

/** Actual ledger WeakMaps, real Context ancestry and real ConfigurationService
 * failure routing; SQL, Access verification and transport are explicit doubles.
 * These Source tests do not connect to a database, session, socket or lab. */
const id = (n: number) => `ab120000-0000-4000-8000-${String(n).padStart(12, '0')}`;
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'c9'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
function fixture(count = 2) {
 const context = new KongExecutionContextService(), secrets = new SecretService(), cid = id(1), wid = id(2), actor = { id: id(3), username: 'source-executor', superAdmin: false };
 const namespaceHandle = Object.freeze({}), originalJob = Object.freeze({}), accessHandle = Object.freeze({}), claimHash = 'a'.repeat(64);
 const until = new Date(Date.now() + 120000).toISOString(), planHash = 'b'.repeat(64), workflowHash = 'c'.repeat(64);
 const job: any = { id: id(4), cluster_id: cid, workspace_id: wid, actor_id: actor.id, origin_type: 'http', origin_session_id: id(5), kind: 'apply', state: 'running',
  execution_mode: 'approval', approval_required: true, remote_started: false, remote_completed: false, revision: 3, lease_generation: 1,
  lease_owner_hash: 'd'.repeat(64), lease_until: until, authority_expires_at: until, expires_at: until, transport_scope: 'e'.repeat(64),
  permission_version: 'source-current-pv', credential_epoch: 2, plan_id: id(6), plan_revision: 2, plan_hash: planHash, workflow_id: id(7),
  safe_progress: { baselineSnapshotId: id(8), baselineVersion: 1 }, request_id: 'original-http-request' };
 const common = { cluster_id: cid, workspace_id: wid }, workflow = { ...common, id: job.workflow_id, kind: 'configuration_v2', subject_type: 'configuration_jobs', subject_id: job.id,
  requester_type: 'console', requester_user_id: actor.id, state: 'executing', execution_mode: 'approval', approval_required: true, plan_revision: 3, plan_hash: workflowHash };
 const wrapper = { ...common, id: id(9), workflow_id: workflow.id, state: 'executing', snapshot_state: 'ready', request_id: null, execution_actor_id: actor.id,
  plan_revision: workflow.plan_revision, plan_hash: workflowHash, permission_version: job.permission_version };
 const origin = { ...common, id: id(10), execution_id: wrapper.id, workflow_id: workflow.id, executor_id: actor.id, claim_id: id(11), schedule_id: id(12),
  workflow_plan_revision: workflow.plan_revision, workflow_plan_hash: workflowHash };
 const workflowStep = { ...common, id: id(13), workflow_id: workflow.id, plan_revision: 3, plan_hash: workflowHash, kind: 'metadata', handler: 'configuration_v2',
  entity_type: 'configuration_jobs', entity_id: job.id, state: 'running', native_requests: [] };
 const anchor: any = { job, version: { ...common, plan_id: job.plan_id, plan_revision: 2, plan_hash: planHash, step_count: count },
  plan: { ...common, id: job.plan_id, current_revision: 2 }, workflow, wrapper, wrapper_origin: origin, workflow_step: workflowStep };
 const objects = Array.from({ length: count }, (_, n) => ({ ...common, plan_id: job.plan_id, plan_revision: 2, plan_hash: planHash, step_id: id(20 + n), step_order: n + 1,
  object_workspace_id: wid, before_hmac: 'f'.repeat(64), native_id: null, allocated_native_id: id(30 + n) }));
 const state: any = { anchor, objects, child: null, steps: [], executionCount: 0, operations: 0, fences: 0, failCas: false, failAudit: false, live: true };
 let db: any;
 db = { transaction: vi.fn(async (fn: any) => { const old = structuredClone(state); try { return await fn(db); } catch (e) { Object.assign(state, old); throw e; } }),
  one: vi.fn(async (sql: string, p: any[]) => {
   if (sql === ANCHOR) { expect(p).toEqual([cid, wid, job.id, wrapper.id]); return structuredClone(state.anchor); }
   if (sql === FOOTPRINT) { expect(p).toEqual([cid, wid, job.id, workflow.id, wrapper.id]); return { execution_count: state.executionCount, operation_count: state.operations, fence_count: state.fences, step_count: state.steps.length }; }
   if (sql === CHILD) { expect(p).toEqual([cid, wid, job.id]); return structuredClone(state.child); }
   if (sql === 'SELECT * FROM configuration_jobs WHERE id=$1') return structuredClone(state.anchor.job);
   throw new Error('UNEXPECTED_SOURCE_QUERY');
  }),
  query: vi.fn(async (sql: string) => { if (sql === OBJECTS) return structuredClone(state.objects); if (sql === STEPS) return structuredClone(state.steps); throw new Error('UNEXPECTED_SOURCE_ROWS'); }),
  exec: vi.fn(async (sql: string, p: any[]) => {
   if (state.failCas) return 0;
   if (sql === STEP) { const s = state.steps.find((s: any) => s.id === p[7]); s.state = p[9]; s.error_code = p[10]; s.revision++; return 1; }
   if (sql === JOB) { expect(p[9]).toBe(job.origin_session_id); state.anchor.job.state = 'failed'; state.anchor.job.revision++; return 1; }
   if (sql === EXECUTION) { expect(p).toHaveLength(14); state.child.execution.state = 'failed'; state.child.execution.revision++; state.child.execution.completed_at = new Date().toISOString(); return 1; }
   if (sql.startsWith("UPDATE configuration_executions SET state='executing'")) { state.child.execution.state = 'executing'; state.child.execution.revision++; return 1; }
   throw new Error('UNEXPECTED_SOURCE_WRITE');
  }) };
 const description: any = { actor, sessionId: null, jobId: job.id, scope: { clusterId: cid, workspaceId: wid, transportScope: job.transport_scope }, permissionVersion: job.permission_version, leaseGeneration: 1 };
 const proof: any = { origin: 'workflow-scheduled-configuration', sessionId: null, readOnly: false, namespaceHandle, jobId: job.id, actor, clusterId: cid, workspaceId: wid,
  expiresAt: Date.now() + 120000, planId: job.plan_id, planRevision: 2, planHash, permissionVersion: job.permission_version, credentialEpoch: 2, leaseGeneration: 1,
  claimId: origin.claim_id, wrapperOriginId: origin.id, wrapperExecutionId: wrapper.id };
 const check = (h: object) => { if (h !== accessHandle || !state.live) throw new Error('ORIGINAL_LIVE_ACCESS_REQUIRED'); };
 const access: any = { description: vi.fn(async (h: object) => { check(h); return description; }), verifyHandle: vi.fn(async (h: object) => { check(h); return { ...proof, originalScheduledJobHandle: originalJob }; }),
  originalWorkflowScheduledConfigurationJobHandle: vi.fn((h: object) => { check(h); return originalJob; }),
  workflowScheduledConfigurationJobProof: vi.fn(async (h: object) => { check(h); return proof; }), assertCurrent: vi.fn(async (h: object) => { check(h); }),
  acquire: vi.fn(async () => accessHandle), isWorkflowScheduledConfigurationJob: vi.fn(() => true) };
 const namespaceProof: any = { origin: 'scheduled-workflow', sessionId: null, actor, clusterId: cid, workspaceId: wid, kind: 'configuration_v2', expiresAt: until,
  workflow: { id: workflow.id }, claim: { id: origin.claim_id }, permissionVersion: job.permission_version };
 context.installWorkflowScheduledNamespacePolicy({ assertLive(h) { if (h !== namespaceHandle || !state.live) throw new Error('NAMESPACE_CLOSED'); },
  async verifyHandle(h) { if (h !== namespaceHandle || !state.live) throw new Error('NAMESPACE_CLOSED'); return namespaceProof; } });
 const approvedHandle = Object.freeze({}), approvedProof: any = { origin: 'scheduled-workflow', sessionId: null, actorId: actor.id, clusterId: cid, workspaceId: wid,
  executionId: wrapper.id, workflowId: workflow.id, scheduleClaimId: origin.claim_id, workflowOriginId: origin.id, permissionVersion: job.permission_version, expiresAt: Date.parse(until) };
 context.installApprovedPolicy({ verifyExecution: async (h: object) => { if (h !== approvedHandle || !state.live) throw Error('ORIGINAL_APPROVED_EXECUTION_REQUIRED'); return approvedProof; },
  verifyWorkflowScheduledExecution: async (p: object, h: object) => { if (p !== approvedProof || h !== namespaceHandle || !state.live) throw Error('ORIGINAL_NAMESPACE_REQUIRED'); },
  verifyStep: async (p: object, selected: string) => { if (p !== approvedProof || selected !== workflowStep.id || !state.live) throw Error('ORIGINAL_METADATA_STEP_REQUIRED'); return { execution: approvedProof, stepId: selected, kind: 'metadata' }; },
  mutationBinding: async () => { throw Error('NO_NATIVE'); }, bindOperation: async () => { throw Error('NO_NATIVE'); }, assertNative: async () => { throw Error('NO_NATIVE'); }, assertMetadata: async () => undefined } as any);
 const audit: any = { append: vi.fn(async () => { if (state.failAudit) throw new Error('AUDIT_WRITE_UNAVAILABLE'); return { id: id(80) }; }) };
 const ledger = new ConfigurationFailureLedgerService(db, secrets, audit, access, context, {} as any);
 const run = <T>(fn: () => Promise<T>) => context.runWorkflowScheduledNamespace(namespaceHandle, () => context.runApprovedWorkflow(approvedHandle as any, () => context.runApprovedStep(workflowStep.id, fn)));
 const arm = () => ledger.armInitialization(accessHandle as any, claimHash, wrapper.id);
 const create = (executionState = 'claimed', pending = false) => {
  state.executionCount = 1;
  state.child = { execution: { ...common, id: id(40), job_id: job.id, actor_id: actor.id, execution_mode: 'approval', state: executionState,
   revision: executionState === 'claimed' ? 1 : 2, completed_at: null, plan_id: job.plan_id, plan_revision: 2, plan_hash: planHash, permission_version: job.permission_version,
   workflow_id: workflow.id, approved_version: 3, workflow_plan_hash: workflowHash, claim_hash: claimHash, lease_generation: 1, expires_at: job.expires_at,
   before_snapshot_id: job.safe_progress.baselineSnapshotId, before_snapshot_version: 1 },
   origin: { ...common, id: id(41), wrapper_origin_id: origin.id, claim_id: origin.claim_id, workflow_execution_id: wrapper.id, workflow_id: workflow.id,
    workflow_plan_revision: 3, workflow_plan_hash: workflowHash, configuration_execution_id: id(40), configuration_job_id: job.id, configuration_plan_id: job.plan_id,
    configuration_plan_revision: 2, configuration_plan_hash: planHash, workflow_step_id: workflowStep.id } };
  if (pending) state.steps = objects.map((p, n) => ({ ...common, id: id(50 + n), job_id: job.id, execution_id: id(40), plan_id: job.plan_id, plan_revision: 2, plan_hash: planHash,
   plan_step_id: p.step_id, step_order: n + 1, object_workspace_id: p.object_workspace_id, approval_required: true, before_hmac: p.before_hmac, original_native_id: p.allocated_native_id,
   state: 'pending', revision: 1, started_at: null, completed_at: null, operation_id: null, receipt_operation_id: null, receipt_ciphertext: null, after_hmac: null,
   recycle_entry_id: null, effective_native_id: null, error_code: null, safe_result: {} }));
 };
 return { ledger, db, audit, context, secrets, state, anchor, job, proof, access, accessHandle, originalJob, run, arm, create, claimHash, wrapper, cid, wid, actor };
}

describe('same-process scheduled initialization failure capability', () => {
 it.each(['claimed', 'executing'])('records exact %s child failed after current authority closes, without reauthorizing or manufacturing a request', async kind => {
  const f = fixture(), token = await f.run(f.arm); f.create(kind); f.state.live = false;
  const calls = f.access.assertCurrent.mock.calls.length;
  await expect(f.ledger.recordInitializationFailure(token, new ForbiddenException({ code: 'WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED' }))).resolves.toMatchObject({ state: 'failed', nativeRequestsSent: 0, initializationFailed: true });
  expect(f.access.assertCurrent).toHaveBeenCalledTimes(calls); expect(f.state.anchor.job.state).toBe('failed'); expect(f.state.child.execution.state).toBe('failed');
  expect(f.audit.append).toHaveBeenCalledOnce(); expect(f.audit.append.mock.calls[0][0]).not.toHaveProperty('requestId'); expect(f.audit.append.mock.calls[0][0]).not.toHaveProperty('ip');
  expect(f.state.anchor.job.origin_session_id).toBe(f.job.origin_session_id); expect(f.db.exec.mock.calls.every(([sql]: any[]) => [JOB, EXECUTION].includes(sql))).toBe(true);
  await expect(f.ledger.recordInitializationFailure(token, Error('replay'))).rejects.toThrow();
 });
 it('fails a complete untouched pending DAG as not started and commits the audit together', async () => {
  const f = fixture(), token = await f.run(f.arm); f.create('executing', true);
  await f.ledger.recordInitializationFailure(token, Error('SOURCE_INITIALIZATION_FAILED'));
  expect(f.state.steps.map((s: any) => [s.state, s.error_code])).toEqual([['failed', 'CONFIGURATION_NOT_STARTED'], ['failed', 'CONFIGURATION_NOT_STARTED']]);
  expect(f.audit.append.mock.calls[0][1]).toBe(f.db); expect(f.state.child.execution.completed_at).toBeTruthy();
 });
 it('accepts an actual zero-step plan only as a failed zero-effect initialization', async () => {
  const f = fixture(0), token = await f.run(f.arm); f.create(); await expect(f.ledger.recordInitializationFailure(token, Error('x'))).resolves.toMatchObject({ state: 'failed', completedSteps: 0 });
 });
 it.each(['executionCount', 'operations', 'fences'])('refuses preexisting %s before an initialization token exists', async field => {
  const f = fixture(); f.state[field] = 1; await expect(f.run(f.arm)).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('refuses preexisting steps before arming', async () => {
  const f = fixture(); f.create('claimed', true); f.state.executionCount = 0; await expect(f.run(f.arm)).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('requires the actual live original Access and Namespace, and cannot arm on a historical child', async () => {
  const f = fixture(); await expect(f.run(() => f.ledger.armInitialization({} as any, f.claimHash, f.wrapper.id))).rejects.toThrow('ORIGINAL_LIVE_ACCESS_REQUIRED');
  expect(f.db.one).not.toHaveBeenCalled(); f.state.live = false; await expect(f.run(f.arm)).rejects.toThrow();
 });
 it('does not accept an HTTP or unframed caller', async () => { const f = fixture(); await expect(f.arm()).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled(); });
 it.each(['namespaceHandle', 'jobId', 'clusterId', 'workspaceId', 'planId', 'planRevision', 'planHash', 'permissionVersion', 'credentialEpoch', 'leaseGeneration', 'claimId', 'wrapperOriginId', 'wrapperExecutionId'])('requires current genuine scheduled proof %s before arming', async field => {
  const f = fixture(); f.proof[field] = field === 'namespaceHandle' ? {} : ['planRevision', 'credentialEpoch', 'leaseGeneration'].includes(field) ? 999 : 'substituted';
  await expect(f.run(f.arm)).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled();
 });
 it('rechecks live authority after SQL awaits before returning the initialization token', async () => {
  const f = fixture(), query = f.db.query.getMockImplementation();
  f.db.query.mockImplementation(async (sql: string, ...args: any[]) => { const result = await query(sql, ...args); if (sql === OBJECTS) f.state.live = false; return result; });
  await expect(f.run(f.arm)).rejects.toThrow('ORIGINAL_LIVE_ACCESS_REQUIRED'); expect(f.db.exec).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled();
 });
 it('tokens cannot be copied, moved to a new provider/process, consumed twice, or rearmed after release', async () => {
  const f = fixture(), token = await f.run(f.arm); f.create();
  await expect(f.ledger.recordInitializationFailure({ ...token } as any, Error('x'))).rejects.toThrow();
  await expect(fixture().ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow();
  f.ledger.releaseInitialization(token); await expect(f.ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow();
  await expect(f.run(f.arm)).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['operations', 'fences'])('refuses newly observed %s and consumes rather than retries the capability', async field => {
  const f = fixture(), token = await f.run(f.arm); f.create(); f.state[field] = 1;
  await expect(f.ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow(); f.state[field] = 0;
  await expect(f.ledger.recordInitializationFailure(token, Error('retry'))).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('refuses a missing claimed child instead of inferring zero from an absent read', async () => {
  const f = fixture(), token = await f.run(f.arm); f.state.executionCount = 1;
  await expect(f.ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow(); expect(f.audit.append).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['claim_hash', 'actor_id', 'job_id', 'plan_id', 'plan_hash', 'workflow_id', 'workflow_plan_hash', 'before_snapshot_id', 'expires_at'])('rejects substituted child %s', async field => {
  const f = fixture(), token = await f.run(f.arm); f.create(); f.state.child.execution[field] = 'substituted';
  await expect(f.ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['claim_id', 'wrapper_origin_id', 'workflow_execution_id', 'configuration_execution_id', 'configuration_job_id', 'configuration_plan_hash', 'workflow_step_id'])('rejects substituted actual origin %s', async field => {
  const f = fixture(), token = await f.run(f.arm); f.create(); f.state.child.origin[field] = 'substituted';
  await expect(f.ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['origin_session_id', 'lease_owner_hash', 'permission_version', 'revision'])('preserves original job %s instead of adopting new facts', async field => {
  const f = fixture(), token = await f.run(f.arm); f.create(); f.state.anchor.job[field] = field === 'revision' ? 999 : 'changed';
  await expect(f.ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('requires actual NULL background request both at arm and record', async () => {
  const f = fixture(); f.state.anchor.wrapper.request_id = 'manufactured-http'; await expect(f.run(f.arm)).rejects.toThrow();
  const g = fixture(), token = await g.run(g.arm); g.create(); g.state.anchor.wrapper.request_id = 'manufactured-http';
  await expect(g.ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow(); expect(g.db.exec).not.toHaveBeenCalled();
 });
 it.each(['state', 'revision', 'operation_id', 'receipt_operation_id', 'receipt_ciphertext', 'after_hmac', 'started_at', 'effective_native_id', 'safe_result'])('rejects started, partial or receipt-bearing step %s', async field => {
  const f = fixture(), token = await f.run(f.arm); f.create('executing', true);
  f.state.steps[0][field] = field === 'state' ? 'running' : field === 'revision' ? 2 : field === 'safe_result' ? { previousEffect: true } : 'present';
  await expect(f.ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow(); expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('rejects an incomplete DAG and changed frozen plan objects', async () => {
  const f = fixture(), token = await f.run(f.arm); f.create('claimed', true); f.state.steps.pop();
  await expect(f.ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow();
  const g = fixture(), second = await g.run(g.arm); g.create(); g.state.objects[0].before_hmac = 'a'.repeat(64);
  await expect(g.ledger.recordInitializationFailure(second, Error('x'))).rejects.toThrow(); expect(g.db.exec).not.toHaveBeenCalled();
 });
 it.each(['failCas', 'failAudit'])('rolls back child/job/step changes on %s and never replays an uncertain transaction', async field => {
  const f = fixture(), token = await f.run(f.arm); f.create('executing', true); f.state[field] = true; const before = structuredClone(f.state);
  await expect(f.ledger.recordInitializationFailure(token, Error('x'))).rejects.toThrow(); expect(f.state).toEqual(before);
  await expect(f.ledger.recordInitializationFailure(token, Error('retry'))).rejects.toThrow();
 });
 it('fixed SQL covers full job/workflow/child operation footprints and uses exact original CAS identity without extending a deadline', () => {
  expect(FOOTPRINT).toContain('m.workflow_execution_id=$5'); expect(FOOTPRINT).toContain('m.configuration_execution_id IN'); expect(FOOTPRINT).toContain('m.idempotency_key LIKE');
  expect(FOOTPRINT).toContain('metrics_write_fences'); expect(JOB).toContain('j.origin_session_id=$10'); expect(JOB).toContain('j.lease_owner_hash=$14');
  expect(JOB).toContain('NOT EXISTS(SELECT 1 FROM mutation_operations'); expect(EXECUTION).toContain("e.state IN('claimed','executing')");
  expect([JOB, EXECUTION].join('')).not.toMatch(/SET[^;]*(?:expires_at|lease_until)\s*=\s*(?!NULL)/i);
 });
});

describe('actual ConfigurationService initialization failure routing', () => {
 it('prearms before create, catches expiry during initialize before entering callback, and closes only the original zero-effect child', async () => {
  const f = fixture(), events: string[] = [], native: any = { execute: vi.fn() };
  const originalArm = f.ledger.armInitialization.bind(f.ledger);
  vi.spyOn(f.ledger, 'armInitialization').mockImplementation(async (...args) => { events.push('arm'); return originalArm(...args); });
  const repo: any = { claimJob: vi.fn(async () => undefined), readPlan: vi.fn(async () => ({ steps: [{}], expiresAt: f.job.expires_at })),
   createExecution: vi.fn(async (_h, input) => { events.push('create'); f.create(); f.state.child.execution.claim_hash = input.claimHash; return { executionId: f.state.child.execution.id, claimHash: input.claimHash }; }),
   initializeSteps: vi.fn(async () => { events.push('initialize'); f.state.live = false; throw new ForbiddenException({ code: 'WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED' }); }) };
  const service = new ConfigurationService(f.db, { withLock: async (_key: string, fn: any) => fn() } as any, f.secrets, f.context, f.audit, {} as any, {} as any, f.access,
   repo, {} as any, native, {} as any, {} as any, {} as any, {} as any, f.ledger, {} as any);
  vi.spyOn(service as any, 'assertPlanGrants').mockResolvedValue(undefined); const fullArm = vi.spyOn(f.ledger, 'arm');
  await expect(f.run(() => (service as any).executeJob(f.accessHandle, f.job.id, { user: f.actor }, { workflowId: f.anchor.workflow.id, approvedVersion: 3, workflowExecutionId: f.wrapper.id }))).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_NAMESPACE_EXPIRED' } });
  expect(events).toEqual(['arm', 'create', 'initialize']); expect(f.state.child.execution.state).toBe('failed'); expect(f.state.anchor.job.state).toBe('failed');
  expect(native.execute).not.toHaveBeenCalled(); expect(fullArm).not.toHaveBeenCalled(); expect(f.audit.append).toHaveBeenCalledOnce();
 });
 it('releases initializing authority only after formal arm succeeds and routes a later failure to the existing full ledger', async () => {
  const f = fixture(), events: string[] = [], failure = new ForbiddenException({ code: 'SOURCE_GATE_AFTER_FORMAL_ARM' }), fullToken = Object.freeze({});
  const repo: any = { claimJob: vi.fn(async () => undefined), readPlan: vi.fn(async () => ({ steps: [], expiresAt: f.job.expires_at })),
   createExecution: vi.fn(async (_h, input) => { f.create(); f.state.child.execution.claim_hash = input.claimHash; return { executionId: f.state.child.execution.id, claimHash: input.claimHash }; }),
   initializeSteps: vi.fn(async () => []) };
  const release = f.ledger.releaseInitialization.bind(f.ledger);
  vi.spyOn(f.ledger, 'releaseInitialization').mockImplementation(token => { events.push('release-initialization'); release(token); });
  vi.spyOn(f.ledger, 'arm').mockImplementation(async () => { events.push('formal-arm'); return fullToken as any; });
  const formalFailure = vi.spyOn(f.ledger, 'recordFailure').mockImplementation(async () => { events.push('formal-failure'); return { state:'failed',terminalFailureRecorded:true } as any; });
  const initializingFailure = vi.spyOn(f.ledger, 'recordInitializationFailure');
  f.access.runWorkflowScheduledConfigurationExecution = vi.fn(async (_h, _eid, fn) => fn(f.originalJob, Object.freeze({})));
  f.access.runJob = vi.fn(async () => { events.push('run-job'); throw failure; });
  const native: any = { execute: vi.fn() }, service = new ConfigurationService(f.db, { withLock: async (_key: string, fn: any) => fn() } as any, f.secrets, f.context, f.audit,
   {} as any, {} as any, f.access, repo, {} as any, native, {} as any, {} as any, {} as any, {} as any, f.ledger, {} as any);
  vi.spyOn(service as any, 'assertPlanGrants').mockResolvedValue(undefined);
  await expect(f.run(() => (service as any).executeJob(f.accessHandle, f.job.id, { user: f.actor }, { workflowId: f.anchor.workflow.id, approvedVersion: 3, workflowExecutionId: f.wrapper.id }))).rejects.toBe(failure);
  expect(events).toEqual(['formal-arm', 'release-initialization', 'run-job', 'formal-failure']); expect(initializingFailure).not.toHaveBeenCalled();
  expect(formalFailure).toHaveBeenCalledExactlyOnceWith(fullToken, failure); expect(native.execute).not.toHaveBeenCalled();
 });
});
