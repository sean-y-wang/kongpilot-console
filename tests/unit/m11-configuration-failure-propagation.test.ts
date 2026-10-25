import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConflictException, ForbiddenException, HttpException } from '@nestjs/common';
import { ConfigurationService } from '../../apps/console-api/src/modules/configuration/configuration.service';
import { WorkflowBusinessRuntimeService } from '../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import { configurationFailureLedgerFixture } from './helpers/m11-configuration-failure-ledger-fixture';
import { businessFailureExecutionFixture } from './helpers/m11-business-failure-execution-fixture';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'e7'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

/** The real formal FailureLedger consumes genuine Source handles, validates
 * original scheduled tuples and transactionally derives its receipt. The
 * initialization and execution provider adapters only locate the failure seam;
 * they grant no Native transport. Core and child share the actual Context. */
function fixture(mode: 'uncertain' | 'failed' | 'partial' = 'uncertain', outer = false, shared?: any) {
  const f = configurationFailureLedgerFixture(shared), events: string[] = [], a = f.state.anchor;
  if (mode !== 'partial') for (const s of f.state.steps) for (const key of Object.keys(s)) {
    if (key === 'state') s[key] = 'pending';
    else if (key === 'fence_count') s[key] = 0;
    else if (key === 'receipt_present') s[key] = false;
    else if (key === 'operation_id' || key === 'receipt_operation_id' || key === 'after_hmac' || key.startsWith('native_') || key.startsWith('remote_') || key.startsWith('configuration_') || key.startsWith('workflow_')) s[key] = null;
  }
  if (shared) for (const s of f.state.steps) if (s.configuration_plan_revision !== null) s.configuration_plan_revision = a.plan_revision;
  const original = new ForbiddenException({ code: 'KONG_EXECUTION_CALL_LIMIT', message: 'synthetic-secret-must-not-leak', fields: { key: 'synthetic-private-field' } });
  const one = f.db.one.getMockImplementation()!, exec = f.db.exec.getMockImplementation()!;
  const job = { id: f.jobId, plan_id: f.planId, plan_revision: a.plan_revision, plan_hash: a.plan_hash,
    safe_progress: { baselineSnapshotId: 'ab110000-0000-4000-8000-000000000090', baselineVersion: 1 } };
  f.db.one.mockImplementation(async (sql: string, p: any[]) => {
    if (sql === 'SELECT * FROM configuration_jobs WHERE id=$1') return job;
    return one(sql, p);
  });
  f.db.exec.mockImplementation(async (sql: string, p: any[]) => {
    if (sql.startsWith("UPDATE configuration_executions SET state='executing'")) { a.execution_state = 'executing'; a.execution_revision = 2; return 1; }
    return exec(sql, p);
  });
  const plan: any = { steps: f.state.steps.map(s => ({ stepId: s.plan_step_id, mutationAction: 'create' })), expiresAt: new Date(Date.now() + 60000).toISOString() };
  const repo: any = { claimJob: vi.fn(async () => {}), readPlan: vi.fn(async () => plan),
    createExecution: vi.fn(async (_: any, input: any) => { a.claim_hash = f.proof.configurationClaimHash = input.claimHash; a.execution_state = 'claimed'; a.execution_revision = 1; return { executionId: f.executionId }; }),
    initializeSteps: vi.fn(async () => f.state.steps.map(s => ({ id: s.id, planStepId: s.plan_step_id }))) };
  const raise = () => { if (mode === 'uncertain') { f.state.steps[0].state = 'running'; f.state.steps[0].remote_started = null; f.state.steps[0].remote_completed = null; } throw original; };
  Object.assign(f.access, { acquire: vi.fn(async () => f.accessHandle), isWorkflowScheduledConfigurationJob: vi.fn(() => true),
    runWorkflowScheduledConfigurationExecution: vi.fn(async (_: any, __: any, fn: any) => fn(f.jobHandle, Object.freeze({}))),
    runJob: vi.fn(async (_: any, fn: any) => outer ? raise() : fn()) });
  // Initialization correctness has independent real-ledger boundary suites;
  // this seam reaches the real formal arm rather than fabricating its token.
  const initializing = Object.freeze({});
  vi.spyOn(f.ledger, 'armInitialization').mockResolvedValue(initializing as any);
  vi.spyOn(f.ledger, 'releaseInitialization').mockImplementation(token => { expect(token).toBe(initializing); events.push('release-initialization'); });
  const formalArm = vi.spyOn(f.ledger, 'arm'), record = vi.spyOn(f.ledger, 'recordFailure');
  const native: any = { execute: vi.fn(async () => { throw Error('NO_NATIVE_SEND_IN_SOURCE_TEST'); }) };
  const approved: any = { runScheduledConfigurationExecution: vi.fn(async () => raise()) };
  const service = new ConfigurationService(f.db, { withLock: async (_: string, fn: any) => fn() } as any, f.secrets, f.context, f.audit,
    {} as any, {} as any, f.access, repo, {} as any, native, {} as any, {} as any, approved, {} as any, f.ledger, {} as any);
  vi.spyOn(service as any, 'assertPlanGrants').mockResolvedValue(undefined);
  const unfinished = vi.spyOn(service as any, 'failUnfinishedExecution');
  const execute = () => (service as any).executeJob(f.accessHandle, f.jobId, { user: f.actor },
    { workflowId: f.workflowId, approvedVersion: a.workflow_plan_revision, workflowExecutionId: f.wrapperE });
  return { ...f, service, original, events, native, repo, approved, formalArm, record, unfinished, execute };
}

describe('configuration failure ledger propagates unresolved child facts to the original wrapper error', () => {
  it.each([false, true])('propagates real committed uncertain from the %s catch without inventing a receipt', async outer => {
    const f = fixture('uncertain', outer); let caught: any;
    await f.run(async () => { try { await f.execute(); } catch (error) { caught = error; } });
    expect(caught).toBeInstanceOf(HttpException); expect(caught.getStatus()).toBe(403);
    expect(caught.getResponse()).toMatchObject({ code: 'KONG_EXECUTION_CALL_LIMIT', state: 'uncertain' });
    expect(caught.getResponse()).not.toHaveProperty('terminalFailureRecorded');
    expect(JSON.stringify(caught.getResponse())).not.toContain('synthetic-secret'); expect(JSON.stringify(caught.getResponse())).not.toContain('synthetic-private-field');
    expect(f.state.anchor).toMatchObject({ job_state: 'uncertain', execution_state: 'uncertain' }); expect(f.state.steps[0].state).toBe('uncertain');
    expect(f.formalArm).toHaveBeenCalledTimes(1); expect(f.record).toHaveBeenCalledTimes(1); expect(f.audit.append).toHaveBeenCalledOnce();
    expect(f.unfinished).not.toHaveBeenCalled(); expect(f.native.execute).not.toHaveBeenCalled();
  });

  it.each(['failed', 'partial'] as const)('preserves the original error for real committed %s child facts', async mode => {
    const f = fixture(mode); await expect(f.run(f.execute)).rejects.toBe(f.original);
    expect(f.state.anchor.job_state).toBe(mode); expect(f.state.anchor.execution_state).toBe(mode);
    expect(f.record).toHaveBeenCalledOnce(); expect(f.native.execute).not.toHaveBeenCalled();
  });

  it.each(['rollback', 'commit-ack'] as const)('marks %s uncertainty without retrying or claiming a persisted receipt', async mode => {
    const f = fixture();
    // Capture the actual original implementation, not this spy's replacement.
    const actual = Object.getPrototypeOf(f.ledger).recordFailure.bind(f.ledger);
    f.record.mockImplementation(async (...args: any[]) => { if (mode === 'commit-ack') await actual(...args); throw new ConflictException({ code: 'SOURCE_LEDGER_SQL_UNKNOWN', fields: { password: 'synthetic-not-public' } }); });
    let caught: any; await f.run(async () => { try { await f.execute(); } catch (error) { caught = error; } });
    expect(caught.getResponse()).toMatchObject({ state: 'uncertain', code: 'KONG_EXECUTION_CALL_LIMIT' });
    expect(caught.getResponse()).not.toHaveProperty('terminalFailureRecorded'); expect(JSON.stringify(caught.getResponse())).not.toContain('synthetic-not-public');
    expect(f.record).toHaveBeenCalledOnce(); expect(f.formalArm).toHaveBeenCalledOnce(); expect(f.unfinished).not.toHaveBeenCalled(); expect(f.native.execute).not.toHaveBeenCalled();
    expect(f.state.anchor.job_state).toBe(mode === 'commit-ack' ? 'uncertain' : 'running');
  });

  it.each([{}, null, undefined, { state: 'failed' }, { state: 'succeeded', terminalFailureRecorded: true },
    { state: new String('failed'), terminalFailureRecorded: true }, Object.assign([], { state: 'failed', terminalFailureRecorded: true })])('does not certify a malformed ledger observation as known failure: %j', async receipt => {
    const f = fixture(); f.record.mockResolvedValue(receipt as any);
    await expect(f.run(f.execute)).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CALL_LIMIT', state: 'uncertain' } });
    expect(f.record).toHaveBeenCalledOnce(); expect(f.unfinished).not.toHaveBeenCalled(); expect(f.native.execute).not.toHaveBeenCalled();
  });

  it('treats an initialization ledger rejection as unknown without claiming a child terminal commit', async () => {
    const f = fixture(); f.repo.initializeSteps.mockRejectedValue(f.original);
    const initializing = vi.spyOn(f.ledger, 'recordInitializationFailure').mockRejectedValue(new ConflictException({ code: 'SOURCE_INIT_COMMIT_UNKNOWN' }));
    await expect(f.run(f.execute)).rejects.toMatchObject({ response: { code: 'KONG_EXECUTION_CALL_LIMIT', state: 'uncertain' }, status: 403 });
    expect(initializing).toHaveBeenCalledOnce(); expect(f.formalArm).not.toHaveBeenCalled(); expect(f.record).not.toHaveBeenCalled();
    expect(f.state.anchor.job_state).toBe('running'); expect(f.unfinished).not.toHaveBeenCalled(); expect(f.native.execute).not.toHaveBeenCalled();
  });

  it.each([new Error('synthetic non-HTTP failure'), new HttpException({ code: 'SOURCE_PREVIOUSLY_UNKNOWN' }, 503)])('does not downgrade an original unknown exception after a known failed ledger result', async error => {
    const f = fixture('failed'); f.approved.runScheduledConfigurationExecution.mockRejectedValue(error);
    await expect(f.run(f.execute)).rejects.toBe(error); expect(f.state.anchor.job_state).toBe('failed'); expect(f.record).toHaveBeenCalledOnce();
  });

  it('uses actual Core/Context unknown classification for a real child uncertain result', async () => {
    const core = businessFailureExecutionFixture(); let child: ReturnType<typeof fixture>;
    core.handler.prepare.mockImplementation(async () => { child = fixture('uncertain', false, core); await child.execute(); });
    const completion = await core.run(); expect(child!.state.anchor.job_state).toBe('uncertain');
    expect(core.stored.w.state).toBe('uncertain'); expect(core.stored.e.state).toBe('uncertain'); expect(core.stored.steps[0].state).toBe('uncertain');
    await expect(core.service.verifyCompletion(core.authorityHandle, completion, core.db)).resolves.toBe('uncertain');
    expect(core.dispatch).not.toHaveBeenCalled(); expect(child!.native.execute).not.toHaveBeenCalled();
  });

  it.each(['failed', 'partial', 'uncertain'] as const)('keeps actual Root completion derivation and Core verification consistent with child %s', async mode => {
    const core = businessFailureExecutionFixture(); let child: ReturnType<typeof fixture>;
    core.handler.prepare.mockImplementation(async () => { child = fixture(mode, false, core); await child.execute(); });
    const one = core.db.one.getMockImplementation()!;
    core.db.one.mockImplementation(async (sql: string, args: any[]) => {
      const value = await one(sql, args);
      return value && sql.includes('w.state AS workflow_state') ? { ...value, completed_at: new Date().toISOString() } : value;
    });
    core.db.query = vi.fn(async (sql: string) => {
      if (sql.includes('FROM workflow_steps')) return core.stored.steps.map((row: any) => ({ ...row, plan_hash: core.ns.workflow.planHash }));
      if (sql.includes('FROM workflow_configuration_execution_origins')) return [{ id: child.executionId, actor_id: core.actor.id,
        state: child.state.anchor.execution_state, completed_at: new Date().toISOString() }];
      throw Error('UNPLANNED_COMPLETION_QUERY');
    });
    const repository: any = { inspectStored: vi.fn(async () => ({ plan: core.plan, claim: core.ns.claim, progress: { claimId: core.ns.claim.id } })) };
    const runtime: any = new WorkflowBusinessRuntimeService(core.db, core.deps.redis, core.secrets, core.context, {} as any, {} as any,
      core.deps.plans, {} as any, {} as any, repository, {} as any, {} as any, {} as any, {} as any, {} as any, {} as any,
      {} as any, {} as any, {} as any, {} as any, {} as any);
    // Controlled fixed Root registry associates the actual original Source
    // Authority handle; copies cannot use the original completion observer.
    runtime.claims.set(core.authorityHandle, { namespace: core.namespaceHandle, proof: core.ns });
    core.delegate.deriveCompletion.mockImplementation((handle: object, eid: string, tx: any) => runtime.completion(handle, eid, tx));
    const completion = await core.run();
    expect(child!.state.anchor.execution_state).toBe(mode); expect(core.stored.e.state).toBe(mode === 'uncertain' ? 'uncertain' : 'failed');
    await expect(core.service.verifyCompletion(core.authorityHandle, completion, core.db)).resolves.toBe(mode);
    await expect(core.service.verifyCompletion(core.authorityHandle, { ...completion }, core.db)).rejects.toBeDefined();
    await expect(runtime.completion({ ...core.authorityHandle }, core.stored.e.id, core.db)).rejects.toBeDefined();
    expect(core.dispatch).not.toHaveBeenCalled(); expect(child!.native.execute).not.toHaveBeenCalled();
  });
});
