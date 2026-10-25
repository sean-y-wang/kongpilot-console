import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { businessStepVerificationFixture } from './helpers/m11-business-step-verification-fixture';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ed'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
const denied = (code: string) => ({ response: { code } });
type Fixture = ReturnType<typeof businessStepVerificationFixture>;
const ordinary = (f: Fixture, format: 1 | 2, fn: () => Promise<void>) => {
  delete f.plan.scheduling; f.resealFixture();
  if (format === 1) for (const row of [f.w, f.e, f.version]) Object.assign(row, { approval_format: 1, approval_set_id: null, approval_set_hmac: null });
  return f.context.runHttp({}, () => { f.context.bindHttpActor(f.actor, f.sid);
    return f.context.runActor({ actor: f.actor, clusterId: f.cid, workspaceId: f.wid, module: 'workflows', action: 'write' },
      () => f.verifier.runApprovedExecution(f.eid, fn)); });
};
function dependency(f: Fixture) {
  const operation = f.operation(0); operation.state = 'succeeded'; operation.remote_started = true; operation.remote_completed = true;
  f.rows[0].state = 'succeeded'; f.rows[0].operation_id = operation.id; f.rows[1].state = 'running'; return operation;
}

/** Actual private execution/step maps, AEAD/normalized plan loading, Namespace
 * and Context are exercised. SQL, current grants and GET responses remain
 * explicit controlled Source adapters; no runtime or Native write is used. */
describe('scheduled V2 step kind lookup retains the final full authority before publication', () => {
  it.each(['portal-credential-issue', 'configuration_v2'] as const)('runs one hint and the final full trusted load for %s', async kind => {
    const f = businessStepVerificationFixture(kind); f.rows[0].state = 'running';
    await f.run(async () => {
      const trusted = vi.spyOn(f.verifier as any, 'trusted'), load = vi.spyOn(f.verifier as any, 'load');
      let entered = false, originalStep: any; await f.context.runApprovedStep(f.rows[0].id, async () => { entered = true;
        originalStep = f.context.currentApprovedStep();
        expect(originalStep).toMatchObject({ execution: f.proof(), stepId: f.rows[0].id, kind: f.rows[0].kind }); });
      expect(entered).toBe(true); expect(trusted).toHaveBeenCalledExactlyOnceWith(f.proof(), f.db, false, 'step', originalStep);
      expect(trusted.mock.calls[0][4]).toBe(originalStep); expect(originalStep.execution).toBe(f.proof());
      expect(load).toHaveBeenCalledTimes(1); expect(f.state.hintReads).toHaveLength(1); expect(f.db.exec).not.toHaveBeenCalled();
    });
    expect(f.kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
  });

  it.each([1, 2] as const)('keeps ordinary HTTP approval format %s on both original full trusted checks', async format => {
    const f = businessStepVerificationFixture(); f.rows[0].state = 'running';
    await ordinary(f, format, async () => {
      const trusted = vi.spyOn(f.verifier as any, 'trusted');
      await f.context.runApprovedStep(f.rows[0].id, async () => {}); expect(trusted).toHaveBeenCalledTimes(2);
      expect(f.proof().origin).toBeUndefined(); expect(f.proof().approvalFormat).toBe(format); expect(f.db.exec).not.toHaveBeenCalled();
    });
  });

  it('rejects a copied execution before any kind lookup or full authority', async () => {
    const f = businessStepVerificationFixture(); f.rows[0].state = 'running';
    await f.run(async () => {
      const load = vi.spyOn(f.verifier as any, 'load');
      await expect(f.verifier.verifyStep({ ...f.proof() }, f.rows[0].id)).rejects.toBeDefined(); expect(load).not.toHaveBeenCalled();
    });
  });

  it('does not reuse the original execution after its actual callback closes', async () => {
    const f = businessStepVerificationFixture(); let original: any; await f.run(async () => { original = f.proof(); });
    const load = vi.spyOn(f.verifier as any, 'load'); await expect(f.verifier.verifyStep(original, f.rows[0].id)).rejects.toBeDefined();
    expect(load).not.toHaveBeenCalled();
  });

  it('does not publish an unknown step after the internal kind lookup', async () => {
    const f = businessStepVerificationFixture(); await f.run(async () => {
      const trusted = vi.spyOn(f.verifier as any, 'trusted');
      await expect(f.verifier.verifyStep(f.proof(), randomUUID())).rejects.toMatchObject(denied('APPROVED_STEP_REQUIRED'));
      expect(trusted).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
    });
  });

  it.each(['reviewer', 'epoch', 'origin', 'workflow', 'execution', 'running-step', 'normalized-step', 'private-state', 'db', 'deadline'] as const)('rejects %s changed after the first kind read in the retained last full chain', async reason => {
    const f = businessStepVerificationFixture(); f.rows[0].state = 'running'; let entered = false;
    const execution = f.run(async () => {
      let reads = 0;
      f.state.afterKindHint = async () => {
        if (++reads === 1) {
          if (reason === 'reviewer') f.state.reviewerRevoked = f.reviewers[0];
          if (reason === 'epoch') f.state.epoch = 'epoch-2';
          if (reason === 'origin') f.origin.claim_id = randomUUID();
          if (reason === 'workflow') f.w.state = 'cancelled';
          if (reason === 'execution') f.e.state = 'uncertain';
          if (reason === 'running-step') f.rows[0].state = 'succeeded';
          if (reason === 'normalized-step') f.rows[0].permission_action = 'delete';
          if (reason === 'private-state') (f.verifier as any).executions.get(f.proof()).active = false;
          if (reason === 'db') f.state.dbFailure = true;
          if (reason === 'deadline') vi.spyOn(Date, 'now').mockReturnValue(Date.parse(f.ns.expiresAt) + 1);
        }
      };
      await expect(f.context.runApprovedStep(f.rows[0].id, async () => { entered = true; })).rejects.toBeDefined();
      expect(entered).toBe(false); expect(f.db.exec).not.toHaveBeenCalled();
    });
    if (reason === 'deadline') await expect(execution).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
    else await execution;
  });

  it.each(['pending', 'failed', 'incomplete', 'wrong-execution', 'wrong-step', 'wrong-plan'] as const)('retains current dependency operation rejection for %s', async reason => {
    const f = businessStepVerificationFixture(), operation = dependency(f); let entered = false;
    if (reason === 'pending' || reason === 'failed') operation.state = reason;
    if (reason === 'incomplete') operation.remote_completed = false;
    if (reason === 'wrong-execution') operation.workflow_execution_id = randomUUID();
    if (reason === 'wrong-step') operation.workflow_step_id = randomUUID();
    if (reason === 'wrong-plan') operation.workflow_plan_hash = '0'.repeat(64);
    await f.run(async () => {
      await expect(f.context.runApprovedStep(f.rows[1].id, async () => { entered = true; })).rejects.toMatchObject(denied('APPROVED_DEPENDENCY_UNACKNOWLEDGED'));
      expect(entered).toBe(false); expect(f.db.exec).not.toHaveBeenCalled();
    });
  });

  it.each(['lease', 'deadline'] as const)('retains the original Context tail when %s expires during a dependency await', async reason => {
    const f = businessStepVerificationFixture(), operation = dependency(f); let entered = false;
    const execution = f.run(async () => {
      const one = f.db.one.getMockImplementation()!;
      f.db.one.mockImplementation(async (sql: string, args: any[]) => {
        const observed = await one(sql, args);
        if (sql.includes('FROM mutation_operations') && args[0] === operation.id) {
          if (reason === 'lease') f.state.live = false;
          else vi.spyOn(Date, 'now').mockReturnValue(Date.parse(f.ns.expiresAt) + 1);
        }
        return observed;
      });
      await expect(f.context.runApprovedStep(f.rows[1].id, async () => { entered = true; })).rejects.toBeDefined();
      expect(entered).toBe(false); expect(f.db.exec).not.toHaveBeenCalled();
    });
    if (reason === 'deadline') await expect(execution).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
    else await execution;
  });

  it.each(['epoch', 'cancel', 'receipt'] as const)('keeps a fresh independent packet rejection for %s changed after dependency observation', async reason => {
    const f = businessStepVerificationFixture(), operation = dependency(f); let entered = false;
    await f.run(async () => {
      const one = f.db.one.getMockImplementation()!; let changed = false;
      f.db.one.mockImplementation(async (sql: string, args: any[]) => {
        const value = await one(sql, args), observed = value == null ? value : structuredClone(value);
        if (!changed && sql.includes('FROM mutation_operations') && args[0] === operation.id) {
          changed = true; if (reason === 'epoch') f.state.epoch = 'epoch-2';
          if (reason === 'cancel') f.w.state = 'cancelled'; if (reason === 'receipt') operation.state = 'failed';
        }
        return observed;
      });
      await f.context.runApprovedStep(f.rows[1].id, async () => {
        entered = true;
        await expect(f.context.approvedMutationBinding(f.nativeContext(1))).rejects.toBeDefined();
      });
      expect(entered).toBe(true); expect(changed).toBe(true); expect(f.db.exec).not.toHaveBeenCalled();
    });
    expect(f.kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
  });
});
