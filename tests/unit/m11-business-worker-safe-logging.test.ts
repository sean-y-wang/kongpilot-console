import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { ConflictException, ForbiddenException, HttpException, Logger, ServiceUnavailableException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WorkflowBusinessSchedulesWorker } from '../../apps/console-api/src/modules/workflows/workflow-business-schedules.worker';

/** Source-only worker/Logger with in-memory fixed delegates. No current SQL,
 * genuine claim, real timer deployment or native outcome is asserted. */
const secret = 'private-key-TEST-password-token-SHOULD-NOT-BE-LOGGED';
let warn: ReturnType<typeof vi.spyOn>, errorLog: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
  errorLog = vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
});
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); });
function fixture(ids = [randomUUID()]) {
  const original = Object.freeze({}), repository: any = { listDue: vi.fn(async () => ids) };
  const acquire = vi.fn(async () => original), execute = vi.fn(async () => {});
  const worker = new WorkflowBusinessSchedulesWorker(repository);
  worker.installFixedDelegate({ acquireDueClaim: acquire, executeClaim: execute });
  return { ids, original, repository, acquire, execute, worker };
}
function entry(spy: typeof warn) { return spy.mock.calls[0]?.[0]; }
function assertNoLeak() {
  const encoded = JSON.stringify([...warn.mock.calls, ...errorLog.mock.calls]);
  expect(encoded).not.toContain(secret); expect(encoded).not.toContain('message'); expect(encoded).not.toContain('stack');
  expect(encoded).not.toContain('body'); expect(encoded).not.toContain('credential');
  for (const call of [...warn.mock.calls, ...errorLog.mock.calls]) {
    expect(call).toHaveLength(1);
    expect(Object.keys(call[0] as any).every(key => ['event', 'stage', 'errorCode', 'scheduleId'].includes(key))).toBe(true);
  }
}
describe('business worker sanitized closed-stage failure logging', () => {
  it('logs a denied preclaim as warn without creating claimed or completed facts', async () => {
    const f = fixture(); f.acquire.mockRejectedValue(new ForbiddenException({ code: 'WORKFLOW_CURRENT_REVIEWER_REVOKED', message: secret, fields: { credential: secret } }));
    await expect(f.worker.tick()).resolves.toEqual({ checked: 1, claimed: 0, completed: 0, blocked: 1, busy: false });
    expect(entry(warn)).toEqual({ event: 'workflow-business-schedule-worker-blocked', stage: 'claim', errorCode: 'WORKFLOW_CURRENT_REVIEWER_REVOKED', scheduleId: f.ids[0] });
    expect(errorLog).not.toHaveBeenCalled(); expect(f.execute).not.toHaveBeenCalled(); assertNoLeak();
  });
  it('records a normal null claim as warn without fabricating an exception or reattempt', async () => {
    const f = fixture(); f.acquire.mockResolvedValue(null as any);
    expect(await f.worker.tick()).toEqual({ checked: 1, claimed: 0, completed: 0, blocked: 1, busy: false });
    expect(entry(warn)).toMatchObject({ stage: 'claim', errorCode: 'WORKFLOW_BUSINESS_SCHEDULE_CLAIM_BLOCKED' });
    expect(f.acquire).toHaveBeenCalledTimes(1); expect(f.execute).not.toHaveBeenCalled(); assertNoLeak();
  });
  it('records an execution denial without converting the existing claim to success or replaying it', async () => {
    const f = fixture(); f.execute.mockRejectedValue(new ConflictException({ code: 'WORKFLOW_NATIVE_OUTCOME_UNKNOWN', message: secret }));
    expect(await f.worker.tick()).toEqual({ checked: 1, claimed: 1, completed: 0, blocked: 1, busy: false });
    expect(entry(warn)).toMatchObject({ stage: 'execution', errorCode: 'WORKFLOW_NATIVE_OUTCOME_UNKNOWN' });
    expect(f.acquire).toHaveBeenCalledTimes(1); expect(f.execute).toHaveBeenCalledTimes(1); assertNoLeak();
  });
  it('logs an unknown exception as error using a fixed fallback only', async () => {
    const f = fixture(); f.acquire.mockRejectedValue(Object.assign(new Error(secret), { code: secret, body: secret }));
    expect((await f.worker.tick()).blocked).toBe(1);
    expect(entry(errorLog)).toMatchObject({ stage: 'claim', errorCode: 'WORKFLOW_BUSINESS_SCHEDULE_WORKER_UNKNOWN_ERROR' });
    expect(warn).not.toHaveBeenCalled(); assertNoLeak();
  });
  it('logs an unavailable infrastructure failure as error while preserving its safe code', async () => {
    const f = fixture(); f.acquire.mockRejectedValue(new ServiceUnavailableException({ code: 'WORKFLOW_STORAGE_UNAVAILABLE', message: secret }));
    await f.worker.tick(); expect(entry(errorLog)).toMatchObject({ errorCode: 'WORKFLOW_STORAGE_UNAVAILABLE' }); expect(warn).not.toHaveBeenCalled(); assertNoLeak();
  });
  it.each([secret, 'bad-code', 'small_code', 'A'.repeat(81), 'OK\nTOKEN', { token: secret }, 42, undefined])
  ('does not pass invalid error code %j into logs', async code => {
    const f = fixture(); f.acquire.mockRejectedValue(new ForbiddenException({ code, message: secret, private: secret }));
    await f.worker.tick(); expect(entry(errorLog)).toMatchObject({ errorCode: 'WORKFLOW_BUSINESS_SCHEDULE_WORKER_UNKNOWN_ERROR' }); assertNoLeak();
  });
  it('does not trust a plain object with a forged HTTP-exception shape', async () => {
    const f = fixture(); f.acquire.mockRejectedValue({ getResponse: () => ({ code: 'FORGED_POLICY', message: secret }), getStatus: () => 403, message: secret });
    await f.worker.tick(); expect(entry(errorLog)).toMatchObject({ errorCode: 'WORKFLOW_BUSINESS_SCHEDULE_WORKER_UNKNOWN_ERROR' }); assertNoLeak();
  });
  it('tolerates throwing exception getters without exposing or replacing the original outcome', async () => {
    const f = fixture(), original = new ForbiddenException();
    vi.spyOn(original, 'getResponse').mockImplementation(() => { throw Error(secret); }); f.acquire.mockRejectedValue(original);
    expect((await f.worker.tick()).blocked).toBe(1); expect(entry(errorLog)).toMatchObject({ errorCode: 'WORKFLOW_BUSINESS_SCHEDULE_WORKER_UNKNOWN_ERROR' }); assertNoLeak();
  });
  it('logs listing failures once, preserves rejection and resets busy', async () => {
    const f = fixture(), original = new Error(secret); f.repository.listDue.mockRejectedValueOnce(original);
    await expect(f.worker.tick()).rejects.toBe(original);
    expect(entry(errorLog)).toEqual({ event: 'workflow-business-schedule-worker-blocked', stage: 'listing', errorCode: 'WORKFLOW_BUSINESS_SCHEDULE_WORKER_UNKNOWN_ERROR' });
    expect(f.acquire).not.toHaveBeenCalled(); await expect(f.worker.tick()).resolves.toMatchObject({ completed: 1, busy: false });
    expect(errorLog).toHaveBeenCalledTimes(1); assertNoLeak();
  });
  it('omits unsafe schedule selectors and logs only the closed stage', async () => {
    const f = fixture([secret]); f.acquire.mockRejectedValue(new ForbiddenException({ code: 'WORKFLOW_SCOPE_DENIED' }));
    await f.worker.tick(); expect(entry(warn)).toEqual({ event: 'workflow-business-schedule-worker-blocked', stage: 'claim', errorCode: 'WORKFLOW_SCOPE_DENIED' }); assertNoLeak();
  });
  it('keeps independent per-object counts and handles without retrying a failed claimed object', async () => {
    const f = fixture([randomUUID(), randomUUID(), randomUUID()]);
    f.acquire.mockResolvedValueOnce(f.original).mockResolvedValueOnce(null as any).mockRejectedValueOnce(new Error(secret));
    expect(await f.worker.tick()).toEqual({ checked: 3, claimed: 1, completed: 1, blocked: 2, busy: false });
    expect(f.repository.listDue).toHaveBeenCalledWith(25); expect(f.acquire).toHaveBeenCalledTimes(3); expect(f.execute).toHaveBeenCalledOnce();
    expect(warn).toHaveBeenCalledTimes(1); expect(errorLog).toHaveBeenCalledTimes(1); assertNoLeak();
  });
  it('does not log or claim on a concurrently busy tick', async () => {
    const f = fixture(); let release!: (ids: string[]) => void;
    f.repository.listDue.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
    const first = f.worker.tick(); expect(await f.worker.tick()).toEqual({ checked: 0, claimed: 0, completed: 0, blocked: 0, busy: true });
    expect(warn).not.toHaveBeenCalled(); expect(errorLog).not.toHaveBeenCalled(); release(f.ids); await first;
  });
  it('logs timer listing failures without an unhandled rejection and stops on destroy', async () => {
    vi.useFakeTimers(); vi.stubEnv('BUSINESS_SCHEDULES_ENABLED', 'true');
    const f = fixture(); f.repository.listDue.mockRejectedValue(new Error(secret)); f.worker.onApplicationBootstrap();
    await vi.advanceTimersByTimeAsync(5000); expect(errorLog).toHaveBeenCalledTimes(1); expect(entry(errorLog)).toMatchObject({ stage: 'listing' });
    f.worker.onModuleDestroy(); await vi.advanceTimersByTimeAsync(10000); expect(errorLog).toHaveBeenCalledTimes(1); assertNoLeak();
  });
  it('remains opt-in and does not start a timer from logging changes', async () => {
    vi.useFakeTimers(); vi.stubEnv('BUSINESS_SCHEDULES_ENABLED', 'false'); const f = fixture(); f.worker.onApplicationBootstrap();
    await vi.advanceTimersByTimeAsync(10000); expect(f.repository.listDue).not.toHaveBeenCalled(); expect(warn).not.toHaveBeenCalled(); expect(errorLog).not.toHaveBeenCalled(); f.worker.onModuleDestroy();
  });
});
