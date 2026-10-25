import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Logger } from '@nestjs/common';
import { GovernanceSchedulerService } from '../../apps/console-api/src/modules/governance/governance-scheduler.service';

describe('governance scheduler background database resilience', () => {
  let scheduler: GovernanceSchedulerService;
  let repo: { expiredScheduleRuns: ReturnType<typeof vi.fn>; dueSchedules: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    vi.useFakeTimers();
    repo = { expiredScheduleRuns: vi.fn().mockResolvedValue([]), dueSchedules: vi.fn().mockResolvedValue([]) };
    scheduler = new GovernanceSchedulerService({} as any, {} as any, repo as any, {} as any, {} as any);
  });
  afterEach(() => { scheduler.onModuleDestroy(); vi.useRealTimers(); vi.restoreAllMocks(); });

  it.each(['expiredScheduleRuns', 'dueSchedules'] as const)('handles timer %s rejection with a fixed safe log and retries on the next tick', async method => {
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    repo[method].mockRejectedValueOnce(Object.assign(new Error('fixture.invalid fixture-password sensitive query'), {
      host: 'fixture.invalid', password: 'fixture-password', stack: 'private database stack',
    }));
    scheduler.onModuleInit();
    await vi.advanceTimersByTimeAsync(10000);
    expect(warn.mock.calls).toEqual([[{
      component: 'governance-scheduler', code: 'GOVERNANCE_SCHEDULE_TICK_FAILED',
    }]]);
    expect(repo[method]).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(10000);
    expect(repo[method]).toHaveBeenCalledTimes(2);
    expect(repo.dueSchedules).toHaveBeenCalledTimes(method === 'expiredScheduleRuns' ? 1 : 2);
    expect(warn).toHaveBeenCalledOnce();
    scheduler.onModuleDestroy();
    await vi.advanceTimersByTimeAsync(20000);
    expect(repo[method]).toHaveBeenCalledTimes(2);
  });

  it.each(['expiredScheduleRuns', 'dueSchedules'] as const)('preserves explicit %s failures and clears the running guard', async method => {
    const failure = new Error('explicit repository failure');
    repo[method].mockRejectedValueOnce(failure);
    await expect(scheduler.tick()).rejects.toBe(failure);
    await expect(scheduler.tick()).resolves.toBeUndefined();
    expect(repo[method]).toHaveBeenCalledTimes(2);
  });
});
