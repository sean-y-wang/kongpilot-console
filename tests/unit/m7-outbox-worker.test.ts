import 'reflect-metadata';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createRequire } from 'node:module';
const { ConflictException } = createRequire(process.cwd() + '/apps/console-api/package.json')('@nestjs/common');
import { randomUUID } from 'node:crypto';
import { EventCoreModule } from '../../apps/console-api/src/modules/event-core/event-core.module';
import { OutboxRepositoryService } from '../../apps/console-api/src/modules/event-core/outbox-repository.service';
import { EVENT_OUTBOX_WORKER_OPTIONS, OutboxWorkerService, outboxWorkerOptions } from '../../apps/console-api/src/modules/event-core/outbox-worker.service';
import type { OutboxClaim } from '../../apps/console-api/src/modules/event-core/event.types';

function claim(): OutboxClaim {
  return Object.freeze({ outboxId: randomUUID(), eventId: randomUUID(), leaseOwner: 'fixture',
    leaseGeneration: 1, revision: 1, leaseUntil: new Date(Date.now() + 30_000).toISOString() });
}
function fixture(claims: OutboxClaim[] = [claim()]) {
  const repository = { claimDue: vi.fn().mockResolvedValueOnce(claims).mockResolvedValue([]),
    fanoutPage: vi.fn(async () => ({ complete: true, created: 1 })), release: vi.fn(async () => true) };
  return { repository, worker: new OutboxWorkerService(repository as unknown as OutboxRepositoryService, { enabled: true }) };
}
function deferred() {
  let resolve!: (value: { complete: boolean; created: number }) => void;
  const promise = new Promise<{ complete: boolean; created: number }>(r => { resolve = r; });
  return { promise, resolve };
}
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

describe('M7 automatic outbox fanout lifecycle', () => {
  it('installs a real Core worker provider and enables it by default; test-only false disables it', async () => {
    vi.stubEnv('EVENT_OUTBOX_WORKER_ENABLED', undefined);
    expect(outboxWorkerOptions()).toEqual({ enabled: true });
    const providers = Reflect.getMetadata('providers', EventCoreModule);
    expect(providers).toContain(OutboxWorkerService);
    expect(providers).toContainEqual({ provide: EVENT_OUTBOX_WORKER_OPTIONS, useFactory: outboxWorkerOptions });
    vi.stubEnv('EVENT_OUTBOX_WORKER_ENABLED', 'false');
    expect(outboxWorkerOptions()).toEqual({ enabled: false });
    vi.useFakeTimers(); const f = fixture();
    const disabled = new OutboxWorkerService(f.repository as unknown as OutboxRepositoryService, outboxWorkerOptions());
    disabled.onModuleInit(); await vi.advanceTimersByTimeAsync(3_000);
    expect(f.repository.claimDue).not.toHaveBeenCalled(); await disabled.onModuleDestroy();
  });

  it('the timer calls the repository and continues 50+5 in separate ticks using the same private claim', async () => {
    vi.useFakeTimers(); const c = claim(), f = fixture([c]);
    f.repository.fanoutPage.mockResolvedValueOnce({ complete: false, created: 50 }).mockResolvedValueOnce({ complete: true, created: 5 });
    f.worker.onModuleInit(); await vi.advanceTimersByTimeAsync(999); expect(f.repository.claimDue).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1); expect(f.repository.fanoutPage.mock.calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1_000); expect(f.repository.fanoutPage.mock.calls).toEqual([[c], [c]]);
    const [first] = f.repository.claimDue.mock.calls[0] as [{ owner: string; limit: number; leaseMs: number }];
    expect(first).toEqual({ owner: expect.stringMatching(/^[a-f0-9-]{36}$/), limit: 20, leaseMs: 30_000 });
    expect(f.repository.claimDue.mock.calls[1]).toEqual([{ ...first, limit: 19 }]);
    await f.worker.onModuleDestroy();
  });

  it('does not overlap slow rounds and shutdown waits for the entered transaction, then skips later claims', async () => {
    vi.useFakeTimers(); const cs = [claim(), claim()], f = fixture(cs), pending = deferred();
    f.repository.fanoutPage.mockImplementationOnce(() => pending.promise);
    f.worker.onModuleInit(); await vi.advanceTimersByTimeAsync(1_000);
    expect(await f.worker.runOnce()).toBe(0);
    await vi.advanceTimersByTimeAsync(2_000); expect(f.repository.claimDue).toHaveBeenCalledTimes(1);
    let ended = false; const stopping = f.worker.onModuleDestroy().then(() => { ended = true; });
    await Promise.resolve(); expect(ended).toBe(false);
    pending.resolve({ complete: false, created: 50 }); await stopping;
    expect(f.repository.fanoutPage).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5_000); expect(await f.worker.runOnce()).toBe(0);
    expect(f.repository.claimDue).toHaveBeenCalledTimes(1);
  });

  it('a failing page and an unconfirmed release do not repeat it or suppress another claim', async () => {
    const cs = [claim(), claim()], f = fixture(cs);
    f.repository.fanoutPage.mockRejectedValueOnce(new Error('synthetic error must never enter a log'));
    f.repository.release.mockRejectedValueOnce(new Error('synthetic lost commit acknowledgement'));
    expect(await f.worker.runOnce()).toBe(1);
    expect(f.repository.fanoutPage.mock.calls).toEqual([[cs[0]], [cs[1]]]);
    expect(f.repository.release).toHaveBeenCalledWith(cs[0], 'EVENT_OUTBOX_FANOUT_FAILED', expect.any(String));
    expect(await f.worker.runOnce()).toBe(0);
    expect(f.repository.fanoutPage).toHaveBeenCalledTimes(2); await f.worker.onModuleDestroy();
  });

  it('a late lease cannot release a new owner and is retried only with a freshly minted claim', async () => {
    const old = claim(), fresh = Object.freeze({ ...old, leaseGeneration: 2, revision: 3 }), f = fixture([old]);
    f.repository.claimDue.mockResolvedValueOnce([fresh]);
    f.repository.fanoutPage.mockRejectedValueOnce(new ConflictException({ code: 'OUTBOX_LEASE_LOST' }));
    expect(await f.worker.runOnce()).toBe(0); expect(f.repository.release).not.toHaveBeenCalled();
    expect(await f.worker.runOnce()).toBe(1); expect(f.repository.fanoutPage.mock.calls).toEqual([[old], [fresh]]);
    await f.worker.onModuleDestroy();
  });

  it('processes at most twenty claims and one page per claim each round without draining the whole collection', async () => {
    const cs = Array.from({ length: 20 }, claim), f = fixture(cs);
    f.repository.fanoutPage.mockResolvedValue({ complete: false, created: 50 });
    expect(await f.worker.runOnce()).toBe(20); expect(f.repository.fanoutPage).toHaveBeenCalledTimes(20);
    expect(await f.worker.runOnce()).toBe(20); expect(f.repository.claimDue).toHaveBeenCalledTimes(1);
    expect(f.repository.fanoutPage).toHaveBeenCalledTimes(40); await f.worker.onModuleDestroy();
  });
});
