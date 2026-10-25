import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { OutboxRepositoryService } from './outbox-repository.service';
import type { OutboxClaim } from './event.types';

export const EVENT_OUTBOX_WORKER_OPTIONS = Symbol('EVENT_OUTBOX_WORKER_OPTIONS');
export interface OutboxWorkerOptions { enabled: boolean; }
export function outboxWorkerOptions(): OutboxWorkerOptions {
  return { enabled: process.env.EVENT_OUTBOX_WORKER_ENABLED !== 'false' };
}
const POLL_MS = 1_000;
const CLAIM_LIMIT = 20;
const LEASE_MS = 30_000;

/** Only the repository mints claims and commits source-authorized fanout pages. */
@Injectable()
export class OutboxWorkerService implements OnModuleInit, OnModuleDestroy {
  private readonly owner = randomUUID();
  private readonly logger = new Logger(OutboxWorkerService.name);
  private readonly continuing = new Map<string, OutboxClaim>();
  private timer?: NodeJS.Timeout;
  private active?: Promise<number>;
  private stopped = false;

  constructor(private readonly repository: OutboxRepositoryService,
    @Inject(EVENT_OUTBOX_WORKER_OPTIONS) private readonly options: OutboxWorkerOptions) {}

  onModuleInit(): void {
    if (!this.options.enabled || this.stopped || this.timer) return;
    this.timer = setInterval(() => {
      void this.runOnce().catch(() => this.logger.error({ code: 'EVENT_OUTBOX_POLL_FAILED' }));
    }, POLL_MS);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    // Finish an already-entered transaction before Nest closes its DB provider.
    // Unfinished claims retain their durable cursor and expire for another owner.
    await this.active?.catch(() => undefined);
    this.continuing.clear();
  }

  runOnce(): Promise<number> {
    if (this.stopped || this.active) return Promise.resolve(0);
    const run = this.poll();
    this.active = run;
    return run.finally(() => { if (this.active === run) this.active = undefined; });
  }

  private async poll(): Promise<number> {
    const capacity = CLAIM_LIMIT - this.continuing.size;
    if (capacity > 0) {
      const fresh = await this.repository.claimDue({ owner: this.owner, limit: capacity, leaseMs: LEASE_MS });
      for (const claim of fresh) this.continuing.set(claim.outboxId, claim);
    }
    let pages = 0;
    for (const claim of [...this.continuing.values()].slice(0, CLAIM_LIMIT)) {
      if (this.stopped) break;
      try {
        const result = await this.repository.fanoutPage(claim);
        pages++;
        if (result.complete) this.continuing.delete(claim.outboxId);
      } catch (error) {
        this.continuing.delete(claim.outboxId);
        const code = outboxFailureCode(error);
        // A page may have committed despite a lost acknowledgement. Release is
        // itself revision/lease-CAS guarded; a new owner or committed cursor wins.
        if (code !== 'OUTBOX_LEASE_LOST' && code !== 'OUTBOX_CLAIM_INVALID') {
          try { await this.repository.release(claim, code, new Date(Date.now() + POLL_MS).toISOString()); }
          catch { this.logger.warn({ code: 'EVENT_OUTBOX_RELEASE_UNCONFIRMED' }); }
        }
        this.logger.warn({ code });
      }
    }
    return pages;
  }
}

function outboxFailureCode(error: unknown): string {
  if (error && typeof error === 'object') {
    const value = error as { getResponse?: () => unknown };
    const response = value.getResponse?.();
    if (response && typeof response === 'object' && 'code' in response) {
      const code = String(response.code);
      if (/^[A-Z0-9_]{1,128}$/.test(code)) return code;
    }
  }
  return 'EVENT_OUTBOX_FANOUT_FAILED';
}
