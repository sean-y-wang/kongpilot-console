import { Injectable, Logger, OnApplicationBootstrap, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { EntityChangeScheduleRepository } from './entity-change-schedule.repository';
import { EntityScheduledAuthorityService } from './entity-scheduled-authority.service';
import { EntityChangeIntentsService } from './entity-change-intents.service';
import { EntityChangeScheduleWorker } from './entity-change-schedule.worker';
import { publishEntityScheduleWorkerProbe } from '../../infrastructure/schedule-worker-probe';

/** Installs metadata/orchestration only. Root's Kernel owns the executor and
 * namespace runner. Timer entry retains its actual ALS; HTTP frames fail at
 * Authority entry instead of being cleared or replaced by a fake identity. */
@Injectable()
export class EntityChangeScheduleBootstrapService implements OnModuleInit, OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(EntityChangeScheduleBootstrapService.name);
  private installed = false;
  private stopped = false;
  private ticking = false;
  private timer?: ReturnType<typeof setInterval>;
  constructor(private readonly repository: EntityChangeScheduleRepository, private readonly authority: EntityScheduledAuthorityService,
    private readonly intents: EntityChangeIntentsService, private readonly worker: EntityChangeScheduleWorker) {}
  onModuleInit(): void {
    if (this.installed) return;
    this.authority.installRepositoryPolicies();
    this.intents.installSchedulingDelegate(this.authority.intentSchedulingDelegate());
    this.worker.installFixedDelegate({ acquireDueClaim: id => this.authority.acquireDueClaim(id), executeClaim: handle => this.authority.executeClaim(handle) });
    this.installed = true;
  }
  onApplicationBootstrap(): void {
    const enabled = process.env.ENTITY_SCHEDULES_ENABLED === 'true';
    // Publish the opt-in before any early return so /health/ready fails closed
    // when the flag is on but the timer could not be installed.
    publishEntityScheduleWorkerProbe({ enabled, timerRunning: !!this.timer });
    if (!this.installed || this.stopped || this.timer || !enabled) return;
    // All OnModuleInit hooks completed before Nest invokes this hook. Starting
    // only here avoids calling Root's executor before its fixed installation.
    this.timer = setInterval(() => { void this.tick(); }, 5000); this.timer.unref?.();
    publishEntityScheduleWorkerProbe({ enabled: true, timerRunning: true });
  }
  private async tick(): Promise<void> {
    if (this.stopped || this.ticking) return;
    this.ticking = true;
    try { await this.worker.tick(); }
    catch { this.logger.warn({ code: 'ENTITY_SCHEDULE_WORKER_TICK_FAILED' }); }
    finally { this.ticking = false; }
  }
  onModuleDestroy(): void {
    this.stopped = true; if (this.timer) clearInterval(this.timer); this.timer = undefined;
    publishEntityScheduleWorkerProbe({ enabled: process.env.ENTITY_SCHEDULES_ENABLED === 'true', timerRunning: false });
    // Existing in-flight work keeps Root's genuine lease/window/native ledger;
    // stopping the timer does not erase claims or guess their outcome.
  }
}
