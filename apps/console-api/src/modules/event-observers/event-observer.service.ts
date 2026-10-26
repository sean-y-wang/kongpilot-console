import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { SecretService } from '../../infrastructure/secret.service';
import { EventRepositoryService, observationDigest } from '../event-core/event-repository.service';
import type { DetectorSubject } from '../event-core/event.types';
import { ObservationAuthorityService } from './observation-authority.service';

/** Cursor-based round robin; never materializes all clusters or native entities. */
@Injectable()
export class EventObserverService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(EventObserverService.name);
  private timer?: ReturnType<typeof setTimeout>;
  private stopped = false;
  private clusterCursor: string | null = null;
  private readonly cursors = new Map<string, string | undefined>();
  private readonly subjects: readonly DetectorSubject[] = ['certificates', 'ca_certificates', 'upstreams'];
  private subjectIndex = 0;
  private healthWindow?: { clusterId: string; ids: string[]; remaining: number };
  private readonly unresolved = new Map<string, { observationId: string; observationHmac: string }>();
  private readonly unresolvedLimit = 1000;
  constructor(private readonly db: DbService, private readonly kong: KongService,
    private readonly execution: KongExecutionContextService, private readonly authority: ObservationAuthorityService,
    private readonly events: EventRepositoryService, private readonly secrets: SecretService) {}
  onModuleInit(): void { this.schedule(10_000); }
  onModuleDestroy(): void { this.stopped = true; if (this.timer) clearTimeout(this.timer); }
  private schedule(delay: number): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => void this.tick().finally(() => this.schedule(30_000)), delay);
    this.timer.unref();
  }
  async tick(): Promise<void> {
    try {
      if (this.healthWindow) {
        const window = this.healthWindow;
        await this.sample(window.clusterId, 'upstreams', window.ids);
        if (--window.remaining === 0) this.healthWindow = undefined;
        return;
      }
      let cluster = await this.db.one<{ id: string }>(`SELECT id FROM clusters WHERE deleted_at IS NULL
        AND status NOT IN ('disabled','incompatible') AND version ~ '^1\\.[345]\\.[0-9]+$'
        AND ($1::uuid IS NULL OR id>$1::uuid) ORDER BY id LIMIT 1`, [this.clusterCursor]);
      if (!cluster) { this.clusterCursor = null; this.subjectIndex++; return; }
      this.clusterCursor = cluster.id;
      const type = this.subjects[this.subjectIndex % this.subjects.length], path = `/${type}`, key = `${cluster.id}:${type}`;
      const page = await this.execution.runEventObservationRead(cluster.id, [path],
        () => this.kong.list(cluster!.id, path, { size: 5 }, this.cursors.get(key), 'event-observer-discovery'));
      if (page.console_permission_projection) throw new Error('OBSERVATION_PROJECTION_UNAVAILABLE');
      this.cursors.set(key, page.nextCursor ?? undefined);
      // Bound cursor cache independently of registry size and remove old aliases.
      if (this.cursors.size > 1000) this.cursors.delete(this.cursors.keys().next().value!);
      const ids = page.items.map(item => item.id);
      await this.sample(cluster.id, type, ids);
      // Two subsequent real samples stay on the same five-subject page. A
      // large registry cannot accidentally space confirmation outside 30–90s.
      if (type === 'upstreams' && ids.length) this.healthWindow = { clusterId: cluster.id, ids, remaining: 2 };
    } catch { this.logger.warn(JSON.stringify({ event: 'observation_poll_unavailable' })); }
  }
  private async sample(clusterId: string, type: DetectorSubject, ids: string[]): Promise<void> {
      for (const id of ids) {
        let captured: Awaited<ReturnType<ObservationAuthorityService['observe']>> | undefined;
        let completed = false, callbackCompleted = false;
        const key = `${clusterId}:${type}:${id}`;
        try {
          const original = this.unresolved.get(key);
          // Never evict an ambiguous original receipt to make room for a new
          // observation. Existing subjects may still reconcile their receipt.
          if (!original && this.unresolved.size >= this.unresolvedLimit) {
            this.authority.noteGap(clusterId, type, id);
            this.logger.warn(JSON.stringify({ event: 'observation_commit_capacity', clusterId, subjectType: type }));
            continue;
          }
          if (original) {
            const row = await this.db.one<{ observation_hmac: string }>('SELECT observation_hmac FROM event_detection_observations WHERE id=$1', [original.observationId]);
            if (!row || row.observation_hmac !== original.observationHmac) {
              this.logger.warn(JSON.stringify({ event: 'observation_commit_unresolved', clusterId, subjectType: type }));
              continue;
            }
            // Observe the original immutable source; never enqueue it again.
            this.unresolved.delete(key);
          }
          captured = await this.authority.observe(clusterId, type, id);
          await this.db.transaction(async tx => {
            const receipt = await this.events.enqueueObservation(captured!.input, tx);
            callbackCompleted = true; return receipt;
          });
          completed = true;
        } catch (error: any) {
          this.authority.noteGap(clusterId, type, id);
          // SQLSTATE alone is not proof of rollback: connection exceptions,
          // shutdown and statement_completion_unknown also have five digits.
          // Once the callback returned, a COMMIT failure is ambiguous until the
          // exact immutable observation receipt is found by a read-only query.
          if (captured && callbackCompleted) {
            this.unresolved.set(key, { observationId: captured.input.observationId, observationHmac: observationDigest(this.secrets, captured.input) });
          }
          // Raw certificate, target, upstream response and endpoint never log.
          this.logger.warn(JSON.stringify({ event: 'observation_not_published', clusterId, subjectType: type }));
        } finally { captured?.release(completed); }
      }
  }
}
