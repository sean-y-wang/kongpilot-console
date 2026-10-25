import { ConflictException, Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { DbService } from '../../../infrastructure/db.service';
import { KongService } from '../../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../../infrastructure/kong/execution-context.service';
import { MetricsRepositoryService } from '../../metrics/metrics-repository.service';
import { MetricsSettingsService } from '../../metrics/metrics-settings.service';
import type { MetricsConsumerInput, MetricsRouteInput, MetricsServiceInput } from '../../metrics/metrics.types';
import { metricsId } from '../vitals-query';

@Injectable()
export class MetricsCatalogService implements OnModuleInit, OnModuleDestroy {
  private readonly inFlight = new Map<string, Promise<void>>();
  private readonly logger = new Logger(MetricsCatalogService.name);
  private timer?: NodeJS.Timeout; private ticking = false;
  constructor(private readonly kong: KongService, private readonly execution: KongExecutionContextService,
    private readonly repository: MetricsRepositoryService, private readonly settings: MetricsSettingsService, private readonly db: DbService) {}
  onModuleInit(): void {
    if (process.env.METRICS_BRIDGE_ENABLED !== 'true') return;
    // Created during bootstrap outside HTTP ALS. Keep proofs continuous even
    // when Prometheus is the only consumer and scrapes every fifteen seconds.
    this.timer = setInterval(() => { void this.tick(); }, 5000); this.timer.unref();
  }
  onModuleDestroy(): void { if (this.timer) clearInterval(this.timer); }
  async tick(): Promise<void> {
    if (this.ticking) return; this.ticking = true;
    try {
      const clusters = await this.db.query<any>("SELECT s.cluster_id FROM metrics_settings s JOIN clusters c ON c.id=s.cluster_id WHERE s.enabled=true AND s.credential_generation>0 AND c.deleted_at IS NULL AND c.status<>'disabled' ORDER BY s.cluster_id LIMIT 101");
      if (clusters.length > 100) throw new ConflictException({ code: 'METRICS_CLUSTER_BUDGET_EXHAUSTED' });
      let next = 0;
      await Promise.all(Array.from({ length: Math.min(4, clusters.length) }, async () => {
        while (next < clusters.length) { const row = clusters[next++]; try { await this.ensureFresh(row.cluster_id); } catch { this.logger.warn(JSON.stringify({ event: 'metrics_catalog_refresh_failed', clusterId: row.cluster_id })); } }
      }));
    } catch { this.logger.warn(JSON.stringify({ event: 'metrics_catalog_scheduler_failed' })); }
    finally { this.ticking = false; }
  }
  async ensureFresh(cid: string): Promise<void> {
    const current = await this.settings.get(cid);
    if (current.state === 'ready' && current.lastVerifiedAt && Date.now() - Date.parse(current.lastVerifiedAt) < Math.min(5000, current.maxAgeMs)) return;
    const running = this.inFlight.get(cid); if (running) return running;
    const result = this.scan(cid); this.inFlight.set(cid, result);
    try { await result; } finally { if (this.inFlight.get(cid) === result) this.inFlight.delete(cid); }
  }
  /** Called only by the independent TCP listener, never from an HTTP actor. */
  async scan(cid: string): Promise<void> {
    const observedAt = new Date().toISOString();
    metricsId(cid); const current = await this.settings.get(cid), scope = await this.kong.transportScope(cid);
    const nodeId = await this.nodeIdentity(cid);
    const lists: Record<string, any[]> = { services: [], routes: [], consumers: [] };
    await this.execution.runSystemRead(cid, 'metrics-catalog', async () => {
      let pages = 0, records = 0, bytes = 0;
      for (const type of ['services', 'routes', 'consumers']) {
        let cursor: string | undefined; const seen = new Set<string>();
        do {
          if (Date.now() - Date.parse(observedAt) > Math.min(15000, current.maxAgeMs) || ++pages > 100 || records + 100 > 10000) throw new ConflictException({ code: 'METRICS_CATALOG_BUDGET_EXHAUSTED', message: '指标归属扫描超出预算，未发布不完整映射' });
          const page = await this.kong.list(cid, `/${type}`, { size: 100 }, cursor, `metrics-catalog:${cid}`);
          records += page.items.length; bytes += Buffer.byteLength(JSON.stringify(page.items));
          if (records > 10000 || bytes > 32 * 1024 * 1024) throw new ConflictException({ code: 'METRICS_CATALOG_BUDGET_EXHAUSTED', message: '指标归属扫描超出预算' });
          for (const entity of page.items) { metricsId(entity.id); lists[type].push(entity); }
          if (page.nextCursor && seen.has(page.nextCursor)) throw new ConflictException({ code: 'METRICS_CATALOG_CURSOR_LOOP', message: '指标归属扫描游标重复' });
          if (page.nextCursor) seen.add(page.nextCursor); cursor = page.nextCursor || undefined;
        } while (cursor);
      }
    }, { maxCalls: 100, maxPages: 100, maxRecords: 10000, maxBytes: 32 * 1024 * 1024, timeoutMs: Math.min(15000, current.maxAgeMs) });
    const services = new Map<string, MetricsServiceInput>();
    for (const row of lists.services) {
      if (services.has(row.id) || typeof row.host !== 'string') throw new ConflictException({ code: 'METRICS_CATALOG_INVALID', message: '原生实体列表重复或缺少指标身份' });
      services.set(row.id, { id: row.id, name: row.name, host: row.host, tags: row.tags });
    }
    const routePairs: Array<{ service: MetricsServiceInput; route: MetricsRouteInput | null }> = [], referenced = new Set<string>();
    const routeIds = new Set<string>();
    for (const row of lists.routes) {
      if (routeIds.has(row.id)) throw new ConflictException({ code: 'METRICS_CATALOG_INVALID', message: '原生 Route 列表重复' });
      routeIds.add(row.id); const service = services.get(row.service?.id);
      if (!service) continue;
      routePairs.push({ service, route: { id: row.id, name: row.name, service: { id: service.id }, tags: row.tags } }); referenced.add(service.id);
    }
    for (const service of services.values()) if (!referenced.has(service.id)) routePairs.push({ service, route: null });
    const consumers: MetricsConsumerInput[] = lists.consumers.map(row => ({ id: row.id, username: row.username, custom_id: row.custom_id, tags: row.tags }));
    if (new Set(consumers.map(row => row.id)).size !== consumers.length) throw new ConflictException({ code: 'METRICS_CATALOG_INVALID', message: '原生 Consumer 列表重复' });
    if (await this.nodeIdentity(cid) !== nodeId) throw new ConflictException({ code: 'METRICS_NATIVE_NODE_CHANGED', message: '归属扫描期间实际 Kong 节点发生变化' });
    if (Date.now() - Date.parse(observedAt) > Math.min(15000, current.maxAgeMs)) throw new ConflictException({ code: 'METRICS_CATALOG_STALE' });
    await this.repository.publishVerifiedCatalog({ cid, expectedCatalogRevision: current.catalogRevision, transportScope: scope, nodeId: scope, observedKongNodeId: nodeId, observedAt, complete: true, routePairs, consumers });
  }
  async nodeIdentity(cid: string): Promise<string> {
    return this.execution.runSystemRead(cid, 'probe', async () => { const root = await this.kong.request(cid, 'GET', '/'); if (!/^1\.5\.\d+$/.test(root.version || '')) throw new ConflictException({ code: 'KONG_METRICS_VERSION_CHANGED' }); return metricsId(root.node_id)!; }, { paths: ['/'], maxCalls: 3, maxPages: 1, maxRecords: 1, maxBytes: 2 * 1024 * 1024, timeoutMs: 5000 });
  }
}
