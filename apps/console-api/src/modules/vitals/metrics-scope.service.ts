import { BadRequestException, ConflictException, ForbiddenException, Injectable } from '@nestjs/common';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { filteredList } from '../../infrastructure/kong/filtered-list';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { MetricsRepositoryService } from '../metrics/metrics-repository.service';
import type { MetricsAssignment } from '../metrics/metrics.types';
import type { EntityActor } from '../entities/entities.types';
import type { VitalsIdentityPage, VitalsQuery } from './vitals.types';
import { exactKeys, metricsId } from './vitals-query';

/** Below this many identities of a type, point GETs are cheaper than a list. */
export const METRICS_PREFETCH_MIN = 8;
export const METRICS_PREFETCH_PAGES = 3;
export interface MetricsScope { workspaceId: string; mode: 'workspace' | 'cluster'; version: string; wholeCluster: boolean; epochs: MetricsAssignment[]; consumerPairEpochs: MetricsAssignment[]; serviceNames: Map<string, string>; consumerNames: Map<string, string>; }
@Injectable()
export class MetricsScopeService {
  constructor(private readonly authz: AuthorizationService, private readonly workspaces: WorkspaceResolverService,
    private readonly kong: KongService, private readonly execution: KongExecutionContextService, private readonly repository: MetricsRepositoryService) {}
  async workspace(cid: string, actor: EntityActor, workspaceId?: string): Promise<string> {
    metricsId(cid); await this.authz.assertCluster(actor.user, cid, 'monitoring', 'read', workspaceId);
    return (await this.workspaces.resolve(cid, workspaceId)).id;
  }
  async identity(cid: string, type: string, id: string, actor: EntityActor, wid?: string): Promise<any> {
    const value = await this.privateIdentity(cid, type, id, wid);
    await this.authz.assertScopedResource(actor.user, cid, 'monitoring', 'read', type, value, wid); return value;
  }
  private async privateIdentity(cid: string, type: string, id: string, wid?: string): Promise<any> {
    metricsId(id); const path = `/${type}/${id}`;
    const value = await this.execution.runInternalRead(cid, 'inventory', () => this.kong.request(cid, 'GET', path), { paths: [path], workspaceId: wid, maxCalls: 3, maxRecords: 1, maxBytes: 2 * 1024 * 1024, timeoutMs: 5000 });
    return value;
  }
  /** Batched inventory read: one paged list per entity type instead of one
   * GET per epoch. It only pre-populates the same current Kong identities that
   * privateIdentity() would fetch; every membership, tag, label and
   * authorization check in resolve() still runs per entity. Misses (or any
   * list failure / budget overrun) fall back to the per-entity GET. */
  private async prefetchIdentities(cid: string, candidates: MetricsAssignment[], wid?: string): Promise<Map<string, any>> {
    const found = new Map<string, any>(), wanted = new Map<string, Set<string>>();
    const want = (type: string, id: string | null | undefined) => { if (!id) return; if (!wanted.has(type)) wanted.set(type, new Set()); wanted.get(type)!.add(id); };
    for (const epoch of candidates) { want(epoch.entity_type, epoch.entity_id); if (epoch.entity_type === 'routes') want('services', epoch.service_id); }
    for (const [type, ids] of wanted) {
      if (ids.size < METRICS_PREFETCH_MIN || !['services', 'routes', 'consumers'].includes(type)) continue;
      const path = `/${type}`;
      try {
        await this.execution.runInternalRead(cid, 'inventory', async () => {
          let cursor: string | undefined, remaining = ids.size;
          for (let page = 0; page < METRICS_PREFETCH_PAGES && remaining > 0; page++) {
            const result = await this.kong.list(cid, path, { size: 1000 }, cursor, `metrics-prefetch:${type}`);
            for (const row of result.items) if (row?.id && ids.has(row.id) && !found.has(`${type}:${row.id}`)) { found.set(`${type}:${row.id}`, row); remaining--; }
            if (!result.nextCursor) break; cursor = result.nextCursor;
          }
        }, { paths: [path], workspaceId: wid, maxCalls: METRICS_PREFETCH_PAGES, maxPages: METRICS_PREFETCH_PAGES, maxRecords: METRICS_PREFETCH_PAGES * 1000, maxBytes: 16 * 1024 * 1024, timeoutMs: 10000 });
      } catch { /* fall back to per-entity reads for this type */ }
    }
    return found;
  }
  async identities(cid: string, query: Record<string, unknown>, actor: EntityActor): Promise<VitalsIdentityPage> {
    exactKeys(query, ['workspaceId', 'scope', 'type', 'size', 'cursor', 'search']);
    if (!['services', 'routes', 'consumers'].includes(query.type as string)) throw new BadRequestException({ code: 'INVALID_METRICS_ENTITY_TYPE', message: '监控对象仅支持 services/routes/consumers' });
    const type = query.type as string, wid = await this.workspace(cid, actor, metricsId(query.workspaceId, true));
    const mode = await this.mode(cid, query.scope, actor), effectiveWid = mode === 'cluster' ? undefined : wid;
    const size = query.size === undefined ? 20 : Number(query.size);
    if ((query.size !== undefined && typeof query.size !== 'string' && typeof query.size !== 'number') || !Number.isInteger(size) || size < 1 || size > 100 || query.cursor !== undefined && typeof query.cursor !== 'string' || query.search !== undefined && (typeof query.search !== 'string' || query.search.length > 100)) throw new BadRequestException({ code: 'INVALID_METRICS_ENTITY_QUERY', message: '监控对象查询无效' });
    const version = await this.authz.permissionVersion(actor.user), physical = await this.workspaces.listScope(cid, wid);
    const path = `/${type}`, subject = `${actor.user.id}:${version}:${physical.binding}:monitoring:${mode}:${type}:${query.search || ''}`;
    const privateKong = { list: (clusterId: string, listPath: string, params: any, cursor?: string, binding?: string) => this.execution.runInternalRead(cid, 'inventory', () => this.kong.list(clusterId, listPath, params, cursor, binding), { paths: [path], workspaceId: wid, maxCalls: 3, maxPages: 1, maxRecords: size, maxBytes: 2 * 1024 * 1024, timeoutMs: 5000 }) };
    const page = await filteredList(privateKong, cid, path, { size }, query.cursor as string | undefined, subject, async items => {
      const selected = items.filter(row => (mode === 'cluster' || this.workspaces.matches(physical, row)) && (!query.search || String(row.name || row.username || row.custom_id || row.id).toLowerCase().includes(String(query.search).toLowerCase())));
      return this.authz.filterScopedResources(actor.user, cid, 'monitoring', 'read', type, selected, effectiveWid);
    });
    const items = page.items.map(row => ({ id: row.id, name: row.name || row.username || row.custom_id || row.id }));
    await this.stable(actor, version); return { ...page, items };
  }
  async resolve(cid: string, query: VitalsQuery, actor: EntityActor, catalogRevision: number): Promise<MetricsScope> {
    const wid = await this.workspace(cid, actor, query.workspaceId), version = await this.authz.permissionVersion(actor.user), mode = await this.mode(cid, query.scope, actor), effectiveWid = mode === 'cluster' ? undefined : wid;
    let service: any, route: any;
    if (query.serviceId) service = await this.identity(cid, 'services', query.serviceId, actor, effectiveWid);
    if (query.routeId) { route = await this.identity(cid, 'routes', query.routeId, actor, effectiveWid); if (service && route.service?.id !== service.id) throw new ForbiddenException({ code: 'METRICS_ROUTE_SERVICE_MISMATCH', message: 'Route 不属于所选 Service' }); }
    const wholeCluster = await this.authz.hasWholeCluster(actor.user, cid, 'monitoring', 'read');
    const epochResult = await this.repository.currentAllowedEpochs(cid, { expectedCatalogRevision: catalogRevision, workspaceId: effectiveWid, ...(service && !route ? { authorizedServiceIds: [service.id] } : {}), ...(route ? { authorizedRouteIds: [route.id] } : {}), includeConsumerCandidates: true });
    const candidates = epochResult.items;
    if (candidates.length > 256) throw new ConflictException({ code: 'METRICS_SELECTOR_BUDGET_EXHAUSTED', message: '授权指标身份超过 256 项，请按 Service 或 Route 缩小范围' });
    const identities = await this.prefetchIdentities(cid, candidates, effectiveWid), epochs: MetricsAssignment[] = [], serviceNames = new Map<string, string>(), consumerNames = new Map<string, string>(), currentPairs: MetricsAssignment[] = [];
    for (const epoch of candidates) {
      const type = epoch.entity_type, id = epoch.entity_id, key = `${type}:${id}`;
      let actual = identities.get(key);
      if (!actual) {
        actual = await this.privateIdentity(cid, type, id, effectiveWid); identities.set(key, actual);
      }
      const actualMembership = await this.workspaces.classify(cid, actual.tags);
      if (actualMembership.state !== 'resolved' || actualMembership.workspace?.id !== epoch.workspace_id || mode === 'workspace' && actualMembership.workspace.id !== wid) continue;
      // Epochs store business tags; route epochs freeze the union of the
      // parent's and Route's tags. Physical workspace tags are checked above.
      const business = (value: any): string[] => [...new Set<string>((value.tags || []).filter((tag: string) => !tag.startsWith('kos-ws-')))].sort();
      if (type !== 'routes' && JSON.stringify(business(actual)) !== JSON.stringify([...epoch.tags].sort())) continue;
      if (type === 'services' && (actual.name || actual.host) !== epoch.service_label) continue;
      if (type === 'routes') {
        if (actual.service?.id !== epoch.service_id) continue;
        const parentKey = `services:${epoch.service_id}`;
        let parent = identities.get(parentKey);
        if (!parent) { parent = await this.privateIdentity(cid, 'services', epoch.service_id!, effectiveWid); identities.set(parentKey, parent); }
        if ((await this.workspaces.classify(cid, parent.tags)).workspace?.id !== epoch.workspace_id) continue;
        const frozenTags = [...new Set([...business(actual), ...business(parent)])].sort();
        if (JSON.stringify(frozenTags) !== JSON.stringify([...epoch.tags].sort()) || (parent.name || parent.host) !== epoch.service_label || (actual.name || actual.id) !== epoch.route_label) continue;
        currentPairs.push(epoch);
        try { await this.authz.assertScopedResource(actor.user, cid, 'monitoring', 'read', 'routes', actual, effectiveWid); }
        catch (error) {
          if (!(error instanceof ForbiddenException)) throw error;
          // A Service's own aggregate includes verified current child traffic;
          // it grants no Route selector or configuration permission.
          try { await this.authz.assertScopedResource(actor.user, cid, 'monitoring', 'read', 'services', parent, effectiveWid); }
          catch (parentError) { if (parentError instanceof ForbiddenException) continue; throw parentError; }
        }
      } else {
        try { await this.authz.assertScopedResource(actor.user, cid, 'monitoring', 'read', type, actual, effectiveWid); }
        catch (error) { if (error instanceof ForbiddenException) continue; throw error; }
      }
      // The repository freezes history; authorization is always current identity.
      if (type === 'services') serviceNames.set(id, actual.name || id);
      if (type === 'routes' && epoch.service_id) {
        const serviceKey = `services:${epoch.service_id}`;
        if (!serviceNames.has(epoch.service_id)) {
          // Only use a minimal display name. A route-only monitoring grant need
          // not disclose or independently authorize its parent configuration.
          serviceNames.set(epoch.service_id, identities.get(serviceKey)?.name || epoch.service_id);
        }
      }
      if (type === 'consumers') consumerNames.set(id, actual.username || actual.custom_id || id);
      epochs.push(epoch);
    }
    const consumerWorkspaces = new Set(epochs.filter(epoch => epoch.entity_type === 'consumers').map(epoch => epoch.workspace_id));
    const consumerPairEpochs = currentPairs.filter(epoch => consumerWorkspaces.has(epoch.workspace_id));
    await this.stable(actor, version); return { workspaceId: wid, mode, version, wholeCluster, epochs, consumerPairEpochs, serviceNames, consumerNames };
  }
  private async mode(cid: string, value: unknown, actor: EntityActor): Promise<'workspace' | 'cluster'> {
    if (value === undefined || value === 'workspace') return 'workspace';
    if (value !== 'cluster') throw new BadRequestException({ code: 'INVALID_METRICS_SCOPE', message: '监控范围须为 workspace 或 cluster' });
    if (!await this.authz.hasWholeCluster(actor.user, cid, 'monitoring', 'read')) throw new ForbiddenException({ code: 'METRICS_CLUSTER_SCOPE_DENIED', message: '集群监控需要覆盖整个集群的权限' });
    return 'cluster';
  }
  async stable(actor: EntityActor, version: string): Promise<void> {
    if (await this.authz.permissionVersion(actor.user) !== version) throw new ForbiddenException({ code: 'PERMISSIONS_CHANGED', message: '监控查询期间授权发生变化，请重新加载' });
  }
}
