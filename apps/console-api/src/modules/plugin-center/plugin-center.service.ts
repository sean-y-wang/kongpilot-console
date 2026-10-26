import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { filteredList } from '../../infrastructure/kong/filtered-list';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { KongActorScope } from '../../infrastructure/kong/actor-scope';
import { kong15ProtocolMatches, kong15ExternalPluginEligible } from '../../infrastructure/kong/plugin-applicability';
import { WorkspaceResolverService, WorkspaceFilter } from '../workspaces/workspace-resolver.service';
import { workspaceIndexWhere } from '../workspaces/workspace-index-scope';
import { SecretService } from '../../infrastructure/secret.service';
import { encodeTag, decodeTag } from '../../infrastructure/kong/tags';
import { stripSensitiveSchemaDefaults } from '../../infrastructure/kong/schema-secrets';
import { AuthorizationService } from '../authorization/authorization.service';
import { EntityService } from '../entities/entities.service';
import { EntityActor, identifier, objectBody, pageSize } from '../entities/entities.types';
import { augmentFormSchema, BINDING_SCOPES, BindingScope, bindingScope, executionPriority, pluginMetadata, pluginRules, PRECEDENCE } from './plugin-metadata';

export type PluginQuery = { size?: string | number; cursor?: string; name?: string; binding_scope?: string; serviceId?: string; routeId?: string; consumerId?: string; tags?: string; workspaceId?: string; protocol?: string };
const READ_PAGE_BUDGET = 5;

@Injectable()
export class PluginCenterService {
  constructor(private readonly db: DbService, private readonly kong: KongService, private readonly authz: AuthorizationService, private readonly secrets: SecretService, private readonly entities: EntityService, private readonly workspaces: WorkspaceResolverService, private readonly execution: KongExecutionContextService) {}

  private async scoped(clusterId: string, actor: EntityActor, workspaceId = actor.workspaceId, action = 'read'): Promise<EntityActor> {
    await this.authz.assertCluster(actor.user, clusterId, 'plugins', action, workspaceId);
    const workspace = await this.workspaces.resolve(clusterId, workspaceId);
    return { ...actor, workspaceId: workspace.id };
  }
  private async scope(clusterId: string, actor: EntityActor, tags?: string): Promise<WorkspaceFilter> {
    return this.workspaces.listScope(clusterId, actor.workspaceId, await this.authz.scopeTags(actor.user, clusterId, actor.workspaceId, tags, 'plugins'));
  }
  private display(plugin: any): any { const value = this.secrets.redact(plugin); if (Array.isArray(value.tags)) value.tags = value.tags.map(decodeTag); return value; }
  private name(value: unknown): string { if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(value)) throw new BadRequestException({ code: 'INVALID_PLUGIN_NAME', message: '插件名称无效' }); return value; }
  private query(query: PluginQuery, allowed: string[]): void {
    for (const [name, value] of Object.entries(query)) if (!allowed.includes(name) || typeof value !== 'string' && !(name === 'size' && typeof value === 'number')) throw new BadRequestException({ code: 'INVALID_PLUGIN_QUERY', message: '插件查询包含无效参数' });
    if (query.binding_scope && !(BINDING_SCOPES as readonly string[]).includes(query.binding_scope)) throw new BadRequestException({ code: 'INVALID_BINDING_SCOPE', message: '插件绑定范围无效' });
    if (query.name) this.name(query.name);
    if (query.workspaceId && query.workspaceId.length > 128) throw new BadRequestException('工作区标识过长');
    if (query.protocol && !['http', 'https', 'grpc', 'grpcs', 'tcp', 'tls'].includes(query.protocol)) throw new BadRequestException('协议无效');
  }
  private encodeTags(tags?: string): string | undefined {
    if (!tags) return undefined;
    if (tags.length > 2048 || tags.includes('/') && tags.includes(',')) throw new BadRequestException({ code: 'INVALID_TAG_EXPRESSION', message: '标签过滤过长或混合 AND/OR' });
    const separator = tags.includes('/') ? '/' : ',';
    return tags.split(separator).map(tag => encodeTag(tag.trim())).join(separator);
  }
  private async bindings(clusterId: string, query: PluginQuery, actor: EntityActor, deriveService = false): Promise<Record<string, string>> {
    const result: Record<string, string> = {};
    for (const [field, kind] of Object.entries({ serviceId: 'services', routeId: 'routes', consumerId: 'consumers' })) if (query[field as keyof PluginQuery]) {
      await this.authz.assertCluster(actor.user, clusterId, kind, 'read', actor.workspaceId);
      const entity = await this.kong.request(clusterId, 'GET', `/${kind}/${identifier(query[field as keyof PluginQuery] as string)}`);
      this.workspaces.assertMembership(await this.workspaces.listScope(clusterId, actor.workspaceId), entity);
      await this.authz.assertEntity(actor.user, clusterId, kind, 'read', entity, actor.workspaceId);
      result[field] = entity.id;
      if (field === 'routeId' && deriveService && entity.service?.id) {
        if (result.serviceId && result.serviceId !== entity.service.id) throw new BadRequestException({ code: 'ROUTE_SERVICE_MISMATCH', message: '所选 Route 不属于所选 Service' });
        if (!result.serviceId) {
          const service = await this.kong.request(clusterId, 'GET', `/services/${identifier(entity.service.id)}`);
          this.workspaces.assertMembership(await this.workspaces.listScope(clusterId, actor.workspaceId), service);
          await this.authz.assertEntity(actor.user, clusterId, 'services', 'read', service, actor.workspaceId);
          result.serviceId = service.id;
        }
      }
    }
    return result;
  }

  @KongActorScope({ module: 'plugins', queryArg: 1 })
  async catalog(clusterId: string, query: PluginQuery, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, query.workspaceId);
    this.query(query, ['workspaceId', 'tags']);
    await this.authz.assertCluster(actor.user, clusterId, 'plugins', 'read', actor.workspaceId);
    const permissionVersion = await this.authz.permissionVersion(actor.user);
    const cluster = await this.db.one<any>('SELECT enabled_plugins,last_probed_at,version FROM clusters WHERE id=$1 AND deleted_at IS NULL', [clusterId]);
    const scope = await this.scope(clusterId, actor, this.encodeTags(query.tags));
    const state = await this.db.one<any>("SELECT completed_at,last_run_at,last_error FROM index_sync_state WHERE cluster_id=$1 AND entity_type='plugins'", [clusterId]);
    // Baseline authorization is super-admin only. Scope-aware M4 grants must never
    // inherit unrestricted inventory counts through this endpoint.
    const visibleCounts = await this.authz.isPlatformAdmin(actor.user) && !!state?.completed_at;
    const params: unknown[] = [clusterId], where = workspaceIndexWhere(scope, params);
    const rows = visibleCounts ? await this.db.query<any>(`SELECT name,
      CASE WHEN document->'consumer'->>'id' IS NOT NULL THEN
        CASE WHEN document->'route'->>'id' IS NOT NULL THEN CASE WHEN document->'service'->>'id' IS NOT NULL THEN 'consumer-route-service' ELSE 'consumer-route' END
        ELSE CASE WHEN document->'service'->>'id' IS NOT NULL THEN 'consumer-service' ELSE 'consumer' END END
      ELSE CASE WHEN document->'route'->>'id' IS NOT NULL THEN CASE WHEN document->'service'->>'id' IS NOT NULL THEN 'route-service' ELSE 'route' END
        ELSE CASE WHEN document->'service'->>'id' IS NOT NULL THEN 'service' ELSE 'global' END END END AS scope,
      count(*)::int AS total,count(*) FILTER (WHERE document->>'enabled'='true')::int AS enabled
      FROM entity_index WHERE cluster_id=$1 AND entity_type='plugins'
      AND ${where.join(' AND ')}
      GROUP BY name,scope`, params) : [];
    const names = [...new Set<string>((cluster?.enabled_plugins || []).filter((name: unknown) => typeof name === 'string'))].sort();
    const items = names.map(name => {
      const matching = rows.filter(row => row.name === name);
      const by_scope = Object.fromEntries(BINDING_SCOPES.map(scope => [scope, { total: matching.find(row => row.scope === scope)?.total || 0, enabled: matching.find(row => row.scope === scope)?.enabled || 0 }]));
      return { ...pluginMetadata(name), counts: visibleCounts ? { total: matching.reduce((sum, row) => sum + row.total, 0), enabled: matching.reduce((sum, row) => sum + row.enabled, 0), by_scope } : null };
    });
    if (await this.authz.permissionVersion(actor.user) !== permissionVersion) throw new ForbiddenException({ code: 'PERMISSIONS_CHANGED', message: '权限在统计查询期间发生变化，请重新加载' });
    return { items, observed_at: state?.completed_at ?? null, sync_error: state?.last_error ?? null, counts_source: 'console_index', counts_visibility: visibleCounts ? 'authorized_inventory' : 'unavailable', workspace_id: actor.workspaceId, scope_notice: '工作区标签只隔离管理视图；全局插件在整个集群运行', discovered_at: cluster?.last_probed_at ?? null, kong_version: cluster?.version ?? null };
  }

  @KongActorScope({ module: 'plugins' })
  async schema(clusterId: string, name: string, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId);
    await this.authz.assertCluster(actor.user, clusterId, 'plugins', 'read', actor.workspaceId);
    this.name(name);
    const wire_schema = stripSensitiveSchemaDefaults(await this.kong.pluginSchema(clusterId, name), this.secrets);
    return { wire_schema, form_schema: augmentFormSchema(name, wire_schema), metadata: pluginMetadata(name), rules: pluginRules(name), remote_authoritative: true };
  }

  @KongActorScope({ module: 'plugins', queryArg: 1 })
  async instances(clusterId: string, query: PluginQuery, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, query.workspaceId);
    this.query(query, ['size', 'cursor', 'name', 'binding_scope', 'serviceId', 'routeId', 'consumerId', 'tags', 'workspaceId']);
    await this.authz.assertCluster(actor.user, clusterId, 'plugins', 'read', actor.workspaceId);
    const bindings = await this.bindings(clusterId, query, actor);
    const scope = await this.scope(clusterId, actor, this.encodeTags(query.tags));
    const size = pageSize(query.size), params = { size, ...(scope.nativeTags ? { tags: scope.nativeTags } : {}) };
    const filter = { name: query.name || null, scope: query.binding_scope || null, ...bindings, workspace: scope.binding };
    const subject = `${actor.user.id}:${await this.authz.permissionVersion(actor.user)}:plugins:${createHash('sha256').update(JSON.stringify(filter)).digest('hex')}`;
    const result = await filteredList(this.kong, clusterId, '/plugins', params, query.cursor, subject, async items => {
      const matches = items.filter(plugin => this.workspaces.matches(scope, plugin) && (!query.name || plugin.name === query.name) && (!query.binding_scope || bindingScope(plugin) === query.binding_scope) && (!bindings.serviceId || plugin.service?.id === bindings.serviceId) && (!bindings.routeId || plugin.route?.id === bindings.routeId) && (!bindings.consumerId || plugin.consumer?.id === bindings.consumerId));
      return this.authz.filterEntities(actor.user, clusterId, 'plugins', matches, actor.workspaceId);
    }, READ_PAGE_BUDGET);
    return { ...result, workspace_id: actor.workspaceId, items: result.items.map(plugin => ({ ...this.display(plugin), binding_scope: bindingScope(plugin), ...(bindingScope(plugin) === 'global' ? { console_scope_notice: '标签只隔离管理视图；全局插件影响整个集群' } : {}) })) };
  }

  @KongActorScope({ module: 'plugins' })
  async precedence(clusterId: string, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId);
    await this.authz.assertCluster(actor.user, clusterId, 'plugins', 'read', actor.workspaceId);
    const cluster = await this.db.one<any>('SELECT enabled_plugins FROM clusters WHERE id=$1 AND deleted_at IS NULL', [clusterId]);
    const execution_order = (cluster?.enabled_plugins || []).map((name: string) => pluginMetadata(name)).sort((a: any, b: any) => (executionPriority(b.name) ?? -Infinity) - (executionPriority(a.name) ?? -Infinity) || a.name.localeCompare(b.name));
    return { levels: PRECEDENCE, disabled_fallback: true, execution_order, notes: ['绑定优先级用于选择同名插件的一个启用配置；禁用的高优先级实例会回退到下一层。', '不同插件按 handler.PRIORITY 从高到低执行；认证后 Consumer 信息可能改变后续阶段的配置选择。', '自定义插件的执行优先级无法从 Kong Admin API 得知，返回 null。'] };
  }

  @KongActorScope({ module: 'plugins', queryArg: 1 })
  async context(clusterId: string, query: PluginQuery, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, query.workspaceId);
    this.query(query, ['serviceId', 'routeId', 'consumerId', 'name', 'protocol', 'workspaceId', 'tags']);
    await this.authz.assertCluster(actor.user, clusterId, 'plugins', 'read', actor.workspaceId);
    const bindings = await this.bindings(clusterId, query, actor, true);
    const scope = await this.scope(clusterId, actor, this.encodeTags(query.tags));
    let cursor: string | undefined, complete = false, excludedApplicable = false, permissionProjection = false;
    const candidates: any[] = [];
    const subject = `${actor.user.id}:${await this.authz.permissionVersion(actor.user)}:plugin-context:${createHash('sha256').update(JSON.stringify({ ...bindings, scope: scope.binding, name: query.name, protocol: query.protocol })).digest('hex')}`;
    for (let page = 0; page < READ_PAGE_BUDGET; page++) {
      const result = await this.kong.list(clusterId, '/plugins', { size: 100, ...(scope.nativeTags ? { tags: scope.nativeTags } : {}) }, cursor, subject);
      const managed = result.items.filter(plugin => this.workspaces.matches(scope, plugin));
      const visible = await this.authz.filterEntities(actor.user, clusterId, 'plugins', managed, actor.workspaceId);
      permissionProjection ||= !!(result as any).console_permission_projection || visible.length !== managed.length;
      // Inspect only a boolean internally. Names/configuration from excluded
      // scopes must never be returned just to explain an incomplete chain.
      excludedApplicable ||= result.items.some(plugin => !this.workspaces.matches(scope, plugin) && kong15ExternalPluginEligible(plugin) && (!query.protocol || kong15ProtocolMatches(plugin.protocols,query.protocol)) && (!query.name || plugin.name === query.name) && (!plugin.service?.id || plugin.service.id === bindings.serviceId) && (!plugin.route?.id || plugin.route.id === bindings.routeId) && (!plugin.consumer?.id || plugin.consumer.id === bindings.consumerId));
      for (const plugin of visible) {
        if (query.name && query.name !== plugin.name) continue;
        const matches = (!plugin.service?.id || plugin.service.id === bindings.serviceId) && (!plugin.route?.id || plugin.route.id === bindings.routeId) && (!plugin.consumer?.id || plugin.consumer.id === bindings.consumerId);
        if (!matches) continue;
        const scope = bindingScope(plugin), protocolMatches = !query.protocol || kong15ProtocolMatches(plugin.protocols,query.protocol), applicable = kong15ExternalPluginEligible(plugin) && protocolMatches;
        candidates.push({ name: plugin.name, entity: this.display(plugin), scope, rank: BINDING_SCOPES.indexOf(scope) + 1, applicable, selected: false, reason: !protocolMatches ? '网关子系统不匹配' : plugin.enabled === false ? '已禁用，继续回退到下层' : !kong15ExternalPluginEligible(plugin) ? '当前配置不参与普通代理请求' : '候选配置' });
      }
      if (!result.nextCursor) { complete = true; break; }
      cursor = result.nextCursor;
    }
    // Do not claim a gateway execution chain from an incomplete inventory or a
    // restricted actor's projection. Both could hide a higher-precedence config.
    complete = complete && await this.authz.isPlatformAdmin(actor.user) && scope.mode === 'default' && !scope.nativeTags && !excludedApplicable && !permissionProjection;
    candidates.sort((a, b) => a.name.localeCompare(b.name) || a.rank - b.rank);
    const selected: any[] = [];
    if (complete) for (const candidate of candidates) {
      if (candidate.applicable && !selected.some(plugin => plugin.name === candidate.name)) {
        candidate.selected = true; candidate.reason = '同名插件的最高优先级启用配置';
        const metadata = pluginMetadata(candidate.name);
        selected.push({ name: candidate.name, entity: candidate.entity, scope: candidate.scope, priority: metadata.priority, ...(metadata.priority_label ? { priority_label: metadata.priority_label } : {}) });
      } else if (candidate.applicable) candidate.reason = '被更高优先级的同名配置覆盖';
    }
    const execution_chain = [...selected].sort((a, b) => (executionPriority(b.name) ?? -Infinity) - (executionPriority(a.name) ?? -Infinity) || a.name.localeCompare(b.name));
    const unknown = selected.some(plugin => executionPriority(plugin.name) === null);
    return { context: { workspace_id: actor.workspaceId, ...bindings, protocol: query.protocol || null }, complete, candidates, selected, execution_chain, scan_budget: { pages: READ_PAGE_BUDGET, page_size: 100 }, warnings: [...(!complete ? ['当前工作区只表示管理范围；其他工作区的全局插件仍可能执行，不能确认完整真实执行链。'] : []), ...(unknown ? ['存在自定义插件，执行优先级未知。'] : []), '这是基于配置的选择诊断；Kong 按 HTTP 或 stream 子系统筛选插件，实际执行还受运行阶段及认证结果影响。'] };
  }

  @KongActorScope({ module: 'plugins', action: 'write' })
  async toggle(clusterId: string, id: string, body: unknown, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId, 'write');
    const input = objectBody(body);
    if (Object.keys(input).length !== 1 || typeof input.enabled !== 'boolean') throw new BadRequestException({ code: 'INVALID_PLUGIN_TOGGLE', message: '启停操作仅接受 enabled 布尔值' });
    return this.entities.update(clusterId, 'plugins', id, input, { workspaceId: actor.workspaceId }, actor);
  }
}
