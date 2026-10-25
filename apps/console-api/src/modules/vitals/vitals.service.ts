import { BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable, NotFoundException, Optional, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { KongActorScope } from '../../infrastructure/kong/actor-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { IamMutationsService } from '../iam/iam-mutations.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { EntityService } from '../entities/entities.service';
import type { EntityActor } from '../entities/entities.types';
import { MetricsSettingsService } from '../metrics/metrics-settings.service';
import { MetricsCredentialsService } from '../metrics/metrics-credentials.service';
import { MetricsRepositoryService } from '../metrics/metrics-repository.service';
import { MetricsScopeService } from './metrics-scope.service';
import { MetricsSourceService } from './providers/metrics-source.service';
import { PrometheusProvider, nullSeries } from './providers/prometheus.provider';
import { LokiProvider } from './providers/loki.provider';
import { lokiEvaluationWindow } from './providers/loki-window';
import { MetricsQueryBudget } from './providers/query-budget';
import { exactKeys, metricsId, parseVitalsQuery } from './vitals-query';
import type { VitalsCapabilities, VitalsMetric, VitalsOverview, VitalsQuery, VitalsSeriesKey } from './vitals.types';

@Injectable()
export class VitalsService {
  constructor(private readonly scope: MetricsScopeService, private readonly sources: MetricsSourceService, private readonly settings: MetricsSettingsService,
    private readonly authz: AuthorizationService, private readonly db: DbService, private readonly repository: MetricsRepositoryService,
    private readonly kong: KongService, private readonly execution: KongExecutionContextService, private readonly entitiesService: EntityService,
    private readonly workspaces: WorkspaceResolverService, private readonly credentials: MetricsCredentialsService, private readonly metadata: IamMutationsService, @Optional() private readonly secrets?: SecretService) {}
  private async cluster(cid: string): Promise<any> {
    metricsId(cid); const row = await this.db.one<any>('SELECT id,name,version,enabled_plugins,status,execution_mode,revision FROM clusters WHERE id=$1 AND deleted_at IS NULL', [cid]);
    if (!row || row.status === 'disabled') throw new NotFoundException({ code: 'CLUSTER_NOT_FOUND', message: '集群不存在或已停用' }); return row;
  }
  @KongActorScope({ module: 'monitoring', queryArg: 1 })
  async capabilities(cid: string, query: VitalsQuery, actor: EntityActor): Promise<VitalsCapabilities> {
    exactKeys(query, ['workspaceId', 'scope', 'sourceId']); metricsId(query.sourceId, true);
    const wid = await this.scope.workspace(cid, actor, metricsId(query.workspaceId, true)), version = await this.authz.permissionVersion(actor.user);
    if (query.scope !== undefined && !['workspace', 'cluster'].includes(query.scope as string)) throw new BadRequestException({ code: 'INVALID_METRICS_SCOPE' });
    const whole = await this.authz.hasWholeCluster(actor.user, cid, 'monitoring', 'read');
    if (query.scope === 'cluster' && !whole) throw new ForbiddenException({ code: 'METRICS_CLUSTER_SCOPE_DENIED' });
    const cluster = await this.cluster(cid), settings = await this.settings.get(cid), sources = await this.sources.list(cid);
    const selected = metricsId(query.sourceId, true) || settings.activeSourceId;
    const connection = selected ? await this.sources.read(cid, selected) : null, source = connection ? this.sources.public(connection) : null;
    const available = settings.enabled && this.fresh(settings) && !!source, native = available && source?.type === 'prometheus', collector = settings.collectorEnabled && settings.credentialGeneration > 0;
    const result: VitalsCapabilities = {
      clusterId: cid, workspaceId: wid, scope: query.scope === 'cluster' ? 'cluster' : 'workspace', source, sources, nativeVersion: cluster.version, pluginVersion: '0.6.0', provider: source?.type || null,
      configured: settings.enabled, collectorEnabled: collector, catalogRevision: settings.catalogRevision, credentialGeneration: settings.credentialGeneration,
      permissions: { setup: await this.authz.isPlatformAdmin(actor.user), nodeMetrics: whole, clusterMetrics: whole },
      capabilities: { qps: available, statusCodes: available, latency: available, bandwidth: available, serviceTopN: available, consumerTopN: available && collector, nodes: !!native && whole, routeDrilldown: available },
      limitations: ['Kong 1.5 prometheus 0.6 没有 Consumer 或工作区原生标签；归属由抓取时验证的当前 epoch 提供', '当前 epoch 的首个 counter 样本只作基线；重命名、标签和工作区变更形成历史缺口', '未命中 Service 的请求（包括部分路由前 404）不计入原生请求指标', '节点表示已登记 Admin 端点实际观察到的节点，不能发现负载均衡地址后的完整拓扑', '直连 Admin API 可绕过软隔离，Kong 1.5 缺少配置 CAS'],
      setupModes: ['native_prometheus', 'collector'], executionMode: cluster.execution_mode,
    };
    if (connection) await this.sources.assertCurrent(cid, connection);
    const final = await this.settings.get(cid);
    if (final.revision !== settings.revision || final.credentialGeneration !== settings.credentialGeneration || final.catalogRevision !== settings.catalogRevision || final.state !== settings.state || available && !this.fresh(final)) throw new ConflictException({ code: 'METRICS_SETTINGS_CHANGED' });
    await this.scope.stable(actor, version); return result;
  }
  @KongActorScope({ module: 'monitoring', queryArg: 1 })
  async entities(cid: string, query: Record<string, unknown>, actor: EntityActor) { return this.scope.identities(cid, query, actor); }
  @KongActorScope({ module: 'monitoring', queryArg: 1 })
  async overview(cid: string, query: VitalsQuery, actor: EntityActor): Promise<VitalsOverview> {
    const requestedWindow = parseVitalsQuery(query), cluster = await this.cluster(cid), initial = await this.settings.get(cid);
    const resolved = await this.scope.resolve(cid, query, actor, initial.catalogRevision), sourceId = query.sourceId || initial.activeSourceId;
    const source = sourceId ? await this.sources.read(cid, sourceId) : null, budget = new MetricsQueryBudget();
    const window = source?.type === 'loki' ? lokiEvaluationWindow(requestedWindow) : requestedWindow;
    const gridAligned = window.start !== requestedWindow.start || window.end !== requestedWindow.end;
    let data = { series: nullSeries(window), topN: { services: [] as Array<{ id: string; name: string; value: number }>, consumers: [] as Array<{ id: string; name: string; value: number }> }, nodes: [] as VitalsOverview['nodes'], reasonCodes: [] as string[] };
    if (!source) data.reasonCodes.push('METRICS_SOURCE_NOT_CONFIGURED');
    else if (!initial.enabled || !this.fresh(initial)) data.reasonCodes.push('METRICS_CATALOG_UNAVAILABLE');
    else {
      try { data = await (source.type === 'loki' ? new LokiProvider() : new PrometheusProvider()).evaluate(source, cid, resolved, window, budget, initial.collectorEnabled); }
      catch (error) { if (!(error instanceof HttpException) || error.getStatus() < 500) throw error; data.reasonCodes.push('METRICS_SOURCE_QUERY_FAILED'); }
    }
    if (gridAligned) data.reasonCodes.push('LOKI_EVALUATION_GRID_ALIGNED');
    await this.scope.stable(actor, resolved.version);
    if (source) await this.sources.assertCurrent(cid, source);
    const final = await this.settings.get(cid);
    if (final.revision !== initial.revision || final.credentialGeneration !== initial.credentialGeneration || final.state !== initial.state) throw new ConflictException({ code: 'METRICS_SETTINGS_CHANGED', message: '查询期间监控设置或归属状态变化' });
    // A durable parent can become uncertain before a fence advances revision.
    // Recheck blocked state and current epochs after every provider await.
    {
      const current = await this.repository.currentAllowedEpochs(cid, { workspaceId: resolved.mode === 'workspace' ? resolved.workspaceId : undefined,
        authorizedServiceIds: [...new Set(resolved.epochs.filter(row => row.entity_type === 'services').map(row => row.entity_id))],
        authorizedRouteIds: [...new Set([...resolved.epochs, ...resolved.consumerPairEpochs].filter(row => row.entity_type === 'routes').map(row => row.entity_id))],
        authorizedConsumerIds: [...new Set(resolved.epochs.filter(row => row.entity_type === 'consumers').map(row => row.entity_id))] });
      const ids = new Set(current.items.map(row => row.epoch_id));
      if (current.blocked || [...resolved.epochs, ...resolved.consumerPairEpochs].some(row => !ids.has(row.epoch_id))) throw new ConflictException({ code: 'METRICS_CATALOG_CHANGED', message: '查询期间指标归属 epoch 变化' });
    }
    if (initial.state === 'ready' && !this.fresh(final)) throw new ConflictException({ code: 'METRICS_CATALOG_STALE', message: '查询期间指标归属证明过期' });
    if ((await this.cluster(cid)).revision !== cluster.revision) throw new ConflictException({ code: 'METRICS_CLUSTER_CHANGED' });
    const unavailable = data.reasonCodes.some(code => ['METRICS_SOURCE_QUERY_FAILED', 'METRICS_SOURCE_NOT_CONFIGURED', 'METRICS_CATALOG_UNAVAILABLE'].includes(code));
    const latest = (key: VitalsSeriesKey): VitalsMetric => { const value = data.series[key].at(-1)?.value ?? null; return { value, availability: value !== null ? 'available' : unavailable ? 'unavailable' : 'insufficient_samples', ...(value === null && unavailable ? { reasonCode: data.reasonCodes[0] } : {}) }; };
    const measuredNodes = data.nodes.length > 0 && data.nodes.every(node => node.online !== null);
    const onlineNodes: VitalsMetric = { value: measuredNodes ? data.nodes.reduce((sum, node) => sum + node.online!, 0) : null, availability: measuredNodes ? 'available' : !resolved.wholeCluster ? 'unsupported' : data.nodes.length ? 'insufficient_samples' : 'unavailable' };
    const result: VitalsOverview = { clusterId: cid, workspaceId: resolved.workspaceId, scope: resolved.mode, source: source ? this.sources.public(source) : null, evaluationAt: window.end, timeWindow: window,
      ...(gridAligned ? { requestedWindow } : {}),
      cards: { qps: latest('qps'), p50: latest('latencyRequestP50'), p95: latest('latencyRequestP95'), p99: latest('latencyRequestP99'), ingressBytesPerSecond: latest('bandwidthIngress'), egressBytesPerSecond: latest('bandwidthEgress'), onlineNodes },
      series: data.series, topN: data.topN, nodes: data.nodes, units: { throughput: 'requests/second', latency: 'milliseconds', bandwidth: 'bytes/second' },
      availability: { qps: latest('qps').availability, latency: latest('latencyRequestP95').availability, bandwidth: latest('bandwidthIngress').availability, consumerTopN: initial.collectorEnabled ? unavailable ? 'unavailable' : data.topN.consumers.length ? 'available' : 'insufficient_samples' : 'unsupported', nodes: onlineNodes.availability },
      quality: { complete: !data.reasonCodes.includes('METRICS_SOURCE_QUERY_FAILED') && initial.state === 'ready', reasonCodes: data.reasonCodes, catalogRevision: final.catalogRevision, historicalScope: 'current_epoch', sourceMetricVersion: source?.type === 'loki' ? 'console-sanitized-http-log-v1' : 'kong-prometheus-0.6.0', gaps: ['当前 epoch 尚未建立足够 counter 样本或发生归属变更时显示空值', 'Service TopN 只汇总当前获授权的服务或路由请求子集'] },
    };
    await this.scope.stable(actor, resolved.version); budget.publicResponse(result); return result;
  }
  private fresh(settings: { state: string; lastVerifiedAt: string | null; maxAgeMs: number }): boolean { const verified = Date.parse(settings.lastVerifiedAt || ''); return settings.state === 'ready' && Number.isFinite(verified) && Date.now() - verified >= 0 && Date.now() - verified <= settings.maxAgeMs; }
  @KongActorScope({ module: 'monitoring', action: 'write', queryArg: 1 })
  async setup(cid: string, query: Record<string, unknown>, body: unknown, actor: EntityActor): Promise<any> {
    exactKeys(query, ['workspaceId']); exactKeys(body, ['sourceId', 'mode', 'confirmed', 'confirm_name']);
    const workspaceId = metricsId(query.workspaceId, true); await this.authz.assertCluster(actor.user, cid, 'monitoring', 'write', workspaceId);
    if (!await this.authz.isPlatformAdmin(actor.user)) throw new ForbiddenException({ code: 'METRICS_SETUP_PLATFORM_PERMISSION_REQUIRED' });
    const cluster = await this.cluster(cid);
    if (body.confirmed !== true || body.confirm_name !== cluster.name) throw new BadRequestException({ code: 'CONFIRMATION_REQUIRED', message: '请二次确认集群名称；启用全局监控会影响全部工作区' });
    if (!['native_prometheus', 'collector'].includes(body.mode as string) || !actor.idempotencyKey) throw new BadRequestException({ code: 'INVALID_METRICS_SETUP' });
    if (cluster.execution_mode === 'approval') throw new ConflictException({ code: 'APPROVAL_REQUIRED', message: '此集群配置须工单审批，未直接创建监控插件' });
    if (!/^1\.5\.\d+$/.test(cluster.version || '') || !cluster.enabled_plugins?.includes('prometheus')) throw new ConflictException({ code: 'KONG_METRICS_UNAVAILABLE' });
    const source = await this.sources.read(cid, metricsId(body.sourceId)!); if (source.type !== 'prometheus') throw new BadRequestException({ code: 'METRICS_SETUP_REQUIRES_PROMETHEUS' });
    const initial = await this.settings.get(cid), defaultWorkspace = await this.workspaces.resolve(cid), anchor = await this.workspaces.resolve(cid, workspaceId);
    const permissionVersion = await this.authz.permissionVersion(actor.user);
    const stepActor = (name: string, wid: string): EntityActor => ({ ...actor, workspaceId: wid, idempotencyKey: this.stepKey(actor.idempotencyKey!, name) });
    const parentPayload = { workspaceAnchorId: anchor.id, sourceId: source.id, mode: body.mode, sourceRevision: source.revision, credentialGeneration: initial.credentialGeneration };
    const settingsContext = { actor: stepActor('settings', anchor.id), module: 'monitoring', action: 'write', cluster_id: cid, workspace_id: anchor.id, payload: parentPayload };
    const replay = await this.metadata.completed<any>(settingsContext);
    if (replay) {
      await this.sources.assertCurrent(cid, source);
      if ((await this.settings.get(cid)).credentialGeneration !== initial.credentialGeneration) throw new ConflictException({ code: 'METRICS_GENERATION_CHANGED', message: '监控回执读取期间采集凭证已轮换' });
      await this.authz.assertCluster(actor.user, cid, 'monitoring', 'write', anchor.id);
      if (!await this.authz.isPlatformAdmin(actor.user)) throw new ForbiddenException();
      await this.scope.stable(actor, permissionVersion); return replay.result;
    }
    // Persist the caller's original workspace before the first remote packet.
    // The marker is a normal audited console-only IAM ledger entry, never a
    // native capability or a claim that provisioning has completed.
    await this.metadata.execute({ ...settingsContext, actor: stepActor('parent', anchor.id) }, async () => parentPayload);
    try {
    const result = await this.execution.runManagedMetricsProvision(cid, async () => {
      const ensure = async (name: string, config: any): Promise<string> => {
        const previous = await this.nativeStep(cid, actor, name);
        if (previous) {
          if (previous.state !== 'succeeded' || previous.remote_completed !== true || !previous.entity_id) throw new ConflictException({ code: 'METRICS_SETUP_STEP_NOT_TERMINAL', message: '原监控步骤尚未核验，不会自动重发', operationId: previous.id, state: previous.state });
          const path = `/plugins/${metricsId(previous.entity_id)}`;
          const current = await this.execution.runInternalRead(cid, 'entity-preflight', () => this.kong.request(cid, 'GET', path), { paths: [path], workspaceId: previous.workspace_id, maxCalls: 3, maxRecords: 1, timeoutMs: 5000 });
          const currentWorkspace = await this.workspaces.classify(cid, current.tags);
          if (currentWorkspace.state !== 'resolved' || currentWorkspace.workspace?.id !== previous.workspace_id || current.name !== name || !current.enabled || current.service?.id || current.route?.id || current.consumer?.id || !this.configMatches(current.config, config)) throw new ConflictException({ code: 'METRICS_SETUP_STEP_DRIFTED', message: '已完成步骤的当前配置或归属已变化，请核验原回执', operationId: previous.id, state: previous.state });
          await this.authz.assertEntity(actor.user, cid, 'plugins', 'read', current, previous.workspace_id);
          if (!await this.authz.isPlatformAdmin(actor.user)) throw new ForbiddenException(); return current.id;
        }
        const existing = await this.globalPlugin(cid, name), workspace = existing ? await this.workspaces.classify(cid, existing.tags) : null;
        if (existing && (workspace?.state !== 'resolved' || !workspace.workspace)) throw new ConflictException({ code: 'METRICS_PLUGIN_QUARANTINED' });
        const wid = existing ? workspace!.workspace!.id : defaultWorkspace.id;
        const changed = existing ? await this.entitiesService.update(cid, 'plugins', existing.id, { enabled: true, config }, { workspaceId: wid }, stepActor(name, wid)) : await this.entitiesService.create(cid, 'plugins', { name, enabled: true, config }, { workspaceId: wid }, stepActor(name, wid));
        return changed.entity.id;
      };
      const pluginId = await ensure('prometheus', {});
      let collectorPluginId: string | undefined;
      if (body.mode === 'collector') { const secret = await this.credentials.getActiveIngestCredential(cid); collectorPluginId = await ensure('http-log', { http_endpoint: `http://kongos:${secret.token}@telemetry-collector:9093/ingest/${cid}`, method: 'POST', retry_count: 0, queue_size: 1, flush_timeout: 1 }); }
      return { pluginId, collectorPluginId };
    });
    await this.sources.assertCurrent(cid, source);
    if ((await this.settings.get(cid)).credentialGeneration !== initial.credentialGeneration) throw new ConflictException({ code: 'METRICS_GENERATION_CHANGED', message: '监控设置期间采集凭证已轮换，请核验原回执' });
    return await this.metadata.execute(settingsContext, async tx => {
      if (!await this.authz.isPlatformAdmin(actor.user)) throw new ForbiddenException();
      const settings = await this.settings.configure(cid, { revision: initial.revision, activeSourceId: source.id, enabled: true, collectorEnabled: body.mode === 'collector' || initial.collectorEnabled }, { actorId: actor.user.id, requestId: actor.requestId, ip: actor.ip }, tx);
      return { mode: body.mode, sourceId: source.id, ...result, settingsRevision: settings.revision, propagation: { state: 'pending', message: '全局插件配置生效中；请等待数据库传播、抓取和 epoch 基线样本建立' } };
    });
    } catch (error) {
      const response = error instanceof HttpException ? error.getResponse() : null;
      const safe = response && typeof response === 'object' ? response : { code: 'METRICS_SETUP_RESULT_UNCERTAIN', message: '监控设置执行进度待核验，请读取原始父回执' };
      throw new HttpException({ ...safe, state: 'uncertain', setupReceipt: true }, error instanceof HttpException ? error.getStatus() : 503);
    }
  }
  private stepKey(key: string, name: string): string { return `metrics:${createHash('sha256').update(`${key}:${name}`).digest('hex')}`; }
  private configMatches(actual: any, desired: any): boolean {
    if (!this.secrets) throw new ServiceUnavailableException({ code: 'METRICS_SETUP_SECRET_PROVIDER_REQUIRED' });
    return Object.keys(desired).every(key => this.secrets!.fingerprint(actual?.[key]) === this.secrets!.fingerprint(desired[key]));
  }
  private async nativeStep(cid: string, actor: EntityActor, name: string): Promise<any | null> {
    const row = await this.db.one<any>('SELECT id,state,entity_type,entity_id,action,workspace_id,remote_completed,error_code FROM mutation_operations WHERE actor_id=$1 AND cluster_id=$2 AND idempotency_key=$3', [actor.user.id, cid, this.stepKey(actor.idempotencyKey!, name)]);
    if (row && (row.entity_type !== 'plugins' || !['create', 'update'].includes(row.action))) throw new ConflictException({ code: 'METRICS_SETUP_KEY_CONFLICT' }); return row;
  }
  @KongActorScope({ module: 'monitoring', actorArg: 3, queryArg: 2 })
  async setupReceipt(cid: string, key: string, query: Record<string, unknown>, actor: EntityActor): Promise<any> {
    exactKeys(query, ['workspaceId']); if (!/^[A-Za-z\d_.:-]{8,128}$/.test(key)) throw new BadRequestException({ code: 'INVALID_IDEMPOTENCY_KEY' });
    const anchor = await this.scope.workspace(cid, actor, metricsId(query.workspaceId, true)), version = await this.authz.permissionVersion(actor.user);
    if (!await this.authz.isPlatformAdmin(actor.user)) throw new ForbiddenException({ code: 'METRICS_SETUP_PLATFORM_PERMISSION_REQUIRED' });
    if (!this.secrets) throw new ServiceUnavailableException({ code: 'METRICS_SETUP_SECRET_PROVIDER_REQUIRED' });
    const parent = await this.db.one<any>('SELECT id,module,action,workspace_id,payload_secret,state FROM iam_operations WHERE actor_id=$1 AND cluster_id=$2 AND idempotency_key=$3', [actor.user.id, cid, this.stepKey(key, 'parent')]);
    if (!parent) { await this.scope.stable(actor, version); return { clusterId: cid, workspaceId: anchor, idempotencyKey: key, parentState: 'not_sent', steps: [] }; }
    const payload = this.secrets.decrypt<any>(parent.payload_secret, `iam:${parent.id}:payload`);
    if (parent.module !== 'monitoring' || parent.action !== 'write' || parent.workspace_id !== anchor || payload.workspaceAnchorId !== anchor || !['native_prometheus', 'collector'].includes(payload.mode)) throw new ForbiddenException({ code: 'METRICS_SETUP_RECEIPT_SCOPE_MISMATCH' });
    const lookupActor = { ...actor, idempotencyKey: key }, steps: any[] = [];
    for (const name of ['prometheus', ...(payload.mode === 'collector' ? ['http-log'] : [])]) { const row = await this.nativeStep(cid, lookupActor, name); steps.push(row ? { name, id: row.id, state: row.state, remoteCompleted: row.remote_completed, errorCode: row.error_code || undefined, workspaceId: row.workspace_id } : { name, id: null, state: 'not_sent', remoteCompleted: false }); }
    const settings = await this.db.one<any>('SELECT id,state,remote_completed,error_code,workspace_id,payload_secret,result_secret FROM iam_operations WHERE actor_id=$1 AND cluster_id=$2 AND idempotency_key=$3', [actor.user.id, cid, this.stepKey(key, 'settings')]);
    if (settings && (settings.workspace_id !== anchor || this.secrets.fingerprint(this.secrets.decrypt(settings.payload_secret, `iam:${settings.id}:payload`)) !== this.secrets.fingerprint(payload))) throw new ForbiddenException({ code: 'METRICS_SETUP_RECEIPT_SCOPE_MISMATCH' });
    steps.push(settings ? { name: 'settings', id: settings.id, state: settings.state, remoteCompleted: settings.remote_completed, errorCode: settings.error_code || undefined } : { name: 'settings', id: null, state: 'not_sent', remoteCompleted: false });
    const parentState = parent.state !== 'succeeded' ? ['running', 'uncertain'].includes(parent.state) ? 'uncertain' : 'failed' : steps.every(row => row.state === 'succeeded' && row.remoteCompleted) ? 'succeeded' : steps.some(row => ['running', 'uncertain'].includes(row.state)) ? 'uncertain' : steps.some(row => row.state === 'succeeded') ? 'partial' : steps.some(row => row.state === 'failed') ? 'failed' : 'partial';
    const result = parentState === 'succeeded' && settings?.result_secret ? this.secrets.redact(this.secrets.decrypt(settings.result_secret, `iam:${settings.id}:result`)) : undefined;
    await this.scope.stable(actor, version); if (!await this.authz.isPlatformAdmin(actor.user)) throw new ForbiddenException();
    return { clusterId: cid, workspaceId: anchor, idempotencyKey: key, parentState, steps, ...(result ? { result } : {}) };
  }
  private async globalPlugin(cid: string, name: string): Promise<any | null> {
    return this.execution.runInternalRead(cid, 'entity-preflight', async () => {
      let cursor: string | undefined; let found: any;
      for (let page = 0; page < 10; page++) { const result = await this.kong.list(cid, '/plugins', { size: 100 }, cursor, `metrics-setup:${name}`);
        for (const plugin of result.items) if (plugin.name === name && !plugin.service?.id && !plugin.route?.id && !plugin.consumer?.id) { if (found && found.id !== plugin.id) throw new ConflictException({ code: 'METRICS_GLOBAL_PLUGIN_CONFLICT' }); found = plugin; }
        if (!result.nextCursor) return found || null; cursor = result.nextCursor;
      } throw new ConflictException({ code: 'METRICS_SETUP_SCAN_INCOMPLETE' });
    }, { paths: ['/plugins'], maxCalls: 12, maxPages: 10, maxRecords: 1000, maxBytes: 8 * 1024 * 1024, timeoutMs: 15000 });
  }
}
