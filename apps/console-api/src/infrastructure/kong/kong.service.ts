import { isSupportedKong, kongCapabilities, stripUnsupportedFields } from './kong-capabilities';
import { BadGatewayException, BadRequestException, ConflictException, HttpException, Injectable, Logger, NotFoundException, Optional, ServiceUnavailableException } from '@nestjs/common';
import { MetricsCredentialsService } from '../../modules/metrics/metrics-credentials.service';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { DbService } from '../db.service';
import { RedisService } from '../redis.service';
import { SecretService } from '../secret.service';
import { assertKongPath, ENTITIES, entityForPath, validateQuery } from './policy';
import { ConnectionAuth, outboundJson, outboundText } from './outbound';
import { flattenKongFields, validateKnownFields } from './schema';
import { readCursor, signCursor } from './cursor';
import { AuditService } from '../../modules/audit/audit.service';
import { validatePluginBindings, validatePluginConfiguration } from '../../modules/plugin-center/plugin-validation';
import { KongExecutionContextService, KongPolicyTicket,type KongExecutionFrame } from './execution-context.service';
import { transportScopeFor } from './transport-scope';
import { assertManagedCollectorDestination, assertPluginDestinations, assertPluginExecutionPrivilege, assertProxyDestination, assertTargetDestination } from './destination-policy';
import { immutableJson } from './immutable-json';
import type { KongWriteSchemaMaterial, PreparedKongSchema } from './prepared-schema';
import type { ScheduledReadAbsentTransportFact } from './scheduled-read-absent-transport.types';
import type {TargetHealthTransportReceipt} from './target-health-transport-receipt';
import { writeFailureDiagnostic } from './write-failure-diagnostics';

type Cluster = { id: string; admin_url: string; transport_scope?: string | null; connection_secret: string | null; version: string | null; enabled_plugins?: string[]; capabilities: any; execution_mode: string; status: string; revision: number };
type Circuit = { failures: number; openedAt: number; testing: boolean };
const writeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

@Injectable()
export class KongService {
  private readonly logger = new Logger(KongService.name);
  private readonly circuits = new Map<string, Circuit>();
  private readonly schemas = new Map<string, { value: any; expires: number }>();
  private readonly scopes = new Map<string, string>();
  private readonly probeInspections = new WeakMap<object, { initial: Cluster; error?: unknown }>();
  private readonly scheduledReadAbsences=new WeakMap<object,{ticket:KongPolicyTicket;fact:Readonly<ScheduledReadAbsentTransportFact>;active:boolean}>();
  private readonly targetHealthResponses=new WeakMap<KongExecutionFrame,Readonly<TargetHealthTransportReceipt>>();
  private readonly targetHealthTransportSpent=new WeakSet<KongExecutionFrame>();

  constructor(private readonly db: DbService, private readonly redis: RedisService, private readonly secrets: SecretService, private readonly audit: AuditService, private readonly execution: KongExecutionContextService, @Optional() private readonly metricsCredentials?: MetricsCredentialsService) {
    if(typeof this.execution.installConfigurationServiceDestinationObserver==='function')this.execution.installConfigurationServiceDestinationObserver({observe:(ticket,result,body)=>this.observeScheduledServiceDestination(ticket,result,body)});
  }

  /** Fixed Root observer only: no response status, path or body can be chosen
   * by its caller. The original proof exists solely while perform() observes
   * the actual parsed-JSON GET404 on this original ticket. */
  verifyScheduledReadAbsentTransport(ticket:KongPolicyTicket,originalProof:object):Readonly<ScheduledReadAbsentTransportFact>{
    this.execution.assertTicketActive(ticket);
    const observed=originalProof&&typeof originalProof==='object'&&!Array.isArray(originalProof)?this.scheduledReadAbsences.get(originalProof):undefined;
    if(!observed?.active||observed.ticket!==ticket||observed.fact.status!==404||observed.fact.method!=='GET')
      throw new HttpException({code:'SCHEDULED_READ_ABSENT_TRANSPORT_REQUIRED'},403);
    return observed.fact;
  }
  /** Fixed Mutation bridge, while still inside the ORIGINAL operation frame.
   * Caller-supplied status, headers, copied frames or DTOs cannot issue a fact.
   * Consumption records an observed failed contract too; it grants no retry. */
  consumeTargetHealthTransportReceipt(originalFrame:KongExecutionFrame):Readonly<TargetHealthTransportReceipt>|undefined{
    if(this.execution.current()!==originalFrame||!originalFrame.operation||originalFrame.operation.entityType!=='targets'
      ||!['mark_healthy','mark_unhealthy'].includes(originalFrame.operation.action??''))throw new HttpException({code:'TARGET_HEALTH_ORIGINAL_FRAME_REQUIRED'},403);
    const original=this.targetHealthResponses.get(originalFrame);if(!original)return undefined;
    if(original.operationId!==originalFrame.operation.operationId||original.clusterId!==originalFrame.clusterId
      ||original.upstreamId!==originalFrame.operation.parentId||original.targetId!==originalFrame.operation.entityId
      ||original.action!==originalFrame.operation.action)throw new HttpException({code:'TARGET_HEALTH_ORIGINAL_FRAME_REQUIRED'},403);
    this.targetHealthResponses.delete(originalFrame);return original;
  }

  invalidate(clusterId: string): void {
    for (const key of this.schemas.keys()) if (key.startsWith(`${clusterId}:`)) this.schemas.delete(key);
    const scope = this.scopes.get(clusterId); if (scope) this.circuits.delete(scope);
  }

  private async cluster(clusterId: string): Promise<Cluster> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(clusterId)) throw new BadRequestException({ code: 'INVALID_CLUSTER_ID', message: '无效的集群 ID' });
    const cluster = await this.db.one<Cluster>('SELECT id, admin_url, transport_scope, connection_secret, version, enabled_plugins, capabilities, execution_mode, status, revision FROM clusters WHERE id=$1 AND deleted_at IS NULL', [clusterId]);
    if (!cluster) throw new NotFoundException({ code: 'CLUSTER_NOT_FOUND', message: '集群不存在或已停用' });
    return cluster;
  }
  async transportScope(clusterId: string): Promise<string> {
    const cluster = await this.cluster(clusterId);
    const scope = transportScopeFor(cluster.admin_url, cluster.transport_scope);
    this.scopes.set(clusterId, scope); return scope;
  }

  async request<T = any>(clusterId: string, method: string, path: string, body?: unknown, query: Record<string, string | number> = {}): Promise<T> {
    if (typeof this.execution.runConfigurationRequestRound === 'function') return this.execution.runConfigurationRequestRound(() => this.requestInner<T>(clusterId, method, path, body, query));
    return this.requestInner<T>(clusterId, method, path, body, query);
  }
  private async requestInner<T>(clusterId: string, method: string, path: string, body?: unknown, query: Record<string, string | number> = {}): Promise<T> {
    method = method.toUpperCase();
    assertKongPath(method, path);
    validateQuery(query);
    body = immutableJson(body); query = immutableJson(query);
    const cluster = await this.cluster(clusterId);
    const ticket = await this.execution.authorizeRequest(cluster, method, path, body, query);
    const scope = transportScopeFor(cluster.admin_url, cluster.transport_scope);
    this.scopes.set(clusterId, scope);
    let result: T;
    if (writeMethods.has(method)) {
      if (!isSupportedKong(cluster.version || '')) throw new HttpException({ code: 'KONG_VERSION_INCOMPATIBLE', message: `集群版本 ${cluster.version || '尚未探测'} 不支持配置写入，仅支持 Kong OSS 1.3.x–1.5.x` }, 409);
      await this.execution.assertApprovedNativeRequest(ticket, 'authorize');
      if (body !== undefined && (body === null || typeof body !== 'object' || Array.isArray(body))) throw new BadRequestException({ code: 'INVALID_KONG_BODY', message: '网关配置必须为 JSON 对象' });
      const entity = entityForPath(path);
      if (body && entity) body = immutableJson(stripUnsupportedFields(entity, body as Record<string, unknown>, cluster.version));
      if (body && entity && !/\/targets\/[^/]+\/(healthy|unhealthy)$/.test(path)) await this.validateBody(clusterId, path, entity, body,ticket);
      if (method !== 'DELETE') await this.protectDestination(clusterId, path, body, ticket);
      result = await this.redis.withLock(`kong:${scope}:write`, () => this.perform<T>(cluster, method, path, body, query, ticket, scope));
    } else result = await this.perform<T>(cluster, method, path, body, query, ticket, scope);
    try { return await this.execution.authorizeResponse(ticket, result); }
    catch (error) {
      if (writeMethods.has(method)) {
        try { this.logger.warn(writeFailureDiagnostic('sdk-response', clusterId, error, this.execution.current().operation?.operationId)); }
        catch { /* A failed diagnostic sink must not change the unknown result. */ }
        throw new ServiceUnavailableException({ code: 'KONG_WRITE_AUTHORIZATION_CHANGED', message: '网关写入后权限或执行上下文变化，结果待核验；不会自动重试' });
      }
      throw error;
    }
  }

  /** The plugin's text endpoint is available only to the isolated scrape actor. */
  async requestMetricsText(clusterId: string): Promise<string> {
    const frame = this.execution.current();
    if (frame.kind !== 'system-read' || frame.purpose !== 'metrics-scrape' || frame.clusterId !== clusterId) throw new HttpException({ code: 'KONG_METRICS_CONTEXT_REQUIRED', message: '指标端点仅允许独立内部抓取上下文访问' }, 403);
    const cluster = await this.cluster(clusterId);
    if (!isSupportedKong(cluster.version || '') || cluster.status === 'disabled' || !cluster.enabled_plugins?.includes('prometheus')) throw new ConflictException({ code: 'KONG_METRICS_UNAVAILABLE', message: '此集群尚未探测到受支持 Kong 版本的 prometheus 插件能力' });
    assertKongPath('GET', '/metrics', true);
    const ticket = await this.execution.authorizeRequest(cluster, 'GET', '/metrics', undefined, {});
    const scope = transportScopeFor(cluster.admin_url, cluster.transport_scope);
    const result = await this.perform<string>(cluster, 'GET', '/metrics', undefined, {}, ticket, scope, true);
    const fresh = await this.cluster(clusterId);
    if (fresh.revision !== cluster.revision || fresh.admin_url !== cluster.admin_url || fresh.status === 'disabled' || !fresh.enabled_plugins?.includes('prometheus')) throw new ConflictException({ code: 'KONG_METRICS_CONNECTION_CHANGED', message: '抓取期间集群能力或连接发生变化' });
    return this.execution.authorizeResponse(ticket, result);
  }

  private async protectedRead(clusterId: string, path: string, query: Record<string, string | number> = {}): Promise<any> {
    return this.execution.runInternalRead(clusterId, 'entity-preflight', () => this.request(clusterId, 'GET', path, undefined, query), { paths: [path], maxCalls: 4 });
  }
  private async protectDestination(clusterId: string, path: string, body: any, ticket: KongPolicyTicket): Promise<void> {
    if (!body || typeof body !== 'object') return;
    const parts = path.split('/').filter(Boolean);
    let before = this.execution.authorizedBefore(ticket);
    if (parts[0] === 'services' && parts.length <= 2) {
      if(typeof this.execution.protectScheduledConfigurationServiceDestination==='function'&&await this.execution.protectScheduledConfigurationServiceDestination(ticket))return;
      if (parts.length === 2 && !before) before = await this.protectedRead(clusterId, path);
      const effective = { ...before, ...body };
      if (typeof effective.host !== 'string') return;
      let upstream: any;
      // 1.5 rejects literal IP Upstream names with 400. Skip this name lookup,
      // while still checking the literal address against destination policy.
      if (!/[\[\]:]/.test(effective.host) && !isIP(effective.host)) try { upstream = await this.protectedRead(clusterId, `/upstreams/${encodeURIComponent(effective.host)}`); }
      catch (error) { if (!(error instanceof HttpException) || error.getStatus() !== 404) throw error; }
      if (upstream?.id) {
        const collection = `/upstreams/${encodeURIComponent(upstream.id)}/targets`;
        await this.execution.runInternalRead(clusterId, 'entity-preflight', async () => {
          let cursor: string | undefined;
          for (let page = 0; page < 5; page++) {
            const result = await this.list(clusterId, collection, { size: 100 }, cursor, 'service-destination-policy');
            for (const target of result.items) { this.execution.assertTicketActive(ticket); await assertTargetDestination(this.db, target.target); }
            if (!result.nextCursor) return;
            cursor = result.nextCursor;
          }
          throw new ConflictException({ code: 'DESTINATION_LOOKUP_LIMIT', message: 'Upstream 目标核验超过预算，变更未执行' });
        }, { paths: [collection], maxPages: 5, maxRecords: 500, maxCalls: 8, timeoutMs: 10_000 });
      } else await assertProxyDestination(this.db, { host: effective.host, port: Number(effective.port ?? (effective.protocol === 'https' || effective.protocol === 'grpcs' ? 443 : 80)) });
    } else if (parts[0] === 'upstreams' && parts[2] === 'targets' && parts.length === 3) {
      await assertTargetDestination(this.db, body.target);
    } else if (parts[0] === 'plugins' && parts.length <= 2) {
      if (parts.length === 2 && !before) before = await this.protectedRead(clusterId, path);
      const effective = { ...before, ...body, config: { ...before?.config, ...body.config } };
      if (typeof effective.name === 'string') await this.pluginDestinations(clusterId, effective.name, effective.config, ticket);
    }
  }
  private async observeScheduledServiceDestination(ticket:KongPolicyTicket,observed:Readonly<import('../../modules/workflows/approved-execution.types').ConfigurationNativeBeforeReadResult>,body:any):Promise<void>{
        if(!observed.before||typeof observed.before!=='object')throw new ConflictException({code:'CONFIGURATION_SERVICE_DESTINATION_BEFORE_REQUIRED'});
        const effective={...observed.before,...body};
        if(typeof effective.host!=='string')throw new ConflictException({code:'CONFIGURATION_SERVICE_DESTINATION_HOST_REQUIRED'});
        if(observed.serviceHostUpstream!==undefined&&observed.serviceHostUpstream!==null){
          if(!Array.isArray(observed.serviceTargets))throw new ConflictException({code:'CONFIGURATION_SERVICE_DESTINATION_EOF_REQUIRED'});
          for(const row of observed.serviceTargets){this.execution.assertTicketActive(ticket);this.execution.assertConfigurationServiceObservation();
            await assertTargetDestination(this.db,(row as any).target);await this.redis.assertLeaseOwnership();
            this.execution.assertTicketActive(ticket);this.execution.assertConfigurationServiceObservation();}
        }else{
          await assertProxyDestination(this.db,{host:effective.host,port:Number(effective.port??(effective.protocol==='https'||effective.protocol==='grpcs'?443:80))});
          await this.redis.assertLeaseOwnership();this.execution.assertTicketActive(ticket);this.execution.assertConfigurationServiceObservation();
        }
  }
  private async pluginDestinations(cid: string, name: string, config: any, ticket: KongPolicyTicket): Promise<void> {
    let safeConfig = config;
    if (name === 'http-log' && typeof config?.http_endpoint === 'string') {
      let endpoint: URL | undefined; try { endpoint = new URL(config.http_endpoint); } catch { /* ordinary URL guard rejects it */ }
      if (endpoint?.username || endpoint?.password) {
        const retainedManagedEndpoint = () => {
          const before = this.execution.authorizedBefore(ticket);
          return this.execution.verifiedPlatformAdmin(ticket) && before?.name === 'http-log' && /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(before?.id || '') && before.config?.http_endpoint === config.http_endpoint;
        };
        const permitted = () => this.execution.verifiedManagedMetricsProvision(ticket) || retainedManagedEndpoint();
        if (!this.metricsCredentials || !permitted()) throw new HttpException({ code: 'MANAGED_METRICS_PROVISION_REQUIRED', message: '新采集凭证须通过平台监控设置；既有端点仅平台管理员可保持配置' }, 403);
        const verification = await this.metricsCredentials.verifyManagedIngestUrl(cid, config.http_endpoint);
        this.execution.assertTicketActive(ticket);
        if (!verification.valid || !permitted()) throw new HttpException({ code: 'MANAGED_METRICS_TOKEN_INVALID', message: '采集凭证、集群或端点已变化' }, 403);
        endpoint.username = ''; endpoint.password = '';
        await assertManagedCollectorDestination(this.db, cid, endpoint.toString());
        // DNS/registry validation awaited above. Re-prove the token and current
        // platform/private ancestor before using this sole protected-channel
        // exception; generic plugin/Service/Target guards remain unchanged.
        const currentVerification = await this.metricsCredentials.verifyManagedIngestUrl(cid, config.http_endpoint);
        await this.execution.refreshAuthorization(ticket);
        this.execution.assertTicketActive(ticket);
        if (!currentVerification.valid || !permitted()) throw new HttpException({ code: 'MANAGED_METRICS_TOKEN_INVALID', message: '采集凭证、集群或端点已变化' }, 403);
        const { http_endpoint: _validatedEndpoint, ...otherConfig } = config;
        safeConfig = otherConfig;
      }
    }
    await assertPluginDestinations(this.db, name, safeConfig, this.execution.verifiedPlatformAdmin(ticket));
  }

  /** Schema-only planning uses the same validator as the final write path.
   * It sends only authorized schema/point GETs and grants no write ticket. */
  async prepareSchema(clusterId: string, canonicalPath: string, input: unknown): Promise<PreparedKongSchema> {
    const frame = this.execution.current();
    // A copied scheduler/actor DTO is not an identity. Only the real private
    // scheduled ancestor can replace the HTTP SID requirement here; internal
    // and system read frames cannot use this schema-planning exemption.
    const scheduled = !frame.sessionId && ['actor', 'scheduled-entity', 'operation'].includes(frame.kind)
      && typeof this.execution.verifyEntityScheduledNamespace === 'function'
      ? await this.execution.verifyEntityScheduledNamespace('capture') : null;
    if (!frame.actor || !frame.sessionId && !scheduled || frame.clusterId !== clusterId || !frame.workspaceId || frame.kind === 'system-read'
      || scheduled && (scheduled.origin !== 'scheduled-entity' || scheduled.sessionId !== null || scheduled.actor.id !== frame.actor.id
        || scheduled.clusterId !== clusterId || scheduled.workspaceId !== frame.workspaceId)) {
      throw new HttpException({ code: 'KONG_SCHEMA_PREPARATION_CONTEXT_REQUIRED', message: '变更准备需要当前用户及明确工作区' }, 403);
    }
    const body = immutableJson(input), parts = canonicalPath.split('/').filter(Boolean);
    const health = /^\/upstreams\/[^/]+\/targets\/[^/]+\/(healthy|unhealthy)$/.test(canonicalPath);
    const collection = parts.length === 1 || parts.length === 3 && (
      parts[0] === 'consumers' || parts[0] === 'upstreams' && parts[2] === 'targets'
      || parts[0] === 'services' && parts[2] === 'routes' || parts[0] === 'certificates' && parts[2] === 'snis');
    assertKongPath(collection || health ? 'POST' : 'PATCH', canonicalPath);
    const entity = entityForPath(canonicalPath);
    if (!entity || !health && (body === undefined || body === null || typeof body !== 'object' || Array.isArray(body))) {
      throw new BadRequestException({ code: 'INVALID_KONG_BODY', message: '变更准备需要有效的实体配置' });
    }
    if (health && body !== undefined) throw new BadRequestException({ code: 'INVALID_KONG_BODY', message: '健康状态置位不接受配置请求体' });
    const before = await this.cluster(clusterId);
    if (!isSupportedKong(before.version ?? '') || before.status === 'disabled') {
      throw new ConflictException({ code: 'KONG_VERSION_INCOMPATIBLE', message: '变更准备仅支持可用的 Kong OSS 1.5.x 集群' });
    }
    if (scheduled && (before.revision !== scheduled.clusterRevision || transportScopeFor(before.admin_url, before.transport_scope) !== scheduled.transportScope)) {
      throw new ConflictException({ code: 'KONG_SCHEMA_PREPARATION_CHANGED', message: '变更准备期间集群发生变化，请重新生成计划' });
    }
    let schemaMaterial: KongWriteSchemaMaterial = health
      ? { entity: { name: entity, canonicalPath: `/schemas/${entity}`, schema: await this.execution.runInternalRead(clusterId, 'entity-preflight', () => this.schema(clusterId, entity), { paths: [`/schemas/${entity}`], maxCalls: 4 }) } }
      : await this.validateBody(clusterId, canonicalPath, entity, body);
    if (entity === 'plugins' && !schemaMaterial.plugin) {
      const name = (body as any).name ?? (await this.protectedRead(clusterId, canonicalPath)).name;
      const schema = await this.execution.runInternalRead(clusterId, 'entity-preflight', () => this.pluginSchema(clusterId, name), { paths: [`/plugins/schema/${name}`], maxCalls: 4 });
      schemaMaterial = { ...schemaMaterial, plugin: { name, canonicalPath: `/plugins/schema/${name}`, schema } };
    }
    const after = await this.cluster(clusterId);
    this.execution.current();
    if (after.revision !== before.revision || after.admin_url !== before.admin_url || after.transport_scope !== before.transport_scope
      || after.version !== before.version || after.status === 'disabled') {
      throw new ConflictException({ code: 'KONG_SCHEMA_PREPARATION_CHANGED', message: '变更准备期间集群发生变化，请重新生成计划' });
    }
    if (scheduled && (await this.execution.verifyEntityScheduledNamespace('capture') !== scheduled || this.execution.current() !== frame)) {
      throw new HttpException({ code: 'KONG_SCHEMA_PREPARATION_CONTEXT_REQUIRED', message: '变更准备需要当前用户及明确工作区' }, 403);
    }
    return immutableJson({ version: 1, clusterId, canonicalPath, nativeType: entity, kongVersion: before.version!,
      adapter: 'kong-oss-1.5-v1', clusterRevision: before.revision, schemaMaterial, payloadHmac: this.secrets.fingerprint(body ?? null) });
  }

  private async validateBody(clusterId: string, path: string, entity: string, body: any,ticket?:KongPolicyTicket): Promise<KongWriteSchemaMaterial> {
    const ordinary=()=>this.execution.runInternalRead(clusterId,'entity-preflight',()=>this.schema(clusterId,entity),{paths:[`/schemas/${entity}`],maxCalls:4});
    const schema=ticket?await this.execution.runPortalWriteSchemaRead(ticket,()=>{
      const phase=this.execution.scheduledPortalPreparationPhase();return phase?.purpose==='schema'?this.schema(clusterId,entity):ordinary();
    }):await ordinary();
    let plugin: KongWriteSchemaMaterial['plugin'];
    if (entity === 'certificates' && body.snis !== undefined) {
      // 1.5 certificate Admin routes accept SNI associations outside the core DAO schema.
      const { snis, ...rest } = body;
      if (!Array.isArray(snis) || snis.length > 1000 || snis.some((name: unknown) => typeof name !== 'string' || !name.length || name.length > 253)) throw new BadRequestException({ code: 'INVALID_SNI_ASSOCIATION', message: 'snis 必须为不超过 1000 项的 SNI 名称数组' });
      validateKnownFields(rest, schema);
    } else if (entity === 'plugins') {
      const { config, ...rest } = body;
      validateKnownFields(rest, schema);
      let name = body.name;
      if (!name && path.split('/').filter(Boolean).length === 2) name = (await this.protectedRead(clusterId, path)).name;
      if (!name) throw new BadRequestException({ code: 'PLUGIN_NAME_REQUIRED', message: '插件配置校验需要插件名称' });
      validatePluginBindings(name, body);
      if (config !== undefined) {
        const pluginSchema = await this.execution.runInternalRead(clusterId, 'entity-preflight', () => this.pluginSchema(clusterId, name), { paths: [`/plugins/schema/${name}`], maxCalls: 4 });
        validateKnownFields(config, pluginSchema, 'config');
        validatePluginConfiguration(name, config, pluginSchema);
        plugin = { name, canonicalPath: `/plugins/schema/${name}`, schema: pluginSchema };
      }
    } else validateKnownFields(body, schema);
    return { entity: { name: entity, canonicalPath: `/schemas/${entity}`, schema }, ...(plugin ? { plugin } : {}) };
  }

  private async perform<T>(cluster: Cluster, method: string, path: string, body: unknown, query: Record<string, string | number>, ticket: KongPolicyTicket, scope: string, text = false): Promise<T> {
    const circuit = this.circuits.get(scope) || { failures: 0, openedAt: 0, testing: false };
    if (circuit.openedAt && Date.now() - circuit.openedAt < 30_000) throw new ServiceUnavailableException({ code: 'KONG_CIRCUIT_OPEN', message: '集群连续故障，连接熔断中，请稍后重试' });
    if (circuit.openedAt && circuit.testing) throw new ServiceUnavailableException({ code: 'KONG_CIRCUIT_OPEN', message: '集群连接正在恢复探测' });
    if (circuit.openedAt) circuit.testing = true;
    this.circuits.set(scope, circuit);
    // Waiting only acquires a local rate slot before transport. A write is still
    // sent exactly once, and Redis failures remain fail-closed.
    const maxWait = Math.min(1500, Math.max(0, Number(process.env.KONG_RATE_WAIT_MS ?? 1500) || 0));
    const deadline = Date.now() + maxWait;
    let rate = await this.redis.rateLimit(`kong:${scope}`, Number(process.env.KONG_RATE_LIMIT || 120), 1000);
    while (!rate.allowed && Date.now() < deadline) {
      const delay = Math.min(Math.max(10, rate.retryAfterMs || 10), deadline - Date.now());
      await new Promise(resolve => setTimeout(resolve, delay));
      if (Date.now() >= deadline) break;
      rate = await this.redis.rateLimit(`kong:${scope}`, Number(process.env.KONG_RATE_LIMIT || 120), 1000);
    }
    if (!rate.allowed) { circuit.testing = false; throw new HttpException({ code: 'KONG_RATE_LIMITED', message: '网关请求速率超过限制，请稍后重试', retryAfterMs: rate.retryAfterMs }, 429); }
    // Check all trusted outer leases after waiting for a rate slot and directly
    // before the single native write. A lost migration/recycle lease stops here.
    const prepareWrite = async (physicalSend=true) => {
      try {
        const fresh = await this.cluster(cluster.id);
        if (fresh.admin_url !== cluster.admin_url || fresh.connection_secret !== cluster.connection_secret || transportScopeFor(fresh.admin_url, fresh.transport_scope) !== scope || fresh.version !== cluster.version || fresh.status === 'disabled') throw new ConflictException({ code: 'KONG_CLUSTER_CONNECTION_CHANGED', message: '集群连接或版本在执行前发生变化，网关写入已停止' });
        await this.execution.assertApprovedNativeRequest(ticket, 'prepare');
        if (fresh.execution_mode === 'approval' && cluster.execution_mode !== 'approval') throw new ConflictException({ code: 'APPROVAL_REQUIRED', message: '集群模式在执行期间变化，当前写入已停止' });
        // The initial decision can precede schema, destination and rate waits.
        // Verify the durable operation and current grants again before sending.
        await this.execution.refreshAuthorization(ticket);
        if (method !== 'DELETE' && path.startsWith('/plugins')) {
          const before = this.execution.authorizedBefore(ticket);
          const name = (body as any)?.name ?? before?.name;
          if (name) assertPluginExecutionPrivilege(name, { ...before?.config, ...(body as any)?.config }, this.execution.verifiedPlatformAdmin(ticket));
          if (name === 'http-log') await this.pluginDestinations(cluster.id, name, { ...before?.config, ...(body as any)?.config }, ticket);
        }
        if(method!=='DELETE'&&path.startsWith('/services/')&&typeof this.execution.protectScheduledConfigurationServiceDestination==='function')await this.execution.protectScheduledConfigurationServiceDestination(ticket);
        await this.redis.assertLeaseOwnership();
        if(physicalSend)await this.execution.beforeNativeSend(ticket);else await this.execution.prepareNativeSend(ticket);
        if (method !== 'DELETE' && path.startsWith('/plugins')) {
          const before = this.execution.authorizedBefore(ticket), name = (body as any)?.name ?? before?.name;
          if (name) assertPluginExecutionPrivilege(name, { ...before?.config, ...(body as any)?.config }, this.execution.verifiedPlatformAdmin(ticket));
          if (name === 'http-log') await this.pluginDestinations(cluster.id, name, { ...before?.config, ...(body as any)?.config }, ticket);
        }
        // Epoch fencing can await SQL. Renew the execution lease again before
        // the synchronous transport fence decides whether a packet may leave.
        await this.redis.assertLeaseOwnership();
      }
      catch (error) { circuit.testing = false; throw error; }
    };
    if (writeMethods.has(method)) await prepareWrite(false);
    else await this.execution.assertGovernanceBeforeSend(ticket);
    const auth = cluster.connection_secret ? this.secrets.decrypt<ConnectionAuth>(cluster.connection_secret, `cluster:${cluster.id}`) : null;
    const attempts = method === 'GET' ? 3 : 1;
    let lastError: any;
    for (let attempt = 0; attempt < attempts; attempt++) {
      try {
        if (attempt > 0) {
          this.execution.chargeRetry(ticket);
          const retryRate = await this.redis.rateLimit(`kong:${scope}`, Number(process.env.KONG_RATE_LIMIT || 120), 1000);
          if (!retryRate.allowed) throw new HttpException({ code: 'KONG_RATE_LIMITED', message: '网关重试请求速率超过限制，请稍后重试' }, 429);
        }
        if (!writeMethods.has(method)) await this.execution.assertGovernanceBeforeSend(ticket);
        const writeFence = () => { this.execution.assertTicketActive(ticket); if (writeMethods.has(method)) this.redis.assertLeaseActive(); };
        writeFence?.();
        const transportFence=()=>{
          writeFence();
          if(method==='POST'&&/^\/upstreams\/[^/]+\/targets\/[^/]+\/(healthy|unhealthy)$/.test(path)){
            const originalFrame=this.execution.current();
            if(this.targetHealthTransportSpent.has(originalFrame))throw new ConflictException({code:'TARGET_HEALTH_TRANSPORT_ALREADY_SPENT',message:'当前健康置位操作已尝试发送，请核验原操作，勿重复提交'});
            this.targetHealthTransportSpent.add(originalFrame);
          }
          if(writeMethods.has(method))this.execution.spendEntityChangeTransport?.(ticket);
        };
        const result = text
          ? await outboundText(cluster.admin_url, '/metrics', auth, 5000, writeFence, 2 * 1024 * 1024)
          : await outboundJson(cluster.admin_url, path, method, body, query, auth, Number(process.env.KONG_TIMEOUT_MS || 5000), transportFence, writeMethods.has(method) ? prepareWrite : () => this.execution.assertGovernanceBeforeSend(ticket));
        if(writeMethods.has(method))this.execution.observeEntityChangeTransportResponse?.(ticket,result.status,result.body);
        else if(method==='GET')this.execution.observeEntityChangeReadResponse?.(ticket,result.status);
        if(method==='POST'&&/^\/upstreams\/[^/]+\/targets\/[^/]+\/(healthy|unhealthy)$/.test(path)){
          const originalFrame=this.execution.current(),operation=originalFrame.operation,parts=path.split('/'),desired=parts[5];
          this.execution.assertTicketActive(ticket);
          if(!operation||operation.entityType!=='targets'||operation.operationId===undefined||operation.parentId!==parts[2]
            ||operation.entityId!==parts[4]||operation.action!==`mark_${desired}`||this.targetHealthResponses.has(originalFrame))
            throw new ServiceUnavailableException({code:'TARGET_HEALTH_TRANSPORT_BINDING_INVALID',message:'健康置位原响应绑定发生变化，请核验原操作，勿重复提交'});
          const emptyBody=result.body===null&&result.bytes===0,contractValid=result.status===204&&emptyBody;
          this.targetHealthResponses.set(originalFrame,immutableJson({version:1,kind:'original-target-health-transport-response',clusterId:cluster.id,
            operationId:operation.operationId,upstreamId:parts[2],targetId:parts[4],action:operation.action as 'mark_healthy'|'mark_unhealthy',
            nativeStatus:result.status,rawResponse:result.body,responseHmac:this.secrets.fingerprint(result.body),responseBytes:result.bytes,emptyBody,contractValid}));
          if(result.status<300&&!contractValid)throw new ServiceUnavailableException({code:'TARGET_HEALTH_NATIVE_RESPONSE_INVALID',message:'健康置位未返回原204空响应，请核验原操作，勿重复提交'});
        }
        if (result.status >= 300 && result.status < 400) throw new BadGatewayException({ code: 'KONG_REDIRECT_FORBIDDEN', message: '网关返回重定向，适配层不会跟随' });
        if (result.status >= 500) throw new ServiceUnavailableException({ code: 'KONG_UPSTREAM_ERROR', message: 'Kong 集群暂时不可用', upstreamStatus: result.status });
        if (result.status >= 400) {
          circuit.failures = 0; circuit.openedAt = 0; circuit.testing = false;
          if(!text&&method==='GET'&&body===undefined&&result.status===404&&'jsonParsed' in result&&result.jsonParsed===true){
            const originalProof=Object.freeze({}),observation={ticket,active:true,fact:Object.freeze({clusterId:cluster.id,
              transportScope:scope,clusterRevision:cluster.revision,method:'GET' as const,path,query,status:404 as const,response:immutableJson(result.body)})};
            this.scheduledReadAbsences.set(originalProof,observation);
            try{await this.execution.observeScheduledReadAbsent?.(ticket,originalProof);}
            finally{observation.active=false;this.scheduledReadAbsences.delete(originalProof);}
          }
          const fields = flattenKongFields(result.body?.fields);
          const normalized = this.secrets.redactError({ message: result.body?.message || 'Kong 拒绝请求', ...(Object.keys(fields).length ? { fields } : {}) }, body);
          throw new HttpException({ code: 'KONG_VALIDATION_ERROR', ...normalized, upstreamStatus: result.status }, result.status);
        }
        circuit.failures = 0; circuit.openedAt = 0; circuit.testing = false;
        return result.body as T;
      } catch (error: any) {
        if (error instanceof HttpException && (/^KONG_EXECUTION_|^KONG_NATIVE_|^KONG_RECYCLE_/.test((error.getResponse() as any)?.code || '') || ['LOCK_LOST', 'LOCK_CONTEXT_REQUIRED'].includes((error.getResponse() as any)?.code))) {
          circuit.testing = false;
          throw error;
        }
        lastError = error;
        const retryable = error?.code === 'ETIMEDOUT' || (error instanceof HttpException && error.getStatus() >= 500 && (error.getResponse() as any)?.code === 'KONG_UPSTREAM_ERROR');
        if (!retryable || attempt === attempts - 1) break;
        await new Promise(resolve => setTimeout(resolve, (100 * 2 ** attempt) + Math.floor(Math.random() * 80)));
      }
    }
    circuit.testing = false;
    const status = lastError instanceof HttpException ? lastError.getStatus() : 503;
    if (status >= 500) {
      circuit.failures += 1;
      if (circuit.failures >= 5) circuit.openedAt = Date.now();
      this.logger.warn(JSON.stringify({ event: 'kong_request_failed', clusterId: cluster.id, method, path, code: lastError?.code || (lastError?.getResponse?.() as any)?.code || 'NETWORK_ERROR', writeResult: writeMethods.has(method) ? 'unknown_requires_verification' : undefined }));
    }
    if (lastError instanceof HttpException) throw lastError;
    throw new ServiceUnavailableException({ code: writeMethods.has(method) ? 'KONG_WRITE_RESULT_UNKNOWN' : 'KONG_CONNECTION_FAILED', message: writeMethods.has(method) ? '写入响应中断，结果待核验；请勿重复提交' : '无法连接 Kong 集群', ...(lastError?.code === 'ETIMEDOUT' ? { reason: 'timeout' } : {}) });
  }

  async schema(clusterId: string, entity: string): Promise<any> {
    assertKongPath('GET', `/schemas/${entity}`);
    return this.cachedSchema(clusterId, `entity:${entity}`, `/schemas/${entity}`);
  }

  async pluginSchema(clusterId: string, name: string): Promise<any> {
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(name)) throw new BadRequestException({ code: 'INVALID_PLUGIN_NAME', message: '插件名称无效' });
    return this.cachedSchema(clusterId, `plugin:${name}`, `/plugins/schema/${name}`);
  }

  private async cachedSchema(clusterId: string, key: string, path: string): Promise<any> {
    const cached = this.schemas.get(`${clusterId}:${key}`);
    if (cached && cached.expires > Date.now()) {
      const ticket = await this.execution.authorizeRequest(await this.cluster(clusterId), 'GET', path, undefined, {});
      return this.execution.authorizeResponse(ticket, cached.value);
    }
    const schema = await this.request(clusterId, 'GET', path);
    if (!schema || typeof schema !== 'object' || !schema.fields) throw new BadGatewayException({ code: 'KONG_INVALID_SCHEMA', message: '网关返回的 schema 无效，拒绝配置写入' });
    this.schemas.set(`${clusterId}:${key}`, { value: schema, expires: Date.now() + 300_000 });
    return schema;
  }

  async list(clusterId: string, path: string, query: Record<string, string | number> = {}, cursor?: string, subject?: string): Promise<{ items: any[]; nextCursor: string | null; size: number; console_permission_projection?: boolean }> {
    const parameters: Record<string, string | number> = { ...query, size: query.size || 20 };
    validateQuery(parameters);
    if (cursor) parameters.offset = readCursor(cursor, clusterId, path, parameters, subject);
    const result = await this.request(clusterId, 'GET', path, undefined, parameters);
    if (!Array.isArray(result?.data)) throw new BadGatewayException({ code: 'KONG_INVALID_LIST', message: '网关返回的列表响应无效' });
    let nextCursor: string | null = null;
    if (result.next) {
      const cluster = await this.cluster(clusterId);
      const base = new URL(cluster.admin_url);
      const next = new URL(result.next, base);
      const expectedPath = `${base.pathname.replace(/\/$/, '')}${path}`;
      if (next.pathname !== expectedPath || !next.searchParams.has('offset')) throw new BadGatewayException({ code: 'KONG_INVALID_NEXT', message: '网关返回的分页路径无效' });
      const offset = next.searchParams.get('offset')!;
      if (offset.length > 8192) throw new BadGatewayException({ code: 'KONG_INVALID_NEXT', message: '网关返回的分页游标过长' });
      const baseQuery = { ...parameters }; delete (baseQuery as Record<string, unknown>).offset;
      nextCursor = signCursor({ clusterId, path, query: baseQuery, offset, subject });
    }
    return { items: result.data, nextCursor, size: Number(parameters.size), ...(result.console_permission_projection ? { console_permission_projection: true } : {}) };
  }

  async probe(clusterId: string, actor: { id?: string; requestId?: string; ip?: string } = {}): Promise<any> {
    const inspection = await this.inspectProbe(clusterId);
    const result = await this.db.transaction(tx => this.persistProbe(clusterId, inspection, actor, tx));
    const error = this.probeInspections.get(inspection)?.error;
    if (error) throw error;
    return result;
  }

  /** Pure Admin reads. Metadata is persisted only inside the caller's ledger
   * transaction, after authorization and a durable requested audit exist. */
  async inspectProbe(clusterId: string): Promise<any> {
    const run = async () => this.redis.withLock(`kong:${await this.transportScope(clusterId)}:probe`, () => this.runInspection(clusterId));
    const current = this.execution.peek();
    if (current?.actor) return this.execution.runActor({ actor: current.actor, clusterId, module: 'clusters', action: 'write' }, () => this.execution.runInternalRead(clusterId, 'probe', run));
    return this.execution.runSystemRead(clusterId, 'probe', run);
  }

  private async runInspection(clusterId: string): Promise<any> {
    const initial = await this.cluster(clusterId), started = Date.now();
    this.invalidate(clusterId);
    let observedVersion: string | null = null;
    try {
      const root = await this.request(clusterId, 'GET', '/');
      if (!root || typeof root.version !== 'string') throw new BadGatewayException({ code: 'KONG_INVALID_ROOT', message: '目标未返回 Kong version，不能识别为 Kong Admin API' });
      observedVersion = root.version;
      const supported = isSupportedKong(root.version);
      // The user's 1.5 allowlist permits root discovery, not GET /endpoints.
      // Missing discovery remains explicit; version/schema-derived endpoints
      // are recorded separately and never invented as native root fields.
      const endpointResult = Object.hasOwn(root, 'endpoints') && root.endpoints != null ? root.endpoints : null;
      const enabled = await this.request(clusterId, 'GET', '/plugins/enabled');
      if (!Array.isArray(enabled?.enabled_plugins)) throw new BadGatewayException({ code: 'KONG_INVALID_PLUGIN_LIST', message: '目标返回的插件清单无效' });
      const statusResult = await this.request(clusterId, 'GET', '/status').catch(error => this.optionalProbeRead(error));
      const schemaCapabilities: Record<string, boolean> = {};
      if (supported) await Promise.all(ENTITIES.map(async entity => { schemaCapabilities[entity] = await this.schema(clusterId, entity).then(() => true).catch(error => { this.optionalProbeRead(error); return false; }); }));
      const capabilities = {
        adapter: supported ? `kong-oss-${kongCapabilities(root.version).line}` : null, version_supported: supported,
        kong_capabilities: kongCapabilities(root.version),
        endpoint_discovery: endpointResult !== null, endpoint_discovery_source: endpointResult !== null ? 'root' : 'unavailable',
        endpoints: endpointResult, derived_endpoints: supported ? ENTITIES.filter(entity => schemaCapabilities[entity]).map(entity => `/${entity}`) : [],
        derived_capability_source: supported ? 'fixed-allowlist-and-schemas' : null, status: statusResult !== null,
        schemas: schemaCapabilities, plugins_schema_path: '/plugins/schema/{name}',
        native_workspaces: false, native_rbac: false, native_vitals: false, native_vaults: false, native_event_hooks: false, native_clustering: false, expression_routes: false,
        write_enabled: supported && initial.execution_mode === 'direct',
        warnings: !supported ? [`仅支持 Kong OSS 1.3.x–1.5.x，检测到 ${root.version}，配置写入已禁止`] : kongCapabilities(root.version).full ? [] : [`Kong ${root.version} 为有限支持：凭证无 tags，门户发放凭证、凭证导入导出与路由模拟已隐藏`],
      };
      const inspection = immutableJson({ cluster_id: clusterId, version: root.version, status: supported ? 'healthy' : 'incompatible', capabilities, enabled_plugins: enabled.enabled_plugins, latency_ms: Date.now() - started, probed_at: new Date().toISOString() });
      this.probeInspections.set(inspection, { initial }); return inspection;
    } catch (error: any) {
      this.optionalProbeRead(error);
      const inspection = immutableJson({ cluster_id: clusterId, version: observedVersion, status: 'unhealthy', capabilities: null, enabled_plugins: [], latency_ms: Date.now() - started, probed_at: new Date().toISOString(), error_code: (error?.getResponse?.() as any)?.code || 'PROBE_FAILED', safe_error: '无法完成 Kong 能力探测' });
      this.probeInspections.set(inspection, { initial, error }); return inspection;
    }
  }
  private optionalProbeRead(error: any): null {
    // Revoked grants or closed capabilities are authorization failures, never a
    // false gateway outage that could be persisted after losing permission.
    const status = error instanceof HttpException ? error.getStatus() : 0;
    const code = (error?.getResponse?.() as any)?.code || '';
    if (status === 401 || status === 403 || /^KONG_(?:POLICY|EXECUTION)_/.test(code)) throw error;
    return null;
  }

  /** SQL/audit only; accepts solely an immutable inspection produced here. */
  async persistProbe(clusterId: string, inspection: any, actor: { id?: string; requestId?: string; ip?: string } = {}, tx: DbService): Promise<any> {
    const trusted = inspection && this.probeInspections.get(inspection);
    if (!trusted || inspection.cluster_id !== clusterId) throw new BadRequestException({ code: 'PROBE_INSPECTION_REQUIRED', message: '探测记录必须来自当前真实能力检查' });
    const { initial } = trusted, healthy = inspection.status !== 'unhealthy';
    let changed: number;
    if (healthy) changed = await tx.exec('UPDATE clusters SET version=$2, capabilities=$3::jsonb, enabled_plugins=$4, status=$5, last_probed_at=now(), updated_at=now() WHERE id=$1 AND revision=$6 AND deleted_at IS NULL', [clusterId, inspection.version, JSON.stringify(inspection.capabilities), inspection.enabled_plugins, inspection.status, initial.revision]);
    else changed = await tx.exec("UPDATE clusters SET status='unhealthy', version=COALESCE($3,version), last_probed_at=now(), updated_at=now() WHERE id=$1 AND revision=$2 AND deleted_at IS NULL", [clusterId, initial.revision, inspection.version]);
    if (!changed) throw new ConflictException({ code: 'PROBE_CONFIG_CHANGED', message: '探测期间集群配置已变更，请重新探测' });
    await tx.exec('INSERT INTO cluster_probes(id,cluster_id,version,adapter,capabilities,enabled_plugins,status,latency_ms,error_code,safe_error) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10)', [randomUUID(), clusterId, inspection.version, inspection.capabilities?.adapter ?? null, JSON.stringify(inspection.capabilities ?? {}), inspection.enabled_plugins, inspection.status, inspection.latency_ms, inspection.error_code ?? null, inspection.safe_error ?? null]);
    await this.audit.append({ actorId: actor.id, clusterId, entityType: 'cluster', entityId: clusterId, action: 'probe', before: { version: initial.version, status: initial.status }, after: { version: inspection.version ?? initial.version, status: inspection.status }, result: healthy ? 'success' : 'failure', requestId: actor.requestId, ip: actor.ip }, tx);
    return inspection;
  }
}
