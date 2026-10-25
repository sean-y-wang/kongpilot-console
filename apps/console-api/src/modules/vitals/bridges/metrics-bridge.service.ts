import { BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable, OnModuleDestroy, OnModuleInit, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { createServer, IncomingMessage, Server, ServerResponse } from 'node:http';
import { DbService } from '../../../infrastructure/db.service';
import { RedisService } from '../../../infrastructure/redis.service';
import { KongService } from '../../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../../infrastructure/kong/execution-context.service';
import { MetricsCredentialsService } from '../../metrics/metrics-credentials.service';
import { MetricsRepositoryService } from '../../metrics/metrics-repository.service';
import { MetricsSettingsService } from '../../metrics/metrics-settings.service';
import { MetricsAssignment, MetricsCredentialIdentity } from '../../metrics/metrics.types';
import { exactKeys, metricsId } from '../vitals-query';
import { MetricsCatalogService } from './metrics-catalog.service';
import { encodePrometheusText, escapePrometheusLabel, parsePrometheusText, PrometheusSample } from './prometheus-text';

@Injectable()
export class MetricsBridgeService implements OnModuleInit, OnModuleDestroy {
  private server?: Server;
  constructor(private readonly credentials: MetricsCredentialsService, private readonly repository: MetricsRepositoryService,
    private readonly settings: MetricsSettingsService, private readonly catalog: MetricsCatalogService,
    private readonly kong: KongService, private readonly execution: KongExecutionContextService, private readonly redis: RedisService, private readonly db: DbService) {}
  async onModuleInit(): Promise<void> {
    if (process.env.METRICS_BRIDGE_ENABLED !== 'true') return;
    const port = Number(process.env.METRICS_BRIDGE_PORT || 9092), host = process.env.METRICS_BRIDGE_HOST || '127.0.0.1';
    if (!Number.isInteger(port) || port < 1024 || port > 65535 || host === '0.0.0.0' || host === '::') throw new Error('Metrics bridge requires an explicit private bind address');
    // This server has no MainHTTP middleware, cookies or actor context.
    this.server = createServer({ maxHeaderSize: 8192 }, (req, res) => { void this.handle(req, res); });
    this.server.requestTimeout = 5000; this.server.headersTimeout = 5000; this.server.keepAliveTimeout = 1000;
    await new Promise<void>((resolve, reject) => { this.server!.once('error', reject); this.server!.listen(port, host, () => { this.server!.off('error', reject); resolve(); }); });
  }
  async onModuleDestroy(): Promise<void> {
    if (!this.server) return; this.server.closeAllConnections(); await new Promise<void>(resolve => this.server!.close(() => resolve()));
  }
  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      if (req.url === '/healthz' && req.method === 'GET') { this.json(res, { status: 'ok' }); return; }
      const match = /^\/(scrape|catalog)\/([a-f\d-]{36})(\/validate)?(?:\?([^#]*))?$/.exec(req.url || '');
      if (!match || match[1] === 'scrape' && (match[3] || match[4]) || match[3] && req.method !== 'POST' || !match[3] && req.method !== 'GET') throw new BadRequestException({ code: 'INVALID_METRICS_BRIDGE_PATH' });
      const cid = metricsId(match[2])!;
      const authorizationCount = req.rawHeaders.filter((_value, index) => index % 2 === 0 && req.rawHeaders[index].toLowerCase() === 'authorization').length;
      if (req.headers.cookie !== undefined || authorizationCount !== 1 || typeof req.headers.authorization !== 'string' || !/^Bearer [A-Za-z\d_-]{43,128}$/.test(req.headers.authorization)) throw new UnauthorizedException();
      const identity = await this.credentials.validate(req.headers.authorization.slice(7), cid, match[1] === 'scrape' ? 'native_scrape' : 'collector_catalog', 'bff');
      const rate = await this.redis.rateLimit(`metrics-bridge:${identity.id}`, 120, 1000);
      if (!rate.allowed) throw new HttpException({ code: 'METRICS_BRIDGE_RATE_LIMITED' }, 429);
      if (match[1] === 'scrape') {
        const text = await this.scrape(cid, identity); res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(text); return;
      }
      if (match[3]) {
        if (match[4] || !/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) throw new BadRequestException();
        this.json(res, await this.validateBatch(cid, identity, await this.body(req))); return;
      }
      const parameters = new URLSearchParams(match[4] || '');
      if ([...parameters.keys()].some(key => parameters.getAll(key).length !== 1)) throw new BadRequestException({ code: 'DUPLICATE_METRICS_QUERY' });
      const query = Object.fromEntries(parameters.entries()); exactKeys(query, ['cursor', 'size']);
      const size = query.size === undefined ? 100 : Number(query.size);
      if (!Number.isInteger(size) || size < 1 || size > 100 || query.cursor !== undefined && typeof query.cursor !== 'string') throw new BadRequestException();
      await this.catalog.ensureFresh(cid);
      const page = await this.repository.catalog(cid, { cursor: query.cursor as string | undefined, size, includeConsumers: true, maxLatenessMs: 300000 });
      await this.credentials.assertCurrent(identity); this.json(res, page);
    } catch (error) {
      const status = error instanceof HttpException ? error.getStatus() : 503;
      if (!res.headersSent) res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ error: { code: status === 401 ? 'METRICS_TOKEN_INVALID' : 'METRICS_BRIDGE_REQUEST_FAILED' } }));
    }
  }
  async scrape(cid: string, identity: Readonly<MetricsCredentialIdentity>): Promise<string> {
    await this.credentials.assertCurrent(identity);
    if (identity.clusterId !== cid || identity.purpose !== 'native_scrape') throw new UnauthorizedException();
    await this.catalog.ensureFresh(cid); const nodeId = await this.kong.transportScope(cid), beforeNode = await this.catalog.nodeIdentity(cid);
    let knownNode = await this.db.one<any>('SELECT observed_kong_node_id FROM metrics_nodes WHERE cluster_id=$1 AND node_id=$2', [cid, nodeId]);
    if (knownNode?.observed_kong_node_id !== beforeNode) { await this.catalog.scan(cid); knownNode = await this.db.one<any>('SELECT observed_kong_node_id FROM metrics_nodes WHERE cluster_id=$1 AND node_id=$2', [cid, nodeId]); }
    if (knownNode?.observed_kong_node_id !== beforeNode) throw new ServiceUnavailableException({ code: 'METRICS_NATIVE_NODE_UNVERIFIED' });
    const initial = await this.settings.get(cid);
    if (initial.state !== 'ready' || !initial.lastVerifiedAt || Date.now() - Date.parse(initial.lastVerifiedAt) > initial.maxAgeMs) throw new ServiceUnavailableException({ code: 'METRICS_CATALOG_UNAVAILABLE' });
    const text = await this.execution.runSystemRead(cid, 'metrics-scrape', () => this.kong.requestMetricsText(cid), { paths: ['/metrics'], maxCalls: 3, maxPages: 1, maxRecords: 1, maxBytes: 2 * 1024 * 1024, timeoutMs: 5000 });
    if (await this.catalog.nodeIdentity(cid) !== beforeNode) throw new ConflictException({ code: 'METRICS_NATIVE_NODE_CHANGED' });
    const result: PrometheusSample[] = [], resolved = new Map<string, MetricsAssignment | null>(), epochStarts = new Map<string, MetricsAssignment>();
    for (const sample of parsePrometheusText(text)) {
      if (!Object.hasOwn(sample.labels, 'service')) { result.push({ ...sample, labels: { ...sample.labels, cluster_id: cid, node_id: nodeId } }); continue; }
      const key = JSON.stringify([sample.labels.service, sample.labels.route]);
      if (!resolved.has(key)) {
        const resolution = await this.repository.resolvePair(cid, sample.labels.service, sample.labels.route, nodeId);
        if (resolution.catalogRevision !== initial.catalogRevision) throw new ConflictException({ code: 'METRICS_CATALOG_CHANGED' });
        resolved.set(key, resolution.assignment);
      }
      const assignment = resolved.get(key), { service: _service, route: _route, ...labels } = sample.labels;
      if (!assignment) { result.push({ ...sample, labels: { ...labels, cluster_id: cid, node_id: nodeId, attribution: 'unassigned' } }); continue; }
      epochStarts.set(assignment.epoch_id, assignment);
      result.push({ ...sample, labels: { ...labels, cluster_id: cid, node_id: nodeId, service_id: assignment.service_id || '', route_id: assignment.route_id || '', workspace_id: assignment.workspace_id, membership_epoch: assignment.epoch_id } });
    }
    // Only unassigned pairs lose their native labels; combine them to keep valid
    // exposition without making any workspace attribution claim.
    const unique = new Map<string, PrometheusSample>();
    for (const sample of result) { const key = JSON.stringify([sample.name, Object.entries(sample.labels).sort()]); const old = unique.get(key); if (old && sample.labels.attribution !== 'unassigned') throw new ServiceUnavailableException({ code: 'DUPLICATE_NATIVE_METRICS' }); if (old) old.value += sample.value; else unique.set(key, sample); }
    let encoded = encodePrometheusText([...unique.values()]);
    encoded += '# TYPE kongos_metrics_epoch_started_timestamp_seconds gauge\n';
    for (const epoch of epochStarts.values()) encoded += `kongos_metrics_epoch_started_timestamp_seconds{cluster_id="${escapePrometheusLabel(cid)}",node_id="${escapePrometheusLabel(nodeId)}",service_id="${epoch.service_id || ''}",route_id="${epoch.route_id || ''}",workspace_id="${epoch.workspace_id}",membership_epoch="${epoch.epoch_id}"} ${Date.parse(epoch.valid_from) / 1000}\n`;
    const after = await this.settings.get(cid);
    if (after.catalogRevision !== initial.catalogRevision || after.state !== 'ready' || !after.lastVerifiedAt || Date.now() - Date.parse(after.lastVerifiedAt) > after.maxAgeMs || after.credentialGeneration !== identity.generation) throw new ConflictException({ code: 'METRICS_CATALOG_CHANGED' });
    const finalProof = await this.repository.currentAllowedEpochs(cid, { expectedCatalogRevision: initial.catalogRevision, authorizedServiceIds: [], authorizedRouteIds: [], authorizedConsumerIds: [] });
    if (finalProof.blocked || finalProof.warnings.length) throw new ConflictException({ code: 'METRICS_CATALOG_CHANGED' });
    await this.credentials.assertCurrent(identity);
    if (Buffer.byteLength(encoded) > 2 * 1024 * 1024) throw new ConflictException({ code: 'METRICS_SCRAPE_BUDGET_EXHAUSTED' }); return encoded;
  }
  async validateBatch(cid: string, identity: Readonly<MetricsCredentialIdentity>, body: unknown): Promise<any> {
    if (identity.clusterId !== cid || identity.purpose !== 'collector_catalog') throw new UnauthorizedException();
    exactKeys(body, ['refs']); if (!Array.isArray(body.refs) || body.refs.length > 256 || Buffer.byteLength(JSON.stringify(body)) > 128 * 1024) throw new BadRequestException({ code: 'INVALID_METRICS_EVENT_BATCH' });
    const items = body.refs.map((ref: any, index: number) => {
      exactKeys(ref, ['serviceId', 'routeId', 'consumerId', 'startedAt', 'endedAt', 'epochIds']);
      const serviceId = metricsId(ref.serviceId)!, routeId = metricsId(ref.routeId)!, consumerId = metricsId(ref.consumerId, true);
      if (!Number.isSafeInteger(ref.startedAt) || !Number.isSafeInteger(ref.endedAt) || (ref.startedAt as number) < 0 || (ref.endedAt as number) < (ref.startedAt as number) || (ref.endedAt as number) - (ref.startedAt as number) > 300000 || (ref.endedAt as number) > Date.now() + 1000) throw new BadRequestException({ code: 'INVALID_METRICS_EVENT_INTERVAL' });
      let epochIds: string[] | undefined; if (ref.epochIds !== undefined) { exactKeys(ref.epochIds, ['route', 'consumer']); epochIds = Object.values(ref.epochIds).map(value => metricsId(value)!); }
      return { index, serviceId, routeId, consumerId, startedAt: ref.startedAt as number, endedAt: ref.endedAt as number, epochIds };
    });
    await this.credentials.assertCurrent(identity);
    const result = await this.repository.validateEventBindings(cid, { credentialGeneration: identity.generation, items });
    await this.credentials.assertCurrent(identity);
    return { catalogRevision: result.catalogRevision, credentialGeneration: result.credentialGeneration, items: result.items.map(item => {
      const request = items[item.index]; if (!request) throw new ServiceUnavailableException();
      if (item.quality !== 'verified' || !item.routeEpoch) return { index: item.index, quality: item.quality, reasonCode: item.reasonCode || 'METRICS_EVENT_UNASSIGNED' };
      const epochs = [item.routeEpoch, ...(item.consumerEpoch ? [item.consumerEpoch] : [])];
      return { index: item.index, quality: 'verified', clusterId: cid, nodeId: item.routeEpoch.node_id, serviceId: request.serviceId, routeId: request.routeId, ...(item.consumerEpoch ? { consumerId: request.consumerId, consumerEpochId: item.consumerEpoch.epoch_id } : {}), workspaceId: item.routeEpoch.workspace_id, epochId: item.routeEpoch.epoch_id, validFrom: Math.max(...epochs.map(epoch => Date.parse(epoch.valid_from))), validUntil: Math.min(...epochs.map(epoch => Date.parse(epoch.closed_at || epoch.verified_until))) };
    }) };
  }
  private json(res: ServerResponse, value: unknown) { res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); }
  private body(req: IncomingMessage): Promise<unknown> {
    return new Promise((resolve, reject) => { let bytes = 0; const chunks: Buffer[] = []; const timer = setTimeout(() => { req.destroy(); reject(new BadRequestException()); }, 5000); req.on('data', chunk => { bytes += chunk.length; if (bytes > 128 * 1024) { clearTimeout(timer); reject(new BadRequestException()); req.destroy(); return; } chunks.push(Buffer.from(chunk)); }); req.on('error', error => { clearTimeout(timer); reject(error); }); req.on('end', () => { clearTimeout(timer); try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new BadRequestException()); } }); });
  }
}
