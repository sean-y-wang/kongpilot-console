import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PrometheusProvider } from '../../apps/console-api/src/modules/vitals/providers/prometheus.provider';
import { LokiProvider } from '../../apps/console-api/src/modules/vitals/providers/loki.provider';
import { MetricsQueryBudget } from '../../apps/console-api/src/modules/vitals/providers/query-budget';
import { MetricsSourceService } from '../../apps/console-api/src/modules/vitals/providers/metrics-source.service';
import { fixedPromql, epochSelector } from '../../apps/console-api/src/modules/vitals/providers/promql';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { parseVitalsQuery } from '../../apps/console-api/src/modules/vitals/vitals-query';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn() }));
const transport = vi.mocked(outboundJson);
const cid = '721bfeda-dc12-4d7a-b33e-06b2879a7ead', wid = 'a109e333-40a0-4965-966b-6b810f54e9b6';
const serviceId = '14368d69-dd76-46f6-b490-583893b13cba', routeId = 'cd7ce64b-e7b0-4b39-9086-c55b7b5f8d9e';
const consumerId = 'f4095396-0771-4b02-9f09-2739a1809c0d', epochId = '40246f11-52ee-43c2-8ca9-71976d078848';
const now = Date.parse('2026-10-10T12:00:00.000Z'), window = parseVitalsQuery({ start: '2026-10-10T11:55:00Z', end: '2026-10-10T12:00:00Z', step: 15 }, now);
const first = Date.parse(window.start), seconds = first/1000;
const source: any = { id: serviceId, name: 'metrics', type: 'prometheus', baseUrl: 'http://registered-prom:9090', auth: { type: 'bearer', token: 'SYNTHETIC-SOURCE-CREDENTIAL' }, revision: 1 };
const epoch = (type='routes') => ({ epoch_id: epochId, cluster_id: cid, node_id: 'a'.repeat(64), entity_type: type, entity_id: type==='consumers'?consumerId:routeId, workspace_id: wid, service_id: type==='consumers'?null:serviceId, route_id: type==='consumers'?null:routeId, consumer_id: type==='consumers'?consumerId:null, tags: [], valid_from: new Date(first-60000).toISOString(), verified_until: new Date(now+15000).toISOString(), closed_at: null, quality: 'verified' });
const scope = (): any => ({ workspaceId: wid, mode: 'workspace', version: 'permission-1', wholeCluster: false, epochs: [epoch()], consumerPairEpochs: [], serviceNames: new Map([[serviceId,'authorized-service']]), consumerNames: new Map([[consumerId,'authorized-consumer']]) });
const body = (result: any[], type='matrix') => ({ status: 200, body: { status: 'success', data: { resultType: type, result } } });
const rangeRow = (value: string, metric: any={}) => ({ metric, values: [[seconds, value]] });
const instantRow = (value: string, metric: any={}) => ({ metric, value: [now/1000, value] });
beforeEach(() => { transport.mockReset(); vi.stubEnv('CONSOLE_ENCRYPTION_KEY','bc'.repeat(32)); });
afterEach(() => vi.unstubAllEnvs());

describe('M5 independent actual Prometheus/Loki providers and fixed query boundary', () => {
  it('keeps explicit zero and NaN/Inf gaps while rejecting malformed numeric strings', async () => {
    const provider = new PrometheusProvider();
    for (const [input, expected] of [['0',0],['1e3',1000],['NaN',null],['+Inf',null],['-Inf',null]] as const) { transport.mockResolvedValue(body([rangeRow(input)])); expect((await provider.range(source, 'fixed-query', window, new MetricsQueryBudget()))[0].values).toEqual([[first,expected]]); }
    for (const input of ['', ' ', '0x10', 'not-a-number', '-1', '1e9999']) {
      transport.mockResolvedValue(body([rangeRow(input)])); await expect(provider.range(source, 'fixed-query', window, new MetricsQueryBudget())).rejects.toMatchObject({ response: { code: 'INVALID_METRICS_RESPONSE' } });
      transport.mockResolvedValue(body([instantRow(input)], 'vector')); await expect(provider.instant(source, 'fixed-query', window, new MetricsQueryBudget())).rejects.toMatchObject({ response: { code: 'INVALID_METRICS_RESPONSE' } });
    }
  });
  it('rejects duplicate, off-grid, out-of-range timestamps and more than800 samples rather than truncating', async () => {
    const provider = new PrometheusProvider();
    for (const values of [[[seconds,'1'],[seconds,'2']],[[seconds+1,'1']],[[seconds-15,'1']],Array(801).fill([seconds,'1'])]) { transport.mockResolvedValue(body([{metric:{},values}])); await expect(provider.range(source,'fixed',window,new MetricsQueryBudget())).rejects.toBeDefined(); }
  });
  it('shares query bytes/series budget across provider calls and limits the transport to its remaining bytes', async () => {
    const provider = new PrometheusProvider(), budget = new MetricsQueryBudget({ calls: 18, bytes: 1000, series: 64, points: 51200 });
    transport.mockResolvedValue({ ...body([rangeRow('0')]), bytes: 600 }); await provider.range(source,'fixed',window,budget);
    transport.mockResolvedValue({ ...body([rangeRow('0')]), bytes: 401 }); await expect(provider.range(source,'fixed',window,budget)).rejects.toBeDefined();
    expect(transport.mock.calls[0][9]).toBe(1000); expect(transport.mock.calls[1][9]).toBe(400);
    transport.mockResolvedValue(body(Array.from({length:65},()=>rangeRow('0')))); await expect(provider.range(source,'fixed',window,new MetricsQueryBudget())).rejects.toBeDefined();
  });
  it('uses current immutable epoch selectors and a baseline guard rather than current business-tag labels', () => {
    const selected = scope(), query = fixedPromql(cid,selected,window);
    expect(query.status).toContain(`workspace_id="${wid}"`); expect(query.status).toContain(`membership_epoch=~"${epochId}"`); expect(query.status).toContain('kongos_metrics_epoch_started_timestamp_seconds'); expect(query.status).toContain('>= 60');
    expect(query.status).not.toContain('team:'); expect(epochSelector(cid,{...selected,epochs:[]})).toContain('a^'); expect(epochSelector(cid,{...selected,mode:'cluster'})).not.toContain('workspace_id');
  });
  it('aggregates status codes, preserves latency milliseconds and filters TopN by authorized identity', async () => {
    transport.mockImplementation(async (_base,path,_method,_body,query) => {
      const text = String(query?.query);
      if (text.includes('sum by(code)')) return body([rangeRow('2',{code:'200'}),rangeRow('0',{code:'404'})]);
      if (text.includes('histogram_quantile')) return body([rangeRow('1500')]);
      if (text.includes('sum by(type)')) return body([rangeRow('1024',{type:'ingress'}),rangeRow('NaN',{type:'egress'})]);
      if (text.includes('topk')) return body([instantRow('2',{service_id:serviceId}),instantRow('777',{service_id:consumerId})],'vector');
      throw new Error('Unexpected provider query');
    });
    const result=await new PrometheusProvider().evaluate(source,cid,scope(),window,new MetricsQueryBudget(),false);
    expect(result.series.qps[0].value).toBe(2); expect(result.series.status4xx[0].value).toBe(0); expect(result.series.latencyRequestP95[0].value).toBe(1500); expect(result.series.bandwidthIngress[0].value).toBe(1024); expect(result.series.bandwidthEgress[0].value).toBeNull();
    expect(result.topN.services).toEqual([{id:serviceId,name:'authorized-service',value:2}]); expect(result.nodes).toEqual([]); expect(transport.mock.calls).toHaveLength(12);
    expect(transport.mock.calls.every(call=>call[0]===source.baseUrl && ['/api/v1/query_range','/api/v1/query'].includes(call[1]))).toBe(true);
  });
  it('does not request cluster node metrics for a scoped reader and does not query traffic for empty assignments', async () => {
    transport.mockResolvedValue(body([])); const result=await new PrometheusProvider().evaluate(source,cid,{...scope(),epochs:[]},window,new MetricsQueryBudget(),false);
    expect(transport).not.toHaveBeenCalled(); expect(result.series.qps.every(point=>point.value===null)).toBe(true); expect(result.reasonCodes).toContain('NO_VERIFIED_TRAFFIC_ASSIGNMENT');
  });
  it('uses fixed Loki API paths/ISO times and blanks rate windows crossing newly opened attribution epochs', async () => {
    transport.mockImplementation(async (_base,path,_method,_body,query) => body(path.endsWith('query')?[]:[rangeRow('1',String(query?.query).includes('sum by(code)')?{code:'200'}:String(query?.query).includes('bytes_ingress')?{type:'ingress'}:{})],path.endsWith('query')?'vector':'matrix'));
    const selected=scope(); selected.epochs[0].valid_from=new Date(first).toISOString();
    const result=await new LokiProvider().evaluate({...source,type:'loki'},cid,selected,window,new MetricsQueryBudget(),true);
    expect(result.series.qps[0].value).toBeNull(); expect(result.reasonCodes).toContain('LOKI_NODE_METRICS_UNSUPPORTED');
    expect(transport.mock.calls.every(call=>call[1].startsWith('/loki/api/v1/'))).toBe(true); expect(transport.mock.calls[0][4].start).toBe(window.start); expect(transport.mock.calls[0][4].end).toBe(window.end);
  });
});

describe('M5 independent source safe projections and query-current connection races', () => {
  it('provides monitoring-only safe source options without URL/auth fields and rejects revision/endpoint/secret changes', async () => {
    const state:any={id:serviceId,name:'chosen',type:'prometheus',enabled:true,last_status:'healthy',revision:1,base_url:'http://prom:9090',auth_secret:null};
    const db:any={one:vi.fn(async()=>structuredClone(state)),query:vi.fn(async()=>[structuredClone(state)])},secrets=new SecretService(),sources=new MetricsSourceService(db,secrets);
    expect(await sources.list(cid)).toEqual([{id:serviceId,name:'chosen',type:'prometheus',status:'healthy',availability:'available'}]);
    const old=await sources.read(cid,serviceId); expect(sources.public(old)).not.toHaveProperty('baseUrl'); expect(sources.public(old)).not.toHaveProperty('auth');
    state.revision++; await expect(sources.assertCurrent(cid,old)).rejects.toMatchObject({response:{code:'METRICS_SOURCE_CHANGED'}});
    state.revision=1;state.base_url='http://other:9090'; await expect(sources.assertCurrent(cid,old)).rejects.toMatchObject({status:409});
  });
});
