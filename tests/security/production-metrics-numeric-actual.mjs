import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { ProductionHarness } from './lib/production-http-harness.mjs';
import { productionProxy } from './lib/production-proxy.mjs';
import { compareMonitoringPoints, oracleMatrixPoints, finitePrometheusValue } from './lib/m5-oracle.mjs';
import { compareRealNativePrometheus } from './lib/m5-native-oracle.mjs';
import { durableProductionJson } from './lib/production-ui-storage.mjs';

const output = 'artifacts/Production/root-production-metrics-same-window-numeric-actual.json';
if (process.env.PRODUCTION_METRICS_NUMERIC_EXCLUSIVE_READY !== 'true' || existsSync(output)) throw Error('PRODUCTION_METRICS_NUMERIC_HANDOFF_REQUIRED');
const h = new ProductionHarness({ resume: true });
if (!h.state.productionMetricsStarted) throw Error('PRODUCTION_METRICS_SETUP_REQUIRED');
const actor = h.state.sessions.bootstrap, area = h.state.scope, fixture = h.state.nativeFixture;
await h.refresh(actor);
const originalCheck = h.check.bind(h);
const oracle = { check: (ok, id, label) => originalCheck(ok, `${id}: ${label}`) };
const internal = (origin, path, token) => {
  if (!['http://prometheus:9090', 'http://metrics-bff:9092'].includes(origin)) throw Error('METRICS_FIXED_INTERNAL_ORIGIN_REQUIRED');
  const program = `const fs=require('fs'),p=JSON.parse(fs.readFileSync(0,'utf8'));fetch(p.url,{headers:p.token?{Authorization:'Bearer '+p.token}:{},redirect:'manual',signal:AbortSignal.timeout(15000)}).then(async r=>{const text=await r.text();if(text.length>8388608)throw Error();process.stdout.write(JSON.stringify({status:r.status,data:JSON.parse(text)}));}).catch(()=>process.exit(1));`;
  let value;
  try { value = JSON.parse(execFileSync('docker', ['--host=unix:///dev/shm/kongos-production-ram-m08-20261012-a3/run/docker-production.sock', 'exec', '-i', 'kongos-prod-m08-20261012-a3-console-api-1', 'node', '-e', program], { input: JSON.stringify({ url: origin + path, token }), stdio: ['pipe', 'pipe', 'pipe'], timeout: 20000, maxBuffer: 10 * 1024 ** 2 })); }
  catch { throw Error('PRODUCTION_FIXED_INTERNAL_METRICS_READ_FAILED'); }
  if (value.status !== 200) throw Error('PRODUCTION_INTERNAL_METRICS_NON_200');
  return value.data;
};
oracle.prometheus = (query, { time, start, end, step } = {}) => {
  const range = start !== undefined, params = new URLSearchParams({ query, ...(range ? { start: String(start), end: String(end), step: String(step) } : { time: String(time) }) });
  const r = internal('http://prometheus:9090', `/api/v1/${range ? 'query_range' : 'query'}?${params}`);
  if (r.status !== 'success') throw Error('PRODUCTION_REAL_PROMETHEUS_QUERY_FAILED');
  return r.data;
};
const privateRead = `const fs=require('fs');const d=JSON.parse(fs.readFileSync('/run/kongos-private/production/metrics/collector/credentials.json'));const c=d.clusters.find(c=>c.clusterId===process.argv[1]);if(!c)process.exit(1);process.stdout.write(JSON.stringify({catalogToken:c.catalogToken}));`;
const catalogToken = JSON.parse(execFileSync('docker', ['--host=unix:///var/run/docker.sock', 'exec', 'kongos-ram-tool-m08-20261012-a3', 'node', '-e', privateRead, area.cid], { stdio: ['ignore', 'pipe', 'pipe'] })).catalogToken;
h.state.secrets.push(catalogToken); h.save();
// Real, separate 4xx and 5xx routes make absent status families measurable.
const routes = [{ path: fixture.routes['key-auth'].proxyPath + '/echo', status: 200 }];
for (const status of [404, 500]) {
  const path = `/m8/${h.state.testTag}/metrics-${status}`;
  const prior=h.state.requests.filter(p=>p.method==='POST'&&p.path===`/api/v1/clusters/${area.cid}/entities/routes`&&p.body?.name===`${h.state.testTag}-metrics-${status}`);
  if(prior.length>1||prior.length===1&&(prior[0].state!=='response_observed'||prior[0].status!==201))throw Error('METRICS_ORIGINAL_NATIVE_CREATE_NOT_PROVEN');
  const route = prior.length?prior[0].responseData.entity:(await h.request(actor, `/api/v1/clusters/${area.cid}/entities/routes?workspaceId=${area.wid}`, 'POST', { name: `${h.state.testTag}-metrics-${status}`, paths: [path], protocols: ['http'], service: { id: fixture.service.id }, tags: [h.state.testTag] })).data.entity;
  if(!prior.length)await h.request(actor, `/api/v1/clusters/${area.cid}/entities/plugins?workspaceId=${area.wid}`, 'POST', { name: 'request-termination', route: { id: route.id }, config: { status_code: status, message: 'production metrics fixture' }, tags: [h.state.testTag] });
  routes.push({ path: path + '/echo', status });
}
const started = Date.now(); let requests = 0;
while (Date.now() - started < 85000) {
  for (const route of routes) {
    await productionProxy(h, fixture, route.path, { headers: { apikey: fixture.inputs['key-auth'].key }, expected: route.status }); requests++;
  }
  await new Promise(resolve => setTimeout(resolve, 1000));
}
const end = Math.floor(Date.now() / 1000) * 1000, window = { start: new Date(end - 300000).toISOString(), end: new Date(end).toISOString(), step: 15 };
h.state.productionMetricsWindow = { ...window, requests, startedAt: new Date(started).toISOString() }; h.save();
await new Promise(resolve => setTimeout(resolve, 16000));
const epochs = []; let cursor;
for (let i = 0; i < 100; i++) {
  const params = new URLSearchParams({ size: '100', ...(cursor ? { cursor } : {}) });
  const r = internal('http://metrics-bff:9092', `/catalog/${area.cid}?${params}`, catalogToken);
  if (r.complete !== true || r.blocked !== false || !Array.isArray(r.items)) throw Error('PRODUCTION_COMPLETE_CURRENT_CATALOG_REQUIRED');
  epochs.push(...r.items); if (epochs.length > 10000) throw Error('PRODUCTION_CATALOG_BUDGET');
  cursor = r.nextCursor; if (!cursor) break;
}
if (cursor) throw Error('PRODUCTION_CATALOG_PAGE_BUDGET');
const sourceId = h.state.productionSources.find(s => s.type === 'prometheus').id;
const overview = async routeId => (await h.request(actor, `/api/v1/clusters/${area.cid}/vitals/overview?${new URLSearchParams({ workspaceId: area.wid, sourceId, serviceId: fixture.service.id, ...window, ...(routeId ? { routeId } : {}) })}`)).data;
const service = await overview(), serviceComparison = compareRealNativePrometheus(oracle, service, { clusterId: area.cid, workspaceId: area.wid, serviceId: fixture.service.id, epochs });
const routeId=fixture.routes['key-auth'].id,route=await overview(routeId),current=epochs.filter(e=>e.closed_at===null&&e.entity_type==='routes'&&e.workspace_id===area.wid&&e.service_id===fixture.service.id&&e.route_id===routeId);
if(!current.length)throw Error('PRODUCTION_ORIGINAL_ROUTE_EPOCH_REQUIRED');
const selector=`cluster_id=${JSON.stringify(area.cid)},workspace_id=${JSON.stringify(area.wid)},service_id=${JSON.stringify(fixture.service.id)},route_id=${JSON.stringify(routeId)},membership_epoch=~${JSON.stringify(current.map(e=>e.epoch_id).join('|'))}`,w=route.timeWindow;
const starts=new Map(oracle.prometheus(`kongos_metrics_epoch_started_timestamp_seconds{${selector}}`,{time:Date.parse(w.end)/1000}).result.map(r=>[r.metric.membership_epoch,finitePrometheusValue(r.value[1])]));
const rates=oracle.prometheus(`rate(kong_http_status{${selector}}[${w.rateWindowSeconds}s])`,{start:Date.parse(w.start)/1000,end:Date.parse(w.end)/1000,step:w.step}).result.map(r=>({...r,values:r.values.map(([t,v])=>[t,starts.get(r.metric.membership_epoch)!==undefined&&t-starts.get(r.metric.membership_epoch)>=w.rateWindowSeconds?v:'NaN'])}));
const routeComparison={sameEvaluationAt:w.end,comparisons:{qps:compareMonitoringPoints(route.series.qps.map(p=>[p.ts,p.value]),oracleMatrixPoints(rates))}};
if(routeComparison.comparisons.qps.compared===0)throw Error('PRODUCTION_ROUTE_NUMERIC_SAMPLES_REQUIRED');
h.state.productionMetricsNumericComplete = true; h.save();
const result = { performedAt: new Date().toISOString(), allPassed: true, actualProvider: 'Prometheus', actualTrafficRequests: requests, sourceId, clusterId: area.cid, workspaceId: area.wid, actualServiceDrilldown: true, actualRouteDrilldown: true, serviceComparison, routeComparison, sameWindow: window, consumerLokiFreshComparisonTested: false, historicalM5EvidenceRetained: true, secretsPublished: false };
durableProductionJson(output, result, true, 0o644);
console.log(JSON.stringify({ allPassed: true, actualNumericSeriesCompared: Object.keys(serviceComparison.comparisons).length + Object.keys(routeComparison.comparisons).length, requests }));
