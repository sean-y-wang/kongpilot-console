import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

const env = Object.fromEntries(readFileSync('.env', 'utf8').trim().split('\n').filter(line => line && !line.startsWith('#')).map(line => { const index = line.indexOf('='); return [line.slice(0,index), line.slice(index+1)]; }));
const base = process.env.CONSOLE_BASE_URL || 'http://127.0.0.1:8080';
const traces = [];
let cookies = '';
let csrf = '';
async function api(path, method='GET', body) {
  const response = await fetch(`${base}/api/v1${path}`, { method, signal: AbortSignal.timeout(15000), headers: { 'content-type': 'application/json', origin: base, ...(cookies ? { cookie: cookies, 'x-csrf-token': csrf } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const payload = await response.json();
  traces.push({ method, path, status: response.status, requestId: payload.meta?.requestId || payload.error?.requestId || null });
  if (!response.ok) throw new Error(`BFF ${method} ${path} returned ${response.status}`);
  return { response, data: payload.data };
}
try {
  const login = await api('/auth/login', 'POST', { username: env.BOOTSTRAP_ADMIN_USERNAME, password: env.BOOTSTRAP_ADMIN_PASSWORD });
  cookies = login.response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
  csrf = login.data.csrfToken;
  const cluster = (await api('/clusters')).data.find(item => item.admin_url === 'http://kong:8001');
  if (!cluster) throw new Error('Default Kong cluster is absent');
  const existing = (await api(`/clusters/${cluster.id}/data-sources`)).data;
  const sources = [];
  for (const item of [{name:'Prometheus 演示数据源',type:'prometheus',base_url:'http://prometheus:9090'}, {name:'Loki 演示数据源',type:'loki',base_url:'http://loki:3100'}]) {
    const source = existing.find(value => value.name === item.name) || (await api(`/clusters/${cluster.id}/data-sources`, 'POST', item)).data;
    const probe = (await api(`/clusters/${cluster.id}/data-sources/${source.id}/probe`, 'POST')).data;
    sources.push({ id: source.id, name: source.name, type: source.type, status: probe.status, latencyMs: probe.latency_ms, probedAt: probe.probed_at });
  }
  mkdirSync(resolve('artifacts/M0'), {recursive:true});
  const allPassed = sources.every(source => source.status === 'healthy');
  writeFileSync(resolve('artifacts/M0/observability-verification.json'), JSON.stringify({ observedAt: new Date().toISOString(), clusterId: cluster.id, source: 'real Prometheus 3.3.1 and Loki 3.5.0 Docker containers', sources, traces, allPassed }, null, 2) + '\n');
  console.log(`${sources.filter(source => source.status === 'healthy').length}/${sources.length} real observability data sources healthy; evidence artifacts/M0/observability-verification.json`);
  if (!allPassed) process.exitCode=1;
} finally {
  if (cookies) await api('/auth/logout', 'POST').catch(() => {});
}
