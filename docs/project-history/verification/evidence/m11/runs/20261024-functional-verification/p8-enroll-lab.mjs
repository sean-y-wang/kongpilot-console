// LAB-ONLY native equivalent of deploy/scripts/enroll-metrics.mjs (no compose). Never prints tokens.
import { execFileSync } from 'node:child_process';
import { writeFileSync, chmodSync } from 'node:fs';
const M = await import('$REPO/deploy/scripts/metrics-material.mjs');
const api = '$REPO/apps/console-api', dir = '$PRIVATE/metrics/prometheus';
const cli = input => JSON.parse(execFileSync('node', ['dist/infrastructure/metrics-enroll.js'], { cwd: api, input: JSON.stringify(input), encoding: 'utf8' }).trim());
const nodeId = cid => JSON.parse(execFileSync('node', ['-e', "const {Pool}=require('pg');const {transportScopeFor}=require('./dist/infrastructure/kong/transport-scope.js');(async()=>{const p=new Pool({connectionString:process.env.DATABASE_URL});const q=await p.query('SELECT admin_url,transport_scope FROM clusters WHERE id=$1',[process.argv[1]]);const r=q.rows[0];console.log(JSON.stringify(transportScopeFor(r.admin_url,r.transport_scope)));await p.end();})()", cid], { cwd: api, encoding: 'utf8' }).trim());
const rows = [];
for (const cid of process.argv.slice(2)) {
  const status = cli({ action: 'status', clusterId: cid });
  const m = M.createMetricsMaterial(cid, (status.generation || 0) + 1);
  const r = cli(m.enrollment);
  if (!r.enrolled || r.generation !== m.enrollment.generation) throw new Error('ENROLL_FAILED');
  for (const [p, t] of [['native_scrape', m.prometheus.native], ['collector_scrape', m.prometheus.collector]]) { const f = `${dir}/${cid}-${p}.token`; try { chmodSync(f, 0o600); } catch {} writeFileSync(f, t + '\n', { mode: 0o400 }); chmodSync(f, 0o444); }
  rows.push({ clusterId: cid, nodeId: nodeId(cid), generation: r.generation });
}
const cfg = M.prometheusConfiguration(rows).replaceAll("'metrics-bff:9092'", "'127.0.0.1:39092'").replaceAll("'telemetry-collector:9093'", "'127.0.0.1:39093'");
writeFileSync(`${dir}/prometheus.yml`, cfg); chmodSync(`${dir}/prometheus.yml`, 0o644);
console.log(JSON.stringify({ enrolled: rows.map(r => ({ clusterId: r.clusterId, generation: r.generation })), secretsPrinted: false }));
