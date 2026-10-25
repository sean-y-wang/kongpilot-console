import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, mkdirSync, writeFileSync, renameSync, chmodSync, chownSync, statSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { createMetricsMaterial, digest, prometheusConfiguration } from './metrics-material.mjs';
import { isUuid } from '../metrics-collector/sanitize.mjs';
import { readTestReference, captureTestMaterial } from './metrics-test-reference.mjs';
import {metricsOperationOptions,metricsComposeArguments,metricsOperationEnvironment,productionMetricsConfiguration} from './metrics-operation-options.mjs';

let options;
try { options=metricsOperationOptions(process.argv.slice(2),'enroll'); } catch { console.error('METRICS_OPERATION_ARGUMENTS_INVALID'); process.exit(2); }
const {rotate,captureTestReference,selected}=options;
if (selected.some(id => !isUuid(id)) || (!selected.length && !options.discover)) { console.error('Specify --cluster=<UUID> or --discover; rotation requires --rotate-confirmed.'); process.exit(2); }
const compose=metricsComposeArguments(options,'enroll');
const dockerEnvironment=metricsOperationEnvironment(options,process.env);
const docker=(args,extra={})=>execFileSync('docker',args,{encoding:'utf8',stdio:['pipe','pipe','pipe'],env:dockerEnvironment,...extra});
const directory = options.metricsDirectory;
const manifestFile = resolve(directory, 'manifest.json');
function capture(material) {
  if (!captureTestReference) return;
  captureTestMaterial(material);
}
function cli(input) {
  const output = docker([...compose, 'exec', '-T', 'console-api', 'node', 'dist/infrastructure/metrics-enroll.js'], { input: JSON.stringify(input), timeout: 20_000 });
  return JSON.parse(output.trim());
}
function nodeIdFor(clusterId) {
  const code = "const {Pool}=require('pg');const fs=require('fs');const {transportScopeFor}=require('./dist/infrastructure/kong/transport-scope.js');(async()=>{const cid=JSON.parse(fs.readFileSync(0,'utf8')).clusterId;const p=new Pool({connectionString:process.env.DATABASE_URL});try{const q=await p.query('SELECT admin_url,transport_scope FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);const row=q.rows[0];console.log(JSON.stringify({nodeId:row?transportScopeFor(row.admin_url,row.transport_scope):null}));}finally{await p.end();}})().catch(()=>process.exit(1));";
  const value = JSON.parse(docker([...compose, 'exec', '-T', 'console-api', 'node', '-e', code], { input: JSON.stringify({ clusterId }), timeout: 15_000 }));
  if (!/^[a-f0-9]{64}$/.test(value.nodeId || '')) throw new Error('METRICS_NODE_ID_NOT_REGISTERED');
  return value.nodeId;
}
function directoryFor(path, uid = 0) { mkdirSync(path, { recursive: true, mode: 0o700 }); chmodSync(path, 0o700); if (process.getuid?.() === 0) chownSync(path, uid, uid); }
function atomic(path, contents, uid = 0) {
  const temporary = `${path}.pending`;
  writeFileSync(temporary, contents, { mode: 0o400, flag: 'wx' });
  if (process.getuid?.() === 0) chownSync(temporary, uid, uid);
  renameSync(temporary, path);
  chmodSync(path, 0o400);
}
let failed = false;
try {
  if (![0, 1000].includes(process.getuid?.())) throw new Error('METRICS_DEPLOYMENT_UID_UNSUPPORTED');
  let productionFacts;
  if(options.production){
    if(existsSync(options.output))throw new Error('METRICS_OPERATION_OUTPUT_SEALED');
    const config=JSON.parse(docker([...compose,'config','--format','json'],{timeout:20_000,maxBuffer:8*1024*1024}));
    productionFacts=productionMetricsConfiguration(options,config);
  }
  let ids = selected;
  if (!ids.length) {
    const code = "const {Pool}=require('pg');const {transportScopeFor}=require('./dist/infrastructure/kong/transport-scope.js');(async()=>{const p=new Pool({connectionString:process.env.DATABASE_URL});try{const q=await p.query(\"SELECT id,admin_url,transport_scope FROM clusters WHERE deleted_at IS NULL AND status='healthy' AND version LIKE '1.5.%' AND enabled_plugins @> ARRAY['prometheus']::text[] ORDER BY created_at\");const seen=new Set(),ids=[];for(const row of q.rows){const scope=transportScopeFor(row.admin_url,row.transport_scope);if(!seen.has(scope)){seen.add(scope);ids.push(row.id);}}console.log(JSON.stringify(ids));}finally{await p.end();}})().catch(()=>process.exit(1));";
    ids = JSON.parse(docker([...compose, 'exec', '-T', 'console-api', 'node', '-e', code], { timeout: 15_000 }));
  }
  if (!Array.isArray(ids) || !ids.length || ids.length > 32 || ids.some(id => !isUuid(id)) || new Set(ids).size !== ids.length) throw new Error('METRICS_DISCOVERY_INVALID');
  if(!options.production)directoryFor(resolve('deploy/private'));
  directoryFor(directory);
  directoryFor(resolve(directory, 'prometheus'), 1000);
  directoryFor(resolve(directory, 'collector'), 1000);
  const old = existsSync(manifestFile) ? JSON.parse(readFileSync(manifestFile, 'utf8')) : { clusters: [] };
  const collectorFile = resolve(directory, 'collector/credentials.json');
  const existingCollector = existsSync(collectorFile) ? JSON.parse(readFileSync(collectorFile, 'utf8')).clusters : [];
  if (!Array.isArray(old.clusters) || !Array.isArray(existingCollector)) throw new Error('METRICS_LOCAL_STATE_INVALID');
  const collectorRows = new Map(existingCollector.map(row => [row.clusterId, row]));
  const records = new Map(old.clusters.map(row => [row.clusterId, row]));
  for (const clusterId of ids) {
    const nodeId = nodeIdFor(clusterId);
    const status = cli({ action: 'status', clusterId });
    const record = records.get(clusterId);
    if (record && !rotate) {
      if (record.state !== 'ready' || status.generation !== record.generation || !collectorRows.has(clusterId)) throw new Error('METRICS_ENROLLMENT_REQUIRES_CONFIRMED_ROTATION');
      for (const purpose of ['native_scrape', 'collector_scrape']) {
        const path = resolve(directory, `prometheus/${clusterId}-${purpose}.token`);
        if (!existsSync(path) || (statSync(path).mode & 0o777) !== 0o400 || digest(readFileSync(path, 'utf8').trim()) !== record.fingerprints[purpose]) throw new Error('METRICS_LOCAL_STATE_INVALID');
      }
      const config = collectorRows.get(clusterId);
      if (config.generation !== record.generation || digest(config.catalogToken) !== record.fingerprints.collector_catalog || config.ingestFingerprint !== record.fingerprints.collector_ingest || config.scrapeFingerprint !== record.fingerprints.collector_scrape) throw new Error('METRICS_LOCAL_STATE_INVALID');
      if (captureTestReference && !['native_scrape', 'collector_scrape', 'collector_catalog', 'collector_ingest'].every(purpose => readTestReference().tokens.some(row => row.clusterId === clusterId && row.generation === record.generation && row.purpose === purpose && digest(row.token) === record.fingerprints[purpose]))) throw new Error('METRICS_TEST_REFERENCE_REQUIRES_CONFIRMED_ROTATION');
      records.set(clusterId, { ...record, nodeId });
      continue;
    }
    if (status.enrolled && !rotate) throw new Error('METRICS_ENROLLMENT_REQUIRES_CONFIRMED_ROTATION');
    const material = createMetricsMaterial(clusterId, (status.generation || 0) + 1);
    // Explicit test-only reference exists before any credential enrollment call.
    capture(material);
    records.set(clusterId, { clusterId, nodeId, generation: material.enrollment.generation, state: 'pending', fingerprints: material.fingerprints });
    atomic(manifestFile, JSON.stringify({ version: 1, clusters: [...records.values()] }) + '\n');
    const result = cli(material.enrollment);
    if (!result.enrolled || result.clusterId !== clusterId || result.generation !== material.enrollment.generation) throw new Error('METRICS_ENROLLMENT_FAILED');
    atomic(resolve(directory, `prometheus/${clusterId}-native_scrape.token`), material.prometheus.native + '\n', 1000);
    atomic(resolve(directory, `prometheus/${clusterId}-collector_scrape.token`), material.prometheus.collector + '\n', 1000);
    collectorRows.set(clusterId, material.collector);
    // Raw ingest token was used only in bounded stdin; never persisted here.
    records.set(clusterId, { clusterId, nodeId, generation: result.generation, state: 'ready', fingerprints: material.fingerprints });
  }
  atomic(collectorFile, JSON.stringify({ version: 1, clusters: [...collectorRows.values()] }) + '\n', 1000);
  atomic(resolve(directory, 'prometheus/prometheus.yml'), prometheusConfiguration([...records.values()].filter(row => row.state === 'ready')), 1000);
  atomic(manifestFile, JSON.stringify({ version: 1, clusters: [...records.values()] }) + '\n');
  const result={ enrolled: true, clusters: ids, rawIngestPersisted: false, ...(captureTestReference ? { testPrivateReferenceWritten: true } : {}), secretsPrinted: false };
  if(options.production){mkdirSync(dirname(options.output),{recursive:true});writeFileSync(options.output,JSON.stringify({...result,observedAt:new Date().toISOString(),productionFacts},null,2)+'\n',{mode:0o644,flag:'wx'});}
  console.log(JSON.stringify(result));
} catch {
  failed = true;
  console.error('METRICS_BOOTSTRAP_FAILED: use the protected local state and current-generation status to review an incomplete enrollment; no secrets were printed.');
}
if (failed) process.exitCode = 1;
