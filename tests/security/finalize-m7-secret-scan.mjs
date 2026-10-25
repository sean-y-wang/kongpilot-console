import { execFileSync, spawnSync } from 'node:child_process';
import { constants, closeSync, existsSync, fstatSync, lstatSync, openSync, readFileSync, readdirSync, rmSync, rmdirSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { resolve, join } from 'node:path';
import { findSecretArtifacts } from './check-artifacts.mjs';
import { collectEnvironmentSecrets } from '../../deploy/scripts/collect-environment-secrets.mjs';
import { M7_REFERENCE, M7_COMPOSE, readM7Reference, durableJson, sha256 } from './lib/m7-harness.mjs';
import { assertFinalM7Evidence, m7CapturedSecrets, m7SecretForms, M7_LOG_SERVICES } from './lib/m7-secret-scan-policy.mjs';
import { readM7PrivateHistories, M7_HISTORY_DIRECTORY } from './lib/m7-private-history.mjs';
import { isKnownM7StoppedSamplingIntent, readM7BlockedObservationEvidence } from './lib/m7-blocked-observation.mjs';
import { isKnownM7BlockedUiExport, readM7BlockedUiExportEvidence } from './lib/m7-ui-blocked-export.mjs';
import { readM7ManualFinalEvidence } from './lib/m7-manual-final-evidence.mjs';
import { readM7FinalScanContinuation } from './lib/m7-final-scan-continuation.mjs';

if (process.env.M7_FINAL_SCAN_READY !== 'true' || !process.argv.includes('--evidence-complete')) throw new Error('M7_EXCLUSIVE_FINAL_SCAN_HANDOFF_REQUIRED');
const reference = readM7Reference(), handoff = reference.finalScanHandoff;
const continuing = process.env.M7_FINAL_SCAN_PROVENANCE_CONTINUATION_READY === 'true';
if (handoff?.version !== 1 || handoff.phase !== 'ready' || handoff.testTag !== reference.testTag || reference.finalScanStarted && !continuing) throw new Error('M7_FINAL_SCAN_ONE_SHOT_HANDOFF_REQUIRED');
const readSafe = (path, maximum = 32 * 1024 * 1024) => {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try { const stat = fstatSync(fd); if (!stat.isFile() || stat.nlink !== 1 || stat.size > maximum) throw new Error('M7_SCAN_FILE_IDENTITY_INVALID'); return readFileSync(fd); } finally { closeSync(fd); }
};
const continuation = continuing ? readM7FinalScanContinuation(reference, path => readSafe(path, 8 * 1024 * 1024)) : null;
const evidence = {};
for (const name of ['http', 'producers', 'manual', 'cleanup']) {
  const spec = handoff.evidence?.[name];
  if (!/^artifacts\/M7\/[a-zA-Z0-9-]+\.json$/.test(spec?.path ?? '') || !/^[a-f\d]{64}$/.test(spec?.sha256 ?? '')) throw new Error('M7_FINAL_EVIDENCE_BINDING_REQUIRED');
  const bytes = readSafe(spec.path, 8 * 1024 * 1024); if (sha256(bytes) !== spec.sha256) throw new Error('M7_FINAL_EVIDENCE_HASH_CHANGED'); evidence[name] = JSON.parse(bytes);
}
assertFinalM7Evidence(reference, evidence);
const manualInheritance = readM7ManualFinalEvidence(reference, evidence.manual, path => readSafe(path, 8 * 1024 * 1024));
if (reference.samplingIntents.some(intent => isKnownM7StoppedSamplingIntent(reference, intent))) readM7BlockedObservationEvidence(reference);
if (reference.requests.some(packet => isKnownM7BlockedUiExport(reference, packet))) readM7BlockedUiExportEvidence(reference);
if (continuation) reference.finalScanProvenanceContinuation = { ...reference.finalScanProvenanceContinuation, phase: 'started', startedAt: new Date().toISOString() };
else reference.finalScanStarted = { at: new Date().toISOString(), evidence: handoff.evidence };
durableJson(M7_REFERENCE, reference);
let report;
try {
  const historySnapshots = readM7PrivateHistories(reference);
  const values = m7CapturedSecrets(reference, historySnapshots), environmentFiles = readdirSync('.').filter(name => /^\.env(?:\.[a-zA-Z\d.-]+)?$/.test(name) && !/(?:example|sample|template)$/.test(name));
  for (const path of environmentFiles) {
    const environment = parseEnv(readSafe(path, 1024 * 1024).toString('utf8'));
    values.push(...collectEnvironmentSecrets(Object.fromEntries(Object.entries(environment).filter(([name]) => !/(?:_FILE|_PATH)$/.test(name)))));
  }
  // Persistent production material is read only for scanning, never rotated,
  // used as an account/session or removed. This includes old telemetry keys.
  let productionSecretFiles = 0;
  const metricsRoot = 'deploy/private/metrics';
  const walk = directory => !existsSync(directory) ? [] : readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = `${directory}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error('M7_SCAN_SYMBOLIC_LINK_REJECTED');
    return entry.isDirectory() ? walk(path) : entry.isFile() ? [path] : [];
  });
  for (const path of walk(metricsRoot).filter(path => path.endsWith('.token'))) { values.push(readSafe(path, 16384).toString('utf8').trim()); productionSecretFiles++; }
  for (const path of walk('deploy/private/event-delivery').filter(path => path.endsWith('.key'))) {
    const value = readSafe(path, 32768).toString('utf8'); if (!/-----BEGIN (?:RSA |EC |)PRIVATE KEY-----/.test(value)) throw new Error('M7_PROVIDER_PRIVATE_KEY_INVALID'); values.push(value); productionSecretFiles++;
  }
  const collector = `${metricsRoot}/collector/credentials.json`;
  if (existsSync(collector)) {
    const config = JSON.parse(readSafe(collector, 1024 * 1024));
    if (!Array.isArray(config.clusters)) throw new Error('M7_PRODUCTION_METRICS_MATERIAL_INVALID');
    for (const row of config.clusters) { if (typeof row.catalogToken !== 'string' || !row.catalogToken) throw new Error('M7_PRODUCTION_METRICS_MATERIAL_INVALID'); values.push(row.catalogToken); }
    productionSecretFiles++;
  }
  const telemetryReference = '/tmp/kongos-m5-runtime-secrets.json';
  if (existsSync(telemetryReference)) {
    const stat = lstatSync(telemetryReference); if ((stat.mode & 0o777) !== 0o600 || stat.uid !== process.getuid()) throw new Error('M7_PRODUCTION_CAPTURE_IDENTITY_INVALID');
    const old = JSON.parse(readSafe(telemetryReference, 2 * 1024 * 1024));
    if (!Array.isArray(old.secrets) || !Array.isArray(old.tokens)) throw new Error('M7_PRODUCTION_CAPTURE_INVALID');
    values.push(...old.secrets);
    for (const row of old.tokens) { values.push(row.token); if (row.purpose === 'collector_ingest') values.push(Buffer.from(`kongos:${row.token}`).toString('base64')); }
    productionSecretFiles++;
  }
  for (const pair of [reference.receiverMaterials?.httpBasic, reference.receiverMaterials?.smtp]) {
    if (typeof pair?.username === 'string' && typeof pair.password === 'string') values.push(Buffer.from(`${pair.username}:${pair.password}`).toString('base64'), Buffer.from(`\0${pair.username}\0${pair.password}`).toString('base64'));
  }
  const observationMaterials = reference.samplingIntents.filter(intent => intent.state === 'completed').flatMap(intent => intent.keys.map((key, index) => ({ key, observationId: intent.samples[index]?.observationId, clusterId: intent.cid, subjectType: intent.type, subjectId: intent.id })));
  const stoppedMaterials = reference.samplingIntents.filter(intent => isKnownM7StoppedSamplingIntent(reference, intent)).flatMap(intent => intent.keys.map((key, index) => ({ key, clusterId: intent.cid, subjectType: intent.type, subjectId: intent.id, originalKeyIndex: index, originalIntentIndex: reference.samplingIntents.indexOf(intent) })));
  const receiptCode = "const f=require('fs');let b='';process.stdin.on('data',c=>{b+=c;if(b.length>16384)process.exit(2)});process.stdin.on('end',()=>{try{const input=JSON.parse(b),a=input.confirmed,old=input.stopped,p='/tmp/kongos-m7-observation-receipts';if(!Array.isArray(a)||a.length>10||!Array.isArray(old)||![0,5,10].includes(old.length))throw Error();const ps=f.lstatSync(p);if(!ps.isDirectory()||ps.isSymbolicLink()||ps.uid!==process.getuid()||(ps.mode&511)!==448)throw Error();const h=a.map(e=>{if(!/^[a-f0-9-]{36}$/.test(e.key))throw Error();const d=f.openSync(p+'/'+e.key+'.json',f.constants.O_RDONLY|f.constants.O_NOFOLLOW);try{const s=f.fstatSync(d);if(!s.isFile()||s.size>4096||s.uid!==process.getuid()||(s.mode&511)!==384)throw Error();const r=JSON.parse(f.readFileSync(d,'utf8'));if(r.state!=='ready'||r.samplingKey!==e.key||r.observationId!==e.observationId||r.clusterId!==e.clusterId||r.subjectType!==e.subjectType||r.subjectId!==e.subjectId||!/^[a-f0-9]{64}$/.test(r.observationHmac))throw Error();return r.observationHmac;}finally{f.closeSync(d)}});const keys=['e381165a-366f-4bc3-a4d7-869ae6c9645e','1d9ada11-58f0-4aba-8684-f2ec9722b79e','440fb6a4-d729-4314-96b0-b9bb25fe6684','bd498586-dd27-46fe-99ec-89df45ef89fd','c097f362-b66c-4887-9dc6-a2142cf1df2f'];const secondKeys=['be9f8242-775d-4bb7-a818-902cfa5fb562','cdd72d04-e4a8-452e-9c2d-a0aa6f483c93','cb7e9b29-cf3d-4ffc-a603-31cd571203bf','7e5af08b-acca-4e30-b56f-51ac54f915cc','40dad785-c30d-4061-82da-832466495b39'];for(let i=0;i<old.length;i++){const e=old[i],group=Math.floor(i/5),local=i%5,expectedKeys=group===0?keys:secondKeys,expectedId=group===0?'9abfa5b8-d34b-4920-88e2-f4058a4ab2dd':'dc480bde-b580-4744-89e8-4c1d9f317ab2';if(e.key!==expectedKeys[local]||e.originalKeyIndex!==local||e.originalIntentIndex!==group||e.clusterId!=='dff45535-ed8d-4851-b7a6-6376feac7f59'||e.subjectType!=='certificates'||e.subjectId!==expectedId)throw Error();let d;try{d=f.openSync(p+'/'+e.key+'.json',f.constants.O_RDONLY|f.constants.O_NOFOLLOW);}catch(error){if(local>0&&error.code==='ENOENT')continue;throw error;}try{const s=f.fstatSync(d);if(local!==0||!s.isFile()||s.size>4096||s.uid!==process.getuid()||(s.mode&511)!==384)throw Error();const r=JSON.parse(f.readFileSync(d,'utf8'));if(r.version!==1||r.state!=='reserved'||r.samplingKey!==e.key||r.clusterId!==e.clusterId||r.subjectType!==e.subjectType||r.subjectId!==e.subjectId||JSON.stringify(Object.keys(r).sort())!==JSON.stringify(['clusterId','samplingKey','state','subjectId','subjectType','version'].sort()))throw Error();}finally{f.closeSync(d)}}process.stdout.write(JSON.stringify({hmacs:h,stoppedValidated:old.length}));}catch{process.exitCode=2;}});";
  const proof = JSON.parse(execFileSync('docker', [...M7_COMPOSE, 'exec', '-T', 'console-api', 'node', '-e', receiptCode], { input: JSON.stringify({ confirmed: observationMaterials, stopped: stoppedMaterials }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000 }));
  if (!Array.isArray(proof.hmacs) || proof.hmacs.length !== observationMaterials.length || proof.stoppedValidated !== stoppedMaterials.length) throw new Error('M7_OBSERVATION_MATERIAL_INCOMPLETE');
  values.push(...proof.hmacs);
  reference.secrets = [...new Set([...reference.secrets, ...proof.hmacs])]; durableJson(M7_REFERENCE, reference);
  const secrets = m7SecretForms(values), source = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).split('\0').filter(Boolean);
  const compiled = ['apps/console-api/dist', 'apps/console-web/dist', 'apps/portal-web/dist', 'packages/contracts/dist'].flatMap(walk);
  const extraReports = ['test-results', 'playwright-report', 'artifacts/playwright-results', 'artifacts/playwright-report'].flatMap(walk);
  const scan = findSecretArtifacts(secrets, [...source, ...compiled, ...extraReports]);
  const since = reference.requests[0]?.startedAt;
  if (!Number.isFinite(Date.parse(since))) throw new Error('M7_ORIGINAL_LOG_START_REQUIRED');
  const run = args => execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, maxBuffer: 32 * 1024 * 1024 });
  const api = run([...M7_COMPOSE, 'ps', '-q', 'console-api']).trim();
  if (!/^[a-f\d]{12,64}$/.test(api)) throw new Error('M7_LOG_API_IDENTITY_INVALID');
  const project = run(['inspect', '-f', '{{index .Config.Labels "com.docker.compose.project"}}', api]).trim();
  if (!/^[a-zA-Z\d_-]{1,100}$/.test(project)) throw new Error('M7_LOG_PROJECT_INVALID');
  const runtimeLogs = [];
  for (const service of M7_LOG_SERVICES) {
    const ids = run(['ps', '--filter', `label=com.docker.compose.project=${project}`, '--filter', `label=com.docker.compose.service=${service}`, '--format', '{{.ID}}']).trim().split('\n').filter(Boolean);
    if (ids.length !== 1) throw new Error('M7_LOG_SERVICE_IDENTITY_INVALID');
    const result = spawnSync('docker', ['logs', '--since', since, ids[0]], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, maxBuffer: 32 * 1024 * 1024 });
    if (result.status !== 0 || result.error) throw new Error('M7_LOG_COLLECTION_FAILED');
    const text = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    runtimeLogs.push({ service, knownSecretDetected: secrets.some(value => text.includes(value)), freshStdoutAndStderr: true });
  }
  report = { performedAt: new Date().toISOString(), milestone: 'M7', testTag: reference.testTag, kind: 'fresh-M7-captures-and-production-material-artifacts-logs', allPassed: scan.leaks.length === 0 && runtimeLogs.every(row => !row.knownSecretDetected), ...scan, manualInheritance, ...(continuation ? { provenanceContinuation: continuation } : {}), compiledFiles: compiled.length, additionalReportFiles: extraReports.length, environmentFiles: environmentFiles.length, productionSecretFiles, privateObservationProofsIncluded: proof.hmacs.length, sealedStoppedSamplingKeysVerified: proof.stoppedValidated, sealedStoppedSamplingGroups: proof.stoppedValidated / 5, backgroundObservationInSecondStoppedGroupRetained: proof.stoppedValidated === 10, originalMemoryObservationUnknownRetained: proof.stoppedValidated > 0, currentAndHistoricalSecretsIncluded: true, base64AndEscapedFormsIncluded: true, syntheticProviderCredentialsIncluded: true, originalFailureArtifactsIncluded: true, runtimeLogs, logsSince: since, rawLogsPublished: false, protectedProductionMaterialsRetained: true, privateReferenceRemoved: false, ephemeralPrivateMaterialsRemoved: false, secretsPublished: false };
} catch { report = { performedAt: new Date().toISOString(), milestone: 'M7', testTag: reference.testTag, allPassed: false, failureClassification: 'FINAL_SCAN_INCOMPLETE_PRIVATE_RETAINED', privateReferenceRemoved: false, secretsPublished: false, rawLogsPublished: false }; }
const reportPath = continuation?.reportPath ?? 'artifacts/M7/runtime-secret-artifact-scan.json';
durableJson(reportPath, report, 0o644, true);
// Root's explicit final handoff permits only captured test references/materials
// to disappear after a complete durable zero-leak result. Production remains.
if (report.allPassed) {
  try {
    for (const directory of reference.privateMaterialDirectories ?? []) {
      if (!/^\/tmp\/kongos-m7-certificate-[a-zA-Z\d]+$/.test(directory)) throw new Error('M7_PRIVATE_REMOVAL_PATH_REJECTED');
      const stat = lstatSync(directory); if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o700) throw new Error('M7_PRIVATE_REMOVAL_IDENTITY_INVALID');
      rmSync(directory, { recursive: true });
    }
    // The authority's receipts contain HMAC proofs; their fixed test-only folder
    // is removed through trusted Dockerexec, never a user-provided shell path.
    execFileSync('docker', [...M7_COMPOSE, 'exec', '-T', 'console-api', 'node', '-e', "const f=require('fs'),p='/tmp/kongos-m7-observation-receipts';if(f.existsSync(p)){const s=f.lstatSync(p);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&511)!==448)process.exit(2);f.rmSync(p,{recursive:true});}"], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 });
    // Histories were byte/SHA/owner/mode verified above and all their original
    // secret contexts were classified before any private capture is removed.
    readM7PrivateHistories(reference);
    for (const ref of reference.privateHistoryRefs ?? []) rmSync(join(M7_HISTORY_DIRECTORY, ref.file));
    rmdirSync(M7_HISTORY_DIRECTORY);
    rmSync(M7_REFERENCE); report.privateReferenceRemoved = !existsSync(M7_REFERENCE); report.ephemeralPrivateMaterialsRemoved = true;
  } catch { report.allPassed = false; report.privateRemovalFailed = true; report.privateReferenceRemoved = !existsSync(M7_REFERENCE); }
  durableJson(reportPath, report, 0o644);
}
console.log(JSON.stringify({ allPassed: report.allPassed, scannedFiles: report.scannedFiles ?? 0, embeddedFiles: report.embeddedFiles ?? 0, leakCount: report.leaks?.length ?? null, freshLogServices: report.runtimeLogs?.length ?? 0, privateReferenceRemoved: report.privateReferenceRemoved }));
process.exitCode = report.allPassed ? 0 : 1;
