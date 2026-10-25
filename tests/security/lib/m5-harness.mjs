import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { M4Harness } from './m4-harness.mjs';
import { findSecretArtifacts } from '../check-artifacts.mjs';

export { entity, rows, scope, strongPassword } from './m4-harness.mjs';

/** Reuse the verified serial/CSRF/BFF fixture helpers; M5 evidence is separate. */
export class M5Harness extends M4Harness {
  constructor() {
    super();
    this.tag = `m5-security-${randomUUID().slice(0, 8)}`;
    this.reference = join(tmpdir(), 'kongos-m5-runtime-secrets.json');
    this.privateTokens = [];
    this.privateTraffic = [];
    this.privateSetupAttempts = [];
    this.privateWriteEvidence = [];
    this.privateWriteAttempts = [];
    if (existsSync(this.reference)) {
      if ((statSync(this.reference).mode & 0o777) !== 0o600) throw new Error('private M5 reference must have mode0600');
      const prior = JSON.parse(readFileSync(this.reference, 'utf8'));
      this.secrets.push(...(prior.secrets ?? []));
      this.users.push(...(prior.users ?? []));
      this.privateTokens.push(...(prior.tokens ?? []));
      this.privateTraffic.push(...(prior.traffic ?? []));
      this.privateSetupAttempts.push(...(prior.setupAttempts ?? []));
      this.privateWriteEvidence.push(...(prior.writeEvidence ?? []));
      this.privateWriteAttempts.push(...(prior.writeAttempts ?? []));
    }
    for (const credential of this.privateTokens) if (credential.purpose === 'collector_ingest') {
      const encoded = Buffer.from(`kongos:${credential.token}`).toString('base64');
      this.remember(encoded); this.remember(`Basic ${encoded}`);
    }
  }
  check(condition, id, name, details = {}) {
    return super.check(condition, id.replace('/M4', '/M5'), name, details);
  }
  remember(value) {
    if (typeof value === 'string' && value.length > 0) this.secrets.push(value);
    return value;
  }
  persistReference() {
    writeFileSync(this.reference, JSON.stringify({ secrets: [...new Set(this.secrets.filter(Boolean))], users: this.users, tokens: this.privateTokens, traffic: this.privateTraffic, setupAttempts: this.privateSetupAttempts, writeEvidence: this.privateWriteEvidence, writeAttempts: this.privateWriteAttempts }), { mode: 0o600 });
    if ((statSync(this.reference).mode & 0o777) !== 0o600) throw new Error('private M5 reference must have mode0600');
  }
  async request(session, path, method = 'GET', body, options = {}) {
    const rememberBody = value => {
      if (!value || typeof value !== 'object') return;
      for (const [name, item] of Object.entries(value)) {
        if (/^(password|current_password|new_password|password_confirmation|client_secret|secret|key)$/i.test(name) && typeof item === 'string') this.remember(item);
        else if (item && typeof item === 'object') rememberBody(item);
      }
    };
    rememberBody(body);
    let attempt;
    if (!['GET', 'HEAD'].includes(method)) {
      const key = Object.entries(options.headers ?? {}).find(([name]) => name.toLowerCase() === 'x-idempotency-key')?.[1] ?? options.key ?? randomUUID();
      options = { ...options, key };
      const context = new URL(path, this.base);
      attempt = { method, path: context.pathname, idempotencyKey: key, ...(session?.user?.id ? { actorId: session.user.id } : {}), ...(context.searchParams.has('workspaceId') ? { workspaceId: context.searchParams.get('workspaceId') } : {}), startedAt: new Date().toISOString() };
      this.privateWriteAttempts.push(attempt);
    }
    this.persistReference();
    const response = await super.request(session, path, method, body, options);
    if (attempt) Object.assign(attempt, { status: response.status, requestId: response.payload?.meta?.requestId, responseReceivedAt: new Date().toISOString() });
    for (const cookie of response.response.headers.getSetCookie()) {
      const [pair] = cookie.split(';'), at = pair.indexOf('=');
      if (/^kongos_(access|refresh|csrf)=/.test(pair)) this.remember(pair.slice(at + 1));
    }
    if (!['GET', 'HEAD'].includes(method) && response.status >= 200 && response.status < 300) this.privateWriteEvidence.push({ method, path: path.split('?')[0], requestId: response.payload?.meta?.requestId });
    this.persistReference();
    return response;
  }
  rememberTokenSet(enrollment) {
    if (!enrollment?.clusterId || !Number.isInteger(enrollment.generation) || !Array.isArray(enrollment.credentials)) throw new Error('trusted enrollment has an invalid shape');
    for (const credential of enrollment.credentials) {
      if (!['native_scrape', 'collector_scrape', 'collector_catalog', 'collector_ingest'].includes(credential.purpose) || typeof credential.token !== 'string' || credential.token.length < 32) throw new Error('trusted enrollment credential is invalid');
      this.remember(credential.token);
      if (credential.purpose === 'collector_ingest') {
        const encoded = Buffer.from(`kongos:${credential.token}`).toString('base64');
        this.remember(encoded); this.remember(`Basic ${encoded}`);
      }
      this.privateTokens.push({ clusterId: enrollment.clusterId, generation: enrollment.generation, ...credential });
    }
    // Persist BEFORE any token leaves memory through an enrollment/fixture stdin.
    this.persistReference();
  }
  enrollmentStatus(clusterId) {
    if (!/^[\da-f-]{36}$/.test(clusterId)) throw new Error('trusted enrollment cluster is invalid');
    return JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', 'dist/infrastructure/metrics-enroll.js'], { input: JSON.stringify({ action: 'status', clusterId }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  }
  enroll(enrollment) {
    this.rememberTokenSet(enrollment);
    const safeResult = JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', 'dist/infrastructure/metrics-enroll.js'], { input: JSON.stringify(enrollment), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
    this.check(!this.secrets.filter(Boolean).some(secret => JSON.stringify(safeResult).includes(secret)), 'Tokens', 'trusted enrollment returns fingerprints and identifiers without raw tokens');
    return safeResult;
  }
  /** Narrow trusted backend-network read/probe, with raw replies private only. */
  internal(source, path, { method = 'GET', token, headers = {}, body, service = 'console-api' } = {}) {
    const allowed = {
      bridge: { origin: 'http://metrics-bff:9092', paths: /^\/(?:scrape|catalog)\/[\da-f-]+(?:\/validate)?(?:\?|$)/ },
      collector: { origin: 'http://telemetry-collector:9093', paths: /^\/(?:healthz|metrics\/[\da-f-]+|ingest\/[\da-f-]+)(?:\?|$)/ },
      prometheus: { origin: 'http://prometheus:9090', paths: /^(?:\/metrics|\/api\/v1\/(?:query|query_range|targets))(?:\?|$)/ },
      loki: { origin: 'http://loki:3100', paths: /^(?:\/metrics|\/loki\/api\/v1\/(?:query|query_range|labels))(?:\?|$)/ },
    };
    const selected = allowed[source];
    if (!selected?.paths.test(path) || !['GET', 'POST'].includes(method) || !['console-api', 'telemetry-collector'].includes(service)) throw new Error('trusted M5 probe is outside fixed paths/services');
    this.remember(token);
    for (const [name, value] of Object.entries(headers)) if (/authorization/i.test(name)) this.remember(value);
    const code = `let input='';for await(const chunk of process.stdin)input+=chunk;const q=JSON.parse(input);const r=await fetch(q.url,{method:q.method,redirect:'manual',signal:AbortSignal.timeout(12000),headers:{...(q.body!==undefined?{'Content-Type':'application/json'}:{}),...(q.token?{Authorization:'Bearer '+q.token}:{}),...q.headers},...(q.body!==undefined?{body:JSON.stringify(q.body)}:{})});const chunks=[];let bytes=0;for await(const c of r.body){bytes+=c.length;if(bytes>8*1024*1024)throw new Error('bounded fixture reply exceeded');chunks.push(c);}const text=Buffer.concat(chunks).toString('utf8');let json;try{json=JSON.parse(text)}catch{}console.log(JSON.stringify({status:r.status,text,json}));`;
    return JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', service, 'node', '--input-type=module', '-e', code], { input: JSON.stringify({ url: selected.origin + path, method, token, headers, body }), encoding: 'utf8', maxBuffer: 10 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] }));
  }
  prometheus(query, { time, start, end, step } = {}) {
    const isRange = start !== undefined;
    const search = new URLSearchParams({ query, ...(isRange ? { start: String(start), end: String(end), step: String(step) } : { time: String(time) }) });
    const result = this.internal('prometheus', `/api/v1/${isRange ? 'query_range' : 'query'}?${search}`);
    this.check(result.status === 200 && result.json?.status === 'success', 'Oracle', 'real Prometheus fixed query succeeds');
    return result.json.data;
  }
  providerQueryCount(source) {
    if (!['prometheus', 'loki'].includes(source)) throw new Error('counter source is invalid');
    const reply = this.internal(source, '/metrics');
    this.check(reply.status === 200, 'Budget', `${source} exposes real request-count instrumentation`);
    const lines = reply.text.split('\n').filter(line => source === 'prometheus'
      ? /^prometheus_http_requests_total\{/.test(line) && /handler="\/api\/v1\/query(?:_range)?"/.test(line)
      : /^loki_request_duration_seconds_count\{/.test(line) && /route="[^"\n]*query(?:_range)?[^"\n]*"/.test(line));
    return { observed: lines.length > 0, count: lines.reduce((total, line) => total + Number(line.match(/\}\s+([^\s]+)/)?.[1] ?? 0), 0) };
  }
  logs(service) {
    if (!['console-api', 'console-web', 'telemetry-collector', 'prometheus', 'loki', 'kong', 'kong-secondary'].includes(service)) throw new Error('log fixture service is not allowed');
    return execFileSync('docker', ['compose', '--env-file', '.env', '--env-file', '.env.multicluster', '-f', 'docker-compose.yml', '-f', 'deploy/compose.multicluster-test.yml', '-f', 'deploy/compose.metrics.yml', 'logs', '--no-color', '--since', '20m', service], { encoding: 'utf8', maxBuffer: 24 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
  }
  async poll(read, accept, name, { timeoutMs = 90_000, intervalMs = 1_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const value = await read();
      if (accept(value)) return value;
      await new Promise(resolve => setTimeout(resolve, Math.min(intervalMs, Math.max(1, deadline - Date.now()))));
    }
    this.check(false, 'Propagation', name);
  }
  async finish(error) {
    if (error) this.checks.push({ id: 'GATE', name: error.safeEvidenceMessage ? error.message : `Unexpected ${error.name || 'Error'}; sensitive runtime detail withheld`, passed: false });
    await mkdir('artifacts/M5', { recursive: true });
    const evidence = { performedAt: new Date().toISOString(), kind: 'real-Kong-1.5-M5-monitoring-and-channel-security', testTag: this.tag, ...this.public, ...(error ? { lastHttpRequest: this.lastEvidenceRequest } : {}), passed: this.checks.filter(item => item.passed).length, failed: this.checks.filter(item => !item.passed).length, checks: this.checks, fixtures: this.journal, successfulConfigurationWrites: this.successfulWrites };
    writeFileSync('artifacts/M5/security-live.json', JSON.stringify(evidence, null, 2) + '\n');
    this.persistReference();
    const scan = findSecretArtifacts(this.secrets.filter(Boolean));
    writeFileSync('artifacts/M5/http-secret-artifact-scan.json', JSON.stringify({ performedAt: new Date().toISOString(), kind: 'M5-HTTP-runtime-secrets', ...scan, allPassed: scan.leaks.length === 0, coversFutureBrowserArtifacts: false, referenceRetainedPrivately: true }, null, 2) + '\n');
    console.log(JSON.stringify({ passed: evidence.passed, failed: evidence.failed, leaks: scan.leaks.length }));
    return evidence.failed || scan.leaks.length ? 1 : 0;
  }
}
