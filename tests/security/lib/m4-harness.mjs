import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { findSecretArtifacts } from '../check-artifacts.mjs';

export function entity(data) { return data?.entity ?? (data?.result ? entity(data.result) : data); }
export function rows(data) { return Array.isArray(data) ? data : data?.items ?? []; }
export function strongPassword() { return `Aa7!${randomUUID()}xQ`; }
export function scope(path, workspace, params = {}) {
  const [pathname, query = ''] = path.split('?');
  const search = new URLSearchParams(query);
  if (workspace) search.set('workspaceId', workspace.id ?? workspace);
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== null) search.set(key, String(value));
  return `${pathname}${search.size ? `?${search}` : ''}`;
}
function mergeCookie(current, setCookies) {
  const pairs = new Map(current.split('; ').filter(Boolean).map(pair => { const at = pair.indexOf('='); return [pair.slice(0, at), pair.slice(at + 1)]; }));
  for (const header of setCookies) { const pair = header.split(';')[0], at = pair.indexOf('='); pairs.set(pair.slice(0, at), pair.slice(at + 1)); }
  return [...pairs].map(([name, value]) => `${name}=${value}`).join('; ');
}

/** Serial HTTP fixture runner; responses and generated secrets stay in memory. */
export class M4Harness {
  constructor() {
    if (existsSync('.env')) process.loadEnvFile('.env');
    this.base = (process.env.SECURITY_BASE_URL || 'http://127.0.0.1:8080/api/v1').replace(/\/$/, '');
    this.tag = `m4-security-${randomUUID().slice(0, 8)}`;
    this.checks = []; this.secrets = []; this.users = []; this.journal = []; this.successfulWrites = [];
    this.lastRequest = 0; this.loginTimes = []; this.reference = join(tmpdir(), 'kongos-m4-runtime-secrets.json');
    if (existsSync(this.reference)) {
      const previous = JSON.parse(readFileSync(this.reference, 'utf8'));
      this.secrets.push(...(previous.secrets ?? []));
    }
    this.secrets.push(process.env.APP_SECRET, process.env.CONSOLE_ENCRYPTION_KEY, process.env.BOOTSTRAP_ADMIN_PASSWORD);
    this.public = {};
  }
  check(condition, id, name, details = {}) {
    if (!condition) { const failure = new Error(`${id}: ${name}`); failure.safeEvidenceMessage = true; throw failure; }
    this.checks.push({ id, name, passed: true, ...details });
  }
  ok(response, id, name) {
    const code = response.payload?.error?.code;
    const safeCode = typeof code === 'string' && /^[A-Z_\d]{1,80}$/.test(code) ? code : undefined;
    this.check(response.status >= 200 && response.status < 300, id, `${name}: HTTP ${response.status}${safeCode ? ` (${safeCode})` : ''}`, { requestId: response.payload?.meta?.requestId });
    return response.payload?.data;
  }
  async request(session, path, method = 'GET', body, options = {}) {
    const remember = value => {
      if (!value || typeof value !== 'object') return;
      for (const [key, item] of Object.entries(value)) {
        if (/^(password|current_password|new_password|password_confirmation|client_secret|secret|key)$/i.test(key) && typeof item === 'string') this.secrets.push(item);
        else if (item && typeof item === 'object') remember(item);
      }
    };
    if (body && !options.raw) remember(body);
    for (const [name, value] of Object.entries(options.headers ?? {})) if (/^(authorization|apikey)$/i.test(name)) this.secrets.push(String(value));
    if (path === '/auth/login' && method === 'POST') {
      this.loginTimes = this.loginTimes.filter(time => Date.now() - time < 60_050);
      // Keep margin below the real 30/IP/minute limiter; do not weaken or
      // repeatedly probe it merely to accelerate fixture account creation.
      if (this.loginTimes.length >= 26) await new Promise(resolve => setTimeout(resolve, Math.min(60_000, Math.max(1, 60_060 - (Date.now() - this.loginTimes[0])))));
      this.loginTimes = this.loginTimes.filter(time => Date.now() - time < 60_050);
      this.loginTimes.push(Date.now());
    }
    const pause = 70 - (Date.now() - this.lastRequest);
    if (pause > 0) await new Promise(resolve => setTimeout(resolve, pause));
    this.lastRequest = Date.now();
    const headers = { ...(session?.cookie ? { Cookie: session.cookie } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(!['GET', 'HEAD'].includes(method) ? { 'X-CSRF-Token': session?.csrf || '', 'X-Idempotency-Key': options.key || randomUUID() } : {}), ...options.headers };
    const result = await fetch(`${this.base}${path}`, { method, headers, ...(body !== undefined ? { body: typeof body === 'string' && options.raw ? body : JSON.stringify(body) } : {}), redirect: 'manual' });
    this.lastEvidenceRequest = { method, path: path.split('?')[0], status: result.status };
    const text = await result.text();
    let payload; try { payload = JSON.parse(text); } catch { payload = null; }
    if (!['GET', 'HEAD'].includes(method) && result.status >= 200 && result.status < 300) this.successfulWrites.push({ method, path: path.split('?')[0], requestId: payload?.meta?.requestId });
    return { status: result.status, text, payload, response: result };
  }
  async login(username, password, id = 'A00') {
    this.secrets.push(password);
    const response = await this.request(null, '/auth/login', 'POST', { username, password });
    const data = this.ok(response, id, 'authenticated fixture login');
    this.secrets.push(data.csrfToken);
    const cookies = response.response.headers.getSetCookie();
    const cookie = mergeCookie('', cookies);
    for (const value of cookie.split('; ')) {
      const at = value.indexOf('='); if (value.startsWith('kongos_access=') || value.startsWith('kongos_refresh=')) this.secrets.push(value.slice(at + 1));
    }
    this.check(!response.text.includes(password) && !data.accessToken && !data.refreshToken, id, 'login JSON contains no password/JWT/refresh token');
    return { cookie, csrf: data.csrfToken, user: data.user, username };
  }
  async reject(session, path, method, body, id, name, statuses = [403], options) {
    const result = await this.request(session, path, method, body, options);
    this.check(statuses.includes(result.status), id, `${name}: HTTP ${result.status}`, { requestId: result.payload?.meta?.requestId });
    this.check(!this.secrets.filter(Boolean).some(secret => result.text.includes(secret)), id, 'denied response contains no known secret');
    return result;
  }
  async create(session, cluster, workspace, type, body, id = 'R00') {
    const result = entity(this.ok(await this.request(session, scope(`/clusters/${cluster.id}/entities/${type}`, workspace), 'POST', body), id, `${type} audited fixture creation`));
    this.journal.push({ clusterId: cluster.id, workspaceId: workspace.id, type, id: result.id, name: result.name ?? result.username ?? result.id, createdThrough: 'BFF' });
    return result;
  }
  certificateFixture() {
    const directory = mkdtempSync(join(tmpdir(), 'kongos-m4-x509-'));
    try {
      const keyPath = join(directory, 'key.pem'), certPath = join(directory, 'cert.pem');
      execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', `/CN=${this.tag}.invalid`, '-keyout', keyPath, '-out', certPath], { stdio: ['ignore', 'pipe', 'pipe'] });
      const key = readFileSync(keyPath, 'utf8'), cert = readFileSync(certPath, 'utf8');
      this.secrets.push(key);
      return { key, cert };
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
  async detail(session, cluster, workspace, type, value, id = 'R00', query = {}) {
    return entity(this.ok(await this.request(session, scope(`/clusters/${cluster.id}/entities/${type}/${typeof value === 'string' ? value : value.id}`, workspace, query)), id, `${type} authoritative readback`));
  }
  async unchanged(session, cluster, workspace, type, value, original, id, label) {
    const current = await this.detail(session, cluster, workspace, type, value, id, { reveal: true });
    this.check(JSON.stringify(canonical(current)) === JSON.stringify(canonical(original)), id, label);
  }
  // Narrow backend-network fixture tool, never a product raw proxy. All output
  // is captured privately. No connection to Kong's own PostgreSQL is possible.
  native(cluster, path, method = 'GET', body, headers = {}) {
    const validCreate = method === 'POST' && (/^\/(services|routes|plugins|upstreams)$/.test(path) || /^\/upstreams\/[\da-f-]+\/targets$/.test(path));
    if (method !== 'GET' && !validCreate) throw new Error('trusted native fixture write outside explicit contract');
    const code = `let input='';for await(const c of process.stdin)input+=c;const q=JSON.parse(input);const allowed=[process.env.DEFAULT_KONG_ADMIN_URL,'http://kong-secondary:8001'];if(!allowed.some(u=>u?.replace(/\\/$/,'')===q.url.replace(/\\/$/,'')))process.exit(3);const r=await fetch(q.url.replace(/\\/$/,'')+q.path,{method:q.method,headers:{...(q.body?{'Content-Type':'application/json'}:{}),...q.headers},...(q.body?{body:JSON.stringify(q.body)}:{})});const text=await r.text();let body;try{body=JSON.parse(text)}catch{body=null};console.log(JSON.stringify({status:r.status,body}));`;
    return JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', code], { input: JSON.stringify({ url: cluster.admin_url, path, method, body, headers }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  }
  async proxy(cluster, path, method = 'GET', body, headers = {}) {
    const port = cluster.admin_url.includes('kong-secondary') ? 9000 : 8000;
    const response = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}), redirect: 'manual' });
    await response.arrayBuffer();
    return response.status;
  }
  async waitProxy(cluster, path, expected, headers = {}, method = 'GET', body) {
    // Configuration propagation may justify bounded read probes. A routed
    // write is sent once: a security failure must never replay that write.
    if (!['GET', 'HEAD'].includes(method)) {
      const status = await this.proxy(cluster, path, method, body, headers);
      this.check(status === expected, 'P/GATE', `single proxy write expected HTTP ${expected}; received HTTP ${status}`);
      return status;
    }
    const deadline = Date.now() + 18_000;
    let lastStatus = 0;
    while (Date.now() < deadline) {
      lastStatus = await this.proxy(cluster, path, method, body, headers);
      if (lastStatus === expected) return lastStatus;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    this.check(false, 'P/GATE', `proxy did not reach expected HTTP ${expected}; last HTTP ${lastStatus}`);
  }
  async archive(session, cluster, workspace, type, value, id = 'I10') {
    this.ok(await this.request(session, scope(`/clusters/${cluster.id}/entities/${type}/${value.id}`, workspace), 'DELETE', { confirmed: true, confirm_name: value.name ?? value.username ?? value.id }), id, 'fixture deletion through audited recycle bin');
    const collection = this.ok(await this.request(session, scope(`/clusters/${cluster.id}/recycle-bin`, workspace, { size: 100 })), id, 'bounded recycle proof');
    const entry = rows(collection).find(item => item.original_id === value.id && !['restored', 'purged'].includes(item.state));
    this.check(Boolean(entry), id, 'deleted fixture has a durable recycle entry');
    return entry;
  }
  verifyAuditCoverage() {
    const requestIds = [...new Set(this.successfulWrites.map(value => value.requestId).filter(Boolean))];
    this.check(this.successfulWrites.every(value => typeof value.requestId === 'string' && value.requestId.length > 0), 'Audit/M4', 'every successful product write has a server request ID');
    // This query reads only the console database via its runtime account. It
    // neither reads nor modifies Kong storage; rows stay in private memory.
    const code = `import pg from 'pg';let input='';for await(const chunk of process.stdin)input+=chunk;const ids=JSON.parse(input);const pool=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});try{const r=await pool.query('SELECT request_id,before,after,json_patch FROM audit_events WHERE request_id=ANY($1::text[])',[ids]);console.log(JSON.stringify(r.rows));}catch{process.exitCode=2;}finally{await pool.end();}`;
    const auditRows = JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', code], { input: JSON.stringify(requestIds), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
    const found = new Set(auditRows.map(value => value.request_id));
    const missing = this.successfulWrites.filter(value => !found.has(value.requestId));
    this.public.auditCoverage = { successfulProductWrites: this.successfulWrites.length, distinctRequestIds: requestIds.length, auditedRequestIds: found.size, missing: missing.map(({ method, path }) => ({ method, path })), controlledNativeFixtureCreationExcluded: true };
    this.check(missing.length === 0, 'Audit/M4', 'all successful HTTP product writes correlate with append-only audit events');
    this.check(auditRows.every(value => Array.isArray(value.json_patch)), 'Audit/M4', 'all inspected audit events have JSON patch arrays');
    const auditText = JSON.stringify(auditRows);
    this.check(!this.secrets.filter(Boolean).some(secret => auditText.includes(secret)), 'Audit/M4', 'current fixture audit before/after/patch contain no known password, token or gateway credential');
  }
  async finish(error) {
    if (error) this.checks.push({ id: 'GATE', name: error.safeEvidenceMessage ? error.message : `Unexpected ${error.name || 'Error'}; sensitive runtime detail withheld`, passed: false });
    await mkdir('artifacts/M4', { recursive: true });
    const evidence = { performedAt: new Date().toISOString(), kind: 'real-Kong-1.5-M4-RBAC-attacks', testTag: this.tag, ...this.public, ...(error ? { lastHttpRequest: this.lastEvidenceRequest } : {}), passed: this.checks.filter(item => item.passed).length, failed: this.checks.filter(item => !item.passed).length, checks: this.checks, fixtures: this.journal, nativeTransportFaultTests: 'Separate explicitly labelled integration mocks; not real network fault injection.' };
    writeFileSync('artifacts/M4/security-live.json', JSON.stringify(evidence, null, 2) + '\n');
    // Keep through every browser/manual screenshot, including an initial failed
    // gate. A caller performs the final scan and removal only after all evidence.
    writeFileSync(this.reference, JSON.stringify({ secrets: this.secrets.filter(Boolean), users: this.users }), { mode: 0o600 });
    if ((statSync(this.reference).mode & 0o777) !== 0o600) throw new Error('runtime reference permissions differ');
    const scan = findSecretArtifacts(this.secrets.filter(Boolean));
    writeFileSync('artifacts/M4/http-secret-artifact-scan.json', JSON.stringify({ performedAt: new Date().toISOString(), kind: 'M4-HTTP-runtime-secrets', ...scan, allPassed: !scan.leaks.length, coversFutureBrowserArtifacts: false, referenceRetainedPrivately: true }, null, 2) + '\n');
    console.log(JSON.stringify({ passed: evidence.passed, failed: evidence.failed, leaks: scan.leaks.length }));
    return evidence.failed || scan.leaks.length ? 1 : 0;
  }
}

export function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).filter(key => !['updated_at', 'console_scope_notice'].includes(key)).sort().map(key => [key, canonical(value[key])]));
  return value;
}
