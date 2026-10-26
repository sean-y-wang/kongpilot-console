import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { readM7PrivateHistories } from './m7-private-history.mjs';

export const M7_REFERENCE = join(tmpdir(), 'kongos-m7-runtime-secrets.json');
export const M7_CLUSTERS = Object.freeze({ direct: 'dff45535-ed8d-4851-b7a6-6376feac7f59', approval: 'd1dfaec8-2a10-4170-8a15-20a600a4bd4f' });
export const M7_COMPOSE = Object.freeze(['compose', '--env-file', '.env', '--env-file', '.env.multicluster', '--env-file', '.env.portal-acceptance', '-f', 'docker-compose.yml', '-f', 'deploy/compose/compose.development.yml', '-f', 'deploy/compose/compose.multicluster-test.yml', '--profile', 'multicluster-test', '-f', 'deploy/compose/compose.metrics.yml', '--profile', 'observability', '-f', 'deploy/compose/compose.portal-acceptance.yml', '--profile', 'portal-acceptance', '-f', 'deploy/compose/compose.notifications-test.yml', '--profile', 'notifications-test']);
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const entity = value => value?.entity ?? value;
export const rows = value => Array.isArray(value) ? value : value?.items ?? [];
export const strongPassword = () => `Aa7!${randomUUID()}xQ`;
export function scope(cid, wid, suffix, query = {}) {
  const search = new URLSearchParams({ workspaceId: wid, ...Object.fromEntries(Object.entries(query).filter(([, value]) => value !== undefined && value !== null)) });
  return `/clusters/${cid}/${suffix}?${search}`;
}
export function cookieMerge(current, values) {
  const pairs = new Map(current.split('; ').filter(Boolean).map(pair => { const at = pair.indexOf('='); return [pair.slice(0, at), pair.slice(at + 1)]; }));
  for (const header of values) { const pair = header.split(';')[0], at = pair.indexOf('='); pairs.set(pair.slice(0, at), pair.slice(at + 1)); }
  return [...pairs].map(([key, value]) => `${key}=${value}`).join('; ');
}
export function durableJson(path, value, mode = 0o600, initial = false) {
  const parent = resolve(path, '..'); mkdirSync(parent, { recursive: true, mode: 0o700 });
  const target = initial ? path : `${path}.${randomUUID()}.tmp`, fd = openSync(target, 'wx', mode);
  try { writeFileSync(fd, JSON.stringify(value, null, 2) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
  if (!initial) renameSync(target, path);
  const directory = openSync(parent, 'r'); try { fsyncSync(directory); } finally { closeSync(directory); }
}
export function readM7Reference() {
  const stat = lstatSync(M7_REFERENCE);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600 || stat.size > 32 * 1024 * 1024) throw new Error('M7_PRIVATE_REFERENCE_INVALID');
  const value = JSON.parse(readFileSync(M7_REFERENCE, 'utf8'));
  if (value.version !== 1 || value.milestone !== 'M7' || !Array.isArray(value.requests) || !Array.isArray(value.secrets)) throw new Error('M7_PRIVATE_REFERENCE_INVALID');
  readM7PrivateHistories(value);
  return value;
}
export class M7Harness {
  constructor({ resume = false, reference } = {}) {
    // This guard precedes all env/private/runtime access. Importing this module
    // for source tests never starts a fixture or reads another milestone.
    if (process.env.M7_DEPLOYMENT_READY !== 'true') throw new Error('M7_EXCLUSIVE_DEPLOYMENT_HANDOFF_REQUIRED');
    if (existsSync('.env')) process.loadEnvFile('.env');
    if (!resume && existsSync(M7_REFERENCE)) throw new Error('M7_ORIGINAL_REFERENCE_PRESENT_NO_REPLAY');
    this.state = resume ? reference ?? readM7Reference() : { version: 1, milestone: 'M7', testTag: `m7-security-${randomUUID().slice(0, 8)}`, phase: 'created', requests: [], secrets: [], sessions: {}, accounts: [], fixtures: [], providerControls: [], samplingIntents: [] };
    if (this.state.version !== 1 || this.state.milestone !== 'M7' || !Array.isArray(this.state.requests) || !Array.isArray(this.state.secrets)) throw new Error('M7_PRIVATE_REFERENCE_INVALID');
    this.base = 'http://127.0.0.1:8080/api/v1'; this.checks = []; this.lastRequest = 0;
    this.remember({ password: process.env.BOOTSTRAP_ADMIN_PASSWORD, secret: process.env.APP_SECRET, key: process.env.CONSOLE_ENCRYPTION_KEY, token: process.env.PORTAL_SECRET });
    if (!resume) durableJson(M7_REFERENCE, this.state, 0o600, true);
    this.save();
  }
  save(extra = {}) { Object.assign(this.state, extra); this.state.secrets = [...new Set(this.state.secrets.filter(v => typeof v === 'string' && v.length))]; durableJson(M7_REFERENCE, this.state); }
  remember(value, fromResponse = false) {
    if (!value || typeof value !== 'object') return;
    for (const [key, item] of Object.entries(value)) {
      if (typeof item === 'string' && /^(password|current_password|new_password|secret|key|token|csrfToken|client_secret|accessToken|refreshToken)$/i.test(key)) {
        if (!fromResponse || !/^\[REDACTED:[a-f\d]{16}\]$/.test(item)) this.state.secrets.push(item);
      } else if (item && typeof item === 'object') this.remember(item, fromResponse);
    }
  }
  cookies(cookie) { for (const pair of cookie.split('; ')) { const at = pair.indexOf('='); if (/^kongos_(portal_)?(access|refresh|csrf)=/.test(pair)) this.state.secrets.push(pair.slice(at + 1)); } }
  check(condition, name, facts = {}) {
    if (!condition) { const error = new Error(name); error.safeEvidenceMessage = true; throw error; }
    this.checks.push({ name, passed: true, ...facts });
  }
  data(result, name = 'BFF success') {
    const code = result.payload?.error?.code;
    this.check(result.status >= 200 && result.status < 300, `${name}: HTTP ${result.status}${/^[A-Z0-9_]{1,80}$/.test(code ?? '') ? ` ${code}` : ''}`, { requestId: result.requestId });
    return result.payload?.data;
  }
  async request(session, path, method = 'GET', body, { key = randomUUID(), expected = [200, 201], raw = false, renew = true } = {}) {
    if (!path.startsWith('/') || path.startsWith('//') || path.includes('://') || path.includes('\\')) throw new Error('M7_RELATIVE_BFF_PATH_REQUIRED');
    if (!['GET', 'HEAD'].includes(method) && (this.state.inFlight != null || this.state.phase.startsWith('stopped') || this.state.requests.some(v => ['prepared', 'response_unknown'].includes(v.state)))) throw new Error('M7_ORIGINAL_UNRESOLVED_REQUEST_NO_FURTHER_WRITE');
    if (session && renew && path !== '/auth/refresh') await this.renewIfNeeded(session);
    // Clone/serialize exactly once before any transport scheduling await.
    const serializedBody = body === undefined ? undefined : JSON.stringify(body);
    const frozenBody = serializedBody === undefined ? undefined : JSON.parse(serializedBody);
    if (!['GET', 'HEAD'].includes(method) && (this.state.inFlight != null || this.state.phase.startsWith('stopped') || this.state.requests.some(v => ['prepared', 'response_unknown'].includes(v.state)))) throw new Error('M7_ORIGINAL_UNRESOLVED_REQUEST_NO_FURTHER_WRITE');
    this.remember(frozenBody); if (session?.cookie) this.cookies(session.cookie);
    const write = !['GET', 'HEAD'].includes(method), url = new URL(this.base + path);
    const requestHeaders = Object.freeze({ ...(session?.cookie ? { Cookie: session.cookie } : {}), ...(serializedBody === undefined ? {} : { 'Content-Type': 'application/json' }), ...(write ? { 'X-CSRF-Token': session?.csrf ?? '', 'X-Idempotency-Key': key } : {}) });
    const packet = write ? { index: this.state.requests.length, key, method, path: url.pathname, query: url.search, body: frozenBody, bodySha256: sha256(serializedBody ?? 'null'), actorId: session?.user?.id ?? null, sessionId: session?.sid ?? null,
      clusterId: url.pathname.match(/\/clusters\/([a-f0-9-]{36})/)?.[1] ?? frozenBody?.clusterId ?? null, workspaceId: url.searchParams.get('workspaceId') ?? frozenBody?.workspaceId ?? null, headers: requestHeaders, state: 'prepared', startedAt: new Date().toISOString(), expected } : undefined;
    if (packet) { this.state.requests.push(packet); this.save({ phase: 'request-in-flight', inFlight: packet.index }); }
    const pause = 100 - (Date.now() - this.lastRequest); if (pause > 0) await new Promise(r => setTimeout(r, pause)); this.lastRequest = Date.now();
    let response, bytes;
    try {
      response = await fetch(this.base + path, { method, redirect: 'manual', signal: AbortSignal.timeout(45000), headers: requestHeaders, ...(serializedBody === undefined ? {} : { body: serializedBody }) });
      // Header evidence must survive a broken body stream or malformed login
      // response, including when no named session exists yet.
      const setCookies = response.headers.getSetCookie();
      if (setCookies.length) {
        if (packet) packet.responseCookies = setCookies;
        const merged = cookieMerge(session?.cookie ?? '', setCookies); this.cookies(merged);
        if (session) session.cookie = merged;
        this.save();
      }
      bytes = Buffer.from(await response.arrayBuffer());
    } catch { if (packet) { packet.state = 'response_unknown'; this.save({ phase: 'stopped-unknown' }); } throw new Error('M7_RESPONSE_UNKNOWN_STOP_ORIGINAL_PACKET_RETAINED'); }
    let payload = null; try { payload = JSON.parse(bytes.toString('utf8')); } catch { /* Export bytes stay in RAM. */ }
    const requestId = payload?.meta?.requestId ?? response.headers.get('x-request-id'), result = { status: response.status, payload, bytes, response, requestId };
    this.remember(payload?.data, true);
    if (packet) { Object.assign(packet, { state: 'response_observed', status: response.status, requestId, responseData: payload?.data ?? null, errorCode: payload?.error?.code ?? null, responseSha256: sha256(bytes) }); this.save({ phase: 'request-observed', inFlight: null }); }
    this.check(expected.includes(response.status), `expected BFF HTTP ${expected.join('/')} received ${response.status}${/^[A-Z0-9_]{1,80}$/.test(payload?.error?.code ?? '') ? ` ${payload.error.code}` : ''}`, { method, path: url.pathname, requestId });
    if (!raw && response.status < 300) this.check(payload?.success === true || payload?.data !== undefined, 'successful JSON envelope is present');
    if (response.status >= 400) this.check(!this.state.secrets.filter(v => v.length >= 8).some(v => bytes.includes(Buffer.from(v))), 'denied response contains no captured secret');
    return result;
  }
  async login(label, username, password) {
    this.remember({ password }); this.save();
    const result = await this.request(null, '/auth/login', 'POST', { username, password }, { expected: [201], renew: false }), data = this.data(result, 'fresh named M7 login');
    const session = { label, username, user: data.user, csrf: data.csrfToken, cookie: cookieMerge('', result.response.headers.getSetCookie()) };
    this.updateSessionIdentity(session); this.cookies(session.cookie); this.remember({ csrfToken: session.csrf }); this.state.sessions[label] = session; this.save();
    this.check(!data.accessToken && !data.refreshToken && !result.bytes.includes(Buffer.from(password)), 'cookie-only login exposes no bearer/password');
    return session;
  }
  updateSessionIdentity(session) {
    const pair = session.cookie.split('; ').find(v => v.startsWith('kongos_access='));
    if (!pair) throw new Error('M7_ACCESS_COOKIE_REQUIRED');
    const value = JSON.parse(Buffer.from(pair.slice(14).split('.')[1], 'base64url').toString());
    if (value.sub !== session.user?.id) throw new Error('M7_ACCESS_ACTOR_CHANGED');
    session.sid = value.sid; session.expiresAt = value.exp * 1000;
    if (typeof session.sid !== 'string' || !Number.isFinite(session.expiresAt)) throw new Error('M7_SESSION_ID_REQUIRED');
  }
  async renewIfNeeded(session) {
    if (session.expiresAt > Date.now() + 90000) return;
    const oldSid = session.sid, oldActor = session.user.id, oldUsername = session.user.username, result = await this.request(session, '/auth/refresh', 'POST', {}, { expected: [201], renew: false }), data = this.data(result, 'normal same-SID session renewal');
    this.check(data.user?.id === oldActor && data.user?.username === oldUsername, 'normal session renewal retains original actor and username');
    session.csrf = session.cookie.split('; ').find(v => v.startsWith('kongos_csrf='))?.slice(12); session.user = data.user;
    this.check(typeof session.csrf === 'string' && session.csrf.length > 0, 'normal session renewal receives current CSRF cookie');
    this.updateSessionIdentity(session); this.cookies(session.cookie); this.remember({ csrfToken: session.csrf }); this.save();
    this.check(session.sid === oldSid, 'normal session renewal retains original SID');
  }
  async poll(read, predicate, name, timeoutMs = 30000) {
    const deadline = Date.now() + timeoutMs; let value;
    while (Date.now() < deadline) { value = await read(); if (predicate(value)) { this.check(true, name); return value; } await new Promise(r => setTimeout(r, 500)); }
    this.check(false, name); return value;
  }
  receiver(service, input) {
    if (!['event-receiver', 'event-mail'].includes(service) || !['stats', 'fault'].includes(input.action)) throw new Error('M7_RECEIVER_CONTROL_INVALID');
    if (input.action === 'fault' && (this.state.inFlight != null || this.state.phase.startsWith('stopped') || this.state.requests.some(v => ['prepared', 'response_unknown'].includes(v.state)))) throw new Error('M7_ORIGINAL_UNRESOLVED_REQUEST_NO_FURTHER_WRITE');
    const intent = { service, input, state: 'prepared', at: new Date().toISOString() }; this.state.providerControls.push(intent); this.save();
    const code = "import{connect}from'node:net';let b='';for await(const c of process.stdin)b+=c;const s=connect({path:'/tmp/receiver-control.sock'});s.setTimeout(3000,()=>process.exit(2));s.once('error',()=>process.exit(2));let o='';s.on('data',c=>{o+=c;if(o.length>300000)process.exit(2);});s.on('end',()=>process.stdout.write(o));s.on('connect',()=>s.end(b+'\\n'));";
    let value; try { value = JSON.parse(execFileSync('docker', [...M7_COMPOSE, 'exec', '-T', service, 'node', '--input-type=module', '-e', code], { input: JSON.stringify(input), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })); }
    catch { intent.state = 'unknown'; this.save({ phase: 'stopped-provider-unknown' }); throw new Error('M7_RECEIVER_CONTROL_UNKNOWN'); }
    intent.state = 'observed'; intent.ok = value.ok === true; this.save(); if (!value.ok) throw new Error('M7_RECEIVER_CONTROL_REJECTED'); return value;
  }
  finish(error, path = 'artifacts/M7/security-live.json', completedPhase = 'http-complete') {
    if (!['http-complete', 'producers-complete', 'cleanup-complete'].includes(completedPhase)) throw new Error('M7_COMPLETION_PHASE_INVALID');
    if (error) this.checks.push({ name: error.safeEvidenceMessage ? error.message : 'Unexpected runtime failure; private packet retained', passed: false });
    this.save({ phase: error ? 'stopped-failure' : completedPhase, inFlight: this.state.inFlight ?? null });
    const report = { performedAt: new Date().toISOString(), milestone: 'M7', testTag: this.state.testTag, allPassed: !error,
      passed: this.checks.filter(v => v.passed).length, failed: this.checks.filter(v => !v.passed).length, checks: this.checks,
      successfulWrites: this.state.requests.filter(v => v.status >= 200 && v.status < 300).length,
      unknownWrites: this.state.requests.filter(v => v.state === 'response_unknown').length, privateReferenceRetained: true,
      fixtures: this.state.fixtures.map(({ cid, wid, type, id, name }) => ({ cid, wid, type, id, name })), secretsPublished: false,
      ...(this.public ?? {}) };
    durableJson(path, report, 0o644, !existsSync(path)); console.log(JSON.stringify({ allPassed: report.allPassed, passed: report.passed, failed: report.failed, successfulWrites: report.successfulWrites, unknownWrites: report.unknownWrites }));
    return error ? 1 : 0;
  }
}
