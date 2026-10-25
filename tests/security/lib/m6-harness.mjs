import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { renameSync, writeFileSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { findSecretArtifacts } from '../check-artifacts.mjs';
import { M4Harness, entity, rows, scope, strongPassword } from './m4-harness.mjs';
import { M6_REFERENCE, privateReference } from './m6-reference.mjs';
import { verifyM6AuditCoverage } from './m6-audit-secret-provenance.mjs';

export { entity, rows, scope, strongPassword };
export { M6_REFERENCE, privateReference };
export const M6_C1 = 'dff45535-ed8d-4851-b7a6-6376feac7f59';
export const M6_C2 = 'd1dfaec8-2a10-4170-8a15-20a600a4bd4f';
export const PORTAL_COOKIE_NAMES = ['kongos_portal_access', 'kongos_portal_refresh', 'kongos_portal_csrf'];

export function portalScope(path, tenant) {
  const url = new URL(path, 'http://private.invalid');
  url.searchParams.set('clusterId', tenant.clusterId);
  url.searchParams.set('workspaceId', tenant.workspaceId);
  return `${url.pathname}${url.search}`;
}
export function cookieMerge(current, setCookies) {
  const pairs = new Map(current.split('; ').filter(Boolean).map(pair => { const at = pair.indexOf('='); return [pair.slice(0, at), pair.slice(at + 1)]; }));
  for (const header of setCookies) { const pair = header.split(';')[0], at = pair.indexOf('='); pairs.set(pair.slice(0, at), pair.slice(at + 1)); }
  return [...pairs].map(([key, value]) => `${key}=${value}`).join('; ');
}
export function workflowEntity(value) { const item = entity(value); return item?.id && item?.planHash && item?.kind ? item : undefined; }
export function releasedReservation(facts) {
  return Boolean(facts?.reservation_released_at && facts.state === 'disabled' && ['cancelled', 'rejected', 'expired'].includes(facts.workflow_state)
    && facts.current_generation === 0 && !facts.current_credential_id && !facts.acl_credential_ref_id
    && facts.no_live_workflows === true && facts.no_executions === true && facts.no_bound_native_steps === true && facts.no_issued_credentials === true && facts.no_mutation_receipts === true && facts.no_native_operations === true && facts.no_credential_refs === true);
}
export function reservationFacts(h, grantId) {
  return h.consoleRead(`SELECT g.id,g.consumer_id,g.acl_id,g.state,g.reservation_released_at,g.current_generation,g.current_credential_id,g.acl_credential_ref_id,w.state AS workflow_state,
    NOT EXISTS(SELECT 1 FROM workflows x WHERE x.subject_type='portal_application_grants' AND x.subject_id=g.id AND x.cluster_id=g.cluster_id AND x.workspace_id=g.workspace_id AND (x.kind<>'portal-credential-issue' OR x.state NOT IN ('cancelled','rejected','expired'))) AS no_live_workflows,
    NOT EXISTS(SELECT 1 FROM workflow_executions e JOIN workflows x ON x.id=e.workflow_id WHERE x.subject_type='portal_application_grants' AND x.subject_id=g.id AND x.cluster_id=g.cluster_id AND x.workspace_id=g.workspace_id) AS no_executions,
    NOT EXISTS(SELECT 1 FROM workflow_steps s JOIN workflows x ON x.id=s.workflow_id WHERE x.subject_type='portal_application_grants' AND x.subject_id=g.id AND x.cluster_id=g.cluster_id AND x.workspace_id=g.workspace_id AND (s.state<>'pending' OR s.operation_id IS NOT NULL OR s.receipt_secret IS NOT NULL OR s.safe_result<>'{}'::jsonb OR s.started_at IS NOT NULL OR s.completed_at IS NOT NULL OR s.after_fingerprint IS NOT NULL OR s.recycle_entry_id IS NOT NULL)) AS no_bound_native_steps,
    NOT EXISTS(SELECT 1 FROM portal_credentials c WHERE c.grant_id=g.id AND (c.state<>'pending' OR c.credential_ref_id IS NOT NULL OR c.issue_operation_id IS NOT NULL OR c.revoke_workflow_id IS NOT NULL OR c.revoke_operation_id IS NOT NULL OR c.recycle_entry_id IS NOT NULL OR c.revoked_at IS NOT NULL OR c.deleted_at IS NOT NULL OR c.retention_until IS NOT NULL OR c.last_revealed_at IS NOT NULL OR NOT EXISTS(SELECT 1 FROM workflows x WHERE x.id=c.workflow_id AND x.subject_type='portal_application_grants' AND x.subject_id=g.id AND x.cluster_id=g.cluster_id AND x.workspace_id=g.workspace_id AND x.kind='portal-credential-issue' AND x.state IN ('cancelled','rejected','expired')))) AS no_issued_credentials,
    NOT EXISTS(SELECT 1 FROM mutation_operations m JOIN workflows x ON x.id=m.workflow_id WHERE x.subject_type='portal_application_grants' AND x.subject_id=g.id AND x.cluster_id=g.cluster_id AND x.workspace_id=g.workspace_id) AS no_mutation_receipts,
    NOT EXISTS(SELECT 1 FROM mutation_operations m WHERE m6_portal_scope_alias(m.cluster_id,g.transport_scope,g.cluster_id) AND ((m.entity_type='consumers' AND m.entity_id=g.consumer_id::text) OR (m.entity_type='credentials' AND (m.parent_id=g.consumer_id::text OR m.entity_id=g.acl_id::text OR m.entity_id IN(SELECT c.kong_id::text FROM portal_credentials c WHERE c.grant_id=g.id))))) AS no_native_operations,
    NOT EXISTS(SELECT 1 FROM credential_refs r WHERE m6_portal_scope_alias(r.cluster_id,g.transport_scope,g.cluster_id) AND (r.consumer_id=g.consumer_id OR r.kong_id=g.acl_id OR r.kong_id IN(SELECT c.kong_id FROM portal_credentials c WHERE c.grant_id=g.id))) AS no_credential_refs
    FROM portal_application_grants g JOIN workflows w ON w.id=g.workflow_id WHERE g.id=$1`, [grantId])[0];
}

/** Real requests run serially only after an explicit deployment handoff. Secrets
 * and original keys are journaled before writes, never copied into evidence. */
export class M6Harness extends M4Harness {
  constructor(options = {}) {
    super();
    this.reference = options.referencePath ?? M6_REFERENCE;
    this.referenceData = privateReference(this.reference, options.requireReference ?? false);
    this.tag = this.referenceData.testTag ?? `m6-security-${randomUUID().slice(0, 8)}`;
    this.secrets.push(...(this.referenceData.secrets ?? []),...(this.referenceData.tokens??[]).map(row=>row.token));
    if (process.env.PORTAL_SECRET) this.secrets.push(process.env.PORTAL_SECRET);
    this.users = this.referenceData.users ?? [];
    this.journal = this.referenceData.fixtureJournal ?? [];
    this.writeAttempts = this.referenceData.writeAttempts ?? [];
    this.successfulWrites = this.referenceData.writeEvidence ?? [];
    this.portalSessions = this.referenceData.portalSessions ?? [];
    this.portalBase = (process.env.PORTAL_SECURITY_BASE_URL ?? 'http://127.0.0.1:8082/api/v1/portal').replace(/\/$/, '');
    this.portalOrigin = new URL(this.portalBase).origin;
    this.liveEnabled = options.liveEnabled ?? process.env.M6_DEPLOYMENT_READY === 'true';
    this.public = { canonicalClusters: [M6_C1, M6_C2], generatedSecretsPublished: false };
  }
  requireLive() { if (!this.liveEnabled) throw new Error('M6 deployment and exclusive live handoff required'); }
  checkpoint(phase, extra = {}) {
    this.saveReference({ ...extra, phase });
    console.log(JSON.stringify({ phase, completedChecks: this.checks.length, generatedSecretsPublished: false }));
  }
  metadataEntity(result, id, label) {
    const item = result?.entity;
    this.check(Boolean(item?.id && result?.workflowId && item.id !== result.workflowId && !item.kind && result?.receipt?.state === 'succeeded'), id, `${label}: direct creation returns the actual portal object and a separate successful workflow receipt`);
    return item;
  }
  remember(value) {
    if (!value || typeof value !== 'object') return;
    for (const [name, item] of Object.entries(value)) {
      if (typeof item === 'string' && /^(password|current_?password|new_?password|client_?secret|secret|key|csrfToken|accessToken|refreshToken|token)$/i.test(name)) this.secrets.push(item);
      else if (item && typeof item === 'object') this.remember(item);
    }
  }
  saveReference(extra = {}) {
    // Preserve trusted metrics capture and manual evidence, including properties
    // this runner does not know. A failed write still retains its original key.
    const disk = privateReference(this.reference);
    const secrets = [...new Set([...this.secrets, ...(disk.secrets ?? [])].filter(value => typeof value === 'string' && value.length > 0))];
    this.secrets = secrets;
    this.referenceData = { ...disk, ...this.referenceData, ...extra, testTag: this.tag, secrets, users: this.users, fixtureJournal: this.journal, writeAttempts: this.writeAttempts, writeEvidence: this.successfulWrites, portalSessions: this.portalSessions };
    const temporary = `${this.reference}.${randomUUID()}.tmp`;
    writeFileSync(temporary, JSON.stringify(this.referenceData), { mode: 0o600, flag: 'wx' });
    renameSync(temporary, this.reference);
  }
  attempt(origin, session, path, method, body, key) {
    const url = new URL(path, origin);
    this.remember(body);
    const attempt = { key, origin, method, path: url.pathname, query: url.search, body, clusterId: body?.clusterId ?? url.searchParams.get('clusterId') ?? url.pathname.match(/\/clusters\/([\da-f-]+)/)?.[1], workspaceId: body?.workspaceId ?? url.searchParams.get('workspaceId'), actorId: session?.developer?.id ?? session?.user?.id ?? null, startedAt: new Date().toISOString(), state: 'not_observed' };
    this.writeAttempts.push(attempt); this.saveReference(); return attempt;
  }
  observed(attempt, result) {
    // Observing an HTTP error is not proof of a failed native write. Preserve
    // the exact private outcome for original-key recovery instead of guessing.
    this.remember(result.payload?.data);
    if (attempt) Object.assign(attempt, { state: 'response_observed', httpStatus: result.status, requestId: result.payload?.meta?.requestId, responseData: result.payload?.data, errorCode: result.payload?.error?.code, errorDetails: result.payload?.error?.details, serverState: result.payload?.error?.details?.state ?? result.payload?.error?.state ?? result.payload?.data?.state });
  }
  async request(session, path, method = 'GET', body, options = {}) {
    this.requireLive(); this.remember(body);
    if (session?.cookie) this.rememberCookies(session.cookie);
    const write = !['GET', 'HEAD'].includes(method), key = options.key ?? randomUUID();
    const attempt = write ? this.attempt(new URL(this.base).origin, session, new URL(this.base).pathname + path, method, body, key) : undefined;
    try {
      const result = await super.request(session, path, method, body, { ...options, key });
      this.observed(attempt, result);
      this.saveReference(); return result;
    } catch (error) {
      if (attempt) attempt.state = 'response_unknown';
      this.saveReference(); throw error;
    }
  }
  rememberCookies(cookie) {
    for (const pair of cookie.split('; ').filter(Boolean)) { const at = pair.indexOf('='); if (/^kongos_(portal_)?(access|refresh|csrf)=/.test(pair)) this.secrets.push(pair.slice(at + 1)); }
  }
  async login(username, password, id) {
    const session = await super.login(username, password, id);
    this.rememberCookies(session.cookie); this.secrets.push(session.csrf); this.saveReference(); return session;
  }
  async create(...args) {
    const result = await super.create(...args);
    this.saveReference(); return result;
  }
  async proxy(cluster,path,method='GET',body,headers={}) {
    this.requireLive();
    const configured=this.referenceData.portalTestTargets;
    const allowed=configured?[configured.primary,configured.secondary]:[{id:M6_C1,adminUrl:'http://kong:8001',proxyOrigin:'http://127.0.0.1:8000'},{id:M6_C2,adminUrl:'http://kong-secondary:8001',proxyOrigin:'http://127.0.0.1:9000'}];
    const target=allowed.find(row=>row.id===cluster.id&&row.adminUrl===cluster.admin_url);
    const strict=configured?/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(configured.primary.id??'')&&![M6_C1,M6_C2].includes(configured.primary.id)&&configured.primary.adminUrl==='http://kong-portal-admin-endpoint:8001'&&configured.primary.proxyOrigin==='http://127.0.0.1:10000'&&configured.secondary.id===M6_C2&&configured.secondary.adminUrl==='http://kong-secondary:8001'&&configured.secondary.proxyOrigin==='http://127.0.0.1:9000':true;
    if(!target||!strict||typeof path!=='string'||!path.startsWith('/')||path.startsWith('//')||path.includes('://')||path.includes('\\'))throw new Error('M6 proxy target must be the exact trusted fixture cluster and fixed local origin');
    const response=await fetch(target.proxyOrigin+path,{method,headers:{...(body!==undefined?{'Content-Type':'application/json'}:{}),...headers},...(body!==undefined?{body:JSON.stringify(body)}:{}),redirect:'manual',signal:AbortSignal.timeout(15_000)});
    await response.arrayBuffer();return response.status;
  }
  async portal(session, path, method = 'GET', body, options = {}) {
    this.requireLive();
    if (!path.startsWith('/') || path.startsWith('//') || path.includes('://')) throw new Error('portal path must be relative');
    this.remember(body); if (session?.cookie) this.rememberCookies(session.cookie);
    const write = !['GET', 'HEAD'].includes(method), key = options.key ?? randomUUID();
    const attempt = write ? this.attempt(this.portalOrigin, session, new URL(this.portalBase).pathname + path, method, body, key) : undefined;
    const pause = 80 - (Date.now() - this.lastRequest); if (pause > 0) await new Promise(resolve => setTimeout(resolve, pause));
    this.lastRequest = Date.now();
    try {
      const response = await fetch(this.portalBase + path, { method, redirect: 'manual', signal: AbortSignal.timeout(30_000), headers: { Origin: this.portalOrigin, 'Sec-Fetch-Site': 'same-origin', ...(session?.cookie ? { Cookie: session.cookie } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(write ? { 'X-Portal-CSRF': session?.csrf ?? '', 'X-Idempotency-Key': key } : {}), ...options.headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      const text = await response.text(); let payload; try { payload = JSON.parse(text); } catch { payload = null; }
      this.lastEvidenceRequest = { origin: 'portal', method, path: path.split('?')[0], status: response.status };
      this.observed(attempt, { status: response.status, payload });
      if (write && response.status >= 200 && response.status < 300) this.successfulWrites.push({ origin: 'portal', method, path: `/api/v1/portal${path.split('?')[0]}`, requestId: payload?.meta?.requestId });
      const result = { status: response.status, text, payload, response };
      this.saveReference(); return result;
    } catch (error) { if (attempt) attempt.state = 'response_unknown'; this.saveReference(); throw error; }
  }
  async portalCsrf(tenant, session = {}) {
    const result = await this.portal(session, portalScope('/auth/csrf', tenant));
    const data = this.ok(result, 'Auth/CSRF', 'scoped portal CSRF bootstrap');
    this.check(typeof data.csrfToken === 'string' && data.csrfToken.length >= 16, 'Auth/CSRF', 'portal CSRF is present');
    this.secrets.push(data.csrfToken);
    const next = { ...session, tenant, cookie: cookieMerge(session.cookie ?? '', result.response.headers.getSetCookie()), csrf: data.csrfToken };
    this.rememberCookies(next.cookie); this.saveReference(); return next;
  }
  async portalLogin(tenant, username, password, label) {
    this.secrets.push(password); let session = await this.portalCsrf(tenant);
    const result = await this.portal(session, '/auth/login', 'POST', { ...tenant, username, password });
    const data = this.ok(result, 'Auth/Login', 'reviewed developer authenticates in its exact tenant');
    session = { ...session, username, label, cookie: cookieMerge(session.cookie, result.response.headers.getSetCookie()), csrf: data.csrfToken, developer: data.developer };
    this.rememberCookies(session.cookie); this.secrets.push(session.csrf);
    for (const header of result.response.headers.getSetCookie()) this.check(header.includes('HttpOnly') && /SameSite=Strict/i.test(header) && /Path=\/api\/v1\/portal(?:;|$)/i.test(header), 'Auth/Cookies', 'portal cookie is HttpOnly, SameSite Strict and portal-path scoped');
    this.check(data.developer.clusterId === tenant.clusterId && data.developer.workspaceId === tenant.workspaceId && !data.accessToken && !data.refreshToken && !result.text.includes(password), 'Auth/Login', 'developer response has exact tenant and no bearer/password');
    this.portalSessions.push(session); this.saveReference(); return session;
  }
  async portalReject(session, path, method, body, id, name, statuses = [403], options) {
    const result = await this.portal(session, path, method, body, options);
    this.check(statuses.includes(result.status), id, `${name}: HTTP ${result.status}`);
    this.check(!this.secrets.filter(value => value.length >= 8).some(secret => result.text.includes(secret)), id, 'denied portal response exposes no known credential'); return result;
  }
  // M6 fixtures and cleanup exclusively use audited BFF and workflow routes.
  native() { throw new Error('M6 has no native Admin fixture escape'); }
  consoleRead(sql, params = []) {
    this.requireLive();
    if (!/^\s*SELECT\b/i.test(sql) || /;|\b(INSERT|UPDATE|DELETE|TRUNCATE|ALTER|DROP|CREATE|COPY|CALL)\b/i.test(sql)) throw new Error('private evidence query must be read-only');
    const code = `import pg from 'pg';let s='';for await(const c of process.stdin)s+=c;const q=JSON.parse(s);const p=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});let client;try{client=await p.connect();await client.query('BEGIN READ ONLY');const r=await client.query(q.sql,q.params);await client.query('ROLLBACK');process.stdout.write(JSON.stringify(r.rows));}catch{if(client)await client.query('ROLLBACK').catch(()=>{});process.exitCode=2;}finally{client?.release();await p.end();}`;
    return JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', code], { input: JSON.stringify({ sql, params }), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  }
  verifyAuditCoverage() { return verifyM6AuditCoverage(this); }
  verifyAppendOnlyStorage() {
    this.requireLive();
    // Every statement executes in its own rollback-only transaction. These
    // fixed empty UPDATE/DELETE statements do not change rows even if a grant
    // is accidentally too broad; TRUNCATE is protected by production triggers.
    const tables = ['audit_events', 'workflow_versions', 'workflow_approvals', 'workflow_events', 'portal_publication_proofs'];
    const code = `import pg from 'pg';const p=new pg.Pool({connectionString:process.env.DATABASE_URL??process.env.CONSOLE_DATABASE_URL});const tables=${JSON.stringify(tables)},checks=[];let client;try{client=await p.connect();const role=(await client.query('SELECT rolsuper,rolname FROM pg_roles WHERE rolname=current_user')).rows[0];for(const table of tables)for(const action of ['UPDATE','DELETE','TRUNCATE']){await client.query('BEGIN');let rejected=false,errorClass=null;try{await client.query(action==='UPDATE'?'UPDATE '+table+' SET cluster_id=cluster_id WHERE false':action==='DELETE'?'DELETE FROM '+table+' WHERE false':'TRUNCATE '+table);}catch(e){rejected=true;errorClass=e.code;}finally{await client.query('ROLLBACK');}checks.push({table,action,rejected,errorClass});}process.stdout.write(JSON.stringify({superuser:role.rolsuper,checks}));}catch{if(client)await client.query('ROLLBACK').catch(()=>{});process.exitCode=2;}finally{client?.release();await p.end();}`;
    const result = JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '--input-type=module', '-e', code], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
    this.check(result.superuser === false, 'Storage/Runtime', 'actual console SQL runtime is not a PostgreSQL superuser');
    for (const row of result.checks) this.check(row.rejected && ['42501', '55000', 'P0001'].includes(row.errorClass), 'Storage/AppendOnly', `${row.table} rejects actual ${row.action} under the runtime account`);
    this.public.appendOnlyRuntimeStorage = result;
  }
  async finish(error) {
    if (error) this.checks.push({ id: 'GATE', name: error.safeEvidenceMessage ? error.message : `Unexpected ${error.name ?? 'Error'}; sensitive runtime detail withheld`, passed: false });
    this.saveReference(); await mkdir('artifacts/M6', { recursive: true });
    const evidence = { performedAt: new Date().toISOString(), kind: 'real-Kong-1.5-M6-portal-workflow-isolation', testTag: this.tag, ...this.public, ...(error ? { lastHttpRequest: this.lastEvidenceRequest } : {}), passed: this.checks.filter(row => row.passed).length, failed: this.checks.filter(row => !row.passed).length, checks: this.checks, fixtures: this.journal, privateReferenceRetained: true, nativeFixturesAndCleanup: 'Audited BFF/workflow only; no direct Admin or Kong database.' };
    writeFileSync('artifacts/M6/security-live.json', JSON.stringify(evidence, null, 2) + '\n');
    const encoded = (this.referenceData.tokens ?? []).filter(row => row.purpose === 'collector_ingest').flatMap(row => { const value = Buffer.from(`kongos:${row.token}`).toString('base64'); return [value, `Basic ${value}`]; });
    const scan = findSecretArtifacts([...this.secrets, ...encoded]);
    writeFileSync('artifacts/M6/http-secret-artifact-scan.json', JSON.stringify({ performedAt: new Date().toISOString(), ...scan, allPassed: !scan.leaks.length, coversFutureBrowserArtifacts: false, referenceRetainedPrivately: true }, null, 2) + '\n');
    console.log(JSON.stringify({ passed: evidence.passed, failed: evidence.failed, leaks: scan.leaks.length })); return evidence.failed || scan.leaks.length ? 1 : 0;
  }
}
