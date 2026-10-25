import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { closeSync, openSync, writeSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ReleaseHarness, releasePassword, releaseScope } from './lib/release-harness.mjs';
import { assertReleaseReportDirectory, selectReleaseReportDirectory } from './lib/release-private-directory.mjs';
import { businessPortalPublicationBody } from './m11-business-portal-schedule-http.mjs';

// SOURCE ONLY until Root explicitly invokes one stage. Importing this module
// opens no ledger, transport, container, SQL connection or timer. Fresh Portal
// identities belong to this run; historical RAM fixtures are never adopted.
export const CURRENT_PORTAL_STAGES = Object.freeze(['preflight', 'policy', 'settings', 'developer-register',
  'developer-approve', 'application', 'publication-create', 'publication-publish', 'request', 'author',
  'vote', 'activate', 'observe', 'verify-key', 'revoke-request', 'revoke-vote', 'revoke-execute', 'verify-revoked', 'inspect']);
const readonlyStages = new Set(['observe', 'inspect']);
const uuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const sha = value => createHash('sha256').update(value).digest('hex');
const canonical = value => value && typeof value === 'object'
  ? Array.isArray(value) ? value.map(canonical) : Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const entity = value => value?.entity ?? value;
const pause = ms => new Promise(done => setTimeout(done, ms));
const code = error => /^[A-Z][A-Z0-9_]{2,120}$/.test(error?.message ?? '') ? error.message : 'CURRENT_PORTAL_STAGE_ASSERTION_OR_HTTP_FAILURE';
const allowedExecuteKinds = new Set(['workflow-policy-metadata', 'portal-metadata', 'portal-publication', 'portal-credential-revoke']);
const own = (value, key) => value != null && Object.hasOwn(value, key);
const plain = value => value && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const reservedNames = new Set([...Object.getOwnPropertyNames(Object.prototype), 'prototype']);
const originalCase = Object.freeze({ version: 1, caseId: 'original', fixtureField: null, oncePrefix: 'm11-current-portal-' });

/** Explicit new cases never adopt the default case's native fixture, original
 * stage journal, unknown operation or command labels. The default stays byte-
 * compatible with the original private state and its readonly inspection. */
export function currentPortalCaseSelection(env) {
  const id = env.RELEASE_LAB_M11_CURRENT_PORTAL_CASE, field = env.RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE;
  if (id === undefined && field === undefined) return originalCase;
  assert(typeof id === 'string' && /^[a-z][a-z0-9-]{0,47}$/.test(id) && !reservedNames.has(id), 'EXACT_CURRENT_PORTAL_CASE_REQUIRED');
  if (id === 'original') { assert(field === undefined, 'ORIGINAL_CURRENT_PORTAL_FIXTURE_MUST_NOT_BE_REBOUND'); return originalCase; }
  assert(typeof field === 'string' && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(field) && !reservedNames.has(field),
    'EXPLICIT_CURRENT_PORTAL_FIXTURE_FIELD_REQUIRED');
  return Object.freeze({ version: 1, caseId: id, fixtureField: field, oncePrefix: `m11-current-portal.case:${id}:` });
}

export function currentPortalSelectedFixture(state, selection) {
  const metadata = state.metadataAcceptance;
  let fixture;
  if (selection.caseId === 'original') fixture = { serviceId: metadata?.service?.id, routeId: metadata?.metricsRouteId, routePath: metadata?.metricsRoutePath };
  else {
    assert(own(metadata, selection.fixtureField), 'EXPLICIT_CURRENT_PORTAL_FIXTURE_MISSING');
    const selected = metadata[selection.fixtureField];
    assert(plain(selected)
      && Object.keys(selected).sort().join(',') === ['clusterId', 'workspaceId', 'serviceId', 'routeId', 'routePath'].sort().join(',')
      && selected.clusterId === state.cid && selected.workspaceId === state.wid, 'EXPLICIT_CURRENT_PORTAL_FIXTURE_SCOPE_REQUIRED');
    fixture = { serviceId: selected.serviceId, routeId: selected.routeId, routePath: selected.routePath };
  }
  assert(uuid(fixture.serviceId) && uuid(fixture.routeId) && typeof fixture.routePath === 'string' && fixture.routePath.startsWith('/'),
    'ACTUAL_CURRENT_PORTAL_SERVICE_ROUTE_REQUIRED');
  if (selection.caseId !== 'original') assert(!/[\[\]()+*?|^$?#%\\]/.test(fixture.routePath)
    && !fixture.routePath.includes('..') && !fixture.routePath.startsWith('//'), 'EXPLICIT_CURRENT_PORTAL_PLAIN_ROUTE_PATH_REQUIRED');
  return Object.freeze(fixture);
}

function caseBinding(selection, state, fixture) {
  return Object.freeze({ ...selection, clusterId: state.cid, workspaceId: state.wid,
    serviceId: fixture.serviceId, routeId: fixture.routeId, routePath: fixture.routePath });
}

function isolatedCaseFixture(state, selection, fixture) {
  if (selection.caseId === 'original') return;
  const legacy = state.currentPortalNaturalOriginal;
  if (legacy !== undefined) assert(plain(legacy) && legacy.version === 1 && plain(legacy.fixture)
    && uuid(legacy.fixture.serviceId) && uuid(legacy.fixture.routeId), 'ORIGINAL_CURRENT_PORTAL_CASE_STORE_INVALID');
  const others = [...(legacy === undefined ? [] : [legacy]),
    { fixture: { serviceId: state.metadataAcceptance?.service?.id, routeId: state.metadataAcceptance?.metricsRouteId } }];
  const cases = state.currentPortalNaturalCases;
  if (cases !== undefined) {
    assert(plain(cases), 'ORIGINAL_CURRENT_PORTAL_CASE_STORE_INVALID');
    for (const [id, value] of Object.entries(cases)) if (id !== selection.caseId) {
      assert(plain(value) && value.version === 2 && value.caseBinding?.caseId === id && plain(value.fixture)
        && value.clusterId === state.cid && value.workspaceId === state.wid
        && uuid(value.fixture.serviceId) && uuid(value.fixture.routeId), 'ORIGINAL_CURRENT_PORTAL_CASE_STORE_INVALID');
      const binding = currentPortalCaseSelection({ RELEASE_LAB_M11_CURRENT_PORTAL_CASE: id,
        RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: value.caseBinding.fixtureField });
      assert.deepEqual(value.caseBinding, caseBinding(binding, state, currentPortalSelectedFixture(state, binding)),
        'ORIGINAL_CURRENT_PORTAL_CASE_BINDING_CHANGED');
      currentPortalOnceLabel(value, 'fixture-ownership');
      others.push(value);
    }
  }
  for (const other of others) {
    assert(other.caseBinding?.fixtureField !== selection.fixtureField, 'CURRENT_PORTAL_FIXTURE_FIELD_ALREADY_BOUND');
    assert(!uuid(other.fixture?.serviceId) || other.fixture.serviceId.toLowerCase() !== fixture.serviceId.toLowerCase(),
      'CURRENT_PORTAL_SERVICE_ALREADY_BOUND_TO_ANOTHER_CASE');
    assert(!uuid(other.fixture?.routeId) || other.fixture.routeId.toLowerCase() !== fixture.routeId.toLowerCase(),
      'CURRENT_PORTAL_ROUTE_ALREADY_BOUND_TO_ANOTHER_CASE');
  }
}

export function currentPortalOnceLabel(g, label) {
  if (!g.caseBinding) { assert(g.version !== 2, 'ORIGINAL_CURRENT_PORTAL_CASE_BINDING_REQUIRED'); return `${originalCase.oncePrefix}${label}`; }
  const expected = currentPortalCaseSelection({ RELEASE_LAB_M11_CURRENT_PORTAL_CASE: g.caseBinding.caseId,
    RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: g.caseBinding.fixtureField });
  assert(expected.caseId !== 'original', 'ORIGINAL_CURRENT_PORTAL_CASE_BINDING_INVALID');
  assert.deepEqual(g.caseBinding, caseBinding(expected, { cid: g.clusterId, wid: g.workspaceId }, g.fixture), 'ORIGINAL_CURRENT_PORTAL_CASE_BINDING_CHANGED');
  return `${expected.oncePrefix}${label}`;
}

export function currentPortalConfiguration(env, stage) {
  assert.equal(env.RELEASE_LAB_M11_CURRENT_PORTAL_READY, 'true', 'EXPLICIT_CURRENT_PORTAL_ACCEPTANCE_GATE_REQUIRED');
  assert(CURRENT_PORTAL_STAGES.includes(stage), 'EXACT_CURRENT_PORTAL_STAGE_REQUIRED');
  const origin = (raw, proxy) => {
    let url; try { url = new URL(raw); } catch { throw Error('EXPLICIT_CURRENT_PORTAL_ORIGINS_REQUIRED'); }
    assert(url.origin === raw && ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password
      && !['8001', '8444', '5445'].includes(url.port), 'CURRENT_PORTAL_ORIGIN_MUST_NOT_BE_ADMIN_OR_API');
    if (proxy) assert(!/^(localhost|kong|console-api|kong-db|postgres|redis)$/i.test(url.hostname), 'CURRENT_PORTAL_PUBLIC_PROXY_ORIGIN_REQUIRED');
    return url.origin;
  };
  const registeredProxyOrigin = origin(env.RELEASE_LAB_M11_REGISTERED_PROXY_ORIGIN, false), registered = new URL(registeredProxyOrigin);
  assert(registered.protocol === 'http:' && registered.port === '8000'
    || registered.protocol === 'https:' && registered.port === '8443', 'EXPLICIT_CURRENT_PORTAL_REGISTERED_PROXY_LISTENER_REQUIRED');
  return Object.freeze({ portalOrigin: origin(env.RELEASE_LAB_M11_PORTAL_ORIGIN, false), registeredProxyOrigin,
    publicProxyOrigin: env.RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN === 'null'
      ? null : origin(env.RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN, true) });
}

/** A public documentation server is optional. Actual probe transport remains
 * the BFF's protected, currently registered proxy; neither this hostname nor
 * a public document URL is used as a direct fetch destination by the runner. */
export function currentPortalProbeHost(route, cluster, configuration) {
  assert(typeof cluster?.proxy_origin === 'string' && cluster.proxy_origin === configuration.registeredProxyOrigin,
    'CURRENT_PORTAL_REGISTERED_PROXY_ORIGIN_CHANGED');
  const host = route.hosts?.length ? route.hosts[0] : new URL(cluster.proxy_origin).hostname;
  assert(typeof host === 'string' && /^[a-z\d.-]+$/i.test(host) && !host.includes('*'), 'PLAIN_CURRENT_PORTAL_PROXY_HOST_REQUIRED');
  return host;
}

export function currentPortalPublicOriginMatches(settings, configuration) {
  return settings?.publicProxyOrigin === (configuration.publicProxyOrigin ?? '');
}

export function currentPortalIssuePolicy(reviewerId) {
  assert(uuid(reviewerId), 'REAL_CURRENT_PORTAL_REVIEWER_REQUIRED');
  return { version: 2, kind: 'portal-credential-issue', allowSelfApproval: false, distinctAcrossStages: true,
    intentTtlHours: 24, stages: [{ level: 1, name: '独立审批', mode: 'any', threshold: 1, selector: { users: [reviewerId] } }] };
}

export function currentPortalWindow(expiresAt, now = Date.now()) {
  assert(Number.isSafeInteger(now) && Number.isFinite(Date.parse(expiresAt)), 'ORIGINAL_PORTAL_WORKFLOW_DEADLINE_REQUIRED');
  const notBefore = now + 120_000, windowEnd = now + 480_000;
  assert(windowEnd <= Date.parse(expiresAt), 'ORIGINAL_PORTAL_DEADLINE_NOT_RENEWABLE');
  return { notBefore: new Date(notBefore).toISOString(), windowStart: new Date(notBefore).toISOString(),
    windowEnd: new Date(windowEnd).toISOString() };
}

export function currentPortalVoteBody(detail, expectedKind) {
  const row = detail?.entity;
  assert(row?.kind === expectedKind && row.state === 'pending' && row.approvalRequired === true
    && row.capabilities?.approve === true && Number.isInteger(row.revision) && /^[a-f\d]{64}$/.test(row.planHash ?? ''),
  'CURRENT_INDEPENDENT_REVIEWER_CAPABILITY_REQUIRED');
  const body = { revision: row.revision, planHash: row.planHash, confirmed: true, confirm_name: expectedKind,
    execute: false, reason: 'M11 当前候选真实独立审批' };
  if (row.approval !== undefined) {
    const active = row.approval.stages?.filter(stage => stage.state === 'active');
    assert(row.approval.format === 2 && active?.length === 1 && Number.isInteger(row.approval.candidateVersion)
      && Number.isInteger(active[0].level) && Number.isInteger(active[0].revision), 'ACTUAL_CURRENT_PORTAL_APPROVAL_STAGE_REQUIRED');
    Object.assign(body, { level: active[0].level, stageRevision: active[0].revision, candidateVersion: row.approval.candidateVersion });
  }
  return body;
}

function scope(g, path, extra) { return releaseScope(g.clusterId, g.workspaceId, path, extra); }
function tenant(g) { return { clusterId: g.clusterId, workspaceId: g.workspaceId }; }
function portalScope(g, path) { return `${path}${path.includes('?') ? '&' : '?'}${new URLSearchParams(tenant(g))}`; }
function cookieMerge(current, values) {
  const jar = new Map((current ?? '').split('; ').filter(Boolean).map(value => { const at = value.indexOf('='); return [value.slice(0, at), value.slice(at + 1)]; }));
  for (const header of values) { const value = header.split(';')[0], at = value.indexOf('='); const name = value.slice(0, at);
    assert(name.startsWith('kongos_portal_'), 'CONSOLE_COOKIE_FORBIDDEN_IN_CURRENT_PORTAL_JAR'); jar.set(name, value.slice(at + 1)); }
  return [...jar].map(([key, value]) => `${key}=${value}`).join('; ');
}
function cookieClaims(session, cookieName) {
  const value = session.cookie?.split('; ').find(pair => pair.startsWith(`${cookieName}=`));
  try { return JSON.parse(Buffer.from(value.slice(cookieName.length + 1).split('.')[1], 'base64url').toString()); }
  catch { throw Error('ACTUAL_CURRENT_PORTAL_SESSION_REQUIRED'); }
}

/** A console command is durably selected once, before the existing harness's
 * own CAS/prepared packet. No old label, replacement key or issue execute is
 * accepted. Only fixed metadata/publication/revoke workflow execution exists. */
export async function currentPortalConsoleWrite(h, g, label, path, method, body, session = g.authorSession) {
  assert(['POST', 'PATCH'].includes(method) && path.startsWith(`/clusters/${g.clusterId}/`)
    && new URL(`http://synthetic.invalid${path}`).searchParams.get('workspaceId') === g.workspaceId, 'FIXED_CURRENT_PORTAL_CONSOLE_SCOPE_REQUIRED');
  assert(!path.includes('://') && !path.includes('\\') && !path.includes('..'), 'FIXED_CURRENT_PORTAL_CONSOLE_SCOPE_REQUIRED');
  const resource = path.split('?')[0].slice(`/clusters/${g.clusterId}/`.length);
  assert(/^(?:workflow-definitions\/[a-f\d-]{36}\/versions|workflows\/[a-f\d-]{36}\/(?:approve|execute)|workflow-schedules(?:\/[a-f\d-]{36}\/activate)?|portal\/(?:settings|publications(?:\/[a-f\d-]{36}\/publish)?|developers\/[a-f\d-]{36}\/review))$/.test(resource), 'FIXED_CURRENT_PORTAL_COMMAND_REQUIRED');
  if (resource.endsWith('/execute')) {
    const id = resource.split('/')[1];
    assert(id !== g.workflowId && allowedExecuteKinds.has(g.workflowKinds[id]), 'PORTAL_ISSUE_MUST_USE_NATURAL_WORKER_ONLY');
  }
  assert(!g.consoleOperations[label], 'ORIGINAL_CURRENT_PORTAL_COMMAND_PRESENT_NO_REPLAY');
  h.assertWritable();
  const onceLabel = currentPortalOnceLabel(g, label);
  const key = randomUUID(), frozen = structuredClone(body), original = { key, path, method, actorId: session.user.id,
    sessionId: session.sid, bodyHash: sha(JSON.stringify(frozen)), state: 'selected' };
  g.consoleOperations[label] = original; h.save();
  const result = await h.once(onceLabel, session, path, method, frozen, { key, expected: [200, 201] });
  Object.assign(original, { state: 'response_observed', status: result.status, requestId: result.requestId }); h.save();
  return result.data;
}

/** Actual developer transport uses only the same BFF /portal namespace. Every
 * original packet, cookie and secret remains in the selected private ledger.
 * GET may inspect an unknown original without auth refresh; POST is fenced. */
export async function currentPortalHttpOnce(h, g, label, path, method = 'GET', body, expected = [200, 201], jar = g.developerSession) {
  assert(['GET', 'POST'].includes(method) && path.startsWith('/') && !path.startsWith('//')
    && !path.includes('://') && !path.includes('\\') && !path.includes('..'), 'FIXED_CURRENT_PORTAL_BFF_PATH_REQUIRED');
  const resource = path.split('?')[0], id = '[a-f\\d-]{36}';
  assert(new RegExp(`^/(?:auth/(?:csrf|register|login|me)|requests|operations/by-key/${id}|applications(?:/${id}/grants(?:/${id}/credentials(?:/${id}/(?:reveal|revoke))?)?)?)$`).test(resource),
    'FIXED_CURRENT_PORTAL_ENDPOINT_REQUIRED');
  assert(!/(?:^|;\s*)kongos_(?:access|refresh|csrf)=/.test(jar.cookie ?? ''), 'CONSOLE_COOKIE_FORBIDDEN_IN_CURRENT_PORTAL_JAR');
  assert(!g.portalPackets.some(packet => packet.label === label), 'ORIGINAL_CURRENT_PORTAL_PACKET_PRESENT_NO_REPLAY');
  if (body?.clusterId !== undefined) assert.equal(body.clusterId, g.clusterId, 'CURRENT_PORTAL_DEVELOPER_SCOPE_CHANGED');
  if (body?.workspaceId !== undefined) assert.equal(body.workspaceId, g.workspaceId, 'CURRENT_PORTAL_DEVELOPER_SCOPE_CHANGED');
  if (method === 'POST') assert(body?.clusterId === g.clusterId && body.workspaceId === g.workspaceId, 'CURRENT_PORTAL_DEVELOPER_SCOPE_REQUIRED');
  else {
    const query = new URL(`http://synthetic.invalid${path}`).searchParams;
    assert(query.getAll('clusterId').length === 1 && query.get('clusterId') === g.clusterId
      && query.getAll('workspaceId').length === 1 && query.get('workspaceId') === g.workspaceId,
    'CURRENT_PORTAL_DEVELOPER_QUERY_SCOPE_REQUIRED');
  }
  const write = method === 'POST'; if (write) h.assertWritable(); else h.save();
  const key = randomUUID(), serialized = body === undefined ? undefined : JSON.stringify(body);
  const headers = { Origin: g.configuration.portalOrigin, ...(jar.cookie ? { Cookie: jar.cookie } : {}),
    ...(write ? { 'Content-Type': 'application/json', 'X-Portal-CSRF': jar.csrf ?? '', 'X-Idempotency-Key': key } : {}) };
  const packet = { transport: 'portal-http', label, method, path: `${h.base}/portal${path}`, key,
    actorId: null, portalDeveloperId: jar.developer?.id ?? null, body: body === undefined ? null : structuredClone(body),
    bodyHash: sha(serialized ?? 'null'), headers, state: 'prepared', startedAt: new Date().toISOString() };
  g.portalPackets.push(packet); h.state.requests.push(packet); h.save();
  try {
    const response = await fetch(packet.path, { method, headers, redirect: 'manual', signal: AbortSignal.timeout(30_000),
      ...(serialized === undefined ? {} : { body: serialized }) });
    const cookies = response.headers.getSetCookie(), reader = response.body?.getReader();
    assert(reader, 'COMPLETE_CURRENT_PORTAL_RESPONSE_REQUIRED');
    const chunks = []; let size = 0;
    for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength;
      if (size > 128 * 1024) { await reader.cancel(); throw Error('CURRENT_PORTAL_RESPONSE_BUDGET_EXCEEDED'); } chunks.push(Buffer.from(part.value)); }
    const bytes = Buffer.concat(chunks); let payload;
    try { payload = JSON.parse(bytes.toString()); } catch { throw Error('COMPLETE_CURRENT_PORTAL_JSON_REQUIRED'); }
    assert(payload && typeof payload === 'object' && !Array.isArray(payload), 'COMPLETE_CURRENT_PORTAL_JSON_REQUIRED');
    jar.cookie = cookieMerge(jar.cookie, cookies);
    if (typeof payload.data?.csrfToken === 'string') jar.csrf = payload.data.csrfToken;
    if (payload.data?.developer) jar.developer = payload.data.developer;
    Object.assign(packet, { state: 'response_observed', status: response.status, responseData: payload.data ?? null,
      errorCode: payload.error?.code ?? null, requestId: payload.meta?.requestId ?? response.headers.get('x-request-id'),
      responseHash: sha(bytes), responseCookies: cookies }); h.save();
    assert(expected.includes(response.status), 'CURRENT_PORTAL_HTTP_STATUS_MISMATCH_ORIGINAL_RETAINED');
    return payload.data;
  } catch (error) {
    if (packet.state === 'prepared') { packet.state = 'response_unknown'; h.save(); }
    throw error;
  }
}

async function readConsole(h, g, path, session = g.authorSession) { return (await h.request(session, path)).data; }
async function assertConsoleIdentity(h, g, session, role) {
  const expected = g.acceptance[role], before = cookieClaims(session, 'kongos_access');
  assert(before.sub === expected.id && before.sid === expected.sid && session.sid === expected.sid, 'CURRENT_PORTAL_ORIGINAL_CONSOLE_SID_CHANGED');
  const me = await readConsole(h, g, '/auth/me', session);
  assert(me.user?.id === expected.id && typeof me.user.permissionsVersion === 'string' && me.user.forcePasswordChange !== true,
    'CURRENT_PORTAL_CONSOLE_IDENTITY_CHANGED');
  if (expected.permissionVersion === null) expected.permissionVersion = me.user.permissionsVersion;
  assert.equal(me.user.permissionsVersion, expected.permissionVersion, 'CURRENT_PORTAL_PERMISSION_VERSION_CHANGED');
  session.user = me.user; session.csrf = me.csrfToken; h.save();
}
async function currentFixture(h, g) {
  await assertConsoleIdentity(h, g, g.authorSession, 'author');
  await assertConsoleIdentity(h, g, g.reviewerSession, 'reviewer');
  const cluster = await readConsole(h, g, `/clusters/${g.clusterId}`);
  const service = entity(await readConsole(h, g, scope(g, `entities/services/${g.fixture.serviceId}`)));
  const route = entity(await readConsole(h, g, scope(g, `entities/routes/${g.fixture.routeId}`)));
  assert(cluster.execution_mode === 'approval' && cluster.status !== 'disabled' && /^1\.5\.\d+$/.test(cluster.version ?? ''), 'ACTUAL_CURRENT_PORTAL_APPROVAL_CLUSTER_REQUIRED');
  assert(service?.id === g.fixture.serviceId && route?.id === g.fixture.routeId && route.service?.id === service.id
    && route.protocols?.includes('http') && (!route.methods?.length || route.methods.includes('GET'))
    && Array.isArray(route.paths) && route.paths.includes(g.fixture.routePath)
    && !/[\[\]()+*?|^$]/.test(g.fixture.routePath) && (!route.headers || !Object.keys(route.headers).length),
  'ACTUAL_CURRENT_PORTAL_ROUTE_SERVICE_RELATION_REQUIRED');
  const host = currentPortalProbeHost(route, cluster, g.configuration);
  const actual = { clusterRevision: cluster.revision, serviceHmac: sha(JSON.stringify(canonical(service))), routeHmac: sha(JSON.stringify(canonical(route))),
    routeName: route.name ?? route.id, routePath: g.fixture.routePath, proxyHost: host, registeredProxyOrigin: cluster.proxy_origin };
  if (!g.fixture.observed) g.fixture.observed = actual;
  else assert.deepEqual(actual, g.fixture.observed, 'CURRENT_PORTAL_ORIGINAL_SCOPE_OR_NATIVE_FIXTURE_CHANGED');
  h.save();
}
function preceding(g, stage) {
  if (stage === 'preflight' || readonlyStages.has(stage)) return;
  const index = CURRENT_PORTAL_STAGES.indexOf(stage), previous = CURRENT_PORTAL_STAGES[index - 1];
  assert(g.stages[previous]?.state === 'succeeded', 'PREVIOUS_CURRENT_PORTAL_STAGE_NOT_COMPLETE');
}
async function workflowDetail(h, g, id, session = g.authorSession) {
  assert(uuid(id), 'ORIGINAL_CURRENT_PORTAL_WORKFLOW_REQUIRED');
  return readConsole(h, g, scope(g, `workflows/${id}`), session);
}
async function approveWorkflow(h, g, id, kind, label) {
  const detail = await workflowDetail(h, g, id, g.reviewerSession);
  const body = currentPortalVoteBody(detail, kind);
  const result = await currentPortalConsoleWrite(h, g, `${label}-vote`, scope(g, `workflows/${id}/approve`), 'POST', body, g.reviewerSession);
  assert(result.entity?.state === 'approved', 'CURRENT_PORTAL_EXPECTS_ONE_COMPLETE_INDEPENDENT_VOTE');
  return result.entity;
}
async function executeWorkflow(h, g, id, kind, label) {
  assert(allowedExecuteKinds.has(kind) && id !== g.workflowId, 'PORTAL_ISSUE_MUST_USE_NATURAL_WORKER_ONLY');
  const detail = await workflowDetail(h, g, id), row = detail.entity;
  assert(row.kind === kind && row.state === 'approved' && row.capabilities.execute === true && row.scheduled !== true, 'ACTUAL_CURRENT_PORTAL_EXECUTABLE_WORKFLOW_REQUIRED');
  g.workflowKinds[id] = kind; h.save();
  const result = await currentPortalConsoleWrite(h, g, `${label}-execute`, scope(g, `workflows/${id}/execute`), 'POST',
    { revision: row.revision, planHash: row.planHash, confirmed: true, confirm_name: kind });
  assert(result.state === 'succeeded' && uuid(result.executionId), 'ACTUAL_CURRENT_PORTAL_WORKFLOW_EXECUTION_NOT_SUCCEEDED');
  const after = await workflowDetail(h, g, id);
  assert(after.entity.state === 'succeeded' && after.steps.length > 0 && after.steps.every(step => step.state === 'succeeded'), 'ACTUAL_CURRENT_PORTAL_WORKFLOW_STEPS_NOT_SUCCEEDED');
  g.executions.push({ workflowId: id, executionId: result.executionId, kind, nativeSteps: after.steps.filter(step => step.kind === 'native').length }); h.save();
}
async function finishFixtureWorkflow(h, g, result, kind, label) {
  assert(uuid(result?.workflowId), 'ACTUAL_CURRENT_PORTAL_FIXTURE_APPROVAL_REQUIRED');
  const detail = await workflowDetail(h, g, result.workflowId);
  assert(detail.entity.kind === kind && detail.entity.state === 'pending' && detail.decisions.length === 0, 'ACTUAL_CURRENT_PORTAL_UNVOTED_FIXTURE_REQUIRED');
  await approveWorkflow(h, g, result.workflowId, kind, label);
  await executeWorkflow(h, g, result.workflowId, kind, label);
}
async function freshDeveloperLogin(h, g, label) {
  assert(!g.developerSessions[label], 'ORIGINAL_CURRENT_PORTAL_LOGIN_PRESENT_NO_REPLAY');
  // A distinct new anonymous jar avoids reusing an authenticated opaque CSRF
  // as the anonymous-login JWT. Every previous real jar stays in private state.
  const jar = { cookie: '', csrf: '' }; g.developerSessions[label] = jar; h.save();
  await currentPortalHttpOnce(h, g, `${label}-csrf`, portalScope(g, '/auth/csrf'), 'GET', undefined, [200], jar);
  const result = await currentPortalHttpOnce(h, g, `${label}-login`, '/auth/login', 'POST',
    { ...tenant(g), username: g.username, password: g.password }, [200, 201], jar);
  assert(result.developer?.id === g.developerId && result.developer.status === 'active', 'ACTUAL_SEPARATE_CURRENT_PORTAL_DEVELOPER_REQUIRED');
  const claims = cookieClaims(jar, 'kongos_portal_access');
  assert(claims.kind === 'portal_developer' && claims.sub === g.developerId && claims.cid === g.clusterId && claims.wid === g.workspaceId && uuid(claims.sid), 'ACTUAL_CURRENT_PORTAL_DEVELOPER_SESSION_REQUIRED');
  jar.sid = claims.sid; g.developerSession = jar; h.save();
}
async function portalRead(h, g, label, path) { return currentPortalHttpOnce(h, g, `${label}-${++g.readSequence}`, portalScope(g, path)); }
async function probe(h, g, label, expected) {
  assert(typeof g.issuedKey === 'string' && g.issuedKey.length >= 16, 'ORIGINAL_CURRENT_PORTAL_ISSUED_KEY_REQUIRED');
  for (let attempt = 1; attempt <= 20; attempt++) {
    const body = { routeId: g.fixture.routeId, input: { method: 'GET',
      url: `http://${g.fixture.observed.proxyHost}${g.fixture.routePath}/m11-current-portal`, headers: { apikey: g.issuedKey } },
    confirmed: true, confirm_name: g.fixture.observed.routeName };
    const result = await h.once(currentPortalOnceLabel(g, `${label}-proxy-get-${attempt}`), g.authorSession, scope(g, 'toolbox/probes'), 'POST', body, { expected: [200, 201] });
    assert(result.data.bodyReturned === false, 'CURRENT_PORTAL_PROXY_RESPONSE_MUST_NOT_DISCLOSE_BODY');
    g.proxyObservations.push({ label, attempt, actualStatus: result.data.status, expectedStatus: expected, requestId: result.requestId, observedAt: result.data.observedAt }); h.save();
    if (result.data.status === expected) return;
    assert([200, 401, 403, 404, 500, 502, 503, 504].includes(result.data.status), 'ACTUAL_CURRENT_PORTAL_PROXY_STATUS_REQUIRED');
    await pause(500);
  }
  throw Error('CURRENT_PORTAL_PROXY_EXPECTED_STATUS_NOT_OBSERVED');
}
export { probe as currentPortalProbe };

async function runStage(h, g, stage) {
  if (stage !== 'inspect') await currentFixture(h, g);
  if (stage === 'preflight') return;
  if (stage === 'policy') {
    const definitions = await readConsole(h, g, scope(g, 'workflow-definitions', { size: '100' }));
    assert(Array.isArray(definitions.items) && !definitions.nextCursor, 'COMPLETE_CURRENT_PORTAL_DEFINITIONS_REQUIRED');
    const matches = definitions.items.filter(row => row.kind === 'portal-credential-issue' && row.status === 'active');
    assert.equal(matches.length, 1, 'ONE_CURRENT_PORTAL_ISSUE_DEFINITION_REQUIRED'); const definition = matches[0];
    const policy = currentPortalIssuePolicy(g.reviewerSession.user.id);
    if (definition.format === 2) assert.deepEqual(definition.policy, policy, 'EXISTING_PORTAL_ISSUE_POLICY_MUST_NOT_BE_SILENTLY_REPLACED');
    else {
      assert.equal(definition.format, 1, 'CURRENT_PORTAL_POLICY_FORMAT_UNSUPPORTED');
      const response = await currentPortalConsoleWrite(h, g, 'policy-version', scope(g, `workflow-definitions/${definition.id}/versions`), 'POST',
        { revision: definition.revision, policy, confirmed: true, confirm_name: definition.name });
      await finishFixtureWorkflow(h, g, response, 'workflow-policy-metadata', 'policy');
    }
    const after = await readConsole(h, g, scope(g, 'workflow-definitions', { size: '100' }));
    const row = after.items.find(item => item.id === definition.id);
    assert(row?.format === 2 && row.status === 'active'); assert.deepEqual(row.policy, policy);
    g.issuePolicy = { id: row.id, version: row.version, policyHash: row.policyHash }; h.save();
  } else if (stage === 'settings') {
    const before = (await readConsole(h, g, scope(g, 'portal/settings'))).settings;
    assert(!before || !before.publicProxyOrigin || before.publicProxyOrigin === g.configuration.publicProxyOrigin, 'EXISTING_PORTAL_PROXY_CONFIGURATION_MUST_NOT_BE_REPLACED');
    g.originalSettings = before; h.save();
    const body = { ...(before ? { revision: before.revision } : { slug: g.slug }),
      ...(!before ? { name: g.name } : {}), publicProxyOrigin: g.configuration.publicProxyOrigin, registrationEnabled: true, published: true };
    const result = await currentPortalConsoleWrite(h, g, 'settings', scope(g, 'portal/settings'), before ? 'PATCH' : 'POST', body);
    await finishFixtureWorkflow(h, g, result, 'portal-metadata', 'settings');
    const after = (await readConsole(h, g, scope(g, 'portal/settings'))).settings;
    assert(after?.registrationEnabled && after.published && currentPortalPublicOriginMatches(after, g.configuration), 'ACTUAL_CURRENT_PORTAL_REGISTERABLE_SETTINGS_REQUIRED');
    g.settingsId = after.id; h.save();
  } else if (stage === 'developer-register') {
    const jar = { cookie: '', csrf: '' }; g.registrationSession = jar; h.save();
    await currentPortalHttpOnce(h, g, 'register-csrf', portalScope(g, '/auth/csrf'), 'GET', undefined, [200], jar);
    const result = await currentPortalHttpOnce(h, g, 'developer-register', '/auth/register', 'POST',
      { ...tenant(g), username: g.username, password: g.password, email: `${g.username}@example.invalid`, displayName: g.name }, [202], jar);
    assert.equal(result.status, 'pending', 'ACTUAL_PENDING_CURRENT_PORTAL_REGISTRATION_REQUIRED');
    const page = await readConsole(h, g, scope(g, 'portal/developers', { size: '100', search: g.username, status: 'pending' }));
    const matches = page.items.filter(row => row.username === g.username);
    assert.equal(matches.length, 1, 'ONE_NEW_CURRENT_PORTAL_DEVELOPER_REQUIRED'); g.developerId = matches[0].id; h.save();
  } else if (stage === 'developer-approve') {
    const detail = entity(await readConsole(h, g, scope(g, `portal/developers/${g.developerId}`)));
    assert(detail.id === g.developerId && detail.username === g.username && detail.status === 'pending', 'ORIGINAL_PENDING_CURRENT_PORTAL_DEVELOPER_REQUIRED');
    const result = await currentPortalConsoleWrite(h, g, 'developer-review', scope(g, `portal/developers/${g.developerId}/review`), 'POST',
      { revision: detail.revision, status: 'active', confirmed: true, confirm_name: g.username });
    await finishFixtureWorkflow(h, g, result, 'portal-metadata', 'developer-review');
  } else if (stage === 'application') {
    await freshDeveloperLogin(h, g, 'application');
    const created = entity(await currentPortalHttpOnce(h, g, 'application-create', '/applications', 'POST', { ...tenant(g), name: g.name }));
    assert(uuid(created.id) && created.state === 'active', 'ACTUAL_NEW_CURRENT_PORTAL_APPLICATION_REQUIRED');
    g.applicationId = created.id; h.save();
  } else if (stage === 'publication-create') {
    const body = businessPortalPublicationBody({ slug: `${g.slug}-api`, name: g.name, serviceId: g.fixture.serviceId, path: g.fixture.routePath });
    const created = await currentPortalConsoleWrite(h, g, 'publication-create', scope(g, 'portal/publications'), 'POST', body);
    await finishFixtureWorkflow(h, g, created, 'portal-metadata', 'publication-create');
    const page = await readConsole(h, g, scope(g, 'portal/publications', { size: '100', search: g.name }));
    const matches = page.items.filter(row => row.slug === body.slug); assert.equal(matches.length, 1, 'ONE_NEW_CURRENT_PORTAL_PUBLICATION_REQUIRED');
    g.publicationId = matches[0].id; h.save();
  } else if (stage === 'publication-publish') {
    const before = entity(await readConsole(h, g, scope(g, `portal/publications/${g.publicationId}`)));
    assert(before.status === 'draft' && before.serviceId === g.fixture.serviceId, 'ORIGINAL_CURRENT_PORTAL_DRAFT_REQUIRED');
    // Publication deliberately secures the entire selected Service with ACL
    // and key-auth. Finish unrelated unauthenticated metric probes beforehand.
    const result = await currentPortalConsoleWrite(h, g, 'publication-publish', scope(g, `portal/publications/${g.publicationId}/publish`), 'POST',
      { revision: before.revision, confirmed: true, confirm_name: before.name });
    await finishFixtureWorkflow(h, g, result, 'portal-publication', 'publication-publish');
    const after = entity(await readConsole(h, g, scope(g, `portal/publications/${g.publicationId}`)));
    assert(after.status === 'published' && after.documentRevision !== null, 'ACTUAL_CURRENT_PORTAL_PUBLICATION_NOT_PUBLISHED');
    g.publishedRevision = after.documentRevision; h.save();
  } else if (stage === 'request') {
    await freshDeveloperLogin(h, g, 'issue-request');
    const result = await currentPortalHttpOnce(h, g, 'issue-request', '/requests', 'POST',
      { ...tenant(g), applicationId: g.applicationId, publicationId: g.publicationId, reason: 'M11 当前候选自然业务排程验收' });
    assert(uuid(result.workflowId) && uuid(result.grant?.id) && result.approvalRequired && result.state === 'pending', 'ACTUAL_CURRENT_PORTAL_PENDING_ISSUE_REQUIRED');
    g.workflowId = result.workflowId; g.grantId = result.grant.id; h.save();
    const detail = await workflowDetail(h, g, g.workflowId), row = detail.entity;
    assert(row.kind === 'portal-credential-issue' && row.approval?.format === 2 && detail.decisions.length === 0
      && detail.steps.length === 4 && detail.steps.filter(step => step.kind === 'native').length === 3
      && detail.steps.every(step => step.state === 'pending' && !step.operationId), 'ACTUAL_CURRENT_PORTAL_UNEXECUTED_FOUR_STEP_ISSUE_REQUIRED');
    g.originalWorkflow = { planRevision: row.planRevision, planHash: row.planHash, expiresAt: row.expiresAt, stepIds: detail.steps.map(step => step.id) }; h.save();
  } else if (stage === 'author') {
    const detail = await workflowDetail(h, g, g.workflowId), row = detail.entity;
    assert(row.state === 'pending' && row.planHash === g.originalWorkflow.planHash && row.planRevision === g.originalWorkflow.planRevision
      && row.approval?.format === 2 && !row.scheduled && detail.decisions.length === 0, 'CURRENT_PORTAL_FIRST_VOTE_MUST_FOLLOW_SCHEDULE_REVISION');
    g.authorBody = { workflowId: row.id, revision: row.revision, planRevision: row.planRevision, planHash: row.planHash,
      spec: currentPortalWindow(row.expiresAt), confirmed: true, confirm_name: 'schedule-workflow' }; h.save();
    const result = await currentPortalConsoleWrite(h, g, 'schedule-author', scope(g, 'workflow-schedules'), 'POST', g.authorBody);
    const schedule = result.entity;
    assert(result.commandCompleted && uuid(schedule?.id) && schedule.workflowId === g.workflowId
      && schedule.state === 'pending-approval' && schedule.nativeAuthority === false, 'ACTUAL_CURRENT_PORTAL_SCHEDULE_AUTHORING_REQUIRED');
    g.scheduleId = schedule.id; h.save();
    const after = await workflowDetail(h, g, g.workflowId), current = after.entity;
    const steps = after.steps.filter(step => !g.originalWorkflow.stepIds.includes(step.id));
    assert(current.planRevision === row.planRevision + 1 && current.planHash !== row.planHash && current.expiresAt === row.expiresAt
      && current.capabilities.execute === false && after.decisions.length === 0 && steps.length === 4
      && steps.every(step => step.state === 'pending' && !step.operationId), 'CURRENT_PORTAL_NEW_REVISION_ORIGINAL_DEADLINE_REQUIRED');
    g.scheduledWorkflow = { planRevision: current.planRevision, planHash: current.planHash, expiresAt: current.expiresAt, stepIds: steps.map(step => step.id) }; h.save();
  } else if (stage === 'vote') {
    const row = await approveWorkflow(h, g, g.workflowId, 'portal-credential-issue', 'scheduled-issue');
    assert(row.planRevision === g.scheduledWorkflow.planRevision && row.planHash === g.scheduledWorkflow.planHash
      && uuid(row.approval?.approvalSetId) && row.capabilities.execute === false, 'ACTUAL_CURRENT_PORTAL_SCHEDULE_APPROVAL_SET_REQUIRED');
  } else if (stage === 'activate') {
    const row = entity(await readConsole(h, g, scope(g, `workflow-schedules/${g.scheduleId}`)));
    assert(row.state === 'pending-approval' && row.claimId === null && Date.parse(row.windowEnd) > Date.now(), 'ORIGINAL_CURRENT_PORTAL_ACTIVATABLE_SCHEDULE_REQUIRED');
    const result = await currentPortalConsoleWrite(h, g, 'schedule-activate', scope(g, `workflow-schedules/${g.scheduleId}/activate`), 'POST',
      { revision: row.revision, confirmed: true, confirm_name: 'activate-schedule' });
    assert(result.commandCompleted && result.entity?.state === 'active', 'ACTUAL_CURRENT_PORTAL_SCHEDULE_ACTIVATION_REQUIRED');
  } else if (stage === 'observe') {
    assert(g.stages.activate?.state === 'succeeded', 'ORIGINAL_CURRENT_PORTAL_ACTIVATION_REQUIRED');
    // Invoke with a yielded exec session: waits are one second each and the
    // immutable original window remains the bound, without manual worker tick.
    const deadline = Math.min(Date.now() + 540_000, Date.parse(g.authorBody.spec.windowEnd) + 30_000); let row;
    do {
      row = entity(await readConsole(h, g, scope(g, `workflow-schedules/${g.scheduleId}`)));
      g.timerObservations.push({ at: new Date().toISOString(), state: row.state, claimId: row.claimId, revision: row.revision }); h.save();
      if (!['pending-approval', 'active', 'claimed', 'running'].includes(row.state)) break;
      await pause(1000);
    } while (Date.now() < deadline);
    assert(row?.state === 'succeeded' && uuid(row.claimId), 'CURRENT_PORTAL_NATURAL_EXECUTION_PENDING_OR_NOT_SUCCEEDED');
    const detail = await workflowDetail(h, g, g.workflowId), steps = detail.steps.filter(step => g.scheduledWorkflow.stepIds.includes(step.id));
    assert(detail.entity.state === 'succeeded' && detail.entity.planHash === g.scheduledWorkflow.planHash
      && steps.length === 4 && steps.every(step => step.state === 'succeeded')
      && steps.filter(step => step.kind === 'native' && uuid(step.operationId)).length === 3, 'ACTUAL_CURRENT_PORTAL_NATURAL_NATIVE_METADATA_COMPLETION_REQUIRED');
    assert(detail.steps.filter(step => g.originalWorkflow.stepIds.includes(step.id)).every(step => step.state === 'pending' && !step.operationId), 'CURRENT_PORTAL_ORIGINAL_REVISION_HISTORY_MUST_REMAIN_UNEXECUTED');
    g.claimId = row.claimId; g.nativeOperationIds = steps.filter(step => step.kind === 'native').map(step => step.operationId); h.save();
    const vote = g.consoleOperations['scheduled-issue-vote'];
    const receipt = await readConsole(h, g, scope(g, `workflows/receipts/by-key/${vote.key}`), g.reviewerSession);
    assert(receipt.state === 'succeeded' && uuid(receipt.executionId) && receipt.workflowId === g.workflowId, 'ACTUAL_CURRENT_PORTAL_ORIGINAL_EXECUTION_RECEIPT_REQUIRED');
    g.executionId = receipt.executionId; h.save();
  } else if (stage === 'verify-key') {
    await freshDeveloperLogin(h, g, 'verify-key');
    const grants = await portalRead(h, g, 'active-grants', `/applications/${g.applicationId}/grants`);
    const grant = grants.items.find(row => row.id === g.grantId && row.publicationId === g.publicationId && row.state === 'active');
    assert(grant, 'ACTUAL_CURRENT_PORTAL_ACTIVE_GRANT_REQUIRED');
    const page = await portalRead(h, g, 'active-credentials', `/applications/${g.applicationId}/grants/${g.grantId}/credentials`);
    const active = page.items.filter(row => row.state === 'active'); assert.equal(active.length, 1, 'ONE_CURRENT_PORTAL_ACTIVE_CREDENTIAL_REQUIRED');
    g.credentialId = active[0].id; h.save();
    const revealed = await currentPortalHttpOnce(h, g, 'original-key-reveal', `/applications/${g.applicationId}/grants/${g.grantId}/credentials/${g.credentialId}/reveal`, 'POST',
      { ...tenant(g), revision: active[0].revision });
    assert(typeof revealed.key === 'string' && revealed.key.length >= 16, 'ACTUAL_AUTHORIZED_CURRENT_PORTAL_KEY_REQUIRED');
    g.issuedKey = revealed.key; h.save(); await probe(h, g, 'issued-key', 200);
  } else if (stage === 'revoke-request') {
    await freshDeveloperLogin(h, g, 'revoke-request');
    const page = await portalRead(h, g, 'before-revoke', `/applications/${g.applicationId}/grants/${g.grantId}/credentials`);
    const active = page.items.find(row => row.id === g.credentialId && row.state === 'active'); assert(active, 'ORIGINAL_CURRENT_PORTAL_ACTIVE_KEY_REQUIRED');
    const result = await currentPortalHttpOnce(h, g, 'original-key-revoke', `/applications/${g.applicationId}/grants/${g.grantId}/credentials/${g.credentialId}/revoke`, 'POST',
      { ...tenant(g), revision: active.revision, confirmed: true, confirm_name: `吊销 ${active.id}`, retireConsumer: true, reason: 'M11 自然定时发放原凭证吊销验收' });
    assert(uuid(result.workflowId) && result.state === 'pending' && result.approvalRequired, 'ACTUAL_CURRENT_PORTAL_REVOKE_APPROVAL_REQUIRED');
    g.revocationWorkflowId = result.workflowId; h.save();
  } else if (stage === 'revoke-vote') {
    await approveWorkflow(h, g, g.revocationWorkflowId, 'portal-credential-revoke', 'revoke');
  } else if (stage === 'revoke-execute') {
    await executeWorkflow(h, g, g.revocationWorkflowId, 'portal-credential-revoke', 'revoke');
  } else if (stage === 'verify-revoked') {
    await freshDeveloperLogin(h, g, 'verify-revoked');
    const page = await portalRead(h, g, 'revoked-credentials', `/applications/${g.applicationId}/grants/${g.grantId}/credentials`);
    assert(page.items.some(row => row.id === g.credentialId && row.state === 'revoked'), 'ORIGINAL_CURRENT_PORTAL_CREDENTIAL_NOT_REVOKED');
    await probe(h, g, 'revoked-original-key', 401);
  } else if (stage === 'inspect') {
    // Read-only evidence only. Missing receipts never authorize retry or close
    // an unknown original; no login/refresh/reveal/probe is performed here.
    g.inspections ??= [];
    const observed = { at: new Date().toISOString(), originalUnknownRetained: true };
    if (g.workflowId) observed.issue = await workflowDetail(h, g, g.workflowId);
    if (g.scheduleId) observed.schedule = await readConsole(h, g, scope(g, `workflow-schedules/${g.scheduleId}`));
    if (g.revocationWorkflowId) observed.revoke = await workflowDetail(h, g, g.revocationWorkflowId);
    if (g.developerSession?.cookie) {
      observed.portalReceipts = [];
      for (const packet of g.portalPackets.filter(item => item.method === 'POST' && /\/portal\/(?:applications|requests)/.test(item.path))) {
        const result = await currentPortalHttpOnce(h, g, `inspect-original-key-${++g.readSequence}`, portalScope(g, `/operations/by-key/${packet.key}`), 'GET', undefined, [200, 404]);
        observed.portalReceipts.push({ originalKey: packet.key, receipt: result ?? null, retryWriteAllowed: false });
      }
    }
    g.inspections.push(observed); h.save();
  }
}

export function currentPortalPublicReport(h, g, stage, passed, start, errorCode) {
  let publicCase = { caseId: null, fixtureField: null };
  if (!g.caseBinding && g.version !== 2) publicCase = { caseId: 'original', fixtureField: null };
  else try {
    const selection = currentPortalCaseSelection({ RELEASE_LAB_M11_CURRENT_PORTAL_CASE: g.caseBinding?.caseId,
      RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: g.caseBinding?.fixtureField });
    assert(own(h.state.currentPortalNaturalCases, selection.caseId) && h.state.currentPortalNaturalCases[selection.caseId] === g,
      'ORIGINAL_CURRENT_PORTAL_REPORT_CASE_REQUIRED');
    const fixture = currentPortalSelectedFixture(h.state, selection);
    assert.deepEqual(g.caseBinding, caseBinding(selection, h.state, fixture), 'ORIGINAL_CURRENT_PORTAL_REPORT_BINDING_CHANGED');
    currentPortalOnceLabel(g, 'public-report'); publicCase = { caseId: selection.caseId, fixtureField: selection.fixtureField };
  }
  catch { /* A corrupted private binding is never copied to public evidence. */ }
  return { atUtc: new Date().toISOString(), stage, passed, sourceOnly: false, actualBff: true,
    ...publicCase,
    wholeM11Accepted: false, productionDeployment: false, credentialsPublished: false,
    publicEndpointConfigured: g.configuration.publicProxyOrigin !== null, externalAccessVerified: false,
    manualWorkerTickInvoked: false, issueExecuteRequestInvoked: false, noKongSourceOrDatabaseAccess: true,
    clusterId: g.clusterId, workspaceId: g.workspaceId, serviceId: g.fixture.serviceId, routeId: g.fixture.routeId,
    developerId: g.developerId ?? null, applicationId: g.applicationId ?? null, publicationId: g.publicationId ?? null,
    workflowId: g.workflowId ?? null, scheduleId: g.scheduleId ?? null, claimId: g.claimId ?? null,
    executionId: g.executionId ?? null, revocationWorkflowId: g.revocationWorkflowId ?? null,
    originalPlanRevision: g.originalWorkflow?.planRevision ?? null, scheduledPlanRevision: g.scheduledWorkflow?.planRevision ?? null,
    originalDeadlinePreserved: g.scheduledWorkflow ? g.originalWorkflow.expiresAt === g.scheduledWorkflow.expiresAt : null,
    independentReviewer: g.acceptance.author.id !== g.acceptance.reviewer.id, wholeServiceAuthenticationImpact: true,
    observations: h.state.requests.slice(start).map(packet => ({ transport: packet.transport ?? 'console-http',
      method: packet.method, path: packet.path.split('?')[0], keySha256: sha(packet.key ?? ''), state: packet.state,
      status: packet.status ?? null, requestId: packet.requestId ?? null, errorCode: packet.errorCode ?? null,
      bodyHash: packet.bodyHash, responseHash: packet.responseHash ?? null })),
    timerObservations: g.timerObservations, proxyObservations: g.proxyObservations,
    limitations: ['HTTP results do not prove SQL claim count, NULL-SID namespace, lease generation, append-only role privileges or exact runtime Source identity.',
      'Root independently verifies the actual original W/E/claim/origin/mutations/audits. No lost RAM-run identities or approvals are reused.',
      'Publication secures the entire selected Service. This runner neither silently unpublishes it nor creates a bypass.'],
    ...(errorCode ? { errorCode } : {}) };
}

export async function main(env = process.env, stage = process.argv[2]) {
  const configuration = currentPortalConfiguration(env, stage), selection = currentPortalCaseSelection(env), reportSelection = selectReleaseReportDirectory('M11');
  assert(reportSelection.custom, 'ISOLATED_CURRENT_PORTAL_REPORT_DIRECTORY_REQUIRED');
  assertReleaseReportDirectory(reportSelection, { create: true });
  const fd = openSync(resolve(reportSelection.directory, 'portal-natural-verification.json'), 'wx', 0o644);
  let h, g, start = 0, attemptStarted = false, bindingValidated = false;
  try {
    h = new ReleaseHarness('M11', { resume: true });
    if (!readonlyStages.has(stage)) h.assertWritable();
    const metadata = h.state.metadataAcceptance, author = h.state.sessions?.admin, reviewer = metadata?.reviewerSession;
    const fixture = currentPortalSelectedFixture(h.state, selection);
    assert(uuid(h.state.cid) && uuid(h.state.wid)
      && uuid(author?.user?.id) && uuid(reviewer?.user?.id) && author.user.id !== reviewer.user.id
      && uuid(author.sid) && uuid(reviewer.sid), 'ACTUAL_CURRENT_RUN_SCOPE_SERVICE_ROUTE_AND_INDEPENDENT_REVIEWER_REQUIRED');
    isolatedCaseFixture(h.state, selection, fixture);
    const cases = h.state.currentPortalNaturalCases;
    g = selection.caseId === 'original' ? h.state.currentPortalNaturalOriginal : own(cases, selection.caseId) ? cases[selection.caseId] : undefined;
    if (selection.caseId !== 'original' && own(cases, selection.caseId)) assert(plain(g), 'ORIGINAL_CURRENT_PORTAL_CASE_STORE_INVALID');
    if (!g) {
      assert.equal(stage, 'preflight', 'FRESH_CURRENT_PORTAL_RUN_MUST_START_AT_PREFLIGHT');
      const suffix = randomUUID().replaceAll('-', '').slice(0, 16);
      g = { version: selection.caseId === 'original' ? 1 : 2, ...(selection.caseId === 'original' ? {} : { caseBinding: caseBinding(selection, h.state, fixture) }),
        clusterId: h.state.cid, workspaceId: h.state.wid,
        configuration, name: `M11 Portal ${suffix}`, slug: `m11-current-portal-${suffix}`, username: `m11portal${suffix}`,
        password: releasePassword(), authorSession: author, reviewerSession: reviewer,
        acceptance: { author: { id: author.user.id, sid: author.sid, permissionVersion: null },
          reviewer: { id: reviewer.user.id, sid: reviewer.sid, permissionVersion: null } },
        fixture: { ...fixture },
        stages: {}, consoleOperations: {}, portalPackets: [], developerSessions: {}, workflowKinds: {},
        executions: [], timerObservations: [], proxyObservations: [], stageHistory: [], readSequence: 0 };
      if (selection.caseId === 'original') h.state.currentPortalNaturalOriginal = g;
      else { h.state.currentPortalNaturalCases ??= {};
        Object.defineProperty(h.state.currentPortalNaturalCases, selection.caseId, { value: g, enumerable: true, configurable: true, writable: true }); }
      h.save();
    }
    if (selection.caseId === 'original') assert(!g.caseBinding && g.version === 1, 'ORIGINAL_CURRENT_PORTAL_CASE_BINDING_CHANGED');
    else assert(g.version === 2 && g.caseBinding, 'ORIGINAL_CURRENT_PORTAL_CASE_BINDING_CHANGED');
    if (selection.caseId !== 'original') assert.deepEqual(g.caseBinding, caseBinding(selection, h.state, fixture), 'ORIGINAL_CURRENT_PORTAL_CASE_BINDING_CHANGED');
    assert(g.clusterId === h.state.cid && g.workspaceId === h.state.wid
      && g.fixture.serviceId === fixture.serviceId && g.fixture.routeId === fixture.routeId
      && g.fixture.routePath === fixture.routePath && g.acceptance.author.id === author.user.id
      && g.acceptance.reviewer.id === reviewer.user.id, 'ORIGINAL_CURRENT_PORTAL_RUN_SCOPE_CHANGED');
    assert.deepEqual(g.configuration, configuration, 'ORIGINAL_CURRENT_PORTAL_ORIGINS_CHANGED');
    bindingValidated = true;
    // JSON resume separates references. Reconnect only the very same genuine
    // ID/SID, so a real refresh updates the shared jar instead of leaving the
    // operator's global slot with an already consumed refresh cookie. A newer
    // login SID is never adopted into this original workflow acceptance.
    if (author.sid === g.acceptance.author.sid) g.authorSession = author;
    if (reviewer.sid === g.acceptance.reviewer.sid) g.reviewerSession = reviewer;
    preceding(g, stage);
    if (!readonlyStages.has(stage)) assert(!g.stages[stage], 'ORIGINAL_CURRENT_PORTAL_STAGE_PRESENT_NO_REPLAY');
    if (readonlyStages.has(stage) && g.stages[stage]) g.stageHistory.push({ stage, ...structuredClone(g.stages[stage]) });
    g.stages[stage] = { state: 'prepared', startedAt: new Date().toISOString() }; start = h.state.requests.length; h.save();
    attemptStarted = true;
    await runStage(h, g, stage);
    g.stages[stage].state = 'succeeded'; g.stages[stage].completedAt = new Date().toISOString(); h.save();
    writeSync(fd, JSON.stringify(currentPortalPublicReport(h, g, stage, true, start), null, 2) + '\n');
    console.log(JSON.stringify({ stage, passed: true, stageOnly: true, wholeM11Accepted: false, credentialsPublished: false }));
  } catch (error) {
    const errorCode = code(error);
    if (attemptStarted && g?.stages[stage]) { g.stages[stage].state = 'failed'; g.stages[stage].errorCode = errorCode; try { h.save(); } catch { /* Original CAS/unknown bytes are never replaced by recovery guesses. */ } }
    writeSync(fd, JSON.stringify(h && g && bindingValidated ? currentPortalPublicReport(h, g, stage, false, start, errorCode)
      : { atUtc: new Date().toISOString(), stage, passed: false, errorCode, caseId: selection.caseId, fixtureField: selection.fixtureField,
        actualHttpAcceptanceClaim: false, credentialsPublished: false }, null, 2) + '\n');
    console.error(JSON.stringify({ stage, passed: false, errorCode })); process.exitCode = 1;
  } finally { closeSync(fd); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
