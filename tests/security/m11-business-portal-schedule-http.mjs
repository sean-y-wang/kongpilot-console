import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';
import {closeSync, existsSync, mkdirSync, openSync, writeSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {ReleaseHarness, releasePassword, releaseScope} from './lib/release-harness.mjs';

// SOURCE ONLY until Root reviews and invokes exactly one stage. Importing this
// module performs no HTTP, Docker, SQL, ledger read, session creation or timer.
// All gateway writes use existing BFF workflows. The only execute calls here
// are newly created fixture portal-metadata / portal-publication workflows.
// Issue is executed exclusively by the natural business scheduler. Revoke is
// submitted and approved here, then executed separately by Root after review.
export const BUSINESS_PORTAL_STAGES = Object.freeze([
  'fixtures', 'publication', 'request', 'author', 'votes', 'activate',
  'observe', 'revoke-request', 'revoke-votes', 'revoke-observe',
]);
const hex = /^[a-f0-9]{64}$/;
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
const sha = value => createHash('sha256').update(value).digest('hex');
const entity = value => value?.entity ?? value;
const pause = ms => new Promise(done => setTimeout(done, ms));
const cookieMerge = (current, values) => {
  const jar = new Map((current ?? '').split('; ').filter(Boolean).map(part => {
    const at = part.indexOf('='); return [part.slice(0, at), part.slice(at + 1)];
  }));
  for (const header of values) {
    const part = header.split(';')[0], at = part.indexOf('=');
    jar.set(part.slice(0, at), part.slice(at + 1));
  }
  return [...jar].map(([key, value]) => `${key}=${value}`).join('; ');
};
const safeCode = error => /^[A-Z][A-Z0-9_]{2,120}$/.test(error?.message ?? '')
  ? error.message : 'BUSINESS_PORTAL_STAGE_ASSERTION_OR_HTTP_FAILURE';

/** Values are explicit Root inputs obtained from real BFF READs, never guessed
 * old fixture slots. This runner does not alter cluster mode or definitions.
 * A service/route must already have been created through approved Native-change
 * workflows if a fresh fixture was required. Portal publish uses its genuine
 * portal-publication workflow, including its two ACL/key-auth Native steps. */
export function businessPortalConfiguration(env, stage = 'fixtures') {
  assert.equal(env.RELEASE_LAB_M11_BUSINESS_PORTAL_READY, 'true', 'ROOT_EXPLICIT_BUSINESS_PORTAL_GATE_REQUIRED');
  assert(BUSINESS_PORTAL_STAGES.includes(stage), 'EXACT_ONE_BUSINESS_PORTAL_STAGE_REQUIRED');
  const serviceId = env.RELEASE_LAB_M11_BUSINESS_PORTAL_SERVICE_ID;
  const routeId = env.RELEASE_LAB_M11_BUSINESS_PORTAL_ROUTE_ID;
  assert(uuid(serviceId) && uuid(routeId), 'ROOT_ACTUAL_SERVICE_AND_ROUTE_IDS_REQUIRED');
  const origin = new URL(env.RELEASE_LAB_M11_PORTAL_ORIGIN);
  assert(['http:', 'https:'].includes(origin.protocol) && origin.origin === env.RELEASE_LAB_M11_PORTAL_ORIGIN
    && !origin.username && !origin.password && !['8001', '8444'].includes(origin.port), 'ROOT_CONFIGURED_PORTAL_PUBLIC_ORIGIN_REQUIRED');
  const proxyOrigin = new URL(env.RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN);
  assert(['http:', 'https:'].includes(proxyOrigin.protocol) && proxyOrigin.origin === env.RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN
    && !proxyOrigin.username && !proxyOrigin.password && !['8001', '8444', '5445'].includes(proxyOrigin.port), 'ROOT_ACTUAL_BUSINESS_PROXY_ORIGIN_REQUIRED');
  return Object.freeze({stage, serviceId, routeId, portalOrigin: origin.origin,
    publicProxyOrigin: proxyOrigin.origin, expectedMode: 'approval'});
}

/** Pure current-policy contract; it does not provide an approval proof. The
 * issue definition must already have been upgraded by an actual console
 * transaction. The existing single-level definitions are not auto-upgraded. */
export function businessPortalIssuePolicy(definition, reviewerIds) {
  assert(definition?.kind === 'portal-credential-issue' && definition.status === 'active'
    && definition.format === 2 && definition.policy?.version === 2
    && definition.policy.kind === definition.kind && definition.policy.allowSelfApproval === false
    && definition.policy.distinctAcrossStages !== false, 'CURRENT_FORMAT2_PORTAL_ISSUE_POLICY_REQUIRED');
  const [first, second] = definition.policy.stages ?? [];
  assert(definition.policy.stages.length === 2 && first.level === 1 && first.mode === 'any' && first.threshold === 1
    && second.level === 2 && second.mode === 'all' && second.threshold === null, 'CURRENT_ANY_A_ALL_BC_PORTAL_POLICY_REQUIRED');
  assert.deepEqual(first.selector, {users: [reviewerIds.a]}, 'CURRENT_PORTAL_INITIAL_REVIEWER_REQUIRED');
  assert.deepEqual([...second.selector.users].sort(), [reviewerIds.b, reviewerIds.c].sort(), 'CURRENT_PORTAL_COUNTERSIGN_REVIEWERS_REQUIRED');
  assert.deepEqual(Object.keys(second.selector), ['users'], 'EXACT_PORTAL_COUNTERSIGN_USER_SELECTOR_REQUIRED');
  assert(hex.test(definition.policyHash), 'CURRENT_PORTAL_POLICY_HMAC_REQUIRED');
  return {definitionId: definition.id, definitionVersion: definition.version, policyHash: definition.policyHash};
}

export function businessPortalPublicationBody({slug, name, serviceId, path}) {
  assert(typeof slug === 'string' && /^[a-z0-9][a-z0-9-]{0,79}$/.test(slug) && uuid(serviceId), 'FRESH_PORTAL_PUBLICATION_SELECTORS_REQUIRED');
  assert(typeof name === 'string' && name.length <= 128 && typeof path === 'string'
    && path.startsWith('/') && !/[\[\]()+*?|^$]/.test(path), 'PLAIN_ACTUAL_ROUTE_PATH_REQUIRED');
  return {slug, name, category: 'M11 验收', serviceId, document: {openapi: '3.0.3',
    info: {title: name, version: '1.0.0'}, paths: {[path]: {get: {responses: {'200': {description: 'Success'}}}}}}};
}

export function businessPortalWindow(expiresAt, now = Date.now()) {
  assert(Number.isSafeInteger(now) && Number.isFinite(Date.parse(expiresAt)), 'ORIGINAL_WORKFLOW_DEADLINE_REQUIRED');
  const notBefore = now + 120_000, windowEnd = now + 300_000;
  assert(windowEnd <= Date.parse(expiresAt), 'ORIGINAL_PORTAL_DEADLINE_MUST_NOT_BE_EXTENDED');
  return {notBefore: new Date(notBefore).toISOString(), windowStart: new Date(notBefore).toISOString(),
    windowEnd: new Date(windowEnd).toISOString()};
}

async function boundedJson(response) {
  const reader = response.body?.getReader(); assert(reader, 'COMPLETE_PORTAL_RESPONSE_BODY_REQUIRED');
  const chunks = []; let bytes = 0;
  for (;;) {
    const part = await reader.read(); if (part.done) break;
    bytes += part.value.byteLength;
    if (bytes > 128 * 1024) {await reader.cancel(); throw Error('PORTAL_RESPONSE_BUDGET_EXCEEDED');}
    chunks.push(Buffer.from(part.value));
  }
  const raw = Buffer.concat(chunks), payload = JSON.parse(raw.toString('utf8'));
  assert(payload && typeof payload === 'object' && !Array.isArray(payload), 'COMPLETE_PORTAL_JSON_REQUIRED');
  return {payload, responseHash: sha(raw)};
}

/** Original Portal requests have their own cookie jar and CSRF header. Each
 * packet enters the existing global private journal BEFORE transport. A lost
 * response stops subsequent stages; no generated replacement key is allowed.
 * No refresh/retry happens inside this transport. Fresh auth is an explicit
 * stage-boundary login using this original developer's real private password. */
async function portalOnce(h, g, label, suffix, method = 'GET', body, expected = [200, 201]) {
  h.assertWritable();
  assert(!g.portalPackets.some(packet => packet.label === label), 'ORIGINAL_PORTAL_PACKET_PRESENT_NO_REPLAY');
  assert(suffix.startsWith('/') && !suffix.includes('://') && ['GET', 'POST'].includes(method), 'FIXED_PORTAL_BFF_PATH_REQUIRED');
  const write = method === 'POST', session = g.developerSession;
  assert(!(session.cookie ?? '').includes('kongos_access='), 'CONSOLE_COOKIE_FORBIDDEN_IN_PORTAL_JAR');
  const headers = {Origin: g.configuration.portalOrigin, ...(session.cookie ? {Cookie: session.cookie} : {}),
    ...(write ? {'Content-Type': 'application/json', 'X-Portal-CSRF': session.csrf ?? ''} : {})};
  const key = randomUUID(); if (write) headers['X-Idempotency-Key'] = key;
  const packet = {transport: 'portal-http', label: `m11-business-portal-${label}`, key, method,
    path: `${h.base}/portal${suffix}`, body: body === undefined ? null : structuredClone(body),
    bodyHash: sha(JSON.stringify(body) ?? 'null'), headers, actorId: null,
    portalDeveloperId: session.developer?.id ?? null, state: 'prepared', startedAt: new Date().toISOString()};
  g.portalPackets.push({...packet, label}); h.state.requests.push(packet); h.save();
  const local = g.portalPackets.at(-1);
  try {
    const response = await fetch(packet.path, {method, headers, redirect: 'manual', signal: AbortSignal.timeout(30_000),
      ...(body === undefined ? {} : {body: JSON.stringify(body)})});
    const cookies = response.headers.getSetCookie(), observed = await boundedJson(response);
    session.cookie = cookieMerge(session.cookie, cookies);
    if (typeof observed.payload.data?.csrfToken === 'string') session.csrf = observed.payload.data.csrfToken;
    if (observed.payload.data?.developer) session.developer = observed.payload.data.developer;
    const facts = {state: 'response_observed', status: response.status, responseData: observed.payload.data ?? null,
      errorCode: observed.payload.error?.code ?? null, requestId: observed.payload.meta?.requestId ?? response.headers.get('x-request-id'),
      responseHash: observed.responseHash, responseCookies: cookies, observedAt: new Date().toISOString()};
    Object.assign(packet, facts); Object.assign(local, facts);
    if (!write) packet.resolution = {kind: 'complete-portal-get-observation', knownNoNativeSend: true};
    h.save(); assert(expected.includes(response.status), 'ACTUAL_PORTAL_STATUS_MISMATCH_ORIGINAL_RETAINED');
    return observed.payload.data;
  } catch (error) {
    if (packet.state === 'prepared') {
      packet.state = local.state = 'response_unknown'; packet.errorCode = local.errorCode = 'PORTAL_ORIGINAL_RESPONSE_UNKNOWN'; h.save();
    }
    throw error;
  }
}

function scopedPortal(g, suffix) {
  return `${suffix}${suffix.includes('?') ? '&' : '?'}${new URLSearchParams({clusterId: g.clusterId, workspaceId: g.workspaceId})}`;
}
function requireDone(g, previous) {
  assert(g.runs[previous]?.state === 'succeeded', 'PREVIOUS_ORIGINAL_PORTAL_STAGE_REQUIRED');
}

async function currentFixture(h, g) {
  const scope = suffix => releaseScope(g.clusterId, g.workspaceId, suffix);
  const cluster = (await h.request(h.state.sessions.admin, `/clusters/${g.clusterId}`)).data;
  assert(cluster.execution_mode === g.configuration.expectedMode && cluster.status !== 'disabled'
    && /^1\.5\.\d+$/.test(cluster.version ?? ''), 'ACTUAL_APPROVAL_KONG15_CLUSTER_REQUIRED');
  const route = entity((await h.request(h.state.sessions.admin, scope(`entities/routes/${g.configuration.routeId}`))).data);
  const service = entity((await h.request(h.state.sessions.admin, scope(`entities/services/${g.configuration.serviceId}`))).data);
  assert(route.id === g.configuration.routeId && service.id === g.configuration.serviceId && route.service?.id === service.id,
    'ACTUAL_PORTAL_ROUTE_SERVICE_RELATION_REQUIRED');
  assert(Array.isArray(route.paths) && route.paths.length === 1 && route.paths[0].startsWith('/')
    && !/[\[\]()+*?|^$]/.test(route.paths[0]) && typeof route.name === 'string'
    && Array.isArray(route.protocols) && route.protocols.includes('http'), 'ONE_PLAIN_HTTP_PORTAL_ROUTE_REQUIRED');
  assert(!route.methods || route.methods.includes('GET'), 'ACTUAL_GET_PORTAL_ROUTE_REQUIRED');
  assert(!route.headers || Object.keys(route.headers).length === 0, 'PORTAL_ROUTE_HEADER_PREDICATES_NOT_SUPPORTED_BY_FIXTURE');
  const host = route.hosts?.length ? route.hosts[0] : new URL(g.configuration.publicProxyOrigin).hostname;
  assert(typeof host === 'string' && !host.includes('*') && /^[a-z0-9.-]+$/i.test(host), 'PLAIN_CURRENT_PORTAL_ROUTE_HOST_REQUIRED');
  const definitions = (await h.request(h.state.sessions.admin, releaseScope(g.clusterId, g.workspaceId, 'workflow-definitions', {size: '100'}))).data;
  assert(Array.isArray(definitions.items) && !definitions.nextCursor, 'ONE_COMPLETE_CURRENT_WORKFLOW_DEFINITION_PAGE_REQUIRED');
  const issue = definitions.items.filter(definition => definition.kind === 'portal-credential-issue' && definition.status === 'active');
  assert.equal(issue.length, 1, 'ONE_CURRENT_PORTAL_ISSUE_DEFINITION_REQUIRED');
  const policy = businessPortalIssuePolicy(issue[0], Object.fromEntries(['a', 'b', 'c'].map(label => [label, h.state.sessions[label].user.id])));
  if (g.issuePolicy) assert.deepEqual(policy, g.issuePolicy, 'CURRENT_PORTAL_ISSUE_POLICY_CHANGED'); else g.issuePolicy = policy;
  const snapshot = {clusterRevision: cluster.revision, executionMode: cluster.execution_mode,
    serviceId: service.id, routeId: route.id, routeName: route.name, routePath: route.paths[0], proxyHost: host};
  if (g.fixture) assert.deepEqual(snapshot, g.fixture, 'ORIGINAL_PORTAL_FIXTURE_OR_CLUSTER_CHANGED'); else g.fixture = snapshot;
  h.save(); return {scope, route, service, definitions: definitions.items};
}

async function vote(h, g, id, label, reviewers, {format2 = false} = {}) {
  const scope = suffix => releaseScope(g.clusterId, g.workspaceId, suffix);
  for (const [index, reviewer] of reviewers.entries()) {
    const view = entity((await h.request(h.state.sessions.admin, scope(`workflows/${id}`))).data);
    assert(view.state === 'pending' && view.approvalRequired === true, 'ACTUAL_PENDING_APPROVAL_REQUIRED');
    assert(!g.votedPackets.some(packet => packet.workflowId === id && packet.reviewer === reviewer), 'ORIGINAL_PORTAL_VOTE_PRESENT_NO_REPLAY');
    const active = format2 ? view.approval?.stages.find(stage => stage.state === 'active') : null;
    if (format2) assert(view.approval.format === 2 && active && Number.isInteger(view.approval.candidateVersion), 'ACTUAL_FROZEN_FORMAT2_STAGE_REQUIRED');
    else assert(view.approval === undefined, 'FIXTURE_EXPECTED_REAL_SINGLE_LEVEL_POLICY');
    const body = {revision: view.revision, planHash: view.planHash, confirmed: true, confirm_name: view.kind, execute: false,
      ...(format2 ? {level: active.level, stageRevision: active.revision, candidateVersion: view.approval.candidateVersion} : {})};
    const operationLabel = `${label}-vote-${reviewer}`;
    const response = await h.once(`m11-business-portal-${operationLabel}`, h.state.sessions[reviewer], scope(`workflows/${id}/approve`), 'POST', body);
    g.votedPackets.push({workflowId: id, reviewer, label: operationLabel, requestId: response.requestId,
      planRevision: view.planRevision, planHash: view.planHash}); h.save();
    const after = entity((await h.request(h.state.sessions.admin, scope(`workflows/${id}`))).data);
    assert.equal(after.state, index === reviewers.length - 1 ? 'approved' : 'pending', 'REAL_PORTAL_APPROVAL_PROGRESS_REQUIRED');
  }
  return entity((await h.request(h.state.sessions.admin, scope(`workflows/${id}`))).data);
}

async function finishFixtureWorkflow(h, g, label, response, kind) {
  assert(['portal-metadata', 'portal-publication'].includes(kind) && uuid(response?.workflowId), 'NEW_FIXTURE_ONLY_WORKFLOW_REQUIRED');
  const id = response.workflowId, scope = suffix => releaseScope(g.clusterId, g.workspaceId, suffix);
  const before = (await h.request(h.state.sessions.admin, scope(`workflows/${id}`))).data;
  assert(before.entity.kind === kind && before.entity.executionMode === 'approval' && before.entity.state === 'pending'
    && before.entity.approvalRequired && !before.entity.scheduled && before.decisions.length === 0,
    'UNVOTED_NEW_FIXTURE_WORKFLOW_REQUIRED');
  const approved = await vote(h, g, id, label, ['a']);
  const result = await h.once(`m11-business-portal-${label}-fixture-execute`, h.state.sessions.admin,
    scope(`workflows/${id}/execute`), 'POST', {revision: approved.revision, planHash: approved.planHash,
      confirmed: true, confirm_name: kind});
  assert(result.data.state === 'succeeded' && uuid(result.data.executionId), 'ACTUAL_FIXTURE_EXECUTION_SUCCEEDED_REQUIRED');
  const final = (await h.request(h.state.sessions.admin, scope(`workflows/${id}`))).data;
  assert(final.entity.state === 'succeeded' && final.steps.length > 0
    && final.steps.every(step => step.state === 'succeeded'), 'ACTUAL_FIXTURE_STEPS_SUCCEEDED_REQUIRED');
  if (kind === 'portal-metadata') assert(final.steps.every(step => step.kind === 'metadata'), 'METADATA_FIXTURE_MUST_HAVE_NO_NATIVE_STEP');
  if (kind === 'portal-publication') assert(final.steps.length === 3 && final.steps.filter(step => step.kind === 'native').length === 2,
    'REAL_PUBLICATION_ACL_KEYAUTH_METADATA_GRAPH_REQUIRED');
  g.fixtureWorkflows.push({label, workflowId: id, executionId: result.data.executionId, kind,
    nativeSteps: final.steps.filter(step => step.kind === 'native').length}); h.save();
}

async function freshDeveloperLogin(h, g, label) {
  await portalOnce(h, g, `${label}-csrf`, scopedPortal(g, '/auth/csrf'));
  const data = await portalOnce(h, g, `${label}-login`, '/auth/login', 'POST', {
    clusterId: g.clusterId, workspaceId: g.workspaceId, username: g.username, password: g.password});
  assert(data.developer?.id === g.developerId && data.developer.status === 'active', 'ORIGINAL_APPROVED_PORTAL_DEVELOPER_REQUIRED');
  const me = await portalOnce(h, g, `${label}-me`, scopedPortal(g, '/auth/me'));
  assert(me.id === g.developerId && me.status === 'active', 'ACTUAL_SEPARATE_DEVELOPER_IDENTITY_REQUIRED');
}

async function probe(h, g, label, expectedStatus) {
  assert(typeof g.issuedKey === 'string' && g.issuedKey.length >= 16, 'ORIGINAL_PRIVATE_ISSUED_KEY_REQUIRED');
  const scope = suffix => releaseScope(g.clusterId, g.workspaceId, suffix);
  const body = {routeId: g.fixture.routeId, input: {method: 'GET',
    url: `http://${g.fixture.proxyHost}${g.fixture.routePath}/m11-business-portal`, headers: {apikey: g.issuedKey}},
    confirmed: true, confirm_name: g.fixture.routeName};
  const deadline = Date.now() + 20_000;
  for (let attempt = 1; attempt <= 40 && Date.now() < deadline; attempt++) {
    // Each POST asks the BFF for one GET proxy probe, never an Admin mutation.
    const response = await h.once(`m11-business-portal-${label}-proxy-get-${attempt}`, h.state.sessions.admin,
      scope('toolbox/probes'), 'POST', body);
    assert(response.data.bodyReturned === false && [200, 401, 403, 404, 500, 502, 503, 504].includes(response.data.status),
      'ACTUAL_BOUNDED_BFF_PROXY_OBSERVATION_REQUIRED');
    g.proxyObservations.push({label, attempt, expectedStatus, actualStatus: response.data.status,
      bffRequestId: response.requestId, debugRunId: response.data.id, observedAt: response.data.observedAt}); h.save();
    if (response.data.status === expectedStatus) return;
    await pause(500);
  }
  throw Error('ACTUAL_PORTAL_KEY_PROXY_STATUS_NOT_OBSERVED');
}

async function runStage(h, g, stage) {
  const {scope} = await currentFixture(h, g), tenant = {clusterId: g.clusterId, workspaceId: g.workspaceId}, admin = h.state.sessions.admin;
  if (stage === 'fixtures') {
    const settingsRead = await h.request(admin, scope('portal/settings'));
    const settings = settingsRead.data.settings;
    assert(!settings || settings.publicProxyOrigin === g.configuration.publicProxyOrigin || !settings.publicProxyOrigin,
      'EXISTING_PORTAL_PUBLIC_PROXY_ORIGIN_CHANGED');
    const body = {...(settings ? {revision: settings.revision} : {slug: g.slug}), name: 'KongPilot M11 业务排程验收',
      publicProxyOrigin: g.configuration.publicProxyOrigin, published: true, registrationEnabled: true};
    const saved = (await h.once('m11-business-portal-settings', admin, scope('portal/settings'), settings ? 'PATCH' : 'POST', body)).data;
    await finishFixtureWorkflow(h, g, 'settings', saved, 'portal-metadata');
    const currentSettings = (await h.request(admin, scope('portal/settings'))).data.settings;
    assert(currentSettings.published && currentSettings.registrationEnabled, 'ACTUAL_PUBLISHED_REGISTERABLE_PORTAL_REQUIRED');
    g.settingsId = currentSettings.id; h.save();
    await portalOnce(h, g, 'register-csrf', scopedPortal(g, '/auth/csrf'));
    await portalOnce(h, g, 'register', '/auth/register', 'POST', {...tenant, username: g.username,
      password: g.password, email: `${g.username}@example.invalid`, displayName: 'M11 排程验收开发者'}, [202]);
    const pending = (await h.request(admin, releaseScope(g.clusterId, g.workspaceId, 'portal/developers',
      {search: g.username, status: 'pending', size: '20'}))).data;
    const matching = pending.items.filter(item => item.username === g.username);
    assert.equal(matching.length, 1, 'ONE_GENUINELY_REGISTERED_PENDING_DEVELOPER_REQUIRED');
    const developer = matching[0]; g.developerId = developer.id; h.save();
    await portalOnce(h, g, 'pending-login-denied', '/auth/login', 'POST', {...tenant, username: g.username, password: g.password}, [401, 403]);
    const review = (await h.once('m11-business-portal-review-developer', admin, scope(`portal/developers/${developer.id}/review`),
      'POST', {revision: developer.revision, status: 'active', confirmed: true, confirm_name: g.username})).data;
    await finishFixtureWorkflow(h, g, 'developer-review', review, 'portal-metadata');
    await freshDeveloperLogin(h, g, 'fixtures-approved');
    const app = entity(await portalOnce(h, g, 'application-create', '/applications', 'POST', {...tenant, name: g.name}));
    assert(uuid(app.id) && app.state === 'active', 'ACTUAL_DEVELOPER_APPLICATION_REQUIRED');
    g.applicationId = app.id; h.save();
  } else if (stage === 'publication') {
    requireDone(g, 'fixtures');
    const body = businessPortalPublicationBody({slug: `${g.slug}-api`, name: g.name,
      serviceId: g.configuration.serviceId, path: g.fixture.routePath});
    const created = (await h.once('m11-business-portal-publication-create', admin, scope('portal/publications'), 'POST', body)).data;
    await finishFixtureWorkflow(h, g, 'publication-create', created, 'portal-metadata');
    const listed = (await h.request(admin, releaseScope(g.clusterId, g.workspaceId, 'portal/publications', {search: g.name, size: '20'}))).data;
    const matches = listed.items.filter(item => item.slug === body.slug);
    assert.equal(matches.length, 1, 'ONE_ORIGINAL_CREATED_PORTAL_PUBLICATION_REQUIRED');
    const publication = entity((await h.request(admin, scope(`portal/publications/${matches[0].id}`))).data);
    assert(publication.status === 'draft' && publication.serviceId === g.configuration.serviceId, 'ACTUAL_NEW_DRAFT_PUBLICATION_REQUIRED');
    g.publicationId = publication.id; h.save();
    const published = (await h.once('m11-business-portal-publication-publish', admin, scope(`portal/publications/${publication.id}/publish`),
      'POST', {revision: publication.revision, confirmed: true, confirm_name: publication.name})).data;
    await finishFixtureWorkflow(h, g, 'publication-publish', published, 'portal-publication');
    const after = entity((await h.request(admin, scope(`portal/publications/${publication.id}`))).data);
    assert(after.status === 'published' && after.documentRevision !== null, 'ACTUAL_TERMINAL_PUBLISHED_PORTAL_REQUIRED');
    g.publishedRevision = after.documentRevision; h.save();
  } else if (stage === 'request') {
    requireDone(g, 'publication'); await freshDeveloperLogin(h, g, 'request');
    const result = await portalOnce(h, g, 'credential-request', '/requests', 'POST', {...tenant,
      applicationId: g.applicationId, publicationId: g.publicationId, reason: 'M11 自然定时器原始验收'});
    assert(uuid(result.workflowId) && result.approvalRequired === true && result.state === 'pending', 'ACTUAL_PENDING_PORTAL_ISSUE_WRAPPER_REQUIRED');
    g.workflowId = result.workflowId; g.grantId = result.grant?.id; h.save();
    const detail = (await h.request(admin, scope(`workflows/${g.workflowId}`))).data, view = detail.entity;
    assert(view.kind === 'portal-credential-issue' && view.approval?.format === 2 && view.executionMode === 'approval'
      && view.approvalRequired === true && detail.decisions.length === 0 && detail.steps.length === 4
      && detail.steps.filter(step => step.kind === 'native').length === 3
      && detail.steps.every(step => step.state === 'pending' && !step.operationId), 'UNEXECUTED_REAL_FOUR_STEP_PORTAL_WRAPPER_REQUIRED');
    g.originalWorkflow = {revision: view.revision, planRevision: view.planRevision, planHash: view.planHash, expiresAt: view.expiresAt,
      stepIds: detail.steps.map(step => step.id)}; h.save();
  } else if (stage === 'author') {
    requireDone(g, 'request');
    const detail = (await h.request(admin, scope(`workflows/${g.workflowId}`))).data, before = detail.entity;
    assert(before.state === 'pending' && before.planHash === g.originalWorkflow.planHash && !before.scheduled
      && detail.decisions.length === 0 && detail.steps.every(step => step.state === 'pending' && !step.operationId), 'FIRST_UNVOTED_ORIGINAL_PLAN_REQUIRED');
    g.authorBody = {workflowId: g.workflowId, revision: before.revision, planRevision: before.planRevision, planHash: before.planHash,
      spec: businessPortalWindow(before.expiresAt), confirmed: true, confirm_name: 'schedule-workflow'}; h.save();
    const result = (await h.once('m11-business-portal-schedule-author', admin, scope('workflow-schedules'), 'POST', g.authorBody)).data;
    const scheduled = entity(result); assert(result.commandCompleted === true && uuid(scheduled.id)
      && scheduled.state === 'pending-approval' && scheduled.workflowId === g.workflowId && scheduled.nativeAuthority === false,
      'ACTUAL_METADATA_ONLY_SCHEDULE_AUTHORING_REQUIRED');
    g.scheduleId = scheduled.id; h.save();
    const after = (await h.request(admin, scope(`workflows/${g.workflowId}`))).data;
    const currentSteps = after.steps.filter(step => !g.originalWorkflow.stepIds.includes(step.id));
    assert(after.entity.planRevision === g.originalWorkflow.planRevision + 1 && after.entity.planHash !== g.originalWorkflow.planHash
      && after.entity.expiresAt === g.originalWorkflow.expiresAt && after.decisions.length === 0
      && after.entity.capabilities.execute === false && currentSteps.length === 4
      && after.steps.every(step => step.state === 'pending' && !step.operationId), 'NEW_UNVOTED_REVISION_OLD_DEADLINE_AND_ORIGINAL_HISTORY_PRESERVED');
    g.scheduledWorkflow = {planRevision: after.entity.planRevision, planHash: after.entity.planHash,
      expiresAt: after.entity.expiresAt, stepIds: currentSteps.map(step => step.id)}; h.save();
  } else if (stage === 'votes') {
    requireDone(g, 'author');
    const approved = await vote(h, g, g.workflowId, 'scheduled-issue', ['a', 'b', 'c'], {format2: true});
    assert(approved.planRevision === g.scheduledWorkflow.planRevision && approved.planHash === g.scheduledWorkflow.planHash
      && uuid(approved.approval.approvalSetId) && approved.capabilities.execute === false, 'REAL_COMPLETE_NEW_REVISION_APPROVAL_SET_REQUIRED');
  } else if (stage === 'activate') {
    requireDone(g, 'votes');
    const current = entity((await h.request(admin, scope(`workflow-schedules/${g.scheduleId}`))).data);
    assert(current.state === 'pending-approval' && current.nativeAuthority === false
      && Date.parse(current.notBefore) > Date.now(), 'ORIGINAL_NOT_YET_DUE_SCHEDULE_REQUIRED');
    const response = (await h.once('m11-business-portal-schedule-activate', admin, scope(`workflow-schedules/${g.scheduleId}/activate`),
      'POST', {revision: current.revision, confirmed: true, confirm_name: 'activate-schedule'})).data;
    const activated = entity(response); assert(response.commandCompleted && activated.state === 'active' && activated.claimId === null,
      'ACTUAL_ACTIVE_UNCLAIMED_SCHEDULE_REQUIRED');
    g.activatedAt = new Date().toISOString(); h.save();
  } else if (stage === 'observe') {
    requireDone(g, 'activate');
    const deadline = Math.min(Date.parse(g.authorBody.spec.windowEnd) + 30_000, Date.now() + 360_000);
    let terminal;
    while (Date.now() < deadline) {
      const observed = entity((await h.request(admin, scope(`workflow-schedules/${g.scheduleId}`))).data);
      g.timerObservations.push({at: new Date().toISOString(), state: observed.state, claimId: observed.claimId, revision: observed.revision}); h.save();
      if (['succeeded', 'partial', 'failed', 'uncertain', 'blocked', 'cancelled', 'expired'].includes(observed.state)) {terminal = observed; break;}
      await pause(1000);
    }
    assert(terminal?.state === 'succeeded' && uuid(terminal.claimId), 'NATURAL_BUSINESS_TIMER_SUCCESS_REQUIRED_NO_MANUAL_EXECUTION');
    const detail = (await h.request(admin, scope(`workflows/${g.workflowId}`))).data;
    const currentSteps = detail.steps.filter(step => g.scheduledWorkflow.stepIds.includes(step.id));
    assert(detail.entity.state === 'succeeded' && detail.entity.planHash === g.scheduledWorkflow.planHash
      && currentSteps.length === 4 && currentSteps.every(step => step.state === 'succeeded')
      && currentSteps.filter(step => step.kind === 'native' && uuid(step.operationId)).length === 3
      && detail.steps.filter(step => g.originalWorkflow.stepIds.includes(step.id)).every(step => step.state === 'pending' && !step.operationId),
      'ACTUAL_SCHEDULED_NATIVE_AND_METADATA_COMPLETION_REQUIRED');
    await freshDeveloperLogin(h, g, 'observe');
    const grants = await portalOnce(h, g, 'active-grants', scopedPortal(g, `/applications/${g.applicationId}/grants`));
    const grant = grants.items.find(item => item.id === g.grantId && item.publicationId === g.publicationId && item.state === 'active');
    assert(grant, 'ACTUAL_ACTIVE_ORIGINAL_PORTAL_GRANT_REQUIRED');
    const credentials = await portalOnce(h, g, 'active-credentials', scopedPortal(g, `/applications/${g.applicationId}/grants/${g.grantId}/credentials`));
    const active = credentials.items.filter(item => item.state === 'active'); assert.equal(active.length, 1, 'ONE_ACTUAL_ACTIVE_PORTAL_CREDENTIAL_REQUIRED');
    g.credentialId = active[0].id; h.save();
    const revealed = await portalOnce(h, g, 'original-key-reveal', `/applications/${g.applicationId}/grants/${g.grantId}/credentials/${g.credentialId}/reveal`,
      'POST', {...tenant, revision: active[0].revision});
    assert(typeof revealed.key === 'string' && revealed.key.length >= 16, 'AUTHORIZED_ACTUAL_PORTAL_KEY_REVEAL_REQUIRED');
    g.issuedKey = revealed.key; h.save(); await probe(h, g, 'issued-key', 200);
  } else if (stage === 'revoke-request') {
    requireDone(g, 'observe'); await freshDeveloperLogin(h, g, 'revoke-request');
    const credentials = await portalOnce(h, g, 'before-revoke-credentials', scopedPortal(g, `/applications/${g.applicationId}/grants/${g.grantId}/credentials`));
    const active = credentials.items.find(item => item.id === g.credentialId && item.state === 'active'); assert(active, 'ORIGINAL_ACTIVE_KEY_REQUIRED_FOR_REVOCATION');
    const result = await portalOnce(h, g, 'revoke-original-key', `/applications/${g.applicationId}/grants/${g.grantId}/credentials/${g.credentialId}/revoke`,
      'POST', {...tenant, revision: active.revision, confirmed: true, confirm_name: `吊销 ${active.id}`, retireConsumer: true,
        reason: 'M11 原始定时发放凭证吊销验收'});
    assert(uuid(result.workflowId) && result.approvalRequired && result.state === 'pending', 'ACTUAL_APPROVAL_REQUIRED_REVOCATION_WRAPPER');
    g.revocationWorkflowId = result.workflowId; h.save();
    const detail = (await h.request(admin, scope(`workflows/${g.revocationWorkflowId}`))).data;
    assert(detail.entity.kind === 'portal-credential-revoke' && detail.entity.approval === undefined
      && detail.decisions.length === 0 && detail.steps.every(step => step.state === 'pending' && !step.operationId), 'ACTUAL_UNVOTED_SINGLE_LEVEL_REVOKE_REQUIRED');
  } else if (stage === 'revoke-votes') {
    requireDone(g, 'revoke-request'); await vote(h, g, g.revocationWorkflowId, 'revoke', ['a']);
    // Intentionally stop here. Root reviews and executes this fresh approved
    // revoke workflow once through its original authenticated BFF receipt.
  } else if (stage === 'revoke-observe') {
    requireDone(g, 'revoke-votes');
    const detail = (await h.request(admin, scope(`workflows/${g.revocationWorkflowId}`))).data;
    assert(detail.entity.state === 'succeeded' && detail.decisions.length === 1
      && detail.steps.every(step => step.state === 'succeeded' && (step.kind === 'metadata' || uuid(step.operationId))),
      'ROOT_SEPARATELY_REVIEWED_ORIGINAL_REVOCATION_EXECUTION_REQUIRED');
    await freshDeveloperLogin(h, g, 'revoke-observe');
    const credentials = await portalOnce(h, g, 'revoked-credentials', scopedPortal(g, `/applications/${g.applicationId}/grants/${g.grantId}/credentials`));
    assert(credentials.items.some(item => item.id === g.credentialId && item.state === 'revoked'), 'ACTUAL_ORIGINAL_CREDENTIAL_REVOKED_REQUIRED');
    await probe(h, g, 'revoked-original-key', 401);
  }
}

function publicReport(h, g, stage, passed, errorCode, startIndex) {
  return {recordedAt: new Date().toISOString(), stage, passed, environment: 'isolated release lab',
    productionDeployment: false, wholeM11Accepted: false, sourceOnlyUntilRootInvocation: true,
    noKongSourceOrDatabaseAccess: true, noManualBusinessTimerTick: true, noIssueExecuteRequest: true,
    noRevokeExecuteRequest: true, credentialsPublished: false, clusterId: g.clusterId, workspaceId: g.workspaceId,
    fixture: g.fixture, publicationId: g.publicationId ?? null, applicationId: g.applicationId ?? null,
    workflowId: g.workflowId ?? null, scheduleId: g.scheduleId ?? null,
    originalPlanRevision: g.originalWorkflow?.planRevision ?? null, scheduledPlanRevision: g.scheduledWorkflow?.planRevision ?? null,
    oldDeadlinePreserved: g.scheduledWorkflow ? g.originalWorkflow.expiresAt === g.scheduledWorkflow.expiresAt : null,
    format2IssuePolicy: g.issuePolicy, stageRequestObservations: h.state.requests.slice(startIndex).map(packet => ({
      transport: packet.transport ?? 'console-http', method: packet.method, path: packet.path.split('?')[0],
      label: packet.label ?? null, state: packet.state, status: packet.status ?? null, requestId: packet.requestId ?? null,
      bodyHash: packet.bodyHash, responseHash: packet.responseHash ?? null})),
    timerObservations: g.timerObservations, proxyObservations: g.proxyObservations,
    evidenceLimitations: ['HTTP-only runner does not prove SQL lease generation, NULL SID, append-only grants or source/runtime equality.',
      'Root must independently verify actual worker runtime, original Native receipts, audits and SQL identities.',
      'Direct-mode Portal mandatory approval requires a separate fresh fixture; this original run uses approval mode.'],
    ...(errorCode ? {errorCode} : {})};
}

export async function main(env = process.env, stage = process.argv[2] ?? 'fixtures') {
  const configuration = businessPortalConfiguration(env, stage);
  const {stage: _selectedStage, ...storedConfiguration} = configuration;
  const reportPath = resolve(`artifacts/M11/business-portal-scheduled-${stage}-original.json`);
  assert(!existsSync(reportPath), 'ORIGINAL_BUSINESS_PORTAL_STAGE_REPORT_PRESENT_NO_REPLAY');
  mkdirSync(dirname(reportPath), {recursive: true});
  const fd = openSync(reportPath, 'wx', 0o644); let h, g, startIndex;
  try {
    h = new ReleaseHarness('M11', {resume: true}); h.assertWritable();
    assert(uuid(h.state.cid) && uuid(h.state.wid) && ['admin', 'a', 'b', 'c'].every(label => uuid(h.state.sessions?.[label]?.user?.id)),
      'ACTUAL_RELEASE_LAB_SCOPE_AND_FOUR_CONSOLE_IDENTITIES_REQUIRED');
    assert.equal(new Set(['admin', 'a', 'b', 'c'].map(label => h.state.sessions[label].user.id)).size, 4, 'FOUR_DISTINCT_ACTUAL_CONSOLE_IDENTITIES_REQUIRED');
    g = h.state.businessPortalScheduledOriginal ??= {version: 1, clusterId: h.state.cid, workspaceId: h.state.wid,
      configuration: storedConfiguration, slug: `m11-biz-portal-${randomUUID().slice(0, 8)}`,
      name: `M11 Portal ${randomUUID().slice(0, 8)}`, username: `m11biz${randomUUID().replaceAll('-', '').slice(0, 20)}`,
      password: releasePassword(), developerSession: {cookie: '', csrf: ''}, runs: {}, portalPackets: [], votedPackets: [],
      fixtureWorkflows: [], timerObservations: [], proxyObservations: []};
    assert(g.version === 1 && g.clusterId === h.state.cid && g.workspaceId === h.state.wid, 'ORIGINAL_BUSINESS_PORTAL_SCOPE_CHANGED');
    assert.deepEqual(g.configuration, storedConfiguration, 'ORIGINAL_BUSINESS_PORTAL_CONFIGURATION_CHANGED');
    assert(!g.runs[stage], 'ORIGINAL_BUSINESS_PORTAL_STAGE_PRESENT_NO_REPLAY');
    g.runs[stage] = {state: 'prepared', startedAt: new Date().toISOString()}; startIndex = h.state.requests.length; h.save();
    await runStage(h, g, stage); g.runs[stage].state = 'succeeded'; g.runs[stage].completedAt = new Date().toISOString(); h.save();
    writeSync(fd, JSON.stringify(publicReport(h, g, stage, true, undefined, startIndex), null, 2) + '\n');
    console.log(JSON.stringify({stage, passed: true, actualStageOnly: true, credentialsPublished: false}));
  } catch (error) {
    const code = safeCode(error);
    if (g?.runs?.[stage]) {g.runs[stage].state = 'failed'; g.runs[stage].errorCode = code; g.runs[stage].failedAt = new Date().toISOString(); try {h.save();} catch {/* Preserve original CAS failure. */}}
    const report = h && g ? publicReport(h, g, stage, false, code, startIndex ?? h.state.requests.length)
      : {recordedAt: new Date().toISOString(), stage, passed: false, errorCode: code, credentialsPublished: false, noHttpAcceptanceClaim: true};
    writeSync(fd, JSON.stringify(report, null, 2) + '\n'); console.error(JSON.stringify({stage, passed: false, errorCode: code})); process.exitCode = 1;
  } finally {closeSync(fd);}
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
