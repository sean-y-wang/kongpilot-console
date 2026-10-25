import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';

// SOURCE ONLY until Root explicitly runs one original stage. Importing this
// module never opens a ledger, reads a CA, creates sessions or sends requests.
// Kong 1.5.1 has authorize/token proxy handlers, not a proxy revoke endpoint.
// Client revocation uses an independently approved credential recycle DELETE;
// its native credential FK cascades to tokens/codes. Restoring the credential
// preserves the original client ID/secret, but cannot resurrect issued tokens.
const stages = ['create-probes', 'issue-refresh', 'revoke-client', 'restore-client'];
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
const referenceId = value => typeof value === 'string' ? value : value?.id;
const sha = value => createHash('sha256').update(value).digest('hex');
const fieldMap = schema => Array.isArray(schema?.fields) ? Object.assign({}, ...schema.fields) : schema?.fields;
const secret = value => typeof value === 'string' && value.length >= 16 && value.length <= 4096 && !/[\r\n]/.test(value);

/** Pure configuration contract. Root supplies a published BUSINESS HTTPS port
 * and public ca.pem in an absolute directory; no Admin destination or HTTP/TLS
 * termination-header bypass is accepted. The SNI is also the exact Route host.
 * Loading the CA and using the transport happen only in main at runtime. */
export function restoredOAuthRequiresTLS(env, caPem) {
  assert.equal(env.RELEASE_LAB_M11_RESTORED_OAUTH2_HTTPS_PROBES_READY, 'true', 'ROOT_EXPLICIT_OAUTH2_HTTPS_GATE_REQUIRED');
  const origin = new URL(env.RELEASE_LAB_OAUTH2_HTTPS_ORIGIN);
  assert(origin.protocol === 'https:' && ['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname)
    && origin.port && !['8001', '8444', '5445'].includes(origin.port) && origin.pathname === '/'
    && !origin.username && !origin.password && !origin.search && !origin.hash, 'EXACT_PUBLISHED_BUSINESS_HTTPS_ORIGIN_REQUIRED');
  const servername = env.RELEASE_LAB_OAUTH2_TLS_SERVERNAME;
  assert(typeof servername === 'string' && servername.length <= 253
    && /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(servername)
    && servername.includes('.') && !servername.includes('..') && !/^[0-9.]+$/.test(servername), 'EXACT_CERTIFICATE_DNS_SAN_REQUIRED');
  const baseDirectory = env.RELEASE_LAB_OAUTH2_TLS_BASE_DIRECTORY;
  assert(typeof baseDirectory === 'string' && isAbsolute(baseDirectory), 'ROOT_PUBLIC_CA_BASE_DIRECTORY_REQUIRED');
  assert(typeof caPem === 'string' && caPem.length <= 64 * 1024 && !caPem.includes('PRIVATE KEY')
    && /^(?:\s*-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END CERTIFICATE-----\s*)+$/.test(caPem), 'EXPLICIT_PUBLIC_CERTIFICATE_CA_REQUIRED');
  return Object.freeze({ requiresTLS: true, origin: origin.origin, hostname: origin.hostname === '[::1]' ? '::1' : origin.hostname,
    port: Number(origin.port), servername, ca: caPem, publicCaSha256: sha(caPem), rejectUnauthorized: true,
    caFile: resolve(baseDirectory, 'ca.pem') });
}

export function restoredOAuthAuthorizationForm(client, provisionKey, consumerId, state, scope = 'm11-read') {
  assert(secret(client?.client_id) && secret(client?.client_secret), 'ORIGINAL_PRIVATE_OAUTH_CLIENT_REQUIRED');
  assert(Array.isArray(client.redirect_uris) && client.redirect_uris.length === 1, 'EXACT_ORIGINAL_REDIRECT_URI_REQUIRED');
  const redirect = new URL(client.redirect_uris[0]);
  assert(redirect.protocol === 'https:' && !redirect.username && !redirect.password && !redirect.hash && !redirect.search, 'ORIGINAL_HTTPS_CALLBACK_REQUIRED');
  assert(secret(provisionKey) && uuid(consumerId) && secret(state) && scope === 'm11-read', 'ROOT_AUTHORIZED_PROVISIONING_INPUT_REQUIRED');
  return { response_type: 'code', client_id: client.client_id, redirect_uri: redirect.href,
    provision_key: provisionKey, authenticated_userid: consumerId, scope, state };
}

export function restoredOAuthAuthorizationCode(body, client, expectedState) {
  assert(body && Object.keys(body).length === 1 && typeof body.redirect_uri === 'string', 'KONG15_AUTHORIZATION_REDIRECT_RESPONSE_REQUIRED');
  const actual = new URL(body.redirect_uri), original = new URL(client.redirect_uris[0]);
  assert.equal(actual.origin, original.origin, 'ORIGINAL_CALLBACK_ORIGIN_REQUIRED');
  assert.equal(actual.pathname, original.pathname, 'ORIGINAL_CALLBACK_PATH_REQUIRED');
  assert(!actual.hash && !actual.username && !actual.password, 'CALLBACK_FRAGMENT_OR_CREDENTIALS_FORBIDDEN');
  assert.deepEqual([...actual.searchParams.keys()].sort(), ['code', 'state'], 'EXACT_AUTHORIZATION_CODE_FIELDS_REQUIRED');
  assert.equal(actual.searchParams.get('state'), expectedState, 'ORIGINAL_AUTHORIZATION_STATE_REQUIRED');
  const code = actual.searchParams.get('code'); assert(secret(code), 'ACTUAL_AUTHORIZATION_CODE_REQUIRED'); return code;
}

export function restoredOAuthToken(body, previous) {
  assert(body && secret(body.access_token) && secret(body.refresh_token) && body.token_type === 'bearer'
    && Number.isSafeInteger(body.expires_in) && body.expires_in > 0 && body.expires_in <= 7200 && !body.error, 'ACTUAL_BEARER_AND_REFRESH_TOKEN_REQUIRED');
  if (previous) { assert.notEqual(body.access_token, previous.access_token, 'NEW_ACCESS_TOKEN_REQUIRED');
    assert.notEqual(body.refresh_token, previous.refresh_token, 'NEW_REFRESH_TOKEN_REQUIRED'); }
  return { access_token: body.access_token, refresh_token: body.refresh_token, token_type: body.token_type,
    expires_in: body.expires_in, receivedAt: new Date().toISOString() };
}

export function restoredOAuthUnexpired(token, now = Date.now()) {
  assert(secret(token?.access_token) && secret(token?.refresh_token) && Number.isSafeInteger(token.expires_in)
    && token.expires_in > 0 && token.expires_in <= 7200 && Number.isSafeInteger(now), 'ORIGINAL_ISSUED_TOKEN_EXPIRY_REQUIRED');
  const receivedAt = Date.parse(token.receivedAt);
  assert(Number.isFinite(receivedAt) && receivedAt <= now && receivedAt + token.expires_in * 1000 > now + 120_000,
    'TOKEN_MUST_REMAIN_UNEXPIRED_THROUGH_REVOCATION_PROOF');
}

function assertProxyWritable(h, g) {
  h.assertWritable();
  assert(Array.isArray(h.state?.requests) && Array.isArray(g.proxyPackets) && !g.proxyPackets.some(packet => ['prepared', 'response_unknown'].includes(packet.state)
    || packet.method === 'POST' && packet.status >= 500), 'OAUTH_ORIGINAL_UNKNOWN_STOPS_ALL_FURTHER_REQUESTS');
  for (const packet of g.proxyPackets) {
    const markers = h.state.requests.filter(item => item.key === packet.key);
    assert(markers.length === 1 && markers[0].transport === 'business-https' && markers[0].label === `m11-restored-oauth2-https-${packet.label}`
      && markers[0].state === packet.state && markers[0].status === packet.status && markers[0].method === packet.method
      && markers[0].path === `${packet.origin}${packet.path}` && JSON.stringify(markers[0].headers) === JSON.stringify(packet.headers)
      && JSON.stringify(markers[0].body) === JSON.stringify(packet.form ?? null)
      && JSON.stringify(markers[0].responseData) === JSON.stringify(packet.responseData)
      && markers[0].servername === packet.servername && markers[0].publicCaSha256 === packet.publicCaSha256
      && markers[0].rejectUnauthorized === true
      && (packet.method === 'GET' ? markers[0].resolution?.knownNoNativeSend === true && packet.knownNoNativeSend === true
        : markers[0].resolution === undefined && packet.knownNoNativeSend === undefined), 'ORIGINAL_GLOBAL_OAUTH_MARKER_CHANGED');
  }
}

/** One original HTTPS request, durable BEFORE transport, no retry/redirect or
 * session refresh. Token bodies/headers/results stay in the private ledger.
 * Tests replace node:https with an EventEmitter, never a live endpoint. */
export async function restoredOAuthHttpsOnce(h, g, label, tls, input) {
  assertProxyWritable(h, g);
  assert(tls?.requiresTLS === true && tls.rejectUnauthorized === true && tls.publicCaSha256 === sha(tls.ca), 'EXPLICIT_TLS_CONFIGURATION_REQUIRED');
  // Reapply the pure contract so a mutated DTO cannot select Admin/HTTP or
  // change SNI/CA between original stages.
  const checked = restoredOAuthRequiresTLS({ RELEASE_LAB_M11_RESTORED_OAUTH2_HTTPS_PROBES_READY: 'true',
    RELEASE_LAB_OAUTH2_HTTPS_ORIGIN: tls.origin, RELEASE_LAB_OAUTH2_TLS_SERVERNAME: tls.servername,
    RELEASE_LAB_OAUTH2_TLS_BASE_DIRECTORY: dirname(tls.caFile) }, tls.ca);
  assert.deepEqual(tls, checked, 'ORIGINAL_TLS_CONFIGURATION_CHANGED');
  assert(typeof label === 'string' && /^[a-z0-9-]{1,120}$/.test(label) && !g.proxyPackets.some(packet => packet.label === label), 'ORIGINAL_OAUTH_HTTPS_REQUEST_PRESENT_NO_REPLAY');
  assert(['GET', 'POST'].includes(input?.method) && typeof input.path === 'string'
    && /^\/m11-oauth2-[a-f0-9-]{36}(?:\/oauth2\/(?:authorize|token))?$/.test(input.path), 'FIXED_OAUTH_BUSINESS_PATH_REQUIRED');
  assert(input.method === 'POST' ? input.path.endsWith('/oauth2/authorize') || input.path.endsWith('/oauth2/token') : !input.path.includes('/oauth2/'), 'FIXED_OAUTH_METHOD_PATH_PAIR_REQUIRED');
  assert(Array.isArray(input.expected) && input.expected.length > 0
    && input.expected.every(status => (input.method === 'GET' ? [200, 401, 500, 502, 503, 504] : [200, 400, 401]).includes(status)), 'EXACT_OAUTH_EXPECTED_STATUS_REQUIRED');
  const timeoutMs = input.timeoutMs ?? 10_000;
  assert(Number.isSafeInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 10_000, 'BOUNDED_HTTPS_DEADLINE_REQUIRED');
  const headers = { ...(input.headers ?? {}) };
  assert(Object.keys(headers).every(name => name === 'authorization') && Object.values(headers).every(value => typeof value === 'string' && !/[\r\n]/.test(value)), 'OAUTH_PROBE_AUTHORIZATION_HEADER_ONLY');
  assert(input.method === 'POST' ? input.form && !Object.keys(headers).length : input.form === undefined, 'FORM_POST_OR_BEARER_GET_REQUIRED');
  const form = input.form ? structuredClone(input.form) : undefined;
  if (form) assert(Object.entries(form).every(([key, value]) => /^[a-z_]+$/.test(key) && typeof value === 'string' && value.length <= 4096 && !/[\r\n]/.test(value)), 'EXACT_PRIVATE_FORM_STRINGS_REQUIRED');
  const body = form ? new URLSearchParams(form).toString() : '';
  const packet = { label, key: randomUUID(), method: input.method, origin: tls.origin, path: input.path, headers, ...(form ? { form } : {}),
    state: 'prepared', preparedAt: new Date().toISOString(), timeoutMs, tls: true, servername: tls.servername,
    publicCaSha256: tls.publicCaSha256, rejectUnauthorized: true };
  assert(!h.state.requests.some(item => item.key === packet.key || item.label === `m11-restored-oauth2-https-${label}`), 'ORIGINAL_GLOBAL_OAUTH_REQUEST_PRESENT_NO_REPLAY');
  // The global ReleaseHarness guard must also see an unknown business POST.
  // This is a transport observation, never an Admin receipt or execution fact.
  // No synthetic server request ID/native status or idempotency guarantee is
  // claimed for OAuth issuance. Both projections retain the original key.
  const marker = { transport: 'business-https', label: `m11-restored-oauth2-https-${label}`, key: packet.key, method: packet.method,
    path: `${packet.origin}${packet.path}`, body: structuredClone(form ?? null), headers: structuredClone(headers),
    state: 'prepared', preparedAt: packet.preparedAt, timeoutMs, tls: true, servername: tls.servername, publicCaSha256: tls.publicCaSha256, rejectUnauthorized: true };
  g.proxyPackets.push(packet); h.state.requests.push(marker); h.save();
  try {
    const observed = await new Promise((accept, reject) => {
      let done = false, deadlineTimer;
      const finish = (error, value) => { if (done) return; done = true; clearTimeout(deadlineTimer); error ? reject(error) : accept(value); };
      const request = httpsRequest({ hostname: tls.hostname, port: tls.port, servername: tls.servername, ca: tls.ca,
        rejectUnauthorized: true, method: packet.method, path: packet.path,
        headers: { host: tls.servername, ...headers, ...(form ? { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body) } : {}) } }, response => {
        if (response.socket?.authorized !== true) { response.destroy(); finish(Error('OAUTH_TLS_SOCKET_NOT_AUTHORIZED')); return; }
        const chunks = []; let length = 0;
        response.on('data', chunk => { length += Buffer.byteLength(chunk); if (length > 64 * 1024) { response.destroy(); finish(Error('OAUTH_RESPONSE_BUDGET_EXCEEDED')); } else chunks.push(Buffer.from(chunk)); });
        response.on('error', () => finish(Error('OAUTH_RESPONSE_INTERRUPTED')));
        response.on('aborted', () => finish(Error('OAUTH_RESPONSE_INTERRUPTED')));
        response.on('end', () => { try {
          assert(Number.isInteger(response.statusCode) && response.statusCode >= 100 && response.statusCode <= 599);
          const result = JSON.parse(Buffer.concat(chunks).toString('utf8')); assert(result && typeof result === 'object' && !Array.isArray(result));
          finish(null, { status: response.statusCode, result, tlsAuthorized: true });
        } catch { finish(Error('OAUTH_RESPONSE_NOT_COMPLETE_BOUNDED_JSON')); } });
      });
      request.on('error', () => finish(Error('OAUTH_HTTPS_TRANSPORT_FAILED')));
      const expire = () => { const error = Error('OAUTH_HTTPS_DEADLINE_EXCEEDED'); finish(error); request.destroy(error); };
      // A wall deadline also covers TLS setup and a slowly streamed response;
      // socket inactivity timeouts alone do not bound total request duration.
      deadlineTimer = setTimeout(expire, timeoutMs); request.setTimeout(timeoutMs, expire);
      request.end(body);
    });
    Object.assign(packet, { state: 'response_observed', status: observed.status, responseData: observed.result,
      tlsAuthorized: true, responseObservedAt: new Date().toISOString() });
    Object.assign(marker, { state: packet.state, status: packet.status, responseData: structuredClone(packet.responseData),
      tlsAuthorized: packet.tlsAuthorized, responseObservedAt: packet.responseObservedAt });
    // A complete fixed-path GET has no OAuth issuance or Admin mutation. Kong
    // 1.5 can briefly return 500 while old-token/credential caches converge;
    // this known read response may be polled, never labelled token invalidity.
    if (packet.method === 'GET') { packet.knownNoNativeSend = true; marker.resolution = { knownNoNativeSend: true, kind: 'complete-business-get-observation' }; }
    h.save();
    assert(input.expected.includes(observed.status), 'OAUTH_ACTUAL_STATUS_MISMATCH_NO_REPLAY');
    return { status: observed.status, body: observed.result };
  } catch (error) {
    if (packet.state === 'prepared') { packet.state = 'response_unknown'; packet.errorCode = 'OAUTH_HTTPS_RESPONSE_UNKNOWN';
      Object.assign(marker, { state: packet.state, errorCode: packet.errorCode }); h.save(); }
    throw error;
  }
}

/** Eventual propagation may be observed only with new bounded GET packets.
 * An OAuth authorize/token/refresh POST is never retried, including 400/401. */
export async function restoredOAuthPollGet(send, { label, path, headers, expectedStatus, consumerId, maxAttempts = 20, delayMs = 500 }, pause = ms => new Promise(resolvePause => setTimeout(resolvePause, ms)), now = () => Date.now()) {
  assert([200, 401].includes(expectedStatus) && Number.isSafeInteger(maxAttempts) && maxAttempts >= 1 && maxAttempts <= 40
    && Number.isSafeInteger(delayMs) && delayMs >= 0 && delayMs <= 500 && maxAttempts * delayMs <= 20_000, 'BOUNDED_GET_PROPAGATION_POLL_REQUIRED');
  const deadline = now() + 20_000;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const remaining = deadline - now();
    if (remaining <= 0) throw Error('OAUTH_PROPAGATION_DEADLINE_EXCEEDED_NO_POST_RETRY');
    const actual = await send(`${label}-${attempt + 1}`, { method: 'GET', path, headers,
      expected: [200, 401, 500, 502, 503, 504], timeoutMs: Math.min(10_000, remaining) });
    if (now() >= deadline) throw Error('OAUTH_PROPAGATION_DEADLINE_EXCEEDED_NO_POST_RETRY');
    assert([200, 401, 500, 502, 503, 504].includes(actual.status), 'EXACT_COMPLETE_GET_RESPONSE_REQUIRED');
    if (actual.status === expectedStatus) {
      if (expectedStatus === 200) assert(actual.body.upstream === 'kongos-test' && actual.body.method === 'GET' && actual.body.path === path
        && actual.body.consumerId === consumerId && uuid(consumerId), 'REAL_UPSTREAM_RESTORED_CONSUMER_REQUIRED');
      else assert(actual.body.error === (headers?.authorization ? 'invalid_token' : 'invalid_request'), 'REAL_OAUTH_AUTHENTICATION_DENIAL_REQUIRED');
      return { actualStatus: actual.status, attempts: attempt + 1 };
    }
    if (attempt + 1 < maxAttempts) await pause(Math.max(0, Math.min(delayMs, deadline - now())));
  }
  throw Error('OAUTH_PROPAGATION_DEADLINE_EXCEEDED_NO_POST_RETRY');
}

async function main() {
  assert.equal(process.env.RELEASE_LAB_M11_RESTORED_OAUTH2_HTTPS_PROBES_READY, 'true', 'ROOT_EXPLICIT_OAUTH2_HTTPS_GATE_REQUIRED');
  assert(process.argv.length === 3 && stages.includes(process.argv[2]), 'ONE_FIXED_ORIGINAL_OAUTH_STAGE_REQUIRED');
  const stage = process.argv[2], reportPath = resolve(`artifacts/M11/gate3-restored-oauth2-https-${stage}-http-original.json`);
  assert(!existsSync(reportPath), 'ORIGINAL_OAUTH_REPORT_PRESENT_NO_REPLAY');
  assert(isAbsolute(process.env.RELEASE_LAB_OAUTH2_TLS_BASE_DIRECTORY ?? ''), 'ROOT_PUBLIC_CA_BASE_DIRECTORY_REQUIRED');
  const tls = restoredOAuthRequiresTLS(process.env, readFileSync(resolve(process.env.RELEASE_LAB_OAUTH2_TLS_BASE_DIRECTORY, 'ca.pem'), 'utf8'));
  const h = new ReleaseHarness('M11', { resume: true }), seed = h.state.gate3PersistentCredentials, cid = h.state.cid, wid = h.state.wid;
  assert(uuid(cid) && uuid(wid) && seed?.version === 1 && seed.clusterId === cid && seed.workspaceId === wid
    && uuid(seed.consumerId) && uuid(seed.credentialIds?.oauth2) && seed.sourceInputs?.oauth2, 'ORIGINAL_RESTORED_CONSUMER_B_REQUIRED');
  const subjects = {};
  function session(label) {
    const current = h.state.sessions[label]; assert(uuid(current?.user?.id) && uuid(current.sid) && typeof current.cookie === 'string', 'ROOT_ACTUAL_SESSION_REQUIRED');
    const access = current.cookie.split('; ').find(pair => pair.startsWith('kongos_access=')); assert(access, 'ROOT_ACTUAL_ACCESS_COOKIE_REQUIRED');
    let claims; try { claims = JSON.parse(Buffer.from(access.slice('kongos_access='.length).split('.')[1], 'base64url').toString()); } catch { throw Error('ROOT_ACCESS_COOKIE_INVALID'); }
    assert.equal(claims.sub, current.user.id); assert.equal(claims.sid, current.sid); assert.equal(current.user.id, seed.subjects?.[label]);
    assert(Number.isFinite(claims.exp) && claims.exp * 1000 > Date.now() + 120_000, 'ROOT_FRESH_LOGIN_REQUIRED_NO_IMPLICIT_REFRESH'); return current;
  }
  h.assertWritable(); for (const actor of ['admin', 'a', 'b', 'c']) subjects[actor] = session(actor).user.id;
  assert.equal(new Set(Object.values(subjects)).size, 4, 'FOUR_DISTINCT_ORIGINAL_ACTUAL_SUBJECTS_REQUIRED');
  const stateKey = 'gate3RestoredOAuth2HttpsProbes', index = stages.indexOf(stage);
  if (!index) assert(!h.state[stateKey], 'ORIGINAL_OAUTH_NAMESPACE_PRESENT_NO_REPLAY');
  else assert(h.state[stateKey]?.stages?.[stages[index - 1]]?.state === 'succeeded', 'EXACT_PREVIOUS_ORIGINAL_OAUTH_STAGE_REQUIRED');
  const g = h.state[stateKey] ??= { version: 1, clusterId: cid, workspaceId: wid, consumerId: seed.consumerId,
    credentialId: seed.credentialIds.oauth2, subjects, stages: {}, writeKeys: {}, intents: {}, checks: [], proxyPackets: [],
    evidenceKey: randomBytes(32).toString('hex'), fixtureSuffix: randomUUID(), provisionKey: randomBytes(32).toString('hex'),
    wrongToken: randomBytes(32).toString('hex'),
    tlsBinding: { origin: tls.origin, servername: tls.servername, publicCaSha256: tls.publicCaSha256 }, authEndpointValidation: 'pending-actual-HTTPS-chain' };
  assert.equal(g.version, 1); assert.equal(g.clusterId, cid); assert.equal(g.workspaceId, wid); assert.equal(g.consumerId, seed.consumerId); assert.equal(g.credentialId, seed.credentialIds.oauth2);
  assert.deepEqual(g.subjects, subjects); assert.deepEqual(g.tlsBinding, { origin: tls.origin, servername: tls.servername, publicCaSha256: tls.publicCaSha256 });
  assertProxyWritable(h, g); assert(!g.stages[stage], 'ORIGINAL_OAUTH_STAGE_PRESENT_NO_REPLAY');
  g.stages[stage] = { state: 'started', startedAt: new Date().toISOString() }; h.save();
  const scope = (suffix, extra = {}) => releaseScope(cid, wid, suffix, extra);
  const hmac = value => createHmac('sha256', g.evidenceKey).update(JSON.stringify(value)).digest('hex');
  const read = (path, options = {}) => h.request(session('admin'), path, 'GET', undefined, options);
  function check(name, facts = {}) { g.checks.push({ stage, name, passed: true, ...facts }); h.check(true, name, { stage, ...facts }); }
  async function once(suffix, path, body, actor = 'admin') {
    assertProxyWritable(h, g); const label = `m11-restored-oauth2-https-${stage}-${suffix}`;
    assert(!Object.hasOwn(g.writeKeys, label) && !h.state.requests.some(packet => packet.label === label), 'ORIGINAL_OAUTH_BFF_REQUEST_PRESENT_NO_REPLAY');
    const key = randomUUID(); assert(!h.state.requests.some(packet => packet.key === key)); g.writeKeys[label] = key; h.save();
    return (await h.once(label, session(actor), path, 'POST', body, { key })).data;
  }
  const send = (label, input) => restoredOAuthHttpsOnce(h, g, `${stage}-${label}`, tls, input);
  const poll = (label, token, expectedStatus) => restoredOAuthPollGet(send, { label, path: g.routeBody.paths[0],
    headers: token ? { authorization: `Bearer ${token}` } : {}, expectedStatus, consumerId: g.consumerId });
  function report(passed) {
    const keys = new Set(Object.entries(g.writeKeys).filter(([label]) => label.startsWith(`m11-restored-oauth2-https-${stage}-`)).map(([, key]) => key));
    const packets = h.state.requests.filter(packet => keys.has(packet.key));
    const output = { passed, milestone: 'M11', stage, sourceOnly: false, productionDeployment: false, overallM11Accepted: false,
      consumerId: g.consumerId, originalOAuthCredentialId: g.credentialId, serviceId: g.serviceId ?? null, routeId: g.routeId ?? null,
      pluginId: g.pluginId ?? null, checks: g.checks.filter(item => item.stage === stage), authEndpointValidation: g.authEndpointValidation,
      requests: packets.map(packet => ({ method: packet.method, path: packet.path.split('?')[0], key: packet.key, state: packet.state,
        status: packet.status, requestId: packet.requestId, requestHmac: hmac(packet.body), responseHmac: hmac(packet.responseData ?? null) })),
      httpsProbes: g.proxyPackets.filter(packet => packet.label.startsWith(`${stage}-`)).map(packet => ({ label: packet.label, key: packet.key,
        method: packet.method, state: packet.state, status: packet.status ?? null, tlsAuthorized: packet.tlsAuthorized === true,
        requestHmac: hmac({ path: packet.path, headers: packet.headers, form: packet.form ?? null }), responseHmac: hmac(packet.responseData ?? null) })),
      credentialValuesRecorded: false, tokenValuesRecorded: false, provisionKeyRecorded: false, sessionCookiesRecorded: false,
      directAdminRequestsSent: 0, tokenAdminRequestsSent: 0, proxyRevokeEndpointRequestsSent: 0, tlsVerificationBypassed: false,
      limitations: ['Root must provide an independently trusted published business HTTPS endpoint and fresh actual sessions.',
        'TLS requests have explicit CA/SNI and verified sockets; POST requests never retry or follow redirects.',
        'Client revocation deletes the OAuth credential through a separate approved recycle workflow; tokens/codes cascade and are not part of its restorable archive.',
        'Restoring the original client ID/secret must leave previous tokens invalid; a new grant is required.',
        'Global-plugin checks enumerate console workspaces; Root must separately verify unclassified or deleted-workspace interference.',
        'This isolated protocol probe does not prove browser UI, HA, all-cluster inventory or complete M11 acceptance.'],
      ...(!passed ? { errorCode: 'M11_RESTORED_OAUTH2_HTTPS_STOPPED_NO_REPLAY' } : {}) };
    mkdirSync(dirname(reportPath), { recursive: true }); writeFileSync(reportPath, JSON.stringify(output, null, 2) + '\n', { flag: 'wx' });
  }
  async function originalCredential(expectedPresent) {
    const page = (await read(scope(`consumers/${seed.consumerId}/credentials/oauth2`, { size: '20' }))).data;
    assert(Array.isArray(page.items) && !page.nextCursor, 'COMPLETE_ORIGINAL_OAUTH_CREDENTIAL_PAGE_REQUIRED');
    assert.deepEqual(page.items.map(item => item.id), expectedPresent ? [g.credentialId] : [], 'EXACT_ORIGINAL_OAUTH_CREDENTIAL_PRESENCE_REQUIRED');
    if (!expectedPresent) { await read(scope(`consumers/${seed.consumerId}/credentials/oauth2/${g.credentialId}`), { expected: [404] }); return; }
    const actual = (await read(scope(`consumers/${seed.consumerId}/credentials/oauth2/${g.credentialId}`, { reveal: 'true' }))).data.entity;
    assert.equal(actual.id, g.credentialId); assert.equal(referenceId(actual.consumer), g.consumerId);
    for (const [field, value] of Object.entries(seed.sourceInputs.oauth2)) assert.equal(hmac(actual[field]), hmac(value), 'EXACT_ORIGINAL_PRIVATE_OAUTH_CLIENT_CUSTODY_REQUIRED');
  }
  async function prerequisites() {
    const cluster = (await read(`/clusters/${cid}`)).data;
    assert.equal(cluster.execution_mode, 'approval'); assert(/^1\.5\.\d+$/.test(cluster.version) && cluster.enabled_plugins?.includes('oauth2'), 'ACTUAL_KONG15_OAUTH2_REQUIRED');
    const workspace = (await read(`/clusters/${cid}/workspaces/${wid}`)).data;
    assert.equal(workspace.status, 'active'); assert.equal(workspace.code, seed.workspaceCode); assert.equal(workspace.cluster_id, cid);
    const definitions = (await read(scope('workflow-definitions', { size: '100' }))).data;
    assert(Array.isArray(definitions.items) && !definitions.nextCursor, 'COMPLETE_ACTUAL_APPROVAL_POLICY_REQUIRED');
    const native = definitions.items.filter(item => item.kind === 'native-change' && item.status === 'active'); assert.equal(native.length, 1);
    const policy = native[0].policy; assert.equal(native[0].format, 2); assert.equal(policy.version, 2);
    assert.equal(policy.kind, 'native-change'); assert.equal(policy.allowSelfApproval, false); assert.equal(policy.distinctAcrossStages, true); assert.equal(policy.stages.length, 2);
    assert.equal(policy.stages[0].mode, 'any'); assert.equal(policy.stages[0].threshold, 1); assert.deepEqual(policy.stages[0].selector, { users: [subjects.a] });
    assert.equal(policy.stages[1].mode, 'all'); assert.equal(policy.stages[1].threshold, null); assert.deepEqual(Object.keys(policy.stages[1].selector), ['users']);
    assert.deepEqual([...policy.stages[1].selector.users].sort(), [subjects.b, subjects.c].sort());
    const archiveId = seed.intents?.['delete-consumer']?.entryId; assert(uuid(archiveId));
    const archive = (await read(scope('recycle-bin', { type: 'consumers', search: seed.consumerId, size: '20' }))).data;
    assert(Array.isArray(archive.items) && !archive.nextCursor); const entry = archive.items.find(item => item.id === archiveId);
    assert(entry?.state === 'restored' && entry.node_count === 7 && entry.original_id === seed.consumerId, 'ORIGINAL_SEVEN_NODE_CONSUMER_RESTORE_REQUIRED');
    const consumer = (await read(scope(`entities/consumers/${g.consumerId}`))).data.entity;
    assert.equal(consumer.username, seed.sourceInputs.consumer.username); assert.equal(consumer.custom_id, seed.sourceInputs.consumer.custom_id);
    for (const kind of ['key-auth', 'basic-auth', 'jwt', 'hmac-auth', 'acls']) {
      const page = (await read(scope(`consumers/${g.consumerId}/credentials/${kind}`, { size: '20' }))).data;
      assert(Array.isArray(page.items) && !page.nextCursor); assert.deepEqual(page.items.map(item => item.id), [seed.credentialIds[kind]], 'OTHER_RESTORED_CREDENTIAL_IDS_MUST_REMAIN_UNCHANGED');
    }
    await originalCredential(stage !== 'restore-client');
    const workspaces = (await read(`/clusters/${cid}/workspaces?size=100`)).data;
    assert(Array.isArray(workspaces.items) && !workspaces.nextCursor);
    for (const current of workspaces.items) {
      assert(uuid(current.id) && ['active', 'disabled'].includes(current.status));
      const globals = (await read(releaseScope(cid, current.id, 'plugin-center/instances', { binding_scope: 'global', size: '100' }))).data;
      assert(Array.isArray(globals.items) && !globals.nextCursor && globals.items.every(item => item.enabled === false || item.name === 'prometheus'), 'GLOBAL_AUTH_INTERFERENCE_BLOCKS_OAUTH_PROBES');
    }
    const bindings = (await read(scope(`entities/consumers/${g.consumerId}/relations/plugins`, { size: '100' }))).data;
    assert(Array.isArray(bindings.items) && !bindings.nextCursor && bindings.items.every(item => item.enabled === false), 'CONSUMER_PLUGIN_INTERFERENCE_BLOCKS_OAUTH_PROBES');
    check('Original restored Consumer B, OAuth custody, unchanged sibling IDs and actual three-reviewer policy verified');
  }
  async function approved(label, change, type, action, status) {
    assert(!g.intents[label], 'INDEPENDENT_OAUTH_INTENT_REQUIRED'); const record = g.intents[label] = { body: { change } }; h.save();
    const intent = await once(`${label}-prepare`, scope('entity-changes/prepare'), record.body);
    assert(uuid(intent.id) && intent.review.impact.nativePackets === 1 && intent.review.changes.length === 1);
    assert.equal(intent.review.changes[0].entityType, type); assert.equal(intent.review.changes[0].action, action); assert(uuid(intent.review.changes[0].nativeId));
    record.id = intent.id; record.receipt = intent; h.save();
    const submitted = await once(`${label}-submit`, scope(`entity-changes/${intent.id}/submit`), { revision: intent.revision, materialHmac: intent.materialHmac, confirmed: true, confirm_name: 'native-change' });
    assert(uuid(submitted.workflowId) && !Object.values(g.intents).some(item => item !== record && item.workflowId === submitted.workflowId));
    record.workflowId = submitted.workflowId; h.save();
    for (const [index, actor] of ['a', 'b', 'c'].entries()) {
      const before = (await read(scope(`workflows/${record.workflowId}`))).data.entity; assert.equal(before.state, 'pending'); assert.equal(before.approval.format, 2);
      const active = before.approval.stages.find(item => item.state === 'active'); assert(active); assert.equal(active.level, index === 0 ? 1 : 2);
      await once(`${label}-vote-${actor}`, scope(`workflows/${record.workflowId}/approve`), { revision: before.revision, planHash: before.planHash,
        confirmed: true, confirm_name: 'native-change', execute: false, level: active.level, stageRevision: active.revision, candidateVersion: before.approval.candidateVersion }, actor);
      const after = (await read(scope(`workflows/${record.workflowId}`))).data.entity;
      assert.equal(after.state, index === 2 ? 'approved' : 'pending'); assert.equal(after.approval.stages.reduce((total, item) => total + item.votes, 0), index + 1);
    }
    const approvedWorkflow = (await read(scope(`workflows/${record.workflowId}`))).data.entity;
    assert.equal(approvedWorkflow.state, 'approved'); assert.equal(approvedWorkflow.capabilities.execute, true);
    assert(uuid(approvedWorkflow.approval.approvalSetId) && !Object.values(g.intents).some(item => item !== record && item.approvalSetId === approvedWorkflow.approval.approvalSetId));
    record.approvalSetId = approvedWorkflow.approval.approvalSetId; h.save();
    const execution = await once(`${label}-execute`, scope(`workflows/${record.workflowId}/execute`), { revision: approvedWorkflow.revision, planHash: approvedWorkflow.planHash, confirmed: true, confirm_name: 'native-change' });
    record.executionId = execution.executionId; record.executionReceipt = execution; h.save(); assert.equal(execution.state, 'succeeded'); assert(uuid(execution.baselineId));
    const detail = (await read(scope(`workflows/${record.workflowId}`))).data;
    assert.equal(detail.entity.state, 'succeeded'); assert.equal(detail.nativeChange.packets.length, 1);
    assert.equal(detail.nativeChange.packets[0].state, 'succeeded'); assert.equal(detail.nativeChange.packets[0].nativeStatus, status);
    assert.equal(detail.nativeChange.baseline.nativeAuthority, false); assert.equal(detail.nativeChange.baseline.baseline.baselineId, execution.baselineId);
    check(`Dedicated ${label} executed by admin after three actual votes`, { workflowId: record.workflowId, executionId: record.executionId, nativePackets: 1, nativeStatus: status });
    return intent.review.changes[0];
  }
  async function verifyFixtures() {
    assert(uuid(g.serviceId) && uuid(g.routeId) && uuid(g.pluginId), 'DEDICATED_APPROVED_OAUTH_FIXTURE_REQUIRED');
    const original = (await read(scope(`entities/services/${g.originalServiceId}`))).data.entity; assert.equal(hmac(original), g.originalServiceHmac);
    const service = (await read(scope(`entities/services/${g.serviceId}`))).data.entity;
    for (const [field, value] of Object.entries(g.serviceBody)) assert.equal(hmac(field === 'tags' ? [...service[field]].sort() : service[field]), hmac(field === 'tags' ? [...value].sort() : value));
    const servicePlugins = (await read(scope(`entities/services/${g.serviceId}/relations/plugins`, { size: '100' }))).data;
    assert(Array.isArray(servicePlugins.items) && !servicePlugins.nextCursor && servicePlugins.items.length === 0, 'DEDICATED_SERVICE_HAS_NO_PLUGIN_BINDING');
    const route = (await read(scope(`entities/routes/${g.routeId}`))).data.entity;
    assert.equal(referenceId(route.service), g.serviceId); assert.deepEqual(route.hosts, [tls.servername]); assert.deepEqual(route.protocols, ['https']);
    assert.deepEqual(route.paths, g.routeBody.paths); assert.equal(route.strip_path, false);
    const bound = (await read(scope(`entities/routes/${g.routeId}/relations/plugins`, { size: '100' }))).data;
    assert(Array.isArray(bound.items) && !bound.nextCursor); assert.deepEqual(bound.items.map(item => item.id), [g.pluginId]);
    const plugin = (await read(scope(`entities/plugins/${g.pluginId}`, { reveal: 'true' }))).data.entity;
    assert.equal(plugin.name, 'oauth2'); assert.equal(plugin.enabled, true); assert.deepEqual(plugin.protocols, ['https']);
    assert.equal(referenceId(plugin.route), g.routeId); assert(!referenceId(plugin.service) && !referenceId(plugin.consumer), 'ROUTE_ONLY_OAUTH_PLUGIN_REQUIRED');
    for (const [field, value] of Object.entries(g.pluginBody.config)) assert.equal(hmac(plugin.config[field]), hmac(value), 'EXACT_PRIVATE_OAUTH_PLUGIN_CONFIG_REQUIRED');
  }
  async function issue(label) {
    const state = randomBytes(32).toString('hex'); g.authorizationStates ??= {}; assert(!g.authorizationStates[label]); g.authorizationStates[label] = state; h.save();
    const form = restoredOAuthAuthorizationForm(seed.sourceInputs.oauth2, g.provisionKey, g.consumerId, state);
    const authorized = await send(`${label}-authorize`, { method: 'POST', path: `${g.routeBody.paths[0]}/oauth2/authorize`, form, expected: [200] });
    const code = restoredOAuthAuthorizationCode(authorized.body, seed.sourceInputs.oauth2, state);
    const response = await send(`${label}-token`, { method: 'POST', path: `${g.routeBody.paths[0]}/oauth2/token`, form: {
      grant_type: 'authorization_code', client_id: seed.sourceInputs.oauth2.client_id, client_secret: seed.sourceInputs.oauth2.client_secret,
      redirect_uri: seed.sourceInputs.oauth2.redirect_uris[0], code }, expected: [200] });
    const token = restoredOAuthToken(response.body); g.tokens ??= {}; assert(!g.tokens[label]); g.tokens[label] = token; h.save(); return token;
  }
  async function invalidRefresh(label, token) {
    const response = await send(label, { method: 'POST', path: `${g.routeBody.paths[0]}/oauth2/token`, form: { grant_type: 'refresh_token',
      client_id: seed.sourceInputs.oauth2.client_id, client_secret: seed.sourceInputs.oauth2.client_secret,
      redirect_uri: seed.sourceInputs.oauth2.redirect_uris[0], refresh_token: token.refresh_token }, expected: [400] });
    assert(['invalid_request', 'invalid_client'].includes(response.body.error), 'REAL_REVOKED_REFRESH_REJECTION_REQUIRED');
  }
  try {
    await prerequisites();
    if (stage === 'create-probes') {
      const originalId = h.state.gate2?.fixtures?.service?.id; assert(uuid(originalId));
      const original = (await read(scope(`entities/services/${originalId}`))).data.entity;
      assert(['http', 'https'].includes(original.protocol) && typeof original.host === 'string' && Number.isSafeInteger(original.port), 'ACTUAL_SAFE_ECHO_UPSTREAM_REQUIRED');
      const tags = [`workspace:${seed.workspaceCode}`, 'team:m11-acceptance', 'owner:m11-acceptance'];
      g.originalServiceId = originalId; g.originalServiceHmac = hmac(original); g.serviceBody = { name: `m11-oauth2-${g.fixtureSuffix}`, path: null, tags };
      for (const field of ['protocol', 'host', 'port', 'retries', 'connect_timeout', 'write_timeout', 'read_timeout']) if (Object.hasOwn(original, field)) g.serviceBody[field] = original[field]; h.save();
      g.serviceId = (await approved('service', { kind: 'entity', action: 'create', entityType: 'services', body: g.serviceBody }, 'services', 'create', 201)).nativeId; h.save();
      g.routeBody = { name: `m11-oauth2-${g.fixtureSuffix}`, service: { id: g.serviceId }, protocols: ['https'], hosts: [tls.servername],
        paths: [`/m11-oauth2-${g.fixtureSuffix}`], strip_path: false, tags }; h.save();
      g.routeId = (await approved('route', { kind: 'entity', action: 'create', entityType: 'routes', body: g.routeBody }, 'routes', 'create', 201)).nativeId; h.save();
      g.pluginBody = { name: 'oauth2', enabled: true, route: { id: g.routeId }, protocols: ['https'], tags, config: {
        scopes: ['m11-read'], mandatory_scope: true, provision_key: g.provisionKey, token_expiration: 3600,
        enable_authorization_code: true, enable_implicit_grant: false, enable_client_credentials: false, enable_password_grant: false,
        hide_credentials: true, accept_http_if_already_terminated: false, global_credentials: false, auth_header_name: 'authorization', refresh_token_ttl: 3600 } }; h.save();
      const schema = (await read(scope('plugin-schemas/oauth2'))).data, fields = fieldMap(schema), configFields = fields?.config ? fieldMap(fields.config) : fields;
      assert(configFields && Object.keys(g.pluginBody.config).every(field => Object.hasOwn(configFields, field)), 'ACTUAL_KONG15_OAUTH_SCHEMA_FIELDS_REQUIRED');
      g.pluginId = (await approved('plugin', { kind: 'entity', action: 'create', entityType: 'plugins', body: g.pluginBody }, 'plugins', 'create', 201)).nativeId; h.save();
      await verifyFixtures(); g.probesNotBefore = new Date(Date.now() + 5000).toISOString(); h.save();
      check('Dedicated HTTPS Route-only OAuth2 plugin uses provisioned authorization-code grant without HTTP termination bypass');
    } else {
      assert(Date.now() >= Date.parse(g.probesNotBefore), 'INITIAL_CONFIGURATION_PROPAGATION_WAIT_REQUIRED'); await verifyFixtures();
      if (stage === 'issue-refresh') {
        await poll('missing-token', undefined, 401); await poll('invalid-token', g.wrongToken, 401);
        const first = await issue('original'); restoredOAuthUnexpired(first); await poll('original-access-positive', first.access_token, 200);
        const response = await send('refresh-original-once', { method: 'POST', path: `${g.routeBody.paths[0]}/oauth2/token`, form: {
          grant_type: 'refresh_token', client_id: seed.sourceInputs.oauth2.client_id, client_secret: seed.sourceInputs.oauth2.client_secret,
          redirect_uri: seed.sourceInputs.oauth2.redirect_uris[0], refresh_token: first.refresh_token }, expected: [200] });
        g.tokens.refreshed = restoredOAuthToken(response.body, first); h.save(); await poll('refreshed-access-positive', g.tokens.refreshed.access_token, 200);
        restoredOAuthUnexpired(first); await poll('old-access-invalidated-by-refresh', first.access_token, 401); await invalidRefresh('old-refresh-reuse-rejected', first);
        g.authEndpointValidation = 'actual-HTTPS-code-access-negative-refresh-passed-revocation-pending';
        check('Actual verified HTTPS authorization-code, token, Consumer identity, negative access and single-use rotating refresh chain passed');
      } else if (stage === 'revoke-client') {
        assert(g.tokens?.refreshed && uuid(g.credentialId)); restoredOAuthUnexpired(g.tokens.refreshed);
        await poll('pre-revoke-current-access', g.tokens.refreshed.access_token, 200);
        const changed = await approved('revoke-client', { kind: 'recycle', action: 'delete', entityType: 'credentials', entityId: g.credentialId,
          parentId: g.consumerId, credentialKind: 'oauth2', confirmed: true, confirm_name: seed.sourceInputs.oauth2.name }, 'oauth2', 'delete', 204);
        assert.equal(changed.nativeId, g.credentialId); await originalCredential(false);
        const archive = (await read(scope('recycle-bin', { type: 'credentials', search: g.credentialId, size: '20' }))).data;
        assert(Array.isArray(archive.items) && !archive.nextCursor);
        const matches = archive.items.filter(item => item.original_id === g.credentialId && item.state === 'deleted' && item.parent_id === g.consumerId
          && item.credential_kind === 'oauth2' && item.mutation_id === null); assert.equal(matches.length, 1);
        assert.equal(matches[0].node_count, 2, 'ONE_OAUTH_CREDENTIAL_AND_CONTEXT_ONLY_CONSUMER_ARCHIVE_REQUIRED');
        g.revocationEntryId = matches[0].id; g.revocationEntryName = matches[0].root_name;
        assert(uuid(g.revocationEntryId)); assert.equal(g.revocationEntryName, seed.sourceInputs.oauth2.name); h.save();
        restoredOAuthUnexpired(g.tokens.refreshed); await poll('revoked-access-denied', g.tokens.refreshed.access_token, 401);
        await invalidRefresh('revoked-refresh-denied', g.tokens.refreshed);
        g.authEndpointValidation = 'actual-HTTPS-chain-and-client-revocation-passed-original-client-restore-pending';
        check('Separate three-vote credential recycle revoked the issued OAuth access and refresh tokens; no token Admin API used');
      } else {
        assert(uuid(g.revocationEntryId) && g.tokens?.refreshed); restoredOAuthUnexpired(g.tokens.refreshed);
        const changed = await approved('restore-client', { kind: 'recycle', action: 'restore', entryId: g.revocationEntryId,
          confirmed: true, confirm_name: g.revocationEntryName }, 'oauth2', 'restore', 201);
        assert.equal(changed.nativeId, g.credentialId); await originalCredential(true);
        const archive = (await read(scope('recycle-bin', { type: 'credentials', search: g.credentialId, size: '20' }))).data;
        assert(Array.isArray(archive.items) && !archive.nextCursor); assert.equal(archive.items.find(item => item.id === g.revocationEntryId)?.state, 'restored');
        restoredOAuthUnexpired(g.tokens.refreshed); await poll('old-token-remains-revoked-after-client-restore', g.tokens.refreshed.access_token, 401);
        await invalidRefresh('old-refresh-remains-revoked-after-client-restore', g.tokens.refreshed);
        // A GET denial of an old, deleted token cannot prove that the restored
        // client-ID cache is fresh. Wait once for DB cache propagation, then
        // send the new authorize/token POST originals exactly once.
        await new Promise(pause => setTimeout(pause, 5000));
        const fresh = await issue('after-client-restore'); await poll('new-grant-after-original-client-restore-positive', fresh.access_token, 200);
        g.authEndpointValidation = 'actual-HTTPS-code-access-negative-refresh-client-revoke-original-ID-restore-new-grant-passed';
        check('Original OAuth client ID/secret restored; old tokens remain revoked and a new code grant authenticates the restored Consumer');
      }
    }
    g.stages[stage] = { state: 'succeeded', finishedAt: new Date().toISOString() }; h.state.phase = `m11-restored-oauth2-https-${stage}-complete`; h.save(); report(true);
    console.log(JSON.stringify({ passed: true, stage, overallM11Accepted: false, credentialValuesRecorded: false, tokenValuesRecorded: false }));
  } catch {
    g.stages[stage] = { state: 'stopped-no-replay', finishedAt: new Date().toISOString() }; h.state.phase = `m11-restored-oauth2-https-${stage}-stopped`; h.save(); report(false);
    throw Error('M11_RESTORED_OAUTH2_HTTPS_STOPPED_NO_REPLAY');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main().catch(() => {
  console.error('M11_RESTORED_OAUTH2_HTTPS_STOPPED_NO_REPLAY'); process.exitCode = 1;
});
