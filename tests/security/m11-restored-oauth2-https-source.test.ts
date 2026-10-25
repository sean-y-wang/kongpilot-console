// @ts-nocheck -- isolated source harness tests; HTTPS is an EventEmitter mock.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';

const transport = vi.hoisted(() => ({ request: vi.fn(), authorized: true, status: 200, body: {}, observe: null, failure: false }));
const harness = vi.hoisted(() => ({ constructor: vi.fn(() => { throw Error('SOURCE_TEST_MUST_NOT_OPEN_PRIVATE_LEDGER'); }) }));
vi.mock('node:https', () => ({ request: (...args) => transport.request(...args) }));
vi.mock('./lib/release-harness.mjs', () => ({ ReleaseHarness: harness.constructor,
  releaseScope: (cid, wid, path) => `/clusters/${cid}/${path}?workspaceId=${wid}` }));
import { restoredOAuthRequiresTLS, restoredOAuthAuthorizationForm, restoredOAuthAuthorizationCode, restoredOAuthToken,
  restoredOAuthUnexpired, restoredOAuthHttpsOnce, restoredOAuthPollGet } from './m11-restored-oauth2-https-probes.mjs';

const publicCA = `-----BEGIN CERTIFICATE-----\n${'U291cmNlT25seVN5bnRoZXRpY0NB'.repeat(8)}\n-----END CERTIFICATE-----\n`;
const env = { RELEASE_LAB_M11_RESTORED_OAUTH2_HTTPS_PROBES_READY: 'true', RELEASE_LAB_OAUTH2_HTTPS_ORIGIN: 'https://127.0.0.1:58443',
  RELEASE_LAB_OAUTH2_TLS_SERVERNAME: 'm11-oauth2.synthetic.invalid', RELEASE_LAB_OAUTH2_TLS_BASE_DIRECTORY: '/tmp/public-only-ca' };
const client = () => ({ client_id: randomUUID(), client_secret: 'SyntheticClientSecret'.repeat(3), redirect_uris: ['https://callback.synthetic.invalid/oauth/callback'] });
const token = () => ({ access_token: `SyntheticAccess-${randomUUID()}`, refresh_token: `SyntheticRefresh-${randomUUID()}`, token_type: 'bearer', expires_in: 3600 });
function fixture() {
  const g = { proxyPackets: [] }, h = { state: { requests: [] }, save: vi.fn(), assertWritable: vi.fn() }, tls = restoredOAuthRequiresTLS(env, publicCA);
  return { h, g, tls, path: `/m11-oauth2-${randomUUID()}` };
}

beforeEach(() => {
  transport.authorized = true; transport.status = 200; transport.body = { ...token() }; transport.observe = null; transport.failure = false;
  transport.request.mockReset().mockImplementation((options, callback) => {
    transport.observe?.(options);
    const request = new EventEmitter(); request.setTimeout = vi.fn(); request.destroy = vi.fn(error => queueMicrotask(() => request.emit('error', error)));
    request.end = vi.fn(body => queueMicrotask(() => {
      if (transport.failure) { request.emit('error', Error('SyntheticNetworkFailure')); return; }
      const response = new EventEmitter(); response.socket = { authorized: transport.authorized }; response.statusCode = transport.status;
      response.destroy = vi.fn(); callback(response); response.emit('data', Buffer.from(JSON.stringify(transport.body))); response.emit('end');
    }));
    return request;
  });
});

describe('OAuth2 source-only HTTPS prerequisites', () => {
  it('does not instantiate a harness, read its private state or open a transport when imported', () => {
    expect(harness.constructor).not.toHaveBeenCalled(); expect(transport.request).not.toHaveBeenCalled();
  });
  it('requires explicit Root gate, verified business HTTPS, exact DNS SNI and an explicit public CA directory', () => {
    expect(restoredOAuthRequiresTLS(env, publicCA)).toMatchObject({ requiresTLS: true, hostname: '127.0.0.1', port: 58443,
      servername: env.RELEASE_LAB_OAUTH2_TLS_SERVERNAME, rejectUnauthorized: true, ca: publicCA, caFile: '/tmp/public-only-ca/ca.pem' });
    expect(Object.isFrozen(restoredOAuthRequiresTLS(env, publicCA))).toBe(true);
  });
  it.each(['http://127.0.0.1:58443', 'https://127.0.0.1:8001', 'https://127.0.0.1:8444', 'https://127.0.0.1:5445',
    'https://public.example:8443', 'https://127.0.0.1:8443/admin', 'https://127.0.0.1:8443?token=secret',
    'https://user:secret@127.0.0.1:8443', 'https://127.0.0.1', 'https://127.0.0.1:8443#fragment'])('rejects unapproved origin %s', origin => {
    expect(() => restoredOAuthRequiresTLS({ ...env, RELEASE_LAB_OAUTH2_HTTPS_ORIGIN: origin }, publicCA)).toThrow();
  });
  it.each(['127.0.0.1', '*.invalid', 'a..invalid', 'https://sni.invalid', 'sni.invalid\r\nX-Forwarded-Proto: https'])('rejects SNI %s', servername => {
    expect(() => restoredOAuthRequiresTLS({ ...env, RELEASE_LAB_OAUTH2_TLS_SERVERNAME: servername }, publicCA)).toThrow();
  });
  it('rejects missing execution authorization, relative CA roots and private key material before transport', () => {
    expect(() => restoredOAuthRequiresTLS({ ...env, RELEASE_LAB_M11_RESTORED_OAUTH2_HTTPS_PROBES_READY: 'false' }, publicCA)).toThrow();
    expect(() => restoredOAuthRequiresTLS({ ...env, RELEASE_LAB_OAUTH2_TLS_BASE_DIRECTORY: 'relative-ca' }, publicCA)).toThrow();
    expect(() => restoredOAuthRequiresTLS(env, publicCA + '-----BEGIN PRIVATE KEY-----')).toThrow();
    expect(() => restoredOAuthRequiresTLS(env, 'untrusted')).toThrow();
    expect(transport.request).not.toHaveBeenCalled();
  });
});

describe('OAuth2 1.5 authorization-code and rotating token material', () => {
  it('uses original client redirect/ID, explicit provisioning authority and restored Consumer UUID', () => {
    const c = client(), consumerId = randomUUID(), provision = 'SyntheticProvision'.repeat(3), state = 'SyntheticState'.repeat(3);
    expect(restoredOAuthAuthorizationForm(c, provision, consumerId, state)).toEqual({ response_type: 'code', client_id: c.client_id,
      redirect_uri: c.redirect_uris[0], provision_key: provision, authenticated_userid: consumerId, scope: 'm11-read', state });
  });
  it('parses only the original callback code/state without following or accepting a foreign callback', () => {
    const c = client(), state = 'SyntheticState'.repeat(3), code = 'SyntheticCode'.repeat(3);
    expect(restoredOAuthAuthorizationCode({ redirect_uri: `${c.redirect_uris[0]}?code=${code}&state=${state}` }, c, state)).toBe(code);
    for (const callback of ['https://foreign.invalid/oauth/callback', 'https://callback.synthetic.invalid/foreign']) {
      expect(() => restoredOAuthAuthorizationCode({ redirect_uri: `${callback}?code=${code}&state=${state}` }, c, state)).toThrow();
    }
    expect(() => restoredOAuthAuthorizationCode({ redirect_uri: `${c.redirect_uris[0]}?code=${code}&state=wrong` }, c, state)).toThrow();
    expect(() => restoredOAuthAuthorizationCode({ redirect_uri: `${c.redirect_uris[0]}?code=${code}&state=${state}&error=denied` }, c, state)).toThrow();
    expect(() => restoredOAuthAuthorizationCode({ redirect_uri: `${c.redirect_uris[0]}?code=${code}&code=${code}&state=${state}` }, c, state)).toThrow();
  });
  it('requires both a finite-expiry bearer and refresh token; a refresh cannot reuse either previous token', () => {
    const previous = token(), fresh = token(); expect(restoredOAuthToken(fresh, previous)).toMatchObject(fresh);
    expect(() => restoredOAuthToken({ ...fresh, access_token: previous.access_token }, previous)).toThrow();
    expect(() => restoredOAuthToken({ ...fresh, refresh_token: previous.refresh_token }, previous)).toThrow();
    expect(() => restoredOAuthToken({ ...fresh, refresh_token: undefined })).toThrow();
    expect(() => restoredOAuthToken({ ...fresh, expires_in: 0 })).toThrow();
    expect(() => restoredOAuthToken({ ...fresh, expires_in: 7201 })).toThrow();
  });
  it('prevents natural token expiry from being claimed as revocation or non-resurrection proof', () => {
    const issued = { ...token(), receivedAt: new Date(1_000_000).toISOString() };
    expect(() => restoredOAuthUnexpired(issued, 1_100_000)).not.toThrow();
    expect(() => restoredOAuthUnexpired(issued, 1_000_000 + 3600_000 - 120_000)).toThrow();
    expect(() => restoredOAuthUnexpired(issued, 999_999)).toThrow();
    expect(() => restoredOAuthUnexpired({ ...issued, receivedAt: 'unknown' }, 1_100_000)).toThrow();
  });
});

describe('original verified HTTPS request custody and no-replay boundary', () => {
  it('durably records one private original form before physical transport and verifies socket trust', async () => {
    const f = fixture(), form = { grant_type: 'authorization_code', client_id: randomUUID(), client_secret: 'SyntheticPrivateClientSecret', code: 'SyntheticPrivateCode' };
    let prepared; transport.observe = options => { prepared = structuredClone(f.g.proxyPackets[0]);
      expect(f.h.state.requests[0]).toMatchObject({ transport: 'business-https', state: 'prepared', body: form }); expect(options).toMatchObject({
      hostname: '127.0.0.1', port: 58443, servername: f.tls.servername, ca: publicCA, rejectUnauthorized: true,
      method: 'POST', path: `${f.path}/oauth2/token`, headers: { host: f.tls.servername, 'content-type': 'application/x-www-form-urlencoded' } });
      expect(options.headers['x-forwarded-proto']).toBeUndefined(); expect(f.h.save).toHaveBeenCalled(); };
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'token-original', f.tls, { method: 'POST', path: `${f.path}/oauth2/token`, form, expected: [200] })).resolves.toMatchObject({ status: 200 });
    expect(prepared).toMatchObject({ state: 'prepared', method: 'POST', form, tls: true, rejectUnauthorized: true });
    expect(f.g.proxyPackets[0]).toMatchObject({ state: 'response_observed', status: 200, tlsAuthorized: true });
    expect(f.h.state.requests[0]).toMatchObject({ transport: 'business-https', state: 'response_observed', status: 200, tlsAuthorized: true });
    expect(f.h.state.requests[0].requestId).toBeUndefined(); expect(f.h.state.requests[0].nativeStatus).toBeUndefined();
    expect(transport.request).toHaveBeenCalledTimes(1);
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'token-original', f.tls, { method: 'POST', path: `${f.path}/oauth2/token`, form, expected: [200] })).rejects.toThrow('NO_REPLAY');
    expect(transport.request).toHaveBeenCalledTimes(1);
  });
  it.each(['authorize', 'token'])('never retries an observed rejected %s POST', async endpoint => {
    const f = fixture(); transport.status = 400; transport.body = { error: 'invalid_client' };
    const input = { method: 'POST', path: `${f.path}/oauth2/${endpoint}`, form: { client_id: randomUUID() }, expected: [200] };
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'original-rejected', f.tls, input)).rejects.toThrow('MISMATCH_NO_REPLAY');
    expect(f.g.proxyPackets[0]).toMatchObject({ state: 'response_observed', status: 400 });
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'original-rejected', f.tls, input)).rejects.toThrow('NO_REPLAY');
    expect(transport.request).toHaveBeenCalledTimes(1);
  });
  it.each(['unauthorizedTLS', 'networkError'])('retains unknown original %s and blocks every further request, including new labels', async failure => {
    const f = fixture(); transport.authorized = failure !== 'unauthorizedTLS'; transport.failure = failure === 'networkError';
    const input = { method: 'POST', path: `${f.path}/oauth2/token`, form: { client_id: randomUUID() }, expected: [200] };
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'unknown-original', f.tls, input)).rejects.toThrow();
    expect(f.g.proxyPackets[0]).toMatchObject({ state: 'response_unknown', errorCode: 'OAUTH_HTTPS_RESPONSE_UNKNOWN' });
    expect(f.h.state.requests[0]).toMatchObject({ transport: 'business-https', state: 'response_unknown' });
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'new-label-cannot-retry', f.tls, input)).rejects.toThrow('UNKNOWN_STOPS');
    expect(transport.request).toHaveBeenCalledTimes(1);
  });
  it('exposes an unknown business POST to the genuine ReleaseHarness global guard without instantiating it', async () => {
    const f = fixture(); transport.failure = true;
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'unknown-global', f.tls, { method: 'POST', path: `${f.path}/oauth2/token`, form: { client_id: randomUUID() }, expected: [200] })).rejects.toThrow();
    const actual = await vi.importActual('./lib/release-harness.mjs');
    expect(() => actual.ReleaseHarness.prototype.assertWritable.call({ state: f.h.state })).toThrow('ORIGINAL_UNRESOLVED_RELEASE_WRITE_NO_REPLAY');
    expect(harness.constructor).not.toHaveBeenCalled();
  });
  it('never gives a POST 5xx a known-no-native-send read exemption', async () => {
    const f = fixture(); transport.status = 503; transport.body = { message: 'SyntheticError' };
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'post-503', f.tls, { method: 'POST', path: `${f.path}/oauth2/token`, form: { client_id: randomUUID() }, expected: [200] })).rejects.toThrow('MISMATCH');
    const actual = await vi.importActual('./lib/release-harness.mjs');
    expect(f.h.state.requests[0].resolution).toBeUndefined();
    expect(() => actual.ReleaseHarness.prototype.assertWritable.call({ state: f.h.state })).toThrow('UNRESOLVED');
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'post-503-new-label', f.tls, { method: 'POST', path: `${f.path}/oauth2/token`, form: { client_id: randomUUID() }, expected: [200] })).rejects.toThrow('UNKNOWN_STOPS');
  });
  it('records a complete business GET 500 as a read observation and allows a new bounded GET without weakening POST or unknown guards', async () => {
    const f = fixture(); transport.status = 500; transport.body = { message: 'SyntheticCredentialCacheWindow' };
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'read-cache-window', f.tls, { method: 'GET', path: f.path, expected: [500] })).resolves.toMatchObject({ status: 500 });
    const actual = await vi.importActual('./lib/release-harness.mjs');
    expect(() => actual.ReleaseHarness.prototype.assertWritable.call({ state: f.h.state })).not.toThrow();
    expect(f.h.state.requests[0]).toMatchObject({ method: 'GET', resolution: { knownNoNativeSend: true } });
    transport.status = 401; transport.body = { error: 'invalid_token' };
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'read-after-cache-window', f.tls, { method: 'GET', path: f.path, expected: [401] })).resolves.toMatchObject({ status: 401 });
    expect(transport.request).toHaveBeenCalledTimes(2);
    f.h.state.requests[0].resolution.knownNoNativeSend = false;
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'tampered-read-exemption', f.tls, { method: 'GET', path: f.path, expected: [401] })).rejects.toThrow('GLOBAL_OAUTH_MARKER_CHANGED');
  });
  it('cannot bypass an existing BFF unknown mutation to start OAuth issuance', async () => {
    const f = fixture(); f.h.assertWritable.mockImplementation(() => { throw Error('ROOT_MUTATION_UNKNOWN'); });
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'no-bypass', f.tls, { method: 'POST', path: `${f.path}/oauth2/token`, form: { client_id: randomUUID() }, expected: [200] })).rejects.toThrow('ROOT_MUTATION_UNKNOWN');
    expect(transport.request).not.toHaveBeenCalled(); expect(f.g.proxyPackets).toHaveLength(0);
  });
  it.each(['tlsSkip', 'adminOrigin', 'forwardedProto', 'proxyRevoke', 'queryToken', 'tokenGet'])('rejects %s before allocating a proxy packet', async tamper => {
    const f = fixture(), input = { method: 'GET', path: f.path, expected: [401] }, tls = { ...f.tls };
    if (tamper === 'tlsSkip') tls.rejectUnauthorized = false;
    else if (tamper === 'adminOrigin') tls.origin = 'https://127.0.0.1:8001';
    else if (tamper === 'forwardedProto') input.headers = { 'x-forwarded-proto': 'https' };
    else if (tamper === 'proxyRevoke') { input.method = 'POST'; input.path += '/oauth2/revoke'; input.form = {}; }
    else if (tamper === 'queryToken') input.path += '?access_token=private';
    else input.path += '/oauth2/token';
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'tampered', tls, input)).rejects.toThrow();
    expect(f.g.proxyPackets).toHaveLength(0); expect(transport.request).not.toHaveBeenCalled();
  });
  it('does not follow an observed redirect or accept a token from its destination', async () => {
    const f = fixture(); transport.status = 302; transport.body = { redirect_uri: 'https://foreign.invalid/token' };
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'redirect', f.tls, { method: 'POST', path: `${f.path}/oauth2/authorize`, form: { client_id: randomUUID() }, expected: [200] })).rejects.toThrow('MISMATCH_NO_REPLAY');
    expect(f.g.proxyPackets[0]).toMatchObject({ state: 'response_observed', status: 302 }); expect(transport.request).toHaveBeenCalledTimes(1);
  });
  it('requires exact global markers after a private ledger resume, including original response custody', async () => {
    const f = fixture(), input = { method: 'POST', path: `${f.path}/oauth2/token`, form: { client_id: randomUUID() }, expected: [200] };
    await restoredOAuthHttpsOnce(f.h, f.g, 'before-resume', f.tls, input);
    f.g = JSON.parse(JSON.stringify(f.g)); f.h.state = JSON.parse(JSON.stringify(f.h.state));
    await restoredOAuthHttpsOnce(f.h, f.g, 'after-resume', f.tls, input);
    f.h.state.requests[0].responseData = { ...token() };
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'tampered-marker', f.tls, input)).rejects.toThrow('GLOBAL_OAUTH_MARKER_CHANGED');
    expect(transport.request).toHaveBeenCalledTimes(2);
  });
  it('retains unknown state on a truncated or oversized response without a second transport', async () => {
    const f = fixture(); transport.request.mockImplementation((options, callback) => {
      const request = new EventEmitter(); request.setTimeout = vi.fn(); request.destroy = vi.fn();
      request.end = () => queueMicrotask(() => { const response = new EventEmitter(); response.socket = { authorized: true };
        response.statusCode = 200; response.destroy = vi.fn(); callback(response); response.emit('data', Buffer.alloc(64 * 1024 + 1)); response.emit('end'); });
      return request;
    });
    await expect(restoredOAuthHttpsOnce(f.h, f.g, 'too-large', f.tls, { method: 'POST', path: `${f.path}/oauth2/token`, form: { client_id: randomUUID() }, expected: [200] })).rejects.toThrow('BUDGET');
    expect(f.g.proxyPackets[0].state).toBe('response_unknown'); expect(f.h.state.requests[0].state).toBe('response_unknown'); expect(transport.request).toHaveBeenCalledTimes(1);
  });
});

describe('bounded GET-only eventual configuration and revocation observations', () => {
  it('uses new GET labels and requires the real echo upstream with original Consumer identity', async () => {
    const f = fixture(), consumerId = randomUUID(), send = vi.fn().mockResolvedValueOnce({ status: 401, body: { error: 'invalid_token' } })
      .mockResolvedValueOnce({ status: 200, body: { upstream: 'kongos-test', method: 'GET', path: f.path, consumerId } }), pause = vi.fn();
    await expect(restoredOAuthPollGet(send, { label: 'positive', path: f.path, headers: { authorization: 'Bearer SyntheticAccess' }, expectedStatus: 200, consumerId, maxAttempts: 3 }, pause)).resolves.toEqual({ actualStatus: 200, attempts: 2 });
    expect(send.mock.calls.map(([label, input]) => [label, input.method])).toEqual([['positive-1', 'GET'], ['positive-2', 'GET']]);
    expect(pause).toHaveBeenCalledTimes(1);
  });
  it('observes a token denial only as invalid_token; a missing bearer requires the distinct invalid_request response', async () => {
    const f = fixture(), send = vi.fn().mockResolvedValue({ status: 401, body: { error: 'invalid_token' } });
    await expect(restoredOAuthPollGet(send, { label: 'revoked', path: f.path, headers: { authorization: 'Bearer SyntheticAccess' }, expectedStatus: 401, maxAttempts: 1 })).resolves.toEqual({ actualStatus: 401, attempts: 1 });
    await expect(restoredOAuthPollGet(send, { label: 'missing', path: f.path, expectedStatus: 401, maxAttempts: 1 })).rejects.toThrow('DENIAL_REQUIRED');
    send.mockResolvedValue({ status: 401, body: { error: 'invalid_request' } });
    await expect(restoredOAuthPollGet(send, { label: 'missing', path: f.path, expectedStatus: 401, maxAttempts: 1 })).resolves.toEqual({ actualStatus: 401, attempts: 1 });
  });
  it('cannot accept a positive response from a foreign Consumer or a cache/proxy fake upstream', async () => {
    const f = fixture(), consumerId = randomUUID(), send = vi.fn().mockResolvedValue({ status: 200, body: { upstream: 'kongos-test', method: 'GET', path: f.path, consumerId: randomUUID() } });
    await expect(restoredOAuthPollGet(send, { label: 'foreign', path: f.path, expectedStatus: 200, consumerId, maxAttempts: 1 })).rejects.toThrow('RESTORED_CONSUMER_REQUIRED');
    send.mockResolvedValue({ status: 200, body: { upstream: 'mock-success', method: 'GET', path: f.path, consumerId } });
    await expect(restoredOAuthPollGet(send, { label: 'fake', path: f.path, expectedStatus: 200, consumerId, maxAttempts: 1 })).rejects.toThrow();
  });
  it('caps eventual GET attempts and never calls a token POST or loops after an unknown', async () => {
    const f = fixture(), send = vi.fn().mockResolvedValue({ status: 200, body: {} }), pause = vi.fn();
    await expect(restoredOAuthPollGet(send, { label: 'revoked', path: f.path, headers: { authorization: 'Bearer SyntheticAccess' }, expectedStatus: 401, maxAttempts: 2, delayMs: 0 }, pause)).rejects.toThrow('DEADLINE');
    expect(send).toHaveBeenCalledTimes(2); expect(send.mock.calls.every(([, input]) => input.method === 'GET')).toBe(true);
    send.mockReset().mockRejectedValue(Error('ORIGINAL_UNKNOWN'));
    await expect(restoredOAuthPollGet(send, { label: 'unknown', path: f.path, expectedStatus: 401, maxAttempts: 2 }, pause)).rejects.toThrow('ORIGINAL_UNKNOWN'); expect(send).toHaveBeenCalledTimes(1);
    await expect(restoredOAuthPollGet(send, { label: 'bad-bound', path: f.path, expectedStatus: 401, maxAttempts: 41 })).rejects.toThrow('BOUNDED');
  });
  it('does not misreport a transient known GET 500 as revocation; only an actual token 401 completes it', async () => {
    const f = fixture(), send = vi.fn().mockResolvedValueOnce({ status: 500, body: { message: 'SyntheticCacheWindow' } })
      .mockResolvedValueOnce({ status: 401, body: { error: 'invalid_token' } }), pause = vi.fn();
    await expect(restoredOAuthPollGet(send, { label: 'revoked', path: f.path, headers: { authorization: 'Bearer SyntheticAccess' }, expectedStatus: 401, maxAttempts: 2 }, pause)).resolves.toEqual({ actualStatus: 401, attempts: 2 });
    expect(send.mock.calls.every(([, input]) => input.method === 'GET')).toBe(true); expect(send).toHaveBeenCalledTimes(2);
  });
  it('caps real elapsed propagation duration as well as attempts, passing only the remaining deadline to HTTPS', async () => {
    const f = fixture(); let now = 1_000_000;
    const send = vi.fn(async () => { now += 8000; return { status: 500, body: { message: 'SyntheticCacheWindow' } }; });
    const pause = vi.fn(async ms => { now += ms; });
    await expect(restoredOAuthPollGet(send, { label: 'wall-bound', path: f.path, headers: { authorization: 'Bearer SyntheticAccess' }, expectedStatus: 401, maxAttempts: 40 }, pause, () => now)).rejects.toThrow('DEADLINE');
    expect(send).toHaveBeenCalledTimes(3); expect(send.mock.calls.map(([, input]) => input.timeoutMs)).toEqual([10000, 10000, 3000]);
    expect(pause).toHaveBeenCalledTimes(2);
  });
});

describe('future OAuth harness source contract and recorded Kong 1.5 schema', () => {
  it('uses only recorded OAuth2 config fields and credential fields', () => {
    const raw = JSON.parse(readFileSync('tests/fixtures/kong-1.5.1/plugin-schema-oauth2.json', 'utf8'));
    const schema = raw.body ?? raw.response?.body ?? raw.response ?? raw;
    const fields = Array.isArray(schema.fields) ? Object.assign({}, ...schema.fields) : schema.fields;
    const config = fields?.config ? (Array.isArray(fields.config.fields) ? Object.assign({}, ...fields.config.fields) : fields.config.fields) : fields;
    for (const key of ['scopes', 'mandatory_scope', 'provision_key', 'token_expiration', 'enable_authorization_code', 'enable_implicit_grant',
      'enable_client_credentials', 'enable_password_grant', 'hide_credentials', 'accept_http_if_already_terminated', 'global_credentials', 'auth_header_name', 'refresh_token_ttl']) expect(config).toHaveProperty(key);
    const credentials = JSON.parse(readFileSync('tests/fixtures/kong15-recorded-admin/schema-oauth2_credentials.json', 'utf8')).response;
    const nativeFields = Object.assign({}, ...credentials.fields);
    for (const key of ['consumer', 'name', 'client_id', 'client_secret', 'redirect_uris']) expect(nativeFields).toHaveProperty(key);
    expect(nativeFields.consumer.reference).toBe('consumers');
  });
  it('keeps revoke/restore as independently approved typed recycle workflows, with no token endpoint invention or stage replay', () => {
    const source = readFileSync('tests/security/m11-restored-oauth2-https-probes.mjs', 'utf8');
    expect(source).toContain("['create-probes', 'issue-refresh', 'revoke-client', 'restore-client']");
    expect(source).toContain("'gate3RestoredOAuth2HttpsProbes'"); expect(source).toContain("new ReleaseHarness('M11', { resume: true })");
    expect(source).toContain("['a', 'b', 'c'].entries()"); expect(source).toContain("record.approvalSetId = approvedWorkflow.approval.approvalSetId");
    expect(source).toContain("kind: 'recycle', action: 'delete', entityType: 'credentials'"); expect(source).toContain("parentId: g.consumerId, credentialKind: 'oauth2'");
    expect(source).toContain("kind: 'recycle', action: 'restore', entryId: g.revocationEntryId");
    expect(source).toContain("await originalCredential(true)"); expect(source).toContain("old-token-remains-revoked-after-client-restore");
    expect(source).toContain("{ flag: 'wx' }"); expect(source).toContain('ROOT_FRESH_LOGIN_REQUIRED_NO_IMPLICIT_REFRESH');
    expect(source).toContain('assertProxyWritable(h, g)'); expect(source).toContain('TOKEN_MUST_REMAIN_UNEXPIRED_THROUGH_REVOCATION_PROOF');
    expect(source).not.toMatch(/(?:scope\(|path:\s*[`'"])[^\n]*(?:oauth2_tokens|oauth2\/revoke)/);
    expect(source).not.toContain('rejectUnauthorized: false'); expect(source).not.toContain("h.login("); expect(source).not.toContain('gate3TargetWeight');
  });
});
