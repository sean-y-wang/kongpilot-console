// @ts-nocheck -- synthetic harness/HTTP only; never opens a private ledger.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';

const runtime = vi.hoisted(() => ({ construct: vi.fn(), open: vi.fn(() => 19), write: vi.fn(), close: vi.fn(), directory: vi.fn() }));
vi.mock('node:fs', async original => ({ ...(await original()), openSync: runtime.open, writeSync: runtime.write, closeSync: runtime.close }));
vi.mock('../security/lib/release-private-directory.mjs', () => ({ selectReleaseReportDirectory: () => ({ custom: true, directory: '/synthetic-no-ledger/reports' }),
  assertReleaseReportDirectory: runtime.directory }));
vi.mock('../security/lib/release-harness.mjs', () => ({ ReleaseHarness: class { constructor(...args) { return runtime.construct(...args); } },
  releasePassword: () => 'SyntheticCasePrivatePassword', releaseScope: (cid, wid, path, extra = {}) =>
    `/clusters/${cid}/${path}?${new URLSearchParams({ workspaceId: wid, ...extra })}` }));
import { currentPortalCaseSelection, currentPortalSelectedFixture, currentPortalOnceLabel, currentPortalConsoleWrite,
  currentPortalProbe, currentPortalPublicReport, main } from '../security/m11-current-portal-natural-http.mjs';

const env = { RELEASE_LAB_M11_CURRENT_PORTAL_READY: 'true', RELEASE_LAB_M11_PORTAL_ORIGIN: 'http://127.0.0.1:5456',
  RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN: 'null', RELEASE_LAB_M11_REGISTERED_PROXY_ORIGIN: 'http://kong:8000' };
const freshEnv = { ...env, RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'ledger-fix-20261015', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'portalNaturalFreshFixture' };
const session = () => {
  const user = { id: randomUUID() }, sid = randomUUID(), claims = Buffer.from(JSON.stringify({ sub: user.id, sid, exp: 2000000000 })).toString('base64url');
  return { user, sid, cookie: `kongos_access=synthetic.${claims}.synthetic`, csrf: 'SyntheticCaseCSRF' };
};
function fixture() {
  const cid = randomUUID(), wid = randomUUID(), author = session(), reviewer = session();
  const selected = { clusterId: cid, workspaceId: wid, serviceId: randomUUID(), routeId: randomUUID(), routePath: '/m11-portal-ledger-fix' };
  const legacy = { serviceId: randomUUID(), routeId: randomUUID(), routePath: '/m11-portal-original' };
  const services = new Map([selected, legacy].map(f => [f.serviceId, { id: f.serviceId, name: `source-${f.serviceId}`, host: 'source.invalid', tags: [] }]));
  const routes = new Map([selected, legacy].map(f => [f.routeId, { id: f.routeId, name: `source-${f.routeId}`, service: { id: f.serviceId },
    protocols: ['http'], methods: ['GET'], paths: [f.routePath], hosts: [], headers: {} }]));
  const state = { cid, wid, requests: [], sessions: { admin: author }, metadataAcceptance: {
    service: { id: legacy.serviceId }, metricsRouteId: legacy.routeId, metricsRoutePath: legacy.routePath,
    reviewerSession: reviewer, portalNaturalFreshFixture: selected } };
  const h = { state, base: 'http://127.0.0.1:5445/api/v1', save: vi.fn(), assertWritable: vi.fn(),
    once: vi.fn(async () => ({ status: 201, requestId: randomUUID(), data: { workflowId: randomUUID() } })),
    request: vi.fn(async (who, path) => {
      if (path === '/auth/me') return { data: { user: { ...who.user, permissionsVersion: `${who.user.id}:1:1`, forcePasswordChange: false }, csrfToken: 'SyntheticFreshCSRF' } };
      if (path === `/clusters/${cid}`) return { data: { id: cid, revision: 1, execution_mode: 'approval', version: '1.5.1', status: 'healthy', proxy_origin: 'http://kong:8000' } };
      const at = new URL(`http://synthetic.invalid${path}`), id = at.pathname.split('/').at(-1);
      if (at.pathname.includes('/entities/services/') && services.has(id)) return { data: { entity: structuredClone(services.get(id)) } };
      if (at.pathname.includes('/entities/routes/') && routes.has(id)) return { data: { entity: structuredClone(routes.get(id)) } };
      throw Error('UNEXPECTED_SYNTHETIC_READ');
    }) };
  runtime.construct.mockImplementation(() => h);
  return { h, state, selected, legacy, services, routes, author, reviewer };
}
async function invoke(input, stage) {
  const before = process.exitCode;
  try { await main(input, stage); } finally { process.exitCode = before; }
  return JSON.parse(runtime.write.mock.calls.at(-1)[1]);
}
beforeEach(() => {
  runtime.construct.mockReset().mockImplementation(() => { throw Error('NO_PRIVATE_LEDGER_IN_SOURCE_TEST'); });
  for (const fn of [runtime.open, runtime.write, runtime.close, runtime.directory]) fn.mockClear();
  vi.spyOn(console, 'log').mockImplementation(() => {}); vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => { vi.restoreAllMocks(); });

describe('explicit Portal case selection and immutable native fixture', () => {
  it('retains the exact default state and once namespace without creating a new case binding', async () => {
    expect(currentPortalCaseSelection(env)).toEqual({ version: 1, caseId: 'original', fixtureField: null, oncePrefix: 'm11-current-portal-' });
    expect(currentPortalCaseSelection({ ...env, RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'original' })).toEqual(currentPortalCaseSelection(env));
    const f = fixture(), report = await invoke(env, 'preflight'), g = f.state.currentPortalNaturalOriginal;
    expect(report.passed).toBe(true); expect(report.caseId).toBe('original'); expect(report.fixtureField).toBeNull();
    expect(g.version).toBe(1); expect(g).not.toHaveProperty('caseBinding'); expect(f.state).not.toHaveProperty('currentPortalNaturalCases');
    expect(g.fixture).toMatchObject(f.legacy); expect(currentPortalOnceLabel(g, 'settings')).toBe('m11-current-portal-settings');
  });
  it('creates only the explicitly selected isolated case, preserving all original case bytes', async () => {
    const f = fixture(); await invoke(env, 'preflight');
    const original = structuredClone(f.state.currentPortalNaturalOriginal), report = await invoke(freshEnv, 'preflight');
    const g = f.state.currentPortalNaturalCases['ledger-fix-20261015'];
    expect(report).toMatchObject({ passed: true, caseId: 'ledger-fix-20261015', fixtureField: 'portalNaturalFreshFixture',
      publicEndpointConfigured: false, externalAccessVerified: false, wholeM11Accepted: false });
    expect(f.state.currentPortalNaturalOriginal).toEqual(original); expect(g.version).toBe(2);
    expect(g.caseBinding).toEqual({ ...currentPortalCaseSelection(freshEnv), ...f.selected });
    expect(g.fixture).toMatchObject({ serviceId: f.selected.serviceId, routeId: f.selected.routeId, routePath: f.selected.routePath });
    expect(g.fixture.observed.registeredProxyOrigin).toBe('http://kong:8000'); expect(g.fixture.observed.proxyHost).toBe('kong');
    expect(f.h.once).not.toHaveBeenCalled();
    expect(f.h.request.mock.calls.every(([, , method]) => method === undefined || method === 'GET')).toBe(true);
  });
  it.each([
    { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: '' }, { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'ValidCase' },
    { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'constructor', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'portalNaturalFreshFixture' },
    { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: '__proto__', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'portalNaturalFreshFixture' },
    { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'prototype', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'portalNaturalFreshFixture' },
    { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'ledger-fix-20261015' },
    { RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'portalNaturalFreshFixture' },
    { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'original', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'portalNaturalFreshFixture' },
    { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'fresh', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: '' },
    { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'fresh', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'constructor' },
    { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'fresh', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'metadata.field' },
    { RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'fresh', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'nested[field]' },
  ])('rejects malformed/unpaired/prototype selectors before opening a harness', async invalid => {
    await expect(main({ ...env, ...invalid }, 'preflight')).rejects.toThrow(); expect(runtime.construct).not.toHaveBeenCalled();
    expect(runtime.open).not.toHaveBeenCalled();
  });
  it.each(['foreign-cluster', 'foreign-workspace', 'unknown-field', 'inherited-field', 'extra-field', 'bad-id', 'regex-path', 'query-path', 'traversal-path'])
  ('rejects a %s native fixture without BFF calls or state selection', async variant => {
    const f = fixture(), metadata = f.state.metadataAcceptance;
    if (variant === 'foreign-cluster') f.selected.clusterId = randomUUID();
    if (variant === 'foreign-workspace') f.selected.workspaceId = randomUUID();
    if (variant === 'unknown-field') delete metadata.portalNaturalFreshFixture;
    if (variant === 'inherited-field') { delete metadata.portalNaturalFreshFixture; Object.setPrototypeOf(metadata, { portalNaturalFreshFixture: f.selected }); }
    if (variant === 'extra-field') f.selected.extra = 'unsupported';
    if (variant === 'bad-id') f.selected.serviceId = 'borrowed-native';
    if (variant === 'regex-path') f.selected.routePath = '/regex(.*)';
    if (variant === 'query-path') f.selected.routePath = '/plain?secret=synthetic';
    if (variant === 'traversal-path') f.selected.routePath = '/../different';
    const report = await invoke(freshEnv, 'preflight'); expect(report.passed).toBe(false);
    expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.once).not.toHaveBeenCalled(); expect(f.h.save).not.toHaveBeenCalled();
    expect(f.state).not.toHaveProperty('currentPortalNaturalCases');
  });
  it.each(['null', 'array', 'inherited-object', 'existing-null-case', 'existing-string-case', 'existing-array-case'])('refuses a malformed %s case store instead of replacing it', async variant => {
    const f = fixture();
    f.state.currentPortalNaturalCases = variant === 'null' ? null : variant === 'array' ? [] : variant === 'inherited-object'
      ? Object.create({ inherited: true }) : { 'ledger-fix-20261015': variant === 'existing-string-case' ? 'not-a-record' : variant === 'existing-array-case' ? [] : null };
    const before = f.state.currentPortalNaturalCases;
    const report = await invoke(freshEnv, 'preflight'); expect(report.passed).toBe(false);
    expect(f.state.currentPortalNaturalCases).toBe(before); expect(f.h.save).not.toHaveBeenCalled(); expect(f.h.request).not.toHaveBeenCalled();
  });
  it.each(['field-name', 'serviceId', 'routeId', 'routePath', 'clusterId', 'workspaceId'])
  ('rejects rebinding the same case via %s before a stage/write is selected', async variant => {
    const f = fixture(); await invoke(freshEnv, 'preflight');
    const original = structuredClone(f.state.currentPortalNaturalCases['ledger-fix-20261015']); f.h.save.mockClear(); f.h.request.mockClear();
    let nextEnv = freshEnv;
    if (variant === 'field-name') { f.state.metadataAcceptance.alternateFixture = { ...f.selected }; nextEnv = { ...freshEnv, RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'alternateFixture' }; }
    else if (variant === 'routePath') f.selected.routePath = '/different-path'; else f.selected[variant] = randomUUID();
    const report = await invoke(nextEnv, 'policy'); expect(report.passed).toBe(false);
    expect(f.state.currentPortalNaturalCases['ledger-fix-20261015']).toEqual(original);
    expect(f.h.save).not.toHaveBeenCalled(); expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.once).not.toHaveBeenCalled();
  });
  it.each(['service', 'route', 'uppercase-service', 'uppercase-route'])('never borrows a default %s native identity', async variant => {
    const f = fixture();
    if (variant.includes('service')) f.selected.serviceId = variant.startsWith('uppercase') ? f.legacy.serviceId.toUpperCase() : f.legacy.serviceId;
    else f.selected.routeId = variant.startsWith('uppercase') ? f.legacy.routeId.toUpperCase() : f.legacy.routeId;
    const report = await invoke(freshEnv, 'preflight'); expect(report.passed).toBe(false);
    expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.save).not.toHaveBeenCalled();
  });
  it.each(['same-field', 'same-service', 'same-route', 'uppercase-service', 'uppercase-route'])
  ('prevents aliasing an occupied failed/unknown case by %s', async variant => {
    const f = fixture(); await invoke(freshEnv, 'preflight');
    const first = f.state.currentPortalNaturalCases['ledger-fix-20261015']; first.stages.policy = { state: 'failed', errorCode: 'ORIGINAL_UNKNOWN_RETAINED' };
    const original = structuredClone(first), next = { ...f.selected, serviceId: randomUUID(), routeId: randomUUID() };
    let field = 'secondFixture';
    if (variant === 'same-field') field = 'portalNaturalFreshFixture';
    if (variant.includes('service')) next.serviceId = variant.startsWith('uppercase') ? f.selected.serviceId.toUpperCase() : f.selected.serviceId;
    if (variant.includes('route')) next.routeId = variant.startsWith('uppercase') ? f.selected.routeId.toUpperCase() : f.selected.routeId;
    if (field === 'secondFixture') f.state.metadataAcceptance.secondFixture = next;
    f.h.save.mockClear(); f.h.request.mockClear();
    const report = await invoke({ ...freshEnv, RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'another-case', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: field }, 'preflight');
    expect(report.passed).toBe(false); expect(first).toEqual(original);
    expect(f.state.currentPortalNaturalCases).not.toHaveProperty('another-case'); expect(f.h.save).not.toHaveBeenCalled(); expect(f.h.request).not.toHaveBeenCalled();
  });
  it.each(['null', 'zero', 'string', 'array', 'wrong-version', 'foreign-key', 'missing-fixture', 'changed-fixture', 'foreign-scope'])
  ('fails closed on a corrupt %s other case instead of freeing its sealed native identities', async variant => {
    const f = fixture(); await invoke(freshEnv, 'preflight');
    const original = f.state.currentPortalNaturalCases['ledger-fix-20261015'];
    if (variant === 'null') f.state.currentPortalNaturalCases['ledger-fix-20261015'] = null;
    if (variant === 'zero') f.state.currentPortalNaturalCases['ledger-fix-20261015'] = 0;
    if (variant === 'string') f.state.currentPortalNaturalCases['ledger-fix-20261015'] = 'not-a-record';
    if (variant === 'array') f.state.currentPortalNaturalCases['ledger-fix-20261015'] = [];
    if (variant === 'wrong-version') original.version = 1;
    if (variant === 'foreign-key') { delete f.state.currentPortalNaturalCases['ledger-fix-20261015']; f.state.currentPortalNaturalCases['another-key'] = original; }
    if (variant === 'missing-fixture') delete original.fixture;
    if (variant === 'changed-fixture') original.fixture.serviceId = randomUUID();
    if (variant === 'foreign-scope') original.clusterId = randomUUID();
    f.state.metadataAcceptance.secondFixture = { ...f.selected, serviceId: randomUUID(), routeId: randomUUID() };
    const before = structuredClone(f.state.currentPortalNaturalCases); f.h.save.mockClear(); f.h.request.mockClear();
    const report = await invoke({ ...freshEnv, RELEASE_LAB_M11_CURRENT_PORTAL_CASE: 'second-case', RELEASE_LAB_M11_CURRENT_PORTAL_FIXTURE: 'secondFixture' }, 'preflight');
    expect(report.passed).toBe(false); expect(f.state.currentPortalNaturalCases).toEqual(before);
    expect(f.h.save).not.toHaveBeenCalled(); expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.once).not.toHaveBeenCalled();
  });
});

describe('isolated Portal once labels, immutable stage history and public evidence', () => {
  it('isolates both console commands and real protected proxy-probe labels while retaining the same explicit key', async () => {
    const f = fixture(); await invoke(freshEnv, 'preflight'); const g = f.state.currentPortalNaturalCases['ledger-fix-20261015'];
    const path = `/clusters/${f.state.cid}/portal/settings?workspaceId=${f.state.wid}`;
    await currentPortalConsoleWrite(f.h, g, 'settings', path, 'POST', { published: true });
    expect(f.h.once.mock.calls[0][0]).toBe('m11-current-portal.case:ledger-fix-20261015:settings');
    expect(f.h.once.mock.calls[0][5].key).toBe(g.consoleOperations.settings.key);
    const original = structuredClone(g.consoleOperations.settings);
    await expect(currentPortalConsoleWrite(f.h, g, 'settings', path, 'POST', { published: true })).rejects.toThrow('NO_REPLAY');
    expect(g.consoleOperations.settings).toEqual(original);
    g.issuedKey = 'SyntheticCaseIssuedKeyNeverPublic';
    f.h.once.mockResolvedValueOnce({ data: { bodyReturned: false, status: 200, observedAt: '2026-10-15T00:00:00.000Z' }, requestId: randomUUID() });
    await currentPortalProbe(f.h, g, 'issued-key', 200);
    expect(f.h.once.mock.calls[1][0]).toBe('m11-current-portal.case:ledger-fix-20261015:issued-key-proxy-get-1');
    expect(f.h.once.mock.calls[1][2]).toContain('/toolbox/probes?'); expect(f.h.once.mock.calls[1][4].routeId).toBe(f.selected.routeId);
  });
  it('preserves both legacy labels and immutable originally selected keys on helper calls', async () => {
    const f = fixture(); await invoke(env, 'preflight'); const g = f.state.currentPortalNaturalOriginal;
    await currentPortalConsoleWrite(f.h, g, 'settings', `/clusters/${f.state.cid}/portal/settings?workspaceId=${f.state.wid}`, 'POST', {});
    expect(f.h.once.mock.calls[0][0]).toBe('m11-current-portal-settings');
    g.issuedKey = 'SyntheticLegacyIssuedKeyNeverPublic'; f.h.once.mockResolvedValueOnce({ data: { bodyReturned: false, status: 401 }, requestId: randomUUID() });
    await currentPortalProbe(f.h, g, 'revoked-original-key', 401);
    expect(f.h.once.mock.calls[1][0]).toBe('m11-current-portal-revoked-original-key-proxy-get-1');
  });
  it('rejects the same failed/prepared stage without replacing it or selecting a new key', async () => {
    const f = fixture(); await invoke(freshEnv, 'preflight'); const g = f.state.currentPortalNaturalCases['ledger-fix-20261015'];
    g.stages.policy = { state: 'failed', originalKey: randomUUID(), errorCode: 'ORIGINAL_UNKNOWN_RETAINED' };
    const before = structuredClone(g); f.h.save.mockClear(); f.h.request.mockClear();
    const report = await invoke(freshEnv, 'policy'); expect(report.passed).toBe(false); expect(g).toEqual(before);
    expect(f.h.save).not.toHaveBeenCalled(); expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.once).not.toHaveBeenCalled();
  });
  it('cannot bypass the existing global unknown-write fence by selecting a distinct new case', async () => {
    const f = fixture(); f.h.assertWritable.mockImplementation(() => { throw Error('ORIGINAL_UNRESOLVED_RELEASE_WRITE_NO_REPLAY'); });
    const report = await invoke(freshEnv, 'preflight'); expect(report.passed).toBe(false);
    expect(f.state).not.toHaveProperty('currentPortalNaturalCases'); expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.once).not.toHaveBeenCalled();
  });
  it('keeps default readonly inspect on the old case after a distinct new case exists', async () => {
    const f = fixture(); await invoke(env, 'preflight'); await invoke(freshEnv, 'preflight');
    const fresh = structuredClone(f.state.currentPortalNaturalCases['ledger-fix-20261015']); f.h.assertWritable.mockClear(); f.h.request.mockClear();
    const report = await invoke(env, 'inspect'); expect(report).toMatchObject({ passed: true, caseId: 'original' });
    expect(f.state.currentPortalNaturalCases['ledger-fix-20261015']).toEqual(fresh);
    expect(f.state.currentPortalNaturalOriginal.stages.inspect.state).toBe('succeeded'); expect(f.h.assertWritable).not.toHaveBeenCalled(); expect(f.h.once).not.toHaveBeenCalled();
  });
  it('checks the original native material and registered proxy on every new-case stage', async () => {
    const f = fixture(); await invoke(freshEnv, 'preflight'); f.services.get(f.selected.serviceId).host = 'changed.invalid';
    const report = await invoke(freshEnv, 'policy'); expect(report.passed).toBe(false);
    expect(f.state.currentPortalNaturalCases['ledger-fix-20261015'].stages.policy.state).toBe('failed'); expect(f.h.once).not.toHaveBeenCalled();
  });
  it('refuses a lost or altered case binding in the label helper', async () => {
    const f = fixture(); await invoke(freshEnv, 'preflight'); const g = f.state.currentPortalNaturalCases['ledger-fix-20261015'];
    const original = g.caseBinding; delete g.caseBinding; expect(() => currentPortalOnceLabel(g, 'settings')).toThrow('BINDING_REQUIRED');
    g.caseBinding = { ...original, oncePrefix: 'm11-current-portal-' }; expect(() => currentPortalOnceLabel(g, 'settings')).toThrow('BINDING_CHANGED');
  });
  it.each(['author-same-SID', 'author-new-SID', 'reviewer-same-SID', 'reviewer-new-SID'])
  ('retains the original %s jar rule on a duplicate new-case stage', async variant => {
    const f = fixture(); await invoke(freshEnv, 'preflight'); const g = f.state.currentPortalNaturalCases['ledger-fix-20261015'];
    const role = variant.startsWith('author') ? 'author' : 'reviewer', key = `${role}Session`, original = g[key];
    const replacement = { ...original, cookie: 'SyntheticRefreshedSameSIDJar', ...(variant.includes('new-SID') ? { sid: randomUUID() } : {}) };
    if (role === 'author') f.state.sessions.admin = replacement; else f.state.metadataAcceptance.reviewerSession = replacement;
    f.h.save.mockClear(); f.h.request.mockClear(); const report = await invoke(freshEnv, 'preflight');
    expect(report.passed).toBe(false); expect(g[key]).toBe(variant.includes('new-SID') ? original : replacement);
    expect(g[key].sid).toBe(g.acceptance[role].sid); expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.save).not.toHaveBeenCalled();
  });
  it('does not publish an unvalidated stored binding, including on the safe main failure report', async () => {
    const f = fixture(); await invoke(freshEnv, 'preflight'); const g = f.state.currentPortalNaturalCases['ledger-fix-20261015'];
    const secret = 'SyntheticCaseIssuedKeyNeverPublic'; g.caseBinding = { ...g.caseBinding, fixtureField: secret };
    f.h.save.mockClear(); f.h.request.mockClear(); const report = await invoke(freshEnv, 'policy');
    expect(report).toMatchObject({ passed: false, actualHttpAcceptanceClaim: false, caseId: 'ledger-fix-20261015', fixtureField: 'portalNaturalFreshFixture' });
    expect(JSON.stringify(report)).not.toContain(secret); expect(f.h.save).not.toHaveBeenCalled(); expect(f.h.request).not.toHaveBeenCalled();
    const direct = currentPortalPublicReport(f.h, g, 'inspect', false, 0);
    expect(direct.caseId).toBeNull(); expect(direct.fixtureField).toBeNull(); expect(JSON.stringify(direct)).not.toContain(secret);
  });
  it('does not include private case passwords, key/cookies/CSRF or binding/native bodies in public evidence', async () => {
    const f = fixture(); await invoke(freshEnv, 'preflight'); const g = f.state.currentPortalNaturalCases['ledger-fix-20261015'];
    g.issuedKey = 'SyntheticCaseIssuedKeyNeverPublic';
    f.state.requests.push({ method: 'POST', path: '/portal/requests?secret=do-not-publish', key: randomUUID(), state: 'response_unknown',
      body: { key: g.issuedKey, password: g.password }, headers: { Cookie: 'SyntheticCaseCookie', 'X-Portal-CSRF': 'SyntheticCasePortalCSRF' } });
    const report = currentPortalPublicReport(f.h, g, 'inspect', false, 0, 'ORIGINAL_UNKNOWN_RETAINED'), encoded = JSON.stringify(report);
    for (const secret of [g.password, g.issuedKey, 'SyntheticCaseCookie', 'SyntheticCasePortalCSRF', 'do-not-publish']) expect(encoded).not.toContain(secret);
    for (const key of ['caseBinding', 'fixture', 'configuration', 'metadataAcceptance']) expect(report).not.toHaveProperty(key);
    expect(report).toMatchObject({ caseId: 'ledger-fix-20261015', fixtureField: 'portalNaturalFreshFixture', credentialsPublished: false,
      issueExecuteRequestInvoked: false, manualWorkerTickInvoked: false, publicEndpointConfigured: false, externalAccessVerified: false });
  });
});
