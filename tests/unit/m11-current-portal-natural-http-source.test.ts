// @ts-nocheck -- synthetic HTTP only. Import must not open a real private ledger.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';

const runtime = vi.hoisted(() => ({ construct: vi.fn(() => { throw Error('SOURCE_TEST_MUST_NOT_OPEN_PRIVATE_LEDGER'); }),
  open: vi.fn(() => 17), write: vi.fn(), close: vi.fn(), report: vi.fn() }));
vi.mock('node:fs', async importOriginal => ({ ...(await importOriginal()), openSync: runtime.open, writeSync: runtime.write, closeSync: runtime.close }));
vi.mock('../security/lib/release-private-directory.mjs', () => ({
  selectReleaseReportDirectory: () => ({ custom: true, directory: '/synthetic-source-only/reports' }), assertReleaseReportDirectory: runtime.report,
}));
vi.mock('../security/lib/release-harness.mjs', () => ({ ReleaseHarness: class { constructor(...args) { return runtime.construct(...args); } },
  releasePassword: () => 'SyntheticNeverUsedPassword',
  releaseScope: (cid, wid, path, extra = {}) => `/clusters/${cid}/${path}?${new URLSearchParams({ workspaceId: wid, ...extra })}` }));
import { CURRENT_PORTAL_STAGES, currentPortalConfiguration, currentPortalIssuePolicy, currentPortalWindow,
  currentPortalVoteBody, currentPortalConsoleWrite, currentPortalHttpOnce, currentPortalPublicReport,
  currentPortalProbeHost, currentPortalPublicOriginMatches, main } from '../security/m11-current-portal-natural-http.mjs';

const env = { RELEASE_LAB_M11_CURRENT_PORTAL_READY: 'true', RELEASE_LAB_M11_PORTAL_ORIGIN: 'http://127.0.0.1:5456',
  RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN: 'http://127.0.0.1:5446', RELEASE_LAB_M11_REGISTERED_PROXY_ORIGIN: 'http://kong:8000' };
function fixture() {
  const clusterId = randomUUID(), workspaceId = randomUUID(), actorId = randomUUID(), sid = randomUUID();
  const g = { clusterId, workspaceId, configuration: currentPortalConfiguration(env, 'preflight'),
    authorSession: { user: { id: actorId }, sid, cookie: '', csrf: 'SyntheticConsoleCSRF' },
    consoleOperations: {}, portalPackets: [], developerSession: { cookie: '', csrf: 'SyntheticPortalCSRF' }, workflowKinds: {},
    fixture: { serviceId: randomUUID(), routeId: randomUUID() }, timerObservations: [], proxyObservations: [],
    acceptance: { author: { id: actorId, sid }, reviewer: { id: randomUUID(), sid: randomUUID() } } };
  const h = { base: 'http://127.0.0.1:5445/api/v1', state: { requests: [] }, save: vi.fn(), assertWritable: vi.fn(),
    once: vi.fn(async () => ({ data: { workflowId: randomUUID() }, status: 201, requestId: randomUUID() })) };
  return { h, g, tenant: { clusterId, workspaceId } };
}
const json = (data, status = 201, cookies = []) => {
  const result = new Response(JSON.stringify({ data, meta: { requestId: randomUUID() } }), { status, headers: { 'Content-Type': 'application/json' } });
  Object.defineProperty(result.headers, 'getSetCookie', { value: () => cookies }); return result;
};
beforeEach(() => { vi.unstubAllGlobals(); runtime.construct.mockReset().mockImplementation(() => { throw Error('SOURCE_TEST_MUST_NOT_OPEN_PRIVATE_LEDGER'); });
  runtime.open.mockClear(); runtime.write.mockClear(); runtime.close.mockClear(); });

describe('current-run Portal natural acceptance authoring contract', () => {
  it('has no import-time private, runtime or transport side effect', () => {
    expect(runtime.construct).not.toHaveBeenCalled(); expect(CURRENT_PORTAL_STAGES).toContain('revoke-execute');
    expect(CURRENT_PORTAL_STAGES).not.toContain('issue-execute');
  });
  it('rejects invocation without the explicit gate before constructing any private harness', async () => {
    await expect(main({ ...env, RELEASE_LAB_M11_CURRENT_PORTAL_READY: 'false' }, 'preflight')).rejects.toThrow('GATE_REQUIRED');
    expect(runtime.construct).not.toHaveBeenCalled();
  });
  it.each(['same-SID', 'new-SID'])('duplicate stage preserves the original result and %s session continuity without BFF writes', async variant => {
    const { h, g } = fixture(); g.version = 1; g.fixture.routePath = '/synthetic';
    const originalAuthor = g.authorSession, globalAuthor = { ...originalAuthor, cookie: 'SyntheticLatestRealJar',
      ...(variant === 'new-SID' ? { sid: randomUUID() } : {}) };
    const original = { state: 'succeeded', startedAt: '2026-10-15T00:00:00.000Z', completedAt: '2026-10-15T00:00:01.000Z' };
    g.stages = { policy: { state: 'succeeded' }, settings: structuredClone(original) };
    h.state.cid = g.clusterId; h.state.wid = g.workspaceId; h.state.sessions = { admin: globalAuthor };
    h.state.metadataAcceptance = { service: { id: g.fixture.serviceId }, metricsRouteId: g.fixture.routeId,
      metricsRoutePath: g.fixture.routePath, reviewerSession: { user: { id: g.acceptance.reviewer.id }, sid: g.acceptance.reviewer.sid } };
    h.state.currentPortalNaturalOriginal = g; h.request = vi.fn(); runtime.construct.mockReturnValueOnce(h);
    const oldExit = process.exitCode, error = vi.spyOn(console, 'error').mockImplementation(() => {});
    try { await main(env, 'settings'); } finally { process.exitCode = oldExit; error.mockRestore(); }
    expect(g.stages.settings).toEqual(original); expect(h.request).not.toHaveBeenCalled(); expect(h.save).not.toHaveBeenCalled();
    expect(g.authorSession).toBe(variant === 'same-SID' ? globalAuthor : originalAuthor);
    expect(g.authorSession.sid).toBe(g.acceptance.author.sid);
    expect(runtime.write).toHaveBeenCalledOnce();
    const report = JSON.parse(runtime.write.mock.calls[0][1]); expect(report.passed).toBe(false);
    expect(report.errorCode).toBe('ORIGINAL_CURRENT_PORTAL_STAGE_PRESENT_NO_REPLAY');
  });
  it.each(['tick', 'all', 'issue-execute', undefined])('rejects non-stage %s', stage => {
    expect(() => currentPortalConfiguration(env, stage)).toThrow('STAGE_REQUIRED');
  });
  it.each(['http://127.0.0.1:8001', 'https://127.0.0.1:8444', 'http://127.0.0.1:5445',
    'http://127.0.0.1:5446/path', 'http://127.0.0.1:5446?secret=synthetic', 'http://user:synthetic@127.0.0.1:5446', 'http://kong:8000'])('refuses an unsafe public proxy origin %s', origin => {
    expect(() => currentPortalConfiguration({ ...env, RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN: origin }, 'preflight')).toThrow();
  });
  it('accepts only explicit string null for the optional public document endpoint', () => {
    const configuration = currentPortalConfiguration({ ...env, RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN: 'null' }, 'preflight');
    expect(configuration.publicProxyOrigin).toBeNull(); expect(configuration.registeredProxyOrigin).toBe('http://kong:8000');
    expect(currentPortalPublicOriginMatches({ publicProxyOrigin: '' }, configuration)).toBe(true);
    expect(currentPortalPublicOriginMatches({ publicProxyOrigin: 'http://kong:8000' }, configuration)).toBe(false);
    for (const value of ['NULL', '', undefined, null]) expect(() => currentPortalConfiguration({ ...env, RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN: value }, 'preflight')).toThrow();
  });
  it.each([undefined, '', 'http://kong:8001', 'https://kong:8444', 'http://kong:5432', 'http://kong:9090', 'http://kong:8443',
    'http://user:synthetic@kong:8000', 'http://kong:8000/path', 'http://kong:8000?token=synthetic'])('rejects missing or unsafe registered proxy %s', registered => {
    expect(() => currentPortalConfiguration({ ...env, RELEASE_LAB_M11_REGISTERED_PROXY_ORIGIN: registered }, 'preflight')).toThrow();
  });
  it('uses the actual registered proxy as the fallback Host without requiring equality to the public endpoint', () => {
    const configuration = currentPortalConfiguration(env, 'preflight'), cluster = { proxy_origin: 'http://kong:8000' };
    expect(configuration.publicProxyOrigin).not.toBe(cluster.proxy_origin);
    expect(currentPortalProbeHost({ hosts: [] }, cluster, configuration)).toBe('kong');
    expect(currentPortalProbeHost({ hosts: ['service.example.invalid'] }, cluster, configuration)).toBe('service.example.invalid');
    expect(() => currentPortalProbeHost({ hosts: ['*.example.invalid'] }, cluster, configuration)).toThrow();
    expect(() => currentPortalProbeHost({ hosts: [] }, { proxy_origin: 'http://other-proxy:8000' }, configuration)).toThrow('REGISTERED_PROXY_ORIGIN_CHANGED');
    expect(() => currentPortalProbeHost({ hosts: ['service.example.invalid'] }, { proxy_origin: 'http://kong:8001' }, configuration)).toThrow('REGISTERED_PROXY_ORIGIN_CHANGED');
  });
  it('matches a non-null public endpoint strictly and leaves internal listeners unsuitable for public documents', () => {
    const configuration = currentPortalConfiguration(env, 'preflight');
    expect(currentPortalPublicOriginMatches({ publicProxyOrigin: env.RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN }, configuration)).toBe(true);
    expect(currentPortalPublicOriginMatches({ publicProxyOrigin: '' }, configuration)).toBe(false);
    expect(() => currentPortalConfiguration({ ...env, RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN: 'http://kong:8000' }, 'preflight')).toThrow();
  });
  it('uses only the actual independent reviewer in a format-2 policy', () => {
    const reviewer = randomUUID(), policy = currentPortalIssuePolicy(reviewer);
    expect(policy).toMatchObject({ version: 2, kind: 'portal-credential-issue', allowSelfApproval: false, distinctAcrossStages: true });
    expect(policy.stages).toEqual([{ level: 1, name: '独立审批', mode: 'any', threshold: 1, selector: { users: [reviewer] } }]);
    expect(() => currentPortalIssuePolicy('borrowed-super-admin')).toThrow();
  });
  it('keeps all schedule instants inside the original deadline and never accepts an expired source', () => {
    const now = Date.parse('2026-10-15T00:00:00.000Z'), expiry = '2026-10-15T00:10:00.000Z';
    expect(currentPortalWindow(expiry, now)).toEqual({ notBefore: '2026-10-15T00:02:00.000Z',
      windowStart: '2026-10-15T00:02:00.000Z', windowEnd: '2026-10-15T00:08:00.000Z' });
    expect(() => currentPortalWindow('2026-10-15T00:07:59.999Z', now)).toThrow('NOT_RENEWABLE');
    expect(() => currentPortalWindow('2026-10-14T23:59:59.000Z', now)).toThrow();
    expect(() => currentPortalWindow('invalid', now)).toThrow();
  });
  it('takes the current genuine format-2 workflow/stage/candidate versions without automatic execution', () => {
    const detail = { entity: { kind: 'portal-credential-issue', state: 'pending', approvalRequired: true,
      capabilities: { approve: true }, revision: 7, planHash: 'a'.repeat(64),
      approval: { format: 2, candidateVersion: 3, stages: [{ state: 'approved', level: 1, revision: 3 }, { state: 'active', level: 2, revision: 4 }] } } };
    expect(currentPortalVoteBody(detail, 'portal-credential-issue')).toMatchObject({ revision: 7, planHash: 'a'.repeat(64),
      level: 2, stageRevision: 4, candidateVersion: 3, confirmed: true, execute: false });
    expect(() => currentPortalVoteBody({ entity: { ...detail.entity, capabilities: { approve: false } } }, 'portal-credential-issue')).toThrow();
    expect(() => currentPortalVoteBody(detail, 'portal-credential-revoke')).toThrow();
  });
  it('keeps a genuine format-1 administrative vote free of invented v2 fields', () => {
    const result = currentPortalVoteBody({ entity: { kind: 'workflow-policy-metadata', state: 'pending', approvalRequired: true,
      capabilities: { approve: true }, revision: 1, planHash: 'b'.repeat(64) } }, 'workflow-policy-metadata');
    expect(result).not.toHaveProperty('level'); expect(result).not.toHaveProperty('stageRevision'); expect(result).not.toHaveProperty('candidateVersion');
    expect(result.execute).toBe(false);
  });
});

describe('current Portal BFF command original-key and natural-worker fences', () => {
  it('records the exact console command before using the existing original CAS harness', async () => {
    const { h, g } = fixture(), path = `/clusters/${g.clusterId}/portal/settings?workspaceId=${g.workspaceId}`, body = { published: true };
    h.once.mockImplementationOnce(async (_label, session, actualPath, method, actualBody, options) => {
      expect(g.consoleOperations.settings).toMatchObject({ path, method: 'POST', state: 'selected', actorId: session.user.id, sessionId: session.sid });
      expect(h.save).toHaveBeenCalled(); expect(options.key).toBe(g.consoleOperations.settings.key);
      expect(actualBody).toEqual(body); expect(actualPath).toBe(path);
      return { status: 201, requestId: randomUUID(), data: { workflowId: randomUUID() } };
    });
    await currentPortalConsoleWrite(h, g, 'settings', path, 'POST', body);
    expect(g.consoleOperations.settings.state).toBe('response_observed');
    await expect(currentPortalConsoleWrite(h, g, 'settings', path, 'POST', body)).rejects.toThrow('NO_REPLAY');
    expect(h.once).toHaveBeenCalledOnce();
  });
  it('cannot use HTTP execute for the Portal issue even with an approved-shaped kind mapping', async () => {
    const { h, g } = fixture(); g.workflowId = randomUUID(); g.workflowKinds[g.workflowId] = 'portal-publication';
    await expect(currentPortalConsoleWrite(h, g, 'forged-issue-execute', `/clusters/${g.clusterId}/workflows/${g.workflowId}/execute?workspaceId=${g.workspaceId}`, 'POST', {}))
      .rejects.toThrow('NATURAL_WORKER_ONLY');
    expect(h.once).not.toHaveBeenCalled(); expect(h.save).not.toHaveBeenCalled();
  });
  it('rejects native paths, foreign cluster/workspace, and missing actual metadata workflow kind', async () => {
    const { h, g } = fixture();
    for (const path of [`/clusters/${g.clusterId}/entities/services?workspaceId=${g.workspaceId}`,
      `/clusters/${randomUUID()}/portal/settings?workspaceId=${g.workspaceId}`,
      `/clusters/${g.clusterId}/portal/settings?workspaceId=${randomUUID()}`,
      `/clusters/${g.clusterId}/workflows/${randomUUID()}/execute?workspaceId=${g.workspaceId}`])
      await expect(currentPortalConsoleWrite(h, g, randomUUID(), path, 'POST', {})).rejects.toThrow();
    expect(h.once).not.toHaveBeenCalled();
  });
  it('a blocked original prevents selection of a new console command or replacement key', async () => {
    const { h, g } = fixture(); h.assertWritable.mockImplementation(() => { throw Error('ORIGINAL_UNRESOLVED_RELEASE_WRITE_NO_REPLAY'); });
    await expect(currentPortalConsoleWrite(h, g, 'settings', `/clusters/${g.clusterId}/portal/settings?workspaceId=${g.workspaceId}`, 'POST', {})).rejects.toThrow('NO_REPLAY');
    expect(g.consoleOperations).toEqual({}); expect(h.once).not.toHaveBeenCalled();
  });
});

describe('isolated developer cookie jar and exact original HTTP packet', () => {
  it('saves developer body/cookie/CSRF privately before one same-BFF transport', async () => {
    const { h, g, tenant } = fixture(), body = { ...tenant, name: 'Synthetic application' };
    const transport = vi.fn(async (url, options) => {
      expect(url).toBe(`${h.base}/portal/applications`); expect(options.redirect).toBe('manual');
      expect(options.headers['X-Portal-CSRF']).toBe('SyntheticPortalCSRF');
      expect(options.headers.Cookie).toBeUndefined(); expect(options.headers['X-CSRF-Token']).toBeUndefined();
      expect(h.state.requests[0]).toMatchObject({ transport: 'portal-http', state: 'prepared', body });
      return json({ entity: { id: randomUUID() } });
    }); vi.stubGlobal('fetch', transport);
    await currentPortalHttpOnce(h, g, 'new-app', '/applications', 'POST', body);
    expect(h.state.requests[0].state).toBe('response_observed'); expect(h.state.requests[0].status).toBe(201);
    await expect(currentPortalHttpOnce(h, g, 'new-app', '/applications', 'POST', body)).rejects.toThrow('NO_REPLAY');
    expect(transport).toHaveBeenCalledOnce();
  });
  it.each(['network', 'invalid-json', 'oversized'])('retains unknown %s without retrying or replacing the selected packet', async failure => {
    const { h, g, tenant } = fixture();
    vi.stubGlobal('fetch', vi.fn(async () => {
      if (failure === 'network') throw Error('SyntheticNetwork');
      if (failure === 'invalid-json') return new Response('untrusted response', { status: 201 });
      return json({ content: 'x'.repeat(129 * 1024) });
    }));
    await expect(currentPortalHttpOnce(h, g, 'original', '/requests', 'POST', tenant)).rejects.toThrow();
    const original = structuredClone(h.state.requests[0]); expect(original.state).toBe('response_unknown');
    await expect(currentPortalHttpOnce(h, g, 'original', '/requests', 'POST', tenant)).rejects.toThrow('NO_REPLAY');
    expect(h.state.requests[0]).toEqual(original); expect(fetch).toHaveBeenCalledOnce();
  });
  it('keeps an observed denied response observed and refuses its old label', async () => {
    const { h, g, tenant } = fixture(); vi.stubGlobal('fetch', vi.fn(async () => json({ error: 'SyntheticDenied' }, 403)));
    await expect(currentPortalHttpOnce(h, g, 'denied', '/requests', 'POST', tenant)).rejects.toThrow('STATUS_MISMATCH');
    expect(h.state.requests[0]).toMatchObject({ state: 'response_observed', status: 403 });
    await expect(currentPortalHttpOnce(h, g, 'denied', '/requests', 'POST', tenant)).rejects.toThrow('NO_REPLAY'); expect(fetch).toHaveBeenCalledOnce();
  });
  it('can read an original operation with an existing developer jar while all new writes remain fenced', async () => {
    const { h, g } = fixture(); h.assertWritable.mockImplementation(() => { throw Error('ORIGINAL_UNRESOLVED_RELEASE_WRITE_NO_REPLAY'); });
    vi.stubGlobal('fetch', vi.fn(async () => json({ state: 'uncertain' }, 200)));
    const path = `/operations/by-key/${randomUUID()}?${new URLSearchParams({ clusterId: g.clusterId, workspaceId: g.workspaceId })}`;
    await expect(currentPortalHttpOnce(h, g, 'read-original', path)).resolves.toEqual({ state: 'uncertain' });
    expect(h.assertWritable).not.toHaveBeenCalled();
    await expect(currentPortalHttpOnce(h, g, 'forbidden-write', '/requests', 'POST', { clusterId: g.clusterId, workspaceId: g.workspaceId })).rejects.toThrow('NO_REPLAY');
    expect(fetch).toHaveBeenCalledOnce();
  });
  it.each(['console-cookie', 'foreign-tenant', 'missing-tenant', 'encoded-traversal', 'admin-path'])('blocks %s before transport', async variant => {
    const { h, g, tenant } = fixture(); let path = '/applications', body = tenant;
    if (variant === 'console-cookie') g.developerSession.cookie = 'kongos_access=SyntheticConsoleToken';
    if (variant === 'foreign-tenant') body = { ...tenant, workspaceId: randomUUID() };
    if (variant === 'missing-tenant') body = {};
    if (variant === 'encoded-traversal') path = '/%2e%2e/auth/login';
    if (variant === 'admin-path') path = '/plugins';
    vi.stubGlobal('fetch', vi.fn()); await expect(currentPortalHttpOnce(h, g, variant, path, 'POST', body)).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled(); expect(h.state.requests).toEqual([]);
  });
  it('public report omits private password, original API key, body, cookie and CSRF', () => {
    const { h, g } = fixture(); g.password = 'SyntheticPrivatePassword'; g.issuedKey = 'SyntheticPrivateIssuedKey';
    h.state.requests.push({ method: 'POST', path: '/portal/requests', key: randomUUID(), body: { key: g.issuedKey, password: g.password },
      headers: { Cookie: 'SyntheticPrivateCookie', 'X-Portal-CSRF': 'SyntheticPrivateCSRF' }, state: 'response_observed', status: 201 });
    const report = currentPortalPublicReport(h, g, 'verify-key', true, 0), text = JSON.stringify(report);
    for (const secret of ['SyntheticPrivatePassword', 'SyntheticPrivateIssuedKey', 'SyntheticPrivateCookie', 'SyntheticPrivateCSRF']) expect(text).not.toContain(secret);
    expect(report).toMatchObject({ issueExecuteRequestInvoked: false, manualWorkerTickInvoked: false, wholeM11Accepted: false, productionDeployment: false });
  });
  it('reports a null public endpoint without claiming external access or exposing the private configuration', () => {
    const { h, g } = fixture(); g.configuration = currentPortalConfiguration({ ...env, RELEASE_LAB_M11_BUSINESS_PORTAL_PROXY_ORIGIN: 'null' }, 'preflight');
    expect(currentPortalPublicReport(h, g, 'preflight', true, 0)).toMatchObject({ publicEndpointConfigured: false, externalAccessVerified: false });
    expect(currentPortalPublicReport(h, g, 'verify-key', true, 0)).not.toHaveProperty('configuration');
  });
});
