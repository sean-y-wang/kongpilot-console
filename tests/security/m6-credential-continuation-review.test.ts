import { describe, expect, it, vi } from 'vitest';
import { credentialContinuationCheckpoint, guardCredentialContinuation, originalPortalSession } from './lib/m6-credential-continuation.mjs';
import { M6_C1, M6_C2 } from './lib/m6-harness.mjs';

const id = (n: number) => `30000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
function fixture() {
  const tag = 'm6-isolated-independent', c3 = id(1);
  const fixtures = [c3, M6_C2, c3].map((clusterId, index) => ({ cluster: { id: clusterId }, workspace: { id: id(10 + index), code: `${tag}-${index}`, revision: 1, status: 'active' }, settings: { id: id(20 + index), revision: 2, published: true },
    services: [{ id: id(30 + index), name: `service-${index}`, host: 'echo-upstream', port: 8081, tags: ['kos-ws-test'] }], routes: [{ id: id(40 + index), name: `route-${index}`, paths: [`/owned-${index}`], service: { id: id(30 + index) } }],
    publications: [{ id: id(50 + index), serviceId: id(30 + index), revision: 5, documentRevision: 2, status: 'published' }] }));
  const developers = ['developer-a', 'developer-b', 'developer-c2'].map((label, index) => {
    const f = fixtures[index === 2 ? 1 : 0], tenant = { clusterId: f.cluster.id, workspaceId: f.workspace.id }, developerId = id(60 + index);
    return { id: developerId, label, tenant, session: { developer: { id: developerId, ...tenant }, cookie: `synthetic-cookie-${index}`, csrf: `synthetic-old-csrf-${index}` } };
  });
  const app = { id: id(70), name: `${tag} Application A`, revision: 1 }, c2App = { id: id(71), name: `${tag} Application C2`, revision: 1 };
  const attempt = { method: 'POST', path: '/api/v1/portal/requests', key: id(80), requestId: id(81), actorId: developers[0].id, state: 'response_observed', httpStatus: 409, errorCode: 'PORTAL_PUBLICATION_REVALIDATION_REQUIRED', body: { ...developers[0].tenant, applicationId: app.id, publicationId: fixtures[0].publications[0].id, reason: 'Independent controlled continuation' } };
  const plugins = ['key-auth', 'acl'].map((name, index) => ({ id: id(90 + index), name, service: { id: fixtures[0].services[0].id }, enabled: true, config: { safeFlag: true } }));
  const appAttempts = [app, c2App].map((value, index) => ({ path: '/api/v1/portal/applications', actorId: developers[index === 0 ? 0 : 2].id, body: { name: value.name }, state: 'response_observed', httpStatus: 201, responseData: { entity: value } }));
  const pluginAttempts = plugins.map(value => ({ path: `/api/v1/clusters/${c3}/entities/plugins`, query: `?workspaceId=${fixtures[0].workspace.id}`, state: 'response_observed', httpStatus: 201, responseData: { entity: value } }));
  const diagnostic: any = { originalRequest: { key: attempt.key, requestId: attempt.requestId }, originalReceipt: { status: 200, state: 'failed', safeResultKeys: [] }, facts: [{ grants: 0, credentials: 0, unresolved: 0 }], currentProofComparison: { effectiveComputedMatchesPublishedProof: true, publicationMatchesPublishedProof: true, clusterRevisionMatches: true, workspaceRevisionMatches: true, workspaceActive: true } };
  const purposes = [['native_scrape', 'bff'], ['collector_catalog', 'bff'], ['collector_scrape', 'collector'], ['collector_ingest', 'collector']];
  const reference: any = { testTag: tag, phase: 'portal-publications-published', isolatedStart: { previousCheckpointSha256: 'a'.repeat(64) },
    portalTestTargets: { primary: { id: c3, adminUrl: 'http://kong-portal-admin-endpoint:8001', proxyOrigin: 'http://127.0.0.1:10000' }, secondary: { id: M6_C2, proxyOrigin: 'http://127.0.0.1:9000' } },
    fixtures, grants: [], consoleAdministrator: { user: { id: id(100) } }, accounts: { 'approver-only': { session: { user: { id: id(101) } } }, 'approver-c2': { session: { user: { id: id(102) } } } },
    portalUsers: developers, writeAttempts: [...appAttempts, ...pluginAttempts, attempt], isolatedPublicationRequestFailure: structuredClone(diagnostic),
    tokens: [M6_C1, M6_C2].flatMap((clusterId, family) => purposes.map(([purpose, audience], i) => ({ clusterId, generation: family === 0 ? 2 : 1, purpose, audience, token: String.fromCharCode(65 + family * 4 + i).repeat(43) }))) };
  return { reference, diagnostic, attempt, plugins, app, c2App };
}
function harness() {
  const f = fixture();
  const h: any = { referenceData: f.reference, requireLive: vi.fn(), check: (passed: boolean) => { if (!passed) throw new Error('Current continuation proof failed'); },
    ok: (result: any) => { if (result.status < 200 || result.status >= 300) throw new Error('Response not successful'); return result.value; },
    saveReference: vi.fn((extra: any) => Object.assign(f.reference, extra)), rememberCookies: vi.fn(), secrets: [] };
  h.request = vi.fn(async (session: any, path: string, method = 'GET') => {
    if (method !== 'GET') throw new Error('Continuation must not repeat console writes');
    if (path === '/auth/me') return { status: 200, value: { id: session.user.id } };
    for (const row of f.reference.fixtures) {
      if (path.includes(`/workspaces/${row.workspace.id}`)) return { status: 200, value: row.workspace };
      if (new URL(path, 'http://synthetic.invalid').searchParams.get('workspaceId') !== row.workspace.id) continue;
      if (path.includes('/portal/settings')) return { status: 200, value: { settings: row.settings } };
      for (const type of ['services', 'routes', 'publications']) for (const item of row[type]) if (path.includes(`/${item.id}?`)) return { status: 200, value: { entity: item } };
      for (const item of f.plugins) if (path.includes(`/plugins/${item.id}?`)) return { status: 200, value: { entity: item } };
    }
    throw new Error('Unexpected synthetic console GET');
  });
  h.portal = vi.fn(async (session: any, path: string, method = 'GET') => {
    if (method !== 'GET') throw new Error('Guard may not submit requests or rebuild fixture');
    if (path.includes('/auth/me')) return { status: 200, value: session.developer };
    if (path.includes('/operations/by-key/')) return { status: 200, value: { state: 'failed', errorCode: 'PORTAL_PUBLICATION_REVALIDATION_REQUIRED', safeResult: {}, remoteStarted: true, remoteCompleted: true } };
    for (const app of [f.app, f.c2App]) if (path.includes(`/applications/${app.id}?`)) return { status: 200, value: { entity: app } };
    throw new Error('Unexpected synthetic Portal GET');
  });
  h.consoleRead = vi.fn((sql: string) => {
    if (!sql.startsWith('SELECT')) throw new Error('Continuation must not rewrite durable ledgers');
    return sql.includes('AS grants') ? [{ grants: 0, credentials: 0, developer_workflows: 0, native_unresolved: 0, portal_unresolved: 0 }] : [{ state: 'failed', error_code: 'PORTAL_PUBLICATION_REVALIDATION_REQUIRED', workflow_id: null, no_result: true, safe_result: {}, remote_started: true, remote_completed: true }];
  });
  return { h, ...f };
}
function refreshFixture(unknown = false) {
  const f = fixture(), developer = f.reference.portalUsers[0], sid = id(110), oldCsrf = 'synthetic-old-csrf'.repeat(2), newCsrf = 'synthetic-new-csrf'.repeat(2);
  developer.session.cookie = `kongos_portal_refresh=${sid}.old-refresh; kongos_portal_access=expired; kongos_portal_csrf=${oldCsrf}`; developer.session.csrf = oldCsrf;
  const h: any = { referenceData: f.reference, secrets: [], rememberCookies: vi.fn(), saveReference: vi.fn((extra: any) => Object.assign(f.reference, extra)),
    check: (passed: boolean) => { if (!passed) throw new Error('Original Portal actor or session changed'); }, ok: (result: any) => { if (result.status !== 200 && result.status !== 201) throw new Error('Refresh failed'); return result.value; } };
  let meCalls = 0;
  h.portal = vi.fn(async (_session: any, path: string, method = 'GET') => {
    if (path.includes('/auth/me')) return ++meCalls === 1 ? { status: 401 } : { status: 200, value: developer.session.developer };
    if (path.includes('/auth/csrf')) return { status: 200, value: { csrfToken: oldCsrf } };
    if (path !== '/auth/refresh' || method !== 'POST') throw new Error('Unexpected refresh request');
    expect(f.reference.originalPortalRefreshes.at(-1).sessionId).toBe(sid);
    if (unknown) throw new Error('Refresh acknowledgement lost');
    const access = `header.${Buffer.from(JSON.stringify({ sid })).toString('base64url')}.signature`;
    const response = new Response('');
    response.headers.append('Set-Cookie', `kongos_portal_access=${access}; HttpOnly; SameSite=Strict`);
    response.headers.append('Set-Cookie', `kongos_portal_refresh=${sid}.new-refresh; HttpOnly; SameSite=Strict`);
    response.headers.append('Set-Cookie', `kongos_portal_csrf=${newCsrf}; HttpOnly; SameSite=Strict`);
    return { status: 201, value: { developer: developer.session.developer, csrfToken: newCsrf }, response };
  });
  return { h, developer, newCsrf, oldCsrf };
}

describe('M6 independent credential continuation guard', () => {
  it('checks existing identities, configuration and dual-cluster ledgers read-only, then persists exactly one new request key without changing the failed key', async () => {
    const f = harness(), originalAttempts = structuredClone(f.reference.writeAttempts), originalTokens = structuredClone(f.reference.tokens);
    const context = await guardCredentialContinuation(f.h, f.diagnostic);
    expect(context.initialRequest.key).not.toBe(f.attempt.key); expect(context.initialRequest.body).toEqual(f.attempt.body);
    expect(f.reference.credentialContinuation).toMatchObject({ phase: 'before-single-new-request', originalFailedKey: f.attempt.key, newKey: context.initialRequest.key, originalReceiptState: 'failed' });
    expect(f.h.saveReference).toHaveBeenCalledTimes(1); expect(f.h.portal.mock.calls.every((row: any[]) => row[2] === undefined || row[2] === 'GET')).toBe(true);
    expect(f.h.request.mock.calls.every((row: any[]) => row[2] === undefined || row[2] === 'GET')).toBe(true);
    expect(f.h.consoleRead.mock.calls[0][1][2]).toEqual([M6_C1, M6_C2, f.reference.fixtures[0].cluster.id]);
    expect(f.reference.writeAttempts).toEqual(originalAttempts); expect(f.reference.tokens).toEqual(originalTokens);
    await expect(guardCredentialContinuation(f.h, f.diagnostic)).rejects.toThrow(); expect(f.h.saveReference).toHaveBeenCalledTimes(1);
  });
  it.each(['grants', 'credentials', 'developer_workflows', 'native_unresolved', 'portal_unresolved'])('refuses a new key when current %s facts appear after the old diagnostic', async field => {
    const f = harness(), read = f.h.consoleRead.getMockImplementation();
    f.h.consoleRead.mockImplementation((sql: string, args: any[]) => { const value = read(sql, args); if (sql.includes('AS grants')) value[0][field] = 1; return value; });
    await expect(guardCredentialContinuation(f.h, f.diagnostic)).rejects.toThrow(); expect(f.h.saveReference).not.toHaveBeenCalled();
    expect(f.reference.credentialContinuation).toBeUndefined();
  });
  it.each(['failed-key-workflow', 'failed-key-result', 'failed-key-uncertain', 'portal-actor', 'workspace-revision', 'publication-revision', 'application-revision', 'legacy-config'])('stops on changed existing proof %s, with no saved remediation key or writes', async variant => {
    const f = harness();
    if (variant.startsWith('failed-key-')) {
      const read = f.h.consoleRead.getMockImplementation(); f.h.consoleRead.mockImplementation((sql: string, args: any[]) => {
        const value = read(sql, args); if (!sql.includes('AS grants')) { if (variant === 'failed-key-workflow') value[0].workflow_id = id(120); if (variant === 'failed-key-result') value[0].no_result = false; if (variant === 'failed-key-uncertain') value[0].state = 'uncertain'; } return value;
      });
    } else if (variant === 'portal-actor' || variant === 'application-revision') {
      const read = f.h.portal.getMockImplementation(); f.h.portal.mockImplementation(async (...args: any[]) => {
        const result = await read(...args); if (variant === 'portal-actor' && args[1].includes('/auth/me')) result.value = { ...result.value, id: id(121) };
        if (variant === 'application-revision' && args[1].includes('/applications/')) result.value = { entity: { ...result.value.entity, revision: 3 } }; return result;
      });
    } else {
      const read = f.h.request.getMockImplementation(); f.h.request.mockImplementation(async (...args: any[]) => {
        const result = await read(...args);
        if (variant === 'workspace-revision' && args[1].includes('/workspaces/')) result.value = { ...result.value, revision: 2 };
        if (variant === 'publication-revision' && args[1].includes('/portal/publications/')) result.value = { entity: { ...result.value.entity, revision: 6 } };
        if (variant === 'legacy-config' && args[1].includes('/entities/plugins/')) result.value = { entity: { ...result.value.entity, config: { anonymous: 'changed' } } };
        return result;
      });
    }
    await expect(guardCredentialContinuation(f.h, f.diagnostic)).rejects.toThrow(); expect(f.h.saveReference).not.toHaveBeenCalled();
    expect(f.h.portal.mock.calls.every((row: any[]) => row[2] === undefined || row[2] === 'GET')).toBe(true);
  });
  it('rejects incomplete or swapped old diagnostic rather than treating HTTP409 as general retry permission', () => {
    const f = fixture();
    for (const diagnostic of [{ ...f.diagnostic, originalRequest: { ...f.diagnostic.originalRequest, key: id(130) } }, { ...f.diagnostic, currentProofComparison: { ...f.diagnostic.currentProofComparison, workspaceRevisionMatches: false } }]) expect(() => credentialContinuationCheckpoint(f.reference, diagnostic)).toThrow();
    const changed = structuredClone(f.reference); changed.writeAttempts.push({ ...f.attempt, key: id(131), state: 'response_unknown' }); expect(() => credentialContinuationCheckpoint(changed, f.diagnostic)).toThrow();
  });
});

describe('M6 independent original Portal refresh compatibility', () => {
  it('uses the real refresh shape to replace the next request header with the rotated CSRF value while preserving actor, tenant and SID', async () => {
    const f = refreshFixture(); const current = await originalPortalSession(f.h, f.developer);
    expect(current.csrf).toBe(f.newCsrf); expect(current.csrf).not.toBe(f.oldCsrf);
    expect(current.cookie).toContain(`kongos_portal_csrf=${f.newCsrf}`);
    expect(current.cookie).toContain(`kongos_portal_refresh=${id(110)}.new-refresh`);
    expect(f.h.portal.mock.calls.filter((row: any[]) => row[1] === '/auth/refresh')).toHaveLength(1);
    expect(f.h.referenceData.originalPortalRefreshes.at(-1).sessionId).toBe(id(110));
    expect(f.h.saveReference).toHaveBeenCalledTimes(2);
  });
  it('never sends another request or changes the old cookie after an unknown refresh acknowledgement', async () => {
    const f = refreshFixture(true), cookie = f.developer.session.cookie;
    await expect(originalPortalSession(f.h, f.developer)).rejects.toThrow('acknowledgement lost');
    expect(f.h.portal.mock.calls.map((row: any[]) => row[1].split('?')[0])).toEqual(['/auth/me', '/auth/csrf', '/auth/refresh']);
    expect(f.developer.session.cookie).toBe(cookie); expect(f.h.saveReference).toHaveBeenCalledTimes(1);
  });
});
