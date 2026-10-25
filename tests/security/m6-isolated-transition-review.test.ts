import { describe, expect, it, vi } from 'vitest';
import { checkpointSha, guardIsolatedTransition, isolatedReference, validateIsolatedTransition } from './lib/m6-isolated-transition.mjs';
import { M6_C1, M6_C2 } from './lib/m6-harness.mjs';

const id = (n: number) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
function fixture() {
  const purposes = [['native_scrape', 'bff'], ['collector_catalog', 'bff'], ['collector_scrape', 'collector'], ['collector_ingest', 'collector']];
  const scopes = [[M6_C1, id(1)], [M6_C2, id(2)], [M6_C1, id(3)]];
  const tokens = [M6_C1, M6_C2].flatMap((clusterId, family) => purposes.map(([purpose, audience], index) => ({ clusterId, generation: family === 0 ? 2 : 1, purpose, audience, token: String.fromCharCode(65 + family * 4 + index).repeat(43) })));
  const reference: any = { phase: 'bootstrap', testTag: 'm6-security-old', liveStartedAt: '2026-10-10T20:00:00.000Z',
    fixtures: scopes.map(([clusterId, workspaceId]) => ({ cluster: { id: clusterId }, workspace: { id: workspaceId, code: `m6-security-old-${workspaceId}` }, publications: [{ id: id(Number(workspaceId.slice(-1)) + 10), serviceId: id(20), status: 'draft' }] })),
    boundaryRefusalProof: { workflowId: id(30), originalKey: id(31) }, consoleAdministrator: { user: { id: id(32) }, cookie: 'synthetic-test-cookie' },
    accounts: { 'approver-only': { session: { user: { id: id(33) } } } }, portalUsers: [], grants: [], tokens,
    writeAttempts: [{ key: id(34), state: 'response_observed', method: 'POST', path: `/api/v1/clusters/${M6_C1}/entities/plugins`, query: `?workspaceId=${id(1)}`, actorId: id(32), clusterId: M6_C1, workspaceId: id(1), requestId: id(35), httpStatus: 403, errorCode: 'PORTAL_UNMANAGED_AUTH_BOUNDARY', body: { name: 'acl' } }],
    fixtureJournal: [{ type: 'services', id: id(20) }], writeEvidence: [{ requestId: id(36) }], users: [{ id: id(33), username: 'old-approver' }],
    secrets: ['synthetic-private-canary'], portalSessions: [{ cookie: 'synthetic-portal-cookie' }],
    unknownAdditionalCheckpoint: { failedOriginalKey: id(31), nested: { preserved: true } },
    metricsProof: { activeFamilies: [{ clusterId: M6_C1, generation: 2 }, { clusterId: M6_C2, generation: 1 }] },
    priorFixtureRuns: [{ testTag: 'even-older', checkpoint: { originalProof: true }, checkpointSha256: checkpointSha({ originalProof: true }) }] };
  const evidence: any = { performedAt: '2026-10-10T22:00:00.000Z', ownedScopes: scopes.map(([clusterId, workspaceId]) => ({ clusterId, workspaceId })), publicationKey: id(31),
    publicationReceipt: { workflowId: id(30), state: 'failed', steps: [{ state: 'failed', remoteCompleted: false }, { state: 'pending', remoteCompleted: false }, { state: 'pending', remoteCompleted: false }] },
    aclKey: id(34), aclReceipt: { state: 'failed', remoteStarted: true, remoteCompleted: false, entityId: null }, oldFacts: { grants: 0, issuedCredentials: 0, credentialRefs: 0, completedNative: 0, unresolvedNative: 0, metadataApplied: 0 } };
  const targets: any = { primary: { id: id(40), adminUrl: 'http://kong-portal-admin-endpoint:8001', proxyOrigin: 'http://127.0.0.1:10000' }, secondary: { id: M6_C2, adminUrl: 'http://kong-secondary:8001', proxyOrigin: 'http://127.0.0.1:9000' } };
  return { reference, evidence, targets };
}
function harness(f: ReturnType<typeof fixture>, currentFacts = f.evidence.oldFacts) {
  const request = vi.fn(async (_actor: unknown, path: string, method = 'GET') => {
    if (method !== 'GET') throw new Error('Independent transition fixture forbids replay of old POST writes');
    if (path === '/auth/me') return { status: 200, value: { user: f.reference.consoleAdministrator.user } };
    if (path.includes('/workflows/receipts/by-key/')) return { status: 200, value: f.evidence.publicationReceipt };
    if (path.includes('/mutations/by-key/')) return { status: 200, value: { state: 'failed', remoteCompleted: false } };
    const saved = f.reference.fixtures.find((row: any) => path.includes(`/workspaces/${row.workspace.id}`));
    if (saved) return { status: 200, value: saved.workspace };
    if (path.includes('/portal/publications/')) { const publication = f.reference.fixtures.flatMap((row: any) => row.publications).find((row: any) => path.includes(row.id)); return { status: 200, value: publication }; }
    const target = [f.targets.primary, f.targets.secondary].find(row => path === `/clusters/${row.id}`);
    if (target) return { status: 200, value: { id: target.id, admin_url: target.adminUrl, version: '1.5.1' } };
    throw new Error('Unexpected transition fixture read');
  });
  const h: any = { referenceData: f.reference, requireLive: vi.fn(), request,
    ok: (result: any) => { if (result.status !== 200) throw new Error('Read not authorized'); return result.value; },
    check: (passed: boolean) => { if (!passed) throw new Error('Fresh transition proof failed'); },
    consoleRead: vi.fn((sql: string) => {
      if (!/^SELECT\b/.test(sql.trim())) throw new Error('Transition source query must be read only');
      return sql.startsWith('SELECT state,') ? [{ state: 'failed', remote_started: true, remote_completed: false, entity_id: null }] : [currentFacts];
    }), saveReference: vi.fn((extra: object) => Object.assign(f.reference, extra)) };
  return h;
}

describe('M6 independent isolated acceptance transition', () => {
  it('preserves the entire old checkpoint by value and hash, plus every global recovery and metrics journal', () => {
    const f = fixture(), original = structuredClone(f.reference), digest = checkpointSha(original);
    const result = isolatedReference(f.reference, f.evidence, f.targets, 'm6-isolated-new-run');
    expect(f.reference).toEqual(original);
    expect(result.priorFixtureRuns.at(-1)).toEqual({ testTag: original.testTag, checkpoint: original, checkpointSha256: digest });
    expect(result.isolatedStart.previousCheckpointSha256).toBe(digest);
    for (const name of ['fixtureJournal', 'writeAttempts', 'writeEvidence', 'users', 'secrets', 'tokens', 'portalSessions', 'metricsProof', 'unknownAdditionalCheckpoint']) expect(result[name]).toEqual(original[name]);
    expect(result.priorFixtureRuns[0]).toEqual(original.priorFixtureRuns[0]);
    expect(result.fixtures).toEqual([]); expect(result.accounts).toEqual({}); expect(result.phase).toBe('isolatedFixtureStart');
    result.fixtures.push({ newlyCreated: true }); result.accounts.newActor = { id: id(50) };
    expect(result.priorFixtureRuns.at(-1).checkpoint).toEqual(original);
    expect(checkpointSha(result.priorFixtureRuns.at(-1).checkpoint)).toBe(digest);
    expect(result.writeAttempts[0].key).toBe(id(34));
  });
  it('keeps the canonical eight metrics tokens scoped to C1/C2; creates no C3 family or material', () => {
    const f = fixture(), result = isolatedReference(f.reference, f.evidence, f.targets, 'm6-isolated-new-run');
    expect(result.tokens).toHaveLength(8); expect(result.tokens.filter((row: any) => row.clusterId === f.targets.primary.id)).toHaveLength(0);
    expect(new Set(result.tokens.map((row: any) => row.clusterId))).toEqual(new Set([M6_C1, M6_C2]));
    expect(result.secrets).toEqual(f.reference.secrets);
  });
  it.each(['grants', 'issuedCredentials', 'credentialRefs', 'completedNative', 'unresolvedNative', 'metadataApplied'])('refuses to reset fixture scope when old %s facts are nonzero', field => {
    const f = fixture(); f.evidence.oldFacts[field] = 1;
    expect(() => isolatedReference(f.reference, f.evidence, f.targets, 'm6-isolated-new-run')).toThrow();
    expect(f.reference.phase).toBe('bootstrap'); expect(f.reference.writeAttempts[0].key).toBe(id(34));
  });
  it.each(['pending', 'approved', 'executing', 'partial', 'uncertain', 'succeeded'])('rejects old publication %s rather than treating a new tag as recovery', state => {
    const f = fixture(); f.evidence.publicationReceipt.state = state;
    expect(() => validateIsolatedTransition(f.reference, f.evidence, f.targets)).toThrow();
  });
  it.each(['unknown-child', 'completed-child', 'completed-acl', 'uncertain-acl', 'allocated-acl-id', 'foreign-workflow', 'foreign-original-key', 'foreign-owned-scope', 'missing-zero-proof'])('rejects incomplete or changed old acknowledgement proof: %s', variant => {
    const f = fixture();
    if (variant === 'unknown-child') f.evidence.publicationReceipt.steps[0].state = 'uncertain';
    if (variant === 'completed-child') f.evidence.publicationReceipt.steps[0].remoteCompleted = true;
    if (variant === 'completed-acl') f.evidence.aclReceipt.remoteCompleted = true;
    if (variant === 'uncertain-acl') f.evidence.aclReceipt.state = 'uncertain';
    if (variant === 'allocated-acl-id') f.evidence.aclReceipt.entityId = id(60);
    if (variant === 'foreign-workflow') f.evidence.publicationReceipt.workflowId = id(61);
    if (variant === 'foreign-original-key') f.evidence.publicationKey = id(62);
    if (variant === 'foreign-owned-scope') f.evidence.ownedScopes[0].workspaceId = id(63);
    if (variant === 'missing-zero-proof') delete f.evidence.oldFacts.unresolvedNative;
    expect(() => validateIsolatedTransition(f.reference, f.evidence, f.targets)).toThrow();
  });
  it.each(['generation', 'purpose', 'audience', 'duplicate', 'missing', 'foreign-c3'])('rejects a changed canonical metrics family: %s', variant => {
    const f = fixture();
    if (variant === 'generation') f.reference.tokens[0].generation = 3;
    if (variant === 'purpose') f.reference.tokens[0].purpose = 'collector_ingest';
    if (variant === 'audience') f.reference.tokens[0].audience = 'collector';
    if (variant === 'duplicate') f.reference.tokens[0].token = f.reference.tokens[1].token;
    if (variant === 'missing') f.reference.tokens.pop();
    if (variant === 'foreign-c3') f.reference.tokens[0].clusterId = f.targets.primary.id;
    expect(() => validateIsolatedTransition(f.reference, f.evidence, f.targets)).toThrow();
  });
  it.each(['http://kong:8001/', 'http://kong-secondary:8001/', 'http://kong-secondary:8001', 'http://KONG:8001', 'http://127.0.0.1:8001', 'http://arbitrary-admin:8001'])('rejects an old or unproved physical endpoint %s as C3', adminUrl => {
    const f = fixture(); f.targets.primary.adminUrl = adminUrl;
    expect(() => validateIsolatedTransition(f.reference, f.evidence, f.targets)).toThrow();
  });
  it.each([M6_C1, M6_C2, 'not-a-cluster-uuid'])('requires a new typed C3 ID: %s', clusterId => {
    const f = fixture(); f.targets.primary.id = clusterId;
    expect(() => validateIsolatedTransition(f.reference, f.evidence, f.targets)).toThrow();
  });
  it.each(['m6-security-old', 'same-tag', 'm6-isolated-../path', 'm6-isolated-New'])('rejects an ambiguous or unsafe new fixture tag %s', tag => {
    const f = fixture(); expect(() => isolatedReference(f.reference, f.evidence, f.targets, tag)).toThrow();
  });
  it('refuses invalid transition before any request, source query, or checkpoint mutation', async () => {
    const f = fixture(); f.evidence.oldFacts.unresolvedNative = 1;
    const h: any = { referenceData: f.reference, requireLive: vi.fn(), request: vi.fn(), consoleRead: vi.fn(), saveReference: vi.fn() };
    await expect(guardIsolatedTransition(h, f.evidence, f.targets)).rejects.toThrow();
    expect(h.request).not.toHaveBeenCalled(); expect(h.consoleRead).not.toHaveBeenCalled(); expect(h.saveReference).not.toHaveBeenCalled();
  });
  it('rechecks original receipts and zero-issued facts using GET/SELECT only and never replays either old key', async () => {
    const f = fixture(), h = harness(f), originalAttempts = structuredClone(f.reference.writeAttempts);
    const result = await guardIsolatedTransition(h, f.evidence, f.targets);
    expect(result.oldFacts).toEqual(f.evidence.oldFacts);
    expect(h.request.mock.calls.every((row: any[]) => row[2] === undefined || row[2] === 'GET')).toBe(true);
    expect(h.request.mock.calls.some((row: any[]) => row[1].includes(`/by-key/${id(31)}`))).toBe(true);
    expect(h.request.mock.calls.some((row: any[]) => row[1].includes(`/by-key/${id(34)}`))).toBe(true);
    expect(h.consoleRead).toHaveBeenCalledTimes(2); expect(h.saveReference).toHaveBeenCalledTimes(1);
    expect(f.reference.writeAttempts).toEqual(originalAttempts); expect(f.reference.phase).toBe('bootstrap');
  });
  it('stops when a current unknown appears after the prior evidence snapshot; does not replace the canonical checkpoint', async () => {
    const f = fixture(), h = harness(f, { ...f.evidence.oldFacts, unresolvedNative: 1 });
    await expect(guardIsolatedTransition(h, f.evidence, f.targets)).rejects.toThrow();
    expect(h.saveReference).not.toHaveBeenCalled(); expect(f.reference.phase).toBe('bootstrap');
    expect(h.request.mock.calls.every((row: any[]) => row[2] === undefined || row[2] === 'GET')).toBe(true);
    expect(h.request.mock.calls.some((row: any[]) => row[1] === `/clusters/${f.targets.primary.id}`)).toBe(false);
  });
});
