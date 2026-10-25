import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { describe, expect, it, vi } from 'vitest';
import { manualReadContract, manualReadPacketMatches, mergeManualWriteEvidence, validateManualReadEvidence } from './lib/m6-manual-read-evidence.mjs';

function fixture(kind: string) {
  const clusterId = randomUUID(), workspaceId = randomUUID(), applicationId = randomUUID(), developerId = randomUUID(), publicationId = randomUUID(), grantId = randomUUID(), workflowId = randomUUID();
  const expected: any = { kind, clusterId, workspaceId, id: kind === 'developer' ? developerId : applicationId, username: 'offline-developer', developerId, publicationId, grantId, workflowId };
  const createdAt = '2026-10-11T10:00:00.000Z';
  let data: any;
  if (kind === 'developer') data = { entity: { id: developerId, clusterId, workspaceId, username: expected.username, email: 'offline@example.invalid', displayName: 'Offline Developer', status: 'active', revision: 1, mustChangePassword: false, createdAt } };
  else if (kind === 'application') data = { entity: { id: applicationId, clusterId, workspaceId, developerId, name: 'Offline Application', description: '', state: 'active', revision: 1, createdAt, capabilities: { readGrants: true, readRequests: true } } };
  else {
    const row = kind === 'catalog' ? { id: publicationId, clusterId, workspaceId, name: 'Offline Published API', slug: 'offline-api', description: '', category: null, revision: 1, documentRevision: 1, status: 'published', auth: { type: 'key-auth', credentialScope: 'application_publication', accessScope: 'whole_service', keyNames: ['apikey'] } }
      : kind === 'grants' ? { id: grantId, applicationId, publicationId, publicationName: 'Offline Published API', state: 'active', generation: 1, revision: 1, reservationReleased: false, createdAt }
        : { id: workflowId, clusterId, workspaceId, applicationId, grantId, publicationId, kind: 'portal-credential-issue', state: 'succeeded', revision: 1, executionMode: 'approval', approvalRequired: true, createdAt, expiresAt: '2026-10-12T10:00:00.000Z' };
    data = { items: [row], size: 20, total: null, nextCursor: null, ...(kind === 'catalog' ? { scanIncomplete: false, searchedRows: 1 } : {}) };
  }
  const contract = manualReadContract(expected), packet = { method: 'GET', url: `${contract.origin}${contract.path}?${new URLSearchParams(contract.query)}` }, payload = { meta: { requestId: randomUUID() }, data };
  return { expected, packet, payload, validate: () => validateManualReadEvidence(packet, 200, payload, expected) };
}

describe('manual current-tenant readonly DOM response evidence', () => {
  it.each(['catalog', 'developer', 'application', 'grants', 'requests'])('accepts actual %s safe DTO with original CID/WID and records safe metadata only', kind => {
    const f = fixture(kind), result = f.validate();
    expect(result.data).toBe(f.payload.data); expect(result.evidence).toMatchObject({ kind, method: 'GET', clusterId: f.expected.clusterId, workspaceId: f.expected.workspaceId, requestId: f.payload.meta.requestId, safeDto: true });
    expect(result.evidence).not.toHaveProperty('data'); expect(result.evidence).not.toHaveProperty('headers'); expect(result.evidence).not.toHaveProperty('username');
  });
  it.each(['POST', 'wrong-origin', 'wrong-path', 'missing-workspace', 'duplicate-workspace', 'wrong-workspace', 'extra-query', 'credentials-in-url', 'fragment'])('rejects %s instead of accepting a tab click or wrong-scope response', reason => {
    const f = fixture('application'), url = new URL(f.packet.url);
    if (reason === 'POST') f.packet.method = 'POST';
    if (reason === 'wrong-origin') url.port = '8001';
    if (reason === 'wrong-path') url.pathname = url.pathname.replace(f.expected.id, randomUUID());
    if (reason === 'missing-workspace') url.searchParams.delete('workspaceId');
    if (reason === 'duplicate-workspace') url.searchParams.append('workspaceId', f.expected.workspaceId);
    if (reason === 'wrong-workspace') url.searchParams.set('workspaceId', randomUUID());
    if (reason === 'extra-query') url.searchParams.set('reveal', 'true');
    if (reason === 'credentials-in-url') url.username = 'offline-user';
    if (reason === 'fragment') url.hash = 'ignored';
    f.packet.url = url.href;
    expect(manualReadPacketMatches(f.packet, f.expected)).toBe(false); expect(f.validate).toThrow('M6_MANUAL_READ_EVIDENCE_INVALID');
  });
  it.each(['developer', 'application', 'catalog', 'requests'])('checks %s entity CID/WID independently of correct request query', kind => {
    const f = fixture(kind), row = f.payload.data.entity ?? f.payload.data.items[0]; row.workspaceId = randomUUID(); expect(f.validate).toThrow();
  });
  it.each(['password', 'passwordHash', 'apiKey', 'key', 'accessToken', 'refreshToken', 'credentials', 'nativeConsumer'])('rejects an unexpected %s field in the purported safe DTO', field => {
    for (const kind of ['developer', 'application', 'catalog', 'grants', 'requests']) { const f = fixture(kind), row = f.payload.data.entity ?? f.payload.data.items[0]; row[field] = 'offline-unexpected'; expect(f.validate).toThrow(); }
  });
  it('requires current developer identity and application ownership/capabilities', () => {
    const developer = fixture('developer'); developer.payload.data.entity.username = 'other-offline-developer'; expect(developer.validate).toThrow();
    const app = fixture('application'); app.payload.data.entity.developerId = randomUUID(); expect(app.validate).toThrow();
    const capability = fixture('application'); capability.payload.data.entity.capabilities.readRequests = false; expect(capability.validate).toThrow();
  });
  it('selects the exact current active grant, preserving historical revoked/disabled grants rather than selecting publication name first', () => {
    const f = fixture('grants'), current = f.payload.data.items[0];
    f.payload.data.items.unshift({ ...current, id: randomUUID(), state: 'revoked', generation: 1 }, { ...current, id: randomUUID(), state: 'disabled', generation: 0, reservationReleased: true });
    expect(f.validate().target).toBe(current);
    current.state = 'revoked'; expect(f.validate).toThrow();
  });
  it.each(['application', 'grant', 'publication', 'workflow', 'state'])('requires the actual completed application-request %s relation', relation => {
    const f = fixture('requests'), row = f.payload.data.items[0];
    row[({ application: 'applicationId', grant: 'grantId', publication: 'publicationId', workflow: 'id', state: 'state' } as any)[relation]] = relation === 'state' ? 'approved' : randomUUID(); expect(f.validate).toThrow();
  });
  it('uses a real published category only when the actual catalog response supplies it', () => {
    const f = fixture('catalog'); f.expected.category = 'Offline Category'; f.payload.data.items[0].category = f.expected.category;
    const contract = manualReadContract(f.expected); f.packet.url = `${contract.origin}${contract.path}?${new URLSearchParams(contract.query)}`;
    expect(f.validate().evidence.filter).toBe('category');
    f.payload.data.items[0].category = 'Other Category'; expect(f.validate).toThrow();
  });
  it('keeps cluster execution mode independent from credential approval requirement', () => {
    const f = fixture('requests'); f.payload.data.items[0].executionMode = 'direct';
    expect(f.validate().target.approvalRequired).toBe(true);
  });
  it('searches the actual publication name with all categories when the current fixture is unclassified, without invented metadata', () => {
    const f = fixture('catalog'); f.expected.search = f.payload.data.items[0].name;
    const contract = manualReadContract(f.expected); f.packet.url = `${contract.origin}${contract.path}?${new URLSearchParams(contract.query)}`;
    expect(new URL(f.packet.url).searchParams.has('category')).toBe(false); expect(f.validate().evidence.filter).toBe('search-all-categories');
    f.payload.data.items[0].description = f.expected.search; f.payload.data.items[0].name = 'Unrelated API'; expect(f.validate).toThrow();
  });
  it('retains actual incomplete scan information and unknown total instead of claiming complete catalog results', () => {
    const f = fixture('catalog'); f.payload.data.scanIncomplete = true; f.payload.data.nextCursor = 'opaque-offline-cursor';
    expect(f.validate().evidence).toMatchObject({ scanIncomplete: true, totalUnknown: true });
    f.payload.data.total = 1; expect(f.validate).toThrow();
  });
  it.each(['duplicate-row', 'missing-target', 'oversized-page', 'no-request-id', 'HTTP-403', 'unexpected-page-field'])('refuses %s as real detail evidence', reason => {
    const f = fixture('grants');
    if (reason === 'duplicate-row') f.payload.data.items.push({ ...f.payload.data.items[0] });
    if (reason === 'missing-target') f.payload.data.items = [];
    if (reason === 'oversized-page') f.payload.data.items = Array.from({ length: 21 }, (_, i) => ({ ...f.payload.data.items[0], id: i === 0 ? f.expected.grantId : randomUUID() }));
    if (reason === 'no-request-id') f.payload.meta.requestId = '';
    if (reason === 'unexpected-page-field') f.payload.data.credentials = [];
    expect(() => validateManualReadEvidence(f.packet, reason === 'HTTP-403' ? 403 : 200, f.payload, f.expected)).toThrow();
  });
});

describe('manual writes participate in final cleanup audit without rewriting original evidence', () => {
  const write = (method = 'POST', path = '/api/v1/auth/login') => ({ method, path, requestId: randomUUID(), status: 201 });
  it('appends three successful logins and all four metadata writes to original evidence, retaining independent manual list', () => {
    const old = [{ origin: 'portal', method: 'POST', path: '/api/v1/portal/auth/login', requestId: randomUUID(), original: 'offline-original-history' }];
    const manual = [write('POST', '/api/v1/portal/auth/login'), write(), write('POST', '/api/v1/clusters/offline/portal/pages'), write('POST', '/api/v1/clusters/offline/portal/pages/offline/publish'), write('DELETE', '/api/v1/clusters/offline/portal/pages/offline'), write('POST', '/api/v1/clusters/offline/portal/pages/offline/restore'), write()];
    const original = JSON.stringify(old), combined = mergeManualWriteEvidence(old, manual);
    expect(combined).toHaveLength(8); expect(combined[0]).toBe(old[0]); expect(combined.slice(1)).toEqual(manual); expect(JSON.stringify(old)).toBe(original); expect(manual).toHaveLength(7);
    expect(mergeManualWriteEvidence(combined, manual)).toEqual(combined);
  });
  it('preserves original duplicate history exactly and deduplicates only incoming manual request IDs', () => {
    const oldRow = write(), old = [oldRow, { ...oldRow, original: true }], next = write();
    const combined = mergeManualWriteEvidence(old, [next, next, { ...oldRow }]);
    expect(combined).toHaveLength(3); expect(combined[0]).toBe(old[0]); expect(combined[1]).toBe(old[1]); expect(combined[2]).toBe(next);
  });
  it.each(['path', 'method', 'status'])('refuses a request ID conflict in %s instead of overwriting prior rows', field => {
    const old = write(), incoming: any = { ...old, [field]: field === 'path' ? '/api/v1/portal/auth/login' : field === 'method' ? 'DELETE' : 200 };
    expect(() => mergeManualWriteEvidence([old], [incoming])).toThrow('M6_MANUAL_WRITE_EVIDENCE_CONFLICT');
  });
  it('compares every preserved historical row for a request ID instead of letting the last duplicate hide a conflict', () => {
    const row = write(), prior = [{ ...row, path: '/api/v1/portal/auth/login' }, row];
    expect(() => mergeManualWriteEvidence(prior, [row])).toThrow('M6_MANUAL_WRITE_EVIDENCE_CONFLICT');
    expect(prior).toHaveLength(2);
  });
  it.each([401, 500, 0, undefined])('does not append HTTP %s or unknown results as successful manual writes', status => {
    expect(() => mergeManualWriteEvidence([], [{ ...write(), status }])).toThrow('M6_MANUAL_WRITE_EVIDENCE_INVALID');
  });
  it('allows preexisting successful evidence without a status field while retaining its original shape', () => {
    const row = write(), old: any = { ...row }; delete old.status;
    expect(mergeManualWriteEvidence([old], [row])).toEqual([old]); expect(old).not.toHaveProperty('status');
    expect(mergeManualWriteEvidence(undefined, [row])).toEqual([row]);
  });
});

describe('actual manual runner source wiring with in-memory adapters', () => {
  const source = readFileSync('tests/security/manual-m6-ui.mjs', 'utf8'), tree = ts.createSourceFile('manual-m6-ui.mjs', source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
  function actualFunction(name: string, bindings: Record<string, any>) {
    const node = tree.statements.find(item => ts.isFunctionDeclaration(item) && item.name?.text === name);
    if (!node) throw Error('offline function not found');
    return runInNewContext(`(${node.getText(tree)})`, { URL, Set, detailRemainingRequested: false, ...bindings });
  }
  it('actual retain merges every successful manual write into original history while keeping manual report and secrets separate', () => {
    const oldRow = { method: 'POST', path: '/api/v1/portal/auth/login', requestId: randomUUID() }, manual = [{ method: 'POST', path: '/api/v1/auth/login', requestId: randomUUID(), status: 201 }];
    const latest = { writeEvidence: [oldRow], writeAttempts: [{ state: 'uncertain', original: true }], secrets: ['offline-old-cookie'], priorFixtureRuns: [{ old: true }], browserRemaining: { completed: false, preserve: true } }, saved = vi.fn();
    const retain = actualFunction('retain', { privateReference: vi.fn(() => latest), M6_REFERENCE: '/offline-only', writeManualReferenceAtomic: saved, mergeManualWriteEvidence, newSecrets: new Set(['offline-new-cookie']), journal: { ready: true }, manualMetadata: [], manualAttempts: [], writes: manual });
    retain(); const value = saved.mock.calls[0][1];
    expect(value.writeEvidence).toEqual([oldRow, ...manual]); expect(value.writeEvidence[0]).toBe(oldRow); expect(value.manualWriteEvidence).toBe(manual); expect(value.secrets).toEqual(['offline-old-cookie', 'offline-new-cookie']);
    expect(value.writeAttempts).toBe(latest.writeAttempts); expect(value.priorFixtureRuns).toBe(latest.priorFixtureRuns); expect(value.browserRemaining).toBe(latest.browserRemaining);
    expect(latest.writeEvidence).toHaveLength(1);
  });
  it('actual GET waiter uses exact safe-read scope and never initiates a request or mutation', async () => {
    const f = fixture('application'), page = { waitForResponse: vi.fn(async predicate => predicate) }, read = actualFunction('manualRead', { manualReadPacketMatches });
    const predicate = await read(page, f.expected), response = (method: string, url = f.packet.url) => ({ url: () => url, request: () => ({ method: () => method }) });
    expect(predicate(response('GET'))).toBe(true); expect(predicate(response('POST'))).toBe(false); expect(predicate(response('GET', f.packet.url + '&reveal=true'))).toBe(false);
    expect(page.waitForResponse).toHaveBeenCalledOnce();
  });
  it('actual read-result adapter validates real DTO before marking PASS and stores only safe evidence', async () => {
    const f = fixture('requests'), report = { readEvidence: [] as any[] }, check = vi.fn(), ready = vi.fn(async () => {});
    const read = actualFunction('readResult', { validateManualReadEvidence, ready, report, check });
    const response = { url: () => f.packet.url, request: () => ({ method: () => 'GET' }), status: () => 200, json: async () => f.payload };
    await read(response, f.expected, 'offline actual request'); expect(check).toHaveBeenCalledWith('offline actual request: actual safe DTO and original CID/WID', true); expect(report.readEvidence).toHaveLength(1); expect(report.readEvidence[0]).not.toHaveProperty('data');
    f.payload.data.items[0].grantId = randomUUID(); await expect(read(response, f.expected, 'offline invalid relation')).rejects.toThrow(); expect(check).toHaveBeenCalledOnce(); expect(report.readEvidence).toHaveLength(1);
  });
  it('actual screenshot guard and top-scroll stability run before capture, without opening a reveal panel', async () => {
    const order: string[] = [], page = { getByRole: vi.fn(() => ({ count: async () => 0 })), evaluate: vi.fn(async () => { order.push('scroll-top'); }), mouse: { move: vi.fn(async () => { order.push('move'); }) }, waitForTimeout: vi.fn(async () => { order.push('stable'); }), screenshot: vi.fn(async () => { order.push('capture'); }) };
    const shot = actualFunction('screenshot', { check: vi.fn(() => order.push('secret-closed')), expect: { poll: vi.fn(() => ({ toBe: async () => { order.push('top-proven'); } })) }, screenshots: [], persist: vi.fn(() => order.push('persist')) });
    await shot(page, 'offline-safe-shot'); expect(order).toEqual(['secret-closed', 'scroll-top', 'top-proven', 'move', 'stable', 'capture', 'persist']);
    expect(page.getByRole).toHaveBeenCalledWith('dialog', { name: '临时查看 API Key' }); expect(page.screenshot).toHaveBeenCalledWith({ path: 'artifacts/M6/offline-safe-shot.png', fullPage: true, animations: 'disabled' });
    page.getByRole.mockReturnValue({ count: async () => 1 }); const check = vi.fn((_name, passed) => { if (!passed) throw Error('offline panel open'); });
    const blocked = actualFunction('screenshot', { check }); await expect(blocked(page, 'never-captured')).rejects.toThrow('offline panel open'); expect(page.screenshot).toHaveBeenCalledOnce();
  });
  it('real DOM detail checks use unique current identities, Configuration and actual relations rather than blanket tab PASS', () => {
    expect(source).not.toContain("for (const tab of ['开发者审核', '应用管理', '门户设置'])");
    expect(source).toContain('tr.ant-table-row[data-row-key="${owner.id}"]'); expect(source).toContain('tr.ant-table-row[data-row-key="${published.applicationId}"]'); expect(source).toContain('tr.ant-table-row[data-row-key="${published.activeGrantId}"]'); expect(source).toContain('tr.ant-table-row[data-row-key="${activeGrant.workflowId}"]');
    expect(source).toContain("name: 'Configuration / 配置', exact: true"); expect(source).toContain("name: '授权记录', exact: true"); expect(source).toContain("name: '申请 / 工作流', exact: true");
    expect(source).toContain('toHaveAttribute(\'href\', `/workflows/${request.id}`)');
    for (const name of ['manual-portal-catalog-filter', 'manual-console-developer-configuration', 'manual-console-application-configuration', 'manual-console-application-grants', 'manual-console-application-requests']) expect(source).toContain(`'${name}'`);
    expect(source).toContain('category ? { category } : { search: currentPublication.name }'); expect(source).toContain('manualWriteEvidence: writes'); expect(source).toContain('writeEvidence: mergeManualWriteEvidence(latest.writeEvidence, writes)');
  });
});
