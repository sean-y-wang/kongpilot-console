import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { manualReadContract, manualReadPacketMatches, mergeManualWriteEvidence, validateManualReadEvidence } from './lib/m6-manual-read-evidence.mjs';

// Extract actual producer methods without loading modules, configuration, a DB,
// HTTP clients, decorators or constructors. All adapters below are memory-only.
function tree(file: string) { return ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS); }
function methods(file: string, names: string[]) {
  const source = tree(file), cls = source.statements.find(ts.isClassDeclaration)!;
  return names.map(name => { const node = cls.members.find(member => ts.isMethodDeclaration(member) && member.name.getText(source) === name); expect(node, `${file}:${name}`).toBeTruthy(); return node!.getText(source); }).join('\n');
}
function declaration(file: string, name: string) {
  const source = tree(file), node = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name || ts.isVariableStatement(node) && node.declarationList.declarations.some(value => value.name.getText(source) === name));
  expect(node, `${file}:${name}`).toBeTruthy(); return node!.getText(source).replace(/^export\s+/, '');
}
function actualProducer(file: string, names: string[], bindings: Record<string, unknown> = {}) {
  const helpers = [declaration('apps/console-api/src/modules/portal/portal-input.ts', 'portalObject'), declaration('apps/console-api/src/modules/portal/portal-input.ts', 'portalText'), declaration('apps/console-api/src/modules/workflows/workflow-validation.ts', 'workflowId'), declaration('apps/console-api/src/modules/entities/entities.types.ts', 'pageSize')].join('\n');
  const code = ts.transpileModule(`${helpers}\nconst portalId=workflowId;\nclass ActualProducer {${methods(file, names)}}\nnew ActualProducer();`, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText;
  return runInNewContext(code, { Buffer, Date, structuredClone, BadRequestException: Error, ConflictException: Error, NotFoundException: Error, ...bindings });
}
function fixture() {
  const clusterId = randomUUID(), workspaceId = randomUUID(), developerId = randomUUID(), applicationId = randomUUID(), publicationId = randomUUID(), grantId = randomUUID(), workflowId = randomUUID();
  const scope = { clusterId, workspaceId }, timestamp = '2026-10-11T10:00:00.000Z', username = 'independent-source-developer';
  const developer = { id: developerId, cluster_id: clusterId, workspace_id: workspaceId, username, email: 'source@example.invalid', display_name: 'Source Developer', status: 'active', revision: 3, must_change_password: false, created_at: timestamp };
  const application = { id: applicationId, cluster_id: clusterId, workspace_id: workspaceId, developer_id: developerId, name: 'Source Application', description: 'Source-only metadata', status: 'active', revision: 4, created_at: timestamp };
  const grant = { id: grantId, application_id: applicationId, publication_id: publicationId, publication_name: 'Published Source API', state: 'active', current_generation: 1, revision: 5, reservation_released_at: null, created_at: timestamp };
  const request = { id: workflowId, cluster_id: clusterId, workspace_id: workspaceId, application_id: applicationId, grant_id: grantId, publication_id: publicationId, kind: 'portal-credential-issue', state: 'succeeded', revision: 6, execution_mode: 'direct', approval_required: true, created_at: timestamp, expires_at: '2026-10-12T10:00:00.000Z' };
  const publication = { id: publicationId, cluster_id: clusterId, workspace_id: workspaceId, slug: 'source-api', revision: 7, published_revision: 2, published_name: 'Old mutable name', published_description: 'Old mutable description', cursor_created_at: '2026-10-11T10:00:00.000000Z', row_bytes: 2048, candidate_count: 1, byte_exhausted: false, publication_proof: {} };
  const proof = { publicationInfo: { name: 'Published Source API', slug: 'source-api', description: 'Published description', category: null }, keyAuthPlugin: { config: { key_names: ['apikey'] } } };
  const expected = (kind: string, extra: Record<string, unknown> = {}) => ({ kind, ...scope, id: kind === 'developer' ? developerId : applicationId, username, developerId, publicationId, grantId, workflowId, ...extra });
  const packet = (target: any) => { const contract = manualReadContract(target); return { method: 'GET', url: `${contract.origin}${contract.path}?${new URLSearchParams(contract.query)}` }; };
  return { ...scope, developerId, applicationId, publicationId, grantId, workflowId, developer, application, grant, request, publication, proof, expected, packet };
}
type Fixture = ReturnType<typeof fixture>;
async function actualAdmin(f: Fixture, kind: string) {
  const service = actualProducer('apps/console-api/src/modules/portal/portal-admin.service.ts', ['developer', 'application', 'adminApplicationView', 'applicationGrants', 'requestSummary', 'adminRequests', 'applicationRequests']);
  const scoped = { cid: f.clusterId, wid: f.workspaceId, version: 'source-permissions' }, calls: any[] = [];
  service.adminReadScope = vi.fn(async () => scoped); service.adminReadFinal = vi.fn(async () => {}); service.adminReadCapability = vi.fn(async () => true); service.adminApplication = vi.fn(async () => f.application);
  service.authz = { assertWholeWorkspace: vi.fn(async () => {}) }; service.secrets = { fingerprint: vi.fn(() => 'source-binding') }; service.adminPage = vi.fn(() => ({ size: 20, offset: 0, state: null })); service.cursors = { encode: vi.fn(() => 'opaque-source-cursor') };
  service.db = { one: vi.fn(async (_sql: string, values: unknown[]) => { calls.push(values); return f.developer; }), query: vi.fn(async (_sql: string, values: unknown[]) => { calls.push(values); return kind === 'grants' ? [f.grant] : [f.request]; }) };
  const actor = { user: { id: randomUUID() }, workspaceId: f.workspaceId }, query = { workspaceId: f.workspaceId, ...(kind === 'grants' || kind === 'requests' ? { size: '20' } : {}) };
  const result = await service[({ grants: 'applicationGrants', requests: 'applicationRequests' } as Record<string, string>)[kind] ?? kind](f.clusterId, kind === 'developer' ? f.developerId : f.applicationId, query, actor);
  return { result, service, calls };
}
async function actualCatalog(f: Fixture, filters: Record<string, string> = {}) {
  const service = actualProducer('apps/console-api/src/modules/portal/portal-public.service.ts', ['publicationView', 'catalogPosition', 'publications'], { decodePublicationProof: () => f.proof, PORTAL_CATALOG_SCAN_LIMITS: { rows: 500, batches: 10, batchSize: 50, bytes: 33554432, batchBytes: 8388608 }, catalogTimestamp: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/ });
  service.published = vi.fn(async () => ({ clusterId: f.clusterId, workspaceId: f.workspaceId })); service.secrets = { fingerprint: vi.fn(() => 'source-catalog-binding') }; service.cursors = { decode: vi.fn(() => null), encode: vi.fn(() => 'opaque-source-cursor') }; service.catalogCandidates = vi.fn(async () => [f.publication]);
  return { result: await service.publications({ clusterId: f.clusterId, workspaceId: f.workspaceId, size: '20', ...filters }), service };
}
function validate(f: Fixture, kind: string, data: unknown, extra: Record<string, unknown> = {}) { const expected = f.expected(kind, extra); return validateManualReadEvidence(f.packet(expected), 200, { data, meta: { requestId: randomUUID() } }, expected); }
function actualRunnerFunction(name: string, bindings: Record<string, unknown> = {}) {
  const source = ts.createSourceFile('manual-m6-ui.mjs', readFileSync('tests/security/manual-m6-ui.mjs', 'utf8'), ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS), node = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
  expect(node, name).toBeTruthy(); return runInNewContext(`(${node!.getText(source)})`, { URL, Set, detailRemainingRequested: false, ...bindings });
}

describe('independent source producer to manual read contract', () => {
  it.each(['developer', 'application', 'grants', 'requests'])('accepts actual %s producer projection with scoped bindings and strips secret-shaped source columns', async kind => {
    const f = fixture(); Object.assign(f.developer, { password_hash: 'SOURCE_ONLY_NOT_A_PASSWORD' }); Object.assign(f.application, { credential_cipher: 'SOURCE_ONLY_NOT_A_CIPHER' }); Object.assign(f.grant, { consumer_id: randomUUID(), credential_id: randomUUID() }); Object.assign(f.request, { plan_secret: 'SOURCE_ONLY_NOT_A_SECRET' });
    const { result, calls, service } = await actualAdmin(f, kind), evidence = validate(f, kind, result);
    expect(evidence.evidence).toMatchObject({ kind, safeDto: true, clusterId: f.clusterId, workspaceId: f.workspaceId });
    expect(JSON.stringify(result)).not.toMatch(/SOURCE_ONLY|password_hash|credential_cipher|consumer_id|credential_id|plan_secret/); expect(service.adminReadFinal).toHaveBeenCalledOnce();
    if (calls.length) expect(calls[0].slice(0, 2)).toEqual([f.clusterId, f.workspaceId]);
    if (kind === 'requests') expect(evidence.target).toMatchObject({ executionMode: 'direct', approvalRequired: true, id: f.workflowId, grantId: f.grantId, applicationId: f.applicationId });
  });
  it('actual credential compiler requires approval separately from cluster execution mode', () => {
    const source = tree('apps/console-api/src/modules/portal/portal-credentials.service.ts'); let plan: ts.ObjectLiteralExpression | undefined;
    function visit(node: ts.Node) { if (ts.isVariableDeclaration(node) && node.name.getText(source) === 'plan' && node.initializer && ts.isObjectLiteralExpression(node.initializer)) plan = node.initializer; ts.forEachChild(node, visit); } visit(source); expect(plan).toBeTruthy();
    const fields = new Map(plan!.properties.filter(ts.isPropertyAssignment).map(field => [field.name.getText(source), field.initializer.getText(source)]));
    expect(fields.get('executionMode')).toBe('cluster.execution_mode'); expect(fields.get('approvalRequired')).toBe('true');
  });
  it.each(['search', 'category'])('actual published catalog %s GET uses proof metadata and its exact supported filtering', async filter => {
    const f = fixture(), filters = filter === 'search' ? { search: 'pUbLiShEd SoUrCe' } : { category: 'Source Category' }; if (filter === 'category') f.proof.publicationInfo.category = filters.category as any;
    const { result, service } = await actualCatalog(f, filters), evidence = validate(f, 'catalog', result, filters);
    expect(evidence.target.name).toBe('Published Source API'); expect(evidence.target.documentRevision).toBe(2); expect(evidence.evidence.filter).toBe(filter === 'search' ? 'search-all-categories' : 'category'); expect(service.catalogCandidates).toHaveBeenCalledOnce(); expect(service.published).toHaveBeenCalledTimes(2);
  });
  it('actual catalog excludes a description-only search match and manual evidence does not claim that API was returned', async () => {
    const f = fixture(); f.proof.publicationInfo.description = 'description-match'; const filters = { search: 'description-match' }, { result } = await actualCatalog(f, filters);
    expect(result.items).toHaveLength(0); expect(() => validate(f, 'catalog', result, filters)).toThrow('M6_MANUAL_READ_EVIDENCE_INVALID');
  });
  it('actual frontend detail and table paths match current-scope contracts without credential requests', () => {
    const source = readFileSync('apps/console-web/src/features/PortalAdminDetails.tsx', 'utf8'), hooks = readFileSync('apps/console-web/src/features/portal-hooks.ts', 'utf8'), portal = readFileSync('apps/portal-web/src/features/PublicPages.tsx', 'utf8');
    expect(source).toContain('scope.path(`portal/${resource}/${selection.id}`)'); for (const kind of ['grants', 'requests']) expect(source).toContain(`\`portal/applications/\${applicationId}/${kind}\``);
    expect(hooks).toContain("new URLSearchParams({ size: '20', ...filters })"); expect(hooks).toContain('scope.path(`${resource}?${params}`)'); expect(portal).toContain("useCursor<Publication>('/publications'"); expect(source).not.toMatch(/api[<(].*credential|\/credentials|\/reveal/);
  });
});

describe('independent exact scope and safe whole-page response evidence', () => {
  it.each(['catalog', 'developer', 'application', 'grants', 'requests'])('accepts reordered exact %s query and rejects any second page or foreign cluster', kind => {
    const f = fixture(), expected = f.expected(kind), packet = f.packet(expected), url = new URL(packet.url); url.searchParams.sort(); expect(manualReadPacketMatches({ ...packet, url: url.href }, expected)).toBe(true);
    url.searchParams.set('cursor', 'opaque-unrequested-page'); expect(manualReadPacketMatches({ ...packet, url: url.href }, expected)).toBe(false); url.searchParams.delete('cursor');
    if (kind === 'catalog') url.searchParams.set('clusterId', randomUUID()); else url.pathname = url.pathname.replace(f.clusterId, randomUUID()); expect(manualReadPacketMatches({ ...packet, url: url.href }, expected)).toBe(false);
  });
  it.each(['auth-extra', 'capability-extra', 'non-target-extra', 'page-extra', 'scope-extra'])('fails closed on %s despite a valid current target', async fault => {
    const f = fixture(); let kind = fault === 'auth-extra' ? 'catalog' : fault === 'capability-extra' ? 'application' : 'requests'; const result = kind === 'catalog' ? (await actualCatalog(f)).result : (await actualAdmin(f, kind)).result;
    if (fault === 'auth-extra') result.items[0].auth.rawKey = 'SOURCE_ONLY_NO_REAL_KEY';
    if (fault === 'capability-extra') result.entity.capabilities.reveal = true;
    if (fault === 'non-target-extra') result.items.push({ ...result.items[0], id: randomUUID(), state: 'failed', accessToken: 'SOURCE_ONLY_NO_REAL_TOKEN' });
    if (fault === 'page-extra') result.credentials = [];
    if (fault === 'scope-extra') result.items.push({ ...result.items[0], id: randomUUID(), workspaceId: randomUUID(), state: 'failed' });
    expect(() => validate(f, kind, result)).toThrow('M6_MANUAL_READ_EVIDENCE_INVALID');
  });
  it.each(['publicationId', 'grantId', 'workflowId'])('requires trusted %s rather than accepting a similarly named succeeded application request', async field => {
    const f = fixture(), { result } = await actualAdmin(f, 'requests'); expect(() => validate(f, 'requests', result, { [field]: randomUUID() })).toThrow();
  });
  it('preserves old failed and revoked rows while identifying the exact active grant and succeeded request', async () => {
    const f = fixture(), grants = (await actualAdmin(f, 'grants')).result, requests = (await actualAdmin(f, 'requests')).result, currentGrant = grants.items[0], currentRequest = requests.items[0];
    grants.items.unshift({ ...currentGrant, id: randomUUID(), state: 'disabled', generation: 0, reservationReleased: true }, { ...currentGrant, id: randomUUID(), state: 'revoked' }); requests.items.unshift({ ...currentRequest, id: randomUUID(), state: 'failed' }, { ...currentRequest, id: randomUUID(), state: 'partial' });
    expect(validate(f, 'grants', grants).target).toBe(currentGrant); expect(validate(f, 'requests', requests).target).toBe(currentRequest); expect(grants.items.map((r: any) => r.state)).toEqual(['disabled', 'revoked', 'active']); expect(requests.items.map((r: any) => r.state)).toEqual(['failed', 'partial', 'succeeded']);
  });
  it.each(['scanIncomplete', 'searchedRows'])('does not erase genuine bounded %s or publish it as complete global statistics', async field => {
    const f = fixture(), { result } = await actualCatalog(f); result.scanIncomplete = true; result.searchedRows = 500; result.nextCursor = 'opaque-source-cursor';
    expect(validate(f, 'catalog', result).evidence).toMatchObject({ scanIncomplete: true, returnedItems: 1, totalUnknown: true }); result[field] = field === 'scanIncomplete' ? 'false' : 501; expect(() => validate(f, 'catalog', result)).toThrow();
  });
  it('only emits scoped identifiers and counts in public evidence, excluding metadata, DTO, query and header values', async () => {
    const f = fixture(), { result } = await actualAdmin(f, 'developer'), evidence = validate(f, 'developer', result).evidence;
    expect(Object.keys(evidence).sort()).toEqual(['clusterId', 'entityId', 'kind', 'method', 'path', 'requestId', 'safeDto', 'workspaceId'].sort()); expect(JSON.stringify(evidence)).not.toContain(f.developer.username); expect(JSON.stringify(evidence)).not.toContain(f.developer.email);
  });
});

describe('independent new successful manual evidence and immutable historical rows', () => {
  const successful = () => ({ requestId: randomUUID(), method: 'POST', path: '/api/v1/portal/auth/login', status: 201 });
  it('keeps original failed/unknown attempts, cookie history and duplicate evidence by reference while appending successful rows once', () => {
    const row = successful(), historical: any[] = [null, { requestId: randomUUID(), method: 'POST', path: '/api/v1/portal/applications', status: 500, state: 'failed' }, { requestId: randomUUID(), state: 'response-unknown', key: 'SOURCE_ONLY_OLD_ATTEMPT' }, { jar: [{ name: 'source-only', value: 'SOURCE_ONLY_OLD_COOKIE' }] }, { ...row, original: 'original1' }, { ...row, original: 'original2' }], before = JSON.stringify(historical), next = successful(), incoming = [row, next, next];
    const result = mergeManualWriteEvidence(historical, incoming); expect(result).toHaveLength(historical.length + 1); historical.forEach((old, index) => expect(result[index]).toBe(old)); expect(result.at(-1)).toBe(next); expect(JSON.stringify(historical)).toBe(before); expect(incoming).toHaveLength(3); expect(mergeManualWriteEvidence(result, incoming)).toEqual(result);
  });
  it.each([0, 1, 2])('a conflicting historical duplicate at index %s cannot be hidden by the later matching record', index => {
    const row = successful(), historical = [{ ...row }, { ...row }, { ...row }]; historical[index].path = '/api/v1/auth/login'; const before = JSON.stringify(historical);
    expect(() => mergeManualWriteEvidence(historical, [row])).toThrow('M6_MANUAL_WRITE_EVIDENCE_CONFLICT'); expect(JSON.stringify(historical)).toBe(before);
  });
  it.each([202, 401, 500])('historical status %s cannot be silently upgraded or rewritten by a new 201 with the same request ID', status => {
    const row = successful(), old = { ...row, status }; expect(() => mergeManualWriteEvidence([old], [row])).toThrow('M6_MANUAL_WRITE_EVIDENCE_CONFLICT'); expect(old.status).toBe(status);
  });
  it('a conflict between two incoming rows fails without partial mutation of historical or incoming arrays', () => {
    const old: any[] = [{ historical: true }], first = successful(), incoming = [first, { ...first, method: 'DELETE' }]; expect(() => mergeManualWriteEvidence(old, incoming)).toThrow('M6_MANUAL_WRITE_EVIDENCE_CONFLICT'); expect(old).toEqual([{ historical: true }]); expect(incoming).toHaveLength(2);
  });
  it.each(['GET', 'PATCH', 'bad-id', 'query', 'NaN-status'])('rejects an invalid %s incoming write rather than appending it to cleanup audit material', fault => {
    const row: any = successful(); if (fault === 'GET' || fault === 'PATCH') row.method = fault; if (fault === 'bad-id') row.requestId = 'not-a-uuid'; if (fault === 'query') row.path += '?reveal=true'; if (fault === 'NaN-status') row.status = NaN;
    expect(() => mergeManualWriteEvidence([], [row])).toThrow('M6_MANUAL_WRITE_EVIDENCE_INVALID');
  });
});

describe('independent actual new manual runner wiring in memory-only adapters', () => {
  it('actual retain saves the latest original failure and jar history and only appends each successful manual write once', () => {
    const oldWrite = { requestId: randomUUID(), method: 'POST', path: '/api/v1/portal/applications' }, oldFailure = { state: 'failed', original: true }, oldJar = [{ name: 'source-only', value: 'SOURCE_ONLY_OLD_COOKIE' }], latest = { secrets: ['SOURCE_ONLY_OLD_SECRET'], failedIssue: oldFailure, browserRemaining: { latestNamedJars: oldJar }, priorFixtureRuns: [{ original: true }], writeAttempts: [{ state: 'response-unknown', key: 'SOURCE_ONLY_ORIGINAL_KEY' }], writeEvidence: [oldWrite] }, before = JSON.stringify(latest), next = { requestId: randomUUID(), method: 'POST', path: '/api/v1/auth/login', status: 201 }, manual = [next, next], save = vi.fn();
    const retain = actualRunnerFunction('retain', { privateReference: vi.fn(() => latest), M6_REFERENCE: '/memory-only', writeManualReferenceAtomic: save, mergeManualWriteEvidence, newSecrets: new Set(['SOURCE_ONLY_NEW_COOKIE']), journal: { sourceOnly: true }, manualMetadata: [], manualAttempts: [], writes: manual }); retain();
    expect(save).toHaveBeenCalledOnce(); const [path, saved] = save.mock.calls[0]; expect(path).toBe('/memory-only'); expect(saved.writeEvidence).toEqual([oldWrite, next]); expect(saved.writeEvidence[0]).toBe(oldWrite); expect(saved.manualWriteEvidence).toBe(manual); expect(saved.failedIssue).toBe(oldFailure); expect(saved.browserRemaining.latestNamedJars).toBe(oldJar); expect(saved.priorFixtureRuns).toBe(latest.priorFixtureRuns); expect(saved.writeAttempts).toBe(latest.writeAttempts); expect(saved.secrets).toEqual(['SOURCE_ONLY_OLD_SECRET', 'SOURCE_ONLY_NEW_COOKIE']); expect(JSON.stringify(latest)).toBe(before);
  });
  it('actual retain detects every original request ID conflict before any persistence call', () => {
    const manual = { requestId: randomUUID(), method: 'POST', path: '/api/v1/auth/login', status: 201 }, save = vi.fn(), latest = { writeEvidence: [{ ...manual, status: 500 }, manual], failedIssue: { original: true } }, original = JSON.stringify(latest);
    const retain = actualRunnerFunction('retain', { privateReference: vi.fn(() => latest), M6_REFERENCE: '/memory-only', writeManualReferenceAtomic: save, mergeManualWriteEvidence, newSecrets: new Set(), journal: {}, manualMetadata: [], manualAttempts: [], writes: [manual] });
    expect(retain).toThrow('M6_MANUAL_WRITE_EVIDENCE_CONFLICT'); expect(save).not.toHaveBeenCalled(); expect(JSON.stringify(latest)).toBe(original);
  });
  it('actual manualRead installs an exact scoped GET waiter without initiating or retrying a request', async () => {
    const f = fixture(), expected = f.expected('requests'), packet = f.packet(expected), page = { waitForResponse: vi.fn(async predicate => predicate) }, read = actualRunnerFunction('manualRead', { manualReadPacketMatches }), predicate = await read(page, expected);
    const response = (url: string, method = 'GET') => ({ url: () => url, request: () => ({ method: () => method }) }); expect(predicate(response(packet.url))).toBe(true); expect(predicate(response(packet.url, 'POST'))).toBe(false); expect(predicate(response(packet.url.replace(f.workspaceId, randomUUID())))).toBe(false); expect(page.waitForResponse).toHaveBeenCalledOnce(); expect(Object.keys(page)).toEqual(['waitForResponse']);
  });
  it('actual readResult validates the producer, awaits non-stopped window, then records safe metadata without copying the DTO', async () => {
    const f = fixture(), { result } = await actualAdmin(f, 'requests'), expected = f.expected('requests'), packet = f.packet(expected), order: string[] = [], report = { readEvidence: [] as any[] }, ready = vi.fn(async () => { order.push('ready'); }), check = vi.fn(() => order.push('check'));
    const read = actualRunnerFunction('readResult', { validateManualReadEvidence, ready, report, check }), response = { url: () => packet.url, request: () => ({ method: () => 'GET' }), status: () => 200, json: async () => ({ data: result, meta: { requestId: randomUUID() } }) }, value = await read(response, expected, 'source-only requests');
    expect(order).toEqual(['ready', 'check']); expect(report.readEvidence).toHaveLength(1); expect(report.readEvidence[0]).toBe(value.evidence); expect(report.readEvidence[0]).not.toHaveProperty('data'); expect(report.readEvidence[0]).not.toHaveProperty('headers'); expect(value.target.id).toBe(f.workflowId);
  });
  it.each(['foreign-scope', 'unexpected-key', 'stopped-window'])('actual readResult appends no proof on %s', async fault => {
    const f = fixture(), { result } = await actualAdmin(f, 'application'), expected = f.expected('application'), packet = f.packet(expected), report = { readEvidence: [] }, ready = vi.fn(async () => { if (fault === 'stopped-window') throw Error('M6_MANUAL_WINDOW_STOPPED'); }), check = vi.fn();
    if (fault === 'foreign-scope') result.entity.workspaceId = randomUUID(); if (fault === 'unexpected-key') result.entity.key = 'SOURCE_ONLY_NO_ACTUAL_KEY';
    const read = actualRunnerFunction('readResult', { validateManualReadEvidence, ready, report, check }), response = { url: () => packet.url, request: () => ({ method: () => 'GET' }), status: () => 200, json: async () => ({ data: result, meta: { requestId: randomUUID() } }) };
    await expect(read(response, expected, 'source-only blocked')).rejects.toThrow(); expect(report.readEvidence).toHaveLength(0); expect(check).not.toHaveBeenCalled(); if (fault !== 'stopped-window') expect(ready).not.toHaveBeenCalled();
  });
  it('actual screenshot proves the secret dialog closed and viewport at top before any capture or report update', async () => {
    const events: string[] = [], window = { scrollY: 100, scrollTo: vi.fn((_x, y) => { window.scrollY = y; events.push('scroll-top'); }) }, screenshots: string[] = [], check = vi.fn((_name, value) => { events.push('secret-check'); expect(value).toBe(true); });
    const page = { getByRole: vi.fn(() => ({ count: async () => 0 })), evaluate: vi.fn(async callback => callback()), mouse: { move: vi.fn(async () => events.push('move')) }, waitForTimeout: vi.fn(async () => events.push('stable')), screenshot: vi.fn(async () => events.push('capture')) }, mockExpect = { poll: (callback: any) => ({ toBe: async (value: number) => { expect(await callback()).toBe(value); events.push('top-proven'); } }) };
    const screenshot = actualRunnerFunction('screenshot', { window, check, expect: mockExpect, screenshots, persist: vi.fn(() => events.push('persist')) }); await screenshot(page, 'source-only-safe');
    expect(events).toEqual(['secret-check', 'scroll-top', 'top-proven', 'move', 'stable', 'capture', 'persist']); expect(screenshots).toEqual(['source-only-safe.png']); expect(page.screenshot).toHaveBeenCalledOnce();
  });
  it('actual screenshot blocks a revealed secret panel before scrolling, capture or persistence', async () => {
    const page = { getByRole: vi.fn(() => ({ count: async () => 1 })), evaluate: vi.fn(), screenshot: vi.fn() }, persist = vi.fn(), screenshot = actualRunnerFunction('screenshot', { check: (_name: string, value: boolean) => { if (!value) throw Error('SOURCE_ONLY_SECRET_PANEL_OPEN'); }, persist });
    await expect(screenshot(page, 'never-captured')).rejects.toThrow('SOURCE_ONLY_SECRET_PANEL_OPEN'); expect(page.evaluate).not.toHaveBeenCalled(); expect(page.screenshot).not.toHaveBeenCalled(); expect(persist).not.toHaveBeenCalled();
  });
});
