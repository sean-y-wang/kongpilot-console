import { describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { collectManualUuidValues, createManualJournal, stopManualJournal, writeManualReferenceAtomic } from './lib/m6-manual-journal.mjs';
import { mergeManualWriteEvidence } from './lib/m6-manual-read-evidence.mjs';
import { MANUAL_PRE_LAUNCH_FAILURE_SHA256, manualChromiumLaunchOptions, prepareManualZeroPacketContinuation, preserveManualZeroPacketContinuation } from './lib/m6-manual-zero-packet.mjs';

function source(file: string, kind = ts.ScriptKind.TS) { return ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.ES2022, true, kind); }
function actualConfigLaunch(environment: Record<string, string>, systemBrowser: boolean) {
  const tree = source('playwright.config.ts'), variables = tree.statements.filter(ts.isVariableStatement).map(node => node.getText(tree)).join('\n'), config = tree.statements.find(ts.isExportAssignment)!.expression.getText(tree), exists = vi.fn(() => systemBrowser);
  const code = ts.transpileModule(`${variables}\n(${config}).use.launchOptions;`, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText;
  const options = runInNewContext(code, { process: { env: environment }, existsSync: exists, defineConfig: (value: unknown) => value, devices: { 'Desktop Chrome': {} } });
  return { options, exists };
}
function stoppedFixture() {
  const clusterId = randomUUID(), workspaceId = randomUUID(), actors = Object.fromEntries(['owner', 'administrator', 'approver'].map(role => [role, { id: randomUUID(), username: 'source-only-' + role, password: 'SOURCE_ONLY_NOT_AN_ACTUAL_PASSWORD_' + role }])), content = { slug: 'source-only-zero-packet', title: 'Source only zero packet', markdown: '# Public source fixture' }, config = { clusterId, workspaceId, actors, content, priorKeys: [randomUUID()], forbiddenEntityIds: [randomUUID()] };
  const journal = createManualJournal(config); stopManualJournal(journal, 'manual-harness-stopped', () => {});
  const failureBytes = readFileSync(failurePath), testTag = JSON.parse(failureBytes.toString()).testTag, reference: any = { testTag, manualJournal: structuredClone(journal), manualMetadata: [], manualWriteAttempts: [], manualWriteEvidence: [], secrets: ['SOURCE_ONLY_ORIGINAL_SECRET'], failedIssue: { state: 'failed', original: true }, browserRemaining: { latestNamedJars: [{ name: 'source-only', value: 'SOURCE_ONLY_ORIGINAL_COOKIE' }] }, priorFixtureRuns: [{ original: true }] };
  const expected = { ...config, testTag }, prepare = () => prepareManualZeroPacketContinuation(reference, failureBytes, expected, true);
  return { config, journal, reference, expected, failureBytes, prepare };
}
const failurePath = 'artifacts/M6/UI-review-pre-launch-attempt.json';
const failureHash = 'eb7a57f7675f56ea5ebd1c6cc7dcba9c462b9a463e75ceb5189f7622d73d1f4b';

describe('independent immutable zero-packet failure and actual Playwright configuration contract', () => {
  it('original public failure remains exact and proves the named preflight stop with no observed packet evidence', () => {
    const bytes = readFileSync(failurePath), report = JSON.parse(bytes.toString()); expect(createHash('sha256').update(bytes).digest('hex')).toBe(failureHash);
    expect(report).toMatchObject({ stage: 'actual-manual', allPassed: false, passed: 0, failed: 1, checks: [{ name: 'harness stopped after preflight', passed: false, errorName: 'Error' }], screenshots: [], readEvidence: [], fixtureJournal: [], workspaces: [], writeBoundary: { complete: false, plannedWrites: 0, successfulPlannedWrites: 0, expectedDeniedAnonymousBootstrapWrites: 0, stoppedWithoutReplay: true, actions: [] } });
  });
  it('actual Playwright config selects explicitly configured browser without probing the system fallback', () => {
    const f = actualConfigLaunch({ CHROMIUM_EXECUTABLE_PATH: '/source-only/custom-chromium' }, false); expect(f.options).toEqual({ executablePath: '/source-only/custom-chromium' }); expect(f.exists).not.toHaveBeenCalled();
  });
  it('actual Playwright config selects the system browser when present and otherwise keeps the bundled default', () => {
    const system = actualConfigLaunch({}, true); expect(system.options).toEqual({ executablePath: '/usr/bin/chromium' }); expect(system.exists).toHaveBeenCalledWith('/usr/bin/chromium'); expect(actualConfigLaunch({}, false).options).toEqual({});
  });
  it.each(['custom', 'system', 'bundled'])('new actual manual launch helper matches the real Playwright %s path contract', mode => {
    const environment = mode === 'custom' ? { CHROMIUM_EXECUTABLE_PATH: '/source-only/custom-chromium' } : {}, system = mode === 'system', exists = vi.fn(() => system);
    expect(manualChromiumLaunchOptions(environment, exists)).toEqual(actualConfigLaunch(environment, system).options); if (mode === 'custom') expect(exists).not.toHaveBeenCalled(); else expect(exists).toHaveBeenCalledWith('/usr/bin/chromium');
  });
});

describe('independent exact zero-packet continuation eligibility', () => {
  it('prepares a deep detached original stopped snapshot without resetting or changing any old journal or history', () => {
    const f = stoppedFixture(), before = JSON.stringify(f.reference), prepared = f.prepare(); expect(prepared.failureReportSha256).toBe(failureHash); expect(MANUAL_PRE_LAUNCH_FAILURE_SHA256).toBe(failureHash); expect(prepared.snapshot.manualJournal.phase).toBe('stopped-without-replay'); expect(prepared.snapshot.manualJournal).not.toBe(f.reference.manualJournal); expect(JSON.stringify(f.reference)).toBe(before); expect(prepared.snapshot.manualWriteAttempts).toEqual([]);
  });
  it.each([false, undefined, 'true', 1])('requires exact explicit authorization rather than truthy flag %s', flag => {
    const f = stoppedFixture(); expect(() => prepareManualZeroPacketContinuation(f.reference, f.failureBytes, f.expected, flag)).toThrow('M6_MANUAL_ZERO_PACKET_CONTINUATION_REJECTED');
  });
  it('rejects even semantically identical reserialized original failure bytes and any amended failure counters', () => {
    const f = stoppedFixture(), parsed = JSON.parse(f.failureBytes.toString()); expect(() => prepareManualZeroPacketContinuation(f.reference, JSON.stringify(parsed), f.expected, true)).toThrow(); parsed.writeBoundary.plannedWrites = 1; expect(() => prepareManualZeroPacketContinuation(f.reference, JSON.stringify(parsed), f.expected, true)).toThrow();
  });
  it.each(['attempt', 'metadata', 'write-attempt', 'write-evidence', 'in-flight', 'next-step', 'page-id', 'page-revision', 'authenticated', 'fresh-context', 'wrong-state', 'wrong-reason', 'missing-field', 'nested-marker', 'top-marker', 'top-history'])('fails closed on %s instead of treating an old nonzero or reentered run as pre-launch', fault => {
    const f = stoppedFixture(), journal = f.reference.manualJournal;
    if (fault === 'attempt') journal.attempts.push({ state: 'response-unknown', key: randomUUID() }); if (fault === 'metadata') f.reference.manualMetadata.push({ id: randomUUID() }); if (fault === 'write-attempt') f.reference.manualWriteAttempts.push({ key: randomUUID() }); if (fault === 'write-evidence') f.reference.manualWriteEvidence.push({ requestId: randomUUID() }); if (fault === 'in-flight') journal.inFlight = randomUUID(); if (fault === 'next-step') journal.nextIndex = 1; if (fault === 'page-id') journal.pageId = randomUUID(); if (fault === 'page-revision') journal.pageRevision = 1; if (fault === 'authenticated') journal.authenticated.owner = journal.actors.owner.id; if (fault === 'fresh-context') journal.freshContexts.owner = { initialCookieCount: 0 }; if (fault === 'wrong-state') journal.phase = 'ready'; if (fault === 'wrong-reason') journal.stopReason = 'transport-interrupted'; if (fault === 'missing-field') delete f.reference.manualWriteEvidence; if (fault === 'nested-marker') journal.zeroPacketContinuation = undefined; if (fault === 'top-marker') f.reference.manualZeroPacketContinuation = undefined; if (fault === 'top-history') f.reference.manualZeroPacketHistory = undefined;
    const before = JSON.stringify(f.reference); expect(f.prepare).toThrow('M6_MANUAL_ZERO_PACKET_CONTINUATION_REJECTED'); expect(JSON.stringify(f.reference)).toBe(before);
  });
  it.each(['cluster', 'workspace', 'tag', 'actor-id', 'actor-username', 'actor-password', 'extra-actor', 'content', 'bad-timestamp'])('requires the same trusted %s binding', fault => {
    const f = stoppedFixture(), journal = f.reference.manualJournal; if (fault === 'cluster') journal.clusterId = randomUUID(); if (fault === 'workspace') journal.workspaceId = randomUUID(); if (fault === 'tag') f.reference.testTag += '-foreign'; if (fault === 'actor-id') journal.actors.owner.id = randomUUID(); if (fault === 'actor-username') journal.actors.administrator.username += '-foreign'; if (fault === 'actor-password') journal.actors.approver.password += '-foreign'; if (fault === 'extra-actor') journal.actors.foreign = { ...journal.actors.owner }; if (fault === 'content') journal.content.markdown += '\nchanged'; if (fault === 'bad-timestamp') journal.stoppedAt = 'invalid'; expect(f.prepare).toThrow();
  });
});

describe('independent immutable history and one atomic continuation save', () => {
  it('seals all four original fields, retains unrelated history and secrets, and never permits prepare to enter again', () => {
    const f = stoppedFixture(), prepared = f.prepare(), active = createManualJournal(f.config), old = JSON.stringify(f.reference), preserved = preserveManualZeroPacketContinuation(f.reference, prepared, active);
    expect(preserved.manualZeroPacketHistory.snapshot).toEqual({ manualJournal: f.reference.manualJournal, manualMetadata: [], manualWriteAttempts: [], manualWriteEvidence: [] }); expect(preserved.manualZeroPacketHistory.snapshot.manualJournal.phase).toBe('stopped-without-replay'); expect(preserved.failedIssue).toBe(f.reference.failedIssue); expect(preserved.browserRemaining).toBe(f.reference.browserRemaining); expect(preserved.priorFixtureRuns).toBe(f.reference.priorFixtureRuns); expect(preserved.secrets).toBe(f.reference.secrets); expect(JSON.stringify(f.reference)).toBe(old); expect(() => prepareManualZeroPacketContinuation(preserved, f.failureBytes, f.expected, true)).toThrow();
    const updated = { ...preserved, manualJournal: active, manualWriteAttempts: active.attempts }; expect(preserveManualZeroPacketContinuation(updated, prepared, active)).toBe(updated);
  });
  it.each(['old-snapshot', 'prepared-snapshot', 'marker-missing', 'history-missing', 'marker-changed', 'history-changed', 'other-active-run'])('refuses %s at atomic-save boundary without dropping old history', fault => {
    const f = stoppedFixture(), prepared = f.prepare(), active = createManualJournal(f.config); let latest = preserveManualZeroPacketContinuation(f.reference, prepared, active);
    if (fault === 'old-snapshot') { latest = f.reference; latest.manualWriteAttempts.push({ state: 'private-save-failed-before-packet' }); }
    if (fault === 'prepared-snapshot') prepared.snapshot.manualJournal.stopReason = 'changed'; if (fault === 'marker-missing') delete latest.manualZeroPacketContinuation; if (fault === 'history-missing') delete latest.manualZeroPacketHistory; if (fault === 'marker-changed') latest.manualZeroPacketContinuation.activeJournalStartedAt = 'changed'; if (fault === 'history-changed') latest.manualZeroPacketHistory.snapshot.manualMetadata.push({ id: randomUUID() }); if (fault === 'other-active-run') active.startedAt = new Date(Date.parse(active.startedAt) + 1000).toISOString();
    const before = JSON.stringify(latest); expect(() => preserveManualZeroPacketContinuation(latest, prepared, active)).toThrow(); expect(JSON.stringify(latest)).toBe(before);
  });
});

async function actualPrelaunch(options: { saveFails?: boolean; wrongOldAttempt?: boolean; flag?: boolean; path?: string } = {}) {
  const f = stoppedFixture(), tree = source('tests/security/manual-m6-ui.mjs', ts.ScriptKind.JS), firstTry = tree.statements.find(ts.isTryStatement)!;
  // Execute only real preflight/retain/launch statements. Launch and IO are fakes;
  // the browser context, page, request and audit bodies are never executed.
  const statements = tree.statements.slice(0, tree.statements.indexOf(firstTry)).filter(node => !ts.isImportDeclaration(node)).map(node => node.getText(tree)).join('\n');
  const launchIndex = firstTry.tryBlock.statements.findIndex(node => ts.isExpressionStatement(node) && ts.isBinaryExpression(node.expression) && node.expression.left.getText(tree) === 'browser');
  expect(launchIndex).toBeGreaterThan(0);
  const first = firstTry.tryBlock.statements.slice(0, launchIndex + 1).map(node => node.getText(tree)).join('\n');
  const tag = f.expected.testTag, contentNames = ['title', 'slug', 'safeMarkdown'], contentValues = new Map(contentNames.map(name => { const statement = tree.statements.find(node => ts.isVariableStatement(node) && node.declarationList.declarations.some(d => d.name.getText(tree) === name)) as ts.VariableStatement; const value = statement.declarationList.declarations.find(d => d.name.getText(tree) === name)!.initializer!; return [name, runInNewContext(value.getText(tree), { http: { testTag: tag } })]; }));
  f.config.content = { title: contentValues.get('title'), slug: contentValues.get('slug'), markdown: contentValues.get('safeMarkdown') }; f.reference.manualJournal.content = structuredClone(f.config.content);
  if (options.wrongOldAttempt) f.reference.manualJournal.attempts.push({ key: randomUUID(), state: 'response-unknown' });
  const actors = f.config.actors, fixture = { cluster: { id: f.config.clusterId }, workspace: { id: f.config.workspaceId }, slug: 'source-only-tenant' }, published = { clusterId: f.config.clusterId, workspaceId: f.config.workspaceId, tenantSlug: fixture.slug }, scope = { cluster_id: f.config.clusterId, workspace_id: f.config.workspaceId };
  Object.assign(f.reference, { fixtures: [fixture], portalUsers: [{ ...actors.owner, label: 'developer-a', tenant: { clusterId: f.config.clusterId, workspaceId: f.config.workspaceId } }], consoleAdministrator: { user: actors.administrator }, accounts: { 'approver-only': { user: actors.approver, password: actors.approver.password, role: scope, binding: scope } } });
  const events: string[] = [], saves: any[] = [], env: Record<string, string> = { M6_MANUAL_READY: 'true', M6_MANUAL_DETAIL_REMAINING_READY: 'false', M6_MANUAL_CATALOG_FILTER_CONTINUATION_READY: 'false', M6_MANUAL_ZERO_PACKET_CONTINUATION_READY: options.flag === false ? 'false' : 'true', BOOTSTRAP_ADMIN_USERNAME: actors.administrator.username, BOOTSTRAP_ADMIN_PASSWORD: actors.administrator.password, ...(options.path ? { CHROMIUM_EXECUTABLE_PATH: options.path } : {}) }, launch = vi.fn(async launchOptions => { events.push('launch'); return { sourceOnly: true, launchOptions }; }), fakeWrite = vi.fn((_path, value) => { events.push('atomic-save'); if (options.saveFails) throw Error('SOURCE_ONLY_DISK_FAILURE'); saves.push(structuredClone(value)); }), read = vi.fn(path => { if (path === failurePath) return f.failureBytes; if (path === 'artifacts/M6/security-live.json') return JSON.stringify({ passed: 1, failed: 0, testTag: tag, fixturesForBrowser: published }); if (path === 'artifacts/M6/browser-verification.json') return JSON.stringify({ passed: 1, failed: 0 }); throw Error('UNEXPECTED_MEMORY_ONLY_READ'); });
  const code = `(async()=>{${statements}\n${first}\nreturn {journal,report,browser};})()`; let result, error;
  try { result = await runInNewContext(code, { process: { env, loadEnvFile: vi.fn(() => { throw Error('NO_ENV_READ'); }) }, existsSync: (path: string) => path === '/usr/bin/chromium', readFileSync: read, mkdirSync: vi.fn(), writeFileSync: vi.fn(), privateReference: vi.fn(() => f.reference), M6_REFERENCE: '/memory-only', collectManualUuidValues, createManualJournal, prepareManualZeroPacketContinuation, preserveManualZeroPacketContinuation, mergeManualWriteEvidence, writeManualReferenceAtomic: fakeWrite, manualChromiumLaunchOptions, chromium: { launch }, Set }); } catch (value) { error = value; }
  return { f, result, error, events, saves, launch, read };
}

describe('independent actual prelaunch statements with no real filesystem or browser IO', () => {
  it('real preflight validates original zero evidence and atomically archives stopped journal before fake configured browser launch', async () => {
    const f = await actualPrelaunch({ path: '/source-only/custom-chromium' }); expect(f.error).toBeUndefined(); expect(f.events).toEqual(['atomic-save', 'launch']); expect(f.launch).toHaveBeenCalledWith({ executablePath: '/source-only/custom-chromium' }); expect(f.saves).toHaveLength(1); expect(f.saves[0].manualZeroPacketHistory.snapshot.manualJournal.phase).toBe('stopped-without-replay'); expect(f.saves[0].manualJournal.phase).toBe('ready'); expect(f.saves[0].manualJournal.attempts).toEqual([]); expect(f.saves[0].manualZeroPacketContinuation.originalSnapshotSha256).toBe(f.result.journal.zeroPacketContinuation.originalSnapshotSha256); expect(f.result.report.zeroPacketContinuation.originalZeroPacketAttemptExcludedFromSuccess).toBe(true); expect(f.f.reference.manualJournal.phase).toBe('stopped-without-replay');
  });
  it.each(['save-failure', 'old-packet', 'missing-flag'])('actual %s stops before launch and keeps the old stopped journal unchanged', async fault => {
    const f = await actualPrelaunch({ saveFails: fault === 'save-failure', wrongOldAttempt: fault === 'old-packet', flag: fault !== 'missing-flag' }); expect(f.error).toBeTruthy(); expect(f.launch).not.toHaveBeenCalled(); expect(f.saves).toHaveLength(0); expect(f.f.reference.manualJournal.phase).toBe('stopped-without-replay'); expect(f.f.reference).not.toHaveProperty('manualZeroPacketHistory');
  });
});
