import { randomUUID, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { describe, expect, it, vi } from 'vitest';
import { createManualJournal, stopManualJournal } from './lib/m6-manual-journal.mjs';
import { MANUAL_PRE_LAUNCH_FAILURE_SHA256, manualChromiumLaunchOptions, prepareManualZeroPacketContinuation, preserveManualZeroPacketContinuation } from './lib/m6-manual-zero-packet.mjs';
import { mergeManualWriteEvidence } from './lib/m6-manual-read-evidence.mjs';

const failureBytes = readFileSync('artifacts/M6/UI-review-pre-launch-attempt.json'), failure = JSON.parse(String(failureBytes));
function fixture() {
  const expected = { testTag: failure.testTag, clusterId: randomUUID(), workspaceId: randomUUID(), actors: Object.fromEntries(['owner', 'administrator', 'approver'].map(role => [role, { id: randomUUID(), username: `offline-${role}`, password: `offline-${role}-password` }])), content: { slug: `${failure.testTag}-manual-ui-page`, title: `${failure.testTag} Manual UI Page`, markdown: '# Offline safe content' } };
  const old = createManualJournal({ ...expected, priorKeys: [randomUUID()], forbiddenEntityIds: [randomUUID()] }); stopManualJournal(old, 'manual-harness-stopped', () => {});
  const reference: any = { testTag: expected.testTag, manualJournal: old, manualMetadata: [], manualWriteAttempts: [], manualWriteEvidence: [], writeEvidence: [{ requestId: randomUUID(), method: 'POST', path: '/api/v1/portal/requests', history: true }], secrets: ['offline-original-secret'], priorFixtureRuns: [{ id: randomUUID(), history: 'original' }], browserRemaining: { originalUnknown: true } };
  const active = createManualJournal({ ...expected, priorKeys: old.priorKeys, forbiddenEntityIds: old.forbiddenEntityIds });
  const prepare = () => prepareManualZeroPacketContinuation(reference, failureBytes, expected, true);
  return { reference, expected, old, active, prepare };
}
describe('manual launch follows actual Playwright path policy', () => {
  it('prefers explicitly configured Chromium without statting fallback', () => {
    const exists = vi.fn(() => true); expect(manualChromiumLaunchOptions({ CHROMIUM_EXECUTABLE_PATH: '/offline/custom/chromium' }, exists)).toEqual({ executablePath: '/offline/custom/chromium' }); expect(exists).not.toHaveBeenCalled();
  });
  it('selects system Chromium only when it exists', () => {
    const exists = vi.fn(() => true); expect(manualChromiumLaunchOptions({}, exists)).toEqual({ executablePath: '/usr/bin/chromium' }); expect(exists).toHaveBeenCalledWith('/usr/bin/chromium');
  });
  it('uses bundled fallback when neither explicit nor system Chromium is available', () => {
    expect(manualChromiumLaunchOptions({ CHROMIUM_EXECUTABLE_PATH: '' }, () => false)).toEqual({});
  });
});
describe('one explicit continuation of immutable pre-launch zero-packet failure', () => {
  it('binds original actual failure SHA and preserves complete zero-state private records in memory', () => {
    expect(createHash('sha256').update(failureBytes).digest('hex')).toBe(MANUAL_PRE_LAUNCH_FAILURE_SHA256);
    const f = fixture(), before = JSON.stringify(f.reference), prepared = f.prepare();
    expect(prepared.snapshot).toEqual({ manualJournal: f.old, manualMetadata: [], manualWriteAttempts: [], manualWriteEvidence: [] }); expect(prepared.originalSnapshotSha256).toBe(createHash('sha256').update(JSON.stringify(prepared.snapshot)).digest('hex')); expect(JSON.stringify(f.reference)).toBe(before);
  });
  it.each([false, undefined, 'true', 1])('requires exact explicit continuation authorization (%s refused)', flag => {
    const f = fixture(); expect(() => prepareManualZeroPacketContinuation(f.reference, failureBytes, f.expected, flag)).toThrow('M6_MANUAL_ZERO_PACKET_CONTINUATION_REJECTED');
  });
  it.each(['whitespace', 'actions', 'screenshots', 'planned', 'success', 'bootstrap', 'phase', 'stage', 'identity'])('rejects %s changes to immutable public failure rather than opening a replay', reason => {
    const f = fixture(), changed = structuredClone(failure);
    if (reason === 'actions') changed.writeBoundary.actions.push({ action: 'portal-owner-login' });
    if (reason === 'screenshots') changed.screenshots.push('offline.png');
    if (reason === 'planned') changed.writeBoundary.plannedWrites = 1;
    if (reason === 'success') changed.writeBoundary.successfulPlannedWrites = 1;
    if (reason === 'bootstrap') changed.writeBoundary.expectedDeniedAnonymousBootstrapWrites = 1;
    if (reason === 'phase') changed.checks[0].name = 'harness stopped after login';
    if (reason === 'stage') changed.stage = 'source-only';
    if (reason === 'identity') changed.testTag = 'foreign-fixture';
    expect(() => prepareManualZeroPacketContinuation(f.reference, reason === 'whitespace' ? String(failureBytes) + ' ' : JSON.stringify(changed), f.expected, true)).toThrow();
  });
  it.each(['private-attempt', 'manual-attempt', 'manual-write-evidence', 'metadata', 'index', 'inflight', 'page-id', 'page-revision', 'authenticated', 'fresh-context', 'phase', 'stop-reason', 'old-continuation', 'old-history'])('rejects private %s state that is not original unstarted window', reason => {
    const f = fixture();
    if (reason === 'private-attempt') f.old.attempts.push({ action: 'portal-owner-login' });
    if (reason === 'manual-attempt') f.reference.manualWriteAttempts.push({ state: 'unknown' });
    if (reason === 'manual-write-evidence') f.reference.manualWriteEvidence.push({ requestId: randomUUID() });
    if (reason === 'metadata') f.reference.manualMetadata.push({ id: randomUUID() });
    if (reason === 'index') f.old.nextIndex = 1;
    if (reason === 'inflight') f.old.inFlight = 'original-request';
    if (reason === 'page-id') f.old.pageId = randomUUID();
    if (reason === 'page-revision') f.old.pageRevision = 1;
    if (reason === 'authenticated') f.old.authenticated.owner = f.expected.actors.owner.id;
    if (reason === 'fresh-context') f.old.freshContexts.owner = { authorizedAt: 'offline' };
    if (reason === 'phase') f.old.phase = 'ready';
    if (reason === 'stop-reason') f.old.stopReason = 'transport-interrupted';
    if (reason === 'old-continuation') f.reference.manualZeroPacketContinuation = null;
    if (reason === 'old-history') f.reference.manualZeroPacketHistory = {};
    expect(f.prepare).toThrow();
  });
  it.each(['CID', 'WID', 'testTag', 'actor-id', 'actor-username', 'actor-password', 'content', 'missing-evidence'])('rejects changed %s relative to current trusted scope and actors', reason => {
    const f = fixture();
    if (reason === 'CID') f.old.clusterId = randomUUID();
    if (reason === 'WID') f.old.workspaceId = randomUUID();
    if (reason === 'testTag') f.reference.testTag = 'foreign-fixture';
    if (reason === 'actor-id') f.expected.actors.owner.id = randomUUID();
    if (reason === 'actor-username') f.expected.actors.administrator.username = 'foreign-administrator';
    if (reason === 'actor-password') f.expected.actors.approver.password = 'different-private-password';
    if (reason === 'content') f.expected.content.markdown = '# Changed intent';
    if (reason === 'missing-evidence') delete f.reference.manualWriteEvidence;
    expect(f.prepare).toThrow();
  });
  it('archives old stopped records and consumes exception together without resetting original journal', () => {
    const f = fixture(), before = JSON.stringify(f.reference), prepared = f.prepare(), archived = preserveManualZeroPacketContinuation(f.reference, prepared, f.active);
    expect(archived.manualZeroPacketHistory.snapshot).toEqual(prepared.snapshot); expect(archived.manualZeroPacketHistory.originalSnapshotSha256).toBe(prepared.originalSnapshotSha256); expect(archived.manualJournal).toBe(f.old); expect(f.old.phase).toBe('stopped-without-replay');
    expect(archived.manualZeroPacketContinuation.activeJournalStartedAt).toBe(f.active.startedAt); expect(archived.writeEvidence).toBe(f.reference.writeEvidence); expect(archived.secrets).toBe(f.reference.secrets); expect(archived.priorFixtureRuns).toBe(f.reference.priorFixtureRuns); expect(JSON.stringify(f.reference)).toBe(before);
    expect(() => prepareManualZeroPacketContinuation(archived, failureBytes, f.expected, true)).toThrow();
  });
  it('preserves sealed history during new active progress and refuses history drift', () => {
    const f = fixture(), prepared = f.prepare(), archived = preserveManualZeroPacketContinuation(f.reference, prepared, f.active), latest = { ...archived, manualJournal: f.active };
    f.active.nextIndex = 1; f.active.authenticated.owner = f.expected.actors.owner.id; expect(preserveManualZeroPacketContinuation(latest, prepared, f.active)).toBe(latest);
    latest.manualZeroPacketHistory.snapshot.manualJournal.stopReason = 'modified'; expect(() => preserveManualZeroPacketContinuation(latest, prepared, f.active)).toThrow();
  });
  it.each(['latest-zero-field', 'snapshot', 'missing-marker', 'foreign-active', 'different-active-start'])('refuses %s before replacement or launch', reason => {
    const f = fixture(), prepared = f.prepare(); let latest: any = f.reference;
    if (reason === 'latest-zero-field') latest.manualWriteAttempts.push({ state: 'before-single-send' });
    if (reason === 'snapshot') prepared.snapshot.manualJournal.nextIndex = 1;
    if (reason === 'missing-marker') { latest = preserveManualZeroPacketContinuation(latest, prepared, f.active); delete latest.manualZeroPacketContinuation; }
    if (reason === 'foreign-active') f.active.workspaceId = randomUUID();
    if (reason === 'different-active-start') { latest = preserveManualZeroPacketContinuation(latest, prepared, f.active); f.active.startedAt = '2026-10-12T00:00:00.000Z'; }
    expect(() => preserveManualZeroPacketContinuation(latest, prepared, f.active)).toThrow();
  });
});
describe('actual runner zero-packet boundary is durable before launch', () => {
  const source = readFileSync('tests/security/manual-m6-ui.mjs', 'utf8'), tree = ts.createSourceFile('manual-m6-ui.mjs', source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
  const retainSource = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'retain')!.getText(tree);
  function retainFixture() {
    const f = fixture(), prepared = f.prepare(); f.active.zeroPacketContinuation = prepared;
    const write = vi.fn(), retain = runInNewContext(`(${retainSource})`, { Set, privateReference: () => f.reference, M6_REFERENCE: '/offline-only', writeManualReferenceAtomic: write, preserveManualZeroPacketContinuation, mergeManualWriteEvidence, newSecrets: new Set(['offline-new-secret']), journal: f.active, manualMetadata: [], manualAttempts: f.active.attempts, writes: [] });
    return { ...f, prepared, write, retain };
  }
  it('actual retain sends original sealed journal and new journal together to atomic writer', () => {
    const f = retainFixture(); f.retain(); const payload = f.write.mock.calls[0][1];
    expect(payload.manualJournal).toBe(f.active); expect(payload.manualZeroPacketHistory.snapshot.manualJournal).toEqual(f.old); expect(payload.manualZeroPacketContinuation.activeJournalStartedAt).toBe(f.active.startedAt); expect(payload.writeEvidence).toEqual(f.reference.writeEvidence); expect(payload.secrets).toEqual(['offline-original-secret', 'offline-new-secret']);
  });
  it('cannot reach browser launch if history preservation or private durability fails', async () => {
    for (const failure of ['history', 'durability']) {
      const f = retainFixture(), launch = vi.fn(); if (failure === 'history') f.reference.manualWriteAttempts.push({ state: 'unknown' }); else f.write.mockImplementation(() => { throw Error('offline fsync failure'); });
      await expect((async () => { f.retain(); await launch(); })()).rejects.toThrow(); expect(launch).not.toHaveBeenCalled();
    }
  });
  it('retains ordinary refusal, explicit zero flag and before-launch preservation order', () => {
    expect(source).toContain("process.env.M6_MANUAL_ZERO_PACKET_CONTINUATION_READY === 'true'"); expect(source).toContain('if (!zeroPacketContinuationRequested && (reference.manualJournal');
    expect(source).toContain('if (zeroPacketContinuationRequested) journal.zeroPacketContinuation = prepareManualZeroPacketContinuation'); expect(source).toContain("readFileSync('artifacts/M6/UI-review-pre-launch-attempt.json')");
    expect(source).toContain('chromium.launch(manualChromiumLaunchOptions(process.env, existsSync))');
    const startup = tree.statements.find(node => ts.isTryStatement(node)) as ts.TryStatement;
    expect(startup.tryBlock.statements[0].getText(tree)).toBe('retain();');
    expect(startup.tryBlock.statements.findIndex(node => node.getText(tree).includes('browser = await chromium.launch'))).toBeGreaterThan(0);
    expect(source).not.toContain('delete reference.manualJournal');
  });
});
