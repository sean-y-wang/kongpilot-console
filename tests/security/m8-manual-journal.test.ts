import { describe, expect, it, vi } from 'vitest';
import { M8_UI_ACTIONS, M8_UI_NOOP_YAML, createM8UiJournal, m8UiCookies, m8UiRemember, m8UiExpected, beforeM8UiPacket, proveM8UiActor, m8UiAttemptFor, observeM8UiAck, confirmM8UiReceipt, m8UiReceiptPath, bindM8UiEntity, interruptM8Ui } from './lib/m8-manual-journal.mjs';
import { sha256 } from './lib/m8-harness.mjs';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
const id = (n: number) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`, cid = id(1), wid = id(2), now = Math.floor(Date.now() / 1000) * 1000;
function fixture() {
  const sessions = Object.fromEntries(['admin', 'owner', 'readonly'].map((role, n) => { const actor = id(10 + n), sid = id(20 + n), access = `unsigned.${Buffer.from(JSON.stringify({ sub: actor, sid, exp: now / 1000 + 900 })).toString('base64url')}.synthetic`, csrf = `private-csrf-${n}`; return [role, { user: { id: actor, username: role }, sid, csrf, expiresAt: now + 900000, cookie: `kongos_access=${access}; kongos_refresh=${sid}.private-refresh-${n}; kongos_csrf=${csrf}` }]; }));
  const handoff = { version: 1, phase: 'ready', testTag: 'm8-security-aabb1122', approvedActions: [...M8_UI_ACTIONS], direct: { cid, wid }, directWorkspaceName: 'synthetic-M8', snapshotId: id(30), planId: id(31), jobId: id(32), exportId: id(33), approvalWorkflowId: id(34), approvalMode: 'completed-read-only' };
  const journal = createM8UiJournal({ handoff, sessions, now }), persist = vi.fn(); proveM8UiActor(journal, 'admin', { user: { ...sessions.admin.user, permissionsVersion: 'actual:1' }, csrfToken: sessions.admin.csrf }, persist);
  const packet = (key = id(40)) => { const plan = m8UiExpected(journal); return { method: plan.method, url: `http://127.0.0.1:8080${plan.path}?${new URLSearchParams(plan.query)}`, rawBody: JSON.stringify(plan.body), headers: { 'content-type': 'application/json', 'x-idempotency-key': key, 'x-csrf-token': sessions.admin.csrf, cookie: sessions.admin.cookie } }; };
  return { journal, sessions, handoff, persist, packet, cookies: m8UiCookies(sessions.admin, now) };
}
function receipt(journal: any, attempt: any) { const job = { id: id(50), jobId: id(50), actorId: attempt.actorId, clusterId: cid, workspaceId: wid, revision: 2, kind: attempt.kind, state: 'succeeded', safeProgress: {} }; return { ...job, domain: 'configuration', durable: true, idempotencyKey: attempt.key, originalScope: { clusterId: cid, workspaceId: wid }, job, executionCompleted: true, snapshotId: id(60), workflowId: null }; }
function acknowledged(f: ReturnType<typeof fixture>, key = id(40)) { const p = f.packet(key), attempt = beforeM8UiPacket(f.journal, 'admin', p, f.cookies, f.persist, now); observeM8UiAck(f.journal, attempt, { status: 201, requestId: id(70), data: receipt(f.journal, attempt) }, f.persist); return attempt; }
function confirm(f: ReturnType<typeof fixture>, attempt: any, data: any) { return confirmM8UiReceipt(f.journal, 'admin', { method: 'GET', url: `http://127.0.0.1:8080${m8UiReceiptPath(f.journal, attempt)}` }, data, id(71), f.persist); }

describe('M8 manual original twelve-intent source boundary', () => {
  it('admits only the five fixed actual-green report paths through the real pre-browser guard and rejects failed/unknown/stale handoffs', () => {
    const source = ts.createSourceFile('manual-m8-ui.mjs', readFileSync('tests/security/manual-m8-ui.mjs', 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    const end = source.statements.findIndex(row => ts.isVariableStatement(row) && row.declarationList.declarations.some(declaration => declaration.name.getText(source) === 'originalCount'));
    expect(end).toBeGreaterThan(0);
    const prefix = source.statements.slice(0, end).filter(row => !ts.isImportDeclaration(row)).map(row => row.getText(source)).join('\n');
    const report = { milestone: 'M8', testTag: 'm8-security-aabb1122', allPassed: true, failed: 0, unknownWrites: 0 };
    function run(path: string, changeReference: (row: any) => void = () => {}, changeReport: (row: any) => void = () => {}, ready = true) {
      const f = fixture(), actualReport = structuredClone(report); changeReport(actualReport);
      const bytes = Buffer.from(JSON.stringify(actualReport)), reference = { phase: 'http-complete', httpAcceptanceComplete: true, testTag: f.handoff.testTag, scopes: { direct: { cid, wid } }, sessions: { admin:f.sessions.admin,owner:f.sessions.owner,'read-only':f.sessions.readonly }, requests: Array.from({ length: 133 }, (_, index) => ({ index, key: id(100 + index), state: 'response_observed' })), inFlight: null, manualUiHandoff: { ...f.handoff, securityReportPath: path, securityReportSha256: sha256(bytes) } };
      changeReference(reference); const privateReader = vi.fn(() => reference), reportReader = vi.fn((requested: string) => { expect(requested).toBe(path); return bytes; });
      const execute = () => runInNewContext(prefix, { process: { env: { M8_MANUAL_UI_READY: ready ? 'true' : 'false' } }, readM8Reference: privateReader, readFileSync: reportReader, sha256, createM8UiJournal, isM8ProvenConsumedUnknownDownload:()=>false });
      return { execute, privateReader, reportReader, reference };
    }
    for (const path of ['artifacts/M8/security-live-final.json', 'artifacts/M8/security-live-deck124-compatibility.json', 'artifacts/M8/security-live-deck-pool-transaction.json', 'artifacts/M8/security-live-deck-record-merge.json', 'artifacts/M8/security-live-deck-wire-body.json', 'artifacts/M8/security-live-http-closed.json', 'artifacts/M8/security-live-http-verified.json', 'artifacts/M8/security-live-audit-chain-final.json', 'artifacts/M8/security-live-manual-edge-ready.json', 'artifacts/M8/security-live-independent-manual-ready.json']) { const f = run(path); expect(f.execute).not.toThrow(); expect(f.reportReader).toHaveBeenCalledTimes(1); expect(f.reference.requests).toHaveLength(133); }
    for (const path of ['artifacts/M8/security-live-deck-wire-body.json?green=true', 'artifacts/M8/../M8/security-live-deck-wire-body.json', '/tmp/security-live-deck-wire-body.json', 'artifacts/M8/security-live-expired-execution-recovery.json']) { const f = run(path); expect(f.execute).toThrow('M8_UI_ACTUAL_HTTP_GREEN_HANDOFF_REQUIRED'); expect(f.reportReader).not.toHaveBeenCalled(); }
    for (const change of [(row: any) => { row.allPassed = false; }, (row: any) => { row.failed = 1; }, (row: any) => { row.unknownWrites = 1; }, (row: any) => { row.testTag = 'm8-security-ffffffff'; }]) expect(run('artifacts/M8/security-live-deck-wire-body.json', undefined, change).execute).toThrow('M8_UI_HTTP_ACTUAL_REPORT_NOT_BOUND');
    for (const change of [(row: any) => { row.manualUiHandoff.securityReportSha256 = 'b'.repeat(64); }, (row: any) => { row.phase = 'cli-running'; }, (row: any) => { row.httpAcceptanceComplete = false; }, (row: any) => { row.requests[132].state = 'response_unknown'; }, (row: any) => { row.inFlight = 132; }, (row: any) => { row.manualUiHandoff.direct.wid = id(99); }, (row: any) => { row.sessions.admin.expiresAt=Date.now()+299000; }, (row: any) => { row.sessions.owner.sid=id(99); }]) expect(run('artifacts/M8/security-live-deck-wire-body.json', change).execute).toThrow();
    const denied = run('artifacts/M8/security-live-deck124-compatibility.json', undefined, undefined, false); expect(denied.execute).toThrow('M8_MANUAL_EXCLUSIVE_PHASE_HANDOFF_REQUIRED'); expect(denied.privateReader).not.toHaveBeenCalled();
  });
  it('requires exact handoff and original actor/SID/current cookie budget without identity inference', () => {
    const f = fixture(); expect(M8_UI_ACTIONS).toHaveLength(12); expect(m8UiCookies(f.sessions.admin, now)).toHaveLength(3);
    for (const patch of [{ approvedActions: [...M8_UI_ACTIONS].reverse() }, { phase: 'not-ready' }, { approvalMode: 'write' }, { planId: 'foreign' }, { directWorkspaceName: '' }]) expect(() => createM8UiJournal({ handoff: { ...f.handoff, ...patch }, sessions: f.sessions, now })).toThrow();
    expect(() => m8UiCookies({ ...f.sessions.admin, sid: id(22) }, now)).toThrow(); expect(() => m8UiCookies(f.sessions.admin, now + 601000)).toThrow();
  });
  it('persists exact raw body, key, actor and original scope before returning transport authorization', () => {
    const f = fixture(), events: string[] = [], packet = f.packet(), attempt = beforeM8UiPacket(f.journal, 'admin', packet, f.cookies, () => { events.push('persist'); expect(f.journal.attempts[0].state).toBe('prepared'); }, now); events.push('continue');
    expect(events).toEqual(['persist', 'continue']); expect(attempt).toMatchObject({ actorId: f.sessions.admin.user.id, sessionId: f.sessions.admin.sid, clusterId: cid, workspaceId: wid, rawBody: packet.rawBody, bodySha256: sha256(packet.rawBody), key: id(40) });
    const failed = fixture(); expect(() => beforeM8UiPacket(failed.journal, 'admin', failed.packet(), failed.cookies, () => { throw Error('disk'); }, now)).toThrow(); expect(failed.journal.phase).toBe('stopped-without-replay');
  });
  it('denies auth/native/foreign/extra body and duplicate key packets globally before transport', () => {
    for (const mutation of [(p: any) => ({ ...p, url: 'http://127.0.0.1:8080/api/v1/auth/refresh' }), (p: any) => ({ ...p, url: p.url.replace('/snapshots?', '/entities/services?') }), (p: any) => ({ ...p, url: p.url.replace(wid, id(99)) }), (p: any) => ({ ...p, rawBody: JSON.stringify({ ...JSON.parse(p.rawBody), approved: true }) })]) { const f = fixture(); expect(() => beforeM8UiPacket(f.journal, 'admin', mutation(f.packet()), f.cookies, f.persist, now)).toThrow(); expect(f.journal.phase).toBe('stopped-without-replay'); expect(f.journal.attempts[0].state).toBe('blocked-before-packet'); }
    const f = fixture(), attempt = acknowledged(f); confirm(f, attempt, receipt(f.journal, attempt)); expect(() => beforeM8UiPacket(f.journal, 'admin', f.packet(), f.cookies, f.persist, now)).toThrow();
  });
  it('uses full original packet identity and leaves ACK pending until protected terminal receipt proof', () => {
    const f = fixture(), p = f.packet(), attempt = beforeM8UiPacket(f.journal, 'admin', p, f.cookies, f.persist, now); expect(m8UiAttemptFor(f.journal, { ...p, rawBody: p.rawBody + ' ' })).toBeUndefined(); expect(m8UiAttemptFor(f.journal, p)).toBe(attempt);
    observeM8UiAck(f.journal, attempt, { status: 201, requestId: id(70), data: receipt(f.journal, attempt) }, f.persist); expect(f.journal.nextIndex).toBe(0); const pending = receipt(f.journal, attempt); pending.state = pending.job.state = 'running'; expect(confirm(f, attempt, pending)).toBe(false); expect(f.journal.nextIndex).toBe(0); expect(confirm(f, attempt, receipt(f.journal, attempt))).toBe(true); expect(f.journal.nextIndex).toBe(1);
  });
  it('rejects foreign receipt actor/key/CID/WID and unknown outcome without advancing or permitting another packet', () => {
    for (const patch of [{ actorId: id(99) }, { idempotencyKey: id(99) }, { clusterId: id(99) }, { workspaceId: id(99) }, { originalScope: { clusterId: cid, workspaceId: id(99) } }, { state: 'uncertain' }]) { const f = fixture(), attempt = acknowledged(f); expect(() => confirm(f, attempt, { ...receipt(f.journal, attempt), ...patch })).toThrow(); expect(f.journal.nextIndex).toBe(0); expect(f.journal.phase).toBe('stopped-without-replay'); }
    const f = fixture(), attempt = beforeM8UiPacket(f.journal, 'admin', f.packet(), f.cookies, f.persist, now); expect(() => interruptM8Ui(f.journal, attempt, f.persist)).toThrow(); expect(attempt.state).toBe('response_unknown'); expect(() => beforeM8UiPacket(f.journal, 'admin', f.packet(id(41)), f.cookies, f.persist, now)).toThrow();
  });
  it('binds actual exportRevision independently of jobRevision and received download bytes to its one-use receipt', () => {
    const f = fixture(); f.journal.nextIndex = 1; const attempt = acknowledged(f), exported = { ...receipt(f.journal, attempt), mode: 'review', exportId: id(80), exportRevision: 8, confirmationName: 'synthetic-M8', capabilities: { download: true } }; exported.job = { ...exported.job, ...exported, job: undefined }; confirm(f, attempt, exported); expect(m8UiExpected(f.journal).body.revision).toBe(8);
    const binary = beforeM8UiPacket(f.journal, 'admin', f.packet(id(41)), f.cookies, f.persist, now); observeM8UiAck(f.journal, binary, { status: 200, requestId: id(70), binary: { bytes: 42, sha256: 'a'.repeat(64), yaml: true, noStore: true, nosniff: true, exportId: id(80) } }, f.persist); expect(() => confirm(f, binary, { ...receipt(f.journal, binary), exportId: id(80), downloadPermitConsumed: true, byteCount: 41 })).toThrow(); expect(f.journal.nextIndex).toBe(2);
  });
  it('keeps empty merge no-op and reconcile observation separate from Native success claims', async () => {
    const { parseDeckDocument } = await import('../../apps/console-api/src/modules/config-transfer/deck-parser');
    expect(parseDeckDocument(M8_UI_NOOP_YAML).document.services).toEqual([]);
    const f = fixture(); f.journal.nextIndex = 11; bindM8UiEntity(f.journal, 'plan', { id: f.handoff.planId, clusterId: cid, workspaceId: wid, revision: 3, planRevision: 2, planHash: 'a'.repeat(64), stepCount: 1 }, f.persist); expect(m8UiExpected(f.journal)).toMatchObject({ kind: 'reconcile', body: { revision: 3, planHash: 'a'.repeat(64) } });
    const attempt = acknowledged(f), observed = receipt(f.journal, attempt); observed.job.safeProgress = { readOnly: true, executionChanged: false, reconciledPlanId: f.handoff.planId, observations: [{ causalOutcomeUnproven: true }] }; expect(confirm(f, attempt, observed)).toBe(true); expect(f.journal.phase).toBe('complete'); expect(observed.job.safeProgress.executionChanged).toBe(false);
  });
  it('retains credential values while excluding public URLs, idempotency UUIDs and safe masks from secret classification', () => {
    const values = m8UiRemember({ endpoint: 'https://fixture.invalid/hook', key: id(40), idempotencyKey: id(41), token: 'private-token', nested: { csrfToken: 'private-csrf', secret: '[REDACTED:abcdef0123456789]' } }); expect([...values]).toEqual(['private-token', 'private-csrf']);
  });
  it('runs the actual browser route boundary in memory: persistence precedes continue and save failure permits only abort', async () => {
    const source = ts.createSourceFile('manual-m8-ui.mjs', readFileSync('tests/security/manual-m8-ui.mjs', 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS), node = source.statements.find(row => ts.isFunctionDeclaration(row) && row.name?.text === 'boundary')!;
    for (const failSave of [false, true]) {
      const f = fixture(), trace: string[] = []; let handler: (route: any) => Promise<void>;
      const boundary = runInNewContext(`(${node.getText(source)})`, { URL, journal: f.journal, beforeM8UiPacket, stopM8Ui: (journal: any, reason: string) => { journal.phase = 'stopped-without-replay'; journal.stopReason = reason; }, packet: (request: any, headers: any) => ({ method: request.method(), url: request.url(), rawBody: request.postData(), headers }), retain: () => { trace.push('fsync-save'); if (failSave) throw Error('synthetic-save-failed'); } });
      await boundary({ route: async (_pattern: string, callback: any) => { handler = callback; }, cookies: async () => f.cookies, on: () => {} }, 'admin'); const wire = f.packet();
      await handler!({ request: () => ({ method: () => wire.method, url: () => wire.url, postData: () => wire.rawBody, allHeaders: async () => wire.headers }), continue: async () => trace.push('transport'), abort: async () => trace.push('abort') });
      if (failSave) { expect(trace).not.toContain('transport'); expect(trace.at(-1)).toBe('abort'); expect(f.journal.phase).toBe('stopped-without-replay'); } else expect(trace).toEqual(['fsync-save', 'transport']);
    }
  });
});
