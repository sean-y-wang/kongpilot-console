import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { describe, expect, it, vi } from 'vitest';
import { PortalDocumentService } from '../../../apps/console-api/src/modules/portal/portal-document.service';
import { authorizeFreshBootstrap, beforeManualMutation, completeManualMutation, createManualJournal, stopManualJournal } from './lib/m6-manual-journal.mjs';
import { MANUAL_CATALOG_BOOTSTRAP_REQUEST_ID, prepareManualCatalogFilterContinuation, prepareManualZeroPacketContinuation, preserveManualCatalogFilterContinuation, preserveManualZeroPacketContinuation } from './lib/m6-manual-zero-packet.mjs';
import { mergeManualWriteEvidence } from './lib/m6-manual-read-evidence.mjs';

const bytes = readFileSync('artifacts/M6/UI-review-pre-catalog-filter-attempt.json'), oldBytes = readFileSync('artifacts/M6/UI-review-pre-launch-attempt.json'), failure = JSON.parse(String(bytes));
function fixture() {
  const scope = failure.readEvidence[0], expected = { testTag: failure.testTag, clusterId: scope.clusterId, workspaceId: scope.workspaceId, publicationId: scope.targetId, actors: Object.fromEntries(['owner', 'administrator', 'approver'].map(role => [role, { id: randomUUID(), username: `offline-${role}`, password: `offline-${role}-password` }])), content: { slug: `${failure.testTag}-manual-ui-page`, title: `${failure.testTag} Manual UI Page`, markdown: '# Offline only' } };
  const original = createManualJournal({ ...expected, priorKeys: [], forbiddenEntityIds: [] }); stopManualJournal(original, 'manual-harness-stopped', () => {});
  let reference: any = { testTag: expected.testTag, manualJournal: original, manualWriteAttempts: [], manualMetadata: [], manualWriteEvidence: [], writeEvidence: [{ method: 'POST', path: '/api/v1/portal/requests', requestId: randomUUID() }], secrets: ['offline-old-cookie'], priorFixtureRuns: [{ immutableHistory: true }] };
  const zero = prepareManualZeroPacketContinuation(reference, oldBytes, expected, true), stopped = createManualJournal({ ...expected, priorKeys: [], forbiddenEntityIds: [] }); stopped.zeroPacketContinuation = zero;
  reference = preserveManualZeroPacketContinuation(reference, zero, stopped); reference.manualJournal = stopped;
  authorizeFreshBootstrap(stopped, 'owner', [], () => {});
  const body = { clusterId: expected.clusterId, workspaceId: expected.workspaceId }, key = randomUUID();
  const attempt = beforeManualMutation(stopped, 'owner', { method: 'POST', url: `http://127.0.0.1:8082/api/v1/portal/auth/refresh?${new URLSearchParams(body)}`, rawBody: JSON.stringify(body), headers: { 'x-idempotency-key': key, 'content-type': 'application/json' } }, [], () => {});
  completeManualMutation(stopped, attempt, 401, { meta: { requestId: MANUAL_CATALOG_BOOTSTRAP_REQUEST_ID }, error: { code: 'PORTAL_SESSION_EXPIRED' } }, () => {}); stopManualJournal(stopped, 'manual-harness-stopped', () => {});
  reference.manualWriteAttempts = stopped.attempts;
  const plannedContent = { ...expected.content, markdown: '# New safe intent\n\n`x < 2`' }, continuationExpected = { ...expected, originalContent: expected.content, plannedContent }, active = createManualJournal({ ...expected, content: plannedContent, priorKeys: [key], forbiddenEntityIds: [] }), prepare = () => prepareManualCatalogFilterContinuation(reference, bytes, oldBytes, continuationExpected, true);
  return { reference, expected: continuationExpected, active, attempt, prepare };
}

describe('single prebusiness catalog continuation source delta', () => {
  it('uses actual aria-label contracts for search inputs and labeled downstream selectors', () => {
    const runner = readFileSync('tests/security/manual-m6-ui.mjs', 'utf8'), catalog = readFileSync('apps/portal-web/src/features/PublicPages.tsx', 'utf8');
    for (const label of ['筛选 API 分类', '搜索 API']) { expect(catalog).toContain(`Input.Search aria-label="${label}"`); expect(runner).toContain(`getByLabel('${label}', { exact: true })`); expect(runner).not.toContain(`getByRole('textbox', { name: '${label}'`); }
    expect(runner).toContain('page.getByLabel(label, { exact: true })'); expect(runner).toContain("apiEditor.getByLabel('发布 Service', { exact: true })");
    expect(runner).toContain(`.and(page.locator('input[role="combobox"]'))`); expect(runner).toContain(`.and(apiEditor.locator('input[role="combobox"]'))`);
    const tree = ts.createSourceFile('manual-m6-ui.mjs', runner, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
    const exclusive = tree.statements.find(item => ts.isIfStatement(item) && item.expression.getText(tree).includes('[zeroPacketContinuationRequested, catalogFilterContinuationRequested, detailRemainingRequested]'));
    expect(exclusive).toBeDefined();
    for (let flags = 0; flags < 8; flags++) {
      const bindings = { zeroPacketContinuationRequested: Boolean(flags & 1), catalogFilterContinuationRequested: Boolean(flags & 2), detailRemainingRequested: Boolean(flags & 4) }, evaluate = () => runInNewContext(exclusive!.getText(tree), bindings);
      if (Object.values(bindings).filter(Boolean).length > 1) expect(evaluate).toThrow('only one explicit manual continuation entry is allowed');
      else expect(evaluate).not.toThrow();
    }
  });
  it('retains complete denied anonymous packet and both older zero histories while starting no successful business replay', () => {
    const f = fixture(), original = JSON.stringify(f.reference), prepared = f.prepare(), sealed = preserveManualCatalogFilterContinuation(f.reference, prepared, f.active);
    expect(sealed.manualCatalogFilterHistory.snapshot.manualWriteAttempts[0]).toEqual(f.attempt); expect(sealed.manualCatalogFilterHistory.snapshot.manualJournal.phase).toBe('stopped-without-replay');
    expect(sealed.manualZeroPacketHistory).toBe(f.reference.manualZeroPacketHistory); expect(sealed.manualZeroPacketContinuation).toBe(f.reference.manualZeroPacketContinuation); expect(sealed.manualZeroPacketContinuation.activeJournalStartedAt).toBe(f.reference.manualJournal.startedAt);
    expect(sealed.writeEvidence).toBe(f.reference.writeEvidence); expect(f.active.nextIndex).toBe(0); expect(f.active.attempts).toHaveLength(0); expect(JSON.stringify(f.reference)).toBe(original);
    expect(() => prepareManualCatalogFilterContinuation(sealed, bytes, oldBytes, f.expected, true)).toThrow();
  });
  it('refuses foreign scope, actor, publication or changed immutable failure', () => {
    for (const reason of ['CID', 'WID', 'actor', 'publication', 'bytes']) {
      const f = fixture(); if (reason === 'CID') f.expected.clusterId = randomUUID(); if (reason === 'WID') f.expected.workspaceId = randomUUID(); if (reason === 'actor') f.expected.actors.owner.id = randomUUID(); if (reason === 'publication') f.expected.publicationId = randomUUID();
      expect(() => prepareManualCatalogFilterContinuation(f.reference, reason === 'bytes' ? String(bytes) + ' ' : bytes, oldBytes, f.expected, true)).toThrow();
    }
  });
  it('refuses any planned/nonzero evidence, unknown denial or different original body/key', () => {
    for (const reason of ['planned', 'success', 'metadata', 'unknown', 'different-status', 'request-id', 'body', 'key']) {
      const f = fixture(); if (reason === 'planned') f.reference.manualJournal.nextIndex = 1; if (reason === 'success') f.reference.manualWriteEvidence.push({ requestId: randomUUID() }); if (reason === 'metadata') f.reference.manualMetadata.push({ id: randomUUID() }); if (reason === 'unknown') f.attempt.state = 'transport-interrupted'; if (reason === 'different-status') f.attempt.status = 503; if (reason === 'request-id') f.attempt.requestId = randomUUID(); if (reason === 'body') f.attempt.rawBody = JSON.stringify({ clusterId: f.expected.clusterId, workspaceId: randomUUID() }); if (reason === 'key') f.attempt.headers['x-idempotency-key'] = randomUUID(); expect(f.prepare).toThrow();
    }
  });
  it('requires explicit new entry and refuses marker reentry or original-history drift', () => {
    const f = fixture(); expect(() => prepareManualCatalogFilterContinuation(f.reference, bytes, oldBytes, f.expected, false)).toThrow();
    const prepared = f.prepare(), sealed = preserveManualCatalogFilterContinuation(f.reference, prepared, f.active); expect(() => prepareManualCatalogFilterContinuation(sealed, bytes, oldBytes, f.expected, true)).toThrow();
    const changed = structuredClone(sealed); changed.manualZeroPacketHistory.snapshot.manualJournal.stopReason = 'modified'; expect(() => preserveManualCatalogFilterContinuation(changed, prepared, f.active)).toThrow();
    const pending = fixture(), pendingPrepared = pending.prepare(); pending.reference.manualWriteAttempts.push({ state: 'before-single-send' }); expect(() => preserveManualCatalogFilterContinuation(pending.reference, pendingPrepared, pending.active)).toThrow();
  });
  it('uses actual backend validation for future safe Markdown while sealing original unsafe intent and binding only the markdown change', () => {
    const source = readFileSync('tests/security/manual-m6-ui.mjs', 'utf8'), tree = ts.createSourceFile('manual-m6-ui.mjs', source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
    const value = (name: string) => { for (const item of tree.statements) if (ts.isVariableStatement(item)) for (const declaration of item.declarationList.declarations) if (declaration.name.getText(tree) === name && declaration.initializer && ts.isStringLiteral(declaration.initializer)) return declaration.initializer.text; throw Error('source constant absent'); };
    const service = new PortalDocumentService({ redact: (input: unknown) => input } as any), original = value('originalMarkdown'), planned = value('safeMarkdown');
    expect(service.markdown(planned)).toBe(planned); try { service.markdown(original); throw Error('unsafe unexpectedly accepted'); } catch (error: any) { expect(error.getResponse().code).toBe('PORTAL_MARKDOWN_UNSAFE'); }
    const f = fixture(), prepared = f.prepare(); expect(prepared.originalContent).toEqual(f.reference.manualJournal.content); expect(prepared.plannedContent).toEqual(f.active.content); expect(prepared.originalContent.title).toBe(prepared.plannedContent.title); expect(prepared.originalContent.slug).toBe(prepared.plannedContent.slug);
    const sealed = preserveManualCatalogFilterContinuation(f.reference, prepared, f.active); expect(sealed.manualCatalogFilterContinuation.plannedContentSha256).toBe(prepared.plannedContentSha256);
    f.active.content = { ...f.active.content, markdown: '# Changed again' }; expect(() => preserveManualCatalogFilterContinuation(sealed, prepared, f.active)).toThrow();
    const wrongTitle = fixture(); wrongTitle.expected.plannedContent.title = 'Other title'; expect(wrongTitle.prepare).toThrow();
    expect(source).toContain("renderedMarkdown.locator('script')).toHaveCount(0)"); expect(source).not.toContain("check('raw Markdown HTML not executed'");
  });
  it('actual retain atomically archives old known401 and fresh window before any possible launch, stopping on save failure', async () => {
    const source = readFileSync('tests/security/manual-m6-ui.mjs', 'utf8'), tree = ts.createSourceFile('manual-m6-ui.mjs', source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS), node = tree.statements.find(item => ts.isFunctionDeclaration(item) && item.name?.text === 'retain')!, f = fixture();
    f.active.catalogFilterContinuation = f.prepare(); const write = vi.fn();
    const retain = runInNewContext(`(${node.getText(tree)})`, { Set, privateReference: () => f.reference, M6_REFERENCE: '/offline-only', writeManualReferenceAtomic: write, preserveManualCatalogFilterContinuation, preserveManualZeroPacketContinuation, mergeManualWriteEvidence, newSecrets: new Set(), journal: f.active, manualMetadata: [], manualAttempts: f.active.attempts, writes: [] });
    retain(); const saved = write.mock.calls[0][1]; expect(saved.manualJournal).toBe(f.active); expect(saved.manualCatalogFilterHistory.snapshot.manualWriteAttempts).toEqual([f.attempt]); expect(saved.manualZeroPacketHistory).toBe(f.reference.manualZeroPacketHistory); expect(saved.manualZeroPacketContinuation).toBe(f.reference.manualZeroPacketContinuation); expect(saved.manualWriteEvidence).toHaveLength(0);
    write.mockImplementation(() => { throw Error('offline fsync failure'); }); const launch = vi.fn(); await expect((async () => { retain(); await launch(); })()).rejects.toThrow(); expect(launch).not.toHaveBeenCalled();
  });
});
