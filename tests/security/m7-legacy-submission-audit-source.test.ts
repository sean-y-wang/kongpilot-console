import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { describe, expect, it, vi } from 'vitest';
import { auditPatchMatches } from './lib/m7-audit-acceptance.mjs';
import { M7_LEGACY_WORKFLOW_SUBMISSION_CHECKPOINT, prepareLegacySubmissionAuditProof } from './lib/m7-legacy-submission-audit.mjs';
import { EVENT_WORKFLOW_HANDLERS } from '../../apps/console-api/src/modules/workflows/event-workflow';

const digest = (value: any) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const sourceFile = fileURLToPath(new URL('./lib/m7-legacy-submission-audit.mjs',import.meta.url));
const fixedHandlers = Object.keys(EVENT_WORKFLOW_HANDLERS);
/** Positive simulation replaces only the hard-coded trust anchor in RAM. The
 * actual deployed/source module retains the real sealed SHA and rejects this
 * synthetic journal. No source/file/env/HTTP/SQL state is changed by the test. */
async function fixture() {
  const cid = randomUUID(), wid = randomUUID(), actor = { user: { id: randomUUID() }, sid: randomUUID() }, views = new Map(), receipts = new Map(), reads: any[] = [];
  const requests = Array.from({ length: 258 }, (_, index) => ({ index, method: 'POST', state: 'response_observed', status: 401, requestId: randomUUID() } as any));
  for (let index = 0; index < 12; index++) {
    const workflowId = randomUUID(), planHash = digest(`plan-${index}`), body = { name: `channel-${index}` }, key = randomUUID();
    const responseData = { domain: 'workflow', id: workflowId, workflowId, handler: fixedHandlers[index % 9], planHash, clusterId: cid, workspaceId: wid, idempotencyKey: key,
      state: 'pending', submissionCompleted: true, configurationCommitted: false, executionCompleted: false,
      entity: { id: workflowId, clusterId: cid, workspaceId: wid, kind: 'event-metadata', planHash } };
    requests[index + 5] = { index: index + 5, key, method: 'POST', path: `/api/v1/clusters/${cid}/events/channels`, query: `?workspaceId=${wid}`, body, bodySha256: digest(body),
      state: 'response_observed', status: 201, actorId: actor.user.id, sessionId: actor.sid, clusterId: cid, workspaceId: wid, requestId: randomUUID(), responseData };
    receipts.set(key, { ...structuredClone(responseData), state: 'succeeded', configurationCommitted: true, executionCompleted: true });
    const after = { kind: 'event-metadata', planHash, approvalRequired: true };
    const view = { id: randomUUID(), actorId: actor.user.id, actorType: 'user', sourceIp: null, clusterId: cid, workspaceId: wid, entityType: 'workflows', entityId: workflowId,
      workflowId, action: 'workflow.submit', before: null, after, jsonPatch: [{ op: 'replace', path: '', value: structuredClone(after) }], result: 'success', requestId: null,
      occurredAt: new Date().toISOString(), scopeQuality: 'verified' };
    views.set(workflowId, view);
  }
  const checkpoint = { ...M7_LEGACY_WORKFLOW_SUBMISSION_CHECKPOINT, packetSha256: digest(requests) };
  const text = readFileSync(sourceFile, 'utf8').replace(M7_LEGACY_WORKFLOW_SUBMISSION_CHECKPOINT.packetSha256, checkpoint.packetSha256)
    .replace("new URL('../../../apps/console-api/src/modules/workflows/event-workflow.ts', import.meta.url)", JSON.stringify(fileURLToPath(new URL('../../apps/console-api/src/modules/workflows/event-workflow.ts',import.meta.url))));
  const moduleUrl = 'data:text/javascript;base64,' + Buffer.from(text).toString('base64'), helper: any = await import(moduleUrl);
  const h: any = { state: { requests, sessions: { owner: actor }, secrets: [], testTag: 'synthetic-legacy', fixtures: [], scopes: { direct: { cid, wid } } }, save: vi.fn(),
    check(condition: any, name: string) { if (!condition) throw Error(name); }, data: (result: any) => result.payload.data };
  h.request = vi.fn(async (session: any, path: string) => {
    reads.push({ session, path }); const uri = new URL('https://synthetic.invalid' + path); let data: any;
    if (uri.pathname.includes('/events/operations/by-key/')) {
      if (session !== actor || actor.revoked) throw Error('ORIGINAL_ACTOR_UNAVAILABLE');
      data = receipts.get(uri.pathname.split('/').at(-1));
    } else if (uri.pathname.endsWith('/audit') || uri.pathname === '/audit/global') {
      data = { items: uri.searchParams.has('requestId') ? [] : [views.get(uri.searchParams.get('workflowId'))], total: null, nextCursor: null };
    } else if (uri.pathname.includes('/audit/')) data = [...views.values()].find(view => view.id === uri.pathname.split('/').at(-1));
    else throw Error('UNEXPECTED_SYNTHETIC_ROUTE');
    return { status: 200, requestId: randomUUID(), payload: { data: structuredClone(data) } };
  });
  const verifyView = (_h: any, view: any) => { if (!auditPatchMatches(view)) throw Error('INDEPENDENT_PATCH_MISMATCH'); };
  return { h, actor, actors: { admin: { user: { id: randomUUID() }, sid: randomUUID() }, direct: { cid, wid } }, views, receipts, reads, checkpoint, helper, moduleUrl, verifyView };
}

describe('sealed M7 twelve legacy submission correlation exceptions', () => {
  it('actual production trust anchors reject an arbitrary synthetic journal before scheduling any BFF read', async () => {
    const f = await fixture(); await expect(prepareLegacySubmissionAuditProof(f.h, f.actors, f.checkpoint, f.verifyView)).rejects.toThrow('exact archived 258-packet');
    expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.state.legacyWorkflowSubmissionAuditProof).toBeUndefined();
  });
  it('requires explicit first-call provenance and never silently enables historical fallback', async () => {
    const f = await fixture(); expect(await f.helper.prepareLegacySubmissionAuditProof(f.h, f.actors, undefined, f.verifyView)).toEqual(new Map()); expect(f.h.request).not.toHaveBeenCalled();
  });
  it('independently proves exactly twelve original active owner receipts and workflow audit/details, then reuses immutable proof after owner disable', async () => {
    const f = await fixture(), prefix = JSON.stringify(f.h.state.requests), proof = await f.helper.prepareLegacySubmissionAuditProof(f.h, f.actors, f.checkpoint, f.verifyView);
    expect(proof.size).toBe(12); expect(f.h.state.legacyWorkflowSubmissionAuditProof).toMatchObject({ state: 'complete', records: Array(12).fill(expect.any(Object)) });
    expect(f.reads.filter(read => read.path.includes('/events/operations/by-key/'))).toHaveLength(12); expect(JSON.stringify(f.h.state.requests)).toBe(prefix);
    f.actor.revoked = true; f.h.state.cleanupStarted = true; f.h.request.mockClear();
    const current = await f.helper.prepareLegacySubmissionAuditProof(f.h, f.actors, undefined, f.verifyView);
    expect(f.h.request).not.toHaveBeenCalled();
    for (const [packet, record] of current) await f.helper.readLegacySubmissionAuditTerminal(f.h, f.actors, packet, record, f.verifyView);
    expect(f.h.request).toHaveBeenCalledTimes(12); expect(f.h.request.mock.calls.every(([session]: any[]) => session === f.actors.admin)).toBe(true);
  });
  it('full coverage explicitly counts twelve legacy ledger matches separately from original request matches', async () => {
    const f = await fixture(), path = fileURLToPath(new URL('./lib/m7-audit-acceptance.mjs',import.meta.url));
    const text = readFileSync(path, 'utf8').replace(/from '([^']+)'/g, (_all, specifier) => `from ${JSON.stringify(specifier === './m7-legacy-submission-audit.mjs' ? f.moduleUrl : specifier.startsWith('.') ? new URL(specifier, pathToFileURL(path)).href : specifier === 'fast-json-patch' ? pathToFileURL(createRequire(import.meta.url).resolve('fast-json-patch/index.mjs')).href : specifier)}`);
    const helper: any = await import('data:text/javascript;base64,' + Buffer.from(text).toString('base64'));
    expect(await helper.auditAllWritesCoverage(f.h, f.actors, f.checkpoint)).toMatchObject({ successfulWrites: 12, coveredWrites: 12, submissionOnlyWrites: 12,
      auditedWriteRequests: 0, legacyMissingRequestMetadata: 12, ledgerMatchedLegacyWrites: 12, requestMatchedWrites: 0, allRequestIdsMatched: false, allCovered: true });
    // A fresh later submission remains strict even when an identical handler
    // and a plausible legacy-looking audit already exist elsewhere.
    f.h.state.requests.push({ ...structuredClone(f.h.state.requests[5]), index: 258, key: randomUUID(), requestId: randomUUID() });
    await expect(helper.auditAllWritesCoverage(f.h, f.actors)).rejects.toThrow('actual successful terminal audit');
  });
  it.each(['prefix', 'failed-artifact', 'readonly-proof', 'body', 'SID', 'scope', 'namespace', 'handler', 'workflow'])('rejects changed %s before current BFF reads', async defect => {
    const f = await fixture(), packet = f.h.state.requests[5];
    if (defect === 'prefix') f.h.state.requests[200].status = 403;
    if (defect === 'failed-artifact') f.checkpoint.failedArtifactSha256 = '0'.repeat(64);
    if (defect === 'readonly-proof') f.checkpoint.legacyReadonlyProofSha256 = '0'.repeat(64);
    if (defect === 'body') packet.body.name = 'changed';
    if (defect === 'SID') packet.sessionId = randomUUID();
    if (defect === 'scope') packet.workspaceId = randomUUID();
    if (defect === 'namespace') packet.path = packet.path.replace('/events/', '/portal/');
    if (defect === 'handler') packet.responseData.handler = 'event.unknown';
    if (defect === 'workflow') packet.responseData.planHash = '0'.repeat(64);
    await expect(f.helper.prepareLegacySubmissionAuditProof(f.h, f.actors, f.checkpoint, f.verifyView)).rejects.toThrow(); expect(f.h.request).not.toHaveBeenCalled();
  });
  it.each(['foreign-key', 'wrong-hash', 'wrong-handler', 'wrong-workspace', 'nonterminal', 'lost-submission', 'lost-execution'])('rejects a plausible current original receipt with %s', async defect => {
    const f = await fixture(), current = f.receipts.get(f.h.state.requests[5].key);
    if (defect === 'foreign-key') current.idempotencyKey = randomUUID(); if (defect === 'wrong-hash') current.planHash = '0'.repeat(64);
    if (defect === 'wrong-handler') current.handler = 'event.channel.test'; if (defect === 'wrong-workspace') current.workspaceId = randomUUID();
    if (defect === 'nonterminal') current.state = 'uncertain'; if (defect === 'lost-submission') current.submissionCompleted = false; if (defect === 'lost-execution') current.executionCompleted = false;
    await expect(f.helper.prepareLegacySubmissionAuditProof(f.h, f.actors, f.checkpoint, f.verifyView)).rejects.toThrow('actual original-key receipt');
    expect(f.h.request).toHaveBeenCalledOnce(); expect(f.h.state.legacyWorkflowSubmissionAuditProof.state).toBe('building');
  });
  it.each(['actor', 'WID', 'hash', 'requestID', 'sourceIP', 'patch', 'duplicate', 'detail'])('rejects missing or altered actual immutable submission evidence: %s', async defect => {
    const f = await fixture(), view = f.views.get(f.h.state.requests[5].responseData.workflowId);
    if (defect === 'actor') view.actorId = randomUUID(); if (defect === 'WID') view.workspaceId = randomUUID();
    if (defect === 'hash') view.after.planHash = '0'.repeat(64); if (defect === 'requestID') view.requestId = randomUUID(); if (defect === 'sourceIP') view.sourceIp = '127.0.0.1';
    if (defect === 'patch') view.jsonPatch = [];
    const original = f.h.request;
    if (defect === 'duplicate' || defect === 'detail') f.h.request = vi.fn(async (...args: any[]) => { const result = await original(...args); if (defect === 'duplicate' && new URL('https://synthetic.invalid' + args[1]).pathname.endsWith('/audit')) result.payload.data.items.push(structuredClone(view)); if (defect === 'detail' && args[1].includes(`/audit/${view.id}`)) result.payload.data.after.approvalRequired = false; return result; });
    await expect(f.helper.prepareLegacySubmissionAuditProof(f.h, f.actors, f.checkpoint, f.verifyView)).rejects.toThrow(); expect(f.h.state.legacyWorkflowSubmissionAuditProof.state).toBe('building');
  });
  it.each(['receipt', 'audit', 'packet', 'state'])('refuses corrupted previously established %s proof after cleanup without reviving the original actor', async defect => {
    const f = await fixture(); await f.helper.prepareLegacySubmissionAuditProof(f.h, f.actors, f.checkpoint, f.verifyView);
    const proof = f.h.state.legacyWorkflowSubmissionAuditProof, record = proof.records[0]; f.actor.revoked = true; f.h.state.cleanupStarted = true; f.h.request.mockClear();
    if (defect === 'receipt') record.receiptRead.sessionId = randomUUID(); if (defect === 'audit') record.auditId = 'missing'; if (defect === 'packet') record.packetSha256 = '0'.repeat(64); if (defect === 'state') proof.state = 'building';
    await expect(f.helper.prepareLegacySubmissionAuditProof(f.h, f.actors, undefined, f.verifyView)).rejects.toThrow(); expect(f.h.request).not.toHaveBeenCalled();
  });
});
