import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setApiActorId } from '../../apps/console-web/src/api/client';
import { configurationWorkflowAttempt, configurationWorkflowConfirmation, configurationWorkflowRejection, configurationWorkflowSourceWasRejected,
  readConfigurationWorkflowAttempt, readConfigurationWorkflowRejectedSource, settleConfigurationWorkflowRejection, storeConfigurationWorkflowAttempt } from '../../apps/console-web/src/features/configuration-workflow.model';
import { postConfigurationWorkflowOnce, readConfigurationWorkflowDisposition } from '../../apps/console-web/src/features/configuration-workflow.transport';
import { id, identity, publishedPlan, receipt, rejectedReceipt, requestKey, sourcePlan } from './helpers/configuration-workflow-web.fixture';

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const csrf = 'controlled-session-csrf';
let values: Map<string, string>;
function original() { const attempt = configurationWorkflowAttempt(identity, sourcePlan(), requestKey); storeConfigurationWorkflowAttempt({ ...attempt, state: 'unknown' }); return attempt; }
beforeEach(() => {
  values = new Map(); vi.stubGlobal('sessionStorage', { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) });
  vi.stubGlobal('window', { dispatchEvent: vi.fn() });
  vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options?: { detail?: unknown }) { super(type); this.detail = options?.detail; } });
  setApiActorId(identity.actor);
});
afterEach(() => { setApiActorId(undefined); vi.unstubAllGlobals(); });

describe('strict original-key durable-registration refusal', () => {
  it('uses the exact original-key GET and archives its real tuple before clearing only that active request', async () => {
    const attempt = original(), fetcher = vi.fn().mockResolvedValue(json({ data: rejectedReceipt() })); vi.stubGlobal('fetch', fetcher);
    const result = await readConfigurationWorkflowDisposition(attempt, () => {});
    expect(result.kind).toBe('rejected'); if (result.kind !== 'rejected') throw Error('wrong disposition');
    expect(readConfigurationWorkflowAttempt(identity)?.state).toBe('unknown');
    const settled = settleConfigurationWorkflowRejection(attempt, result.rejection);
    expect(settled).toMatchObject({ version: 1, state: 'settled-rejected', original: { ...attempt, state: 'unknown' }, receipt: rejectedReceipt() });
    expect(readConfigurationWorkflowAttempt(identity)).toBeUndefined(); expect(readConfigurationWorkflowRejectedSource(identity, sourcePlan())).toEqual(settled);
    expect(fetcher).toHaveBeenCalledTimes(1); expect(fetcher.mock.calls[0][0]).toBe(`/api/v1/clusters/${identity.cid}/configuration/jobs/by-key/${requestKey}?workspaceId=${identity.wid}`);
    expect(fetcher.mock.calls[0][1].method).toBe('GET'); expect([...values.values()][0]).toContain(requestKey);
    expect((window.dispatchEvent as any).mock.calls.some((call: any[]) => call[0].type === 'kongos:mutation-uncertain')).toBe(false);
  });
  it.each(Object.keys(rejectedReceipt()))('a missing %s cannot settle or archive the original request', field => {
    const attempt = original(), raw = rejectedReceipt(); delete raw[field];
    expect(() => configurationWorkflowRejection(raw, attempt)).toThrow(); expect(() => settleConfigurationWorkflowRejection(attempt, raw)).toThrow();
    expect(readConfigurationWorkflowAttempt(identity)?.key).toBe(requestKey); expect([...values.keys()].some(key => key.includes('Rejected:'))).toBe(false);
  });
  it.each([
    ['domain', 'workflow'], ['authorityDomain', 'legacy-http-v1'], ['receiptKind', 'durable-submission-failed-v1'], ['result', 'failed'], ['commandCompleted', false],
    ['registrationCompleted', true], ['registrationRejected', false], ['submissionCompleted', true], ['knownNoEffect', false], ['effectScope', 'all-console-metadata'],
    ['nativeWrites', 'unknown'], ['newPreviewRequired', false], ['idempotencyKey', id(99)], ['actorId', id(99)], ['clusterId', id(99)], ['workspaceId', id(99)],
    ['sourceJobId', id(99)], ['sourcePlanId', id(99)], ['sourcePlanRevision', 2], ['sourcePlanRevision', '1'], ['sourcePlanHash', 'b'.repeat(64)],
    ['rejectionId', 'not-an-id'], ['rejectedAt', '2026-10-15T12:00:00Z'], ['code', 'SOME_GENERIC_CONFLICT'],
  ])('rejects changed receipt field %s=%j without releasing the journal', async (field, value) => {
    const attempt = original(), fetcher = vi.fn().mockResolvedValue(json({ data: { ...rejectedReceipt(), [field]: value } })); vi.stubGlobal('fetch', fetcher);
    await expect(readConfigurationWorkflowDisposition(attempt, () => {})).rejects.toThrow(); expect(readConfigurationWorkflowAttempt(identity)?.state).toBe('unknown');
    expect(fetcher).toHaveBeenCalledTimes(1); expect([...values.keys()].some(key => key.includes('Rejected:'))).toBe(false);
  });
  it('never renders or stores undeclared receipt data including private fields', async () => {
    const attempt = original(), fetcher = vi.fn().mockResolvedValue(json({ data: { ...rejectedReceipt(), privateMaterial: 'must-never-store' } })); vi.stubGlobal('fetch', fetcher);
    await expect(readConfigurationWorkflowDisposition(attempt, () => {})).rejects.toThrow(); expect(JSON.stringify([...values.values()])).not.toContain('must-never-store');
  });
  it.each([404, 409, 500])('generic GET HTTP%s never proves a refusal or replaces the original key', async status => {
    const attempt = original(), fetcher = vi.fn().mockResolvedValue(json({ error: { code: 'CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED', receipt: rejectedReceipt() } }, status)); vi.stubGlobal('fetch', fetcher);
    await expect(readConfigurationWorkflowDisposition(attempt, () => {})).rejects.toMatchObject({ status }); expect(readConfigurationWorkflowAttempt(identity)).toEqual({ ...attempt, state: 'unknown' });
    expect(fetcher).toHaveBeenCalledTimes(1); expect([...values.keys()].some(key => key.includes('Rejected:'))).toBe(false);
  });
  it('a public code-only POST409 keeps its journal until an independently typed original-key GET is read', async () => {
    const attempt = configurationWorkflowAttempt(identity, sourcePlan(), requestKey); storeConfigurationWorkflowAttempt(attempt);
    const fetcher = vi.fn().mockResolvedValueOnce(json({ error: { code: 'CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED', message: '配置已变化' } }, 409))
      .mockResolvedValueOnce(json({ error: { code: 'CONFIGURATION_RECEIPT_NOT_FOUND' } }, 404)); vi.stubGlobal('fetch', fetcher);
    await expect(postConfigurationWorkflowOnce(attempt, configurationWorkflowConfirmation(sourcePlan(), identity, sourcePlan().name), csrf)).rejects.toMatchObject({ status: 409 });
    expect(readConfigurationWorkflowAttempt(identity)?.state).toBe('unknown');
    await expect(readConfigurationWorkflowDisposition(attempt, () => {})).rejects.toMatchObject({ status: 404 });
    expect(fetcher.mock.calls.map(call => call[1].method)).toEqual(['POST', 'GET']); expect(readConfigurationWorkflowAttempt(identity)?.key).toBe(requestKey);
    expect([...values.keys()].some(key => key.includes('Rejected:'))).toBe(false);
  });
  it.each(['network', 'malformed-json', 'empty-json'])('retains the original request through a %s GET', async mode => {
    const attempt = original(), fetcher = mode === 'network' ? vi.fn().mockRejectedValue(Error('lost response'))
      : vi.fn().mockResolvedValue(mode === 'malformed-json' ? new Response('invalid', { status: 200 }) : json({ data: null })); vi.stubGlobal('fetch', fetcher);
    await expect(readConfigurationWorkflowDisposition(attempt, () => {})).rejects.toThrow(); expect(readConfigurationWorkflowAttempt(identity)?.key).toBe(requestKey);
  });
  it('still loads a genuine registered publication and actual new Diff without treating execution failure as rejection', async () => {
    const attempt = original(), fetcher = vi.fn().mockResolvedValueOnce(json({ data: receipt('failed') }))
      .mockResolvedValueOnce(json({ data: { entity: publishedPlan(), capabilities: publishedPlan().capabilities } })); vi.stubGlobal('fetch', fetcher);
    const result = await readConfigurationWorkflowDisposition(attempt, () => {}); expect(result.kind).toBe('registered');
    if (result.kind !== 'registered') throw Error('wrong disposition'); expect(result.proof.state).toBe('failed'); expect(result.proof.registrationOnly).toBe(true);
    expect(readConfigurationWorkflowAttempt(identity)?.state).toBe('unknown'); expect(fetcher.mock.calls.every(call => call[1].method === 'GET')).toBe(true);
  });
});

describe('refusal settlement is fenced against late or unrelated transactions', () => {
  it('a late old-key GET cannot clear a later journal or preserve an unverified archive', async () => {
    const attempt = original(); let finish!: (response: Response) => void;
    const fetcher = vi.fn(() => new Promise<Response>(resolve => { finish = resolve; })); vi.stubGlobal('fetch', fetcher);
    const reading = readConfigurationWorkflowDisposition(attempt, () => {});
    const journalKey = [...values.keys()][0]; values.delete(journalKey);
    const fresh = { ...sourcePlan(), id: id(11), jobId: id(12), name: `配置计划 ${id(11)}`, planHash: 'c'.repeat(64) }, next = configurationWorkflowAttempt(identity, fresh, id(13));
    storeConfigurationWorkflowAttempt(next); finish(json({ data: rejectedReceipt() })); const result = await reading;
    if (result.kind !== 'rejected') throw Error('wrong disposition'); expect(() => settleConfigurationWorkflowRejection(attempt, result.rejection)).toThrow();
    expect(readConfigurationWorkflowAttempt(identity)).toEqual(next); expect(configurationWorkflowSourceWasRejected(identity, sourcePlan().id)).toBe(false);
  });
  it('a changed actor or scope after GET prevents disposition consumption', async () => {
    const attempt = original(), fetcher = vi.fn(async () => { setApiActorId(id(99)); return json({ data: rejectedReceipt() }); }); vi.stubGlobal('fetch', fetcher);
    await expect(readConfigurationWorkflowDisposition(attempt, () => {})).rejects.toMatchObject({ code: 'CONFIGURATION_WORKFLOW_SCOPE_CHANGED' });
    expect(readConfigurationWorkflowAttempt(identity)?.state).toBe('unknown');
  });
  it('a current scope/PV guard failure after GET retains both the original transaction and its key', async () => {
    const attempt = original(); let checks = 0; vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ data: rejectedReceipt() })));
    await expect(readConfigurationWorkflowDisposition(attempt, () => { if (++checks === 2) throw Error('scope or permission changed'); })).rejects.toThrow('scope or permission changed');
    expect(readConfigurationWorkflowAttempt(identity)?.key).toBe(requestKey);
  });
  it('a refusal cannot clear another workspace journal', () => {
    const attempt = original(), otherIdentity = { ...identity, wid: id(30) }, otherPlan = { ...sourcePlan(), workspaceId: otherIdentity.wid };
    const other = configurationWorkflowAttempt(otherIdentity, otherPlan, id(31)); storeConfigurationWorkflowAttempt(other);
    settleConfigurationWorkflowRejection(attempt, rejectedReceipt()); expect(readConfigurationWorkflowAttempt(otherIdentity)).toEqual(other);
  });
  it('archive persistence failure never removes the active original journal', () => {
    const attempt = original(), storage = sessionStorage; vi.stubGlobal('sessionStorage', { ...storage, setItem(key: string, value: string) {
      if (key.includes('Rejected:')) throw Error('storage is full'); values.set(key, value);
    } });
    expect(() => settleConfigurationWorkflowRejection(attempt, rejectedReceipt())).toThrow('storage is full'); expect(readConfigurationWorkflowAttempt(identity)?.key).toBe(requestKey);
  });
  it('a source remains rejected after reload/PV change and cannot be continued under a replacement key', async () => {
    const attempt = original(); settleConfigurationWorkflowRejection(attempt, rejectedReceipt());
    expect(readConfigurationWorkflowRejectedSource({ ...identity, version: 'new-current-PV' }, sourcePlan())?.original.key).toBe(requestKey);
    const replacement = configurationWorkflowAttempt(identity, sourcePlan(), id(91)); storeConfigurationWorkflowAttempt(replacement); const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    await expect(postConfigurationWorkflowOnce(replacement, configurationWorkflowConfirmation(sourcePlan(), identity, sourcePlan().name), csrf)).rejects.toThrow('重新预览');
    expect(fetcher).not.toHaveBeenCalled(); expect(readConfigurationWorkflowAttempt(identity)).toEqual(replacement);
  });
  it('a separately authored new preview remains an independent explicit intent and does not erase the old key', () => {
    const attempt = original(); settleConfigurationWorkflowRejection(attempt, rejectedReceipt());
    const fresh = { ...sourcePlan(), id: id(11), jobId: id(12), name: `配置计划 ${id(11)}`, planHash: 'c'.repeat(64) };
    expect(readConfigurationWorkflowRejectedSource(identity, fresh)).toBeUndefined(); const next = configurationWorkflowAttempt(identity, fresh, id(13)); storeConfigurationWorkflowAttempt(next);
    expect(readConfigurationWorkflowAttempt(identity)).toEqual(next); expect(readConfigurationWorkflowRejectedSource(identity, sourcePlan())?.original.key).toBe(requestKey);
  });
  it('a conflicting archive or unsent journal cannot be silently converted into settlement', () => {
    const attempt = original(), archiveKey = `kongpilot.configurationWorkflowRejected:${identity.actor}:${identity.cid}:${identity.wid}:${attempt.sourcePlanId}`;
    values.set(archiveKey, JSON.stringify({ unrelated: true })); expect(() => settleConfigurationWorkflowRejection(attempt, rejectedReceipt())).toThrow();
    expect(readConfigurationWorkflowAttempt(identity)?.state).toBe('unknown'); values.delete(archiveKey);
    const activeKey = [...values.keys()][0]; values.set(activeKey, JSON.stringify(attempt)); expect(() => settleConfigurationWorkflowRejection(attempt, rejectedReceipt())).toThrow();
    expect(readConfigurationWorkflowAttempt(identity)?.state).toBe('pending');
  });
});
