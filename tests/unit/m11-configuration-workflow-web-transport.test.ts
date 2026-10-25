import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, getApiActorId, setApiActorId } from '../../apps/console-web/src/api/client';
import { clearConfigurationWorkflowAttempt, configurationWorkflowAttempt, configurationWorkflowConfirmation, readConfigurationWorkflowAttempt, storeConfigurationWorkflowAttempt } from '../../apps/console-web/src/features/configuration-workflow.model';
import { fetchConfigurationWorkflowPlan, freshConfigurationWorkflowSession, postConfigurationWorkflowOnce, readConfigurationWorkflowRegistration } from '../../apps/console-web/src/features/configuration-workflow.transport';
import { id, identity, publishedPlan, receipt, requestKey, sourcePlan } from './helpers/configuration-workflow-web.fixture';

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const csrf = 'controlled-session-csrf';
function original() { const value = configurationWorkflowAttempt(identity, sourcePlan(), requestKey); storeConfigurationWorkflowAttempt(value); return value; }
beforeEach(() => {
  const values = new Map<string, string>(); vi.stubGlobal('sessionStorage', { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) });
  vi.stubGlobal('window', { dispatchEvent: vi.fn() });
  vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options?: { detail?: unknown }) { super(type); this.detail = options?.detail; } });
  setApiActorId(identity.actor);
});
afterEach(() => { setApiActorId(undefined); vi.unstubAllGlobals(); });
describe('configuration workflow uses its real isolated one-shot BFF transport', () => {
  it('sends only the real route/body/original key and marks that send opportunity spent before fetch', async () => {
    const attempt = original(), body = configurationWorkflowConfirmation(sourcePlan(), identity, sourcePlan().name);
    const fetcher = vi.fn(async () => { expect(readConfigurationWorkflowAttempt(identity)?.state).toBe('unknown'); return json({ data: receipt() }, 201); }); vi.stubGlobal('fetch', fetcher);
    await postConfigurationWorkflowOnce(attempt, body, csrf);
    expect(fetcher).toHaveBeenCalledTimes(1); const [path, init] = fetcher.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe(`/api/v1/clusters/${identity.cid}/configuration/plans/${id(4)}/durable-submissions?workspaceId=${identity.wid}`);
    expect(init.method).toBe('POST'); expect(init.credentials).toBe('include'); expect(init.body).toBe(JSON.stringify(body));
    const headers = new Headers(init.headers); expect(headers.get('X-Idempotency-Key')).toBe(requestKey); expect(headers.get('X-CSRF-Token')).toBe(csrf);
    await expect(postConfigurationWorkflowOnce(attempt, body, csrf)).rejects.toThrow(); expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it.each([401, 403, 409, 500])('never retries an HTTP %s or clears the original journal from its status alone', async status => {
    const attempt = original(), fetcher = vi.fn().mockResolvedValue(json({ error: { code: status === 409 ? 'CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED' : 'FIXTURE_REQUEST_REJECTED' } }, status)); vi.stubGlobal('fetch', fetcher);
    await expect(postConfigurationWorkflowOnce(attempt, configurationWorkflowConfirmation(sourcePlan(), identity, sourcePlan().name), csrf)).rejects.toBeTruthy();
    expect(fetcher).toHaveBeenCalledTimes(1); expect(fetcher.mock.calls[0][0]).not.toContain('/auth/refresh'); expect(readConfigurationWorkflowAttempt(identity)).toEqual({ ...attempt, state: 'unknown' });
  });
  it.each(['network', 'invalid-json'])('retains only original-key verification after %s', async mode => {
    const attempt = original(), fetcher = mode === 'network' ? vi.fn().mockRejectedValue(Error('disconnected')) : vi.fn().mockResolvedValue(new Response('not-json', { status: 201 })); vi.stubGlobal('fetch', fetcher);
    await expect(postConfigurationWorkflowOnce(attempt, configurationWorkflowConfirmation(sourcePlan(), identity, sourcePlan().name), csrf)).rejects.toBeTruthy(); expect(fetcher).toHaveBeenCalledTimes(1);
    expect(readConfigurationWorkflowAttempt(identity)?.key).toBe(requestKey); expect(readConfigurationWorkflowAttempt(identity)?.state).toBe('unknown');
    expect((window.dispatchEvent as any).mock.calls.some((call: any[]) => call[0].type === 'kongos:mutation-uncertain')).toBe(false);
  });
  it('refuses a parallel second call before the first fetch settles', async () => {
    const attempt = original(), body = configurationWorkflowConfirmation(sourcePlan(), identity, sourcePlan().name); let finish!: (value: Response) => void;
    const fetcher = vi.fn(() => new Promise<Response>(resolve => { finish = resolve; })); vi.stubGlobal('fetch', fetcher);
    const first = postConfigurationWorkflowOnce(attempt, body, csrf); await expect(postConfigurationWorkflowOnce(attempt, body, csrf)).rejects.toThrow();
    expect(fetcher).toHaveBeenCalledTimes(1); finish(json({ data: receipt() }, 201)); await first;
  });
  it('a late response never recreates an original journal already verified and replaced by an independent request', async () => {
    const attempt = original(), body = configurationWorkflowConfirmation(sourcePlan(), identity, sourcePlan().name); let finish!: (value: Response) => void;
    const fetcher = vi.fn((path: string, init: RequestInit) => {
      if (init.method === 'POST') return new Promise<Response>(resolve => { finish = resolve; });
      if (path.includes('/jobs/by-key/')) return Promise.resolve(json({ data: receipt() }));
      if (path.includes(`/configuration/plans/${id(7)}`)) return Promise.resolve(json({ data: { entity: publishedPlan(), capabilities: publishedPlan().capabilities } }));
      throw Error('Unexpected fixture request');
    }); vi.stubGlobal('fetch', fetcher);
    const oldSending = postConfigurationWorkflowOnce(attempt, body, csrf);
    await readConfigurationWorkflowRegistration(attempt, () => {}); clearConfigurationWorkflowAttempt(attempt);
    const newSource = { ...sourcePlan(), id: id(11), jobId: id(12), name: `配置计划 ${id(11)}`, planHash: 'c'.repeat(64) };
    const next = configurationWorkflowAttempt(identity, newSource, id(13)); storeConfigurationWorkflowAttempt(next);
    finish(json({ error: { code: 'ORIGINAL_ACK_LOST' } }, 500)); await expect(oldSending).rejects.toBeTruthy();
    expect(readConfigurationWorkflowAttempt(identity)).toEqual(next);
    expect((window.dispatchEvent as any).mock.calls.some((call: any[]) => call[0].type === 'kongos:mutation-uncertain')).toBe(false);
  });
  it.each([{ planRevision: 2 }, { planHash: 'b'.repeat(64) }, { confirm_name: 'different-name' }, { confirmed: false }, { ttlHours: 168 }, { driver: 'deck' }, { confirm_deletes: false }])('rejects a changed or invented request field before fetch %j', async change => {
    const attempt = original(), fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    await expect(postConfigurationWorkflowOnce(attempt, { ...configurationWorkflowConfirmation(sourcePlan(), identity, sourcePlan().name), ...change }, csrf)).rejects.toThrow(); expect(fetcher).not.toHaveBeenCalled();
  });
  it('loads the actual original by-key receipt then the independent new Diff, without a POST or approval command', async () => {
    const attempt = original(); storeConfigurationWorkflowAttempt({ ...attempt, state: 'unknown' });
    const fetcher = vi.fn().mockResolvedValueOnce(json({ data: receipt() })).mockResolvedValueOnce(json({ data: { entity: publishedPlan(), capabilities: publishedPlan().capabilities } })); vi.stubGlobal('fetch', fetcher);
    const assertCurrent = vi.fn(), result = await readConfigurationWorkflowRegistration(attempt, assertCurrent);
    expect(fetcher.mock.calls.map(call => call[0])).toEqual([`/api/v1/clusters/${identity.cid}/configuration/jobs/by-key/${requestKey}?workspaceId=${identity.wid}`, `/api/v1/clusters/${identity.cid}/configuration/plans/${id(7)}?workspaceId=${identity.wid}`]);
    expect(fetcher.mock.calls.every(call => call[1].method === 'GET')).toBe(true); expect(result.proof.registrationOnly).toBe(true); expect(result.plan.id).toBe(id(7)); expect(assertCurrent).toHaveBeenCalledTimes(3);
    expect(readConfigurationWorkflowAttempt(identity)?.state).toBe('unknown');
  });
  it('a missing by-key receipt does not create another key or fall back to a made-up native receipt', async () => {
    const attempt = original(); storeConfigurationWorkflowAttempt({ ...attempt, state: 'unknown' }); const fetcher = vi.fn().mockResolvedValue(json({ error: { code: 'CONFIGURATION_RECEIPT_NOT_FOUND' } }, 404)); vi.stubGlobal('fetch', fetcher);
    await expect(readConfigurationWorkflowRegistration(attempt, () => {})).rejects.toMatchObject({ status: 404 }); expect(fetcher).toHaveBeenCalledTimes(1); expect(readConfigurationWorkflowAttempt(identity)?.key).toBe(requestKey);
  });
  it('checks the current authenticated actor and session permissions without silently refreshing', async () => {
    const fetcher = vi.fn().mockResolvedValue(json({ data: { user: { id: identity.actor, permissionsVersion: identity.version, forcePasswordChange: false }, csrfToken: csrf } })); vi.stubGlobal('fetch', fetcher);
    expect((await freshConfigurationWorkflowSession(identity)).csrfToken).toBe(csrf); expect(fetcher).toHaveBeenCalledTimes(1);
    fetcher.mockResolvedValueOnce(json({ data: { user: { id: identity.actor, permissionsVersion: 'changed', forcePasswordChange: false }, csrfToken: csrf } })); await expect(freshConfigurationWorkflowSession(identity)).rejects.toMatchObject({ code: 'CONFIGURATION_WORKFLOW_SCOPE_CHANGED' });
    setApiActorId(id(99)); await expect(freshConfigurationWorkflowSession(identity)).rejects.toMatchObject({ code: 'CONFIGURATION_WORKFLOW_SCOPE_CHANGED' }); expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('does not show a late receipt or fetch its new plan after the actor changes', async () => {
    const attempt = original(), fetcher = vi.fn(async () => { setApiActorId(id(99)); return json({ data: receipt() }); }); vi.stubGlobal('fetch', fetcher);
    await expect(readConfigurationWorkflowRegistration(attempt, () => {})).rejects.toMatchObject({ code: 'CONFIGURATION_WORKFLOW_SCOPE_CHANGED' }); expect(fetcher).toHaveBeenCalledTimes(1); expect(getApiActorId()).toBe(id(99));
  });
  it('stops after a permission/scope check changes between the receipt and new Diff', async () => {
    const attempt = original(), fetcher = vi.fn().mockResolvedValue(json({ data: receipt() })); vi.stubGlobal('fetch', fetcher); let checks = 0;
    await expect(readConfigurationWorkflowRegistration(attempt, () => { if (++checks === 2) throw Error('current scope changed'); })).rejects.toThrow('current scope changed'); expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('rejects a foreign plan response and refuses an external or malformed plan selector', async () => {
    const fetcher = vi.fn().mockResolvedValue(json({ data: { entity: { ...publishedPlan(), workspaceId: id(99) } } })); vi.stubGlobal('fetch', fetcher);
    await expect(fetchConfigurationWorkflowPlan(identity, id(7))).rejects.toThrow('原范围'); await expect(fetchConfigurationWorkflowPlan(identity, 'https://kong:8001/services')).rejects.toThrow(); expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('preserves the generic global fence for existing native configuration apply requests', async () => {
    const fetcher = vi.fn().mockResolvedValue(json({ error: { code: 'ORIGINAL_NATIVE_RESPONSE_LOST' } }, 500)); vi.stubGlobal('fetch', fetcher);
    await expect(api(`/clusters/${identity.cid}/configuration/plans/${id(4)}/apply?workspaceId=${identity.wid}`, { method: 'POST', body: '{}', headers: { 'X-Idempotency-Key': requestKey, 'X-CSRF-Token': csrf } }, true)).rejects.toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind: 'configuration', idempotencyKey: requestKey } });
    expect((window.dispatchEvent as any).mock.calls.some((call: any[]) => call[0].type === 'kongos:mutation-uncertain')).toBe(true);
  });
});
