import * as React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
vi.mock('antd', () => ({ Input: 'test-input', Alert: 'test-alert' }));
vi.mock('@ant-design/icons', () => ({ ExclamationCircleOutlined: 'test-icon' }));
import { api, ApiError, authWriteNeedsVerification, setApiActorId } from '../../apps/console-web/src/api/client';
import { closeMutationConfirmDialogs, mutationConfirm } from '../../apps/console-web/src/components/MutationConfirm';

const actorA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', actorB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const cid = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', wid = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', key = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
let events: ReturnType<typeof vi.fn>;
beforeEach(() => { events = vi.fn(); vi.stubGlobal('React', React); vi.stubGlobal('window', { dispatchEvent: events }); vi.stubGlobal('crypto', { randomUUID: () => key }); setApiActorId(actorA); });
afterEach(() => { closeMutationConfirmDialogs(); setApiActorId(undefined); vi.unstubAllGlobals(); });
async function flush() { for (let i = 0; i < 8; i++) await Promise.resolve(); }
function findInput(element: any): any { if (element?.props?.onChange) return element; for (const child of React.Children.toArray(element?.props?.children)) { const input = findInput(child); if (input) return input; } }
function confirmation(onConfirm: () => Promise<void>) {
  let config: any;
  const destroy = vi.fn(), update = vi.fn(), modal = { confirm: vi.fn(value => { config = value; return { destroy, update }; }) };
  mutationConfirm(modal, { title: '保存角色', expected: 'pay-admin', description: '审阅完整授权行', onConfirm });
  findInput(config.content).props.onChange({ target: { value: 'pay-admin' } });
  return { config, destroy, close: vi.fn() };
}
describe('M4 confirmation and durable metadata recovery', () => {
  it('does not execute a retained confirmation after the account switches', async () => {
    const write = vi.fn().mockResolvedValue(undefined), fixture = confirmation(write);
    setApiActorId(actorB); fixture.config.onOk(fixture.close); await flush();
    expect(write).not.toHaveBeenCalled(); expect(fixture.close).toHaveBeenCalledOnce();
  });
  it('checks the account again before the asynchronous write starts', async () => {
    const write = vi.fn().mockResolvedValue(undefined), fixture = confirmation(write);
    fixture.config.onOk(fixture.close); setApiActorId(actorB); await flush();
    expect(write).not.toHaveBeenCalled();
  });
  it('closes outstanding confirmations on logout or permission epoch changes', () => {
    const fixture = confirmation(vi.fn()); closeMutationConfirmDialogs(); closeMutationConfirmDialogs();
    expect(fixture.destroy).toHaveBeenCalledOnce();
  });
  it.each([
    ['POST', '/clusters'], ['PATCH', `/clusters/${cid}`], ['DELETE', `/clusters/${cid}`],
    ['POST', `/clusters/${cid}/probe`], ['POST', `/clusters/${cid}/test`], ['POST', `/clusters/${cid}/deactivate`],
    ['POST', `/clusters/${cid}/data-sources`], ['PATCH', `/clusters/${cid}/data-sources/${wid}`],
    ['DELETE', `/clusters/${cid}/data-sources/${wid}`], ['POST', `/clusters/${cid}/data-sources/${wid}/test`],
    ['POST', `/clusters/${cid}/data-sources/${wid}/probe`], ['POST', `/clusters/${cid}/data-sources/${wid}/deactivate`],
  ])('keeps %s %s in IAM domain without invented Gateway scope', async (method, path) => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('response lost')));
    const error = await api(path, { method, body: '{}' }).catch(error => error);
    expect(error).toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { domain: 'iam', idempotencyKey: key, state: 'uncertain' } });
    expect(error.recovery.clusterId).toBeUndefined(); expect(error.recovery.workspaceId).toBeUndefined();
    expect(events).toHaveBeenCalledOnce();
  });
  it('keeps object-level native writes in their original cluster/workspace domain', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('response lost')));
    const error = await api(`/clusters/${cid}/entities/services?workspaceId=${wid}`, { method: 'PATCH', body: '{}' }).catch(error => error);
    expect(error.recovery).toMatchObject({ clusterId: cid, workspaceId: wid, idempotencyKey: key }); expect(error.recovery.domain).toBeUndefined();
  });
  it('does not invent a receipt for read-only object capability projection', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('response lost')));
    const error = await api(`/clusters/${cid}/authorization/entity-capabilities?workspaceId=${wid}`, { method: 'POST', body: '{}' }).catch(error => error);
    expect(error.code).toBe('NETWORK_REVIEW_INTERRUPTED'); expect(error.recovery).toBeUndefined(); expect(events).not.toHaveBeenCalled();
  });
  it('requires manual auth verification for an unreadable successful write without inventing a durable receipt', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('response interrupted', { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    const error = await api('/auth/me/profile', { method: 'PATCH', body: JSON.stringify({ display_name: 'User', revision: 1 }) }).catch(error => error);
    expect(error).toMatchObject({ code: 'INVALID_RESPONSE' }); expect(error.recovery).toBeUndefined();
    expect(authWriteNeedsVerification(error)).toBe(true); expect(fetch).toHaveBeenCalledOnce(); expect(events).not.toHaveBeenCalled();
    expect(authWriteNeedsVerification(new ApiError('validation', 400, 'INVALID_PROFILE'))).toBe(false);
    expect(authWriteNeedsVerification(new ApiError('commit unavailable', 503))).toBe(true);
  });
});
