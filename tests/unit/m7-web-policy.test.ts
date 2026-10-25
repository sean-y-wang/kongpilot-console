import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { currentCursor, m7QueryIdentity, nextCursorPage, sameM7Identity } from '../../apps/console-web/src/features/m7.cursor';
import { m7ReceiptPath, m7ReceiptResult, assertM7Entity } from '../../apps/console-web/src/features/m7.results';
import { channelPayload, logicalTags, notificationBatch, eventFilters, personalPreferencePayload } from '../../apps/console-web/src/features/m7.forms';
import { jsonPointerParts, redactAuditPatch } from '../../apps/console-web/src/features/m7.redaction';
import { safeRecoveryReferences } from '../../apps/console-web/src/api/workspace-scope';

const cid = '5b316db5-b0b7-4b91-8197-f893ecb76540', wid = 'ac18ace3-6ecd-473e-a09b-46be792203d7', actor = 'b3b86cf9-aeab-4a8b-97f8-34c06c0c9f40', other = '8d0fcfe8-f993-4d97-829f-e3e9b4cfb113', key = 'fc843d08-7627-46f5-8cd0-93fc49f1af22', id = 'bc7bd065-9372-405d-9782-015d31a30aa1';
const identity = { actor, version: 'actor:7', cid, wid, mode: 'workspace' as const }, ref = { kind: 'events' as const, clusterId: cid, workspaceId: wid, scope: 'workspace' as const, idempotencyKey: key };
const channel = { id, revision: 7, type: 'webhook', name: 'original', maskedDestination: 'https://host/••••', status: 'active' } as any;
const notification = { id, clusterId: cid, workspaceId: wid, revision: 2, capabilities: { read: true, write: true } } as any;
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('M7 source policy uses actual scoped DTOs and bounded cursors', () => {
  it('resets prior/next cache on actor, permission, scope, mode and filter changes', () => {
    const query = m7QueryIdentity(identity, 'records', { from: 'a', eventType: 'b' }), second = nextCursorPage({ key: query, page: 0, cursors: [undefined] }, 'opaque-1'), third = nextCursorPage(second, 'opaque-2');
    expect(third.cursors).toEqual([undefined, 'opaque-1', 'opaque-2']); expect(nextCursorPage({ ...third, page: 0 }, 'reloaded').cursors).toEqual([undefined, 'reloaded']);
    for (const changed of [{ actor: other }, { version: 'actor:8' }, { cid: other }, { wid: other }, { mode: 'cluster' as const }]) expect(currentCursor(third, m7QueryIdentity({ ...identity, ...changed }, 'records', { from: 'a', eventType: 'b' }))).toMatchObject({ page: 0, cursors: [undefined] });
    expect(currentCursor(third, m7QueryIdentity(identity, 'records', { from: 'new' })).page).toBe(0); expect(m7QueryIdentity(identity, 'records', { eventType: 'b', from: 'a' })).toBe(query); expect(() => nextCursorPage(second, 'x'.repeat(24577))).toThrow(); expect(sameM7Identity(identity, { ...identity, version: 'new' })).toBe(false);
  });
  it('uses fixed original-key namespace without replacing missing scope or permitting raw URLs', () => {
    expect(m7ReceiptPath(ref)).toBe(`/clusters/${cid}/events/operations/by-key/${key}?workspaceId=${wid}`);
    expect(m7ReceiptPath({ ...ref, kind: 'notifications' })).toBe(`/notifications/operations/by-key/${key}?clusterId=${cid}&workspaceId=${wid}`);
    expect(m7ReceiptPath({ kind: 'audit-global-export', scope: 'global', idempotencyKey: key })).toBe(`/audit/global/exports/by-key/${key}`);
    for (const invalid of [{ ...ref, workspaceId: undefined }, { ...ref, idempotencyKey: 'https://kong:8001' }, { ...ref, kind: 'vaults' }, { ...ref, kind: 'audit-global-export' }]) expect(() => m7ReceiptPath(invalid as any)).toThrow();
  });
  it('classifies shared actual flat workflow submission separately from execution and remote delivery', () => {
    const base = { idempotencyKey: key, clusterId: cid, workspaceId: wid, domain: 'workflow', workflowId: id, state: 'submitted', submissionCompleted: true, executionCompleted: false, configurationCommitted: false, queued: false, deliverySucceeded: false };
    expect(m7ReceiptResult(base, ref)).toMatchObject({ complete: true, success: true, workflowId: id }); expect(m7ReceiptResult(base, ref).label).toContain('等待审批');
    const queue = m7ReceiptResult({ ...base, domain: 'iam', state: 'succeeded', executionCompleted: true, configurationCommitted: true, queued: true }, ref); expect(queue.label).toContain('远端结果'); expect(queue.label).not.toContain('投递成功');
    for (const changed of [{ idempotencyKey: other }, { clusterId: other }, { workspaceId: other }, { submissionCompleted: false }]) expect(m7ReceiptResult({ ...base, ...changed }, ref).complete).toBe(false);
  });
  it('accepts protected personal IAM and audit export producer shapes without invented response fields', () => {
    const personal = { id, clusterId: cid, workspaceId: wid, remote_completed: true, state: 'succeeded', result: { entity: notification }, errorCode: null };
    expect(m7ReceiptResult(personal, { ...ref, kind: 'notifications' }).success).toBe(true); expect(m7ReceiptResult({ ...personal, workspaceId: other }, { ...ref, kind: 'notifications' }).complete).toBe(false);
    const receipt = { domain: 'audit-export', jobId: id, durable: true, job: { id, state: 'queued', complete: false, capabilities: { download: false } } };
    expect(m7ReceiptResult(receipt, { ...ref, kind: 'audit-export' })).toMatchObject({ complete: true, success: true }); expect(m7ReceiptResult(receipt, { ...ref, kind: 'audit-export' }).label).toContain('生成状态'); expect(m7ReceiptResult({ ...receipt, durable: false }, { ...ref, kind: 'audit-export' }).complete).toBe(false);
  });
  it('preserves old channel target when omitted and rejects masked or incomplete target replacements', () => {
    expect(channelPayload({ type: 'webhook', replaceTarget: false, endpoint: channel.maskedDestination, authType: 'none' }, channel)).toEqual({ revision: 7 });
    expect(channelPayload({ type: 'webhook', replaceTarget: true, endpoint: 'https://receiver.example/hook', authType: 'none' }, channel)).toEqual({ revision: 7, endpoint: 'https://receiver.example/hook', auth: { type: 'none' } });
    expect(() => channelPayload({ type: 'webhook', replaceTarget: true, endpoint: channel.maskedDestination, authType: 'none' }, channel)).toThrow(); expect(() => channelPayload({ type: 'webhook', replaceTarget: true, endpoint: 'https://example/hook', authType: 'bearer' }, channel)).toThrow();
    expect(channelPayload({ type: 'email', name: 'mail', recipients: 'a@example.test\na@example.test\nb@example.test', authType: 'none' }).endpoint).toEqual({ recipients: ['a@example.test', 'b@example.test'] });
  });
  it('builds revision batch from actual selected rows and rejects mixed scope, duplicate, stale and nonwritable rows', () => {
    expect(notificationBatch([notification, { ...notification, id: other }], 'read')).toEqual({ clusterId: cid, workspaceId: wid, items: [{ id, revision: 2 }, { id: other, revision: 2 }], confirmed: true });
    for (const row of [{ ...notification, id: other, clusterId: other }, { ...notification, id: other, workspaceId: other }, { ...notification, id: other, revision: 0 }, { ...notification, id: other, capabilities: { write: false } }, notification]) expect(() => notificationBatch([notification, row], 'dismiss')).toThrow();
    expect(() => notificationBatch([], 'read')).toThrow(); expect(() => logicalTags('workspace:billing')).toThrow(); expect(() => logicalTags('kos-ws-reserved')).toThrow(); expect(logicalTags('team:pay\nteam:pay')).toEqual(['team:pay']);
  });
  it('decodes JSON pointer escapes before redacting patch values and rejects malformed pointers', () => {
    expect(jsonPointerParts('/a~1b/~0c')).toEqual(['a/b', '~c']); const value = redactAuditPatch([{ op: 'replace', path: '/config/provision_key', value: 'never-render-this' }, { op: 'copy', from: '/authorization', path: '/copied', value: 'never-copy-this' }, { op: 'add', path: '/name', value: 'safe' }, { op: 'add', path: '/broken~9', value: 'no' }]);
    expect(JSON.stringify(value)).not.toContain('never-render-this'); expect(JSON.stringify(value)).not.toContain('never-copy-this'); expect(JSON.stringify(value)).toContain('safe'); expect(value).toContain('[INVALID PATCH]');
  });
  it('persists only initiating actor/scope/key and discards credentials, foreign actors and invalid scopes', () => {
    const row = { actor_id: actor, cid, wid, kind: 'events', idempotencyKey: key, created_at: new Date().toISOString(), state: 'uncertain', body: { token: 'never-store' }, endpoint: 'https://private' };
    const kept = safeRecoveryReferences([row, { ...row, actor_id: other }, { ...row, scope: 'invented' }, { ...row, wid: undefined }], actor); expect(kept).toHaveLength(1); expect(JSON.stringify(kept)).not.toContain('never-store'); expect(JSON.stringify(kept)).not.toContain('private');
  });
  it('validates exact original detail identity and typed filter UUIDs without accepting workspace tags', () => {
    expect(assertM7Entity(notification, notification)).toBe(notification); for (const foreign of [{ id: other }, { clusterId: other }, { workspaceId: other }]) expect(() => assertM7Entity({ ...notification, ...foreign }, notification)).toThrow();
    expect(eventFilters({ eventTypes: ['entity.updated'], nativeType: 'services', nativeIdsText: id, tagsText: 'team:pay' })).toEqual({ eventTypes: ['entity.updated'], nativeType: 'services', nativeIds: [id], tags: ['team:pay'] });
    for (const invalid of [{ eventTypes: [] }, { eventTypes: ['entity.updated'], nativeIdsText: id }, { eventTypes: ['entity.updated'], nativeType: 'vaults' }, { eventTypes: ['entity.updated'], nativeType: 'services', nativeIdsText: 'invalid' }, { eventTypes: ['entity.updated'], tagsText: 'workspace:private' }]) expect(() => eventFilters(invalid)).toThrow();
  });
  it('serializes personal no-filter create and edit clearing without nativeType null, while rejecting IDs without a type', () => {
    const values = { name: 'own-preference', eventTypes: ['channel.test'], inAppEnabled: true };
    const create = JSON.parse(JSON.stringify(personalPreferencePayload(values, { cid, wid })));
    expect(create).toEqual({ clusterId: cid, workspaceId: wid, name: values.name, eventTypes: values.eventTypes, nativeIds: [], tags: [], inAppEnabled: true });
    const cleared = JSON.parse(JSON.stringify(personalPreferencePayload({ ...values, nativeType: undefined, nativeIdsText: '', tagsText: '', inAppEnabled: false }, { cid, wid }, 8)));
    expect(cleared).not.toHaveProperty('nativeType'); expect(cleared).toMatchObject({ nativeIds: [], revision: 8, inAppEnabled: false });
    expect(() => personalPreferencePayload({ ...values, nativeIdsText: id }, { cid, wid })).toThrow();
    expect(personalPreferencePayload({ ...values, nativeType: 'services', nativeIdsText: id }, { cid, wid })).toMatchObject({ nativeType: 'services', nativeIds: [id] });
    expect(eventFilters(values).nativeType).toBeNull();
  });
});

describe('M7 authenticated binary and unknown-write client behavior with memory-only fetch', () => {
  let client: typeof import('../../apps/console-web/src/api/client'), events: ReturnType<typeof vi.fn>;
  const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
  beforeEach(async () => { vi.resetModules(); events = vi.fn(); vi.stubGlobal('window', { dispatchEvent: events }); vi.stubGlobal('crypto', { randomUUID: () => key }); vi.stubGlobal('CustomEvent', class extends Event { detail: unknown; constructor(type: string, options?: { detail?: unknown }) { super(type); this.detail = options?.detail; } }); client = await import('../../apps/console-web/src/api/client'); client.setApiActorId(actor); client.setCsrfToken('source-only-csrf'); });
  it('keeps exact new recovery kinds, original actor and scope on network loss without a second business request', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('closed')); vi.stubGlobal('fetch', fetch);
    for (const [path, kind, expected] of [[`/clusters/${cid}/events/channels?workspaceId=${wid}`, 'events', { clusterId: cid, workspaceId: wid }], [`/notifications/${id}/read?clusterId=${cid}&workspaceId=${wid}`, 'notifications', { clusterId: cid, workspaceId: wid, scope: 'workspace' }], [`/clusters/${cid}/audit/exports?scope=cluster`, 'audit-export', { clusterId: cid, scope: 'cluster' }], ['/audit/global/exports', 'audit-global-export', { scope: 'global' }]] as const) {
      const error = await client.api(path, { method: 'POST', body: '{}' }).catch(error => error); expect(error).toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { kind, idempotencyKey: key, ...expected } }); expect(events.mock.calls.at(-1)?.[0].detail.actorId).toBe(actor);
    }
    expect(fetch).toHaveBeenCalledTimes(4);
  });
  it('downloads binary through the same one-refresh authentication path and rejects arbitrary stream URLs', async () => {
    const path = `/clusters/${cid}/audit/exports/${id}/download?workspaceId=${wid}`, fetch = vi.fn().mockResolvedValueOnce(json({ error: { code: 'SESSION_EXPIRED' } }, 401)).mockResolvedValueOnce(json({ data: {} })).mockResolvedValueOnce(new Response('safe,file', { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="audit-${id}.csv"` } })); vi.stubGlobal('fetch', fetch);
    const result = await client.apiBlob(path); expect(await result.blob.text()).toBe('safe,file'); expect(fetch.mock.calls.map(call => call[0])).toEqual([`/api/v1${path}`, '/api/v1/auth/refresh', `/api/v1${path}`]); expect(fetch.mock.calls.every(call => call[1].credentials === 'include')).toBe(true);
    expect(() => client.apiBlob('https://kong:8001/status')).toThrow(); expect(fetch).toHaveBeenCalledTimes(3);
  });
  it('rejects stale-actor downloads and releases Blob URL after a successful browser save', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { client.setApiActorId(other); return new Response('safe'); })); await expect(client.apiBlob(`/audit/global/exports/${id}/download`)).rejects.toMatchObject({ code: 'SESSION_CHANGED' });
    client.setApiActorId(actor); vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('safe'))); const create = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:source-only'), revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {}), click = vi.fn(), remove = vi.fn(); vi.stubGlobal('document', { createElement: () => ({ style: {}, click, remove }), body: { appendChild: vi.fn() } });
    const { downloadAuditExport, auditDownloadFilename } = await import('../../apps/console-web/src/features/m7.download'); expect(auditDownloadFilename(`attachment; filename="audit-${id}.csv"`, 'csv')).toBe(`audit-${id}.csv`); expect(auditDownloadFilename('attachment; filename="../../private.pem"', 'csv')).toBe('audit-export.csv');
    await downloadAuditExport(`/audit/global/exports/${id}/download`, 'csv', identity, () => identity); expect(click).toHaveBeenCalledTimes(1); expect(remove).toHaveBeenCalledTimes(1); expect(revoke).toHaveBeenCalledWith('blob:source-only');
    await expect(downloadAuditExport(`/audit/global/exports/${id}/download`, 'csv', identity, () => ({ ...identity, wid: other }))).rejects.toThrow(); expect(create).toHaveBeenCalledTimes(1);
  });
});
