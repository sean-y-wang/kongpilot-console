import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, apiConfigurationAbandon, setApiActorId, setCsrfToken } from '../../apps/console-web/src/api/client';
import { safeRecoveryReferences } from '../../apps/console-web/src/api/workspace-scope';
import { configurationAbandonmentAuthority, configurationAbandonmentIntent, configurationAbandonmentBody, configurationAbandonmentResult, configurationAbandonmentReadback, configurationAbandonmentReferencesToResolve, configurationOriginalJobPath, configurationOriginalJobResult, configurationReceiptPath, configurationDetailEntity } from '../../apps/console-web/src/features/m8.model';
import type { ConfigurationJob, ConfigurationAbandonmentIntent } from '../../apps/console-web/src/features/m8.types';
import type { User } from '../../apps/console-web/src/api/types';

const cid = 'a2331790-664b-4d9e-a5c4-ed692f92308d', wid = 'a3217968-39d7-4458-9e52-e726519e40e5', actor = 'fe8e836d-ea93-4a1d-977c-eb85f8f56a1c', id = '578b1021-9c76-4241-bd75-6f89b783392c', executionId = '2a384c83-125f-408e-8392-f5f51fba63ba', oldKey = '3e53395b-5124-40a9-9cbd-c66894347c74', key = '6595c2bf-ea25-4a6c-8e86-1cad8898b53f', other = '7e6b4bdb-43fc-4e88-85a5-2885a90f5e21', sid = 'f473c489-2577-40b3-b359-179bca02575c';
const identity = { actor, version: 'epoch:3', cid, wid }, authority = { writable: true, snapshotsWrite: true, workflowsWrite: true };
const intent: ConfigurationAbandonmentIntent = { jobId: id, revision: 8, executionId, executionRevision: 3, planRevision: 2, planHash: 'a'.repeat(64), leaseGeneration: 1, workflowExecutionId: null, confirmationName: `abandon:${id}` };
const job: ConfigurationJob = { id, clusterId: cid, workspaceId: wid, actorId: actor, idempotencyKey: oldKey, revision: 8, kind: 'apply', state: 'running', executionMode: 'direct', createdAt: '2026-10-11T12:00:00.000Z', completedAt: null, safeProgress: {}, capabilities: { abandon: true }, abandonmentIntent: intent };
const reference = { kind: 'configuration', actorId: actor, clusterId: cid, workspaceId: wid, idempotencyKey: key, originalJobId: id, originalJobKey: oldKey, abandonmentIntent: intent };
const body = () => configurationAbandonmentBody(job, identity, identity, intent, authority, intent.confirmationName);
const readback = () => ({ entity: { ...job, state: 'uncertain', revision: 9, capabilities: { abandon: false }, abandonmentSessionMatches: true, safeProgress: { abandoned: true, terminalFailureRecorded: true, executionId, executionRevision: 4, planRevision: 2, planHash: 'a'.repeat(64), leaseGeneration: 1, workflowExecutionId: null, completedSteps: 16, unresolvedSteps: 1 } } });
const user: User = { id: actor, username: 'source-only', superAdmin: false, permissionsVersion: identity.version, capabilities: { platformAdmin: false, modules: {}, clusters: [cid], grants: [{ module: 'snapshots', action: 'write', cluster_id: cid, workspace_id: wid, scope_type: 'workspace', scope_values: [wid] }] } };

beforeEach(() => { setApiActorId(actor); setCsrfToken('synthetic-source-csrf'); vi.stubGlobal('window', { dispatchEvent: vi.fn(() => true) }); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); setApiActorId(undefined); setCsrfToken(''); });

describe('M8 original execution factual closure', () => {
  it('uses the actual job producer capability, tuple, original key and same-session projection', async () => {
    const { ConfigurationService } = await import('../../apps/console-api/src/modules/configuration/configuration.service');
    let currentSid = sid;
    const service = Object.assign(Object.create(ConfigurationService.prototype), {
      access: { description: async () => ({ actor: { id: actor }, scope: { clusterId: cid, workspaceId: wid } }) },
      db: { one: async () => ({ idempotency_key: oldKey, actor_id: actor, origin_session_id: sid, execution_id: executionId, execution_mode: 'direct', approval_required: false, workflow_id: null, plan_id: other }) },
      failureLedger: { abandonmentIntent: vi.fn(async () => intent) },
      context: { current: () => ({ actor: { id: actor }, sessionId: currentSid, clusterId: cid, workspaceId: wid }) }, authz: { hasWholeWorkspace: vi.fn(async () => true) }
    });
    const actual = await service.jobProjection({}, job as any), row = configurationDetailEntity<ConfigurationJob>({ entity: actual }, identity, id);
    expect(configurationAbandonmentIntent(row, identity, authority)).toEqual(intent);
    expect(configurationAbandonmentBody(row, identity, identity, intent, authority, intent.confirmationName)).toEqual(body());
    const proven = await service.jobProjection({}, readback().entity as any);
    expect(configurationAbandonmentReadback({ entity: proven }, reference, identity, authority).state).toBe('uncertain');
    currentSid = other;
    expect((await service.jobProjection({}, readback().entity as any)).abandonmentSessionMatches).toBe(false);
    expect(() => configurationAbandonmentReadback({ entity: { ...proven, abandonmentSessionMatches: false } }, reference, identity, authority)).toThrow();
  });

  it('hides the control for readonly, foreign scope/actor, malformed or unoffered tuples', () => {
    for (const invalid of [{ writable: false }, { snapshotsWrite: false }]) expect(configurationAbandonmentIntent(job, identity, { ...authority, ...invalid })).toBeUndefined();
    for (const invalid of [{ actor: other }, { cid: other }, { wid: other }, { version: undefined }]) expect(configurationAbandonmentIntent(job, { ...identity, ...invalid }, authority)).toBeUndefined();
    for (const invalid of [{ actorId: other }, { capabilities: { abandon: false } }, { state: 'uncertain' }, { kind: 'export' }, { idempotencyKey: undefined }, { abandonmentIntent: { ...intent, jobId: other } }, { abandonmentIntent: { ...intent, revision: 7 } }, { abandonmentIntent: { ...intent, leaseGeneration: 0 } }, { abandonmentIntent: { ...intent, privateExtra: 'must-not-submit' } }, { executionMode: 'approval' }]) expect(configurationAbandonmentIntent({ ...job, ...invalid } as any, identity, authority)).toBeUndefined();
    const approved = { ...job, executionMode: 'approval' as const, abandonmentIntent: { ...intent, workflowExecutionId: other } };
    expect(configurationAbandonmentIntent(approved, identity, authority)).toEqual(approved.abandonmentIntent);
    expect(configurationAbandonmentIntent(approved, identity, { ...authority, workflowsWrite: false })).toBeUndefined();
  });

  it('checks current whole-workspace grants and permission epochs, never tag/entity or another scope', () => {
    expect(configurationAbandonmentAuthority(user, identity, true)).toMatchObject({ snapshotsWrite: true, workflowsWrite: false });
    for (const invalid of [{ id: other }, { permissionsVersion: 'epoch:4' }, { capabilities: undefined }]) expect(configurationAbandonmentAuthority({ ...user, ...invalid } as User, identity, true).snapshotsWrite).toBe(false);
    for (const scope_type of ['tag_group', 'entity'] as const) expect(configurationAbandonmentAuthority({ ...user, capabilities: { ...user.capabilities!, grants: [{ ...user.capabilities!.grants[0], scope_type }] } }, identity, true).snapshotsWrite).toBe(false);
    for (const invalid of [{ cid: other }, { wid: other }]) expect(configurationAbandonmentAuthority(user, { ...identity, ...invalid }, true).snapshotsWrite).toBe(false);
  });

  it('requires exact confirmation/current identity/full tuple and projects only the nine POST fields', () => {
    expect(Object.keys(body()).sort()).toEqual(['confirmed', 'confirm_name', 'revision', 'executionId', 'executionRevision', 'planRevision', 'planHash', 'leaseGeneration', 'workflowExecutionId'].sort());
    expect(body()).not.toHaveProperty('jobId'); expect(body()).not.toHaveProperty('confirmationName');
    for (const invalid of [{ actor: other }, { cid: other }, { wid: other }, { version: 'epoch:4' }]) expect(() => configurationAbandonmentBody(job, identity, { ...identity, ...invalid }, intent, authority, intent.confirmationName)).toThrow();
    expect(() => configurationAbandonmentBody(job, identity, identity, intent, authority, 'wrong-name')).toThrow();
    for (const invalid of [{ revision: 9 }, { executionId: other }, { executionRevision: 4 }, { planRevision: 3 }, { planHash: 'b'.repeat(64) }, { leaseGeneration: 2 }, { workflowExecutionId: other }]) expect(() => configurationAbandonmentBody(job, identity, identity, { ...intent, ...invalid }, authority, intent.confirmationName)).toThrow();
  });

  it('treats uncertain as factual accounting only and rejects every foreign/incomplete readback proof', () => {
    const response = { jobId: id, executionId, clusterId: cid, workspaceId: wid, state: 'uncertain', completedSteps: 16, unresolvedSteps: 1, terminalFailureRecorded: true, abandoned: true, originalWorkflowUnchanged: true, originalNativeReceiptsUnchanged: true };
    expect(configurationAbandonmentResult(response, job, intent).state).toBe('uncertain');
    expect(() => configurationAbandonmentResult({ ...response, state: 'succeeded' }, job, intent)).toThrow();
    expect(configurationOriginalJobResult(readback(), reference)).toMatchObject({ complete: false, success: false, jobId: id });
    for (const invalid of [{ actorId: other }, { clusterId: other }, { workspaceId: other }, { idempotencyKey: other }, { state: 'succeeded' }, { abandonmentSessionMatches: false }, { revision: 8 }]) expect(() => configurationAbandonmentReadback({ entity: { ...readback().entity, ...invalid } }, reference, identity, authority)).toThrow();
    for (const invalid of [{ abandoned: false }, { terminalFailureRecorded: false }, { executionId: other }, { executionRevision: 3 }, { planRevision: 3 }, { planHash: 'b'.repeat(64) }, { leaseGeneration: 2 }, { workflowExecutionId: other }]) expect(() => configurationAbandonmentReadback({ entity: { ...readback().entity, safeProgress: { ...readback().entity.safeProgress, ...invalid } } }, reference, identity, authority)).toThrow();
    for (const invalid of [{ writable: false }, { snapshotsWrite: false }]) expect(() => configurationAbandonmentReadback(readback(), reference, identity, { ...authority, ...invalid })).toThrow();
    expect(() => configurationAbandonmentReadback(readback(), { ...reference, originalJobKey: other }, identity, authority)).toThrow();
  });

  it('explicitly releases only the exact original request and its accounting reference, retaining every other risk', () => {
    const saved = { actor_id: actor, kind: 'configuration' as const, cid, wid, idempotencyKey: oldKey, state: 'uncertain', created_at: new Date().toISOString() };
    const own = { ...saved, idempotencyKey: key, originalJobId: id, originalJobKey: oldKey, abandonmentIntent: intent };
    const foreign = [{ ...saved, idempotencyKey: other }, { ...saved, wid: other }, { ...saved, cid: other }, { ...saved, actor_id: other }, { ...saved, kind: 'portal' as const }], refs = [saved, own, ...foreign];
    expect(configurationAbandonmentReferencesToResolve(refs, readback(), reference, identity, authority, intent.confirmationName)).toEqual([saved, own]);
    expect(refs.map(ref => ref.state)).toEqual(Array(refs.length).fill('uncertain'));
    expect(() => configurationAbandonmentReferencesToResolve(refs, readback(), reference, identity, authority, 'wrong')).toThrow();
    expect(() => configurationAbandonmentReferencesToResolve(refs, readback(), reference, { ...identity, actor: other }, authority, intent.confirmationName)).toThrow();
    expect(() => configurationAbandonmentReferencesToResolve(refs, readback(), reference, { ...identity, wid: other }, authority, intent.confirmationName)).toThrow();
  });

  it('sends abandon exactly once on 401 with no automatic refresh or POST replay; normal writes keep their refresh behavior', async () => {
    let calls: string[] = [];
    const fetcher = vi.fn(async (url: string) => { calls.push(url); return new Response(JSON.stringify({ error: { code: 'SESSION_EXPIRED' } }), { status: 401 }); }); vi.stubGlobal('fetch', fetcher);
    await expect(apiConfigurationAbandon(configurationOriginalJobPath(reference).replace(/\?/, '/abandon?'), body(), key, { originalJobKey: oldKey, intent })).rejects.toMatchObject({ status: 401 });
    expect(calls).toEqual([`/api/v1/clusters/${cid}/configuration/jobs/${id}/abandon?workspaceId=${wid}`]);
    calls = []; let first = true;
    fetcher.mockImplementation(async url => { calls.push(url); if (first) { first = false; return new Response(JSON.stringify({ error: { code: 'SESSION_EXPIRED' } }), { status: 401 }); } return new Response(JSON.stringify({ data: { ok: true } }), { status: 201 }); });
    const normal = `/clusters/${cid}/configuration/imports?workspaceId=${wid}`;
    await expect(api(normal, { method: 'POST', body: '{}', headers: { 'X-Idempotency-Key': key } })).resolves.toEqual({ ok: true });
    expect(calls).toEqual([`/api/v1${normal}`, '/api/v1/auth/refresh', `/api/v1${normal}`]);
  });

  it('keeps unknown recovery on the original job with safe persisted tuple, without creating a new-job resolver', async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({ error: { code: 'UPSTREAM_TIMEOUT' } }), { status: 504 })); vi.stubGlobal('fetch', fetcher);
    let error: any;
    try { await apiConfigurationAbandon(configurationOriginalJobPath(reference).replace(/\?/, '/abandon?'), body(), key, { originalJobKey: oldKey, intent }); } catch (caught) { error = caught; }
    expect(error).toMatchObject({ code: 'WRITE_RESULT_UNKNOWN', recovery: { originalJobId: id, originalJobKey: oldKey, idempotencyKey: key, abandonmentIntent: intent, state: 'uncertain' } });
    expect(fetcher).toHaveBeenCalledTimes(1); expect(configurationOriginalJobPath(error.recovery)).not.toContain('by-key');
    const saved = { actor_id: actor, kind: 'configuration', cid, wid, ...error.recovery, created_at: new Date().toISOString() }, refs = safeRecoveryReferences([saved], actor);
    expect(refs[0]).toMatchObject({ originalJobId: id, originalJobKey: oldKey, abandonmentIntent: intent });
    for (const invalid of [{ originalJobId: undefined }, { originalJobKey: other, abandonmentIntent: { ...intent, executionRevision: 0 } }, { kind: 'portal' }, { actor_id: other }]) expect(safeRecoveryReferences([{ ...saved, ...invalid }], actor)).toEqual([]);
    expect(configurationReceiptPath({ kind: 'configuration', clusterId: cid, workspaceId: wid, idempotencyKey: oldKey })).toBe(`/clusters/${cid}/configuration/jobs/by-key/${oldKey}?workspaceId=${wid}`);
  });

  it('refuses extra body fields, foreign query scope, wrong names and altered captured tuples before any transport', () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    const path = configurationOriginalJobPath(reference).replace(/\?/, '/abandon?');
    for (const invalid of [{ ...body(), jobId: id }, { ...body(), driver: 'deck' }, { ...body(), confirm_name: 'wrong' }, { ...body(), executionRevision: 4 }]) expect(() => apiConfigurationAbandon(path, invalid as any, key, { originalJobKey: oldKey, intent })).toThrow();
    for (const invalid of [path + '&workspaceId=' + wid, path + '&scope=cluster', path.replace(cid, 'not-uuid'), path.replace(id, 'not-uuid'), path + '#fragment']) expect(() => apiConfigurationAbandon(invalid, body(), key, { originalJobKey: oldKey, intent })).toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });
});
