import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { WorkflowBusinessRuntimeService } from '../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';

/** Approved design (2026-10-25 00:50): per Kong business request, per party, ONE
 * fresh verification read shared by the non-before-send checkpoint layers; replays
 * still re-authorize the observation and re-check current grants; before-send
 * always performs its own separate fresh read; a new request is always fresh. */
function fixture() {
  const namespace = Object.freeze({}), tx: any = {}, plan: any = { workflowId: 'wf-1', scheduling: {} };
  const state = { permissionVersion: 'p1', grantsRevoked: false };
  const resource = { clusterId: 'c', workspaceId: 'w', path: '/upstreams/u', kind: 'point', required: true };
  const context: any = {
    peek: () => ({ sessionId: null }), requireWorkflowScheduledNamespaceHandle: () => namespace,
    requireWorkflowScheduledCurrentPrincipal: () => ({ namespace: { kind: 'configuration_v2', workflow: { id: 'wf-1' }, claim: { scheduleId: 's' }, permissionVersion: state.permissionVersion } }),
  };
  const material: any = {
    currentReadInput: vi.fn(async (_p: any, _d: any, userId: string, role: string) => ({ userId, role })),
    runResponseScope: vi.fn((fn: any) => fn()), resolveAbsenceReadScope: vi.fn(async () => ({ resources: [resource] })),
    authorizeResponse: vi.fn(async () => undefined),
    assertCurrentReadGrants: vi.fn(async () => { if (state.grantsRevoked) throw Object.assign(new Error('denied'), { response: { code: 'WORKFLOW_BUSINESS_GRANT_CHANGED' } }); }),
  };
  const repository: any = { inspectStored: vi.fn(async () => ({ plan, draft: {} })) };
  const secrets: any = { fingerprint: (v: unknown) => JSON.stringify(v) };
  const args: any[] = Array(21).fill({}); args[2] = secrets; args[3] = context; args[9] = repository; args[15] = material;
  const svc: any = new (WorkflowBusinessRuntimeService as any)(...args);
  const fresh = vi.spyOn(svc, 'withLiveReads').mockImplementation(async (...a: any[]) => {
    if (state.grantsRevoked) throw Object.assign(new Error('denied'), { response: { code: 'WORKFLOW_BUSINESS_GRANT_CHANGED' } });
    return a[5]({ role: a[3] }, new Map([['k', { resource, value: { id: 'u' } }]]), {});
  });
  const layer = (phase: string, action: 'write' | 'approve' = 'write') =>
    svc.runConfigurationPartyCheckpoint(namespace, phase, tx, () => svc.subject(plan, action === 'approve' ? 'rev' : 'exe', action, phase, tx), true);
  const request = (fn: () => Promise<unknown>) => svc.runConfigurationRequestRound(namespace, fn);
  const reads = (role: string) => fresh.mock.calls.filter(c => c[3] === role).length;
  return { svc, state, material, fresh, layer, request, reads };
}

describe('scheduled configuration per-request shared party read', () => {
  it('shares one fresh read per party across the job/execution/load/claim layers of one request, re-checking grants on each replay', async () => {
    const f = fixture();
    await f.request(async () => {
      for (const phase of ['step', 'packet', 'capture']) { await f.layer(phase); await f.layer(phase, 'approve'); }
    });
    expect(f.reads('executor')).toBe(1); expect(f.reads('reviewer')).toBe(1);
    expect(f.material.assertCurrentReadGrants).toHaveBeenCalledTimes(4);
    expect(f.material.authorizeResponse).toHaveBeenCalledTimes(4);
  });
  it('before-send always performs its own separate fresh read, even inside a shared request round', async () => {
    const f = fixture();
    await f.request(async () => {
      await f.layer('step'); await f.layer('step', 'approve');
      await f.layer('before-send'); await f.layer('before-send', 'approve');
      await f.layer('before-send'); await f.layer('before-send', 'approve');
    });
    expect(f.reads('executor')).toBe(3); expect(f.reads('reviewer')).toBe(3);
  });
  it('each new Kong business request starts with a fresh read; a permission change between requests is denied', async () => {
    const f = fixture();
    await f.request(async () => { await f.layer('step'); await f.layer('step', 'approve'); });
    await f.request(async () => { await f.layer('step'); await f.layer('step', 'approve'); });
    expect(f.reads('executor')).toBe(2); expect(f.reads('reviewer')).toBe(2);
    f.state.grantsRevoked = true;
    await expect(f.request(() => f.layer('step'))).rejects.toMatchObject({ response: { code: 'WORKFLOW_BUSINESS_GRANT_CHANGED' } });
  });
  it('a permission change inside one request fails closed on replay or forces a fresh read', async () => {
    const f = fixture();
    await expect(f.request(async () => { await f.layer('step'); f.state.grantsRevoked = true; await f.layer('packet'); }))
      .rejects.toMatchObject({ response: { code: 'WORKFLOW_BUSINESS_GRANT_CHANGED' } });
    const g = fixture();
    await g.request(async () => { await g.layer('step'); g.state.permissionVersion = 'p2'; await g.layer('packet'); });
    expect(g.reads('executor')).toBe(2);
  });
  it('without a request round every checkpoint keeps its own fresh read', async () => {
    const f = fixture();
    await f.layer('step'); await f.layer('packet'); await f.layer('capture');
    expect(f.reads('executor')).toBe(3);
  });
});
