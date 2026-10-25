import { describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { decideConfigurationTargetResult, decideConfigurationUnsentTargetResult, aggregateConfigurationUnsentDecisions, type ConfigurationTargetDecisionInput } from '../../apps/console-api/src/modules/workflows/configuration-unknown-result-decision';
import { ConfigurationUnknownResultReconcileService } from '../../apps/console-api/src/modules/workflows/configuration-unknown-result-reconcile.service';
import { assertOriginalMutationReceiptMatch } from '../../apps/console-api/src/modules/workflows/unknown-result-disposition';

const OLD = randomUUID(), NEW = randomUUID(), ADDR = '10.0.0.1:8000';
const before = { id: OLD, target: ADDR, weight: 100 };
const input = (over: Partial<ConfigurationTargetDecisionInput> = {}): ConfigurationTargetDecisionInput => ({
  action: 'update', address: ADDR, desiredWeight: 55, allocatedId: NEW, before,
  effective: before, historyAllocated: [], historyComplete: true, effectiveComplete: true, ...over,
});

describe('configuration_v2 target unknown-result decision (fail closed)', () => {
  it('applied: allocated record written with the desired weight and currently effective', () => {
    const written = { id: NEW, target: ADDR, weight: 55 };
    expect(decideConfigurationTargetResult(input({ effective: written, historyAllocated: [written] })).decision).toBe('verified-applied');
    expect(decideConfigurationTargetResult(input({ desiredWeight: 0, effective: null, historyAllocated: [{ ...written, weight: 0 }] })).decision).toBe('verified-applied');
    expect(decideConfigurationTargetResult(input({ action: 'create', before: null, effective: written, historyAllocated: [written] })).decision).toBe('verified-applied');
  });
  it('not-applied: allocated id absent from full history and the before record still effective (create: address absent)', () => {
    expect(decideConfigurationTargetResult(input())).toEqual({ decision: 'verified-not-applied', reason: 'before-still-effective' });
    expect(decideConfigurationTargetResult(input({ action: 'create', before: null, effective: null })).decision).toBe('verified-not-applied');
  });
  it('ambiguous: incomplete readback, superseded/divergent writes, changed effective state, malformed input', () => {
    const written = { id: NEW, target: ADDR, weight: 55 };
    const cases: Partial<ConfigurationTargetDecisionInput>[] = [
      { historyComplete: false }, { effectiveComplete: false },
      { historyAllocated: [written], effective: before },
      { historyAllocated: [written], effective: { id: randomUUID(), target: ADDR, weight: 55 } },
      { historyAllocated: [{ ...written, weight: 70 }], effective: { ...written, weight: 70 } },
      { historyAllocated: [written, written], effective: written },
      { effective: { ...before, weight: 80 } }, { effective: null }, { effective: { id: randomUUID(), target: ADDR, weight: 100 } },
      { before: null }, { before: { ...before, id: NEW } }, { desiredWeight: 1001 }, { allocatedId: '' },
      { action: 'create', before: null, effective: { id: randomUUID(), target: ADDR, weight: 100 } },
      { action: 'create', before },
      { parentAbsent: true }, { parentAbsent: true, action: 'create', before: null, effective: null },
    ];
    for (const c of cases) expect(decideConfigurationTargetResult(input(c)).decision, JSON.stringify(c)).toBe('ambiguous');
  });
});

describe('original receipt match for configuration-linked mutations', () => {
  const row = { id: randomUUID(), state: 'uncertain', remote_started: true, remote_completed: false, error_code: 'LOCK_LOST', workflow_execution_id: null };
  const original = { executionState: 'uncertain' as const, mutationId: row.id, mutationState: 'uncertain' as const, remoteStarted: true, remoteCompleted: false, errorCode: 'LOCK_LOST' };
  it('requires the in-transaction origin link proof for NULL workflow_execution_id', () => {
    expect(() => assertOriginalMutationReceiptMatch(original, row, randomUUID())).toThrow(/RECEIPT_MISMATCH/);
    expect(() => assertOriginalMutationReceiptMatch(original, row, randomUUID(), true)).not.toThrow();
    expect(() => assertOriginalMutationReceiptMatch(original, { ...row, workflow_execution_id: randomUUID() }, randomUUID(), true)).toThrow(/RECEIPT_MISMATCH/);
  });
});

const fp = (v: unknown) => createHash('sha256').update(JSON.stringify(v ?? null)).digest('hex');
function harness(o: { parentAbsent?: boolean; effective?: any[]; history?: any[]; lease?: boolean; quiescent?: boolean; entityType?: string; versions?: string[]; siblings?: string[]; request?: any } = {}) {
  const cid = randomUUID(), wid = randomUUID(), wf = randomUUID(), mid = randomUUID(), up = randomUUID(), ce = randomUUID();
  const payload = { id: NEW, target: ADDR, weight: 55 }, beforeBody = { ...before, upstream: { id: up } };
  const m = { id: mid, state: 'uncertain', workflow_execution_id: null, configuration_execution_id: ce, configuration_step_id: randomUUID(), transport_scope: 'scope',
    entity_type: o.entityType ?? 'targets', action: 'update', parent_id: up, payload_secret: 'P', before_secret: 'B', remote_started: true, remote_completed: false,
    error_code: 'LOCK_LOST', quiescent: o.quiescent ?? true };
  const link = { workflow_execution_id: randomUUID(), claim_id: randomUUID(), workflow_id: wf, workflow_plan_revision: 2, workflow_plan_hash: 'a'.repeat(64), schedule_id: randomUUID(),
    execution_state: 'uncertain', configuration_state: 'uncertain', lease_expired: o.lease ?? true };
  const plan = { native_id: OLD, allocated_native_id: NEW, parent_id: up, body_hmac: fp(payload), before_hmac: fp(beforeBody), entity_type: 'targets', mutation_action: 'update' };
  const db = {
    one: vi.fn(async (sql: string) => sql.includes('FROM workflow_unknown_result_abandon_requests') ? (o.request ?? null) : sql.includes('SELECT transport_scope') ? { transport_scope: 'scope' }
      : sql.includes('AS quiescent') ? m : sql.includes('workflow_configuration_execution_origins') ? link : sql.includes('configuration_plan_objects') ? plan : null),
    query: vi.fn(async () => (o.siblings ?? []).map(state => ({ state }))),
    transaction: vi.fn(async (fn: any) => fn(tx)),
  };
  const tx = { exec: vi.fn(async () => undefined) };
  const audit = { append: vi.fn(async () => ({ id: randomUUID(), eventHash: 'e'.repeat(64) })) };
  const versions = [...(o.versions ?? ['v1', 'v1'])];
  const authz = { assertCluster: vi.fn(async () => undefined), permissionVersion: vi.fn(async () => versions.shift() ?? 'v1') };
  const page = (items: any[]) => ({ items: items.map(i => ({ ...i, upstream: { id: up } })), nextCursor: null, size: 100 });
  const kong = {
    request: vi.fn(async (_c: string, method: string) => { if (method !== 'GET') throw new Error('native write'); if (o.parentAbsent) throw Object.assign(new Error('nf'), { getStatus: () => 404 }); return { id: up }; }),
    list: vi.fn(async (_c: string, path: string) => path.endsWith('/targets/all') ? page(o.history ?? [before]) : page(o.effective ?? [before])),
  };
  const dispose = vi.fn(async (_c: string, _w: string, ev: any) => ({ dispositionId: randomUUID(), disposition: ev.disposition, nativeRequestsSent: 0 }));
  const svc = new ConfigurationUnknownResultReconcileService(db as any, { withLock: (_k: string, fn: any) => fn(), assertLeaseOwnership: async () => undefined } as any,
    { decrypt: (s: string) => s === 'P' ? payload : beforeBody, fingerprint: fp } as any,
    { runInternalRead: (_c: string, _p: string, fn: any) => fn(), current: () => ({ sessionId: randomUUID() }) } as any, kong as any, authz as any, { dispose } as any, { withKey: async () => { throw new Error('crypto unused in mutation harness'); }, decrypt: () => null } as any, audit as any);
  const actor = { user: { id: randomUUID() }, workspaceId: wid } as any;
  const run = (body: any = { mutationId: mid, confirmed: true, reason: 'box suspended mid-send' }) =>
    svc.reconcile({ kind: 'configuration_v2', clusterId: cid, workspaceId: wid, workflowId: wf }, body, actor);
  const p = { kind: 'configuration_v2', clusterId: cid, workspaceId: wid, workflowId: wf };
  const request = (body: any = { mutationId: mid, confirmed: true, reason: 'parent deleted by cleanup', ticket: 'OPS-42' }) => svc.requestAbandon(p, body, actor);
  const confirm = (body: any, who: any = actor) => svc.confirmAbandon(p, body, who);
  return { run, dispose, kong, authz, link, request, confirm, audit, tx, actor, mid };
}


describe('configuration_v2 unsent (no-mutation) decision', () => {
  it('treats parent-absent as verified-not-applied (send ledger never opened)', () => {
    expect(decideConfigurationUnsentTargetResult(input({ parentAbsent: true }))).toEqual({ decision: 'verified-not-applied', reason: 'unsent-parent-absent' });
  });
  it('aggregates: appears-applied wins; else ambiguous; else not-applied', () => {
    expect(aggregateConfigurationUnsentDecisions([
      { decision: 'verified-not-applied', reason: 'before-still-effective' },
      { decision: 'verified-applied', reason: 'allocated-effective' },
    ]).decision).toBe('appears-applied');
    expect(aggregateConfigurationUnsentDecisions([
      { decision: 'verified-not-applied', reason: 'unsent-parent-absent' },
      { decision: 'ambiguous', reason: 'effective-changed' },
    ]).decision).toBe('ambiguous');
    expect(aggregateConfigurationUnsentDecisions([
      { decision: 'verified-not-applied', reason: 'unsent-parent-absent' },
      { decision: 'verified-not-applied', reason: 'before-still-effective' },
    ]).decision).toBe('verified-not-applied');
  });
});

describe('ConfigurationUnknownResultReconcileService', () => {
  it('not-applied: closes via verified-not-applied disposition, zero native writes, approval-level authority', async () => {
    const h = harness();
    const r = await h.run();
    expect(r).toMatchObject({ decision: 'verified-not-applied', mutationState: 'failed', nativeRequestsSent: 0 });
    const [, , ev, , detail] = h.dispose.mock.calls[0];
    expect(ev).toMatchObject({ disposition: 'verified-not-applied', workflowExecutionId: h.link.workflow_execution_id, nativeRequestsSent: 0,
      original: { mutationState: 'uncertain', remoteStarted: true, remoteCompleted: false, errorCode: 'LOCK_LOST' } });
    expect(detail).toMatchObject({ decision: 'verified-not-applied', decisionReason: 'before-still-effective' });
    expect(h.kong.request.mock.calls.every(c => c[1] === 'GET')).toBe(true);
    expect(h.authz.assertCluster).toHaveBeenCalledWith(expect.anything(), expect.any(String), 'workflows', 'approve', expect.any(String));
  });
  it('applied: allocated target effective with desired weight', async () => {
    const written = { id: NEW, target: ADDR, weight: 55 };
    const h = harness({ effective: [written], history: [before, written] });
    expect(await h.run()).toMatchObject({ decision: 'verified-applied', mutationState: 'succeeded' });
    expect(h.dispose.mock.calls[0][2].disposition).toBe('verified-applied');
  });
  it('ambiguous: records verification-rejected and refuses with 409, state untouched', async () => {
    const h = harness({ effective: [{ id: randomUUID(), target: ADDR, weight: 10 }] });
    await expect(h.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_RECONCILE_AMBIGUOUS', disposition: 'verification-rejected' } });
    expect(h.dispose.mock.calls[0][2].disposition).toBe('verification-rejected');
  });
  it('ambiguous: deleted parent upstream (targets cascaded) is never settled', async () => {
    const h = harness({ parentAbsent: true });
    await expect(h.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_RECONCILE_AMBIGUOUS', decisionReason: 'parent-absent' } });
    expect(h.dispose.mock.calls[0][2].disposition).toBe('verification-rejected');
    expect(h.kong.list).not.toHaveBeenCalled();
  });
  it('fails closed before any disposition on active lease, non-quiescent row, unsupported entity, sibling pending, permission change, no confirmation', async () => {
    for (const [opts, code] of [[{ lease: false }, 'LEASE_ACTIVE'], [{ quiescent: false }, 'NOT_QUIESCENT'], [{ entityType: 'services' }, 'UNSUPPORTED_ENTITY'],
      [{ siblings: ['running'] }, 'SIBLINGS_PENDING'], [{ versions: ['v1', 'v2'] }, 'PERMISSIONS_CHANGED']] as const) {
      const h = harness(opts as any);
      await expect(h.run()).rejects.toMatchObject({ response: { code: `CONFIGURATION_RECONCILE_${code}` } });
      expect(h.dispose).not.toHaveBeenCalled();
    }
    const h = harness();
    await expect(h.run({ mutationId: randomUUID(), confirmed: false, reason: 'x' })).rejects.toMatchObject({ response: { code: 'CONFIGURATION_RECONCILE_CONFIRMATION_REQUIRED' } });
    await expect(h.run({ mutationId: randomUUID(), confirmed: true, reason: ' ' })).rejects.toMatchObject({ response: { code: 'CONFIGURATION_RECONCILE_REASON_REQUIRED' } });
  });

  describe('two-person abandon', () => {
    it('request: only for unprovable state; audits fresh readback, inserts request, zero native writes', async () => {
      const h = harness({ parentAbsent: true });
      const r = await h.request();
      expect(r).toMatchObject({ status: 'awaiting-second-approver', decisionReason: 'parent-absent', nativeRequestsSent: 0, ticket: 'OPS-42' });
      const a = (h.audit.append.mock.calls[0] as any[])[0];
      expect(a).toMatchObject({ action: 'workflow.unknown-result.abandon-requested', after: { requestId: r.requestId, nativeRequestsSent: 0, ticket: 'OPS-42' } });
      expect(String((h.tx.exec.mock.calls[0] as any[])[0])).toContain('workflow_unknown_result_abandon_requests');
      expect(h.dispose).not.toHaveBeenCalled();
      expect(h.kong.request.mock.calls.every(c => c[1] === 'GET')).toBe(true);
    });
    it('request: refuses provable mutations, missing ticket/reason/confirmation', async () => {
      await expect(harness().request()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_ABANDON_PROVABLE', decision: 'verified-not-applied' } });
      const h = harness({ parentAbsent: true });
      await expect(h.request({ mutationId: h.mid, confirmed: true, reason: 'x', ticket: '' })).rejects.toMatchObject({ response: { code: 'CONFIGURATION_ABANDON_TICKET_REQUIRED' } });
      await expect(h.request({ mutationId: h.mid, confirmed: true, reason: '', ticket: 'T-1' })).rejects.toMatchObject({ response: { code: 'CONFIGURATION_RECONCILE_REASON_REQUIRED' } });
      await expect(h.request({ mutationId: h.mid, confirmed: false, reason: 'x', ticket: 'T-1' })).rejects.toMatchObject({ response: { code: 'CONFIGURATION_RECONCILE_CONFIRMATION_REQUIRED' } });
      expect(h.audit.append).not.toHaveBeenCalled();
    });
    const open = (h: any, extra: any = {}) => ({ id: randomUUID(), mutation_id: h.mid, workflow_execution_id: h.link.workflow_execution_id, requester_id: randomUUID(),
      observation_hmac: 'o'.repeat(64), ticket: 'OPS-42', consumed_at: null, expired: false, ...extra });
    it('confirm: second distinct approver re-reads Kong and disposes abandoned (failed-unknown)', async () => {
      const hh = harness({ parentAbsent: true }); const rq = open(hh);
      const g = harness({ parentAbsent: true, request: rq });
      (rq as any).mutation_id = g.mid; (rq as any).workflow_execution_id = g.link.workflow_execution_id;
      const r = await g.confirm({ requestId: rq.id, confirmed: true });
      expect(r).toMatchObject({ disposition: 'abandoned', mutationState: 'failed', outcome: 'failed-unknown', requesterId: rq.requester_id, nativeRequestsSent: 0 });
      const [, , ev, , detail] = g.dispose.mock.calls[0];
      expect(ev).toMatchObject({ disposition: 'abandoned', abandonRequestId: rq.id, nativeRequestsSent: 0 });
      expect(detail).toMatchObject({ abandonRequestId: rq.id, requesterId: rq.requester_id, decisionReason: 'parent-absent' });
      expect(g.kong.request.mock.calls.every(c => c[1] === 'GET')).toBe(true);
    });
    it('confirm: refuses same person, consumed/expired request, and state that became provable', async () => {
      const g = harness({ parentAbsent: true }); const self = open(g, { requester_id: g.actor.user.id });
      const s = harness({ parentAbsent: true, request: self }); self.requester_id = s.actor.user.id; self.mutation_id = s.mid;
      await expect(s.confirm({ requestId: self.id, confirmed: true })).rejects.toMatchObject({ response: { code: 'CONFIGURATION_ABANDON_SECOND_APPROVER_REQUIRED' } });
      for (const extra of [{ consumed_at: new Date() }, { expired: true }]) {
        const x = harness({ parentAbsent: true, request: open(g, extra) });
        await expect(x.confirm({ requestId: randomUUID(), confirmed: true })).rejects.toMatchObject({ response: { code: 'CONFIGURATION_ABANDON_REQUEST_NOT_OPEN' } });
      }
      const pr = harness({}); const rq = open(pr); const q = harness({ request: rq }); rq.mutation_id = q.mid; rq.workflow_execution_id = q.link.workflow_execution_id;
      await expect(q.confirm({ requestId: rq.id, confirmed: true })).rejects.toMatchObject({ response: { code: 'CONFIGURATION_ABANDON_PROVABLE' } });
      for (const h of [s, q]) expect(h.dispose).not.toHaveBeenCalled();
    });
  });
});
