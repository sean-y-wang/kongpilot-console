import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { EntityChangeExecutionService } from '../../apps/console-api/src/modules/workflows/entity-change-execution.service';
import { partialNoSendTerminalFixture } from './helpers/partial-no-send-terminal-fixture';

/** Offline integration of the real Root entry, private HTTP frames and crypto
 * certifier with explicit in-memory SQL/current-policy adapters. Synthetic rows
 * never represent runtime facts or issue an executable packet/native handle. */
function fixture() {
  const f = partialNoSendTerminalFixture(), db = f.txMock, context = new KongExecutionContextService();
  const originalOne = db.one.getMockImplementation()!, originalQuery = db.query.getMockImplementation()!;
  f.actor.idempotencyKey = 'original-execution-key';
  const originalKey = f.actor.idempotencyKey, sid = randomUUID();
  const state = { epoch: '1', sessionActive: true, permission: f.envelope.prepared.permissionVersion,
    denied: false, failAudit: false, failCas: '', revokedAfterCertification: false };
  const workflow: any = { revision: 7, state: 'failed', plan_hash: f.source.workflowPlanHash };
  const execution: any = { id: f.source.workflowExecutionId, workflow_id: f.plan.workflowId,
    cluster_id: f.plan.clusterId, workspace_id: f.plan.workspaceId, plan_revision: f.plan.planRevision,
    plan_hash: f.source.workflowPlanHash, execution_actor_id: f.actor.user.id, idempotency_key: originalKey,
    state: 'failed', snapshot_state: 'ready', completed_at: new Date() };
  const cluster: any = { revision: f.plan.scope.clusterRevision, execution_mode: f.plan.executionMode,
    admin_url: 'http://fixture.invalid:8001', transport_scope: f.plan.scope.transportScope };
  const workspace: any = { revision: f.plan.scope.workspaceRevision, status: 'active' };
  const audits: any[] = [];
  db.one.mockImplementation(async (sql: string, params: any[] = []) => {
    if (sql.includes('FROM iam_epoch')) return { version: state.permission };
    if (sql.includes('FROM workflow_executions e')) return { ...execution,
      workflow_state: workflow.state, workflow_revision: workflow.revision };
    if (sql.includes('FROM auth_sessions')) {
      expect(params).toEqual([sid, f.actor.user.id]);
      return state.sessionActive ? { credential_epoch: state.epoch, user_epoch: state.epoch } : null;
    }
    if (sql.includes('FROM clusters')) return structuredClone(cluster);
    if (sql.includes('FROM workspaces')) return structuredClone(workspace);
    if (sql.includes('FROM entity_change_execution_sources WHERE workflow_execution_id'))
      return structuredClone(f.rows.entity_change_execution_sources.find(r => r.workflow_execution_id === params[0]));
    if (sql.startsWith('SELECT id FROM recycle_entries') && sql.includes('FOR UPDATE'))
      return { id: f.entryId };
    if (sql.startsWith('SELECT restore_state,restored_id FROM recycle_nodes')) {
      const node=f.rows.recycle_nodes.find(row=>row.entry_id===params[0]&&row.node_key===params[1]);
      return node?{restore_state:node.restore_state,restored_id:node.restored_id}:null;
    }
    return originalOne(sql, params);
  });
  db.query.mockImplementation(async (sql: string, params: any[] = []) => {
    if (sql.includes('FROM audit_events')) return structuredClone(audits.filter(a => a.after.requestHmac === params[4]));
    if (sql.startsWith('SELECT id FROM mutation_operations') && sql.includes('FOR UPDATE'))
      return f.rows.mutation_operations.filter(m => m.entity_change_source_id === params[0]).map(m => ({ id: m.id }));
    if (sql.startsWith('SELECT node_key FROM recycle_nodes') && sql.includes('FOR UPDATE'))
      return f.rows.recycle_nodes.map(n => ({ node_key: n.node_key }));
    return originalQuery(sql, params);
  });
  db.exec.mockImplementation(async (sql: string, params: any[] = []) => {
    if (sql.startsWith('SELECT pg_advisory_xact_lock')) return 0;
    if (sql.startsWith('UPDATE mutation_operations')) {
      if (state.failCas === 'mutation') return 0;
      const m = f.rows.mutation_operations.find(m => m.id === params[0] && m.cluster_id === params[1]
        && m.workspace_id === params[2] && m.entity_change_source_id === params[3] && m.entity_change_attempt_id === params[4]
        && m.state === 'uncertain' && m.remote_started === true && m.remote_completed === false && m.result_secret === null);
      if (!m) return 0; m.state = 'failed'; return 1;
    }
    if (sql.startsWith('UPDATE recycle_nodes')) {
      if (state.failCas === 'node') return 0;
      const n = f.rows.recycle_nodes.find(n => n.entry_id === params[0] && n.node_key === params[1]
        && n.restore_state === 'pending' && n.restored_id === null);
      if (!n) return 0; n.restore_state = 'failed'; return 1;
    }
    if (sql.startsWith('UPDATE recycle_entries')) {
      if (state.failCas === 'entry') return 0;
      const e = f.rows.recycle_entries.find(e => e.id === params[0] && e.cluster_id === params[1]
        && e.workspace_id === params[2] && e.state === 'restoring' && e.mutation_id === null);
      if (!e) return 0; e.state = 'partially_restored'; return 1;
    }
    throw new Error('Unexpected SQL mutation in metadata-only test');
  });
  db.transaction.mockImplementation(async (fn: any) => {
    const before = structuredClone(f.rows), auditBefore = structuredClone(audits);
    try { return await fn(db); } catch (error) {
      Object.assign(f.rows, before); audits.splice(0, audits.length, ...auditBefore); throw error;
    }
  });
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()), assertLeaseOwnership: vi.fn(async () => undefined) };
  const authz: any = { permissionVersion: vi.fn(async () => state.permission) };
  const audit: any = { append: vi.fn(async (event: any, tx: any) => {
    expect(tx).toBe(db); if (state.failAudit) throw new Error('Synthetic audit transaction unavailable');
    const id = randomUUID(), eventHash = f.secrets.fingerprint(event.after);
    audits.push({ id, event_hash: eventHash, after: structuredClone(event.after), result: event.result });
    if (state.revokedAfterCertification) state.denied = true;
    return { id, eventHash };
  }) };
  const plans: any = { load: vi.fn(async () => ({ row: structuredClone(workflow), plan: f.plan })) };
  const intents: any = { assertSubject: vi.fn(async () => { if (state.denied) throw new ForbiddenException({ code: 'SYNTHETIC_CURRENT_SUBJECT_DENIED' }); }),
    executionMaterial: vi.fn(async () => { if (state.denied) throw new ForbiddenException(); return f.envelope; }) };
  const kong: any = { request: vi.fn(), transportScope: vi.fn() }, writer: any = { execute: vi.fn() };
  const capturer: any = { capture: vi.fn(), assertUnchanged: vi.fn() };
  const appendOutcome = vi.spyOn(f.facts, 'appendOutcome'), appendSendIntent = vi.spyOn(f.facts, 'appendSendIntent');
  const approval:any={verifyApprovalSet:vi.fn(async()=>({reviewers:[{userId:randomUUID()},{userId:randomUUID()},{userId:randomUUID()}]}))},boundary:any={assertReviewer:vi.fn(async()=>undefined)};
  const certify=f.reader.certifyKnownNoSendPartialSource.getMockImplementation()!;
  f.reader.certifyKnownNoSendPartialSource.mockImplementation(async()=>({...await certify(),alreadyClosed:f.rows.recycle_entries[0].state==='partially_restored'}));
  const kernel = new EntityChangeExecutionService(db, redis, f.secrets, context, kong, authz, audit,
    plans, approval, intents, f.facts, capturer, writer, boundary, undefined, undefined, undefined, f.reader as any);
  const body: any = { revision: workflow.revision, planHash: f.source.workflowPlanHash,
    executionId: f.source.workflowExecutionId, confirmed: true, confirm_name: 'native-change' };
  const call = (request: any = body, actor: any = f.actor, boundUser: any = f.actor.user, boundSid: string | null = sid) =>
    context.runHttp({ requestId: actor.requestId, idempotencyKey: actor.idempotencyKey }, () => {
      context.bindHttpActor(boundUser, boundSid ?? undefined);
      return context.runActor({ actor: boundUser, clusterId: f.plan.clusterId, workspaceId: f.plan.workspaceId,
        module: 'workflows', action: 'write' }, () => kernel.reconcilePartialRestoreNoSend(f.plan, request, actor));
    });
  const writes = () => db.exec.mock.calls.filter(([sql]: any[]) => sql.startsWith('UPDATE'));
  const immutable = () => f.secrets.fingerprint(Object.fromEntries(Object.entries(f.rows).filter(([table]) =>
    !['mutation_operations', 'recycle_entries', 'recycle_nodes'].includes(table))));
  const noNative = () => {
    expect(kong.request).not.toHaveBeenCalled(); expect(kong.transportScope).not.toHaveBeenCalled();
    expect(writer.execute).not.toHaveBeenCalled(); expect(capturer.capture).not.toHaveBeenCalled();
    expect(appendOutcome).not.toHaveBeenCalled(); expect(appendSendIntent).not.toHaveBeenCalled();
    expect(db.exec.mock.calls.some(([sql]: any[]) => /INSERT|DELETE|TRUNCATE/.test(sql))).toBe(false);
  };
  return { ...f, db, kernel, context, state, workflow, execution, cluster, workspace, sid, redis, authz,
    audit, audits, plans, intents, body, call, writes, immutable, noNative, approval, boundary };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '49'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
describe('M11 fixed partial no-send terminal metadata repair (offline SQL/current-policy/Reader adapters)', () => {
  it('changes only entry and failed HMAC node, preserves failed execution/native ledgers and replays only exact audit recipe', async () => {
    const f = fixture(), before = structuredClone(f.rows.mutation_operations), immutableBefore = f.immutable();
    const first = await f.call();
    expect(first).toMatchObject({ state: 'failed', terminal: 'failed', metadataReconciled: true, alreadyReconciled: false, nativeRequestsSent: 0 });
    expect(f.writes().map(([sql]: any[]) => sql.split(' ')[1])).toEqual(['recycle_nodes', 'recycle_entries']);
    expect(f.rows.mutation_operations).toEqual(before); expect(f.immutable()).toBe(immutableBefore);
    expect(f.workflow.state).toBe('failed'); expect(f.execution.state).toBe('failed');
    expect(f.rows.recycle_entries[0].state).toBe('partially_restored'); expect(f.rows.recycle_nodes[5].restore_state).toBe('failed'); expect(f.rows.recycle_nodes[6].restore_state).toBe('pending');
    expect(f.audit.append).toHaveBeenCalledOnce(); expect(f.audit.append.mock.calls[0][0]).toMatchObject({ result: 'failed',
      before: { operationState: 'failed', entryState: 'restoring', nodeRestoreState: 'pending' },
      after: { shape: 'partial-no-send', workflowState: 'failed', executionState: 'failed', operationState: 'failed', coveredPresent: 5, nativeSuccesses: 0, knownNotSent: 1, unattempted: 1, nativeRequestsSent: 0 } });
    const writes = f.writes().length, replay = await f.call(); expect(replay).toEqual({ ...first, alreadyReconciled: true }); expect(f.writes()).toHaveLength(writes); expect(f.audit.append).toHaveBeenCalledOnce();
    expect(f.approval.verifyApprovalSet).toHaveBeenCalledTimes(4); expect(f.boundary.assertReviewer).toHaveBeenCalledTimes(6); f.noNative();
  });
  it.each(['entry', 'node', 'audit'])('rolls both projection rows back when %s fails, with no fabricated facts or Native callback', async failure => {
    const f = fixture(), before = structuredClone(f.rows);
    if (failure === 'audit') f.state.failAudit = true; else f.state.failCas = failure;
    await expect(f.call()).rejects.toBeDefined(); expect(f.rows).toEqual(before); expect(f.audits).toEqual([]); f.noNative();
  });
  it('preserves the real already-failed HMAC projection and records that truth while closing only the entry', async () => {
    const f=fixture();f.rows.recycle_nodes[5].restore_state='failed';f.rows.recycle_nodes[5].safe_error='Synthetic original writer failure';
    const nodeBefore=structuredClone(f.rows.recycle_nodes[5]),operations=structuredClone(f.rows.mutation_operations),immutableBefore=f.immutable();
    const first=await f.call();expect(first).toMatchObject({state:'failed',metadataReconciled:true,nativeRequestsSent:0,alreadyReconciled:false});
    expect(f.writes().map(([sql]:any[])=>sql.split(' ')[1])).toEqual(['recycle_entries']);expect(f.rows.recycle_nodes[5]).toEqual(nodeBefore);
    expect(f.rows.mutation_operations).toEqual(operations);expect(f.immutable()).toBe(immutableBefore);
    expect(f.audit.append.mock.calls[0][0]).toMatchObject({before:{operationState:'failed',entryState:'restoring',nodeRestoreState:'failed'},after:{shape:'partial-no-send',nodeRestoreState:'failed'}});
    const replay=await f.call();expect(replay).toEqual({...first,alreadyReconciled:true});expect(f.writes()).toHaveLength(1);expect(f.audit.append).toHaveBeenCalledOnce();f.noNative();
  });
  it.each(['uncertain','restored','running'])('rejects the actual locked %s node even if a Reader adapter reports a no-send footprint',async state=>{
    const f=fixture();f.rows.recycle_nodes[5].restore_state=state;
    await expect(f.call()).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_PROOF_INVALID'}});
    expect(f.writes()).toEqual([]);expect(f.audit.append).not.toHaveBeenCalled();f.noNative();
  });
  it('rejects a purported failed node with a restored UUID',async()=>{
    const f=fixture();f.rows.recycle_nodes[5].restore_state='failed';f.rows.recycle_nodes[5].restored_id=randomUUID();
    await expect(f.call()).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_PARTIAL_NO_SEND_TERMINAL_PROOF_INVALID'}});expect(f.writes()).toEqual([]);f.noNative();
  });
  it('refuses replacement key, foreign actor/SID and revoked epoch before any metadata writes', async () => {
    for (const edit of [(f: any) => { f.actor.idempotencyKey = 'replacement-execution-key'; },
      (f: any) => { f.actor.workspaceId = randomUUID(); }, (f: any) => { f.state.epoch = '2'; }, (f: any) => { f.state.sessionActive = false; }]) {
      const f = fixture(); edit(f); await expect(f.call()).rejects.toBeDefined(); expect(f.writes()).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled(); f.noNative();
    }
  });
  it('rolls back when current approval or subject is revoked and refuses a Reader that cannot certify its real no-send footprint', async () => {
    for (const edit of [(f: any) => { f.approval.verifyApprovalSet.mockRejectedValue(new ForbiddenException()); },
      (f: any) => { f.reader.certifyKnownNoSendPartialSource.mockRejectedValue(new Error('Synthetic unknown original outcome')); },
      (f: any) => { f.state.revokedAfterCertification = true; }]) {
      const f = fixture(), before = structuredClone(f.rows); edit(f); await expect(f.call()).rejects.toBeDefined(); expect(f.rows).toEqual(before); expect(f.audits).toEqual([]); f.noNative();
    }
  });
});
