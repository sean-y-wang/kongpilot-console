import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { EntityChangeExecutionService } from '../../apps/console-api/src/modules/workflows/entity-change-execution.service';
import { terminalMetadataFixture } from './helpers/terminal-metadata-fixture';

/** Offline integration of the real Root entry, private HTTP frames and crypto
 * certifier with explicit in-memory SQL/current-policy adapters. Synthetic rows
 * never represent runtime facts or issue an executable packet/native handle. */
function fixture() {
  const f = terminalMetadataFixture(), db = f.txMock, context = new KongExecutionContextService();
  const originalOne = db.one.getMockImplementation()!, originalQuery = db.query.getMockImplementation()!;
  f.actor.idempotencyKey = 'original-execution-key';
  const originalKey = f.actor.idempotencyKey, sid = randomUUID();
  const state = { epoch: '1', sessionActive: true, permission: f.envelope.prepared.permissionVersion,
    denied: false, failAudit: false, failCas: '', revokedAfterCertification: false };
  const workflow: any = { revision: 7, state: 'partial', plan_hash: f.source.workflowPlanHash };
  const execution: any = { id: f.source.workflowExecutionId, workflow_id: f.plan.workflowId,
    cluster_id: f.plan.clusterId, workspace_id: f.plan.workspaceId, plan_revision: f.plan.planRevision,
    plan_hash: f.source.workflowPlanHash, execution_actor_id: f.actor.user.id, idempotency_key: originalKey,
    state: 'partial', snapshot_state: 'ready', completed_at: new Date() };
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
  const kernel = new EntityChangeExecutionService(db, redis, f.secrets, context, kong, authz, audit,
    plans, {} as any, intents, f.facts, capturer, writer, {} as any);
  const body: any = { revision: workflow.revision, planHash: f.source.workflowPlanHash,
    executionId: f.source.workflowExecutionId, confirmed: true, confirm_name: 'native-change' };
  const call = (request: any = body, actor: any = f.actor, boundUser: any = f.actor.user, boundSid: string | null = sid) =>
    context.runHttp({ requestId: actor.requestId, idempotencyKey: actor.idempotencyKey }, () => {
      context.bindHttpActor(boundUser, boundSid ?? undefined);
      return context.runActor({ actor: boundUser, clusterId: f.plan.clusterId, workspaceId: f.plan.workspaceId,
        module: 'workflows', action: 'write' }, () => kernel.reconcileTerminalMetadata(f.plan, request, actor));
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
    audit, audits, plans, intents, body, call, writes, immutable, noNative };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '49'.repeat(32)); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe('M11 Root terminal Consumer credential metadata reconciliation', () => {
  it('closes only three mutable metadata rows and leaves native facts and partial workflow intact', async () => {
    const f = fixture(), factsBefore = f.immutable(), error = f.rows.mutation_operations[5].error_code;
    const response = await f.call();
    expect(response).toMatchObject({ state: 'partial', terminal: 'partial', metadataReconciled: true,
      nativeRequestsSent: 0, alreadyReconciled: false, executionId: f.source.workflowExecutionId });
    expect(f.rows.mutation_operations[5]).toMatchObject({ state: 'failed', remote_started: true,
      remote_completed: false, result_secret: null, error_code: error, entity_id: f.packets[5].nativeId });
    expect(f.rows.recycle_entries[0].state).toBe('partially_restored');
    expect(f.rows.recycle_nodes[5]).toMatchObject({ restore_state: 'failed', restored_id: null });
    expect(f.rows.recycle_nodes[6]).toMatchObject({ restore_state: 'pending', restored_id: null });
    expect(f.workflow.state).toBe('partial'); expect(f.execution.state).toBe('partial');
    expect(f.writes()).toHaveLength(3); expect(f.immutable()).toBe(factsBefore);
    expect(f.audit.append).toHaveBeenCalledOnce();
    expect(f.audit.append.mock.calls[0][0]).toMatchObject({ actorId: f.actor.user.id, clusterId: f.plan.clusterId,
      workspaceId: f.plan.workspaceId, workflowId: f.plan.workflowId, action: 'workflow.execute.terminal-metadata-reconciled',
      result: 'failed', scopeHints: { quality: 'verified', module: 'workflows' },
      after: { nativeSuccesses: 5, knownNotSent: 1, unattempted: 1, nativeRequestsSent: 0 } });
    expect(JSON.stringify(f.audits)).not.toContain('synthetic-basic-plaintext');
    expect(f.redis.withLock.mock.calls.map(([key]: any[]) => key)).toEqual([
      `workflow:${f.plan.workflowId}`, `mutation:${f.plan.scope.transportScope}`,
    ]);
    const locks = f.db.exec.mock.calls.filter(([sql]: any[]) => sql.startsWith('SELECT pg_advisory_xact_lock'));
    expect(locks).toHaveLength(7);
    expect(locks.slice(0, 6).every(([sql]: any[]) => sql.includes('entity-change-attempt:'))).toBe(true);
    expect(locks[6][0]).toContain('entity-change-recycle-entry:'); f.noNative();
  });

  it('replays the exact original execution key using the same metadata audit without new writes', async () => {
    const f = fixture(), first = await f.call(), factsBefore = f.immutable(), second = await f.call();
    expect(second).toEqual({ ...first, alreadyReconciled: true });
    expect(f.writes()).toHaveLength(3); expect(f.audit.append).toHaveBeenCalledOnce();
    expect(f.immutable()).toBe(factsBefore); f.noNative();
  });

  it.each(['revision', 'planHash', 'executionId', 'confirmed', 'confirm_name'])('rejects changed original request %s', async field => {
    const f = fixture(), body = { ...f.body, [field]: field === 'revision' ? 999 : field === 'confirmed' ? false : 'caller-replacement' };
    await expect(f.call(body)).rejects.toBeDefined(); expect(f.writes()).toHaveLength(0); expect(f.audit.append).not.toHaveBeenCalled(); f.noNative();
  });

  it('rejects a new execution key despite the same actor and intact immutable outcome', async () => {
    const f = fixture(); f.actor.idempotencyKey = 'different-new-key';
    await expect(f.call()).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_TERMINAL_METADATA_PROOF_INVALID' } });
    expect(f.writes()).toHaveLength(0); f.noNative();
  });

  it.each(['no-session', 'other-user', 'forged-user-fields'])('rejects %s before SQL', async scenario => {
    const f = fixture();
    const actor = scenario === 'other-user' ? { ...f.actor, user: { ...f.actor.user, id: randomUUID() } }
      : scenario === 'forged-user-fields' ? { ...f.actor, user: { ...f.actor.user, superAdmin: true } } : f.actor;
    await expect(f.call(f.body, actor, f.actor.user, scenario === 'no-session' ? null : f.sid)).rejects.toMatchObject({ status: 403 });
    expect(f.db.one).not.toHaveBeenCalled(); expect(f.writes()).toHaveLength(0); f.noNative();
  });

  it.each(['revoked', 'epoch', 'permission', 'subject', 'cluster', 'workspace'])('keeps metadata uncertain after current %s authority changes', async scenario => {
    const f = fixture();
    if (scenario === 'revoked') f.state.sessionActive = false;
    if (scenario === 'epoch') f.state.epoch = '2';
    if (scenario === 'permission') f.state.permission = 'changed-permission';
    if (scenario === 'subject') f.state.denied = true;
    if (scenario === 'cluster') f.cluster.revision++;
    if (scenario === 'workspace') f.workspace.status = 'disabled';
    await expect(f.call()).rejects.toBeDefined(); expect(f.writes()).toHaveLength(0);
    expect(f.rows.mutation_operations[5].state).toBe('uncertain'); f.noNative();
  });

  it('refuses ciphertext substitution even when mutable status still looks eligible', async () => {
    const f = fixture(), outcome = f.rows.entity_change_packet_events.find(e => e.event_kind === 'outcome'
      && e.attempt_id === f.rows.entity_change_packet_attempts[5].id);
    outcome.fact_ciphertext = f.rows.entity_change_packet_events[0].fact_ciphertext;
    await expect(f.call()).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_TERMINAL_METADATA_PROOF_INVALID' } });
    expect(f.writes()).toHaveLength(0); f.noNative();
  });

  it.each(['mutation', 'node', 'entry'])('rolls back all metadata if the %s CAS fails', async table => {
    const f = fixture(); f.state.failCas = table;
    await expect(f.call()).rejects.toMatchObject({ response: { code: 'REVISION_CONFLICT' } });
    expect(f.rows.mutation_operations[5].state).toBe('uncertain'); expect(f.rows.recycle_entries[0].state).toBe('restoring');
    expect(f.rows.recycle_nodes[5].restore_state).toBe('pending'); expect(f.audits).toHaveLength(0); f.noNative();
  });

  it.each(['audit', 'late-subject'])('rolls back metadata if %s persistence/final authority fails', async failure => {
    const f = fixture(); f.state.failAudit = failure === 'audit'; f.state.revokedAfterCertification = failure === 'late-subject';
    await expect(f.call()).rejects.toBeDefined();
    expect(f.rows.mutation_operations[5].state).toBe('uncertain'); expect(f.rows.recycle_entries[0].state).toBe('restoring');
    expect(f.rows.recycle_nodes[5].restore_state).toBe('pending'); expect(f.audits).toHaveLength(0); f.noNative();
  });

  it('refuses already-closed mutable projections without the exact original scoped metadata audit', async () => {
    const f = fixture(); f.closeProjection();
    await expect(f.call()).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_TERMINAL_METADATA_PROOF_INVALID' } });
    expect(f.writes()).toHaveLength(0); expect(f.audit.append).not.toHaveBeenCalled(); f.noNative();
  });
});
