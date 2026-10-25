import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { EntityChangeExecutionService } from '../../apps/console-api/src/modules/workflows/entity-change-execution.service';

/** Genuine Root WeakMap registrations and ALS lifetime, with explicitly
 * modeled SQL/facts adapters. This is not a real PostgreSQL/native receipt. */
function fixture() {
  const secrets = new SecretService(), context = new KongExecutionContextService();
  const cid = randomUUID(), wid = randomUUID(), uid = randomUUID(), workflowId = randomUUID(), executionId = randomUUID();
  const intentId = randomUUID(), sourceId = randomUUID(), nativeId = randomUUID(), attemptId = randomUUID(), operationId = randomUUID();
  const actor = { user: { id: uid, username: 'original-owner', superAdmin: false }, workspaceId: wid, idempotencyKey: 'original-execution-request-key' };
  const metadata = { intentId, intentRevision: 1, materialHmac: 'a'.repeat(64), changeDigest: 'b'.repeat(64), packetManifestHmac: 'c'.repeat(64) };
  const plan: any = { kind: 'native-change', clusterId: cid, workspaceId: wid, workflowId, planRevision: 1,
    requester: { type: 'console', id: uid }, subject: { type: 'entity_change_intents', id: intentId }, prerequisites: [],
    steps: [{ id: randomUUID(), kind: 'metadata', handler: 'entity.change', entityType: 'entity_change_intents', entityId: intentId,
      permissionAction: 'write', dependencies: [], nativeRequests: [], metadata, metadataRevision: 1,
      metadataPayloadHmac: secrets.fingerprint(metadata), metadataBeforeHmac: 'd'.repeat(64) }] };
  const before = { id: nativeId, read_timeout: 60000 }, payload = { read_timeout: 45000 };
  const source: any = { id: sourceId, expired: true, session_id: randomUUID(), execution_actor_id: uid,
    idempotency_key: actor.idempotencyKey, revision: 2, credential_epoch: '1', state: 'failed', workflow_state: 'failed' };
  const attempt: any = { id: attemptId, source_id: sourceId, cluster_id: cid, workspace_id: wid, baseline_id: randomUUID(), pin_id: randomUUID(),
    packet_key: 'packet-1', packet_order: 1, native_type: 'services', native_id: nativeId, parent_id: null, credential_kind: null,
    mutation_action: 'update', before_hmac: secrets.fingerprint(before), body_hmac: secrets.fingerprint(payload) };
  const mutation: any = { id: operationId, actor_id: uid, cluster_id: cid, workspace_id: wid, workflow_id: workflowId,
    entity_change_source_id: sourceId, entity_change_baseline_id: attempt.baseline_id, entity_change_attempt_id: attemptId, entity_change_packet_key: attempt.packet_key,
    state: 'uncertain', error_code: '42501', remote_started: true, remote_completed: false, result_secret: null, entity_id: nativeId,
    action: 'update', entity_type: 'services', parent_id: null, credential_kind: null, idempotency_key: `entity-${executionId}-1`,
    before_secret: secrets.encrypt(before, `mutation:${operationId}:before`), payload_secret: secrets.encrypt(payload, `mutation:${operationId}:payload`) };
  const state: any = { attempts: [attempt], eventCount: 0, epoch: '1', canWrite: true };
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('FROM iam_epoch')) return { version: 1 };
    if (sql.includes('FROM entity_change_execution_sources')) return source;
    if (sql.includes('FROM users')) return { credential_epoch: state.epoch };
    if (sql.includes('FROM entity_change_packet_events')) return { count: state.eventCount };
    if (sql.includes('FROM mutation_operations')) return mutation;
    throw new Error('Unexpected reconciliation query');
  }), query: vi.fn(async (sql: string) => sql.includes('FROM entity_change_packet_attempts') ? state.attempts : []),
  exec: vi.fn(async (sql: string) => { if (sql.startsWith('UPDATE mutation_operations')) mutation.state = 'failed'; return 1; }) };
  db.transaction = vi.fn(async (fn: any) => fn(db));
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()), assertLeaseOwnership: vi.fn() };
  const kong: any = { request: vi.fn() }, writer: any = { execute: vi.fn(), installExecutionDelegate: vi.fn() }, capturer: any = { capture: vi.fn() };
  let factPolicy: any, proof: any, fact: any;
  const facts: any = { installFixedDelegate: vi.fn(value => { factPolicy = value; }), appendOutcome: vi.fn(async (value: any, token: any, tx: any) => {
    fact = value; proof = token; expect(tx).toBe(db);
    await factPolicy.verifySource(value.binding.sourceId, 'outcome', tx);
    await factPolicy.verifyPacketFact(value.binding, value, token, tx);
  }) };
  const intents: any = { assertSubject: vi.fn(async () => { if (!state.canWrite) throw new ForbiddenException(); }) };
  const audit: any = { append: vi.fn() };
  const kernel = new EntityChangeExecutionService(db, redis, secrets, context, kong, {} as any, audit, {} as any,
    {} as any, intents, facts, capturer, writer, {} as any);
  kernel.onModuleInit();
  const body = { revision: source.revision, planHash: secrets.fingerprint(plan), executionId, confirmed: true, confirm_name: 'native-change' };
  const run = (value = body, caller = actor) => context.runHttp({}, async () => {
    context.bindHttpActor(caller.user, randomUUID());
    return context.runActor({ actor: caller.user, clusterId: cid, workspaceId: caller.workspaceId, module: 'workflows', action: 'write' },
      () => kernel.reconcileNoSend(plan, value, caller));
  });
  return { kernel, context, db, redis, kong, writer, capturer, intents, audit, source, attempt, mutation, state, actor, body, run, facts,
    policy: () => factPolicy, receipt: () => ({ fact, proof }) };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe('M11 no-send reconciliation has outcome-only genuine proof authority', () => {
  it('accepts only its original outcome proof while rejecting copies, send-intent and every native checkpoint', async () => {
    const f = fixture();
    f.facts.appendOutcome.mockImplementation(async (fact: any, proof: any, tx: any) => {
      const policy = f.policy();
      await policy.verifySource(fact.binding.sourceId, 'outcome', tx);
      await policy.verifyPacketFact(fact.binding, fact, proof, tx);
      for (const copy of [{}, { ...proof }, structuredClone(proof), { approved: true, sourceId: fact.binding.sourceId }]) {
        await expect(policy.verifyPacketFact(fact.binding, fact, copy, tx)).rejects.toMatchObject({ status: 403 });
      }
      await expect(policy.verifyPacketFact(fact.binding, { ...fact, kind: 'send-intent' }, proof, tx)).rejects.toMatchObject({ status: 403 });
      await expect(policy.verifyPacketFact(fact.binding, { ...fact, outcome: 'sent-unknown' }, proof, tx)).rejects.toMatchObject({ status: 403 });
      await expect(policy.verifyPacketFact({ ...fact.binding, attemptId: randomUUID() }, fact, proof, tx)).rejects.toMatchObject({ status: 403 });
      for (const checkpoint of ['capture', 'packet', 'before-send', 'retention', 'recovery']) {
        await expect(policy.verifySource(fact.binding.sourceId, checkpoint, tx)).rejects.toMatchObject({ status: 403 });
      }
      await expect(f.kernel.verifyHandle(proof)).rejects.toMatchObject({ status: 403 });
      await expect(f.context.runEntityChangePacket(proof, async () => f.kong.request())).rejects.toMatchObject({ status: 403 });
    });
    expect(await f.run()).toMatchObject({ state: 'failed', knownNoNativeSend: true, nativeRequestsSent: 0 });
    expect(f.mutation.remote_started).toBe(true); expect(f.mutation.remote_completed).toBe(false); expect(f.mutation.result_secret).toBeNull();
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.writer.execute).not.toHaveBeenCalled(); expect(f.capturer.capture).not.toHaveBeenCalled();
    expect(f.db.exec.mock.calls.every(([sql]: any[]) => !/INSERT|remote_started\s*=|result_secret\s*=/.test(sql))).toBe(true);
  });

  it('discards the proof and historical source marker after its callback completes', async () => {
    const f = fixture(); await f.run(); const { fact, proof } = f.receipt();
    await expect(f.policy().verifyPacketFact(fact.binding, fact, proof, f.db)).rejects.toMatchObject({ status: 403 });
    await expect(f.policy().verifySource(fact.binding.sourceId, 'outcome', f.db)).rejects.toMatchObject({ status: 403 });
  });

  it.each(['active-source', 'foreign-actor', 'different-key', 'wrong-revision', 'missing-original-session', 'changed-epoch',
    'zero-attempts', 'multiple-attempts', 'any-transport-event', 'completed-result', 'stored-result', 'different-sqlstate',
    'succeeded-mutation', 'different-native-id', 'changed-body-hmac', 'changed-before-hmac', 'write-revoked',
    'different-packet-operation-key', 'different-attempt-binding', 'unknown-state-with-transport-event'])
  ('refuses %s without appending a fact, updating a mutation or sending native traffic', async condition => {
    const f = fixture();
    if (condition === 'active-source') f.source.expired = false;
    if (condition === 'foreign-actor') f.source.execution_actor_id = randomUUID();
    if (condition === 'different-key') f.source.idempotency_key = 'another-execution-request-key';
    if (condition === 'wrong-revision') f.source.revision++;
    if (condition === 'missing-original-session') f.source.session_id = null;
    if (condition === 'changed-epoch') f.state.epoch = '2';
    if (condition === 'zero-attempts') f.state.attempts = [];
    if (condition === 'multiple-attempts') f.state.attempts.push({ ...f.attempt, id: randomUUID() });
    if (condition === 'any-transport-event') f.state.eventCount = 1;
    if (condition === 'completed-result') f.mutation.remote_completed = true;
    if (condition === 'stored-result') f.mutation.result_secret = 'untrusted-recorded-response';
    if (condition === 'different-sqlstate') f.mutation.error_code = 'ETIMEDOUT';
    if (condition === 'succeeded-mutation') f.mutation.state = 'succeeded';
    if (condition === 'different-native-id') f.mutation.entity_id = randomUUID();
    if (condition === 'changed-body-hmac') f.attempt.body_hmac = '0'.repeat(64);
    if (condition === 'changed-before-hmac') f.attempt.before_hmac = '0'.repeat(64);
    if (condition === 'write-revoked') f.state.canWrite = false;
    if (condition === 'different-packet-operation-key') f.mutation.idempotency_key = 'substituted-packet-operation-key';
    if (condition === 'different-attempt-binding') f.mutation.entity_change_attempt_id = randomUUID();
    if (condition === 'unknown-state-with-transport-event') {
      f.source.state = f.source.workflow_state = 'uncertain'; f.state.eventCount = 2;
    }
    await expect(f.run()).rejects.toMatchObject({ status: expect.any(Number) });
    expect(f.facts.appendOutcome).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled();
    expect(f.db.exec.mock.calls.every(([sql]: any[]) => !sql.startsWith('UPDATE'))).toBe(true);
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.writer.execute).not.toHaveBeenCalled();
  });
});
