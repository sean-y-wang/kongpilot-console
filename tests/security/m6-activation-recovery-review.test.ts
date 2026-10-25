import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ServiceUnavailableException } from '@nestjs/common';
import { portalKeyAad } from '../../apps/console-api/src/modules/portal/portal-proof';
import { actor, cid, eid, id, physical, wid, wf } from './m6-approved-fixture';
import { activationRecoveryFixture } from './m6-activation-recovery-fixture';

beforeEach(() => { vi.stubEnv('APP_SECRET', 'offline-recovery-signing-secret-at-least32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'bd'.repeat(32)); });
afterEach(() => { vi.unstubAllEnvs(); vi.useRealTimers(); });
type Fixture = ReturnType<typeof activationRecoveryFixture>;
const deny = (promise: Promise<unknown>, code?: string) => code
  ? expect(promise).rejects.toMatchObject({ response: { code } }) : expect(promise).rejects.toBeDefined();
const run = <T>(f: Fixture, fn: () => Promise<T>) => f.http(() => f.verifier.runIssueActivationRecovery(eid, f.originalKey, f.workflow.revision, f.workflow.plan_hash, fn));

describe('M6 independent actual sealed activation recovery verifier', () => {
  it('admits only original metadata recovery and seals an exact transaction check without opening native capabilities', async () => {
    const f = activationRecoveryFixture(), originalCiphertext = f.credential.key_secret;
    const operations = structuredClone([...f.operations.values()]), rows = structuredClone(f.rows.slice(0, 3));
    await run(f, async () => {
      const proof = await f.context.currentIssueActivationRecovery();
      expect(proof).toMatchObject({ executionId: eid, workflowId: wf, actorId: actor.id, sessionId: f.sessionId,
        clusterId: cid, workspaceId: wid, transportScope: physical, stepId: f.last.id });
      await f.verifier.assertIssueActivationRecovery(f.input(), f.tx, 'before');
      await deny(f.context.approvedMutationBinding(f.mutationContext()), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
      await deny(f.context.runApprovedStep(f.plan.steps[0].id, async () => undefined), 'PORTAL_RECOVERY_NATIVE_FORBIDDEN');
    });
    expect(f.credential.key_secret).toBe(originalCiphertext); expect([...f.operations.values()]).toEqual(operations); expect(f.rows.slice(0, 3)).toEqual(rows);
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
  });

  it('does not relax the original executing-only approved workflow loader', async () => {
    const f = activationRecoveryFixture(), callback = vi.fn();
    await deny(f.http(() => f.verifier.runApprovedExecution(eid, callback)), 'APPROVED_EXECUTION_NOT_READY');
    await deny(f.http(() => f.context.runIssueActivationRecovery({ executionId: eid } as any, callback)), 'PORTAL_RECOVERY_REQUIRED');
    expect(callback).not.toHaveBeenCalled();
  });

  it.each([
    ['wrong key', 'other-explicit-key', 4, undefined],
    ['wrong revision', undefined, 3, undefined],
    ['wrong plan hash', undefined, 4, '0'.repeat(64)],
  ])('rejects %s before producing a recovery callback', async (_label, key, revision, hash) => {
    const f = activationRecoveryFixture(), callback = vi.fn();
    await deny(f.http(() => f.verifier.runIssueActivationRecovery(eid, key ?? f.originalKey, revision, hash ?? f.workflow.plan_hash, callback)), 'PORTAL_RECOVERY_REQUEST_MISMATCH');
    expect(callback).not.toHaveBeenCalled();
  });

  it.each([
    ['missing step', (f: Fixture) => { f.rows.pop(); }],
    ['missing successful operation', (f: Fixture) => { f.operations.delete(f.rows[0].operation_id); }],
    ['unknown operation', (f: Fixture) => { f.operations.get(f.rows[2].operation_id).state = 'uncertain'; }],
    ['missing native ACK', (f: Fixture) => { f.operations.get(f.rows[1].operation_id).remote_completed = false; }],
    ['unstarted native operation', (f: Fixture) => { f.operations.get(f.rows[1].operation_id).remote_started = false; }],
    ['substituted typed parent', (f: Fixture) => { f.operations.get(f.rows[1].operation_id).parent_id = id(777); }],
    ['wrong credential kind', (f: Fixture) => { f.operations.get(f.rows[1].operation_id).credential_kind = 'key-auth'; }],
    ['foreign operation execution', (f: Fixture) => { f.operations.get(f.rows[0].operation_id).workflow_execution_id = id(777); }],
    ['changed logical original-create hash', (f: Fixture) => { f.operations.get(f.rows[0].operation_id).request_hash = '0'.repeat(64); }],
    ['display-only result', (f: Fixture) => { const op = f.operations.get(f.rows[2].operation_id); op.result_secret = f.secrets.encrypt({ entity: { id: f.credential.kong_id, key: '[REDACTED]' } }, `mutation:${op.id}:result`); }],
    ['wrong raw after fingerprint', (f: Fixture) => { f.rows[0].after_fingerprint = '0'.repeat(64); }],
    ['missing after fingerprint', (f: Fixture) => { f.rows[0].after_fingerprint = null; }],
    ['final metadata already succeeded', (f: Fixture) => { f.rows[3].state = 'succeeded'; }],
    ['final metadata still running', (f: Fixture) => { f.rows[3].state = 'running'; }],
    ['metadata unexpectedly bound to native op', (f: Fixture) => { f.rows[3].operation_id = f.rows[0].operation_id; }],
    ['metadata success facts already present', (f: Fixture) => { f.rows[3].safe_result = { state: 'active' }; }],
    ['already changed generation', (f: Fixture) => { f.grant.current_generation = 1; }],
    ['released reservation', (f: Fixture) => { f.grant.reservation_released_at = new Date(); }],
    ['inactive credential reference', (f: Fixture) => { f.refs[1].state = 'deleted'; }],
    ['another physical scope', (f: Fixture) => { f.cluster.transport_scope = '0'.repeat(64); }],
    ['changed workspace revision', (f: Fixture) => { f.workspace.revision++; }],
  ])('fails closed on %s and never dispatches a packet or metadata callback', async (_label, change) => {
    const f = activationRecoveryFixture(), callback = vi.fn(); change(f);
    await deny(run(f, callback)); expect(callback).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
    expect(f.kong.request.mock.calls.every(call => call[1] === 'GET')).toBe(true);
  });

  it('binds actor and active current session and rechecks revoked approver and permissions after proof mint', async () => {
    const f = activationRecoveryFixture(), callback = vi.fn();
    await deny(f.http(() => f.verifier.runIssueActivationRecovery(eid, f.originalKey, 4, f.workflow.plan_hash, callback), { ...actor, id: id(777) }), 'PORTAL_RECOVERY_SESSION_INVALID');
    await deny(f.http(() => f.verifier.runIssueActivationRecovery(eid, f.originalKey, 4, f.workflow.plan_hash, callback), actor, ''), 'PORTAL_RECOVERY_SESSION_INVALID');
    expect(callback).not.toHaveBeenCalled();
    await run(f, async () => { f.grants.length = 0; await deny(f.verifier.assertIssueActivationRecovery(f.input(), f.tx, 'before'), 'APPROVED_APPROVER_REVOKED'); });
    const g = activationRecoveryFixture();
    await run(g, async () => { g.setVersion('epoch-2'); await deny(g.verifier.assertIssueActivationRecovery(g.input(), g.tx, 'before'), 'APPROVED_EXECUTOR_CHANGED'); });
  });

  it('requires a supplied transaction and refuses another target, handler, payload, before or revision', async () => {
    const f = activationRecoveryFixture();
    await run(f, async () => {
      await deny(f.verifier.assertIssueActivationRecovery(f.input(), f.db, 'before'), 'PORTAL_RECOVERY_REQUIRED');
      for (const change of [{ handler: 'portal.credential.rotate' }, { entityId: id(777) }, { clusterId: id(777) }, { workspaceId: id(777) },
        { payload: { ...f.last.metadata as any, kongId: id(777) } }, { before: { ...f.grant, state: 'active' } }, { revision: 2 }]) {
        await deny(f.verifier.assertIssueActivationRecovery({ ...f.input(), ...change }, f.tx, 'before'), 'PORTAL_RECOVERY_REQUEST_MISMATCH');
      }
    });
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each([
    ['revoked session', (f: Fixture) => { f.session.revoked_at = new Date(); }],
    ['expired session', (f: Fixture) => { f.session.expires_at = new Date(Date.now() - 1); }],
    ['password epoch changed', (f: Fixture) => { f.session.credential_epoch++; }],
    ['disabled current user', (f: Fixture) => { f.session.status = 'disabled'; }],
    ['forced password change', (f: Fixture) => { f.session.force_password_change = true; }],
  ])('revalidates %s after authority was minted and before commit proof', async (_label, change) => {
    const f = activationRecoveryFixture();
    await run(f, async () => { change(f); await deny(f.verifier.assertIssueActivationRecovery(f.input(), f.tx, 'before'), 'PORTAL_RECOVERY_SESSION_INVALID'); });
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('allows only exact active metadata after-state, with the same original ciphertext and native receipts', async () => {
    const f = activationRecoveryFixture(), original = f.credential.key_secret, input = f.input();
    await run(f, async () => {
      await f.verifier.assertIssueActivationRecovery(input, f.tx, 'before');
      Object.assign(f.grant, { state: 'active', current_generation: 1, current_credential_id: f.credential.id,
        acl_credential_ref_id: f.refs[0].id, revision: 2, updated_at: new Date() });
      Object.assign(f.credential, { state: 'active', credential_ref_id: f.refs[1].id, issue_operation_id: f.rows[2].operation_id, revision: 2 });
      await f.verifier.assertIssueActivationRecovery(input, f.tx, 'after');
      f.credential.key_secret = f.secrets.encrypt({ key: f.key }, portalKeyAad(cid, wid, f.credential.id, 1));
      await deny(f.verifier.assertIssueActivationRecovery(input, f.tx, 'after'), 'PORTAL_RECOVERY_STATE_CHANGED');
      f.credential.key_secret = original; f.credential.issue_operation_id = f.rows[1].operation_id;
      await deny(f.verifier.assertIssueActivationRecovery(input, f.tx, 'after'), 'PORTAL_RECOVERY_STATE_CHANGED');
    });
    expect(f.rows.slice(0, 3).every(row => row.state === 'succeeded')).toBe(true); expect(f.workflow.state).toBe('uncertain');
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('closed callbacks and lost locks cannot reuse a metadata recovery authority', async () => {
    const f = activationRecoveryFixture(); let resume!: () => void, late!: Promise<unknown>;
    const gate = new Promise<void>(resolve => { resume = resolve; });
    await run(f, async () => { late = gate.then(() => f.verifier.assertIssueActivationRecovery(f.input(), f.tx, 'before')).catch(error => error); });
    resume(); expect(await late).toMatchObject({ response: { code: 'PORTAL_RECOVERY_REQUIRED' } });
    const g = activationRecoveryFixture();
    await run(g, async () => { g.redis.assertLeaseOwnership.mockRejectedValue(new ServiceUnavailableException({ code: 'LOCK_LOST' }));
      await deny(g.verifier.assertIssueActivationRecovery(g.input(), g.tx, 'before'), 'LOCK_LOST'); });
  });
});
