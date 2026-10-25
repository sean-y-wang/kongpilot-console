import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { businessStepVerificationFixture } from './helpers/m11-business-step-verification-fixture';
import { normalizedHintSql, STEP_KIND_HINT_SQL } from './helpers/m11-scheduled-step-kind-hint-sql';
import { configurationApprovedFixture } from '../security/m8-configuration-approved-fixture';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ce'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
type Fixture = ReturnType<typeof businessStepVerificationFixture>;
const denied = (code: string) => ({ response: { code } });
const first = (f: Fixture) => { f.rows[0].state = 'running'; return f.rows[0].id; };
const verify = (f: Fixture, id = f.rows[0].id) => f.verifier.verifyStep(f.proof(), id);
function dependency(f: Fixture) {
  const op = f.operation(2); Object.assign(op, { state: 'succeeded', remote_started: true, remote_completed: true });
  Object.assign(f.rows[2], { state: 'succeeded', operation_id: op.id }); f.rows[3].state = 'running'; return op;
}

/** Actual Context-minted capabilities and complete Approved AEAD/normalized
 * plan loading are retained. SQL/grants/GET adapters are controlled Source
 * facts, not PostgreSQL, authentication, Native sends or runtime acceptance. */
describe('scheduled V2 kind hints do not establish step authority', () => {
  it.each(['portal-credential-issue', 'configuration_v2'] as const)('pins the complete association before the actual %s final verifier', async kind => {
    const f = businessStepVerificationFixture(kind), id = first(f);
    await f.run(async () => {
      const load = vi.spyOn(f.verifier as any, 'load'), trusted = vi.spyOn(f.verifier as any, 'trusted');
      f.state.validationRoles.length = 0;
      const proof = await verify(f, id);
      expect(proof).toMatchObject({ execution: f.proof(), stepId: id, kind: kind === 'configuration_v2' ? 'metadata' : 'native' });
      expect(load).toHaveBeenCalledExactlyOnceWith(f.eid, f.db, false, 'execution', f.proof());
      expect(trusted).toHaveBeenCalledExactlyOnceWith(f.proof(), f.db, false, 'step', proof);
      expect(trusted.mock.calls[0][4]).toBe(proof); expect(proof.execution).toBe(f.proof());
      expect(f.state.hintReads).toHaveLength(1);
      expect(normalizedHintSql(f.state.hintReads[0].sql)).toBe(normalizedHintSql(STEP_KIND_HINT_SQL));
      expect(f.state.hintReads[0].args).toEqual([f.eid, f.wf, f.cid, f.wid, id]);
      if (kind === 'portal-credential-issue') for (const reviewer of f.reviewers)
        expect(f.state.validationRoles.some((r: any) => r.role === 'reviewer' && r.userId === reviewer)).toBe(true);
    });
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.kong.request.mock.calls.every(c => c[1] === 'GET')).toBe(true);
  });

  it('returns the actual Portal activation metadata kind only after its original successful dependency', async () => {
    const f = businessStepVerificationFixture(); dependency(f);
    await f.run(async () => {
      const proof = await verify(f, f.rows[3].id); expect(proof.kind).toBe('metadata');
      await expect(f.verifier.mutationBinding(proof, f.nativeContext())).rejects.toMatchObject(denied('APPROVED_NATIVE_STEP_REQUIRED'));
    }); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['step-workflow', 'step-cluster', 'step-workspace', 'step-revision', 'step-hash', 'step-id',
    'execution-workflow', 'execution-cluster', 'execution-workspace'] as const)('rejects the controlled SQL association mismatch %s', async reason => {
    const f = businessStepVerificationFixture(), id = first(f);
    await f.run(async () => {
      const load = vi.spyOn(f.verifier as any, 'load');
      if (reason === 'step-workflow') f.rows[0].workflow_id = randomUUID();
      if (reason === 'step-cluster') f.rows[0].cluster_id = randomUUID();
      if (reason === 'step-workspace') f.rows[0].workspace_id = randomUUID();
      if (reason === 'step-revision') f.rows[0].plan_revision++;
      if (reason === 'step-hash') f.rows[0].plan_hash = '0'.repeat(64);
      if (reason === 'step-id') f.rows[0].id = randomUUID();
      if (reason === 'execution-workflow') f.e.workflow_id = randomUUID();
      if (reason === 'execution-cluster') f.e.cluster_id = randomUUID();
      if (reason === 'execution-workspace') f.e.workspace_id = randomUUID();
      await expect(verify(f, id)).rejects.toMatchObject(denied('APPROVED_STEP_REQUIRED'));
      expect(load).not.toHaveBeenCalled();
    }); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['missing', 'null-kind', 'foreign-kind', 'false-native-hint', 'false-metadata-hint'] as const)('cannot adopt a %s hint as an authenticated plan', async reason => {
    const f = businessStepVerificationFixture(), id = first(f);
    if (reason === 'false-native-hint') { dependency(f); }
    await f.run(async () => {
      f.state.hintOverrideEnabled = true;
      f.state.hintOverride = reason === 'missing' ? null : { kind: reason === 'null-kind' ? null : reason === 'foreign-kind' ? 'arbitrary' : reason === 'false-native-hint' ? 'native' : 'metadata' };
      const stepId = reason === 'false-native-hint' ? f.rows[3].id : id;
      await expect(verify(f, stepId)).rejects.toBeDefined();
      expect(f.db.exec).not.toHaveBeenCalled();
    });
  });

  it.each(['invalid', '', '00000000-0000-0000-0000-000000000000'])('refuses invalid step UUID %j before hint SQL', async id => {
    const f = businessStepVerificationFixture(); first(f);
    await f.run(async () => {
      const calls = f.db.one.mock.calls.length;
      await expect(verify(f, id)).rejects.toMatchObject(denied('APPROVED_STEP_REQUIRED'));
      expect(f.db.one).toHaveBeenCalledTimes(calls);
    });
  });

  it.each(['workflow', 'execution', 'running-step', 'normalized-kind', 'AEAD', 'snapshot', 'executor-epoch', 'permission-version', 'developer-epoch',
    'cluster', 'transport', 'service-tags', 'lease', 'deadline'] as const)('keeps the final full verifier fresh after the hint for %s', async reason => {
    const f = businessStepVerificationFixture(), id = first(f);
    const execution = f.run(async () => {
      f.state.afterKindHint = async () => {
        if (reason === 'workflow') f.w.state = 'cancelled';
        if (reason === 'execution') f.e.state = 'uncertain';
        if (reason === 'running-step') f.rows[0].state = 'succeeded';
        if (reason === 'normalized-kind') f.rows[0].kind = 'metadata';
        if (reason === 'AEAD') f.version.payload_secret = 'changed-ciphertext';
        if (reason === 'snapshot') f.e.snapshot_hash = '0'.repeat(64);
        if (reason === 'executor-epoch') f.state.executorEpoch = '2';
        if (reason === 'permission-version') f.state.epoch = 'epoch-2';
        if (reason === 'developer-epoch') f.state.requesterEpoch = '2';
        if (reason === 'cluster') f.cluster.status = 'disabled';
        if (reason === 'transport') f.cluster.transport_scope = '0'.repeat(64);
        if (reason === 'service-tags') f.state.service.tags = ['team-foreign'];
        if (reason === 'lease') f.state.live = false;
        if (reason === 'deadline') vi.spyOn(Date, 'now').mockReturnValue(Date.parse(f.ns.expiresAt) + 1);
      };
      let published = false;
      await expect(verify(f, id).then(proof => { published = true; return proof; })).rejects.toBeDefined();
      expect(published).toBe(false); expect(f.db.exec).not.toHaveBeenCalled();
    });
    if (reason === 'deadline') await expect(execution).rejects.toMatchObject(denied('KONG_EXECUTION_CONTEXT_EXPIRED'));
    else await execution;
  });

  it.each([0, 1, 2])('rechecks current reviewer %s after the advisory hint', async index => {
    const f = businessStepVerificationFixture(); first(f);
    await f.run(async () => {
      f.state.afterKindHint = async () => { f.state.reviewerRevoked = f.reviewers[index]; };
      await expect(verify(f)).rejects.toMatchObject(denied('APPROVED_APPROVER_REVOKED'));
    }); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each([0, 1, 2])('observes natural current SQL grant expiry of reviewer %s without changing permission epoch', async index => {
    const f = businessStepVerificationFixture(); first(f);
    await f.run(async () => {
      const query = f.db.query.getMockImplementation()!, expires = Date.now() + 1000;
      f.db.query.mockImplementation(async (sql: string, args: any[]) => {
        if (sql.includes('FROM iam_effective_grants') && args[0] === f.reviewers[index] && Date.now() >= expires) return [];
        return query(sql, args);
      });
      f.state.afterKindHint = async () => { vi.spyOn(Date, 'now').mockReturnValue(expires + 1); };
      await expect(verify(f)).rejects.toMatchObject(denied('APPROVED_APPROVER_REVOKED'));
      expect(f.state.epoch).toBe('epoch-1');
    }); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['disabled', 'deleted', 'password-change'] as const)('rejects developer %s facts changed after hint', async reason => {
    const f = businessStepVerificationFixture(); first(f);
    await f.run(async () => {
      const one = f.db.one.getMockImplementation()!; let changed = false;
      f.db.one.mockImplementation(async (sql: string, args: any[]) => {
        const value = await one(sql, args);
        if (changed && sql.includes('FROM portal_developers')) return value && { ...value,
          status: reason === 'disabled' ? 'disabled' : value.status, deleted_at: reason === 'deleted' ? new Date().toISOString() : null,
          must_change_password: reason === 'password-change' };
        return value;
      });
      f.state.afterKindHint = async () => { changed = true; };
      await expect(verify(f)).rejects.toBeDefined();
    }); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['missing', 'pending', 'remote-incomplete', 'wrong-execution', 'wrong-step', 'wrong-hash'] as const)('does not replace original dependency receipt checks for %s', async reason => {
    const f = businessStepVerificationFixture(), op = dependency(f);
    await f.run(async () => {
      f.state.afterKindHint = async () => {
        if (reason === 'missing') f.state.operations.delete(op.id);
        if (reason === 'pending') op.state = 'pending';
        if (reason === 'remote-incomplete') op.remote_completed = false;
        if (reason === 'wrong-execution') op.workflow_execution_id = randomUUID();
        if (reason === 'wrong-step') op.workflow_step_id = randomUUID();
        if (reason === 'wrong-hash') op.workflow_plan_hash = '0'.repeat(64);
      };
      await expect(verify(f, f.rows[3].id)).rejects.toMatchObject(denied('APPROVED_DEPENDENCY_UNACKNOWLEDGED'));
    }); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('does not mint from a copied, foreign or genuinely closed execution capability', async () => {
    const f = businessStepVerificationFixture(), other = businessStepVerificationFixture(); first(f); let original: any;
    await f.run(async () => {
      original = f.proof();
      await expect(f.verifier.verifyStep({ ...original }, f.rows[0].id)).rejects.toBeDefined();
      await expect(other.verifier.verifyStep(original, f.rows[0].id)).rejects.toBeDefined();
      expect(f.state.hintReads).toBeUndefined(); expect(other.db.one).not.toHaveBeenCalled();
    });
    await expect(f.verifier.verifyStep(original, f.rows[0].id)).rejects.toBeDefined();
  });

  it('does not resume hint work after the actual Approved callback has closed', async () => {
    const f = businessStepVerificationFixture(); first(f); let enter!: () => void, release!: () => void, pending!: Promise<unknown>;
    const started = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
    await f.run(async () => {
      f.state.afterKindHint = async () => { enter(); await gate; };
      pending = verify(f); await started;
    });
    const reads = f.db.one.mock.calls.length; release(); await expect(pending).rejects.toBeDefined();
    expect(f.db.one).toHaveBeenCalledTimes(reads); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each([1, 2] as const)('keeps the HTTP format %s original trusted checks without a hint', async format => {
    const f = businessStepVerificationFixture('configuration_v2'), id = first(f);
    delete f.plan.scheduling; f.resealFixture();
    if (format === 1) for (const row of [f.w, f.e, f.version]) Object.assign(row, { approval_format: 1, approval_set_id: null, approval_set_hmac: null });
    await f.context.runHttp({}, () => {
      f.context.bindHttpActor(f.actor, f.sid);
      return f.context.runActor({ actor: f.actor, clusterId: f.cid, workspaceId: f.wid }, () => f.verifier.runApprovedExecution(f.eid, async () => {
        const trusted = vi.spyOn(f.verifier as any, 'trusted'), load = vi.spyOn(f.verifier as any, 'load');
        await f.context.runApprovedStep(id, async () => { expect(f.context.currentApprovedStep().kind).toBe('metadata'); });
        expect(trusted).toHaveBeenCalledTimes(2); expect(load).toHaveBeenCalledTimes(2); expect(f.state.hintReads).toBeUndefined();
      }));
    });
  });

  it('keeps a genuine nested configuration step on its unchanged verifier branch', async () => {
    const f = await configurationApprovedFixture();
    await f.run(() => f.verifier.runConfigurationExecution(f.executionId, () => f.context.runApprovedStep(f.jobStepId, async () => {
      expect(f.context.currentApprovedStep().kind).toBe('native');
      expect(f.db.one.mock.calls.some((call: any[]) => call[0].trimStart().startsWith('SELECT s.kind FROM workflow_steps s'))).toBe(false);
    })));
  });
});
