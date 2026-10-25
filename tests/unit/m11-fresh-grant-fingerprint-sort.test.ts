import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { sortByFreshFingerprint } from '../../apps/console-api/src/modules/workflows/workflow-fresh-fingerprint-sort';
import { WorkflowScheduledValidationReadService, WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-validation-read.service';
import { WorkflowBusinessMaterialService } from '../../apps/console-api/src/modules/workflows/workflow-business-material.service';

const legacy = <T>(rows: readonly T[], fingerprint: (row: T) => string) => [...rows].sort((a, b) => fingerprint(a).localeCompare(fingerprint(b)));
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe('fresh decorate-sort-undecorate preserves the exact former grant ordering', () => {
  it.each([0, 1, 2, 8, 32, 100, 1000])('uses the original SecretService ordering with exactly one call per row for %i rows', count => {
    const secrets = new SecretService(), rows = Array.from({ length: count }, (_, index) => ({ id: index, user_id: 'source-user',
      module: index % 2 ? 'services' : 'routes', action: index % 3 ? 'read' : 'write', nested: { tags: [`team:${index}`], enabled: true } }));
    const before = structuredClone(rows), expected = legacy(rows, row => secrets.fingerprint(row)), fingerprint = vi.fn(row => secrets.fingerprint(row));
    const result = sortByFreshFingerprint(rows, fingerprint);
    expect(result).toEqual(expected); expect(result).not.toBe(rows); expect(rows).toEqual(before); expect(fingerprint).toHaveBeenCalledTimes(count);
    for (const row of rows) expect(fingerprint.mock.calls.filter(([value]) => value === row)).toHaveLength(1);
    result.forEach((row, index) => expect(row).toBe(expected[index]));
  });

  it('keeps the original order of equal actual canonical HMACs and equal comparator keys', () => {
    const secrets = new SecretService(), a = { module: 'services', action: 'read' }, b = { action: 'read', module: 'services' };
    expect(secrets.fingerprint(a)).toBe(secrets.fingerprint(b));
    const rows = Object.freeze([a, b, a]), fingerprint = vi.fn(row => secrets.fingerprint(row));
    const result = sortByFreshFingerprint(rows, fingerprint);
    result.forEach((row, index) => expect(row).toBe(rows[index])); expect(fingerprint).toHaveBeenCalledTimes(3);
    const tied = [{ index: 3 }, { index: 1 }, { index: 2 }];
    expect(sortByFreshFingerprint(tied, () => 'same-key')).toEqual(tied);
  });

  it('preserves localeCompare semantics rather than switching to a different lexical comparator', () => {
    const rows = ['b', 'B', 'a', 'A', '2', '10', 'ä', 'a'];
    expect(sortByFreshFingerprint(rows, value => value)).toEqual(legacy(rows, value => value));
  });

  it('never mutates a frozen source collection or exposes decorated hashes', () => {
    const rows = Object.freeze([Object.freeze({ n: 3 }), Object.freeze({ n: 1 }), Object.freeze({ n: 2 })]);
    const result = sortByFreshFingerprint(rows, row => String(row.n));
    expect(result).toEqual([{ n: 1 }, { n: 2 }, { n: 3 }]); expect(rows.map(row => row.n)).toEqual([3, 1, 2]);
    expect(result.every(row => !Object.hasOwn(row, 'key') && rows.includes(row))).toBe(true);
  });

  it('rehashes every occurrence on every fresh read, including the same object and a changed grant', () => {
    const secrets = new SecretService(), row = { module: 'services', action: 'read' }, fingerprint = vi.fn(value => secrets.fingerprint(value));
    sortByFreshFingerprint([row, row], fingerprint); expect(fingerprint).toHaveBeenCalledTimes(2);
    const before = secrets.fingerprint(row); row.action = 'write';
    sortByFreshFingerprint([row, row], fingerprint); expect(fingerprint).toHaveBeenCalledTimes(4);
    expect(secrets.fingerprint(row)).not.toBe(before);
  });

  it('propagates a current fingerprint failure without returning a partial result or changing input', () => {
    const rows = [{ n: 3 }, { n: 2 }, { n: 1 }], failure = new Error('SOURCE_FINGERPRINT_UNAVAILABLE');
    expect(() => sortByFreshFingerprint(rows, row => { if (row.n === 2) throw failure; return String(row.n); })).toThrow(failure);
    expect(rows.map(row => row.n)).toEqual([3, 2, 1]);
  });

  it('reduces repeated hashing only, while computing the exact old result', () => {
    const secrets = new SecretService(), rows = Array.from({ length: 64 }, (_, n) => ({ module: 'services', action: 'read', id: n }));
    const oldHash = vi.fn(value => secrets.fingerprint(value)), newHash = vi.fn(value => secrets.fingerprint(value));
    expect(sortByFreshFingerprint(rows, newHash)).toEqual(legacy(rows, oldHash)); expect(newHash).toHaveBeenCalledTimes(rows.length);
    expect(oldHash.mock.calls.length).toBeGreaterThan(rows.length * 2);
  });
});

function principalFixture() {
  const secrets = new SecretService(), actor = randomUUID(), cid = randomUUID(), wid = randomUUID();
  const user = { id: actor, username: 'source-executor', status: 'active', deleted_at: null, force_password_change: false,
    credential_epoch: '1', permissions_epoch: '2', super_admin: false, display_name: 'Source', locale: 'zh-CN', timezone: 'UTC', revision: 3 };
  const grants = Array.from({ length: 12 }, (_, n) => ({ id: randomUUID(), user_id: actor, module: n % 2 ? 'services' : 'routes',
    action: n % 3 ? 'read' : 'write', cluster_id: null, workspace_id: null, scope_type: 'global', scope_values: [] }));
  const state = { epoch: '4', rows: grants as any[], latestRows: [] as any[] };
  const db: any = { one: vi.fn(async (sql: string) => {
      if (sql === WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL) { state.latestRows = structuredClone(state.rows); return { ...user, iam_version: state.epoch, grants: state.latestRows }; }
      if (sql === 'SELECT version FROM iam_epoch WHERE singleton=true') return { version: state.epoch };
      if (sql === 'SELECT * FROM users WHERE id=$1') return { ...user };
      throw new Error('UNEXPECTED_FRESH_GRANT_SOURCE_SQL');
    }), query: vi.fn(async (sql: string) => { if (sql !== 'SELECT * FROM iam_effective_grants WHERE user_id=$1') throw new Error('UNEXPECTED_FRESH_GRANT_SOURCE_LIST'); state.latestRows = structuredClone(state.rows); return state.latestRows; }) };
  const validation = new WorkflowScheduledValidationReadService(db, secrets, {} as any, {} as any, {} as any, {} as any);
  const material = new WorkflowBusinessMaterialService(db, secrets);
  const expiresAt = new Date(Date.now() + 120000).toISOString(), workflowId = randomUUID(), subjectId = randomUUID();
  const plan: any = { kind: 'configuration_v2', subject: { type: 'configuration_jobs', id: subjectId }, clusterId: cid, workspaceId: wid,
    workflowId, planRevision: 2, requester: { type: 'console', id: actor }, scheduling: { version: 1 }, expiresAt };
  const draft: any = { binding: { kind: plan.kind, subjectType: plan.subject.type, subjectId, clusterId: cid, workspaceId: wid,
    workflowId, workflowPlanRevision: 2, workflowPlanHash: secrets.fingerprint(plan), requester: plan.requester },
    spec: { windowEnd: expiresAt }, delegation: { ownerId: actor, executorId: actor } };
  const input: any = { plan, draft, role: 'executor', transaction: db, principal: { user: { id: actor, superAdmin: false },
    credentialEpoch: '1', permissionVersion: `${actor}:2:4`, grants: structuredClone(grants) } };
  return { secrets, actor, user, state, db, validation, material, plan, draft, input };
}
function expectHashedOnce(spy: any, rows: any[]) { for (const row of rows) expect(spy.mock.calls.filter(([value]: any[]) => value === row)).toHaveLength(1); }

describe('the actual four Source call sites hash fresh grant rows once without caching SQL authority', () => {
  it('ValidationRead.principal rereads epochs and grants on each invocation and filters invalid rows before hashing', async () => {
    const f = principalFixture(), spy = vi.spyOn(f.secrets, 'fingerprint');
    f.state.rows.push({ ...f.state.rows[0], action: 'unsupported' });
    const first = await (f.validation as any).principal(f.actor, f.db), rows = f.state.latestRows;
    expectHashedOnce(spy, rows.slice(0, -1)); expect(spy.mock.calls.some(([value]) => value === rows.at(-1))).toBe(false);
    expect(first.grants).toHaveLength(12); expect(Object.isFrozen(first.grants)).toBe(true);
    spy.mockClear(); f.state.epoch = '5'; f.state.rows[0].action = 'approve';
    const next = await (f.validation as any).principal(f.actor, f.db);
    expect(next.permissionVersion).toBe(`${f.actor}:2:5`); expect(next.grants).not.toEqual(first.grants);
    expectHashedOnce(spy, f.state.latestRows.slice(0, -1)); expect(f.db.query).not.toHaveBeenCalled();
    expect(f.db.one).toHaveBeenCalledTimes(2);
    expect(f.db.one.mock.calls.every(([sql,args]: any[]) => sql === WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL && args.length === 1 && args[0] === f.actor)).toBe(true);
  });

  it('BusinessMaterial.currentReadInput constructs the same fresh principal with one hash per valid SQL row', async () => {
    const f = principalFixture(), check = vi.spyOn(f.material, 'assertCurrent').mockResolvedValue(undefined), spy = vi.spyOn(f.secrets, 'fingerprint');
    // Subject/material validation is explicitly controlled in this construction
    // test; the related unchanged suites exercise those complete original gates.
    const first = await f.material.currentReadInput(f.plan, f.draft, f.actor, 'executor', f.db);
    expectHashedOnce(spy, f.state.latestRows); expect(first.transaction).toBe(f.db); expect(check).toHaveBeenCalledExactlyOnceWith(first);
    spy.mockClear(); f.state.rows[0].action = 'approve';
    const next = await f.material.currentReadInput(f.plan, f.draft, f.actor, 'executor', f.db);
    expectHashedOnce(spy, f.state.latestRows); expect(next.principal.grants).not.toEqual(first.principal.grants); expect(f.db.query).toHaveBeenCalledTimes(2);
  });

  it('assertStoredCurrent compares every fresh SQL grant and retained principal grant after one hash each', async () => {
    const f = principalFixture(), sentinel = new Error('SOURCE_STOP_AFTER_COMPLETE_GRANT_EQUALITY');
    const retainedOrder = f.input.principal.grants.map((row: any) => row.id);
    const read = vi.spyOn(f.material, 'materialForPlan').mockRejectedValue(sentinel), spy = vi.spyOn(f.secrets, 'fingerprint');
    f.state.rows.reverse();
    await expect((f.material as any).assertStoredCurrent(f.input, false)).rejects.toBe(sentinel);
    expectHashedOnce(spy, f.state.latestRows); expectHashedOnce(spy, f.input.principal.grants); expect(read).toHaveBeenCalledTimes(1);
    spy.mockClear(); f.state.rows.reverse();
    await expect((f.material as any).assertStoredCurrent(f.input, false)).rejects.toBe(sentinel);
    expectHashedOnce(spy, f.state.latestRows); expectHashedOnce(spy, f.input.principal.grants); expect(f.db.query).toHaveBeenCalledTimes(2);
    expect(f.input.principal.grants.map((row: any) => row.id)).toEqual(retainedOrder);
  });

  it('rejects a changed current grant before inspecting material, without borrowing a prior sorted result', async () => {
    const f = principalFixture(), sentinel = new Error('SOURCE_STOP_AFTER_COMPLETE_GRANT_EQUALITY');
    const read = vi.spyOn(f.material, 'materialForPlan').mockRejectedValue(sentinel), spy = vi.spyOn(f.secrets, 'fingerprint');
    await expect((f.material as any).assertStoredCurrent(f.input, false)).rejects.toBe(sentinel); read.mockClear(); spy.mockClear();
    f.state.rows[0].action = 'approve';
    await expect((f.material as any).assertStoredCurrent(f.input, false)).rejects.toMatchObject({ response: { code: 'WORKFLOW_BUSINESS_MATERIAL_CHANGED' } });
    expectHashedOnce(spy, f.state.latestRows); expectHashedOnce(spy, f.input.principal.grants); expect(read).not.toHaveBeenCalled();
  });
});
