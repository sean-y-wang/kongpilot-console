import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { WorkflowScheduleCandidateReadService } from '../../apps/console-api/src/modules/workflows/workflow-schedule-candidate-read.service';
import { validGrant } from '../../apps/console-api/src/modules/authorization/grant-policy';
import { candidateAbsenceFixture } from './helpers/workflow-scheduled-read-absence-fixture';

const userSql = `SELECT id,username,super_admin,credential_epoch,permissions_epoch,force_password_change,display_name,locale,timezone,revision
      FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change`;
const epochSql = 'SELECT version FROM iam_epoch WHERE singleton=true';
const grantSql = 'SELECT * FROM iam_effective_grants WHERE user_id=$1';
const legacySort = <T>(rows: readonly T[], fingerprint: (row: T) => string): T[] => [...rows]
  .sort((a, b) => fingerprint(a).localeCompare(fingerprint(b)));
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'd5'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

/** Actual CandidateRead principal and keyed crypto with exact controlled SQL.
 * The reader lifecycle case uses the established controlled Root/business
 * fixture. These are Source semantics checks, not live runtime or timings. */
function fixture(count = 12) {
  const secrets = new SecretService(), actorId = randomUUID(), cid = randomUUID(), wid = randomUUID();
  const user: any = { id: actorId, username: 'source-candidate-executor', super_admin: false, credential_epoch: '7', permissions_epoch: '9',
    force_password_change: false, display_name: null, locale: 'zh-CN', timezone: 'Asia/Shanghai', revision: 5 };
  const rows = Array.from({ length: count }, (_, n) => ({ user_id: actorId, role_id: randomUUID(), role_code: n % 2 ? null : `source-role-${n}`,
    permission_id: randomUUID(), binding_id: randomUUID(), binding_source: n % 2 ? 'team' : 'user', cluster_id: n % 3 ? cid : null,
    workspace_id: n % 3 ? wid : null, module: n % 2 ? 'services' : 'routes', action: n % 3 ? 'read' : 'write', scope_type: 'global', scope_values: [] }));
  const state: any = { epoch: '11', user, rows, latest: [], batches: [], fail: false };
  const db: any = { one: vi.fn(async (sql: string, args: any[] = []) => {
    if (state.fail) throw Error('SOURCE_FRESH_PRINCIPAL_SQL_UNAVAILABLE');
    if (sql === epochSql) { expect(args).toEqual([]); return { version: state.epoch }; }
    if (sql === userSql) { expect(args).toEqual([actorId]); return state.user && { ...state.user }; }
    throw Error('UNEXPECTED_CANDIDATE_FRESH_SORT_SQL');
  }), query: vi.fn(async (sql: string, args: any[] = []) => {
    if (sql !== grantSql) throw Error('UNEXPECTED_CANDIDATE_FRESH_SORT_ROWS');
    expect(args).toEqual([actorId]); state.latest = structuredClone(state.rows); state.batches.push(state.latest); return state.latest;
  }) };
  const service = new WorkflowScheduleCandidateReadService(db, secrets, {} as any, {} as any, {} as any, {} as any);
  const principal = () => (service as any).principal(actorId, db);
  const oldPrincipal = () => ({ user: { id: user.id, username: user.username, superAdmin: user.super_admin === true, forcePasswordChange: false,
    displayName: user.display_name, locale: user.locale, timezone: user.timezone, revision: user.revision },
    credentialEpoch: String(user.credential_epoch), permissionVersion: `${user.id}:${user.permissions_epoch}:${state.epoch}`,
    grants: legacySort(state.rows.filter(validGrant), row => secrets.fingerprint(row)) });
  return { secrets, actorId, cid, wid, state, db, service, principal, oldPrincipal };
}
function expectFreshOccurrenceHashes(spy: any, rows: any[]): void {
  for (const row of new Set(rows)) {
    const occurrences = rows.filter(value => value === row).length;
    expect(spy.mock.calls.filter(([value]: any[]) => value === row)).toHaveLength(occurrences);
  }
}

describe('actual CandidateRead fifth fresh-grant fingerprint sort', () => {
  it.each([0, 1, 2, 145])('keeps the full former principal and SQL contract for %i grants with one hash per fresh occurrence', async count => {
    const f = fixture(count), expected = f.oldPrincipal(), original = structuredClone(f.state.rows), hash = vi.spyOn(f.secrets, 'fingerprint');
    const result = await f.principal();
    expect(result).toEqual(expected); expect(f.secrets.fingerprint(result)).toBe(f.secrets.fingerprint(expected));
    expectFreshOccurrenceHashes(hash, f.state.latest); expect(f.state.rows).toEqual(original);
    expect(f.db.one).toHaveBeenCalledTimes(2); expect(f.db.query).toHaveBeenCalledExactlyOnceWith(grantSql, [f.actorId]);
    expect(f.db.one.mock.calls.map(([sql]: any[]) => sql)).toEqual([epochSql, userSql]);
    expect(Object.isFrozen(result)).toBe(true); expect(Object.isFrozen(result.grants)).toBe(true);
    expect(result.user.displayName).toBeNull();
    result.grants.forEach((row: any, n: number) => {
      expect(Object.keys(row)).toHaveLength(12); expect(Object.isFrozen(row)).toBe(true);
      // immutableJson still clones the complete proof. The helper hands each
      // original fresh SQL row to the existing fingerprint before that clone.
      expect(row).not.toBe(expected.grants[n]);
    });
  });
  it('filters invalid rows before hashing and preserves duplicates, null ceilings, stable ties and complete row insertion order', async () => {
    const f = fixture(1), a = f.state.rows[0], b = Object.fromEntries(Object.entries(a).reverse());
    expect(f.secrets.fingerprint(a)).toBe(f.secrets.fingerprint(b));
    f.state.rows = [a, b, a, { ...a, action: 'unsupported' }, null, { ...a, scope_type: 'entity', scope_values: [] }];
    const expected = f.oldPrincipal(), hash = vi.spyOn(f.secrets, 'fingerprint'), result = await f.principal();
    expect(result).toEqual(expected); expect(result.grants).toHaveLength(3);
    expect(result.grants.map((row: any) => Object.keys(row))).toEqual([Object.keys(a), Object.keys(b), Object.keys(a)]);
    expect(result.grants.every((row: any) => row.cluster_id === null && row.workspace_id === null)).toBe(true);
    expectFreshOccurrenceHashes(hash, f.state.latest.filter(validGrant));
    f.state.latest.filter((row: any) => !validGrant(row)).forEach((row: any) => expect(hash.mock.calls.some(([value]) => value === row)).toBe(false));
  });
  it('rereads every epoch, full row and grant on the next call without caching mutable SQL object identity', async () => {
    const f = fixture(), hash = vi.spyOn(f.secrets, 'fingerprint'), first = await f.principal(), firstRows = f.state.latest;
    expectFreshOccurrenceHashes(hash, firstRows); hash.mockClear();
    f.state.rows[0].binding_source = 'team'; f.state.rows[1].role_code = 'changed-role-provenance';
    f.state.rows.splice(2, 1); f.state.epoch = '12';
    const next = await f.principal();
    expect(next.permissionVersion).toBe(`${f.actorId}:9:12`); expect(next.grants).not.toEqual(first.grants);
    expectFreshOccurrenceHashes(hash, f.state.latest); expect(f.state.latest[0]).not.toBe(firstRows[0]);
    expect(f.db.one).toHaveBeenCalledTimes(4); expect(f.db.query).toHaveBeenCalledTimes(2);
    expect(first.grants).toHaveLength(12); expect(next.grants).toHaveLength(11);
  });
  it.each(['binding_source', 'binding_id', 'permission_id', 'role_code', 'cluster_id', 'workspace_id', 'module', 'action', 'scope_values'])('retains complete %s data in the principal fingerprint', async field => {
    const f = fixture(2), first = await f.principal();
    if (field === 'scope_values') { f.state.rows[1].scope_type = 'entity'; f.state.rows[1].scope_values = [{ entity_type: 'services', entity_id: randomUUID() }]; }
    else if (field === 'action') f.state.rows[1][field] = 'approve';
    else if (field === 'binding_source') f.state.rows[1][field] = 'user';
    else if (field === 'cluster_id') { f.state.rows[1][field] = randomUUID(); f.state.rows[1].workspace_id = null; }
    else if (field === 'workspace_id') f.state.rows[1][field] = randomUUID();
    else f.state.rows[1][field] = field.endsWith('_id') ? randomUUID() : 'changed-source-value';
    const next = await f.principal();
    expect(next.grants).toHaveLength(2); expect(f.secrets.fingerprint(next)).not.toBe(f.secrets.fingerprint(first));
    expect(next).toEqual(f.oldPrincipal());
  });
  it.each(['missing', 'foreign', 'forced-password'])('retains the %s principal refusal and reads no grants', async reason => {
    const f = fixture();
    if (reason === 'missing') f.state.user = null; else if (reason === 'foreign') f.state.user.id = randomUUID(); else f.state.user.force_password_change = true;
    await expect(f.principal()).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_PRINCIPAL_REVOKED' } });
    expect(f.db.query).not.toHaveBeenCalled();
  });
  it('propagates actual keyed fingerprint failure instead of returning a partial sorted authority', async () => {
    const f = fixture(), original = f.secrets.fingerprint.bind(f.secrets), fail = Error('SOURCE_CURRENT_HASH_UNAVAILABLE');
    vi.spyOn(f.secrets, 'fingerprint').mockImplementation(value => { if ((value as any)?.permission_id === f.state.rows[3].permission_id) throw fail; return original(value); });
    await expect(f.principal()).rejects.toBe(fail); expect(f.db.query).toHaveBeenCalledOnce();
  });
  it('rejects changed fresh grants through the actual retained-handle lifecycle and poisons that original capability', async () => {
    const f = candidateAbsenceFixture(); f.install();
    await expect(f.service.runOriginalPlan(f.plan, f.owner, 'executor', async handle => {
      await f.service.verifyHandle(handle);
      f.values.secrets = false;
      await expect(f.service.verifyHandle(handle)).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_FACTS_CHANGED' } });
      f.values.secrets = true;
      await expect(f.service.verifyHandle(handle)).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_FAILED' } });
      return { reused: true };
    })).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_READ_FAILED' } });
    expect(f.repository.appendDueClaim).not.toHaveBeenCalled(); expect(f.executor.executeClaim).not.toHaveBeenCalled();
  });
});
