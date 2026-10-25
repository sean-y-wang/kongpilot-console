import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { SecretService, canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';
import { immutableJson } from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import { validGrant } from '../../apps/console-api/src/modules/authorization/grant-policy';
import { WorkflowScheduledValidationReadService, WORKFLOW_VALIDATION_PRINCIPAL_SNAPSHOT_SQL as SQL } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-validation-read.service';
import { validationAbsenceFixture } from './helpers/workflow-scheduled-read-absence-fixture';

/** Real principal/current/provider/crypto; explicit exact-query SQL transport
 * fixtures only. This does not execute PostgreSQL or prove its query plan. */
const deny = { response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_PRINCIPAL_REVOKED' } };
const pg = createRequire(new URL('../../apps/console-api/package.json', import.meta.url))('pg');
function fixture() {
  const actor = randomUUID(), cid = randomUUID(), wid = randomUUID(), secrets = new SecretService();
  const user: any = { id: actor, username: 'source-only', super_admin: false, credential_epoch: '9007199254740993',
    permissions_epoch: '9007199254740995', force_password_change: false, display_name: '完整用户', locale: 'zh-CN', timezone: 'Asia/Shanghai', revision: 2147483647 };
  const grant = (scope: string, index: number): any => ({ user_id: actor, role_id: randomUUID(), role_code: `role-${index}`,
    permission_id: randomUUID(), binding_id: randomUUID(), binding_source: index % 2 ? 'team' : 'user',
    cluster_id: scope === 'global' ? null : cid, workspace_id: scope === 'workspace' ? wid : null,
    module: 'services', action: 'read', scope_type: scope, scope_values: scope === 'workspace' ? [wid]
      : scope === 'tag_group' ? ['encoded_owner_tag'] : scope === 'entity' ? [{ entity_type: 'services', entity_id: randomUUID() }] : [] });
  const rows = ['global', 'workspace', 'tag_group', 'entity'].map(grant); rows.push(structuredClone(rows[0]));
  const state: any = { user, epoch: '9223372036854775807', grants: rows, userPresent: true, epochPresent: true, malformed: undefined, lastRaw: null };
  const db: any = { one: vi.fn(async (sql: string, params: unknown[]) => {
    if (sql !== SQL || params.length !== 1 || params[0] !== actor) throw new Error('UNEXPECTED_TYPED_PRINCIPAL_SQL');
    if (state.malformed !== undefined) return state.malformed;
    if (!state.userPresent || !state.epochPresent || state.user.force_password_change) return null;
    // Model the already parsed JSONB aggregate, including complete raw rows,
    // nulls and duplicates. No pg server is used by this Source fixture.
    state.lastRaw = structuredClone({ ...state.user, iam_version: state.epoch, grants: state.grants }); return state.lastRaw;
  }), query: vi.fn(async () => { throw new Error('NO_SECOND_SQL_QUERY_ALLOWED'); }) };
  const service = new WorkflowScheduledValidationReadService(db, secrets, {} as any, {} as any, {} as any, {} as any);
  const read = () => (service as any).principal(actor, db);
  const legacy = () => immutableJson({ user: { id: user.id, username: user.username, superAdmin: user.super_admin === true, forcePasswordChange: false,
    displayName: user.display_name, locale: user.locale, timezone: user.timezone, revision: user.revision }, credentialEpoch: String(user.credential_epoch),
    permissionVersion: `${user.id}:${user.permissions_epoch}:${state.epoch}`,
    grants: [...state.grants.filter(validGrant)].sort((left: any, right: any) => secrets.fingerprint(left).localeCompare(secrets.fingerprint(right))) });
  return { actor, user, grant, rows, state, db, secrets, service, read, legacy };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.useRealTimers(); });

describe('Validation principal single typed fresh SQL snapshot', () => {
  it('has ten original typed user columns and a typed epoch, with only the complete grant row aggregated', () => {
    const compact = SQL.replace(/\s+/g, ' ');
    expect(compact).toMatch(/^SELECT u\.id,u\.username,u\.super_admin,u\.credential_epoch,u\.permissions_epoch, u\.force_password_change,u\.display_name,u\.locale,u\.timezone,u\.revision,e\.version AS iam_version,/);
    expect(compact).toContain("COALESCE((SELECT jsonb_agg(to_jsonb(g)) FROM iam_effective_grants g WHERE g.user_id=u.id),'[]'::jsonb) AS grants");
    expect(compact).toContain("FROM users u CROSS JOIN iam_epoch e WHERE e.singleton=true AND u.id=$1 AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change");
    expect(compact).not.toMatch(/\bDISTINCT\b|\bLIMIT\b|\bLEFT JOIN\b|jsonb_build_object|to_jsonb\(u\)|to_jsonb\(e\)|\bNumber\b|\bFOR UPDATE\b|\bSET\b/i);
  });

  it.each(['9007199254740993', '9007199254740995', '9223372036854775807'])('keeps all three bigint epochs exact with the actual pg text parser for %s', async epoch => {
    const f = fixture(), parse = pg.types.getTypeParser(20, 'text');
    expect(parse(epoch)).toBe(epoch); f.user.credential_epoch = parse(epoch); f.user.permissions_epoch = parse(epoch); f.state.epoch = parse(epoch);
    const result = await f.read(); expect(result.credentialEpoch).toBe(epoch); expect(result.permissionVersion).toBe(`${f.actor}:${epoch}:${epoch}`);
    expect(result.user.revision).toBe(2147483647); expect(typeof result.user.revision).toBe('number');
    expect(canonicalJson(result)).toBe(canonicalJson(f.legacy()));
  });

  it.each([0, 1, 5, 25, 200])('preserves complete canonical bytes and HMA for %i raw rows, with nulls and duplicate bindings', async count => {
    const f = fixture(); f.state.grants = Array.from({ length: count }, (_, index) => structuredClone(f.rows[index % f.rows.length]));
    // A JSONB object's key order may differ from pg's ordinary row property order.
    f.state.grants = f.state.grants.map((row: any) => Object.fromEntries(Object.entries(row).reverse()));
    const before = structuredClone(f.state.grants), expected = f.legacy(), result = await f.read();
    expect(canonicalJson(result)).toBe(canonicalJson(expected)); expect(f.secrets.fingerprint(result)).toBe(f.secrets.fingerprint(expected));
    expect(result.grants).toHaveLength(count); expect(f.state.grants).toEqual(before); expect(f.db.one).toHaveBeenCalledExactlyOnceWith(SQL, [f.actor]); expect(f.db.query).not.toHaveBeenCalled();
    for (const row of result.grants) expect(Object.keys(row).sort()).toEqual(['user_id', 'role_id', 'role_code', 'permission_id', 'binding_id', 'binding_source', 'cluster_id', 'workspace_id', 'module', 'action', 'scope_type', 'scope_values'].sort());
    expect(result.grants.filter((row: any) => row.scope_type === 'global').every((row: any) => row.cluster_id === null && row.workspace_id === null)).toBe(true);
  });

  it('filters invalid full rows before hashing without removing valid duplicate rows or provenance', async () => {
    const f = fixture(); f.state.grants.push({ ...f.rows[0], action: 'unsupported' }, null);
    const fingerprint = vi.spyOn(f.secrets, 'fingerprint'), result = await f.read(), raw = f.state.lastRaw.grants;
    expect(result.grants).toHaveLength(5);
    for (const row of raw.slice(0, 5)) expect(fingerprint.mock.calls.filter(([value]) => value === row)).toHaveLength(1);
    expect(fingerprint.mock.calls.some(([value]) => value === raw[5] || value === raw[6])).toBe(false);
    expect(result.grants.filter((row: any) => row.binding_id === f.rows[0].binding_id)).toHaveLength(2);
  });

  it('returns a detached deeply immutable principal and re-reads every adjacent invocation', async () => {
    const f = fixture(), first = await f.read(); expect(Object.isFrozen(first.grants[0].scope_values)).toBe(true);
    f.state.lastRaw.grants[0].action = 'delete'; expect(first.grants.some((row: any) => row.action === 'delete')).toBe(false);
    f.user.permissions_epoch = '9007199254740997'; f.state.grants[0].action = 'approve';
    const second = await f.read(); expect(second.permissionVersion).not.toBe(first.permissionVersion); expect(second.grants).not.toEqual(first.grants);
    expect(f.db.one).toHaveBeenCalledTimes(2); expect(f.db.query).not.toHaveBeenCalled();
  });

  it.each(['user', 'epoch', 'forced-password-change'])('denies a fresh missing/inactive %s rather than using the earlier snapshot', async reason => {
    const f = fixture(); await f.read();
    if (reason === 'user') f.state.userPresent = false; else if (reason === 'epoch') f.state.epochPresent = false; else f.user.force_password_change = true;
    await expect(f.read()).rejects.toMatchObject(deny); expect(f.db.one).toHaveBeenCalledTimes(2);
  });

  it.each([null, undefined, {}, '[]'])('denies a non-array aggregate %j without [] fallback', async value => {
    const f = fixture(); f.state.malformed = { ...f.user, iam_version: f.state.epoch, grants: value };
    await expect(f.read()).rejects.toMatchObject(deny);
  });

  it.each(['credential_epoch', 'permissions_epoch', 'iam_version'])('refuses a numerically decoded or missing %s before canonical/HMA generation', async field => {
    const f = fixture(); f.state.malformed = { ...f.user, iam_version: f.state.epoch, grants: f.rows, [field]: 9007199254740992 };
    await expect(f.read()).rejects.toMatchObject(deny);
    delete f.state.malformed[field]; await expect(f.read()).rejects.toMatchObject(deny);
  });

  it('refuses a foreign row ID and propagates query failure without a second read or fallback principal', async () => {
    const f = fixture(); f.state.malformed = { ...f.user, id: randomUUID(), iam_version: f.state.epoch, grants: f.rows };
    await expect(f.read()).rejects.toMatchObject(deny);
    const error = new Error('SOURCE_TYPED_SNAPSHOT_FAILURE'); f.db.one.mockRejectedValueOnce(error);
    await expect(f.read()).rejects.toBe(error); expect(f.db.query).not.toHaveBeenCalled();
  });
});

describe('the actual Validation current/request fences still revalidate typed snapshots', () => {
  it.each(['iam', 'credential-epoch', 'permissions-epoch', 'display-name', 'locale', 'timezone', 'revision', 'super-admin', 'grants', 'missing-user', 'missing-epoch'])('rejects a changed %s at the adjacent request checkpoint before response release', async reason => {
    vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-14T01:00:00Z'));
    const f = validationAbsenceFixture(), original = f.db.one.getMockImplementation()!; let changed = false, entered = false, rejection: any;
    f.db.one.mockImplementation(async (sql: string, args: unknown[]) => {
      const row = await original(sql, args); if (!changed || sql !== SQL || !row) return row;
      if (['missing-user', 'missing-epoch'].includes(reason)) return null;
      if (reason === 'iam') row.iam_version = '2'; if (reason === 'credential-epoch') row.credential_epoch = '2';
      if (reason === 'permissions-epoch') row.permissions_epoch = '2'; if (reason === 'display-name') row.display_name = 'changed label';
      if (reason === 'locale') row.locale = 'en-US'; if (reason === 'timezone') row.timezone = 'UTC';
      if (reason === 'revision') row.revision = 2; if (reason === 'super-admin') row.super_admin = true;
      if (reason === 'grants') row.grants = []; return row;
    });
    f.install(); await expect(f.run(async (handle: object) => {
      const token = await f.service.authorizeRequest(handle, f.packet()); entered = true; changed = true;
      try { await f.service.verifyRequest(token); } catch (error) { rejection = error; }
      return true;
    })).rejects.toBeDefined();
    expect(entered).toBe(true); expect(rejection).toBeDefined(); expect(f.business.authorizeResponse).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('retains distinct before/after IAM and principal observations within the same current call', async () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-14T01:00:00Z'));
    const f = validationAbsenceFixture(), scope = f.business.resolveReadScope.getMockImplementation()!;
    f.business.resolveReadScope.mockImplementationOnce(async (...args: unknown[]) => { const value = await scope(...args); f.state.principalVersion = '2'; return value; });
    f.install(); await expect(f.run(async () => true)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_VALIDATION_PERMISSIONS_CHANGED' } });
    expect(f.runner.run).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
  });
});
