import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { IamService } from '../../apps/console-api/src/modules/iam/iam.service';
import { IamMutationsService } from '../../apps/console-api/src/modules/iam/iam-mutations.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { encodeTag } from '../../apps/console-api/src/infrastructure/kong/tags';
import type { IamApprovedMutationBinding, IamCapturedChange } from '../../apps/console-api/src/modules/iam/iam-workflow.types';

/** These tests use the real IAM services and their ALS/SQL callback boundary.
 * SQL transactions, Redis leases, authorization and the Root-owned private
 * capability provider are fixture transports; they are not runtime evidence. */
function fixture(install = true) {
  const cid = randomUUID(), wid = randomUUID(), rid = randomUUID(), tid = randomUUID(), uid = randomUUID(), cid2 = randomUUID(), wid2 = randomUUID();
  const actor: any = { user: { id: randomUUID(), username: 'reviewer', superAdmin: false }, sessionId: randomUUID(), idempotencyKey: 'fixture-original-key', requestId: randomUUID(), ip: '192.0.2.91' };
  const role = { id: rid, code: 'payment_ops', name: 'Payments Operators', description: 'Own scope', revision: 4, status: 'active', protected: false, builtin_kind: null, cluster_id: cid, workspace_id: wid };
  const team = { id: tid, code: 'payment_team', name: 'Payments Team', description: '', revision: 3, status: 'active', cluster_id: cid, workspace_id: wid };
  const user = { id: uid, username: 'application_owner', display_name: 'Application Owner', revision: 2, status: 'active', super_admin: false };
  let state: any = { roles: new Map([[rid, role]]), teams: new Map([[tid, team]]), users: new Map([[uid, user]]), permissions: [], bindings: [], members: [], operations: new Map(), facts: [], epoch: 10, audit: [] };
  const secrets = new SecretService(), sqlWrites: string[] = [], transactionStack: object[] = [];
  const authz: any = { assertConsole: vi.fn().mockResolvedValue(undefined), assertCluster: vi.fn().mockResolvedValue(undefined),
    assertDelegatable: vi.fn().mockResolvedValue(undefined), isPlatformAdmin: vi.fn().mockResolvedValue(false),
    snapshot: vi.fn(async () => ({ user: actor.user, grants: ['roles', 'teams', 'users', 'permissions'].flatMap(module => ['read', 'write', 'delete'].map(action => ({ module, action, cluster_id: null, workspace_id: null, scope_type: 'global', scope_values: [] }))) })),
    permissionVersion: vi.fn(async () => `permissions-${state.epoch}`) };
  const auth: any = { hashPassword: vi.fn(async () => 'Synthetic-bcrypt-hash'), revokeAllSessions: vi.fn().mockResolvedValue(undefined) };
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()), assertLeaseOwnership: vi.fn().mockResolvedValue(undefined) };
  const audit: any = { append: vi.fn(async (event: any) => state.audit.push(secrets.redact(event))) };
  const read = (sql: string, p: any[] = []): any => {
    if (sql.includes('FROM iam_epoch')) return { version: state.epoch };
    if (sql.includes('FROM iam_operations')) return [...state.operations.values()].find(row => row.actor_id === p[0] && row.idempotency_key === p[1]) ?? null;
    if (sql.includes('FROM clusters')) return sql.includes('id=ANY') ? { id: cid } : { id: p[0], execution_mode: 'approval', status: 'healthy' };
    if (sql.includes('FROM workspaces')) return { id: p[1], cluster_id: p[0], status: 'active' };
    if (sql.startsWith('SELECT id FROM roles WHERE code=')) return [...state.roles.values()].find(row => row.code === p[0]) ?? null;
    if (sql.includes('FROM roles WHERE id=')) return structuredClone(state.roles.get(p[0]) ?? null);
    if (sql.includes('FROM teams WHERE id=')) return structuredClone(state.teams.get(p[0]) ?? null);
    if (sql.includes('FROM users WHERE id=')) return structuredClone(state.users.get(p[0]) ?? null);
    if (sql.startsWith('SELECT id FROM users WHERE lower')) return [...state.users.values()].find(row => row.username.toLowerCase() === p[0].toLowerCase()) ?? null;
    if (sql.startsWith('INSERT INTO roles') || sql.startsWith('INSERT INTO teams')) {
      sqlWrites.push(sql); const table = sql.startsWith('INSERT INTO roles') ? 'roles' : 'teams';
      const row = { id: p[0], code: p[1], name: p[2], description: p[3], cluster_id: p[4], workspace_id: p[5], revision: 1, status: 'active', protected: false, builtin_kind: null };
      state[table].set(row.id, row); state.epoch++; return structuredClone(row);
    }
    if (sql.startsWith('INSERT INTO users')) {
      sqlWrites.push(sql); const row = { id: p[0], username: p[1], password_hash: p[2], display_name: p[3], email: p[4], status: 'active', revision: 1 };
      state.users.set(row.id, row); state.epoch++; return structuredClone(row);
    }
    if (sql.startsWith('UPDATE roles SET revision=')) {
      sqlWrites.push(sql); const row = state.roles.get(p[0]); if (!row || row.revision !== p[1]) return null;
      row.revision++; state.epoch++; return { revision: row.revision };
    }
    if (/^UPDATE (roles|teams|users) SET status=/.test(sql)) {
      sqlWrites.push(sql); const table = sql.match(/^UPDATE (\w+)/)![1], row = state[table].get(p[0]); if (!row || row.revision !== p[3]) return null;
      row.status = p[1]; row.revision++; state.epoch++; return structuredClone(row);
    }
    if (/^UPDATE (roles|teams|users) SET /.test(sql)) {
      sqlWrites.push(sql); const table = sql.match(/^UPDATE (\w+)/)![1], row = state[table].get(p[p.length - 2]);
      if (!row || row.revision !== p[p.length - 1]) return null;
      for (const field of sql.matchAll(/(name|description|display_name|email)=\$(\d+)/g)) row[field[1]] = p[Number(field[2]) - 1];
      row.revision++; state.epoch++; return structuredClone(row);
    }
    return null;
  };
  const query = (sql: string, p: any[] = []): any[] => {
    if (sql.includes('FROM role_permissions')) return structuredClone(state.permissions.filter((row: any) => row.role_id === p[0] && row.status === 'active'));
    if (sql.includes("'user' AS subject_type")) return structuredClone(state.bindings.filter((row: any) => row.role_id === p[0]));
    if (sql.includes('FROM user_role_bindings') && sql.includes('user_id=$1')) return structuredClone(state.bindings.filter((row: any) => row.user_id === p[0]));
    if (sql.includes('FROM team_role_bindings') && sql.includes('team_id=$1')) return structuredClone(state.bindings.filter((row: any) => row.team_id === p[0]));
    if (sql.includes('FROM team_members')) return structuredClone(state.members.filter((row: any) => row.team_id === p[0]));
    return [];
  };
  const exec = (sql: string, p: any[] = []): number => {
    sqlWrites.push(sql);
    if (sql.startsWith('INSERT INTO iam_operations')) state.operations.set(p[0], { id: p[0], actor_id: p[1], idempotency_key: p[2], request_hash: p[3], module: p[4], action: p[5], target_id: p[6], cluster_id: p[7], workspace_id: p[8], payload_secret: p[9], state: 'running', remote_completed: false });
    if (sql.startsWith('UPDATE iam_operations')) { const row = state.operations.get(p[0]); if (!row || row.state !== 'running') return 0; Object.assign(row, { state: 'succeeded', remote_completed: true, result_secret: p[1], safe_result: JSON.parse(p[2]) }); }
    if (sql.startsWith('INSERT INTO iam_workflow_mutation_facts')) state.facts.push([...p]);
    if (sql.startsWith('UPDATE role_permissions')) for (const row of state.permissions) if (row.role_id === p[0] && row.status === 'active') row.status = 'revoked';
    if (sql.startsWith('INSERT INTO role_permissions')) state.permissions.push({ id: p[0], role_id: p[1], module: p[2], action: p[3], scope_type: p[4], cluster_id: p[5], workspace_id: p[6], status: 'active', scope_values: p[4] === 'workspace' ? [p[6]] : [] });
    if (sql.startsWith('INSERT INTO role_permission_tags')) state.permissions.find((row: any) => row.id === p[0]).scope_values.push(p[2]);
    if (sql.startsWith('INSERT INTO role_permission_entities')) state.permissions.find((row: any) => row.id === p[0]).scope_values.push({ entity_type: p[1], entity_id: p[2] });
    return 1;
  };
  const tx: any = { one: vi.fn(async (sql: string, p?: any[]) => read(sql, p)), query: vi.fn(async (sql: string, p?: any[]) => query(sql, p)), exec: vi.fn(async (sql: string, p?: any[]) => exec(sql, p)) };
  const db: any = { one: vi.fn(async (sql: string, p?: any[]) => read(sql, p)), query: vi.fn(async (sql: string, p?: any[]) => query(sql, p)), exec: vi.fn(async (sql: string, p?: any[]) => exec(sql, p)),
    transaction: vi.fn(async (fn: any) => { const old = structuredClone(state); transactionStack.push(tx); try { return await fn(tx); } catch (error) { state = old; throw error; } finally { transactionStack.pop(); } }) };
  const mutations = new IamMutationsService(db, redis, secrets, audit, authz), service = new IamService(db, secrets, audit, authz, auth, mutations);
  const handles = new WeakMap<object, { capture: Readonly<IamCapturedChange>; binding: Readonly<IamApprovedMutationBinding>; live: boolean }>();
  let afterOverride: Record<string, unknown> = {};
  const policy: any = { verify: vi.fn(async (handle: object, context: any, phase: string, transaction: any) => {
    const original = handles.get(handle);
    if (!original?.live || transaction !== tx || !transactionStack.includes(transaction)) throw new ForbiddenException({ code: 'FIXTURE_ORIGINAL_IAM_HANDLE_REQUIRED' });
    const { actor: actual, ...mutation } = context;
    if (actual.user.id !== actor.user.id || secrets.fingerprint(mutation) !== secrets.fingerprint(original.capture.mutation)) throw new ForbiddenException({ code: 'FIXTURE_IAM_SUBJECT_MISMATCH' });
    return Object.freeze({ ...original.binding, ...(phase === 'after' ? { permissionVersion: `permissions-${state.epoch}`, iamEpoch: String(state.epoch), ...afterOverride } : {}) });
  }) };
  const changePolicy: any = { verifyCapture: vi.fn(async (handle: object, capture: Readonly<IamCapturedChange>, actual: any, transaction: any) => {
    const original = handles.get(handle);
    if (!original?.live || transaction !== tx || !transactionStack.includes(transaction)) throw new ForbiddenException({ code: 'FIXTURE_ORIGINAL_IAM_HANDLE_REQUIRED' });
    if (actual.user.id !== actor.user.id || secrets.fingerprint(capture) !== secrets.fingerprint(original.capture)) throw new ForbiddenException({ code: 'FIXTURE_IAM_CAPTURE_MISMATCH' });
  }) };
  if (install) { mutations.installApprovedMetadataPolicy(policy); service.installApprovedChangePolicy(changePolicy); }
  const mint = (capture: Readonly<IamCapturedChange>) => {
    const handle = Object.freeze({}), binding: IamApprovedMutationBinding = { intentId: randomUUID(), workflowId: randomUUID(), executionId: randomUUID(), stepId: randomUUID(), planRevision: 1,
      planHash: secrets.fingerprint(capture), clusterId: cid, workspaceId: wid, actorId: actor.user.id, sessionId: actor.sessionId, permissionVersion: `permissions-${state.epoch}`, iamEpoch: String(state.epoch) };
    handles.set(handle, { capture, binding, live: true }); return { handle, binding, revoke: () => { handles.get(handle)!.live = false; } };
  };
  return { cid, wid, rid, tid, uid, cid2, wid2, actor, tx, db, secrets, audit, authz, auth, redis, mutations, service, policy, changePolicy, mint, sqlWrites,
    state: () => state, overrideAfter: (value: Record<string, unknown>) => { afterOverride = value; } };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '4a'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('M11 IAM captured SQL graph and explicit approved mutation path', () => {
  it('captures current resource/dependencies/scopes without running a SQL mutation callback or writing the ledger', async () => {
    const f = fixture(), permission = { id: randomUUID(), role_id: f.rid, module: 'services', action: 'read', scope_type: 'workspace', scope_values: [f.wid2], cluster_id: f.cid2, workspace_id: f.wid2, status: 'active', revision: 2 };
    // A platform-owned role may contain grants and bindings for distinct
    // clusters. A workspace-owned role cannot cross that owner boundary.
    Object.assign(f.state().roles.get(f.rid), { cluster_id: null, workspace_id: null });
    f.state().permissions.push(permission);
    f.state().bindings.push({ id: randomUUID(), role_id: f.rid, user_id: f.uid, cluster_id: f.cid, workspace_id: f.wid, revision: 1, status: 'active' });
    const before = structuredClone(f.state()), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'New name' } }, f.actor, f.tx);
    expect(capture.before.resource).toEqual(before.roles.get(f.rid));
    expect(capture.before.permissions).toEqual([permission]);
    expect(capture.before.bindings).toHaveLength(1);
    expect(capture.before.related).toHaveLength(1);
    expect(capture.affectedScopes).toEqual(expect.arrayContaining([{ cluster_id: null, workspace_id: null }, { cluster_id: f.cid, workspace_id: f.wid }, { cluster_id: f.cid2, workspace_id: f.wid2 }]));
    expect(capture.allocatedIds).toEqual([]);
    expect(f.sqlWrites).toEqual([]);
    expect(f.policy.verify).not.toHaveBeenCalled();
    expect(f.audit.append).not.toHaveBeenCalled();
    expect(f.state()).toEqual(before);
    expect(f.tx.query).toHaveBeenCalledWith(expect.stringContaining('FROM role_permissions'), [f.rid]);
    expect(Object.isFrozen(capture.before.permissions)).toBe(true);
  });

  it('requires the caller-supplied transaction for every captured resource/dependency graph read', async () => {
    const f = fixture(); f.db.one.mockRejectedValue(new Error('outside-transaction read prohibited'));
    f.db.query.mockRejectedValue(new Error('outside-transaction read prohibited'));
    await expect(f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'New name' } }, f.actor, f.tx)).resolves.toHaveProperty('mutation.targetId', f.rid);
    expect(f.sqlWrites).toEqual([]);
  });

  it('prepares permission replacement with physical business tags and fixed IDs while leaving old permissions untouched', async () => {
    const f = fixture(), entityId = randomUUID(), input = { revision: 4, permissions: [
      { module: 'services', action: 'read', scope_type: 'tag_group', scope_values: ['team:payments'], cluster_id: f.cid, workspace_id: f.wid },
      { module: 'services', action: 'write', scope_type: 'entity', scope_values: [{ entity_type: 'services', entity_id: entityId }], cluster_id: f.cid, workspace_id: f.wid },
    ] };
    const capture = await f.service.captureChange({ resource: 'roles', operation: 'permissions', resourceId: f.rid, input }, f.actor, f.tx);
    expect(capture.delegatedGrants[0].scope_values).toEqual([encodeTag('team:payments')]);
    expect(capture.delegatedGrants[1].scope_values).toEqual([{ entity_type: 'services', entity_id: entityId }]);
    expect(capture.allocatedIds).toHaveLength(2); expect(new Set(capture.allocatedIds).size).toBe(2);
    expect(f.sqlWrites).toEqual([]); expect(f.state().permissions).toEqual([]);
    expect(f.authz.assertDelegatable).toHaveBeenCalled();
  });

  it('applies one captured role change on an approval cluster, binds actual ledger facts and audits in the outer transaction', async () => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture);
    const result = await f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx));
    expect(result).toMatchObject({ id: f.rid, name: 'Approved name', revision: 5 });
    expect(f.policy.verify.mock.calls.map((call: any[]) => call[2])).toEqual(['before', 'after']);
    expect(f.policy.verify.mock.calls.every((call: any[]) => call[0] === original.handle && call[3] === f.tx)).toBe(true);
    const ledger: any = [...f.state().operations.values()][0];
    expect(ledger).toMatchObject({ actor_id: f.actor.user.id, idempotency_key: `iam-approved-${original.binding.executionId}`, cluster_id: f.cid, workspace_id: f.wid, state: 'succeeded', remote_completed: true });
    expect(f.state().facts).toHaveLength(1);
    expect(f.state().facts[0]).toEqual(expect.arrayContaining([original.binding.intentId, original.binding.workflowId, original.binding.executionId, original.binding.stepId, original.binding.sessionId, original.binding.planHash]));
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'iam.write.approved', workflowId: original.binding.workflowId, result: 'success' }), f.tx);
    expect(f.db.transaction).toHaveBeenCalledTimes(1);
    expect(f.sqlWrites.every(sql => !sql.includes('DELETE FROM'))).toBe(true);
  });

  it('creates a captured role with its allocated original ID and no caller-supplied ID or Native request', async () => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'create', input: { code: 'approved_role', name: 'Approved Role', cluster_id: f.cid, workspace_id: f.wid } }, f.actor, f.tx);
    expect(capture.allocatedIds).toHaveLength(1); expect(f.sqlWrites).toEqual([]);
    const original = f.mint(capture), result = await f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx));
    expect(result.id).toBe(capture.allocatedIds[0]);
    expect(f.state().roles.get(result.id)).toMatchObject({ code: 'approved_role', cluster_id: f.cid, workspace_id: f.wid });
  });

  it('uses the same sealed capture for approval verification and allocation despite mutation of the caller clone during await', async () => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'create', input: { code: 'approved_role', name: 'Approved Role', cluster_id: f.cid, workspace_id: f.wid } }, f.actor, f.tx), original = f.mint(capture);
    const supplied: any = structuredClone(capture), injectedId = randomUUID(), verify = f.changePolicy.verifyCapture.getMockImplementation()!;
    f.changePolicy.verifyCapture.mockImplementation(async (...args: any[]) => { await verify(...args); supplied.allocatedIds[0] = injectedId; });
    const result = await f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, supplied, f.actor, tx));
    expect(result.id).toBe(capture.allocatedIds[0]);
    expect(f.state().roles.has(injectedId)).toBe(false);
  });

  it.each(['underflow', 'overflow'])('rolls back all approved SQL if captured ID allocation has %s', async variant => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'create', input: { code: 'approved_role', name: 'Approved Role', cluster_id: f.cid, workspace_id: f.wid } }, f.actor, f.tx);
    // Deliberately corrupt the server compiler fixture, preserving its genuine
    // private handle, to exercise the independent SQL allocation guard.
    const altered = { ...capture, allocatedIds: variant === 'underflow' ? [] : [...capture.allocatedIds, randomUUID()] }, original = f.mint(altered), before = structuredClone(f.state());
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, altered, f.actor, tx))).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_ALLOCATION_MISMATCH' } });
    expect(f.state()).toEqual(before);
  });

  it.each(['clone', 'shape', 'revoked'])('refuses a %s execution handle before any IAM business or ledger SQL', async variant => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture), before = structuredClone(f.state());
    if (variant === 'revoked') original.revoke();
    const handle = variant === 'clone' ? structuredClone(original.handle) : variant === 'shape' ? { ...original.binding } : original.handle;
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(handle, capture, f.actor, tx))).rejects.toMatchObject({ response: { code: 'FIXTURE_ORIGINAL_IAM_HANDLE_REQUIRED' } });
    expect(f.state()).toEqual(before); expect(f.sqlWrites).toEqual([]);
  });

  it.each(['request', 'mutation', 'allocatedIds', 'before', 'delegatedGrants', 'affectedScopes'])('refuses changed %s in the captured graph under an original execution handle', async field => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture);
    const altered: any = structuredClone(capture);
    if (field === 'request') altered.request.input.name = 'Injected name';
    if (field === 'mutation') altered.mutation.payload.name = 'Injected name';
    if (field === 'allocatedIds') altered.allocatedIds.push(randomUUID());
    if (field === 'before') altered.before.resource.revision++;
    if (field === 'delegatedGrants') altered.delegatedGrants.push({ module: 'roles', action: 'write', scope_type: 'global', scope_values: [] });
    if (field === 'affectedScopes') altered.affectedScopes.push({ cluster_id: f.cid2, workspace_id: f.wid2 });
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, altered, f.actor, tx))).rejects.toMatchObject({ response: { code: 'FIXTURE_IAM_CAPTURE_MISMATCH' } });
    expect(f.sqlWrites).toEqual([]); expect(f.policy.verify).not.toHaveBeenCalled();
  });

  it.each(['intentId', 'workflowId', 'executionId', 'stepId', 'planRevision', 'planHash', 'clusterId', 'workspaceId', 'actorId', 'sessionId'])('rolls back actual IAM effects when after-verification changes %s', async field => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture), before = structuredClone(f.state());
    f.overrideAfter({ [field]: field === 'planRevision' ? 2 : field === 'planHash' ? 'f'.repeat(64) : randomUUID() });
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx))).rejects.toMatchObject({ response: { code: 'IAM_APPROVED_METADATA_BINDING_INVALID' } });
    expect(f.sqlWrites.some(sql => sql.startsWith('UPDATE roles'))).toBe(true);
    expect(f.state()).toEqual(before);
  });

  it('rolls back business SQL and the IAM ledger if the original grant is revoked during the callback', async () => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture), before = structuredClone(f.state());
    f.audit.append.mockImplementation(async (event: any) => { f.state().audit.push(f.secrets.redact(event)); if (event.action === 'iam.update') original.revoke(); });
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx))).rejects.toMatchObject({ response: { code: 'FIXTURE_ORIGINAL_IAM_HANDLE_REQUIRED' } });
    expect(f.state()).toEqual(before);
  });

  it('rolls back all SQL if terminal approval audit persistence fails', async () => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture), before = structuredClone(f.state());
    f.audit.append.mockImplementation(async (event: any) => { if (event.action === 'iam.write.approved') throw new Error('terminal audit unavailable'); f.state().audit.push(f.secrets.redact(event)); });
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx))).rejects.toThrow('terminal audit unavailable');
    expect(f.state()).toEqual(before);
  });

  it('does not report success or persist mutation facts when terminal IAM ledger CAS updates zero rows', async () => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture), before = structuredClone(f.state());
    const exec = f.tx.exec.getMockImplementation()!;
    f.tx.exec.mockImplementation(async (sql: string, p: any[]) => sql.startsWith('UPDATE iam_operations') ? 0 : exec(sql, p));
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx))).rejects.toThrow();
    expect(f.state()).toEqual(before);
    expect(f.audit.append.mock.calls.some((call: any[]) => call[0].action === 'iam.write.approved')).toBe(false);
  });

  it('rejects a stale resource revision before any approved business update', async () => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture);
    f.state().roles.get(f.rid).revision = 5; const before = structuredClone(f.state());
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx))).rejects.toMatchObject({ response: { code: 'IAM_CHANGED' } });
    expect(f.state()).toEqual(before);
  });

  it('rejects nested capture from inside the original capture async scope', async () => {
    const f = fixture(); f.authz.snapshot.mockImplementationOnce(async () => f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Injected name' } }, f.actor, f.tx));
    await expect(f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx)).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_FIXED_REENTRY' } });
    expect(f.sqlWrites).toEqual([]);
  });

  it('expires an async continuation inherited from capture without allowing a later direct SQL mutation', async () => {
    const f = fixture(); let resume!: () => void, escaped!: Promise<any>;
    const barrier = new Promise<void>(resolve => { resume = resolve; });
    const snapshot = f.authz.snapshot.getMockImplementation()!;
    f.authz.snapshot.mockImplementationOnce(async () => { escaped = (async () => { await barrier; return f.service.update('roles', f.rid, { revision: 4, name: 'Escaped name' }, f.actor); })(); return snapshot(); });
    await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx);
    resume(); await expect(escaped).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_FIXED_OPERATION_REQUIRED' } });
    expect(f.sqlWrites).toEqual([]);
  });

  it('rejects reentry from an approved SQL callback and rolls back the original callback effects', async () => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture), before = structuredClone(f.state());
    f.audit.append.mockImplementation(async (event: any) => { if (event.action === 'iam.update') await f.service.applyApprovedChange(original.handle, capture, f.actor, f.tx); });
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx))).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_FIXED_REENTRY' } });
    expect(f.state()).toEqual(before);
  });

  it('expires a detached async continuation of the actual approved SQL callback', async () => {
    const f = fixture(), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture);
    let resume!: () => void, escaped!: Promise<any>; const barrier = new Promise<void>(resolve => { resume = resolve; });
    f.audit.append.mockImplementation(async (event: any) => { f.state().audit.push(f.secrets.redact(event)); if (event.action === 'iam.update') escaped = (async () => { await barrier; return f.service.update('roles', f.rid, { revision: 5, name: 'Escaped name' }, f.actor); })(); });
    await f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx));
    const before = structuredClone(f.state()), writeCount = f.sqlWrites.length;
    resume(); await expect(escaped).rejects.toMatchObject({ response: { code: 'IAM_WORKFLOW_FIXED_OPERATION_REQUIRED' } });
    expect(f.state()).toEqual(before); expect(f.sqlWrites).toHaveLength(writeCount);
  });

  it('keeps captured plaintext password out of actual IAM ledger, audit storage and public user result', async () => {
    const f = fixture(), password = 'Synthetic-private-user-password', capture = await f.service.captureChange({ resource: 'users', operation: 'create', input: { username: 'new_operator', password, display_name: 'New Operator' } }, f.actor, f.tx), original = f.mint(capture);
    expect(f.sqlWrites).toEqual([]);
    const result = await f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx));
    expect(result.id).toBe(capture.allocatedIds[0]); expect(result).not.toHaveProperty('password_hash');
    expect(JSON.stringify(result)).not.toContain(password);
    const ledger: any = [...f.state().operations.values()][0];
    expect(JSON.stringify(ledger)).not.toContain(password); expect(JSON.stringify(f.state().audit)).not.toContain(password);
    expect(f.secrets.decrypt<any>(ledger.payload_secret, `iam:${ledger.id}:payload`)).toHaveProperty('password', password);
    expect(f.state().users.get(result.id).password_hash).toBe('Synthetic-bcrypt-hash');
  });

  it('keeps the ordinary direct path closed for approval clusters after installing the fixed provider', async () => {
    const f = fixture(); await expect(f.service.update('roles', f.rid, { revision: 4, name: 'Direct bypass' }, f.actor)).rejects.toMatchObject({ response: { code: 'APPROVAL_REQUIRED' } });
    expect(f.policy.verify).not.toHaveBeenCalled(); expect(f.sqlWrites).toEqual([]);
  });

  it('keeps the fixed path closed when no provider is installed', async () => {
    const f = fixture(false), capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture);
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx))).rejects.toMatchObject({ response: { code: 'IAM_APPROVED_METADATA_UNAVAILABLE' } });
    expect(f.sqlWrites).toEqual([]);
    f.mutations.installApprovedMetadataPolicy(f.policy);
    expect(() => f.mutations.installApprovedMetadataPolicy(f.policy)).toThrow();
    f.service.installApprovedChangePolicy(f.changePolicy);
    expect(() => f.service.installApprovedChangePolicy(f.changePolicy)).toThrow();
  });

  it('keeps mutation SQL closed even if only the capture verifier was installed', async () => {
    const f = fixture(false); f.service.installApprovedChangePolicy(f.changePolicy);
    const capture = await f.service.captureChange({ resource: 'roles', operation: 'update', resourceId: f.rid, input: { revision: 4, name: 'Approved name' } }, f.actor, f.tx), original = f.mint(capture);
    await expect(f.db.transaction((tx: any) => f.service.applyApprovedChange(original.handle, capture, f.actor, tx))).rejects.toMatchObject({ response: { code: 'IAM_APPROVED_METADATA_UNAVAILABLE' } });
    expect(f.sqlWrites).toEqual([]);
  });

  it('refuses unexpected functions in the once-installed private capability provider', () => {
    const f = fixture(false);
    expect(() => f.mutations.installApprovedMetadataPolicy({ ...f.policy, approved: () => true } as any)).toThrow();
    expect(() => f.mutations.installApprovedMetadataPolicy({ verify: null } as any)).toThrow();
    expect(() => f.service.installApprovedChangePolicy({ ...f.changePolicy, approved: () => true } as any)).toThrow();
    expect(() => f.service.installApprovedChangePolicy({ verifyCapture: null } as any)).toThrow();
  });
});
