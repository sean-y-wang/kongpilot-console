import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { workspaceFixture, payWorkspaceId } from '../unit/workspace-test-fixture';

const cid = '7530297b-364c-41d9-aeb5-9e2d119843b4';
const id = '9d0043e1-576e-4ad2-a397-2b9da0e6ce11';
const parent = '3f600157-d5bd-4600-a505-381f34321285';
const otherParent = '78aa2f7e-683c-46bf-ae1f-15577727a3f0';
const alice = { id: '75ea1b46-eb04-4b56-8d1d-87b020bdb68a', username: 'alice', superAdmin: true };
const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct' };
const failure = () => new ForbiddenException({ code: 'FIXTURE_CURRENT_GRANT_DENIED' });

// The policy provider and private execution capabilities are real. Current IAM
// rows, recorded operations, raw Kong responses and authorization are controlled
// fixtures; these checks do not claim real DB/network fault injection.
function fixture() {
  const contexts = new KongExecutionContextService(), secrets = new SecretService();
  const state = { revoked: false, platform: false, version: 'current-version', returnedEntityIdRecorded: true };
  const op: any = { id: 'operation-1', cluster_id: cid, workspace_id: payWorkspaceId, actor_id: alice.id, state: 'running', entity_type: 'services', action: 'create', remote_started: true, payload_secret: secrets.encrypt({ name: 'approved-name', host: 'safe.example', tags: ['kos-ws-pay'] }, 'mutation:operation-1:payload') };
  const archive: any = { id: 'entry-1', cluster_id: cid, workspace_id: payWorkspaceId, actor_id: alice.id, mutation_id: op.id, state: 'restoring' };
  const raw = new Map<string, any>([[`/services/${id}`, { id, name: 'approved-name', host: 'safe.example', tags: ['kos-ws-pay'] }], [`/consumers/${parent}`, { id: parent, username: 'parent', tags: ['kos-ws-pay'] }], [`/routes/${parent}`, { id: parent, service: { id }, tags: ['kos-ws-pay'] }], [`/plugins/${parent}`, { id: parent, service: { id }, route: null, consumer: null, tags: ['kos-ws-pay'] }]]);
  const db: any = { one: vi.fn(async (sql: string) => sql.includes('FROM mutation_operations') ? op : sql.includes('FROM recycle_entries') ? archive : null), exec: vi.fn(async () => state.returnedEntityIdRecorded ? 1 : 0) };
  const authz: any = {
    snapshot: vi.fn(async () => ({ user: { ...alice, superAdmin: state.platform }, version: state.version, grants: [{ cluster_id: cid }] })),
    assertCluster: vi.fn(async () => { if (state.revoked) throw failure(); }),
    assertEntity: vi.fn(async () => { if (state.revoked) throw failure(); }),
    assertNestedParentScope: vi.fn(async () => { if (state.revoked) throw failure(); }),
    filterEntities: vi.fn(async (_actor: unknown, _cid: string, _type: string, items: any[]) => state.revoked ? [] : items.filter(item => item.id === id)),
    permissionVersion: vi.fn(async () => state.version),
    hasWholeCluster: vi.fn(async () => (state as any).wholeCluster === true),
  };
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => { if (method !== 'GET') throw new Error('native write is outside this policy-only fixture'); return raw.get(path) ?? { id: path.split('/').at(-1), tags: ['kos-ws-pay'] }; }) };
  const ws = workspaceFixture(cid);
  const policy = new NativeKongPolicyService(db, secrets, kong, contexts, authz, ws.resolver);
  policy.install();
  const run = <T>(fn: () => Promise<T>, operation = false) => contexts.runHttp({}, async () => {
    contexts.bindHttpActor(alice, 'validated-session'); const close = contexts.captureHttpCloser();
    try { return await contexts.runActor({ actor: alice, clusterId: cid, workspaceId: payWorkspaceId, module: op.entity_type, action: operation ? op.action : 'read' }, () => operation ? contexts.runOperation({ actor: alice, clusterId: cid, workspaceId: payWorkspaceId, operationId: op.id, entityType: op.entity_type, action: op.action, parentId: op.parent_id, credentialKind: op.credential_kind }, fn) : fn()); }
    finally { close(); }
  });
  const payload = (value: unknown) => { op.payload_secret = secrets.encrypt(value, `mutation:${op.id}:payload`); };
  return { contexts, policy, state, op, archive, raw, db, authz, kong, secrets, run, payload };
}
beforeEach(() => { vi.stubEnv('APP_SECRET', 'independent-policy-fixture-private-key-minimum-32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'de'.repeat(32)); });
afterEach(() => vi.unstubAllEnvs());

describe('M4 independent native provider durable authorization', () => {
  it('uses the current trusted platform flag rather than cached actor.superAdmin', async () => {
    const f = fixture();
    await f.run(async () => {
      const ticket = await f.contexts.authorizeRequest(cluster, 'GET', `/services/${id}`, undefined, {});
      expect(f.contexts.current().actor?.superAdmin).toBe(true);
      expect(f.contexts.verifiedPlatformAdmin(ticket)).toBe(false);
      await f.contexts.authorizeResponse(ticket, f.raw.get(`/services/${id}`));
    });
  });
  it('allows a global credential collection read only to platform or whole-cluster Consumer+credential readers and never for writes', async () => {
    const f = fixture();
    await f.run(async () => {
      await expect(f.contexts.authorizeRequest(cluster, 'GET', '/key-auths', undefined, { size: 100 })).rejects.toMatchObject({ response: { code: 'KONG_GLOBAL_CREDENTIAL_LIST_FORBIDDEN' } });
      (f.state as any).wholeCluster = true;
      const ticket = await f.contexts.authorizeRequest(cluster, 'GET', '/key-auths', undefined, { size: 100 });
      expect(f.authz.hasWholeCluster).toHaveBeenCalledWith(expect.anything(), cid, 'consumers', 'read');
      expect(f.authz.hasWholeCluster).toHaveBeenCalledWith(expect.anything(), cid, 'key-auth', 'read');
      await expect(f.contexts.authorizeResponse(ticket, { data: [{ id, key: 'k' }], next: null })).rejects.toMatchObject({ response: { code: 'KONG_PARENT_MISMATCH' } });
    });
    await f.run(async () => { await expect(f.contexts.authorizeRequest(cluster, 'POST', '/key-auths', { key: 'x' }, {})).rejects.toBeTruthy(); });
  });
  it('rejects plain fabricated policy decisions even if all visible fields look valid', async () => {
    const f = fixture();
    await expect(f.policy.authorizeResponse({ kind: 'private', platformAdmin: true, frame: { actor: alice } }, { secret: 'must-not-return' })).rejects.toMatchObject({ response: { code: 'KONG_POLICY_TICKET_INVALID' } });
  });
  it.each(['succeeded', 'uncertain', 'failed'])('rejects a non-running durable operation in state %s before authorizing a write', async state => {
    const f = fixture(); f.op.state = state;
    await expect(f.run(() => f.contexts.authorizeRequest(cluster, 'POST', '/services', { name: 'approved-name', host: 'safe.example', tags: ['kos-ws-pay'] }, {}), true)).rejects.toMatchObject({ response: { code: 'KONG_NATIVE_OPERATION_INVALID' } });
    expect(f.authz.assertEntity).not.toHaveBeenCalled();
  });
  it('requires durable actor and remote-started proof instead of trusting factory metadata', async () => {
    for (const change of [{ actor_id: 'other-actor' }, { remote_started: false }, { workspace_id: 'foreign-workspace' }]) {
      const f = fixture(); Object.assign(f.op, change);
      await expect(f.run(() => f.contexts.authorizeRequest(cluster, 'POST', '/services', {}, {}), true)).rejects.toMatchObject({ response: { code: 'KONG_NATIVE_OPERATION_INVALID' } });
    }
  });
  it('rejects an actual create payload that differs from the encrypted durable approval payload', async () => {
    const f = fixture();
    await expect(f.run(() => f.contexts.authorizeRequest(cluster, 'POST', '/services', { name: 'approved-name', host: 'different.example', tags: ['kos-ws-pay'] }, {}), true)).rejects.toMatchObject({ response: { code: 'KONG_OPERATION_PAYLOAD_MISMATCH' } });
    expect(f.authz.assertEntity).not.toHaveBeenCalled();
  });
  it('rejects nested credential transport under a different durable parent even when policy would permit both parents', async () => {
    const f = fixture(); Object.assign(f.op, { entity_type: 'credentials', parent_id: parent, credential_kind: 'key-auth' }); f.payload({ key: 'synthetic-private-value', tags: ['kos-ws-pay'] });
    await expect(f.run(() => f.contexts.authorizeRequest(cluster, 'POST', `/consumers/${otherParent}/key-auth`, { key: 'synthetic-private-value', tags: ['kos-ws-pay'] }, {}), true)).rejects.toMatchObject({ response: { code: 'KONG_OPERATION_PARENT_MISMATCH' } });
    expect(f.authz.assertEntity).not.toHaveBeenCalled();
  });
  it('authorizes relation parent and returned actual type separately', async () => {
    for (const rootType of ['routes', 'plugins']) {
      const f = fixture();
      await f.run(async () => {
        const ticket = await f.contexts.authorizeRequest(cluster, 'GET', `/${rootType}/${parent}/service`, undefined, {});
        await f.contexts.authorizeResponse(ticket, f.raw.get(`/services/${id}`));
      });
      expect(f.authz.assertEntity.mock.calls.some(call => call[2] === rootType && call[4].id === parent)).toBe(true);
      expect(f.authz.assertEntity.mock.calls.some(call => call[2] === 'services' && call[4].id === id)).toBe(true);
      expect(f.authz.assertEntity.mock.calls.some(call => call[2] === rootType && call[4].id === id)).toBe(false);
    }
  });
  it('checks each actual child and filters native totals after a fresh list authorization', async () => {
    const f = fixture();
    await f.run(async () => {
      const ticket = await f.contexts.authorizeRequest(cluster, 'GET', '/services', undefined, { size: 2 });
      const result = await f.contexts.authorizeResponse(ticket, { data: [{ id, tags: ['kos-ws-pay'] }, { id: otherParent, tags: ['kos-ws-pay'] }], total: 2 });
      expect(result.data.map((item: any) => item.id)).toEqual([id]); expect(result.total).toBeNull(); expect(result.console_permission_projection).toBe(true);
    });
  });
  it('rechecks permission after the native read and denies a newly revoked entity', async () => {
    const f = fixture();
    await f.run(async () => {
      const ticket = await f.contexts.authorizeRequest(cluster, 'GET', `/services/${id}`, undefined, {});
      f.state.revoked = true;
      await expect(f.contexts.authorizeResponse(ticket, f.raw.get(`/services/${id}`))).rejects.toMatchObject({ response: { code: 'FIXTURE_CURRENT_GRANT_DENIED' } });
    });
  });
  it('marks a write response unknown if authorization is revoked after the remote write', async () => {
    const f = fixture();
    await f.run(async () => {
      const ticket = await f.contexts.authorizeRequest(cluster, 'POST', '/services', { name: 'approved-name', host: 'safe.example', tags: ['kos-ws-pay'] }, {});
      f.state.revoked = true;
      await expect(f.contexts.authorizeResponse(ticket, f.raw.get(`/services/${id}`))).rejects.toMatchObject({ response: { code: 'KONG_WRITE_RESULT_UNKNOWN' } });
    }, true);
  });
  it('rejects changed restore contents despite a matching original ID and authorized actor', async () => {
    const f = fixture(); Object.assign(f.op, { action: 'restore', entity_type: 'recycle_entries' }); f.payload({ entryId: f.archive.id });
    const body = { id, name: 'approved-name', host: 'safe.example', tags: ['kos-ws-pay'] };
    f.archive.payload_secret = f.secrets.encrypt({ complete: true, nodes: [{ affected: true, type: 'services', id, path: `/services/${id}`, data: { ...body, created_at: 1 } }] }, `recycle:${f.archive.id}`);
    // Recycle entries use a native operation scope typed as its restored root.
    f.op.entity_type = 'services';
    await expect(f.run(() => f.contexts.authorizeRequest(cluster, 'POST', '/services', { ...body, host: 'tampered.example' }, {}), true)).rejects.toMatchObject({ response: { code: 'KONG_OPERATION_PAYLOAD_MISMATCH' } });
  });
  it('requires successful compare-and-set when recording a newly created native ID', async () => {
    const f = fixture(); f.state.returnedEntityIdRecorded = false;
    await f.run(async () => {
      const ticket = await f.contexts.authorizeRequest(cluster, 'POST', '/services', { name: 'approved-name', host: 'safe.example', tags: ['kos-ws-pay'] }, {});
      await expect(f.contexts.authorizeResponse(ticket, f.raw.get(`/services/${id}`))).rejects.toMatchObject({ response: { code: 'KONG_WRITE_RESULT_UNKNOWN' } });
    }, true);
    expect(f.db.exec).toHaveBeenCalledTimes(1);
  });
});
