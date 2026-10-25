import { afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { EntityAnnotationsService, type EntityAnnotationRow } from '../../apps/console-api/src/modules/workspaces/entity-annotations.service';
import { EntityAnnotationsController } from '../../apps/console-api/src/modules/workspaces/entity-annotations.controller';
import { MutationService } from '../../apps/console-api/src/modules/mutations/mutation.service';
import { executionFixture } from './execution-test-fixture';

const cid = randomUUID(), otherCid = randomUUID(), workspaceId = randomUUID(), otherWorkspaceId = randomUUID(), defaultWorkspaceId = randomUUID();
const user = { id: randomUUID(), username: 'operator', superAdmin: true };
const actor = { user, requestId: 'annotations-request', ip: '127.0.0.1', idempotencyKey: 'annotations-create' };
const entityId = randomUUID(), ownerId = randomUUID();

function fixture() {
  const entity = { id: entityId, name: 'orders', host: 'orders.internal', tags: ['kos-ws-orders', 'team:orders'] };
  const rows = new Map<string, EntityAnnotationRow>();
  const owners = new Map<string, string>([[ownerId, 'active']]);
  const key = (cluster: string, type: string, id: string) => `${cluster}:${type}:${id}`;
  const db: any = {
    one: vi.fn(async (sql: string, p: any[]) => {
      if (sql.includes('FROM clusters')) return { id: p[0], version: '1.5.1', execution_mode: 'direct' };
      if (sql.includes('FROM users')) return owners.get(p[0]) === 'active' ? { id: p[0] } : null;
      const current = rows.get(key(p[0], p[1], p[2]));
      if (sql.startsWith('SELECT') && sql.includes('FROM entity_annotations')) return current ? structuredClone(current) : null;
      if (sql.startsWith('INSERT INTO entity_annotations')) {
        if (current) return null;
        const row: EntityAnnotationRow = { cluster_id: p[0], entity_type: p[1], kong_id: p[2], description: p[3],
          owner_user_id: p[4], metadata: JSON.parse(p[5]), revision: 1, status: 'active', deleted_at: null,
          retention_until: null, created_at: new Date(), updated_at: new Date() };
        rows.set(key(p[0], p[1], p[2]), row);
        return structuredClone(row);
      }
      if (sql.startsWith('UPDATE entity_annotations')) {
        const revision = sql.includes('description=$4') ? p[6] : p[3];
        if (!current || current.revision !== revision) return null;
        if (sql.includes('description=$4')) {
          if (current.status !== 'active') return null;
          Object.assign(current, { description: p[3], owner_user_id: p[4], metadata: JSON.parse(p[5]) });
        } else if (sql.includes("SET status='deleted'")) {
          if (current.status !== 'active') return null;
          Object.assign(current, { status: 'deleted', deleted_at: new Date(), retention_until: new Date(Date.now() + p[4] * 86400000) });
        } else {
          if (current.status !== 'deleted') return null;
          Object.assign(current, { status: 'active', deleted_at: null, retention_until: null });
        }
        current.revision++;
        current.updated_at = new Date();
        return structuredClone(current);
      }
      throw new Error(`Unexpected SQL: ${sql}`);
    }),
    query: vi.fn(async (_sql: string, p: any[]) => [...rows.values()].filter(row => row.cluster_id === p[0] && row.entity_type === p[1] && p[2].includes(row.kong_id)).map(row => structuredClone(row))),
    exec: vi.fn(async () => 1),
  };
  db.transaction = vi.fn(async (fn: any) => {
    const snapshot = structuredClone(rows);
    try { return await fn(db); } catch (error) { rows.clear(); for (const [id, row] of snapshot) rows.set(id, row); throw error; }
  });
  const kong: any = { request: vi.fn(async (cluster: string, method: string, path: string) => {
    if (cluster !== cid) throw new NotFoundException('Kong entity is absent in this cluster');
    if (method !== 'GET') throw new Error('Annotations cannot write native Kong fields');
    if (path !== `/services/${entity.id}` && path !== '/services/orders') throw new NotFoundException('Kong entity missing');
    return structuredClone(entity);
  }) };
  const authz: any = { assertCluster: vi.fn(async () => undefined), assertEntity: vi.fn(async () => undefined),
    snapshot:vi.fn(async()=>({user,grants:[],version:'annotation-permission-1'})) };
  const resolver: any = {
    resolve: vi.fn(async (_cluster: string, wid?: string) => ({ id: wid ?? defaultWorkspaceId, status: 'active' })),
    listScope: vi.fn(async (_cluster: string, wid?: string) => ({ workspaceId: wid ?? defaultWorkspaceId,
      workspaceTag: wid === workspaceId ? 'kos-ws-orders' : wid === otherWorkspaceId ? 'kos-ws-payments' : null,
      workspaceRevision: 1, mode: 'workspace', requestedTags: [], tagOperator: 'and', requiresPostFilter: false, binding: {} })),
    assertMembership: vi.fn(async (scope: any, candidate: any) => {
      const workspaceTags = (candidate.tags ?? []).filter((tag: string) => tag.startsWith('kos-ws-'));
      if (scope.workspaceTag ? !workspaceTags.includes(scope.workspaceTag) : workspaceTags.length > 0) {
        throw new ForbiddenException({ code: 'WORKSPACE_ENTITY_MISMATCH', message: 'Entity is outside this workspace' });
      }
    }),
  };
  const mutations: any = { execute: vi.fn(async (_context: any, fn: any) => fn()) };
  const audit: any = { append: vi.fn(async () => undefined) };
  const execution=executionFixture();execution.runActor=vi.fn(execution.runActor);execution.runInternalRead=vi.fn(execution.runInternalRead);
  const service = new EntityAnnotationsService(db, kong, authz, mutations, audit, resolver,execution);
  const create = (input: any = { revision: 0, description: 'Order service', owner_user_id: ownerId, metadata: { runbook: 'https://internal/orders' } }) => service.set(cid, 'services', entityId, input, actor, workspaceId);
  const confirm = (revision: number) => ({ revision, confirmed: true as const, confirm_name: 'orders' });
  return { service, db, kong, authz, resolver, mutations, audit, rows, owners, entity, create, confirm, key,execution };
}

afterEach(() => vi.unstubAllEnvs());

describe('Entity annotations scope, concurrency and soft recovery', () => {
  it('returns revision-zero metadata without persisting or exposing the native entity', async () => {
    const f = fixture();
    const value = await f.service.get(cid, 'services', 'orders', actor, workspaceId);
    expect(value).toMatchObject({ kong_id: entityId, revision: 0, description: '', metadata: {}, status: 'active' });
    expect(value).not.toHaveProperty('host');
    expect(f.rows.size).toBe(0);
    expect(f.authz.assertEntity).toHaveBeenCalledWith(user, cid, 'services', 'read', f.entity, workspaceId);
    expect(f.resolver.assertMembership).toHaveBeenCalled();
  });

  it('requires both cluster and real entity permissions before reading annotations', async () => {
    const f = fixture();
    f.authz.assertCluster.mockRejectedValueOnce(new ForbiddenException());
    await expect(f.service.get(cid, 'services', entityId, actor, workspaceId)).rejects.toMatchObject({ status: 403 });
    expect(f.kong.request).not.toHaveBeenCalled();
    f.authz.assertEntity.mockRejectedValueOnce(new ForbiddenException());
    await expect(f.service.get(cid, 'services', entityId, actor, workspaceId)).rejects.toMatchObject({ status: 403 });
    expect(f.db.one).not.toHaveBeenCalled();
  });

  it('rejects cross-workspace and cross-cluster IDs without returning stored annotation content', async () => {
    const f = fixture(); await f.create();
    await expect(f.service.get(cid, 'services', entityId, actor, otherWorkspaceId)).rejects.toMatchObject({ status: 403 });
    await expect(f.service.get(otherCid, 'services', entityId, actor, workspaceId)).rejects.toMatchObject({ status: 404 });
    expect(f.rows.size).toBe(1);
  });

  it('uses the default workspace when none is selected, including historical untagged entities', async () => {
    const f = fixture();
    await expect(f.service.get(cid, 'services', entityId, actor)).rejects.toMatchObject({ status: 403 });
    f.entity.tags = ['team:orders'];
    expect((await f.service.get(cid, 'services', entityId, actor)).revision).toBe(0);
    expect(f.resolver.listScope).toHaveBeenLastCalledWith(cid, undefined);
  });

  it('canonicalizes name aliases to the real UUID and writes only console metadata with atomic audit', async () => {
    const f = fixture();
    const value = await f.service.set(cid, 'services', 'orders', { revision: 0, description: 'Order service', metadata: { owner: 'business' } }, actor, workspaceId);
    expect(value).toMatchObject({ kong_id: entityId, revision: 1, description: 'Order service' });
    expect(f.kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
    expect(f.mutations.execute.mock.calls[0][0]).toMatchObject({ entityType: 'annotations', entityId, actor: user,
      before: f.entity, payload: { entityType: 'services', entityId, workspaceId }, idempotencyKey: actor.idempotencyKey });
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'annotation.metadata.created', before: null,
      after: value, workspaceId }), f.db);
  });

  it('enforces revision-zero create and exact update CAS, preserving omitted fields', async () => {
    const f = fixture();
    await expect(f.create({ revision: 4, description: 'stale create' })).rejects.toMatchObject({ status: 409 });
    const initial = await f.create();
    const updated = await f.service.set(cid, 'services', entityId, { revision: initial.revision, description: 'Revised description' }, actor, workspaceId);
    expect(updated).toMatchObject({ revision: 2, description: 'Revised description', owner_user_id: ownerId, metadata: initial.metadata });
    await expect(f.service.set(cid, 'services', entityId, { revision: 1, metadata: { lost: true } }, actor, workspaceId)).rejects.toMatchObject({ status: 409 });
    expect((await f.service.get(cid, 'services', entityId, actor, workspaceId)).metadata).toEqual(initial.metadata);
  });

  it('does not commit metadata if its same-transaction audit cannot be appended', async () => {
    const f = fixture();
    f.audit.append.mockRejectedValueOnce(new Error('Audit unavailable'));
    await expect(f.create()).rejects.toThrow('Audit unavailable');
    expect(f.rows.size).toBe(0);
  });

  it('rejects absent or disabled owners and allows explicit clearing of an existing owner', async () => {
    const f = fixture();
    await expect(f.create({ revision: 0, owner_user_id: randomUUID() })).rejects.toMatchObject({ status: 400 });
    f.owners.set(ownerId, 'disabled');
    await expect(f.create()).rejects.toMatchObject({ status: 400 });
    expect(f.rows.size).toBe(0);
    f.owners.set(ownerId, 'active');
    await f.create();
    const updated = await f.service.set(cid, 'services', entityId, { revision: 1, owner_user_id: null }, actor, workspaceId);
    expect(updated.owner_user_id).toBeNull();
  });

  it.each([
    { revision: 0, description: 'x'.repeat(8193) },
    { revision: 0, metadata: { oversized: '汉'.repeat(22000) } },
    { revision: 0, metadata: JSON.parse('{"nested":{"__proto__":{"injected":true}}}') },
    { revision: 0, metadata: { constructor: 'reserved' } },
    { revision: 0, metadata: [] },
    { revision: 0, owner_user_id: 'not-a-uuid' },
    { revision: '0', metadata: {} },
    { revision: -1 },
    { revision: 0, tags: ['kos-ws-payments'] },
    { revision: 0, entity_type: 'consumers' },
  ])('rejects invalid input before mutation or native entity requests (%j)', async input => {
    const f = fixture();
    await expect(f.create(input)).rejects.toMatchObject({ status: 400 });
    expect(f.mutations.execute).not.toHaveBeenCalled();
    expect(f.kong.request).not.toHaveBeenCalled();
    expect(f.rows.size).toBe(0);
  });

  it('bounds nested metadata and rejects cycles and non-JSON values', async () => {
    const f = fixture();
    const deep: any = {}; let nested = deep;
    for (let depth = 0; depth < 21; depth++) nested = nested.child = {};
    const cyclic: any = {}; cyclic.self = cyclic;
    for (const metadata of [deep, cyclic, { unavailable: undefined }, { number: Infinity }, { timestamp: new Date() }]) {
      await expect(f.create({ revision: 0, metadata })).rejects.toMatchObject({ status: 400 });
    }
    expect(f.rows.size).toBe(0);
  });

  it('requires typed second confirmation and retains payload through delete and explicit CAS restore', async () => {
    vi.stubEnv('RECYCLE_RETENTION_DAYS', '7');
    const f = fixture(), initial = await f.create();
    await expect(f.service.remove(cid, 'services', entityId, { ...f.confirm(1), confirm_name: 'wrong' }, actor, workspaceId)).rejects.toMatchObject({ status: 400 });
    await expect(f.service.remove(cid, 'services', entityId, { ...f.confirm(1), confirmed: false } as any, actor, workspaceId)).rejects.toMatchObject({ status: 400 });
    const deleted = await f.service.remove(cid, 'services', entityId, f.confirm(1), actor, workspaceId);
    expect(deleted).toMatchObject({ revision: 2, status: 'deleted', metadata: initial.metadata, description: initial.description, owner_user_id: ownerId });
    expect(Date.parse(String(deleted.retention_until)) - Date.parse(String(deleted.deleted_at))).toBeGreaterThan(6 * 86400000);
    await expect(f.service.set(cid, 'services', entityId, { revision: 2, description: 'implicit resurrection' }, actor, workspaceId)).rejects.toMatchObject({ status: 409 });
    await expect(f.service.restore(cid, 'services', entityId, f.confirm(1), actor, workspaceId)).rejects.toMatchObject({ status: 409 });
    const restored = await f.service.restore(cid, 'services', entityId, f.confirm(2), actor, workspaceId);
    expect(restored).toMatchObject({ revision: 3, status: 'active', deleted_at: null, retention_until: null, metadata: initial.metadata });
    expect(f.rows.size).toBe(1);
    expect(f.audit.append.mock.calls.map((call: any[]) => call[0].action)).toEqual(['annotation.metadata.created', 'annotation.metadata.deleted', 'annotation.metadata.restored']);
    expect(f.db.one.mock.calls.some((call: any[]) => /^DELETE/i.test(call[0]))).toBe(false);
  });

  it('rechecks membership and permissions after entering the serialized mutation callback', async () => {
    const f = fixture();
    f.mutations.execute.mockImplementationOnce(async (_context: any, fn: any) => { f.entity.tags = ['kos-ws-payments']; return fn(); });
    await expect(f.create()).rejects.toMatchObject({ status: 403 });
    expect(f.rows.size).toBe(0);
    expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('uses the real MutationService approval gate, performing no metadata writes', async () => {
    const f = fixture(), normal = f.db.one.getMockImplementation()!;
    Object.assign(f.kong,{transportScope:vi.fn().mockResolvedValue('a'.repeat(64))});
    f.db.one.mockImplementation(async (sql: string, p: any[]) => sql.includes('FROM clusters')
      ? { id: cid, version: '1.5.1', execution_mode: 'approval' } : normal(sql, p));
    const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()) };
    const secrets: any = { fingerprint: vi.fn(() => 'request-hash') };
    const realMutation = new MutationService(f.db, redis, secrets, f.audit, f.kong, f.authz, f.resolver, executionFixture());
    const service = new EntityAnnotationsService(f.db, f.kong, f.authz, realMutation, f.audit, f.resolver,f.execution);
    await expect(service.set(cid, 'services', entityId, { revision: 0, description: 'Cannot bypass approval' }, actor, workspaceId))
      .rejects.toMatchObject({ status: 409, response: { code: 'APPROVAL_REQUIRED' } });
    expect(f.rows.size).toBe(0);
    expect(f.db.transaction).not.toHaveBeenCalled();
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({ result: 'blocked_approval_required' }));
  });

  it('does not expose metadata for a Kong entity that has disappeared, even while its annotation remains', async () => {
    const f = fixture(); await f.create();
    f.kong.request.mockRejectedValueOnce(new NotFoundException());
    await expect(f.service.get(cid, 'services', entityId, actor, workspaceId)).rejects.toMatchObject({ status: 404 });
    expect(f.rows.size).toBe(1);
  });

  it('bounds getMany and validates every returned entity scope before a parameterized batch lookup', async () => {
    const f = fixture(); await f.create();
    const result = await f.service.getMany(cid, 'services', [f.entity], { ...actor, workspaceId });
    expect(result[entityId]).toMatchObject({ revision: 1, description: 'Order service' });
    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(f.db.query).toHaveBeenCalledWith(expect.stringContaining('kong_id=ANY($3::uuid[])'), [cid, 'services', [entityId]]);
    await expect(f.service.getMany(cid, 'services', Array.from({ length: 101 }, () => f.entity), { ...actor, workspaceId })).rejects.toMatchObject({ status: 400 });
    await expect(f.service.getMany(cid, 'services', [f.entity], { ...actor, workspaceId: otherWorkspaceId })).rejects.toMatchObject({ status: 403 });
    f.authz.assertEntity.mockRejectedValueOnce(new ForbiddenException());
    await expect(f.service.getMany(cid, 'services', [f.entity], { ...actor, workspaceId })).rejects.toMatchObject({ status: 403 });
  });

  it('rejects unsupported entity endpoints and conflicting caller workspace contexts', async () => {
    const f = fixture();
    await expect(f.service.get(cid, 'vaults', entityId, actor, workspaceId)).rejects.toMatchObject({ status: 400 });
    await expect(f.service.get(cid, 'services', '../consumers', actor, workspaceId)).rejects.toMatchObject({ status: 400 });
    await expect(f.service.get(cid, 'services', entityId, { ...actor, workspaceId }, otherWorkspaceId)).rejects.toMatchObject({ status: 400 });
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('privately reads exact identity for annotation writes without requiring public native read permission', async () => {
    const f=fixture();let purpose:string|undefined;
    f.execution.runInternalRead.mockImplementation(async(_cid:string,next:string,fn:any)=>{const prior=purpose;purpose=next;try{return await fn();}finally{purpose=prior;}});
    f.kong.request.mockImplementation(async()=>{if(purpose!=='entity-preflight')throw new ForbiddenException();return structuredClone(f.entity);});
    const written=await f.create();expect(written.revision).toBe(1);
    expect(f.execution.runActor).toHaveBeenCalledWith(expect.objectContaining({actor:user,clusterId:cid,workspaceId,module:'annotations',action:'write'}),expect.any(Function));
    expect(f.execution.runInternalRead).toHaveBeenCalledWith(cid,'entity-preflight',expect.any(Function),expect.objectContaining({paths:[`/services/${entityId}`],maxCalls:1,maxRecords:1,workspaceId}));
    expect(f.authz.assertEntity.mock.calls.every((call:any[])=>call[2]==='services'&&call[3]==='write')).toBe(true);
    await expect(f.service.get(cid,'services',entityId,actor,workspaceId)).rejects.toMatchObject({status:403});
  });

  it('checks annotations module/action/cluster/workspace/tags/typed entity as complete grants, even with a stale admin claim', async () => {
    const f=fixture(),currentUser={...user,superAdmin:false};
    const allowed={module:'annotations',action:'write',scope_type:'entity',cluster_id:cid,workspace_id:workspaceId,scope_values:[{entity_type:'services',entity_id:entityId}]};
    const invalid=[{...allowed,module:'services'},{...allowed,action:'read'},{...allowed,cluster_id:otherCid},
      {...allowed,workspace_id:otherWorkspaceId},{...allowed,scope_values:[{entity_type:'routes',entity_id:entityId}]},
      {...allowed,scope_type:'tag_group',scope_values:['team-unrelated']},
      {...allowed,scope_type:'workspace',scope_values:[otherWorkspaceId]}];
    for(const grant of invalid){
      f.authz.snapshot.mockResolvedValue({user:currentUser,grants:[grant],version:'changed'});
      await expect(f.create()).rejects.toMatchObject({status:403,response:{code:'PERMISSION_DENIED'}});
    }
    f.authz.snapshot.mockResolvedValue({user:currentUser,grants:[invalid[1],invalid[2]],version:'mixed'});
    await expect(f.create()).rejects.toMatchObject({status:403});expect(f.rows.size).toBe(0);expect(f.mutations.execute).not.toHaveBeenCalled();
    f.authz.snapshot.mockResolvedValue({user:currentUser,grants:[allowed],version:'permitted'});
    expect((await f.create()).revision).toBe(1);
  });

  it('rechecks current annotation grants inside mutation lock and denies revoked permission before metadata SQL', async () => {
    const f=fixture(),grant={module:'annotations',action:'write',scope_type:'entity',cluster_id:cid,workspace_id:workspaceId,scope_values:[{entity_type:'services',entity_id:entityId}]};
    f.authz.snapshot.mockResolvedValue({user:{...user,superAdmin:false},grants:[grant],version:'before'});
    f.mutations.execute.mockImplementation(async(_ctx:any,fn:any)=>{f.authz.snapshot.mockResolvedValue({user:{...user,superAdmin:false},grants:[],version:'revoked'});return fn();});
    await expect(f.create()).rejects.toMatchObject({status:403});expect(f.db.transaction).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();
  });

  it('rejects a different native UUID returned by an exact annotation preflight without any metadata write', async () => {
    const f=fixture();f.kong.request.mockResolvedValue({...f.entity,id:randomUUID()});
    await expect(f.create()).rejects.toMatchObject({response:{code:'INVALID_KONG_ENTITY'}});
    expect(f.rows.size).toBe(0);expect(f.mutations.execute).not.toHaveBeenCalled();
  });

  it('controller propagates scope and mutation metadata without putting Kong fields into annotation payloads', async () => {
    const service: any = { get: vi.fn(), set: vi.fn(), remove: vi.fn(), restore: vi.fn() };
    const controller = new EntityAnnotationsController(service), body = { revision: 0, description: 'Test' };
    controller.set(cid, 'services', entityId, body, workspaceId, 'controller-key', actor);
    expect(service.set).toHaveBeenCalledWith(cid, 'services', entityId, body,
      { user, requestId: actor.requestId, ip: actor.ip, idempotencyKey: 'controller-key' }, workspaceId);
    controller.restore(cid, 'services', entityId, { revision: 1, confirmed: true, confirm_name: 'orders' }, workspaceId, 'restore-key', actor);
    expect(service.restore).toHaveBeenCalledWith(cid, 'services', entityId, expect.objectContaining({ revision: 1 }), expect.objectContaining({ idempotencyKey: 'restore-key' }), workspaceId);
  });
});
