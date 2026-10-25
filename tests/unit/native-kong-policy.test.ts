import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { DEFAULT_WORKSPACE_ID as wid, workspaceTestResolver } from './workspace-test-helper';

// Real execution capabilities, native policy, encrypted ledger payloads and
// resolver; AuthorizationService alone is an explicit synthetic grant fixture.
// These tests establish native-policy invariants, not real DB/RBAC integration.
const cid = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const oid = '414191a0-90c2-4cf0-b2cc-ad5ab2668949';
const sid = '83b737fc-f02f-4dc3-b5f0-470fdb4c82c7';
const parentId = 'd0350b4a-f011-4c8a-9eb3-5e65479e4d6b';
const childId = '109621c2-cf81-4e25-b87b-4cdecc148ad5';
const entryId = 'b06ca9f4-98cf-49de-aa71-f58220d5375b';
const actor = { id: 'a35313a2-9968-4818-9f31-7b3066ce1728', username: 'native-policy-test', superAdmin: true };
const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct' };

describe('M4 independent native policy durable execution and response invariants', () => {
  let execution: KongExecutionContextService, policy: NativeKongPolicyService, secrets: SecretService;
  let db: any, kong: any, authz: any, op: any, entry: any, remote: Map<string, any>, platform: boolean, epoch: string;
  const encryptPayload = (body: any) => { op.payload_secret = secrets.encrypt(body, `mutation:${oid}:payload`); };
  const encryptBefore = (before: any) => { op.before_secret = secrets.encrypt(before, `mutation:${oid}:before`); };
  const graph = (nodes: any[]) => { entry.payload_secret = secrets.encrypt({ complete: true, purpose: 'recycle', nodes }, `recycle:${entryId}`); };
  const run = <T>(fn: () => Promise<T>, module = 'services', action = 'write'): Promise<T> => execution.runHttp({ requestId: 'native-policy-test' }, async () => {
    execution.bindHttpActor(actor, 'synthetic-validated-session');
    const close = execution.captureHttpCloser();
    try { return await execution.runActor({ actor, clusterId: cid, workspaceId: wid, module, action }, fn); }
    finally { close(); }
  });
  const operation = <T>(fn: () => Promise<T>) => run(() => execution.runOperation({ actor, clusterId: cid, workspaceId: wid, operationId: oid, entityType: op.entity_type, entityId: op.entity_id, action: op.action, parentId: op.parent_id, credentialKind: op.credential_kind }, fn));
  const request = (method: string, path: string, body?: any) => execution.authorizeRequest(cluster, method, path, body, {});
  const refused = (promise: Promise<any>, code: string) => expect(promise).rejects.toMatchObject({ response: { code } });

  beforeEach(() => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); secrets = new SecretService();
    platform = true; epoch = 'epoch-1'; execution = new KongExecutionContextService();
    op = { id: oid, cluster_id: cid, actor_id: actor.id, workspace_id: wid, state: 'running', remote_started: true, entity_type: 'services', entity_id: sid, action: 'update' };
    entry = { id: entryId, cluster_id: cid, actor_id: actor.id, workspace_id: wid, mutation_id: oid, state: 'restoring' };
    remote = new Map([[`/services/${sid}`, { id: sid, name: 'service', host: 'business.test', tags: [] }], [`/consumers/${parentId}`, { id: parentId, username: 'parent', tags: [] }], [`/upstreams/${parentId}`, { id: parentId, name: 'upstream', tags: [] }]]);
    db = { one: vi.fn(async (sql: string, params: any[]) => {
      if (sql.includes('mutation_operations')) return params[0] === op.id ? op : null;
      if (sql.includes('recycle_entries')) return params[1] === entry.id ? entry : null;
      return null;
    }), exec: vi.fn(async (_sql: string, params: any[]) => {
      if (op.state !== 'running' || op.entity_id && op.entity_id !== params[4]) return 0;
      op.entity_id = params[4]; return 1;
    }) };
    authz = { snapshot: vi.fn(async () => ({ user: { ...actor, superAdmin: platform }, grants: [{ cluster_id: cid }], version: epoch })),
      assertCluster: vi.fn(), assertEntity: vi.fn(), assertNestedParentScope: vi.fn(), assertMigrationEntity: vi.fn(),
      permissionVersion: vi.fn(async () => epoch), filterEntities: vi.fn(async (_u, _c, _t, items) => items.filter((item: any) => item.id !== 'denied')) };
    kong = { request: vi.fn(async (_cid: string, method: string, path: string, body?: any, query = {}) => {
      const ticket = await execution.authorizeRequest(cluster, method, path, body, query);
      if (!remote.has(path)) throw new NotFoundException();
      return execution.authorizeResponse(ticket, structuredClone(remote.get(path)));
    }), list: vi.fn(async (_cid: string, path: string, query: any) => {
      const result = await kong.request(cid, 'GET', path, undefined, query);
      return { items: result.data, nextCursor: null, size: query.size };
    }) };
    policy = new NativeKongPolicyService(db, secrets, kong, execution, authz, workspaceTestResolver(cid).resolver); policy.install();
    encryptPayload({ host: 'updated.business' }); encryptBefore(remote.get(`/services/${sid}`));
  });
  afterEach(() => vi.unstubAllEnvs());

  it('accepts exact encrypted approved payloads and compares object keys canonically', async () => {
    encryptPayload({ host: 'updated.business', name: 'new' });
    await expect(operation(() => request('PATCH', `/services/${sid}`, { name: 'new', host: 'updated.business' }))).resolves.toBeDefined();
  });
  it('rejects payload replacement even if the caller otherwise has permission', async () => {
    await refused(operation(() => request('PATCH', `/services/${sid}`, { host: 'unaudited.business' })), 'KONG_OPERATION_PAYLOAD_MISMATCH');
  });
  it.each([{ state: 'succeeded' }, { remote_started: false }, { actor_id: parentId }, { workspace_id: parentId }])('requires an actual matching running durable operation %j', async patch => {
    Object.assign(op, patch);
    await refused(operation(() => request('PATCH', `/services/${sid}`, { host: 'updated.business' })), 'KONG_NATIVE_OPERATION_INVALID');
  });
  it('fails if the durable operation ID is absent despite a valid server capability', async () => {
    db.one.mockResolvedValue(null);
    await refused(operation(() => request('PATCH', `/services/${sid}`, { host: 'updated.business' })), 'KONG_NATIVE_OPERATION_INVALID');
  });
  it('rejects an unexpected method and exact entity type rather than module aliases', async () => {
    await refused(operation(() => request('PUT', `/services/${sid}`, { host: 'updated.business' })), 'KONG_OPERATION_ACTION_MISMATCH');
    op.entity_type = 'credentials'; op.credential_kind = 'key-auth'; op.parent_id = parentId; op.entity_id = childId;
    await refused(operation(() => request('PATCH', `/consumers/${parentId}/jwt/${childId}`, { host: 'updated.business' })), 'KONG_OPERATION_ENTITY_MISMATCH');
  });
  it('rejects the correct credential kind under a different parent', async () => {
    op.entity_type = 'credentials'; op.credential_kind = 'key-auth'; op.parent_id = parentId; op.entity_id = childId;
    await refused(operation(() => request('PATCH', `/consumers/${sid}/key-auth/${childId}`, { host: 'updated.business' })), 'KONG_OPERATION_PARENT_MISMATCH');
  });
  it('rejects a changed before-state and an identifier resolving to another entity', async () => {
    remote.set(`/services/${sid}`, { ...remote.get(`/services/${sid}`), host: 'external.change' });
    await refused(operation(() => request('PATCH', `/services/${sid}`, { host: 'updated.business' })), 'KONG_OPERATION_STATE_CHANGED');
    remote.set(`/services/${sid}`, { id: parentId });
    await refused(operation(() => request('PATCH', `/services/${sid}`, { host: 'updated.business' })), 'KONG_OPERATION_ID_MISMATCH');
  });
  it('requires health endpoint state, durable action and payload to agree', async () => {
    op.entity_type = 'targets'; op.entity_id = childId; op.parent_id = parentId; op.action = 'mark_healthy'; encryptPayload({ state: 'healthy' });
    await refused(operation(() => request('POST', `/upstreams/${parentId}/targets/${childId}/unhealthy`)), 'KONG_HEALTH_STATE_MISMATCH');
    encryptPayload({ state: 'unhealthy' });
    await refused(operation(() => request('POST', `/upstreams/${parentId}/targets/${childId}/healthy`)), 'KONG_HEALTH_STATE_MISMATCH');
  });
  it('accepts only a currently effective Target for manual health changes', async () => {
    op.entity_type = 'targets'; op.entity_id = childId; op.parent_id = parentId; op.action = 'mark_healthy'; encryptPayload({ state: 'healthy' });
    const target = { id: childId, target: 'business.test:8080', weight: 100, upstream: { id: parentId } };
    remote.set(`/upstreams/${parentId}/targets/${childId}`, target); remote.set(`/upstreams/${parentId}/targets`, { data: [target], next: null });
    await expect(operation(() => request('POST', `/upstreams/${parentId}/targets/${childId}/healthy`))).resolves.toBeDefined();
    remote.set(`/upstreams/${parentId}/targets`, { data: [{ ...target, id: sid }], next: null });
    await refused(operation(() => request('POST', `/upstreams/${parentId}/targets/${childId}/healthy`)), 'KONG_TARGET_NOT_EFFECTIVE');
  });
  it('restores only exact original IDs and archived data without read-only timestamps', async () => {
    op.action = 'restore'; encryptPayload({ entryId });
    const original = { id: sid, host: 'archived.business', tags: [], created_at: 1 };
    graph([{ affected: true, type: 'services', id: sid, path: `/services/${sid}`, data: original }]);
    await expect(operation(() => request('POST', '/services', { id: sid, host: 'archived.business', tags: [] }))).resolves.toBeDefined();
    await refused(operation(() => request('POST', '/services', { id: sid, host: 'replacement.business', tags: [] })), 'KONG_OPERATION_PAYLOAD_MISMATCH');
    await refused(operation(() => request('POST', '/services', { ...original, id: parentId })), 'KONG_RESTORE_NODE_INVALID');
  });
  it('validates Basic restore against original plaintext restoreData rather than resubmitting a Kong hash', async () => {
    op.entity_type = 'credentials'; op.credential_kind = 'basic-auth'; op.parent_id = parentId; op.entity_id = childId; op.action = 'restore'; encryptPayload({ entryId });
    const base = { id: childId, username: 'basic', consumer: { id: parentId }, tags: [] };
    graph([{ affected: true, type: 'basic-auth', id: childId, path: `/consumers/${parentId}/basic-auth/${childId}`, data: { ...base, password: 'kong-hash' }, restoreData: { ...base, password: 'original-plaintext' } }]);
    await expect(operation(() => request('POST', `/consumers/${parentId}/basic-auth`, { ...base, password: 'original-plaintext' }))).resolves.toBeDefined();
    await refused(operation(() => request('POST', `/consumers/${parentId}/basic-auth`, { ...base, password: 'kong-hash' })), 'KONG_OPERATION_PAYLOAD_MISMATCH');
  });
  it('allows Target restore to create a new effective ID only with the exact archived address/weight/tags', async () => {
    op.entity_type = 'targets'; op.parent_id = parentId; op.entity_id = childId; op.action = 'restore'; encryptPayload({ entryId });
    graph([{ affected: true, type: 'targets', id: childId, path: `/upstreams/${parentId}/targets/${childId}`, data: { id: childId, target: 'business.test:8080', weight: 80, tags: [], upstream: { id: parentId }, created_at: 1 } }]);
    await expect(operation(() => request('POST', `/upstreams/${parentId}/targets`, { target: 'business.test:8080', weight: 80, tags: [] }))).resolves.toBeDefined();
    await refused(operation(() => request('POST', `/upstreams/${parentId}/targets`, { target: 'business.test:8080', weight: 81, tags: [] })), 'KONG_OPERATION_PAYLOAD_MISMATCH');
  });
  it('requires the original Target ID when its affected restored Upstream has no original history row', async () => {
    op.entity_type='upstreams';op.entity_id=parentId;op.action='restore';encryptPayload({entryId});
    const parent={key:`upstreams:${parentId}`,affected:true,type:'upstreams',id:parentId,path:`/upstreams/${parentId}`,data:remote.get(`/upstreams/${parentId}`)};
    const target={id:childId,target:'business.test:8080',weight:80,tags:[],upstream:{id:parentId},created_at:1};
    graph([parent,{key:`targets:${parentId}:${childId}`,affected:true,type:'targets',id:childId,path:`/upstreams/${parentId}/targets/${childId}`,data:target,dependencies:[parent.key]}]);
    await expect(operation(()=>request('POST',`/upstreams/${parentId}/targets`,{id:childId,target:target.target,weight:80,tags:[]}))).resolves.toBeDefined();
    await refused(operation(()=>request('POST',`/upstreams/${parentId}/targets`,{target:target.target,weight:80,tags:[]})),'KONG_OPERATION_PAYLOAD_MISMATCH');
    await refused(operation(()=>request('POST',`/upstreams/${parentId}/targets`,{id:sid,target:target.target,weight:80,tags:[]})),'KONG_OPERATION_PAYLOAD_MISMATCH');
  });
  it('never overwrites surviving Target history with its archived ID', async()=>{
    op.entity_type='upstreams';op.entity_id=parentId;op.action='restore';encryptPayload({entryId});
    const parent={key:`upstreams:${parentId}`,affected:true,type:'upstreams',id:parentId,path:`/upstreams/${parentId}`,data:remote.get(`/upstreams/${parentId}`)};
    const target={id:childId,target:'business.test:8080',weight:80,tags:[],upstream:{id:parentId}};
    graph([parent,{affected:true,type:'targets',id:childId,path:`/upstreams/${parentId}/targets/${childId}`,data:target,dependencies:[parent.key]}]);
    remote.set(`/upstreams/${parentId}/targets/${childId}`,target);
    await refused(operation(()=>request('POST',`/upstreams/${parentId}/targets`,{id:childId,target:target.target,weight:80,tags:[]})),'KONG_OPERATION_PAYLOAD_MISMATCH');
  });
  it('refuses original Target ID reconstruction with a changed current parent or a missing archive dependency',async()=>{
    op.entity_type='upstreams';op.entity_id=parentId;op.action='restore';encryptPayload({entryId});
    const parent={key:`upstreams:${parentId}`,affected:true,type:'upstreams',id:parentId,path:`/upstreams/${parentId}`,data:structuredClone(remote.get(`/upstreams/${parentId}`))};
    const target={id:childId,target:'business.test:8080',weight:80,tags:[],upstream:{id:parentId}};
    const child={affected:true,type:'targets',id:childId,path:`/upstreams/${parentId}/targets/${childId}`,data:target,dependencies:[parent.key]};
    graph([parent,child]);remote.set(parent.path,{...parent.data,name:'changed'});
    await refused(operation(()=>request('POST',`/upstreams/${parentId}/targets`,{id:childId,target:target.target,weight:80,tags:[]})),'KONG_RESTORE_PARENT_CHANGED');
    remote.set(parent.path,parent.data);graph([parent,{...child,dependencies:[]}]);
    await refused(operation(()=>request('POST',`/upstreams/${parentId}/targets`,{id:childId,target:target.target,weight:80,tags:[]})),'KONG_OPERATION_PAYLOAD_MISMATCH');
  });
  it('does not treat a failed original Target history read as a missing row',async()=>{
    op.entity_type='upstreams';op.entity_id=parentId;op.action='restore';encryptPayload({entryId});
    const parent={key:`upstreams:${parentId}`,affected:true,type:'upstreams',id:parentId,path:`/upstreams/${parentId}`,data:remote.get(`/upstreams/${parentId}`)};
    const target={id:childId,target:'business.test:8080',weight:80,tags:[],upstream:{id:parentId}};
    graph([parent,{affected:true,type:'targets',id:childId,path:`/upstreams/${parentId}/targets/${childId}`,data:target,dependencies:[parent.key]}]);
    const implementation=kong.request.getMockImplementation(),failure=new ForbiddenException({code:'synthetic-read-denied'});
    kong.request.mockImplementation(async(...args:any[])=>{if(args[2]===`/upstreams/${parentId}/targets/${childId}`)throw failure;return implementation(...args);});
    await expect(operation(()=>request('POST',`/upstreams/${parentId}/targets`,{id:childId,target:target.target,weight:80,tags:[]}))).rejects.toBe(failure);
  });
  it('binds DELETE to a complete, durable, matching archive and its unchanged actual node', async () => {
    op.action = 'delete'; entry.state = 'deleting'; encryptPayload({ confirmed: true });
    const node = { affected: true, type: 'services', id: sid, path: `/services/${sid}`, data: remote.get(`/services/${sid}`) }; graph([node]);
    const deletion = () => operation(() => execution.runArchiveDelete({ entryId, operationId: oid, clusterId: cid, workspaceId: wid, nodes: [node] }, () => request('DELETE', node.path)));
    await expect(deletion()).resolves.toBeDefined();
    remote.set(node.path, { ...node.data, host: 'externally.modified' });
    await refused(deletion(), 'KONG_RECYCLE_STATE_CHANGED');
    entry.mutation_id = sid;
    await refused(deletion(), 'KONG_RECYCLE_ARCHIVE_INVALID');
  });
  it('records a generated primary create ID atomically before implicit SNI stamps', async () => {
    op.entity_type = 'certificates'; op.entity_id = null; op.action = 'create'; encryptPayload({ cert: 'certificate', key: 'private', snis: ['test.example'] });
    await operation(async () => {
      const ticket = await request('POST', '/certificates', { cert: 'certificate', key: 'private', snis: ['test.example'] });
      await execution.authorizeResponse(ticket, { id: sid, cert: 'certificate', key: 'private', tags: [] });
    });
    expect(op.entity_id).toBe(sid); expect(db.exec).toHaveBeenCalledWith(expect.stringContaining('entity_id=$5'), [oid, cid, actor.id, 'certificates', sid]);
    remote.set(`/snis/${childId}`, { id: childId, name: 'test.example', tags: [], certificate: { id: sid } });
    await expect(operation(() => request('PATCH', `/snis/${childId}`, { tags: ['kos-ws-default'] }))).resolves.toBeDefined();
    await refused(operation(() => request('PATCH', `/snis/${childId}`, { tags: ['invented'] })), 'KONG_OPERATION_PAYLOAD_MISMATCH');
    remote.set(`/snis/${childId}`, { id: childId, name: 'test.example', tags: [], certificate: { id: parentId } });
    await refused(operation(() => request('PATCH', `/snis/${childId}`, { tags: ['kos-ws-default'] })), 'KONG_SNI_STAMP_INVALID');
  });
  it('marks native create response uncertain if its durable create-ID CAS no longer matches', async () => {
    op.entity_type = 'certificates'; op.entity_id = null; op.action = 'create'; encryptPayload({ cert: 'certificate', key: 'private' }); db.exec.mockResolvedValue(0);
    await refused(operation(async () => {
      const ticket = await request('POST', '/certificates', { cert: 'certificate', key: 'private' });
      return execution.authorizeResponse(ticket, { id: sid });
    }), 'KONG_WRITE_RESULT_UNKNOWN');
  });
  it('rejects post-write authorization changes as uncertain rather than safely retryable 403', async () => {
    await refused(operation(async () => {
      const ticket = await request('PATCH', `/services/${sid}`, { host: 'updated.business' });
      authz.assertEntity.mockRejectedValue(new ForbiddenException());
      return execution.authorizeResponse(ticket, { id: sid, host: 'updated.business' });
    }), 'KONG_WRITE_RESULT_UNKNOWN');
  });
  it('filters raw public lists and exposes a permission-projection marker without leaking denied rows or totals', async () => {
    platform = false;
    await run(async () => {
      const ticket = await request('GET', '/services');
      const result = await execution.authorizeResponse(ticket, { data: [{ id: sid }, { id: 'denied', key: 'private-denied' }], next: '/services?offset=next', total: 2 });
      expect(result).toEqual({ data: [{ id: sid }], next: '/services?offset=next', total: null, console_permission_projection: true });
      expect(JSON.stringify(result)).not.toContain('private-denied');
    }, 'services', 'read');
  });
  it('injects only a verified nested child parent for filtering and refuses foreign-parent responses', async () => {
    await run(async () => {
      const ticket = await request('GET', `/consumers/${parentId}/key-auth`);
      const result = await execution.authorizeResponse(ticket, { data: [{ id: childId }], next: null });
      expect(result.data[0].consumer.id).toBe(parentId);
      expect(authz.assertNestedParentScope).toHaveBeenCalledWith(expect.anything(), cid, 'consumers', expect.objectContaining({ id: parentId }), 'key-auth', 'read', wid, undefined);
      const forged = await request('GET', `/consumers/${parentId}/key-auth`);
      await refused(execution.authorizeResponse(forged, { data: [{ id: childId, consumer: { id: sid } }], next: null }), 'KONG_PARENT_MISMATCH');
    }, 'consumers', 'read');
  });
  it('keeps schema secret defaults private and denies arbitrary information paths to actor frames', async () => {
    await run(async () => {
      const ticket = await request('GET', '/plugins/schema/session');
      const result = await execution.authorizeResponse(ticket, { fields: [{ secret: { type: 'string', default: 'worker-secret' } }] });
      expect(result.fields[0].secret.default).toBeUndefined();
      await refused(request('GET', '/'), 'KONG_INFO_PRIVATE');
    }, 'plugins', 'read');
  });
  it('never treats a cloned policy decision as an authorization ticket', async () => {
    await run(async () => {
      await refused(policy.authorizeResponse({ kind: 'list', clusterId: cid, frame: execution.current() }, { data: [] }), 'KONG_POLICY_TICKET_INVALID');
    }, 'services', 'read');
  });
  it('rejects unknown native writes even when there is a valid durable operation', async () => {
    await refused(operation(() => request('POST', '/invented-entities', { host: 'updated.business' })), 'KONG_OPERATION_ENTITY_MISMATCH');
  });
  it('rejects password-reset sessions before consulting the native operation ledger', async () => {
    authz.snapshot.mockResolvedValue({ user: { ...actor, forcePasswordChange: true }, grants: [], version: epoch });
    await refused(operation(() => request('PATCH', `/services/${sid}`, { host: 'updated.business' })), 'PASSWORD_CHANGE_REQUIRED');
    expect(db.one).not.toHaveBeenCalled();
  });
  it('rejects read responses if the permission epoch changes during server-side filtering', async () => {
    authz.filterEntities.mockImplementation(async (_u: any, _cid: string, _type: string, items: any[]) => { epoch = 'epoch-2'; return items; });
    await run(async () => {
      const ticket = await request('GET', '/services');
      await refused(execution.authorizeResponse(ticket, { data: [{ id: sid }], next: null }), 'PERMISSIONS_CHANGED');
    }, 'services', 'read');
  });
  it.each([
    { type: 'routes', body: { name: 'new-route', service: { id: parentId }, tags: [] }, reference: `/services/${parentId}` },
    { type: 'plugins', body: { name: 'request-termination', service: { id: parentId }, config: {}, tags: [] }, reference: `/services/${parentId}` },
    { type: 'snis', body: { name: 'cross-scope.example', certificate: { id: parentId }, tags: [] }, reference: `/certificates/${parentId}` },
    { type: 'services', body: { host: 'business.test', client_certificate: { id: parentId }, tags: [] }, reference: `/certificates/${parentId}` },
    { type: 'services', body: { host: 'business.test', ca_certificates: [parentId], tags: [] }, reference: `/ca_certificates/${parentId}` },
    { type: 'services', body: { host: 'workspace-upstream', tags: [] }, reference: '/upstreams/workspace-upstream' },
  ])('checks fresh real workspace membership for $type references even for platform administrators', async ({ type, body, reference }) => {
    op.entity_type = type; op.entity_id = null; op.action = 'create'; encryptPayload(body);
    remote.set(reference, { id: parentId, tags: ['kos-ws-pay'] });
    await expect(operation(() => request('POST', `/${type}`, body))).rejects.toMatchObject({ response: { code: 'WORKSPACE_ENTITY_MISMATCH' } });
    expect(kong.request).toHaveBeenCalledWith(cid, 'GET', reference);
  });
  it('requires actual parent read or write grants after proving same-workspace child-write membership', async () => {
    op.entity_type = 'routes'; op.entity_id = null; op.action = 'create';
    const body = { service: { id: sid }, paths: ['/reference'], tags: [] }; encryptPayload(body);
    authz.assertEntity.mockImplementation(async (_user: unknown, _cid: string, type: string, action: string) => {
      if (type === 'services' && ['read', 'write'].includes(action)) throw new ForbiddenException({ code: 'REFERENCE_ACCESS_DENIED' });
    });
    await refused(operation(() => request('POST', '/routes', body)), 'REFERENCE_ACCESS_DENIED');
    expect(authz.assertEntity).toHaveBeenCalledWith(expect.anything(), cid, 'services', 'read', expect.objectContaining({ id: sid }), wid);
  });
  it('keeps certificate references read-protected when the caller has only certificate write', async () => {
    op.entity_type = 'snis'; op.entity_id = null; op.action = 'create';
    const body = { name: 'protected-certificate.test', certificate: { id: sid }, tags: [] }; encryptPayload(body);
    remote.set(`/certificates/${sid}`, { id: sid, tags: [] });
    authz.assertEntity.mockImplementation(async (_user: unknown, _cid: string, type: string, action: string) => {
      if (type === 'certificates' && action === 'read') throw new ForbiddenException({ code: 'CERTIFICATE_READ_DENIED' });
    });
    await refused(operation(() => request('POST', '/snis', body)), 'CERTIFICATE_READ_DENIED');
    expect(authz.assertEntity.mock.calls.some((call: any[]) => call[2] === 'certificates' && call[3] === 'write')).toBe(false);
  });
  it('rejects a selected-workspace write whose fresh primary entity belongs to another workspace', async () => {
    const before = { ...remote.get(`/services/${sid}`), tags: ['kos-ws-pay'] };
    remote.set(`/services/${sid}`, before); encryptBefore(before);
    await refused(operation(() => request('PATCH', `/services/${sid}`, { host: 'updated.business' })), 'WORKSPACE_ENTITY_MISMATCH');
  });
  it('allows an ordinary DNS host absent from the Upstream registry without inventing a reference', async () => {
    await expect(operation(() => request('PATCH', `/services/${sid}`, { host: 'updated.business' }))).resolves.toBeDefined();
    expect(kong.request).toHaveBeenCalledWith(cid, 'GET', '/upstreams/updated.business');
    expect(authz.assertEntity.mock.calls.some((call: any[]) => call[2] === 'upstreams')).toBe(false);
  });
  it.each(['203.0.113.10', '2001:db8::10', '[2001:db8::10]'])('does not interpret literal Service host %s as an Upstream unique name', async host => {
    const body = { host }; encryptPayload(body);
    await expect(operation(() => request('PATCH', `/services/${sid}`, body))).resolves.toBeDefined();
    expect(kong.request.mock.calls.some((call: any[]) => call[2].startsWith('/upstreams/'))).toBe(false);
    expect(authz.assertEntity.mock.calls.some((call: any[]) => call[2] === 'upstreams')).toBe(false);
  });
  it('never emits a write ticket with a stale platform snapshot after a private reference await', async () => {
    authz.assertEntity.mockImplementation(async () => { epoch = 'epoch-2'; platform = false; });
    await refused(operation(() => request('PATCH', `/services/${sid}`, { host: 'updated.business' })), 'PERMISSIONS_CHANGED');
  });
  it.each([
    { path: `/consumers/${parentId}/key-auth`, parentPath: `/consumers/${parentId}`, child: { id: childId, consumer: { id: parentId } } },
    { path: `/upstreams/${parentId}/targets`, parentPath: `/upstreams/${parentId}`, child: { id: childId, upstream: { id: parentId } } },
    { path: `/upstreams/${parentId}/health`, parentPath: `/upstreams/${parentId}`, child: { id: childId, upstream: { id: parentId }, health: 'HEALTHY' } },
  ])('rechecks the real nested parent workspace after the native $path read, including platform administrators', async ({ path, parentPath, child }) => {
    await run(async () => {
      const ticket = await request('GET', path);
      remote.set(parentPath, { ...remote.get(parentPath), tags: ['kos-ws-pay'] });
      await refused(execution.authorizeResponse(ticket, { data: [child], next: null }), 'WORKSPACE_ENTITY_MISMATCH');
    }, path.includes('/consumers/') ? 'consumers' : 'upstreams', 'read');
  });
  it.each(['routes', 'plugins', 'snis'])('restores every approved %s node in a shared collection rather than only the first archived node', async type => {
    op.action = 'restore'; encryptPayload({ entryId });
    const first = type === 'routes' ? { id: parentId, name: 'first', paths: ['/first'], service: { id: sid }, tags: [] }
      : type === 'plugins' ? { id: parentId, name: 'cors', config: { origins: ['*'] }, service: { id: sid }, tags: [] }
      : { id: parentId, name: 'first.business', certificate: { id: sid }, tags: [] };
    const second = type === 'routes' ? { id: childId, name: 'second', paths: ['/second'], service: { id: sid }, tags: [] }
      : type === 'plugins' ? { id: childId, name: 'request-termination', config: { status_code: 403 }, service: { id: sid }, tags: [] }
      : { id: childId, name: 'second.business', certificate: { id: sid }, tags: [] };
    remote.set(`/certificates/${sid}`, { id: sid, tags: [] });
    graph([first, second].map(data => ({ affected: true, type, id: data.id, path: `/${type}/${data.id}`, data })));
    await expect(operation(() => request('POST', `/${type}`, second))).resolves.toBeDefined();
  });
  it('restores every approved Target address in the same Upstream without inventing original effective IDs', async () => {
    op.entity_type = 'upstreams'; op.entity_id = parentId; op.action = 'restore'; encryptPayload({ entryId });
    const first = { id: sid, target: 'first.business:8080', weight: 80, tags: [], upstream: { id: parentId } };
    const second = { id: childId, target: 'second.business:8080', weight: 90, tags: [], upstream: { id: parentId } };
    graph([first, second].map(data => ({ affected: true, type: 'targets', id: data.id, path: `/upstreams/${parentId}/targets/${data.id}`, data })));
    await expect(operation(() => request('POST', `/upstreams/${parentId}/targets`, { target: second.target, weight: second.weight, tags: [] }))).resolves.toBeDefined();
  });
  it('fails closed when an archived Target address has two possible approved nodes under the same parent', async () => {
    op.entity_type = 'upstreams'; op.entity_id = parentId; op.action = 'restore'; encryptPayload({ entryId });
    const base = { target: 'ambiguous.business:8080', weight: 80, tags: [], upstream: { id: parentId } };
    graph([sid, childId].map(id => ({ affected: true, type: 'targets', id, path: `/upstreams/${parentId}/targets/${id}`, data: { id, ...base } })));
    await refused(operation(() => request('POST', `/upstreams/${parentId}/targets`, { target: base.target, weight: base.weight, tags: [] })), 'KONG_RESTORE_NODE_INVALID');
  });
});
