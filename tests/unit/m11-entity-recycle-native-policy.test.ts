import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { DEFAULT_WORKSPACE_ID as wid, workspaceTestResolver } from './workspace-test-helper';

/** Real native-policy/context/crypto boundaries with isolated SQL, grant and
 * execution-policy adapters. No approval/source/SQL23/runtime authority is
 * claimed, and authorization tickets are never spent on native transport. */
function fixture(direction: 'delete' | 'restore' = 'delete', type: 'services'|'targets'|'certificates' = 'services') {
  const cid = randomUUID(), nativeId = randomUUID(), operationId = randomUUID(), entryId = randomUUID(), sessionId = randomUUID();
  const actor = { id: randomUUID(), username: 'recycle-owner', superAdmin: false };
  const secrets = new SecretService(), execution = new KongExecutionContextService();
  const parentId=randomUUID(),allocatedId=direction==='restore'&&type==='targets'?randomUUID():nativeId;
  const data:any=type==='targets'?{id:nativeId,target:'127.0.0.1:8080',weight:75,upstream:{id:parentId},tags:[]}:
   type==='certificates'?{id:nativeId,cert:'source-synthetic-cert',key:'source-synthetic-key',snis:['source.test'],tags:[]}:
   { id: nativeId, name: 'offline-service', host: 'business.test', protocol: 'http', port: 80, tags: [] };
  const body:any={...data,id:allocatedId};if(type==='targets')delete body.upstream;if(type==='certificates')delete body.snis;
  const collection=type==='targets'?`/upstreams/${parentId}/targets`:`/${type}`;
  const node: any = { key: `${type}:${nativeId}`, type, id: nativeId, path: `${collection}/${nativeId}`,
    affected: true, dependencies: [], data, restoreData: data, restorable: true };
  const graph: any = { complete: true, rootKey: node.key, purpose: 'recycle', capturedAt: new Date().toISOString(), nodes: [node] };
  const operation: any = { id: operationId, cluster_id: cid, workspace_id: wid, actor_id: actor.id, entity_id:allocatedId,
    entity_type:type, action: direction, state: 'running', remote_started: true, remote_completed: false,
    workflow_id: randomUUID(), entity_change_source_id: randomUUID(), entity_change_baseline_id: randomUUID(),
    entity_change_attempt_id: randomUUID(), entity_change_packet_key: 'packet-1', idempotency_key: 'offline-exact-packet-key',
    parent_id:type==='targets'?parentId:null, credential_kind: null, before_secret: secrets.encrypt(direction === 'delete' ? data : null, `mutation:${operationId}:before`),
    payload_secret: secrets.encrypt(direction === 'delete' ? null : body, `mutation:${operationId}:payload`) };
  const entry: any = { id: entryId, cluster_id: cid, workspace_id: wid, actor_id: actor.id, mutation_id: null,
    state: direction === 'delete' ? 'deleting' : 'restoring', payload_secret: secrets.encrypt(graph, `recycle:${entryId}`) };
  const db: any = { one: vi.fn(async (sql: string, params: any[]) => {
    if (sql.includes('FROM mutation_operations')) return params[0] === operationId ? operation : null;
    if (sql.includes('FROM recycle_entries')) return params[1] === entryId ? entry : null;
    return null;
  }), exec: vi.fn() };
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => {
    expect(method).toBe('GET');
    if(type==='targets'&&path===`/upstreams/${parentId}`)return{id:parentId,name:'source-parent',tags:[]};
    if (path.startsWith('/upstreams/')) throw new NotFoundException();
    expect(path).toBe(node.path); return structuredClone(data);
  }) };
  const authz: any = { snapshot: vi.fn(async () => ({ user: actor, grants: [{ cluster_id: cid }], version: 'offline-v1' })),
    assertEntity: vi.fn(), assertCluster: vi.fn(), permissionVersion: vi.fn(async () => 'offline-v1') };
  const policy = new NativeKongPolicyService(db, secrets, kong, execution, authz, workspaceTestResolver(cid).resolver);
  policy.install();
  const handle = Object.freeze({}), originalHandles = new WeakSet([handle]);
  const tuple = { sourceId: operation.entity_change_source_id, baselineId: operation.entity_change_baseline_id,
    attemptId: operation.entity_change_attempt_id, packetKey: operation.entity_change_packet_key };
  execution.installEntityChangePacketPolicy({
    verifyHandle: vi.fn(async (value: object) => {
      if (!originalHandles.has(value)) throw new ForbiddenException({ code: 'OFFLINE_OPAQUE_HANDLE_REQUIRED' });
      return { sourceId: tuple.sourceId, baselineId: tuple.baselineId, packetKey: tuple.packetKey, workflowId: operation.workflow_id,
        executionId: randomUUID(), stepId: randomUUID(), actorId: actor.id, sessionId, clusterId: cid, workspaceId: wid,
        transportScope: 'a'.repeat(64), permissionVersion: 'offline-v1', expiresAt: Date.now() + 300000 };
    }), mutationBinding: vi.fn(), bindOperation: vi.fn(), assertNative: vi.fn(), beforeNativeSend: vi.fn(),
    observeTransportResponse: vi.fn(), spendTransport: vi.fn(),
  } as any);
  const assertBinding = (input: any) => {
    expect(input.frame).toBe(execution.current());
    expect(execution.requireEntityChangePacketFrame(input.frame)).toBe(handle);
    if (input.operation.entity_change_source_id !== tuple.sourceId || input.operation.entity_change_baseline_id !== tuple.baselineId
      || input.operation.entity_change_attempt_id !== tuple.attemptId || input.operation.entity_change_packet_key !== tuple.packetKey) {
      throw new ForbiddenException({ code: 'OFFLINE_FIXED_BINDING_REJECTED' });
    }
  };
  const delegate: any = {
    assertCurrentBeforeSend:vi.fn(async input=>{assertBinding(input);}),
    assertDeleteArchive: vi.fn(async input => { assertBinding(input); expect(input.entry.id).toBe(entryId); expect(secrets.fingerprint(input.graph)).toBe(secrets.fingerprint(graph)); }),
    resolveRestoreArchive: vi.fn(async input => { assertBinding(input); return { entryId }; }),
    assertRestoreArchive: vi.fn(async input => { assertBinding(input);if(secrets.fingerprint(input.body)!==secrets.fingerprint(body)||input.operation.entity_id!==body.id)throw new ForbiddenException({code:'SOURCE_SEALED_PACKET_BODY_MISMATCH'}); expect(input.node.id).toBe(nativeId); expect(secrets.fingerprint(input.graph)).toBe(secrets.fingerprint(graph)); }),
  };
  let closer: (() => void) | undefined;
  const run = (options: { packet?: boolean; copiedFrame?: boolean; packetHandle?: object; body?: any; httpSession?: boolean; finalChecks?:number; copyDecision?:boolean } = {}) => execution.runHttp({}, async () => {
    execution.bindHttpActor(actor, options.httpSession === false ? undefined : sessionId); closer = execution.captureHttpCloser();
    return execution.runActor({ actor, clusterId: cid, workspaceId: wid, module: 'workflows', action: 'write' }, async () => {
      const enter = () => execution.runOperation({ actor, clusterId: cid, workspaceId: wid, operationId, entityType: operation.entity_type, action: direction,
        entityId: direction === 'delete' ? nativeId : allocatedId, parentId:type==='targets'?parentId:undefined }, async () => {
        const finalChecks=async()=>{const frame=execution.current(),method=direction==='delete'?'DELETE':'POST',path=direction==='delete'?node.path:collection,payload=options.body??(direction==='restore'?body:undefined);
          const decision=await policy.authorizeRequest(frame,cluster,method,path,payload,{});
          for(let i=0;i<(options.finalChecks??0);i++)await policy.beforeNativeSend(frame,cluster,method,path,payload,{},options.copyDecision?{...decision as any}:decision,{} as any);
          return decision;
        };
        const authorize = () => options.finalChecks?finalChecks():options.copiedFrame
          ? policy.authorizeRequest({ ...execution.current() }, cluster, direction === 'delete' ? 'DELETE' : 'POST', direction === 'delete' ? node.path : collection, options.body ?? (direction === 'restore' ? body : undefined), {})
          : execution.authorizeRequest(cluster, direction === 'delete' ? 'DELETE' : 'POST', direction === 'delete' ? node.path : collection, options.body ?? (direction === 'restore' ? body : undefined), {});
        return direction === 'delete' ? execution.runArchiveDelete({ entryId, operationId, clusterId: cid, workspaceId: wid, nodes: [{ path: node.path, type: node.type, id: node.id }] }, authorize) : authorize();
      });
      return options.packet === false ? enter() : execution.runEntityChangePacket(options.packetHandle ?? handle, enter);
    });
  });
  const cluster = { id: cid, version: '1.5.1', admin_url: 'http://kong:8001', execution_mode: 'direct' };
  const legacy = () => {
    for (const field of ['entity_change_source_id', 'entity_change_baseline_id', 'entity_change_attempt_id', 'entity_change_packet_key']) operation[field] = null;
    entry.mutation_id = direction === 'delete' ? operationId : randomUUID();
    if (direction === 'restore') operation.payload_secret = secrets.encrypt({ entryId }, `mutation:${operationId}:payload`);
  };
  return { policy, execution, operation, entry, data, body, allocatedId, graph, node, delegate, run, db, kong, secrets, handle, legacy, close: () => closer!() };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe('M11 V3 recycle entries require a fixed verifier and original opaque packet', () => {
  it.each(['delete','restore'] as const)('runs the fresh current %s hook once on each genuine final DNS guard and never during archive resolution',async direction=>{const f=fixture(direction);f.policy.installEntityChangeRecyclePolicy(f.delegate);await f.run();expect(f.delegate.assertCurrentBeforeSend).not.toHaveBeenCalled();await f.run({finalChecks:2});expect(f.delegate.assertCurrentBeforeSend).toHaveBeenCalledTimes(2);expect(f.delegate.resolveRestoreArchive.mock.calls.length+f.delegate.assertDeleteArchive.mock.calls.length).toBeGreaterThanOrEqual(3);});
  it('rejects a copied decision and propagates current graph/reviewer revocation before native',async()=>{const f=fixture();f.policy.installEntityChangeRecyclePolicy(f.delegate);await expect(f.run({finalChecks:1,copyDecision:true})).rejects.toMatchObject({response:{code:'KONG_POLICY_TICKET_INVALID'}});expect(f.delegate.assertCurrentBeforeSend).not.toHaveBeenCalled();f.delegate.assertCurrentBeforeSend.mockRejectedValueOnce(new ForbiddenException({code:'TEST_CURRENT_REVIEWER_REVOKED'}));await expect(f.run({finalChecks:1})).rejects.toMatchObject({response:{code:'TEST_CURRENT_REVIEWER_REVOKED'}});});
  it.each(['delete', 'restore'] as const)('defaults %s to closed when no fixed verifier is installed', async direction => {
    const f = fixture(direction);
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_RECYCLE_POLICY_UNAVAILABLE' } });
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['delete', 'restore'] as const)('rejects a %s V3 SQL-shaped tuple without the context private packet', async direction => {
    const f = fixture(direction); f.policy.installEntityChangeRecyclePolicy(f.delegate);
    await expect(f.run({ packet: false })).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_PACKET_CONTEXT_INVALID' } });
    for (const method of Object.values(f.delegate) as any[]) expect(method).not.toHaveBeenCalled();
  });

  it.each(['delete', 'restore'] as const)('rejects a copied %s frame despite a real opaque packet ancestor', async direction => {
    const f = fixture(direction); f.policy.installEntityChangeRecyclePolicy(f.delegate);
    await expect(f.run({ copiedFrame: true })).rejects.toMatchObject({ status: 403 });
    for (const method of Object.values(f.delegate) as any[]) expect(method).not.toHaveBeenCalled();
  });

  it('does not substitute a copied or shaped handle for the original context registration', async () => {
    const f = fixture(); f.policy.installEntityChangeRecyclePolicy(f.delegate);
    for (const packetHandle of [{ ...f.handle }, { sourceId: f.operation.entity_change_source_id, approved: true }]) {
      await expect(f.run({ packetHandle })).rejects.toMatchObject({ response: { code: 'OFFLINE_OPAQUE_HANDLE_REQUIRED' } });
    }
    expect(f.delegate.assertDeleteArchive).not.toHaveBeenCalled();
  });

  it('keeps the current HTTP packet namespace closed without its real session', async () => {
    const f = fixture(); f.policy.installEntityChangeRecyclePolicy(f.delegate);
    await expect(f.run({ httpSession: false })).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_PACKET_CONTEXT_INVALID' } });
    expect(f.delegate.assertDeleteArchive).not.toHaveBeenCalled();
    expect(f.kong.request).not.toHaveBeenCalled();
    // A future scheduled origin needs Root's distinct claim verifier; this
    // test does not create a session substitute or scheduled capability.
  });

  it('requires exact V3 binding even after receiving a genuine context handle', async () => {
    const f = fixture(); f.policy.installEntityChangeRecyclePolicy(f.delegate); f.operation.entity_change_attempt_id = randomUUID();
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'OFFLINE_FIXED_BINDING_REJECTED' } });
  });

  it('passes the original frame and full private graph to the fixed delete verifier', async () => {
    const f = fixture(); f.policy.installEntityChangeRecyclePolicy(f.delegate);
    await expect(f.run()).resolves.toBeDefined();
    expect(f.delegate.assertDeleteArchive).toHaveBeenCalledTimes(1);
    const input = f.delegate.assertDeleteArchive.mock.calls[0][0];
    expect(input.operation.entity_change_source_id).toBe(f.operation.entity_change_source_id);
    expect(input.entry.mutation_id).toBeNull(); expect(Object.isFrozen(input.graph)).toBe(true);
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
  });

  it('derives the restore entry from the fixed private binding, retaining exact native body and graph checks', async () => {
    const f = fixture('restore'); f.policy.installEntityChangeRecyclePolicy(f.delegate);
    await expect(f.run()).resolves.toBeDefined();
    expect(f.delegate.resolveRestoreArchive).toHaveBeenCalledTimes(1); expect(f.delegate.assertRestoreArchive).toHaveBeenCalledTimes(1);
    expect(f.delegate.resolveRestoreArchive.mock.calls[0][0].body).toEqual(f.data);
    expect(f.delegate.resolveRestoreArchive.mock.calls[0][0].operation.payload_secret).toBe(f.operation.payload_secret);
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['source', 'legacy-binding', 'non-null-entry', 'malformed-packet-key'])('blocks altered %s in the V3 namespace', async variant => {
    const f = fixture(); f.policy.installEntityChangeRecyclePolicy(f.delegate);
    if (variant === 'source') f.operation.entity_change_source_id = null;
    if (variant === 'legacy-binding') f.operation.workflow_step_id = randomUUID();
    if (variant === 'non-null-entry') f.entry.mutation_id = f.operation.id;
    if (variant === 'malformed-packet-key') f.operation.entity_change_packet_key = 'packet/unsafe';
    await expect(f.run()).rejects.toMatchObject({ status: 403 });
    expect(f.delegate.assertDeleteArchive).not.toHaveBeenCalled();
  });

  it.each(['sealed-payload', 'native-body'])('rejects legacy entryId injected into V3 %s', async variant => {
    const f = fixture('restore'); f.policy.installEntityChangeRecyclePolicy(f.delegate);
    if (variant === 'sealed-payload') f.operation.payload_secret = f.secrets.encrypt({ ...f.data, entryId: f.entry.id }, `mutation:${f.operation.id}:payload`);
    await expect(f.run(variant === 'native-body' ? { body: { ...f.data, entryId: f.entry.id } } : {})).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_RECYCLE_PAYLOAD_INVALID' } });
    expect(f.delegate.resolveRestoreArchive).not.toHaveBeenCalled();
  });

  it.each(['malformed-id', 'extra-field', 'fixed-rejection', 'closed-origin'])('does not accept restore resolver %s as caller authority', async variant => {
    const f = fixture('restore');
    if (variant === 'malformed-id') f.delegate.resolveRestoreArchive.mockResolvedValue({ entryId: '../other' });
    if (variant === 'extra-field') f.delegate.resolveRestoreArchive.mockResolvedValue({ entryId: f.entry.id, approved: true });
    if (variant === 'fixed-rejection') f.delegate.resolveRestoreArchive.mockRejectedValue(new ForbiddenException({ code: 'ROOT_FIXED_REJECTED' }));
    if (variant === 'closed-origin') f.delegate.resolveRestoreArchive.mockImplementation(async () => { f.close(); return { entryId: f.entry.id }; });
    f.policy.installEntityChangeRecyclePolicy(f.delegate);
    await expect(f.run()).rejects.toMatchObject({ status: 403 });
    expect(f.delegate.assertRestoreArchive).not.toHaveBeenCalled();
  });

  it.each(['delete', 'restore'] as const)('preserves legacy %s behavior and never routes it through a V3 verifier', async direction => {
    const f = fixture(direction); f.legacy(); f.policy.installEntityChangeRecyclePolicy(f.delegate);
    await expect(f.run({ packet: false })).resolves.toBeDefined();
    for (const method of Object.values(f.delegate) as any[]) expect(method).not.toHaveBeenCalled();
  });

  it('does not allow legacy restore payload.entryId to open a NULL mutation-id V3 entry', async () => {
    const f = fixture('restore'); f.legacy(); f.entry.mutation_id = null;
    await expect(f.run({ packet: false })).rejects.toMatchObject({ response: { code: 'KONG_RESTORE_ARCHIVE_INVALID' } });
  });

  it('requires all fixed methods and rejects policy replacement', () => {
    const f = fixture(), incomplete = { ...f.delegate }; delete incomplete.assertRestoreArchive;
    expect(() => f.policy.installEntityChangeRecyclePolicy(incomplete)).toThrow();
    f.policy.installEntityChangeRecyclePolicy(f.delegate);
    expect(() => f.policy.installEntityChangeRecyclePolicy(f.delegate)).toThrow();
  });

  it('uses the sealed V3 Target append allocation while the archive preserves its original ID',async()=>{
    const f=fixture('restore','targets');f.policy.installEntityChangeRecyclePolicy(f.delegate);
    expect(f.body.id).not.toBe(f.node.id);await expect(f.run()).resolves.toBeDefined();
    expect(f.delegate.assertRestoreArchive).toHaveBeenCalledTimes(1);expect(f.db.exec).not.toHaveBeenCalled();
    expect(f.delegate.assertRestoreArchive.mock.calls[0][0].body.id).toBe(f.operation.entity_id);
  });
  it.each(['body','operation','extra-field'] as const)('cannot substitute the V3 Target allocated %s after the original fixed packet verifier',async variant=>{
    const f=fixture('restore','targets');f.policy.installEntityChangeRecyclePolicy(f.delegate);
    if(variant==='operation')f.operation.entity_id=randomUUID();
    const body=variant==='body'?{...f.body,id:randomUUID()}:variant==='extra-field'?{...f.body,owner:'outside-sealed-packet'}:f.body;
    await expect(f.run({body})).rejects.toMatchObject({status:403});
  });
  it('uses the V3 explicit SNI successor plan instead of certificate implicit names',async()=>{
    const f=fixture('restore','certificates');f.policy.installEntityChangeRecyclePolicy(f.delegate);
    expect(f.node.restoreData.snis).toEqual(['source.test']);expect(f.body.snis).toBeUndefined();
    await expect(f.run()).resolves.toBeDefined();expect(f.delegate.assertRestoreArchive).toHaveBeenCalledTimes(1);
  });
  it('rejects certificate implicit SNI injection outside the real V3 sealed packet',async()=>{
    const f=fixture('restore','certificates');f.policy.installEntityChangeRecyclePolicy(f.delegate);
    await expect(f.run({body:{...f.body,snis:['source.test']}})).rejects.toMatchObject({status:403});
  });
});
