import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpException, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { KongService } from '../../apps/console-api/src/infrastructure/kong/kong.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { EntityChangeExecutionService } from '../../apps/console-api/src/modules/workflows/entity-change-execution.service';
import type { EntityChangeRecycleKernelBridge } from '../../apps/console-api/src/modules/recycle-bin/entity-change-recycle-execution.types';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn(), outboundText: vi.fn() }));
const transport = vi.mocked(outboundJson);

/** Source-only regression of the real read-ticket observer. All SQL, native
 * responses and domain acknowledgements below are controlled adapters.
 * This file creates no real runtime grant, SQL025 or native acceptance.
 * The production Kernel.execute issues actual original private handles;
 * Context issues real WeakMap tickets/frames; KongService observes the actual
 * controlled transport result. SQL/approval/baseline/coordinator business
 * adapters are fixtures, not real runtime source/grant/SQL/native evidence.
 * No private registry is seeded or replaced, and verifyHandle is not mocked. */
function fixture(options: { restore?: boolean; core?: boolean; deleteStatus?: number; deleteBody?: unknown; skipWireFence?: boolean } = {}) {
  const secrets = new SecretService(), context = new KongExecutionContextService();
  const cid = randomUUID(), wid = randomUUID(), sessionId = randomUUID(), nativeId = randomUUID(), workflowId = randomUUID(), intentId = randomUUID(), operationId = randomUUID();
  const actor: any = { user: { id: randomUUID(), username: 'transport-owner', superAdmin: false }, workspaceId: wid, idempotencyKey: 'fixture-original-execution' };
  const data = { id: nativeId, name: 'unit-transport-service', host: '192.0.2.10', retries: 5, tags: [] }, path = `/services/${nativeId}`;
  const cluster: any = { id: cid, admin_url: 'http://kong:8001', connection_secret: null, transport_scope: null, revision: 1, version: '1.5.1', execution_mode: 'approval', status: 'healthy', capabilities: {} };
  const scope = transportScopeFor(cluster.admin_url), packet: any = { key: 'packet-1', order: 1, dependencies: [], method: options.restore ? 'POST' : options.core ? 'PATCH' : 'DELETE', canonicalPath: options.restore ? '/services' : path, nativeType: 'services', nativeId,
    permissionAction: options.restore || options.core ? 'write' : 'delete', mutationAction: options.restore ? 'restore' : options.core ? 'update' : 'delete', before: options.restore ? null : data, ...(options.restore ? {body: data} : options.core ? { body: { retries: 4 } } : {}),
    beforeHmac: secrets.fingerprint(options.restore ? null : data), bodyHmac: secrets.fingerprint(options.restore ? data : options.core ? { retries: 4 } : null) };
  const graph: any = { complete: true, purpose: 'recycle', rootKey: `services:${nativeId}`, nodes: [{ key: `services:${nativeId}`, id: nativeId, type: 'services', path, data, restoreData: data, restorable: true, affected: true, dependencies: [] }] };
  const initial: any = { version: 1, clusterId: cid, workspaceId: wid, requesterId: actor.user.id, scope: { transportScope: scope, clusterRevision: 1, workspaceRevision: 1 }, packets: [packet],
    metadataObligations: options.core ? [{ kind: 'entity-index', entityType: 'services', packetKey: packet.key }] : [{kind: options.restore ? 'recycle-restore' : 'recycle-archive',graph,graphHmac:secrets.fingerprint(graph),packetKeys:[packet.key],...(options.restore?{entryId:randomUUID(),sealedEntry:{payloadHmac:secrets.fingerprint(graph)}}:{})}] };
  const prepared = { ...initial, changeDigest: secrets.fingerprint(initial) }, envelope: any = { version: 1, intentId, revision: 1, credentialEpoch: '1', prepared, packetManifestHmac: secrets.fingerprint([packet]), expiresAt: new Date(Date.now() + 86400000).toISOString() };
  const metadata = { intentId, intentRevision: 1, materialHmac: secrets.fingerprint(envelope), changeDigest: prepared.changeDigest, packetManifestHmac: envelope.packetManifestHmac };
  const plan: any = { version: 1, kind: 'native-change', workflowId, clusterId: cid, workspaceId: wid, planRevision: 1, executionMode: 'approval', approvalRequired: true,
    subject: { type: 'entity_change_intents', id: intentId }, requester: { type: 'console', id: actor.user.id }, definition: { id: randomUUID(), version: 1, policyHash: secrets.fingerprint('fixture-policy') },
    expiresAt: envelope.expiresAt, scope: prepared.scope, prerequisites: [], steps: [{ id: randomUUID(), key: 'entity', order: 1, kind: 'metadata', handler: 'entity.change', entityType: 'entity_change_intents', entityId: intentId,
      permissionAction: 'write', dependencies: [], nativeRequests: [], metadata, metadataRevision: 1, metadataPayloadHmac: secrets.fingerprint(metadata), metadataBeforeHmac: secrets.fingerprint(metadata) }] };
  const workflow: any = { id: workflowId, state: 'approved', revision: 1, plan_hash: secrets.fingerprint(plan), approved_by: randomUUID() };
  let sourceRow: any, executionRow: any, mutation: any, baseline: any, bridge: EntityChangeRecycleKernelBridge, factsPolicy: any, writerDelegate: any, originalHandle: object | undefined;
  let beforeWrite: ((handle: object) => Promise<void>) | undefined, afterWrite: ((handle: object) => Promise<void>) | undefined, rejectedWrite: ((handle: object) => Promise<void>) | undefined;
  let baselineRead: (() => Promise<void>) | undefined;
  let originalExecutionHandle: object;
  let lastVerification: any, httpCloser: (() => void) | undefined;
  const readResponses=new Map<string,{status:number;body:unknown}>();
  const eventFacts: any[] = [], attempts: any[] = [];
  const db: any = {
    one: vi.fn(async (sql: string, values: any[] = []) => {
      if (sql.includes('FROM mutation_operations')) return mutation && values[0] === operationId ? mutation : null;
      if (sql.includes('FROM entity_change_execution_sources')) return sourceRow && values[0] === sourceRow.id ? sourceRow : null;
      if (sql.includes('FROM auth_sessions')) return { expires_at: new Date(Date.now() + 86400000), credential_epoch: '1', user_epoch: '1' };
      if (sql.includes('FROM workflow_executions') && sql.includes('JOIN workflows')) return { state: executionRow?.state, workflow_state: workflow.state };
      if (sql.includes('FROM workflow_executions')) return executionRow ?? null;
      if (sql.includes('FROM iam_epoch')) return { version: 1 };
      if (sql.includes('FROM clusters')) return cluster;
      if (sql.includes('FROM workspaces')) return { id: wid, revision: 1, status: 'active' };
      if (sql.includes('FROM workflows')) return workflow;
      if (sql.includes('FROM entity_change_packet_events')) { const found = eventFacts.find(fact => fact.binding.attemptId === values[0] && fact.kind === 'outcome'); return found ? { outcome: found.outcome, native_status: found.nativeStatus } : null; }
      throw new Error(`Unexpected fixture SQL read: ${sql}`);
    }),
    query: vi.fn(async (sql: string) => sql.includes('entity_change_packet_attempts') ? eventFacts.map(fact => ({ packet_key: fact.binding.packetKey, event_kind: fact.kind, outcome: fact.outcome, error_code: fact.errorCode })) : []),
    exec: vi.fn(async (sql: string, values: any[] = []) => {
      if (sql.startsWith('INSERT INTO entity_change_execution_sources')) sourceRow = Object.fromEntries(['id', 'cluster_id', 'workspace_id', 'intent_id', 'intent_revision', 'material_hmac', 'change_digest', 'packet_manifest_hmac', 'workflow_id', 'workflow_plan_revision', 'workflow_plan_hash', 'workflow_execution_id', 'execution_actor_id', 'credential_epoch', 'session_id', 'permission_version_hmac', 'issued_at', 'expires_at'].map((key, index) => [key, values[index]]));
      else if (sql.startsWith('INSERT INTO workflow_executions')) executionRow = { id: values[0], state: 'executing', workflow_id: values[3], execution_actor_id: values[9] };
      else if (sql.startsWith("UPDATE workflows SET state='executing'")) { workflow.state = 'executing'; workflow.revision++; }
      else if (sql.startsWith("UPDATE workflows SET state='succeeded'")) { workflow.state = 'succeeded'; workflow.revision++; }
      else if (sql.startsWith('UPDATE workflows SET state=$2')) { workflow.state = values[1]; workflow.revision++; }
      else if (sql.startsWith("UPDATE workflow_executions SET state='succeeded'")) executionRow.state = 'succeeded';
      else if (sql.startsWith('UPDATE workflow_executions SET state=$2')) executionRow.state = values[1];
      return 1;
    }), transaction: vi.fn(async (callback: any) => callback(db)),
  };
  const redis: any = { withLock: vi.fn(async (_key: string, callback: any) => callback()), assertLeaseOwnership: vi.fn(async () => undefined), assertLeaseActive: vi.fn(),
    rateLimit: vi.fn(async () => ({ allowed: true, retryAfterMs: 0 })) };
  const audit: any = { append: vi.fn(async () => undefined) }, authz: any = { permissionVersion: vi.fn(async () => 'fixture-current-permissions') };
  const facts: any = {
    installFixedDelegate: vi.fn((policy: any) => { factsPolicy = policy; }),
    persistReady: vi.fn(async (sourceId: string, capture: any, proof: object) => {
      await factsPolicy.verifySource(sourceId, 'capture', db); await factsPolicy.verifyCapture(sourceId, capture, proof, db);
      baseline = { baselineId: randomUUID(), sourceId, pinId: randomUUID(), baselineHmac: secrets.fingerprint(capture), captureHmac: secrets.fingerprint(capture), objectManifestHmac: secrets.fingerprint(capture), objectCount: 1, graphCount: 1, protectedUntil: '2099-01-01T00:00:00.000Z' }; return baseline;
    }),
    assertReadyForPacket: vi.fn(async () => ({ capture: { version: 1 }, baseline, packet })),
    appendAttempt: vi.fn(async (binding: any, proof: object) => { await factsPolicy.verifySource(binding.sourceId, 'packet', db); await factsPolicy.verifyPacketFact(binding, null, proof, db); attempts.push(binding); return binding; }),
    appendSendIntent: vi.fn(async (fact: any, proof: object) => { await factsPolicy.verifySource(fact.binding.sourceId, 'before-send', db); await factsPolicy.verifyPacketFact(fact.binding, fact, proof, db); eventFacts.push(fact); }),
    appendOutcome: vi.fn(async (fact: any, proof: object) => { await factsPolicy.verifySource(fact.binding.sourceId, 'outcome', db); await factsPolicy.verifyPacketFact(fact.binding, fact, proof, db); eventFacts.push(fact); }),
  };
  const kong = new KongService(db, redis, secrets, audit, context), plans: any = { load: vi.fn(async () => ({ plan, row: { ...workflow } })), revalidateEntityChange: vi.fn(async () => undefined) };
  const intents: any = { executionMaterial: vi.fn(async () => envelope) }, approval: any = { verifyApprovalSet: vi.fn(async () => ({ format: 2, setId: randomUUID(), setHmac: secrets.fingerprint('approvals'), reviewers: [] })) };
  const capturer: any = { capture: vi.fn(async () => ({ version: 1, fixture: 'already-approved-domain-baseline' })), assertUnchanged: vi.fn(async () => { if (baselineRead) await baselineRead(); }) }, boundary: any = { assertPacket: vi.fn(async () => undefined), assertCurrentRecycleSubject: vi.fn(async () => performance.now() + 5000) };
  const writer: any = { installExecutionDelegate: vi.fn((delegate: any) => { writerDelegate = delegate; }), execute: vi.fn(async (handle: object) => writerDelegate.run(handle, () => packetOperation(handle))) };
  const coordinator: any = { installKernelBridge: vi.fn((value: EntityChangeRecycleKernelBridge) => { bridge = value; }), onModuleInit: vi.fn(), supports: vi.fn(() => true), prepare: vi.fn(async (handle: object) => { originalExecutionHandle = handle; }),
    // Explicit metadata-only domain adapter. It establishes neither a real
    // recycle entry state transition nor any native or approval authority.
    bindPacketOperation: vi.fn(async () => undefined),
    execute: vi.fn(async (handle: object) => context.runEntityChangePacket(handle, () => packetOperation(handle))), verification: vi.fn(() => lastVerification), release: vi.fn() };
  const kernel = new EntityChangeExecutionService(db, redis, secrets, context, kong, authz, audit, plans, approval, intents, facts, capturer, writer, boundary, coordinator);
  kernel.onModuleInit();
  context.installPolicy({ authorizeRequest: async () => ({ before: options.restore ? null : data, platformAdmin: false }), authorizeResponse: async (_decision, response) => response,
    // Controlled domain adapter; the original bridge still issues and checks
    // the operation-bound monotonic current-authority deadline.
    beforeNativeSend: async () => { if (!options.core) await bridge.assertCurrentGraphParties(originalExecutionHandle, {} as any); }
  });
  const issuedTickets: any[] = [], realAuthorize = context.authorizeRequest.bind(context);
  vi.spyOn(context, 'authorizeRequest').mockImplementation(async (...args: Parameters<KongExecutionContextService['authorizeRequest']>) => { const ticket = await realAuthorize(...args); issuedTickets.push({ ticket, method: args[1], path: args[2], frame: context.current() }); return ticket; });
  transport.mockImplementation(async (_base, requestPath, method, body, _query, _auth, _timeout, fence, prepare) => {
    if (prepare) await prepare(); if (!options.skipWireFence || method === 'GET') fence?.();
    if(method==='GET'&&readResponses.has(requestPath))return {...readResponses.get(requestPath)!,bytes:100};
    if (requestPath === '/schemas/services') return { status: 200, body: { fields: [{id:{type:'string'}},{name:{type:'string'}},{host:{type:'string'}},{retries:{type:'integer'}},{tags:{type:'array',elements:{type:'string'}}}] }, bytes: 150 };
    if (method === 'DELETE') return { status: options.deleteStatus ?? 204, body: Object.hasOwn(options, 'deleteBody') ? options.deleteBody : null, bytes: 0 };
    if (method === 'POST') return {status:201,body,bytes:100};
    if (method === 'PATCH') return { status: 200, body: { ...data, ...(body as any) }, bytes: 100 };
    if (requestPath === path && mutation?.state === 'running' && mutation?.remote_completed === false) return { status: 200, body: data, bytes: 100 };
    return { status: 404, body: { message: 'Not found' }, bytes: 20 };
  });

  async function packetOperation(handle: object) {
    originalHandle = handle;
    const info = bridge.packet(handle), mutationContext: any = { clusterId: cid, workspaceId: wid, actor: actor.user, action: packet.mutationAction, entityType: 'services', entityId: options.restore ? undefined : nativeId,
      before: packet.before, payload: packet.body, idempotencyKey: info.operationKey };
    const binding: any = await context.approvedMutationBinding(mutationContext);
    mutation = { id: operationId, cluster_id: cid, workspace_id: wid, actor_id: actor.user.id, workflow_id: workflowId, state: 'running', remote_started: true, remote_completed: false,
      entity_change_source_id: binding.sourceId, entity_change_baseline_id: binding.baselineId, entity_change_attempt_id: binding.attemptId, entity_change_packet_key: binding.packetKey,
      workflow_step_id: null, configuration_step_id: null, before_secret: secrets.encrypt(packet.before, `mutation:${operationId}:before`), payload_secret: secrets.encrypt(packet.body ?? null, `mutation:${operationId}:payload`), idempotency_key: info.operationKey };
    await context.bindApprovedOperation(mutationContext, binding, operationId, db);
    return context.runOperation({ ...mutationContext, operationId, entityType: 'services', entityId: nativeId }, async () => {
      if (beforeWrite) await beforeWrite(handle);
      const send = () => kong.request(cid, packet.method, packet.canonicalPath, packet.body);
      let raw: any;
      try { raw = options.restore || options.core ? await send() : await context.runArchiveDelete({ entryId: randomUUID(), operationId, clusterId: cid, workspaceId: wid, nodes: [{ path, type: 'services', id: nativeId }] }, send); }
      catch (error) { if (rejectedWrite) await rejectedWrite(handle); throw error; }
      mutation.state = 'succeeded'; mutation.remote_completed = true; mutation.result_secret = secrets.encrypt(raw, `mutation:${operationId}:result`);
      if (afterWrite) await afterWrite(handle);
      if(options.restore)await bridge.appendKnownOutcome(handle,undefined,db);
      if (!options.core && !options.restore) {
        const infoAfter = bridge.packet(handle);
        const candidate = { version: 1, clusterId: cid, workspaceId: wid, entryId: randomUUID(), nodeKey: graph.rootKey, packetKey: packet.key,
          attemptId: infoAfter.binding.attemptId, operationId, canonicalPath: path, nativeId, status: 404 };
        // Match the real coordinator: it exposes a verification only after
        // Root's original private claim recorded the actual exact GET404.
        if (infoAfter.verificationStatus === 404 && infoAfter.verificationPath === path) lastVerification = candidate;
        await bridge.appendKnownOutcome(handle, candidate as any, db);
      }
    });
  }
  const run = () => context.runHttp({}, async () => { context.bindHttpActor(actor.user, sessionId); httpCloser = context.captureHttpCloser(); return context.runActor({ actor: actor.user, clusterId: cid, workspaceId: wid, module: 'workflows', action: 'write' },
    () => kernel.execute(plan, { revision: 1, planHash: workflow.plan_hash, confirmed: true, confirm_name: 'native-change' }, actor)); });
  const verificationRead = async () => {
    await context.runInternalRead(cid, 'recycle-check', async () => {
      try { await kong.request(cid, 'GET', path); throw new Error('404 expected'); }
      catch (error) { if (!(error instanceof HttpException && error.getStatus() === 404)) throw error; }
    }, { paths: [path], maxCalls: 1, maxPages: 1, maxRecords: 1, workspaceId: wid });
  };
  const readInput = () => ({ frame: context.current(), cluster, clusterId: cid, workspaceId: wid, operationId, transportScope: scope, method: 'GET', canonicalPath: path,
    mutationAction: packet.mutationAction, query: {}, body: undefined, before: undefined });
  return {readResponses,context, kernel, kong, bridge: () => bridge, run, verificationRead, readInput, issuedTickets, eventFacts, attempts, packet, path, operationId, cid, wid, sessionId, actor, secrets, db, coordinator,
    before: (callback: (handle: object) => Promise<void>) => { beforeWrite = callback; }, after: (callback: (handle: object) => Promise<void>) => { afterWrite = callback; },
    rejected: (callback: (handle: object) => Promise<void>) => { rejectedWrite = callback; },
    baseline: (callback: () => Promise<void>) => { baselineRead = callback; },
    handle: () => originalHandle!, close: () => httpCloser!() };
}

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'de'.repeat(32)); vi.stubEnv('KONG_RATE_WAIT_MS', '0'); transport.mockReset(); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe('M11 non-DELETE genuine packet read observations',()=>{
  it.each([{restore:true},{core:true}])('treats bound-operation whole-graph GETs as reads for $restore/$core without DELETE proof',async options=>{
    const f=fixture(options),consumer=randomUUID(),ids=Array.from({length:4},()=>randomUUID());
    const paths=[`/consumers/${consumer}`,...['key-auth','basic-auth','jwt','oauth2'].map((kind,i)=>`/consumers/${consumer}/${kind}/${ids[i]}`)];
    const missing=`/consumers/${consumer}/hmac-auth/${randomUUID()}`;
    paths.forEach((path,i)=>f.readResponses.set(path,{status:200,body:{id:i?ids[i-1]:consumer,...(i?{consumer:{id:consumer}}:{username:'controlled-consumer'})}}));
    f.readResponses.set(missing,{status:404,body:{message:'Not found'}});
    const observed=vi.spyOn(f.kernel,'observeVerificationResponse');
    f.before(async handle=>{
      expect(f.context.current().operation?.operationId).toBe(f.operationId);
      expect(f.bridge().packet(handle)).toMatchObject({sent:false,wireSpent:false});
      await f.context.runInternalRead(f.cid,'recycle-check',async()=>{
        for(const path of paths)expect(await f.kong.request(f.cid,'GET',path)).toHaveProperty('id');
        await expect(f.kong.request(f.cid,'GET',missing)).rejects.toMatchObject({status:404,response:{code:'KONG_VALIDATION_ERROR'}});
        const input=f.readInput();expect(()=>f.kernel.observeVerificationResponse({...handle},input as any,404)).toThrow();
        expect(()=>f.kernel.observeVerificationResponse({approved:true},input as any,404)).toThrow();
        expect(()=>f.kernel.observeVerificationResponse(handle,{...input,frame:{...input.frame}} as any,404)).toThrow();
      },{paths:[...paths,missing],maxCalls:6,maxRecords:6,maxPages:1,workspaceId:f.wid});
      expect(f.bridge().packet(handle).verificationStatus).toBeUndefined();expect(f.bridge().packet(handle).verificationPath).toBeUndefined();
    });
    f.after(async handle=>{
      await f.context.runInternalRead(f.cid,'recycle-check',()=>f.kong.request(f.cid,'GET',paths[0]),{paths:[paths[0]],maxCalls:1,workspaceId:f.wid});
      expect(f.bridge().packet(handle).verificationStatus).toBeUndefined();expect(f.bridge().packet(handle).verificationPath).toBeUndefined();
    });
    const result=await f.run().catch(error=>{throw new Error(JSON.stringify((error as HttpException).getResponse()));});expect(result).toMatchObject({state:'succeeded'});
    expect(observed.mock.calls.filter(call=>call[0]===f.handle()&&f.issuedTickets.some(t=>t.method==='GET'&&t.frame===call[1].frame))).toHaveLength(7);
    expect(transport.mock.calls.filter(call=>call[2]==='GET'&&[...paths,missing].includes(call[1]))).toHaveLength(7);
    expect(transport.mock.calls.filter(call=>call[2]===f.packet.method)).toHaveLength(1);
    expect(f.eventFacts.find(fact=>fact.kind==='outcome')).toMatchObject({outcome:'succeeded',nativeStatus:options.restore?201:200});
    expect(f.eventFacts.some(fact=>fact.evidence?.deleteVerification)).toBe(false);
  });
  it('keeps original DELETE post-wire 204/null and exact GET404 verification strict',async()=>{
    const f=fixture();f.after(async handle=>{
      await f.context.runInternalRead(f.cid,'recycle-check',async()=>{
        const input=f.readInput();expect(()=>f.kernel.observeVerificationResponse(handle,{...input,canonicalPath:`/services/${randomUUID()}`} as any,404)).toThrow();
        expect(()=>f.kernel.observeVerificationResponse(handle,{...input,operationId:randomUUID()} as any,404)).toThrow();
        expect(()=>f.kernel.observeVerificationResponse(handle,input as any,99)).toThrow();
      },{paths:[f.path],maxCalls:1,workspaceId:f.wid});
      await f.verificationRead();expect(f.bridge().packet(handle)).toMatchObject({verificationStatus:404,verificationPath:f.path});
    });expect(await f.run()).toMatchObject({state:'succeeded'});
    expect(f.eventFacts.find(fact=>fact.kind==='outcome')).toMatchObject({nativeStatus:204,evidence:{deleteVerification:{status:404}}});
  });
});
