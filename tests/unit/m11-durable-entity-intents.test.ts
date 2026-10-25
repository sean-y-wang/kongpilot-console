import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { SecretService, canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';
import { EntityChangeIntentsService } from '../../apps/console-api/src/modules/workflows/entity-change-intents.service';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';
import { entityChangeIntentAad } from '../../apps/console-api/src/modules/workflows/entity-change-workflow';
import type { PreparedEntityChange } from '../../apps/console-api/src/modules/entities/entity-change.types';
import { entityDelegationAad } from '../../apps/console-api/src/modules/workflows/entity-change-schedule.repository';
import type { EntityScheduledDraft } from '../../apps/console-api/src/modules/workflows/entity-change-schedule.contract';

/** Real repository/HMAC/encryption and workflow validator. SQL/compiler/auth
 * adapters are isolated; live PostgreSQL/native authorization needs Root's gate. */
function fixture() {
  const secrets = new SecretService(), cid = randomUUID(), wid = randomUUID(), userId = randomUUID(), nativeId = randomUUID(), definitionId = randomUUID();
  const actor = { user: { id: userId, username: 'intent-owner', superAdmin: false }, workspaceId: wid, idempotencyKey: 'durable-original-prepare', requestId: randomUUID(), ip: '192.0.2.50' };
  const request = { kind: 'entity' as const, action: 'update' as const, entityType: 'services' as const, entityId: nativeId, body: { host: 'after.internal' } };
  const before = { id: nativeId, host: 'before.internal', tags: ['kos-ws-pay'] }, packet = { key: 'packet-1', order: 1, dependencies: [], method: 'PATCH' as const, canonicalPath: `/services/${nativeId}`, nativeType: 'services', nativeId, permissionAction: 'write' as const, mutationAction: 'update' as const, body: request.body, before, bodyHmac: secrets.fingerprint(request.body), beforeHmac: secrets.fingerprint(before) };
  const payload = { version: 1 as const, clusterId: cid, workspaceId: wid, requesterId: userId, permissionVersion: 'original-prepare-permission-version', scope: { transportScope: 'a'.repeat(64), clusterRevision: 1, workspaceRevision: 1, kongVersion: '1.5.1', adapter: 'kong-1.5' }, request, prerequisites: [], schemas: [], packets: [packet], metadataObligations: [], recovery: { state: 'baseline-required' as const, blockerCodes: ['EXECUTION_BASELINE_REQUIRED'], objects: [] }, impact: { version: 1 as const, keyId: 'b'.repeat(64), keys: [], domains: [], wildcards: [] } };
  const prepared: PreparedEntityChange = { ...payload, changeDigest: secrets.fingerprint(payload) }, bytes = canonicalJson(prepared), review = { version: 1, clusterId: cid, workspaceId: wid, changeDigest: prepared.changeDigest, changes: [{ entityType: 'services', nativeId, action: 'update', before, after: request.body }], impact: { changedObjects: 1, nativePackets: 1, traffic: null, trafficAvailability: 'unavailable', globalPlugin: false }, recovery: prepared.recovery };
  const state: any = { intent: null, version: null, packets: [], submission: null, plans: [], definition: { id: definitionId, version: 1, policyHash: secrets.fingerprint({ version: 1, mode: 'single' }) }, credentialEpoch: '1', policyFormat: 1, policyTtl: 24, permissionVersion: 'current-permission-version' };
  const db: any = { one: vi.fn(async (sql: string, p: any[] = []) => {
    if (sql.includes('FROM iam_epoch')) return { version: 1 };
    if (sql.includes('FROM users')) return { credential_epoch: state.credentialEpoch };
    if (sql.includes('FROM workflow_definition_versions')) return { approval_format: state.policyFormat, policy: { intentTtlHours: state.policyTtl } };
    if (sql.includes('FROM clusters')) return { execution_mode: 'approval', revision: 1 };
    if (sql.includes('FROM entity_change_intent_versions')) return state.version && p[0] === state.version.intent_id && p[1] === cid && p[2] === wid && p[3] === 1 ? state.version : null;
    if (sql.includes('FROM entity_change_intents')) {
      if (sql.includes('requester_id=$1')) return state.intent && p[0] === userId && p[1] === state.intent.prepare_key ? state.intent : null;
      return state.intent && p[0] === state.intent.id && p[1] === cid && p[2] === wid ? state.intent : null;
    }
    if (sql.includes('FROM entity_change_submissions')) return state.submission;
    if (sql.includes('FROM entity_change_schedules')) return state.schedule??null;
    throw new Error(`Unimplemented fixture query: ${sql}`);
  }), query: vi.fn(async (sql: string) => sql.includes('FROM entity_change_intent_packets') ? state.packets : []), exec: vi.fn(async (sql: string, p: any[]) => {
    if (sql.startsWith('INSERT INTO entity_change_intents(')) state.intent = { id: p[0], cluster_id: p[1], workspace_id: p[2], requester_id: p[3], credential_epoch: p[4], prepare_key: p[5], request_hmac: p[6], issued_at: p[7], expires_at: p[8] };
    else if (sql.startsWith('INSERT INTO entity_change_intent_versions(')) state.version = { cluster_id: p[0], workspace_id: p[1], intent_id: p[2], intent_revision: 1, requester_id: p[3], credential_epoch: p[4], issued_at: p[5], expires_at: p[6], execution_mode: p[7], definition_id: p[8], definition_version: p[9], policy_hash: p[10], change_digest: p[11], material_hmac: p[12], packet_manifest_hmac: p[13], packet_count: p[14], packet_manifest: JSON.parse(p[15]), envelope_ciphertext: p[16], safe_review: JSON.parse(p[17]) };
    else if (sql.startsWith('INSERT INTO entity_change_intent_packets(')) state.packets.push({ material_hmac: p[3], change_digest: p[4], packet_manifest_hmac: p[5], packet_key: p[6], packet_order: p[7], dependencies: p[8], method: p[9], path_hmac: p[10], native_type: p[11], native_id: p[12], parent_id: p[13], credential_kind: p[14], original_native_id: p[15], mutation_action: p[16], permission_action: p[17], body_hmac: p[18], before_hmac: p[19] });
    else if (sql.startsWith('INSERT INTO entity_change_submissions(')) state.submission = { actor_id: p[7], submit_key: p[8], request_hmac: p[9], workflow_id: p[10], workflow_plan_revision: 1, workflow_plan_hash: p[11], material_hmac: p[4], change_digest: p[5], packet_manifest_hmac: p[6] };
    else throw new Error(`Unexpected write: ${sql}`); return 1;
  }), transaction: vi.fn(async (fn: any) => fn(db)) };
  const compiler: any = { prepare: vi.fn(async () => prepared), project: vi.fn(async () => review), projectStored: vi.fn(async () => review), revalidateStored: vi.fn(async (material: any) => { expect(canonicalJson(material)).toBe(bytes); }) };
  const plans: any = { definitions: vi.fn(), definition: vi.fn(async () => state.definition), persist: vi.fn(async (plan: any) => { validateWorkflowPlan(plan); state.plans.push(plan); }) }, authz: any = { permissionVersion: vi.fn(async () => state.permissionVersion), assertCluster: vi.fn() }, redis: any = { withLock: vi.fn(async (_key: any, fn: any) => fn()), assertLeaseOwnership: vi.fn() };
  const subject = vi.fn(async (_envelope: any, id: string) => { if (id !== userId) throw new ForbiddenException(); });
  const service = new EntityChangeIntentsService(db, secrets, redis, compiler, plans, {} as any, {} as any, { append: vi.fn() } as any, authz);
  service.installSubjectPolicy({ assertSubject: subject, verifyReviewer: vi.fn() });
  const prepare = (ttlHours?: number) => service.prepare(cid, { change: request, ...(ttlHours === undefined ? {} : { ttlHours }) }, actor);
  const submit = (receipt: any, extra: any = {}) => service.submit(cid, receipt.id, { revision: receipt.revision, materialHmac: receipt.materialHmac, confirmed: true, confirm_name: 'native-change' }, { ...actor, idempotencyKey: 'durable-original-submit', ...extra });
  return { service, secrets, actor, cid, wid, state, compiler, plans, db, prepared, bytes, prepare, submit };
}
beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-13T12:00:00Z')); }); afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });
describe('M11 immutable durable entity review intent', () => {
  it('persists the original material bytes with an independent default 24-hour expiry and no session/job source', async () => {
    const f = fixture(), receipt = await f.prepare(), envelope: any = f.secrets.decrypt(f.state.version.envelope_ciphertext, entityChangeIntentAad(f.cid, f.wid, receipt.id, 1));
    expect(Date.parse(receipt.expiresAt) - Date.parse(receipt.issuedAt)).toBe(24 * 3600000); expect(canonicalJson(envelope.prepared)).toBe(f.bytes); expect(envelope).not.toHaveProperty('sessionId'); expect(f.db.exec.mock.calls.every(([sql]: any[]) => !sql.includes('execution_sources'))).toBe(true);
  });
  it('submits later using current caller validation while keeping original IDs, material and expiry', async () => {
    const f = fixture(), receipt = await f.prepare(), ciphertext = f.state.version.envelope_ciphertext; vi.setSystemTime(new Date('2026-10-13T14:00:00Z')); f.state.permissionVersion = 'later-current-permission-version';
    const submitted = await f.submit(receipt, { requestId: randomUUID() }); expect(submitted.submissionCompleted).toBe(true); expect(f.compiler.revalidateStored).toHaveBeenCalledWith(expect.objectContaining({ permissionVersion: 'original-prepare-permission-version' }), expect.objectContaining({ user: f.actor.user }), 'write', 'submit');
    expect(f.state.version.envelope_ciphertext).toBe(ciphertext); expect(f.state.plans[0].expiresAt).toBe(receipt.expiresAt); expect(f.state.plans[0].steps[0].nativeRequests).toEqual([]); expect(canonicalJson(f.prepared)).toBe(f.bytes);
  });
  it('requires a new intent when its frozen policy changes or TTL exceeds policy', async () => {
    const f = fixture(), receipt = await f.prepare(); f.state.definition = { ...f.state.definition, version: 2 }; await expect(f.submit(receipt)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_INTENT_POLICY_CHANGED' } }); expect(f.state.submission).toBeNull();
    const g = fixture(); g.state.policyFormat = 2; g.state.policyTtl = 1; await expect(g.prepare(2)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_POLICY_TTL_EXCEEDED' } }); expect(g.state.intent).toBeNull();
  });
  it('reads historical facts without fresh-before calls after the actual objects change', async () => {
    const f = fixture(), receipt = await f.prepare(); f.compiler.revalidateStored.mockRejectedValue(new Error('Current before changed'));
    const result = await f.service.get(f.cid, receipt.id, f.actor); expect(result.review.changes[0].before.host).toBe('before.internal'); expect(f.compiler.projectStored).toHaveBeenCalled(); expect(f.compiler.revalidateStored).not.toHaveBeenCalled();
  });
  it('rejects foreign scope, changed credential epoch and substituted packet source', async () => {
    const f = fixture(), receipt = await f.prepare(); await expect(f.service.get(f.cid, receipt.id, { ...f.actor, workspaceId: randomUUID() })).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_INTENT_NOT_FOUND' } });
    f.state.credentialEpoch = '2'; await expect(f.submit(receipt)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_REQUESTER_CREDENTIAL_CHANGED' } }); expect(f.state.submission).toBeNull();
    f.state.packets[0].native_id = randomUUID(); await expect(f.service.get(f.cid, receipt.id, f.actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_INTENT_PACKET_SOURCE_INVALID' } });
  });
  it('reuses each original prepare/submit receipt and forbids changing the original key domain', async () => {
    const f = fixture(), receipt = await f.prepare(), replay = await f.prepare(); expect(replay.materialHmac).toBe(receipt.materialHmac); expect(f.compiler.prepare).toHaveBeenCalledTimes(1);
    const first = await f.submit(receipt), second = await f.submit(receipt); expect(second.workflowId).toBe(first.workflowId); expect(f.plans.persist).toHaveBeenCalledTimes(1);
    await expect(f.prepare(24)).rejects.toMatchObject({ response: { code: 'IDEMPOTENCY_CONFLICT' } }); await expect(f.submit(receipt, { idempotencyKey: 'another-submit-key' })).rejects.toMatchObject({ response: { code: 'IDEMPOTENCY_CONFLICT' } });
  });
  it('rejects newly prepared oversized V1 material before intent insertion and keeps the actual AES envelope below SQL020 cipher budget',async()=>{
    const f=fixture();f.compiler.project.mockResolvedValue({version:1,padding:'x'.repeat(2*1024*1024)});
    await expect(f.prepare()).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_INTENT_MATERIAL_BUDGET',message:expect.stringContaining('拆分')}});expect(f.state.intent).toBeNull();expect(f.db.exec).not.toHaveBeenCalled();
    const overhead=Buffer.byteLength(JSON.stringify({payload:''})),boundary={payload:'x'.repeat(2*1024*1024-overhead)};
    expect(Buffer.byteLength(JSON.stringify(boundary))).toBe(2*1024*1024);const cipher=f.secrets.encrypt(boundary,'public-budget-fixture');
    expect(Buffer.byteLength(cipher)).toBeLessThan(3*1024*1024);expect(f.secrets.decrypt(cipher,'public-budget-fixture')).toEqual(boundary);
  });
});
function scheduledFixture(){
  const f=fixture(),available=vi.fn(async()=>undefined),persist=vi.fn(async(draft:Readonly<EntityScheduledDraft>,actor:any,tx:any)=>{
    expect(tx).toBe(f.db);expect(actor.user.id).toBe(f.actor.user.id);expect(f.state.version.material_hmac).toBe(draft.binding.materialHmac);
    const b=draft.binding,d=draft.delegation;
    f.state.schedule={id:draft.scheduleId,version:1,cluster_id:b.clusterId,workspace_id:b.workspaceId,intent_id:b.intentId,intent_revision:b.intentRevision,material_hmac:b.materialHmac,change_digest:b.changeDigest,packet_manifest_hmac:b.packetManifestHmac,
      owner_id:d.ownerId,owner_credential_epoch:d.ownerCredentialEpoch,spec_hmac:draft.specHmac,spec:draft.spec,not_before:draft.spec.notBefore,window_start:draft.spec.windowStart,window_end:draft.spec.windowEnd,expires_at:d.expiresAt,transport_scope:draft.transportScope,impact:draft.impact,impact_hmac:draft.impactHmac,
      delegation_id:d.id,delegation_version:1,actual_delegation_version:1,delegation_hmac:draft.delegationHmac,delegation_owner_id:d.ownerId,executor_id:d.executorId,delegation_owner_epoch:d.ownerCredentialEpoch,executor_credential_epoch:d.executorCredentialEpoch,
      policy_hash:d.policyHash,delegation_issued_at:d.issuedAt,delegation_expires_at:d.expiresAt,delegation_ciphertext:f.secrets.encrypt(d,entityDelegationAad(b.clusterId,b.workspaceId,d.id))};
    return {id:draft.scheduleId,revision:1,state:'pending-approval',intentId:b.intentId,notBefore:draft.spec.notBefore,windowStart:draft.spec.windowStart,windowEnd:draft.spec.windowEnd,workflowId:null,claimId:null,reasonCode:null,nativeAuthority:false};
  }),body={change:{kind:'entity',action:'update',entityType:'services',entityId:f.prepared.packets[0].nativeId,body:{host:'after.internal'}},
    schedule:{version:1,executorId:f.actor.user.id,notBefore:'2026-10-13T14:00:00.000Z',windowStart:'2026-10-13T13:30:00.000Z',windowEnd:'2026-10-13T14:15:00.000Z'},confirmed:true,confirm_name:'scheduled-change'};
  const install=()=>f.service.installSchedulingDelegate({assertAvailable:available,persistDraft:persist as any}),prepare=()=>f.service.prepareScheduled(f.cid,body,f.actor);
  return {...f,available,persist,body,install,prepareScheduled:prepare};
}
describe('M11 scheduled envelope V2 preparation (source-only, no scheduler activation)',()=>{
  it('requires once-installed Root availability and writes nothing when the scheduling adapter or SQL is unavailable',async()=>{
    const f=scheduledFixture();await expect(f.prepareScheduled()).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_PREPARATION_NOT_ENABLED'}});expect(f.db.exec).not.toHaveBeenCalled();
    f.install();expect(()=>f.install()).toThrow();f.available.mockRejectedValue(new Error('SQL024 unavailable'));await expect(f.prepareScheduled()).rejects.toThrow('SQL024 unavailable');expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('seals a new exact minute window and real owner delegation inside the outer HMAC while preserving foundation bytes and original V1 shape',async()=>{
    const f=scheduledFixture();f.install();const receipt=await f.prepareScheduled(),envelope:any=f.secrets.decrypt(f.state.version.envelope_ciphertext,entityChangeIntentAad(f.cid,f.wid,receipt.id,1));
    expect(envelope.version).toBe(2);expect(envelope.expiresAt).toBe(f.body.schedule.windowEnd);expect(envelope.ttlHours).toBe(24);expect(envelope.scheduling.delegation.expiresAt).toBe(envelope.expiresAt);
    expect(envelope.scheduling.delegation.ownerId).toBe(f.actor.user.id);expect(envelope.scheduling.delegation.executorId).toBe(f.actor.user.id);expect(envelope.scheduling.delegation.ownerCredentialEpoch).toBe('1');expect(envelope).not.toHaveProperty('sessionId');
    expect(f.secrets.fingerprint(envelope)).toBe(receipt.materialHmac);expect(canonicalJson(envelope.prepared)).toBe(f.bytes);expect(receipt.capabilities.scheduleSubmit).toBe(receipt.capabilities.submit);expect(receipt.nativeExecutionAvailable).toBe(false);
    expect(f.persist).toHaveBeenCalledTimes(1);expect(f.persist.mock.calls[0][2]).toBe(f.db);expect(f.db.exec.mock.calls.every(([sql]:any[])=>!sql.includes('execution_sources')&&!sql.includes('workflow_executions'))).toBe(true);
    const old=fixture(),v1=await old.prepare(),original:any=old.secrets.decrypt(old.state.version.envelope_ciphertext,entityChangeIntentAad(old.cid,old.wid,v1.id,1));expect(original.version).toBe(1);expect(original).not.toHaveProperty('scheduling');expect(v1).not.toHaveProperty('schedule');
  });
  it('reuses the exact original scheduled key but rejects changed windows, foreign executors and excess TTL without extending authority',async()=>{
    const f=scheduledFixture();f.install();const first=await f.prepareScheduled(),second=await f.prepareScheduled();expect(second.materialHmac).toBe(first.materialHmac);expect(f.compiler.prepare).toHaveBeenCalledTimes(1);
    f.body.schedule.windowEnd='2026-10-13T14:16:00.000Z';await expect(f.prepareScheduled()).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});
    const g=scheduledFixture();g.install();g.body.schedule.executorId=randomUUID();await expect(g.prepareScheduled()).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_SPEC_INVALID'}});expect(g.state.intent).toBeNull();
    const h=scheduledFixture();h.install();h.body.schedule.windowEnd='2026-10-14T14:15:00.000Z';await expect(h.prepareScheduled()).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_WINDOW_TTL_EXCEEDED'}});expect(h.state.intent).toBeNull();
  });
  it('checks actual immutable schedule storage on reads and current identity/scope/definition on V2 submission with fresh approval binding',async()=>{
    const f=scheduledFixture();f.install();const receipt=await f.prepareScheduled();vi.setSystemTime(new Date('2026-10-13T13:00:00Z'));await f.submit(receipt);
    expect(f.state.plans).toHaveLength(1);expect(f.state.plans[0].expiresAt).toBe(f.body.schedule.windowEnd);expect(f.state.plans[0].steps[0].nativeRequests).toEqual([]);
    f.state.schedule.spec_hmac='00'.repeat(32);await expect(f.service.get(f.cid,receipt.id,f.actor)).rejects.toMatchObject({response:{code:'ENTITY_SCHEDULE_STORAGE_BINDING_INVALID'}});
    const revoked=scheduledFixture();revoked.install();const r=await revoked.prepareScheduled();revoked.state.credentialEpoch='2';await expect(revoked.submit(r)).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_REQUESTER_CREDENTIAL_CHANGED'}});expect(revoked.state.submission).toBeNull();
  });
  it('requires the draft and all intent facts to share one transaction and rolls back every write if Root drafting fails',async()=>{
    const f=scheduledFixture();f.install();f.db.transaction.mockImplementation(async(fn:any)=>{const before=structuredClone(f.state);try{return await fn(f.db);}catch(error){Object.keys(f.state).forEach(key=>delete f.state[key]);Object.assign(f.state,before);throw error;}});
    f.persist.mockRejectedValue(new Error('Draft verification failed'));await expect(f.prepareScheduled()).rejects.toThrow('Draft verification failed');expect(f.state.intent).toBeNull();expect(f.state.version).toBeNull();expect(f.state.packets).toEqual([]);expect(f.state.schedule).toBeUndefined();
  });
  it('rejects oversized V2 material before intent and schedule writes without widening the immutable SQL020 budget',async()=>{
    const f=scheduledFixture();f.install();f.compiler.project.mockResolvedValue({version:1,padding:'x'.repeat(2*1024*1024)});
    await expect(f.prepareScheduled()).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_INTENT_MATERIAL_BUDGET'}});expect(f.state.intent).toBeNull();expect(f.persist).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });
});
