import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { EntityPreparedWriterService, type EntityPreparedWriteGrant, type EntityPreparedWriteHandle, type EntityPreparedWriterDelegate } from '../../apps/console-api/src/modules/entities/entity-prepared-writer.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import type { EntityChangePacket } from '../../apps/console-api/src/modules/entities/entity-change.types';

const clusterId = 'a949b292-2e4a-4326-b30d-3a883b5ef3d7', workspaceId = '306a8d36-d1f9-4542-8972-9b30aa1bd67c';
const userId = 'cc2019b5-8061-4a3c-bc19-f24c586e00fa', nativeId = '35b60072-927d-4f3b-bba1-dbc31bd345e4';
const parentId = 'c6439d99-75a0-4f2b-b6d7-a2d3f0c87177', originalId = 'f02f0f79-03bb-4494-9b2c-f3fa4a28a28a';

function fixture() {
  const secrets = new SecretService(), issued = new WeakMap<object, EntityPreparedWriteGrant>();
  const index = { upsert: vi.fn(async () => undefined) }, credentials = { save: vi.fn(async () => undefined) };
  const kong = { request: vi.fn(async (_cid: string, _method: string, _path: string, body?: any) => ({ ...body, id: body?.id ?? nativeId })) };
  const mutations = { execute: vi.fn(async (_context: any, callback: () => Promise<any>) => callback()) };
  const writer = new EntityPreparedWriterService(mutations as any, kong as any, index as any, credentials as any, secrets);
  // Controlled routing fixture only. It is not the Root authorization kernel
  // and provides no evidence of real approvals, permissions or native permits.
  const delegate: EntityPreparedWriterDelegate = { run: async (handle, callback) => {
    const grant = issued.get(handle); if (!grant) throw new ForbiddenException({ code: 'TEST_UNISSUED_HANDLE' });
    return callback(grant);
  } };
  const packet = (overrides: Partial<EntityChangePacket> = {}): EntityChangePacket => {
    const result = { key: 'p-0', order: 0, dependencies: [], method: 'POST', canonicalPath: '/services', nativeType: 'services', nativeId,
      permissionAction: 'write', mutationAction: 'create', before: null, body: { id: nativeId, host: 'business.example', tags: ['kos-ws-pay', 'kos-tag-dGVhbTpwYXk'] },
      ...overrides } as EntityChangePacket;
    result.bodyHmac = secrets.fingerprint(result.body ?? null); result.beforeHmac = secrets.fingerprint(result.before ?? null); return result;
  };
  const issue = (sealedPacket = packet(), obligations: EntityPreparedWriteGrant['obligations'] = [{ kind: 'entity-index', packetKey: sealedPacket.key, entityType: 'services' }],targetHealthBefore?:EntityPreparedWriteGrant['targetHealthBefore']) => {
    const handle = Object.freeze({}) as EntityPreparedWriteHandle;
    issued.set(handle, { clusterId, workspaceId, actor: { user: { id: userId, username: 'unit', superAdmin: true }, workspaceId, idempotencyKey: 'ignored-client-key' },
      operationKey: 'server-packet-operation-0', packet: sealedPacket, obligations,...(targetHealthBefore?{targetHealthBefore}:{}) }); return handle;
  };
  return { writer, secrets, delegate, issue, packet, mutations, kong, index, credentials };
}

describe('M11 fixed prepared writer, source-only unit boundary', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ce'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());
  it('fails closed without a delegate and rejects replacement after bootstrap installation', async () => {
    const f = fixture();
    await expect(f.writer.execute({} as EntityPreparedWriteHandle)).rejects.toMatchObject({ response: { code: 'ENTITY_PREPARED_WRITER_UNAVAILABLE' } });
    f.writer.installExecutionDelegate(f.delegate);
    expect(() => f.writer.installExecutionDelegate(f.delegate)).toThrow();
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('rejects forged handles and unsupported, mismatched or modified packets before native dispatch', async () => {
    const f = fixture(); f.writer.installExecutionDelegate(f.delegate);
    await expect(f.writer.execute({ packet: f.packet(), approved: true } as any)).rejects.toMatchObject({ response: { code: 'TEST_UNISSUED_HANDLE' } });
    const invalid = [
      f.packet({ nativeType: 'vaults' }),
      f.packet({ method: 'DELETE', mutationAction: 'delete', permissionAction: 'delete' }),
      f.packet({ canonicalPath: '/routes' }),
      f.packet({ body: { id: originalId, host: 'other.example' } }),
      f.packet({ nativeType: 'certificates', canonicalPath: '/certificates', body: { id: nativeId, cert: 'unit-cert', key: 'unit-key', snis: ['hidden.example'] } }),
    ];
    const modified = f.packet(); (modified.body as any).host = 'tampered.example'; invalid.push(modified);
    for (const packet of invalid) await expect(f.writer.execute(f.issue(packet))).rejects.toMatchObject({ response: { code: 'ENTITY_PREPARED_PACKET_INVALID' } });
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('reaches the final transport guard and never substitutes a delegate result for native authorization', async () => {
    const f = fixture(); f.writer.installExecutionDelegate(f.delegate);
    f.kong.request.mockRejectedValueOnce(new ForbiddenException({ code: 'TEST_FINAL_TRANSPORT_GUARD_DENIED' }));
    await expect(f.writer.execute(f.issue())).rejects.toMatchObject({ response: { code: 'TEST_FINAL_TRANSPORT_GUARD_DENIED' } });
    expect(f.mutations.execute).toHaveBeenCalledOnce(); expect(f.kong.request).toHaveBeenCalledOnce();
    expect(f.index.upsert).not.toHaveBeenCalled(); expect(f.credentials.save).not.toHaveBeenCalled();
  });
  it('preserves sealed physical tags and body bytes, then indexes only a known completed mutation', async () => {
    const f = fixture(), packet = f.packet(); f.writer.installExecutionDelegate(f.delegate);
    f.index.upsert.mockImplementationOnce(async () => { expect(f.kong.request).toHaveBeenCalledOnce(); expect(f.mutations.execute).toHaveBeenCalledOnce(); });
    const result = await f.writer.execute(f.issue(packet));
    expect(f.kong.request).toHaveBeenCalledWith(clusterId, 'POST', '/services', packet.body);
    const context = f.mutations.execute.mock.calls[0][0];
    expect(context).toMatchObject({ entityType: 'services', action: 'create', idempotencyKey: 'server-packet-operation-0', payload: packet.body });
    expect(context.entityId).toBeUndefined(); expect(context.before).toBeUndefined(); expect(f.secrets.fingerprint(context.payload)).toBe(packet.bodyHmac);
    expect(f.index.upsert).toHaveBeenCalledWith(clusterId, 'services', packet.body);
    expect(result).toEqual({ packetKey: 'p-0', operationKey: 'server-packet-operation-0', nativeId, state: 'succeeded', metadata: 'complete' });
    expect(JSON.stringify(result)).not.toContain('business.example');
  });
  it('appends Target weight history under the logical original ID and sends health with no wire body', async () => {
    const f = fixture(); f.writer.installExecutionDelegate(f.delegate);
    const before = { id: originalId, target: 'echo.example:8080', weight: 100, upstream: { id: parentId },created_at:1,tags:[] };
    const weight = f.packet({ nativeType: 'targets', parentId, originalNativeId: originalId, mutationAction: 'update',
      canonicalPath: `/upstreams/${parentId}/targets`, before, body: { id: nativeId, target: before.target, weight: 80, tags: ['kos-ws-pay'] } });
    await f.writer.execute(f.issue(weight, []));
    expect(f.mutations.execute.mock.calls[0][0]).toMatchObject({ entityType: 'targets', entityId: originalId, parentId, action: 'update', payload: weight.body });
    expect(f.kong.request).toHaveBeenNthCalledWith(1, clusterId, 'POST', `/upstreams/${parentId}/targets`, weight.body);
    const health = f.packet({ key: 'p-1', nativeType: 'targets', parentId, nativeId: originalId, mutationAction: 'mark_unhealthy',
      canonicalPath: `/upstreams/${parentId}/targets/${originalId}/unhealthy`, before, body: undefined });
    const observation:any={version:1,kind:'kong-1.5-target-health-observation',upstreamId:parentId,targetId:originalId,targetAddress:before.target,
      nodeId:'unit-node',health:'HEALTHY',targetRow:{...before,health:'HEALTHY'},targetHmac:f.secrets.fingerprint(before),nodeScope:'current_admin_node',recoverableOverride:false};
    observation.observationHmac=f.secrets.fingerprint(observation);
    f.kong.request.mockResolvedValueOnce(null);
    await f.writer.execute(f.issue(health, [],observation));
    expect(f.mutations.execute.mock.calls[1][0]).toMatchObject({ entityId: originalId, parentId, action: 'mark_unhealthy', payload: { state: 'unhealthy' } });
    expect(f.kong.request).toHaveBeenNthCalledWith(2, clusterId, 'POST', `/upstreams/${parentId}/targets/${originalId}/unhealthy`, undefined);
    await expect(f.mutations.execute.mock.results[1].value).resolves.toBeNull();
    expect(f.index.upsert).not.toHaveBeenCalled(); expect(f.credentials.save).not.toHaveBeenCalled();
  });
  it('keeps trusted credential plaintext for metadata and does not resend native or leak secrets after metadata failure or replay', async () => {
    const f = fixture(); f.writer.installExecutionDelegate(f.delegate);
    const packet = f.packet({ nativeType: 'basic-auth', credentialKind: 'basic-auth', parentId, canonicalPath: `/consumers/${parentId}/basic-auth`,
      body: { id: nativeId, username: 'basic-user', password: 'trusted-unit-plaintext' } });
    const obligation = { kind: 'credential-remember' as const, packetKey: packet.key, consumerId: parentId, credentialKind: 'basic-auth' as const, rawInput: packet.body! };
    f.kong.request.mockResolvedValueOnce({ ...packet.body, password: 'native-unit-hash' });
    f.credentials.save.mockRejectedValueOnce(new Error('persistence detail trusted-unit-plaintext'));
    const handle = f.issue(packet, [obligation]);
    let error: any;
    try { await f.writer.execute(handle); } catch (caught) { error = caught; }
    expect(error.getResponse()).toEqual({ code: 'ENTITY_PREPARED_METADATA_INCOMPLETE', message: '网关变更已完成，元数据待恢复；请核验原操作，勿重新提交',
      packetKey: 'p-0', operationKey: 'server-packet-operation-0', nativeId, knownNativeComplete: true });
    expect(JSON.stringify(error.getResponse())).not.toContain('trusted-unit-plaintext'); expect(JSON.stringify(error.getResponse())).not.toContain('native-unit-hash');
    expect(f.credentials.save).toHaveBeenCalledWith(clusterId, parentId, 'basic-auth', { ...packet.body, password: 'native-unit-hash' }, packet.body);
    expect(f.mutations.execute.mock.calls[0][0]).toMatchObject({ entityType: 'credentials', parentId, credentialKind: 'basic-auth', idempotencyKey: 'server-packet-operation-0' });
    // A completed-operation replay does not invoke the native callback. Root
    // must recover metadata from the original durable operation receipt.
    f.mutations.execute.mockImplementationOnce(async () => ({ id: nativeId }));
    await expect(f.writer.execute(handle)).rejects.toMatchObject({ response: { code: 'ENTITY_PREPARED_METADATA_RECOVERY_REQUIRED', knownNativeComplete: true } });
    expect(f.kong.request).toHaveBeenCalledOnce(); expect(f.credentials.save).toHaveBeenCalledOnce();
  });
});
