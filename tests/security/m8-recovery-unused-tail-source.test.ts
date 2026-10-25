// @ts-nocheck -- actual continuation helper with synthetic RAM dependencies.
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
const native = vi.hoisted(() => ({ recycleAndRestore: vi.fn(), nativeRead: vi.fn(), sixCredentialProxyAcceptance: vi.fn(),
  CREDENTIAL_KINDS: Object.freeze(['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls']) }));
vi.mock('./lib/m8-native-acceptance.mjs', () => native);
import { finishM8FiveClassRecovery } from './lib/m8-transfer-acceptance.mjs';

const consumerEntryId = '57e3ac7b-cc7a-4ed1-aff8-802339029411';
function fixture(corruption = null) {
  const area = { cid: randomUUID(), wid: randomUUID() }, consumer = { id: randomUUID() };
  const f = { area, consumer, service: { id: randomUUID() }, upstream: { id: randomUUID() }, certificate: { id: randomUUID() },
    sni: { id: randomUUID() }, target: { id: randomUUID(), target: 'synthetic-upstream:8081', weight: 100 }, plugins: { 'key-auth': { id: randomUUID() } },
    credentials: Object.fromEntries(native.CREDENTIAL_KINDS.map(kind => [kind, { id: randomUUID(), consumer: { id: consumer.id } }])) };
  const prefix = [{ ...area, id: randomUUID(), type: 'plugins', originalId: f.plugins['key-auth'].id, name: 'Synthetic original plugin', state: 'deleted' },
    { ...area, id: consumerEntryId, type: 'consumers', originalId: consumer.id, name: 'Synthetic original consumer', state: 'deleted' }];
  const consumerReceipt = { entryId: consumerEntryId, state: 'restored', restored: [
    { type: 'consumers', originalId: consumer.id, restoredId: consumer.id },
    ...Object.entries(f.credentials).map(([kind, credential]) => ({ type: kind, originalId: credential.id, restoredId: credential.id }))] };
  native.recycleAndRestore.mockReset().mockImplementation(async (_h, _actor, actualArea, type, original) => {
    const entry = { ...actualArea, id: randomUUID(), type, originalId: original.id, state: 'deleted' }; h.state.recycleEntries.push(entry);
    return { entry, restored: { state: 'restored', entryId: entry.id }, current: { id: original.id } };
  });
  native.nativeRead.mockReset().mockImplementation(async (_h, _a, _area, type, id) => type === 'plugins' ? { id } :
    { id: f.sni.id, certificate: { id: corruption === 'sniCertificate' ? randomUUID() : f.certificate.id } });
  native.sixCredentialProxyAcceptance.mockReset().mockResolvedValue(undefined);
  const h = { state: { nativeFixture: f, recycleEntries: prefix }, save: vi.fn(), check: (condition, name) => { if (!condition) throw Error(name); }, data: value => value.payload.data,
    request: vi.fn(async (_actor, path) => {
      const kind = native.CREDENTIAL_KINDS.find(value => path.includes(`/credentials/${value}/`));
      if (kind) return { payload: { data: { entity: { id: corruption === 'credentialId' ? randomUUID() : f.credentials[kind].id,
        consumer: { id: corruption === 'credentialParent' ? randomUUID() : consumer.id } } } } };
      if (path.includes(`/upstreams/${f.upstream.id}/targets?`)) return { payload: { data: { items: [{ ...f.target,
        ...(corruption === 'targetId' ? { id: randomUUID() } : {}), ...(corruption === 'targetWeight' ? { weight: 0 } : {}) }] } } };
      throw Error('unexpected synthetic read');
    }) };
  return { h, f, prefix, consumerReceipt, actors: { admin: { user: { id: randomUUID() }, sid: randomUUID() } } };
}

describe('independent exact unused M8 five-class recovery tail', () => {
  it('inherits two exact restored originals and only deletes/restores the remaining three classes once', async () => {
    const { h, f, consumerReceipt, actors } = fixture();
    const result = await finishM8FiveClassRecovery(h, actors, consumerReceipt);
    expect(native.recycleAndRestore.mock.calls.map(call => call[3])).toEqual(['services', 'upstreams', 'certificates']);
    expect(native.recycleAndRestore.mock.calls.map(call => call[4].id)).toEqual([f.service.id, f.upstream.id, f.certificate.id]);
    for (const call of native.recycleAndRestore.mock.calls) expect(call[2]).toEqual(f.area);
    expect(h.request.mock.calls.filter(call => call[1].includes('/credentials/'))).toHaveLength(6);
    expect(native.sixCredentialProxyAcceptance.mock.calls.map(call => call[2])).toEqual(['consumer-graph-restored', 'five-classes-restored']);
    expect(result.map(value => value.type)).toEqual(['plugins', 'consumers', 'services', 'upstreams', 'certificates']);
    expect(result[0]).toMatchObject({ inheritedOriginalSuccess: true, fullyRestored: true });
    expect(result[1]).toMatchObject({ entryId: consumerEntryId, id: f.consumer.id, fullyRestored: true });
    expect(h.state.fiveClassRecovery).toEqual(result); expect(h.public.fiveClassRecovery).toEqual(result);
  });
  it('requires the literal original Consumer entry and a fully restored receipt before any read or write', async () => {
    for (const change of [{ entryId: randomUUID() }, { state: 'partially_restored' }]) {
      const { h, consumerReceipt, actors } = fixture();
      await expect(finishM8FiveClassRecovery(h, actors, { ...consumerReceipt, ...change })).rejects.toThrow();
      expect(native.nativeRead).not.toHaveBeenCalled(); expect(native.recycleAndRestore).not.toHaveBeenCalled(); expect(h.request).not.toHaveBeenCalled();
    }
  });
  it('rejects mistyped, foreign-scoped or duplicated original archive anchors before unused-tail writes', async () => {
    for (const change of ['pluginType', 'consumerType', 'pluginScope', 'consumerScope', 'duplicatePlugin', 'duplicateConsumer']) {
      const { h, prefix, consumerReceipt, actors } = fixture();
      if (change === 'pluginType') prefix[0].type = 'services';
      if (change === 'consumerType') prefix[1].type = 'services';
      if (change === 'pluginScope') prefix[0].wid = randomUUID();
      if (change === 'consumerScope') prefix[1].cid = randomUUID();
      if (change === 'duplicatePlugin') prefix.push(structuredClone(prefix[0]));
      if (change === 'duplicateConsumer') prefix.push(structuredClone(prefix[1]));
      await expect(finishM8FiveClassRecovery(h, actors, consumerReceipt), change).rejects.toThrow();
      expect(native.recycleAndRestore).not.toHaveBeenCalled(); expect(h.state.fiveClassRecovery).toBeUndefined();
    }
  });
  it('requires all six original credential kinds and IDs before unused native changes', async () => {
    const { h, f, consumerReceipt, actors } = fixture(); delete f.credentials.jwt;
    await expect(finishM8FiveClassRecovery(h, actors, consumerReceipt)).rejects.toThrow();
    expect(native.recycleAndRestore).not.toHaveBeenCalled(); expect(h.state.fiveClassRecovery).toBeUndefined();
  });
  it('rejects any substituted original credential ID or Consumer parent before authentication and tail writes', async () => {
    for (const change of ['credentialId', 'credentialParent']) {
      const { h, consumerReceipt, actors } = fixture(change);
      await expect(finishM8FiveClassRecovery(h, actors, consumerReceipt)).rejects.toThrow('original credential parent and ID');
      expect(native.sixCredentialProxyAcceptance).not.toHaveBeenCalled(); expect(native.recycleAndRestore).not.toHaveBeenCalled();
    }
  });
  it('rejects a replacement Target or changed weight without continuing to certificate or claiming completion', async () => {
    for (const change of ['targetId', 'targetWeight']) {
      const { h, consumerReceipt, actors } = fixture(change);
      await expect(finishM8FiveClassRecovery(h, actors, consumerReceipt)).rejects.toThrow('original target UUID');
      expect(native.recycleAndRestore.mock.calls.map(call => call[3])).toEqual(['services', 'upstreams']);
      expect(h.state.fiveClassRecovery).toBeUndefined(); expect(native.sixCredentialProxyAcceptance).toHaveBeenCalledTimes(1);
    }
  });
  it('rejects a restored SNI which points to a different certificate before the final authentication proof', async () => {
    const { h, consumerReceipt, actors } = fixture('sniCertificate');
    await expect(finishM8FiveClassRecovery(h, actors, consumerReceipt)).rejects.toThrow('original SNI relation');
    expect(native.recycleAndRestore.mock.calls.map(call => call[3])).toEqual(['services', 'upstreams', 'certificates']);
    expect(native.sixCredentialProxyAcceptance).toHaveBeenCalledTimes(1); expect(h.state.fiveClassRecovery).toBeUndefined();
  });
  it('never repeats a completed scenario or a partially used Service/Upstream/Certificate tail', async () => {
    for (const change of ['completed', 'services', 'upstreams', 'certificates']) {
      const { h, f, consumerReceipt, actors } = fixture();
      if (change === 'completed') h.state.fiveClassRecovery = [{ type: 'plugins', fullyRestored: true }];
      else h.state.recycleEntries.push({ ...f.area, type: change, id: randomUUID(), originalId: f[change === 'services' ? 'service' : change === 'upstreams' ? 'upstream' : 'certificate'].id, state: 'deleted' });
      await expect(finishM8FiveClassRecovery(h, actors, consumerReceipt), change).rejects.toThrow();
      expect(native.recycleAndRestore).not.toHaveBeenCalled();
    }
  });
});
