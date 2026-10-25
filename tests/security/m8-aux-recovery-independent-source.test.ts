// @ts-nocheck -- real fiveClassRecoveryAcceptance; RAM-only dependency replies.
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
const native = vi.hoisted(() => ({ recycleAndRestore: vi.fn(), nativeRead: vi.fn(), sixCredentialProxyAcceptance: vi.fn() }));
vi.mock('./lib/m8-native-acceptance.mjs', () => native);
import { fiveClassRecoveryAcceptance } from './lib/m8-transfer-acceptance.mjs';

function fixture({ wrongTargetId = false, wrongCredentialParent = false } = {}) {
  const area = { cid: randomUUID(), wid: randomUUID() }, consumer = { id: randomUUID(), username: 'synthetic-consumer' };
  const credentials = Object.fromEntries(['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'].map(kind => [kind, { id: randomUUID(), consumer: { id: consumer.id } }]));
  const f = { area, consumer, credentials, service: { id: randomUUID() }, upstream: { id: randomUUID() }, certificate: { id: randomUUID() },
    sni: { id: randomUUID() }, target: { id: randomUUID(), target: 'synthetic-upstream:8081', weight: 100 }, plugins: { 'key-auth': { id: randomUUID() } } };
  native.recycleAndRestore.mockReset().mockImplementation(async (_h, _a, _area, _type, object) => ({ entry: { id: randomUUID() }, restored: { state: 'restored' }, current: { id: object.id } }));
  native.nativeRead.mockReset().mockResolvedValue({ id: f.sni.id, certificate: { id: f.certificate.id } });
  native.sixCredentialProxyAcceptance.mockReset().mockResolvedValue(undefined);
  const h = { state: { nativeFixture: f }, save: vi.fn(), data: value => value.payload.data, check: (condition, name) => { if (!condition) throw Error(name); },
    request: vi.fn(async (_actor, path) => {
      const kind = Object.keys(credentials).find(value => path.includes(`/credentials/${value}/`));
      if (kind) return { payload: { data: { entity: { ...credentials[kind], ...(wrongCredentialParent ? { consumer: { id: randomUUID() } } : {}) } } } };
      if (path.includes(`/upstreams/${f.upstream.id}/targets?`)) return { payload: { data: { items: [{ ...f.target, ...(wrongTargetId ? { id: randomUUID() } : {}) }] } } };
      throw Error('synthetic unexpected read');
    }) };
  return { h, f, actors: { admin: { user: { id: randomUUID() } } } };
}
describe('independent five-class recovery exact native graph contracts', () => {
  it('proves five exact root IDs, all six original credential parents and original target ID', async () => {
    const { h, f, actors } = fixture();
    const recovered = await fiveClassRecoveryAcceptance(h, actors);
    expect(recovered.map(value => value.type)).toEqual(['plugins', 'consumers', 'services', 'upstreams', 'certificates']);
    expect(recovered.map(value => value.id)).toEqual([f.plugins['key-auth'].id, f.consumer.id, f.service.id, f.upstream.id, f.certificate.id]);
    expect(h.request.mock.calls.filter(call => call[1].includes('/credentials/'))).toHaveLength(6);
    expect(native.sixCredentialProxyAcceptance).toHaveBeenCalledTimes(2);
    expect(h.state.fiveClassRecovery).toEqual(recovered);
  });
  it('rejects a replacement Target UUID even when restored target address and weight match', async () => {
    const { h, actors } = fixture({ wrongTargetId: true });
    await expect(fiveClassRecoveryAcceptance(h, actors)).rejects.toThrow();
    expect(h.state.fiveClassRecovery).toBeUndefined();
  });
  it('rejects a credential transplanted to a different Consumer before claiming real credential recovery', async () => {
    const { h, actors } = fixture({ wrongCredentialParent: true });
    await expect(fiveClassRecoveryAcceptance(h, actors)).rejects.toThrow('original credential parent and ID');
    expect(native.sixCredentialProxyAcceptance).not.toHaveBeenCalled();
    expect(h.state.fiveClassRecovery).toBeUndefined();
  });
});
