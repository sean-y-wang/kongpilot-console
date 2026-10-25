import 'reflect-metadata';
import { createHmac } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { immutableJson, isFactoryImmutableJson } from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import { canonicalJson, SecretService } from '../../apps/console-api/src/infrastructure/secret.service';

// The wrapper counts real cryptographic operations; successful digests always
// come from Node's actual crypto implementation, never a synthetic hash.
vi.mock('node:crypto', async importOriginal => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return { ...actual, createHmac: vi.fn(actual.createHmac) };
});

const keyHex = 'ab'.repeat(32), secondKeyHex = 'cd'.repeat(32);
let realCrypto: typeof import('node:crypto');
beforeEach(async () => {
  realCrypto = await vi.importActual<typeof import('node:crypto')>('node:crypto');
  vi.mocked(createHmac).mockReset().mockImplementation(realCrypto.createHmac);
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY', keyHex);
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
const expected = (value: unknown, key = keyHex) => realCrypto.createHmac('sha256', Buffer.from(key, 'hex'))
  .update('kongos-fingerprint:v1:').update(canonicalJson(value)).digest('hex');

describe('Factory immutable JSON root provenance is data-only and unforgeable by shape', () => {
  it('marks only the actual fully cloned/frozen root and isolates it from later source changes', () => {
    const source = { name: 'original', nested: { enabled: true }, array: [{ count: 1 }] }, copy = immutableJson(source);
    expect(copy).not.toBe(source); expect(isFactoryImmutableJson(copy)).toBe(true);
    expect(isFactoryImmutableJson(copy.nested)).toBe(false); expect(isFactoryImmutableJson(copy.array)).toBe(false);
    expect(isFactoryImmutableJson(copy.array[0])).toBe(false); expect(isFactoryImmutableJson(source)).toBe(false);
    for (const item of [copy, copy.nested, copy.array, copy.array[0]]) expect(Object.isFrozen(item)).toBe(true);
    expect(Object.getOwnPropertyNames(copy)).toEqual(['name', 'nested', 'array']); expect(Object.getOwnPropertySymbols(copy)).toEqual([]);
    source.name = 'changed'; source.nested.enabled = false; source.array[0].count = 2; source.array.push({ count: 3 });
    expect(copy).toEqual({ name: 'original', nested: { enabled: true }, array: [{ count: 1 }] });
    expect(() => Reflect.set(copy.nested, 'enabled', false)).not.toThrow(); expect(copy.nested.enabled).toBe(true);
  });

  it.each([undefined, null, false, true, 0, -0, 1, '', 'source-only'])('never registers primitive factory output %j', input => {
    expect(isFactoryImmutableJson(immutableJson(input))).toBe(false);
  });

  it('does not recognize ordinary deep freeze, equal JSON clones, spreads, prototype descendants or Proxies', () => {
    const root = immutableJson({ nested: { enabled: true } });
    const ordinary = Object.freeze({ nested: Object.freeze({ enabled: true }) });
    const proxy = new Proxy(root, { get() { throw Error('PROVENANCE_MUST_NOT_INSPECT_PROXY'); } });
    const revoked = Proxy.revocable(root, {}); revoked.revoke();
    for (const value of [ordinary, { ...root }, structuredClone(root), JSON.parse(JSON.stringify(root)), Object.create(root), proxy, revoked.proxy])
      expect(isFactoryImmutableJson(value)).toBe(false);
    expect(isFactoryImmutableJson(Object.freeze(root))).toBe(true);
  });

  it('normalizes input getters and toJSON once, keeping no hooks or source prototypes in the registered copy', () => {
    let current = 'original'; const getter = vi.fn(() => current), toJSON = vi.fn(() => ({ value: current }));
    const source = Object.defineProperty({ nested: { toJSON } }, 'fromGetter', { enumerable: true, get: getter });
    const root: any = immutableJson(source); current = 'later';
    expect(getter).toHaveBeenCalledOnce(); expect(toJSON).toHaveBeenCalledOnce();
    expect(root).toEqual({ nested: { value: 'original' }, fromGetter: 'original' });
    expect(Object.getOwnPropertyDescriptor(root, 'fromGetter')?.get).toBeUndefined();
    expect(Object.getPrototypeOf(root)).toBe(Object.prototype); expect(Object.getPrototypeOf(root.nested)).toBe(Object.prototype);
    expect(isFactoryImmutableJson(root)).toBe(true); expect(isFactoryImmutableJson(root.nested)).toBe(false);
  });

  it('treats parsed __proto__ as immutable own JSON data without prototype injection', () => {
    const root = immutableJson(JSON.parse('{"__proto__":{"name":"own-data"},"constructor":{"safe":true}}'));
    expect(Object.hasOwn(root, '__proto__')).toBe(true); expect(Object.getPrototypeOf(root)).toBe(Object.prototype);
    expect(Object.isFrozen(root.__proto__)).toBe(true); expect(({} as any).name).toBeUndefined();
    expect(new SecretService().fingerprint(root)).toBe(expected(root)); expect(isFactoryImmutableJson(root)).toBe(true);
  });

  it('does not register raw Date or Buffer, while their JSON-normalized copies retain existing semantics', () => {
    const date = new Date('2026-10-15T00:00:00Z'), buffer = Buffer.from([1, 2, 3]);
    expect(isFactoryImmutableJson(date)).toBe(false); expect(isFactoryImmutableJson(buffer)).toBe(false);
    expect(immutableJson(date)).toBe(date.toISOString());
    const normalized = immutableJson(buffer);
    expect(normalized).toEqual({ type: 'Buffer', data: [1, 2, 3] }); expect(Buffer.isBuffer(normalized)).toBe(false);
    expect(isFactoryImmutableJson(normalized)).toBe(true); expect(isFactoryImmutableJson((normalized as any).data)).toBe(false);
  });

  it('preserves invalid JSON errors without registering the original cyclic or bigint input', () => {
    const cycle: any = {}; cycle.self = cycle;
    for (const value of [cycle, { big: 1n }]) {
      expect(() => immutableJson(value)).toThrow(); expect(isFactoryImmutableJson(value)).toBe(false);
    }
  });
});

describe('Per-instance bounded memo preserves the exact real canonical HMAC', () => {
  it.each([
    { b: 2, a: [true, null, '中文'] },
    { unicode: 'é😀\u2028\u2029', escaped: '\\"\r\n', number: 1e30 },
    { omit: undefined, array: [undefined, NaN, Infinity, -0] },
    [], [1, false, { z: 'tail', a: 0 }],
    JSON.parse('{"__proto__":{"safe":true},"10":"numeric-key","2":"two"}'),
  ].map(source => [source]))('preserves cold/warm bytes for normalized vector %j', source => {
    const root = immutableJson(source), secrets = new SecretService(), independent = expected(root);
    expect(secrets.fingerprint(root)).toBe(independent); expect(secrets.fingerprint(root)).toBe(independent);
    expect(createHmac).toHaveBeenCalledOnce();
  });

  it('retains exact canonical order and prefix using an independently written byte vector', () => {
    const root = immutableJson({ b: 2, a: [true, null, '中文'] }), secrets = new SecretService();
    expect(canonicalJson(root)).toBe('{"a":[true,null,"中文"],"b":2}');
    const bytes = realCrypto.createHmac('sha256', Buffer.from(keyHex, 'hex')).update('kongos-fingerprint:v1:')
      .update('{"a":[true,null,"中文"],"b":2}').digest('hex');
    expect(secrets.fingerprint(root)).toBe(bytes); expect(secrets.fingerprint(root)).toBe(bytes);
    expect(createHmac).toHaveBeenCalledOnce();
  });

  it('keeps fingerprint entry calls observable while computing once for the same original root across an await', async () => {
    const secrets = new SecretService(), entry = vi.spyOn(secrets, 'fingerprint'), root = immutableJson({ name: 'fixed' });
    const first = secrets.fingerprint(root); await Promise.resolve();
    expect(secrets.fingerprint(root)).toBe(first); expect(entry).toHaveBeenCalledTimes(2); expect(createHmac).toHaveBeenCalledOnce();
    expect(first).toBe(expected(root));
  });

  it('rehashes equal newly normalized references and never memoizes unregistered child objects', () => {
    const secrets = new SecretService(), a = immutableJson({ nested: { n: 1 } }), b = immutableJson({ nested: { n: 1 } });
    expect(a).not.toBe(b); expect(secrets.fingerprint(a)).toBe(secrets.fingerprint(b)); expect(createHmac).toHaveBeenCalledTimes(2);
    expect(secrets.fingerprint(a.nested)).toBe(expected(a.nested)); expect(secrets.fingerprint(a.nested)).toBe(expected(a.nested));
    expect(createHmac).toHaveBeenCalledTimes(4);
  });

  it('does not memoize raw mutable, ordinary frozen, Proxy or cloned lookalikes', () => {
    const secrets = new SecretService(), root = immutableJson({ name: 'safe' });
    const lookalikes = [{ name: 'safe' }, Object.freeze({ name: 'safe' }), new Proxy(root, {}), structuredClone(root)];
    for (const value of lookalikes) {
      const before = vi.mocked(createHmac).mock.calls.length;
      expect(secrets.fingerprint(value)).toBe(expected(value)); expect(secrets.fingerprint(value)).toBe(expected(value));
      expect(vi.mocked(createHmac).mock.calls.length).toBe(before + 2);
    }
  });

  it('keeps fresh mutable data and mutable internals of frozen Date/getter objects observable', () => {
    const secrets = new SecretService(), value = { grant: 'read' }, first = secrets.fingerprint(value);
    value.grant = 'write'; expect(secrets.fingerprint(value)).not.toBe(first);
    const date = Object.freeze(new Date('2026-10-15T00:00:00Z')), beforeDate = secrets.fingerprint(date);
    date.setTime(date.getTime() + 1000); expect(secrets.fingerprint(date)).not.toBe(beforeDate);
    const buffer = Buffer.from([1, 2]), beforeBuffer = secrets.fingerprint(buffer); buffer[0] = 3;
    expect(secrets.fingerprint(buffer)).not.toBe(beforeBuffer);
    let data = 'read'; const getter = vi.fn(() => data), frozen = Object.freeze(Object.defineProperty({}, 'grant', { enumerable: true, get: getter }));
    const beforeGetter = secrets.fingerprint(frozen); data = 'write'; expect(secrets.fingerprint(frozen)).not.toBe(beforeGetter);
    expect(getter).toHaveBeenCalledTimes(2); expect(createHmac).toHaveBeenCalledTimes(8);
  });

  it('never shares memo values across instances, including equal keys', () => {
    const root = immutableJson({ value: 'same' }), first = new SecretService(), second = new SecretService();
    expect(first.fingerprint(root)).toBe(second.fingerprint(root)); expect(createHmac).toHaveBeenCalledTimes(2);
    first.fingerprint(root); second.fingerprint(root); expect(createHmac).toHaveBeenCalledTimes(2);
  });

  it('uses the constructor key after environment changes and recomputes with a genuinely new instance key', () => {
    const root = immutableJson({ value: 'same' }), original = new SecretService(), first = original.fingerprint(root);
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', secondKeyHex);
    const later = new SecretService(), newDigest = later.fingerprint(root), freshRoot = immutableJson({ value: 'same' });
    expect(newDigest).toBe(expected(root, secondKeyHex)); expect(newDigest).not.toBe(first);
    expect(original.fingerprint(root)).toBe(first); expect(original.fingerprint(freshRoot)).toBe(expected(freshRoot, keyHex));
    expect(first).toBe(expected(root, keyHex)); expect(createHmac).toHaveBeenCalledTimes(3);
  });

  it('isolates equal constructor keys decoded from hex and base64 without changing output', () => {
    const root = immutableJson({ same: true }), first = new SecretService();
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', Buffer.from(keyHex, 'hex').toString('base64')); const second = new SecretService();
    expect(first.fingerprint(root)).toBe(second.fingerprint(root)); expect(createHmac).toHaveBeenCalledTimes(2);
  });

  it('retains encryption/AAD round trips and recomputes for decrypted data until explicitly normalized again', () => {
    const root = immutableJson({ password: 'SyntheticOnlySecret!Memo', nested: ['中文', true] }), secrets = new SecretService();
    const digest = secrets.fingerprint(root), ciphertext = secrets.encrypt(root, 'memo-source-only');
    expect(secrets.encrypt(root, 'memo-source-only')).not.toBe(ciphertext);
    expect(() => secrets.decrypt(ciphertext, 'wrong-aad')).toThrow();
    const decrypted = secrets.decrypt(ciphertext, 'memo-source-only'); expect(decrypted).toEqual(root); expect(isFactoryImmutableJson(decrypted)).toBe(false);
    expect(secrets.fingerprint(decrypted)).toBe(digest); expect(secrets.fingerprint(decrypted)).toBe(digest);
    const normalized = immutableJson(decrypted); expect(secrets.fingerprint(normalized)).toBe(digest); expect(secrets.fingerprint(normalized)).toBe(digest);
    expect(createHmac).toHaveBeenCalledTimes(4);
  });

  it('keeps redaction markers and error masking equal without exposing cached secret objects', () => {
    const root = immutableJson({ private: { value: 'SyntheticSecretObject!Memo' } }), secrets = new SecretService();
    const digest = secrets.fingerprint(root), safe = secrets.redact({ credentials: root });
    expect(safe).toEqual({ credentials: `[REDACTED:${digest.slice(0, 16)}]` }); expect(createHmac).toHaveBeenCalledOnce();
    expect(JSON.stringify(safe)).not.toContain('SyntheticSecretObject!Memo');
    expect(secrets.redactError({ message: 'SyntheticSecretObject!Memo was rejected' }, { credentials: root }).message).not.toContain('SyntheticSecretObject!Memo');
  });

  it('bounds cache entries at 4096, counts no hits or uncached objects, and recomputes after reset', () => {
    const secrets = new SecretService(), roots = Array.from({ length: 4097 }, (_, id) => immutableJson({ id }));
    const original = secrets.fingerprint(roots[0]);
    for (let i = 0; i < 16; i++) expect(secrets.fingerprint(roots[0])).toBe(original);
    for (let i = 0; i < 8; i++) secrets.fingerprint({ ordinary: i });
    for (let i = 1; i < 4096; i++) secrets.fingerprint(roots[i]);
    expect(createHmac).toHaveBeenCalledTimes(4096 + 8);
    expect(secrets.fingerprint(roots[0])).toBe(original); expect(createHmac).toHaveBeenCalledTimes(4096 + 8);
    secrets.fingerprint(roots[4096]); expect(createHmac).toHaveBeenCalledTimes(4097 + 8);
    secrets.fingerprint(roots[4096]); expect(createHmac).toHaveBeenCalledTimes(4097 + 8);
    expect(secrets.fingerprint(roots[0])).toBe(original); expect(createHmac).toHaveBeenCalledTimes(4098 + 8);
  });

  it('never caches crypto failure or unsupported-value errors', () => {
    const secrets = new SecretService(), root = immutableJson({ value: 'fixed' }), failure = Error('SYNTHETIC_CRYPTO_FAILURE');
    vi.mocked(createHmac).mockImplementationOnce(() => { throw failure; });
    expect(() => secrets.fingerprint(root)).toThrow(failure);
    expect(secrets.fingerprint(root)).toBe(expected(root)); expect(secrets.fingerprint(root)).toBe(expected(root));
    expect(createHmac).toHaveBeenCalledTimes(2);
    for (let n = 0; n < 2; n++) expect(() => secrets.fingerprint({ bigint: 1n })).toThrow();
    expect(createHmac).toHaveBeenCalledTimes(4);
  });
});
