import { describe, expect, it, vi } from 'vitest';
import { EntityService, referenceLabel } from '../../apps/console-api/src/modules/entities/entities.service';

// Synthetic self-signed test certificate (no private key is used or stored).
const CERT = `-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUIPZxH8mIjQdgFbO4cqKsvRsURnQwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQYXBpLmV4YW1wbGUudGVzdDAeFw0yNjEwMjYwNzQ0NTha
Fw0yNzEwMjYwNzQ0NThaMBsxGTAXBgNVBAMMEGFwaS5leGFtcGxlLnRlc3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpTFz0S6EvUDT6nUPaKgoeXpBN
7VMGr2iEBVAU+dsLrG+pDrH9e4EQ1E6A/1+8vqx+JIIqWff8d7FzKAJSZpHr7WZf
sD8HMjYcL+s0vrqDZwiNb5IDMZgGN7JS3jT9PTqm+bCgStuxDna0rNgurS40hITO
h7MtljnJRjA62o4ffhp8O+ZoMyPamDlJ/ipjm6SrJdlh+cp1oyHblNrvV71q9mU/
votnK5WgHcJQxd6nSOYUYsjeENbWw4vyIZgY07dpYfUdfDY5M4Y2QCFObkkonwoj
wIBKAomDEe7HAL16P2Dpz2vmIXkP+aJH6WT4IwfppRk50ctFLmEZsMLZoeOdAgMB
AAGjYTBfMB0GA1UdDgQWBBTY5TOqM9xLLOMfvxvllJZATxQlkDAPBgNVHRMBAf8E
BTADAQH/MC0GA1UdEQQmMCSCEGFwaS5leGFtcGxlLnRlc3SCEHd3dy5leGFtcGxl
LnRlc3QwDQYJKoZIhvcNAQELBQADggEBAHicC81LvLQeYGnNfCpNJpz/QbePpmIn
FAvZX4XUwdyHkWbStWP0GkY5pHZnfok14+6Oy8h80oVClFUmCieZJ0kFxKsjRC7H
xIVuAvrLOKZZMeTIkrpzh19VfjCL8vyw+Kns/Hr89U6pGdy3c3MaAIUmGk3xADOo
mGAToJ9aZ6CS77y3Ghh4J5v6kLVEcGePp6kvZkHiNfd+CsOmW4rR7lILioCAuEsV
vR2ByAzNko417YF13Vy3BTX9CRQ0GBAlbknExTUdOydHwQVWDoywKzhi5aKUrdjc
EnoO7JhAvrO6TKzuJAgoFkqEmzrbRoqCdSX+ro7lPWMNBWRHJoB2g2g=
-----END CERTIFICATE-----`;

describe('entity reference labels', () => {
  it('labels certificates by CN with SAN and expiry, never returning PEM', () => {
    const out = referenceLabel('certificates', { id: 'c1', cert: CERT, key: 'secret' });
    expect(out.label).toBe('api.example.test');
    expect(out.detail).toBe('SAN: api.example.test, www.example.test');
    expect(out.expired).toBe(false);
    expect(JSON.stringify(out)).not.toMatch(/BEGIN|secret/);
  });
  it('falls back to readable fields then ID', () => {
    expect(referenceLabel('consumers', { id: 'u', username: 'alice', custom_id: 'A1' })).toMatchObject({ label: 'alice', detail: 'custom_id: A1' });
    expect(referenceLabel('consumers', { id: 'u' }).label).toBe('u');
    expect(referenceLabel('services', { id: 's', host: 'up.internal', protocol: 'http', port: 80 })).toMatchObject({ label: 'up.internal', detail: 'http://up.internal:80' });
    expect(referenceLabel('routes', { id: 'r', paths: ['/a'] }).label).toBe('/a');
    expect(referenceLabel('routes', { id: 'r' }).label).toBe('r');
    expect(referenceLabel('certificates', { id: 'c', cert: 'garbage' }).label).toBe('c');
  });
});

describe('EntityService.resolveReferences', () => {
  const fake = (readable: Set<string>, scopedDenied: Set<string> = new Set()) => ({
    scoped: vi.fn(async (_c: string, a: any, _w: any, type: string) => { if (scopedDenied.has(type)) throw new Error('forbidden'); return a; }),
    raw: vi.fn(async (_c: string, type: string, id: string) => { if (!readable.has(`${type}:${id}`)) throw new Error('forbidden'); return { id, name: `n-${id}` }; }),
  });
  const run = (self: any, refs: unknown) => (EntityService.prototype as any).resolveReferences.call(self, 'cid', { refs }, {}, { user: {} });
  it('dedupes references into one read each and hides unreadable ones', async () => {
    const self = fake(new Set(['services:a']));
    const { items } = await run(self, [{ type: 'services', id: 'a' }, { type: 'services', id: 'a' }, { type: 'services', id: 'b' }]);
    expect(self.raw).toHaveBeenCalledTimes(2);
    expect(items.find((i: any) => i.id === 'a')).toMatchObject({ visible: true, label: 'n-a' });
    expect(items.find((i: any) => i.id === 'b')).toEqual({ type: 'services', id: 'b', visible: false });
  });
  it('returns ID-only for types the actor cannot read at all', async () => {
    const self = fake(new Set(['consumers:x']), new Set(['consumers']));
    const { items } = await run(self, [{ type: 'consumers', id: 'x' }]);
    expect(self.raw).not.toHaveBeenCalled();
    expect(items).toEqual([{ type: 'consumers', id: 'x', visible: false }]);
  });
  it('rejects oversized or malformed batches', async () => {
    await expect(run(fake(new Set()), Array.from({ length: 101 }, (_, i) => ({ type: 'services', id: String(i) })))).rejects.toMatchObject({ response: { code: 'ENTITY_REFERENCES_INVALID' } });
    await expect(run(fake(new Set()), [{ type: 'targets', id: 'a' }])).rejects.toMatchObject({ response: { code: 'ENTITY_REFERENCES_INVALID' } });
    await expect(run(fake(new Set()), [{ type: 'services', id: '../x' }])).rejects.toMatchObject({ response: { code: 'ENTITY_REFERENCES_INVALID' } });
  });
});
