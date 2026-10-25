import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { authHeaders, validateOutboundUrl } from '../../apps/console-api/src/infrastructure/kong/outbound';

describe('M0 outbound connection policy', () => {
  beforeEach(() => vi.stubEnv('OUTBOUND_ALLOWED_HOSTS', 'kong,prometheus,localhost:9090'));
  afterEach(() => vi.unstubAllEnvs());

  it('accepts an explicit Kong hostname and port', () => {
    expect(validateOutboundUrl('http://kong:8001').hostname).toBe('kong');
  });

  it.each([
    'http://169.254.169.254/latest/meta-data/',
    'http://kong.attacker.example:8001',
    'http://evil-kong:8001',
    'http://localhost:22',
  ])('denies destinations outside the exact host/port allowlist: %s', (url) => {
    expect(() => validateOutboundUrl(url)).toThrow(expect.objectContaining({ status: 403 }));
  });

  it.each([
    'file:///etc/passwd',
    'http://admin:password@kong:8001',
    'http://kong:8001/?target=http://evil.example',
    'http://kong:8001/#fragment',
    'http://kong:8001/path%2fservices',
    'http://kong:8001/path%5cservices',
    'http://kong:8001/path%00services',
    'http://kong.:8001',
  ])('rejects ambiguous or credential-bearing connection URL: %s', (url) => {
    expect(() => validateOutboundUrl(url)).toThrow(expect.objectContaining({ status: 400 }));
  });

  it('allows an explicit allowed localhost port only', () => {
    expect(validateOutboundUrl('http://localhost:9090').port).toBe('9090');
  });

  it('applies wildcard host policy on subdomain boundaries', () => {
    vi.stubEnv('OUTBOUND_ALLOWED_HOSTS', '*.internal.example');
    expect(validateOutboundUrl('https://kong.internal.example').hostname).toBe('kong.internal.example');
    expect(() => validateOutboundUrl('https://internal.example')).toThrow();
    expect(() => validateOutboundUrl('https://evilinternal.example')).toThrow();
  });

  it.each(['Host', 'connection', 'Cookie', 'Content-Length', 'Transfer-Encoding', 'bad\r\nname'])('denies control-header override: %s', (name) => {
    expect(() => authHeaders({ type: 'header', header_name: name, header_value: 'unsafe' })).toThrow(expect.objectContaining({ status: 400 }));
  });

  it('adds bearer credentials only in the request header', () => {
    expect(authHeaders({ type: 'bearer', token: 'opaque-secret' })).toEqual({ Authorization: 'Bearer opaque-secret' });
  });
});
