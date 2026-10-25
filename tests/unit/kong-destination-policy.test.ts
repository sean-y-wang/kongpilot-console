import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
const dns = vi.hoisted(() => ({ lookup: vi.fn(), resolve4: vi.fn(), resolve6: vi.fn() }));
vi.mock('node:dns/promises', () => ({ lookup: dns.lookup, Resolver: class { resolve4(host: string) { return dns.resolve4(host); } resolve6(host: string) { return dns.resolve6(host); } } }));
import { __setDestinationLookupForTests, assertPluginDestinations, assertProxyDestination, assertProxyUrl, assertTargetDestination } from '../../apps/console-api/src/infrastructure/kong/destination-policy';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';

describe('M4 protected management destinations and legitimate private upstreams', () => {
  let db: any;
  beforeEach(() => {
    __setDestinationLookupForTests();
    vi.stubEnv('DESTINATION_HOSTS_FILE', '/nonexistent-hosts');
    dns.resolve4.mockRejectedValue(Object.assign(new Error('nf'), { code: 'ENOTFOUND' }));
    dns.resolve6.mockRejectedValue(Object.assign(new Error('nf'), { code: 'ENOTFOUND' }));
    vi.stubEnv('DATABASE_URL', 'postgresql://user:hidden@console-db:5432/console');
    vi.stubEnv('REDIS_URL', 'redis://redis:6379');
    const addresses: Record<string, string> = { kong: '172.28.11.20', 'kong-secondary': '172.28.12.20', 'console-api': '172.28.11.10', 'console-db': '172.28.11.11', redis: '172.28.11.12', prometheus: '172.28.13.5', 'admin-alias.business': '172.28.11.20', 'db-alias.business': '172.28.11.11', 'metadata.business': '169.254.169.254', 'service.business': '10.80.1.30' };
    dns.lookup.mockImplementation(async (host: string) => { if (!addresses[host]) throw new Error('unresolved'); return [{ address: addresses[host], family: 4 }]; });
    db = { query: vi.fn().mockImplementation(async (sql: string) => sql.includes('clusters') ? [{ admin_url: 'http://kong:8001' }, { admin_url: 'http://kong-secondary:8001' }] : [{ base_url: 'http://prometheus:9090' }]) };
  });
  afterEach(() => vi.unstubAllEnvs());
  it.each(['localhost', '127.0.0.1', '127.1', '2130706433', '0x7f000001', '169.254.169.254', '::1', '0:0:0:0:0:0:0:1', '::ffff:a9fe:a9fe', '0:0:0:0:0:ffff:a9fe:a9fe', 'fe80::1', 'fe90::1', 'febf::1', 'ff02::1', '0.0.0.0', '0.1.2.3', '255.255.255.255', '224.0.0.1'])('rejects reserved address %s before registry access', async host => {
    await expect(assertProxyDestination(db, { host, port: 8080 })).rejects.toMatchObject({ status: 403, response: { code: 'PROTECTED_PROXY_DESTINATION' } });
    expect(db.query).not.toHaveBeenCalled();
  });
  it.each([{ host: 'kong', port: 8001 }, { host: 'kong-secondary', port: 8001 }, { host: '172.28.11.20', port: 8001 }, { host: 'admin-alias.business', port: 8001 }, { host: 'console-api', port: 9999 }, { host: 'console-web', port: 80 }, { host: 'kong-secondary-db', port: 5432 }, { host: 'db-alias.business', port: 8080 }, { host: 'prometheus', port: 8000 }, { host: 'metadata.business', port: 80 }])('rejects configured management host/address and DNS aliases %j', async candidate => {
    await expect(assertProxyDestination(db, candidate)).rejects.toMatchObject({ status: 403 });
  });
  it('allows ordinary private business destinations and Kong proxy ports', async () => {
    for (const candidate of [{ host: '10.80.1.30', port: 8001 }, { host: 'service.business', port: 8080 }, { host: 'unresolved.business', port: 443 }, { host: 'ffbusiness.example', port: 80 }, { host: 'kong', port: 8000 }, { host: 'kong-secondary', port: 9000 }]) await expect(assertProxyDestination(db, candidate)).resolves.toBeUndefined();
  });
  it('rejects URL credentials, unsupported schemes and invalid target authority', async () => {
    await expect(assertProxyUrl(db, 'http://user:password@service.business:8080')).rejects.toMatchObject({ status: 403 });
    await expect(assertProxyUrl(db, 'file:///etc/passwd')).rejects.toMatchObject({ status: 403 });
    await expect(assertTargetDestination(db, 'service.business:8080/path')).rejects.toMatchObject({ status: 403 });
    await expect(assertTargetDestination(db, 'kong:8001')).rejects.toMatchObject({ status: 403 });
    await expect(assertTargetDestination(db, 'service.business:8080')).resolves.toBeUndefined();
  });
  it('uses verified platform privilege for Lua/custom plugins while still protecting their explicit network sinks', async () => {
    for (const name of ['pre-function', 'post-function', 'custom-executable']) await expect(assertPluginDestinations(db, name, { functions: ['return'] }, false)).rejects.toMatchObject({ status: 403, response: { code: 'PLUGIN_PLATFORM_EXECUTION_REQUIRED' } });
    await expect(assertPluginDestinations(db, 'pre-function', { functions: ['return'] }, true)).resolves.toBeUndefined();
    await expect(assertPluginDestinations(db, 'http-log', { http_endpoint: 'http://admin-alias.business:8001/services' }, true)).rejects.toMatchObject({ status: 403 });
    await expect(assertPluginDestinations(db, 'rate-limiting', { redis_host: 'redis', redis_port: 6379 }, true)).rejects.toMatchObject({ status: 403 });
    await expect(assertPluginDestinations(db, 'ldap-auth', { ldap_host: 'service.business', ldap_port: 389 }, false)).resolves.toBeUndefined();
  });
  it.each(['unix:/var/run/console.sock', 'unix:/var/run/console.sock.', '/var/run/socket', 'kong:8001', 'user@kong', 'kong/path', 'kong\\path', 'bad host', 'kong\u0000'])('rejects non-DNS connect syntax %s before registry access', async host => {
    await expect(assertProxyDestination(db, { host, port: 80 })).rejects.toMatchObject({ status: 403 });
    expect(db.query).not.toHaveBeenCalled();
  });
  it('guards Loggly explicit destinations and Azure source-derived host composition', async () => {
    await expect(assertPluginDestinations(db, 'loggly', { host: 'console-api', port: 3000 }, true)).rejects.toMatchObject({ status: 403 });
    await expect(assertPluginDestinations(db, 'loggly', { host: 'service.business', port: 514 }, false)).resolves.toBeUndefined();
    await expect(assertPluginDestinations(db, 'azure-functions', { appname: 'db-alias', hostdomain: 'business', https: false }, true)).rejects.toMatchObject({ status: 403 });
    await expect(assertPluginDestinations(db, 'azure-functions', { appname: 'service', hostdomain: 'business', https: true }, false)).resolves.toBeUndefined();
    await expect(assertPluginDestinations(db, 'azure-functions', { appname: 'unix:/var/run/socket', hostdomain: 'example' }, true)).rejects.toMatchObject({ status: 403 });
  });
  it('requires current platform privilege for local file append even on a disabled plugin configuration', async () => {
    await expect(assertPluginDestinations(db, 'file-log', { path: '/tmp/console-fixture.log' }, false)).rejects.toMatchObject({ status: 403, response: { code: 'PLUGIN_LOCAL_FILE_PERMISSION_REQUIRED' } });
    await expect(assertPluginDestinations(db, 'file-log', { path: '/tmp/console-fixture.log' }, true)).resolves.toBeUndefined();
  });
  it('fails closed if configured protected endpoint metadata is corrupt', async () => {
    db.query.mockResolvedValue([{ admin_url: 'invalid url' }]);
    await expect(assertProxyDestination(db, { host: 'service.business', port: 8080 })).rejects.toMatchObject({ status: 502, response: { code: 'DESTINATION_POLICY_UNAVAILABLE' } });
  });
});

describe('M4 stable physical transport identity', () => {
  it('normalizes authority, default ports and trailing path slashes', () => {
    expect(transportScopeFor('HTTP://KONG:80/')).toBe(transportScopeFor('http://kong'));
    expect(transportScopeFor('https://KONG:443/admin///')).toBe(transportScopeFor('https://kong/admin'));
    expect(transportScopeFor('http://kong:8001')).not.toBe(transportScopeFor('http://kong:8000'));
  });
  it('shares explicitly registered physical identity for distinct DNS aliases without inferring unstable DNS identity', () => {
    const scope = transportScopeFor('http://kong:8001');
    expect(transportScopeFor('http://other-alias:8001', scope)).toBe(scope);
    expect(transportScopeFor('http://other-alias:8001')).not.toBe(scope);
    expect(() => transportScopeFor('http://kong:8001', 'actor-controlled')).toThrow();
  });
  it.each(['http://user:password@kong:8001', 'file:///etc/passwd', 'http://kong:8001/?key=value', 'http://kong:8001/#fragment'])('rejects ambiguous Admin identity %s', url => expect(() => transportScopeFor(url)).toThrow());
});

describe('M11 destination lookups do not starve the libuv threadpool without upstream DNS', () => {
  const db = { query: vi.fn(async (sql: string) => sql.includes('clusters') ? [{ admin_url: 'http://kong:8001' }] : []) };
  afterEach(() => { __setDestinationLookupForTests(); vi.useRealTimers(); });

  it('caps concurrent system lookups, single-flights per host and negatively caches hung names', async () => {
    let started = 0, peak = 0, active = 0;
    const calls: string[] = [];
    __setDestinationLookupForTests(host => {
      calls.push(host); started++; active++; peak = Math.max(peak, active);
      // Absent hostnames hang far beyond the budget (as getaddrinfo does offline).
      return new Promise((_resolve, reject) => setTimeout(() => { active--; reject(new Error('EAI_AGAIN')); }, 3000));
    });
    const begin = Date.now();
    await Promise.all(Array.from({ length: 10 }, () => assertProxyDestination(db, { host: '203.0.113.10', port: 80 })));
    expect(Date.now() - begin).toBeLessThan(2500);
    expect(peak).toBeLessThanOrEqual(2);
    expect(new Set(calls).size).toBe(calls.length); // no duplicate in-flight lookup per host
    await new Promise(resolve => setTimeout(resolve, 3200));
    const before = started;
    // Still bounded after the hung lookups settle.
    await assertProxyDestination(db, { host: '203.0.113.10', port: 80 });
    expect(started - before).toBeLessThanOrEqual(2);
  }, 15000);

  it('still rejects a hostname that resolves to a protected address once DNS answers', async () => {
    __setDestinationLookupForTests(async host => host === 'alias.example' || host === 'kong' ? ['172.28.11.20'] : []);
    await expect(assertProxyDestination(db, { host: 'alias.example', port: 8001 })).rejects.toMatchObject({ response: { code: 'PROTECTED_PROXY_DESTINATION' } });
  });
});

describe('M11 default resolver path is threadpool-free when DNS is unreachable', () => {
  const db = { query: vi.fn(async (sql: string) => sql.includes('clusters') ? [{ admin_url: 'http://kong:8001' }] : []) };
  afterEach(() => { __setDestinationLookupForTests(); vi.unstubAllEnvs(); });
  it('never falls back to getaddrinfo on resolver timeout, but does on a definitive NXDOMAIN', async () => {
    __setDestinationLookupForTests();
    vi.stubEnv('DESTINATION_HOSTS_FILE', '/nonexistent-hosts');
    dns.lookup.mockReset();
    dns.lookup.mockResolvedValue([{ address: '198.51.100.7', family: 4 }]);
    dns.resolve4.mockReset(); dns.resolve6.mockReset();
    dns.resolve4.mockImplementation(async (host: string) => { if (host === 'kong') return ['172.28.11.20']; throw Object.assign(new Error('t'), { code: host === 'nx.example' ? 'ENOTFOUND' : 'ETIMEOUT' }); });
    dns.resolve6.mockImplementation(async (host: string) => { throw Object.assign(new Error('t'), { code: host === 'nx.example' ? 'ENOTFOUND' : 'ETIMEOUT' }); });
    await assertProxyDestination(db, { host: '203.0.113.10', port: 80 });
    expect(dns.lookup).not.toHaveBeenCalled();
    await assertProxyDestination(db, { host: 'nx.example', port: 80 });
    expect(dns.lookup).toHaveBeenCalledWith('nx.example', { all: true });
  });
});
