import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { portalTopologyChecks } from '../../deploy/scripts/portal-network-policy.mjs';

const requireApi = createRequire(new URL('../../apps/console-api/package.json', import.meta.url));
const { parse } = requireApi('yaml');
// Compose's sequence override tag affects volumes, not these network facts.
const parseCompose = (text: string) => parse(text, { customTags: [{ tag: '!override', collection: 'seq', resolve: (value: any) => value }] });
function allowedFacts(): any {
  return { portalNetworks: ['portal-edge', 'portal-entry'], apiNetworks: ['frontend', 'portal-edge', 'kong-admin', 'console-storage'],
    edge: { internal: true, driver: 'bridge', members: ['console-api', 'portal-web'] },
    entry: { internal: false, driver: 'bridge', members: ['portal-web'] },
    edgeAddress: '172.28.41.20', entryAddress: '172.28.42.20', networkMode: 'isolated_portal-entry', runtime: true,
    published: [{ hostIp: '127.0.0.1', hostPort: '8082', containerPort: 8080 }],
    effectivePublished: [{ hostIp: '127.0.0.1', hostPort: '8082', containerPort: 8080 }],
    protectedHosts: ['portal-web', '172.28.41.20', '172.28.42.20'] };
}
const allPassed = (facts: any) => portalTopologyChecks(facts).every((row: any) => row.passed === true);
const defaults = (text: string) => text.replace(/\$\{[A-Z0-9_]+:-([^}]*)\}/g, '$1');
const networkNames = (service: any) => Array.isArray(service.networks) ? service.networks : Object.keys(service.networks ?? {});

describe('M6 independent Portal two-network boundary', () => {
  it('accepts exactly a private two-member backend and a Portal-only entry, regardless of network/member order', () => {
    const facts = allowedFacts(); expect(allPassed(facts)).toBe(true);
    facts.portalNetworks.reverse(); facts.edge.members.reverse(); expect(allPassed(facts)).toBe(true);
    expect(facts.portalNetworks).toEqual(['portal-entry', 'portal-edge']);
  });
  it.each(['default', 'kong-admin', 'kong-storage', 'console-storage', 'telemetry', 'observability'])('rejects Portal joining additional %s', name => {
    const facts = allowedFacts(); facts.portalNetworks.push(name); expect(allPassed(facts)).toBe(false);
  });
  it.each(['console-api', 'kong', 'kong-db', 'console-db', 'redis', 'telemetry-collector', 'console-web'])('rejects %s as an entry network member', service => {
    const facts = allowedFacts(); facts.entry.members.push(service); expect(allPassed(facts)).toBe(false);
  });
  it.each(['kong', 'kong-db', 'console-db', 'redis', 'telemetry-collector'])('rejects %s as a private Portal backend member', service => {
    const facts = allowedFacts(); facts.edge.members.push(service); expect(allPassed(facts)).toBe(false);
  });
  it.each(['internal-entry', 'external-backend', 'host-entry', 'macvlan-entry', 'host-backend', 'api-entry', 'api-no-backend'])('rejects incorrect isolation %s', variant => {
    const facts = allowedFacts();
    if (variant === 'internal-entry') facts.entry.internal = true;
    if (variant === 'external-backend') facts.edge.internal = false;
    if (variant === 'host-entry') facts.entry.driver = 'host';
    if (variant === 'macvlan-entry') facts.entry.driver = 'macvlan';
    if (variant === 'host-backend') facts.edge.driver = 'host';
    if (variant === 'api-entry') facts.apiNetworks.push('portal-entry');
    if (variant === 'api-no-backend') facts.apiNetworks = ['frontend'];
    expect(allPassed(facts)).toBe(false);
  });
  it.each(['host', 'container:unrelated-management-container', 'none'])('rejects network_mode %s even when nominal attachment facts otherwise pass', mode => {
    const facts = allowedFacts(); facts.networkMode = mode; expect(allPassed(facts)).toBe(false);
  });
  it.each(['portal-web', '172.28.41.20', '172.28.42.20'])('requires ordinary destination protection for %s independently', destination => {
    const facts = allowedFacts(); facts.protectedHosts = facts.protectedHosts.filter((host: string) => host !== destination); expect(allPassed(facts)).toBe(false);
  });
  it.each(['duplicate-address', 'ipv6', 'malformed-address'])('rejects Portal interface identity %s', variant => {
    const facts = allowedFacts(); facts.entryAddress = variant === 'duplicate-address' ? facts.edgeAddress : variant === 'ipv6' ? '::1' : 'not-an-address';
    expect(allPassed(facts)).toBe(false);
  });
  it.each(['wildcard', 'ipv6-wildcard', 'admin-container-port', 'extra-admin-publication', 'wrong-host-port'])('rejects publication bypass %s', variant => {
    const facts = allowedFacts();
    if (variant === 'wildcard') facts.published[0].hostIp = '0.0.0.0';
    if (variant === 'ipv6-wildcard') facts.published[0].hostIp = '::';
    if (variant === 'admin-container-port') facts.published[0].containerPort = 8001;
    if (variant === 'extra-admin-publication') facts.published.push({ hostIp: '127.0.0.1', hostPort: '8001', containerPort: 8001 });
    if (variant === 'wrong-host-port') facts.published[0].hostPort = '8001';
    expect(allPassed(facts)).toBe(false);
  });
  it('does not mistake HostConfig declaration for effective Docker publication when Ports is empty', () => {
    const facts = allowedFacts(); facts.effectivePublished = []; expect(allPassed(facts)).toBe(false);
  });
  it('requires explicit effective runtime publication rather than falling back when Ports is missing', () => {
    const facts = allowedFacts(); delete facts.effectivePublished; expect(allPassed(facts)).toBe(false);
  });
  it('rejects an effective wildcard or extra mapping even though requested publication remains localhost-only', () => {
    const facts = allowedFacts(); facts.effectivePublished[0].hostIp = '0.0.0.0'; expect(allPassed(facts)).toBe(false);
    facts.effectivePublished = [...allowedFacts().effectivePublished, { hostIp: '127.0.0.1', hostPort: '8001', containerPort: 8001 }]; expect(allPassed(facts)).toBe(false);
  });
  it('checks actual base Compose network members and both protected IPs without resolving environment or calling Docker', () => {
    const config = parseCompose(readFileSync('docker-compose.yml', 'utf8')), portal = config.services['portal-web'], api = config.services['console-api'];
    const members = (name: string) => Object.entries(config.services).filter(([, service]) => networkNames(service).includes(name)).map(([name]) => name);
    const [hostIp, hostPort, containerPort] = defaults(portal.ports[0]).split(':');
    const facts = { ...allowedFacts(), runtime: false, networkMode: portal.network_mode ?? 'bridge', portalNetworks: networkNames(portal), apiNetworks: networkNames(api),
      edge: { internal: config.networks['portal-edge'].internal === true, driver: config.networks['portal-edge'].driver ?? 'bridge', members: members('portal-edge') },
      entry: { internal: config.networks['portal-entry'].internal === true, driver: config.networks['portal-entry'].driver ?? 'bridge', members: members('portal-entry') },
      edgeAddress: defaults(portal.networks['portal-edge'].ipv4_address), entryAddress: defaults(portal.networks['portal-entry'].ipv4_address),
      published: [{ hostIp, hostPort, containerPort: Number(containerPort) }], protectedHosts: defaults(api.environment.PROTECTED_DESTINATION_HOSTS).split(',') };
    expect(allPassed(facts)).toBe(true); expect(api.ports).toBeUndefined(); expect(portal.network_mode).toBeUndefined();
    expect(config.networks['portal-edge'].internal).toBe(true); expect(config.networks['portal-entry'].internal === true).toBe(false);
  });
  it.each(['deploy/compose/compose.multicluster-test.yml', 'deploy/compose/compose.metrics.yml'])('retains BOTH Portal literal IPs when %s overrides API protection', filename => {
    const config = parseCompose(readFileSync(filename, 'utf8')), hosts = defaults(config.services['console-api'].environment.PROTECTED_DESTINATION_HOSTS).split(',');
    expect(hosts.includes('portal-web')).toBe(true); expect(hosts.includes('172.28.41.20')).toBe(true); expect(hosts.includes('172.28.42.20')).toBe(true);
    for (const service of Object.values(config.services)) expect(networkNames(service).includes('portal-entry')).toBe(false);
  });
});
