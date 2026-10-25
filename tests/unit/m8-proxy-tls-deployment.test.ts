import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {parse} from 'yaml';

const base=parse(readFileSync('docker-compose.yml','utf8'));
const tls=parse(readFileSync('deploy/compose.proxy-tls-test.yml','utf8'));
const exactTestEntry=(input:any)=>JSON.stringify(input)===JSON.stringify({services:{kong:{ports:['127.0.0.1:8443:8443']}}});

describe('M8 genuine Kong1.5 proxy TLS source boundary',()=>{
 it('adds a genuine ssl listener while retaining the existing HTTP listener',()=>{
  expect(base.services.kong.image).toBe('kong:1.5.1');
  expect(base.services.kong.environment.KONG_PROXY_LISTEN).toBe('0.0.0.0:8000, 0.0.0.0:8443 ssl');
  expect(base.services.kong.environment.KONG_TRUSTED_IPS).toBeUndefined();
  expect(base.services.kong.environment.KONG_REAL_IP_HEADER).toBeUndefined();
 });
 it('does not publish TLS or Admin in the production base',()=>{
  expect(base.services.kong.ports).toEqual(['127.0.0.1:${KONG_PROXY_PORT:-8000}:8000']);
  expect(base.services.kong.networks['kong-admin'].ipv4_address).toBe('${KONG_ADMIN_IP:-172.28.11.20}');
  expect(base.services.kong.environment.KONGOS_BFF_ADMIN_IP).toBe('${CONSOLE_KONG_ADMIN_IP:-172.28.11.10}');
 });
 it('limits the test overlay to the one localhost TLS entry with no config/secret/network changes',()=>{
  expect(exactTestEntry(tls)).toBe(true);
  expect(exactTestEntry({services:{kong:{ports:['0.0.0.0:8443:8443']}}})).toBe(false);
  expect(exactTestEntry({services:{kong:{ports:['127.0.0.1:8001:8001']}}})).toBe(false);
  expect(exactTestEntry({services:{kong:{ports:['127.0.0.1:8443:8443'],network_mode:'host'}}})).toBe(false);
  expect(exactTestEntry({services:{kong:{ports:['127.0.0.1:8443:8443'],environment:{KONG_TRUSTED_IPS:'0.0.0.0/0'}}}})).toBe(false);
 });
 it('retains real secondary/Portal acceptance nodes and exact native Admin ACL implementation',()=>{
  const secondary=parse(readFileSync('deploy/compose.multicluster-test.yml','utf8'));
  const portal=parse(readFileSync('deploy/compose.portal-acceptance.yml','utf8'));
  expect(secondary.services['kong-secondary'].environment.KONG_PROXY_LISTEN).toBe('0.0.0.0:8000');
  expect(portal.services['kong-portal'].environment.KONG_PROXY_LISTEN).toBe('0.0.0.0:8000');
  const start=readFileSync('deploy/scripts/kong-secure-start.sh','utf8');
  expect(start).toContain("printf 'allow %s;\\ndeny all;\\n'");
  expect(start).toContain("export KONG_ADMIN_ERROR_LOG='/dev/null'");
  expect(start).toContain("export KONG_PROXY_ERROR_LOG='/dev/null'");
 });
});
