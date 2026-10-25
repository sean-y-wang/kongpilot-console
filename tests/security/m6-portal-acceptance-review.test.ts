import { afterEach, describe, expect, it } from 'vitest';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { portalAcceptanceChecks } from '../../deploy/scripts/portal-acceptance-policy.mjs';
import { generatePortalAcceptanceEnvironment } from '../../deploy/scripts/portal-acceptance-environment.mjs';

function composeFacts() {
  const api = { image: 'unchanged-api', command: ['node', 'dist/main.js'], environment: { APP_SECRET: 'synthetic-existing-app-key', PORTAL_SECRET: 'synthetic-existing-portal-key', OUTBOUND_ALLOWED_HOSTS: 'kong,prometheus,loki,kong-secondary', PROTECTED_DESTINATION_HOSTS: 'kong-db,172.28.21.20,portal-web,172.28.41.20,172.28.42.20' }, networks: { frontend: {}, 'kong-admin': { ipv4_address: '172.28.11.10' }, telemetry: { ipv4_address: '172.28.31.10' } }, volumes: [{ source: 'existing-metrics-material', target: '/run/metrics', read_only: true }] };
  const base: any = { services: { 'console-api': api, kong: { image: 'kong:1.5.1', networks: { 'kong-admin': {}, 'proxy-edge': {} }, environment: { KONG_PG_PASSWORD: 'synthetic-existing-native-db' } }, 'console-web': { image: 'unchanged-web', networks: { frontend: {} } }, 'telemetry-collector': { image: 'unchanged-collector', networks: { telemetry: {} }, environment: { MATERIAL_GENERATION: '2' } } }, networks: { frontend: { driver: 'bridge' }, 'kong-admin': { internal: true }, telemetry: { internal: true }, 'proxy-edge': { driver: 'bridge' } }, volumes: { old_native_data: {} } };
  const config: any = structuredClone(base), password = 'd4'.repeat(32);
  config.services['console-api'].environment.OUTBOUND_ALLOWED_HOSTS += ',kong-portal-admin-endpoint:8001';
  config.services['console-api'].environment.PROTECTED_DESTINATION_HOSTS += ',kong-portal-db,172.28.23.20,kong-portal-admin-endpoint,172.28.13.20,172.28.13.10';
  config.services['console-api'].networks['kong-portal-admin'] = { ipv4_address: '172.28.13.10' };
  config.services['kong-portal'] = { image: 'kong:1.5.1', user: 'kong', profiles: ['portal-acceptance'], networks: { 'kong-portal-admin': { ipv4_address: '172.28.13.20', aliases: ['kong-portal-admin-endpoint'] }, 'kong-portal-storage': { ipv4_address: '172.28.23.10' }, 'proxy-edge': {} }, environment: { KONG_PG_PASSWORD: password, KONGOS_ADMIN_BIND_IP: '172.28.13.20', KONGOS_BFF_ADMIN_IP: '172.28.13.10', KONG_ADMIN_ERROR_LOG: '/dev/null', KONG_PROXY_ERROR_LOG: '/dev/null' }, entrypoint: ['/bin/sh', '/opt/kongos/kong-secure-start.sh'], cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'], ports: [{ host_ip: '127.0.0.1', published: '10000', target: 8000 }], volumes: [{ type: 'bind', source: resolve('deploy/scripts/kong-secure-start.sh'), target: '/opt/kongos/kong-secure-start.sh', read_only: true }], healthcheck: { test: ['CMD', 'kong', 'health'] }, depends_on: { 'kong-portal-migrations': { condition: 'service_completed_successfully' } } };
  config.services['kong-portal-db'] = { image: 'postgres:11-alpine', profiles: ['portal-acceptance'], networks: { 'kong-portal-storage': { ipv4_address: '172.28.23.20' } }, environment: { POSTGRES_PASSWORD: password }, volumes: [{ source: 'kong_portal_db_data', target: '/var/lib/postgresql/data' }] };
  config.services['kong-portal-migrations'] = { image: 'kong:1.5.1', profiles: ['portal-acceptance'], networks: { 'kong-portal-storage': {} }, environment: { KONG_PG_PASSWORD: password }, entrypoint: ['/bin/sh', '/opt/kongos/kong-migrate.sh'], volumes: [{ type: 'bind', source: resolve('deploy/scripts/kong-migrate.sh'), target: '/opt/kongos/kong-migrate.sh', read_only: true }], depends_on: { 'kong-portal-db': { condition: 'service_healthy' } } };
  config.networks['kong-portal-admin'] = { internal: true, driver: 'bridge', ipam: { config: [{ subnet: '172.28.13.0/24' }] } };
  config.networks['kong-portal-storage'] = { internal: true, driver: 'bridge', ipam: { config: [{ subnet: '172.28.23.0/24' }] } };
  config.volumes.kong_portal_db_data = {};
  return { base, config };
}
function accepted(base: any, config: any) { try { const checks = portalAcceptanceChecks(base, config); return checks.length > 0 && checks.every((row: any) => row.passed); } catch { return false; } }
const directories: string[] = [];
const directory = () => { const path = mkdtempSync(join(tmpdir(), 'kongos-c3-offline-review-')); chmodSync(path, 0o700); directories.push(path); return path; };
afterEach(() => { for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true }); });

describe('M6 independent isolated C3 acceptance deployment facts', () => {
  it('accepts only the optional new Kong1.5/PG11/bootstrap with preserved original services, metrics and storage', () => {
    const f = composeFacts(), original = structuredClone(f.base); expect(accepted(f.base, f.config)).toBe(true); expect(f.base).toEqual(original);
    expect(Object.values(f.config.services['console-api'].environment)).not.toContain(f.config.services['kong-portal-db'].environment.POSTGRES_PASSWORD);
  });
  it.each(['api-publication', 'api-command', 'api-build', 'api-volume', 'old-kong', 'old-collector', 'old-network', 'old-volume'])('rejects an unauthorized existing configuration mutation: %s', variant => {
    const f = composeFacts();
    if (variant === 'api-publication') f.config.services['console-api'].ports = [{ host_ip: '0.0.0.0', published: '3000', target: 3000 }];
    if (variant === 'api-command') f.config.services['console-api'].command = ['node', 'unsafe-replacement.js'];
    if (variant === 'api-build') f.config.services['console-api'].build = { context: 'other-source' };
    if (variant === 'api-volume') f.config.services['console-api'].volumes = [{ source: '/', target: '/host', read_only: false }];
    if (variant === 'old-kong') f.config.services.kong.image = 'kong:latest';
    if (variant === 'old-collector') f.config.services['telemetry-collector'].environment.MATERIAL_GENERATION = '3';
    if (variant === 'old-network') f.config.networks.telemetry.internal = false;
    if (variant === 'old-volume') f.config.volumes.old_native_data = { external: true };
    expect(accepted(f.base, f.config)).toBe(false);
  });
  it.each(['db-admin', 'api-storage', 'collector-admin', 'migration-admin', 'kong-extra-network'])('rejects management or storage cross-membership: %s', variant => {
    const f = composeFacts();
    if (variant === 'db-admin') f.config.services['kong-portal-db'].networks['kong-portal-admin'] = {};
    if (variant === 'api-storage') f.config.services['console-api'].networks['kong-portal-storage'] = {};
    if (variant === 'collector-admin') f.config.services['telemetry-collector'].networks['kong-portal-admin'] = {};
    if (variant === 'migration-admin') f.config.services['kong-portal-migrations'].networks['kong-portal-admin'] = {};
    if (variant === 'kong-extra-network') f.config.services['kong-portal'].networks.telemetry = {};
    expect(accepted(f.base, f.config)).toBe(false);
  });
  it.each(['kong-portal', 'kong-portal-db', 'kong-portal-migrations'])('rejects %s using host networking behind nominal attachment facts', service => {
    const f = composeFacts(); f.config.services[service].network_mode = 'host'; expect(accepted(f.base, f.config)).toBe(false);
  });
  it.each(['native-host-pid', 'db-host-pid', 'migration-host-pid', 'db-privileged', 'migration-capability', 'host-device', 'native-extra-host-mount', 'foreign-startup-script', 'bootstrap-script-swap', 'writable-startup-script', 'unsafe-sysctl'])('rejects namespace, privilege or foreign-host authority outside the fixed C3 topology: %s', variant => {
    const f = composeFacts(), native = f.config.services['kong-portal'], db = f.config.services['kong-portal-db'], migration = f.config.services['kong-portal-migrations'];
    if (variant === 'native-host-pid') native.pid = 'host';
    if (variant === 'db-host-pid') db.pid = 'host';
    if (variant === 'migration-host-pid') migration.pid = 'host';
    if (variant === 'db-privileged') db.privileged = true;
    if (variant === 'migration-capability') migration.cap_add = ['SYS_ADMIN'];
    if (variant === 'host-device') native.devices = [{ source: '/dev/sda', target: '/dev/sda' }];
    if (variant === 'native-extra-host-mount') native.volumes.push({ type: 'bind', source: '/', target: '/host', read_only: false });
    if (variant === 'foreign-startup-script') native.volumes[0].source = '/tmp/foreign-project/deploy/scripts/kong-secure-start.sh';
    if (variant === 'bootstrap-script-swap') migration.entrypoint = ['/bin/sh', '-c', 'unsafe-command'];
    if (variant === 'writable-startup-script') native.volumes[0].read_only = false;
    if (variant === 'unsafe-sysctl') native.sysctls = { 'net.ipv4.ip_forward': '1' };
    expect(accepted(f.base, f.config)).toBe(false);
  });
  it.each(['wildcard-proxy', 'admin-published', 'db-published', 'bootstrap-published', 'unprofiled', 'version', 'allow-wildcard', 'allow-dropped', 'protected-ip-dropped', 'api-secret-copy', 'shared-old-storage'])('rejects unsafe optional C3 facts: %s', variant => {
    const f = composeFacts(), native = f.config.services['kong-portal'], db = f.config.services['kong-portal-db'], api = f.config.services['console-api'];
    if (variant === 'wildcard-proxy') native.ports[0].host_ip = '0.0.0.0';
    if (variant === 'admin-published') native.ports.push({ host_ip: '127.0.0.1', published: '8001', target: 8001 });
    if (variant === 'db-published') db.ports = [{ host_ip: '127.0.0.1', published: '5432', target: 5432 }];
    if (variant === 'bootstrap-published') f.config.services['kong-portal-migrations'].ports = [{ host_ip: '127.0.0.1', published: '8001', target: 8001 }];
    if (variant === 'unprofiled') delete native.profiles;
    if (variant === 'version') native.image = 'kong:2.8';
    if (variant === 'allow-wildcard') api.environment.OUTBOUND_ALLOWED_HOSTS += ',*';
    if (variant === 'allow-dropped') api.environment.OUTBOUND_ALLOWED_HOSTS = 'kong-portal-admin-endpoint:8001';
    if (variant === 'protected-ip-dropped') api.environment.PROTECTED_DESTINATION_HOSTS = api.environment.PROTECTED_DESTINATION_HOSTS.split(',').filter((host: string) => host !== '172.28.13.20').join(',');
    if (variant === 'api-secret-copy') api.environment.PORTAL_SECRET = db.environment.POSTGRES_PASSWORD;
    if (variant === 'shared-old-storage') db.volumes[0].source = 'old_native_data';
    expect(accepted(f.base, f.config)).toBe(false);
  });
});

describe('M6 independent C3 private environment generation', () => {
  it('creates only one new private owned key file and never reads or changes existing material', () => {
    const parent = directory(), previous = join(parent, 'old-material'); writeFileSync(previous, 'synthetic-old-material\n', { mode: 0o600 });
    const target = join(parent, 'new-material'), result = generatePortalAcceptanceEnvironment(target), text = readFileSync(target, 'utf8');
    expect(result).toEqual({ path: target, mode: '0600', overwritten: false, existingMaterialsModified: false });
    expect(text).toMatch(/^KONG_PORTAL_DATABASE_PASSWORD=[a-f0-9]{64}\n$/);
    expect(lstatSync(target).mode & 0o777).toBe(0o600); expect(lstatSync(target).uid).toBe(process.getuid?.()); expect(lstatSync(target).nlink).toBe(1);
    expect(readFileSync(previous, 'utf8')).toBe('synthetic-old-material\n'); expect(readdirSync(parent).sort()).toEqual(['new-material', 'old-material']);
    expect(JSON.stringify(result)).not.toContain(text.trim().split('=')[1]);
  });
  it('does not overwrite, rotate or chmod an existing new environment on repeated invocation', () => {
    const target = join(directory(), 'material'); generatePortalAcceptanceEnvironment(target); const before = readFileSync(target, 'utf8');
    expect(() => generatePortalAcceptanceEnvironment(target)).toThrow(); expect(readFileSync(target, 'utf8')).toBe(before); expect(lstatSync(target).mode & 0o777).toBe(0o600);
  });
  it.each(['symlink-target', 'directory-target', 'symlink-parent'])('rejects %s without changing another file', variant => {
    const parent = directory(), original = join(parent, 'original'); writeFileSync(original, 'unchanged\n', { mode: 0o600 }); let target = join(parent, 'new-material');
    if (variant === 'symlink-target') symlinkSync(original, target);
    if (variant === 'directory-target') mkdirSync(target);
    if (variant === 'symlink-parent') { symlinkSync(parent, join(parent, 'parent-link')); target = join(parent, 'parent-link', 'new-material'); }
    expect(() => generatePortalAcceptanceEnvironment(target)).toThrow(); expect(readFileSync(original, 'utf8')).toBe('unchanged\n');
    if (variant === 'symlink-parent') expect(existsSync(join(parent, 'new-material'))).toBe(false);
  });
  it.each([0o777, 0o770, 0o707])('rejects writable shared parent mode %s before a credential file exists', mode => {
    const parent = directory(), target = join(parent, 'new-material'); chmodSync(parent, mode);
    expect(() => generatePortalAcceptanceEnvironment(target)).toThrow('PORTAL_ACCEPTANCE_ENV_PARENT_INVALID'); expect(existsSync(target)).toBe(false);
  });
});
