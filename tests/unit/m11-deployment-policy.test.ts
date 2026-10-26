import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseDocument } from 'yaml';

const database = vi.hoisted(() => ({ query: vi.fn(), connect: vi.fn(), on: vi.fn(), end: vi.fn() }));
vi.mock('pg', () => ({ Pool: class {
  query = database.query; connect = database.connect; on = database.on; end = database.end;
} }));
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';

function composition(path: string) {
  const document = parseDocument(readFileSync(path, 'utf8'), {
    customTags: [{ tag: '!override', collection: 'seq', resolve: (value: any) => value }],
  });
  expect(document.errors).toEqual([]);
  return document.toJS() as any;
}
const base = composition('docker-compose.yml');
const production = composition('deploy/compose/compose.production.yml');
const migrations = 'apps/console-api/src/infrastructure/migrations';
const ledger = readdirSync(migrations).filter(name => /^\d+_[\w-]+\.sql$/.test(name)).sort().map(name => ({
  name, checksum: createHash('sha256').update(readFileSync(join(migrations, name), 'utf8')).digest('hex'),
}));
const required = Array.from({ length: 21 }, (_, index) => index + 4);

afterEach(() => vi.unstubAllEnvs());

describe('M11 scheduled worker deployment is explicit and API-only', () => {
  it('defaults to false in the public template and Compose, with an explicit real-timer acceptance notice', () => {
    const example = readFileSync('.env.example', 'utf8');
    expect(example.match(/^ENTITY_SCHEDULES_ENABLED=(.*)$/gm)).toEqual(['ENTITY_SCHEDULES_ENABLED=false']);
    expect(example).toContain('开启后须完成真实定时执行验收');
    expect(base.services['console-api'].environment.ENTITY_SCHEDULES_ENABLED).toBe('${ENTITY_SCHEDULES_ENABLED:-false}');
    expect(production.services['console-api'].environment.ENTITY_SCHEDULES_ENABLED).toBeUndefined();
  });

  it('does not pass the schedule switch or any other worker enable switch into the migration job', () => {
    expect(Object.entries(base.services).filter(([, service]: any) =>
      Object.hasOwn(service.environment ?? {}, 'ENTITY_SCHEDULES_ENABLED')).map(([name]) => name)).toEqual(['console-api']);
    for (const config of [base, production]) {
      const environment = config.services['console-migrations'].environment ?? {};
      expect(Object.keys(environment).filter(key => /(?:WORKER_ENABLED|SCHEDULES_ENABLED)$/.test(key))).toEqual([]);
    }
  });

  it('requires the completed migration job before API startup and keeps ready health checking enabled', () => {
    expect(base.services['console-api'].environment.SKIP_MIGRATIONS).toBe('true');
    expect(base.services['console-api'].depends_on['console-migrations']).toEqual({ condition: 'service_completed_successfully' });
    expect(base.services['console-migrations'].command).toEqual(['node', 'dist/infrastructure/migrate.js']);
    expect(base.services['console-api'].healthcheck.disable).not.toBe(true);
    expect(base.services['console-api'].healthcheck.test.at(-1)).toContain('/api/v1/health/ready');
    expect(readFileSync('apps/console-api/Dockerfile', 'utf8')).toContain('cp -a /app/apps/console-api/src/infrastructure/migrations /runtime/apps/console-api/dist/infrastructure/migrations');
  });

  it.each([
    ['kong-db', 'kong_db_data', '/var/lib/postgresql/data'],
    ['console-db', 'console_db_data', '/var/lib/postgresql/data'],
    ['redis', 'redis_data', '/data'],
    ['prometheus', 'prometheus_data', '/prometheus'],
    ['loki', 'loki_data', '/loki'],
  ])('retains the persistent %s data volume through the production overlay', (service, volume, target) => {
    expect(base.services[service].volumes).toContain(`${volume}:${target}`);
    expect(Object.hasOwn(base.volumes, volume)).toBe(true);
    expect(base.volumes[volume].driver_opts?.type).not.toBe('tmpfs');
    for (const config of [base, production]) {
      const serviceConfig = config.services[service] ?? {};
      expect((serviceConfig.tmpfs ?? []).some((mount: string) => mount.split(':')[0] === target)).toBe(false);
    }
    // This overlay supplies security/resources, without replacing durable mounts.
    expect(production.services[service]?.volumes).toBeUndefined();
  });
});

describe('M11 runtime schema admission checks the real shipped 004–024 SQL files', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv('DATABASE_URL', 'postgres://synthetic:synthetic@db.invalid/offline');
    vi.stubEnv('SKIP_MIGRATIONS', 'true');
    vi.stubEnv('ENTITY_SCHEDULES_ENABLED', 'false');
  });
  function boot(rows: typeof ledger) {
    database.query.mockImplementation(async (sql: string) => ({ rows: sql.includes('schema_migrations') ? rows : [{ id: 'offline-admin' }] }));
    return new DbService().onModuleInit();
  }
  it('accepts the complete matching ledger with SELECT-only mocked SQL and no pool connection', async () => {
    expect(required.every(number => ledger.some(row => Number.parseInt(row.name, 10) === number))).toBe(true);
    await boot(ledger);
    expect(database.query.mock.calls.map(([sql]) => sql)).toEqual([
      'SELECT name, checksum FROM schema_migrations ORDER BY name',
      "SELECT id FROM users WHERE super_admin = true AND status = 'active' LIMIT 1",
    ]);
    expect(database.connect).not.toHaveBeenCalled();
  });
  it.each(required)('refuses startup with schedules disabled when migration %i is missing', async number => {
    const missing = ledger.find(row => Number.parseInt(row.name, 10) === number)!;
    expect(missing).toBeDefined();
    await expect(boot(ledger.filter(row => row.name !== missing.name))).rejects.toThrow(`CONSOLE_SCHEMA_MISSING:${missing.name}`);
    expect(database.query).toHaveBeenCalledTimes(1);
    expect(database.connect).not.toHaveBeenCalled();
  });
  it.each([4, 24])('refuses a changed checksum for migration %i without applying or repairing SQL', async number => {
    const changed = ledger.find(row => Number.parseInt(row.name, 10) === number)!;
    await expect(boot(ledger.map(row => row.name === changed.name ? { ...row, checksum: '0'.repeat(64) } : row)))
      .rejects.toThrow(`CONSOLE_SCHEMA_CHECKSUM_MISMATCH:${changed.name}`);
    expect(database.query).toHaveBeenCalledTimes(1);
    expect(database.connect).not.toHaveBeenCalled();
  });
});
