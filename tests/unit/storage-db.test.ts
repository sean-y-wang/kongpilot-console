import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';

const mocks = vi.hoisted(() => ({
  query: vi.fn(), release: vi.fn(), end: vi.fn(), on: vi.fn(), connect: vi.fn(),
}));
vi.mock('pg', () => ({ Pool: class {
  query = mocks.query; end = mocks.end; on = mocks.on; connect = mocks.connect;
} }));
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';

describe('DbService transaction and migration integrity', () => {
  beforeEach(() => {
    vi.stubEnv('DATABASE_URL', 'postgres://console:explicit-password@localhost/console');
    vi.clearAllMocks();
    mocks.query.mockResolvedValue({ rows: [], rowCount: 0 });
    mocks.connect.mockResolvedValue({ query: mocks.query, release: mocks.release });
  });
  afterEach(() => vi.unstubAllEnvs());

  it('passes parameter values separately and reads empty/one results correctly', async () => {
    const db = new DbService();
    mocks.query.mockResolvedValueOnce({ rows: [{ id: 'one' }], rowCount: 1 });
    expect(await db.one('SELECT id FROM users WHERE username = $1', ["x' OR 1=1 --"])).toEqual({ id: 'one' });
    expect(mocks.query).toHaveBeenCalledWith('SELECT id FROM users WHERE username = $1', ["x' OR 1=1 --"]);
    expect(await db.one('SELECT id FROM users')).toBeNull();
    expect(await db.exec('UPDATE users SET status = $1', ['disabled'])).toBe(0);
  });

  it('commits callback work on one connection and implements nested savepoints', async () => {
    const db = new DbService();
    expect(await db.transaction(async tx => tx.transaction(async nested => {
      await nested.exec('SELECT $1::text', ['nested']); return 'done';
    }))).toBe('done');
    expect(mocks.query.mock.calls.map(call => call[0])).toEqual([
      'BEGIN', 'SAVEPOINT kongos_savepoint_1', 'SELECT $1::text',
      'RELEASE SAVEPOINT kongos_savepoint_1', 'COMMIT',
    ]);
    expect(mocks.connect).toHaveBeenCalledTimes(1);
    expect(mocks.release).toHaveBeenCalledOnce();
  });

  it('rolls back and releases its connection after callback failure', async () => {
    const db = new DbService();
    await expect(db.transaction(async () => { throw new Error('simulated failure'); })).rejects.toThrow('simulated failure');
    expect(mocks.query.mock.calls.map(call => call[0])).toEqual(['BEGIN', 'ROLLBACK']);
    expect(mocks.release).toHaveBeenCalledOnce();
  });

  it('applies migrations under an advisory lock with persisted SQL checksums', async () => {
    const db = new DbService();
    await db.migrate();
    const sql = await readFile('apps/console-api/src/infrastructure/migrations/000_m0.sql', 'utf8');
    expect(mocks.query).toHaveBeenCalledWith('SELECT pg_advisory_lock($1)', [1545015001]);
    expect(mocks.query).toHaveBeenCalledWith('INSERT INTO schema_migrations(name, checksum) VALUES ($1, $2)',
      ['000_m0.sql', createHash('sha256').update(sql).digest('hex')]);
    expect(mocks.query).toHaveBeenCalledWith('SELECT pg_advisory_unlock($1)', [1545015001]);
    expect(mocks.release).toHaveBeenCalledOnce();
  });

  it('refuses changed migration SQL without applying it', async () => {
    const db = new DbService();
    mocks.query.mockImplementation(async (sql: string) => ({ rows: sql.startsWith('SELECT name, checksum')
      ? [{ name: '000_m0.sql', checksum: 'changed' }] : [], rowCount: 0 }));
    await expect(db.migrate()).rejects.toThrow('checksum mismatch');
    expect(mocks.query.mock.calls.some(call => call[0] === 'BEGIN')).toBe(false);
    expect(mocks.release).toHaveBeenCalledOnce();
  });

  it('runtime skip does not migrate or bootstrap and verifies existing administrator', async () => {
    vi.stubEnv('SKIP_MIGRATIONS', 'true');
    const directory='apps/console-api/src/infrastructure/migrations';
    const files=(await readdir(directory)).filter(file=>/^\d+_[\w-]+\.sql$/.test(file));
    const ledger=await Promise.all(files.map(async name=>({name,checksum:createHash('sha256').update(await readFile(`${directory}/${name}`,'utf8')).digest('hex')})));
    mocks.query.mockImplementation(async (sql: string) => ({ rows: sql.includes('super_admin') ? [{ id: 'admin' }] : ledger, rowCount: 0 }));
    await new DbService().onModuleInit();
    expect(mocks.connect).not.toHaveBeenCalled();
    expect(mocks.query.mock.calls.some(call => String(call[0]).includes('INSERT INTO users'))).toBe(false);
  });
});
