import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { DbService } from '../../apps/console-api/src/infrastructure/db.service';
import { runBreakGlass, eligibleApprovers } from '../../apps/console-api/src/infrastructure/approval-break-glass';

const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const directory = 'apps/console-api/src/infrastructure/migrations';
const origin = { host: 'test-host', osUser: 'ops' };
const ok = { operator: 'oncall-ops', reason: 'single admin cannot approve own change; INC recovery', ticket: 'INC-1234' };

describe('approval break-glass CLI core on real PostgreSQL', () => {
  const container = `kongos-m11-bg-${randomUUID().slice(0, 8)}`;
  let started = false; let db: DbService; const audits: any[] = [];
  const audit = { append: async (event: any) => { audits.push(event); return {} as any; } };
  const query = (sql: string): string => execFileSync('docker', [...base, 'exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'], {
    env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
  const user = (super_admin = false) => { const id = randomUUID(); query(`INSERT INTO users(id,username,password_hash,super_admin,status) VALUES('${id}','u${id.slice(0, 8)}','x',${super_admin},'active');`); return id; };

  beforeAll(async () => {
    if (!existsSync('/var/run/docker.sock')) throw new Error('Disposable SQL tests require the local Docker socket');
    execFileSync('docker', [...base, 'run', '-d', '--name', container, '--tmpfs', '/tmp/sql-data:rw,size=256m,mode=1777',
      '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'PGDATA=/tmp/sql-data/pgdata', 'postgres:16-alpine'], { env: dockerEnv, stdio: 'pipe' });
    started = true;
    for (let i = 0; i < 100; i++) {
      try { query('SELECT 1;'); break; }
      catch { if (i === 99) throw new Error('Disposable PostgreSQL unavailable'); await new Promise(r => setTimeout(r, 100)); }
    }
    for (const file of readdirSync(directory).filter(n => /^\d{3}_.*\.sql$/.test(n)).sort()) query(readFileSync(`${directory}/${file}`, 'utf8'));
    // Connect to the container's own bridge address rather than an ephemeral
    // host port: under full-suite load many disposable PostgreSQL containers
    // start and stop concurrently, and a recycled loopback port could point
    // this file's DbService at another file's database (older migrations, no
    // approver role). A per-container marker proves which server we reached.
    const ip = execFileSync('docker', [...base, 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', container], { env: dockerEnv, encoding: 'utf8' }).trim();
    const marker = randomUUID();
    query(`CREATE TABLE IF NOT EXISTS zz_test_identity(marker text NOT NULL); INSERT INTO zz_test_identity VALUES('${marker}');`);
    process.env.DATABASE_URL = `postgres://postgres@${ip}:5432/postgres`;
    db = new DbService();
    const seen = await db.query<{ marker: string }>('SELECT marker FROM zz_test_identity');
    if (seen.length !== 1 || seen[0].marker !== marker) throw new Error('Connected to an unexpected PostgreSQL server');
  }, 180_000);
  afterAll(async () => { await db?.onModuleDestroy(); if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  it('rejects malformed or under-justified commands before touching IAM', async () => {
    const target = user();
    for (const bad of [null, [], { action: 'set-direct' }, { action: 'status', x: 1 },
      { action: 'grant-approver', userId: target, ...ok, approve: true },
      { action: 'grant-approver', userId: 'nope', ...ok },
      { action: 'grant-approver', userId: target, ...ok, reason: 'short' },
      { action: 'grant-approver', userId: target, ...ok, ticket: '' },
      { action: 'grant-approver', userId: target, ...ok, operator: '' }])
      await expect(runBreakGlass(db, audit, bad, origin)).rejects.toThrow(/BREAK_GLASS_/);
    expect(audits).toHaveLength(0);
  });

  it('grants the protected approver role only during a real deadlock, fully audited', async () => {
    const admin = user(true), second = user();
    expect(await runBreakGlass(db, audit, { action: 'status' }, origin)).toMatchObject({ eligibleApprovers: 1, deadlockRisk: true });
    const epoch = Number(query("SELECT permissions_epoch FROM users WHERE id='" + second + "';"));
    const result: any = await runBreakGlass(db, audit, { action: 'grant-approver', userId: second, ...ok }, origin);
    expect(result).toMatchObject({ eligibleApproversBefore: 1, eligibleApproversAfter: 2 });
    expect(Number(query("SELECT permissions_epoch FROM users WHERE id='" + second + "';"))).toBe(epoch + 1);
    expect(query(`SELECT count(*) FROM iam_effective_grants WHERE user_id='${second}' AND action IN('write','delete');`)).toBe('0');
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ actorType: 'system', action: 'break_glass_grant_approver', entityId: result.bindingId,
      after: { user_id: second, operator: 'oncall-ops', ticket: 'INC-1234', host: 'test-host', os_user: 'ops' } });
    // No longer deadlocked: a second grant is refused and nothing is audited.
    const third = user();
    await expect(runBreakGlass(db, audit, { action: 'grant-approver', userId: third, ...ok }, origin)).rejects.toThrow('BREAK_GLASS_NOT_DEADLOCKED');
    expect(audits).toHaveLength(1);
    expect(await eligibleApprovers(db)).toBe(2); void admin;
  });

  it('rolls the grant back when the audit write fails', async () => {
    query("UPDATE user_role_bindings SET status='revoked',revoked_at=now(),retention_until=now()+interval '1 day' WHERE role_id=(SELECT id FROM roles WHERE builtin_kind='approver');");
    const target = user();
    const failing = { append: async () => { throw new Error('audit down'); } };
    await expect(runBreakGlass(db, failing, { action: 'grant-approver', userId: target, ...ok }, origin)).rejects.toThrow('audit down');
    expect(query(`SELECT count(*) FROM user_role_bindings WHERE user_id='${target}';`)).toBe('0');
  });

  it('refuses inactive users', async () => {
    const target = user(); query(`UPDATE users SET status='disabled' WHERE id='${target}';`);
    await expect(runBreakGlass(db, audit, { action: 'grant-approver', userId: target, ...ok }, origin)).rejects.toThrow('BREAK_GLASS_USER_NOT_ACTIVE');
  });
});

describe('approval break-glass has no API surface', () => {
  it('is not imported by any Nest module, controller or service', () => {
    const out = execFileSync('grep', ['-rl', 'approval-break-glass', 'apps/console-api/src'], { encoding: 'utf8' }).trim().split('\n');
    expect(out).toEqual(['apps/console-api/src/infrastructure/approval-break-glass.ts']);
  });
});
