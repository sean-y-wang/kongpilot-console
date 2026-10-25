import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';

const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const directory = 'apps/console-api/src/infrastructure/migrations';
const sql046 = readFileSync(`${directory}/046_m11_builtin_approver_role.sql`, 'utf8');
const down046 = readFileSync('deploy/db-rollback/046_m11_builtin_approver_role.down.sql', 'utf8');

describe('SQL046 built-in approver role on real PostgreSQL', () => {
  const container = `kongos-m11-sql046-${randomUUID().slice(0, 8)}`;
  let started = false;
  const query = (sql: string): string => execFileSync('docker', [...base, 'exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'], {
    env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
  const perms = () => query("SELECT p.module||':'||p.action FROM role_permissions p JOIN roles r ON r.id=p.role_id WHERE r.builtin_kind='approver' ORDER BY 1;").split('\n').filter(Boolean);

  beforeAll(async () => {
    if (!existsSync('/var/run/docker.sock')) throw new Error('Disposable SQL tests require the local Docker socket');
    execFileSync('docker', [...base, 'run', '-d', '--name', container, '--network', 'none', '--tmpfs', '/tmp/sql-data:rw,size=256m,mode=1777',
      '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'PGDATA=/tmp/sql-data/pgdata', 'postgres:16-alpine'], { env: dockerEnv, stdio: 'pipe' });
    started = true;
    for (let i = 0; i < 100; i++) {
      try { query('SELECT 1;'); break; }
      catch { if (i === 99) throw new Error('Disposable SQL046 PostgreSQL unavailable'); await new Promise(r => setTimeout(r, 100)); }
    }
    const files = readdirSync(directory).filter(n => /^0(?:[0-3]\d|4[0-5])_.*\.sql$/.test(n)).sort();
    expect(files).toHaveLength(46);
    for (const file of files) query(readFileSync(`${directory}/${file}`, 'utf8'));
  }, 180_000);
  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  it('seeds a protected global approver with only read+approve and no secrets', () => {
    const epoch = Number(query('SELECT version FROM iam_epoch WHERE singleton;'));
    query(sql046);
    expect(Number(query('SELECT version FROM iam_epoch WHERE singleton;'))).toBeGreaterThan(epoch);
    expect(query("SELECT code||'|'||protected||'|'||coalesce(cluster_id::text,'-')||'|'||status FROM roles WHERE builtin_kind='approver';")).toBe('approver|true|-|active');
    const list = perms();
    expect(list).toHaveLength(72);
    expect(list.every(p => /:(read|approve)$/.test(p))).toBe(true);
    expect(list.some(p => p.startsWith('secrets:'))).toBe(false);
    expect(list).toContain('workflows:approve');
    expect(list).toContain('promote:approve');
  });

  it('keeps built-in scope constraints strict', () => {
    expect(() => query("INSERT INTO roles(code,name,builtin_kind,protected) VALUES('approver','dup','approver',true);")).toThrow();
    expect(() => query("INSERT INTO roles(code,name,builtin_kind,protected) VALUES('bogus','bogus','bogus',true);")).toThrow();
    expect(() => query("INSERT INTO roles(code,name,builtin_kind,protected) VALUES('workspace-admin','x','workspace-admin',true);")).toThrow();
  });

  it('rolls back cleanly and re-applies', () => {
    query(down046);
    expect(query("SELECT count(*) FROM roles WHERE code='approver';")).toBe('0');
    expect(() => query("INSERT INTO roles(code,name,builtin_kind,protected) VALUES('approver2','x','approver',true);")).toThrow();
    query(sql046);
    expect(perms()).toHaveLength(72);
    expect(() => query("DELETE FROM roles WHERE code='approver';")).toThrow(/soft-deleted/);
  });

  it('refuses when a custom global role already uses the approver code', () => {
    query(down046);
    query("INSERT INTO roles(code,name) VALUES('approver','custom');");
    expect(() => query(sql046)).toThrow(/SQL046 refused/);
  });
});
