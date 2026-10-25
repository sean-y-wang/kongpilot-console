import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';

const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const directory = 'apps/console-api/src/infrastructure/migrations';
const sql045 = readFileSync(`${directory}/045_m11_portal_credential_change_schedules.sql`, 'utf8');
const functions = [
  'm11_business_schedule_pointer_advance(workflows,workflows)',
  'm11_business_schedule_revision_complete()',
  'm11_business_origin_permission()',
  'm11_business_storage_complete()',
];

describe('SQL045 portal-credential rotate/revoke schedules on real PostgreSQL', () => {
  const container = `kongos-m11-sql045-${randomUUID().slice(0, 8)}`;
  let started = false;
  const query = (sql: string): string => execFileSync('docker', [...base, 'exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'], {
    env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
  const fnDef = (f: string) => query(`SELECT pg_get_functiondef('public.${f}'::regprocedure);`);

  beforeAll(async () => {
    if (!existsSync('/var/run/docker.sock')) throw new Error('Disposable SQL tests require the local Docker socket');
    execFileSync('docker', [...base, 'run', '-d', '--name', container, '--network', 'none', '--tmpfs', '/tmp/sql-data:rw,size=256m,mode=1777',
      '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'PGDATA=/tmp/sql-data/pgdata', 'postgres:16-alpine'], { env: dockerEnv, stdio: 'pipe' });
    started = true;
    for (let i = 0; i < 100; i++) {
      try { query('SELECT 1;'); break; }
      catch { if (i === 99) throw new Error('Disposable SQL045 PostgreSQL unavailable'); await new Promise(r => setTimeout(r, 100)); }
    }
    const files = readdirSync(directory).filter(n => /^0(?:[0-3]\d|4[0-4])_.*\.sql$/.test(n)).sort();
    expect(files).toHaveLength(45);
    for (const file of files) query(readFileSync(`${directory}/${file}`, 'utf8'));
  }, 180_000);
  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  it('applies once, admits rotate/revoke kinds with developer+grant binding, pins search_path', () => {
    const before = functions.map(fnDef);
    query(sql045);
    for (const [n, f] of functions.entries()) {
      const def = fnDef(f);
      expect(def).toContain("'portal-credential-rotate'");
      expect(def).toContain("'portal-credential-revoke'");
      expect(def).toMatch(/SET search_path TO 'pg_catalog', 'public', 'pg_temp'/);
      expect(before[n]).not.toContain("'portal-credential-rotate'");
    }
    expect(query(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='workflow_schedules_kind_check';`))
      .toContain('portal-credential-rotate');
    expect(query(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='workflow_executor_delegations_portal_subject_check';`))
      .toContain('portal-credential-revoke');
    const owner = randomUUID(), other = randomUUID();
    const def = query(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='workflow_executor_delegations_portal_subject_check';`);
    const run = (row: string) => query(`BEGIN;CREATE TEMP TABLE d(kind text,subject_type text,requester_type text,requester_id uuid,owner_id uuid,requester_credential_epoch bigint,owner_credential_epoch bigint);
      ALTER TABLE d ADD CONSTRAINT c ${def};INSERT INTO d VALUES(${row});ROLLBACK;`);
    expect(() => run(`'portal-credential-rotate','portal_application_grants','developer','${owner}','${other}',3,4`)).not.toThrow();
    expect(() => run(`'portal-credential-revoke','portal_application_grants','developer','${owner}','${other}',3,4`)).not.toThrow();
    expect(() => run(`'portal-credential-rotate','portal_application_grants','console','${owner}','${owner}',3,3`)).toThrow(/violates check constraint/);
    expect(() => run(`'portal-credential-revoke','configuration_jobs','developer','${owner}','${other}',3,4`)).toThrow(/violates check constraint/);
    expect(() => run(`'portal-credential-issue','portal_application_grants','developer','${owner}','${other}',3,4`)).not.toThrow();
    expect(() => query(`BEGIN;\n${sql045}\nROLLBACK;`)).toThrow();
  });
});
