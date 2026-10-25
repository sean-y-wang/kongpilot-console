import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';

// Regression: SQL040 re-created m11_validate_control_intent_author() with the
// transaction-start issuance guard that SQL034 had repaired, so every control
// change preparation on an approval-mode cluster failed with 23514.
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const directory = 'apps/console-api/src/infrastructure/migrations';
const sql047 = readFileSync(`${directory}/047_m11_control_intent_clock_reapply.sql`, 'utf8');
const down047 = readFileSync('deploy/db-rollback/047_m11_control_intent_clock_reapply.down.sql', 'utf8');
const U = '11111111-1111-4111-8111-111111111111', S = '22222222-2222-4222-8222-222222222222', C = '33333333-3333-4333-8333-333333333333', W = '44444444-4444-4444-8444-444444444444';

describe('SQL047 control intent issuance clock on real PostgreSQL', () => {
  const container = `kongos-m11-sql047-${randomUUID().slice(0, 8)}`;
  let started = false;
  const query = (sql: string): string => execFileSync('docker', [...base, 'exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'], {
    env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
  const definition = () => query("SELECT pg_get_functiondef('m11_validate_control_intent_author()'::regprocedure);");
  // Issued after validators ran inside the same transaction, exactly as the service does.
  const prepare = (issued = "clock_timestamp()-interval '1 millisecond'", permission = "u.id::text||':'||u.permissions_epoch::text||':'||(SELECT version FROM iam_epoch WHERE singleton)::text") => query(`BEGIN;
SELECT pg_sleep(0.05);
INSERT INTO control_change_intents(id,cluster_id,workspace_id,actor_id,authoring_session_id,workflow_id,idempotency_key,request_hmac,material_hmac,material_secret,credential_epoch,permission_version,resource,resource_id,operation,before_revision,before_config_hmac,issued_at,expires_at)
SELECT gen_random_uuid(),'${C}','${W}',u.id,'${S}',gen_random_uuid(),'k-'||gen_random_uuid(),repeat('a',64),repeat('b',64),'v1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.AAAA',u.credential_epoch,${permission},'data-sources',gen_random_uuid(),'create',0,repeat('c',64),${issued},clock_timestamp()+interval '1 hour' FROM users u WHERE u.id='${U}';
ROLLBACK;`);

  beforeAll(async () => {
    if (!existsSync('/var/run/docker.sock')) throw new Error('Disposable SQL tests require the local Docker socket');
    execFileSync('docker', [...base, 'run', '-d', '--name', container, '--network', 'none', '--tmpfs', '/tmp/sql-data:rw,size=256m,mode=1777',
      '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'PGDATA=/tmp/sql-data/pgdata', 'postgres:16-alpine'], { env: dockerEnv, stdio: 'pipe' });
    started = true;
    for (let i = 0; i < 100; i++) {
      try { query('SELECT 1;'); break; }
      catch { if (i === 99) throw new Error('Disposable SQL047 PostgreSQL unavailable'); await new Promise(r => setTimeout(r, 100)); }
    }
    const files = readdirSync(directory).filter(n => /^0(?:[0-3]\d|4[0-6])_.*\.sql$/.test(n)).sort();
    expect(files).toHaveLength(47);
    for (const file of files) query(readFileSync(`${directory}/${file}`, 'utf8'));
    query(`INSERT INTO users(id,username,password_hash,status) VALUES('${U}','fx','x','active');
INSERT INTO auth_sessions(id,user_id,expires_at,credential_epoch) SELECT '${S}',id,now()+interval '2 hours',credential_epoch FROM users WHERE id='${U}';
INSERT INTO clusters(id,name,admin_url,execution_mode) VALUES('${C}','fx','http://127.0.0.1:1','approval');
INSERT INTO workspaces(id,cluster_id,code,name) VALUES('${W}','${C}','fx','fx');`);
  }, 180_000);
  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  it('reproduces the SQL040 regression: an intent issued after transaction start is rejected', () => {
    expect(definition()).toContain('NEW.issued_at>now()');
    expect(() => prepare()).toThrow(/genuine current original author/);
  });

  it('repairs only the issuance clock and accepts a genuinely prepared intent', () => {
    const before = definition();
    query(sql047);
    const after = definition();
    expect(after).not.toContain('NEW.issued_at>now()');
    expect(after).toBe(before.replace('NEW.issued_at>now()', 'NEW.issued_at>clock_timestamp()'));
    expect(() => prepare()).not.toThrow();
  });

  it('keeps every other guard: future issuance and stale permission versions are still rejected', () => {
    expect(() => prepare("clock_timestamp()+interval '1 minute'")).toThrow(/genuine current original author/);
    expect(() => prepare("clock_timestamp()-interval '1 millisecond'", "'stale'")).toThrow(/genuine current original author/);
    query("UPDATE clusters SET execution_mode='direct' WHERE id='" + C + "';");
    expect(() => prepare()).toThrow(/genuine current original author/);
    query("UPDATE clusters SET execution_mode='approval' WHERE id='" + C + "';");
  });

  it('is idempotent, rolls back exactly and re-applies', () => {
    const repaired = definition();
    query(sql047);
    expect(definition()).toBe(repaired);
    query(down047);
    expect(definition()).toContain('NEW.issued_at>now()');
    expect(() => prepare()).toThrow(/genuine current original author/);
    query(sql047);
    expect(definition()).toBe(repaired);
  });
});
