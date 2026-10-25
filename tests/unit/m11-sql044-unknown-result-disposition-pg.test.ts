import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';

/** SQL044 apply + rollback on disposable postgres:16-alpine (--network none, never DATABASE_URL). */
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const directory = 'apps/console-api/src/infrastructure/migrations';
const forward = readFileSync(`${directory}/044_m11_unknown_result_disposition.sql`, 'utf8');
const down = readFileSync('deploy/db-rollback/044_m11_unknown_result_disposition.down.sql', 'utf8');

describe('SQL044 unknown-result disposition migration (KP-003)', () => {
  const container = `kongos-m11-sql044-${randomUUID().slice(0, 8)}`;
  let started = false;
  const psql = ['exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'];
  const query = (sql: string): string => execFileSync('docker', [...base, ...psql], { env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  const fails = (sql: string): string => { try { query(sql); return ''; } catch (e) { return String((e as { stderr?: string }).stderr ?? e); } };
  const config = (name: string) => query(`SELECT coalesce(array_to_string(proconfig,';'),'') FROM pg_proc WHERE proname='${name}' ORDER BY 1 LIMIT 1;`);

  beforeAll(async () => {
    if (!existsSync('/var/run/docker.sock')) throw new Error('Disposable SQL tests require the local Docker socket');
    execFileSync('docker', [...base, 'run', '-d', '--name', container, '--network', 'none', '--tmpfs', '/tmp/sql-data:rw,size=256m,mode=1777',
      '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'PGDATA=/tmp/sql-data/pgdata', 'postgres:16-alpine'], { env: dockerEnv, stdio: 'pipe' });
    started = true;
    for (let i = 0; i < 100; i++) {
      try { query('SELECT 1;'); break; }
      catch { if (i === 99) throw new Error('Disposable PostgreSQL unavailable'); await new Promise(r => setTimeout(r, 100)); }
    }
    query('CREATE TABLE schema_migrations(name text PRIMARY KEY, checksum text NOT NULL);');
    const files = readdirSync(directory).filter(n => /^0(?:[0-3]\d|4[0-3])_.*\.sql$/.test(n)).sort();
    expect(files).toHaveLength(44);
    for (const file of files) query(readFileSync(`${directory}/${file}`, 'utf8'));
  }, 180_000);
  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  it('applies with pinned search_path, immutability, closing unique index and disposition checks', () => {
    expect(query(`SELECT to_regclass('public.workflow_unknown_result_dispositions') IS NOT NULL`)).toBe('f');
    query(`BEGIN;${forward};INSERT INTO schema_migrations VALUES('044_m11_unknown_result_disposition.sql','x');COMMIT;`);
    expect(query(`SELECT to_regclass('public.workflow_unknown_result_dispositions') IS NOT NULL`)).toBe('t');
    expect(config('m11_validate_unknown_result_disposition')).toBe('search_path=pg_catalog, public, pg_temp');
    expect(config('m11_unknown_result_disposition_insert')).toBe('search_path=pg_catalog, public, pg_temp');
    expect(config('m11_unknown_result_state_guard')).toBe('search_path=pg_catalog, public, pg_temp');
    const body = query(`SELECT prosrc FROM pg_proc WHERE proname='m11_validate_unknown_result_disposition';`);
    expect(body).toContain('nativeRequestsSent');
    expect(body).toContain('cannot rewrite or mismatch the original mutation receipt');
    const idx = query(`SELECT indexdef FROM pg_indexes WHERE indexname='workflow_unknown_result_closing_claim';`);
    expect(idx).toContain('verified-applied');
    expect(idx).toContain('verified-not-applied');
    expect(fails(`INSERT INTO workflow_unknown_result_dispositions(id,disposition,original_execution_state,evidence_hmac,request_hmac)
      VALUES(gen_random_uuid(),'replayed','uncertain',repeat('a',64),repeat('a',64));`)).toMatch(/violates|null value|check|Unknown-result disposition|not-null/i);
    query(`SET session_replication_role=replica;
      INSERT INTO workflow_unknown_result_dispositions(
        id,cluster_id,workspace_id,schedule_id,claim_id,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,
        actor_id,session_id,credential_epoch,disposition,original_execution_state,evidence_hmac,request_hmac,audit_id,audit_event_hash,observed_at)
      VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,repeat('a',64),
        gen_random_uuid(),gen_random_uuid(),1,'verification-rejected','uncertain',repeat('a',64),repeat('b',64),gen_random_uuid(),repeat('c',64),clock_timestamp());
      SET session_replication_role=origin;`);
    expect(fails(`UPDATE workflow_unknown_result_dispositions SET disposition='verified-applied';`)).toMatch(/immutable|cannot|m8|not allowed/i);
    expect(fails(`DELETE FROM workflow_unknown_result_dispositions;`)).toMatch(/immutable|cannot|m8|not allowed/i);
  });

  it('rolls back cleanly, refuses while dispositions exist, and re-applies', () => {
    // Clear evidence left by the previous case (replica bypasses immutability only for DELETE).
    query(`SET session_replication_role=replica;DELETE FROM workflow_unknown_result_dispositions;SET session_replication_role=origin;`);
    query(down);
    expect(query(`SELECT to_regclass('public.workflow_unknown_result_dispositions') IS NOT NULL`)).toBe('f');
    expect(query(`SELECT count(*) FROM schema_migrations WHERE name LIKE '044_%';`)).toBe('0');
    query(`BEGIN;${forward};INSERT INTO schema_migrations VALUES('044_m11_unknown_result_disposition.sql','x');COMMIT;`);
    expect(query(`SELECT to_regclass('public.workflow_unknown_result_dispositions') IS NOT NULL`)).toBe('t');
    // Seed with replica role to leave immutable evidence without full FK graph.
    query(`SET session_replication_role=replica;
      INSERT INTO workflow_unknown_result_dispositions(
        id,cluster_id,workspace_id,schedule_id,claim_id,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,
        actor_id,session_id,credential_epoch,disposition,original_execution_state,evidence_hmac,request_hmac,audit_id,audit_event_hash,observed_at)
      VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,repeat('a',64),
        gen_random_uuid(),gen_random_uuid(),1,'verification-rejected','uncertain',repeat('a',64),repeat('b',64),gen_random_uuid(),repeat('c',64),clock_timestamp());
      SET session_replication_role=origin;`);
    expect(fails(down)).toContain('SQL044 rollback refused');
    expect(query(`SELECT to_regclass('public.workflow_unknown_result_dispositions') IS NOT NULL`)).toBe('t');
  });
});
