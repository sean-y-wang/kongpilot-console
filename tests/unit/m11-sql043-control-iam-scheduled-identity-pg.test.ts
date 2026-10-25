import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';

/** SQL043 apply + rollback on disposable postgres:16-alpine (--network none, never DATABASE_URL). */
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const directory = 'apps/console-api/src/infrastructure/migrations';
const forward = readFileSync(`${directory}/043_m11_control_iam_scheduled_identity.sql`, 'utf8');
const down = readFileSync('deploy/db-rollback/043_m11_control_iam_scheduled_identity.down.sql', 'utf8');

describe('SQL043 scheduled control/iam identity migration', () => {
  const container = `kongos-m11-sql043-${randomUUID().slice(0, 8)}`;
  let started = false;
  const psql = ['exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'];
  const query = (sql: string): string => execFileSync('docker', [...base, ...psql], { env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  const fails = (sql: string): string => { try { query(sql); return ''; } catch (e) { return String((e as { stderr?: string }).stderr ?? e); } };
  const columns = (table: string) => query(`SELECT string_agg(column_name,',' ORDER BY column_name) FROM information_schema.columns WHERE table_name='${table}' AND column_name IN('execution_origin','schedule_claim_id');`);
  const config = (name: string) => query(`SELECT coalesce(array_to_string(proconfig,';'),'') FROM pg_proc WHERE proname='${name}';`);

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
    const files = readdirSync(directory).filter(n => /^0(?:[0-3]\d|4[0-2])_.*\.sql$/.test(n)).sort();
    expect(files).toHaveLength(43);
    for (const file of files) query(readFileSync(`${directory}/${file}`, 'utf8'));
  }, 180_000);
  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  it('applies with pinned search_path, defaults existing facts to session origin and enforces origin/claim pairing', () => {
    expect(columns('control_workflow_mutation_facts')).toBe('');
    expect(columns('iam_workflow_mutation_facts')).toBe('');
    query(`BEGIN;${forward};INSERT INTO schema_migrations VALUES('043_m11_control_iam_scheduled_identity.sql','x');COMMIT;`);
    expect(columns('control_workflow_mutation_facts')).toBe('execution_origin,schedule_claim_id');
    expect(columns('iam_workflow_mutation_facts')).toBe('execution_origin,schedule_claim_id');
    expect(config('m11_validate_control_mutation_fact')).toBe('search_path=pg_catalog, public, pg_temp');
    expect(config('m11_validate_iam_mutation_fact')).toBe('search_path=pg_catalog, public, pg_temp');
    const bodyC = query(`SELECT prosrc FROM pg_proc WHERE proname='m11_validate_control_mutation_fact';`);
    expect(bodyC).toContain(`NEW.execution_origin='session' AND (NEW.schedule_claim_id IS NOT NULL OR sid.revoked_at IS NOT NULL OR sid.expires_at<=now())`);
    expect(bodyC).toContain('o.claim_id IS DISTINCT FROM NEW.schedule_claim_id');
    const bodyI = query(`SELECT prosrc FROM pg_proc WHERE proname='m11_validate_iam_mutation_fact';`);
    expect(bodyI).toContain(`NEW.execution_origin='session' AND (NEW.schedule_claim_id IS NOT NULL OR sid.revoked_at IS NOT NULL OR sid.expires_at<=now())`);
    expect(bodyI).toContain('origin.claim_id IS DISTINCT FROM NEW.schedule_claim_id');
    expect(fails(`INSERT INTO control_workflow_mutation_facts(execution_origin) VALUES('remote');`)).toMatch(/violates|null value/);
    expect(fails(`INSERT INTO iam_workflow_mutation_facts(execution_origin) VALUES('remote');`)).toMatch(/violates|null value/);
  });

  it('rolls back cleanly, refuses while scheduled evidence exists, and re-applies', () => {
    query(down);
    expect(columns('control_workflow_mutation_facts')).toBe('');
    expect(columns('iam_workflow_mutation_facts')).toBe('');
    expect(query(`SELECT count(*) FROM schema_migrations WHERE name LIKE '043_%';`)).toBe('0');
    query(`BEGIN;${forward};COMMIT;`);
    expect(columns('control_workflow_mutation_facts')).toBe('execution_origin,schedule_claim_id');
    query(`SET session_replication_role=replica;ALTER TABLE control_workflow_mutation_facts DROP CONSTRAINT control_fact_origin_claim;
      INSERT INTO control_workflow_mutation_facts(id,intent_id,workflow_id,execution_id,step_id,cluster_id,workspace_id,actor_id,session_id,plan_revision,plan_hash,before_permission_version,after_permission_version,before_config_hmac,after_config_hmac,result_hmac,result_secret,audit_id,resource,resource_id,operation,before_revision,after_revision,execution_origin)
      VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,repeat('a',64),'x','x',repeat('a',64),repeat('a',64),repeat('a',64),'v1.'||repeat('A',16)||'.'||repeat('B',22)||'.C',gen_random_uuid(),'clusters',gen_random_uuid(),'update',0,1,'scheduled');`);
    expect(fails(down)).toContain('SQL043 rollback refused');
    expect(columns('control_workflow_mutation_facts')).toBe('execution_origin,schedule_claim_id');
  });
});
