import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFile, execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { promisify } from 'node:util';

/** SQL041 entity-annotation: real-PostgreSQL proof of the claim/outcome
 * primitives the annotation executor relies on (disposable postgres:16-alpine,
 * --network none, never DATABASE_URL). Fixture rows for the long FK chain are
 * seeded with session_replication_role=replica (superuser, test DB only);
 * every asserted transition runs with role=origin so the SQL026 triggers and
 * all UNIQUE constraints are live; only the deferred whole-chain completeness
 * trigger on progress is disabled (see beforeAll). */
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const run = promisify(execFile);
const directory = 'apps/console-api/src/infrastructure/migrations';
const cid = randomUUID(), wid = randomUUID(), sid = randomUUID(), wfid = randomUUID(), occ = randomUUID(), hash = 'c'.repeat(64);

describe('entity-annotation schedule claim primitives on real PostgreSQL', () => {
  const container = `kongos-m11-annclaim-${randomUUID().slice(0, 8)}`;
  let started = false;
  const psqlArgs = ['exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'];
  const query = (sql: string): string => execFileSync('docker', [...base, ...psqlArgs], { env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  const queryAsync = async (sql: string): Promise<{ ok: boolean; err: string }> => {
    const child = run('docker', [...base, ...psqlArgs], { env: dockerEnv, encoding: 'utf8' });
    child.child.stdin!.end(sql);
    try { await child; return { ok: true, err: '' }; } catch (e) { return { ok: false, err: String((e as { stderr?: string }).stderr ?? e) }; }
  };
  const claimSql = (claimId: string, holdSeconds: number) => `BEGIN;
    SET LOCAL session_replication_role=replica;
    INSERT INTO workflow_schedule_claims(id,cluster_id,workspace_id,schedule_id,occurrence_id,generation,worker_owner_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,issued_at,authority_expires_at,initial_lease_until,claim)
     VALUES('${claimId}','${cid}','${wid}','${sid}','${occ}',1,'${'d'.repeat(64)}','${wfid}',1,'${hash}',now(),now()+interval '4 minutes',now()+interval '1 minute',
     jsonb_build_object('id','${claimId}','scheduleId','${sid}','scheduleVersion',1,'occurrenceId','${occ}','generation',1,'workerOwnerHmac','${'d'.repeat(64)}','workflowId','${wfid}','workflowPlanRevision',1,'workflowPlanHash','${hash}',
      'issuedAt',to_jsonb(now()),'authorityExpiresAt',to_jsonb(now()+interval '4 minutes'),'initialLeaseUntil',to_jsonb(now()+interval '1 minute')));
    SET LOCAL session_replication_role=origin;
    UPDATE workflow_schedule_progress SET state='claimed',claim_id='${claimId}',revision=revision+1,updated_at=now() WHERE schedule_id='${sid}' AND state='active';
    SELECT pg_sleep(${holdSeconds});
    COMMIT;`;

  beforeAll(async () => {
    if (!existsSync('/var/run/docker.sock')) throw new Error('Disposable SQL tests require the local Docker socket');
    execFileSync('docker', [...base, 'run', '-d', '--name', container, '--network', 'none', '--tmpfs', '/tmp/sql-data:rw,size=256m,mode=1777',
      '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'PGDATA=/tmp/sql-data/pgdata', 'postgres:16-alpine'], { env: dockerEnv, stdio: 'pipe' });
    started = true;
    for (let i = 0; i < 100; i++) {
      try { query('SELECT 1;'); break; }
      catch { if (i === 99) throw new Error('Disposable PostgreSQL unavailable'); await new Promise(r => setTimeout(r, 100)); }
    }
    const files = readdirSync(directory).filter(n => /^0(?:[0-3]\d|4[01])_.*\.sql$/.test(n)).sort();
    expect(files).toHaveLength(42);
    for (const file of files) query(readFileSync(`${directory}/${file}`, 'utf8'));
    // The deferred whole-chain completeness trigger (m11_business_storage_complete) needs the full
    // schedule/approval/lease chain; it is covered by the SQL026 suites. Only for this disposable DB
    // it is disabled on progress so the per-row state machine and UNIQUE claim guards can be isolated.
    query(`ALTER TABLE workflow_schedule_progress DISABLE TRIGGER workflow_schedule_progress_complete;`);
    query(`SET session_replication_role=replica;
      INSERT INTO workflow_schedule_progress(schedule_id,cluster_id,workspace_id,state,revision) VALUES('${sid}','${cid}','${wid}','active',2);`);
  }, 180_000);
  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  it('concurrent double claim: exactly one claim and one claimed progress survive', async () => {
    const a = randomUUID(), b = randomUUID();
    const [ra, rb] = await Promise.all([queryAsync(claimSql(a, 1.5)), new Promise(r => setTimeout(r, 300)).then(() => queryAsync(claimSql(b, 0)))]);
    expect([ra.ok, rb.ok].filter(Boolean)).toHaveLength(1);
    expect(ra.ok ? rb.err : ra.err).toMatch(/duplicate key value violates unique constraint/);
    expect(query(`SELECT count(*) FROM workflow_schedule_claims WHERE schedule_id='${sid}';`)).toBe('1');
    expect(query(`SELECT state||':'||(claim_id=${ra.ok ? `'${a}'` : `'${b}'`})::text FROM workflow_schedule_progress WHERE schedule_id='${sid}';`)).toBe('claimed:true');
  }, 60_000);

  it('a claimed occurrence cannot be reset to active or blocked', () => {
    for (const state of ['active', 'blocked'])
      expect(() => query(`UPDATE workflow_schedule_progress SET state='${state}',claim_id=NULL,revision=revision+1 WHERE schedule_id='${sid}';`)).toThrow();
    expect(() => query(`UPDATE workflow_schedule_progress SET state='blocked',revision=revision+1 WHERE schedule_id='${sid}';`)).toThrow();
  });

  it('a recheck rejection lands as terminal failed with the reason code, and terminal is final', () => {
    query(`UPDATE workflow_schedule_progress SET state='failed',reason_code='ANNOTATION_SCHEDULE_PERMISSION_REVOKED',revision=revision+1,updated_at=clock_timestamp() WHERE schedule_id='${sid}';`);
    expect(query(`SELECT state||':'||reason_code FROM workflow_schedule_progress WHERE schedule_id='${sid}';`)).toBe('failed:ANNOTATION_SCHEDULE_PERMISSION_REVOKED');
    for (const state of ['running', 'succeeded', 'active'])
      expect(() => query(`UPDATE workflow_schedule_progress SET state='${state}',revision=revision+1 WHERE schedule_id='${sid}';`)).toThrow();
    expect(() => query(`DELETE FROM workflow_schedule_progress WHERE schedule_id='${sid}';`)).toThrow();
  });
});
