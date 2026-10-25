import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';

/** SQL049 apply + rollback on disposable postgres:16-alpine (--network none, never DATABASE_URL). */
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const directory = 'apps/console-api/src/infrastructure/migrations';
const forward = readFileSync(`${directory}/049_m11_configuration_unknown_result.sql`, 'utf8');
const down = readFileSync('deploy/db-rollback/049_m11_configuration_unknown_result.down.sql', 'utf8');

describe('SQL049 configuration_v2 unknown-result disposition', () => {
  const container = `kongos-m11-sql049-${randomUUID().slice(0, 8)}`;
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
    const files = readdirSync(directory).filter(n => /^0(?:[0-3]\d|4[0-8])_.*\.sql$/.test(n)).sort();
    expect(files).toHaveLength(49);
    for (const file of files) query(readFileSync(`${directory}/${file}`, 'utf8'));
  }, 180_000);
  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  // Parent-table CHECKs are dropped in this disposable DB only so the fixture graph stays small;
  // every mutation_operations constraint and trigger under test is left intact.
  const relaxParents = () => query(`DO $r$ DECLARE c record; BEGIN FOR c IN SELECT conrelid::regclass::text t, conname FROM pg_constraint
    WHERE contype='c' AND conrelid::regclass::text IN('configuration_jobs','configuration_executions','configuration_job_steps','configuration_plan_objects')
    LOOP EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', c.t, c.conname); END LOOP; END;$r$;`);
  const apply = () => query(`BEGIN;${forward};INSERT INTO schema_migrations VALUES('049_m11_configuration_unknown_result.sql','x');COMMIT;`);
  // Seeds bypass FK graphs with the replica role; the UPDATE under test runs with every trigger live,
  // including the deferred m8_validate_native_binding over a full approval-mode targets/update graph.
  const seed = (mutation: string, ce: string, we: string, withOrigin: boolean, disposition?: string) => query(`SET session_replication_role=replica;
    DO $seed$ DECLARE c uuid:=gen_random_uuid(); w uuid:=gen_random_uuid(); j uuid:=gen_random_uuid(); pl uuid:=gen_random_uuid(); st uuid:=gen_random_uuid();
      ps uuid:=gen_random_uuid(); wf uuid:=gen_random_uuid(); actor uuid:=gen_random_uuid(); up uuid:=gen_random_uuid(); old uuid:=gen_random_uuid(); fresh uuid:=gen_random_uuid();
    BEGIN
     INSERT INTO configuration_jobs(id,cluster_id,workspace_id,transport_scope,actor_id,authority_expires_at,kind,idempotency_key,request_hmac,scope_kind,permission_version,
       credential_epoch,cluster_revision,workspace_revision,capture_epoch,execution_mode,expires_at)
      VALUES(j,c,w,repeat('d',64),actor,now(),'apply','job-'||j,repeat('a',64),'workspace','1',1,1,1,'e','approval',now());
     INSERT INTO configuration_executions(id,cluster_id,workspace_id,job_id,plan_id,plan_revision,plan_hash,actor_id,execution_mode,claim_hash,permission_version,
       before_snapshot_id,before_snapshot_version,lease_generation,expires_at,workflow_id,state)
      VALUES('${ce}',c,w,j,pl,1,repeat('b',64),actor,'approval',repeat('c',64),'1',gen_random_uuid(),1,1,now(),wf,'uncertain');
     INSERT INTO configuration_job_steps(id,cluster_id,workspace_id,job_id,execution_id,plan_id,plan_revision,plan_hash,plan_step_id,step_order,object_workspace_id,approval_required,before_hmac)
      VALUES(st,c,w,j,'${ce}',pl,1,repeat('b',64),ps,1,w,true,repeat('e',64));
     INSERT INTO configuration_plan_objects(cluster_id,workspace_id,plan_id,plan_revision,plan_hash,step_id,step_order,object_key,entity_type,object_workspace_id,permission_action,
       mutation_action,body_hmac,before_hmac,payload_ciphertext,native_requests,reference_only,masked_diff,native_id,allocated_native_id,parent_id)
      VALUES(c,w,pl,1,repeat('b',64),ps,1,'targets:x','targets',w,'update','update',repeat('f',64),repeat('e',64),'x','[]',false,'{}',old,fresh,up);
     INSERT INTO mutation_operations(id,cluster_id,workspace_id,action,idempotency_key,request_hash,state,remote_started,remote_completed,error_code,entity_type,entity_id,parent_id,
       workflow_id,actor_id,transport_scope,configuration_job_id,configuration_execution_id,configuration_step_id,configuration_plan_revision,configuration_plan_hash)
      VALUES('${mutation}',c,w,'update','k-${mutation}',repeat('a',64),'uncertain',true,false,'LOCK_LOST','targets',old::text,up::text,
       wf,actor,repeat('d',64),j,'${ce}',st,1,repeat('b',64));
    END;$seed$;
    ${withOrigin ? `INSERT INTO workflow_configuration_execution_origins(id,cluster_id,workspace_id,wrapper_origin_id,claim_id,workflow_execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash,
      configuration_execution_id,configuration_job_id,configuration_plan_id,configuration_plan_revision,configuration_plan_hash,workflow_step_id)
      VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'${we}',gen_random_uuid(),2,repeat('a',64),'${ce}',gen_random_uuid(),gen_random_uuid(),1,repeat('b',64),gen_random_uuid());` : ''}
    ${disposition ? `INSERT INTO workflow_unknown_result_dispositions(
        id,cluster_id,workspace_id,schedule_id,claim_id,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,
        actor_id,session_id,credential_epoch,disposition,original_execution_state,evidence_hmac,request_hmac,audit_id,audit_event_hash,observed_at,
        mutation_id,original_mutation_state,original_remote_started,original_remote_completed,original_error_code)
      VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'${we}',2,repeat('a',64),
        gen_random_uuid(),gen_random_uuid(),1,'${disposition}','uncertain',repeat('a',64),repeat('b',64),gen_random_uuid(),repeat('c',64),clock_timestamp(),
        '${mutation}','uncertain',true,false,'LOCK_LOST');` : ''}
    SET session_replication_role=origin;`);

  it('accepts the exact configuration origin link in the validator and keeps search_path pinned', () => {
    apply();
    relaxParents();
    expect(config('m11_validate_unknown_result_disposition')).toBe('search_path=pg_catalog, public, pg_temp');
    expect(config('m11_unknown_result_state_guard')).toBe('search_path=pg_catalog, public, pg_temp');
    const body = query(`SELECT prosrc FROM pg_proc WHERE proname='m11_validate_unknown_result_disposition';`);
    expect(body).toContain('workflow_configuration_execution_origins');
    expect(body).toContain("ce.state='uncertain'");
    expect(body).toContain('nativeRequestsSent');
  });

  it('refuses closing a schedule-origin configuration mutation without its disposition (applied and not-applied)', () => {
    const [m, ce, we] = [randomUUID(), randomUUID(), randomUUID()];
    seed(m, ce, we, true);
    expect(fails(`UPDATE mutation_operations SET state='failed' WHERE id='${m}';`)).toContain('requires its exact unknown-result disposition');
    expect(fails(`UPDATE mutation_operations SET state='succeeded' WHERE id='${m}';`)).toContain('requires its exact unknown-result disposition');
    expect(query(`SELECT state FROM mutation_operations WHERE id='${m}';`)).toBe('uncertain');
  });

  it('closes state-only with the matching disposition and refuses receipt rewrites or wrong outcome', () => {
    const [m, ce, we] = [randomUUID(), randomUUID(), randomUUID()];
    seed(m, ce, we, true, 'verified-not-applied');
    expect(fails(`UPDATE mutation_operations SET state='succeeded' WHERE id='${m}';`)).toContain('requires its exact unknown-result disposition');
    expect(fails(`UPDATE mutation_operations SET state='failed',remote_completed=true WHERE id='${m}';`)).toContain('requires its exact unknown-result disposition');
    query(`UPDATE mutation_operations SET state='failed' WHERE id='${m}';`);
    expect(query(`SELECT state||'|'||remote_started||'|'||remote_completed||'|'||error_code FROM mutation_operations WHERE id='${m}';`)).toBe('failed|true|false|LOCK_LOST');
    const [m2, ce2, we2] = [randomUUID(), randomUUID(), randomUUID()];
    seed(m2, ce2, we2, true, 'verified-applied');
    query(`UPDATE mutation_operations SET state='succeeded' WHERE id='${m2}';`);
    expect(query(`SELECT state FROM mutation_operations WHERE id='${m2}';`)).toBe('succeeded');
  });

  it('leaves non-schedule configuration mutations (no origin link) on their existing paths', () => {
    const [m, ce, we] = [randomUUID(), randomUUID(), randomUUID()];
    seed(m, ce, we, false);
    query(`UPDATE mutation_operations SET state='failed' WHERE id='${m}';`);
    expect(query(`SELECT state FROM mutation_operations WHERE id='${m}';`)).toBe('failed');
  });

  it('rolls back to the SQL044 bodies and re-applies', () => {
    query(down);
    expect(query(`SELECT count(*) FROM schema_migrations WHERE name LIKE '049_%';`)).toBe('0');
    expect(query(`SELECT prosrc FROM pg_proc WHERE proname='m11_validate_unknown_result_disposition';`)).not.toContain('workflow_configuration_execution_origins');
    apply();
    expect(query(`SELECT prosrc FROM pg_proc WHERE proname='m11_validate_unknown_result_disposition';`)).toContain('workflow_configuration_execution_origins');
  });
});
