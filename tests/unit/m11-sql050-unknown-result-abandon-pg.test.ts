import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';

/** SQL050 apply + rollback on disposable postgres:16-alpine (--network none, never DATABASE_URL). */
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const directory = 'apps/console-api/src/infrastructure/migrations';
const forward = readFileSync(`${directory}/050_m11_unknown_result_abandon.sql`, 'utf8');
const down = readFileSync('deploy/db-rollback/050_m11_unknown_result_abandon.down.sql', 'utf8');

describe('SQL050 two-person abandoned disposition', () => {
  const container = `kongos-m11-sql050-${randomUUID().slice(0, 8)}`;
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
    const files = readdirSync(directory).filter(n => /^0(?:[0-3]\d|4[0-9])_.*\.sql$/.test(n)).sort();
    expect(files).toHaveLength(50);
    for (const file of files) query(readFileSync(`${directory}/${file}`, 'utf8'));
  }, 180_000);
  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  // Parent-table CHECKs are dropped in this disposable DB only so the fixture graph stays small;
  // every mutation_operations constraint and trigger under test is left intact.
  const relaxParents = () => query(`DO $r$ DECLARE c record; BEGIN FOR c IN SELECT conrelid::regclass::text t, conname FROM pg_constraint
    WHERE contype='c' AND conrelid::regclass::text IN('configuration_jobs','configuration_executions','configuration_job_steps','configuration_plan_objects')
    LOOP EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', c.t, c.conname); END LOOP; END;$r$;`);
  const apply = () => query(`BEGIN;${forward};INSERT INTO schema_migrations VALUES('050_m11_unknown_result_abandon.sql','x');COMMIT;`);
  // Seeds bypass FK graphs with the replica role; the UPDATE under test runs with every trigger live,
  // including the deferred m8_validate_native_binding over a full approval-mode targets/update graph.
  const seed = (mutation: string, ce: string, we: string, withOrigin: boolean, disposition?: string, request?: string) => query(`SET session_replication_role=replica;
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
        mutation_id,original_mutation_state,original_remote_started,original_remote_completed,original_error_code,abandon_request_id)
      VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'${we}',2,repeat('a',64),
        gen_random_uuid(),gen_random_uuid(),1,'${disposition}','uncertain',repeat('a',64),repeat('b',64),gen_random_uuid(),repeat('c',64),clock_timestamp(),
        '${mutation}','uncertain',true,false,'LOCK_LOST',${request ? `'${request}'` : 'NULL'});` : ''}
    SET session_replication_role=origin;`);

  const request = (id: string, mutation: string, we: string) => query(`SET session_replication_role=replica;
    INSERT INTO workflow_unknown_result_abandon_requests(id,cluster_id,workspace_id,mutation_id,workflow_execution_id,requester_id,session_id,reason_hmac,ticket,observation_hmac,audit_id,audit_event_hash,expires_at)
     VALUES('${id}',gen_random_uuid(),gen_random_uuid(),'${mutation}','${we}',gen_random_uuid(),gen_random_uuid(),repeat('a',64),'OPS-1',repeat('b',64),gen_random_uuid(),repeat('c',64),clock_timestamp()+interval '1 hour');
    SET session_replication_role=origin;`);

  it('adds abandoned with a mandatory request binding and closing uniqueness', () => {
    apply();
    relaxParents();
    expect(query(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='workflow_unknown_result_dispositions_disposition_check'`)).toContain('abandoned');
    expect(query(`SELECT indexdef FROM pg_indexes WHERE indexname='workflow_unknown_result_closing_claim'`)).toContain('abandoned');
    const body = query(`SELECT prosrc FROM pg_proc WHERE proname='m11_validate_unknown_result_disposition';`);
    expect(body).toContain('r.requester_id=p_row.actor_id');
    expect(body).toContain('workflow_configuration_execution_origins');
    expect(config('m11_unknown_result_abandon_request_guard')).toBe('search_path=pg_catalog, public, pg_temp');
    const [m, ce, we] = [randomUUID(), randomUUID(), randomUUID()];
    expect(fails(`SET session_replication_role=replica;INSERT INTO workflow_unknown_result_dispositions(
        id,cluster_id,workspace_id,schedule_id,claim_id,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,
        actor_id,session_id,credential_epoch,disposition,original_execution_state,evidence_hmac,request_hmac,audit_id,audit_event_hash,observed_at,
        mutation_id,original_mutation_state,original_remote_started,original_remote_completed,original_error_code)
      VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'${we}',2,repeat('a',64),
        gen_random_uuid(),gen_random_uuid(),1,'abandoned','uncertain',repeat('a',64),repeat('b',64),gen_random_uuid(),repeat('c',64),clock_timestamp(),
        '${m}','uncertain',true,false,'LOCK_LOST');`)).toContain('workflow_unknown_result_abandon_binding');
    query('SET session_replication_role=origin;');
  });

  it('abandon requests: refused for non-uncertain/unlinked mutations; immutable except one-shot consumption', () => {
    expect(fails(`INSERT INTO workflow_unknown_result_abandon_requests(id,cluster_id,workspace_id,mutation_id,workflow_execution_id,requester_id,session_id,reason_hmac,ticket,observation_hmac,audit_id,audit_event_hash,expires_at)
      VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),repeat('a',64),'T',repeat('b',64),gen_random_uuid(),repeat('c',64),clock_timestamp()+interval '1 hour');`))
      .toContain('Abandon request requires an uncertain configuration-origin mutation');
    const [r, m, we] = [randomUUID(), randomUUID(), randomUUID()];
    request(r, m, we);
    expect(fails(`UPDATE workflow_unknown_result_abandon_requests SET ticket='X' WHERE id='${r}';`)).toContain('immutable');
    expect(fails(`DELETE FROM workflow_unknown_result_abandon_requests WHERE id='${r}';`)).toContain('immutable');
    query(`UPDATE workflow_unknown_result_abandon_requests SET consumed_at=clock_timestamp() WHERE id='${r}';`);
    expect(fails(`UPDATE workflow_unknown_result_abandon_requests SET consumed_at=clock_timestamp() WHERE id='${r}';`)).toContain('immutable');
  });

  it('abandoned closes a configuration mutation as failed only (state-only, m8 trigger live)', () => {
    const [m, ce, we, r] = [randomUUID(), randomUUID(), randomUUID(), randomUUID()];
    request(r, m, we);
    seed(m, ce, we, true, 'abandoned', r);
    expect(fails(`UPDATE mutation_operations SET state='succeeded' WHERE id='${m}';`)).toContain('requires its exact unknown-result disposition');
    query(`UPDATE mutation_operations SET state='failed',safe_result='{"outcome":"failed-unknown"}' WHERE id='${m}';`);
    expect(query(`SELECT state||'|'||remote_completed||'|'||(safe_result->>'outcome') FROM mutation_operations WHERE id='${m}';`)).toBe('failed|false|failed-unknown');
  });

  it('rollback refuses while abandon evidence exists, then restores SQL049 and re-applies', () => {
    expect(fails(down)).toContain('SQL050 rollback refused');
    query(`SET session_replication_role=replica;DELETE FROM workflow_unknown_result_dispositions;DELETE FROM workflow_unknown_result_abandon_requests;SET session_replication_role=origin;`);
    query(down);
    expect(query(`SELECT to_regclass('public.workflow_unknown_result_abandon_requests') IS NULL`)).toBe('t');
    expect(query(`SELECT prosrc FROM pg_proc WHERE proname='m11_validate_unknown_result_disposition';`)).toContain('workflow_configuration_execution_origins');
    expect(query(`SELECT prosrc FROM pg_proc WHERE proname='m11_validate_unknown_result_disposition';`)).not.toContain('abandon');
    apply();
    expect(query(`SELECT to_regclass('public.workflow_unknown_result_abandon_requests') IS NOT NULL`)).toBe('t');
  });
});
