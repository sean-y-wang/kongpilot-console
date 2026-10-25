import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { loadEntityAnnotationScheduleFacts } from '../../apps/console-api/src/modules/workflows/entity-annotation-schedule.facts';
import { assertEntityAnnotationExecution } from '../../apps/console-api/src/modules/workflows/entity-annotation-schedule.guard';

/** SQL041/042: full approval-chain write-time recheck against real PostgreSQL.
 * Seeds the subject/request/owner/iam facts the scheduled executor reads, then
 * runs loadEntityAnnotationScheduleFacts + assertEntityAnnotationExecution.
 * Negative cases: expired window, disabled user, permission version change,
 * credential epoch change, tampered subject seal, revoked annotation write.
 * Double-claim uniqueness is covered by m11-entity-annotation-schedule-claim-pg. */
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const directory = 'apps/console-api/src/infrastructure/migrations';
const key = Buffer.from('6f'.repeat(32), 'hex');
const fp = (value: unknown): string => createHmac('sha256', key).update(JSON.stringify(value)).digest('hex');
const hex = (n = 64) => 'a'.repeat(n);

describe('entity-annotation scheduled approval-chain E2E on real PostgreSQL', () => {
  const container = `kongos-m11-annchain-${randomUUID().slice(0, 8)}`;
  let started = false;
  const owner = randomUUID(), cid = randomUUID(), wid = randomUUID(), wf = randomUUID(), subject = randomUUID(), sid = randomUUID();
  const materialHmac = hex();
  const nativeManifestHmac = fp({ version: 1, origin: 'workflow-scheduled-entity-annotation', workflowId: wf });
  const subjectSeal = { version: 1 as const, driver: 'entity-annotation' as const, subjectId: subject, materialHmac, nativeManifestHmac, sourceScopes: [] as const };
  const subjectSealHmac = fp(subjectSeal);
  const seal = (m: { subjectId: string; materialHmac: string; workflowId: string }) =>
    fp({ version: 1, driver: 'entity-annotation', subjectId: m.subjectId, materialHmac: m.materialHmac,
      nativeManifestHmac: fp({ version: 1, origin: 'workflow-scheduled-entity-annotation', workflowId: m.workflowId }), sourceScopes: [] });
  const now = Date.now();
  const iso = (deltaMs: number) => new Date(now + deltaMs).toISOString();
  const psql = ['exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'];
  const query = (sql: string): string => execFileSync('docker', [...base, ...psql], { env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  const sqlPort = {
    async one<T>(sqlText: string, params: readonly unknown[]): Promise<T | null> {
      // Map $1..$n to literal SQL for the disposable psql driver (test-only).
      let text = sqlText;
      params.forEach((v, i) => {
        const lit = v === null || v === undefined ? 'NULL' : typeof v === 'number' ? String(v) : `'${String(v).replace(/'/g, "''")}'`;
        text = text.replace(new RegExp(`\\$${i + 1}(?!\\d)`, 'g'), lit);
      });
      const marker = '__ROW__';
      const out = query(`SELECT COALESCE(row_to_json(q)::text,'${marker}') FROM (${text}) q;`);
      if (!out || out === marker) return null;
      return JSON.parse(out) as T;
    },
  };
  const stored = (o: { windowEnd?: string; expiresAt?: string; seal?: string; epoch?: string } = {}) => ({
    draft: {
      binding: { clusterId: cid, workspaceId: wid, workflowId: wf, kind: 'entity-annotation', subjectType: 'entity_annotation_requests', subjectId: subject,
        requester: { type: 'console', id: owner, credentialEpoch: o.epoch ?? '7' } },
      delegation: { kind: 'entity-annotation', subjectType: 'entity_annotation_requests', subjectId: subject, ownerId: owner,
        ownerCredentialEpoch: o.epoch ?? '7', subjectSealHmac: o.seal ?? subjectSealHmac, expiresAt: o.expiresAt ?? iso(3_600_000) },
      spec: { windowStart: iso(-3_600_000), notBefore: iso(-60_000), windowEnd: o.windowEnd ?? iso(3_600_000) },
    },
    plan: { kind: 'entity-annotation', executionMode: 'approval', approvalRequired: true },
  }) as never;

  const run = async (opts: {
    write?: boolean; sealed?: string; windowEnd?: string; expiresAt?: string; sealHmac?: string; epoch?: string; at?: number;
  } = {}) => {
    const facts = await loadEntityAnnotationScheduleFacts(sqlPort, {
      stored: stored({ windowEnd: opts.windowEnd, expiresAt: opts.expiresAt, seal: opts.sealHmac, epoch: opts.epoch }),
      sealedPermissionVersion: opts.sealed ?? `${owner}:3:294`,
      hasAnnotationWrite: async () => opts.write ?? true,
      seal,
    });
    try {
      assertEntityAnnotationExecution({ ...facts, claim: { state: 'claimed', attempt: 1 } }, opts.at ?? now);
      return 'ok';
    } catch (e) { return (e as { code: string }).code; }
  };

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
    expect(files.length).toBeGreaterThanOrEqual(42);
    for (const file of files) query(readFileSync(`${directory}/${file}`, 'utf8'));
    // Seed owner + iam + annotation request (replica role: test DB only; FK graph not under test here).
    query(`SET session_replication_role=replica;
      INSERT INTO iam_epoch(singleton,version) VALUES(true,294) ON CONFLICT (singleton) DO UPDATE SET version=294;
      INSERT INTO users(id,username,password_hash,status,super_admin,force_password_change,credential_epoch,permissions_epoch,revision,display_name,locale,timezone)
       VALUES('${owner}','ann-chain','x','active',false,false,7,3,1,'Ann','en-US','UTC')
       ON CONFLICT (id) DO UPDATE SET status='active',deleted_at=NULL,force_password_change=false,credential_epoch=7,permissions_epoch=3;
      INSERT INTO entity_annotation_requests(id,cluster_id,workspace_id,actor_id,workflow_id,idempotency_key,submit_key,request_hmac,material_hmac)
       VALUES('${subject}','${cid}','${wid}','${owner}','${wf}','k1','s1','${hex()}','${materialHmac}');`);
  }, 180_000);
  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  it('positive: current SQL facts + matching seal pass the write-time recheck', async () => {
    expect(seal({ subjectId: subject, materialHmac, workflowId: wf })).toBe(subjectSealHmac);
    expect(await run()).toBe('ok');
  }, 30_000);

  it('expired window is rejected', async () => {
    expect(await run({ windowEnd: iso(-1_000), at: now })).toBe('ANNOTATION_SCHEDULE_EXPIRED');
  });

  it('disabled / deleted / force-password user is rejected', async () => {
    query(`UPDATE users SET status='disabled' WHERE id='${owner}';`);
    expect(await run()).toBe('ANNOTATION_SCHEDULE_REQUESTER_INACTIVE');
    query(`UPDATE users SET status='deleted',deleted_at=now(),retention_until=now()+interval '30 days' WHERE id='${owner}';`);
    expect(await run()).toBe('ANNOTATION_SCHEDULE_REQUESTER_INACTIVE');
    query(`UPDATE users SET status='active',deleted_at=NULL,retention_until=NULL,force_password_change=true WHERE id='${owner}';`);
    expect(await run()).toBe('ANNOTATION_SCHEDULE_REQUESTER_INACTIVE');
    query(`UPDATE users SET force_password_change=false WHERE id='${owner}';`);
  });

  it('credential epoch change is rejected', async () => {
    query(`UPDATE users SET credential_epoch=8 WHERE id='${owner}';`);
    expect(await run()).toBe('ANNOTATION_SCHEDULE_EPOCH_CHANGED');
    query(`UPDATE users SET credential_epoch=7 WHERE id='${owner}';`);
  });

  it('permission / iam version change is rejected', async () => {
    query(`UPDATE users SET permissions_epoch=4 WHERE id='${owner}';`);
    expect(await run()).toBe('ANNOTATION_SCHEDULE_PERMISSION_CHANGED');
    query(`UPDATE users SET permissions_epoch=3 WHERE id='${owner}';`);
    query(`UPDATE iam_epoch SET version=295 WHERE singleton=true;`);
    expect(await run()).toBe('ANNOTATION_SCHEDULE_PERMISSION_CHANGED');
    query(`UPDATE iam_epoch SET version=294 WHERE singleton=true;`);
  });

  it('tampered subject seal is rejected', async () => {
    expect(await run({ sealHmac: 'b'.repeat(64) })).toBe('ANNOTATION_SCHEDULE_SUBJECT_CHANGED');
    // request rows are append-only; swap material under replica role (test DB only) to prove re-seal mismatch.
    query(`SET session_replication_role=replica;
      UPDATE entity_annotation_requests SET material_hmac='${'c'.repeat(64)}' WHERE id='${subject}';
      SET session_replication_role=origin;`);
    expect(await run()).toBe('ANNOTATION_SCHEDULE_SUBJECT_CHANGED');
    query(`SET session_replication_role=replica;
      UPDATE entity_annotation_requests SET material_hmac='${materialHmac}' WHERE id='${subject}';
      SET session_replication_role=origin;`);
  });

  it('revoked annotation write is rejected', async () => {
    expect(await run({ write: false })).toBe('ANNOTATION_SCHEDULE_PERMISSION_REVOKED');
  });

  it('double-claim uniqueness still holds on the same schedule (SQL026)', () => {
    const a = randomUUID(), b = randomUUID(), occ = randomUUID(), hash = hex();
    query(`ALTER TABLE workflow_schedule_progress DISABLE TRIGGER workflow_schedule_progress_complete;
      SET session_replication_role=replica;
      INSERT INTO workflow_schedule_progress(schedule_id,cluster_id,workspace_id,state,revision)
       VALUES('${sid}','${cid}','${wid}','active',1) ON CONFLICT DO NOTHING;`);
    const claim = (id: string) => `BEGIN;
      SET LOCAL session_replication_role=replica;
      INSERT INTO workflow_schedule_claims(id,cluster_id,workspace_id,schedule_id,occurrence_id,generation,worker_owner_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,issued_at,authority_expires_at,initial_lease_until,claim)
       VALUES('${id}','${cid}','${wid}','${sid}','${occ}',1,'${hex()}','${wf}',1,'${hash}',now(),now()+interval '4 minutes',now()+interval '1 minute',
       jsonb_build_object('id','${id}','scheduleId','${sid}','scheduleVersion',1,'occurrenceId','${occ}','generation',1,'workerOwnerHmac','${hex()}','workflowId','${wf}',
        'workflowPlanRevision',1,'workflowPlanHash','${hash}','issuedAt',to_jsonb(now()),'authorityExpiresAt',to_jsonb(now()+interval '4 minutes'),'initialLeaseUntil',to_jsonb(now()+interval '1 minute')));
      SET LOCAL session_replication_role=origin;
      UPDATE workflow_schedule_progress SET state='claimed',claim_id='${id}',revision=revision+1 WHERE schedule_id='${sid}' AND state='active';
      COMMIT;`;
    let firstOk = false, secondErr = '';
    try { query(claim(a)); firstOk = true; } catch (e) { secondErr = String(e); }
    try { query(claim(b)); if (firstOk) throw new Error('second claim should fail'); }
    catch (e) { secondErr = String((e as { stderr?: string }).stderr ?? e); }
    expect(firstOk).toBe(true);
    expect(secondErr).toMatch(/duplicate key|unique constraint/i);
    expect(query(`SELECT count(*) FROM workflow_schedule_claims WHERE schedule_id='${sid}';`)).toBe('1');
  });
});
