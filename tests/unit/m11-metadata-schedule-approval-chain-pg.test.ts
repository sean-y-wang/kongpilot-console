import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { loadMetadataScheduleFacts } from '../../apps/console-api/src/modules/workflows/metadata-schedule.facts';
import { assertMetadataScheduleExecution } from '../../apps/console-api/src/modules/workflows/metadata-schedule.guard';
import { METADATA_SUBJECT_SEAL_SOURCE } from '../../apps/console-api/src/modules/workflows/metadata-schedule.registry';

/** SQL041 remaining 8 metadata kinds: approval-chain write-time recheck on real PG.
 * Positive path for each kind; negatives shared on control-metadata (request) and
 * config_snapshots (entity). Mirrors m11-entity-annotation-schedule-approval-chain-pg. */
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];
const directory = 'apps/console-api/src/infrastructure/migrations';
const key = Buffer.from('6f'.repeat(32), 'hex');
const fp = (value: unknown): string => createHmac('sha256', key).update(JSON.stringify(value)).digest('hex');
const hex = (n = 64) => 'a'.repeat(n);
const enc = 'v1.abcdefghijklmnop.ABCDEFGHIJKLMNOPQRSTUV.ciphertext';
const bcrypt = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

const KIND_CASES = [
  { kind: 'control-metadata', subjectType: 'control_metadata_requests' },
  { kind: 'iam-metadata', subjectType: 'iam_metadata_requests' },
  { kind: 'governance-metadata', subjectType: 'governance_metadata_requests' },
  { kind: 'workflow-policy-metadata', subjectType: 'workflow_policy_requests' },
  { kind: 'configuration-metadata', subjectType: 'config_snapshots' },
  { kind: 'portal-metadata', subjectType: 'portal_settings' },
  { kind: 'portal-developer-review', subjectType: 'portal_developers' },
  { kind: 'event-metadata', subjectType: 'notification_channels' },
] as const;

describe('metadata scheduled approval-chain E2E on real PostgreSQL (8 kinds)', () => {
  const container = `kongos-m11-metachain-${randomUUID().slice(0, 8)}`;
  let started = false;
  const owner = randomUUID(), cid = randomUUID(), wid = randomUUID();
  const materialHmac = hex();
  const now = Date.now();
  const iso = (deltaMs: number) => new Date(now + deltaMs).toISOString();
  const psql = ['exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'];
  const query = (sql: string): string => execFileSync('docker', [...base, ...psql], { env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  const sqlPort = {
    async one<T>(sqlText: string, params: readonly unknown[]): Promise<T | null> {
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

  const sealFor = (kind: string, subjectId: string, wf: string, hmac: string) =>
    fp({ version: 1, driver: kind, subjectId, materialHmac: hmac,
      nativeManifestHmac: fp({ version: 1, origin: `workflow-scheduled-${kind}`, workflowId: wf }), sourceScopes: [] });

  const entityMaterialHmac = (row: Readonly<Record<string, unknown>>) =>
    fp({ id: row.id, revision: row.revision, clusterId: row.cluster_id, workspaceId: row.workspace_id });

  const seedSubject = (kind: string, subjectType: string, subjectId: string, wf: string) => {
    const src = METADATA_SUBJECT_SEAL_SOURCE[subjectType];
    if (!src) throw new Error(`missing seal source ${subjectType}`);
    if (src.style === 'request') {
      if (subjectType === 'governance_metadata_requests') {
        query(`SET session_replication_role=replica;
          INSERT INTO governance_metadata_requests(id,cluster_id,workspace_id,actor_id,resource_type,resource_id,operation,idempotency_key,request_hmac,payload_secret,payload_hmac,before_hmac,scope_secret,workflow_id)
           VALUES('${subjectId}','${cid}','${wid}','${owner}','governance_rules','${randomUUID()}','create','k-${subjectId.slice(0,8)}','${hex()}','${enc}','${materialHmac}','${hex()}','${enc}','${wf}');
          SET session_replication_role=origin;`);
      } else if (subjectType === 'workflow_policy_requests') {
        query(`SET session_replication_role=replica;
          INSERT INTO workflow_policy_requests(id,cluster_id,workspace_id,actor_id,definition_id,operation,workflow_id,idempotency_key,request_hmac,material_hmac,payload_secret)
           VALUES('${subjectId}','${cid}','${wid}','${owner}','${randomUUID()}','version','${wf}','k-${subjectId.slice(0,8)}','${hex()}','${materialHmac}','${enc}');
          SET session_replication_role=origin;`);
      } else if (subjectType === 'control_metadata_requests') {
        query(`SET session_replication_role=replica;
          INSERT INTO control_metadata_requests(id,cluster_id,workspace_id,actor_id,workflow_id,idempotency_key,submit_key,request_hmac,material_hmac)
           VALUES('${subjectId}','${cid}','${wid}','${owner}','${wf}','k-${subjectId.slice(0,8)}','s-${subjectId.slice(0,8)}','${hex()}','${materialHmac}');
          SET session_replication_role=origin;`);
      } else if (subjectType === 'iam_metadata_requests') {
        query(`SET session_replication_role=replica;
          INSERT INTO iam_metadata_requests(id,cluster_id,workspace_id,actor_id,workflow_id,idempotency_key,request_hmac,material_hmac)
           VALUES('${subjectId}','${cid}','${wid}','${owner}','${wf}','k-${subjectId.slice(0,8)}','${hex()}','${materialHmac}');
          SET session_replication_role=origin;`);
      }
    } else if (subjectType === 'config_snapshots') {
      query(`SET session_replication_role=replica;
        INSERT INTO config_snapshots(id,cluster_id,workspace_id,transport_scope,created_by,name,scope_kind,revision,state)
         VALUES('${subjectId}','${cid}','${wid}','${hex()}','${owner}','snap-${subjectId.slice(0,8)}','workspace',1,'ready');
        SET session_replication_role=origin;`);
    } else if (subjectType === 'portal_settings') {
      query(`SET session_replication_role=replica;
        INSERT INTO portal_settings(id,cluster_id,workspace_id,slug,name,revision,status)
         VALUES('${subjectId}','${cid}','${wid}','slug-${subjectId.slice(0,8)}','Portal',1,'active');
        SET session_replication_role=origin;`);
    } else if (subjectType === 'portal_developers') {
      query(`SET session_replication_role=replica;
        INSERT INTO portal_developers(id,cluster_id,workspace_id,username,email,display_name,password_hash,status,credential_epoch,revision)
         VALUES('${subjectId}','${cid}','${wid}','dev${subjectId.slice(0,8)}','dev${subjectId.slice(0,8)}@example.com','Dev','${bcrypt}','active',1,1);
        SET session_replication_role=origin;`);
    } else if (subjectType === 'notification_channels') {
      query(`SET session_replication_role=replica;
        INSERT INTO notification_channels(id,cluster_id,workspace_id,name,type,status,revision,created_by,updated_by,endpoint_secret)
         VALUES('${subjectId}','${cid}','${wid}','ch-${subjectId.slice(0,8)}','webhook','pending',1,'${owner}','${owner}',NULL);
        SET session_replication_role=origin;`);
    } else throw new Error(`unsupported seed ${subjectType}`);
    void kind;
  };

  const run = async (opts: {
    kind: string; subjectType: string; subjectId: string; wf: string;
    write?: boolean; sealed?: string; windowStart?: string; notBefore?: string; windowEnd?: string; expiresAt?: string; sealHmac?: string; epoch?: string; at?: number; attempt?: number;
  }) => {
    const src = METADATA_SUBJECT_SEAL_SOURCE[opts.subjectType]!;
    const hmac = src.style === 'entity'
      ? entityMaterialHmac({ id: opts.subjectId, revision: 1, cluster_id: cid, workspace_id: wid })
      : materialHmac;
    const sealHmac = opts.sealHmac ?? sealFor(opts.kind, opts.subjectId, opts.wf, hmac);
    const stored = {
      draft: {
        binding: { clusterId: cid, workspaceId: wid, workflowId: opts.wf, kind: opts.kind, subjectType: opts.subjectType, subjectId: opts.subjectId,
          requester: { type: 'console', id: owner, credentialEpoch: opts.epoch ?? '7' } },
        delegation: { kind: opts.kind, subjectType: opts.subjectType, subjectId: opts.subjectId, ownerId: owner,
          ownerCredentialEpoch: opts.epoch ?? '7', subjectSealHmac: sealHmac, expiresAt: opts.expiresAt ?? iso(3_600_000) },
        spec: { windowStart: opts.windowStart ?? iso(-3_600_000), notBefore: opts.notBefore ?? iso(-60_000), windowEnd: opts.windowEnd ?? iso(3_600_000) },
      },
      plan: { kind: opts.kind, executionMode: 'approval', approvalRequired: true },
    } as never;
    const facts = await loadMetadataScheduleFacts(sqlPort, {
      stored,
      sealedPermissionVersion: opts.sealed ?? `${owner}:3:294`,
      hasDomainWrite: async () => opts.write ?? true,
      seal: (m) => sealFor(opts.kind, m.subjectId, m.workflowId, m.materialHmac),
      entityMaterialHmac: src.style === 'entity' ? entityMaterialHmac : undefined,
    });
    try {
      assertMetadataScheduleExecution({ ...facts, claim: { state: 'claimed', attempt: opts.attempt ?? 1 } }, opts.at ?? now);
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
    query(`SET session_replication_role=replica;
      INSERT INTO iam_epoch(singleton,version) VALUES(true,294) ON CONFLICT (singleton) DO UPDATE SET version=294;
      INSERT INTO users(id,username,password_hash,status,super_admin,force_password_change,credential_epoch,permissions_epoch,revision,display_name,locale,timezone)
       VALUES('${owner}','meta-chain','x','active',false,false,7,3,1,'Meta','en-US','UTC')
       ON CONFLICT (id) DO UPDATE SET status='active',deleted_at=NULL,force_password_change=false,credential_epoch=7,permissions_epoch=3;
      SET session_replication_role=origin;`);
    for (const c of KIND_CASES) {
      const subjectId = randomUUID(), wf = randomUUID();
      (c as { subjectId?: string; wf?: string }).subjectId = subjectId;
      (c as { subjectId?: string; wf?: string }).wf = wf;
      seedSubject(c.kind, c.subjectType, subjectId, wf);
    }
  }, 180_000);
  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  it.each(KIND_CASES)('positive: $kind / $subjectType', async (c) => {
    const subjectId = (c as { subjectId: string }).subjectId;
    const wf = (c as { wf: string }).wf;
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId, wf })).toBe('ok');
  }, 30_000);

  it('negatives on control-metadata (request-style)', async () => {
    const c = KIND_CASES[0] as typeof KIND_CASES[0] & { subjectId: string; wf: string };
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId: c.subjectId, wf: c.wf, windowEnd: iso(-1_000) })).toBe('METADATA_SCHEDULE_EXPIRED');
    query(`UPDATE users SET status='disabled' WHERE id='${owner}';`);
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId: c.subjectId, wf: c.wf })).toBe('METADATA_SCHEDULE_REQUESTER_INACTIVE');
    query(`UPDATE users SET status='active',force_password_change=false,deleted_at=NULL,retention_until=NULL WHERE id='${owner}';`);
    query(`UPDATE users SET credential_epoch=8 WHERE id='${owner}';`);
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId: c.subjectId, wf: c.wf })).toBe('METADATA_SCHEDULE_EPOCH_CHANGED');
    query(`UPDATE users SET credential_epoch=7 WHERE id='${owner}';`);
    query(`UPDATE users SET permissions_epoch=4 WHERE id='${owner}';`);
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId: c.subjectId, wf: c.wf })).toBe('METADATA_SCHEDULE_PERMISSION_CHANGED');
    query(`UPDATE users SET permissions_epoch=3 WHERE id='${owner}';`);
    // users_iam_epoch bumps iam_epoch on permissions_epoch UPDATE; pin it back for later cases.
    query(`UPDATE iam_epoch SET version=294 WHERE singleton=true;`);
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId: c.subjectId, wf: c.wf, sealHmac: 'b'.repeat(64) })).toBe('METADATA_SCHEDULE_SUBJECT_CHANGED');
    query(`SET session_replication_role=replica;
      UPDATE control_metadata_requests SET material_hmac='${'c'.repeat(64)}' WHERE id='${c.subjectId}';
      SET session_replication_role=origin;`);
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId: c.subjectId, wf: c.wf })).toBe('METADATA_SCHEDULE_SUBJECT_CHANGED');
    query(`SET session_replication_role=replica;
      UPDATE control_metadata_requests SET material_hmac='${materialHmac}' WHERE id='${c.subjectId}';
      SET session_replication_role=origin;`);
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId: c.subjectId, wf: c.wf, write: false })).toBe('METADATA_SCHEDULE_PERMISSION_REVOKED');
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId: c.subjectId, wf: c.wf })).toBe('ok');
  }, 60_000);

  it('negatives on configuration-metadata entity seal drift', async () => {
    const c = KIND_CASES.find(x => x.kind === 'configuration-metadata')! as typeof KIND_CASES[number] & { subjectId: string; wf: string };
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId: c.subjectId, wf: c.wf })).toBe('ok');
    query(`SET session_replication_role=replica;
      UPDATE config_snapshots SET revision=2 WHERE id='${c.subjectId}';
      SET session_replication_role=origin;`);
    expect(await run({ kind: c.kind, subjectType: c.subjectType, subjectId: c.subjectId, wf: c.wf })).toBe('METADATA_SCHEDULE_SUBJECT_CHANGED');
    query(`SET session_replication_role=replica;
      UPDATE config_snapshots SET revision=1 WHERE id='${c.subjectId}';
      SET session_replication_role=origin;`);
  }, 30_000);

  it('negatives on iam-metadata request seal + governance-metadata not-due', async () => {
    const iam = KIND_CASES.find(x => x.kind === 'iam-metadata')! as typeof KIND_CASES[number] & { subjectId: string; wf: string };
    expect(await run({ kind: iam.kind, subjectType: iam.subjectType, subjectId: iam.subjectId, wf: iam.wf })).toBe('ok');
    query(`SET session_replication_role=replica;
      UPDATE iam_metadata_requests SET material_hmac='${'d'.repeat(64)}' WHERE id='${iam.subjectId}';
      SET session_replication_role=origin;`);
    expect(await run({ kind: iam.kind, subjectType: iam.subjectType, subjectId: iam.subjectId, wf: iam.wf })).toBe('METADATA_SCHEDULE_SUBJECT_CHANGED');
    query(`SET session_replication_role=replica;
      UPDATE iam_metadata_requests SET material_hmac='${materialHmac}' WHERE id='${iam.subjectId}';
      SET session_replication_role=origin;`);
    const gov = KIND_CASES.find(x => x.kind === 'governance-metadata')! as typeof KIND_CASES[number] & { subjectId: string; wf: string };
    expect(await run({ kind: gov.kind, subjectType: gov.subjectType, subjectId: gov.subjectId, wf: gov.wf, windowStart: iso(60_000), notBefore: iso(60_000) })).toBe('METADATA_SCHEDULE_NOT_DUE');
    expect(await run({ kind: gov.kind, subjectType: gov.subjectType, subjectId: gov.subjectId, wf: gov.wf, attempt: 2 })).toBe('METADATA_SCHEDULE_CLAIM');
    expect(await run({ kind: gov.kind, subjectType: gov.subjectType, subjectId: gov.subjectId, wf: gov.wf })).toBe('ok');
  }, 60_000);
});
