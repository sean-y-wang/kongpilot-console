import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { ORDINARY_CREDENTIAL_KINDS, ORDINARY_RECYCLE_ROOT_TYPES } from '../../apps/console-api/src/modules/recycle-bin/ordinary-recycle-contract';

/**
 * Disposable Postgres: KP-004 schema surface for six credential_type CHECK
 * values and five ordinary recycle root_type rows. Minimal DDL mirrors 001_m1
 * (no full migration chain; FK to clusters/users omitted).
 */
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];

describe('KP-004 ordinary six credentials + five recycle roots (PG constraints)', () => {
  const container = `kongos-m11-kp004-${randomUUID().slice(0, 8)}`;
  let started = false;
  const psql = ['exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'];
  const query = (sql: string): string => execFileSync('docker', [...base, ...psql], {
    env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
  const fails = (sql: string): string => { try { query(sql); return ''; } catch (e) { return String((e as { stderr?: string }).stderr ?? e); } };

  beforeAll(async () => {
    if (!existsSync('/var/run/docker.sock')) throw new Error('Disposable SQL tests require the local Docker socket');
    execFileSync('docker', [...base, 'run', '-d', '--name', container, '--network', 'none',
      '--tmpfs', '/tmp/sql-data:rw,size=128m,mode=1777',
      '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'PGDATA=/tmp/sql-data/pgdata', 'postgres:16-alpine'],
    { env: dockerEnv, stdio: 'pipe' });
    started = true;
    for (let i = 0; i < 100; i++) {
      try { query('SELECT 1;'); break; }
      catch { if (i === 99) throw new Error('Disposable PostgreSQL unavailable'); await new Promise(r => setTimeout(r, 100)); }
    }
    query(`
      CREATE TABLE credential_refs (
        id uuid PRIMARY KEY,
        cluster_id uuid NOT NULL,
        consumer_id uuid NOT NULL,
        credential_type text NOT NULL CHECK (credential_type IN ('key-auth','basic-auth','jwt','oauth2','hmac-auth','acls')),
        kong_id uuid NOT NULL,
        payload_secret text NOT NULL,
        masked_summary jsonb NOT NULL DEFAULT '{}',
        recovery_capability text NOT NULL,
        state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','revoked')),
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE(cluster_id,consumer_id,credential_type,kong_id)
      );
      CREATE TABLE recycle_entries (
        id uuid PRIMARY KEY,
        cluster_id uuid NOT NULL,
        actor_id uuid NOT NULL,
        root_type text NOT NULL,
        original_id text NOT NULL,
        root_name text NOT NULL,
        parent_id text,
        credential_kind text,
        state text NOT NULL DEFAULT 'archived' CHECK (state IN ('archived','deleting','deleted','partially_deleted','restoring','partially_restored','restored','purged')),
        node_count integer NOT NULL CHECK (node_count > 0),
        payload_secret text NOT NULL,
        expires_at timestamptz NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
    `);
  }, 120_000);

  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  it('accepts all six ordinary credential_type values and rejects unknown kinds', () => {
    const cluster = randomUUID(), consumer = randomUUID();
    for (const kind of ORDINARY_CREDENTIAL_KINDS) {
      query(`INSERT INTO credential_refs(id,cluster_id,consumer_id,credential_type,kong_id,payload_secret,recovery_capability)
        VALUES('${randomUUID()}','${cluster}','${consumer}','${kind}','${randomUUID()}','sealed','complete');`);
    }
    expect(query(`SELECT count(DISTINCT credential_type) FROM credential_refs WHERE cluster_id='${cluster}';`)).toBe('6');
    expect(fails(`INSERT INTO credential_refs(id,cluster_id,consumer_id,credential_type,kong_id,payload_secret,recovery_capability)
      VALUES('${randomUUID()}','${cluster}','${consumer}','ldap-auth','${randomUUID()}','x','complete');`))
      .toMatch(/check|credential_type|violates/i);
  });

  it('stores five ordinary recycle root_type archives with positive node_count', () => {
    const cluster = randomUUID(), actor = randomUUID();
    for (const root of ORDINARY_RECYCLE_ROOT_TYPES) {
      query(`INSERT INTO recycle_entries(id,cluster_id,actor_id,root_type,original_id,root_name,node_count,payload_secret,expires_at)
        VALUES('${randomUUID()}','${cluster}','${actor}','${root}','${randomUUID()}','${root}-name',${root === 'consumers' ? 7 : 2},'sealed',now()+interval '30 days');`);
    }
    expect(query(`SELECT count(DISTINCT root_type) FROM recycle_entries WHERE cluster_id='${cluster}';`)).toBe('5');
    expect(query(`SELECT string_agg(root_type,',' ORDER BY root_type) FROM recycle_entries WHERE cluster_id='${cluster}';`))
      .toBe([...ORDINARY_RECYCLE_ROOT_TYPES].sort().join(','));
    expect(fails(`INSERT INTO recycle_entries(id,cluster_id,actor_id,root_type,original_id,root_name,node_count,payload_secret,expires_at)
      VALUES('${randomUUID()}','${cluster}','${actor}','services','${randomUUID()}','empty',0,'sealed',now()+interval '30 days');`))
      .toMatch(/check|node_count|violates/i);
  });
});
