import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { CredentialStoreService } from '../../apps/console-api/src/modules/credentials/credential-store.service';
import { ORDINARY_CREDENTIAL_KINDS } from '../../apps/console-api/src/modules/recycle-bin/ordinary-recycle-contract';

/**
 * KP-004: six-credential restore custody against disposable Postgres —
 * encrypt → save → getRestorePayload (original secrets / Basic plaintext)
 * without live Kong. Mirrors credential_refs CHECK + recovery_capability.
 */
const dockerEnv = { ...process.env };
for (const key of ['DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION']) delete dockerEnv[key];
const base = ['--host', 'unix:///var/run/docker.sock'];

describe('KP-004 ordinary six-credential restore custody (Docker PG)', () => {
  const container = `kongos-m11-kp004-cred-${randomUUID().slice(0, 8)}`;
  let started = false;
  const psql = ['exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA', '-q'];
  const query = (sql: string): string => execFileSync('docker', [...base, ...psql], {
    env: dockerEnv, input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();

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
    `);
  }, 120_000);

  afterAll(() => { if (started) execFileSync('docker', [...base, 'rm', '-f', container], { env: dockerEnv, stdio: 'pipe' }); });

  beforeEach(() => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
    query('TRUNCATE credential_refs;');
  });
  afterEach(() => vi.unstubAllEnvs());

  function store(): { secrets: SecretService; store: CredentialStoreService; cluster: string; consumer: string } {
    const secrets = new SecretService();
    const cluster = randomUUID(), consumer = randomUUID();
    const db: any = {
      one: async (sql: string, params: any[]) => {
        const rows = query(`SELECT payload_secret FROM credential_refs WHERE cluster_id='${params[0]}' AND consumer_id='${params[1]}'
          AND credential_type='${params[2]}' AND kong_id='${params[3]}';`);
        if (!rows) return null;
        return { payload_secret: rows.split('\n')[0] };
      },
      exec: async (sql: string, params: any[]) => {
        if (sql.startsWith('INSERT INTO credential_refs')) {
          const [id, clusterId, consumerId, kind, kongId, payload, summary, recovery] = params;
          const escaped = String(payload).replace(/'/g, "''");
          const sum = String(summary).replace(/'/g, "''");
          query(`INSERT INTO credential_refs(id,cluster_id,consumer_id,credential_type,kong_id,payload_secret,masked_summary,recovery_capability)
            VALUES('${id}','${clusterId}','${consumerId}','${kind}','${kongId}','${escaped}','${sum}'::jsonb,'${recovery}')
            ON CONFLICT(cluster_id,consumer_id,credential_type,kong_id) DO UPDATE SET
              payload_secret=EXCLUDED.payload_secret, masked_summary=EXCLUDED.masked_summary,
              recovery_capability=EXCLUDED.recovery_capability, state='active', updated_at=now();`);
          return 1;
        }
        if (sql.startsWith("UPDATE credential_refs SET state='revoked'")) {
          query(`UPDATE credential_refs SET state='revoked', updated_at=now()
            WHERE cluster_id='${params[0]}' AND consumer_id='${params[1]}' AND credential_type='${params[2]}' AND kong_id='${params[3]}';`);
          return 1;
        }
        throw new Error(`unexpected sql: ${sql.slice(0, 80)}`);
      },
    };
    return { secrets, store: new CredentialStoreService(db, secrets), cluster, consumer };
  }

  it('round-trips restore payloads for all six kinds with encrypted custody in PG', async () => {
    const f = store();
    const samples: Record<string, { credential: any; raw: Record<string, unknown>; remote: any; expectRestore: Record<string, unknown> }> = {};
    for (const kind of ORDINARY_CREDENTIAL_KINDS) {
      const id = randomUUID();
      if (kind === 'key-auth') {
        const credential = { id, key: 'live-key', consumer: { id: f.consumer }, created_at: 1 };
        samples[kind] = { credential, raw: { key: 'live-key' }, remote: { ...credential }, expectRestore: { id, key: 'live-key', consumer: { id: f.consumer } } };
      } else if (kind === 'basic-auth') {
        const hash = createHash('sha1').update('plain-pw' + f.consumer).digest('hex');
        const credential = { id, username: 'u', password: hash, consumer: { id: f.consumer }, created_at: 1 };
        samples[kind] = { credential, raw: { password: 'plain-pw', username: 'u' }, remote: { ...credential },
          expectRestore: { id, username: 'u', password: 'plain-pw', consumer: { id: f.consumer } } };
      } else if (kind === 'jwt') {
        const credential = { id, key: 'jk', secret: 'js', algorithm: 'HS256', consumer: { id: f.consumer }, created_at: 1 };
        samples[kind] = { credential, raw: { key: 'jk', secret: 'js' }, remote: { ...credential },
          expectRestore: { id, key: 'jk', secret: 'js', algorithm: 'HS256', consumer: { id: f.consumer } } };
      } else if (kind === 'oauth2') {
        const credential = { id, name: 'app', client_id: 'c', client_secret: 'hashed', hash_secret: true, consumer: { id: f.consumer }, created_at: 1 };
        samples[kind] = { credential, raw: { client_secret: 'oauth-plain', name: 'app', client_id: 'c' }, remote: { ...credential },
          expectRestore: { id, name: 'app', client_id: 'c', client_secret: 'oauth-plain', hash_secret: true, consumer: { id: f.consumer } } };
      } else if (kind === 'hmac-auth') {
        const credential = { id, username: 'h', secret: 'hmac-plain-secret', consumer: { id: f.consumer }, created_at: 1 };
        samples[kind] = { credential, raw: { username: 'h', secret: 'hmac-plain-secret' }, remote: { ...credential },
          expectRestore: { id, username: 'h', secret: 'hmac-plain-secret', consumer: { id: f.consumer } } };
      } else {
        const credential = { id, group: 'g', consumer: { id: f.consumer }, created_at: 1 };
        samples[kind] = { credential, raw: { group: 'g' }, remote: { ...credential },
          expectRestore: { id, group: 'g', consumer: { id: f.consumer } } };
      }
    }

    for (const kind of ORDINARY_CREDENTIAL_KINDS) {
      const s = samples[kind];
      await f.store.save(f.cluster, f.consumer, kind, s.credential, s.raw);
    }
    expect(query(`SELECT count(DISTINCT credential_type) FROM credential_refs WHERE cluster_id='${f.cluster}';`)).toBe('6');
    expect(query(`SELECT count(*) FROM credential_refs WHERE recovery_capability='complete' AND cluster_id='${f.cluster}';`)).toBe('6');
    // Ciphertext must not leak plaintext secrets in PG storage.
    const dump = query(`SELECT string_agg(payload_secret, ',') FROM credential_refs WHERE cluster_id='${f.cluster}';`);
    expect(dump).not.toContain('plain-pw');
    expect(dump).not.toContain('oauth-plain');
    expect(dump).not.toContain('live-key');
    expect(dump).not.toContain('hmac-plain-secret');

    for (const kind of ORDINARY_CREDENTIAL_KINDS) {
      const s = samples[kind];
      const body = await f.store.getRestorePayload(f.cluster, f.consumer, kind, s.credential.id, s.remote);
      expect(body).toMatchObject(s.expectRestore);
      expect(body.created_at).toBeUndefined();
    }
  });

  it('fails closed for Basic without remembered password and hashed OAuth without plaintext', async () => {
    const f = store();
    const basicId = randomUUID(), oauthId = randomUUID();
    const hash = createHash('sha1').update('x' + f.consumer).digest('hex');
    await expect(f.store.getRestorePayload(f.cluster, f.consumer, 'basic-auth', basicId, { id: basicId, password: hash }))
      .rejects.toMatchObject({ response: { code: 'BASIC_AUTH_NOT_RECOVERABLE' } });
    await f.store.save(f.cluster, f.consumer, 'oauth2', { id: oauthId, client_secret: 'hash', hash_secret: true }, {});
    await expect(f.store.getRestorePayload(f.cluster, f.consumer, 'oauth2', oauthId, { id: oauthId, client_secret: 'hash', hash_secret: true }))
      .rejects.toMatchObject({ response: { code: 'OAUTH_SECRET_NOT_RECOVERABLE' } });
  });

  it('revokes custody without dropping the CHECK-constrained row shape', async () => {
    const f = store();
    const id = randomUUID();
    await f.store.save(f.cluster, f.consumer, 'key-auth', { id, key: 'k' }, { key: 'k' });
    await f.store.remove(f.cluster, f.consumer, 'key-auth', id);
    expect(query(`SELECT state FROM credential_refs WHERE kong_id='${id}';`)).toBe('revoked');
  });
});
