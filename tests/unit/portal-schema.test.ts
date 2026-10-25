import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';

// Managed workspaces can inherit a remote Docker selector. This isolated SQL
// fixture must use only the local daemon and must never borrow live databases.
const dockerEnv={...process.env};
for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION'])delete dockerEnv[key];
const docker=(args:string[],input?:string):string=>execFileSync('docker',['--host','unix:///var/run/docker.sock',...args],{
 env:dockerEnv,...(input!==undefined?{input}:{}),encoding:'utf8',stdio:['pipe','pipe','pipe'],
});

// These tests execute the actual migration functions in disposable PostgreSQL.
// They never use DATABASE_URL or a running console database.
describe('M6 SQL encrypted and native manifest boundaries', () => {
  const container = `kongos-m6-sql-unit-${randomUUID().slice(0, 8)}`;
  let started = false;
  const query = (sql: string): string => docker(['exec', '-i', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA'],sql).trim();
  const manifest = (value: unknown): boolean => query(`SELECT m6_native_request_manifest('${JSON.stringify(value).replaceAll("'", "''")}'::jsonb);`) === 't';
  const hash = 'a'.repeat(64);
  const packet = { method: 'POST', path_hash: hash, native_type: 'plugins', native_id: randomUUID(), body_hmac: hash };

  beforeAll(async () => {
    if(!existsSync('/var/run/docker.sock'))throw new Error('Disposable SQL tests require the local Docker socket');
    docker(['run', '-d', '--name', container, '--network','none','--tmpfs','/tmp/sql-data:rw,size=128m,mode=1777',
      '-e', 'POSTGRES_HOST_AUTH_METHOD=trust','-e','PGDATA=/tmp/sql-data/pgdata','postgres:16-alpine']);
    started = true;
    for (let i = 0; i < 80; i++) {
      try { query('SELECT 1;'); break; }
      catch { if (i === 79) throw new Error('Disposable M6 SQL unit PostgreSQL unavailable'); await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    const directory='apps/console-api/src/infrastructure/migrations';
    if(process.env.KONGOS_SQL_UNIT_FULL_MIGRATIONS==='1'){
      const files=readdirSync(directory).filter(name=>/^0(?:0[0-9]|1[01])_.*\.sql$/.test(name)).sort();
      if(files.length!==12)throw new Error('Expected the exact SQL000–011 test migration set');
      for(const file of files)query(readFileSync(`${directory}/${file}`,'utf8'));
    }else{
      const sql = readFileSync(`${directory}/008_m6_portal.sql`, 'utf8');
      query(sql.slice(sql.indexOf('CREATE FUNCTION m6_encrypted'), sql.indexOf('CREATE TABLE portal_settings')));
    }
  }, 30000);
  afterAll(() => { if (started) docker(['rm', '-f','-v', container]); });

  it('accepts bounded safe packets and empty metadata manifests', () => {
    expect(manifest([])).toBe(true);
    expect(manifest([packet])).toBe(true);
    expect(manifest([{ ...packet, method: 'DELETE', native_type: 'key-auth', parent_id: randomUUID(), credential_kind: 'key-auth', before_hmac: hash }])).toBe(true);
  });
  it('rejects raw bodies, plaintext paths, arbitrary keys and nested secret material', () => {
    for (const extra of [{ body: { key: 'synthetic-raw-secret' } }, { canonicalPath: '/plugins' }, { path: '/plugins' }, { headers: { authorization: 'secret' } }, { config: { password: 'secret' } }]) {
      expect(manifest([{ ...packet, ...extra }])).toBe(false);
    }
  });
  it('rejects unsupported methods/types, absent or null required fields, and non-string hashes', () => {
    for (const changes of [{ method: 'GET' }, { method: null }, { native_type: 'vaults' }, { native_type: null }, { path_hash: 'x' }, { body_hmac: null }, { body_hmac: 1 }, { native_id: 'alias-name' }]) {
      expect(manifest([{ ...packet, ...changes }])).toBe(false);
    }
    const { method: _method, ...missing } = packet;
    expect(manifest([missing])).toBe(false);
    expect(manifest({ packet })).toBe(false);
  });
  it('enforces packet count and byte budgets', () => {
    expect(manifest(Array.from({ length: 32 }, () => packet))).toBe(true);
    expect(manifest(Array.from({ length: 33 }, () => packet))).toBe(false);
    expect(manifest([{ ...packet, body_hmac: 'a'.repeat(131073) }])).toBe(false);
  });
  it('rejects plaintext, malformed envelopes and ciphertext exceeding its field budget', () => {
    const envelope = `v1.${'a'.repeat(16)}.${'b'.repeat(22)}.${'c'.repeat(40)}`;
    const encrypted = (value: string, limit = 3145728): boolean => query(`SELECT m6_encrypted('${value.replaceAll("'", "''")}',${limit});`) === 't';
    expect(encrypted(envelope)).toBe(true);
    for (const value of ['plaintext-api-key', 'v1.bad.bad.raw', envelope.replace('v1.', 'v2.'), envelope + '=', '']) expect(encrypted(value)).toBe(false);
    expect(encrypted(envelope, 10)).toBe(false);
    expect(query('SELECT m6_encrypted(NULL);')).toBe('f');
  });
  it('allows only safe frozen portal branding fields and exact hex colors', () => {
    const branding = (value: unknown): boolean => query(`SELECT m6_portal_branding('${JSON.stringify(value).replaceAll("'", "''")}'::jsonb);`) === 't';
    expect(branding({ primaryColor: '#1890FF', logoText: 'KongOS', welcomeText: '欢迎使用 API' })).toBe(true);
    for (const value of [{ css: 'color:red' }, { primaryColor: 'red' }, { logoText: '<script>1</script>' }, { welcomeText: 'javascript:alert(1)' }, { logoText: 'data:image/svg+xml,test' }, { welcomeText: 1 }, { welcomeText: 'a'.repeat(1025) }, []]) expect(branding(value)).toBe(false);
  });
});
