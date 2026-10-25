import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService, canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';
import { jsonDiff } from '../../apps/console-api/src/modules/audit/audit.service';
import jsonPatch from 'fast-json-patch';
import { readFileSync } from 'node:fs';
import { stripSensitiveSchemaDefaults } from '../../apps/console-api/src/infrastructure/kong/schema-secrets';
import { AuditService } from '../../apps/console-api/src/modules/audit/audit.service';
import { EntityIndexService } from '../../apps/console-api/src/modules/entities/entity-index.service';

describe('SecretService encryption and disclosure protection', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '12'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());
  it('keeps Kong OAuth lifetime and its schema default public without revealing refresh tokens',()=>{
    const secret=new SecretService(),safe=secret.redact({refresh_token_ttl:1209600,refresh_token:'synthetic-private-token'});
    expect(safe.refresh_token_ttl).toBe(1209600);expect(safe.refresh_token).toMatch(/^\[REDACTED:/);
    const source=JSON.parse(readFileSync('tests/fixtures/kong-1.5.1/plugin-schema-oauth2.json','utf8'));
    const schema=stripSensitiveSchemaDefaults(source,secret),field=schema.fields.find((r:any)=>r.refresh_token_ttl).refresh_token_ttl;
    expect(field.default).toBe(1209600);expect(field.default_redacted).toBeUndefined();
  });

  it('requires an explicit 32-byte key and accepts hex and base64', () => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', '');
    expect(() => new SecretService()).toThrow(/required/);
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'short-password');
    expect(() => new SecretService()).toThrow();
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', Buffer.alloc(32, 7).toString('base64'));
    expect(() => new SecretService()).not.toThrow();
  });

  it('round trips nested JSON and emits different ciphertext for the same plaintext', () => {
    const secrets = new SecretService();
    const value = { key: 'sensitive-api-key', array: [true, 7, null], nested: { message: '中文' } };
    const first = secrets.encrypt(value, 'cluster:123');
    expect(first).not.toContain('sensitive');
    expect(first).not.toBe(secrets.encrypt(value, 'cluster:123'));
    expect(secrets.decrypt(first, 'cluster:123')).toEqual(value);
  });

  it('rejects ciphertext tampering, wrong AAD and unknown versions', () => {
    const secrets = new SecretService();
    const encrypted = secrets.encrypt({ password: 'value' }, 'consumer:1');
    expect(() => secrets.decrypt(encrypted, 'consumer:2')).toThrow();
    const parts = encrypted.split('.');
    const bytes = Buffer.from(parts[3], 'base64url');
    bytes[0] ^= 1;
    parts[3] = bytes.toString('base64url');
    expect(() => secrets.decrypt(parts.join('.'), 'consumer:1')).toThrow();
    expect(() => secrets.decrypt(encrypted.replace('v1.', 'v9.'))).toThrow();
  });

  it('redacts nested plugin secrets, headers, PEM, encrypted values and URL credentials', () => {
    const secrets = new SecretService();
    const input = { name: 'ldap-auth', config: { bind_password: 'ldap-secret', key_names: ['apikey'],
      records: [{ apiKey: 'api-key', client_secret: 'oauth-value', privateKey: 'private-value' }] },
      headers: { Authorization: 'Bearer jwt-value', Cookie: 'sid=secret-cookie' },
      raw: '-----BEGIN RSA PRIVATE KEY-----\nprivate\n-----END RSA PRIVATE KEY-----',
      auth_secret: secrets.encrypt({ password: 'db-value' }),
      url: 'postgres://admin:db-value@localhost/db' };
    const output = secrets.redact(input);
    const json = JSON.stringify(output);
    for (const secret of ['ldap-secret', 'api-key', 'oauth-value', 'private-value', 'jwt-value', 'secret-cookie', 'db-value']) {
      expect(json).not.toContain(secret);
    }
    expect(output.config.key_names).toEqual(['apikey']);
    expect(output.name).toBe('ldap-auth');
    expect(output.url).toBe('postgres://REDACTED@localhost/db');
  });

  it('redacts independent Portal CSRF values without hiding key-name metadata', () => {
    const secrets = new SecretService();
    const result = secrets.redact({ csrfToken: 'private-session-csrf', csrf_token: 'anonymous-session-csrf',
      headers: { 'X-Portal-CSRF': 'private-header-csrf', 'X-CSRF-Token': 'console-header-csrf' }, key_names: ['apikey'] });
    for (const value of ['private-session-csrf', 'anonymous-session-csrf', 'private-header-csrf', 'console-header-csrf']) expect(JSON.stringify(result)).not.toContain(value);
    expect(result.key_names).toEqual(['apikey']);
  });

  it('retains stable fingerprints while recording secret changes without their values', () => {
    const secrets = new SecretService();
    expect(secrets.fingerprint({ b: 2, a: 1 })).toBe(secrets.fingerprint({ a: 1, b: 2 }));
    expect(secrets.redact({ password: 'first' })).toEqual(secrets.redact({ password: 'first' }));
    const diff = jsonDiff(secrets.redact({ password: 'first' }), secrets.redact({ password: 'second' }));
    expect(diff[0]?.path).toBe('/password');
    expect(JSON.stringify(diff)).not.toContain('second');
  });

  it('redacts credential headers embedded in transformer arrays and custom connection values', () => {
    const secrets = new SecretService();
    const result = secrets.redact({ config: { add: { headers: ['Authorization: Bearer embedded-secret',
      'Cookie: session=embedded-cookie', 'X-API-Key: embedded-api-key', 'X-Public-Trace: okay'] } },
      auth: { header_name: 'X-Custom-Auth', header_value: 'custom-secret' } });
    const json = JSON.stringify(result);
    for (const secret of ['embedded-secret', 'embedded-cookie', 'embedded-api-key', 'custom-secret']) expect(json).not.toContain(secret);
    expect(json).toContain('X-Public-Trace: okay');
  });

  it('scrubs raw validator echoes in messages and fields including array bodies and short secrets',()=>{
    const secrets=new SecretService();
    const body=[{config:{password:'x',nested:[{client_secret:'oauth-secret'}],headers:['Authorization: Bearer bearer-secret']}}];
    const result=secrets.redactError({message:'invalid x / oauth-secret / bearer-secret',fields:{config:{password:'the x value was rejected'}}},body);
    const json=JSON.stringify(result);
    for(const value of ['oauth-secret','bearer-secret'])expect(json).not.toContain(value);
    expect(result.fields.config.password).toContain('[REDACTED]');
  });

  it('scrubs managed ingest URLs and encoded or decoded userinfo echoed in validator text',()=>{
    const secrets=new SecretService(),username='synthetic-metrics-user',password='synthetic+metrics/secret';
    const encodedPassword=encodeURIComponent(password),url=`http://${username}:${encodedPassword}@telemetry-collector:9093/ingest/test-cluster`;
    const body={config:{http_endpoint:url}};
    expect(secrets.redact(body).config.http_endpoint).toContain('http://REDACTED@telemetry-collector:9093');
    const safe=secrets.redactError({message:`validator rejected endpoint ${url}; user ${username}; password ${password}; encoded ${encodedPassword}`,
      fields:{'config.http_endpoint':`could not use ${url}`}},body),serialized=JSON.stringify(safe);
    for(const scalar of [url,username,password,encodedPassword])expect(serialized).not.toContain(scalar);
    expect(safe.message).toContain('[REDACTED]');
    expect(body.config.http_endpoint).toBe(url);
  });

  it('classifies all credential-bearing Kong 1.5 plugin key fields without hiding public flags',()=>{
    const secrets=new SecretService();
    const config={provision_key:'synthetic-oauth-provision',aws_key:'synthetic-aws-access-key',aws_secret:'synthetic-aws-secret',
      redis_password:'synthetic-redis-password',client_secret:'synthetic-client-secret',password:'synthetic-basic-password',
      secret:'synthetic-jwt-secret',rsa_private_key:'synthetic-private-key',key:'synthetic-api-key',
      secret_is_base64:false,enable_password_grant:true,credentials:false,rsa_public_key:'public-material',key_names:['apikey']};
    const safe=secrets.redact({config,credentials:{provision_key:'boxed-credential-secret'}});
    for(const [name,value]of Object.entries(config)){
      if(typeof value==='string'&&name!=='rsa_public_key')expect(JSON.stringify(safe),name).not.toContain(value);
    }
    expect(safe.config).toMatchObject({secret_is_base64:false,enable_password_grant:true,credentials:false,rsa_public_key:'public-material',key_names:['apikey']});
    expect(safe.credentials).toMatch(/^\[REDACTED:/);
  });

  it('removes sensitive schema defaults but preserves real JWT, OAuth2 and CORS flag defaults',()=>{
    const secrets=new SecretService();
    const fixture=(name:string)=>JSON.parse(readFileSync(`tests/fixtures/kong-1.5.1/plugin-schema-${name}.json`,'utf8'));
    for(const name of ['jwt','oauth2','cors']){
      const schema=fixture(name);
      if(name==='oauth2')schema.fields.find((entry:any)=>entry.provision_key).provision_key.default='synthetic-default-provision';
      const safe=stripSensitiveSchemaDefaults(schema,secrets);
      for(const key of ['secret_is_base64','enable_password_grant','credentials']){
        const entry=schema.fields.find((field:any)=>field[key]);
        if(entry&&Object.hasOwn(entry[key],'default'))expect(safe.fields.find((field:any)=>field[key])[key].default,key).toBe(entry[key].default);
      }
      expect(JSON.stringify(safe)).not.toContain('synthetic-default-provision');
    }
  });

  it('scrubs OAuth provisioning and AWS access-key validator echoes in both messages and arbitrary flattened field keys',()=>{
    const secrets=new SecretService(),body={config:{provision_key:'synthetic-provision-rejected',aws_key:'synthetic-aws-rejected'}};
    const safe=secrets.redactError({message:'invalid synthetic-provision-rejected / synthetic-aws-rejected',
      fields:{'config.provision_key':'synthetic-provision-rejected is invalid','config.aws_key':'invalid synthetic-aws-rejected'}},body);
    expect(JSON.stringify(safe)).not.toContain('synthetic-provision-rejected');expect(JSON.stringify(safe)).not.toContain('synthetic-aws-rejected');
    expect(safe.message).toContain('[REDACTED]');
  });

  it('redacts historical JSON Patch values by decoded secret paths while retaining public flag changes',()=>{
    const secrets=new SecretService();
    const historical=[{op:'replace',path:'/config/provision_key',value:'historic-oauth-key'},
      {op:'add',path:'/config/aws~1key',value:'historic-aws-key'},{op:'test',path:'/records/0/client~0secret',value:'historic-client-secret'},
      {op:'replace',path:'/config/secret_is_base64',value:true},{op:'replace',path:'/config/enable_password_grant',value:false},
      {op:'replace',path:'/config/credentials',value:true},{op:'replace',path:'/name',value:'visible-name'}];
    const safe=secrets.redact({json_patch:historical});
    for(const value of ['historic-oauth-key','historic-aws-key','historic-client-secret'])expect(JSON.stringify(safe)).not.toContain(value);
    expect(safe.json_patch.slice(3)).toEqual(historical.slice(3));expect(historical[0].value).toBe('historic-oauth-key');
    const before={config:{provision_key:'old-provision',aws_key:'old-aws',enable_password_grant:false}};
    const after={config:{provision_key:'new-provision',aws_key:'new-aws',enable_password_grant:true}};
    const generated=jsonDiff(secrets.redact(before),secrets.redact(after));
    expect(JSON.stringify(generated)).not.toContain('new-provision');expect(JSON.stringify(generated)).not.toContain('new-aws');
    expect(generated).toContainEqual({op:'replace',path:'/config/enable_password_grant',value:true});
  });

  it('persists no plugin provisioning or cloud key plaintext through audit or entity indexing',async()=>{
    const secrets=new SecretService(),calls:any[]=[];
    const tx={exec:vi.fn(async(sql:string,params:any[])=>{calls.push([sql,params]);return 1;}),one:vi.fn().mockResolvedValue({last_sequence:'0',last_hash:'initial'})};
    const db={transaction:vi.fn(async(fn:any)=>fn(tx)),exec:tx.exec};
    const plugin={id:'plugin',name:'oauth2',config:{provision_key:'stored-synthetic-provision',aws_key:'stored-synthetic-access-key',enable_password_grant:true}};
    await new AuditService(db as any,secrets,{fromAudit:vi.fn().mockResolvedValue(null)} as any).append({entityType:'plugins',entityId:plugin.id,clusterId:'cluster',action:'create',after:plugin});
    await new EntityIndexService(db as any,{} as any,secrets,{} as any,{} as any,{} as any,{} as any).upsert('cluster','plugins',plugin);
    for(const secret of ['stored-synthetic-provision','stored-synthetic-access-key'])expect(JSON.stringify(calls)).not.toContain(secret);
    const index=calls.find(([sql])=>sql.includes('INSERT INTO entity_index'));
    expect(index[1][5].config.enable_password_grant).toBe(true);
  });

  it('handles circular references and object prototype names without disclosure or mutation', () => {
    const secrets = new SecretService();
    const source: any = JSON.parse('{"__proto__":{"password":"hidden"},"safe":true}');
    source.loop = source;
    source.secret = source;
    const result = secrets.redact(source);
    expect(JSON.stringify(result)).not.toContain('hidden');
    expect(result.loop).toBe('[CIRCULAR]');
    expect(result.safe).toBe(true);
    expect(source.__proto__.password).toBe('hidden');
  });
});

describe('Audit RFC 6902 diff', () => {
  it('produces an applicable patch including escaped keys, removals, nested objects and arrays', () => {
    const before = { 'a/b~c': 1, remove: 1, items: [1, 2, 3], child: { present: true } };
    const after = { 'a/b~c': 2, items: [2], child: { present: true, added: 'value' } };
    const patch = jsonDiff(before, after);
    expect(patch.some(operation => operation.path === '/a~1b~0c')).toBe(true);
    expect(jsonPatch.applyPatch(structuredClone(before), patch as any).newDocument).toEqual(after);
  });

  it('supports null roots and scalar replacement', () => {
    expect(jsonPatch.applyPatch(null as any, jsonDiff(null, { name: 'new' }) as any).newDocument).toEqual({ name: 'new' });
    expect(jsonDiff({ a: 1 }, { a: 1 })).toEqual([]);
    expect(jsonDiff('first', 'second')).toEqual([{ op: 'replace', path: '', value: 'second' }]);
    expect(canonicalJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });
});
