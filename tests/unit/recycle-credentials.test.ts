import {afterEach,beforeEach,describe,expect,it,vi}from'vitest';
import {SecretService}from'../../apps/console-api/src/infrastructure/secret.service';
import {CredentialStoreService}from'../../apps/console-api/src/modules/credentials/credential-store.service';

describe('CredentialStore trustworthy recoverable secrets',()=>{
  beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ef'.repeat(32)));
  afterEach(()=>vi.unstubAllEnvs());
  function fixture(){
    let row:any=null;
    const db:any={one:vi.fn(async()=>row),exec:vi.fn(async(sql:string,p:any[])=>{if(sql.startsWith('INSERT INTO credential_refs'))row={payload_secret:p[5]};return 1;})};
    const secrets=new SecretService();return{db,secrets,store:new CredentialStoreService(db,secrets)};
  }
  it('remembers Basic-auth original plaintext only encrypted and restores it instead of the Kong hash',async()=>{
    const f=fixture();await f.store.save('cluster','consumer','basic-auth',{id:'basic',consumer:{id:'consumer'},username:'user',password:'returned-kong-hash',created_at:123},{password:'original-plaintext'});
    const params=f.db.exec.mock.calls[0][1];expect(params[5]).not.toContain('original-plaintext');expect(params[6]).not.toContain('returned-kong-hash');
    const body=await f.store.getRestorePayload('cluster','consumer','basic-auth','basic',{id:'basic',password:'returned-kong-hash',created_at:123});
    expect(body.password).toBe('original-plaintext');expect(body.created_at).toBeUndefined();
  });
  it('refuses historical Basic credentials and out-of-band rotations with stale remembered passwords',async()=>{
    const f=fixture();await expect(f.store.getRestorePayload('cluster','consumer','basic-auth','unknown',{password:'old-hash'})).rejects.toMatchObject({status:409});
    await f.store.save('cluster','consumer','basic-auth',{id:'basic',password:'old-hash'},{password:'original'});
    await expect(f.store.getRestorePayload('cluster','consumer','basic-auth','basic',{password:'out-of-band-hash'})).rejects.toMatchObject({status:409});
    await f.store.save('cluster','consumer','basic-auth',{id:'basic',password:'out-of-band-hash'},{});
    expect((await f.store.get('cluster','consumer','basic-auth','basic'))?.rawInput.password).toBeUndefined();
  });
  it('allows unchanged Basic edits and remembers deliberate password rotations',async()=>{
    const f=fixture();await f.store.save('cluster','consumer','basic-auth',{id:'basic',password:'same-hash'},{password:'original'});
    await f.store.save('cluster','consumer','basic-auth',{id:'basic',password:'same-hash',username:'renamed'},{username:'renamed'});
    expect((await f.store.getRestorePayload('cluster','consumer','basic-auth','basic',{password:'same-hash'})).password).toBe('original');
    await f.store.save('cluster','consumer','basic-auth',{id:'basic',password:'rotated-hash'},{password:'rotated'});
    expect((await f.store.getRestorePayload('cluster','consumer','basic-auth','basic',{password:'rotated-hash'})).password).toBe('rotated');
  });
  it('preserves non-Basic keys and blocks hashed OAuth clients without trustworthy plaintext',async()=>{
    const f=fixture();const key={id:'key',key:'raw-key',consumer:{id:'consumer'},created_at:123};
    expect((await f.store.getRestorePayload('cluster','consumer','key-auth','key',key)).key).toBe('raw-key');
    await expect(f.store.getRestorePayload('cluster','consumer','oauth2','oauth',{hash_secret:true,client_secret:'hash'})).rejects.toMatchObject({status:409});
    await f.store.save('cluster','consumer','oauth2',{id:'oauth',client_secret:'hash'},{client_secret:'plain'});
    expect((await f.store.getRestorePayload('cluster','consumer','oauth2','oauth',{hash_secret:true,client_secret:'hash'})).client_secret).toBe('plain');
  });
});
