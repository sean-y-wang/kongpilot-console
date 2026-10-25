import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { ConfigurationDurableCodec, decodeDurableConfigurationEnvelope, durableConfigurationAad, durableConfigurationLocator } from '../../apps/console-api/src/modules/configuration/configuration-durable.codec';
import type { DurableConfigurationEnvelope } from '../../apps/console-api/src/modules/configuration/configuration-durable.types';

const NOW = Date.parse('2026-10-15T20:00:00.000Z');
const digest = (n: number) => String(n).repeat(64);
function fixture(): DurableConfigurationEnvelope {
  const ownerId = randomUUID();
  return {domain:'durable-configuration-v1', envelopeVersion:1, issueId:randomUUID(), clusterId:randomUUID(), workspaceId:randomUUID(),
    jobId:randomUUID(), ownerId, authoringSessionId:randomUUID(), credentialEpoch:1, permissionVersion:`${ownerId}:2:3`,
    issuedAt:new Date(NOW).toISOString(), admissionExpiresAt:new Date(NOW+90_000).toISOString(), expiresAt:new Date(NOW+3_600_000).toISOString(),
    policy:{definitionId:randomUUID(),version:1,hash:digest(1),intentTtlHours:24},
    provenance:{jobId:randomUUID(),planId:randomUUID(),planRevision:1,planHash:digest(2),kind:'import'},
    baseline:{snapshotId:randomUUID(),version:1,manifestHmac:digest(3)}, recipeHmac:digest(4),schemaHmac:digest(5),scopeHmac:digest(6),
    plan:{planId:randomUUID(),planRevision:1,planHash:digest(7),stepsHmac:digest(8),sourceManifestHmac:digest(9),baselineManifestHmac:digest(3)}};
}
function changed(value: unknown, path: string, replacement: unknown): unknown {
  const copy = structuredClone(value) as Record<string, any>, keys = path.split('.');
  let parent = copy;
  for (const key of keys.slice(0,-1)) parent = parent[key];
  parent[keys.at(-1)!] = replacement;
  return copy;
}
let oldKey: string | undefined;
beforeEach(()=>{oldKey=process.env.CONSOLE_ENCRYPTION_KEY;process.env.CONSOLE_ENCRYPTION_KEY='61'.repeat(32);});
afterEach(()=>{vi.useRealTimers();if(oldKey===undefined)delete process.env.CONSOLE_ENCRYPTION_KEY;else process.env.CONSOLE_ENCRYPTION_KEY=oldKey;});

describe('M11 durable Configuration V2 exact material codec with real AES-GCM/HMAC',()=>{
  it('round trips all fields, authenticates the complete envelope, and freezes an independent decoded copy',()=>{
    const secrets=new SecretService(),codec=new ConfigurationDurableCodec(secrets),e=fixture(),locator=durableConfigurationLocator(e);
    const seal=codec.seal(e,locator,NOW),other=codec.seal(e,locator,NOW),opened=codec.open(seal,locator,NOW);
    expect(opened).toEqual(e);expect(opened).not.toBe(e);expect(seal.materialHmac).toBe(secrets.fingerprint(e));
    expect(seal.ciphertext).not.toBe(other.ciphertext);expect(seal.materialHmac).toBe(other.materialHmac);
    for(const v of [seal,opened,opened.policy,opened.provenance,opened.baseline,opened.plan])expect(Object.isFrozen(v)).toBe(true);
    expect(secrets.decrypt(seal.ciphertext,durableConfigurationAad(locator))).toEqual(e);
    expect(opened.provenance.jobId).not.toBe(opened.jobId);expect(opened.provenance.planId).not.toBe(opened.plan.planId);
  });
  it.each(['','policy','provenance','baseline','plan'])('rejects extra keys on exact envelope level %s',(path)=>{
    const e=fixture(),value=path?changed(e,path,{...(e as any)[path],extra:true}):{...e,extra:true};
    expect(()=>decodeDurableConfigurationEnvelope(value,NOW)).toThrow('DURABLE_CONFIGURATION_INVALID');
  });
  it.each(Object.keys(fixture()))('rejects missing required top-level field %s',(key)=>{
    const e=structuredClone(fixture()) as any;delete e[key];expect(()=>decodeDurableConfigurationEnvelope(e,NOW)).toThrow();
  });
  it('rejects own symbols, non-enumerable fields, accessors and non-plain objects without invoking getters',()=>{
    const e=fixture(),getter=vi.fn(()=>e.issueId),accessor={...e};Object.defineProperty(accessor,'issueId',{get:getter,enumerable:true});
    expect(()=>decodeDurableConfigurationEnvelope(accessor,NOW)).toThrow();expect(getter).not.toHaveBeenCalled();
    const symbol={...e,[Symbol('unexpected')]:true};expect(()=>decodeDurableConfigurationEnvelope(symbol,NOW)).toThrow();
    const hidden={...e};Object.defineProperty(hidden,'issueId',{value:e.issueId,enumerable:false});
    expect(()=>decodeDurableConfigurationEnvelope(hidden,NOW)).toThrow();
    expect(()=>decodeDurableConfigurationEnvelope(Object.assign(Object.create({inherited:true}),e),NOW)).toThrow();
    expect(()=>decodeDurableConfigurationEnvelope([],NOW)).toThrow();
  });
  it.each(['issueId','clusterId','workspaceId','jobId','ownerId','authoringSessionId','policy.definitionId','provenance.jobId','provenance.planId','baseline.snapshotId','plan.planId'])('rejects malformed UUID %s',(path)=>{
    expect(()=>decodeDurableConfigurationEnvelope(changed(fixture(),path,'not-a-uuid'),NOW)).toThrow();
  });
  it.each(['recipeHmac','schemaHmac','scopeHmac','policy.hash','provenance.planHash','baseline.manifestHmac','plan.planHash','plan.stepsHmac','plan.sourceManifestHmac','plan.baselineManifestHmac'])('rejects malformed keyed digest %s',(path)=>{
    for(const replacement of ['a'.repeat(63),'A'.repeat(64),'g'.repeat(64),null])expect(()=>decodeDurableConfigurationEnvelope(changed(fixture(),path,replacement),NOW)).toThrow();
  });
  it.each(['credentialEpoch','policy.version','provenance.planRevision','baseline.version','plan.planRevision'])('rejects invalid positive safe integer %s',(path)=>{
    for(const replacement of [0,-1,1.5,Number.MAX_SAFE_INTEGER+1,'1',null])expect(()=>decodeDurableConfigurationEnvelope(changed(fixture(),path,replacement),NOW)).toThrow();
  });
  it('requires canonical owner-bound permission epochs and rejects malformed or foreign version strings',()=>{
    const e=fixture();
    for(const replacement of [`${randomUUID()}:2:3`,`${e.ownerId}:0:3`,`${e.ownerId}:02:3`,`${e.ownerId}:2:3:4`,`${e.ownerId}:2:${Number.MAX_SAFE_INTEGER+1}`,null])
      expect(()=>decodeDurableConfigurationEnvelope({...e,permissionVersion:replacement},NOW)).toThrow();
  });
  it('accepts canonical whole-hour policy TTL 1–168 and never extends an envelope beyond its sealed deadline',()=>{
    const e=fixture();for(const ttl of [1,168])expect(decodeDurableConfigurationEnvelope(changed(e,'policy.intentTtlHours',ttl),NOW).policy.intentTtlHours).toBe(ttl);
    for(const ttl of [0,169,1.5,'24'])expect(()=>decodeDurableConfigurationEnvelope(changed(e,'policy.intentTtlHours',ttl),NOW)).toThrow();
    expect(()=>decodeDurableConfigurationEnvelope({...e,expiresAt:new Date(NOW+24*3_600_000+1).toISOString()},NOW)).toThrow();
    expect(()=>decodeDurableConfigurationEnvelope({...e,expiresAt:e.issuedAt},NOW)).toThrow();
    expect(()=>decodeDurableConfigurationEnvelope({...e,expiresAt:new Date(NOW-1).toISOString()},NOW)).toThrow();
  });
  it('binds the short admission as historical material without expiring long-window verification',()=>{
    const e=fixture(),codec=new ConfigurationDurableCodec(new SecretService()),locator=durableConfigurationLocator(e),seal=codec.seal(e,locator,NOW);
    expect(codec.open(seal,locator,NOW+600_000).admissionExpiresAt).toBe(e.admissionExpiresAt);
    expect(()=>decodeDurableConfigurationEnvelope({...e,admissionExpiresAt:e.issuedAt},NOW)).toThrow();
    expect(()=>decodeDurableConfigurationEnvelope({...e,admissionExpiresAt:new Date(NOW+300001).toISOString()},NOW)).toThrow();
    const changed={...e,admissionExpiresAt:new Date(NOW+90001).toISOString()};
    const forged={ciphertext:new SecretService().encrypt(changed,durableConfigurationAad(locator)),materialHmac:seal.materialHmac};
    expect(()=>codec.open(forged,locator,NOW)).toThrow();
  });
  it.each(['issuedAt','admissionExpiresAt','expiresAt'])('requires a real canonical millisecond UTC timestamp for %s',(path)=>{
    for(const value of ['2026-10-15T20:00:00Z','2026-10-15T20:00:00.000+00:00','2026-02-30T20:00:00.000Z','invalid',null])
      expect(()=>decodeDurableConfigurationEnvelope(changed(fixture(),path,value),NOW)).toThrow();
  });
  it('rejects wrong domains, versions, provenance kinds and inconsistent baseline manifests',()=>{
    const e=fixture();for(const [path,value]of [['domain','legacy-http-v1'],['domain','durable-configuration-v2'],['envelopeVersion',2],['provenance.kind','promote'],['plan.baselineManifestHmac',digest(2)]] as const)
      expect(()=>decodeDurableConfigurationEnvelope(changed(e,path,value),NOW)).toThrow();
  });
  it('defaults to the actual clock and keeps explicit historical integrity checks separate from execution permission',()=>{
    vi.useFakeTimers();vi.setSystemTime(NOW);const e=fixture(),codec=new ConfigurationDurableCodec(new SecretService()),l=durableConfigurationLocator(e),s=codec.seal(e,l);
    expect(codec.open(s,l)).toEqual(e);vi.setSystemTime(NOW+3_600_000);expect(()=>codec.open(s,l)).toThrow('DURABLE_CONFIGURATION_NOT_CURRENT');
    expect(codec.open(s,l,NOW)).toEqual(e);expect(()=>codec.open(s,l,NOW-1)).toThrow('DURABLE_CONFIGURATION_NOT_CURRENT');
    expect(()=>codec.open(s,l,NaN)).toThrow();expect(()=>codec.open(s,l,Infinity)).toThrow();
    expect(codec.open(s,l,NOW)).not.toHaveProperty('nativePermit');
  });
  it.each(['issueId','clusterId','workspaceId','jobId','planId','planRevision','planHash'])('rejects AEAD locator substitution %s',(key)=>{
    const codec=new ConfigurationDurableCodec(new SecretService()),e=fixture(),l=durableConfigurationLocator(e),s=codec.seal(e,l,NOW);
    const value=key==='planRevision'?2:key==='planHash'?digest(2):randomUUID();
    expect(()=>codec.open(s,{...l,[key]:value},NOW)).toThrow('DURABLE_CONFIGURATION_SEAL_INVALID');
    expect(()=>codec.seal(e,{...l,[key]:value},NOW)).toThrow('DURABLE_CONFIGURATION_BINDING_INVALID');
  });
  it('rejects malformed or extra locator and sealed-record keys',()=>{
    const codec=new ConfigurationDurableCodec(new SecretService()),e=fixture(),l=durableConfigurationLocator(e),s=codec.seal(e,l,NOW);
    for(const locator of [{...l,extra:true},{...l,envelopeVersion:2},{...l,domain:'configuration-v2'}])expect(()=>codec.open(s,locator,NOW)).toThrow();
    for(const seal of [{...s,extra:true},{ciphertext:s.ciphertext},{...s,materialHmac:'x'},{...s,ciphertext:null},{...s,ciphertext:'x'.repeat(131_073)}])expect(()=>codec.open(seal,l,NOW)).toThrow();
  });
  it('rejects wrong AAD, a legacy ciphertext, corrupted ciphertext and a well-formed but wrong material HMAC',()=>{
    const secrets=new SecretService(),codec=new ConfigurationDurableCodec(secrets),e=fixture(),l=durableConfigurationLocator(e),s=codec.seal(e,l,NOW);
    const pieces=s.ciphertext.split('.');pieces[3]=(pieces[3][0]==='A'?'B':'A')+pieces[3].slice(1);
    for(const ciphertext of [secrets.encrypt(e,'configuration-v2'),secrets.encrypt(e),pieces.join('.')])
      expect(()=>codec.open({...s,ciphertext},l,NOW)).toThrow('DURABLE_CONFIGURATION_SEAL_INVALID');
    expect(()=>codec.open({...s,materialHmac:'0'.repeat(64)},l,NOW)).toThrow('DURABLE_CONFIGURATION_SEAL_INVALID');
    expect(()=>codec.open({...s,materialHmac:secrets.fingerprint({...e,domain:'legacy-http-v1'})},l,NOW)).toThrow('DURABLE_CONFIGURATION_SEAL_INVALID');
  });
  it('authenticates expiry and every plain field even when AES-GCM plaintext is re-encrypted under the correct AAD',()=>{
    const secrets=new SecretService(),codec=new ConfigurationDurableCodec(secrets),e=fixture(),l=durableConfigurationLocator(e),s=codec.seal(e,l,NOW),aad=durableConfigurationAad(l);
    const cases:[string,unknown][]=[['expiresAt',new Date(NOW+2*3_600_000).toISOString()],['issuedAt',new Date(NOW-1).toISOString()],
      ['credentialEpoch',2],['permissionVersion',`${e.ownerId}:3:3`],['recipeHmac',digest(1)],['schemaHmac',digest(1)],['scopeHmac',digest(1)],
      ['authoringSessionId',randomUUID()],['policy.hash',digest(2)],['policy.version',2],['policy.intentTtlHours',25],
      ['provenance.jobId',randomUUID()],['provenance.planId',randomUUID()],['provenance.planHash',digest(1)],['provenance.kind','rollback'],
      ['baseline.snapshotId',randomUUID()],['baseline.version',2],['plan.stepsHmac',digest(1)],['plan.sourceManifestHmac',digest(1)]];
    for(const [path,value]of cases){const ciphertext=secrets.encrypt(changed(e,path,value),aad);expect(()=>codec.open({...s,ciphertext},l,NOW),path).toThrow('DURABLE_CONFIGURATION_SEAL_INVALID');}
    const changedBaseline={...e,baseline:{...e.baseline,manifestHmac:digest(1)},plan:{...e.plan,baselineManifestHmac:digest(1)}};
    expect(()=>codec.open({...s,ciphertext:secrets.encrypt(changedBaseline,aad)},l,NOW)).toThrow('DURABLE_CONFIGURATION_SEAL_INVALID');
  });
});
