import { describe,expect,it,vi } from 'vitest';
import { randomBytes,createHash } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { MetricsCredentialsService,metricsTokenDigest } from '../../apps/console-api/src/modules/metrics/metrics-credentials.service';
import { metricsTimestamp } from '../../apps/console-api/src/modules/metrics/metrics-repository.service';
import { normalizePermission } from '../../apps/console-api/src/modules/iam/iam-policy';
const cid='30000000-0000-4000-8000-000000000001',id='30000000-0000-4000-8000-000000000061';
process.env.CONSOLE_ENCRYPTION_KEY='dd'.repeat(32);
describe('metrics input security boundaries',()=>{
 it('normalizes native serializer Unix milliseconds and explicit UTC ISO, rejecting invalid calendar dates and timezone ambiguity',()=>{
  expect(metricsTimestamp('2026-10-10T12:30:00.123Z')).toBe(metricsTimestamp(1791635400123));
  for(const value of ['2026-02-30T12:30:00Z','2026-10-10T12:30:00+08:00','2026-10-10','2026-10-10T25:00:00Z',Infinity,NaN,-1,1.5])expect(()=>metricsTimestamp(value)).toThrow();
 });
 it('grants monitoring typed IDs only to real traffic identities, retaining the full cluster/workspace tuple',()=>{
  for(const type of ['services','routes','consumers'])expect(normalizePermission({module:'monitoring',action:'read',scope_type:'entity',cluster_id:cid,
    scope_values:[{entity_type:type,entity_id:id}]},{cluster_id:null,workspace_id:null})).toMatchObject({module:'monitoring',action:'read',cluster_id:cid,scope_type:'entity'});
  for(const type of ['plugins','certificates','targets','basic-auth'])expect(()=>normalizePermission({module:'monitoring',action:'read',scope_type:'entity',cluster_id:cid,
    scope_values:[{entity_type:type,entity_id:id}]},{cluster_id:null,workspace_id:null})).toThrow();
 });
 it('hashes the UTF-8 bearer wire value rather than its base64 payload',()=>{
  const bytes=randomBytes(32),token=bytes.toString('base64url');
  expect(metricsTokenDigest(token)).toBe(createHash('sha256').update(token,'utf8').digest('hex'));
  expect(metricsTokenDigest(token)).not.toBe(createHash('sha256').update(bytes).digest('hex'));
 });
 it('checks credentials with fresh database authority, immutable identities, no JWT/cookie fallback, and immediate revocation',async()=>{
  const token=randomBytes(32).toString('base64url'),db:any={one:vi.fn().mockResolvedValue({id,cluster_id:cid,purpose:'native_scrape',audience:'bff',generation:2,token_fingerprint:metricsTokenDigest(token)})};
  const service=new MetricsCredentialsService(db,new SecretService(),{} as any),identity=await service.validate(token,cid,'native_scrape','bff');
  expect(Object.isFrozen(identity)).toBe(true);await expect(service.assertCurrent({...identity})).rejects.toMatchObject({status:401});
  db.one.mockResolvedValue(null);await expect(service.assertCurrent(identity)).rejects.toMatchObject({status:401});
  await expect(service.validate(token,cid,'native_scrape','collector')).rejects.toMatchObject({status:401});
  await expect(service.validate('Bearer '+token,cid,'native_scrape','bff')).rejects.toMatchObject({status:401});
 });
 it('permits managed ingest userinfo only at the fixed cluster-bound endpoint with the current key',async()=>{
  const token=randomBytes(32).toString('base64url'),db:any={one:vi.fn().mockResolvedValue({id,cluster_id:cid,purpose:'collector_ingest',audience:'collector',generation:2,token_fingerprint:metricsTokenDigest(token)})};
  const service=new MetricsCredentialsService(db,new SecretService(),{} as any),url=`http://kongos:${token}@telemetry-collector:9093/ingest/${cid}`;
  await expect(service.verifyManagedIngestUrl(cid,url)).resolves.toMatchObject({valid:true,generation:2});
  for(const input of [url.replace('telemetry-collector','attacker.invalid'),url+'?token=another',url+'/extra',url.replace('kongos:','admin:'),url.replace(token,randomBytes(32).toString('base64url'))])
    await expect(service.verifyManagedIngestUrl(cid,input)).resolves.toEqual({valid:false});
  db.one.mockResolvedValue(null);await expect(service.verifyManagedIngestUrl(cid,url)).resolves.toEqual({valid:false});
 });
});
