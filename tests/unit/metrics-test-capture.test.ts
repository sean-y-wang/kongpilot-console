import 'reflect-metadata';
import { beforeEach,describe,expect,it,vi } from 'vitest';
import { randomBytes,randomUUID,createHash } from 'node:crypto';
import { readFile,rm,stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { captureMetricsTestMaterial } from '../../apps/console-api/src/infrastructure/metrics-test-capture';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { METRICS_AUDIENCE,METRICS_PURPOSES } from '../../apps/console-api/src/modules/metrics/metrics.types';
beforeEach(()=>{process.env.CONSOLE_ENCRYPTION_KEY='bc'.repeat(32);});
function fixture(){
 const cid=randomUUID(),generation=2,secrets=new SecretService(),rows=METRICS_PURPOSES.map(purpose=>{
  const id=randomUUID(),token=randomBytes(32).toString('base64url');return {id,purpose,audience:METRICS_AUDIENCE[purpose],generation,token,
   token_fingerprint:createHash('sha256').update(token).digest('hex'),token_secret:secrets.encrypt(token,`metrics-credential:${id}:${cid}:${purpose}:${generation}`)};});
 const db:any={one:vi.fn(async()=>({credential_generation:generation})),query:vi.fn(async()=>rows),transaction:vi.fn(async(fn:any)=>fn(db))};
 return {cid,rows,secrets,db};
}
describe('trusted read-only metrics material capture',()=>{
 it('writes raw material only to a private tmpfs file and returns a safe acknowledgement',async()=>{const f=fixture(),ack=await captureMetricsTestMaterial(f.db,f.secrets,{clusterIds:[f.cid]});
  try{expect(ack.path).toMatch(/^\/dev\/shm\/kongos-metrics-capture-[^/]+\/capture\.json$/);expect((await stat(dirname(ack.path))).mode&0o777).toBe(0o700);expect((await stat(ack.path)).mode&0o777).toBe(0o600);
   expect(ack.count).toBe(4);expect(ack.generations[f.cid]).toBe(2);const bundle=JSON.parse(await readFile(ack.path,'utf8'));expect(bundle.tokens).toHaveLength(4);for(const row of f.rows){expect(JSON.stringify(ack)).not.toContain(row.token);expect(bundle.secrets).toContain(row.token);}
   expect(f.db.one.mock.calls[0][0]).toContain('FOR SHARE');expect(f.db.query.mock.calls[0][0]).toContain("status='active'");
  }finally{await rm(dirname(ack.path),{recursive:true,force:true});}
 });
 it('rejects copied wrong-purpose/generation material and contextual ciphertext before creating output',async()=>{const f=fixture();f.rows[0].generation=1;await expect(captureMetricsTestMaterial(f.db,f.secrets,{clusterIds:[f.cid]})).rejects.toThrow('METRICS_CAPTURE_FAMILY');f.rows[0].generation=2;f.rows[0].token_fingerprint='f'.repeat(64);await expect(captureMetricsTestMaterial(f.db,f.secrets,{clusterIds:[f.cid]})).rejects.toThrow('METRICS_CAPTURE_FAMILY');});
 it('rejects a partial family, duplicate CID, arbitrary path/options and more than eight CIDs',async()=>{const f=fixture();f.rows.pop();await expect(captureMetricsTestMaterial(f.db,f.secrets,{clusterIds:[f.cid]})).rejects.toThrow('METRICS_CAPTURE_FAMILY');for(const input of [{clusterIds:[f.cid,f.cid]},{clusterIds:[f.cid],path:'/tmp/leak'},{clusterIds:Array.from({length:9},()=>randomUUID())},{clusterIds:[]}])await expect(captureMetricsTestMaterial(f.db,f.secrets,input)).rejects.toThrow('METRICS_CAPTURE_INPUT');});
});
