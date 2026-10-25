import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmod, mkdtemp, rm, statfs, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DbService } from './db.service';
import { SecretService } from './secret.service';
import { METRICS_AUDIENCE, METRICS_PURPOSES } from '../modules/metrics/metrics.types';

const uuid = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
export interface MetricsCaptureAck {captureId:string;path:string;clusterIds:string[];generations:Record<string,number>;count:number}

/** Trusted CLI only. Never imported into an HTTP controller or registered as a provider. */
export async function captureMetricsTestMaterial(db:DbService,secrets:SecretService,input:unknown):Promise<MetricsCaptureAck> {
  if (!input || typeof input!=='object' || Array.isArray(input) || Object.keys(input).some(key=>key!=='clusterIds')) throw new Error('METRICS_CAPTURE_INPUT');
  const ids=(input as any).clusterIds;
  if (!Array.isArray(ids) || ids.length<1 || ids.length>8 || ids.some(id=>typeof id!=='string'||!uuid.test(id)) || new Set(ids).size!==ids.length) throw new Error('METRICS_CAPTURE_INPUT');
  // The only plaintext destination is private Linux tmpfs, never a persistent mount.
  if ((await statfs('/dev/shm',{bigint:true})).type !== 0x01021994n) throw new Error('METRICS_CAPTURE_TMPFS');
  const material=await db.transaction(async tx=>{
    const generations:Record<string,number>={},tokens:any[]=[];
    for (const cid of [...ids].sort()) {
      const settings=await tx.one<any>(`SELECT s.credential_generation FROM metrics_settings s JOIN clusters c ON c.id=s.cluster_id
        WHERE s.cluster_id=$1 AND c.deleted_at IS NULL FOR SHARE OF s,c`,[cid]);
      if (!settings || Number(settings.credential_generation)<1) throw new Error('METRICS_CAPTURE_FAMILY');
      const generation=Number(settings.credential_generation);
      const rows=await tx.query<any>(`SELECT id,purpose,audience,generation,token_fingerprint,token_secret FROM metrics_credentials
        WHERE cluster_id=$1 AND status='active' ORDER BY purpose FOR SHARE`,[cid]);
      if (rows.length!==4 || new Set(rows.map(row=>row.purpose)).size!==4) throw new Error('METRICS_CAPTURE_FAMILY');
      for (const row of rows) {
        if (!METRICS_PURPOSES.includes(row.purpose) || row.audience!==METRICS_AUDIENCE[row.purpose as keyof typeof METRICS_AUDIENCE]
          || Number(row.generation)!==generation || !/^[a-f0-9]{64}$/.test(row.token_fingerprint)) throw new Error('METRICS_CAPTURE_FAMILY');
        const token=secrets.decrypt<string>(row.token_secret,`metrics-credential:${row.id}:${cid}:${row.purpose}:${generation}`);
        if (typeof token!=='string' || !/^[A-Za-z0-9_-]{43,128}$/.test(token)) throw new Error('METRICS_CAPTURE_FAMILY');
        const digest=createHash('sha256').update(token,'utf8').digest();
        if (!timingSafeEqual(digest,Buffer.from(row.token_fingerprint,'hex'))) throw new Error('METRICS_CAPTURE_FAMILY');
        tokens.push({clusterId:cid,generation,purpose:row.purpose,audience:row.audience,token});
      }
      generations[cid]=generation;
    }
    if (new Set(tokens.map(row=>row.token)).size!==tokens.length) throw new Error('METRICS_CAPTURE_FAMILY');
    return {tokens,secrets:tokens.map(row=>row.token),users:[],generations};
  });
  let directory:string|undefined;
  try {
    directory=await mkdtemp('/dev/shm/kongos-metrics-capture-');await chmod(directory,0o700);
    const path=join(directory,'capture.json');
    await writeFile(path,JSON.stringify({tokens:material.tokens,secrets:material.secrets,users:material.users}),{mode:0o600,flag:'wx'});
    return {captureId:randomUUID(),path,clusterIds:ids,generations:material.generations,count:material.tokens.length};
  } catch (error) {if(directory)await rm(directory,{recursive:true,force:true});throw error;}
}

async function main():Promise<void> {
  if (process.argv.length!==2) throw new Error('METRICS_CAPTURE_INPUT');
  let bytes=0;const chunks:Buffer[]=[];
  for await (const chunk of process.stdin) {const value=Buffer.from(chunk);bytes+=value.length;if(bytes>2048)throw new Error('METRICS_CAPTURE_INPUT');chunks.push(value);}
  const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));chunks.length=0;
  const db=new DbService();
  try {const ack=await captureMetricsTestMaterial(db,new SecretService(),input);process.stdout.write(`${JSON.stringify(ack)}\n`);}
  finally {await db.onModuleDestroy();}
}
if(require.main===module)main().catch(()=>{process.stderr.write('METRICS_TEST_CAPTURE_FAILED\n');process.exitCode=1;});
