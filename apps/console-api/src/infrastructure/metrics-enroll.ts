import { DbService } from './db.service';
import { SecretService } from './secret.service';
import { AuditService } from '../modules/audit/audit.service';
import { AuditOutboxWriter } from '../modules/event-core/audit-outbox-writer.service';
import { MetricsCredentialsService } from '../modules/metrics/metrics-credentials.service';

/** Secrets enter exclusively through bounded stdin, never argv, environment or output. */
async function main():Promise<void>{
  let bytes=0;const chunks:Buffer[]=[];
  for await(const chunk of process.stdin){const buffer=Buffer.from(chunk);bytes+=buffer.length;if(bytes>8192)throw new Error('stdin budget');chunks.push(buffer);}
  const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));chunks.length=0;
  if(!input||typeof input!=='object'||Array.isArray(input)||process.argv.length!==2)throw new Error('invalid command');
  const status=input.action==='status';
  const allowed=status?['action','clusterId']:['clusterId','generation','credentials'];
  if(Object.keys(input).some(key=>!allowed.includes(key)))throw new Error('invalid fields');
  const db=new DbService();
  try{
    const secrets=new SecretService(),service=new MetricsCredentialsService(db,secrets,new AuditService(db,secrets,new AuditOutboxWriter(db,secrets)));
    // Never apply migrations or bootstrap administrators from the enrollment process.
    const result=status?await service.currentGeneration(input.clusterId):await service.trustedEnroll(input,{requestId:'trusted-metrics-enrollment'});
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }finally{await db.onModuleDestroy();}
}
if(require.main===module)main().catch(()=>{process.stderr.write('METRICS_ENROLLMENT_FAILED\n');process.exitCode=1;});
