import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ConfigurationRepositoryService} from '../../apps/console-api/src/modules/config-storage/configuration-repository.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {CONFIGURATION_TIMEOUT_MS} from '../../apps/console-api/src/infrastructure/kong/configuration-budget';
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','64'.repeat(32));vi.useFakeTimers();vi.setSystemTime(Date.parse('2026-10-15T20:00:00.000Z'));});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});
describe('new durable material lifetime and short actual configuration execution are separate',()=>{
 it.each(['durable-configuration-v1',null])('sets actual execution expiry for domain %s without extending proof or changing job',async domain=>{
  const secrets=new SecretService(),ids={job:randomUUID(),cluster:randomUUID(),workspace:randomUUID(),owner:randomUUID(),plan:randomUUID(),snapshot:randomUUID(),workflow:randomUUID()};
  const scope={clusterId:ids.cluster,workspaceId:ids.workspace,transportScope:'1'.repeat(64),kind:'workspace',rootIds:[]},job:any={id:ids.job,cluster_id:ids.cluster,workspace_id:ids.workspace,transport_scope:scope.transportScope,
   scope_kind:'workspace',root_ids:[],actor_id:ids.owner,plan_id:ids.plan,plan_revision:1,plan_hash:'2'.repeat(64),lease_generation:2,expires_at:new Date(Date.now()+(domain?86400000:600000)),execution_mode:'approval',permission_version:`${ids.owner}:1:1`,authority_domain:domain};
  const before=structuredClone(job),proof={actorId:ids.owner,scope,expiresAt:Date.now()+90000};let expiry:any;
  const handle=Object.freeze({});const tx:any={one:vi.fn(async(sql:string,args:any[])=>{
   if(sql==='SELECT * FROM configuration_jobs WHERE id=$1 FOR UPDATE'){expect(args).toEqual([ids.job]);return job;}
   if(sql.startsWith('SELECT id,claim_hash FROM configuration_executions'))return null;
   if(sql.startsWith('SELECT v.*,s.transport_scope FROM config_snapshot_versions'))return{transport_scope:scope.transportScope,consistency:'console_fenced_best_effort'};
   if(sql.startsWith('SELECT w.plan_hash FROM workflows'))return{plan_hash:'3'.repeat(64)};
   throw Error('UNEXPECTED_SHORT_EXECUTION_SQL');
  }),exec:vi.fn(async(sql:string,args:any[])=>{if(!sql.startsWith('INSERT INTO configuration_executions'))throw Error('UNEXPECTED_SHORT_EXECUTION_WRITE');expect(args).toHaveLength(18);expiry=args[17];return 1;})};
  const db:any={transaction:async(fn:any)=>fn(tx)},access:any={assertStorage:vi.fn(async(actual:any)=>{expect(actual).toBe(handle);return proof;})};
  const repo=new ConfigurationRepositoryService(db,secrets,new SnapshotCryptoService(secrets),access);
  await repo.createExecution(handle as any,{jobId:ids.job,planId:ids.plan,planRevision:1,planHash:job.plan_hash,beforeSnapshotId:ids.snapshot,beforeSnapshotVersion:1,workflowId:ids.workflow,approvedVersion:1,claimHash:'4'.repeat(64)});
  expect(new Date(expiry).getTime()).toBe(domain?Math.min(job.expires_at.getTime(),proof.expiresAt,Date.now()+CONFIGURATION_TIMEOUT_MS):job.expires_at.getTime());
  expect(job).toEqual(before);expect(proof.expiresAt).toBe(Date.now()+90000);expect(tx.exec).toHaveBeenCalledOnce();
 });
});
