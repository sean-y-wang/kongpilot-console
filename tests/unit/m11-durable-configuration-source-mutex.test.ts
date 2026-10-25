import {configurationHttpWait} from '../../apps/console-api/src/infrastructure/kong/configuration-budget';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {ConfigurationRepositoryService} from '../../apps/console-api/src/modules/config-storage/configuration-repository.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','45'.repeat(32));});afterEach(()=>{vi.unstubAllEnvs();});
function fixture(kind:'apply'|'rollback',durableWon:boolean,rejected=false){
 const secrets=new SecretService(),id=randomUUID(),actorId=randomUUID(),sid=randomUUID(),sourceId=randomUUID();
 const scope={clusterId:randomUUID(),workspaceId:randomUUID(),transportScope:secrets.fingerprint('mutex-transport'),kind:'workspace' as const,rootIds:[]};
 const input={planId:sourceId,planRevision:1,planHash:secrets.fingerprint('source-plan'),confirmed:true};
 const events:string[]=[],key='same-source-new-ordinary-key',evidence=vi.fn(async()=>{});
 const proof={actorId,sessionId:sid,scope,expiresAt:Date.now()+60000,credentialEpoch:1,permissionVersion:`${actorId}:1:1`,clusterRevision:1,workspaceRevision:1,captureEpoch:secrets.fingerprint('capture'),origin:'http'};
 const exec=vi.fn(async(sql:string,args:unknown[])=>{expect(sql).toBe('SELECT pg_advisory_xact_lock(hashtextextended($1,0))');
  if(args[0]===`configuration-job:${actorId}:${key}`){events.push('job-lock');return 1;}
  expect(args).toEqual([`configuration-source-plan:${sourceId}`]);events.push('source-lock');return 1;
 });
 const one=vi.fn(async(sql:string,args:unknown[])=>{
  if(sql==='SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4'){expect(args).toEqual([scope.clusterId,scope.workspaceId,actorId,key]);return null;}
  if(sql==='SELECT id FROM configuration_plans WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3'){expect(events).toContain('source-lock');expect(args).toEqual([sourceId,scope.clusterId,scope.workspaceId]);events.push('scope-checked');return{id:sourceId};}
  if(sql==='SELECT id FROM configuration_durable_issues WHERE source_plan_id=$1 AND cluster_id=$2 AND workspace_id=$3'){expect(events.at(-1)).toBe('scope-checked');expect(args).toEqual([sourceId,scope.clusterId,scope.workspaceId]);events.push('durable-checked');return durableWon?{id:randomUUID()}:null;}
  if(sql==='SELECT id FROM configuration_durable_rejections WHERE source_plan_id=$1 AND cluster_id=$2 AND workspace_id=$3'){expect(events.at(-1)).toBe('durable-checked');expect(args).toEqual([sourceId,scope.clusterId,scope.workspaceId]);events.push('rejection-checked');return rejected?{id:randomUUID()}:null;}
  if(sql==='SELECT execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE'){expect(args).toEqual([scope.clusterId]);return{execution_mode:'approval'};}
  if(sql.startsWith('INSERT INTO configuration_jobs(id,cluster_id')){expect(events.at(-1)).toBe('rejection-checked');expect(args[0]).toBe(id);expect(args[7]).toBe(kind);expect(secrets.decrypt(args[13] as string,`configuration-job:${id}`)).toEqual(input);events.push('ordinary-job-insert');return{id,cluster_id:scope.clusterId,workspace_id:scope.workspaceId,kind,state:'pending',revision:1,safe_progress:{},created_at:new Date(),completed_at:null};}
  throw Error('UNEXPECTED_SOURCE_MUTEX_SQL');
 });
 const db:any={one,exec,transaction:async(fn:any)=>{events.push('transaction-start');try{const r=await fn(db);events.push('transaction-commit');return r;}catch(e){events.push('transaction-rollback');throw e;}}};
 const repo=new ConfigurationRepositoryService(db,secrets,new SnapshotCryptoService(secrets),{assertStorage:async()=>proof}as any);
 return{events,one,exec,evidence,run:()=>repo.createJob(Object.freeze({})as any,{id,scope,kind,input,idempotencyKey:key,expiresAt:new Date(Date.now()+60000).toISOString(),writeEvidence:evidence})};
}
describe('reciprocal ordinary source registration uses the real createJob transaction (strict SQL adapters)',()=>{
 it.each(['apply','rollback']as const)('durable-first rejects a later %s before inserting any ordinary Job, regardless of source author',async kind=>{
  const f=fixture(kind,true);await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_ALREADY_SUBMITTED'}});
  expect(f.events).toEqual(['transaction-start','job-lock','source-lock','scope-checked','durable-checked','transaction-rollback']);expect(f.evidence).not.toHaveBeenCalled();
 });
 it.each(['apply','rollback']as const)('rejects later legacy %s under another key for a permanently rejected source',async kind=>{
  const f=fixture(kind,false,true);await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_REJECTED'}});
  expect(f.events).toEqual(['transaction-start','job-lock','source-lock','scope-checked','durable-checked','rejection-checked','transaction-rollback']);expect(f.evidence).not.toHaveBeenCalled();
 });
 it.each(['apply','rollback']as const)('ordinary-first commits %s only after the common source lock and reciprocal durable query',async kind=>{
  const f=fixture(kind,false);await expect(f.run()).resolves.toMatchObject({kind,state:'pending'});
  expect(f.events).toEqual(['transaction-start','job-lock','source-lock','scope-checked','durable-checked','rejection-checked','ordinary-job-insert','transaction-commit']);expect(f.evidence).toHaveBeenCalledOnce();
 });
});

describe('fixed durable-submissions HTTP wait classification',()=>{
 const cid='10000000-0000-4000-8000-000000000001',pid='10000000-0000-4000-8000-000000000002';
 const route=`/api/v1/clusters/${cid}/configuration/plans/${pid}/durable-submissions`;
 it('classifies only the exact current ordinary durable authoring POST as M8 wait',()=>{expect(configurationHttpWait('POST',route)).toBe(true);});
 it.each(['GET','PUT','PATCH','DELETE','OPTIONS','post'])('retains ordinary budget for method %s',method=>{expect(configurationHttpWait(method,route)).toBe(false);});
 it.each(['/extra','/','?budget=durable'])('does not classify an inexact durable path %s',tail=>{expect(configurationHttpWait('POST',route+tail)).toBe(false);});
 it('does not classify caller-controlled fake IDs or unrelated workflows',()=>{expect(configurationHttpWait('POST',route.replace(cid,'from-http'))).toBe(false);expect(configurationHttpWait('POST',route.replace('durable-submissions','approve'))).toBe(false);});
});
