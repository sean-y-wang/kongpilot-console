import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {ConfigurationRepositoryService} from '../../apps/console-api/src/modules/config-storage/configuration-repository.service';
import {SnapshotCryptoService} from '../../apps/console-api/src/modules/config-storage/snapshot-crypto.service';
import {CONFIGURATION_JOB_PROJECTION_QUERY} from '../../apps/console-api/src/modules/configuration/configuration-job-queries';
import {createSourceDispositionFixture} from './helpers/m11-source-disposition-facade-fixture';

const id=(n:number)=>`ab000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const EXISTING='SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4';
const SOURCE='SELECT id FROM configuration_plans WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3';
const REGISTERED='SELECT id FROM configuration_durable_issues WHERE source_plan_id=$1 AND cluster_id=$2 AND workspace_id=$3';
const REJECTED='SELECT id FROM configuration_durable_rejections WHERE source_plan_id=$1 AND cluster_id=$2 AND workspace_id=$3';

/** Actual ConfigurationService.apply/plan/newJob and actual Repository.createJob
 * /getJob over exact controlled SQL and current scope adapters. Plan material
 * reads are controlled, but original facade authorization and grant evaluator
 * run. No HTTP, PostgreSQL commit race, opaque Access issuer or Native send is
 * claimed. Native/freeze callbacks fail if a blocked request reaches them. */
function fixture(rejected=true,kind:'apply'|'rollback'='apply'){
 const f=createSourceDispositionFixture({rejected,registered:false});
 const state=Object.assign(f.state,{existing:null as any,sourcePresent:true,storageCurrent:true,afterSourceLock:undefined as undefined|(()=>void),afterRejectionRead:undefined as undefined|(()=>void),inserted:[] as any[],transactionDepth:0});
 f.actor.idempotencyKey='legacy-source-current-key';Object.assign(f.source,{scope_kind:f.scope.kind,root_ids:f.scope.rootIds,kind:'import'});
 Object.assign(f.summary,{mode:kind==='rollback'?'rollback':'merge'});
 const input=()=>({planId:f.summary.id,planRevision:f.summary.planRevision,planHash:f.summary.planHash,driver:'bff',confirmed:true,confirm_deletes:false});
 const stored=()=>({...f.source,id:id(80),scope_kind:f.scope.kind,root_ids:f.scope.rootIds,transport_scope:f.scope.transportScope,actor_id:f.actor.user.id,
  origin_session_id:f.sid,kind,state:'failed',revision:3,created_at:new Date().toISOString(),completed_at:new Date().toISOString(),safe_progress:{completedSteps:0},
  execution_mode:'approval',approval_required:true,idempotency_key:f.actor.idempotencyKey,
  request_hmac:f.secrets.fingerprint({scope:f.scope,kind,input:input()}),required_origin_kind:null,required_origin_id:null,required_origin_hmac:null});
 const baseOne=f.db.one.getMockImplementation()!;
 f.db.one.mockImplementation(async(sql:string,args:unknown[])=>{
  if(sql==='SELECT job_id FROM configuration_durable_issues WHERE cluster_id=$1 AND source_plan_id=$2'){
   expect(args).toHaveLength(2);f.trace.push('legacy-registered-early-guard');return args[0]===f.scope.clusterId&&args[1]===f.summary.id&&f.state.disposition.registered?{job_id:id(90)}:null;
  }
  if(sql==='SELECT j.* FROM configuration_plans p JOIN configuration_jobs j ON j.id=p.source_job_id WHERE p.id=$1'){
   expect(args).toEqual([f.summary.id]);f.trace.push('authorized-source-row');return f.source;
  }
  if(sql===EXISTING){expect(args).toEqual([f.scope.clusterId,f.scope.workspaceId,f.actor.user.id,f.actor.idempotencyKey]);f.trace.push('existing-key');return state.existing;}
  if(sql===SOURCE){expect(state.transactionDepth).toBeGreaterThan(0);expect(args).toEqual([f.summary.id,f.scope.clusterId,f.scope.workspaceId]);f.trace.push('transaction-source-scope');return state.sourcePresent?{id:f.summary.id}:null;}
  if(sql===REGISTERED){expect(state.transactionDepth).toBeGreaterThan(0);expect(args).toEqual([f.summary.id,f.scope.clusterId,f.scope.workspaceId]);f.trace.push('transaction-registration');return f.state.disposition.registered?{id:id(91)}:null;}
  if(sql===REJECTED){expect(state.transactionDepth).toBeGreaterThan(0);expect(args).toEqual([f.summary.id,f.scope.clusterId,f.scope.workspaceId]);f.trace.push('transaction-rejection');state.afterRejectionRead?.();return f.state.disposition.rejected?{id:id(92)}:null;}
  if(sql==='SELECT execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE'){
   expect(args).toEqual([f.scope.clusterId]);f.trace.push('transaction-cluster');return{execution_mode:'approval'};
  }
  if(sql.startsWith('INSERT INTO configuration_jobs(id,cluster_id')){
   expect(state.transactionDepth).toBeGreaterThan(0);expect(args[1]).toBe(f.scope.clusterId);expect(args[2]).toBe(f.scope.workspaceId);expect(args[4]).toBe(f.actor.user.id);expect(args[7]).toBe(kind);
   expect(f.secrets.decrypt(args[13] as string,`configuration-job:${args[0]}`)).toEqual(input());f.trace.push('ordinary-job-insert');state.inserted.push(args);
   return{...stored(),id:args[0],state:'pending',revision:1,safe_progress:{},completed_at:null};
  }
  if(sql==='SELECT * FROM configuration_jobs WHERE id=$1 FOR UPDATE'){
   expect(args).toEqual([state.existing?.id]);f.trace.push('original-job-row');return state.existing;
  }
  if(sql===CONFIGURATION_JOB_PROJECTION_QUERY){expect(args).toEqual([state.existing?.id,f.scope.clusterId,f.scope.workspaceId,f.actor.user.id]);f.trace.push('original-receipt-projection');return state.existing;}
  if(sql==='SELECT state,safe_progress FROM configuration_jobs WHERE id=$1'){expect(args).toEqual([state.inserted.at(-1)?.[0]]);return null;}
  return baseOne(sql,args);
 });
 f.db.exec.mockImplementation(async(sql:string,args:unknown[])=>{
  expect(sql).toBe('SELECT pg_advisory_xact_lock(hashtextextended($1,0))');expect(state.transactionDepth).toBeGreaterThan(0);
  if(args[0]===`configuration-job:${f.actor.user.id}:${f.actor.idempotencyKey}`){f.trace.push('transaction-key-lock');return 1;}
  expect(args).toEqual([`configuration-source-plan:${f.summary.id}`]);f.trace.push('transaction-source-lock');state.afterSourceLock?.();return 1;
 });
 f.db.transaction=async(fn:any)=>{state.transactionDepth++;f.trace.push('transaction-open');try{const value=await fn(f.db);f.trace.push('transaction-commit');return value;}
  catch(error){f.trace.push('transaction-rollback');throw error;}finally{state.transactionDepth--;}};
 const assertStorage=vi.fn(async(selected:any,request:any,tx:any)=>{
  expect(selected).toBe(f.handle);expect(tx).toBe(f.db);expect(request.scope).toEqual(f.scope);expect(['capture-page','read']).toContain(request.phase);
  f.trace.push('storage-current');if(!state.storageCurrent||!f.state.current||f.context.current().sessionId!==f.sid)throw new ForbiddenException({code:'CURRENT_STORAGE_SCOPE_REVOKED'});
  return{actorId:f.actor.user.id,sessionId:f.sid,scope:f.scope,expiresAt:Date.now()+60_000,credentialEpoch:1,
   permissionVersion:`${f.actor.user.id}:1:1`,clusterRevision:1,workspaceRevision:1,captureEpoch:'e'.repeat(64),origin:'http'};
 });
 f.access.assertStorage=assertStorage;
 f.access.acquireReceipt=vi.fn(async(jobId:string)=>{expect(jobId).toBe(state.existing?.id);f.trace.push('original-receipt-access');if(!f.state.current)throw new ForbiddenException({code:'CURRENT_RECEIPT_DENIED'});return f.handle;});
 f.access.acquire=vi.fn(async(jobId:string)=>{expect(jobId).toBe(state.inserted.at(-1)?.[0]);f.trace.push('new-job-access');return f.handle;});
 const actualRepository=new ConfigurationRepositoryService(f.db,f.secrets,new SnapshotCryptoService(f.secrets),f.access);
 f.repo.createJob=vi.fn(actualRepository.createJob.bind(actualRepository));f.repo.getJob=vi.fn(actualRepository.getJob.bind(actualRepository));
 f.repo.freezePlan=vi.fn(async()=>{throw Error('UNUSED_SOURCE_REACHED_FREEZE');});f.repo.initializeExecutionProgress=vi.fn();
 const audit={append:vi.fn(async()=>{f.trace.push('ordinary-job-audit');})};(f.service as any).audit=audit;
 (f.service as any).redis={withLock:vi.fn(async(key:string,fn:any)=>{expect(key).toMatch(/^configuration-source-plan:[a-f\d-]{36}$/);return fn();})};
 const body=()=>({planHash:f.summary.planHash,planRevision:f.summary.planRevision,confirmed:true,confirm_name:`配置计划 ${f.summary.id}`});
 const run=(cid=f.scope.clusterId,pid=f.summary.id)=>f.context.runHttp({requestId:f.actor.requestId},async()=>{f.context.bindHttpActor(f.actor.user,f.sid);return f.service.apply(cid,pid,body(),f.actor);});
 return{...f,state,actualRepository,assertStorage,audit,stored,input,run,body};
}

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','2'.repeat(64));vi.stubEnv('CURSOR_SIGNING_KEY','legacy-source-disposition-unit-key');});
afterEach(()=>vi.unstubAllEnvs());

describe('legacy apply cannot bypass permanent source disposition through a hand-crafted POST',()=>{
 it.each(['apply','rollback']as const)('the actual facade/newJob/repository rejects a new %s before INSERT/freeze/audit or Native',async kind=>{
  const f=fixture(true,kind);await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_REJECTED'}});
  expect(f.trace).toContain('source-disposition');expect(f.trace).toContain('transaction-rejection');expect(f.trace.at(-1)).toBe('transaction-rollback');
  expect(f.trace.indexOf('transaction-source-scope')).toBeLessThan(f.trace.indexOf('transaction-rejection'));
  expect(f.assertStorage).toHaveBeenCalledOnce();expect(f.repo.createJob).toHaveBeenCalledOnce();expect(f.state.inserted).toEqual([]);
  expect(f.repo.freezePlan).not.toHaveBeenCalled();expect(f.repo.initializeExecutionProgress).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();
  expect(f.native.execute).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('uses the transaction source mutex to refuse a disposition appearing after the plan UI projection was read',async()=>{
  const f=fixture(false);f.state.afterSourceLock=()=>{f.state.disposition.rejected=true;};
  await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_REJECTED'}});
  expect(f.state.inserted).toEqual([]);expect(f.repo.freezePlan).not.toHaveBeenCalled();expect(f.trace).toContain('transaction-source-lock');
 });
 it('keeps enforcing the SQL rejection when the optional durable authoring provider is absent',async()=>{
  const f=fixture();(f.service as any).durable=undefined;await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_REJECTED'}});
  expect(f.trace).not.toContain('legacy-registered-early-guard');expect(f.state.inserted).toEqual([]);expect(f.repo.freezePlan).not.toHaveBeenCalled();
 });
 it('keeps the existing registered earlyguard behavior',async()=>{
  const f=fixture(false);f.state.disposition.registered=true;
  await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_ALREADY_SUBMITTED'}});
  expect(f.trace).toEqual(['legacy-registered-early-guard']);expect(f.repo.createJob).not.toHaveBeenCalled();
 });
 it('rechecks the scoped source inside the transaction before revealing its disposition',async()=>{
  const f=fixture();f.state.sourcePresent=false;
  await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_SOURCE_PLAN_UNAVAILABLE'}});
  expect(f.trace).not.toContain('transaction-registration');expect(f.trace).not.toContain('transaction-rejection');expect(f.state.inserted).toEqual([]);
 });
 it('rejects revoked current storage authority before source disposition queries or INSERT',async()=>{
  const f=fixture();f.state.storageCurrent=false;
  await expect(f.run()).rejects.toMatchObject({response:{code:'CURRENT_STORAGE_SCOPE_REVOKED'}});
  expect(f.trace).not.toContain('transaction-source-scope');expect(f.trace).not.toContain('transaction-rejection');expect(f.state.inserted).toEqual([]);
 });
 it('rejects missing manifest READ before the repository or source disposition can disclose a refusal',async()=>{
  const f=fixture();f.state.read=false;await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_PLAN_ENTITY_DENIED'}});
  expect(f.trace).not.toContain('source-disposition');expect(f.repo.createJob).not.toHaveBeenCalled();expect(f.state.inserted).toEqual([]);
 });
 it.each(['cluster','plan','workspace']as const)('does not reveal the rejection for a foreign %s',async kind=>{
  const f=fixture();if(kind==='workspace')f.state.missingPlan=true;
  await expect(f.run(kind==='cluster'?id(98):f.scope.clusterId,kind==='plan'?id(99):f.summary.id)).rejects.toMatchObject({status:404});
  expect(f.trace).not.toContain('source-disposition');expect(f.trace).not.toContain('transaction-rejection');expect(f.repo.createJob).not.toHaveBeenCalled();
 });
 it('returns an existing original-key receipt without creating or replaying an apply despite a rejected source',async()=>{
  const f=fixture();f.state.existing=f.stored();const result=await f.run();
  expect(result).toMatchObject({jobId:f.state.existing.id,idempotencyKey:f.actor.idempotencyKey,state:'failed',registrationCompleted:true,executionCompleted:true});
  expect(result.originalScope).toEqual({clusterId:f.scope.clusterId,workspaceId:f.scope.workspaceId});expect(f.trace).toContain('original-receipt-access');
  expect(f.repo.createJob).not.toHaveBeenCalled();expect(f.repo.getJob).toHaveBeenCalledOnce();expect(f.state.inserted).toEqual([]);
  expect(f.repo.freezePlan).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();expect(f.native.execute).not.toHaveBeenCalled();
 });
 it('rejects an existing key attached to another request instead of returning or replacing that receipt',async()=>{
  const f=fixture();f.state.existing={...f.stored(),request_hmac:'0'.repeat(64)};
  await expect(f.run()).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});
  expect(f.access.acquireReceipt).not.toHaveBeenCalled();expect(f.repo.createJob).not.toHaveBeenCalled();expect(f.state.inserted).toEqual([]);
 });
 it('does not convert an unrelated durable-only blocker into a blanket legacy apply denial',async()=>{
  const f=fixture(false);f.durable.unsupportedReason.mockReturnValue({code:'CONFIGURATION_DURABLE_TARGET_APPEND_UNSUPPORTED',message:'fixture durable-only blocker'});
  await expect(f.run()).rejects.toThrow('UNUSED_SOURCE_REACHED_FREEZE');
  expect(f.state.inserted).toHaveLength(1);expect(f.audit.append).toHaveBeenCalledOnce();expect(f.repo.freezePlan).toHaveBeenCalledOnce();
  expect(f.trace.indexOf('transaction-rejection')).toBeLessThan(f.trace.indexOf('ordinary-job-insert'));expect(f.native.execute).not.toHaveBeenCalled();
 });
});
