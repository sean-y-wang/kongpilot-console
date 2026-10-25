import 'reflect-metadata';
import {performance} from 'node:perf_hooks';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
import {originCanonicalSqlFixture,installOriginSqlOutbound} from './helpers/m11-origin-canonical-sql-fixture';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn()}));
let monotonic:number;
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','d2'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-15T19:00:00Z'));monotonic=10000;vi.spyOn(performance,'now').mockImplementation(()=>monotonic);});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
/** Actual canonical Authority, Approval/Candidates/Material/Namespace SQL and
 * binding wall clock. Controlled adapters issue the original Authority lifetime
 * and preparation association; actual Context phase lifecycle is tested in its
 * companion file. This is not a persisted claim, transaction or runtime receipt. */
async function fixture(){
 const f=await originCanonicalSqlFixture(3,'team');installOriginSqlOutbound(f,vi.mocked(outboundJson));
 const state:any={deadline:Infinity,commit:undefined,afterCommitRedis:undefined,committed:false,transfers:0};
 const run=async(fn:(handle:object,phase:any)=>Promise<void>)=>f.withNamespace(async()=>{
  const {handle:nsHandle,proof:namespace}=f.current(),handle=Object.freeze({}),phase=Object.freeze({namespaceHandle:nsHandle,namespace});
  const privateFact={scheduleId:namespace.claim.scheduleId,claim:f.stored.claim,state:'executing',executorEntered:true,callbackEntered:true};
  // Source-only issuer adapter, matching the existing Namespace fixture. The
  // real Authority original() registry and every subsequent guard remain real.
  (f.authority as any).handles.set(handle,privateFact);(f.authority as any).workerOwnerHmac=namespace.claim.workerOwnerHmac;
  vi.spyOn(f.context,'scheduledConfigurationPreparationPhase').mockImplementation(()=>{if(monotonic>=state.deadline)throw Error('CONTROLLED_PHASE_MONOTONIC_EXPIRED');return phase as any;});
  vi.spyOn(f.context,'limitScheduledConfigurationPreparation').mockImplementation((original,bound)=>{expect(original).toBe(phase);state.deadline=Math.min(state.deadline,bound);state.transfers++;if(monotonic>=state.deadline)throw Error('CONTROLLED_PHASE_MONOTONIC_EXPIRED');});
  const oldOne=f.db.one.getMockImplementation()!;
  f.db.one.mockImplementation(async function(this:any,sql:string,args:any[]=[]){
   if(sql.includes('m6_rejected_impact_collision'))return null;
   const row=await oldOne.call(this,sql,args);
   return sql.includes('FROM workflow_schedule_claims')?{...row,cluster_id:f.cid,workspace_id:f.wid,initial_lease_until:namespace.claim.initialLeaseUntil}:row;
  });
  f.db.exec.mockImplementation(async(sql:string)=>{if(!sql.startsWith('SELECT pg_advisory_xact_lock('))throw Error('SOURCE_MUTATION_FORBIDDEN');return 0;});
  f.db.transaction.mockImplementation(async(fn:any)=>{const result=await fn(f.db);await state.commit?.();state.committed=true;return result;});
  f.redis.assertLeaseOwnership.mockImplementation(async()=>{if(!f.state.lease)throw Error('SOURCE_LEASE_LOST');if(state.committed)await state.afterCommitRedis?.();});
  try{await fn(handle,phase);}finally{(f.authority as any).handles.delete(handle);}
 });
 return{...f,phaseState:state,run};
}
describe('configuration SQL preparation closes original canonical authority',()=>{
 it('performs actual canonical all-party checks and physical reservation checks without Native reads',async()=>{
  const f=await fixture();await f.run(async(handle,phase)=>{const before=f.state.native.length;await f.authority.verifyConfigurationSqlPreparation(handle,phase.namespaceHandle,phase.namespace,'packet');
   expect(f.state.native.length).toBe(before);expect(f.phaseState.transfers).toBeGreaterThan(0);expect(Number.isFinite(f.phaseState.deadline)).toBe(true);
   for(const id of [f.actor,...f.reviewers])expect(f.db.query.mock.calls.some(([sql,args]:any[])=>sql.includes('SELECT to_jsonb(g) AS grant')&&args[0]===id)).toBe(true);
   expect(f.db.one.mock.calls.some(([sql]:any[])=>sql.includes('m6_rejected_impact_collision'))).toBe(true);
  });
 });
 it.each(['commit','redis'] as const)('rejects natural binding expiry across the final %s await without epoch change',async point=>{
  const f=await fixture();await f.run(async(handle,phase)=>{const epoch=structuredClone(f.tables.iam_epoch),b=f.bindingFor(f.reviewers[2]);b.expires_at=new Date(Date.now()+5000).toISOString();
   if(point==='commit')f.phaseState.commit=async()=>{await Promise.resolve();monotonic+=6000;};else f.phaseState.afterCommitRedis=async()=>{await Promise.resolve();monotonic+=6000;};
   await expect(f.authority.verifyConfigurationSqlPreparation(handle,phase.namespaceHandle,phase.namespace,'packet')).rejects.toThrow('CONTROLLED_PHASE_MONOTONIC_EXPIRED');expect(f.tables.iam_epoch).toEqual(epoch);
  });
 });
 it.each(['executor','reviewer-1','reviewer-3'] as const)('rejects current %s complete grant drift during its canonical observation',async party=>{
  const f=await fixture();await f.run(async(handle,phase)=>{const id=party==='executor'?f.actor:party==='reviewer-1'?f.reviewers[0]:f.reviewers[2];let changed=false;f.control.afterRead=(sql:string,args:any[])=>{if(!changed&&sql.includes('SELECT to_jsonb(g) AS grant')&&args[0]===id){changed=true;f.bindingFor(id).status='revoked';}};
   await expect(f.authority.verifyConfigurationSqlPreparation(handle,phase.namespaceHandle,phase.namespace,'packet')).rejects.toThrow();});
 });
 it('keeps SQL consistency distinct from Native permission: zero executor grants are rejected by the final actual Root subject gate',async()=>{
  const f=await fixture();await f.run(async(handle,phase)=>{f.bindingFor(f.actor).status='revoked';
   await expect(f.authority.verifyConfigurationSqlPreparation(handle,phase.namespaceHandle,phase.namespace,'packet')).resolves.toBeUndefined();
   await expect((f.runtime as any).subject(f.plan,f.actor,'write','before-send',f.db)).rejects.toThrow();
  });
 });
 it('rejects another original Authority handle with a different claim before opening its canonical namespace',async()=>{
  const f=await fixture();await f.run(async(_handle,phase)=>{const other=Object.freeze({});(f.authority as any).handles.set(other,{scheduleId:randomUUID(),claim:{...f.stored.claim,id:randomUUID()},state:'executing',executorEntered:true,callbackEntered:true});
   try{await expect(f.authority.verifyConfigurationSqlPreparation(other,phase.namespaceHandle,phase.namespace,'packet')).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_SQL_PREPARATION_ORIGINAL_REQUIRED'}});}finally{(f.authority as any).handles.delete(other);}
  });
 });
});
