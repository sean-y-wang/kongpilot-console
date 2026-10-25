import 'reflect-metadata';
import {performance} from 'node:perf_hooks';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
import {originCanonicalSqlFixture,installOriginSqlOutbound} from './helpers/m11-origin-canonical-sql-fixture';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn()}));
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','d2'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-15T19:00:00Z'));vi.spyOn(performance,'now').mockReturnValue(10000);});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
/** Real original Origin/Namespace handles, canonical SQL and Root callbacks.
 * Only the private preparation association is a controlled provider adapter;
 * real Context phase lifecycle has its own independent companion suite. */
describe('explicit SQL preparation keeps original Origin closing semantics',()=>{
 it('retains full canonical SQL and original proof tuple while deferring its Native scan',async()=>{
  const f=await originCanonicalSqlFixture(3,'team'),sdk=installOriginSqlOutbound(f,vi.mocked(outboundJson));
  await f.withOrigin(async(job,execution)=>{const {handle,proof}=f.current(),frame=f.context.current(),preparation=Object.freeze({originalJobHandle:job,namespaceHandle:handle,namespace:proof});
   vi.spyOn(f.context,'scheduledConfigurationPreparationPhase').mockImplementation(()=>f.context.current()===frame?preparation as any:null);
   const limit=vi.spyOn(f.context,'limitScheduledConfigurationPreparation').mockImplementation(()=>{});
   f.observedRoot.assertLiveMaterial.mockClear();f.observedRoot.openClosedCheckpoint.mockClear();const before=sdk.calls;
   const pair=await f.origin.verifyOriginalExecutionAndJob(job,execution,'packet',f.db);
   expect(pair.job.jobId).toBe(f.job.id);expect(pair.execution.jobHandle).toBe(job);expect(f.observedRoot.assertLiveMaterial).not.toHaveBeenCalled();
   expect(f.observedRoot.openClosedCheckpoint).toHaveBeenCalledOnce();expect(limit).toHaveBeenCalledWith(preparation,expect.any(Number));expect(sdk.calls).toBe(before);
  });
 });
 it('rejects a detached preparation after a successful canonical close rather than publishing its proof',async()=>{
  const f=await originCanonicalSqlFixture(),sdk=installOriginSqlOutbound(f,vi.mocked(outboundJson));
  await f.withOrigin(async(job,execution)=>{const {handle,proof}=f.current(),frame=f.context.current(),preparation=Object.freeze({originalJobHandle:job,namespaceHandle:handle,namespace:proof});let active=true;
   vi.spyOn(f.context,'scheduledConfigurationPreparationPhase').mockImplementation(()=>active&&f.context.current()===frame?preparation as any:null);
   vi.spyOn(f.context,'limitScheduledConfigurationPreparation').mockImplementation(()=>{});
   f.observedRoot.assertClosedCheckpoint.mockImplementation(async(...args:any[])=>{await f.root.assertClosedCheckpoint(...args);active=false;});
   f.observedRoot.releaseClosedCheckpoint.mockClear();const before=sdk.calls;
   await expect(f.origin.verifyOriginalExecutionAndJob(job,execution,'packet',f.db)).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_SQL_PREPARATION_ORIGINAL_REQUIRED'}});
   expect(f.observedRoot.releaseClosedCheckpoint).toHaveBeenCalledOnce();expect(sdk.calls).toBe(before);
  });
 });
});
