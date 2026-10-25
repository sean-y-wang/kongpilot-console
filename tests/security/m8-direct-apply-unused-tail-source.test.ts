// @ts-nocheck -- actual continuation method, synthetic transport only.
import{describe,it,expect,vi}from'vitest';import{randomUUID}from'node:crypto';
const cfg=vi.hoisted(()=>({configurationRead:vi.fn(),configurationWrite:vi.fn(),completeConfigurationWorkflow:vi.fn()}));
const native=vi.hoisted(()=>({nativeRead:vi.fn(),sixCredentialProxyAcceptance:vi.fn(),recycleAndRestore:vi.fn()}));
vi.mock('./lib/m8-configuration-acceptance.mjs',()=>cfg);vi.mock('./lib/m8-native-acceptance.mjs',()=>native);
import{finishM8DirectImportRollback}from'./lib/m8-transfer-acceptance.mjs';
function fixture(mode='success'){
 const actor={user:{id:randomUUID()},sid:randomUUID()},area={cid:randomUUID(),wid:randomUUID()},sourcePlanId=randomUUID(),rollbackPlanId=randomUUID();
 const imported={kind:'import',state:'succeeded',actorId:actor.user.id,clusterId:area.cid,workspaceId:area.wid,jobId:randomUUID(),planId:sourcePlanId,planHash:'a'.repeat(64),planRevision:1,counts:{update:1}},f={area,service:{id:randomUUID(),retries:0}};
 const state={nativeFixture:f,baseline:{snapshotId:randomUUID(),name:'synthetic original snapshot'},fiveClassRecovery:Array.from({length:5},()=>({fullyRestored:true}))},h={state,check:(v,n)=>{if(!v)throw Error(n);},save:vi.fn()},actors={admin:actor};
 cfg.configurationRead.mockReset().mockImplementation(async(_h,_a,_area,path)=>path.startsWith('snapshots/')?{entity:{revision:1}}:{entity:{id:path.split('/')[2],name:'synthetic original sealed plan',revision:2,planRevision:1,planHash:'a'.repeat(64),mode:path.includes(rollbackPlanId)?'rollback':'merge',capabilities:{apply:true}}});
 cfg.configurationWrite.mockReset().mockImplementation(async(_h,_a,_area,path)=>{
  if(mode==='unknown')throw Error('ORIGINAL_UNKNOWN_NO_REPLAY');
  if(path.endsWith('/rollback-plan'))return{jobId:randomUUID(),planId:rollbackPlanId,planHash:'a'.repeat(64),planRevision:1};
  return{state:'succeeded',jobId:randomUUID()};
 });
 native.nativeRead.mockReset().mockResolvedValueOnce({retries:mode==='wrongApply'?9:1}).mockResolvedValueOnce({retries:mode==='wrongRollback'?9:0});
 native.sixCredentialProxyAcceptance.mockReset().mockResolvedValue(undefined);native.recycleAndRestore.mockReset();
 return{h,actors,imported,sourcePlanId,rollbackPlanId};
}
describe('unused direct M8 apply and rollback after Native-free historical failure',()=>{
 it('reuses the successful import plan, starts only new apply/rollback operations, and never repeats recovery/import',async()=>{
  const{h,actors,imported,sourcePlanId,rollbackPlanId}=fixture();await finishM8DirectImportRollback(h,actors,imported);
  expect(cfg.configurationWrite.mock.calls.map(v=>v[3])).toEqual([`configuration/plans/${sourcePlanId}/apply`,`snapshots/${h.state.baseline.snapshotId}/rollback-plan`,`configuration/plans/${rollbackPlanId}/apply`]);
  expect(native.recycleAndRestore).not.toHaveBeenCalled();expect(native.sixCredentialProxyAcceptance.mock.calls.map(v=>v[2])).toEqual(['direct-import-applied','snapshot-rollback-applied']);expect(h.state.directTransfer.importJobId).toBe(imported.jobId);
 });
 for(const changed of['actor','cluster','workspace','kind','state','fiveClasses','alreadyDone'])it(`rejects ${changed} before any new write`,async()=>{
  const{h,actors,imported}=fixture();if(changed==='actor')imported.actorId=randomUUID();if(changed==='cluster')imported.clusterId=randomUUID();if(changed==='workspace')imported.workspaceId=randomUUID();if(changed==='kind')imported.kind='apply';if(changed==='state')imported.state='failed';if(changed==='fiveClasses')h.state.fiveClassRecovery=[];if(changed==='alreadyDone')h.state.directTransfer={};
  await expect(finishM8DirectImportRollback(h,actors,imported)).rejects.toThrow();expect(cfg.configurationWrite).not.toHaveBeenCalled();
 });
 it('wrong real apply readback stops before creating a rollback plan',async()=>{const{h,actors,imported}=fixture('wrongApply');await expect(finishM8DirectImportRollback(h,actors,imported)).rejects.toThrow();expect(cfg.configurationWrite).toHaveBeenCalledTimes(1);expect(native.sixCredentialProxyAcceptance).not.toHaveBeenCalled();expect(h.state.directTransfer).toBeUndefined();});
 it('wrong rollback readback cannot claim credential recovery or a completed transfer',async()=>{const{h,actors,imported}=fixture('wrongRollback');await expect(finishM8DirectImportRollback(h,actors,imported)).rejects.toThrow();expect(native.sixCredentialProxyAcceptance).toHaveBeenCalledTimes(1);expect(h.state.directTransfer).toBeUndefined();});
 it('unknown new apply sends no follow-up rollback request and never retries it',async()=>{const{h,actors,imported}=fixture('unknown');await expect(finishM8DirectImportRollback(h,actors,imported)).rejects.toThrow('ORIGINAL_UNKNOWN');expect(cfg.configurationWrite).toHaveBeenCalledTimes(1);expect(native.nativeRead).not.toHaveBeenCalled();});
});
