import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {portalInspectionApprovedSeamFixture} from './helpers/m11-portal-inspection-approved-seam-fixture';
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
function packet(f:ReturnType<typeof portalInspectionApprovedSeamFixture>){const frame=f.context.current(),request=f.plan.steps[0].nativeRequests[0];return{clusterId:f.cid,workspaceId:f.wid,transportScope:f.plan.scope.transportScope,operationId:frame.operation!.operationId,method:request.method,canonicalPath:request.canonicalPath,body:request.body,before:null,mutationAction:f.plan.steps[0].mutationAction};}
describe('Portal entry and boundary avoid discarded full-checkpoint traversals only',()=>{
 it('retains both real before-send all-party checkpoints while avoiding the extra Portal-kind-only step scan',async()=>{
  const f=portalInspectionApprovedSeamFixture();await f.run(async()=>{
   const prior=f.consume.mock.calls.length,before={...f.scan};await f.approved.assertNativeWrite(packet(f) as any);
   const fresh=f.consume.mock.calls.slice(prior);expect(fresh.map(x=>x[2])).toEqual(['before-send','before-send']);
   expect(f.scan.executor-before.executor).toBe(2);expect(f.scan.reviewer-before.reviewer).toBe(6);
  });
 });
 it.each(['requester','IAM','approval','lease'])('denies %s revoked during the cluster SQL await before the retained true native checkpoint',async reason=>{
  const f=portalInspectionApprovedSeamFixture();let entered=false;
  await expect(f.run(async()=>{const prior=f.db.one.getMockImplementation()!;f.db.one.mockImplementation(async(sql:string,args:any[])=>{
   const row=await prior(sql,args);if(sql.startsWith('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL')){
    entered=true;if(reason==='requester')f.state.requesterActive=false;else if(reason==='IAM')f.state.principalVersion='2';else if(reason==='approval')f.flags.approvalChanged=true;else f.state.lease=false;
   }return row;
  });await f.approved.assertNativeWrite(packet(f) as any);})).rejects.toBeDefined();expect(entered).toBe(true);
 });
 it('retains the second genuine current checkpoint after prerequisites and rejects revocation across that await',async()=>{
  const f=portalInspectionApprovedSeamFixture();let consumed=0;
  await expect(f.run(async()=>{f.flags.afterConsume=async()=>{if(++consumed===1){await Promise.resolve();f.state.requesterActive=false;}};await f.approved.assertNativeWrite(packet(f) as any);})).rejects.toBeDefined();expect(consumed).toBe(1);
 });
});
