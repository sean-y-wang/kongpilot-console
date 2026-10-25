import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {performance} from 'node:perf_hooks';
import {portalInspectionProducerFixture} from './helpers/m11-portal-inspection-producer-fixture';
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-18T11:00:00Z'));});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});

describe('Portal fresh Authority inspection: real original Namespace/Context; controlled SQL/subject adapters',()=>{
 it('consumes the exact fresh result once with zero second subject scans and keeps next checkpoint fresh',async()=>{
  const f=portalInspectionProducerFixture();await f.run(async(handle,ns)=>{
   const start={...f.scan};await f.context.verifyWorkflowScheduledNamespace('packet');
   expect(f.scan.executor).toBe(start.executor+1);expect(f.scan.reviewer).toBe(start.reviewer+3);
   const before={...f.scan};expect(await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db)).toEqual({approvalSet:f.approvalSet});
   expect(f.scan).toEqual(before);expect(await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db)).toBeNull();
   await f.context.verifyWorkflowScheduledNamespace('before-send');expect(f.scan.executor).toBe(before.executor+1);expect(f.scan.reviewer).toBe(before.reviewer+3);
   expect(await f.namespace.consumeFreshPortalInspection(handle,ns,'before-send',f.db)).toEqual({approvalSet:f.approvalSet});
  });
 });
 it('does not invoke the old full reviewer policy inside the same Portal operation checkpoint',async()=>{
  const f=portalInspectionProducerFixture();await f.run(async()=>{
   f.approvals.verifyApprovalSet.mockClear();f.approvals.installScheduledPortalInspectionSqlReader.mockClear();
   const before={...f.scan};await f.context.verifyWorkflowScheduledNamespace('packet');
   expect(f.approvals.verifyApprovalSet).not.toHaveBeenCalled();expect(f.scan.executor).toBe(before.executor+1);expect(f.scan.reviewer).toBe(before.reviewer+3);
  });
 });
 it.each(['membership','approval','reviewer','IAM','requester']as const)('closes %s changes during the final genuine subject reviewer scan',async reason=>{
  const f=portalInspectionProducerFixture();await expect(f.run(async()=>{
   const original=f.policy.assertReviewer.getMockImplementation()!;let visited=0;
   f.policy.assertReviewer.mockImplementation(async(...args:any[])=>{await original(...args);if(++visited===3){
    if(reason==='membership')f.flags.membershipRevoked=true;else if(reason==='approval')f.flags.approvalChanged=true;
    else if(reason==='reviewer')f.state.reviewerActive=false;else if(reason==='IAM')f.state.principalVersion='2';else f.state.requesterActive=false;
   }});
   await f.context.verifyWorkflowScheduledNamespace('packet');
  })).rejects.toBeDefined();
 });
 it.each(['namespace-copy','proof-copy','checkpoint']as const)('rejects %s rather than lending a pending inspection',async reason=>{
  const f=portalInspectionProducerFixture();await expect(f.run(async(handle,ns)=>{
   await f.context.verifyWorkflowScheduledNamespace('packet');
   await f.namespace.consumeFreshPortalInspection(reason==='namespace-copy'?{...handle}:handle,reason==='proof-copy'?{...ns}:ns,reason==='checkpoint'?'before-send':'packet',f.db);
  })).rejects.toBeDefined();
 });
 it.each(['owner-disabled','credential-epoch','permission-version','reviewer-disabled','membership','grants','approval','cancelled','requester','transport','lease','deadline']as const)('SQL closing denies current %s after the genuine source checkpoint',async reason=>{
  const f=portalInspectionProducerFixture();await expect(f.run(async(handle,ns)=>{
   await f.context.verifyWorkflowScheduledNamespace('packet');const before={...f.scan};
   if(reason==='owner-disabled')f.state.ownerActive=false;
   else if(reason==='credential-epoch')f.state.epoch='2';
   else if(reason==='permission-version')f.state.principalVersion='2';
   else if(reason==='reviewer-disabled')f.state.reviewerActive=false;
   else if(reason==='membership')f.flags.membershipRevoked=true;
   else if(reason==='grants')f.flags.grantsChanged=true;
   else if(reason==='approval')f.flags.approvalChanged=true;
   else if(reason==='cancelled')f.state.workflowState='cancelled';
   else if(reason==='requester')f.state.requesterActive=false;
   else if(reason==='transport')f.state.directMode=true;
   else if(reason==='lease')f.state.lease=false;
   else vi.setSystemTime(new Date(f.draft.spec.windowEnd));
   try{await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db);}finally{expect(f.scan).toEqual(before);}
  })).rejects.toBeDefined();
 });
 it('denies monotonic grant-window expiry without renewing the original claim',async()=>{
  const f=portalInspectionProducerFixture();await expect(f.run(async(handle,ns)=>{
   await f.context.verifyWorkflowScheduledNamespace('packet');const time=performance.now();vi.spyOn(performance,'now').mockReturnValue(time+30001);
   await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db);
  })).rejects.toBeDefined();
 });
 it('loads only the current SQL set for the real original native Step and then still requires a fresh full checkpoint',async()=>{
  const f=portalInspectionProducerFixture();await f.run(async(handle,ns)=>{
   const before={...f.scan};expect(await f.namespace.readPortalOperationApprovalSet(f.plan,f.executionId,handle,f.db)).toEqual(f.approvalSet);expect(f.scan).toEqual(before);
   expect(await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db)).toBeNull();
   await f.context.verifyWorkflowScheduledNamespace('packet');expect(f.scan.executor).toBe(before.executor+1);
   expect(await f.namespace.consumeFreshPortalInspection(handle,ns,'packet',f.db)).toEqual({approvalSet:f.approvalSet});
  });
 });
 it('cannot load a set for another execution or changed sealed plan',async()=>{
  const f=portalInspectionProducerFixture();await f.run(async(handle)=>{
   await expect(f.namespace.readPortalOperationApprovalSet(f.plan,'10000000-0000-4000-8000-000000000001',handle,f.db)).rejects.toBeDefined();
   await expect(f.namespace.readPortalOperationApprovalSet({...f.plan,planRevision:2},f.executionId,handle,f.db)).rejects.toBeDefined();
  });
 });
});
