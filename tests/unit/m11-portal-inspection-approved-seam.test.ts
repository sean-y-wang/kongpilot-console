import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {performance} from 'node:perf_hooks';
import {portalInspectionApprovedSeamFixture} from './helpers/m11-portal-inspection-approved-seam-fixture';

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-18T11:00:00Z'));});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});

describe('same-source genuine Authority/Namespace/Context/Approved Portal inspection seam, controlled SQL and subject adapters, no Native send',()=>{
 it('loads and consumes the true current private namespace inspection in the actual Approved operation',async()=>{
  const f=portalInspectionApprovedSeamFixture();await f.run(async()=>{
   const before={...f.scan};await f.verify();
   expect(f.canonicalLoad).toHaveBeenCalled();expect(f.consume).toHaveBeenCalled();
   expect(f.scan.executor).toBe(before.executor+1);
   expect(f.scan.reviewer).toBe(before.reviewer+3);
   expect(f.context.currentApprovedStep().execution.sessionId).toBeNull();
  });
  expect(f.kong.request.mock.calls.every(([,method]:any)=>method==='GET')).toBe(true);
 });
 it('freshly checks every real before-send checkpoint while avoiding the repeated same-checkpoint subject scan',async()=>{
  const f=portalInspectionApprovedSeamFixture();await f.run(async()=>{
   const count=f.consume.mock.calls.length,before={...f.scan};await f.verifyNative();
   expect(f.consume.mock.calls.length).toBeGreaterThan(count);
   const calls=f.consume.mock.calls.slice(count);expect(calls.every(call=>call[2]==='before-send')).toBe(true);
   expect(f.scan.executor-before.executor).toBe(calls.length);expect(f.scan.reviewer-before.reviewer).toBe(calls.length*3);
   const middle={...f.scan};await f.verify();expect(f.scan.executor).toBe(middle.executor+1);expect(f.scan.reviewer).toBe(middle.reviewer+3);
  });
 });
 it.each(['membership','approval','reviewer','IAM','requester','grants','lease'] as const)('denies current %s changes between genuine fresh inspection and its actual SQL closing',async(reason)=>{
  const f=portalInspectionApprovedSeamFixture();let entered=false;
  await expect(f.run(async()=>{entered=true;f.flags.beforeConsume=()=>{
   if(reason==='membership')f.flags.membershipRevoked=true;
   else if(reason==='approval')f.flags.approvalChanged=true;
   else if(reason==='reviewer')f.state.reviewerActive=false;
   else if(reason==='IAM')f.state.principalVersion='2';
   else if(reason==='requester')f.state.requesterActive=false;
   else if(reason==='grants')f.flags.grantsChanged=true;
   else f.state.lease=false;
  };await f.verify();})).rejects.toBeDefined();expect(entered).toBe(true);
 });
 it.each(['permission-version','lease','deadline'] as const)('denies %s changed after the real consume during the awaited Approved closing tail',async(reason)=>{
  const f=portalInspectionApprovedSeamFixture();let consumed=false;
  await expect(f.run(async()=>{f.flags.afterConsume=async()=>{consumed=true;await Promise.resolve();
   if(reason==='permission-version')f.state.principalVersion='2';else if(reason==='lease')f.state.lease=false;
   else vi.setSystemTime(new Date(f.draft.spec.windowEnd));
  };await f.verify();})).rejects.toBeDefined();expect(consumed).toBe(true);
 });
 it('rejects a copied actual execution proof before any new canonical load or inspection consume',async()=>{
  const f=portalInspectionApprovedSeamFixture();await f.run(async()=>{
   const before=f.consume.mock.calls.length,loads=f.canonicalLoad.mock.calls.length;
   await expect(f.approved.verifyWorkflowScheduledExecution({...f.context.currentApprovedStep().execution},f.originalNamespaceHandle())).rejects.toBeDefined();
   expect(f.consume.mock.calls.length).toBe(before);expect(f.canonicalLoad.mock.calls.length).toBe(loads);
  });
 });
 it('cannot continue a deferred SQL-only load when the exact same-frame one-shot inspection was already consumed',async()=>{
  const f=portalInspectionApprovedSeamFixture();let closed=false;
  await expect(f.run(async()=>{f.flags.beforeConsume=async()=>{if(closed)return;closed=true;
   const [handle,proof,checkpoint,tx]=f.consume.mock.calls.at(-1)??[];
   expect(handle).toBe(f.originalNamespaceHandle());
   expect(await f.namespace.consumeFreshPortalInspection(handle,proof,checkpoint,tx)).toEqual({approvalSet:f.approvalSet});
  };await f.verify();})).rejects.toBeDefined();expect(closed).toBe(true);
 });
 it.each(['user','team'] as const)('keeps genuine %s binding provenance current through a real successful consume',async(kind)=>{
  const f=portalInspectionApprovedSeamFixture();f.flags.bindingKind=kind;
  await f.run(async()=>{f.flags.bindingExpiresAt=new Date(Date.now()+60000).toISOString();const before=f.consume.mock.calls.length;
   await f.verify();expect(f.consume.mock.calls.length).toBe(before+1);expect(f.context.current().kind).toBe('operation');
  });
 });
 it.each(['user','team'] as const)('rejects naturally expired %s binding while the same-source all-party checkpoint closes',async(kind)=>{
  const f=portalInspectionApprovedSeamFixture();f.flags.bindingKind=kind;let reached=false;
  await expect(f.run(async()=>{f.flags.bindingExpiresAt=new Date(Date.now()+50).toISOString();
   f.flags.beforeConsume=async()=>{reached=true;await Promise.resolve();vi.setSystemTime(new Date(Date.now()+51));};await f.verify();
  })).rejects.toBeDefined();expect(reached).toBe(true);
 });
 it.each(['user','team'] as const)('retains the original %s binding monotonic deadline through the awaited tail after actual consume',async(kind)=>{
  const f=portalInspectionApprovedSeamFixture();f.flags.bindingKind=kind;let consumed=false;
  await expect(f.run(async()=>{f.flags.bindingExpiresAt=new Date(Date.now()+50).toISOString();
   f.flags.afterConsume=async()=>{consumed=true;await Promise.resolve();const time=performance.now();vi.spyOn(performance,'now').mockReturnValue(time+51);};await f.verify();
  })).rejects.toBeDefined();expect(consumed).toBe(true);
 });
});
