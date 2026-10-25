import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {performance} from 'node:perf_hooks';
import {portalInspectionApprovedSeamFixture} from './helpers/m11-portal-inspection-approved-seam-fixture';
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
function fixture(){const f=portalInspectionApprovedSeamFixture(),verifier=f.approved.installPortalInspectionInvocationVerifier();f.authority.installPortalInspectionInvocationVerifier(verifier);return{...f,verifier};}
describe('genuine Portal execution/Step private invocations consume current same-frame inspections',()=>{
 it('uses canonical SQL loads and real all-party checks for original execution/Step entries without lending the capability outside its invocation',async()=>{
  const f=fixture(),selected:any[]=[],read=f.authority.readPortalOperationApprovalSet.bind(f.authority);
  vi.spyOn(f.authority,'readPortalOperationApprovalSet').mockImplementation(async(...args:any[])=>{const value=f.verifier.current();expect(value).not.toBeNull();selected.push(value);return(read as any)(...args);});
  await f.run(async()=>{await f.verify();await f.verifyNative();});
  expect(selected.some(s=>s.frame.kind==='scheduled-workflow'&&s.step===null)).toBe(true);expect(selected.some(s=>s.frame.kind==='actor'&&s.step)).toBe(true);
  expect(f.verifier.current()).toBeNull();for(const value of selected)expect(()=>f.verifier.assert(value)).toThrow();
 });
 it('keeps a Namespace-only entry without an issued private execution on the original full path',async()=>{
  const f=fixture(),load=(f.approved as any).load.bind(f.approved);let checked=false;
  vi.spyOn(f.approved as any,'load').mockImplementation(async(...args:any[])=>{
   if(!checked&&f.context.peek()?.kind==='scheduled-workflow'){checked=true;expect(f.verifier.current()).toBeNull();
    const handle=f.context.requireWorkflowScheduledNamespaceHandle();expect(await f.namespace.readPortalOperationApprovalSet(f.plan,f.e.id,handle,f.db)).toBeNull();}
   return load(...args);
  });await f.run(async()=>{await f.verify();});expect(checked).toBe(true);
 });
 it('does not accept a copied selector, execution proof, or a retained selection after its finally closes',async()=>{
  const f=fixture();await f.run(async()=>{const proof=f.context.currentApprovedStep().execution;
   await expect(f.approved.verifyWorkflowScheduledExecution({...proof},f.originalNamespaceHandle())).rejects.toBeDefined();expect(f.verifier.current()).toBeNull();
   let original:any;f.flags.beforeConsume=()=>{original=f.verifier.current();expect(original).not.toBeNull();expect(()=>f.verifier.assert({...original})).toThrow();};await f.verify();
   expect(()=>f.verifier.assert(original)).toThrow();
  });
 });
 it.each(['membership','approval','reviewer','IAM','requester','grants','lease'])('retains current %s rejection between actual all-party reads and SQL closing',async reason=>{
  const f=fixture();let entered=false;await expect(f.run(async()=>{f.flags.beforeConsume=()=>{entered=true;
   if(reason==='membership')f.flags.membershipRevoked=true;else if(reason==='approval')f.flags.approvalChanged=true;else if(reason==='reviewer')f.state.reviewerActive=false;
   else if(reason==='IAM')f.state.principalVersion='2';else if(reason==='requester')f.state.requesterActive=false;else if(reason==='grants')f.flags.grantsChanged=true;else f.state.lease=false;
  };await f.verify();})).rejects.toBeDefined();expect(entered).toBe(true);
 });
 it('cannot consume an original inspection at a different checkpoint',async()=>{
  const f=fixture();await expect(f.run(async()=>{f.flags.beforeConsume=async()=>{const[h,ns,checkpoint,tx]=f.consume.mock.calls.at(-1)!;
   expect(checkpoint).toBe('before-send');await f.namespace.consumeFreshPortalInspection(h,ns,'packet',tx);
  };await f.verifyNative();})).rejects.toBeDefined();
 });
 it('cannot enter another private invocation from a currently active invocation continuation',async()=>{
  const f=fixture();await expect(f.run(async()=>{f.flags.beforeConsume=()=>f.verify();await f.verify();})).rejects.toBeDefined();
 });
 it.each(['user','team']as const)('retains the original %s binding deadline after the actual SQL consume completes',async kind=>{
  // The original 50ms binding must still be live at SQL consume. Advance only
  // after that real callback, independently of runner CPU speed.
  vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(new Date('2026-10-20T00:00:00Z'));
  let monotonic=10000;vi.spyOn(performance,'now').mockImplementation(()=>monotonic);
  const f=fixture();f.flags.bindingKind=kind;let consumed=false;await expect(f.run(async()=>{
   f.flags.bindingExpiresAt=new Date(Date.now()+50).toISOString();f.flags.afterConsume=async()=>{consumed=true;monotonic+=51;};await f.verify();
  })).rejects.toBeDefined();expect(consumed).toBe(true);
 });
 it('rejects an actor SID injected across a genuine private invocation await',async()=>{
  const f=fixture();await expect(f.run(async()=>{f.flags.beforeConsume=()=>{(f.context.current() as any).sessionId='foreign-source-session';};await f.verify();})).rejects.toBeDefined();
 });
 it.each(['loader','consume'])('cannot borrow a foreign transaction for the %s of an actual private invocation',async which=>{
  const f=fixture();await expect(f.run(async()=>{f.flags.beforeConsume=async()=>{
   const[h,ns,checkpoint]=f.consume.mock.calls.at(-1)!;
   if(which==='consume')await f.namespace.consumeFreshPortalInspection(h,ns,checkpoint,{...f.db});
   else await f.namespace.readPortalOperationApprovalSet(f.plan,f.e.id,h,{...f.db});
  };await f.verify();})).rejects.toBeDefined();
 });

 it('does not use a different privately minted Step while the current original Step is active',async()=>{
  const f=fixture();await f.run(async()=>{f.rows[1].state='running';const before=f.canonicalLoad.mock.calls.length;
   await expect(f.approved.verifyStep(f.context.currentApprovedStep().execution,f.plan.steps[1].id)).rejects.toBeDefined();expect(f.canonicalLoad).toHaveBeenCalledTimes(before);
  });
 });
 it('does not let an earlier invocation consume the later concurrent invocation inspection',async()=>{
  const f=fixture();let enter!:()=>void,release!:()=>void;const entered=new Promise<void>(done=>enter=done),held=new Promise<void>(done=>release=done);let calls=0;
  await f.run(async()=>{f.flags.beforeConsume=async()=>{if(++calls===1){enter();await held;}};
   const first=f.verify();await entered;await f.verify();release();await expect(first).rejects.toBeDefined();
  });expect(calls).toBe(2);
 });

});
