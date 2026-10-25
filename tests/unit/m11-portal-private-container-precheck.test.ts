import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {performance} from 'node:perf_hooks';
import {portalContainerInspectionFixture} from './helpers/m11-portal-container-inspection-fixture';
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
function fixture(metadata=false){const f=portalContainerInspectionFixture(metadata),verifier=f.approved.installPortalInspectionInvocationVerifier();f.authority.installPortalInspectionInvocationVerifier(verifier);return{...f,verifier};}
describe('original private Execution and NativeStep containers have SQL prechecks without Native permits',()=>{
 it('keeps an issued execution container on current SQL while retaining its genuine private invocation',async()=>{
  const f=fixture();await f.run(async()=>{const before={...f.scan};let original:any;f.flags.beforeConsume=()=>{original=f.verifier.current();expect(original?.execution).toBe(f.context.currentApprovedStep().execution);};
   await f.verify();expect(f.scan).toEqual(before);expect(original).toBeDefined();expect(()=>f.verifier.assert(original)).toThrow();
  });
 });
 it('keeps NativeStep packet and private mutation-binding checks on current SQL, but real final send and response each require fresh SDK checks',async()=>{
  const f=fixture();await f.run(async()=>{const proof=f.context.currentApprovedStep(),frame=f.context.current(),step=f.plan.steps[0],request=step.nativeRequests[0],before={...f.scan};
   await f.verifyNative('packet');expect(f.scan).toEqual(before);
   const mutation:any={actor:frame.actor,clusterId:f.cid,workspaceId:f.wid,entityType:step.entityType,entityId:step.entityId,action:step.mutationAction,payload:step.mutationPayload,before:null,idempotencyKey:step.mutationIdempotencyKey};
   const binding=await f.approved.mutationBinding(proof,mutation);expect(binding.executionId).toBe(proof.execution.executionId);expect(f.scan).toEqual(before);
   const cluster={id:f.cid,admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'approval',revision:1},ticket=await f.context.authorizeRequest(cluster,'POST',request.canonicalPath,request.body,{}),prior={...f.scan};
   await f.context.beforeNativeSend(ticket);expect(f.scan.executor-prior.executor).toBe(1);expect(f.scan.reviewer-prior.reviewer).toBe(3);
   const sent={...f.scan};await f.context.authorizeResponse(ticket,{...request.body});expect(f.scan.executor-sent.executor).toBe(1);expect(f.scan.reviewer-sent.reviewer).toBe(3);
  });
 });
 it('never selects SQL container checks for a real current Metadata Step',async()=>{
  const f=fixture(true);await f.run(async()=>{expect(f.context.currentApprovedStep().kind).toBe('metadata');const before={...f.scan};await f.verify();
   expect(f.scan.executor-before.executor).toBe(1);expect(f.scan.reviewer-before.reviewer).toBe(3);
  });
 });
 it.each(['membership','approval','requester','reviewer','IAM','grants','lease'])('rejects current %s revocation while a container SQL inspection closes',async reason=>{
  const f=fixture();let entered=false;await expect(f.run(async()=>{f.flags.beforeConsume=()=>{entered=true;
   if(reason==='membership')f.flags.membershipRevoked=true;else if(reason==='approval')f.flags.approvalChanged=true;else if(reason==='requester')f.state.requesterActive=false;
   else if(reason==='reviewer')f.state.reviewerActive=false;else if(reason==='IAM')f.state.principalVersion='2';else if(reason==='grants')f.flags.grantsChanged=true;else f.state.lease=false;
  };await f.verify();})).rejects.toBeDefined();expect(entered).toBe(true);
 });
 it.each(['user','team']as const)('keeps the original %s binding monotonic MIN after a SQL container await',async kind=>{
  const f=fixture();f.flags.bindingKind=kind;let entered=false;await expect(f.run(async()=>{f.flags.bindingExpiresAt=new Date(Date.now()+5000).toISOString();
   f.flags.afterConsume=()=>{entered=true;const now=performance.now();vi.spyOn(performance,'now').mockReturnValue(now+5001);};await f.verify();
  })).rejects.toBeDefined();expect(entered).toBe(true);
 });
 it('does not allow copied execution or private mutation binding inputs to borrow the SQL container',async()=>{
  const f=fixture();await f.run(async()=>{const proof=f.context.currentApprovedStep(),before=f.canonicalLoad.mock.calls.length;
   await expect(f.approved.verifyWorkflowScheduledExecution({...proof.execution},f.originalNamespaceHandle())).rejects.toBeDefined();expect(f.canonicalLoad).toHaveBeenCalledTimes(before);
   await expect(f.approved.mutationBinding({...proof},{}as any)).rejects.toBeDefined();expect(f.canonicalLoad).toHaveBeenCalledTimes(before);
  });
 });
});
