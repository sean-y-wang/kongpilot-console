import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {approvedOriginalDeadlineFixture} from './helpers/m11-approved-original-deadline-fixture';
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-18T09:00:00Z'));});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllEnvs();});
/** Actual Authority/Namespace/Approved private handles and Context, real AEAD
 * plans; controlled SQL/approval/business registries, no HTTP/native send. */
describe('original Authority to Approved execution absolute deadline',()=>{
 it.each(['configuration_v2','portal-credential-issue'] as const)('retains %s original absolute expiry through the real Approved proof',async kind=>{
  const f=approvedOriginalDeadlineFixture(kind);let actual:any;
  await f.run(async()=>{actual=f.proof();const ns=await f.namespaces.verifyHandle(f.originalHandle(),'step');
   expect(actual.expiresAt).toBe(Date.parse(ns.expiresAt));expect(actual.expiresAt-Date.now()).toBe(240000);
   vi.advanceTimersByTime(120001);expect(f.context.current().actor?.id).toBe(f.actor.id);
   await f.verifier.verifyWorkflowScheduledExecution(actual,f.originalHandle());
   expect(actual.sessionId).toBeNull();expect(f.context.current().sessionId).toBeUndefined();
  });
  await expect(f.verifier.verifyWorkflowScheduledExecution(actual,f.originalHandle())).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED'}});
 });
 it.each(['configuration_v2','portal-credential-issue'] as const)('does not renew %s during delayed Approved entry',async kind=>{
  const f=approvedOriginalDeadlineFixture(kind);f.state.beforeApproved=async()=>{vi.advanceTimersByTime(200000);};
  await f.run(async()=>{expect(f.proof().expiresAt-Date.now()).toBe(40000);expect(f.context.current().limits.timeoutMs).toBe(40000);
   vi.advanceTimersByTime(10000);await f.verifier.verifyWorkflowScheduledExecution(f.proof(),f.originalHandle());
  });
 });
 it.each(['configuration_v2','portal-credential-issue'] as const)('cannot consume a copied %s proof or namespace after a fresh grant check',async kind=>{
  const f=approvedOriginalDeadlineFixture(kind);await f.run(async()=>{
   await expect(f.verifier.verifyWorkflowScheduledExecution({...f.proof()},f.originalHandle())).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED'}});
   await expect(f.verifier.verifyWorkflowScheduledExecution(f.proof(),{...f.originalHandle()})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED'}});
  });
 });
 it.each(['configuration_v2','portal-credential-issue'] as const)('keeps a shorter genuine %s execution expiry as an ancestor bound',async kind=>{
  const f=approvedOriginalDeadlineFixture(kind);f.state.executionRemainingMs=180000;
  await f.run(async()=>{expect(f.proof().expiresAt-Date.now()).toBe(180000);expect(f.context.current().limits.timeoutMs).toBe(240000);
   vi.advanceTimersByTime(150000);const parent=f.context.current();await f.context.runActor({actor:parent.actor!,clusterId:f.cid,workspaceId:f.wid},async()=>{
    expect(f.context.current().limits.timeoutMs).toBe(30000);await f.verifier.verifyWorkflowScheduledExecution(f.proof(),f.originalHandle());
   });
  });
 });
 it.each(['configuration_v2','portal-credential-issue'] as const)('closes %s original proof on callback failure',async kind=>{
  const f=approvedOriginalDeadlineFixture(kind);let proof:any;
  await expect(f.run(async()=>{proof=f.proof();throw Error('CONTROLLED_BUSINESS_CALLBACK_FAILURE');})).rejects.toThrow('CONTROLLED_BUSINESS_CALLBACK_FAILURE');
  await expect(f.verifier.verifyWorkflowScheduledExecution(proof,f.originalHandle())).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED'}});
  expect(f.context.peek()).toBeNull();expect(f.original.repository.finishClaim).not.toHaveBeenCalled();
 });
 it.each(['configuration_v2','portal-credential-issue'] as const)('does not survive the %s exact original execution deadline',async kind=>{
  const f=approvedOriginalDeadlineFixture(kind);f.state.executionRemainingMs=180000;
  await expect(f.run(async()=>{vi.advanceTimersByTime(180001);f.context.current();})).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
  expect(f.original.repository.finishClaim).not.toHaveBeenCalled();
 });
 it('keeps the genuine Portal Native Step, Mutation actor, operation and final fresh checks past 120 seconds',async()=>{
  const f=approvedOriginalDeadlineFixture('portal-credential-issue');f.rows[0].state='running';
  await f.run(()=>f.context.runApprovedStep(f.rows[0].id,async()=>{
   vi.advanceTimersByTime(120001);const mutation=f.nativeContext(),step=f.context.currentApprovedStep();
   await f.context.runMutationActor(mutation,async()=>{
    expect(f.context.current().limits.timeoutMs).toBe(119999);
    const binding=await f.context.approvedMutationBinding(mutation),op=f.operation();expect(binding).not.toBeNull();
    await f.context.bindApprovedOperation(mutation,binding!,op.id,f.db);op.remote_started=true;
    await f.context.runOperation({...mutation,operationId:op.id},async()=>{
     const request=f.plan.steps[0].nativeRequests[0];
     await f.verifier.assertNative(step,{clusterId:f.cid,workspaceId:f.wid,transportScope:f.plan.scope.transportScope,operationId:op.id,
      method:request.method,canonicalPath:request.canonicalPath,body:request.body,before:null,mutationAction:'create',frame:f.context.current(),cluster:f.cluster,query:{}},'before-send');
     expect(f.context.current().limits.timeoutMs).toBe(119999);
    });
   });
  }));expect(f.state.validationRoles.some((r:any)=>r.role==='reviewer')).toBe(true);expect(f.kong.request.mock.calls.every(call=>call[1]==='GET')).toBe(true);
 });
});
