import {expect,it,vi} from 'vitest';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

/** Regression for the preparation wrapper only. Policy issuers are explicit
 * controlled adapters; this is not Portal eligibility or SDK acceptance. */
async function withScheduledExecutionRead(fn:(context:KongExecutionContextService,ticket:any)=>Promise<void>){
 const context=new KongExecutionContextService(),namespaceHandle=Object.freeze({}),executionHandle=Object.freeze({});
 const namespace:any=Object.freeze({version:1,origin:'scheduled-workflow',sessionId:null,actor:Object.freeze({id:'executor'}),
  clusterId:'cluster',workspaceId:'workspace',kind:'configuration_v2',permissionVersion:'current',workflow:{id:'workflow'},claim:{id:'claim'},expiresAt:new Date(Date.now()+60000).toISOString()});
 const execution:any=Object.freeze({executionId:'execution',workflowId:'workflow',actorId:'executor',clusterId:'cluster',workspaceId:'workspace',
  sessionId:null,origin:'scheduled-workflow',scheduleClaimId:'claim',permissionVersion:'current',expiresAt:Date.now()+30000});
 const assertNative=vi.fn(async()=>{}),verifyStep=vi.fn(async()=>{throw Error('READ_MUST_NOT_REQUIRE_STEP');});
 context.installWorkflowScheduledNamespacePolicy({assertLive(handle){expect(handle).toBe(namespaceHandle);},async verifyHandle(handle){expect(handle).toBe(namespaceHandle);return namespace;}});
 context.installApprovedPolicy({async verifyExecution(handle:object){expect(handle).toBe(executionHandle);return execution;},
  async verifyWorkflowScheduledExecution(proof:object,handle:object){expect(proof).toBe(execution);expect(handle).toBe(namespaceHandle);},
  verifyStep,assertNative,async mutationBinding(){},async bindOperation(){},async assertMetadata(){} } as any);
 context.installPolicy({async authorizeRequest(){return{platformAdmin:true};},async authorizeResponse(_ticket,result){return result;}});
 await context.runWorkflowScheduledNamespace(namespaceHandle,()=>context.runApprovedWorkflow(executionHandle as any,()=>
  context.runInternalRead('cluster','capture',async()=>{
   const ticket=await context.authorizeRequest({id:'cluster',admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'approval'},'GET','/services/example',undefined,{});
   await fn(context,ticket);
   await expect(context.authorizeResponse(ticket,{id:'example'})).resolves.toEqual({id:'example'});
  },{paths:['/services/example'],maxCalls:2})));
 expect(verifyStep).not.toHaveBeenCalled();expect(assertNative).not.toHaveBeenCalled();
}
it('refreshes an original early scheduled GET before a Native Step exists',async()=>{
 await withScheduledExecutionRead(async(context,ticket)=>{
  expect(context.scheduledPortalPreparationPhase()).toBeNull();await context.refreshAuthorization(ticket);
  expect(context.scheduledPortalFinalNativePhase()).toBeNull();
 });
});
it('keeps a readonly ticket outside the Portal physical final proof',async()=>{
 await withScheduledExecutionRead(async(context,ticket)=>{
  await context.prepareNativeSend(ticket);expect(context.scheduledPortalFinalNativePhase()).toBeNull();
 });
});
