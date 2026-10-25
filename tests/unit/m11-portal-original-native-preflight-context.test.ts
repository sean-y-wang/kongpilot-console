import {expect,it,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';

/** Context capability contract only. Namespace/Approved policy issuers and SQL
 * are controlled adapters; all frame/ticket/phase issuance is the actual Context
 * public fixed invocation path. No SDK/native/whole-business acceptance. */
function fixture(){
 const context=new KongExecutionContextService(),namespaceHandle=Object.freeze({}),executionHandle=Object.freeze({}),parentId='00000000-0000-4000-8000-000000000011';
 const cluster={id:'cluster',admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'approval',revision:1};
 const actor={id:'executor'},namespace:any=Object.freeze({version:1,origin:'scheduled-workflow',sessionId:null,actor,clusterId:'cluster',workspaceId:'workspace',kind:'portal-credential-issue',
  permissionVersion:'current',workflow:{id:'workflow'},claim:{id:'claim'},expiresAt:new Date(Date.now()+60000).toISOString(),transportScope:transportScopeFor(cluster.admin_url)});
 const execution:any=Object.freeze({executionId:'execution',workflowId:'workflow',actorId:'executor',clusterId:'cluster',workspaceId:'workspace',sessionId:null,
  origin:'scheduled-workflow',scheduleClaimId:'claim',permissionVersion:'current',expiresAt:Date.now()+30000});
 const step:any=Object.freeze({execution,stepId:'step',kind:'native'});
 let hook:(...args:any[])=>Promise<unknown>=async()=>({}),captured:any;const gets:any[]=[],markers:any[]=[];
 context.installWorkflowScheduledNamespacePolicy({assertLive(handle){expect(handle).toBe(namespaceHandle);},async verifyHandle(handle){expect(handle).toBe(namespaceHandle);return namespace;}});
 context.installApprovedPolicy({async verifyExecution(handle:object){expect(handle).toBe(executionHandle);return execution;},async verifyWorkflowScheduledExecution(proof:object,handle:object){expect(proof).toBe(execution);expect(handle).toBe(namespaceHandle);},
  async verifyStep(proof:object,id:string){expect(proof).toBe(execution);expect(id).toBe('step');return step;},async mutationBinding(){},async bindOperation(){},async assertNative(){},async assertMetadata(){} }as any);
 context.installPolicy({async authorizeRequest(frame,c,method,path,body,query){
  if(method==='GET'){gets.push({path,phase:context.scheduledPortalPreparationPhase(),frame});return{};}
  captured=context.scheduledPortalPreparationPhase();return hook(frame,c,method,path,body,query);
 },async authorizeResponse(_ticket,result){return result;}});
 const run=async(fn:()=>Promise<void>)=>context.runWorkflowScheduledNamespace(namespaceHandle,()=>context.runApprovedWorkflow(executionHandle as any,()=>
  context.runApprovedStep('step',()=>{
   const mutation:any={actor,clusterId:'cluster',workspaceId:'workspace',entityType:'credentials',action:'create',parentId,credentialKind:'acls',payload:{id:'credential',group:'team'},before:null};
   expect(context.isOriginalPortalNativeMutationFrame(context.current())).toBe(false);
   return context.runMutationActor(mutation,()=>{
    const frame=context.current();markers.push(frame);expect(frame.action).toBe('create');expect(context.isOriginalPortalNativeMutationFrame(frame)).toBe(true);
    expect(context.isOriginalPortalNativeMutationFrame({...frame})).toBe(false);
    return context.runOperation({...mutation,operationId:'operation'},async()=>{expect(context.isOriginalPortalNativeMutationFrame(context.current())).toBe(false);await fn();});
   });
  })));
 return{context,cluster,parentId,gets,markers,run,setHook:(fn:typeof hook)=>{hook=fn;},captured:()=>captured,request:()=>context.authorizeRequest(cluster,'POST',`/consumers/${parentId}/acls`,{id:'credential',group:'team'},{} )};
}
it('issues an original pending request identity without granting Native/final authority and performs the exact real parent GET path',async()=>{
 const f=fixture();let observed:any;
 f.setHook(async()=>{const phase=f.context.scheduledPortalPreparationPhase()!;expect(phase.stage).toBe('sql-preflight');expect(f.context.verifiedPlatformAdmin(phase.ticket)).toBe(false);
  await expect(f.context.beforeNativeSend(phase.ticket)).rejects.toMatchObject({response:{code:'PORTAL_SQL_PREPARATION_NATIVE_FORBIDDEN'}});
  await expect(f.context.authorizeResponse(phase.ticket,{})).rejects.toMatchObject({response:{code:'PORTAL_SQL_PREPARATION_NATIVE_FORBIDDEN'}});
  observed=await f.context.runPortalNativeParentRead(f.cluster.id,`/consumers/${f.parentId}`,async()=>{
   expect(f.context.scheduledPortalPreparationPhase()).toBe(phase);const ticket=await f.context.authorizeRequest(f.cluster,'GET',`/consumers/${f.parentId}`,undefined,{});
   return f.context.authorizeResponse(ticket,{id:f.parentId,tags:[]});
  });return{platformAdmin:true};
 });
 await f.run(async()=>{const ticket=await f.request();expect(ticket).toBe(f.captured().ticket);expect(f.context.verifiedPlatformAdmin(ticket)).toBe(true);expect(f.context.scheduledPortalPreparationPhase()).toBeNull();});
 expect(observed.id).toBe(f.parentId);expect(f.gets).toHaveLength(1);expect(f.gets[0].phase).not.toBeNull();
 for(const frame of f.markers)expect(f.context.isOriginalPortalNativeMutationFrame(frame)).toBe(false);
});
it('destroys the pending request ticket when the original current authorizer rejects it',async()=>{
 const f=fixture();f.setHook(async()=>{throw new ForbiddenException({code:'CURRENT_AUTHORITY_REVOKED'});});
 await f.run(async()=>{await expect(f.request()).rejects.toMatchObject({response:{code:'CURRENT_AUTHORITY_REVOKED'}});expect(()=>f.context.assertTicketActive(f.captured().ticket)).toThrow();expect(f.context.scheduledPortalPreparationPhase()).toBeNull();});
});
it.each([['foreign cluster','foreign','/consumers/00000000-0000-4000-8000-000000000011'],['foreign parent','cluster','/consumers/00000000-0000-4000-8000-000000000099'],['schema','cluster','/schemas/consumers']])('rejects %s as support for the original credential POST',async(_name,cid,path)=>{
 const f=fixture();const callback=vi.fn(async()=>({}));f.setHook(async()=>{await expect(f.context.runPortalNativeParentRead(cid,path,callback)).rejects.toMatchObject({response:{code:'PORTAL_SQL_PREPARATION_PARENT_CHANGED'}});return{};});
 await f.run(async()=>{await f.request();});expect(callback).not.toHaveBeenCalled();expect(f.gets).toHaveLength(0);
});
it('does not inherit the original parent read scope into an arbitrary internal-read sibling',async()=>{
 const f=fixture();f.setHook(async()=>{await f.context.runInternalRead(f.cluster.id,'capture',async()=>{expect(f.context.scheduledPortalPreparationPhase()).toBeNull();},{paths:[`/consumers/${f.parentId}`],maxCalls:1});return{};});await f.run(async()=>{await f.request();});
});
