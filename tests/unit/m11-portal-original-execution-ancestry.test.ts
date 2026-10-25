import {expect,it} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

/** Original Context issuance only. Issuer/SQL adapters are controlled; this
 * proves ancestry identity and synchronous liveness, not SDK or HTTP closure. */
function fixture(kind:'portal-credential-issue'|'configuration_v2'='portal-credential-issue'){
 const context=new KongExecutionContextService(),handle=Object.freeze({}),executionHandle=Object.freeze({}),actor={id:'executor'};
 let live=true,expiry=Date.now()+30000;
 const namespace:any=Object.freeze({version:1,origin:'scheduled-workflow',sessionId:null,actor,clusterId:'cluster',workspaceId:'workspace',kind,
  permissionVersion:'current',workflow:{id:'workflow'},claim:{id:'claim'},expiresAt:new Date(Date.now()+60000).toISOString()});
 const execution:any=Object.freeze({executionId:'execution',workflowId:'workflow',actorId:'executor',clusterId:'cluster',workspaceId:'workspace',sessionId:null,
  origin:'scheduled-workflow',scheduleClaimId:'claim',permissionVersion:'current',get expiresAt(){return expiry;}});
 const native:any=Object.freeze({execution,stepId:'native',kind:'native'}),metadata:any=Object.freeze({execution,stepId:'metadata',kind:'metadata'});
 context.installWorkflowScheduledNamespacePolicy({assertLive(original){expect(original).toBe(handle);if(!live)throw new ForbiddenException({code:'ORIGINAL_NAMESPACE_REVOKED'});},
  async verifyHandle(original){expect(original).toBe(handle);return namespace;}});
 context.installApprovedPolicy({async verifyExecution(original:object){expect(original).toBe(executionHandle);return execution;},
  async verifyWorkflowScheduledExecution(original:object,ns:object){expect(original).toBe(execution);expect(ns).toBe(handle);},
  async verifyStep(original:object,id:string){expect(original).toBe(execution);return id==='native'?native:metadata;},async mutationBinding(){},async bindOperation(){},async assertNative(){},async assertMetadata(){}}as any);
 return{context,actor,namespace,execution,native,metadata,handle,
  ns:<T>(fn:()=>Promise<T>)=>context.runWorkflowScheduledNamespace(handle,fn),
  execute:<T>(fn:()=>Promise<T>)=>context.runApprovedWorkflow(executionHandle as any,fn),
  revoke:()=>{live=false;},expire:()=>{expiry=Date.now()-1;}};
}
it('returns null before genuine issuance, including an active Namespace before its execution',async()=>{
 const f=fixture();expect(f.context.originalScheduledPortalExecution()).toBeNull();
 await f.ns(async()=>{expect(f.context.originalScheduledPortalExecution()).toBeNull();});
 expect(f.context.originalScheduledPortalExecution()).toBeNull();
});
it('distinguishes the true original execution container from its later original Native step',async()=>{
 const f=fixture();await f.ns(()=>f.execute(async()=>{
  const outer=f.context.originalScheduledPortalExecution()!;expect(Object.isFrozen(outer)).toBe(true);expect(outer.execution).toBe(f.execution);expect(outer.step).toBeNull();
  await f.context.runApprovedStep('native',async()=>{const current=f.context.originalScheduledPortalExecution()!;expect(current.execution).toBe(f.execution);expect(current.step).toBe(f.native);});
  expect(f.context.originalScheduledPortalExecution()!.step).toBeNull();
 }));
});
it('preserves a genuine metadata step as metadata and never projects it as Native',async()=>{
 const f=fixture();await f.ns(()=>f.execute(()=>f.context.runApprovedStep('metadata',async()=>{
  const value=f.context.originalScheduledPortalExecution()!;expect(value.execution).toBe(f.execution);expect(value.step).toBe(f.metadata);expect(value.step?.kind).toBe('metadata');
 })));
});
it('only observes actual issued ancestry through the original Mutation actor and operation',async()=>{
 const f=fixture();await f.ns(()=>f.execute(()=>f.context.runApprovedStep('native',async()=>{
  const mutation:any={actor:f.actor,clusterId:'cluster',workspaceId:'workspace',entityType:'credentials',action:'create',parentId:'consumer',credentialKind:'acls'};
  await f.context.runMutationActor(mutation,()=>f.context.runOperation({...mutation,operationId:'operation'},async()=>{
   const value=f.context.originalScheduledPortalExecution()!;expect(value.execution).toBe(f.execution);expect(value.step).toBe(f.native);
  }));
 })));
});
it('cannot use an unrelated workspace actor to select the original execution',async()=>{
 const f=fixture();await f.ns(()=>f.execute(()=>f.context.runActor({actor:f.actor,clusterId:'cluster',workspaceId:'foreign',module:'services',action:'read'},async()=>{
  expect(f.context.originalScheduledPortalExecution()).toBeNull();
 })));
});
it('does not expose Configuration execution as a Portal execution',async()=>{
 const f=fixture('configuration_v2');await f.ns(()=>f.execute(async()=>{expect(f.context.originalScheduledPortalExecution()).toBeNull();}));
});
it('does not expose an inherited execution from a genuine readonly Validation frame',async()=>{
 const f=fixture(),read=Object.freeze({}),proof:any=Object.freeze({version:1,origin:'workflow-scheduled-validation-read',readOnly:true,
  actor:f.actor,sessionId:null,role:'executor',namespace:f.namespace,expiresAt:new Date(Date.now()+15000).toISOString(),
  scope:{version:1,domain:'scoped-points-v1',resources:[{kind:'point',clusterId:'cluster',workspaceId:'workspace',path:'/services/00000000-0000-4000-8000-000000000011'}],
   limits:{maxCalls:1,maxPages:1,maxRecords:1,maxBytes:4096,timeoutMs:15000}},
  registries:[{clusterId:'cluster',workspaceId:'workspace',transportScope:'a'.repeat(64),clusterRevision:1,workspaceRevision:1}]});
 f.context.installWorkflowScheduledValidationReadPolicy({async verifyHandle(original,ns,source){expect(original).toBe(read);expect(ns).toBe(f.handle);expect(source).toBe(f.namespace);return proof;},
  assertLive(original){expect(original).toBe(read);},async authorizeRequest(){throw new Error('unused');},async verifyRequest(){throw new Error('unused');},async authorizeResponse(){throw new Error('unused');}});
 await f.ns(()=>f.execute(()=>f.context.runApprovedStep('native',()=>f.context.runWorkflowScheduledValidationRead(read,f.handle,async()=>{
  expect(f.context.originalScheduledPortalExecution()).toBeNull();
 }))));
});
it('rechecks current Namespace liveness rather than trusting an earlier original projection',async()=>{
 const f=fixture();await expect(f.ns(()=>f.execute(async()=>{
  expect(f.context.originalScheduledPortalExecution()!.execution).toBe(f.execution);f.revoke();f.context.originalScheduledPortalExecution();
 }))).rejects.toMatchObject({response:{code:'ORIGINAL_NAMESPACE_REVOKED'}});
});
it('does not expose an expired original proof or renew its execution deadline',async()=>{
 const f=fixture();await f.ns(()=>f.execute(async()=>{expect(f.context.originalScheduledPortalExecution()).not.toBeNull();f.expire();expect(f.context.originalScheduledPortalExecution()).toBeNull();}));
});
it('rejects the asynchronous tail after the actual issued frame has closed',async()=>{
 const f=fixture();let release!:()=>void;let tail!:Promise<unknown>;
 await f.ns(()=>f.execute(async()=>{tail=new Promise<void>(resolve=>{release=resolve;}).then(()=>{expect(()=>f.context.originalScheduledPortalExecution()).toThrow();});}));
 release();await tail;
});
it('does not accept shape-only copies in an ordinary actor frame',async()=>{
 const f=fixture();await f.context.runHttp({},()=>{f.context.bindHttpActor(f.actor,'source-session');return f.context.runActor({actor:f.actor,clusterId:'cluster',workspaceId:'workspace',module:'workflows',action:'write'},async()=>{
  expect((f.context.originalScheduledPortalExecution as any)({...f.execution},{...f.native})).toBeNull();
 });});
});
