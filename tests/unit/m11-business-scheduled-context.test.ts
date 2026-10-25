import {describe,expect,it} from 'vitest';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

function fixture(){
 const context=new KongExecutionContextService(),handle=Object.freeze({}),other=Object.freeze({});
 let live=true,changed=false;const checkpoints:string[]=[];
 const proof:any=Object.freeze({version:1,origin:'scheduled-workflow',sessionId:null,actor:Object.freeze({id:'executor',forcePasswordChange:false}),
  clusterId:'cluster',workspaceId:'workspace',kind:'configuration_v2',expiresAt:new Date(Date.now()+60000).toISOString()});
 context.installWorkflowScheduledNamespacePolicy({assertLive(h){if(h!==handle||!live)throw Error('LEASE_REVOKED');},async verifyHandle(h,checkpoint){
  if(h!==handle||!live)throw Error('ORIGINAL_REQUIRED');checkpoints.push(checkpoint);return changed?Object.freeze({...proof}):proof;
 }});
 context.installPolicy({async authorizeRequest(){return{};},async authorizeResponse(_ticket,result){return result;}});
 const cluster:any={id:'cluster',admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'approval'};
 return{context,handle,other,proof,checkpoints,cluster,revoke(){live=false;},replace(){changed=true;}};
}
describe('business scheduled Context keeps a separate original namespace',()=>{
 it('requires the actual original handle; copies never create a context',async()=>{
  const f=fixture();await expect(f.context.runWorkflowScheduledNamespace({...f.handle},async()=>{})).rejects.toThrow('ORIGINAL_REQUIRED');
  expect(f.context.peek()).toBeNull();
 });
 it('cannot adopt an inherited HTTP context, including an unauthenticated one',async()=>{
  const f=fixture();await f.context.runHttp({},async()=>{
   await expect(f.context.runWorkflowScheduledNamespace(f.handle,async()=>{})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_EXISTING_CONTEXT_FORBIDDEN'}});
  });expect(f.checkpoints).toEqual([]);
 });
 it('keeps a NULL SID and cannot lend business provenance to the entity namespace',async()=>{
  const f=fixture();await f.context.runWorkflowScheduledNamespace(f.handle,async()=>{
   expect(f.context.current()).toMatchObject({kind:'scheduled-workflow',actor:{id:'executor'}});
   expect(f.context.current().sessionId).toBeUndefined();expect(f.context.hasEntityScheduledNamespace()).toBe(false);
   expect(()=>f.context.requireEntityScheduledNamespaceHandle()).toThrow();try{f.context.requireEntityScheduledNamespaceHandle();}catch(e:any){expect(e.getResponse()).toMatchObject({code:'ENTITY_SCHEDULE_NAMESPACE_REQUIRED'});}
   expect(f.context.requireWorkflowScheduledNamespaceHandle()).toBe(f.handle);
  });await expect(f.context.runWorkflowScheduledNamespace(f.handle,async()=>{})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ORIGINAL_NAMESPACE_REQUIRED'}});
 });
 it('revalidates capture on request and response; the business handle alone cannot write',async()=>{
  const f=fixture();await f.context.runWorkflowScheduledNamespace(f.handle,async()=>{
   const ticket=await f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{size:20});
   await expect(f.context.authorizeResponse(ticket,{data:[]})).resolves.toEqual({data:[]});
   expect(f.checkpoints).toEqual(['claim','capture','capture']);
   await expect(f.context.authorizeRequest(f.cluster,'POST','/services',{},{})).rejects.toMatchObject({response:{code:'KONG_NATIVE_OPERATION_REQUIRED'}});
  });
 });
 it('rejects a copied proof returned after a current SQL verification',async()=>{
  const f=fixture();await f.context.runWorkflowScheduledNamespace(f.handle,async()=>{
   f.replace();await expect(f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{size:20})).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_NAMESPACE_SCOPE_CHANGED'}});
  });
 });
 it('losing a lease fences even a current ticket before response consumption',async()=>{
  const f=fixture();await f.context.runWorkflowScheduledNamespace(f.handle,async()=>{
   const ticket=await f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{size:20});f.revoke();
   await expect(f.context.authorizeResponse(ticket,{data:[]})).rejects.toThrow('LEASE_REVOKED');
  });
 });
 it('a detached continuation cannot use the closed namespace',async()=>{
  const f=fixture();let release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});let detached!:Promise<unknown>;
  await f.context.runWorkflowScheduledNamespace(f.handle,async()=>{
   detached=(async()=>{await gate;return f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{size:20});})();
  });release();await expect(detached).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CONTEXT_EXPIRED'}});
 });
});
