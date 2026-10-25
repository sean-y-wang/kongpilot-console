import {randomUUID} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {describe,it,expect,vi} from 'vitest';
import {KongExecutionContextService,type PromotionPlanningProof} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';

// The actual kernel is exercised with a private synthetic policy. This is not
// native transport, real database or deployed-platform evidence.
function fixture(){
 const context=new KongExecutionContextService(),actor={id:randomUUID(),username:'planning-reviewer',superAdmin:true},sid=randomUUID();
 const cid=randomUUID(),wid=randomUUID(),targetCid=randomUUID(),targetWid=randomUUID(),handle=Object.freeze({});
 const cluster={id:targetCid,admin_url:'http://planning-target.invalid:8001',version:'1.5.1',execution_mode:'direct'};
 const state={active:true},claims=new WeakMap<object,PromotionPlanningProof>(),wire:any[]=[];
 let proof:PromotionPlanningProof;
 const policy={verifyHandle:vi.fn(async(candidate:object)=>{
  if(candidate!==handle||!claims.has(candidate)||!state.active)throw new ForbiddenException({code:'PLANNING_CURRENT_AUTHORITY_REVOKED'});
  return proof;
 })};
 context.installPromotionPlanningPolicy(policy);
 context.installPolicy({authorizeRequest:async()=>({}),authorizeResponse:async(_,result)=>result});
 const request=async(method='GET',path='/services',target=cluster,result:any={data:[]})=>{
  const ticket=await context.authorizeRequest(target,method,path,undefined,{});
  await context.assertGovernanceBeforeSend(ticket);await context.beforeNativeSend(ticket);
  wire.push({method,path,actor:context.current().actor?.id,sid:context.current().sessionId,cid:context.current().clusterId});
  return context.authorizeResponse(ticket,result);
 };
 const run=<T>(fn:()=>Promise<T>)=>context.runHttp({requestId:randomUUID(),ip:'127.0.0.1'},async()=>{
  context.bindHttpActor(actor,sid);
  return context.runActor({actor,clusterId:cid,workspaceId:wid,module:'promote',action:'write'},async()=>{
   proof={promotionId:randomUUID(),actor,sessionId:sid,sourceClusterId:cid,sourceWorkspaceId:wid,clusterId:targetCid,workspaceId:targetWid,
    transportScope:transportScopeFor(cluster.admin_url),permissionVersion:'actual-synthetic-permission-version',credentialEpoch:1,expiresAt:Date.now()+60000,originFrame:context.current()};
   claims.set(handle,proof);return fn();
  });
 });
 return{context,actor,sid,cid,wid,targetCid,targetWid,cluster,handle,state,wire,policy,request,run,get proof(){return proof},set proof(value){proof=value;}};
}

describe('fixed read-only cross-cluster Promote planning namespace',()=>{
 it('preserves the generic CID guard, true actor/SID, source restoration and target read namespace',async()=>{
  const f=fixture();await f.run(async()=>{
   const source=f.context.current();
   expect(()=>f.context.runActor({actor:f.actor,clusterId:f.targetCid,workspaceId:f.targetWid},async()=>{})).toThrow();
   await f.context.runPromotionPlanning(f.handle,async()=>{
    expect(f.context.current()).toMatchObject({clusterId:f.targetCid,workspaceId:f.targetWid,sessionId:f.sid,purpose:'promotion-planning'});
    expect(f.context.current().operation).toBeUndefined();expect(f.context.current().archive).toBeUndefined();
    await f.context.runActor({actor:f.actor,clusterId:f.targetCid,workspaceId:f.targetWid,module:'snapshots'},()=>f.request());
   });
   expect(f.context.current()).toBe(source);
  });expect(f.wire).toEqual([{method:'GET',path:'/services',actor:f.actor.id,sid:f.sid,cid:f.targetCid}]);
 });
 it.each(['copy','plain','other-user','other-session','source-cid','source-workspace','closed-frame','expired'])('rejects %s before any target request',async(kind)=>{
  const f=fixture();await f.run(async()=>{
   if(kind==='other-user')f.proof={...f.proof,actor:{...f.actor,id:randomUUID()}};
   if(kind==='other-session')f.proof={...f.proof,sessionId:randomUUID()};
   if(kind==='source-cid')f.proof={...f.proof,sourceClusterId:randomUUID()};
   if(kind==='source-workspace')f.proof={...f.proof,sourceWorkspaceId:randomUUID()};
   if(kind==='closed-frame')f.proof={...f.proof,originFrame:{...f.proof.originFrame}};
   if(kind==='expired')f.proof={...f.proof,expiresAt:Date.now()-1};
   const input=kind==='copy'?{...f.handle}:kind==='plain'?{approved:true}:f.handle;
   await expect(f.context.runPromotionPlanning(input,()=>f.request())).rejects.toMatchObject({status:403});
  });expect(f.wire).toHaveLength(0);
 });
 it.each(['POST','PUT','PATCH','DELETE'])('cannot grant %s or a nested native operation',async(method)=>{
  const f=fixture();await f.run(()=>f.context.runPromotionPlanning(f.handle,async()=>{
   await expect(f.request(method,'/services')).rejects.toMatchObject({response:{code:'PROMOTION_PLANNING_NATIVE_FORBIDDEN'}});
   expect(()=>f.context.runOperation({actor:f.actor,clusterId:f.targetCid,workspaceId:f.targetWid,operationId:randomUUID(),entityType:'services',action:'update'},()=>f.request(method)))
    .toThrow();
  }));expect(f.wire).toHaveLength(0);
 });
 it('nested genuine configuration authority cannot turn planning into a write',async()=>{
  const f=fixture(),config=Object.freeze({});
  f.context.installConfigurationJobPolicy({verifyHandle:async()=>({actor:f.actor,sessionId:f.sid,clusterId:f.targetCid,workspaceId:f.targetWid,module:'snapshots',purpose:'apply',jobId:randomUUID(),permissionVersion:'pv',credentialEpoch:1,leaseGeneration:1,expiresAt:Date.now()+60000,readOnly:false})});
  await f.run(()=>f.context.runPromotionPlanning(f.handle,async()=>{
   await expect(f.context.runConfigurationJob(config,()=>f.request('PATCH',`/services/${randomUUID()}`))).rejects.toMatchObject({response:{code:'PROMOTION_PLANNING_NATIVE_FORBIDDEN'}});
  }));expect(f.wire).toHaveLength(0);
 });
 it('read-only capture jobs keep the original namespace call budget and source authority',async()=>{
  const f=fixture(),first=Object.freeze({}),second=Object.freeze({}),expiresAt=Date.now()+60000;
  const base={actor:f.actor,sessionId:f.sid,clusterId:f.targetCid,workspaceId:f.targetWid,module:'snapshots',purpose:'capture' as const,permissionVersion:'pv',credentialEpoch:1,leaseGeneration:1,expiresAt,readOnly:true};
  const captures=new WeakMap<object,any>([[first,{...base,jobId:randomUUID()}],[second,{...base,jobId:randomUUID()}]]);
  f.context.installConfigurationJobPolicy({verifyHandle:async handle=>captures.get(handle)});
  await f.run(()=>f.context.runPromotionPlanning(f.handle,async()=>{
   for(const handle of [first,second])await f.context.runConfigurationJob(handle,async()=>{
    for(let i=0;i<250;i++)await f.request('GET',`/services/${f.actor.id}`,f.cluster,{id:f.actor.id});
   });
   await expect(f.context.runConfigurationJob(second,()=>f.request('GET',`/services/${f.actor.id}`,f.cluster,{id:f.actor.id}))).rejects.toMatchObject({response:{code:'KONG_EXECUTION_CALL_LIMIT'}});
  }));expect(f.wire).toHaveLength(500);
 });
 it('revalidates after DNS/rate and before a raw response is returned',async()=>{
  const f=fixture();await f.run(()=>f.context.runPromotionPlanning(f.handle,async()=>{
   const first=await f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{});f.state.active=false;
   await expect(f.context.assertGovernanceBeforeSend(first)).rejects.toMatchObject({response:{code:'PLANNING_CURRENT_AUTHORITY_REVOKED'}});
   f.state.active=true;const second=await f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{});f.state.active=false;
   await expect(f.context.authorizeResponse(second,{data:[]})).rejects.toMatchObject({status:403});f.state.active=true;
  }));expect(f.wire).toHaveLength(0);
 });
 it.each(['permissions','target','transport'])('rejects changed %s at the send fence',async(kind)=>{
  const f=fixture();await f.run(()=>f.context.runPromotionPlanning(f.handle,async()=>{
   const ticket=await f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{}),original=f.proof;
   if(kind==='permissions')f.proof={...f.proof,permissionVersion:'revoked'};
   if(kind==='target')f.proof={...f.proof,clusterId:randomUUID()};
   if(kind==='transport')f.cluster.admin_url='http://other.invalid:8001';
   await expect(f.context.assertGovernanceBeforeSend(ticket)).rejects.toMatchObject({status:403});f.proof=original;f.cluster.admin_url='http://planning-target.invalid:8001';
  }));expect(f.wire).toHaveLength(0);
 });
 it('cannot reuse a completed namespace or retain a valid ticket after it closes',async()=>{
  const f=fixture();await f.run(async()=>{
   let ticket:any;
   await f.context.runPromotionPlanning(f.handle,async()=>{ticket=await f.context.authorizeRequest(f.cluster,'GET','/services',undefined,{});});
   await expect(f.context.runPromotionPlanning(f.handle,()=>f.request())).rejects.toMatchObject({status:403});
   expect(()=>f.context.assertTicketActive(ticket)).toThrow();
  });expect(f.wire).toHaveLength(0);
 });
});
