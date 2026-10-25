// @ts-nocheck: actual helper methods with synthetic RAM envelopes only.
import {describe,it,expect,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {assertM8DeckSession,submitM8DeckApply} from './lib/m8-deck-acceptance.mjs';
const area={cid:randomUUID(),wid:randomUUID()},actor={user:{id:randomUUID()},sid:randomUUID()},jobId=randomUUID(),planId=randomUUID(),localPlanId=randomUUID(),executionId=randomUUID(),serviceId=randomUUID(),planStepId=randomUUID(),jobStepId=randomUUID();
const check=(value,label)=>{if(!value)throw Error(label)};
const session=()=>({id:randomUUID(),revision:1,purpose:'read',authorizationScheme:'KongOS-Deck',tokenSecret:'S'.repeat(43),expiresAt:new Date(Date.now()+100000).toISOString()});
const h=()=>({check,state:{configurationOperations:[]},save:vi.fn(),data:v=>v.payload.data});
function clonedFixture(){
 const harness=h(),plan={id:planId,planHash:'a'.repeat(64),planRevision:1,revision:1,name:'RAM plan',deleteCount:0,executionMode:'direct',capabilities:{apply:true}},local={...plan,id:localPlanId,clusterId:area.cid,workspaceId:area.wid,stepCount:1};
 const change={stepId:planStepId,entityType:'services',action:'update',nativeId:serviceId,objectWorkspaceId:area.wid},step={id:jobStepId,executionId,planStepId,state:'pending',operationId:null,verified:false,type:'services',action:'update',originalId:serviceId,objectWorkspaceId:area.wid};
 const receipt={domain:'configuration',durable:true,id:jobId,jobId,actorId:actor.user.id,clusterId:area.cid,workspaceId:area.wid,originalScope:{clusterId:area.cid,workspaceId:area.wid},kind:'apply',state:'running',driver:'deck',planId:localPlanId,planHash:plan.planHash,planRevision:1,executionId,executionCompleted:false};
 const changes={entity:local,items:[change],nextCursor:null},steps={items:[step],nextCursor:null};
 harness.request=vi.fn(async(_a,path,method='GET',_body,options)=>({payload:{data:method==='GET'?(path.includes('/changes')?changes:path.includes('/steps')?steps:{entity:plan}):{...receipt,idempotencyKey:options.key}}}));
 return{harness,plan,local,change,step,receipt,changes,steps};
}
describe('actual fixed decK pending-driver and scoped session contracts',()=>{
 it('requires exact session namespace, opaque token and real bounded expiry',()=>{
  const value=session();value.basePath=`/api/v1/deck/${value.id}`;expect(assertM8DeckSession(h(),value,{actor,area,purpose:'read',jobId}).sessionId).toBe(actor.sid);
  for(const change of [{purpose:'write'},{basePath:'/services'},{revision:0},{tokenSecret:'canned'},{authorizationScheme:'Bearer'},{expiresAt:new Date(Date.now()-1000).toISOString()},{expiresAt:new Date(Date.now()+900000).toISOString()}])expect(()=>assertM8DeckSession(h(),{...value,...change},{actor,area,purpose:'read',jobId})).toThrow();
 });
 it('submits one exact driver packet then returns its genuine running receipt',async()=>{
  const harness=h(),plan={id:planId,planHash:'a'.repeat(64),planRevision:1,revision:1,name:'RAM plan',deleteCount:0,executionMode:'direct',capabilities:{apply:true}};
  harness.request=vi.fn(async(_actor,path,method='GET',body,options)=>({payload:{data:method==='GET'?(path.includes('/changes')?
   {entity:{...plan,id:localPlanId,clusterId:area.cid,workspaceId:area.wid,stepCount:1},items:[{stepId:planStepId,entityType:'services',action:'update',nativeId:serviceId,objectWorkspaceId:area.wid}],nextCursor:null}:
   path.includes('/steps')?{items:[{id:jobStepId,executionId,planStepId,state:'pending',operationId:null,verified:false,type:'services',action:'update',originalId:serviceId,objectWorkspaceId:area.wid}],nextCursor:null}:{entity:plan}):
   {domain:'configuration',durable:true,id:jobId,jobId,idempotencyKey:options.key,actorId:actor.user.id,clusterId:area.cid,workspaceId:area.wid,originalScope:{clusterId:area.cid,workspaceId:area.wid},kind:'apply',state:'running',driver:'deck',planId:localPlanId,planHash:plan.planHash,planRevision:1,executionId,executionCompleted:false}}}));
  const result=await submitM8DeckApply(harness,actor,area,{planId,planHash:plan.planHash,planRevision:1});
  expect(result.receipt.state).toBe('running');expect(result.plan.id).toBe(localPlanId);expect(result.plan.id).not.toBe(planId);expect(result.sourcePlan.id).toBe(planId);expect(harness.request.mock.calls.filter(v=>v[2]==='POST')).toHaveLength(1);expect(harness.state.configurationOperations[0].state).toBe('submitted');
 });
 it.each(['foreign','approval','delete','capability'])('rejects %s plan before any driver apply packet',async mode=>{
  const harness=h(),plan={id:planId,planHash:'a'.repeat(64),planRevision:1,revision:1,name:'RAM plan',deleteCount:0,executionMode:'direct',capabilities:{apply:true}};
  if(mode==='foreign')plan.planHash='b'.repeat(64);if(mode==='approval')plan.executionMode='approval';if(mode==='delete')plan.deleteCount=1;if(mode==='capability')plan.capabilities.apply=false;
  harness.request=vi.fn(async()=>({payload:{data:{entity:plan}}}));await expect(submitM8DeckApply(harness,actor,area,{planId,planHash:'a'.repeat(64),planRevision:1})).rejects.toThrow();expect(harness.request.mock.calls).toHaveLength(1);expect(harness.state.configurationOperations).toHaveLength(0);
 });
 it.each(['nativeCompleted','foreignReceipt','wrongDriver'])('will not substitute %s response for the original running direct job',async mode=>{
  const harness=h(),plan={id:planId,planHash:'a'.repeat(64),planRevision:1,revision:1,name:'RAM plan',deleteCount:0,executionMode:'direct',capabilities:{apply:true}};
  harness.request=vi.fn(async(_actor,_path,method='GET',_body,options)=>{const receipt={domain:'configuration',durable:true,id:jobId,jobId,idempotencyKey:options?.key,actorId:actor.user.id,clusterId:area.cid,workspaceId:area.wid,originalScope:{clusterId:area.cid,workspaceId:area.wid},kind:'apply',state:'running',driver:'deck',planId,executionId:randomUUID(),executionCompleted:false};if(mode==='nativeCompleted')Object.assign(receipt,{state:'succeeded',executionCompleted:true});if(mode==='foreignReceipt')receipt.workspaceId=randomUUID();if(mode==='wrongDriver')receipt.driver='bff';return{payload:{data:method==='GET'?{entity:plan}:receipt}}});
  await expect(submitM8DeckApply(harness,actor,area,{planId,planHash:plan.planHash,planRevision:1})).rejects.toThrow();expect(harness.request.mock.calls.filter(v=>v[2]==='POST')).toHaveLength(1);expect(harness.state.configurationOperations[0].state).toBe('prepared');
 });
 for(const[name,change]of[
  ['old source ID instead of clone',f=>f.receipt.planId=planId],['foreign clone hash',f=>f.local.planHash='b'.repeat(64)],['foreign clone revision',f=>f.local.planRevision=2],
  ['foreign clone CID',f=>f.local.clusterId=randomUUID()],['foreign clone WID',f=>f.local.workspaceId=randomUUID()],['unbounded changes continuation',f=>f.changes.nextCursor='next'],
  ['foreign object WID',f=>f.change.objectWorkspaceId=randomUUID()],['foreign execution step',f=>f.step.executionId=randomUUID()],['unrelated plan step',f=>f.step.planStepId=randomUUID()],
  ['Native operation already bound',f=>f.step.operationId=randomUUID()],['step already running',f=>f.step.state='running'],['step falsely verified',f=>f.step.verified=true],
  ['wrong object ID',f=>f.step.originalId=randomUUID()],['wrong type',f=>f.step.type='routes'],['wrong action',f=>f.step.action='delete'],['incomplete steps cursor',f=>f.steps.nextCursor='next'],
 ])it(name+' rejects the current execution proof without resubmission or session creation',async()=>{const f=clonedFixture();change(f);await expect(submitM8DeckApply(f.harness,actor,area,{planId,planHash:f.plan.planHash,planRevision:1})).rejects.toThrow();expect(f.harness.request.mock.calls.filter(v=>v[2]==='POST')).toHaveLength(1)});
 it('unknown current clone read retains original submitted key and does not replay its apply',async()=>{const f=clonedFixture(),request=f.harness.request.getMockImplementation();f.harness.request.mockImplementation(async(...args)=>{if(args[1].includes('/changes'))throw Error('M8_RESPONSE_UNKNOWN');return request(...args)});await expect(submitM8DeckApply(f.harness,actor,area,{planId,planHash:f.plan.planHash,planRevision:1})).rejects.toThrow('UNKNOWN');expect(f.harness.request.mock.calls.filter(v=>v[2]==='POST')).toHaveLength(1);expect(f.harness.state.configurationOperations[0].state).toBe('submitted')});
});
