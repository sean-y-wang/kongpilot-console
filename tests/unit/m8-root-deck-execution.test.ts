import {ConfigurationFailureLedgerService} from '../../apps/console-api/src/modules/configuration/configuration-failure-ledger.service';
import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {ConflictException} from '@nestjs/common';
import {ConfigurationService} from '../../apps/console-api/src/modules/configuration/configuration.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
const id=(n:number)=>`60000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','4'.repeat(64)));
afterEach(()=>vi.unstubAllEnvs());
/** The façade and transport counters are real; sealed-plan/storage/native
 * participants below are synthetic. This is not a live gateway result. */
function fixture(target=false){
 const ctx=new KongExecutionContextService(),secrets=new SecretService(),handle=Object.freeze({}),user={id:id(1),username:'deck-exec-unit',superAdmin:false};
 const proof:any={actor:user,sessionId:id(2),clusterId:id(3),workspaceId:id(4),module:'snapshots',purpose:'apply',jobId:id(5),permissionVersion:'v1',credentialEpoch:1,leaseGeneration:2,expiresAt:Date.now()+600000,readOnly:false};
 ctx.installConfigurationJobPolicy({verifyHandle:async(candidate:any)=>{expect(candidate).toBe(handle);return{...proof};}});
 ctx.installPolicy({authorizeRequest:async()=>({}),authorizeResponse:async(_:any,value:any)=>value});
 const body:any=target?{id:id(12),target:'upstream.test:80',weight:80,upstream:{id:id(13)}}:{id:id(11),host:'planned.test',headers:null};
 const step:any={stepId:id(10),entityType:target?'targets':'services',mutationAction:'update',nativeId:id(11),allocatedNativeId:target?id(12):null,parentId:target?id(13):null,
  credentialKind:null,objectWorkspaceId:id(4),objectKey:`${target?'targets':'services'}:${id(11)}`,body,nativeRequests:[{body}],dependencies:[]};
 const plan:any={steps:[step]},row:any={id:id(14),planStepId:step.stepId,plan_step_id:step.stepId,revision:1,state:'pending'};
 const locator:any={id:id(6),jobId:id(5),clusterId:id(3),workspaceId:id(4),purpose:'write'};
 const authority:any={handle,user,sessionId:id(2),locator};
 const job:any={id:id(5),safe_progress:{planId:id(15)}};
 const access:any={runJob:async(_:any,fn:any)=>ctx.runConfigurationJob(handle,fn),runStep:async(_:any,__ :any,___ :any,fn:any)=>fn(),assertCurrent:vi.fn(async()=>({})),assertObject:vi.fn(async()=>undefined)};
 const db:any={one:vi.fn(async(sql:string)=>{if(sql.includes('state NOT IN'))return null;if(sql.includes('configuration_job_steps'))return{...row};throw new Error('unexpected deck executor query');})};
 const repo:any={recordStepEvidence:vi.fn(async(_:any,input:any)=>{row.state=input.state;row.revision++;}),chargeDeckSessionBudget:vi.fn(async()=>undefined),finishJob:vi.fn(async()=>({state:'succeeded'}))};
 const cluster:any={id:id(3),admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'direct'};
 const read=async()=>{const ticket=await ctx.authorizeRequest(cluster,'GET',`/services/${id(11)}`,undefined,{});ctx.chargeRetry(ticket);await ctx.authorizeResponse(ticket,{id:id(11),host:'planned.test'});};
 const native:any={execute:vi.fn(async()=>{await read();await read();return{receipt:{state:'succeeded'},after:{...body,id:target?id(12):id(11)},result:{},effectiveNativeId:target?id(12):id(11)};}),
  context:vi.fn(async()=>({})),receipt:vi.fn(async()=>({state:'uncertain'}))};
 const redis:any={withLock:async(_:string,fn:any)=>fn()};
 const service=new ConfigurationService(db,redis,secrets,ctx,{}as any,{}as any,{}as any,access,repo,{}as any,native,{}as any,{}as any,{}as any,{}as any,new ConfigurationFailureLedgerService(db,secrets,{}as any,access,ctx,{}as any));
 vi.spyOn(service as any,'assertPlanGrants').mockResolvedValue(undefined);vi.spyOn(service as any,'finish').mockResolvedValue({state:'succeeded'});
 const execution={handle,plan,job,executionId:id(16),rows:[row],targetDeleteIntents:new Set<string>(),completed:0,expiresAt:Date.now()+600000};
 (service as any).deckExecutions.set(job.id,execution);
 const packet=(method='PATCH',patch:Record<string,unknown>=body):any=>({method,path:`/${target?'upstreams':'services'}/${id(11)}`,kind:target?'targets':'entity',type:step.entityType,id:method==='POST'?undefined:id(11),parentId:step.parentId??undefined,collection:method==='POST',query:{size:100},body:patch,bodyHmac:secrets.fingerprint({domain:'deck-cli-packet:v1',body:patch})});
 return{ctx,secrets,handle,service,authority,step,body,row,repo,native,packet,execution};
}
describe('M8 Root immutable decK write executor',()=>{
 it('accepts SDK full PUT fields only from the sealed envelope and executes only the delta',async()=>{
  const f=fixture(),delta={retries:3};f.step.body=delta;f.step.nativeRequests[0].body=delta;
  f.step.deckWirePayload={id:id(11),name:'sealed-service',host:'sealed.test',protocol:'http',port:80,retries:3,connect_timeout:60000,read_timeout:60000,write_timeout:60000,path:null};
  const wire={...f.step.deckWirePayload};delete wire.path;
  const result=await f.service.executeDeckPacket(f.authority,f.packet('PUT',wire));expect(result.status).toBe(200);
  expect(f.native.execute).toHaveBeenCalledTimes(1);expect(f.native.execute.mock.calls[0][1]).toBe(f.step);
  expect(f.step.nativeRequests[0].body).toEqual({retries:3});expect(f.step.body).toEqual({retries:3});
 });
 it.each([false,true])('accepts only a schema-sealed tag permutation while preserving the native delta (tags changed=%s)',async changed=>{
  const f=fixture(),tags=['kos-tag-team','kos-tag-owner','kos-ws-pay'],delta=changed?{retries:4,tags}:{retries:4};
  f.step.body=delta;f.step.nativeRequests[0].body=delta;
  f.step.deckWirePayload={id:id(11),host:'sealed.test',retries:4,tags};f.step.deckWireSetFields=['tags'];
  const result=await f.service.executeDeckPacket(f.authority,f.packet('PUT',{...f.step.deckWirePayload,tags:['kos-ws-pay','kos-tag-owner','kos-tag-team']}));
  expect(result.status).toBe(200);expect(f.native.execute).toHaveBeenCalledTimes(1);expect(f.step.nativeRequests[0].body).toEqual(delta);
 });
 it.each(['extra','missing','duplicate','foreign-workspace','wrong-type','unsealed-array','nested-array','missing-delta'])('refuses set-envelope substitution %s before any native mutation',async scenario=>{
  const f=fixture(),tags=['kos-tag-team','kos-ws-pay'];f.step.body={retries:4,tags};f.step.nativeRequests[0].body=f.step.body;
  f.step.deckWirePayload={id:id(11),host:'sealed.test',retries:4,tags,ordered:['first','second'],records:[{ordered:['first','second']}],nullable:null};
  f.step.deckWireSetFields=['tags','records'];const wire=structuredClone(f.step.deckWirePayload);
  if(scenario==='extra')wire.tags.push('unplanned');else if(scenario==='missing')wire.tags.pop();
  else if(scenario==='duplicate')wire.tags=['kos-ws-pay','kos-ws-pay'];else if(scenario==='foreign-workspace')wire.tags=['kos-tag-team','kos-ws-foreign'];
  else if(scenario==='wrong-type')wire.tags='kos-ws-pay';else if(scenario==='unsealed-array')wire.ordered.reverse();
  else if(scenario==='nested-array')wire.records[0].ordered.reverse();else delete wire.tags;
  await expect(f.service.executeDeckPacket(f.authority,f.packet('PUT',wire))).rejects.toMatchObject({response:{code:'CONFIGURATION_DECK_PACKET_NOT_IN_PLAN'}});
  expect(f.native.execute).not.toHaveBeenCalled();expect(f.repo.recordStepEvidence).not.toHaveBeenCalled();expect(f.row.state).toBe('pending');
 });
 it('keeps old sealed envelopes without set metadata order-sensitive',async()=>{
  const f=fixture();f.step.body={retries:4};f.step.nativeRequests[0].body=f.step.body;
  f.step.deckWirePayload={retries:4,tags:['kos-tag-team','kos-ws-pay']};
  await expect(f.service.executeDeckPacket(f.authority,f.packet('PUT',{retries:4,tags:['kos-ws-pay','kos-tag-team']}))).rejects.toThrow();expect(f.native.execute).not.toHaveBeenCalled();
 });
 it.each(['host','name','port','protocol','read_timeout','id','extra','null-extra','missing-delta','wrong-delta','nested-extra'])('rejects a rehashed full SDK envelope substitution: %s',async field=>{
  const f=fixture(),delta={retries:3};f.step.body=delta;f.step.nativeRequests[0].body=delta;
  f.step.deckWirePayload={id:id(11),name:'sealed-service',host:'sealed.test',protocol:'http',port:80,read_timeout:60000,retries:3};
  const body={...f.step.deckWirePayload};
  if(field==='missing-delta')delete body.retries;else if(field==='wrong-delta')body.retries=2;
  else if(field==='extra')body.unsealed='arbitrary';else if(field==='null-extra')body.unsealed=null;
  else if(field==='nested-extra')body.host={id:'sealed.test'};else body[field]=field==='id'?id(99):field==='port'||field==='read_timeout'?123:'substituted';
  await expect(f.service.executeDeckPacket(f.authority,f.packet('PUT',body))).rejects.toMatchObject({response:{code:'CONFIGURATION_DECK_PACKET_NOT_IN_PLAN'}});
  expect(f.native.execute).not.toHaveBeenCalled();expect(f.row.state).toBe('pending');
 });
 it('requires explicit planned nulls even if the SDK envelope is otherwise valid',async()=>{
  const f=fixture();f.step.deckWirePayload={...f.body,name:'sealed'};const body={...f.step.deckWirePayload};delete body.headers;
  await expect(f.service.executeDeckPacket(f.authority,f.packet('PUT',body))).rejects.toMatchObject({response:{code:'CONFIGURATION_DECK_PACKET_NOT_IN_PLAN'}});expect(f.native.execute).not.toHaveBeenCalled();
 });
 it('does not upgrade historical plans to full-object acceptance',async()=>{
  const f=fixture();await expect(f.service.executeDeckPacket(f.authority,f.packet('PUT',{...f.body,name:'unsealed'}))).rejects.toThrow();expect(f.native.execute).not.toHaveBeenCalled();
 });
 it('accepts only the complete sealed plugin config including removed fields',async()=>{
  const f=fixture();f.step.entityType='plugins';f.step.body={config:{nested:{kept:true}}};f.step.nativeRequests[0].body=f.step.body;
  f.step.deckWirePayload={id:id(11),name:'synthetic-plugin',enabled:false,config:{nested:{kept:true}}};
  const packet={...f.packet('PUT',f.step.deckWirePayload),type:'plugins',path:`/plugins/${id(11)}`};
  await f.service.executeDeckPacket(f.authority,packet);expect(f.native.execute).toHaveBeenCalledTimes(1);expect(f.step.body).toEqual({config:{nested:{kept:true}}});
 });
 it('charges actual hidden reads and retries instead of one CLI packet',async()=>{const f=fixture();const result=await f.service.executeDeckPacket(f.authority,f.packet());
  expect(result.status).toBe(200);expect(f.native.execute).toHaveBeenCalledTimes(1);expect(f.row.state).toBe('succeeded');
  const delta=f.repo.chargeDeckSessionBudget.mock.calls.at(-1)![2];expect(delta.calls).toBe(4);expect(delta.bytes).toBeGreaterThan(0);
 });
 it.each([{host:'different.test'},{host:'planned.test',unexpected:'extra'},{host:'planned.test',headers:{} }])('rejects rehashed unsealed wire body %j before native execution',async(body)=>{const f=fixture();
  await expect(f.service.executeDeckPacket(f.authority,f.packet('PATCH',{id:id(11),headers:null,...body}))).rejects.toMatchObject({response:{code:'CONFIGURATION_DECK_PACKET_NOT_IN_PLAN'}});
  expect(f.native.execute).not.toHaveBeenCalled();expect(f.row.state).toBe('pending');
 });
 it('translates Target DELETE/POST as one sealed append and preserves both IDs',async()=>{const f=fixture(true);
  const staged=await f.service.executeDeckPacket(f.authority,{...f.packet('DELETE'),body:undefined,bodyHmac:undefined});expect(staged.status).toBe(204);expect(f.native.execute).not.toHaveBeenCalled();
  const result=await f.service.executeDeckPacket(f.authority,f.packet('POST'));expect(result.entity?.id).toBe(id(11));expect(f.native.execute).toHaveBeenCalledTimes(1);
  expect(f.repo.recordStepEvidence.mock.calls.at(-1)![1].effectiveNativeId).toBe(id(12));
 });
 it('requires Target pair intent and rejects a substituted parent',async()=>{const f=fixture(true);
  await expect(f.service.executeDeckPacket(f.authority,f.packet('POST'))).rejects.toMatchObject({response:{code:'CONFIGURATION_DECK_TARGET_PAIR_REQUIRED'}});
  await f.service.executeDeckPacket(f.authority,{...f.packet('DELETE'),body:undefined,bodyHmac:undefined});
  await expect(f.service.executeDeckPacket(f.authority,f.packet('POST',{...f.body,upstream:{id:id(99)}}))).rejects.toMatchObject({response:{code:'CONFIGURATION_DECK_PACKET_NOT_IN_PLAN'}});
  expect(f.native.execute).not.toHaveBeenCalled();
 });
 it('records uncertain original outcome and refuses an implicit replay after failure',async()=>{const f=fixture(),actual=f.native.execute.getMockImplementation()!;
  f.native.execute.mockImplementation(async()=>{await actual();throw new Error('synthetic lost response');});
  await expect(f.service.executeDeckPacket(f.authority,f.packet())).rejects.toThrow('synthetic lost response');expect(f.row.state).toBe('uncertain');
  expect(f.repo.chargeDeckSessionBudget.mock.calls.at(-1)![2].calls).toBe(4);
  await expect(f.service.executeDeckPacket(f.authority,f.packet())).rejects.toMatchObject({response:{code:'CONFIGURATION_DECK_PACKET_NOT_IN_PLAN'}});expect(f.native.execute).toHaveBeenCalledTimes(1);
 });
 it('records a definite pre-native validation failure without pretending completion',async()=>{const f=fixture();f.native.receipt.mockResolvedValue(null);f.native.execute.mockRejectedValue(new ConflictException({code:'CONFIGURATION_NATIVE_PLAN_CHANGED'}));
  await expect(f.service.executeDeckPacket(f.authority,f.packet())).rejects.toThrow();expect(f.row.state).toBe('failed');expect(f.execution.completed).toBe(0);
 });
});
