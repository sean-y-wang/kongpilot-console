import {describe,expect,it,vi} from 'vitest';
import {KongExecutionContextService,type KongPolicyTicket,type ScheduledReadAbsentTransportFact} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';

function fixture(){
 const context=new KongExecutionContextService(),handle=Object.freeze({}),requests=new WeakSet<object>(),transport=new WeakMap<object,{ticket:KongPolicyTicket;fact:Readonly<ScheduledReadAbsentTransportFact>}>();
 const cluster:any={id:'target',admin_url:'http://target:8001',revision:1},response={message:'Not found'},path='/services/590b2291-3a1c-4d00-b3f5-9dee427bf052';
 let current=true,observed:object|undefined,originalToken:object|undefined;
 const proof:any=Object.freeze({version:1,origin:'workflow-schedule-candidate-read',sessionId:null,readOnly:true,actor:{id:'reviewer'},
  expiresAt:new Date(Date.now()+29000).toISOString(),scope:{limits:{maxCalls:8,maxPages:2,maxRecords:10,maxBytes:1048576},resources:[
   {clusterId:'target',workspaceId:'target-w',path,kind:'point',entityId:path.split('/').at(-1),allowAbsent:true}]},registries:[
   {clusterId:'target',workspaceId:'target-w',transportScope:transportScopeFor(cluster.admin_url),clusterRevision:1}]});
 const generic=vi.fn(async()=>{throw Error('ORDINARY_POLICY_MUST_NOT_BE_BORROWED');});context.installPolicy({authorizeRequest:generic,authorizeResponse:generic});
 const observe=vi.fn(async(token:object,body:unknown,observation?:200|object)=>{
  if(!requests.has(token)||!current)throw Error('ORIGINAL_REQUEST_REQUIRED');if(!observation||typeof observation!=='object')throw Error('ORIGINAL_OBSERVATION_REQUIRED');
  const original=context.verifyScheduledReadAbsentObservation(token,observation);expect(original.response).toBe(body);expect(original.status).toBe(404);
  observed=observation;originalToken=token;requests.delete(token);return body;
 });
 context.installWorkflowScheduleCandidateReadPolicy({async verifyHandle(h){if(h!==handle||!current)throw Error('CURRENT_AUTHORITY_REVOKED');return proof;},
  assertLive(h){if(h!==handle||!current)throw Error('CURRENT_AUTHORITY_REVOKED');},async authorizeRequest(h){if(h!==handle||!current)throw Error('CURRENT_AUTHORITY_REVOKED');const token=Object.freeze({});requests.add(token);return token;},
  async verifyRequest(token){if(!requests.has(token)||!current)throw Error('CURRENT_AUTHORITY_REVOKED');return proof;},authorizeResponse:observe});
 const verify=vi.fn((ticket:KongPolicyTicket,original:object)=>{const value=transport.get(original);if(!value||value.ticket!==ticket)throw Error('ORIGINAL_TRANSPORT_REQUIRED');return value.fact;});
 const install=()=>context.installScheduledReadAbsentTransportObserver({verifyTransport:verify});
 const mint=(ticket:KongPolicyTicket,changes:Record<string,unknown>={})=>{const value=Object.freeze({});transport.set(value,{ticket,fact:Object.freeze({clusterId:cluster.id,
  transportScope:transportScopeFor(cluster.admin_url),clusterRevision:1,method:'GET',path,query:{},status:404,response,...changes}) as any});return value;};
 return{context,handle,cluster,path,response,observe,verify,install,mint,generic,revoke(){current=false;},get observation(){return observed;},get token(){return originalToken;}};
}
describe('scheduled absence requires the genuine transport and request observation',()=>{
 it('accepts one original GET observation, charges actual bytes, and closes it without Native permission',async()=>{
  const f=fixture();f.install();await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   const ticket=await f.context.authorizeRequest(f.cluster,'GET',f.path,undefined,{}),proof=f.mint(ticket);
   await expect(f.context.observeScheduledReadAbsent(ticket,proof)).resolves.toBe(true);expect(f.observe).toHaveBeenCalledTimes(1);
   expect(f.context.currentUsage()).toMatchObject({calls:1,pages:0,records:0,bytes:Buffer.byteLength(JSON.stringify(f.response))});
   expect(()=>f.context.verifyScheduledReadAbsentObservation(f.token!,f.observation!)).toThrow();
   await expect(f.context.observeScheduledReadAbsent(ticket,proof)).resolves.toBe(false);expect(f.generic).not.toHaveBeenCalled();
  });
 });
 it('missing observer rejects scheduled absence before the response can become a completed read',async()=>{
  const f=fixture();await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   const ticket=await f.context.authorizeRequest(f.cluster,'GET',f.path,undefined,{});
   await expect(f.context.observeScheduledReadAbsent(ticket,f.mint(ticket))).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ABSENCE_TRANSPORT_REQUIRED'}});
   expect(f.observe).not.toHaveBeenCalled();
  });
 });
 it('copied transport handles or a transport for another ticket cannot prove absence',async()=>{
  const f=fixture();f.install();await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   const first=await f.context.authorizeRequest(f.cluster,'GET',f.path,undefined,{}),second=await f.context.authorizeRequest(f.cluster,'GET',f.path,undefined,{}),proof=f.mint(first);
   for(const [ticket,value]of [[first,{...proof}],[second,proof]] as const)await expect(f.context.observeScheduledReadAbsent(ticket,value)).rejects.toThrow('ORIGINAL_TRANSPORT_REQUIRED');
   expect(f.observe).not.toHaveBeenCalled();
  });
 });
 it.each([{clusterId:'foreign'},{clusterRevision:2},{transportScope:transportScopeFor('http://foreign:8001')},{method:'POST'},{path:'/consumers'},{query:{offset:'foreign'}},{status:500}])('rejects changed transport tuple %j',async changes=>{
  const f=fixture();f.install();await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   const ticket=await f.context.authorizeRequest(f.cluster,'GET',f.path,undefined,{});
   await expect(f.context.observeScheduledReadAbsent(ticket,f.mint(ticket,changes))).rejects.toMatchObject({response:{code:'WORKFLOW_SCHEDULE_ABSENCE_TRANSPORT_CHANGED'}});expect(f.observe).not.toHaveBeenCalled();
  });
 });
 it('rechecks current authorization after transport completion',async()=>{
  const f=fixture();f.install();await f.context.runWorkflowScheduleCandidateRead(f.handle,async()=>{
   const ticket=await f.context.authorizeRequest(f.cluster,'GET',f.path,undefined,{}),proof=f.mint(ticket);f.revoke();
   await expect(f.context.observeScheduledReadAbsent(ticket,proof)).rejects.toThrow('CURRENT_AUTHORITY_REVOKED');expect(f.observe).not.toHaveBeenCalled();
  });
 });
 it('does not observe an ordinary HTTP read as a scheduled absence',async()=>{
  const context=new KongExecutionContextService();context.installPolicy({async authorizeRequest(){return{};},async authorizeResponse(_t,r){return r;}});
  const verify=vi.fn(()=>{throw Error('NOT_SCHEDULED');});context.installScheduledReadAbsentTransportObserver({verifyTransport:verify});
  await context.runHttp({},async()=>{context.bindHttpActor({id:'ordinary'} as any,'real-http-fixture');return context.runActor({actor:{id:'ordinary'} as any,clusterId:'cluster',workspaceId:'workspace'},async()=>{
   const ticket=await context.authorizeRequest({id:'cluster',admin_url:'http://kong:8001',version:'1.5.1',execution_mode:'direct'},'GET','/services',undefined,{});
   await expect(context.observeScheduledReadAbsent(ticket,{})).resolves.toBe(false);expect(verify).not.toHaveBeenCalled();
  });});
 });
 it('does not allow caller-shaped observation DTOs or duplicate observer installation',()=>{
  const f=fixture();f.install();expect(()=>f.context.verifyScheduledReadAbsentObservation({},{})).toThrow();expect(()=>f.install()).toThrow();
 });
});
