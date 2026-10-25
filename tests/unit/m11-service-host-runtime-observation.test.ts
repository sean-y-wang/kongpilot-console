import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {HttpException} from '@nestjs/common';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {serviceObservationContextFixture} from './helpers/m11-service-observation-context-fixture';
import {WorkflowBusinessRuntimeService} from '../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {assertProxyDestination,assertTargetDestination} from '../../apps/console-api/src/infrastructure/kong/destination-policy';

vi.mock('../../apps/console-api/src/infrastructure/kong/destination-policy',async original=>({...await original<any>(),assertProxyDestination:vi.fn(async()=>undefined),assertTargetDestination:vi.fn(async()=>undefined)}));
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ae'.repeat(32)));
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
/** Actual Runtime fixed observer algorithm, Context original public-registration
 * ALS/meter and Kong installed DNS consumer. SQL/Approved/Material/Validation,
 * SDK responses and DNS are controlled Source adapters. No real HTTP/Native,
 * SQL, permission or SDK404 transport provenance acceptance is claimed here. */
function fixture(options:{destination?:boolean;reviewers?:number;absent?:boolean;fake404?:boolean;literal?:boolean;pages?:number;tls?:boolean}={}){
 const f=serviceObservationContextFixture(),secrets=new SecretService(),handle=Object.freeze({}),upstreamId=randomUUID(),host=options.literal?'203.0.113.7':'service-backend.local';
 const reviewers=Array.from({length:options.reviewers??2},()=>randomUUID());f.ns.approvalSet.reviewers.push(...reviewers.map(userId=>({userId})));
 const parent:any={clusterId:f.cid,workspaceId:f.wid,path:`/upstreams/${host}`,kind:'point',entityType:'upstreams',secrets:false,required:false,allowAbsent:true,serviceHostReference:{host,serviceIds:[f.nativeId]}};
 const child:any={clusterId:f.cid,workspaceId:f.wid,path:`/upstreams/${upstreamId}/targets`,kind:'collection',entityType:'targets',parentId:upstreamId,secrets:false,required:false,query:{size:100},serviceHostReference:parent.serviceHostReference};
 const certId=randomUUID(),caId=randomUUID(),serviceBefore:any={id:f.nativeId,host,...(options.tls?{client_certificate:{id:certId},ca_certificates:[caId]}:{})};
 const certResource:any={clusterId:f.cid,workspaceId:f.wid,path:`/certificates/${certId}`,kind:'point',entityType:'certificates',entityId:certId,secrets:true,required:true},caResource:any={clusterId:f.cid,workspaceId:f.wid,path:`/ca_certificates/${caId}`,kind:'point',entityType:'ca_certificates',entityId:caId,secrets:false,required:true};
 const tlsRows:any[]=[{resource:certResource,entity:{id:certId,cert:'controlled-public-cert',key:'controlled-test-private-key'}},{resource:caResource,entity:{id:caId,cert:'controlled-ca-cert'}}];
 const tlsObservations=new Map(tlsRows.map(ref=>[ref.resource.path,{resource:ref.resource,value:ref.entity}]));
 const parentRaw:any={id:upstreamId,name:host,tags:[]},targetPages=Array.from({length:options.pages??1},(_v,i)=>({data:[{id:randomUUID(),target:`203.0.113.${i+8}:8080`,upstream:{id:upstreamId}}],next:i===(options.pages??1)-1?null:`/upstreams/${upstreamId}/targets?offset=${i+1}`}));
 const state:any={deniedReviewer:undefined,rows:[],participantCalls:[],tlsParticipantCalls:[],readCalls:[],contexts:[],witnesses:new WeakMap<object,any>(),live:true};
 const input:any={plan:{workflowId:f.ns.workflow.id},draft:{},role:'executor',principal:{user:f.actor},transaction:{}};
 const intent:any={namespaceHandle:f.nsHandle,namespace:f.ns,clusterId:f.cid,workspaceId:f.wid,actorId:f.actor.id,workflowId:f.ns.workflow.id,nativeId:f.nativeId,observation:options.destination===false?undefined:'service-destination'};
 let activeRead:object|undefined;
 const validation:any={runValidationResources:vi.fn(async(_ns:any,_cid:any,_wid:any,resources:any[],_tx:any,fn:any)=>{
   const read=Object.freeze({});activeRead=read;state.contexts.push(resources);try{return await fn(read);}finally{activeRead=undefined;}
 }),observedServiceHostAbsence:vi.fn(async(original:any,selected:any)=>{const witness=state.witnesses.get(original);if(original!==activeRead||selected!==parent||!witness)throw Error('SOURCE_ORIGINAL_SDK404_REQUIRED');return witness;})};
 const contextResource=vi.spyOn(f.context,'runWorkflowScheduledReadResource').mockImplementation(async(original:any,resource:any,fn:any)=>{
   if(original!==activeRead||resource!==parent&&resource!==child)throw Error('SOURCE_ORIGINAL_FIXED_RESOURCE_REQUIRED');return fn();
 });
 const kong:any={request:vi.fn(async(_cid:any,method:any,path:any,_body:any,query:any)=>{
   if(method!=='GET')throw Error('SOURCE_NO_NATIVE');state.readCalls.push({path,query});
   const ticket=await f.context.authorizeRequest(f.cluster,'GET',path,undefined,query);
   if(path===parent.path&&options.absent){if(!options.fake404)state.witnesses.set(activeRead!,{originalWitness:Object.freeze({}),response:{message:'Not found'}});throw new HttpException({message:'not found'},404);}
   const raw=path===parent.path?parentRaw:targetPages[Number(query.offset??0)];return f.context.authorizeResponse(ticket,raw);
 })};
 const material:any={resolveAbsenceReadScope:vi.fn(async()=>({resources:[parent]})),resolveServiceHostTargetResource:vi.fn(async(_input:any,p:any,raw:any)=>{if(p!==parent||raw!==parentRaw)throw Error('SOURCE_EXACT_PARENT_RAW_REQUIRED');return child;}),
   assertServiceTlsParticipant:vi.fn(async(participant:any,observation:any)=>{state.tlsParticipantCalls.push({participant,observation});if(participant.principal.user.id===state.deniedTlsReviewer)throw Error('SOURCE_CURRENT_TLS_READ_DENIED');await state.afterTls?.(observation);}),
   assertServiceHostReadComplete:vi.fn(async()=>{if(!state.live)throw Error('SOURCE_CURRENT_READ_REVOKED');}),
   currentReadInput:vi.fn(async(plan:any,draft:any,userId:any,role:any,tx:any)=>({plan,draft,role,transaction:tx,principal:{user:{id:userId}}})),
   assertServiceHostParticipant:vi.fn(async(participant:any,p:any,raw:any,status:any,pages:any,includeTargets:any,serviceObservation:any)=>{
     state.participantCalls.push({participant,p,raw,status,pages,includeTargets,serviceObservation});if(!serviceObservation||serviceObservation.serviceId!==f.nativeId||serviceObservation.before.id!==f.nativeId||serviceObservation.before.host!==host)throw Error('SOURCE_CURRENT_SERVICE_OBSERVATION_REQUIRED');if(participant.principal.user.id===state.deniedServiceReviewer)throw Error('SOURCE_CURRENT_SERVICE_READ_DENIED');if(participant.principal.user.id===state.deniedReviewer)throw Error('SOURCE_CURRENT_REVIEWER_READ_DENIED');
     if(p!==parent||status===200&&raw!==parentRaw||status===404&&raw?.message!=='Not found'||pages.some((page:any,i:number)=>page!==targetPages[i]))throw Error('SOURCE_ORIGINAL_RAW_CHANGED');
   })};
 const approved:any={assertConfigurationNativeBeforeReadLive(original:any){if(original!==handle||!state.live)throw Error('SOURCE_ORIGINAL_BEFORE_READ_REQUIRED');}};
 const repository:any={inspectStored:vi.fn(async()=>({plan:input.plan,draft:input.draft}))};
 const runtime:any=new WorkflowBusinessRuntimeService({}as any,{}as any,secrets,f.context,kong,{}as any,{}as any,{}as any,approved,repository,{}as any,{}as any,{}as any,validation,{}as any,material,{}as any,{}as any,{}as any,{}as any,{}as any);
 const read=f.context.installConfigurationServiceBeforeObserver({read:async(original:any)=>{
   if(original!==handle)throw Error('SOURCE_ORIGINAL_READ_REQUIRED');
   const tls=options.tls?await runtime.configurationServiceTlsObservation(handle,intent,input,tlsObservations,serviceBefore,{}):{};
   const result=await runtime.configurationServiceHostObservation(handle,intent,input,serviceBefore,{});return{before:serviceBefore,...tls,...result};
 }});
 f.approved.readConfigurationNativeBefore=vi.fn(async()=>read(handle as any));
 const redis:any={assertLeaseOwnership:vi.fn(async()=>{if(!state.live)throw Error('SOURCE_CURRENT_REDIS_LEASE_REVOKED');})};
 const service=new KongService({}as any,redis,secrets,{}as any,f.context);
 return{...f,state,handle,intent,input,parent,child,parentRaw,targetPages,reviewers,material,validation,kong,runtime,read,redis,service,contextResource,tlsRows,tlsObservations,serviceBefore};
}
describe('Service one SDK observation and every current participant',()=>{
 it('reads one named parent and two real pages once while checking each reviewer',async()=>{
  const f=fixture({reviewers:4,pages:2});await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).resolves.toBe(true);});
  expect(f.state.readCalls).toHaveLength(3);expect(f.state.participantCalls).toHaveLength(4);expect(f.state.participantCalls.every((call:any)=>call.raw===f.parentRaw&&call.pages[0]===f.targetPages[0]&&call.includeTargets)).toBe(true);
  expect(assertTargetDestination).toHaveBeenCalledTimes(2);expect(f.redis.assertLeaseOwnership).toHaveBeenCalledTimes(2);
 });
 it('checks an SDK404 for the original exact name and then checks every reviewer before direct DNS',async()=>{
  const f=fixture({absent:true});await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).resolves.toBe(true);});
  expect(f.validation.observedServiceHostAbsence).toHaveBeenCalledOnce();expect(f.state.readCalls).toHaveLength(1);expect(f.state.participantCalls).toHaveLength(2);expect(assertProxyDestination).toHaveBeenCalled();
 });
 it('rejects a caught404 with no original opaque SDK observation',async()=>{
  const f=fixture({absent:true,fake404:true});await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toThrow('SOURCE_ORIGINAL_SDK404_REQUIRED');});expect(f.state.participantCalls).toEqual([]);
 });
 it('does not publish or reach DNS after any reviewer loses current read access',async()=>{
  const f=fixture();f.state.deniedReviewer=f.reviewers[1];vi.mocked(assertTargetDestination).mockClear();
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toThrow('SOURCE_CURRENT_REVIEWER_READ_DENIED');});expect(assertTargetDestination).not.toHaveBeenCalled();
 });
 it('keeps the same current Service observation for entity-scoped participants on the genuine404 branch',async()=>{
  const f=fixture({absent:true});await f.packet(async(ticket:any)=>{await f.context.protectScheduledConfigurationServiceDestination(ticket);});
  expect(f.state.participantCalls.every((call:any)=>call.serviceObservation.serviceId===f.nativeId&&call.serviceObservation.before.id===f.nativeId)).toBe(true);
 });
 it('denies genuine404 if any participant loses the current Service permission',async()=>{
  const f=fixture({absent:true});f.state.deniedServiceReviewer=f.reviewers[0];vi.mocked(assertProxyDestination).mockClear();
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toThrow('SOURCE_CURRENT_SERVICE_READ_DENIED');});expect(assertProxyDestination).not.toHaveBeenCalled();
 });
 it('enforces the fifth actual Target page boundary without inventing EOF',async()=>{
  const f=fixture({pages:6});await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toMatchObject({response:{code:'CONFIGURATION_SERVICE_TARGET_PAGE_BUDGET'}});});expect(f.state.readCalls).toHaveLength(6);
 });
 it('does not call the arbitrary Upstream name API for a literal IP host',async()=>{
  const f=fixture({literal:true});await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).resolves.toBe(true);});expect(f.state.readCalls).toHaveLength(0);expect(assertProxyDestination).toHaveBeenCalled();
 });
 it('reference-only reads do not collect Targets and cannot leak a destination result',async()=>{
  const f=fixture({destination:false});await f.packet(async()=>{const result=await f.read(f.handle as any);expect(result).toHaveProperty('serviceHostUpstream',f.parentRaw);expect(result).not.toHaveProperty('serviceTargets');});expect(f.state.readCalls).toHaveLength(1);expect(f.state.participantCalls.every((call:any)=>call.includeTargets===false)).toBe(true);
 });
 it('uses the same fresh TLS SDK reference points for every reviewer, including literal IP Services',async()=>{
  const f=fixture({tls:true,literal:true});let result:any;await f.packet(async()=>{result=await f.read(f.handle as any);});
  expect(result.serviceReferences).toHaveLength(2);expect(f.state.readCalls).toHaveLength(0);expect(f.state.tlsParticipantCalls).toHaveLength(2);
  expect(f.state.tlsParticipantCalls.every((call:any)=>call.observation.before===f.serviceBefore&&call.observation.references.some((ref:any)=>ref.entity===f.tlsRows[0].entity))).toBe(true);
 });
 it('requires the genuine same-round TLS point instead of falling back to a five-second fresh read',async()=>{
  const f=fixture({tls:true});f.tlsObservations.delete(f.tlsRows[0].resource.path);
  await f.packet(async()=>{await expect(f.read(f.handle as any)).rejects.toMatchObject({response:{code:'CONFIGURATION_SERVICE_TLS_CURRENT_POINT_REQUIRED'}});});expect(f.state.readCalls).toHaveLength(0);
 });
 it('rejects a participant TLS secret/read revocation before destination DNS',async()=>{
  const f=fixture({tls:true});f.state.deniedTlsReviewer=f.reviewers[0];vi.mocked(assertTargetDestination).mockClear();
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toThrow('SOURCE_CURRENT_TLS_READ_DENIED');});expect(assertTargetDestination).not.toHaveBeenCalled();
 });
 it('rejects raw TLS substitution during an awaited participant closing',async()=>{
  const f=fixture({tls:true});f.state.afterTls=async()=>{await Promise.resolve();f.tlsRows[0].entity.cert='changed-after-observation';};
  await f.packet(async()=>{await expect(f.read(f.handle as any)).rejects.toMatchObject({response:{code:'CONFIGURATION_SERVICE_TLS_ORIGINAL_OBSERVATION_REQUIRED'}});});
 });
 it('keeps the same ten seconds through the last asynchronous DNS and lease check',async()=>{
  const f=fixture();let now=500;vi.spyOn(globalThis.performance,'now').mockImplementation(()=>now);vi.mocked(assertTargetDestination).mockImplementationOnce(async()=>{await Promise.resolve();now+=10001;});
  await f.packet(async(ticket:any)=>{await expect(f.context.protectScheduledConfigurationServiceDestination(ticket)).rejects.toMatchObject({response:{code:'CONFIGURATION_SERVICE_OBSERVATION_EXPIRED'}});});
 });
});
