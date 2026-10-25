import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {HttpException} from '@nestjs/common';
import {candidateAbsenceFixture,validationAbsenceFixture} from './helpers/workflow-scheduled-read-absence-fixture';
import {immutableJson} from '../../apps/console-api/src/infrastructure/kong/immutable-json';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn()}));
const outbound=vi.mocked(outboundJson);
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32)));afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
function fixture(superAdmin:boolean,kind:'candidate'|'validation'='candidate'){
 const f:any=kind==='candidate'?candidateAbsenceFixture():validationAbsenceFixture(),context=new KongExecutionContextService(),consumerId=randomUUID(),childId=randomUUID();
 const parent:any={clusterId:f.cid,workspaceId:f.wid,path:`/consumers/${consumerId}`,kind:'point',entityType:'consumers',entityId:consumerId,secrets:false,required:true,allowAbsent:true};
 const child:any={clusterId:f.cid,workspaceId:f.wid,path:`/consumers/${consumerId}/key-auth/${childId}`,kind:'point',entityType:'keyauth_credentials',entityId:childId,parentId:consumerId,secrets:true,required:true,allowAbsent:true};
 const business=kind==='candidate'?f.policies:f.business;f.values.resources=[parent,child];business.resolveReadScope.mockImplementation(async()=>({version:1,domain:'scoped-points-v1',resources:f.values.resources,limits:{maxCalls:10,maxPages:5,maxRecords:10,maxBytes:8192}}));
 const one=f.db.one.getMockImplementation()!;f.db.one.mockImplementation(async(sql:string,args:any[])=>{const row=await one(sql,args);return sql.includes('FROM users')&&row?{...row,super_admin:superAdmin}:row;});
 context.installPolicy({authorizeRequest:async()=>{throw Error('NO_ORDINARY_POLICY');},authorizeResponse:async()=>{throw Error('NO_ORDINARY_POLICY');}});
 f.redis.rateLimit=vi.fn(async()=>({allowed:true}));const kong=new KongService(f.db,f.redis,f.secrets,{}as any,context);
 if(kind==='candidate')context.installWorkflowScheduleCandidateReadPolicy(f.service);else context.installWorkflowScheduledValidationReadPolicy(f.service);
 context.installScheduledReadAbsentTransportObserver({verifyTransport:(ticket,proof)=>kong.verifyScheduledReadAbsentTransport(ticket,proof)});
 f.service.installAbsentResponseVerifier({verifyOriginalResponse:(token,observation)=>context.verifyScheduledReadAbsentObservation(token,observation)});
 const assertChild=vi.fn(async(input:any,selected:any,actualParent:any)=>{expect(input.principal.user.superAdmin).toBe(superAdmin);expect(input.transaction).toBe(f.db);
  expect(selected).toEqual(child);expect(actualParent).toEqual(parent);});f.service.installParentAbsencePolicy({assertChild});
 const namespace=kind==='validation'?immutableJson({...f.ns,actor:{...f.ns.actor,superAdmin}}):undefined;
 if(kind==='candidate'){
  f.runner.assertNoFrame.mockImplementation(()=>{if(context.peek())throw Error('GENUINE_EMPTY_CONTEXT_REQUIRED');});
  f.runner.run.mockImplementation((handle:object,fn:()=>Promise<unknown>)=>context.runWorkflowScheduleCandidateRead(handle,fn));
 }else{
  const live=(handle:object)=>{if(handle!==f.nsHandle||!f.values.live||!f.state.lease)throw Error('GENUINE_NAMESPACE_REQUIRED');};
  context.installWorkflowScheduledNamespacePolicy({verifyHandle:async handle=>{live(handle);return namespace;},assertLive:live}as any);
  f.runner.originalNamespaceProof.mockImplementation((handle:object)=>context.requireWorkflowScheduledCurrentPrincipal(handle).namespace);
  f.runner.assertNamespaceLive.mockImplementation(live);
  f.runner.run.mockImplementation((handle:object,original:object,fn:()=>Promise<unknown>)=>context.runWorkflowScheduledValidationRead(handle,original,fn));
 }
 f.install();
 const state={status:404};outbound.mockImplementation(async(_base,_path,_method,_body,_query,_auth,_timeout,before,prepare)=>{await prepare?.();before?.();return{status:state.status,body:state.status===404?{message:'Not found'}:{id:consumerId},bytes:23,jsonParsed:true};});
 const run=(fn:(handle:object)=>Promise<unknown>)=>kind==='candidate'?f.service.runOriginalPlan(f.plan,f.owner,'executor',fn,f.db):context.runWorkflowScheduledNamespace(f.nsHandle,()=>f.run(fn));
 return{...f,context,kong,parent,child,assertChild,state,run,namespace,kind};
}
/** Genuine Candidate/Context/Kong SDK original404/FK association; controlled
 * SQL/HTTP fixtures and fixed domain callback, not a production Native trial. */
describe('all-role required exact points preserve original SDK absence gates',()=>{
 it.each([{superAdmin:false,kind:'candidate'},{superAdmin:true,kind:'candidate'},{superAdmin:false,kind:'validation'},{superAdmin:true,kind:'validation'}]as const)('observes parent404 once and derives no extra child GET for %j',async({superAdmin,kind})=>{
  const f=fixture(superAdmin,kind);let original:object|undefined;
  await f.run(async handle=>{original=handle;const proof=await f.service.verifyHandle(handle,...(kind==='validation'?[f.nsHandle,f.namespace]:[]));expect(proof.actor.superAdmin).toBe(superAdmin);
   await expect(f.kong.request(f.cid,'GET',f.parent.path)).rejects.toMatchObject({status:404});
   const witness=await f.service.requireObservedAbsentPoint(handle,f.parent);expect(witness).toBeTypeOf('object');
   expect(await f.service.observeFutureChildAbsence(handle,f.child,witness)).toEqual({kind:'parent-FK-absence',nativeRequestsSent:0});
  });expect(outbound).toHaveBeenCalledTimes(1);expect(f.assertChild).toHaveBeenCalledOnce();
  await expect(f.service.verifyHandle(original!)).rejects.toThrow();
 });
 it.each([{superAdmin:false,kind:'candidate'},{superAdmin:true,kind:'candidate'},{superAdmin:false,kind:'validation'},{superAdmin:true,kind:'validation'}]as const)('cannot replace the original SDK observation with an error or DTO for %j',async({superAdmin,kind})=>{
  const f=fixture(superAdmin,kind);await expect(f.run(async handle=>{
   const token=await f.service.authorizeRequest(handle,{clusterId:f.cid,workspaceId:f.wid,method:'GET',path:f.parent.path,query:{}});
   await expect(f.service.authorizeResponse(token,{message:'Not found'},404 as any)).rejects.toThrow();
   await expect(f.service.requireObservedAbsentPoint(handle,f.parent)).rejects.toThrow();
  })).rejects.toThrow();expect(outbound).not.toHaveBeenCalled();expect(f.assertChild).not.toHaveBeenCalled();
 });
 it.each([{superAdmin:false,kind:'candidate'},{superAdmin:true,kind:'candidate'},{superAdmin:false,kind:'validation'},{superAdmin:true,kind:'validation'}]as const)('does not relabel an actual parent200 as nonexistent for %j',async({superAdmin,kind})=>{
  const f=fixture(superAdmin,kind);f.state.status=200;
  await expect(f.run(async handle=>{await f.kong.request(f.cid,'GET',f.parent.path);await f.service.requireObservedAbsentPoint(handle,f.parent);})).rejects.toThrow();
  expect(outbound).toHaveBeenCalledTimes(1);expect(f.assertChild).not.toHaveBeenCalled();
 });
});
