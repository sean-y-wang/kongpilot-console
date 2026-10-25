import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
import {candidateAbsenceFixture,validationAbsenceFixture} from './helpers/workflow-scheduled-read-absence-fixture';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn()}));
const outbound=vi.mocked(outboundJson);

/** Actual SDK perform, Context private tickets, both real provider state
 * machines and cryptography. Outbound responses and SQL are controlled Source
 * adapters; these tests do not contact a runtime Kong or prove real approvals. */
function fixture(kind:'candidate'|'validation'){
 const f:any=kind==='candidate'?candidateAbsenceFixture():validationAbsenceFixture(),context=new KongExecutionContextService();
 const target={...f.values.resources[0],allowAbsent:true},collection={clusterId:f.cid,workspaceId:f.wid,path:'/services',kind:'collection',entityType:'services',secrets:false,query:{size:2}};
 f.values.resources=[collection,target];
 const business=kind==='candidate'?f.policies:f.business;
 business.authorizeResponse.mockImplementation(async(input:any)=>{if(f.values.scopeChanged)throw Error('CURRENT_OBJECT_SCOPE_DENIED');
  if(input.status===404){if(!input.resource.allowAbsent||!f.values.read)throw Error('ACTUAL_FIXED_ABSENCE_GRANTS_DENIED');return;}});
 const generic=vi.fn(async()=>{throw Error('ORDINARY_HTTP_POLICY_MUST_NOT_RUN');});context.installPolicy({authorizeRequest:generic,authorizeResponse:generic});
 f.redis.rateLimit=vi.fn(async()=>({allowed:true}));
 let originalProof:object|undefined,originalTicket:any,originalObservation:object|undefined,originalToken:object|undefined;
 const kong=new KongService(f.db,f.redis,f.secrets,{} as any,context);
 context.installScheduledReadAbsentTransportObserver({verifyTransport(ticket,proof){originalTicket=ticket;originalProof=proof;return kong.verifyScheduledReadAbsentTransport(ticket,proof);}});
 f.service.installAbsentResponseVerifier({verifyOriginalResponse(token:object,observation:object){originalObservation=observation;originalToken=token;return context.verifyScheduledReadAbsentObservation(token,observation);}});
 const policy={verifyHandle:f.service.verifyHandle.bind(f.service),assertLive:f.service.assertLive.bind(f.service),authorizeRequest:f.service.authorizeRequest.bind(f.service),
  verifyRequest:f.service.verifyRequest.bind(f.service),authorizeResponse:f.service.authorizeResponse.bind(f.service)};
 if(kind==='candidate'){
  f.runner.assertNoFrame.mockImplementation(()=>{if(context.peek())throw Error('REAL_EMPTY_CONTEXT_REQUIRED');});
  f.runner.run.mockImplementation((handle:object,fn:()=>Promise<any>)=>context.runWorkflowScheduleCandidateRead(handle,fn));context.installWorkflowScheduleCandidateReadPolicy(policy);
 }else{
  context.installWorkflowScheduledNamespacePolicy({async verifyHandle(handle){if(handle!==f.nsHandle)throw Error('ORIGINAL_NAMESPACE_REQUIRED');return f.ns;},
   assertLive(handle){if(handle!==f.nsHandle||!f.values.live||!f.state.lease)throw Error('ACTUAL_SOURCE_NS_LEASE_DENIED');}});
  f.runner.originalNamespaceProof.mockImplementation((handle:object)=>context.requireWorkflowScheduledCurrentPrincipal(handle).namespace);
  // Namespace.assertLive is the leaf guard. Calling any Context getter here
  // would recurse through Context.chain -> validation.assertLive -> runner.
  f.runner.assertNamespaceLive.mockImplementation((handle:object)=>{if(handle!==f.nsHandle||!f.values.live||!f.state.lease)throw Error('ACTUAL_SOURCE_NS_LEASE_DENIED');});
  f.runner.run.mockImplementation((handle:object,original:object,fn:()=>Promise<any>)=>context.runWorkflowScheduledValidationRead(handle,original,fn));context.installWorkflowScheduledValidationReadPolicy(policy);
 }
 f.install();
 outbound.mockImplementation(async(_base,path,_method,_body,_query,_auth,_timeout,beforeSend,prepareSend)=>{
  await prepareSend?.();beforeSend?.();return {status:path===target.path?404:200,body:path===target.path?{message:'Not found'}:{data:[],next:null},bytes:20,jsonParsed:true};
 });
 const run=(fn:(handle:object)=>Promise<any>)=>kind==='candidate'?f.service.runOriginalPlan(f.plan,f.owner,'executor',fn)
  :context.runWorkflowScheduledNamespace(f.nsHandle,()=>f.run(fn));
 const eof=()=>kong.request(f.cid,'GET','/services',undefined,{size:2});
 const point=()=>kong.request(f.cid,'GET',target.path);
 return{...f,kind,context,kong,generic,business,target,collection,run,eof,point,proofs:()=>({originalProof,originalTicket,originalObservation,originalToken})};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-14T01:00:00.000Z'));outbound.mockReset();});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});
describe.each(['candidate','validation'] as const)('original %s scheduled GET404 observation',kind=>{
 it('observes one genuine SDK JSON404 after actual complete EOF, then still throws the original 404 to readBefore',async()=>{
  const f=fixture(kind);await f.run(async()=>{await f.eof();await expect(f.point()).rejects.toMatchObject({status:404,response:{code:'KONG_VALIDATION_ERROR',upstreamStatus:404}});});
  expect(outbound).toHaveBeenCalledTimes(2);expect(outbound.mock.calls.every(call=>call[2]==='GET')).toBe(true);expect(f.generic).not.toHaveBeenCalled();
  expect(f.business.authorizeResponse.mock.calls.map((call:any[])=>call[0].status)).toEqual([200,404]);
  const p=f.proofs();expect(()=>f.kong.verifyScheduledReadAbsentTransport(p.originalTicket,p.originalProof!)).toThrow();
  expect(()=>f.context.verifyScheduledReadAbsentObservation(p.originalToken!,p.originalObservation!)).toThrow();
 });
 it('rejects an absence before a complete observed collection even when the caller catches the response',async()=>{
  const f=fixture(kind);await expect(f.run(async()=>{try{await f.point();}catch{}return true;})).rejects.toThrow();
  expect(f.business.authorizeResponse).not.toHaveBeenCalled();expect(outbound).toHaveBeenCalledTimes(1);
 });
 it('does not accept an incomplete collection or a collection that observed that same id as an absence witness',async()=>{
  const f=fixture(kind);outbound.mockImplementation(async(_base,path)=>({status:path===f.target.path?404:200,
   body:path===f.target.path?{message:'Not found'}:{data:[{id:f.nativeId}],next:null},bytes:20,jsonParsed:true}));
  await expect(f.run(async()=>{await f.eof();try{await f.point();}catch{}return true;})).rejects.toThrow();
  expect(f.business.authorizeResponse.mock.calls.filter((call:any[])=>call[0].status===404)).toHaveLength(0);
 });
 it.each(['false','missing','empty','primitive','entity-body','non-json-message'])('cannot complete an optional absent point from %s parsing/body evidence',async mode=>{
  const f=fixture(kind);f.target.required=false;f.values.resources=[f.collection,f.target];
  outbound.mockImplementation(async(_base,path)=>path===f.target.path?{status:404,body:mode==='empty'?null:mode==='primitive'?false:mode==='entity-body'?{id:f.nativeId}:mode==='non-json-message'?{message:'上游返回非 JSON 响应'}:{message:'Not found'},bytes:20,
   ...(mode==='missing'?{}:{jsonParsed:mode!=='false'})} as any:{status:200,body:{data:[],next:null},bytes:20,jsonParsed:true});
  await expect(f.run(async()=>{await f.eof();try{await f.point();}catch{}return {callerGuessedAbsent:true};})).rejects.toThrow();
  expect(f.business.authorizeResponse.mock.calls.filter((call:any[])=>call[0].status===404)).toHaveLength(0);
 });
 it.each([401,403,429,500])('does not turn HTTP %s into optional-point absence',async status=>{
  const f=fixture(kind);f.target.required=false;f.values.resources=[f.collection,f.target];
  outbound.mockImplementation(async(_base,path)=>({status:path===f.target.path?status:200,body:path===f.target.path?{message:'Not found'}:{data:[],next:null},bytes:20,jsonParsed:true}));
  const running=f.run(async()=>{await f.eof();try{await f.point();}catch{}return true;});const rejected=expect(running).rejects.toThrow();await vi.runAllTimersAsync();await rejected;
  expect(f.business.authorizeResponse.mock.calls.filter((call:any[])=>call[0].status===404)).toHaveLength(0);expect(f.proofs().originalProof).toBeUndefined();
 });
 it('cannot turn a transport timeout into optional-point absence or issue a Native request',async()=>{
  const f=fixture(kind);f.target.required=false;f.values.resources=[f.collection,f.target];
  outbound.mockImplementation(async(_base,path)=>{if(path===f.target.path)throw Object.assign(Error('controlled timeout'),{code:'ETIMEDOUT'});return {status:200,body:{data:[],next:null},bytes:20,jsonParsed:true};});
  const running=f.run(async()=>{await f.eof();try{await f.point();}catch{}return true;});const rejected=expect(running).rejects.toThrow();await vi.runAllTimersAsync();await rejected;
  expect(f.proofs().originalProof).toBeUndefined();expect(outbound.mock.calls.every(call=>call[2]==='GET')).toBe(true);
 });
 it.each([kind==='candidate'?'actor-status':'lease','epoch','permission','scope'])('rechecks %s after the actual 404 transport response and poisons a caught failure',async reason=>{
  const f=fixture(kind);outbound.mockImplementation(async(_base,path)=>{if(path===f.target.path){if(reason==='actor-status')f.state.forceChange=true;if(reason==='lease')f.state.lease=false;
   if(reason==='epoch')f.state.epoch='2';if(reason==='permission')f.values.read=false;if(reason==='scope')f.values.scopeChanged=true;return {status:404,body:{message:'Not found'},bytes:20,jsonParsed:true};}
   return {status:200,body:{data:[],next:null},bytes:20,jsonParsed:true};});
  await expect(f.run(async()=>{await f.eof();try{await f.point();}catch{}return true;})).rejects.toThrow();
  expect(f.business.authorizeResponse.mock.calls.filter((call:any[])=>call[0].status===404)).toHaveLength(reason==='scope'?1:0);
 });
 it.each([404,{},null,{status:404,response:{message:'Not found'}}])('refuses a caller-shaped observation %j despite an original request token',async forged=>{
  const f=fixture(kind);await expect(f.run(async(handle:object)=>{await f.eof();const token=await f.service.authorizeRequest(handle,{clusterId:f.cid,workspaceId:f.wid,method:'GET',path:f.target.path,query:{}});
   try{await f.service.authorizeResponse(token,{message:'Not found'},forged);}catch{}return true;})).rejects.toThrow();
  expect(outbound).toHaveBeenCalledTimes(1);expect(f.business.authorizeResponse.mock.calls.filter((call:any[])=>call[0].status===404)).toHaveLength(0);
 });
 it.each(['collection','schema','allowAbsent=false'])('keeps %s 404 outside the absence exception',async reason=>{
  const f=fixture(kind);if(reason==='allowAbsent=false'){f.target.allowAbsent=false;f.values.resources=[f.collection,f.target];}
  else if(reason==='schema')f.values.resources=[{clusterId:f.cid,workspaceId:f.wid,path:'/schemas/services',kind:'schema',entityType:'services',secrets:false}];
  else f.values.resources=[f.collection];
  outbound.mockResolvedValue({status:404,body:{message:'Not found'},bytes:20,jsonParsed:true});
  await expect(f.run(async()=>{try{await f.kong.request(f.cid,'GET',reason==='schema'?'/schemas/services':reason==='collection'?'/services':f.target.path,undefined,reason==='collection'?{size:2}:{});}catch{}return true;})).rejects.toThrow();
  expect(f.business.authorizeResponse).not.toHaveBeenCalled();
 });
});
