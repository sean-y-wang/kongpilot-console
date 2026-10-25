import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {MutationService} from '../../apps/console-api/src/modules/mutations/mutation.service';
import {ConfigurationNativeService} from '../../apps/console-api/src/modules/configuration/configuration-native.service';
import type {ConfigurationPlanStep} from '../../apps/console-api/src/modules/configuration/configuration.types';
import {executionFixture} from './execution-test-fixture';
import {payWorkspaceId,workspaceFixture} from './workspace-test-fixture';

const cid='20000000-0000-4000-8000-000000000001',nativeId='20000000-0000-4000-8000-000000000002';
const actor={id:'20000000-0000-4000-8000-000000000003',username:'scoped-executor',superAdmin:false};
const tags=['team-pay','kos-ws-pay'];
/** Real native adapter, mutation service, authorization and workspace resolver;
 * only infrastructure/transport and the domain execution bridge are fixtures.
 * This is not a claim of a live Kong or approved-token execution. */
function fixture(){
 const secrets=new SecretService(),ws=workspaceFixture(cid),execution=executionFixture(),records=new Map<string,any>();
 const grants:any[]=['services','ca_certificates'].flatMap(module=>['read','write','delete'].map(action=>({module,action,scope_type:'global',scope_values:[],cluster_id:cid,workspace_id:payWorkspaceId})));
 let remote:any={id:nativeId,name:'new-service',host:'example.internal',tags};
 const db:any={one:vi.fn(async(sql:string,p:any[])=>{
  if(sql.includes('FROM users'))return{id:actor.id,username:actor.username,status:'active',super_admin:false,permissions_epoch:1,credential_epoch:1};
  if(sql.includes('iam_epoch'))return{version:1};
  if(sql.includes('FROM clusters'))return{id:cid,execution_mode:'direct',version:'1.5.1'};
  if(sql.includes('FROM mutation_operations'))return[...records.values()].find(r=>r.id===(p[1]??p[0])||r.idempotency_key===p[1])??null;
  throw new Error(`Unexpected fixture query: ${sql}`);
 }),query:vi.fn(async(sql:string)=>{
  if(sql.includes('iam_effective_grants'))return grants;
  if(sql.includes('mutation_operations'))return[...records.values()].filter(r=>['running','uncertain'].includes(r.state));
  throw new Error(`Unexpected fixture collection: ${sql}`);
 }),exec:vi.fn(async(sql:string,p:any[])=>{
  if(sql.startsWith('INSERT INTO mutation_operations')){
   records.set(p[4],{id:p[0],cluster_id:p[1],actor_id:p[2],action:p[3],idempotency_key:p[4],request_hash:p[5],workflow_id:p[6],request_id:p[7],entity_type:p[8],entity_id:p[9],before_secret:p[10],payload_secret:p[11],workspace_id:p[12],transport_scope:p[13],impact:JSON.parse(p[14]),state:'running'});return 1;
  }
  const row=[...records.values()].find(r=>r.id===p[0]);if(!row)throw new Error('Missing fixture operation');
  if(sql.includes('remote_started=true'))row.remote_started=true;
  else if(sql.includes('remote_completed=true'))Object.assign(row,{remote_completed:true,entity_id:p[1],result_secret:p[2]});
  else if(sql.includes("state='succeeded'"))Object.assign(row,{state:'succeeded',safe_result:JSON.parse(p[1])});
  else throw new Error(`Unexpected fixture update: ${sql}`);
  return 1;
 })};db.transaction=async(fn:any)=>fn(db);
 const kong:any={transportScope:vi.fn(async()=>cid),request:vi.fn(async(_cid:string,method:string,_path:string,body:any)=>{
  if(method==='POST'||method==='PATCH'){remote={...remote,...body};return structuredClone(remote);}
  if(method==='GET')return structuredClone(remote);
  throw new Error('Unexpected transport method');
 })};
 const authz=new AuthorizationService(db,ws.resolver,kong,execution),audit:any={append:vi.fn(async()=>undefined)},redis:any={withLock:vi.fn(async(_key:any,fn:any)=>fn())};
 const mutations=new MutationService(db,redis,secrets,audit,kong,authz,ws.resolver,execution);
 const access:any={description:vi.fn(async()=>({actor,scope:{clusterId:cid,workspaceId:payWorkspaceId},jobId:'job',requestId:'source-request',ip:'127.0.0.1'})),assertCurrent:vi.fn(),currentJob:()=>({jobId:'job'})};
 const native=new ConfigurationNativeService(access,kong,execution,secrets,authz,ws.resolver,mutations,{archiveAndDelete:vi.fn()}as any,{save:vi.fn()}as any,{upsert:vi.fn()}as any);
 function step(action:'create'|'update'|'delete'='create',before:unknown=null):ConfigurationPlanStep{
  const body={id:nativeId,name:'new-service',host:'example.internal',tags},beforeHmac=secrets.fingerprint(before),bodyHmac=secrets.fingerprint(body);
  return{stepId:'sealed-step',stepOrder:1,objectKey:`services:${nativeId}`,entityType:'services',objectWorkspaceId:payWorkspaceId,clearMap:[],nativeId:action==='create'?null:nativeId,allocatedNativeId:action==='create'?nativeId:null,permissionAction:action==='delete'?'delete':'write',mutationAction:action,dependencies:[],body,before,bodyHmac,beforeHmac,nativeRequests:[{method:action==='create'?'POST':action==='delete'?'DELETE':'PATCH',canonicalPath:action==='create'?'/services':`/services/${nativeId}`,body,bodyHmac,beforeHmac}],referenceOnly:false,blockerCodes:[],maskedDiff:[]};
 }
 return{native,mutations,authz,kong,db,records,secrets,grants,step,redis,audit};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','a8'.repeat(32));vi.stubEnv('APP_SECRET','native-create-test-material-at-least-32-characters');});
afterEach(()=>vi.unstubAllEnvs());

describe('M8 sealed CREATE absence at the native mutation boundary',()=>{
 it('creates once through real authorization/mutation and retains canonical encrypted null plus a verifiable receipt',async()=>{
  const f=fixture(),step=f.step(),sealed=structuredClone(step),context=await f.native.context({}as any,step,'job-step');
  expect(context.before).toBeUndefined();expect(f.secrets.fingerprint(context.before??null)).toBe(step.beforeHmac);
  const result=await f.native.execute({}as any,step,'job-step'),row=[...f.records.values()][0];
  expect(result.receipt).toMatchObject({state:'succeeded',remoteStarted:true,remoteCompleted:true,entityId:nativeId});
  expect(f.secrets.decrypt(row.before_secret,`mutation:${row.id}:before`)).toBeNull();
  expect(f.secrets.decrypt(row.payload_secret,`mutation:${row.id}:payload`)).toEqual(step.body);
  expect(f.kong.request.mock.calls.filter(c=>c[1]==='POST')).toHaveLength(1);
  expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'create',requestId:'source-request',result:'success'}),expect.anything());
  expect(step).toEqual(sealed);
  const replay=await f.native.execute({}as any,step,'job-step');expect(replay.receipt.operationId).toBe(row.id);
  expect(f.kong.request.mock.calls.filter(c=>c[1]==='POST')).toHaveLength(1);
 });
 it.each(['update','delete']as const)('retains null %s before and real authorization denies it before ledger/transport',async action=>{
  const f=fixture(),context=await f.native.context({}as any,f.step(action),'job-step');expect(context.before).toBeNull();
  await expect(f.mutations.execute(context,vi.fn())).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
  expect(f.records.size).toBe(0);expect(f.redis.withLock).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('does not turn a non-null CREATE before into missing authorization',async()=>{
  const f=fixture(),before={id:nativeId,tags:['kos-ws-ops']},context=await f.native.context({}as any,f.step('create',before),'job-step');
  expect(context.before).toEqual(before);await expect(f.mutations.execute(context,vi.fn())).rejects.toMatchObject({status:403});
  expect(f.records.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('keeps generic MutationService null CREATE fail closed',async()=>{
  const f=fixture(),context=await f.native.context({}as any,f.step(),'job-step');context.before=null;
  await expect(f.mutations.execute(context,vi.fn())).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
  expect(f.records.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('still denies an unauthorized CREATE payload even with no old resource',async()=>{
  const f=fixture();for(const grant of f.grants)Object.assign(grant,{scope_type:'tag_group',scope_values:['team-ops']});
  await expect(f.native.execute({}as any,f.step(),'job-step')).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
  expect(f.records.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('still denies read-only CREATE before transport',async()=>{
  const f=fixture();f.grants.splice(0,f.grants.length,...f.grants.filter(g=>g.action==='read'));
  await expect(f.native.execute({}as any,f.step(),'job-step')).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
  expect(f.records.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('retains and checks a real UPDATE before including concurrent-change detection',async()=>{
  const f=fixture(),before={id:nativeId,name:'new-service',host:'old.internal',tags},step=f.step('update',before);
  expect((await f.native.context({}as any,step,'job-step')).before).toEqual(before);
  await expect(f.native.execute({}as any,step,'job-step')).rejects.toMatchObject({response:{code:'ENTITY_CHANGED'}});
  expect(f.records.size).toBe(0);expect(f.kong.request.mock.calls.every(c=>c[1]==='GET')).toBe(true);
 });
 it.each(['body','before','packet-body','packet-before'])('rejects changed %s seal before allocating a mutation',async kind=>{
  const f=fixture(),step=f.step();if(kind==='body')step.bodyHmac='changed';else if(kind==='before')step.beforeHmac='changed';else if(kind==='packet-body')(step.nativeRequests[0]as any).bodyHmac='changed';else(step.nativeRequests[0]as any).beforeHmac='changed';
  await expect(f.native.execute({}as any,step,'job-step')).rejects.toMatchObject({response:{code:'CONFIGURATION_NATIVE_PLAN_CHANGED'}});
  expect(f.records.size).toBe(0);expect(f.kong.request).not.toHaveBeenCalled();
 });
});
