import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {defer,from,lastValueFrom} from 'rxjs';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {KongScopeInterceptor} from '../../apps/console-api/src/modules/authorization/kong-scope.interceptor';
import {NativeKongPolicyService} from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import {AuthorizationService} from '../../apps/console-api/src/modules/authorization/authorization.service';
import {WorkspaceResolverService} from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import {GovernanceAuthorityService} from '../../apps/console-api/src/modules/governance/governance-authority.service';
import {GovernanceService} from '../../apps/console-api/src/modules/governance/governance.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {GOVERNANCE_ENTITY_TYPES} from '../../apps/console-api/src/modules/governance/governance-inventory.types';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import {workspaceTestResolver} from '../unit/workspace-test-helper';

/** SQL records and gateway responses below are explicitly synthetic fixtures.
 * The actual HTTP scope interceptor, authorization, private read capability,
 * native policy and restored ALS ancestry run without mocks of their guards. */
function fixture(){
 const cid=randomUUID(),targetCid=randomUUID(),uid=randomUUID(),sid=randomUUID(),targetWid=randomUUID(),comparisonId=randomUUID(),runId=randomUUID(),key=randomUUID();
 const sourceWs=workspaceTestResolver(cid),targetWs=workspaceTestResolver(targetCid);targetWs.rows[0].id=targetWid;
 const wid=sourceWs.rows[0].id,context=new KongExecutionContextService(),secrets=new SecretService(),actor={user:{id:uid,username:'cross-cluster-history',superAdmin:true},workspaceId:wid,requestId:randomUUID(),idempotencyKey:key};
 const state={allowTarget:true,sessionActive:true},wire:any[]=[],clusters=new Map([cid,targetCid].map((id,index)=>[id,{id,admin_url:`http://${index?'target':'source'}-kong:8001`,version:'1.5.1',status:'healthy',revision:1,execution_mode:'direct',connection_secret:null,enabled_plugins:[]} ]));
 const db:any={exec:vi.fn(async(sql:string)=>{if(sql.startsWith('INSERT INTO workspaces(')&&sql.includes("ON CONFLICT(cluster_id,code) DO NOTHING"))return 0;throw Error('HISTORY_BUSINESS_FACT_WRITE_FORBIDDEN');}),query:vi.fn(async(sql:string)=>sql.includes('iam_effective_grants')?state.allowTarget?[]:['drift',...GOVERNANCE_ENTITY_TYPES].map(module=>({module,action:'read',scope_type:'global',scope_values:[],cluster_id:cid,workspace_id:null})):[]),one:vi.fn(async(sql:string,p:any[])=>{
  if(sql.includes('FROM users'))return p[0]===uid?{id:uid,username:actor.user.username,status:'active',deleted_at:null,super_admin:state.allowTarget,force_password_change:false,credential_epoch:1,permissions_epoch:1}:null;
  if(sql.includes('FROM auth_sessions'))return p[0]===sid&&p[1]===uid&&state.sessionActive?{id:sid,credential_epoch:1,expires_at:new Date(Date.now()+600000).toISOString()}:null;
  if(sql.includes('iam_epoch'))return{version:1};
  if(sql.includes('metrics_write_fences'))return{count:'0',latest_time:null,latest_id:null};
  if(sql.includes('mutation_operations'))return{count:'0'};
  if(sql.includes('FROM clusters'))return clusters.get(p[0])??null;
  if(sql.includes('FROM workspaces'))return (p[0]===cid?sourceWs:targetWs).db.one(sql,p);
  if(sql.includes('SELECT id FROM governance_comparisons'))return p[0]===runId?{id:comparisonId}:null;
  throw Error('UNEXPECTED_SYNTHETIC_HISTORY_READ');
 })};
 const resolver=new WorkspaceResolverService(db),responses=new Map<string,any>();
 const inventory=(clusterId:string,workspaceId:string)=>{
  const serviceId=randomUUID(),routeId=randomUUID(),pluginId=randomUUID(),service={id:serviceId,name:'payments',host:'echo',tags:[]},route={id:routeId,name:'payments-route',service:{id:serviceId},paths:['/pay'],protocols:['http'],tags:[]},plugin={id:pluginId,name:'request-termination',route:{id:routeId},config:{status_code:418},tags:[]};
  for(const[type,data]of [['services',service],['routes',route],['plugins',plugin]]as const)responses.set(`${clusterId}:/${type}/${data.id}`,data);
  return{id:randomUUID(),scope:{clusterId,workspaceId,kind:'workspace',rootIds:[],transportScope:transportScopeFor(clusters.get(clusterId)!.admin_url)},objects:[['services',service],['routes',route],['plugins',plugin]].map(([entityType,payload]:any)=>({entityType,nativeId:payload.id,objectWorkspaceId:workspaceId,payload,sensitiveFields:[]})),completeness:'complete',projection:false};
 };
 const source=inventory(cid,wid),target=inventory(targetCid,targetWid);
 const kong:any={request:vi.fn(async(clusterId:string,method:string,path:string,body?:unknown,query={})=>{
  const ticket=await context.authorizeRequest(clusters.get(clusterId)!,method,path,body,query);await context.assertGovernanceBeforeSend(ticket);await context.beforeNativeSend(ticket);
  const frame=context.current();wire.push({clusterId,method,path,actorId:frame.actor?.id,sessionId:frame.sessionId,purpose:frame.purpose,operation:frame.operation,archive:frame.archive});
  if(!responses.has(`${clusterId}:${path}`))throw Error('UNEXPECTED_SYNTHETIC_NATIVE_PATH');return context.authorizeResponse(ticket,structuredClone(responses.get(`${clusterId}:${path}`)));
 })};
 const authz=new AuthorizationService(db,resolver,kong,context),nativePolicy=new NativeKongPolicyService(db,secrets,kong,context,authz,resolver);nativePolicy.install();
 const authority=new GovernanceAuthorityService(db,secrets,context,authz,resolver,kong);authority.onModuleInit();
 const row={id:comparisonId,cluster_id:cid,workspace_id:wid,target_cluster_id:targetCid,target_workspace_id:targetWid,run_state:'succeeded',quality:'complete',counts:{sourceOnly:0,targetOnly:0,changed:1,unchanged:2},threshold:0,threshold_exceeded:true,safe_changes:[],created_at:new Date().toISOString()};
 const runRow={id:runId,cluster_id:cid,workspace_id:wid,actor_id:uid,idempotency_key:key,kind:'comparison',state:'succeeded'};
 const repo:any={comparison:vi.fn(async(id:string,clusterId:string,workspaceId:string)=>{if(id!==comparisonId||clusterId!==cid||workspaceId!==wid)throw Error('SYNTHETIC_COMPARISON_SCOPE_CHANGED');return row;}),comparisonInventories:vi.fn(()=>({source,target})),comparisonMaterials:vi.fn(()=>({source,target})),runByKey:vi.fn(async(userId:string,originalKey:string)=>userId===uid&&originalKey===key?runRow:null)};
 const capture:any={captureActor:vi.fn(),capture:vi.fn()},configuration:any={importDocument:vi.fn(),createGovernancePromotionPlan:vi.fn()},audit:any={append:vi.fn()};
 const service=new GovernanceService(db,{}as any,secrets,context,authz,resolver,authority,capture,repo,{}as any,configuration,audit,kong),interceptor=new KongScopeInterceptor(context);
 const http=<T>(fn:()=>Promise<T>)=>context.runHttp({requestId:actor.requestId},async()=>{
  context.bindHttpActor(actor.user,sid);const close=context.captureHttpCloser(),req={params:{clusterId:cid},query:{workspaceId:wid},user:actor.user,requestId:actor.requestId,method:'GET',path:`/api/v1/clusters/${cid}/governance/comparisons/${comparisonId}`};
  try{return await lastValueFrom(interceptor.intercept({switchToHttp:()=>({getRequest:()=>req})}as any,{handle:()=>defer(()=>from(fn()))}));}finally{close();}
 });
 return{cid,targetCid,wid,targetWid,uid,sid,key,comparisonId,actor,state,wire,context,service,http,db,capture,configuration,audit};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','fa'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());

describe('M10 comparison historical reads under the actual source HTTP interceptor stack',()=>{
 it('reads both bound Plugin parent scopes using genuine isolated target authority and then restores the source frame',async()=>{
  const f=fixture(),response=await f.http(async()=>{expect(f.context.current().clusterId).toBe(f.cid);const response=await f.service.comparison(f.cid,f.comparisonId,{},f.actor);expect(f.context.current().clusterId).toBe(f.cid);expect(f.context.current().sessionId).toBe(f.sid);return response;});
  expect(response.entity).toMatchObject({id:f.comparisonId,quality:'complete',source:{clusterId:f.cid,workspaceId:f.wid},target:{clusterId:f.targetCid,workspaceId:f.targetWid}});
  expect(new Set(f.wire.map(row=>row.clusterId))).toEqual(new Set([f.cid,f.targetCid]));
  expect(f.wire.every(row=>row.method==='GET'&&row.actorId===f.uid&&row.sessionId===f.sid&&row.operation===undefined&&row.archive===undefined)).toBe(true);
  expect(f.capture.captureActor).not.toHaveBeenCalled();expect(f.capture.capture).not.toHaveBeenCalled();expect(f.configuration.importDocument).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();expect(f.db.exec.mock.results.every((r:any)=>r.type==='return')).toBe(true);
 });
 it('recovers the exact sealed original comparison by key without recapturing or changing its succeeded fact',async()=>{
  const f=fixture(),response=await f.http(()=>f.service.receipt(f.cid,f.key,f.actor));
  expect(response).toMatchObject({actorId:f.uid,clusterId:f.cid,workspaceId:f.wid,idempotencyKey:f.key,kind:'comparison',state:'succeeded',executionCompleted:true,nativeExecutionRequested:false,entity:{id:f.comparisonId,target:{clusterId:f.targetCid,workspaceId:f.targetWid}}});
  expect(f.capture.captureActor).not.toHaveBeenCalled();expect(f.capture.capture).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();expect(f.db.exec.mock.results.every((r:any)=>r.type==='return')).toBe(true);
 });
 it('a caller super-admin projection cannot disclose target history after current SQL grants are revoked',async()=>{
  const f=fixture();f.state.allowTarget=false;
  await expect(f.http(()=>f.service.comparison(f.cid,f.comparisonId,{},f.actor))).rejects.toMatchObject({status:403});
  expect(f.wire).toHaveLength(0);expect(f.capture.captureActor).not.toHaveBeenCalled();
 });
 it('keeps the generic cross-cluster internal-read guard closed under the same real source interceptor stack',async()=>{
  const f=fixture();await expect(f.http(()=>f.context.runInternalRead(f.targetCid,'authorization',async()=>{}))).rejects.toMatchObject({response:{code:'KONG_INTERNAL_SCOPE_MISMATCH'}});expect(f.wire).toHaveLength(0);
 });
});
