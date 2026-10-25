import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import type { EffectiveGrant } from '../../apps/console-api/src/common/authorization.types';

/** Real authorization matching and private executor context. SQL/transport
 * adapters are synthetic and do not establish real Kong/database acceptance. */
function fixture(){
 const cid=randomUUID(),sourceId=randomUUID(),targetId=randomUUID(),consumerId=randomUUID(),credentialId=randomUUID(),serviceId=randomUUID(),executorId=randomUUID(),reviewerId=randomUUID();
 const executor={id:executorId,username:'executor',superAdmin:false},execution=new KongExecutionContextService();let epoch='1',reviewerActive=true,reviewerSuper=false,executorSessionActive=true;
 const source={id:sourceId,cluster_id:cid,code:'source',name:'源',status:'active',revision:1},target={id:targetId,cluster_id:cid,code:'target',name:'目标',status:'active',revision:1};
 const service={id:serviceId,host:'backend.test',name:'business',tags:['kos-ws-source','team-pay']},consumer={id:consumerId,username:'app',tags:['kos-ws-source','team-pay']},key={id:credentialId,consumer:{id:consumerId},tags:['kos-ws-source','team-pay']};
 const material:any={source:structuredClone(source),target:structuredClone(target),nodes:[['services',service],['consumers',consumer],['key-auth',key]].map(([type,data]:any)=>({type,id:data.id,data,affected:true,path:type==='key-auth'?`/consumers/${consumerId}/key-auth/${data.id}`:`/${type}/${data.id}`,afterTags:['kos-ws-target','team-pay'],inheritedOnly:false})),referenceNodes:[],conflicts:[]};
 let grants:EffectiveGrant[]=['workflows:approve','workspaces:read','services:read','consumers:read'].map(pair=>{const [module,action]=pair.split(':');return {cluster_id:cid,workspace_id:null,module,action:action as any,scope_type:'global',scope_values:[]};});
 const row=(id:string)=>({id,username:id===reviewerId?'reviewer':'executor',super_admin:id===reviewerId?reviewerSuper:false,permissions_epoch:1,credential_epoch:1,force_password_change:false,status:'active',deleted_at:null});
 const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
  if(sql.includes('FROM users'))return p[0]===reviewerId?reviewerActive?row(reviewerId):null:p[0]===executorId?row(executorId):null;
  if(sql.includes('FROM auth_sessions'))return p[0]==='executor-only-session'&&p[1]===executorId&&executorSessionActive||p[0]==='reviewer-own-session'&&p[1]===reviewerId?{id:p[0]}:null;
  if(sql.includes('FROM iam_epoch'))return {version:epoch};if(sql.includes('FROM clusters'))return {id:cid};throw new Error('Unexpected authorization fixture SQL');
 }),query:vi.fn(async(sql:string,p:any[])=>{if(sql.includes('iam_effective_grants'))return p[0]===reviewerId?grants:[];throw new Error('Unexpected grant query');})};
 const workspaces:any={get:vi.fn(async(_cid:string,id:string)=>id===sourceId?source:id===targetId?target:null),classify:vi.fn(async(_cid:string,tags:string[])=>({state:'resolved',workspace:tags.includes('kos-ws-target')?target:source}))};
 let route:any;
 const kong:any={request:vi.fn(async(_cid:string,method:string,path:string)=>{expect(method).toBe('GET');const frame=execution.current();expect(frame.actor?.id===executorId&&frame.sessionId==='executor-only-session'||frame.actor?.id===reviewerId&&frame.sessionId==='reviewer-own-session').toBe(true);if(path===`/consumers/${consumerId}`)return structuredClone(consumer);if(route&&path===`/routes/${route.id}`)return structuredClone(route);if(path===`/services/${serviceId}/routes`)return {data:route?[structuredClone(route)]:[],next:null};throw new Error('Unexpected native read');})};
 const authorization=new AuthorizationService(db,workspaces,kong,execution);
 const run=(fn:()=>Promise<any>)=>execution.runHttp({},async()=>{execution.bindHttpActor(executor,'executor-only-session');const close=execution.captureHttpCloser();try{return await execution.runActor({actor:executor,clusterId:cid,workspaceId:sourceId,module:'workflows',action:'write'},fn);}finally{close();}});
 const verify=()=>run(()=>authorization.assertMigrationWorkflowReviewerEligibility(reviewerId,cid,material));
 const runReviewer=(fn:()=>Promise<any>)=>execution.runHttp({},async()=>{const reviewer={id:reviewerId,username:'reviewer',superAdmin:false};execution.bindHttpActor(reviewer,'reviewer-own-session');const close=execution.captureHttpCloser();try{return await execution.runActor({actor:reviewer,clusterId:cid,workspaceId:targetId,module:'services',action:'read'},fn);}finally{close();}});
 return {cid,sourceId,targetId,serviceId,consumerId,reviewerId,executorId,executor,execution,material,source,target,service,db,kong,authorization,run,runReviewer,verify,setRoute:(value:any)=>{route=structuredClone(value);},getGrants:()=>grants,setGrants:(value:EffectiveGrant[])=>{grants=value;},setEpoch:(value:string)=>{epoch=value;},setReviewerActive:(value:boolean)=>{reviewerActive=value;},setReviewerSuper:(value:boolean)=>{reviewerSuper=value;},setExecutorSessionActive:(value:boolean)=>{executorSessionActive=value;}};
}
afterEach(()=>vi.restoreAllMocks());
describe('M9 reviewer checks keep the executor identity and complete live scope',()=>{
 it('accepts a distinct active global-role reviewer without borrowing a reviewer SID',async()=>{
  const f=fixture();await expect(f.verify()).resolves.toBeUndefined();expect(f.db.one.mock.calls.filter(([sql]:any[])=>sql.includes('auth_sessions')).every(([,p]:any[])=>p[1]===f.executorId)).toBe(true);expect(f.kong.request).toHaveBeenCalled();
 });
 it.each(['entity','tag_group'])('retains planned Route → Service read inheritance for a %s reviewer',async scope=>{
  const f=fixture(),route={id:randomUUID(),name:'authorized-route',service:{id:f.serviceId},paths:['/business'],tags:['kos-ws-source','team-pay']};f.setRoute(route);
  f.material.nodes.push({key:`routes:${route.id}`,type:'routes',id:route.id,data:structuredClone(route),path:`/routes/${route.id}`,affected:true,afterTags:['kos-ws-target','team-pay'],inheritedOnly:false});
  f.setGrants([...f.getGrants().filter(g=>g.module!=='services'),{cluster_id:f.cid,workspace_id:null,module:'routes',action:'read',scope_type:scope as any,scope_values:scope==='entity'?[{entity_type:'routes',entity_id:route.id}]:['team-pay']}]);
  await expect(f.verify()).resolves.toBeUndefined();expect(f.kong.request.mock.calls.filter(([,method,path]:any[])=>method==='GET'&&path===`/routes/${route.id}`).length).toBeGreaterThanOrEqual(2);
 });
 it('fresh Route Service references cannot be forged by a future tag projection',async()=>{
  const f=fixture(),route={id:randomUUID(),name:'captured-route',service:{id:f.serviceId},paths:['/business'],tags:['kos-ws-source','team-pay']};
  f.material.nodes.push({key:`routes:${route.id}`,type:'routes',id:route.id,data:structuredClone(route),path:`/routes/${route.id}`,affected:true,afterTags:['kos-ws-target','team-pay'],inheritedOnly:false});f.setRoute({...route,service:{id:randomUUID()}});
  f.setGrants([...f.getGrants().filter(g=>g.module!=='services'),{cluster_id:f.cid,workspace_id:null,module:'routes',action:'read',scope_type:'entity',scope_values:[{entity_type:'routes',entity_id:route.id}]}]);
  await expect(f.verify()).rejects.toMatchObject({response:{code:'MIGRATION_PARENT_CHANGED'}});
 });
 it('Route grants from a foreign cluster cannot approve a planned Service',async()=>{
  const f=fixture(),route={id:randomUUID(),name:'route',service:{id:f.serviceId},paths:['/business'],tags:['kos-ws-source','team-pay']};f.setRoute(route);
  f.material.nodes.push({key:`routes:${route.id}`,type:'routes',id:route.id,data:route,path:`/routes/${route.id}`,affected:true,afterTags:['kos-ws-target','team-pay'],inheritedOnly:false});f.setGrants([...f.getGrants().filter(g=>g.module!=='services'),{cluster_id:randomUUID(),workspace_id:null,module:'routes',action:'read',scope_type:'entity',scope_values:[{entity_type:'routes',entity_id:route.id}]}]);
  await expect(f.verify()).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('normal entity reads do not inherit future tags from a caller object',async()=>{
  const f=fixture(),route={id:randomUUID(),name:'route',service:{id:f.serviceId},paths:['/business'],tags:['kos-ws-source','team-pay']};f.setRoute(route);f.setGrants([...f.getGrants().filter(g=>g.module!=='services'),{cluster_id:f.cid,workspace_id:null,module:'routes',action:'read',scope_type:'entity',scope_values:[{entity_type:'routes',entity_id:route.id}]}]);
  const reviewer={id:f.reviewerId,username:'reviewer',superAdmin:false};await expect(f.runReviewer(()=>f.authorization.assertEntity(reviewer,f.cid,'services','read',{...f.service,tags:['kos-ws-target','team-pay']},f.targetId))).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
 });
 it('ordinary actor authorization still rejects using the distinct reviewer identity',async()=>{
  const f=fixture();await expect(f.run(()=>f.authorization.assertCluster({id:f.reviewerId,username:'reviewer',superAdmin:false},f.cid,'workflows','approve',f.sourceId))).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
 });
 it('requires target approval rather than combining a source-only grant with target read',async()=>{
  const f=fixture();f.setGrants(f.getGrants().map(g=>g.module==='workflows'?{...g,scope_type:'workspace',workspace_id:f.sourceId,scope_values:[f.sourceId]}:g));await expect(f.verify()).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('rejects tag/entity approval rows even when coarse module dimensions match',async()=>{
  const f=fixture();f.setGrants(f.getGrants().map(g=>g.module==='workflows'?{...g,scope_type:'entity',scope_values:[{entity_type:'services',entity_id:f.serviceId}]}:g));await expect(f.verify()).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
 });
 it('rechecks native graph read after approval, including a removed Service grant',async()=>{
  const f=fixture();f.setGrants(f.getGrants().filter(g=>g.module!=='services'));await expect(f.verify()).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('reuses credential parent scope rather than requiring or inventing a credentials module',async()=>{
  const f=fixture();f.setGrants(f.getGrants().map(g=>g.module==='consumers'?{...g,scope_type:'entity',scope_values:[{entity_type:'consumers',entity_id:f.consumerId}]}:g));await expect(f.verify()).resolves.toBeUndefined();expect(f.getGrants().some(g=>g.module==='credentials')).toBe(false);
 });
 it('rejects a changed consumer scope instead of combining IDs from independent rows',async()=>{
  const f=fixture();f.setGrants(f.getGrants().map(g=>g.module==='consumers'?{...g,scope_type:'entity',scope_values:[{entity_type:'consumers',entity_id:randomUUID()}]}:g));await expect(f.verify()).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
 });
 it.each(['revision','code','status'])('rejects changed target workspace %s',async field=>{
  const f=fixture();(f.target as any)[field]=field==='revision'?2:field==='code'?'new-target':'disabled';await expect(f.verify()).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('fences a reviewer permission epoch change during parent reads',async()=>{
  const f=fixture(),original=f.kong.request.getMockImplementation()!;f.kong.request.mockImplementation(async(...args:any[])=>{const result=await (original as any)(...args);f.setEpoch('2');return result;});await expect(f.verify()).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
 });
 it('requires the executor session and active reviewer without manufacturing a reviewer session',async()=>{
  const f=fixture();f.setExecutorSessionActive(false);await expect(f.verify()).rejects.toMatchObject({response:{code:'SESSION_EXPIRED'}});expect(f.kong.request).not.toHaveBeenCalled();
  const g=fixture();g.setReviewerActive(false);await expect(g.verify()).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
 });
 it('allows an active platform reviewer but still rejects their later disabled identity',async()=>{
  const f=fixture();f.setGrants([]);f.setReviewerSuper(true);await expect(f.verify()).resolves.toBeUndefined();f.setReviewerActive(false);await expect(f.verify()).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
 });
 it('refuses an unscoped HTTP request and self reviewer before SQL access',async()=>{
  const f=fixture();await expect(Promise.resolve().then(()=>f.authorization.assertMigrationWorkflowReviewerEligibility(f.reviewerId,f.cid,f.material))).rejects.toThrow();expect(f.db.one).not.toHaveBeenCalled();await expect(f.run(()=>f.authorization.assertMigrationWorkflowReviewerEligibility(f.executorId,f.cid,f.material))).rejects.toMatchObject({response:{code:'PERMISSION_DENIED'}});
 });
});
