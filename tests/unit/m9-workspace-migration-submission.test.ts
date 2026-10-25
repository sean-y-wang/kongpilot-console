import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { WorkspaceMigrationWorkflowService } from '../../apps/console-api/src/modules/workflows/workspace-migration-workflow.service';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';

/** Real decorator + private HTTP/actor context + compiler. SQL storage and
 * grants are explicit domain fixtures, not native or database acceptance. */
function fixture(){
 const cid=randomUUID(),id=randomUUID(),sourceId=randomUUID(),targetId=randomUUID(),nativeId=randomUUID(),secrets=new SecretService(),execution=new KongExecutionContextService();
 const user={id:randomUUID(),username:'migration-submitter',superAdmin:false},actor={user,workspaceId:sourceId,idempotencyKey:`submit-${randomUUID()}`,requestId:randomUUID(),ip:'127.0.0.1'};
 const data={id:nativeId,name:'source-service',host:'backend.test',tags:['kos-ws-source']},afterTags=['kos-ws-target'];
 const material={source:{id:sourceId,cluster_id:cid,code:'source',name:'源',revision:1,status:'active'},target:{id:targetId,cluster_id:cid,code:'target',name:'目标',revision:1,status:'active'},
  nodes:[{key:`services:${nativeId}`,type:'services',id:nativeId,path:`/services/${nativeId}`,data,affected:true,dependencies:[],sourceWorkspaceId:sourceId,beforeFingerprint:secrets.fingerprint(data),configFingerprint:secrets.fingerprint({id:nativeId,name:'source-service',host:'backend.test'}),afterTags,inheritedOnly:false}],referenceNodes:[],edges:[],conflicts:[],budget:{pages:1,records:1,nodes:1},permissions:'fixture-epoch'};
 const row={id,cluster_id:cid,actor_id:user.id,source_workspace_id:sourceId,target_workspace_id:targetId,state:'planned',operation_id:null,expires_at:new Date(Date.now()+30*60_000),plan_hash:secrets.fingerprint({cid,actor:user.id,payload:material}),payload_secret:secrets.encrypt(material,`workspace-migration:${id}`)};
 const request={confirmed:true,confirm_name:'目标',plan_hash:row.plan_hash};let persisted:any;
 const scope=()=>{const frame=execution.current();expect(frame).toMatchObject({kind:'actor',actor:{id:user.id},sessionId:'verified-http-session',clusterId:cid,workspaceId:sourceId,module:'workspaces',action:'write',requestId:actor.requestId});};
 const db:any={one:vi.fn(async(sql:string)=>{scope();if(sql.includes('workspace_migration_workflow_bindings'))return null;if(sql.includes('FROM clusters'))return {revision:1,execution_mode:'approval'};if(sql.includes('FROM workspace_migration_plans'))return row;throw new Error('Unexpected fixture query');}),exec:vi.fn(async()=>{scope();return 1;}),transaction:vi.fn(async(fn:any)=>fn(db))};
 const redis:any={withLock:vi.fn(async(_key:string,fn:any)=>{scope();return fn();})},kong:any={transportScope:vi.fn(async()=>{scope();return secrets.fingerprint('fixture-transport');}),request:vi.fn(()=>{throw new Error('Submission must not send a native write');})};
 const authz:any={assertWholeWorkspace:vi.fn(async()=>{scope();})},migrations:any={workflowMaterial:vi.fn(async(_cid:string,_id:string,_body:any,currentActor:any)=>{scope();expect(currentActor).toBe(actor);return {row,material};})};
 const plans:any={definitions:vi.fn(async()=>scope()),definition:vi.fn(async()=>({id:randomUUID(),version:1,policyHash:secrets.fingerprint('fixed-policy')})),persist:vi.fn(async(plan:any,key:string,_request:any,tx:any,meta:any)=>{scope();validateWorkflowPlan(plan);expect(key).toBe(actor.idempotencyKey);expect(tx).toBe(db);expect(meta).toEqual({requestId:actor.requestId,ip:actor.ip});persisted=plan;return {id:plan.workflowId};})};
 const workflows:any={get:vi.fn(async(_cid:string,wfid:string,current:any)=>{scope();expect(wfid).toBe(persisted.workflowId);expect(current.workspaceId).toBe(sourceId);return {entity:{id:wfid,state:'pending'}};})};
 const service=new WorkspaceMigrationWorkflowService(db,redis,secrets,kong,authz,migrations,plans,workflows,execution);
 const run=(fn:()=>Promise<any>,boundUser=user)=>execution.runHttp({requestId:actor.requestId,ip:actor.ip},async()=>{execution.bindHttpActor(boundUser,'verified-http-session');const close=execution.captureHttpCloser();try{return await fn();}finally{close();}});
 return {cid,id,user,actor,sourceId,targetId,request,execution,db,redis,kong,authz,migrations,plans,workflows,service,run,getPlan:()=>persisted};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','d1'.repeat(32)));
afterEach(()=>vi.unstubAllEnvs());
describe('M9 actual decorated migration submission entry',()=>{
 it('binds the verified HTTP session before planning and seals the existing M3 operation without native writes',async()=>{
  const f=fixture();await expect(f.run(()=>f.service.submit(f.cid,f.id,f.request,f.actor))).resolves.toMatchObject({entity:{state:'pending'}});
  expect(f.plans.persist).toHaveBeenCalledOnce();expect(f.db.exec).toHaveBeenCalledOnce();expect(f.kong.request).not.toHaveBeenCalled();
  const plan=f.getPlan();expect(plan).toMatchObject({kind:'workspace-migration',workspaceId:f.sourceId,requester:{type:'console',id:f.user.id},migration:{sourceWorkspaceId:f.sourceId,targetWorkspaceId:f.targetId}});
  expect(plan.steps[0].nativeRequests).toHaveLength(1);expect(plan.steps[0].nativeRequests[0].body).toEqual({tags:['kos-ws-target']});
 });
 it('rejects calls without the private HTTP context before any SQL or plan work',async()=>{
  const f=fixture();await expect(Promise.resolve().then(()=>f.service.submit(f.cid,f.id,f.request,f.actor))).rejects.toBeInstanceOf(ForbiddenException);expect(f.db.one).not.toHaveBeenCalled();expect(f.migrations.workflowMaterial).not.toHaveBeenCalled();
 });
 it('rejects an unbound HTTP principal before inspecting the request or ledger',async()=>{
  const f=fixture();await expect(Promise.resolve().then(()=>f.execution.runHttp({},()=>f.service.submit(f.cid,f.id,f.request,f.actor)))).rejects.toMatchObject({response:{code:'KONG_ACTOR_SCOPE_MISMATCH'}});expect(f.db.one).not.toHaveBeenCalled();
 });
 it('rejects replacing the verified actor even with a valid body and key',async()=>{
  const f=fixture(),other={id:randomUUID(),username:'other',superAdmin:true};await expect(f.run(()=>f.service.submit(f.cid,f.id,f.request,{...f.actor,user:other}))).rejects.toMatchObject({response:{code:'KONG_ACTOR_SCOPE_MISMATCH'}});expect(f.db.one).not.toHaveBeenCalled();
 });
 it('fails closed if the required decorator execution provider is absent',async()=>{
  const f=fixture();(f.service as any).execution=undefined;expect(()=>f.service.submit(f.cid,f.id,f.request,f.actor)).toThrow(ForbiddenException);expect(f.db.one).not.toHaveBeenCalled();
 });
});
