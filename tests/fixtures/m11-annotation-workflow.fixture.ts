import 'reflect-metadata';
import {expect,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {EntityAnnotationsService} from '../../apps/console-api/src/modules/workspaces/entity-annotations.service';
import {EntityAnnotationBusinessService} from '../../apps/console-api/src/modules/annotations/entity-annotation-business.service';
import {EntityAnnotationWorkflowService} from '../../apps/console-api/src/modules/annotations/entity-annotation-workflow.service';
import {assertEntityAnnotationPlan} from '../../apps/console-api/src/modules/annotations/entity-annotation-workflow-plan';
import {immutableJson} from '../../apps/console-api/src/infrastructure/kong/immutable-json';
/** Real original annotation closures, Business ALS, Main WeakMap and Context
 * ALS. SQL/current grants and the Approved root are controlled Source transport
 * fixtures. These tests do not certify real PostgreSQL, browser or Kong. */
const clone=<T>(v:T):T=>structuredClone(v);
export function annotationWorkflowFixture(){
 const cid=randomUUID(),wid=randomUUID(),entityId=randomUUID(),userId=randomUUID(),sid=randomUUID(),secondSid=randomUUID(),reviewerId=randomUUID(),reviewerSid=randomUUID(),secrets=new SecretService(),context=new KongExecutionContextService();
 const author:any={user:{id:userId,username:'annotation-author',superAdmin:false},workspaceId:wid,idempotencyKey:'annotation-original-prepare',requestId:randomUUID()},reviewer:any={user:{id:reviewerId,username:'annotation-reviewer',superAdmin:false},workspaceId:wid,requestId:randomUUID()},
  workspaceGrant=(module:string,action:string)=>({module,action,scope_type:'workspace',scope_values:[wid],cluster_id:cid,workspace_id:wid});
 let state:any={epoch:1,users:new Map([userId,reviewerId].map(id=>[id,{id,status:'active',deleted_at:null,force_password_change:false,super_admin:false,credential_epoch:1,permissions_epoch:1}])),
  grants:new Map([userId,reviewerId].map(id=>[id,['annotations','services','workflows'].flatMap(module=>['read','write','delete','approve'].map(action=>workspaceGrant(module,action)))])),
  sessions:new Map([[sid,{id:sid,user_id:userId,credential_epoch:1,expires_at:new Date(Date.now()+3600000).toISOString(),revoked_at:null}],[secondSid,{id:secondSid,user_id:userId,credential_epoch:1,expires_at:new Date(Date.now()+3600000).toISOString(),revoked_at:null}],
   [reviewerSid,{id:reviewerSid,user_id:reviewerId,credential_epoch:1,expires_at:new Date(Date.now()+3600000).toISOString(),revoked_at:null}]]),
  cluster:{id:cid,revision:2,admin_url:'http://kong:8001',transport_scope:null,execution_mode:'approval',status:'healthy',deleted_at:null},workspace:{id:wid,cluster_id:cid,revision:3,status:'active',deleted_at:null},
  entity:{id:entityId,name:'payments',host:'payments.example',port:80,tags:['team-pay']},annotation:null,intents:new Map(),requests:new Map(),workflows:new Map(),plans:new Map(),facts:new Map(),audit:new Map(),running:null,
  definition:{id:randomUUID(),version:1},policy:{version:2,kind:'entity-annotation',allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:24,stages:[{level:1,name:'Review',mode:'any',threshold:1,selector:{users:[reviewerId]}}]}};
 const writes:string[]=[],nativeCalls:any[]=[],checks:any[]=[],phaseHook:{afterApply?:()=>void}={};
 const one=(sql:string,p:any[]=[]):any=>{
  if(sql.includes('FROM iam_epoch'))return {version:state.epoch};
  if(sql.includes('FROM auth_sessions')){const s=state.sessions.get(p[0]),u=s&&state.users.get(s.user_id);return s&&(!p[1]||s.user_id===p[1])&&!s.revoked_at&&Date.parse(s.expires_at)>Date.now()&&(!p[2]||String(s.credential_epoch)===String(p[2]))
   &&(!sql.includes('JOIN users')||u?.status==='active'&&!u.deleted_at&&!u.force_password_change&&u.credential_epoch===s.credential_epoch)?clone(s):null;}
  if(sql.includes('FROM users WHERE id=')){const u=state.users.get(p[0]);return u?.status==='active'&&!u.deleted_at&&!u.force_password_change?clone(u):null;}
  if(sql.includes('FROM clusters WHERE id='))return p[0]===cid&&!state.cluster.deleted_at?clone(state.cluster):null;
  if(sql.includes('FROM workspaces'))return p[0]===cid&&p[1]===wid?clone(state.workspace):null;
  if(sql.includes('FROM annotation_change_intents')){
   if(sql.includes('actor_id=$1'))return clone([...state.intents.values()].find((r:any)=>r.actor_id===p[0]&&(sql.includes('cluster_id=$2')?r.cluster_id===p[1]&&r.workspace_id===p[2]&&r.idempotency_key===p[3]:r.idempotency_key===p[1]))??null);
   return clone(state.intents.get(p[0])??null);}
  if(sql.includes('FROM entity_annotation_requests')){const r=state.requests.get(p[0]);return r&&(!p[1]||r.workflow_id===p[1])&&(!p[2]||r.cluster_id===p[2])&&(!p[3]||r.workspace_id===p[3])?clone(r):null;}
  if(sql.includes('FROM workflow_definition_versions'))return {approval_format:2,policy:clone(state.policy)};
  if(sql.includes('FROM mutation_operations'))return null;
  if(sql.includes('FROM workflows WHERE id='))return clone(state.workflows.get(p[0])??null);
  if(sql.includes('FROM workflow_executions e JOIN workflows')){const r=state.running;return r&&r.executionId===p[0]&&r.workflowId===p[1]&&r.clusterId===p[2]&&r.workspaceId===p[3]&&r.actorId===p[4]&&r.stepId===p[5]&&r.planHash===p[6]&&r.planRevision===p[7]&&r.executionState==='executing'&&r.workflowState==='executing'&&r.stepState==='running'&&r.nativeCount===0&&r.approvalFormat===2?{id:r.executionId}:null;}
  if(sql.includes('FROM annotation_workflow_mutation_facts f')){
   if(sql.includes('WHERE f.id=$1')){const f=state.facts.get(p[0]),a=f&&state.audit.get(f.audit_id);return f&&a?{...clone(f),audit_actor:a.actorId,audit_cluster:a.clusterId,audit_workspace:a.workspaceId,audit_type:a.entityType,audit_entity:a.entityId,actual_audit_action:a.action,audit_workflow:a.workflowId,audit_result:'success'}:null;}
   const f=[...state.facts.values()].find((f:any)=>f.intent_id===p[0]&&f.workflow_id===p[1]&&f.actor_id===p[2]&&f.session_id===p[3]&&f.plan_hash===p[4]),r=state.running,w=f&&state.workflows.get(f.workflow_id);
   return f&&r&&w?.state==='succeeded'&&r.executionState==='succeeded'&&r.stepState==='succeeded'?{...clone(f),execution_key:r.executionKey,revision:w.revision}:null;
  }
  if(sql.includes('FROM entity_annotations'))return p[0]===cid&&p[1]==='services'&&p[2]===entityId?clone(state.annotation):null;
  if(sql.startsWith('INSERT INTO entity_annotations')){writes.push(sql);if(state.annotation)return null;state.annotation={cluster_id:cid,entity_type:'services',kong_id:entityId,description:p[3],owner_user_id:p[4],metadata:JSON.parse(p[5]),revision:1,status:'active',deleted_at:null,retention_until:null,created_at:new Date().toISOString(),updated_at:new Date().toISOString()};return clone(state.annotation);}
  if(sql.startsWith('UPDATE entity_annotations')){writes.push(sql);const r=state.annotation;if(!r)return null;
   if(sql.includes('SET description=')){if(r.revision!==p[6]||r.status!=='active')return null;Object.assign(r,{description:p[3],owner_user_id:p[4],metadata:JSON.parse(p[5])});}
   else {if(r.revision!==p[3])return null;if(sql.includes("SET status='deleted'")){if(r.status!=='active')return null;Object.assign(r,{status:'deleted',deleted_at:new Date().toISOString(),retention_until:new Date(Date.now()+p[4]*86400000).toISOString()});}
    else {if(r.status!=='deleted')return null;Object.assign(r,{status:'active',deleted_at:null,retention_until:null});}}
   r.revision++;r.updated_at=new Date().toISOString();phaseHook.afterApply?.();return clone(r);}
  throw new Error(`Unimplemented Source annotation fixture SQL: ${sql}`);
 };
 const exec=(sql:string,p:any[]=[])=>{writes.push(sql);const match=sql.match(/^INSERT INTO (annotation_change_intents|entity_annotation_requests|annotation_workflow_mutation_facts)\(([^)]+)\)/);if(!match)throw new Error('Unexpected fixture exec');
  const row=Object.fromEntries(match[2].split(',').map((name,i)=>[name,clone(p[i])])),target=match[1]==='annotation_change_intents'?state.intents:match[1]==='entity_annotation_requests'?state.requests:state.facts;target.set(row.id,row);return 1;};
 const tx:any={one:vi.fn(async(sql:string,p?:any[])=>one(sql,p)),query:vi.fn(async(sql:string,p:any[]=[])=>sql.includes('FROM iam_effective_grants')?clone(state.grants.get(p[0])??[]):[]),exec:vi.fn(async(sql:string,p?:any[])=>exec(sql,p)),transaction:async(fn:any)=>fn(tx)};
 const db:any={...tx,transaction:vi.fn(async(fn:any)=>{const before=clone(state);try{return await fn(tx);}catch(error){state=before;throw error;}})};
 const authz:any={assertCluster:vi.fn(),assertEntity:vi.fn(),snapshot:vi.fn(async(user:any)=>({user:{...user,superAdmin:state.users.get(user.id)?.super_admin===true},grants:clone(state.grants.get(user.id)??[])}))};
 const resolver:any={listScope:vi.fn(async(c:string,w:string)=>{if(c!==cid||w!==wid)throw new ForbiddenException();return {clusterId:cid,workspaceId:wid};}),assertMembership:vi.fn(),classify:vi.fn(async()=>({state:'resolved',workspace:clone(state.workspace)}))};
 const kong:any={request:vi.fn(async(c:string,method:string,path:string)=>{nativeCalls.push({c,method,path});if(method!=='GET')throw new Error('Native writes forbidden');if(c!==cid)throw new Error('Cross cluster');if(path===`/services/${entityId}`)return clone(state.entity);if(path===`/services/${entityId}/routes`)return {data:[],next:null};throw new Error('Unapproved native path');})};
 const audit:any={append:vi.fn(async(event:any,transaction:any)=>{expect(transaction).toBe(tx);const id=randomUUID();state.audit.set(id,clone(secrets.redact(event)));return {id,chainScope:`cluster:${cid}`,sequence:String(state.audit.size),eventHash:'a'.repeat(64),occurredAt:new Date().toISOString()};})};
 const mutations:any={execute:vi.fn(async()=>{throw new ForbiddenException({code:'APPROVAL_REQUIRED'});})},redis:any={withLock:vi.fn(async(_k:string,fn:any)=>fn()),assertLeaseOwnership:vi.fn()},annotations=new EntityAnnotationsService(db,kong,authz,mutations,audit,resolver,context),business=new EntityAnnotationBusinessService(db,secrets,annotations,kong,resolver,context,audit);
 business.onModuleInit();const registry:any={handlers:new Map(),register(name:string,h:any){if(this.handlers.has(name))throw new Error('Duplicate');this.handlers.set(name,h);},get(name:string){return this.handlers.get(name);}},
  plans:any={definitions:vi.fn(),definition:vi.fn(async()=>({...state.definition,policyHash:secrets.fingerprint(state.policy)})),persist:vi.fn(async(plan:any,key:string,_request:any,transaction:any)=>{expect(transaction).toBe(tx);assertEntityAnnotationPlan(plan);state.plans.set(plan.workflowId,immutableJson(plan));state.workflows.set(plan.workflowId,{id:plan.workflowId,cluster_id:cid,workspace_id:wid,state:'pending',revision:1,plan_revision:plan.planRevision,plan_hash:secrets.fingerprint(plan),idempotency_key:key});})};
 const workflow=new EntityAnnotationWorkflowService(db,redis,secrets,audit,context,business,plans,registry);workflow.onModuleInit();
 const executionHandles=new WeakMap<object,any>(),stepHandles=new WeakSet<object>();
 const approved:any={verifyExecution:vi.fn(async(h:object)=>{const p=executionHandles.get(h);if(!p)throw new Error('Original fixture execution handle required');return p;}),verifyStep:vi.fn(async(proof:any,id:string)=>{if(state.running?.stepId!==id)throw new Error('Original fixture step required');const s=Object.freeze({execution:proof,stepId:id,kind:'metadata'});stepHandles.add(s);return s;}),
  assertMetadata:vi.fn(async(s:any,input:any,t:any)=>{const p=state.plans.get(s.execution.workflowId),sealed=p.steps[0];if(!stepHandles.has(s)||t!==tx||input.handler!=='entity.annotation'||input.actor.id!==userId||input.clusterId!==cid||input.workspaceId!==wid||input.entityType!=='entity_annotation_requests'||input.entityId!==p.subject.id||input.revision!==sealed.metadataRevision||secrets.fingerprint(input.before)!==sealed.metadataBeforeHmac||secrets.fingerprint(input.payload)!==sealed.metadataPayloadHmac)throw new Error('Exact fixture metadata binding required');checks.push(input);}),
  mutationBinding:vi.fn(()=>{throw new Error('Annotations cannot mint native bindings');}),assertNative:vi.fn(()=>{throw new Error('Annotations cannot send Native');}),bindOperation:vi.fn()};context.installApprovedPolicy(approved);
 const http=<T>(fn:()=>Promise<T>,actor:any=author,sessionId=actor.user.id===userId?sid:reviewerSid)=>context.runHttp({requestId:actor.requestId},async()=>{context.bindHttpActor(actor.user,sessionId);const close=context.captureHttpCloser();try{return await fn();}finally{close();}});
 const request=()=>({entityType:'services',entityId,operation:'set',input:{revision:state.annotation?.revision??0,description:'Approved annotation',metadata:{api_key:'Synthetic-fixture-secret',business:'payments'}}});
 const prepare=(raw:any=request())=>http(()=>workflow.prepare(cid,wid,raw,author));
 const submit=(r:any)=>http(()=>workflow.submit(cid,wid,r.intentId,{confirmed:true,materialHmac:r.materialHmac},{...author,idempotencyKey:'annotation-original-submit'}));
 const intent=(id?:string):any=>{const r=id?state.intents.get(id):[...state.intents.values()][0];return secrets.decrypt(r.material_secret,`annotation-workflow:${r.id}:intent`);};
 const execute=(plan:any,options:{running?:(r:any)=>void;complete?:(input:any,result:any,pv:string)=>Promise<void>}={})=>http(()=>db.transaction(async(transaction:any)=>{
  const executionId=randomUUID(),handle=Object.freeze({}),proof=Object.freeze({executionId,workflowId:plan.workflowId,actorId:userId,sessionId:sid,clusterId:cid,workspaceId:wid,permissionVersion:`${userId}:1:${state.epoch}`,expiresAt:Date.now()+60000});executionHandles.set(handle,proof);
  state.running={executionId,executionKey:`workflow-${executionId}`,workflowId:plan.workflowId,clusterId:cid,workspaceId:wid,actorId:userId,stepId:plan.steps[0].id,planHash:secrets.fingerprint(plan),planRevision:plan.planRevision,executionState:'executing',workflowState:'executing',stepState:'running',nativeCount:0,approvalFormat:2};options.running?.(state.running);
  return context.runApprovedWorkflow(handle as any,()=>context.runApprovedStep(plan.steps[0].id,async()=>{const input={plan,step:plan.steps[0],actor:author,executionId,transaction},pv=`${userId}:1:${state.epoch}`,result=await registry.get('entity.annotation').apply(input);if(options.complete)await options.complete(input,result,pv);else await workflow.verifyMetadataCompletion(input,result,pv);return result;}));
 }));
 return {cid,wid,entityId,userId,sid,secondSid,reviewerId,reviewerSid,author,reviewer,context,db,tx,secrets,annotations,business,workflow,registry,plans,audit,authz,redis,mutations,kong,resolver,approved,writes,nativeCalls,checks,phaseHook,request,http,prepare,submit,intent,execute,state:()=>state,workspaceGrant};
}
