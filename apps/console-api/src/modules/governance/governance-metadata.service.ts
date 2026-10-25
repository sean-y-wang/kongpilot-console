import {BadRequestException,ConflictException,ForbiddenException,Injectable,NotFoundException,OnModuleInit} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import {SecretService} from '../../infrastructure/secret.service';
import {transportScopeFor} from '../../infrastructure/kong/transport-scope';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {AuthorizationService} from '../authorization/authorization.service';
import {validGrant} from '../authorization/grant-policy';
import {WorkspaceResolverService} from '../workspaces/workspace-resolver.service';
import {EntityService} from '../entities/entities.service';
import {IamMutationsService} from '../iam/iam-mutations.service';
import {AuditService} from '../audit/audit.service';
import {metadataAuditScope} from '../event-producers/native-audit-scope';
import {WorkflowPlansService} from '../workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../workflows/workflow-registry.service';
import {ApprovedWorkflowExecutionService} from '../workflows/approved-workflow-execution.service';
import type {WorkflowPlanV1,WorkflowHandlerInput} from '../workflows/workflow.types';
import type {EntityActor} from '../entities/entities.types';
import {governanceId,governanceKey,governanceConfirm,governanceObject,governanceRevision,ruleInput,scheduleInput,governanceText} from './governance-input';
import {GovernanceRepositoryService} from './governance-repository.service';
import {assertGovernanceMetadataPlan,governanceMetadataAction,governanceMetadataModule,governanceMetadataProjection} from './governance-workflow';
import type {GovernanceMetadataIntent,GovernanceMetadataOperation,GovernanceMetadataResource,GovernanceScopeSnapshot,GovernanceReceipt,GovernanceFixedMetadataPayload} from './governance-storage.types';
import {validateLintRules} from './lint-engine';
import {GovernanceLintError} from './lint-types';
import {assertGovernanceOriginalDomain,governanceOriginalLock} from './governance-original-key';

const conflict=(code:string)=>new ConflictException({code,message:'治理配置、授权或冻结范围已变化，请核验原回执'});
function ruleContent(input:Record<string,any>):Record<string,any>{try{const rule=validateLintRules([{code:input.code,given:input.given,then:input.then,severity:input.severity,description:input.description?.trim()||input.name,enabled:input.enabled!==false}])[0];return{...input,...rule};}catch(error){if(error instanceof GovernanceLintError)throw new BadRequestException({code:error.code,message:'Lint 规则字段、谓词或路径不符合约束'});throw error;}}
/** Shared configuration writes honor cluster mode; personal analytical facts do not use this writer. */
@Injectable()
export class GovernanceMetadataService implements OnModuleInit {
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,private readonly authz:AuthorizationService,
  private readonly workspaces:WorkspaceResolverService,private readonly entities:EntityService,private readonly iam:IamMutationsService,
  private readonly audit:AuditService,private readonly repo:GovernanceRepositoryService,private readonly plans:WorkflowPlansService,private readonly registry:WorkflowRegistryService,
  private readonly approved:ApprovedWorkflowExecutionService,private readonly context:KongExecutionContextService){}
 onModuleInit():void{
  const delegate=Object.freeze({verifyIntent:(plan:WorkflowPlanV1,tx?:DbService)=>this.verifyIntent(plan,tx),verifyReviewer:(id:string,plan:WorkflowPlanV1,tx?:DbService)=>this.verifyReviewer(id,plan,tx),
   assertSubject:(plan:WorkflowPlanV1,id:string,action:'read'|'write'|'approve',tx?:DbService)=>{const f=this.context.current();
    if(f.actor?.id!==id)throw new ForbiddenException({code:'GOVERNANCE_ACTOR_CONTEXT_REQUIRED'});
    // Scheduled business execution has no live HTTP session; admission still rechecks grants/snapshot.
    if(!f.sessionId&&!this.context.hasWorkflowScheduledNamespace())throw new ForbiddenException({code:'GOVERNANCE_ACTOR_CONTEXT_REQUIRED'});
    if(!f.sessionId){const ns=this.context.requireWorkflowScheduledCurrentPrincipal(this.context.requireWorkflowScheduledNamespaceHandle()).namespace;
     if((ns.kind as string)!=='governance-metadata'||ns.sessionId!==null||ns.actor.id!==id||f.operation||f.archive)throw new ForbiddenException({code:'GOVERNANCE_SCHEDULED_ACTOR_REQUIRED'});}
    return this.assertWorkflowSubject(plan,{user:f.actor,workspaceId:plan.workspaceId,requestId:f.requestId,ip:f.ip},action,tx);}});
  this.approved.installGovernanceMetadataDelegate(delegate);this.plans.installGovernanceMetadataDelegate(delegate);
  this.registry.register('governance.metadata',{authorize:(plan,actor,action)=>this.assertWorkflowSubject(plan,actor,action),
  prepare:input=>this.prepare(input),inspect:async(input,tx)=>{const intent=await this.boundIntent(input.plan,tx),before=await this.target(intent,tx,true);return{before,revision:before?.revision??0};},
  apply:input=>this.applyApproved(input)});}
 private async snapshot(cid:string,actor:EntityActor,module:string,action:'read'|'write'|'delete',tx=this.db,lock=false):Promise<GovernanceScopeSnapshot>{
  const wid=governanceId(actor.workspaceId),ws=await this.workspaces.get(cid,wid,false,tx);
  await this.authz.assertWholeWorkspace(actor.user,cid,wid,module,action,tx);
  const c=await tx.one<any>('SELECT admin_url,transport_scope,revision,execution_mode,version,status FROM clusters WHERE id=$1 AND deleted_at IS NULL'+(lock?' FOR SHARE':''),[cid]);
  if(!c)throw new NotFoundException({code:'CLUSTER_NOT_FOUND'});if(action!=='read'&&(ws.status!=='active'||c.status==='disabled'||!/^1\.5\.\d+$/.test(c.version??'')))throw conflict('GOVERNANCE_SCOPE_UNAVAILABLE');
  return{clusterId:cid,workspaceId:wid,transportScope:transportScopeFor(c.admin_url,c.transport_scope),clusterRevision:c.revision,workspaceRevision:ws.revision,executionMode:c.execution_mode,permissionVersion:await this.authz.permissionVersion(actor.user,tx)};
 }
 private async assertSnapshot(scope:GovernanceScopeSnapshot,actor:EntityActor,module:string,action:'read'|'write'|'delete',tx=this.db):Promise<void>{
  const current=await this.snapshot(scope.clusterId,{...actor,workspaceId:scope.workspaceId},module,action,tx,tx!==this.db);
  for(const key of ['transportScope','clusterRevision','workspaceRevision','executionMode'])if(current[key as keyof GovernanceScopeSnapshot]!==scope[key as keyof GovernanceScopeSnapshot])throw conflict('GOVERNANCE_SCOPE_CHANGED');
 }
 private async target(i:GovernanceMetadataIntent,tx=this.db,lock=false):Promise<any>{return this.repo.resource(i.resourceType,i.resourceId,i.clusterId,i.workspaceId,tx,lock,i.payload.entityType);}
 private async nativeAnnotation(i:GovernanceMetadataIntent,actor:EntityActor):Promise<void>{if(i.resourceType!=='entity_annotations')return;
  await this.authz.assertWholeWorkspace(actor.user,i.clusterId,i.workspaceId,'annotations','write');
  const current=await this.entities.get(i.clusterId,i.payload.entityType,i.resourceId,{workspaceId:i.workspaceId},{...actor,workspaceId:i.workspaceId});
  await this.authz.assertEntity(actor.user,i.clusterId,i.payload.entityType,'write',current.entity??current,i.workspaceId);
 }
 private async boundIntent(plan:WorkflowPlanV1,tx=this.db):Promise<GovernanceMetadataIntent>{
  const step=assertGovernanceMetadataPlan(plan),p=step.metadata as GovernanceFixedMetadataPayload,i=await this.repo.intent(p.intentId,tx);
  if(i.clusterId!==plan.clusterId||i.workspaceId!==plan.workspaceId||i.actorId!==plan.requester.id||i.workflowId!==plan.workflowId||i.resourceType!==p.resourceType||i.resourceId!==p.resourceId||i.operation!==p.operation||this.secrets.fingerprint(i.payload)!==p.payloadHmac||this.secrets.fingerprint(step.metadata)!==step.metadataPayloadHmac||this.secrets.fingerprint(i.before)!==step.metadataBeforeHmac||this.secrets.fingerprint(step.before)!==step.metadataBeforeHmac||i.scope.transportScope!==plan.scope.transportScope||i.scope.clusterRevision!==plan.scope.clusterRevision||i.scope.workspaceRevision!==plan.scope.workspaceRevision)throw conflict('GOVERNANCE_WORKFLOW_BINDING_INVALID');
  const original=i.scope.originalRequest;
  if(!original||original.type!==i.resourceType||original.operation!==i.operation||original.target!==(i.operation==='create'&&i.resourceType!=='entity_annotations'?null:i.resourceId)||this.secrets.fingerprint(original)!==i.requestHmac)throw conflict('GOVERNANCE_WORKFLOW_REQUEST_CHANGED');
  const workflow=await tx.one<any>('SELECT request_hash,idempotency_key FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[i.workflowId,i.clusterId,i.workspaceId]);
  if(workflow&&(workflow.idempotency_key!==i.idempotencyKey||workflow.request_hash!==this.secrets.fingerprint({requester:plan.requester,clusterId:i.clusterId,workspaceId:i.workspaceId,request:original})))throw conflict('GOVERNANCE_WORKFLOW_REQUEST_CHANGED');
  return i;
 }
 async verifyIntent(plan:WorkflowPlanV1,tx=this.db):Promise<void>{await this.boundIntent(plan,tx);}
 async assertWorkflowSubject(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve',tx=this.db):Promise<void>{
  const i=await this.boundIntent(plan,tx),module=governanceMetadataModule(i.resourceType);
  if(actor.workspaceId!==plan.workspaceId||action==='write'&&actor.user.id!==i.actorId)throw new ForbiddenException({code:'GOVERNANCE_EXECUTOR_SCOPE_DENIED'});
  await this.authz.assertWholeWorkspace(actor.user,i.clusterId,i.workspaceId,'workflows',action,tx);
  await this.assertSnapshot(i.scope,actor,module,action==='write'?governanceMetadataAction(i.operation):'read',tx);
  if(i.resourceType==='governance_schedules'&&i.payload.kind==='drift'&&i.payload.target){await this.authz.assertWholeWorkspace(actor.user,i.payload.target.clusterId,i.payload.target.workspaceId,'drift','read',tx);}
  if(action!=='read'){const current=await this.target(i,tx);if(this.secrets.fingerprint(current)!==this.secrets.fingerprint(i.before))throw conflict('GOVERNANCE_METADATA_CHANGED');}
 }
 /** Review another persisted user with SQL only. It neither swaps ALS nor borrows the executor's SID. */
 async verifyReviewer(userId:string,plan:WorkflowPlanV1,tx=this.db):Promise<void>{
  const i=await this.boundIntent(plan,tx),row=await tx.one<any>("SELECT id,status,deleted_at,super_admin,force_password_change FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL",[governanceId(userId)]);
  if(!row||row.force_password_change)throw new ForbiddenException({code:'GOVERNANCE_REVIEWER_INACTIVE'});
  const grants=(await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[userId])).filter(validGrant);
  const whole=(cid:string,wid:string,module:string,action:string)=>row.super_admin===true||grants.some(g=>g.module===module&&g.action===action&&(g.cluster_id===null||g.cluster_id===cid)&&(g.workspace_id===null||g.workspace_id===wid)&&(g.scope_type==='global'||g.scope_type==='workspace'&&g.cluster_id===cid&&g.workspace_id===wid&&g.scope_values.length===1&&g.scope_values[0]===wid));
  const c=await tx.one<any>('SELECT admin_url,transport_scope,revision,execution_mode,status,version FROM clusters WHERE id=$1 AND deleted_at IS NULL',[i.clusterId]),w=await tx.one<any>('SELECT revision,status FROM workspaces WHERE cluster_id=$1 AND id=$2',[i.clusterId,i.workspaceId]);
  if(!c||!w||c.execution_mode!=='approval'||c.status==='disabled'||w.status!=='active'||!/^1\.5\.\d+$/.test(c.version??'')||c.revision!==i.scope.clusterRevision||w.revision!==i.scope.workspaceRevision||transportScopeFor(c.admin_url,c.transport_scope)!==i.scope.transportScope)throw conflict('GOVERNANCE_REVIEWER_SCOPE_CHANGED');
  const requester=userId===i.actorId;
  if(!whole(i.clusterId,i.workspaceId,'workflows',requester?'write':'approve')||!whole(i.clusterId,i.workspaceId,governanceMetadataModule(i.resourceType),requester?governanceMetadataAction(i.operation):'read'))throw new ForbiddenException({code:'GOVERNANCE_REVIEWER_SCOPE_DENIED'});
  if(i.resourceType==='governance_schedules'&&i.payload.kind==='drift'&&i.payload.target){const t=i.payload.target,live=await tx.one('SELECT w.id FROM workspaces w JOIN clusters c ON c.id=w.cluster_id WHERE c.id=$1 AND w.id=$2 AND c.deleted_at IS NULL AND c.status<>\'disabled\' AND w.status=\'active\'',[t.clusterId,t.workspaceId]);if(!live||!whole(t.clusterId,t.workspaceId,'drift','read'))throw new ForbiddenException({code:'GOVERNANCE_TARGET_REVIEWER_DENIED'});}
 }
 private async prepare(input:Omit<WorkflowHandlerInput,'transaction'>):Promise<void>{const i=await this.boundIntent(input.plan);await this.assertWorkflowSubject(input.plan,input.actor,'write');await this.nativeAnnotation(i,input.actor);}
 private async applyApproved(input:WorkflowHandlerInput):Promise<Record<string,unknown>>{
  const {plan,step,actor,executionId,transaction:tx}=input,i=await this.boundIntent(plan,tx);
  await this.assertWorkflowSubject(plan,actor,'write',tx);
  const e=await tx.one<any>(`SELECT e.id FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id AND w.cluster_id=e.cluster_id AND w.workspace_id=e.workspace_id JOIN workflow_steps s ON s.workflow_id=w.id AND s.plan_revision=e.plan_revision AND s.plan_hash=e.plan_hash WHERE e.id=$1 AND e.workflow_id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4 AND e.state='executing' AND w.state='executing' AND e.execution_actor_id=$5 AND e.approved_by IS NOT NULL AND s.id=$6 AND s.state='running' AND s.handler='governance.metadata' AND s.kind='metadata' AND jsonb_array_length(s.native_requests)=0`,[executionId,plan.workflowId,plan.clusterId,plan.workspaceId,actor.user.id,step.id]);
  if(!e)throw new ForbiddenException({code:'GOVERNANCE_APPROVED_EXECUTION_REQUIRED'});
  const before=await this.target(i,tx,true);if(this.secrets.fingerprint(before)!==this.secrets.fingerprint(i.before))throw conflict('GOVERNANCE_METADATA_CHANGED');
  const after=await this.repo.saveResource(i.resourceType,i.resourceId,i.clusterId,i.workspaceId,actor.user.id,i.operation,before,i.payload,i.scope.transportScope,tx);
  await this.audit.append({actorId:actor.user.id,clusterId:i.clusterId,workspaceId:i.workspaceId,entityType:i.resourceType,entityId:i.resourceId,workflowId:plan.workflowId,requestId:actor.requestId,ip:actor.ip,action:`governance.metadata.${i.operation}`,before:governanceMetadataProjection(before),after:governanceMetadataProjection(after),scopeHints:metadataAuditScope(governanceMetadataModule(i.resourceType),i.resourceType,i.resourceId,i.workspaceId)},tx);
  return{entity:this.resourceView(after),resourceType:i.resourceType,resourceId:i.resourceId,operation:i.operation};
 }
 resourceView(row:any):Record<string,any>{return{id:row.id,code:row.code,name:row.name??row.content?.name,revision:row.revision,currentVersion:row.current_version??row.revision,state:row.state,enabled:row.enabled??row.content?.enabled??true,...row.content,createdAt:new Date(row.created_at).toISOString(),updatedAt:new Date(row.updated_at).toISOString()};}
 private async prior(cid:string,wid:string,type:GovernanceMetadataResource,actor:EntityActor,requestHmac?:string):Promise<GovernanceReceipt|null>{
  const key=governanceKey(actor.idempotencyKey),iam=await this.db.one<any>('SELECT * FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]),intent=await this.db.one<any>('SELECT * FROM governance_metadata_requests WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
  if(iam&&intent)throw conflict('IDEMPOTENCY_CONFLICT');const module=governanceMetadataModule(type),kind=type==='governance_rules'?'rule-change':'schedule-change';
  if(iam){const payload=iam.payload_secret?this.secrets.decrypt<any>(iam.payload_secret,`iam:${iam.id}:payload`):null;if(iam.cluster_id!==cid||iam.workspace_id!==wid||iam.module!==module||payload?.governanceResource!==type||requestHmac&&payload.originalRequestHmac!==requestHmac)throw conflict('IDEMPOTENCY_CONFLICT');const completed=iam.state==='succeeded'&&iam.remote_completed===true,result=completed&&iam.result_secret?this.secrets.decrypt<any>(iam.result_secret,`iam:${iam.id}:result`):undefined;return{id:iam.id,actorId:actor.user.id,clusterId:cid,workspaceId:wid,idempotencyKey:key,domain:'iam',kind,state:iam.state,registrationCompleted:true,submissionCompleted:false,executionCompleted:completed,nativeExecutionRequested:false,configurationCommitted:completed,...(result?{entity:result.entity,result}:{} )};}
  if(intent){if(intent.cluster_id!==cid||intent.workspace_id!==wid||intent.resource_type!==type||requestHmac&&intent.request_hmac!==requestHmac)throw conflict('IDEMPOTENCY_CONFLICT');const w=await this.db.one<any>('SELECT w.*,s.safe_result,s.state AS step_state FROM workflows w JOIN workflow_steps s ON s.workflow_id=w.id AND s.plan_revision=w.plan_revision AND s.plan_hash=w.plan_hash WHERE w.id=$1 AND w.subject_type=\'governance_metadata_requests\' AND s.handler=\'governance.metadata\'',[intent.workflow_id]);if(!w)throw conflict('GOVERNANCE_WORKFLOW_SOURCE_MISSING');const done=w.state==='succeeded'&&w.step_state==='succeeded';return{id:intent.id,actorId:actor.user.id,clusterId:cid,workspaceId:wid,idempotencyKey:key,domain:'workflow',kind,state:w.state,workflowId:w.id,registrationCompleted:true,submissionCompleted:true,executionCompleted:done,nativeExecutionRequested:false,configurationCommitted:done,...(done?{entity:w.safe_result?.entity,result:w.safe_result}:{} )};}
  return null;
 }
 async receipt(cid:string,key:string,actor:EntityActor):Promise<GovernanceReceipt|null>{const wid=governanceId(actor.workspaceId),original={...actor,idempotencyKey:key},i=await this.db.one<any>('SELECT resource_type FROM governance_metadata_requests WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,governanceKey(key)]),op=await this.db.one<any>('SELECT module,payload_secret,id FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
  const type=i?.resource_type??(op?.payload_secret?this.secrets.decrypt<any>(op.payload_secret,`iam:${op.id}:payload`).governanceResource:undefined);if(!type)return null;if(!['governance_rules','governance_schedules','entity_annotations'].includes(type))throw conflict('IDEMPOTENCY_CONFLICT');await this.authz.assertWholeWorkspace(actor.user,cid,wid,governanceMetadataModule(type),'read');return this.prior(cid,wid,type,original);
 }
 async mutate(cid:string,type:GovernanceMetadataResource,id:string|undefined,operation:GovernanceMetadataOperation,raw:unknown,actor:EntityActor):Promise<GovernanceReceipt>{
  cid=governanceId(cid);const wid=governanceId(actor.workspaceId),key=governanceKey(actor.idempotencyKey),module=governanceMetadataModule(type),action=governanceMetadataAction(operation);
  const value=operation==='archive'||operation==='restore'?governanceObject(raw,['revision','confirmed','confirm_name']):type==='governance_rules'?ruleInput(raw,operation==='update'):type==='governance_schedules'?scheduleInput(raw,operation==='update'):governanceObject(raw,['entityType','nativeId','description','revision']);
  const requestHmac=this.secrets.fingerprint({type,target:id??null,operation,input:value});
  return this.redis.withLock(governanceOriginalLock(actor.user.id,key),async()=>{
   await this.authz.assertWholeWorkspace(actor.user,cid,wid,module,action);await assertGovernanceOriginalDomain(this.db,actor.user.id,key,'metadata');const prior=await this.prior(cid,wid,type,actor,requestHmac);if(prior)return prior;
   const scope=await this.snapshot(cid,actor,module,action),target=id?governanceId(id):randomUUID(),before=id?await this.repo.resource(type,target,cid,wid,this.db,false,value.entityType):null;
   if(operation!=='create'&&!before)throw new NotFoundException({code:'GOVERNANCE_RESOURCE_NOT_FOUND'});
   if(operation==='archive'||operation==='restore'){governanceRevision(value.revision);governanceConfirm(value,before.name);}
   if(operation==='update'&&value.revision!==before.revision)throw conflict('GOVERNANCE_REVISION_CONFLICT');
   let payload={...(before?.content??{}),...value};
   if(type==='governance_rules')payload=ruleContent(payload);else if(type==='governance_schedules'){const content={...payload};delete content.revision;delete content.confirmed;delete content.confirm_name;payload=scheduleInput(content);for(const key of ['revision','confirmed','confirm_name'])if(value[key]!==undefined)payload[key]=value[key];}
   else{payload.description=governanceText(payload.description,8192,false);if(payload.nativeId!==target)throw conflict('GOVERNANCE_ANNOTATION_ID_MISMATCH');}
   if(type==='governance_schedules'&&payload.kind==='drift')await this.authz.assertWholeWorkspace(actor.user,payload.target.clusterId,payload.target.workspaceId,'drift','read');
   scope.originalRequest={type,target:id??null,operation,input:value};
   const i:GovernanceMetadataIntent={id:randomUUID(),clusterId:cid,workspaceId:wid,actorId:actor.user.id,resourceType:type,resourceId:target,operation,idempotencyKey:key,requestHmac,payload,before,scope,workflowId:randomUUID()};
   await this.nativeAnnotation(i,actor);
   if(scope.executionMode==='direct')await this.iam.execute({module,action,targetId:id?target:undefined,cluster_id:cid,workspace_id:wid,payload:{governanceResource:type,originalRequestHmac:requestHmac,resourceId:target,operation,payload},actor},async(tx,_operationId,setBusinessAudit)=>{
    await this.assertSnapshot(scope,actor,module,action,tx);const current=await this.target(i,tx,true);if(this.secrets.fingerprint(current)!==this.secrets.fingerprint(before))throw conflict('GOVERNANCE_METADATA_CHANGED');
    const after=await this.repo.saveResource(type,target,cid,wid,actor.user.id,operation,current,payload,scope.transportScope,tx);
    setBusinessAudit({entityType:type,entityId:target,before:governanceMetadataProjection(before),after:governanceMetadataProjection(after),scopeHints:metadataAuditScope(module,type,target,wid)});return{entity:this.resourceView(after),resourceType:type,resourceId:target,operation};
   });else await this.db.transaction(async tx=>{
    await this.assertSnapshot(scope,actor,module,action,tx);const current=await this.target(i,tx,true);if(this.secrets.fingerprint(current)!==this.secrets.fingerprint(before))throw conflict('GOVERNANCE_METADATA_CHANGED');
    await this.repo.insertIntent(i,tx);await this.plans.definitions(cid,wid,actor.user.id,tx);const definition=await this.plans.definition(cid,wid,'governance-metadata' as any,tx),metadata:GovernanceFixedMetadataPayload={intentId:i.id,resourceType:type,resourceId:target,operation,payloadHmac:this.secrets.fingerprint(payload)};
    const plan:WorkflowPlanV1={version:1,kind:'governance-metadata' as any,clusterId:cid,workspaceId:wid,workflowId:i.workflowId,planRevision:1,executionMode:'approval',approvalRequired:true,subject:{type:'governance_metadata_requests' as any,id:i.id},requester:{type:'console',id:actor.user.id},definition,issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString(),scope:{transportScope:scope.transportScope,clusterRevision:scope.clusterRevision,workspaceRevision:scope.workspaceRevision},prerequisites:[],steps:[{id:randomUUID(),key:'governance.metadata',order:1,kind:'metadata',handler:'governance.metadata',entityType:'governance_metadata_requests',entityId:i.id,permissionAction:action,dependencies:[],nativeRequests:[],before,metadataRevision:before?.revision??0,metadataBeforeHmac:this.secrets.fingerprint(before),metadata,metadataPayloadHmac:this.secrets.fingerprint(metadata)}]};
    await this.plans.persist(plan,key,{type,target:id??null,operation,input:value},tx,{requestId:actor.requestId,ip:actor.ip});await this.redis.assertLeaseOwnership();
   });const result=await this.prior(cid,wid,type,actor,requestHmac);if(!result)throw conflict('GOVERNANCE_METADATA_RESULT_UNCERTAIN');return result;
  });
 }
}
