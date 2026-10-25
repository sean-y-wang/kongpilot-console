import { ConflictException, ForbiddenException, HttpException, Injectable } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { AuditService } from '../audit/audit.service';
import type { EntityActor } from '../entities/entities.types';
import { portalConfirm, portalObject, portalRevision, requirePortalCas } from '../portal/portal-input';
import { WorkflowPlansService } from './workflow-plans.service';
import { ApprovedWorkflowExecutionService } from './approved-workflow-execution.service';
import { normalizedNativeRequests } from './approved-execution.types';
import { assertWorkspaceMigrationWorkflowPlan, type WorkspaceMigrationWorkflowPayload } from './workspace-migration-workflow';
import { snapshotAad, type WorkflowSnapshotV1 } from './workflow.types';
import { workflowId, workflowKey } from './workflow-validation';
import type { WorkspaceMigrationMaterial } from '../workspaces/workspace-migration.service';

const invalid=()=>new ConflictException({code:'MIGRATION_METADATA_RECOVERY_NOT_ELIGIBLE',message:'原执行缺少完整且确定的迁移成功事实，只能保留原回执核验'});
/** Fixed historical closure, with bounded GET checks and SQL only writes.
 * No approved/native handle is minted; apply/dispatch/reconcile are not called. */
@Injectable()
export class WorkspaceMigrationWorkflowRecoveryService {
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
  private readonly kong:KongService,private readonly context:KongExecutionContextService,private readonly authz:AuthorizationService,
  private readonly audit:AuditService,private readonly plans:WorkflowPlansService,private readonly approved:ApprovedWorkflowExecutionService){}
 private equal(a:unknown,b:unknown):boolean{return this.secrets.fingerprint(a??null)===this.secrets.fingerprint(b??null);}
 private async facts(cid:string,wid:string,id:string,actor:EntityActor,tx:DbService=this.db,lock=false){
  const loaded=await this.plans.load(cid,wid,id,tx),plan=loaded.plan,step=assertWorkspaceMigrationWorkflowPlan(plan),payload=step.mutationPayload as WorkspaceMigrationWorkflowPayload;
  const frame=this.context.current();
  if(!frame.actor||!frame.sessionId||frame.actor.id!==actor.user.id||frame.clusterId!==cid||frame.workspaceId!==wid||plan.requester.id!==actor.user.id)throw new ForbiddenException({code:'MIGRATION_METADATA_RECOVERY_OWNER_REQUIRED'});
  await this.approved.assertSubject(plan,actor.user,'write');
  const execution=await tx.one<any>(`SELECT * FROM workflow_executions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4${lock?' FOR UPDATE':''}`,[cid,wid,id,plan.planRevision]);
  const rows=await tx.query<any>(`SELECT * FROM workflow_steps WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 ORDER BY step_order${lock?' FOR SHARE':''}`,[cid,wid,id,plan.planRevision]);
  if(!execution||rows.length!==1||execution.execution_actor_id!==actor.user.id||execution.plan_hash!==loaded.row.plan_hash||execution.execution_mode!==plan.executionMode||!execution.approval_required||execution.approved_by!==loaded.row.approved_by||execution.snapshot_state!=='ready'||!execution.snapshot_secret||!execution.snapshot_hash)throw invalid();
  const row=rows[0];
  if(row.id!==step.id||row.state!=='succeeded'||row.plan_hash!==loaded.row.plan_hash||row.entity_type!==step.entityType||row.entity_id!==step.entityId||row.mutation_action!=='migrate'||row.permission_action!=='write'||row.parent_id||row.credential_kind||row.handler||row.step_order!==1||row.step_key!==step.key||row.kind!=='native'||row.execution_mode!==plan.executionMode||!row.approval_required
   ||row.before_fingerprint!==step.beforeFingerprint||row.mutation_payload_hmac!==step.mutationPayloadHmac||row.mutation_idempotency_key!==step.mutationIdempotencyKey||!this.equal(row.dependencies,[])||!this.equal(row.native_requests,normalizedNativeRequests(step.nativeRequests,this.secrets))||!row.operation_id||!row.receipt_secret)throw invalid();
  const migration=await tx.one<any>(`SELECT * FROM workspace_migration_plans WHERE cluster_id=$1 AND id=$2${lock?' FOR SHARE':''}`,[cid,plan.subject.id]);
  const mutation=await tx.one<any>(`SELECT * FROM mutation_operations WHERE cluster_id=$1 AND id=$2${lock?' FOR SHARE':''}`,[cid,row.operation_id]);
  if(!migration||!mutation||migration.state!=='succeeded'||mutation.state!=='succeeded'||!mutation.remote_started||!mutation.remote_completed||migration.operation_id!==mutation.id||migration.actor_id!==actor.user.id||migration.source_workspace_id!==wid||migration.target_workspace_id!==plan.migration!.targetWorkspaceId||migration.plan_hash!==payload.plan_hash
   ||mutation.actor_id!==actor.user.id||mutation.workspace_id!==wid||mutation.entity_type!=='workspace_migration'||mutation.entity_id!==plan.subject.id||mutation.action!=='migrate'||mutation.workflow_id!==id||mutation.workflow_execution_id!==execution.id||mutation.workflow_step_id!==step.id||mutation.workflow_plan_revision!==plan.planRevision||mutation.workflow_plan_hash!==loaded.row.plan_hash||mutation.idempotency_key!==step.mutationIdempotencyKey||mutation.transport_scope!==plan.scope.transportScope||mutation.parent_id||mutation.credential_kind||!mutation.result_secret)throw invalid();
  const material=this.secrets.decrypt<WorkspaceMigrationMaterial>(migration.payload_secret,`workspace-migration:${migration.id}`),result=this.secrets.decrypt<any>(mutation.result_secret,`mutation:${mutation.id}:result`);
  const binding={workflowId:id,executionId:execution.id,planRevision:plan.planRevision,planHash:loaded.row.plan_hash,stepId:step.id,beforeHmac:step.beforeFingerprint!};
  if(mutation.request_hash!==this.secrets.fingerprint({actor:actor.user.id,clusterId:cid,workspaceId:wid,entityType:step.entityType,entityId:step.entityId,action:'migrate',payload:step.mutationPayload,parentId:null,credentialKind:null,approvedWorkflow:binding}))throw invalid();
  if(this.secrets.fingerprint(material)!==plan.migration!.materialHmac||this.secrets.fingerprint({cid,actor:actor.user.id,payload:material})!==payload.plan_hash||this.secrets.fingerprint(this.secrets.decrypt(mutation.before_secret,`mutation:${mutation.id}:before`))!==step.beforeFingerprint||this.secrets.fingerprint(this.secrets.decrypt(mutation.payload_secret,`mutation:${mutation.id}:payload`))!==step.mutationPayloadHmac)throw invalid();
  const components=await tx.query<any>(`SELECT object_key,type,kong_id::text AS id,status,after_fingerprint,error_code FROM workspace_migration_steps WHERE cluster_id=$1 AND plan_id=$2 ORDER BY object_key${lock?' FOR SHARE':''}`,[cid,migration.id]),nodes=new Map(material.nodes.map(node=>[node.key,node]));
  if(nodes.size!==material.nodes.length||components.length!==nodes.size||new Set(components.map(node=>node.object_key)).size!==nodes.size||components.some(component=>{const node=nodes.get(component.object_key);return !node||component.type!==node.type||component.id!==node.id||component.status!=='succeeded'||component.error_code||!component.after_fingerprint;})
   ||result?.id!==migration.id||result?.state!=='succeeded'||!Array.isArray(result.affected)||result.affected.length!==nodes.size||new Set(result.affected.map((node:any)=>node.key)).size!==nodes.size||result.affected.some((node:any)=>{const original=nodes.get(node.key);return !original||node.id!==original.id||node.type!==original.type||node.status!=='succeeded';}))throw invalid();
  if(row.after_fingerprint!==this.secrets.fingerprint({migrationPlanId:plan.subject.id,state:result.state,objects:result.affected.map((node:any)=>({key:node.key,id:node.id,type:node.type,status:node.status}))}))throw invalid();
  const receipt=this.secrets.decrypt<any>(row.receipt_secret,`workflow:${execution.id}:${row.id}:receipt`);
  if(receipt?.receipt?.operationId!==mutation.id||receipt.receipt.state!=='succeeded'||!receipt.receipt.remoteStarted||!receipt.receipt.remoteCompleted||receipt.receipt.entityId!==plan.subject.id||!this.equal(receipt.result,this.secrets.redact(result)))throw invalid();
  const snapshot=this.secrets.decrypt<WorkflowSnapshotV1>(execution.snapshot_secret,snapshotAad(cid,wid,id,execution.id));
  const expected=[...plan.prerequisites.map(item=>({path:item.path,type:item.type,id:item.id,fingerprint:item.fingerprint})),...step.nativeRequests.map(item=>({path:item.canonicalPath,type:item.nativeType,id:item.nativeId!,fingerprint:item.beforeHmac!}))];
  if(snapshot.workflowId!==id||snapshot.executionId!==execution.id||snapshot.clusterId!==cid||snapshot.workspaceId!==wid||snapshot.planRevision!==plan.planRevision||snapshot.planHash!==loaded.row.plan_hash||this.secrets.fingerprint(snapshot)!==execution.snapshot_hash||snapshot.objects.length!==expected.length||new Set(snapshot.objects.map(object=>object.path)).size!==expected.length||expected.some(item=>{const object=snapshot.objects.find(object=>object.path===item.path);return !object||object.type!==item.type||object.id!==item.id||object.absent||object.fingerprint!==item.fingerprint||this.secrets.fingerprint(object.before)!==item.fingerprint;}))throw invalid();
  const approvals=await tx.query<any>('SELECT * FROM workflow_approvals WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4',[cid,wid,id,plan.planRevision]),stages=await tx.query<any>('SELECT * FROM workflow_stages WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4',[cid,wid,id,plan.planRevision]);
  const definition=await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[cid,wid,plan.definition.id,plan.definition.version]);
  if(approvals.length!==1||approvals[0].decision!=='approve'||approvals[0].approver_id!==execution.approved_by||approvals[0].plan_hash!==loaded.row.plan_hash||approvals[0].level!==1||execution.approved_by===actor.user.id||stages.length!==1||stages[0].state!=='approved'||stages[0].plan_hash!==loaded.row.plan_hash||stages[0].level!==1||stages[0].required_approvals!==1||!definition||definition.mode!=='single'||definition.allow_self_approval!==false||definition.policy_hash!==plan.definition.policyHash)throw invalid();
  await this.authz.assertMigrationWorkflowReviewerEligibility(execution.approved_by,cid,material);
  const cluster=await tx.one<any>('SELECT admin_url,transport_scope,revision,execution_mode,status FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);
  if(!cluster||cluster.status==='disabled'||cluster.revision!==plan.scope.clusterRevision||cluster.execution_mode!==plan.executionMode||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==plan.scope.transportScope)throw invalid();
  return {loaded,plan,step,row,execution,migration,mutation,material,components};
 }
 private async observe(facts:Awaited<ReturnType<WorkspaceMigrationWorkflowRecoveryService['facts']>>):Promise<void>{
  const {plan,material,components}=facts,paths=material.nodes.map(node=>node.path);
  await this.context.runInternalRead(plan.clusterId,'recycle-check',async()=>{
   for(const node of material.nodes){const current=await this.kong.request(plan.clusterId,'GET',node.path),component=components.find(item=>item.object_key===node.key);if(!component||current?.id!==node.id||this.secrets.fingerprint(current)!==component.after_fingerprint||!this.equal([...(current.tags??[])].sort(),[...node.afterTags].sort()))throw new ConflictException({code:'MIGRATION_RECOVERY_CURRENT_OBJECT_CHANGED'});const stable={...current};delete stable.tags;delete stable.updated_at;if(this.secrets.fingerprint(stable)!==node.configFingerprint)throw new ConflictException({code:'MIGRATION_RECOVERY_CURRENT_OBJECT_CHANGED'});}
  },{paths,maxCalls:paths.length,maxRecords:paths.length,maxBytes:2*1024*1024,timeoutMs:30000,workspaceId:plan.workspaceId});
 }
 async projection(cid:string,wid:string,id:string,actor:EntityActor):Promise<{eligible:boolean;kind:'workspace-migration';knownNativeComplete:true;completed?:true;executionId:string;originalExecutionKeyRequired:true}|undefined>{
  return this.context.runActor({actor:actor.user,clusterId:cid,workspaceId:wid,module:'workflows',action:'write'},async()=>{
   try{const facts=await this.facts(cid,wid,id,actor);const states=[facts.loaded.row.state,facts.execution.state];
    if(states.every(state=>state==='succeeded')){const event=await this.db.one<any>("SELECT safe_metadata FROM workflow_events WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND actor_id=$4 AND action='execution.reconcile-migration-metadata' AND safe_metadata->>'executionId'=$5",[cid,wid,id,actor.user.id,facts.execution.id]);if(event)return{eligible:false,kind:'workspace-migration',knownNativeComplete:true,completed:true,executionId:facts.execution.id,originalExecutionKeyRequired:true};return undefined;}
    if(!states.every(state=>['uncertain','partial'].includes(state)))return undefined;return{eligible:true,kind:'workspace-migration',knownNativeComplete:true,executionId:facts.execution.id,originalExecutionKeyRequired:true};
   }catch(error){if(error instanceof HttpException)return undefined;throw error;}
  });
 }
 async reconcile(cid:string,id:string,input:unknown,actor:EntityActor):Promise<void>{
  const value=portalObject(input,['revision','planHash','executionId','confirmed','confirm_name']),key=workflowKey(actor.idempotencyKey),wid=workflowId(actor.workspaceId);workflowId(value.executionId);portalRevision(value.revision);portalConfirm(value,'workspace-migration');const requestHash=this.secrets.fingerprint(value);
  await this.redis.withLock(`workflow:${id}`,async()=>{
   const initial=await this.facts(cid,wid,id,actor);
   if(initial.execution.id!==value.executionId||initial.execution.idempotency_key!==key||value.planHash!==initial.loaded.row.plan_hash)throw new ForbiddenException({code:'MIGRATION_METADATA_RECOVERY_REQUEST_MISMATCH'});
   if(initial.loaded.row.state==='succeeded'&&initial.execution.state==='succeeded'){
    const event=await this.db.one<any>("SELECT safe_metadata FROM workflow_events WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND actor_id=$4 AND action='execution.reconcile-migration-metadata' AND safe_metadata->>'executionId'=$5",[cid,wid,id,actor.user.id,initial.execution.id]);
    if(!event||event.safe_metadata?.requestHash!==requestHash||event.safe_metadata?.executionKeyFingerprint!==this.secrets.fingerprint(key))throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});return;
   }
   if(!['uncertain','partial'].includes(initial.loaded.row.state)||!['uncertain','partial'].includes(initial.execution.state)||initial.loaded.row.revision!==value.revision)throw invalid();
   await this.redis.withLock(`mutation:${initial.plan.scope.transportScope}`,async()=>{
    const permissionVersion=await this.authz.permissionVersion(actor.user);await this.observe(initial);await this.redis.assertLeaseOwnership();
    await this.db.transaction(async tx=>{
     await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');const current=await this.facts(cid,wid,id,actor,tx,true);
     if(current.loaded.row.revision!==value.revision||current.execution.id!==value.executionId||current.execution.idempotency_key!==key||!['uncertain','partial'].includes(current.loaded.row.state)||!['uncertain','partial'].includes(current.execution.state)||await this.authz.permissionVersion(actor.user,tx)!==permissionVersion)throw invalid();
     requirePortalCas(await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND workflow_id=$2 AND plan_revision=$3 AND plan_hash=$4 AND execution_actor_id=$5 AND state=$6 AND revision=$7",[current.execution.id,id,current.plan.planRevision,current.loaded.row.plan_hash,actor.user.id,current.execution.state,current.execution.revision]));
     requirePortalCas(await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND plan_hash=$5 AND revision=$6 AND state=$7",[id,cid,wid,current.plan.planRevision,current.loaded.row.plan_hash,value.revision,current.loaded.row.state]));
     await tx.exec(`INSERT INTO workflow_events(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,actor_id,actor_type,action,result,execution_id,step_id,operation_id,request_id,safe_metadata) VALUES($1,$2,$3,$4,$5,$6,'user','execution.reconcile-migration-metadata','success',$7,$8,$9,$10,$11::jsonb)`,[cid,wid,id,current.plan.planRevision,current.loaded.row.plan_hash,actor.user.id,current.execution.id,current.step.id,current.mutation.id,actor.requestId??null,JSON.stringify({executionId:current.execution.id,fromState:current.loaded.row.state,toState:'succeeded',requestHash,executionKeyFingerprint:this.secrets.fingerprint(key),knownNativeComplete:true,nativeWrites:0,originalResponseResolved:false})]);
     await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:wid,workflowId:id,entityType:'workflows',entityId:id,action:'workflow.reconcile-migration-metadata',before:{state:current.loaded.row.state},after:{state:'succeeded',executionId:current.execution.id,knownNativeComplete:true,nativeWrites:0,originalResponseResolved:false},requestId:actor.requestId,ip:actor.ip,result:'success',scopeHints:{quality:'verified',module:'workflows',subject:{type:'workflows',id},beforeExists:true,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:wid,afterWorkspaceId:wid}},tx);
     await this.approved.assertSubject(current.plan,actor.user,'write');await this.authz.assertMigrationWorkflowReviewerEligibility(current.execution.approved_by,cid,current.material);
     if(await this.authz.permissionVersion(actor.user,tx)!==permissionVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});await this.redis.assertLeaseOwnership();this.context.current();
    });
   });
  });
 }
}
