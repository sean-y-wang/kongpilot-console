import {ConflictException,ForbiddenException,Injectable,NotFoundException,OnModuleInit} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import {SecretService} from '../../infrastructure/secret.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {transportScopeFor} from '../../infrastructure/kong/transport-scope';
import {AuditService} from '../audit/audit.service';
import {AuthorizationService} from '../authorization/authorization.service';
import {coarseGrantMatches,grantMatchesEntity,validGrant} from '../authorization/grant-policy';
import type {EntityActor} from '../entities/entities.types';
import {iamBody,iamId} from '../iam/iam.types';
import {WorkflowPlansService} from '../workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../workflows/workflow-registry.service';
import {normalizeWorkflowApprovalPolicy} from '../workflows/workflow-approval-policy';
import type {WorkflowHandlerInput,WorkflowPlanV1,WorkflowReceipt} from '../workflows/workflow.types';
import {ControlMetadataBusinessService} from './control-metadata-business.service';
import {assertControlMetadataPlan,normalizeControlChangeRequest} from './control-metadata-plan';
import {CONTROL_WORKSPACE_SEED_EPOCH_DELTA,CONTROL_WORKSPACE_SEED_ROLES,verifyControlWorkspaceSeed} from './control-workspace-seed';
import type {ControlBusinessMutation,ControlCapturedChange,ControlMetadataApprovedDelegate,ControlMetadataCompletionDelegate,ControlMetadataPayload,ControlWorkflowIntent,ControlWorkflowScope} from './control-metadata.types';

const deny=(code:string)=>new ForbiddenException({code}),changed=(code:string)=>new ConflictException({code});
const aad=(id:string)=>`control-workflow:${id}:intent`,resultAad=(id:string)=>`control-workflow:${id}:result`;
interface ExecutionState {active:boolean;intent:Readonly<ControlWorkflowIntent>;plan:WorkflowPlanV1;input:WorkflowHandlerInput;tx:DbService;
 actorId:string;sessionId:string;frameSessionId:string|null;scheduledClaimId:string|null;permissionVersion:string;captureVerified:boolean;beforeVerified:boolean;afterVerified:boolean;
 beforeIamEpoch:string;beforePermissionsEpoch:string;beforeCredentialEpoch:string;beforeSuperAdmin:boolean;beforeGrantsHmac:string;
 resultHmac?:string;after?:Readonly<Record<string,unknown>>|null;factId?:string;afterPermissionVersion?:string;}

/** Registry configuration is a distinct zero-native approval domain. Each
 * approved invocation re-enters the original service with its fixed SQL
 * transaction. Only that exact original result may close a self-changing
 * cluster/workspace scope; it confers no authority for another operation. */
@Injectable()
export class ControlMetadataService implements OnModuleInit {
 private readonly executions=new WeakMap<object,ExecutionState>();
 private readonly completions=new WeakMap<object,Readonly<{state:ExecutionState;resultHmac:string}>>();
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
  private readonly audit:AuditService,private readonly authz:AuthorizationService,private readonly context:KongExecutionContextService,
  private readonly business:ControlMetadataBusinessService,private readonly plans:WorkflowPlansService,private readonly registry:WorkflowRegistryService){}
 onModuleInit():void {
  this.business.installApprovedPolicy({verifyCapture:(h,c,a,tx)=>this.verifyCapture(h,c,a,tx),verifyMutation:(h,m,p,tx,r,after)=>this.verifyMutation(h,m,p,tx,r,after)});
  this.registry.register('control.metadata',{authorize:(p,a,action)=>this.assertActor(p,a,action),prepare:i=>this.assertActor(i.plan,i.actor,'write'),
   inspect:async(i,tx)=>{const intent=await this.bound(i.plan,tx);return {before:await this.config(intent,tx),revision:this.revision(intent)};},apply:i=>this.apply(i)});
 }
 approvedDelegate():Readonly<ControlMetadataApprovedDelegate>{return Object.freeze({verifyIntent:(p:WorkflowPlanV1,tx?:DbService)=>this.verifyIntent(p,tx),
  assertSubject:async(p:WorkflowPlanV1,id:string,action:'read'|'write'|'approve',tx?:DbService)=>{const f=this.context.current();
   if(f.actor?.id!==id)throw deny('CONTROL_ACTOR_CONTEXT_REQUIRED');
   const actor={user:f.actor,workspaceId:f.workspaceId,requestId:f.requestId,ip:f.ip};
   if(!f.sessionId&&!this.scheduled(actor))throw deny('CONTROL_ACTOR_CONTEXT_REQUIRED');
   await this.assertWorkflowAdmission(p,actor,action,tx);},
  verifyReviewer:(id:string,p:WorkflowPlanV1,tx?:DbService)=>this.verifyReviewer(id,p,tx),
  assertWorkflowAdmission:(p:WorkflowPlanV1,a:EntityActor,action:'read'|'write'|'approve',tx?:DbService)=>this.assertWorkflowAdmission(p,a,action,tx)});}
 completionDelegate():Readonly<ControlMetadataCompletionDelegate>{return Object.freeze({
  verifyMetadataCompletion:(i:WorkflowHandlerInput,r:Record<string,unknown>,pv:string)=>this.verifyMetadataCompletion(i,r,pv),
  terminalReceipt:(p:WorkflowPlanV1,a:EntityActor)=>this.terminalReceipt(p,a),reviewPreview:(p:WorkflowPlanV1,a:EntityActor)=>this.reviewPreview(p,a)});}
 private actor(actor:EntityActor):string {const f=this.context.current();if(f.actor?.id!==actor.user.id||!f.sessionId||f.operation||f.archive||this.context.hasWorkflowScheduledNamespace())throw deny('CONTROL_HTTP_ACTOR_REQUIRED');return f.sessionId;}
 /** Scheduled execution identity (SQL043). Only inside the original scheduled namespace of a
  * control-metadata claim. Authoring-session snapshot on the intent; live HTTP session not required. */
 private scheduled(a:EntityActor):Readonly<{claimId:string;workflowId:string;planHash:string}>|null {const f=this.context.current();
  if(f.sessionId||!this.context.hasWorkflowScheduledNamespace())return null;
  const ns=this.context.requireWorkflowScheduledCurrentPrincipal(this.context.requireWorkflowScheduledNamespaceHandle()).namespace;
  if((ns.kind as string)!=='control-metadata'||ns.sessionId!==null||ns.actor.id!==a.user.id||f.actor?.id!==a.user.id||f.operation||f.archive)throw deny('CONTROL_SCHEDULED_ACTOR_REQUIRED');
  return Object.freeze({claimId:ns.claim.id,workflowId:ns.workflow.id,planHash:ns.workflow.planHash});}
 private async executionSession(a:EntityActor,i:Readonly<ControlWorkflowIntent>,plan:WorkflowPlanV1|null,tx:DbService):Promise<string> {const sched=this.scheduled(a);if(!sched)return this.liveSession(a,tx);
  if(a.user.id!==i.actorId||plan&&(sched.workflowId!==plan.workflowId||sched.planHash!==this.secrets.fingerprint(plan)))throw deny('CONTROL_SCHEDULED_ACTOR_REQUIRED');
  if(!await tx.one(`SELECT s.id FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2 AND s.credential_epoch=u.credential_epoch
   AND u.credential_epoch::text=$3 AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change FOR SHARE OF u`,[i.authoringSessionId,a.user.id,String(i.credentialEpoch)]))throw deny('CONTROL_SCHEDULED_REQUESTER_REVOKED');
  return i.authoringSessionId;}
 private key(actor:EntityActor):string {if(typeof actor.idempotencyKey!=='string'||!/^[A-Za-z\d_.:-]{1,128}$/.test(actor.idempotencyKey))throw changed('INVALID_IDEMPOTENCY_KEY');return actor.idempotencyKey;}
 private async liveSession(actor:EntityActor,tx:DbService):Promise<string> {const sid=this.actor(actor),s=await tx.one<any>(`SELECT s.id FROM auth_sessions s JOIN users u ON u.id=s.user_id
  WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>now() AND s.credential_epoch=u.credential_epoch
   AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change`,[sid,actor.user.id]);if(!s)throw deny('CONTROL_SESSION_REVOKED');return sid;}
 private async identity(id:string,tx:DbService) {const row=await tx.one<any>("SELECT * FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change",[iamId(id)]),epoch=await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
  if(!row||!epoch)throw deny('CONTROL_PRINCIPAL_REVOKED');return {row,grants:(await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[id])).filter(validGrant),
   version:`${row.id}:${row.permissions_epoch}:${epoch.version}`,epoch:String(epoch.version)};}
 private revision(intent:Readonly<ControlWorkflowIntent>):number {return Number(intent.capture.before?.revision??0);}
 private config(intent:Readonly<ControlWorkflowIntent>,tx=this.db) {return this.business.readConfig(intent.capture.request,intent.scope.clusterId,intent.capture.mutation.resourceId,tx);}
 private async scope(capture:Readonly<ControlCapturedChange>,tx:DbService):Promise<Readonly<ControlWorkflowScope>> {
  const m=capture.mutation,c=await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[m.clusterId]);
  if(!c||c.status==='disabled'||c.execution_mode!=='approval')throw changed('CONTROL_APPROVAL_SCOPE_REQUIRED');
  const target=capture.request.resource==='recycle-bin'?m.workspaceId:capture.request.resource==='workspaces'&&capture.request.operation!=='create'?m.resourceId:null,
   targetRow=target?await tx.one<any>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2 FOR SHARE',[c.id,target]):null;
  if(target&&!targetRow)throw changed('CONTROL_SCOPE_CHANGED');
  const w=targetRow?.status==='active'&&!targetRow.deleted_at?targetRow:await tx.one<any>("SELECT * FROM workspaces WHERE cluster_id=$1 AND is_default=true AND status='active' AND deleted_at IS NULL FOR SHARE",[c.id]);
  if(!w)throw changed('CONTROL_ANCHOR_WORKSPACE_REQUIRED');
  return immutableJson({clusterId:c.id,workspaceId:w.id,targetWorkspaceId:target,clusterRevision:c.revision,workspaceRevision:w.revision,
   transportScope:transportScopeFor(c.admin_url,c.transport_scope),executionMode:'approval'});
 }
 private whole(grants:any[],superAdmin:boolean,module:string,action:string,cid:string,wid:string|null):boolean {
  return superAdmin||grants.some(g=>coarseGrantMatches(g,module,action as any,{clusterId:cid,workspaceId:wid??undefined})
   &&(g.scope_type==='global'&&g.workspace_id===null||wid!==null&&g.scope_type==='workspace'&&g.cluster_id===cid&&g.workspace_id===wid&&g.scope_values.length===1&&g.scope_values[0]===wid));
 }
 private async subjectPermission(i:Readonly<ControlWorkflowIntent>,identity:any,action:string,tx:DbService=this.db):Promise<boolean> {
  const m=i.capture.mutation,superAdmin=identity.row.super_admin===true,target=i.scope.targetWorkspaceId;
  if(m.resource==='recycle-bin'){await this.business.assertPurgeSubject(i.capture,{user:{id:identity.row.id,username:identity.row.username,superAdmin:identity.row.super_admin===true},workspaceId:m.workspaceId??undefined},action,tx);return true;}
  if(m.resource==='clusters')return superAdmin||identity.grants.some((g:any)=>g.module==='clusters'&&g.action===action&&g.scope_type==='global'&&g.cluster_id===null&&g.workspace_id===null);
  if(m.resource==='workspaces'&&target)return superAdmin||identity.grants.some((g:any)=>grantMatchesEntity(g,'workspaces',action as any,
   {clusterId:i.scope.clusterId,workspaceId:target,entityType:'workspaces',entity:i.capture.before}));
  return this.whole(identity.grants,superAdmin,m.module,action,i.scope.clusterId,i.scope.targetWorkspaceId);
 }
 private async assertCurrent(intent:Readonly<ControlWorkflowIntent>,id:string,role:'requester'|'reader'|'reviewer',tx:DbService):Promise<void> {
  const identity=await this.identity(id,tx),m=intent.capture.mutation,s=intent.scope,wid=s.targetWorkspaceId;
  if(role==='requester'&&(id!==intent.actorId||String(identity.row.credential_epoch)!==intent.credentialEpoch||identity.version!==intent.permissionVersion))throw deny('CONTROL_REQUESTER_REVOKED');
  if(this.secrets.fingerprint(await this.scope(intent.capture,tx))!==this.secrets.fingerprint(s))throw changed('CONTROL_SCOPE_CHANGED');
  if(!this.whole(identity.grants,identity.row.super_admin===true,'workflows',role==='requester'?'write':role==='reviewer'?'approve':'read',s.clusterId,wid))throw deny('CONTROL_WORKFLOW_SCOPE_DENIED');
  const action=role==='requester'?m.action:'read';
  // Cluster registry changes retain the original console-global capability.
  const permitted=await this.subjectPermission(intent,identity,action,tx);
  if(!permitted)throw deny('CONTROL_SUBJECT_DENIED');
 }
 private async load(id:string,tx=this.db):Promise<Readonly<ControlWorkflowIntent>> {
  const row=await tx.one<any>('SELECT * FROM control_change_intents WHERE id=$1',[iamId(id)]);if(!row)throw new NotFoundException({code:'CONTROL_CHANGE_INTENT_NOT_FOUND'});
  const i=immutableJson(this.secrets.decrypt<ControlWorkflowIntent>(row.material_secret,aad(row.id))),m=i.capture?.mutation;
  if(i.version!==1||i.id!==row.id||i.actorId!==row.actor_id||i.authoringSessionId!==row.authoring_session_id||i.workflowId!==row.workflow_id||i.scope.clusterId!==row.cluster_id||i.scope.workspaceId!==row.workspace_id
   ||i.idempotencyKey!==row.idempotency_key||i.requestHmac!==row.request_hmac||i.permissionVersion!==row.permission_version||i.credentialEpoch!==String(row.credential_epoch)
   ||this.secrets.fingerprint(i)!==row.material_hmac||i.workflowKey!==`control-${i.id}`||this.secrets.fingerprint(i.capture.request)!==i.requestHmac
   ||this.secrets.fingerprint(normalizeControlChangeRequest(i.capture.request))!==i.requestHmac||m.resource!==row.resource||m.resourceId!==row.resource_id||m.operation!==row.operation||m.clusterId!==row.cluster_id
   ||this.revision(i)!==row.before_revision||this.secrets.fingerprint(i.capture.before)!==row.before_config_hmac
   ||!Number.isFinite(Date.parse(i.issuedAt))||!Number.isFinite(Date.parse(i.expiresAt))||Date.parse(i.expiresAt)<=Date.parse(i.issuedAt)||Date.parse(i.expiresAt)>Date.parse(i.issuedAt)+86400000
   ||new Date(row.issued_at).getTime()!==Date.parse(i.issuedAt)||new Date(row.expires_at).getTime()!==Date.parse(i.expiresAt))throw changed('CONTROL_INTENT_INVALID');return i;
 }
 private async definition(scope:Readonly<ControlWorkflowScope>,actorId:string,tx:DbService) {
  await this.plans.definitions(scope.clusterId,scope.workspaceId,actorId,tx);const definition=await this.plans.definition(scope.clusterId,scope.workspaceId,'control-metadata' as any,tx),
   row=await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[scope.clusterId,scope.workspaceId,definition.id,definition.version]);
  if(row?.approval_format!==2||this.secrets.fingerprint(row.policy)!==definition.policyHash)throw changed('CONTROL_V2_POLICY_REQUIRED');
  return {definition,policy:normalizeWorkflowApprovalPolicy(row.policy,'control-metadata' as any)};
 }
 async prepare(clusterId:string,raw:unknown,actor:EntityActor):Promise<Record<string,unknown>> {
  clusterId=iamId(clusterId).toLowerCase();const request=normalizeControlChangeRequest(raw),sid=this.actor(actor),key=this.key(actor),requestHmac=this.secrets.fingerprint(request);
  return this.redis.withLock(`control-change:${actor.user.id}:${key}`,()=>this.db.transaction(async tx=>{
   await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');await this.liveSession(actor,tx);
   const prior=await tx.one<any>('SELECT id,cluster_id,request_hmac FROM control_change_intents WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
   if(prior){if(prior.cluster_id!==clusterId||prior.request_hmac!==requestHmac)throw changed('IDEMPOTENCY_CONFLICT');return this.receipt(clusterId,prior.id,actor,tx);}
   if(await tx.one('SELECT id FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]))throw changed('IDEMPOTENCY_CONFLICT');
   const capture=await this.business.capture(request,clusterId,actor,tx),scope=await this.scope(capture,tx),identity=await this.identity(actor.user.id,tx),{policy}=await this.definition(scope,actor.user.id,tx);
   if(request.operation!=='create'&&Number(request.input.revision)!==Number(capture.before?.revision))throw changed('CONTROL_METADATA_CHANGED');
   const session=await tx.one<any>('SELECT expires_at FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() AND credential_epoch=$3',[sid,actor.user.id,identity.row.credential_epoch]);
   if(!session)throw deny('CONTROL_SESSION_REVOKED');const id=randomUUID(),now=Date.now(),expiresAt=new Date(Math.min(now+86400000,now+policy.intentTtlHours*3600000,new Date(session.expires_at).getTime())).toISOString(),
    intent:Readonly<ControlWorkflowIntent>=immutableJson({version:1,id,workflowId:randomUUID(),actorId:actor.user.id,authoringSessionId:sid,credentialEpoch:String(identity.row.credential_epoch),permissionVersion:identity.version,
     idempotencyKey:key,workflowKey:`control-${id}`,requestHmac,issuedAt:new Date(now).toISOString(),expiresAt,capture,scope});
   await this.assertCurrent(intent,actor.user.id,'requester',tx);
   await tx.exec(`INSERT INTO control_change_intents(id,cluster_id,workspace_id,actor_id,authoring_session_id,workflow_id,idempotency_key,request_hmac,material_hmac,material_secret,
    credential_epoch,permission_version,resource,resource_id,operation,before_revision,before_config_hmac,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
    [id,scope.clusterId,scope.workspaceId,actor.user.id,sid,intent.workflowId,key,requestHmac,this.secrets.fingerprint(intent),this.secrets.encrypt(intent,aad(id)),intent.credentialEpoch,intent.permissionVersion,
     capture.mutation.resource,capture.mutation.resourceId,capture.mutation.operation,this.revision(intent),this.secrets.fingerprint(capture.before),intent.issuedAt,intent.expiresAt]);
   await this.audit.append({actorId:actor.user.id,clusterId,workspaceId:scope.workspaceId,entityType:'control_change_intents',entityId:id,action:'control.change.prepare',after:{resource:request.resource,operation:request.operation,resourceId:capture.mutation.resourceId,materialHmac:this.secrets.fingerprint(intent),nativeRequestsSent:0},requestId:actor.requestId,ip:actor.ip},tx);
   await this.redis.assertLeaseOwnership();return this.receipt(clusterId,id,actor,tx);
  }));
 }
 private interactive(plan:WorkflowPlanV1):WorkflowPlanV1 {if((plan as any)?.scheduling===undefined)return plan;const f=this.context.peek();
  if(!f||f.sessionId||!this.context.hasWorkflowScheduledNamespace())throw changed('CONTROL_BINDING_INVALID');
  const ns=this.context.requireWorkflowScheduledCurrentPrincipal(this.context.requireWorkflowScheduledNamespaceHandle()).namespace;
  if((ns.kind as string)!=='control-metadata'||ns.workflow.id!==plan.workflowId||ns.workflow.planHash!==this.secrets.fingerprint(plan))throw changed('CONTROL_BINDING_INVALID');
  const {scheduling:_sealed,...rest}=plan as any;return rest;}
 private async bound(plan:WorkflowPlanV1,tx=this.db):Promise<Readonly<ControlWorkflowIntent>> {
  const step=assertControlMetadataPlan(this.interactive(plan)),p=step.metadata as ControlMetadataPayload,i=await this.load(p.intentId,tx),r=await tx.one<any>('SELECT * FROM control_metadata_requests WHERE id=$1 AND workflow_id=$2 AND cluster_id=$3 AND workspace_id=$4',[i.id,plan.workflowId,plan.clusterId,plan.workspaceId]);
  if(!r||i.workflowId!==plan.workflowId||i.actorId!==plan.requester.id||i.scope.clusterId!==plan.clusterId||i.scope.workspaceId!==plan.workspaceId||r.actor_id!==i.actorId||r.material_hmac!==this.secrets.fingerprint(i)
   ||p.materialHmac!==r.material_hmac||p.resource!==i.capture.request.resource||p.operation!==i.capture.request.operation||r.idempotency_key!==i.workflowKey||r.request_hmac!==i.requestHmac||plan.expiresAt!==i.expiresAt
   ||this.secrets.fingerprint(step.before)!==this.secrets.fingerprint(i.capture.before)||step.metadataBeforeHmac!==this.secrets.fingerprint(i.capture.before)||step.metadataPayloadHmac!==this.secrets.fingerprint(p)
   ||step.metadataRevision!==this.revision(i)||this.secrets.fingerprint(plan.scope)!==this.secrets.fingerprint({transportScope:i.scope.transportScope,clusterRevision:i.scope.clusterRevision,workspaceRevision:i.scope.workspaceRevision}))throw changed('CONTROL_BINDING_INVALID');return i;
 }
 async verifyIntent(plan:WorkflowPlanV1,tx=this.db):Promise<void>{await this.bound(plan,tx);}
 async verifyReviewer(id:string,plan:WorkflowPlanV1,tx=this.db):Promise<void>{const i=await this.bound(plan,tx);await this.assertCurrent(i,id,id===i.actorId?'requester':'reviewer',tx);}
 async assertWorkflowAdmission(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve',tx=this.db):Promise<void> {
  const intent=await this.bound(plan,tx),frame=this.context.current(),allowed=new Set([plan.workspaceId,intent.scope.targetWorkspaceId].filter((id):id is string=>id!==null));
  if(actor.workspaceId!==undefined&&!allowed.has(actor.workspaceId)||frame.workspaceId!==undefined&&!allowed.has(frame.workspaceId)||frame.clusterId&&frame.clusterId!==plan.clusterId)throw deny('CONTROL_WORKFLOW_SELECTOR_DENIED');
  // Only the sealed anchor and its genuine original target are selectable.
  // Permission checks still use the target; the current Context frame is
  // neither exited nor rewritten by this fixed admission callback.
  await this.assertActor(plan,{...actor,workspaceId:plan.workspaceId},action,tx);
 }
 private async assertActor(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve',tx=this.db):Promise<void> {
  const i=await this.bound(plan,tx),sid=await this.executionSession(actor,i,plan,tx);
  if(this.scheduled(actor)&&action!=='write')throw deny('CONTROL_SCHEDULED_ACTOR_REQUIRED');
  if(actor.workspaceId!==plan.workspaceId||action==='write'&&(actor.user.id!==i.actorId||sid!==i.authoringSessionId))throw deny('CONTROL_EXECUTOR_DENIED');
  if(action!=='read'&&Date.parse(i.expiresAt)<=Date.now())throw changed('CONTROL_INTENT_EXPIRED');
  await this.assertCurrent(i,actor.user.id,action==='write'?'requester':action==='approve'?'reviewer':'reader',tx);
  if(action!=='read'&&this.secrets.fingerprint(await this.config(i,tx))!==this.secrets.fingerprint(i.capture.before))throw changed('CONTROL_METADATA_CHANGED');
 }
 async submit(clusterId:string,id:string,raw:unknown,actor:EntityActor):Promise<Record<string,unknown>> {
  clusterId=iamId(clusterId).toLowerCase();const value=iamBody(raw,['confirmed','materialHmac']);if(value.confirmed!==true||typeof value.materialHmac!=='string')throw changed('CONFIRMATION_REQUIRED');const sid=this.actor(actor),key=this.key(actor);
  return this.redis.withLock(`control-change-submit:${id}`,()=>this.db.transaction(async tx=>{
   await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');await this.liveSession(actor,tx);const i=await this.load(id,tx);
   if(i.actorId!==actor.user.id||i.authoringSessionId!==sid||i.scope.clusterId!==clusterId)throw deny('CONTROL_AUTHOR_MISMATCH');
   const existing=await tx.one<any>('SELECT submit_key,material_hmac FROM control_metadata_requests WHERE id=$1',[id]);
   if(existing){if(existing.submit_key!==key||existing.material_hmac!==value.materialHmac)throw changed('IDEMPOTENCY_CONFLICT');return this.receipt(clusterId,id,actor,tx);}
   if(Date.parse(i.expiresAt)<=Date.now()||value.materialHmac!==this.secrets.fingerprint(i))throw changed('CONTROL_INTENT_EXPIRED_OR_CHANGED');
   await this.assertCurrent(i,actor.user.id,'requester',tx);if(this.secrets.fingerprint(await this.config(i,tx))!==this.secrets.fingerprint(i.capture.before))throw changed('CONTROL_METADATA_CHANGED');
   const {definition,policy}=await this.definition(i.scope,actor.user.id,tx);if(Date.parse(i.expiresAt)>Date.parse(i.issuedAt)+policy.intentTtlHours*3600000)throw changed('CONTROL_POLICY_TTL_CHANGED');
   const s=i.scope,payload:ControlMetadataPayload={intentId:id,resource:i.capture.request.resource,operation:i.capture.request.operation,materialHmac:this.secrets.fingerprint(i)};
   await tx.exec(`INSERT INTO control_metadata_requests(id,cluster_id,workspace_id,actor_id,workflow_id,idempotency_key,submit_key,request_hmac,material_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[id,s.clusterId,s.workspaceId,actor.user.id,i.workflowId,i.workflowKey,key,i.requestHmac,this.secrets.fingerprint(i)]);
   const plan:WorkflowPlanV1={version:1,kind:'control-metadata' as any,clusterId:s.clusterId,workspaceId:s.workspaceId,workflowId:i.workflowId,planRevision:1,executionMode:'approval',approvalRequired:true,subject:{type:'control_metadata_requests' as any,id},requester:{type:'console',id:actor.user.id},definition,
    issuedAt:i.issuedAt,expiresAt:i.expiresAt,scope:{transportScope:s.transportScope,clusterRevision:s.clusterRevision,workspaceRevision:s.workspaceRevision},prerequisites:[],steps:[{id:randomUUID(),key:'control.metadata',order:1,kind:'metadata',handler:'control.metadata',entityType:'control_metadata_requests',entityId:id,permissionAction:i.capture.mutation.action,
     dependencies:[],nativeRequests:[],before:i.capture.before,metadataRevision:this.revision(i),metadataBeforeHmac:this.secrets.fingerprint(i.capture.before),metadata:payload,metadataPayloadHmac:this.secrets.fingerprint(payload)}]};
   await this.plans.persist(plan,i.workflowKey,i.capture.request,tx,{requestId:actor.requestId,ip:actor.ip});await this.redis.assertLeaseOwnership();return this.receipt(clusterId,id,actor,tx);
  }));
 }
 private async terminalFact(intent:Readonly<ControlWorkflowIntent>,planHash:string,tx:DbService):Promise<any> {
  return tx.one<any>(`SELECT f.*,e.idempotency_key AS execution_key,w.revision FROM control_workflow_mutation_facts f JOIN workflows w ON w.id=f.workflow_id
   JOIN workflow_executions e ON e.id=f.execution_id JOIN workflow_steps s ON s.id=f.step_id JOIN audit_events a ON a.id=f.audit_id
   WHERE f.intent_id=$1 AND f.workflow_id=$2 AND f.actor_id=$3 AND f.session_id=$4 AND f.plan_hash=$5 AND f.cluster_id=$6 AND f.workspace_id=$7
    AND w.kind='control-metadata' AND w.subject_id=f.intent_id AND w.state='succeeded' AND e.state='succeeded' AND s.state='succeeded' AND e.workflow_id=w.id AND s.workflow_id=w.id
    AND e.plan_hash=w.plan_hash AND s.plan_hash=w.plan_hash AND e.plan_revision=w.plan_revision AND s.plan_revision=w.plan_revision AND e.plan_hash=f.plan_hash AND e.plan_revision=f.plan_revision
    AND e.execution_actor_id=f.actor_id AND e.approval_format=2 AND e.approval_set_id=w.approval_set_id AND e.approval_set_hmac=w.approval_set_hmac
    AND s.handler='control.metadata' AND s.kind='metadata' AND s.native_requests='[]'::jsonb AND a.actor_id=f.actor_id AND a.actor_type='user'
    AND a.cluster_id=f.cluster_id AND a.workspace_id=f.workspace_id AND a.entity_type=f.resource AND a.entity_id=f.resource_id::text
    AND a.action='control.metadata' AND a.workflow_id=w.id AND a.result='success'
    AND f.resource=$8 AND f.resource_id=$9 AND f.operation=$10 AND f.before_config_hmac=$11 AND f.before_revision=$12`,
   [intent.id,intent.workflowId,intent.actorId,intent.authoringSessionId,planHash,intent.scope.clusterId,intent.scope.workspaceId,intent.capture.mutation.resource,intent.capture.mutation.resourceId,intent.capture.mutation.operation,this.secrets.fingerprint(intent.capture.before),this.revision(intent)]);
 }
 async receipt(clusterId:string,id:string,actor:EntityActor,tx=this.db):Promise<Record<string,unknown>> {
  clusterId=iamId(clusterId).toLowerCase();const i=await this.load(id,tx),sid=await this.liveSession(actor,tx);if(i.actorId!==actor.user.id||i.authoringSessionId!==sid||i.scope.clusterId!==clusterId)throw deny('CONTROL_INTENT_OWNER_REQUIRED');
  const r=await tx.one<any>('SELECT workflow_id FROM control_metadata_requests WHERE id=$1',[id]),w=r?await tx.one<any>('SELECT id,state,revision,plan_hash FROM workflows WHERE id=$1',[r.workflow_id]):null;
  let preview:Record<string,unknown>|null=null;
  if(w?.state==='succeeded'){if(!await this.terminalFact(i,w.plan_hash,tx))throw deny('CONTROL_TERMINAL_FACT_REQUIRED');}
  else {await this.assertCurrent(i,actor.user.id,'requester',tx);preview=await this.preview(i,actor,tx);}
  return {intentId:i.id,resource:i.capture.request.resource,operation:i.capture.request.operation,resourceId:i.capture.mutation.resourceId,materialHmac:this.secrets.fingerprint(i),state:w?.state??'prepared',workflowId:w?.id??null,
   revision:w?.revision??null,planHash:w?.plan_hash??null,clusterId:i.scope.clusterId,workspaceId:i.scope.workspaceId,expiresAt:i.expiresAt,nativeRequestsSent:0,preview};
 }
 async receiptByKey(clusterId:string,key:string,actor:EntityActor):Promise<Record<string,unknown>> {
  await this.liveSession(actor,this.db);this.key({...actor,idempotencyKey:key});clusterId=iamId(clusterId).toLowerCase();
  const row=await this.db.one<any>('SELECT id FROM control_change_intents WHERE actor_id=$1 AND cluster_id=$2 AND idempotency_key=$3',[actor.user.id,clusterId,key]);if(!row)throw new NotFoundException({code:'CONTROL_CHANGE_INTENT_NOT_FOUND'});return this.receipt(clusterId,row.id,actor);
 }
 private safe(value:unknown,platformAdmin:boolean):unknown {const redacted:any=this.secrets.redact(value);
  const visit=(v:any):any=>{if(Array.isArray(v))return v.map(visit);if(!v||typeof v!=='object')return v;return Object.fromEntries(Object.entries(v).filter(([k])=>!['connection_auth','connection_secret','auth','auth_secret'].includes(k)&&
   (platformAdmin||!['admin_url','base_url','proxy_origin','transport_scope'].includes(k))).map(([k,x])=>[k,visit(x)]));};return visit(redacted);
 }
 private auditConfig(value:Readonly<Record<string,unknown>>|null):unknown {
  if(!value)return null;const privateFields=['admin_url','base_url','proxy_origin','transport_scope','connection_secret','auth_secret'];
  return {...this.safe(value,false) as Record<string,unknown>,protectedFields:Object.fromEntries(privateFields.filter(k=>Object.hasOwn(value,k)).map(k=>[k,value[k]===null?null:this.secrets.fingerprint(value[k])]))};
 }
 private async preview(i:Readonly<ControlWorkflowIntent>,actor:EntityActor,tx:DbService):Promise<Record<string,unknown>> {
  const identity=await this.identity(actor.user.id,tx),admin=identity.row.super_admin===true,m=i.capture.mutation;
  // Review never obtains more metadata than the actor's current module READ.
  const canRead=await this.subjectPermission(i,identity,'read',tx);
  if(!canRead)throw deny('CONTROL_PREVIEW_READ_DENIED');
  const authKey=m.resource==='clusters'?'connection_auth':m.resource==='data-sources'?'auth':null,payload=m.payload as Record<string,any>,hasAuthChange=!!authKey&&Object.hasOwn(payload,authKey),
   authSummary=hasAuthChange?{mode:payload[authKey!]?.type??'none',materialHmac:this.secrets.fingerprint(payload[authKey!]??null)}:undefined,
   before=i.capture.before?{...this.safe(i.capture.before,admin) as Record<string,unknown>,...(authKey?{authenticationConfigured:!!(i.capture.before.connection_secret??i.capture.before.auth_secret)}:{})}:null;
  return {request:this.safe(i.capture.request,admin),before,after:{resource:m.resource,operation:m.operation,resourceId:m.resourceId,input:this.safe(m.payload,admin),...(authSummary?{authentication:authSummary}:{}),
   ...(m.resource==='workspaces'&&m.operation==='create'?{builtInRoles:CONTROL_WORKSPACE_SEED_ROLES,roleAssignments:0}:{})},
   affectedScopes:[{clusterId:i.scope.clusterId,workspaceId:i.scope.targetWorkspaceId,clusterRevision:i.scope.clusterRevision,workspaceRevision:i.scope.workspaceRevision}],confirmationName:(m.payload as any)?.confirm_name??i.capture.before?.name??(m.payload as any)?.name??m.resourceId};
 }
 async reviewPreview(p:WorkflowPlanV1,a:EntityActor):Promise<Record<string,unknown>> {const i=await this.bound(p);await this.assertActor(p,a,'read');const preview=await this.preview(i,a,this.db),step=assertControlMetadataPlan(p);
  return {diff:[{id:step.id,kind:'metadata',operation:i.capture.request.operation,entityType:i.capture.request.resource,entityId:i.capture.mutation.resourceId,before:preview.before,after:preview.after}],affectedScopes:preview.affectedScopes};}
 private execution(h:object):ExecutionState {const s=this.executions.get(h);if(!s?.active||Date.parse(s.intent.expiresAt)<=Date.now())throw deny('CONTROL_ORIGINAL_EXECUTION_REQUIRED');return s;}
 private async running(s:ExecutionState,tx:DbService):Promise<void> {
  const {plan,input}=s,f=this.context.current(),step=this.context.currentApprovedStep();
  if(f.actor?.id!==s.actorId||(f.sessionId??null)!==s.frameSessionId||step.kind!=='metadata'||step.stepId!==input.step.id||step.execution.executionId!==input.executionId||step.execution.workflowId!==plan.workflowId
   ||step.execution.actorId!==s.actorId||(step.execution.sessionId??null)!==s.frameSessionId||s.tx!==tx||input.transaction!==tx)throw deny('CONTROL_ORIGINAL_EXECUTION_REQUIRED');
  if(!await tx.one(`SELECT e.id FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id JOIN workflow_steps s ON s.workflow_id=w.id
   WHERE e.id=$1 AND w.id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4 AND e.state='executing' AND w.state='executing' AND e.execution_actor_id=$5
    AND e.approval_format=2 AND e.approval_set_id=w.approval_set_id AND e.approval_set_hmac=w.approval_set_hmac AND s.id=$6 AND s.state='running'
    AND s.handler='control.metadata' AND s.kind='metadata' AND s.native_requests='[]'::jsonb AND e.plan_hash=$7 AND e.plan_revision=$8
    AND w.plan_hash=e.plan_hash AND w.plan_revision=e.plan_revision AND s.plan_hash=e.plan_hash AND s.plan_revision=e.plan_revision`,[input.executionId,plan.workflowId,plan.clusterId,plan.workspaceId,s.actorId,input.step.id,this.secrets.fingerprint(plan),plan.planRevision]))throw deny('CONTROL_APPROVED_EXECUTION_REQUIRED');
 }
 private async apply(input:WorkflowHandlerInput):Promise<Record<string,unknown>> {
  const {plan,actor,transaction:tx}=input,intent=await this.bound(plan,tx);await this.assertActor(plan,actor,'write',tx);
  await this.context.assertApprovedMetadataStep({handler:'control.metadata',actor:actor.user,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'control_metadata_requests',entityId:intent.id,before:intent.capture.before,revision:this.revision(intent),payload:input.step.metadata},tx);
  const identity=await this.identity(actor.user.id,tx),handle=Object.freeze({}),state:ExecutionState={active:true,intent,plan:immutableJson(plan),input,tx,actorId:actor.user.id,...(()=>{const sched=this.scheduled(actor);return sched?{sessionId:intent.authoringSessionId,frameSessionId:null,scheduledClaimId:sched.claimId}:{sessionId:this.actor(actor),frameSessionId:this.actor(actor),scheduledClaimId:null};})(),permissionVersion:identity.version,
   beforeIamEpoch:identity.epoch,beforePermissionsEpoch:String(identity.row.permissions_epoch),beforeCredentialEpoch:String(identity.row.credential_epoch),beforeSuperAdmin:identity.row.super_admin===true,beforeGrantsHmac:this.grantsHmac(identity.grants),captureVerified:false,beforeVerified:false,afterVerified:false};
  this.executions.set(handle,state);
  try {const entity=await this.business.apply(handle,intent.capture,actor,tx);if(!state.afterVerified||state.resultHmac!==this.secrets.fingerprint(entity)||!state.factId)throw deny('CONTROL_RESULT_UNACKNOWLEDGED');
   // The public workflow result contains no registry endpoints or auth payload.
   const result=immutableJson({intentId:intent.id,resource:intent.capture.request.resource,resourceId:intent.capture.mutation.resourceId,operation:intent.capture.request.operation,nativeRequestsSent:0});
   this.completions.set(result,Object.freeze({state,resultHmac:this.secrets.fingerprint(result)}));return result;
  }finally {state.active=false;this.executions.delete(handle);}
 }
 private async verifyCapture(h:object,capture:Readonly<ControlCapturedChange>,actor:EntityActor,tx:DbService):Promise<void> {
  const s=this.execution(h);await this.running(s,tx);if(s.captureVerified||actor.user.id!==s.actorId||this.secrets.fingerprint(capture)!==this.secrets.fingerprint(s.intent.capture))throw deny('CONTROL_CAPTURE_MISMATCH');s.captureVerified=true;
 }
 private grantsHmac(grants:unknown[]):string {return this.secrets.fingerprint(grants.map(g=>this.secrets.fingerprint(g)).sort());}
 private async verifyFinalIdentity(s:ExecutionState,identity:any,tx:DbService):Promise<void> {
  if(String(identity.row.permissions_epoch)!==s.beforePermissionsEpoch||String(identity.row.credential_epoch)!==s.beforeCredentialEpoch||(identity.row.super_admin===true)!==s.beforeSuperAdmin
   ||this.grantsHmac(identity.grants)!==s.beforeGrantsHmac)throw deny('CONTROL_PERMISSIONS_CHANGED');
  const mutation=s.intent.capture.mutation,seed=mutation.resource==='workspaces'&&mutation.operation==='create'&&s.intent.capture.before===null;
  if(!seed){if(identity.version!==s.permissionVersion)throw deny('CONTROL_PERMISSIONS_CHANGED');return;}
  if(!/^\d+$/.test(s.beforeIamEpoch)||identity.epoch!==(BigInt(s.beforeIamEpoch)+BigInt(CONTROL_WORKSPACE_SEED_EPOCH_DELTA)).toString())throw deny('CONTROL_WORKSPACE_SEED_CHANGED');
  await verifyControlWorkspaceSeed(tx,s.plan.clusterId,mutation.resourceId);
 }
 private async verifyMutation(h:object,m:Readonly<ControlBusinessMutation>,phase:'before'|'after',tx:DbService,result?:unknown,after?:Readonly<Record<string,unknown>>|null):Promise<void> {
  const s=this.execution(h);await this.running(s,tx);const {actor,...pure}=m;
  if(!s.captureVerified||actor.user.id!==s.actorId||this.secrets.fingerprint(pure)!==this.secrets.fingerprint(s.intent.capture.mutation))throw deny('CONTROL_MUTATION_MISMATCH');
  if(phase==='before') {if(s.beforeVerified||s.afterVerified)throw deny('CONTROL_FIXED_OPERATION_REQUIRED');await this.assertActor(s.plan,actor,'write',tx);
   await this.context.assertApprovedMetadataStep({handler:'control.metadata',actor:actor.user,clusterId:s.plan.clusterId,workspaceId:s.plan.workspaceId,entityType:'control_metadata_requests',entityId:s.intent.id,before:s.intent.capture.before,revision:this.revision(s.intent),payload:s.input.step.metadata},tx);s.beforeVerified=true;return;}
  if(!s.beforeVerified||s.afterVerified||result===undefined||!after||after.id!==m.resourceId||m.resource!=='clusters'&&after.cluster_id!==m.clusterId||Number(after.revision)!==this.revision(s.intent)+1
   ||this.secrets.fingerprint(await this.config(s.intent,tx))!==this.secrets.fingerprint(after))throw changed('CONTROL_RESULT_READBACK_MISMATCH');
  if(['archive','deactivate'].includes(m.operation)?!after.deleted_at:!!after.deleted_at)throw changed('CONTROL_RESULT_STATE_MISMATCH');
  if(m.resource==='recycle-bin'&&(m.operation!=='purge'||after.state!=='purged'||after.payload_present!==false||after.purged_at===null))throw changed('CONTROL_PURGE_RESULT_STATE_MISMATCH');
  if(m.resource==='workspaces'&&(m.operation==='archive'?after.status!=='deleted':m.operation==='restore'||m.operation==='create'?after.status!=='active':!['active','disabled'].includes(String(after.status))))throw changed('CONTROL_RESULT_STATE_MISMATCH');
  if(await this.executionSession(actor,s.intent,s.plan,tx)!==s.sessionId)throw deny('CONTROL_SESSION_REVOKED');const identity=await this.identity(s.actorId,tx);await this.verifyFinalIdentity(s,identity,tx);
  const audit=await this.audit.append({actorId:s.actorId,clusterId:s.plan.clusterId,workspaceId:s.plan.workspaceId,entityType:m.resource,entityId:m.resourceId,action:'control.metadata',workflowId:s.plan.workflowId,
   before:this.auditConfig(s.intent.capture.before),after:this.auditConfig(after),requestId:actor.requestId,ip:actor.ip},tx),factId=randomUUID();
  await tx.exec(`INSERT INTO control_workflow_mutation_facts(id,intent_id,workflow_id,execution_id,step_id,cluster_id,workspace_id,actor_id,session_id,plan_revision,plan_hash,
   before_permission_version,after_permission_version,before_config_hmac,after_config_hmac,result_hmac,result_secret,audit_id,resource,resource_id,operation,before_revision,after_revision,execution_origin,schedule_claim_id)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
   [factId,s.intent.id,s.plan.workflowId,s.input.executionId,s.input.step.id,s.plan.clusterId,s.plan.workspaceId,s.actorId,s.sessionId,s.plan.planRevision,this.secrets.fingerprint(s.plan),s.permissionVersion,identity.version,
    this.secrets.fingerprint(s.intent.capture.before),this.secrets.fingerprint(after),this.secrets.fingerprint(result),this.secrets.encrypt(result,resultAad(factId)),audit.id,m.resource,m.resourceId,m.operation,this.revision(s.intent),Number(after.revision),s.scheduledClaimId?'scheduled':'session',s.scheduledClaimId]);
  s.afterVerified=true;s.after=immutableJson(after);s.resultHmac=this.secrets.fingerprint(result);s.factId=factId;s.afterPermissionVersion=identity.version;
 }
 async verifyMetadataCompletion(input:WorkflowHandlerInput,result:Record<string,unknown>,beforePermissionVersion:string):Promise<void> {
  const completion=result&&typeof result==='object'?this.completions.get(result):undefined;if(!completion)throw deny('CONTROL_ORIGINAL_COMPLETION_REQUIRED');this.completions.delete(result);
  const {state:s}=completion,tx=input.transaction;
  if(s.input!==input||s.tx!==tx||!s.afterVerified||!s.factId||beforePermissionVersion!==s.permissionVersion||Date.parse(s.intent.expiresAt)<=Date.now()
   ||this.secrets.fingerprint(result)!==completion.resultHmac||this.secrets.fingerprint(input.plan)!==this.secrets.fingerprint(s.plan)||this.secrets.fingerprint(input.step)!==this.secrets.fingerprint(s.plan.steps[0]))throw deny('CONTROL_ORIGINAL_COMPLETION_REQUIRED');
  if(await this.executionSession(input.actor,s.intent,s.plan,tx)!==s.sessionId)throw deny('CONTROL_SESSION_REVOKED');await this.running(s,tx);await this.bound(input.plan,tx);const identity=await this.identity(s.actorId,tx),row=await tx.one<any>(`SELECT f.*,a.actor_id AS audit_actor,a.cluster_id AS audit_cluster,a.workspace_id AS audit_workspace,a.entity_type AS audit_type,a.entity_id AS audit_entity,a.action AS audit_action,a.workflow_id AS audit_workflow,a.result AS audit_result
   FROM control_workflow_mutation_facts f JOIN audit_events a ON a.id=f.audit_id WHERE f.id=$1 AND f.intent_id=$2 AND f.workflow_id=$3 AND f.execution_id=$4 AND f.step_id=$5`,[s.factId,s.intent.id,s.plan.workflowId,input.executionId,input.step.id]),m=s.intent.capture.mutation;
  if(!row||row.actor_id!==s.actorId||row.session_id!==s.sessionId||(row.execution_origin??'session')!==(s.scheduledClaimId?'scheduled':'session')||(row.schedule_claim_id??null)!==s.scheduledClaimId||row.cluster_id!==s.plan.clusterId||row.workspace_id!==s.plan.workspaceId||row.plan_hash!==this.secrets.fingerprint(s.plan)||row.plan_revision!==s.plan.planRevision
   ||row.before_permission_version!==s.permissionVersion||row.after_permission_version!==identity.version||identity.version!==s.afterPermissionVersion||row.resource!==m.resource||row.resource_id!==m.resourceId||row.operation!==m.operation
   ||row.before_revision!==this.revision(s.intent)||row.after_revision!==Number(s.after?.revision)
   ||row.before_config_hmac!==this.secrets.fingerprint(s.intent.capture.before)||row.after_config_hmac!==this.secrets.fingerprint(s.after)||row.result_hmac!==s.resultHmac||this.secrets.fingerprint(this.secrets.decrypt(row.result_secret,resultAad(s.factId)))!==s.resultHmac
   ||this.secrets.fingerprint(await this.config(s.intent,tx))!==row.after_config_hmac||row.audit_actor!==s.actorId||row.audit_cluster!==s.plan.clusterId||row.audit_workspace!==s.plan.workspaceId||row.audit_type!==m.resource||row.audit_entity!==m.resourceId||row.audit_action!=='control.metadata'||row.audit_workflow!==s.plan.workflowId||row.audit_result!=='success')throw deny('CONTROL_COMPLETION_FACTS_CHANGED');
  await this.verifyFinalIdentity(s,identity,tx);await this.redis.assertLeaseOwnership();this.context.current();
 }
 async terminalReceipt(plan:WorkflowPlanV1,actor:EntityActor):Promise<WorkflowReceipt> {
  const i=await this.bound(plan),sid=await this.liveSession(actor,this.db),frame=this.context.current(),allowed=new Set([plan.workspaceId,i.scope.targetWorkspaceId].filter((id):id is string=>id!==null));
  if(i.actorId!==actor.user.id||sid!==i.authoringSessionId||actor.workspaceId!==undefined&&!allowed.has(actor.workspaceId)||frame.workspaceId!==undefined&&!allowed.has(frame.workspaceId)||frame.clusterId&&frame.clusterId!==plan.clusterId)throw deny('CONTROL_INTENT_OWNER_REQUIRED');
  const row=await this.terminalFact(i,this.secrets.fingerprint(plan),this.db);if(!row)throw deny('CONTROL_TERMINAL_RECEIPT_UNAVAILABLE');
  return {id:row.execution_id,workflowId:plan.workflowId,executionId:row.execution_id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,idempotencyKey:row.execution_key,state:'succeeded',revision:row.revision,planHash:this.secrets.fingerprint(plan),
   executionMode:'approval',approvalRequired:true,steps:[{id:row.step_id,name:'control.metadata',state:'succeeded',operationId:null,remoteStarted:false,remoteCompleted:true,recycleEntryId:null,errorCode:null}],propagation:'acknowledged'};
 }
}
