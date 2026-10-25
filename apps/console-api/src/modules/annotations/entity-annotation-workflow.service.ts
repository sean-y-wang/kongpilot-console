import {ConflictException,ForbiddenException,Injectable,NotFoundException,OnModuleInit} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import {SecretService} from '../../infrastructure/secret.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {transportScopeFor} from '../../infrastructure/kong/transport-scope';
import {AuditService,type AuditOutboxReceipt} from '../audit/audit.service';
import {coarseGrantMatches,grantMatchesEntity,validGrant} from '../authorization/grant-policy';
import type {EntityActor} from '../entities/entities.types';
import type {EntityAnnotationRow} from '../workspaces/entity-annotations.service';
import {iamBody,iamId} from '../iam/iam.types';
import {WorkflowPlansService} from '../workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../workflows/workflow-registry.service';
import {normalizeWorkflowApprovalPolicy} from '../workflows/workflow-approval-policy';
import type {WorkflowHandlerInput,WorkflowPlanV1,WorkflowReceipt} from '../workflows/workflow.types';
import {EntityAnnotationBusinessService} from './entity-annotation-business.service';
import {annotationNativePermitted} from './entity-annotation-authorization';
import {assertEntityAnnotationPlan,normalizeAnnotationChangeRequest} from './entity-annotation-workflow-plan';
import type {AnnotationBusinessMutation,AnnotationCapturedChange,AnnotationMetadataPayload,AnnotationWorkflowIntent,AnnotationWorkflowScope,EntityAnnotationApprovedDelegate,EntityAnnotationCompletionDelegate} from './entity-annotation-workflow.types';
const deny=(code:string)=>new ForbiddenException({code}),changed=(code:string)=>new ConflictException({code});
const aad=(id:string)=>`annotation-workflow:${id}:intent`,resultAad=(id:string)=>`annotation-workflow:${id}:result`;
interface ExecutionState {active:boolean;intent:Readonly<AnnotationWorkflowIntent>;plan:WorkflowPlanV1;input:WorkflowHandlerInput;tx:DbService;actorId:string;sessionId:string;frameSessionId:string|null;scheduledClaimId:string|null;permissionVersion:string;
 captureVerified:boolean;beforeVerified:boolean;afterVerified:boolean;after?:Readonly<EntityAnnotationRow>;resultHmac?:string;factId?:string;}

/** A metadata-only approval domain. Original entity/annotation grants and
 * native identity are independently checked; an approved intent never grants
 * a native write, another SID, or authority to select a SQL transaction. */
@Injectable()
export class EntityAnnotationWorkflowService implements OnModuleInit {
 private readonly executions=new WeakMap<object,ExecutionState>();
 private readonly completions=new WeakMap<object,Readonly<{state:ExecutionState;resultHmac:string}>>();
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
  private readonly audit:AuditService,private readonly context:KongExecutionContextService,private readonly business:EntityAnnotationBusinessService,
  private readonly plans:WorkflowPlansService,private readonly registry:WorkflowRegistryService){}
 onModuleInit():void {
  this.business.installApprovedPolicy({verifyCapture:(h,c,a,tx)=>this.verifyCapture(h,c,a,tx),verifyMutation:(h,m,p,tx,r,after,audit)=>this.verifyMutation(h,m,p,tx,r,after,audit)});
  this.registry.register('entity.annotation',{authorize:(p,a,action)=>this.assertWorkflowAdmission(p,a,action),prepare:i=>this.assertWorkflowAdmission(i.plan,i.actor,'write'),
   inspect:async(i,tx)=>{const intent=await this.bound(i.plan,tx);return {before:await this.business.readAnnotation(intent.capture,tx),revision:this.revision(intent)};},apply:i=>this.apply(i)});
 }
 approvedDelegate():Readonly<EntityAnnotationApprovedDelegate>{return Object.freeze({verifyIntent:(p:WorkflowPlanV1,tx?:DbService)=>this.verifyIntent(p,tx),
  assertSubject:async(p:WorkflowPlanV1,id:string,action:'read'|'write'|'approve',tx?:DbService)=>{const f=this.context.current();
   if(f.actor?.id!==id)throw deny('ANNOTATION_ACTOR_CONTEXT_REQUIRED');
   const actor={user:f.actor,workspaceId:f.workspaceId,requestId:f.requestId,ip:f.ip};
   if(!f.sessionId&&!this.scheduled(actor))throw deny('ANNOTATION_ACTOR_CONTEXT_REQUIRED');
   await this.assertWorkflowAdmission(p,actor,action,tx);},
  verifyReviewer:(id:string,p:WorkflowPlanV1,tx?:DbService)=>this.verifyReviewer(id,p,tx),
  assertWorkflowAdmission:(p:WorkflowPlanV1,a:EntityActor,action:'read'|'write'|'approve',tx?:DbService)=>this.assertWorkflowAdmission(p,a,action,tx)});}
 completionDelegate():Readonly<EntityAnnotationCompletionDelegate>{return Object.freeze({verifyMetadataCompletion:(i:WorkflowHandlerInput,r:Record<string,unknown>,pv:string)=>this.verifyMetadataCompletion(i,r,pv),
  terminalReceipt:(p:WorkflowPlanV1,a:EntityActor)=>this.terminalReceipt(p,a),reviewPreview:(p:WorkflowPlanV1,a:EntityActor)=>this.reviewPreview(p,a)});}
 private actor(a:EntityActor):string {const f=this.context.current();if(f.actor?.id!==a.user.id||!f.sessionId||f.operation||f.archive||this.context.hasWorkflowScheduledNamespace())throw deny('ANNOTATION_HTTP_ACTOR_REQUIRED');return f.sessionId;}
 /** Scheduled execution identity (SQL042, owner decision 2026-10-24). Only inside the original
  * scheduled namespace of an entity-annotation claim, never for HTTP. The "session" is the
  * requester's authoring-session snapshot recorded on the intent: same user, same current
  * credential epoch; liveness of that HTTP session is not required. Active status, credential and
  * permission/iam versions are rechecked live by every caller (assertCurrent/identity). */
 private scheduled(a:EntityActor):Readonly<{claimId:string;workflowId:string;planHash:string}>|null {const f=this.context.current();
  if(f.sessionId||!this.context.hasWorkflowScheduledNamespace())return null;
  const ns=this.context.requireWorkflowScheduledCurrentPrincipal(this.context.requireWorkflowScheduledNamespaceHandle()).namespace;
  if((ns.kind as string)!=='entity-annotation'||ns.sessionId!==null||ns.actor.id!==a.user.id||f.actor?.id!==a.user.id||f.operation||f.archive)throw deny('ANNOTATION_SCHEDULED_ACTOR_REQUIRED');
  return Object.freeze({claimId:ns.claim.id,workflowId:ns.workflow.id,planHash:ns.workflow.planHash});}
 private async executionSession(a:EntityActor,i:Readonly<AnnotationWorkflowIntent>,plan:WorkflowPlanV1|null,tx:DbService):Promise<string> {const sched=this.scheduled(a);if(!sched)return this.liveSession(a,tx);
  if(a.user.id!==i.actorId||plan&&(sched.workflowId!==plan.workflowId||sched.planHash!==this.secrets.fingerprint(plan)))throw deny('ANNOTATION_SCHEDULED_ACTOR_REQUIRED');
  if(!await tx.one(`SELECT s.id FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2 AND s.credential_epoch=u.credential_epoch
   AND u.credential_epoch::text=$3 AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change FOR SHARE OF u`,[i.authoringSessionId,a.user.id,String(i.credentialEpoch)]))throw deny('ANNOTATION_SCHEDULED_REQUESTER_REVOKED');
  return i.authoringSessionId;}
 private selected(cid:string,wid:string,a:EntityActor):void {const f=this.context.current();if(a.workspaceId!==wid||f.workspaceId!==undefined&&f.workspaceId!==wid||f.clusterId!==undefined&&f.clusterId!==cid)throw deny('ANNOTATION_SCOPE_SELECTOR_DENIED');}
 private key(a:EntityActor):string {if(typeof a.idempotencyKey!=='string'||!/^[A-Za-z\d_.:-]{1,128}$/.test(a.idempotencyKey))throw changed('INVALID_IDEMPOTENCY_KEY');return a.idempotencyKey;}
 private async liveSession(a:EntityActor,tx:DbService):Promise<string> {const sid=this.actor(a);if(!await tx.one(`SELECT s.id FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2
  AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.credential_epoch=u.credential_epoch AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change`,[sid,a.user.id]))throw deny('ANNOTATION_SESSION_REVOKED');return sid;}
 private async identity(id:string,tx:DbService) {const row=await tx.one<any>("SELECT * FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change",[iamId(id)]),epoch=await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
  if(!row||!epoch)throw deny('ANNOTATION_PRINCIPAL_REVOKED');return {row,grants:(await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[id])).filter(validGrant),version:`${row.id}:${row.permissions_epoch}:${epoch.version}`};}
 private revision(i:Readonly<AnnotationWorkflowIntent>):number{return Number(i.capture.before?.revision??0);}
 private async scope(capture:Readonly<AnnotationCapturedChange>,tx:DbService):Promise<Readonly<AnnotationWorkflowScope>> {const m=capture.mutation,
  c=await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[m.clusterId]),w=await tx.one<any>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2 FOR SHARE',[m.clusterId,m.workspaceId]);
  if(!c||c.status==='disabled'||c.execution_mode!=='approval'||!w||w.status!=='active'||w.deleted_at)throw changed('ANNOTATION_APPROVAL_SCOPE_REQUIRED');
  return immutableJson({clusterId:c.id,workspaceId:w.id,transportScope:transportScopeFor(c.admin_url,c.transport_scope),clusterRevision:c.revision,workspaceRevision:w.revision,executionMode:'approval'});}
 private whole(grants:any[],superAdmin:boolean,module:string,action:'read'|'write'|'approve',cid:string,wid:string):boolean {
  return superAdmin||grants.some(g=>coarseGrantMatches(g,module,action,{clusterId:cid,workspaceId:wid})&&(g.scope_type==='global'&&g.workspace_id===null||g.scope_type==='workspace'&&g.cluster_id===cid&&g.workspace_id===wid&&g.scope_values.length===1&&g.scope_values[0]===wid));}
 private async assertCurrent(i:Readonly<AnnotationWorkflowIntent>,id:string,role:'requester'|'reader'|'reviewer',tx:DbService):Promise<void> {const identity=await this.identity(id,tx),s=i.scope,m=i.capture.mutation,admin=identity.row.super_admin===true,
  action=role==='requester'?m.action:'read';
  if(role==='requester'&&(id!==i.actorId||String(identity.row.credential_epoch)!==i.credentialEpoch||identity.version!==i.permissionVersion))throw deny('ANNOTATION_REQUESTER_REVOKED');
  if(this.secrets.fingerprint(await this.scope(i.capture,tx))!==this.secrets.fingerprint(s))throw changed('ANNOTATION_SCOPE_CHANGED');
  if(!this.whole(identity.grants,admin,'workflows',role==='requester'?'write':role==='reviewer'?'approve':'read',s.clusterId,s.workspaceId))throw deny('ANNOTATION_WORKFLOW_SCOPE_DENIED');
  if(!admin&&!identity.grants.some(g=>grantMatchesEntity(g,'annotations',action,{clusterId:s.clusterId,workspaceId:s.workspaceId,entityType:m.entityType,entity:i.capture.nativeProof.root.entity})))throw deny('ANNOTATION_METADATA_SCOPE_DENIED');
  if(!annotationNativePermitted(identity.grants,admin,s.clusterId,i.capture.nativeProof,action))throw deny('ANNOTATION_NATIVE_SCOPE_DENIED');
 }
 private async load(id:string,tx=this.db):Promise<Readonly<AnnotationWorkflowIntent>> {const r=await tx.one<any>('SELECT * FROM annotation_change_intents WHERE id=$1',[iamId(id)]);if(!r)throw new NotFoundException({code:'ANNOTATION_CHANGE_INTENT_NOT_FOUND'});
  const i=immutableJson(this.secrets.decrypt<AnnotationWorkflowIntent>(r.material_secret,aad(r.id))),m=i.capture?.mutation,p=i.capture?.nativeProof;
  if(i.version!==1||i.id!==r.id||i.actorId!==r.actor_id||i.authoringSessionId!==r.authoring_session_id||i.workflowId!==r.workflow_id||i.scope.clusterId!==r.cluster_id||i.scope.workspaceId!==r.workspace_id
   ||i.idempotencyKey!==r.idempotency_key||i.workflowKey!==`annotation-${i.id}`||i.requestHmac!==r.request_hmac||i.permissionVersion!==r.permission_version||i.credentialEpoch!==String(r.credential_epoch)
   ||this.secrets.fingerprint(i)!==r.material_hmac||this.secrets.fingerprint(normalizeAnnotationChangeRequest(i.capture.request))!==i.requestHmac||m.clusterId!==r.cluster_id||m.workspaceId!==r.workspace_id
   ||m.entityType!==r.entity_type||m.entityId!==r.entity_id||m.operation!==r.operation||m.action!==(m.operation==='remove'?'delete':'write')||this.revision(i)!==r.before_revision
   ||this.secrets.fingerprint(i.capture.before)!==r.before_config_hmac||this.secrets.fingerprint(p)!==r.native_proof_hmac||p.root.entityType!==m.entityType||p.root.entity.id!==m.entityId||p.root.workspaceId!==m.workspaceId
   ||this.secrets.fingerprint(p.root.entity)!==this.secrets.fingerprint(m.entity)||!p.routesComplete||!Array.isArray(p.parents)||!Array.isArray(p.serviceRoutes)||p.parents.length>16||p.serviceRoutes.length>800
   ||!Number.isFinite(Date.parse(i.issuedAt))||!Number.isFinite(Date.parse(i.expiresAt))||Date.parse(i.expiresAt)<=Date.parse(i.issuedAt)||Date.parse(i.expiresAt)>Date.parse(i.issuedAt)+86400000
   ||new Date(r.issued_at).getTime()!==Date.parse(i.issuedAt)||new Date(r.expires_at).getTime()!==Date.parse(i.expiresAt))throw changed('ANNOTATION_INTENT_INVALID');return i;}
 private async definition(s:Readonly<AnnotationWorkflowScope>,actorId:string,tx:DbService) {await this.plans.definitions(s.clusterId,s.workspaceId,actorId,tx);
  const definition=await this.plans.definition(s.clusterId,s.workspaceId,'entity-annotation',tx),r=await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[s.clusterId,s.workspaceId,definition.id,definition.version]);
  if(r?.approval_format!==2||this.secrets.fingerprint(r.policy)!==definition.policyHash)throw changed('ANNOTATION_V2_POLICY_REQUIRED');return {definition,policy:normalizeWorkflowApprovalPolicy(r.policy,'entity-annotation')};}
 async prepare(clusterId:string,workspaceId:string,raw:unknown,actor:EntityActor):Promise<Record<string,unknown>> {clusterId=iamId(clusterId).toLowerCase();workspaceId=iamId(workspaceId).toLowerCase();this.selected(clusterId,workspaceId,actor);
  const request=normalizeAnnotationChangeRequest(raw),sid=this.actor(actor),key=this.key(actor),requestHmac=this.secrets.fingerprint(request);
  return this.redis.withLock(`annotation-change:${actor.user.id}:${key}`,()=>this.db.transaction(async tx=>{await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');await this.liveSession(actor,tx);
   const prior=await tx.one<any>('SELECT id,cluster_id,workspace_id,request_hmac FROM annotation_change_intents WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
   if(prior){if(prior.cluster_id!==clusterId||prior.workspace_id!==workspaceId||prior.request_hmac!==requestHmac)throw changed('IDEMPOTENCY_CONFLICT');return this.receipt(clusterId,workspaceId,prior.id,actor,tx);}
   if(await tx.one('SELECT id FROM mutation_operations WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]))throw changed('IDEMPOTENCY_CONFLICT');
   const capture=await this.business.capture(request,clusterId,actor,workspaceId,tx),scope=await this.scope(capture,tx),identity=await this.identity(actor.user.id,tx),{policy}=await this.definition(scope,actor.user.id,tx),
    session=await tx.one<any>('SELECT expires_at FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp() AND credential_epoch=$3',[sid,actor.user.id,identity.row.credential_epoch]);
   if(!session)throw deny('ANNOTATION_SESSION_REVOKED');const id=randomUUID(),now=Date.now(),intent:Readonly<AnnotationWorkflowIntent>=immutableJson({version:1,id,workflowId:randomUUID(),actorId:actor.user.id,authoringSessionId:sid,credentialEpoch:String(identity.row.credential_epoch),permissionVersion:identity.version,
    idempotencyKey:key,workflowKey:`annotation-${id}`,requestHmac,issuedAt:new Date(now).toISOString(),expiresAt:new Date(Math.min(now+86400000,now+policy.intentTtlHours*3600000,new Date(session.expires_at).getTime())).toISOString(),capture,scope});
   await this.assertCurrent(intent,actor.user.id,'requester',tx);
   await tx.exec(`INSERT INTO annotation_change_intents(id,cluster_id,workspace_id,actor_id,authoring_session_id,workflow_id,idempotency_key,request_hmac,material_hmac,material_secret,credential_epoch,permission_version,entity_type,entity_id,operation,before_revision,before_config_hmac,native_proof_hmac,issued_at,expires_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,[id,clusterId,workspaceId,actor.user.id,sid,intent.workflowId,key,requestHmac,this.secrets.fingerprint(intent),this.secrets.encrypt(intent,aad(id)),intent.credentialEpoch,intent.permissionVersion,request.entityType,request.entityId,request.operation,this.revision(intent),this.secrets.fingerprint(capture.before),this.secrets.fingerprint(capture.nativeProof),intent.issuedAt,intent.expiresAt]);
   await this.audit.append({actorId:actor.user.id,clusterId,workspaceId,entityType:'annotation_change_intents',entityId:id,action:'annotation.change.prepare',after:{entityType:request.entityType,entityId:request.entityId,operation:request.operation,materialHmac:this.secrets.fingerprint(intent),nativeRequestsSent:0},requestId:actor.requestId,ip:actor.ip},tx);
   await this.redis.assertLeaseOwnership();return this.receipt(clusterId,workspaceId,id,actor,tx);
  }));}
 private async bound(plan:WorkflowPlanV1,tx=this.db):Promise<Readonly<AnnotationWorkflowIntent>> {const step=assertEntityAnnotationPlan(this.interactive(plan)),p=step.metadata as AnnotationMetadataPayload,i=await this.load(p.intentId,tx),r=await tx.one<any>('SELECT * FROM entity_annotation_requests WHERE id=$1 AND workflow_id=$2 AND cluster_id=$3 AND workspace_id=$4',[i.id,plan.workflowId,plan.clusterId,plan.workspaceId]);
  if(!r||i.workflowId!==plan.workflowId||i.actorId!==plan.requester.id||i.scope.clusterId!==plan.clusterId||i.scope.workspaceId!==plan.workspaceId||r.actor_id!==i.actorId||r.material_hmac!==this.secrets.fingerprint(i)||p.materialHmac!==r.material_hmac
   ||p.entityType!==i.capture.request.entityType||p.entityId!==i.capture.request.entityId||p.operation!==i.capture.request.operation||r.idempotency_key!==i.workflowKey||r.request_hmac!==i.requestHmac||plan.expiresAt!==i.expiresAt||plan.issuedAt!==i.issuedAt
   ||this.secrets.fingerprint(step.before)!==this.secrets.fingerprint(i.capture.before)||step.metadataBeforeHmac!==this.secrets.fingerprint(i.capture.before)||step.metadataPayloadHmac!==this.secrets.fingerprint(p)||step.metadataRevision!==this.revision(i)
   ||this.secrets.fingerprint(plan.scope)!==this.secrets.fingerprint({transportScope:i.scope.transportScope,clusterRevision:i.scope.clusterRevision,workspaceRevision:i.scope.workspaceRevision}))throw changed('ANNOTATION_BINDING_INVALID');return i;}
 /** A sealed scheduling block is admitted only inside the matching scheduled namespace. */
 private interactive(plan:WorkflowPlanV1):WorkflowPlanV1 {if((plan as any)?.scheduling===undefined)return plan;const f=this.context.peek();
  if(!f||f.sessionId||!this.context.hasWorkflowScheduledNamespace())throw changed('ANNOTATION_BINDING_INVALID');
  const ns=this.context.requireWorkflowScheduledCurrentPrincipal(this.context.requireWorkflowScheduledNamespaceHandle()).namespace;
  if((ns.kind as string)!=='entity-annotation'||ns.workflow.id!==plan.workflowId||ns.workflow.planHash!==this.secrets.fingerprint(plan))throw changed('ANNOTATION_BINDING_INVALID');
  const {scheduling:_sealed,...rest}=plan as any;return rest;}
 async verifyIntent(plan:WorkflowPlanV1,tx=this.db):Promise<void>{await this.bound(plan,tx);}
 async verifyReviewer(id:string,plan:WorkflowPlanV1,tx=this.db):Promise<void>{const i=await this.bound(plan,tx);await this.assertCurrent(i,id,id===i.actorId?'requester':'reviewer',tx);}
 async assertWorkflowAdmission(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve',tx=this.db):Promise<void> {const i=await this.bound(plan,tx);this.selected(plan.clusterId,plan.workspaceId,actor);
  const sid=await this.executionSession(actor,i,plan,tx);if(this.scheduled(actor)&&action!=='write')throw deny('ANNOTATION_SCHEDULED_ACTOR_REQUIRED');if(action==='write'&&(actor.user.id!==i.actorId||sid!==i.authoringSessionId))throw deny('ANNOTATION_AUTHOR_MISMATCH');if(action!=='read'&&Date.parse(i.expiresAt)<=Date.now())throw changed('ANNOTATION_INTENT_EXPIRED');
  await this.assertCurrent(i,actor.user.id,action==='write'?'requester':action==='approve'?'reviewer':'reader',tx);
  const proof=await this.business.observe(i.capture,actor,action==='write'?i.capture.mutation.action:'read',tx);
  if(this.secrets.fingerprint(proof)!==this.secrets.fingerprint(i.capture.nativeProof))throw changed('ANNOTATION_NATIVE_MATERIAL_CHANGED');
  if(action!=='read'&&this.secrets.fingerprint(await this.business.readAnnotation(i.capture,tx))!==this.secrets.fingerprint(i.capture.before))throw changed('ANNOTATION_METADATA_CHANGED');
 }
 async submit(clusterId:string,workspaceId:string,id:string,raw:unknown,actor:EntityActor):Promise<Record<string,unknown>> {clusterId=iamId(clusterId).toLowerCase();workspaceId=iamId(workspaceId).toLowerCase();this.selected(clusterId,workspaceId,actor);
  const v=iamBody(raw,['confirmed','materialHmac']);if(v.confirmed!==true||typeof v.materialHmac!=='string')throw changed('CONFIRMATION_REQUIRED');const sid=this.actor(actor),key=this.key(actor);
  return this.redis.withLock(`annotation-change-submit:${id}`,()=>this.db.transaction(async tx=>{await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');await this.liveSession(actor,tx);const i=await this.load(id,tx);
   if(i.actorId!==actor.user.id||i.authoringSessionId!==sid||i.scope.clusterId!==clusterId||i.scope.workspaceId!==workspaceId)throw deny('ANNOTATION_AUTHOR_MISMATCH');
   const r=await tx.one<any>('SELECT submit_key,material_hmac FROM entity_annotation_requests WHERE id=$1',[id]);if(r){if(r.submit_key!==key||r.material_hmac!==v.materialHmac)throw changed('IDEMPOTENCY_CONFLICT');return this.receipt(clusterId,workspaceId,id,actor,tx);}
   if(Date.parse(i.expiresAt)<=Date.now()||v.materialHmac!==this.secrets.fingerprint(i))throw changed('ANNOTATION_INTENT_EXPIRED_OR_CHANGED');await this.assertCurrent(i,actor.user.id,'requester',tx);
   const capture=await this.business.capture(i.capture.request,clusterId,actor,workspaceId,tx);if(this.secrets.fingerprint(capture)!==this.secrets.fingerprint(i.capture))throw changed('ANNOTATION_CURRENT_MATERIAL_CHANGED');
   const {definition,policy}=await this.definition(i.scope,actor.user.id,tx);if(Date.parse(i.expiresAt)>Date.parse(i.issuedAt)+policy.intentTtlHours*3600000)throw changed('ANNOTATION_POLICY_TTL_CHANGED');
   const s=i.scope,payload:AnnotationMetadataPayload={intentId:id,entityType:i.capture.request.entityType,entityId:i.capture.request.entityId,operation:i.capture.request.operation,materialHmac:this.secrets.fingerprint(i)};
   await tx.exec(`INSERT INTO entity_annotation_requests(id,cluster_id,workspace_id,actor_id,workflow_id,idempotency_key,submit_key,request_hmac,material_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[id,clusterId,workspaceId,actor.user.id,i.workflowId,i.workflowKey,key,i.requestHmac,this.secrets.fingerprint(i)]);
   const plan:WorkflowPlanV1={version:1,kind:'entity-annotation',clusterId,workspaceId,workflowId:i.workflowId,planRevision:1,executionMode:'approval',approvalRequired:true,subject:{type:'entity_annotation_requests',id},requester:{type:'console',id:actor.user.id},definition,
    issuedAt:i.issuedAt,expiresAt:i.expiresAt,scope:{transportScope:s.transportScope,clusterRevision:s.clusterRevision,workspaceRevision:s.workspaceRevision},prerequisites:[],steps:[{id:randomUUID(),key:'entity.annotation',order:1,kind:'metadata',handler:'entity.annotation',entityType:'entity_annotation_requests',entityId:id,permissionAction:i.capture.mutation.action,
    dependencies:[],nativeRequests:[],before:i.capture.before,metadataRevision:this.revision(i),metadataBeforeHmac:this.secrets.fingerprint(i.capture.before),metadata:payload,metadataPayloadHmac:this.secrets.fingerprint(payload)}]};
   await this.plans.persist(plan,i.workflowKey,i.capture.request,tx,{requestId:actor.requestId,ip:actor.ip});await this.redis.assertLeaseOwnership();return this.receipt(clusterId,workspaceId,id,actor,tx);
  }));}
 private async terminalFact(i:Readonly<AnnotationWorkflowIntent>,hash:string,tx:DbService):Promise<any> {return tx.one<any>(`SELECT f.*,e.idempotency_key AS execution_key,w.revision FROM annotation_workflow_mutation_facts f JOIN workflows w ON w.id=f.workflow_id
  JOIN workflow_executions e ON e.id=f.execution_id JOIN workflow_steps s ON s.id=f.step_id JOIN audit_events a ON a.id=f.audit_id
  WHERE f.intent_id=$1 AND f.workflow_id=$2 AND f.actor_id=$3 AND f.session_id=$4 AND f.plan_hash=$5 AND f.cluster_id=$6 AND f.workspace_id=$7
   AND w.kind='entity-annotation' AND w.subject_type='entity_annotation_requests' AND w.subject_id=f.intent_id AND w.state='succeeded' AND e.state='succeeded' AND s.state='succeeded'
   AND e.workflow_id=w.id AND s.workflow_id=w.id AND e.plan_hash=w.plan_hash AND s.plan_hash=w.plan_hash AND e.plan_revision=w.plan_revision AND s.plan_revision=w.plan_revision
   AND e.plan_hash=f.plan_hash AND e.plan_revision=f.plan_revision AND e.execution_actor_id=f.actor_id AND e.approval_format=2 AND e.approval_set_id=w.approval_set_id AND e.approval_set_hmac=w.approval_set_hmac
   AND s.handler='entity.annotation' AND s.kind='metadata' AND s.native_requests='[]'::jsonb AND a.actor_id=f.actor_id AND a.actor_type='user' AND a.cluster_id=f.cluster_id AND a.workspace_id=f.workspace_id
   AND a.entity_type=f.entity_type AND a.entity_id=f.entity_id::text AND a.action=f.audit_action AND a.workflow_id=w.id AND a.result='success'`,[i.id,i.workflowId,i.actorId,i.authoringSessionId,hash,i.scope.clusterId,i.scope.workspaceId]);}
 async receipt(clusterId:string,workspaceId:string,id:string,a:EntityActor,tx=this.db):Promise<Record<string,unknown>> {clusterId=iamId(clusterId).toLowerCase();workspaceId=iamId(workspaceId).toLowerCase();this.selected(clusterId,workspaceId,a);
  const i=await this.load(id,tx),sid=await this.liveSession(a,tx);if(i.actorId!==a.user.id||i.authoringSessionId!==sid||i.scope.clusterId!==clusterId||i.scope.workspaceId!==workspaceId)throw deny('ANNOTATION_INTENT_OWNER_REQUIRED');
  await this.assertCurrent(i,a.user.id,'requester',tx);const observed=await this.business.observe(i.capture,a,'read',tx);if(this.secrets.fingerprint(observed)!==this.secrets.fingerprint(i.capture.nativeProof))throw changed('ANNOTATION_NATIVE_MATERIAL_CHANGED');const r=await tx.one<any>('SELECT workflow_id FROM entity_annotation_requests WHERE id=$1',[id]),w=r?await tx.one<any>('SELECT id,state,revision,plan_hash FROM workflows WHERE id=$1',[r.workflow_id]):null;
  if(w?.state==='succeeded'&&!await this.terminalFact(i,w.plan_hash,tx))throw deny('ANNOTATION_TERMINAL_FACT_REQUIRED');
  return {intentId:i.id,entityType:i.capture.request.entityType,entityId:i.capture.request.entityId,operation:i.capture.request.operation,materialHmac:this.secrets.fingerprint(i),state:w?.state??'prepared',workflowId:w?.id??null,
   revision:w?.revision??null,annotationRevision:this.revision(i),planHash:w?.plan_hash??null,clusterId,workspaceId,expiresAt:i.expiresAt,nativeRequestsSent:0,nativeExecutionAvailable:false,capabilities:{submit:!w&&Date.parse(i.expiresAt)>Date.now()&&this.secrets.fingerprint(await this.business.readAnnotation(i.capture,tx))===this.secrets.fingerprint(i.capture.before)},preview:await this.preview(i,a,tx)};}
 async receiptByKey(cid:string,wid:string,key:string,a:EntityActor):Promise<Record<string,unknown>> {this.selected(cid,wid,a);await this.liveSession(a,this.db);this.key({...a,idempotencyKey:key});
  const r=await this.db.one<any>('SELECT id FROM annotation_change_intents WHERE actor_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND idempotency_key=$4',[a.user.id,iamId(cid),iamId(wid),key]);if(!r)throw new NotFoundException({code:'ANNOTATION_CHANGE_INTENT_NOT_FOUND'});return this.receipt(cid,wid,r.id,a);}
 private async preview(i:Readonly<AnnotationWorkflowIntent>,a:EntityActor,tx:DbService):Promise<Record<string,unknown>> {await this.assertCurrent(i,a.user.id,'reader',tx);const m=i.capture.mutation;
  return {request:this.secrets.redact(i.capture.request),before:this.secrets.redact(i.capture.before),after:{entityType:m.entityType,entityId:m.entityId,operation:m.operation,input:this.secrets.redact(m.input)},
   affectedScopes:[{clusterId:i.scope.clusterId,workspaceId:i.scope.workspaceId,clusterRevision:i.scope.clusterRevision,workspaceRevision:i.scope.workspaceRevision}],confirmationName:String(m.entity.name||m.entity.username||m.entity.id),retentionDays:m.retentionDays};}
 async reviewPreview(p:WorkflowPlanV1,a:EntityActor):Promise<Record<string,unknown>> {const i=await this.bound(p);await this.assertWorkflowAdmission(p,a,'read');const preview=await this.preview(i,a,this.db),s=assertEntityAnnotationPlan(p);
  return {diff:[{id:s.id,kind:'metadata',operation:i.capture.request.operation,entityType:i.capture.request.entityType,entityId:i.capture.request.entityId,before:preview.before,after:preview.after}],affectedScopes:preview.affectedScopes};}
 private execution(h:object):ExecutionState {const s=this.executions.get(h);if(!s?.active||Date.parse(s.intent.expiresAt)<=Date.now())throw deny('ANNOTATION_ORIGINAL_EXECUTION_REQUIRED');return s;}
 private async running(s:ExecutionState,tx:DbService):Promise<void> {const {plan,input}=s,f=this.context.current(),step=this.context.currentApprovedStep();
  if(f.actor?.id!==s.actorId||(f.sessionId??null)!==s.frameSessionId||step.kind!=='metadata'||step.stepId!==input.step.id||step.execution.executionId!==input.executionId||step.execution.workflowId!==plan.workflowId||step.execution.actorId!==s.actorId||(step.execution.sessionId??null)!==s.frameSessionId||s.tx!==tx||input.transaction!==tx)throw deny('ANNOTATION_ORIGINAL_EXECUTION_REQUIRED');
  if(!await tx.one(`SELECT e.id FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id JOIN workflow_steps s ON s.workflow_id=w.id WHERE e.id=$1 AND w.id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4 AND e.state='executing' AND w.state='executing' AND e.execution_actor_id=$5
   AND e.approval_format=2 AND e.approval_set_id=w.approval_set_id AND e.approval_set_hmac=w.approval_set_hmac AND s.id=$6 AND s.state='running' AND s.handler='entity.annotation' AND s.kind='metadata' AND s.native_requests='[]'::jsonb
   AND e.plan_hash=$7 AND e.plan_revision=$8 AND w.plan_hash=e.plan_hash AND w.plan_revision=e.plan_revision AND s.plan_hash=e.plan_hash AND s.plan_revision=e.plan_revision`,[input.executionId,plan.workflowId,plan.clusterId,plan.workspaceId,s.actorId,input.step.id,this.secrets.fingerprint(plan),plan.planRevision]))throw deny('ANNOTATION_APPROVED_EXECUTION_REQUIRED');}
 private async apply(input:WorkflowHandlerInput):Promise<Record<string,unknown>> {const {plan,actor,transaction:tx}=input,i=await this.bound(plan,tx);await this.assertWorkflowAdmission(plan,actor,'write',tx);
  await this.context.assertApprovedMetadataStep({handler:'entity.annotation',actor:actor.user,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'entity_annotation_requests',entityId:i.id,before:i.capture.before,revision:this.revision(i),payload:input.step.metadata},tx);
  const identity=await this.identity(actor.user.id,tx),h=Object.freeze({}),state:ExecutionState={active:true,intent:i,plan:immutableJson(plan),input,tx,actorId:actor.user.id,...(()=>{const sched=this.scheduled(actor);return sched?{sessionId:i.authoringSessionId,frameSessionId:null,scheduledClaimId:sched.claimId}:{sessionId:this.actor(actor),frameSessionId:this.actor(actor),scheduledClaimId:null};})(),permissionVersion:identity.version,captureVerified:false,beforeVerified:false,afterVerified:false};this.executions.set(h,state);
  try {const entity=await this.business.apply(h,i.capture,actor,tx);if(!state.afterVerified||!state.factId||state.resultHmac!==this.secrets.fingerprint(entity))throw deny('ANNOTATION_RESULT_UNACKNOWLEDGED');
   const result=immutableJson({intentId:i.id,entityType:i.capture.request.entityType,entityId:i.capture.request.entityId,operation:i.capture.request.operation,nativeRequestsSent:0});this.completions.set(result,Object.freeze({state,resultHmac:this.secrets.fingerprint(result)}));return result;
  }finally{state.active=false;this.executions.delete(h);}}
 private async verifyCapture(h:object,c:Readonly<AnnotationCapturedChange>,a:EntityActor,tx:DbService):Promise<Readonly<{workflowId:string}>> {const s=this.execution(h);await this.running(s,tx);
  if(s.captureVerified||a.user.id!==s.actorId||this.secrets.fingerprint(c)!==this.secrets.fingerprint(s.intent.capture))throw deny('ANNOTATION_CAPTURE_MISMATCH');s.captureVerified=true;return Object.freeze({workflowId:s.plan.workflowId});}
 private auditAction(i:Readonly<AnnotationWorkflowIntent>):string{return i.capture.request.operation==='remove'?'annotation.metadata.deleted':i.capture.request.operation==='restore'?'annotation.metadata.restored':i.capture.before?'annotation.metadata.updated':'annotation.metadata.created';}
 private async verifyMutation(h:object,m:Readonly<AnnotationBusinessMutation>,phase:'before'|'after',tx:DbService,result?:unknown,after?:Readonly<EntityAnnotationRow>|null,audit?:Readonly<AuditOutboxReceipt>):Promise<void> {const s=this.execution(h);await this.running(s,tx);const {actor,...pure}=m;
  if(!s.captureVerified||actor.user.id!==s.actorId||this.secrets.fingerprint(pure)!==this.secrets.fingerprint(s.intent.capture.mutation))throw deny('ANNOTATION_MUTATION_MISMATCH');
  if(phase==='before'){if(s.beforeVerified||s.afterVerified)throw deny('ANNOTATION_FIXED_OPERATION_REQUIRED');await this.assertWorkflowAdmission(s.plan,actor,'write',tx);s.beforeVerified=true;return;}
  if(!s.beforeVerified||s.afterVerified||!after||result===undefined||!audit?.id||after.cluster_id!==m.clusterId||after.entity_type!==m.entityType||after.kong_id!==m.entityId||after.revision!==this.revision(s.intent)+1
   ||this.secrets.fingerprint(result)!==this.secrets.fingerprint(after)||this.secrets.fingerprint(await this.business.readAnnotation(s.intent.capture,tx))!==this.secrets.fingerprint(after))throw changed('ANNOTATION_RESULT_READBACK_MISMATCH');
  if(m.operation==='remove'?after.status!=='deleted'||!after.deleted_at||!after.retention_until:after.status!=='active'||after.deleted_at!==null||after.retention_until!==null)throw changed('ANNOTATION_RESULT_STATE_MISMATCH');
  if(await this.executionSession(actor,s.intent,s.plan,tx)!==s.sessionId)throw deny('ANNOTATION_SESSION_REVOKED');await this.assertCurrent(s.intent,s.actorId,'requester',tx);const identity=await this.identity(s.actorId,tx);if(identity.version!==s.permissionVersion)throw deny('ANNOTATION_PERMISSIONS_CHANGED');
  const factId=randomUUID();await tx.exec(`INSERT INTO annotation_workflow_mutation_facts(id,intent_id,workflow_id,execution_id,step_id,cluster_id,workspace_id,actor_id,session_id,plan_revision,plan_hash,permission_version,before_config_hmac,after_config_hmac,result_hmac,result_secret,native_proof_hmac,audit_id,audit_action,entity_type,entity_id,operation,before_revision,after_revision,execution_origin,schedule_claim_id)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`,[factId,s.intent.id,s.plan.workflowId,s.input.executionId,s.input.step.id,s.plan.clusterId,s.plan.workspaceId,s.actorId,s.sessionId,s.plan.planRevision,this.secrets.fingerprint(s.plan),identity.version,this.secrets.fingerprint(s.intent.capture.before),this.secrets.fingerprint(after),this.secrets.fingerprint(result),this.secrets.encrypt(result,resultAad(factId)),this.secrets.fingerprint(s.intent.capture.nativeProof),audit.id,this.auditAction(s.intent),m.entityType,m.entityId,m.operation,this.revision(s.intent),after.revision,s.scheduledClaimId?'scheduled':'session',s.scheduledClaimId]);
  s.afterVerified=true;s.after=immutableJson(after);s.resultHmac=this.secrets.fingerprint(result);s.factId=factId;}
 async verifyMetadataCompletion(input:WorkflowHandlerInput,result:Record<string,unknown>,beforePermissionVersion:string):Promise<void> {const completion=result&&typeof result==='object'?this.completions.get(result):undefined;if(!completion)throw deny('ANNOTATION_ORIGINAL_COMPLETION_REQUIRED');this.completions.delete(result);
  const {state:s}=completion,tx=input.transaction;if(s.input!==input||s.tx!==tx||!s.afterVerified||!s.factId||beforePermissionVersion!==s.permissionVersion||Date.parse(s.intent.expiresAt)<=Date.now()||this.secrets.fingerprint(result)!==completion.resultHmac
   ||this.secrets.fingerprint(input.plan)!==this.secrets.fingerprint(s.plan)||this.secrets.fingerprint(input.step)!==this.secrets.fingerprint(s.plan.steps[0]))throw deny('ANNOTATION_ORIGINAL_COMPLETION_REQUIRED');
  if(await this.executionSession(input.actor,s.intent,s.plan,tx)!==s.sessionId)throw deny('ANNOTATION_SESSION_REVOKED');await this.running(s,tx);await this.bound(input.plan,tx);await this.assertCurrent(s.intent,s.actorId,'requester',tx);
  const f=await tx.one<any>(`SELECT f.*,a.actor_id AS audit_actor,a.cluster_id AS audit_cluster,a.workspace_id AS audit_workspace,a.entity_type AS audit_type,a.entity_id AS audit_entity,a.action AS actual_audit_action,a.workflow_id AS audit_workflow,a.result AS audit_result
   FROM annotation_workflow_mutation_facts f JOIN audit_events a ON a.id=f.audit_id WHERE f.id=$1 AND f.intent_id=$2 AND f.workflow_id=$3 AND f.execution_id=$4 AND f.step_id=$5`,[s.factId,s.intent.id,s.plan.workflowId,input.executionId,input.step.id]),m=s.intent.capture.mutation,identity=await this.identity(s.actorId,tx);
  if(!f||f.actor_id!==s.actorId||f.session_id!==s.sessionId||f.execution_origin!==(s.scheduledClaimId?'scheduled':'session')||(f.schedule_claim_id??null)!==s.scheduledClaimId||f.cluster_id!==s.plan.clusterId||f.workspace_id!==s.plan.workspaceId||f.plan_hash!==this.secrets.fingerprint(s.plan)||f.plan_revision!==s.plan.planRevision||f.permission_version!==s.permissionVersion||identity.version!==s.permissionVersion
   ||f.entity_type!==m.entityType||f.entity_id!==m.entityId||f.operation!==m.operation||f.before_revision!==this.revision(s.intent)||f.after_revision!==s.after?.revision||f.before_config_hmac!==this.secrets.fingerprint(s.intent.capture.before)||f.after_config_hmac!==this.secrets.fingerprint(s.after)||f.result_hmac!==s.resultHmac
   ||f.native_proof_hmac!==this.secrets.fingerprint(s.intent.capture.nativeProof)||this.secrets.fingerprint(this.secrets.decrypt(f.result_secret,resultAad(s.factId)))!==s.resultHmac||this.secrets.fingerprint(await this.business.readAnnotation(s.intent.capture,tx))!==f.after_config_hmac
   ||f.audit_actor!==s.actorId||f.audit_cluster!==s.plan.clusterId||f.audit_workspace!==s.plan.workspaceId||f.audit_type!==m.entityType||f.audit_entity!==m.entityId||f.audit_action!==this.auditAction(s.intent)||f.actual_audit_action!==f.audit_action||f.audit_workflow!==s.plan.workflowId||f.audit_result!=='success')throw deny('ANNOTATION_COMPLETION_FACTS_CHANGED');
  await this.redis.assertLeaseOwnership();this.context.current();}
 async terminalReceipt(plan:WorkflowPlanV1,a:EntityActor):Promise<WorkflowReceipt> {const i=await this.bound(plan);this.selected(plan.clusterId,plan.workspaceId,a);if(a.user.id!==i.actorId||await this.liveSession(a,this.db)!==i.authoringSessionId)throw deny('ANNOTATION_INTENT_OWNER_REQUIRED');await this.assertCurrent(i,a.user.id,'requester',this.db);
  const row=await this.terminalFact(i,this.secrets.fingerprint(plan),this.db);if(!row)throw deny('ANNOTATION_TERMINAL_RECEIPT_UNAVAILABLE');return {id:row.execution_id,workflowId:plan.workflowId,executionId:row.execution_id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,idempotencyKey:row.execution_key,state:'succeeded',revision:row.revision,planHash:this.secrets.fingerprint(plan),executionMode:'approval',approvalRequired:true,
   steps:[{id:row.step_id,name:'entity.annotation',state:'succeeded',operationId:null,remoteStarted:false,remoteCompleted:true,recycleEntryId:null,errorCode:null}],propagation:'acknowledged'};}
}
