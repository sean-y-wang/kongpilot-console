import {ConflictException,ForbiddenException,Injectable,NotFoundException,OnModuleInit} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import {SecretService} from '../../infrastructure/secret.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {transportScopeFor} from '../../infrastructure/kong/transport-scope';
import {AuditService} from '../audit/audit.service';
import {AuthorizationService} from '../authorization/authorization.service';
import {grantContains,validGrant,coarseGrantMatches} from '../authorization/grant-policy';
import {WorkflowPlansService} from '../workflows/workflow-plans.service';
import {WorkflowRegistryService} from '../workflows/workflow-registry.service';
import {normalizeWorkflowApprovalPolicy} from '../workflows/workflow-approval-policy';
import type {WorkflowHandlerInput,WorkflowPlanV1,WorkflowReceipt} from '../workflows/workflow.types';
import {IamService} from './iam.service';
import {IamMutationsService,type IamMutation} from './iam-mutations.service';
import {iamBody,iamId,type IamActor,type IamScope} from './iam.types';
import {assertIamMetadataPlan,normalizeIamChangeRequest} from './iam-workflow-plan';
import {resolveAssignedGrants} from './iam-policy';
import type {IamWorkflowIntent,IamWorkflowScope,IamCapturedChange,IamMetadataPayload,IamMetadataApprovedDelegate,IamApprovedMutationBinding,IamMetadataCompletionDelegate} from './iam-workflow.types';

const deny=(code:string)=>new ForbiddenException({code}),changed=(code:string)=>new ConflictException({code});
const aad=(id:string)=>`iam-workflow:${id}:intent`;
interface ExecutionState {active:boolean;intent:Readonly<IamWorkflowIntent>;plan:WorkflowPlanV1;input:WorkflowHandlerInput;transaction:DbService;binding:Readonly<IamApprovedMutationBinding>;
 captureVerified:boolean;beforeVerified:boolean;afterVerified:boolean;resultHmac?:string;afterBinding?:Readonly<IamApprovedMutationBinding>;}

/** IAM metadata approvals use the original business rules/SQL and zero Kong
 * packets. An immutable prepared intention precedes its one V2 submission.
 * Execution recognizes only its own short lived original handle. */
@Injectable()
export class IamWorkflowService implements OnModuleInit {
 private readonly executions=new WeakMap<object,ExecutionState>();
 private readonly completions=new WeakMap<object,Readonly<{state:ExecutionState;resultHmac:string}>>();
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,private readonly audit:AuditService,
  private readonly authz:AuthorizationService,private readonly context:KongExecutionContextService,private readonly iam:IamService,
  private readonly mutations:IamMutationsService,private readonly plans:WorkflowPlansService,private readonly registry:WorkflowRegistryService){}
 onModuleInit():void{
  this.iam.installWorkflowApi({prepare:(raw,actor)=>this.prepare(raw,actor),submit:(id,raw,actor)=>this.submit(id,raw,actor),receipt:(id,actor)=>this.receipt(id,actor),receiptByKey:(key,actor)=>this.receiptByKey(key,actor),assertDirectMutation:(context,tx)=>this.assertDirectMutation(context,tx)});
  this.iam.installApprovedChangePolicy({verifyCapture:(handle,capture,actor,tx)=>this.verifyCapture(handle,capture,actor,tx)});
  this.mutations.installApprovedMetadataPolicy({verify:(handle,context,phase,tx,result)=>this.verifyMutation(handle,context,phase,tx,result)});
  this.registry.register('iam.metadata',{authorize:(plan,actor,action)=>this.assertActor(plan,actor,action),prepare:input=>this.prepareExecution(input),
   inspect:async(input,tx)=>{const intent=await this.bound(input.plan,tx);return{before:await this.iam.changeBeforeGraph(intent.capture.request,tx),revision:this.revision(intent)};},
   apply:input=>this.apply(input)});
 }
 approvedDelegate():Readonly<IamMetadataApprovedDelegate>{return Object.freeze({verifyIntent:(plan:WorkflowPlanV1,tx?:DbService)=>this.verifyIntent(plan,tx),
  assertSubject:async(plan:WorkflowPlanV1,id:string,action:'read'|'write'|'approve',tx?:DbService)=>{const frame=this.context.current();
   if(frame.actor?.id!==id)throw deny('IAM_WORKFLOW_ACTOR_CONTEXT_REQUIRED');
   const actor={user:frame.actor,workspaceId:plan.workspaceId,requestId:frame.requestId,ip:frame.ip};
   if(!frame.sessionId&&!this.scheduled(actor))throw deny('IAM_WORKFLOW_ACTOR_CONTEXT_REQUIRED');
   await this.assertActor(plan,actor,action,tx);},
  verifyReviewer:(id:string,plan:WorkflowPlanV1,tx?:DbService)=>this.verifyReviewer(id,plan,tx)});}
 completionDelegate():Readonly<IamMetadataCompletionDelegate>{return Object.freeze({
  verifyMetadataCompletion:(input:WorkflowHandlerInput,result:Record<string,unknown>,before:string)=>this.verifyMetadataCompletion(input,result,before),
  terminalReceipt:(plan:WorkflowPlanV1,actor:IamActor)=>this.terminalReceipt(plan,actor),
  reviewPreview:(plan:WorkflowPlanV1,actor:IamActor)=>this.reviewPreview(plan,actor)});}
 private actor(actor:IamActor):string{const frame=this.context.current();if(frame.actor?.id!==actor.user.id||!frame.sessionId||frame.operation||frame.archive
  ||this.context.hasWorkflowScheduledNamespace())throw deny('IAM_WORKFLOW_HTTP_ACTOR_REQUIRED');return frame.sessionId;}
 /** Scheduled execution identity (SQL043). Authoring-session snapshot; live HTTP session not required. */
 private scheduled(a:IamActor):Readonly<{claimId:string;workflowId:string;planHash:string}>|null{const f=this.context.current();
  if(f.sessionId||!this.context.hasWorkflowScheduledNamespace())return null;
  const ns=this.context.requireWorkflowScheduledCurrentPrincipal(this.context.requireWorkflowScheduledNamespaceHandle()).namespace;
  if((ns.kind as string)!=='iam-metadata'||ns.sessionId!==null||ns.actor.id!==a.user.id||f.actor?.id!==a.user.id||f.operation||f.archive)throw deny('IAM_WORKFLOW_SCHEDULED_ACTOR_REQUIRED');
  return Object.freeze({claimId:ns.claim.id,workflowId:ns.workflow.id,planHash:ns.workflow.planHash});}
 private async executionSession(a:IamActor,i:Readonly<IamWorkflowIntent>,plan:WorkflowPlanV1|null,tx:DbService):Promise<string>{const sched=this.scheduled(a);if(!sched)return this.liveSession(a,tx);
  if(a.user.id!==i.actorId||plan&&(sched.workflowId!==plan.workflowId||sched.planHash!==this.secrets.fingerprint(plan)))throw deny('IAM_WORKFLOW_SCHEDULED_ACTOR_REQUIRED');
  if(!await tx.one(`SELECT s.id FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2 AND s.credential_epoch=u.credential_epoch
   AND u.credential_epoch::text=$3 AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change FOR SHARE OF u`,[i.authoringSessionId,a.user.id,String(i.credentialEpoch)]))throw deny('IAM_WORKFLOW_SCHEDULED_REQUESTER_REVOKED');
  return i.authoringSessionId;}
 private key(actor:IamActor):string{const key=actor.idempotencyKey;if(typeof key!=='string'||!/^[A-Za-z\d_.:-]{1,128}$/.test(key))throw changed('INVALID_IDEMPOTENCY_KEY');return key;}
 private async liveSession(actor:IamActor,tx:DbService):Promise<string>{const sid=this.actor(actor),row=await tx.one<any>(`SELECT s.id FROM auth_sessions s JOIN users u ON u.id=s.user_id
  WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>now() AND s.credential_epoch=u.credential_epoch
   AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change`,[sid,actor.user.id]);if(!row)throw deny('IAM_WORKFLOW_SESSION_REVOKED');return sid;}
 private revision(intent:Readonly<IamWorkflowIntent>):number{return Number((intent.capture.before.resource as any)?.revision??0);}
 private async identity(userId:string,tx:DbService){const row=await tx.one<any>("SELECT * FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change",[iamId(userId)]),epoch=await tx.one<any>('SELECT version FROM iam_epoch WHERE singleton=true');
  if(!row||!epoch)throw deny('IAM_WORKFLOW_PRINCIPAL_REVOKED');const grants=(await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[userId])).filter(validGrant);
  return{row,grants,epoch:String(epoch.version),version:`${row.id}:${row.permissions_epoch}:${epoch.version}`};}
 private whole(grants:any[],superAdmin:boolean,module:string,action:string,scope:IamScope):boolean{return superAdmin||grants.some(g=>coarseGrantMatches(g,module,action as any,{clusterId:scope.cluster_id??undefined,workspaceId:scope.workspace_id??undefined})
  &&(scope.cluster_id===null?g.scope_type==='global'&&g.cluster_id===null&&g.workspace_id===null:g.scope_type==='global'&&g.workspace_id===null
    ||g.scope_type==='workspace'&&scope.workspace_id!==null&&g.cluster_id===scope.cluster_id&&g.workspace_id===scope.workspace_id&&g.scope_values.length===1&&g.scope_values[0]===scope.workspace_id));}
 private async scope(capture:Readonly<IamCapturedChange>,tx:DbService):Promise<Readonly<IamWorkflowScope>>{
  const isBinding=capture.request.operation.startsWith('binding.'),referencesOnly=isBinding||capture.request.operation==='clone',
   teamGrants=capture.request.resource==='teams'?capture.before.bindings.flatMap((b:any)=>{const r:any=capture.before.related.find((v:any)=>v.type==='roles'&&v.row?.id===b.role_id);
    return r?resolveAssignedGrants(r.permissions,{cluster_id:r.row.cluster_id??null,workspace_id:r.row.workspace_id??null},{cluster_id:b.cluster_id??null,workspace_id:b.workspace_id??null}):[];}):[],
   globalPermissions=[...capture.delegatedGrants,...(referencesOnly?[]:capture.request.resource==='teams'?teamGrants:[...capture.before.permissions,...capture.before.related.flatMap((r:any)=>r.permissions??[])])].some((g:any)=>g?.cluster_id===null&&typeof g.module==='string')
    ||isBinding&&capture.affectedScopes.some(s=>s.cluster_id===null)&&capture.before.related.some((r:any)=>r.type==='roles'&&r.row?.builtin_kind==='super-admin');
  const resources=new Map<string,{clusterId:string;workspaceId:string|null}>();
  for(const s of capture.affectedScopes){if(s.cluster_id)resources.set(`${s.cluster_id}:${s.workspace_id}`,{clusterId:s.cluster_id,workspaceId:s.workspace_id});
   else if(globalPermissions){for(const c of await tx.query<any>("SELECT id FROM clusters WHERE deleted_at IS NULL ORDER BY id LIMIT 101"))resources.set(`${c.id}:null`,{clusterId:c.id,workspaceId:null});}}
  if(!resources.size||resources.size>100)throw changed('IAM_WORKFLOW_APPROVAL_SCOPE_REQUIRED');
  const snapshots:IamWorkflowScope['clusterScopes'][number][]=[],approved:IamWorkflowScope['clusterScopes'][number][]=[];
  for(const resource of [...resources.values()].sort((a,b)=>`${a.clusterId}:${a.workspaceId}`.localeCompare(`${b.clusterId}:${b.workspaceId}`))){
   const c=await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL FOR SHARE',[resource.clusterId]);
   const w=resource.workspaceId?await tx.one<any>("SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2 AND status='active' AND deleted_at IS NULL FOR SHARE",[resource.clusterId,resource.workspaceId]):null;
   if(!c||c.status==='disabled'||!/^1\.5\.\d+$/.test(c.version??'')||resource.workspaceId&&!w)throw changed('IAM_WORKFLOW_SCOPE_UNAVAILABLE');
   const snapshot={clusterId:c.id,revision:c.revision,executionMode:c.execution_mode,workspaceId:resource.workspaceId,workspaceRevision:w?.revision??null,transportScope:transportScopeFor(c.admin_url,c.transport_scope)};
   snapshots.push(snapshot);if(c.execution_mode==='approval')approved.push(snapshot);
  }
  if(!approved.length)throw changed('IAM_WORKFLOW_DIRECT_SCOPE');const anchor=approved[0],w=anchor.workspaceId?await tx.one<any>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2',[anchor.clusterId,anchor.workspaceId])
   :await tx.one<any>("SELECT * FROM workspaces WHERE cluster_id=$1 AND is_default=true AND status='active' AND deleted_at IS NULL",[anchor.clusterId]);
  if(!w)throw changed('IAM_WORKFLOW_ANCHOR_WORKSPACE_REQUIRED');return immutableJson({clusterId:anchor.clusterId,workspaceId:w.id,transportScope:anchor.transportScope,
   clusterRevision:anchor.revision,workspaceRevision:w.revision,executionMode:'approval',clusterScopes:snapshots});
 }
 /** Existing direct endpoints cannot use a global owner to hide permissions
  * or bindings affecting an approval cluster. Directory profile/password
  * operations keep their existing console policy and create no fake scope. */
 private async assertDirectMutation(context:Readonly<IamMutation>,tx:DbService=this.db):Promise<void>{
  const payload=context.payload as any,roleIds=new Set<string>(),caps=new Map<string,IamScope[]>(),scopes:IamScope[]=[{cluster_id:context.cluster_id,workspace_id:context.workspace_id}],
   addCap=(id:string,scope:IamScope)=>caps.set(id,[...(caps.get(id)??[]),scope]);
  if(context.module==='roles'&&context.targetId){const role=await tx.one<any>('SELECT id FROM roles WHERE id=$1',[context.targetId]);if(role){roleIds.add(role.id);
   const bindings=await tx.query<any>('SELECT cluster_id,workspace_id FROM user_role_bindings WHERE role_id=$1 UNION ALL SELECT cluster_id,workspace_id FROM team_role_bindings WHERE role_id=$1 LIMIT 1001',[role.id]);
   if(bindings.length>1000)throw changed('IAM_WORKFLOW_GRAPH_BUDGET');scopes.push(...bindings);}}
  if(payload?.source){const id=iamId(payload.source);roleIds.add(id);addCap(id,{cluster_id:context.cluster_id,workspace_id:context.workspace_id});}
  if(payload?.role_id){const id=iamId(payload.role_id);roleIds.add(id);const scope={cluster_id:payload.cluster_id??null,workspace_id:payload.workspace_id??null};addCap(id,scope);scopes.push(scope);}
  if(payload?.bindingId&&['users','roles','teams'].includes(context.module)){const team=context.module==='teams',table=team?'team_role_bindings':'user_role_bindings',owner=team?'team_id':'user_id';
   const binding=await tx.one<any>(`SELECT role_id,cluster_id,workspace_id FROM ${table} WHERE id=$1 AND ${owner}=$2`,[payload.bindingId,context.targetId]);if(binding){roleIds.add(binding.role_id);scopes.push(binding);addCap(binding.role_id,{cluster_id:binding.cluster_id,workspace_id:binding.workspace_id});}}
  if(context.module==='teams'&&context.targetId&&!payload?.role_id&&!payload?.bindingId){const bindings=await tx.query<any>('SELECT role_id,cluster_id,workspace_id FROM team_role_bindings WHERE team_id=$1 AND status=\'active\' LIMIT 1001',[context.targetId]);
   if(bindings.length>1000)throw changed('IAM_WORKFLOW_GRAPH_BUDGET');for(const b of bindings){roleIds.add(b.role_id);scopes.push(b);addCap(b.role_id,{cluster_id:b.cluster_id,workspace_id:b.workspace_id});}}
  if(Array.isArray(payload?.permissions))for(const p of payload.permissions)scopes.push({cluster_id:p.cluster_id??context.cluster_id,workspace_id:p.workspace_id??context.workspace_id});
  if(roleIds.size>100)throw changed('IAM_WORKFLOW_GRAPH_BUDGET');let global=false;for(const roleId of roleIds){const permissions=await tx.query<any>('SELECT cluster_id,workspace_id FROM role_permissions WHERE role_id=$1 AND status=\'active\' LIMIT 1001',[roleId]),roleCaps=caps.get(roleId);
   if(permissions.length>1000)throw changed('IAM_WORKFLOW_GRAPH_BUDGET');for(const p of permissions)for(const cap of roleCaps??[undefined]){if(cap&&(p.cluster_id&&cap.cluster_id&&p.cluster_id!==cap.cluster_id||p.workspace_id&&cap.workspace_id&&p.workspace_id!==cap.workspace_id))continue;
    const actual={cluster_id:p.cluster_id??cap?.cluster_id??null,workspace_id:p.workspace_id??cap?.workspace_id??null};scopes.push(actual);if(scopes.length>10000)throw changed('IAM_WORKFLOW_GRAPH_BUDGET');if(actual.cluster_id===null)global=true;}
   if(roleCaps?.some(cap=>cap.cluster_id===null)&&(await tx.one<any>('SELECT id,builtin_kind FROM roles WHERE id=$1',[roleId]))?.builtin_kind==='super-admin')global=true;
  }
  if(Array.isArray(payload?.permissions)&&payload.permissions.some((p:any)=>p.cluster_id==null&&context.cluster_id===null))global=true;
  const ids=[...new Set(scopes.flatMap(s=>s.cluster_id?[s.cluster_id]:[]))];
  const clusters=await tx.query<any>(`SELECT id,execution_mode FROM clusters WHERE deleted_at IS NULL AND($1::boolean OR id=ANY($2::uuid[])) ORDER BY id LIMIT 101 FOR SHARE`,[global,ids]);
  if(clusters.length>100)throw changed('IAM_WORKFLOW_GRAPH_BUDGET');if(clusters.some(c=>c.execution_mode==='approval'))throw changed('APPROVAL_REQUIRED');
 }
 private async assertCurrent(intent:Readonly<IamWorkflowIntent>,userId:string,role:'requester'|'reviewer'|'reader',tx:DbService):Promise<void>{
  const identity=await this.identity(userId,tx),mutation=intent.capture.mutation;
  if(role==='requester'&&(userId!==intent.actorId||String(identity.row.credential_epoch)!==intent.credentialEpoch))throw deny('IAM_WORKFLOW_REQUESTER_REVOKED');
  const protectedPrincipal=(intent.capture.before.resource as any)?.super_admin===true||intent.capture.before.related.some((r:any)=>r.type==='roles'&&r.row?.builtin_kind==='super-admin');
  if(role!=='reader'&&protectedPrincipal&&identity.row.super_admin!==true)throw deny('IAM_WORKFLOW_SUPER_ADMIN_REQUIRED');
  if(this.secrets.fingerprint(await this.scope(intent.capture,tx))!==this.secrets.fingerprint(intent.scope))throw changed('IAM_WORKFLOW_SCOPE_CHANGED');
  for(const s of intent.scope.clusterScopes){const scope={cluster_id:s.clusterId,workspace_id:s.workspaceId};
   if(!this.whole(identity.grants,identity.row.super_admin===true,'workflows',role==='requester'?'write':role==='reviewer'?'approve':'read',scope))throw deny('IAM_WORKFLOW_SCOPE_DENIED');}
  const primary={cluster_id:mutation.cluster_id,workspace_id:mutation.workspace_id};
  if(!this.whole(identity.grants,identity.row.super_admin===true,mutation.module,role==='requester'?mutation.action:'read',primary))throw deny('IAM_WORKFLOW_SUBJECT_DENIED');
  if(role!=='reader')for(const grant of intent.capture.delegatedGrants)if(identity.row.super_admin!==true&&!identity.grants.some(g=>grantContains(g,grant)))throw deny('IAM_WORKFLOW_DELEGATION_DENIED');
  if(intent.capture.request.resource==='roles'&&['permissions','clone'].includes(intent.capture.request.operation)
   &&!this.whole(identity.grants,identity.row.super_admin===true,'permissions',role==='requester'?'write':'read',primary))throw deny('IAM_WORKFLOW_PERMISSION_SCOPE_DENIED');
 }
 private async load(id:string,tx=this.db):Promise<Readonly<IamWorkflowIntent>>{const row=await tx.one<any>('SELECT * FROM iam_change_intents WHERE id=$1',[iamId(id)]);if(!row)throw new NotFoundException({code:'IAM_CHANGE_INTENT_NOT_FOUND'});
  const intent=immutableJson(this.secrets.decrypt<IamWorkflowIntent>(row.material_secret,aad(row.id)));
  if(intent.version!==1||intent.id!==row.id||intent.actorId!==row.actor_id||intent.authoringSessionId!==row.authoring_session_id||intent.workflowId!==row.workflow_id
   ||intent.scope.clusterId!==row.cluster_id||intent.scope.workspaceId!==row.workspace_id||intent.idempotencyKey!==row.idempotency_key||intent.requestHmac!==row.request_hmac
   ||intent.permissionVersion!==row.permission_version||intent.credentialEpoch!==String(row.credential_epoch)||this.secrets.fingerprint(intent)!==row.material_hmac
   ||intent.workflowKey!==`iam-${intent.id}`||!Number.isFinite(Date.parse(intent.issuedAt))||!Number.isFinite(Date.parse(intent.expiresAt))
   ||Date.parse(intent.expiresAt)<=Date.parse(intent.issuedAt)||Date.parse(intent.expiresAt)>Date.parse(intent.issuedAt)+86400000
   ||new Date(row.issued_at).getTime()!==Date.parse(intent.issuedAt)||new Date(row.expires_at).getTime()!==Date.parse(intent.expiresAt)
   ||this.secrets.fingerprint(intent.capture.request)!==intent.requestHmac)throw changed('IAM_CHANGE_INTENT_INVALID');return intent;}
 async prepare(raw:unknown,actor:IamActor):Promise<Record<string,unknown>>{const request=normalizeIamChangeRequest(raw),sessionId=this.actor(actor),key=this.key(actor),requestHmac=this.secrets.fingerprint(request);
  if(request.resource==='users'&&!request.operation.startsWith('binding.'))throw changed('IAM_WORKFLOW_GLOBAL_DIRECTORY_DIRECT');
  return this.redis.withLock(`iam-change:${actor.user.id}:${key}`,()=>this.db.transaction(async tx=>{
   await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');await this.liveSession(actor,tx);const prior=await tx.one<any>('SELECT id,request_hmac FROM iam_change_intents WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);
   if(prior){if(prior.request_hmac!==requestHmac)throw changed('IDEMPOTENCY_CONFLICT');return this.receipt(prior.id,actor,tx);}
   if(await tx.one('SELECT id FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]))throw changed('IDEMPOTENCY_CONFLICT');
   const captured=await this.iam.captureChange(request,actor,tx),scope=await this.scope(captured,tx),identity=await this.identity(actor.user.id,tx);
   await this.plans.definitions(scope.clusterId,scope.workspaceId,actor.user.id,tx);const currentDefinition=await this.plans.definition(scope.clusterId,scope.workspaceId,'iam-metadata' as any,tx);
   const currentPolicy=await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[scope.clusterId,scope.workspaceId,currentDefinition.id,currentDefinition.version]);
   if(currentPolicy?.approval_format!==2||this.secrets.fingerprint(currentPolicy.policy)!==currentDefinition.policyHash)throw changed('IAM_WORKFLOW_V2_POLICY_REQUIRED');
   const policy=normalizeWorkflowApprovalPolicy(currentPolicy.policy,'iam-metadata' as any);
   const session=await tx.one<any>('SELECT expires_at FROM auth_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() AND credential_epoch=$3',[sessionId,actor.user.id,identity.row.credential_epoch]);
   if(!session)throw deny('IAM_WORKFLOW_SESSION_REVOKED');const id=randomUUID(),now=Date.now(),expiresAt=new Date(Math.min(now+policy.intentTtlHours*3600000,now+86400000,new Date(session.expires_at).getTime())).toISOString();
   const intent:Readonly<IamWorkflowIntent>=immutableJson({version:1,id,workflowId:randomUUID(),actorId:actor.user.id,authoringSessionId:sessionId,credentialEpoch:String(identity.row.credential_epoch),
    permissionVersion:identity.version,idempotencyKey:key,workflowKey:`iam-${id}`,requestHmac,issuedAt:new Date(now).toISOString(),expiresAt,capture:captured,scope});
   await this.assertCurrent(intent,actor.user.id,'requester',tx);
   await tx.exec(`INSERT INTO iam_change_intents(id,cluster_id,workspace_id,actor_id,authoring_session_id,workflow_id,idempotency_key,request_hmac,material_hmac,material_secret,
    credential_epoch,permission_version,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,[id,scope.clusterId,scope.workspaceId,actor.user.id,sessionId,intent.workflowId,key,requestHmac,
      this.secrets.fingerprint(intent),this.secrets.encrypt(intent,aad(id)),intent.credentialEpoch,intent.permissionVersion,intent.issuedAt,intent.expiresAt]);
   await this.audit.append({actorId:actor.user.id,clusterId:scope.clusterId,workspaceId:scope.workspaceId,entityType:'iam_change_intents',entityId:id,action:'iam.change.prepare',
    requestId:actor.requestId,ip:actor.ip,result:'success',after:{resource:request.resource,operation:request.operation,resourceId:request.resourceId??null,materialHmac:this.secrets.fingerprint(intent),nativeRequestsSent:0}},tx);
   await this.redis.assertLeaseOwnership();return this.receipt(id,actor,tx);
  }));}
 private interactive(plan:WorkflowPlanV1):WorkflowPlanV1{if((plan as any)?.scheduling===undefined)return plan;const f=this.context.peek();
  if(!f||f.sessionId||!this.context.hasWorkflowScheduledNamespace())throw changed('IAM_WORKFLOW_BINDING_INVALID');
  const ns=this.context.requireWorkflowScheduledCurrentPrincipal(this.context.requireWorkflowScheduledNamespaceHandle()).namespace;
  if((ns.kind as string)!=='iam-metadata'||ns.workflow.id!==plan.workflowId||ns.workflow.planHash!==this.secrets.fingerprint(plan))throw changed('IAM_WORKFLOW_BINDING_INVALID');
  const {scheduling:_sealed,...rest}=plan as any;return rest;}
 private async bound(plan:WorkflowPlanV1,tx=this.db):Promise<Readonly<IamWorkflowIntent>>{const step=assertIamMetadataPlan(this.interactive(plan)),payload=step.metadata as IamMetadataPayload,intent=await this.load(payload.intentId,tx);
  const request=await tx.one<any>('SELECT * FROM iam_metadata_requests WHERE id=$1 AND workflow_id=$2 AND cluster_id=$3 AND workspace_id=$4',[intent.id,plan.workflowId,plan.clusterId,plan.workspaceId]);
  if(!request||intent.workflowId!==plan.workflowId||intent.actorId!==plan.requester.id||intent.scope.clusterId!==plan.clusterId||intent.scope.workspaceId!==plan.workspaceId
   ||request.actor_id!==intent.actorId||request.material_hmac!==this.secrets.fingerprint(intent)||payload.materialHmac!==request.material_hmac||payload.resource!==intent.capture.request.resource
   ||payload.operation!==intent.capture.request.operation||request.idempotency_key!==intent.workflowKey||request.request_hmac!==intent.requestHmac||plan.expiresAt!==intent.expiresAt
   ||this.secrets.fingerprint(step.before)!==this.secrets.fingerprint(intent.capture.before)||step.metadataBeforeHmac!==this.secrets.fingerprint(intent.capture.before)
   ||step.metadataPayloadHmac!==this.secrets.fingerprint(payload)||step.metadataRevision!==this.revision(intent)||this.secrets.fingerprint(plan.scope)!==this.secrets.fingerprint({transportScope:intent.scope.transportScope,clusterRevision:intent.scope.clusterRevision,workspaceRevision:intent.scope.workspaceRevision}))throw changed('IAM_WORKFLOW_BINDING_INVALID');return intent;}
 async verifyIntent(plan:WorkflowPlanV1,tx=this.db):Promise<void>{await this.bound(plan,tx);}
 async verifyReviewer(userId:string,plan:WorkflowPlanV1,tx=this.db):Promise<void>{const intent=await this.bound(plan,tx);await this.assertCurrent(intent,userId,userId===intent.actorId?'requester':'reviewer',tx);}
 private async assertActor(plan:WorkflowPlanV1,actor:IamActor,action:'read'|'write'|'approve',tx=this.db):Promise<void>{const intent=await this.bound(plan,tx),sid=await this.executionSession(actor,intent,plan,tx);
  if(this.scheduled(actor)&&action!=='write')throw deny('IAM_WORKFLOW_SCHEDULED_ACTOR_REQUIRED');
  if(actor.workspaceId!==plan.workspaceId||action==='write'&&(actor.user.id!==intent.actorId||sid!==intent.authoringSessionId))throw deny('IAM_WORKFLOW_EXECUTOR_DENIED');
  if(action!=='read'&&Date.parse(intent.expiresAt)<=Date.now())throw changed('IAM_CHANGE_INTENT_EXPIRED_OR_CHANGED');
  await this.assertCurrent(intent,actor.user.id,action==='write'?'requester':action==='approve'?'reviewer':'reader',tx);
  if(action!=='read'&&this.secrets.fingerprint(await this.iam.changeBeforeGraph(intent.capture.request,tx))!==this.secrets.fingerprint(intent.capture.before))throw changed('IAM_WORKFLOW_METADATA_CHANGED');}
 async submit(id:string,raw:unknown,actor:IamActor):Promise<Record<string,unknown>>{const value=iamBody(raw,['confirmed','materialHmac']);if(value.confirmed!==true||typeof value.materialHmac!=='string')throw changed('CONFIRMATION_REQUIRED');
  const session=this.actor(actor);return this.redis.withLock(`iam-change-submit:${id}`,()=>this.db.transaction(async tx=>{await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
   await this.liveSession(actor,tx);const intent=await this.load(id,tx);if(intent.actorId!==actor.user.id||intent.authoringSessionId!==session)throw deny('IAM_WORKFLOW_AUTHOR_MISMATCH');
   if(Date.parse(intent.expiresAt)<=Date.now()||value.materialHmac!==this.secrets.fingerprint(intent))throw changed('IAM_CHANGE_INTENT_EXPIRED_OR_CHANGED');
   await this.assertCurrent(intent,actor.user.id,'requester',tx);if(this.secrets.fingerprint(await this.iam.changeBeforeGraph(intent.capture.request,tx))!==this.secrets.fingerprint(intent.capture.before))throw changed('IAM_WORKFLOW_METADATA_CHANGED');
   if(await tx.one('SELECT id FROM iam_metadata_requests WHERE id=$1',[id]))return this.receipt(id,actor,tx);
   const scope=intent.scope;await this.plans.definitions(scope.clusterId,scope.workspaceId,actor.user.id,tx);const definition=await this.plans.definition(scope.clusterId,scope.workspaceId,'iam-metadata' as any,tx);
   const version=await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[scope.clusterId,scope.workspaceId,definition.id,definition.version]);
   if(version?.approval_format!==2||this.secrets.fingerprint(version.policy)!==definition.policyHash)throw changed('IAM_WORKFLOW_V2_POLICY_REQUIRED');normalizeWorkflowApprovalPolicy(version.policy,'iam-metadata' as any);
   if(Date.parse(intent.expiresAt)>Date.parse(intent.issuedAt)+version.policy.intentTtlHours*3600000)throw changed('IAM_WORKFLOW_POLICY_TTL_CHANGED');
   await tx.exec(`INSERT INTO iam_metadata_requests(id,cluster_id,workspace_id,actor_id,workflow_id,idempotency_key,request_hmac,material_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
    [id,scope.clusterId,scope.workspaceId,actor.user.id,intent.workflowId,intent.workflowKey,intent.requestHmac,this.secrets.fingerprint(intent)]);
   const metadata:IamMetadataPayload={intentId:id,resource:intent.capture.request.resource,operation:intent.capture.request.operation,materialHmac:this.secrets.fingerprint(intent)};
   const plan:WorkflowPlanV1={version:1,kind:'iam-metadata' as any,clusterId:scope.clusterId,workspaceId:scope.workspaceId,workflowId:intent.workflowId,planRevision:1,executionMode:'approval',approvalRequired:true,
    subject:{type:'iam_metadata_requests' as any,id},requester:{type:'console',id:actor.user.id},definition,issuedAt:intent.issuedAt,expiresAt:intent.expiresAt,
    scope:{transportScope:scope.transportScope,clusterRevision:scope.clusterRevision,workspaceRevision:scope.workspaceRevision},prerequisites:[],steps:[{id:randomUUID(),key:'iam.metadata',order:1,kind:'metadata',handler:'iam.metadata',
      entityType:'iam_metadata_requests',entityId:id,permissionAction:['archive','binding.revoke','member.revoke'].includes(metadata.operation)?'delete':'write',dependencies:[],nativeRequests:[],before:intent.capture.before,
      metadataRevision:this.revision(intent),metadataBeforeHmac:this.secrets.fingerprint(intent.capture.before),metadata,metadataPayloadHmac:this.secrets.fingerprint(metadata)}]};
   await this.plans.persist(plan,intent.workflowKey,intent.capture.request,tx,{requestId:actor.requestId,ip:actor.ip});await this.redis.assertLeaseOwnership();return this.receipt(id,actor,tx);
  }));}
 async receipt(id:string,actor:IamActor,tx=this.db):Promise<Record<string,unknown>>{const intent=await this.load(id,tx);await this.liveSession(actor,tx);
  if(intent.actorId!==actor.user.id)throw deny('IAM_CHANGE_INTENT_OWNER_REQUIRED');
  const request=await tx.one<any>('SELECT workflow_id FROM iam_metadata_requests WHERE id=$1',[id]),workflow=request?await tx.one<any>('SELECT id,state,revision,plan_hash FROM workflows WHERE id=$1',[request.workflow_id]):null;
  let preview:Record<string,unknown>|null=null;
  try{await this.assertCurrent(intent,actor.user.id,'requester',tx);preview=await this.preview(intent,actor,tx);}catch(error){
   if(!(error instanceof ForbiddenException)||workflow?.state!=='succeeded'||!await tx.one(`SELECT f.operation_id FROM iam_workflow_mutation_facts f
     JOIN workflow_executions e ON e.id=f.execution_id JOIN workflow_steps s ON s.id=f.step_id
     WHERE f.intent_id=$1 AND f.workflow_id=$2 AND f.actor_id=$3 AND f.session_id=$4 AND f.plan_hash=$5 AND e.state='succeeded' AND s.state='succeeded'
      AND e.workflow_id=f.workflow_id AND e.plan_hash=f.plan_hash AND e.execution_actor_id=f.actor_id AND s.handler='iam.metadata'`,[id,intent.workflowId,actor.user.id,intent.authoringSessionId,workflow.plan_hash]))throw error;
   // The current user may inspect only its own authenticated terminal status
   // after the exact approved operation removed its IAM grants. No metadata
   // body, new privilege or execution capability is returned in this branch.
  }
  return{intentId:intent.id,resource:intent.capture.request.resource,operation:intent.capture.request.operation,resourceId:intent.capture.request.resourceId??null,
   materialHmac:this.secrets.fingerprint(intent),state:workflow?.state??'prepared',workflowId:workflow?.id??null,revision:workflow?.revision??null,planHash:workflow?.plan_hash??null,
   clusterId:intent.scope.clusterId,workspaceId:intent.scope.workspaceId,expiresAt:intent.expiresAt,nativeRequestsSent:0,preview};}
 async receiptByKey(key:string,actor:IamActor):Promise<Record<string,unknown>>{await this.liveSession(actor,this.db);this.key({...actor,idempotencyKey:key});
  const row=await this.db.one<any>('SELECT id FROM iam_change_intents WHERE actor_id=$1 AND idempotency_key=$2',[actor.user.id,key]);if(!row)throw new NotFoundException({code:'IAM_CHANGE_INTENT_NOT_FOUND'});return this.receipt(row.id,actor);}
 private async preview(intent:Readonly<IamWorkflowIntent>,actor:IamActor,tx:DbService):Promise<Record<string,unknown>>{
  const {request,before,mutation}=intent.capture,identity=await this.identity(actor.user.id,tx),canRead=(module:string,scope:IamScope)=>this.whole(identity.grants,identity.row.super_admin===true,module,'read',scope);
  const projectUser=(row:any)=>row&&canRead('users',{cluster_id:null,workspace_id:null})?row:row?{id:row.id}:null;
  const graph:any=this.secrets.redact(before),owner=before.resource as any,ownerScope={cluster_id:owner?.cluster_id??null,workspace_id:owner?.workspace_id??null};
  if(request.resource==='users')graph.resource=projectUser(graph.resource);
  else if(graph.resource&&!canRead(request.resource,ownerScope))graph.resource={id:graph.resource.id};
  if(!canRead('permissions',ownerScope))graph.permissions={count:before.permissions.length,restricted:true};
  const readableBindings=graph.bindings.filter((binding:any)=>request.resource==='teams'?canRead('teams',ownerScope)
   :canRead('roles',{cluster_id:binding.cluster_id??null,workspace_id:binding.workspace_id??null})&&(request.resource!=='roles'||canRead('roles',ownerScope)));
  if(readableBindings.length!==graph.bindings.length)graph.restrictedBindings={count:graph.bindings.length-readableBindings.length,restricted:true};
  graph.bindings=readableBindings;
  if(request.operation.startsWith('binding.')||request.operation==='clone'){
   const boundRole=(mutation.payload as any)?.role_id??(request.operation==='clone'?request.resourceId:(before.bindings as any[]).find(b=>b.id===request.relatedId)?.role_id),
    visibleRelated=graph.related.filter((r:any)=>r.type!=='roles'||r.row?.id===boundRole);
   if(visibleRelated.length!==graph.related.length)graph.restrictedRelated={count:graph.related.length-visibleRelated.length,restricted:true};graph.related=visibleRelated;
  }
  graph.related=graph.related.map((related:any)=>{
   if(related.type==='users')return{...related,row:projectUser(related.row)};
   if(related.type!=='roles')return related;const scope={cluster_id:related.row?.cluster_id??null,workspace_id:related.row?.workspace_id??null};
   return{type:'roles',row:canRead('roles',scope)?related.row:{id:related.row?.id},
    permissions:canRead('permissions',scope)?related.permissions:{count:related.permissions?.length??0,restricted:true}};
  });
  const input=this.secrets.redact(request.input),confirmationName=(request.input.confirm_name as string)??graph.resource?.name??graph.resource?.username??(mutation.payload as any)?.name??request.resourceId??request.resource;
  const after=request.operation==='archive'?{resourceId:request.resourceId,status:'deleted'}:request.operation==='restore'?{resourceId:request.resourceId,status:'active'}
   :request.operation==='status'?{resourceId:request.resourceId,status:request.input.status}:{resource:request.resource,operation:request.operation,resourceId:request.resourceId??intent.capture.allocatedIds[0]??null,input:this.secrets.redact(mutation.payload)};
  return{request:immutableJson({resource:request.resource,operation:request.operation,...(request.resourceId?{resourceId:request.resourceId}:{}),...(request.relatedId?{relatedId:request.relatedId}:{}),input}),
   before:graph,after,affectedScopes:intent.scope.clusterScopes,confirmationName};
 }
 async reviewPreview(plan:WorkflowPlanV1,actor:IamActor):Promise<Record<string,unknown>>{
  const intent=await this.bound(plan);await this.assertActor(plan,actor,'read');const preview=await this.preview(intent,actor,this.db),step=assertIamMetadataPlan(plan);
  return{diff:[{id:step.id,kind:'metadata',operation:intent.capture.request.operation,entityType:intent.capture.request.resource,
    entityId:intent.capture.request.resourceId??intent.capture.allocatedIds[0]??null,before:preview.before,after:preview.after}],
   affectedScopes:intent.scope.clusterScopes.map(s=>({clusterId:s.clusterId,workspaceId:s.workspaceId,clusterRevision:s.revision,workspaceRevision:s.workspaceRevision,executionMode:s.executionMode}))};
 }
 private async prepareExecution(input:Omit<WorkflowHandlerInput,'transaction'>):Promise<void>{await this.assertActor(input.plan,input.actor,'write');}
 private async apply(input:WorkflowHandlerInput):Promise<Record<string,unknown>>{const {plan,step,actor,executionId,transaction:tx}=input,intent=await this.bound(plan,tx),session=await this.executionSession(actor,intent,plan,tx);
  if(session!==intent.authoringSessionId)throw deny('IAM_WORKFLOW_AUTHOR_SESSION_CHANGED');await this.assertActor(plan,actor,'write',tx);
  await this.context.assertApprovedMetadataStep({handler:'iam.metadata',actor:actor.user,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'iam_metadata_requests',entityId:intent.id,
   before:intent.capture.before,revision:this.revision(intent),payload:step.metadata},tx);
  const identity=await this.identity(actor.user.id,tx),sched=this.scheduled(actor),binding:Readonly<IamApprovedMutationBinding>=Object.freeze({intentId:intent.id,workflowId:plan.workflowId,executionId,stepId:step.id,
   planRevision:plan.planRevision,planHash:this.secrets.fingerprint(plan),clusterId:plan.clusterId,workspaceId:plan.workspaceId,actorId:actor.user.id,sessionId:session,frameSessionId:sched?null:session,scheduledClaimId:sched?sched.claimId:null,permissionVersion:identity.version,iamEpoch:identity.epoch}),handle=Object.freeze({});
  const state:ExecutionState={active:true,intent,plan,input,transaction:tx,binding,captureVerified:false,beforeVerified:false,afterVerified:false};this.executions.set(handle,state);
  try{const entity=await this.iam.applyApprovedChange(handle,intent.capture,actor,tx);if(!state.afterVerified||state.resultHmac!==this.secrets.fingerprint(entity))throw deny('IAM_WORKFLOW_RESULT_UNACKNOWLEDGED');
   const result=immutableJson({entity,resource:intent.capture.request.resource,operation:intent.capture.request.operation,intentId:intent.id,nativeRequestsSent:0});
   this.completions.set(result,Object.freeze({state,resultHmac:this.secrets.fingerprint(result)}));return result;
  }finally{state.active=false;this.executions.delete(handle);}}
 private execution(handle:object):ExecutionState{const state=this.executions.get(handle);if(!state?.active||Date.parse(state.intent.expiresAt)<=Date.now())throw deny('IAM_WORKFLOW_ORIGINAL_EXECUTION_REQUIRED');return state;}
 private async running(state:ExecutionState,tx:DbService):Promise<void>{const {plan,input,binding}=state,frame=this.context.current(),step=this.context.currentApprovedStep();
  if(frame.actor?.id!==binding.actorId||(frame.sessionId??null)!==binding.frameSessionId||step.kind!=='metadata'||step.stepId!==binding.stepId||step.execution.executionId!==binding.executionId
   ||step.execution.workflowId!==binding.workflowId||step.execution.actorId!==binding.actorId||(step.execution.sessionId??null)!==binding.frameSessionId||state.transaction!==tx||input.transaction!==tx)throw deny('IAM_WORKFLOW_ORIGINAL_EXECUTION_REQUIRED');
  const row=await tx.one<any>(`SELECT e.id FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id AND w.cluster_id=e.cluster_id AND w.workspace_id=e.workspace_id
   JOIN workflow_steps s ON s.workflow_id=w.id AND s.plan_revision=e.plan_revision AND s.plan_hash=e.plan_hash WHERE e.id=$1 AND e.workflow_id=$2 AND e.cluster_id=$3 AND e.workspace_id=$4
   AND e.state='executing' AND w.state='executing' AND e.execution_actor_id=$5 AND e.approval_format=2 AND e.approval_set_id=w.approval_set_id AND e.approval_set_hmac=w.approval_set_hmac
   AND s.id=$6 AND s.state='running' AND s.handler='iam.metadata' AND s.kind='metadata' AND jsonb_array_length(s.native_requests)=0
   AND e.plan_hash=$7 AND e.plan_revision=$8 AND w.plan_hash=e.plan_hash AND w.plan_revision=e.plan_revision`,[binding.executionId,plan.workflowId,plan.clusterId,plan.workspaceId,binding.actorId,binding.stepId,binding.planHash,binding.planRevision]);
  if(!row)throw deny('IAM_WORKFLOW_APPROVED_EXECUTION_REQUIRED');}
 private async verifyCapture(handle:object,capture:Readonly<IamCapturedChange>,actor:IamActor,tx:DbService):Promise<void>{const state=this.execution(handle);await this.running(state,tx);
  if(state.captureVerified||actor.user.id!==state.binding.actorId||this.secrets.fingerprint(capture)!==this.secrets.fingerprint(state.intent.capture))throw deny('IAM_WORKFLOW_CAPTURE_MISMATCH');state.captureVerified=true;}
 private async verifyMutation(handle:object,mutation:Readonly<IamMutation>,phase:'before'|'after',tx:DbService,result?:unknown):Promise<Readonly<IamApprovedMutationBinding>>{const state=this.execution(handle);await this.running(state,tx);
  const {actor,...actual}=mutation;if(!state.captureVerified||actor.user.id!==state.binding.actorId||this.secrets.fingerprint(actual)!==this.secrets.fingerprint(state.intent.capture.mutation))throw deny('IAM_WORKFLOW_MUTATION_MISMATCH');
  if(phase==='before'){if(state.beforeVerified||state.afterVerified)throw deny('IAM_WORKFLOW_FIXED_OPERATION_REQUIRED');await this.assertActor(state.plan,actor,'write',tx);
   await this.context.assertApprovedMetadataStep({handler:'iam.metadata',actor:actor.user,clusterId:state.plan.clusterId,workspaceId:state.plan.workspaceId,entityType:'iam_metadata_requests',entityId:state.intent.id,
    before:state.intent.capture.before,revision:this.revision(state.intent),payload:state.input.step.metadata},tx);state.beforeVerified=true;return state.binding;}
  if(!state.beforeVerified||state.afterVerified||result===undefined)throw deny('IAM_WORKFLOW_FIXED_OPERATION_REQUIRED');
  // Only the already-authorized exact SQL operation may finish after its own
  // IAM epoch change. No new grant check uses the old approval as authority.
  if(this.secrets.fingerprint(await this.iam.readAppliedChange(state.intent.capture,tx))!==this.secrets.fingerprint(result))throw changed('IAM_WORKFLOW_RESULT_READBACK_MISMATCH');
  const identity=await this.identity(state.binding.actorId,tx);state.afterVerified=true;state.resultHmac=this.secrets.fingerprint(result);
  return state.afterBinding=Object.freeze({...state.binding,permissionVersion:identity.version,iamEpoch:identity.epoch});
 }
 /** Finalizes only this service's original result in its original transaction.
  * Reading the current epoch is an integrity check, not authorization for a
  * second action after this operation changes its own IAM grants. */
 async verifyMetadataCompletion(input:WorkflowHandlerInput,result:Record<string,unknown>,beforePermissionVersion:string):Promise<void>{
  const completed=result&&typeof result==='object'?this.completions.get(result):undefined;
  if(!completed)throw deny('IAM_WORKFLOW_ORIGINAL_COMPLETION_REQUIRED');this.completions.delete(result);
  const {state}=completed,{binding,afterBinding}=state,tx=input.transaction;
  if(state.input!==input||state.transaction!==tx||!state.afterVerified||!afterBinding||Date.parse(state.intent.expiresAt)<=Date.now()||beforePermissionVersion!==binding.permissionVersion
   ||input.executionId!==binding.executionId||input.actor.user.id!==binding.actorId||this.secrets.fingerprint(input.plan)!==binding.planHash
   ||this.secrets.fingerprint(input.step)!==this.secrets.fingerprint(state.plan.steps[0])
   ||this.secrets.fingerprint(result)!==completed.resultHmac||this.secrets.fingerprint(result.entity)!==state.resultHmac)throw deny('IAM_WORKFLOW_ORIGINAL_COMPLETION_REQUIRED');
  if(await this.executionSession(input.actor,state.intent,state.plan,tx)!==binding.sessionId)throw deny('IAM_WORKFLOW_SESSION_REVOKED');await this.running(state,tx);await this.bound(input.plan,tx);
  const row=await tx.one<any>(`SELECT f.*,o.idempotency_key AS operation_key,o.actor_id AS operation_actor,o.cluster_id AS operation_cluster_id,o.workspace_id AS operation_workspace_id,
   o.state AS operation_state,o.remote_completed,o.result_secret FROM iam_workflow_mutation_facts f JOIN iam_operations o ON o.id=f.operation_id
   WHERE f.intent_id=$1 AND f.workflow_id=$2 AND f.execution_id=$3 AND f.step_id=$4 AND f.actor_id=$5 AND f.session_id=$6 AND f.plan_hash=$7 AND f.plan_revision=$8`,
   [binding.intentId,binding.workflowId,binding.executionId,binding.stepId,binding.actorId,binding.sessionId,binding.planHash,binding.planRevision]);
  const identity=await this.identity(binding.actorId,tx),mutation=state.intent.capture.mutation;
  if(!row||(row.execution_origin??'session')!==(binding.scheduledClaimId?'scheduled':'session')||(row.schedule_claim_id??null)!==binding.scheduledClaimId||row.operation_key!==`iam-approved-${binding.executionId}`||row.operation_actor!==binding.actorId||row.operation_state!=='succeeded'||row.remote_completed!==true||!row.result_secret
   ||row.workflow_cluster_id!==binding.clusterId||row.workflow_workspace_id!==binding.workspaceId||row.operation_cluster_id!==mutation.cluster_id||row.operation_workspace_id!==mutation.workspace_id
   ||row.cluster_id!==mutation.cluster_id||row.workspace_id!==mutation.workspace_id||row.before_permission_version!==binding.permissionVersion||String(row.before_iam_epoch)!==binding.iamEpoch
   ||row.after_permission_version!==afterBinding.permissionVersion||String(row.after_iam_epoch)!==afterBinding.iamEpoch||identity.version!==afterBinding.permissionVersion||identity.epoch!==afterBinding.iamEpoch
   ||row.result_hmac!==state.resultHmac||this.secrets.fingerprint(this.secrets.decrypt(row.result_secret,`iam:${row.operation_id}:result`))!==state.resultHmac
   ||this.secrets.fingerprint(await this.iam.readAppliedChange(state.intent.capture,tx))!==state.resultHmac)throw deny('IAM_WORKFLOW_COMPLETION_FACTS_CHANGED');
  await this.redis.assertLeaseOwnership();this.context.current();
 }
 async terminalReceipt(plan:WorkflowPlanV1,actor:IamActor):Promise<WorkflowReceipt>{
  const intent=await this.bound(plan);await this.liveSession(actor,this.db);if(intent.actorId!==actor.user.id||actor.workspaceId!==plan.workspaceId)throw deny('IAM_CHANGE_INTENT_OWNER_REQUIRED');
  const row=await this.db.one<any>(`SELECT e.id AS execution_id,e.idempotency_key AS execution_key,w.revision,s.id AS step_id FROM iam_workflow_mutation_facts f
   JOIN workflows w ON w.id=f.workflow_id JOIN workflow_executions e ON e.id=f.execution_id JOIN workflow_steps s ON s.id=f.step_id JOIN iam_operations o ON o.id=f.operation_id
   WHERE f.intent_id=$1 AND f.workflow_id=$2 AND f.actor_id=$3 AND f.session_id=$4 AND f.plan_hash=$5 AND f.plan_revision=$6
    AND w.cluster_id=$7 AND w.workspace_id=$8 AND w.state='succeeded' AND e.state='succeeded' AND s.state='succeeded' AND o.state='succeeded' AND o.remote_completed
    AND e.workflow_id=w.id AND s.workflow_id=w.id AND e.plan_hash=w.plan_hash AND s.plan_hash=w.plan_hash AND e.plan_revision=w.plan_revision AND s.plan_revision=w.plan_revision
    AND e.execution_actor_id=f.actor_id AND s.handler='iam.metadata' AND s.kind='metadata' AND s.native_requests='[]'::jsonb`,
   [intent.id,plan.workflowId,actor.user.id,intent.authoringSessionId,this.secrets.fingerprint(plan),plan.planRevision,plan.clusterId,plan.workspaceId]);
  if(!row)throw deny('IAM_WORKFLOW_TERMINAL_RECEIPT_UNAVAILABLE');
  return{id:row.execution_id,workflowId:plan.workflowId,executionId:row.execution_id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,idempotencyKey:row.execution_key,
   state:'succeeded',revision:row.revision,planHash:this.secrets.fingerprint(plan),executionMode:'approval',approvalRequired:true,steps:[{id:row.step_id,name:'iam.metadata',state:'succeeded',
    operationId:null,remoteStarted:false,remoteCompleted:true,recycleEntryId:null,errorCode:null}],propagation:'acknowledged'};
 }
}
