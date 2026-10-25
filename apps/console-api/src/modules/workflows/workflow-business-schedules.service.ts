import {BadRequestException,ConflictException,ForbiddenException,HttpException,Injectable,NotFoundException,ServiceUnavailableException} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {AsyncLocalStorage} from 'node:async_hooks';
import {DbService} from '../../infrastructure/db.service';
import {SecretService} from '../../infrastructure/secret.service';
import {RedisService} from '../../infrastructure/redis.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {AuthorizationService} from '../authorization/authorization.service';
import {AuditService} from '../audit/audit.service';
import {pageSize,type EntityActor} from '../entities/entities.types';
import {portalObject,portalRevision,portalConfirm,PortalCursor} from '../portal/portal-input';
import {validImpact,type MutationImpact} from '../mutations/mutation-impact';
import {WorkflowPlansService} from './workflow-plans.service';
import {WorkflowScheduleRepository,normalizeWorkflowScheduleDraft,normalizeWorkflowScheduleSpec,workflowSchedulePlanSeal,assertWorkflowScheduledPlan} from './workflow-schedule.repository';
import {WorkflowScheduledAuthorityService} from './workflow-scheduled-authority.service';
import {workflowId,workflowKey,validateWorkflowPlan} from './workflow-validation';
import type {WorkflowPlanV1} from './workflow.types';
import type {WorkflowBusinessSubjectSealV1,WorkflowScheduleDraft,WorkflowScheduleSpecV1,WorkflowScheduledPlanV1,WorkflowScheduleReceipt,WorkflowScheduleStored} from './workflow-schedule.contract';
import { assertPortalCredentialScheduleKindSupported } from '../portal/portal-credential-lifecycle-contract';
import { assertKp008BusinessWriteSealed } from '../audit/kp008-write-audit-reconcile-contract';

export interface WorkflowBusinessScheduleAcceptance {readonly sessionId:string;readonly credentialEpoch:string;readonly permissionVersion:string;}
/** Private actual source material and plaintext never leave the BFF. Root
 * authenticates the original persisted business material before deriving a
 * new commitment for server-remapped step UUIDs/revision/idempotency keys. */
export interface WorkflowBusinessSchedulePrepareInput {
 readonly old:Readonly<{row:any;version:any;plan:WorkflowPlanV1}>;
 readonly basePlan:Readonly<WorkflowPlanV1>;
 readonly spec:Readonly<WorkflowScheduleSpecV1>;
 readonly actor:EntityActor;
 readonly acceptance:Readonly<WorkflowBusinessScheduleAcceptance>;
 readonly transaction:DbService;
}
export interface WorkflowBusinessSchedulePreparedMaterial {
 readonly subjectSeal:Readonly<WorkflowBusinessSubjectSealV1>;
 readonly requesterCredentialEpoch:string;
 readonly impact:Readonly<MutationImpact>;
}
export interface WorkflowBusinessScheduleProposalInput extends WorkflowBusinessSchedulePrepareInput {
 readonly plan:Readonly<WorkflowScheduledPlanV1>;
 readonly draft:Readonly<WorkflowScheduleDraft>;
 readonly checkpoint:'before-version'|'after-version';
}
export interface WorkflowBusinessScheduleProposalPolicy {
 prepareRevision(input:Readonly<WorkflowBusinessSchedulePrepareInput>):Promise<Readonly<WorkflowBusinessSchedulePreparedMaterial>>;
 assertProposal(input:Readonly<WorkflowBusinessScheduleProposalInput>):Promise<void>;
}
export type WorkflowBusinessScheduleCommand='author'|'activate'|'cancel'|'read'|'receipt'|'list';
/** Root derives workflow/module/native scope from the actual stored business
 * manifest and current native observations. A caller cannot choose a Service,
 * role, tag set, grant, scope or policy. This DTO issues no native authority. */
export interface WorkflowBusinessScheduleOperationInput {
 readonly plan:Readonly<WorkflowPlanV1>;
 readonly schedule:Readonly<WorkflowScheduleStored>|null;
 readonly actor:EntityActor;
 readonly acceptance:Readonly<WorkflowBusinessScheduleAcceptance>;
 readonly action:'read'|'write'|'approve';
 readonly command:WorkflowBusinessScheduleCommand;
 readonly checkpoint:'before'|'after';
 readonly transaction:DbService;
}
export interface WorkflowBusinessScheduleOperationPolicy {
 assertOperation(input:Readonly<WorkflowBusinessScheduleOperationInput>):Promise<void>;
}
interface ProposalState {active:boolean;expiresAt:number;input:Readonly<WorkflowBusinessSchedulePrepareInput>;plan:Readonly<WorkflowScheduledPlanV1>;
 draft:Readonly<WorkflowScheduleDraft>;digest:string;versionPersisted:boolean;draftPersisted:boolean;transaction:DbService;}
interface ReceiptReadState {active:boolean;frame:ReturnType<KongExecutionContextService['current']>;frameActor:unknown;actor:EntityActor;
 scheduleId:string;clusterId:string;workspaceId:string;workflowId:string;materialHmac:string;acceptance:Readonly<WorkflowBusinessScheduleAcceptance>;transaction:DbService;}
const hex=/^[a-f\d]{64}$/;
const epoch=(v:unknown):v is string=>typeof v==='string'&&/^[1-9]\d{0,18}$/.test(v)&&BigInt(v)<=9223372036854775807n;
const deny=(code:string)=>new ForbiddenException({code});
const changed=(code:string)=>new ConflictException({code});
const iso=(v:any)=>{const d=new Date(v);if(!Number.isFinite(d.getTime()))throw new BadRequestException({code:'WORKFLOW_SCHEDULE_TIME_INVALID'});return d.toISOString();};

/** HTTP metadata authoring only. No worker claim, namespace, Native Source or
 * background principal can be submitted by this API. Root owns the fixed
 * original source/material verifier and the independent scheduled executor. */
@Injectable()
export class WorkflowBusinessSchedulesService {
 private root?:Readonly<WorkflowBusinessScheduleProposalPolicy>;
 private operations?:Readonly<WorkflowBusinessScheduleOperationPolicy>;
 private storage?:Readonly<{name:string;checksum:string}>;
 private readonly proposals=new WeakMap<object,ProposalState>();
 private readonly receiptReads=new AsyncLocalStorage<object>();
 private readonly receiptStates=new WeakMap<object,ReceiptReadState>();
 private readonly cursors=new PortalCursor();
 constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly redis:RedisService,
  private readonly context:KongExecutionContextService,private readonly authz:AuthorizationService,private readonly audit:AuditService,
  private readonly plans:WorkflowPlansService,private readonly repository:WorkflowScheduleRepository,private readonly authority:WorkflowScheduledAuthorityService){}
 installProposalPolicy(root:WorkflowBusinessScheduleProposalPolicy,storage:Readonly<{name:string;checksum:string}>):void {
  if(this.root||!root||typeof root.prepareRevision!=='function'||typeof root.assertProposal!=='function'||Object.keys(root).some(k=>!['prepareRevision','assertProposal'].includes(k))
   ||storage?.name!=='029_m11_business_schedule_revisions.sql'||!hex.test(storage?.checksum??''))throw new Error('One complete fixed Root business proposal policy and exact SQL029 is required');
  const policy=Object.freeze({prepareRevision:root.prepareRevision.bind(root),assertProposal:root.assertProposal.bind(root)});
  this.plans.installScheduledRevisionDelegate({verifyRevision:(proof,old,plan,draft,actor,tx)=>this.verifyProposal(proof,old,plan,draft,actor,tx),
   beforeApprovalFreeze:async(proof,plan,draft,actor,tx)=>{const state=this.original(proof,tx);state.versionPersisted=true;await this.verifyProposal(proof,state.input.old,plan,draft,actor,tx);
    if(state.draftPersisted)throw changed('WORKFLOW_SCHEDULE_PROPOSAL_ALREADY_USED');
    await this.authority.persistPreparedDraft(draft,actor,tx);state.draftPersisted=true;
    await this.verifyProposal(proof,state.input.old,plan,draft,actor,tx);}},storage);
  this.root=policy;this.storage=Object.freeze({...storage});
 }
 installWorkflowOperationPolicy(policy:WorkflowBusinessScheduleOperationPolicy):void {
  if(this.operations||!policy||typeof policy.assertOperation!=='function'||Object.keys(policy).some(k=>k!=='assertOperation'))
   throw new Error('One complete fixed actual-subject workflow operation verifier is required');
  this.operations=Object.freeze({assertOperation:policy.assertOperation.bind(policy)});
 }
 private operationPolicy():Readonly<WorkflowBusinessScheduleOperationPolicy>{
  if(!this.operations)throw new ServiceUnavailableException({code:'WORKFLOW_BUSINESS_SCHEDULE_OPERATION_POLICY_UNAVAILABLE'});return this.operations;
 }
 private installed():Readonly<WorkflowBusinessScheduleProposalPolicy>{if(!this.root||!this.storage)throw new ServiceUnavailableException({code:'WORKFLOW_BUSINESS_SCHEDULE_ADAPTER_UNAVAILABLE'});return this.root;}
 private async schema(tx=this.db):Promise<void>{this.installed();this.operationPolicy();const row=await tx.one<any>('SELECT checksum FROM schema_migrations WHERE name=$1',[this.storage!.name]);
  if(row?.checksum!==this.storage!.checksum)throw new ServiceUnavailableException({code:'WORKFLOW_BUSINESS_SCHEDULE_STORAGE_UNAVAILABLE'});}
 private scoped<T>(cid:string,actor:EntityActor,action:'read'|'write'|'approve',fn:()=>Promise<T>):Promise<T>{
  const parent=this.context.peek();if(!parent?.sessionId||!['http','actor'].includes(parent.kind)||parent.actor?.id!==actor.user.id||parent.operation||parent.archive
   ||parent.clusterId&&parent.clusterId!==cid||parent.workspaceId&&parent.workspaceId!==actor.workspaceId)throw deny('WORKFLOW_SCHEDULE_ACTUAL_HTTP_OWNER_REQUIRED');
  return this.context.runActor({actor:actor.user,clusterId:cid,workspaceId:actor.workspaceId,module:'workflows',action,requestId:actor.requestId},fn);
 }
 private async acceptance(cid:string,actor:EntityActor,tx:DbService,action:'read'|'write'|'approve'='write'):Promise<Readonly<WorkflowBusinessScheduleAcceptance>> {
  const frame=this.context.peek();if(!frame?.sessionId||frame.actor?.id!==actor.user.id||frame.clusterId!==cid||frame.workspaceId!==actor.workspaceId
   ||!['http','actor'].includes(frame.kind))throw deny('WORKFLOW_SCHEDULE_ACTUAL_HTTP_OWNER_REQUIRED');
  const row=await tx.one<any>(`SELECT s.id,s.credential_epoch,u.permissions_epoch,i.version AS iam_version FROM auth_sessions s JOIN users u ON u.id=s.user_id
   CROSS JOIN iam_epoch i WHERE s.id=$1 AND s.user_id=$2 AND i.singleton=true AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
   AND s.credential_epoch=u.credential_epoch AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change FOR SHARE OF s,u,i`,[frame.sessionId,actor.user.id]);
  if(!row||row.id!==frame.sessionId||!epoch(String(row.credential_epoch)))throw deny('SESSION_EXPIRED');
  await this.authz.assertCluster(actor.user,cid,'workflows',action,actor.workspaceId!,tx);
  return Object.freeze({sessionId:row.id,credentialEpoch:String(row.credential_epoch),permissionVersion:`${actor.user.id}:${row.permissions_epoch}:${row.iam_version}`});
 }
 /** Presence deliberately includes a closed inherited scope: detached work
  * must fail its original guard, never fall back to ordinary execution reads. */
 receiptReadActive():boolean{return this.receiptReads.getStore()!==undefined;}
 private receiptMaterial(stored:Readonly<WorkflowScheduleStored>):string{return this.secrets.fingerprint({draft:stored.draft,plan:stored.plan});}
 private receiptState(stored:Readonly<WorkflowScheduleStored>,actor:EntityActor,tx:DbService):ReceiptReadState{
  const handle=this.receiptReads.getStore(),state=handle&&this.receiptStates.get(handle),frame=this.context.current();
  if(!state?.active||state.transaction!==tx||state.frame!==frame||state.frameActor!==frame.actor||state.actor!==actor
   ||frame.kind!=='actor'||frame.module!=='workflows'||frame.action!=='read'||frame.operation||frame.archive
   ||frame.sessionId!==state.acceptance.sessionId||frame.actor?.id!==actor.user.id||frame.clusterId!==state.clusterId||frame.workspaceId!==state.workspaceId
   ||actor.workspaceId!==state.workspaceId||stored.draft.scheduleId!==state.scheduleId||stored.plan.clusterId!==state.clusterId
   ||stored.plan.workspaceId!==state.workspaceId||stored.plan.workflowId!==state.workflowId||this.receiptMaterial(stored)!==state.materialHmac)
   throw deny('WORKFLOW_SCHEDULE_ORIGINAL_RECEIPT_SCOPE_REQUIRED');
  return state;
 }
 /** A verifier only; no caller can mint the private token or adopt another
  * frame/SID/plan. This read scope supplies neither execution nor Native proof. */
 async assertReceiptReadScope(stored:Readonly<WorkflowScheduleStored>,actor:EntityActor,tx:DbService):Promise<void>{
  const state=this.receiptState(stored,actor,tx),current=await this.repository.inspectStored(state.scheduleId,tx);
  this.receiptState(current,actor,tx);
  if(this.secrets.fingerprint(await this.acceptance(state.clusterId,actor,tx,'read'))!==this.secrets.fingerprint(state.acceptance))
   throw deny('WORKFLOW_BUSINESS_SCHEDULE_OPERATION_PERMISSIONS_CHANGED');
  if(this.receiptState(stored,actor,tx)!==state)throw deny('WORKFLOW_SCHEDULE_ORIGINAL_RECEIPT_SCOPE_REQUIRED');
 }
 private async receiptRead<T>(id:string,actor:EntityActor,fn:()=>Promise<T>):Promise<T>{
  if(this.receiptReadActive())throw deny('WORKFLOW_SCHEDULE_RECEIPT_SCOPE_NESTING_FORBIDDEN');
  const frame=this.context.current(),stored=await this.repository.inspectStored(id,this.db),cid=stored.plan.clusterId,wid=stored.plan.workspaceId;
  const acceptance=await this.acceptance(cid,actor,this.db,'read');
  if(this.context.current()!==frame||frame.kind!=='actor'||frame.module!=='workflows'||frame.action!=='read'||frame.operation||frame.archive
   ||frame.actor?.id!==actor.user.id||frame.clusterId!==cid||frame.workspaceId!==wid||actor.workspaceId!==wid||stored.draft.scheduleId!==id)
   throw deny('WORKFLOW_SCHEDULE_ORIGINAL_RECEIPT_SCOPE_REQUIRED');
  const handle=Object.freeze({}),state:ReceiptReadState={active:true,frame,frameActor:frame.actor,actor,scheduleId:id,clusterId:cid,workspaceId:wid,
   workflowId:stored.plan.workflowId,materialHmac:this.receiptMaterial(stored),acceptance,transaction:this.db};
  this.receiptStates.set(handle,state);
  return this.receiptReads.run(handle,async()=>{try{await this.assertReceiptReadScope(stored,actor,this.db);const result=await fn();
    await this.assertReceiptReadScope(stored,actor,this.db);return result;
   }finally{state.active=false;}});
 }
 /** Actual SQL load is the sole source of plan/subject selectors. Both
  * identity and the concrete workflow grant are repeated around the fixed
  * Root verifier, including receipt replays after a role/password change. */
 private async operation(cid:string,actor:EntityActor,action:'read'|'write'|'approve',command:WorkflowBusinessScheduleCommand,
  checkpoint:'before'|'after',tx:DbService,workflowIdValue:string,scheduleId?:string):Promise<Readonly<WorkflowBusinessScheduleAcceptance>> {
  const policy=this.operationPolicy(),acceptance=await this.acceptance(cid,actor,tx,action),wid=actor.workspaceId!;
  const receipt=this.receiptReadActive();
  if(receipt&&(action!=='read'||!['read','list','receipt'].includes(command)||!scheduleId))throw deny('WORKFLOW_SCHEDULE_RECEIPT_READ_ONLY');
  const receiptStored=receipt?await this.repository.inspectStored(scheduleId!,tx):null;
  if(receipt)await this.assertReceiptReadScope(receiptStored!,actor,tx);
  // A historical receipt authenticates the immutable repository plan. It must
  // not re-enter Promote/source or executable-subject loading to show a result.
  const loaded=receipt?{plan:receiptStored!.plan,row:{plan_hash:receiptStored!.draft.binding.workflowPlanHash}}:await this.plans.load(cid,wid,workflowIdValue,tx);
  if(typeof loaded.plan.kind==='string'&&loaded.plan.kind.startsWith('portal-credential-'))assertPortalCredentialScheduleKindSupported(loaded.plan.kind);
  if(loaded.plan.clusterId!==cid||loaded.plan.workspaceId!==wid||loaded.plan.workflowId!==workflowIdValue
   ||!['configuration_v2','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'].includes(loaded.plan.kind)||this.secrets.fingerprint(loaded.plan)!==loaded.row.plan_hash)
   throw deny('WORKFLOW_BUSINESS_SCHEDULE_OPERATION_SUBJECT_INVALID');
  const schedule=receiptStored??(scheduleId?await this.repository.inspectStored(scheduleId,tx):null);
  if(schedule&&(schedule.plan.clusterId!==cid||schedule.plan.workspaceId!==wid||schedule.plan.workflowId!==workflowIdValue
   ||this.secrets.fingerprint(schedule.plan)!==this.secrets.fingerprint(loaded.plan)))throw deny('WORKFLOW_BUSINESS_SCHEDULE_OPERATION_SUBJECT_CHANGED');
  const input=Object.freeze({plan:immutableJson(loaded.plan),schedule:schedule?immutableJson(schedule):null,actor,acceptance,action,command,checkpoint,transaction:tx});
  const digest=this.secrets.fingerprint({plan:input.plan,schedule:input.schedule,actorId:actor.user.id,acceptance,action,command,checkpoint});
  await policy.assertOperation(input);
  if(digest!==this.secrets.fingerprint({plan:input.plan,schedule:input.schedule,actorId:actor.user.id,acceptance,action,command,checkpoint}))throw deny('WORKFLOW_BUSINESS_SCHEDULE_OPERATION_CHANGED');
  const currentStored=receipt?await this.repository.inspectStored(scheduleId!,tx):null;
  if(receipt)await this.assertReceiptReadScope(currentStored!,actor,tx);
  const current=receipt?{plan:currentStored!.plan,row:{plan_hash:currentStored!.draft.binding.workflowPlanHash}}:await this.plans.load(cid,wid,workflowIdValue,tx);
  if(current.row.plan_hash!==loaded.row.plan_hash||this.secrets.fingerprint(current.plan)!==this.secrets.fingerprint(input.plan))
   throw deny('WORKFLOW_BUSINESS_SCHEDULE_OPERATION_SUBJECT_CHANGED');
  if(this.secrets.fingerprint(await this.acceptance(cid,actor,tx,action))!==this.secrets.fingerprint(acceptance))throw deny('WORKFLOW_BUSINESS_SCHEDULE_OPERATION_PERMISSIONS_CHANGED');
  return acceptance;
 }
 private original(proof:object,tx:DbService):ProposalState {const s=proof&&this.proposals.get(proof);
  if(!s?.active||s.transaction!==tx||s.expiresAt<=Date.now())throw deny('WORKFLOW_SCHEDULE_ORIGINAL_PROPOSAL_REQUIRED');return s;}
 private proposalDigest(state:Pick<ProposalState,'input'|'plan'|'draft'>):string{return this.secrets.fingerprint({old:state.input.old,basePlan:state.input.basePlan,spec:state.input.spec,
  actor:{id:state.input.actor.user.id,workspaceId:state.input.actor.workspaceId,requestId:state.input.actor.requestId,ip:state.input.actor.ip},acceptance:state.input.acceptance,plan:state.plan,draft:state.draft});}
 private async verifyProposal(proof:object,old:any,plan:Readonly<WorkflowScheduledPlanV1>,draft:Readonly<WorkflowScheduleDraft>,actor:EntityActor,tx:DbService):Promise<void>{
  const state=this.original(proof,tx);if(state.input.actor!==actor||this.secrets.fingerprint(old)!==this.secrets.fingerprint(state.input.old)
   ||this.secrets.fingerprint(plan)!==this.secrets.fingerprint(state.plan)||this.secrets.fingerprint(draft)!==this.secrets.fingerprint(state.draft)
   ||this.proposalDigest(state)!==state.digest)throw deny('WORKFLOW_SCHEDULE_PROPOSAL_CHANGED');
  const current=await this.operation(plan.clusterId,actor,'write','author',state.versionPersisted?'after':'before',tx,plan.workflowId,state.draftPersisted?draft.scheduleId:undefined);if(this.secrets.fingerprint(current)!==this.secrets.fingerprint(state.input.acceptance))throw deny('WORKFLOW_SCHEDULE_AUTHORING_PERMISSIONS_CHANGED');
  await this.redis.assertLeaseOwnership();assertWorkflowScheduledPlan(plan as WorkflowPlanV1,draft,this.secrets);
  await this.installed().assertProposal(Object.freeze({...state.input,plan,draft,checkpoint:state.versionPersisted?'after-version':'before-version'}));
  this.original(proof,tx);if(this.proposalDigest(state)!==state.digest)throw deny('WORKFLOW_SCHEDULE_PROPOSAL_CHANGED');
 }
 private baseRevision(old:WorkflowPlanV1):Readonly<WorkflowPlanV1> {
  if(typeof old.kind==='string'&&old.kind.startsWith('portal-credential-'))assertPortalCredentialScheduleKindSupported(old.kind);
  if((old as any).scheduling!==undefined||!['configuration_v2','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'].includes(old.kind)||!old.approvalRequired)throw changed('WORKFLOW_SCHEDULE_NOT_PENDING_BUSINESS');
  const ids=new Map(old.steps.map(s=>[s.id,randomUUID()])),base=structuredClone(old);base.planRevision=old.planRevision+1;base.issuedAt=new Date().toISOString();
  base.steps=base.steps.map(s=>({...s,id:ids.get(s.id)!,dependencies:s.dependencies.map(id=>ids.get(id)!),
   ...(s.kind==='native'?{mutationIdempotencyKey:`business-${old.workflowId}-${ids.get(s.id)}`}:{})}));
  validateWorkflowPlan(base);return immutableJson(base);
 }
 private async commandReceipt(cid:string,wid:string,actor:EntityActor,keyHmac:string,requestHmac:string,action:string,tx:DbService):Promise<any|null>{
  const old=await tx.one<any>(`SELECT action,after FROM audit_events WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3
   AND action IN('workflow.business-schedule.author.command','workflow.business-schedule.activate.command','workflow.business-schedule.cancel.command')
   AND after->>'keyHmac'=$4 ORDER BY occurred_at,id LIMIT 1`,[cid,wid,actor.user.id,keyHmac]);
  if(!old)return null;if(old.action!==action||old.after?.requestHmac!==requestHmac||!old.after?.receipt||typeof old.after?.scheduleId!=='string')throw changed('IDEMPOTENCY_CONFLICT');
  const scoped=await this.scopedRow(cid,wid,old.after.scheduleId,tx);await this.operation(cid,actor,'read','receipt','before',tx,scoped.workflow_id,old.after.scheduleId);
  await this.repository.get(old.after.scheduleId,actor,tx);await this.operation(cid,actor,'read','receipt','after',tx,scoped.workflow_id,old.after.scheduleId);
  await this.redis.assertLeaseOwnership();return structuredClone(old.after.receipt);
 }
 private keyHmac(cid:string,actor:EntityActor):string{return this.secrets.fingerprint({domain:'workflow-business-schedule-command',cid,wid:actor.workspaceId,actor:actor.user.id,key:workflowKey(actor.idempotencyKey)});}
 /** User supplies only an existing pending workflow pointer and its window.
  * Console owner/executor is always the genuine accepting HTTP principal. */
 async author(clusterId:string,body:unknown,actor:EntityActor):Promise<unknown>{
  const cid=workflowId(clusterId),wid=workflowId(actor.workspaceId),value=portalObject(body,['workflowId','revision','planRevision','planHash','spec','confirmed','confirm_name'],8192);
  portalConfirm(value,'schedule-workflow');const workflow=workflowId(value.workflowId),revision=portalRevision(value.revision),planRevision=portalRevision(value.planRevision);
  if(!hex.test(value.planHash??''))throw new BadRequestException({code:'WORKFLOW_SCHEDULE_PLAN_HASH_REQUIRED'});
  const rawSpec=portalObject(value.spec,['notBefore','windowStart','windowEnd'],4096),spec=normalizeWorkflowScheduleSpec({version:1,...rawSpec,executorId:actor.user.id},actor.user.id);
  const keyHmac=this.keyHmac(cid,actor),requestHmac=this.secrets.fingerprint({cid,wid,actor:actor.user.id,body:value}),action='workflow.business-schedule.author.command';
  return this.scoped(cid,actor,'write',async()=>{
   await this.schema();this.operationPolicy();await this.authz.assertCluster(actor.user,cid,'workflows','write',wid);
   return this.redis.withLock(`business-schedule-command:${keyHmac}`,()=>this.redis.withLock(`workflow:${workflow}`,()=>this.db.transaction(async tx=>{
    await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('business-schedule-command:'||$1,0))",[keyHmac]);
    await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');const accepted=await this.acceptance(cid,actor,tx);
    const replay=await this.commandReceipt(cid,wid,actor,keyHmac,requestHmac,action,tx);if(replay)return replay;
    if(Date.parse(spec.notBefore)<=Date.now()||Date.parse(spec.windowEnd)<=Date.now())throw changed('WORKFLOW_SCHEDULE_WINDOW_EXPIRED');
    const loaded=await this.plans.load(cid,wid,workflow,tx);await this.operation(cid,actor,'write','author','before',tx,workflow);
    await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))",[loaded.plan.scope.transportScope]);
    const row=await tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR UPDATE',[workflow,cid,wid]);
    if(!row||row.revision!==revision||row.plan_revision!==planRevision||row.plan_hash!==value.planHash||row.state!=='pending'
     ||row.approved_by!==null||row.approved_at!==null||row.approval_set_id!=null||Number(row.approval_format)!==2)throw changed('WORKFLOW_SCHEDULE_REVISION_CHANGED');
    if(loaded.row.revision!==row.revision||loaded.row.plan_hash!==row.plan_hash||loaded.plan.requester.type==='console'&&loaded.plan.requester.id!==actor.user.id)throw deny('WORKFLOW_SCHEDULE_CONSOLE_OWNER_REQUIRED');
    if(Date.parse(spec.windowEnd)>Date.parse(loaded.plan.expiresAt))throw changed('WORKFLOW_SCHEDULE_OLD_DEADLINE_NOT_RENEWABLE');
    const basePlan=this.baseRevision(loaded.plan),input:WorkflowBusinessSchedulePrepareInput=Object.freeze({old:immutableJson(loaded),basePlan,spec,actor,acceptance:accepted,transaction:tx});
    const material=await this.installed().prepareRevision(input);
    if(!material||Object.keys(material).sort().join(',')!=='impact,requesterCredentialEpoch,subjectSeal'||!epoch(material.requesterCredentialEpoch)||!validImpact(material.impact)
     ||material.subjectSeal?.subjectId!==basePlan.subject.id)throw deny('WORKFLOW_SCHEDULE_PREPARED_MATERIAL_INVALID');
    if(basePlan.requester.type==='console'&&material.requesterCredentialEpoch!==accepted.credentialEpoch)throw deny('WORKFLOW_SCHEDULE_REQUESTER_EPOCH_CHANGED');
    const requester={...basePlan.requester,credentialEpoch:material.requesterCredentialEpoch},scheduleId=randomUUID(),basePlanHash=this.secrets.fingerprint(basePlan),specHmac=this.secrets.fingerprint(spec),
     impact=immutableJson(material.impact),subjectSeal=immutableJson(material.subjectSeal),impactHmac=this.secrets.fingerprint(impact),delegation={version:1 as const,id:randomUUID(),revision:1 as const,
      clusterId:cid,workspaceId:wid,workflowId:workflow,workflowPlanRevision:basePlan.planRevision,basePlanHash,kind:basePlan.kind as WorkflowScheduledPlanV1['kind'],
      subjectType:basePlan.subject.type as WorkflowScheduleDraft['binding']['subjectType'],subjectId:basePlan.subject.id,subjectSealHmac:this.secrets.fingerprint(subjectSeal),requester,
      ownerId:actor.user.id,executorId:actor.user.id,ownerCredentialEpoch:accepted.credentialEpoch,executorCredentialEpoch:accepted.credentialEpoch,policyHash:basePlan.definition.policyHash,
      specHmac,issuedAt:new Date().toISOString(),expiresAt:basePlan.expiresAt,statement:'execute-this-exact-approved-business-workflow-with-my-current-authority' as const};
    const draft:WorkflowScheduleDraft={binding:{clusterId:cid,workspaceId:wid,workflowId:workflow,workflowPlanRevision:basePlan.planRevision,workflowPlanHash:'0'.repeat(64),basePlanHash,
      kind:delegation.kind,subjectType:delegation.subjectType,subjectId:basePlan.subject.id,requester,definitionId:basePlan.definition.id,definitionVersion:basePlan.definition.version,
      policyHash:basePlan.definition.policyHash,subjectSeal},scheduleId,scheduleVersion:1,occurrenceId:randomUUID(),spec,specHmac,delegation,delegationHmac:this.secrets.fingerprint(delegation),
      transportScope:basePlan.scope.transportScope,impact,impactHmac};
    const plan=immutableJson({...basePlan,scheduling:workflowSchedulePlanSeal(draft)}) as Readonly<WorkflowScheduledPlanV1>;
    const sealedDraft=normalizeWorkflowScheduleDraft({...draft,binding:{...draft.binding,workflowPlanHash:this.secrets.fingerprint(plan)}},this.secrets);
    const proof=Object.freeze({}),state:ProposalState={active:true,expiresAt:Math.min(Date.now()+120000,Date.parse(plan.expiresAt)),input,plan,draft:sealedDraft,digest:'',versionPersisted:false,draftPersisted:false,transaction:tx};
    state.digest=this.proposalDigest(state);this.proposals.set(proof,state);
    try{
     await this.plans.appendScheduledRevision(plan,sealedDraft,actor,proof,tx);if(!state.draftPersisted)throw deny('WORKFLOW_SCHEDULE_DRAFT_NOT_PERSISTED');
     const entity=await this.repository.get(scheduleId,actor,tx),receipt={entity,commandCompleted:true};
     const after={scheduleId,keyHmac,requestHmac,authoringSessionId:accepted.sessionId,receipt};
     const requestId=workflowId(actor.requestId);
     const auditReceipt=await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:wid,workflowId:workflow,entityType:'workflows',entityId:workflow,action,
      result:'success',requestId,ip:actor.ip,after},tx);
     assertKp008BusinessWriteSealed({requestId,actorId:actor.user.id,clusterId:cid,workspaceId:wid,workflowId:workflow,action,
      auditReceiptId:auditReceipt.id,auditEventHash:auditReceipt.eventHash,auditSequence:auditReceipt.sequence,after});
     await this.verifyProposal(proof,loaded,plan,sealedDraft,actor,tx);return receipt;
    }finally{state.active=false;this.proposals.delete(proof);}
   })));
  });
 }
 private async scopedRow(cid:string,wid:string,id:string,tx=this.db):Promise<any>{const row=await tx.one<any>(`SELECT s.id,s.owner_id,s.workflow_id,s.transport_scope,p.revision,p.state,p.claim_id
  FROM workflow_schedules s JOIN workflow_schedule_progress p ON p.schedule_id=s.id WHERE s.id=$1 AND s.cluster_id=$2 AND s.workspace_id=$3`,[id,cid,wid]);
  if(!row)throw new NotFoundException({code:'WORKFLOW_SCHEDULE_NOT_FOUND'});return row;}
 async get(clusterId:string,scheduleId:string,actor:EntityActor):Promise<unknown>{const cid=workflowId(clusterId),wid=workflowId(actor.workspaceId),id=workflowId(scheduleId);
  return this.scoped(cid,actor,'read',async()=>{await this.schema();await this.authz.assertCluster(actor.user,cid,'workflows','read',wid);
   const row=await this.scopedRow(cid,wid,id);return this.receiptRead(id,actor,async()=>{await this.operation(cid,actor,'read','read','before',this.db,row.workflow_id,id);const entity=await this.repository.get(id,actor);
    await this.operation(cid,actor,'read','read','after',this.db,row.workflow_id,id);return{entity};});});}
 async receiptByKey(clusterId:string,key:string,actor:EntityActor):Promise<unknown>{const cid=workflowId(clusterId),wid=workflowId(actor.workspaceId);
  return this.scoped(cid,actor,'read',async()=>{await this.schema();await this.authz.assertCluster(actor.user,cid,'workflows','read',wid);
   const keyHmac=this.secrets.fingerprint({domain:'workflow-business-schedule-command',cid,wid,actor:actor.user.id,key:workflowKey(key)}),old=await this.db.one<any>(`SELECT after FROM audit_events
    WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND action IN('workflow.business-schedule.author.command','workflow.business-schedule.activate.command','workflow.business-schedule.cancel.command')
    AND after->>'keyHmac'=$4 ORDER BY occurred_at,id LIMIT 1`,[cid,wid,actor.user.id,keyHmac]);
   if(!old?.after?.receipt||typeof old.after.scheduleId!=='string')throw new NotFoundException({code:'WORKFLOW_SCHEDULE_RECEIPT_NOT_FOUND'});
   const row=await this.scopedRow(cid,wid,old.after.scheduleId);return this.receiptRead(old.after.scheduleId,actor,async()=>{await this.operation(cid,actor,'read','receipt','before',this.db,row.workflow_id,old.after.scheduleId);
    const entity=await this.repository.get(old.after.scheduleId,actor);await this.operation(cid,actor,'read','receipt','after',this.db,row.workflow_id,old.after.scheduleId);
    // Preserve the original command envelope but return only today's safe
    // repository projection; an audit payload is never a plan/secret source.
    return{entity,commandCompleted:true};});});}
 async list(clusterId:string,query:Record<string,unknown>,actor:EntityActor):Promise<unknown>{const cid=workflowId(clusterId),wid=workflowId(actor.workspaceId),value=portalObject(query,['workspaceId','size','cursor']),size=pageSize(value.size);
  return this.scoped(cid,actor,'read',async()=>{await this.schema();await this.authz.assertCluster(actor.user,cid,'workflows','read',wid);
   const version=await this.authz.permissionVersion(actor.user),binding=this.secrets.fingerprint({domain:'workflow-business-schedules',cid,wid,actor:actor.user.id,version,size}),after=this.cursors.decode(value.cursor,binding);
   if(after&&(Object.keys(after).sort().join(',')!=='id,time'||typeof after.time!=='string'||iso(after.time)!==after.time))throw new BadRequestException({code:'INVALID_CURSOR'});
   const lastId=after?workflowId(after.id):null,rows=await this.db.query<any>(`SELECT id,created_at FROM workflow_schedules WHERE cluster_id=$1 AND workspace_id=$2
    AND($3::timestamptz IS NULL OR(created_at,id)<($3::timestamptz,$4::uuid)) ORDER BY created_at DESC,id DESC LIMIT $5`,[cid,wid,after?.time??null,lastId,size+1]);
   const candidates=rows.slice(0,size),items=[];
   for(const row of candidates)try{const id=workflowId(row.id),scope=await this.scopedRow(cid,wid,id);items.push(await this.receiptRead(id,actor,async()=>{await this.operation(cid,actor,'read','list','before',this.db,scope.workflow_id,id);
    const receipt=await this.repository.get(id,actor);await this.operation(cid,actor,'read','list','after',this.db,scope.workflow_id,id);return receipt;}));
   }catch(e){if(!(e instanceof HttpException&&e.getStatus()===403))throw e;}
   if(await this.authz.permissionVersion(actor.user)!==version)throw deny('PERMISSIONS_CHANGED');
   return{items,size,total:null,nextCursor:rows.length>size?this.cursors.encode(binding,{time:iso(candidates.at(-1)!.created_at),id:candidates.at(-1)!.id}):null};});
 }
 async command(clusterId:string,scheduleId:string,action:'activate'|'cancel',body:unknown,actor:EntityActor):Promise<unknown>{
  if(!['activate','cancel'].includes(action))throw new BadRequestException({code:'UNKNOWN_SCHEDULE_COMMAND'});
  const cid=workflowId(clusterId),wid=workflowId(actor.workspaceId),id=workflowId(scheduleId),value=portalObject(body,['revision','confirmed','confirm_name'],4096);
  portalRevision(value.revision);portalConfirm(value,`${action}-schedule`);const keyHmac=this.keyHmac(cid,actor),requestHmac=this.secrets.fingerprint({cid,wid,id,action,actor:actor.user.id,body:value}),auditAction=`workflow.business-schedule.${action}.command`;
  return this.scoped(cid,actor,'read',async()=>{await this.schema();await this.authz.assertCluster(actor.user,cid,'workflows','read',wid);
   const scope=await this.scopedRow(cid,wid,id);await this.operation(cid,actor,'read',action,'before',this.db,scope.workflow_id,id);
   await this.repository.get(id,actor);await this.operation(cid,actor,'read',action,'after',this.db,scope.workflow_id,id);
   return this.redis.withLock(`business-schedule-command:${keyHmac}`,()=>this.db.transaction(async tx=>{
    await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('business-schedule-command:'||$1,0))",[keyHmac]);
    const replay=await this.commandReceipt(cid,wid,actor,keyHmac,requestHmac,auditAction,tx);if(replay)return replay;
    const first=await this.scopedRow(cid,wid,id,tx),mode=action==='activate'&&first.owner_id!==actor.user.id?'approve':'write';
    return this.scoped(cid,actor,mode,async()=>{
     await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');await this.operation(cid,actor,mode,action,'before',tx,first.workflow_id,id);
     const version=await this.authz.permissionVersion(actor.user,tx);
     await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-schedule-impact:'||$1,0))",[first.transport_scope]);
     await tx.one('SELECT schedule_id FROM workflow_schedule_progress WHERE schedule_id=$1 FOR UPDATE',[id]);const current=await this.scopedRow(cid,wid,id,tx);
     if(current.revision!==value.revision)throw changed('REVISION_CONFLICT');
     const entity=action==='activate'?await this.authority.activateApproved(id,actor,tx):await this.repository.cancel(id,actor,tx),receipt={entity,commandCompleted:true};
     const after={scheduleId:id,keyHmac,requestHmac,receipt};
     const requestId=workflowId(actor.requestId);
     const auditReceipt=await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:wid,workflowId:current.workflow_id,entityType:'workflows',entityId:current.workflow_id,
      action:auditAction,result:'success',requestId,ip:actor.ip,before:{scheduleId:id,revision:current.revision,state:current.state},after},tx);
     assertKp008BusinessWriteSealed({requestId,actorId:actor.user.id,clusterId:cid,workspaceId:wid,workflowId:current.workflow_id,action:auditAction,
      auditReceiptId:auditReceipt.id,auditEventHash:auditReceipt.eventHash,auditSequence:auditReceipt.sequence,after});
     await this.operation(cid,actor,mode,action,'after',tx,current.workflow_id,id);
     if(await this.authz.permissionVersion(actor.user,tx)!==version)throw deny('PERMISSIONS_CHANGED');await this.redis.assertLeaseOwnership();return receipt;
    });
   }));
  });
 }
}
