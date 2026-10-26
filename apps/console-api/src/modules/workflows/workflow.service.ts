import { isSupportedKong } from '../../infrastructure/kong/kong-capabilities';
import { BadRequestException, ConflictException, ForbiddenException, HttpException, Inject, Injectable, Logger, NotFoundException, Optional } from '@nestjs/common';
import { randomBytes, randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { AuditService } from '../audit/audit.service';
import { selfApprovalPermitted } from './workflow-approval-authority.service';
import { EntityService } from '../entities/entities.service';
import { type EntityActor, credentialKind, entityType, pageSize } from '../entities/entities.types';
import { MutationService, type MutationContext } from '../mutations/mutation.service';
import { IamMutationsService } from '../iam/iam-mutations.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { ApprovedWorkflowExecutionService } from './approved-workflow-execution.service';
import { PORTAL_AUTH_BOUNDARY, type PortalAuthBoundaryPolicy } from './approved-execution.types';
import { workflowMetadataProjection, WorkflowPlansService } from './workflow-plans.service';
import { WorkflowRegistryService } from './workflow-registry.service';
import { ConfigurationUnknownResultReconcileService } from './configuration-unknown-result-reconcile.service';
import { snapshotAad, type WorkflowPlanV1, type WorkflowStep, type WorkflowSummary, type WorkflowReceipt, type WorkflowSnapshotV1, type EntityChangeExecutorDelegate } from './workflow.types';
import { workflowId, workflowKey } from './workflow-validation';
import { decodeTag } from '../../infrastructure/kong/tags';
import { WorkspaceMigrationService } from '../workspaces/workspace-migration.service';
import type { WorkspaceMigrationMaterial } from '../workspaces/workspace-migration.service';
import { assertWorkspaceMigrationWorkflowPlan, type WorkspaceMigrationWorkflowPayload } from './workspace-migration-workflow';
import { WorkspaceMigrationWorkflowRecoveryService } from './workspace-migration-workflow-recovery.service';
import { PortalCursor, portalConfirm, portalObject, portalRevision, requirePortalCas } from '../portal/portal-input';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { coarseGrantMatches, grantMatchesEntity, validGrant } from '../authorization/grant-policy';
import { decodePublicationProof } from '../portal/portal-proof';
import { validateRejectedIssuePlan } from '../portal/portal-rejected-issue-plan';
import { restoreUnusedPortalCredentialChange } from '../portal/portal-grant-lifecycle';
import { loadRejectedIssueAbandonmentFacts, getRejectedIssueAbandonment, persistRejectedIssueAbandonment, type RejectedIssueProofV1 } from '../portal/portal-failed-issue-abandonment';
import { assertEventWorkflowPlan, eventExecutionAuditProof, eventMetadataProjection } from './event-workflow';
import { assertGovernanceMetadataPlan, governanceMetadataProjection } from '../governance/governance-workflow';
import { WorkflowApprovalAuthorityService } from './workflow-approval-authority.service';
import { assertWorkflowPolicyMetadataPlan, workflowPolicyMetadataProjection } from './workflow-policy-metadata';
import { WorkflowBusinessExecutionService, type WorkflowBusinessScheduledDelegate } from './workflow-business-execution.service';
import type { WorkflowScheduleTerminalOutcome } from './workflow-schedule.contract';
import { assertControlMetadataPlan } from '../control-plane/control-metadata-plan';
import type { ControlMetadataCompletionDelegate } from '../control-plane/control-metadata.types';
import type { IamMetadataCompletionDelegate } from '../iam/iam-workflow.types';
import type { MetricsSetupExecutionDelegate } from '../vitals/vitals-setup.types';
import { metricsSetupPublicProjection } from '../vitals/vitals-setup-plan';
import { assertEntityAnnotationPlan } from '../annotations/entity-annotation-workflow-plan';
import type { EntityAnnotationCompletionDelegate } from '../annotations/entity-annotation-workflow.types';

const abandonmentSqlStates=new Set(['42501','23514','23505','40001','40P01','55P03','57014','08003','08006','57P01','XX000']);
const logScopeUuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

@Injectable()
export class WorkflowService {
  private readonly logger=new Logger(WorkflowService.name);
  private readonly cursors=new PortalCursor();
  private entityExecutor?:Readonly<EntityChangeExecutorDelegate>;
  private iamCompletion?:Readonly<IamMetadataCompletionDelegate>;
  private controlCompletion?:Readonly<ControlMetadataCompletionDelegate>;
  private annotationCompletion?:Readonly<EntityAnnotationCompletionDelegate>;
  installEntityAnnotationCompletionDelegate(delegate:EntityAnnotationCompletionDelegate):void {
    const names=['verifyMetadataCompletion','terminalReceipt','reviewPreview'] as const;
    if(this.annotationCompletion||!delegate||names.some(key=>typeof delegate[key]!=='function')||Object.keys(delegate).some(key=>!names.includes(key as any)))throw new Error('Entity annotation requires one fixed completion delegate');
    this.annotationCompletion=Object.freeze({verifyMetadataCompletion:delegate.verifyMetadataCompletion.bind(delegate),terminalReceipt:delegate.terminalReceipt.bind(delegate),reviewPreview:delegate.reviewPreview.bind(delegate)});
  }
  installControlMetadataCompletionDelegate(delegate:ControlMetadataCompletionDelegate):void {
    const names=['verifyMetadataCompletion','terminalReceipt','reviewPreview'] as const;
    if(this.controlCompletion||!delegate||names.some(key=>typeof delegate[key]!=='function')||Object.keys(delegate).some(key=>!names.includes(key as any)))throw new Error('Control metadata requires one fixed completion delegate');
    this.controlCompletion=Object.freeze({verifyMetadataCompletion:delegate.verifyMetadataCompletion.bind(delegate),terminalReceipt:delegate.terminalReceipt.bind(delegate),reviewPreview:delegate.reviewPreview.bind(delegate)});
  }
  private metricsSetup?:Readonly<MetricsSetupExecutionDelegate>;
  installMetricsSetupExecutionDelegate(delegate:MetricsSetupExecutionDelegate):void{
    if(this.metricsSetup||!delegate||['runManagedNative','nativeWorkspace','reviewPreview'].some(key=>typeof(delegate as any)[key]!=='function'))throw new Error('Metrics setup requires one fixed execution delegate');
    this.metricsSetup=Object.freeze(delegate);
  }
  installIamMetadataCompletionDelegate(delegate:IamMetadataCompletionDelegate):void {
    if(this.iamCompletion||!delegate||typeof delegate.verifyMetadataCompletion!=='function'||typeof delegate.terminalReceipt!=='function'||typeof delegate.reviewPreview!=='function'
      ||Object.keys(delegate).some(key=>!['verifyMetadataCompletion','terminalReceipt','reviewPreview'].includes(key)))throw new Error('IAM metadata requires one fixed completion delegate');
    this.iamCompletion=Object.freeze({verifyMetadataCompletion:delegate.verifyMetadataCompletion.bind(delegate),terminalReceipt:delegate.terminalReceipt.bind(delegate),reviewPreview:delegate.reviewPreview.bind(delegate)});
  }
  private readonly businessExecution: WorkflowBusinessExecutionService;
  installBusinessScheduledDelegate(delegate: WorkflowBusinessScheduledDelegate): void { this.businessExecution.install(delegate); }
  executeBusinessScheduledClaim(originalAuthorityHandle: object, originalNamespaceHandle: object): Promise<object> {
    return this.businessExecution.execute(originalAuthorityHandle, originalNamespaceHandle);
  }
  verifyBusinessScheduledCompletion(originalAuthorityHandle: object, originalCompletion: object, tx: DbService): Promise<WorkflowScheduleTerminalOutcome> {
    return this.businessExecution.verifyCompletion(originalAuthorityHandle, originalCompletion, tx);
  }
  installEntityChangeExecutor(delegate:NonNullable<WorkflowService['entityExecutor']>):void{
    if(this.entityExecutor||!delegate||['canExecute','canPreflight','canRollback','execute','historical','rollbackPrepare','preflight','closeUnsent','reconcileNoSend'].some(key=>typeof (delegate as any)[key]!=='function'))throw new Error('Entity changes require one fixed execution delegate');
    if(delegate.reconcileTerminalMetadata!==undefined&&typeof delegate.reconcileTerminalMetadata!=='function')throw new Error('Entity changes require one fixed execution delegate');
    if(delegate.reconcilePartialRestoreNoSend!==undefined&&typeof delegate.reconcilePartialRestoreNoSend!=='function')throw new Error('Entity changes require one fixed execution delegate');
    if(delegate.reconcileTargetResult!==undefined&&typeof delegate.reconcileTargetResult!=='function')throw new Error('Entity changes require one fixed execution delegate');
    this.entityExecutor=Object.freeze(delegate);
  }
  constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
    private readonly kong:KongService,private readonly execution:KongExecutionContextService,private readonly authz:AuthorizationService,
    private readonly audit:AuditService,private readonly entities:EntityService,private readonly mutations:MutationService,
    private readonly iam:IamMutationsService,private readonly workspaces:WorkspaceResolverService,
    private readonly plans:WorkflowPlansService,private readonly registry:WorkflowRegistryService,private readonly approved:ApprovedWorkflowExecutionService,
    @Inject(PORTAL_AUTH_BOUNDARY) private readonly boundary:PortalAuthBoundaryPolicy,
    @Optional() private readonly migrations?:WorkspaceMigrationService,
    @Optional() private readonly migrationRecovery?:WorkspaceMigrationWorkflowRecoveryService,
    @Optional() private readonly approval?:WorkflowApprovalAuthorityService,
    @Optional() private readonly configurationUnknownResults?:ConfigurationUnknownResultReconcileService){
    this.businessExecution = new WorkflowBusinessExecutionService({db,redis,secrets,context:execution,authz,audit,mutations,plans,registry,approved,
      dispatch:(plan,step,actor)=>this.dispatch(plan,step,actor),mutationContext:(plan,step,actor)=>this.mutationContext(plan,step,actor)});
  }
  private logAbandonmentPersistenceFailure(error:unknown,scope:{clusterId:string;workspaceId:string;workflowId:string;executionId:string;grantId:string}):void{
    const code=error&&typeof error==='object'?(error as {code?:unknown}).code:undefined;
    const sqlState=typeof code==='string'&&abandonmentSqlStates.has(code)?code:undefined;
    const uuidScope=Object.fromEntries(Object.entries({clusterId:scope.clusterId,workspaceId:scope.workspaceId,workflowId:scope.workflowId,executionId:scope.executionId,grantId:scope.grantId}).filter(([,value])=>typeof value==='string'&&logScopeUuid.test(value)));
    this.logger.error({event:'portal.issue.abandon-rejected.persistence-unknown',...uuidScope,category:sqlState?'sql_failure':'unknown_failure',...(sqlState?{sqlState}:{})});
  }
  private withActor<T>(cid:string,actor:EntityActor,action:string,fn:()=>Promise<T>,configuration=false):Promise<T>{return this.execution.runActor({actor:actor.user,clusterId:cid,workspaceId:actor.workspaceId,module:'workflows',action,requestId:actor.requestId,...(configuration?{purpose:'configuration' as const}:{})},fn);}
  private workflowScopeHints(wid:string,id:string) {return{quality:'verified' as const,module:'workflows',subject:{type:'workflows',id},beforeExists:true,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:wid,afterWorkspaceId:wid};}
  private async loadForAction(cid:string,id:string,actor:EntityActor,action:'read'|'write'|'approve') {
    const originalId=workflowId(id),hint=await this.db.one<{kind:string;workspace_id:string}>('SELECT kind,workspace_id FROM workflows WHERE id=$1 AND cluster_id=$2',[originalId,cid]);
    if(hint?.kind==='control-metadata') {
      const loaded=await this.plans.load(cid,hint.workspace_id,originalId);assertControlMetadataPlan(loaded.plan);
      await this.approved.assertControlWorkflowAdmission(loaded.plan,actor,action);
      const ws=await this.workspaces.get(cid,loaded.plan.workspaceId,true);return{ws,loaded};
    }
    if(action==='read')await this.authz.assertCluster(actor.user,cid,'workflows','read',actor.workspaceId);
    const ws=await this.workspaces.resolve(cid,actor.workspaceId),loaded=await this.plans.load(cid,ws.id,originalId);return{ws,loaded};
  }
  private async authorize(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve'){
    if(plan.kind==='entity-annotation')return this.approved.assertEntityAnnotationWorkflowAdmission(plan,actor,action);
    if(plan.kind==='control-metadata')return this.approved.assertControlWorkflowAdmission(plan,actor,action);
    if(plan.kind==='native-change')return this.plans.assertEntityChangeSubject(plan,actor.user.id,action);
    if(plan.kind==='workspace-migration'){assertWorkspaceMigrationWorkflowPlan(plan);return this.approved.assertSubject(plan,actor.user,action);}
    if(plan.kind==='governance-metadata'){assertGovernanceMetadataPlan(plan);return this.approved.assertSubject(plan,actor.user,action);}
    if(plan.kind==='workflow-policy-metadata'){assertWorkflowPolicyMetadataPlan(plan);return this.approved.assertSubject(plan,actor.user,action);}
    if(plan.kind==='configuration_v2')await this.approved.assertConfigurationOrigin(plan,actor.user.id,action);
    const last=[...plan.steps].reverse().find(step=>step.kind==='metadata');if(!last?.handler)throw new ConflictException({code:'WORKFLOW_HANDLER_INVALID'});return this.registry.get(last.handler).authorize(plan,actor,action);
  }
  /** This exact kind/handler branch reads the immutable business row in the
   * same transaction. A lookalike result property or old receipt is not proof. */
  private async eventBusinessResult(value:Record<string,unknown>,plan:WorkflowPlanV1,step:WorkflowStep,actor:EntityActor,executionId:string,before:unknown,tx:DbService):Promise<Record<string,unknown>> {
    assertEventWorkflowPlan(plan);
    const receipt=value.auditReceipt as Record<string,unknown>|undefined,result=value.result;
    const invalid=()=>new ConflictException({code:'EVENT_BUSINESS_AUDIT_INVALID'});
    if(!receipt||typeof receipt.id!=='string'||typeof receipt.eventHash!=='string'||typeof receipt.sequence!=='string'
      ||typeof receipt.occurredAt!=='string'||typeof receipt.chainScope!=='string'||!result||typeof result!=='object'||Array.isArray(result)
      ||Object.keys(value).some(key=>!['result','auditReceipt'].includes(key)))throw invalid();
    const row=await tx.one<any>('SELECT * FROM audit_events WHERE id=$1',[receipt.id]);
    const queued=(result as Record<string,unknown>).queued as Record<string,unknown>|undefined;
    const queueHandler=step.handler==='event.channel.test'||step.handler==='event.delivery.replay';
    if(queueHandler&&(!queued||typeof queued.eventId!=='string'||typeof queued.deliveryId!=='string'))throw invalid();
    if(queueHandler&&(Object.keys(result).some(key=>key!=='queued')||Object.keys(queued!).some(key=>!['eventId','deliveryId','replayGeneration'].includes(key))))throw invalid();
    if(!queueHandler&&queued!==undefined)throw invalid();
    const expectedAfter=this.secrets.redact({result:queueHandler?{queued:true}:result,operationProof:eventExecutionAuditProof(plan,step,executionId,this.secrets.fingerprint(plan))});
    if(!row||row.event_hash!==receipt.eventHash||String(row.sequence)!==receipt.sequence||row.chain_scope!==receipt.chainScope
      ||!Number.isFinite(new Date(row.occurred_at).getTime())||new Date(row.occurred_at).toISOString()!==receipt.occurredAt||row.actor_type!=='user'||row.actor_id!==actor.user.id
      ||row.cluster_id!==plan.clusterId||row.workspace_id!==plan.workspaceId||row.workflow_id!==plan.workflowId
      ||row.entity_type!==step.entityType||row.entity_id!==step.entityId||row.action!==step.handler||row.result!=='success'
      ||this.secrets.fingerprint(row.before)!==this.secrets.fingerprint(this.secrets.redact(eventMetadataProjection(before)))
      ||this.secrets.fingerprint(row.after)!==this.secrets.fingerprint(expectedAfter))throw invalid();
    if(queueHandler){
      const event=await tx.one<any>('SELECT * FROM event_records WHERE id=$1',[queued!.eventId]);
      const delivery=await tx.one<any>('SELECT * FROM event_deliveries WHERE id=$1',[queued!.deliveryId]);
      if(!event||!delivery||event.audit_event_id!==row.id||event.actor_id!==actor.user.id||event.cluster_id!==plan.clusterId||event.workspace_id!==plan.workspaceId
        ||event.source_kind!=='workflow'||event.source_id!==plan.workflowId||event.iam_operation_id!==null
        ||event.event_type!==(step.handler==='event.channel.test'?'channel.test':'delivery.replay')
        ||event.workflow_id!==plan.workflowId||event.workflow_execution_id!==executionId||event.workflow_plan_revision!==plan.planRevision||event.workflow_plan_hash!==this.secrets.fingerprint(plan)||event.workflow_step_id!==step.id
        ||delivery.cluster_id!==plan.clusterId||delivery.workspace_id!==plan.workspaceId||delivery.creator_id!==actor.user.id
        ||delivery.state!=='pending'||delivery.intent_started_at!==null
        ||step.handler==='event.channel.test'&&(delivery.channel_id!==step.entityId||delivery.delivery_kind!=='test'||delivery.subscription_id!==null||delivery.replay_generation!==0||queued!.replayGeneration!==undefined||delivery.event_id!==event.id)
        ||step.handler==='event.delivery.replay'&&(delivery.parent_delivery_id!==step.entityId||delivery.event_id!==(before as Record<string,unknown>).event_id
          ||delivery.channel_id!==(before as Record<string,unknown>).channel_id||delivery.subscription_id!==((before as Record<string,unknown>).subscription_id??null)
          ||!Number.isInteger(queued!.replayGeneration)||Number(queued!.replayGeneration)<1||queued!.replayGeneration!==delivery.replay_generation))throw invalid();
    }
    return result as Record<string,unknown>;
  }
  /** Approver-notification directory (advisory only; every vote is still
   * fully re-authorized by decide()). Format 2 returns null: the caller uses
   * the frozen active-stage candidate manifest. Format 1 has no frozen list and
   * its subject-level check needs an HTTP actor frame, so the directory is the
   * DB-only coarse authority: super admins and holders of a global/workspace
   * workflows:approve grant covering this cluster+workspace, minus the requester. */
  async approvalRecipients(cid:string,wid:string,id:string):Promise<string[]|null>{
    const row=await this.db.one<any>('SELECT id,state,approval_required,approval_format,requester_user_id FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[id,cid,wid]);
    if(!row||row.state!=='pending'||!row.approval_required)return [];
    if(row.approval_format===2)return null;
    const users=await this.db.query<any>("SELECT id,super_admin FROM users WHERE status='active' AND deleted_at IS NULL AND id IS DISTINCT FROM $1 ORDER BY id LIMIT 1000",[row.requester_user_id]);
    const out:string[]=[];
    for(const u of users){if(out.length>=200)break;if(u.super_admin===true){out.push(u.id);continue;}
      const grants=(await this.db.query<any>("SELECT * FROM iam_effective_grants WHERE user_id=$1 AND module='workflows' AND action='approve'",[u.id])).filter(validGrant);
      if(grants.some(g=>['global','workspace'].includes(g.scope_type)&&coarseGrantMatches(g,'workflows','approve',{clusterId:cid,workspaceId:wid})))out.push(u.id);}
    return out;
  }
  private async summary(row:any,plan:WorkflowPlanV1,actor?:EntityActor):Promise<WorkflowSummary>{
    if(row.approval_format===2&&!this.approval)throw new ConflictException({code:'WORKFLOW_APPROVAL_AUTHORITY_UNAVAILABLE'});
    const can=async(action:'read'|'write'|'approve')=>{if(!actor)return false;try{await this.authorize(plan,actor,action);return true;}catch(error){if(error instanceof ForbiddenException)return false;throw error;}};
    const selfRow=!!actor&&row.requester_user_id===actor.user.id;
    let approve=plan.approvalRequired&&row.state==='pending'&&(!selfRow||await selfApprovalPermitted(this.db,actor!.user.id))&&await can('approve'),reject=approve&&!selfRow;
    if(approve&&row.approval_format===2){
      if(!this.approval)throw new ConflictException({code:'WORKFLOW_APPROVAL_AUTHORITY_UNAVAILABLE'});
      const stage=await this.db.one<any>("SELECT level,revision FROM workflow_stages WHERE workflow_id=$1 AND plan_revision=$2 AND state='active'",[row.id,row.plan_revision]);
      const eligible=async(decision:'approve'|'reject')=>{if(!stage||!actor)return false;try{await this.approval!.assertCanVote(plan,{reviewerId:actor.user.id,level:stage.level,stageRevision:stage.revision,candidateVersion:row.candidate_version,decision},this.db);return true;}catch(error){if(error instanceof ForbiddenException||error instanceof ConflictException)return false;throw error;}};
      approve=await eligible('approve');reject=await eligible('reject');
    }
    const recoveryExecution=actor&&plan.kind==='portal-credential-issue'&&row.state==='uncertain'?await this.db.one<any>('SELECT id FROM workflow_executions WHERE workflow_id=$1 AND plan_revision=$2 AND execution_actor_id=$3',[row.id,row.plan_revision,actor.user.id]):null;
    const migrationRecovery=actor&&plan.kind==='workspace-migration'&&['uncertain','partial'].includes(row.state)?await this.migrationRecovery?.projection(row.cluster_id,row.workspace_id,row.id,actor):undefined;
    const reconcileMetadata=!!recoveryExecution&&await this.approved.canIssueActivationRecovery(recoveryExecution.id)||migrationRecovery?.eligible===true;
    const rejectedExecution=actor&&plan.kind==='portal-credential-issue'&&row.state==='failed'?await this.db.one<any>('SELECT * FROM workflow_executions WHERE workflow_id=$1 AND plan_revision=$2 AND execution_actor_id=$3',[row.id,row.plan_revision,actor.user.id]):null;
    const abandonRejectedIssue=!!rejectedExecution&&!!actor&&await this.canAbandonRejectedIssue(plan,rejectedExecution,actor);
    const executable=!(plan as WorkflowPlanV1 & {scheduling?:unknown}).scheduling&&(row.state==='approved'||!row.approval_required&&row.state==='pending')&&await can('write');
    const nativeExecutable=plan.kind==='native-change'&&executable&&actor?(await this.entityExecutor?.canExecute(plan,actor))===true:false;
    const nativeWriteAllowed=plan.kind==='native-change'&&!!actor&&(executable||await can('write'));
    const entityPreflight=nativeWriteAllowed&&actor?(await this.entityExecutor?.canPreflight(plan,actor))===true:false;
    // A terminal state cannot prove a usable baseline or resolved outcomes.
    // Root's read-only verifier checks their real source/packet facts and grants.
    const rollbackPrepare=nativeWriteAllowed&&actor?(await this.entityExecutor?.canRollback(plan,actor))===true:false;
    return{id:row.id,kind:row.kind,clusterId:row.cluster_id,workspaceId:row.workspace_id,...(row.self_approved===true?{selfApproved:true}:{}),...(plan.kind==='control-metadata'&&actor?{scopeSelectorWorkspaceId:actor.workspaceId??plan.workspaceId}:{}),name:row.kind,revision:row.revision,planRevision:row.plan_revision,planHash:row.plan_hash,state:row.state,executionMode:row.execution_mode,approvalRequired:row.approval_required,createdAt:new Date(row.created_at).toISOString(),expiresAt:new Date(row.expires_at).toISOString(),...((plan as WorkflowPlanV1&{scheduling?:unknown}).scheduling?{scheduled:true as const}:{}),...(row.approval_format===2?{approval:await this.approval!.projection(plan)}:{}),capabilities:Object.freeze({approve,reject,cancel:['pending','approved'].includes(row.state)&&row.requester_user_id===actor?.user.id,execute:plan.kind==='native-change'?nativeExecutable:executable,reconcileMetadata,abandonRejectedIssue,entityPreflight,rollbackPrepare})};
  }
  async get(cid:string,id:string,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    const terminal=await this.db.one<any>("SELECT workspace_id FROM workflows WHERE id=$1 AND cluster_id=$2 AND kind='control-metadata' AND state='succeeded' AND requester_user_id=$3",[workflowId(id),cid,actor.user.id]);
    if(terminal) {
      const closed=await this.plans.load(cid,terminal.workspace_id,workflowId(id));assertControlMetadataPlan(closed.plan);
      if(!this.controlCompletion)throw new ConflictException({code:'CONTROL_METADATA_COMPLETION_UNAVAILABLE'});
      const receipt=await this.controlCompletion.terminalReceipt(closed.plan,actor);
      return{entity:{id:closed.plan.workflowId,kind:closed.plan.kind,clusterId:cid,workspaceId:closed.plan.workspaceId,scopeSelectorWorkspaceId:actor.workspaceId??closed.plan.workspaceId,name:closed.plan.kind,revision:receipt.revision,planRevision:closed.plan.planRevision,planHash:receipt.planHash,state:receipt.state,executionMode:'approval',approvalRequired:true,createdAt:closed.row.created_at,expiresAt:closed.plan.expiresAt,capabilities:{approve:false,reject:false,cancel:false,execute:false}},diff:[],impact:{nativeRequests:0},steps:receipt.steps,decisions:[]};
    }
    const{ws,loaded}=await this.loadForAction(cid,id,actor,'read');await this.authorize(loaded.plan,actor,'read');
    const steps=await this.db.query<any>('SELECT id,step_key,step_order,kind,state,operation_id,recycle_entry_id,safe_result,error_code FROM workflow_steps WHERE workflow_id=$1 ORDER BY step_order',[id]);
    const decisions=await this.db.query<any>('SELECT approver_id,decision,reason,decided_at,level,candidate_version FROM workflow_approvals WHERE workflow_id=$1 AND plan_revision=$2 ORDER BY decided_at',[id,loaded.row.plan_revision]);
    let iamReview:Record<string,unknown>|undefined;
    if(loaded.plan.kind==='iam-metadata') {
      if(!this.iamCompletion)throw new ConflictException({code:'IAM_METADATA_COMPLETION_UNAVAILABLE'});
      iamReview=await this.iamCompletion.reviewPreview(loaded.plan,actor);
    }
    if(loaded.plan.kind==='control-metadata') {
      if(!this.controlCompletion)throw new ConflictException({code:'CONTROL_METADATA_COMPLETION_UNAVAILABLE'});
      iamReview=await this.controlCompletion.reviewPreview(loaded.plan,{...actor,workspaceId:loaded.plan.workspaceId});
    }
    if(loaded.plan.kind==='metrics-setup') {
      if(!this.metricsSetup)throw new ConflictException({code:'METRICS_SETUP_EXECUTION_UNAVAILABLE'});
      iamReview=await this.metricsSetup.reviewPreview(loaded.plan,actor);
    }
    if(loaded.plan.kind==='entity-annotation') {
      if(!this.annotationCompletion)throw new ConflictException({code:'ENTITY_ANNOTATION_COMPLETION_UNAVAILABLE'});
      iamReview=await this.annotationCompletion.reviewPreview(loaded.plan,actor);
    }
    await this.authorize(loaded.plan,actor,'read');return{entity:await this.summary(loaded.row,loaded.plan,actor),diff:this.secrets.redact(iamReview?.diff??loaded.version.safe_diff),impact:this.secrets.redact(iamReview?{...loaded.version.safe_impact,...(iamReview.impact&&typeof iamReview.impact==='object'?iamReview.impact:{}),...(iamReview.affectedScopes?{affectedScopes:iamReview.affectedScopes}:{})}:loaded.version.safe_impact),steps:steps.map(step=>({id:step.id,name:step.step_key,order:step.step_order,kind:step.kind,state:step.state,operationId:step.operation_id,recycleEntryId:step.recycle_entry_id,errorCode:step.error_code})),decisions,
      ...(loaded.plan.kind==='native-change'&&this.entityExecutor?{nativeChange:await this.entityExecutor.historical(loaded.plan,actor)}:{})};
  });}
  async list(cid:string,query:Record<string,unknown>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    portalObject(query,['workspaceId','size','cursor','state','view']);await this.authz.assertCluster(actor.user,cid,'workflows','read',actor.workspaceId);const ws=actor.workspaceId?await this.workspaces.get(cid,actor.workspaceId,true):await this.workspaces.resolve(cid),size=pageSize(query.size),version=await this.authz.permissionVersion(actor.user);
    if(query.state!==undefined&&!['pending','approved','executing','succeeded','partial','failed','uncertain','rejected','cancelled','expired'].includes(String(query.state)))throw new BadRequestException({code:'INVALID_WORKFLOW_STATE'});
    if(query.view!==undefined&&!['submitted','pending-my-approval','all'].includes(String(query.view)))throw new BadRequestException({code:'INVALID_WORKFLOW_VIEW'});
    const binding=this.secrets.fingerprint({cid,wid:ws.id,actor:actor.user.id,version,size,state:query.state??null,view:query.view??'all'}),offset=this.cursors.decode(query.cursor,binding)?.offset??0;
    if(!Number.isInteger(offset)||offset<0)throw new BadRequestException({code:'INVALID_CURSOR'});
    const rows=await this.db.query<any>(`SELECT * FROM workflows w WHERE cluster_id=$1 AND (workspace_id=$2 OR (kind='control-metadata' AND EXISTS(SELECT 1 FROM control_change_intents i WHERE i.id=w.subject_id AND i.workflow_id=w.id AND i.cluster_id=w.cluster_id AND i.resource='workspaces' AND i.resource_id=$2))) AND ($8::boolean=false OR kind='control-metadata') AND ($3::text IS NULL OR state=$3) AND ($4::text<>'submitted' OR requester_user_id=$5) ORDER BY created_at DESC,id DESC LIMIT $6 OFFSET $7`,[cid,ws.id,query.state??null,query.view??'all',actor.user.id,size,offset,ws.status==='deleted']);
    const items=[];for(const row of rows){
      // Invalid sealed plans remain fatal. Only current domain scope changes
      // are filtered below; they never authorize a historical write.
      const {plan}=await this.plans.load(cid,row.workspace_id,row.id);
      try{
        if(plan.kind==='control-metadata'&&row.state==='succeeded'&&row.requester_user_id===actor.user.id&&query.view!=='pending-my-approval'){
          assertControlMetadataPlan(plan);
          if(!this.controlCompletion)throw new ConflictException({code:'CONTROL_METADATA_COMPLETION_UNAVAILABLE'});
          const receipt=await this.controlCompletion.terminalReceipt(plan,actor);
          items.push({id:plan.workflowId,kind:plan.kind,clusterId:cid,workspaceId:plan.workspaceId,scopeSelectorWorkspaceId:actor.workspaceId??plan.workspaceId,
            name:plan.kind,revision:receipt.revision,planRevision:plan.planRevision,planHash:receipt.planHash,state:receipt.state,executionMode:'approval',approvalRequired:true,
            createdAt:row.created_at,expiresAt:plan.expiresAt,capabilities:{approve:false,reject:false,cancel:false,execute:false}});
          continue;
        }
        await this.authorize(plan,actor,query.view==='pending-my-approval'?'approve':'read');
        if(query.view==='pending-my-approval'&&(row.state!=='pending'||!row.approval_required||row.requester_user_id===actor.user.id&&!await selfApprovalPermitted(this.db,actor.user.id)))continue;
        const item=await this.summary(row,plan,actor);if(query.view==='pending-my-approval'&&!item.capabilities.approve&&!item.capabilities.reject)continue;items.push(item);
      }catch(error){
        const response=error instanceof ConflictException?error.getResponse():null;
        const code=response&&typeof response==='object'&&'code' in response?response.code:null;
        if(error instanceof ForbiddenException)continue;
        if(plan.kind==='control-metadata'&&['CONTROL_SCOPE_CHANGED','CONTROL_APPROVAL_SCOPE_REQUIRED','CONTROL_ANCHOR_WORKSPACE_REQUIRED'].includes(String(code)))continue;
        // A stale IAM change (its before-graph moved on, or it expired) can no longer be approved; it must not poison the whole list.
        if(plan.kind==='iam-metadata'&&query.view==='pending-my-approval'&&['IAM_WORKFLOW_METADATA_CHANGED','IAM_CHANGE_INTENT_EXPIRED_OR_CHANGED'].includes(String(code)))continue;
        throw error;
      }
    }
    if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    return{items,size,total:null,nextCursor:rows.length===size?this.cursors.encode(binding,{offset:offset+size}):null};
  });}
  async decide(cid:string,id:string,decision:'approve'|'reject',body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'approve',async()=>{
    const value=portalObject(body,['revision','planHash','reason','confirmed','confirm_name','execute','level','stageRevision','candidateVersion']),key=workflowKey(actor.idempotencyKey),{ws,loaded}=await this.loadForAction(cid,id,actor,'approve');
    await this.authorize(loaded.plan,actor,'approve');portalConfirm(value,loaded.row.kind);portalRevision(value.revision);
    if(loaded.row.approval_format!==2&&['level','stageRevision','candidateVersion'].some(field=>Object.hasOwn(value,field)))throw new BadRequestException({code:'INVALID_WORKFLOW_DECISION'});
    if(loaded.row.approval_format===2&&(!Number.isInteger(value.level)||Number(value.level)<1||Number(value.level)>8||!Number.isInteger(value.stageRevision)||Number(value.stageRevision)<1||!Number.isInteger(value.candidateVersion)||Number(value.candidateVersion)<1))throw new BadRequestException({code:'WORKFLOW_APPROVAL_STAGE_REQUIRED'});
    const replayDecision=await this.db.one<any>('SELECT * FROM workflow_approvals WHERE cluster_id=$1 AND workspace_id=$2 AND approver_id=$3 AND idempotency_key=$4',[cid,ws.id,actor.user.id,key]);
    if(replayDecision){const event=await this.db.one<any>("SELECT safe_metadata FROM workflow_events WHERE workflow_id=$1 AND actor_id=$2 AND action=$3 AND safe_metadata->>'key'=$4 ORDER BY created_at DESC LIMIT 1",[id,actor.user.id,`decision.${decision}`,key]);if(replayDecision.workflow_id!==id||replayDecision.decision!==decision||event?.safe_metadata?.requestHash!==this.secrets.fingerprint(value))throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});return {entity:await this.summary(loaded.row,loaded.plan,actor),decisionCompleted:true};}
    if(typeof value.planHash!=='string'||value.planHash!==loaded.row.plan_hash||value.revision!==loaded.row.revision)throw new ConflictException({code:'WORKFLOW_PLAN_CHANGED'});
    const selfVote=loaded.row.requester_user_id===actor.user.id;
    if(!loaded.plan.approvalRequired||selfVote&&(decision!=='approve'||!await selfApprovalPermitted(this.db,actor.user.id)))throw new ForbiddenException({code:'WORKFLOW_SELF_APPROVAL_FORBIDDEN'});
    if(loaded.plan.kind==='native-change'&&decision==='approve')await this.plans.revalidateEntityChange(loaded.plan,actor,'approve');
    const reason=typeof value.reason==='string'?value.reason.trim().slice(0,2048):'';
    await this.redis.withLock(`workflow:${id}`,()=>this.db.transaction(async tx=>{
      await this.authorize(loaded.plan,actor,'approve');const current=await tx.one<any>('SELECT * FROM workflows WHERE id=$1 FOR UPDATE',[id]);
      const previous=await tx.one<any>('SELECT * FROM workflow_approvals WHERE cluster_id=$1 AND workspace_id=$2 AND approver_id=$3 AND idempotency_key=$4',[cid,ws.id,actor.user.id,key]);
      if(previous){if(previous.workflow_id!==id||previous.plan_hash!==value.planHash||previous.decision!==decision)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});return;}
      if(!current||current.state!=='pending'||current.revision!==value.revision||current.plan_hash!==value.planHash||Date.parse(current.expires_at)<=Date.now())throw new ConflictException({code:'WORKFLOW_NOT_APPROVABLE'});
      let decisionResultState=decision==='approve'?'approved':'rejected';
      if(current.approval_format===2){
        if(!this.approval)throw new ConflictException({code:'WORKFLOW_APPROVAL_AUTHORITY_UNAVAILABLE'});
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
        const vote={reviewerId:actor.user.id,level:Number(value.level),stageRevision:Number(value.stageRevision),candidateVersion:Number(value.candidateVersion),decision};
        await this.approval.assertCanVote(loaded.plan,vote,tx);if(decision==='approve')await this.approval.assertVoteFeasible(loaded.plan,actor.user.id,vote.level,tx);
        await tx.exec(`INSERT INTO workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,approver_id,decision,reason,request_id,idempotency_key,candidate_version,candidate_manifest_hmac,stage_revision,is_self_approval) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,[cid,ws.id,id,current.plan_revision,current.plan_hash,vote.level,actor.user.id,decision,reason,actor.requestId??null,key,vote.candidateVersion,current.candidate_manifest_hmac,vote.stageRevision,selfVote]);
        const stage=await tx.one<any>('SELECT required_approvals FROM workflow_stages WHERE workflow_id=$1 AND plan_revision=$2 AND level=$3 FOR UPDATE',[id,current.plan_revision,vote.level]);
        const count=await tx.one<any>("SELECT count(*)::integer AS votes FROM workflow_approvals WHERE workflow_id=$1 AND plan_revision=$2 AND level=$3 AND decision='approve'",[id,current.plan_revision,vote.level]);
        const complete=decision==='approve'&&count?.votes===stage?.required_approvals;
        requirePortalCas(await tx.exec("UPDATE workflow_stages SET state=$2,revision=revision+1,completed_at=CASE WHEN $2='active' THEN NULL ELSE now() END,updated_at=now() WHERE workflow_id=$1 AND plan_revision=$3 AND level=$4 AND state='active' AND revision=$5",[id,decision==='reject'?'rejected':complete?'approved':'active',current.plan_revision,vote.level,vote.stageRevision]));
        let state='pending';
        if(decision==='reject'){state='rejected';await tx.exec("UPDATE workflow_stages SET state='skipped',revision=revision+1,completed_at=now(),updated_at=now() WHERE workflow_id=$1 AND plan_revision=$2 AND state='pending'",[id,current.plan_revision]);}
        else if(complete){
          const next=await tx.one<any>('SELECT level,revision FROM workflow_stages WHERE workflow_id=$1 AND plan_revision=$2 AND level=$3 AND state=\'pending\'',[id,current.plan_revision,vote.level+1]);
          if(next)requirePortalCas(await tx.exec("UPDATE workflow_stages SET state='active',revision=revision+1,activated_at=now(),updated_at=now() WHERE workflow_id=$1 AND plan_revision=$2 AND level=$3 AND revision=$4 AND state='pending'",[id,current.plan_revision,next.level,next.revision]));
          else{await this.approval.sealApprovalSet(loaded.plan,tx);state='approved';}
        }
        requirePortalCas(await tx.exec('UPDATE workflows SET state=$2,approved_by=$3,approved_at=$4,self_approved=$6,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$5',[id,state,state==='approved'?actor.user.id:null,state==='approved'?new Date():null,current.revision,state==='approved'&&selfVote]));
        decisionResultState=state;
      }else{
      await tx.exec(`INSERT INTO workflow_approvals(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,approver_id,decision,reason,request_id,idempotency_key,is_self_approval) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11)`,[cid,ws.id,id,current.plan_revision,current.plan_hash,actor.user.id,decision,reason,actor.requestId??null,key,selfVote]);
      await tx.exec("UPDATE workflow_stages SET state=$2,completed_at=now(),updated_at=now() WHERE workflow_id=$1 AND plan_revision=$3",[id,decision==='approve'?'approved':'rejected',current.plan_revision]);
      requirePortalCas(await tx.exec(`UPDATE workflows SET state=$2,approved_by=$3,approved_at=$4,self_approved=$6,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$5`,[id,decision==='approve'?'approved':'rejected',decision==='approve'?actor.user.id:null,decision==='approve'?new Date():null,current.revision,decision==='approve'&&selfVote]));
      }
      await tx.exec(`INSERT INTO workflow_events(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,actor_type,actor_id,action,result,safe_metadata,request_id) VALUES($1,$2,$3,$4,$5,'user',$6,$7,'success',$8::jsonb,$9)`,[cid,ws.id,id,current.plan_revision,current.plan_hash,actor.user.id,`decision.${decision}`,JSON.stringify({key,requestHash:this.secrets.fingerprint(value)}),actor.requestId??null]);
      const action=current.approval_format===2&&decision==='approve'&&decisionResultState!=='approved'?'workflow.approval.progress':`workflow.${decision}`;
      await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'workflows',entityId:id,workflowId:id,action,requestId:actor.requestId,ip:actor.ip,after:{planHash:current.plan_hash,reason,...(selfVote?{selfApproval:true,selfApprovalOverride:'super_admin'}:{}),...(current.approval_format===2?{level:Number(value.level),stageState:(await tx.one<any>('SELECT state FROM workflow_stages WHERE workflow_id=$1 AND plan_revision=$2 AND level=$3',[id,current.plan_revision,Number(value.level)]))?.state,workflowState:decisionResultState}:{})},result:'success',scopeHints:this.workflowScopeHints(ws.id,id)},tx);
      if(decision==='reject'&&decisionResultState==='rejected')await restoreUnusedPortalCredentialChange(tx,{clusterId:cid,workspaceId:ws.id,workflowId:id,kind:loaded.plan.kind,workflowTerminal:'rejected'});
    }));
    const updated=await this.plans.load(cid,ws.id,id);if(decision==='approve'&&value.execute===true&&updated.row.state==='approved'&&!(updated.plan as WorkflowPlanV1 & {scheduling?:unknown}).scheduling)return this.execute(cid,id,{revision:updated.row.revision,planHash:updated.row.plan_hash,confirmed:true,confirm_name:updated.row.kind},{...actor,idempotencyKey:`execute-${this.secrets.fingerprint({key,id}).slice(0,48)}`});return{entity:await this.summary(updated.row,updated.plan,actor)};
  });}
  async cancel(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const value=portalObject(body,['revision','confirmed','confirm_name']),key=workflowKey(actor.idempotencyKey),{ws,loaded}=await this.loadForAction(cid,id,actor,'write');
    // Cancelling is de-escalating: an IAM change stays cancellable by its requester from any live session and after its before-graph moved on;
    // execution keeps the authoring-session and freshness checks.
    const cancelAction=loaded.plan.kind==='iam-metadata'?'read':'write';await this.authorize(loaded.plan,actor,cancelAction);portalConfirm(value,loaded.row.kind);portalRevision(value.revision);
    if(loaded.row.requester_user_id!==actor.user.id)throw new ForbiddenException({code:'WORKFLOW_REQUESTER_REQUIRED'});
    return this.redis.withLock(`workflow-decision:${actor.user.id}:${cid}:${ws.id}:${key}`,()=>this.redis.withLock(`workflow:${id}`,()=>this.db.transaction(async tx=>{
      const old=await tx.one<any>("SELECT workflow_id,safe_metadata FROM workflow_events WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND action='decision.cancel' AND safe_metadata->>'key'=$4",[cid,ws.id,actor.user.id,key]);
      if(old){if(old.workflow_id!==id||old.safe_metadata?.requestHash!==this.secrets.fingerprint(value))throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});return{entity:await this.summary((await this.plans.load(cid,ws.id,id,tx)).row,loaded.plan,actor),decisionCompleted:true};}
      const collision=await tx.one<any>(`SELECT id FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND requester_user_id=$3 AND idempotency_key=$4 UNION ALL SELECT id FROM workflow_approvals WHERE cluster_id=$1 AND workspace_id=$2 AND approver_id=$3 AND idempotency_key=$4 LIMIT 1`,[cid,ws.id,actor.user.id,key]);if(collision)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});
      const version=await this.authz.permissionVersion(actor.user);await this.authorize(loaded.plan,actor,cancelAction);
      requirePortalCas(await tx.exec("UPDATE workflows SET state='cancelled',cancelled_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND plan_hash=$3 AND state IN ('pending','approved')",[id,value.revision,loaded.row.plan_hash]));
      if(loaded.row.approval_format===2)await tx.exec("UPDATE workflow_stages SET state='skipped',revision=revision+1,completed_at=now(),updated_at=now() WHERE workflow_id=$1 AND plan_revision=$2 AND state IN ('pending','active')",[id,loaded.row.plan_revision]);
      else await tx.exec("UPDATE workflow_stages SET state='skipped',completed_at=now(),updated_at=now() WHERE workflow_id=$1 AND plan_revision=$2 AND state IN ('pending','active','approved')",[id,loaded.row.plan_revision]);
      await tx.exec(`INSERT INTO workflow_events(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,actor_type,actor_id,action,result,safe_metadata,request_id) VALUES($1,$2,$3,$4,$5,'user',$6,'decision.cancel','success',$7::jsonb,$8)`,[cid,ws.id,id,loaded.row.plan_revision,loaded.row.plan_hash,actor.user.id,JSON.stringify({key,requestHash:this.secrets.fingerprint(value)}),actor.requestId??null]);
      await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'workflows',entityId:id,workflowId:id,action:'workflow.cancel',result:'success',requestId:actor.requestId,ip:actor.ip,scopeHints:this.workflowScopeHints(ws.id,id)},tx);await restoreUnusedPortalCredentialChange(tx,{clusterId:cid,workspaceId:ws.id,workflowId:id,kind:loaded.plan.kind,workflowTerminal:'cancelled'});await this.redis.assertLeaseOwnership();if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
      return{entity:await this.summary((await this.plans.load(cid,ws.id,id,tx)).row,loaded.plan,actor),decisionCompleted:true};
    })));
  });}
  private mutationContext(plan:WorkflowPlanV1,step:WorkflowStep,actor:EntityActor):MutationContext{return{clusterId:plan.clusterId,workspaceId:plan.workspaceId,actor:actor.user,entityType:step.entityType,entityId:step.mutationAction==='create'?undefined:step.entityId,action:step.mutationAction!,idempotencyKey:step.mutationIdempotencyKey,requestId:actor.requestId,ip:actor.ip,before:step.before,payload:step.mutationPayload,parentId:step.parentId,credentialKind:step.credentialKind};}
  private async dispatch(plan:WorkflowPlanV1,step:WorkflowStep,actor:EntityActor):Promise<any>{
    const child={...actor,workspaceId:plan.workspaceId,idempotencyKey:step.mutationIdempotencyKey},query={workspaceId:plan.workspaceId};
    const payload:any=structuredClone(step.mutationPayload);if(Array.isArray(payload?.tags))payload.tags=payload.tags.map(decodeTag);
    if(plan.kind==='workspace-migration'){
      const fixed=assertWorkspaceMigrationWorkflowPlan(plan),migration=fixed.mutationPayload as WorkspaceMigrationWorkflowPayload;
      if(fixed.id!==step.id||!this.migrations)throw new ConflictException({code:'MIGRATION_WORKFLOW_HANDLER_UNAVAILABLE'});
      return this.migrations.apply(plan.clusterId,plan.subject.id,{confirmed:true,confirm_name:migration.confirm_name,plan_hash:migration.plan_hash},child);
    }
    if(step.entityType==='credentials'){
      if(!step.parentId||!step.credentialKind)throw new ConflictException({code:'WORKFLOW_STEP_INVALID'});const kind=credentialKind(step.credentialKind);
      if(step.mutationAction==='create')return this.entities.createCredential(plan.clusterId,step.parentId,kind,payload,query,child);
      if(step.mutationAction==='update')return this.entities.updateCredential(plan.clusterId,step.parentId,kind,step.entityId!,payload,query,child);
      if(step.mutationAction==='delete')return this.entities.deleteCredential(plan.clusterId,step.parentId,kind,step.entityId!,payload,child);
    }else{
      const type=entityType(step.entityType);
      if(step.mutationAction==='create')return this.entities.create(plan.clusterId,type,payload,query,child);
      if(step.mutationAction==='update')return this.entities.update(plan.clusterId,type,step.entityId!,payload,query,child);
      if(step.mutationAction==='delete')return this.entities.delete(plan.clusterId,type,step.entityId!,payload,child);
    }
    throw new ConflictException({code:'WORKFLOW_STEP_UNSUPPORTED'});
  }
  private async snapshot(plan:WorkflowPlanV1,executionId:string,actor:EntityActor):Promise<WorkflowSnapshotV1>{
    if(plan.kind==='control-metadata') {
      assertControlMetadataPlan(plan);await this.approved.assertControlWorkflowAdmission(plan,actor,'write');
      return{version:1,workflowId:plan.workflowId,executionId,clusterId:plan.clusterId,workspaceId:plan.workspaceId,planRevision:plan.planRevision,planHash:this.secrets.fingerprint(plan),objects:[],capturedAt:new Date().toISOString()};
    }
    const paths=new Map<string,{type:string;id:string;before:any;absent:boolean;fingerprint:string}>();
    for(const prerequisite of plan.prerequisites)paths.set(prerequisite.path,{type:prerequisite.type,id:prerequisite.id,before:prerequisite.before,absent:false,fingerprint:prerequisite.fingerprint});
    for(const step of plan.steps.filter(step=>step.kind==='native'))for(const request of step.nativeRequests){
      const id=request.nativeId;if(!id)throw new ConflictException({code:'WORKFLOW_NATIVE_ID_REQUIRED'});
      const path=request.method==='POST'?`${request.canonicalPath}/${id}`:request.canonicalPath,absent=request.method==='POST',fingerprint=absent?this.secrets.fingerprint(null):request.beforeHmac??step.beforeFingerprint!;
      const existing=paths.get(path);if(existing&&(existing.absent!==absent||existing.fingerprint!==fingerprint||existing.id!==id))throw new ConflictException({code:'WORKFLOW_SNAPSHOT_CONFLICT'});
      paths.set(path,{type:request.nativeType,id,before:step.before??null,absent,fingerprint});
    }
    const retired:any=plan.steps.find(step=>step.handler==='portal.credential.revoke'&&(step.metadata as any)?.retireConsumer)?.metadata;
    const childPaths=retired?['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].map(kind=>`/consumers/${retired.consumerId}/${kind}`):[];
    const objects:WorkflowSnapshotV1['objects']=[];if(paths.size+childPaths.length>100)throw new BadRequestException({code:'WORKFLOW_SNAPSHOT_BUDGET'});
    await this.execution.runInternalRead(plan.clusterId,'entity-preflight',async()=>{
      for(const path of childPaths){const kind=path.split('/').at(-1),allowed=new Set(plan.steps.filter(step=>step.mutationAction==='delete'&&step.entityType==='credentials'&&step.parentId===retired.consumerId&&step.credentialKind===kind).map(step=>step.entityId));const page:any=await this.kong.request(plan.clusterId,'GET',path,undefined,{size:100});if(!Array.isArray(page.data)||page.next||page.data.some((child:any)=>!allowed.has(child.id)))throw new ConflictException({code:'PORTAL_RETIREMENT_UNLISTED_CHILDREN'});}
      const allowed=new Set(plan.steps.filter(step=>step.mutationAction==='delete'&&step.entityType==='plugins'&&(step.before as any)?.consumer?.id===retired?.consumerId).map(step=>step.entityId));
      if(retired){let offset:string|undefined;for(let page=0;page<10;page++){
        const result:any=await this.kong.request(plan.clusterId,'GET','/plugins',undefined,{size:100,...(offset?{offset}:{})});
        if(!Array.isArray(result.data)||result.data.some((plugin:any)=>plugin.consumer?.id===retired.consumerId&&!allowed.has(plugin.id)))throw new ConflictException({code:'PORTAL_RETIREMENT_UNLISTED_CHILDREN'});
        if(!result.next)break;if(page===9)throw new ConflictException({code:'WORKFLOW_SNAPSHOT_BUDGET'});
        try{offset=new URL(result.next,'http://kong').searchParams.get('offset')??undefined;}catch{throw new ConflictException({code:'PORTAL_NATIVE_RESPONSE_INVALID'});}if(!offset)throw new ConflictException({code:'PORTAL_NATIVE_RESPONSE_INVALID'});
      }}
      for(const [path,expected]of paths){let actual:any=null;try{actual=await this.kong.request(plan.clusterId,'GET',path);}catch(error){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;}
        if(expected.absent?actual!==null:actual===null||this.secrets.fingerprint(actual)!==expected.fingerprint)throw new ConflictException({code:'WORKFLOW_PREFLIGHT_CHANGED',message:'当前对象与不可变计划不一致，未执行变更'});
        objects.push({type:expected.type,id:expected.id,path,before:actual,absent:expected.absent,fingerprint:this.secrets.fingerprint(actual)});
      }
    },{paths:[...paths.keys(),...childPaths,...(retired?['/plugins']:[])],maxCalls:100,maxRecords:1000,maxBytes:2*1024*1024,timeoutMs:30000,workspaceId:plan.workspaceId});
    const snapshot:WorkflowSnapshotV1={version:1,workflowId:plan.workflowId,executionId,clusterId:plan.clusterId,workspaceId:plan.workspaceId,planRevision:plan.planRevision,planHash:this.secrets.fingerprint(plan),objects,capturedAt:new Date().toISOString()};
    if(Buffer.byteLength(JSON.stringify(snapshot))>2*1024*1024)throw new BadRequestException({code:'WORKFLOW_SNAPSHOT_TOO_LARGE'});return snapshot;
  }
  async execute(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{
    // A route or caller-supplied kind cannot extend native execution. Only the
    // actual durable workflow selects M8's budget; full plan authorization and
    // the sealed kind/handler verifier below remain mandatory.
    const budgetRow=await this.db.one<{kind:string}>('SELECT kind FROM workflows WHERE id=$1 AND cluster_id=$2',[workflowId(id),cid]);
    return this.withActor(cid,actor,'write',async()=>{
    const value=portalObject(body,['revision','planHash','confirmed','confirm_name']),key=workflowKey(actor.idempotencyKey),{ws,loaded}=await this.loadForAction(cid,id,actor,'write');
    if(loaded.plan.kind==='control-metadata'&&actor.workspaceId!==loaded.plan.workspaceId) {
      // loadForAction authenticated the original selector and sealed target.
      // A child keeps the genuine HTTP/SID ancestry and all original budgets;
      // the fixed Native-zero anchor never grants access to another workspace.
      const anchored={...actor,workspaceId:loaded.plan.workspaceId};
      const receipt=await this.execution.runActor({actor:actor.user,clusterId:cid,workspaceId:loaded.plan.workspaceId,module:'workflows',action:'write',requestId:actor.requestId},()=>this.execute(cid,id,body,anchored));
      return{...receipt,kind:'control-metadata',scopeSelectorWorkspaceId:actor.workspaceId??loaded.plan.workspaceId};
    }
    if((loaded.plan as WorkflowPlanV1 & {scheduling?:unknown}).scheduling)throw new ForbiddenException({code:'WORKFLOW_SCHEDULE_BACKGROUND_EXECUTION_REQUIRED'});
    await this.authorize(loaded.plan,actor,'write');portalConfirm(value,loaded.row.kind);portalRevision(value.revision);
    if(loaded.plan.kind==='native-change'){
      if(!this.entityExecutor)throw new ConflictException({code:'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED',message:'此工单尚未取得执行前快照及专用执行授权'});
      return this.entityExecutor.execute(loaded.plan,body,actor);
    }
    if(value.planHash!==loaded.row.plan_hash)throw new ConflictException({code:'WORKFLOW_PLAN_CHANGED'});
    return this.redis.withLock(`workflow:${id}`,async()=>{
      const current=await this.plans.load(cid,ws.id,id);await this.authorize(current.plan,actor,'write');
      const old=await this.db.one<any>('SELECT * FROM workflow_executions WHERE workflow_id=$1 AND plan_revision=$2',[id,current.row.plan_revision]);
      if(old){if(old.execution_actor_id!==actor.user.id||old.idempotency_key!==key)throw new ConflictException({code:'WORKFLOW_ALREADY_EXECUTED',state:old.state});return this.receiptFor(current.row,current.plan,actor,old);}
      if(current.row.revision!==value.revision||!['approved',...(!current.plan.approvalRequired?['pending']:[])].includes(current.row.state)||Date.parse(current.row.expires_at)<=Date.now())throw new ConflictException({code:'WORKFLOW_NOT_EXECUTABLE'});
      const cluster=await this.db.one<any>('SELECT revision,execution_mode,admin_url,transport_scope FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);const transport=current.plan.kind==='control-metadata'&&cluster?transportScopeFor(cluster.admin_url,cluster.transport_scope):await this.kong.transportScope(cid);
      if(!cluster||cluster.revision!==current.plan.scope.clusterRevision||cluster.execution_mode!==current.plan.executionMode||transport!==current.plan.scope.transportScope||ws.revision!==current.plan.scope.workspaceRevision)throw new ConflictException({code:'WORKFLOW_SCOPE_CHANGED'});
      const executionId=randomUUID();
      await this.db.transaction(async tx=>{
        if(current.row.approval_format===2)await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
        const approvalSet=current.row.approval_format===2?await this.approval?.verifyApprovalSet(current.plan,{checkpoint:'claim'},tx):null;
        if(current.row.approval_format===2&&!approvalSet)throw new ConflictException({code:'WORKFLOW_APPROVAL_AUTHORITY_UNAVAILABLE'});
        requirePortalCas(await tx.exec("UPDATE workflows SET state='executing',revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND state=$3",[id,current.row.revision,current.row.state]));
        await tx.exec(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,claim_token_hash,request_id,idempotency_key,expires_at${approvalSet?',approval_format,approval_set_id,approval_set_hmac':''}) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'executing',$11,$12,$13,$14${approvalSet?',$15,$16,$17':''})`,[executionId,cid,ws.id,id,current.row.plan_revision,current.row.plan_hash,current.plan.executionMode,current.plan.approvalRequired,current.plan.approvalRequired?current.row.approved_by:null,actor.user.id,this.secrets.fingerprint(randomBytes(32).toString('base64url')),actor.requestId??null,key,current.plan.expiresAt,...(approvalSet?[approvalSet.format,approvalSet.setId,approvalSet.setHmac]:[])]);
        await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'workflows',entityId:id,workflowId:id,action:'workflow.execute.requested',requestId:actor.requestId,ip:actor.ip,result:'pending',scopeHints:this.workflowScopeHints(ws.id,id)},tx);
      });
      let succeeded=0;
      try{
        const snapshot=await this.redis.withLock(`mutation:${transport}`,()=>this.snapshot(current.plan,executionId,actor));await this.authorize(current.plan,actor,'write');
        requirePortalCas(await this.db.exec("UPDATE workflow_executions SET snapshot_state='ready',snapshot_secret=$2,snapshot_hash=$3,snapshot_id=$4,revision=revision+1,updated_at=now() WHERE id=$1 AND snapshot_state='pending' AND state='executing' AND workflow_id=$5 AND plan_hash=$6",[executionId,this.secrets.encrypt(snapshot,snapshotAad(cid,ws.id,id,executionId)),this.secrets.fingerprint(snapshot),randomUUID(),id,current.row.plan_hash]));
        const run=async()=>{
          for(const step of current.plan.steps){await this.redis.assertLeaseOwnership();await this.authorize(current.plan,actor,'write');
            requirePortalCas(await this.db.exec("UPDATE workflow_steps SET state='running',started_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='pending'",[step.id]));
            const executeStep=async()=>{
              if(step.kind==='native'){
                let result:any;
                if(current.plan.kind==='metrics-setup'){
                  if(!this.metricsSetup)throw new ConflictException({code:'METRICS_SETUP_EXECUTION_UNAVAILABLE'});
                  if(await this.metricsSetup.nativeWorkspace(current.plan,step)!==current.plan.workspaceId)throw new ForbiddenException({code:'METRICS_SETUP_PLUGIN_WORKSPACE_REQUIRED'});
                  result=await this.metricsSetup.runManagedNative(current.plan,executionId,()=>this.dispatch(current.plan,step,actor));
                }else result=await this.dispatch(current.plan,step,actor);
                const receipt=await this.mutations.inspectStepReceipt(this.mutationContext(current.plan,step,actor));
                if(!receipt||receipt.state!=='succeeded')throw new ConflictException({code:'WORKFLOW_NATIVE_RECEIPT_MISSING',state:'uncertain'});
                if(current.plan.kind==='workspace-migration'&&result?.state!=='succeeded')throw new ConflictException({code:'MIGRATION_WORKFLOW_PARTIAL',message:'迁移部分完成，必须核验原回执与原计划，批准不会自动重试剩余对象'});
                const recycleId=result?.entryId??result?.recycleEntryId??result?.entry?.id??null;
                const nativeRequest=step.nativeRequests[0],readPath=nativeRequest.method==='POST'?`${nativeRequest.canonicalPath}/${nativeRequest.nativeId}`:nativeRequest.canonicalPath;
                let nativeAfter:any=null;if(current.plan.kind==='workspace-migration')nativeAfter={migrationPlanId:current.plan.subject.id,state:result.state,objects:result.affected.map((node:any)=>({key:node.key,id:node.id,type:node.type,status:node.status}))};else if(step.mutationAction!=='delete')nativeAfter=await this.execution.runInternalRead(cid,'entity-preflight',()=>this.kong.request(cid,'GET',readPath),{paths:[readPath],maxCalls:1,maxBytes:2*1024*1024,workspaceId:ws.id});
                requirePortalCas(await this.db.exec("UPDATE workflow_steps SET state='succeeded',safe_result=$2::jsonb,receipt_secret=$3,recycle_entry_id=$4,after_fingerprint=$5,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='running' AND workflow_id=$6 AND plan_revision=$7 AND plan_hash=$8",[step.id,JSON.stringify({nativeOperationId:receipt.operationId,entityId:receipt.entityId,remoteStarted:receipt.remoteStarted,remoteCompleted:receipt.remoteCompleted}),this.secrets.encrypt({receipt,result:this.secrets.redact(result)},`workflow:${executionId}:${step.id}:receipt`),recycleId,this.secrets.fingerprint(nativeAfter),id,current.row.plan_revision,current.row.plan_hash]));
              }else{
                const handler=this.registry.get(step.handler!);
                if(handler.prepare)await handler.prepare({plan:current.plan,step,actor,executionId});
                const apply=async(tx:DbService)=>{
                  const grantVersion=await this.authz.permissionVersion(actor.user,['iam-metadata','control-metadata','entity-annotation'].includes(current.plan.kind)?tx:undefined);
                  const input={plan:current.plan,step,actor,executionId,transaction:tx},inspection=await handler.inspect(input,tx);
                  if(inspection.revision!==step.metadataRevision||this.secrets.fingerprint(inspection.before)!==step.metadataBeforeHmac)throw new ConflictException({code:'WORKFLOW_METADATA_CHANGED'});
                  if(current.plan.approvalRequired)await this.approved.assertStep({handler:step.handler!,actor:actor.user,clusterId:cid,workspaceId:ws.id,entityType:step.entityType,entityId:step.entityId!,before:inspection.before,revision:inspection.revision,payload:step.metadata},tx);
                  const applied=await handler.apply(input);
                  const result=current.plan.kind==='event-metadata'?await this.eventBusinessResult(applied,current.plan,step,actor,executionId,inspection.before,tx):applied;
                  const metadataProjection=current.plan.kind==='governance-metadata'?governanceMetadataProjection:current.plan.kind==='workflow-policy-metadata'?workflowPolicyMetadataProjection:current.plan.kind==='metrics-setup'?(value:unknown)=>metricsSetupPublicProjection(value,this.secrets):workflowMetadataProjection;
                  if(!['event-metadata','entity-annotation'].includes(current.plan.kind))await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:step.entityType,entityId:step.entityId,workflowId:id,requestId:actor.requestId,ip:actor.ip,action:step.handler!,before:metadataProjection(step.before),after:metadataProjection((result as any).entity??result),result:'success',
                    ...(['configuration_v2','configuration-metadata'].includes(current.plan.kind)?{scopeHints:{quality:'verified' as const,module:step.entityType==='configuration_gitops_runs'?'gitops':'snapshots',subject:{type:step.entityType,id:step.entityId!},beforeExists:step.before!=null,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:ws.id,afterWorkspaceId:ws.id}}:{})},tx);
                  await this.redis.assertLeaseOwnership();
                  if(current.plan.kind==='iam-metadata') {
                    if(!this.iamCompletion)throw new ConflictException({code:'IAM_METADATA_COMPLETION_UNAVAILABLE'});
                    await this.iamCompletion.verifyMetadataCompletion(input,applied,grantVersion);
                  }else if(current.plan.kind==='control-metadata') {
                    if(!this.controlCompletion)throw new ConflictException({code:'CONTROL_METADATA_COMPLETION_UNAVAILABLE'});
                    await this.controlCompletion.verifyMetadataCompletion(input,applied,grantVersion);
                  }else if(current.plan.kind==='entity-annotation') {
                    if(!this.annotationCompletion)throw new ConflictException({code:'ENTITY_ANNOTATION_COMPLETION_UNAVAILABLE'});
                    await this.annotationCompletion.verifyMetadataCompletion(input,applied,grantVersion);
                  }else if(await this.authz.permissionVersion(actor.user)!==grantVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
                  requirePortalCas(await tx.exec("UPDATE workflow_steps SET state='succeeded',safe_result=$2::jsonb,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='running' AND workflow_id=$3 AND plan_revision=$4 AND plan_hash=$5",[step.id,JSON.stringify(this.secrets.redact(result)),id,current.row.plan_revision,current.row.plan_hash]));
                  if(step.order===current.plan.steps.length){
                    requirePortalCas(await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing' AND workflow_id=$2 AND plan_revision=$3 AND plan_hash=$4 AND execution_actor_id=$5",[executionId,id,current.row.plan_revision,current.row.plan_hash,actor.user.id]));
                    requirePortalCas(await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing' AND plan_revision=$2 AND plan_hash=$3 AND revision=$4",[id,current.row.plan_revision,current.row.plan_hash,current.row.revision+1]));
                    await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'workflows',entityId:id,workflowId:id,action:'workflow.execute',result:'success',requestId:actor.requestId,ip:actor.ip,scopeHints:this.workflowScopeHints(ws.id,id)},tx);
                  }
                  return result;
                };
                if(current.plan.approvalRequired)await this.db.transaction(apply);
                else await this.iam.execute({module:'portal',action:'write',targetId:step.entityId,cluster_id:cid,workspace_id:ws.id,payload:{workflowId:id,planHash:current.row.plan_hash,stepId:step.id,payload:step.metadata},actor:{...actor,idempotencyKey:`metadata-${this.secrets.fingerprint({id,step:step.id,key}).slice(0,48)}`}},apply);
              }
            };
            if(current.plan.approvalRequired)await this.execution.runApprovedStep(step.id,executeStep);else await executeStep();succeeded++;
          }
        };
        if(current.plan.approvalRequired)await this.approved.runApprovedExecution(executionId,run);else await run();
        if(current.plan.kind==='workspace-migration'){
          const step=assertWorkspaceMigrationWorkflowPlan(current.plan),payload=step.mutationPayload as WorkspaceMigrationWorkflowPayload;
          if(succeeded!==current.plan.steps.length)throw new ConflictException({code:'MIGRATION_WORKFLOW_ACK_MISSING',state:'uncertain'});
          await this.db.transaction(async tx=>{
            await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
            const permissionVersion=await this.authz.permissionVersion(actor.user,tx);await this.authorize(current.plan,actor,'write');
            const fact=await tx.one<any>(`SELECT s.state AS step_state,s.operation_id,m.actor_id,m.cluster_id,m.workspace_id,m.entity_type,m.entity_id,m.action,
              m.workflow_id,m.workflow_execution_id,m.workflow_step_id,m.workflow_plan_revision,m.workflow_plan_hash,m.state AS mutation_state,m.remote_started,m.remote_completed,
              m.before_secret,m.payload_secret,m.result_secret,p.state AS migration_state,p.plan_hash AS migration_plan_hash,p.operation_id AS migration_operation_id,
              p.actor_id AS migration_actor_id,p.source_workspace_id,p.target_workspace_id,p.payload_secret AS migration_material_secret
              FROM workflow_steps s JOIN mutation_operations m ON m.id=s.operation_id AND m.cluster_id=s.cluster_id AND m.workspace_id=s.workspace_id
              JOIN workspace_migration_plans p ON p.id=s.entity_id AND m.entity_id=p.id::text AND p.cluster_id=m.cluster_id
              WHERE s.id=$1 AND s.workflow_id=$2 AND s.plan_revision=$3 AND s.plan_hash=$4 FOR SHARE OF s,m,p`,[step.id,id,current.plan.planRevision,current.row.plan_hash]);
            if(!fact||fact.step_state!=='succeeded'||fact.mutation_state!=='succeeded'||fact.migration_state!=='succeeded'||!fact.remote_started||!fact.remote_completed
              ||fact.actor_id!==actor.user.id||fact.migration_actor_id!==actor.user.id||fact.cluster_id!==cid||fact.workspace_id!==ws.id||fact.source_workspace_id!==ws.id||fact.target_workspace_id!==current.plan.migration!.targetWorkspaceId
              ||fact.entity_type!=='workspace_migration'||fact.entity_id!==current.plan.subject.id||fact.action!=='migrate'||fact.workflow_id!==id||fact.workflow_execution_id!==executionId||fact.workflow_step_id!==step.id
              ||fact.workflow_plan_revision!==current.plan.planRevision||fact.workflow_plan_hash!==current.row.plan_hash||fact.migration_plan_hash!==payload.plan_hash||fact.migration_operation_id!==fact.operation_id
              ||!fact.result_secret||this.secrets.fingerprint(this.secrets.decrypt(fact.before_secret,`mutation:${fact.operation_id}:before`))!==step.beforeFingerprint
              ||this.secrets.fingerprint(this.secrets.decrypt(fact.payload_secret,`mutation:${fact.operation_id}:payload`))!==step.mutationPayloadHmac)throw new ConflictException({code:'MIGRATION_WORKFLOW_ACK_MISSING',state:'uncertain'});
            const result=this.secrets.decrypt<any>(fact.result_secret,`mutation:${fact.operation_id}:result`);
            const material=this.secrets.decrypt<WorkspaceMigrationMaterial>(fact.migration_material_secret,`workspace-migration:${current.plan.subject.id}`);
            const expected=new Map(material.nodes.map(node=>[node.key,node]));
            if(this.secrets.fingerprint(material)!==current.plan.migration!.materialHmac||this.secrets.fingerprint({cid,actor:actor.user.id,payload:material})!==payload.plan_hash
              ||result?.id!==current.plan.subject.id||result?.state!=='succeeded'||!Array.isArray(result.affected)||result.affected.length!==material.nodes.length||new Set(result.affected.map((node:any)=>node.key)).size!==expected.size
              ||result.affected.some((node:any)=>{const original=expected.get(node.key);return !original||node.type!==original.type||node.id!==original.id||node.status!=='succeeded';}))throw new ConflictException({code:'MIGRATION_WORKFLOW_ACK_MISSING',state:'uncertain'});
            requirePortalCas(await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing' AND workflow_id=$2 AND plan_revision=$3 AND plan_hash=$4 AND execution_actor_id=$5",[executionId,id,current.plan.planRevision,current.row.plan_hash,actor.user.id]));
            requirePortalCas(await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing' AND plan_revision=$2 AND plan_hash=$3 AND revision=$4",[id,current.plan.planRevision,current.row.plan_hash,current.row.revision+1]));
            await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'workflows',entityId:id,workflowId:id,action:'workflow.execute',result:'success',requestId:actor.requestId,ip:actor.ip,scopeHints:this.workflowScopeHints(ws.id,id)},tx);
            if(await this.authz.permissionVersion(actor.user,tx)!==permissionVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});await this.redis.assertLeaseOwnership();
          });
        }
      }catch(error:any){
        const response=error instanceof HttpException?error.getResponse():null,code=response&&typeof response==='object'&&'code'in response?String(response.code):'WORKFLOW_EXECUTION_FAILED';
        const active=await this.db.one<any>("SELECT * FROM workflow_steps WHERE workflow_id=$1 AND state='running' ORDER BY step_order LIMIT 1",[id]);
        const knownIamRollback=['iam-metadata','control-metadata','entity-annotation'].includes(current.plan.kind)&&['23514','23503','23505','42501','40001','40P01','55P03','57014'].includes(error?.code);
        let failedReceipt:any=null;let uncertain=!knownIamRollback&&(!(error instanceof HttpException)||error.getStatus()>=500||(response as any)?.state==='uncertain');
        if(active?.kind==='native'){const step=current.plan.steps.find(step=>step.id===active.id)!;const receipt=await this.mutations.inspectStepReceipt(this.mutationContext(current.plan,step,actor)).catch(()=>null);failedReceipt=receipt;uncertain||=!!receipt&&(receipt.state==='uncertain'||receipt.state==='running');}
        const state=uncertain?'uncertain':succeeded||failedReceipt?.remoteCompleted===true?'partial':'failed';await this.db.transaction(async tx=>{
          if(active)await tx.exec("UPDATE workflow_steps SET state=$2,error_code=$3,safe_result=$4::jsonb,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='running'",[active.id,uncertain?'uncertain':'failed',/^[A-Z0-9_]{1,128}$/.test(code)?code:'WORKFLOW_EXECUTION_FAILED',JSON.stringify(failedReceipt?{nativeOperationId:failedReceipt.operationId,remoteStarted:failedReceipt.remoteStarted,remoteCompleted:failedReceipt.remoteCompleted}:{})]);
          await tx.exec("UPDATE workflow_executions SET state=$2,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing'",[executionId,state]);
          await tx.exec("UPDATE workflows SET state=$2,revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing'",[id,state]);
          await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'workflows',entityId:id,workflowId:id,action:'workflow.execute',result:uncertain?'uncertain':'failed',after:{code,state},requestId:actor.requestId,ip:actor.ip,scopeHints:this.workflowScopeHints(ws.id,id)},tx);
        }).catch(()=>undefined);
        throw new HttpException({code,message:'变更未全部完成，请核验原工作流回执，不要使用新幂等键重复执行',workflowId:id,executionId,state},error instanceof HttpException?error.getStatus():503);
      }
      const final=await this.plans.load(cid,ws.id,id);return this.receiptFor(final.row,final.plan,actor);
    });
  },budgetRow?.kind==='configuration_v2');}
  async rollbackPrepare(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const wid=workflowId(actor.workspaceId),{plan}=await this.plans.load(cid,wid,workflowId(id));await this.authorize(plan,actor,'read');
    if(plan.kind!=='native-change'||!this.entityExecutor)throw new ConflictException({code:'ENTITY_CHANGE_RECOVERY_ADAPTER_REQUIRED'});
    return this.entityExecutor.rollbackPrepare(plan,body,actor);
  });}
  async entityPreflight(cid:string,id:string,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(cid,workflowId(actor.workspaceId),workflowId(id));await this.authorize(plan,actor,'write');
    if(plan.kind!=='native-change'||!this.entityExecutor)throw new ConflictException({code:'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED'});
    return this.entityExecutor.preflight(plan,actor);
  });}
  async closeEntityUnsent(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(cid,workflowId(actor.workspaceId),workflowId(id));await this.authorize(plan,actor,'write');
    if(plan.kind!=='native-change'||!this.entityExecutor)throw new ConflictException({code:'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED'});
    return this.entityExecutor.closeUnsent(plan,body,actor);
  });}
  /** Metadata-only reconciliation remains inside Root's exact historical
   * verifier. A workflow ID, DTO or this actor frame grants no native send. */
  async reconcileEntityNoSend(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(cid,workflowId(actor.workspaceId),workflowId(id));await this.authorize(plan,actor,'write');
    if(plan.kind!=='native-change'||!this.entityExecutor)throw new ConflictException({code:'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED'});
    return this.entityExecutor.reconcileNoSend(plan,body,actor);
  });}
  async reconcileTerminalMetadata(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(workflowId(cid),workflowId(actor.workspaceId),workflowId(id));
    await this.authorize(plan,actor,'write');
    if(plan.kind!=='native-change'||!this.entityExecutor?.reconcileTerminalMetadata)throw new ConflictException({code:'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED'});
    return this.entityExecutor.reconcileTerminalMetadata(plan,body,actor);
  });}
  async reconcilePartialRestoreNoSend(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(workflowId(cid),workflowId(actor.workspaceId),workflowId(id));
    await this.authorize(plan,actor,'write');
    if(plan.kind!=='native-change'||!this.entityExecutor?.reconcilePartialRestoreNoSend)throw new ConflictException({code:'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED'});
    return this.entityExecutor.reconcilePartialRestoreNoSend(plan,body,actor);
  });}
  async reconcileTargetResult(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(workflowId(cid),workflowId(actor.workspaceId),workflowId(id));await this.authorize(plan,actor,'write');
    if(plan.kind!=='native-change'||!this.entityExecutor?.reconcileTargetResult)throw new ConflictException({code:'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED'});
    return this.entityExecutor.reconcileTargetResult(plan,body,actor);
  });}
  /** Approval-level, readback-decided settlement of an uncertain schedule-origin configuration_v2 mutation. */
  async reconcileConfigurationUnknownResult(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(workflowId(cid),workflowId(actor.workspaceId),workflowId(id));
    if(plan.kind!=='configuration_v2'||!this.configurationUnknownResults)throw new ConflictException({code:'CONFIGURATION_RECONCILE_UNAVAILABLE'});
    await this.authorize(plan,actor,'approve');
    return this.configurationUnknownResults.reconcile(plan,body,actor);
  });}
  async requestConfigurationUnknownResultAbandon(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(workflowId(cid),workflowId(actor.workspaceId),workflowId(id));
    if(plan.kind!=='configuration_v2'||!this.configurationUnknownResults)throw new ConflictException({code:'CONFIGURATION_RECONCILE_UNAVAILABLE'});
    await this.authorize(plan,actor,'approve');
    return this.configurationUnknownResults.requestAbandon(plan,body,actor);
  });}
  async confirmConfigurationUnknownResultAbandon(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(workflowId(cid),workflowId(actor.workspaceId),workflowId(id));
    if(plan.kind!=='configuration_v2'||!this.configurationUnknownResults)throw new ConflictException({code:'CONFIGURATION_RECONCILE_UNAVAILABLE'});
    await this.authorize(plan,actor,'approve');
    return this.configurationUnknownResults.confirmAbandon(plan,body,actor);
  });}
  async reconcileConfigurationUnsentResult(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(workflowId(cid),workflowId(actor.workspaceId),workflowId(id));
    if(plan.kind!=='configuration_v2'||!this.configurationUnknownResults)throw new ConflictException({code:'CONFIGURATION_RECONCILE_UNAVAILABLE'});
    await this.authorize(plan,actor,'approve');
    return this.configurationUnknownResults.reconcileUnsent(plan,body,actor);
  });}
  async requestConfigurationUnsentResultAbandon(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(workflowId(cid),workflowId(actor.workspaceId),workflowId(id));
    if(plan.kind!=='configuration_v2'||!this.configurationUnknownResults)throw new ConflictException({code:'CONFIGURATION_RECONCILE_UNAVAILABLE'});
    await this.authorize(plan,actor,'approve');
    return this.configurationUnknownResults.requestUnsentAbandon(plan,body,actor);
  });}
  async confirmConfigurationUnsentResultAbandon(cid:string,id:string,body:unknown,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const {plan}=await this.plans.load(workflowId(cid),workflowId(actor.workspaceId),workflowId(id));
    if(plan.kind!=='configuration_v2'||!this.configurationUnknownResults)throw new ConflictException({code:'CONFIGURATION_RECONCILE_UNAVAILABLE'});
    await this.authorize(plan,actor,'approve');
    return this.configurationUnknownResults.confirmUnsentAbandon(plan,body,actor);
  });}
  async receiptByKey(cid:string,key:string,actor:EntityActor):Promise<WorkflowReceipt>{return this.withActor(cid,actor,'read',async()=>{
    workflowKey(key);
    // Locate only this actual actor's fixed Native-zero Control records. A
    // selector mismatch is denied by sealed-domain admission, never by adopting
    // another workspace's authority or treating an unknown POST as absent.
    const controlRows=await this.db.query<any>(`SELECT DISTINCT w.* FROM workflows w
      LEFT JOIN workflow_executions e ON e.workflow_id=w.id
      LEFT JOIN workflow_approvals a ON a.workflow_id=w.id
      LEFT JOIN workflow_events v ON v.workflow_id=w.id AND v.action='decision.cancel'
      WHERE w.cluster_id=$1 AND w.kind='control-metadata' AND
      ((w.requester_user_id=$2 AND w.idempotency_key=$3) OR (e.execution_actor_id=$2 AND e.idempotency_key=$3)
       OR (a.approver_id=$2 AND a.idempotency_key=$3) OR (v.actor_id=$2 AND v.safe_metadata->>'key'=$3)) LIMIT 2`,[cid,actor.user.id,key]);
    if(controlRows.length) {
      if(controlRows.length!==1)throw new ConflictException({code:'WORKFLOW_RECEIPT_KEY_AMBIGUOUS'});
      const row=controlRows[0],{plan}=await this.plans.load(cid,row.workspace_id,row.id);assertControlMetadataPlan(plan);
      const terminalOwner=row.state==='succeeded'&&row.requester_user_id===actor.user.id;
      if(!terminalOwner)await this.approved.assertControlWorkflowAdmission(plan,actor,'read');
      const decision=await this.db.one<any>('SELECT decision FROM workflow_approvals WHERE workflow_id=$1 AND approver_id=$2 AND idempotency_key=$3',[row.id,actor.user.id,key]);
      const cancellation=await this.db.one<any>("SELECT workflow_id FROM workflow_events WHERE workflow_id=$1 AND actor_id=$2 AND action='decision.cancel' AND safe_metadata->>'key'=$3",[row.id,actor.user.id,key]);
      if(decision&&!terminalOwner)await this.authorize(plan,actor,'approve');
      const receipt=await this.receiptFor(row,plan,actor,undefined,!!decision);
      return{...receipt,kind:'control-metadata',scopeSelectorWorkspaceId:actor.workspaceId??plan.workspaceId,idempotencyKey:key,
        action:decision?.decision??(cancellation?'cancel':row.idempotency_key===key?'submit':'execute'),
        ...(decision?{decisionCompleted:true,executionRequested:!!receipt.executionId}:cancellation?{decisionCompleted:row.state==='cancelled',executionRequested:false}:{submissionCompleted:row.idempotency_key===key&&row.approval_required===true})};
    }
    const ws=await this.workspaces.resolve(cid,actor.workspaceId);
    const cancellation=await this.db.one<any>("SELECT workflow_id FROM workflow_events WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND action='decision.cancel' AND safe_metadata->>'key'=$4",[cid,ws.id,actor.user.id,key]);
    if(cancellation){const loaded=await this.plans.load(cid,ws.id,cancellation.workflow_id);await this.authorize(loaded.plan,actor,'write');if(loaded.row.requester_user_id!==actor.user.id)throw new ForbiddenException({code:'WORKFLOW_REQUESTER_REQUIRED'});return{...await this.receiptFor(loaded.row,loaded.plan,actor),idempotencyKey:key,action:'cancel',decisionCompleted:loaded.row.state==='cancelled',executionRequested:false};}
    const decision=await this.db.one<any>('SELECT workflow_id,decision FROM workflow_approvals WHERE cluster_id=$1 AND workspace_id=$2 AND approver_id=$3 AND idempotency_key=$4',[cid,ws.id,actor.user.id,key]);
    const row=decision?await this.db.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[decision.workflow_id,cid,ws.id]):await this.db.one<any>(`SELECT w.* FROM workflows w LEFT JOIN workflow_executions e ON e.workflow_id=w.id WHERE w.cluster_id=$1 AND w.workspace_id=$2 AND ((w.requester_user_id=$3 AND w.idempotency_key=$4) OR (e.execution_actor_id=$3 AND e.idempotency_key=$4)) ORDER BY w.created_at DESC LIMIT 1`,[cid,ws.id,actor.user.id,key]);
    if(!row)throw new NotFoundException({code:'WORKFLOW_RECEIPT_NOT_FOUND'});const {plan}=await this.plans.load(cid,ws.id,row.id);
    if(decision){await this.authorize(plan,actor,'approve');const receipt=await this.receiptFor(row,plan,actor,undefined,true);return{...receipt,idempotencyKey:key,action:decision.decision,decisionCompleted:true,executionRequested:!!receipt.executionId};}
    const receipt=await this.receiptFor(row,plan,actor);return{...receipt,idempotencyKey:key,action:row.idempotency_key===key?'submit':'execute',submissionCompleted:row.idempotency_key===key&&row.approval_required===true};
  });}
  private async abandonmentSession(actor:EntityActor,tx=this.db,expectedSessionId?:string):Promise<string>{
    const frame=this.execution.current();
    if(frame.actor?.id!==actor.user.id||!frame.sessionId||expectedSessionId&&frame.sessionId!==expectedSessionId)throw new ForbiddenException({code:'PORTAL_ABANDONMENT_SESSION_INVALID'});
    const row=await tx.one<any>(`SELECT s.id FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.user_id=$2
      AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.credential_epoch=u.credential_epoch
      AND u.status='active' AND u.deleted_at IS NULL AND u.force_password_change=false${tx!==this.db?' FOR SHARE OF s,u':''}`,[frame.sessionId,actor.user.id]);
    if(!row||row.id!==frame.sessionId)throw new ForbiddenException({code:'PORTAL_ABANDONMENT_SESSION_INVALID'});
    this.execution.current();return frame.sessionId;
  }
  private async abandonmentAuthority(plan:WorkflowPlanV1,execution:any,actor:EntityActor,tx=this.db,expectedVersion?:string,expectedSessionId?:string){
    const cid=plan.clusterId,wid=plan.workspaceId,sessionId=await this.abandonmentSession(actor,tx,expectedSessionId);
    if(execution.execution_actor_id!==actor.user.id||execution.workflow_id!==plan.workflowId||execution.plan_hash!==this.secrets.fingerprint(plan)||execution.plan_revision!==plan.planRevision)throw new ForbiddenException({code:'PORTAL_ABANDONMENT_EXECUTOR_MISMATCH'});
    const version=await this.authz.permissionVersion(actor.user);if(expectedVersion&&version!==expectedVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    const cluster=await tx.one<any>(`SELECT admin_url,transport_scope,revision,execution_mode,status,version FROM clusters WHERE id=$1 AND deleted_at IS NULL${tx!==this.db?' FOR SHARE':''}`,[cid]);
    const workspace=await tx.one<any>(`SELECT revision,status FROM workspaces WHERE id=$1 AND cluster_id=$2${tx!==this.db?' FOR SHARE':''}`,[wid,cid]);
    if(!cluster||cluster.status==='disabled'||!isSupportedKong(cluster.version??'')||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==plan.scope.transportScope
      ||cluster.revision!==plan.scope.clusterRevision||cluster.execution_mode!==plan.executionMode||!workspace||workspace.status!=='active'||workspace.revision!==plan.scope.workspaceRevision)throw new ConflictException({code:'WORKFLOW_SCOPE_CHANGED'});
    const grant=await tx.one<any>('SELECT * FROM portal_application_grants WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,cid,wid]);
    if(!grant||grant.transport_scope!==plan.scope.transportScope||grant.workflow_id!==plan.workflowId)throw new ConflictException({code:'PORTAL_REJECTED_ISSUE_PROOF_INVALID'});
    const publication=await tx.one<any>(`SELECT * FROM portal_publications WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3${tx!==this.db?' FOR SHARE':''}`,[grant.publication_id,cid,wid]);
    const application=await tx.one<any>(`SELECT id FROM portal_applications WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND developer_id=$4 AND status='active'${tx!==this.db?' FOR SHARE':''}`,[grant.application_id,cid,wid,grant.developer_id]);
    const developer=await tx.one<any>(`SELECT id FROM portal_developers WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND status='active'${tx!==this.db?' FOR SHARE':''}`,[grant.developer_id,cid,wid]);
    if(!application||!developer||!publication||publication.state!=='published'||publication.transport_scope!==plan.scope.transportScope)throw new ConflictException({code:'PORTAL_PUBLICATION_REVALIDATION_REQUIRED'});
    const proofRow=await tx.one<any>(`SELECT p.* FROM portal_publication_proofs p JOIN workflows w ON w.id=p.workflow_id JOIN workflow_executions e ON e.id=p.workflow_execution_id
      WHERE p.publication_id=$1 AND p.publication_revision=$2 AND p.cluster_id=$3 AND p.workspace_id=$4 AND w.state='succeeded' AND e.state='succeeded'`,[publication.id,publication.published_revision,cid,wid]);
    if(!proofRow)throw new ConflictException({code:'PORTAL_PUBLICATION_PROOF_UNAVAILABLE'});
    if(tx!==this.db&&!await tx.one('SELECT id FROM workflow_definitions WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR SHARE',[plan.definition.id,cid,wid]))throw new ConflictException({code:'WORKFLOW_DEFINITION_UNAVAILABLE'});
    const proof=decodePublicationProof(proofRow,this.secrets),definition=await this.plans.exactDefinition(cid,wid,plan.definition,tx),prerequisite=plan.prerequisites[0];
    if(this.secrets.fingerprint(definition)!==this.secrets.fingerprint(plan.definition)||proof.transportScope!==plan.scope.transportScope||proof.serviceId!==publication.service_id
      ||proof.clusterRevision!==cluster.revision||proof.workspaceRevision!==workspace.revision||!prerequisite||prerequisite.type!=='services'
      ||prerequisite.id!==publication.service_id||prerequisite.path!==`/services/${publication.service_id}`||prerequisite.fingerprint!==this.secrets.fingerprint(proof.service)
      ||prerequisite.fingerprint!==this.secrets.fingerprint(prerequisite.before))throw new ConflictException({code:'WORKFLOW_PREFLIGHT_CHANGED'});
    const service=await this.execution.runInternalRead(cid,'inventory',()=>this.kong.request<any>(cid,'GET',prerequisite.path),{paths:[prerequisite.path],maxCalls:1,maxBytes:2*1024*1024,workspaceId:wid});
    if(service.id!==publication.service_id||this.secrets.fingerprint(service)!==prerequisite.fingerprint)throw new ConflictException({code:'WORKFLOW_PREFLIGHT_CHANGED'});
    await this.authz.assertScopedResource(actor.user,cid,'workflows','write','services',service,wid);
    await this.authz.assertScopedResource(actor.user,cid,'portal','write','services',service,wid);
    await this.authz.assertEntity(actor.user,cid,'consumers','read',plan.steps[0].mutationPayload,wid);
    const approvedBy=await tx.one<any>(`SELECT id,super_admin FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false${tx!==this.db?' FOR SHARE':''}`,[execution.approved_by]);
    const approval=await tx.one<any>("SELECT id FROM workflow_approvals WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4 AND plan_hash=$5 AND approver_id=$6 AND decision='approve' AND level=1",[plan.workflowId,cid,wid,plan.planRevision,execution.plan_hash,execution.approved_by]);
    if(!approvedBy||!approval)throw new ForbiddenException({code:'APPROVED_APPROVER_REVOKED'});
    if(!approvedBy.super_admin){const grants=(await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[approvedBy.id])).filter(validGrant);
      if(!grants.some(grant=>grantMatchesEntity(grant,'workflows','approve',{clusterId:cid,workspaceId:wid,entityType:'services',entity:service})))throw new ForbiddenException({code:'APPROVED_APPROVER_REVOKED'});}
    if(await this.authz.permissionVersion(actor.user)!==version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    await this.abandonmentSession(actor,tx,sessionId);
    return{version,sessionId,serviceId:service.id,serviceFingerprint:this.secrets.fingerprint(service),publicationId:publication.id,publicationRevision:publication.published_revision,publicationProofHmac:proofRow.publication_proof_hmac,clusterRevision:cluster.revision,workspaceRevision:workspace.revision};
  }
  private async canAbandonRejectedIssue(plan:WorkflowPlanV1,execution:any,actor:EntityActor):Promise<boolean>{
    if(plan.kind!=='portal-credential-issue'||execution.state!=='failed'||execution.execution_actor_id!==actor.user.id)return false;
    try{
      const old=await getRejectedIssueAbandonment(this.db,this.secrets,{clusterId:plan.clusterId,workspaceId:plan.workspaceId,workflowId:plan.workflowId,executionId:execution.id,actorId:actor.user.id,originalExecutionKey:execution.idempotency_key});if(old)return false;
      const facts=await loadRejectedIssueAbandonmentFacts(this.db,{clusterId:plan.clusterId,workspaceId:plan.workspaceId,grantId:plan.subject.id,workflowId:plan.workflowId,executionId:execution.id});
      const checked=validateRejectedIssuePlan(facts,this.secrets);await this.abandonmentAuthority(checked,execution,actor);return true;
    }catch(error){if(error instanceof ConflictException||error instanceof ForbiddenException)return false;throw error;}
  }
  async abandonRejectedIssue(cid:string,id:string,body:unknown,actor:EntityActor):Promise<WorkflowReceipt>{return this.withActor(cid,actor,'write',async()=>{
    const value=portalObject(body,['revision','planHash','executionId','confirmed','confirm_name']),key=workflowKey(actor.idempotencyKey),ws=await this.workspaces.resolve(cid,actor.workspaceId);
    id=workflowId(id);workflowId(value.executionId);portalRevision(value.revision);portalConfirm(value,'portal-credential-issue');
    if(this.execution.current().idempotencyKey!==key)throw new ForbiddenException({code:'PORTAL_ABANDONMENT_REQUEST_MISMATCH'});
    const requestHash=this.secrets.fingerprint({handler:'portal.issue.abandon-rejected',clusterId:cid,workspaceId:ws.id,workflowId:id,body:value});
    return this.redis.withLock(`workflow:${id}`,async()=>{
      const loaded=await this.plans.load(cid,ws.id,id),plan=loaded.plan;
      if(plan.kind!=='portal-credential-issue'||plan.subject.type!=='portal_application_grants'||plan.steps.length!==4||plan.steps[3].handler!=='portal.credential.activate'||value.planHash!==loaded.row.plan_hash)throw new ConflictException({code:'PORTAL_REJECTED_ISSUE_PROOF_INVALID'});
      const execution=await this.db.one<any>('SELECT * FROM workflow_executions WHERE id=$1 AND workflow_id=$2 AND cluster_id=$3 AND workspace_id=$4',[value.executionId,id,cid,ws.id]);
      if(!execution||execution.execution_actor_id!==actor.user.id||execution.idempotency_key!==key||execution.plan_hash!==loaded.row.plan_hash)throw new ForbiddenException({code:'PORTAL_ABANDONMENT_EXECUTOR_MISMATCH'});
      await this.abandonmentAuthority(plan,execution,actor);
      const lookup={clusterId:cid,workspaceId:ws.id,workflowId:id,executionId:execution.id,actorId:actor.user.id,originalExecutionKey:key,requestHash};
      const old=await getRejectedIssueAbandonment(this.db,this.secrets,lookup);
      if(old)return{...await this.receiptFor(loaded.row,plan,actor,execution),idempotencyKey:key,action:'execute'};
      if(loaded.row.state!=='failed'||execution.state!=='failed'||loaded.row.revision!==value.revision)throw new ConflictException({code:'PORTAL_REJECTED_ISSUE_NOT_ELIGIBLE'});
      return this.redis.withLock(`mutation:${plan.scope.transportScope}`,async()=>{
        const scope={clusterId:cid,workspaceId:ws.id,grantId:plan.subject.id,workflowId:id,executionId:execution.id};
        const facts=await loadRejectedIssueAbandonmentFacts(this.db,scope),checked=validateRejectedIssuePlan(facts,this.secrets),authority=await this.abandonmentAuthority(checked,execution,actor);
        const observedAt=new Date().toISOString(),paths=[`/consumers/${facts.grant.consumer_id}`,`/consumers/${facts.grant.consumer_id}/acls/${facts.grant.acl_id}`,`/consumers/${facts.grant.consumer_id}/key-auth/${facts.credential.kong_id}`];
        await this.execution.runInternalRead(cid,'inventory',async()=>{for(const path of paths){try{await this.kong.request(cid,'GET',path);throw new ConflictException({code:'PORTAL_ABANDONMENT_NATIVE_OBJECT_EXISTS'});}catch(error){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;}}},{paths,maxCalls:3,maxRecords:3,maxBytes:2*1024*1024,timeoutMs:15000,workspaceId:ws.id});
        const proof:RejectedIssueProofV1={version:1,...scope,planRevision:plan.planRevision,planHash:loaded.row.plan_hash,actorId:actor.user.id,sessionId:authority.sessionId,transportScope:plan.scope.transportScope,observedAt,consumerId:facts.grant.consumer_id,consumerAbsent:true,aclId:facts.grant.acl_id,aclAbsent:true,keyId:facts.credential.kong_id,keyAbsent:true,clusterRevision:authority.clusterRevision,workspaceRevision:authority.workspaceRevision,serviceId:authority.serviceId,serviceFingerprint:authority.serviceFingerprint,publicationId:authority.publicationId,publicationRevision:authority.publicationRevision,publicationProofHmac:authority.publicationProofHmac,factsHash:facts.factsHash};
        try{await this.db.transaction(async tx=>{
          await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
          const current=await loadRejectedIssueAbandonmentFacts(tx,scope);validateRejectedIssuePlan(current,this.secrets);
          if(current.factsHash!==facts.factsHash||current.workflow.revision!==value.revision)throw new ConflictException({code:'PORTAL_REJECTED_ISSUE_PROOF_CHANGED'});
          const finalAuthority=await this.abandonmentAuthority(checked,current.execution,actor,tx,authority.version,authority.sessionId);
          if(finalAuthority.serviceFingerprint!==proof.serviceFingerprint||finalAuthority.publicationProofHmac!==proof.publicationProofHmac||Date.now()-Date.parse(observedAt)>15000)throw new ConflictException({code:'PORTAL_ABANDONMENT_PROOF_EXPIRED'});
          requirePortalCas(await tx.exec("UPDATE portal_application_grants SET state='disabled',reservation_released_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND state='pending' AND workflow_id=$3 AND current_generation=0 AND current_credential_id IS NULL AND acl_credential_ref_id IS NULL AND reservation_released_at IS NULL",[current.grant.id,current.grant.revision,id]));
          const receipt=await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,workflowId:id,entityType:'portal_application_grants',entityId:current.grant.id,action:'portal.issue.abandon-rejected',before:{id:current.grant.id,state:'pending',revision:current.grant.revision,generation:0},after:{id:current.grant.id,state:'disabled',revision:current.grant.revision+1,generation:0,reservationReleased:true,executionId:execution.id,reason:'KNOWN_KONG_VALIDATION_REJECTION'},result:'success',requestId:actor.requestId,ip:actor.ip},tx);
          await persistRejectedIssueAbandonment(tx,this.secrets,{...scope,planRevision:plan.planRevision,planHash:loaded.row.plan_hash,failedStepId:current.steps[0].id,failedOperationId:current.operation.id,actorId:actor.user.id,sessionId:authority.sessionId,originalExecutionKey:key,requestHash,expectedGrantRevision:current.grant.revision,factsHash:current.factsHash,proof,auditReceipt:receipt});
          await this.abandonmentSession(actor,tx,authority.sessionId);await this.redis.assertLeaseOwnership();
          if(await this.authz.permissionVersion(actor.user)!==authority.version)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
          const endpoint=await tx.one<any>('SELECT admin_url,transport_scope,revision,execution_mode,status FROM clusters WHERE id=$1 AND deleted_at IS NULL',[cid]);
          if(!endpoint||endpoint.status==='disabled'||endpoint.revision!==plan.scope.clusterRevision||endpoint.execution_mode!==plan.executionMode||transportScopeFor(endpoint.admin_url,endpoint.transport_scope)!==plan.scope.transportScope||Date.now()-Date.parse(observedAt)>15000)throw new ConflictException({code:'WORKFLOW_SCOPE_CHANGED'});
          this.execution.current();
        });}catch(error){if(error instanceof HttpException)throw error;this.logAbandonmentPersistenceFailure(error,{clusterId:cid,workspaceId:ws.id,workflowId:id,executionId:execution.id,grantId:plan.subject.id});throw new HttpException({code:'PORTAL_ISSUE_ABANDONMENT_UNKNOWN',workflowId:id,executionId:execution.id,state:'uncertain',message:'放弃操作回执需要核验，请保留原执行幂等键'},503);}
        return{...await this.receiptFor(loaded.row,plan,actor,execution),idempotencyKey:key,action:'execute'};
      });
    });
  });}
  async reconcileMetadata(cid:string,id:string,body:unknown,actor:EntityActor):Promise<WorkflowReceipt>{return this.withActor(cid,actor,'write',async()=>{
    const kind=await this.db.one<{kind:string}>('SELECT kind FROM workflows WHERE id=$1 AND cluster_id=$2',[workflowId(id),cid]);
    if(kind?.kind==='workspace-migration'){
      if(!this.migrationRecovery)throw new ConflictException({code:'MIGRATION_METADATA_RECOVERY_UNAVAILABLE'});
      await this.migrationRecovery.reconcile(cid,id,body,actor);const wid=workflowId(actor.workspaceId),loaded=await this.plans.load(cid,wid,id);
      return {...await this.receiptFor(loaded.row,loaded.plan,actor),idempotencyKey:workflowKey(actor.idempotencyKey),action:'execute'};
    }
    const value=portalObject(body,['revision','planHash','executionId','confirmed','confirm_name']),key=workflowKey(actor.idempotencyKey);
    await this.authz.assertCluster(actor.user,cid,'workflows','write',actor.workspaceId);
    const ws=await this.workspaces.resolve(cid,actor.workspaceId);id=workflowId(id);workflowId(value.executionId);portalRevision(value.revision);
    return this.redis.withLock(`workflow:${id}`,async()=>{
      const loaded=await this.plans.load(cid,ws.id,id);await this.authorize(loaded.plan,actor,'write');portalConfirm(value,'portal-credential-issue');
      if(loaded.plan.kind!=='portal-credential-issue'||loaded.plan.subject.type!=='portal_application_grants'||loaded.plan.steps.length!==4
        ||loaded.plan.steps[3].handler!=='portal.credential.activate'||value.planHash!==loaded.row.plan_hash)throw new ConflictException({code:'PORTAL_RECOVERY_NOT_ELIGIBLE'});
      const execution=await this.db.one<any>('SELECT * FROM workflow_executions WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4 AND plan_revision=$5',[value.executionId,cid,ws.id,id,loaded.row.plan_revision]);
      if(!execution||execution.execution_actor_id!==actor.user.id||execution.idempotency_key!==key||execution.plan_hash!==loaded.row.plan_hash)throw new ForbiddenException({code:'PORTAL_RECOVERY_REQUEST_MISMATCH'});
      const requestHash=this.secrets.fingerprint(value);
      if(loaded.row.state==='succeeded'&&execution.state==='succeeded'){
        const event=await this.db.one<any>("SELECT safe_metadata FROM workflow_events WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND actor_id=$4 AND action='execution.reconcile-metadata' AND safe_metadata->>'executionId'=$5",[id,cid,ws.id,actor.user.id,execution.id]);
        if(!event||event.safe_metadata?.requestHash!==requestHash||event.safe_metadata?.executionKeyFingerprint!==this.secrets.fingerprint(key))throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});
        return{...await this.receiptFor(loaded.row,loaded.plan,actor,execution),idempotencyKey:key,action:'execute'};
      }
      if(loaded.row.state!=='uncertain'||execution.state!=='uncertain'||loaded.row.revision!==value.revision)throw new ConflictException({code:'PORTAL_RECOVERY_NOT_ELIGIBLE'});
      return this.redis.withLock(`mutation:${loaded.plan.scope.transportScope}`,()=>this.approved.runIssueActivationRecovery(execution.id,key,loaded.row.revision,loaded.row.plan_hash,async()=>{
        if(!this.boundary||typeof this.boundary.assertCurrentIssueRecoveryBoundary!=='function')throw new ConflictException({code:'PORTAL_RECOVERY_POLICY_UNAVAILABLE'});
        await this.boundary.assertCurrentIssueRecoveryBoundary();
        const step=loaded.plan.steps[3],handler=this.registry.get('portal.credential.activate'),input={plan:loaded.plan,step,actor:{...actor,workspaceId:ws.id},executionId:execution.id};
        if(!handler.prepare)throw new ConflictException({code:'PORTAL_RECOVERY_NOT_ELIGIBLE'});await handler.prepare(input);
        await this.db.transaction(async tx=>{
          const permissionVersion=await this.authz.permissionVersion(actor.user),inspection=await handler.inspect(input,tx);
          if(inspection.revision!==step.metadataRevision||this.secrets.fingerprint(inspection.before)!==step.metadataBeforeHmac)throw new ConflictException({code:'WORKFLOW_METADATA_CHANGED'});
          const metadataInput={handler:'portal.credential.activate',actor:actor.user,clusterId:cid,workspaceId:ws.id,entityType:'portal_application_grants',entityId:step.entityId!,before:inspection.before,revision:inspection.revision,payload:step.metadata};
          await this.approved.assertIssueActivationRecovery(metadataInput,tx,'before');
          const result=await handler.apply({...input,transaction:tx});
          await this.approved.assertIssueActivationRecovery(metadataInput,tx,'after');
          await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,workflowId:id,entityType:step.entityType,entityId:step.entityId,action:'portal.credential.activate',before:workflowMetadataProjection(step.before),after:this.secrets.redact(result),result:'success',requestId:actor.requestId,ip:actor.ip},tx);
          await this.redis.assertLeaseOwnership();if(await this.authz.permissionVersion(actor.user)!==permissionVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
          requirePortalCas(await tx.exec("UPDATE workflow_steps SET state='succeeded',safe_result=$2::jsonb,error_code=NULL,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='uncertain' AND operation_id IS NULL AND workflow_id=$3 AND plan_revision=$4 AND plan_hash=$5 AND revision=$6",[step.id,JSON.stringify(this.secrets.redact(result)),id,loaded.row.plan_revision,loaded.row.plan_hash,(await tx.one<any>('SELECT revision FROM workflow_steps WHERE id=$1',[step.id]))?.revision]));
          requirePortalCas(await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='uncertain' AND workflow_id=$2 AND plan_revision=$3 AND plan_hash=$4 AND execution_actor_id=$5 AND idempotency_key=$6 AND revision=$7",[execution.id,id,loaded.row.plan_revision,loaded.row.plan_hash,actor.user.id,key,execution.revision]));
          requirePortalCas(await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND state='uncertain' AND plan_revision=$2 AND plan_hash=$3 AND revision=$4",[id,loaded.row.plan_revision,loaded.row.plan_hash,loaded.row.revision]));
          await tx.exec("INSERT INTO workflow_events(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,actor_type,actor_id,action,result,safe_metadata,request_id) VALUES($1,$2,$3,$4,$5,'user',$6,'execution.reconcile-metadata','success',$7::jsonb,$8)",[cid,ws.id,id,loaded.row.plan_revision,loaded.row.plan_hash,actor.user.id,JSON.stringify({executionId:execution.id,stepId:step.id,requestHash,executionKeyFingerprint:this.secrets.fingerprint(key),reason:'ACKNOWLEDGED_NATIVE_METADATA_COMPLETION'}),actor.requestId??null]);
          await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,workflowId:id,entityType:'workflows',entityId:id,action:'workflow.reconcile-metadata',after:{executionId:execution.id,stepId:step.id,planHash:loaded.row.plan_hash,reason:'ACKNOWLEDGED_NATIVE_METADATA_COMPLETION'},result:'success',requestId:actor.requestId,ip:actor.ip},tx);
          await this.redis.assertLeaseOwnership();if(await this.authz.permissionVersion(actor.user)!==permissionVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
        });
        const final=await this.plans.load(cid,ws.id,id);return{...await this.receiptFor(final.row,final.plan,actor),idempotencyKey:key,action:'execute'};
      }));
    });
  });}
  private async receiptFor(row:any,plan:WorkflowPlanV1,actor:EntityActor,execution?:any,decisionAuthorized=false):Promise<WorkflowReceipt>{
    if(plan.kind==='entity-annotation'&&row.state==='succeeded'&&plan.requester.type==='console'&&plan.requester.id===actor.user.id) {
      assertEntityAnnotationPlan(plan);
      if(actor.workspaceId!==plan.workspaceId)throw new ForbiddenException({code:'ANNOTATION_SCOPE_SELECTOR_DENIED'});
      if(!this.annotationCompletion)throw new ConflictException({code:'ENTITY_ANNOTATION_COMPLETION_UNAVAILABLE'});
      return this.annotationCompletion.terminalReceipt(plan,actor);
    }
    if(plan.kind==='control-metadata'&&row.state==='succeeded'&&plan.requester.type==='console'&&plan.requester.id===actor.user.id) {
      if(!this.controlCompletion)throw new ConflictException({code:'CONTROL_METADATA_COMPLETION_UNAVAILABLE'});
      return{...await this.controlCompletion.terminalReceipt(plan,actor),kind:'control-metadata',scopeSelectorWorkspaceId:actor.workspaceId??plan.workspaceId};
    }
    if(plan.kind==='iam-metadata'&&row.state==='succeeded'&&plan.requester.type==='console'&&plan.requester.id===actor.user.id) {
      if(!this.iamCompletion)throw new ConflictException({code:'IAM_METADATA_COMPLETION_UNAVAILABLE'});
      return this.iamCompletion.terminalReceipt(plan,actor);
    }
    if(!decisionAuthorized)try{await this.authorize(plan,actor,'read');}catch(error){if(!(error instanceof ForbiddenException))throw error;await this.authorize(plan,actor,'write');}
    execution??=await this.db.one<any>('SELECT * FROM workflow_executions WHERE workflow_id=$1 AND plan_revision=$2',[row.id,row.plan_revision]);
    const rows=await this.db.query<any>('SELECT * FROM workflow_steps WHERE workflow_id=$1 AND plan_revision=$2 ORDER BY step_order',[row.id,row.plan_revision]);
    const metadataRecovery:WorkflowReceipt['metadataRecovery']=plan.kind==='workspace-migration'&&execution?await this.migrationRecovery?.projection(row.cluster_id,row.workspace_id,row.id,actor):plan.kind==='portal-credential-issue'&&execution?{eligible:execution.execution_actor_id===actor.user.id&&row.state==='uncertain'&&execution.state==='uncertain'&&await this.approved.canIssueActivationRecovery(execution.id),kind:'portal-credential-issue'as const,executionId:execution.id,originalExecutionKeyRequired:true as const}:undefined;
    let issueAbandonment:WorkflowReceipt['issueAbandonment'];
    if(plan.kind==='portal-credential-issue'&&execution&&execution.execution_actor_id===actor.user.id&&row.state==='failed'&&execution.state==='failed'){
      const certificate=await getRejectedIssueAbandonment(this.db,this.secrets,{clusterId:plan.clusterId,workspaceId:plan.workspaceId,workflowId:plan.workflowId,executionId:execution.id,actorId:actor.user.id,originalExecutionKey:execution.idempotency_key});
      issueAbandonment={eligible:!certificate&&await this.canAbandonRejectedIssue(plan,execution,actor),completed:!!certificate,kind:'portal-credential-issue',executionId:execution.id,grantId:plan.subject.id,...(certificate?{certificateId:certificate.id}:{}),reservationReleased:!!certificate,originalExecutionKeyRequired:true};
    }
    return{id:execution?.id??row.id,workflowId:row.id,executionId:execution?.id??null,clusterId:row.cluster_id,workspaceId:row.workspace_id,...(plan.kind==='control-metadata'?{kind:'control-metadata' as const,scopeSelectorWorkspaceId:actor.workspaceId??plan.workspaceId}:{}),idempotencyKey:row.idempotency_key,state:execution?.state??row.state,revision:row.revision,planHash:row.plan_hash,executionMode:row.execution_mode,approvalRequired:row.approval_required,steps:rows.map(step=>({id:step.id,name:step.step_key,state:step.state,operationId:step.operation_id??step.safe_result?.nativeOperationId??null,remoteStarted:step.kind==='metadata'?step.state!=='pending':step.safe_result?.remoteStarted===true,remoteCompleted:step.kind==='metadata'?step.state==='succeeded':step.safe_result?.remoteCompleted===true,recycleEntryId:step.recycle_entry_id,errorCode:step.error_code})),metadataRecovery,issueAbandonment,propagation:execution?.state==='succeeded'?'acknowledged':execution?'pending':'not_started'};
  }
}
