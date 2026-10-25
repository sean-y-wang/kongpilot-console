import { BadRequestException, ConflictException, Injectable, NotFoundException, Optional } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { AuditService } from '../audit/audit.service';
import { configurationOriginMarker, normalizedNativeRequests, type ConfigurationOriginDelegate, type GovernanceMetadataApprovedDelegate } from './approved-execution.types';
import {configurationDurableMarker,DURABLE_CONFIGURATION_PRESENCE_QUERY,isProvenLegacyConfigurationRow} from '../configuration/configuration-durable.repository';
import { planAad, WORKFLOW_KINDS, type WorkflowKind, type WorkflowPlanV1 } from './workflow.types';
import { validateWorkflowPlan, workflowKey } from './workflow-validation';
import { eventMetadataProjection } from './event-workflow';
import { assertConfigurationWorkflowPlan, type ConfigurationWorkflowPayload } from './configuration-workflow';
import { assertToolboxWorkflowPlan, type ToolboxWorkflowPayload } from './toolbox-workflow';
import { assertWorkspaceMigrationWorkflowPlan, type WorkspaceMigrationWorkflowPayload } from './workspace-migration-workflow';
import type { WorkspaceMigrationMaterial } from '../workspaces/workspace-migration.service';
import { assertConfigurationMetadataWorkflowPlan, configurationMetadataLedgerInput, type ConfigurationMetadataPayload } from './configuration-metadata-workflow';
import { assertGovernanceMetadataPlan, governanceMetadataProjection } from '../governance/governance-workflow';
import { assertWorkflowPolicyMetadataPlan, workflowPolicyMetadataProjection } from './workflow-policy-metadata';
import { WorkflowApprovalAuthorityService } from './workflow-approval-authority.service';
import type { EntityChangeIntentEnvelope, EntityChangeIntentWorkflowDelegate } from './entity-change-intent.types';
import { assertEntityChangeWorkflowPlan, entityChangeIntentAad, normalizedEntityChangePackets } from './entity-change-workflow';
import { nativeWorkflowImpact } from './workflow-impact';
import type { EntityActor } from '../entities/entities.types';
import type { WorkflowScheduleDraft, WorkflowScheduledPlanV1 } from './workflow-schedule.contract';
import { assertWorkflowScheduledPlan } from './workflow-schedule.repository';
import { assertIamMetadataPlan } from '../iam/iam-workflow-plan';
import type { IamMetadataApprovedDelegate } from '../iam/iam-workflow.types';
import { assertControlMetadataPlan } from '../control-plane/control-metadata-plan';
import type { ControlMetadataApprovedDelegate } from '../control-plane/control-metadata.types';
import { assertMetricsSetupPlan, metricsSetupPublicProjection } from '../vitals/vitals-setup-plan';
import type { MetricsSetupApprovedDelegate } from '../vitals/vitals-setup.types';
import { assertEntityAnnotationPlan } from '../annotations/entity-annotation-workflow-plan';
import type { EntityAnnotationApprovedDelegate } from '../annotations/entity-annotation-workflow.types';

/** One server authoring registry owns the original proposal token. These
 * callbacks create metadata only; they never return execution authority. */
export interface WorkflowScheduledRevisionDelegate {
  verifyRevision(originalProposal: object, old: { row:any; version:any; plan:WorkflowPlanV1 },
    plan:Readonly<WorkflowScheduledPlanV1>, draft:Readonly<WorkflowScheduleDraft>, actor:EntityActor, tx:DbService):Promise<void>;
  beforeApprovalFreeze(originalProposal: object, plan:Readonly<WorkflowScheduledPlanV1>,
    draft:Readonly<WorkflowScheduleDraft>, actor:EntityActor, tx:DbService):Promise<void>;
}
export const WORKFLOW_SCHEDULE_REVISION_ZERO_HISTORY_SQL = `SELECT
 EXISTS(SELECT 1 FROM workflow_approvals WHERE workflow_id=$1)
 OR EXISTS(SELECT 1 FROM workflow_executions WHERE workflow_id=$1)
 OR EXISTS(SELECT 1 FROM mutation_operations WHERE workflow_id=$1)
 OR EXISTS(SELECT 1 FROM configuration_executions WHERE workflow_id=$1)
 OR EXISTS(SELECT 1 FROM workflow_steps WHERE workflow_id=$1 AND(operation_id IS NOT NULL OR state<>'pending'))
 OR EXISTS(SELECT 1 FROM workflow_schedules WHERE workflow_id=$1) AS blocked`;

/** Supplied only by the server's authenticated HTTP actor/context, never by a
 * workflow plan or request body. Optional field types match the existing actor
 * type; persistence rejects a missing value before any database operation. */
export interface WorkflowSubmissionAuditRequest { readonly requestId?: string; readonly ip?: string }
function submissionAuditRequest(value: WorkflowSubmissionAuditRequest): { requestId: string; ip: string } {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['requestId', 'ip'].includes(key)) || typeof value.requestId !== 'string' || !/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(value.requestId)
    || typeof value.ip !== 'string' || isIP(value.ip) === 0) throw new BadRequestException({ code: 'WORKFLOW_SUBMISSION_AUDIT_METADATA_REQUIRED' });
  return { requestId: value.requestId, ip: value.ip };
}

/** Public review keeps business changes, never private planning evidence. */
export function workflowMetadataProjection(value:unknown):Record<string,unknown>|null {
  if(value===null||value===undefined)return null;
  if(typeof value!=='object'||Array.isArray(value))return {};
  const source=value as Record<string,unknown>,output:Record<string,unknown>={};
  const fields=['id','revision','slug','name','title','description','category','status','state','published','registrationEnabled','registration_enabled','publicProxyOrigin','public_proxy_origin','documentHash','document_hash','content_hash','publicationRevision','current_revision','published_revision','applicationId','publicationId','grantId','consumerId','credentialId','generation','aclGroup','aclPluginId','keyAuthPluginId','retireConsumer','archive','reason','jobId','resourceType','resourceId','operation','sourceJobId','repositoryLabel','commitSha','pipelineReference','intervalMinutes','timezone','retentionDays','paused','scopeKind','currentVersion','ownerUserId','confirmationName','cacheKey','operationId','kind'];
  for(const field of fields)if(Object.hasOwn(source,field)&&(['string','number','boolean'].includes(typeof source[field])||source[field]===null))output[field]=source[field];
  if(source.branding&&typeof source.branding==='object'&&!Array.isArray(source.branding)){
    const branding=source.branding as Record<string,unknown>;output.branding=Object.fromEntries(['primaryColor','logoText','welcomeText'].filter(key=>typeof branding[key]==='string').map(key=>[key,branding[key]]));
  }
  if(source.payload&&typeof source.payload==='object'&&!Array.isArray(source.payload)){
    const payload=source.payload as Record<string,unknown>;
    output.payload=Object.fromEntries(['revision','confirmed','confirm_name','name','intervalMinutes','timezone','retentionDays','paused','sourceJobId','repositoryLabel','commitSha','pipelineReference']
      .filter(key=>Object.hasOwn(payload,key)&&['string','number','boolean'].includes(typeof payload[key])).map(key=>[key,payload[key]]));
  }
  return output;
}

/** DB-only immutable plan repository. Developer requests can use it without any Kong context. */
@Injectable()
export class WorkflowPlansService {
  private governance?:GovernanceMetadataApprovedDelegate;
  private configurationOrigin?:(ConfigurationOriginDelegate&{assertScheduledProposalOrigin?(plan:WorkflowPlanV1,base:WorkflowPlanV1,originalProposal:object,tx:DbService):Promise<void>});
  private workflowPolicy?:GovernanceMetadataApprovedDelegate;
  private iamMetadata?:Readonly<IamMetadataApprovedDelegate>;
  private metricsSetup?:Readonly<MetricsSetupApprovedDelegate>;
  private controlMetadata?:Readonly<ControlMetadataApprovedDelegate>;
  private annotationMetadata?:Readonly<EntityAnnotationApprovedDelegate>;
  installEntityAnnotationDelegate(delegate:EntityAnnotationApprovedDelegate):void{
    const names=['verifyIntent','assertSubject','verifyReviewer','assertWorkflowAdmission'] as const;
    if(this.annotationMetadata||!delegate||names.some(key=>typeof delegate[key]!=='function')||Object.keys(delegate).some(key=>!names.includes(key as any)))throw new ConflictException({code:'ENTITY_ANNOTATION_POLICY_ALREADY_INSTALLED'});
    this.annotationMetadata=Object.freeze({verifyIntent:delegate.verifyIntent.bind(delegate),assertSubject:delegate.assertSubject.bind(delegate),verifyReviewer:delegate.verifyReviewer.bind(delegate),assertWorkflowAdmission:delegate.assertWorkflowAdmission.bind(delegate)});
  }
  private async annotationIntent(plan:WorkflowPlanV1,tx:DbService):Promise<void>{
    assertEntityAnnotationPlan(plan);if(!this.annotationMetadata)throw new ConflictException({code:'ENTITY_ANNOTATION_POLICY_UNAVAILABLE'});await this.annotationMetadata.verifyIntent(plan,tx);
  }
  installControlMetadataDelegate(delegate:ControlMetadataApprovedDelegate):void{
    const names=['verifyIntent','assertSubject','verifyReviewer','assertWorkflowAdmission'] as const;
    if(this.controlMetadata||!delegate||names.some(key=>typeof delegate[key]!=='function')||Object.keys(delegate).some(key=>!names.includes(key as any)))throw new ConflictException({code:'CONTROL_METADATA_POLICY_ALREADY_INSTALLED'});
    this.controlMetadata=Object.freeze({verifyIntent:delegate.verifyIntent.bind(delegate),assertSubject:delegate.assertSubject.bind(delegate),verifyReviewer:delegate.verifyReviewer.bind(delegate),assertWorkflowAdmission:delegate.assertWorkflowAdmission.bind(delegate)});
  }
  private async controlIntent(plan:WorkflowPlanV1,tx:DbService):Promise<void>{
    assertControlMetadataPlan(plan);if(!this.controlMetadata)throw new ConflictException({code:'CONTROL_METADATA_POLICY_UNAVAILABLE'});await this.controlMetadata.verifyIntent(plan,tx);
  }
  private entityChange?:EntityChangeIntentWorkflowDelegate;
  private scheduledRevision?:Readonly<WorkflowScheduledRevisionDelegate>;
  private scheduledRevisionStorage?:Readonly<{name:string;checksum:string}>;
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly audit: AuditService,
    @Optional() private readonly approval?:WorkflowApprovalAuthorityService) {}
  installIamMetadataDelegate(delegate:IamMetadataApprovedDelegate):void{
    if(this.iamMetadata||!delegate||['verifyIntent','assertSubject','verifyReviewer'].some(key=>typeof(delegate as any)[key]!=='function'))throw new ConflictException({code:'IAM_WORKFLOW_POLICY_ALREADY_INSTALLED'});
    this.iamMetadata=Object.freeze({verifyIntent:delegate.verifyIntent.bind(delegate),assertSubject:delegate.assertSubject.bind(delegate),verifyReviewer:delegate.verifyReviewer.bind(delegate)});
  }
  private async iamIntent(plan:WorkflowPlanV1,tx:DbService):Promise<void>{
    assertIamMetadataPlan(plan);if(!this.iamMetadata)throw new ConflictException({code:'IAM_WORKFLOW_POLICY_UNAVAILABLE'});await this.iamMetadata.verifyIntent(plan,tx);
  }
  installMetricsSetupDelegate(delegate:MetricsSetupApprovedDelegate):void{
    if(this.metricsSetup||!delegate||['verifyIntent','assertSubject','verifyReviewer','nativeWorkspace'].some(key=>typeof(delegate as any)[key]!=='function'))throw new ConflictException({code:'METRICS_SETUP_POLICY_ALREADY_INSTALLED'});
    this.metricsSetup=Object.freeze(delegate);
  }
  private async metricsIntent(plan:WorkflowPlanV1,tx:DbService):Promise<void>{
    assertMetricsSetupPlan(plan);if(!this.metricsSetup)throw new ConflictException({code:'METRICS_SETUP_POLICY_UNAVAILABLE'});await this.metricsSetup.verifyIntent(plan,tx);
  }
  installScheduledRevisionDelegate(delegate:WorkflowScheduledRevisionDelegate, storage:Readonly<{name:string;checksum:string}>):void {
    if(this.scheduledRevision||!delegate||typeof delegate.verifyRevision!=='function'||typeof delegate.beforeApprovalFreeze!=='function'
      ||!storage||storage.name!=='029_m11_business_schedule_revisions.sql'||!/^[a-f\d]{64}$/.test(storage.checksum))
      throw new Error('A single exact SQL029 and original business schedule authoring registry is required');
    this.scheduledRevision=Object.freeze({verifyRevision:delegate.verifyRevision.bind(delegate),beforeApprovalFreeze:delegate.beforeApprovalFreeze.bind(delegate)});
    this.scheduledRevisionStorage=Object.freeze({...storage});
  }
  /** Append one scheduling revision before any historical vote or execution.
   * Old versions/steps/candidates/stages remain untouched. SQL029 narrowly
   * permits only this pointer advance and validates the complete fresh facts
   * at commit; missing migration or private original proposal stays closed. */
  async appendScheduledRevision(plan:Readonly<WorkflowScheduledPlanV1>,draft:Readonly<WorkflowScheduleDraft>,actor:EntityActor,
    originalProposal:object,tx:DbService):Promise<any> {
    if(!this.scheduledRevision||!this.scheduledRevisionStorage)throw new ConflictException({code:'WORKFLOW_SCHEDULE_REVISION_ADAPTER_UNAVAILABLE'});
    const contract=await tx.one<any>('SELECT checksum FROM schema_migrations WHERE name=$1',[this.scheduledRevisionStorage.name]);
    if(contract?.checksum!==this.scheduledRevisionStorage.checksum)throw new ConflictException({code:'WORKFLOW_SCHEDULE_REVISION_STORAGE_UNAVAILABLE'});
    const auditRequest=submissionAuditRequest({requestId:actor.requestId,ip:actor.ip});
    assertWorkflowScheduledPlan(plan as WorkflowPlanV1,draft,this.secrets);
    await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
    const pointer=await tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR UPDATE',[plan.workflowId,plan.clusterId,plan.workspaceId]);
    const old=await this.load(plan.clusterId,plan.workspaceId,plan.workflowId,tx);
    if(!pointer||pointer.state!=='pending'||pointer.approved_by!==null||pointer.approved_at!==null||pointer.approval_set_id!=null||pointer.approval_set_hmac!=null
      ||(old.plan as any).scheduling!==undefined||!['configuration_v2','portal-credential-issue','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'].includes(old.plan.kind)
      ||pointer.not_before!=null||pointer.window_start!=null||pointer.window_end!=null||old.row.revision!==pointer.revision||old.row.plan_hash!==pointer.plan_hash||plan.planRevision!==old.plan.planRevision+1
      ||plan.expiresAt!==old.plan.expiresAt||Date.parse(plan.expiresAt)<=Date.now())throw new ConflictException({code:'WORKFLOW_SCHEDULE_REVISION_NOT_PRISTINE'});
    const zero=await tx.one<any>(WORKFLOW_SCHEDULE_REVISION_ZERO_HISTORY_SQL,[plan.workflowId]);
    if(!zero||zero.blocked!==false)throw new ConflictException({code:'WORKFLOW_SCHEDULE_REVISION_HISTORY_EXISTS'});
    await this.scheduledRevision.verifyRevision(originalProposal,old,plan,draft,actor,tx);
    if(plan.kind==='configuration_v2'){
      if(this.configurationOrigin?.assertScheduledProposalOrigin)await this.configurationOrigin.assertScheduledProposalOrigin(plan as WorkflowPlanV1,old.plan,originalProposal,tx);
      else await this.storedConfigurationOrigin(plan as WorkflowPlanV1,tx);
    }
    await this.exactDefinition(plan.clusterId,plan.workspaceId,plan.definition,tx);
    const hash=this.secrets.fingerprint(plan),format=Number(pointer.approval_format??1);
    if(format!==2||!this.approval)throw new ConflictException({code:'WORKFLOW_SCHEDULE_APPROVAL_ADAPTER_UNAVAILABLE'});
    if(this.approval&&await this.approval.formatForDefinition(plan as WorkflowPlanV1,tx)!==format)throw new ConflictException({code:'WORKFLOW_SCHEDULE_POLICY_CHANGED'});
    if(await tx.exec(`UPDATE workflows SET plan_revision=$4,plan_hash=$5,not_before=$6,window_start=$7,window_end=$8,
      candidate_version=NULL,candidate_manifest_hmac=NULL,revision=revision+1,updated_at=clock_timestamp()
      WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND revision=$9 AND plan_revision=$10 AND plan_hash=$11
      AND state='pending' AND approved_by IS NULL AND approval_set_id IS NULL`,[plan.workflowId,plan.clusterId,plan.workspaceId,plan.planRevision,hash,
      draft.spec.notBefore,draft.spec.windowStart,draft.spec.windowEnd,pointer.revision,pointer.plan_revision,pointer.plan_hash])!==1)
      throw new ConflictException({code:'WORKFLOW_SCHEDULE_REVISION_CHANGED'});
    const safeImpact={...(old.version.safe_impact??{}),schedule:{id:draft.scheduleId,notBefore:draft.spec.notBefore,windowStart:draft.spec.windowStart,
      windowEnd:draft.spec.windowEnd,executorId:actor.user.id,approvalRequired:true,nativeAuthority:false}};
    await tx.exec(`INSERT INTO workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,
      payload_secret,policy_version,step_count,native_request_count,steps_hash,safe_diff,safe_impact,expires_at,created_by,created_by_developer_id,approval_format)
      VALUES($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb,$14,$15,NULL,$16)`,[plan.clusterId,plan.workspaceId,plan.workflowId,
      plan.planRevision,hash,plan.executionMode,this.secrets.encrypt(plan,planAad(plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision)),
      plan.definition.version,plan.steps.length,plan.steps.reduce((n,s)=>n+s.nativeRequests.length,0),this.secrets.fingerprint(plan.steps),
      JSON.stringify(old.version.safe_diff??[]),JSON.stringify(safeImpact),plan.expiresAt,actor.user.id,format]);
    for(const step of plan.steps)await tx.exec(`INSERT INTO workflow_steps(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,
      approval_required,step_key,step_order,kind,handler,entity_type,entity_id,parent_id,credential_kind,permission_action,mutation_action,
      mutation_payload_hmac,mutation_idempotency_key,before_fingerprint,native_requests,metadata_before_hmac,metadata_revision,metadata_payload_hmac,dependencies)
      VALUES($1,$2,$3,$4,$5,$6,$7,true,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21::jsonb,$22,$23,$24,$25)`,[step.id,plan.clusterId,plan.workspaceId,
      plan.workflowId,plan.planRevision,hash,plan.executionMode,step.key,step.order,step.kind,step.handler??null,step.entityType,step.entityId??null,
      step.parentId??null,step.credentialKind??null,step.permissionAction,step.mutationAction??null,step.mutationPayloadHmac??null,
      step.mutationIdempotencyKey??null,step.beforeFingerprint??null,JSON.stringify(normalizedNativeRequests(step.nativeRequests,this.secrets)),
      step.metadataBeforeHmac??null,step.metadataRevision??null,step.metadataPayloadHmac??null,step.dependencies]);
    // The true SQL026 row precedes candidate freezing so candidate READ policy
    // can authenticate the newly sealed plan/window in this same transaction.
    await this.scheduledRevision.beforeApprovalFreeze(originalProposal,plan,draft,actor,tx);
    if(format===2)await this.approval!.freezeSubmission(plan as WorkflowPlanV1,tx);
    else await tx.exec(`INSERT INTO workflow_stages(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,state,activated_at)
      VALUES($1,$2,$3,$4,$5,1,'active',clock_timestamp())`,[plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,hash]);
    await this.scheduledRevision.verifyRevision(originalProposal,old,plan,draft,actor,tx);
    await this.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,
      workflowId:plan.workflowId,action:'workflow.business-schedule.revision',requestId:auditRequest.requestId,ip:auditRequest.ip,
      before:{planRevision:old.plan.planRevision,planHash:old.row.plan_hash},after:{planRevision:plan.planRevision,planHash:hash,scheduleId:draft.scheduleId,
      executorId:actor.user.id,requesterType:plan.requester.type,requesterId:plan.requester.id,notBefore:draft.spec.notBefore,windowStart:draft.spec.windowStart,
      windowEnd:draft.spec.windowEnd,nativeAuthority:false},result:'success'},tx);
    return tx.one('SELECT * FROM workflows WHERE id=$1',[plan.workflowId]);
  }
  installWorkflowPolicyMetadataDelegate(delegate:GovernanceMetadataApprovedDelegate):void {
    if(this.workflowPolicy||!delegate||typeof delegate.verifyIntent!=='function'||typeof delegate.assertSubject!=='function'||typeof delegate.verifyReviewer!=='function')throw new ConflictException({code:'WORKFLOW_POLICY_METADATA_ALREADY_INSTALLED'});
    this.workflowPolicy=Object.freeze(delegate);
  }
  installEntityChangeIntentDelegate(delegate:EntityChangeIntentWorkflowDelegate):void {
    if(this.entityChange||!delegate||typeof delegate.verifyIntent!=='function'||typeof delegate.assertSubject!=='function'||typeof delegate.verifyReviewer!=='function'||typeof delegate.revalidate!=='function')throw new ConflictException({code:'ENTITY_CHANGE_INTENT_POLICY_ALREADY_INSTALLED'});
    this.entityChange=Object.freeze(delegate);
  }
  async assertEntityChangeSubject(plan:WorkflowPlanV1,userId:string,action:'read'|'write'|'approve',tx:DbService=this.db):Promise<void>{
    assertEntityChangeWorkflowPlan(plan);if(!this.entityChange)throw new ConflictException({code:'ENTITY_CHANGE_INTENT_POLICY_UNAVAILABLE'});
    await this.entityChange.assertSubject(plan,userId,action,tx);
  }
  async revalidateEntityChange(plan:WorkflowPlanV1,actor:import('../entities/entities.types').EntityActor,phase:'submit'|'approve'|'claim'):Promise<void>{
    assertEntityChangeWorkflowPlan(plan);if(!this.entityChange)throw new ConflictException({code:'ENTITY_CHANGE_INTENT_POLICY_UNAVAILABLE'});
    await this.entityChange.revalidate(plan,actor,phase);
  }
  installGovernanceMetadataDelegate(delegate:GovernanceMetadataApprovedDelegate):void {
    if(this.governance||!delegate||typeof delegate.verifyIntent!=='function'||typeof delegate.assertSubject!=='function'||typeof delegate.verifyReviewer!=='function')throw new ConflictException({code:'GOVERNANCE_WORKFLOW_POLICY_ALREADY_INSTALLED'});
    this.governance=Object.freeze(delegate);
  }
  installConfigurationOriginDelegate(delegate:NonNullable<WorkflowPlansService['configurationOrigin']>):void{
    if(this.configurationOrigin||!delegate||typeof delegate.assertStoredOrigin!=='function'||delegate.assertOrigin!==undefined&&typeof delegate.assertOrigin!=='function')throw new ConflictException({code:'CONFIGURATION_ORIGIN_POLICY_ALREADY_INSTALLED'});
    this.configurationOrigin=Object.freeze(delegate);
  }
  private async storedConfigurationOrigin(plan:WorkflowPlanV1,tx:DbService):Promise<void>{
    assertConfigurationWorkflowPlan(plan);
    const job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
    if(!job)throw new ConflictException({code:'CONFIGURATION_ORIGIN_JOB_UNAVAILABLE'});
    let marker;try{marker=configurationOriginMarker(job);}catch{throw new ConflictException({code:'CONFIGURATION_ORIGIN_MARKER_INVALID'});}
    let durable;try{durable=configurationDurableMarker(job);}catch{throw new ConflictException({code:'CONFIGURATION_DURABLE_MARKER_INVALID'});}
    if(!this.configurationOrigin?.assertStoredOrigin){
      if(marker||durable)throw new ConflictException({code:'CONFIGURATION_ORIGIN_POLICY_UNAVAILABLE'});
      const presence=await tx.one<any>(DURABLE_CONFIGURATION_PRESENCE_QUERY,[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!isProvenLegacyConfigurationRow(presence))throw new ConflictException({code:'CONFIGURATION_DURABLE_POLICY_UNAVAILABLE'});
    }
    if(this.configurationOrigin?.assertStoredOrigin)await this.configurationOrigin.assertStoredOrigin(plan,tx);
  }
  private async governanceIntent(plan:WorkflowPlanV1,tx:DbService):Promise<void>{
    assertGovernanceMetadataPlan(plan);
    if(!this.governance)throw new ConflictException({code:'GOVERNANCE_WORKFLOW_POLICY_UNAVAILABLE'});
    await this.governance.verifyIntent(plan,tx);
  }
  async definitions(cid:string,wid:string,userId:string,tx?:DbService):Promise<void> {
    // The current-version FK and complete stage constraints are deferred.
    // Standalone calls must not autocommit a definition before its version.
    if(!tx)return this.db.transaction(transaction=>this.definitions(cid,wid,userId,transaction));
    await tx.exec('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`workflow-definitions:${cid}:${wid}`]);
    for(const kind of WORKFLOW_KINDS){
      const existing=await tx.one<any>('SELECT id FROM workflow_definitions WHERE cluster_id=$1 AND workspace_id=$2 AND code=$3',[cid,wid,kind]);
      if(existing)continue;
      if(kind==='iam-metadata'||kind==='metrics-setup'||kind==='control-metadata'||kind==='entity-annotation'){
        const role=await tx.one<any>("SELECT id FROM roles WHERE builtin_kind='super-admin' AND code='super-admin' AND cluster_id IS NULL AND workspace_id IS NULL AND status='active' AND deleted_at IS NULL");
        if(!role?.id)throw new ConflictException({code:'IAM_WORKFLOW_DEFAULT_REVIEWER_ROLE_UNAVAILABLE'});
        const id=randomUUID(),selector={roles:[role.id]},policy={version:2,kind,allowSelfApproval:false,distinctAcrossStages:true,intentTtlHours:24,
          stages:[{level:1,name:'管理员审批',mode:'any',threshold:1,selector}]},hash=this.secrets.fingerprint(policy);
        await tx.exec(`INSERT INTO workflow_definitions(id,cluster_id,workspace_id,code,name,kind,created_by) VALUES($1,$2,$3,$4,$4,$4,$5)`,[id,cid,wid,kind,userId]);
        await tx.exec(`INSERT INTO workflow_definition_versions(cluster_id,workspace_id,definition_id,version,mode,policy,policy_hash,created_by,approval_format) VALUES($1,$2,$3,1,'single',$4::jsonb,$5,$6,2)`,[cid,wid,id,JSON.stringify(policy),hash,userId]);
        await tx.exec(`INSERT INTO workflow_definition_stages(cluster_id,workspace_id,definition_id,definition_version,level,name,required_approvals,selector,approval_format,stage_mode) VALUES($1,$2,$3,1,1,'管理员审批',1,$4::jsonb,2,'any')`,[cid,wid,id,JSON.stringify(selector)]);
        continue;
      }
      const id=randomUUID(),policy={version:1,mode:'single',allowSelfApproval:false,kind},hash=this.secrets.fingerprint(policy);
      await tx.exec(`INSERT INTO workflow_definitions(id,cluster_id,workspace_id,code,name,kind,created_by) VALUES($1,$2,$3,$4,$4,$4,$5)`,[id,cid,wid,kind,userId]);
      await tx.exec(`INSERT INTO workflow_definition_versions(cluster_id,workspace_id,definition_id,version,policy,policy_hash,created_by) VALUES($1,$2,$3,1,$4::jsonb,$5,$6)`,[cid,wid,id,JSON.stringify(policy),hash,userId]);
      await tx.exec(`INSERT INTO workflow_definition_stages(cluster_id,workspace_id,definition_id,definition_version,level,name) VALUES($1,$2,$3,1,1,'管理员审批')`,[cid,wid,id]);
    }
  }
  async definition(cid:string,wid:string,kind:WorkflowKind,tx:DbService=this.db):Promise<WorkflowPlanV1['definition']>{
    const row=await tx.one<any>(`SELECT d.id,d.current_version,v.policy_hash FROM workflow_definitions d JOIN workflow_definition_versions v ON v.definition_id=d.id AND v.version=d.current_version AND v.cluster_id=d.cluster_id AND v.workspace_id=d.workspace_id WHERE d.cluster_id=$1 AND d.workspace_id=$2 AND d.kind=$3 AND d.status='active'`,[cid,wid,kind]);
    if(!row)throw new ConflictException({code:'WORKFLOW_DEFINITION_UNAVAILABLE'});return{id:row.id,version:row.current_version,policyHash:row.policy_hash};
  }
  async exactDefinition(cid:string,wid:string,definition:WorkflowPlanV1['definition'],tx:DbService=this.db):Promise<WorkflowPlanV1['definition']>{
    const row=await tx.one<any>('SELECT definition_id,version,policy_hash FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[cid,wid,definition.id,definition.version]);
    if(!row||row.policy_hash!==definition.policyHash)throw new ConflictException({code:'WORKFLOW_DEFINITION_UNAVAILABLE'});
    return{id:row.definition_id,version:row.version,policyHash:row.policy_hash};
  }
  async persist(plan:WorkflowPlanV1,key:string,request:unknown,tx:DbService,serverAuditRequest:WorkflowSubmissionAuditRequest):Promise<any>{
    const auditRequest=submissionAuditRequest(serverAuditRequest);
    validateWorkflowPlan(plan);workflowKey(key);let migrationMaterial:WorkspaceMigrationMaterial|undefined;
    if(plan.kind==='iam-metadata'){
      await this.iamIntent(plan,tx);
      const edge=await tx.one<any>('SELECT actor_id,workflow_id,idempotency_key,request_hmac FROM iam_metadata_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!edge||edge.actor_id!==plan.requester.id||edge.workflow_id!==plan.workflowId||edge.idempotency_key!==key||edge.request_hmac!==this.secrets.fingerprint(request))throw new ConflictException({code:'IAM_WORKFLOW_SUBMISSION_BINDING_INVALID'});
    }
    if(plan.kind==='metrics-setup'){
      await this.metricsIntent(plan,tx);
      const edge=await tx.one<any>('SELECT actor_id,workflow_id,idempotency_key,request_hmac FROM metrics_setup_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!edge||edge.actor_id!==plan.requester.id||edge.workflow_id!==plan.workflowId||edge.idempotency_key!==key||edge.request_hmac!==this.secrets.fingerprint(request))throw new ConflictException({code:'METRICS_SETUP_SUBMISSION_BINDING_INVALID'});
    }
    if(plan.kind==='control-metadata'){
      await this.controlIntent(plan,tx);
      const edge=await tx.one<any>('SELECT actor_id,workflow_id,idempotency_key,request_hmac FROM control_metadata_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!edge||edge.actor_id!==plan.requester.id||edge.workflow_id!==plan.workflowId||edge.idempotency_key!==key||edge.request_hmac!==this.secrets.fingerprint(request))throw new ConflictException({code:'CONTROL_METADATA_SUBMISSION_BINDING_INVALID'});
    }
    if(plan.kind==='entity-annotation'){
      await this.annotationIntent(plan,tx);
      const edge=await tx.one<any>('SELECT actor_id,workflow_id,idempotency_key,request_hmac FROM entity_annotation_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!edge||edge.actor_id!==plan.requester.id||edge.workflow_id!==plan.workflowId||edge.idempotency_key!==key||edge.request_hmac!==this.secrets.fingerprint(request))throw new ConflictException({code:'ENTITY_ANNOTATION_SUBMISSION_BINDING_INVALID'});
    }
    if(plan.kind==='native-change'){
      assertEntityChangeWorkflowPlan(plan);if(!this.entityChange)throw new ConflictException({code:'ENTITY_CHANGE_INTENT_POLICY_UNAVAILABLE'});
      await this.entityChange.verifyIntent(plan,tx);
      const submission=await tx.one<any>('SELECT actor_id,workflow_id,submit_key,request_hmac FROM entity_change_submissions WHERE intent_id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!submission||submission.actor_id!==plan.requester.id||submission.workflow_id!==plan.workflowId||submission.submit_key!==key||submission.request_hmac!==this.secrets.fingerprint(request))throw new ConflictException({code:'ENTITY_CHANGE_SUBMISSION_BINDING_INVALID'});
    }
    if(plan.kind==='workflow-policy-metadata'){
      assertWorkflowPolicyMetadataPlan(plan);
      if(!this.workflowPolicy)throw new ConflictException({code:'WORKFLOW_POLICY_METADATA_UNAVAILABLE'});
      await this.workflowPolicy.verifyIntent(plan,tx);
      const intent=await tx.one<any>('SELECT actor_id,workflow_id,idempotency_key,request_hmac FROM workflow_policy_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!intent||intent.actor_id!==plan.requester.id||intent.workflow_id!==plan.workflowId||intent.idempotency_key!==key||intent.request_hmac!==this.secrets.fingerprint(request))throw new ConflictException({code:'WORKFLOW_POLICY_REQUEST_BINDING_INVALID'});
    }
    if(plan.kind==='governance-metadata'){
      await this.governanceIntent(plan,tx);
      const intent=await tx.one<any>('SELECT actor_id,workflow_id,idempotency_key,request_hmac FROM governance_metadata_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!intent||intent.actor_id!==plan.requester.id||intent.workflow_id!==plan.workflowId||intent.idempotency_key!==key||intent.request_hmac!==this.secrets.fingerprint(request))throw new ConflictException({code:'GOVERNANCE_WORKFLOW_REQUEST_BINDING_INVALID'});
    }
    if(plan.kind==='workspace-migration'){
      const step=assertWorkspaceMigrationWorkflowPlan(plan),payload=step.mutationPayload as WorkspaceMigrationWorkflowPayload;
      const row=await tx.one<any>('SELECT * FROM workspace_migration_plans WHERE id=$1 AND cluster_id=$2 AND source_workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      const binding=await tx.one<any>('SELECT * FROM workspace_migration_workflow_bindings WHERE cluster_id=$1 AND migration_plan_id=$2 AND workflow_id=$3',[plan.clusterId,plan.subject.id,plan.workflowId]);
      if(!row||!binding||row.actor_id!==plan.requester.id||row.state!=='planned'||row.operation_id||row.plan_hash!==payload.plan_hash||binding.actor_id!==row.actor_id||binding.source_workspace_id!==plan.workspaceId||binding.target_workspace_id!==plan.migration!.targetWorkspaceId||binding.migration_plan_hash!==row.plan_hash||binding.material_hmac!==plan.migration!.materialHmac)throw new ConflictException({code:'MIGRATION_WORKFLOW_BINDING_INVALID'});
      migrationMaterial=this.secrets.decrypt<WorkspaceMigrationMaterial>(row.payload_secret,`workspace-migration:${row.id}`);
      if(this.secrets.fingerprint(migrationMaterial)!==plan.migration!.materialHmac)throw new ConflictException({code:'MIGRATION_WORKFLOW_BINDING_INVALID'});
    }
    if(plan.kind==='toolbox-operation'){
      const step=assertToolboxWorkflowPlan(plan),payload=step.metadata as ToolboxWorkflowPayload,row=await tx.one<any>('SELECT * FROM toolbox_operations WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
      if(!row||row.actor_id!==plan.requester.id||row.workflow_id!==plan.workflowId||row.cache_key!==payload.cacheKey||row.execution_mode!==plan.executionMode||row.transport_scope!==plan.scope.transportScope||row.state!=='pending-approval'||row.remote_started)throw new ConflictException({code:'CACHE_WORKFLOW_BINDING_INVALID'});
    }
    if(plan.kind==='configuration_v2'){
      await this.storedConfigurationOrigin(plan,tx);
      const step=assertConfigurationWorkflowPlan(plan),payload=step.metadata as ConfigurationWorkflowPayload;
      const job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[plan.clusterId,plan.workspaceId,payload.jobId]);
      const version=await tx.one<any>('SELECT plan_hash FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4',[plan.clusterId,plan.workspaceId,payload.planId,payload.planRevision]);
      if(!job||job.actor_id!==plan.requester.id||job.plan_id!==payload.planId||job.plan_revision!==payload.planRevision||job.plan_hash!==payload.planHash||version?.plan_hash!==payload.planHash
        ||job.transport_scope!==plan.scope.transportScope||job.cluster_revision!==plan.scope.clusterRevision||job.workspace_revision!==plan.scope.workspaceRevision
        ||job.execution_mode!==plan.executionMode||job.approval_required!==plan.approvalRequired||job.workflow_id&&job.workflow_id!==plan.workflowId
        ||step.metadataBeforeHmac!==this.secrets.fingerprint(step.before??null)||step.metadataPayloadHmac!==this.secrets.fingerprint(payload))throw new ConflictException({code:'CONFIGURATION_WORKFLOW_BINDING_INVALID'});
    }
    if(plan.kind==='configuration-metadata'){
      const step=assertConfigurationMetadataWorkflowPlan(plan),metadata=step.metadata as ConfigurationMetadataPayload;
      const job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[plan.clusterId,plan.workspaceId,metadata.jobId]);
      if(!job||job.actor_id!==plan.requester.id||job.kind!=='compare'||job.plan_id!=null||job.transport_scope!==plan.scope.transportScope
        ||job.cluster_revision!==plan.scope.clusterRevision||job.workspace_revision!==plan.scope.workspaceRevision||job.execution_mode!==plan.executionMode
        ||job.approval_required!==plan.approvalRequired||job.workflow_id&&job.workflow_id!==plan.workflowId
        ||step.metadataBeforeHmac!==this.secrets.fingerprint(step.before??null)||step.metadataPayloadHmac!==this.secrets.fingerprint(metadata))throw new ConflictException({code:'CONFIGURATION_METADATA_WORKFLOW_BINDING_INVALID'});
      const input=configurationMetadataLedgerInput(metadata),scope={clusterId:job.cluster_id,workspaceId:job.workspace_id,transportScope:job.transport_scope,kind:job.scope_kind,rootIds:job.root_ids};
      if(!job.input_secret||this.secrets.fingerprint(this.secrets.decrypt(job.input_secret,`configuration-job:${job.id}`))!==this.secrets.fingerprint(input)
        ||job.request_hmac!==this.secrets.fingerprint({scope,kind:'compare',input}))throw new ConflictException({code:'CONFIGURATION_METADATA_WORKFLOW_BINDING_INVALID'});
    }
    const hash=this.secrets.fingerprint(plan),requestHash=this.secrets.fingerprint({requester:plan.requester,clusterId:plan.clusterId,workspaceId:plan.workspaceId,request});
    const column=plan.requester.type==='console'?'requester_user_id':'requester_developer_id';
    const old=await tx.one<any>(`SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND ${column}=$3 AND idempotency_key=$4`,[plan.clusterId,plan.workspaceId,plan.requester.id,key]);
    if(old){if(old.request_hash!==requestHash)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT'});return old;}
    const native=plan.steps.reduce((sum,step)=>sum+step.nativeRequests.length,0),approvalFormat=this.approval?await this.approval.formatForDefinition(plan,tx):1;
    if(plan.kind==='entity-annotation'&&approvalFormat!==2)throw new ConflictException({code:'ENTITY_ANNOTATION_APPROVAL_FORMAT_REQUIRED'});
    await tx.exec(`INSERT INTO workflows(id,cluster_id,workspace_id,kind,subject_type,subject_id,requester_type,requester_user_id,requester_developer_id,definition_id,definition_version,plan_revision,plan_hash,execution_mode,approval_required,state,request_hash,idempotency_key,expires_at${approvalFormat===2?',approval_format':''}) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'pending',$16,$17,$18${approvalFormat===2?',$19':''})`,[plan.workflowId,plan.clusterId,plan.workspaceId,plan.kind,plan.subject.type,plan.subject.id,plan.requester.type,plan.requester.type==='console'?plan.requester.id:null,plan.requester.type==='developer'?plan.requester.id:null,plan.definition.id,plan.definition.version,plan.planRevision,hash,plan.executionMode,plan.approvalRequired,requestHash,key,plan.expiresAt,...(approvalFormat===2?[2]:[])]);
    const project=plan.kind==='event-metadata'?eventMetadataProjection:plan.kind==='governance-metadata'?governanceMetadataProjection:plan.kind==='workflow-policy-metadata'?workflowPolicyMetadataProjection:workflowMetadataProjection;
    let diff=migrationMaterial?migrationMaterial.nodes.map(node=>({kind:node.inheritedOnly?'inherited':'native',operation:'migrate',entityType:node.type,entityId:node.id,before:{workspaceId:migrationMaterial!.source.id,tags:node.data.tags??[]},after:{workspaceId:migrationMaterial!.target.id,tags:node.afterTags}})):plan.steps.map(step=>({id:step.id,kind:step.kind,operation:step.mutationAction??step.handler,entityType:step.entityType,entityId:step.entityId??null,before:this.secrets.redact(step.kind==='metadata'?project(step.before):step.before??null),after:this.secrets.redact(step.kind==='metadata'?project(step.metadata):step.mutationPayload??null)}));
    if(plan.kind==='metrics-setup')diff=metricsSetupPublicProjection(diff,this.secrets);
    let impact:Record<string,unknown>=migrationMaterial?{subject:plan.subject,nativeRequests:native,sourceWorkspaceId:migrationMaterial.source.id,targetWorkspaceId:migrationMaterial.target.id,objectCount:migrationMaterial.nodes.length,rollback:'执行前将加密保存对象快照；回迁须重新预览并按集群模式批准',partialFailure:'Kong 无跨对象事务；原计划与原执行键不自动重放'}:{subject:plan.subject,nativeRequests:native,rollback:'回收站与执行前受限快照'};
    if(plan.kind==='native-change'){
      const payload=assertEntityChangeWorkflowPlan(plan).metadata as import('./entity-change-intent.types').EntityChangeWorkflowPayload;
      const source=await tx.one<any>('SELECT safe_review,envelope_ciphertext,material_hmac,change_digest,packet_manifest_hmac FROM entity_change_intent_versions WHERE intent_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND intent_revision=$4 AND material_hmac=$5',[plan.subject.id,plan.clusterId,plan.workspaceId,payload.intentRevision,payload.materialHmac]);
      if(!source?.safe_review||!Array.isArray(source.safe_review.changes))throw new ConflictException({code:'ENTITY_CHANGE_REVIEW_SOURCE_UNAVAILABLE'});
      // verifyIntent above authenticates the persisted workflow/intent binding.
      // Recheck the exact envelope before deriving relationships; safe_review
      // IDs alone are neither graph evidence nor an authorization grant.
      const envelope=this.secrets.decrypt<EntityChangeIntentEnvelope>(source.envelope_ciphertext,entityChangeIntentAad(plan.clusterId,plan.workspaceId,plan.subject.id,payload.intentRevision)),material=envelope.prepared;
      const {changeDigest,...original}=material;
      if(![1,2].includes(envelope.version)||envelope.intentId!==plan.subject.id||envelope.revision!==payload.intentRevision||envelope.clusterId!==plan.clusterId||envelope.workspaceId!==plan.workspaceId
        ||envelope.requesterId!==plan.requester.id||material.requesterId!==plan.requester.id||material.clusterId!==plan.clusterId||material.workspaceId!==plan.workspaceId
        ||this.secrets.fingerprint(envelope)!==payload.materialHmac||source.material_hmac!==payload.materialHmac
        ||this.secrets.fingerprint(original)!==changeDigest||changeDigest!==payload.changeDigest||source.change_digest!==changeDigest
        ||this.secrets.fingerprint(normalizedEntityChangePackets(material,this.secrets))!==payload.packetManifestHmac||envelope.packetManifestHmac!==payload.packetManifestHmac||source.packet_manifest_hmac!==payload.packetManifestHmac
        ||this.secrets.fingerprint(envelope.review)!==this.secrets.fingerprint(source.safe_review))throw new ConflictException({code:'ENTITY_CHANGE_REVIEW_SOURCE_INVALID'});
      const complete=this.secrets.redact(source.safe_review.changes.map((item:any)=>({kind:'native',operation:item.action,entityType:item.entityType,entityId:item.nativeId,originalNativeId:item.originalNativeId??null,before:item.before,after:item.after})));
      const detailed=Buffer.byteLength(JSON.stringify(complete))<=262144;
      diff=(detailed?complete:source.safe_review.changes.map((item:any)=>({kind:'native',operation:item.action,entityType:item.entityType,entityId:item.nativeId,originalNativeId:item.originalNativeId??null,detailsAvailable:true}))) as typeof diff;
      impact=nativeWorkflowImpact(material,plan.subject,payload.intentRevision,detailed);
    }
    await tx.exec(`INSERT INTO workflow_versions(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,payload_secret,policy_version,step_count,native_request_count,steps_hash,safe_diff,safe_impact,expires_at,created_by,created_by_developer_id${approvalFormat===2?',approval_format':''}) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14::jsonb,$15,$16,$17${approvalFormat===2?',$18':''})`,[plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,hash,plan.executionMode,plan.approvalRequired,this.secrets.encrypt(plan,planAad(plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision)),plan.definition.version,plan.steps.length,native,this.secrets.fingerprint(plan.steps),JSON.stringify(diff),JSON.stringify(impact),plan.expiresAt,plan.requester.type==='console'?plan.requester.id:null,plan.requester.type==='developer'?plan.requester.id:null,...(approvalFormat===2?[2]:[])]);
    for(const step of plan.steps)await tx.exec(`INSERT INTO workflow_steps(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,step_key,step_order,kind,handler,entity_type,entity_id,parent_id,credential_kind,permission_action,mutation_action,mutation_payload_hmac,mutation_idempotency_key,before_fingerprint,native_requests,metadata_before_hmac,metadata_revision,metadata_payload_hmac,dependencies) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22::jsonb,$23,$24,$25,$26)`,[step.id,plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,hash,plan.executionMode,plan.approvalRequired,step.key,step.order,step.kind,step.handler??null,step.entityType,step.entityId??null,step.parentId??null,step.credentialKind??null,step.permissionAction,step.mutationAction??null,step.mutationPayloadHmac??null,step.mutationIdempotencyKey??null,step.beforeFingerprint??null,JSON.stringify(normalizedNativeRequests(step.nativeRequests,this.secrets)),step.metadataBeforeHmac??null,step.metadataRevision??null,step.metadataPayloadHmac??null,step.dependencies]);
    if(approvalFormat===2)await this.approval!.freezeSubmission(plan,tx);
    else if(plan.approvalRequired)await tx.exec(`INSERT INTO workflow_stages(cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,level,state,activated_at) VALUES($1,$2,$3,$4,$5,1,'active',now())`,[plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,hash]);
    await this.audit.append({actorId:plan.requester.type==='console'?plan.requester.id:undefined,actorType:plan.requester.type==='console'?'user':'developer',clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,action:'workflow.submit',requestId:auditRequest.requestId,ip:auditRequest.ip,after:{kind:plan.kind,planHash:hash,approvalRequired:plan.approvalRequired},result:'success',scopeHints:{quality:'verified',module:'workflows',subject:{type:'workflows',id:plan.workflowId},beforeExists:false,afterExists:true,afterTags:[],afterWorkspaceId:plan.workspaceId}},tx);
    return tx.one<any>('SELECT * FROM workflows WHERE id=$1',[plan.workflowId]);
  }
  async load(cid:string,wid:string,id:string,tx:DbService=this.db):Promise<{row:any;plan:WorkflowPlanV1;version:any}>{
    const row=await tx.one<any>('SELECT * FROM workflows WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[id,cid,wid]);if(!row)throw new NotFoundException({code:'WORKFLOW_NOT_FOUND'});
    const version=await tx.one<any>('SELECT * FROM workflow_versions WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND plan_revision=$4',[id,cid,wid,row.plan_revision]);if(!version)throw new ConflictException({code:'WORKFLOW_PLAN_INVALID'});
    const plan=this.secrets.decrypt<WorkflowPlanV1>(version.payload_secret,planAad(cid,wid,id,row.plan_revision));validateWorkflowPlan(plan);
    if(this.secrets.fingerprint(plan)!==row.plan_hash||version.plan_hash!==row.plan_hash||this.secrets.fingerprint(plan.steps)!==version.steps_hash)throw new ConflictException({code:'WORKFLOW_PLAN_INVALID'});
    if(plan.kind==='governance-metadata')await this.governanceIntent(plan,tx);
    if(plan.kind==='iam-metadata')await this.iamIntent(plan,tx);
    if(plan.kind==='metrics-setup')await this.metricsIntent(plan,tx);
    if(plan.kind==='control-metadata')await this.controlIntent(plan,tx);
    if(plan.kind==='entity-annotation')await this.annotationIntent(plan,tx);
    if(plan.kind==='workflow-policy-metadata'){
      if(!this.workflowPolicy)throw new ConflictException({code:'WORKFLOW_POLICY_METADATA_UNAVAILABLE'});
      await this.workflowPolicy.verifyIntent(plan,tx);
    }
    if(plan.kind==='configuration_v2')await this.storedConfigurationOrigin(plan,tx);
    if(plan.kind==='native-change'){
      if(!this.entityChange)throw new ConflictException({code:'ENTITY_CHANGE_INTENT_POLICY_UNAVAILABLE'});
      await this.entityChange.verifyIntent(plan,tx);
    }
    return{row,plan,version};
  }
}
