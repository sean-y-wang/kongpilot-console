import { isSupportedKong } from '../../infrastructure/kong/kong-capabilities';
import { ConflictException, ForbiddenException } from '@nestjs/common';
import type { DbService } from '../../infrastructure/db.service';
import type { SecretService } from '../../infrastructure/secret.service';
import type { RedisService } from '../../infrastructure/redis.service';
import type { KongService } from '../../infrastructure/kong/kong.service';
import type { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import {CONFIGURATION_TIMEOUT_MS} from '../../infrastructure/kong/configuration-budget';
import { assertKongPath } from '../../infrastructure/kong/policy';
import type { AuthorizationService } from '../authorization/authorization.service';
import { validGrant } from '../authorization/grant-policy';
import type { MutationContext } from '../mutations/mutation.service';
import { SnapshotCryptoService } from '../config-storage/snapshot-crypto.service';
import type { ConfigPlan, ConfigurationPlanStep } from '../configuration/configuration.types';
import { planAad, snapshotAad, type WorkflowPlanV1, type WorkflowSnapshotV1 } from './workflow.types';
import { assertConfigurationWorkflowPlan, configurationMutationKey, type ConfigurationWorkflowPayload } from './configuration-workflow';
import type { ApprovedExecutionProof, ApprovedNativeRequest, ApprovedNativeStage, ApprovedMutationBindingV2, ConfigurationApprovedDelegate,ApprovedStepProof,ConfigurationNativeBeforeInput,ConfigurationNativeBeforeReadResult } from './approved-execution.types';
import {configurationOriginMarker} from './approved-execution.types';
import type { WorkflowScheduledConfigurationExecutionProof } from './workflow-scheduled-configuration-origin.types';
import type { WorkflowApprovalAuthorityService } from './workflow-approval-authority.service';

const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i,hex=/^[a-f\d]{64}$/;
const denied=(code='CONFIGURATION_APPROVED_INVALID')=>new ForbiddenException({code});
export interface ConfigurationApprovedLoaded {execution:any;job:any;version:any;plan:ConfigPlan;rows:any[];workflow:any;wrapper:WorkflowPlanV1;claimExpiresAt:number;scheduledOrigin?:Readonly<WorkflowScheduledConfigurationExecutionProof>}
export interface ConfigurationNativeBeforeBinding {readonly loaded:ConfigurationApprovedLoaded;readonly step:ConfigurationPlanStep;readonly row:any;readonly request:ConfigurationPlanStep['nativeRequests'][number];readonly input:Readonly<ConfigurationNativeBeforeInput>;}

/** Only the private V2 binding path uses this query, in the mutation INSERT
 * transaction. The reciprocal link must exist before the current job verifier
 * can inspect that inserted operation. Full authority and encrypted-plan checks
 * still run afterwards; any rejection rolls this link and INSERT back together.
 * Params: step, operation, revision, CID, anchor WID, job, execution,
 * plan revision/hash, workflow, actor, SID, permission version, object WID,
 * original key, action, entity type/ID, parent, credential kind, before/body HMAC.
 */
export const CONFIGURATION_APPROVED_OPERATION_LINK_SQL = `UPDATE configuration_job_steps s
 SET operation_id=o.id,revision=s.revision+1
 FROM configuration_executions e,configuration_jobs j,configuration_plan_objects p,workflows w,mutation_operations o
 WHERE s.id=$1 AND o.id=$2 AND s.revision=$3 AND s.cluster_id=$4 AND s.workspace_id=$5
 AND s.job_id=$6 AND s.execution_id=$7 AND s.plan_revision=$8 AND s.plan_hash=$9
 AND s.state='running' AND s.approval_required=true AND s.operation_id IS NULL AND s.receipt_operation_id IS NULL
 AND e.id=s.execution_id AND e.cluster_id=s.cluster_id AND e.workspace_id=s.workspace_id AND e.job_id=s.job_id
 AND e.plan_id=s.plan_id AND e.plan_revision=s.plan_revision AND e.plan_hash=s.plan_hash
 AND e.execution_mode='approval' AND e.state='executing' AND e.workflow_id=$10 AND e.actor_id=$11
 AND e.permission_version=$13 AND e.expires_at>clock_timestamp()
 AND j.id=s.job_id AND j.cluster_id=s.cluster_id AND j.workspace_id=s.workspace_id
 AND j.plan_id=s.plan_id AND j.plan_revision=s.plan_revision AND j.plan_hash=s.plan_hash
 AND j.workflow_id=e.workflow_id AND j.actor_id=e.actor_id AND j.origin_session_id=$12
 AND j.execution_mode='approval' AND j.approval_required=true AND j.state='running'
 AND j.permission_version=e.permission_version AND j.lease_generation=e.lease_generation
 AND j.lease_owner_hash IS NOT NULL AND j.lease_until>clock_timestamp()
 AND j.expires_at>clock_timestamp() AND j.authority_expires_at>clock_timestamp()
 AND w.id=e.workflow_id AND w.cluster_id=e.cluster_id AND w.workspace_id=e.workspace_id
 AND w.state='executing' AND w.kind='configuration_v2' AND w.subject_type='configuration_jobs' AND w.subject_id=j.id
 AND w.requester_type='console' AND w.requester_user_id=j.actor_id AND w.execution_mode='approval' AND w.approval_required=true
 AND w.plan_revision=e.approved_version AND w.plan_hash=e.workflow_plan_hash
 AND p.cluster_id=s.cluster_id AND p.workspace_id=s.workspace_id AND p.plan_id=s.plan_id
 AND p.plan_revision=s.plan_revision AND p.plan_hash=s.plan_hash AND p.step_id=s.plan_step_id AND p.step_order=s.step_order
 AND p.object_workspace_id=s.object_workspace_id AND s.object_workspace_id=$14 AND p.reference_only=false
 AND cardinality(p.blocker_codes)=0 AND p.before_hmac=s.before_hmac AND p.before_hmac=$21 AND p.body_hmac=$22
 AND p.mutation_action=$16 AND p.entity_type=$17 AND p.parent_id::text IS NOT DISTINCT FROM $19::text
 AND p.credential_kind IS NOT DISTINCT FROM $20::text
 AND (CASE WHEN p.mutation_action='create' THEN p.allocated_native_id ELSE p.native_id END)::text IS NOT DISTINCT FROM $18::text
 AND o.state='running' AND o.remote_started=false AND o.remote_completed=false AND o.result_secret IS NULL
 AND o.actor_id=e.actor_id AND o.cluster_id=s.cluster_id AND o.workspace_id=s.object_workspace_id
 AND o.workflow_id=e.workflow_id AND o.configuration_job_id=s.job_id AND o.configuration_execution_id=s.execution_id
 AND o.configuration_step_id=s.id AND o.configuration_plan_revision=s.plan_revision AND o.configuration_plan_hash=s.plan_hash
 AND o.workflow_execution_id IS NULL AND o.workflow_step_id IS NULL AND o.workflow_plan_revision IS NULL AND o.workflow_plan_hash IS NULL
 AND o.transport_scope=j.transport_scope AND o.idempotency_key=$15 AND o.action=p.mutation_action AND o.entity_type=p.entity_type
 AND o.entity_id IS NOT DISTINCT FROM $18::text AND o.parent_id IS NOT DISTINCT FROM $19::text AND o.credential_kind IS NOT DISTINCT FROM $20::text`;

/** NULL SID lives only in the independent private scheduled namespace. SQL011
 * authoring SID remains a real UUID in $12; exact immutable SQL026 origins are
 * mandatory in this separate reciprocal-link statement. */
export const CONFIGURATION_APPROVED_SCHEDULED_OPERATION_LINK_SQL = CONFIGURATION_APPROVED_OPERATION_LINK_SQL + `
 AND EXISTS(SELECT 1 FROM workflow_configuration_execution_origins co JOIN workflow_execution_origins wo ON wo.id=co.wrapper_origin_id
   JOIN workflow_schedule_claims c ON c.id=co.claim_id AND c.schedule_id=wo.schedule_id
   JOIN workflow_schedule_progress sp ON sp.schedule_id=c.schedule_id
   JOIN LATERAL(SELECT * FROM workflow_schedule_leases WHERE claim_id=c.id ORDER BY lease_version DESC LIMIT 1) sl ON true
   WHERE co.id=$23 AND co.wrapper_origin_id=$24 AND co.claim_id=$25 AND co.configuration_execution_id=e.id
   AND co.cluster_id=e.cluster_id AND co.workspace_id=e.workspace_id AND co.configuration_job_id=j.id
   AND co.configuration_plan_id=e.plan_id AND co.configuration_plan_revision=e.plan_revision AND co.configuration_plan_hash=e.plan_hash
   AND co.workflow_id=e.workflow_id AND co.workflow_plan_revision=e.approved_version AND co.workflow_plan_hash=e.workflow_plan_hash
   AND co.workflow_step_id=$26 AND wo.execution_id=co.workflow_execution_id AND wo.executor_id=e.actor_id
   AND wo.claim_id=co.claim_id AND wo.workflow_id=co.workflow_id AND wo.workflow_plan_revision=co.workflow_plan_revision AND wo.workflow_plan_hash=co.workflow_plan_hash
   AND wo.cluster_id=co.cluster_id AND wo.workspace_id=co.workspace_id AND c.generation=1
   AND sp.claim_id=c.id AND sp.state IN('claimed','running') AND c.authority_expires_at>clock_timestamp()
   AND sl.lease_until>clock_timestamp() AND sl.worker_owner_hmac=c.worker_owner_hmac)`;

/** Used only behind ApprovedWorkflowExecutionService's private WeakMaps. SQL
 * and crypto checks are independent of Root's opaque job-claim verifier. */
export class ConfigurationApprovedVerifier {
  private delegate?:ConfigurationApprovedDelegate;
  private nativeBeforeReader?:Readonly<{read(originalStep:ApprovedStepProof,binding:Readonly<ConfigurationNativeBeforeBinding>):Promise<Readonly<ConfigurationNativeBeforeReadResult>>}>;
  installNativeBeforeReader(reader:{read(originalStep:ApprovedStepProof,binding:Readonly<ConfigurationNativeBeforeBinding>):Promise<Readonly<ConfigurationNativeBeforeReadResult>>}):void{
    if(this.nativeBeforeReader||!reader||typeof reader.read!=='function'||Object.keys(reader).some(k=>k!=='read'))throw denied('CONFIGURATION_BEFORE_READER_ALREADY_INSTALLED');
    this.nativeBeforeReader=Object.freeze({read:reader.read.bind(reader)});
  }
  private readonly crypto:SnapshotCryptoService;
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly authz:AuthorizationService,
    private readonly kong:KongService,private readonly redis:RedisService,private readonly context:KongExecutionContextService,
    private readonly approvalAuthority?:WorkflowApprovalAuthorityService){this.crypto=new SnapshotCryptoService(secrets);}
  install(delegate:ConfigurationApprovedDelegate):void{
    if(!delegate||typeof delegate.verifyExecution!=='function'||delegate.assertOrigin!==undefined&&typeof delegate.assertOrigin!=='function'||delegate.assertStoredOrigin!==undefined&&typeof delegate.assertStoredOrigin!=='function'||delegate.runLoad!==undefined&&typeof delegate.runLoad!=='function'||this.delegate&&this.delegate!==delegate)throw denied('CONFIGURATION_POLICY_ALREADY_INSTALLED');
    this.delegate=delegate;
  }
  async assertOrigin(plan:WorkflowPlanV1,actorId:string,action:'read'|'write'|'approve',tx:DbService=this.db):Promise<void>{
    assertConfigurationWorkflowPlan(plan);if(!uuid.test(actorId))throw denied('CONFIGURATION_ORIGIN_ACTOR_INVALID');
    const job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[plan.subject.id,plan.clusterId,plan.workspaceId]);
    if(!job)throw denied('CONFIGURATION_ORIGIN_JOB_UNAVAILABLE');
    let marker;try{marker=configurationOriginMarker(job);}catch{throw denied('CONFIGURATION_ORIGIN_MARKER_INVALID');}
    if(marker&&!this.delegate?.assertOrigin)throw denied('CONFIGURATION_ORIGIN_POLICY_UNAVAILABLE');
    if(this.delegate?.assertOrigin)await this.delegate.assertOrigin(plan,actorId,action,tx);
  }
  private same(a:unknown,b:unknown):boolean{return this.secrets.fingerprint(a??null)===this.secrets.fingerprint(b??null);}
  // SQL005 user/session epochs are bigint (node-pg decimal text); SQL011
  // configuration epochs are int4. Normalize only canonical actual DB values,
  // never arbitrary coercible strings or client-supplied authority claims.
  private credentialEpoch(value:unknown):number|null{
    if(typeof value!=='number'&&(typeof value!=='string'||!/^[1-9][0-9]{0,9}$/.test(value)))return null;
    const epoch=typeof value==='number'?value:Number(value);
    return Number.isSafeInteger(epoch)&&epoch>=1&&epoch<=2_147_483_647?epoch:null;
  }
  private targetAppend(step:ConfigurationPlanStep):boolean{return step.entityType==='targets'&&step.mutationAction==='update'
    &&uuid.test(step.nativeId??'')&&uuid.test(step.allocatedNativeId??'')&&step.nativeId!==step.allocatedNativeId;}
  private future(value:unknown):number{const time=new Date(value as any).getTime();if(!Number.isFinite(time)||time<=Date.now())throw denied('CONFIGURATION_APPROVED_EXPIRED');return time;}
  async load(id:string,tx:DbService=this.db,lock=false,proof?:ApprovedExecutionProof):Promise<ConfigurationApprovedLoaded>{
    const run=this.delegate?.runLoad;return run?run(()=>this.loadOnce(id,tx,lock,proof)):this.loadOnce(id,tx,lock,proof);
  }
  private async loadOnce(id:string,tx:DbService=this.db,lock=false,proof?:ApprovedExecutionProof):Promise<ConfigurationApprovedLoaded>{
    if(!this.delegate||!uuid.test(id))throw denied();
    if(lock)await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
    const claim=await this.delegate.verifyExecution(id,tx),frame=this.context.current(),scheduled=claim.scheduledOrigin;
    if(scheduled && (scheduled.origin!=='workflow-scheduled-configuration' || scheduled.sessionId!==null || claim.sessionId!==null || frame.sessionId!=null
      || !this.context.hasWorkflowScheduledNamespace() || this.context.requireWorkflowScheduledNamespaceHandle()!==scheduled.namespaceHandle
      || scheduled.configurationExecutionId!==id || scheduled.configurationJobId!==claim.jobId || scheduled.actorId!==claim.actorId
      || scheduled.wrapperExecutionId!==claim.workflowExecutionId || scheduled.configurationClaimHash!==claim.claimHash
      || scheduled.permissionVersion!==claim.permissionVersion || scheduled.leaseGeneration!==claim.leaseGeneration || scheduled.expiresAt<claim.expiresAt))
      throw denied('CONFIGURATION_APPROVED_SCHEDULE_ORIGIN_MISMATCH');
    const execution=await tx.one<any>(`SELECT * FROM configuration_executions WHERE id=$1${lock?' FOR UPDATE':''}`,[id]);
    if(!execution||execution.state!=='executing'||execution.execution_mode!=='approval'||!hex.test(claim.claimHash)||execution.claim_hash!==claim.claimHash
      ||execution.job_id!==claim.jobId||execution.actor_id!==claim.actorId||execution.lease_generation!==claim.leaseGeneration||execution.permission_version!==claim.permissionVersion
      ||!frame.actor||frame.actor.id!==claim.actorId||(scheduled?frame.sessionId!=null:frame.sessionId!==claim.sessionId||!uuid.test(claim.sessionId??''))
      ||frame.clusterId!==execution.cluster_id)throw denied('CONFIGURATION_APPROVED_CLAIM_MISMATCH');
    const keys=[execution.cluster_id,execution.workspace_id],job=await tx.one<any>(`SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3${lock?' FOR UPDATE':''}`,[...keys,execution.job_id]);
    const expires=Math.min(this.future(execution.expires_at),this.future(claim.expiresAt),job?this.future(job.expires_at):0,job?this.future(job.authority_expires_at):0);
    if(!job||job.state!=='running'||job.actor_id!==execution.actor_id||(scheduled?job.origin_type!=='http'||!uuid.test(job.origin_session_id??''):job.origin_session_id!==claim.sessionId)||job.execution_mode!=='approval'||job.approval_required!==true
      ||job.plan_id!==execution.plan_id||job.plan_revision!==execution.plan_revision||job.plan_hash!==execution.plan_hash||job.workflow_id!==execution.workflow_id
      ||job.lease_generation!==execution.lease_generation||job.permission_version!==claim.permissionVersion||!hex.test(job.lease_owner_hash??''))throw denied('CONFIGURATION_APPROVED_JOB_MISMATCH');
    this.future(job.lease_until);
    if(proof&&(scheduled?(proof.origin!=='scheduled-configuration'||proof.sessionId!==null||proof.scheduleClaimId!==scheduled.claimId||proof.workflowOriginId!==scheduled.wrapperOriginId||proof.configurationOriginId!==scheduled.configurationOriginId):proof.origin==='scheduled-configuration'))throw denied('CONFIGURATION_APPROVED_SCHEDULE_ORIGIN_MISMATCH');
    if(proof&&(proof.executionId!==id||proof.workflowId!==execution.workflow_id||proof.actorId!==claim.actorId||(scheduled?proof.sessionId!==null:proof.sessionId!==claim.sessionId)
      ||proof.clusterId!==keys[0]||proof.workspaceId!==keys[1]||proof.permissionVersion!==claim.permissionVersion||proof.expiresAt>Date.now()+CONFIGURATION_TIMEOUT_MS+1||proof.expiresAt>expires||proof.expiresAt<=Date.now()))throw denied();
    const jobEpoch=this.credentialEpoch(job.credential_epoch);
    if(scheduled){
      const user=await tx.one<any>(`SELECT credential_epoch FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND force_password_change=false${lock?' FOR SHARE':''}`,[claim.actorId]);
      if(!user||jobEpoch===null||this.credentialEpoch(user.credential_epoch)!==jobEpoch||scheduled.credentialEpoch!==jobEpoch
        ||scheduled.clusterId!==keys[0]||scheduled.workspaceId!==keys[1]||scheduled.configurationPlanId!==job.plan_id
        ||scheduled.configurationPlanRevision!==job.plan_revision||scheduled.configurationPlanHash!==job.plan_hash
        ||scheduled.workflowId!==execution.workflow_id||scheduled.workflowPlanRevision!==execution.approved_version||scheduled.workflowPlanHash!==execution.workflow_plan_hash)
        throw denied('CONFIGURATION_APPROVED_SCHEDULE_ORIGIN_MISMATCH');
      const origin=await tx.one<any>(`SELECT co.*,o.executor_id AS scheduled_executor,o.schedule_id,o.execution_id AS wrapper_execution_id,
        c.generation,c.authority_expires_at,c.worker_owner_hmac,p.state AS progress_state,p.claim_id AS progress_claim_id,
        l.lease_until,l.worker_owner_hmac AS lease_worker_owner_hmac
        FROM workflow_configuration_execution_origins co JOIN workflow_execution_origins o ON o.id=co.wrapper_origin_id
        AND ROW(o.cluster_id,o.workspace_id,o.claim_id,o.execution_id,o.workflow_id,o.workflow_plan_revision,o.workflow_plan_hash)
          =ROW(co.cluster_id,co.workspace_id,co.claim_id,co.workflow_execution_id,co.workflow_id,co.workflow_plan_revision,co.workflow_plan_hash)
        JOIN workflow_schedule_claims c ON c.id=co.claim_id AND c.schedule_id=o.schedule_id
        JOIN workflow_schedule_progress p ON p.schedule_id=o.schedule_id
        JOIN LATERAL(SELECT * FROM workflow_schedule_leases WHERE claim_id=c.id ORDER BY lease_version DESC LIMIT 1) l ON true
        WHERE co.id=$1 AND co.configuration_execution_id=$2 AND co.wrapper_origin_id=$3 AND co.claim_id=$4`,
        [scheduled.configurationOriginId,id,scheduled.wrapperOriginId,scheduled.claimId]);
      if(!origin||origin.id!==scheduled.configurationOriginId||origin.wrapper_origin_id!==scheduled.wrapperOriginId||origin.claim_id!==scheduled.claimId
        ||origin.configuration_execution_id!==id||origin.wrapper_execution_id!==claim.workflowExecutionId||origin.configuration_job_id!==job.id||origin.configuration_plan_id!==job.plan_id||origin.configuration_plan_revision!==job.plan_revision
        ||origin.configuration_plan_hash!==job.plan_hash||origin.cluster_id!==keys[0]||origin.workspace_id!==keys[1]||origin.workflow_id!==execution.workflow_id
        ||origin.workflow_plan_revision!==execution.approved_version||origin.workflow_plan_hash!==execution.workflow_plan_hash||origin.workflow_execution_id!==claim.workflowExecutionId
        ||origin.scheduled_executor!==claim.actorId||origin.generation!==1||origin.progress_claim_id!==scheduled.claimId||!['claimed','running'].includes(origin.progress_state)
        ||origin.worker_owner_hmac!==origin.lease_worker_owner_hmac||this.future(origin.authority_expires_at)<claim.expiresAt)
        throw denied('CONFIGURATION_APPROVED_SCHEDULE_ORIGIN_MISMATCH');
      this.future(origin.lease_until);
    }else{
      const session=await tx.one<any>(`SELECT s.id,s.credential_epoch,u.credential_epoch AS user_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id
        WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.credential_epoch=u.credential_epoch
        AND u.status='active' AND u.deleted_at IS NULL AND u.force_password_change=false${lock?' FOR SHARE OF s,u':''}`,[claim.sessionId,claim.actorId]);
      if(!session||jobEpoch===null||this.credentialEpoch(session.credential_epoch)!==jobEpoch||this.credentialEpoch(session.user_epoch)!==jobEpoch)throw denied('CONFIGURATION_APPROVED_SESSION_INVALID');
    }
    const current=await this.authz.snapshot(frame.actor);if(current.version!==claim.permissionVersion||current.user.forcePasswordChange)throw denied('CONFIGURATION_APPROVED_GRANTS_CHANGED');
    const cluster=await tx.one<any>('SELECT * FROM clusters WHERE id=$1 AND deleted_at IS NULL',[keys[0]]),ws=await tx.one<any>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2',keys);
    if(!cluster||cluster.status==='disabled'||cluster.execution_mode!=='approval'||!isSupportedKong(cluster.version??'')||cluster.revision!==job.cluster_revision
      ||transportScopeFor(cluster.admin_url,cluster.transport_scope)!==job.transport_scope||!ws||ws.status!=='active'||ws.revision!==job.workspace_revision)throw denied('CONFIGURATION_APPROVED_SCOPE_CHANGED');
    const version=await tx.one<any>('SELECT * FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4',[...keys,execution.plan_id,execution.plan_revision]);
    const p=await tx.one<any>('SELECT * FROM configuration_plans WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,execution.plan_id]);
    const material=version&&await tx.one<any>('SELECT * FROM configuration_materials WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,version.material_id]);
    if(!version||version.plan_hash!==execution.plan_hash||!hex.test(version.plan_hash)||!p||p.current_revision!==execution.plan_revision
      ||!['approved','executing'].includes(p.state)||p.transport_scope!==job.transport_scope||!material||material.job_id!==version.source_job_id
      ||material.artifact_id!==version.artifact_id||material.artifact_kind!=='plan'||material.state!=='available')throw denied('CONFIGURATION_APPROVED_PLAN_MISMATCH');
    const identity={clusterId:keys[0],workspaceId:keys[1],jobId:version.source_job_id,materialId:material.id,artifactId:version.artifact_id,artifactKind:'plan' as const};
    const plan=await this.crypto.withKey(identity,material.wrapped_key_secret,async key=>this.crypto.decrypt<ConfigPlan>(key,identity,{section:'manifest',key:'plan'},version.manifest_ciphertext));
    let origin;try{origin=configurationOriginMarker(job);}catch{throw denied('CONFIGURATION_ORIGIN_MARKER_INVALID');}
    const originRef=(plan as ConfigPlan&{originRef?:{version:number;kind:string;originId:string;materialHmac:string}}).originRef;
    if(origin?!originRef||Object.keys(originRef).length!==4||originRef.version!==1||originRef.kind!==origin.kind||originRef.originId!==origin.id||originRef.materialHmac!==origin.hmac:originRef!==undefined)throw denied('CONFIGURATION_ORIGIN_PLAN_MISMATCH');
    if(this.secrets.fingerprint(plan)!==execution.plan_hash||this.secrets.fingerprint(plan)!==version.input_hmac||this.secrets.fingerprint(plan.steps)!==version.steps_hmac
      ||plan.scope.clusterId!==keys[0]||plan.scope.workspaceId!==keys[1]||plan.scope.transportScope!==job.transport_scope||plan.permissionVersion!==claim.permissionVersion
      ||plan.clusterRevision!==cluster.revision||plan.workspaceRevision!==ws.revision||plan.kongVersion!==cluster.version||!plan.recoveryComplete||!Array.isArray(plan.steps)
      ||plan.steps.length>10000||version.step_count!==plan.steps.length||plan.schemaHmac!==version.schema_hmac||plan.sourceManifestHmac!==version.source_manifest_hmac
      ||plan.baselineManifestHmac!==version.baseline_manifest_hmac)throw denied('CONFIGURATION_APPROVED_PLAN_MISMATCH');
    this.future(plan.expiresAt);this.future(version.expires_at);
    if(frame.workspaceId!==job.workspace_id&&!plan.steps.some(s=>s.objectWorkspaceId===frame.workspaceId))throw denied('CONFIGURATION_APPROVED_SCOPE_CHANGED');
    const rows=await tx.query<any>('SELECT * FROM configuration_job_steps WHERE cluster_id=$1 AND workspace_id=$2 AND execution_id=$3 ORDER BY step_order',[...keys,id]);
    const objects=await tx.query<any>('SELECT * FROM configuration_plan_objects WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 ORDER BY step_order',[...keys,execution.plan_id,execution.plan_revision]);
    if(rows.length!==plan.steps.length||objects.length!==plan.steps.length)throw denied('CONFIGURATION_APPROVED_DAG_INCOMPLETE');
    const seen=new Set<string>();let packets=0;
    for(const [i,step]of plan.steps.entries()){
      const row=rows[i],object=objects[i];packets+=step.nativeRequests?.length??501;
      if(!uuid.test(step.stepId)||seen.has(step.stepId)||step.stepOrder!==i+1||!Array.isArray(step.dependencies)||step.dependencies.some((dep:string)=>!seen.has(dep))
        ||new Set(step.dependencies).size!==step.dependencies.length||!Array.isArray(step.nativeRequests)||step.nativeRequests.length>32||step.blockerCodes.length||step.referenceOnly
        ||step.bodyHmac!==this.secrets.fingerprint(step.body??null)||step.beforeHmac!==this.secrets.fingerprint(step.before??null)
        ||row.job_id!==job.id||row.execution_id!==id||row.plan_id!==execution.plan_id||row.plan_revision!==execution.plan_revision||row.plan_hash!==execution.plan_hash
        ||!uuid.test(step.objectWorkspaceId)||row.object_workspace_id!==step.objectWorkspaceId||row.plan_step_id!==step.stepId||row.step_order!==step.stepOrder||row.approval_required!==true||row.before_hmac!==step.beforeHmac
        ||object.object_workspace_id!==step.objectWorkspaceId||object.step_id!==step.stepId||object.plan_hash!==execution.plan_hash||object.object_key!==step.objectKey||object.entity_type!==step.entityType||object.step_order!==step.stepOrder
        ||(object.native_id??null)!==(step.nativeId??null)||(object.allocated_native_id??null)!==(step.allocatedNativeId??null)||(object.parent_id??null)!==(step.parentId??null)
        ||(object.parent_type??null)!==(step.parentType??null)||(object.credential_kind??null)!==(step.credentialKind??null)||object.permission_action!==step.permissionAction
        ||object.mutation_action!==step.mutationAction||object.before_hmac!==step.beforeHmac||object.body_hmac!==step.bodyHmac||!this.same(object.dependencies,step.dependencies)
        ||!this.same(object.native_requests,step.nativeRequests.map((r:ConfigurationPlanStep['nativeRequests'][number])=>({method:r.method,path_hmac:this.secrets.fingerprint(r.canonicalPath),body_hmac:r.bodyHmac,before_hmac:r.beforeHmac})))||object.reference_only!==false||object.blocker_codes?.length)throw denied('CONFIGURATION_APPROVED_STEP_INVALID');
      for(const request of step.nativeRequests){assertKongPath(request.method,request.canonicalPath);if(!['POST','PATCH','DELETE'].includes(request.method)
        ||request.bodyHmac!==this.secrets.fingerprint(request.body??null)||!hex.test(request.beforeHmac))throw denied();
        if(request.method==='POST'&&(request.body as any)?.id!==step.allocatedNativeId)throw denied('CONFIGURATION_APPROVED_CREATED_ID_MISMATCH');
      }
      if(this.targetAppend(step)&&(step.nativeRequests.length!==1||step.nativeRequests[0].method!=='POST'
        ||step.nativeRequests[0].canonicalPath!==`/upstreams/${step.parentId}/targets`||step.beforeHmac!==step.nativeRequests[0].beforeHmac))throw denied('CONFIGURATION_APPROVED_TARGET_APPEND_INVALID');
      seen.add(step.stepId);
    }
    if(packets>500||packets!==version.native_packet_count)throw denied('CONFIGURATION_APPROVED_PACKET_BUDGET');
    await this.crypto.withKey(identity,material.wrapped_key_secret,async key=>{for(const [i,step]of plan.steps.entries()){
      const sealed=this.crypto.decrypt(key,identity,{section:'plan-step',key:step.stepId,entityType:step.entityType,nativeId:step.nativeId??step.allocatedNativeId??null,parentId:step.parentId??null,credentialKind:step.credentialKind??null},objects[i].payload_ciphertext);
      if(!this.same(sealed,step))throw denied('CONFIGURATION_APPROVED_STEP_CIPHERTEXT_INVALID');
    }});
    const baseline=await tx.one<any>('SELECT * FROM config_snapshot_versions WHERE cluster_id=$1 AND workspace_id=$2 AND snapshot_id=$3 AND version=$4',[...keys,execution.before_snapshot_id,execution.before_snapshot_version]);
    if(!baseline||baseline.completeness!=='complete'||baseline.consistency!=='console_fenced_best_effort'||baseline.manifest_hmac!==plan.baselineManifestHmac)throw denied('CONFIGURATION_APPROVED_BASELINE_INVALID');
    const workflow=await tx.one<any>('SELECT * FROM workflows WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[...keys,execution.workflow_id]);
    const wrapperVersion=await tx.one<any>('SELECT * FROM workflow_versions WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4',[...keys,execution.workflow_id,execution.approved_version]);
    if(!workflow||!wrapperVersion||workflow.state!=='executing'||workflow.kind!=='configuration_v2'||workflow.subject_type!=='configuration_jobs'
      ||workflow.subject_id!==job.id||workflow.requester_user_id!==job.actor_id||workflow.requester_type!=='console'||workflow.approval_required!==true||workflow.execution_mode!=='approval'
      ||workflow.plan_revision!==execution.approved_version||workflow.plan_hash!==execution.workflow_plan_hash||wrapperVersion.plan_hash!==execution.workflow_plan_hash
      ||wrapperVersion.execution_mode!=='approval'||wrapperVersion.approval_required!==true||wrapperVersion.step_count!==1||wrapperVersion.native_request_count!==0
      ||!uuid.test(workflow.approved_by??''))throw denied('CONFIGURATION_APPROVED_WRAPPER_INVALID');
    const wrapper=this.secrets.decrypt<WorkflowPlanV1>(wrapperVersion.payload_secret,planAad(keys[0],keys[1],workflow.id,execution.approved_version));
    const wrapperStep=assertConfigurationWorkflowPlan(wrapper),payload=wrapperStep.metadata as ConfigurationWorkflowPayload;
    if(this.secrets.fingerprint(wrapper)!==execution.workflow_plan_hash||this.secrets.fingerprint(wrapper.steps)!==wrapperVersion.steps_hash||wrapper.clusterId!==keys[0]||wrapper.workspaceId!==keys[1]
      ||wrapper.workflowId!==workflow.id||wrapper.planRevision!==execution.approved_version||wrapper.approvalRequired!==true||wrapper.executionMode!=='approval'
      ||wrapper.requester.id!==job.actor_id||wrapper.definition.id!==workflow.definition_id||wrapper.definition.version!==workflow.definition_version
      ||wrapperVersion.policy_version!==wrapper.definition.version||wrapper.scope.transportScope!==job.transport_scope||wrapper.scope.clusterRevision!==cluster.revision
      ||wrapper.scope.workspaceRevision!==ws.revision||wrapperStep.metadataRevision!==execution.plan_revision
      ||wrapperStep.metadataBeforeHmac!==this.secrets.fingerprint(wrapperStep.before??null)||wrapperStep.metadataPayloadHmac!==this.secrets.fingerprint(payload)
      ||payload.jobId!==job.id||payload.planId!==execution.plan_id||payload.planRevision!==execution.plan_revision||payload.planHash!==execution.plan_hash)throw denied('CONFIGURATION_APPROVED_WRAPPER_INVALID');
    this.future(wrapper.expiresAt);this.future(wrapperVersion.expires_at);this.future(workflow.expires_at);
    await this.assertOrigin(wrapper,current.user.id,'write',tx);
    const normalized=await tx.query<any>('SELECT * FROM workflow_steps WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 ORDER BY step_order',[...keys,workflow.id,execution.approved_version]);
    const wrapperRow=normalized[0];
    if(normalized.length!==1||!wrapperRow||wrapperRow.id!==wrapperStep.id||wrapperRow.cluster_id!==keys[0]||wrapperRow.workspace_id!==keys[1]
      ||wrapperRow.workflow_id!==workflow.id||wrapperRow.plan_revision!==execution.approved_version||wrapperRow.plan_hash!==execution.workflow_plan_hash
      ||wrapperRow.state!=='running'||wrapperRow.execution_mode!=='approval'||wrapperRow.approval_required!==true||wrapperRow.step_key!==wrapperStep.key||wrapperRow.step_order!==1
      ||wrapperRow.kind!=='metadata'||wrapperRow.handler!=='configuration_v2'||wrapperRow.entity_type!=='configuration_jobs'||wrapperRow.entity_id!==job.id
      ||wrapperRow.permission_action!=='write'||wrapperRow.operation_id!=null||wrapperRow.parent_id!=null||wrapperRow.credential_kind!=null
      ||wrapperRow.mutation_action!=null||wrapperRow.mutation_payload_hmac!=null||wrapperRow.mutation_idempotency_key!=null||wrapperRow.before_fingerprint!=null
      ||!this.same(wrapperRow.native_requests,[])||!this.same(wrapperRow.dependencies,[])||wrapperRow.metadata_revision!==wrapperStep.metadataRevision
      ||wrapperRow.metadata_before_hmac!==wrapperStep.metadataBeforeHmac||wrapperRow.metadata_payload_hmac!==wrapperStep.metadataPayloadHmac)throw denied('CONFIGURATION_APPROVED_NORMALIZED_WRAPPER_INVALID');
    if(!uuid.test(claim.workflowExecutionId??''))throw denied('CONFIGURATION_APPROVED_WRAPPER_EXECUTION_INVALID');
    const wrapperExecution=await tx.one<any>('SELECT * FROM workflow_executions WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4',[claim.workflowExecutionId,...keys,workflow.id]);
    if(!wrapperExecution||wrapperExecution.id!==claim.workflowExecutionId||wrapperExecution.cluster_id!==keys[0]||wrapperExecution.workspace_id!==keys[1]
      ||wrapperExecution.workflow_id!==workflow.id||wrapperExecution.plan_revision!==execution.approved_version||wrapperExecution.plan_hash!==execution.workflow_plan_hash
      ||wrapperExecution.state!=='executing'||wrapperExecution.execution_mode!=='approval'||wrapperExecution.approval_required!==true
      ||wrapperExecution.execution_actor_id!==job.actor_id||wrapperExecution.approved_by!==workflow.approved_by||wrapperExecution.snapshot_state!=='ready'
      ||!hex.test(wrapperExecution.snapshot_hash??'')||!uuid.test(wrapperExecution.snapshot_id??'')||!wrapperExecution.snapshot_secret)throw denied('CONFIGURATION_APPROVED_WRAPPER_EXECUTION_INVALID');
    this.future(wrapperExecution.expires_at);
    const wrapperSnapshot=this.secrets.decrypt<WorkflowSnapshotV1>(wrapperExecution.snapshot_secret,snapshotAad(keys[0],keys[1],workflow.id,wrapperExecution.id));
    if(!wrapperSnapshot||wrapperSnapshot.version!==1||wrapperSnapshot.workflowId!==workflow.id||wrapperSnapshot.executionId!==wrapperExecution.id
      ||wrapperSnapshot.clusterId!==keys[0]||wrapperSnapshot.workspaceId!==keys[1]||wrapperSnapshot.planRevision!==execution.approved_version
      ||wrapperSnapshot.planHash!==execution.workflow_plan_hash||this.secrets.fingerprint(wrapperSnapshot)!==wrapperExecution.snapshot_hash
      ||!Array.isArray(wrapperSnapshot.objects)||wrapperSnapshot.objects.length)throw denied('CONFIGURATION_APPROVED_WRAPPER_SNAPSHOT_INVALID');
    const approvalFormat=wrapperVersion.approval_format??1;
    if(scheduled&&approvalFormat!==2||![1,2].includes(approvalFormat)||(workflow.approval_format??1)!==approvalFormat||(wrapperExecution.approval_format??1)!==approvalFormat)throw denied('CONFIGURATION_APPROVAL_INCOMPLETE');
    if(approvalFormat===2){
      if(!this.approvalAuthority)throw denied('WORKFLOW_APPROVAL_POLICY_UNAVAILABLE');
      const preparation=scheduled&&typeof this.context.scheduledConfigurationPreparationPhase==='function'?this.context.scheduledConfigurationPreparationPhase():null;
      const namespace=preparation?await this.context.verifyWorkflowScheduledNamespace('packet'):null;
      if(preparation&&(!namespace||namespace!==preparation.namespace||preparation.namespaceHandle!==scheduled!.namespaceHandle
        ||namespace.workflow.id!==wrapper.workflowId||namespace.workflow.planRevision!==wrapper.planRevision||namespace.workflow.planHash!==execution.workflow_plan_hash))throw denied('CONFIGURATION_APPROVED_SCHEDULE_ORIGIN_MISMATCH');
      const set=preparation?namespace!.approvalSet:await this.approvalAuthority.verifyApprovalSet(wrapper,{executionId:wrapperExecution.id,checkpoint:'packet'},tx);
      if(preparation&&(wrapperExecution.approval_format!==2||wrapperExecution.approval_set_id!==set.setId||wrapperExecution.approval_set_hmac!==set.setHmac))throw denied('CONFIGURATION_APPROVAL_SET_CHANGED');
      if(set.format!==2||!set.setId||!set.setHmac||proof&&(proof.approvalFormat!==2||proof.approvalSetId!==set.setId||proof.approvalSetHmac!==set.setHmac))throw denied('CONFIGURATION_APPROVAL_SET_CHANGED');
    }else{
    if(proof&&(proof.approvalFormat!==undefined&&proof.approvalFormat!==1||proof.approvalSetId!=null||proof.approvalSetHmac!=null))throw denied('CONFIGURATION_APPROVAL_SET_CHANGED');
    const approvals=await tx.query<any>(`SELECT a.*,u.status,u.deleted_at,u.force_password_change,u.super_admin FROM workflow_approvals a JOIN users u ON u.id=a.approver_id
      WHERE a.cluster_id=$1 AND a.workspace_id=$2 AND a.workflow_id=$3 AND a.plan_revision=$4 AND a.plan_hash=$5 AND a.decision='approve'`,[...keys,workflow.id,execution.approved_version,execution.workflow_plan_hash]);
    const stages=await tx.query<any>('SELECT * FROM workflow_stages WHERE cluster_id=$1 AND workspace_id=$2 AND workflow_id=$3 AND plan_revision=$4 AND plan_hash=$5',[...keys,workflow.id,execution.approved_version,execution.workflow_plan_hash]);
    const definition=await tx.one<any>('SELECT * FROM workflow_definition_versions WHERE cluster_id=$1 AND workspace_id=$2 AND definition_id=$3 AND version=$4',[...keys,wrapper.definition.id,wrapper.definition.version]);
    if(stages.length!==1||stages[0].state!=='approved'||stages[0].level!==1||stages[0].required_approvals!==1||approvals.length!==1||approvals[0].approver_id!==workflow.approved_by
      ||approvals[0].level!==1||!definition||definition.mode!=='single'||definition.allow_self_approval!==false||definition.policy_hash!==wrapper.definition.policyHash)throw denied('CONFIGURATION_APPROVAL_INCOMPLETE');
    for(const approval of approvals){if(approval.approver_id===job.actor_id||approval.status!=='active'||approval.deleted_at||approval.force_password_change)throw denied('CONFIGURATION_APPROVER_REVOKED');
      // The active frame belongs to the executor. Inspect the current approver's
      // database authority without adopting their identity or bypassing the
      // AuthorizationService actor/session anti-IDOR check. Restricted grants
      // cannot be combined into whole-workspace approval authority. The IAM
      // epoch lock and final executor permission-version check remain in force.
      const grants=(await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1',[approval.approver_id])).filter(validGrant);
      if(approval.super_admin!==true&&!grants.some(grant=>grant.module==='workflows'&&grant.action==='approve'
        &&(grant.cluster_id===null||grant.cluster_id===keys[0])&&(grant.workspace_id===null||grant.workspace_id===keys[1])
        &&(grant.scope_type==='global'||grant.scope_type==='workspace'&&grant.cluster_id===keys[0]&&grant.workspace_id===keys[1]
          &&grant.scope_values.length===1&&grant.scope_values[0]===keys[1])))throw denied('CONFIGURATION_APPROVER_REVOKED');
      await this.assertOrigin(wrapper,approval.approver_id,'approve',tx);}
    }
    await this.authz.assertWholeWorkspace(current.user,keys[0],keys[1],'snapshots','write');
    if(await this.authz.permissionVersion(current.user)!==claim.permissionVersion)throw denied('CONFIGURATION_APPROVED_GRANTS_CHANGED');
    await this.redis.assertLeaseOwnership();this.context.current();
    return{execution,job,version,plan,rows,workflow,wrapper,...(scheduled?{scheduledOrigin:scheduled}:{}),claimExpiresAt:Math.min(expires,this.future(plan.expiresAt),this.future(wrapper.expiresAt))};
  }
  async step(proof:ApprovedExecutionProof,stepId:string,tx=this.db,lock=false):Promise<{loaded:ConfigurationApprovedLoaded;step:ConfigurationPlanStep;row:any}>{
    const loaded=await this.load(proof.executionId,tx,lock,proof),row=loaded.rows.find(r=>r.id===stepId),step=loaded.plan.steps.find(s=>s.stepId===row?.plan_step_id);
    if(!row||!step||row.state!=='running')throw denied('CONFIGURATION_APPROVED_STEP_NOT_RUNNING');
    const frame=this.context.current();if(frame.workspaceId!==loaded.job.workspace_id&&frame.workspaceId!==step.objectWorkspaceId)throw denied('CONFIGURATION_APPROVED_SCOPE_CHANGED');
    const workspace=await tx.one<any>('SELECT * FROM workspaces WHERE cluster_id=$1 AND id=$2',[loaded.job.cluster_id,step.objectWorkspaceId]);
    if(!workspace||workspace.status!=='active')throw denied('CONFIGURATION_APPROVED_SCOPE_CHANGED');
    await this.authz.assertWholeWorkspace(frame.actor!,loaded.job.cluster_id,step.objectWorkspaceId,'snapshots','write');
    for(const dep of step.dependencies){const prior=loaded.rows.find(r=>r.plan_step_id===dep);if(!prior||prior.state!=='succeeded'||!hex.test(prior.after_hmac??'')||!prior.receipt_ciphertext)throw denied('CONFIGURATION_DEPENDENCY_UNACKNOWLEDGED');
      if(prior.operation_id){const op=await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[prior.operation_id]);if(!op||op.state!=='succeeded'||op.remote_completed!==true||op.configuration_execution_id!==loaded.execution.id||op.configuration_step_id!==prior.id||op.configuration_plan_hash!==loaded.execution.plan_hash)throw denied('CONFIGURATION_DEPENDENCY_UNACKNOWLEDGED');}}
    return{loaded,step,row};
  }
  logical(loaded:ConfigurationApprovedLoaded,step:ConfigurationPlanStep,row:any,input:Readonly<MutationContext>):void{
    if(input.actor.id!==loaded.execution.actor_id||input.clusterId!==loaded.job.cluster_id||input.workspaceId!==step.objectWorkspaceId||input.entityType!==step.entityType
      ||input.action!==step.mutationAction||(input.entityId??null)!==(step.mutationAction==='create'?step.allocatedNativeId??null:step.nativeId??null)||(input.parentId??null)!==(step.parentId??null)
      ||(input.credentialKind??null)!==(step.credentialKind??null)||input.idempotencyKey!==configurationMutationKey(loaded.job.id,row.id)
      ||this.secrets.fingerprint(input.before??null)!==step.beforeHmac||this.secrets.fingerprint(input.payload??null)!==step.bodyHmac)throw denied('CONFIGURATION_APPROVED_MUTATION_MISMATCH');
  }
  async bind(proof:ApprovedExecutionProof,stepId:string,input:Readonly<MutationContext>,binding:ApprovedMutationBindingV2,operationId:string,tx:DbService):Promise<void>{
    const frame=this.context.current(),beforeHmac=this.secrets.fingerprint(input.before??null),bodyHmac=this.secrets.fingerprint(input.payload??null);
    if(!uuid.test(stepId)||!uuid.test(operationId)||!uuid.test(binding.configurationJobId)||!Number.isSafeInteger(binding.configurationPlanRevision)||binding.configurationPlanRevision<1
      ||!hex.test(binding.configurationPlanHash)||binding.configurationExecutionId!==proof.executionId||binding.configurationStepId!==stepId||binding.workflowId!==proof.workflowId
      ||binding.beforeHmac!==beforeHmac||input.actor.id!==proof.actorId||input.clusterId!==proof.clusterId||!uuid.test(input.workspaceId??'')
      ||input.idempotencyKey!==configurationMutationKey(binding.configurationJobId,stepId)||frame.actor?.id!==proof.actorId||(proof.origin==='scheduled-configuration'?frame.sessionId!=null:frame.sessionId!==proof.sessionId)
      ||frame.clusterId!==proof.clusterId||frame.workspaceId!==proof.workspaceId&&frame.workspaceId!==input.workspaceId||proof.expiresAt<=Date.now())throw denied();
    await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
    const prior=await tx.one<any>(`SELECT revision FROM configuration_job_steps WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3
      AND job_id=$4 AND execution_id=$5 AND plan_revision=$6 AND plan_hash=$7 FOR UPDATE`,
      [stepId,proof.clusterId,proof.workspaceId,binding.configurationJobId,proof.executionId,binding.configurationPlanRevision,binding.configurationPlanHash]);
    if(!prior||!Number.isSafeInteger(prior.revision)||prior.revision<1)throw denied('CONFIGURATION_APPROVED_STEP_NOT_RUNNING');
    let authoringSessionId=proof.sessionId,extra:unknown[]=[],sql=CONFIGURATION_APPROVED_OPERATION_LINK_SQL;
    if(proof.origin==='scheduled-configuration'){
      const tuple=await tx.one<any>(`SELECT j.origin_session_id,s.id AS wrapper_step_id FROM configuration_jobs j
        JOIN configuration_executions e ON e.job_id=j.id AND e.cluster_id=j.cluster_id AND e.workspace_id=j.workspace_id
        JOIN workflow_steps s ON s.workflow_id=e.workflow_id AND s.plan_revision=e.approved_version AND s.plan_hash=e.workflow_plan_hash
        WHERE j.id=$1 AND e.id=$2 AND e.workflow_id=$3 AND s.cluster_id=e.cluster_id AND s.workspace_id=e.workspace_id
        AND s.kind='metadata' AND s.handler='configuration_v2' AND s.entity_id=j.id AND s.state='running'`,[binding.configurationJobId,proof.executionId,proof.workflowId]);
      if(!tuple||!uuid.test(tuple.origin_session_id??'')||!uuid.test(tuple.wrapper_step_id??'')||!uuid.test(proof.configurationOriginId??'')||!uuid.test(proof.workflowOriginId??'')||!uuid.test(proof.scheduleClaimId??'')
        ||proof.sessionId!==null||!this.context.hasWorkflowScheduledNamespace())throw denied('CONFIGURATION_APPROVED_SCHEDULE_ORIGIN_MISMATCH');
      authoringSessionId=tuple.origin_session_id;extra=[proof.configurationOriginId,proof.workflowOriginId,proof.scheduleClaimId,tuple.wrapper_step_id];sql=CONFIGURATION_APPROVED_SCHEDULED_OPERATION_LINK_SQL;
    }
    if(await tx.exec(sql,[stepId,operationId,prior.revision,proof.clusterId,proof.workspaceId,binding.configurationJobId,
      proof.executionId,binding.configurationPlanRevision,binding.configurationPlanHash,proof.workflowId,proof.actorId,authoringSessionId,proof.permissionVersion,
      input.workspaceId,input.idempotencyKey,input.action,input.entityType,input.entityId??null,input.parentId??null,input.credentialKind??null,beforeHmac,bodyHmac,...extra])!==1)
      throw new ConflictException({code:'CONFIGURATION_OPERATION_LINK_CONFLICT'});
    const{loaded,step,row}=await this.step(proof,stepId,tx,true);this.logical(loaded,step,row,input);
    if(row.operation_id!==operationId||binding.configurationExecutionId!==loaded.execution.id||binding.configurationJobId!==loaded.job.id||binding.configurationStepId!==row.id
      ||binding.configurationPlanRevision!==loaded.execution.plan_revision||binding.configurationPlanHash!==loaded.execution.plan_hash||binding.workflowId!==loaded.workflow.id||binding.beforeHmac!==step.beforeHmac)throw denied();
    const op=await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[operationId]);this.operation(loaded,step,row,{...op,configuration_step_id:op?.configuration_step_id},binding,operationId);
  }
  private operation(loaded:ConfigurationApprovedLoaded,step:ConfigurationPlanStep,row:any,op:any,binding?:ApprovedMutationBindingV2,id=row.operation_id):void{
    const appendCompleted=this.targetAppend(step)&&op?.remote_completed===true&&op?.entity_id===step.allocatedNativeId;
    if(!op||op.id!==id||op.state!=='running'||op.actor_id!==loaded.execution.actor_id||op.cluster_id!==loaded.job.cluster_id||op.workspace_id!==step.objectWorkspaceId
      ||op.workflow_id!==loaded.workflow.id||op.configuration_job_id!==loaded.job.id||op.configuration_execution_id!==loaded.execution.id||op.configuration_step_id!==row.id
      ||op.configuration_plan_revision!==loaded.execution.plan_revision||op.configuration_plan_hash!==loaded.execution.plan_hash||op.workflow_execution_id!=null||op.workflow_step_id!=null
      ||op.workflow_plan_revision!=null||op.workflow_plan_hash!=null||op.transport_scope!==loaded.job.transport_scope||op.action!==step.mutationAction||op.entity_type!==step.entityType
      ||(op.parent_id??null)!==(step.parentId??null)||(op.credential_kind??null)!==(step.credentialKind??null)
      ||(op.entity_id??null)!==(step.mutationAction==='create'?step.allocatedNativeId??null:step.nativeId??null)&&!appendCompleted
      ||op.idempotency_key!==configurationMutationKey(loaded.job.id,row.id)||this.secrets.fingerprint(this.secrets.decrypt(op.before_secret,`mutation:${op.id}:before`))!==step.beforeHmac
      ||this.secrets.fingerprint(this.secrets.decrypt(op.payload_secret,`mutation:${op.id}:payload`))!==step.bodyHmac)throw denied('CONFIGURATION_APPROVED_OPERATION_INVALID');
  }
  async nativeBeforeBinding(proof:ApprovedExecutionProof,stepId:string,input:Readonly<ConfigurationNativeBeforeInput>):Promise<Readonly<ConfigurationNativeBeforeBinding>>{
    const{loaded,step,row}=await this.step(proof,stepId),request=step.nativeRequests.find(r=>r.method===input.method&&r.canonicalPath===input.canonicalPath);
    if(step.nativeRequests.length!==1||!request||input.clusterId!==loaded.job.cluster_id||input.workspaceId!==step.objectWorkspaceId
      ||input.transportScope!==loaded.job.transport_scope||input.operationId!==row.operation_id||input.frame!==this.context.current()
      ||input.frame.actor?.id!==proof.actorId||proof.origin!=='scheduled-configuration'||proof.sessionId!==null||input.frame.sessionId!=null
      ||input.mutationAction!==step.mutationAction||(input.parentId??null)!==(step.parentId??null)||(input.credentialKind??null)!==(step.credentialKind??null)
      ||Object.keys(input.query).length||request.bodyHmac!==this.secrets.fingerprint(input.body??null))throw denied('CONFIGURATION_APPROVED_NATIVE_MISMATCH');
    const op=await this.db.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[row.operation_id]);this.operation(loaded,step,row,op);
    if(op.remote_started!==true||op.remote_completed===true)throw denied('CONFIGURATION_APPROVED_OPERATION_INVALID');
    return Object.freeze({loaded,step,row,request,input});
  }
  /** Fresh SQL only inside the exact original read callback. Full material
   * and every current principal/Native scope are independently checked by Root,
   * then the caller retains its original post-read complete step verification. */
  async assertNativeBeforeBinding(binding:Readonly<ConfigurationNativeBeforeBinding>,tx:DbService):Promise<void>{
    const{loaded,step,input}=binding,job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[loaded.job.id]);
    const execution=await tx.one<any>('SELECT * FROM configuration_executions WHERE id=$1',[loaded.execution.id]);
    const row=await tx.one<any>('SELECT * FROM configuration_job_steps WHERE id=$1',[binding.row.id]);
    if(!job||job.state!=='running'||job.actor_id!==loaded.execution.actor_id||job.cluster_id!==input.clusterId||job.workspace_id!==loaded.job.workspace_id
      ||job.plan_id!==loaded.job.plan_id||job.plan_revision!==loaded.job.plan_revision||job.plan_hash!==loaded.job.plan_hash
      ||job.workflow_id!==loaded.workflow.id||job.execution_mode!=='approval'||job.lease_generation!==loaded.execution.lease_generation
      ||!execution||execution.state!=='executing'||execution.job_id!==job.id||execution.cluster_id!==job.cluster_id||execution.workspace_id!==job.workspace_id
      ||execution.plan_id!==job.plan_id||execution.plan_revision!==job.plan_revision||execution.plan_hash!==job.plan_hash
      ||execution.actor_id!==job.actor_id||execution.workflow_id!==job.workflow_id||execution.claim_hash!==loaded.execution.claim_hash
      ||execution.permission_version!==loaded.execution.permission_version||execution.lease_generation!==job.lease_generation
      ||!row||row.state!=='running'||row.job_id!==job.id||row.execution_id!==execution.id||row.cluster_id!==job.cluster_id||row.workspace_id!==job.workspace_id
      ||row.plan_id!==job.plan_id||row.plan_revision!==job.plan_revision||row.plan_hash!==job.plan_hash||row.plan_step_id!==step.stepId
      ||row.object_workspace_id!==step.objectWorkspaceId||row.operation_id!==input.operationId||row.before_hmac!==step.beforeHmac)
      throw denied('CONFIGURATION_BEFORE_READ_BINDING_CHANGED');
    for(const value of [job.authority_expires_at,job.expires_at,job.lease_until,execution.expires_at])this.future(value);
    const op=await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[input.operationId]);this.operation({...loaded,job,execution},step,row,op);
    if(op.remote_started!==true||op.remote_completed===true)throw denied('CONFIGURATION_APPROVED_OPERATION_INVALID');
    await this.redis.assertLeaseOwnership();this.context.current();
  }
  async native(proof:ApprovedExecutionProof,stepId:string,input:Readonly<ApprovedNativeRequest>,stage:ApprovedNativeStage,originalStep?:ApprovedStepProof):Promise<void>{
    const{loaded,step,row}=await this.step(proof,stepId),request=step.nativeRequests.find(r=>r.method===input.method&&r.canonicalPath===input.canonicalPath);
    if(!request||input.clusterId!==loaded.job.cluster_id||input.workspaceId!==step.objectWorkspaceId||input.transportScope!==loaded.job.transport_scope||input.operationId!==row.operation_id
      ||input.frame.actor?.id!==proof.actorId||(proof.origin==='scheduled-configuration'?input.frame.sessionId!=null:input.frame.sessionId!==proof.sessionId)||input.mutationAction!==step.mutationAction||(input.parentId??null)!==(step.parentId??null)
      ||(input.credentialKind??null)!==(step.credentialKind??null)||Object.keys(input.query).length||request.bodyHmac!==this.secrets.fingerprint(input.body??null)
      ||request.beforeHmac!==this.secrets.fingerprint(input.before??null))throw denied('CONFIGURATION_APPROVED_NATIVE_MISMATCH');
    const op=await this.db.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[row.operation_id]);this.operation(loaded,step,row,op);
    if(op.remote_started!==true||op.remote_completed===true)throw denied('CONFIGURATION_APPROVED_OPERATION_INVALID');
    if(stage==='response'&&input.method==='POST'&&(input.result as any)?.id!==(step.allocatedNativeId??step.nativeId))throw denied('CONFIGURATION_APPROVED_CREATED_ID_MISMATCH');
    if(stage==='before-send'){
      const append=this.targetAppend(step);
      if(proof.origin==='scheduled-configuration'){
        if(!originalStep||originalStep.execution!==proof||originalStep.stepId!==stepId||!this.nativeBeforeReader)throw denied('CONFIGURATION_BEFORE_READER_REQUIRED');
        const observed=await this.nativeBeforeReader.read(originalStep,Object.freeze({loaded,step,row,request,input}));
        if(this.secrets.fingerprint(observed.before??null)!==request.beforeHmac)throw new ConflictException({code:'CONFIGURATION_CURRENT_BEFORE_CHANGED'});
        if(append&&observed.allocatedAbsent!==true)throw new ConflictException({code:'CONFIGURATION_TARGET_APPEND_ID_OCCUPIED'});
      }else{
      const path=append?`${input.canonicalPath}/${step.nativeId}`:input.method==='POST'?`${input.canonicalPath}/${step.allocatedNativeId??step.nativeId}`:input.canonicalPath;
      let before:unknown;try{before=await this.context.runInternalRead(input.clusterId,'authorization',()=>this.kong.request(input.clusterId,'GET',path),{paths:[path],maxCalls:1});}
      catch(error:any){if(error?.getStatus?.()!==404&&error?.status!==404)throw error;before=null;}
      if(this.secrets.fingerprint(before??null)!==request.beforeHmac)throw new ConflictException({code:'CONFIGURATION_CURRENT_BEFORE_CHANGED'});
      if(append){
        const allocatedPath=`${input.canonicalPath}/${step.allocatedNativeId}`;let allocated:unknown;
        try{allocated=await this.context.runInternalRead(input.clusterId,'authorization',()=>this.kong.request(input.clusterId,'GET',allocatedPath),{paths:[allocatedPath],maxCalls:1});}
        catch(error:any){if(error?.getStatus?.()!==404&&error?.status!==404)throw error;allocated=null;}
        if(allocated!==null)throw new ConflictException({code:'CONFIGURATION_TARGET_APPEND_ID_OCCUPIED'});
      }
      }
      await this.step(proof,stepId);
    }
    await this.redis.assertLeaseOwnership();this.context.current();
  }
}
