import { BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable, Logger, NotFoundException, OnModuleInit } from '@nestjs/common';
import {compareCapturedSchemas} from '../config-transfer/schema-comparison';
import {ConfigTransferError} from '../config-transfer/transfer.types';
import { validateBatchSelection, toolboxBatchTarget } from '../toolbox/batch-plan';
import { randomBytes, randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { canonicalJson, SecretService } from '../../infrastructure/secret.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import {KongService} from '../../infrastructure/kong/kong.service';
import { AuditService } from '../audit/audit.service';
import { metadataAuditScope } from '../event-producers/native-audit-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { ConfigurationRepositoryService, SNAPSHOT_TERMINAL_CAPTURE_QUERY } from '../config-storage/configuration-repository.service';
import { ConfigurationCaptureService } from '../config-capture/configuration-capture.service';
import { parseDeckDocument, normalizeDeckDocument, normalizeCaptureGraph, serializeDeck11WithReport, diffTransferGraphs, compileTransferDag, formatSafeDiff } from '../config-transfer';
import type { ParsedDeckDocument, TransferDiff } from '../config-transfer';
import { WorkflowPlansService } from '../workflows/workflow-plans.service';
import { WorkflowRegistryService } from '../workflows/workflow-registry.service';
import { ApprovedWorkflowExecutionService } from '../workflows/approved-workflow-execution.service';
import { assertConfigurationWorkflowPlan, type ConfigurationWorkflowPayload } from '../workflows/configuration-workflow';
import {assertConfigurationMetadataWorkflowPlan,configurationMetadataAction,type ConfigurationMetadataPayload,type ConfigurationMetadataResource,type ConfigurationMetadataOperation} from '../workflows/configuration-metadata-workflow';
import type { WorkflowPlanV1, WorkflowHandlerInput } from '../workflows/workflow.types';
import type { EntityActor } from '../entities/entities.types';
import { PortalCursor } from '../portal/portal-input';
import { ConfigurationAccessService } from './configuration-access.service';
import { ConfigurationDurableService,type ConfigurationDurablePublicationWriter } from './configuration-durable.service';
import {DURABLE_CONFIGURATION_PRESENCE_QUERY,isProvenLegacyConfigurationRow} from './configuration-durable.repository';
import {DURABLE_REJECTION_CODE,type DurableConfigurationRejectionFact} from './configuration-durable-rejection';
import {assertDurableConfigurationEquivalent} from './configuration-durable-equivalence';
import { ConfigurationOriginService } from './configuration-origin.service';
import {decryptComparisonMaterial} from '../governance/governance-comparison-material';
import type {ComparisonInventory} from '../governance/comparison-types';
import { ConfigurationNativeService } from './configuration-native.service';
import {ConfigurationFailureLedgerService,type ConfigurationFailureHandle,type ConfigurationInitializationFailureHandle} from './configuration-failure-ledger.service';
import { ConfigurationRecycleGraphsService } from './configuration-recycle-graphs.service';
import {CONFIGURATION_LEASE_MS} from '../../infrastructure/kong/configuration-budget';
import { configurationId, configurationKey, configurationConfirm, configurationPage, configurationScopeInput, safeConfigurationError } from './configuration-input';
import {EXPORT_PROJECTION_QUERY,EXPORT_DOWNLOAD_QUERY} from './configuration-export-queries';
import {CONFIGURATION_JOB_PROJECTION_QUERY} from './configuration-job-queries';
import {APPROVAL_WORKFLOW_CONTEXT_QUERY,APPROVAL_CONFIGURATION_PLAN_QUERY} from './configuration-approval-queries';
import type { CaptureGraph, CaptureObject, ConfigPlan, ConfigurationAccessHandle, ConfigurationJobSummary, ConfigurationScope, ConfigurationScopeKind, ConfigurationDownloadEvidence,ConfigurationOriginRef,ConfigurationPromotionSourcePolicy } from './configuration.types';
import {historicalConfigurationAllowed} from './configuration-history-policy';
import {grantMatchesEntity} from '../authorization/grant-policy';
import type { WorkflowScheduledConfigurationOriginService } from '../workflows/workflow-scheduled-configuration-origin.service';
import type { WorkflowScheduledConfigurationJobHandle, WorkflowScheduledConfigurationExecutionHandle } from '../workflows/workflow-scheduled-configuration-origin.types';
import type {DeckAuthority,DeckPacket,DeckSessionIssue} from '../deck-adapter/deck.types';

/** Executed solely by the once-installed Repository created callback, in the
 * same transaction as the actual nested execution INSERT. No native authority
 * comes from this SQL string or any client-supplied tuple. */
export const CONFIGURATION_SCHEDULED_NESTED_ORIGIN_INSERT_SQL = `INSERT INTO workflow_configuration_execution_origins(id,cluster_id,workspace_id,wrapper_origin_id,claim_id,workflow_execution_id,workflow_id,workflow_plan_revision,workflow_plan_hash,configuration_execution_id,configuration_job_id,configuration_plan_id,configuration_plan_revision,configuration_plan_hash,workflow_step_id)
      SELECT $1,e.cluster_id,e.workspace_id,o.id,o.claim_id,o.execution_id,o.workflow_id,o.workflow_plan_revision,o.workflow_plan_hash,e.id,e.job_id,e.plan_id,e.plan_revision,e.plan_hash,s.id
      FROM configuration_executions e JOIN configuration_jobs j ON j.id=e.job_id AND j.cluster_id=e.cluster_id AND j.workspace_id=e.workspace_id
      JOIN workflow_execution_origins o ON o.id=$2 AND o.claim_id=$3 AND o.execution_id=$4 AND o.executor_id=e.actor_id
      JOIN workflow_steps s ON s.workflow_id=o.workflow_id AND s.plan_revision=o.workflow_plan_revision AND s.plan_hash=o.workflow_plan_hash
      JOIN workflow_executions we ON we.id=o.execution_id AND we.workflow_id=o.workflow_id AND we.plan_revision=o.workflow_plan_revision AND we.plan_hash=o.workflow_plan_hash
      WHERE e.id=$5 AND e.job_id=$6 AND e.actor_id=$7 AND e.cluster_id=$8 AND e.workspace_id=$9
      AND e.plan_id=$10 AND e.plan_revision=$11 AND e.plan_hash=$12 AND e.state='claimed' AND e.execution_mode='approval'
      AND e.workflow_id=o.workflow_id AND e.approved_version=o.workflow_plan_revision AND e.workflow_plan_hash=o.workflow_plan_hash
      AND e.permission_version=$13 AND e.lease_generation=j.lease_generation AND e.expires_at<=j.expires_at
      AND j.origin_type='http' AND j.origin_session_id IS NOT NULL AND j.state='running' AND j.execution_mode='approval' AND j.approval_required=true
      AND j.actor_id=e.actor_id AND j.workflow_id=o.workflow_id AND j.plan_id=e.plan_id AND j.plan_revision=e.plan_revision AND j.plan_hash=e.plan_hash
      AND j.lease_until>clock_timestamp() AND j.authority_expires_at>clock_timestamp() AND j.expires_at>clock_timestamp()
      AND o.cluster_id=e.cluster_id AND o.workspace_id=e.workspace_id AND we.state='executing' AND we.execution_actor_id=e.actor_id
      AND s.cluster_id=e.cluster_id AND s.workspace_id=e.workspace_id AND s.kind='metadata' AND s.handler='configuration_v2'
      AND s.entity_type='configuration_jobs' AND s.entity_id=j.id AND s.state='running' AND jsonb_array_length(s.native_requests)=0`;

/** A read-only deny projection over append-only source dispositions. It does
 * not authorize either publication or Native execution; the original current
 * scope/manifest/object permission checks must run before consulting it. */
export const CONFIGURATION_SOURCE_SUBMISSION_DISPOSITION_QUERY = `SELECT
 EXISTS(SELECT 1 FROM configuration_durable_rejections r WHERE r.source_plan_id=$1 AND r.cluster_id=$2 AND r.workspace_id=$3) AS rejected,
 EXISTS(SELECT 1 FROM configuration_durable_issues i WHERE i.source_plan_id=$1 AND i.cluster_id=$2 AND i.workspace_id=$3) AS registered`;

const fail=(code:string)=>new ConflictException({code,message:'配置作业未完成，请核验原回执'});
const uncertainFailure=(error:unknown)=>new HttpException(Object.freeze({code:safeConfigurationError(error),
  message:'配置执行结果待核验，请查看原回执',state:'uncertain'}),error instanceof HttpException?error.getStatus():503);
/** A committed known result preserves the original failure. An unresolved
 * result or lost ledger acknowledgement cannot certify a known failed write. */
const failureError=(error:unknown,receipt:Readonly<Record<string,unknown>>)=>receipt&&typeof receipt==='object'&&!Array.isArray(receipt)
  &&receipt.terminalFailureRecorded===true&&(receipt.state==='failed'||receipt.state==='partial')?error:uncertainFailure(error);
const expiry=()=>new Date(Date.now()+14*60_000).toISOString();
/** HTTP M8 jobs return the actual sealed/result receipt. The M11 scheduled
 * branch retains separate original NULL-SID job/nested execution handles and
 * records the actual same V2 outcomes. Lost acknowledgements resolve through
 * the original immutable ledger; neither path implicitly replays a write. */
@Injectable()
export class ConfigurationService implements OnModuleInit {
  private readonly logger=new Logger(ConfigurationService.name);
  private scheduledOrigin?: WorkflowScheduledConfigurationOriginService;
  /** Fixed bootstrap wiring only. No HTTP endpoint accepts origin handles. */
  installWorkflowScheduledConfigurationOrigin(origin: WorkflowScheduledConfigurationOriginService): void {
    if(this.scheduledOrigin || !origin || typeof origin.runOriginalJob!=='function') throw new ForbiddenException({code:'CONFIGURATION_SCHEDULE_ORIGIN_ALREADY_INSTALLED'});
    this.access.installWorkflowScheduledConfigurationOrigin(origin);
    this.approved.installWorkflowScheduledConfigurationDelegate({verifyExecution:(handle,checkpoint,tx)=>origin.verifyConfigurationExecution(handle,checkpoint,tx)});
    this.scheduledOrigin=origin;
  }
  private async scheduledConfigurationOriginCreated(tx: DbService, handle: ConfigurationAccessHandle, executionId: string): Promise<void> {
    if(!this.access.isWorkflowScheduledConfigurationJob(handle)){
      if(this.context.hasWorkflowScheduledNamespace())throw new ForbiddenException({code:'CONFIGURATION_SCHEDULE_ORIGINAL_JOB_REQUIRED'});
      return;
    }
    if(!this.scheduledOrigin)throw new ForbiddenException({code:'CONFIGURATION_SCHEDULE_ORIGIN_UNAVAILABLE'});
    const proof=await this.access.workflowScheduledConfigurationJobProof(handle,tx);
    const count=await tx.exec(CONFIGURATION_SCHEDULED_NESTED_ORIGIN_INSERT_SQL,
      [randomUUID(),proof.wrapperOriginId,proof.claimId,proof.wrapperExecutionId,executionId,proof.jobId,proof.actor.id,proof.clusterId,proof.workspaceId,proof.planId,proof.planRevision,proof.planHash,proof.permissionVersion]);
    if(count!==1)throw fail('CONFIGURATION_SCHEDULE_NESTED_ORIGIN_CONFLICT');
  }
  private readonly cursors=new PortalCursor();
  private readonly claims=new AsyncLocalStorage<{executionId:string;claimHash:string;handle:ConfigurationAccessHandle;workflowExecutionId?:string}>();
  private readonly metadataExecutions=new Map<string,{handle:ConfigurationAccessHandle;payloadHmac:string;expiresAt:number}>();
  private readonly deckExecutions=new Map<string,{handle:ConfigurationAccessHandle;plan:ConfigPlan;executionId:string;job:any;rows:any[];targetDeleteIntents:Set<string>;completed:number;expiresAt:number}>();
  constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
    private readonly context:KongExecutionContextService,private readonly audit:AuditService,private readonly authz:AuthorizationService,
    private readonly workspaces:WorkspaceResolverService,private readonly access:ConfigurationAccessService,
    private readonly repo:ConfigurationRepositoryService,private readonly capture:ConfigurationCaptureService,
    private readonly native:ConfigurationNativeService,private readonly workflowPlans:WorkflowPlansService,
    private readonly registry:WorkflowRegistryService,private readonly approved:ApprovedWorkflowExecutionService,private readonly kong:KongService,
    private readonly failureLedger:ConfigurationFailureLedgerService,private readonly recycleGraphs:ConfigurationRecycleGraphsService,private readonly origins?:ConfigurationOriginService,private readonly durable?:ConfigurationDurableService){}
  onModuleInit():void{
    this.durable?.installPublicationWriter({persist:(tx,input)=>this.persistDurableCompilation(tx,input),recordRejection:(tx,fact)=>this.recordDurableRejection(tx,fact)});
    this.repo.installScheduledExecutionOriginPolicy({created:(tx,handle,id)=>this.scheduledConfigurationOriginCreated(tx,handle,id)});
    if(this.origins)this.repo.installOriginPolicy(this.origins.storagePolicy());
    if(this.origins){
      this.origins.installRecovery({read:async(binding,source,actor)=>{
        const reader=(await this.scopeHandle(source.scope.clusterId,{...actor,workspaceId:source.scope.workspaceId},{scope:source.scope.kind,serviceIds:source.scope.rootIds},'compare')).handle;
        const graph=await this.repo.readSnapshot(reader,{scope:source.scope,snapshotId:binding.snapshot_id,version:binding.snapshot_version});
        await this.access.assertHistoricalGraph(reader,graph,true);return{graph,handle:reader};
      },verify:async(handle,graph)=>{await this.access.assertHistoricalGraph(handle,graph,true);return this.access.assertCurrent(handle,{phase:'read'});}});
      this.context.installPromotionRecoveryReadPolicy(this.origins.recoveryPolicy());
      this.context.installPromotionPlanningPolicy(this.origins.planningPolicy());
    }
    this.repo.installEvidenceWriter({jobCreated:(tx,before,after)=>this.auditJob(tx,before,after,'configuration.job.requested'),
      snapshotSealed:async(tx,before,after,snapshot)=>{await this.auditJob(tx,before,after,'configuration.capture');
        const frame=this.context.current();await this.audit.append({actorId:frame.actor?.id,clusterId:snapshot.clusterId,workspaceId:snapshot.workspaceId,
          entityType:'config_snapshots',entityId:snapshot.id,action:'snapshot.capture',before:null,after:snapshot,requestId:frame.requestId,ip:frame.ip,
          scopeHints:metadataAuditScope('snapshots','config_snapshots',snapshot.id,snapshot.workspaceId)},tx);},
      metadataChanged:async(tx,event)=>{const frame=this.context.current();await this.audit.append({actorId:frame.actor?.id,clusterId:event.scope.clusterId,workspaceId:event.scope.workspaceId,
        entityType:event.resourceType,entityId:event.resourceId,action:`configuration.${event.action}`,before:event.before,after:event.after,requestId:frame.requestId,ip:frame.ip,
        scopeHints:metadataAuditScope(event.resourceType==='configuration_gitops_runs'?'gitops':'snapshots',event.resourceType,event.resourceId,event.scope.workspaceId)},tx);}});
    this.approved.installConfigurationDelegate({verifyExecution:async(id,tx)=>{
      const privateClaim=this.claims.getStore(),job=this.access.currentJob();
      if(!privateClaim||privateClaim.executionId!==id||privateClaim.handle!==job.handle||!privateClaim.workflowExecutionId)throw new ForbiddenException({code:'CONFIGURATION_EXECUTION_CLAIM_REQUIRED'});
      const proof=await this.access.assertCurrent(job.handle,{phase:'step',jobId:job.jobId},tx);
      const scheduledOrigin=this.access.isWorkflowScheduledConfigurationJob(job.handle)?await this.access.workflowScheduledConfigurationExecutionProof(job.handle,id,tx):undefined;
      return{...(scheduledOrigin?{scheduledOrigin}:{}),claimHash:privateClaim.claimHash,jobId:job.jobId,actorId:proof.actorId,sessionId:proof.sessionId??null,leaseGeneration:proof.leaseGeneration!,
        permissionVersion:proof.permissionVersion,expiresAt:proof.expiresAt,workflowExecutionId:privateClaim.workflowExecutionId};
    },assertOrigin:async(plan,actorId,action,tx)=>{
      await this.assertDurableWorkflow(plan,tx);
      if(this.context.peek()&&this.context.hasWorkflowScheduledNamespace()){
        const claim=this.claims.getStore(),job=this.access.currentJob();
        if(!claim||!this.scheduledOrigin||!this.access.isWorkflowScheduledConfigurationJob(job.handle)||action!=='write')throw new ForbiddenException({code:'CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED'});
        const proof=await this.access.workflowScheduledConfigurationExecutionProof(job.handle,claim.executionId,tx);
        if(proof.workflowId!==plan.workflowId||proof.workflowPlanRevision!==plan.planRevision||proof.workflowPlanHash!==this.secrets.fingerprint(plan)||proof.actorId!==actorId)throw new ForbiddenException({code:'CONFIGURATION_SCHEDULE_WORKFLOW_CHANGED'});
        const preparation=typeof this.context.scheduledConfigurationPreparationPhase==='function'?this.context.scheduledConfigurationPreparationPhase():null;
        if(preparation){
          if(preparation.originalJobHandle!==this.access.originalWorkflowScheduledConfigurationJobHandle(job.handle)||preparation.namespaceHandle!==proof.namespaceHandle)throw new ForbiddenException({code:'CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED'});
          if(this.origins)await this.origins.assertStoredWorkflow(plan,tx);else await this.assertLegacyOrigin(plan,tx);
        }else if(this.origins)await this.origins.assertWorkflow(plan,actorId,action,tx);else await this.assertLegacyOrigin(plan,tx);
        return;
      }
      return this.origins?this.origins.assertWorkflow(plan,actorId,action,tx):this.assertLegacyOrigin(plan,tx);
    },
      assertStoredOrigin:async(plan,tx)=>{await this.assertDurableWorkflow(plan,tx);return this.origins?this.origins.assertStoredWorkflow(plan,tx):this.assertLegacyOrigin(plan,tx);},
      runLoad:fn=>this.access.runCheckpointOccurrence(fn)});
    this.workflowPlans.installConfigurationOriginDelegate({assertStoredOrigin:async(plan,tx)=>{await this.assertDurableWorkflow(plan,tx);return this.origins?this.origins.assertStoredWorkflow(plan,tx):this.assertLegacyOrigin(plan,tx);},
      assertScheduledProposalOrigin:async(plan,base,originalProposal,tx)=>{
        if(!originalProposal||typeof originalProposal!=='object')throw new ForbiddenException({code:'CONFIGURATION_DURABLE_SCHEDULE_PROPOSAL_REQUIRED'});
        if(this.durable)await this.durable.scheduledProposal(plan,base,tx);
        return this.origins?this.origins.assertStoredWorkflow(plan,tx):this.assertLegacyOrigin(plan,tx);
      }});
    this.registry.register('configuration_v2',{authorize:(plan,actor,action)=>this.authorizeWrapper(plan,actor,action),
      inspect:async(input,tx)=>({before:await this.wrapperProjection(input.plan,tx),revision:(input.step.metadata as ConfigurationWorkflowPayload).planRevision}),
      prepare:input=>this.prepareWrapper(input),apply:async input=>{
        const p=input.step.metadata as ConfigurationWorkflowPayload,row=await input.transaction.one<any>('SELECT state,safe_progress FROM configuration_jobs WHERE id=$1',[p.jobId]);
        if(row?.state!=='succeeded')throw fail('CONFIGURATION_JOB_NOT_SUCCEEDED');
        return{jobId:p.jobId,planId:p.planId,planRevision:p.planRevision,planHash:p.planHash,state:row.state};
      }});
    this.registry.register('configuration.metadata',{
      authorize:(plan,actor,action)=>this.authorizeMetadata(plan,actor,action),
      inspect:async(input,tx)=>{const m=assertConfigurationMetadataWorkflowPlan(input.plan).metadata as ConfigurationMetadataPayload;
        const before=await this.metadataBefore(m,input.plan.clusterId,input.plan.workspaceId,tx);return{before,revision:before?Number(before.revision):0};},
      prepare:async input=>{const m=assertConfigurationMetadataWorkflowPlan(input.plan).metadata as ConfigurationMetadataPayload;
        const handle=await this.access.acquire(m.jobId);await this.access.assertCurrent(handle,{phase:'read',jobId:m.jobId});
        for(const [id,value]of this.metadataExecutions)if(value.expiresAt<=Date.now())this.metadataExecutions.delete(id);
        this.metadataExecutions.set(input.executionId,{handle,payloadHmac:this.secrets.fingerprint(m),expiresAt:Date.parse(input.plan.expiresAt)});},
      apply:async input=>{const m=assertConfigurationMetadataWorkflowPlan(input.plan).metadata as ConfigurationMetadataPayload,privateClaim=this.metadataExecutions.get(input.executionId);
        if(!privateClaim||privateClaim.expiresAt<=Date.now()||privateClaim.payloadHmac!==this.secrets.fingerprint(m))throw new ForbiddenException({code:'CONFIGURATION_METADATA_EXECUTION_REQUIRED'});
        try{return await this.applyMetadata(privateClaim.handle,m,input.actor,input.transaction);}finally{this.metadataExecutions.delete(input.executionId);}
      }});
  }
  private async auditJob(tx:DbService,before:ConfigurationJobSummary|null,after:ConfigurationJobSummary,action='configuration.job.complete'):Promise<void>{
    const frame=this.context.current();await this.audit.append({actorId:frame.actor?.id,clusterId:after.clusterId,workspaceId:after.workspaceId,
      entityType:'configuration_jobs',entityId:after.id,action,before,after,requestId:frame.requestId,ip:frame.ip,result:after.state==='uncertain'?'uncertain':after.state==='failed'?'failed':'success',
      scopeHints:metadataAuditScope('snapshots','configuration_jobs',after.id,after.workspaceId)},tx);
  }
  private withActor<T>(cid:string,actor:EntityActor,action:string,fn:()=>Promise<T>):Promise<T>{return this.context.runActor({actor:actor.user,clusterId:configurationId(cid),
    workspaceId:actor.workspaceId,module:'snapshots',action,requestId:actor.requestId,purpose:'configuration'},async()=>{
      try{return await (this.origins?this.origins.run(fn):fn());}catch(error){
        if(error instanceof ConfigTransferError){
          if(error.code==='CONFIGURATION_DIFF_SCOPE_MISMATCH')throw new ConflictException({code:error.code,message:'快照范围、版本或字段约束不兼容，请重新核验配置'});
          throw new BadRequestException({code:error.code,message:'配置未通过校验，请核验格式、字段及恢复条件'});
        }throw error;
      }
    });}
  private async scopeHandle(cid:string,actor:EntityActor,value:Record<string,any>,purpose:'capture'|'compare'|'export'|'import'|'apply'|'rollback',kindOfJob:string=purpose,key:string=randomUUID(),module:'snapshots'|'gitops'='snapshots'):Promise<{handle:ConfigurationAccessHandle;scope:ConfigurationScope}>{
    const scopeInput=configurationScopeInput(value),handle=await this.access.acquireJob({actor:actor.user,clusterId:cid,workspaceId:actor.workspaceId,...scopeInput,purpose,kindOfJob,idempotencyKey:configurationKey(key),module});
    return{handle,scope:(await this.access.description(handle)).scope};
  }
  private async newJob(cid:string,actor:EntityActor,value:Record<string,any>,kind:'capture'|'import'|'compare'|'export'|'apply'|'rollback'|'reconcile',input:unknown,key=actor.idempotencyKey,module:'snapshots'|'gitops'='snapshots',originRef?:ConfigurationOriginRef):Promise<{handle:ConfigurationAccessHandle;scope:ConfigurationScope;job:ConfigurationJobSummary;existing:boolean}>{
    const k=configurationKey(key),{handle,scope}=await this.scopeHandle(cid,actor,value,kind==='reconcile'?'compare':kind,kind,k,module);
    const row=await this.db.one<any>('SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4',[scope.clusterId,scope.workspaceId,actor.user.id,k]);
    if(row){if(row.request_hmac!==this.secrets.fingerprint({scope,kind,input:input??null,...(originRef?{originRef}:{})}))throw fail('IDEMPOTENCY_CONFLICT');
      const receiptHandle=await this.access.acquireReceipt(row.id);return{handle:receiptHandle,scope,job:await this.repo.getJob(receiptHandle,row.id),existing:true};}
    if(originRef){if(!this.origins)throw fail('CONFIGURATION_ORIGIN_PROVIDER_UNAVAILABLE');this.origins.permitJob(handle,originRef);}
    const job=await this.repo.createJob(handle,{scope,kind,idempotencyKey:k,input,...(originRef?{originRef}:{}),expiresAt:expiry(),requestId:actor.requestId,writeEvidence:(tx,before,after)=>this.auditJob(tx,before,after,'configuration.job.requested')});
    return{handle:await this.access.acquire(job.id),scope,job,existing:false};
  }
  private async finish(handle:ConfigurationAccessHandle,id:string,state:'succeeded'|'failed'|'uncertain'|'partial',progress:unknown,error?:unknown):Promise<ConfigurationJobSummary>{
    return this.repo.finishJob(handle,{jobId:id,state,safeProgress:progress,...(error?{errorCode:safeConfigurationError(error)}:{}),writeEvidence:(tx,before,after)=>this.auditJob(tx,before,after)});
  }
  private async workspaceCodes(cid:string):Promise<Record<string,string>>{const rows=await this.db.query<any>("SELECT id,code FROM workspaces WHERE cluster_id=$1 AND status='active'",[cid]);return Object.fromEntries(rows.map(r=>[r.id,r.code]));}
  private metadataModule(resource:ConfigurationMetadataResource):'snapshots'|'gitops'{return resource==='configuration_gitops_runs'?'gitops':'snapshots';}
  private async metadataBefore(m:ConfigurationMetadataPayload,cid:string,wid:string,tx=this.db):Promise<Record<string,any>|null>{
    // Only fixed table choices enter SQL; no request supplies an identifier.
    const table=m.resourceType==='config_snapshots'?'config_snapshots':m.resourceType==='config_snapshot_schedules'?'config_snapshot_schedules':'configuration_gitops_runs';
    const row=await tx.one<any>(`SELECT * FROM ${table} WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`,[m.resourceId,cid,wid]);
    if(m.operation==='create'){if(row)throw fail('CONFIGURATION_METADATA_ALREADY_EXISTS');return null;}
    if(!row)throw new NotFoundException({code:'CONFIGURATION_METADATA_NOT_FOUND'});
    if(m.resourceType==='config_snapshots')return{id:row.id,name:row.name,revision:row.revision,state:row.state,currentVersion:row.current_version,transportScope:row.transport_scope};
    return{id:row.id,name:row.name,revision:row.revision,state:row.state,currentVersion:row.current_version,ownerUserId:row.owner_user_id,transportScope:row.transport_scope,purgedAt:row.purged_at?new Date(row.purged_at).toISOString():null};
  }
  private async authorizeMetadata(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve'):Promise<void>{
    const m=assertConfigurationMetadataWorkflowPlan(plan).metadata as ConfigurationMetadataPayload,ws=await this.workspaces.resolve(plan.clusterId,actor.workspaceId);
    if(ws.id!==plan.workspaceId||action==='write'&&actor.user.id!==plan.requester.id)throw new ForbiddenException({code:'CONFIGURATION_METADATA_SCOPE_DENIED'});
    await this.authz.assertWholeWorkspace(actor.user,plan.clusterId,ws.id,this.metadataModule(m.resourceType),action==='approve'?'read':action==='write'?configurationMetadataAction(m):'read');
    await this.authz.assertWholeWorkspace(actor.user,plan.clusterId,ws.id,'workflows',action);
  }
  private async applyMetadata(handle:ConfigurationAccessHandle,m:ConfigurationMetadataPayload,actor:EntityActor,transaction?:DbService):Promise<any>{
    const state=await this.access.description(handle),module=this.metadataModule(m.resourceType);
    await this.authz.assertWholeWorkspace(actor.user,state.scope.clusterId,state.scope.workspaceId,module,configurationMetadataAction(m));
    return (transaction??this.db).transaction(async tx=>{
      await this.access.assertCurrent(handle,{phase:configurationMetadataAction(m)==='delete'?'purge':'read',jobId:m.jobId},tx);
      const current=await this.metadataBefore(m,state.scope.clusterId,state.scope.workspaceId,tx),p=m.payload as any;
      if(current&&current.revision!==p.revision)throw fail('CONFIGURATION_METADATA_REVISION_CONFLICT');
      if(current){const table=m.resourceType==='config_snapshots'?'config_snapshots':'config_snapshot_schedules';
        const owner=await tx.one<any>(`SELECT ${m.resourceType==='config_snapshots'?'created_by':'owner_user_id'} AS owner FROM ${table} WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR UPDATE`,[m.resourceId,state.scope.clusterId,state.scope.workspaceId]);
        if(owner?.owner!==actor.user.id)throw new ForbiddenException({code:'CONFIGURATION_METADATA_OWNER_DENIED'});}
      let entity:any;
      if(m.resourceType==='config_snapshots'){
        if(m.operation==='purge')entity={...current,...await this.repo.destroySnapshotMaterial(handle,{scope:state.scope,snapshotId:m.resourceId,revision:p.revision,confirmName:p.confirm_name},tx)};
        else entity=await this.repo.archiveSnapshot(handle,{scope:state.scope,snapshotId:m.resourceId,revision:p.revision,restore:m.operation==='restore'},tx);
      }else if(m.resourceType==='config_snapshot_schedules'){
        if(m.operation==='create')entity=await this.repo.createSchedule(handle,{scope:state.scope,id:m.resourceId,name:p.name,intervalMinutes:p.intervalMinutes,timezone:p.timezone,retentionDays:p.retentionDays},tx);
        else if(m.operation==='update')entity=await this.repo.updateSchedule(handle,{scope:state.scope,scheduleId:m.resourceId,revision:p.revision,name:p.name,intervalMinutes:p.intervalMinutes,timezone:p.timezone,retentionDays:p.retentionDays,paused:p.paused},tx);
        else if(m.operation==='purge')entity=await this.repo.purgeSchedule(handle,{scope:state.scope,scheduleId:m.resourceId,revision:p.revision,confirmName:p.confirm_name},tx);
        else entity=await this.repo.archiveSchedule(handle,{scope:state.scope,scheduleId:m.resourceId,revision:p.revision,restore:m.operation==='restore'},tx);
      }else entity=await this.repo.createGitOpsRun(handle,{scope:state.scope,id:m.resourceId,jobId:p.sourceJobId,repositoryLabel:p.repositoryLabel,commitSha:p.commitSha,pipelineReference:p.pipelineReference},tx);
      const job=await this.repo.finishJob(handle,{jobId:m.jobId,state:'succeeded',safeProgress:{resourceType:m.resourceType,resourceId:m.resourceId,operation:m.operation},writeEvidence:(t,b,a)=>this.auditJob(t,b,a)},tx);
      return{entity,jobId:job.id,resourceId:m.resourceId,operation:m.operation,state:job.state};
    });
  }
  private async submitMetadata(cid:string,actor:EntityActor,value:Record<string,any>,resourceType:ConfigurationMetadataResource,resourceId:string,operation:ConfigurationMetadataOperation,payload:Record<string,unknown>):Promise<any>{
    const module=this.metadataModule(resourceType),ws=await this.workspaces.resolve(cid,actor.workspaceId);
    await this.authz.assertWholeWorkspace(actor.user,cid,ws.id,module,configurationMetadataAction({operation}));
    const old=await this.db.one<any>('SELECT * FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4',[cid,ws.id,actor.user.id,configurationKey(actor.idempotencyKey)]);
    if(old){const input=old.input_secret?this.secrets.decrypt<any>(old.input_secret,`configuration-job:${old.id}`):null;
      if(input?.action!=='metadata'||input.resourceType!==resourceType||input.operation!==operation||operation!=='create'&&input.resourceId!==resourceId
        ||canonicalJson(input.payload)!==canonicalJson(payload)||canonicalJson({kind:old.scope_kind,rootIds:old.root_ids})!==canonicalJson(configurationScopeInput(value)))throw fail('IDEMPOTENCY_CONFLICT');
      const reader=await this.access.acquireReceipt(old.id);return this.jobProjection(reader,await this.repo.getJob(reader,old.id));}
    const j=await this.newJob(cid,actor,value,'compare',{action:'metadata',resourceType,resourceId,operation,payload},actor.idempotencyKey,module);
    if(j.existing)return this.jobProjection(j.handle,j.job);
    try{
    const m:ConfigurationMetadataPayload={jobId:j.job.id,resourceType,resourceId,operation,payload},before=await this.metadataBefore(m,cid,ws.id),proof=await this.access.assertCurrent(j.handle,{phase:'read',jobId:j.job.id});
    const cluster=await this.db.one<any>('SELECT execution_mode FROM clusters WHERE id=$1',[cid]);
    if(cluster.execution_mode==='approval'){
      const workflowId=randomUUID();await this.db.transaction(async tx=>{
      await this.access.assertCurrent(j.handle,{phase:'read',jobId:j.job.id},tx);
      await this.workflowPlans.definitions(cid,ws.id,actor.user.id,tx);const definition=await this.workflowPlans.definition(cid,ws.id,'configuration-metadata',tx);
      const plan:WorkflowPlanV1={version:1,clusterId:cid,workspaceId:ws.id,workflowId,planRevision:1,kind:'configuration-metadata',executionMode:'approval',approvalRequired:true,
        subject:{type:resourceType,id:resourceId},requester:{type:'console',id:actor.user.id},definition,issuedAt:new Date().toISOString(),expiresAt:new Date(proof.expiresAt).toISOString(),
        scope:{transportScope:proof.scope.transportScope,clusterRevision:proof.clusterRevision,workspaceRevision:proof.workspaceRevision},prerequisites:[],
        steps:[{id:randomUUID(),key:'configuration.metadata',order:1,kind:'metadata',handler:'configuration.metadata',entityType:resourceType,entityId:resourceId,permissionAction:configurationMetadataAction(m),dependencies:[],nativeRequests:[],metadata:m,
          before,metadataBeforeHmac:this.secrets.fingerprint(before),metadataRevision:before?Number(before.revision):0,metadataPayloadHmac:this.secrets.fingerprint(m)}]};
      assertConfigurationMetadataWorkflowPlan(plan);
      await this.workflowPlans.persist(plan,this.internalKey(actor.idempotencyKey!,'metadata'),m,tx,{requestId:actor.requestId,ip:actor.ip});
      const count=await tx.exec("UPDATE configuration_jobs SET state='waiting_approval',workflow_id=$2,revision=revision+1,updated_at=now() WHERE id=$1 AND workflow_id IS NULL AND state='pending'",[j.job.id,workflowId]);
      if(count!==1)throw fail('CONFIGURATION_JOB_STATE_CHANGED');await this.access.assertCurrent(j.handle,{phase:'read',jobId:j.job.id},tx);
      });
      return this.jobProjection(j.handle,await this.repo.getJob(j.handle,j.job.id));
    }
    const result=await this.applyMetadata(j.handle,m,actor);return{...await this.jobProjection(j.handle,await this.repo.getJob(j.handle,j.job.id)),entity:result.entity};}
    catch(error){await this.finish(j.handle,j.job.id,'failed',{resourceId,operation},error);throw error;}
  }
  async mutateSnapshot(cid:string,id:string,operation:'archive'|'restore'|'purge',body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,operation==='restore'?'write':'delete',async()=>{
    const source=await this.snapshotScope(cid,id,actor);configurationConfirm(body,source.row.name);
    if(!Number.isSafeInteger(body.revision)||body.revision!==source.row.revision)throw fail('SNAPSHOT_REVISION_CONFLICT');
    const payload=operation==='restore'?{revision:body.revision}:{revision:body.revision,confirmed:true,confirm_name:body.confirm_name};
    return this.submitMetadata(cid,actor,{scope:source.scope.kind,serviceIds:source.scope.rootIds},'config_snapshots',id,operation,payload);
  });}
  async listSchedules(cid:string,query:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    const {handle,scope}=await this.scopeHandle(cid,actor,query,'compare'),page=await this.repo.listSchedules(handle,{scope,...configurationPage(query),state:query.state,search:query.search,includeDeleted:query.includeDeleted==='true'});
    const whole=(action:string)=>scope.kind==='cluster'?this.authz.hasWholeCluster(actor.user,cid,'snapshots',action):this.authz.hasWholeWorkspace(actor.user,cid,scope.workspaceId,'snapshots',action);
    const write=await whole('write'),del=await whole('delete');
    return{...page,items:page.items.map(e=>({...e,capabilities:{write:write&&e.ownerUserId===actor.user.id&&e.state!=='deleted',delete:del&&e.ownerUserId===actor.user.id&&e.state!=='deleted',restore:write&&e.ownerUserId===actor.user.id&&e.state==='deleted'&&!e.purgedAt,purge:del&&e.ownerUserId===actor.user.id&&e.state==='deleted'&&!e.purgedAt}}))};
  });}
  async mutateSchedule(cid:string,id:string|undefined,operation:ConfigurationMetadataOperation,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    let value:Record<string,any>=body,row:any;
    if(id){const ws=await this.workspaces.resolve(cid,actor.workspaceId);row=await this.db.one<any>(`SELECT s.*,v.scope_kind,v.root_ids FROM config_snapshot_schedules s JOIN config_snapshot_schedule_versions v
      ON v.schedule_id=s.id AND v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.version=s.current_version WHERE s.id=$1 AND s.cluster_id=$2 AND s.workspace_id=$3`,[id,cid,ws.id]);
      if(!row)throw new NotFoundException({code:'SNAPSHOT_SCHEDULE_NOT_FOUND'});value={scope:row.scope_kind,serviceIds:row.root_ids};
      if(body.scope!==undefined&&canonicalJson(configurationScopeInput(body))!==canonicalJson(configurationScopeInput(value)))throw fail('SNAPSHOT_SCHEDULE_SCOPE_IMMUTABLE');
      if(body.confirmed!==undefined||['archive','restore','purge'].includes(operation))configurationConfirm(body,row.name);
      if(body.revision!==row.revision)throw fail('SNAPSHOT_SCHEDULE_REVISION_CONFLICT');
    }
    const payload:Record<string,unknown>=operation==='create'||operation==='update'?{name:body.name,intervalMinutes:body.intervalMinutes,timezone:body.timezone,retentionDays:body.retentionDays,
      ...(id?{revision:body.revision,...(body.paused!==undefined?{paused:body.paused}:{})}:{})}:operation==='restore'?{revision:body.revision}:{revision:body.revision,confirmed:true,confirm_name:body.confirm_name};
    return this.submitMetadata(cid,actor,value,'config_snapshot_schedules',id??randomUUID(),operation,payload);
  });}
  async listGitOps(cid:string,query:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    const {handle,scope}=await this.scopeHandle(cid,actor,query,'compare','compare',randomUUID(),'gitops');return this.repo.listGitOpsRuns(handle,{scope,...configurationPage(query)});
  });}
  async createGitOps(cid:string,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const ws=await this.workspaces.resolve(cid,actor.workspaceId),source=await this.db.one<any>('SELECT id,scope_kind,root_ids FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND actor_id=$4',[configurationId(body.jobId),cid,ws.id,actor.user.id]);
    if(!source)throw new NotFoundException({code:'CONFIGURATION_JOB_NOT_FOUND'});
    return this.submitMetadata(cid,actor,{scope:source.scope_kind,serviceIds:source.root_ids},'configuration_gitops_runs',randomUUID(),'create',{sourceJobId:source.id,repositoryLabel:body.repositoryLabel,commitSha:body.commitSha,pipelineReference:body.pipelineReference});
  });}
  async runDueSchedules():Promise<void>{
    const locators=await this.repo.peekDueSchedules(20);
    for(const locator of locators)try{await this.redis.withLock(`configuration-schedule:${locator.scheduleId}`,async()=>{
      const trusted=await this.access.acquireDueSchedule(locator);
      await this.access.runJob(trusted.handle,async()=>{
        const registration=await this.db.transaction(async tx=>{
          const claimed=await this.repo.claimDue(trusted.handle,{scope:trusted.scope,...locator,runId:trusted.runId},tx);
          const job=await this.repo.createJob(trusted.handle,{id:trusted.jobId,scope:trusted.scope,kind:'capture',idempotencyKey:`schedule-${trusted.runId}`,expiresAt:expiry(),
          input:{scheduleId:locator.scheduleId,scheduleVersion:locator.version,runId:trusted.runId,scheduledAt:locator.scheduledAt},requestId:`schedule-${trusted.runId}`,writeEvidence:(tx,b,a)=>this.auditJob(tx,b,a,'configuration.schedule.capture.requested')},tx);
          await this.repo.bindScheduleRunJob(trusted.handle,{jobId:job.id,runId:trusted.runId},tx);return{claimed,job};});
        const {claimed,job}=registration;await this.access.completeScheduleRegistration(trusted.handle);
        let snapshotId:string|undefined;
        try{const stage=await this.repo.beginCapture(trusted.handle,{scope:trusted.scope,jobId:job.id,name:`${trusted.name.slice(0,100)} · ${locator.scheduledAt}`,description:'定时策略捕获',idempotencyKey:`schedule-${trusted.runId}`,expiresAt:expiry()});snapshotId=stage.snapshotId;
          await this.capture.capture(trusted.handle,stage,trusted.scope);
          // Expiration retains encrypted material. Only a confirmed purge can
          // destroy online keys; independently retained backups remain explicit.
          await this.db.transaction(async tx=>{await this.access.assertCurrent(trusted.handle,{phase:'read',jobId:job.id},tx);
            const before=await this.repo.getSnapshotSummary(trusted.handle,{scope:trusted.scope,snapshotId:stage.snapshotId});
            const retentionUntil=new Date(Date.now()+claimed.retentionDays*86400000).toISOString();
            await tx.exec('UPDATE config_snapshots SET retention_until=$2,revision=revision+1,updated_at=now() WHERE id=$1 AND cluster_id=$3 AND workspace_id=$4 AND state=\'ready\'',[stage.snapshotId,retentionUntil,trusted.scope.clusterId,trusted.scope.workspaceId]);
            await this.audit.append({actorId:(await this.access.description(trusted.handle)).actor.id,clusterId:trusted.scope.clusterId,workspaceId:trusted.scope.workspaceId,entityType:'config_snapshots',entityId:stage.snapshotId,action:'configuration.snapshot.retention',before,after:{...before,revision:before.revision+1,retentionUntil},requestId:`schedule-${trusted.runId}`,scopeHints:metadataAuditScope('snapshots','config_snapshots',stage.snapshotId,trusted.scope.workspaceId)},tx);
          });
        }catch(error){const latest=await this.db.one<any>('SELECT state FROM configuration_jobs WHERE id=$1',[job.id]);if(latest?.state!=='succeeded')await this.finish(trusted.handle,job.id,'failed',{...(snapshotId?{snapshotId}:{}),scheduleRunId:trusted.runId},error);throw error;}
      });
    });}catch(error){this.logger.warn(JSON.stringify({event:'configuration.schedule.failed',scheduleId:locator.scheduleId,code:safeConfigurationError(error)}));}
  }
  private internalKey(key:string,kind:string):string{return`configuration-${kind}-${this.secrets.fingerprint(key).slice(0,48)}`;}
  private async captureBaseline(cid:string,actor:EntityActor,value:Record<string,any>,key:string,name:string,requiredPluginSchemas?:readonly string[]):Promise<{graph:CaptureGraph;snapshotId:string;version:number}>{
    const required=requiredPluginSchemas?[...new Set(requiredPluginSchemas)].sort():undefined,input={name,description:'',...(required?{requiredPluginSchemas:required}:{})},job=await this.newJob(cid,actor,value,'capture',input,key);
    if(job.existing){const snapshotId=job.job.safeProgress.snapshotId;if(job.job.state!=='succeeded'||typeof snapshotId!=='string')throw fail('CONFIGURATION_BASELINE_NOT_READY');
      const reader=(await this.scopeHandle(cid,actor,value,'compare')).handle,graph=await this.repo.readSnapshot(reader,{scope:job.scope,snapshotId});
      await this.access.assertHistoricalGraph(reader,graph,true);if(required?.some(name=>!Object.hasOwn(graph.schemas.plugins,name)))throw fail('CONFIGURATION_BASELINE_SCHEMA_NOT_CAPTURED');return{graph,snapshotId,version:1};}
    let snapshotId:string|undefined;
    try{const stage=await this.repo.beginCapture(job.handle,{jobId:job.job.id,scope:job.scope,name,idempotencyKey:key,expiresAt:expiry()});snapshotId=stage.snapshotId;
      await this.access.runJob(job.handle,()=>required?this.capture.capture(job.handle,stage,job.scope,{requiredPluginSchemas:required}):this.capture.capture(job.handle,stage,job.scope));const graph=await this.repo.readSnapshot(job.handle,{scope:job.scope,snapshotId:stage.snapshotId});return{graph,snapshotId:stage.snapshotId,version:1};}
    catch(error){await this.finish(job.handle,job.job.id,'failed',snapshotId?{snapshotId}:{},error);throw error;}
  }
  async captureSnapshot(cid:string,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    if(typeof body.name!=='string'||!body.name.trim()||body.name.length>128||body.description!==undefined&&(typeof body.description!=='string'||body.description.length>8192))throw new BadRequestException({code:'INVALID_SNAPSHOT_NAME'});
    const input={name:body.name,description:body.description??''},j=await this.newJob(cid,actor,body,'capture',input);
    if(j.existing)return this.jobProjection(j.handle,j.job);
    let snapshotId:string|undefined;
    try{const stage=await this.repo.beginCapture(j.handle,{jobId:j.job.id,scope:j.scope,...input,idempotencyKey:actor.idempotencyKey!,expiresAt:expiry()});snapshotId=stage.snapshotId;
      await this.access.runJob(j.handle,()=>this.capture.capture(j.handle,stage,j.scope));return this.jobProjection(j.handle,await this.repo.getJob(j.handle,j.job.id));}
    catch(error){await this.finish(j.handle,j.job.id,'failed',snapshotId?{snapshotId}:{},error);throw error;}
  });}
  async listSnapshots(cid:string,query:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    const {handle,scope}=await this.scopeHandle(cid,actor,query,'compare'),page=await this.repo.listSnapshots(handle,{scope,...configurationPage(query),includeDeleted:query.includeDeleted==='true',state:query.state,search:query.search});
    return{...page,items:await Promise.all(page.items.map(async e=>({...e,capabilities:await this.snapshotCapabilities(actor,e)})))};
  });}
  private async snapshotCapabilities(actor:EntityActor,e:{id:string;clusterId:string;workspaceId:string;scopeKind:string;state:string;recovery:Record<string,number>}):Promise<Record<string,boolean>>{
    const whole=(action:string)=>e.scopeKind==='cluster'?this.authz.hasWholeCluster(actor.user,e.clusterId,'snapshots',action):this.authz.hasWholeWorkspace(actor.user,e.clusterId,e.workspaceId,'snapshots',action);
    const read=await whole('read'),write=await whole('write'),del=await whole('delete'),material=await this.db.one<any>(`SELECT s.created_by,count(*) FILTER(WHERE m.state='available')::integer AS available FROM config_snapshots s
      LEFT JOIN config_snapshot_versions v ON v.snapshot_id=s.id AND v.cluster_id=s.cluster_id AND v.workspace_id=s.workspace_id AND v.version=s.current_version
      LEFT JOIN configuration_materials m ON m.id=v.material_id AND m.cluster_id=v.cluster_id AND m.workspace_id=v.workspace_id WHERE s.id=$1 AND s.cluster_id=$2 AND s.workspace_id=$3 GROUP BY s.created_by`,[e.id,e.clusterId,e.workspaceId]);
    const owner=material?.created_by===actor.user.id,ready=e.state==='ready'&&material.available>0;
    const archivable=['ready','failed','incomplete','expired'].includes(e.state)||e.state==='capturing'&&!!await this.db.one(SNAPSHOT_TERMINAL_CAPTURE_QUERY,[e.clusterId,e.workspaceId,e.id]);
    return{read,compare:read&&ready,export:read&&ready,rollback:write&&ready&&Object.entries(e.recovery).every(([state,count])=>state==='complete'||count===0),
      write:write&&owner&&ready,delete:del&&owner&&archivable,restore:write&&owner&&e.state==='deleted'&&material.available>0,purge:del&&owner&&e.state==='deleted'&&material.available>0};
  }
  private async snapshotScope(cid:string,id:string,actor:EntityActor):Promise<{handle:ConfigurationAccessHandle;scope:ConfigurationScope;row:any}>{
    const ws=await this.workspaces.resolve(cid,actor.workspaceId),row=await this.db.one<any>('SELECT * FROM config_snapshots WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[configurationId(id),cid,ws.id]);
    if(!row)throw new NotFoundException({code:'SNAPSHOT_NOT_FOUND'});const r=await this.scopeHandle(cid,actor,{scope:row.scope_kind,serviceIds:row.root_ids},'compare');return{...r,row};
  }
  async snapshot(cid:string,id:string,query:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    const {handle,scope,row}=await this.snapshotScope(cid,id,actor),summary=await this.repo.getSnapshotSummary(handle,{scope,snapshotId:id});
    const capabilities=await this.snapshotCapabilities(actor,summary);
    if(row.state!=='ready')return{entity:{...summary,capabilities},items:[],size:20,nextCursor:null,total:null,capabilities};
    const graph=await this.repo.readSnapshot(handle,{scope,snapshotId:id});await this.access.assertHistoricalGraph(handle,graph);
    const page=configurationPage(query),binding=this.secrets.fingerprint({cid,wid:scope.workspaceId,id,actor:actor.user.id,version:graph.versionId,permissionVersion:(await this.access.description(handle)).permissionVersion,size:page.size});
    const start=this.cursors.decode(page.cursor,binding)?.offset??0;if(!Number.isInteger(start)||start<0||start>graph.objects.length)throw new BadRequestException({code:'INVALID_CURSOR'});
    const items=graph.objects.slice(start,start+page.size).map(o=>({objectKey:o.objectKey,entityType:o.entityType,nativeId:o.nativeId,parentId:o.parentId,credentialKind:o.credentialKind,
      objectWorkspaceId:o.objectWorkspaceId,referenceOnly:o.referenceOnly,recovery:o.recovery.state,blockerCodes:o.recovery.blockerCodes,payload:this.secrets.redact(o.payload)}));
    return{entity:{...summary,capabilities},items,size:page.size,total:null,
      nextCursor:start+page.size<graph.objects.length?this.cursors.encode(binding,{offset:start+page.size}):null,capabilities};
  });}
  async exportSnapshot(cid:string,id:string,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    const source=await this.snapshotScope(cid,id,actor);if(!['review','deployment'].includes(body.mode))throw new BadRequestException({code:'INVALID_EXPORT_MODE'});
    if(body.mode==='deployment')configurationConfirm(body,source.row.name);
    const input={snapshotId:id,version:source.row.current_version,mode:body.mode},j=await this.newJob(cid,actor,{scope:source.scope.kind,serviceIds:source.scope.rootIds},'export',input);
    if(j.existing)return this.jobProjection(j.handle,j.job);
    let job:ConfigurationJobSummary;
    try{const graph=await this.repo.readSnapshot(j.handle,{scope:j.scope,snapshotId:id});await this.access.assertHistoricalGraph(j.handle,graph,body.mode==='deployment');
      const exported=serializeDeck11WithReport(graph,{mode:body.mode,redact:v=>this.secrets.redact(v)}),artifact=await this.repo.createExport(j.handle,{jobId:j.job.id,content:exported.yaml,
        mode:body.mode,format:'deck-1.1',expiresAt:expiry(),sourceSnapshotId:id,sourceVersion:source.row.current_version});
      job=await this.finish(j.handle,j.job.id,'succeeded',{exportId:artifact.id,sourceSnapshotId:id,format:'deck-1.1',mode:body.mode,confirmationName:source.row.name,formatOmissionCount:exported.formatOmissions.length,formatOmissions:exported.formatOmissions});
    }catch(error){await this.finish(j.handle,j.job.id,'failed',{},error);throw error;}
    // A response projection failure cannot undo or rewrite a committed export.
    // Its original job/key remains the sole recovery source.
    return this.jobProjection(j.handle,job);
  });}
  async download(cid:string,id:string,body:Record<string,any>,actor:EntityActor):Promise<{content:string;handle:ConfigurationAccessHandle;filename:string}>{return this.withActor(cid,actor,'read',async()=>{
    const ws=await this.workspaces.resolve(cid,actor.workspaceId),row=await this.db.one<any>(EXPORT_DOWNLOAD_QUERY,[configurationId(id),cid,ws.id,actor.user.id]);
    if(!row)throw new NotFoundException({code:'CONFIGURATION_EXPORT_NOT_FOUND'});
    if(body.revision!==row.export_revision)throw fail('CONFIGURATION_EXPORT_REVISION_CONFLICT');
    if(row.state!=='ready'||row.material_state!=='available'||new Date(row.expires_at).getTime()<=Date.now())throw fail('CONFIGURATION_EXPORT_UNAVAILABLE');
    const j=await this.newJob(cid,actor,{scope:row.scope_kind,serviceIds:row.root_ids},'export',{action:'download',exportId:id,mode:row.mode});
    if(j.existing)throw new ConflictException({code:'CONFIGURATION_DOWNLOAD_ALREADY_REQUESTED',message:'原下载请求已登记，请按原幂等键核验许可；文件不会重复发送',originalJobId:j.job.id});
    const {handle,scope}=j;try{
    if(row.source_snapshot_id){const source=await this.repo.readSnapshot(handle,{scope,snapshotId:row.source_snapshot_id,version:row.source_version});await this.access.assertHistoricalGraph(handle,source,row.mode==='deployment');
      const name=await this.db.one<any>('SELECT name FROM config_snapshots WHERE id=$1',[row.source_snapshot_id]);if(row.mode==='deployment')configurationConfirm(body,name.name);}
    const writeEvidence=(tx:DbService,e:ConfigurationDownloadEvidence)=>this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'configuration_exports',entityId:id,action:`configuration.download.${e.action}`,
      after:e,requestId:actor.requestId,ip:actor.ip,scopeHints:metadataAuditScope('snapshots','configuration_exports',id,ws.id)},tx).then(()=>undefined);
    // Permit consumption and the durable result share one transaction. A lost
    // file response cannot leave an unrecorded consumed permit or be replayed.
    const result=await this.db.transaction(async tx=>{
      const grant=await this.repo.issueDownloadGrant(handle,{scope,exportId:id,writeEvidence},tx),result=await this.repo.consumeDownloadGrant(handle,{scope,grantId:grant.id,token:grant.token,writeEvidence},tx);
      await this.access.assertCurrent(handle,{phase:'download'},tx);
      if(result.byteCount>32*1024*1024)throw new BadRequestException({code:'CONFIGURATION_DOWNLOAD_TOO_LARGE'});
      await this.repo.finishJob(handle,{jobId:j.job.id,state:'succeeded',safeProgress:{exportId:id,mode:row.mode,downloadGrantId:grant.id,downloadPermitConsumed:true,byteCount:result.byteCount,fileDeliveryUnconfirmed:true},writeEvidence:(t,b,a)=>this.auditJob(t,b,a)},tx);
      return result;
    });
    return{content:result.content,handle,filename:`configuration-${id}.yaml`};
    }catch(error){await this.finish(handle,j.job.id,'failed',{exportId:id,mode:row.mode,downloadPermitConsumed:false,fileDeliveryUnconfirmed:true},error);throw error;}
  });}
  private allocatedIds(document:ParsedDeckDocument):Record<string,string>{
    const result:Record<string,string>={},collections=new Set(['services','routes','consumers','plugins','upstreams','targets','certificates','ca_certificates','snis','keyauth_credentials','basicauth_credentials','jwt_secrets','oauth2_credentials','hmacauth_credentials','acls']);
    const visit=(value:unknown,path:string)=>{if(!value||typeof value!=='object'||Array.isArray(value))return;for(const [key,items]of Object.entries(value))if(collections.has(key)&&Array.isArray(items))items.forEach((item,i)=>{
      const child=path?`${path}.${key}[${i}]`:`${key}[${i}]`;if(item&&typeof item==='object'&&!Array.isArray(item)&&typeof item.id!=='string')result[child]=randomUUID();visit(item,child);});};visit(document.document,'');return result;
  }
  private async persistDiff(handle:ConfigurationAccessHandle,id:string,diff:TransferDiff,sourceHmac:string,originRef?:ConfigurationOriginRef):Promise<any>{
    if(diff.blockerCodes.length){const job=await this.finish(handle,id,'failed',{blockerCodes:diff.blockerCodes,changes:formatSafeDiff(diff,v=>this.secrets.redact(v))});return this.jobProjection(handle,job);}
    const stepIds=Object.fromEntries(diff.changes.map(c=>[c.objectKey,randomUUID()])),allocatedTargetIds=Object.fromEntries(diff.changes.filter(c=>c.entityType==='targets'&&c.action==='update').map(c=>[c.objectKey,randomUUID()]));
    const plan={...compileTransferDag(diff,{stepIds,allocatedTargetIds,sourceManifestHmac:sourceHmac,baselineManifestHmac:this.secrets.fingerprint(diff.baseline),expiresAt:expiry(),fingerprint:v=>this.secrets.fingerprint(v),redact:v=>this.secrets.redact(v)}),...(originRef?{originRef}:{})};
    if(originRef)await this.origins!.assertExecutionBudget(originRef,plan);
    const identity=await this.repo.freezePlan(handle,{jobId:id,plan});const job=await this.finish(handle,id,'succeeded',{...identity,baselineSnapshotId:diff.baseline.snapshotId,baselineVersion:1,
      stepCount:plan.steps.length,deleteCount:plan.steps.filter(s=>s.mutationAction==='delete').length,recoveryComplete:plan.recoveryComplete,
      sharedReferences:diff.referenceCount,counts:{create:diff.changes.filter(c=>c.action==='create').length,update:diff.changes.filter(c=>c.action==='update').length,delete:diff.changes.filter(c=>c.action==='delete').length,unchanged:diff.unchangedCount,conflict:0}});return this.jobProjection(handle,job);
  }
  installGovernancePromotionSourcePolicy(policy:ConfigurationPromotionSourcePolicy):void{if(!this.origins)throw fail('CONFIGURATION_ORIGIN_PROVIDER_UNAVAILABLE');this.origins.install(policy);}
  /** Server-owned locator only. Public import DTOs cannot select this path or origin. */
  async createGovernancePromotionPlan(locator:{promotionId:string;sourceClusterId:string;sourceWorkspaceId:string;targetClusterId:string;targetWorkspaceId:string},actor:EntityActor):Promise<any>{
    if(!this.origins)throw fail('CONFIGURATION_ORIGIN_PROVIDER_UNAVAILABLE');
    return this.origins.run(async()=>{
      const sourceParent=await this.db.one<any>('SELECT * FROM governance_promotions WHERE id=$1',[configurationId(locator.promotionId)]);
      if(!sourceParent||sourceParent.actor_id!==actor.user.id||sourceParent.cluster_id!==locator.sourceClusterId||sourceParent.workspace_id!==locator.sourceWorkspaceId||sourceParent.target_cluster_id!==locator.targetClusterId||sourceParent.target_workspace_id!==locator.targetWorkspaceId||sourceParent.state!=='planning')throw new ForbiddenException({code:'CONFIGURATION_ORIGIN_PARENT_INVALID'});
      try{
      const selection=this.secrets.decrypt<Record<string,any>>(sourceParent.selection_secret,`governance:promotion-selection:${sourceParent.id}`);
      if(this.secrets.fingerprint(selection)!==sourceParent.selection_hmac)throw fail('CONFIGURATION_ORIGIN_MATERIAL_INVALID');
      if(selection.includeSecrets===true||selection.includeCredentials===true)await this.withActor(locator.sourceClusterId,{...actor,workspaceId:locator.sourceWorkspaceId},'write',()=>this.capturePromotionRecovery(sourceParent,actor));
      return await this.origins!.runTargetPlanning(sourceParent.id,actor,()=>this.withActor(locator.targetClusterId,{...actor,workspaceId:locator.targetWorkspaceId},'write',async()=>{
      const parent=await this.db.one<any>('SELECT * FROM governance_promotions WHERE id=$1',[configurationId(locator.promotionId)]);
      if(!parent||parent.actor_id!==actor.user.id||parent.cluster_id!==locator.sourceClusterId||parent.workspace_id!==locator.sourceWorkspaceId||parent.target_cluster_id!==locator.targetClusterId||parent.target_workspace_id!==locator.targetWorkspaceId||parent.state!=='planning')throw new ForbiddenException({code:'CONFIGURATION_ORIGIN_PARENT_INVALID'});
      const privateBinding=await this.db.one<any>('SELECT * FROM promotion_recovery_bindings WHERE promotion_id=$1',[parent.id]);
      let targetBaseline:Awaited<ReturnType<ConfigurationService['captureBaseline']>>|undefined;
      if(privateBinding){
        await this.origins!.preparePromotion(parent.id,actor);
        const comparison=await this.db.one<any>('SELECT * FROM governance_comparisons WHERE id=$1',[parent.comparison_id]),target=decryptComparisonMaterial<ComparisonInventory>(comparison,this.secrets).target.inventory;
        const key=`governance-promote-${parent.id}`,targetActor={...actor,workspaceId:locator.targetWorkspaceId,idempotencyKey:key};
        targetBaseline=await this.captureBaseline(locator.targetClusterId,targetActor,{scope:target.scope.kind,serviceIds:target.scope.rootIds},this.internalKey(key,'baseline'),'环境发布执行前快照');
      }
      const material=await this.origins!.compile(parent.id,actor,targetBaseline?.graph);
      if(material.compiled.state==='blocked'){
        await this.db.transaction(async tx=>{const n=await tx.exec("UPDATE governance_promotions SET state='blocked',error_code=$2,updated_at=now() WHERE id=$1 AND state='planning' AND configuration_job_id IS NULL",[parent.id,material.compiled.blockers[0]?.code??'CONFIGURATION_ORIGIN_BLOCKED']);if(n!==1)throw fail('CONFIGURATION_ORIGIN_PARENT_CHANGED');
          await this.audit.append({actorId:actor.user.id,clusterId:parent.cluster_id,workspaceId:parent.workspace_id,entityType:'governance_promotions',entityId:parent.id,action:'governance.promote.plan.blocked',after:{blockerCodes:material.compiled.blockers.map(item=>item.code)},requestId:actor.requestId,ip:actor.ip,result:'failed',scopeHints:metadataAuditScope('promote','governance_promotions',parent.id,parent.workspace_id)},tx);});
        return{state:'blocked',nativeExecutionRequested:false};
      }
      const targetActor={...actor,workspaceId:locator.targetWorkspaceId,idempotencyKey:`governance-promote-${parent.id}`},body={scope:material.target.scope.kind,serviceIds:material.target.scope.rootIds},parsed=parseDeckDocument(material.compiled.yaml!);
      const input={mode:'merge',documentHmac:this.secrets.fingerprint(parsed.document),basicPasswordIntents:material.compiled.basicPasswordIntents},j=await this.newJob(locator.targetClusterId,targetActor,body,'import',input,targetActor.idempotencyKey,'snapshots',material.ref);
      if(j.existing)return this.jobProjection(j.handle,j.job);
      try{
        const artifact=await this.repo.freezeImport(j.handle,{jobId:j.job.id,document:{parsed,allocatedNativeIds:this.allocatedIds(parsed),basicPasswordIntents:material.compiled.basicPasswordIntents}});
        const baseline=targetBaseline??await this.captureBaseline(locator.targetClusterId,targetActor,body,this.internalKey(targetActor.idempotencyKey,'baseline'),'环境发布执行前快照'),codes=await this.workspaceCodes(locator.targetClusterId);
        const document=await this.repo.readImport<any>(j.handle,{jobId:j.job.id,artifactId:artifact.artifactId});
        const normalized=normalizeDeckDocument(document.parsed,baseline.graph.schemas,{scope:j.scope,workspaceCode:codes[j.scope.workspaceId],workspaceCodesById:codes,allocatedNativeIds:document.allocatedNativeIds,basicPasswordIntents:document.basicPasswordIntents,references:baseline.graph});
        const diff=diffTransferGraphs(baseline.graph,normalized,{mode:'merge'}),result=await this.persistDiff(j.handle,j.job.id,diff,this.secrets.fingerprint(document),material.ref);
        await this.settlePromotionPlanningFailure(parent.id,j.job.id,actor);return result;
      }catch(error){await this.finish(j.handle,j.job.id,'failed',{},error).catch(()=>undefined);await this.settlePromotionPlanningFailure(parent.id,j.job.id,actor);throw error;}
      }));
      }catch(error){await this.settlePromotionBeforeChild(sourceParent.id,actor,error).catch(()=>undefined);throw error;}
    });
  }
  private async settlePromotionBeforeChild(promotionId:string,actor:EntityActor,error:unknown):Promise<void>{
    // Only a confirmed local validation/authorization rejection with no
    // persisted child is terminal here. An unknown commit remains uncertain.
    if(!(error instanceof BadRequestException||error instanceof ForbiddenException||error instanceof ConflictException))return;
    await this.db.transaction(async tx=>{
      const parent=await tx.one<any>('SELECT * FROM governance_promotions WHERE id=$1 FOR UPDATE',[promotionId]);
      if(!parent||parent.actor_id!==actor.user.id||parent.state!=='planning'||parent.configuration_job_id||parent.plan_id)return;
      const child=await tx.one<any>('SELECT id FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND (idempotency_key=$4 OR required_origin_id=$5) LIMIT 1',
        [parent.target_cluster_id,parent.target_workspace_id,parent.actor_id,`governance-promote-${parent.id}`,parent.id]);
      if(child)return;
      const code=safeConfigurationError(error),n=await tx.exec("UPDATE governance_promotions SET state='blocked',error_code=$2,updated_at=now() WHERE id=$1 AND state='planning' AND configuration_job_id IS NULL AND plan_id IS NULL",[parent.id,code]);
      if(n!==1)throw fail('CONFIGURATION_ORIGIN_PARENT_CHANGED');
      await this.audit.append({actorId:actor.user.id,clusterId:parent.cluster_id,workspaceId:parent.workspace_id,entityType:'governance_promotions',entityId:parent.id,action:'governance.promote.plan.blocked',
        after:{state:'blocked',errorCode:code,nativeExecutionRequested:false},requestId:actor.requestId,ip:actor.ip,result:'failed',scopeHints:metadataAuditScope('promote','governance_promotions',parent.id,parent.workspace_id)},tx);
    });
  }
  private async capturePromotionRecovery(parent:any,actor:EntityActor):Promise<void>{
    if(await this.db.one('SELECT promotion_id FROM promotion_recovery_bindings WHERE promotion_id=$1',[parent.id]))return;
    const comparison=await this.db.one<any>('SELECT * FROM governance_comparisons WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3',[parent.comparison_id,parent.cluster_id,parent.workspace_id]);
    if(!comparison)throw fail('CONFIGURATION_ORIGIN_COMPARISON_INVALID');
    const source=decryptComparisonMaterial<ComparisonInventory>(comparison,this.secrets).source.inventory,sourceActor={...actor,workspaceId:parent.workspace_id,idempotencyKey:`governance-promote-source-${parent.id}`};
    const captured=await this.captureBaseline(parent.cluster_id,sourceActor,{scope:source.scope.kind,serviceIds:source.scope.rootIds},sourceActor.idempotencyKey,'环境发布源恢复材料');
    const graph=captured.graph,recoveryHash=this.origins!.recoveryHash(graph),manifestHash=this.secrets.fingerprint(graph);
    await this.db.transaction(async tx=>{
      await tx.exec('INSERT INTO promotion_recovery_bindings(promotion_id,source_cluster_id,source_workspace_id,source_job_id,snapshot_id,snapshot_version,manifest_hmac,recovery_hmac) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[parent.id,parent.cluster_id,parent.workspace_id,graph.jobId,captured.snapshotId,captured.version,manifestHash,recoveryHash]);
      await this.audit.append({actorId:actor.user.id,clusterId:parent.cluster_id,workspaceId:parent.workspace_id,entityType:'governance_promotions',entityId:parent.id,action:'governance.promote.recovery.sealed',after:{snapshotId:captured.snapshotId,snapshotVersion:captured.version},requestId:actor.requestId,ip:actor.ip,scopeHints:metadataAuditScope('promote','governance_promotions',parent.id,parent.workspace_id)},tx);
    });
  }
  private async settlePromotionPlanningFailure(promotionId:string,jobId:string,actor:EntityActor):Promise<void>{
    await this.db.transaction(async tx=>{
      const parent=await tx.one<any>('SELECT * FROM governance_promotions WHERE id=$1 FOR UPDATE',[promotionId]),job=await tx.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[jobId]);
      if(!parent||parent.state!=='planning'||!job||job.required_origin_kind!=='governance-promote'||job.required_origin_id!==parent.id||job.actor_id!==parent.actor_id
        ||job.cluster_id!==parent.target_cluster_id||job.workspace_id!==parent.target_workspace_id||job.kind!=='import'||!['failed','uncertain'].includes(job.state))return;
      const state=job.state==='uncertain'?'uncertain':'blocked',code=job.error_code??'CONFIGURATION_ORIGIN_TARGET_PLAN_BLOCKED';
      const n=await tx.exec("UPDATE governance_promotions SET state=$2,error_code=$3,configuration_job_id=$4,updated_at=now() WHERE id=$1 AND state='planning' AND plan_id IS NULL",[promotionId,state,code,jobId]);
      if(n!==1)throw fail('CONFIGURATION_ORIGIN_PARENT_CHANGED');
      await this.audit.append({actorId:actor.user.id,clusterId:parent.cluster_id,workspaceId:parent.workspace_id,entityType:'governance_promotions',entityId:promotionId,action:'governance.promote.plan.failed',after:{configurationJobId:jobId,state,errorCode:code},requestId:actor.requestId,ip:actor.ip,result:state==='uncertain'?'uncertain':'failed',scopeHints:metadataAuditScope('promote','governance_promotions',promotionId,parent.workspace_id)},tx);
    });
  }
  async importDocument(cid:string,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    if(typeof body.yaml!=='string'||!['merge','sync'].includes(body.mode))throw new BadRequestException({code:'INVALID_CONFIGURATION_IMPORT'});
    if(body.mode==='sync'&&body.confirm_deletes!==true)throw new BadRequestException({code:'CONFIRMATION_REQUIRED'});
    const parsed=parseDeckDocument(body.yaml),input={mode:body.mode,documentHmac:this.secrets.fingerprint(parsed.document),basicPasswordIntents:body.basicPasswordIntents??{}};
    const j=await this.newJob(cid,actor,body,'import',input);if(j.existing)return this.jobProjection(j.handle,j.job);
    try{const artifact=await this.repo.freezeImport(j.handle,{jobId:j.job.id,document:{parsed,allocatedNativeIds:this.allocatedIds(parsed),basicPasswordIntents:body.basicPasswordIntents??{}}});
      const baseline=await this.captureBaseline(cid,actor,body,this.internalKey(actor.idempotencyKey!,'baseline'),'导入执行前快照'),codes=await this.workspaceCodes(cid);
      const document=await this.repo.readImport<any>(j.handle,{jobId:j.job.id,artifactId:artifact.artifactId});
      const normalized=normalizeDeckDocument(document.parsed,baseline.graph.schemas,{scope:j.scope,workspaceCode:codes[j.scope.workspaceId],workspaceCodesById:codes,allocatedNativeIds:document.allocatedNativeIds,basicPasswordIntents:document.basicPasswordIntents,references:baseline.graph});
      const diff=diffTransferGraphs(baseline.graph,normalized,{mode:body.mode,syncConfirmed:body.confirm_deletes===true});return this.persistDiff(j.handle,j.job.id,diff,this.secrets.fingerprint(document));
    }catch(error){await this.finish(j.handle,j.job.id,'failed',{},error);throw error;}
  });}
  async createToolboxBatchPlan(cid:string,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const selection=validateBatchSelection(body),ws=await this.workspaces.resolve(cid,actor.workspaceId);
    await this.authz.assertCluster(actor.user,cid,'batches','write',ws.id);
    const value={scope:'workspace'},input={toolboxBatch:selection},job=await this.newJob(cid,actor,value,'import',input);
    const recordBatch=async()=>{
      const latest=await this.repo.getJob(job.handle,job.job.id);
      if(latest.state!=='succeeded'||typeof latest.safeProgress.planId!=='string')return;
      await this.db.transaction(async tx=>{
        const inserted=await tx.one<any>('INSERT INTO toolbox_batches(id,cluster_id,workspace_id,actor_id,configuration_job_id,plan_id,kind,selection_hmac,selected_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(configuration_job_id) DO NOTHING RETURNING id',[randomUUID(),cid,ws.id,actor.user.id,job.job.id,latest.safeProgress.planId,selection.action,this.secrets.fingerprint(selection.roots),selection.roots.length]);
        if(inserted)await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'toolbox_batches',entityId:inserted.id,action:'toolbox.batch.plan',requestId:actor.requestId,ip:actor.ip,after:{configurationJobId:job.job.id,planId:latest.safeProgress.planId,kind:selection.action,selectedCount:selection.roots.length},result:'success'},tx);
      });
    };
    if(job.existing){await recordBatch();return this.jobProjection(job.handle,job.job);}
    try{
      const baseline=await this.captureBaseline(cid,actor,value,this.internalKey(actor.idempotencyKey!,'toolbox-baseline'),'批量变更执行前快照'),codes=await this.workspaceCodes(cid);
      const target=toolboxBatchTarget(baseline.graph,selection,codes),diff=diffTransferGraphs(baseline.graph,target,{mode:selection.action==='delete'?'sync':'merge',syncConfirmed:selection.action==='delete'});
      const result=await this.persistDiff(job.handle,job.job.id,diff,this.secrets.fingerprint(selection));await recordBatch();
      return result;
    }catch(error){const current=await this.repo.getJob(job.handle,job.job.id);if(current.state!=='succeeded')await this.finish(job.handle,job.job.id,'failed',{},error);throw error;}
  });}
  async compareSnapshots(cid:string,id:string,otherId:string,actor:EntityActor,view:'configuration'|'schema'='configuration'):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    const source=await this.snapshotScope(cid,id,actor),other=await this.snapshotScope(cid,otherId,actor);
    if(canonicalJson(source.scope)!==canonicalJson(other.scope))throw fail('CONFIGURATION_COMPARE_SCOPE_MISMATCH');
    const a=await this.repo.readSnapshot(source.handle,{scope:source.scope,snapshotId:id}),b=await this.repo.readSnapshot(other.handle,{scope:other.scope,snapshotId:otherId});
    await this.access.assertHistoricalGraph(source.handle,a);await this.access.assertHistoricalGraph(other.handle,b);
    if(view==='schema')return{schemaComparison:compareCapturedSchemas(a.schemas,b.schemas),readOnly:true};
    const diff=diffTransferGraphs(a,normalizeCaptureGraph(b,await this.workspaceCodes(cid)),{mode:'sync',syncConfirmed:true});return{changes:formatSafeDiff(diff,v=>this.secrets.redact(v)),blockerCodes:diff.blockerCodes,readOnly:true};
  });}
  async rollbackPreview(cid:string,id:string,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',async()=>{
    const source=await this.snapshotScope(cid,id,actor),value={scope:source.scope.kind,serviceIds:source.scope.rootIds},input={snapshotId:id,version:source.row.current_version,action:'rollback-preview'};
    configurationConfirm(body,source.row.name,true);if(body.revision!==source.row.revision)throw fail('SNAPSHOT_REVISION_CONFLICT');
    const j=await this.newJob(cid,actor,value,'compare',input);if(j.existing)return this.jobProjection(j.handle,j.job);
    try{const target=await this.repo.readSnapshot(j.handle,{scope:j.scope,snapshotId:id});await this.access.assertHistoricalGraph(j.handle,target,true);
      const normalized=normalizeCaptureGraph(target,await this.workspaceCodes(cid)),requiredPluginSchemas=normalized.objects.filter(object=>object.entityType==='plugins').map(object=>object.payload.name as string);
      const baseline=await this.captureBaseline(cid,actor,value,this.internalKey(actor.idempotencyKey!,'rollback-baseline'),'回滚执行前快照',requiredPluginSchemas);
      const diff=diffTransferGraphs(baseline.graph,normalized,{mode:'rollback',syncConfirmed:true,rollbackBaselineVerified:true});
      return this.persistDiff(j.handle,j.job.id,diff,this.secrets.fingerprint(target));
    }catch(error){await this.finish(j.handle,j.job.id,'failed',{},error);throw error;}
  });}
  async plan(cid:string,id:string,query:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    if(this.origins)await this.origins.preparePlan(id,actor);
    const ws=await this.workspaces.resolve(cid,actor.workspaceId),row=await this.db.one<any>('SELECT p.*,j.scope_kind,j.root_ids,j.authority_domain,j.durable_issue_id FROM configuration_plans p JOIN configuration_jobs j ON j.id=p.source_job_id WHERE p.id=$1 AND p.cluster_id=$2 AND p.workspace_id=$3',[configurationId(id),cid,ws.id]);
    if(!row)throw new NotFoundException({code:'CONFIGURATION_PLAN_NOT_FOUND'});const {handle,scope}=await this.scopeHandle(cid,actor,{scope:row.scope_kind,serviceIds:row.root_ids},'compare');
    const summary=await this.repo.readPlanSummary(handle,{scope,planId:id});const manifest=await this.repo.readPlan(handle,{scope,planId:id,planRevision:summary.planRevision as number,planHash:summary.planHash as string});
    await this.assertPlanGrants(handle,manifest);const page=configurationPage(query);
    const changes=await this.repo.listChanges(handle,{scope,planId:id,planRevision:summary.planRevision as number,planHash:summary.planHash as string,...page});
    const cluster=await this.db.one<any>('SELECT execution_mode FROM clusters WHERE id=$1',[cid]),source=await this.db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[row.source_job_id]);
    const writable=manifest.recoveryComplete&&Date.parse(manifest.expiresAt)>Date.now()&&await this.planWritable(handle,manifest);
    const disposition=await this.sourceSubmissionBlocker(row.id,cid,ws.id);
    const blocked=disposition??this.durable?.unsupportedReason(manifest)??null;
    const capabilities={apply:!disposition&&row.authority_domain==null&&row.durable_issue_id==null&&writable,reconcile:true,durableSubmit:!blocked&&!!this.durable&&writable&&cluster.execution_mode==='approval'&&source.actor_id===actor.user.id&&await this.durable.canSubmit(handle,source,manifest,actor),durableSubmitReason:blocked?.message??null,durableSubmitBlockerCode:blocked?.code??null};
    await this.access.assertCurrent(handle,{phase:'read'});
    return{entity:{...summary,name:`配置计划 ${id}`,clusterId:cid,workspaceId:ws.id,scope:row.scope_kind,executionMode:cluster.execution_mode,approvalRequired:cluster.execution_mode==='approval',
      authorityDomain:source.authority_domain??'legacy-http-v1',durableIssueId:source.durable_issue_id??null,workflowId:source.workflow_id??null,expiresAt:manifest.expiresAt,counts:source.safe_progress.counts,baselineSnapshotId:source.safe_progress.baselineSnapshotId,sharedReferences:source.safe_progress.sharedReferences,blockers:[],deleteConfirmName:summary.deleteCount?`DELETE ${summary.deleteCount}`:null,capabilities},
      ...changes,items:changes.items.map(c=>{const step=manifest.steps.find(s=>s.stepId===c.stepId)!;return{...c,action:c.mutationAction,patch:c.diff,clearMap:step.clearMap,dependencies:step.dependencies,recovery:manifest.recoveryComplete?'complete':null};}),capabilities};
  });}
  /** Source IDs come only from the already authorized, decrypted plan. An
   * old source's permanent disposition applies to every reader/session/tab;
   * it reveals no submission owner/key or derivative job/plan identity. */
  private async sourceSubmissionBlocker(planId:string,cid:string,wid:string):Promise<Readonly<{code:string;message:string}>|null>{
    const row=await this.db.one<any>(CONFIGURATION_SOURCE_SUBMISSION_DISPOSITION_QUERY,[configurationId(planId),configurationId(cid),configurationId(wid)]);
    if(!row||typeof row.rejected!=='boolean'||typeof row.registered!=='boolean'||row.rejected&&row.registered)throw fail('CONFIGURATION_SOURCE_DISPOSITION_UNAVAILABLE');
    if(row.rejected)return Object.freeze({code:'CONFIGURATION_DURABLE_SOURCE_REJECTED',message:'当前配置已变化，原计划已拒绝，请重新预览后创建配置工单'});
    if(row.registered)return Object.freeze({code:'CONFIGURATION_DURABLE_SOURCE_ALREADY_SUBMITTED',message:'原计划已创建配置工单，请核验原请求并查看对应工单'});
    return null;
  }
  private async planWritable(handle:ConfigurationAccessHandle,manifest:ConfigPlan):Promise<boolean>{
    const s=await this.access.description(handle),module=manifest.scope.kind==='cluster'?await this.authz.hasWholeCluster(s.actor,s.scope.clusterId,'snapshots','write'):await this.authz.hasWholeWorkspace(s.actor,s.scope.clusterId,s.scope.workspaceId,'snapshots','write');
    if(!module)return false;try{await this.assertPlanGrants(handle,manifest,true);return true;}catch(e){if(e instanceof ForbiddenException)return false;throw e;}
  }
  async reconcilePlan(cid:string,id:string,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    if(this.origins)await this.origins.preparePlan(id,actor);
    const summary=(await this.plan(cid,id,{},actor)).entity;if(body.revision!==summary.revision||body.planHash!==summary.planHash)throw fail('CONFIGURATION_PLAN_CHANGED');
    const source=await this.db.one<any>('SELECT j.scope_kind,j.root_ids,j.required_origin_kind,j.required_origin_id,j.required_origin_hmac FROM configuration_plans p JOIN configuration_jobs j ON j.id=p.source_job_id WHERE p.id=$1 AND p.cluster_id=$2 AND p.workspace_id=$3',[id,cid,summary.workspaceId]);
    const originRef=source.required_origin_kind?{version:1 as const,kind:source.required_origin_kind,originId:source.required_origin_id,materialHmac:source.required_origin_hmac}:undefined;
    const j=await this.newJob(cid,actor,{scope:source.scope_kind,serviceIds:source.root_ids},'reconcile',{action:'observe',planId:id,planRevision:summary.planRevision,planHash:summary.planHash},actor.idempotencyKey,'snapshots',originRef);
    if(j.existing)return this.jobProjection(j.handle,j.job);
    try{const plan=await this.repo.readPlan(j.handle,{scope:j.scope,planId:id,planRevision:summary.planRevision,planHash:summary.planHash});await this.assertPlanGrants(j.handle,plan);
      const observations=await this.access.runRead(j.handle,[],async()=>{const items=[];for(const step of plan.steps){
        const effective=step.mutationAction==='create'||step.entityType==='targets'&&step.mutationAction==='update'?step.allocatedNativeId:step.nativeId;
        const path=step.entityType==='credentials'?`/consumers/${step.parentId}/${step.credentialKind}/${effective}`:step.entityType==='targets'?`/upstreams/${step.parentId}/targets/${effective}`:`/${step.entityType}/${effective}`;
        let raw:any=null;try{raw=await this.kong.request<any>(cid,'GET',path);await this.access.assertObject(j.handle,{entityType:step.entityType,nativeId:effective!,payload:raw,parentId:step.parentId??undefined,credentialKind:step.credentialKind??undefined,secrets:false});}
        catch(error){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;}
        const expected=step.mutationAction==='delete'?null:{...(step.body??{}),id:effective};
        const matches=expected===null?raw===null:raw!==null&&Object.entries(expected).every(([key,value])=>canonicalJson(raw[key]??null)===canonicalJson(value??null));
        items.push({planStepId:step.stepId,type:step.credentialKind??step.entityType,action:step.mutationAction,originalId:step.nativeId??null,effectiveId:effective,present:raw!==null,expectedFieldsMatch:matches,
          causalOutcomeUnproven:true,observedAt:new Date().toISOString()});}return items;});
      const job=await this.finish(j.handle,j.job.id,'succeeded',{reconciledPlanId:id,readOnly:true,executionChanged:false,observations});return this.jobProjection(j.handle,job);
    }catch(error){await this.finish(j.handle,j.job.id,'failed',{reconciledPlanId:id,readOnly:true,executionChanged:false},error);throw error;}
  });}
  private async assertPlanGrants(handle:ConfigurationAccessHandle,plan:ConfigPlan,write=false,secretsRequired=false):Promise<void>{
    const state=await this.access.description(handle),snapshot=await this.authz.snapshot(state.actor);
    const version=await this.db.one<any>('SELECT j.safe_progress FROM configuration_jobs j JOIN configuration_plans p ON p.source_job_id=j.id WHERE p.id=(SELECT id FROM configuration_plans WHERE cluster_id=$1 AND workspace_id=$2 AND id IN(SELECT plan_id FROM configuration_plan_versions WHERE plan_hash=$3) LIMIT 1)',[state.scope.clusterId,state.scope.workspaceId,this.secrets.fingerprint(plan)]);
    if(!version?.safe_progress?.baselineSnapshotId)throw fail('CONFIGURATION_BASELINE_NOT_READY');
    const baseline=await this.repo.readSnapshot(handle,{scope:state.scope,snapshotId:version.safe_progress.baselineSnapshotId,version:version.safe_progress.baselineVersion}),objects=[...baseline.objects];
    const object=(step:ConfigPlan['steps'][number],payload:any):CaptureObject=>({...baseline.objects.find(o=>o.objectKey===step.objectKey),objectKey:step.objectKey,entityType:step.entityType,nativeId:step.nativeId??step.allocatedNativeId!,
      parentId:step.parentId??undefined,credentialKind:step.credentialKind??undefined,objectWorkspaceId:step.objectWorkspaceId,payload,ownershipTags:payload.tags??baseline.objects.find(o=>o.objectKey===step.objectKey)?.ownershipTags??[],
      affected:true,referenceOnly:step.referenceOnly,dependencies:[],beforeHmac:step.beforeHmac,schemaHmac:plan.schemaHmac,observedAt:new Date().toISOString(),recovery:{state:'complete',blockerCodes:[]}});
    // Parent candidates are drawn solely from this sealed plan, never HTTP overrides.
    for(const step of plan.steps)if(step.body&&step.mutationAction!=='delete'){const candidate=object(step,{...(step.before as any??{}),...step.body,id:step.allocatedNativeId??step.nativeId});const at=objects.findIndex(o=>o.objectKey===candidate.objectKey);if(at<0)objects.push(candidate);else objects[at]=candidate;}
    for(const step of plan.steps){
      if(snapshot.user.superAdmin)continue;
      if(step.before&&!historicalConfigurationAllowed(snapshot.grants,state.scope.clusterId,object(step,step.before),baseline.objects,write?step.permissionAction:'read'))throw new ForbiddenException({code:'CONFIGURATION_PLAN_ENTITY_DENIED'});
      if(step.body&&step.mutationAction!=='delete'&&!historicalConfigurationAllowed(snapshot.grants,state.scope.clusterId,object(step,{...(step.before as any??{}),...step.body,id:step.allocatedNativeId??step.nativeId}),objects,write?'write':'read'))throw new ForbiddenException({code:'CONFIGURATION_PLAN_ENTITY_DENIED'});
      if(secretsRequired&&step.body&&step.mutationAction!=='delete'){
        const candidate=object(step,{...(step.before as any??{}),...step.body,id:step.allocatedNativeId??step.nativeId});
        if(canonicalJson(this.secrets.redact(candidate.payload))!==canonicalJson(candidate.payload))await this.authz.assertSecretRead(state.actor,state.scope.clusterId,step.credentialKind??step.entityType,{...candidate.payload,tags:candidate.ownershipTags},step.objectWorkspaceId);
      }
    }
    await this.access.assertCurrent(handle,{phase:'read'});
  }
  async apply(cid:string,id:string,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',()=>this.redis.withLock(`configuration-source-plan:${configurationId(id)}`,async()=>{
    if(this.durable&&await this.db.one('SELECT job_id FROM configuration_durable_issues WHERE cluster_id=$1 AND source_plan_id=$2',[cid,id]))throw new ForbiddenException({code:'CONFIGURATION_DURABLE_ALREADY_SUBMITTED'});
    if(body.driver!==undefined&&!['bff','deck'].includes(body.driver))throw new BadRequestException({code:'CONFIGURATION_DRIVER_UNAVAILABLE'});
    // Keep the original source read authority anchored to this live executor
    // frame. The nested public plan read reuses it and its cumulative budget.
    if(this.origins)await this.origins.preparePlan(id,actor);
    const detail=await this.plan(cid,id,{},actor),summary=detail.entity;configurationConfirm(body,summary.name,summary.deleteCount>0);
    if(body.planHash!==summary.planHash||body.planRevision!==summary.planRevision)throw fail('CONFIGURATION_PLAN_CHANGED');
    const source=await this.db.one<any>('SELECT j.* FROM configuration_plans p JOIN configuration_jobs j ON j.id=p.source_job_id WHERE p.id=$1',[id]);
    if(source.authority_domain!=null||source.durable_issue_id!=null)throw new ForbiddenException({code:'CONFIGURATION_DURABLE_ALREADY_SUBMITTED'});
    if(body.driver==='deck'&&summary.executionMode!=='direct')throw new ForbiddenException({code:'CONFIGURATION_DECK_APPROVAL_DRIVER_DENIED',message:'审批模式须由原工单执行封存的 BFF 计划'});
    const originRef=source.required_origin_kind?{version:1 as const,kind:source.required_origin_kind,originId:source.required_origin_id,materialHmac:source.required_origin_hmac}:undefined;
    if(originRef&&body.driver==='deck')throw new ForbiddenException({code:'CONFIGURATION_ORIGIN_DECK_DRIVER_DENIED'});
    const value={scope:source.scope_kind,serviceIds:source.root_ids},j=await this.newJob(cid,actor,value,summary.mode==='rollback'?'rollback':'apply',{planId:id,planRevision:summary.planRevision,planHash:summary.planHash,driver:body.driver??'bff',confirmed:true,confirm_deletes:body.confirm_deletes===true},actor.idempotencyKey,'snapshots',originRef);
    if(j.existing)return this.jobProjection(j.handle,j.job);
    try{
    const original=await this.repo.readPlan(j.handle,{scope:j.scope,planId:id,planRevision:summary.planRevision,planHash:summary.planHash});await this.assertPlanGrants(j.handle,original,true);
    const identity=await this.repo.freezePlan(j.handle,{jobId:j.job.id,plan:original});
    await this.repo.initializeExecutionProgress(j.handle,{identity,revision:j.job.revision+1,safeProgress:{...source.safe_progress,driver:body.driver??'bff'}});
    const cluster=await this.db.one<any>('SELECT execution_mode FROM clusters WHERE id=$1',[cid]);
    if(cluster.execution_mode==='approval'){await this.createWrapper(j.handle,j.job.id,identity,actor);return this.jobProjection(j.handle,await this.repo.getJob(j.handle,j.job.id));}
    if(body.driver==='deck')return await this.startDeckExecution(j.handle,j.job.id);
    return await this.executeJob(j.handle,j.job.id,actor);
    }catch(error){await this.failUnfinishedExecution(j.job.id,error);throw error;}
  }));}
  private async assertDurableAllocationsAbsent(handle:ConfigurationAccessHandle,plan:ConfigPlan):Promise<void>{
    const creates=plan.steps.filter(step=>step.mutationAction==='create'||step.entityType==='targets'&&step.mutationAction==='update');
    const paths=creates.map(step=>step.entityType==='credentials'?`/consumers/${step.parentId}/${step.credentialKind}/${step.allocatedNativeId}`:
      step.entityType==='targets'?`/upstreams/${step.parentId}/targets/${step.allocatedNativeId}`:`/${step.entityType}/${step.allocatedNativeId}`);
    if(!paths.length)return;
    await this.access.runRead(handle,paths,async()=>{for(const path of paths){
      try{await this.kong.request(plan.scope.clusterId,'GET',path);}
      catch(error){if(error instanceof HttpException&&error.getStatus()===404)continue;throw error;}
      throw fail('CONFIGURATION_DURABLE_NATIVE_ALLOCATION_EXISTS');
    }});
  }
  private async persistDurableCompilation(tx:DbService,input:Parameters<ConfigurationDurablePublicationWriter['persist']>[1]):Promise<{identity:import('./configuration.types').ConfigurationPlanIdentity;workflow:WorkflowPlanV1}>{
    const {plan,baseline,actor,jobId}=input,cid=plan.scope.clusterId,ws={id:plan.scope.workspaceId};
      const identity=await this.repo.freezePlan(input.handle,{jobId,plan},tx);
      await this.repo.initializeExecutionProgress(input.handle,{identity,revision:2,safeProgress:{baselineSnapshotId:baseline.snapshotId,baselineVersion:1,driver:'bff',
        authorityDomain:'durable-configuration-v1',durableIssueId:input.issueId,sourcePlanId:input.sourcePlanId,expiresAt:input.expiresAt,stepCount:plan.steps.length,deleteCount:plan.steps.filter(step=>step.mutationAction==='delete').length,recoveryComplete:plan.recoveryComplete}},tx);
      await this.assertDurableCompilationGrants(actor,plan,baseline,tx);
      const workflow=await this.createWrapper(input.handle,jobId,identity,actor,tx,input.expiresAt);
      await this.audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:ws.id,entityType:'configuration_jobs',entityId:jobId,workflowId:workflow.workflowId,
        action:'configuration.durable.submitted',after:{issueId:input.issueId,...identity,sourcePlanId:input.sourcePlanId,expiresAt:input.expiresAt},requestId:actor.requestId,ip:actor.ip,
        scopeHints:metadataAuditScope('snapshots','configuration_jobs',jobId,ws.id)},tx);
      await this.assertDurableCompilationGrants(actor,plan,baseline,tx);
      return{identity,workflow};
  }
  private async assertDurableCompilationGrants(actor:EntityActor,plan:ConfigPlan,baseline:CaptureGraph,tx?:DbService):Promise<void>{
    const snapshot=await this.authz.snapshot(actor.user,tx),objects=[...baseline.objects];
    const projected=(step:ConfigPlan['steps'][number],payload:any):CaptureObject=>({...baseline.objects.find(o=>o.objectKey===step.objectKey),
      objectKey:step.objectKey,entityType:step.entityType,nativeId:step.nativeId??step.allocatedNativeId!,parentId:step.parentId??undefined,
      credentialKind:step.credentialKind??undefined,objectWorkspaceId:step.objectWorkspaceId,payload,ownershipTags:payload.tags??baseline.objects.find(o=>o.objectKey===step.objectKey)?.ownershipTags??[],
      affected:true,referenceOnly:false,dependencies:step.dependencies,beforeHmac:step.beforeHmac,schemaHmac:plan.schemaHmac,observedAt:baseline.observedUntil,recovery:{state:'complete',blockerCodes:[]}});
    for(const step of plan.steps)if(step.body&&step.mutationAction!=='delete'){
      const o=projected(step,{...(step.before as any??{}),...step.body,id:step.allocatedNativeId??step.nativeId}),at=objects.findIndex(x=>x.objectKey===o.objectKey);
      if(at<0)objects.push(o);else objects[at]=o;
    }
    if(snapshot.user.superAdmin)return;
    const canSecret=(o:CaptureObject)=>snapshot.grants.some(g=>grantMatchesEntity(g,'secrets','read',{clusterId:plan.scope.clusterId,workspaceId:o.objectWorkspaceId,
      entityType:o.credentialKind??o.entityType,entity:{...o.payload,tags:[...o.ownershipTags]}}));
    for(const o of baseline.objects)if(!historicalConfigurationAllowed(snapshot.grants,plan.scope.clusterId,o,baseline.objects)
      ||canonicalJson(this.secrets.redact(o.payload))!==canonicalJson(o.payload)&&!canSecret(o))throw new ForbiddenException({code:'CONFIGURATION_DURABLE_CURRENT_GRANTS_REQUIRED'});
    for(const step of plan.steps){
      if(step.before&&!historicalConfigurationAllowed(snapshot.grants,plan.scope.clusterId,projected(step,step.before),baseline.objects,step.permissionAction))throw new ForbiddenException({code:'CONFIGURATION_DURABLE_CURRENT_GRANTS_REQUIRED'});
      if(step.body&&step.mutationAction!=='delete'){
        const o=projected(step,{...(step.before as any??{}),...step.body,id:step.allocatedNativeId??step.nativeId});
        if(!historicalConfigurationAllowed(snapshot.grants,plan.scope.clusterId,o,objects,'write')||canonicalJson(this.secrets.redact(o.payload))!==canonicalJson(o.payload)&&!canSecret(o))throw new ForbiddenException({code:'CONFIGURATION_DURABLE_CURRENT_GRANTS_REQUIRED'});
      }
    }
  }
  /** A fresh material issue re-captures and re-compiles before a new approval.
   * The old input is provenance; no old J/P/W/Claim is updated or continued. */
  async submitDurable(cid:string,id:string,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',()=>this.redis.withLock(`configuration-source-plan:${configurationId(id)}`,async()=>{
    if(!Number.isSafeInteger(body.planRevision)||body.planRevision<1||typeof body.planHash!=='string'||!/^([a-f\d]{64})$/.test(body.planHash))throw new BadRequestException({code:'INVALID_CONFIGURATION_PLAN_IDENTITY'});
    if(!this.durable)throw new ForbiddenException({code:'CONFIGURATION_DURABLE_PROVIDER_UNAVAILABLE'});
    const ws=await this.workspaces.resolve(cid,actor.workspaceId),key=configurationKey(actor.idempotencyKey);
    const rejected=await this.durable.rejectionReceipt(key,actor,cid,ws.id);
    if(rejected){
      if(rejected.fact.sourcePlanId!==id||rejected.fact.sourcePlanRevision!==body.planRevision||rejected.fact.sourcePlanHash!==body.planHash)throw fail('IDEMPOTENCY_CONFLICT');
      await this.assertDurableRejectionReadable(rejected,actor,cid);
      throw new ConflictException({code:DURABLE_REJECTION_CODE,receipt:rejected.receipt});
    }
    const old=await this.durable.receipt(id,key,actor,cid,ws.id,body.planRevision,body.planHash);
    if(old){const reader=await this.access.acquireReceipt(old);return this.jobProjection(reader,await this.repo.getJob(reader,old));}
    const source=await this.db.one<any>(`SELECT j.* FROM configuration_plans p JOIN configuration_jobs j ON j.id=p.source_job_id
      WHERE p.id=$1 AND p.cluster_id=$2 AND p.workspace_id=$3 AND p.state='ready' AND p.current_revision=$4 AND j.plan_hash=$5`,[id,cid,ws.id,body.planRevision,body.planHash]);
    if(!source||source.required_origin_kind!=null||source.required_origin_id!=null||source.required_origin_hmac!=null)throw new ForbiddenException({code:'CONFIGURATION_DURABLE_SOURCE_UNAVAILABLE'});
    const input=source.input_secret?this.secrets.decrypt<any>(source.input_secret,`configuration-job:${source.id}`):null;
    const rollback=source.kind==='compare'&&input?.action==='rollback-preview';
    const value={scope:source.scope_kind,serviceIds:source.root_ids},j=await this.scopeHandle(cid,actor,value,rollback?'rollback':'apply',rollback?'rollback':'apply',key);
    const original=await this.repo.readPlan(j.handle,{scope:j.scope,planId:id,planRevision:body.planRevision,planHash:body.planHash});
    await this.assertPlanGrants(j.handle,original,true,true);configurationConfirm(body,`配置计划 ${id}`,original.steps.some(step=>step.mutationAction==='delete'));
    const admission=await this.durable.begin(j.handle,source,original,actor,key),d=this.durable.describe(admission);
    let recipe:any,normalized:any,baseline:Awaited<ReturnType<ConfigurationService['captureBaseline']>>;
    if(d.sourceKind==='import'){
      const artifact=await this.db.one<any>('SELECT artifact_id FROM configuration_imports WHERE cluster_id=$1 AND workspace_id=$2 AND job_id=$3',[cid,ws.id,source.id]);
      if(!artifact)throw fail('CONFIGURATION_DURABLE_RECIPE_UNAVAILABLE');
      const sourceReader=await this.access.acquireReadJob(source.id);recipe=await this.repo.readImport<any>(sourceReader,{jobId:source.id,artifactId:artifact.artifact_id});
      if(this.secrets.fingerprint(recipe)!==original.sourceManifestHmac)throw fail('CONFIGURATION_DURABLE_RECIPE_CHANGED');
      const required:string[]=[];const plugins=(value:any):void=>{if(!value||typeof value!=='object')return;if(Array.isArray(value)){for(const child of value)plugins(child);return;}for(const [name,child]of Object.entries(value)){if(name==='plugins'&&Array.isArray(child))for(const plugin of child)if(typeof plugin?.name==='string')required.push(plugin.name);plugins(child);}};plugins(recipe.parsed.document);
      baseline=await this.captureBaseline(cid,actor,value,this.internalKey(key,'durable-baseline'),'配置工单执行前快照',required);
      const codes=await this.workspaceCodes(cid);normalized=normalizeDeckDocument(recipe.parsed,baseline.graph.schemas,{scope:j.scope,workspaceCode:codes[j.scope.workspaceId],
        workspaceCodesById:codes,allocatedNativeIds:recipe.allocatedNativeIds,basicPasswordIntents:recipe.basicPasswordIntents,references:baseline.graph});
    }else{
      const target=await this.repo.readSnapshot(j.handle,{scope:j.scope,snapshotId:configurationId(input.snapshotId),version:input.version});
      await this.access.assertHistoricalGraph(j.handle,target,true);recipe=target;normalized=normalizeCaptureGraph(target,await this.workspaceCodes(cid));
      const required=normalized.objects.filter((o:any)=>o.entityType==='plugins').map((o:any)=>o.payload.name as string);
      baseline=await this.captureBaseline(cid,actor,value,this.internalKey(key,'durable-baseline'),'回滚工单执行前快照',required);
    }
    const diff=diffTransferGraphs(baseline.graph,normalized,{mode:rollback?'rollback':input.mode,syncConfirmed:rollback||body.confirm_deletes===true,rollbackBaselineVerified:rollback});
    if(diff.blockerCodes.length||!diff.changes.length)throw fail(diff.blockerCodes[0]??'CONFIGURATION_DURABLE_EMPTY_PLAN');
    const steps=Object.fromEntries(diff.changes.map(change=>[change.objectKey,randomUUID()])),targets=Object.fromEntries(diff.changes.filter(change=>change.entityType==='targets'&&change.action==='update').map(change=>[change.objectKey,original.steps.find(step=>step.objectKey===change.objectKey&&step.entityType==='targets'&&step.mutationAction==='update')?.allocatedNativeId??randomUUID()]));
    const plan:ConfigPlan={...compileTransferDag(diff,{stepIds:steps,allocatedTargetIds:targets,sourceManifestHmac:this.secrets.fingerprint(recipe),baselineManifestHmac:this.secrets.fingerprint(baseline.graph),
      expiresAt:d.expiresAt,fingerprint:v=>this.secrets.fingerprint(v),redact:v=>this.secrets.redact(v)}),durableRef:{version:1,domain:'durable-configuration-v1',issueId:d.issueId}};
    try{assertDurableConfigurationEquivalent(original,plan,this.secrets);}catch(error){
      if(!(error instanceof ConflictException)||(error.getResponse()as any)?.code!==DURABLE_REJECTION_CODE)throw error;
      await this.assertDurableCompilationGrants(actor,plan,baseline.graph);
      const receipt=await this.durable.rejectFreshDiff(admission,plan,baseline.graph,this.secrets.fingerprint(recipe));
      throw new ConflictException({code:DURABLE_REJECTION_CODE,message:'当前配置已变化，请重新预览后创建配置工单',receipt});
    }
    await this.assertDurableAllocationsAbsent(j.handle,plan);
    if(baseline.graph.objects.some(object=>object.recovery.absoluteExpiresAt!=null&&Date.parse(object.recovery.absoluteExpiresAt)<=Date.parse(d.expiresAt)))throw fail('CONFIGURATION_DURABLE_SECRET_EXPIRES_BEFORE_WINDOW');
    await this.assertDurableCompilationGrants(actor,plan,baseline.graph);
    const completed=await this.durable.publish(admission,plan,baseline.graph,this.secrets.fingerprint(recipe));
    const reader=await this.access.acquireReceipt(completed.jobId);return this.jobProjection(reader,await this.repo.getJob(reader,completed.jobId));
  }));}
  /** Finalizes only an actually unfinished attempt, from persisted step states.
   * It never repeats a native packet or changes an existing terminal result. */
  private async failUnfinishedExecution(jobId:string,error:unknown):Promise<void>{
    try{const row=await this.db.one<any>('SELECT state,safe_progress FROM configuration_jobs WHERE id=$1',[jobId]);
      if(!row||!['pending','running'].includes(row.state))return;
      const steps=await this.db.one<any>(`SELECT count(*) FILTER(WHERE state IN('running','uncertain'))::integer AS unresolved,
        count(*) FILTER(WHERE state='succeeded')::integer AS completed FROM configuration_job_steps WHERE job_id=$1`,[jobId]);
      const handle=await this.access.acquire(jobId),state=steps?.unresolved?'uncertain':steps?.completed?'partial':'failed';
      await this.finish(handle,jobId,state,{...row.safe_progress,completedSteps:steps?.completed??0,initializationOrFinalizationFailed:true},error);
    }catch(failure){this.logger.warn(JSON.stringify({event:'configuration.execution.receipt_unavailable',jobId,code:safeConfigurationError(failure),causeCode:safeConfigurationError(error)}));}
  }
  private async startDeckExecution(original:ConfigurationAccessHandle,jobId:string):Promise<any>{return this.redis.withLock(`configuration:${jobId}`,async()=>{
    for(const[id,e]of this.deckExecutions)if(e.expiresAt<=Date.now())this.deckExecutions.delete(id);if(this.deckExecutions.size>=100)throw fail('CONFIGURATION_DECK_CAPACITY');
    await this.repo.claimJob(original,{jobId,leaseMs:CONFIGURATION_LEASE_MS});const handle=await this.access.acquire(jobId),job=await this.db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[jobId]);
    const state=await this.access.description(handle),plan=await this.repo.readPlan(handle,{scope:state.scope,planId:job.plan_id,planRevision:job.plan_revision,planHash:job.plan_hash});
    if(job.execution_mode!=='direct'||job.approval_required||Date.parse(plan.expiresAt)<=Date.now())throw fail('CONFIGURATION_DECK_PLAN_UNAVAILABLE');await this.assertPlanGrants(handle,plan,true,true);
    const execution=await this.repo.createExecution(handle,{jobId,planId:job.plan_id,planRevision:job.plan_revision,planHash:job.plan_hash,beforeSnapshotId:job.safe_progress.baselineSnapshotId,beforeSnapshotVersion:job.safe_progress.baselineVersion,claimHash:this.secrets.fingerprint(randomBytes(32).toString('base64url'))});
    const rows=await this.repo.initializeSteps(handle,{jobId,executionId:execution.executionId});await this.db.exec("UPDATE configuration_executions SET state='executing',revision=revision+1 WHERE id=$1 AND state='claimed'",[execution.executionId]);
    if(plan.steps.filter(step=>step.mutationAction==='delete').length>=2)await this.access.runJob(handle,()=>this.recycleGraphs.prepare(handle,plan,execution.executionId));
    this.deckExecutions.set(jobId,{handle,plan,job,executionId:execution.executionId,rows,targetDeleteIntents:new Set(),completed:0,expiresAt:Math.min(state.expiresAt,Date.parse(plan.expiresAt))});
    if(!rows.length)await this.finish(handle,jobId,'succeeded',{...job.safe_progress,driver:'deck',executionId:execution.executionId,completedSteps:0});
    return this.jobProjection(handle,await this.repo.getJob(handle,jobId));
  });}
  async deckExecutionHandle(input:DeckSessionIssue,actor:{user:EntityActor['user'];sessionId:string;clusterId:string;workspaceId?:string;requestId?:string}):Promise<ConfigurationAccessHandle>{
    const origin=await this.db.one<any>('SELECT required_origin_kind FROM configuration_jobs WHERE id=$1',[input.jobId]);if(origin?.required_origin_kind)throw new ForbiddenException({code:'CONFIGURATION_ORIGIN_DECK_DRIVER_DENIED'});
    const e=this.deckExecutions.get(input.jobId);if(!e||e.expiresAt<=Date.now())throw new ForbiddenException({code:'CONFIGURATION_DECK_EXECUTION_UNAVAILABLE'});
    const state=await this.access.description(e.handle);
    if(state.actor.id!==actor.user.id||state.sessionId!==actor.sessionId||state.scope.clusterId!==actor.clusterId||actor.workspaceId&&state.scope.workspaceId!==actor.workspaceId
      ||e.job.plan_id!==input.planId||e.job.plan_revision!==input.planRevision||e.job.plan_hash!==input.planHash||e.job.execution_mode!=='direct')throw new ForbiddenException({code:'CONFIGURATION_DECK_EXECUTION_DENIED'});
    await this.access.assertCurrent(e.handle,{phase:'step',jobId:input.jobId});return e.handle;
  }
  async deckGraphObjects(jobId:string,baseline:CaptureGraph):Promise<CaptureGraph>{
    const e=this.deckExecutions.get(jobId);if(!e)return baseline;const objects=[...baseline.objects];
    for(const step of e.plan.steps){const row=e.rows.find(r=>r.planStepId===step.stepId),actual=await this.db.one<any>('SELECT state FROM configuration_job_steps WHERE id=$1',[row.id]);if(actual.state!=='succeeded')continue;
      const index=objects.findIndex(o=>o.objectKey===step.objectKey);if(step.mutationAction==='delete'){if(index>=0)objects.splice(index,1);continue;}
      const object:CaptureObject={...(index>=0?objects[index]:{}),objectKey:step.objectKey,entityType:step.entityType,nativeId:step.nativeId??step.allocatedNativeId!,parentId:step.parentId??undefined,credentialKind:step.credentialKind??undefined,
        objectWorkspaceId:step.objectWorkspaceId,ownershipTags:(step.body?.tags as string[])??[],affected:true,referenceOnly:false,dependencies:[],payload:{...(step.before as any??{}),...step.body,id:step.nativeId??step.allocatedNativeId},
        beforeHmac:step.beforeHmac,schemaHmac:e.plan.schemaHmac,observedAt:new Date().toISOString(),recovery:{state:'complete',blockerCodes:[]}};
      if(index<0)objects.push(object);else objects[index]=object;
    }
    return{...baseline,objects};
  }
  async readLiveDeckObject(authority:DeckAuthority,object:CaptureObject):Promise<{entity:Record<string,unknown>;calls:number}>{
    const e=this.deckExecutions.get(authority.locator.jobId);if(!e||e.handle!==authority.handle)throw new ForbiddenException({code:'CONFIGURATION_DECK_EXECUTION_UNAVAILABLE'});
    const matching=e.plan.steps.find(s=>s.objectKey===object.objectKey),stepRow=matching&&e.rows.find(r=>r.planStepId===matching.stepId),stored=stepRow&&await this.db.one<any>('SELECT state,effective_native_id FROM configuration_job_steps WHERE id=$1',[stepRow.id]);
    const effective=stored?.state==='succeeded'&&stored.effective_native_id||object.nativeId;
    const path=object.entityType==='credentials'?`/consumers/${object.parentId}/${object.credentialKind}/${effective}`:object.entityType==='targets'?`/upstreams/${object.parentId}/targets/${effective}`:`/${object.entityType}/${effective}`;
    return this.access.runRead(e.handle,[path],async usage=>{const before=usage().calls;try{const raw=await this.kong.request<Record<string,unknown>>(authority.locator.clusterId,'GET',path);
      await this.access.assertObject(e.handle,{entityType:object.entityType,nativeId:effective,payload:raw,parentId:object.parentId??undefined,credentialKind:object.credentialKind??undefined,secrets:true});
      const recovery=object.credentialKind==='basic-auth'?await this.access.freezeRecovery(e.handle,{entityType:'credentials',nativeId:effective,payload:raw,parentId:object.parentId??undefined,credentialKind:'basic-auth',observedAt:new Date().toISOString()}):null;
      const entity={...(recovery?.restorePayload??raw),id:object.nativeId};return{entity,calls:0};
      }finally{await this.repo.chargeDeckSessionBudget(e.handle,authority.locator.id,{pages:0,records:0,bytes:0,calls:usage().calls-before});}});
  }
  async executeDeckPacket(authority:DeckAuthority,packet:DeckPacket):Promise<{status:200|201|204;entity?:Record<string,unknown>}>{
    const e=this.deckExecutions.get(authority.locator.jobId);if(!e||e.handle!==authority.handle||authority.locator.purpose!=='write'||e.expiresAt<=Date.now())throw new ForbiddenException({code:'CONFIGURATION_DECK_EXECUTION_UNAVAILABLE'});
    return this.redis.withLock(`configuration:${authority.locator.jobId}`,()=>this.access.runJob(e.handle,async()=>{
      const usageBefore=this.context.currentUsage();try{
      await this.assertPlanGrants(e.handle,e.plan,true,true);await this.access.assertCurrent(e.handle,{phase:'step',jobId:authority.locator.jobId});
      const candidates=e.plan.steps.filter(s=>(s.credentialKind??s.entityType)===packet.type&&(s.parentId??undefined)===packet.parentId&&(!packet.id||packet.id===(s.mutationAction==='create'?s.allocatedNativeId:s.nativeId)));
      const ready=[];for(const step of candidates){const row=e.rows.find(r=>r.planStepId===step.stepId),actual=await this.db.one<any>('SELECT * FROM configuration_job_steps WHERE id=$1',[row.id]);
        if(actual.state!=='pending')continue;const unsettled=await this.db.one<any>("SELECT 1 FROM configuration_job_steps WHERE job_id=$1 AND plan_step_id=ANY($2::uuid[]) AND state NOT IN('succeeded','skipped') LIMIT 1",[e.job.id,step.dependencies]);if(!unsettled)ready.push({step,row:actual});}
      const matches=ready.filter(({step})=>{
        if(step.entityType==='targets'&&step.mutationAction==='update')return packet.method==='DELETE'||packet.method==='POST'&&this.deckBodyMatches(step,packet,true);
        if(step.mutationAction==='delete')return packet.method==='DELETE';
        return ['POST','PUT','PATCH'].includes(packet.method)&&this.deckBodyMatches(step,packet,false);
      });if(matches.length!==1)throw new ConflictException({code:'CONFIGURATION_DECK_PACKET_NOT_IN_PLAN'});
      const {step,row}=matches[0];
      if(step.entityType==='targets'&&step.mutationAction==='update'&&packet.method==='DELETE'){
        if(e.targetDeleteIntents.has(step.stepId))throw fail('CONFIGURATION_DECK_TARGET_INTENT_ALREADY_STAGED');e.targetDeleteIntents.add(step.stepId);return{status:204};
      }
      if(step.entityType==='targets'&&step.mutationAction==='update'&&!e.targetDeleteIntents.has(step.stepId))throw fail('CONFIGURATION_DECK_TARGET_PAIR_REQUIRED');
      await this.repo.recordStepEvidence(e.handle,{jobId:e.job.id,stepId:row.id,revision:row.revision,state:'running'});
      try{
        const result=await this.access.runStep(e.handle,step,row.id,()=>this.native.execute(e.handle,step,row.id)),latest=await this.db.one<any>('SELECT revision FROM configuration_job_steps WHERE id=$1',[row.id]);
        await this.repo.recordStepEvidence(e.handle,{jobId:e.job.id,stepId:row.id,revision:latest.revision,state:'succeeded',receipt:result.receipt,afterHmac:this.secrets.fingerprint(result.after),safeResult:result.result,effectiveNativeId:result.effectiveNativeId??undefined,recycleEntryId:result.result?.entryId});e.completed++;
        if(e.plan.steps.filter(s=>s.mutationAction==='delete').length>=2)await this.recycleGraphs.settle(e.handle);
        if(e.completed===e.plan.steps.length){await this.finish(e.handle,e.job.id,'succeeded',{...e.job.safe_progress,driver:'deck',executionId:e.executionId,completedSteps:e.completed});if(e.plan.steps.filter(s=>s.mutationAction==='delete').length>=2)await this.recycleGraphs.settle(e.handle,true);}
        if(packet.method==='DELETE')return{status:204};
        // The fixed CLI expects its original logical Target ID. Storage retains
        // the separately verified effective append ID for native readbacks.
        await this.access.assertObject(e.handle,{entityType:step.entityType,nativeId:result.effectiveNativeId!,payload:result.after as Record<string,unknown>,parentId:step.parentId??undefined,credentialKind:step.credentialKind??undefined,secrets:true});
        const entity={...(result.after as Record<string,unknown>),id:packet.id??(step.entityType==='targets'&&step.mutationAction==='update'?step.nativeId:step.allocatedNativeId??step.nativeId)};
        return{status:step.mutationAction==='create'?201:200,entity};
      }catch(error){const actual=await this.db.one<any>('SELECT state,revision FROM configuration_job_steps WHERE id=$1',[row.id]);
        if(actual.state==='running'){const receipt=await this.native.receipt(await this.native.context(e.handle,step,row.id)),unknown=receipt&&['running','uncertain'].includes(receipt.state)||!(error instanceof ConflictException||error instanceof BadRequestException||error instanceof ForbiddenException);
          await this.repo.recordStepEvidence(e.handle,{jobId:e.job.id,stepId:row.id,revision:actual.revision,state:unknown?'uncertain':'failed',errorCode:safeConfigurationError(error)});
          await this.finish(e.handle,e.job.id,unknown?'uncertain':e.completed?'partial':'failed',{...e.job.safe_progress,driver:'deck',executionId:e.executionId,completedSteps:e.completed},error);}
        if(e.plan.steps.filter(s=>s.mutationAction==='delete').length>=2)await this.recycleGraphs.settle(e.handle,true);throw error;}
      }finally{const actual=this.context.currentUsage();await this.repo.chargeDeckSessionBudget(e.handle,authority.locator.id,{pages:actual.pages-usageBefore.pages,records:actual.records-usageBefore.records,bytes:actual.bytes-usageBefore.bytes,calls:actual.calls-usageBefore.calls});}
    }));
  }
  private deckBodyMatches(step:ConfigPlan['steps'][number],packet:DeckPacket,target:boolean):boolean{
    if(!packet.body||packet.bodyHmac!==this.secrets.fingerprint({domain:'deck-cli-packet:v1',body:packet.body}))return false;
    const expected=structuredClone(step.nativeRequests[0].body) as Record<string,unknown>,actual=structuredClone(packet.body) as Record<string,unknown>;
    if(target){if(actual.id!==undefined&&actual.id!==step.allocatedNativeId&&actual.id!==step.nativeId)return false;delete expected.id;delete actual.id;}
    // Fixed decK omits the already-path-bound ID and parent FK. No other field
    // or explicit null is silently projected away from an executable packet.
    if(actual.id===undefined)delete expected.id;
    if(step.parentId){const field=step.entityType==='targets'?'upstream':'consumer';if(actual[field]===undefined)delete expected[field];}
    // Historical plans retain their original exact-delta protocol. New plans
    // seal the complete normalized SDK envelope under the plan HMAC. Every
    // supplied extra must equal that envelope, and every planned delta remains
    // mandatory, including explicit nulls. The packet is never sent to Kong.
    if(step.deckWirePayload){
      const wire=structuredClone(step.deckWirePayload);
      const equivalent=(key:string,left:unknown,right:unknown):boolean=>{
        if(!step.deckWireSetFields?.includes(key)||!Array.isArray(left)||!Array.isArray(right))return canonicalJson(left)===canonicalJson(right);
        // Kong sets have no order. Accept a permutation only: duplicates,
        // missing members and foreign workspace tags remain refused. Records
        // and their nested arrays are compared without further normalization.
        const a=left.map(value=>canonicalJson(value)),b=right.map(value=>canonicalJson(value));
        return a.length===b.length&&new Set(a).size===a.length&&new Set(b).size===b.length&&canonicalJson(a.sort())===canonicalJson(b.sort());
      };
      if(target)delete wire.id;
      for(const [key,value]of Object.entries(actual)){
        if(!Object.hasOwn(wire,key)||!equivalent(key,value,wire[key]))return false;
      }
      for(const [key,value]of Object.entries(expected)){
        if(!Object.hasOwn(actual,key)||!equivalent(key,value,actual[key]))return false;
      }
      return true;
    }
    return canonicalJson(actual)===canonicalJson(expected);
  }
  private async createWrapper(handle:ConfigurationAccessHandle,jobId:string,identity:{planId:string;planRevision:number;planHash:string},actor:EntityActor,transaction?:DbService,durableDeadline?:string):Promise<WorkflowPlanV1>{
    const workflowId=randomUUID();return (transaction??this.db).transaction(async tx=>{
    const proof=await this.access.assertCurrent(handle,{phase:'step',jobId},tx);await this.workflowPlans.definitions(proof.scope.clusterId,proof.scope.workspaceId,actor.user.id,tx);
    const metadata={jobId,...identity},before=await this.immutableJobProjection(jobId,tx),definition=await this.workflowPlans.definition(proof.scope.clusterId,proof.scope.workspaceId,'configuration_v2',tx);
    const plan:WorkflowPlanV1={version:1,clusterId:proof.scope.clusterId,workspaceId:proof.scope.workspaceId,workflowId,planRevision:1,kind:'configuration_v2',executionMode:'approval',approvalRequired:true,
      subject:{type:'configuration_jobs',id:jobId},requester:{type:'console',id:actor.user.id},definition,issuedAt:new Date().toISOString(),expiresAt:durableDeadline??new Date(proof.expiresAt).toISOString(),scope:{transportScope:proof.scope.transportScope,clusterRevision:proof.clusterRevision,workspaceRevision:proof.workspaceRevision},prerequisites:[],
      steps:[{id:randomUUID(),key:'configuration_v2',order:1,kind:'metadata',handler:'configuration_v2',entityType:'configuration_jobs',entityId:jobId,permissionAction:'write',dependencies:[],nativeRequests:[],metadata,
        before,metadataBeforeHmac:this.secrets.fingerprint(before),metadataRevision:identity.planRevision,metadataPayloadHmac:this.secrets.fingerprint(metadata)}]};
    await this.workflowPlans.persist(plan,this.internalKey(actor.idempotencyKey!,'approval'),metadata,tx,{requestId:actor.requestId,ip:actor.ip});
    const jobs=await tx.exec("UPDATE configuration_jobs SET state='waiting_approval',workflow_id=$2,revision=revision+1 WHERE id=$1 AND workflow_id IS NULL AND state='pending'",[jobId,workflowId]);
    const plans=await tx.exec("UPDATE configuration_plans SET state='pending_approval',revision=revision+1,updated_at=now() WHERE id=$1 AND state='ready' AND source_job_id=$2 AND current_revision=$3",[identity.planId,jobId,identity.planRevision]);
    if(jobs!==1||plans!==1)throw fail('CONFIGURATION_JOB_STATE_CHANGED');await this.access.assertCurrent(handle,{phase:'read',jobId},tx);return plan;
    });
  }
  private async immutableJobProjection(id:string,tx=this.db):Promise<Record<string,unknown>>{
    const row=await tx.one<any>('SELECT id,actor_id,cluster_id,workspace_id,transport_scope,kind,plan_id,plan_revision,plan_hash,request_hmac,execution_mode,approval_required FROM configuration_jobs WHERE id=$1',[id]);if(!row)throw fail('CONFIGURATION_JOB_NOT_FOUND');return row;
  }
  private async wrapperProjection(plan:WorkflowPlanV1,tx=this.db):Promise<Record<string,unknown>>{const step=assertConfigurationWorkflowPlan(plan);return this.immutableJobProjection((step.metadata as ConfigurationWorkflowPayload).jobId,tx);}
  /** An optional constructor supports legacy fixtures, never a permissive
   * origin policy. Only a real unmarked and unbound durable job may fall back. */
  private async assertLegacyOrigin(plan:WorkflowPlanV1,tx=this.db):Promise<void>{
    await this.assertDurableWorkflow(plan,tx);
    const payload=assertConfigurationWorkflowPlan(plan).metadata as ConfigurationWorkflowPayload;
    const job=await tx.one<any>(`SELECT j.required_origin_kind,j.required_origin_id,j.required_origin_hmac,
      EXISTS(SELECT 1 FROM configuration_job_origin_bindings b WHERE b.job_id=j.id) AS has_job_origin,
      EXISTS(SELECT 1 FROM configuration_plan_origin_bindings b WHERE b.job_id=j.id OR b.plan_id=j.plan_id) AS has_plan_origin
      FROM configuration_jobs j WHERE j.id=$1 AND j.cluster_id=$2 AND j.workspace_id=$3`,[payload.jobId,plan.clusterId,plan.workspaceId]);
    if(!job||job.required_origin_kind!=null||job.required_origin_id!=null||job.required_origin_hmac!=null||job.has_job_origin||job.has_plan_origin)
      throw new ForbiddenException({code:'CONFIGURATION_ORIGIN_PROVIDER_UNAVAILABLE'});
  }
  private async assertDurableWorkflow(plan:WorkflowPlanV1,tx:DbService=this.db):Promise<void>{
    if(this.durable){await this.durable.workflow(plan,tx);return;}
    const payload=assertConfigurationWorkflowPlan(plan).metadata as ConfigurationWorkflowPayload;
    const row=await tx.one<any>(DURABLE_CONFIGURATION_PRESENCE_QUERY,[payload.jobId,plan.clusterId,plan.workspaceId]);
    if(!isProvenLegacyConfigurationRow(row))throw new ForbiddenException({code:'CONFIGURATION_DURABLE_PROVIDER_UNAVAILABLE'});
  }
  private async authorizeWrapper(plan:WorkflowPlanV1,actor:EntityActor,action:'read'|'write'|'approve'):Promise<void>{
    assertConfigurationWorkflowPlan(plan);await this.assertDurableWorkflow(plan);const ws=await this.workspaces.resolve(plan.clusterId,actor.workspaceId);
    if(ws.id!==plan.workspaceId||action==='write'&&actor.user.id!==plan.requester.id)throw new ForbiddenException({code:'CONFIGURATION_WORKFLOW_SCOPE_DENIED'});
    await this.authz.assertWholeWorkspace(actor.user,plan.clusterId,ws.id,'workflows',action);await this.authz.assertWholeWorkspace(actor.user,plan.clusterId,ws.id,'snapshots',action==='approve'?'read':action);
    if(this.origins)await this.origins.assertWorkflow(plan,actor.user.id,action);else await this.assertLegacyOrigin(plan);
  }
  private async prepareWrapper(input:Omit<WorkflowHandlerInput,'transaction'>):Promise<void>{
    if(this.context.hasWorkflowScheduledNamespace()){
      if(!this.scheduledOrigin)throw new ForbiddenException({code:'CONFIGURATION_SCHEDULE_ORIGIN_UNAVAILABLE'});
      return this.scheduledOrigin.runOriginalJob(this.context.requireWorkflowScheduledNamespaceHandle(),input.executionId,(input.step.metadata as ConfigurationWorkflowPayload).jobId,()=>this.prepareWrapperInner(input));
    }
    return this.origins?this.origins.run(()=>this.prepareWrapperInner(input)):this.prepareWrapperInner(input);
  }
  private async prepareWrapperInner(input:Omit<WorkflowHandlerInput,'transaction'>):Promise<void>{
    if(!this.context.hasWorkflowScheduledNamespace()){
      if(!this.origins)await this.assertLegacyOrigin(input.plan);
      if(this.origins)await this.origins.prepareJob((input.step.metadata as ConfigurationWorkflowPayload).jobId,input.actor);
    }
    const p=input.step.metadata as ConfigurationWorkflowPayload,handle=await this.access.acquire(p.jobId);
    await this.db.transaction(async tx=>{
      const actual=await tx.one<any>(APPROVAL_WORKFLOW_CONTEXT_QUERY,[input.plan.workflowId,input.executionId,input.step.id,input.plan.clusterId,input.plan.workspaceId]);
      if(!actual||actual.state!=='executing'||actual.execution_state!=='executing'||actual.step_state!=='running'||actual.execution_actor_id!==input.actor.user.id
        ||!actual.approved_by||actual.plan_revision!==input.plan.planRevision||actual.plan_hash!==this.secrets.fingerprint(input.plan))throw new ForbiddenException({code:'CONFIGURATION_APPROVAL_EXECUTION_REQUIRED'});
      const count=await tx.exec(APPROVAL_CONFIGURATION_PLAN_QUERY,[p.planId,p.jobId,p.planRevision,input.plan.clusterId,input.plan.workspaceId,p.planHash,input.plan.workflowId]);
      if(count!==1)throw fail('CONFIGURATION_PLAN_STATE_CHANGED');
    });
    const receipt=await this.executeJob(handle,p.jobId,input.actor,{workflowId:input.plan.workflowId,approvedVersion:input.plan.planRevision,workflowExecutionId:input.executionId});
    if(receipt.state!=='succeeded')throw fail('CONFIGURATION_JOB_NOT_SUCCEEDED');
  }
  private async executeJob(originalHandle:ConfigurationAccessHandle,jobId:string,actor:EntityActor,wrapper?:{workflowId:string;approvedVersion:number;workflowExecutionId:string}):Promise<any>{
    let failureHandle:ConfigurationFailureHandle|null=null,ledgerArmed=false,initializationHandle:ConfigurationInitializationFailureHandle|null=null,initializationArmed=false;
    return this.redis.withLock(`configuration:${jobId}`,async()=>{
      await this.repo.claimJob(originalHandle,{jobId,leaseMs:CONFIGURATION_LEASE_MS});const handle=await this.access.acquire(jobId),job=await this.db.one<any>('SELECT * FROM configuration_jobs WHERE id=$1',[jobId]);
      const plan=await this.repo.readPlan(handle,{scope:(await this.access.description(handle)).scope,planId:job.plan_id,planRevision:job.plan_revision,planHash:job.plan_hash});
      await this.assertPlanGrants(handle,plan,true);if(Date.parse(plan.expiresAt)<=Date.now())throw fail('CONFIGURATION_PLAN_EXPIRED');
      if(plan.originRef){if(!this.origins)throw new ForbiddenException({code:'CONFIGURATION_ORIGIN_PROVIDER_UNAVAILABLE'});await this.origins.assertExecutionBudget(plan.originRef,plan);}
      const claimHash=this.secrets.fingerprint(randomBytes(32).toString('base64url'));
      if(this.access.isWorkflowScheduledConfigurationJob(handle)){
        if(!wrapper)throw new ForbiddenException({code:'CONFIGURATION_APPROVAL_EXECUTION_REQUIRED'});
        initializationHandle=await this.failureLedger.armInitialization(handle,claimHash,wrapper.workflowExecutionId);initializationArmed=true;
      }
      const execution=await this.repo.createExecution(handle,{jobId,planId:job.plan_id,planRevision:job.plan_revision,planHash:job.plan_hash,beforeSnapshotId:job.safe_progress.baselineSnapshotId,
        beforeSnapshotVersion:job.safe_progress.baselineVersion,claimHash,...(wrapper?{workflowId:wrapper.workflowId,approvedVersion:wrapper.approvedVersion}:{})});
      const rows=await this.repo.initializeSteps(handle,{jobId,executionId:execution.executionId});await this.db.exec("UPDATE configuration_executions SET state='executing',revision=revision+1 WHERE id=$1 AND state='claimed'",[execution.executionId]);
      let completed=0;
      const execute=async(originalJobHandle?:WorkflowScheduledConfigurationJobHandle,originalExecutionHandle?:WorkflowScheduledConfigurationExecutionHandle)=>{
      failureHandle=await this.failureLedger.arm(handle,execution.executionId,claimHash,wrapper?.workflowExecutionId??null);ledgerArmed=true;
      if(initializationHandle){this.failureLedger.releaseInitialization(initializationHandle);initializationHandle=null;}
      return this.access.runJob(handle,()=>this.claims.run({executionId:execution.executionId,claimHash,handle,workflowExecutionId:wrapper?.workflowExecutionId},async()=>{
        const groupedDeletes=plan.steps.filter(step=>step.mutationAction==='delete').length>=2;
        const run=async()=>{if(groupedDeletes)await this.recycleGraphs.prepare(handle,plan,execution.executionId);for(const step of plan.steps){await this.redis.assertLeaseOwnership();const row=rows.find(r=>r.planStepId===step.stepId)!;
          const current=await this.db.one<any>('SELECT * FROM configuration_job_steps WHERE id=$1',[row.id]);
          if(current.state!=='pending')throw fail('CONFIGURATION_STEP_ALREADY_ATTEMPTED');
          await this.repo.recordStepEvidence(handle,{jobId,stepId:row.id,revision:current.revision,state:'running'});
          const execute=()=>this.access.runStep(handle,step,row.id,async()=>{
            const result=await this.native.execute(handle,step,row.id),latest=await this.db.one<any>('SELECT revision FROM configuration_job_steps WHERE id=$1',[row.id]);
            await this.repo.recordStepEvidence(handle,{jobId,stepId:row.id,revision:latest.revision,state:'succeeded',receipt:result.receipt,afterHmac:this.secrets.fingerprint(result.after),
              safeResult:result.result,effectiveNativeId:result.effectiveNativeId??undefined,recycleEntryId:result.result?.entryId});
            if(groupedDeletes)await this.recycleGraphs.settle(handle);
          });if(wrapper)await this.context.runApprovedStep(row.id,execute);else await execute();completed++;
        }};
        try{if(originalJobHandle&&originalExecutionHandle)await this.approved.runScheduledConfigurationExecution(originalJobHandle,originalExecutionHandle,execution.executionId,run);
          else if(wrapper)await this.approved.runConfigurationExecution(execution.executionId,run);else await run();
          const done=await this.finish(handle,jobId,'succeeded',{...job.safe_progress,executionId:execution.executionId,completedSteps:completed});return this.jobProjection(handle,done);
        }catch(error){
          // Consuming this private failure handle records only existing facts.
          // Neither an expired Native frame nor a revoked account may cause
          // another Native packet or conceal the original execution failure.
          const token=failureHandle;failureHandle=null;
          if(token)try{error=failureError(error,await this.failureLedger.recordFailure(token,error));}catch(failure){this.logger.warn(JSON.stringify({event:'configuration.execution.failure_ledger_unavailable',jobId,
            code:safeConfigurationError(failure),causeCode:safeConfigurationError(error)}));error=uncertainFailure(error);}
          throw error;
        }finally{try{if(groupedDeletes)await this.recycleGraphs.settle(handle,true);}catch(error){this.logger.warn(JSON.stringify({event:'configuration.recycle_graph.finalization_pending',jobId,code:safeConfigurationError(error)}));}if(failureHandle){this.failureLedger.release(failureHandle);failureHandle=null;}}
      }));};
      return this.access.isWorkflowScheduledConfigurationJob(handle)?this.access.runWorkflowScheduledConfigurationExecution(handle,execution.executionId,execute):execute();
    }).catch(async error=>{if(failureHandle){const token=failureHandle;failureHandle=null;try{error=failureError(error,await this.failureLedger.recordFailure(token,error));}catch(failure){this.logger.warn(JSON.stringify({event:'configuration.execution.failure_ledger_unavailable',jobId,code:safeConfigurationError(failure),causeCode:safeConfigurationError(error)}));error=uncertainFailure(error);}}
      else if(initializationHandle){const token=initializationHandle;initializationHandle=null;try{error=failureError(error,await this.failureLedger.recordInitializationFailure(token,error));}catch(failure){this.logger.warn(JSON.stringify({event:'configuration.execution.initialization_ledger_unavailable',jobId,code:safeConfigurationError(failure),causeCode:safeConfigurationError(error)}));error=uncertainFailure(error);}}
      else if(!ledgerArmed&&!initializationArmed)await this.failUnfinishedExecution(jobId,error);throw error;});
  }
  private async mutationsReceipt(context:any):Promise<any>{return this.native.receipt(context);}
  async jobProjection(handle:ConfigurationAccessHandle,job:ConfigurationJobSummary):Promise<any>{
    const state=await this.access.description(handle),row=await this.db.one<any>(CONFIGURATION_JOB_PROJECTION_QUERY,[job.id,state.scope.clusterId,state.scope.workspaceId,state.actor.id]);
    if(!row)throw new NotFoundException({code:'CONFIGURATION_RECEIPT_NOT_FOUND'});
    const exported=typeof job.safeProgress.exportId==='string'?await this.db.one<any>(EXPORT_PROJECTION_QUERY,[job.safeProgress.exportId,job.clusterId,job.workspaceId,row.actor_id]):null;
    const abandonmentIntent=job.state==='running'&&['apply','rollback'].includes(job.kind)?await this.failureLedger.abandonmentIntent(handle,job.id):null;
    const frame=job.state==='uncertain'&&job.safeProgress.abandoned===true&&job.safeProgress.terminalFailureRecorded===true?this.context.current():null;
    const abandonmentSessionMatches=!!frame&&!!frame.actor&&!!frame.sessionId&&frame.actor.id===row.actor_id&&frame.sessionId===row.origin_session_id
      &&frame.clusterId===job.clusterId&&frame.workspaceId===job.workspaceId
      &&await this.authz.hasWholeWorkspace(frame.actor,state.scope.clusterId,state.scope.workspaceId,'snapshots','write')
      &&(row.execution_mode!=='approval'||await this.authz.hasWholeWorkspace(frame.actor,state.scope.clusterId,state.scope.workspaceId,'workflows','write'));
    const entity={...job,...job.safeProgress,jobId:job.id,actorId:row.actor_id,planId:row.plan_id,executionId:row.execution_id??null,workflowId:row.workflow_id,executionMode:row.execution_mode,approvalRequired:row.approval_required,exportRevision:exported?.revision??null,
      capabilities:{download:job.kind==='export'&&job.state==='succeeded'&&exported?.state==='ready'&&exported.material_state==='available'&&new Date(exported.expires_at).getTime()>Date.now()&&job.safeProgress.downloadPermitConsumed!==true,abandon:abandonmentIntent!==null},
      ...(abandonmentIntent?{abandonmentIntent}:{}),abandonmentSessionMatches,confirmationName:job.safeProgress.confirmationName??null};
    return{...entity,domain:'configuration',durable:true,job:entity,idempotencyKey:row.idempotency_key,registrationCompleted:true,submissionCompleted:true,
      executionCompleted:['succeeded','failed','partial','uncertain','cancelled'].includes(job.state),originalScope:{clusterId:state.scope.clusterId,workspaceId:state.scope.workspaceId}};
  }
  private async recordDurableRejection(tx:DbService,fact:DurableConfigurationRejectionFact):Promise<void>{
    const frame=this.context.current();if(frame.actor?.id!==fact.ownerId)throw new ForbiddenException({code:'CONFIGURATION_DURABLE_REJECTION_ACTOR_REQUIRED'});
    await this.audit.append({actorId:fact.ownerId,clusterId:fact.clusterId,workspaceId:fact.workspaceId,entityType:'configuration_durable_rejections',entityId:fact.id,
      action:'configuration.durable.rejected',result:'failed',after:{sourcePlanId:fact.sourcePlanId,sourcePlanRevision:fact.sourcePlanRevision,sourcePlanHash:fact.sourcePlanHash,
        code:fact.code,effectScope:fact.effectScope,rejectedAt:fact.rejectedAt},requestId:frame.requestId,ip:frame.ip,
      scopeHints:metadataAuditScope('snapshots','configuration_durable_rejections',fact.id,fact.workspaceId)},tx);
  }
  private async assertDurableRejectionReadable(rejected:NonNullable<Awaited<ReturnType<ConfigurationDurableService['rejectionReceipt']>>>,actor:EntityActor,cid:string):Promise<void>{
    const current=await this.scopeHandle(cid,actor,{scope:rejected.scopeKind,serviceIds:rejected.rootIds},'compare');
    if(current.scope.clusterId!==rejected.fact.clusterId||current.scope.workspaceId!==rejected.fact.workspaceId||rejected.fact.ownerId!==actor.user.id)throw new ForbiddenException({code:'CONFIGURATION_DURABLE_REJECTION_SCOPE_DENIED'});
    await this.access.assertCurrent(current.handle,{phase:'read'});
  }
  async abandon(cid:string,jobId:string,value:Record<string,unknown>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'write',()=>this.failureLedger.abandon(cid,jobId,value,actor));}
  async receipt(cid:string,key:string,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    const ws=await this.workspaces.resolve(cid,actor.workspaceId),row=await this.db.one<any>('SELECT id FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4',[cid,ws.id,actor.user.id,configurationKey(key)]);
    const rejected=this.durable?await this.durable.rejectionReceipt(configurationKey(key),actor,cid,ws.id):null;
    if(rejected){
      if(row)throw fail('CONFIGURATION_RECEIPT_DISPOSITION_CONFLICT');
      await this.assertDurableRejectionReadable(rejected,actor,cid);return rejected.receipt;
    }
    if(!row)throw new NotFoundException({code:'CONFIGURATION_RECEIPT_NOT_FOUND'});
    const handle=await this.access.acquireReceipt(row.id);return this.jobProjection(handle,await this.repo.getJob(handle,row.id));
  });}
  async job(cid:string,id:string,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{const handle=await this.access.acquireReceipt(configurationId(id));return{entity:await this.jobProjection(handle,await this.repo.getJob(handle,id))};});}
  async listJobs(cid:string,query:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    const {handle,scope}=await this.scopeHandle(cid,actor,query,'compare');return this.repo.listJobs(handle,{scope,...configurationPage(query)});
  });}
  async steps(cid:string,id:string,query:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    const handle=await this.access.acquireReceipt(configurationId(id));return this.repo.listSteps(handle,{jobId:id,...configurationPage(query)});
  });}
  async exportCurrent(cid:string,body:Record<string,any>,actor:EntityActor):Promise<any>{return this.withActor(cid,actor,'read',async()=>{
    if(!['review','deployment'].includes(body.mode))throw new BadRequestException({code:'INVALID_EXPORT_MODE'});
    const ws=await this.workspaces.resolve(cid,actor.workspaceId);if(body.mode==='deployment')configurationConfirm(body,ws.name);
    const key=configurationKey(actor.idempotencyKey),base=await this.captureBaseline(cid,actor,body,this.internalKey(key,'export-source'),'导出配置快照');
    return this.exportSnapshot(cid,base.snapshotId,{mode:body.mode,confirmed:true,confirm_name:'导出配置快照'},actor);
  });}
}
