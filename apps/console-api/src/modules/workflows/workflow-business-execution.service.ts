import { assertEntityAnnotationPlan } from '../annotations/entity-annotation-workflow-plan';
import { isMetadataScheduledKind } from './metadata-schedule.guard';
import { ConflictException, ForbiddenException, HttpException, Logger } from '@nestjs/common';
import { WorkflowExecutionObservation } from './workflow-execution-observation';
import { randomBytes, randomUUID } from 'node:crypto';
import type { DbService } from '../../infrastructure/db.service';
import type { RedisService } from '../../infrastructure/redis.service';
import type { SecretService } from '../../infrastructure/secret.service';
import type { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import type { AuthorizationService } from '../authorization/authorization.service';
import type { AuditService } from '../audit/audit.service';
import type { EntityActor } from '../entities/entities.types';
import type { MutationService, MutationContext } from '../mutations/mutation.service';
import type { ApprovedWorkflowExecutionService } from './approved-workflow-execution.service';
import type { WorkflowPlansService } from './workflow-plans.service';
import type { WorkflowRegistryService } from './workflow-registry.service';
import type { WorkflowScheduledAuthorityCheckpoint, WorkflowScheduledAuthorityInspection } from './workflow-scheduled-authority.types';
import type { WorkflowScheduleTerminalOutcome, WorkflowScheduledPlanV1 } from './workflow-schedule.contract';
import { assertConfigurationWorkflowPlan } from './configuration-workflow';
import { workflowMetadataProjection } from './workflow-plans.service';
import { snapshotAad, type WorkflowPlanV1, type WorkflowSnapshotV1, type WorkflowStep } from './workflow.types';

/** Fixed bootstrap callbacks only. Caller DTOs, returned strings and copied
 * facts never create a namespace, an execution handle or Native permission. */
export interface WorkflowBusinessScheduledDelegate {
  verifyOriginalClaim(originalAuthorityHandle: object, originalNamespaceHandle: object,
    checkpoint: WorkflowScheduledAuthorityCheckpoint, tx: DbService): Promise<Readonly<WorkflowScheduledAuthorityInspection>>;
  captureSnapshot(originalAuthorityHandle: object, originalNamespaceHandle: object,
    plan: Readonly<WorkflowScheduledPlanV1>, executionId: string): Promise<WorkflowSnapshotV1>;
  readNativeAfter(originalAuthorityHandle: object, originalNamespaceHandle: object,
    plan: Readonly<WorkflowScheduledPlanV1>, step: Readonly<WorkflowStep>, executionId: string): Promise<unknown>;
  deriveCompletion(originalAuthorityHandle: object, executionId: string, tx: DbService): Promise<WorkflowScheduleTerminalOutcome>;
}
export interface WorkflowBusinessExecutionDependencies {
  db: DbService; redis: RedisService; secrets: SecretService; context: KongExecutionContextService; authz: AuthorizationService;
  audit: AuditService; mutations: MutationService; plans: WorkflowPlansService; registry: WorkflowRegistryService; approved: ApprovedWorkflowExecutionService;
  dispatch(plan: WorkflowPlanV1, step: WorkflowStep, actor: EntityActor): Promise<any>;
  mutationContext(plan: WorkflowPlanV1, step: WorkflowStep, actor: EntityActor): MutationContext;
}
interface CompletionState {
  authorityHandle: object; namespaceHandle: object; executionId: string; originId: string; claimId: string; scheduleId: string;
  clusterId: string; workspaceId: string; workflowId: string; planRevision: number; planHash: string; actorId: string; permissionVersion: string;
}
const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const digest = /^[a-f\d]{64}$/;
const deny = (code = 'WORKFLOW_SCHEDULE_ORIGINAL_BUSINESS_EXECUTION_REQUIRED') => new ForbiddenException({ code });
const conflict = (code: string) => new ConflictException({ code });
const cas = (count: number) => { if(count !== 1)throw conflict('WORKFLOW_SCHEDULE_BUSINESS_CAS_CONFLICT'); };

/** Private business executor owned by WorkflowService, not an HTTP service.
 * Uses the original Registry/Entity/Mutation/Approved execution paths. */
export class WorkflowBusinessExecutionService {
  private readonly logger = new Logger(WorkflowBusinessExecutionService.name);
  private delegate?: Readonly<WorkflowBusinessScheduledDelegate>;
  private readonly usedAuthorities = new WeakSet<object>();
  private readonly completions = new WeakMap<object, Readonly<CompletionState>>();
  constructor(private readonly d: WorkflowBusinessExecutionDependencies) {}
  install(delegate: WorkflowBusinessScheduledDelegate): void {
    if(this.delegate || !delegate || ['verifyOriginalClaim','captureSnapshot','readNativeAfter','deriveCompletion'].some(key => typeof (delegate as any)[key] !== 'function'))throw deny('WORKFLOW_SCHEDULE_BUSINESS_POLICY_ALREADY_INSTALLED');
    this.delegate = Object.freeze({ verifyOriginalClaim: delegate.verifyOriginalClaim.bind(delegate), captureSnapshot: delegate.captureSnapshot.bind(delegate),
      readNativeAfter: delegate.readNativeAfter.bind(delegate), deriveCompletion: delegate.deriveCompletion.bind(delegate) });
  }
  private policy(): Readonly<WorkflowBusinessScheduledDelegate> { if(!this.delegate)throw deny('WORKFLOW_SCHEDULE_BUSINESS_POLICY_UNAVAILABLE');return this.delegate; }
  private scopeHints(s: Pick<CompletionState,'workspaceId'|'workflowId'>) { return { quality: 'verified' as const, module: 'workflows', subject: { type: 'workflows', id: s.workflowId },
    beforeExists: true, afterExists: true, beforeTags: [], afterTags: [], beforeWorkspaceId: s.workspaceId, afterWorkspaceId: s.workspaceId }; }
  private async inspect(authority: object, namespace: object, checkpoint: WorkflowScheduledAuthorityCheckpoint, tx = this.d.db): Promise<Readonly<WorkflowScheduledAuthorityInspection>> {
    if(!authority || !namespace || typeof authority !== 'object' || typeof namespace !== 'object'
      || this.d.context.requireWorkflowScheduledNamespaceHandle() !== namespace)throw deny();
    const value = await this.policy().verifyOriginalClaim(authority, namespace, checkpoint, tx);
    const principal = this.d.context.requireWorkflowScheduledCurrentPrincipal(namespace), ns = principal.namespace, frame = this.d.context.current();
    const p = value?.plan, c = value?.claim, draft = value?.draft;
    if(principal.role !== 'executor' || principal.readOnly !== false || !ns || frame.sessionId != null || ns.sessionId !== null || ns.kind !== p?.kind || ns.actor.id !== value?.principal?.id || frame.actor?.id !== value?.principal?.id
      || !p?.scheduling || !['configuration_v2','portal-credential-issue','portal-credential-rotate','portal-credential-revoke','entity-annotation','control-metadata','configuration-metadata','governance-metadata','workflow-policy-metadata','iam-metadata','portal-metadata','portal-developer-review','event-metadata'].includes(p.kind) || !p.approvalRequired || !['approval','direct'].includes(p.executionMode)
      || (p.kind==='configuration_v2'||isMetadataScheduledKind(p.kind))&&p.executionMode!=='approval'
      || p.workflowId !== ns.workflow.id || p.planRevision !== ns.workflow.planRevision || this.d.secrets.fingerprint(p) !== ns.workflow.planHash
      || p.clusterId !== ns.clusterId || p.workspaceId !== ns.workspaceId || frame.clusterId !== p.clusterId || frame.workspaceId !== p.workspaceId
      || p.scope.transportScope !== ns.transportScope || p.scope.clusterRevision !== ns.clusterRevision || p.scope.workspaceRevision !== ns.workspaceRevision
      || value.permissionVersion !== ns.permissionVersion || c.id !== ns.claim.id || c.scheduleId !== ns.claim.scheduleId || c.generation !== 1
      || c.workflowId !== p.workflowId || c.workflowPlanRevision !== p.planRevision || c.workflowPlanHash !== ns.workflow.planHash
      || draft.scheduleId !== c.scheduleId || draft.binding.workflowId !== p.workflowId || draft.binding.workflowPlanRevision !== p.planRevision
      || draft.binding.workflowPlanHash !== ns.workflow.planHash || draft.binding.clusterId !== p.clusterId || draft.binding.workspaceId !== p.workspaceId
      || p.scheduling.executorId !== value.principal.id || p.scheduling.scheduleId !== c.scheduleId || p.scheduling.occurrenceId !== c.occurrenceId
      || p.requester.type !== ns.requester.type || p.requester.id !== ns.requester.id || value.approvalSet.format !== 2
      || this.d.secrets.fingerprint(value.approvalSet) !== this.d.secrets.fingerprint(ns.approvalSet)
      || !uuid.test(value.approvalSet.setId ?? '') || !digest.test(value.approvalSet.setHmac ?? '')
      || [p.expiresAt,c.authorityExpiresAt,value.authorityExpiresAt,value.leaseUntil,ns.expiresAt].some(v => !Number.isFinite(Date.parse(v)) || Date.parse(v) <= Date.now()))throw deny('WORKFLOW_SCHEDULE_BUSINESS_FACTS_CHANGED');
    if(p.kind === 'configuration_v2')assertConfigurationWorkflowPlan(p);
    else if((p.kind as string) === 'entity-annotation'){
      // The sealed scheduling block is the only difference from the interactive annotation plan.
      try{const {scheduling:_sealed,...interactive}=p as any;assertEntityAnnotationPlan(interactive);}catch{throw deny('WORKFLOW_SCHEDULE_ANNOTATION_PLAN_INVALID');}
      if(p.requester.type!=='console')throw deny('WORKFLOW_SCHEDULE_ANNOTATION_PLAN_INVALID');
    }
    else if(isMetadataScheduledKind(p.kind)){
      if(p.executionMode!=='approval'||p.requester.type!=='console')throw deny('WORKFLOW_SCHEDULE_METADATA_PLAN_INVALID');
    }
    else {
      const [consumer,acl,key,activation] = p.steps;
      if(p.requester.type !== 'developer' || p.requester.id === value.principal.id || p.subject.type !== 'portal_application_grants' || p.steps.length !== 4
        || consumer?.kind !== 'native' || consumer.entityType !== 'consumers' || consumer.mutationAction !== 'create'
        || acl?.kind !== 'native' || acl.entityType !== 'credentials' || acl.credentialKind !== 'acls' || acl.mutationAction !== 'create'
        || key?.kind !== 'native' || key.entityType !== 'credentials' || key.credentialKind !== 'key-auth' || key.mutationAction !== 'create'
        || activation?.kind !== 'metadata' || activation.handler !== 'portal.credential.activate' || activation.entityId !== p.subject.id
        || this.d.secrets.fingerprint(consumer.dependencies) !== this.d.secrets.fingerprint([])
        || this.d.secrets.fingerprint(acl.dependencies) !== this.d.secrets.fingerprint([consumer.id])
        || this.d.secrets.fingerprint(key.dependencies) !== this.d.secrets.fingerprint([acl.id])
        || this.d.secrets.fingerprint(activation.dependencies) !== this.d.secrets.fingerprint([key.id]))throw deny('WORKFLOW_SCHEDULE_PORTAL_PLAN_INVALID');
    }
    await this.d.redis.assertLeaseOwnership();this.d.context.current();return value;
  }
  private snapshot(plan: WorkflowScheduledPlanV1, executionId: string, snapshot: WorkflowSnapshotV1): void {
    const expected = new Map<string,{type:string;id:string;absent:boolean;fingerprint:string}>();
    for(const p of plan.prerequisites)expected.set(p.path,{type:p.type,id:p.id,absent:false,fingerprint:p.fingerprint});
    for(const step of plan.steps)for(const req of step.nativeRequests){
      if(!req.nativeId)throw conflict('WORKFLOW_NATIVE_ID_REQUIRED');const absent=req.method==='POST',path=absent?`${req.canonicalPath}/${req.nativeId}`:req.canonicalPath;
      const entry={type:req.nativeType,id:req.nativeId,absent,fingerprint:absent?this.d.secrets.fingerprint(null):req.beforeHmac??step.beforeFingerprint!};
      const prior=expected.get(path);if(prior&&this.d.secrets.fingerprint(prior)!==this.d.secrets.fingerprint(entry))throw conflict('WORKFLOW_SNAPSHOT_CONFLICT');expected.set(path,entry);
    }
    if(!snapshot || snapshot.version!==1 || snapshot.workflowId!==plan.workflowId || snapshot.executionId!==executionId || snapshot.clusterId!==plan.clusterId
      || snapshot.workspaceId!==plan.workspaceId || snapshot.planRevision!==plan.planRevision || snapshot.planHash!==this.d.secrets.fingerprint(plan)
      || !Number.isFinite(Date.parse(snapshot.capturedAt)) || Date.parse(snapshot.capturedAt)>Date.now() || !Array.isArray(snapshot.objects)
      || snapshot.objects.length!==expected.size || expected.size>100 || Buffer.byteLength(JSON.stringify(snapshot))>2*1024*1024)throw conflict('WORKFLOW_SCHEDULE_SNAPSHOT_INVALID');
    const seen=new Set<string>();for(const object of snapshot.objects){const e=expected.get(object.path);
      if(!e||seen.has(object.path)||object.type!==e.type||object.id!==e.id||object.absent!==e.absent||object.fingerprint!==e.fingerprint
        || this.d.secrets.fingerprint(object.before)!==e.fingerprint||object.absent&&object.before!==null)throw conflict('WORKFLOW_SCHEDULE_SNAPSHOT_INVALID');seen.add(object.path);
    }
  }
  async execute(authorityHandle: object, namespaceHandle: object): Promise<object> {
    this.policy();if(this.usedAuthorities.has(authorityHandle))throw deny('WORKFLOW_SCHEDULE_BUSINESS_EXECUTION_REPLAY_FORBIDDEN');
    const current=await this.inspect(authorityHandle,namespaceHandle,'claim'),plan=current.plan,actor:EntityActor={user:current.principal,workspaceId:plan.workspaceId};
    const loaded=await this.d.plans.load(plan.clusterId,plan.workspaceId,plan.workflowId);
    if(loaded.row.state!=='approved'||loaded.row.plan_hash!==current.claim.workflowPlanHash||loaded.row.approval_format!==2
      || this.d.secrets.fingerprint(loaded.plan)!==this.d.secrets.fingerprint(plan))throw conflict('WORKFLOW_SCHEDULE_BUSINESS_NOT_EXECUTABLE');
    this.usedAuthorities.add(authorityHandle);
    const executionId=randomUUID(),originId=randomUUID(),state:CompletionState={authorityHandle,namespaceHandle,executionId,originId,claimId:current.claim.id,
      scheduleId:current.claim.scheduleId,clusterId:plan.clusterId,workspaceId:plan.workspaceId,workflowId:plan.workflowId,planRevision:plan.planRevision,
      planHash:current.claim.workflowPlanHash,actorId:actor.user.id,permissionVersion:current.permissionVersion};
    const key=`scheduled-${current.claim.id}`,expiry=new Date(Math.min(Date.parse(plan.expiresAt),Date.parse(current.claim.authorityExpiresAt),Date.parse(current.authorityExpiresAt),Date.parse(current.leaseUntil))).toISOString();
    await this.d.db.transaction(async tx=>{
      await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');await this.inspect(authorityHandle,namespaceHandle,'claim',tx);
      const existing=await tx.one<any>('SELECT id FROM workflow_executions WHERE workflow_id=$1 AND plan_revision=$2',[plan.workflowId,plan.planRevision]);
      if(existing)throw conflict('WORKFLOW_SCHEDULE_BUSINESS_ALREADY_EXECUTED');
      cas(await tx.exec("UPDATE workflows SET state='executing',revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND state='approved' AND plan_revision=$3 AND plan_hash=$4",[plan.workflowId,loaded.row.revision,plan.planRevision,state.planHash]));
      await tx.exec(`INSERT INTO workflow_executions(id,cluster_id,workspace_id,workflow_id,plan_revision,plan_hash,execution_mode,approval_required,approved_by,execution_actor_id,state,claim_token_hash,request_id,idempotency_key,expires_at,approval_format,approval_set_id,approval_set_hmac,permission_version)
        VALUES($1,$2,$3,$4,$5,$6,$15,true,$7,$8,'executing',$9,NULL,$10,$11,2,$12,$13,$14)`,[executionId,plan.clusterId,plan.workspaceId,plan.workflowId,plan.planRevision,state.planHash,loaded.row.approved_by,actor.user.id,
          this.d.secrets.fingerprint(randomBytes(32).toString('base64url')),key,expiry,current.approvalSet.setId,current.approvalSet.setHmac,current.permissionVersion,plan.executionMode]);
      await tx.exec(`INSERT INTO workflow_execution_origins(id,cluster_id,workspace_id,schedule_id,claim_id,workflow_id,workflow_plan_revision,workflow_plan_hash,execution_id,executor_id)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[originId,plan.clusterId,plan.workspaceId,current.claim.scheduleId,current.claim.id,plan.workflowId,plan.planRevision,state.planHash,executionId,actor.user.id]);
      await this.d.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,
        action:'workflow.execute.requested',result:'pending',after:{origin:'scheduled-workflow',scheduleId:current.claim.scheduleId,claimId:current.claim.id,executionId},scopeHints:this.scopeHints(state)},tx);
      await this.d.redis.assertLeaseOwnership();
    });
    let succeeded=0;
    const observation=new WorkflowExecutionObservation(()=>this.d.context.currentScheduledWorkflowUsage());
    observation.mark('claimed');
    try {
      const snapshot=await this.d.redis.withLock(`mutation:${plan.scope.transportScope}`,()=>this.policy().captureSnapshot(authorityHandle,namespaceHandle,plan,executionId));
      observation.mark('snapshot');
      this.snapshot(plan,executionId,snapshot);await this.inspect(authorityHandle,namespaceHandle,'capture');
      observation.mark('snapshot-checked');
      cas(await this.d.db.exec("UPDATE workflow_executions SET snapshot_state='ready',snapshot_secret=$2,snapshot_hash=$3,snapshot_id=$4,revision=revision+1,updated_at=now() WHERE id=$1 AND snapshot_state='pending' AND state='executing' AND workflow_id=$5 AND plan_hash=$6",[executionId,this.d.secrets.encrypt(snapshot,snapshotAad(plan.clusterId,plan.workspaceId,plan.workflowId,executionId)),this.d.secrets.fingerprint(snapshot),randomUUID(),plan.workflowId,state.planHash]));
      await this.d.approved.runApprovedBusinessExecution(namespaceHandle,executionId,async()=>{
        for(const step of plan.steps){
          observation.mark('step-check',step.order);
          await this.inspect(authorityHandle,namespaceHandle,'step');
          observation.mark('step-ready',step.order);
          cas(await this.d.db.exec("UPDATE workflow_steps SET state='running',started_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='pending' AND workflow_id=$2 AND plan_revision=$3 AND plan_hash=$4",[step.id,plan.workflowId,plan.planRevision,state.planHash]));
          await this.d.context.runApprovedStep(step.id,async()=>{
            if(step.kind==='native'){
              const result=await this.d.dispatch(plan,step,actor),receipt=await this.d.mutations.inspectStepReceipt(this.d.mutationContext(plan,step,actor));
              observation.mark('native-complete',step.order);
              if(!receipt||receipt.state!=='succeeded'||receipt.remoteStarted!==true||receipt.remoteCompleted!==true)throw new ConflictException({code:'WORKFLOW_NATIVE_RECEIPT_MISSING',state:'uncertain'});
              const after=await this.policy().readNativeAfter(authorityHandle,namespaceHandle,plan,step,executionId),nativeId=step.nativeRequests[0]?.nativeId;
              observation.mark('readback-complete',step.order);
              if(!after||typeof after!=='object'||(after as any).id!==nativeId||receipt.entityId!==nativeId)throw conflict('WORKFLOW_SCHEDULE_NATIVE_READBACK_INVALID');
              await this.inspect(authorityHandle,namespaceHandle,'step');
              observation.mark('native-checked',step.order);
              cas(await this.d.db.exec("UPDATE workflow_steps SET state='succeeded',safe_result=$2::jsonb,receipt_secret=$3,after_fingerprint=$4,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='running' AND workflow_id=$5 AND plan_revision=$6 AND plan_hash=$7",[step.id,
                JSON.stringify({nativeOperationId:receipt.operationId,entityId:receipt.entityId,remoteStarted:true,remoteCompleted:true}),this.d.secrets.encrypt({receipt,result:this.d.secrets.redact(result)},`workflow:${executionId}:${step.id}:receipt`),this.d.secrets.fingerprint(after),plan.workflowId,plan.planRevision,state.planHash]));
            } else {
              observation.mark('metadata-prepare',step.order);
              const handler=this.d.registry.get(step.handler!);if(handler.prepare)await handler.prepare({plan,step,actor,executionId});
              observation.mark('metadata-prepared',step.order);
              await this.d.db.transaction(async tx=>{
                observation.mark('metadata-transaction',step.order);
                await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');await this.inspect(authorityHandle,namespaceHandle,'step',tx);
                observation.mark('metadata-inspected',step.order);
                const permissionVersion=await this.d.authz.permissionVersion(actor.user,tx),input={plan,step,actor,executionId,transaction:tx},before=await handler.inspect(input,tx);
                if(before.revision!==step.metadataRevision||this.d.secrets.fingerprint(before.before)!==step.metadataBeforeHmac)throw conflict('WORKFLOW_METADATA_CHANGED');
                await this.d.approved.assertStep({handler:step.handler!,actor:actor.user,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:step.entityType,
                  entityId:step.entityId!,before:before.before,revision:before.revision,payload:step.metadata},tx);
                observation.mark('metadata-authorized',step.order);
                const result=await handler.apply(input);
                observation.mark('metadata-applied',step.order);
                await this.d.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:step.entityType,entityId:step.entityId,workflowId:plan.workflowId,
                  action:step.handler!,before:workflowMetadataProjection(step.before),after:workflowMetadataProjection((result as any).entity??result),result:'success',
                  ...(plan.kind==='configuration_v2'?{scopeHints:{quality:'verified' as const,module:'snapshots',subject:{type:step.entityType,id:step.entityId!},beforeExists:step.before!=null,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:plan.workspaceId,afterWorkspaceId:plan.workspaceId}}:{})},tx);
                if(await this.d.authz.permissionVersion(actor.user,tx)!==permissionVersion||permissionVersion!==state.permissionVersion)throw deny('WORKFLOW_SCHEDULE_BUSINESS_PERMISSIONS_CHANGED');await this.d.redis.assertLeaseOwnership();
                cas(await tx.exec("UPDATE workflow_steps SET state='succeeded',safe_result=$2::jsonb,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='running' AND workflow_id=$3 AND plan_revision=$4 AND plan_hash=$5",[step.id,JSON.stringify(this.d.secrets.redact(result)),plan.workflowId,plan.planRevision,state.planHash]));
                if(step.order===plan.steps.length){
                  cas(await tx.exec("UPDATE workflow_executions SET state='succeeded',completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing' AND workflow_id=$2 AND plan_revision=$3 AND plan_hash=$4 AND execution_actor_id=$5",[executionId,plan.workflowId,plan.planRevision,state.planHash,actor.user.id]));
                  cas(await tx.exec("UPDATE workflows SET state='succeeded',revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing' AND plan_revision=$2 AND plan_hash=$3 AND revision=$4",[plan.workflowId,plan.planRevision,state.planHash,loaded.row.revision+1]));
                  await this.d.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,
                    action:'workflow.execute',result:'success',scopeHints:this.scopeHints(state)},tx);
                }
              });
            }
          });succeeded++;observation.mark('step-complete',step.order);
        }
      });
    } catch(error) {
      const response=error instanceof HttpException?error.getResponse():null,code=response&&typeof response==='object'&&'code'in response?String(response.code):'WORKFLOW_EXECUTION_FAILED';
      const active=await this.d.db.one<any>("SELECT * FROM workflow_steps WHERE workflow_id=$1 AND plan_revision=$2 AND plan_hash=$3 AND state='running' ORDER BY step_order LIMIT 1",[plan.workflowId,plan.planRevision,state.planHash]);
      let receipt:any=null,unknown=!(error instanceof HttpException)||error.getStatus()>=500||(response as any)?.state==='uncertain';
      if(active?.kind==='native'){const step=plan.steps.find(s=>s.id===active.id);if(!step)throw error;
        // A receipt probe can itself outlive the live execution context. Its
        // failure is unresolved, never evidence that the native write was absent.
        try{receipt=await this.d.mutations.inspectStepReceipt(this.d.mutationContext(plan,step,actor));unknown||=!!receipt&&['pending','running','uncertain'].includes(receipt.state);}
        catch{unknown=true;}
      }
      const terminal=unknown?'uncertain':succeeded||receipt?.remoteCompleted===true?'partial':'failed';
      observation.mark('failed',active?.step_order??0);
      try { this.logger.warn({event:'workflow_execution_observation',workflowId:plan.workflowId,executionId,kind:plan.kind,
        outcome:terminal,errorCode:/^[A-Z0-9_]{1,128}$/.test(code)?code:'WORKFLOW_EXECUTION_FAILED',...observation.snapshot()}); }
      catch { /* Preserve the original failure even if the log sink fails. */ }
      await this.d.db.transaction(async tx=>{
        if(active)cas(await tx.exec("UPDATE workflow_steps SET state=$2,error_code=$3,safe_result=$4::jsonb,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='running'",[active.id,unknown?'uncertain':'failed',/^[A-Z0-9_]{1,128}$/.test(code)?code:'WORKFLOW_EXECUTION_FAILED',JSON.stringify(receipt?{nativeOperationId:receipt.operationId,remoteStarted:receipt.remoteStarted,remoteCompleted:receipt.remoteCompleted}:{})]));
        cas(await tx.exec("UPDATE workflow_executions SET state=$2,completed_at=now(),revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing' AND workflow_id=$3 AND plan_hash=$4",[executionId,terminal,plan.workflowId,state.planHash]));
        cas(await tx.exec("UPDATE workflows SET state=$2,revision=revision+1,updated_at=now() WHERE id=$1 AND state='executing' AND plan_revision=$3 AND plan_hash=$4",[plan.workflowId,terminal,plan.planRevision,state.planHash]));
        await this.d.audit.append({actorId:actor.user.id,clusterId:plan.clusterId,workspaceId:plan.workspaceId,entityType:'workflows',entityId:plan.workflowId,workflowId:plan.workflowId,
          action:'workflow.execute',result:unknown?'uncertain':'failed',after:{code:/^[A-Z0-9_]{1,128}$/.test(code)?code:'WORKFLOW_EXECUTION_FAILED',state:terminal},scopeHints:this.scopeHints(state)},tx);
      });
    }
    const completion=Object.freeze({});this.completions.set(completion,Object.freeze(state));
    await this.verifyCompletion(authorityHandle,completion,this.d.db);return completion;
  }
  async verifyCompletion(authorityHandle: object, completion: object, tx: DbService): Promise<WorkflowScheduleTerminalOutcome> {
    const s=completion&&this.completions.get(completion);if(!s||s.authorityHandle!==authorityHandle)throw deny('WORKFLOW_SCHEDULE_ORIGINAL_COMPLETION_REQUIRED');
    const fact=await tx.one<any>(`SELECT e.*,w.state AS workflow_state,o.id AS origin_id,o.claim_id,o.schedule_id,o.executor_id
      FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id AND w.plan_revision=e.plan_revision AND w.plan_hash=e.plan_hash
      JOIN workflow_execution_origins o ON o.execution_id=e.id WHERE e.id=$1 AND e.cluster_id=$2 AND e.workspace_id=$3`,[s.executionId,s.clusterId,s.workspaceId]);
    if(!fact||fact.id!==s.executionId||fact.workflow_id!==s.workflowId||fact.plan_revision!==s.planRevision||fact.plan_hash!==s.planHash||fact.origin_id!==s.originId
      || fact.claim_id!==s.claimId||fact.schedule_id!==s.scheduleId||fact.executor_id!==s.actorId||fact.execution_actor_id!==s.actorId||fact.permission_version!==s.permissionVersion
      || !['succeeded','partial','failed','uncertain'].includes(fact.state)||fact.workflow_state!==fact.state)throw deny('WORKFLOW_SCHEDULE_COMPLETION_FACTS_CHANGED');
    const outcome=await this.policy().deriveCompletion(authorityHandle,s.executionId,tx);
    if(!['succeeded','partial','failed','uncertain'].includes(outcome)||outcome!==fact.state&&!(outcome==='partial'&&fact.state==='failed'))throw deny('WORKFLOW_SCHEDULE_COMPLETION_FACTS_CHANGED');
    return outcome;
  }
}
