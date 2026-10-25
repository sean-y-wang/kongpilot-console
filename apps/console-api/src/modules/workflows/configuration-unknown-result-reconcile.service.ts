import {BadRequestException,ConflictException,ForbiddenException,Injectable} from '@nestjs/common';
import {DbService} from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import {SecretService} from '../../infrastructure/secret.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {KongService} from '../../infrastructure/kong/kong.service';
import {currentEffectiveTarget} from '../../infrastructure/kong/effective-target';
import {AuthorizationService} from '../authorization/authorization.service';
import type {EntityActor} from '../entities/entities.types';
import {portalObject} from '../portal/portal-input';
import {UnknownResultDispositionService} from './unknown-result-disposition.service';
import {decideConfigurationTargetResult,decideConfigurationUnsentTargetResult,aggregateConfigurationUnsentDecisions,type ConfigurationTargetObservedEntry} from './configuration-unknown-result-decision';
import {SnapshotCryptoService} from '../config-storage/snapshot-crypto.service';
import {workflowId} from './workflow-validation';
import {AuditService} from '../audit/audit.service';
import {randomUUID} from 'node:crypto';

const deny=(code:string)=>new ForbiddenException({code});
const conflict=(code:string,extra:Record<string,unknown>={})=>new ConflictException({code,...extra});
const QUIESCENT_MS=30_000;
const HISTORY={maxPages:80,pageSize:100,maxBytes:24*1024*1024};

/** Supported, audited way out of an uncertain schedule-origin configuration_v2
 * targets mutation (e.g. sender paused/crashed mid-send → LOCK_LOST).
 * - approval-level operator only (workflow approve + upstream read, re-checked);
 * - zero Native writes: fresh Kong readback (effective + full history) decides;
 * - ambiguous ⇒ recorded verification-rejected disposition, state untouched;
 * - closure is state-only through SQL044/049 dispositions, so
 *   m8_validate_native_binding / m8_guard_mutation_binding hold by design. */
@Injectable()
export class ConfigurationUnknownResultReconcileService{
  constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly secrets:SecretService,
    private readonly execution:KongExecutionContextService,private readonly kong:KongService,private readonly authz:AuthorizationService,
    private readonly dispositions:UnknownResultDispositionService,private readonly crypto:SnapshotCryptoService,private readonly audit?:AuditService){}

  private async authority(actor:EntityActor,cid:string,wid:string):Promise<string>{
    await this.authz.assertCluster(actor.user,cid,'workflows','approve',wid);
    await this.authz.assertCluster(actor.user,cid,'upstreams','read',wid);
    return this.authz.permissionVersion(actor.user);
  }

  async reconcile(plan:{kind:string;clusterId:string;workspaceId:string;workflowId:string},body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    if(plan.kind!=='configuration_v2')throw conflict('CONFIGURATION_RECONCILE_PLAN_KIND');
    const value=portalObject(body,['mutationId','confirmed','reason']);
    if(value.confirmed!==true)throw new BadRequestException({code:'CONFIGURATION_RECONCILE_CONFIRMATION_REQUIRED'});
    const reason=typeof value.reason==='string'?value.reason.trim():'';
    if(!reason||reason.length>500)throw new BadRequestException({code:'CONFIGURATION_RECONCILE_REASON_REQUIRED'});
    const mutationId=workflowId(value.mutationId),cid=workflowId(plan.clusterId),wid=workflowId(plan.workspaceId);
    if(actor.workspaceId!==wid)throw deny('CONFIGURATION_RECONCILE_SCOPE');
    const permissionVersion=await this.authority(actor,cid,wid);
    const hint=await this.db.one<any>('SELECT transport_scope FROM mutation_operations WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4',[mutationId,cid,wid,plan.workflowId]);
    if(!hint?.transport_scope)throw conflict('CONFIGURATION_RECONCILE_MUTATION_NOT_FOUND');
    // Same locks a sender holds: no concurrent send/settle on this scope or workflow.
    return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.redis.withLock(`mutation:${hint.transport_scope}`,async()=>{
      const {m,link,observation,result,allocatedId}=await this.observe(plan,mutationId,actor,cid,wid,permissionVersion,hint.transport_scope);
      const reasonHmac=this.secrets.fingerprint({reason}),observationHmac=this.secrets.fingerprint(observation);
      const disposition=result.decision==='ambiguous'?'verification-rejected':result.decision;
      const requestHmac=this.secrets.fingerprint({kind:'configuration-unknown-result-reconcile-v1',cid,wid,workflowId:plan.workflowId,mutationId,actorId:actor.user.id,reasonHmac,observedAt:observation.observedAt});
      const evidenceHmac=this.secrets.fingerprint({version:1,contract:'kong-1.5-configuration-target-unknown-result-readback-v1',mutationId,allocatedId,
        decision:result.decision,reason:result.reason,observationHmac});
      const disposed=await this.dispositions.dispose(cid,wid,{version:1,disposition,scheduleId:link.schedule_id,claimId:link.claim_id,workflowId:plan.workflowId,
        workflowExecutionId:link.workflow_execution_id,workflowPlanRevision:link.workflow_plan_revision,workflowPlanHash:link.workflow_plan_hash,requestHmac,evidenceHmac,
        original:{executionState:'uncertain',mutationId,mutationState:'uncertain',remoteStarted:m.remote_started,remoteCompleted:m.remote_completed,errorCode:m.error_code??null},
        nativeRequestsSent:0},actor,{contract:'configuration-v2-targets',configurationExecutionId:m.configuration_execution_id,decision:result.decision,
        decisionReason:result.reason,observationHmac,reasonHmac,effectiveBudget:observation.effectiveBudget,historyBudget:observation.historyBudget});
      const receipt={workflowId:plan.workflowId,executionId:link.workflow_execution_id,mutationId,decision:result.decision,decisionReason:result.reason,
        dispositionId:disposed.dispositionId,disposition,nativeRequestsSent:0,observationHmac};
      if(result.decision==='ambiguous')throw conflict('CONFIGURATION_RECONCILE_AMBIGUOUS',receipt);
      return {...receipt,mutationState:result.decision==='verified-applied'?'succeeded':'failed'};
    }));
  }


  private input(body:unknown,keys:string[]){
    const value=portalObject(body,keys);
    if(value.confirmed!==true)throw new BadRequestException({code:'CONFIGURATION_RECONCILE_CONFIRMATION_REQUIRED'});
    return value;
  }

  /** Two-person abandon, step 1: an unprovable (ambiguous) mutation may be proposed for
   * failed-unknown closure. Records the fresh readback; zero Native writes; 24h expiry. */
  async requestAbandon(plan:{kind:string;clusterId:string;workspaceId:string;workflowId:string},body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    if(plan.kind!=='configuration_v2')throw conflict('CONFIGURATION_RECONCILE_PLAN_KIND');
    if(!this.audit)throw conflict('CONFIGURATION_ABANDON_UNAVAILABLE');
    const value=this.input(body,['mutationId','confirmed','reason','ticket']);
    const reason=typeof value.reason==='string'?value.reason.trim():'';
    if(!reason||reason.length>500)throw new BadRequestException({code:'CONFIGURATION_RECONCILE_REASON_REQUIRED'});
    const ticket=typeof value.ticket==='string'?value.ticket.trim():'';
    if(!ticket||ticket.length>200||!/^[\w.:#\/-]+$/.test(ticket))throw new BadRequestException({code:'CONFIGURATION_ABANDON_TICKET_REQUIRED'});
    const mutationId=workflowId(value.mutationId),cid=workflowId(plan.clusterId),wid=workflowId(plan.workspaceId);
    if(actor.workspaceId!==wid)throw deny('CONFIGURATION_RECONCILE_SCOPE');
    const permissionVersion=await this.authority(actor,cid,wid);
    const sessionId=this.execution.current()?.sessionId;if(!sessionId)throw deny('CONFIGURATION_ABANDON_SESSION_REQUIRED');
    const hint=await this.scopeHint(mutationId,cid,wid,plan.workflowId);
    return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.redis.withLock(`mutation:${hint}`,async()=>{
      const {link,observation,result}=await this.observe(plan,mutationId,actor,cid,wid,permissionVersion,hint);
      const observationHmac=this.secrets.fingerprint(observation);
      if(result.decision!=='ambiguous')throw conflict('CONFIGURATION_ABANDON_PROVABLE',{decision:result.decision,observationHmac});
      const id=randomUUID(),reasonHmac=this.secrets.fingerprint({reason});
      const audit=this.audit!;
      await this.db.transaction(async tx=>{
        const a=await audit.append({actorId:actor.user.id,clusterId:cid,workspaceId:wid,workflowId:plan.workflowId,entityType:'workflows',entityId:plan.workflowId,
          action:'workflow.unknown-result.abandon-requested',result:'success',requestId:actor.requestId,ip:actor.ip,
          after:{requestId:id,mutationId,executionId:link.workflow_execution_id,ticket,reasonHmac,observationHmac,decisionReason:result.reason,
            effectiveBudget:observation.effectiveBudget,historyBudget:observation.historyBudget,nativeRequestsSent:0},
          scopeHints:{quality:'verified',module:'workflows',subject:{type:'workflows',id:plan.workflowId},beforeExists:true,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:wid,afterWorkspaceId:wid}},tx);
        await tx.exec(`INSERT INTO workflow_unknown_result_abandon_requests(id,cluster_id,workspace_id,mutation_id,workflow_execution_id,requester_id,session_id,
          reason_hmac,ticket,observation_hmac,audit_id,audit_event_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp()+interval '24 hours')`,
          [id,cid,wid,mutationId,link.workflow_execution_id,actor.user.id,sessionId,reasonHmac,ticket,observationHmac,a.id,a.eventHash]);
      });
      return {requestId:id,mutationId,decisionReason:result.reason,observationHmac,ticket,nativeRequestsSent:0,status:'awaiting-second-approver'};
    }));
  }

  /** Two-person abandon, step 2: a different approver re-reads Kong (must still be
   * ambiguous) and closes the mutation as failed-unknown via an 'abandoned' disposition. */
  async confirmAbandon(plan:{kind:string;clusterId:string;workspaceId:string;workflowId:string},body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    if(plan.kind!=='configuration_v2')throw conflict('CONFIGURATION_RECONCILE_PLAN_KIND');
    const value=this.input(body,['requestId','confirmed']);
    const requestId=workflowId(value.requestId),cid=workflowId(plan.clusterId),wid=workflowId(plan.workspaceId);
    if(actor.workspaceId!==wid)throw deny('CONFIGURATION_RECONCILE_SCOPE');
    const permissionVersion=await this.authority(actor,cid,wid);
    const r=await this.db.one<any>(`SELECT *,(expires_at<=clock_timestamp()) AS expired FROM workflow_unknown_result_abandon_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`,[requestId,cid,wid]);
    if(!r||r.consumed_at||r.expired)throw conflict('CONFIGURATION_ABANDON_REQUEST_NOT_OPEN');
    if(r.requester_id===actor.user.id)throw deny('CONFIGURATION_ABANDON_SECOND_APPROVER_REQUIRED');
    const hint=await this.scopeHint(r.mutation_id,cid,wid,plan.workflowId);
    return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.redis.withLock(`mutation:${hint}`,async()=>{
      const {m,link,observation,result,allocatedId}=await this.observe(plan,r.mutation_id,actor,cid,wid,permissionVersion,hint);
      const observationHmac=this.secrets.fingerprint(observation);
      if(link.workflow_execution_id!==r.workflow_execution_id)throw conflict('CONFIGURATION_ABANDON_REQUEST_NOT_OPEN');
      if(result.decision!=='ambiguous')throw conflict('CONFIGURATION_ABANDON_PROVABLE',{decision:result.decision,observationHmac});
      const requestHmac=this.secrets.fingerprint({kind:'configuration-unknown-result-abandon-v1',cid,wid,workflowId:plan.workflowId,mutationId:r.mutation_id,requestId,
        requesterId:r.requester_id,actorId:actor.user.id,observedAt:observation.observedAt});
      const evidenceHmac=this.secrets.fingerprint({version:1,contract:'kong-1.5-configuration-target-unknown-result-abandon-v1',mutationId:r.mutation_id,allocatedId,
        decision:'abandoned',reason:result.reason,observationHmac,requestObservationHmac:r.observation_hmac});
      const disposed=await this.dispositions.dispose(cid,wid,{version:1,disposition:'abandoned',abandonRequestId:requestId,scheduleId:link.schedule_id,claimId:link.claim_id,
        workflowId:plan.workflowId,workflowExecutionId:link.workflow_execution_id,workflowPlanRevision:link.workflow_plan_revision,workflowPlanHash:link.workflow_plan_hash,requestHmac,evidenceHmac,
        original:{executionState:'uncertain',mutationId:r.mutation_id,mutationState:'uncertain',remoteStarted:m.remote_started,remoteCompleted:m.remote_completed,errorCode:m.error_code??null},
        nativeRequestsSent:0},actor,{contract:'configuration-v2-targets',configurationExecutionId:m.configuration_execution_id,abandonRequestId:requestId,requesterId:r.requester_id,
        ticket:r.ticket,decisionReason:result.reason,observationHmac,requestObservationHmac:r.observation_hmac,effectiveBudget:observation.effectiveBudget,historyBudget:observation.historyBudget});
      return {requestId,mutationId:r.mutation_id,dispositionId:disposed.dispositionId,disposition:'abandoned',mutationState:'failed',outcome:'failed-unknown',
        requesterId:r.requester_id,approverId:actor.user.id,decisionReason:result.reason,observationHmac,nativeRequestsSent:0};
    }));
  }

  private async scopeHint(mutationId:string,cid:string,wid:string,wf:string):Promise<string>{
    const hint=await this.db.one<any>('SELECT transport_scope FROM mutation_operations WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4',[mutationId,cid,wid,wf]);
    if(!hint?.transport_scope)throw conflict('CONFIGURATION_RECONCILE_MUTATION_NOT_FOUND');
    return hint.transport_scope;
  }


  /** Approval-level settle for an uncertain schedule-origin configuration_v2 job
   * that never opened a mutation_operations row (remote send never started).
   * Fresh Kong readback only; never writes Kong; fails closed if a mutation appears. */
  async reconcileUnsent(plan:{kind:string;clusterId:string;workspaceId:string;workflowId:string},body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    if(plan.kind!=='configuration_v2')throw conflict('CONFIGURATION_RECONCILE_PLAN_KIND');
    const value=portalObject(body,['confirmed','reason']);
    if(value.confirmed!==true)throw new BadRequestException({code:'CONFIGURATION_RECONCILE_CONFIRMATION_REQUIRED'});
    const reason=typeof value.reason==='string'?value.reason.trim():'';
    if(!reason||reason.length>500)throw new BadRequestException({code:'CONFIGURATION_RECONCILE_REASON_REQUIRED'});
    const cid=workflowId(plan.clusterId),wid=workflowId(plan.workspaceId);
    if(actor.workspaceId!==wid)throw deny('CONFIGURATION_RECONCILE_SCOPE');
    const permissionVersion=await this.authority(actor,cid,wid);
    const hint=await this.unsentScopeHint(plan.workflowId,cid,wid);
    return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.redis.withLock(`mutation:${hint.transport_scope}`,async()=>{
      const observed=await this.observeUnsent(plan,actor,cid,wid,permissionVersion,hint);
      if(observed.aggregate.decision==='appears-applied')throw conflict('CONFIGURATION_UNSENT_APPEARS_APPLIED',{decisionReason:observed.aggregate.reason,observationHmac:observed.observationHmac});
      const disposition=observed.aggregate.decision==='ambiguous'?'verification-rejected':'verified-not-applied';
      const reasonHmac=this.secrets.fingerprint({reason}),observationHmac=observed.observationHmac;
      const requestHmac=this.secrets.fingerprint({kind:'configuration-unsent-result-reconcile-v1',cid,wid,workflowId:plan.workflowId,jobId:hint.job_id,actorId:actor.user.id,reasonHmac,observedAt:observed.observation.observedAt});
      const evidenceHmac=this.secrets.fingerprint({version:1,contract:'kong-1.5-configuration-unsent-result-readback-v1',jobId:hint.job_id,
        decision:observed.aggregate.decision,reason:observed.aggregate.reason,observationHmac});
      const disposed=await this.dispositions.dispose(cid,wid,{version:1,disposition,scheduleId:observed.link.schedule_id,claimId:observed.link.claim_id,workflowId:plan.workflowId,
        workflowExecutionId:observed.link.workflow_execution_id,workflowPlanRevision:observed.link.workflow_plan_revision,workflowPlanHash:observed.link.workflow_plan_hash,requestHmac,evidenceHmac,
        original:{executionState:'uncertain'},nativeRequestsSent:0,...(disposition==='verified-not-applied'?{unsentJobId:hint.job_id}:{})},actor,
        {contract:'configuration-v2-unsent',decision:observed.aggregate.decision,decisionReason:observed.aggregate.reason,observationHmac,reasonHmac,
          knownNoNativeSend:true,unsentJobId:hint.job_id,effectiveBudget:observed.observation.effectiveBudget,historyBudget:observed.observation.historyBudget});
      const receipt={workflowId:plan.workflowId,executionId:observed.link.workflow_execution_id,jobId:hint.job_id,decision:observed.aggregate.decision,decisionReason:observed.aggregate.reason,
        dispositionId:disposed.dispositionId,disposition,knownNoNativeSend:true,nativeRequestsSent:0,observationHmac};
      if(observed.aggregate.decision==='ambiguous')throw conflict('CONFIGURATION_UNSENT_AMBIGUOUS',receipt);
      return {...receipt,workflowState:'failed',jobState:'failed'};
    }));
  }

  /** Two-person abandon for an unprovable never-sent uncertain job (step 1). */
  async requestUnsentAbandon(plan:{kind:string;clusterId:string;workspaceId:string;workflowId:string},body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    if(plan.kind!=='configuration_v2')throw conflict('CONFIGURATION_RECONCILE_PLAN_KIND');
    if(!this.audit)throw conflict('CONFIGURATION_ABANDON_UNAVAILABLE');
    const value=this.input(body,['confirmed','reason','ticket']);
    const reason=typeof value.reason==='string'?value.reason.trim():'';
    if(!reason||reason.length>500)throw new BadRequestException({code:'CONFIGURATION_RECONCILE_REASON_REQUIRED'});
    const ticket=typeof value.ticket==='string'?value.ticket.trim():'';
    if(!ticket||ticket.length>200||!/^[\w.:#\/-]+$/.test(ticket))throw new BadRequestException({code:'CONFIGURATION_ABANDON_TICKET_REQUIRED'});
    const cid=workflowId(plan.clusterId),wid=workflowId(plan.workspaceId);
    if(actor.workspaceId!==wid)throw deny('CONFIGURATION_RECONCILE_SCOPE');
    const permissionVersion=await this.authority(actor,cid,wid);
    const sessionId=this.execution.current()?.sessionId;if(!sessionId)throw deny('CONFIGURATION_ABANDON_SESSION_REQUIRED');
    const hint=await this.unsentScopeHint(plan.workflowId,cid,wid);
    return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.redis.withLock(`mutation:${hint.transport_scope}`,async()=>{
      const observed=await this.observeUnsent(plan,actor,cid,wid,permissionVersion,hint);
      if(observed.aggregate.decision==='appears-applied')throw conflict('CONFIGURATION_UNSENT_APPEARS_APPLIED',{observationHmac:observed.observationHmac});
      if(observed.aggregate.decision!=='ambiguous')throw conflict('CONFIGURATION_ABANDON_PROVABLE',{decision:observed.aggregate.decision,observationHmac:observed.observationHmac});
      const id=randomUUID(),reasonHmac=this.secrets.fingerprint({reason}),observationHmac=observed.observationHmac;
      await this.db.transaction(async tx=>{
        const a=await this.audit!.append({actorId:actor.user.id,clusterId:cid,workspaceId:wid,workflowId:plan.workflowId,entityType:'workflows',entityId:plan.workflowId,
          action:'workflow.unsent-result.abandon-requested',result:'success',requestId:actor.requestId,ip:actor.ip,
          after:{requestId:id,executionId:observed.link.workflow_execution_id,jobId:hint.job_id,ticket,reasonHmac,observationHmac,decisionReason:observed.aggregate.reason,
            knownNoNativeSend:true,nativeRequestsSent:0,effectiveBudget:observed.observation.effectiveBudget,historyBudget:observed.observation.historyBudget},
          scopeHints:{quality:'verified',module:'workflows',subject:{type:'workflows',id:plan.workflowId},beforeExists:true,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:wid,afterWorkspaceId:wid}},tx);
        await tx.exec(`INSERT INTO workflow_unsent_result_abandon_requests(id,cluster_id,workspace_id,workflow_id,workflow_execution_id,configuration_job_id,requester_id,session_id,
          reason_hmac,ticket,observation_hmac,audit_id,audit_event_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,clock_timestamp()+interval '24 hours')`,
          [id,cid,wid,plan.workflowId,observed.link.workflow_execution_id,hint.job_id,actor.user.id,sessionId,reasonHmac,ticket,observationHmac,a.id,a.eventHash]);
      });
      return {requestId:id,jobId:hint.job_id,decisionReason:observed.aggregate.reason,observationHmac,ticket,knownNoNativeSend:true,nativeRequestsSent:0,status:'awaiting-second-approver'};
    }));
  }

  /** Two-person abandon for never-sent uncertain job (step 2). */
  async confirmUnsentAbandon(plan:{kind:string;clusterId:string;workspaceId:string;workflowId:string},body:unknown,actor:EntityActor):Promise<Record<string,unknown>>{
    if(plan.kind!=='configuration_v2')throw conflict('CONFIGURATION_RECONCILE_PLAN_KIND');
    const value=this.input(body,['requestId','confirmed']);
    const requestId=workflowId(value.requestId),cid=workflowId(plan.clusterId),wid=workflowId(plan.workspaceId);
    if(actor.workspaceId!==wid)throw deny('CONFIGURATION_RECONCILE_SCOPE');
    const permissionVersion=await this.authority(actor,cid,wid);
    const r=await this.db.one<any>(`SELECT *,(expires_at<=clock_timestamp()) AS expired FROM workflow_unsent_result_abandon_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3`,[requestId,cid,wid]);
    if(!r||r.consumed_at||r.expired||r.workflow_id!==plan.workflowId)throw conflict('CONFIGURATION_ABANDON_REQUEST_NOT_OPEN');
    if(r.requester_id===actor.user.id)throw deny('CONFIGURATION_ABANDON_SECOND_APPROVER_REQUIRED');
    const hint=await this.unsentScopeHint(plan.workflowId,cid,wid);
    if(hint.job_id!==r.configuration_job_id)throw conflict('CONFIGURATION_ABANDON_REQUEST_NOT_OPEN');
    return this.redis.withLock(`workflow:${plan.workflowId}`,()=>this.redis.withLock(`mutation:${hint.transport_scope}`,async()=>{
      const observed=await this.observeUnsent(plan,actor,cid,wid,permissionVersion,hint);
      const observationHmac=observed.observationHmac;
      if(observed.link.workflow_execution_id!==r.workflow_execution_id)throw conflict('CONFIGURATION_ABANDON_REQUEST_NOT_OPEN');
      if(observed.aggregate.decision==='appears-applied')throw conflict('CONFIGURATION_UNSENT_APPEARS_APPLIED',{observationHmac});
      if(observed.aggregate.decision!=='ambiguous')throw conflict('CONFIGURATION_ABANDON_PROVABLE',{decision:observed.aggregate.decision,observationHmac});
      const requestHmac=this.secrets.fingerprint({kind:'configuration-unsent-result-abandon-v1',cid,wid,workflowId:plan.workflowId,jobId:hint.job_id,requestId,
        requesterId:r.requester_id,actorId:actor.user.id,observedAt:observed.observation.observedAt});
      const evidenceHmac=this.secrets.fingerprint({version:1,contract:'kong-1.5-configuration-unsent-result-abandon-v1',jobId:hint.job_id,
        decision:'abandoned',reason:observed.aggregate.reason,observationHmac,requestObservationHmac:r.observation_hmac});
      const disposed=await this.dispositions.dispose(cid,wid,{version:1,disposition:'abandoned',unsentAbandonRequestId:requestId,unsentJobId:hint.job_id,
        scheduleId:observed.link.schedule_id,claimId:observed.link.claim_id,workflowId:plan.workflowId,workflowExecutionId:observed.link.workflow_execution_id,
        workflowPlanRevision:observed.link.workflow_plan_revision,workflowPlanHash:observed.link.workflow_plan_hash,requestHmac,evidenceHmac,
        original:{executionState:'uncertain'},nativeRequestsSent:0},actor,
        {contract:'configuration-v2-unsent',unsentAbandonRequestId:requestId,requesterId:r.requester_id,ticket:r.ticket,decisionReason:observed.aggregate.reason,
          observationHmac,requestObservationHmac:r.observation_hmac,knownNoNativeSend:true,unsentJobId:hint.job_id,
          effectiveBudget:observed.observation.effectiveBudget,historyBudget:observed.observation.historyBudget});
      return {requestId,jobId:hint.job_id,dispositionId:disposed.dispositionId,disposition:'abandoned',workflowState:'failed',jobState:'failed',outcome:'failed-unknown',
        requesterId:r.requester_id,approverId:actor.user.id,decisionReason:observed.aggregate.reason,observationHmac,knownNoNativeSend:true,nativeRequestsSent:0};
    }));
  }

  private async unsentScopeHint(wf:string,cid:string,wid:string){
    const job=await this.db.one<any>(`SELECT id AS job_id,transport_scope,state,remote_started,lease_until,plan_id,plan_revision,plan_hash,updated_at
      FROM configuration_jobs WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3`,[wf,cid,wid]);
    if(!job||!['running','uncertain'].includes(job.state)||job.remote_started!==false||!job.transport_scope)
      throw conflict('CONFIGURATION_UNSENT_JOB_NOT_FOUND');
    const mutation=await this.db.one<any>('SELECT 1 AS ok FROM mutation_operations WHERE workflow_id=$1 OR configuration_job_id=$2 LIMIT 1',[wf,job.job_id]);
    if(mutation)throw conflict('CONFIGURATION_UNSENT_MUTATION_PRESENT');
    return job;
  }

  private async observeUnsent(plan:{workflowId:string},actor:EntityActor,cid:string,wid:string,permissionVersion:string,hint:any){
    const job=await this.db.one<any>(`SELECT j.*,(j.updated_at<clock_timestamp()-make_interval(secs=>$4::double precision/1000)) AS quiescent,
        (j.lease_until IS NULL OR j.lease_until<clock_timestamp()) AS lease_expired
      FROM configuration_jobs j WHERE j.id=$1 AND j.cluster_id=$2 AND j.workspace_id=$3 AND j.workflow_id=$5`,
      [hint.job_id,cid,wid,QUIESCENT_MS,plan.workflowId]);
    if(!job||!['running','uncertain'].includes(job.state)||job.remote_started!==false||job.transport_scope!==hint.transport_scope)
      throw conflict('CONFIGURATION_UNSENT_JOB_NOT_FOUND');
    if(!job.lease_expired)throw conflict('CONFIGURATION_RECONCILE_LEASE_ACTIVE');
    if(!job.quiescent)throw conflict('CONFIGURATION_RECONCILE_NOT_QUIESCENT');
    const mutation=await this.db.one<any>('SELECT 1 AS ok FROM mutation_operations WHERE workflow_id=$1 OR configuration_job_id=$2 LIMIT 1',[plan.workflowId,job.id]);
    if(mutation)throw conflict('CONFIGURATION_UNSENT_MUTATION_PRESENT');
    // Never-sent path: no configuration_executions / origin link; schedule origin is on the workflow execution.
    const link=await this.db.one<any>(`SELECT e.id AS workflow_execution_id,o.claim_id,e.workflow_id,e.plan_revision AS workflow_plan_revision,e.plan_hash AS workflow_plan_hash,
        o.schedule_id,e.state AS execution_state,w.state AS workflow_state
      FROM workflow_executions e
      JOIN workflows w ON w.id=e.workflow_id
      JOIN workflow_execution_origins o ON o.execution_id=e.id
      WHERE e.workflow_id=$1 AND e.cluster_id=$2 AND e.workspace_id=$3 AND e.state='uncertain' AND w.state='uncertain'
      ORDER BY e.updated_at DESC LIMIT 1`,[plan.workflowId,cid,wid]);
    if(!link)throw conflict('CONFIGURATION_RECONCILE_ORIGIN_REQUIRED');
    const objects=await this.db.query<any>(`SELECT * FROM configuration_plan_objects
      WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5 ORDER BY step_order`,
      [cid,wid,job.plan_id,job.plan_revision,job.plan_hash]);
    if(!objects.length)throw conflict('CONFIGURATION_UNSENT_PLAN_EMPTY');
    if(objects.some((o:any)=>o.entity_type!=='targets'||!['create','update'].includes(o.mutation_action)||!o.allocated_native_id||!o.parent_id))
      throw conflict('CONFIGURATION_RECONCILE_UNSUPPORTED_ENTITY');
    // Decrypt plan steps only when at least one parent is still present (need address/weight/before).
    const steps=await this.loadUnsentSteps(cid,wid,job,objects);
    const stepResults=[];
    let effectiveBudget={pages:0,records:0,bytes:0},historyBudget={pages:0,records:0,bytes:0};
    const observedAt=new Date().toISOString();
    for(const step of steps){
      const base=`/upstreams/${encodeURIComponent(step.parentId)}`;
      const observation=await this.execution.runInternalRead(cid,'operation-check',async()=>{
        try{await this.kong.request(cid,'GET',base);}catch(error){
          if((error as any)?.getStatus?.()!==404)throw error;
          return Object.freeze({parentAbsent:true as const,effective:null,effectiveBudget:{pages:0,records:0,bytes:0},historyAllocated:Object.freeze([] as ConfigurationTargetObservedEntry[]),
            historyComplete:false,historyBudget:{pages:0,records:0,bytes:0},observedAt});
        }
        const effectiveRead=await currentEffectiveTarget(this.kong,cid,step.parentId,step.address,{maxPages:40});
        const history=await this.history(cid,base,step.allocatedId);
        return Object.freeze({parentAbsent:false as const,effective:effectiveRead.target?entry(effectiveRead.target):null,effectiveBudget:effectiveRead.budget,...history,observedAt});
      },{paths:[base,`${base}/targets`,`${base}/targets/all`],workspaceId:wid,maxCalls:200,maxPages:80,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000});
      effectiveBudget=observation.effectiveBudget;historyBudget=observation.historyBudget;
      stepResults.push(decideConfigurationUnsentTargetResult({action:step.action,address:step.address,desiredWeight:step.desiredWeight,allocatedId:step.allocatedId,
        before:step.before,effective:observation.effective,historyAllocated:observation.historyAllocated,historyComplete:observation.historyComplete,
        effectiveComplete:!observation.parentAbsent,parentAbsent:observation.parentAbsent}));
    }
    const aggregate=aggregateConfigurationUnsentDecisions(stepResults);
    if(await this.authority(actor,cid,wid)!==permissionVersion)throw deny('CONFIGURATION_RECONCILE_PERMISSIONS_CHANGED');
    // Final fail-closed mutation presence check before returning.
    const raced=await this.db.one<any>('SELECT 1 AS ok FROM mutation_operations WHERE workflow_id=$1 OR configuration_job_id=$2 LIMIT 1',[plan.workflowId,job.id]);
    if(raced)throw conflict('CONFIGURATION_UNSENT_MUTATION_PRESENT');
    await this.redis.assertLeaseOwnership();
    const observation=Object.freeze({observedAt,effectiveBudget,historyBudget,steps:stepResults.map(s=>({decision:s.decision,reason:s.reason}))});
    return {link,observation,aggregate,observationHmac:this.secrets.fingerprint(observation),job};
  }

  private async loadUnsentSteps(cid:string,wid:string,job:any,objects:any[]){
    const version=await this.db.one<any>(`SELECT * FROM configuration_plan_versions WHERE cluster_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_revision=$4 AND plan_hash=$5`,
      [cid,wid,job.plan_id,job.plan_revision,job.plan_hash]);
    const material=version&&await this.db.one<any>('SELECT * FROM configuration_materials WHERE cluster_id=$1 AND workspace_id=$2 AND id=$3',[cid,wid,version.material_id]);
    if(!version||!material||material.state!=='available'||!material.wrapped_key_secret||material.job_id!==version.source_job_id)
      throw conflict('CONFIGURATION_UNSENT_PLAN_INVALID');
    const identity={clusterId:cid,workspaceId:wid,jobId:version.source_job_id,materialId:material.id,artifactId:version.artifact_id,artifactKind:'plan' as const};
    const planDoc=await this.crypto.withKey(identity,material.wrapped_key_secret,async key=>this.crypto.decrypt<any>(key,identity,{section:'manifest',key:'plan'},version.manifest_ciphertext));
    if(this.secrets.fingerprint(planDoc)!==job.plan_hash||!Array.isArray(planDoc.steps)||planDoc.steps.length!==objects.length)
      throw conflict('CONFIGURATION_UNSENT_PLAN_INVALID');
    const steps:{action:'create'|'update';parentId:string;allocatedId:string;address:string;desiredWeight:number;before:ConfigurationTargetObservedEntry|null}[]=[];
    await this.crypto.withKey(identity,material.wrapped_key_secret,async key=>{
      for(let i=0;i<objects.length;i++){
        const object=objects[i],step=planDoc.steps[i];
        const sealed=this.crypto.decrypt(key,identity,{section:'plan-step',key:step.stepId,entityType:step.entityType,
          nativeId:step.nativeId??step.allocatedNativeId??null,parentId:step.parentId??null,credentialKind:step.credentialKind??null},object.payload_ciphertext);
        if(this.secrets.fingerprint(sealed)!==this.secrets.fingerprint(step)||object.step_id!==step.stepId)
          throw conflict('CONFIGURATION_UNSENT_PLAN_INVALID');
        const action=step.mutationAction as 'create'|'update';
        const body=step.body??null,beforeRaw=step.before??null;
        const before=action==='update'?entry(beforeRaw):null;
        const address=action==='update'?before!.target:(body as any)?.target;
        const desiredWeight=(body as any)?.weight===undefined?100:(body as any).weight;
        if(typeof address!=='string'||!address||!Number.isInteger(desiredWeight))throw conflict('CONFIGURATION_UNSENT_PLAN_INVALID');
        if(action==='update'&&(!before||before.id!==String(object.native_id)))throw conflict('CONFIGURATION_UNSENT_PLAN_INVALID');
        steps.push({action,parentId:String(object.parent_id),allocatedId:String(object.allocated_native_id),address,desiredWeight,before});
      }
    });
    return steps;
  }

  /** Shared fail-closed preconditions + fresh Kong readback (caller holds workflow and scope locks). */
  private async observe(plan:{workflowId:string},mutationId:string,actor:EntityActor,cid:string,wid:string,permissionVersion:string,transportScope:string){
      const m=await this.db.one<any>(`SELECT m.*,(m.updated_at<clock_timestamp()-make_interval(secs=>$5::double precision/1000)) AS quiescent FROM mutation_operations m
        WHERE m.id=$1 AND m.cluster_id=$2 AND m.workspace_id=$3 AND m.workflow_id=$4`,[mutationId,cid,wid,plan.workflowId,QUIESCENT_MS]);
      if(!m||m.state!=='uncertain'||m.workflow_execution_id!==null||!m.configuration_execution_id||!m.configuration_step_id||m.transport_scope!==transportScope)
        throw conflict('CONFIGURATION_RECONCILE_NOT_UNCERTAIN');
      if(!m.quiescent)throw conflict('CONFIGURATION_RECONCILE_NOT_QUIESCENT');
      if(m.entity_type!=='targets'||!['create','update'].includes(m.action))throw conflict('CONFIGURATION_RECONCILE_UNSUPPORTED_ENTITY');
      const link=await this.db.one<any>(`SELECT x.workflow_execution_id,x.claim_id,x.workflow_id,x.workflow_plan_revision,x.workflow_plan_hash,o.schedule_id,
          e.state AS execution_state,ce.state AS configuration_state,(ce.expires_at<clock_timestamp()) AS lease_expired
        FROM workflow_configuration_execution_origins x
        JOIN configuration_executions ce ON ce.id=x.configuration_execution_id
        JOIN workflow_executions e ON e.id=x.workflow_execution_id
        JOIN workflow_execution_origins o ON o.execution_id=e.id AND o.claim_id=x.claim_id
        WHERE x.configuration_execution_id=$1 AND x.cluster_id=$2 AND x.workspace_id=$3 AND x.workflow_id=$4
          AND e.workflow_id=x.workflow_id AND e.plan_revision=x.workflow_plan_revision AND e.plan_hash=x.workflow_plan_hash`,
        [m.configuration_execution_id,cid,wid,plan.workflowId]);
      if(!link)throw conflict('CONFIGURATION_RECONCILE_ORIGIN_REQUIRED');
      if(link.execution_state!=='uncertain'||link.configuration_state!=='uncertain')throw conflict('CONFIGURATION_RECONCILE_NOT_UNCERTAIN');
      if(!link.lease_expired)throw conflict('CONFIGURATION_RECONCILE_LEASE_ACTIVE');
      const siblings=await this.db.query<any>('SELECT state FROM mutation_operations WHERE configuration_execution_id=$1 AND id<>$2',[m.configuration_execution_id,m.id]);
      if(siblings.some(s=>!['succeeded','failed'].includes(s.state)))throw conflict('CONFIGURATION_RECONCILE_SIBLINGS_PENDING');
      const p=await this.db.one<any>(`SELECT p.native_id,p.allocated_native_id,p.parent_id,p.body_hmac,p.before_hmac,p.entity_type,p.mutation_action FROM configuration_job_steps s
        JOIN configuration_plan_objects p ON p.cluster_id=s.cluster_id AND p.workspace_id=s.workspace_id AND p.plan_id=s.plan_id AND p.plan_revision=s.plan_revision AND p.step_id=s.plan_step_id
        WHERE s.id=$1 AND s.execution_id=$2`,[m.configuration_step_id,m.configuration_execution_id]);
      if(!p||p.entity_type!=='targets'||p.mutation_action!==m.action||!p.allocated_native_id||!p.parent_id||String(p.parent_id)!==m.parent_id)
        throw conflict('CONFIGURATION_RECONCILE_PLAN_OBJECT_MISMATCH');
      const payload=m.payload_secret?this.secrets.decrypt(m.payload_secret,`mutation:${m.id}:payload`):null;
      const before=m.before_secret?this.secrets.decrypt(m.before_secret,`mutation:${m.id}:before`):null;
      if(!payload||this.secrets.fingerprint(payload)!==p.body_hmac||this.secrets.fingerprint(before)!==p.before_hmac)throw conflict('CONFIGURATION_RECONCILE_RECEIPT_MISMATCH');
      const upstreamId=String(p.parent_id),allocatedId=String(p.allocated_native_id);
      const beforeEntry=m.action==='update'?entry(before):null;
      if(m.action==='update'&&(!beforeEntry||beforeEntry.id!==String(p.native_id)))throw conflict('CONFIGURATION_RECONCILE_RECEIPT_MISMATCH');
      const address=m.action==='update'?beforeEntry!.target:(payload as any)?.target;
      const desiredWeight=(payload as any)?.weight===undefined?100:(payload as any).weight;
      const base=`/upstreams/${encodeURIComponent(upstreamId)}`;
      const observation=await this.execution.runInternalRead(cid,'operation-check',async()=>{
        try{await this.kong.request(cid,'GET',base);}catch(error){
          // Only an explicit Kong 404 for the parent counts as absent; any other failure aborts without a disposition.
          if((error as any)?.getStatus?.()!==404)throw error;
          return Object.freeze({parentAbsent:true as const,effective:null,effectiveBudget:{pages:0,records:0,bytes:0},historyAllocated:Object.freeze([] as ConfigurationTargetObservedEntry[]),
            historyComplete:false,historyBudget:{pages:0,records:0,bytes:0},observedAt:new Date().toISOString()});
        }
        const effectiveRead=await currentEffectiveTarget(this.kong,cid,upstreamId,address,{maxPages:40});
        const history=await this.history(cid,base,allocatedId);
        return Object.freeze({parentAbsent:false as const,effective:effectiveRead.target?entry(effectiveRead.target):null,effectiveBudget:effectiveRead.budget,...history,observedAt:new Date().toISOString()});
      },{paths:[base,`${base}/targets`,`${base}/targets/all`],workspaceId:wid,maxCalls:200,maxPages:80,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000});
      const result=decideConfigurationTargetResult({action:m.action,address,desiredWeight,allocatedId,before:beforeEntry,effective:observation.effective,
        historyAllocated:observation.historyAllocated,historyComplete:observation.historyComplete,effectiveComplete:!observation.parentAbsent,parentAbsent:observation.parentAbsent});
      if(await this.authority(actor,cid,wid)!==permissionVersion)throw deny('CONFIGURATION_RECONCILE_PERMISSIONS_CHANGED');
      await this.redis.assertLeaseOwnership();
      return {m,link,observation,result,allocatedId};
  }

  /** Complete bounded traversal of the parent-scoped history collection. */
  private async history(cid:string,base:string,allocatedId:string){
    const path=`${base}/targets/all`,seen=new Set<string>(),cursors=new Set<string>(),historyAllocated:ConfigurationTargetObservedEntry[]=[];
    const budget={pages:0,records:0,bytes:0};let cursor:string|undefined;
    do{
      if(budget.pages>=HISTORY.maxPages)throw conflict('CONFIGURATION_RECONCILE_READ_BUDGET');
      const page=await this.kong.list(cid,path,{size:HISTORY.pageSize},cursor,`configuration-unknown-result-history:${allocatedId}`);
      if(!Array.isArray(page?.items)||page.items.length>HISTORY.pageSize)throw conflict('CONFIGURATION_RECONCILE_READ_INVALID');
      budget.pages++;budget.records+=page.items.length;budget.bytes+=Buffer.byteLength(JSON.stringify(page.items),'utf8');
      if(budget.bytes>HISTORY.maxBytes)throw conflict('CONFIGURATION_RECONCILE_READ_BUDGET');
      for(const item of page.items){
        const e=entry(item);if(!e||seen.has(e.id))throw conflict('CONFIGURATION_RECONCILE_READ_INVALID');
        seen.add(e.id);if(e.id===allocatedId)historyAllocated.push(e);
      }
      if(page.nextCursor){if(cursors.has(page.nextCursor))throw conflict('CONFIGURATION_RECONCILE_READ_INVALID');cursors.add(page.nextCursor);}
      cursor=page.nextCursor??undefined;
    }while(cursor);
    return {historyAllocated:Object.freeze(historyAllocated),historyComplete:true,historyBudget:budget};
  }
}

function entry(value:any):ConfigurationTargetObservedEntry|null{
  if(!value||typeof value.id!=='string'||!value.id||typeof value.target!=='string'||!value.target||!Number.isInteger(value.weight))return null;
  return Object.freeze({id:value.id,target:value.target,weight:value.weight});
}
