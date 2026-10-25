import {ConflictException,ForbiddenException,Injectable,ServiceUnavailableException} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {DbService} from '../../infrastructure/db.service';
import {SecretService} from '../../infrastructure/secret.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {AuditService} from '../audit/audit.service';
import type {EntityActor} from '../entities/entities.types';
import {
  assertOriginalMutationReceiptMatch,
  assertUnknownResultDispositionEvidence,
  expectedMetadataState,
  UnknownResultDispositionRejected,
  type UnknownResultDispositionEvidence,
} from './unknown-result-disposition';

const deny=(code='UNKNOWN_RESULT_ACTOR_REQUIRED')=>new ForbiddenException({code});
const changed=(code='UNKNOWN_RESULT_CHANGED')=>new ConflictException({code});

/** Metadata-only unknown-result disposition (KP-003 / historical SQL042 → migration 044).
 * Sends zero Native requests. Closing dispositions may CAS schedule-origin
 * uncertain execution/mutation rows; rejected verifications never unlock state. */
@Injectable()
export class UnknownResultDispositionService{
  private checksum?:string;
  private configurationChecksum?:string;
  private abandonChecksum?:string;
  private unsentChecksum?:string;
  constructor(
    private readonly db:DbService,
    private readonly secrets:SecretService,
    private readonly context:KongExecutionContextService,
    private readonly audit:AuditService,
  ){}
  installStorageChecksum(checksum:string):void{
    if(this.checksum||!/^[a-f\d]{64}$/.test(checksum))throw changed('UNKNOWN_RESULT_STORAGE_CHECKSUM_INVALID');
    this.checksum=checksum;
  }
  /** SQL049 ledger checksum; without it configuration_v2 mutations stay non-disposable (fail closed). */
  installConfigurationStorageChecksum(checksum:string):void{
    if(this.configurationChecksum||!/^[a-f\d]{64}$/.test(checksum))throw changed('UNKNOWN_RESULT_STORAGE_CHECKSUM_INVALID');
    this.configurationChecksum=checksum;
  }
  installAbandonStorageChecksum(checksum:string):void{
    if(this.abandonChecksum||!/^[a-f\d]{64}$/.test(checksum))throw changed('UNKNOWN_RESULT_STORAGE_CHECKSUM_INVALID');
    this.abandonChecksum=checksum;
  }
  /** SQL051 ledger checksum; without it never-sent uncertain jobs stay non-disposable. */
  installUnsentStorageChecksum(checksum:string):void{
    if(this.unsentChecksum||!/^[a-f\d]{64}$/.test(checksum))throw changed('UNKNOWN_RESULT_STORAGE_CHECKSUM_INVALID');
    this.unsentChecksum=checksum;
  }
  private frame(actor:EntityActor,cid:string,wid:string){
    const f=this.context.current();
    if(f.kind!=='actor'||f.module!=='workflows'||f.action!=='write'||f.operation||f.archive||f.purpose||!f.sessionId
      ||f.actor?.id!==actor.user.id||f.clusterId!==cid||f.workspaceId!==wid||actor.workspaceId!==wid)throw deny();
    return f;
  }
  async dispose(cid:string,wid:string,evidence:UnknownResultDispositionEvidence,actor:EntityActor,
    /** Non-secret audit detail (HMACs/decision); cannot override bound fields. */ detail:Readonly<Record<string,unknown>>={}):Promise<Readonly<{dispositionId:string;disposition:string;nativeRequestsSent:0}>>{
    if(!this.checksum)throw new ServiceUnavailableException({code:'UNKNOWN_RESULT_DISPOSITION_UNAVAILABLE'});
    try{assertUnknownResultDispositionEvidence(evidence);}catch(e){
      if(e instanceof UnknownResultDispositionRejected)throw new ConflictException({code:e.code});throw e;
    }
    const frame=this.frame(actor,cid,wid),actorHmac=this.secrets.fingerprint(actor);
    return this.db.transaction(async tx=>{
      if(this.context.current()!==frame||this.secrets.fingerprint(actor)!==actorHmac)throw deny();
      const ledger=await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='044_m11_unknown_result_disposition.sql'");
      if(!ledger||ledger.checksum!==this.checksum)throw new ServiceUnavailableException({code:'UNKNOWN_RESULT_DISPOSITION_UNAVAILABLE'});
      const session=await tx.one<any>(`SELECT s.credential_epoch,u.credential_epoch AS user_epoch FROM auth_sessions s JOIN users u ON u.id=s.user_id
        WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
        AND s.credential_epoch=u.credential_epoch AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change FOR SHARE OF s,u`,
        [frame.sessionId,actor.user.id]);
      if(!session)throw deny('UNKNOWN_RESULT_SESSION_REVOKED');
      const execution=await tx.one<any>(`SELECT e.*,o.claim_id,o.schedule_id FROM workflow_executions e
        JOIN workflow_execution_origins o ON o.execution_id=e.id
        WHERE e.id=$1 AND e.cluster_id=$2 AND e.workspace_id=$3 AND e.workflow_id=$4 AND e.plan_revision=$5 AND e.plan_hash=$6
        AND o.claim_id=$7 AND o.schedule_id=$8 FOR SHARE OF e,o`,
        [evidence.workflowExecutionId,cid,wid,evidence.workflowId,evidence.workflowPlanRevision,evidence.workflowPlanHash,evidence.claimId,evidence.scheduleId]);
      if(!execution||execution.state!=='uncertain')throw changed('UNKNOWN_RESULT_EXECUTION_NOT_UNCERTAIN');
      let mutation:any=null;
      if(evidence.original.mutationId){
        mutation=await tx.one<any>('SELECT * FROM mutation_operations WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR SHARE',
          [evidence.original.mutationId,cid,wid]);
        if(!mutation)throw changed('UNKNOWN_RESULT_MUTATION_RECEIPT_MISMATCH');
        let linked=false;
        if(mutation.workflow_execution_id===null){
          if(!this.configurationChecksum)throw new ServiceUnavailableException({code:'UNKNOWN_RESULT_DISPOSITION_UNAVAILABLE'});
          const configLedger=await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='049_m11_configuration_unknown_result.sql'");
          if(!configLedger||configLedger.checksum!==this.configurationChecksum)throw new ServiceUnavailableException({code:'UNKNOWN_RESULT_DISPOSITION_UNAVAILABLE'});
          // Exact schedule-origin configuration link, identical to the SQL049 validator.
          linked=!!mutation.configuration_execution_id&&!!await tx.one<any>(`SELECT 1 AS ok FROM workflow_configuration_execution_origins x
            JOIN configuration_executions ce ON ce.id=x.configuration_execution_id
            WHERE x.configuration_execution_id=$1 AND x.workflow_execution_id=$2 AND x.claim_id=$3 AND x.workflow_id=$4 AND x.cluster_id=$5 AND x.workspace_id=$6
            AND x.workflow_plan_revision=$7 AND x.workflow_plan_hash=$8 AND ce.cluster_id=$5 AND ce.workspace_id=$6 AND ce.state='uncertain' FOR SHARE OF x,ce`,
            [mutation.configuration_execution_id,evidence.workflowExecutionId,evidence.claimId,evidence.workflowId,cid,wid,evidence.workflowPlanRevision,evidence.workflowPlanHash]);
        }
        assertOriginalMutationReceiptMatch(evidence.original,mutation,evidence.workflowExecutionId,linked);
      }
      const abandoning=evidence.disposition==='abandoned';
      const unsentAbandoning=abandoning&&!!evidence.unsentAbandonRequestId;
      const unsentClosing=!evidence.original.mutationId&&(evidence.disposition==='verified-not-applied'||unsentAbandoning);
      if(abandoning&&!unsentAbandoning){
        const abandonLedger=await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='050_m11_unknown_result_abandon.sql'");
        if(!this.abandonChecksum||!abandonLedger||abandonLedger.checksum!==this.abandonChecksum)throw new ServiceUnavailableException({code:'UNKNOWN_RESULT_DISPOSITION_UNAVAILABLE'});
        if(!mutation||mutation.workflow_execution_id!==null)throw changed('UNKNOWN_RESULT_ABANDON_CONFIGURATION_ONLY');
      }
      if(unsentClosing||unsentAbandoning){
        const unsentLedger=await tx.one<any>("SELECT checksum FROM schema_migrations WHERE name='051_m11_configuration_unsent_settle.sql'");
        if(!this.unsentChecksum||!unsentLedger||unsentLedger.checksum!==this.unsentChecksum)throw new ServiceUnavailableException({code:'UNKNOWN_RESULT_DISPOSITION_UNAVAILABLE'});
        if(mutation||!evidence.unsentJobId)throw changed('UNKNOWN_RESULT_UNSENT_JOB_REQUIRED');
        const appeared=await tx.one<any>('SELECT 1 AS ok FROM mutation_operations WHERE workflow_id=$1 OR configuration_job_id=$2 LIMIT 1',
          [evidence.workflowId,evidence.unsentJobId]);
        if(appeared)throw changed('CONFIGURATION_UNSENT_MUTATION_PRESENT');
      }
      const id=randomUUID(),expected=expectedMetadataState(evidence.disposition);
      const after={...detail,dispositionId:id,disposition:evidence.disposition,claimId:evidence.claimId,executionId:evidence.workflowExecutionId,
        evidenceHmac:evidence.evidenceHmac,requestHmac:evidence.requestHmac,nativeRequestsSent:0,expectedMetadataState:expected,
        mutationId:evidence.original.mutationId??null,
        ...(unsentAbandoning?{unsentAbandonRequestId:evidence.unsentAbandonRequestId,knownNoNativeSend:true}:{}),
        ...(unsentClosing&&!unsentAbandoning?{knownNoNativeSend:true,unsentJobId:evidence.unsentJobId}:{}),
        ...(unsentAbandoning?{unsentJobId:evidence.unsentJobId}:{})};
      const audit=await this.audit.append({
        actorId:actor.user.id,clusterId:cid,workspaceId:wid,workflowId:evidence.workflowId,
        entityType:'workflows',entityId:evidence.workflowId,action:'workflow.unknown-result.disposed',
        after,result:'success',requestId:actor.requestId,ip:actor.ip,
        scopeHints:{quality:'verified',module:'workflows',subject:{type:'workflows',id:evidence.workflowId},
          beforeExists:true,afterExists:true,beforeTags:[],afterTags:[],beforeWorkspaceId:wid,afterWorkspaceId:wid},
      },tx);
      const abandonCol=abandoning?(unsentAbandoning?',unsent_abandon_request_id':',abandon_request_id'):'';
      const abandonVal=abandoning?',$23':'';
      await tx.exec(`INSERT INTO workflow_unknown_result_dispositions(
        id,cluster_id,workspace_id,schedule_id,claim_id,workflow_id,workflow_execution_id,workflow_plan_revision,workflow_plan_hash,
        mutation_id,actor_id,session_id,credential_epoch,disposition,original_execution_state,original_mutation_state,
        original_remote_started,original_remote_completed,original_error_code,evidence_hmac,request_hmac,audit_id,audit_event_hash,observed_at${abandonCol})
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'uncertain',$15,$16,$17,$18,$19,$20,$21,$22,clock_timestamp()${abandonVal})`,
        [id,cid,wid,evidence.scheduleId,evidence.claimId,evidence.workflowId,evidence.workflowExecutionId,evidence.workflowPlanRevision,evidence.workflowPlanHash,
          evidence.original.mutationId??null,actor.user.id,frame.sessionId,session.credential_epoch,evidence.disposition,
          evidence.original.mutationState??null,evidence.original.remoteStarted??null,evidence.original.remoteCompleted??null,
          evidence.original.errorCode??null,evidence.evidenceHmac,evidence.requestHmac,audit.id,audit.eventHash,
          ...(abandoning?[unsentAbandoning?evidence.unsentAbandonRequestId:evidence.abandonRequestId]:[])]);
      if(evidence.disposition==='verified-applied'||evidence.disposition==='verified-not-applied'||evidence.disposition==='abandoned'){
        const state=expectedMetadataState(evidence.disposition);
        if(mutation){
          if(evidence.disposition==='abandoned')await tx.exec(`UPDATE mutation_operations SET state='failed',safe_result=$2::jsonb,updated_at=clock_timestamp() WHERE id=$1 AND state='uncertain'`,
            [mutation.id,JSON.stringify({outcome:'failed-unknown',abandoned:true,dispositionId:id,nativeRequestsSent:0})]);
          else await tx.exec(`UPDATE mutation_operations SET state=$1,updated_at=clock_timestamp() WHERE id=$2 AND state='uncertain'`,[state,mutation.id]);
        }
        await tx.exec(`UPDATE workflow_executions SET state=$1,revision=revision+1,updated_at=clock_timestamp() WHERE id=$2 AND state='uncertain'`,
          [state,evidence.workflowExecutionId]);
        if(unsentClosing){
          // Re-check under the same locks: a mutation appearing mid-tx fails closed.
          const raced=await tx.one<any>('SELECT 1 AS ok FROM mutation_operations WHERE workflow_id=$1 OR configuration_job_id=$2 LIMIT 1',
            [evidence.workflowId,evidence.unsentJobId]);
          if(raced)throw changed('CONFIGURATION_UNSENT_MUTATION_PRESENT');
          await tx.exec(`UPDATE workflows SET state=$1,revision=revision+1,updated_at=clock_timestamp() WHERE id=$2 AND cluster_id=$3 AND workspace_id=$4 AND state='uncertain'`,
            [state,evidence.workflowId,cid,wid]);
          await tx.exec(`UPDATE configuration_jobs SET state='failed',error_code='CONFIGURATION_UNSENT_SETTLED',remote_completed=false,
            completed_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp(),lease_until=NULL
            WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3 AND workflow_id=$4 AND state IN('running','uncertain') AND remote_started=false`,
            [evidence.unsentJobId,cid,wid,evidence.workflowId]);
        }
      }
      if(this.context.current()!==frame||this.secrets.fingerprint(actor)!==actorHmac)throw deny();
      return Object.freeze({dispositionId:id,disposition:evidence.disposition,nativeRequestsSent:0 as const});
    });
  }
}
