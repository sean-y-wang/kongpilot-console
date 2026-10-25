import {HttpException,Injectable,Logger,OnModuleDestroy,OnModuleInit} from '@nestjs/common';
import {DbService} from '../../infrastructure/db.service';
import {RedisService} from '../../infrastructure/redis.service';
import {AuditService} from '../audit/audit.service';
import {metadataAuditScope} from '../event-producers/native-audit-scope';
import {GovernanceRepositoryService} from './governance-repository.service';
import {GovernanceService} from './governance.service';
import {governanceFailureCode} from './governance-input';

/** Timer locators never impersonate login sessions or perform native writes. */
@Injectable()
export class GovernanceSchedulerService implements OnModuleInit,OnModuleDestroy {
 private timer?:ReturnType<typeof setTimeout>;private stopped=false;private running=false;private readonly logger=new Logger(GovernanceSchedulerService.name);
 constructor(private readonly db:DbService,private readonly redis:RedisService,private readonly repo:GovernanceRepositoryService,private readonly service:GovernanceService,private readonly audit:AuditService){}
 onModuleInit():void{this.schedule();}onModuleDestroy():void{this.stopped=true;if(this.timer)clearTimeout(this.timer);}
 private schedule():void{if(this.stopped)return;this.timer=setTimeout(()=>void this.tick().catch(()=>{
  // Initial repository reads can fail before per-schedule catches. Handle only
  // timer rejections; explicit callers still observe tick/database failures.
  this.logger.warn({component:'governance-scheduler',code:'GOVERNANCE_SCHEDULE_TICK_FAILED'});
 }).finally(()=>this.schedule()),10000);this.timer.unref();}
 async tick():Promise<void>{if(this.running)return;this.running=true;
  try{
   // An expired lease proves neither failure nor successful persistence. Seal
   // the original occurrence as uncertain and fence later occurrences; never
   // rerun a diagnostic under a fresh key to conceal that unresolved fact.
   for(const expired of await this.repo.expiredScheduleRuns(10))try{await this.redis.withLock(`governance-schedule:${expired.schedule_id}`,()=>this.db.transaction(async tx=>{if(await this.repo.markExpiredScheduleRun(expired,tx))await this.audit.append({actorId:expired.creator_id,clusterId:expired.cluster_id,workspaceId:expired.workspace_id,entityType:'governance_schedule_runs',entityId:expired.id,requestId:`governance-schedule-${expired.id}`,action:'governance.schedule.lease_expired',after:{scheduleId:expired.schedule_id,errorCode:'GOVERNANCE_SCHEDULE_LEASE_EXPIRED'},result:'uncertain',scopeHints:metadataAuditScope('governance','governance_schedule_runs',expired.id,expired.workspace_id)},tx);}));}catch(error){this.logger.warn({component:'governance-scheduler',code:governanceFailureCode(error),scheduleId:expired.schedule_id});}
   for(const candidate of await this.repo.dueSchedules(10))try{await this.redis.withLock(`governance-schedule:${candidate.id}`,async()=>{
   const registration=await this.db.transaction(async tx=>{const r=await this.repo.claimSchedule(candidate,tx);if(r)await this.audit.append({actorId:r.locator.ownerUserId,clusterId:r.locator.clusterId,workspaceId:r.locator.workspaceId,entityType:'governance_schedule_runs',entityId:r.locator.runId,requestId:`governance-schedule-${r.locator.runId}`,action:'governance.schedule.claim',after:{scheduleId:r.locator.scheduleId,version:r.locator.version},result:'pending',scopeHints:metadataAuditScope('governance','governance_schedule_runs',r.locator.runId,r.locator.workspaceId)},tx);return r;});if(!registration)return;
   try{const result=await this.service.runScheduled(registration.locator,registration.payload);await this.db.transaction(async tx=>{await this.repo.finishSchedule(registration.locator,result.state,result.runId,undefined,tx);await this.audit.append({actorId:registration.locator.ownerUserId,clusterId:registration.locator.clusterId,workspaceId:registration.locator.workspaceId,entityType:'governance_schedule_runs',entityId:registration.locator.runId,requestId:`governance-schedule-${registration.locator.runId}`,action:'governance.schedule.finish',after:{runId:result.runId,state:result.state},scopeHints:metadataAuditScope('governance','governance_schedule_runs',registration.locator.runId,registration.locator.workspaceId)},tx);});}
   catch(error){const code=governanceFailureCode(error),current=await this.db.one<any>('SELECT state FROM governance_schedule_runs WHERE id=$1',[registration.locator.runId]);if(current?.state==='running'){const denied=/PERMISSION|AUTHORITY|OWNER|SCOPE|CREDENTIAL|SESSION|INACTIVE/.test(code),known=error instanceof HttpException&&!/UNKNOWN|UNCERTAIN/.test(code),state=denied?'paused_authority':known?'failed':'uncertain',linked=await this.db.one<any>('SELECT id FROM governance_runs WHERE schedule_run_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND actor_id=$4',[registration.locator.runId,registration.locator.clusterId,registration.locator.workspaceId,registration.locator.ownerUserId]);await this.db.transaction(async tx=>{await this.repo.finishSchedule(registration.locator,state,linked?.id,error,tx);await this.audit.append({actorId:registration.locator.ownerUserId,clusterId:registration.locator.clusterId,workspaceId:registration.locator.workspaceId,entityType:'governance_schedule_runs',entityId:registration.locator.runId,requestId:`governance-schedule-${registration.locator.runId}`,action:'governance.schedule.failed',after:{errorCode:code},result:state==='uncertain'?'uncertain':'failed',scopeHints:metadataAuditScope('governance','governance_schedule_runs',registration.locator.runId,registration.locator.workspaceId)},tx);});}throw error;}
  });}catch(error){this.logger.warn({component:'governance-scheduler',code:governanceFailureCode(error),scheduleId:candidate.id});}}
  finally{this.running=false;}
 }
}
