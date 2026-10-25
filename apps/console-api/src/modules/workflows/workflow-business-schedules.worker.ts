import {HttpException,Injectable,Logger,OnModuleDestroy,OnApplicationBootstrap,ServiceUnavailableException} from '@nestjs/common';
import {WorkflowScheduleRepository} from './workflow-schedule.repository';
import type {WorkflowScheduleWorkerDelegate} from './workflow-schedule.contract';
import {assertKp007WorkerTickBounds} from './kp007-access-fault-contract';
import {publishBusinessScheduleWorkerProbe} from '../../infrastructure/schedule-worker-probe';

/** Root's fixed Authority acquires/executes an original opaque claim. This
 * worker never creates an actor or acknowledges an outcome. Timer is disabled
 * by default and starts only after an explicit environment opt-in plus Root's
 * complete executor installation. Unknown/failed claims are never replayed. */
@Injectable()
export class WorkflowBusinessSchedulesWorker implements OnApplicationBootstrap,OnModuleDestroy {
 private delegate?:Readonly<WorkflowScheduleWorkerDelegate>;private timer?:NodeJS.Timeout;private initialized=false;private busy=false;
 private readonly logger=new Logger(WorkflowBusinessSchedulesWorker.name);
 constructor(private readonly repository:WorkflowScheduleRepository){}
 installFixedDelegate(delegate:WorkflowScheduleWorkerDelegate):void{
  if(this.delegate||!delegate||typeof delegate.acquireDueClaim!=='function'||typeof delegate.executeClaim!=='function'
   ||Object.keys(delegate).some(k=>!['acquireDueClaim','executeClaim'].includes(k)))throw new Error('Business schedule worker requires one fixed complete Root Authority delegate');
  this.delegate=Object.freeze({acquireDueClaim:delegate.acquireDueClaim.bind(delegate),executeClaim:delegate.executeClaim.bind(delegate)});this.start();
 }
 onApplicationBootstrap():void{this.initialized=true;this.start();}
 private start():void{
  const enabled=process.env.BUSINESS_SCHEDULES_ENABLED==='true';
  if(!this.initialized||!this.delegate||this.timer||!enabled){
   publishBusinessScheduleWorkerProbe({enabled,timerRunning:!!this.timer});
   return;
  }
  this.timer=setInterval(()=>{void this.tick().catch(()=>{/* tick records a sanitized failure; original facts remain unchanged. */});},5000);this.timer.unref();
  publishBusinessScheduleWorkerProbe({enabled:true,timerRunning:true});
 }
 onModuleDestroy():void{if(this.timer)clearInterval(this.timer);this.timer=undefined;this.initialized=false;publishBusinessScheduleWorkerProbe({enabled:process.env.BUSINESS_SCHEDULES_ENABLED==='true',timerRunning:false});}
 private logEntry(stage:'listing'|'claim'|'execution',errorCode:string,scheduleId?:string){
  return{event:'workflow-business-schedule-worker-blocked',stage,errorCode,
   ...(typeof scheduleId==='string'&&/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(scheduleId)?{scheduleId}:{})};
 }
 private logFailure(stage:'listing'|'claim'|'execution',error:unknown,scheduleId?:string):void{
  let code='WORKFLOW_BUSINESS_SCHEDULE_WORKER_UNKNOWN_ERROR',policyBlock=false;
  // Never pass an exception, its message, stack or response into Logger.
  // Even structured errors contribute only one bounded uppercase code.
  if(error instanceof HttpException)try{
   const response=error.getResponse(),candidate=typeof response==='object'&&response!==null?(response as {code?:unknown}).code:undefined;
   if(typeof candidate==='string'&&/^[A-Z][A-Z0-9_]{2,79}$/.test(candidate)){
    code=candidate;policyBlock=[400,401,403,404,409,412,422,429].includes(error.getStatus());
   }
  }catch{/* A malformed exception remains an unknown error without leaking it. */}
  const entry=this.logEntry(stage,code,scheduleId);
  if(policyBlock)this.logger.warn(entry);else this.logger.error(entry);
 }
 async tick():Promise<{checked:number;claimed:number;completed:number;blocked:number;busy:boolean}>{
  if(!this.delegate)throw new ServiceUnavailableException({code:'WORKFLOW_BUSINESS_SCHEDULE_EXECUTOR_UNAVAILABLE'});
  if(this.busy){const tick={checked:0,claimed:0,completed:0,blocked:0,busy:true as const};assertKp007WorkerTickBounds(tick);return tick;}this.busy=true;
  let checked=0,claimed=0,completed=0,blocked=0;
  try{let due:readonly string[];
   try{due=await this.repository.listDue(25);}catch(error){this.logFailure('listing',error);throw error;}
   for(const id of due){checked++;let stage:'claim'|'execution'='claim';
    try{const original=await this.delegate.acquireDueClaim(id);if(original===null){blocked++;
      this.logger.warn(this.logEntry('claim','WORKFLOW_BUSINESS_SCHEDULE_CLAIM_BLOCKED',id));continue;}
     if(!original||typeof original!=='object'||Array.isArray(original))throw new Error('Original claim handle required');
     claimed++;stage='execution';await this.delegate.executeClaim(original);completed++;
    }catch(error){blocked++;this.logFailure(stage,error,id);}
   }const tick={checked,claimed,completed,blocked,busy:false as const};assertKp007WorkerTickBounds(tick);return tick;
  }finally{this.busy=false;}
 }
}
