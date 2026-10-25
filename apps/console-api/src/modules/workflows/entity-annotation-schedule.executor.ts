import {assertEntityAnnotationExecution,EntityAnnotationScheduleRejected,type EntityAnnotationExecutionRecheck} from './entity-annotation-schedule.guard';

/** SQL041 entity-annotation scheduled executor core. It owns the ordering of a
 * single scheduled annotation write and is deliberately transport-agnostic:
 * every fact comes from ports evaluated inside the caller's transaction.
 *
 * Ordering (all inside one transaction):
 *  1. claim the occurrence (attempt must be exactly 1; a second claim is denied),
 *  2. load current requester authority + recompute the subject seal,
 *  3. run the fail-closed write-time recheck,
 *  4. apply the sealed annotation change once,
 *  5. record the terminal outcome.
 * Any post-claim rejection records a terminal `failed` outcome carrying the
 * rejection reason code and never calls apply. SQL026 m11_business_progress only
 * allows claimed -> running/succeeded/partial/failed/uncertain, so `blocked`
 * (an unclaimed-only state) is never written after a claim. Failed or unknown
 * occurrences are never replayed.
 *
 * Not yet installed into WorkflowBusinessRuntimeService: the authority and
 * service allow-lists keep 'entity-annotation' out until the Root policy
 * adapter (assertDraft/assertSubject/receipt read) is wired. */
export interface EntityAnnotationScheduleTx{readonly id:symbol}
export interface EntityAnnotationScheduleExecutorPorts<Tx extends EntityAnnotationScheduleTx=EntityAnnotationScheduleTx>{
  transaction<T>(fn:(tx:Tx)=>Promise<T>):Promise<T>;
  claim(scheduleId:string,tx:Tx):Promise<Readonly<{state:string;attempt:number}>|null>;
  load(scheduleId:string,tx:Tx):Promise<Readonly<Omit<EntityAnnotationExecutionRecheck,'claim'>>>;
  apply(scheduleId:string,tx:Tx):Promise<void>;
  recordOutcome(scheduleId:string,outcome:Readonly<{state:'succeeded'|'failed';code:string|null}>,tx:Tx):Promise<void>;
  now():number;
}
export type EntityAnnotationScheduleResult=Readonly<{state:'succeeded'|'failed'|'not-claimed';code:string|null}>;

export async function executeEntityAnnotationSchedule<Tx extends EntityAnnotationScheduleTx>(scheduleId:string,ports:EntityAnnotationScheduleExecutorPorts<Tx>):Promise<EntityAnnotationScheduleResult>{
  return ports.transaction(async tx=>{
    const claim=await ports.claim(scheduleId,tx);
    if(claim===null)return Object.freeze({state:'not-claimed' as const,code:'ANNOTATION_SCHEDULE_CLAIM_BLOCKED'});
    try{
      const facts=await ports.load(scheduleId,tx);
      assertEntityAnnotationExecution({...facts,claim},ports.now());
      await ports.apply(scheduleId,tx);
    }catch(error){
      if(!(error instanceof EntityAnnotationScheduleRejected))throw error; // unknown failure: transaction rolls back, nothing replayed
      await ports.recordOutcome(scheduleId,{state:'failed',code:error.code},tx);
      return Object.freeze({state:'failed' as const,code:error.code});
    }
    await ports.recordOutcome(scheduleId,{state:'succeeded',code:null},tx);
    return Object.freeze({state:'succeeded' as const,code:null});
  });
}
