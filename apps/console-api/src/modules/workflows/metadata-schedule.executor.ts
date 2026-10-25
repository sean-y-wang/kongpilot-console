import {assertMetadataScheduleExecution,MetadataScheduleRejected,type MetadataExecutionRecheck} from './metadata-schedule.guard';

/** SQL041 generic metadata scheduled executor core. Same ordering as
 * entity-annotation: claim → load → recheck → apply once → terminal outcome.
 * Post-claim rejection records terminal failed (never blocked). */
export interface MetadataScheduleTx{readonly id:symbol}
export interface MetadataScheduleExecutorPorts<Tx extends MetadataScheduleTx=MetadataScheduleTx>{
  transaction<T>(fn:(tx:Tx)=>Promise<T>):Promise<T>;
  claim(scheduleId:string,tx:Tx):Promise<Readonly<{state:string;attempt:number}>|null>;
  load(scheduleId:string,tx:Tx):Promise<Readonly<Omit<MetadataExecutionRecheck,'claim'>>>;
  apply(scheduleId:string,tx:Tx):Promise<void>;
  recordOutcome(scheduleId:string,outcome:Readonly<{state:'succeeded'|'failed';code:string|null}>,tx:Tx):Promise<void>;
  now():number;
}
export type MetadataScheduleResult=Readonly<{state:'succeeded'|'failed'|'not-claimed';code:string|null}>;

export async function executeMetadataSchedule<Tx extends MetadataScheduleTx>(scheduleId:string,ports:MetadataScheduleExecutorPorts<Tx>):Promise<MetadataScheduleResult>{
  return ports.transaction(async tx=>{
    const claim=await ports.claim(scheduleId,tx);
    if(claim===null)return Object.freeze({state:'not-claimed' as const,code:'METADATA_SCHEDULE_CLAIM_BLOCKED'});
    try{
      const facts=await ports.load(scheduleId,tx);
      assertMetadataScheduleExecution({...facts,claim},ports.now());
      await ports.apply(scheduleId,tx);
    }catch(error){
      if(!(error instanceof MetadataScheduleRejected))throw error;
      await ports.recordOutcome(scheduleId,{state:'failed',code:error.code},tx);
      return Object.freeze({state:'failed' as const,code:error.code});
    }
    await ports.recordOutcome(scheduleId,{state:'succeeded',code:null},tx);
    return Object.freeze({state:'succeeded' as const,code:null});
  });
}
