import {type MetadataScheduledKind} from './metadata-schedule.guard';
import {METADATA_SCHEDULE_KINDS} from './metadata-schedule.registry';
import {executeMetadataSchedule,type MetadataScheduleExecutorPorts,type MetadataScheduleTx} from './metadata-schedule.executor';
import {loadMetadataScheduleFacts,type MetadataScheduleFactsInput,type MetadataScheduleFactsSql} from './metadata-schedule.facts';
import {WORKFLOW_HANDLERS} from './workflow-registry.service';
import type {WorkflowScheduleStored} from './workflow-schedule.contract';

/** Canonical production apply handlers per SQL041 metadata schedule kind.
 * Worker dispatch: Root Authority → ApprovedBusinessExecution → registry.apply(handler).
 * portal-metadata / event-metadata register multiple handlers; any one proves the domain is wired. */
export const METADATA_SCHEDULE_APPLY_HANDLERS = Object.freeze({
  'entity-annotation':['entity.annotation'],
  'control-metadata':['control.metadata'],
  'configuration-metadata':['configuration.metadata'],
  'governance-metadata':['governance.metadata'],
  'workflow-policy-metadata':['workflow.policy'],
  'iam-metadata':['iam.metadata'],
  'portal-metadata':['portal.settings.update','portal.developer.review','portal.application.update'],
  'portal-developer-review':['portal.developer.review'],
  'event-metadata':['event.channel.save','event.subscription.save','event.delivery.replay'],
} as const satisfies Record<MetadataScheduledKind,readonly string[]>);

export function assertMetadataScheduleProductionHandlers(registered:(handler:string)=>boolean = h=> (WORKFLOW_HANDLERS as readonly string[]).includes(h)):void {
  for(const kind of METADATA_SCHEDULE_KINDS){
    const handlers=METADATA_SCHEDULE_APPLY_HANDLERS[kind];
    if(!handlers.some(registered))throw new Error(`METADATA_SCHEDULE_APPLY_MISSING:${kind}`);
  }
}

export interface MetadataScheduleProductionDeps<Tx extends MetadataScheduleTx>{
  transaction<T>(fn:(tx:Tx)=>Promise<T>):Promise<T>;
  claim(scheduleId:string,tx:Tx):Promise<Readonly<{state:string;attempt:number}>|null>;
  inspectStored(scheduleId:string,tx:Tx):Promise<Readonly<WorkflowScheduleStored>>;
  sql(tx:Tx):MetadataScheduleFactsSql;
  factsInput(stored:Readonly<WorkflowScheduleStored>,tx:Tx):Promise<Omit<MetadataScheduleFactsInput,'stored'>>;
  applyApproved(scheduleId:string,stored:Readonly<WorkflowScheduleStored>,tx:Tx):Promise<void>;
  recordOutcome(scheduleId:string,outcome:Readonly<{state:'succeeded'|'failed';code:string|null}>,tx:Tx):Promise<void>;
  now():number;
}

/** Claim → loadMetadataScheduleFacts → domain apply for any of the 8 kinds. */
export function createMetadataScheduleProductionPorts<Tx extends MetadataScheduleTx>(deps:MetadataScheduleProductionDeps<Tx>):MetadataScheduleExecutorPorts<Tx>{
  return Object.freeze({
    transaction:deps.transaction,
    claim:deps.claim,
    load:async(scheduleId:string,tx:Tx)=>{
      const stored=await deps.inspectStored(scheduleId,tx);
      const kind=stored.plan.kind as MetadataScheduledKind;
      if(!(METADATA_SCHEDULE_KINDS as readonly string[]).includes(kind))throw new Error(`METADATA_SCHEDULE_KIND:${kind}`);
      return loadMetadataScheduleFacts(deps.sql(tx),{stored,...await deps.factsInput(stored,tx)});
    },
    apply:async(scheduleId:string,tx:Tx)=>{
      const stored=await deps.inspectStored(scheduleId,tx);
      await deps.applyApproved(scheduleId,stored,tx);
    },
    recordOutcome:deps.recordOutcome,
    now:deps.now,
  });
}

export async function executeMetadataScheduleProduction<Tx extends MetadataScheduleTx>(scheduleId:string,deps:MetadataScheduleProductionDeps<Tx>){
  return executeMetadataSchedule(scheduleId,createMetadataScheduleProductionPorts(deps));
}
