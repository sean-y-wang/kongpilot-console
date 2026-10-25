import {describe,expect,it} from 'vitest';
import {assertMetadataScheduleProductionHandlers,METADATA_SCHEDULE_APPLY_HANDLERS,createMetadataScheduleProductionPorts} from '../../apps/console-api/src/modules/workflows/metadata-schedule.production';
import {METADATA_SCHEDULE_KINDS} from '../../apps/console-api/src/modules/workflows/metadata-schedule.registry';
import {WORKFLOW_HANDLERS} from '../../apps/console-api/src/modules/workflows/workflow-registry.service';

describe('metadata schedule production apply ports',()=>{
  it('covers all metadata schedule kinds with at least one registered WORKFLOW_HANDLERS entry',()=>{
    expect(Object.keys(METADATA_SCHEDULE_APPLY_HANDLERS).sort()).toEqual([...METADATA_SCHEDULE_KINDS].sort());
    expect(()=>assertMetadataScheduleProductionHandlers()).not.toThrow();
    for(const kind of METADATA_SCHEDULE_KINDS){
      const handlers=METADATA_SCHEDULE_APPLY_HANDLERS[kind];
      expect(handlers.some(h=>(WORKFLOW_HANDLERS as readonly string[]).includes(h))).toBe(true);
    }
  });
  it('createMetadataScheduleProductionPorts exposes claim→load→apply→outcome',()=>{
    const calls:string[]=[];
    const tx={id:Symbol('tx')};
    const ports=createMetadataScheduleProductionPorts({
      transaction:async fn=>{calls.push('tx');return fn(tx as never);},
      claim:async()=>{calls.push('claim');return {state:'claimed',attempt:1};},
      inspectStored:async()=>{calls.push('inspect');return {plan:{kind:'control-metadata'},draft:{binding:{kind:'control-metadata'},delegation:{kind:'control-metadata'}}} as never;},
      sql:()=>({one:async()=>null}),
      factsInput:async()=>{throw Object.assign(new Error('METADATA_SCHEDULE_KIND'),{code:'METADATA_SCHEDULE_KIND'});},
      applyApproved:async()=>{calls.push('apply');},
      recordOutcome:async(_id,o)=>{calls.push(`outcome:${o.state}:${o.code}`);},
      now:()=>Date.now(),
    });
    expect(typeof ports.claim).toBe('function');
    expect(typeof ports.load).toBe('function');
    expect(typeof ports.apply).toBe('function');
    expect(typeof ports.recordOutcome).toBe('function');
  });
});
