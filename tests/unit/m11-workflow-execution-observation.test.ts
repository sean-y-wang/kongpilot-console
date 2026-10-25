import {describe,expect,it} from 'vitest';
import {WorkflowExecutionObservation} from '../../apps/console-api/src/modules/workflows/workflow-execution-observation';

describe('bounded workflow observation without execution authority',()=>{
 it('projects counters only and preserves immutable snapshots',()=>{
  const current={calls:1,pages:2,records:3,bytes:4,key:'private-key',handle:{}};
  const trace=new WorkflowExecutionObservation(()=>current);trace.mark('claimed');
  const first=trace.snapshot();current.calls=12;trace.mark('step-ready',2);
  expect(first.samples).toEqual([{phase:'claimed',step:0,calls:1,pages:2,records:3,bytes:4}]);
  expect(Object.isFrozen(first.samples)).toBe(true);expect(Object.isFrozen(first.samples[0])).toBe(true);
  expect(JSON.stringify(trace.snapshot())).not.toMatch(/private-key|handle/);
 });
 it('never surfaces a failed context read or its exception contents',()=>{
  const trace=new WorkflowExecutionObservation(()=>{throw Error('private-key');});
  expect(()=>trace.mark('failed',4)).not.toThrow();expect(trace.snapshot()).toEqual({samples:[],omitted:0});
 });
 it.each([-1,NaN,Infinity,1.5,Number.MAX_SAFE_INTEGER+1])('discards invalid counters %s',calls=>{
  const trace=new WorkflowExecutionObservation(()=>({calls,pages:0,records:0,bytes:0}));trace.mark('claimed');
  expect(trace.snapshot().samples).toEqual([]);
 });
 it('rejects arbitrary phases, steps and returned extra fields',()=>{
  const trace=new WorkflowExecutionObservation(()=>({calls:0,pages:0,records:0,bytes:0}));
  trace.mark('user-controlled-secret');trace.mark('claimed',-1);trace.mark('claimed',10001);trace.mark('claimed',0.5);
  expect(trace.snapshot().samples).toEqual([]);
 });
 it('bounds retained samples while retaining the final known counter',()=>{
  let calls=0;const trace=new WorkflowExecutionObservation(()=>({calls:calls++,pages:0,records:0,bytes:0}));
  for(let n=0;n<100;n++)trace.mark(n===99?'failed':'step-ready',n);
  expect(trace.snapshot().samples).toHaveLength(64);expect(trace.snapshot().omitted).toBe(36);
  expect(trace.snapshot().samples.at(-1)).toMatchObject({phase:'failed',step:99,calls:99});
 });
});
