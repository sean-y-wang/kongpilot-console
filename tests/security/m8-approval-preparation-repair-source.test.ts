import { describe, it, expect } from 'vitest';
// Actual acceptance predicates exercised on safe metadata only, without an
// environment, file, session, SQL connection or Native transport.
import { M8_PREPARATION_STOPPED as c, assertM8OriginalApprovalNoNative, assertM8PreparationRepairCheckpoint } from './lib/m8-v2-preparation-repair.mjs';
function original(){return{workflow_id:c.workflowId,job_id:c.jobId,plan_id:c.planId,execution_id:c.executionId,step_id:c.stepId,
 workflow_state:'uncertain',execution_state:'uncertain',step_state:'uncertain',snapshot_state:'ready',job_state:'waiting_approval',plan_state:'pending_approval',
 remote_started:false,remote_completed:false,same_request:true,same_key:true,same_actor:true,same_sid:true,same_plan_hash:true,same_workflow_tuple:true,
 handler:'configuration_v2',kind:'metadata',native_request_count:0,operation_id:null,configuration_execution_count:0,configuration_step_count:0,native_operation_count:0};}
describe('M8 exact stopped approval preparation safety',()=>{
 it('retains the original uncertain receipt without treating it as successful or replayable',()=>{const row=original();expect(assertM8OriginalApprovalNoNative(row)).toBe(row);expect(row.workflow_state).toBe('uncertain');});
 for(const[field,value]of[
  ['workflow_id','another-workflow'],['job_id','another-job'],['plan_id','another-plan'],['execution_id','another-execution'],['step_id','another-step'],
  ['workflow_state','succeeded'],['execution_state','executing'],['step_state','failed'],['snapshot_state','pending'],['job_state','running'],['plan_state','approved'],
  ['remote_started',true],['remote_completed',true],['same_request',false],['same_key',false],['same_actor',false],['same_sid',false],['same_plan_hash',false],['same_workflow_tuple',false],
  ['handler','configuration.metadata'],['kind','native'],['native_request_count',1],['operation_id',c.stepId],['configuration_execution_count',1],['configuration_step_count',1],['native_operation_count',1],
 ] as const)it(`rejects changed ${field} instead of clearing original uncertainty`,()=>{expect(()=>assertM8OriginalApprovalNoNative({...original(),[field]:value})).toThrow('M8_CURRENT_ORIGINAL_UNCERTAIN_WITH_ZERO_NATIVE_REQUIRED');});
 it('rejects absent or partial runtime proof',()=>{expect(()=>assertM8OriginalApprovalNoNative(null)).toThrow();const row:any=original();delete row.same_sid;expect(()=>assertM8OriginalApprovalNoNative(row)).toThrow();});
 it('does not accept a newly fabricated source checkpoint or failure artifact',()=>{expect(()=>assertM8PreparationRepairCheckpoint({requests:[],phase:'stopped-failure',inFlight:null},Buffer.from('{}'),Buffer.from('{}'))).toThrow('M8_EXACT_STOPPED_APPROVAL_PREPARATION_REQUIRED');});
});
