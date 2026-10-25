import{describe,it,expect,vi}from'vitest';
const child=vi.hoisted(()=>({execFileSync:vi.fn(),spawnSync:vi.fn()}));
vi.mock('node:child_process',()=>child);
import{M8_RECIPROCAL_BINDING_STOPPED as c,assertM8ReciprocalBindingNoNative,assertM8ReciprocalBindingRepairCheckpoint,m8ReciprocalBindingStoppedProof}from'./lib/m8-reciprocal-binding-repair.mjs';
function original(){return{workflow_id:c.workflowId,job_id:c.jobId,plan_id:c.planId,workflow_execution_id:c.workflowExecutionId,workflow_step_id:c.workflowStepId,configuration_execution_id:c.configurationExecutionId,
 workflow_state:'failed',workflow_execution_state:'failed',workflow_step_state:'failed',snapshot_state:'ready',job_state:'failed',job_error_code:'CONFIGURATION_NATIVE_BINDING_CHANGED',plan_state:'approved',configuration_execution_state:'failed',configuration_execution_completed:true,workflow_execution_completed:true,
 remote_started:false,remote_completed:false,same_request:true,same_key:true,same_actor:true,same_sid:true,same_plan_hash:true,same_workflow_tuple:true,handler:'configuration_v2',kind:'metadata',native_request_count:0,operation_id:null,configuration_execution_count:1,configuration_step_count:17,pending_unstarted_step_count:16,failed_unstarted_step_count:1,native_operation_count:0};}
describe('M8 exact terminal reciprocal-binding failure checkpoint',()=>{
 it('retains known terminal failure and requires all seventeen Native operations unstarted with the first rejected authorization retained',()=>{const row=original();expect(assertM8ReciprocalBindingNoNative(row)).toBe(row);expect(row.job_state).toBe('failed');});
 for(const[field,value]of[
  ['workflow_id','foreign'],['job_id','foreign'],['plan_id','foreign'],['workflow_execution_id','foreign'],['workflow_step_id','foreign'],['configuration_execution_id','foreign'],
  ['workflow_state','uncertain'],['workflow_execution_state','executing'],['workflow_step_state','succeeded'],['snapshot_state','pending'],['job_state','running'],['job_error_code','ANOTHER_ERROR'],['plan_state','pending_approval'],['configuration_execution_state','executing'],['configuration_execution_completed',false],['workflow_execution_completed',false],
  ['remote_started',true],['remote_completed',true],['same_request',false],['same_key',false],['same_actor',false],['same_sid',false],['same_plan_hash',false],['same_workflow_tuple',false],['handler','configuration.metadata'],['kind','native'],['native_request_count',1],['operation_id',c.workflowStepId],['configuration_execution_count',2],['configuration_step_count',16],['pending_unstarted_step_count',17],['failed_unstarted_step_count',0],['native_operation_count',1],
 ]as const)it(`rejects changed ${field} before a new independent validation`,()=>expect(()=>assertM8ReciprocalBindingNoNative({...original(),[field]:value})).toThrow('M8_CURRENT_FAILED_RECIPROCAL_BINDING_WITH_ZERO_NATIVE_REQUIRED'));
 it('rejects absent/partial current proof',()=>{expect(()=>assertM8ReciprocalBindingNoNative(null)).toThrow();const row:any=original();delete row.same_actor;expect(()=>assertM8ReciprocalBindingNoNative(row)).toThrow();});
 it('rejects fabricated failure/source checkpoint without exact frozen artifacts',()=>expect(()=>assertM8ReciprocalBindingRepairCheckpoint({requests:[]},Buffer.from('{}'),Buffer.from('{}'))).toThrow('M8_EXACT_FAILED_RECIPROCAL_BINDING_CHECKPOINT_REQUIRED'));
 it('binds current SQL proof to the exact original apply/approval packets rather than a prior validation',async()=>{
  child.execFileSync.mockReturnValue('c'.repeat(64));child.spawnSync.mockReturnValue({status:0,stdout:JSON.stringify({ok:true,nonOwnerReadOnly:true,row:original()})});
  const requests:any[]=Array.from({length:115},()=>({}));requests[100]={responseData:{planHash:'0'.repeat(64)}};requests[112]={responseData:{planHash:'1'.repeat(64)}};requests[113]={responseData:{entity:{planHash:'2'.repeat(64)}}};
  const actor={user:{id:'10000000-0000-4000-8000-000000000001'},sid:'10000000-0000-4000-8000-000000000002'},area={cid:'10000000-0000-4000-8000-000000000003',wid:'10000000-0000-4000-8000-000000000004'};
  await m8ReciprocalBindingStoppedProof({state:{requests},check:(value:boolean)=>expect(value).toBe(true)},actor,area);
  const args=child.spawnSync.mock.calls[0],input=JSON.parse(args[2].input);
  expect(input).toMatchObject({jobId:c.jobId,workflowId:c.workflowId,requestId:c.requestId,key:c.key,actorId:actor.user.id,sid:actor.sid,cid:area.cid,wid:area.wid,planHash:'1'.repeat(64),workflowPlanHash:'2'.repeat(64)});
  expect(args[1].at(-1)).toContain('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');expect(args[1].at(-1)).not.toMatch(/\b(?:INSERT|UPDATE|DELETE|TRUNCATE)\b/);
 });
});
