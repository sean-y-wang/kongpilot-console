import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {configurationApprovedFixture,id} from '../security/m8-configuration-approved-fixture';
import {ConfigurationApprovedVerifier,CONFIGURATION_APPROVED_OPERATION_LINK_SQL,CONFIGURATION_APPROVED_SCHEDULED_OPERATION_LINK_SQL} from '../../apps/console-api/src/modules/workflows/configuration-approved-verifier';
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ba'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
/** Uses actual plan encryption/HMAC, ConfigurationVerifier and Context
 * namespace WeakMaps; database and fixed Origin/approval adapters are doubles.
 * No real SQL migration, timer, new native packet or business result is claimed. */
async function fixture(){
 const f=await configurationApprovedFixture(),namespaceHandle=Object.freeze({}),jobHandle=Object.freeze({}),expiry=f.claim.expiresAt;
 f.job.origin_type='http';for(const row of [f.workflow,f.wrapperVersion,f.wrapperExecution])row.approval_format=2;
 const approvalSet={format:2,setId:id(55),setHmac:'5'.repeat(64),reviewers:[{userId:id(41)},{userId:id(42)},{userId:id(43)}]};
 const namespace:any=Object.freeze({version:1,origin:'scheduled-workflow',sessionId:null,actor:f.actor,clusterId:f.cid,workspaceId:f.wid,kind:'configuration_v2',expiresAt:new Date(expiry).toISOString()});
 f.context.installWorkflowScheduledNamespacePolicy({assertLive(h){if(h!==namespaceHandle)throw Error('ORIGINAL_NAMESPACE_REQUIRED');},async verifyHandle(h){if(h!==namespaceHandle)throw Error('ORIGINAL_NAMESPACE_REQUIRED');return namespace;}});
 const scheduled:any={origin:'workflow-scheduled-configuration',sessionId:null,jobHandle,namespaceHandle,claimId:id(51),wrapperOriginId:id(52),wrapperExecutionId:f.wrapperExecution.id,
  configurationOriginId:id(53),configurationExecutionId:f.executionId,configurationJobId:f.jobId,configurationPlanId:f.job.plan_id,configurationPlanRevision:1,configurationPlanHash:f.job.plan_hash,
  configurationClaimHash:f.claim.claimHash,workflowId:f.workflow.id,workflowPlanRevision:1,workflowPlanHash:f.workflow.plan_hash,actorId:f.actor.id,clusterId:f.cid,workspaceId:f.wid,
  permissionVersion:f.claim.permissionVersion,credentialEpoch:1,leaseGeneration:1,expiresAt:expiry};
 Object.assign(f.claim,{sessionId:null,scheduledOrigin:scheduled});
 const origin:any={id:scheduled.configurationOriginId,configuration_execution_id:f.executionId,configuration_job_id:f.jobId,configuration_plan_id:f.job.plan_id,configuration_plan_revision:1,configuration_plan_hash:f.job.plan_hash,
  cluster_id:f.cid,workspace_id:f.wid,wrapper_origin_id:scheduled.wrapperOriginId,claim_id:scheduled.claimId,workflow_id:f.workflow.id,workflow_plan_revision:1,workflow_plan_hash:f.workflow.plan_hash,
  workflow_execution_id:f.wrapperExecution.id,workflow_step_id:f.wrapper.steps[0].id,scheduled_executor:f.actor.id,generation:1,authority_expires_at:new Date(expiry),worker_owner_hmac:'9'.repeat(64),
  wrapper_execution_id:f.wrapperExecution.id,progress_state:'running',progress_claim_id:scheduled.claimId,lease_until:new Date(expiry),lease_worker_owner_hmac:'9'.repeat(64)};
 const oldOne=f.db.one.getMockImplementation()!,oldExec=f.db.exec.getMockImplementation()!;
 f.db.one.mockImplementation(async(sql:string,p:any[])=>sql.includes('FROM workflow_configuration_execution_origins')?origin:sql.includes('SELECT j.origin_session_id,s.id AS wrapper_step_id')?{origin_session_id:f.sid,wrapper_step_id:f.wrapper.steps[0].id}:
  sql.startsWith('SELECT id FROM workflow_steps')?f.wrapperRows[0]:oldOne(sql,p));
 f.db.exec.mockImplementation(async(sql:string,p:any[])=>sql===CONFIGURATION_APPROVED_SCHEDULED_OPERATION_LINK_SQL?oldExec(CONFIGURATION_APPROVED_OPERATION_LINK_SQL,p.slice(0,22)):oldExec(sql,p));
 const approvals:any={verifyApprovalSet:vi.fn(async()=>approvalSet)};
 const verifier=new ConfigurationApprovedVerifier(f.db,f.secrets,f.authz,f.kong,f.redis,f.context,approvals);verifier.install(f.delegate);
 const proof:any={executionId:f.executionId,workflowId:f.workflow.id,clusterId:f.cid,workspaceId:f.wid,actorId:f.actor.id,sessionId:null,origin:'scheduled-configuration',scheduleClaimId:scheduled.claimId,
  workflowOriginId:scheduled.wrapperOriginId,configurationOriginId:scheduled.configurationOriginId,permissionVersion:f.claim.permissionVersion,expiresAt:Math.min(Date.now()+120_000,expiry),approvalFormat:2,approvalSetId:approvalSet.setId,approvalSetHmac:approvalSet.setHmac};
 const run=<T>(fn:()=>Promise<T>)=>f.context.runWorkflowScheduledNamespace(namespaceHandle,fn);
 return{...f,namespaceHandle,jobHandle,scheduled,origin,verifier,approvals,approvalSet,proof,run};
}
describe('NULL SID ConfigurationVerifier independently binds actual SQL026 origins',()=>{
 it('loads exact original job and baseline using current user epoch without adopting the authoring session',async()=>{const f=await fixture();await f.run(async()=>{
  const loaded=await f.verifier.load(f.executionId,f.db,false,f.proof);expect(loaded.scheduledOrigin).toBe(f.scheduled);expect(loaded.job.origin_session_id).toBe(f.sid);
  expect(f.context.current().sessionId).toBeUndefined();expect(f.db.one.mock.calls.some(([s]:any[])=>s.includes('FROM auth_sessions'))).toBe(false);
  expect(f.approvals.verifyApprovalSet).toHaveBeenCalledWith(expect.objectContaining({workflowId:f.workflow.id}),{executionId:f.wrapperExecution.id,checkpoint:'packet'},f.db);
 });expect(f.kong.request).not.toHaveBeenCalled();});
 it.each(['configurationJobId','configurationPlanHash','configurationClaimHash','wrapperExecutionId','actorId','namespaceHandle','leaseGeneration','credentialEpoch'])('rejects original claim %s substitution before native work',async field=>{const f=await fixture();f.scheduled[field]=field==='namespaceHandle'?{}:field==='credentialEpoch'||field==='leaseGeneration'?2:field.endsWith('Hash')?'a'.repeat(64):id(99);
  await f.run(async()=>{await expect(f.verifier.load(f.executionId)).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVED_SCHEDULE_ORIGIN_MISMATCH'}});});expect(f.kong.request).not.toHaveBeenCalled();});
 it.each(['configuration_job_id','configuration_plan_hash','workflow_execution_id','scheduled_executor','generation','progress_claim_id','progress_state','lease_worker_owner_hmac'])('rejects actual 026 %s mismatch independently from the supplied private claim',async field=>{const f=await fixture();f.origin[field]=field==='generation'?2:field==='progress_state'?'uncertain':field.endsWith('hash')||field.endsWith('hmac')?'a'.repeat(64):id(99);
  await f.run(async()=>{await expect(f.verifier.load(f.executionId)).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVED_SCHEDULE_ORIGIN_MISMATCH'}});});expect(f.kong.request).not.toHaveBeenCalled();});
 it.each(['lease_until','authority_expires_at'])('rejects expired %s even if the job plan is still valid',async field=>{const f=await fixture();f.origin[field]=new Date(Date.now()-1);await f.run(async()=>{await expect(f.verifier.load(f.executionId)).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVED_EXPIRED'}});});});
 it('never accepts NULL on the persisted SQL011 authoring job',async()=>{const f=await fixture();f.job.origin_session_id=null;await f.run(async()=>{await expect(f.verifier.load(f.executionId)).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVED_JOB_MISMATCH'}});});});
 it('keeps current force-password-change and epoch fences when there is no HTTP session',async()=>{const f=await fixture();f.actorRow.credential_epoch=2;await f.run(async()=>{await expect(f.verifier.load(f.executionId)).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVED_SCHEDULE_ORIGIN_MISMATCH'}});});});
 it('requires the approved format2 set and does not degrade to the legacy single reviewer',async()=>{const f=await fixture();for(const row of [f.workflow,f.wrapperVersion,f.wrapperExecution])row.approval_format=1;await f.run(async()=>{await expect(f.verifier.load(f.executionId)).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVAL_INCOMPLETE'}});});});
 it.each(['origin','scheduleClaimId','workflowOriginId','configurationOriginId'])('rejects Approved proof %s cross-ledger substitution',async field=>{const f=await fixture();f.proof[field]=field==='origin'?'scheduled-workflow':id(99);await f.run(async()=>{await expect(f.verifier.load(f.executionId,f.db,false,f.proof)).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVED_SCHEDULE_ORIGIN_MISMATCH'}});});});
 it('uses the preserved authoring SID plus exact 026 tuple in reciprocal V2 binding; wrapper receives no V1 binding',async()=>{const f=await fixture();const binding:any={version:2,workflowId:f.workflow.id,configurationJobId:f.jobId,configurationExecutionId:f.executionId,configurationStepId:f.jobStepId,configurationPlanRevision:1,configurationPlanHash:f.job.plan_hash,beforeHmac:f.step.beforeHmac};
  const operation=f.op(binding);f.operations.set(operation.id,operation);await f.run(async()=>{await f.db.transaction((tx:any)=>f.verifier.bind(f.proof,f.jobStepId,f.mutation,binding,operation.id,tx));});
  const call=f.db.exec.mock.calls.find(([sql]:any[])=>sql===CONFIGURATION_APPROVED_SCHEDULED_OPERATION_LINK_SQL);expect(call?.[1][11]).toBe(f.sid);expect(call?.[1].slice(22)).toEqual([f.scheduled.configurationOriginId,f.scheduled.wrapperOriginId,f.scheduled.claimId,f.wrapper.steps[0].id]);
  expect(f.rows[0].operation_id).toBe(operation.id);expect(operation.workflow_execution_id).toBeUndefined();expect(operation.configuration_execution_id).toBe(f.executionId);
 });
});
