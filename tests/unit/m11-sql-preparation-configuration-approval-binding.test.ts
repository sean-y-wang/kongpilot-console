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
 const namespace:any=Object.freeze({workflow:{id:f.workflow.id,planRevision:1,planHash:f.workflow.plan_hash},approvalSet,version:1,origin:'scheduled-workflow',sessionId:null,actor:f.actor,clusterId:f.cid,workspaceId:f.wid,kind:'configuration_v2',expiresAt:new Date(expiry).toISOString()});
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
 Object.assign(f.wrapperExecution,{approval_set_id:approvalSet.setId,approval_set_hmac:approvalSet.setHmac});
 const preparation=Object.freeze({namespaceHandle,namespace});
 vi.spyOn(f.context,'scheduledConfigurationPreparationPhase').mockReturnValue(preparation as any);
 vi.spyOn(f.context,'verifyWorkflowScheduledNamespace').mockResolvedValue(namespace);
 const run=<T>(fn:()=>Promise<T>)=>f.context.runWorkflowScheduledNamespace(namespaceHandle,fn);
 return{...f,namespaceHandle,jobHandle,scheduled,origin,verifier,approvals,approvalSet,proof,run};
}

describe('configuration SQL preparation keeps execution-specific approval binding',()=>{
 it('uses actual encrypted plans and the fixed fresh canonical namespace set',async()=>{const f=await fixture();await f.run(async()=>{await expect(f.verifier.load(f.executionId,f.db,false,f.proof)).resolves.toBeDefined();expect(f.approvals.verifyApprovalSet).not.toHaveBeenCalled();});});
 it.each(['approval_set_id','approval_set_hmac'] as const)('rejects a substituted wrapper execution %s',async field=>{const f=await fixture();f.wrapperExecution[field]=field==='approval_set_id'?id(98):'8'.repeat(64);await f.run(async()=>{await expect(f.verifier.load(f.executionId,f.db,false,f.proof)).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVAL_SET_CHANGED'}});});});
 it.each(['job','epoch','stepAEAD','baseline','dependency'] as const)('retains the actual %s verifier checks',async change=>{const f=await fixture();
  if(change==='job')f.job.state='uncertain';if(change==='epoch')f.actorRow.credential_epoch=2;
  if(change==='stepAEAD')f.objects[0].payload_ciphertext='invalid';if(change==='baseline')f.baseline.completeness='incomplete';
  if(change==='dependency')f.rows[0].state='uncertain';
  await f.run(async()=>{await expect(change==='dependency'?f.verifier.step(f.proof,f.jobStepId):f.verifier.load(f.executionId,f.db,false,f.proof)).rejects.toThrow();});
 });
});
