import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {ApprovedWorkflowExecutionService} from '../../apps/console-api/src/modules/workflows/approved-workflow-execution.service';
import {WorkflowBusinessRuntimeService} from '../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import {planAad} from '../../apps/console-api/src/modules/workflows/workflow.types';
import {createDurableRepositoryFixture,NOW} from './helpers/m11-durable-scheduled-proposal-fixture';

/** Real Runtime proposal policy -> Approved subject/origin -> durable repository
 * -> real AEAD/HMAC records, against exact SQL fixtures. This proves Source
 * component behavior only; no database transaction, HTTP or Native execution. */
function fixture(){
 const f=createDurableRepositoryFixture(),context=new KongExecutionContextService();
 const actor:any={user:{id:f.ids.owner,username:'durable-author',superAdmin:false},workspaceId:f.ids.workspace,requestId:randomUUID(),ip:'127.0.0.1'};
 const accepted={sessionId:f.ids.sid,credentialEpoch:'1',permissionVersion:f.e.permissionVersion};
 const state={session:true,epoch:'1',permissions:'1',iam:'1',grant:true,deniedModule:'',lease:true,subjectPlans:[] as any[],grantChecks:0,materialPlans:[] as any[]};
 Object.assign(f.rows.job,{transport_scope:f.workflow.scope.transportScope,state:'waiting_approval'});
 const originalOne=f.tx.one.bind(f.tx);
 const tx:any={...f.tx,one:vi.fn(async(sql:string,args:any[])=>{
  if(sql===`SELECT u.id,u.credential_epoch,u.permissions_epoch,i.version FROM auth_sessions s JOIN users u ON u.id=s.user_id
      CROSS JOIN iam_epoch i WHERE s.id=$1 AND u.id=$2 AND i.singleton=true AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
      AND s.credential_epoch=u.credential_epoch AND u.status='active' AND u.deleted_at IS NULL AND NOT u.force_password_change FOR SHARE OF s,u,i`){
   expect(args).toEqual([f.ids.sid,f.ids.owner]);return state.session?{id:f.ids.owner,credential_epoch:state.epoch,permissions_epoch:state.permissions,version:state.iam}:null;
  }
  return originalOne(sql,args);
 })};
 const authz:any={assertWholeWorkspace:vi.fn(async(user:any,cid:string,wid:string,module:string,action:string)=>{
  expect(user).toBe(actor.user);expect([cid,wid,action]).toEqual([f.ids.cluster,f.ids.workspace,'write']);expect(['workflows','snapshots']).toContain(module);state.grantChecks++;
  if(!state.grant||module===state.deniedModule)throw new ForbiddenException({code:'CURRENT_WORKFLOW_WRITE_REVOKED'});
 })},redis:any={assertLeaseOwnership:vi.fn(async()=>{if(!state.lease)throw new ForbiddenException({code:'LEASE_LOST'});})};
 const kong:any={request:vi.fn(async()=>{throw Error('NO_KONG_CALL_IN_PROPOSAL_SOURCE_TEST');})};
 const approved=new ApprovedWorkflowExecutionService(tx,f.secrets,authz,{} as any,kong,redis,context);
 approved.installConfigurationDelegate({verifyExecution:async()=>{throw Error('NO_EXECUTION_IN_PROPOSAL_SOURCE_TEST');},assertOrigin:async(plan,actorId,action,actualTx)=>{
  expect(actualTx).toBe(tx);expect([actorId,action]).toEqual([actor.user.id,'write']);state.subjectPlans.push(plan);
  await f.repository.verifyWorkflow(plan,actualTx);
 }});
 const material:any={materialForPlan:vi.fn(async(plan:any,actualTx:any)=>{
  expect(actualTx).toBe(tx);state.materialPlans.push(plan);await f.repository.verifyWorkflow(plan,actualTx);
  const e=await f.repository.verify(f.rows.job,actualTx,true,f.plan);return{kind:'configuration_v2',plan:f.plan,subjectSeal:{materialHmac:e!.plan.planHash}};
 })};
 const runtime:any=new WorkflowBusinessRuntimeService(tx,redis,f.secrets,context,kong,authz,{} as any,{} as any,approved,{} as any,{} as any,
  {} as any,{} as any,{} as any,{} as any,material,{} as any,{} as any,{} as any,{} as any,{} as any);
 const basePlan={...structuredClone(f.workflow),planRevision:2,issuedAt:new Date(NOW+16*60_000).toISOString(),steps:[{...structuredClone(f.workflow.steps[0]),id:randomUUID()}]};
 const plan:any={...basePlan,scheduling:{ownerId:actor.user.id,executorId:actor.user.id,ownerCredentialEpoch:'1'}};
 const input:any={old:{plan:f.workflow},basePlan,actor,acceptance:accepted,transaction:tx,plan,
  spec:{windowEnd:new Date(NOW+20*60_000).toISOString()},draft:{binding:{subjectSeal:{materialHmac:f.e.plan.planHash}}}};
 const persist=()=>{f.rows.workflow.plan_revision=plan.planRevision;f.rows.workflow.plan_hash=f.secrets.fingerprint(plan);
  f.rows.workflowVersions['2']={workflow_id:f.ids.workflow,cluster_id:f.ids.cluster,workspace_id:f.ids.workspace,plan_revision:2,
   plan_hash:f.secrets.fingerprint(plan),payload_secret:f.secrets.encrypt(plan,planAad(f.ids.cluster,f.ids.workspace,f.ids.workflow,2))};};
 const run=<T>(fn:()=>Promise<T>)=>context.runHttp({requestId:actor.requestId},async()=>{
  context.bindHttpActor(actor.user,f.ids.sid);return context.runActor({actor:actor.user,clusterId:f.ids.cluster,workspaceId:f.ids.workspace,module:'workflows',action:'write',purpose:'configuration'},fn);
 });
 return{...f,tx,actor,accepted,state,context,authz,redis,kong,approved,material,runtime,basePlan,plan,input,persist,run};
}

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','71'.repeat(32));vi.stubEnv('APP_SECRET','proposal-source-impact-key-'.repeat(3));vi.useFakeTimers();vi.setSystemTime(NOW+16*60_000);});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});

describe('durable scheduled proposal uses the actual current persisted workflow version',()=>{
 it('authorizes old stored revision before persistence sixteen minutes after issuance and after its admission deadline',async()=>{
  const f=fixture();expect(Date.now()).toBeGreaterThan(Date.parse(f.e.admissionExpiresAt));expect(Date.now()).toBeGreaterThan(NOW+15*60_000);
  await f.run(()=>f.runtime.prepareProposal(f.input));expect(f.state.subjectPlans).toEqual([f.workflow]);expect(f.state.grantChecks).toBe(2);
  expect(f.e.expiresAt).toBe(new Date(NOW+24*3_600_000).toISOString());expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('authorizes the newly persisted scheduling revision in the same transaction without renewing original authority',async()=>{
  const f=fixture();f.persist();
  // The real repository intentionally still rejects the obsolete initial wrapper.
  await expect(f.repository.verifyWorkflow(f.workflow,f.tx)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_BINDING_INVALID'}});
  await expect(f.repository.verifyWorkflow(f.plan,f.tx)).resolves.toBeUndefined();
  await expect(f.run(()=>f.runtime.proposalPrincipal({...f.input,checkpoint:'after-version'},f.plan))).resolves.toBeUndefined();
  expect(f.state.subjectPlans).toEqual([f.plan]);expect(f.state.grantChecks).toBe(2);expect(f.redis.assertLeaseOwnership).toHaveBeenCalledOnce();
  expect(f.plan.expiresAt).toBe(f.e.expiresAt);expect(f.rows.issue.expires_at).toBe(f.e.expiresAt);expect(f.rows.binding.workflow_plan_revision).toBe(1);
  expect(f.rows.workflowVersions['1'].plan_hash).toBe(f.secrets.fingerprint(f.workflow));expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('selects the persisted after-version plan through the complete assertProposal policy',async()=>{
  const f=fixture();f.persist();const prepared=await f.run(()=>f.runtime.prepareProposal({...f.input,old:{plan:f.plan},basePlan:{...f.plan,planRevision:3}}));
  // Derive exactly the same impact with the real policy, then verify revision2.
  f.input.draft.impact=prepared.impact;f.state.subjectPlans=[];f.state.materialPlans=[];
  await expect(f.run(()=>f.runtime.assertProposal({...f.input,checkpoint:'after-version'}))).resolves.toBeUndefined();
  expect(f.state.subjectPlans).toEqual([f.plan]);expect(f.state.materialPlans).toEqual([f.plan]);expect(f.state.grantChecks).toBe(4);
 });
 it('keeps the same original transaction and permissions across prepare, before-version and after-version checkpoints',async()=>{
  const f=fixture(),prepared=await f.run(()=>f.runtime.prepareProposal(f.input));f.input.draft.impact=prepared.impact;
  await expect(f.run(()=>f.runtime.assertProposal({...f.input,checkpoint:'before-version'}))).resolves.toBeUndefined();
  expect(f.rows.workflow.plan_revision).toBe(1);f.persist();
  await expect(f.run(()=>f.runtime.assertProposal({...f.input,checkpoint:'after-version'}))).resolves.toBeUndefined();
  expect(f.state.subjectPlans).toEqual([f.workflow,f.workflow,f.plan]);expect(f.state.materialPlans).toEqual([f.workflow,f.workflow,f.plan]);
  expect(f.state.grantChecks).toBe(6);expect(f.redis.assertLeaseOwnership).toHaveBeenCalledTimes(3);expect(f.kong.request).not.toHaveBeenCalled();
 });
 it.each(['session','epoch','permissions','iam'] as const)('refuses current %s revocation after persistence',async field=>{
  const f=fixture();f.persist();if(field==='session')f.state.session=false;else f.state[field]='2';
  await expect(f.run(()=>f.runtime.proposalPrincipal({...f.input,checkpoint:'after-version'},f.plan))).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_PROPOSAL_IDENTITY_CHANGED'}});
  expect(f.state.subjectPlans).toEqual([]);expect(f.state.grantChecks).toBe(0);
 });
 it('still enforces current subject write grants after the new revision is persisted',async()=>{
  const f=fixture();f.persist();f.state.grant=false;
  await expect(f.run(()=>f.runtime.proposalPrincipal({...f.input,checkpoint:'after-version'},f.plan))).rejects.toMatchObject({response:{code:'CURRENT_WORKFLOW_WRITE_REVOKED'}});
  expect(f.state.subjectPlans).toEqual([f.plan]);expect(f.state.grantChecks).toBe(1);expect(f.redis.assertLeaseOwnership).not.toHaveBeenCalled();
 });
 it('checks snapshots write as well as workflows write after the new revision is persisted',async()=>{
  const f=fixture();f.persist();f.state.deniedModule='snapshots';
  await expect(f.run(()=>f.runtime.proposalPrincipal({...f.input,checkpoint:'after-version'},f.plan))).rejects.toMatchObject({response:{code:'CURRENT_WORKFLOW_WRITE_REVOKED'}});
  expect(f.state.subjectPlans).toEqual([f.plan]);expect(f.state.grantChecks).toBe(2);expect(f.redis.assertLeaseOwnership).not.toHaveBeenCalled();
 });
 it('rejects a lost original lease after current-version subject and grant verification',async()=>{
  const f=fixture();f.persist();f.state.lease=false;
  await expect(f.run(()=>f.runtime.proposalPrincipal({...f.input,checkpoint:'after-version'},f.plan))).rejects.toMatchObject({response:{code:'LEASE_LOST'}});
  expect(f.state.subjectPlans).toEqual([f.plan]);expect(f.state.grantChecks).toBe(2);
 });
 it.each(['ciphertext','initial-ciphertext','plan-hash','plan-metadata','tenant','deadline'] as const)('refuses a substituted current %s with the original durable binding',async kind=>{
  const f=fixture();f.persist();let current=f.plan;
  if(kind==='ciphertext')f.rows.workflowVersions['2'].payload_secret='v1.invalid.invalid.invalid';
  if(kind==='initial-ciphertext')f.rows.workflowVersions['1'].payload_secret='v1.invalid.invalid.invalid';
  if(kind==='plan-hash')f.rows.workflow.plan_hash='0'.repeat(64);
  if(kind==='plan-metadata')current={...f.plan,steps:[{...f.plan.steps[0],metadata:{...f.plan.steps[0].metadata,planHash:'0'.repeat(64)}}]};
  if(kind==='tenant')current={...f.plan,workspaceId:randomUUID()};
  if(kind==='deadline')current={...f.plan,expiresAt:new Date(Date.parse(f.e.expiresAt)+1).toISOString()};
  await expect(f.run(()=>f.runtime.proposalPrincipal({...f.input,checkpoint:'after-version'},current))).rejects.toThrow();
  expect(f.state.grantChecks).toBe(0);expect(f.redis.assertLeaseOwnership).not.toHaveBeenCalled();
 });
 it('rejects trying the future revision before it has actually been persisted',async()=>{
  const f=fixture();await expect(f.run(()=>f.runtime.proposalPrincipal({...f.input,checkpoint:'after-version'},f.plan))).rejects.toThrow();
  expect(f.state.grantChecks).toBe(0);expect(f.rows.workflow.plan_revision).toBe(1);
 });
 it('does not extend the durable material deadline for the after-version policy',async()=>{
  const f=fixture();f.persist();vi.setSystemTime(Date.parse(f.e.expiresAt));
  await expect(f.run(()=>f.runtime.assertProposal({...f.input,checkpoint:'after-version'}))).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_BINDING_INVALID'}});
  expect(f.plan.expiresAt).toBe(f.e.expiresAt);expect(f.rows.issue.expires_at).toBe(f.e.expiresAt);
 });
});
