import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ConfigurationOriginService} from '../../apps/console-api/src/modules/configuration/configuration-origin.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {governanceComparisonEnvelope} from '../../apps/console-api/src/modules/governance/governance-comparison-material';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ec'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
/** Actual SourceOrigin authenticated codec, SQL marker checks and Context
 * namespace ancestry. Fixed job verifier/current raw reader use explicit
 * dependency doubles. No runtime database or production material is read. */
const id=(n:number)=>`ac110000-0000-4000-8000-${String(n).padStart(12,'0')}`;
async function fixture(install=true){
 const secrets=new SecretService(),context=new KongExecutionContextService(),namespaceHandle=Object.freeze({}),jobHandle=Object.freeze({});
 const actor={id:id(1),username:'synthetic-executor',superAdmin:false},sourceCid=id(2),sourceWid=id(3),cid=id(4),wid=id(5),promotionId=id(6),comparisonId=id(7);
 const inventory=(target=false):any=>({scope:{clusterId:target?cid:sourceCid,workspaceId:target?wid:sourceWid,transportScope:target?'b'.repeat(64):'a'.repeat(64),kind:'workspace',rootIds:[]},
  objects:[{entityType:'services',nativeId:id(target?9:8),payload:{id:id(target?9:8),name:target?'target':'source',tags:['workspace:synthetic']},sensitiveFields:[]}],
  schemas:{},pluginSchemas:{},enabledPlugins:[],version:'1.5.1',adapterVersion:'kong-1.5',completeness:'complete',projection:false});
 const source=inventory(),target=inventory(true),sourceSeals={[`services:${id(8)}`]:'c'.repeat(64)},targetSeals={[`services:${id(9)}`]:'d'.repeat(64)};
 const s=governanceComparisonEnvelope(source,sourceSeals),t=governanceComparisonEnvelope(target,targetSeals),selection={includeSecrets:false,includeCredentials:false,targetWorkspaceCode:'synthetic'},policy={scope:'workspace'};
 const comparison:any={id:comparisonId,cluster_id:sourceCid,workspace_id:sourceWid,target_cluster_id:cid,target_workspace_id:wid,quality:'complete',policy,
  policy_hmac:secrets.fingerprint(policy),source_inventory_secret:secrets.encrypt(s,`governance:comparison-source:${comparisonId}`),
  target_inventory_secret:secrets.encrypt(t,`governance:comparison-target:${comparisonId}`),source_inventory_hmac:secrets.fingerprint(s),target_inventory_hmac:secrets.fingerprint(t)};
 const parent:any={id:promotionId,comparison_id:comparisonId,cluster_id:sourceCid,workspace_id:sourceWid,target_cluster_id:cid,target_workspace_id:wid,
  actor_id:actor.id,state:'ready',request_hmac:'e'.repeat(64),selection_secret:secrets.encrypt(selection,`governance:promotion-selection:${promotionId}`),
  selection_hmac:secrets.fingerprint(selection),source_inventory_hmac:comparison.source_inventory_hmac,target_inventory_hmac:comparison.target_inventory_hmac};
 const job:any={id:id(10),cluster_id:cid,workspace_id:wid,actor_id:actor.id,origin_type:'http',origin_session_id:id(11),kind:'apply',execution_mode:'approval',approval_required:true,
  transport_scope:target.scope.transportScope,plan_id:id(12),plan_revision:2,plan_hash:'f'.repeat(64),permission_version:'current-iam',credential_epoch:3,lease_generation:1,
  authority_expires_at:new Date(Date.now()+120000).toISOString(),expires_at:new Date(Date.now()+120000).toISOString(),required_origin_kind:'governance-promote',required_origin_id:promotionId};
 const binding:any={cluster_id:cid,workspace_id:wid,job_id:job.id,origin_kind:'governance-promote',origin_id:promotionId,source_cluster_id:sourceCid,source_workspace_id:sourceWid,comparison_id:comparisonId};
 const planBinding:any={cluster_id:cid,workspace_id:wid,job_id:job.id,plan_id:job.plan_id,plan_revision:job.plan_revision,plan_hash:job.plan_hash,origin_kind:'governance-promote',origin_id:promotionId};
 const db:any={one:vi.fn(async(sql:string)=>{if(sql.includes('FROM governance_promotions'))return structuredClone(parent);
  if(sql.includes('FROM governance_comparisons'))return structuredClone(comparison);if(sql.includes('FROM promotion_recovery_bindings'))return null;
  if(sql.includes('FROM configuration_job_origin_bindings'))return structuredClone(binding);if(sql.includes('FROM configuration_plan_origin_bindings'))return structuredClone(planBinding);
  if(sql.includes('FROM configuration_jobs'))return structuredClone(job);throw Error('UNEXPECTED_SQL');}),exec:vi.fn(),query:vi.fn()};
 const origin=new ConfigurationOriginService(db,secrets,context),loaded=await(origin as any).load(promotionId),ref=loaded.ref;
 job.required_origin_hmac=ref.materialHmac;binding.material_hmac=ref.materialHmac;planBinding.material_hmac=ref.materialHmac;
 const proof:any={origin:'workflow-scheduled-configuration',sessionId:null,actor,clusterId:cid,workspaceId:wid,module:'snapshots',purpose:'apply',jobId:job.id,
  permissionVersion:'current-iam',credentialEpoch:3,leaseGeneration:1,expiresAt:Date.now()+60000,readOnly:false,namespaceHandle,
  claimId:id(13),wrapperOriginId:id(14),wrapperExecutionId:id(15),planId:job.plan_id,planRevision:job.plan_revision,planHash:job.plan_hash,subjectSealHmac:'1'.repeat(64)};
 const namespaceProof:any=Object.freeze({origin:'scheduled-workflow',sessionId:null,actor,clusterId:cid,workspaceId:wid,kind:'configuration_v2',expiresAt:new Date(Date.now()+60000).toISOString()});
 let live=true;context.installWorkflowScheduledNamespacePolicy({assertLive(h){if(h!==namespaceHandle||!live)throw Error('CURRENT_NAMESPACE_CLOSED');},
  async verifyHandle(h){if(h!==namespaceHandle||!live)throw Error('ORIGINAL_NAMESPACE_REQUIRED');return namespaceProof;}});
 const handles=new WeakSet<object>();handles.add(jobHandle);
 const bridge={currentOriginalJobHandle:vi.fn(()=>jobHandle),verifyOriginalJobHandle:vi.fn(async(h:object)=>{if(!handles.has(h)||!live)throw Error('ORIGINAL_JOB_REQUIRED');return proof;}),
  assertCurrentSourceMaterial:vi.fn(async()=>undefined),assertExecutionBudget:vi.fn(async()=>undefined)};
 if(install)origin.installWorkflowScheduledOrigin(bridge as any);
 const httpPolicy:any={acquire:vi.fn(),refresh:vi.fn(),fingerprints:vi.fn(),assertCurrent:vi.fn(),assertVerifierCurrent:vi.fn(),assertGrants:vi.fn()};origin.install(httpPolicy);
 const run=<T>(fn:()=>Promise<T>)=>context.runWorkflowScheduledNamespace(namespaceHandle,fn),assert=(phase='step')=>origin.assertJob(job,phase,actor.id,db);
 db.one.mockClear();return{origin,context,secrets,namespaceHandle,jobHandle,actor,job,ref,parent,comparison,binding,planBinding,proof,sourceSeals,targetSeals,bridge,httpPolicy,db,run,assert,revoke(){live=false;}};
}

describe('scheduled Promote origin preserves complete SQL 018 material and current source checks',()=>{
 it('uses genuine NULL-SID ancestry and the exact original job; no historical HTTP source proof is adopted',async()=>{
  const f=await fixture();await f.run(async()=>{await f.assert('step');await f.origin.beforeNativeSend(f.job.id,f.actor.id);});
  expect(f.bridge.assertCurrentSourceMaterial).toHaveBeenCalledTimes(2);expect(f.bridge.verifyOriginalJobHandle.mock.calls.map(c=>c[1])).toEqual(['ledger','before-send']);
  const input=f.bridge.assertCurrentSourceMaterial.mock.calls[0][0];expect(input).toMatchObject({phase:'step',action:'write',actorId:f.actor.id,ref:f.ref,
   job:{origin_session_id:f.job.origin_session_id},proof:{sessionId:null},sourceNativeFingerprints:f.sourceSeals,targetNativeFingerprints:f.targetSeals});
  expect(input.originalJobHandle).toBe(f.jobHandle);expect(input.proof.namespaceHandle).toBe(f.namespaceHandle);
  expect(f.context.peek()).toBeNull();for(const fn of Object.values(f.httpPolicy))expect(fn).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('a missing bridge fails closed despite complete stored markers and an installed HTTP provider',async()=>{
  const f=await fixture(false);await expect(f.run(f.assert)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGIN_BRIDGE_UNAVAILABLE'}});
  expect(f.httpPolicy.assertGrants).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('installs exactly once and rejects incomplete bridge callbacks',async()=>{
  const f=await fixture(false);expect(()=>f.origin.installWorkflowScheduledOrigin({}as any)).toThrow();f.origin.installWorkflowScheduledOrigin(f.bridge as any);
  expect(()=>f.origin.installWorkflowScheduledOrigin(f.bridge as any)).toThrow();
 });
 it('requires the independent budget callback rather than accepting a source reader alone',async()=>{
  const f=await fixture(false),{assertExecutionBudget:_,...incomplete}=f.bridge;
  expect(()=>f.origin.installWorkflowScheduledOrigin(incomplete as any)).toThrow();
 });
 it.each(['jobId','actor','namespaceHandle','planId','planRevision','planHash','credentialEpoch','permissionVersion','leaseGeneration','sessionId','origin','readOnly'])('refuses changed original %s before invoking the raw source reader',async field=>{
  const f=await fixture();f.proof[field]=field==='actor'?{...f.actor,id:id(99)}:field==='namespaceHandle'?{}:field==='readOnly'?true:field==='planRevision'||field==='credentialEpoch'||field==='leaseGeneration'?99:id(99);
  await expect(f.run(f.assert)).rejects.toThrow();expect(f.bridge.assertCurrentSourceMaterial).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('does not extend a persisted deadline to fit the future schedule proof',async()=>{
  const f=await fixture();f.job.authority_expires_at=new Date(Date.now()+1000).toISOString();await expect(f.run(f.assert)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGIN_PROOF_INVALID'}});
  expect(f.bridge.assertCurrentSourceMaterial).not.toHaveBeenCalled();
 });
 it.each(['source_cluster_id','source_workspace_id','comparison_id','material_hmac'])('keeps the actual job source binding %s mandatory',async field=>{
  const f=await fixture();f.binding[field]=field==='material_hmac'?'9'.repeat(64):id(99);
  await expect(f.run(f.assert)).rejects.toThrow();expect(f.bridge.assertCurrentSourceMaterial).not.toHaveBeenCalled();
 });
 it.each(['job_id','origin_id','origin_kind','material_hmac'])('keeps the actual plan binding %s mandatory',async field=>{
  const f=await fixture();f.planBinding[field]=field==='material_hmac'?'9'.repeat(64):id(99);
  await expect(f.run(f.assert)).rejects.toThrow();expect(f.bridge.assertCurrentSourceMaterial).not.toHaveBeenCalled();
 });
 it('re-checks source permissions on every call without caching a previous success',async()=>{
  const f=await fixture();await f.run(async()=>{await f.assert();f.bridge.assertCurrentSourceMaterial.mockRejectedValueOnce(Error('SOURCE_PERMISSION_REVOKED'));
   await expect(f.assert()).rejects.toThrow('SOURCE_PERMISSION_REVOKED');});expect(f.bridge.assertCurrentSourceMaterial).toHaveBeenCalledTimes(2);expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('propagates a hidden-field source drift rejection before native dispatch',async()=>{
  const f=await fixture();f.bridge.assertCurrentSourceMaterial.mockRejectedValueOnce(Error('RAW_SECRET_SOURCE_DRIFT'));
  await expect(f.run(()=>f.origin.beforeNativeSend(f.job.id,f.actor.id))).rejects.toThrow('RAW_SECRET_SOURCE_DRIFT');expect(f.httpPolicy.refresh).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('does not accept a copied private job handle as a current original',async()=>{
  const f=await fixture();f.bridge.currentOriginalJobHandle.mockReturnValue({...f.jobHandle});await expect(f.run(f.assert)).rejects.toThrow('ORIGINAL_JOB_REQUIRED');
  expect(f.bridge.assertCurrentSourceMaterial).not.toHaveBeenCalled();
 });
 it('rejects scope tampering by a current material callback rather than accepting its mutated observations',async()=>{
  const f=await fixture();f.bridge.assertCurrentSourceMaterial.mockImplementationOnce(async(input:any)=>{input.source.scope.clusterId=id(99);});
  await expect(f.run(f.assert)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGIN_SOURCE_CHANGED'}});expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('rejects a historical author SID passed to the scheduled verifier',async()=>{
  const f=await fixture();await expect(f.run(()=>f.origin.assertJobVerifier(f.job,'step',f.actor.id,f.job.origin_session_id,f.db))).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGIN_NULL_SID_REQUIRED'}});
  expect(f.bridge.verifyOriginalJobHandle).not.toHaveBeenCalled();
 });
 it('allows the SQL-bound scheduled verifier only with an actual NULL SID',async()=>{
  const f=await fixture();await f.run(()=>f.origin.assertJobVerifier(f.job,'step',f.actor.id,null,f.db));expect(f.bridge.assertCurrentSourceMaterial).toHaveBeenCalledOnce();
 });
 function budgetPlan(f:any){
  const plan:any={scope:{clusterId:f.job.cluster_id,workspaceId:f.job.workspace_id,transportScope:f.job.transport_scope,kind:'workspace',rootIds:[]},
   steps:[{stepId:id(100),nativeRequests:[{method:'PATCH',path:'/services/'+id(9)}]}]};
  f.job.scope_kind='workspace';f.job.root_ids=[];f.job.plan_hash=f.secrets.fingerprint(plan);f.proof.planHash=f.job.plan_hash;f.planBinding.plan_hash=f.job.plan_hash;return plan;
 }
 it('preflights the actual sealed plan with fixed limits and both source fences before any Native authority',async()=>{
  const f=await fixture(),plan=budgetPlan(f);await f.run(()=>f.origin.assertExecutionBudget(f.ref,plan));
  expect(f.bridge.assertExecutionBudget).toHaveBeenCalledOnce();const input=f.bridge.assertExecutionBudget.mock.calls[0][0];
  expect(input).toMatchObject({phase:'preflight',action:'write',plan,limits:{calls:500,pages:100,records:10000,bytes:33554432},readRetriesReserved:3,sourceFenceRounds:2});
  expect(input.originalJobHandle).toBe(f.jobHandle);expect(input.proof.sessionId).toBeNull();expect(f.httpPolicy.acquire).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('does not replace an actual private source budget rejection with the legacy HTTP reserve',async()=>{
  const f=await fixture(),plan=budgetPlan(f);f.bridge.assertExecutionBudget.mockRejectedValueOnce(Error('RAW_CREDENTIAL_EOF_BUDGET_EXCEEDED'));
  await expect(f.run(()=>f.origin.assertExecutionBudget(f.ref,plan))).rejects.toThrow('RAW_CREDENTIAL_EOF_BUDGET_EXCEEDED');expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('does not preflight a caller-edited plan using the actual job hash',async()=>{
  const f=await fixture(),plan=budgetPlan(f);plan.steps[0].nativeRequests[0].path='/plugins';
  await expect(f.run(()=>f.origin.assertExecutionBudget(f.ref,plan))).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGIN_BUDGET_PLAN_INVALID'}});
  expect(f.bridge.assertExecutionBudget).not.toHaveBeenCalled();expect(f.bridge.assertCurrentSourceMaterial).not.toHaveBeenCalled();
 });
 it('keeps the original plan intact across the fixed budget callback',async()=>{
  const f=await fixture(),plan=budgetPlan(f);f.bridge.assertExecutionBudget.mockImplementationOnce(async(input:any)=>{input.plan.steps[0].nativeRequests.push({method:'POST'});});
  await expect(f.run(()=>f.origin.assertExecutionBudget(f.ref,plan))).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGIN_SOURCE_CHANGED'}});
  expect(plan.steps[0].nativeRequests).toHaveLength(1);expect(f.db.exec).not.toHaveBeenCalled();
 });
});
