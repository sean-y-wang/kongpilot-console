import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ConfigurationService} from '../../apps/console-api/src/modules/configuration/configuration.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {parseDeckDocument,normalizeDeckDocument,diffTransferGraphs,compileTransferDag} from '../../apps/console-api/src/modules/config-transfer';
import {configurationCaptureFixture} from './helpers/m11-durable-real-capture';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','2'.repeat(64));vi.stubEnv('CURSOR_SIGNING_KEY','durable-capture-unit-key-32-characters');});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
async function fixture(drift=false){
 const captured=configurationCaptureFixture(),secrets=new SecretService(),context=new KongExecutionContextService();await captured.run();
 const before=captured.graph(),actor={user:{id:id(1),username:'durable-test',superAdmin:true},workspaceId:before.scope.workspaceId,requestId:id(2),ip:'127.0.0.1',idempotencyKey:'durable-unit-key'},handle=Object.freeze({});
 const yaml=`_format_version: "1.1"\nservices:\n- id: ${before.objects.find(o=>o.entityType==='services')!.nativeId}\n  name: service-0\n  host: shop-upstream\n  path: /desired\n`;
 const parsed=parseDeckDocument(yaml),recipe={parsed,allocatedNativeIds:{},basicPasswordIntents:{}},normalized=normalizeDeckDocument(parsed,before.schemas,{scope:before.scope,workspaceCode:'team',workspaceCodesById:{[before.scope.workspaceId]:'team'},references:before});
 const oldPlan=compileTransferDag(diffTransferGraphs(before,normalized,{mode:'merge'}),{stepIds:Object.fromEntries(diffTransferGraphs(before,normalized,{mode:'merge'}).changes.map((c,i)=>[c.objectKey,id(100+i)])),allocatedTargetIds:{},sourceManifestHmac:secrets.fingerprint(recipe),baselineManifestHmac:secrets.fingerprint(before),expiresAt:new Date(Date.now()+600000).toISOString(),fingerprint:v=>secrets.fingerprint(v),redact:v=>secrets.redact(v)});
 const source:any={id:id(3),cluster_id:before.scope.clusterId,workspace_id:before.scope.workspaceId,plan_id:id(4),plan_revision:1,plan_hash:secrets.fingerprint(oldPlan),kind:'import',scope_kind:'workspace',root_ids:[],actor_id:actor.user.id,
  input_secret:secrets.encrypt({mode:'merge',documentHmac:secrets.fingerprint(parsed.document)},`configuration-job:${id(3)}`)};
 const identity={jobId:id(10),planId:id(11),planRevision:1,planHash:''};let compiled:any,workflow:any;
 const tx:any={transaction:async(fn:any)=>fn(tx),one:vi.fn(async(sql:string)=>{if(sql.includes('SELECT id,actor_id,cluster_id'))return{id:identity.jobId,actor_id:actor.user.id,cluster_id:source.cluster_id,workspace_id:source.workspace_id};throw Error('unknown durable publication query');}),exec:vi.fn(async()=>1)};
 const db:any={one:vi.fn(async(sql:string)=>{if(sql.includes('SELECT j.* FROM configuration_plans'))return source;if(sql.includes('SELECT artifact_id FROM configuration_imports'))return{artifact_id:id(5)};if(sql==='SELECT id FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4')return null;throw Error('unknown durable façade query');})};
 const access:any={assertCurrent:vi.fn(async()=>({scope:before.scope,expiresAt:Date.now()+600000,clusterRevision:1,workspaceRevision:1})),acquireReadJob:vi.fn(async()=>handle),acquireReceipt:vi.fn(async()=>handle)};
 const repo:any={readPlan:vi.fn(async()=>oldPlan),readImport:vi.fn(async()=>recipe),freezePlan:vi.fn(async(_:any,input:any,actualTx:any)=>{expect(actualTx).toBe(tx);compiled=input.plan;identity.planHash=secrets.fingerprint(input.plan);return identity;}),initializeExecutionProgress:vi.fn(async()=>{}),getJob:vi.fn(async()=>({id:identity.jobId,state:'waiting_approval'}))};
 const durable:any={rejectionReceipt:vi.fn(async()=>null),rejectFreshDiff:vi.fn(async()=>({receiptKind:'synthetic-facade-rejection',result:'rejected'})),receipt:vi.fn(async()=>null),begin:vi.fn(async()=>Object.freeze({})),describe:vi.fn(()=>({issueId:id(9),jobId:identity.jobId,issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString(),sourceKind:'import'})),
  publish:vi.fn(async(_:any,plan:any,baseline:any,recipeHmac:any)=>{expect(baseline.completeness).toBe('complete');expect(recipeHmac).toBe(secrets.fingerprint(recipe));const r=await(service as any).persistDurableCompilation(tx,{handle,jobId:identity.jobId,issueId:id(9),sourcePlanId:source.plan_id,expiresAt:plan.expiresAt,plan,baseline,actor});return{jobId:identity.jobId,workflowId:r.workflow.workflowId};})};
 const plans:any={definitions:vi.fn(async()=>{}),definition:vi.fn(async()=>({id:id(15),version:1,policyHash:'b'.repeat(64)})),persist:vi.fn(async(p:any)=>{workflow=p;})};
 const audit:any={append:vi.fn(async()=>{})},authz:any={snapshot:vi.fn(async()=>({user:actor.user,grants:[],version:'permission-1'}))},workspaces:any={resolve:vi.fn(async()=>({id:before.scope.workspaceId}))};
 const redis:any={withLock:vi.fn(async(_:string,fn:any)=>fn())};
 const service=new ConfigurationService(db,redis,secrets,context,audit,authz,workspaces,access,repo,{}as any,{}as any,plans,{}as any,{}as any,{}as any,{}as any,{}as any,undefined,durable);
 vi.spyOn(service as any,'scopeHandle').mockResolvedValue({handle,scope:before.scope});vi.spyOn(service as any,'assertPlanGrants').mockResolvedValue(undefined);
 vi.spyOn(service as any,'workspaceCodes').mockResolvedValue({[before.scope.workspaceId]:'team'});
 const capture=vi.spyOn(service as any,'captureBaseline').mockImplementation(async()=>{if(drift)captured.data['/services'][0].path='/fresh-drift';await captured.run();return{graph:captured.graph(),snapshotId:before.snapshotId,version:1};});
 vi.spyOn(service,'jobProjection').mockImplementation(async()=>({jobId:identity.jobId,state:'waiting_approval'}));
 const run=()=>context.runHttp({requestId:actor.requestId},async()=>{context.bindHttpActor(actor.user,id(20));return service.submitDurable(source.cluster_id,source.plan_id,{planRevision:1,planHash:source.plan_hash,confirmed:true,confirm_name:`配置计划 ${source.plan_id}`},actor);});
 const frame=<T>(fn:()=>Promise<T>)=>context.runHttp({requestId:actor.requestId},async()=>{context.bindHttpActor(actor.user,id(20));return fn();});
 return{run,frame,actor,scope:before.scope,handle,access,service,source,oldPlan,captured,capture,durable,repo,plans,audit,compiled:()=>compiled,workflow:()=>workflow,db,redis};
}
describe('fresh durable ordinary configuration authoring façade (synthetic transport/storage)',()=>{
 it('runs the real complete capture/normalize/diff/DAG compiler; preserves confirmed business semantics and creates a new approval wrapper',async()=>{
  const f=await fixture();await f.run();
  const plan=f.compiled();expect(plan.steps[0]).toMatchObject({mutationAction:'update',before:{path:null},body:{path:'/desired'}});
  expect(plan.steps[0].stepId).not.toBe(f.oldPlan.steps[0].stepId);expect(plan.steps[0].nativeId).toBe(f.oldPlan.steps[0].nativeId);
  expect(plan.durableRef).toMatchObject({domain:'durable-configuration-v1'});expect(Date.parse(plan.expiresAt)-Date.parse(f.oldPlan.expiresAt)).toBeGreaterThan(15*60000);
  expect(f.workflow()).toMatchObject({kind:'configuration_v2',executionMode:'approval',approvalRequired:true,expiresAt:plan.expiresAt});
  expect(f.workflow().steps[0].nativeRequests).toEqual([]);expect(f.capture).toHaveBeenCalledOnce();expect(f.durable.publish).toHaveBeenCalledOnce();
  expect(f.captured.packets.every(p=>p.method==='GET')).toBe(true);expect(f.repo.initializeExecutionProgress).toHaveBeenCalledOnce();expect(f.audit.append).toHaveBeenCalledOnce();
 });
 it('rejects fresh drift before durable Job/Plan/Workflow publication instead of silently rebasing consent',async()=>{const f=await fixture(true);await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED'}});expect(f.capture).toHaveBeenCalledOnce();expect(f.durable.publish).not.toHaveBeenCalled();expect(f.repo.freezePlan).not.toHaveBeenCalled();expect(f.plans.persist).not.toHaveBeenCalled();});
 it('rejects Promote before capture or publishing',async()=>{const f=await fixture();f.source.required_origin_kind='governance-promote';await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_SOURCE_UNAVAILABLE'}});expect(f.capture).not.toHaveBeenCalled();expect(f.durable.publish).not.toHaveBeenCalled();});
 it('reads the original issued receipt on its exact key without re-capture or new signing',async()=>{const f=await fixture();f.durable.receipt.mockResolvedValue(id(10));await f.run();expect(f.capture).not.toHaveBeenCalled();expect(f.durable.begin).not.toHaveBeenCalled();expect(f.durable.publish).not.toHaveBeenCalled();});
 it('does not publish if the real capture fails',async()=>{const f=await fixture();f.capture.mockRejectedValue(new Error('CAPTURE_FAILED'));await expect(f.run()).rejects.toThrow('CAPTURE_FAILED');expect(f.durable.publish).not.toHaveBeenCalled();expect(f.plans.persist).not.toHaveBeenCalled();});
 it('returns an original-key rejection only through current scoped read authority without acquiring or executing a job',async()=>{
  const f=await fixture(),receipt={receiptKind:'durable-submission-rejected-v1',effectScope:'durable-registration',result:'rejected'},fact={ownerId:f.actor.user.id,clusterId:f.scope.clusterId,workspaceId:f.scope.workspaceId,sourcePlanId:f.source.plan_id,sourcePlanRevision:1,sourcePlanHash:f.source.plan_hash};
  f.durable.rejectionReceipt.mockResolvedValue({receipt,fact,scopeKind:'workspace',rootIds:[],transportScope:f.scope.transportScope});
  await expect(f.frame(()=>f.service.receipt(f.scope.clusterId,'durable-unit-key',f.actor))).resolves.toEqual(receipt);
  expect(f.access.assertCurrent).toHaveBeenCalledWith(f.handle,{phase:'read'});expect(f.access.acquireReceipt).not.toHaveBeenCalled();expect(f.capture).not.toHaveBeenCalled();expect(f.durable.publish).not.toHaveBeenCalled();
 });
 it('does not disclose a stored refusal after current scoped access has been revoked',async()=>{
  const f=await fixture();f.durable.rejectionReceipt.mockResolvedValue({receipt:{receiptKind:'durable-submission-rejected-v1'},fact:{ownerId:f.actor.user.id,clusterId:f.scope.clusterId,workspaceId:f.scope.workspaceId},scopeKind:'workspace',rootIds:[]});
  f.access.assertCurrent.mockRejectedValueOnce(new Error('CURRENT_GRANT_REVOKED'));
  await expect(f.frame(()=>f.service.receipt(f.scope.clusterId,'durable-unit-key',f.actor))).rejects.toThrow('CURRENT_GRANT_REVOKED');expect(f.capture).not.toHaveBeenCalled();expect(f.durable.publish).not.toHaveBeenCalled();
 });
 it('never recaptures or submits the old plan when its original key is already proven rejected',async()=>{
  const f=await fixture(),receipt={receiptKind:'durable-submission-rejected-v1',result:'rejected'};
  f.durable.rejectionReceipt.mockResolvedValue({receipt,fact:{ownerId:f.actor.user.id,clusterId:f.scope.clusterId,workspaceId:f.scope.workspaceId,sourcePlanId:f.source.plan_id,sourcePlanRevision:1,sourcePlanHash:f.source.plan_hash},scopeKind:'workspace',rootIds:[]});
  await expect(f.run()).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED',receipt}});
  expect(f.capture).not.toHaveBeenCalled();expect(f.durable.begin).not.toHaveBeenCalled();expect(f.durable.publish).not.toHaveBeenCalled();
 });
 it('does not map a different source tuple onto an existing rejection key',async()=>{
  const f=await fixture();f.durable.rejectionReceipt.mockResolvedValue({receipt:{receiptKind:'durable-submission-rejected-v1'},fact:{sourcePlanId:id(999),sourcePlanRevision:1,sourcePlanHash:f.source.plan_hash}});
  await expect(f.run()).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});expect(f.capture).not.toHaveBeenCalled();expect(f.durable.begin).not.toHaveBeenCalled();
 });
 it('does not generate any rejection receipt for a generic capture or transport error',async()=>{
  const f=await fixture();f.capture.mockRejectedValue(new Error('UNKNOWN_TRANSPORT_OUTCOME'));
  await expect(f.run()).rejects.toThrow('UNKNOWN_TRANSPORT_OUTCOME');expect(f.durable.rejectFreshDiff).not.toHaveBeenCalled();expect(f.durable.publish).not.toHaveBeenCalled();
 });

 it('fails closed instead of choosing a winner if an inconsistent job and rejected disposition are both returned',async()=>{
  const f=await fixture(),oldOne=f.db.one.getMockImplementation()!;f.db.one.mockImplementation(async(sql:string,...args:any[])=>sql==='SELECT id FROM configuration_jobs WHERE cluster_id=$1 AND workspace_id=$2 AND actor_id=$3 AND idempotency_key=$4'?{id:id(800)}:oldOne(sql,...args));
  f.durable.rejectionReceipt.mockResolvedValue({receipt:{receiptKind:'durable-submission-rejected-v1'},fact:{ownerId:f.actor.user.id,clusterId:f.scope.clusterId,workspaceId:f.scope.workspaceId},scopeKind:'workspace',rootIds:[]});
  await expect(f.frame(()=>f.service.receipt(f.scope.clusterId,'durable-unit-key',f.actor))).rejects.toMatchObject({response:{code:'CONFIGURATION_RECEIPT_DISPOSITION_CONFLICT'}});expect(f.access.acquireReceipt).not.toHaveBeenCalled();expect(f.capture).not.toHaveBeenCalled();
 });

});
