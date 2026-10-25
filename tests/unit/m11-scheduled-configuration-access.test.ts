import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {ConfigurationAccessService} from '../../apps/console-api/src/modules/configuration/configuration-access.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';
const id=(n:number)=>`5e000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','cb'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
/** Real Access WeakMaps and Core namespace ancestry. SQL, IAM and the fixed
 * original configuration origin provider are explicit dependency doubles;
 * this suite does not assert a real migration, timer or native outcome. */
function fixture(install=true){
 const context=new KongExecutionContextService(),secrets=new SecretService(),namespaceHandle=Object.freeze({}),jobHandle=Object.freeze({}),executionHandle=Object.freeze({});
 const actor={id:id(1),username:'worker-owner',superAdmin:false},authoringSid=id(2),cluster={id:id(3),version:'1.5.1',admin_url:'http://kong:8001',status:'connected',revision:1,execution_mode:'approval'},workspace={id:id(4),status:'active',revision:1};
 const transport=transportScopeFor(cluster.admin_url),expires=Date.now()+60_000;
 const job:any={id:id(5),origin_type:'http',origin_session_id:authoringSid,actor_id:actor.id,cluster_id:cluster.id,workspace_id:workspace.id,kind:'apply',execution_mode:'approval',approval_required:true,
  plan_id:id(6),plan_revision:1,plan_hash:'6'.repeat(64),permission_version:'original-v1',credential_epoch:1,transport_scope:transport,authority_expires_at:new Date(expires),expires_at:new Date(expires),
  scope_kind:'workspace',root_ids:[],idempotency_key:'scheduled-original-key',lease_generation:1,capture_epoch:'7'.repeat(64),state:'waiting_approval'};
 const namespace:any=Object.freeze({version:1,origin:'scheduled-workflow',sessionId:null,actor,clusterId:cluster.id,workspaceId:workspace.id,kind:'configuration_v2',expiresAt:new Date(expires).toISOString()});
 const state={live:true,version:'original-v1',epoch:1,rejectOrigin:false,proofOverride:{}as any,executionOverride:{}as any};
 context.installWorkflowScheduledNamespacePolicy({assertLive(h){if(h!==namespaceHandle||!state.live)throw Error('ORIGINAL_NAMESPACE_REVOKED');},async verifyHandle(h){if(h!==namespaceHandle||!state.live)throw Error('ORIGINAL_NAMESPACE_REVOKED');return namespace;}});
 const db:any={one:vi.fn(async(sql:string,p:any[])=>{
  if(sql.includes('FROM configuration_jobs'))return p[0]===job.id?job:null;
  if(sql.includes('FROM users'))return{id:actor.id,username:actor.username,super_admin:false,credential_epoch:state.epoch,force_password_change:false};
  if(sql.includes('FROM clusters'))return cluster;if(sql.includes('FROM workspaces'))return workspace;
  if(sql.includes('FROM iam_epoch'))return{version:1};if(sql.includes('FROM metrics_write_fences'))return{count:'0',latest_time:null,latest_id:null,unsettled:'0'};
  if(sql.includes('FROM mutation_operations'))return{count:'0'};throw Error('UNEXPECTED_SQL');
 }),query:vi.fn(async(sql:string)=>sql.includes('FROM clusters')?[cluster]:[]),exec:vi.fn(async()=>1)};
 const authz:any={snapshot:vi.fn(async()=>({user:actor,version:state.version,grants:[]})),permissionVersion:vi.fn(async()=>state.version),assertWholeWorkspace:vi.fn(async()=>undefined)};
 const proof=()=>Object.freeze({origin:'workflow-scheduled-configuration',actor,sessionId:null,clusterId:cluster.id,workspaceId:workspace.id,module:'snapshots',purpose:'apply',jobId:job.id,
  permissionVersion:'original-v1',credentialEpoch:1,leaseGeneration:job.lease_generation,expiresAt:expires,readOnly:false,idempotencyKey:job.idempotency_key,
  namespaceHandle,claimId:id(10),wrapperOriginId:id(11),wrapperExecutionId:id(12),planId:job.plan_id,planRevision:1,planHash:'6'.repeat(64),subjectSealHmac:'8'.repeat(64),...state.proofOverride});
 const original:any={currentOriginalJobHandle:()=>jobHandle,verifyJobHandle:vi.fn(async(h:object)=>{if(h!==jobHandle||state.rejectOrigin)throw Error('ORIGINAL_CONFIGURATION_REVOKED');return proof();}),
  runOriginalConfigurationExecution:vi.fn(async(h:object,_id:string,fn:any)=>{if(h!==jobHandle)throw Error('ORIGINAL_JOB_REQUIRED');return fn(executionHandle);}),
  verifyConfigurationExecution:vi.fn(async(h:object)=>{if(h!==executionHandle||state.rejectOrigin)throw Error('ORIGINAL_CONFIGURATION_REVOKED');return Object.freeze({origin:'workflow-scheduled-configuration',sessionId:null,jobHandle,namespaceHandle,configurationExecutionId:id(13),configurationJobId:job.id,
   claimId:id(10),wrapperOriginId:id(11),wrapperExecutionId:id(12),configurationOriginId:id(14),configurationPlanId:job.plan_id,
   configurationPlanRevision:job.plan_revision,configurationPlanHash:job.plan_hash,configurationClaimHash:'5'.repeat(64),workflowId:id(15),workflowPlanRevision:1,
   workflowPlanHash:'4'.repeat(64),actorId:actor.id,clusterId:cluster.id,workspaceId:workspace.id,permissionVersion:'original-v1',credentialEpoch:1,
   leaseGeneration:job.lease_generation,expiresAt:expires,...state.executionOverride});})};
 // This legacy dependency adapter retains BOTH complete fixture verifiers.
 // It does not model the optimized Origin or supply a cached authority result.
 original.verifyOriginalExecutionAndJob=vi.fn(async(j:object,e:object,phase:any,tx:any)=>{
  const execution=await original.verifyConfigurationExecution(e,phase,tx),job=await original.verifyJobHandle(j,phase,tx);
  return Object.freeze({job,execution});
 });
 const access=new ConfigurationAccessService(db,secrets,authz,{}as any,{}as any,context,{}as any);access.onModuleInit();if(install)access.installWorkflowScheduledConfigurationOrigin(original);
 const run=<T>(fn:()=>Promise<T>)=>context.runWorkflowScheduledNamespace(namespaceHandle,fn);
 return{access,context,db,authz,actor,cluster,workspace,job,state,original,namespaceHandle,jobHandle,executionHandle,authoringSid,run};
}
describe('scheduled configuration Access retains original HTTP job without adopting SID',()=>{
 it('requires the installed fixed origin even in a genuine business namespace',async()=>{const f=fixture(false);await f.run(async()=>{await expect(f.access.acquire(f.job.id)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGIN_UNAVAILABLE'}});});expect(f.db.exec).not.toHaveBeenCalled();});
 it('installs once, mints an opaque NULL SID access handle, preserves authoring SID and deadline',async()=>{const f=fixture();expect(()=>f.access.installWorkflowScheduledConfigurationOrigin(f.original)).toThrow();await f.run(async()=>{
  const handle=await f.access.acquire(f.job.id),state=await f.access.description(handle),proof=await f.access.workflowScheduledConfigurationJobProof(handle);
  expect(Object.keys(handle)).toEqual([]);expect(state.sessionId).toBeNull();expect(state.expiresAt).toBe(proof.expiresAt);expect(f.job.origin_session_id).toBe(f.authoringSid);
  expect(f.access.originalWorkflowScheduledConfigurationJobHandle(handle)).toBe(f.jobHandle);expect(f.db.one.mock.calls.some(([s]:any[])=>s.includes('FROM auth_sessions'))).toBe(false);
 });});
 it.each(['origin_type','origin_session_id','kind','execution_mode','approval_required'])('rejects malformed %s rather than switching to timer or HTTP authority',async field=>{const f=fixture();f.job[field]=field==='approval_required'?false:field==='origin_session_id'?null:'wrong';await f.run(async()=>{await expect(f.access.acquire(f.job.id)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_JOB_INVALID'}});});});
 it.each(['sessionId','namespaceHandle','planHash','planRevision','actor','clusterId','workspaceId','readOnly'])('rejects a fixed origin proof with foreign %s',async field=>{const f=fixture();f.state.proofOverride[field]=field==='readOnly'?true:field==='namespaceHandle'?{}:field==='planRevision'?2:field==='actor'?{id:id(99)}:field==='planHash'?'9'.repeat(64):id(99);await f.run(async()=>{await expect(f.access.acquire(f.job.id)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_JOB_INVALID'}});});});
 it('never refreshes an expired existing job authority',async()=>{const f=fixture();f.job.authority_expires_at=new Date(Date.now()-1);await f.run(async()=>{await expect(f.access.acquire(f.job.id)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_JOB_INVALID'}});});});
 it('rejects a replaced persisted authoring SID after minting while the NULL SID namespace remains live',async()=>{const f=fixture();await f.run(async()=>{const h=await f.access.acquire(f.job.id);f.job.origin_session_id=id(99);await expect(f.access.assertCurrent(h,{phase:'step',jobId:f.job.id})).rejects.toMatchObject({response:{code:'CONFIGURATION_JOB_BINDING_INVALID'}});});});
 it.each(['credentials','permissions','origin','lease'])('rechecks current %s before storage work',async what=>{const f=fixture();await f.run(async()=>{const h=await f.access.acquire(f.job.id);if(what==='credentials')f.state.epoch=2;if(what==='permissions')f.state.version='changed';if(what==='origin')f.state.rejectOrigin=true;if(what==='lease')f.job.lease_generation=2;await expect(f.access.assertCurrent(h,{phase:'step',jobId:f.job.id})).rejects.toThrow();});});
 it('requires original nested execution ancestry for Core packet proof',async()=>{const f=fixture();await f.run(async()=>{const h=await f.access.acquire(f.job.id);await expect(f.access.verifyHandle(h)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED'}});
  await f.access.runWorkflowScheduledConfigurationExecution(h,id(13),async(job,execution)=>{expect(job).toBe(f.jobHandle);expect(execution).toBe(f.executionHandle);const proof:any=await f.access.verifyHandle(h);expect(proof.originalScheduledJobHandle).toBe(f.jobHandle);expect(proof.namespaceHandle).toBe(f.namespaceHandle);expect(proof.sessionId).toBeNull();});
  await expect(f.access.workflowScheduledConfigurationExecutionProof(h,id(13))).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_ORIGINAL_EXECUTION_REQUIRED'}});
 });});
 it.each(['jobHandle','namespaceHandle','configurationJobId','configurationExecutionId'])('rejects original nested tuple substitution of %s',async field=>{const f=fixture();await f.run(async()=>{const h=await f.access.acquire(f.job.id);f.state.executionOverride[field]=field.endsWith('Handle')?{}:id(99);
  await expect(f.access.runWorkflowScheduledConfigurationExecution(h,id(13),()=>f.access.workflowScheduledConfigurationExecutionProof(h,id(13)))).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_EXECUTION_HANDLE_CHANGED'}});
 });});
 it('rejects serialized access handles before accepting a genuine origin UUID',async()=>{const f=fixture();await f.run(async()=>{const h=await f.access.acquire(f.job.id);await expect(f.access.workflowScheduledConfigurationJobProof({...h}as any)).rejects.toMatchObject({response:{code:'CONFIGURATION_AUTHORITY_REQUIRED'}});});});
});
