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
  verifyConfigurationExecution:vi.fn(async(h:object)=>{if(h!==executionHandle||state.rejectOrigin)throw Error('ORIGINAL_CONFIGURATION_REVOKED');return Object.freeze({origin:'workflow-scheduled-configuration',sessionId:null,jobHandle,namespaceHandle,configurationExecutionId:id(13),configurationJobId:job.id,...state.executionOverride});})};
 original.verifyOriginalExecutionAndJob=vi.fn(async(j:object,e:object)=>{
  if(j!==jobHandle||e!==executionHandle||state.rejectOrigin)throw Error('ORIGINAL_CONFIGURATION_REVOKED');
  return Object.freeze({job:proof(),execution:Object.freeze({origin:'workflow-scheduled-configuration',sessionId:null,jobHandle,namespaceHandle,
   claimId:id(10),wrapperOriginId:id(11),wrapperExecutionId:id(12),configurationOriginId:id(14),configurationExecutionId:id(13),configurationJobId:job.id,
   configurationPlanId:job.plan_id,configurationPlanRevision:job.plan_revision,configurationPlanHash:job.plan_hash,configurationClaimHash:'5'.repeat(64),
   workflowId:id(15),workflowPlanRevision:1,workflowPlanHash:'4'.repeat(64),actorId:actor.id,clusterId:cluster.id,workspaceId:workspace.id,
   permissionVersion:'original-v1',credentialEpoch:1,leaseGeneration:job.lease_generation,expiresAt:expires,...state.executionOverride})});
 });
 const access=new ConfigurationAccessService(db,secrets,authz,{}as any,{}as any,context,{}as any);access.onModuleInit();if(install)access.installWorkflowScheduledConfigurationOrigin(original);
 const run=<T>(fn:()=>Promise<T>)=>context.runWorkflowScheduledNamespace(namespaceHandle,fn);
 return{access,context,db,authz,actor,cluster,workspace,job,state,original,namespaceHandle,jobHandle,executionHandle,authoringSid,run};
}

describe('Access retains distinct step and packet combined original gates',()=>{
 it('requires the fixed combined original verifier at bootstrap',()=>{
  const f=fixture(false);const {verifyOriginalExecutionAndJob:_absent,...partial}=f.original;
  expect(()=>f.access.installWorkflowScheduledConfigurationOrigin(partial)).toThrow();
 });
 it('runs one combined gate for step and one for packet, scoped to the actual job SQL tuple',async()=>{
  const f=fixture();await f.run(async()=>{const handle=await f.access.acquire(f.job.id);await f.access.runWorkflowScheduledConfigurationExecution(handle,id(13),async()=>{
   f.original.verifyConfigurationExecution.mockClear();f.original.verifyJobHandle.mockClear();f.original.verifyOriginalExecutionAndJob.mockClear();f.db.one.mockClear();
   const proof:any=await f.access.verifyHandle(handle);
   expect(f.original.verifyOriginalExecutionAndJob.mock.calls.map((call:any[])=>call[2])).toEqual(['step','packet']);
   expect(f.original.verifyConfigurationExecution).not.toHaveBeenCalled();expect(f.original.verifyJobHandle).not.toHaveBeenCalled();
   const marker=f.db.one.mock.calls.filter(([sql]:any[])=>sql.startsWith('SELECT required_origin_kind,required_origin_id,required_origin_hmac'));
   expect(marker).toHaveLength(2);for(const [,args]of marker)expect(args).toEqual([f.job.id,f.cluster.id,f.workspace.id]);
   expect(proof.originalScheduledJobHandle).toBe(f.jobHandle);expect(proof.sessionId).toBeNull();
  });});
 });
 it.each(['required_origin_kind','required_origin_id','required_origin_hmac'])('preserves the original complete two-check Promote path for %s',async marker=>{
  const f=fixture();await f.run(async()=>{const handle=await f.access.acquire(f.job.id);await f.access.runWorkflowScheduledConfigurationExecution(handle,id(13),async()=>{
   f.job[marker]=marker==='required_origin_kind'?'governance-promote':marker==='required_origin_id'?id(99):'9'.repeat(64);
   f.original.verifyConfigurationExecution.mockClear();f.original.verifyJobHandle.mockClear();f.original.verifyOriginalExecutionAndJob.mockClear();
   await (f.access as any).verifyScheduledJob(handle,'packet',f.db);
   expect(f.original.verifyConfigurationExecution).toHaveBeenCalledExactlyOnceWith(f.executionHandle,'packet',f.db);
   expect(f.original.verifyJobHandle).toHaveBeenCalledExactlyOnceWith(f.jobHandle,'packet',f.db);
   expect(f.original.verifyOriginalExecutionAndJob).not.toHaveBeenCalled();
  });});
 });
 it('selects a complete Promote tuple before the group and propagates its original combined failure',async()=>{
  const f=fixture();await f.run(async()=>{const handle=await f.access.acquire(f.job.id);await f.access.runWorkflowScheduledConfigurationExecution(handle,id(13),async()=>{
   Object.assign(f.job,{required_origin_kind:'governance-promote',required_origin_id:id(99),required_origin_hmac:'9'.repeat(64)});
   f.original.verifyConfigurationExecution.mockClear();f.original.verifyJobHandle.mockClear();f.original.verifyOriginalExecutionAndJob.mockClear();
   await (f.access as any).verifyScheduledJob(handle,'packet',f.db);
   expect(f.original.verifyOriginalExecutionAndJob).toHaveBeenCalledExactlyOnceWith(f.jobHandle,f.executionHandle,'packet',f.db);
   expect(f.original.verifyConfigurationExecution).not.toHaveBeenCalled();expect(f.original.verifyJobHandle).not.toHaveBeenCalled();
   f.original.verifyOriginalExecutionAndJob.mockRejectedValueOnce(Error('PROMOTE_SQL_OR_SOURCE_DENIED'));
   await expect((f.access as any).verifyScheduledJob(handle,'packet',f.db)).rejects.toThrow('PROMOTE_SQL_OR_SOURCE_DENIED');
   expect(f.original.verifyConfigurationExecution).not.toHaveBeenCalled();expect(f.original.verifyJobHandle).not.toHaveBeenCalled();
  });});
 });
 it('does not fall back after a failed combined original gate',async()=>{
  const f=fixture();await f.run(async()=>{const handle=await f.access.acquire(f.job.id);await f.access.runWorkflowScheduledConfigurationExecution(handle,id(13),async()=>{
   f.original.verifyConfigurationExecution.mockClear();f.original.verifyJobHandle.mockClear();
   f.original.verifyOriginalExecutionAndJob.mockRejectedValueOnce(Error('CANONICAL_CLOSURE_REVOKED'));
   await expect(f.access.verifyHandle(handle)).rejects.toThrow('CANONICAL_CLOSURE_REVOKED');
   expect(f.original.verifyConfigurationExecution).not.toHaveBeenCalled();expect(f.original.verifyJobHandle).not.toHaveBeenCalled();
  });});
 });
 it('fails closed when a marker appears after fresh selection without falling back to the source path',async()=>{
  const f=fixture();await f.run(async()=>{const handle=await f.access.acquire(f.job.id);await f.access.runWorkflowScheduledConfigurationExecution(handle,id(13),async()=>{
   f.original.verifyConfigurationExecution.mockClear();f.original.verifyJobHandle.mockClear();
   f.original.verifyOriginalExecutionAndJob.mockImplementationOnce(async()=>{
    f.job.required_origin_kind='governance-promote';f.job.required_origin_id=id(98);f.job.required_origin_hmac='8'.repeat(64);
    throw Error('WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_SOURCE_UNSUPPORTED');
   });
   await expect((f.access as any).verifyScheduledJob(handle,'packet',f.db)).rejects.toThrow('WORKFLOW_SCHEDULE_CONFIGURATION_COMBINED_SOURCE_UNSUPPORTED');
   expect(f.original.verifyConfigurationExecution).not.toHaveBeenCalled();expect(f.original.verifyJobHandle).not.toHaveBeenCalled();
  });});
 });
 it.each(['jobHandle','namespaceHandle','configurationJobId','configurationPlanId','configurationPlanRevision','configurationPlanHash','claimId','wrapperOriginId','wrapperExecutionId','actorId','clusterId','workspaceId','permissionVersion','credentialEpoch','leaseGeneration','expiresAt'])('rejects a mixed combined proof pair %s',async field=>{
  const f=fixture();await f.run(async()=>{const handle=await f.access.acquire(f.job.id);await f.access.runWorkflowScheduledConfigurationExecution(handle,id(13),async()=>{
   f.state.executionOverride[field]=field.endsWith('Handle')?{}:['configurationPlanRevision','credentialEpoch','leaseGeneration','expiresAt'].includes(field)?2:id(99);
   await expect((f.access as any).verifyScheduledJob(handle,'packet',f.db)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_EXECUTION_HANDLE_CHANGED'}});
  });});
 });
 it.each(['capture-page','seal','ledger','read'])('preserves the existing %s verifier path',async phase=>{
  const f=fixture();await f.run(async()=>{const handle=await f.access.acquire(f.job.id);await f.access.runWorkflowScheduledConfigurationExecution(handle,id(13),async()=>{
   f.original.verifyOriginalExecutionAndJob.mockClear();f.original.verifyJobHandle.mockClear();f.original.verifyConfigurationExecution.mockClear();
   await (f.access as any).verifyScheduledJob(handle,phase,f.db);
   expect(f.original.verifyOriginalExecutionAndJob).not.toHaveBeenCalled();expect(f.original.verifyConfigurationExecution).not.toHaveBeenCalled();
   expect(f.original.verifyJobHandle).toHaveBeenCalledExactlyOnceWith(f.jobHandle,['capture-page','seal'].includes(phase)?'capture':'ledger',f.db);
  });});
 });
});
