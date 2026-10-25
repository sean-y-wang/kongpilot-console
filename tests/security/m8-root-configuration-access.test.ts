import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {ConfigurationAccessService} from '../../apps/console-api/src/modules/configuration/configuration-access.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import {scheduleAuthorityQuery} from '../../apps/console-api/src/modules/configuration/configuration-schedule-queries';

const id=(n:number)=>`30000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','1'.repeat(64)));
afterEach(()=>vi.unstubAllEnvs());
/** The Root provider and execution frames are real. Database/permission rows
 * are explicit synthetic fixtures; these cases do not claim HTTP/PG evidence. */
function fixture(){
 const ctx=new KongExecutionContextService(),secrets=new SecretService();
 const user={id:id(1),username:'root-unit',superAdmin:false};
 const userRow={id:user.id,username:user.username,super_admin:false,credential_epoch:1,force_password_change:false};
 const cluster={id:id(3),version:'1.5.1',status:'connected',admin_url:'http://kong:8001',revision:1,enabled_plugins:['key-auth'],execution_mode:'direct'};
 const workspace={id:id(4),cluster_id:cluster.id,status:'active',revision:1,code:'unit'};
 const physical=transportScopeFor(cluster.admin_url);
 const job={id:id(5),cluster_id:cluster.id,workspace_id:workspace.id,transport_scope:physical,actor_id:user.id,origin_session_id:id(2),
  idempotency_key:'root-unit-original',kind:'capture',scope_kind:'workspace',root_ids:[],lease_generation:1,permission_version:'v1',credential_epoch:1,
  authority_expires_at:new Date(Date.now()+600000),state:'pending',input_secret:null};
 const policy={id:id(8),cluster_id:cluster.id,workspace_id:workspace.id,owner_user_id:user.id,name:'timer',current_version:1,revision:1,policy_hmac:'a'.repeat(64),
  next_run_at:new Date(Date.now()-60000),state:'active',purged_at:null,transport_scope:physical,scope_kind:'workspace',root_ids:[]};
 const state={version:'v1',revoked:false,unfinished:'0',fences:'0',enabled:true,sessionEpoch:1 as unknown};
 const db:any={exec:vi.fn(async()=>1),query:vi.fn(async(sql:string)=>{
  if(sql.includes('FROM clusters'))return[cluster];throw new Error('unexpected query');
 }),one:vi.fn(async(sql:string,p:any[])=>{
  if(sql.includes('FROM users'))return state.enabled&&p[0]===user.id?userRow:null;
  if(sql.includes('FROM auth_sessions'))return !state.revoked&&[id(2),id(7)].includes(p[0])?{expires_at:new Date(Date.now()+3600000),credential_epoch:state.sessionEpoch}:null;
  if(sql.includes('FROM config_snapshot_schedules'))return policy;
  if(sql.includes('FROM config_snapshot_schedule_runs'))return{job_id:job.id,schedule_version:1,creator_id:user.id,state:'running'};
  if(sql.includes('FROM configuration_jobs'))return p[0]===job.id?job:null;
  if(sql.includes('FROM metrics_write_fences'))return{count:'0',latest_time:null,latest_id:null,unsettled:state.fences};
  if(sql.includes('FROM mutation_operations'))return{count:state.unfinished};
  if(sql.includes('FROM clusters'))return p[0]===cluster.id?cluster:null;
  if(sql.includes('FROM workspaces'))return p[0]===cluster.id&&p[1]===workspace.id?workspace:null;
  if(sql.includes('FROM iam_epoch'))return{version:1};
  throw new Error('unexpected one');
 })};
 const authz:any={snapshot:vi.fn(async()=>({user:{...user},version:state.version,grants:[]})),permissionVersion:vi.fn(async()=>state.version),
  assertWholeWorkspace:vi.fn(async()=>undefined),assertWholeCluster:vi.fn(async()=>undefined),assertCluster:vi.fn(async()=>undefined)};
 const workspaces:any={resolve:vi.fn(async(_cid:string,wid:string)=>({...workspace,id:wid}))};
 const access=new ConfigurationAccessService(db,secrets,authz,workspaces,{}as any,ctx,{}as any);access.onModuleInit();
 const nativePolicy={authorizeRequest:vi.fn(async()=>({})),authorizeResponse:vi.fn(async(_:unknown,value:unknown)=>value)};ctx.installPolicy(nativePolicy);
 const frame=<T>(fn:()=>Promise<T>,sid=id(2),actor=user)=>ctx.runHttp({requestId:id(10)},async()=>{
  ctx.bindHttpActor(actor,sid);return ctx.runActor({actor,clusterId:cluster.id,workspaceId:workspace.id,module:'snapshots',action:'read'},fn);
 });
 const mint=()=>access.acquireJob({actor:user,clusterId:cluster.id,workspaceId:workspace.id,kind:'workspace',rootIds:[],purpose:'capture',kindOfJob:'capture',idempotencyKey:job.idempotency_key});
 return{access,ctx,db,authz,user,userRow,cluster,workspace,job,policy,state,frame,mint,nativePolicy};
}
describe('M8 Root genuine configuration authority',()=>{
 it.each([['1','1'],['1',1],[1,'1'],[1,1]])('normalizes actual PostgreSQL epoch representations %s/%s before immutable int4 job comparison',async(userEpoch,sessionEpoch)=>{
  const f=fixture();(f.userRow as any).credential_epoch=userEpoch;f.state.sessionEpoch=sessionEpoch;
  await f.frame(async()=>{const h=await f.access.acquire(f.job.id),proof=await f.access.assertCurrent(h,{phase:'capture-page',jobId:f.job.id});expect(proof.credentialEpoch).toBe(1);});
 });
 it.each([0,-1,1.5,NaN,Infinity,'0','-1','01',' 1','1 ','1e0','1.0','2147483648',2_147_483_648,'9007199254740993',true,null,{}])('rejects invalid or overflowing actual database user epoch %s without native authority',async(value)=>{
  const f=fixture();(f.userRow as any).credential_epoch=value;
  await f.frame(async()=>{await expect(f.mint()).rejects.toMatchObject({response:{code:'CONFIGURATION_ACTOR_INACTIVE'}});});expect(f.nativePolicy.authorizeRequest).not.toHaveBeenCalled();
 });
 it.each(['2','01','2147483648',null])('rejects mismatched or invalid current database session epoch %s',async(value)=>{
  const f=fixture();(f.userRow as any).credential_epoch='1';f.state.sessionEpoch=value;
  await f.frame(async()=>{await expect(f.mint()).rejects.toMatchObject({response:{code:'CONFIGURATION_SESSION_EXPIRED'}});});
 });
 it('rechecks a changed bigint user and session epoch after minting the original handle',async()=>{
  const f=fixture();(f.userRow as any).credential_epoch='1';f.state.sessionEpoch='1';
  await f.frame(async()=>{const h=await f.mint();(f.userRow as any).credential_epoch='2';f.state.sessionEpoch='2';await expect(f.access.assertCurrent(h,{phase:'capture-page'})).rejects.toMatchObject({response:{code:'CONFIGURATION_CREDENTIALS_CHANGED'}});});
 });
 it('rejects serialized/copied handles before storage or transport',async()=>{const f=fixture();await f.frame(async()=>{
  const handle=await f.mint();expect(Object.keys(handle)).toEqual([]);
  for(const forged of [{},JSON.parse(JSON.stringify(handle)),{jobId:f.job.id,actor:f.user}])await expect(f.access.assertCurrent(forged as any,{phase:'read'})).rejects.toMatchObject({response:{code:'CONFIGURATION_AUTHORITY_REQUIRED'}});
 });expect(f.nativePolicy.authorizeRequest).not.toHaveBeenCalled();});
 it('uses the actual database actor and SID, with workspace argument before module',async()=>{const f=fixture();await f.frame(async()=>{const h=await f.mint();const s=await f.access.description(h);
  expect(s.actor.superAdmin).toBe(false);expect(s.sessionId).toBe(id(2));expect(f.authz.assertWholeWorkspace).toHaveBeenCalledWith(f.user,f.cluster.id,f.workspace.id,'snapshots','write');
 },id(2),{...f.user,superAdmin:true});});
 it.each(['cluster','workspace','actor','session'])('does not adopt foreign %s identifiers',async(which)=>{const f=fixture();await f.frame(async()=>{
  if(which==='session'){await expect(f.access.acquireJob({actor:f.user,clusterId:f.cluster.id,workspaceId:f.workspace.id,kind:'workspace',rootIds:[],purpose:'capture',kindOfJob:'capture',idempotencyKey:'root-unit-other'})).rejects.toThrow();return;}
  const data={actor:f.user,clusterId:f.cluster.id,workspaceId:f.workspace.id,kind:'workspace' as const,rootIds:[],purpose:'capture' as const,kindOfJob:'capture',idempotencyKey:'root-unit-other'};
  if(which==='cluster')data.clusterId=id(99);if(which==='actor')data.actor={...f.user,id:id(99)};
  // A foreign workspace must resolve to its own actual registry row.
  if(which==='workspace')data.workspaceId=id(99);
  await expect(f.access.acquireJob(data)).rejects.toThrow();
 },which==='session'?id(99):id(2));});
 it.each(['revoked','credentials','permissions','endpoint','version'])('rechecks current %s before later use',async(which)=>{const f=fixture();await f.frame(async()=>{const h=await f.mint();
  if(which==='revoked')f.state.revoked=true;if(which==='credentials')f.userRow.credential_epoch++;
  if(which==='permissions')f.state.version='v2';if(which==='endpoint')f.cluster.admin_url='http://other:8001';if(which==='version')f.cluster.version='2.8.0';
  await expect(f.access.assertCurrent(h,{phase:'capture-page'})).rejects.toThrow();
 });});
 it('permits a new current SID to read a safe receipt, never to capture or execute it',async()=>{const f=fixture();let h:any;
  await f.frame(async()=>{h=await f.access.acquireReceipt(f.job.id);await expect(f.access.assertCurrent(h,{phase:'read',jobId:f.job.id})).resolves.toBeTruthy();
   for(const phase of ['capture-page','seal','step','ledger','download','metadata-write'])await expect(f.access.assertCurrent(h,{phase,jobId:f.job.id})).rejects.toMatchObject({response:{code:'CONFIGURATION_RECEIPT_READ_ONLY'}});
   await expect(f.access.runJob(h,async()=>undefined)).rejects.toMatchObject({response:{code:'CONFIGURATION_JOB_REQUIRED'}});
   await expect(f.access.acquire(f.job.id)).rejects.toMatchObject({response:{code:'CONFIGURATION_JOB_ACCESS_DENIED'}});
  },id(7));});
 it('binds full immutable original tuple and current lease',async()=>{const f=fixture();await f.frame(async()=>{const h=await f.access.acquire(f.job.id);
  f.job.lease_generation++;await expect(f.access.assertCurrent(h,{phase:'capture-page',jobId:f.job.id})).rejects.toMatchObject({response:{code:'CONFIGURATION_LEASE_CHANGED'}});
 });});
 it.each(['actor_id','origin_session_id','idempotency_key','scope_kind','root_ids','transport_scope'])('rejects original job %s substitution',async(field)=>{const f=fixture();await f.frame(async()=>{const h=await f.access.acquire(f.job.id);
  (f.job as any)[field]=field==='root_ids'?[id(20)]:field==='scope_kind'?'cluster':field==='transport_scope'?'b'.repeat(64):field==='idempotency_key'?'root-unit-changed':id(20);
  await expect(f.access.assertCurrent(h,{phase:'capture-page',jobId:f.job.id})).rejects.toMatchObject({response:{code:'CONFIGURATION_JOB_BINDING_INVALID'}});
 });});
 it('refuses capture across unresolved changes on any physical alias',async()=>{const f=fixture();await f.frame(async()=>{const h=await f.mint();f.state.unfinished='1';
  await expect(f.access.assertCurrent(h,{phase:'capture-page'})).rejects.toMatchObject({response:{code:'CONFIGURATION_NATIVE_CHANGE_PENDING'}});
 });});
 it('mints timer-only readonly authority without a pretend login or native write',async()=>{const f=fixture();const locator={scheduleId:f.policy.id,clusterId:f.cluster.id,workspaceId:f.workspace.id,ownerUserId:f.user.id,version:1,revision:1,scheduledAt:f.policy.next_run_at.toISOString()};
  await f.frame(async()=>{await expect(f.access.acquireDueSchedule(locator)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_TIMER_REQUIRED'}});});
  const timer=await f.access.acquireDueSchedule(locator);expect((await f.access.description(timer.handle)).sessionId).toBeNull();
  await f.access.runJob(timer.handle,async()=>{
   expect(f.ctx.current().sessionId).toBeUndefined();
   await expect(f.ctx.authorizeRequest(f.cluster,'POST','/services',{host:'bad'},{})).rejects.toMatchObject({response:{code:'CONFIGURATION_JOB_READ_ONLY'}});
   await expect(f.access.assertCurrent(timer.handle,{phase:'step'})).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_READ_ONLY'}});
  });expect(f.nativePolicy.authorizeRequest).not.toHaveBeenCalled();
 });
 it.each(['owner','version','revision','due'])('re-reads timer policy %s instead of trusting its locator',async(which)=>{const f=fixture();const locator={scheduleId:f.policy.id,clusterId:f.cluster.id,workspaceId:f.workspace.id,ownerUserId:f.user.id,version:1,revision:1,scheduledAt:f.policy.next_run_at.toISOString()};
  if(which==='owner')locator.ownerUserId=id(99);if(which==='version')locator.version=2;if(which==='revision')locator.revision=2;if(which==='due')locator.scheduledAt=new Date(Date.now()+60000).toISOString();
  await expect(f.access.acquireDueSchedule(locator)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_CHANGED'}});
 });
 it('locks the current mutable policy without requiring UPDATE on immutable versions',async()=>{
  const f=fixture(),locator={scheduleId:f.policy.id,clusterId:f.cluster.id,workspaceId:f.workspace.id,ownerUserId:f.user.id,version:1,revision:1,scheduledAt:f.policy.next_run_at.toISOString()};
  const timer=await f.access.acquireDueSchedule(locator);
  await f.access.assertStorage(timer.handle,{phase:'capture-page'},f.db);
  const policyRead=f.db.one.mock.calls.find(([sql]:any[])=>sql===scheduleAuthorityQuery(true));
  expect(policyRead?.[1]).toEqual([f.policy.id,f.cluster.id,f.workspace.id]);
  expect(scheduleAuthorityQuery(true)).toMatch(/FOR SHARE OF s$/);
  expect(scheduleAuthorityQuery(true)).not.toMatch(/FOR SHARE OF s,v/);
  expect(scheduleAuthorityQuery(false)).not.toContain('FOR SHARE');
  f.policy.policy_hmac='b'.repeat(64);
  await expect(f.access.assertStorage(timer.handle,{phase:'capture-page'},f.db)).rejects.toMatchObject({response:{code:'CONFIGURATION_SCHEDULE_CHANGED'}});
  expect(f.nativePolicy.authorizeRequest).not.toHaveBeenCalled();
 });
});
