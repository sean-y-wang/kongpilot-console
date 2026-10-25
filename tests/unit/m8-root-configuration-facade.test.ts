import {DURABLE_CONFIGURATION_PRESENCE_QUERY} from '../../apps/console-api/src/modules/configuration/configuration-durable.repository';
import {ConfigurationFailureLedgerService} from '../../apps/console-api/src/modules/configuration/configuration-failure-ledger.service';
import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {ConflictException,ForbiddenException,HttpException} from '@nestjs/common';
import {ConfigurationService} from '../../apps/console-api/src/modules/configuration/configuration.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {EXPORT_DOWNLOAD_QUERY,EXPORT_PROJECTION_QUERY} from '../../apps/console-api/src/modules/configuration/configuration-export-queries';
import {APPROVAL_WORKFLOW_CONTEXT_QUERY,APPROVAL_CONFIGURATION_PLAN_QUERY} from '../../apps/console-api/src/modules/configuration/configuration-approval-queries';
import {SNAPSHOT_TERMINAL_CAPTURE_QUERY} from '../../apps/console-api/src/modules/config-storage/configuration-repository.service';
import {CONFIGURATION_JOB_PROJECTION_QUERY} from '../../apps/console-api/src/modules/configuration/configuration-job-queries';
import {graph as transferGraph} from './m8-config-transfer.fixture';
import {ConfigTransferError} from '../../apps/console-api/src/modules/config-transfer/transfer.types';

const id=(n:number)=>`40000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','2'.repeat(64)));
afterEach(()=>vi.unstubAllEnvs());
/** Real public façade orchestration, with explicit synthetic storage. Actual
 * SQL commit/rollback is covered separately by the isolated PostgreSQL suite. */
function fixture(){
 const ctx=new KongExecutionContextService(),secrets=new SecretService();
 const user={id:id(1),username:'facade-unit',superAdmin:false},actor={user,workspaceId:id(4),requestId:id(9),ip:'127.0.0.1',idempotencyKey:'facade-unit-original'};
 const scope={clusterId:id(3),workspaceId:id(4),transportScope:'a'.repeat(64),kind:'workspace',rootIds:[]};
 const handle=Object.freeze({}),trace:string[]=[],data={consumed:false,jobState:'pending',safeProgress:{}as any};
 const job:any={id:id(5),kind:'export',state:'pending',scope,safeProgress:{},clusterId:scope.clusterId,workspaceId:scope.workspaceId};
 let txDepth=0;
 const tx:any={exec:vi.fn(async()=>1),one:vi.fn(async()=>null)};
 const db:any={one:vi.fn(async(sql:string)=>{
  if(sql.includes('SELECT e.*'))return{id:id(6),export_revision:7,material_state:'available',state:'ready',expires_at:new Date(Date.now()+600000),mode:'review',scope_kind:'workspace',root_ids:[],source_snapshot_id:null};
  if(sql.includes('SELECT * FROM configuration_jobs'))return null;
  if(sql.includes('SELECT state FROM configuration_jobs'))return{state:data.jobState};
  throw new Error('unexpected façade query');
 }),transaction:vi.fn(async(fn:any)=>{trace.push('begin');const old=structuredClone(data);txDepth++;
  try{const result=await fn(tx);trace.push('commit');return result;}catch(e){Object.assign(data,old);trace.push('rollback');throw e;}finally{txDepth--;}
 })};
 const access:any={acquireJob:vi.fn(async()=>handle),acquire:vi.fn(async()=>handle),description:vi.fn(async()=>({actor:user,scope,permissionVersion:'v1',expiresAt:Date.now()+600000})),
  assertCurrent:vi.fn(async()=>({scope})),assertHistoricalGraph:vi.fn(async()=>undefined),runJob:vi.fn(async(_:any,fn:any)=>fn()),runRead:vi.fn(async(_:any,__ :any,fn:any)=>fn(()=>({calls:0,pages:0,records:0,bytes:0}))),assertObject:vi.fn(async()=>undefined)};
 const repo:any={createJob:vi.fn(async()=>job),getJob:vi.fn(async()=>({...job,state:data.jobState,safeProgress:data.safeProgress})),
  issueDownloadGrant:vi.fn(async(_:any,input:any,transaction:any)=>{expect(transaction).toBe(tx);expect(txDepth).toBe(1);trace.push('issue');await input.writeEvidence(tx,{scope,grantId:id(7),exportId:id(6),action:'issue'});return{id:id(7),token:'synthetic-unit-token'};}),
  consumeDownloadGrant:vi.fn(async(_:any,input:any,transaction:any)=>{expect(transaction).toBe(tx);expect(txDepth).toBe(1);data.consumed=true;trace.push('consume');await input.writeEvidence(tx,{scope,grantId:id(7),exportId:id(6),action:'consume'});return{content:'_format_version: "1.1"\nservices: []\n',byteCount:37,format:'deck-1.1'};}),
  finishJob:vi.fn(async(_:any,input:any,transaction:any)=>{if(input.safeProgress?.downloadPermitConsumed){expect(transaction).toBe(tx);expect(txDepth).toBe(1);trace.push('result');}
   data.jobState=input.state;data.safeProgress=input.safeProgress;return{...job,state:input.state,safeProgress:input.safeProgress};}),
  beginCapture:vi.fn(async()=>{throw new ConflictException({code:'CAPTURE_REGISTRATION_FAILED'});}),recordStepEvidence:vi.fn(),claimJob:vi.fn()};
 const audit:any={append:vi.fn(async(_:any,transaction:any)=>{expect(transaction).toBe(tx);trace.push('audit');})};
 const workspaces:any={resolve:vi.fn(async()=>({id:scope.workspaceId,name:'unit'}))};
 const kong:any={request:vi.fn()};
 const native:any={execute:vi.fn()};
 const redis:any={withLock:vi.fn(async(_:string,fn:any)=>fn())};
 const service=new ConfigurationService(db,redis,secrets,ctx,audit,{}as any,workspaces,access,repo,{capture:vi.fn()}as any,native,{}as any,{}as any,{}as any,kong,new ConfigurationFailureLedgerService(db,secrets,audit,access,ctx,{}as any));
 const frame=<T>(fn:()=>Promise<T>)=>ctx.runHttp({requestId:actor.requestId},async()=>{ctx.bindHttpActor(user,id(2));return fn();});
 return{service,ctx,secrets,actor,scope,handle,trace,data,job,db,tx,repo,access,audit,workspaces,kong,native,redis,frame};
}
describe('M8 Root façade failure and transaction seams',()=>{
 it.each([null,id(50)])('projects only the persisted full-tuple execution identity: %s',async executionId=>{
  const f=fixture();f.job.kind='apply';f.job.state='running';f.job.safeProgress={driver:'deck',executionId:id(99),planRevision:1,planHash:'a'.repeat(64)};
  vi.spyOn((f.service as any).failureLedger,'abandonmentIntent').mockResolvedValue(null);
  f.db.one.mockImplementation(async(sql:string,params:any[])=>{
   expect(sql).toBe(CONFIGURATION_JOB_PROJECTION_QUERY);expect(params).toEqual([f.job.id,f.scope.clusterId,f.scope.workspaceId,f.actor.user.id]);
   expect(sql).toContain('e.plan_id=j.plan_id AND e.plan_revision=j.plan_revision AND e.plan_hash=j.plan_hash');expect(sql).toContain('e.actor_id=j.actor_id');
   return{plan_id:id(21),actor_id:f.actor.user.id,idempotency_key:f.actor.idempotencyKey,execution_id:executionId,execution_mode:'direct',approval_required:false};
  });
  const result=await f.service.jobProjection(f.handle,f.job);expect(result).toMatchObject({planId:id(21),driver:'deck',executionId,state:'running',executionCompleted:false});
  expect(result.job.executionId).toBe(executionId);expect(f.native.execute).not.toHaveBeenCalled();expect(f.db.transaction).not.toHaveBeenCalled();
 });
 it('does not project a missing or scope-mismatched authorized job row',async()=>{
  const f=fixture();f.db.one.mockResolvedValue(null);await expect(f.service.jobProjection(f.handle,f.job)).rejects.toMatchObject({status:404});expect(f.native.execute).not.toHaveBeenCalled();
 });
 it.each(['capturing-live','capturing-terminal','failed','incomplete','expired','deleted'])('returns only authorized metadata for an unready snapshot: %s',async scenario=>{
  const f=fixture(),state=scenario.startsWith('capturing')?'capturing':scenario;
  const summary={id:id(25),clusterId:f.scope.clusterId,workspaceId:f.scope.workspaceId,scopeKind:'workspace',state,recovery:{complete:0}};
  (f.service as any).authz={hasWholeWorkspace:vi.fn(async()=>true),hasWholeCluster:vi.fn(async()=>false)};
  vi.spyOn(f.service as any,'snapshotScope').mockResolvedValue({scope:f.scope,handle:f.handle,row:{state}});
  f.repo.getSnapshotSummary=vi.fn(async()=>summary);f.repo.readSnapshot=vi.fn();
  f.db.one.mockImplementation(async(sql:string)=>sql===SNAPSHOT_TERMINAL_CAPTURE_QUERY?(scenario==='capturing-terminal'?{state:'failed'}:null):{created_by:f.actor.user.id,available:0});
  const result=await f.frame(()=>f.service.snapshot(f.scope.clusterId,summary.id,{},f.actor));
  expect(result).toMatchObject({entity:{state},items:[],nextCursor:null,capabilities:{read:true,compare:false,export:false,rollback:false,restore:false,purge:false,delete:scenario!=='capturing-live'&&state!=='deleted'}});
  expect(f.repo.readSnapshot).not.toHaveBeenCalled();expect(f.access.assertHistoricalGraph).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it.each(['success','context','plan-cas','remote-failure'])('prepares approval only from the exact original workflow and plan transaction: %s',async outcome=>{
  const f=fixture(),workflowId=id(30),executionId=id(31),stepId=id(32),payload={jobId:f.job.id,planId:id(33),planRevision:1,planHash:'c'.repeat(64)};
  const step={id:stepId,key:'configuration',order:1,kind:'metadata',handler:'configuration_v2',entityType:'configuration_jobs',entityId:f.job.id,permissionAction:'write',dependencies:[],nativeRequests:[],metadata:payload},
    plan:any={version:1,workflowId,clusterId:f.scope.clusterId,workspaceId:f.scope.workspaceId,planRevision:1,kind:'configuration_v2',executionMode:'approval',approvalRequired:true,
      subject:{type:'configuration_jobs',id:f.job.id},requester:{type:'console',id:f.actor.user.id},definition:{id:id(35),version:1,policyHash:'d'.repeat(64)},
      issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+120000).toISOString(),scope:{transportScope:f.scope.transportScope,clusterRevision:1,workspaceRevision:1},prerequisites:[],steps:[step]},input:any={plan,step,actor:f.actor,executionId};
  // The legacy branch is allowed only by an actual scoped, unmarked and
  // unbound durable row. Its provenance guard is not mocked or disabled.
  f.db.one.mockImplementation(async(sql:string,params:any[])=>{
    if(sql===DURABLE_CONFIGURATION_PRESENCE_QUERY){expect(params).toEqual([payload.jobId,plan.clusterId,plan.workspaceId]);f.trace.push('legacy-domain');return{authority_domain:null,durable_issue_id:null,has_durable_issue:false,has_durable_binding:false};}
    expect(sql).toContain('SELECT j.required_origin_kind,j.required_origin_id,j.required_origin_hmac');expect(sql).toContain('configuration_job_origin_bindings');expect(sql).toContain('configuration_plan_origin_bindings');
    expect(params).toEqual([payload.jobId,plan.clusterId,plan.workspaceId]);f.trace.push('legacy-origin');
    return{required_origin_kind:null,required_origin_id:null,required_origin_hmac:null,has_job_origin:false,has_plan_origin:false};
  });
  f.tx.one.mockImplementation(async(sql:string,params:any[])=>{expect(sql).toBe(APPROVAL_WORKFLOW_CONTEXT_QUERY);expect(params).toEqual([workflowId,executionId,stepId,f.scope.clusterId,f.scope.workspaceId]);return outcome==='context'?null:{state:'executing',execution_state:'executing',step_state:'running',execution_actor_id:f.actor.user.id,approved_by:id(34),plan_revision:1,plan_hash:f.secrets.fingerprint(plan)};});
  f.tx.exec.mockImplementation(async(sql:string,params:any[])=>{expect(sql).toBe(APPROVAL_CONFIGURATION_PLAN_QUERY);expect(params).toEqual([payload.planId,payload.jobId,1,f.scope.clusterId,f.scope.workspaceId,payload.planHash,workflowId]);f.trace.push('approve-plan');return outcome==='plan-cas'?0:1;});
  const dispatch=vi.spyOn(f.service as any,'executeJob').mockImplementation(async(...args:any[])=>{expect(args).toEqual([f.handle,f.job.id,f.actor,{workflowId,approvedVersion:1,workflowExecutionId:executionId}]);expect(f.trace.at(-1)).toBe('commit');f.trace.push('dispatch');if(outcome==='remote-failure')throw new ForbiddenException({code:'CURRENT_EXECUTION_DENIED'});return{state:'succeeded'};});
  const call=()=>f.frame(()=>(f.service as any).prepareWrapper(input));
  if(outcome==='success'){await call();expect(f.trace).toEqual(['legacy-domain','legacy-origin','begin','approve-plan','commit','dispatch']);}else{await expect(call()).rejects.toThrow();if(outcome!=='remote-failure'){expect(f.trace.at(-1)).toBe('rollback');expect(dispatch).not.toHaveBeenCalled();}}
  expect(f.native.execute).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it.each([['CONFIGURATION_DIFF_SCOPE_MISMATCH',409],['CONFIGURATION_INVALID_YAML',400]])('normalizes only typed transfer error %s to HTTP %i without private paths',async(code,status)=>{const f=fixture();const error=new ConfigTransferError(code,'SyntheticPrivateFieldValue');await expect(f.frame(()=>(f.service as any).withActor(f.scope.clusterId,f.actor,'read',async()=>{throw error;}))).rejects.toMatchObject({status,response:{code}});try{await f.frame(()=>(f.service as any).withActor(f.scope.clusterId,f.actor,'read',async()=>{throw error;}));}catch(e:any){expect(JSON.stringify(e.getResponse())).not.toContain('SyntheticPrivateFieldValue');}expect(f.repo.createJob).not.toHaveBeenCalled();});
 it('keeps unexpected storage errors as real failures rather than recasting them as validation',async()=>{const f=fixture(),error=Object.assign(new Error('synthetic storage failure'),{code:'23514'});await expect(f.frame(()=>(f.service as any).withActor(f.scope.clusterId,f.actor,'read',async()=>{throw error;}))).rejects.toBe(error);});
 it.each(['success','job-cas','plan-cas','authority'])('keeps V2 defaults, wrapper and exact pending binding in the same authorized transaction: %s',async outcome=>{
  const f=fixture(),identity={planId:id(20),planRevision:1,planHash:'a'.repeat(64)};f.tx.one.mockResolvedValue({id:f.job.id});f.access.assertCurrent.mockResolvedValue({scope:f.scope,expiresAt:Date.now()+60000,clusterRevision:1,workspaceRevision:1});
  const definitions=vi.fn(async(_:any,__:any,___:any,tx:any)=>{expect(tx).toBe(f.tx);f.trace.push('definitions');}),definition=vi.fn(async(_:any,__:any,___:any,tx:any)=>{expect(tx).toBe(f.tx);return{id:id(21),version:1,policyHash:'b'.repeat(64)};}),persist=vi.fn(async(plan:any,_:any,__:any,tx:any)=>{expect(tx).toBe(f.tx);expect(plan.steps).toHaveLength(1);expect(plan.steps[0].nativeRequests).toEqual([]);f.trace.push('persist');});
  (f.service as any).workflowPlans={definitions,definition,persist};f.tx.exec.mockImplementation(async(sql:string)=>sql.includes('UPDATE configuration_jobs')&&outcome==='job-cas'||sql.includes('UPDATE configuration_plans')&&outcome==='plan-cas'?0:1);
  if(outcome==='authority')f.access.assertCurrent.mockResolvedValueOnce({scope:f.scope,expiresAt:Date.now()+60000,clusterRevision:1,workspaceRevision:1}).mockRejectedValueOnce(new ForbiddenException({code:'CURRENT_AUTHORITY_REVOKED'}));
  const call=()=>f.frame(()=>(f.service as any).createWrapper(f.handle,f.job.id,identity,f.actor));
  if(outcome==='success'){await call();expect(f.trace).toEqual(['begin','definitions','persist','commit']);}else{await expect(call()).rejects.toThrow();expect(f.trace.at(-1)).toBe('rollback');}
  expect(f.access.assertCurrent.mock.calls.every(c=>c[2]===f.tx)).toBe(true);expect(f.native.execute).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
 });
 it('compares only schema booleans after authorizing both actual sealed graphs',async()=>{const f=fixture(),a=transferGraph(),b=structuredClone(a);(b.schemas.entities.services as any).fields.reverse();
  vi.spyOn(f.service as any,'snapshotScope').mockImplementation(async(_:string,snapshotId:string)=>({scope:f.scope,handle:snapshotId===id(30)?f.handle:Object.freeze({second:true}),row:{}}));
  f.repo.readSnapshot=vi.fn(async(_:any,input:any)=>input.snapshotId===id(30)?a:b);
  const result=await f.frame(()=>f.service.compareSnapshots(id(3),id(30),id(31),f.actor,'schema'));
  expect(result).toMatchObject({readOnly:true,schemaComparison:{exactEqual:false,namedFieldOrderEquivalent:true}});
  expect(f.repo.readSnapshot).toHaveBeenCalledTimes(2);expect(f.access.assertHistoricalGraph).toHaveBeenCalledTimes(2);expect(f.repo.createJob).not.toHaveBeenCalled();expect(f.native.execute).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  expect(JSON.stringify(result)).not.toContain('fixture-not-a-live-password');
 });
 it('denies schema diagnostics when either current historical graph is unauthorized',async()=>{const f=fixture();vi.spyOn(f.service as any,'snapshotScope').mockResolvedValue({scope:f.scope,handle:f.handle,row:{}});f.repo.readSnapshot=vi.fn(async()=>transferGraph());f.access.assertHistoricalGraph.mockRejectedValueOnce(new ForbiddenException({code:'CONFIGURATION_HISTORICAL_OBJECT_DENIED'}));
  await expect(f.frame(()=>f.service.compareSnapshots(id(3),id(30),id(31),f.actor,'schema'))).rejects.toMatchObject({status:403});expect(f.repo.createJob).not.toHaveBeenCalled();
 });
 it('refuses diagnostics across different scope roots before decrypting either graph',async()=>{const f=fixture();vi.spyOn(f.service as any,'snapshotScope').mockResolvedValueOnce({scope:f.scope,handle:f.handle,row:{}}).mockResolvedValueOnce({scope:{...f.scope,kind:'services',rootIds:[id(99)]},handle:f.handle,row:{}});f.repo.readSnapshot=vi.fn();
  await expect(f.frame(()=>f.service.compareSnapshots(id(3),id(30),id(31),f.actor,'schema'))).rejects.toMatchObject({response:{code:'CONFIGURATION_COMPARE_SCOPE_MISMATCH'}});expect(f.repo.readSnapshot).not.toHaveBeenCalled();
 });
 it.each(['bff','deck','approval'])('initializes the once-frozen execution revision before %s dispatch',async driver=>{
  const f=fixture(),planId=id(20),identity={jobId:f.job.id,planId:id(21),planRevision:1,planHash:'b'.repeat(64)},progress={baselineSnapshotId:id(22),baselineVersion:1};
  f.job.revision=1;f.job.kind='apply';
  vi.spyOn(f.service,'plan').mockResolvedValue({entity:{name:'unit',planRevision:1,planHash:identity.planHash,executionMode:'direct',deleteCount:0,mode:'merge'}}as any);
  vi.spyOn(f.service as any,'newJob').mockResolvedValue({scope:f.scope,handle:f.handle,job:f.job,existing:false});vi.spyOn(f.service as any,'assertPlanGrants').mockResolvedValue(undefined);
  f.db.one.mockImplementation(async(sql:string)=>{if(sql.includes('SELECT j.*'))return{safe_progress:progress,scope_kind:'workspace',root_ids:[]};if(sql.includes('SELECT execution_mode'))return{execution_mode:driver==='approval'?'approval':'direct'};throw Error('unexpected execution initializer query');});
  f.repo.readPlan=vi.fn(async()=>({steps:[]}));f.repo.freezePlan=vi.fn(async()=>{f.trace.push('freeze');return identity;});
  f.repo.initializeExecutionProgress=vi.fn(async(handle:any,input:any)=>{expect(handle).toBe(f.handle);expect(input).toEqual({identity,revision:2,safeProgress:{...progress,driver:driver==='approval'?'bff':driver}});f.trace.push('initialize');});
  vi.spyOn(f.service as any,'executeJob').mockImplementation(async()=>{f.trace.push('bff');return{state:'succeeded'};});
  vi.spyOn(f.service as any,'startDeckExecution').mockImplementation(async()=>{f.trace.push('deck');return{state:'running'};});
  vi.spyOn(f.service as any,'createWrapper').mockImplementation(async()=>{f.trace.push('approval');});vi.spyOn(f.service,'jobProjection').mockResolvedValue({state:'waiting_approval'});
  await f.frame(()=>f.service.apply(id(3),planId,{driver:driver==='approval'?'bff':driver,confirmed:true,confirm_name:'unit',planHash:identity.planHash,planRevision:1},f.actor));
  expect(f.trace).toEqual(['freeze','initialize',driver]);expect(f.db.transaction).not.toHaveBeenCalled();expect(f.tx.exec).not.toHaveBeenCalled();
 });
 it('returns a current material revision for an already committed export receipt',async()=>{
  const f=fixture();f.job.state='succeeded';f.job.safeProgress={exportId:id(6),mode:'review'};
  f.db.one.mockImplementation(async(sql:string,params:any[])=>{
   if(sql===EXPORT_PROJECTION_QUERY){expect(params).toEqual([id(6),id(3),id(4),f.actor.user.id]);return{revision:7,state:'ready',material_state:'available',expires_at:new Date(Date.now()+600000)};}
   return{actor_id:f.actor.user.id,plan_id:null,workflow_id:null,execution_mode:'direct',approval_required:false,idempotency_key:f.actor.idempotencyKey};
  });
  const receipt=await f.service.jobProjection(f.handle,f.job);
  expect(receipt).toMatchObject({state:'succeeded',exportRevision:7,capabilities:{download:true},idempotencyKey:f.actor.idempotencyKey});
  expect(f.repo.createJob).not.toHaveBeenCalled();expect(f.repo.finishJob).not.toHaveBeenCalled();expect(f.native.execute).not.toHaveBeenCalled();
 });
 it.each([{state:'destroyed',material_state:'available'},{state:'ready',material_state:'destroyed'},{state:'ready',material_state:'available',expires_at:new Date(0)}])(
  'does not advertise or consume unavailable export material %j',async unavailable=>{
   const f=fixture(),row={id:id(6),export_revision:7,revision:999,state:'ready',material_state:'available',expires_at:new Date(Date.now()+600000),...unavailable};
   f.db.one.mockImplementation(async(sql:string)=>{expect(sql).toBe(EXPORT_DOWNLOAD_QUERY);return row;});
   await expect(f.frame(()=>f.service.download(id(3),id(6),{revision:7},f.actor))).rejects.toMatchObject({response:{code:'CONFIGURATION_EXPORT_UNAVAILABLE'}});
   expect(f.repo.createJob).not.toHaveBeenCalled();expect(f.repo.issueDownloadGrant).not.toHaveBeenCalled();
  });
 it('preserves a committed export if response projection fails and never reruns export or marks it failed',async()=>{
  const f=fixture();vi.spyOn(f.service as any,'snapshotScope').mockResolvedValue({scope:f.scope,handle:f.handle,row:{current_version:1,name:'unit'}});
  vi.spyOn(f.service as any,'newJob').mockResolvedValue({scope:f.scope,handle:f.handle,job:f.job,existing:false});
  f.repo.readSnapshot=vi.fn(async()=>transferGraph());f.repo.createExport=vi.fn(async()=>({id:id(6),byteCount:100,expiresAt:new Date(Date.now()+600000).toISOString()}));
  vi.spyOn(f.service,'jobProjection').mockRejectedValue(new Error('synthetic lost response projection'));
  await expect(f.frame(()=>f.service.exportSnapshot(id(3),id(8),{mode:'review'},f.actor))).rejects.toThrow('synthetic lost response projection');
  expect(f.data.jobState).toBe('succeeded');expect(f.repo.createExport).toHaveBeenCalledTimes(1);
  expect(f.repo.finishJob).toHaveBeenCalledTimes(1);expect(f.repo.finishJob.mock.calls[0][1].state).toBe('succeeded');
 });
 it('atomically records issue, consume and safe result before exposing file bytes',async()=>{const f=fixture();const result=await f.frame(()=>f.service.download(id(3),id(6),{revision:7},f.actor));
  expect(result.content).toContain('_format_version');expect(f.trace).toEqual(['begin','issue','audit','consume','audit','result','commit']);
  expect(f.data.safeProgress).toMatchObject({downloadGrantId:id(7),downloadPermitConsumed:true,fileDeliveryUnconfirmed:true});expect(f.data.safeProgress.fileDelivered).toBeUndefined();
 });
 it('rolls consumption back if the durable result cannot be saved; returns no file',async()=>{const f=fixture(),original=f.repo.finishJob.getMockImplementation()!;
  f.repo.finishJob.mockImplementation(async(...args:any[])=>{if(args[1].state==='succeeded')throw new Error('synthetic write failure');return original(...args);});
  await expect(f.frame(()=>f.service.download(id(3),id(6),{revision:7},f.actor))).rejects.toThrow('synthetic write failure');
  expect(f.trace).toContain('rollback');expect(f.trace).not.toContain('commit');expect(f.data.consumed).toBe(false);expect(f.data.jobState).toBe('failed');
 });
 it('rolls issue and consume back on an audit failure',async()=>{const f=fixture();f.audit.append.mockRejectedValueOnce(new Error('synthetic outbox failure'));
  await expect(f.frame(()=>f.service.download(id(3),id(6),{revision:7},f.actor))).rejects.toThrow('synthetic outbox failure');
  expect(f.repo.consumeDownloadGrant).not.toHaveBeenCalled();expect(f.data.consumed).toBe(false);expect(f.data.jobState).toBe('failed');
 });
 it('fails before grant consumption on a stale actual export revision',async()=>{const f=fixture();await expect(f.frame(()=>f.service.download(id(3),id(6),{revision:1},f.actor))).rejects.toMatchObject({response:{code:'CONFIGURATION_EXPORT_REVISION_CONFLICT'}});
  expect(f.repo.createJob).not.toHaveBeenCalled();expect(f.repo.issueDownloadGrant).not.toHaveBeenCalled();
 });
 it('rejects oversized download before transaction commit',async()=>{const f=fixture();f.repo.consumeDownloadGrant.mockImplementation(async()=>{f.data.consumed=true;return{content:'small synthetic value',byteCount:33554433};});
  await expect(f.frame(()=>f.service.download(id(3),id(6),{revision:7},f.actor))).rejects.toMatchObject({response:{code:'CONFIGURATION_DOWNLOAD_TOO_LARGE'}});
  expect(f.data.consumed).toBe(false);expect(f.data.jobState).toBe('failed');
 });
 it('records failed capture registration instead of leaving the job pending',async()=>{const f=fixture();f.job.kind='capture';
  await expect(f.frame(()=>f.service.captureSnapshot(id(3),{name:'unit'},f.actor))).rejects.toMatchObject({response:{code:'CAPTURE_REGISTRATION_FAILED'}});
  expect(f.data.jobState).toBe('failed');expect(f.data.safeProgress).toEqual({});
 });
 it('rejects a too-long description before registering a job',async()=>{const f=fixture();await expect(f.frame(()=>f.service.captureSnapshot(id(3),{name:'unit',description:'x'.repeat(8193)},f.actor))).rejects.toThrow();expect(f.repo.createJob).not.toHaveBeenCalled();});
 it('one invalid timer owner does not starve other due policies',async()=>{const f=fixture();f.repo.peekDueSchedules=vi.fn(async()=>[{scheduleId:id(20)},{scheduleId:id(21)}]);f.access.acquireDueSchedule=vi.fn(async()=>{throw new ForbiddenException({code:'CONFIGURATION_ACTOR_INACTIVE'});});
  await f.service.runDueSchedules();expect(f.access.acquireDueSchedule).toHaveBeenCalledTimes(2);expect(f.redis.withLock.mock.calls.map((c:any)=>c[0])).toEqual([`configuration-schedule:${id(20)}`,`configuration-schedule:${id(21)}`]);
  expect(f.native.execute).not.toHaveBeenCalled();
 });
 it('observes actual objects without replaying mutations or rewriting their uncertain receipt',async()=>{const f=fixture();const summary={revision:1,planRevision:1,planHash:'b'.repeat(64),workspaceId:id(4)};
  vi.spyOn(f.service,'plan').mockResolvedValue({entity:summary});vi.spyOn(f.service as any,'assertPlanGrants').mockResolvedValue(undefined);
  vi.spyOn(f.service,'jobProjection').mockImplementation(async(_:any,j:any)=>j);
  f.db.one.mockImplementation(async(sql:string)=>{if(sql.includes('SELECT j.scope_kind'))return{scope_kind:'workspace',root_ids:[]};if(sql.includes('SELECT * FROM configuration_jobs'))return null;throw new Error('unexpected reconcile query');});
  f.repo.readPlan=vi.fn(async()=>({steps:[{stepId:id(22),entityType:'services',mutationAction:'update',nativeId:id(23),body:{host:'expected.test'}},
   {stepId:id(24),entityType:'routes',mutationAction:'delete',nativeId:id(25),body:null}]}));
  f.kong.request.mockImplementation(async(_:string,method:string,path:string)=>{expect(method).toBe('GET');if(path.endsWith(id(25)))throw new HttpException('synthetic missing',404);return{id:id(23),host:'changed.test',tags:[]};});
  const receipt=await f.frame(()=>f.service.reconcilePlan(id(3),id(26),{revision:1,planHash:summary.planHash},f.actor));
  expect(receipt.safeProgress).toMatchObject({readOnly:true,executionChanged:false,reconciledPlanId:id(26)});
  expect(receipt.safeProgress.observations.map((o:any)=>({match:o.expectedFieldsMatch,unproven:o.causalOutcomeUnproven}))).toEqual([{match:false,unproven:true},{match:true,unproven:true}]);
  expect(f.repo.recordStepEvidence).not.toHaveBeenCalled();expect(f.repo.claimJob).not.toHaveBeenCalled();expect(f.native.execute).not.toHaveBeenCalled();
  expect(JSON.stringify(receipt)).not.toContain('changed.test');
 });
});
