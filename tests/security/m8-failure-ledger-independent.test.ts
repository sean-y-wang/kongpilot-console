import {describe,expect,it,vi} from 'vitest';
import {createHash} from 'node:crypto';
import {ConfigurationFailureLedgerService} from '../../apps/console-api/src/modules/configuration/configuration-failure-ledger.service';
import {ConfigurationAccessService} from '../../apps/console-api/src/modules/configuration/configuration-access.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {canonicalJson} from '../../apps/console-api/src/infrastructure/secret.service';
import {transportScopeFor} from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import {CONFIGURATION_FAILURE_ANCHOR_QUERY as ANCHOR,CONFIGURATION_FAILURE_STEPS_QUERY as STEPS,
 CONFIGURATION_FAILURE_JOB_CAS as JOB,CONFIGURATION_FAILURE_EXECUTION_CAS as EXECUTION,
 CONFIGURATION_FAILURE_STEP_CAS as STEP,CONFIGURATION_ABANDON_CURRENT_IDENTITY_QUERY as IDENTITY,
 CONFIGURATION_ABANDON_EXECUTION_REFERENCE_QUERY as REFERENCES} from '../../apps/console-api/src/modules/configuration/configuration-failure-queries';

/** Actual ledger, private AccessService handles and execution frames. All SQL
 * rows/permissions are synthetic. No env, credentials, sockets or real DB are
 * read; the SHA fingerprint substitute provides no product encryption key. */
const id=(n:number)=>`a8000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const hash=(v:unknown)=>createHash('sha256').update(canonicalJson(v)).digest('hex');
function fixture(approval=false){
 const actor={id:id(1),username:'synthetic-ledger-owner',superAdmin:false},sid=id(2),cid=id(3),wid=id(4),jobId=id(5),executionId=id(6),planId=id(7),requestId=id(8);
 const ctx=new KongExecutionContextService(),physical=transportScopeFor('http://kong:8001'),planHash='a'.repeat(64),claimHash='b'.repeat(64);
 const cluster={id:cid,version:'1.5.1',status:'connected',admin_url:'http://kong:8001',revision:1,enabled_plugins:['key-auth'],execution_mode:approval?'approval':'direct'};
 const workspace={id:wid,cluster_id:cid,status:'active',revision:1,code:'synthetic'};
 const user={id:actor.id,username:actor.username,super_admin:false,credential_epoch:1,force_password_change:false};
 const job:any={id:jobId,cluster_id:cid,workspace_id:wid,transport_scope:physical,actor_id:actor.id,origin_session_id:sid,
  idempotency_key:'synthetic-ledger-original',kind:'apply',scope_kind:'workspace',root_ids:[],lease_generation:1,permission_version:'original-iam',credential_epoch:1,
  authority_expires_at:new Date(Date.now()+600000),state:'running',input_secret:null};
 const anchor:any={job_id:jobId,cluster_id:cid,workspace_id:wid,actor_id:actor.id,origin_session_id:sid,transport_scope:physical,kind:'apply',
  job_state:'running',job_revision:4,plan_id:planId,plan_revision:2,plan_hash:planHash,workflow_id:approval?id(9):null,
  execution_mode:approval?'approval':'direct',permission_version:'original-iam',credential_epoch:1,lease_generation:1,lease_owner_hash:'c'.repeat(64),lease_until:new Date(Date.now()+30000).toISOString(),
  safe_progress:{originalMarker:'preserve'},job_request_id:requestId,execution_id:executionId,execution_state:'executing',execution_revision:3,claim_hash:claimHash,
  execution_actor_id:actor.id,execution_workflow_id:approval?id(9):null,approved_version:approval?2:null,workflow_plan_hash:approval?'d'.repeat(64):null,
  execution_mode_actual:approval?'approval':'direct',execution_permission_version:'original-iam',execution_lease_generation:1,
  execution_plan_id:planId,execution_plan_revision:2,execution_plan_hash:planHash,step_count:3,version_plan_hash:planHash,current_revision:2,
  workflow_kind:approval?'configuration_v2':null,workflow_state:approval?'executing':null,subject_id:approval?jobId:null,subject_type:approval?'configuration_jobs':null,
  requester_user_id:approval?actor.id:null,workflow_plan_revision:approval?2:null,current_workflow_plan_hash:approval?'d'.repeat(64):null,
  workflow_execution_id:approval?id(10):null,workflow_execution_state:approval?'executing':null,snapshot_state:approval?'ready':null,
  workflow_execution_actor_id:approval?actor.id:null,workflow_request_id:approval?requestId:null,workflow_execution_plan_revision:approval?2:null,
  workflow_execution_plan_hash:approval?'d'.repeat(64):null};
 const step=(n:number,status:string,hasOp:boolean):any=>{
  const stepId=id(20+n),opId=hasOp?id(30+n):null;
  return{id:stepId,state:status,revision:1,step_order:n,plan_step_id:id(40+n),object_workspace_id:wid,
   operation_id:approval?opId:null,receipt_operation_id:status==='succeeded'?opId:null,after_hmac:status==='succeeded'?'e'.repeat(64):null,
   receipt_present:status==='succeeded',entity_type:'services',permission_action:'write',mutation_action:'create',parent_id:null,credential_kind:null,allocated_native_id:id(50+n),native_id:null,
   native_operation_id:opId,native_entity_id:hasOp?id(50+n):null,native_workflow_id:approval&&hasOp?id(9):null,
   native_result_present:hasOp&&status==='succeeded',native_state:hasOp?(status==='succeeded'?'succeeded':'running'):null,remote_started:hasOp?true:null,remote_completed:hasOp?status==='succeeded':null,
   native_cluster_id:hasOp?cid:null,native_workspace_id:hasOp?wid:null,native_actor_id:hasOp?actor.id:null,native_transport_scope:hasOp?physical:null,
   native_action:hasOp?'create':null,native_entity_type:hasOp?'services':null,native_parent_id:null,native_credential_kind:null,native_key:hasOp?`configuration-${jobId}-${stepId}`:null,
   configuration_job_id:approval&&hasOp?jobId:null,configuration_execution_id:approval&&hasOp?executionId:null,configuration_step_id:approval&&hasOp?stepId:null,
   configuration_plan_revision:approval&&hasOp?2:null,configuration_plan_hash:approval&&hasOp?planHash:null,
   workflow_execution_id:null,workflow_step_id:null,workflow_plan_revision:null,workflow_plan_hash:null,fence_count:hasOp?1:0};
 };
 const state={anchor,steps:[step(1,'succeeded',true),step(2,'running',true),step(3,'pending',false)],identityActive:true,revoked:false,granted:true,currentEpoch:1,referenceCount:1,version:'original-iam',failCas:'',events:[]as any[]};
 const secrets:any={fingerprint:vi.fn(hash),redact:vi.fn((v:any)=>structuredClone(v))};
 let db:any;
 db={transaction:vi.fn(async(fn:any)=>{const saved=structuredClone({anchor:state.anchor,steps:state.steps,events:state.events});try{return await fn(db);}catch(e){Object.assign(state,saved);throw e;}}),
  one:vi.fn(async(sql:string,p:any[]=[])=>{
   if(sql===ANCHOR||sql===ANCHOR.replace('FOR UPDATE OF j,e','')){const a=state.anchor;return p[0]===a.cluster_id&&p[1]===a.workspace_id&&p[2]===a.job_id&&p[3]===a.execution_id&&p[4]===a.workflow_execution_id?structuredClone(a):null;}
   if(sql===IDENTITY||sql===IDENTITY.replace('FOR SHARE OF u,s,c,w',''))return state.identityActive&&state.granted&&p[0]===actor.id&&p[1]===sid&&p[2]===cid&&p[3]===wid&&p[4]===state.currentEpoch?{id:actor.id,session_id:sid}:null;
   if(sql.includes('FROM iam_epoch'))return{version:1};
   if(sql.includes('FROM configuration_jobs'))return p[0]===jobId?structuredClone(job):null;
   if(sql.includes('FROM auth_sessions'))return !state.revoked&&[sid,id(99)].includes(p[0])&&p[1]===actor.id?{expires_at:new Date(Date.now()+3600000),credential_epoch:state.currentEpoch}:null;
   if(sql.includes('FROM users'))return p[0]===actor.id&&state.identityActive?{...user,credential_epoch:state.currentEpoch}:null;
   if(sql.includes('FROM metrics_write_fences'))return{count:'0',latest_time:null,latest_id:null,unsettled:'0'};
   if(sql.includes('FROM mutation_operations'))return{count:'0'};
   if(sql.includes('FROM clusters'))return p[0]===cid?structuredClone(cluster):null;
   if(sql.includes('FROM workspaces'))return p[0]===cid&&p[1]===wid?structuredClone(workspace):null;
   throw Error(`Unexpected synthetic one: ${sql.slice(0,70)}`);
  }),query:vi.fn(async(sql:string)=>{
   if(sql===REFERENCES)return Array.from({length:state.referenceCount},()=>({execution_id:executionId,workflow_execution_id:state.anchor.workflow_execution_id}));
   if(sql===STEPS){const rows=structuredClone(state.steps);if(!/p\.mutation_action/.test(sql))for(const row of rows)delete row.mutation_action;return rows;}
   if(sql.includes('FROM clusters'))return[structuredClone(cluster)];throw Error(`Unexpected synthetic query: ${sql.slice(0,70)}`);
  }),exec:vi.fn(async(sql:string,p:any[]=[])=>{
   if(sql===STEP){if(state.failCas==='step')return 0;const row=state.steps.find(s=>s.id===p[7]);if(!row||row.revision!==p[8]||!['pending','running'].includes(row.state))return 0;row.state=p[9];row.error_code=p[10];row.revision++;return 1;}
   if(sql===JOB){expect(p).toHaveLength(16);if(state.failCas==='job')return 0;const a=state.anchor;if(a.job_revision!==p[10]||a.job_state!=='running'||a.lease_owner_hash!==p[14]||a.claim_hash!==p[15])return 0;a.job_state=p[11];a.safe_progress=JSON.parse(p[12]);a.error_code=p[13];a.job_revision++;return 1;}
   if(sql===EXECUTION){expect(p).toHaveLength(14);if(state.failCas==='execution')return 0;const a=state.anchor;if(a.execution_revision!==p[10]||a.execution_state!=='executing'||a.lease_owner_hash!==p[12]||a.claim_hash!==p[13])return 0;a.execution_state=p[11];a.execution_revision++;return 1;}
   if(sql.includes('pg_advisory_xact_lock'))return 1;throw Error(`Unexpected synthetic write: ${sql.slice(0,70)}`);
  })};
 const authz:any={snapshot:vi.fn(async()=>({user:{...actor},version:state.version,grants:[]})),permissionVersion:vi.fn(async()=>state.version),hasWholeWorkspace:vi.fn(async()=>state.granted),
  assertWholeWorkspace:vi.fn(async()=>{if(!state.granted)throw Error('CURRENT_PERMISSION_DENIED');}),assertWholeCluster:vi.fn(async()=>undefined),assertCluster:vi.fn(async()=>undefined)};
 const workspaces:any={resolve:vi.fn(async(_cid:string,_wid:string)=>({...workspace,id:_wid}))};
 const native={authorizeRequest:vi.fn(async()=>({})),authorizeResponse:vi.fn(async(_:any,v:any)=>v)};ctx.installPolicy(native);
 const access=new ConfigurationAccessService(db,secrets,authz,workspaces,{}as any,ctx,{}as any);access.onModuleInit();
 const audit:any={append:vi.fn(async(event:any,tx:any)=>{expect(tx).toBe(db);state.events.push(structuredClone(event));return{id:id(60)};})};
 const ledger=new ConfigurationFailureLedgerService(db,secrets,audit,access,ctx,authz);
 const frame=<T>(fn:()=>Promise<T>,options:any={})=>ctx.runHttp({requestId:options.requestId??requestId,ip:'192.0.2.1'},async()=>{
  ctx.bindHttpActor(options.actor??actor,options.sid??sid);const close=ctx.captureHttpCloser();
  try{return await ctx.runActor({actor:options.actor??actor,clusterId:options.cid??cid,workspaceId:options.wid??wid,module:'snapshots',action:'write'},fn);}finally{close();}
 });
 const arm=()=>frame(async()=>ledger.arm(await access.acquire(jobId),executionId,claimHash,state.anchor.workflow_execution_id));
 const value=()=>({revision:state.anchor.job_revision,executionId,executionRevision:state.anchor.execution_revision,planRevision:2,planHash,leaseGeneration:1,
  workflowExecutionId:state.anchor.workflow_execution_id,confirmed:true,confirm_name:`abandon:${jobId}`});
 const entityActor=()=>({user:actor,workspaceId:wid,idempotencyKey:'synthetic-ledger-abandon',requestId});
 const expired=()=>{state.anchor.lease_until=new Date(Date.now()-7000).toISOString();if(approval){state.anchor.workflow_state='failed';state.anchor.workflow_execution_state='uncertain';}};
 const unchangedNative=()=>{expect(native.authorizeRequest).not.toHaveBeenCalled();for(const [sql]of db.exec.mock.calls)expect([STEP,JOB,EXECUTION].includes(sql)||sql.includes('pg_advisory_xact_lock')).toBe(true);};
 return{ledger,access,ctx,db,secrets,audit,authz,native,state,actor,sid,cid,wid,job,jobId,executionId,planId,claimHash,requestId,frame,arm,value,entityActor,expired,unchangedNative};
}

describe('M8 failure ledger independent actual-class SOURCE boundaries',()=>{
 it('uses the actual query projection required by native receipt validation',()=>{
  expect(STEPS).toMatch(/p\.mutation_action/);expect(STEPS).toMatch(/o\.entity_id AS native_entity_id/);
  expect(STEPS).toMatch(/o\.workflow_id AS native_workflow_id/);expect(STEPS).toMatch(/\(o\.result_secret IS NOT NULL\) AS native_result_present/);
 });
 it('arms a genuine private handle and records once after the original frame and authority expire',async()=>{
  const f=fixture(),token=await f.arm(),originalSucceeded=structuredClone(f.state.steps[0]);
  expect(Object.isFrozen(token)).toBe(true);expect(Object.keys(token)).toEqual([]);
  f.job.authority_expires_at=new Date(Date.now()-1);f.state.revoked=true;f.state.granted=false;
  f.authz.permissionVersion.mockClear();f.authz.assertWholeWorkspace.mockClear();
  const result=await f.ledger.recordFailure(token,{code:'SAFE_FAILURE',message:'never persist raw password',stack:'private stack'});
  expect(result).toMatchObject({state:'uncertain',completedSteps:1,unresolvedSteps:1,terminalFailureRecorded:true,originalNativeReceiptsUnchanged:true});
  expect(f.state.steps[0]).toEqual(originalSucceeded);expect(f.state.steps[1].state).toBe('uncertain');expect(f.state.steps[2].error_code).toBe('CONFIGURATION_NOT_STARTED');
  expect(f.state.anchor.safe_progress).toMatchObject({originalMarker:'preserve',executionId:f.executionId,executionRevision:4,planRevision:2,
   planHash:'a'.repeat(64),leaseGeneration:1,workflowExecutionId:null,completedSteps:1,unresolvedSteps:1,terminalFailureRecorded:true});
  expect(f.authz.permissionVersion).not.toHaveBeenCalled();expect(f.authz.assertWholeWorkspace).not.toHaveBeenCalled();
  expect(JSON.stringify(f.state.events)).not.toMatch(/raw password|private stack/);expect(f.state.events).toHaveLength(1);
  await expect(f.ledger.recordFailure(token,{code:'AGAIN'})).rejects.toMatchObject({response:{code:'CONFIGURATION_FAILURE_CAPABILITY_INVALID'}});f.unchangedNative();
 });
 it.each(['forged','copied','foreign-instance'])('rejects %s access/token authority without ledger effects',async(which)=>{
  const f=fixture();if(which==='forged')await expect(f.frame(()=>f.ledger.arm({}as any,f.executionId,f.claimHash,null))).rejects.toThrow();
  else{const t=await f.arm();await expect((which==='foreign-instance'?fixture().ledger:f.ledger).recordFailure((which==='foreign-instance'?t:{...t})as any,Error('x'))).rejects.toThrow();}
  expect(f.audit.append).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();f.unchangedNative();
 });
 it('release consumes a token with zero SQL/audit effects and prevents record/release replay',async()=>{
  const f=fixture(),token=await f.arm();f.db.transaction.mockClear();f.ledger.release(token);expect(f.db.transaction).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  expect(()=>f.ledger.release(token)).toThrow();await expect(f.ledger.recordFailure(token,Error('x'))).rejects.toThrow();expect(f.audit.append).not.toHaveBeenCalled();
 });
 it.each(['cid','wid'])('does not arm an original private handle inside a foreign current frame %s',async(field)=>{
  const f=fixture(),handle=await f.frame(()=>f.access.acquire(f.jobId));
  await expect(f.frame(()=>f.ledger.arm(handle,f.executionId,f.claimHash,null),{[field]:id(99)})).rejects.toThrow();
  expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();f.unchangedNative();
 });
 it('consumes a capability before the first await so simultaneous failures cannot start two transactions',async()=>{
  const f=fixture(),token=await f.arm();let resume!:()=>void;const pending=new Promise<void>(resolve=>{resume=resolve;});f.db.transaction.mockClear();
  f.db.transaction.mockImplementationOnce(async(fn:any)=>{await pending;return fn(f.db);});
  const first=f.ledger.recordFailure(token,{code:'FIRST_FAILURE'});await expect(f.ledger.recordFailure(token,{code:'SECOND_FAILURE'})).rejects.toThrow();
  expect(f.db.transaction).toHaveBeenCalledTimes(1);resume();await first;expect(f.state.events).toHaveLength(1);f.unchangedNative();
 });
 it('does not persist an unsafe error code, message or stack',async()=>{
  const f=fixture(),token=await f.arm();await f.ledger.recordFailure(token,{code:'password=synthetic-private',message:'secret raw message',stack:'secret raw stack'});
  expect(f.state.events[0].after.errorCode).toBe('CONFIGURATION_OPERATION_FAILED');expect(JSON.stringify(f.state.events)).not.toMatch(/synthetic-private|secret raw/);f.unchangedNative();
 });
 it.each([null,'not-a-time',new Date(Date.now()-1000).toISOString()])('refuses invalid or expired arm lease %s',async(lease)=>{
  const f=fixture();f.state.anchor.lease_until=lease;await expect(f.arm()).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['execution_actor_id','execution_plan_id','execution_plan_hash','execution_permission_version','execution_lease_generation','claim_hash','job_request_id'])('refuses changed arm %s before minting',async(field)=>{
  const f=fixture();f.state.anchor[field]=field.includes('generation')?2:field.includes('hash')?'f'.repeat(64):field.includes('permission')?'changed':id(99);
  await expect(f.arm()).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it.each(['claim_hash','job_revision','execution_revision','plan_hash','lease_generation','lease_owner_hash'])('rejects changed immutable %s after arm and consumes the token',async(field)=>{
  const f=fixture(),token=await f.arm();f.state.anchor[field]=typeof f.state.anchor[field]==='number'?f.state.anchor[field]+1:'f'.repeat(64);
  await expect(f.ledger.recordFailure(token,Error('x'))).rejects.toThrow();await expect(f.ledger.recordFailure(token,Error('again'))).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();
 });
 it('includes the exact lease owner and original claim hash in both CAS predicates and arguments',async()=>{
  const f=fixture(),token=await f.arm(),owner=f.state.anchor.lease_owner_hash;await f.ledger.recordFailure(token,Error('synthetic'));
  const jobCall=f.db.exec.mock.calls.find(([sql]:any[])=>sql===JOB),executionCall=f.db.exec.mock.calls.find(([sql]:any[])=>sql===EXECUTION);
  expect(jobCall?.[1].slice(14)).toEqual([owner,f.claimHash]);expect(executionCall?.[1].slice(12)).toEqual([owner,f.claimHash]);
  expect(JOB).toMatch(/j\.lease_owner_hash=\$15/);expect(JOB).toMatch(/e\.claim_hash=\$16/);expect(EXECUTION).toMatch(/e\.claim_hash=\$14/);expect(EXECUTION).toMatch(/j\.lease_owner_hash=\$13/);f.unchangedNative();
 });
 it.each(['create-services','append-target','update-services'])('rejects a wrong native entity identity for %s without modifying any existing facts',async(which)=>{
  const f=fixture(),s=f.state.steps[0];
  if(which==='append-target')Object.assign(s,{entity_type:'targets',native_entity_type:'targets',mutation_action:'update',native_action:'update',native_id:id(90),parent_id:id(91),native_parent_id:id(91)});
  if(which==='update-services')Object.assign(s,{mutation_action:'update',native_action:'update',native_id:id(90),native_entity_id:id(90)});
  const token=await f.arm();s.native_entity_id=which==='append-target'?s.native_id:which==='update-services'?s.allocated_native_id:id(99);
  const before=structuredClone({anchor:f.state.anchor,steps:f.state.steps});
  await expect(f.ledger.recordFailure(token,Error('x'))).rejects.toMatchObject({response:{code:'CONFIGURATION_FAILURE_RECEIPT_INVALID'}});
  expect({anchor:f.state.anchor,steps:f.state.steps}).toEqual(before);expect(f.db.exec).not.toHaveBeenCalled();expect(f.state.events).toEqual([]);f.unchangedNative();
 });
 it.each(['completed-target-append','incomplete-target-update','completed-service-update'])('retains the correct typed native identity for %s',async(which)=>{
  const f=fixture(),s=f.state.steps[which==='incomplete-target-update'?1:0];
  Object.assign(s,{mutation_action:'update',native_action:'update',native_id:id(90)});
  if(which.includes('target'))Object.assign(s,{entity_type:'targets',native_entity_type:'targets',parent_id:id(91),native_parent_id:id(91)});
  s.native_entity_id=which==='completed-target-append'?s.allocated_native_id:s.native_id;
  const token=await f.arm(),original=structuredClone(s);await f.ledger.recordFailure(token,Error('x'));
  if(s.state==='succeeded')expect(s).toEqual(original);else expect(s.native_entity_id).toBe(original.native_entity_id);f.unchangedNative();
 });
 it('rejects pre-completion Targets using the future allocated identity',async()=>{
  const f=fixture(),s=f.state.steps[1];Object.assign(s,{entity_type:'targets',native_entity_type:'targets',mutation_action:'update',native_action:'update',native_id:id(90),parent_id:id(91),native_parent_id:id(91)});
  const token=await f.arm();await expect(f.ledger.recordFailure(token,Error('x'))).rejects.toMatchObject({response:{code:'CONFIGURATION_FAILURE_RECEIPT_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();f.unchangedNative();
 });
 it.each(['approval-foreign','approval-missing','direct-attached'])('rejects wrong existing native workflow binding %s',async(which)=>{
  const f=fixture(which!=='direct-attached'),token=await f.arm();f.state.steps[0].native_workflow_id=which==='approval-missing'?null:id(99);
  await expect(f.ledger.recordFailure(token,Error('x'))).rejects.toMatchObject({response:{code:'CONFIGURATION_FAILURE_RECEIPT_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();f.unchangedNative();
 });
 it.each(['result-missing','result-undefined','remote-started-false','remote-completed-false'])('rejects incomplete successful native proof %s before any ledger update',async(which)=>{
  const f=fixture(),token=await f.arm(),s=f.state.steps[0];
  if(which==='result-missing')s.native_result_present=false;if(which==='result-undefined')delete s.native_result_present;
  if(which==='remote-started-false')s.remote_started=false;if(which==='remote-completed-false')s.remote_completed=false;
  const before=structuredClone({anchor:f.state.anchor,steps:f.state.steps});await expect(f.ledger.recordFailure(token,Error('x'))).rejects.toMatchObject({response:{code:'CONFIGURATION_FAILURE_RECEIPT_INVALID'}});
  expect({anchor:f.state.anchor,steps:f.state.steps}).toEqual(before);expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();f.unchangedNative();
 });
 it.each(['job','execution','step'])('rolls back a zero-row %s CAS and never retries its consumed capability',async(which)=>{
  const f=fixture(),token=await f.arm(),before=structuredClone({anchor:f.state.anchor,steps:f.state.steps});f.state.failCas=which;
  await expect(f.ledger.recordFailure(token,Error('private'))).rejects.toMatchObject({response:{code:'CONFIGURATION_FAILURE_LEDGER_CHANGED'}});
  expect({anchor:f.state.anchor,steps:f.state.steps}).toEqual(before);expect(f.state.events).toEqual([]);await expect(f.ledger.recordFailure(token,Error('retry'))).rejects.toThrow();f.unchangedNative();
 });
 it('preserves terminal workflow and native/complete step facts in an approval failure',async()=>{
  const f=fixture(true),token=await f.arm(),succeeded=structuredClone(f.state.steps[0]);f.state.anchor.workflow_state='failed';f.state.anchor.workflow_execution_state='uncertain';
  await f.ledger.recordFailure(token,Error('raw error'));expect(f.state.anchor.workflow_state).toBe('failed');expect(f.state.anchor.workflow_execution_state).toBe('uncertain');
  expect(f.state.steps[0]).toEqual(succeeded);expect(f.state.events[0].after.errorCode).toBe('CONFIGURATION_OPERATION_FAILED');
  expect(f.state.anchor.safe_progress).toMatchObject({executionId:f.executionId,executionRevision:4,planRevision:2,planHash:'a'.repeat(64),leaseGeneration:1,workflowExecutionId:id(10)});f.unchangedNative();
 });
 it.each(['native_actor_id','native_transport_scope','native_action','receipt_operation_id','configuration_job_id','workflow_execution_id'])('rejects foreign existing native receipt %s without any terminal update',async(field)=>{
  const f=fixture(true),token=await f.arm();f.state.steps[0][field]=field.includes('scope')?'f'.repeat(64):field==='native_action'?'delete':id(99);
  await expect(f.ledger.recordFailure(token,Error('x'))).rejects.toMatchObject({response:{code:'CONFIGURATION_FAILURE_RECEIPT_INVALID'}});expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();
 });
 it.each(['missing','reordered','receiptless-success'])('rejects an inconsistent %s DAG before writes',async(which)=>{
  const f=fixture(),token=await f.arm();if(which==='missing')f.state.steps.pop();if(which==='reordered')f.state.steps[1].step_order=9;if(which==='receiptless-success')f.state.steps[0].receipt_present=false;
  await expect(f.ledger.recordFailure(token,Error('x'))).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();
 });
 it('records partial only for known pre-transport failure, retaining successful receipts',async()=>{
  const f=fixture(),token=await f.arm();Object.assign(f.state.steps[1],{remote_started:false,remote_completed:false,fence_count:0,native_state:'failed'});
  const result=await f.ledger.recordFailure(token,{code:'BEFORE_TRANSPORT_FAILED'});expect(result.state).toBe('partial');expect(result.unresolvedSteps).toBe(0);expect(f.state.steps[1].state).toBe('failed');f.unchangedNative();
 });
 it('abandon requires a current original SID/grant and expired-grace full tuple, and only appends uncertain facts',async()=>{
  const f=fixture(true);f.expired();const original=structuredClone(f.state.steps[0]),result=await f.frame(()=>f.ledger.abandon(f.cid,f.jobId,f.value(),f.entityActor()));
  expect(result).toMatchObject({state:'uncertain',abandoned:true,originalWorkflowUnchanged:true,originalNativeReceiptsUnchanged:true});expect(f.state.steps[0]).toEqual(original);
  expect(f.state.anchor.workflow_state).toBe('failed');expect(f.state.anchor.workflow_execution_state).toBe('uncertain');expect(f.state.steps[2].state).toBe('uncertain');
  expect(f.state.events[0].action).toBe('configuration.execution.abandon');expect(f.authz.assertWholeWorkspace).toHaveBeenCalledWith(f.actor,f.cid,f.wid,'workflows','write');f.unchangedNative();
 });
 it.each(['actor','sid','cid','wid','plan','revision','executionRevision','leaseGeneration','terminal','grace','confirmation','grant','identity','credentials','epoch'])('rejects abandon %s substitution with zero committed writes',async(which)=>{
  const f=fixture();f.expired();const value:any=f.value(),options:any={};let cid=f.cid,actor:any=f.entityActor();
  if(which==='actor'){actor={...actor,user:{...f.actor,id:id(99)}};options.actor=actor.user;}if(which==='sid')options.sid=id(99);if(which==='cid'){cid=id(99);options.cid=cid;}
  if(which==='wid'){actor.workspaceId=id(99);options.wid=id(99);}if(which==='plan')value.planHash='f'.repeat(64);
  if(['revision','executionRevision','leaseGeneration'].includes(which))value[which]++;if(which==='terminal')f.state.anchor.execution_state='succeeded';
  if(which==='grace')f.state.anchor.lease_until=new Date(Date.now()-1000).toISOString();if(which==='confirmation')value.confirm_name='foreign';
  if(which==='grant')f.state.granted=false;if(which==='identity')f.state.identityActive=false;if(which==='credentials')f.state.currentEpoch=2;
  if(which==='epoch')f.authz.permissionVersion.mockResolvedValueOnce('original-iam').mockResolvedValueOnce('new-iam');
  await expect(f.frame(()=>f.ledger.abandon(cid,f.jobId,value,actor),options)).rejects.toThrow();expect(f.state.events).toHaveLength(0);expect(f.db.exec).not.toHaveBeenCalled();f.unchangedNative();
 });
 it('discovers a safe read-only abandonment confirmation without renewing expired execution authority',async()=>{
  const f=fixture(true);f.expired();f.job.authority_expires_at=new Date(Date.now()-1000);
  const intent=await f.frame(async()=>f.ledger.abandonmentIntent(await f.access.acquireReceipt(f.jobId),f.jobId));
  expect(intent).toMatchObject({jobId:f.jobId,executionId:f.executionId,revision:4,executionRevision:3,planRevision:2,leaseGeneration:1,confirmationName:`abandon:${f.jobId}`});
  expect(Object.isFrozen(intent)).toBe(true);expect(intent).not.toHaveProperty('claimHash');expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();f.unchangedNative();
 });
 it.each(['cid','wid'])('does not expose abandonment intent for a genuine readonly handle in a foreign frame %s',async(field)=>{
  const f=fixture();f.expired();const handle=await f.frame(()=>f.access.acquireReceipt(f.jobId));f.db.query.mockClear();
  await expect(f.frame(()=>f.ledger.abandonmentIntent(handle,f.jobId),{[field]:id(99)})).resolves.toBeNull();
  expect(f.db.query.mock.calls.filter(([sql]:any[])=>sql===REFERENCES)).toEqual([]);expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();f.unchangedNative();
 });
 it.each(['new-sid','current-grant','current-epoch','active-lease','no-reference','ambiguous-reference'])('does not disclose abandonment intent for %s',async(which)=>{
  const f=fixture();f.expired();const options:any={};if(which==='new-sid')options.sid=id(99);if(which==='current-grant')f.state.granted=false;
  if(which==='current-epoch')f.state.currentEpoch=2;if(which==='active-lease')f.state.anchor.lease_until=new Date(Date.now()+1000).toISOString();
  if(which==='no-reference')f.state.referenceCount=0;if(which==='ambiguous-reference')f.state.referenceCount=2;
  const result=await f.frame(async()=>{const h=await f.access.acquireReceipt(f.jobId);return f.ledger.abandonmentIntent(h,f.jobId);},options).catch(e=>{if(which==='current-grant'&&e.message==='CURRENT_PERMISSION_DENIED')return null;throw e;});
  expect(result).toBeNull();expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();
 });
 it('re-reads CAS facts instead of treating a prior read-only intent as abandonment authority',async()=>{
  const f=fixture();f.expired();const intent=await f.frame(async()=>f.ledger.abandonmentIntent(await f.access.acquireReceipt(f.jobId),f.jobId));
  f.state.anchor.job_revision++;const value={...f.value(),revision:intent!.revision};
  await expect(f.frame(()=>f.ledger.abandon(f.cid,f.jobId,value,f.entityActor()))).rejects.toThrow();expect(f.db.exec).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();
 });
 it('does not provide any native/workflow mutation API or SQL entry point',()=>{
  const f=fixture();expect(Object.getOwnPropertyNames(ConfigurationFailureLedgerService.prototype)).not.toEqual(expect.arrayContaining(['execute','retry','recover','resume','mutate']));
  for(const sql of[JOB,EXECUTION,STEP])expect(sql).not.toMatch(/(?:UPDATE|DELETE FROM|INSERT INTO)\s+(?:mutation_operations|workflow_executions|workflow_execution_steps|workflows)\b/i);
  expect(STEP).toMatch(/state IN\('pending','running'\)/);expect(JOB).toMatch(/j\.revision=\$11/);expect(EXECUTION).toMatch(/e\.revision=\$11/);f.unchangedNative();
 });
});
