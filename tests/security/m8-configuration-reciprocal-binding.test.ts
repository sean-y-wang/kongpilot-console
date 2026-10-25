import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ConfigurationAccessService} from '../../apps/console-api/src/modules/configuration/configuration-access.service';
import {MutationService} from '../../apps/console-api/src/modules/mutations/mutation.service';
import {CONFIGURATION_APPROVED_OPERATION_LINK_SQL} from '../../apps/console-api/src/modules/workflows/configuration-approved-verifier';
import {configurationApprovedFixture,id} from './m8-configuration-approved-fixture';

beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.stubEnv('APP_SECRET','reciprocal-binding-synthetic-material-over-thirty-two-characters');});
afterEach(()=>vi.unstubAllEnvs());

/** Real Root access/delegate, approved verifier, crypto, execution frames,
 * AuthorizationService and MutationService. SQL/Redis/transport are explicit
 * RAM ports; the exact exported CAS is also tested by the isolated PG owner.
 * No live fixtures, current environment, HTTP or native side effects are used.
 */
async function fixture(){
  const f=await configurationApprovedFixture({actualAuthorization:true});
  Object.assign(f.job,{kind:'apply',scope_kind:'workspace',root_ids:[],idempotency_key:'synthetic-original-apply',input_secret:null});
  Object.assign(f.session,{expires_at:f.job.expires_at});Object.assign(f.ws,{code:'unit'});
  f.executorGrants.push(...['read','write'].map(action=>({module:'services',action,scope_type:'workspace',cluster_id:f.cid,workspace_id:f.wid,scope_values:[f.wid]})));
  const baseOne=f.db.one.getMockImplementation()!,baseQuery=f.db.query.getMockImplementation()!,baseExec=f.db.exec.getMockImplementation()!;
  const state={remote:null as any,casAfter:null as null|(()=>void),forceCasConflict:false,otherRunning:false,sessionRevoked:false};
  f.db.one.mockImplementation(async(sql:string,p:any[])=>{
    if(sql.includes('FROM auth_sessions')&&state.sessionRevoked)return null;
    if(sql.includes('FROM metrics_write_fences'))return{count:'0',latest_time:null,latest_id:null,unsettled:'0'};
    if(sql.includes('SELECT count(*)::text AS count FROM mutation_operations'))return{count:state.otherRunning?'1':String([...f.operations.values()].filter(o=>['pending','running','uncertain'].includes(o.state)&&!p[2].includes(o.id)).length)};
    if(sql.includes('FROM mutation_operations'))return p[1]? [...f.operations.values()].find(o=>o.cluster_id===p[0]&&o.idempotency_key===p[1]):f.operations.get(p[0]);
    if(sql.includes('FROM configuration_job_steps s'))return{...f.rows[0],execution_mode:f.job.execution_mode,execution_state:f.execution.state,body_hmac:f.step.bodyHmac,plan_before_hmac:f.step.beforeHmac};
    return baseOne(sql,p);
  });
  f.db.query.mockImplementation(async(sql:string,p:any[])=>{
    if(sql.includes('SELECT id,admin_url,transport_scope FROM clusters'))return[f.cluster];
    if(sql.includes('FROM mutation_operations'))return[...f.operations.values()].filter(o=>['running','uncertain'].includes(o.state));
    return baseQuery(sql,p);
  });
  f.db.exec.mockImplementation(async(sql:string,p:any[])=>{
    if(sql.startsWith('INSERT INTO mutation_operations')){
      f.operations.set(p[0],{id:p[0],cluster_id:p[1],actor_id:p[2],action:p[3],idempotency_key:p[4],request_hash:p[5],workflow_id:p[6],request_id:p[7],entity_type:p[8],entity_id:p[9],before_secret:p[10],payload_secret:p[11],workspace_id:p[12],transport_scope:p[13],impact:JSON.parse(p[14]),parent_id:p[15],credential_kind:p[16],workflow_execution_id:p[17],workflow_plan_revision:p[18],workflow_plan_hash:p[19],workflow_step_id:p[20],configuration_job_id:p[21],configuration_execution_id:p[22],configuration_step_id:p[23],configuration_plan_revision:p[24],configuration_plan_hash:p[25],state:'running',remote_started:false,remote_completed:false,result_secret:null});return 1;
    }
    if(sql===CONFIGURATION_APPROVED_OPERATION_LINK_SQL){if(state.forceCasConflict)return 0;const count=await baseExec(sql,p);if(count)state.casAfter?.();return count;}
    if(sql.includes('UPDATE mutation_operations')){
      const row=f.operations.get(p[0]);if(!row)throw new Error('synthetic operation absent');
      if(sql.includes('remote_started=true'))row.remote_started=true;
      else if(sql.includes('remote_completed=true'))Object.assign(row,{remote_completed:true,entity_id:p[1],result_secret:p[2]});
      else if(sql.includes("state='succeeded'"))Object.assign(row,{state:'succeeded',safe_result:JSON.parse(p[1])});
      else throw new Error('unexpected synthetic update');return 1;
    }
    return baseExec(sql,p);
  });
  const ws:any={resolve:vi.fn(async()=>f.ws),get:vi.fn(async()=>f.ws),listScope:vi.fn(async()=>({workspaceId:f.wid})),assertMembership:vi.fn()};
  const access=new ConfigurationAccessService(f.db,f.secrets,f.authz,ws,f.kong,f.context,{}as any);access.onModuleInit();
  const observedLinks:Array<string|null>=[];let handle:any;
  f.delegate.verifyExecution.mockImplementation(async(_id:string,tx:any)=>{
    await access.assertCurrent(handle,{phase:'step',jobId:f.jobId},tx);
    if(f.operations.size)observedLinks.push(f.rows[0].operation_id);return {...f.claim};
  });
  f.redis.withLock=vi.fn(async(_key:string,fn:any)=>fn());f.kong.transportScope=vi.fn(async()=>f.job.transport_scope);
  f.kong.request.mockImplementation(async(_cid:string,method:string,_path:string,body:any)=>{
    if(method==='POST'){state.remote={...body};return structuredClone(state.remote);}
    if(method==='GET'&&state.remote)return structuredClone(state.remote);
    const error:any=new Error('synthetic absent');error.status=404;throw error;
  });
  const audit:any={append:vi.fn(async()=>undefined)},mutations=new MutationService(f.db,f.redis,f.secrets,audit,f.kong,f.authz,ws,f.context);
  const run=<T>(fn:()=>Promise<T>)=>f.run(async()=>{
    handle=await access.acquire(f.jobId);
    return access.runJob(handle,()=>access.runStep(handle,f.step,f.jobStepId,()=>f.verifier.runConfigurationExecution(f.executionId,()=>f.context.runApprovedStep(f.jobStepId,fn))));
  });
  const mutate=()=>mutations.execute({...f.mutation,before:undefined},async()=>{
    const op=[...f.operations.values()][0],packet:any={clusterId:f.cid,workspaceId:f.wid,transportScope:f.job.transport_scope,operationId:op.id,method:'POST',canonicalPath:'/services',body:f.step.body,before:null,mutationAction:'create',frame:f.context.current(),cluster:f.cluster,query:{}};
    await f.verifier.assertNative(f.context.currentApprovedStep(),packet,'before-send');
    const entity=await f.kong.request(f.cid,'POST','/services',f.step.body);
    await f.verifier.assertNative(f.context.currentApprovedStep(),{...packet,result:entity},'response');return{entity};
  });
  return{...f,access,state,audit,mutations,run,mutate,observedLinks};
}

describe('M8 exact V2 reciprocal link before current native authority',()=>{
  it('reproduces the strict current Root delegate refusal for an inserted but unlinked operation',async()=>{
    const f=await fixture();await f.run(async()=>{
      const binding=await f.context.approvedMutationBinding(f.mutation);f.operations.set(id(19),f.op(binding));
      await expect(f.delegate.verifyExecution(f.executionId,f.db)).rejects.toMatchObject({response:{code:'CONFIGURATION_NATIVE_BINDING_CHANGED'}});
      expect(f.rows[0].operation_id).toBeNull();
    });expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('runs real Mutation INSERT→full reciprocal CAS→Root current authority→one native callback and terminal audit',async()=>{
    const f=await fixture();await expect(f.run(f.mutate)).resolves.toMatchObject({entity:{id:f.nativeId}});
    const op=[...f.operations.values()][0];expect(op.state).toBe('succeeded');expect(op.remote_started).toBe(true);expect(op.remote_completed).toBe(true);
    expect(f.rows[0].operation_id).toBe(op.id);expect(f.rows[0].revision).toBe(2);
    expect(f.observedLinks.length).toBeGreaterThan(0);expect(f.observedLinks.every(link=>link===op.id)).toBe(true);
    expect(f.kong.request.mock.calls.filter(c=>c[1]==='POST')).toHaveLength(1);
    expect(f.audit.append).toHaveBeenCalledWith(expect.objectContaining({action:'create',result:'success'}),f.db);
    expect(f.secrets.decrypt(op.before_secret,`mutation:${op.id}:before`)).toBeNull();
  });
  it.each(['approverGrant','executorEpoch','session','lease','encryptedBody','foreignRunning'])('rolls reciprocal link and INSERT back for late %s refusal, before any native callback',async(kind)=>{
    const f=await fixture();f.state.casAfter=()=>{
      if(kind==='approverGrant')f.approvalGrants.length=0;
      if(kind==='executorEpoch')f.iamEpoch.version++;
      if(kind==='session')f.state.sessionRevoked=true;
      if(kind==='lease')f.claim.leaseGeneration++;
      if(kind==='encryptedBody'){const op=[...f.operations.values()][0];op.payload_secret=f.secrets.encrypt({foreign:true},`mutation:${op.id}:payload`);}
      if(kind==='foreignRunning')f.state.otherRunning=true;
    };
    await expect(f.run(f.mutate)).rejects.toThrow();expect(f.operations.size).toBe(0);expect(f.rows[0].operation_id).toBeNull();expect(f.rows[0].revision).toBe(1);
    expect(f.kong.request).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();
  });
  it('rejects a failed revision CAS without a current-verifier recursion or any native packet',async()=>{
    const f=await fixture();f.state.forceCasConflict=true;
    await expect(f.run(f.mutate)).rejects.toMatchObject({response:{code:'CONFIGURATION_OPERATION_LINK_CONFLICT'}});
    expect(f.operations.size).toBe(0);expect(f.rows[0].operation_id).toBeNull();expect(f.observedLinks).toHaveLength(0);expect(f.kong.request).not.toHaveBeenCalled();
  });
  it.each(['actor_id','workspace_id','configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash','workflow_id','workflow_execution_id','idempotency_key','remote_started','remote_completed','result_secret'])('rejects substituted inserted operation %s before linking',async(field)=>{
    const f=await fixture();await f.run(async()=>{
      const binding=await f.context.approvedMutationBinding(f.mutation),op=f.op(binding);
      (op as any)[field]=field==='configuration_plan_revision'?2:field==='configuration_plan_hash'?'0'.repeat(64):field.startsWith('remote_')?true:field==='idempotency_key'?'other-key':field==='result_secret'?'already-remote':id(90);
      f.operations.set(op.id,op);
      await expect(f.db.transaction((tx:any)=>f.context.bindApprovedOperation(f.mutation,binding!,op.id,tx))).rejects.toThrow();
      expect(f.rows[0].operation_id).toBeNull();expect(f.observedLinks).toHaveLength(0);
    });expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('rejects an inactive genuine private proof/binding after its execution frame closes, before CAS',async()=>{
    const f=await fixture();let proof:any,binding:any;
    await f.run(async()=>{proof=f.context.currentApprovedStep();binding=await f.context.approvedMutationBinding(f.mutation);});
    const originalCalls=f.db.exec.mock.calls.length;
    await f.run(()=>expect(f.verifier.bindOperation(proof,f.mutation,binding,id(19),f.db)).rejects.toMatchObject({response:{code:'CONFIGURATION_APPROVED_BINDING_INVALID'}}));
    expect(f.db.exec.mock.calls).toHaveLength(originalCalls);expect(f.kong.request).not.toHaveBeenCalled();
  });
});
