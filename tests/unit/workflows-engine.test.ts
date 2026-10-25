import 'reflect-metadata';
import { describe,it,expect,vi,beforeEach,afterEach } from 'vitest';
import { ConflictException,ForbiddenException,ServiceUnavailableException,NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { WorkflowService } from '../../apps/console-api/src/modules/workflows/workflow.service';
import { PortalNativeService } from '../../apps/console-api/src/modules/portal/portal-native.service';
import { WorkflowRegistryService } from '../../apps/console-api/src/modules/workflows/workflow-registry.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';
import type { WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { assertKongPath } from '../../apps/console-api/src/infrastructure/kong/policy';
import { ConfigurationApprovedVerifier } from '../../apps/console-api/src/modules/workflows/configuration-approved-verifier';
import { ConfigurationService } from '../../apps/console-api/src/modules/configuration/configuration.service';
import { DURABLE_CONFIGURATION_PRESENCE_QUERY } from '../../apps/console-api/src/modules/configuration/configuration-durable.repository';

const scopedOriginJobSql='SELECT * FROM configuration_jobs WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3';
const scopedLegacyOriginSql=`SELECT j.required_origin_kind,j.required_origin_id,j.required_origin_hmac,
  EXISTS(SELECT 1 FROM configuration_job_origin_bindings b WHERE b.job_id=j.id) AS has_job_origin,
  EXISTS(SELECT 1 FROM configuration_plan_origin_bindings b WHERE b.job_id=j.id OR b.plan_id=j.plan_id) AS has_plan_origin
  FROM configuration_jobs j WHERE j.id=$1 AND j.cluster_id=$2 AND j.workspace_id=$3`.replace(/\s+/g,' ').trim();

/** Actual engine/plan helpers. Infrastructure and gateway are explicitly isolated fixtures,
 * not evidence of live authorization or PostgreSQL deferred constraints. */
function fixture(approval=false,configurationWrapper=false){
  const cid=randomUUID(),wid=randomUUID(),workflowId=randomUUID(),userId=randomUUID(),serviceId=randomUUID(),pluginId=randomUUID(),actor={user:{id:userId,username:'engine-user',superAdmin:false},workspaceId:wid,idempotencyKey:'engine-original-key'};
  const secrets=new SecretService(),gateway=new Map<string,any>([[`/services/${serviceId}`,{id:serviceId,name:'source',tags:['kos-ws-pay']}]]),physical='a'.repeat(64),locks:string[]=[];let physicalHeld=false,version='v1';
  const execution:any={peek:vi.fn(()=>null),hasWorkflowScheduledNamespace:vi.fn(()=>false),runActor:vi.fn(async (_scope:any,fn:any)=>fn()),runPortalMetadataRead:vi.fn(async(_cid:any,_path:any,fn:any)=>fn()),runInternalRead:vi.fn(async (_cid:any,_purpose:any,fn:any)=>fn()),runApprovedStep:vi.fn(async (_id:any,fn:any)=>fn())};
  const authz:any={permissionVersion:vi.fn(async()=>version),assertCluster:vi.fn(),assertScopedResource:vi.fn()};
  const kong:any={transportScope:vi.fn(async()=>physical),request:vi.fn(async (_cid:string,method:string,path:string)=>{if(method!=='GET')throw new Error('Engine must dispatch native writes through Entities');const item=gateway.get(path);if(!item)throw new NotFoundException();return structuredClone(item);})};
  const resolver:any={resolve:vi.fn(async()=>({id:wid,revision:1,status:'active'}))};
  const native=new PortalNativeService({}as any,secrets,kong,execution,authz,resolver),before={id:randomUUID(),revision:2};
  const first=native.nativeStep(1,'plugins','create',{id:pluginId,name:'acl',service:{id:serviceId},tags:['kos-ws-pay'],config:{whitelist:['group']}},null,{workflowId});
  const last=configurationWrapper?native.metadataStep(1,'configuration_v2','configuration_jobs',before.id,before,{jobId:before.id,planId:randomUUID(),planRevision:2,planHash:'c'.repeat(64)},[]):native.metadataStep(2,'portal.publication.publish','portal_publications',before.id,before,{publicationRevision:1},[first.id]);
  const plan:WorkflowPlanV1={version:1,clusterId:cid,workspaceId:wid,workflowId,planRevision:1,kind:configurationWrapper?'configuration_v2':'portal-publication',executionMode:approval?'approval':'direct',approvalRequired:approval,subject:{type:configurationWrapper?'configuration_jobs':'portal_publications',id:before.id},requester:{type:'console',id:userId},definition:{id:randomUUID(),version:1,policyHash:'b'.repeat(64)},issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+3600000).toISOString(),scope:{transportScope:physical,clusterRevision:1,workspaceRevision:1},prerequisites:configurationWrapper?[]:[{type:'services',id:serviceId,path:`/services/${serviceId}`,before:gateway.get(`/services/${serviceId}`),fingerprint:secrets.fingerprint(gateway.get(`/services/${serviceId}`))}],steps:configurationWrapper?[last]:[first,last]};
  validateWorkflowPlan(plan);
  const row:any={id:workflowId,cluster_id:cid,workspace_id:wid,kind:plan.kind,revision:1,plan_revision:1,plan_hash:secrets.fingerprint(plan),execution_mode:plan.executionMode,approval_required:approval,state:approval?'approved':'pending',approved_by:approval?randomUUID():null,requester_user_id:userId,idempotency_key:actor.idempotencyKey,created_at:new Date().toISOString(),expires_at:plan.expiresAt};
  const configurationJob=configurationWrapper?{id:before.id,cluster_id:cid,workspace_id:wid,plan_id:(last.metadata as any).planId,plan_revision:2,plan_hash:'c'.repeat(64),authority_domain:null,durable_issue_id:null,required_origin_kind:null,required_origin_id:null,required_origin_hmac:null}:null;
  const state:any={events:[],execution:null,business:{published:false},configurationJob,originBindings:{job:false,plan:false},durableBindings:{issue:false,binding:false},steps:plan.steps.map(step=>({id:step.id,step_key:step.key,kind:step.kind,state:'pending',safe_result:{},operation_id:null,recycle_entry_id:null,error_code:null}))};
  const db:any={one:vi.fn(async(sql:string,params:any[])=>{
    const normalized=sql.replace(/\s+/g,' ').trim();if(normalized===scopedOriginJobSql||normalized===scopedLegacyOriginSql||normalized===DURABLE_CONFIGURATION_PRESENCE_QUERY.replace(/\s+/g,' ').trim()){
      const job=state.configurationJob;if(!job||params.length!==3||params[0]!==job.id||params[1]!==job.cluster_id||params[2]!==job.workspace_id)return null;
      if(normalized===scopedOriginJobSql)return structuredClone(job);
      if(normalized===DURABLE_CONFIGURATION_PRESENCE_QUERY.replace(/\s+/g,' ').trim())return {authority_domain:job.authority_domain,durable_issue_id:job.durable_issue_id,has_durable_issue:state.durableBindings.issue,has_durable_binding:state.durableBindings.binding};
      return{required_origin_kind:job.required_origin_kind,required_origin_id:job.required_origin_id,required_origin_hmac:job.required_origin_hmac,has_job_origin:state.originBindings.job,has_plan_origin:state.originBindings.plan};
    }
    if(sql.includes('FROM workflow_events'))return state.events.find((e:any)=>e.key===params[3])??null;if(sql.includes('FROM clusters'))return{revision:1,execution_mode:plan.executionMode};if(sql.includes('FROM workflow_executions'))return state.execution;if(sql.includes("state='running'"))return state.steps.find((s:any)=>s.state==='running')??null;return null;}),query:vi.fn(async(sql:string)=>sql.includes('workflow_steps')?structuredClone(state.steps):[]),exec:vi.fn(async(sql:string,p:any[])=>{
    if(sql.startsWith('INSERT INTO workflow_events')){state.events.push({workflow_id:p[2],safe_metadata:JSON.parse(p[6]),key:JSON.parse(p[6]).key});return 1;}
    if(sql.startsWith('INSERT INTO workflow_executions')){state.execution={id:p[0],state:'executing',execution_actor_id:p[9],idempotency_key:p[12]};return 1;}
    if(sql.startsWith('UPDATE workflows')){if(sql.includes("SET state='cancelled'")){row.state='cancelled';row.revision++;return 1;}if(sql.includes("state='executing'")){if(sql.includes("SET state='succeeded'"))row.state='succeeded';else if(sql.includes('SET state=$2'))row.state=p[1];else row.state='executing';}else if(sql.includes("SET state='executing'"))row.state='executing';row.revision++;return 1;}
    if(sql.startsWith('UPDATE workflow_executions')){if(sql.includes("snapshot_state='ready'")){state.execution.snapshot_state='ready';state.execution.snapshot_secret=p[1];state.execution.snapshot_hash=p[2];state.execution.snapshot_id=p[3];}else state.execution.state=sql.includes("SET state='succeeded'")?'succeeded':p[1];return 1;}
    if(sql.startsWith('UPDATE workflow_steps')){const step=state.steps.find((s:any)=>s.id===p[0]);if(!step)return 0;if(sql.includes("SET state='running'")){if(step.state!=='pending')return 0;step.state='running';}else if(sql.includes("SET state='succeeded'")){step.state='succeeded';step.safe_result=JSON.parse(p[1]);}else{step.state=p[1];step.error_code=p[2];step.safe_result=JSON.parse(p[3]);}return 1;}return 1;
  }),transaction:vi.fn(async(fn:any)=>{const old=structuredClone(state),oldRow=structuredClone(row);try{return await fn(db);}catch(error){Object.assign(state,old);Object.assign(row,oldRow);throw error;}})};
  const redis:any={withLock:vi.fn(async(key:string,fn:any)=>{locks.push(key);if(key.startsWith('mutation:')){physicalHeld=true;try{return await fn();}finally{physicalHeld=false;}}return fn();}),assertLeaseOwnership:vi.fn()};
  const receipt:any={operationId:randomUUID(),state:'succeeded',remoteStarted:true,remoteCompleted:true,entityId:pluginId};
  const entities:any={create:vi.fn(async(_cid:string,type:string,body:any)=>{expect(physicalHeld).toBe(false);expect(type).toBe('plugins');gateway.set(`/plugins/${body.id}`,{...body,tags:['kos-ws-pay'],enabled:true});return{entity:{id:body.id}};})};
  const mutations:any={inspectStepReceipt:vi.fn(async()=>receipt)},iam:any={execute:vi.fn(async(_ctx:any,fn:any)=>db.transaction(fn))},audit:any={append:vi.fn()};
  const originVerifier=new ConfigurationApprovedVerifier(db,secrets,authz,kong,redis,execution);
  const approved:any={runApprovedExecution:vi.fn(async(_id:any,fn:any)=>fn()),assertStep:vi.fn(),
    assertConfigurationOrigin:vi.fn((plan:WorkflowPlanV1,actorId:string,action:'read'|'write'|'approve',tx?:any)=>originVerifier.assertOrigin(plan,actorId,action,tx)),
    installConfigurationDelegate:(delegate:any)=>originVerifier.install(delegate)};
  // Use the real installed fallback and exact scoped SQL shapes. A job needs
  // explicit negative SQL038 domain/issue/binding facts before its separate
  // SQL018 legacy-origin fallback can remain legacy-compatible;
  // marked or stray-bound jobs cannot gain a permissive mock callback.
  const configurationPolicy=Object.assign(Object.create(ConfigurationService.prototype),{db,context:execution,
    repo:{installEvidenceWriter:vi.fn(),installScheduledExecutionOriginPolicy:vi.fn()},registry:{register:vi.fn()},approved,workflowPlans:{installConfigurationOriginDelegate:vi.fn()}});
  configurationPolicy.onModuleInit();
  const registry=new WorkflowRegistryService(),handler:any={authorize:vi.fn(),prepare:vi.fn(),inspect:vi.fn(async()=>({before,revision:before.revision})),apply:vi.fn(async()=>{state.business.published=true;return{publicationId:before.id};})};registry.register(configurationWrapper?'configuration_v2':'portal.publication.publish',handler);
  const plans:any={load:vi.fn(async()=>({row,plan,version:{}}))};
  const engine=new WorkflowService(db,redis,secrets,kong,execution,authz,audit,entities,mutations,iam,resolver,plans,registry,approved);
  const body={revision:1,planHash:row.plan_hash,confirmed:true,confirm_name:row.kind};
  return{engine,actor,cid,wid,workflowId,plan,row,body,state,secrets,db,redis,kong,entities,mutations,receipt,iam,approved,handler,audit,execution,gateway,locks,setVersion:(value:string)=>version=value};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ae'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('M6 durable workflow engine',()=>{
  it('keeps direct metadata audit tied to the original request, IP and workflow',async()=>{
    const f=fixture(),actor={...f.actor,requestId:randomUUID(),ip:'192.0.2.25'};
    await f.engine.execute(f.cid,f.workflowId,f.body,actor);
    const calls=f.audit.append.mock.calls.filter((call:any[])=>call[0].action==='portal.publication.publish');
    expect(calls).toHaveLength(1);expect(calls[0][0]).toMatchObject({requestId:actor.requestId,ip:actor.ip,workflowId:f.workflowId,actorId:actor.user.id,result:'success'});expect(calls[0][1]).toBe(f.db);
  });
  it('binds approved configuration metadata audit to its real job scope without native writes in the wrapper',async()=>{
    const f=fixture(true,true),actor={...f.actor,requestId:randomUUID(),ip:'192.0.2.26'};
    await f.engine.execute(f.cid,f.workflowId,f.body,actor);
    const calls=f.audit.append.mock.calls.filter((call:any[])=>call[0].action==='configuration_v2');
    expect(calls).toHaveLength(1);expect(calls[0][0]).toMatchObject({requestId:actor.requestId,ip:actor.ip,workflowId:f.workflowId,entityType:'configuration_jobs',entityId:f.plan.subject.id,scopeHints:{quality:'verified',module:'snapshots',subject:f.plan.subject,beforeWorkspaceId:f.wid,afterWorkspaceId:f.wid}});expect(calls[0][1]).toBe(f.db);expect(f.entities.create).not.toHaveBeenCalled();
    const snapshot=f.secrets.decrypt<any>(f.state.execution.snapshot_secret,`workflow:${f.cid}:${f.wid}:${f.workflowId}:${f.state.execution.id}:snapshot`);
    expect(f.state.execution.snapshot_hash).toBe(f.secrets.fingerprint(snapshot));expect(f.state.execution.snapshot_id).toMatch(/^[a-f\d-]{36}$/);expect(snapshot.objects).toEqual([]);
    const presenceReads=f.db.one.mock.calls.filter(([sql]:any)=>sql===DURABLE_CONFIGURATION_PRESENCE_QUERY);expect(presenceReads.length).toBeGreaterThanOrEqual(2);expect(presenceReads.every(([,params]:any)=>JSON.stringify(params)===JSON.stringify([f.plan.subject.id,f.cid,f.wid]))).toBe(true);
    const originReads=f.db.one.mock.calls.filter(([sql]:any)=>[scopedOriginJobSql,scopedLegacyOriginSql].includes(sql.replace(/\s+/g,' ').trim()));
    expect(originReads.length).toBeGreaterThanOrEqual(2);expect(originReads.every(([,params]:any)=>JSON.stringify(params)===JSON.stringify([f.plan.subject.id,f.cid,f.wid]))).toBe(true);
  });
  it.each(['domain','issue-id','issue-row','binding-row','partial-domain'] as const)('refuses %s durable evidence without its real provider before legacy metadata execution',async change=>{
    const f=fixture(true,true);if(change==='domain')f.state.configurationJob.authority_domain='durable-configuration-v1';
    else if(change==='issue-id')f.state.configurationJob.durable_issue_id=randomUUID();
    else if(change==='partial-domain')delete f.state.configurationJob.authority_domain;
    else f.state.durableBindings[change==='issue-row'?'issue':'binding']=true;
    await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'CONFIGURATION_DURABLE_PROVIDER_UNAVAILABLE'}});
    expect(f.handler.apply).not.toHaveBeenCalled();expect(f.approved.runApprovedExecution).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('rolls configuration metadata back if its mandatory correlated audit cannot append',async()=>{
    const f=fixture(true,true);f.audit.append.mockImplementation(async(event:any)=>{if(event.action==='configuration_v2')throw new Error('audit unavailable');});
    await expect(f.engine.execute(f.cid,f.workflowId,f.body,{...f.actor,requestId:randomUUID(),ip:'192.0.2.27'})).rejects.toMatchObject({response:{code:'WORKFLOW_EXECUTION_FAILED'}});
    expect(f.state.business.published).toBe(false);expect(f.state.steps[0].state).not.toBe('succeeded');expect(f.entities.create).not.toHaveBeenCalled();
  });
  it.each(['marked','job-binding','plan-binding']as const)('rejects a %s configuration wrapper without a source-origin provider before execution or metadata apply',async change=>{
    const f=fixture(true,true);if(change==='marked')Object.assign(f.state.configurationJob,{required_origin_kind:'governance-promote',required_origin_id:randomUUID(),required_origin_hmac:'d'.repeat(64)});
    else f.state.originBindings[change==='job-binding'?'job':'plan']=true;
    await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_PROVIDER_UNAVAILABLE'}});
    expect(f.handler.apply).not.toHaveBeenCalled();expect(f.approved.runApprovedExecution).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();expect(f.state.business.published).toBe(false);
  });
  it.each(['missing','foreign-cluster','foreign-workspace']as const)('requires the actual scoped durable job for a %s configuration wrapper',async change=>{
    const f=fixture(true,true);if(change==='missing')f.state.configurationJob=null;else f.state.configurationJob[change==='foreign-cluster'?'cluster_id':'workspace_id']=randomUUID();
    await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'CONFIGURATION_ORIGIN_JOB_UNAVAILABLE'}});
    expect(f.handler.apply).not.toHaveBeenCalled();expect(f.approved.runApprovedExecution).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('runs direct publication through ordinary Entities and IAM without any approved capability',async()=>{const f=fixture();const result=await f.engine.execute(f.cid,f.workflowId,f.body,f.actor);expect(result.state).toBe('succeeded');expect(f.approved.runApprovedExecution).not.toHaveBeenCalled();expect(f.execution.runApprovedStep).not.toHaveBeenCalled();expect(f.iam.execute).toHaveBeenCalledOnce();expect(f.entities.create).toHaveBeenCalledOnce();expect(f.mutations.inspectStepReceipt.mock.calls[0][0].entityId).toBeUndefined();expect(result.steps.every((step:any)=>step.remoteCompleted)).toBe(true);});
  it('releases snapshot physical lock before native Entity mutation locks',async()=>{const f=fixture();await f.engine.execute(f.cid,f.workflowId,f.body,f.actor);expect(f.locks).toEqual([`workflow:${f.workflowId}`,`mutation:${f.plan.scope.transportScope}`]);expect(f.kong.request.mock.calls[0][2]).toBe(f.plan.prerequisites[0].path);});
  it('establishes approved execution then private step before dispatch, never IAM approval bypass',async()=>{const f=fixture(true);await f.engine.execute(f.cid,f.workflowId,f.body,f.actor);expect(f.approved.runApprovedExecution).toHaveBeenCalledOnce();expect(f.execution.runApprovedStep).toHaveBeenCalledTimes(2);expect(f.iam.execute).not.toHaveBeenCalled();expect(f.approved.assertStep).toHaveBeenCalledOnce();});
  it('writes only logical original payload even when entity response is masked',async()=>{const f=fixture();await f.engine.execute(f.cid,f.workflowId,f.body,f.actor);const actual=f.mutations.inspectStepReceipt.mock.calls[0][0];expect(actual.payload).toEqual(f.plan.steps[0].mutationPayload);expect(actual.entityId).toBeUndefined();expect(f.entities.create.mock.calls[0][2].tags).toEqual(['workspace:pay']);});
  it('seals encrypted targeted snapshot including preallocated absence',async()=>{const f=fixture();await f.engine.execute(f.cid,f.workflowId,f.body,f.actor);const snapshot=f.secrets.decrypt<any>(f.state.execution.snapshot_secret,`workflow:${f.cid}:${f.wid}:${f.workflowId}:${f.state.execution.id}:snapshot`);expect(snapshot.objects).toHaveLength(2);expect(snapshot.objects[1]).toMatchObject({path:`/plugins/${f.plan.steps[0].nativeRequests[0].nativeId}`,before:null,absent:true});});
  it('stops all native writes on changed prerequisite',async()=>{const f=fixture();f.gateway.set(f.plan.prerequisites[0].path,{id:'changed'});await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'WORKFLOW_PREFLIGHT_CHANGED',state:'failed'}});expect(f.entities.create).not.toHaveBeenCalled();expect(f.state.business.published).toBe(false);});
  it('stops all native writes if allocated create ID already exists',async()=>{const f=fixture();f.gateway.set(`/plugins/${f.plan.steps[0].nativeRequests[0].nativeId}`,{id:'existing'});await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'WORKFLOW_PREFLIGHT_CHANGED'}});expect(f.entities.create).not.toHaveBeenCalled();});
  it('refuses changed metadata before committing business state and records partial result',async()=>{const f=fixture();f.handler.inspect.mockResolvedValue({before:{id:'different'},revision:2});await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'WORKFLOW_METADATA_CHANGED',state:'partial'}});expect(f.handler.apply).not.toHaveBeenCalled();expect(f.state.business.published).toBe(false);});
  it('rolls back publication and terminal parent on permission change during apply',async()=>{const f=fixture();f.handler.apply.mockImplementation(async()=>{f.state.business.published=true;f.setVersion('v2');return{};});await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'PERMISSIONS_CHANGED',state:'partial'}});expect(f.state.business.published).toBe(false);expect(f.state.execution.state).toBe('partial');});
  it('does not retry native calls after unknown result; original receipt preserves started state',async()=>{const f=fixture();f.receipt.state='uncertain';f.receipt.remoteCompleted=false;f.entities.create.mockRejectedValue(new ServiceUnavailableException({code:'KONG_RESULT_UNCERTAIN'}));await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{state:'uncertain'}});const result=await f.engine.execute(f.cid,f.workflowId,f.body,f.actor);expect(result.state).toBe('uncertain');expect(result.steps[0].remoteStarted).toBe(true);expect(f.entities.create).toHaveBeenCalledOnce();});
  it('succeeded original execution replay has zero additional gateway calls',async()=>{const f=fixture();await f.engine.execute(f.cid,f.workflowId,f.body,f.actor);const calls=f.kong.request.mock.calls.length;await f.engine.execute(f.cid,f.workflowId,f.body,f.actor);expect(f.entities.create).toHaveBeenCalledOnce();expect(f.kong.request).toHaveBeenCalledTimes(calls);});
  it('rejects foreign actor execution receipt ownership without replay',async()=>{const f=fixture();await f.engine.execute(f.cid,f.workflowId,f.body,f.actor);await expect(f.engine.execute(f.cid,f.workflowId,f.body,{...f.actor,user:{...f.actor.user,id:randomUUID()}})).rejects.toMatchObject({response:{code:'WORKFLOW_ALREADY_EXECUTED'}});expect(f.entities.create).toHaveBeenCalledOnce();});
  it('refuses pending unapproved credential/native plan before snapshot or Entity call',async()=>{const f=fixture(true);f.row.state='pending';await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'WORKFLOW_NOT_EXECUTABLE'}});expect(f.kong.request).not.toHaveBeenCalled();expect(f.entities.create).not.toHaveBeenCalled();});
  it('rejects changed cluster mode without quietly minting approved claim',async()=>{const f=fixture();f.db.one.mockImplementation(async(sql:string)=>sql.includes('clusters')?{revision:1,execution_mode:'approval'}:null);await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'WORKFLOW_SCOPE_CHANGED'}});expect(f.approved.runApprovedExecution).not.toHaveBeenCalled();expect(f.entities.create).not.toHaveBeenCalled();});
  it.each(['workflow_steps','workflow_executions','workflows'])('rolls back business publication when terminal %s CAS updates zero rows',async(table)=>{const f=fixture(),exec=f.db.exec.getMockImplementation()!;f.db.exec.mockImplementation(async(sql:string,p:any[])=>sql.startsWith(`UPDATE ${table} `)&&sql.includes("SET state='succeeded'")?0:exec(sql,p));await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'REVISION_CONFLICT',state:'partial'}});expect(f.state.business.published).toBe(false);expect(f.state.execution.state).toBe('partial');});
  it('stops before any native dispatch when durable snapshot ready CAS updates zero rows',async()=>{const f=fixture(),exec=f.db.exec.getMockImplementation()!;f.db.exec.mockImplementation(async(sql:string,p:any[])=>sql.includes("SET snapshot_state='ready'")?0:exec(sql,p));await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'REVISION_CONFLICT',state:'failed'}});expect(f.entities.create).not.toHaveBeenCalled();expect(f.handler.apply).not.toHaveBeenCalled();});
  it('captures every exact manifest target before dispatch, rejecting a changed second object',async()=>{const f=fixture();const nativeId=randomUUID();f.plan.steps[0].nativeRequests.push({...f.plan.steps[0].nativeRequests[0],nativeId,body:{id:nativeId},bodyHmac:f.secrets.fingerprint({id:nativeId})});f.row.plan_hash=f.secrets.fingerprint(f.plan);f.body.planHash=f.row.plan_hash;f.gateway.set(`/plugins/${nativeId}`,{id:nativeId});await expect(f.engine.execute(f.cid,f.workflowId,f.body,f.actor)).rejects.toMatchObject({response:{code:'WORKFLOW_PREFLIGHT_CHANGED'}});expect(f.entities.create).not.toHaveBeenCalled();});
  it('rejects multi-packet logical steps because the M6 dispatcher executes exactly one Entity operation',()=>{const f=fixture();f.plan.steps[0].nativeRequests.push({...f.plan.steps[0].nativeRequests[0],nativeId:randomUUID()});expect(()=>validateWorkflowPlan(f.plan)).toThrow();expect(f.entities.create).not.toHaveBeenCalled();});
  it.each(['unlisted-child','more-pages'])('stops retirement snapshot on %s before any credential or Consumer mutation',async(reason)=>{const f=fixture(),consumer=randomUUID();f.plan.steps[1].handler='portal.credential.revoke';f.plan.steps[1].metadata={consumerId:consumer,retireConsumer:true};const original=f.kong.request.getMockImplementation()!;f.kong.request.mockImplementation(async(cid:string,method:string,path:string)=>path.startsWith(`/consumers/${consumer}/`)?reason==='more-pages'?{data:[],next:'/consumers/next?offset=another'}:{data:[{id:randomUUID()}],next:null}:original(cid,method,path));await expect((f.engine as any).snapshot(f.plan,randomUUID(),f.actor)).rejects.toMatchObject({response:{code:'PORTAL_RETIREMENT_UNLISTED_CHILDREN'}});expect(f.entities.create).not.toHaveBeenCalled();expect(f.handler.apply).not.toHaveBeenCalled();});
  it('uses strict allowed global plugin pages to prove a retired Consumer has no plugin children',async()=>{
    const f=fixture(),consumer=randomUUID(),original=f.kong.request.getMockImplementation()!;
    f.plan.steps[1].handler='portal.credential.revoke';f.plan.steps[1].metadata={consumerId:consumer,retireConsumer:true};
    f.kong.request.mockImplementation(async(cid:string,method:string,path:string,_body:any,query:any)=>{
      assertKongPath(method as any,path);
      if(path.startsWith(`/consumers/${consumer}/`))return{data:[],next:null};
      if(path==='/plugins')return query.offset?{data:[{id:randomUUID(),consumer:{id:randomUUID()},route:{id:randomUUID()}}],next:null}:{data:[{id:randomUUID(),consumer:null}],next:'/plugins?size=100&offset=later'};
      return original(cid,method,path);
    });
    const snapshot=await(f.engine as any).snapshot(f.plan,randomUUID(),f.actor);
    expect(snapshot.objects).toHaveLength(2);expect(f.kong.request.mock.calls.filter((call:any[])=>call[2]==='/plugins').map((call:any[])=>call[4])).toEqual([{size:100},{size:100,offset:'later'}]);
    expect(f.execution.runInternalRead.mock.calls[0][3].paths).toContain('/plugins');
    expect(f.kong.request.mock.calls.some((call:any[])=>call[2]===`/consumers/${consumer}/plugins`)).toBe(false);
    expect(()=>assertKongPath('GET',`/consumers/${consumer}/plugins`)).toThrow();expect(f.entities.create).not.toHaveBeenCalled();
  });
  it.each(['consumer-only','route-consumer','service-route-consumer'])('blocks an unlisted %s plugin on a later global page before any retirement mutation',async(scope)=>{
    const f=fixture(),consumer=randomUUID(),original=f.kong.request.getMockImplementation()!;
    f.plan.steps[1].handler='portal.credential.revoke';f.plan.steps[1].metadata={consumerId:consumer,retireConsumer:true};
    const plugin={id:randomUUID(),consumer:{id:consumer},...(scope==='consumer-only'?{}:{route:{id:randomUUID()}}),...(scope==='service-route-consumer'?{service:{id:randomUUID()}}:{})};
    f.kong.request.mockImplementation(async(cid:string,method:string,path:string,_body:any,query:any)=>{
      assertKongPath(method as any,path);if(path.startsWith(`/consumers/${consumer}/`))return{data:[],next:null};
      if(path==='/plugins')return query.offset?{data:[plugin],next:null}:{data:[],next:'/plugins?offset=later'};return original(cid,method,path);
    });
    await expect((f.engine as any).snapshot(f.plan,randomUUID(),f.actor)).rejects.toMatchObject({response:{code:'PORTAL_RETIREMENT_UNLISTED_CHILDREN'}});
    expect(f.entities.create).not.toHaveBeenCalled();expect(f.handler.apply).not.toHaveBeenCalled();
  });
  it('fails closed when a complete Consumer-plugin absence proof exceeds ten global pages',async()=>{
    const f=fixture(),consumer=randomUUID(),original=f.kong.request.getMockImplementation()!;let page=0;
    f.plan.steps[1].handler='portal.credential.revoke';f.plan.steps[1].metadata={consumerId:consumer,retireConsumer:true};
    f.kong.request.mockImplementation(async(cid:string,method:string,path:string)=>{
      assertKongPath(method as any,path);if(path.startsWith(`/consumers/${consumer}/`))return{data:[],next:null};
      if(path==='/plugins')return{data:[],next:`/plugins?offset=page-${++page}`};return original(cid,method,path);
    });
    await expect((f.engine as any).snapshot(f.plan,randomUUID(),f.actor)).rejects.toMatchObject({response:{code:'WORKFLOW_SNAPSHOT_BUDGET'}});
    expect(f.kong.request.mock.calls.filter((call:any[])=>call[2]==='/plugins')).toHaveLength(10);expect(f.entities.create).not.toHaveBeenCalled();expect(f.handler.apply).not.toHaveBeenCalled();
  });
  it('cancellation records original key durably and can be replayed without additional writes',async()=>{const f=fixture(),actor={...f.actor,idempotencyKey:'cancel-original-key'},body={revision:1,confirmed:true,confirm_name:f.row.kind};const result=await f.engine.cancel(f.cid,f.workflowId,body,actor);expect(result.entity.state).toBe('cancelled');expect(result.decisionCompleted).toBe(true);const calls=f.db.exec.mock.calls.length;await f.engine.cancel(f.cid,f.workflowId,body,actor);expect(f.db.exec).toHaveBeenCalledTimes(calls);const receipt=await f.engine.receiptByKey(f.cid,actor.idempotencyKey,actor);expect(receipt).toMatchObject({action:'cancel',decisionCompleted:true,state:'cancelled',idempotencyKey:actor.idempotencyKey});expect(f.entities.create).not.toHaveBeenCalled();});
  it('same cancellation key with changed body cannot replay a completed decision',async()=>{const f=fixture(),actor={...f.actor,idempotencyKey:'cancel-original-key'},body={revision:1,confirmed:true,confirm_name:f.row.kind};await f.engine.cancel(f.cid,f.workflowId,body,actor);await expect(f.engine.cancel(f.cid,f.workflowId,{...body,revision:2},actor)).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});});

});
