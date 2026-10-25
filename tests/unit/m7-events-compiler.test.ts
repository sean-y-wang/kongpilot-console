import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConflictException, ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { EventsCompilerService } from '../../apps/console-api/src/modules/events/events-compiler.service';
import { EventsService } from '../../apps/console-api/src/modules/events/events.service';
import { validateWorkflowPlan } from '../../apps/console-api/src/modules/workflows/workflow-validation';
import type { WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Actual compiler/reader; authorization, DNS policy, transport and SQL are
 * explicit isolated doubles. This does not certify PostgreSQL constraints. */
function fixture(mode:'direct'|'approval'='direct') {
  const secrets=new SecretService(),cid=randomUUID(),wid=randomUUID(),actor={user:{id:randomUUID(),username:'events-owner',superAdmin:false},workspaceId:wid,idempotencyKey:'events-original-key',requestId:randomUUID(),ip:'192.0.2.17'};
  let revoked=false,permission='v1';const operations=new Map<string,any>(),workflows=new Map<string,any>(),plansById=new Map<string,WorkflowPlanV1>(),rows=new Map<string,any>();
  const db:any={one:vi.fn(async(sql:string,p:any[])=>{
    if(sql.includes('FROM iam_operations'))return [...operations.values()].find(r=>sql.includes('actor_id=$1')?r.actor_id===p[0]&&r.idempotency_key===p[1]:r.id===p[0])??null;
    if(sql.includes('FROM clusters'))return {...cluster};
    if(sql.includes('FROM workspaces'))return {...workspace};
    if(sql.includes('FROM workflow_steps'))return{state:'pending',safe_result:{}};return null;
  }),query:vi.fn(async(sql:string,p:any[])=>sql.includes('FROM workflows')?[...workflows.values()].filter(r=>r.requester_user_id===p[0]&&r.idempotency_key===p[1]):[]),transaction:vi.fn(async(fn:any)=>fn(db)),exec:vi.fn().mockResolvedValue(1)};
  const authz:any={assertWholeWorkspace:vi.fn(async()=>{if(revoked)throw new ForbiddenException();}),assertCluster:vi.fn(),permissionVersion:vi.fn(async()=>permission),hasWholeWorkspace:vi.fn().mockResolvedValue(true)};
  const cluster={admin_url:'http://kong:8001',transport_scope:'d'.repeat(64),revision:2,execution_mode:mode,version:'1.5.1',status:'healthy'},workspace={id:wid,status:'active',revision:1};
  const resolver:any={get:vi.fn(async()=>({...workspace}))},redis:any={withLock:vi.fn(async(_name:string,fn:any)=>fn()),assertLeaseOwnership:vi.fn()};
  const validated={type:'webhook' as const,endpoint:{url:'https://receiver.example.test/hook'},auth:{type:'none' as const},optionsSafe:{},safeSummary:{destinationHost:'receiver.example.test',maskedDestination:'https://receiver.example.test/***',authConfigured:false}};
  const policy:any={validateChannelConfig:vi.fn(async()=>validated),describeProviders:vi.fn(()=>[])};
  const metadata:any={row:vi.fn(async(_handler:string,_cid:string,_wid:string,id:string)=>rows.get(id)??null),material:vi.fn(()=>validated),
    reserve:vi.fn(async(handler:string,_cid:string,_wid:string,id:string,payload:any,_actor:any,workflowId:string)=>{const row={id,cluster_id:cid,workspace_id:wid,name:payload.name,type:payload.type,status:'pending',revision:1,credential_generation:1,endpoint_secret:null,auth_secret:null,options_safe:{},workflow_id:workflowId};rows.set(id,row);return row;}),
    applyDirect:vi.fn(async(_handler:string,_cid:string,_wid:string,id:string)=>({entity:{id,clusterId:cid,workspaceId:wid,name:'channel',revision:1,configured:true,capabilities:{write:true,delete:true,restore:false,test:true}}}))};
  const iam:any={execute:vi.fn(async(context:any,fn:any)=>{const id=randomUUID(),row={id,actor_id:actor.user.id,idempotency_key:actor.idempotencyKey,module:'events',action:context.action,cluster_id:cid,workspace_id:wid,payload_secret:secrets.encrypt(context.payload,`iam:${id}:payload`),request_hash:secrets.fingerprint(context),state:'running',remote_completed:false};operations.set(id,row);const result=await fn(db,id,vi.fn());Object.assign(row,{state:'succeeded',remote_completed:true,result_secret:secrets.encrypt(result,`iam:${id}:result`)});return result;})};
  const plans:any={definitions:vi.fn(),definition:vi.fn(async()=>({id:randomUUID(),version:1,policyHash:'a'.repeat(64)})),
    persist:vi.fn(async(plan:WorkflowPlanV1,key:string)=>{validateWorkflowPlan(plan);plansById.set(plan.workflowId,plan);const row={id:plan.workflowId,kind:'event-metadata',cluster_id:cid,workspace_id:wid,requester_user_id:actor.user.id,idempotency_key:key,plan_hash:secrets.fingerprint(plan),plan_revision:1,revision:1,state:'pending',execution_mode:'approval',created_at:new Date().toISOString(),expires_at:plan.expiresAt};workflows.set(row.id,row);return row;}),
    load:vi.fn(async(_cid:string,_wid:string,id:string)=>({row:workflows.get(id),plan:plansById.get(id)}))};
  const compiler=new EventsCompilerService(db,redis,secrets,authz,iam,resolver,policy,metadata,plans);
  return{compiler,db,redis,secrets,cid,wid,actor,operations,workflows,rows,policy,metadata,iam,authz,resolver,plans,validated,cluster,workspace,revoke:()=>{revoked=true;permission='v2';}};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','e7'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
describe('M7 actual shared event compiler, old keys and current authority',()=>{
  const create={name:'payments',type:'webhook',endpoint:'https://receiver.example.test/hook',auth:{type:'none'}};
  it('direct creates once inside IAM and same key/body returns original result without DNS or reallocation',async()=>{
    const f=fixture(),one=await f.compiler.channel(f.cid,undefined,create,f.actor),two=await f.compiler.channel(f.cid,undefined,create,f.actor);
    expect(two).toEqual(one);expect(f.iam.execute).toHaveBeenCalledOnce();expect(f.policy.validateChannelConfig).toHaveBeenCalledOnce();expect(f.metadata.reserve).not.toHaveBeenCalled();expect(one).toMatchObject({domain:'iam',configurationCommitted:true,queued:false,deliverySucceeded:false});
  });
  it.each(['changed-body','different-target','different-scope'])('rejects %s raw-key reuse before DNS/CAS',async(kind)=>{
    const f=fixture();await f.compiler.channel(f.cid,undefined,create,f.actor);
    await expect(kind==='different-target'?f.compiler.channel(f.cid,randomUUID(),{revision:9,status:'disabled'},f.actor):f.compiler.channel(f.cid,undefined,kind==='changed-body'?{...create,name:'other'}:create,kind==='different-scope'?{...f.actor,workspaceId:randomUUID()}:f.actor)).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});
    expect(f.policy.validateChannelConfig).toHaveBeenCalledOnce();expect(f.iam.execute).toHaveBeenCalledOnce();
  });
  it('old uncertain receipt never reruns its callback, even when the current mode changed',async()=>{
    const f=fixture();await f.compiler.channel(f.cid,undefined,create,f.actor);const row=[...f.operations.values()][0];row.state='uncertain';row.remote_completed=false;
    const receipt=await f.compiler.channel(f.cid,undefined,create,f.actor);expect(receipt).toMatchObject({state:'uncertain',configurationCommitted:false});expect(f.iam.execute).toHaveBeenCalledOnce();expect(f.policy.validateChannelConfig).toHaveBeenCalledOnce();
  });
  it('rechecks real whole-workspace grant after DNS await and does not reserve or call IAM after revocation',async()=>{
    const f=fixture();f.policy.validateChannelConfig.mockImplementation(async()=>{f.revoke();return f.validated;});await expect(f.compiler.channel(f.cid,undefined,create,f.actor)).rejects.toBeInstanceOf(ForbiddenException);expect(f.iam.execute).not.toHaveBeenCalled();expect(f.metadata.reserve).not.toHaveBeenCalled();
  });
  it.each(['mode','cluster-revision','disabled-workspace'])('rejects %s change during DNS before IAM or inert reservation',async(kind)=>{
    const f=fixture();f.policy.validateChannelConfig.mockImplementation(async()=>{if(kind==='mode')f.cluster.execution_mode='approval';if(kind==='cluster-revision')f.cluster.revision++;if(kind==='disabled-workspace')f.workspace.status='disabled';return f.validated;});
    await expect(f.compiler.channel(f.cid,undefined,create,f.actor)).rejects.toMatchObject({response:{code:'EVENT_SCOPE_CHANGED'}});expect(f.iam.execute).not.toHaveBeenCalled();expect(f.metadata.reserve).not.toHaveBeenCalled();
  });
  it('new target rejects implicit transplantation of old host auth before destination validation',async()=>{
    const f=fixture(),id=randomUUID();f.rows.set(id,{id,revision:2,type:'webhook',status:'active'});
    await expect(f.compiler.channel(f.cid,id,{revision:2,endpoint:'https://other.example.test/new'},f.actor)).rejects.toMatchObject({response:{code:'EVENT_NEW_TARGET_AUTH_REQUIRED'}});expect(f.policy.validateChannelConfig).not.toHaveBeenCalled();
  });
  it('approval creates an inert secret-free reservation and exact one-step sealed plan, never ordinary IAM',async()=>{
    const f=fixture('approval'),receipt=await f.compiler.channel(f.cid,undefined,create,f.actor),plan=f.plans.persist.mock.calls[0][0];
    expect(receipt).toMatchObject({domain:'workflow',submissionCompleted:true,configurationCommitted:false,executionCompleted:false});expect(f.iam.execute).not.toHaveBeenCalled();expect(f.metadata.applyDirect).not.toHaveBeenCalled();
    expect(plan).toMatchObject({kind:'event-metadata',executionMode:'approval',approvalRequired:true,prerequisites:[]});expect(f.plans.persist.mock.calls[0][4]).toEqual({requestId:f.actor.requestId,ip:f.actor.ip});expect(plan.steps).toHaveLength(1);expect(plan.steps[0].nativeRequests).toEqual([]);expect(plan.steps[0].before).toMatchObject({status:'pending',endpoint_secret:null,auth_secret:null});expect(JSON.stringify(plan.steps[0].before)).not.toContain('receiver.example');
    expect(receipt.entity?.capabilities).toMatchObject({approve:false,execute:false});
  });
  it('write-only original submitter can retrieve submission proof without workflows.read/write',async()=>{
    const f=fixture('approval');await f.compiler.channel(f.cid,undefined,create,f.actor);f.authz.assertCluster.mockRejectedValue(new ForbiddenException());f.authz.hasWholeWorkspace.mockImplementation(async(_u:any,_c:any,_w:any,_m:any,action:string)=>action!=='read');
    const receipt=await f.compiler.receipt(f.cid,f.actor.idempotencyKey,f.actor);expect(receipt.submissionCompleted).toBe(true);expect(f.authz.assertCluster).not.toHaveBeenCalled();expect(JSON.stringify(receipt)).not.toContain('receiver.example.test');expect(receipt).not.toHaveProperty('plan');
  });
  it('read-only current grant can verify its own original result but receives no cached write controls',async()=>{
    const f=fixture();await f.compiler.channel(f.cid,undefined,create,f.actor);f.authz.assertWholeWorkspace.mockRejectedValue(new ForbiddenException());f.authz.hasWholeWorkspace.mockResolvedValue(true);
    const proof=await f.compiler.receipt(f.cid,f.actor.idempotencyKey,f.actor);expect(proof.configurationCommitted).toBe(true);expect(proof.result?.entity?.capabilities).toEqual({write:false,delete:false,restore:false,test:false});
  });
  it('subscription filters do not grant entity reads and reject reserved workspace selectors',async()=>{
    const f=fixture(),channelId=randomUUID();f.rows.set(channelId,{id:channelId,status:'active'});
    await expect(f.compiler.subscription(f.cid,undefined,{name:'restricted',channelId,eventTypes:['entity.updated'],nativeType:'services',nativeIds:[randomUUID()],tags:['workspace:other']},f.actor)).rejects.toThrow();expect(f.iam.execute).not.toHaveBeenCalled();
  });
  it('shared directory requires complete workspace permission even when coarse cluster grant succeeds',async()=>{
    const f=fixture();f.authz.assertWholeWorkspace.mockRejectedValue(new ForbiddenException());const reads=new EventsService(f.db,f.secrets,f.authz,f.resolver,f.policy,f.metadata,{} as any,{} as any);
    await expect(reads.directory('channels',f.cid,{workspaceId:f.wid},f.actor)).rejects.toBeInstanceOf(ForbiddenException);expect(f.db.query).not.toHaveBeenCalled();
  });
});
