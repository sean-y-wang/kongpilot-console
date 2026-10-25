import 'reflect-metadata';
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { transportScopeFor } from '../../apps/console-api/src/infrastructure/kong/transport-scope';
import { WorkflowBusinessRuntimeService } from '../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import type { WorkflowScheduledValidationFixedReader } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-validation-read.types';
import { WorkflowBusinessScopedReadService } from '../../apps/console-api/src/modules/workflows/workflow-business-scoped-read.service';
import { grantMatchesEntity } from '../../apps/console-api/src/modules/authorization/grant-policy';

beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','e7'.repeat(32)));
afterEach(()=>vi.unstubAllEnvs());

/** Real Root assembly, Context and private original WeakMap read policies.
 * SQL/material providers and SDK transport are in-memory fixtures. Provider
 * logs report actual Context principals/roles/queries, never real runtime SQL
 * or Native sends. No prototype or private Context state is altered. */
function fixture(portal=false){
  const context=new KongExecutionContextService(),secrets=new SecretService(),cid=randomUUID(),sourceCid=randomUUID(),wid=randomUUID(),wf=randomUUID();
  const actor:any=Object.freeze({id:randomUUID(),username:'executor',superAdmin:true}),reviewer:any=Object.freeze({id:randomUUID(),username:'reviewer',superAdmin:false});
  const namespaceHandle=Object.freeze({}),authorityHandle=Object.freeze({}),expiry=new Date(Date.now()+60000).toISOString();
  const consumerId=randomUUID(),aclId=randomUUID(),keyId=randomUUID(),serviceId=randomUUID(),scope=transportScopeFor('http://target-kong:8001');
  const native=(order:number,type:string,id:string,path:string,parentId?:string):any=>({id:randomUUID(),order,kind:'native',entityType:type,parentId,mutationAction:'create',
    beforeFingerprint:secrets.fingerprint(null),mutationPayloadHmac:secrets.fingerprint({id}),nativeRequests:[{method:'POST',canonicalPath:path,nativeType:type,nativeId:id,parentId,body:{id},bodyHmac:secrets.fingerprint({id})}]});
  const steps=portal?[native(1,'consumers',consumerId,'/consumers'),native(2,'credentials',aclId,`/consumers/${consumerId}/acls`,consumerId),
    native(3,'credentials',keyId,`/consumers/${consumerId}/key-auth`,consumerId),{id:randomUUID(),order:4,kind:'metadata',metadata:{credentialId:randomUUID(),consumerId,kongId:keyId,keyFingerprint:'a'.repeat(64)},nativeRequests:[]}]
    :[{id:randomUUID(),order:1,kind:'metadata',nativeRequests:[],metadata:{jobId:randomUUID(),planId:randomUUID(),planRevision:1,planHash:'b'.repeat(64)}}];
  const plan:any={version:1,clusterId:cid,workspaceId:wid,workflowId:wf,planRevision:1,kind:portal?'portal-credential-issue':'configuration_v2',
    requester:{type:portal?'developer':'console',id:portal?randomUUID():actor.id},scope:{transportScope:scope},subject:{id:randomUUID()},prerequisites:[],steps,
    scheduling:{scheduleId:randomUUID(),executorId:actor.id}};
  const claim:any={id:randomUUID(),scheduleId:plan.scheduling.scheduleId};
  const ns:any=Object.freeze({version:1,origin:'scheduled-workflow',sessionId:null,actor,clusterId:cid,workspaceId:wid,kind:plan.kind,permissionVersion:'current-epoch',
    credentialEpoch:'1',expiresAt:expiry,workflow:{id:wf,planRevision:1,planHash:secrets.fingerprint(plan)},claim,approvalSet:{format:2,reviewers:[{userId:reviewer.id}]}});
  const resources:any[]=[{clusterId:cid,workspaceId:wid,path:'/services',kind:'collection',entityType:'services',required:true,secrets:false,query:{size:100}},
    {clusterId:sourceCid,workspaceId:wid,path:'/routes',kind:'collection',entityType:'routes',required:true,secrets:false,query:{size:100}},
    {clusterId:cid,workspaceId:wid,path:'/consumers',kind:'collection',entityType:'consumers',required:true,secrets:false,query:{size:100}},
    {clusterId:cid,workspaceId:wid,path:`/services/${serviceId}`,kind:'point',entityType:'services',entityId:serviceId,required:true,secrets:false}];
  if(portal)resources.push({clusterId:cid,workspaceId:wid,path:`/consumers/${consumerId}`,kind:'point',entityType:'consumers',entityId:consumerId,required:false,secrets:false},
    {clusterId:cid,workspaceId:wid,path:`/consumers/${consumerId}/acls/${aclId}`,kind:'point',entityType:'credentials',entityId:aclId,parentId:consumerId,required:false,secrets:true},
    {clusterId:cid,workspaceId:wid,path:`/consumers/${consumerId}/key-auth/${keyId}`,kind:'point',entityType:'credentials',entityId:keyId,parentId:consumerId,required:false,secrets:true});
  const state={live:true,reviewerLive:true,missingEof:false,parentPresent:false,foreignWorkflow:false,terminal:'succeeded',nestedState:'succeeded',queryCalls:[] as any[],providerCalls:[] as any[],coreFn:undefined as undefined|(()=>Promise<any>),
    operationLease:false,operationSessionLive:true,operationPermissionVersion:'current-source-permissions',operationGrants:[] as any[],operationAfterGrant:undefined as undefined|(()=>Promise<void>)};
  const nsRegistry=new WeakMap<object,any>([[namespaceHandle,ns]]),authorities=new WeakMap<object,any>([[authorityHandle,{namespace:namespaceHandle,proof:ns}]]);
  const readRegistry=new WeakMap<object,any>(),tokens=new WeakMap<object,any>(),responseScope=new AsyncLocalStorage<boolean>();
  let contextRunner:any,executor:any,businessDelegate:any;
  const cluster=(id:string):any=>({id,admin_url:id===cid?'http://target-kong:8001':'http://source-kong:8001',version:'1.5.1',revision:1,execution_mode:'approval'});
  // Registration supplies no optimized capability, keeping this legacy
  // fixture on the original full runValidationResources path below.
  const validation:any={installStorageContract:vi.fn(),installBusinessPolicy:vi.fn(),installContextRunner:vi.fn(),installAbsentResponseVerifier:vi.fn(),installParentAbsencePolicy:vi.fn(),
    installFixedReader:vi.fn((_reader:WorkflowScheduledValidationFixedReader):undefined=>undefined),
    assertLive(h:object){if(!readRegistry.has(h)||!state.live)throw Error('ORIGINAL_VALIDATION_READ_REQUIRED');},
    async verifyHandle(h:object,n:object,p:any){const row=readRegistry.get(h);if(!row||n!==namespaceHandle||p!==ns||!state.live||row.proof.role==='reviewer'&&!state.reviewerLive)throw Error('CURRENT_ORIGINAL_VALIDATION_REQUIRED');return row.proof;},
    async authorizeRequest(h:object,req:any){const row=readRegistry.get(h);if(!row||req.method!=='GET'||!row.proof.scope.resources.some((r:any)=>r.clusterId===req.clusterId&&r.path===req.path))throw Error('FIXED_READ_RESOURCE_REQUIRED');
      const token=Object.freeze({});tokens.set(token,{row,req,h});state.providerCalls.push({phase:'request',role:row.proof.role,userId:context.current().actor?.id,clusterId:req.clusterId,path:req.path});return token;},
    async verifyRequest(token:object){const request=tokens.get(token);if(!request||!state.live||request.row.proof.role==='reviewer'&&!state.reviewerLive)throw Error('CURRENT_ORIGINAL_REQUEST_REQUIRED');return request.row.proof;},
    async authorizeResponse(token:object,value:any){const request=tokens.get(token);if(!request||!responseScope.getStore())throw Error('ORIGINAL_RESPONSE_SCOPE_REQUIRED');
      if(request.row.proof.role==='reviewer'&&!state.reviewerLive)throw Error('CURRENT_REVIEWER_READ_REVOKED');request.row.seen.add(request.req.path);
      state.providerCalls.push({phase:'response',role:request.row.proof.role,userId:context.current().actor?.id,clusterId:request.req.clusterId,path:request.req.path});return value;},
    async runValidationRead(n:object,selectedCid:string,paths:readonly string[],_tx:any,fn:any,options?:any){
      if(n!==namespaceHandle||!state.live)throw Error('ORIGINAL_NAMESPACE_REQUIRED');const role=options?.role??'executor',userId=options?.userId??actor.id;
      if(role==='executor'?userId!==actor.id:userId!==reviewer.id||!state.reviewerLive)throw Error('CURRENT_READ_PRINCIPAL_REQUIRED');
      const selected=resources.filter(r=>r.clusterId===selectedCid&&paths.includes(r.path)),reader=role==='reviewer'?reviewer:actor;
      if(selected.length!==paths.length)throw Error('SEALED_READ_SCOPE_REQUIRED');
      const proof=Object.freeze({version:1,origin:'workflow-scheduled-validation-read',readOnly:true,actor:reader,sessionId:null,role,namespace:ns,expiresAt:new Date(Date.now()+20000).toISOString(),
        scope:{version:1,resources:selected,limits:{maxCalls:500,maxPages:100,maxRecords:10000,maxBytes:33554432}},
        registries:[{clusterId:selectedCid,workspaceId:wid,transportScope:transportScopeFor(cluster(selectedCid).admin_url),clusterRevision:1,workspaceRevision:1,endpointHmac:'d'.repeat(64)}]});
      const handle=Object.freeze({}),row={proof,seen:new Set()};readRegistry.set(handle,row);state.providerCalls.push({phase:'open',role,userId,clusterId:selectedCid,paths:[...paths]});
      try{return await context.runWorkflowScheduledValidationRead(handle,n,async()=>{const result=await fn(handle);
        for(const r of selected)if(r.required!==false&&!row.seen.has(r.path))throw Error('ACTUAL_REQUIRED_READ_INCOMPLETE');return result;});}finally{readRegistry.delete(handle);}
    }};
  validation.runValidationResources=vi.fn(async(n:object,selectedCid:string,selectedWid:string,selected:any[],tx:any,fn:any,options?:any)=>{
    if(selectedWid!==wid||selected.some(r=>r.clusterId!==selectedCid||r.workspaceId!==selectedWid
      ||!resources.some(original=>secrets.fingerprint(original)===secrets.fingerprint(r))))throw Error('EXACT_CURRENT_READ_RESOURCES_REQUIRED');
    return validation.runValidationRead(n,selectedCid,selected.map(r=>r.path),tx,fn,options);
  });
  const kong:any={verifyScheduledReadAbsentTransport:vi.fn(()=>{throw Error('NO_ABSENCE_TRANSPORT_IN_THIS_TEST');}),request:vi.fn(async(id:string,method:string,path:string,_body?:any,query:any={})=>{
    if(method!=='GET')throw Error('NO_NATIVE_SEND_IN_SOURCE_TEST');state.queryCalls.push({clusterId:id,method,path,query:{...query},actorId:context.current().actor?.id});
    const ticket=await context.authorizeRequest(cluster(id),method,path,undefined,query);await context.beforeNativeSend(ticket);
    let value:any=path===`/services/${serviceId}`?{id:serviceId}:path.startsWith('/consumers/')?{id:path.split('/').at(-1)}
      :path==='/consumers'?{data:state.parentPresent?[{id:consumerId}]:[],next:null}:path==='/services'&&!query.offset?{data:[{id:serviceId}],next:'/services?offset=next-page'}:{data:[],next:null};
    if(state.missingEof&&path==='/services')value={data:[]};return context.authorizeResponse(ticket,value);
  })};
  const repository:any={inspectStored:vi.fn(async()=>({plan:state.foreignWorkflow?{...plan,workflowId:randomUUID()}:plan,draft:{},claim,progress:{claimId:claim.id}}))};
  const material:any={installScopedReadBridge:vi.fn(),authorizeScopedParentAbsence:vi.fn(async()=>{throw Error('NO_SCOPED_FK_ABSENCE_IN_FULL_SOURCE_FIXTURE');}),
    businessReadPolicy:vi.fn(()=>({})),materialForPlan:vi.fn(async()=>({kind:plan.kind,subjectSeal:{}})),configurationMaterial:vi.fn(),
    currentReadInput:vi.fn(async(p:any,draft:any,userId:string,role:string)=>{state.providerCalls.push({phase:'input',role,userId});return{plan:p,draft,role,principal:{user:userId===actor.id?actor:reviewer}};}),
    resolveAbsenceReadScope:vi.fn(async()=>({version:1,resources,limits:{maxCalls:500,maxPages:100,maxRecords:10000,maxBytes:33554432}})),
    runResponseScope:vi.fn(async(fn:any)=>{if(responseScope.getStore())throw Error('RECURSIVE_RESPONSE_SCOPE');return responseScope.run(true,fn);}),
    assertCurrentReadGrants:vi.fn(async(input:any)=>{if(input.role==='reviewer'&&!state.reviewerLive)throw Error('CURRENT_REVIEWER_READ_REVOKED');}),assertCurrent:vi.fn(),assertReadComplete:vi.fn(),assertExecutionReadBudget:vi.fn()};
  const namespaces:any={installContextRunner:vi.fn((runner:any)=>{contextRunner=runner;}),verifyHandle:async(h:object)=>{if(!nsRegistry.has(h)||!state.live)throw Error('ORIGINAL_NAMESPACE_REQUIRED');return ns;},assertLive(h:object){if(!nsRegistry.has(h)||!state.live)throw Error('ORIGINAL_NAMESPACE_REQUIRED');},
    runOriginalClaim:async(h:object,fn:any)=>{if(!authorities.has(h))throw Error('ORIGINAL_AUTHORITY_REQUIRED');contextRunner.assertNoFrame();return contextRunner.run(namespaceHandle,fn);}};
  const noCombinedCheckpoint=()=>{throw Error('RUNTIME_ASSEMBLY_FIXTURE_HAS_NO_COMBINED_AUTHORITY');};
  const closedCheckpoint=Object.freeze({openClosedCheckpoint:async()=>noCombinedCheckpoint(),assertClosedCheckpoint:async()=>noCombinedCheckpoint(),
    assertClosedCheckpointLive:noCombinedCheckpoint,releaseClosedCheckpoint:vi.fn()});
  const authority:any={installScheduledConfigurationOriginSqlVerifier:vi.fn(()=>closedCheckpoint),installRepositoryPolicies:vi.fn(),installBusinessPolicy:vi.fn(),installExecutor:vi.fn((e:any)=>{executor=e;}),verifyClaim:vi.fn(async(h:object)=>{if(!authorities.has(h))throw Error('ORIGINAL_AUTHORITY_REQUIRED');return{};})};
  const candidates:any={installStorageContract:vi.fn(),installContextRunner:vi.fn(),installBusinessPolicy:vi.fn(),installAbsentResponseVerifier:vi.fn(),installParentAbsencePolicy:vi.fn(),
    installFixedReader:vi.fn(()=>undefined),
    assertOriginalHttpAcceptance:vi.fn(async()=>{throw Error('NO_ORIGINAL_HTTP_CANDIDATE_IN_THIS_ASSEMBLY_FIXTURE');}),
    verifyHandle:vi.fn(),assertLive:vi.fn(),authorizeRequest:vi.fn(),authorizeResponse:vi.fn(),verifyRequest:vi.fn()};
  const configuration:any={installRootVerifier:vi.fn()},core={installWorkflowScheduledConfigurationOrigin:vi.fn()},origins={installWorkflowScheduledOrigin:vi.fn()};
  let runtime:any;
  const workflows:any={installBusinessScheduledDelegate:vi.fn((d:any)=>{businessDelegate=d;}),executeBusinessScheduledClaim:vi.fn(async()=>state.coreFn?state.coreFn():Object.freeze({})),
    verifyBusinessScheduledCompletion:vi.fn(async(h:object,_c:object,tx:any)=>businessDelegate.deriveCompletion(h,'execution',tx))};
  const row:any={id:'execution',workflow_id:wf,plan_revision:1,plan_hash:ns.workflow.planHash,permission_version:ns.permissionVersion,claim_id:claim.id,executor_id:actor.id,execution_actor_id:actor.id,completed_at:new Date().toISOString()};
  const db:any={one:vi.fn(async(sql:string)=>sql.includes('w.state AS workflow_state')?{...row,state:state.terminal,workflow_state:state.terminal}:null),
    query:vi.fn(async(sql:string)=>sql.includes('configuration_execution_origins')?[{state:state.nestedState,actor_id:actor.id,completed_at:new Date().toISOString()}]:steps.map(s=>({id:s.id,plan_hash:ns.workflow.planHash,state:state.terminal==='succeeded'?'succeeded':'failed'})))};
  const scopedReads=new WorkflowBusinessScopedReadService();
  const operationUser:any=Object.freeze({id:randomUUID(),username:'source-console-user',superAdmin:false}),operationSid=randomUUID();
  const operationPlan={...plan,requester:{type:'console',id:operationUser.id}},operationAcceptance={sessionId:operationSid,credentialEpoch:'1',permissionVersion:state.operationPermissionVersion};
  state.operationGrants=['read','write','approve'].map(action=>({user_id:operationUser.id,cluster_id:cid,workspace_id:wid,module:'workflows',action,scope_type:'global',scope_values:[]}));
  // The Source-only fixed subject adapter executes the actual grant matcher
  // against current in-memory session/permission/grant facts. It is not an
  // unconditional mock approval, SQL authentication or runtime IAM evidence.
  const approved:any={installWorkflowScheduledDelegate:vi.fn(),installWorkflowScheduledReviewerReadPolicy:vi.fn(),assertSubject:vi.fn(async(p:any,user:any,action:any,tx:any)=>{
    if(tx!==db||!state.operationSessionLive||context.current().sessionId!==operationSid||state.operationPermissionVersion!==operationAcceptance.permissionVersion)
      throw new ForbiddenException({code:'CURRENT_SOURCE_OPERATION_IDENTITY_REVOKED'});
    if(!state.operationGrants.some(g=>g.user_id===user.id&&grantMatchesEntity(g,'workflows',action,
      {clusterId:p.clusterId,workspaceId:p.workspaceId,entityType:'workflows',entity:{id:p.subject.id}})))throw new ForbiddenException({code:'CURRENT_SOURCE_OPERATION_GRANT_DENIED'});
    await state.operationAfterGrant?.();
  })};
  const operationRedis:any={assertLeaseOwnership:vi.fn(async()=>{if(!state.operationLease)throw new ServiceUnavailableException({code:'LOCK_CONTEXT_REQUIRED'});})};
  const schedules:any={installProposalPolicy:vi.fn(),installWorkflowOperationPolicy:vi.fn(),receiptReadActive:()=>false};
  runtime=new WorkflowBusinessRuntimeService(db,operationRedis,secrets,context,kong,{installWorkflowScheduledCurrentIdentityBridge:vi.fn()} as any,{load:async()=>({plan})} as any,workflows,approved,
    repository,authority,namespaces,candidates,validation,configuration,material,{currentPrincipal:vi.fn()} as any,
    schedules,{installFixedDelegate:vi.fn()} as any,{get:(type:any)=>type.name==='ConfigurationService'?core:origins} as any,
    scopedReads);
  runtime.onModuleInit();context.installPolicy({async authorizeRequest(){throw Error('ORDINARY_POLICY_MUST_NOT_BE_BORROWED');},async authorizeResponse(){throw Error('ORDINARY_POLICY_MUST_NOT_BE_BORROWED');}});
  const run=(fn:any)=>{state.coreFn=fn;return executor.executeClaim(authorityHandle,(original:object)=>{if(original!==namespaceHandle||context.requireWorkflowScheduledNamespaceHandle()!==original)throw Error('SOURCE_ORIGINAL_BUSINESS_BOUNDARY_REQUIRED');});};
  const assertOperation=schedules.installWorkflowOperationPolicy.mock.calls[0][0].assertOperation;
  const operationInput=(action:'read'|'write'|'approve',overrides:any={})=>({action,plan:operationPlan,actor:{user:operationUser,workspaceId:wid},acceptance:operationAcceptance,transaction:db,...overrides});
  const runOperation=(action:'read'|'write'|'approve',inputOverrides:any={},frameOverrides:any={})=>context.runHttp({},()=>{
    context.bindHttpActor(frameOverrides.actor??operationUser,frameOverrides.sessionId??operationSid);
    return context.runActor({actor:frameOverrides.actor??operationUser,clusterId:frameOverrides.clusterId??cid,workspaceId:frameOverrides.workspaceId??wid,module:'workflows',action},
      ()=>assertOperation(operationInput(action,inputOverrides)));
  });
  return{runtime,context,secrets,run,state,plan,claim,ns,cid,sourceCid,wid,wf,actor,reviewer,authorityHandle,namespaceHandle,resources,kong,material,repository,executor,workflows,businessDelegate,db,consumerId,aclId,keyId,validation,candidates,scopedReads,
    approved,operationRedis,schedules,operationUser,operationSid,operationPlan,operationAcceptance,assertOperation,operationInput,runOperation};
}

describe('Root actual business runtime preserves original readonly namespaces and EOF',()=>{
  it('installs the fixed scoped compiler and both original parent policies exactly once',async()=>{
    const f=fixture();f.runtime.onModuleInit();
    expect(f.material.installScopedReadBridge).toHaveBeenCalledOnce();expect(f.material.installScopedReadBridge).toHaveBeenCalledWith(f.scopedReads);
    expect(f.approved.installWorkflowScheduledReviewerReadPolicy).toHaveBeenCalledOnce();
    expect(f.candidates.installParentAbsencePolicy).toHaveBeenCalledOnce();expect(f.validation.installParentAbsencePolicy).toHaveBeenCalledOnce();
    const parent=f.candidates.installParentAbsencePolicy.mock.calls[0][0];expect(f.validation.installParentAbsencePolicy.mock.calls[0][0]).toBe(parent);
    await expect(parent.assertChild({controlled:'input'},{controlled:'child'},{controlled:'parent'})).rejects.toThrow('NO_SCOPED_FK_ABSENCE_IN_FULL_SOURCE_FIXTURE');
    expect(f.material.authorizeScopedParentAbsence).toHaveBeenCalledWith({controlled:'input'},{controlled:'child'},{controlled:'parent'});
    expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('uses each genuine selected reviewer/executor across two clusters and preserves the parent budgets',async()=>{
    const f=fixture();await f.run(async()=>{
      const values:any[]=[],usages:any[]=[];
      for(const [user,role]of [[f.actor,'executor'],[f.reviewer,'reviewer']]as const)await f.runtime.withLiveReads(f.namespaceHandle,f.wf,user.id,role,f.db,async(input:any,observations:Map<string,any>,usage:any)=>{
        expect(input.principal.user.id).toBe(user.id);expect(observations.size).toBe(4);expect(usage.calls).toBe(5);values.push(observations);usages.push(usage);
      });expect(f.context.currentUsage().calls).toBe(10);expect(usages[0].pages).toBe(4);expect(values[0]).not.toBe(values[1]);return Object.freeze({});
    });
    for(const role of ['executor','reviewer']){const user=role==='executor'?f.actor:f.reviewer;const calls=f.state.providerCalls.filter((c:any)=>c.phase==='request'&&c.role===role);
      expect(calls).toHaveLength(5);expect(calls.every((c:any)=>c.userId===user.id)).toBe(true);expect(new Set(calls.map((c:any)=>c.clusterId))).toEqual(new Set([f.cid,f.sourceCid]));}
    expect(f.kong.request.mock.calls.every(call=>call[1]==='GET')).toBe(true);
  });
  it('requires actual explicit EOF and does not accept omitted next as an empty collection',async()=>{
    const f=fixture();f.state.missingEof=true;
    await expect(f.run(()=>f.runtime.withLiveReads(f.namespaceHandle,f.wf,f.actor.id,'executor',f.db,async()=>undefined))).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_ACTUAL_EOF_REQUIRED'}});
  });
  it('a sealed absent Consumer collection EOF proves its future ACL/key parent without a fabricated nested 404',async()=>{
    const f=fixture(true);const snapshot=await f.run(()=>f.runtime.snapshot(f.authorityHandle,f.namespaceHandle,f.plan,'execution'));
    expect(snapshot.objects).toHaveLength(3);expect(snapshot.objects.every((o:any)=>o.absent===true&&o.before===null&&o.fingerprint===f.secrets.fingerprint(null))).toBe(true);
    expect(f.state.queryCalls.some(c=>c.path===`/consumers/${f.consumerId}/acls`||c.path===`/consumers/${f.consumerId}/key-auth`)).toBe(false);
  });
  it('refuses Portal readback from a namespace without the original approved Native step',async()=>{
    const f=fixture(true);f.state.parentPresent=true;
    // The current Portal path requires Core-issued step ancestry plus the
    // durable completed mutation receipt. This assembly-only fixture has
    // neither; successful readback is covered by the whole Portal Core suite.
    await expect(f.run(()=>f.runtime.nativeAfter(f.authorityHandle,f.namespaceHandle,f.plan,f.plan.steps[2],'execution')))
      .rejects.toMatchObject({response:{code:'APPROVED_STEP_REQUIRED'}});
    expect(f.state.queryCalls.some(c=>c.path===`/consumers/${f.consumerId}/key-auth/${f.keyId}`)).toBe(false);
  });
  it('rejects an already-present allocated Consumer and an absence without any real root EOF witness',async()=>{
    const present=fixture(true);present.state.parentPresent=true;await expect(present.run(()=>present.runtime.snapshot(present.authorityHandle,present.namespaceHandle,present.plan,'execution'))).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_SNAPSHOT_CHANGED'}});
    const missing=fixture(true);missing.resources.find(r=>r.path==='/consumers')!.required=false;
    await expect(missing.run(()=>missing.runtime.snapshot(missing.authorityHandle,missing.namespaceHandle,missing.plan,'execution'))).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_SNAPSHOT_ABSENCE_NOT_OBSERVED'}});
  });
  it('original claims and Namespace facts cannot be supplied by copied shape',async()=>{
    const f=fixture();await f.run(async()=>{
      await expect(f.runtime.snapshot({...f.authorityHandle},f.namespaceHandle,f.plan,'execution')).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_ORIGINAL_CLAIM_REQUIRED'}});
      await expect(f.runtime.snapshot(f.authorityHandle,{...f.namespaceHandle},f.plan,'execution')).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_ORIGINAL_CLAIM_REQUIRED'}});
      await expect(f.runtime.snapshot(f.authorityHandle,f.namespaceHandle,{...f.plan,workflowId:randomUUID()},'execution')).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_ORIGINAL_CLAIM_REQUIRED'}});
      return Object.freeze({});
    });
  });
  it('a live reviewer read does not borrow the executor authority after that reviewer is revoked',async()=>{
    const f=fixture();await f.run(async()=>{f.state.reviewerLive=false;
      await expect(f.runtime.withLiveReads(f.namespaceHandle,f.wf,f.reviewer.id,'reviewer',f.db,async()=>undefined)).rejects.toThrow('CURRENT_READ_PRINCIPAL_REQUIRED');return Object.freeze({});
    });expect(f.state.queryCalls).toEqual([]);
  });
  it('rejects stored foreign workflow before issuing any validation GET',async()=>{
    const f=fixture();f.state.foreignWorkflow=true;
    await expect(f.run(()=>f.runtime.withLiveReads(f.namespaceHandle,f.wf,f.actor.id,'executor',f.db,async()=>undefined))).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_PLAN_CHANGED'}});
    expect(f.kong.request).not.toHaveBeenCalled();
  });
  it('keeps the original completion claim for both independent Authority verification calls',async()=>{
    const f=fixture(),completion=await f.run(async()=>Object.freeze({}));
    await expect(f.executor.verifyCompletion(f.authorityHandle,completion,f.db)).resolves.toBe('succeeded');
    await expect(f.executor.verifyCompletion(f.authorityHandle,completion,f.db)).resolves.toBe('succeeded');
  });
  it('derives partial from known nested configuration effects rather than hiding them behind wrapper failure',async()=>{
    const f=fixture();f.state.terminal='failed';f.state.nestedState='succeeded';
    const completion=await f.run(async()=>Object.freeze({}));await expect(f.executor.verifyCompletion(f.authorityHandle,completion,f.db)).resolves.toBe('partial');
  });
});

describe('Root once-installed business operation callback read lock correction',()=>{
  it('admits a current granted readonly operation without a mutation lease',async()=>{
    const f=fixture();expect(f.state.operationLease).toBe(false);
    await expect(f.runOperation('read')).resolves.toBeUndefined();expect(f.operationRedis.assertLeaseOwnership).not.toHaveBeenCalled();
    expect(f.approved.assertSubject).toHaveBeenCalledWith(f.operationPlan,f.operationUser,'read',f.db);
    expect(f.kong.request).not.toHaveBeenCalled();expect(f.db.one).not.toHaveBeenCalled();expect(f.db.query).not.toHaveBeenCalled();
  });

  it.each(['write','approve'] as const)('requires an original mutation lease for %s after current subject grants',async action=>{
    const f=fixture();await expect(f.runOperation(action)).rejects.toMatchObject({status:503,response:{code:'LOCK_CONTEXT_REQUIRED'}});
    expect(f.approved.assertSubject).toHaveBeenCalledWith(f.operationPlan,f.operationUser,action,f.db);
    expect(f.operationRedis.assertLeaseOwnership).toHaveBeenCalledOnce();expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each(['write','approve'] as const)('retains the original lease and current grants for authorized %s',async action=>{
    const f=fixture();f.state.operationLease=true;await expect(f.runOperation(action)).resolves.toBeUndefined();
    expect(f.operationRedis.assertLeaseOwnership).toHaveBeenCalledOnce();expect(f.approved.assertSubject).toHaveBeenCalledOnce();
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each(['read','write','approve'] as const)('does not skip current %s subject grants when changing the read lease behavior',async action=>{
    const f=fixture();f.state.operationLease=true;f.state.operationGrants=[];
    await expect(f.runOperation(action)).rejects.toMatchObject({response:{code:'CURRENT_SOURCE_OPERATION_GRANT_DENIED'}});
    expect(f.approved.assertSubject).toHaveBeenCalledOnce();expect(f.operationRedis.assertLeaseOwnership).not.toHaveBeenCalled();
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each(['actor','session','cluster','workspace'] as const)('closes current frame %s mismatch before grant or lock adapters',async mismatch=>{
    const f=fixture();f.state.operationLease=true;const frame:any=mismatch==='actor'?{actor:{...f.operationUser,id:randomUUID()}}
      :mismatch==='session'?{sessionId:randomUUID()}:mismatch==='cluster'?{clusterId:randomUUID()}:{workspaceId:randomUUID()};
    await expect(f.runOperation('read',{},frame)).rejects.toMatchObject({response:{code:'WORKFLOW_BUSINESS_ORIGINAL_HTTP_PROPOSAL_REQUIRED'}});
    expect(f.approved.assertSubject).not.toHaveBeenCalled();expect(f.operationRedis.assertLeaseOwnership).not.toHaveBeenCalled();
    expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each(['read','write','approve'] as const)('retains current SID and permission facts for %s',async action=>{
    for(const reason of ['revoked-session','permission-version']){
      const f=fixture();f.state.operationLease=true;if(reason==='revoked-session')f.state.operationSessionLive=false;else f.state.operationPermissionVersion='revoked-source-permissions';
      await expect(f.runOperation(action)).rejects.toMatchObject({response:{code:'CURRENT_SOURCE_OPERATION_IDENTITY_REVOKED'}});
      expect(f.operationRedis.assertLeaseOwnership).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
    }
  });

  it('does not accept a foreign-workspace grant for the current operation',async()=>{
    const f=fixture();f.state.operationGrants=f.state.operationGrants.map(g=>({...g,workspace_id:randomUUID()}));
    await expect(f.runOperation('read')).rejects.toMatchObject({response:{code:'CURRENT_SOURCE_OPERATION_GRANT_DENIED'}});
    expect(f.operationRedis.assertLeaseOwnership).not.toHaveBeenCalled();
  });

  it('rechecks the original frame after the asynchronous subject verifier closes it',async()=>{
    const f=fixture();f.state.operationAfterGrant=async()=>{f.context.captureHttpCloser()();};
    await expect(f.runOperation('read')).rejects.toBeDefined();expect(f.approved.assertSubject).toHaveBeenCalledOnce();
    expect(f.operationRedis.assertLeaseOwnership).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('keeps one fixed installed callback and denies an absent original Context',async()=>{
    const f=fixture();f.runtime.onModuleInit();expect(f.schedules.installWorkflowOperationPolicy).toHaveBeenCalledOnce();
    await expect(f.assertOperation(f.operationInput('read'))).rejects.toBeDefined();expect(f.approved.assertSubject).not.toHaveBeenCalled();
  });
});
