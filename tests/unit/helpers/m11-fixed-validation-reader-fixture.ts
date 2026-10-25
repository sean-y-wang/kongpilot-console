import 'reflect-metadata';
import {expect,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException,HttpException} from '@nestjs/common';
import {KongExecutionContextService} from '../../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {KongService} from '../../../apps/console-api/src/infrastructure/kong/kong.service';
import {outboundJson} from '../../../apps/console-api/src/infrastructure/kong/outbound';
import {WorkflowBusinessRuntimeService} from '../../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import {WorkflowBusinessScopedReadService} from '../../../apps/console-api/src/modules/workflows/workflow-business-scoped-read.service';
import {entityForPath} from '../../../apps/console-api/src/infrastructure/kong/policy';
import {candidateAbsenceFixture,validationAbsenceFixture} from './workflow-scheduled-read-absence-fixture';
vi.mock('../../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn()}));
const outbound=vi.mocked(outboundJson),code=(value:string)=>({response:{code:value}});

/** Root readResources/withLiveReads, actual SDK/Context and genuine provider
 * WeakMaps. SQL, Namespace issuance and outbound transport are controlled
 * Source fixtures. No runtime HTTP/SQL, native permits, fake browser identity,
 * business writes or claims of production execution are made by this suite. */
export function fixedValidationFixture(installFixed = true){
  const kind = 'validation' as const;
  const f:any=kind==='candidate'?candidateAbsenceFixture():validationAbsenceFixture(),context=new KongExecutionContextService();
  f.values.domain='scoped-points-v1';f.values.pointGrant=true;f.values.childGrant=true;
  const business=kind==='candidate'?f.policies:f.business;
  business.resolveReadScope.mockImplementation(async()=>({version:1,domain:f.values.domain,resources:f.values.resources,
    limits:{maxCalls:20,maxPages:10,maxRecords:20,maxBytes:8192}}));
  business.authorizeResponse.mockImplementation(async(input:any)=>{
    if(!f.values.read||f.values.scopeChanged)throw new ForbiddenException({code:'CURRENT_FIXED_OBJECT_SCOPE_DENIED'});
    if(input.status===404&&!f.values.pointGrant)throw new ForbiddenException({code:'CURRENT_COMPILED_CREATE_SCOPE_DENIED'});
  });
  const generic=vi.fn(async()=>{throw Error('ORDINARY_HTTP_POLICY_MUST_NOT_BE_BORROWED');});
  context.installPolicy({authorizeRequest:generic,authorizeResponse:generic});f.redis.rateLimit=vi.fn(async()=>({allowed:true}));
  const kong=new KongService(f.db,f.redis,f.secrets,{} as any,context);
  context.installScheduledReadAbsentTransportObserver({verifyTransport:(ticket,proof)=>kong.verifyScheduledReadAbsentTransport(ticket,proof)});
  f.service.installAbsentResponseVerifier({verifyOriginalResponse:(token,observation)=>context.verifyScheduledReadAbsentObservation(token,observation)});
  const acceptedRequests:any[]=[];
  const provider={verifyHandle:f.service.verifyHandle.bind(f.service),assertLive:f.service.assertLive.bind(f.service),
    authorizeRequest:async(handle:object,request:any)=>{const token=await f.service.authorizeRequest(handle,request);acceptedRequests.push(request);return token;},
    verifyRequest:f.service.verifyRequest.bind(f.service),authorizeResponse:f.service.authorizeResponse.bind(f.service)};
  if(kind==='candidate'){
    context.installWorkflowScheduleCandidateReadPolicy(provider);
    f.runner.assertNoFrame.mockImplementation(()=>{if(context.peek())throw Error('GENUINE_EMPTY_CONTEXT_REQUIRED');});
    f.runner.run.mockImplementation((handle:object,fn:()=>Promise<unknown>)=>context.runWorkflowScheduleCandidateRead(handle,fn));
  }else{
    const live=(handle:object)=>{if(handle!==f.nsHandle||!f.values.live||!f.state.lease)throw Error('SOURCE_ORIGINAL_NAMESPACE_LEASE_REQUIRED');};
    context.installWorkflowScheduledNamespacePolicy({verifyHandle:async handle=>{live(handle);return f.ns;},assertLive:live});
    context.installWorkflowScheduledValidationReadPolicy(provider);
    f.runner.originalNamespaceProof.mockImplementation((handle:object)=>context.requireWorkflowScheduledCurrentPrincipal(handle).namespace);
    f.runner.assertNamespaceLive.mockImplementation(live);
    f.runner.run.mockImplementation((handle:object,namespace:object,fn:()=>Promise<unknown>)=>context.runWorkflowScheduledValidationRead(handle,namespace,fn));
  }
  const parentPolicy={assertChild:vi.fn(async(input:any,child:any,parent:any)=>{
    if(!f.values.childGrant)throw new ForbiddenException({code:'CURRENT_COMPILED_FK_CHILD_DENIED'});
    expect(input.transaction).toBe(f.db);expect(input.principal.user.id).toBe(context.current().actor?.id);
    expect(child.parentId).toBe(parent.entityId);expect(child.workspaceId).toBe(parent.workspaceId);
  })};
  f.service.installParentAbsencePolicy(parentPolicy);f.install();
  const material:any={currentReadInput:vi.fn(async(plan:any,draft:any,userId:string,role:string,tx:any)=>{
    const row=await tx.one("SELECT * FROM users WHERE id=$1 AND status='active'",[userId]),iam=await tx.one('SELECT version FROM iam_epoch WHERE singleton=true');
    if(!row||!iam)throw new ForbiddenException({code:'CURRENT_SQL_PRINCIPAL_REQUIRED'});
    return{plan,draft,role,transaction:tx,principal:{user:{id:row.id,username:row.username,superAdmin:row.super_admin===true},
      credentialEpoch:String(row.credential_epoch),permissionVersion:`${row.id}:${row.permissions_epoch}:${iam.version}`,
      grants:await tx.query('SELECT * FROM iam_effective_grants WHERE user_id=$1',[userId])}};
  }),resolveAbsenceReadScope:vi.fn(async()=>business.resolveReadScope()),runResponseScope:vi.fn((fn:()=>Promise<unknown>)=>fn()),
    assertCurrentReadGrants:vi.fn(async()=>{if(!f.values.read)throw Error('CURRENT_SOURCE_READ_GRANTS_REQUIRED');})};
  // No bootstrap here: real providers already have their once-only original
  // Context bridges above. This exercises Root's exact read orchestration.
  const runtime:any=new WorkflowBusinessRuntimeService(f.db,f.redis,f.secrets,context,kong,{} as any,f.plans,{} as any,{} as any,
    f.repository,{} as any,{} as any,kind==='candidate'?f.service:{} as any,kind==='validation'?f.service:{} as any,{} as any,
    material,{} as any,{} as any,{} as any,{} as any,new WorkflowBusinessScopedReadService());
  outbound.mockImplementation(async(_base,path,method,_body,_query,_auth,_timeout,beforeSend,prepareSend)=>{
    if(method!=='GET')throw Error('SOURCE_FIXTURE_MUST_NOT_SEND_NATIVE');await prepareSend?.();beforeSend?.();
    const r=f.values.resources.find((r:any)=>r.path===path),body=r?.kind==='collection'?{data:[],next:null}:r?.kind==='schema'?{fields:[],workspace:context.current().workspaceId}:
      f.values.present?.has(path)?{id:r.entityId}: {message:'Not found'};
    return{status:r?.kind==='point'&&!f.values.present?.has(path)?404:200,body,bytes:20,jsonParsed:true};
  });
  const run=(fn:(handle:object)=>Promise<unknown>,userId=f.owner,role:'executor'|'reviewer'='executor')=>kind==='candidate'
    ?f.service.runOriginalPlan(f.plan,userId,role,fn,f.db)
    :context.runWorkflowScheduledNamespace(f.nsHandle,()=>f.service.runValidationResources(f.nsHandle,f.cid,f.values.resources[0].workspaceId,f.values.resources,f.db,fn,{role,userId}));
  const rootRead=(handle:object,resources=f.values.resources,observations=new Map())=>runtime.readResources(resources,observations,
    {handle,domain:f.values.domain,provider:f.service}).then((inferred:number)=>({observations,inferred}));
  const liveRead=(fn:any,userId=f.owner,role:'executor'|'reviewer'='executor')=>context.runWorkflowScheduledNamespace(f.nsHandle,
    ()=>runtime.withLiveReads(f.nsHandle,f.plan.workflowId,userId,role,f.db,fn));
  if(installFixed && typeof runtime.installFixedValidationReader === 'function')runtime.installFixedValidationReader();
  return{...f,context,kong,generic,business,parentPolicy,material,runtime,run,rootRead,liveRead,acceptedRequests,outbound};
}
export function fixedParentChild(f:ReturnType<typeof fixedValidationFixture>,childKind='key-auth',workspaceId=f.wid){
  const parentType=childKind==='targets'?'upstreams':'consumers',parentId=randomUUID(),childId=randomUUID();
  const parent:any={clusterId:f.cid,workspaceId,path:`/${parentType}/${parentId}`,kind:'point',entityType:parentType,
    entityId:parentId,secrets:false,required:true,allowAbsent:true};
  const path=`/${parentType}/${parentId}/${childKind}/${childId}`,child:any={clusterId:f.cid,workspaceId,path,kind:'point',entityType:entityForPath(path),
    entityId:childId,parentId,secrets:childKind!=='targets'&&childKind!=='acls',required:true,allowAbsent:true};
  f.values.resources=[parent,child];return{parent,child};
}
export function fixedSourceWorkspaces(f:ReturnType<typeof fixedValidationFixture>){
  const allowed=new Set(f.values.resources.map((r:any)=>r.workspaceId)),original=f.db.one.getMockImplementation()!;
  f.db.one.mockImplementation(async(sql:string,args:any[])=>{
    const row=await original(sql,args);
    if(sql.includes('FROM workspaces'))return row&&allowed.has(args[0])?{...row,id:args[0],cluster_id:args[1]}:null;
    return row;
  });
}
