import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException,HttpException} from '@nestjs/common';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
import {WorkflowBusinessRuntimeService} from '../../apps/console-api/src/modules/workflows/workflow-business-runtime.service';
import {WorkflowBusinessScopedReadService} from '../../apps/console-api/src/modules/workflows/workflow-business-scoped-read.service';
import {entityForPath} from '../../apps/console-api/src/infrastructure/kong/policy';
import {candidateAbsenceFixture,validationAbsenceFixture} from './helpers/workflow-scheduled-read-absence-fixture';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn()}));
const outbound=vi.mocked(outboundJson),code=(value:string)=>({response:{code:value}});

/** Root readResources/withLiveReads, actual SDK/Context and genuine provider
 * WeakMaps. SQL, Namespace issuance and outbound transport are controlled
 * Source fixtures. No runtime HTTP/SQL, native permits, fake browser identity,
 * business writes or claims of production execution are made by this suite. */
function fixture(kind:'candidate'|'validation'='candidate'){
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
  return{...f,context,kong,generic,business,parentPolicy,material,runtime,run,rootRead,liveRead,acceptedRequests};
}
function parentChild(f:ReturnType<typeof fixture>,childKind='key-auth',workspaceId=f.wid){
  const parentType=childKind==='targets'?'upstreams':'consumers',parentId=randomUUID(),childId=randomUUID();
  const parent:any={clusterId:f.cid,workspaceId,path:`/${parentType}/${parentId}`,kind:'point',entityType:parentType,
    entityId:parentId,secrets:false,required:true,allowAbsent:true};
  const path=`/${parentType}/${parentId}/${childKind}/${childId}`,child:any={clusterId:f.cid,workspaceId,path,kind:'point',entityType:entityForPath(path),
    entityId:childId,parentId,secrets:childKind!=='targets'&&childKind!=='acls',required:true,allowAbsent:true};
  f.values.resources=[parent,child];return{parent,child};
}
function registerSourceWorkspaces(f:ReturnType<typeof fixture>){
  const allowed=new Set(f.values.resources.map((r:any)=>r.workspaceId)),original=f.db.one.getMockImplementation()!;
  f.db.one.mockImplementation(async(sql:string,args:any[])=>{
    const row=await original(sql,args);
    if(sql.includes('FROM workspaces'))return row&&allowed.has(args[0])?{...row,id:args[0],cluster_id:args[1]}:null;
    return row;
  });
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-14T01:00:00.000Z'));outbound.mockReset();});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});

describe.each(['candidate','validation'] as const)('Root scoped %s SDK404/FK orchestration',kind=>{
  it.each(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls','targets'])('records actual parent SDK404 and derived %s provenance separately without nested HTTP',async childKind=>{
    const f=fixture(kind),{parent,child}=parentChild(f,childKind);let result:any;
    await f.run(async handle=>{result=await f.rootRead(handle);});
    expect(result.inferred).toBe(1);expect(result.observations.size).toBe(2);
    const observations=[...result.observations.values()] as any[];
    expect(observations).toEqual([{resource:parent,value:null,absence:'sdk404'},{resource:child,value:null,absence:'parent-FK-absence'}]);
    expect(outbound).toHaveBeenCalledTimes(1);expect(outbound.mock.calls[0][1]).toBe(parent.path);expect(outbound.mock.calls.every(c=>c[2]==='GET')).toBe(true);
    expect(f.business.authorizeResponse.mock.calls.map((c:any)=>c[0].status)).toEqual([404]);expect(f.parentPolicy.assertChild).toHaveBeenCalledTimes(1);
    expect(f.generic).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('keeps an existing parent200 and a real child404 distinct from a derived FK fact',async()=>{
    const f=fixture(kind),{parent,child}=parentChild(f);f.values.present=new Set([parent.path]);let result:any;
    await f.run(async handle=>{result=await f.rootRead(handle);});
    expect(result.inferred).toBe(0);expect([...result.observations.values()]).toEqual([
      {resource:parent,value:{id:parent.entityId}},{resource:child,value:null,absence:'sdk404'}]);
    expect(outbound).toHaveBeenCalledTimes(2);expect(f.parentPolicy.assertChild).not.toHaveBeenCalled();
  });

  it.each(['http-shaped','plain-shaped','non-json','not-found-with-id','read-revoked'])('does not catch %s into an authorized absence',async reason=>{
    const f=fixture(kind),{parent}=parentChild(f);const witness=vi.spyOn(f.service,'requireObservedAbsentPoint');
    if(reason==='http-shaped')vi.spyOn(f.kong,'request').mockRejectedValue(new HttpException({upstreamStatus:404,message:'Not found'},404));
    else if(reason==='plain-shaped')vi.spyOn(f.kong,'request').mockRejectedValue(Object.assign(Error('caller shaped404'),{status:404}));
    else outbound.mockImplementation(async(_base,path,_method,_body,_query,_auth,_timeout,before,prepare)=>{
      await prepare?.();before?.();if(reason==='read-revoked')f.values.read=false;
      return{status:404,body:reason==='not-found-with-id'?{message:'Not found',id:parent.entityId}:{message:'Not found'},bytes:20,jsonParsed:reason!=='non-json'};
    });
    await expect(f.run(handle=>f.rootRead(handle))).rejects.toBeDefined();
    expect(f.parentPolicy.assertChild).not.toHaveBeenCalled();
    if(reason==='plain-shaped')expect(witness).not.toHaveBeenCalled();
    if(reason==='http-shaped')expect(witness).toHaveBeenCalledTimes(1);
  });

  it.each([401,403,500])('does not transform original transport status %i into metadata absence',async status=>{
    const f=fixture(kind);parentChild(f);outbound.mockResolvedValue({status,body:{message:'Not found'},bytes:20,jsonParsed:true});
    const running=f.run(handle=>f.rootRead(handle)),rejected=expect(running).rejects.toBeDefined();await vi.runAllTimersAsync();await rejected;
    expect(f.parentPolicy.assertChild).not.toHaveBeenCalled();expect(f.business.authorizeResponse).not.toHaveBeenCalled();
  });

  it('cannot pass a copied SDK witness to the genuine child provider',async()=>{
    const f=fixture(kind);parentChild(f);const original=f.service.requireObservedAbsentPoint.bind(f.service);
    vi.spyOn(f.service,'requireObservedAbsentPoint').mockImplementation(async(handle:object,r:any)=>({...await original(handle,r)}));
    await expect(f.run(handle=>f.rootRead(handle))).rejects.toMatchObject(code(kind==='candidate'?'WORKFLOW_CANDIDATE_ORIGINAL_PARENT_ABSENCE_REQUIRED':'WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
    expect(outbound).toHaveBeenCalledTimes(1);expect(f.parentPolicy.assertChild).not.toHaveBeenCalled();
  });

  it('cannot reuse a previous genuine SDK witness in a fresh capsule',async()=>{
    const f=fixture(kind);parentChild(f);const original=f.service.requireObservedAbsentPoint.bind(f.service);let previous!:object;
    const spy=vi.spyOn(f.service,'requireObservedAbsentPoint').mockImplementation(async(handle:object,r:any)=>{const w=await original(handle,r);previous=w;return w;});
    const check=async(read:(fn:(handle:object)=>Promise<unknown>)=>Promise<unknown>)=>{
      await read(handle=>f.rootRead(handle));spy.mockResolvedValue(previous);
      await expect(read(handle=>f.rootRead(handle))).rejects.toMatchObject(code(kind==='candidate'?'WORKFLOW_CANDIDATE_ORIGINAL_PARENT_ABSENCE_REQUIRED':'WORKFLOW_SCHEDULE_VALIDATION_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
    };
    if(kind==='candidate')await check(f.run);
    else await f.context.runWorkflowScheduledNamespace(f.nsHandle,()=>check(fn=>f.service.runValidationResources(f.nsHandle,f.cid,f.wid,f.values.resources,f.db,fn)));
    expect(f.parentPolicy.assertChild).toHaveBeenCalledTimes(1);
  });

  it('does not issue native writes from the original read capsule',async()=>{
    const f=fixture(kind);parentChild(f);
    await expect(f.run(()=>f.kong.request(f.cid,'POST','/consumers',{id:randomUUID()}))).rejects.toBeDefined();
    expect(outbound).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('preserves a domainless full EOF read and skips its optional allocated point',async()=>{
    const f=fixture(kind),{parent}=parentChild(f);f.values.domain=undefined;parent.required=false;
    const root={clusterId:f.cid,workspaceId:f.wid,path:'/consumers',kind:'collection',entityType:'consumers',secrets:false,required:true,query:{size:2}};
    f.values.resources=[root,parent];let result:any;await f.run(async handle=>{result=await f.rootRead(handle);});
    expect(result.inferred).toBe(0);expect([...result.observations.values()]).toEqual([{resource:root,value:{data:[],next:null}}]);
    expect(outbound).toHaveBeenCalledTimes(1);expect(f.parentPolicy.assertChild).not.toHaveBeenCalled();
  });

  it('preserves the original domainless required point404 instead of making a scoped absence',async()=>{
    const f=fixture(kind),{parent}=parentChild(f);f.values.domain=undefined;
    f.values.resources=[{clusterId:f.cid,workspaceId:f.wid,path:'/consumers',kind:'collection',entityType:'consumers',secrets:false,required:true,query:{size:2}},parent];
    await expect(f.run(handle=>f.rootRead(handle))).rejects.toMatchObject({status:404});
    expect(f.parentPolicy.assertChild).not.toHaveBeenCalled();expect(f.business.authorizeResponse.mock.calls.map((c:any)=>c[0].status)).toEqual([200,404]);
  });
});

describe('Root exact scoped descriptor grouping and observations',()=>{
  it('keys observations by CID, WID, exact path and complete query without granting a request',()=>{
    const f=fixture(),r=f.values.resources[0],key=f.runtime.observationKey(r),query={...r,query:{size:2,tags:'team:pay'}};
    expect(key).toBe(f.secrets.fingerprint({clusterId:r.clusterId,workspaceId:r.workspaceId,path:r.path,query:{}}));
    for(const changed of [{...r,clusterId:randomUUID()},{...r,workspaceId:randomUUID()},{...r,path:'/schemas/services'},query,{...query,query:{size:2,tags:'team:ops'}}])
      expect(f.runtime.observationKey(changed)).not.toBe(key);
    expect(outbound).not.toHaveBeenCalled();
  });

  it('keeps identical schema paths in two real workspace registries and separate original Validation capsules',async()=>{
    const f=fixture('validation'),secondWid=randomUUID(),first:any={clusterId:f.cid,workspaceId:f.wid,path:'/schemas/services',kind:'schema',entityType:'services',secrets:false,required:true},
      second={...first,workspaceId:secondWid};f.values.resources=[first,second];
    const original=f.db.one.getMockImplementation()!;f.db.one.mockImplementation(async(sql:string,args:any[])=>{
      const row=await original(sql,args);return sql.includes('FROM workspaces')&&row?{...row,id:args[0],cluster_id:args[1]}:row;
    });const opens=vi.spyOn(f.service,'runValidationResources'),actual=outbound.getMockImplementation()!;
    outbound.mockImplementation(async(...args)=>{
      const result=await actual(...args);return{...result,body:{...result.body,workspace:f.acceptedRequests.at(-1)?.workspaceId}};
    });let observed:any,usage:any;
    await f.liveRead(async(_input:any,observations:any,u:any)=>{observed=observations;usage=u;});
    expect(opens).toHaveBeenCalledTimes(2);expect(opens.mock.calls.map((c:any)=>[c[1],c[2],c[3]])).toEqual([[f.cid,f.wid,[first]],[f.cid,secondWid,[second]]]);
    expect(observed.size).toBe(2);expect([...observed.values()].map((o:any)=>o.value.workspace)).toEqual([f.wid,secondWid]);
    expect(usage.calls).toBe(2);expect(usage.records).toBe(0);expect(outbound).toHaveBeenCalledTimes(2);
    expect(f.generic).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('selects both workspace schemas inside one original Candidate capsule without substituting the reader',async()=>{
    const f=fixture('candidate'),first:any={clusterId:f.cid,workspaceId:f.wid,path:'/schemas/services',kind:'schema',entityType:'services',secrets:false,required:true},
      second={...first,workspaceId:randomUUID()};f.values.resources=[first,second];
    const original=f.db.one.getMockImplementation()!;f.db.one.mockImplementation(async(sql:string,args:any[])=>{
      const row=await original(sql,args);return sql.includes('FROM workspaces')&&row?{...row,id:args[0],cluster_id:args[1]}:row;
    });
    let observed:any;await f.run(async handle=>{observed=(await f.rootRead(handle)).observations;});
    expect(observed.size).toBe(2);expect(f.acceptedRequests.map(r=>r.workspaceId)).toEqual([f.wid,second.workspaceId]);
    expect(outbound).toHaveBeenCalledTimes(2);expect(outbound.mock.calls.every(c=>Object.keys(c[4]??{}).length===0)).toBe(true);
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('keeps duplicate CID/path resources ambiguous without the original selector before any ticket or transport',async()=>{
    const f=fixture(),first:any={clusterId:f.cid,workspaceId:f.wid,path:'/schemas/services',kind:'schema',entityType:'services',secrets:false,required:true},
      second={...first,workspaceId:randomUUID()};f.values.resources=[first,second];registerSourceWorkspaces(f);
    await expect(f.run(()=>f.kong.request(f.cid,'GET',first.path))).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_READ_RESOURCE_AMBIGUOUS'));
    expect(f.acceptedRequests).toEqual([]);expect(outbound).not.toHaveBeenCalled();
  });

  it('counts FK metadata records without inventing extra SDK calls/pages/bytes',async()=>{
    const f=fixture('validation');parentChild(f);let usage:any,observed:any;
    await f.liveRead(async(_input:any,observations:any,u:any)=>{usage=u;observed=observations;});
    expect(usage.calls).toBe(1);expect(usage.records).toBe(1);expect(usage.pages).toBe(0);
    expect(usage.bytes).toBe(Buffer.byteLength(JSON.stringify({message:'Not found'})));expect(observed.size).toBe(2);
    expect(outbound).toHaveBeenCalledTimes(1);expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('keeps true SDK parents and inferred child facts in each exact live workspace capsule',async()=>{
    const f=fixture('validation'),a=parentChild(f),b=parentChild(f,'targets',randomUUID());f.values.resources=[a.parent,a.child,b.parent,b.child];registerSourceWorkspaces(f);let observed:any,usage:any;
    await f.liveRead(async(_input:any,o:any,u:any)=>{observed=o;usage=u;});
    expect(observed.size).toBe(4);expect([...observed.values()].map((o:any)=>[o.resource.workspaceId,o.absence])).toEqual([
      [a.parent.workspaceId,'sdk404'],[a.parent.workspaceId,'parent-FK-absence'],[b.parent.workspaceId,'sdk404'],[b.parent.workspaceId,'parent-FK-absence']]);
    expect(f.acceptedRequests.map(r=>r.workspaceId)).toEqual([a.parent.workspaceId,b.parent.workspaceId]);
    expect(outbound.mock.calls.map(c=>c[1])).toEqual([a.parent.path,b.parent.path]);expect(usage.calls).toBe(2);expect(usage.records).toBe(2);expect(usage.pages).toBe(0);
    expect(f.parentPolicy.assertChild).toHaveBeenCalledTimes(2);expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('does not borrow a different-workspace parent SDK404 for a future child',async()=>{
    const f=fixture('validation'),{parent,child}=parentChild(f);child.workspaceId=randomUUID();f.values.resources=[parent,child];registerSourceWorkspaces(f);
    await expect(f.liveRead(async()=>true)).rejects.toBeDefined();
    expect(f.parentPolicy.assertChild).not.toHaveBeenCalled();expect(outbound).toHaveBeenCalledTimes(2);
    expect(f.acceptedRequests.map(r=>r.workspaceId)).toEqual([parent.workspaceId,child.workspaceId]);expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('uses only Kong 1.5 plugin schemas and keeps the newer path closed before transport',async()=>{
    const f=fixture(),r={clusterId:f.cid,workspaceId:f.wid,path:'/plugins/schema/key-auth',kind:'schema',entityType:'key-auth',secrets:false,required:true};
    f.values.resources=[r];await f.run(handle=>f.rootRead(handle));expect(outbound).toHaveBeenCalledTimes(1);expect(outbound.mock.calls[0][1]).toBe(r.path);
    outbound.mockClear();f.values.resources=[{...r,path:'/schemas/plugins/key-auth'}];
    await expect(f.run(handle=>f.rootRead(handle))).rejects.toBeDefined();expect(outbound).not.toHaveBeenCalled();
  });

  it('executes the live reader as the genuine current selected reviewer and never substitutes executor grants',async()=>{
    const f=fixture('validation');parentChild(f);const reviewer=f.approvalSet.reviewers[0].userId;
    await f.liveRead(async(input:any)=>{expect(input.principal.user.id).toBe(reviewer);expect(input.role).toBe('reviewer');},reviewer,'reviewer');
    expect(f.parentPolicy.assertChild.mock.calls[0][0].principal.user.id).toBe(reviewer);
    expect(f.parentPolicy.assertChild.mock.calls[0][0].role).toBe('reviewer');expect(f.generic).not.toHaveBeenCalled();
  });

  it('rejects an ambiguous same CID/WID/path observation even when queries differ',()=>{
    const f=fixture(),r=f.values.resources[0],a={...r,query:{size:2,tags:'team:a'}},b={...r,query:{size:2,tags:'team:b'}},observations=new Map([
      [f.runtime.observationKey(a),{resource:a,value:{data:[],next:null}}],[f.runtime.observationKey(b),{resource:b,value:{data:[],next:null}}]]);
    expect(()=>f.runtime.observation(observations,r.clusterId,r.workspaceId,r.path)).toThrow();expect(outbound).not.toHaveBeenCalled();
  });

  it('selects readback resources by exact CID/WID/path and rejects ambiguous or foreign selectors',()=>{
    const f=fixture(),r=f.values.resources[0],second={...r,workspaceId:randomUUID()};
    expect(f.runtime.selectResources([r,second],r.clusterId,r.workspaceId,[r.path])).toEqual([r]);
    expect(()=>f.runtime.selectResources([r,second],r.clusterId,randomUUID(),[r.path])).toThrow();
    expect(()=>f.runtime.selectResources([r,r],r.clusterId,r.workspaceId,[r.path])).toThrow();
    expect(()=>f.runtime.selectResources([r],randomUUID(),r.workspaceId,[r.path])).toThrow();
    expect(outbound).not.toHaveBeenCalled();
  });
});

describe.each(['candidate','validation'] as const)('Original %s short resource selector boundaries',kind=>{
  function selected(){
    const f=fixture(kind),r={clusterId:f.cid,workspaceId:f.wid,path:'/schemas/services',kind:'schema',entityType:'services',secrets:false,required:true};
    f.values.resources=[r];return{f,r};
  }
  it.each(['clusterId','workspaceId','path','query','secrets','required','allowAbsent','entityId','parentId','kind'])('rejects changed descriptor %s without starting an SDK request',async field=>{
    const {f,r}=selected(),changed:any={...r,[field]:['clusterId','workspaceId','entityId','parentId'].includes(field)?randomUUID():field==='query'?{size:2}:field==='path'?'/schemas/routes':field==='kind'?'point':!(r as any)[field]};
    await expect(f.run(handle=>f.context.runWorkflowScheduledReadResource(handle,changed,()=>f.kong.request(f.cid,'GET',r.path))))
      .rejects.toMatchObject(code('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED'));
    expect(outbound).not.toHaveBeenCalled();expect(f.acceptedRequests).toEqual([]);
  });

  it('requires the original read handle even for a byte-identical selector',async()=>{
    const {f,r}=selected();await expect(f.run(handle=>f.context.runWorkflowScheduledReadResource({...handle},r,()=>f.kong.request(f.cid,'GET',r.path))))
      .rejects.toMatchObject(code('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED'));
    expect(outbound).not.toHaveBeenCalled();
  });

  it('allows a descriptor copy only by locating the current original scope member',async()=>{
    const {f,r}=selected();await f.run(handle=>f.context.runWorkflowScheduledReadResource(handle,{...r},()=>f.kong.request(f.cid,'GET',r.path)));
    expect(f.acceptedRequests).toHaveLength(1);expect(f.acceptedRequests[0].workspaceId).toBe(r.workspaceId);expect(outbound).toHaveBeenCalledTimes(1);
  });

  it('rejects a nested selector and cannot silently replace its original resource',async()=>{
    const {f,r}=selected();await expect(f.run(handle=>f.context.runWorkflowScheduledReadResource(handle,r,
      ()=>f.context.runWorkflowScheduledReadResource(handle,r,()=>f.kong.request(f.cid,'GET',r.path)))))
      .rejects.toMatchObject(code('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED'));
    expect(outbound).not.toHaveBeenCalled();
  });

  it('closes an issued original ticket as soon as its selector callback ends',async()=>{
    const {f,r}=selected(),cluster=await f.db.one('SELECT * FROM clusters WHERE id=$1',[f.cid]);
    await expect(f.run(async handle=>{
      const ticket=await f.context.runWorkflowScheduledReadResource(handle,r,async()=>{
        const token=await f.context.authorizeRequest(cluster,'GET',r.path,undefined,{});expect(()=>f.context.assertTicketActive(token)).not.toThrow();return token;
      });expect(()=>f.context.assertTicketActive(ticket)).toThrow();
    })).rejects.toMatchObject(code(kind==='candidate'?'WORKFLOW_CANDIDATE_READ_INCOMPLETE':'WORKFLOW_SCHEDULE_VALIDATION_READ_INCOMPLETE'));
    expect(outbound).not.toHaveBeenCalled();
  });

  it('rejects an async callback escaping its original short selector lifetime',async()=>{
    const {f,r}=selected();let release!:()=>void,escaped!:Promise<unknown>;
    const gate=new Promise<void>(resolve=>{release=resolve;});
    await expect(f.run(async handle=>{
      await f.context.runWorkflowScheduledReadResource(handle,r,async()=>{escaped=gate.then(()=>f.kong.request(f.cid,'GET',r.path));});
      const rejected=expect(escaped).rejects.toMatchObject(code('WORKFLOW_SCHEDULE_ORIGINAL_RESOURCE_REQUIRED'));release();await rejected;
    })).rejects.toMatchObject(code(kind==='candidate'?'WORKFLOW_CANDIDATE_READ_INCOMPLETE':'WORKFLOW_SCHEDULE_VALIDATION_READ_INCOMPLETE'));
    expect(outbound).not.toHaveBeenCalled();
  });

  it('does not allow an original active ticket to cross into a parallel sibling selector',async()=>{
    const {f,r}=selected(),cluster=await f.db.one('SELECT * FROM clusters WHERE id=$1',[f.cid]);let release!:()=>void,started!:()=>void;
    const gate=new Promise<void>(resolve=>{release=resolve;}),ready=new Promise<void>(resolve=>{started=resolve;});
    await expect(f.run(async handle=>{
      let ticket:any;const first=f.context.runWorkflowScheduledReadResource(handle,r,async()=>{
        ticket=await f.context.authorizeRequest(cluster,'GET',r.path,undefined,{});started();await gate;
      });
      await ready;
      try{await f.context.runWorkflowScheduledReadResource(handle,r,async()=>{expect(()=>f.context.assertTicketActive(ticket)).toThrow();});}
      finally{release();await first;}
    })).rejects.toMatchObject(code(kind==='candidate'?'WORKFLOW_CANDIDATE_READ_INCOMPLETE':'WORKFLOW_SCHEDULE_VALIDATION_READ_INCOMPLETE'));
    expect(outbound).not.toHaveBeenCalled();
  });

  it('cannot reopen the selector from a closed or absent original read context',async()=>{
    const {f,r}=selected();let saved!:object;await f.run(async handle=>{saved=handle;await f.rootRead(handle);});
    await expect(f.context.runWorkflowScheduledReadResource(saved,r,()=>f.kong.request(f.cid,'GET',r.path))).rejects.toBeDefined();
    expect(outbound).toHaveBeenCalledTimes(1);
  });
});
