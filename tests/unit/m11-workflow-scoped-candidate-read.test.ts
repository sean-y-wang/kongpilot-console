import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {candidateAbsenceFixture} from './helpers/workflow-scheduled-read-absence-fixture';
import {entityForPath} from '../../apps/console-api/src/infrastructure/kong/policy';

/** Real Candidate provider/crypto/private maps with controlled SQL and a
 * fixed original-observation fixture. No live HTTP/SQL, native permit,
 * approval execution, fake runtime acceptance or business ledger writes. */
function fixture(collection=false){
  const f=candidateAbsenceFixture(collection);
  f.values.domain='scoped-points-v1';f.values.childGrant=true;f.values.parentCreate=true;
  f.values.pointGrant=true;f.values.pointCreate=true;
  f.values.limits={maxCalls:10,maxPages:5,maxRecords:10,maxBytes:8192};
  f.policies.resolveReadScope.mockImplementation(async()=>({version:1,domain:f.values.domain,resources:f.values.resources,limits:f.values.limits}));
  const originalResponse=f.policies.authorizeResponse.getMockImplementation()!;
  f.policies.authorizeResponse.mockImplementation(async(input:any)=>{
    await originalResponse(input);
    if(input.status===404){
      if(!f.values.pointGrant)throw new ForbiddenException({code:'ACTUAL_ABSENT_CREATE_READ_WRITE_SECRET_DENIED'});
      if(!f.values.pointCreate)throw new ForbiddenException({code:'ACTUAL_ABSENT_COMPILED_CREATE_REQUIRED'});
    }
  });
  const observations=new WeakMap<object,{token:object,response:unknown,status:number}>();
  const observer={verifyOriginalResponse:vi.fn((token:object,original:object)=>{
    const value=observations.get(original);
    if(!value||value.token!==token)throw new ForbiddenException({code:'ORIGINAL_SDK_404_REQUIRED'});
    return value;
  })};
  const original404=(token:object,response:unknown={message:'Not found'},status=404)=>{
    const original=Object.freeze({});observations.set(original,{token,response,status});return{original,response};
  };
  const packetFor=(r:any)=>({clusterId:r.clusterId,workspaceId:r.workspaceId,method:'GET',path:r.path,query:r.query??{}});
  const actualRead=async(handle:object,r:any,response:any)=>{
    const token=await f.service.authorizeRequest(handle,packetFor(r));await f.service.verifyRequest(token);
    return f.service.authorizeResponse(token,response);
  };
  const actualAbsent=async(handle:object,r:any)=>{
    const token=await f.service.authorizeRequest(handle,packetFor(r));await f.service.verifyRequest(token);
    const observed=original404(token);return f.service.authorizeResponse(token,observed.response,observed.original);
  };
  const install=()=>{f.service.installAbsentResponseVerifier(observer as any);f.install();};
  const run=(fn:(handle:object)=>Promise<unknown>,actor=f.owner,role:'executor'|'reviewer'='executor')=>f.service.runOriginalPlan(f.plan,actor,role,fn,f.db);
  return{...f,observer,original404,packetFor,actualRead,actualAbsent,install,run};
}
function parentChild(f:ReturnType<typeof fixture>,kind='key-auth',workspaceId=f.wid){
  const parentType=kind==='targets'?'upstreams':'consumers',parentId=randomUUID(),childId=randomUUID();
  const parent:any={clusterId:f.cid,workspaceId,path:`/${parentType}/${parentId}`,kind:'point',entityType:parentType,
    entityId:parentId,secrets:false,allowAbsent:true,required:true};
  const path=`/${parentType}/${parentId}/${kind}/${childId}`;
  const child:any={clusterId:f.cid,workspaceId,path,kind:'point',entityType:entityForPath(path),entityId:childId,parentId,
    secrets:kind!=='targets'&&kind!=='acls',allowAbsent:true,required:true};
  f.values.resources=[parent,child];
  // Source stand-in for the once-fixed Material compiler. A fresh compiled
  // parent create and this principal's child READ/write/secret decision are
  // separately required; the observer cannot supply either decision.
  const policy={assertChild:vi.fn(async(input:any,actualChild:any,actualParent:any)=>{
    expect(input.transaction).toBe(f.db);expect(input.principal.user.superAdmin).toBe(false);
    expect(actualChild).toEqual(child);expect(actualParent).toEqual(parent);
    if(!f.values.childGrant)throw new ForbiddenException({code:'ACTUAL_CHILD_READ_WRITE_SECRET_DENIED'});
    if(!f.values.parentCreate)throw new ForbiddenException({code:'ACTUAL_COMPILED_PARENT_CREATE_REQUIRED'});
    await f.values.beforeChildFinish?.();
  })};
  return{parent,child,policy};
}
const code=(value:string)=>({response:{code:value}});
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.useFakeTimers();vi.setSystemTime(new Date('2026-10-14T01:00:00.000Z'));});
afterEach(()=>{vi.useRealTimers();vi.unstubAllEnvs();});

describe('M11 scoped Candidate original SDK point absence',()=>{
  it('accepts a fixed canonical point404 without a broad collection and returns only a private witness',async()=>{
    const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;r.required=true;f.install();let saved!:object;
    await f.run(async handle=>{
      await f.actualAbsent(handle,r);saved=await f.service.requireObservedAbsentPoint(handle,r);
      expect(Object.isFrozen(saved)).toBe(true);expect(Object.keys(saved)).toEqual([]);
      const proof=await f.service.verifyHandle(handle);expect(proof.readOnly).toBe(true);expect(proof.sessionId).toBeNull();
      expect(proof.scope.resources).toEqual([r]);expect(proof.actor.id).toBe(f.owner);
    });
    expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);expect(f.policies.authorizeResponse.mock.calls.map(([input]:any)=>input.status)).toEqual([404]);
    expect(f.db.exec).not.toHaveBeenCalled();expect(f.repository.appendDueClaim).not.toHaveBeenCalled();
  });

  it('retains the domainless original EOF requirement',async()=>{
    const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;f.values.domain=undefined;f.install();
    await expect(f.run(handle=>f.actualAbsent(handle,r))).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_ABSENT_WITNESS_REQUIRED'));
  });

  it('permits only the fixed same-cluster actual workspace descriptors and their fresh registry',async()=>{
    const f=fixture(),secondWid=randomUUID(),first:any={clusterId:f.cid,workspaceId:f.wid,path:'/schemas/services',kind:'schema',entityType:'services',secrets:false,required:true},
      second={...first,workspaceId:secondWid};f.values.resources=[first,second];
    const original=f.db.one.getMockImplementation()!;
    f.db.one.mockImplementation(async(sql:string,args:any[])=>{
      const row=await original(sql,args);return sql.includes('FROM workspaces')&&row?{...row,id:args[0],cluster_id:args[1]}:row;
    });f.install();
    await f.run(async handle=>{
      const proof=await f.service.verifyHandle(handle);expect(proof.registries.map(r=>r.workspaceId)).toEqual([f.wid,secondWid]);
      await f.actualRead(handle,first,{fields:[{name:{type:'string'}}]});await f.actualRead(handle,second,{fields:[{name:{type:'string'}}]});
    });
    expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['domainless','foreign-cluster','missing-workspace'])('closes %s scope before an original read capsule',async reason=>{
    const f=fixture();f.values.resources=[{clusterId:reason==='foreign-cluster'?randomUUID():f.cid,workspaceId:randomUUID(),
      path:'/schemas/services',kind:'schema',entityType:'services',secrets:false}];
    if(reason==='domainless')f.values.domain=undefined;
    if(reason==='missing-workspace'){
      const original=f.db.one.getMockImplementation()!;f.db.one.mockImplementation(async(sql:string,args:any[])=>sql.includes('FROM workspaces')?null:original(sql,args));
    }f.install();
    await expect(f.run(async()=>true)).rejects.toBeDefined();expect(f.runner.run).not.toHaveBeenCalled();
  });

  it.each(['caller-scoped','full','SCOPED-POINTS-V1',true,{}])('rejects arbitrary domain %j',async domain=>{
    const f=fixture();f.values.domain=domain;f.install();
    await expect(f.run(async()=>true)).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID'));
    expect(f.runner.run).not.toHaveBeenCalled();
  });

  it.each([404,401,500,{status:404,response:{message:'Not found'}},'404'])('rejects supplied status/observation %j',async observed=>{
    const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;f.install();
    await expect(f.run(async handle=>{
      const token=await f.service.authorizeRequest(handle,f.packetFor(r));return f.service.authorizeResponse(token,{message:'Not found'},observed as any);
    })).rejects.toBeDefined();expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });

  it.each([401,403,500,502])('rejects even an original observation with status %i',async status=>{
    const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;f.install();
    await expect(f.run(async handle=>{
      const token=await f.service.authorizeRequest(handle,f.packetFor(r)),observed=f.original404(token,{message:'Not found'},status);
      return f.service.authorizeResponse(token,observed.response,observed.original);
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_ABSENT_OBSERVATION_REQUIRED'));
  });

  it.each(['copy','response-copy','wrong-request','malformed-body','array-body'])('rejects %s as an original JSON404 fact',async reason=>{
    const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;f.install();
    await expect(f.run(async handle=>{
      const token=await f.service.authorizeRequest(handle,f.packetFor(r)),observed=f.original404(reason==='wrong-request'?{}:token,
        reason==='malformed-body'?{message:'Not found',id:r.entityId}:reason==='array-body'?[{message:'Not found'}]:{message:'Not found'});
      return f.service.authorizeResponse(token,reason==='response-copy'?{...observed.response as any}:observed.response,
        reason==='copy'?{...observed.original}:observed.original);
    })).rejects.toBeDefined();expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });

  it.each(['never-read','pending','present200'])('cannot mint absence from %s',async reason=>{
    const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;f.install();
    await expect(f.run(async handle=>{
      if(reason==='pending')await f.service.authorizeRequest(handle,f.packetFor(r));
      if(reason==='present200')await f.actualRead(handle,r,{id:r.entityId});
      return f.service.requireObservedAbsentPoint(handle,r);
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_ORIGINAL_ABSENCE_REQUIRED'));
  });

  it.each(['clusterId','workspaceId','entityId','secrets','allowAbsent','required','parentId','query','kind'])('requires exact descriptor %s after the real404',async field=>{
    const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;r.required=true;f.install();
    await expect(f.run(async handle=>{
      await f.actualAbsent(handle,r);
      const changed={...r,[field]:['clusterId','workspaceId','entityId','parentId'].includes(field)?randomUUID():field==='query'?{size:1}:field==='kind'?'schema':!r[field]};
      return f.service.requireObservedAbsentPoint(handle,changed);
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_ORIGINAL_ABSENCE_REQUIRED'));
  });

  it('does not treat a collection-shaped point endpoint as a canonical scoped404',async()=>{
    const f=fixture(),r=f.values.resources[0];r.path='/services';r.allowAbsent=true;f.install();
    await expect(f.run(handle=>f.actualAbsent(handle,r))).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID'));
    expect(f.runner.run).not.toHaveBeenCalled();
  });

  it.each(['trailing-slash','different-id','root-parent','nested-parent','entity-type'])('rejects noncanonical fixed point %s before any GET',async reason=>{
    const f=fixture(),{child}=parentChild(f);let r=f.values.resources[0];
    if(reason==='trailing-slash')r.path+='/';if(reason==='different-id')r.entityId=randomUUID();
    if(reason==='root-parent')r.parentId=randomUUID();if(reason==='nested-parent'){r=child;r.parentId=randomUUID();}
    if(reason==='entity-type')r.entityType='services';f.values.resources=[r];f.install();
    await expect(f.run(async()=>true)).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID'));
    expect(f.runner.run).not.toHaveBeenCalled();expect(f.observer.verifyOriginalResponse).not.toHaveBeenCalled();
  });

  it.each(['schema','collection','not-allowed'])('rejects 404 for %s before the response authorizer',async reason=>{
    const f=fixture(reason==='collection');if(reason==='schema')f.values.resources=[{clusterId:f.cid,workspaceId:f.wid,path:'/schemas/services',kind:'schema',entityType:'services',secrets:false}];
    const r=f.values.resources[0];f.install();
    await expect(f.run(handle=>f.actualAbsent(handle,r))).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_RESPONSE_INVALID'));
    expect(f.policies.authorizeResponse).not.toHaveBeenCalled();
  });

  it('leaves an unobserved timed-out GET incomplete even when its error is caught',async()=>{
    const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;f.install();
    await expect(f.run(async handle=>{
      await f.service.authorizeRequest(handle,f.packetFor(r));try{throw new Error('controlled timeout');}catch{}return true;
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_READ_INCOMPLETE'));
  });

  it('requires fresh response scope and poisons a caught authorization denial',async()=>{
    const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;f.install();
    await expect(f.run(async handle=>{
      f.values.scopeChanged=true;try{await f.actualAbsent(handle,r);}catch{}return true;
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_READ_FAILED'));
  });

  it.each(['grant','compiled-create'])('cannot turn genuine SDK404 into absence without fixed current %s approval',async reason=>{
    const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;f.install();
    await expect(f.run(async handle=>{
      if(reason==='grant')f.values.pointGrant=false;else f.values.pointCreate=false;
      return f.actualAbsent(handle,r);
    })).rejects.toMatchObject(code(reason==='grant'?'ACTUAL_ABSENT_CREATE_READ_WRITE_SECRET_DENIED':'ACTUAL_ABSENT_COMPILED_CREATE_REQUIRED'));
    expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);
  });

  it('rejects expired or copied original handles after an observed404',async()=>{
    for(const reason of ['expired','copy','closed']){
      const f=fixture(),r=f.values.resources[0];r.allowAbsent=true;f.install();let saved!:object;
      if(reason==='closed'){
        await f.run(async handle=>{saved=handle;await f.actualAbsent(handle,r);});
        await expect(f.service.requireObservedAbsentPoint(saved,r)).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_ORIGINAL_HANDLE_REQUIRED'));
      }else await expect(f.run(async handle=>{
        await f.actualAbsent(handle,r);if(reason==='expired')vi.advanceTimersByTime(30001);
        return f.service.requireObservedAbsentPoint(reason==='copy'?{...handle}:handle,r);
      })).rejects.toBeDefined();
    }
  });
});

describe('M11 Candidate future FK child absence stays separate from SDK404',()=>{
  it('installs exactly one complete fixed parent material policy',()=>{
    const f=fixture(),{policy}=parentChild(f);f.install();
    expect(()=>f.service.installParentAbsencePolicy({} as any)).toThrow();
    expect(()=>f.service.installParentAbsencePolicy({...policy,authority:'caller'} as any)).toThrow();
    f.service.installParentAbsencePolicy(policy);expect(()=>f.service.installParentAbsencePolicy(policy)).toThrow();
  });

  it.each(['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls','targets'])('derives %s with one parent GET and zero child HTTP requests',async kind=>{
    const f=fixture(),{parent,child,policy}=parentChild(f,kind);f.values.limits.maxCalls=1;f.install();f.service.installParentAbsencePolicy(policy);
    await f.run(async handle=>{
      await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
      const derived=await f.service.observeFutureChildAbsence(handle,child,witness);
      expect(derived).toEqual({kind:'parent-FK-absence',nativeRequestsSent:0});expect(Object.isFrozen(derived)).toBe(true);
    });
    expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
    expect(policy.assertChild).toHaveBeenCalledTimes(1);expect(f.db.exec).not.toHaveBeenCalled();expect(f.repository.appendDueClaim).not.toHaveBeenCalled();
  });

  it('does not permit an FK child absence to be advertised as an original SDK404',async()=>{
    const f=fixture(),{parent,child,policy}=parentChild(f);f.install();f.service.installParentAbsencePolicy(policy);
    await expect(f.run(async handle=>{
      await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
      await f.service.observeFutureChildAbsence(handle,child,witness);
      return f.service.requireObservedAbsentPoint(handle,child);
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_ORIGINAL_ABSENCE_REQUIRED'));
    expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);
  });

  it('requires the current selected reviewer identity and its own SQL grants in the child policy',async()=>{
    const f=fixture(),{parent,child,policy}=parentChild(f);f.install();f.service.installParentAbsencePolicy(policy);
    await f.run(async handle=>{
      const proof=await f.service.verifyHandle(handle);expect(proof.actor.id).toBe(f.reviewer);expect(proof.sessionId).toBeNull();
      await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
      await f.service.observeFutureChildAbsence(handle,child,witness);
    },f.reviewer,'reviewer');
    const input=policy.assertChild.mock.calls[0][0];expect(input.role).toBe('reviewer');expect(input.principal.user.id).toBe(f.reviewer);
    expect(input.principal.grants.every((g:any)=>g.user_id===f.reviewer)).toBe(true);
    expect(input.principal.user.id).not.toBe(f.owner);expect(f.approvals.verifyApprovalSet).not.toHaveBeenCalled();
  });

  it.each(['missing-policy','copy','foreign-capsule','parent-id','descriptor','pending-child','already-derived','read-revoked','expiry','grant-revoked','not-create'])('rejects %s and poisons the capsule after caught denial',async reason=>{
    const f=fixture(),{parent,child,policy}=parentChild(f);f.install();if(reason!=='missing-policy')f.service.installParentAbsencePolicy(policy);
    let previous!:object;
    if(reason==='foreign-capsule'){
      child.required=false;
      await f.run(async handle=>{await f.actualAbsent(handle,parent);previous=await f.service.requireObservedAbsentPoint(handle,parent);});child.required=true;
    }
    await expect(f.run(async handle=>{
      await f.actualAbsent(handle,parent);let witness=await f.service.requireObservedAbsentPoint(handle,parent),selected={...child};
      if(reason==='copy')witness={...witness};if(reason==='foreign-capsule')witness=previous;
      if(reason==='parent-id')selected.parentId=randomUUID();if(reason==='descriptor')selected.secrets=!selected.secrets;
      if(reason==='pending-child')await f.service.authorizeRequest(handle,f.packetFor(child));
      if(reason==='already-derived')await f.service.observeFutureChildAbsence(handle,child,witness);
      if(reason==='read-revoked')f.values.read=false;if(reason==='grant-revoked')f.values.childGrant=false;
      if(reason==='not-create')f.values.parentCreate=false;if(reason==='expiry')vi.advanceTimersByTime(30001);
      try{await f.service.observeFutureChildAbsence(handle,selected,witness);}catch{}return true;
    })).rejects.toBeDefined();
  });

  it('keeps a true parent404 from authorizing a nested SDK404 via the legacy helper',async()=>{
    const f=fixture(),{parent,child}=parentChild(f);f.install();
    await expect(f.run(async handle=>{await f.actualAbsent(handle,parent);return f.actualAbsent(handle,child);})).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_ABSENT_WITNESS_REQUIRED'));
    expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
  });

  it('accepts a genuine parent200 then an original child404 without logical inference',async()=>{
    const f=fixture(),{parent,child}=parentChild(f);f.install();
    await f.run(async handle=>{
      await f.actualRead(handle,parent,{id:parent.entityId,tags:['owner-pay']});await f.actualAbsent(handle,child);
      await f.service.requireObservedAbsentPoint(handle,child);
    });
    expect(f.policies.authorizeResponse.mock.calls.map(([input]:any)=>input.status)).toEqual([200,404]);
    expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);
  });

  it('requires the exact original parent even when both parents are absent in the same capsule',async()=>{
    const f=fixture(),a=parentChild(f),b=parentChild(f);f.values.resources=[a.parent,a.child,b.parent,b.child];f.install();f.service.installParentAbsencePolicy(a.policy);
    await expect(f.run(async handle=>{
      await f.actualAbsent(handle,a.parent);await f.actualAbsent(handle,b.parent);
      const wrong=await f.service.requireObservedAbsentPoint(handle,b.parent);return f.service.observeFutureChildAbsence(handle,a.child,wrong);
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
    expect(a.policy.assertChild).not.toHaveBeenCalled();
  });

  it('rejects a genuine parent witness from another real workspace in the same original capsule',async()=>{
    const f=fixture(),a=parentChild(f),b=parentChild(f,'key-auth',randomUUID());f.values.resources=[a.parent,a.child,b.parent,b.child];f.install();f.service.installParentAbsencePolicy(a.policy);
    await expect(f.run(async handle=>{
      await f.actualAbsent(handle,a.parent);await f.actualAbsent(handle,b.parent);
      const wrong=await f.service.requireObservedAbsentPoint(handle,b.parent);return f.service.observeFutureChildAbsence(handle,a.child,wrong);
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
    expect(a.policy.assertChild).not.toHaveBeenCalled();
  });

  it('never infers arbitrary Route or Plugin relation absence',async()=>{
    const f=fixture(),parent=f.values.resources[0],id=randomUUID();parent.allowAbsent=true;parent.required=true;
    const child:any={...parent,path:`/routes/${id}`,entityType:'routes',entityId:id,parentId:parent.entityId};f.values.resources=[parent,child];f.install();
    const policy={assertChild:vi.fn(async()=>undefined)};f.service.installParentAbsencePolicy(policy);
    await expect(f.run(async handle=>{
      await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
      return f.service.observeFutureChildAbsence(handle,child,witness);
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_READ_SCOPE_INVALID'));
    expect(policy.assertChild).not.toHaveBeenCalled();
  });

  it.each(['iam','credentials','owner','policy','scope','migration'])('rechecks current %s before the inference callback',async reason=>{
    const f=fixture(),{parent,child,policy}=parentChild(f);f.install();f.service.installParentAbsencePolicy(policy);
    await expect(f.run(async handle=>{
      await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
      if(reason==='iam')f.state.principalVersion='2';if(reason==='credentials')f.state.epoch='2';if(reason==='owner')f.state.ownerActive=false;
      if(reason==='policy')f.state.policyChanged=true;if(reason==='scope')f.values.resources=[{...parent,secrets:true},child];if(reason==='migration')f.state.migration=false;
      return f.service.observeFutureChildAbsence(handle,child,witness);
    })).rejects.toBeDefined();expect(policy.assertChild).not.toHaveBeenCalled();
  });

  it('rechecks current principal facts after the fixed async child policy',async()=>{
    const f=fixture(),{parent,child,policy}=parentChild(f);f.values.beforeChildFinish=async()=>{f.state.principalVersion='2';};f.install();f.service.installParentAbsencePolicy(policy);
    await expect(f.run(async handle=>{
      await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
      return f.service.observeFutureChildAbsence(handle,child,witness);
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_FACTS_CHANGED'));
    expect(policy.assertChild).toHaveBeenCalledTimes(1);
  });

  it('rechecks pending reads introduced while the fixed child policy is awaiting',async()=>{
    const f=fixture(),{parent,child,policy}=parentChild(f);f.install();f.service.installParentAbsencePolicy(policy);
    await expect(f.run(async handle=>{
      await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
      f.values.beforeChildFinish=async()=>{await f.service.authorizeRequest(handle,f.packetFor(child));};
      return f.service.observeFutureChildAbsence(handle,child,witness);
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_ORIGINAL_PARENT_ABSENCE_REQUIRED'));
    expect(policy.assertChild).toHaveBeenCalledTimes(1);expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);
  });

  it('charges derived children to the shared record budget while issuing no extra GET',async()=>{
    const f=fixture(),{parent,child}=parentChild(f),id=randomUUID(),second={...child,entityId:id,path:child.path.slice(0,child.path.lastIndexOf('/')+1)+id};
    f.values.resources=[parent,child,second];f.values.limits.maxRecords=1;f.install();f.service.installParentAbsencePolicy({assertChild:async()=>undefined});
    await expect(f.run(async handle=>{
      await f.actualAbsent(handle,parent);const witness=await f.service.requireObservedAbsentPoint(handle,parent);
      await f.service.observeFutureChildAbsence(handle,child,witness);return f.service.observeFutureChildAbsence(handle,second,witness);
    })).rejects.toMatchObject(code('WORKFLOW_CANDIDATE_READ_BUDGET'));
    expect(f.observer.verifyOriginalResponse).toHaveBeenCalledTimes(1);expect(f.policies.authorizeResponse).toHaveBeenCalledTimes(1);
  });
});
