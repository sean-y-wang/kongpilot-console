import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {ForbiddenException} from '@nestjs/common';
import {KongExecutionContextService,type PromotionRecoveryReadProof} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {NativeKongPolicyService} from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';

/** Real execution kernel/native policy. The bootstrap/ConfigAccess verifier is
 * an explicit synthetic private WeakMap boundary; provider/Repo tests and the
 * isolated runtime separately prove genuine source ConfigAccess authority. */
function fixture(){
 const context=new KongExecutionContextService(),secrets=new SecretService(),uid=randomUUID(),sid=randomUUID(),cid=randomUUID(),wid=randomUUID(),targetCid=randomUUID(),targetWid=randomUUID();
 const certificate=randomUUID(),consumer=randomUUID(),credential=randomUUID(),actor={id:uid,username:'actual-source-owner',superAdmin:false};
 const cluster={id:cid,admin_url:'http://source-kong:8001',version:'1.5.1',execution_mode:'approval',transport_scope:'b'.repeat(64),status:'healthy'};
 const point=`/certificates/${certificate}`,collection=`/consumers/${consumer}/key-auth`,schema='/plugins/schema/key-auth',handle=Object.freeze({});
 let proof:PromotionRecoveryReadProof;const state={active:true,rawChanged:false},requests:any[]=[],responses=new Map<string,any>([
  [point,{id:certificate,cert:'synthetic-public-certificate',key:'synthetic-private-key'}],
  [collection,{data:[{id:credential,key:'synthetic-private-key',consumer:{id:consumer}}],next:null}],
  [schema,{fields:[{config:{type:'record',fields:[]}}]}],
 ]);
 const provider={verifyHandle:vi.fn(async(candidate:object)=>{if(candidate!==handle||!state.active)throw new ForbiddenException({code:'CONFIGURATION_SOURCE_HANDLE_INVALID'});return proof;}),
  assertResponse:vi.fn(async(candidate:object,path:string,result:any)=>{if(candidate!==handle||!state.active||state.rawChanged)throw new ForbiddenException({code:'SOURCE_RECOVERY_MATERIAL_CHANGED'});if(path===point&&result.key!=='synthetic-private-key')throw new ForbiddenException({code:'SOURCE_RECOVERY_MATERIAL_CHANGED'});})};
 context.installPromotionRecoveryReadPolicy(provider);
 const policy=new NativeKongPolicyService({}as any,secrets,{}as any,context,{}as any,{}as any);policy.install();
 const request=async(path:string,method='GET',body?:unknown,query:Record<string,string|number>={},actualCluster=cluster)=>{
  const ticket=await context.authorizeRequest(actualCluster,method,path,body,query);await context.assertGovernanceBeforeSend(ticket);await context.beforeNativeSend(ticket);
  requests.push({path,method,cluster:actualCluster.id,actor:context.current().actor!.id,sid:context.current().sessionId});
  const result=responses.get(path),raw=typeof result==='function'?result(query):structuredClone(result);return context.authorizeResponse(ticket,raw);
 };
 const run=<T>(fn:()=>Promise<T>,mode:'bootstrap'|'read'='read')=>context.runHttp({requestId:randomUUID()},async()=>{
  context.bindHttpActor(actor,sid);const close=context.captureHttpCloser(),originFrame=context.current();
  proof={mode,actor,sessionId:sid,clusterId:cid,workspaceId:wid,transportScope:cluster.transport_scope,permissionVersion:'real-owner:1:1',credentialEpoch:1,expiresAt:Date.now()+600000,originFrame,
   pointPaths:mode==='read'?[point]:[],credentialCollections:[],schemaPaths:mode==='read'?[schema]:[]};
  try{return await context.runActor({actor,clusterId:targetCid,workspaceId:targetWid,module:'snapshots',action:'write'},fn);}finally{close();}
 });
 return{context,actor,cid,wid,targetCid,targetWid,sid,certificate,consumer,credential,cluster,point,collection,schema,handle,provider,requests,responses,state,run,request,
  get proof(){return proof;},set proof(value:PromotionRecoveryReadProof){proof=value;}};
}
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','dd'.repeat(32)));afterEach(()=>{vi.unstubAllEnvs();vi.useRealTimers();});
describe('M10 private promotion recovery GET namespace',()=>{
 it('isolates source read from actual target write ancestry and preserves the real owner/session',async()=>{
  const f=fixture();await f.run(()=>f.context.runOperation({actor:f.actor,clusterId:f.targetCid,workspaceId:f.targetWid,module:'snapshots',action:'update',operationId:randomUUID(),entityType:'services',entityId:randomUUID()},()=>f.context.runPromotionRecoveryRead(f.handle,async()=>{
   const frame=f.context.current();expect(frame).toMatchObject({clusterId:f.cid,workspaceId:f.wid,sessionId:f.sid,purpose:'promotion-recovery',action:'read'});expect(frame.operation).toBeUndefined();expect(frame.archive).toBeUndefined();expect(()=>f.context.currentApprovedStep()).toThrow();
   expect(await f.request(f.point)).toMatchObject({key:'synthetic-private-key'});expect(await f.request(f.schema)).toMatchObject({fields:expect.any(Array)});
  })));expect(f.requests.every(r=>r.cluster===f.cid&&r.actor===f.actor.id&&r.sid===f.sid&&r.method==='GET')).toBe(true);expect(f.provider.assertResponse).toHaveBeenCalledTimes(2);
 });
 it('bootstrap permits SQL-only source scope and upgrades once to a genuine attached read claim between scopes',async()=>{
  const f=fixture();await f.run(async()=>{
   await f.context.runPromotionRecoveryRead(f.handle,async()=>{expect(f.context.current().clusterId).toBe(f.cid);await expect(f.request(f.point)).rejects.toMatchObject({status:403});});
   f.proof={...f.proof,mode:'read',pointPaths:[f.point],schemaPaths:[f.schema]};
   await f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.point));
   f.proof={...f.proof,mode:'bootstrap',pointPaths:[],schemaPaths:[]};await expect(f.context.runPromotionRecoveryRead(f.handle,async()=>{})).rejects.toMatchObject({response:{code:'PROMOTION_RECOVERY_CHANGED'}});
  },'bootstrap');expect(f.requests).toHaveLength(1);
 });
 it.each(['copied-handle','plain-handle','other-actor','other-sid','expired','changed-permission','changed-origin'])('rejects %s instead of granting a raw source read',async(kind)=>{
  const f=fixture();await f.run(async()=>{
   const input=kind==='copied-handle'?{...f.handle}:kind==='plain-handle'?{clusterId:f.cid,approved:true}:f.handle;
   if(kind==='other-actor')f.proof={...f.proof,actor:{...f.actor,id:randomUUID()}};if(kind==='other-sid')f.proof={...f.proof,sessionId:randomUUID()};if(kind==='expired')f.proof={...f.proof,expiresAt:Date.now()-1};
   if(kind==='changed-permission'||kind==='changed-origin'){await f.context.runPromotionRecoveryRead(f.handle,async()=>{});if(kind==='changed-permission')f.proof={...f.proof,permissionVersion:'revoked'};else f.proof={...f.proof,originFrame:{...f.proof.originFrame}as any};}
   await expect(f.context.runPromotionRecoveryRead(input,()=>f.request(f.point))).rejects.toMatchObject({status:403});
  });expect(f.requests).toHaveLength(0);
 });
 it.each(['POST','PATCH','PUT','DELETE'])('rejects %s even under a nested operation claiming source entity write permission',async(method)=>{
  const f=fixture();await f.run(()=>f.context.runPromotionRecoveryRead(f.handle,()=>f.context.runOperation({actor:f.actor,clusterId:f.cid,workspaceId:f.wid,operationId:randomUUID(),entityType:'certificates',entityId:f.certificate,action:'update'},async()=>{
   await expect(f.request(f.point,method,{key:'forged'})).rejects.toMatchObject({status:403});
  })));expect(f.requests).toHaveLength(0);
 });
 it.each(['/','/plugins/enabled','/services','/status','/cache/secret','/clustering','/vaults','/schemas/plugins/key-auth'])('denies outside-whitelist path %s',async(path)=>{
  const f=fixture();await f.run(()=>f.context.runPromotionRecoveryRead(f.handle,async()=>{await expect(f.request(path)).rejects.toMatchObject({status:403});}));expect(f.requests).toHaveLength(0);
 });
 it('checks current ConfigAccess/secrets authority before DNS/send and again before raw response leaves the namespace',async()=>{
  const f=fixture();await f.run(()=>f.context.runPromotionRecoveryRead(f.handle,async()=>{
   const ticket=await f.context.authorizeRequest(f.cluster,'GET',f.point,undefined,{});f.state.active=false;
   await expect(f.context.assertGovernanceBeforeSend(ticket)).rejects.toMatchObject({response:{code:'CONFIGURATION_SOURCE_HANDLE_INVALID'}});f.state.active=true;f.state.rawChanged=true;
   await expect(f.context.authorizeResponse(ticket,{id:f.certificate,key:'synthetic-private-key'})).rejects.toMatchObject({response:{code:'SOURCE_RECOVERY_MATERIAL_CHANGED'}});
  }));expect(f.requests).toHaveLength(0);
 });
 it('same opaque handle retains the cumulative call budget across separate checks and transport retries',async()=>{
  const f=fixture();await f.run(async()=>{
   for(let i=0;i<3;i++)await f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.point));
   await f.context.runPromotionRecoveryRead(f.handle,async()=>{const ticket=await f.context.authorizeRequest(f.cluster,'GET',f.point,undefined,{});for(let i=0;i<496;i++)f.context.chargeRetry(ticket);
    await expect(f.context.refreshAuthorization(ticket)).resolves.toBeUndefined();await expect(f.context.assertGovernanceBeforeSend(ticket)).resolves.toBeUndefined();});
   await expect(f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.point))).rejects.toMatchObject({status:403});
  });expect(f.requests).toHaveLength(3);
 });
 it('preflight reads exact persistent point/page/byte usage only under the genuine current owner/session',async()=>{
  const f=fixture();await f.run(async()=>{
   await expect(f.context.promotionRecoveryUsage({...f.handle})).rejects.toMatchObject({status:403});
   await f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.point));const first=await f.context.promotionRecoveryUsage(f.handle);
   expect(first).toMatchObject({calls:1,pages:0,records:1});expect(first.bytes).toBeGreaterThan(0);
   await f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.point));const second=await f.context.promotionRecoveryUsage(f.handle);
   expect(second.calls).toBe(2);expect(second.records).toBe(2);expect(second.bytes).toBe(first.bytes*2);expect(second.deadline).toBe(first.deadline);
   f.state.active=false;await expect(f.context.promotionRecoveryUsage(f.handle)).rejects.toMatchObject({response:{code:'CONFIGURATION_SOURCE_HANDLE_INVALID'}});
  });
 });
 it('credential collections enforce exact source parent, ordered opaque offsets and actual EOF',async()=>{
  const f=fixture();f.responses.set(f.collection,(query:any)=>query.offset?{data:[],next:null}:{data:[{id:f.credential,key:'synthetic-private-key',consumer:{id:f.consumer}}],next:`${f.collection}?offset=second-page`});
  await f.run(async()=>{f.proof={...f.proof,credentialCollections:[f.collection]};await f.context.runPromotionRecoveryRead(f.handle,async()=>{
   await expect(f.request(f.collection,'GET',undefined,{size:100,offset:'forged'})).rejects.toMatchObject({status:403});
   await f.request(f.collection,'GET',undefined,{size:100});await f.request(f.collection,'GET',undefined,{size:100,offset:'second-page'});
   await expect(f.request(f.collection,'GET',undefined,{size:100})).rejects.toMatchObject({status:403});
  });});expect(f.requests).toHaveLength(2);
 });
 it('never reports a partial credential page as a completed private read',async()=>{
  const f=fixture();f.responses.set(f.collection,{data:[],next:`${f.collection}?offset=more`});await f.run(async()=>{f.proof={...f.proof,credentialCollections:[f.collection]};
   await expect(f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.collection))).rejects.toMatchObject({response:{code:'PROMOTION_RECOVERY_PAGINATION_INCOMPLETE'}});
  });
 });
 it.each(['foreign-parent','duplicate-id','cross-page-duplicate','foreign-next-host','url-credentials','foreign-next-path','next-cycle','changed-size'])('rejects credential collection %s',async(kind)=>{
  const f=fixture();f.responses.set(f.collection,(q:any)=>{const data=[{id:f.credential,consumer:{id:kind==='foreign-parent'?randomUUID():f.consumer},key:'synthetic-private-key'}];
   if(kind==='duplicate-id')data.push({...data[0]});let next=kind==='foreign-next-host'?`http://attacker.test${f.collection}?offset=more`:kind==='url-credentials'?`http://user:password@source-kong:8001${f.collection}?offset=more`:kind==='foreign-next-path'?'/consumers/wrong/key-auth?offset=more':kind==='changed-size'?`${f.collection}?size=1&offset=more`:kind==='next-cycle'||kind==='cross-page-duplicate'&&!q.offset?`${f.collection}?offset=more`:null;
   return{data,next};});
  await f.run(async()=>{f.proof={...f.proof,credentialCollections:[f.collection]};await expect(f.context.runPromotionRecoveryRead(f.handle,async()=>{await f.request(f.collection);if(kind==='next-cycle'||kind==='cross-page-duplicate')await f.request(f.collection,'GET',undefined,{offset:'more'});})).rejects.toMatchObject({status:403});});
 });
 it('revalidates a current source permit before a GET retry after server failure',async()=>{
  const f=fixture();await expect(f.run(()=>f.context.runPromotionRecoveryRead(f.handle,async()=>{const ticket=await f.context.authorizeRequest(f.cluster,'GET',f.point,undefined,{});
   f.context.chargeRetry(ticket);f.state.active=false;await expect(f.context.refreshAuthorization(ticket)).rejects.toMatchObject({response:{code:'CONFIGURATION_SOURCE_HANDLE_INVALID'}});
  }))).rejects.toMatchObject({response:{code:'CONFIGURATION_SOURCE_HANDLE_INVALID'}});expect(f.requests).toHaveLength(0);
 });
 it('shared 120-second deadline cannot be renewed by repeated read scopes',async()=>{
  vi.useFakeTimers();const f=fixture();await f.run(async()=>{await f.context.runPromotionRecoveryRead(f.handle,async()=>{});vi.setSystemTime(Date.now()+120001);
   await expect(f.context.runPromotionRecoveryRead(f.handle,async()=>{})).rejects.toMatchObject({status:403});});
 });
 it('the shared page budget cannot be reset by repeatedly scanning an EOF credential collection',async()=>{
  const f=fixture();f.responses.set(f.collection,{data:[],next:null});await f.run(async()=>{f.proof={...f.proof,credentialCollections:[f.collection]};
   for(let i=0;i<100;i++)await f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.collection));
   await expect(f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.collection))).rejects.toMatchObject({response:{code:'PROMOTION_RECOVERY_BUDGET_EXHAUSTED'}});
  });expect(f.requests).toHaveLength(100);
 });
 it('point records share the ten-thousand record cap with credential pages',async()=>{
  const f=fixture(),data=Array.from({length:100},()=>({id:randomUUID(),consumer:{id:f.consumer},key:'synthetic-private-key'}));f.responses.set(f.collection,{data,next:null});
  await f.run(async()=>{f.proof={...f.proof,credentialCollections:[f.collection]};for(let i=0;i<99;i++)await f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.collection));
   await expect(f.context.runPromotionRecoveryRead(f.handle,async()=>{for(let i=0;i<101;i++)await f.request(f.point);})).rejects.toMatchObject({response:{code:'PROMOTION_RECOVERY_BUDGET_EXHAUSTED'}});
  });expect(f.requests).toHaveLength(200);
 });
 it('the 32MiB byte cap is cumulative across private scopes rather than per response',async()=>{
  const f=fixture();f.responses.set(f.point,{id:f.certificate,key:'synthetic-private-key',cert:'x'.repeat(1024*1024)});
  await f.run(async()=>{for(let i=0;i<31;i++)await f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.point));
   await expect(f.context.runPromotionRecoveryRead(f.handle,()=>f.request(f.point))).rejects.toMatchObject({status:403});
  });expect(f.requests).toHaveLength(32);
 });
});
