import 'reflect-metadata';
import {randomUUID} from 'node:crypto';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {NativeKongPolicyService} from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import {DEFAULT_WORKSPACE_ID as wid,workspaceTestResolver} from './workspace-test-helper';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn(),outboundText:vi.fn()}));
const transport=vi.mocked(outboundJson);

/** Real Context/NativePolicy/KongService/private receipt registries. SQL,
 * current grants, leases and wire responses are explicit SOURCE adapters;
 * these are not actual HTTP, approvals, Runtime204 or PostgreSQL evidence. */
function fixture(status=204,rawBody:unknown=null,bytes=0){
  const cid=randomUUID(),upstream=randomUUID(),target=randomUUID(),operationId=randomUUID(),sid=randomUUID(),secrets=new SecretService(),execution=new KongExecutionContextService(),
    actor={id:randomUUID(),username:'fixture',superAdmin:true},before={id:target,target:'echo.internal:8080',weight:100,tags:[],created_at:1,upstream:{id:upstream}},
    path=`/upstreams/${upstream}/targets/${target}/unhealthy`,cluster:any={id:cid,admin_url:'http://kong:8001',connection_secret:null,version:'1.5.1',capabilities:{},execution_mode:'direct',status:'healthy',revision:1},
    operation:any={id:operationId,cluster_id:cid,workspace_id:wid,actor_id:actor.id,entity_id:target,entity_type:'targets',parent_id:upstream,action:'mark_unhealthy',state:'running',remote_started:true,
      before_secret:secrets.encrypt(before,`mutation:${operationId}:before`),payload_secret:secrets.encrypt({state:'unhealthy'},`mutation:${operationId}:payload`)},
    db:any={one:vi.fn(async(sql:string)=>sql.includes('FROM clusters')?cluster:sql.includes('FROM mutation_operations')?operation:null),exec:vi.fn(async()=>1),query:vi.fn(async()=>[])},
    redis:any={withLock:vi.fn(async(_key:string,fn:any)=>fn()),assertLeaseActive:vi.fn(),assertLeaseOwnership:vi.fn(async()=>undefined),rateLimit:vi.fn(async()=>({allowed:true,retryAfterMs:0}))},
    authz:any={snapshot:vi.fn(async()=>({user:actor,grants:[],version:'fixture-permissions'})),permissionVersion:vi.fn(async()=> 'fixture-permissions'),assertCluster:vi.fn(),assertWholeCluster:vi.fn(),assertEntity:vi.fn(),assertNestedParentScope:vi.fn()},
    kong=new KongService(db,redis,secrets,{} as any,execution),policy=new NativeKongPolicyService(db,secrets,kong,execution,authz,workspaceTestResolver(cid).resolver);
  policy.install();let sends=0;
  transport.mockImplementation(async(_base,requestPath,method,_body,query,_auth,_timeout,fence,prepare)=>{
    await prepare?.();fence?.();
    if(method==='POST'){sends++;return{status,body:structuredClone(rawBody),bytes,jsonParsed:bytes>0};}
    if(requestPath===`/upstreams/${upstream}`)return{status:200,body:{id:upstream,name:'fixture-upstream',tags:[]},bytes:80,jsonParsed:true};
    if(requestPath===`/upstreams/${upstream}/targets/${target}`)return{status:200,body:structuredClone(before),bytes:120,jsonParsed:true};
    if(requestPath===`/upstreams/${upstream}/targets`)return{status:200,body:{data:[structuredClone(before)],next:null},bytes:160,jsonParsed:true};
    throw Error('Unexpected SOURCE transport path: '+requestPath+' '+JSON.stringify(query));
  });
  const run=(callback:(frame:any)=>Promise<any>)=>execution.runHttp({requestId:'fixture-health-request'},async()=>{
    execution.bindHttpActor(actor,sid);const close=execution.captureHttpCloser();
    try{return await execution.runActor({actor,clusterId:cid,workspaceId:wid,module:'targets',action:'mark_unhealthy'},()=>execution.runOperation({actor,clusterId:cid,workspaceId:wid,operationId,entityType:'targets',entityId:target,parentId:upstream,action:'mark_unhealthy'},()=>callback(execution.current())));}
    finally{close();}
  });
  return{kong,execution,secrets,path,run,operationId,cid,sends:()=>sends};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','af'.repeat(32));transport.mockReset();});afterEach(()=>vi.unstubAllEnvs());
describe('original Target health transport receipt',()=>{
  it('records only a real adapter-observed204/empty response and consumes it once inside the original operation frame',async()=>{
    const f=fixture();await f.run(async frame=>{
      expect(await f.kong.request(f.cid,'POST',f.path)).toBeNull();
      expect(()=>f.kong.consumeTargetHealthTransportReceipt({...frame})).toThrow();
      const actual=f.kong.consumeTargetHealthTransportReceipt(frame);
      expect(actual).toMatchObject({kind:'original-target-health-transport-response',operationId:f.operationId,nativeStatus:204,rawResponse:null,responseBytes:0,emptyBody:true,contractValid:true,responseHmac:f.secrets.fingerprint(null)});
      expect(f.kong.consumeTargetHealthTransportReceipt(frame)).toBeUndefined();expect(f.sends()).toBe(1);
    });
  });
  it.each([[200,null,0],[201,null,0],[204,{id:'synthetic'},20],[204,null,4]])('rejects observed status/body/bytes %j without substituting a success receipt',async(status,body,bytes)=>{
    const f=fixture(status as number,body,bytes as number);await f.run(async frame=>{
      await expect(f.kong.request(f.cid,'POST',f.path)).rejects.toMatchObject({response:{code:'TARGET_HEALTH_NATIVE_RESPONSE_INVALID'}});
      expect(f.kong.consumeTargetHealthTransportReceipt(frame)).toMatchObject({nativeStatus:status,rawResponse:body,responseBytes:bytes,contractValid:false});expect(f.sends()).toBe(1);
    });
  });
  it('retains an original rejected4xx response as observed rejection, not completion',async()=>{
    const body={message:'Target rejected'},f=fixture(400,body,28);await f.run(async frame=>{
      await expect(f.kong.request(f.cid,'POST',f.path)).rejects.toMatchObject({status:400});
      expect(f.kong.consumeTargetHealthTransportReceipt(frame)).toMatchObject({nativeStatus:400,rawResponse:body,contractValid:false});
    });
  });
  it('blocks a second send in the original frame even after consumption',async()=>{
    const f=fixture();await f.run(async frame=>{
      await f.kong.request(f.cid,'POST',f.path);f.kong.consumeTargetHealthTransportReceipt(frame);
      await expect(f.kong.request(f.cid,'POST',f.path)).rejects.toMatchObject({response:{code:'TARGET_HEALTH_TRANSPORT_ALREADY_SPENT'}});expect(f.sends()).toBe(1);
    });
  });
  it('does not let a foreign HTTP actor frame consume a retained original response',async()=>{
    const f=fixture();let original:any;
    await f.run(async frame=>{original=frame;await f.kong.request(f.cid,'POST',f.path);});
    expect(()=>f.kong.consumeTargetHealthTransportReceipt(original)).toThrow();
  });
});
