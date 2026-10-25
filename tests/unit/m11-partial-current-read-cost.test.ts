import 'reflect-metadata';
import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {randomUUID,createHash} from 'node:crypto';
import {HttpException} from '@nestjs/common';
import {SecretService} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {KongService} from '../../apps/console-api/src/infrastructure/kong/kong.service';
import {outboundJson} from '../../apps/console-api/src/infrastructure/kong/outbound';
import {NativeKongPolicyService} from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import {GraphCapturerService} from '../../apps/console-api/src/modules/recycle-bin/graph-capturer.service';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn(),outboundText:vi.fn()}));
const transport=vi.mocked(outboundJson);
/** Real Context/NativePolicy/KongService/GraphCapturer; authority SQL and
 * native responses are controlled source adapters, not runtime acceptance. */
function fixture(){
  const cid=randomUUID(),wid=randomUUID(),consumer=randomUUID(),sid=randomUUID(),user:any={id:randomUUID(),username:'controlled-cost-owner',superAdmin:false},context=new KongExecutionContextService(),secrets=new SecretService();
  const kinds=['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'],parent={id:consumer,username:'unit-consumer',tags:['workspace:unit']};
  const nodes=[{type:'consumers',id:consumer,path:`/consumers/${consumer}`,data:parent},...kinds.map(kind=>{const id=randomUUID();return{type:kind,id,path:`/consumers/${consumer}/${kind}/${id}`,data:{id,consumer:{id:consumer},...(kind==='basic-auth'?{username:'unit-basic',password:createHash('sha1').update('unit-password'+consumer).digest('hex')}:{})}};})];
  const live=new Map(nodes.slice(0,5).map(n=>[n.path,n.data])),cluster:any={id:cid,revision:1,execution_mode:'approval',admin_url:'http://kong:8001',version:'1.5.1',status:'healthy',capabilities:{}};
  const db:any={one:vi.fn(async(sql:string)=>{if(sql.includes('FROM clusters'))return cluster;throw Error('Unexpected cost fixture SQL');}),exec:vi.fn(async()=>1)};
  const redis:any={rateLimit:vi.fn(async()=>({allowed:true})),assertLeaseActive:vi.fn(),assertLeaseOwnership:vi.fn(async()=>undefined)};
  const authz:any={snapshot:vi.fn(async()=>({user,version:'unit-current',grants:[{cluster_id:cid}]})),permissionVersion:vi.fn(async()=> 'unit-current'),assertCluster:vi.fn(async()=>undefined),assertEntity:vi.fn(async()=>undefined),assertNestedParentScope:vi.fn(async()=>undefined),filterEntities:vi.fn(async(_u:any,_c:any,_t:any,x:any)=>x)};
  const scope={clusterId:cid,workspaceId:wid,code:'unit'},workspaces:any={listScope:vi.fn(async()=>scope),resolve:vi.fn(async()=>({id:wid})),assertMembership:vi.fn(),matches:vi.fn(()=>true)};
  const kong=new KongService(db,redis,secrets,{} as any,context),policy=new NativeKongPolicyService(db,secrets,kong,context,authz,workspaces);policy.install();
  const custody:any={getRestorePayload:vi.fn(async(_c:any,_p:any,kind:string,_id:any,raw:any)=>({...raw,...(kind==='basic-auth'?{password:'unit-password'}:{})}))};
  const graphs=new GraphCapturerService(kong,custody,context);
  transport.mockImplementation(async(_base,path,method,_body,_query,_auth,_timeout,fence,prepare)=>{
    expect(method).toBe('GET');await prepare?.();fence?.();
    if(live.has(path))return{status:200,body:live.get(path),bytes:100};
    const kind=kinds.find(kind=>path===`/consumers/${consumer}/${kind}`);
    if(kind)return{status:200,body:{data:nodes.filter(n=>n.type===kind&&live.has(n.path)).map(n=>live.get(n.path)),next:null},bytes:100};
    if(path==='/plugins')return{status:200,body:{data:[],next:null},bytes:20};
    return{status:404,body:{message:'Not found'},bytes:20};
  });
  const run=(fn:()=>Promise<any>)=>context.runHttp({},async()=>{context.bindHttpActor(user,sid);return context.runActor({actor:user,clusterId:cid,workspaceId:wid,module:'workflows',action:'write'},fn);});
  const points=()=>context.runInternalRead(cid,'recycle-check',async()=>{for(const node of nodes){try{const raw=await kong.request(cid,'GET',node.path);expect(raw.id).toBe(node.id);}catch(error){if(!(error instanceof HttpException&&error.getStatus()===404&&['hmac-auth','acls'].includes(node.type)))throw error;}}
    return context.currentUsage();},{paths:nodes.map(n=>n.path),maxCalls:7,maxPages:1,maxRecords:7,maxBytes:16*1024*1024,timeoutMs:120000,workspaceId:wid});
  return{run,points,context,kong,graphs,cid,wid,consumer,nodes,live,authz};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));vi.stubEnv('KONG_RATE_WAIT_MS','0');transport.mockReset();});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllEnvs();});
describe('M11 actual private-read cost accounting (source adapters)',()=>{
  it('reads five original points and two missing credentials within the exact current seven-point budget',async()=>{
    const f=fixture(),usage=await f.run(()=>f.points());expect(usage).toMatchObject({calls:7,pages:0,records:0});expect(transport).toHaveBeenCalledTimes(7);
    expect(f.authz.assertCluster).toHaveBeenCalledTimes(7);expect(f.authz.assertNestedParentScope).not.toHaveBeenCalled();
  });
  it('rejects a foreign point before the controlled transport with the original exact path allowlist',async()=>{
    const f=fixture();await f.run(()=>f.context.runInternalRead(f.cid,'recycle-check',()=>expect(f.kong.request(f.cid,'GET',`/consumers/${randomUUID()}`)).rejects.toMatchObject({response:{code:'KONG_INTERNAL_PATH_FORBIDDEN'}}),{paths:f.nodes.map(n=>n.path),maxCalls:7,maxPages:1,maxRecords:7,maxBytes:16*1024*1024}));expect(transport).not.toHaveBeenCalled();
  });
  it('captures actual collection EOF costs in the ancestor rather than adding fictitious parent authorization reads',async()=>{
    const f=fixture();await f.run(async()=>{const graph=await f.graphs.capture(f.cid,'consumers',f.consumer,{purpose:'baseline',budget:{maxPages:100,maxRecords:10000,maxNodes:1000,maxBytes:16*1024*1024}});
      expect(graph.nodes).toHaveLength(5);expect(f.context.currentUsage()).toMatchObject({calls:8,pages:7,records:4});
      const points=await f.points();expect(points).toMatchObject({calls:7,pages:0,records:0});expect(f.context.currentUsage()).toMatchObject({calls:15,pages:7,records:4});});
  });
  it('reproduces RESPONSE_LIMIT after repeated graph EOF checkpoints exceed the same genuine ancestor 100-page ceiling',async()=>{
    const f=fixture();await f.run(async()=>{for(let i=0;i<14;i++)await f.graphs.capture(f.cid,'consumers',f.consumer,{purpose:'baseline',budget:{maxPages:100,maxRecords:10000,maxNodes:1000,maxBytes:16*1024*1024}});
      expect(f.context.currentUsage()).toMatchObject({pages:98,records:56});
      await expect(f.graphs.capture(f.cid,'consumers',f.consumer,{purpose:'baseline',budget:{maxPages:100,maxRecords:10000,maxNodes:1000,maxBytes:16*1024*1024}})).rejects.toMatchObject({response:{code:'KONG_EXECUTION_RESPONSE_LIMIT'}});
    });
  });
});
