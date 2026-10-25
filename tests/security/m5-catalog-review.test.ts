import 'reflect-metadata';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { MetricsCatalogService } from '../../apps/console-api/src/modules/vitals/bridges/metrics-catalog.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';

const cid='721bfeda-dc12-4d7a-b33e-06b2879a7ead',sid='14368d69-dd76-46f6-b490-583893b13cba',rid='cd7ce64b-e7b0-4b39-9086-c55b7b5f8d9e',uid='f4095396-0771-4b02-9f09-2739a1809c0d';
const firstNode='40246f11-52ee-43c2-8ca9-71976d078848',secondNode='6d5a920e-e5d6-4b9b-a731-0759b7a21191',physical='a'.repeat(64),canary='SYNTHETIC-NATIVE-CREDENTIAL-CANARY';
const deferred=()=>{let resolve!:(value?:any)=>void;const promise=new Promise<any>(done=>{resolve=done;});return {promise,resolve};};
beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','cd'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
function fixture(){
 const execution=new KongExecutionContextService(),cluster={id:cid,version:'1.5.1',enabled_plugins:['prometheus'],status:'connected'};
 const lists:any={services:[{id:sid,name:'s',host:'safe.example',tags:[],client_certificate:{key:canary}}],routes:[{id:rid,name:'r',service:{id:sid},tags:[],private_config:canary}],consumers:[{id:uid,username:'u',tags:[],credentials:canary}]};
 const state={ready:false,nodes:[firstNode,firstNode],gate:undefined as Promise<any>|undefined,rows:undefined as ((type:string,page:number)=>any)|undefined};let nodeCall=0,pageCount=0;
 const settings:any={get:vi.fn(async()=>({state:state.ready?'ready':'pending',catalogRevision:1,lastVerifiedAt:new Date().toISOString(),maxAgeMs:15000}))};
 const db:any={query:vi.fn(async()=>[])},repository:any={publishVerifiedCatalog:vi.fn(async()=>{state.ready=true;return {catalogRevision:2};})};
 const kong:any={transportScope:vi.fn(async()=>physical),request:vi.fn(async(_cid:string,method:string,path:string)=>{
  const ticket=await execution.authorizeRequest(cluster,method,path,undefined,{});return execution.authorizeResponse(ticket,{version:'1.5.1',node_id:state.nodes[Math.min(nodeCall++,state.nodes.length-1)]});
 }),list:vi.fn(async(_cid:string,path:string,query:any)=>{
  const ticket=await execution.authorizeRequest(cluster,'GET',path,undefined,query);await state.gate;const type=path.slice(1),page=state.rows?.(type,++pageCount)??{items:lists[type],nextCursor:null,size:query.size};
  await execution.authorizeResponse(ticket,{data:page.items,next:page.nextCursor});return page;
 })};
 const policy=new NativeKongPolicyService(db,new SecretService(),kong,execution,{} as any,{} as any);policy.install();
 const service=new MetricsCatalogService(kong,execution,repository,settings,db);return {service,state,lists,kong,repository};
}
describe('M5 independent catalog scan completeness, native-node proof and refresh coalescing',()=>{
 it('publishes only minimal stable native identities from complete scans, stripping credential-bearing extras',async()=>{
  const f=fixture();await f.service.scan(cid);expect(f.repository.publishVerifiedCatalog).toHaveBeenCalledOnce();const input=f.repository.publishVerifiedCatalog.mock.calls[0][0];
  expect(input).toMatchObject({cid,nodeId:physical,observedKongNodeId:firstNode,complete:true,expectedCatalogRevision:1});expect(input.routePairs[0]).toEqual({service:{id:sid,name:'s',host:'safe.example',tags:[]},route:{id:rid,name:'r',service:{id:sid},tags:[]}});expect(input.consumers).toEqual([{id:uid,username:'u',custom_id:undefined,tags:[]}]);expect(JSON.stringify(input)).not.toContain(canary);
 });
 it('rejects native node rollover or a cursor loop before publishing a falsely complete directory',async()=>{
  const rollover=fixture();rollover.state.nodes=[firstNode,secondNode];await expect(rollover.service.scan(cid)).rejects.toMatchObject({response:{code:'METRICS_NATIVE_NODE_CHANGED'}});expect(rollover.repository.publishVerifiedCatalog).not.toHaveBeenCalled();
  const loop=fixture();loop.state.rows=()=>({items:[],nextCursor:'same-cursor',size:100});await expect(loop.service.scan(cid)).rejects.toMatchObject({response:{code:'METRICS_CATALOG_CURSOR_LOOP'}});expect(loop.repository.publishVerifiedCatalog).not.toHaveBeenCalled();expect(loop.kong.list).toHaveBeenCalledTimes(2);
 });
 it('rejects duplicate native identities instead of using last-write-wins mappings',async()=>{
  for(const type of ['services','routes','consumers']){const f=fixture();f.lists[type].push({...f.lists[type][0]});await expect(f.service.scan(cid)).rejects.toMatchObject({status:409});expect(f.repository.publishVerifiedCatalog).not.toHaveBeenCalled();}
 });
 it('stops a paginated directory at100 pages and never publishes a partial uniqueness proof',async()=>{
  const f=fixture();f.state.rows=(_type,page)=>({items:[],nextCursor:`offset-${page}`,size:100});await expect(f.service.scan(cid)).rejects.toMatchObject({response:{code:'METRICS_CATALOG_BUDGET_EXHAUSTED'}});expect(f.kong.list).toHaveBeenCalledTimes(100);expect(f.repository.publishVerifiedCatalog).not.toHaveBeenCalled();
 });
 it('coalesces concurrent freshness requests into one complete scan without resolving early',async()=>{
  const f=fixture(),gate=deferred();f.state.gate=gate.promise;let firstDone=false,secondDone=false;
  const first=f.service.ensureFresh(cid).then(()=>{firstDone=true;});for(let turn=0;turn<10&&!f.kong.list.mock.calls.length;turn++)await new Promise(resolve=>setImmediate(resolve));
  const second=f.service.ensureFresh(cid).then(()=>{secondDone=true;});await new Promise(resolve=>setImmediate(resolve));expect(firstDone).toBe(false);expect(secondDone).toBe(false);expect(f.kong.list).toHaveBeenCalledTimes(1);
  gate.resolve();await Promise.all([first,second]);expect(f.repository.publishVerifiedCatalog).toHaveBeenCalledOnce();expect(f.kong.list).toHaveBeenCalledTimes(3);await f.service.ensureFresh(cid);expect(f.kong.list).toHaveBeenCalledTimes(3);
 });
 it('does not lift a public HTTP actor into a catalog system scan',async()=>{
  const f=fixture();const execution=(f.service as any).execution as KongExecutionContextService;
  await expect(execution.runHttp({},()=>{execution.bindHttpActor({id:uid,username:'public-user',superAdmin:true});return f.service.scan(cid);})).rejects.toMatchObject({status:403});expect(f.kong.list).not.toHaveBeenCalled();expect(f.repository.publishVerifiedCatalog).not.toHaveBeenCalled();
 });
});
