import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { VitalsService } from '../../apps/console-api/src/modules/vitals/vitals.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
vi.mock('../../apps/console-api/src/infrastructure/kong/outbound',()=>({outboundJson:vi.fn()}));
const transport=vi.mocked(outboundJson);
const cid='721bfeda-dc12-4d7a-b33e-06b2879a7ead',wid='a109e333-40a0-4965-966b-6b810f54e9b6',id='14368d69-dd76-46f6-b490-583893b13cba',eid='40246f11-52ee-43c2-8ca9-71976d078848';
const user={id,username:'monitor-user',superAdmin:false},actor={user,idempotencyKey:'metrics-test-key'},now=Date.parse('2026-10-10T12:00:00.000Z');
const query={workspaceId:wid,start:'2026-10-10T11:55:00Z',end:'2026-10-10T12:00:00Z'};
const body=(rows:any[],type='matrix')=>({status:200,body:{status:'success',data:{resultType:type,result:rows}}});
const deferred=()=>{let resolve!:(value?:any)=>void;const promise=new Promise<any>(done=>{resolve=done;});return {promise,resolve};};
beforeEach(()=>{transport.mockReset();vi.spyOn(Date,'now').mockReturnValue(now);});afterEach(()=>vi.restoreAllMocks());
function fixture(){
 const execution=new KongExecutionContextService(),state={blocked:false,epochRemoved:false,permissionVersion:'p1',sourceChanged:false,settingsRevision:1,catalogRevision:1,generation:1,platform:false,approval:false};
 const epoch={epoch_id:eid,cluster_id:cid,node_id:'a'.repeat(64),entity_type:'routes',entity_id:id,workspace_id:wid,service_id:id,route_id:id,consumer_id:null,tags:[],valid_from:new Date(now-600000).toISOString(),verified_until:new Date(now+15000).toISOString(),closed_at:null,quality:'verified'};
 const resolved:any={workspaceId:wid,mode:'workspace',version:'p1',wholeCluster:false,epochs:[epoch],consumerPairEpochs:[],serviceNames:new Map([[id,'display-name']]),consumerNames:new Map()};
 const scope:any={workspace:vi.fn(async()=>wid),resolve:vi.fn(async()=>resolved),stable:vi.fn(async(_actor,version)=>{if(version!==state.permissionVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});})};
 const source:any={id,name:'private-provider',type:'prometheus',baseUrl:'http://approved-prom:9090',auth:{type:'bearer',token:'SYNTHETIC-SECRET-ONLY-SERVER'},revision:1};
 const sources:any={list:vi.fn(async()=>[{id,name:source.name,type:source.type,status:'healthy',availability:'available'}]),read:vi.fn(async()=>source),public:vi.fn(value=>({id:value.id,name:value.name,type:value.type,status:'healthy',availability:'available'})),assertCurrent:vi.fn(async()=>{if(state.sourceChanged)throw new ForbiddenException({code:'METRICS_SOURCE_CHANGED'});})};
 const settings:any={get:vi.fn(async()=>({revision:state.settingsRevision,catalogRevision:state.catalogRevision,credentialGeneration:state.generation,state:'ready',enabled:true,collectorEnabled:false,activeSourceId:id,lastVerifiedAt:new Date(now).toISOString(),maxAgeMs:15000}))};
 const authz:any={permissionVersion:vi.fn(async()=>state.permissionVersion),hasWholeCluster:vi.fn(async()=>resolved.wholeCluster),isPlatformAdmin:vi.fn(async()=>state.platform),assertCluster:vi.fn(async()=>undefined)};
 const db:any={one:vi.fn(async()=>({id:cid,name:'test-cluster',version:'1.5.1',enabled_plugins:['prometheus'],status:'connected',execution_mode:state.approval?'approval':'direct',revision:1}))};
 const repository:any={currentAllowedEpochs:vi.fn(async()=>({catalogRevision:state.catalogRevision,items:state.epochRemoved?[]:[epoch],blocked:state.blocked,warnings:[]}))};
 const entities:any={create:vi.fn(),update:vi.fn()},credentials:any={getActiveIngestCredential:vi.fn()};
 const service=new VitalsService(scope,sources,settings,authz,db,repository,{} as any,execution,entities,{} as any,credentials,{} as any);
 const run=<T>(fn:()=>Promise<T>)=>execution.runHttp({},async()=>{execution.bindHttpActor(user);const close=execution.captureHttpCloser();try{return await fn();}finally{close();}});
 transport.mockImplementation(async(_base,path,_method,_body,params)=>path.endsWith('query_range')?body(String(params?.query).includes('sum by(code)')?[{metric:{code:'200'},values:[[now/1000,'2']]}]:[]):body([],'vector'));
 return {service,run,state,resolved,scope,sources,repository,entities,credentials};
}
describe('M5 independent actual public Vitals final-response and setup safety',()=>{
 it('returns measured QPS and documented current-epoch quality with no secret provider connection details',async()=>{
  const f=fixture(),result=await f.run(()=>f.service.overview(cid,query,actor));expect(result.cards.qps.value).toBe(2);expect(result.quality.historicalScope).toBe('current_epoch');expect(JSON.stringify(result)).not.toContain('SYNTHETIC-SECRET');expect(JSON.stringify(result)).not.toContain('approved-prom');
 });
 it('refuses a final response if durable native-write blocking appeared during query even at unchanged catalog revision',async()=>{
  const f=fixture(),original=transport.getMockImplementation()!;transport.mockImplementation(async(...args)=>{const result=await original(...args);f.state.blocked=true;return result;});
  await expect(f.run(()=>f.service.overview(cid,query,actor))).rejects.toMatchObject({response:{code:'METRICS_CATALOG_CHANGED'}});expect(f.repository.currentAllowedEpochs).toHaveBeenCalled();
 });
 it('does not present an unknown up sample as a measured zero merely because the datastore sample exists',async()=>{
  const f=fixture();f.resolved.wholeCluster=true;const original=transport.getMockImplementation()!;
  transport.mockImplementation(async(...args)=>String(args[4]?.query).startsWith('kong_datastore_reachable')?body([{metric:{node_id:'a'.repeat(64)},value:[now/1000,'1']}],'vector'):original(...args));
  const result=await f.run(()=>f.service.overview(cid,query,actor));expect(result.nodes).toEqual([{id:'a'.repeat(64),online:null,datastoreReachable:1}]);expect(result.cards.onlineNodes.value).toBeNull();expect(result.cards.onlineNodes.availability).not.toBe('available');
 });
 it.each(['permission','source','family'])('discards old-provider results after %s changes in flight',async cause=>{
  const f=fixture(),original=transport.getMockImplementation()!;transport.mockImplementation(async(...args)=>{const result=await original(...args);if(cause==='permission')f.state.permissionVersion='p2';else if(cause==='source')f.state.sourceChanged=true;else f.state.generation++;return result;});
  await expect(f.run(()=>f.service.overview(cid,query,actor))).rejects.toBeDefined();
 });
 it('permits a verification-only revision refresh when exact epochs survive, and rejects changed epochs',async()=>{
  for(const removed of [false,true]){const f=fixture(),original=transport.getMockImplementation()!;transport.mockImplementation(async(...args)=>{const result=await original(...args);f.state.catalogRevision=2;f.state.epochRemoved=removed;return result;});const result=f.run(()=>f.service.overview(cid,query,actor));if(removed)await expect(result).rejects.toMatchObject({response:{code:'METRICS_CATALOG_CHANGED'}});else expect((await result).cards.qps.value).toBe(2);}
 });
 it('denies nonplatform setup and approval-mode provisioning before any plugin or token lookup',async()=>{
  for(const approval of [false,true]){const f=fixture();f.state.platform=approval;f.state.approval=approval;await expect(f.run(()=>f.service.setup(cid,{workspaceId:wid},{sourceId:id,mode:'collector',confirmed:true,confirm_name:'test-cluster'},actor))).rejects.toMatchObject({status:approval?409:403});expect(f.entities.create).not.toHaveBeenCalled();expect(f.entities.update).not.toHaveBeenCalled();expect(f.credentials.getActiveIngestCredential).not.toHaveBeenCalled();}
 });
});
