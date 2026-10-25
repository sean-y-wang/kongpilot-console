import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PluginCenterService } from '../../apps/console-api/src/modules/plugin-center/plugin-center.service';
import { BINDING_SCOPES, bindingScope, executionPriority, pluginMetadata } from '../../apps/console-api/src/modules/plugin-center/plugin-metadata';
import { ruleValues, validatePluginBindings, validatePluginConfiguration } from '../../apps/console-api/src/modules/plugin-center/plugin-validation';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { readCursor, signCursor } from '../../apps/console-api/src/infrastructure/kong/cursor';
import { DEFAULT_WORKSPACE_ID, workspaceTestResolver } from './workspace-test-helper';
import { executionFixture } from './execution-test-fixture';

const fixture=(name:string)=>JSON.parse(readFileSync(`tests/fixtures/kong-1.5.1/plugin-schema-${name}.json`,'utf8'));
const recorded=JSON.parse(readFileSync('tests/fixtures/kong-1.5.1-plugin-metadata.json','utf8'));
const clusterId='6bc62cb6-63cf-4c21-8d67-b84974caebac';
const actor={user:{id:'2f17b12e-d3b0-40c3-96f5-32468871f03f',username:'review',superAdmin:true}};
function harness(){
 const db={one:vi.fn(async(sql:string)=>sql.includes('index_sync_state')?{completed_at:'2026-10-10'}:{enabled_plugins:['rate-limiting','zipkin','custom-plugin'],version:'1.5.1'}),query:vi.fn().mockResolvedValue([])};
 const kong={list:vi.fn().mockResolvedValue({items:[],nextCursor:null,size:20}),pluginSchema:vi.fn(),request:vi.fn(async(_cid:string,_method:string,path:string)=>{
  if(path.startsWith('/routes/'))return {id:'route',service:{id:'service'}};
  if(path.startsWith('/services/'))return {id:'service'};
  return {id:'consumer'};
 })};
 const authz={assertCluster:vi.fn().mockResolvedValue(undefined),assertEntity:vi.fn().mockResolvedValue(undefined),
  isPlatformAdmin:vi.fn(async(user:any)=>user.superAdmin===true),
  permissionVersion:vi.fn().mockResolvedValue('version-1'),scopeTags:vi.fn(async(_user:any,_cid:string,_workspace:any,tags:any)=>tags),
  filterEntities:vi.fn(async(_user:any,_cid:string,_type:string,items:any[])=>items)};
 const entities={update:vi.fn().mockResolvedValue({id:'plugin',enabled:false})};
 const {resolver:workspaces}=workspaceTestResolver(clusterId);
 const service=new PluginCenterService(db as any,kong as any,authz as any,new SecretService(),entities as any,workspaces,executionFixture());
 return {service,db,kong,authz,entities};
}
function failure(fn:()=>void){try{fn();throw new Error('Expected validation failure');}catch(error:any){if(!error.getResponse)throw error;return error.getResponse();}}

describe('Independent M2 schema and selection review against real Kong 1.5.1 evidence',()=>{
 beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','f3'.repeat(32));vi.stubEnv('APP_SECRET','review-cursor-signing-secret-32bytes-minimum');});
 afterEach(()=>vi.unstubAllEnvs());

 it('matches installed Lua binding constraints and execution priorities for all 34 discovered plugins',()=>{
  expect(recorded.count).toBe(34);
  for(const row of recorded.plugins){
   const metadata=pluginMetadata(row.name);
   expect(metadata.known,row.name).toBe(true);
   expect(metadata.constraints.consumer,row.name).toBe(row.consumer);
   expect(metadata.constraints.route,row.name).toBe(row.route);
   expect(metadata.constraints.service,row.name).toBe(row.service);
   expect(metadata.constraints.protocols,row.name).toEqual(row.http_only?['http','https','grpc','grpcs']:['http','https','grpc','grpcs','tcp','tls']);
   expect(executionPriority(row.name),row.name).toBe(row.priority==='Infinity'?Infinity:row.priority);
  }
 });

 it.each(['statsd','datadog'])('evaluates %s conditional requirements independently for each metrics record',name=>{
  const schema=fixture(name),config={metrics:[{name:'request_count',stat_type:'counter',sample_rate:1},{name:'unique_users',stat_type:'set',consumer_identifier:'custom_id'}]};
  expect(()=>validatePluginConfiguration(name,config,schema)).not.toThrow();
  const bad=failure(()=>validatePluginConfiguration(name,{metrics:[config.metrics[0],{name:'unique_users',stat_type:'counter'}]},schema));
  expect(bad.fields).toHaveProperty('config.metrics[1].stat_type');
  expect(bad.fields).toHaveProperty('config.metrics[1].sample_rate');
  expect(bad.fields).toHaveProperty('config.metrics[1].consumer_identifier');
  expect(bad.fields).not.toHaveProperty('config.metrics[0].sample_rate');
 });

 it('keeps numeric zero present for Datadog sample_rate and evaluates default metrics without changing the submitted object',()=>{
  const config={metrics:[{name:'request_count',stat_type:'counter',sample_rate:0}]};
  expect(()=>validatePluginConfiguration('datadog',config,fixture('datadog'))).not.toThrow();
  const empty={};expect(()=>validatePluginConfiguration('statsd',empty,fixture('statsd'))).not.toThrow();expect(empty).toEqual({});
  const defaults=ruleValues({},fixture('response-ratelimiting'));
  expect(defaults.block_on_first_violation).toBe(false);expect(defaults.redis_database).toBe(0);
 });

 it('validates each response-ratelimiting map record and its ordered windows using the real schema',()=>{
  const schema=fixture('response-ratelimiting');
  expect(()=>validatePluginConfiguration('response-ratelimiting',{limits:{video:{second:5,minute:50},audio:{hour:100}}},schema)).not.toThrow();
  expect(failure(()=>validatePluginConfiguration('response-ratelimiting',{limits:{video:{second:5},audio:{}}},schema)).fields).toHaveProperty('config.limits.audio');
  expect(failure(()=>validatePluginConfiguration('response-ratelimiting',{limits:{video:{second:50,minute:5}}},schema)).fields).toHaveProperty('config.limits.video.minute');
 });

 it('uses Redis defaults only to evaluate conditions and leaves missing-host errors on the host field',()=>{
  const config={policy:'redis',second:1};
  const result=failure(()=>validatePluginConfiguration('rate-limiting',config,fixture('rate-limiting')));
  expect(Object.keys(result.fields)).toEqual(['config.redis_host']);
  expect(config).toEqual({policy:'redis',second:1});
 });

 it('defers unknown Lua predicates instead of assuming they match and rejecting unrelated fields',()=>{
  const schema={fields:[{trigger:{type:'string'}},{extra:{type:'string'}}],entity_checks:[{conditional:{
   if_field:'trigger',if_match:{custom_validator:'installed-lua-function'},then_field:'extra',then_match:{required:true}}}]};
  expect(()=>validatePluginConfiguration('custom-plugin',{trigger:'server-decides'},schema)).not.toThrow();
 });

 it('does not execute server-only custom validators or invent unknown custom-plugin binding restrictions',()=>{
  expect(()=>validatePluginConfiguration('custom-plugin',{script:'do not execute'}, {fields:[{script:{type:'string',custom_validator:'loadstring'}}]})).not.toThrow();
  expect(pluginMetadata('custom-plugin')).toMatchObject({known:false,priority:null,constraints:{consumer:null,route:null,service:null}});
  expect(()=>validatePluginBindings('custom-plugin',{consumer:{id:'consumer'},protocols:['tcp']})).not.toThrow();
  expect(()=>validatePluginBindings('key-auth',{consumer:{id:'consumer'}})).toThrow();
  expect(()=>validatePluginBindings('kubernetes-sidecar-injector',{route:{id:'route'}})).toThrow();
 });

 it('returns a secret-free session wire schema while preserving its definition and an independently augmented form schema',async()=>{
  const {service,kong}=harness(),wire=fixture('session');kong.pluginSchema.mockResolvedValue(wire);
  // The response recorder removes random worker secrets; exercise the actual field shape with a synthetic default.
  wire.fields.find((entry:any)=>entry.secret).secret.default='synthetic-worker-session-secret';
  const original=wire.fields.find((entry:any)=>entry.secret).secret.default;
  const result=await service.schema(clusterId,'session',actor);
  const field=result.wire_schema.fields.find((entry:any)=>entry.secret).secret;
  expect(field.type).toBe('string');expect(field).not.toHaveProperty('default');expect(field.default_redacted).toBe(true);
  expect(JSON.stringify(result)).not.toContain(original);
  expect(wire.fields.find((entry:any)=>entry.secret).secret.default).toBe(original);
  expect(result.wire_schema).not.toHaveProperty('console_metadata_source');expect(result.form_schema).toHaveProperty('console_metadata_source');
 });

 it('selects all eight scopes correctly and keeps same-name selection separate from cross-plugin execution priority',async()=>{
  const {service,kong}=harness();
  const configs=BINDING_SCOPES.map(scope=>({id:scope,name:'rate-limiting',enabled:true,protocols:['http'],
   ...(scope.includes('consumer')?{consumer:{id:'consumer'}}:{}),...(scope.includes('route')?{route:{id:'route'}}:{}),...(scope.includes('service')?{service:{id:'service'}}:{})}));
  for(let i=0;i<configs.length;i++)expect(bindingScope(configs[i])).toBe(BINDING_SCOPES[i]);
  kong.list.mockResolvedValue({items:[...configs,{id:'zipkin-global',name:'zipkin',enabled:true,protocols:['http']}],nextCursor:null,size:100});
  const result=await service.context(clusterId,{routeId:'route',consumerId:'consumer',protocol:'http'},actor);
  expect(result.complete).toBe(true);
  expect(result.selected.find((item:any)=>item.name==='rate-limiting').scope).toBe('consumer-route-service');
  expect(result.execution_chain.map((item:any)=>item.name)).toEqual(['zipkin','rate-limiting']);
  expect(result.candidates.filter((item:any)=>item.name==='rate-limiting').map((item:any)=>item.rank)).toEqual([1,2,3,4,5,6,7,8]);
 });

 it('discards disabled or wrong-protocol candidates and falls back to the next applicable same-name scope',async()=>{
  const {service,kong}=harness();
  kong.list.mockResolvedValue({items:[
   {id:'highest-disabled',name:'rate-limiting',enabled:false,protocols:['http'],consumer:{id:'consumer'},route:{id:'route'},service:{id:'service'}},
   {id:'route-wrong-protocol',name:'rate-limiting',enabled:true,protocols:['tcp'],consumer:{id:'consumer'},route:{id:'route'}},
   {id:'service-selected',name:'rate-limiting',enabled:true,protocols:['http'],consumer:{id:'consumer'},service:{id:'service'}},
   {id:'global-shadowed',name:'rate-limiting',enabled:true,protocols:['http']},
  ],nextCursor:null,size:100});
  const result=await service.context(clusterId,{routeId:'route',consumerId:'consumer',protocol:'http'},actor);
  expect(result.selected.map((item:any)=>item.entity.id)).toEqual(['service-selected']);
  expect(result.candidates.find((item:any)=>item.entity.id==='highest-disabled').applicable).toBe(false);
  expect(result.candidates.find((item:any)=>item.entity.id==='route-wrong-protocol').applicable).toBe(false);
 });

 it('refuses to claim a winner when a later page could still hide a higher-priority instance',async()=>{
  const {service,kong}=harness();kong.list.mockResolvedValue({items:[{id:'global',name:'rate-limiting',enabled:true,protocols:['http']}],nextCursor:'more',size:100});
  const result=await service.context(clusterId,{},actor);
  expect(kong.list).toHaveBeenCalledTimes(5);expect(result.complete).toBe(false);expect(result.selected).toEqual([]);expect(result.execution_chain).toEqual([]);
 });

 it('refuses to claim a gateway chain from a restricted user or a tag/workspace projection',async()=>{
  const {service,kong}=harness();kong.list.mockResolvedValue({items:[{id:'global',name:'rate-limiting',enabled:true,protocols:['http']}],nextCursor:null,size:100});
  const restricted=await service.context(clusterId,{}, {user:{...actor.user,superAdmin:false}});
  expect(restricted.complete).toBe(false);expect(restricted.selected).toEqual([]);
  const tagged=await service.context(clusterId,{tags:'team:pay'},actor);expect(tagged.complete).toBe(false);expect(tagged.selected).toEqual([]);
 });

 it('marks a selected custom plugin priority unknown without inventing a handler priority',async()=>{
  const {service,kong}=harness();kong.list.mockResolvedValue({items:[{id:'custom',name:'custom-plugin',enabled:true,protocols:['http']}],nextCursor:null,size:100});
  const result=await service.context(clusterId,{protocol:'http'},actor);
  expect(result.selected[0].priority).toBeNull();expect(result.warnings.some((item:string)=>item.includes('未知'))).toBe(true);
 });

 it('caps instance filtering at five native cursor pages and lets the caller continue an empty filtered page',async()=>{
  const {service,kong}=harness();kong.list.mockResolvedValue({items:[{id:'irrelevant',name:'cors'}],nextCursor:'continue',size:20});
  const result=await service.instances(clusterId,{name:'rate-limiting'},actor);
  expect(kong.list).toHaveBeenCalledTimes(5);expect(result.items).toEqual([]);expect(result.nextCursor).toBe('continue');expect(result.scan_budget_exhausted).toBe(true);expect(result.total).toBeNull();
 });

 it('binds a native cursor to name, binding scope, cluster, actor, permission revision, tags and page size',async()=>{
  const {service,kong,authz}=harness();
  kong.list.mockImplementation(async(cid:string,path:string,query:any,cursor:string|undefined,subject:string)=>{
   if(cursor)readCursor(cursor,cid,path,query,subject);
   return {items:[{id:'visible',name:'rate-limiting',enabled:true,tags:query.tags?.split(',')??[]}],size:query.size,nextCursor:signCursor({clusterId:cid,path,query,subject,offset:'next-native-page'})};
  });
  const initial=await service.instances(clusterId,{name:'rate-limiting',binding_scope:'global',size:20,tags:'team:pay'},actor);
  const cursor=initial.nextCursor;
  expect((await service.instances(clusterId,{name:'rate-limiting',binding_scope:'global',size:20,tags:'team:pay',cursor},actor)).items).toHaveLength(1);
  for(const change of [{name:'cors'},{binding_scope:'service'},{size:10},{tags:'team:other'}])await expect(service.instances(clusterId,{name:'rate-limiting',binding_scope:'global',size:20,tags:'team:pay',cursor,...change},actor)).rejects.toMatchObject({response:{code:'INVALID_CURSOR'}});
  await expect(service.instances('7f57d46f-2f7b-486f-82b2-a27e5655a831',{name:'rate-limiting',binding_scope:'global',size:20,tags:'team:pay',cursor},actor)).rejects.toMatchObject({status:404});
  await expect(service.instances(clusterId,{name:'rate-limiting',binding_scope:'global',size:20,tags:'team:pay',cursor},{user:{...actor.user,id:'other-actor'}})).rejects.toMatchObject({response:{code:'INVALID_CURSOR'}});
  authz.permissionVersion.mockResolvedValue('version-2');
  await expect(service.instances(clusterId,{name:'rate-limiting',binding_scope:'global',size:20,tags:'team:pay',cursor},actor)).rejects.toMatchObject({response:{code:'INVALID_CURSOR'}});
 });

 it('does not query unrestricted plugin inventory counts for a restricted actor',async()=>{
  const {service,db}=harness();const result=await service.catalog(clusterId,{}, {user:{...actor.user,superAdmin:false}});
  expect(db.query).not.toHaveBeenCalled();expect(result.counts_visibility).toBe('unavailable');expect(result.items.every((item:any)=>item.counts===null)).toBe(true);
 });

 it('routes an exact boolean toggle through the audited EntityService and rejects arbitrary fields',async()=>{
  const {service,entities}=harness();await service.toggle(clusterId,'plugin',{enabled:false},actor);
  expect(entities.update).toHaveBeenCalledWith(clusterId,'plugins','plugin',{enabled:false},{workspaceId:DEFAULT_WORKSPACE_ID},{...actor,workspaceId:DEFAULT_WORKSPACE_ID});
  await expect(service.toggle(clusterId,'plugin',{enabled:false,config:{second:10}},actor)).rejects.toMatchObject({response:{code:'INVALID_PLUGIN_TOGGLE'}});
  expect(entities.update).toHaveBeenCalledTimes(1);
 });
});
