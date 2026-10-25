import { ForbiddenException, ConflictException } from '@nestjs/common';
import { BINDING_SCOPES, bindingScope, pluginMetadata } from '../plugin-center/plugin-metadata';
import { kong15PluginSubsystem, kong15ProtocolMatches, kong15ExternalPluginEligible } from '../../infrastructure/kong/plugin-applicability';

export interface PortalGraph { services:any[]; routes:any[]; plugins:any[]; }
export interface PortalPublicationBoundary {
 id:string; serviceId:string; aclGroup:string; keyAuthPluginId?:string|null; aclPluginId?:string|null;
 /** Previously published revisions remain protected during an edit. */
 established:boolean;
}
export interface PortalConsumerBoundary { consumerId:string; publicationId:string; groups:string[]; }
export interface PortalSurface { serviceId?:string; routeId?:string; consumerId:string; protocol:string; }
const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const protocols=new Set(['http','https','grpc','grpcs','tcp','tls']);
// Kong 1.5's iterator selects by ngx subsystem, not the current request's
// specific protocol. HTTPS-only plugin metadata still participates in HTTP.
const subsystem=(protocol:string)=>kong15PluginSubsystem(protocol)!;
const unsupportedAuthentication=new Set(['basic-auth','hmac-auth','jwt','oauth2','ldap-auth','session','pre-function','post-function']);
const denied=(code='PORTAL_UNMANAGED_AUTH_BOUNDARY')=>new ForbiddenException({code,
 message:'当前认证链无法证明门户 API Key 的授权边界；请检查 key-auth、ACL 白名单和覆盖插件'});
function id(value:any):string|undefined{
 if(value===null||value===undefined)return undefined;
 if(!value||typeof value!=='object'||Array.isArray(value)||!uuid.test(value.id??''))throw denied('PORTAL_AUTH_GRAPH_INVALID');
 return value.id;
}
function protocolList(value:unknown):string[]{
 if(!Array.isArray(value)||!value.length||value.length>6||value.some(entry=>typeof entry!=='string'||!protocols.has(entry))
  ||new Set(value).size!==value.length)throw denied('PORTAL_AUTH_GRAPH_INVALID');
 return value;
}
function records(rows:any[]):Map<string,any>{
 if(!Array.isArray(rows)||rows.length>10000)throw denied('PORTAL_AUTH_GRAPH_BUDGET');
 const map=new Map<string,any>();
 for(const row of rows){
  if(!row||typeof row!=='object'||Array.isArray(row)||!uuid.test(row.id??'')||map.has(row.id))throw denied('PORTAL_AUTH_GRAPH_INVALID');
  map.set(row.id,row);
 }return map;
}
/** The complete private capture is required. A filtered public list is not an
 * authentication proof, and missing references never mean an empty surface. */
export function validatePortalGraph(graph:PortalGraph):void{
 const services=records(graph.services),routes=records(graph.routes);records(graph.plugins);
 if(graph.services.length+graph.routes.length+graph.plugins.length>10000)throw denied('PORTAL_AUTH_GRAPH_BUDGET');
 for(const service of services.values())if(!protocols.has(service.protocol))throw denied('PORTAL_AUTH_GRAPH_INVALID');
 for(const route of routes.values()){
  protocolList(route.protocols);const service=id(route.service);
  if(service&&!services.has(service))throw denied('PORTAL_AUTH_GRAPH_INCOMPLETE');
 }
 for(const plugin of graph.plugins){
  if(typeof plugin.name!=='string'||!plugin.name||typeof plugin.enabled!=='boolean'
   ||!plugin.config||typeof plugin.config!=='object'||Array.isArray(plugin.config)
   ||plugin.run_on!==undefined&&!['first','second','all'].includes(plugin.run_on))throw denied('PORTAL_AUTH_GRAPH_INVALID');
  protocolList(plugin.protocols);const service=id(plugin.service),route=id(plugin.route);id(plugin.consumer);
  if(service&&!services.has(service)||route&&!routes.has(route))throw denied('PORTAL_AUTH_GRAPH_INCOMPLETE');
 }
}
export function effectivePortalPlugin(plugins:any[],name:string,surface:PortalSurface):any|undefined{
 let selected:any,rank=Infinity;
 for(const plugin of plugins){
  if(plugin.name!==name||plugin.enabled!==true||!kong15ExternalPluginEligible(plugin)||!kong15ProtocolMatches(plugin.protocols,surface.protocol))continue;
  const c=id(plugin.consumer),r=id(plugin.route),s=id(plugin.service);
  if(c&&c!==surface.consumerId||r&&r!==surface.routeId||s&&s!==surface.serviceId)continue;
  const candidate=BINDING_SCOPES.indexOf(bindingScope(plugin));
  if(candidate<rank){selected=plugin;rank=candidate;}
  else if(candidate===rank)throw denied('PORTAL_AUTH_CHAIN_AMBIGUOUS');
 }return selected;
}
function whitelist(plugin:any):string[]{
 const config=plugin?.config,values=config?.whitelist;
 if(!plugin||!Array.isArray(values)||!values.length||values.length>1000
  ||values.some((group:any)=>typeof group!=='string'||!group||group.length>128)
  ||config.blacklist!==null&&config.blacklist!==undefined)throw denied();
 return values;
}
function keyAuth(plugin:any):void{
 if(!plugin||plugin.config.anonymous!==null&&plugin.config.anonymous!==undefined)throw denied();
 const names=plugin.config.key_names;
 if(!Array.isArray(names)||!names.length||names.length>1000||names.some((name:any)=>typeof name!=='string'||!name||name.length>128||/[\u0000-\u0020\u007f]/.test(name)))throw denied();
}
/** Bounded captures can contain thousands of logging instances. Indexing the
 * exact bindings avoids rescanning the whole graph for each Consumer/Route. */
function indexedPlugins(plugins:any[]){
 const index=new Map<string,Map<string,Map<string,any>>>(),unsafeNames:string[]=[];
 const bindingKey=(c?:string,r?:string,s?:string)=>JSON.stringify([c??null,r??null,s??null]);
 for(const plugin of plugins){
  if(!plugin.enabled||!kong15ExternalPluginEligible(plugin))continue;
  let byProtocol=index.get(plugin.name);if(!byProtocol){index.set(plugin.name,byProtocol=new Map());
   if(!pluginMetadata(plugin.name).known||unsupportedAuthentication.has(plugin.name))unsafeNames.push(plugin.name);
  }
  const key=bindingKey(id(plugin.consumer),id(plugin.route),id(plugin.service));
  for(const protocol of new Set<string>((plugin.protocols as string[]).map(subsystem))){
   let byBinding=byProtocol.get(protocol);if(!byBinding)byProtocol.set(protocol,byBinding=new Map());
   if(byBinding.has(key))throw denied('PORTAL_AUTH_CHAIN_AMBIGUOUS');byBinding.set(key,plugin);
  }
 }
 const select=(name:string,surface:PortalSurface):any|undefined=>{
  const bindings=index.get(name)?.get(subsystem(surface.protocol));if(!bindings)return;
  const c=surface.consumerId,r=surface.routeId,s=surface.serviceId;
  const candidates=[r&&s?[c,r,s]:null,r?[c,r,undefined]:null,s?[c,undefined,s]:null,r&&s?[undefined,r,s]:null,
   [c,undefined,undefined],r?[undefined,r,undefined]:null,s?[undefined,undefined,s]:null,[undefined,undefined,undefined]];
  for(const tuple of candidates)if(tuple){const plugin=bindings.get(bindingKey(...tuple as [string|undefined,string|undefined,string|undefined]));if(plugin)return plugin;}
 };
 return {select,unsafe:(surface:PortalSurface,hasKey:boolean)=>unsafeNames.some(name=>(hasKey||['pre-function','post-function'].includes(name)||!pluginMetadata(name).known)&&!!select(name,surface))};
}

/** Exact same-name precedence, disabled fallback and protocol applicability
 * are distinct from numeric execution priorities. No fabricated Consumer is
 * sent to Kong: baseline identities exist only within this private analysis. */
export function assertPortalAuthenticationBoundary(graph:PortalGraph,
 publications:PortalPublicationBoundary[],consumers:PortalConsumerBoundary[],combinationLimit=100000):void{
 validatePortalGraph(graph);
 const plugins=indexedPlugins(graph.plugins);
 if(!Number.isSafeInteger(combinationLimit)||combinationLimit<1||combinationLimit>100000)throw denied('PORTAL_AUTH_GRAPH_BUDGET');
 const services=new Map(graph.services.map(service=>[service.id,service])),publicationMap=new Map<string,PortalPublicationBoundary>();
 const risks:PortalConsumerBoundary[]=[...consumers];
 for(const pub of publications){
  if(!uuid.test(pub.id)||!uuid.test(pub.serviceId)||pub.aclGroup!==`kos-portal-api-${pub.id}`||publicationMap.has(pub.serviceId))throw denied('PORTAL_AUTH_GRAPH_INVALID');
  if(!services.has(pub.serviceId))throw denied('PORTAL_PUBLISHED_SERVICE_MISSING');
  if(!['http','https'].includes(services.get(pub.serviceId)!.protocol))throw denied('PORTAL_AUTH_PROTOCOL_UNSUPPORTED');
  publicationMap.set(pub.serviceId,pub);
  risks.push({consumerId:`portal-baseline:${pub.id}`,publicationId:pub.id,groups:[pub.aclGroup]});
 }
 const surfaces:Array<Omit<PortalSurface,'consumerId'>>=[];
 // Published Service baselines cover future HTTP/HTTPS Routes. Unpublished
 // Services without Routes are not reachable authentication surfaces.
 for(const pub of publications)for(const protocol of ['http','https'])surfaces.push({serviceId:pub.serviceId,protocol});
 for(const route of graph.routes)for(const protocol of route.protocols)surfaces.push({serviceId:id(route.service),routeId:route.id,protocol});
 if(surfaces.length*risks.length>combinationLimit)throw denied('PORTAL_AUTH_GRAPH_BUDGET');
 for(const risk of risks){
  if(typeof risk.consumerId!=='string'||!uuid.test(risk.publicationId)||!Array.isArray(risk.groups)
   ||risk.groups.length>1000||risk.groups.some(group=>typeof group!=='string'||!group||group.length>128))throw denied('PORTAL_AUTH_GRAPH_INVALID');
  for(const base of surfaces){
   const surface={...base,consumerId:risk.consumerId},pub=base.serviceId?publicationMap.get(base.serviceId):undefined;
   const key=plugins.select('key-auth',surface);
   if(plugins.unsafe(surface,!!key||!!pub?.established))throw denied();
   // A first publication installs ACL before key-auth. Its unpublished target
   // is staged; every other existing authentication surface is still checked.
   if(pub?.id===risk.publicationId&&(pub.established||key)){
    keyAuth(key);const acl=plugins.select('acl',surface),groups=whitelist(acl);
    if(!groups.includes(pub.aclGroup)||pub.established&&(key.id!==pub.keyAuthPluginId||acl.id!==pub.aclPluginId))throw denied();
   }else if(key){
    keyAuth(key);const groups=whitelist(plugins.select('acl',surface));
    if(groups.some(group=>risk.groups.includes(group)))throw denied();
   }
  }
 }
}

export function assertPortalCaptureStable(before:any,current:any,fingerprint:(value:unknown)=>string):void{
 if(before!==undefined&&before!==null&&(!current||fingerprint(before)!==fingerprint(current)))
  throw new ConflictException({code:'PORTAL_AUTH_GRAPH_CHANGED',message:'认证图在核验期间变化，请核验原回执后重新检查'});
}
