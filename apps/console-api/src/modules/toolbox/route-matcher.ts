import { isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import type { RouteDebugInput } from './toolbox-input';
import {boundedPcre1Matches,PCRE1_PROFILE,type Pcre1Match} from './pcre1-engine';
import { pluginMetadata, executionPriority } from '../plugin-center/plugin-metadata';

export const ROUTER_ADAPTER_VERSION='kong-1.5-traditional-pcre1-v2';
const plainPath=/^[a-zA-Z0-9.\-_~/%]*$/;
const maxRegexCalls=PCRE1_PROFILE.patternLimit,maxSimulationRoutes=1000,simulationDeadlineMs=2000;
export const boundedRegexMatches=boundedPcre1Matches;
function ipNumber(value:string):{bits:number;value:bigint}|null{
  if(value.includes('%'))return null;
  const family=isIP(value);if(family===4)return{bits:32,value:value.split('.').reduce((sum,part)=>(sum<<8n)+BigInt(part),0n)};
  if(family!==6)return null;
  let text=value.toLowerCase();if(text.includes('.')){const at=text.lastIndexOf(':'),v4=ipNumber(text.slice(at+1));if(!v4)return null;text=text.slice(0,at+1)+((v4.value>>16n)&65535n).toString(16)+':'+(v4.value&65535n).toString(16);}
  const sides=text.split('::'),left=sides[0]?sides[0].split(':'):[],right=sides[1]?sides[1].split(':'):[];
  const words=sides.length===2?[...left,...Array(8-left.length-right.length).fill('0'),...right]:left;
  if(words.length!==8)return null;return{bits:128,value:words.reduce((sum,part)=>(sum<<16n)+BigInt('0x'+part),0n)};
}
export function cidrContains(cidr:string,address:string):boolean{
  const [network,prefix]=cidr.split('/'),a=ipNumber(network),b=ipNumber(address);if(!a||!b||a.bits!==b.bits)return false;
  const bits=prefix===undefined?a.bits:Number(prefix);if(!Number.isInteger(bits)||bits<0||bits>a.bits)return false;
  const shift=BigInt(a.bits-bits);return(a.value>>shift)===(b.value>>shift);
}
function compareRank(a:number[],b:number[]):number{for(let i=0;i<a.length;i++)if(a[i]!==b[i])return b[i]-a[i];return 0;}
function hostMatches(pattern:string,host:string):boolean{pattern=pattern.toLowerCase();return pattern.startsWith('*.')?host.endsWith(pattern.slice(1))&&host.length>pattern.length-1:pattern.endsWith('.*')?host.startsWith(pattern.slice(0,-1))&&host.length>pattern.length-1:pattern===host;}

/** Categories and tie-breakers follow actual Kong1.5 router.lua. The native
 * PCRE1 profile reproduces its anchored index/strip-regex calls with explicit
 * resource bounds. An unavailable/invalid/exhausted match stays partial. */
export async function simulateRoutes(routes:any[],input:RouteDebugInput){
  const deadline=performance.now()+simulationDeadlineMs,limitedRoutes=routes.slice(0,maxSimulationRoutes),patterns=new Set<string>();
  let deadlineExceeded=false,regexBudgetExceeded=false;
  const url=new URL(input.url),protocol=url.protocol.slice(0,-1),path=url.pathname||'/',host=url.hostname.toLowerCase();
  capture:for(const route of limitedRoutes){for(const pattern of Array.isArray(route.paths)?route.paths:[]){
    if(performance.now()>=deadline){deadlineExceeded=true;break capture;}
    if(typeof pattern==='string'&&!plainPath.test(pattern)&&!patterns.has(pattern)){if(patterns.size<maxRegexCalls)patterns.add(pattern);else regexBudgetExceeded=true;}
  }}
  const remaining=deadline-performance.now();if(remaining<=0)deadlineExceeded=true;
  const regex:Record<string,Pcre1Match>=deadlineExceeded?{}:await boundedRegexMatches([...patterns],path,Math.min(250,remaining));let unsupported=false;
  const candidates:Array<{id:string;name:string|null;serviceId:string|null;matched:boolean;reasons:string[];warnings:string[];rank:number[]}>=[];
  for(const route of limitedRoutes){
    if(performance.now()>=deadline){deadlineExceeded=true;break;}
    const reasons:string[]=[],warnings:string[]=[];
    const hosts:Array<string>=route.hosts??[],methods:Array<string>=route.methods??[],paths:Array<string>=route.paths??[],snis:Array<string>=route.snis??[],sources:Array<any>=route.sources??[],destinations:Array<any>=route.destinations??[];
    const headers=route.headers&&typeof route.headers==='object'?Object.entries(route.headers):[];
    if(Array.isArray(route.protocols)&&!route.protocols.includes(protocol))reasons.push('PROTOCOL_MISMATCH');
    if(hosts.length&&!hosts.some(pattern=>hostMatches(pattern,host)))reasons.push('HOST_MISMATCH');
    if(methods.length&&!methods.includes(input.method))reasons.push('METHOD_MISMATCH');
    if(headers.some(([,values])=>Array.isArray(values)&&values.some(value=>typeof value==='string'&&/\[REDACTED(?::[^\]]*)?\]/.test(value))))warnings.push('HEADER_VALUE_MASKED');
    if(headers.some(([name,values])=>!Array.isArray(values)||!values.includes(input.headers[name.toLowerCase()])))reasons.push('HEADER_MISMATCH');
    if(snis.length){if(!input.sni)warnings.push('SNI_CONTEXT_MISSING');else if(!snis.includes(input.sni))reasons.push('SNI_MISMATCH');}
    for(const [entries,ip,port,kind]of [[sources,input.sourceIp,input.sourcePort,'SOURCE'],[destinations,input.destinationIp??(isIP(host)?host:undefined),input.destinationPort??Number(url.port||(protocol==='https'||protocol==='tls'?443:80)),'DESTINATION']] as const){
      if(entries.length){if(entries.some((entry:any)=>entry.ip&&!ip||entry.port&&!port))warnings.push(`${kind}_CONTEXT_MISSING`);
        if(!entries.some((entry:any)=>(!entry.ip||!!ip&&cidrContains(entry.ip,ip))&&(!entry.port||entry.port===port)))reasons.push(`${kind}_MISMATCH`);
      }
    }
    let knownPath=false,unverifiedPath=false,matchedRegex=false,longestMatchedPrefix=0;
    for(const pattern of paths){
      if(plainPath.test(pattern)){if(path.startsWith(pattern)){knownPath=true;longestMatchedPrefix=Math.max(longestMatchedPrefix,pattern.length);}}
      else if(!regex[pattern]||regex[pattern].unsupported){unverifiedPath=true;if(regex[pattern]?.reason)warnings.push(regex[pattern].reason!);}
      else if(regex[pattern].match){knownPath=true;matchedRegex=true;}
    }
    if(paths.length){if(unverifiedPath)warnings.push('PCRE_PATTERN_UNSUPPORTED');else if(!knownPath)reasons.push('PATH_MISMATCH');}
    if(warnings.length)unsupported=true;
    const bits=(hosts.length?64:0)+(headers.length?32:0)+(paths.length?16:0)+(methods.length?8:0)+(snis.length?4:0)+(sources.length?2:0)+(destinations.length?1:0);
    const count=[hosts.length,headers.length,paths.length,methods.length,snis.length,sources.length,destinations.length].filter(Boolean).length;
    // Kong 1.5 splits multi-path routes before sorting. Rank the best matched
    // path instance; another path cannot lend it regex weight or URI length.
    const subWeight=(hosts.length&&!hosts.some(pattern=>pattern.includes('*'))?2:0)+(matchedRegex?1:0);
    const rank=[count,bits,subWeight,headers.length,Number(route.regex_priority??0),matchedRegex?0:longestMatchedPrefix,-Number(route.created_at??0)];
    candidates.push({id:route.id,name:route.name??null,serviceId:route.service?.id??null,matched:reasons.length===0&&warnings.length===0,reasons,warnings,rank});
  }
  if(performance.now()>=deadline)deadlineExceeded=true;
  const matched=candidates.filter(candidate=>candidate.matched).sort((a,b)=>compareRank(a.rank,b.rank)||String(a.id).localeCompare(String(b.id))),tie=matched.length>1&&compareRank(matched[0].rank,matched[1].rank)===0;
  const routeBudgetExceeded=routes.length>maxSimulationRoutes;
  return{route:matched[0]??null,candidates,complete:!unsupported&&!tie&&!deadlineExceeded&&!regexBudgetExceeded&&!routeBudgetExceeded,reasonCodes:[...(unsupported?['UNSUPPORTED_OR_MISSING_CONTEXT']:[]),...(tie?['ROUTE_PRIORITY_TIE']:[]),...[...new Set(Object.values(regex).filter(x=>x.unsupported&&x.reason).map(x=>x.reason!))],...(regexBudgetExceeded?['REGEX_CALL_BUDGET_EXHAUSTED']:[]),...(deadlineExceeded?['SIMULATION_DEADLINE_EXCEEDED']:[]),...(routeBudgetExceeded?['CAPTURE_BUDGET_EXHAUSTED']:[])],engine:ROUTER_ADAPTER_VERSION,regexEngine:'PCRE1 8.45 anchored 8-bit; isolated process; no JIT',regexProfile:PCRE1_PROFILE,regexBudgetMs:250,simulationBudget:{deadlineMs:simulationDeadlineMs,regexCallLimit:maxRegexCalls,regexCalls:patterns.size,routeLimit:maxSimulationRoutes,examinedRoutes:candidates.length}};
}
const scopes=['consumer-route-service','consumer-route','consumer-service','route-service','consumer','route','service','global'];
export function resolvePluginChain(plugins:any[],routeId:string,serviceId:string|null,consumerId?:string){
  const consumerContextMissing=!consumerId&&plugins.some(plugin=>plugin.enabled!==false&&plugin.consumer&&(!plugin.route||plugin.route.id===routeId)&&(!plugin.service||plugin.service.id===serviceId));
  const applicable=plugins.filter(plugin=>plugin.enabled!==false&&(!plugin.route||plugin.route.id===routeId)&&(!plugin.service||plugin.service.id===serviceId)&&(!plugin.consumer||plugin.consumer.id===consumerId));
  const ranked=applicable.map(plugin=>{const scope=[...(plugin.consumer?['consumer']:[]),...(plugin.route?['route']:[]),...(plugin.service?['service']:[])].join('-')||'global';return{plugin,scope,rank:scopes.indexOf(scope)};});
  const selected=new Map<string,typeof ranked[number]>();for(const item of ranked.sort((a,b)=>a.rank-b.rank))if(!selected.has(item.plugin.name))selected.set(item.plugin.name,item);
  const ordered=[...selected.values()].sort((a,b)=>(executionPriority(b.plugin.name)??-Infinity)-(executionPriority(a.plugin.name)??-Infinity));
  const execution=ordered.map(item=>({id:item.plugin.id,name:item.plugin.name,scope:item.scope,selectionRank:item.rank+1,priority:pluginMetadata(item.plugin.name).priority,...(pluginMetadata(item.plugin.name).priority_label?{priorityLabel:pluginMetadata(item.plugin.name).priority_label}:{})}));
  const reasonCodes=[...(consumerContextMissing?['CONSUMER_CONTEXT_MISSING']:[]),...(ordered.some(item=>executionPriority(item.plugin.name)===null)?['PLUGIN_PRIORITY_UNKNOWN']:[])];
  return{selectionPrecedence:ranked.map(item=>({id:item.plugin.id,name:item.plugin.name,scope:item.scope,rank:item.rank+1,selected:selected.get(item.plugin.name)?.plugin.id===item.plugin.id})),executionOrder:execution,complete:reasonCodes.length===0,reasonCodes};
}
