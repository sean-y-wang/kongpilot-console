import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { assertPortalAuthenticationBoundary, effectivePortalPlugin, validatePortalGraph, assertPortalCaptureStable } from '../../apps/console-api/src/modules/portal-boundary/auth-graph';
import { canonicalJson } from '../../apps/console-api/src/infrastructure/secret.service';

const ids=Array.from({length:24},(_,n)=>`00000000-0000-4000-8000-${String(n+1).padStart(12,'0')}`);
const [pubId,sid,rid,kid,aid,cid,otherSid,otherRid]=ids;
const group=`kos-portal-api-${pubId}`;
const service=(id=sid)=>({id,protocol:'http',tags:['kos-ws-pay']});
const route=(id=rid,s=sid)=>({id,service:{id:s},protocols:['http','https']});
const plugin=(id:string,name:string,scope:any={},config:any=name==='acl'?{whitelist:[group],blacklist:null}:{key_names:['apikey'],anonymous:null},extra:any={})=>({id,name,enabled:true,protocols:['http','https'],config,service:null,route:null,consumer:null,...scope,...extra});
const publication={id:pubId,serviceId:sid,aclGroup:group,keyAuthPluginId:kid,aclPluginId:aid,established:true};
function graph(){return {services:[service()],routes:[route()],plugins:[plugin(kid,'key-auth',{service:{id:sid}}),plugin(aid,'acl',{service:{id:sid}})]};}
const check=(g=graph(),pubs=[publication],consumers:any[]=[])=>assertPortalAuthenticationBoundary(g,pubs,consumers);
const code=(name:string)=>({response:expect.objectContaining({code:name})});

describe('M6 private Portal authentication graph',()=>{
 it('protects a published API even before its first credential is issued',()=>expect(()=>check()).not.toThrow());
 it.each(['key-auth','acl'])('rejects removal of published %s with zero active keys',name=>{
  const g=graph();g.plugins=g.plugins.filter(p=>p.name!==name);expect(()=>check(g)).toThrow();
 });
 it('uses the actual 1.5 HTTP subsystem across HTTP and HTTPS Routes',()=>{
  const g=graph();g.routes[0].protocols=['http'];g.plugins[0].protocols=['http'];expect(()=>check(g)).not.toThrow();
 });
 it('allows ACL-before-key staging on a first unpublished target',()=>{
  const g=graph();g.plugins=g.plugins.filter(p=>p.name==='acl');expect(()=>check(g,[{...publication,established:false}])).not.toThrow();
 });
 it('checks other reachable APIs during first-publication staging',()=>{
  const g=graph();g.services.push(service(otherSid));g.routes.push(route(otherRid,otherSid));
  g.plugins=[plugin(aid,'acl',{service:{id:sid}}),plugin(ids[9],'key-auth',{service:{id:otherSid}})];
  expect(()=>check(g,[{...publication,established:false}])).toThrow();
 });
 it('rejects a global key-auth chain that accepts a Portal group on an unrelated API',()=>{
  const g=graph();g.services.push(service(otherSid));g.routes.push(route(otherRid,otherSid));
  g.plugins.push(plugin(ids[9],'key-auth'),plugin(ids[10],'acl'));
  expect(()=>check(g)).toThrow();
 });
 it('accepts unrelated key-auth protected by a disjoint ACL whitelist',()=>{
  const g=graph();g.services.push(service(otherSid));g.routes.push(route(otherRid,otherSid));
  g.plugins.push(plugin(ids[9],'key-auth',{service:{id:otherSid}}),plugin(ids[10],'acl',{service:{id:otherSid}},{whitelist:['other-team'],blacklist:null}));
  expect(()=>check(g,undefined,[{consumerId:cid,publicationId:pubId,groups:[group]}])).not.toThrow();
 });
 it('checks every actual Consumer ACL membership, including an added business group',()=>{
  const g=graph();g.services.push(service(otherSid));g.routes.push(route(otherRid,otherSid));
  g.plugins.push(plugin(ids[9],'key-auth',{service:{id:otherSid}}),plugin(ids[10],'acl',{service:{id:otherSid}},{whitelist:['team-pay'],blacklist:null}));
  expect(()=>check(g,undefined,[{consumerId:cid,publicationId:pubId,groups:[group,'team-pay']}])).toThrow();
 });
 it.each(['anonymous','blacklist'])('rejects %s configuration that cannot prove whitelist isolation',field=>{
  const g=graph();if(field==='anonymous')g.plugins[0].config.anonymous=cid;else g.plugins[1].config.blacklist=['other'];
  expect(()=>check(g)).toThrow();
 });
 it('uses actual same-name precedence, rather than numeric execution priority',()=>{
  const surface={serviceId:sid,routeId:rid,consumerId:cid,protocol:'http'};
  const scopes=[{consumer:{id:cid},route:{id:rid},service:{id:sid}},{consumer:{id:cid},route:{id:rid}},{consumer:{id:cid},service:{id:sid}},{route:{id:rid},service:{id:sid}},{consumer:{id:cid}},{route:{id:rid}},{service:{id:sid}},{}];
  const plugins=scopes.map((scope,i)=>plugin(ids[8+i],'key-auth',scope));
  for(let i=0;i<scopes.length;i++)expect(effectivePortalPlugin(plugins.slice(i),'key-auth',surface)?.id).toBe(ids[8+i]);
 });
 it('skips disabled and other-subsystem overrides',()=>{
  const g=graph();g.plugins.push(plugin(ids[9],'key-auth',{route:{id:rid}},undefined,{enabled:false}),plugin(ids[10],'key-auth',{consumer:{id:cid}},undefined,{protocols:['tcp']}));
  expect(()=>check(g,undefined,[{consumerId:cid,publicationId:pubId,groups:[group]}])).not.toThrow();
 });
 it('rejects an enabled Route override of the verified published key-auth',()=>{
  const g=graph();g.plugins.push(plugin(ids[9],'key-auth',{route:{id:rid}}));expect(()=>check(g)).toThrow();
 });
 it('rejects ambiguity instead of arbitrarily selecting an authentication instance',()=>{
  const g=graph();g.plugins.push(plugin(ids[9],'key-auth',{service:{id:sid}}));
  expect(()=>check(g)).toThrowError(expect.objectContaining(code('PORTAL_AUTH_CHAIN_AMBIGUOUS')));
 });
 it.each(['custom-auth','pre-function','post-function','session'])('fails closed for unprovable %s authentication logic',name=>{
  const g=graph();g.plugins.push(plugin(ids[9],name,{service:{id:sid}},{}));expect(()=>check(g)).toThrow();
 });
 it('does not mistake an unrelated basic-auth-only API for a key-auth acceptance chain',()=>{
  const g=graph();g.services.push(service(otherSid));g.routes.push(route(otherRid,otherSid));g.plugins.push(plugin(ids[9],'basic-auth',{service:{id:otherSid}},{}));expect(()=>check(g)).not.toThrow();
 });
 it('does not invent reachable HTTP surfaces for unrelated stream Services without Routes',()=>{
  const g=graph();g.services.push({...service(otherSid),protocol:'tcp'});expect(()=>check(g)).not.toThrow();
 });
 it.each(['reference','duplicate','protocol','partial'])('rejects a %s graph instead of treating it as an empty list',kind=>{
  const g=graph();if(kind==='reference')g.routes[0].service={id:otherSid};if(kind==='duplicate')g.services.push(service());if(kind==='protocol')g.routes[0].protocols=['expression'];if(kind==='partial')(g as any).plugins={data:[]};expect(()=>validatePortalGraph(g)).toThrow();
 });
 it('bounds the prospective Surface × Consumer combinations',()=>expect(()=>assertPortalAuthenticationBoundary(graph(),[publication],[],1)).toThrowError(expect.objectContaining(code('PORTAL_AUTH_GRAPH_BUDGET'))));
 it('rejects a changed source object after a capture await',()=>{
  const before={id:sid,name:'original'};expect(()=>assertPortalCaptureStable(before,{...before,name:'changed'},canonicalJson)).toThrowError(expect.objectContaining(code('PORTAL_AUTH_GRAPH_CHANGED')));
  expect(()=>assertPortalCaptureStable(before,{name:'original',id:sid},canonicalJson)).not.toThrow();
 });
});
