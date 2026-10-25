import {describe,it,expect} from 'vitest';
import {resolve} from 'node:path';
import {assertProductionComposition} from '../../deploy/scripts/production-policy.mjs';
function configuration(){
 const hard={user:'1000:1000',image:'kongos/api:m0-m8-20261011',read_only:true,cap_drop:['ALL'],security_opt:['no-new-privileges:true']};
 const web=(name:string)=>({...structuredClone(hard),user:'101:101',networks:name==='console'?{frontend:{}}:{'portal-edge':{},'portal-entry':{}},ports:[{target:8443,published:'18443'}],volumes:[{type:'bind',source:resolve(`deploy/nginx/${name}-production.conf`),target:'/etc/nginx/conf.d/default.conf',read_only:true},{type:'bind',source:resolve(`deploy/private/test-${name}`),target:'/run/kongos-tls',read_only:true}]});
 return{name:'production-unit',services:{'kong-db':{},'kong-migrations':{},kong:{ports:[{target:8000}]},'console-db':{},redis:{},'console-migrations':structuredClone(hard),'console-api':{...structuredClone(hard),networks:{frontend:{},'kong-admin':{},'console-storage':{}},environment:{NODE_ENV:'production',COOKIE_SECURE:'true',TRUST_PROXY:'1',PUBLIC_ORIGINS:'https://console.example.test:18443',PORTAL_PUBLIC_ORIGINS:'https://portal.example.test:19443'}},'console-web':web('console'),'portal-web':web('portal')},networks:{'kong-admin':{internal:true},'kong-storage':{internal:true},'console-storage':{internal:true}}}as any;
}
describe('production deployment contract without Docker or secrets',()=>{
 it('accepts an independent hardened TLS deployment and states that runtime remains unverified',()=>{expect(assertProductionComposition(configuration(),{project:'production-unit'})).toMatchObject({productionContractValid:true,runtimeVerified:false,secretsPrinted:false});});
 it('validates an explicit platform-only installation without gateway/database startup dependencies',()=>{
  const c=configuration();for(const name of ['kong','kong-db','kong-migrations'])delete c.services[name];
  c.services['console-api'].environment.DEFAULT_KONG_ADMIN_URL='https://kong-admin.example.test';
  c.services['console-api'].environment.OUTBOUND_ALLOWED_HOSTS='kong-admin.example.test,prometheus,loki';
  c.services['console-api'].depends_on={'console-db':{condition:'service_healthy'},redis:{condition:'service_healthy'},'console-migrations':{condition:'service_completed_successfully'}};
  expect(assertProductionComposition(c,{project:'production-unit',externalKong:true})).toMatchObject({productionContractValid:true,services:6,externalKong:true,runtimeVerified:false});
  expect(()=>assertProductionComposition(c,{project:'production-unit'})).toThrow('PRODUCTION_COMPOSITION_INVALID');
  for(const mutation of [(v:any)=>v.services.kong={},(v:any)=>v.services['console-api'].depends_on.kong={condition:'service_healthy'},(v:any)=>v.services['console-api'].environment.OUTBOUND_ALLOWED_HOSTS='foreign.example.test',(v:any)=>v.services['console-api'].environment.DEFAULT_KONG_ADMIN_URL='https://user:password@kong-admin.example.test',(v:any)=>v.services['console-api'].environment.DEFAULT_KONG_ADMIN_URL='http://kong:8001']){const bad=structuredClone(c);mutation(bad);expect(()=>assertProductionComposition(bad,{project:'production-unit',externalKong:true})).toThrow('PRODUCTION_COMPOSITION_INVALID');}
 });
 it.each(['kongos-console','kongpilot-console'])('protects development project %s from production helpers',name=>{const c=configuration();c.name=name;expect(()=>assertProductionComposition(c,{project:name})).toThrow('PRODUCTION_COMPOSITION_INVALID');});
 it.each(['old-project','wrong-project','development','insecure-cookie','http-origin','same-cookie-host','public-admin','public-db','api-kong-db-network','source-bind','writable-bind','wrong-web-listener','missing-tls','root-web','different-migrator','test-service'])('rejects %s without exposing resolved secrets',kind=>{
  const c=configuration(),api=c.services['console-api'];api.environment.APP_SECRET='private-unit-canary';
  if(kind==='old-project')c.name='kongos-console';if(kind==='wrong-project')c.name='different';
  if(kind==='development')api.environment.NODE_ENV='development';if(kind==='insecure-cookie')api.environment.COOKIE_SECURE='false';
  if(kind==='http-origin')api.environment.PUBLIC_ORIGINS='http://console.example.test';if(kind==='same-cookie-host')api.environment.PORTAL_PUBLIC_ORIGINS='https://console.example.test:19443';
  if(kind==='public-admin')c.services.kong.ports.push({target:8001});if(kind==='public-db')c.services['kong-db'].ports=[{target:5432}];
  if(kind==='api-kong-db-network')api.networks['kong-storage']={};
  if(kind==='source-bind')api.volumes=[{type:'bind',target:'/app/apps/console-api/dist',source:'/private',read_only:true}];
  if(kind==='writable-bind')c.services['console-web'].volumes[0].read_only=false;
  if(kind==='wrong-web-listener')c.services['console-web'].ports[0].target=8080;
  if(kind==='missing-tls')c.services['console-web'].volumes.pop();if(kind==='root-web')c.services['console-web'].user='0:0';
  if(kind==='different-migrator')c.services['console-migrations'].image='different:release';if(kind==='test-service')c.services['mock-kong']={};
  expect(()=>assertProductionComposition(c,{project:'production-unit'})).toThrow('PRODUCTION_COMPOSITION_INVALID');
  try{assertProductionComposition(c,{project:'production-unit'});}catch(e:any){expect(e.message).not.toContain('private-unit-canary');}
 });
});
