import {resolve} from 'node:path';

const required=['kong-db','kong-migrations','kong','console-db','redis','console-migrations','console-api','console-web','portal-web'];
const sourceTargets=['/app','/app/apps/console-api/dist','/app/apps/console-api/dist/infrastructure/migrations','/usr/share/nginx/html','/opt/kongos-collector'];
const fail=()=>new Error('PRODUCTION_COMPOSITION_INVALID');
const names=value=>Array.isArray(value)?value:Object.keys(value??{});
function origins(value){
 const values=typeof value==='string'?value.split(',').map(s=>s.trim()).filter(Boolean):[];
 if(!values.length||values.length>8)throw fail();
 for(const s of values){let u;try{u=new URL(s);}catch{throw fail();}if(u.protocol!=='https:'||u.origin!==s||u.username||u.password)throw fail();}
 return values.map(s=>new URL(s));
}
/** Validate Docker's resolved JSON in memory. Never include its environment,
 * endpoint/secret values or raw Docker output in an exception or report.
 * This checks a deployment contract; live network/TLS/image checks are separate. */
export function assertProductionComposition(config,{project,repository=process.cwd(),observability=false,gitops=false,externalKong=false}={}){
 if(!project||['kongos-console','kongpilot-console'].includes(project)||!/^[a-z][a-z0-9_-]{1,62}$/.test(project)||config?.name!==project)throw fail();
 const services=config.services??{};
 const selectedRequired=externalKong?required.filter(name=>!['kong-db','kong-migrations','kong'].includes(name)):required;
 if(selectedRequired.some(name=>!services[name]))throw fail();
 if(externalKong&&['kong-db','kong-migrations','kong'].some(name=>services[name]))throw fail();
 if(Object.keys(services).some(name=>/^(mock-kong|echo-upstream|event-mail|event-receiver|kong-secondary|kong-portal)(?:-|$)/.test(name)))throw fail();
 const api=services['console-api'],env=api.environment??{};
 if(externalKong){
  let endpoint;try{endpoint=new URL(env.DEFAULT_KONG_ADMIN_URL);}catch{throw fail();}
  if(!['http:','https:'].includes(endpoint.protocol)||endpoint.username||endpoint.password||endpoint.search||endpoint.hash||endpoint.pathname!=='/'||['kong','localhost','127.0.0.1'].includes(endpoint.hostname))throw fail();
  const allowed=String(env.OUTBOUND_ALLOWED_HOSTS??'').split(',').map(value=>value.trim().toLowerCase());
  if(!allowed.includes(endpoint.hostname.toLowerCase()))throw fail();
  if(names(api.depends_on).some(name=>['kong','kong-db','kong-migrations'].includes(name)))throw fail();
 }
 if(env.NODE_ENV!=='production'||env.COOKIE_SECURE!=='true'||String(env.TRUST_PROXY)!=='1')throw fail();
 const consoleOrigins=origins(env.PUBLIC_ORIGINS),portalOrigins=origins(env.PORTAL_PUBLIC_ORIGINS);
 // Cookie scope is not isolated by TCP ports: use independent hostnames.
 if(consoleOrigins.some(c=>portalOrigins.some(p=>c.hostname===p.hostname)))throw fail();
 if(api.user!=='1000:1000'||api.read_only!==true||!names(api.cap_drop).includes('ALL')||api.ports?.length)throw fail();
 if(names(api.networks).some(n=>/kong-storage/.test(n)))throw fail();
 if(services['console-migrations'].image!==api.image)throw fail();
 for(const name of ['console-api','console-migrations','console-web','portal-web',...(observability?['telemetry-collector']:[])]){
  const s=services[name];if(!s||s.read_only!==true||!names(s.cap_drop).includes('ALL')||!s.security_opt?.some(x=>x==='no-new-privileges:true'||x==='no-new-privileges'))throw fail();
  if(typeof s.image!=='string'||/<|>|:(?:local|latest)$/.test(s.image))throw fail();
  for(const m of s.volumes??[]){
   if(m.type==='bind'&&(sourceTargets.includes(m.target)||/\/(?:node_modules|src|dist)(?:\/|$)/.test(m.target)||m.target==='/var/run/docker.sock'))throw fail();
   if(m.type==='bind'&&m.read_only!==true)throw fail();
  }
 }
 for(const name of ['console-web','portal-web']){
  const s=services[name];if(s.user!=='101:101'||!s.ports?.length||s.ports.some(p=>Number(p.target)!==8443))throw fail();
  const mounts=s.volumes??[],expected=resolve(repository,`deploy/nginx/${name==='console-web'?'console':'portal'}-production.conf`);
  if(!mounts.some(m=>m.type==='bind'&&m.source===expected&&m.target==='/etc/nginx/conf.d/default.conf'&&m.read_only===true))throw fail();
  if(!mounts.some(m=>m.type==='bind'&&m.target==='/run/kongos-tls'&&m.read_only===true))throw fail();
 }
 const kong=services.kong;
 if((kong?.ports??[]).some(p=>Number(p.target)===8001)||!config.networks?.['kong-admin']?.internal||!config.networks?.['console-storage']?.internal||(!externalKong&&!config.networks?.['kong-storage']?.internal))throw fail();
 for(const name of ['kong-db','console-db','redis'])if(services[name]?.ports?.length)throw fail();
 if(names(services['console-web'].networks).some(n=>n!=='frontend')||names(services['portal-web'].networks).some(n=>!['portal-edge','portal-entry'].includes(n)))throw fail();
 if(observability){
  const collector=services['telemetry-collector'];
  if(collector.user!=='1000:1000'||collector.ports?.length||names(collector.networks).some(n=>!['telemetry','proxy-edge','observability'].includes(n)))throw fail();
  if(!config.networks?.telemetry?.internal)throw fail();
  if((collector.volumes??[]).some(m=>m.target!=='/run/kongos-metrics'||m.read_only!==true)||!collector.volumes?.length)throw fail();
 }
 if(gitops){
  const runner=services['console-deck-runner'];if(!runner||runner.user!=='1000:1000'||runner.read_only!==true||runner.ports?.length||names(runner.networks).some(n=>n!=='frontend'))throw fail();
  if((runner.volumes??[]).some(m=>m.target!=='/run/kongos-deck-ca'||m.read_only!==true))throw fail();
  let u;try{u=new URL(runner.environment?.DECK_CONSOLE_ORIGIN);}catch{throw fail();}
  if(u.protocol!=='https:'||u.port!=='8443'||!consoleOrigins.some(c=>c.hostname===u.hostname)||u.username||u.password||u.search||u.hash||u.pathname!=='/')throw fail();
 }
 return Object.freeze({project,productionContractValid:true,services:selectedRequired.length,observability,gitops,externalKong,secretsPrinted:false,runtimeVerified:false});
}
