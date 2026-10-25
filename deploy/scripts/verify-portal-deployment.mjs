import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {portalTopologyChecks} from './portal-network-policy.mjs';
const stage=process.env.PORTAL_EVIDENCE_STAGE||'M6',directory=resolve(process.env.PORTAL_EVIDENCE_DIRECTORY||`artifacts/${stage}`);
const multicluster=process.argv.includes('--multicluster'),observability=process.argv.includes('--observability');
const compose=['compose','--env-file','.env',...(multicluster?['--env-file','.env.multicluster']:[]),'-f','docker-compose.yml','-f','deploy/compose.development.yml',...(multicluster?['-f','deploy/compose.multicluster-test.yml','--profile','multicluster-test']:[]),...(observability?['-f','deploy/compose.metrics.yml','--profile','observability']:[])];
const checks=[],traces=[],assets=[];
const check=(name,passed)=>checks.push({name,passed:Boolean(passed)});
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
function inspect(name){const id=execFileSync('docker',[...compose,'ps','-q',name],{encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();if(!id)throw new Error('missing');return JSON.parse(execFileSync('docker',['inspect',id],{encoding:'utf8',stdio:['pipe','pipe','pipe']}))[0];}
let topology;
try{
  const portal=inspect('portal-web'),api=inspect('console-api');
  const networks=Object.entries(portal.NetworkSettings.Networks);
  const edge=networks.find(([name])=>name.endsWith('_portal-edge')),entry=networks.find(([name])=>name.endsWith('_portal-entry'));
  const privateNetwork=JSON.parse(execFileSync('docker',['network','inspect',edge[1].NetworkID],{encoding:'utf8',stdio:['pipe','pipe','pipe']}))[0],entryNetwork=JSON.parse(execFileSync('docker',['network','inspect',entry[1].NetworkID],{encoding:'utf8',stdio:['pipe','pipe','pipe']}))[0];
  const members=network=>Object.keys(network.Containers).map(id=>id===api.Id?'console-api':id===portal.Id?'portal-web':`other:${id}`);
  const published=bindings=>Object.entries(bindings||{}).flatMap(([target,rows])=>(rows||[]).map(row=>({hostIp:row.HostIp,hostPort:row.HostPort,containerPort:Number(target.split('/')[0])})));
  const env=Object.fromEntries(api.Config.Env.map(value=>{const index=value.indexOf('=');return[value.slice(0,index),value.slice(index+1)];}));
  for(const row of portalTopologyChecks({runtime:true,networkMode:portal.HostConfig.NetworkMode,portalNetworks:networks.map(([name])=>name.replace(/^.*_(portal-edge|portal-entry)$/,'$1')),apiNetworks:Object.keys(api.NetworkSettings.Networks).map(name=>name.replace(/^.*_(portal-edge|portal-entry)$/,'$1')),edge:{internal:privateNetwork.Internal,driver:privateNetwork.Driver,members:members(privateNetwork)},entry:{internal:entryNetwork.Internal,driver:entryNetwork.Driver,members:members(entryNetwork)},edgeAddress:edge[1].IPAddress,entryAddress:entry[1].IPAddress,published:published(portal.HostConfig.PortBindings),effectivePublished:published(portal.NetworkSettings.Ports),protectedHosts:(env.PROTECTED_DESTINATION_HOSTS||'').split(',')}))check(`actual ${row.name}`,row.passed);
  check('actual Portal is healthy',portal.State.Health?.Status==='healthy');
  check('actual Portal UID101/capdrop/NNP/rootfsreadonly',portal.Config.User==='101:101'&&portal.HostConfig.CapDrop.includes('ALL')&&portal.HostConfig.SecurityOpt.includes('no-new-privileges:true')&&portal.HostConfig.ReadonlyRootfs===true);
  check('actual Portal tmpfs and no persistent mounts',Object.hasOwn(portal.HostConfig.Tmpfs||{},'/tmp')&&!portal.Mounts.some(row=>row.Type==='volume'));
  check('API management and telemetry ports remain unpublished',Object.keys(api.HostConfig.PortBindings||{}).length===0);
  check('actual Portal secret independent from Console/encryption',/^[a-f0-9]{64}$/.test(env.PORTAL_SECRET)&&env.PORTAL_SECRET!==env.APP_SECRET&&env.PORTAL_SECRET!==env.CONSOLE_ENCRYPTION_KEY);
  check('explicit development override permits local HTTP cookies only',env.NODE_ENV==='development'&&env.COOKIE_SECURE==='false');
  check('Portal origins explicit and separate from SSO setting',env.PORTAL_PUBLIC_ORIGINS?.split(',').every(origin=>origin==='http://127.0.0.1:8082'||origin==='http://localhost:8082'||origin.startsWith('https://')));
  for(const name of ['console-web','portal-web',...(observability?['prometheus','telemetry-collector','loki']:[])])check(`${name} has no Portal signing key`,!inspect(name).Config.Env.some(value=>value.startsWith('PORTAL_SECRET=')));
  for(const [destination,host] of [['/etc/nginx/nginx.conf','deploy/nginx/portal-nginx.conf'],['/etc/nginx/conf.d/default.conf','deploy/nginx/portal.conf']]){
    const actual=execFileSync('docker',[...compose,'exec','-T','portal-web','cat',destination],{stdio:['pipe','pipe','pipe']});
    check(`actual Portal ${destination} matches approved config`,hash(actual)===hash(readFileSync(host)));
    check(`actual Portal ${destination} readonly binding`,portal.Mounts.some(row=>row.Type==='bind'&&row.Destination===destination&&!row.RW));
  }
  check('actual Portal frontend readonly binding',portal.Mounts.some(row=>row.Type==='bind'&&row.Destination==='/usr/share/nginx/html'&&!row.RW));
  const base=(process.env.PORTAL_BASE_URL||'http://127.0.0.1:8082').replace(/\/$/,''),consoleBase=(process.env.CONSOLE_BASE_URL||'http://127.0.0.1:8080').replace(/\/$/,'');
  const indexResponse=await fetch(base,{signal:AbortSignal.timeout(5000)}),index=Buffer.from(await indexResponse.arrayBuffer());
  check('served Portal index matches current compiled file',indexResponse.status===200&&hash(index)===hash(readFileSync('apps/portal-web/dist/index.html')));
  for(const header of ['content-security-policy','x-content-type-options','x-frame-options','referrer-policy','permissions-policy'])check(`Portal sends ${header}`,Boolean(indexResponse.headers.get(header)));
  const paths=[...new Set([...index.toString('utf8').matchAll(/(?:src|href)="(\/assets\/[A-Za-z0-9_-]+\.(?:js|css))"/g)].map(match=>match[1]))];
  check('Portal declares compiled assets',paths.length>0);
  for(const path of paths){const response=await fetch(`${base}${path}`,{signal:AbortSignal.timeout(5000)}),bytes=Buffer.from(await response.arrayBuffer());check(`served Portal ${path} matches current compiled asset`,response.status===200&&hash(bytes)===hash(readFileSync(resolve('apps/portal-web/dist',path.slice(1)))));assets.push({path,sha256:hash(bytes),bytes:bytes.length});}
  for(const path of ['/api','/api/v1/portal','/api/docs','/api/docs-json','/api/v1/clusters','/api/v1/auth/me','/api/v1/health/ready','/scrape/x','/catalog/x','/ingest/x','/metrics/x','/swagger','/admin']){const response=await fetch(`${base}${path}`,{signal:AbortSignal.timeout(3000)});traces.push({origin:'portal',method:'GET',path,status:response.status});check(`Portal blocks ${path}`,response.status===404);await response.body?.cancel();}
  const authPath='/api/v1/portal/auth/me';
  const forwarded=await fetch(`${base}${authPath}`,{signal:AbortSignal.timeout(3000)});
  check('exact Portal API prefix reaches authentication guard',forwarded.headers.get('content-type')?.includes('application/json')&&Boolean(forwarded.headers.get('x-request-id'))&&[400,401].includes(forwarded.status));
  traces.push({origin:'portal',method:'GET',path:authPath,status:forwarded.status,requestId:forwarded.headers.get('x-request-id')});await forwarded.body?.cancel();
  const denied=await fetch(`${consoleBase}${authPath}`,{signal:AbortSignal.timeout(3000)});check('Console host refuses Portal private API prefix',denied.status===404);await denied.body?.cancel();
  for(const [name,address] of [['KongAdmin','http://kong:8001/'],['KongDB','http://kong-db:5432/'],['Redis','http://redis:6379/'],['internal metrics listener','http://console-api:9092/health'],['collector','http://telemetry-collector:9093/health']]){let reachable=false;try{execFileSync('docker',[...compose,'exec','-T','portal-web','wget','-Y','off','-T','2','-q','--spider',address],{timeout:4000,stdio:['pipe','pipe','pipe']});reachable=true;}catch{}check(`Portal network cannot reach ${name}`,!reachable);}
  const networkIP=(service,kind)=>Object.entries(inspect(service).NetworkSettings.Networks).find(([name])=>!kind||name.includes(kind))[1].IPAddress;
  for(const[name,address,port]of [['local Portal','127.0.0.1',8080],['private BFF',api.NetworkSettings.Networks[edge[0]].IPAddress,3000]]){
    let connected=false;try{execFileSync('docker',[...compose,'exec','-T','portal-web','nc','-n','-z','-w','1',address,String(port)],{timeout:2500,stdio:['pipe','pipe','pipe']});connected=true;}catch{}
    check(`same nc flags positively connect to ${name}`,connected);
    traces.push({origin:'portal',method:'TCP',target:name,address,port,positiveControl:true,tcpReachable:connected});
  }
  const literalTargets=[['primary Admin',networkIP('kong','admin'),8001,'/status'],...(multicluster?[['secondary Admin',networkIP('kong-secondary','admin'),8001,'/status'],['secondary KongDB',networkIP('kong-secondary-db'),5432,'/']]:[]),['KongDB',networkIP('kong-db'),5432,'/'],['console DB',networkIP('console-db'),5432,'/'],['Redis',networkIP('redis'),6379,'/'],['private backend metrics port',api.NetworkSettings.Networks[edge[0]].IPAddress,9092,'/health'],...(observability?[['internal metrics listener',env.METRICS_BRIDGE_HOST,9092,'/health'],...Object.entries(inspect('telemetry-collector').NetworkSettings.Networks).map(([name,row])=>[`collector ${name}`,row.IPAddress,9093,'/health'])]:[])];
  for(const[name,address,port,path]of literalTargets){
    let readable=false,tcpReachable=false,httpStatus=null;
    try{execFileSync('docker',[...compose,'exec','-T','portal-web','wget','-Y','off','-T','2','-q','-O','/dev/null',`http://${address}:${port}${path}`],{timeout:4000,stdio:['pipe','pipe','pipe']});readable=true;httpStatus=200;}catch(error){httpStatus=Number(error.stderr?.toString().match(/server returned error:\s*(?:HTTP\/[\d.]+\s+)?(\d{3})/)?.[1]||0)||null;}
    try{execFileSync('docker',[...compose,'exec','-T','portal-web','nc','-n','-z','-w','1',address,String(port)],{timeout:2500,stdio:['pipe','pipe','pipe']});tcpReachable=true;}catch{}
    check(`Portal cannot read protected ${name} by literalIP`,!readable);
    check(`Portal ${name} TCP is unreachable or Admin ACL denies403`,!tcpReachable||(name.includes('Admin')&&httpStatus===403));
    traces.push({origin:'portal',method:'GET',target:name,address,port,httpStatus,tcpReachable});
  }
  topology={portalNetworks:networks.map(([name,value])=>({name,address:value.IPAddress})),apiPortalAddress:api.NetworkSettings.Networks[edge[0]]?.IPAddress,portalImage:portal.Image,portalIndexSHA256:hash(index)};
}catch{check('actual Portal deployment verification completed',false);}
const result={stage,observedAt:new Date().toISOString(),scope:'startup/network/UID/static assets/API boundary only; user workflow and gateway credentials require separate live tests',allPassed:checks.length>0&&checks.every(row=>row.passed),checks,traces,assets,topology};
mkdirSync(directory,{recursive:true});writeFileSync(resolve(directory,'portal-deployment-verification.json'),JSON.stringify(result,null,2)+'\n');
console.log(`${checks.filter(row=>row.passed).length}/${checks.length} actual Portal deployment checks passed; no private values recorded.`);
if(!result.allPassed)process.exitCode=1;
