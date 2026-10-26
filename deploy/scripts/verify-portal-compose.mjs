import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {stagePlan} from './stage-plan.mjs';
import {portalTopologyChecks} from './portal-network-policy.mjs';

const checks=[];
const check=(name,passed)=>checks.push({name,passed:Boolean(passed)});
function subnetRange(cidr){const [ip,rawPrefix]=cidr.split('/'),parts=ip.split('.').map(Number),prefix=Number(rawPrefix);if(parts.length!==4||parts.some(part=>!Number.isInteger(part)||part<0||part>255)||!Number.isInteger(prefix)||prefix<0||prefix>32)throw new Error('PORTAL_SUBNET_INVALID');const number=parts.reduce((result,part)=>result*256+part,0),span=2**(32-prefix),start=Math.floor(number/span)*span;return[start,start+span-1];}
try{
  // The new mandatory variable is a synthetic process-scoped value during
  // offline validation. Never append to the live environment here.
  const env={...process.env,PORTAL_SECRET:randomBytes(32).toString('hex'),PORTAL_PUBLIC_ORIGINS:'https://portal.example.test',COOKIE_SECURE:'true'};
  const base=['compose','--env-file','.env'];
  const configurations=[
    ['production',[...base,'-f','docker-compose.yml']],
    ['development-dual-monitoring',[...base,'--env-file','.env.multicluster','-f','docker-compose.yml','-f','deploy/compose/compose.development.yml','-f','deploy/compose/compose.multicluster-test.yml','--profile','multicluster-test','-f','deploy/compose/compose.metrics.yml','--profile','observability']],
  ];
  for(const [mode,args] of configurations){
    const effectiveEnv=mode==='production'?env:{...env,PORTAL_PUBLIC_ORIGINS:'http://127.0.0.1:8082,http://localhost:8082'};
    const config=JSON.parse(execFileSync('docker',[...args,'config','--format','json'],{env:effectiveEnv,encoding:'utf8',stdio:['pipe','pipe','pipe']}));
    const portal=config.services['portal-web'],api=config.services['console-api'];
    const members=name=>Object.entries(config.services).filter(([,service])=>Object.hasOwn(service.networks||{},name)).map(([service])=>service);
    for(const row of portalTopologyChecks({networkMode:portal.network_mode||'bridge',portalNetworks:Object.keys(portal.networks),apiNetworks:Object.keys(api.networks),edge:{internal:config.networks['portal-edge'].internal===true,driver:config.networks['portal-edge'].driver||'bridge',members:members('portal-edge')},entry:{internal:config.networks['portal-entry'].internal===true,driver:config.networks['portal-entry'].driver||'bridge',members:members('portal-entry')},edgeAddress:portal.networks['portal-edge'].ipv4_address,entryAddress:portal.networks['portal-entry'].ipv4_address,published:portal.ports.map(row=>({hostIp:row.host_ip,hostPort:row.published,containerPort:row.target})),protectedHosts:api.environment.PROTECTED_DESTINATION_HOSTS.split(',')}))check(`${mode}: ${row.name}`,row.passed);
    check(`${mode}: Portal backend and API fixed IPs distinct`,portal.networks['portal-edge'].ipv4_address!==api.networks['portal-edge'].ipv4_address);
    check(`${mode}: nonroot Portal with read-only rootfs/capdrop/NNP`,portal.user==='101:101'&&portal.read_only===true&&portal.cap_drop.includes('ALL')&&portal.security_opt.includes('no-new-privileges:true'));
    check(`${mode}: Portal ephemeral tmpfs only`,portal.tmpfs.some(path=>path.startsWith('/tmp:'))&&!portal.volumes?.some(mount=>mount.type==='volume'));
    check(`${mode}: independent Portal secret only in API`,/^[a-f0-9]{64}$/.test(api.environment.PORTAL_SECRET)&&api.environment.PORTAL_SECRET!==api.environment.APP_SECRET&&Object.entries(config.services).every(([name,service])=>name==='console-api'||!Object.hasOwn(service.environment||{},'PORTAL_SECRET')));
    check(`${mode}: Portal origins are distinct explicit API setting`,Boolean(api.environment.PORTAL_PUBLIC_ORIGINS)&&Object.entries(config.services).every(([name,service])=>name==='console-api'||!Object.hasOwn(service.environment||{},'PORTAL_PUBLIC_ORIGINS')));
    check(`${mode}: explicit TLS production or HTTP development runtime`,mode==='production'?api.environment.NODE_ENV==='production'&&api.environment.COOKIE_SECURE==='true'&&api.environment.PORTAL_PUBLIC_ORIGINS.startsWith('https://'):api.environment.NODE_ENV==='development'&&api.environment.COOKIE_SECURE==='false');
    for(const name of ['portal-edge','portal-entry']){
      const range=subnetRange(config.networks[name].ipam.config[0].subnet);
      check(`${mode}: declared ${name} subnet does not overlap other fixed networks`,Object.entries(config.networks).filter(([other])=>other!==name).every(([,network])=>(network.ipam?.config||[]).filter(row=>!row.subnet.includes(':')).every(row=>{const other=subnetRange(row.subnet);return range[1]<other[0]||range[0]>other[1];})));
    }
    if(mode.startsWith('development'))check(`${mode}: nginx/compiled assets bind read-only`,['/usr/share/nginx/html','/etc/nginx/conf.d/default.conf','/etc/nginx/nginx.conf'].every(target=>portal.volumes.some(row=>row.target===target&&row.type==='bind'&&row.read_only===true)));
  }
  const server=readFileSync('deploy/nginx/portal.conf','utf8'),main=readFileSync('deploy/nginx/portal-nginx.conf','utf8'),consoleNginx=readFileSync('deploy/nginx/default.conf','utf8');
  check('exact trailing-slash Portal API is sole proxy',server.includes('location ^~ /api/v1/portal/ {')&&[...server.matchAll(/proxy_pass\s/g)].length===1&&server.includes('proxy_pass http://console-api:3000;'));
  check('all other API paths fail404',server.includes('location ^~ /api/ { return 404; }')&&server.includes('location = /api { return 404; }'));
  check('Console host rejects developer Portal API',consoleNginx.includes('location ^~ /api/v1/portal/ { return 404; }'));
  check('Portal origin preserves external port and replaces client spoof headers',server.includes('Host $http_host;')&&server.includes('X-Forwarded-Host $http_host;')&&server.includes('X-Forwarded-For $remote_addr;')&&server.includes('X-Real-IP $remote_addr;'));
  check('Portal CSP disallows external script/connect/frame',server.includes("script-src 'self';")&&server.includes("connect-src 'self';")&&server.includes("frame-ancestors 'none';")&&server.includes("object-src 'none';"));
  const log=server.split('\n').find(line=>line.startsWith('log_format'));
  check('Portal native logs omit query/referrer/header/body and errors',Boolean(log)&&!['$request ','$args','$request_uri','$http_'].some(field=>log.includes(field))&&server.includes('error_log /dev/null;'));
  check('all nginx writable paths use tmpfs',main.includes('pid /tmp/nginx.pid;')&&['client_body','proxy','fastcgi','uwsgi','scgi'].every(name=>new RegExp(`${name}_temp_path /tmp/`).test(main)));
  const plan=stagePlan({stage:'M6',compose:['compose'],portal:true,observability:true,multicluster:true,captureExistingMetrics:true});
  check('M6 plan has no metrics enrollment/rotation/service up/reload or native transition',plan.every(([name])=>!['enroll-metrics','prometheus-reload','prepare-metrics-storage','apply-metrics-services','move-kong-databases-preserving-volumes','move-kong-gateways-preserving-volumes'].includes(name)));
  check('M6 captures current generation after API config/readiness and continuity',plan.findIndex(([name])=>name==='capture-existing-metrics-test-reference')>plan.findIndex(([name])=>name==='continuity-after')&&plan.findIndex(([name])=>name==='apply-api-config')>plan.findIndex(([name])=>name==='migrate'));
  check('M5 retains initial metrics enrollment',stagePlan({stage:'M5',compose:['compose'],observability:true}).some(([name])=>name==='enroll-metrics'));
}catch{check('offline Portal configuration validation completed',false);}
const result={stage:'M6',observedAt:new Date().toISOString(),scope:'offline Compose, nginx source and stage plan only; no runtime changes or live secrets generated',allPassed:checks.length>0&&checks.every(row=>row.passed),checks};
mkdirSync('artifacts/M6',{recursive:true});writeFileSync('artifacts/M6/portal-compose-verification.json',JSON.stringify(result,null,2)+'\n');
console.log(`${checks.filter(row=>row.passed).length}/${checks.length} offline Portal deployment checks passed; no private values recorded.`);
if(!result.allPassed)process.exitCode=1;
