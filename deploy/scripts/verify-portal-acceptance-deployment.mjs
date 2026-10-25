import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
const checks=[],observations=[];
const check=(name,passed)=>checks.push({name,passed:Boolean(passed)});
function docker(args,input){return execFileSync('docker',args,{encoding:'utf8',input,stdio:['pipe','pipe','pipe'],timeout:20000,maxBuffer:2e6});}
function inspect(service){const ids=docker(['ps','-q','--filter','label=com.docker.compose.project=kongos-console','--filter',`label=com.docker.compose.service=${service}`]).trim().split(/\s+/).filter(Boolean);if(ids.length!==1)throw new Error('SERVICE_MISSING');return JSON.parse(docker(['inspect',ids[0]]))[0];}
function ownStatus(id,address,spoof=false){const args=['exec',id,'wget','-Y','off','-T','3','-q','-O','/dev/null'];if(spoof)args.push('--header','X-Forwarded-For: 172.28.13.10','--header','X-Real-IP: 172.28.13.10','--header','Forwarded: for=172.28.13.10');args.push(`http://${address}:8001/status`);const result=spawnSync('docker',args,{encoding:'utf8',timeout:6000,stdio:['pipe','pipe','pipe']});return result.status===0?200:Number((result.stderr||'').match(/server returned error:\s*(?:HTTP\/[\d.]+\s+)?(\d{3})/)?.[1]||0);}
function tcp(id,address,port){return spawnSync('docker',['exec',id,'nc','-n','-z','-w','1',address,String(port)],{encoding:'utf8',timeout:3000,stdio:['pipe','pipe','pipe']}).status===0;}
try{
 const api=inspect('console-api'),native=inspect('kong-portal'),db=inspect('kong-portal-db'),portal=inspect('portal-web');
 const adminName=Object.keys(native.NetworkSettings.Networks).find(name=>name.endsWith('_kong-portal-admin')),storageName=Object.keys(native.NetworkSettings.Networks).find(name=>name.endsWith('_kong-portal-storage'));
 const admin=JSON.parse(docker(['network','inspect',adminName]))[0],storage=JSON.parse(docker(['network','inspect',storageName]))[0];
 const names=value=>Object.values(value.Containers||{}).map(row=>row.Name.replace(/^kongos-console-/,'').replace(/-1$/,'')).sort().join(',');
 check('C3 Kong/PG and BFF/Portal healthy',[native,db,api,portal].every(value=>value.State.Health?.Status==='healthy'));
 check('new Admin internal exact BFF/Kong members',admin.Internal===true&&names(admin)==='console-api,kong-portal');
 check('new PG internal exact Kong/PG members after bootstrap exits',storage.Internal===true&&names(storage)==='kong-portal,kong-portal-db');
 check('BFF exact source and Kong exact Admin IPv4',api.NetworkSettings.Networks[adminName]?.IPAddress==='172.28.13.10'&&native.NetworkSettings.Networks[adminName]?.IPAddress==='172.28.13.20');
 check('BFF has no C3 or canonical KongDB network',Object.keys(api.NetworkSettings.Networks).every(name=>!/_kong(?:-secondary|-portal)?-storage(?:-secure)?$/.test(name)));
 check('C3 fixed storage and independent PG11 volume',db.NetworkSettings.Networks[storageName]?.IPAddress==='172.28.23.20'&&native.NetworkSettings.Networks[storageName]?.IPAddress==='172.28.23.10'&&db.Mounts.some(row=>row.Type==='volume'&&row.Name==='kongos-console_kong_portal_db_data'));
 const oldVolumes=['kong-db','kong-secondary-db'].flatMap(name=>inspect(name).Mounts.filter(row=>row.Type==='volume').map(row=>row.Name));
 check('new PG volume differs from all canonical KongDB volumes',db.Mounts.filter(row=>row.Type==='volume').every(row=>!oldVolumes.includes(row.Name)));
 check('onlylocalhost10000 proxy published and no Admin/PG ports',native.NetworkSettings.Ports['8000/tcp']?.length===1&&native.NetworkSettings.Ports['8000/tcp'][0].HostIp==='127.0.0.1'&&native.NetworkSettings.Ports['8000/tcp'][0].HostPort==='10000'&&!native.NetworkSettings.Ports['8001/tcp']?.length&&!Object.values(db.NetworkSettings.Ports||{}).some(rows=>rows?.length));
 check('native kong user capdrop NNP',native.Config.User==='kong'&&native.HostConfig.CapDrop?.includes('ALL')&&native.HostConfig.SecurityOpt?.includes('no-new-privileges:true'));
 const acl=docker(['exec',native.Id,'cat','/usr/local/kong/kongos-admin-access.conf']);
 check('ordered Admin ACL exact BFF source only',acl==='allow 172.28.13.10;\ndeny all;\n');
 const main=docker(['exec',native.Id,'cat','/usr/local/kong/nginx.conf']),generated=docker(['exec',native.Id,'cat','/usr/local/kong/nginx-kong.conf']),format=docker(['exec',native.Id,'cat','/usr/local/kong/kongos-http.conf']);
 const marker=generated.indexOf('server_name kong_admin;'),start=generated.lastIndexOf('\nserver {',marker),end=generated.indexOf('\nserver {',marker),block=generated.slice(start,end<0?undefined:end),listeners=[...block.matchAll(/\blisten\s+([^;]+);/g)].map(row=>row[1].trim()).sort();
 check('only fixed IPv4 and rejected loopback Admin listeners',JSON.stringify(listeners)===JSON.stringify(['127.0.0.1:8001','172.28.13.20:8001']));
 check('Admin does not trust forwarded source headers',!/\b(?:real_ip_header|set_real_ip_from|real_ip_recursive)\b/.test(main+block+generated.slice(0,generated.indexOf('\nserver {'))));
 check('loopback Admin denied while PID health healthy',ownStatus(native.Id,'127.0.0.1')===403);
 check('native self Admin denied',ownStatus(native.Id,'172.28.13.20')===403);
 check('spoofed forwarding headers cannot impersonate BFF',ownStatus(native.Id,'172.28.13.20',true)===403);
 const errors=[...(main+generated).matchAll(/\berror_log\s+([^;]+);/g)].map(row=>row[1].trim());
 check('native request errors discarded and safe access format only',errors.length>0&&errors.every(line=>/^\/dev\/null(?:\s+\w+)?$/.test(line))&&!/\$(?:request_uri|uri|args|query_string|http_|request_body|request\b)/.test(format));
 const env=Object.fromEntries(api.Config.Env.map(row=>{const index=row.indexOf('=');return[row.slice(0,index),row.slice(index+1)];}));
 check('BFF exact endpoint host:port allow rule installed',env.OUTBOUND_ALLOWED_HOSTS.split(',').includes('kong-portal-admin-endpoint:8001'));
 for(const host of ['kong-portal-db','172.28.23.20','kong-portal-admin-endpoint','172.28.13.20','172.28.13.10'])check(`BFF protects C3 control destination ${host}`,env.PROTECTED_DESTINATION_HOSTS.split(',').includes(host));
 const code=String.raw`const urls=['http://kong-portal-admin-endpoint:8001','http://kong-secondary:8001'];const out=[];for(const url of urls){const r=await fetch(url+'/',{signal:AbortSignal.timeout(5000)}),root=await r.json(),s=await fetch(url+'/status'),p=await fetch(url+'/plugins/enabled'),plugins=await p.json();await s.body.cancel();out.push({endpoint:url,version:root.version,nodeId:root.node_id,rootStatus:r.status,statusStatus:s.status,pluginsStatus:p.status,pluginCount:plugins.enabled_plugins?.length});}const empty=[];for(const name of ['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis']){const r=await fetch(urls[0]+'/'+name+'?size=1'),data=await r.json();empty.push({type:name,status:r.status,empty:Array.isArray(data.data)&&data.data.length===0&&!data.next});}console.log(JSON.stringify({nodes:out,empty}));`;
 const result=JSON.parse(docker(['exec','-i',api.Id,'node','--input-type=module','-e',code]));
 check('C3 and reused C2 are genuine distinct Kong1.5.1 nodes',result.nodes.length===2&&result.nodes.every(row=>row.version==='1.5.1')&&result.nodes[0].nodeId!==result.nodes[1].nodeId&&Boolean(result.nodes[0].nodeId));
 check('genuine BFF source root/status/enabled access succeeds',result.nodes.every(row=>row.rootStatus===200&&row.statusStatus===200&&row.pluginsStatus===200));
 for(const row of result.empty)check(`initial C3 ${row.type} collection clean before registration/fixtures`,row.status===200&&row.empty);
 observations.push(...result.nodes);
 const edge=Object.entries(api.NetworkSettings.Networks).find(([name])=>name.endsWith('_portal-edge'))?.[1];
 const positiveLocal=tcp(portal.Id,'127.0.0.1',8080),positiveApi=tcp(portal.Id,edge.IPAddress,3000);
 check('same nc flags positive localhostPortal control succeeds',positiveLocal);
 check('same nc flags positive BFF-private3000 control succeeds',positiveApi);
 for(const [name,address,port] of [['C3Admin','172.28.13.20',8001],['C3PG','172.28.23.20',5432]])check(`Portal literal TCP ${name} unreachable`,positiveLocal&&positiveApi&&!tcp(portal.Id,address,port));
 for(const name of ['portal-web','console-web','telemetry-collector','prometheus','loki'])check(`${name} absent from new Admin/storage networks`,Object.keys(inspect(name).NetworkSettings.Networks).every(network=>network!==adminName&&network!==storageName));
 const response=await fetch('http://127.0.0.1:10000/',{signal:AbortSignal.timeout(3000)});check('fresh C3 localhost proxy works with no configured Route',response.status===404);await response.body?.cancel();
}catch{check('C3 read-only deployment validation completed',false);}
const result={stage:'M6',scope:'read-only new C3 Kong1.5.1/PG11/Admin ACL/initial clean collections and Portal literal isolation; no writes or KongDB queries',observedAt:new Date().toISOString(),allPassed:checks.length>0&&checks.every(row=>row.passed),checks,observations};
mkdirSync('artifacts/M6',{recursive:true});writeFileSync('artifacts/M6/portal-acceptance-deployment-verification.json',JSON.stringify(result,null,2)+'\n');
console.log(`${checks.filter(row=>row.passed).length}/${checks.length} new C3 deployment checks passed; no secret/native response bodies recorded.`);
if(!result.allPassed)process.exitCode=1;
