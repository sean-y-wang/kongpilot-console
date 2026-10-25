import{execFileSync}from'node:child_process';
import{createHash}from'node:crypto';
import{mkdirSync,readFileSync,writeFileSync}from'node:fs';
import{resolve}from'node:path';
const stage=process.env.DELIVERY_EVIDENCE_STAGE??'M7',directory=resolve(process.env.DELIVERY_EVIDENCE_DIRECTORY??`artifacts/${stage}`);
const compose=['compose','--env-file','.env','--env-file','.env.multicluster',...(process.argv.includes('--portal-acceptance')?['--env-file','.env.portal-acceptance']:[]),'-f','docker-compose.yml','-f','deploy/compose.development.yml','-f','deploy/compose.multicluster-test.yml','-f','deploy/compose.metrics.yml',...(process.argv.includes('--portal-acceptance')?['-f','deploy/compose.portal-acceptance.yml']:[]),'-f','deploy/compose.notifications-test.yml','--profile','multicluster-test','--profile','observability','--profile','notifications-test'];
const checks=[],hash=bytes=>createHash('sha256').update(bytes).digest('hex'),check=(name,passed)=>checks.push({name,passed:!!passed});
const run=args=>execFileSync('docker',args,{stdio:['pipe','pipe','pipe'],encoding:'utf8',timeout:5000});
const inspect=name=>JSON.parse(run(['inspect',run([...compose,'ps','-q',name]).trim()]))[0];
try{
 const api=inspect('console-api'),https=inspect('event-receiver'),smtp=inspect('event-mail');
 const delivery=Object.entries(api.NetworkSettings.Networks).find(([name])=>name.endsWith('_delivery-test'));
 const network=JSON.parse(run(['network','inspect',delivery[1].NetworkID]))[0];
 const exactIDs=Object.keys(network.Containers??{}).sort(),expected=[api.Id,https.Id,smtp.Id].sort();
 check('actual delivery network exact API/HTTPS/SMTP members',JSON.stringify(exactIDs)===JSON.stringify(expected));
 check('actual delivery network internal .51 bridge',network.Internal===true&&network.Driver==='bridge'&&network.IPAM.Config?.[0]?.Subnet==='172.28.51.0/24');
 const env=Object.fromEntries(api.Config.Env.map(value=>{const i=value.indexOf('=');return[value.slice(0,i),value.slice(i+1)];}));
 check('actual API delivery address',delivery[1].IPAddress==='172.28.51.10');
 check('actual worker enabled and narrow authority',env.EVENT_DELIVERY_WORKER_ENABLED==='true'&&env.EVENT_DELIVERY_ALLOWED_HOSTS==='event-receiver:9087,event-mail:2465');
 check('actual native sink protected interfaces',['event-receiver','event-mail','172.28.51.10','172.28.51.20','172.28.51.30'].every(value=>(env.PROTECTED_DESTINATION_HOSTS??'').split(',').includes(value)));
 for(const[name,value,ip,kind]of[['event-receiver',https,'172.28.51.20','https'],['event-mail',smtp,'172.28.51.30','smtp']]){
  const networks=Object.entries(value.NetworkSettings.Networks);check(name+' actual sole delivery interface',networks.length===1&&networks[0][1].NetworkID===delivery[1].NetworkID&&networks[0][1].IPAddress===ip);
  check(name+' healthy nonroot readonly',value.State.Health?.Status==='healthy'&&value.Config.User==='1000:1000'&&value.HostConfig.ReadonlyRootfs===true);
  check(name+' no capabilities or privilege',JSON.stringify(value.HostConfig.CapDrop)==='["ALL"]'&&!value.HostConfig.CapAdd?.length&&value.HostConfig.SecurityOpt.includes('no-new-privileges:true')&&!value.HostConfig.Privileged);
  check(name+' no host ports or namespaces',!Object.keys(value.HostConfig.PortBindings??{}).length&&!Object.values(value.NetworkSettings.Ports??{}).some(rows=>rows?.length)&&!['host','container'].some(mode=>value.HostConfig.NetworkMode.startsWith(mode))&&value.HostConfig.PidMode!=='host');
  check(name+' only readonly approved bindings',value.Mounts.length===2&&value.Mounts.every(m=>m.Type==='bind'&&!m.RW&&['/run/receiver','/opt/kongos-event-receiver'].includes(m.Destination)));
  check(name+' fixed receiver kind and no signing/database material',value.Config.Env.includes('RECEIVER_KIND='+kind)&&!value.Config.Env.some(v=>/^(?:APP_SECRET|PORTAL_SECRET|DATABASE_URL|CONSOLE_ENCRYPTION_KEY|REDIS_URL)=/.test(v)));
  for(const file of['http.mjs','smtp.mjs','control.mjs','server.mjs','safe-records.mjs','health.mjs'])check(name+' actual source '+file,hash(run([...compose,'exec','-T',name,'cat','/opt/kongos-event-receiver/'+file]))===hash(readFileSync('deploy/event-receivers/'+file)));
 }
 check('actual API private material binding',api.Mounts.some(m=>m.Type==='bind'&&!m.RW&&m.Destination==='/run/event-delivery'));
 // Health and network/source verification never enqueue an event or configure
 // any native entity; actual provider/lease tests use a separate write window.
}catch{check('bounded actual delivery deployment verification completed',false);}
const result={stage,observedAt:new Date().toISOString(),scope:'network/readiness/source only; provider delivery and current authority require separate live tests',allPassed:checks.length>0&&checks.every(c=>c.passed),checks,businessWrites:0,nativeWrites:0};
mkdirSync(directory,{recursive:true});writeFileSync(resolve(directory,'delivery-deployment-verification.json'),JSON.stringify(result,null,2)+'\n');
process.stdout.write(`${checks.filter(c=>c.passed).length}/${checks.length} delivery deployment checks passed; no private material printed.\n`);if(!result.allPassed)process.exitCode=1;
