import {randomBytes} from 'node:crypto';
import {mkdirSync,existsSync,writeFileSync,chmodSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {resolve} from 'node:path';
import {isIPv4} from 'node:net';
const directory='/dev/shm/kongpilot-release-lab',envFile=directory+'/lab.env';
const dockerEnv={...process.env};for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete dockerEnv[key];
const docker=args=>execFileSync('docker',['--host=unix:///var/run/docker.sock',...args],{env:dockerEnv,encoding:'utf8'});
if(existsSync(envFile))throw new Error('The release lab already has private configuration; reuse the original file rather than overwrite keys.');
const ids=docker(['network','ls','-q']).trim().split(/\s+/).filter(Boolean);
const networks=ids.length?JSON.parse(docker(['network','inspect',...ids])):[];
function prefix(address,mask){return address.split('.').reduce((n,octet)=>(n*256+Number(octet))>>>0,0)>>> (32-mask);}
for(const net of networks)for(const ipam of net.IPAM?.Config??[]){const [ip,bits]=String(ipam.Subnet??'').split('/');if(isIPv4(ip)){const mask=Math.min(Number(bits),28);if(prefix(ip,mask)===prefix('172.31.91.0',mask))throw new Error('The proposed isolated Admin subnet overlaps an existing network.');}}
mkdirSync(directory,{recursive:true,mode:0o700});chmodSync(directory,0o700);
const values={LAB_CONSOLE_DB_PASSWORD:randomBytes(24).toString('hex'),LAB_CONSOLE_APP_PASSWORD:randomBytes(24).toString('hex'),LAB_KONG_DB_PASSWORD:randomBytes(24).toString('hex'),LAB_REDIS_PASSWORD:randomBytes(24).toString('hex'),LAB_BOOTSTRAP_USER:'kongpilot-release-admin',LAB_BOOTSTRAP_PASSWORD:'Synthetic!Release'+randomBytes(24).toString('hex'),LAB_APP_SECRET:randomBytes(32).toString('hex'),LAB_CONSOLE_ENCRYPTION_KEY:randomBytes(32).toString('hex'),LAB_CURSOR_SIGNING_KEY:randomBytes(32).toString('hex')};
values.LAB_PORTAL_SECRET=randomBytes(32).toString('hex');
writeFileSync(envFile,Object.entries(values).map(([key,value])=>`${key}=${value}`).join('\n')+'\n',{mode:0o600});
mkdirSync(resolve('artifacts/ReleaseV1_0'),{recursive:true});writeFileSync('artifacts/ReleaseV1_0/lab-preparation.json',JSON.stringify({prepared:true,environment:'isolated native Kong 1.5.1 release validation',privateEnvFile:envFile,originalServicesChanged:false,credentialsRecorded:false,productionDeployment:false,memoryBackedData:true},null,2)+'\n');
process.stdout.write(JSON.stringify({prepared:true,privateEnvFile:envFile,credentialsRecorded:false})+'\n');
