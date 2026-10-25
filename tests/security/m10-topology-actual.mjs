import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdirSync,writeFileSync,existsSync,readFileSync} from 'node:fs';

const checks=[],containerPrefix='kongpilot-release-lab-',networkPrefix='kongpilot-release-lab_',tool='kongos-ram-tool-m08-20261012-a3';
const env={...process.env,GOMAXPROCS:'2'};
for(const key of ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'])delete env[key];
const docker=args=>execFileSync('docker',['--host=unix:///var/run/docker.sock','exec','--env','GOMAXPROCS=2',tool,'docker','--host=unix:///run/docker-production.sock',...args],{env,encoding:'utf8',timeout:20000,maxBuffer:4*1024*1024});
const check=(name,condition)=>{assert(condition,name);checks.push({name,passed:true});};
let passed=false,failure,facts;
try{
 check('explicit own isolated release topology handoff',process.env.RELEASE_LAB_READY==='true'&&process.env.RELEASE_M10_TOPOLOGY_READY==='true');
 // Inspect data stays in memory. Environment values, connection passwords and
 // full container inspection records never enter the public evidence report.
 const names=['console-api','kong','kong-db','stage-kong','stage-kong-db','stage-kong-migrations'].map(n=>containerPrefix+n+'-1');
 const rows=JSON.parse(docker(['inspect',...names]));
 const [api,source,sourceDb,target,targetDb,migration]=rows;
 const networks=row=>Object.keys(row.NetworkSettings.Networks);
 check('all inspected resources belong to the isolated acceptance project',rows.every((r,i)=>r.Name==='/'+names[i]&&r.Config.Labels['com.docker.compose.project']==='kongpilot-release-lab'));
 check('two physically distinct healthy gateways and independent databases',source.Id!==target.Id&&sourceDb.Id!==targetDb.Id&&[source,target,sourceDb,targetDb,api].every(r=>r.State.Health?.Status==='healthy'));
 check('the second gateway bootstrap exited successfully',migration.State.Status==='exited'&&migration.State.ExitCode===0);
 check('neither Admin API port is published',!Object.keys(source.HostConfig.PortBindings??{}).length&&!Object.keys(target.HostConfig.PortBindings??{}).length);
 check('console BFF cannot join either Kong database network',!networks(api).includes(networkPrefix+'kong-store')&&!networks(api).includes(networkPrefix+'stage-kong-store'));
 check('source and target Admin interfaces use distinct private networks',networks(source).includes(networkPrefix+'kong-admin')&&networks(target).includes(networkPrefix+'stage-kong-admin')&&!networks(target).includes(networkPrefix+'kong-admin'));
 for(const network of [networkPrefix+'kong-admin',networkPrefix+'stage-kong-admin']){
  const r=JSON.parse(docker(['network','inspect',network]))[0],members=Object.values(r.Containers).map(c=>c.Name).sort();
  check(network+' allows only its gateway and the BFF',members.length===2&&members.includes(containerPrefix+'console-api-1')&&members.includes(network.includes('stage-')?containerPrefix+'stage-kong-1':containerPrefix+'kong-1'));
 }
 const program="Promise.all(['http://kong-admin:8001/','http://stage-kong-admin:8001/'].map(async url=>{const r=await fetch(url,{signal:AbortSignal.timeout(5000)});if(!r.ok)throw Error('ROOT_READ_FAILED');const data=await r.json();return{version:data.version,nodeId:data.node_id??null};})).then(v=>process.stdout.write(JSON.stringify(v))).catch(()=>process.exitCode=1);";
 const versions=JSON.parse(docker(['exec',containerPrefix+'console-api-1','node','-e',program]));
 check('BFF reads actual Kong 1.5.1 version from both registered Admin interfaces',versions.length===2&&versions.every(v=>v.version==='1.5.1'));
 facts={gateways:[{container:names[1],version:versions[0].version,imageId:source.Image},{container:names[3],version:versions[1].version,imageId:target.Image}],independentDatabases:true,adminPortsPublished:false,bffConnectedToKongDatabase:false};
 passed=true;
}catch(e){failure={code:e.code==='ERR_ASSERTION'?'TOPOLOGY_ASSERTION_FAILED':'TOPOLOGY_READ_FAILED'};process.exitCode=1;}
finally{
 mkdirSync('artifacts/M10',{recursive:true});const path='artifacts/M10/topology-verification.json';
 if(existsSync(path)){let n=1;while(existsSync(path.replace('.json',`.attempt-${n}.json`)))n++;writeFileSync(path.replace('.json',`.attempt-${n}.json`),readFileSync(path));}
 writeFileSync(path,JSON.stringify({passed,milestone:'M10',environment:'two independent real Kong 1.5.1 acceptance gateways',productionDeployment:false,memoryBackedData:true,originalServicesChanged:false,credentialsRecorded:false,checks,...(facts?{facts}:{}),...(failure?{failure}:{})},null,2)+'\n');
 console.log(JSON.stringify({passed,checks:checks.length,...(failure?{failure}:{})}));
}
