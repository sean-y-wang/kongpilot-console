import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';

const before=process.argv.includes('--before'),after=process.argv.includes('--after');
if(before===after||process.argv.slice(2).some(arg=>!['--before','--after'].includes(arg))){console.error('M6_CONTINUITY_ARGUMENTS_INVALID');process.exit(2);}
const directory='artifacts/M6',output=`${directory}/runtime-continuity.json`;
const project=process.env.COMPOSE_PROJECT_NAME||'kongos-console';
function container(service,optional=false){
  const ids=execFileSync('docker',['ps','-q','--filter',`label=com.docker.compose.project=${project}`,'--filter',`label=com.docker.compose.service=${service}`],{encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim().split(/\s+/).filter(Boolean);
  if(optional&&ids.length===0)return null;
  if(ids.length!==1)throw new Error('M6_CONTINUITY_CONTAINER_INVALID');
  return JSON.parse(execFileSync('docker',['inspect',ids[0]],{encoding:'utf8',stdio:['pipe','pipe','pipe']}))[0];
}
function snapshot(){
  const services=['kong','kong-secondary','kong-db','kong-secondary-db','console-db','redis','telemetry-collector','prometheus','loki','echo-upstream'].map(name=>{
    const item=container(name,!['kong','kong-db','console-db','redis'].includes(name));
    if(!item)return null;
    return {name,id:item.Id,image:item.Image,startedAt:item.State.StartedAt,volumes:item.Mounts.filter(row=>row.Type==='volume').map(row=>({name:row.Name,target:row.Destination})).sort((a,b)=>a.target.localeCompare(b.target)),networks:Object.entries(item.NetworkSettings.Networks).map(([name,row])=>({name,id:row.NetworkID,ip:row.IPAddress})).sort((a,b)=>a.name.localeCompare(b.name))};
  }).filter(Boolean);
  const manifest=existsSync('deploy/private/metrics/manifest.json')?JSON.parse(readFileSync('deploy/private/metrics/manifest.json','utf8')):{clusters:[]};
  const paths=['deploy/private/metrics/manifest.json','deploy/private/metrics/collector/credentials.json','deploy/private/metrics/prometheus/prometheus.yml'].filter(existsSync);
  for(const row of manifest.clusters)for(const purpose of ['native_scrape','collector_scrape'])paths.push(`deploy/private/metrics/prometheus/${row.clusterId}-${purpose}.token`);
  const hash=createHash('sha256');for(const path of paths){hash.update(path);hash.update(readFileSync(path));}
  const code=String.raw`const{Pool}=require('pg'),{createHash}=require('node:crypto');(async()=>{const p=new Pool({connectionString:process.env.DATABASE_URL});try{const settings=(await p.query('SELECT cluster_id,credential_generation,catalog_revision FROM metrics_settings ORDER BY cluster_id')).rows;const epochs=(await p.query('SELECT id,cluster_id,node_id,entity_type,entity_id,workspace_id,config_fingerprint,tags_fingerprint,source_pair_hash,valid_from,closed_at FROM metrics_assignment_epochs ORDER BY id')).rows;console.log(JSON.stringify({settings,epochCount:epochs.length,epochIdentitySHA256:createHash('sha256').update(JSON.stringify(epochs)).digest('hex')}));}finally{await p.end();}})().catch(()=>process.exit(1));`;
  const api=container('console-api');
  const database=JSON.parse(execFileSync('docker',['exec','-i',api.Id,'node','-e',code],{encoding:'utf8',stdio:['pipe','pipe','pipe']}));
  return {observedAt:new Date().toISOString(),services,materialSHA256:hash.digest('hex'),database};
}
try{
  const current=snapshot();mkdirSync(directory,{recursive:true});
  if(before){
    if(existsSync(output))throw new Error('M6_CONTINUITY_BASELINE_EXISTS');
    writeFileSync(output,JSON.stringify({stage:'M6',scope:'Portal deployment preserves running data/native/monitoring services and monitoring key generations',allPassed:null,before:current},null,2)+'\n');
    console.log('M6 read-only baseline captured; existing services and keys unchanged.');
  }else{
    const saved=JSON.parse(readFileSync(output,'utf8')),checks=[];
    for(const old of saved.before.services){const next=current.services.find(row=>row.name===old.name);checks.push({name:`${old.name} container/process/image/volumes/network IDs and IPs unchanged`,passed:Boolean(next&&JSON.stringify(old)===JSON.stringify(next))});}
    checks.push({name:'monitoring private file bytes unchanged',passed:current.materialSHA256===saved.before.materialSHA256});
    checks.push({name:'current monitoring generations/catalog revisions unchanged',passed:JSON.stringify(current.database.settings)===JSON.stringify(saved.before.database.settings)});
    checks.push({name:'native immutable epochs unchanged',passed:current.database.epochIdentitySHA256===saved.before.database.epochIdentitySHA256&&current.database.epochCount===saved.before.database.epochCount});
    const allPassed=checks.every(row=>row.passed);
    writeFileSync(output,JSON.stringify({...saved,observedAt:new Date().toISOString(),after:current,checks,allPassed},null,2)+'\n');
    console.log(`${checks.filter(row=>row.passed).length}/${checks.length} M6 continuity checks passed; no private values recorded.`);
    if(!allPassed)process.exitCode=1;
  }
}catch{console.error('M6_RUNTIME_CONTINUITY_FAILED; no private values or metadata bodies printed.');process.exitCode=1;}
