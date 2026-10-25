import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {copyFileSync,existsSync,readFileSync,writeFileSync} from 'node:fs';

const beforeMode=process.argv.includes('--before');
const afterMode=process.argv.includes('--after');
if(beforeMode===afterMode || process.argv.slice(2).some(arg=>!['--before','--after','--collector-restarted'].includes(arg))){console.error('M5_CONTINUITY_ARGUMENTS_INVALID');process.exit(2);}
const collectorRestarted=process.argv.includes('--collector-restarted');
const compose=['compose','--env-file','.env','--env-file','.env.multicluster','-f','docker-compose.yml','-f','deploy/compose.development.yml','-f','deploy/compose.multicluster-test.yml','--profile','multicluster-test','-f','deploy/compose.metrics.yml','--profile','observability'];
const serviceNames=['kong','kong-secondary','echo-upstream','console-api','console-web','telemetry-collector','prometheus','loki','kong-db','kong-secondary-db','console-db','redis'];
const output='artifacts/M5/loki-repair-runtime-continuity.json';
function snapshot(){
  const services=serviceNames.map(name=>{
    const id=execFileSync('docker',[...compose,'ps','-q',name],{encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();
    if(!id)throw new Error('missing service');
    const value=JSON.parse(execFileSync('docker',['inspect',id],{encoding:'utf8',stdio:['pipe','pipe','pipe']}))[0];
    return {name,id:value.Id,image:value.Image,startedAt:value.State.StartedAt,volumes:value.Mounts.filter(row=>row.Type==='volume').map(row=>({name:row.Name,target:row.Destination})).sort((a,b)=>a.target.localeCompare(b.target)),networks:Object.entries(value.NetworkSettings.Networks).map(([name,row])=>({name,id:row.NetworkID,ip:row.IPAddress})).sort((a,b)=>a.name.localeCompare(b.name))};
  });
  const manifest=JSON.parse(readFileSync('deploy/private/metrics/manifest.json','utf8'));
  const paths=['deploy/private/metrics/manifest.json','deploy/private/metrics/collector/credentials.json','deploy/private/metrics/prometheus/prometheus.yml'];
  for(const row of manifest.clusters)for(const purpose of ['native_scrape','collector_scrape'])paths.push(`deploy/private/metrics/prometheus/${row.clusterId}-${purpose}.token`);
  const materialDigest=createHash('sha256');for(const path of paths){materialDigest.update(path);materialDigest.update(readFileSync(path));}
  const metadataCode=String.raw`const{Pool}=require('pg'),{createHash}=require('node:crypto');(async()=>{const p=new Pool({connectionString:process.env.DATABASE_URL});try{const settings=(await p.query('SELECT cluster_id,credential_generation,catalog_revision FROM metrics_settings ORDER BY cluster_id')).rows;const epochs=(await p.query('SELECT id,cluster_id,node_id,entity_type,entity_id,workspace_id,config_fingerprint,tags_fingerprint,source_pair_hash,valid_from,closed_at FROM metrics_assignment_epochs ORDER BY id')).rows;const migrations=(await p.query('SELECT name FROM schema_migrations ORDER BY name')).rows.map(row=>row.name);console.log(JSON.stringify({settings,epochCount:epochs.length,epochIdentitySHA256:createHash("sha256").update(JSON.stringify(epochs)).digest("hex"),migrations}));}finally{await p.end();}})().catch(()=>process.exit(1));`;
  const database=JSON.parse(execFileSync('docker',[...compose,'exec','-T','console-api','node','-e',metadataCode],{encoding:'utf8',stdio:['pipe','pipe','pipe']}));
  return {observedAt:new Date().toISOString(),services,materialSHA256:materialDigest.digest('hex'),database};
}
try{
  const current=snapshot();
  if(beforeMode){
    if(existsSync(output))throw new Error('baseline already exists');
    for(const file of ['startup-final-verification.json','metrics-deployment-verification.json','deployment-boundary-final.json','admin-network-final-verification.json']){
      const path=`artifacts/M5/${file}`,saved=`artifacts/M5/${file.replace(/\.json$/,'-before-loki-repair.json')}`;
      if(existsSync(path)&&!existsSync(saved))copyFileSync(path,saved);
    }
    writeFileSync(output,JSON.stringify({stage:'M5',scope:'read-only before/after deployment continuity; no provider queries or native writes',allPassed:null,before:current},null,2)+'\n');
    console.log('M5 read-only Loki repair baseline captured; no containers changed.');
  }else{
    const saved=JSON.parse(readFileSync(output,'utf8')),checks=[];
    const check=(name,passed)=>checks.push({name,passed:Boolean(passed)});
    check('all container IDs, image IDs, named volumes and network memberships/IDs unchanged',saved.before.services.every(old=>{const next=current.services.find(row=>row.name===old.name);return next&&old.id===next.id&&old.image===next.image&&JSON.stringify(old.volumes)===JSON.stringify(next.volumes)&&JSON.stringify(old.networks.map(({name,id})=>({name,id})))===JSON.stringify(next.networks.map(({name,id})=>({name,id})));}));
    // Docker restart releases dynamic addresses: concurrently restarted API/Web
    // can exchange frontend IPs. The existing network and every protected/static
    // interface must remain exact; Nginx is restarted to resolve the current API.
    check('all protected/static and untouched service interface IPs unchanged',saved.before.services.every(old=>{const next=current.services.find(row=>row.name===old.name);return old.networks.every(network=>{
      if(['console-api','console-web'].includes(old.name)&&network.name.endsWith('_frontend'))return true;
      return next.networks.find(row=>row.name===network.name)?.ip===network.ip;
    });}));
    const restarted=['console-api','console-web',...(collectorRestarted?['telemetry-collector']:[])];
    for(const row of saved.before.services){const next=current.services.find(value=>value.name===row.name);check(`${row.name} ${restarted.includes(row.name)?'process restarted':'process untouched'}`,restarted.includes(row.name)?Date.parse(next.startedAt)>Date.parse(row.startedAt):next.startedAt===row.startedAt);}
    check('all monitoring credential/config file bytes unchanged',current.materialSHA256===saved.before.materialSHA256);
    check('database migration list unchanged',JSON.stringify(current.database.migrations)===JSON.stringify(saved.before.database.migrations));
    check('immutable native assignment identities and intervals unchanged',current.database.epochIdentitySHA256===saved.before.database.epochIdentitySHA256&&current.database.epochCount===saved.before.database.epochCount);
    check('catalog revisions and credential generations unchanged',JSON.stringify(current.database.settings)===JSON.stringify(saved.before.database.settings));
    const allPassed=checks.every(row=>row.passed);
    writeFileSync(output,JSON.stringify({...saved,observedAt:new Date().toISOString(),allPassed,collectorRestarted,checks,after:current},null,2)+'\n');
    console.log(`${checks.filter(row=>row.passed).length}/${checks.length} Loki repair runtime continuity checks passed; no secret values recorded.`);
    if(!allPassed)process.exitCode=1;
  }
}catch{console.error('M5_RUNTIME_CONTINUITY_FAILED; no metadata bodies or secrets printed.');process.exitCode=1;}
