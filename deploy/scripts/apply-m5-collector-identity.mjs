import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync, readFileSync, writeFileSync, copyFileSync} from 'node:fs';

// One bounded upgrade from auto-allocated bridge networks to explicit source
// IPAM. No migrations/enrollment/rotation, no database or volume removal.
const apply = process.argv.includes('--apply');
if (process.argv.some(value => value.startsWith('--') && !['--apply','--dry-run'].includes(value)) || (apply && process.argv.includes('--dry-run'))) {
  console.error('M5_IDENTITY_ARGUMENTS_INVALID'); process.exit(2);
}
const compose = ['compose','--env-file','.env','--env-file','.env.multicluster','-f','docker-compose.yml','-f','deploy/compose/compose.development.yml','-f','deploy/compose/compose.multicluster-test.yml','--profile','multicluster-test','-f','deploy/compose/compose.metrics.yml','--profile','observability','--profile','test'];
const connectedServices = ['kong','kong-secondary','echo-upstream','console-api','prometheus','loki','telemetry-collector'];
const preservedServices = ['kong-db','kong-secondary-db','console-db','redis'];
const targetNetworks = ['proxy-edge','observability'];
const commands = [];
let step = 'preflight';
const readJSON = (args) => JSON.parse(execFileSync('docker',args,{encoding:'utf8',stdio:['pipe','pipe','pipe']}));
const config = readJSON([...compose,'config','--format','json']); // Never publish resolved environment.
function serviceInspect(name) {
  const id = execFileSync('docker',[...compose,'ps','-q',name],{encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();
  if (!id) throw new Error('required service absent');
  return readJSON(['inspect',id])[0];
}
function snapshot() {
  return [...connectedServices,...preservedServices].map(name => {
    const value = serviceInspect(name);
    return {name,id:value.Id,health:value.State.Health?.Status,volumes:value.Mounts.filter(row => row.Type==='volume').map(row => ({name:row.Name,target:row.Destination})).sort((a,b)=>a.target.localeCompare(b.target))};
  });
}
function materials() {
  const paths = ['deploy/private/metrics/manifest.json','deploy/private/metrics/collector/credentials.json','deploy/private/metrics/prometheus/prometheus.yml'];
  const manifest = JSON.parse(readFileSync(paths[0],'utf8'));
  for (const row of manifest.clusters) for (const purpose of ['native_scrape','collector_scrape']) paths.push(`deploy/private/metrics/prometheus/${row.clusterId}-${purpose}.token`);
  return {generations:manifest.clusters.map(row=>({clusterId:row.clusterId,generation:row.generation})),digests:paths.map(path=>({path,sha256:createHash('sha256').update(readFileSync(path)).digest('hex')}))};
}
function run(name,args) {
  step=name;
  // Output is intentionally captured: source/env/database URLs cannot appear in error output.
  execFileSync('docker',args,{stdio:['pipe','pipe','pipe']});
  commands.push({name,completed:true});
  console.log(`M5 collector identity: ${name} completed.`);
}
let result;
try {
  const before=snapshot();
  const originalMaterials=materials();
  const networkPlan=targetNetworks.map(name=>{
    const declared=config.networks[name];
    const network=readJSON(['network','inspect',declared.name])[0];
    if (network.IPAM.Config.length!==1 || network.IPAM.Config[0].Subnet!==declared.ipam.config[0].subnet || network.Labels['com.docker.compose.project']!==config.name) throw new Error('network precondition');
    for (const id of Object.keys(network.Containers)) {
      const value=readJSON(['inspect',id])[0];
      if (!connectedServices.includes(value.Config.Labels['com.docker.compose.service']) || value.Config.Labels['com.docker.compose.project']!==config.name) throw new Error('unexpected network member');
    }
    return {name:declared.name,subnet:network.IPAM.Config[0].Subnet,previousId:network.Id};
  });
  const collector=serviceInspect('telemetry-collector');
  for (const name of ['telemetry','proxy-edge','observability']) {
    if (collector.NetworkSettings.Networks[config.networks[name].name]?.IPAddress!==config.services['telemetry-collector'].networks[name].ipv4_address) throw new Error('address continuity precondition');
  }
  const plannedCommands=[
    ['stop-attached-services',[...compose,'stop','--timeout','20',...connectedServices]],
    ['remove-only-stopped-attached-containers',[...compose,'rm','--force',...connectedServices]],
    ['replace-two-empty-networks',['network','rm',...networkPlan.map(row=>row.name)]],
    ['recreate-attached-services',[...compose,'up','-d','--no-deps','--no-build','--force-recreate','--wait','--wait-timeout','90',...connectedServices]],
  ];
  if (apply) {
    for (const file of ['startup-final-verification.json','metrics-deployment-verification.json','deployment-boundary-final.json','admin-network-final-verification.json']) {
      const path=`artifacts/M5/${file}`;
      const saved=`artifacts/M5/${file.replace(/\.json$/, '-before-collector-identity.json')}`;
      if (existsSync(path) && !existsSync(saved)) copyFileSync(path,saved);
    }
    for (const [name,args] of plannedCommands) run(name,args);
    step='continuity-verification';
    const after=snapshot();
    if (preservedServices.some(name=>before.find(row=>row.name===name).id!==after.find(row=>row.name===name).id)) throw new Error('persistent service restarted');
    if (before.some(row=>JSON.stringify(row.volumes)!==JSON.stringify(after.find(value=>value.name===row.name).volumes))) throw new Error('volume changed');
    if (JSON.stringify(originalMaterials)!==JSON.stringify(materials())) throw new Error('credential material changed');
    result={stage:'M5',observedAt:new Date().toISOString(),allPassed:true,deploymentPerformed:true,networkPlan,recreatedServices:connectedServices,untouchedServices:preservedServices,credentialGenerations:originalMaterials.generations,migrationsRepeated:false,enrollmentRepeated:false,tokenRotation:false,allNamedVolumeBindingsPreserved:true,persistentContainerIdsPreserved:true,commands};
  } else {
    result={stage:'M5',observedAt:new Date().toISOString(),allPassed:true,deploymentPerformed:false,scope:'read-only guarded transition preflight',networkPlan,recreatedServices:connectedServices,untouchedServices:preservedServices,credentialGenerations:originalMaterials.generations,commands:plannedCommands.map(([name,args])=>({name,command:'docker',args}))};
  }
} catch {
  result={stage:'M5',observedAt:new Date().toISOString(),allPassed:false,deploymentPerformed:apply,failedStep:step,commands};
  console.error(`M5_IDENTITY_TRANSITION_FAILED at ${step}; no secrets or resolved config printed.`);
  process.exitCode=1;
}
writeFileSync(`artifacts/M5/collector-identity-transition${apply?'':'-plan'}.json`,JSON.stringify(result,null,2)+'\n');
if (result.allPassed) console.log(`M5 collector identity ${apply?'bounded transition':'read-only plan'} passed.`);
