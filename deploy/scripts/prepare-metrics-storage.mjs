import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import {dirname} from 'node:path';
import {metricsOperationOptions,metricsComposeArguments,metricsOperationEnvironment,productionMetricsConfiguration} from './metrics-operation-options.mjs';

let options;
try{options=metricsOperationOptions(process.argv.slice(2),'storage');}catch{console.error('METRICS_OPERATION_ARGUMENTS_INVALID');process.exit(2);}
const compose=metricsComposeArguments(options,'storage');
const dockerEnvironment=metricsOperationEnvironment(options,process.env);
const prefix=options.production?['--host=unix:///var/run/docker.sock']:[];
let volume='kongos-console_prometheus_data',helperImage='node:22-bookworm-slim',productionFacts;
const run = (args, extra = {}) => execFileSync('docker', args, { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8', timeout: 60_000, env:dockerEnvironment, ...extra });
let result;
if(options.production&&existsSync(options.output)){console.error('METRICS_OPERATION_OUTPUT_SEALED');process.exit(2);}
try {
  if(options.production){const config=JSON.parse(run([...compose,'config','--format','json'],{timeout:20_000,maxBuffer:8*1024*1024}));productionFacts=productionMetricsConfiguration(options,config);volume=productionFacts.prometheusVolume;helperImage=productionFacts.helperImage;}
  let id = run([...compose, 'ps', '-a', '-q', 'prometheus']).trim();
  // Docker may copy the image's directory ownership into an empty volume on
  // first container creation. Materialize that mount before setting its owner.
  if (!id) {
    run([...compose, 'up', '--no-start', '--no-build', '--no-deps', 'prometheus']);
    id = run([...compose, 'ps', '-a', '-q', 'prometheus']).trim();
    if (!id) throw new Error('prometheus container was not created');
  }
  let value;
  if (id) {
    value = JSON.parse(run([...prefix,'inspect', id]))[0];
    const mount = value.Mounts.find(item => item.Destination === '/prometheus');
    if (mount?.Type !== 'volume' || mount.Name !== volume) throw new Error('unexpected volume');
  }
  let prepared = false;
  if (value?.State.Status === 'running' && value.Config.User === '1000:1000') {
    try { run([...compose, 'exec', '-T', 'prometheus', '/bin/sh', '-ec', 'test "$(stat -c %u /prometheus)" = 1000 && test "$(stat -c %g /prometheus)" = 1000']); prepared = true; } catch { /* migrate ownership below */ }
  }
  let metadata = { visitedNodes: 0, changedNodes: 0 };
  if (!prepared) {
    if (value?.State.Status === 'running') run([...compose, 'stop', '-t', '20', 'prometheus']);
    // CHOWN only: temporarily take ownership of directories to traverse owner
    // 0700 permissions, then give them to the unprivileged runtime. No file is
    // opened, no mode/content is changed, and symlinks/special files are refused.
    const code = `const fs=require('fs');const path=require('path');let visitedNodes=0,changedNodes=0;
function walk(file){if(++visitedNodes>250000)throw new Error('budget');const stat=fs.lstatSync(file);if(!stat.isDirectory()&&!stat.isFile())throw new Error('special file');if(stat.isDirectory()){if((stat.mode&0500)!==0500)throw new Error('directory permissions');fs.chownSync(file,0,0);for(const name of fs.readdirSync(file))walk(path.join(file,name));}if(stat.uid!==1000||stat.gid!==1000)changedNodes++;fs.chownSync(file,1000,1000);}
try{walk('/prometheus');process.stdout.write(JSON.stringify({visitedNodes,changedNodes})+'\\n');}catch{process.stderr.write('METRICS_STORAGE_METADATA_FAILED\\n');process.exitCode=1;}`;
    metadata = JSON.parse(run([...prefix,'run', '--rm', '--network', 'none', '--user', '0:0', '--read-only', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges=true', '--mount', `type=volume,src=${volume},dst=/prometheus`, helperImage, 'node', '-e', code]));
  }
  result = { stage: 'M5', observedAt: new Date().toISOString(), allPassed: true, scope: 'Prometheus TSDB ownership only; no file contents read or changed', namedVolume: volume, targetUid: 1000, targetGid: 1000, reusedOwnership: prepared, ...metadata, otherPersistentVolumesMounted: false, helperNetwork: 'none', helperRootfsReadOnly: true, helperCapabilities: ['CHOWN'],...(options.production?{productionFacts}:{}) };
} catch {
  result = { stage: 'M5', observedAt: new Date().toISOString(), allPassed: false, scope: 'Prometheus TSDB ownership only', namedVolume: volume, otherPersistentVolumesMounted: false };
  console.error('METRICS_STORAGE_PREPARATION_FAILED: no file content or container environment printed.');
  process.exitCode = 1;
}
mkdirSync(dirname(options.output), { recursive: true });
writeFileSync(options.output, JSON.stringify(result, null, 2) + '\n',options.production?{flag:'wx',mode:0o644}:undefined);
if (result.allPassed) console.log(JSON.stringify({ metricsStoragePrepared: true, metadataOnly: true, reusedOwnership: result.reusedOwnership, visitedNodes: result.visitedNodes, changedNodes: result.changedNodes }));
