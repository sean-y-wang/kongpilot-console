import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync,lstatSync,readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureOutboxRepairSnapshot,outboxRepairChecks} from './verify-m7-outbox-repair-continuity.mjs';
const LABEL='edge-nosniff-single-author',OUTPUT='artifacts/M7/edge-nosniff-single-author-continuity.json';
const digest=value=>createHash('sha256').update(value).digest('hex');
const CONFIG='deploy/nginx/default.conf';
export function singleNosniffConfig(original){
 const author='    add_header X-Content-Type-Options nosniff always;';
 const proxy='        proxy_pass http://console-api:3000;';
 if(original.split(author).length!==2||original.split(proxy).length!==2||/proxy_hide_header\s+X-Content-Type-Options/i.test(original))throw Error('NOSNIFF_SOURCE_BOUNDARY_INVALID');
 return original.replace(proxy,proxy+'\n        proxy_hide_header X-Content-Type-Options;');
}
export function edgeNosniffChecks(before,after){
 const checks=outboxRepairChecks(before,after).filter(c=>!['API process restarted after compiled code','public deployment/ACL/portal/delivery configuration unchanged'].includes(c.name));
 checks.push({name:'all containers/processes/interfaces/environment/storage remain exact',passed:JSON.stringify(before.services)===JSON.stringify(after.services)});
 checks.push({name:'all Console and Portal static bytes unchanged',passed:JSON.stringify(before.staticAssets)===JSON.stringify(after.staticAssets)});
 checks.push({name:'all other deployment configuration files unchanged',passed:JSON.stringify(before.otherConfiguration)===JSON.stringify(after.otherConfiguration)});
 checks.push({name:'only upstream nosniff hidden; edge always author and remaining config exact',passed:after.edgeConfiguration.sourceSHA256===before.edgeConfiguration.expectedSHA256&&after.edgeConfiguration.runtimeSHA256===before.edgeConfiguration.expectedSHA256&&before.edgeConfiguration.sourceSHA256===before.edgeConfiguration.runtimeSHA256});
 return checks;
}
function assets(path){const s=lstatSync(path);if(s.isSymbolicLink())throw Error('NOSNIFF_STATIC_INVALID');return s.isDirectory()?readdirSync(path).sort().flatMap(n=>assets(path+'/'+n)):[{path,sha256:digest(readFileSync(path))}];}
function snapshot(before){
 const current=captureOutboxRepairSnapshot(),web=current.services.find(s=>s.name==='console-web');if(!web)throw Error('NOSNIFF_WEB_UNAVAILABLE');
 // Nginx has no Node runtime. Read only this public fixed configuration file.
 const runtime=execFileSync('docker',['--host=unix:///var/run/docker.sock','exec',web.id,'cat','/etc/nginx/conf.d/default.conf'],{stdio:['pipe','pipe','pipe'],timeout:10000});
 const source=readFileSync(CONFIG),sourceSHA256=digest(source),runtimeSHA256=digest(runtime);
 current.edgeConfiguration={sourceSHA256,runtimeSHA256,...(before?{expectedSHA256:digest(singleNosniffConfig(source.toString()))}:{})};
 current.staticAssets=[...assets('apps/console-web/dist'),...assets('apps/portal-web/dist')];
 current.otherConfiguration=['docker-compose.yml','deploy/compose.development.yml','deploy/compose.multicluster-test.yml','deploy/compose.metrics.yml','deploy/compose.portal-acceptance.yml','deploy/compose.notifications-test.yml','deploy/nginx/portal.conf','deploy/nginx/portal-nginx.conf','deploy/scripts/kong-secure-start.sh'].map(path=>({path,sha256:digest(readFileSync(path))}));
 return current;
}
export function runEdgeNosniffContinuity(mode){
 if(!['before','after'].includes(mode))throw Error('NOSNIFF_ARGUMENT_INVALID');
 if(mode==='before'&&existsSync(OUTPUT))throw Error('NOSNIFF_BASELINE_SEALED');
 const saved=mode==='after'?JSON.parse(readFileSync(OUTPUT,'utf8')):null;
 if(saved&&(saved.label!==LABEL||saved.allPassed!==null||saved.after))throw Error('NOSNIFF_RESULT_SEALED');
 const current=snapshot(mode==='before'),checks=saved?edgeNosniffChecks(saved.before,current):null;
 const result=saved?{...saved,after:current,checks,allPassed:checks.every(c=>c.passed),scope:'Console Nginx configuration reload only; no new HTTP download, build, container restart, migration, account/business/native/provider write'}:{label:LABEL,allPassed:null,before:current};
 writeFileSync(OUTPUT,JSON.stringify(result,null,2)+'\n',{flag:mode==='before'?'wx':'w'});return result;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))try{const result=runEdgeNosniffContinuity(process.argv[2]==='--before'?'before':process.argv[2]==='--after'?'after':'invalid');console.log(JSON.stringify({baselineCaptured:result.allPassed===null,allPassed:result.allPassed,checks:result.checks?.length??0}));if(result.allPassed===false)process.exitCode=1;}catch{process.stderr.write('NOSNIFF_CONTINUITY_FAILED; no private values printed.\n');process.exitCode=1;}
