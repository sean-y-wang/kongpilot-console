import {existsSync,lstatSync,mkdirSync,readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureOutboxRepairSnapshot,outboxRepairChecks} from './verify-m7-outbox-repair-continuity.mjs';

export const REPLAY_REPAIR_LABEL='delivery-replay-capability-repair';
export const REPLAY_REPAIR_OUTPUT='artifacts/M7/delivery-replay-capability-repair-continuity.json';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export function replayRepairAfter(saved,current){
 if(saved?.label!==REPLAY_REPAIR_LABEL||saved.allPassed!==null||saved.after)throw new Error('REPLAY_REPAIR_RESULT_SEALED');
 const checks=outboxRepairChecks(saved.before,current);
 checks.push({name:'all Console and Portal static bytes unchanged',passed:JSON.stringify(saved.before.staticAssets)===JSON.stringify(current.staticAssets)});
 return {...saved,after:current,checks,allPassed:checks.every(check=>check.passed),scope:'API process-only replay capability projection repair; no static build/migration/environment/material/topology/provider or business/native write. Observation-only monitoring progress is excluded by the same fixed stable-settings projection.'};
}
function assets(path){const stat=lstatSync(path);if(stat.isSymbolicLink())throw new Error('REPLAY_REPAIR_STATIC_INVALID');if(stat.isDirectory())return readdirSync(path).sort().flatMap(name=>assets(`${path}/${name}`));if(!stat.isFile())throw new Error('REPLAY_REPAIR_STATIC_INVALID');return[{path,sha256:hash(readFileSync(path))}];}
function snapshot(){return{...captureOutboxRepairSnapshot(),staticAssets:[...assets('apps/console-web/dist'),...assets('apps/portal-web/dist')]};}
export function runReplayRepairContinuity(mode){
 if(!['before','after'].includes(mode))throw new Error('REPLAY_REPAIR_ARGUMENT_INVALID');
 const output=resolve(REPLAY_REPAIR_OUTPUT);mkdirSync(resolve('artifacts/M7'),{recursive:true});
 if(mode==='before'&&existsSync(output))throw new Error('REPLAY_REPAIR_BASELINE_SEALED');
 const saved=mode==='after'?JSON.parse(readFileSync(output,'utf8')):null;
 if(saved&&(saved.label!==REPLAY_REPAIR_LABEL||saved.allPassed!==null||saved.after))throw new Error('REPLAY_REPAIR_RESULT_SEALED');
 const current=snapshot(),result=mode==='before'?{label:REPLAY_REPAIR_LABEL,allPassed:null,before:current}:replayRepairAfter(saved,current);
 writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:mode==='before'?'wx':'w'});return result;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=runReplayRepairContinuity(process.argv[2]==='--before'?'before':process.argv[2]==='--after'?'after':'invalid');console.log(JSON.stringify({baselineCaptured:result.allPassed===null,allPassed:result.allPassed,checks:result.checks?.length??0}));if(result.allPassed===false)process.exitCode=1;}catch{process.stderr.write('REPLAY_REPAIR_CONTINUITY_FAILED; no private values printed.\n');process.exitCode=1;}
}
