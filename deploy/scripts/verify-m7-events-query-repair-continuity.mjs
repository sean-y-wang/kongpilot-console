import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureOutboxRepairSnapshot,outboxRepairChecks} from './verify-m7-outbox-repair-continuity.mjs';

export const EVENTS_QUERY_REPAIR_LABEL='events-query-prototype-repair';
export const EVENTS_QUERY_REPAIR_OUTPUT='artifacts/M7/events-query-prototype-repair-continuity.json';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export function queryRepairRecordBefore(saved,exists){
 if(exists)throw new Error('QUERY_REPAIR_BASELINE_SEALED');
 return {label:EVENTS_QUERY_REPAIR_LABEL,allPassed:null,before:saved};
}
export function queryRepairRecordAfter(saved,current){
 if(saved?.label!==EVENTS_QUERY_REPAIR_LABEL||saved.allPassed!==null||saved.after)throw new Error('QUERY_REPAIR_RESULT_SEALED');
 const checks=outboxRepairChecks(saved.before,current);
 checks.push({name:'Console and Portal static assets unchanged',passed:JSON.stringify(saved.before.staticAssets)===JSON.stringify(current.staticAssets)});
 return {...saved,after:current,checks,allPassed:checks.every(check=>check.passed),scope:'API process-only query compatibility repair; no migration, environment, topology, material, static build or business/native write; observation-only catalog progress is excluded by the fixed stable-settings projection'};
}
function snapshot(){
 const current=captureOutboxRepairSnapshot();
 const files=['apps/console-web/dist/index.html','apps/console-web/dist/assets','apps/portal-web/dist/index.html','apps/portal-web/dist/assets'];
 // The directory digests below are added by the fixed public-file walker.
 const walk=(path)=>{
  const {readdirSync,lstatSync}=fs;
  const stat=lstatSync(path);if(stat.isSymbolicLink())throw new Error('QUERY_REPAIR_STATIC_INVALID');
  return stat.isDirectory()?readdirSync(path).sort().flatMap(name=>walk(`${path}/${name}`)):[{path,sha256:hash(readFileSync(path))}];
 };
 current.staticAssets=files.flatMap(walk);
 return current;
}
import * as fs from 'node:fs';
export function runQueryRepairContinuity(mode){
 if(!['before','after'].includes(mode))throw new Error('QUERY_REPAIR_ARGUMENT_INVALID');
 const output=resolve(EVENTS_QUERY_REPAIR_OUTPUT);
 mkdirSync(resolve('artifacts/M7'),{recursive:true});
 if(mode==='before'&&existsSync(output))throw new Error('QUERY_REPAIR_BASELINE_SEALED');
 const saved=mode==='after'?JSON.parse(readFileSync(output,'utf8')):null;
 // Reject a completed or unrelated record before any runtime/private read.
 if(saved&&(saved.label!==EVENTS_QUERY_REPAIR_LABEL||saved.allPassed!==null||saved.after))throw new Error('QUERY_REPAIR_RESULT_SEALED');
 const current=snapshot();
 const result=mode==='before'?queryRepairRecordBefore(current,false):queryRepairRecordAfter(saved,current);
 writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:mode==='before'?'wx':'w'});
 return result;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=runQueryRepairContinuity(process.argv[2]==='--before'?'before':process.argv[2]==='--after'?'after':'invalid');console.log(JSON.stringify({baselineCaptured:result.allPassed===null,allPassed:result.allPassed,checks:result.checks?.length??0}));if(result.allPassed===false)process.exitCode=1;}catch{process.stderr.write('QUERY_REPAIR_CONTINUITY_FAILED; no private values printed.\n');process.exitCode=1;}
}
