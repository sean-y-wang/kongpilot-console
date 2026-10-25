import {existsSync,lstatSync,mkdirSync,readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureOutboxRepairSnapshot,outboxRepairChecks} from './verify-m7-outbox-repair-continuity.mjs';

export const NOTIFICATION_REPAIR_LABEL='notification-preference-repair';
export const NOTIFICATION_REPAIR_OUTPUT='artifacts/M7/notification-preference-repair-continuity.json';
export const NOTIFICATION_WEB_SOURCE={
 'apps/console-web/src/features/NotificationsPage.tsx':'a2c4b6bd3a339380ca0b1db0e5d58e57d74505360b6881d56a541d0023072c38',
 'apps/console-web/src/features/m7.forms.ts':'66ee8aa1bac895822210dcceb369f984d8002cae3924824fcc9b9de3ef6aeaae'
};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export function notificationRepairBefore(current,exists){
 if(exists)throw new Error('NOTIFICATION_REPAIR_BASELINE_SEALED');
 return {label:NOTIFICATION_REPAIR_LABEL,allPassed:null,before:current};
}
export function notificationRepairAfter(saved,current){
 if(saved?.label!==NOTIFICATION_REPAIR_LABEL||saved.allPassed!==null||saved.after)throw new Error('NOTIFICATION_REPAIR_RESULT_SEALED');
 const checks=outboxRepairChecks(saved.before,current);
 checks.push({name:'Portal static assets remain exact',passed:JSON.stringify(saved.before.portalAssets)===JSON.stringify(current.portalAssets)});
 checks.push({name:'frozen notification Web source remains exact across build',passed:JSON.stringify(saved.before.webSource)===JSON.stringify(current.webSource)&&Object.entries(NOTIFICATION_WEB_SOURCE).every(([path,sha256])=>current.webSource?.some(item=>item.path===path&&item.sha256===sha256))});
 return {...saved,after:current,checks,allPassed:checks.every(check=>check.passed),scope:'API process-only notification SQL repair plus Console workspace static build; Portal and every other container/material/migration remain exact. Stable settings exclude only normal observation fields. Console asset bytes are reported before/after and may change for the frozen Web source.'};
}
function assets(path){
 const stat=lstatSync(path);if(stat.isSymbolicLink())throw new Error('NOTIFICATION_REPAIR_STATIC_INVALID');
 if(stat.isDirectory())return readdirSync(path).sort().flatMap(name=>assets(`${path}/${name}`));
 if(!stat.isFile())throw new Error('NOTIFICATION_REPAIR_STATIC_INVALID');
 return [{path,sha256:hash(readFileSync(path))}];
}
function source(){return Object.entries(NOTIFICATION_WEB_SOURCE).map(([path,sha256])=>{const actual=hash(readFileSync(path));if(actual!==sha256)throw new Error('NOTIFICATION_REPAIR_SOURCE_CHANGED');return{path,sha256:actual};});}
export function captureNotificationRepairSnapshot(){
 const webSource=source(); // Reject stale source before runtime/private reads.
 const current=captureOutboxRepairSnapshot();
 return {...current,webSource,consoleAssets:assets('apps/console-web/dist'),portalAssets:assets('apps/portal-web/dist')};
}
export function runNotificationRepairContinuity(mode){
 if(!['before','after'].includes(mode))throw new Error('NOTIFICATION_REPAIR_ARGUMENT_INVALID');
 const output=resolve(NOTIFICATION_REPAIR_OUTPUT);
 mkdirSync(resolve('artifacts/M7'),{recursive:true});
 if(mode==='before'&&existsSync(output))throw new Error('NOTIFICATION_REPAIR_BASELINE_SEALED');
 const saved=mode==='after'?JSON.parse(readFileSync(output,'utf8')):null;
 if(saved&&(saved.label!==NOTIFICATION_REPAIR_LABEL||saved.allPassed!==null||saved.after))throw new Error('NOTIFICATION_REPAIR_RESULT_SEALED');
 const current=captureNotificationRepairSnapshot();
 const result=mode==='before'?notificationRepairBefore(current,false):notificationRepairAfter(saved,current);
 writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:mode==='before'?'wx':'w'});
 return result;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=runNotificationRepairContinuity(process.argv[2]==='--before'?'before':process.argv[2]==='--after'?'after':'invalid');console.log(JSON.stringify({baselineCaptured:result.allPassed===null,allPassed:result.allPassed,checks:result.checks?.length??0}));if(result.allPassed===false)process.exitCode=1;}catch{process.stderr.write('NOTIFICATION_REPAIR_CONTINUITY_FAILED; no private values printed.\n');process.exitCode=1;}
}
