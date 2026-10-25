import {existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureNotificationRepairSnapshot} from './verify-m7-notification-preference-repair-continuity.mjs';
import {outboxRepairChecks} from './verify-m7-outbox-repair-continuity.mjs';
export const WORKFLOW_AUDIT_REPAIR_LABEL='workflow-submit-audit-metadata-repair';
export const WORKFLOW_AUDIT_REPAIR_OUTPUT='artifacts/M7/workflow-submit-audit-metadata-repair-continuity.json';
export function workflowAuditRepairAfter(saved,current){
 if(saved?.label!==WORKFLOW_AUDIT_REPAIR_LABEL||saved.allPassed!==null||saved.after)throw Error('WORKFLOW_AUDIT_REPAIR_RESULT_SEALED');
 const checks=outboxRepairChecks(saved.before,current);
 checks.push({name:'all Console and Portal static bytes unchanged',passed:JSON.stringify(saved.before.consoleAssets)===JSON.stringify(current.consoleAssets)&&JSON.stringify(saved.before.portalAssets)===JSON.stringify(current.portalAssets)});
 return{...saved,after:current,checks,allPassed:checks.every(c=>c.passed),scope:'API process-only trusted workflow audit metadata propagation repair; SQL000-010, single-nosniff Console Nginx configuration, all static assets/private materials and every other container remain exact; zero business/native/provider writes by this deployer.'};
}
export function runWorkflowAuditRepairContinuity(mode){
 if(!['before','after'].includes(mode))throw Error('WORKFLOW_AUDIT_REPAIR_ARGUMENT_INVALID');
 mkdirSync(resolve('artifacts/M7'),{recursive:true});
 if(mode==='before'&&existsSync(WORKFLOW_AUDIT_REPAIR_OUTPUT))throw Error('WORKFLOW_AUDIT_REPAIR_BASELINE_SEALED');
 const saved=mode==='after'?JSON.parse(readFileSync(WORKFLOW_AUDIT_REPAIR_OUTPUT,'utf8')):null;
 if(saved&&(saved.label!==WORKFLOW_AUDIT_REPAIR_LABEL||saved.allPassed!==null||saved.after))throw Error('WORKFLOW_AUDIT_REPAIR_RESULT_SEALED');
 const current=captureNotificationRepairSnapshot();
 const result=mode==='before'?{label:WORKFLOW_AUDIT_REPAIR_LABEL,allPassed:null,before:current}:workflowAuditRepairAfter(saved,current);
 writeFileSync(WORKFLOW_AUDIT_REPAIR_OUTPUT,JSON.stringify(result,null,2)+'\n',{flag:mode==='before'?'wx':'w'});return result;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))try{const result=runWorkflowAuditRepairContinuity(process.argv[2]==='--before'?'before':process.argv[2]==='--after'?'after':'invalid');console.log(JSON.stringify({baselineCaptured:result.allPassed===null,allPassed:result.allPassed,checks:result.checks?.length??0}));if(result.allPassed===false)process.exitCode=1;}catch{process.stderr.write('WORKFLOW_AUDIT_REPAIR_CONTINUITY_FAILED; no private values printed.\n');process.exitCode=1;}
