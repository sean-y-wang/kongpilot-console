import { ConflictException } from '@nestjs/common';
import type { SecretService } from '../../infrastructure/secret.service';
import type { ConfigPlan } from './configuration.types';
const changed=()=>new ConflictException({code:'CONFIGURATION_DURABLE_FRESH_DIFF_CHANGED',message:'当前配置已变化，请重新预览后创建配置工单'});
/** Compare complete business semantics. Only newly allocated console step IDs
 * are mapped to their exact object keys. Native/Target UUIDs, secrets, bodies,
 * current-before facts, packet paths and dependency edges are never removed. */
export function assertDurableConfigurationEquivalent(original:ConfigPlan,fresh:ConfigPlan,secrets:SecretService):void{
 const project=(p:ConfigPlan):unknown=>{
  const ids=new Map(p.steps.map(step=>[step.stepId,step.objectKey]));
  if(ids.size!==p.steps.length||new Set(ids.values()).size!==p.steps.length)throw changed();
  return{scope:p.scope,mode:p.mode,schemaHmac:p.schemaHmac,permissionVersion:p.permissionVersion,clusterRevision:p.clusterRevision,
   workspaceRevision:p.workspaceRevision,kongVersion:p.kongVersion,recoveryComplete:p.recoveryComplete,
   steps:p.steps.map((step,index)=>{
    const {stepId,dependencies,...facts}=step;
    if(step.stepOrder!==index+1||new Set(dependencies).size!==dependencies.length||dependencies.some(id=>!ids.has(id)||p.steps.findIndex(candidate=>candidate.stepId===id)>=index))throw changed();
    // Object order and explicit stepOrder are also retained. This deliberately
    // rejects uncertain independent-order changes rather than widening consent.
    return{...facts,dependencies:dependencies.map(id=>ids.get(id))};
   })};
 };
 if(secrets.fingerprint(project(original))!==secrets.fingerprint(project(fresh)))throw changed();
}
