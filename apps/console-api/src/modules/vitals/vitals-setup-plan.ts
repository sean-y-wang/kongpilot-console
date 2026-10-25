import {BadRequestException} from '@nestjs/common';
import type {WorkflowPlanV1,WorkflowStep} from '../workflows/workflow.types';
import type {MetricsSetupIntent,MetricsSetupMetadata} from './vitals-setup.types';
import type {SecretService} from '../../infrastructure/secret.service';
const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i,hex=/^[a-f\d]{64}$/;
const fail=():never=>{throw new BadRequestException({code:'METRICS_SETUP_PLAN_INVALID'});};
/** Public workflow/intent projections never reveal the managed endpoint or
 * arbitrary HTTP log headers, including on the before side of a diff. */
export function metricsSetupPublicProjection(value:unknown,secrets:Pick<SecretService,'redact'>):any{
 const visit=(entry:any):any=>{if(Array.isArray(entry))return entry.map(visit);if(entry&&typeof entry==='object')return Object.fromEntries(Object.entries(entry).map(([key,v])=>
  [key,key==='http_endpoint'?'[MANAGED_ENDPOINT]':key==='headers'?'[REDACTED]':visit(v)]));return entry;};return visit(secrets.redact(value));
}
/** This compiler has only two fixed global plugin names and one SQL settings
 * handler. It cannot transport an HTTP supplied plugin, URL, token or handler. */
export function assertMetricsSetupPlan(plan:WorkflowPlanV1):WorkflowStep{
 if(!plan||(plan.kind as string)!=='metrics-setup'||(plan.subject.type as string)!=='metrics_setup_requests'||plan.requester.type!=='console'
  ||plan.executionMode!=='approval'||plan.approvalRequired!==true||plan.planRevision!==1||plan.generated!==undefined||plan.migration!==undefined||(plan as any).scheduling!==undefined
  ||!Array.isArray(plan.prerequisites)||plan.prerequisites.length||!Array.isArray(plan.steps)||![2,3].includes(plan.steps.length))fail();
 const final=plan.steps.at(-1)!,payload=final.metadata as MetricsSetupMetadata,count=plan.steps.length-1;
 if(final.kind!=='metadata'||final.handler!=='metrics.setup.settings'||final.key!=='metrics.setup.settings'||final.entityType!=='metrics_setup_requests'
  ||final.entityId!==plan.subject.id||!uuid.test(final.entityId??'')||final.permissionAction!=='write'||final.order!==plan.steps.length
  ||final.parentId!=null||final.credentialKind!=null||final.mutationAction!==undefined||final.mutationPayload!==undefined||final.beforeFingerprint!==undefined
  ||final.mutationIdempotencyKey!==undefined||final.mutationPayloadHmac!==undefined||!Array.isArray(final.nativeRequests)||final.nativeRequests.length||!Array.isArray(final.dependencies)
  ||final.dependencies.length!==1||final.dependencies[0]!==plan.steps[count-1].id||!Number.isSafeInteger(final.metadataRevision)||Number(final.metadataRevision)<0
  ||!hex.test(final.metadataBeforeHmac??'')||!hex.test(final.metadataPayloadHmac??'')||!payload||typeof payload!=='object'||Array.isArray(payload)
  ||Object.keys(payload).length!==4||!['intentId','mode','sourceId','materialHmac'].every(k=>Object.hasOwn(payload,k))||payload.intentId!==plan.subject.id
  ||!uuid.test(payload.sourceId)||!hex.test(payload.materialHmac)||payload.mode!==(count===1?'native_prometheus':'collector'))fail();
 const ids=new Set<string>();
 for(const [i,s] of plan.steps.slice(0,-1).entries()){
  const name=i===0?'prometheus':'http-log',r=s.nativeRequests?.[0],body=s.mutationPayload as any;
  if(!uuid.test(s.id)||ids.has(s.id)||s.kind!=='native'||s.handler!==undefined||s.key!==`metrics.setup.${name}`||s.order!==i+1||s.entityType!=='plugins'
   ||!uuid.test(s.entityId??'')||s.parentId!=null||s.credentialKind!=null||s.permissionAction!=='write'||!['create','update'].includes(s.mutationAction??'')
   ||s.metadata!==undefined||!Array.isArray(s.dependencies)||s.dependencies.length!==(i?1:0)||i&&s.dependencies[0]!==plan.steps[i-1].id
   ||s.nativeRequests.length!==1||!r||r.nativeType!=='plugins'||r.nativeId!==s.entityId||r.parentId!=null||r.credentialKind!=null
   ||r.method!==(s.mutationAction==='create'?'POST':'PATCH')||r.canonicalPath!==(s.mutationAction==='create'?'/plugins':`/plugins/${s.entityId}`)
   ||!hex.test(s.beforeFingerprint??'')||!hex.test(s.mutationPayloadHmac??'')||!hex.test(r.bodyHmac)||r.beforeHmac!==s.beforeFingerprint
   ||s.mutationIdempotencyKey!==`metrics-approved-${plan.subject.id}-${name}`||!body||body.enabled!==true||!body.config||typeof body.config!=='object'||Array.isArray(body.config)
   ||Object.keys(body).some(k=>!(s.mutationAction==='create'?['id','name','enabled','config','tags']:['enabled','config']).includes(k))
   ||s.mutationAction==='create'&&(body.name!==name||body.id!==s.entityId||s.before!==null)
   ||s.mutationAction==='update'&&((s.before as any)?.name!==name||(s.before as any)?.id!==s.entityId)
   ||['service','route','consumer'].some(k=>(s.before as any)?.[k]?.id||body[k]!=null))fail();
  ids.add(s.id);
 }
 if(!uuid.test(final.id)||ids.has(final.id))fail();return final;
}
export function metricsSetupSteps(intent:Readonly<MetricsSetupIntent>,fingerprint:(value:unknown)=>string,newId:()=>string):WorkflowStep[]{
 const steps:WorkflowStep[]=intent.plugins.map((plugin,i)=>({id:newId(),key:`metrics.setup.${plugin.name}`,order:i+1,kind:'native',entityType:'plugins',entityId:plugin.nativeId,
  permissionAction:'write',dependencies:[],mutationAction:plugin.action,mutationPayload:plugin.payload,mutationPayloadHmac:fingerprint(plugin.payload),
  mutationIdempotencyKey:`metrics-approved-${intent.id}-${plugin.name}`,before:plugin.before,beforeFingerprint:fingerprint(plugin.before),
  nativeRequests:[{method:plugin.action==='create'?'POST':'PATCH',canonicalPath:plugin.action==='create'?'/plugins':`/plugins/${plugin.nativeId}`,nativeType:'plugins',nativeId:plugin.nativeId,
   body:plugin.payload,bodyHmac:fingerprint(plugin.payload),beforeHmac:fingerprint(plugin.before)}]}));
 for(let i=1;i<steps.length;i++)steps[i].dependencies=[steps[i-1].id];
 const metadata:MetricsSetupMetadata={intentId:intent.id,mode:intent.mode,sourceId:intent.source.id,materialHmac:fingerprint(intent)};
 steps.push({id:newId(),key:'metrics.setup.settings',order:steps.length+1,kind:'metadata',handler:'metrics.setup.settings',entityType:'metrics_setup_requests',entityId:intent.id,
  permissionAction:'write',dependencies:[steps.at(-1)!.id],nativeRequests:[],before:intent.settings,metadataRevision:intent.settings.revision,metadataBeforeHmac:fingerprint(intent.settings),
  metadata,metadataPayloadHmac:fingerprint(metadata)});return steps;
}
