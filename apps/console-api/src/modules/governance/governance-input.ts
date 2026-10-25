import { BadRequestException } from '@nestjs/common';
import { configurationId, configurationKey, configurationPage } from '../configuration/configuration-input';

export const governanceId=configurationId,governanceKey=configurationKey,governancePage=configurationPage;
export const GOVERNANCE_JSON_LIMIT=1024*1024;
const fail=(code='INVALID_GOVERNANCE_INPUT'):never=>{throw new BadRequestException({code,message:'治理请求不符合字段、类型或范围约束'});};
/** Data-only DTOs: no getters, callbacks, prototype paths or authorization flags. */
export function governanceObject(value:unknown,allowed?:readonly string[],maximum=GOVERNANCE_JSON_LIMIT):Record<string,any>{
 let nodes=0;
 const visit=(entry:unknown,depth:number):void=>{
  if(++nodes>50000||depth>20)fail('GOVERNANCE_JSON_LIMIT');
  if(entry===null||typeof entry==='string'||typeof entry==='boolean')return;
  if(typeof entry==='number'){if(!Number.isFinite(entry))fail();return;}
  if(!entry||typeof entry!=='object'||!Array.isArray(entry)&&![Object.prototype,null].includes(Object.getPrototypeOf(entry)))fail();
  const target=entry as object,descriptors=Object.getOwnPropertyDescriptors(target);
  for(const key of Reflect.ownKeys(target)){
   if(Array.isArray(entry)&&key==='length')continue;
   if(typeof key!=='string')fail('GOVERNANCE_CONTROL_FIELD');const name=key as string;
   if(['__proto__','prototype','constructor','approved','superAdmin','ownerId','owner_user_id','sourceProof'].includes(name)||!Object.hasOwn(descriptors[name],'value')||!descriptors[name].enumerable)fail('GOVERNANCE_CONTROL_FIELD');
   visit(descriptors[name].value,depth+1);
  }
 };
 if(!value||typeof value!=='object'||Array.isArray(value))fail();visit(value,0);
 if(Buffer.byteLength(JSON.stringify(value))>maximum)fail('GOVERNANCE_JSON_LIMIT');
 const body=value as Record<string,any>;if(allowed&&Object.keys(body).some(key=>!allowed.includes(key)))fail('UNKNOWN_GOVERNANCE_FIELD');
 return structuredClone(body);
}
export function governanceText(value:unknown,max=128,required=true):string{
 if(typeof value!=='string'||value.length>max||required&&!value.trim()||/[\u0000-\u001f\u007f]/.test(value))fail('INVALID_GOVERNANCE_TEXT');return (value as string).trim();
}
export function governanceRevision(value:unknown):number{if(!Number.isSafeInteger(value)||Number(value)<1||Number(value)>2147483646)fail('INVALID_GOVERNANCE_REVISION');return value as number;}
export function governanceBoolean(value:unknown,fallback=false):boolean{if(value===undefined)return fallback;if(typeof value!=='boolean')fail('INVALID_GOVERNANCE_BOOLEAN');return value as boolean;}
export function governanceStrings(value:unknown,max=200):string[]{if(!Array.isArray(value)||value.length>max)fail('INVALID_GOVERNANCE_LIST');const entries=(value as unknown[]).map(v=>governanceText(v,256));if(new Set(entries).size!==entries.length)fail('DUPLICATE_GOVERNANCE_VALUE');return entries;}
export function governanceConfirm(value:Record<string,unknown>,name:string):void{if(value.confirmed!==true||value.confirm_name!==name)fail('CONFIRMATION_REQUIRED');}
export function governanceCode(value:unknown):string{const code=governanceText(value,96);if(!/^[a-z][a-z0-9_.-]{0,95}$/.test(code))fail('INVALID_GOVERNANCE_CODE');return code;}
export interface GovernanceScopeInput {scope:'cluster'|'workspace'|'services';serviceIds:string[];}
export function governanceScope(value:Record<string,any>,allowCluster=true):GovernanceScopeInput{
 const scope=value.scope??'workspace';if(!['workspace','services',...(allowCluster?['cluster']:[])].includes(scope))fail('INVALID_GOVERNANCE_SCOPE');
 const roots=value.serviceIds??[];if(!Array.isArray(roots)||roots.length>100||(scope==='services')!==(roots.length>0))fail('INVALID_GOVERNANCE_ROOTS');
 const serviceIds=roots.map(governanceId);if(new Set(serviceIds).size!==serviceIds.length)fail('DUPLICATE_GOVERNANCE_ROOT');return{scope,serviceIds};
}
export interface GovernanceTargetInput extends GovernanceScopeInput {clusterId:string;workspaceId:string;}
export function governanceTarget(value:unknown):GovernanceTargetInput{const v=governanceObject(value,['clusterId','workspaceId','scope','serviceIds']);return{clusterId:governanceId(v.clusterId),workspaceId:governanceId(v.workspaceId),...governanceScope(v,false)};}
export function inspectionInput(value:unknown):GovernanceScopeInput&{ruleCodes?:string[]}{const v=governanceObject(value,['scope','serviceIds','ruleCodes']);return{...governanceScope(v),...(v.ruleCodes===undefined?{}:{ruleCodes:governanceStrings(v.ruleCodes).map(governanceCode)})};}
export interface ComparisonInput extends GovernanceScopeInput {target:GovernanceTargetInput;threshold:number;includeEnvironmentFields:boolean;}
export function comparisonInput(value:unknown):ComparisonInput{const v=governanceObject(value,['scope','serviceIds','target','threshold','includeEnvironmentFields']);const threshold=v.threshold??0;if(!Number.isSafeInteger(threshold)||threshold<0||threshold>10000)fail('INVALID_DRIFT_THRESHOLD');return{...governanceScope(v,false),target:governanceTarget(v.target),threshold,includeEnvironmentFields:governanceBoolean(v.includeEnvironmentFields)};}
export interface GovernanceSchedulePayload extends GovernanceScopeInput {name:string;kind:'inspection'|'drift';ruleCodes?:string[];target?:GovernanceTargetInput;intervalMinutes:number;timezone:string;threshold:number;includeEnvironmentFields:boolean;paused:boolean;}
export function scheduleInput(value:unknown,update=false):Record<string,any>{
 const v=governanceObject(value,['name','kind','scope','serviceIds','ruleCodes','target','intervalMinutes','timezone','threshold','includeEnvironmentFields','paused',...(update?['revision']:[])]);
 if(update)governanceRevision(v.revision);
 if(v.name!==undefined||!update)v.name=governanceText(v.name);
 if(v.kind!==undefined||!update){if(!['inspection','drift'].includes(v.kind))fail('INVALID_GOVERNANCE_SCHEDULE_KIND');}
 // Partial changes are validated in their actual stored policy after merge.
 // Validating roots against a guessed default workspace would reject a
 // serviceIds-only patch of an existing service policy.
 if(!update||v.scope!==undefined&&v.serviceIds!==undefined)Object.assign(v,governanceScope(v,v.kind!=='drift'));
 else{
  if(v.scope!==undefined&&!['cluster','workspace','services'].includes(v.scope))fail('INVALID_GOVERNANCE_SCOPE');
  if(v.serviceIds!==undefined){if(!Array.isArray(v.serviceIds)||v.serviceIds.length>100)fail('INVALID_GOVERNANCE_ROOTS');v.serviceIds=v.serviceIds.map(governanceId);if(new Set(v.serviceIds).size!==v.serviceIds.length)fail('DUPLICATE_GOVERNANCE_ROOT');}
 }
 if(v.ruleCodes!==undefined)v.ruleCodes=governanceStrings(v.ruleCodes).map(governanceCode);
 if(v.target!==undefined)v.target=governanceTarget(v.target);
 if(v.intervalMinutes!==undefined||!update){if(!Number.isSafeInteger(v.intervalMinutes)||v.intervalMinutes<5||v.intervalMinutes>10080)fail('INVALID_GOVERNANCE_INTERVAL');}
 if(v.timezone!==undefined||!update){v.timezone=governanceText(v.timezone??'UTC',64);try{new Intl.DateTimeFormat('en',{timeZone:v.timezone});}catch{fail('INVALID_GOVERNANCE_TIMEZONE');}}
 if(v.threshold!==undefined||!update){const n=v.threshold??0;if(!Number.isSafeInteger(n)||n<0||n>10000)fail('INVALID_DRIFT_THRESHOLD');v.threshold=n;}
 for(const key of ['includeEnvironmentFields','paused'])if(v[key]!==undefined||!update)v[key]=governanceBoolean(v[key]);
 if(!update){if(v.kind==='drift'&&!v.target)fail('DRIFT_TARGET_REQUIRED');if(v.kind==='inspection'&&v.target)fail('INSPECTION_TARGET_FORBIDDEN');}
 return v;
}
export function ruleInput(value:unknown,update=false):Record<string,any>{
 const v=governanceObject(value,[...(!update?['code']:[]),'name','description','severity','given','then','enabled',...(update?['revision']:[])]);
 if(update)governanceRevision(v.revision);else v.code=governanceCode(v.code);
 if(v.name!==undefined||!update)v.name=governanceText(v.name);
 if(v.description!==undefined||!update)v.description=governanceText(v.description??'',500,false);
 if(v.severity!==undefined||!update){if(!['error','warn','info'].includes(v.severity))fail('INVALID_LINT_SEVERITY');}
 if(!update&&(v.given===undefined||v.then===undefined))fail('LINT_PREDICATE_REQUIRED');
 if(v.enabled!==undefined||!update)v.enabled=governanceBoolean(v.enabled,true);return v;
}
export function promotionInput(value:unknown):Record<string,any>{
 const v=governanceObject(value,['selectedObjectKeys','mapping','fieldOverrides','includeEnvironmentFields','includeSecrets','includeCredentials','credentialKinds','confirmed','confirm_name']);
 if(v.selectedObjectKeys!==undefined)v.selectedObjectKeys=governanceStrings(v.selectedObjectKeys,1000);
 for(const field of ['mapping','fieldOverrides'])if(v[field]!==undefined){const m=governanceObject(v[field]);if(Object.keys(m).length>1000)fail('PROMOTION_MAPPING_LIMIT');for(const [key,entry]of Object.entries(m)){governanceText(key,256);if(field==='mapping')m[key]=governanceId(entry);else m[key]=governanceObject(entry);}v[field]=m;}
 for(const field of ['includeEnvironmentFields','includeSecrets','includeCredentials'])v[field]=governanceBoolean(v[field]);
 if(v.credentialKinds!==undefined){const kinds=governanceStrings(v.credentialKinds,6);if(!v.includeCredentials||!kinds.length||kinds.some(kind=>!['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].includes(kind)))fail('INVALID_PROMOTION_CREDENTIAL_KINDS');v.credentialKinds=kinds;}
 if(v.confirmed!==true)fail('CONFIRMATION_REQUIRED');v.confirm_name=governanceText(v.confirm_name,256);return v;
}
export function governanceFailureCode(error:unknown):string{const e=error as any,r=typeof e?.getResponse==='function'?e.getResponse():null,code=r?.code??e?.code;return typeof code==='string'&&/^[A-Z0-9_]{1,128}$/.test(code)?code:'GOVERNANCE_OPERATION_FAILED';}
