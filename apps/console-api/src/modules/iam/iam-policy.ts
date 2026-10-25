import { BadRequestException } from '@nestjs/common';
import { PERMISSION_ACTIONS,PERMISSION_MODULES,permissionModule,type EffectiveGrant } from '../../common/authorization.types';
import { encodeTag } from '../../infrastructure/kong/tags';
import { iamBody,iamId,type IamScope } from './iam.types';

export const SCOPE_TYPES=['global','workspace','tag_group','entity'] as const;
export const ENTITY_TYPES=['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','targets','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'];
const invalid=()=>new BadRequestException({code:'INVALID_PERMISSION',message:'权限必须包含完整且一致的模块、操作、集群和范围'});
export function iamScope(body:any):IamScope {
 const cid=body.cluster_id==null?null:iamId(body.cluster_id),wid=body.workspace_id==null?null:iamId(body.workspace_id);
 if(wid&&!cid)throw invalid();return {cluster_id:cid,workspace_id:wid};
}
/** Normalize logical business tags once. A workspace ceiling is never a business tag. */
export function normalizePermission(input:unknown,owner:IamScope):EffectiveGrant {
 const value=iamBody(input,['module','action','scope_type','scope_values','cluster_id','workspace_id']),scope=iamScope(value);
 if(!PERMISSION_MODULES.includes(value.module)||!PERMISSION_ACTIONS.includes(value.action)||!SCOPE_TYPES.includes(value.scope_type)||!Array.isArray(value.scope_values))throw invalid();
 if(owner.cluster_id&&scope.cluster_id!==owner.cluster_id||owner.workspace_id&&scope.workspace_id!==owner.workspace_id)throw invalid();
 let values:EffectiveGrant['scope_values'];
 if(value.scope_type==='global'){
  if(scope.cluster_id||scope.workspace_id||value.scope_values.length||owner.cluster_id||owner.workspace_id)throw invalid();values=[];
 }else if(value.scope_type==='workspace'){
  if(!scope.cluster_id||!scope.workspace_id||value.scope_values.length!==1||value.scope_values[0]!==scope.workspace_id)throw invalid();values=[scope.workspace_id];
 }else if(value.scope_type==='tag_group'){
  if(!scope.cluster_id||!value.scope_values.length||value.scope_values.length>100)throw invalid();
  if(value.scope_values.some((tag:any)=>typeof tag!=='string'||!tag.trim()||tag.length>128||tag.startsWith('workspace:')||tag.startsWith('kos-ws-')||tag.startsWith('kos-tag-')))throw invalid();
  values=[...new Set(value.scope_values.map((tag:string)=>encodeTag(tag)))];
 }else{
  if(!scope.cluster_id||!value.scope_values.length||value.scope_values.length>500)throw invalid();
  values=value.scope_values.map((entry:any)=>{const item=iamBody(entry,['entity_type','entity_id']);
   const annotations=value.module==='annotations'&&ENTITY_TYPES.slice(0,8).includes(item.entity_type);
   const monitoring=value.module==='monitoring'&&['services','routes','consumers'].includes(item.entity_type);
   const operational=value.module==='portal'&&['services','routes'].includes(item.entity_type)
     ||value.module==='workflows'&&ENTITY_TYPES.includes(item.entity_type);
   const historical=['audit','events','notifications'].includes(value.module)&&ENTITY_TYPES.includes(item.entity_type);
   if(!ENTITY_TYPES.includes(item.entity_type)||(value.module!=='secrets'&&!annotations&&!monitoring&&!operational&&!historical&&permissionModule(item.entity_type)!==value.module))throw invalid();return {entity_type:item.entity_type,entity_id:iamId(item.entity_id)};});
  values=[...new Map(values.map((item:any)=>[`${item.entity_type}:${item.entity_id}`,item])).values()];
 }
 return {...scope,module:value.module,action:value.action,scope_type:value.scope_type,scope_values:values};
}
/** Permission, role owner and assignment are intersected pairwise, never unioned. */
export function resolveAssignedGrants(permissions:EffectiveGrant[],role:IamScope,binding:IamScope):EffectiveGrant[] {
 if(role.cluster_id&&binding.cluster_id!==role.cluster_id||role.workspace_id&&binding.workspace_id!==role.workspace_id)throw invalid();
 return permissions.flatMap(permission=>{
  const ids=[permission.cluster_id,role.cluster_id,binding.cluster_id].filter(Boolean),wids=[permission.workspace_id,role.workspace_id,binding.workspace_id].filter(Boolean);
  if(new Set(ids).size>1||new Set(wids).size>1)return [];
  return [{...permission,cluster_id:ids[0]??null,workspace_id:wids[0]??null}];
 });
}
