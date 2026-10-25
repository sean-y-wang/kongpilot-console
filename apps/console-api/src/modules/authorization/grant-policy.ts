import { EffectiveGrant, EntityScopeValue, PermissionAction, permissionModule } from '../../common/authorization.types';

export interface GrantTarget {
  clusterId?:string; workspaceId?:string; entityType?:string; entity?:any;
}
const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;

/** Normalize database rows without inventing a value for an empty restricted scope. */
export function validGrant(value:any):value is EffectiveGrant {
  if(!value||typeof value!=='object'||!['read','write','delete','approve'].includes(value.action)
    ||typeof value.module!=='string'||!['global','workspace','tag_group','entity'].includes(value.scope_type)
    ||!Array.isArray(value.scope_values))return false;
  if(value.cluster_id!==null&&!uuid.test(value.cluster_id??''))return false;
  if(value.workspace_id!==null&&(!value.cluster_id||!uuid.test(value.workspace_id??'')))return false;
  if(value.scope_type==='workspace')return !!value.cluster_id&&!!value.workspace_id
    &&value.scope_values.length>0&&value.scope_values.every((item:any)=>typeof item==='string'&&uuid.test(item)&&item===value.workspace_id);
  if(value.scope_type==='tag_group')return !!value.cluster_id&&value.scope_values.length>0
    &&value.scope_values.every((item:any)=>typeof item==='string'&&/^[a-zA-Z\d._~-]{1,128}$/.test(item)&&!item.startsWith('kos-ws-'));
  if(value.scope_type==='entity')return !!value.cluster_id&&value.scope_values.length>0
    &&value.scope_values.every((item:any)=>item&&typeof item==='object'&&typeof item.entity_type==='string'&&uuid.test(item.entity_id??''));
  return value.scope_values.length===0;
}

export function grantCeilingMatches(grant:EffectiveGrant,target:GrantTarget):boolean {
  if(grant.cluster_id!==null&&target.clusterId!==undefined&&grant.cluster_id!==target.clusterId)return false;
  if(grant.workspace_id!==null&&target.workspaceId!==undefined&&grant.workspace_id!==target.workspaceId)return false;
  return true;
}

/** Coarse checks only decide whether to inspect objects; they never authorize an object. */
export function coarseGrantMatches(grant:EffectiveGrant,module:string,action:PermissionAction,target:GrantTarget):boolean {
  return validGrant(grant)&&permissionModule(grant.module)===permissionModule(module)
    &&grant.action===action&&grantCeilingMatches(grant,target);
}

export function grantMatchesEntity(grant:EffectiveGrant,module:string,action:PermissionAction,target:GrantTarget):boolean {
  // Discovery may omit a workspace while enumerating allowed scopes. Actual
  // objects never inherit that omission: they must have a resolved, valid CID
  // and WID before any global/tag/entity grant can authorize them.
  if(!uuid.test(target.clusterId??'')||!uuid.test(target.workspaceId??''))return false;
  if(grant.cluster_id!==null&&grant.cluster_id!==target.clusterId
    ||grant.workspace_id!==null&&grant.workspace_id!==target.workspaceId)return false;
  if(!coarseGrantMatches(grant,module,action,target))return false;
  if(grant.scope_type==='global')return true;
  if(grant.scope_type==='workspace')return !!target.workspaceId&&grant.scope_values.includes(target.workspaceId);
  if(grant.scope_type==='tag_group')return Array.isArray(target.entity?.tags)
    &&grant.scope_values.some(tag=>typeof tag==='string'&&target.entity.tags.includes(tag));
  return typeof target.entity?.id==='string'&&grant.scope_values.some(value=>typeof value==='object'
    &&value.entity_type===target.entityType&&value.entity_id===target.entity.id);
}

/** A single existing complete grant must cover each proposed scope value. */
export function grantContains(existing:EffectiveGrant,proposed:EffectiveGrant):boolean {
  if(!validGrant(existing)||!validGrant(proposed)||permissionModule(existing.module)!==permissionModule(proposed.module)||existing.action!==proposed.action)return false;
  if(existing.cluster_id!==null&&existing.cluster_id!==proposed.cluster_id)return false;
  if(existing.workspace_id!==null&&existing.workspace_id!==proposed.workspace_id)return false;
  if(existing.scope_type==='global')return true;
  if(existing.scope_type==='workspace')return !!proposed.workspace_id&&existing.scope_values.includes(proposed.workspace_id);
  if(existing.scope_type!==proposed.scope_type)return false;
  if(existing.scope_type==='tag_group')return proposed.scope_values.every(value=>existing.scope_values.includes(value));
  return proposed.scope_values.every(value=>typeof value==='object'&&existing.scope_values.some(item=>typeof item==='object'
    &&(item as EntityScopeValue).entity_type===value.entity_type&&(item as EntityScopeValue).entity_id===value.entity_id));
}

export function inheritedTagMatches(grant:EffectiveGrant,child:any):boolean {
  return grant.scope_type!=='tag_group'||Array.isArray(child?.tags)
    &&grant.scope_values.some(value=>typeof value==='string'&&child.tags.includes(value));
}
