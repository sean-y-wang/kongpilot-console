import type { EffectiveGrant, PermissionAction } from '../../common/authorization.types';
import { validGrant } from './grant-policy';

export const HISTORY_NATIVE_TYPES = ['services','routes','consumers','plugins','upstreams','certificates',
  'ca_certificates','snis','targets','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'] as const;
export const HISTORY_UUID = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
export type HistoryModule = 'audit'|'events'|'notifications';
export interface HistorySide { workspaceId:string|null; physicalTags:readonly string[] }
export interface HistoricalScope {
  version:1; quality:'verified'|'legacy_unknown'; module:string;
  nativeType?:string; nativeId?:string; parentId?:string; credentialKind?:string;
  before:HistorySide|null; after:HistorySide|null; subject?:{type:string;id:string};
}
export interface HistoricalIdentity {clusterId:string|null;workspaceId:string|null;scope:HistoricalScope}
export interface HistoricalPrincipal {user:{superAdmin:boolean};grants:readonly EffectiveGrant[]}

/** The caller must first verify the immutable scope's HMAC and source tuple. */
export function historyScopeValid(value:unknown):value is HistoricalScope {
  if(!value||typeof value!=='object'||Array.isArray(value))return false;
  const scope=value as HistoricalScope;
  if(scope.version!==1||!['verified','legacy_unknown'].includes(scope.quality)||typeof scope.module!=='string')return false;
  if(scope.nativeType!==undefined&&!(HISTORY_NATIVE_TYPES as readonly string[]).includes(scope.nativeType)
    ||scope.nativeId!==undefined&&!HISTORY_UUID.test(scope.nativeId))return false;
  if((scope.nativeType===undefined)!==(scope.nativeId===undefined))return false;
  for(const side of [scope.before,scope.after]){
    if(side===null)continue;
    if(!side||typeof side!=='object'||side.workspaceId!==null&&!HISTORY_UUID.test(side.workspaceId)
      ||!Array.isArray(side.physicalTags)||side.physicalTags.length>1000
      ||side.physicalTags.some(tag=>typeof tag!=='string'||!tag.length||tag.length>128))return false;
  }
  if(scope.subject!==undefined&&(!scope.subject||typeof scope.subject.type!=='string'||!HISTORY_UUID.test(scope.subject.id)))return false;
  return true;
}

export function wholeHistoryGrant(grant:EffectiveGrant,module:HistoryModule,action:PermissionAction,
  clusterId:string|null,workspaceId?:string|null):boolean {
  if(!validGrant(grant)||grant.module!==module||grant.action!==action)return false;
  if(clusterId===null)return grant.scope_type==='global'&&grant.cluster_id===null&&grant.workspace_id===null;
  if(grant.cluster_id!==null&&grant.cluster_id!==clusterId)return false;
  if(workspaceId===undefined)return grant.scope_type==='global'&&grant.workspace_id===null;
  if(grant.workspace_id!==null&&grant.workspace_id!==workspaceId)return false;
  return grant.scope_type==='global'||grant.scope_type==='workspace'&&workspaceId!==null
    &&grant.cluster_id===clusterId&&grant.workspace_id===workspaceId&&grant.scope_values.includes(workspaceId);
}

/** No current object, parent, workspace-tag resolution, or cross-row grant union. */
export function historicalAllows(principal:HistoricalPrincipal,module:HistoryModule,identity:HistoricalIdentity,
  action:PermissionAction='read'):boolean {
  const {clusterId,workspaceId,scope}=identity;
  if(clusterId!==null&&!HISTORY_UUID.test(clusterId)||workspaceId!==null&&(!clusterId||!HISTORY_UUID.test(workspaceId)))return false;
  if(principal.user.superAdmin)return true;
  if(!historyScopeValid(scope)||scope.quality!=='verified'){
    return principal.grants.some(grant=>wholeHistoryGrant(grant,module,action,clusterId));
  }
  if(clusterId===null)return principal.grants.some(grant=>wholeHistoryGrant(grant,module,action,null));
  const sides=[scope.before,scope.after].filter((side):side is HistorySide=>side!==null);
  if(!sides.length||sides.some(side=>side.workspaceId===null)){
    return principal.grants.some(grant=>wholeHistoryGrant(grant,module,action,clusterId));
  }
  return principal.grants.some(grant=>{
    if(!validGrant(grant)||grant.module!==module||grant.action!==action
      ||grant.cluster_id!==null&&grant.cluster_id!==clusterId)return false;
    // Both existing sides must be covered by this exact grant, including WID ceilings.
    return sides.every(side=>{
      if(grant.workspace_id!==null&&grant.workspace_id!==side.workspaceId)return false;
      if(wholeHistoryGrant(grant,module,action,clusterId,side.workspaceId))return true;
      if(!scope.nativeType||!scope.nativeId)return false;
      if(grant.scope_type==='tag_group')return grant.scope_values.some(tag=>typeof tag==='string'
        &&!tag.startsWith('kos-ws-')&&side.physicalTags.includes(tag));
      return grant.scope_type==='entity'&&grant.scope_values.some(value=>typeof value==='object'
        &&value.entity_type===scope.nativeType&&value.entity_id===scope.nativeId);
    });
  });
}
