import type { EffectiveGrant, PermissionAction } from '../../common/authorization.types';
import { permissionModule } from '../../common/authorization.types';
import { grantMatchesEntity, inheritedTagMatches } from '../authorization/grant-policy';
import type { CaptureObject } from './configuration.types';

/** Private sealed graph only. A current complete grant row must match each
 * side and inherited tag ceiling; scopes are never unioned across rows. */
export function historicalConfigurationAllowed(grants:readonly EffectiveGrant[],clusterId:string,object:CaptureObject,objects:readonly CaptureObject[],action:PermissionAction='read'):boolean{
  const type=object.credentialKind??object.entityType,wid=object.objectWorkspaceId,entity={...object.payload,tags:[...object.ownershipTags]};
  const direct=(t:string,e:any,a:PermissionAction=action)=>grants.filter(g=>grantMatchesEntity(g,permissionModule(t),a,{clusterId,workspaceId:wid,entityType:t,entity:e}));
  const parent=(t:string,id:string)=>objects.find(o=>o.entityType===t&&o.nativeId===id&&o.objectWorkspaceId===wid);
  const parentGrants=(t:string,id:string,child:any,depth=0):EffectiveGrant[]=>{
    if(depth>2)return[];const o=parent(t,id);if(!o)return[];const p={...o.payload,tags:[...o.ownershipTags]};
    const own=direct(t,p).filter(g=>inheritedTagMatches(g,child));if(own.length)return own;
    if(t==='routes'&&['write','delete'].includes(action)&&(p as any).service?.id)return parentGrants('services',(p as any).service.id,child,depth+1).filter(g=>inheritedTagMatches(g,p));return[];
  };
  if(type==='plugins'){
    const bindings=[['service','services'],['route','routes'],['consumer','consumers']].filter(([field])=>(entity as any)[field]?.id);
    if(!bindings.length)return action==='read'&&direct(type,entity).length>0;
    return bindings.every(([field,t])=>parentGrants(t,(entity as any)[field].id,entity).length>0);
  }
  if(direct(type,entity).length)return true;
  if(type==='routes'&&['write','delete'].includes(action)&&(entity as any).service?.id)return parentGrants('services',(entity as any).service.id,entity).length>0;
  if(type==='services'&&action==='read')return objects.some(o=>o.entityType==='routes'&&o.objectWorkspaceId===wid&&(o.payload.service as any)?.id===object.nativeId
    &&grants.some(g=>grantMatchesEntity(g,'routes',g.action,{clusterId,workspaceId:wid,entityType:'routes',entity:{...o.payload,tags:[...o.ownershipTags]}})));
  if(type==='targets'&&object.parentId)return parentGrants('upstreams',object.parentId,entity).length>0;
  if(object.entityType==='credentials'&&object.parentId)return parentGrants('consumers',object.parentId,entity).length>0;
  return false;
}
