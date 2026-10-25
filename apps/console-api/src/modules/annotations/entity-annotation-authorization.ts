import {permissionModule,type EffectiveGrant,type PermissionAction} from '../../common/authorization.types';
import {grantMatchesEntity,inheritedTagMatches} from '../authorization/grant-policy';
import type {AnnotationNativeNode,AnnotationNativeProof} from './entity-annotation-workflow.types';

/** Pure current raw-graph checks mirror AuthorizationService's native
 * relationship rules. Nodes must come from the fixed original observer;
 * caller DTOs, old tags and unions of unrelated grants never qualify. */
export function annotationNativePermitted(grants:readonly EffectiveGrant[],superAdmin:boolean,clusterId:string,proof:Readonly<AnnotationNativeProof>,action:PermissionAction):boolean {
 const root=proof.root,wid=root.workspaceId,find=(type:string,id:unknown)=>proof.parents.find(n=>n.entityType===type&&n.entity.id===id),
  direct=(node:Readonly<AnnotationNativeNode>,operation:PermissionAction)=>grants.filter(g=>grantMatchesEntity(g,permissionModule(node.entityType),operation,
   {clusterId,workspaceId:node.workspaceId,entityType:node.entityType,entity:node.entity}));
 if(superAdmin)return true;
 const parentGrants=(type:string,id:unknown,child:Readonly<Record<string,unknown>>):EffectiveGrant[]=>{
  const parent=find(type,id);if(!parent||parent.workspaceId!==wid)return [];
  const own=direct(parent,action).filter(g=>inheritedTagMatches(g,child));if(own.length)return own;
  if(type==='routes'&&(action==='write'||action==='delete')){
   const service=(parent.entity.service as any)?.id;if(!service)return [];
   return parentGrants('services',service,child).filter(g=>inheritedTagMatches(g,parent.entity));
  }return [];
 };
 if(root.entityType==='plugins'){
  const refs:[string,unknown][]=[];for(const [field,type] of [['service','services'],['route','routes'],['consumer','consumers']]){
   const id=(root.entity[field] as any)?.id;if(id)refs.push([type,id]);
  }
  return refs.length?refs.every(([type,id])=>parentGrants(type,id,root.entity).length>0):action==='read'&&direct(root,action).length>0;
 }
 if(direct(root,action).length)return true;
 if(root.entityType==='routes'&&(action==='write'||action==='delete'))return parentGrants('services',(root.entity.service as any)?.id,root.entity).length>0;
 if(root.entityType==='services'&&action==='read')return proof.serviceRoutes.some(node=>node.workspaceId===wid&&(node.entity.service as any)?.id===root.entity.id
  &&grants.some(g=>grantMatchesEntity(g,'routes',g.action,{clusterId,workspaceId:wid,entityType:'routes',entity:node.entity})));
 return false;
}
