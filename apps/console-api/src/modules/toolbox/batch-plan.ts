import { BadRequestException } from '@nestjs/common';
import type { CaptureGraph, CaptureObject } from '../configuration/configuration.types';
import type { NormalizedTransferGraph, TransferObject } from '../config-transfer';
import { encodeTag } from '../../infrastructure/kong/tags';
import { TOOLBOX_ENTITIES, toolboxId, toolboxObject } from './toolbox-input';

export interface ToolboxBatchSelection { action:'tags'|'plugin-enabled'|'delete'; roots:Array<{type:string;id:string}>; tags?:string[]; enabled?:boolean; }
export function validateBatchSelection(value:unknown):ToolboxBatchSelection{
  const input=toolboxObject(value,['action','roots','tags','enabled']);
  if(!['tags','plugin-enabled','delete'].includes(input.action)||!Array.isArray(input.roots)||!input.roots.length||input.roots.length>50)throw new BadRequestException({code:'INVALID_BATCH_SELECTION'});
  const roots=input.roots.map((value:unknown)=>{const root=toolboxObject(value,['type','id']);if(!(TOOLBOX_ENTITIES as readonly unknown[]).includes(root.type))throw new BadRequestException({code:'INVALID_BATCH_ROOT_TYPE'});return{type:root.type as string,id:toolboxId(root.id)};});
  if(new Set(roots.map((root:{type:string;id:string})=>`${root.type}:${root.id}`)).size!==roots.length)throw new BadRequestException({code:'DUPLICATE_BATCH_ROOT'});
  if(input.action==='tags'&&(!Array.isArray(input.tags)||!input.tags.length||input.tags.length>32||input.tags.some((tag:unknown)=>typeof tag!=='string'||tag.length>80||/^workspace:|^kos-ws-|^kos-tag-/i.test(tag))))throw new BadRequestException({code:'INVALID_BATCH_TAGS',message:'批量操作只添加普通业务标签，工作区标签须通过迁移流程修改'});
  if(input.action==='plugin-enabled'&&(typeof input.enabled!=='boolean'||roots.some((root:{type:string})=>root.type!=='plugins')))throw new BadRequestException({code:'INVALID_PLUGIN_BATCH'});
  if(input.action!=='tags'&&input.tags!==undefined||input.action!=='plugin-enabled'&&input.enabled!==undefined)throw new BadRequestException({code:'INVALID_BATCH_FIELDS'});
  return{action:input.action,roots,...(input.action==='tags'?{tags:input.tags}:{}),...(input.action==='plugin-enabled'?{enabled:input.enabled}:{})};
}
function ownedChild(parent:CaptureObject,child:CaptureObject):boolean{
  if(parent.entityType==='services')return child.entityType==='routes'&&((child.payload.service as any)?.id===parent.nativeId)||child.entityType==='plugins'&&((child.payload.service as any)?.id===parent.nativeId);
  if(parent.entityType==='routes')return child.entityType==='plugins'&&((child.payload.route as any)?.id===parent.nativeId);
  if(parent.entityType==='consumers')return child.entityType==='credentials'&&child.parentId===parent.nativeId||child.entityType==='plugins'&&((child.payload.consumer as any)?.id===parent.nativeId);
  if(parent.entityType==='upstreams')return child.entityType==='targets'&&child.parentId===parent.nativeId;
  return parent.entityType==='certificates'&&child.entityType==='snis'&&((child.payload.certificate as any)?.id===parent.nativeId);
}
/** Build an exact selected change set. Native permission checks, recovery,
 * managed boundaries and dependency checks remain in the M8 compiler/executor. */
export function toolboxBatchTarget(graph:CaptureGraph,selection:ToolboxBatchSelection,codes:Record<string,string>):NormalizedTransferGraph{
  const selected=new Set(selection.roots.map(root=>`${root.type}:${root.id}`));
  for(const root of selection.roots)if(!graph.objects.some(object=>object.entityType===root.type&&object.nativeId===root.id&&object.affected&&!object.referenceOnly&&object.objectWorkspaceId===graph.scope.workspaceId))throw new BadRequestException({code:'BATCH_ROOT_NOT_IN_SCOPE'});
  const removed=new Set<string>();
  if(selection.action==='delete'){
    for(const object of graph.objects)if(selected.has(`${object.entityType}:${object.nativeId}`))removed.add(object.objectKey);
    let changed=true;while(changed){changed=false;for(const child of graph.objects){if(removed.has(child.objectKey)||!child.affected||child.referenceOnly)continue;
      if(graph.objects.some(parent=>removed.has(parent.objectKey)&&ownedChild(parent,child))){if(child.objectWorkspaceId!==graph.scope.workspaceId)throw new BadRequestException({code:'BATCH_FOREIGN_DEPENDENCY'});removed.add(child.objectKey);changed=true;}
    }}
  }
  const objects:TransferObject[]=graph.objects.filter(object=>object.affected&&!object.referenceOnly&&!removed.has(object.objectKey)&&(selection.action==='delete'||selected.has(`${object.entityType}:${object.nativeId}`))).map(object=>({
    objectKey:object.objectKey,entityType:object.entityType,nativeId:object.nativeId,parentType:object.parentType??undefined,parentId:object.parentId??undefined,credentialKind:object.credentialKind??undefined,
    objectWorkspaceId:object.objectWorkspaceId,dependencies:object.dependencies,sourcePath:'toolbox-explicit-selection',
    payload:{id:object.nativeId,...(selection.action==='tags'?{tags:[...new Set([...((object.payload.tags??[]) as string[]),...selection.tags!.map(encodeTag)])]}:selection.action==='plugin-enabled'?{enabled:selection.enabled}:{} )},
    ...(object.credentialKind==='basic-auth'?{passwordIntent:'keep' as const}:{}),
  }));
  return{scope:graph.scope,schemas:graph.schemas,objects,workspaceCodesById:codes,semantics:'merge'};
}
