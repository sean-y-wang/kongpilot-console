import type { WorkflowScheduleCandidateReadResource as Resource } from './workflow-schedule-candidate-read.types';

const key=(resource:Pick<Resource,'clusterId'|'workspaceId'|'path'>)=>`${resource.clusterId}:${resource.workspaceId}:${resource.path}`;
/** These sets/cursors are provider-owned actual accepted responses, never a
 * client's list, Parent DTO, historical snapshot or guessed HTTP status. */
export function hasObservedAbsenceWitness(resource:Readonly<Resource>,resources:readonly Readonly<Resource>[],
 trueEofs:ReadonlySet<string>,presentPoints:ReadonlySet<string>,cursors:ReadonlyMap<string,{complete:boolean;ids:ReadonlySet<string>}>,observedAbsences?:ReadonlySet<string>):boolean{
 if(resource.kind!=='point'||resource.allowAbsent!==true)return false;
 const parts=resource.path.split('/').filter(Boolean);
 if(parts.at(-1)!==resource.entityId)return false;
 const collectionPath=`/${parts.slice(0,-1).join('/')}`;
 const sameScope=(r:Readonly<Resource>)=>r.clusterId===resource.clusterId&&r.workspaceId===resource.workspaceId;
 const collection=resources.find(r=>sameScope(r)&&r.kind==='collection'&&r.path===collectionPath&&r.entityType===resource.entityType
  &&(r.parentId??null)===(resource.parentId??null));
 if(collection){const cursor=cursors.get(key(collection));
  if(trueEofs.has(key(collection))&&cursor?.complete&&!cursor.ids.has(resource.entityId!))return true;}
 if(parts.length!==4||!['consumers','upstreams'].includes(parts[0])||resource.parentId!==parts[1])return false;
 const parent=resources.find(r=>sameScope(r)&&r.kind==='point'&&r.path===`/${parts[0]}/${parts[1]}`&&r.entityType===parts[0]
  &&r.entityId===resource.parentId&&!r.parentId);
 if(parent&&presentPoints.has(key(parent)))return true;
 // A declared future-parent create must itself have a genuine observed point
 // absence and its root collection EOF. Its descriptor is fixed by Material.
 const parentCollection=resources.find(r=>sameScope(r)&&r.kind==='collection'&&r.path===`/${parts[0]}`&&r.entityType===parts[0]);
 const cursor=parentCollection&&cursors.get(key(parentCollection));
 return!!parent&&parent.allowAbsent===true&&!!observedAbsences?.has(key(parent))&&!!parentCollection
  &&trueEofs.has(key(parentCollection))&&!!cursor?.complete&&!cursor.ids.has(resource.parentId!);
}

/** Kong 1.5's point NotFound object. A JSON entity, list, primitive or parsing
 * fallback cannot be treated as a missing configuration object. */
export function isKongPointNotFound(response:unknown):boolean{
 return!!response&&typeof response==='object'&&!Array.isArray(response)&&Object.keys(response).length===1
  &&Object.hasOwn(response,'message')&&typeof (response as any).message==='string'&&/^not found$/i.test((response as any).message);
}
