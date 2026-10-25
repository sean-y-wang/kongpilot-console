import { isIP } from 'node:net';
import { assertKongPath } from '../../infrastructure/kong/policy';
import type { WorkflowScheduleCandidateReadResource as Resource } from './workflow-schedule-candidate-read.types';

const uuid=/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
/** A fixed compiler selector, never an SDK observation or an authority. UUID
 * shaped names are ambiguous with Kong 1.5's ID-or-name lookup and therefore
 * cannot be used as proof of a missing upstream name. */
export function validServiceHostReference(value:unknown):value is NonNullable<Resource['serviceHostReference']>{
 if(!value||typeof value!=='object'||Array.isArray(value))return false;
 const ref=value as any;
 if(Object.keys(ref).length!==2||!Object.hasOwn(ref,'host')||!Object.hasOwn(ref,'serviceIds')||typeof ref.host!=='string'||!ref.host.length
  // Kong 1.5's utils.check_hostname has no DNS label/total-length cap.
  // Preserve its name grammar, including leading-dash punycode, without
  // normalizing the exact sealed name or allowing an encoded path segment.
  ||/[^a-z\d_.-]/i.test(ref.host)||ref.host.split('.').some((label:string)=>!label||label.endsWith('-'))||/^[\d.]+$/.test(ref.host)
  ||isIP(ref.host)||uuid.test(ref.host)||!Array.isArray(ref.serviceIds)||!ref.serviceIds.length||ref.serviceIds.length>500
  ||ref.serviceIds.some((id:unknown,i:number)=>typeof id!=='string'||!uuid.test(id)||i>0&&ref.serviceIds[i-1]>=id))return false;
 try{assertKongPath('GET',`/upstreams/${encodeURIComponent(ref.host)}`);return true;}catch{return false;}
}
export function isServiceHostReferencePoint(resource:Readonly<Resource>):boolean{
 const ref=resource.serviceHostReference;
 return validServiceHostReference(ref)&&resource.kind==='point'&&resource.entityType==='upstreams'&&resource.entityId===undefined
  &&resource.parentId===undefined&&resource.query===undefined&&resource.secrets===false&&resource.allowAbsent===true&&resource.required===false
  &&resource.path===`/upstreams/${encodeURIComponent(ref.host)}`;
}
export function isServiceHostTargetCollection(resource:Readonly<Resource>):boolean{
 return validServiceHostReference(resource.serviceHostReference)&&resource.kind==='collection'&&resource.entityType==='targets'
  &&uuid.test(resource.parentId??'')&&resource.entityId===undefined&&resource.secrets===false&&resource.allowAbsent===undefined&&resource.required===false
  &&resource.path===`/upstreams/${resource.parentId}/targets`&&resource.query?.size===100&&Object.keys(resource.query).length===1;
}
