import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';

export const AUTHORITY_PHASES=['bootstrap','prepare','revoke','verify','timer-observe','restore'];
export const AUTHORITY_NATIVE_MODULES=['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis'];
const uuid=value=>typeof value==='string'&&/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
export const authorityBodyHash=value=>createHash('sha256').update(JSON.stringify(value)??'null').digest('hex');
export function authorityPhase(args){assert(args.length===2&&args[0]==='--phase'&&AUTHORITY_PHASES.includes(args[1]),'FIXED_AUTHORITY_PHASE_REQUIRED');return args[1];}
export function authorityPermissions(clusterId,workspaceId){
 assert(uuid(clusterId)&&uuid(workspaceId),'EXACT_AUTHORITY_WORKSPACE_REQUIRED');
 return [...AUTHORITY_NATIVE_MODULES.flatMap(module=>['read','write'].map(action=>({module,action}))),
  ...['clusters','workspaces','annotations','mutations','secrets','drift'].map(module=>({module,action:'read'})),
  ...['snapshots','governance','promote'].flatMap(module=>['read','write'].map(action=>({module,action})))
 ].map(value=>({...value,scope_type:'workspace',cluster_id:clusterId,workspace_id:workspaceId,scope_values:[workspaceId]}));
}
export function assertAuthorityInitialLogin(user,ownerId){
 assert(uuid(ownerId)&&user?.id===ownerId&&user.superAdmin===false,'ACTUAL_NON_SUPER_INITIAL_LOGIN_REQUIRED');
 assert(typeof user.forcePasswordChange==='boolean','ACTUAL_INITIAL_PASSWORD_POLICY_BOOLEAN_REQUIRED');
 // Administrator-created accounts legitimately follow the active policy's
 // true/false setting. The separate real password change and second login
 // remain required regardless of this observed flag; no flag is rewritten.
 return user.forcePasswordChange;
}
export function assertAuthorityBinding(value,{userId,roleId,roleName,clusterId,workspaceId,status,previousRevision}){
 assert(uuid(value?.id)&&value.user_id===userId&&value.role_id===roleId&&value.role_name===roleName,'EXACT_ACTUAL_AUTHORITY_BINDING_REQUIRED');
 assert(value.cluster_id===clusterId&&value.workspace_id===workspaceId&&value.status===status,'EXACT_ACTUAL_AUTHORITY_BINDING_SCOPE_REQUIRED');
 assert(Number.isSafeInteger(value.revision)&&value.revision>=1,'CURRENT_AUTHORITY_BINDING_REVISION_REQUIRED');
 if(previousRevision!==undefined)assert.equal(value.revision,previousRevision+1,'ACTUAL_AUTHORITY_BINDING_NEXT_REVISION_REQUIRED');
 return value;
}
export function assertAuthorityBlockedTimer(entity,fixture){
 assert(entity?.id===fixture.id&&entity.ownerUserId===fixture.ownerUserId&&entity.currentVersion===fixture.currentVersion,'ORIGINAL_AUTHORITY_TIMER_IDENTITY_REQUIRED');
 assert(entity.state==='active'&&entity.enabled===true&&entity.executionBlocked===true&&entity.blockingState==='paused_authority','CURRENT_VERSION_AUTHORITY_TIMER_BLOCK_REQUIRED');
 assert(uuid(entity.blockingOccurrenceId)&&entity.blockingVersion===fixture.currentVersion&&entity.blockingReasonCode==='PERMISSION_DENIED','EXACT_AUTHORITY_TIMER_BLOCKING_OCCURRENCE_REQUIRED');
 assert.equal(new Date(entity.scheduledAt).toISOString(),fixture.nextRunAt,'ACTUAL_ORIGINAL_TIMER_DUE_REQUIRED');
 assert(Date.now()>=Date.parse(fixture.nextRunAt),'NATURAL_AUTHORITY_TIMER_DUE_REQUIRED');
 return entity;
}
/** Intent keys precede actual HTTP WAL packets. An unknown/failed old request
 * cannot be hidden behind a replacement label or a new idempotency key. */
export function authorityLedger(h){
 const state=h.state.authorityAcceptance??={version:1,phases:{},inputs:{},intents:{},checks:[]};assert.equal(state.version,1);
 const freeze=(name,factory)=>{if(!Object.hasOwn(state.inputs,name)){state.inputs[name]=structuredClone(factory());h.save();}return state.inputs[name];};
 const once=async(label,session,path,method,body,expected=[200,201])=>{
  const actorId=session?.user?.id??null,bodyHash=authorityBodyHash(body);
  const intent=state.intents[label]??={key:randomUUID(),actorId,path,method,bodyHash};h.save();
  assert.deepEqual({actorId:intent.actorId,path:intent.path,method:intent.method,bodyHash:intent.bodyHash},{actorId,path,method,bodyHash},'ORIGINAL_AUTHORITY_INTENT_REQUIRED');
  let matches=h.state.requests.filter(p=>p.key===intent.key);assert(matches.length<=1,'ONE_ORIGINAL_AUTHORITY_PACKET_REQUIRED');
  if(!matches.length){h.assertWritable();await h.request(session,path,method,body,{key:intent.key,expected});matches=h.state.requests.filter(p=>p.key===intent.key);}
  assert.equal(matches.length,1,'EXACT_ORIGINAL_AUTHORITY_PACKET_REQUIRED');const packet=matches[0];
  assert(packet.actorId===actorId&&packet.path===path&&packet.method===method&&packet.bodyHash===bodyHash,'ORIGINAL_AUTHORITY_PACKET_BINDING_REQUIRED');
  assert(packet.state==='response_observed'&&expected.includes(packet.status),'ORIGINAL_AUTHORITY_RESPONSE_REQUIRED_NO_REPLAY');
  if(packet.label!==undefined)assert.equal(packet.label,label,'ORIGINAL_AUTHORITY_LABEL_REQUIRED');else{packet.label=label;h.save();}
  return{data:packet.responseData,status:packet.status,requestId:packet.requestId,packet};
 };
 const packet=label=>{const intent=state.intents[label];assert(intent,'ORIGINAL_AUTHORITY_INTENT_REQUIRED');const matches=h.state.requests.filter(p=>p.key===intent.key);assert.equal(matches.length,1);return matches[0];};
 const check=(condition,name,facts={})=>{assert(condition,name);state.checks.push({passed:true,name,...facts});h.save();};
 return{state,freeze,once,packet,check};
}
