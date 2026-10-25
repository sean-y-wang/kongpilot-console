import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID} from 'node:crypto';
import {ForbiddenException,NotFoundException} from '@nestjs/common';
import {SecretService,canonicalJson} from '../../apps/console-api/src/infrastructure/secret.service';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {EntityChangeIntentsService} from '../../apps/console-api/src/modules/workflows/entity-change-intents.service';
import {EntityChangeIntentsController} from '../../apps/console-api/src/modules/workflows/entity-change-intents.controller';
import {entityChangeIntentAad} from '../../apps/console-api/src/modules/workflows/entity-change-workflow';
const PATH_METADATA='path',METHOD_METADATA='method';

/** SOURCE fixture: real Core Context private ALS/frame lifecycle and real
 * AEAD/HMAC. SQL, grants and compiler are controlled contract adapters. No
 * actual DB/HTTP/Redis/native execution or commercial acceptance is claimed. */
function fixture(resource:'service'|'credential-create'|'credential-update'|'credential-delete'='service'){
 const context=new KongExecutionContextService(),secrets=new SecretService(),cid=randomUUID(),wid=randomUUID(),uid=randomUUID(),sid=randomUUID(),nativeId=randomUUID(),consumerId=randomUUID(),definitionId=randomUUID();
 const actor:any={user:{id:uid,username:'owner',superAdmin:false},workspaceId:wid,idempotencyKey:'actual-original-prepare-key',requestId:randomUUID()};
 const request:any=resource==='service'?{kind:'entity',action:'update',entityType:'services',entityId:nativeId,body:{host:'new.internal'}}
  :resource==='credential-delete'?{kind:'recycle',action:'delete',entityType:'credentials',entityId:nativeId,parentId:consumerId,credentialKind:'key-auth',confirmed:true,confirm_name:nativeId}
  :{kind:'credential',action:resource==='credential-create'?'create':'update',consumerId,credentialKind:'key-auth',...(resource==='credential-update'?{credentialId:nativeId}:{}),body:{key:'source-private-credential'}};
 const action=resource==='credential-create'?'create':resource==='credential-delete'?'delete':'update',type=resource==='service'?'services':'credentials',path=type==='services'?`/services/${nativeId}`:`/consumers/${consumerId}/key-auth${action==='create'?'':`/${nativeId}`}`;
 const before=action==='create'?null:{id:nativeId,...(type==='services'?{host:'old.internal'}:{consumer:{id:consumerId},key:'old-source-private-credential'}),tags:['kos-ws-pay']},body=action==='delete'?undefined:action==='create'?{...request.body,id:nativeId}:request.body;
 const packet:any={key:'packet-1',order:1,dependencies:[],method:action==='create'?'POST':action==='delete'?'DELETE':'PATCH',canonicalPath:path,nativeType:type,nativeId,
  ...(type==='credentials'?{parentId:consumerId,credentialKind:'key-auth'}:{}),permissionAction:action==='delete'?'delete':'write',mutationAction:action,body,before,bodyHmac:secrets.fingerprint(body??null),beforeHmac:secrets.fingerprint(before)};
 const base:any={version:1,clusterId:cid,workspaceId:wid,requesterId:uid,permissionVersion:'original-material-pv',scope:{transportScope:'a'.repeat(64),clusterRevision:1,workspaceRevision:1,kongVersion:'1.5.1',adapter:'kong-1.5'},request,prerequisites:[],schemas:[],packets:[packet],metadataObligations:[],
  recovery:{state:'baseline-required',blockerCodes:['EXECUTION_BASELINE_REQUIRED'],objects:[]},impact:{version:1,keyId:'b'.repeat(64),keys:[],domains:[],wildcards:[]}},prepared:any={...base,changeDigest:secrets.fingerprint(base)};
 const review:any={version:1,clusterId:cid,workspaceId:wid,changeDigest:prepared.changeDigest,changes:[{entityType:type,nativeId,action,before:secrets.redact(before),after:secrets.redact(body??null)}],impact:{changedObjects:1,nativePackets:1,traffic:null,trafficAvailability:'unavailable',globalPlugin:false},recovery:prepared.recovery};
 const state:any={intent:null,version:null,packets:[],submission:null,credentialEpoch:'1',permissionVersion:'current-grant-pv',sessionRevoked:false,currentSessionId:sid,sessionEpoch:'1',sessionUserId:uid,sessionExpiresAt:new Date(Date.now()+3600000).toISOString(),scopeAllowed:true,subjectAllowed:true,lookupPointer:null,
  definition:{id:definitionId,version:1,policyHash:secrets.fingerprint({version:1,mode:'single'})}};
 const clone=(v:any)=>v?structuredClone(v):v,trace:string[]=[];
 const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{trace.push(sql);
  if(sql.includes('FROM auth_sessions'))return !state.sessionRevoked&&p[0]===state.currentSessionId&&p[1]===state.sessionUserId&&state.sessionEpoch===state.credentialEpoch?{id:state.currentSessionId,credential_epoch:state.sessionEpoch,expires_at:state.sessionExpiresAt}:null;
  if(sql.includes('FROM iam_epoch'))return{version:1};if(sql.includes('FROM users'))return{credential_epoch:state.credentialEpoch};
  if(sql.includes('FROM workflow_definition_versions'))return{approval_format:1,policy:{intentTtlHours:24}};
  if(sql.includes('FROM clusters'))return{execution_mode:'approval',revision:1};
  if(sql.includes('FROM entity_change_intent_versions'))return state.version&&p[0]===state.version.intent_id&&p[1]===cid&&p[2]===wid&&p[3]===1?clone(state.version):null;
  if(sql.includes('FROM entity_change_intents')){
   if(sql.includes('requester_id=$1 AND cluster_id=$2')){if(state.lookupPointer)return clone(state.lookupPointer);return state.intent&&p[0]===uid&&p[1]===cid&&p[2]===wid&&p[3]===state.intent.prepare_key?clone(state.intent):null;}
   if(sql.includes('requester_id=$1'))return state.intent&&p[0]===uid&&p[1]===state.intent.prepare_key?clone(state.intent):null;
   return state.intent&&p[0]===state.intent.id&&p[1]===cid&&p[2]===wid?clone(state.intent):null;
  }
  if(sql.includes('FROM entity_change_submissions'))return clone(state.submission);throw Error('Unmodeled SOURCE SELECT '+sql);
 }),query:vi.fn(async(sql:string)=>{trace.push(sql);if(sql.includes('FROM entity_change_intent_packets'))return clone(state.packets);throw Error('Unmodeled SOURCE query');}),
 exec:vi.fn(async(sql:string,p:any[])=>{trace.push(sql);
  if(sql.startsWith('INSERT INTO entity_change_intents'))state.intent={id:p[0],cluster_id:p[1],workspace_id:p[2],requester_id:p[3],credential_epoch:p[4],prepare_key:p[5],request_hmac:p[6],issued_at:p[7],expires_at:p[8]};
  else if(sql.startsWith('INSERT INTO entity_change_intent_versions'))state.version={cluster_id:p[0],workspace_id:p[1],intent_id:p[2],intent_revision:1,requester_id:p[3],credential_epoch:p[4],issued_at:p[5],expires_at:p[6],execution_mode:p[7],definition_id:p[8],definition_version:p[9],policy_hash:p[10],change_digest:p[11],material_hmac:p[12],packet_manifest_hmac:p[13],packet_count:p[14],packet_manifest:JSON.parse(p[15]),envelope_ciphertext:p[16],safe_review:JSON.parse(p[17])};
  else if(sql.startsWith('INSERT INTO entity_change_intent_packets'))state.packets.push({material_hmac:p[3],change_digest:p[4],packet_manifest_hmac:p[5],packet_key:p[6],packet_order:p[7],dependencies:p[8],method:p[9],path_hmac:p[10],native_type:p[11],native_id:p[12],parent_id:p[13],credential_kind:p[14],original_native_id:p[15],mutation_action:p[16],permission_action:p[17],body_hmac:p[18],before_hmac:p[19]});
  else throw Error('Unexpected SOURCE write '+sql);return 1;
 }),transaction:vi.fn(async(fn:any)=>fn(db))};
 const compiler:any={prepare:vi.fn(async()=>prepared),project:vi.fn(async()=>review),projectStored:vi.fn(async()=>review),revalidateStored:vi.fn()},plans:any={definitions:vi.fn(),definition:vi.fn(async()=>state.definition),persist:vi.fn()},
 authz:any={permissionVersion:vi.fn(async()=>state.permissionVersion),assertCluster:vi.fn(async(user:any,c:any,module:any,a:any,w:any)=>{if(user.id!==uid||c!==cid||w!==wid||!state.scopeAllowed)throw new ForbiddenException({code:'SCOPE_DENIED'});})},
 redis:any={withLock:vi.fn(async(_key:any,fn:any)=>fn()),assertLeaseOwnership:vi.fn()},audit:any={append:vi.fn()};
 const subject=vi.fn(async(_envelope:any,id:string,action:string)=>{if(id!==uid||!state.subjectAllowed)throw new ForbiddenException({code:'SUBJECT_DENIED'});});
 const service=new EntityChangeIntentsService(db,secrets,redis,compiler,plans,{} as any,{} as any,audit,authz,context);service.installSubjectPolicy({assertSubject:subject,verifyReviewer:vi.fn()});
 const run=<T>(fn:()=>Promise<T>,httpUser=actor.user,httpSid:string|undefined=sid)=>context.runHttp({requestId:actor.requestId},async()=>{context.bindHttpActor(httpUser,httpSid);const close=context.captureHttpCloser();try{return await fn();}finally{close();}});
 const prepare=()=>run(()=>service.prepare(cid,{change:request},actor)),lookup=(key=actor.idempotencyKey,caller=actor)=>run(()=>service.byPrepareKey(cid,key,caller));
 return{context,secrets,cid,wid,uid,sid,nativeId,consumerId,actor,request,prepared,review,state,db,compiler,plans,authz,redis,audit,subject,trace,service,run,prepare,lookup};
}
beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','ab'.repeat(32));});afterEach(()=>{vi.unstubAllEnvs();vi.restoreAllMocks();});
describe('M11 original prepare-key lookup SOURCE authority',()=>{
 it('registers the exact static GET path before :id and preserves all old routes',()=>{const p=EntityChangeIntentsController.prototype;expect(Reflect.getMetadata(PATH_METADATA,p.byPrepareKey)).toBe('by-prepare-key/:key');expect(Reflect.getMetadata(METHOD_METADATA,p.byPrepareKey)).toBe(0);
  expect(Object.getOwnPropertyNames(p).indexOf('byPrepareKey')).toBeLessThan(Object.getOwnPropertyNames(p).indexOf('get'));expect(Reflect.getMetadata(PATH_METADATA,p.get)).toBe(':id');expect(Reflect.getMetadata(PATH_METADATA,p.prepare)).toBe('prepare');});
 it('recovers exactly the original encrypted intent, safe review and material with no writes or fresh-before calls',async()=>{const f=fixture(),original=await f.prepare(),cipher=f.state.version.envelope_ciphertext,material=canonicalJson(f.prepared),writes=f.db.exec.mock.calls.length;
  const result:any=await f.lookup();expect(result).toMatchObject({id:original.id,revision:original.revision,materialHmac:original.materialHmac,nativeExecutionAvailable:false,workflowId:null});expect(result.review).toEqual(f.review);
  expect(f.db.exec).toHaveBeenCalledTimes(writes);expect(f.compiler.prepare).toHaveBeenCalledTimes(1);expect(f.compiler.revalidateStored).not.toHaveBeenCalled();expect(f.plans.persist).not.toHaveBeenCalled();expect(f.state.version.envelope_ciphertext).toBe(cipher);expect(canonicalJson(f.prepared)).toBe(material);expect(f.context.peek()).toBeNull();});
 it('returns only a current not-observed observation, never retry authority, for a genuinely absent original key',async()=>{const f=fixture(),result=await f.lookup();expect(result).toEqual({state:'not_prepared',clusterId:f.cid,workspaceId:f.wid,idempotencyKey:f.actor.idempotencyKey,intentId:null,nativeExecutionAvailable:false,retryWriteAllowed:false,originalOutcome:'not_observed'});
  expect(f.authz.assertCluster).toHaveBeenCalledTimes(2);expect(f.db.exec).not.toHaveBeenCalled();expect(f.compiler.prepare).not.toHaveBeenCalled();expect(f.compiler.projectStored).not.toHaveBeenCalled();});
 it.each(['CID','WID','actor'])('denies a caller changing %s before original-key disclosure',async part=>{const f=fixture();await f.prepare();const caller=part==='actor'?{...f.actor,user:{...f.actor.user,id:randomUUID()}}:part==='WID'?{...f.actor,workspaceId:randomUUID()}:f.actor;
  const cid=part==='CID'?randomUUID():f.cid;await expect(f.run(()=>f.service.byPrepareKey(cid,f.actor.idempotencyKey,caller))).rejects.toThrow();expect(f.compiler.projectStored).not.toHaveBeenCalled();});
 it.each(['revoked','foreign user','stale epoch','expired','wrong SID','no SID'])('requires actual current %s session even for absence',async condition=>{const f=fixture();if(condition==='revoked')f.state.sessionRevoked=true;if(condition==='foreign user')f.state.sessionUserId=randomUUID();if(condition==='stale epoch')f.state.sessionEpoch='2';if(condition==='expired')f.state.sessionExpiresAt=new Date(Date.now()-1).toISOString();
  const sid=condition==='wrong SID'?randomUUID():f.sid;
  const operation=condition==='no SID'?f.context.runHttp({},async()=>{f.context.bindHttpActor(f.actor.user);return f.service.byPrepareKey(f.cid,f.actor.idempotencyKey,f.actor);}):f.run(()=>f.service.byPrepareKey(f.cid,f.actor.idempotencyKey,f.actor),f.actor.user,sid);
  await expect(operation).rejects.toThrow();expect(f.trace.some(q=>q.includes('FROM entity_change_intents'))).toBe(false);});
 it('does not manufacture Context or adopt a caller actor when the optional provider is absent',async()=>{const f=fixture(),closed=new EntityChangeIntentsService(f.db,f.secrets,f.redis,f.compiler,f.plans,{} as any,{} as any,f.audit,f.authz);closed.installSubjectPolicy({assertSubject:f.subject,verifyReviewer:vi.fn()});
  await expect(f.run(()=>closed.byPrepareKey(f.cid,f.actor.idempotencyKey,f.actor))).rejects.toThrow();expect(f.db.one).not.toHaveBeenCalled();});
 it('closes a genuine original entity namespace with NULL SID; no HTTP adoption or SQL lookup occurs',async()=>{const f=fixture(),handle=Object.freeze({}),proof:any=Object.freeze({version:1,origin:'scheduled-entity',sessionId:null,actor:Object.freeze({...f.actor.user}),clusterId:f.cid,workspaceId:f.wid,expiresAt:new Date(Date.now()+60000).toISOString()});
  f.context.installEntityScheduledNamespacePolicy({verifyHandle:async h=>{if(h!==handle)throw Error('foreign original');return proof;},assertLive:h=>{if(h!==handle)throw Error('foreign original');}});
  await expect(f.context.runEntityScheduledNamespace(handle,()=>f.service.byPrepareKey(f.cid,f.actor.idempotencyKey,f.actor))).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_PREPARE_LOOKUP_HTTP_REQUIRED'}});expect(f.db.one).not.toHaveBeenCalled();expect(f.context.peek()).toBeNull();});
 it('closes a genuine original business namespace with NULL SID',async()=>{const f=fixture(),handle=Object.freeze({}),proof:any=Object.freeze({version:1,origin:'scheduled-workflow',sessionId:null,actor:Object.freeze({...f.actor.user}),clusterId:f.cid,workspaceId:f.wid,kind:'configuration_v2',expiresAt:new Date(Date.now()+60000).toISOString()});
  f.context.installWorkflowScheduledNamespacePolicy({verifyHandle:async h=>{if(h!==handle)throw Error('foreign original');return proof;},assertLive:h=>{if(h!==handle)throw Error('foreign original');}});
  await expect(f.context.runWorkflowScheduledNamespace(handle,()=>f.service.byPrepareKey(f.cid,f.actor.idempotencyKey,f.actor))).rejects.toThrow();expect(f.db.one).not.toHaveBeenCalled();});
 it('cannot turn a 403, 404 or SQL failure into not-observed retry rights',async()=>{for(const kind of ['scope','404','SQL']){const f=fixture();if(kind==='scope')f.state.scopeAllowed=false;else f.db.one.mockImplementation(async(sql:string)=>{if(sql.includes('FROM auth_sessions'))return{id:f.sid,credential_epoch:'1',expires_at:f.state.sessionExpiresAt};if(sql.includes('FROM users'))return{credential_epoch:'1'};throw kind==='404'?new NotFoundException():Error('SQL unavailable');});
   await expect(f.lookup()).rejects.toThrow();expect(f.compiler.projectStored).not.toHaveBeenCalled();}});
 it.each(['','short','white space original key','../key','x'.repeat(129)])('rejects malformed original key %s',async key=>{const f=fixture();await expect(f.lookup(key)).rejects.toThrow();expect(f.db.one).not.toHaveBeenCalled();});
 it.each(['cluster_id','workspace_id','requester_id','prepare_key','request_hmac'])('rejects wrong original pointer %s before projection',async field=>{const f=fixture();await f.prepare();f.state.lookupPointer={...f.state.intent,[field]:field==='request_hmac'?'bad':randomUUID()};await expect(f.lookup()).rejects.toThrow();expect(f.compiler.projectStored).not.toHaveBeenCalled();});
 it('authenticates the original AAD and does not substitute a ciphertext from another intention',async()=>{const f=fixture();await f.prepare();const value=f.secrets.decrypt(f.state.version.envelope_ciphertext,entityChangeIntentAad(f.cid,f.wid,f.state.intent.id,1));f.state.version.envelope_ciphertext=f.secrets.encrypt(value,entityChangeIntentAad(f.cid,f.wid,randomUUID(),1));
  await expect(f.lookup()).rejects.toThrow();expect(f.compiler.projectStored).not.toHaveBeenCalled();});
 it.each(['native_id','body_hmac','before_hmac','material_hmac'])('keeps substituted frozen packet %s closed',async field=>{const f=fixture();await f.prepare();f.state.packets[0][field]='bad';await expect(f.lookup()).rejects.toThrow();expect(f.compiler.projectStored).not.toHaveBeenCalled();});
 it('requires current sealed-subject read grants, not merely coarse workflows scope',async()=>{const f=fixture();await f.prepare();f.state.subjectAllowed=false;await expect(f.lookup()).rejects.toMatchObject({response:{code:'SUBJECT_DENIED'}});expect(f.compiler.projectStored).not.toHaveBeenCalled();});
 it.each(['PV','session','scope','subject'])('rechecks late %s changes before returning existing sensitive projection',async change=>{const f=fixture();await f.prepare();f.compiler.projectStored.mockImplementation(async()=>{if(change==='PV')f.state.permissionVersion='revoked-current-pv';if(change==='session')f.state.sessionRevoked=true;if(change==='scope')f.state.scopeAllowed=false;if(change==='subject')f.state.subjectAllowed=false;return f.review;});
  await expect(f.lookup()).rejects.toThrow();});
 it('retains real submitted workflow identity and disables another submission',async()=>{const f=fixture(),old=await f.prepare(),workflowId=randomUUID();f.state.submission={workflow_id:workflowId};const result:any=await f.lookup();expect(result.id).toBe(old.id);expect(result.workflowId).toBe(workflowId);expect(result.capabilities.submit).toBe(false);expect(f.plans.persist).not.toHaveBeenCalled();});
 it('can read an expired original intention without extending expiry or authorizing submission',async()=>{const f=fixture(),old=await f.prepare();vi.spyOn(Date,'now').mockReturnValue(Date.parse(old.expiresAt)+1);f.state.sessionExpiresAt=new Date(Date.now()+3600000).toISOString();const result:any=await f.lookup();expect(result.expiresAt).toBe(old.expiresAt);expect(result.capabilities.submit).toBe(false);});
 it('keeps a new genuine current SID and current credential epoch for historical READ without borrowing original write authority',async()=>{const f=fixture(),old=await f.prepare(),cipher=f.state.version.envelope_ciphertext,freshSid=randomUUID();
  f.state.currentSessionId=freshSid;f.state.credentialEpoch='2';f.state.sessionEpoch='2';f.state.permissionVersion='fresh-current-grant-pv';
  const result:any=await f.run(async()=>{const value=await f.service.byPrepareKey(f.cid,f.actor.idempotencyKey,f.actor);expect(f.context.current().sessionId).toBe(freshSid);return value;},f.actor.user,freshSid);
  expect(result.id).toBe(old.id);expect(result.materialHmac).toBe(old.materialHmac);expect(result.capabilities.submit).toBe(false);expect(f.state.version.envelope_ciphertext).toBe(cipher);expect(f.plans.persist).not.toHaveBeenCalled();
  f.state.subjectAllowed=false;await expect(f.run(()=>f.service.byPrepareKey(f.cid,f.actor.idempotencyKey,f.actor),f.actor.user,freshSid)).rejects.toThrow();});
});
describe('sealed credential subject public tuple',()=>{
 it.each(['credential-create','credential-update','credential-delete'] as const)('projects only original UUID and enum fields for %s',async resource=>{const f=fixture(resource),first=await f.prepare(),get:any=await f.run(()=>f.service.get(f.cid,first.id,f.actor)),lookup:any=await f.lookup(),expected={consumerId:f.consumerId,credentialKind:'key-auth',action:resource.split('-')[1],...(resource==='credential-create'?{}:{credentialId:f.nativeId})};
  expect(first.credentialSubject).toEqual(expected);expect(get.credentialSubject).toEqual(expected);expect(lookup.credentialSubject).toEqual(expected);expect(Object.keys(lookup.credentialSubject).sort()).toEqual(Object.keys(expected).sort());expect(JSON.stringify(lookup)).not.toContain('source-private-credential');});
 it('does not project a credential subject for a different entity or generic batch',async()=>{const f=fixture();const result=await f.prepare();expect(result).not.toHaveProperty('credentialSubject');const envelope:any={prepared:{request:{kind:'batch',operations:[],confirmed:true}}};expect((f.service as any).credentialSubject(envelope)).toBeNull();});
 it.each(['plugin-auth','../../jwt','enterprise-key'])('refuses nonallowlisted credential kind %s in a corrupt material',kind=>{const f=fixture('credential-update'),envelope:any={prepared:{request:{...f.request,credentialKind:kind}}};expect(()=>(f.service as any).credentialSubject(envelope)).toThrow();});
});
