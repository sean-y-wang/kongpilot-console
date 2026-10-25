import 'reflect-metadata';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {randomUUID,createHash} from 'node:crypto';
import {ForbiddenException} from '@nestjs/common';
import {KongExecutionContextService} from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import {canonicalJson} from '../../apps/console-api/src/infrastructure/secret.service';
import {eventAuditScopeDigest,scopeFromHints} from '../../apps/console-api/src/modules/event-core/event-utils';
import {attestTargetOriginalProducer} from '../../apps/console-api/src/modules/workflows/entity-change-target-producer-contract';
import {TargetResultReconciliationService} from '../../apps/console-api/src/modules/workflows/target-result-reconciliation.service';
import {certifyTargetReconciliationHistory,authenticateTargetResultObservation,targetResultObservationAad} from '../../apps/console-api/src/modules/workflows/entity-change-target-reconciliation-proof';
import {targetReconciliationFixture} from './helpers/target-reconciliation-fixture';

/** Actual private HTTP/actor/read Context + Source service/crypto/history
 * certifier. SQL, current RBAC and Kong collections are controlled adapters;
 * this is neither a native runtime operation nor a PostgreSQL DDL test. */
function fixture(){
 const f=targetReconciliationFixture(),{tx:db,secrets,rows}=f,context=new KongExecutionContextService(),sid=randomUUID(),key='original-target-execution-key',h=(v:any)=>secrets.fingerprint(v);
 const actor:any={user:{id:f.source.executionActorId,username:'unit-owner',superAdmin:false},workspaceId:f.source.workspaceId,idempotencyKey:key,requestId:randomUUID(),ip:'192.0.2.20'},body={revision:7,planHash:f.source.workflowPlanHash,executionId:f.source.workflowExecutionId,confirmed:true,confirm_name:'native-change'};
 const w=rows.workflows[0],e=rows.workflow_executions[0],step=rows.workflow_steps[0];w.revision=7;e.revision=3;step.revision=4;e.idempotency_key=key;
 const prepared=f.input.envelope.prepared,envelope=f.input.envelope,source=f.source,plan=f.input.plan;
 const state:any={session:true,epoch:'1',permission:prepared.permissionVersion,grant:true,migration:true,sourceActive:false,failCas:'',failAudit:false,drift:false,producer:true,revokeAfterRead:false,nativePruned:false},cluster={revision:1,execution_mode:'approval',admin_url:'http://kong:8001',transport_scope:plan.scope.transportScope,version:'1.5.1',status:'healthy'};
 const originalOne=db.one.getMockImplementation()!,originalQuery=db.query.getMockImplementation()!;
 rows.entity_change_target_result_observations=[];rows.audit_events=[];rows.audit_event_scopes=[];
 db.one.mockImplementation(async(sql:string,p:any[]=[])=>{
  if(sql.includes('FROM schema_migrations'))return state.migration?{checksum:'a'.repeat(64)}:null;
  if(sql.includes('FROM iam_epoch'))return{version:state.permission};
  if(sql.includes('FROM auth_sessions')){expect(p).toEqual([sid,actor.user.id]);return state.session?{credential_epoch:state.epoch,user_epoch:state.epoch}:null;}
  if(sql.includes('FROM clusters'))return structuredClone(cluster);if(sql.includes('FROM workspaces'))return{revision:1,status:'active'};
  if(sql.includes('FROM workflow_executions e'))return{...structuredClone(e),workflow_state:w.state,workflow_revision:w.revision};
  if(sql.includes('FROM workflow_steps')&&sql.includes('FOR UPDATE'))return structuredClone(step);
  if(sql.includes('FROM entity_change_execution_sources WHERE workflow_execution_id'))return structuredClone(rows.entity_change_execution_sources[0]);
  if(sql.includes('FROM entity_change_target_result_observations'))return structuredClone(rows.entity_change_target_result_observations.find((r:any)=>sql.includes('WHERE source_id')?r.source_id===p[0]:r.id===p[0])??null);
  if(sql.includes('FROM audit_events'))return structuredClone(rows.audit_events.find((r:any)=>r.id===p[0])??null);
  if(sql.includes('FROM audit_event_scopes'))return structuredClone(rows.audit_event_scopes.find((r:any)=>r.audit_event_id===p[0])??null);
  return originalOne(sql,p);
 });
 db.query.mockImplementation(async(sql:string,p:any[]=[])=>{if(sql.includes('FOR UPDATE')&&sql.includes('FROM mutation_operations'))return structuredClone(rows.mutation_operations);return originalQuery(sql,p);});
 db.exec.mockImplementation(async(sql:string,p:any[]=[])=>{
  if(sql.startsWith('SELECT pg_advisory_xact_lock'))return 1;
  if(sql.startsWith('INSERT INTO entity_change_target_result_observations')){const columns=sql.slice(sql.indexOf('(')+1,sql.indexOf(')')).split(',');rows.entity_change_target_result_observations.push(Object.fromEntries(columns.map((c,i)=>[c,p[i]])));return 1;}
  if(sql.startsWith('UPDATE ')){const table=/UPDATE (\w+)/.exec(sql)![1];if(state.failCas===table)return 0;const row=rows[table].find((r:any)=>r.id===p[0]);if(!row||row.state!=='uncertain'||table!=='mutation_operations'&&row.revision!==p[1])return 0;row.state='succeeded';if(table!=='mutation_operations')row.revision++;else row.safe_result=JSON.parse(p[1]);return 1;}
  throw Error('Unexpected metadata write');
 });
 db.transaction.mockImplementation(async(fn:any)=>{const saved=structuredClone(rows);try{return await fn(db);}catch(error){for(const k of Object.keys(rows))rows[k]=saved[k];throw error;}});
 let held=0;const redis:any={withLock:vi.fn(async(_key:string,fn:any)=>{held++;try{return await fn();}finally{held--;}}),assertLeaseOwnership:vi.fn(async()=>{if(!held)throw Error('No original lock');})};
 const audit:any={append:vi.fn(async(event:any)=>{if(state.failAudit)throw Error('audit down');const a:any={id:randomUUID(),chain_scope:`cluster:${source.clusterId}`,sequence:String(rows.audit_events.length+1),actor_id:event.actorId,actor_type:'user',source_ip:event.ip??null,cluster_id:event.clusterId,workspace_id:event.workspaceId,entity_type:event.entityType,entity_id:event.entityId,action:event.action,before:event.before,after:event.after,json_patch:[],workflow_id:event.workflowId,result:event.result,request_id:event.requestId,prev_hash:'0'.repeat(64),occurred_at:new Date().toISOString()};a.event_hash=createHash('sha256').update(canonicalJson(a)).digest('hex');rows.audit_events.push(a);const scope=scopeFromHints(event.scopeHints);rows.audit_event_scopes.push({audit_event_id:a.id,audit_event_hash:a.event_hash,cluster_id:source.clusterId,workspace_id:source.workspaceId,scope,scope_hmac:eventAuditScopeDigest(secrets,{auditEventId:a.id,auditEventHash:a.event_hash,clusterId:source.clusterId,workspaceId:source.workspaceId,scope})});return{id:a.id,eventHash:a.event_hash};})};
 const authz:any={permissionVersion:vi.fn(async()=>state.permission)},boundary:any={assertStoredSubject:vi.fn(async()=>{if(!state.grant)throw new ForbiddenException({code:'TEST_CURRENT_SCOPE_DENIED'});})},plans:any={load:vi.fn(async()=>({plan:structuredClone(plan),row:{revision:w.revision,state:w.state}}))},intents:any={assertSubject:vi.fn(async()=>{if(!state.grant)throw new ForbiddenException();}),executionMaterial:vi.fn(async()=>structuredClone(envelope))};
 const kong:any={request:vi.fn(async(_cid:string,method:string,path:string)=>{expect(method).toBe('GET');expect(path).toBe(`/upstreams/${f.upstream}`);return structuredClone(f.capture.objects[0].before);}),list:vi.fn(async(_cid:string,path:string,q:any)=>{if(state.revokeAfterRead)state.session=false;return{items:path.endsWith('/all')?[...(state.nativePruned?[]:[structuredClone(f.before),structuredClone(f.raw)]),...(state.drift?[{...f.raw,id:randomUUID(),weight:50,created_at:f.raw.created_at+1}]:[])]:[],size:q.size,nextCursor:null};})};
 const bridge:any={assertNoActiveSource:vi.fn(async()=>{if(state.sourceActive)throw new ForbiddenException();}),attestProducer:vi.fn(async(cert:any)=>{if(!state.producer)throw new ForbiddenException();return attestTargetOriginalProducer(cert,secrets);})};
 const service=new TargetResultReconciliationService(db,redis,secrets,context,kong,authz,audit,plans,intents,boundary),install=()=>service.installFixedBridge(bridge,'a'.repeat(64)),run=(input=body,who=actor)=>context.runHttp({requestId:who.requestId,ip:who.ip,idempotencyKey:who.idempotencyKey},()=>{context.bindHttpActor(who.user,sid);return context.runActor({actor:who.user,clusterId:plan.clusterId,workspaceId:who.workspaceId,module:'workflows',action:'write'},()=>service.reconcile(plan,input,who));});
 const cap=()=>context.runHttp({},()=>{context.bindHttpActor(actor.user,sid);return context.runActor({actor:actor.user,clusterId:plan.clusterId,workspaceId:actor.workspaceId,module:'workflows',action:'read'},()=>service.canReconcile(plan,actor));});
 return{...f,service,state,actor,body,context,db,redis,audit,kong,bridge,install,run,cap,w,e,step,source,plan,envelope};
}

describe('M11 Target result metadata reconciliation Source integration',()=>{
 beforeEach(()=>vi.stubEnv('CONSOLE_ENCRYPTION_KEY','c3'.repeat(32)));afterEach(()=>vi.unstubAllEnvs());
 it('fails closed with no installed bridge or unapplied/mismatched storage and performs no native requests',async()=>{const f=fixture();await expect(f.run()).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_TARGET_RECONCILIATION_UNAVAILABLE'}});f.install();expect(()=>f.install()).toThrow();f.state.migration=false;await expect(f.run()).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_TARGET_RECONCILIATION_STORAGE_UNAVAILABLE'}});expect(f.kong.request).not.toHaveBeenCalled();expect(f.audit.append).not.toHaveBeenCalled();});
 it('uses only the genuine current actor frame and original key, rejecting a copied actor or inherited read frame',async()=>{const f=fixture();f.install();await expect(f.service.reconcile(f.plan,f.body,f.actor)).rejects.toThrow();await expect(f.run(f.body,{...f.actor,user:{...f.actor.user,id:randomUUID()}})).rejects.toThrow();expect(f.audit.append).not.toHaveBeenCalled();});
 it('closes four original metadata rows once with scoped audit and separate inferred201 observation while preserving old unknown/result/failures',async()=>{const f=fixture();f.install();const old=structuredClone(f.rows.entity_change_packet_events),result=await f.run();expect(result).toMatchObject({state:'succeeded',nativeRequestsSent:0,metadataReconciled:true,alreadyReconciled:false,originalNativeStatus:null,statusInferredViaContract:201});expect(f.rows.entity_change_packet_events).toEqual(old);expect(f.rows.mutation_operations[0]).toMatchObject({state:'succeeded',remote_started:true,remote_completed:true,error_code:'KONG_VALIDATION_ERROR'});expect(f.rows.entity_change_target_result_observations).toHaveLength(1);expect(f.rows.audit_events).toHaveLength(1);expect(f.kong.list).toHaveBeenCalledTimes(4);expect(f.kong.request).toHaveBeenCalledOnce();expect(f.db.exec.mock.calls.every(([sql]:any)=>!sql.includes('INSERT INTO entity_change_execution_sources')&&!sql.includes('entity_change_packet_events SET'))).toBe(true);
  expect(await f.run()).toMatchObject({...result,alreadyReconciled:true});expect(f.rows.audit_events).toHaveLength(1);expect(f.rows.entity_change_target_result_observations).toHaveLength(1);
  const obs=f.rows.entity_change_target_result_observations[0],again=await certifyTargetReconciliationHistory({...f.input,priorObservationId:obs.id});expect(again.proofHmac).toBe(obs.history_proof_hmac);
 });
 it.each(['session','epoch','permission','grant','sourceActive','producer','drift','revokeAfterRead'])('blocks %s without metadata or native write',async key=>{const f=fixture();f.install();f.state[key]=key==='epoch'?'2':key==='permission'?'changed':!['session','grant','producer'].includes(key);await expect(f.run()).rejects.toThrow();expect(f.rows.audit_events).toHaveLength(0);expect(f.rows.entity_change_target_result_observations).toHaveLength(0);expect(f.rows.mutation_operations[0].state).toBe('uncertain');});
 it.each(['workflow_steps','workflow_executions','workflows','mutation_operations'])('rolls back audit/observation/all metadata if %s CAS fails',async table=>{const f=fixture();f.install();f.state.failCas=table;await expect(f.run()).rejects.toThrow();expect(f.rows.audit_events).toHaveLength(0);expect(f.rows.entity_change_target_result_observations).toHaveLength(0);expect(f.rows.workflows[0].state).toBe('uncertain');expect(f.rows.mutation_operations[0].state).toBe('uncertain');});
 it('rolls back before CAS on audit failure and denies idempotent replay after current credential/scope revocation',async()=>{const f=fixture();f.install();f.state.failAudit=true;await expect(f.run()).rejects.toThrow();expect(f.rows.entity_change_target_result_observations).toHaveLength(0);f.state.failAudit=false;await f.run();f.state.session=false;await expect(f.run()).rejects.toThrow();expect(f.rows.audit_events).toHaveLength(1);});
 it('computes a read-only detail capability without minting a key/source/observation or requiring a caller write frame',async()=>{const f=fixture();expect(await f.cap()).toBe(false);f.install();expect(await f.cap()).toBe(true);expect(f.audit.append).not.toHaveBeenCalled();expect(f.db.exec).not.toHaveBeenCalled();expect(f.kong.request).not.toHaveBeenCalled();f.state.grant=false;expect(await f.cap()).toBe(false);});
 it.each(['observation_hmac','result_hmac','history_proof_hmac','audit_event_hash','workflow_revision_before'])('rejects a tampered completed %s observation on reentry',async field=>{const f=fixture();f.install();await f.run();const row=f.rows.entity_change_target_result_observations[0];row[field]=field==='workflow_revision_before'?row[field]+1:'0'.repeat(64);await expect(f.run()).rejects.toThrow();expect(f.rows.audit_events).toHaveLength(1);expect(f.rows.entity_change_target_result_observations).toHaveLength(1);});
 it('rechecks completed raw native result and fresh current collections on idempotent reentry',async()=>{const f=fixture();f.install();await f.run();f.state.drift=true;await expect(f.run()).rejects.toThrow();expect(f.rows.audit_events).toHaveLength(1);expect(f.rows.entity_change_packet_events[1].native_status).toBeNull();});
 it('rejects a different original request or execution key after metadata closure',async()=>{const f=fixture();f.install();await f.run();await expect(f.run({...f.body,revision:f.body.revision+1})).rejects.toMatchObject({response:{code:'IDEMPOTENCY_CONFLICT'}});await expect(f.run(f.body,{...f.actor,idempotencyKey:'different-original-execution-key'})).rejects.toThrow();expect(f.rows.audit_events).toHaveLength(1);});
 it('rejects an audit scope of another subject type even with a coherently signed scope HMA',async()=>{const f=fixture();f.install();await f.run();const scope=f.rows.audit_event_scopes[0];scope.scope.subject.type='consumers';scope.scope_hmac=eventAuditScopeDigest(f.secrets,{auditEventId:scope.audit_event_id,auditEventHash:scope.audit_event_hash,clusterId:scope.cluster_id,workspaceId:scope.workspace_id,scope:scope.scope});await expect(f.run()).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_TARGET_RECONCILIATION_PROOF_INVALID'}});expect(f.rows.audit_events).toHaveLength(1);});
 it('closes genuine original response metadata after native pruning, explicitly sealing absence rather than a fabricated history GET',async()=>{
  const f=fixture();f.install();f.state.nativePruned=true;const old=structuredClone(f.rows.entity_change_packet_events),result=await f.run();expect(result).toMatchObject({state:'succeeded',nativeRequestsSent:0,originalNativeStatus:null,statusInferredViaContract:201});
  const row=f.rows.entity_change_target_result_observations[0],sealed=f.secrets.decrypt<any>(row.observation_ciphertext,`entity-change-target-result-observation:${row.cluster_id}:${row.workspace_id}:${row.id}:material`);
  expect(sealed.currentObservation).toMatchObject({version:2,historyRetention:'native-pruned',originalResultHmac:f.secrets.fingerprint(f.raw),observedHistoryHmac:null,historyAddressAbsent:true,currentEffectiveAbsent:true});expect(sealed.currentObservation).not.toHaveProperty('resultHmac');
  expect(await f.run()).toMatchObject({...result,alreadyReconciled:true});expect(f.rows.entity_change_packet_events).toEqual(old);expect(f.rows.audit_events).toHaveLength(1);expect(f.kong.request.mock.calls.every((c:any)=>c[1]==='GET'&&c[2]===`/upstreams/${f.upstream}`)).toBe(true);
 });
 it.each([
  ['pruned history with a fabricated GET HMA',(o:any)=>{o.observedHistoryHmac=o.originalResultHmac;}],
  ['pruned history without full address absence',(o:any)=>{o.historyAddressAbsent=false;}],
  ['claimed retained history with no GET row',(o:any)=>{o.historyRetention='retained';}],
  ['current effective target present',(o:any)=>{o.currentEffectiveAbsent=false;}],
  ['foreign original response',(o:any)=>{o.originalResultHmac='0'.repeat(64);}],
  ['foreign source',(o:any)=>{o.sourceId=randomUUID();}],
  ['foreign operation',(o:any)=>{o.operationId=randomUUID();}],
  ['mislabelled response as a GET',(o:any)=>{o.resultHmac=o.originalResultHmac;}],
  ['fabricated native GET object',(o:any)=>{o.observedTarget={id:randomUUID(),weight:0};}],
  ['fabricated status receipt',(o:any)=>{o.nativeStatus=201;}],
  ['foreign status field',(o:any)=>{o.status=201;}],
  ['copied original response in current observation',(o:any)=>{o.knownOriginalResponse={id:randomUUID(),weight:0};}],
  ['missing read budget',(o:any)=>{delete o.budget;}],
  ['no complete EOF reads',(o:any)=>{o.budget.pages=0;}],
  ['incomplete four-collection budget',(o:any)=>{o.budget.pages=3;}],
  ['excess pages',(o:any)=>{o.budget.pages=81;}],
  ['excess records',(o:any)=>{o.budget.records=9001;}],
  ['excess bytes',(o:any)=>{o.budget.bytes=24*1024*1024+1;}],
  ['fractional read count',(o:any)=>{o.budget.pages=4.5;}],
  ['unknown budget field',(o:any)=>{o.budget.fakeEof=true;}],
 ])('rejects coherently re-sealed V2 %s rather than trusting an HMA alone',async(_name,change)=>{
  const f=fixture();f.install();f.state.nativePruned=true;await f.run();const row=f.rows.entity_change_target_result_observations[0],aad=targetResultObservationAad(row.cluster_id,row.workspace_id,row.id),sealed=f.secrets.decrypt<any>(row.observation_ciphertext,aad);
  change(sealed.currentObservation);row.current_observation_hmac=f.secrets.fingerprint(sealed.currentObservation);sealed.binding.current_observation_hmac=row.current_observation_hmac;row.observation_hmac=f.secrets.fingerprint(sealed);row.observation_ciphertext=f.secrets.encrypt(sealed,aad);
  const audit=f.rows.audit_events[0];audit.after.currentObservationHmac=row.current_observation_hmac;audit.after.observationHmac=row.observation_hmac;const{event_hash:ignored,...record}=audit;row.audit_event_hash=audit.event_hash=createHash('sha256').update(canonicalJson(record)).digest('hex');
  const scope=f.rows.audit_event_scopes[0];scope.audit_event_hash=audit.event_hash;scope.scope_hmac=eventAuditScopeDigest(f.secrets,{auditEventId:audit.id,auditEventHash:audit.event_hash,clusterId:row.cluster_id,workspaceId:row.workspace_id,scope:scope.scope});
  await expect(authenticateTargetResultObservation(f.db,f.secrets,row.id)).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_TARGET_RECONCILIATION_PROOF_INVALID'}});expect(f.rows.audit_events).toHaveLength(1);
 });
});
