import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { EntityChangeExecutionFactsService, entityBaselineAad } from '../../apps/console-api/src/modules/workflows/entity-change-execution-facts.service';
import type { EntityChangeBaselineCapture, EntityChangeExecutionFactsDelegate, EntityChangePacketAttemptBinding, EntityChangePacketFact, EntityChangeRecoveryLink } from '../../apps/console-api/src/modules/workflows/entity-change-execution-facts.types';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import {readTargetHealthObservation} from '../../apps/console-api/src/infrastructure/kong/target-health-observation';

// SQL is an explicit domain adapter here. Root executes actual migration/FK
// and genuine kernel tests separately; these proofs model only the mandatory
// delegate contract, not Root's private execution namespace.
function fixture(){
  const secrets=new SecretService(),cid=randomUUID(),wid=randomUUID(),uid=randomUUID(),id=randomUUID(),objectId=randomUUID(),
    source:any={id,cluster_id:cid,workspace_id:wid,intent_id:randomUUID(),intent_revision:1,material_hmac:'11'.repeat(32),change_digest:'22'.repeat(32),packet_manifest_hmac:'33'.repeat(32),workflow_id:randomUUID(),workflow_plan_revision:1,workflow_plan_hash:'44'.repeat(32),workflow_execution_id:randomUUID(),execution_actor_id:uid,credential_epoch:'1',session_id:randomUUID(),permission_version_hmac:'55'.repeat(32),issued_at:new Date(Date.now()-1000),expires_at:new Date(Date.now()+240000)},
    packet:any={cluster_id:cid,workspace_id:wid,intent_id:source.intent_id,intent_revision:1,material_hmac:source.material_hmac,change_digest:source.change_digest,packet_manifest_hmac:source.packet_manifest_hmac,packet_key:'packet-1',packet_order:1,dependencies:[],method:'POST',path_hmac:'66'.repeat(32),native_type:'services',native_id:objectId,parent_id:null,credential_kind:null,original_native_id:null,mutation_action:'create',permission_action:'write',body_hmac:'77'.repeat(32),before_hmac:secrets.fingerprint(null)},
    capture:EntityChangeBaselineCapture={version:1,observedFrom:new Date(Date.now()-500).toISOString(),observedUntil:new Date().toISOString(),graphs:[],objects:[{key:'service-absence',nativeType:'services',nativeId:objectId,affected:true,present:false,dependencies:[],before:null,schemaMaterial:{fields:[]},trustedProvenance:{kind:'actual-404'},recovery:'absent'}],blockerCodes:[],nonreversiblePacketKeys:[]};
  const baselines=new Map<string,any>(),objects:any[]=[],pins:any[]=[],attempts:any[]=[],events:any[]=[],links:any[]=[],healthRows:any[]=[],proofs=new WeakMap<object,any>();let live=true,executionState='executing',historicalAllowed=true;
  const db:any={one:vi.fn(async(sql:string,p:any[]=[])=>{
    if(/FROM entity_change_(packet_attempts|baseline_pins).*FOR (UPDATE|SHARE)/.test(sql))throw Object.assign(new Error('Append-only role cannot lock immutable rows'),{code:'42501'});
    if(sql.includes('FROM entity_change_execution_sources'))return p[0]===source.id?source:null;
    if(sql.includes('FROM entity_change_intent_packets'))return p[4]===packet.packet_key?packet:null;
    if(sql.includes('FROM entity_change_baselines'))return sql.includes('source_id=$1')?[...baselines.values()].find(row=>row.source_id===p[0])??null:baselines.get(p[0])??null;
    if(sql.includes('FROM entity_change_baseline_pins'))return sql.includes('WHERE id=$1')?pins.find(pin=>pin.id===p[0]&&pin.baseline_id===p[1])??null:[...pins].filter(pin=>pin.baseline_id===p[0]).sort((a,b)=>b.pin_version-a.pin_version)[0]??null;
    if(sql.includes('FROM workflow_executions'))return {state:executionState,unknown:events.some(event=>event.outcome==='sent-unknown'),pending:attempts.some(attempt=>!events.some(event=>event.attempt_id===attempt.id&&event.event_kind==='outcome'))};
    if(sql.includes('FROM entity_change_packet_attempts'))return sql.includes('source_id=$1')?attempts.find(row=>row.source_id===p[0]&&row.packet_key===p[1])??null:attempts.find(row=>row.id===p[0])??null;
    if(sql.includes('FROM entity_change_packet_events'))return events.find(row=>row.attempt_id===p[0]&&row.event_kind===p[1])??null;
    if(sql.includes('FROM entity_change_recovery_links'))return links.find(row=>row.actor_id===p[0]&&row.idempotency_key===p[1])??null;
    return null;
  }),query:vi.fn(async(sql:string,p:any[])=>sql.includes('FROM entity_change_target_health_baselines')?healthRows.filter(row=>row.baseline_id===p[0]).sort((a,b)=>a.packet_key.localeCompare(b.packet_key)).map(row=>({packetKey:row.packet_key,objectKey:row.object_key,nativeId:row.native_id,upstreamId:row.upstream_id,beforeHmac:row.before_hmac,provenanceHmac:row.provenance_hmac,nodeId:row.node_id,health:row.health,healthRowHmac:row.health_row_hmac,observationHmac:row.observation_hmac})):sql.includes('FROM entity_change_baseline_objects')?objects.filter(row=>row.baseline_id===p[0]).sort((a,b)=>a.object_order-b.object_order):[]),exec:vi.fn(async(sql:string,p:any[])=>{
    const row=(names:string[],values:any[])=>Object.fromEntries(names.map((name,index)=>[name,values[index]]));
    if(sql.includes('pg_advisory_xact_lock'))return 1;
    if(sql.startsWith('INSERT INTO entity_change_baselines')){const value=row(['id','cluster_id','workspace_id','source_id','intent_id','intent_revision','material_hmac','change_digest','packet_manifest_hmac','workflow_id','workflow_plan_revision','workflow_plan_hash','workflow_execution_id','execution_actor_id','credential_epoch','baseline_hmac','capture_hmac','object_manifest_hmac','object_manifest','object_count','graph_count','material_ciphertext','observed_from','observed_until'],p);value.object_manifest=JSON.parse(value.object_manifest);value.created_at=new Date();value.readiness='ready';baselines.set(value.id,value);}
    else if(sql.startsWith('INSERT INTO entity_change_baseline_objects'))objects.push(row(['cluster_id','workspace_id','baseline_id','object_manifest_hmac','object_key','object_order','native_type','native_id','parent_id','credential_kind','affected','present','dependencies','before_hmac','restore_hmac','schema_hmac','provenance_hmac','recovery'],p));
    else if(sql.startsWith('INSERT INTO entity_change_target_health_baselines'))healthRows.push(row(['cluster_id','workspace_id','baseline_id','object_manifest_hmac','object_key','packet_key','native_id','upstream_id','before_hmac','provenance_hmac','node_id','health','health_row_hmac','observation_hmac'],p));
    else if(sql.startsWith('INSERT INTO entity_change_baseline_pins')){
      if(sql.includes('SELECT $1,cluster_id')){const b=baselines.get(p[1]);pins.push({id:p[0],cluster_id:b.cluster_id,workspace_id:b.workspace_id,baseline_id:b.id,source_id:b.source_id,workflow_execution_id:b.workflow_execution_id,baseline_hmac:b.baseline_hmac,object_manifest_hmac:b.object_manifest_hmac,pin_version:1,previous_pin_id:null,protected_until:new Date(b.created_at.getTime()+p[2]*86400000)});}
      else pins.push(row(['id','cluster_id','workspace_id','baseline_id','source_id','workflow_execution_id','baseline_hmac','object_manifest_hmac','pin_version','previous_pin_id','protected_until'],p));
    }else if(sql.startsWith('INSERT INTO entity_change_packet_attempts'))attempts.push(row(['id','cluster_id','workspace_id','source_id','baseline_id','pin_id','workflow_execution_id','intent_id','intent_revision','material_hmac','change_digest','packet_manifest_hmac','packet_key','packet_order','method','path_hmac','native_type','native_id','parent_id','credential_kind','original_native_id','permission_action','mutation_action','body_hmac','before_hmac'],p));
    else if(sql.startsWith('INSERT INTO entity_change_packet_events'))events.push(row(['id','cluster_id','workspace_id','attempt_id','source_id','baseline_id','pin_id','workflow_execution_id','event_kind','outcome','native_status','error_code','fact_hmac','fact_ciphertext','observed_at'],p));
    else if(sql.startsWith('INSERT INTO entity_change_recovery_links'))links.push(row(['id','cluster_id','workspace_id','baseline_id','pin_id','source_id','workflow_execution_id','new_intent_id','new_intent_revision','new_material_hmac','new_change_digest','new_packet_manifest_hmac','actor_id','idempotency_key','request_hmac'],p));
    else throw new Error('Unexpected domain SQL');return 1;
  })};db.transaction=vi.fn(async(fn:any)=>fn(db));
  const check=(proof:object,kind:string,value:unknown)=>{const record=proofs.get(proof);if(!record||record.kind!==kind||record.hash!==secrets.fingerprint(value))throw new ForbiddenException({code:'FAKE_ROOT_FACT'});};
  const delegate:EntityChangeExecutionFactsDelegate={verifySource:vi.fn(async(sourceId,phase)=>{if(sourceId!==source.id||phase!=='outcome'&&!live)throw new ForbiddenException({code:'SOURCE_NOT_CURRENT'});}),
    verifyCapture:vi.fn(async(_id,value,proof)=>{check(proof,'capture',value);if(proofs.get(proof).original!==value)throw new ForbiddenException({code:'FAKE_ROOT_CAPTURE'});}),
    verifyPacketFact:vi.fn(async(binding,fact,proof)=>check(proof,fact?'fact':'attempt',fact??binding)),assertHistoricalRead:vi.fn(async()=>{if(!historicalAllowed)throw new ForbiddenException();}),
    verifyRetention:vi.fn(async(id,until,proof)=>check(proof,'retention',{id,until})),verifyRecovery:vi.fn(async(value,proof)=>check(proof,'recovery',value))};
  const service=new EntityChangeExecutionFactsService(db,secrets),install=()=>service.installFixedDelegate(delegate),proof=(kind:string,value:unknown)=>{const token={};proofs.set(token,{kind,hash:secrets.fingerprint(value),original:value});return token;};
  const ready=()=>service.persistReady(source.id,capture,proof('capture',capture));
  return {service,db,secrets,source,packet,capture,baselines,objects,pins,attempts,events,links,healthRows,delegate,proof,ready,install,setLive:(value:boolean)=>{live=value;},setState:(value:string)=>{executionState=value;},setHistorical:(value:boolean)=>{historicalAllowed=value;}};
}
async function healthFixture(){
  const f=fixture(),upstream=randomUUID(),target=f.packet.native_id,before={id:target,target:'echo:8080',weight:100,tags:[],created_at:1,upstream:{id:upstream}},
    observed=await readTargetHealthObservation({request:async()=>({version:'1.5.1',node_id:'fixture-admin-node'}),list:async(_cid:any,_path:any,query:any)=>({items:[{...before,health:'HEALTHY'}],size:query.size,nextCursor:null})} as any,f.secrets,{clusterId:f.source.cluster_id,upstreamId:upstream,target:before});
  Object.assign(f.packet,{method:'POST',native_type:'targets',parent_id:upstream,mutation_action:'mark_unhealthy',before_hmac:f.secrets.fingerprint(before),body_hmac:f.secrets.fingerprint(null)});
  const parentKey=`upstreams:${upstream}`,targetKey=`targets:${upstream}:${target}`,parent={id:upstream,name:'fixture-upstream'};
  const capture:EntityChangeBaselineCapture={...f.capture,observedUntil:new Date().toISOString(),graphs:[{purpose:'baseline',complete:true,rootKey:targetKey,nodes:[{key:parentKey,type:'upstreams',id:upstream,path:`/upstreams/${upstream}`,data:parent,affected:false,dependencies:[],restorable:true},
    {key:targetKey,type:'targets',id:target,path:`/upstreams/${upstream}/targets/${target}`,data:before,restoreData:before,affected:true,dependencies:[parentKey],restorable:true}]} as any],
    objects:[{key:parentKey,nativeType:'upstreams',nativeId:upstream,affected:false,present:true,dependencies:[],before:parent,schemaMaterial:{fields:[]},trustedProvenance:{kind:'native-observed'},recovery:'reference'},
      {key:targetKey,nativeType:'targets',nativeId:target,parentId:upstream,affected:true,present:true,dependencies:[parentKey],before,restorePayload:before,schemaMaterial:{fields:[]},
        trustedProvenance:{kind:'target-health-observed',beforeHmac:f.secrets.fingerprint(before),healthBefore:observed,overrideRecovery:'unavailable'},recovery:'complete'}],nonreversiblePacketKeys:[f.packet.packet_key]};
  return{...f,capture,observed,upstream};
}
describe('M11 entity execution facts repository (explicit SQL/Root-delegate domain adapters)',()=>{
  beforeEach(()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','de'.repeat(32));vi.stubEnv('ENTITY_BASELINE_RETENTION_DAYS','30');});afterEach(()=>vi.unstubAllEnvs());
  it('requires a complete once-installed Root delegate and rejects a copied capture proof before writes',async()=>{
    const f=fixture();await expect(f.ready()).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_EXECUTION_FACT_POLICY_UNAVAILABLE'}});f.install();expect(()=>f.install()).toThrow();
    await expect(f.service.persistReady(f.source.id,f.capture,{})).rejects.toMatchObject({response:{code:'FAKE_ROOT_FACT'}});expect(f.db.exec).not.toHaveBeenCalled();
    const token=f.proof('capture',f.capture);await expect(f.service.persistReady(f.source.id,structuredClone(f.capture),token)).rejects.toMatchObject({response:{code:'FAKE_ROOT_CAPTURE'}});expect(f.db.exec).not.toHaveBeenCalled();
  });
  it('pins genuine absence independently of packet count and verifies every ciphertext/manifest/source binding on read',async()=>{
    const f=fixture();f.install();const receipt=await f.ready();expect(receipt.objectCount).toBe(1);expect(receipt.graphCount).toBe(0);expect(Date.parse(receipt.protectedUntil)-Date.now()).toBeGreaterThanOrEqual(29*86400000);
    const loaded=await f.service.assertReadyForPacket(f.source.id,receipt.baselineId,'packet-1');expect(loaded.capture.objects[0].present).toBe(false);expect(loaded.packet.nativeId).toBe(f.packet.native_id);
    f.objects[0].before_hmac='00'.repeat(32);await expect(f.service.assertReadyForPacket(f.source.id,receipt.baselineId,'packet-1')).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_BASELINE_MANIFEST_INVALID'}});
  });
  it('keeps Basic salted hash and verified plaintext distinct and rejects missing/forged recovery or health baselines',async()=>{
    const f=fixture();f.install();const consumer=randomUUID(),credential=randomUUID(),plain='baseline-password-fixture';
    const capture:EntityChangeBaselineCapture={...f.capture,objects:[...f.capture.objects,{key:'consumer',nativeType:'consumers',nativeId:consumer,affected:false,present:true,dependencies:[],before:{id:consumer,username:'owner'},schemaMaterial:{fields:[]},trustedProvenance:{kind:'native-get'},recovery:'reference'},
      {key:'basic',nativeType:'basic-auth',nativeId:credential,parentId:consumer,credentialKind:'basic-auth',affected:true,present:true,dependencies:['consumer'],before:{id:credential,consumer:{id:consumer},username:'api',password:createHash('sha1').update(plain+consumer).digest('hex')},restorePayload:{id:credential,consumer:{id:consumer},username:'api',password:plain},schemaMaterial:{fields:[]},trustedProvenance:{kind:'credential-store',sourceHashHmac:'aa'.repeat(32)},recovery:'complete'}]};
    const receipt=await f.service.persistReady(f.source.id,capture,f.proof('capture',capture)),row=f.baselines.get(receipt.baselineId)!;expect(row.material_ciphertext).not.toContain(plain);
    const envelope=f.secrets.decrypt<any>(row.material_ciphertext,entityBaselineAad(f.source.cluster_id,f.source.workspace_id,receipt.baselineId));expect(envelope.capture.objects[2].restorePayload.password).toBe(plain);expect(envelope.capture.objects[2].before.password).not.toBe(plain);
    const bad:any=structuredClone(capture);bad.objects[2].restorePayload.password='different';await expect(f.service.persistReady(f.source.id,bad,f.proof('capture',bad))).rejects.toMatchObject({response:{code:'BASIC_AUTH_RESTORE_PROVENANCE_INVALID'}});
    const timed:any=structuredClone(capture);timed.objects[2].before.ttl=60;await expect(f.service.persistReady(f.source.id,timed,f.proof('capture',timed))).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_BASELINE_NOT_RECOVERABLE'}});
    const health={...f.capture,blockerCodes:['TARGET_HEALTH_NODE_STATE_NOT_RECOVERABLE'],nonreversiblePacketKeys:['packet-1']};await expect(f.service.persistReady(f.source.id,health,f.proof('capture',health))).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_BASELINE_NOT_RECOVERABLE'}});
  });
  it('creates exactly one attempt, rejects replay, encrypts real fact evidence and preserves immutable unknown outcomes',async()=>{
    const f=fixture();f.install();const receipt=await f.ready(),binding:EntityChangePacketAttemptBinding={sourceId:f.source.id,baselineId:receipt.baselineId,pinId:receipt.pinId,packetKey:'packet-1',attemptId:randomUUID()};
    await f.service.appendAttempt(binding,f.proof('attempt',binding));await expect(f.service.appendAttempt(binding,f.proof('attempt',binding))).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_PACKET_ALREADY_ATTEMPTED'}});
    const send:Extract<EntityChangePacketFact,{kind:'send-intent'}>={version:1,binding,kind:'send-intent',observedAt:new Date().toISOString(),evidence:{actualOperationId:randomUUID()}};
    await f.service.appendSendIntent(send,f.proof('fact',send));const outcome:Extract<EntityChangePacketFact,{kind:'outcome'}>={version:1,binding,kind:'outcome',outcome:'sent-unknown',observedAt:new Date().toISOString(),evidence:{transport:'connection-lost'}};
    f.setLive(false);await f.service.appendOutcome(outcome,f.proof('fact',outcome)); // expired/withdrawn source can record an already observed result, not send
    const replaced={...outcome,outcome:'succeeded' as const,nativeStatus:201};await expect(f.service.appendOutcome(replaced,f.proof('fact',replaced))).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_PACKET_OUTCOME_IMMUTABLE'}});
    expect(f.events.map(event=>[event.event_kind,event.outcome])).toEqual([['send-intent',null],['outcome','sent-unknown']]);expect(f.events[1].fact_ciphertext).not.toContain('connection-lost');
  });
  it('historical projection uses current actual subject read authority while retention only extends immutable pins',async()=>{
    const f=fixture();f.install();const receipt=await f.ready();f.setLive(false);
    const actor={user:{id:f.source.execution_actor_id,username:'owner',superAdmin:false},workspaceId:f.source.workspace_id};
    const history:any=await f.service.historicalProjection(f.source.cluster_id,f.source.workspace_id,receipt.baselineId,actor);expect(history.nativeAuthority).toBe(false);expect(history.objects).toBeUndefined();expect(history.recovery.absentObjects).toBe(1);expect(JSON.stringify(history)).not.toContain(f.packet.native_id);expect(JSON.stringify(history)).not.toContain(f.source.session_id);
    f.setHistorical(false);await expect(f.service.historicalProjection(f.source.cluster_id,f.source.workspace_id,receipt.baselineId,actor)).rejects.toMatchObject({status:403});
    const shortened=new Date(Date.parse(receipt.protectedUntil)-1000).toISOString();await expect(f.service.extendRetention(receipt.baselineId,shortened,f.proof('retention',{id:receipt.baselineId,until:shortened}))).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_PIN_CANNOT_SHORTEN'}});
    const longer=new Date(Date.parse(receipt.protectedUntil)+86400000).toISOString();await f.service.extendRetention(receipt.baselineId,longer,f.proof('retention',{id:receipt.baselineId,until:longer}));expect(f.pins).toHaveLength(2);expect(f.pins[0].protected_until.toISOString()).toBe(receipt.protectedUntil);
  });
  it('preserves an observed 201 alongside unknown completion without allowing recovery or replacing the original outcome',async()=>{
    const f=fixture();f.install();const receipt=await f.ready(),binding:EntityChangePacketAttemptBinding={sourceId:f.source.id,baselineId:receipt.baselineId,pinId:receipt.pinId,packetKey:'packet-1',attemptId:randomUUID()};
    await f.service.appendAttempt(binding,f.proof('attempt',binding));
    const send:Extract<EntityChangePacketFact,{kind:'send-intent'}>={version:1,binding,kind:'send-intent',observedAt:new Date().toISOString(),evidence:{actualOperationId:randomUUID()}};
    await f.service.appendSendIntent(send,f.proof('fact',send));
    const unknown:Extract<EntityChangePacketFact,{kind:'outcome'}>={version:1,binding,kind:'outcome',outcome:'sent-unknown',nativeStatus:201,errorCode:'MUTATION_RESULT_UNCERTAIN',observedAt:new Date().toISOString(),evidence:{metadataComplete:false}};
    await f.service.appendOutcome(unknown,f.proof('fact',unknown));expect(f.events[1]).toMatchObject({outcome:'sent-unknown',native_status:201});
    f.setState('partial');const link:EntityChangeRecoveryLink={baselineId:receipt.baselineId,pinId:receipt.pinId,clusterId:f.source.cluster_id,workspaceId:f.source.workspace_id,newIntentId:randomUUID(),newIntentRevision:1,newMaterialHmac:'88'.repeat(32),newChangeDigest:'99'.repeat(32),newPacketManifestHmac:'aa'.repeat(32),actorId:f.source.execution_actor_id,idempotencyKey:'observed-status-not-completion',requestHmac:'bb'.repeat(32)};
    await expect(f.service.linkRecovery(link,f.proof('recovery',link))).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_RECOVERY_OUTCOME_UNRESOLVED'}});
    const success={...unknown,outcome:'succeeded' as const,errorCode:undefined,evidence:{metadataComplete:true}};
    await expect(f.service.appendOutcome(success,f.proof('fact',success))).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_PACKET_OUTCOME_IMMUTABLE'}});expect(f.links).toHaveLength(0);
  });
  it('recovery links require a new intent and reject active or sent-unknown originals, without creating an intent/native request',async()=>{
    const f=fixture();f.install();const receipt=await f.ready(),link:EntityChangeRecoveryLink={baselineId:receipt.baselineId,pinId:receipt.pinId,clusterId:f.source.cluster_id,workspaceId:f.source.workspace_id,newIntentId:randomUUID(),newIntentRevision:1,newMaterialHmac:'88'.repeat(32),newChangeDigest:'99'.repeat(32),newPacketManifestHmac:'aa'.repeat(32),actorId:f.source.execution_actor_id,idempotencyKey:'recovery-link-fixture',requestHmac:'bb'.repeat(32)};
    await expect(f.service.linkRecovery(link,f.proof('recovery',link))).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_RECOVERY_OUTCOME_UNRESOLVED'}});f.setState('partial');
    f.events.push({baseline_id:receipt.baselineId,outcome:'sent-unknown'});await expect(f.service.linkRecovery(link,f.proof('recovery',link))).rejects.toMatchObject({response:{code:'ENTITY_CHANGE_RECOVERY_OUTCOME_UNRESOLVED'}});f.events.length=0;
    const result=await f.service.linkRecovery(link,f.proof('recovery',link));expect(result.linkId).toBe(f.links[0].id);expect(f.db.exec.mock.calls.every(([sql]:any[])=>!sql.startsWith('UPDATE')&&!sql.startsWith('DELETE')&&!sql.includes('INSERT INTO entity_change_intents('))).toBe(true);
  });
  it('serializes event and pin append under SELECT/INSERT-only runtime permissions without row-lock UPDATE authority',async()=>{
    const f=fixture();f.install();const receipt=await f.ready(),binding:EntityChangePacketAttemptBinding={sourceId:f.source.id,baselineId:receipt.baselineId,pinId:receipt.pinId,packetKey:'packet-1',attemptId:randomUUID()};
    await f.service.appendAttempt(binding,f.proof('attempt',binding));
    const send:Extract<EntityChangePacketFact,{kind:'send-intent'}>={version:1,binding,kind:'send-intent',observedAt:new Date().toISOString(),evidence:{actualOperationId:randomUUID()}};
    await f.service.appendSendIntent(send,f.proof('fact',send));
    const outcome:Extract<EntityChangePacketFact,{kind:'outcome'}>={version:1,binding,kind:'outcome',outcome:'failed-known-not-sent',observedAt:new Date().toISOString(),evidence:{rootObservedNoWire:true}};
    await f.service.appendOutcome(outcome,f.proof('fact',outcome));
    const until=new Date(Date.parse(receipt.protectedUntil)+86400000).toISOString();await f.service.extendRetention(receipt.baselineId,until,f.proof('retention',{id:receipt.baselineId,until}));
    expect(f.events).toHaveLength(2);expect(f.pins).toHaveLength(2);
    const locks=f.db.exec.mock.calls.filter(([sql]:any[])=>sql.includes('pg_advisory_xact_lock'));
    expect(locks.map(([sql,p]:any[])=>[sql.includes('entity-change-attempt:'),p[0]])).toEqual([[true,binding.attemptId],[true,binding.attemptId],[false,receipt.baselineId]]);
    expect(f.db.one.mock.calls.every(([sql]:any[])=>!/entity_change_(packet_attempts|baseline_pins).*FOR (UPDATE|SHARE)/.test(sql))).toBe(true);
  });
  it('binds executable health POST to present Target, real sealed observation and typed immutable rows while declaring rollback unavailable',async()=>{
    const f=await healthFixture();f.install();const receipt=await f.service.persistReady(f.source.id,f.capture,f.proof('capture',f.capture));
    const ready=await f.service.assertReadyForPacket(f.source.id,receipt.baselineId,f.packet.packet_key);
    expect(ready.capture.nonreversiblePacketKeys).toEqual([f.packet.packet_key]);expect(f.healthRows).toHaveLength(1);
    expect(f.healthRows[0]).toMatchObject({native_id:f.packet.native_id,upstream_id:f.upstream,health:'HEALTHY',node_id:'fixture-admin-node',before_hmac:f.packet.before_hmac});
    const projection:any=await f.service.historicalProjection(f.source.cluster_id,f.source.workspace_id,receipt.baselineId,{user:{id:f.source.execution_actor_id,username:'fixture',superAdmin:false},workspaceId:f.source.workspace_id});
    expect(projection.recovery).toMatchObject({state:'contains-nonreversible',rollbackUnavailableReason:'TARGET_HEALTH_OVERRIDE_ROLLBACK_UNAVAILABLE',nonreversiblePacketKeys:[f.packet.packet_key]});expect(projection.nativeAuthority).toBe(false);
    f.healthRows[0].node_id='forged-node';await expect(f.service.assertReadyForPacket(f.source.id,receipt.baselineId,f.packet.packet_key)).rejects.toMatchObject({response:{code:'TARGET_HEALTH_BASELINE_MANIFEST_INVALID'}});
  });
  it.each(['missing-observation','reversible-claim','wrong-parent','wrong-before','missing-key','non-health-packet'])('rejects forged health baseline content before packet facts: %s',async defect=>{
    const f=await healthFixture();f.install();const capture:any=structuredClone(f.capture);
    if(defect==='missing-observation')delete capture.objects[1].trustedProvenance.healthBefore;
    if(defect==='reversible-claim')capture.objects[1].trustedProvenance.overrideRecovery='complete';
    if(defect==='wrong-parent')capture.objects[1].parentId=randomUUID();if(defect==='wrong-before')capture.objects[1].before.weight=70;
    if(defect==='missing-key')capture.nonreversiblePacketKeys=[];if(defect==='non-health-packet')f.packet.mutation_action='update';
    await expect(f.service.persistReady(f.source.id,capture,f.proof('capture',capture))).rejects.toBeDefined();expect(f.attempts).toHaveLength(0);expect(f.events).toHaveLength(0);
  });
});
