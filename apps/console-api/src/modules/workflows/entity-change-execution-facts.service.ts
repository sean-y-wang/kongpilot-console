import { ConflictException, ForbiddenException, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { entityReferenceId } from '../entities/entity-reference';
import { CREDENTIAL_KINDS, type EntityActor } from '../entities/entities.types';
import type { EntityChangeNormalizedPacket } from './entity-change-intent.types';
import type { EntityExecutionSourceByOrigin } from './entity-change-schedule.contract';
import { decodeEntityExecutionSource } from './entity-change-source-codec';
import type { GraphNode } from '../recycle-bin/graph-capturer.service';
import {assertTargetHealthObservation} from '../../infrastructure/kong/target-health-observation';
import type { EntityChangeBaselineCapture, EntityChangeBaselineEnvelope, EntityChangeBaselineNormalizedObject, EntityChangeBaselineReceipt,
  EntityChangeExecutionFactsDelegate, EntityChangeExecutionFactsRepository, EntityChangePacketAttemptBinding, EntityChangePacketFact, EntityChangeRecoveryLink } from './entity-change-execution-facts.types';

const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const hex=/^[a-f\d]{64}$/;
const native=new Set(['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis','targets',...CREDENTIAL_KINDS]);
const changed=(code='ENTITY_CHANGE_EXECUTION_FACT_INVALID')=>new ConflictException({code});
const iso=(value:any)=>{const date=new Date(value);if(!Number.isFinite(date.getTime()))throw changed();return date.toISOString();};
export function entityBaselineAad(cid:string,wid:string,id:string):string{return `entity-change-baseline:${cid}:${wid}:${id}:material`;}
export function entityPacketFactAad(cid:string,wid:string,attemptId:string,kind:string):string{return `entity-change-packet-fact:${cid}:${wid}:${attemptId}:${kind}`;}

/** An append-only evidence repository. It does not capture, create sources,
 * expose HTTP endpoints, schedule, send native requests or mint permits. */
@Injectable()
export class EntityChangeExecutionFactsService implements EntityChangeExecutionFactsRepository {
  private delegate?:Readonly<EntityChangeExecutionFactsDelegate>;
  constructor(private readonly db:DbService,private readonly secrets:SecretService){}
  installFixedDelegate(delegate:EntityChangeExecutionFactsDelegate):void{
    const keys=['verifySource','verifyCapture','verifyPacketFact','assertHistoricalRead','verifyRetention','verifyRecovery'] as const;
    if(this.delegate||!delegate||keys.some(key=>typeof delegate[key]!=='function'))throw new Error('Entity execution facts require one complete fixed delegate');
    this.delegate=Object.freeze(Object.fromEntries(keys.map(key=>[key,delegate[key].bind(delegate)]))) as unknown as Readonly<EntityChangeExecutionFactsDelegate>;
  }
  private policy():Readonly<EntityChangeExecutionFactsDelegate>{if(!this.delegate)throw new ServiceUnavailableException({code:'ENTITY_CHANGE_EXECUTION_FACT_POLICY_UNAVAILABLE'});return this.delegate;}
  private proof(value:object):void{if(!value||typeof value!=='object'||Array.isArray(value))throw changed('ENTITY_CHANGE_GENUINE_FACT_REQUIRED');}
  private transaction<T>(tx:DbService|undefined,fn:(tx:DbService)=>Promise<T>):Promise<T>{return tx?fn(tx):this.db.transaction(fn);}
  private unchanged(original:unknown,hmac:string):void{if(this.secrets.fingerprint(original)!==hmac)throw changed('ENTITY_CHANGE_FACT_MUTATED');}
  private async source(id:string,tx:DbService):Promise<EntityExecutionSourceByOrigin>{
    if(!uuid.test(id))throw changed();const row=await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE id=$1',[id]);if(!row)throw new NotFoundException({code:'ENTITY_CHANGE_SOURCE_NOT_FOUND'});
    return decodeEntityExecutionSource(row);
  }
  private async packet(source:EntityExecutionSourceByOrigin,key:string,tx:DbService):Promise<EntityChangeNormalizedPacket>{
    const row=await tx.one<any>('SELECT * FROM entity_change_intent_packets WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4 AND packet_key=$5',[source.clusterId,source.workspaceId,source.intentId,source.intentRevision,key]);
    if(!row||row.material_hmac!==source.materialHmac||row.change_digest!==source.changeDigest||row.packet_manifest_hmac!==source.packetManifestHmac)throw changed('ENTITY_CHANGE_PACKET_SOURCE_INVALID');
    return immutableJson({key:row.packet_key,order:row.packet_order,dependencies:row.dependencies,method:row.method,pathHmac:row.path_hmac,nativeType:row.native_type,nativeId:row.native_id,parentId:row.parent_id,credentialKind:row.credential_kind,
      originalNativeId:row.original_native_id,mutationAction:row.mutation_action,permissionAction:row.permission_action,bodyHmac:row.body_hmac,beforeHmac:row.before_hmac});
  }
  private normalize(capture:Readonly<EntityChangeBaselineCapture>):EntityChangeBaselineNormalizedObject[]{
    if(!capture||capture.version!==1||!Array.isArray(capture.objects)||!capture.objects.length||capture.objects.length>10000||!Array.isArray(capture.graphs)||capture.graphs.length>1000
      ||!Array.isArray(capture.blockerCodes)||capture.blockerCodes.length||!Array.isArray(capture.nonreversiblePacketKeys)||capture.nonreversiblePacketKeys.length>1000
      ||capture.nonreversiblePacketKeys.some(key=>typeof key!=='string'||!/^[a-zA-Z\d_.:-]{1,128}$/.test(key))||new Set(capture.nonreversiblePacketKeys).size!==capture.nonreversiblePacketKeys.length
      ||capture.objects.filter(object=>(object.trustedProvenance as any)?.kind==='target-health-observed').length!==capture.nonreversiblePacketKeys.length
      ||Buffer.byteLength(JSON.stringify(capture))>32*1024*1024||Date.parse(iso(capture.observedUntil))<Date.parse(iso(capture.observedFrom)))throw changed('ENTITY_CHANGE_BASELINE_NOT_RECOVERABLE');
    for(const graph of capture.graphs)if(!graph||graph.complete!==true||!Array.isArray(graph.nodes)||!graph.nodes.length||graph.nodes.length>10000||!graph.nodes.some((node:GraphNode)=>node.key===graph.rootKey))throw changed('ENTITY_CHANGE_BASELINE_GRAPH_INCOMPLETE');
    const seen=new Set<string>(),identities=new Set<string>();
    return capture.objects.map(object=>{
      if(!object)throw changed('ENTITY_CHANGE_BASELINE_OBJECT_INVALID');
      const credential=CREDENTIAL_KINDS.includes(object.nativeType as any),parentType=credential?'consumers':object.nativeType==='targets'?'upstreams':undefined;
      if(!object||!native.has(object.nativeType)||!uuid.test(object.nativeId)||typeof object.key!=='string'||!object.key.length||object.key.length>160||seen.has(object.key)
        ||typeof object.affected!=='boolean'||typeof object.present!=='boolean'||!Array.isArray(object.dependencies)||object.dependencies.some((key:string)=>!seen.has(key))||new Set(object.dependencies).size!==object.dependencies.length
        ||object.schemaMaterial===undefined||object.schemaMaterial===null||object.trustedProvenance===undefined||object.trustedProvenance===null
        ||parentType&&(!object.parentId||!uuid.test(object.parentId))||!parentType&&object.parentId!==undefined
        ||credential&&object.credentialKind!==object.nativeType||!credential&&object.credentialKind!==undefined)throw changed('ENTITY_CHANGE_BASELINE_OBJECT_INVALID');
      const identity=`${object.nativeType}:${object.parentId??''}:${object.nativeId}`;if(identities.has(identity))throw changed('ENTITY_CHANGE_BASELINE_OBJECT_DUPLICATE');seen.add(object.key);identities.add(identity);
      if(object.present){
        if(!object.before||typeof object.before!=='object'||(object.before as any).id!==object.nativeId||parentType&&entityReferenceId((object.before as any)[credential?'consumer':'upstream'])!==object.parentId)throw changed();
        if(object.affected){if(object.recovery!=='complete'||!object.restorePayload||typeof object.restorePayload!=='object'||(object.restorePayload as any).id!==object.nativeId
          ||typeof (object.before as any).ttl==='number'&&(object.before as any).ttl>0)throw changed('ENTITY_CHANGE_BASELINE_NOT_RECOVERABLE');}
        else if(object.recovery!=='reference'||object.restorePayload!==undefined)throw changed();
      }else if(!object.affected||object.before!==null||object.recovery!=='absent'||object.restorePayload!==undefined)throw changed();
      if(object.nativeType==='basic-auth'&&object.present&&object.affected){
        const raw=(object.before as any).password,plain=(object.restorePayload as any).password;
        if(typeof plain!=='string'||typeof raw!=='string'||!/^[a-f\d]{40}$/i.test(raw)||createHash('sha1').update(plain+object.parentId).digest('hex')!==raw.toLowerCase())throw changed('BASIC_AUTH_RESTORE_PROVENANCE_INVALID');
      }
      if((object.trustedProvenance as any)?.kind==='target-health-observed'){
        const provenance=object.trustedProvenance as any;
        if(object.nativeType!=='targets'||!object.present||!object.affected||provenance.overrideRecovery!=='unavailable'
          ||provenance.beforeHmac!==this.secrets.fingerprint(object.before))throw changed('TARGET_HEALTH_BASELINE_INVALID');
        assertTargetHealthObservation(provenance.healthBefore,{upstreamId:object.parentId!,target:object.before as Record<string,unknown>},this.secrets);
      }
      return {key:object.key,nativeType:object.nativeType,nativeId:object.nativeId,parentId:object.parentId??null,credentialKind:object.credentialKind??null,affected:object.affected,present:object.present,dependencies:[...object.dependencies],
        beforeHmac:this.secrets.fingerprint(object.before),restoreHmac:object.restorePayload===undefined?null:this.secrets.fingerprint(object.restorePayload),schemaHmac:this.secrets.fingerprint(object.schemaMaterial),provenanceHmac:this.secrets.fingerprint(object.trustedProvenance),recovery:object.recovery};
    });
  }
  private async receipt(row:any,tx:DbService):Promise<EntityChangeBaselineReceipt>{
    const pin=await tx.one<any>('SELECT * FROM entity_change_baseline_pins WHERE baseline_id=$1 ORDER BY pin_version DESC LIMIT 1',[row.id]);if(!pin||pin.baseline_hmac!==row.baseline_hmac||pin.object_manifest_hmac!==row.object_manifest_hmac||pin.source_id!==row.source_id||pin.workflow_execution_id!==row.workflow_execution_id)throw changed('ENTITY_CHANGE_BASELINE_PIN_INVALID');
    return immutableJson({baselineId:row.id,sourceId:row.source_id,pinId:pin.id,baselineHmac:row.baseline_hmac,captureHmac:row.capture_hmac,objectManifestHmac:row.object_manifest_hmac,objectCount:row.object_count,graphCount:row.graph_count,protectedUntil:iso(pin.protected_until)});
  }
  private async ready(id:string,tx:DbService):Promise<{row:any;envelope:EntityChangeBaselineEnvelope;receipt:EntityChangeBaselineReceipt}>{
    if(!uuid.test(id))throw changed();const row=await tx.one<any>('SELECT * FROM entity_change_baselines WHERE id=$1',[id]);if(!row)throw new NotFoundException({code:'ENTITY_CHANGE_BASELINE_NOT_FOUND'});
    const envelope=this.secrets.decrypt<EntityChangeBaselineEnvelope>(row.material_ciphertext,entityBaselineAad(row.cluster_id,row.workspace_id,row.id)),source=await this.source(row.source_id,tx),normalized=this.normalize(envelope.capture);
    if(envelope.version!==1||envelope.baselineId!==row.id||row.readiness!=='ready'||this.secrets.fingerprint(envelope)!==row.baseline_hmac||this.secrets.fingerprint(envelope.source)!==this.secrets.fingerprint(source)
      ||this.secrets.fingerprint(envelope.capture)!==row.capture_hmac||this.secrets.fingerprint(normalized)!==row.object_manifest_hmac||this.secrets.fingerprint(row.object_manifest)!==row.object_manifest_hmac
      ||row.object_count!==normalized.length||row.graph_count!==envelope.capture.graphs.length||iso(row.observed_from)!==envelope.capture.observedFrom||iso(row.observed_until)!==envelope.capture.observedUntil
      ||row.cluster_id!==source.clusterId||row.workspace_id!==source.workspaceId||row.intent_id!==source.intentId||row.intent_revision!==source.intentRevision||row.material_hmac!==source.materialHmac||row.change_digest!==source.changeDigest||row.packet_manifest_hmac!==source.packetManifestHmac
      ||row.workflow_id!==source.workflowId||row.workflow_plan_revision!==source.workflowPlanRevision||row.workflow_plan_hash!==source.workflowPlanHash||row.workflow_execution_id!==source.workflowExecutionId||row.execution_actor_id!==source.executionActorId||String(row.credential_epoch)!==source.credentialEpoch)throw changed('ENTITY_CHANGE_BASELINE_MATERIAL_INVALID');
    const rows=await tx.query<any>('SELECT * FROM entity_change_baseline_objects WHERE baseline_id=$1 ORDER BY object_order',[id]);
    const objects=rows.map(object=>({key:object.object_key,nativeType:object.native_type,nativeId:object.native_id,parentId:object.parent_id,credentialKind:object.credential_kind,affected:object.affected,present:object.present,dependencies:object.dependencies,
      beforeHmac:object.before_hmac,restoreHmac:object.restore_hmac,schemaHmac:object.schema_hmac,provenanceHmac:object.provenance_hmac,recovery:object.recovery}));
    if(rows.length!==row.object_count||rows.some((object,index)=>object.object_order!==index+1||object.cluster_id!==source.clusterId||object.workspace_id!==source.workspaceId||object.object_manifest_hmac!==row.object_manifest_hmac)
      ||this.secrets.fingerprint(objects)!==row.object_manifest_hmac)throw changed('ENTITY_CHANGE_BASELINE_MANIFEST_INVALID');
    if(envelope.capture.nonreversiblePacketKeys.length){
      const expected=await this.healthManifest(envelope.capture,source,tx),actual=await tx.query<any>(`SELECT packet_key AS "packetKey",object_key AS "objectKey",native_id AS "nativeId",upstream_id AS "upstreamId",
        before_hmac AS "beforeHmac",provenance_hmac AS "provenanceHmac",node_id AS "nodeId",health,health_row_hmac AS "healthRowHmac",observation_hmac AS "observationHmac"
        FROM entity_change_target_health_baselines WHERE baseline_id=$1 ORDER BY packet_key`,[row.id]);
      if(this.secrets.fingerprint(actual)!==this.secrets.fingerprint(expected))throw changed('TARGET_HEALTH_BASELINE_MANIFEST_INVALID');
    }
    return {row,envelope:immutableJson(envelope),receipt:await this.receipt(row,tx)};
  }
  private async healthManifest(capture:Readonly<EntityChangeBaselineCapture>,source:EntityExecutionSourceByOrigin,tx:DbService){
    const facts=[];
    for(const key of [...capture.nonreversiblePacketKeys].sort()){
      const packet=await this.packet(source,key,tx),object=capture.objects.find(item=>item.nativeType==='targets'&&item.nativeId===packet.nativeId&&item.parentId===packet.parentId);
      const provenance=object?.trustedProvenance as any;
      if(packet.nativeType!=='targets'||packet.method!=='POST'||packet.originalNativeId||packet.credentialKind||!packet.parentId
        ||!['mark_healthy','mark_unhealthy'].includes(packet.mutationAction)||packet.permissionAction!=='write'||packet.bodyHmac!==this.secrets.fingerprint(null)
        ||!object?.affected||!object.present||this.secrets.fingerprint(object.before)!==packet.beforeHmac||provenance?.kind!=='target-health-observed'
        ||provenance.overrideRecovery!=='unavailable')throw changed('TARGET_HEALTH_BASELINE_INVALID');
      const health=assertTargetHealthObservation(provenance.healthBefore,{upstreamId:packet.parentId,target:object.before as Record<string,unknown>},this.secrets);
      facts.push({packetKey:key,objectKey:object.key,nativeId:packet.nativeId,upstreamId:packet.parentId,beforeHmac:packet.beforeHmac,
        provenanceHmac:this.secrets.fingerprint(provenance),nodeId:health.nodeId,health:health.health,healthRowHmac:this.secrets.fingerprint(health.targetRow),observationHmac:health.observationHmac});
    }
    return facts;
  }
  async persistReady(sourceId:string,capture:Readonly<EntityChangeBaselineCapture>,rootProof:object,tx?:DbService):Promise<EntityChangeBaselineReceipt>{
    this.proof(rootProof);const policy=this.policy(),originalHmac=this.secrets.fingerprint(capture),frozen=immutableJson(capture),normalized=this.normalize(frozen);
    const days=Number(process.env.ENTITY_BASELINE_RETENTION_DAYS??30);if(!Number.isInteger(days)||days<30||days>3650)throw new Error('ENTITY_BASELINE_RETENTION_DAYS must be 30–3650');
    return this.transaction(tx,async db=>{
      await policy.verifySource(sourceId,'capture',db);await policy.verifyCapture(sourceId,capture,rootProof,db);this.unchanged(capture,originalHmac);
      const source=await this.source(sourceId,db),existing=await db.one<any>('SELECT id,capture_hmac FROM entity_change_baselines WHERE source_id=$1',[sourceId]);
      if(existing){const loaded=await this.ready(existing.id,db);if(existing.capture_hmac!==originalHmac)throw changed('ENTITY_CHANGE_BASELINE_ALREADY_PINNED');return loaded.receipt;}
      if(Date.parse(frozen.observedFrom)<Date.parse(source.issuedAt)||Date.parse(frozen.observedUntil)>Date.parse(source.expiresAt))throw changed('ENTITY_CHANGE_BASELINE_SOURCE_WINDOW');
      const baselineId=randomUUID(),pinId=randomUUID(),envelope:EntityChangeBaselineEnvelope={version:1,baselineId,source,capture:frozen},baselineHmac=this.secrets.fingerprint(envelope),manifestHmac=this.secrets.fingerprint(normalized);
      if(Buffer.byteLength(JSON.stringify(envelope))>32*1024*1024)throw changed('ENTITY_CHANGE_BASELINE_BUDGET');
      await db.exec(`INSERT INTO entity_change_baselines(id,cluster_id,workspace_id,source_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,workflow_id,workflow_plan_revision,workflow_plan_hash,workflow_execution_id,execution_actor_id,credential_epoch,baseline_hmac,capture_hmac,object_manifest_hmac,object_manifest,object_count,graph_count,material_ciphertext,observed_from,observed_until)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20,$21,$22,$23,$24)`,[baselineId,source.clusterId,source.workspaceId,sourceId,source.intentId,source.intentRevision,source.materialHmac,source.changeDigest,source.packetManifestHmac,source.workflowId,source.workflowPlanRevision,source.workflowPlanHash,source.workflowExecutionId,source.executionActorId,source.credentialEpoch,baselineHmac,originalHmac,manifestHmac,JSON.stringify(normalized),normalized.length,frozen.graphs.length,this.secrets.encrypt(envelope,entityBaselineAad(source.clusterId,source.workspaceId,baselineId)),frozen.observedFrom,frozen.observedUntil]);
      for(const [index,object] of normalized.entries())await db.exec(`INSERT INTO entity_change_baseline_objects(cluster_id,workspace_id,baseline_id,object_manifest_hmac,object_key,object_order,native_type,native_id,parent_id,credential_kind,affected,present,dependencies,before_hmac,restore_hmac,schema_hmac,provenance_hmac,recovery)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,[source.clusterId,source.workspaceId,baselineId,manifestHmac,object.key,index+1,object.nativeType,object.nativeId,object.parentId,object.credentialKind,object.affected,object.present,object.dependencies,object.beforeHmac,object.restoreHmac,object.schemaHmac,object.provenanceHmac,object.recovery]);
      for(const health of await this.healthManifest(frozen,source,db))await db.exec(`INSERT INTO entity_change_target_health_baselines(cluster_id,workspace_id,baseline_id,object_manifest_hmac,object_key,packet_key,native_id,upstream_id,before_hmac,provenance_hmac,node_id,health,health_row_hmac,observation_hmac)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,[source.clusterId,source.workspaceId,baselineId,manifestHmac,health.objectKey,health.packetKey,health.nativeId,health.upstreamId,health.beforeHmac,health.provenanceHmac,health.nodeId,health.health,health.healthRowHmac,health.observationHmac]);
      await db.exec(`INSERT INTO entity_change_baseline_pins(id,cluster_id,workspace_id,baseline_id,source_id,workflow_execution_id,baseline_hmac,object_manifest_hmac,pin_version,protected_until)
        SELECT $1,cluster_id,workspace_id,id,source_id,workflow_execution_id,baseline_hmac,object_manifest_hmac,1,created_at+$3::integer*interval '1 day' FROM entity_change_baselines WHERE id=$2`,[pinId,baselineId,days]);
      await policy.verifySource(sourceId,'capture',db);this.unchanged(capture,originalHmac);return (await this.ready(baselineId,db)).receipt;
    });
  }
  async assertReadyForPacket(sourceId:string,baselineId:string,packetKey:string,tx?:DbService):Promise<{source:EntityExecutionSourceByOrigin;baseline:EntityChangeBaselineReceipt;capture:EntityChangeBaselineCapture;packet:EntityChangeNormalizedPacket}>{
    const db=tx??this.db;await this.policy().verifySource(sourceId,'packet',db);const loaded=await this.ready(baselineId,db);if(loaded.row.source_id!==sourceId)throw changed('ENTITY_CHANGE_BASELINE_SOURCE_INVALID');
    const source=loaded.envelope.source,packet=await this.packet(source,packetKey,db),health=['mark_healthy','mark_unhealthy'].includes(packet.mutationAction);
    const object=loaded.envelope.capture.objects.find(item=>item.nativeType===packet.nativeType&&item.nativeId===packet.nativeId&&(item.parentId??null)===packet.parentId&&(item.credentialKind??null)===packet.credentialKind);
    if(!object?.affected||object.present!==(packet.method!=='POST'||health))throw changed('ENTITY_CHANGE_PACKET_BASELINE_INCOMPLETE');
    if(health){
      if(packet.nativeType!=='targets'||packet.method!=='POST'||!packet.parentId||packet.originalNativeId||packet.credentialKind
        ||!loaded.envelope.capture.nonreversiblePacketKeys.includes(packet.key)||(object.trustedProvenance as any)?.kind!=='target-health-observed'
        ||this.secrets.fingerprint(object.before)!==packet.beforeHmac)throw changed('TARGET_HEALTH_BASELINE_INVALID');
      assertTargetHealthObservation((object.trustedProvenance as any).healthBefore,{upstreamId:packet.parentId,target:object.before as Record<string,unknown>},this.secrets);
    }else if(loaded.envelope.capture.nonreversiblePacketKeys.includes(packet.key))throw changed('TARGET_HEALTH_BASELINE_INVALID');
    if(packet.originalNativeId&&packet.mutationAction!=='restore'&&!loaded.envelope.capture.objects.some(item=>item.affected&&item.present&&item.nativeType===packet.nativeType&&item.nativeId===packet.originalNativeId&&(item.parentId??null)===packet.parentId))throw changed('ENTITY_CHANGE_PACKET_BASELINE_INCOMPLETE');
    return immutableJson({source,baseline:loaded.receipt,capture:loaded.envelope.capture,packet});
  }
  async appendAttempt(binding:Readonly<EntityChangePacketAttemptBinding>,rootProof:object,tx?:DbService):Promise<EntityChangePacketAttemptBinding>{
    this.proof(rootProof);const hmac=this.secrets.fingerprint(binding),frozen=immutableJson(binding);if(!uuid.test(frozen.attemptId)||!uuid.test(frozen.pinId))throw changed();
    return this.transaction(tx,async db=>{await this.policy().verifyPacketFact(binding,null,rootProof,db);this.unchanged(binding,hmac);
      const ready=await this.assertReadyForPacket(frozen.sourceId,frozen.baselineId,frozen.packetKey,db),{source,packet}=ready;
      const pin=await db.one<any>('SELECT * FROM entity_change_baseline_pins WHERE id=$1 AND baseline_id=$2',[frozen.pinId,frozen.baselineId]);if(!pin||pin.source_id!==source.id||pin.workflow_execution_id!==source.workflowExecutionId)throw changed('ENTITY_CHANGE_BASELINE_PIN_INVALID');
      const prior=await db.one<any>('SELECT * FROM entity_change_packet_attempts WHERE source_id=$1 AND packet_key=$2',[source.id,packet.key]);
      if(prior)throw changed('ENTITY_CHANGE_PACKET_ALREADY_ATTEMPTED');
      await db.exec(`INSERT INTO entity_change_packet_attempts(id,cluster_id,workspace_id,source_id,baseline_id,pin_id,workflow_execution_id,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,packet_key,packet_order,method,path_hmac,native_type,native_id,parent_id,credential_kind,original_native_id,permission_action,mutation_action,body_hmac,before_hmac)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,[frozen.attemptId,source.clusterId,source.workspaceId,source.id,frozen.baselineId,frozen.pinId,source.workflowExecutionId,source.intentId,source.intentRevision,source.materialHmac,source.changeDigest,source.packetManifestHmac,packet.key,packet.order,packet.method,packet.pathHmac,packet.nativeType,packet.nativeId,packet.parentId,packet.credentialKind,packet.originalNativeId,packet.permissionAction,packet.mutationAction,packet.bodyHmac,packet.beforeHmac]);
      this.unchanged(binding,hmac);return frozen;});
  }
  async appendSendIntent(fact:Extract<EntityChangePacketFact,{kind:'send-intent'}>,rootProof:object,tx?:DbService):Promise<{eventId:string;factHmac:string}>{return this.appendEvent(fact,rootProof,tx);}
  async appendOutcome(fact:Extract<EntityChangePacketFact,{kind:'outcome'}>,rootProof:object,tx?:DbService):Promise<{eventId:string;factHmac:string}>{return this.appendEvent(fact,rootProof,tx);}
  private async appendEvent(fact:EntityChangePacketFact,rootProof:object,tx?:DbService):Promise<{eventId:string;factHmac:string}>{
    this.proof(rootProof);const hash=this.secrets.fingerprint(fact),frozen=immutableJson(fact),binding=frozen.binding;
    if(frozen.version!==1||!['send-intent','outcome'].includes(frozen.kind)||Buffer.byteLength(JSON.stringify(frozen))>4*1024*1024||iso(frozen.observedAt)!==frozen.observedAt)throw changed();
    if(frozen.kind==='outcome'&&(!['succeeded','native-rejected','sent-unknown','rejected-before-send','failed-known-not-sent'].includes(frozen.outcome)
      ||frozen.outcome==='succeeded'&&(!Number.isInteger(frozen.nativeStatus)||frozen.nativeStatus!<200||frozen.nativeStatus!>299||frozen.errorCode!==undefined)
      ||frozen.outcome==='native-rejected'&&(!Number.isInteger(frozen.nativeStatus)||frozen.nativeStatus!<400||frozen.nativeStatus!>499)
      ||['rejected-before-send','failed-known-not-sent'].includes(frozen.outcome)&&frozen.nativeStatus!==undefined||frozen.errorCode!==undefined&&!/^[A-Z0-9_]{1,128}$/.test(frozen.errorCode)))throw changed();
    return this.transaction(tx,async db=>{
      await this.policy().verifySource(binding.sourceId,frozen.kind==='send-intent'?'before-send':'outcome',db);await this.policy().verifyPacketFact(fact.binding,fact,rootProof,db);this.unchanged(fact,hash);
      await db.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-change-attempt:'||$1,0))",[binding.attemptId]);
      const attempt=await db.one<any>('SELECT * FROM entity_change_packet_attempts WHERE id=$1',[binding.attemptId]);
      if(!attempt||attempt.source_id!==binding.sourceId||attempt.baseline_id!==binding.baselineId||attempt.pin_id!==binding.pinId||attempt.packet_key!==binding.packetKey)throw changed('ENTITY_CHANGE_ATTEMPT_BINDING_INVALID');
      const previous=await db.one<any>('SELECT * FROM entity_change_packet_events WHERE attempt_id=$1 AND event_kind=$2',[binding.attemptId,frozen.kind]);
      if(previous){if(previous.fact_hmac!==hash)throw changed('ENTITY_CHANGE_PACKET_OUTCOME_IMMUTABLE');return {eventId:previous.id,factHmac:hash};}
      if(frozen.kind==='send-intent')await this.assertReadyForPacket(binding.sourceId,binding.baselineId,binding.packetKey,db);
      const eventId=randomUUID();await db.exec(`INSERT INTO entity_change_packet_events(id,cluster_id,workspace_id,attempt_id,source_id,baseline_id,pin_id,workflow_execution_id,event_kind,outcome,native_status,error_code,fact_hmac,fact_ciphertext,observed_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,[eventId,attempt.cluster_id,attempt.workspace_id,binding.attemptId,binding.sourceId,binding.baselineId,binding.pinId,attempt.workflow_execution_id,frozen.kind,
        frozen.kind==='outcome'?frozen.outcome:null,frozen.kind==='outcome'?frozen.nativeStatus??null:null,frozen.kind==='outcome'?frozen.errorCode??null:null,hash,this.secrets.encrypt(frozen,entityPacketFactAad(attempt.cluster_id,attempt.workspace_id,binding.attemptId,frozen.kind)),frozen.observedAt]);
      this.unchanged(fact,hash);return {eventId,factHmac:hash};
    });
  }
  async historicalProjection(cid:string,wid:string,id:string,actor:EntityActor,tx?:DbService):Promise<unknown>{
    const db=tx??this.db;if(actor.workspaceId!==wid)throw new ForbiddenException({code:'ENTITY_CHANGE_SCOPE_MISMATCH'});await this.policy().assertHistoricalRead(id,actor,db);
    const loaded=await this.ready(id,db);if(loaded.row.cluster_id!==cid||loaded.row.workspace_id!==wid)throw new NotFoundException({code:'ENTITY_CHANGE_BASELINE_NOT_FOUND'});
    return {baseline:loaded.receipt,intentId:loaded.envelope.source.intentId,workflowId:loaded.envelope.source.workflowId,observedFrom:loaded.envelope.capture.observedFrom,observedUntil:loaded.envelope.capture.observedUntil,
      recovery:{state:loaded.envelope.capture.nonreversiblePacketKeys.length?'contains-nonreversible':'complete',
        nonreversiblePacketKeys:loaded.envelope.capture.nonreversiblePacketKeys,
        ...(loaded.envelope.capture.nonreversiblePacketKeys.length?{rollbackUnavailableReason:'TARGET_HEALTH_OVERRIDE_ROLLBACK_UNAVAILABLE'}:{}),
        totalObjects:loaded.envelope.capture.objects.length,affectedObjects:loaded.envelope.capture.objects.filter(object=>object.affected).length,
        presentObjects:loaded.envelope.capture.objects.filter(object=>object.present).length,absentObjects:loaded.envelope.capture.objects.filter(object=>!object.present).length,
        referenceObjects:loaded.envelope.capture.objects.filter(object=>!object.affected).length},nativeAuthority:false};
  }
  async extendRetention(baselineId:string,protectedUntil:string,rootProof:object,tx?:DbService):Promise<EntityChangeBaselineReceipt>{
    this.proof(rootProof);const until=iso(protectedUntil);return this.transaction(tx,async db=>{
      await this.policy().verifyRetention(baselineId,until,rootProof,db);
      await db.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-change-baseline-pin:'||$1,0))",[baselineId]);
      const loaded=await this.ready(baselineId,db),prior=await db.one<any>('SELECT * FROM entity_change_baseline_pins WHERE baseline_id=$1 ORDER BY pin_version DESC LIMIT 1',[baselineId]);
      if(!prior||Date.parse(until)<=Date.parse(iso(prior.protected_until)))throw changed('ENTITY_CHANGE_PIN_CANNOT_SHORTEN');
      await db.exec(`INSERT INTO entity_change_baseline_pins(id,cluster_id,workspace_id,baseline_id,source_id,workflow_execution_id,baseline_hmac,object_manifest_hmac,pin_version,previous_pin_id,protected_until)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[randomUUID(),loaded.row.cluster_id,loaded.row.workspace_id,baselineId,loaded.row.source_id,loaded.row.workflow_execution_id,loaded.row.baseline_hmac,loaded.row.object_manifest_hmac,prior.pin_version+1,prior.id,until]);return this.receipt(loaded.row,db);
    });
  }
  async linkRecovery(link:Readonly<EntityChangeRecoveryLink>,rootProof:object,tx?:DbService):Promise<{linkId:string}>{
    this.proof(rootProof);const hash=this.secrets.fingerprint(link),frozen=immutableJson(link);if(!uuid.test(frozen.actorId)||!uuid.test(frozen.newIntentId)||!Number.isInteger(frozen.newIntentRevision)||frozen.newIntentRevision<1
      ||!hex.test(frozen.newMaterialHmac)||!hex.test(frozen.newChangeDigest)||!hex.test(frozen.newPacketManifestHmac)||!hex.test(frozen.requestHmac)||typeof frozen.idempotencyKey!=='string'||frozen.idempotencyKey.length<8||frozen.idempotencyKey.length>128)throw changed();
    return this.transaction(tx,async db=>{await this.policy().verifyRecovery(link,rootProof,db);this.unchanged(link,hash);const loaded=await this.ready(frozen.baselineId,db),source=loaded.envelope.source;
      if(source.clusterId!==frozen.clusterId||source.workspaceId!==frozen.workspaceId||frozen.newIntentId===source.intentId)throw changed();
      const closed=await db.one<any>(`SELECT e.state,EXISTS(SELECT 1 FROM entity_change_packet_events result WHERE result.baseline_id=$1 AND result.outcome='sent-unknown') AS unknown,
        EXISTS(SELECT 1 FROM entity_change_packet_attempts a WHERE a.baseline_id=$1 AND NOT EXISTS(SELECT 1 FROM entity_change_packet_events result WHERE result.attempt_id=a.id AND result.event_kind='outcome')) AS pending
        FROM workflow_executions e WHERE e.id=$2`,[frozen.baselineId,source.workflowExecutionId]);
      if(!closed||!['succeeded','partial','failed'].includes(closed.state)||closed.unknown!==false||closed.pending!==false)throw changed('ENTITY_CHANGE_RECOVERY_OUTCOME_UNRESOLVED');
      const pin=await db.one<any>('SELECT * FROM entity_change_baseline_pins WHERE id=$1 AND baseline_id=$2',[frozen.pinId,frozen.baselineId]);if(!pin||pin.source_id!==source.id)throw changed();
      const existing=await db.one<any>('SELECT * FROM entity_change_recovery_links WHERE actor_id=$1 AND idempotency_key=$2',[frozen.actorId,frozen.idempotencyKey]);
      if(existing){if(existing.request_hmac!==frozen.requestHmac||existing.baseline_id!==frozen.baselineId||existing.pin_id!==frozen.pinId||existing.new_intent_id!==frozen.newIntentId||existing.new_intent_revision!==frozen.newIntentRevision||existing.new_material_hmac!==frozen.newMaterialHmac||existing.new_change_digest!==frozen.newChangeDigest||existing.new_packet_manifest_hmac!==frozen.newPacketManifestHmac)throw changed('IDEMPOTENCY_CONFLICT');return {linkId:existing.id};}
      const id=randomUUID();await db.exec(`INSERT INTO entity_change_recovery_links(id,cluster_id,workspace_id,baseline_id,pin_id,source_id,workflow_execution_id,new_intent_id,new_intent_revision,new_material_hmac,new_change_digest,new_packet_manifest_hmac,actor_id,idempotency_key,request_hmac)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,[id,source.clusterId,source.workspaceId,frozen.baselineId,frozen.pinId,source.id,source.workflowExecutionId,frozen.newIntentId,frozen.newIntentRevision,frozen.newMaterialHmac,frozen.newChangeDigest,frozen.newPacketManifestHmac,frozen.actorId,frozen.idempotencyKey,frozen.requestHmac]);this.unchanged(link,hash);return {linkId:id};
    });
  }
}
