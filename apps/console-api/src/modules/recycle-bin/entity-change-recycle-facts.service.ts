import { ConflictException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { assertKongPath } from '../../infrastructure/kong/policy';
import { entityReferenceId } from '../entities/entity-reference';
import { CREDENTIAL_KINDS } from '../entities/entities.types';
import type { EntityChangePacket, PreparedEntityChange } from '../entities/entity-change.types';
import { decodeEntityExecutionSource } from '../workflows/entity-change-source-codec';
import { entityChangeIntentAad, normalizedEntityChangePackets } from '../workflows/entity-change-workflow';
import { entityBaselineAad, entityPacketFactAad } from '../workflows/entity-change-execution-facts.service';
import type { EntityChangeBaselineCapture, EntityChangeBaselineEnvelope } from '../workflows/entity-change-execution-facts.types';
import type { EntityExecutionSourceByOrigin } from '../workflows/entity-change-schedule.contract';
import type { GraphNode, RecycleGraph } from './graph-capturer.service';
import type { EntityPreparedRecycleNodeManifest } from './entity-prepared-recycle-writer.types';
import { PARTIAL_RECYCLE_FACTS_MIGRATION, partialRestoreNodeIdentity, partialRestoreObservationAad, validatePartialRecycleRestoreSelection } from './partial-recycle-restore';
import type { PreparedRecycleObligation, PreparedRecycleRestoreObligation } from './entity-prepared-recycle-writer.types';
import { derivePreparedRecyclePackets } from './entity-prepared-recycle-writer.service';
import type { EntityChangeRecycleArchiveFactsInput, EntityChangeRecycleCompletionFactsInput, EntityChangeRecycleFactsBinding,
  EntityChangeRecycleFactsDelegate, EntityChangeRecycleRestoreFactsInput, EntityChangeRecycleDeleteVerification } from './entity-change-recycle-facts.types';

const uuid=/^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
const key=/^[a-zA-Z\d_.:-]{1,160}$/;
const object=(value:any):value is Record<string,any>=>!!value&&typeof value==='object'&&!Array.isArray(value);
const credential=(type:string)=>CREDENTIAL_KINDS.includes(type as any);
const invalid=(code='ENTITY_RECYCLE_FACT_INVALID')=>new ConflictException({code});
const iso=(value:any)=>{const date=new Date(value);if(!Number.isFinite(date.getTime()))throw invalid();return date.toISOString();};

/** Append-only SQL023 evidence. This provider has no controller, gateway,
 * execution context, source creator, handle registry or native permission.
 * It never edits a legacy entry/graph or an observed outcome. */
@Injectable()
export class EntityChangeRecycleFactsService {
  private delegate?:Readonly<EntityChangeRecycleFactsDelegate>;
  constructor(private readonly db:DbService,private readonly secrets:SecretService){}
  installFixedDelegate(delegate:EntityChangeRecycleFactsDelegate):void{
    const methods=['verifyArchive','verifyRestore','verifyCompletion'] as const;
    if(this.delegate||!delegate||methods.some(method=>typeof delegate[method]!=='function'))throw new Error('Recycle facts require one complete fixed verifier');
    this.delegate=Object.freeze(Object.fromEntries(methods.map(method=>[method,delegate[method].bind(delegate)]))) as unknown as Readonly<EntityChangeRecycleFactsDelegate>;
  }
  private policy(){if(!this.delegate)throw new ServiceUnavailableException({code:'ENTITY_RECYCLE_FACT_POLICY_UNAVAILABLE'});return this.delegate;}
  private proof(proof:object):void{if(!proof||typeof proof!=='object'||Array.isArray(proof))throw invalid('ENTITY_RECYCLE_GENUINE_PROOF_REQUIRED');}
  private same(actual:unknown,expected:unknown):void{if(this.secrets.fingerprint(actual)!==this.secrets.fingerprint(expected))throw invalid();}
  private unchanged(value:unknown,hash:string):void{if(this.secrets.fingerprint(value)!==hash)throw invalid('ENTITY_RECYCLE_FACT_MUTATED');}
  private transaction<T>(tx:DbService|undefined,fn:(tx:DbService)=>Promise<T>):Promise<T>{return tx?fn(tx):this.db.transaction(fn);}
  private async lock(tx:DbService,id:string):Promise<void>{await tx.exec("SELECT pg_advisory_xact_lock(hashtextextended('entity-change-recycle-entry:'||$1,0))",[id]);}
  private tuple(row:any,source:EntityExecutionSourceByOrigin):void{
    if(!row||row.cluster_id!==source.clusterId||row.workspace_id!==source.workspaceId||row.intent_id!==source.intentId||row.intent_revision!==source.intentRevision
      ||row.material_hmac!==source.materialHmac||row.change_digest!==source.changeDigest||row.packet_manifest_hmac!==source.packetManifestHmac)throw invalid();
  }
  private parent(graph:Readonly<RecycleGraph>,node:Readonly<GraphNode>):string|undefined{
    if(node.type!=='targets'&&!credential(node.type))return undefined;
    const parentId=entityReferenceId(node.data[node.type==='targets'?'upstream':'consumer']),type=node.type==='targets'?'upstreams':'consumers';
    if(!parentId||!uuid.test(parentId)||!graph.nodes.some(parent=>parent.type===type&&parent.id===parentId&&node.dependencies.includes(parent.key)))throw invalid();
    return parentId;
  }
  private restore(node:Readonly<GraphNode>):Record<string,any>{
    if(node.restorable!==true||!object(node.restoreData)||node.restoreData.id!==node.id||typeof node.data.ttl==='number'&&node.data.ttl>0)throw invalid();
    const {created_at:_created,updated_at:_updated,ttl:_ttl,...body}=node.restoreData;return body;
  }
  private ordered(graph:Readonly<RecycleGraph>):Readonly<GraphNode>[] {
    if(!graph||graph.complete!==true||graph.purpose==='migration'||graph.purpose==='baseline'||!Array.isArray(graph.nodes)||!graph.nodes.length||graph.nodes.length>1000
      ||Buffer.byteLength(JSON.stringify(graph))>16*1024*1024)throw invalid();
    const nodes=new Map<string,Readonly<GraphNode>>();
    for(const node of graph.nodes){if(!node||!key.test(node.key)||nodes.has(node.key)||!uuid.test(node.id)||!object(node.data)||node.data.id!==node.id
      ||typeof node.affected!=='boolean'||!Array.isArray(node.dependencies)||node.dependencies.some(dep=>!key.test(dep))||new Set(node.dependencies).size!==node.dependencies.length)throw invalid();
      assertKongPath('GET',node.path);nodes.set(node.key,node);}
    if(!nodes.has(graph.rootKey)||!nodes.get(graph.rootKey)!.affected)throw invalid();
    // Preserve the fixed writer's original DFS tie order. A second topology
    // algorithm can legitimately order independent nodes differently and
    // would then change the immutable normalized manifest/packet sequence.
    const visited=new Set<string>(),visiting=new Set<string>(),result:Readonly<GraphNode>[]=[];
    const visit=(nodeKey:string):void=>{if(visited.has(nodeKey))return;const node=nodes.get(nodeKey);
      if(!node||visiting.has(nodeKey))throw invalid('ENTITY_RECYCLE_GRAPH_DEPENDENCY_INVALID');
      visiting.add(nodeKey);for(const dependency of node.dependencies)visit(dependency);
      visiting.delete(nodeKey);visited.add(nodeKey);result.push(node);};
    for(const node of graph.nodes)visit(node.key);
    return result;
  }
  private manifest(graph:Readonly<RecycleGraph>):EntityPreparedRecycleNodeManifest[]{
    return this.ordered(graph).map((node,index)=>{const parentId=this.parent(graph,node),path=parentId?`/${node.type==='targets'?'upstreams':'consumers'}/${parentId}/${node.type}/${node.id}`:`/${node.type}/${node.id}`;
      if(path!==node.path)throw invalid();
      if(node.affected&&node.type==='basic-auth'){const plain=this.restore(node).password,raw=node.data.password;
        if(typeof plain!=='string'||typeof raw!=='string'||!parentId||createHash('sha1').update(plain+parentId).digest('hex')!==raw.toLowerCase())throw invalid('BASIC_AUTH_RESTORE_PROVENANCE_INVALID');}
      return{key:node.key,order:index+1,nativeType:node.type,nativeId:node.id,parentId:parentId??null,credentialKind:credential(node.type)?node.type:null,
        affected:node.affected,dependencies:node.dependencies,pathHmac:this.secrets.fingerprint(node.path),dataHmac:this.secrets.fingerprint(node.data),restoreHmac:node.affected?this.secrets.fingerprint(this.restore(node)):null};});
  }
  private baselineManifest(capture:EntityChangeBaselineCapture):unknown[]{
    if(capture.version!==1||!Array.isArray(capture.objects)||!capture.objects.length||capture.objects.length>10000||!Array.isArray(capture.graphs)
      ||capture.blockerCodes.length||capture.nonreversiblePacketKeys.length)throw invalid();
    return capture.objects.map(item=>({key:item.key,nativeType:item.nativeType,nativeId:item.nativeId,parentId:item.parentId??null,credentialKind:item.credentialKind??null,
      affected:item.affected,present:item.present,dependencies:item.dependencies,beforeHmac:this.secrets.fingerprint(item.before),
      restoreHmac:item.restorePayload===undefined?null:this.secrets.fingerprint(item.restorePayload),schemaHmac:this.secrets.fingerprint(item.schemaMaterial),
      provenanceHmac:this.secrets.fingerprint(item.trustedProvenance),recovery:item.recovery}));
  }
  private async binding(input:EntityChangeRecycleFactsBinding,tx:DbService):Promise<{source:EntityExecutionSourceByOrigin;capture:EntityChangeBaselineCapture;material:PreparedEntityChange}>{
    const sourceRow=await tx.one<any>('SELECT * FROM entity_change_execution_sources WHERE id=$1',[input.source.id]);
    const source=decodeEntityExecutionSource(sourceRow);this.same(source,input.source);
    if(input.actor.user.id!==source.executionActorId||input.actor.workspaceId!==source.workspaceId||input.baseline.sourceId!==source.id)throw invalid();
    const b=await tx.one<any>('SELECT * FROM entity_change_baselines WHERE id=$1',[input.baseline.baselineId]);this.tuple(b,source);
    if(b.source_id!==source.id||b.workflow_execution_id!==source.workflowExecutionId||b.readiness!=='ready'||b.workflow_id!==source.workflowId
      ||b.workflow_plan_revision!==source.workflowPlanRevision||b.workflow_plan_hash!==source.workflowPlanHash||b.execution_actor_id!==source.executionActorId||String(b.credential_epoch)!==source.credentialEpoch)throw invalid();
    const envelope=this.secrets.decrypt<EntityChangeBaselineEnvelope>(b.material_ciphertext,entityBaselineAad(source.clusterId,source.workspaceId,b.id)),manifest=this.baselineManifest(envelope.capture);
    if(envelope.version!==1||envelope.baselineId!==b.id||b.baseline_hmac!==this.secrets.fingerprint(envelope)||b.capture_hmac!==this.secrets.fingerprint(envelope.capture)
      ||b.object_manifest_hmac!==this.secrets.fingerprint(manifest)||b.object_count!==manifest.length||b.graph_count!==envelope.capture.graphs.length
      ||iso(b.observed_from)!==envelope.capture.observedFrom||iso(b.observed_until)!==envelope.capture.observedUntil)throw invalid();
    this.same(envelope.source,source);this.same(b.object_manifest,manifest);
    const objects=await tx.query<any>('SELECT * FROM entity_change_baseline_objects WHERE baseline_id=$1 ORDER BY object_order',[b.id]);
    if(objects.length!==manifest.length||objects.some((row,index)=>row.object_order!==index+1||row.cluster_id!==source.clusterId||row.workspace_id!==source.workspaceId||row.object_manifest_hmac!==b.object_manifest_hmac))throw invalid();
    this.same(objects.map(row=>({key:row.object_key,nativeType:row.native_type,nativeId:row.native_id,parentId:row.parent_id,credentialKind:row.credential_kind,affected:row.affected,present:row.present,
      dependencies:row.dependencies,beforeHmac:row.before_hmac,restoreHmac:row.restore_hmac,schemaHmac:row.schema_hmac,provenanceHmac:row.provenance_hmac,recovery:row.recovery})),manifest);
    const pin=await tx.one<any>('SELECT * FROM entity_change_baseline_pins WHERE id=$1 AND baseline_id=$2',[input.baseline.pinId,b.id]);
    if(!pin||pin.cluster_id!==source.clusterId||pin.workspace_id!==source.workspaceId||pin.source_id!==source.id||pin.workflow_execution_id!==source.workflowExecutionId
      ||pin.baseline_hmac!==b.baseline_hmac||pin.object_manifest_hmac!==b.object_manifest_hmac)throw invalid();
    this.same(input.baseline,{baselineId:b.id,sourceId:source.id,pinId:pin.id,baselineHmac:b.baseline_hmac,captureHmac:b.capture_hmac,objectManifestHmac:b.object_manifest_hmac,
      objectCount:b.object_count,graphCount:b.graph_count,protectedUntil:iso(pin.protected_until)});
    const version=await tx.one<any>('SELECT * FROM entity_change_intent_versions WHERE intent_id=$1 AND cluster_id=$2 AND workspace_id=$3 AND intent_revision=$4',[source.intentId,source.clusterId,source.workspaceId,source.intentRevision]);this.tuple(version,source);
    const intent=this.secrets.decrypt<any>(version.envelope_ciphertext,entityChangeIntentAad(source.clusterId,source.workspaceId,source.intentId,source.intentRevision)),material=intent.prepared as PreparedEntityChange;
    if(![1,2].includes(intent.version)||intent.intentId!==source.intentId||intent.revision!==source.intentRevision||intent.requesterId!==source.executionActorId
      ||intent.clusterId!==source.clusterId||intent.workspaceId!==source.workspaceId||intent.credentialEpoch!==source.credentialEpoch||this.secrets.fingerprint(intent)!==source.materialHmac)throw invalid();
    const {changeDigest,...original}=material;if(changeDigest!==source.changeDigest||this.secrets.fingerprint(original)!==changeDigest)throw invalid();
    const packets=normalizedEntityChangePackets(material,this.secrets),rows=await tx.query<any>('SELECT * FROM entity_change_intent_packets WHERE cluster_id=$1 AND workspace_id=$2 AND intent_id=$3 AND intent_revision=$4 ORDER BY packet_order',[source.clusterId,source.workspaceId,source.intentId,source.intentRevision]);
    if(packets.length!==version.packet_count||packets.length!==rows.length||intent.packetManifestHmac!==source.packetManifestHmac||this.secrets.fingerprint(packets)!==source.packetManifestHmac)throw invalid();
    this.same(version.packet_manifest,packets);for(const [index,row]of rows.entries()){this.tuple(row,source);this.same(this.packetTuple(row),packets[index]);}
    return{source,capture:envelope.capture,material:immutableJson(material)};
  }
  private packetTuple(row:any){return{key:row.packet_key,order:row.packet_order,dependencies:row.dependencies,method:row.method,pathHmac:row.path_hmac,nativeType:row.native_type,nativeId:row.native_id,
    parentId:row.parent_id,credentialKind:row.credential_kind,originalNativeId:row.original_native_id,mutationAction:row.mutation_action,permissionAction:row.permission_action,bodyHmac:row.body_hmac,beforeHmac:row.before_hmac};}
  private subset(obligation:PreparedRecycleObligation,packets:readonly Readonly<EntityChangePacket>[]):Array<{node:Readonly<GraphNode>;packet:Readonly<EntityChangePacket>}>{
    // One canonical parser matches the original sealed compiler packets in
    // both the writer and SQL023 evidence. This proves explicit SNI ordering
    // and Target original/allocated ID mapping; it grants no native rights.
    return derivePreparedRecyclePackets(obligation,packets,this.secrets);
  }
  private selected(material:PreparedEntityChange,obligation:unknown,packets:readonly Readonly<EntityChangePacket>[]):void{
    if(!material.metadataObligations.some(item=>this.secrets.fingerprint(item)===this.secrets.fingerprint(obligation)))throw invalid();
    for(const packet of packets){const actual=material.packets.find(item=>item.key===packet.key);if(!actual)throw invalid();this.same(actual,packet);}
  }
  private async entry(tx:DbService,id:string,source:EntityExecutionSourceByOrigin,graph:Readonly<RecycleGraph>,states:string[]):Promise<any>{
    if(!uuid.test(id))throw invalid();const entry=await tx.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND id=$2',[source.clusterId,id]);
    if(!entry||entry.cluster_id!==source.clusterId||entry.workspace_id!==source.workspaceId||entry.mutation_id!==null||!states.includes(entry.state)||typeof entry.payload_secret!=='string')throw invalid();
    this.same(this.secrets.decrypt(entry.payload_secret,`recycle:${id}`),graph);return entry;
  }
  private async insertPackets(tx:DbService,binding:EntityChangeRecycleFactsBinding,entryId:string,subset:ReturnType<EntityChangeRecycleFactsService['subset']>,direction:'delete'|'restore'):Promise<void>{
    const s=binding.source,b=binding.baseline;
    const prior=await tx.query<any>('SELECT * FROM entity_change_recycle_packets WHERE source_id=$1 AND entry_id=$2 ORDER BY packet_order',[s.id,entryId]);
    if(prior.length){if(prior.length!==subset.length)throw invalid();for(const [index,row]of prior.entries())this.same(row,this.packetRow(binding,entryId,subset[index].node,subset[index].packet,direction,row.created_at));return;}
    for(const {node,packet:p}of subset)await tx.exec(`INSERT INTO entity_change_recycle_packets(cluster_id,workspace_id,source_id,baseline_id,pin_id,workflow_execution_id,entry_id,node_key,direction,intent_id,intent_revision,material_hmac,change_digest,packet_manifest_hmac,packet_key,packet_order,method,path_hmac,native_type,native_id,parent_id,credential_kind,original_native_id,permission_action,mutation_action,body_hmac,before_hmac)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)`,[s.clusterId,s.workspaceId,s.id,b.baselineId,b.pinId,s.workflowExecutionId,entryId,node.key,direction,s.intentId,s.intentRevision,s.materialHmac,s.changeDigest,s.packetManifestHmac,p.key,p.order,p.method,this.secrets.fingerprint(p.canonicalPath),p.nativeType,p.nativeId,p.parentId??null,p.credentialKind??null,p.originalNativeId??null,p.permissionAction,p.mutationAction,p.bodyHmac,p.beforeHmac]);
  }
  private packetRow(binding:EntityChangeRecycleFactsBinding,entryId:string,node:Readonly<GraphNode>,p:Readonly<EntityChangePacket>,direction:'delete'|'restore',created:any){const s=binding.source,b=binding.baseline;return{cluster_id:s.clusterId,workspace_id:s.workspaceId,source_id:s.id,baseline_id:b.baselineId,pin_id:b.pinId,workflow_execution_id:s.workflowExecutionId,
    entry_id:entryId,node_key:node.key,direction,intent_id:s.intentId,intent_revision:s.intentRevision,material_hmac:s.materialHmac,change_digest:s.changeDigest,packet_manifest_hmac:s.packetManifestHmac,packet_key:p.key,packet_order:p.order,
    method:p.method,path_hmac:this.secrets.fingerprint(p.canonicalPath),native_type:p.nativeType,native_id:p.nativeId,parent_id:p.parentId??null,credential_kind:p.credentialKind??null,original_native_id:p.originalNativeId??null,
    permission_action:p.permissionAction,mutation_action:p.mutationAction,body_hmac:p.bodyHmac,before_hmac:p.beforeHmac,created_at:created};}
  private async verifyStoredArchive(tx:DbService,entryId:string,graph:Readonly<RecycleGraph>):Promise<any>{
    const row=await tx.one<any>('SELECT * FROM entity_change_recycle_archives WHERE entry_id=$1',[entryId]),manifest=this.manifest(graph);
    if(!row||row.graph_hmac!==this.secrets.fingerprint(graph)||row.payload_hmac!==row.graph_hmac||row.node_manifest_hmac!==this.secrets.fingerprint(manifest)||row.node_count!==manifest.length
      ||row.packet_count!==manifest.filter(node=>node.affected).length||row.root_key!==graph.rootKey)throw invalid();this.same(row.node_manifest,manifest);
    const nodes=await tx.query<any>('SELECT * FROM entity_change_recycle_nodes WHERE entry_id=$1 ORDER BY node_order',[entryId]);
    if(nodes.length!==manifest.length||nodes.some(node=>node.cluster_id!==row.cluster_id||node.workspace_id!==row.workspace_id))throw invalid();
    this.same(nodes.map(node=>({key:node.node_key,order:node.node_order,nativeType:node.native_type,nativeId:node.native_id,parentId:node.parent_id,credentialKind:node.credential_kind,
      affected:node.affected,dependencies:node.dependencies,pathHmac:node.path_hmac,dataHmac:node.data_hmac,restoreHmac:node.restore_hmac})),manifest);return row;
  }
  async persistArchive(input:Readonly<EntityChangeRecycleArchiveFactsInput>,proof:object,tx?:DbService):Promise<{entryId:string}>{
    this.proof(proof);const policy=this.policy(),hash=this.secrets.fingerprint(input),value=immutableJson(input);this.unchanged(value,hash);
    return this.transaction(tx,async db=>{await this.lock(db,value.grant.entryId);await policy.verifyArchive(input,proof,db);this.unchanged(input,hash);
      const g=value.grant,{source,capture,material}=await this.binding(g,db),graph=g.obligation.graph,manifest=this.manifest(graph),subset=this.subset(g.obligation,g.packets);
      this.selected(material,g.obligation,g.packets);this.same(g.obligation.packetKeys,g.packets.map(packet=>packet.key));
      const root=graph.nodes.find(node=>node.key===graph.rootKey)!,entry=await this.entry(db,g.entryId,source,graph,['archived']);
      if(entry.actor_id!==source.executionActorId||entry.node_count!==manifest.length||entry.original_id!==root.id||entry.root_type!==(credential(root.type)?'credentials':root.type)
        ||(entry.parent_id??null)!==(this.parent(graph,root)??null)||(entry.credential_kind??null)!==(credential(root.type)?root.type:null)
        ||iso(entry.expires_at)!==g.expiresAt||g.obligation.graphHmac!==this.secrets.fingerprint(graph))throw invalid();
      this.same(value.receipt,{entryId:g.entryId,graphHmac:g.obligation.graphHmac,payloadHmac:this.secrets.fingerprint(graph),nodeManifestHmac:this.secrets.fingerprint(manifest),nodeCount:manifest.length,packetCount:subset.length});
      const captured=capture.graphs.find(item=>item.rootKey===graph.rootKey);if(!captured||captured.nodes.length!==graph.nodes.length)throw invalid();
      this.same([...captured.nodes].sort((a,b)=>a.key.localeCompare(b.key)),[...graph.nodes].sort((a,b)=>a.key.localeCompare(b.key)));
      const legacy=await db.query<any>('SELECT * FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key',[g.entryId]);
      if(legacy.length!==manifest.length||manifest.some(node=>{const row=legacy.find(row=>row.node_key===node.key);return !row||row.entity_type!==node.nativeType||row.original_id!==node.nativeId||row.affected!==node.affected||this.secrets.fingerprint(row.dependencies)!==this.secrets.fingerprint(node.dependencies);}))throw invalid();
      const prior=await db.one<any>('SELECT * FROM entity_change_recycle_archives WHERE entry_id=$1',[g.entryId]);
      if(prior){await this.verifyStoredArchive(db,g.entryId,graph);if(prior.cluster_id!==source.clusterId||prior.workspace_id!==source.workspaceId||prior.actor_id!==source.executionActorId
          ||prior.source_id!==source.id||prior.baseline_id!==g.baseline.baselineId||prior.pin_id!==g.baseline.pinId||prior.workflow_execution_id!==source.workflowExecutionId)throw invalid();}
      else{
        await db.exec(`INSERT INTO entity_change_recycle_archives(entry_id,cluster_id,workspace_id,source_id,baseline_id,pin_id,workflow_execution_id,actor_id,root_key,graph_hmac,payload_hmac,node_manifest_hmac,node_manifest,node_count,packet_count)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15)`,[g.entryId,source.clusterId,source.workspaceId,source.id,g.baseline.baselineId,g.baseline.pinId,source.workflowExecutionId,source.executionActorId,graph.rootKey,g.obligation.graphHmac,value.receipt.payloadHmac,value.receipt.nodeManifestHmac,JSON.stringify(manifest),manifest.length,subset.length]);
        for(const node of manifest)await db.exec(`INSERT INTO entity_change_recycle_nodes(cluster_id,workspace_id,entry_id,node_key,node_order,native_type,native_id,parent_id,credential_kind,affected,dependencies,path_hmac,data_hmac,restore_hmac)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,[source.clusterId,source.workspaceId,g.entryId,node.key,node.order,node.nativeType,node.nativeId,node.parentId,node.credentialKind,node.affected,node.dependencies,node.pathHmac,node.dataHmac,node.restoreHmac]);
      }
      await this.insertPackets(db,g,g.entryId,subset,'delete');await this.verifyStoredArchive(db,g.entryId,graph);
      await policy.verifyArchive(input,proof,db);this.unchanged(input,hash);return{entryId:g.entryId};});
  }
  private async presentRows(db:DbService,input:Readonly<EntityChangeRecycleRestoreFactsInput>,capture:Readonly<EntityChangeBaselineCapture>):Promise<Array<{row:Record<string,any>;fact:unknown}>>{
    const obligation=input.obligation,selection=obligation.partialRestore;if(!selection)throw invalid();
    const partition=validatePartialRecycleRestoreSelection(obligation.graph,selection,this.secrets),history=selection.history,s=input.source,b=input.baseline;
    if(history.clusterId!==s.clusterId||history.workspaceId!==s.workspaceId||history.entryId!==input.entryId||history.sourceId===s.id
      ||capture.objects.length!==7||b.objectCount!==7)throw invalid();
    for(const node of obligation.graph.nodes){
      const matched=capture.objects.filter(item=>partialRestoreNodeIdentity(item)===partialRestoreNodeIdentity(node)),current=matched[0],present=partition.present.some(item=>item.key===node.key),parent=this.parent(obligation.graph,node);
      if(matched.length!==1)throw invalid();
      if(!current||current.nativeType!==node.type||current.nativeId!==node.id||(current.parentId??null)!==(parent??null)
        ||(current.credentialKind??null)!==(credential(node.type)?node.type:null)||current.present!==present||current.affected!==!present
        ||current.recovery!==(present?'reference':'absent')||current.restorePayload!==undefined||!present&&current.before!==null)throw invalid();
      this.same(current.dependencies,node.dependencies);
    }
    const rows=[];
    for(const node of partition.present){
      const prior=history.presentNodes.find(item=>item.nodeKey===node.key)!,selected=selection.presentNodes.find(item=>item.nodeKey===node.key)!,current=capture.objects.find(item=>partialRestoreNodeIdentity(item)===partialRestoreNodeIdentity(node))!;
      const priorReceipt=await db.one<any>('SELECT * FROM entity_change_recycle_receipts WHERE attempt_id=$1',[prior.attemptId]);
      if(!priorReceipt||priorReceipt.cluster_id!==s.clusterId||priorReceipt.workspace_id!==s.workspaceId||priorReceipt.source_id!==history.sourceId
        ||priorReceipt.entry_id!==input.entryId||priorReceipt.node_key!==node.key||priorReceipt.packet_key!==prior.packetKey||priorReceipt.operation_id!==prior.operationId
        ||priorReceipt.operation_key!==prior.operationKey||priorReceipt.native_id!==node.id||priorReceipt.direction!=='restore'||priorReceipt.result_hmac!==prior.resultHmac
        ||this.secrets.fingerprint(current.before)!==selected.beforeHmac||selected.beforeHmac!==prior.resultHmac)throw invalid();
      const provenance={kind:'closed-restore-current-present',nodeKey:node.key,historyCoverageHmac:history.coverageHmac,priorSourceId:history.sourceId,
        priorAttemptId:prior.attemptId,priorOperationId:prior.operationId,priorResultHmac:prior.resultHmac,beforeHmac:selected.beforeHmac,
        ...(selected.basicCustodyHmac?{basicCustodyHmac:selected.basicCustodyHmac}:{})};
      this.same(current.trustedProvenance,provenance);
      const observedAt=capture.observedUntil,fact={version:1,kind:'closed-restore-current-present',sourceId:s.id,baselineId:b.baselineId,pinId:b.pinId,
        clusterId:s.clusterId,workspaceId:s.workspaceId,workflowExecutionId:s.workflowExecutionId,entryId:input.entryId,nodeKey:node.key,baselineObjectKey:current.key,
        priorHistory:prior,closedSourceHmac:history.coverageHmac,currentBefore:current.before,provenance,observedAt};
      const row={cluster_id:s.clusterId,workspace_id:s.workspaceId,source_id:s.id,baseline_id:b.baselineId,pin_id:b.pinId,workflow_execution_id:s.workflowExecutionId,
        entry_id:input.entryId,node_key:node.key,direction:'restore',baseline_object_key:current.key,object_manifest_hmac:b.objectManifestHmac,
        native_type:node.type,native_id:node.id,parent_id:this.parent(obligation.graph,node)??null,credential_kind:credential(node.type)?node.type:null,
        prior_attempt_id:prior.attemptId,prior_operation_id:prior.operationId,prior_source_id:history.sourceId,prior_packet_key:prior.packetKey,
        observed_before_hmac:selected.beforeHmac,prior_result_hmac:prior.resultHmac,closed_source_hmac:history.coverageHmac,
        basic_custody_hmac:selected.basicCustodyHmac??null,fact_hmac:this.secrets.fingerprint(fact),observed_at:observedAt};
      rows.push({row,fact});
    }
    return rows;
  }
  private async persistPresentFacts(db:DbService,input:Readonly<EntityChangeRecycleRestoreFactsInput>,capture:Readonly<EntityChangeBaselineCapture>):Promise<void>{
    const migration=await db.one<any>('SELECT name,checksum FROM schema_migrations WHERE name=$1',[PARTIAL_RECYCLE_FACTS_MIGRATION.name]);
    if(!migration||migration.checksum!==PARTIAL_RECYCLE_FACTS_MIGRATION.checksum)throw new ServiceUnavailableException({code:'ENTITY_RECYCLE_PARTIAL_SCHEMA_UNAVAILABLE'});
    const rows=await this.presentRows(db,input,capture),existing=await db.query<any>('SELECT * FROM entity_change_recycle_restore_present_facts WHERE source_id=$1 AND entry_id=$2 ORDER BY node_key',[input.source.id,input.entryId]);
    if(existing.length){await this.assertPresentRows(input,rows,existing);return;}
    for(const {row,fact}of rows){const columns=Object.keys(row),ciphertext=this.secrets.encrypt(fact,partialRestoreObservationAad(input.source.clusterId,input.source.workspaceId,input.source.id,input.entryId,row.node_key));
      await db.exec(`INSERT INTO entity_change_recycle_restore_present_facts(${columns.join(',')},fact_ciphertext) VALUES(${[...columns,'fact_ciphertext'].map((_,index)=>`$${index+1}`).join(',')})`,[...columns.map(column=>row[column]),ciphertext]);}
  }
  private async assertPresentRows(input:Readonly<EntityChangeRecycleRestoreFactsInput>,expected:Array<{row:Record<string,any>;fact:unknown}>,stored:any[]):Promise<void>{
    if(stored.length!==5||new Set(stored.map(row=>row.node_key)).size!==5)throw invalid();
    for(const item of expected){const row=stored.find(value=>value.node_key===item.row.node_key);if(!row)throw invalid();
      const normalized={...row};delete normalized.created_at;delete normalized.fact_ciphertext;normalized.observed_at=iso(row.observed_at);this.same(normalized,item.row);
      if(typeof row.fact_ciphertext!=='string')throw invalid();
      const fact=this.secrets.decrypt(row.fact_ciphertext,partialRestoreObservationAad(input.source.clusterId,input.source.workspaceId,input.source.id,input.entryId,row.node_key));
      this.same(fact,item.fact);if(this.secrets.fingerprint(fact)!==row.fact_hmac)throw invalid();}
  }
  /** Read-only revalidation. Original current Root handles are checked by the
   * coordinator before this method; rows/JSON alone never authorize a send. */
  async assertPresentFacts(input:Readonly<EntityChangeRecycleRestoreFactsInput>,tx:DbService=this.db):Promise<void>{
    if(!input.obligation.partialRestore)throw invalid();
    const migration=await tx.one<any>('SELECT name,checksum FROM schema_migrations WHERE name=$1',[PARTIAL_RECYCLE_FACTS_MIGRATION.name]);
    if(!migration||migration.checksum!==PARTIAL_RECYCLE_FACTS_MIGRATION.checksum)throw new ServiceUnavailableException({code:'ENTITY_RECYCLE_PARTIAL_SCHEMA_UNAVAILABLE'});
    const {capture,material}=await this.binding(input,tx);this.selected(material,input.obligation,input.packets);
    const expected=await this.presentRows(tx,input,capture),stored=await tx.query<any>('SELECT * FROM entity_change_recycle_restore_present_facts WHERE source_id=$1 AND entry_id=$2 ORDER BY node_key',[input.source.id,input.entryId]);
    await this.assertPresentRows(input,expected,stored);
  }
  async bindRestore(input:Readonly<EntityChangeRecycleRestoreFactsInput>,proof:object,tx?:DbService):Promise<{entryId:string;packetCount:number}>{
    this.proof(proof);const policy=this.policy(),hash=this.secrets.fingerprint(input),value=immutableJson(input);this.unchanged(value,hash);
    return this.transaction(tx,async db=>{await this.lock(db,value.entryId);await policy.verifyRestore(input,proof,db);this.unchanged(input,hash);
      const {source,capture,material}=await this.binding(value,db),graph=value.obligation.graph,subset=this.subset(value.obligation,value.packets);
      if(value.obligation.entryId!==value.entryId||value.obligation.graphHmac!==this.secrets.fingerprint(graph))throw invalid();
      this.selected(material,value.obligation,value.packets);this.same(value.obligation.packetKeys,value.packets.map(packet=>packet.key));
      await this.entry(db,value.entryId,source,graph,['deleted','partially_deleted','restoring',...(value.obligation.partialRestore?['partially_restored']:[])]);const archive=await this.verifyStoredArchive(db,value.entryId,graph);
      if(archive.cluster_id!==source.clusterId||archive.workspace_id!==source.workspaceId||archive.source_id===source.id)throw invalid();
      for(const {packet}of subset){const matches=capture.objects.filter(item=>item.nativeType===packet.nativeType&&item.nativeId===packet.nativeId&&(item.parentId??null)===(packet.parentId??null)),absent=matches[0];
        // A Target replacement is already authenticated by the canonical
        // originalNativeId mapping above. Its newly sealed UUID needs its
        // own actual absence baseline; the historical UUID cannot stand in.
        if(matches.length!==1||!absent.affected||absent.present||absent.before!==null||absent.recovery!=='absent'||absent.restorePayload!==undefined
          ||(absent.credentialKind??null)!==(packet.credentialKind??null))throw invalid();}
      if(value.obligation.partialRestore)await this.persistPresentFacts(db,value,capture);
      await this.insertPackets(db,value,value.entryId,subset,'restore');await policy.verifyRestore(input,proof,db);this.unchanged(input,hash);return{entryId:value.entryId,packetCount:subset.length};});
  }
  async linkNode(input:Readonly<EntityChangeRecycleCompletionFactsInput>,proof:object,tx?:DbService):Promise<{attemptId:string}>{
    this.proof(proof);const policy=this.policy(),hash=this.secrets.fingerprint(input),value=immutableJson(input);this.unchanged(value,hash);
    return this.transaction(tx,async db=>{await this.lock(db,value.grant.entryId);await policy.verifyCompletion(input,proof,db);this.unchanged(input,hash);
      const g=value.grant,{source,material}=await this.binding(g,db),direction=g.packet.method==='DELETE'?'delete':'restore',graph=g.obligation.graph,subset=this.subset(g.obligation,g.packets);
      this.selected(material,g.obligation,g.packets);const selected=subset.find(item=>item.packet.key===g.packet.key&&item.node.key===g.nodeKey);if(!selected)throw invalid();this.same(selected.packet,g.packet);
      await this.entry(db,g.entryId,source,graph,['deleting','partially_deleted','deleted','restoring','partially_restored','restored']);const archive=await this.verifyStoredArchive(db,g.entryId,graph);
      if(archive.cluster_id!==source.clusterId||archive.workspace_id!==source.workspaceId||direction==='delete'&&(archive.source_id!==source.id||archive.baseline_id!==g.baseline.baselineId||archive.pin_id!==g.baseline.pinId)
        ||direction==='restore'&&archive.source_id===source.id||g.operationKey!==`entity-${source.workflowExecutionId}-${g.packet.order}`)throw invalid();
      const packet=await db.one<any>('SELECT * FROM entity_change_recycle_packets WHERE source_id=$1 AND packet_key=$2',[source.id,g.packet.key]);
      this.same(packet,this.packetRow(g,g.entryId,selected.node,g.packet,direction,packet?.created_at));
      const a=await db.one<any>('SELECT * FROM entity_change_packet_attempts WHERE id=$1',[value.attempt.attemptId]);this.tuple(a,source);
      if(a.source_id!==source.id||a.baseline_id!==g.baseline.baselineId||a.pin_id!==g.baseline.pinId||a.workflow_execution_id!==source.workflowExecutionId)throw invalid();
      for(const field of ['packet_key','packet_order','method','path_hmac','native_type','native_id','parent_id','credential_kind','original_native_id','permission_action','mutation_action','body_hmac','before_hmac'])if(a[field]!==packet[field])throw invalid();
      this.same(value.attempt,{sourceId:source.id,baselineId:g.baseline.baselineId,pinId:g.baseline.pinId,packetKey:g.packet.key,attemptId:a.id});
      const receipt=value.receipt,m=await db.one<any>('SELECT * FROM mutation_operations WHERE id=$1',[receipt.operationId]);
      if(!m||m.state!=='succeeded'||m.remote_started!==true||m.remote_completed!==true||typeof m.result_secret!=='string'||typeof m.before_secret!=='string'||typeof m.payload_secret!=='string'
        ||['workflow_execution_id','workflow_plan_revision','workflow_plan_hash','workflow_step_id','configuration_job_id','configuration_execution_id','configuration_step_id','configuration_plan_revision','configuration_plan_hash'].some(field=>m[field]!=null)
        ||m.actor_id!==source.executionActorId||m.cluster_id!==source.clusterId||m.workspace_id!==source.workspaceId
        ||m.workflow_id!==source.workflowId||m.entity_change_source_id!==source.id||m.entity_change_baseline_id!==g.baseline.baselineId||m.entity_change_attempt_id!==a.id||m.entity_change_packet_key!==g.packet.key
        ||m.entity_type!==(g.packet.credentialKind?'credentials':g.packet.nativeType)||m.action!==g.packet.mutationAction||m.entity_id!==g.packet.nativeId
        ||(m.parent_id??null)!==(g.packet.parentId??null)||(m.credential_kind??null)!==(g.packet.credentialKind??null)||m.idempotency_key!==g.operationKey)throw invalid();
      this.same(receipt,{entryId:g.entryId,nodeKey:g.nodeKey,packetKey:g.packet.key,operationKey:g.operationKey,operationId:m.id,nativeId:g.packet.nativeId,state:'succeeded',metadata:'complete'});
      const raw=this.secrets.decrypt(m.result_secret,`mutation:${m.id}:result`);this.same(raw,value.nativeResult);
      this.same(this.secrets.decrypt(m.before_secret,`mutation:${m.id}:before`),g.packet.before);
      this.same(this.secrets.decrypt(m.payload_secret,`mutation:${m.id}:payload`),g.packet.body??null);
      const events=await db.query<any>('SELECT * FROM entity_change_packet_events WHERE attempt_id=$1 ORDER BY event_kind',[a.id]);
      if(events.length!==2||new Set(events.map(event=>event.event_kind)).size!==2)throw invalid();const facts:any={};
      for(const event of events){if(!['send-intent','outcome'].includes(event.event_kind)||event.source_id!==source.id||event.baseline_id!==g.baseline.baselineId||event.pin_id!==g.baseline.pinId||event.workflow_execution_id!==source.workflowExecutionId
          ||event.cluster_id!==source.clusterId||event.workspace_id!==source.workspaceId||event.attempt_id!==a.id)throw invalid();
        const fact=this.secrets.decrypt<any>(event.fact_ciphertext,entityPacketFactAad(source.clusterId,source.workspaceId,a.id,event.event_kind));
        if(fact.version!==1||fact.kind!==event.event_kind||this.secrets.fingerprint(fact)!==event.fact_hmac||fact.observedAt!==iso(event.observed_at)||Date.parse(fact.observedAt)<Date.parse(iso(a.created_at))
          ||Date.parse(fact.observedAt)>Date.parse(iso(event.created_at)))throw invalid();
        this.same(fact.binding,value.attempt);facts[event.event_kind]=fact;
        if(event.event_kind==='outcome'&&(fact.outcome!==event.outcome||fact.nativeStatus!==event.native_status||(fact.errorCode??null)!==event.error_code)
          ||event.event_kind==='send-intent'&&(event.outcome!==null||event.native_status!==null||event.error_code!==null))throw invalid();}
      const sent=facts['send-intent'],outcome=facts.outcome,resultHmac=this.secrets.fingerprint(raw);
      if(!sent||!outcome||outcome.outcome!=='succeeded'||!Number.isInteger(outcome.nativeStatus)||outcome.nativeStatus<200||outcome.nativeStatus>299||outcome.errorCode!==undefined
        ||Date.parse(sent.observedAt)<Date.parse(source.issuedAt)||Date.parse(sent.observedAt)>Date.parse(source.expiresAt)||Date.parse(outcome.observedAt)<Date.parse(sent.observedAt)
        ||outcome.evidence?.operationId!==m.id||outcome.evidence?.mutationState!=='succeeded'||outcome.evidence?.remoteCompleted!==true||outcome.evidence?.responseHmac!==resultHmac)throw invalid();
      this.same(sent.evidence,{operationId:m.id,method:g.packet.method,pathHmac:this.secrets.fingerprint(g.packet.canonicalPath),bodyHmac:g.packet.bodyHmac,beforeHmac:g.packet.beforeHmac});
      let verificationHmac:string|null=null;
      if(direction==='delete'){
        if(outcome.nativeStatus!==204||raw!==null)throw invalid();
        let expected:EntityChangeRecycleDeleteVerification;
        if(g.packet.nativeType==='targets'){
          const observed=value.deleteVerification;
          if(!observed||observed.status!=='target-poststate'||observed.kind!=='target-poststate'
            ||observed.nativeId!==g.packet.nativeId||typeof observed.address!=='string'||!observed.address
            ||!['weight-zero-overlay','native-pruned'].includes(observed.historyRetention)
            ||!/^[a-f\d]{64}$/i.test(observed.observationHmac)||!/^[a-f\d]{64}$/i.test(observed.archiveGraphHmac))throw invalid();
          expected={version:1,clusterId:source.clusterId,workspaceId:source.workspaceId,entryId:g.entryId,nodeKey:g.nodeKey,
            packetKey:g.packet.key,attemptId:a.id,operationId:m.id,canonicalPath:g.packet.canonicalPath,nativeId:g.packet.nativeId,
            status:'target-poststate',kind:'target-poststate',historyRetention:observed.historyRetention,
            observationHmac:observed.observationHmac,archiveGraphHmac:observed.archiveGraphHmac,address:observed.address};
        }else{
          expected={version:1,clusterId:source.clusterId,workspaceId:source.workspaceId,entryId:g.entryId,nodeKey:g.nodeKey,
            packetKey:g.packet.key,attemptId:a.id,operationId:m.id,canonicalPath:g.packet.canonicalPath,nativeId:g.packet.nativeId,status:404};
        }
        this.same(value.deleteVerification,expected);this.same(outcome.evidence.deleteVerification,expected);verificationHmac=this.secrets.fingerprint(expected);
      }else if(value.deleteVerification!==undefined||!object(raw)||raw.id!==g.packet.nativeId||(g.packet.credentialKind&&entityReferenceId(raw.consumer)!==g.packet.parentId||g.packet.nativeType==='targets'&&entityReferenceId(raw.upstream)!==g.packet.parentId))throw invalid();
      const row={attempt_id:a.id,cluster_id:source.clusterId,workspace_id:source.workspaceId,source_id:source.id,baseline_id:g.baseline.baselineId,pin_id:g.baseline.pinId,workflow_execution_id:source.workflowExecutionId,
        entry_id:g.entryId,node_key:g.nodeKey,packet_key:g.packet.key,operation_id:m.id,operation_key:g.operationKey,native_id:g.packet.nativeId,direction,result_hmac:resultHmac,verification_hmac:verificationHmac};
      const prior=await db.one<any>('SELECT * FROM entity_change_recycle_receipts WHERE attempt_id=$1',[a.id]);
      if(prior)this.same(prior,{...row,created_at:prior.created_at});
      else await db.exec(`INSERT INTO entity_change_recycle_receipts(attempt_id,cluster_id,workspace_id,source_id,baseline_id,pin_id,workflow_execution_id,entry_id,node_key,packet_key,operation_id,operation_key,native_id,direction,result_hmac,verification_hmac)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,Object.values(row));
      await policy.verifyCompletion(input,proof,db);this.unchanged(input,hash);return{attemptId:a.id};});
  }
}
