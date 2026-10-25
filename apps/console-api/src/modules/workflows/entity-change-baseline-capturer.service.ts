import {ConflictException, HttpException, Injectable} from '@nestjs/common';
import {createHash} from 'node:crypto';
import {KongService} from '../../infrastructure/kong/kong.service';
import {KongExecutionContextService} from '../../infrastructure/kong/execution-context.service';
import {SecretService} from '../../infrastructure/secret.service';
import {immutableJson} from '../../infrastructure/kong/immutable-json';
import {GraphCapturerService, type GraphNode, type RecycleGraph} from '../recycle-bin/graph-capturer.service';
import {CredentialStoreService} from '../credentials/credential-store.service';
import {EntityChangeCompilerService} from '../entities/entity-change-compiler.service';
import {entityReferenceId} from '../entities/entity-reference';
import {readTargetHealthObservation,type TargetHealthObservation} from '../../infrastructure/kong/target-health-observation';
import {CREDENTIAL_KINDS, type EntityActor} from '../entities/entities.types';
import {partialBasicCustodyHmac,partialRestoreNodeIdentity,validatePartialRecycleRestoreSelection} from '../recycle-bin/partial-recycle-restore';
import type {PreparedEntityChange} from '../entities/entity-change.types';
import type {EntityChangeBaselineCapture, EntityChangeBaselineObject} from './entity-change-execution-facts.types';

const stale = (code='ENTITY_CHANGE_BASELINE_CHANGED') => new ConflictException({code, message:'执行前对象图或恢复材料已变化，未发送网关变更'});
const objectKey = (type:string,id:string,parent?:string) => parent?`${type}:${parent}:${id}`:`${type}:${id}`;
const parentOf = (type:string,data:any) => entityReferenceId(type==='targets'?data?.upstream:data?.consumer);
/** Root's fixed capturer. It performs bounded real reads and preserves full
 * native secrets only inside the encrypted baseline. It creates no mutation,
 * session, workflow execution, snapshot identifier or native capability. */
@Injectable()
export class EntityChangeBaselineCapturerService {
  constructor(private readonly kong:KongService,private readonly context:KongExecutionContextService,
    private readonly graphs:GraphCapturerService,private readonly credentials:CredentialStoreService,
    private readonly compiler:EntityChangeCompilerService,private readonly secrets:SecretService) {}

  async capture(material:PreparedEntityChange,actor:EntityActor):Promise<Readonly<EntityChangeBaselineCapture>> {
    const observedFrom=new Date().toISOString();
    await this.compiler.revalidateStored(material,actor,'write','claim');
    const health=new Map<string,Readonly<TargetHealthObservation>>();
    for(const packet of material.packets)if(['mark_healthy','mark_unhealthy'].includes(packet.mutationAction)){
      if(packet.nativeType!=='targets'||!packet.parentId||!packet.before||packet.body!==undefined||packet.originalNativeId)throw stale('TARGET_HEALTH_BASELINE_INVALID');
      health.set(packet.key,await this.observeHealth(material.clusterId,packet.parentId,packet.before,actor));
    }
    const captured:RecycleGraph[]=[],nodes=new Map<string,GraphNode>();
    const partial=material.metadataObligations.filter(o=>o.kind==='recycle-restore'&&o.partialRestore);
    if(partial.length>1)throw stale('ENTITY_RECYCLE_PARTIAL_SELECTION_INVALID');
    const partialObligation=partial[0]?.kind==='recycle-restore'?partial[0]:undefined;
    const partialPartition=partialObligation?.partialRestore?validatePartialRecycleRestoreSelection(partialObligation.graph,partialObligation.partialRestore,this.secrets):undefined;
    let pages=0,records=0,bytes=0;
    const add=(node:GraphNode)=>{
      const prior=nodes.get(node.key);
      if(prior&&this.secrets.fingerprint(prior.data)!==this.secrets.fingerprint(node.data))throw stale();
      if(prior){if(node.affected){prior.affected=true;prior.restoreData=node.restoreData;}return;}
      if(nodes.size>=10000)throw stale('ENTITY_CHANGE_BASELINE_BUDGET');
      nodes.set(node.key,structuredClone(node));
    };
    if(partialObligation&&partialPartition){
      // Capture the currently present Consumer's full bounded graph/collection
      // EOF, independently of the two missing packets. Extra live descendants
      // never disappear by restricting the baseline to caller-chosen IDs.
      const root=partialObligation.graph.nodes.find(node=>node.key===partialObligation.graph.rootKey)!;
      const graph=await this.graphs.capture(material.clusterId,'consumers',root.id,{purpose:'baseline',budget:{maxPages:100,maxRecords:10000,maxNodes:1000,maxBytes:16*1024*1024}});
      if(graph.complete!==true||graph.purpose!=='baseline'||graph.nodes.length!==5||new Set(graph.nodes.map(partialRestoreNodeIdentity)).size!==5
        ||graph.nodes.some(node=>!partialPartition.present.some(item=>partialRestoreNodeIdentity(item)===partialRestoreNodeIdentity(node))))throw stale('ENTITY_RECYCLE_CURRENT_GRAPH_CHANGED');
      pages+=graph.budget?.pages??0;records+=graph.budget?.records??0;bytes+=graph.budget?.bytes??0;captured.push(graph);
      for(const node of graph.nodes){const old=partialObligation.graph.nodes.find(item=>partialRestoreNodeIdentity(item)===partialRestoreNodeIdentity(node))!,observed=partialObligation.partialRestore!.presentNodes.find(item=>item.nodeKey===old.key)!;
        if(this.secrets.fingerprint(node.data)!==observed.beforeHmac||this.secrets.fingerprint(node.dependencies)!==this.secrets.fingerprint(old.dependencies))throw stale('ENTITY_RECYCLE_PRESENT_RESULT_CHANGED');
        add({...node,affected:false,restoreData:undefined,dependencies:[...old.dependencies]});}
    }
    // Every changed existing root is captured with all of its subordinate
    // objects. References remain references; packet count never stands in for
    // graph completeness. Shared graph nodes must agree byte-for-byte.
    for(const packet of material.packets){
      if(packet.before===null)continue;
      const logicalId=(packet.before as any).id??packet.originalNativeId??packet.nativeId;
      const key=objectKey(packet.nativeType,logicalId,packet.parentId);
      if(nodes.get(key)?.affected)continue;
      const graph=await this.graphs.capture(material.clusterId,packet.nativeType,logicalId,{purpose:'baseline',parentId:packet.parentId,
        credentialKind:packet.credentialKind,budget:{maxPages:100-pages,maxRecords:10000-records,maxNodes:10000-nodes.size,maxBytes:32*1024*1024-bytes}});
      if(graph.complete!==true||graph.purpose!=='baseline')throw stale('ENTITY_CHANGE_BASELINE_INCOMPLETE');
      pages+=graph.budget?.pages??0;records+=graph.budget?.records??0;bytes+=graph.budget?.bytes??0;
      captured.push(graph);for(const node of graph.nodes)add(node);
    }
    // Current live references and explicit absence are independently sealed,
    // including restoration whose original archive is historical, not live.
    const absent=new Map<string,{type:string;id:string;parent?:string;path:string;dependencies:string[]}>();
    for(const p of material.prerequisites){
      const id=p.nativeId??(p.before as any)?.id;if(!id)continue;
      const key=objectKey(p.type,id,p.parentId);
      if(p.absent)absent.set(key,{type:p.type,id,parent:p.parentId,path:p.path,dependencies:p.parentId?[objectKey(p.type==='targets'?'upstreams':'consumers',p.parentId)]:[]});
      else if(!nodes.has(key))add({key,type:p.type,id,path:p.path,data:p.before,affected:false,
        dependencies:partialObligation?.graph.nodes.find(node=>node.key===key)?.dependencies??[],restorable:true});
    }
    for(const p of material.packets)if(p.before===null){
      const key=objectKey(p.nativeType,p.nativeId,p.parentId);
      const path=p.method==='POST'?`${p.canonicalPath}/${p.nativeId}`:p.canonicalPath;
      absent.set(key,{type:p.nativeType,id:p.nativeId,parent:p.parentId,path,dependencies:p.parentId?[objectKey(p.nativeType==='targets'?'upstreams':'consumers',p.parentId)]:[]});
    }
    const objects:EntityChangeBaselineObject[]=[];
    const allPaths=[...nodes.values()].map(n=>n.path).concat([...absent.values()].map(n=>n.path));
    if(allPaths.length>500)throw stale('ENTITY_CHANGE_BASELINE_BUDGET');
    const graphFingerprint=(graph:RecycleGraph)=>this.secrets.fingerprint({rootKey:graph.rootKey,
      nodes:[...graph.nodes].sort((a,b)=>a.key.localeCompare(b.key)).map(node=>({...node,dependencies:[...node.dependencies].sort()})),
      targetHistory:[...(graph.targetHistory??[])].sort((a,b)=>a.upstreamId.localeCompare(b.upstreamId)).map(history=>({...history,items:[...history.items].sort((a,b)=>a.id.localeCompare(b.id))}))});
    // Point observations cannot detect a new subordinate object. Re-enumerate
    // each complete graph, including its collection EOF, before sealing it.
    for(const original of captured){
      const root=original.nodes.find(node=>node.key===original.rootKey);if(!root)throw stale('ENTITY_CHANGE_BASELINE_INCOMPLETE');
      const nested=root.type==='targets'||CREDENTIAL_KINDS.includes(root.type as any),parentId=nested?parentOf(root.type,root.data):undefined;
      const current=await this.graphs.capture(material.clusterId,root.type,root.id,{purpose:'baseline',parentId,credentialKind:CREDENTIAL_KINDS.includes(root.type as any)?root.type:undefined,
        budget:{maxPages:100-pages,maxRecords:10000-records,maxNodes:10000,maxBytes:32*1024*1024-bytes}});
      pages+=current.budget?.pages??0;records+=current.budget?.records??0;bytes+=current.budget?.bytes??0;
      if(graphFingerprint(original)!==graphFingerprint(current))throw stale('ENTITY_CHANGE_BASELINE_GRAPH_CHANGED');
    }
    // A complete second observation rejects a graph assembled across a race.
    // Internal reads remain bounded by the caller's genuine actor frame.
    await this.context.runInternalRead(material.clusterId,'capture',async()=>{
      for(const node of nodes.values()){
        const actual=await this.kong.request(material.clusterId,'GET',node.path);
        if(this.secrets.fingerprint(actual)!==this.secrets.fingerprint(node.data))throw stale();
      }
      for(const node of absent.values()){
        try{await this.kong.request(material.clusterId,'GET',node.path);throw stale('ENTITY_CHANGE_BASELINE_EXPECTED_ABSENCE');}
        catch(error){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;}
      }
    },{maxCalls:Math.max(1,allPaths.length),maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000,workspaceId:material.workspaceId});
    for(const node of nodes.values()){
      const nested=node.type==='targets'||CREDENTIAL_KINDS.includes(node.type as any),parentId=nested?parentOf(node.type,node.data):undefined;
      let provenance:unknown={kind:'native-observed',beforeHmac:this.secrets.fingerprint(node.data)};
      const healthPacket=material.packets.find(packet=>health.has(packet.key)&&packet.nativeType===node.type&&packet.nativeId===node.id&&packet.parentId===parentId);
      if(healthPacket)provenance={kind:'target-health-observed',beforeHmac:this.secrets.fingerprint(node.data),healthBefore:health.get(healthPacket.key),overrideRecovery:'unavailable'};
      if(partialObligation?.partialRestore){
        const archiveNode=partialObligation.graph.nodes.find(item=>partialRestoreNodeIdentity(item)===partialRestoreNodeIdentity(node));if(!archiveNode)throw stale('ENTITY_RECYCLE_CURRENT_GRAPH_CHANGED');
        const selection=partialObligation.partialRestore,prior=selection.history.presentNodes.find(item=>item.nodeKey===archiveNode.key),observed=selection.presentNodes.find(item=>item.nodeKey===archiveNode.key);
        if(!prior||!observed||node.affected||this.secrets.fingerprint(node.data)!==observed.beforeHmac||observed.beforeHmac!==prior.resultHmac)throw stale('ENTITY_RECYCLE_PRESENT_RESULT_CHANGED');
        if(node.type==='basic-auth'){const remembered=await this.credentials.get(material.clusterId,parentId!,'basic-auth',node.id);
          if(partialBasicCustodyHmac(archiveNode,node.data,remembered,parentId!,this.secrets)!==observed.basicCustodyHmac)throw stale('BASIC_AUTH_NOT_RECOVERABLE');}
        provenance={kind:'closed-restore-current-present',nodeKey:archiveNode.key,historyCoverageHmac:selection.history.coverageHmac,priorSourceId:selection.history.sourceId,
          priorAttemptId:prior.attemptId,priorOperationId:prior.operationId,priorResultHmac:prior.resultHmac,beforeHmac:observed.beforeHmac,
          ...(observed.basicCustodyHmac?{basicCustodyHmac:observed.basicCustodyHmac}:{})};
      }
      if(node.affected&&!node.restorable)throw stale(node.reason??'ENTITY_CHANGE_RECOVERY_MATERIAL_MISSING');
      if(node.affected&&node.restoreData===undefined)throw stale('ENTITY_CHANGE_RECOVERY_MATERIAL_MISSING');
      if(node.affected&&node.type==='basic-auth'){
        const remembered=await this.credentials.get(material.clusterId,parentId!,'basic-auth',node.id),password=remembered?.rawInput.password;
        if(typeof password!=='string'||remembered!.credential.password!==node.data.password
          ||createHash('sha1').update(password+parentId).digest('hex')!==node.data.password||node.restoreData.password!==password)throw stale('BASIC_AUTH_NOT_RECOVERABLE');
        provenance={kind:'credential-store-sha1-verified',nativeHashHmac:this.secrets.fingerprint(node.data.password),plaintextHmac:this.secrets.fingerprint(password),rememberedHmac:this.secrets.fingerprint(remembered)};
      }
      const schemaInput={...(node.restoreData??node.data)};delete schemaInput.created_at;delete schemaInput.updated_at;delete schemaInput.ttl;
      if(node.type==='certificates')delete schemaInput.snis;
      if(node.type==='targets')delete schemaInput.upstream;
      const schemaPath=node.type==='targets'?`/upstreams/${parentId}/targets`:node.path;
      // Planning retains the original actor or genuine scheduled namespace.
      // prepareSchema allocates its own bounded, schema-only read capabilities;
      // an enclosing internal-read frame must not acquire no-session authority.
      const schema=await this.kong.prepareSchema(material.clusterId,schemaPath,schemaInput);
      objects.push({key:node.key,nativeType:node.type,nativeId:node.id,...(parentId?{parentId}:{}),
        ...(CREDENTIAL_KINDS.includes(node.type as any)?{credentialKind:node.type as any}:{}),affected:node.affected,present:true,
        dependencies:node.dependencies,before:node.data,...(node.affected?{restorePayload:node.restoreData}:{}),
        schemaMaterial:schema,trustedProvenance:provenance,recovery:node.affected?'complete':'reference'});
    }
    for(const node of absent.values()){
      if(nodes.has(objectKey(node.type,node.id,node.parent)))throw stale('ENTITY_CHANGE_BASELINE_PRESENCE_CONFLICT');
      const packet=material.packets.find(p=>p.nativeType===node.type&&p.nativeId===node.id&&p.parentId===node.parent);
      const schemas=packet?material.schemas.filter(s=>s.canonicalPath===packet.canonicalPath&&s.payloadHmac===packet.bodyHmac):[];
      if(packet&&!schemas.length)throw stale('ENTITY_CHANGE_BASELINE_SCHEMA_MISSING');
      objects.push({key:objectKey(node.type,node.id,node.parent),nativeType:node.type,nativeId:node.id,...(node.parent?{parentId:node.parent}:{}),
        ...(CREDENTIAL_KINDS.includes(node.type as any)?{credentialKind:node.type as any}:{}),affected:!!packet,present:false,
        dependencies:node.dependencies,before:null,schemaMaterial:schemas,
        trustedProvenance:{kind:'native-get-404',pathHmac:this.secrets.fingerprint(node.path)},recovery:'absent'});
    }
    if(partialObligation&&(objects.length!==7||objects.filter(item=>item.present).length!==5||objects.filter(item=>!item.present&&item.affected).length!==2))throw stale('ENTITY_RECYCLE_CURRENT_GRAPH_CHANGED');
    // Stable topological order is part of the persisted normalized manifest.
    const pending=new Map(objects.map(o=>[o.key,o])),ordered:EntityChangeBaselineObject[]=[];
    while(pending.size){const available=[...pending.values()].filter(o=>o.dependencies.every(d=>!pending.has(d))).sort((a,b)=>a.key.localeCompare(b.key));
      if(!available.length)throw stale('ENTITY_CHANGE_BASELINE_DEPENDENCY_CYCLE');
      for(const object of available){ordered.push(object);pending.delete(object.key);}}
    await this.compiler.revalidateStored(material,actor,'write','claim');
    for(const packet of material.packets)if(health.has(packet.key)){
      const after=await this.observeHealth(material.clusterId,packet.parentId!,packet.before,actor);
      if(this.secrets.fingerprint(after)!==this.secrets.fingerprint(health.get(packet.key)))throw stale('TARGET_HEALTH_BASELINE_CHANGED');
    }
    const capture={version:1 as const,observedFrom,observedUntil:new Date().toISOString(),graphs:captured,objects:ordered,blockerCodes:[],nonreversiblePacketKeys:[...health.keys()]};
    if(Buffer.byteLength(JSON.stringify(capture))>32*1024*1024)throw stale('ENTITY_CHANGE_BASELINE_BUDGET');
    return immutableJson(capture);
  }
  /** Bounded raw observations under the caller's genuine actor/read scope.
   * HEALTHCHECKS_OFF, node changes and incomplete health EOF fail closed. */
  async observeHealth(clusterId:string,upstreamId:string,target:unknown,actor:EntityActor):Promise<Readonly<TargetHealthObservation>>{
    return this.context.runInternalRead(clusterId,'capture',()=>readTargetHealthObservation(this.kong,this.secrets,
      {clusterId,upstreamId,target:target as Readonly<Record<string,unknown>>}),
      {paths:['/',`/upstreams/${upstreamId}/health`],workspaceId:actor.workspaceId,maxCalls:22,maxPages:20,maxRecords:2000,maxBytes:4*1024*1024,timeoutMs:30000});
  }
  /** Called by Root inside the first packet's actual Mutation lock. A fresh
   * graph EOF check closes the gap after initial baseline capture; original
   * baseline bytes and retention pins remain immutable. */
  async assertUnchanged(capture:Readonly<EntityChangeBaselineCapture>,material:PreparedEntityChange,actor:EntityActor):Promise<void>{
    const current=await this.capture(material,actor);
    const normalized=(value:Readonly<EntityChangeBaselineCapture>)=>({objects:value.objects,
      graphs:value.graphs.map(graph=>({rootKey:graph.rootKey,nodes:[...graph.nodes].sort((a,b)=>a.key.localeCompare(b.key)),targetHistory:graph.targetHistory??[]}))});
    if(this.secrets.fingerprint(normalized(capture))!==this.secrets.fingerprint(normalized(current)))throw stale('ENTITY_CHANGE_BASELINE_GRAPH_CHANGED');
  }
}
