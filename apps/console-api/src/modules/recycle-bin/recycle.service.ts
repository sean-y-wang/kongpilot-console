import { expectedRecycleDeleteGraph, assertRecycleDeleteGraphCurrent } from './entity-recycle-current-delete-graph';
import { assertOrdinaryRecycleArchiveContract, isOrdinaryRecycleRoot } from './ordinary-recycle-contract';
import { BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable, Logger, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { createHash, createHmac, timingSafeEqual, randomUUID } from 'node:crypto';
import type { AuthUser } from '../../common/auth';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { AuditService } from '../audit/audit.service';
import { nativeAuditScope } from '../event-producers/native-audit-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { CredentialStoreService, CREDENTIAL_KINDS } from '../credentials/credential-store.service';
import { MutationContext, MutationService } from '../mutations/mutation.service';
import { GraphCapturerService, GraphNode, RecycleGraph } from './graph-capturer.service';
import { EntityIndexService } from '../entities/entity-index.service';
import { WorkspaceResolverService, WorkspaceFilter } from '../workspaces/workspace-resolver.service';
import { workspaceTag } from '../../infrastructure/kong/tags';
import { currentEffectiveTarget } from '../../infrastructure/kong/effective-target';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { assertKongPath, entityForPath, ENTITIES } from '../../infrastructure/kong/policy';
import { entityReferenceId, normalizeEntityAuthorizationView } from '../entities/entity-reference';
import type { EntityActor, CredentialKind, EntityType } from '../entities/entities.types';
import type { EntityChangeOperation, EntityChangePacket, EntityChangePrerequisite, EntityChangeMetadataObligation, EntityWriteSchemaMaterial, PreparedEntityChange, StoredEntitySubjectAction } from '../entities/entity-change.types';
import type { EntityRecycleClosedRestoreCoverage, EntityRecycleOriginLookup } from './entity-recycle-origin-reader.types';
import type {ControlBusinessBridge} from '../control-plane/control-metadata.types';
import { partialBasicCustodyHmac, validatePartialRecycleRestoreSelection } from './partial-recycle-restore';

type Entry = {id:string;cluster_id:string;workspace_id?:string|null;root_type:string;original_id:string;root_name:string;state:string;revision:number;payload_secret:string|null;parent_id:string|null;credential_kind:string|null;mutation_id?:string|null;node_count:number;created_at:Date;expires_at:Date};
type Confirmation = boolean | {confirmed:boolean;confirm_name:string};
type RecycleChange = Extract<EntityChangeOperation,{kind:'recycle'}>;
type RecyclePreparation = {graph:RecycleGraph;packets:EntityChangePacket[];schemas:EntityWriteSchemaMaterial[];prerequisites:EntityChangePrerequisite[];metadataObligations:EntityChangeMetadataObligation[]};
type StoredNode = {node_key:string;entity_type:string;original_id:string;affected:boolean;dependencies:string[];delete_state:string;restore_state:string;restored_id:string|null};
const NATIVE_UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Shared dependency ordering for deletion, restoration and later snapshot apply. */
export function graphOrder(graph: RecycleGraph): GraphNode[] {
  const nodes = new Map(graph.nodes.map(node => [node.key,node]));
  const visited = new Set<string>(), visiting = new Set<string>(), ordered:GraphNode[]=[];
  const visit = (key:string) => {
    if (visited.has(key)) return;
    const node=nodes.get(key);
    if (!node) throw new ConflictException({code:'GRAPH_REFERENCE_MISSING',message:'归档依赖图缺少对象'});
    if (visiting.has(key)) throw new ConflictException({code:'GRAPH_CYCLE',message:'归档依赖图存在循环引用'});
    visiting.add(key);
    for (const dependency of node.dependencies) visit(dependency);
    visiting.delete(key);visited.add(key);ordered.push(node);
  };
  for (const node of graph.nodes) visit(node.key);
  return ordered;
}

export function recycleName(node:GraphNode):string {
  // API keys and JWT key values must never become publicly listed confirmation labels.
  const data=node.data;
  return String(data?.name??data?.username??data?.target??node.id);
}

function comparable(value:any):any {
  if (!value || typeof value!=='object') return value;
  // Only Kong entity bookkeeping is ignored; plugin config fields with these names are meaningful.
  return Object.fromEntries(Object.entries(value).filter(([key])=>!['created_at','updated_at','ttl'].includes(key)));
}

@Injectable()
export class RecycleService {
  private readonly logger=new Logger(RecycleService.name);
  private entityOriginLookup?:Readonly<EntityRecycleOriginLookup>;
  private controlBridge?:Readonly<ControlBusinessBridge>;
  constructor(private readonly db:DbService,private readonly secrets:SecretService,private readonly kong:KongService,
    private readonly mutations:MutationService,private readonly capturer:GraphCapturerService,
    private readonly authz:AuthorizationService,private readonly audit:AuditService,private readonly credentials:CredentialStoreService,
    private readonly index:EntityIndexService,private readonly workspaces:WorkspaceResolverService,private readonly execution:KongExecutionContextService){}

  installControlMetadataBridge(bridge:ControlBusinessBridge):void{
    if(this.controlBridge||!bridge||typeof bridge.currentTransaction!=='function'||typeof bridge.execute!=='function')throw new Error('One fixed recycle metadata bridge is required');
    this.controlBridge=Object.freeze(bridge);
  }
  async readControlPurgeConfig(clusterId:string,id:string,tx:DbService=this.db):Promise<Readonly<Record<string,unknown>>|null>{
    const row=await tx.one<any>(`SELECT id,cluster_id,workspace_id,root_type,original_id,root_name,state,parent_id,credential_kind,node_count,
      expires_at,mutation_id,purged_at,revision,payload_secret FROM recycle_entries WHERE cluster_id=$1 AND id=$2 FOR SHARE`,[clusterId,id]);
    if(!row)return null;const {payload_secret,...safe}=row;
    return {...safe,payload_present:typeof payload_secret==='string',payload_hmac:this.secrets.fingerprint(payload_secret??null)};
  }
  async assertControlPurgeSubject(clusterId:string,id:string,actor:AuthUser,action:string,workspaceId:string,tx:DbService=this.db):Promise<void>{
    if(!NATIVE_UUID.test(workspaceId??'')||!['read','delete'].includes(action))throw new ForbiddenException({code:'RECYCLE_PURGE_SCOPE_REQUIRED'});
    await this.authz.assertCluster(actor,clusterId,'recycle-bin',action,workspaceId);
    const entry=await tx.one<Entry>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND id=$2 FOR SHARE',[clusterId,id]);
    if(!entry||entry.workspace_id!==workspaceId)throw new NotFoundException({code:'RECYCLE_ENTRY_NOT_FOUND'});
    if(entry.state==='purged'||!entry.payload_secret)throw new ConflictException({code:'RECYCLE_PURGED'});
    const scope=await this.scope(clusterId,actor,workspaceId,true),graph=this.secrets.decrypt<RecycleGraph>(entry.payload_secret,`recycle:${entry.id}`);
    if(graph.complete!==true||graph.nodes.length!==entry.node_count)throw new ConflictException({code:'RECYCLE_MANIFEST_INVALID'});
    await this.authorizeGraph(clusterId,actor,graph,action,scope,true);
  }
  private async approvedPurge(clusterId:string,id:string,actor:AuthUser,confirmation:Confirmation,request:{requestId?:string;ip?:string;idempotencyKey?:string;workspaceId?:string;revision?:number},tx:DbService):Promise<any>{
    const wid=request.workspaceId;if(!NATIVE_UUID.test(wid??'')||!Number.isSafeInteger(request.revision)||Number(request.revision)<1)throw new BadRequestException({code:'RECYCLE_PURGE_REVISION_REQUIRED'});
    await this.assertControlPurgeSubject(clusterId,id,actor,'delete',wid!,tx);
    const row=await this.readControlPurgeConfig(clusterId,id,tx);if(!row||row.revision!==request.revision)throw new ConflictException({code:'RECYCLE_PURGE_CHANGED'});
    this.validateConfirmation(confirmation,String(row.root_name));
    if((await tx.one<any>('SELECT m11_recycle_purge_available($1,$2) AS eligible',[clusterId,id]))?.eligible!==true)throw new ConflictException({code:'RECYCLE_PURGE_REFERENCED',message:'此归档仍有未终结的变更或恢复引用，不能永久清除'});
    const payload={revision:request.revision,workspaceId:wid,confirmed:true,confirm_name:String(row.root_name)};
    return this.controlBridge!.execute({resource:'recycle-bin',operation:'purge',clusterId,resourceId:id,module:'recycle-bin',action:'delete',workspaceId:wid!,actor:{user:actor,...request,workspaceId:wid},payload},async originalTx=>{
      const step=this.execution.currentApprovedStep();
      if(step.kind!=='metadata'||step.execution.clusterId!==clusterId||step.execution.actorId!==actor.id)throw new ForbiddenException({code:'RECYCLE_PURGE_APPROVED_STEP_REQUIRED'});
      // Lock the original row before the final eligibility/current-authority
      // checks. SQL040 also serializes new restore/configuration references.
      const current=await originalTx.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND id=$2 FOR UPDATE',[clusterId,id]);
      if(!current||current.revision!==request.revision||this.secrets.fingerprint(current.payload_secret??null)!==row.payload_hmac||current.state!==row.state)throw new ConflictException({code:'RECYCLE_PURGE_CHANGED'});
      await this.assertControlPurgeSubject(clusterId,id,actor,'delete',wid!,originalTx);
      if((await originalTx.one<any>('SELECT m11_recycle_purge_available($1,$2) AS eligible',[clusterId,id]))?.eligible!==true)throw new ConflictException({code:'RECYCLE_PURGE_REFERENCED'});
      if(await originalTx.exec(`UPDATE recycle_entries SET state='purged',payload_secret=NULL,purged_at=now(),updated_at=now()
        WHERE cluster_id=$1 AND id=$2 AND workspace_id=$3 AND revision=$4 AND payload_secret=$5 AND state=$6`,[clusterId,id,wid,request.revision,current.payload_secret,current.state])!==1)throw new ConflictException({code:'RECYCLE_PURGE_CHANGED'});
      await this.audit.append({actorId:actor.id,clusterId,workspaceId:wid,entityType:'recycle_entries',entityId:id,action:'purge_recycle',
        before:{entryId:id,state:row.state,revision:row.revision,payloadHmac:row.payload_hmac},after:{entryId:id,state:'purged',revision:Number(row.revision)+1,payloadPresent:false},
        requestId:request.requestId,ip:request.ip,workflowId:step.execution.workflowId},originalTx);
      return {id,purged:true};
    },async()=>{throw new ForbiddenException({code:'RECYCLE_PURGE_APPROVAL_REQUIRED'});});
  }

  /** Fixed bootstrap read-only lookup; NULL legacy mutation_id is not an
   * origin proof and never creates an aggregate Mutation or native permit. */
  installEntityOriginLookup(lookup:EntityRecycleOriginLookup):void{
    if(this.entityOriginLookup||!lookup||typeof lookup.readClosedOrigin!=='function')throw new Error('Recycle requires one fixed entity origin lookup');
    this.entityOriginLookup=Object.freeze({readClosedOrigin:lookup.readClosedOrigin.bind(lookup)});
  }

  private read(clusterId:string,path:string):Promise<any>{return this.execution.runInternalRead(clusterId,'recycle-check',()=>this.kong.request(clusterId,'GET',path),{paths:[path],maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024});}

  private async scope(clusterId:string,actor:AuthUser,workspaceId?:string,archived=false):Promise<WorkspaceFilter>{
    if(archived&&workspaceId&&await this.authz.isPlatformAdmin(actor)){
      const row=await this.workspaces.get(clusterId,workspaceId,true);
      if(row.status!=='active')return {workspaceId:row.id,workspaceRevision:row.revision,mode:row.is_default?'default':'tag',workspaceTag:workspaceTag(row.code),requestedTags:[],tagOperator:'and',requiresPostFilter:true,binding:`archived:${row.id}:${row.revision}`};
    }
    return this.workspaces.listScope(clusterId,workspaceId);
  }

  private owner(graph:RecycleGraph,node:GraphNode,data=node.data):GraphNode|undefined{
    if(node.type!=='targets'&&!CREDENTIAL_KINDS.includes(node.type as any))return undefined;
    const type=node.type==='targets'?'upstreams':'consumers';
    const id=(node.type==='targets'?data.upstream:data.consumer)?.id;
    const parent=graph.nodes.find(item=>node.dependencies.includes(item.key)&&item.type===type);
    if(!parent||id&&id!==parent.id)throw new ConflictException({code:'GRAPH_PARENT_MISMATCH',message:'凭证或 Target 的真实父对象不匹配'});
    return parent;
  }

  private async membership(clusterId:string,scope:WorkspaceFilter,graph:RecycleGraph,node:GraphNode,data=node.data,fresh=false):Promise<void>{
    const parent=this.owner(graph,node,data);
    const entity=parent?(fresh?await this.read(clusterId,parent.path):parent.data):data;
    this.workspaces.assertMembership(scope,entity);
    if(fresh)for(const key of node.dependencies){
      const dependency=graph.nodes.find(item=>item.key===key);
      if(!dependency)throw new ConflictException({code:'GRAPH_REFERENCE_MISSING',message:'对象图依赖缺失'});
      if(parent?.key===key)continue;
      const current=await this.read(clusterId,dependency.path);
      this.workspaces.assertMembership(scope,current);
    }
  }

  private async bindEntry(entry:Entry,graph:RecycleGraph,actor:AuthUser,scope:WorkspaceFilter):Promise<void>{
    if(entry.workspace_id&&entry.workspace_id!==scope.workspaceId)throw new ForbiddenException({code:'WORKSPACE_MISMATCH',message:'回收记录属于其他工作区'});
    const root=graph.nodes.find(node=>node.key===graph.rootKey);
    if(!root)throw new ConflictException('归档对象图无根对象');
    await this.membership(entry.cluster_id,scope,graph,root);
    await this.authz.assertArchivedEntity(actor,entry.cluster_id,root.type,'read',root.data,scope.workspaceId,graph.nodes);
    if(!entry.workspace_id){
      const updated=await this.db.transaction(async tx=>{
        const count=await tx.exec('UPDATE recycle_entries SET workspace_id=$2 WHERE id=$1 AND workspace_id IS NULL',[entry.id,scope.workspaceId]);
        if(count)await this.audit.append({actorId:actor.id,clusterId:entry.cluster_id,workspaceId:scope.workspaceId,entityType:'recycle_entries',entityId:entry.id,action:'workspace_scope_bound',before:{workspace_id:null},after:{workspace_id:scope.workspaceId},result:'success'},tx);
        return count;
      });
      if(updated===0){const current=await this.db.one<any>('SELECT workspace_id FROM recycle_entries WHERE cluster_id=$1 AND id=$2',[entry.cluster_id,entry.id]);if(current?.workspace_id!==scope.workspaceId)throw new ForbiddenException({code:'WORKSPACE_MISMATCH',message:'归档工作区在核验期间变化'});}
      entry.workspace_id=scope.workspaceId;
    }
  }

  private async indexChange(clusterId:string,node:GraphNode,restored?:any):Promise<void>{
    if(!['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis'].includes(node.type))return;
    try{if(restored)await this.index.upsert(clusterId,node.type,restored);else await this.index.remove(clusterId,node.type,node.id);}
    catch{this.logger.warn(JSON.stringify({event:'recycle_index_sync_failed',clusterId,entityType:node.type,entityId:node.id}));}
  }

  private validateConfirmation(confirmation:Confirmation,name:string,providedName?:string):void {
    const confirmed=typeof confirmation==='boolean'?confirmation:confirmation?.confirmed;
    const confirmName=typeof confirmation==='boolean'?providedName:confirmation?.confirm_name;
    if (confirmed!==true||confirmName!==name) throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:`请二次确认并输入对象名称 ${name}`});
  }

  private async authorizeGraph(clusterId:string,actor:AuthUser,graph:RecycleGraph,action:string,scope:WorkspaceFilter,archived=false):Promise<void>{
    for(const node of graph.nodes){
      await this.membership(clusterId,scope,graph,node);
      if(archived)await this.authz.assertArchivedEntity(actor,clusterId,node.type,node.affected?action:'read',node.data,scope.workspaceId,graph.nodes);
      else await this.authz.assertEntity(actor,clusterId,node.type,node.affected?action:'read',node.data,scope.workspaceId);
    }
  }

  private async effectiveTarget(clusterId:string,node:GraphNode):Promise<any|null>{
    const parentPath=node.path.match(/^\/upstreams\/([^/]+)\/targets\/[^/]+$/);
    if(!parentPath)throw new ConflictException({code:'GRAPH_PARENT_MISMATCH',message:'Target 归档缺少真实 Upstream 路径'});
    const parentId=decodeURIComponent(parentPath[1]),foreign=typeof node.data.upstream==='string'?node.data.upstream:node.data.upstream?.id;
    if(foreign&&foreign!==parentId)throw new ConflictException({code:'GRAPH_PARENT_MISMATCH',message:'Target 的父对象与归档路径不匹配'});
    return this.execution.runInternalRead(clusterId,'recycle-check',async()=>(await currentEffectiveTarget(this.kong,clusterId,parentId,node.data.target)).target);
  }

  /** Fixed V3 coordinator read only. This never accepts a permit, writes
   * archive state, or turns caller-supplied graph bytes into native authority. */
  async assertPreparedDeleteCurrentGraph(clusterId:string,graph:Readonly<RecycleGraph>,nodeKey:string,completedNodeKeys:readonly string[]):Promise<void>{
    const expected=expectedRecycleDeleteGraph(graph,nodeKey,completedNodeKeys),root=expected.nodes.find(node=>node.key===nodeKey)!;
    const parent=root.type==='targets'||CREDENTIAL_KINDS.includes(root.type as any)?this.owner(graph as RecycleGraph,root)?.id:undefined;
    const actual=await this.capturer.capture(clusterId,root.type,root.id,{purpose:'baseline',parentId:parent,credentialKind:CREDENTIAL_KINDS.includes(root.type as any)?root.type:undefined,
      budget:{maxPages:100,maxRecords:10000,maxNodes:1000,maxBytes:16*1024*1024}});
    assertRecycleDeleteGraphCurrent(expected,actual,this.secrets);
  }

  /** Read-only planning. No archive, receipt, credential, audit or native write
   * happens here: the execution adapter must persist the complete baseline
   * and satisfy these obligations before it can send the first native packet. */
  async prepareEntityChange(clusterId:string,request:RecycleChange,actor:EntityActor):Promise<RecyclePreparation>{
    return this.prepareRecycleFacts(clusterId,request,actor,'write');
  }

  /** Uses the real current caller. Approvers need subject read authority here;
   * Root's closed stored-subject policy separately proves workflows.approve.
   * Neither requester impersonation nor writer grants substitute for it. */
  async assertPreparedEntityChange(clusterId:string,request:RecycleChange,material:PreparedEntityChange,actor:EntityActor,
    context?:{action:StoredEntitySubjectAction;mode:'fresh'}):Promise<void>{
    if(clusterId!==material.clusterId||actor.workspaceId!==material.workspaceId||context&&context.mode!=='fresh')throw new ForbiddenException({code:'ENTITY_CHANGE_SCOPE_MISMATCH'});
    const obligation=material.metadataObligations.find(item=>request.action==='restore'
      ? item.kind==='recycle-restore'&&item.entryId===request.entryId
      : item.kind==='recycle-archive'&&item.graph.nodes.some(node=>node.key===item.graph.rootKey&&node.id===request.entityId&&node.type===(request.entityType==='credentials'?request.credentialKind:request.entityType)));
    if(!obligation||!('packetKeys' in obligation)||!('graph' in obligation)||this.secrets.fingerprint(obligation.graph)!==obligation.graphHmac)throw new ConflictException({code:'ENTITY_CHANGE_RECYCLE_SEAL_INVALID'});
    const packets=obligation.packetKeys.map(key=>material.packets.find(packet=>packet.key===key));
    if(packets.some(packet=>!packet)||new Set(obligation.packetKeys).size!==packets.length)throw new ConflictException({code:'ENTITY_CHANGE_RECYCLE_SEAL_INVALID'});
    const fresh=await this.prepareRecycleFacts(clusterId,request,actor,context?.action??'write',{graph:obligation.graph,packets:packets as EntityChangePacket[]});
    if(this.secrets.fingerprint(fresh.packets)!==this.secrets.fingerprint(packets))throw new ConflictException({code:'ENTITY_CHANGE_RECYCLE_CHANGED'});
    for(const schema of fresh.schemas)if(!material.schemas.some(saved=>this.secrets.fingerprint(saved)===this.secrets.fingerprint(schema)))throw new ConflictException({code:'ENTITY_CHANGE_SCHEMA_CHANGED'});
    for(const prerequisite of fresh.prerequisites){const saved=material.prerequisites.find(item=>item.path===prerequisite.path);
      if(!saved||saved.type!==prerequisite.type||saved.absent!==prerequisite.absent||saved.fingerprint!==prerequisite.fingerprint)throw new ConflictException({code:'ENTITY_CHANGE_RECYCLE_CHANGED'});}
    const sealed=fresh.metadataObligations.find(item=>item.kind==='recycle-archive'||item.kind==='recycle-restore');
    if(!sealed||this.secrets.fingerprint(sealed)!==this.secrets.fingerprint(obligation))throw new ConflictException({code:'ENTITY_CHANGE_RECYCLE_SEAL_CHANGED'});
  }

  private validatePreparedGraph(graph:RecycleGraph):GraphNode{
    if(!graph||graph.complete!==true||graph.purpose==='migration'||!Array.isArray(graph.nodes)||!graph.nodes.length||graph.nodes.length>1000
      ||Buffer.byteLength(JSON.stringify(graph))>16*1024*1024)throw new ConflictException({code:'GRAPH_INCOMPLETE'});
    const keys=new Set<string>(),identities=new Set<string>();
    for(const node of graph.nodes){
      if(!node||typeof node.key!=='string'||keys.has(node.key)||!NATIVE_UUID.test(node.id)||!node.data||node.data.id!==node.id
        ||typeof node.affected!=='boolean'||!Array.isArray(node.dependencies)||new Set(node.dependencies).size!==node.dependencies.length
        ||!(ENTITIES as readonly string[]).includes(node.type)&&node.type!=='targets'&&!CREDENTIAL_KINDS.includes(node.type as any))throw new ConflictException({code:'GRAPH_INVALID'});
      keys.add(node.key);const parent=this.owner(graph,node,normalizeEntityAuthorizationView(node.type,node.data));
      const path=parent?`/${parent.type}/${parent.id}/${node.type}/${node.id}`:`/${node.type}/${node.id}`;
      if(node.path!==path||identities.has(path))throw new ConflictException({code:'GRAPH_PARENT_MISMATCH'});
      assertKongPath('GET',node.path);identities.add(path);
    }
    const root=graph.nodes.find(node=>node.key===graph.rootKey);if(!root?.affected)throw new ConflictException({code:'GRAPH_INCOMPLETE'});
    if(isOrdinaryRecycleRoot(root.type))assertOrdinaryRecycleArchiveContract(graph);
    graphOrder(graph);return root;
  }

  private graphFacts(graph:RecycleGraph):unknown{
    return {rootKey:graph.rootKey,purpose:graph.purpose??'recycle',complete:graph.complete,
      nodes:[...graph.nodes].sort((a,b)=>a.key.localeCompare(b.key)).map(node=>({...node,dependencies:[...node.dependencies].sort()})),targetHistory:graph.targetHistory??[]};
  }

  private async preparedAuthorization(clusterId:string,actor:EntityActor,scope:WorkspaceFilter,graph:RecycleGraph,action:string,archived:boolean):Promise<Set<string>>{
    const authGraph=graph.nodes.map(node=>({...node,data:normalizeEntityAuthorizationView(node.type,node.data)})),view={...graph,nodes:authGraph},privateParents=new Set<string>();
    for(const node of authGraph){
      await this.membership(clusterId,scope,view,node);
      try{
        if(archived)await this.authz.assertArchivedEntity(actor.user,clusterId,node.type,node.affected?action:'read',node.data,scope.workspaceId,authGraph);
        else await this.authz.assertEntity(actor.user,clusterId,node.type,node.affected?action:'read',node.data,scope.workspaceId);
      }catch(error){
        const children=authGraph.filter(child=>child.affected&&child.dependencies.includes(node.key)&&this.owner(view,child)?.key===node.key);
        // Context-only parent identity is a closed child-scope exception. It
        // never reveals or grants access to an unrelated parent's config.
        if(!(error instanceof HttpException)||error.getStatus()!==403||node.affected||!children.length||!['consumers','upstreams'].includes(node.type))throw error;
        for(const child of children)await this.authz.assertNestedParentScope(actor.user,clusterId,node.type,node.data,child.type,action,scope.workspaceId,child.data);
        privateParents.add(node.key);
      }
    }
    return privateParents;
  }

  private async preparedEntry(clusterId:string,id:string,scope:WorkspaceFilter,actor:EntityActor,subjectAction:StoredEntitySubjectAction):Promise<{entry:Entry;graph:RecycleGraph;closedRestoreCoverage?:EntityRecycleClosedRestoreCoverage;seal:Extract<EntityChangeMetadataObligation,{kind:'recycle-restore'}>['sealedEntry']}>{
    const entry=await this.db.one<Entry>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND id=$2',[clusterId,id]);
    if(!entry)throw new NotFoundException({code:'RECYCLE_NOT_FOUND'});
    if(!entry.workspace_id||entry.workspace_id!==scope.workspaceId)throw new ForbiddenException({code:entry.workspace_id?'WORKSPACE_MISMATCH':'RECYCLE_WORKSPACE_BINDING_REQUIRED'});
    if(entry.state==='purged'||!entry.payload_secret)throw new ConflictException({code:'RECYCLE_PURGED'});
    if(!['archived','deleted','partially_deleted','partially_restored'].includes(entry.state))throw new ConflictException({code:'RECYCLE_BUSY'});
    const expiresAt=new Date(entry.expires_at);if(!Number.isFinite(expiresAt.getTime())||expiresAt.getTime()<=Date.now())throw new ConflictException({code:'RECYCLE_EXPIRED'});
    const component=await this.db.one<any>(`SELECT g.recycle_entry_id FROM configuration_recycle_components c
      JOIN configuration_recycle_graphs g ON g.cluster_id=c.cluster_id AND g.workspace_id=c.workspace_id AND g.id=c.graph_id
      WHERE c.cluster_id=$1 AND c.recycle_entry_id=$2 AND g.object_workspace_id=$3`,[clusterId,id,scope.workspaceId]);
    if(component)throw new ConflictException({code:'RECYCLE_COMPONENT_RESTORE_REQUIRED'});
    // A matching GET/404 cannot disprove a delayed old DELETE. Require the
    // original execution ledger to be closed; never reconcile it as a side
    // effect of preparing a new restore.
    const origins=await this.db.query<any>(`SELECT 'mutation'::text AS kind,m.id,m.state,m.workspace_id,m.workflow_id,
        w.state AS workflow_state,x.state AS execution_state,
        EXISTS(SELECT 1 FROM workflow_steps s WHERE s.cluster_id=m.cluster_id AND s.workspace_id=m.workspace_id
          AND s.workflow_id=m.workflow_id AND s.plan_revision=m.workflow_plan_revision AND s.state IN('pending','running','uncertain')) AS unresolved_steps
      FROM mutation_operations m LEFT JOIN workflows w ON w.cluster_id=m.cluster_id AND w.workspace_id=m.workspace_id AND w.id=m.workflow_id
      LEFT JOIN workflow_executions x ON x.cluster_id=m.cluster_id AND x.workspace_id=m.workspace_id AND x.id=m.workflow_execution_id
      WHERE m.cluster_id=$1 AND m.id=$3::uuid
      UNION ALL SELECT 'configuration'::text,g.id,j.state,g.object_workspace_id,j.workflow_id,w.state,e.state,
        EXISTS(SELECT 1 FROM configuration_job_steps s WHERE s.cluster_id=g.cluster_id AND s.workspace_id=g.workspace_id
          AND s.job_id=g.job_id AND s.execution_id=g.execution_id AND s.state IN('pending','running','uncertain'))
      FROM configuration_recycle_graphs g JOIN configuration_jobs j ON j.cluster_id=g.cluster_id AND j.workspace_id=g.workspace_id AND j.id=g.job_id
      JOIN configuration_executions e ON e.cluster_id=g.cluster_id AND e.workspace_id=g.workspace_id AND e.id=g.execution_id
      LEFT JOIN workflows w ON w.cluster_id=j.cluster_id AND w.workspace_id=j.workspace_id AND w.id=j.workflow_id
      WHERE g.cluster_id=$1 AND g.object_workspace_id=$2 AND g.recycle_entry_id=$4 ORDER BY kind,id`,[clusterId,scope.workspaceId,entry.mutation_id??null,id]);
    // Existing non-NULL legacy and configuration origins retain their exact
    // checks. A new independently archived entry needs its complete closed
    // source/baseline/attempt/204+404/receipt chain, via the fixed reader only.
    if(!origins.length&&entry.mutation_id===null){
      if(!this.entityOriginLookup)throw new ServiceUnavailableException({code:'RECYCLE_ENTITY_ORIGIN_POLICY_UNAVAILABLE'});
      origins.push(await this.entityOriginLookup.readClosedOrigin({clusterId,workspaceId:scope.workspaceId,entryId:id,actor,subjectAction}));
    }
    if(!origins.length||origins.length>2||origins.some(origin=>origin.workspace_id!==scope.workspaceId||origin.unresolved_steps===true
      ||origin.kind==='mutation'&&!['succeeded','failed','blocked'].includes(origin.state)
      ||origin.kind==='configuration'&&!['succeeded','partial','failed','cancelled','expired'].includes(origin.state)
      ||origin.workflow_id&&(!['succeeded','partial','failed','cancelled','expired'].includes(origin.workflow_state)||!['succeeded','partial','failed'].includes(origin.execution_state))
      ||origin.kind==='configuration'&&!['succeeded','partial','failed'].includes(origin.execution_state)))throw new ConflictException({code:'RECYCLE_ORIGIN_UNRESOLVED'});
    const graph=this.secrets.decrypt<RecycleGraph>(entry.payload_secret,`recycle:${entry.id}`),root=this.validatePreparedGraph(graph);
    if(root.id!==entry.original_id||root.type!==(entry.root_type==='credentials'?entry.credential_kind:entry.root_type)||entry.node_count!==graph.nodes.length)throw new ConflictException({code:'RECYCLE_MANIFEST_INVALID'});
    const rows=await this.db.query<StoredNode>('SELECT node_key,entity_type,original_id,affected,dependencies,delete_state,restore_state,restored_id FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key',[id]);
    if(rows.length!==graph.nodes.length||new Set(rows.map(row=>row.node_key)).size!==rows.length)throw new ConflictException({code:'RECYCLE_MANIFEST_INVALID'});
    for(const node of graph.nodes){const row=rows.find(item=>item.node_key===node.key);
      if(!row||row.entity_type!==node.type||row.original_id!==node.id||row.affected!==node.affected
        ||this.secrets.fingerprint([...row.dependencies].sort())!==this.secrets.fingerprint([...node.dependencies].sort())
        ||node.affected&&(!['pending','deleted','failed'].includes(row.delete_state)||!['pending','restored','failed'].includes(row.restore_state))
        ||!node.affected&&(row.delete_state!=='reference'||row.restore_state!=='reference')
        ||row.restore_state==='restored'&&row.restored_id!==node.id)throw new ConflictException({code:'RECYCLE_MANIFEST_INVALID'});
      if(node.affected){
        if(!node.restorable||!node.restoreData||node.restoreData.id!==node.id||typeof node.data.ttl==='number'&&node.data.ttl>0)throw new ConflictException({code:'OBJECT_NOT_RESTORABLE'});
        if(node.type==='basic-auth'){
          const parent=this.owner(graph,node,normalizeEntityAuthorizationView(node.type,node.data)),plain=node.restoreData.password,hash=node.data.password;
          if(!parent||typeof plain!=='string'||typeof hash!=='string'||!/^[\da-f]{40}$/i.test(hash)
            ||createHash('sha1').update(plain+parent.id).digest('hex')!==hash.toLowerCase())throw new ConflictException({code:'BASIC_AUTH_RESTORE_PROVENANCE_INVALID'});
        }
      }
    }
    const closedRestoreCoverage=origins.find(origin=>origin.kind==='entity-change')?.closedRestoreCoverage as EntityRecycleClosedRestoreCoverage|undefined;
    if(entry.state==='partially_restored'&&entry.mutation_id===null&&!closedRestoreCoverage)throw new ConflictException({code:'ENTITY_RECYCLE_PARTIAL_HISTORY_REQUIRED'});
    return {entry,graph,...(closedRestoreCoverage?{closedRestoreCoverage}:{}),seal:{clusterId,workspaceId:scope.workspaceId,entryId:id,state:entry.state,expiresAt:expiresAt.toISOString(),
      payloadHmac:this.secrets.fingerprint(graph),nodeManifestHmac:this.secrets.fingerprint({nodes:rows.map(row=>({...row,dependencies:[...row.dependencies].sort()})),origins}),
      restoreMaterialHmac:this.secrets.fingerprint(graph.nodes.filter(node=>node.affected).map(node=>({key:node.key,restoreData:node.restoreData})))}};
  }

  private async deleteSchema(clusterId:string,packet:EntityChangePacket,actor:EntityActor):Promise<EntityWriteSchemaMaterial>{
    assertKongPath('DELETE',packet.canonicalPath);const dao=entityForPath(packet.canonicalPath);if(!dao)throw new ConflictException({code:'GRAPH_INVALID'});
    const readCluster=()=>this.db.one<any>('SELECT admin_url,transport_scope,revision,version,status FROM clusters WHERE id=$1 AND deleted_at IS NULL',[clusterId]);
    const before=await readCluster();if(!before||!/^1\.5\.\d+$/.test(before.version??'')||before.status==='disabled')throw new ConflictException({code:'KONG_VERSION_INCOMPATIBLE'});
    const path=`/schemas/${dao}`,schema=await this.execution.runInternalRead(clusterId,'entity-preflight',()=>this.kong.schema(clusterId,dao),{paths:[path],workspaceId:actor.workspaceId,maxCalls:4});
    const schemaMaterial:EntityWriteSchemaMaterial['schemaMaterial']={entity:{name:dao,canonicalPath:path,schema}};
    if(packet.nativeType==='plugins'){
      const name=(packet.before as any)?.name;if(typeof name!=='string')throw new ConflictException({code:'GRAPH_INVALID'});
      const pluginPath=`/plugins/schema/${name}`;assertKongPath('GET',pluginPath);
      schemaMaterial.plugin={name,canonicalPath:pluginPath,schema:await this.execution.runInternalRead(clusterId,'entity-preflight',()=>this.kong.pluginSchema(clusterId,name),{paths:[pluginPath],workspaceId:actor.workspaceId,maxCalls:4})};
    }
    const after=await readCluster();if(this.secrets.fingerprint(before)!==this.secrets.fingerprint(after))throw new ConflictException({code:'KONG_SCHEMA_PREPARATION_CHANGED'});
    return {version:1,clusterId,canonicalPath:packet.canonicalPath,nativeType:dao,kongVersion:before.version,adapter:'kong-oss-1.5-v1',clusterRevision:before.revision,payloadHmac:packet.bodyHmac,schemaMaterial};
  }

  private async prepareRecycleFacts(clusterId:string,request:RecycleChange,actor:EntityActor,subjectAction:StoredEntitySubjectAction,
    stored?:{graph:RecycleGraph;packets:EntityChangePacket[]}):Promise<RecyclePreparation>{
    if(!actor.workspaceId||!NATIVE_UUID.test(actor.workspaceId))throw new ForbiddenException({code:'EXPLICIT_WORKSPACE_REQUIRED'});
    const scope=await this.scope(clusterId,actor.user,actor.workspaceId);
    const workspace=await this.workspaces.get(clusterId,scope.workspaceId);if(workspace.status!=='active')throw new ConflictException({code:'WORKSPACE_DISABLED'});
    const authorizingAction=subjectAction==='write'?(request.action==='delete'?'delete':'write'):'read';
    let graph:RecycleGraph,entrySeal:Extract<EntityChangeMetadataObligation,{kind:'recycle-restore'}>['sealedEntry']|undefined,closedRestoreCoverage:EntityRecycleClosedRestoreCoverage|undefined;
    if(request.action==='delete'){
      graph=await this.capturer.capture(clusterId,request.entityType,request.entityId,{parentId:request.parentId,credentialKind:request.credentialKind,purpose:'recycle',budget:{maxNodes:1000,maxRecords:10000,maxPages:100,maxBytes:16*1024*1024}});
      const root=this.validatePreparedGraph(graph);this.validateConfirmation(request,recycleName(root));
      if(root.id!==request.entityId||root.type!==(request.entityType==='credentials'?request.credentialKind:request.entityType))throw new ConflictException({code:'GRAPH_INVALID'});
      if(stored){if(this.secrets.fingerprint(this.graphFacts(graph))!==this.secrets.fingerprint(this.graphFacts(stored.graph)))throw new ConflictException({code:'ENTITY_CHANGE_RECYCLE_CHANGED'});graph=stored.graph;}
      await this.assertPortalArchiveDeleteAllowed(clusterId,graph);
    }else{
      const loaded=await this.preparedEntry(clusterId,request.entryId,scope,actor,subjectAction);graph=loaded.graph;entrySeal=loaded.seal;
      closedRestoreCoverage=loaded.closedRestoreCoverage;
      this.validateConfirmation(request,loaded.entry.root_name);await this.assertPortalRestoreAllowed(clusterId,graph);
      if(stored&&this.secrets.fingerprint(graph)!==this.secrets.fingerprint(stored.graph))throw new ConflictException({code:'ENTITY_CHANGE_RECYCLE_SEAL_CHANGED'});
    }
    const privateParents=await this.preparedAuthorization(clusterId,actor,scope,graph,authorizingAction,request.action==='restore');
    const prerequisites:EntityChangePrerequisite[]=[],packets:EntityChangePacket[]=[],schemas:EntityWriteSchemaMaterial[]=[],metadataObligations:EntityChangeMetadataObligation[]=[];
    const current=new Map<string,any|null>();
    for(const node of graphOrder(graph)){
      const parent=this.owner(graph,node,normalizeEntityAuthorizationView(node.type,node.data));let value:any=null;
      if(request.action==='restore'&&node.type==='targets'&&parent?.affected&&current.get(parent.key)===null){
        // The only nested 404 exception is a genuinely absent affected
        // Upstream in this authenticated full restore graph.
        try{value=await this.read(clusterId,node.path);}catch(error){if(!(error instanceof HttpException)||error.getStatus()!==404)throw error;}
        if(value)throw new ConflictException({code:'RESTORE_TARGET_PARENT_CHANGED'});
      }else if(node.type==='targets')value=await this.effectiveTarget(clusterId,node);
      else try{value=await this.read(clusterId,node.path);}catch(error){if(!(error instanceof HttpException)||error.getStatus()!==404||request.action!=='restore'||!node.affected)throw error;}
      if(!node.affected&&value===null||request.action==='delete'&&(value===null||this.secrets.fingerprint(value)!==this.secrets.fingerprint(node.data)))throw new ConflictException({code:'ENTITY_CHANGE_RECYCLE_CHANGED'});
      if(request.action==='restore'&&value){
        const actual=comparable(value),desired=comparable(node.data);
        if(node.type==='certificates'){delete actual.snis;delete desired.snis;}
        // A single-Target logical restore may not adopt a new physical row.
        if(node.type==='targets'&&value.id!==node.id)throw new ConflictException({code:'RESTORE_TARGET_CONFLICT'});
        if(this.secrets.fingerprint(actual)!==this.secrets.fingerprint(desired))throw new ConflictException({code:'RESTORE_ID_CONFLICT'});
      }
      if(value)this.workspaces.assertMembership(scope,parent?current.get(parent.key)??parent.data:value);
      current.set(node.key,value);
      if(node.type!=='targets'||value){prerequisites.push({type:node.type,path:node.path,nativeId:node.id,...(parent?{parentId:parent.id}:{}),before:value,absent:value===null,fingerprint:this.secrets.fingerprint(value),
        permissionAction:node.affected&&subjectAction==='write'?(request.action==='delete'?'delete':'write'):'read',...(privateParents.has(node.key)?{purpose:'private-parent' as const}:{})});}
    }
    if(request.action==='restore')for(const certificate of graph.nodes.filter(node=>node.type==='certificates'&&current.get(node.key))){
      const initial=certificate.data.snis,actual=current.get(certificate.key)?.snis;
      if(!Array.isArray(initial)||!Array.isArray(actual))throw new ConflictException({code:'RESTORE_ID_CONFLICT'});
      const expected=initial.filter((name:string)=>{const child=graph.nodes.find(node=>node.type==='snis'&&node.dependencies.includes(certificate.key)&&node.data.name===name);return !child||current.get(child.key)!==null;});
      if(this.secrets.fingerprint([...actual].sort())!==this.secrets.fingerprint([...expected].sort()))throw new ConflictException({code:'RESTORE_ID_CONFLICT'});
    }
    const ordered=graphOrder(graph).filter(node=>node.affected),sendOrder=request.action==='delete'?[...ordered].reverse():ordered,keyByNode=new Map<string,string>();
    for(const node of sendOrder){
      if(request.action==='restore'&&current.get(node.key)!==null)continue;
      const saved=stored?.packets.find(packet=>packet.nativeType===node.type&&(packet.originalNativeId??packet.nativeId)===node.id);
      const key=saved?.key??`recycle:${request.action}:${node.key}`,parent=this.owner(graph,node,normalizeEntityAuthorizationView(node.type,node.data));
      const dependencies=request.action==='delete'?graph.nodes.filter(child=>child.affected&&child.dependencies.includes(node.key)).flatMap(child=>keyByNode.get(child.key)??[]):node.dependencies.flatMap(dependency=>keyByNode.get(dependency)??[]);
      let before:any=request.action==='delete'?structuredClone(node.data):null,body:Record<string,any>|undefined,nativeId=node.id,originalNativeId:string|undefined;
      if(request.action==='delete'&&node.type==='certificates'&&Array.isArray(before.snis)){
        const removed=new Set(graph.nodes.filter(child=>child.affected&&child.type==='snis'&&child.dependencies.includes(node.key)&&keyByNode.has(child.key)).map(child=>child.data.name));
        before.snis=before.snis.filter((name:string)=>!removed.has(name));
      }
      if(request.action==='restore'){
        body=structuredClone(node.restoreData);delete body!.created_at;delete body!.updated_at;delete body!.ttl;
        if(node.type==='certificates')delete body!.snis;
        if(node.type==='targets'){
          if(!parent)throw new ConflictException({code:'GRAPH_PARENT_MISMATCH'});
          if(!parent.affected||current.get(parent.key)!==null){nativeId=saved?.nativeId??randomUUID();originalNativeId=node.id;}
          body!.id=nativeId;delete body!.upstream;
          const path=`/upstreams/${parent.id}/targets/${nativeId}`;
          try{await this.read(clusterId,path);throw new ConflictException({code:'RESTORE_TARGET_CONFLICT'});}catch(error){if(!(error instanceof HttpException)||error.getStatus()!==404)throw error;}
          if(!prerequisites.some(item=>item.path===path))prerequisites.push({type:'targets',path,nativeId,parentId:parent.id,before:null,absent:true,fingerprint:this.secrets.fingerprint(null),permissionAction:'write'});
        }
      }
      const packet:EntityChangePacket={key,order:saved?.order??packets.length+1,dependencies,method:request.action==='delete'?'DELETE':'POST',canonicalPath:request.action==='delete'?node.path:node.path.replace(/\/[^/]+$/,''),nativeType:node.type,nativeId,
        ...(parent?{parentId:parent.id}:{}),...(CREDENTIAL_KINDS.includes(node.type as any)?{credentialKind:node.type as CredentialKind}:{}),permissionAction:request.action==='delete'?'delete':'write',mutationAction:request.action,
        ...(body?{body}:{}),before,bodyHmac:this.secrets.fingerprint(body??null),beforeHmac:this.secrets.fingerprint(before),...(originalNativeId?{originalNativeId}:{})};
      assertKongPath(packet.method,packet.canonicalPath);keyByNode.set(node.key,key);packets.push(packet);
      schemas.push(request.action==='delete'?await this.deleteSchema(clusterId,packet,actor):await this.kong.prepareSchema(clusterId,packet.canonicalPath,packet.body));
      if((ENTITIES as readonly string[]).includes(node.type))metadataObligations.push({kind:'entity-index',packetKey:key,entityType:node.type as EntityType});
      if(request.action==='restore'&&CREDENTIAL_KINDS.includes(node.type as any))metadataObligations.push({kind:'credential-remember',packetKey:key,consumerId:parent!.id,credentialKind:node.type as CredentialKind,rawInput:body!});
    }
    if(!packets.length)throw new ConflictException({code:'RECYCLE_ALREADY_RESTORED'});
    const graphHmac=this.secrets.fingerprint(graph),packetKeys=packets.map(packet=>packet.key);
    let partialRestore:Extract<EntityChangeMetadataObligation,{kind:'recycle-restore'}>['partialRestore'];
    if(closedRestoreCoverage){
      const presentNodes=[];
      for(const prior of closedRestoreCoverage.presentNodes){const node=graph.nodes.find(item=>item.key===prior.nodeKey),value=node?current.get(node.key):null;
        if(!node||value===null||value===undefined||this.secrets.fingerprint(value)!==prior.resultHmac)throw new ConflictException({code:'ENTITY_RECYCLE_PRESENT_RESULT_CHANGED'});
        let basicCustodyHmac:string|undefined;
        if(node.type==='basic-auth'){const parent=this.owner(graph,node);if(!parent)throw new ConflictException({code:'GRAPH_PARENT_MISMATCH'});
          basicCustodyHmac=partialBasicCustodyHmac(node,value,await this.credentials.get(clusterId,parent.id,'basic-auth',node.id),parent.id,this.secrets);}
        presentNodes.push({nodeKey:node.key,beforeHmac:this.secrets.fingerprint(value),...(basicCustodyHmac?{basicCustodyHmac}:{})});
      }
      const remainingNodeKeys=closedRestoreCoverage.remainingNodes.map(item=>item.nodeKey);
      if(remainingNodeKeys.some(key=>current.get(key)!==null)||packets.length!==2||packets.some(packet=>!remainingNodeKeys.some(key=>{
        const node=graph.nodes.find(item=>item.key===key);return node?.type===packet.nativeType&&node.id===packet.nativeId;})))throw new ConflictException({code:'ENTITY_RECYCLE_PARTIAL_PARTITION_CHANGED'});
      const partition={version:1 as const,history:closedRestoreCoverage,presentNodes,remainingNodeKeys};partialRestore={...partition,selectionHmac:this.secrets.fingerprint(partition)};
      validatePartialRecycleRestoreSelection(graph,partialRestore,this.secrets);
    }
    metadataObligations.push(request.action==='delete'?{kind:'recycle-archive',graph,graphHmac,packetKeys}:{kind:'recycle-restore',entryId:request.entryId,graph,graphHmac,packetKeys,sealedEntry:entrySeal!,...(partialRestore?{partialRestore}:{})});
    return {graph,packets,schemas,prerequisites,metadataObligations};
  }

  async archiveAndDelete(context:MutationContext & {confirmed?:boolean},confirmed=context.confirmed??false):Promise<any>{
    if(!context.entityId)throw new BadRequestException('删除需要对象 ID');
    if(confirmed!==true)throw new BadRequestException({code:'CONFIRMATION_REQUIRED',message:'删除需要二次确认'});
    const mutationContext={...context,action:'delete',payload:{confirmed,confirm_name:context.confirmName,parentId:context.parentId,credentialKind:context.credentialKind}};
    const scope=await this.scope(context.clusterId,context.actor,context.workspaceId);
    mutationContext.workspaceId=scope.workspaceId;
    return this.mutations.execute(mutationContext,async()=>{
      const graph=await this.capturer.capture(context.clusterId,context.entityType,context.entityId!,{parentId:context.parentId,credentialKind:context.credentialKind});
      const root=graph.nodes.find(node=>node.key===graph.rootKey);
      if(graph.purpose==='migration')throw new ConflictException({code:'GRAPH_PURPOSE_MISMATCH',message:'迁移对象图不能用于回收删除'});
      if(!graph.complete||!root)throw new ConflictException({code:'GRAPH_INCOMPLETE',message:'对象图未完整归档，删除已停止'});
      this.validateConfirmation(confirmed,recycleName(root),context.confirmName);
      await this.authorizeGraph(context.clusterId,context.actor,graph,'delete',scope);
      await this.assertPortalArchiveDeleteAllowed(context.clusterId,graph);
      await this.mutations.claimGraphImpact(mutationContext,graph.nodes);
      const ordered=graphOrder(graph),entryId=randomUUID();
      const retentionDays=Number(process.env.RECYCLE_RETENTION_DAYS??30);
      if(!Number.isInteger(retentionDays)||retentionDays<1||retentionDays>3650)throw new Error('RECYCLE_RETENTION_DAYS must be 1–3650');
      await this.db.transaction(async tx=>{
        await tx.exec(`INSERT INTO recycle_entries(id,cluster_id,actor_id,root_type,original_id,root_name,parent_id,credential_kind,node_count,payload_secret,expires_at,mutation_id,workspace_id)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()+$11::integer*interval '1 day',$12,$13)`,
          [entryId,context.clusterId,context.actor.id,context.entityType,context.entityId,recycleName(root),context.parentId??null,
            context.credentialKind??null,graph.nodes.length,this.secrets.encrypt(graph,`recycle:${entryId}`),retentionDays,mutationContext.operationId??null,scope.workspaceId]);
        for(const node of graph.nodes)await tx.exec(`INSERT INTO recycle_nodes(entry_id,node_key,entity_type,original_id,affected,dependencies,delete_state,restore_state)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,[entryId,node.key,node.type,node.id,node.affected,node.dependencies,node.affected?'pending':'reference',node.affected?'pending':'reference']);
        await this.audit.append({actorId:context.actor.id,clusterId:context.clusterId,workspaceId:scope.workspaceId,entityType:'recycle_entries',entityId:entryId,
          action:'archive',after:{rootType:context.entityType,originalId:context.entityId,nodeCount:graph.nodes.length},requestId:context.requestId,ip:context.ip},tx);
      });
      // Archive and every node are durable before the first remote DELETE.
      await this.db.exec("UPDATE recycle_entries SET state='deleting',updated_at=now() WHERE id=$1",[entryId]);
      const deleted:any[]=[];
      await this.execution.runArchiveDelete({entryId,operationId:mutationContext.operationId!,clusterId:context.clusterId,workspaceId:scope.workspaceId,
        nodes:graph.nodes.filter(node=>node.affected).map(node=>({path:node.path,type:node.type,id:node.id}))},async()=>{for(const node of ordered.filter(node=>node.affected).reverse()){
        try{
          const current=node.type==='targets'?await this.effectiveTarget(context.clusterId,node):await this.read(context.clusterId,node.path);
          const currentComparison=current?{...current}:null,archivedComparison={...node.data};
          // Certificate GET expands SNI names. Earlier child deletions legitimately
          // change this relationship; each SNI is already checked independently.
          if(node.type==='certificates'){if(currentComparison)delete currentComparison.snis;delete archivedComparison.snis;}
          if(!current||this.secrets.fingerprint(currentComparison)!==this.secrets.fingerprint(archivedComparison)){
            throw new ConflictException({code:'ENTITY_CHANGED_DURING_DELETE',message:'对象在归档后发生变化，已停止删除新配置'});
          }
          await this.membership(context.clusterId,scope,graph,node,current,true);
          await this.authz.assertEntity(context.actor,context.clusterId,node.type,'delete',current,scope.workspaceId);
          await this.kong.request(context.clusterId,'DELETE',node.path);
          if(node.type==='targets'){
            if(await this.effectiveTarget(context.clusterId,node))throw new ServiceUnavailableException({code:'DELETE_NOT_VERIFIED',message:'Target 仍处于有效集合，结果需要核验'});
          }else{
            try{await this.read(context.clusterId,node.path);throw new ServiceUnavailableException({code:'DELETE_NOT_VERIFIED',message:'删除后的对象仍可读取，结果需要核验'});}
            catch(error:any){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;}
          }
          await this.db.transaction(async tx=>{
            await tx.exec("UPDATE recycle_nodes SET delete_state='deleted',safe_error=NULL,updated_at=now() WHERE entry_id=$1 AND node_key=$2",[entryId,node.key]);
            await this.audit.append({actorId:context.actor.id,clusterId:context.clusterId,workspaceId:scope.workspaceId,entityType:node.type,entityId:node.id,action:'delete',before:node.data,after:null,
              result:'success',requestId:context.requestId,ip:context.ip,scopeHints:nativeAuditScope({type:node.type,id:node.id,before:current,after:null,beforeWorkspaceId:scope.workspaceId,afterWorkspaceId:null,parentId:this.owner(graph,node)?.id,credentialKind:CREDENTIAL_KINDS.includes(node.type as any)?node.type:undefined})},tx);
          });
          if(CREDENTIAL_KINDS.includes(node.type as any))await this.credentials.remove(context.clusterId,node.data.consumer?.id??context.parentId!,node.type,node.id);
          await this.indexChange(context.clusterId,node);
          deleted.push({type:node.type,id:node.id});
        }catch(error:any){
          const uncertain=!(error instanceof HttpException)||error.getStatus()>=500;
          await this.db.transaction(async tx=>{
            await tx.exec('UPDATE recycle_nodes SET delete_state=$3,safe_error=$4,updated_at=now() WHERE entry_id=$1 AND node_key=$2',
              [entryId,node.key,uncertain?'uncertain':'failed','删除失败或结果待核验']);
            await tx.exec("UPDATE recycle_entries SET state='partially_deleted',updated_at=now() WHERE id=$1",[entryId]);
            await this.audit.append({actorId:context.actor.id,clusterId:context.clusterId,workspaceId:scope.workspaceId,entityType:node.type,entityId:node.id,action:'delete',before:node.data,
              result:uncertain?'uncertain':'failed',requestId:context.requestId,ip:context.ip},tx);
          });
          throw new ServiceUnavailableException({code:'RECYCLE_DELETE_INCOMPLETE',message:'对象图已安全归档，部分删除未完成；请核验或恢复回收站记录',entryId,deleted,
            cause:error instanceof HttpException?(error.getResponse() as any)?.code:'DELETE_FAILED'});
        }
      }});
      await this.db.exec("UPDATE recycle_entries SET state='deleted',updated_at=now() WHERE id=$1",[entryId]);
      return {entryId,state:'deleted',deleted};
    });
  }

  private async entry(clusterId:string,id:string,actor:AuthUser,action:string,workspaceId?:string):Promise<{entry:Entry;graph:RecycleGraph;scope:WorkspaceFilter}>{
    await this.authz.assertCluster(actor,clusterId,'recycle-bin',action,workspaceId);
    const entry=await this.db.one<Entry>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND id=$2',[clusterId,id]);
    if(!entry)throw new NotFoundException('回收站记录不存在');
    if(entry.state==='purged'||!entry.payload_secret)throw new ConflictException({code:'RECYCLE_PURGED',message:'此归档已永久清除'});
    const graph=this.secrets.decrypt<RecycleGraph>(entry.payload_secret,`recycle:${entry.id}`);
    // This must precede bindEntry: even legacy workspace binding is a write.
    if(action==='write')await this.assertPortalRestoreAllowed(clusterId,graph);
    const scope=await this.scope(clusterId,actor,workspaceId,action!=='write');
    if(action==='write'&&(await this.workspaces.resolve(clusterId,scope.workspaceId)).status!=='active')throw new ConflictException({code:'WORKSPACE_DISABLED',message:'恢复必须选择原来的活动工作区'});
    const root=graph.nodes.find(node=>node.key===graph.rootKey);
    if(!root)throw new ConflictException('归档对象图无根对象');
    await this.bindEntry(entry,graph,actor,scope);
    await this.authz.assertArchivedEntity(actor,clusterId,root.type,action,root.data,scope.workspaceId,graph.nodes);
    return {entry,graph,scope};
  }

  /** Database-only ownership check, including revoked identities and captured
   * physical aliases. Generic restore must not resurrect developer secrets. */
  async assertPortalRestoreAllowed(clusterId:string,graph:RecycleGraph,tx:DbService=this.db):Promise<void>{
    if(!graph||!Array.isArray(graph.nodes)||graph.nodes.length>10000||graph.nodes.some(node=>!node||typeof node.affected!=='boolean'||typeof node.type!=='string'
      ||typeof node.id!=='string'||!node.id||node.id.length>256||typeof node.path!=='string'||!Array.isArray(node.dependencies)))throw new ConflictException({code:'GRAPH_INVALID'});
    const consumers=new Set<string>(),credentials=new Set<string>();
    const add=(set:Set<string>,value:unknown)=>{if(typeof value==='string'&&value.length<=256)set.add(value.toLowerCase());};
    for(const node of graph.nodes.filter(node=>node.affected)){
      const values=[node.data,node.restoreData].filter(Boolean) as any[];
      if(node.type==='consumers')add(consumers,node.id);
      const credential=CREDENTIAL_KINDS.includes(node.type as any)||node.type==='credentials';
      if(credential)add(credentials,node.id);
      for(const value of values){
        if(node.type==='consumers')add(consumers,value.id);
        add(consumers,value.consumer?.id);
        if(credential){add(credentials,value.id);
          if(typeof value.group==='string'&&/^kos-portal-api-[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(value.group))throw new ForbiddenException({code:'PORTAL_MANAGED_OBJECT',message:'门户凭证历史归属不允许通过通用回收站恢复'});
        }
      }
      const parent=graph.nodes.find(item=>node.dependencies?.includes(item.key)&&item.type==='consumers');if(parent)add(consumers,parent.id);
      const parts=node.path?.split('/').filter(Boolean)??[];
      if(parts[0]==='consumers'&&parts.length>=2){try{add(consumers,decodeURIComponent(parts[1]));if(credential&&parts[3])add(credentials,decodeURIComponent(parts[3]));}catch{throw new ConflictException({code:'GRAPH_INVALID'});}}
    }
    if(!consumers.size&&!credentials.size)return;
    const owned=await tx.query(`SELECT g.id FROM portal_application_grants g
      WHERE m6_portal_scope_alias($1,g.transport_scope,g.cluster_id)
        AND (g.consumer_id::text=ANY($2::text[]) OR g.acl_id::text=ANY($3::text[]))
      UNION ALL SELECT c.id FROM portal_credentials c JOIN portal_application_grants g
        ON g.cluster_id=c.cluster_id AND g.workspace_id=c.workspace_id AND g.id=c.grant_id
      WHERE m6_portal_scope_alias($1,g.transport_scope,g.cluster_id) AND c.kong_id::text=ANY($3::text[]) LIMIT 1`,[clusterId,[...consumers],[...credentials]]);
    if(owned.length)throw new ForbiddenException({code:'PORTAL_MANAGED_OBJECT',message:'门户凭证历史归属不允许通过通用回收站恢复'});
  }

  /** Published/pending Portal publications own their Service and auth plugins.
   * Ordinary recycle must refuse before any durable archive so the graph cannot
   * land in partially_deleted after PORTAL_UNMANAGED_AUTH_BOUNDARY mid-DELETE. */
  async assertPortalArchiveDeleteAllowed(clusterId:string,graph:RecycleGraph,tx:DbService=this.db):Promise<void>{
    if(!graph||!Array.isArray(graph.nodes)||graph.nodes.length>10000||graph.nodes.some(node=>!node||typeof node.affected!=='boolean'||typeof node.type!=='string'
      ||typeof node.id!=='string'||!node.id||node.id.length>256||typeof node.path!=='string'||!Array.isArray(node.dependencies)))throw new ConflictException({code:'GRAPH_INVALID'});
    const ids=new Set<string>();
    const add=(value:unknown)=>{if(typeof value==='string'&&value&&value.length<=256)ids.add(value.toLowerCase());};
    for(const node of graph.nodes.filter(node=>node.affected)){
      add(node.id);add(node.data?.id);
      if(node.type==='plugins'){add(node.data?.id);add(node.restoreData?.id);}
    }
    if(!ids.size)return;
    const owned=await tx.query(`SELECT p.id FROM portal_publications p
      WHERE m6_portal_scope_alias($1,p.transport_scope,p.cluster_id)
        AND (p.service_id::text=ANY($2::text[])
          OR COALESCE(p.key_auth_plugin_id::text,'')=ANY($2::text[])
          OR COALESCE(p.acl_plugin_id::text,'')=ANY($2::text[]))
        AND (p.published_revision IS NOT NULL OR p.state='pending')
      LIMIT 1`,[clusterId,[...ids]]);
    if(owned.length)throw new ForbiddenException({code:'PORTAL_PUBLISHED_OBJECT',message:'已发布或待发布的门户服务及其认证插件不可通过通用回收站删除，请先取消发布'});
  }

  async preview(clusterId:string,id:string,actor:AuthUser,workspaceId?:string):Promise<any>{
    const {entry,graph,scope}=await this.entry(clusterId,id,actor,'read',workspaceId);
    await this.authorizeGraph(clusterId,actor,graph,'read',scope,true);
    const recoveryEntryId=await this.completeRecoveryEntry(entry,actor,scope,'read');
    const nodes=await this.db.query('SELECT node_key,entity_type,original_id,affected,dependencies,delete_state,restore_state,restored_id,safe_error FROM recycle_nodes WHERE entry_id=$1 ORDER BY node_key',[id]);
    const {payload_secret,...safeEntry}=entry;
    return {entry:safeEntry,graph:this.secrets.redact(graph),nodes,...(recoveryEntryId?{recoveryEntryId}: {})};
  }

  /** Component receipts remain available as execution evidence. Restoration
   * must use the complete graph captured before the first child was deleted. */
  private async completeRecoveryEntry(entry:Entry,actor:AuthUser,scope:WorkspaceFilter,action:'read'|'write'):Promise<string|null>{
    const link=await this.db.one<{recycle_entry_id:string}>(`SELECT g.recycle_entry_id FROM configuration_recycle_components c
      JOIN configuration_recycle_graphs g ON g.cluster_id=c.cluster_id AND g.workspace_id=c.workspace_id AND g.id=c.graph_id
      WHERE c.cluster_id=$1 AND c.recycle_entry_id=$2 AND g.object_workspace_id=$3`,[entry.cluster_id,entry.id,scope.workspaceId]);
    if(!link)return null;
    const parent=await this.entry(entry.cluster_id,link.recycle_entry_id,actor,'read',scope.workspaceId);
    if(action==='write')await this.assertPortalRestoreAllowed(entry.cluster_id,parent.graph);
    await this.authorizeGraph(entry.cluster_id,actor,parent.graph,action,parent.scope,true);
    return parent.entry.id;
  }

  private cursorSignature(value:string):Buffer{
    const key=process.env.APP_SECRET;if(!key||key.length<32)throw new Error('APP_SECRET must contain at least 32 characters');
    return createHmac('sha256',key).update('recycle-cursor:v1:').update(value).digest();
  }

  async list(clusterId:string,actor:AuthUser,options:{size?:number;cursor?:string;type?:string;state?:string;search?:string;workspaceId?:string}={}):Promise<any>{
    await this.authz.assertCluster(actor,clusterId,'recycle-bin','read',options.workspaceId);
    const scope=await this.scope(clusterId,actor,options.workspaceId,true);
    const size=options.size??20;if(!Number.isInteger(size)||size<1||size>100)throw new BadRequestException('size 必须为 1–100');
    if(options.search!==undefined&&(typeof options.search!=='string'||options.search.length>256))throw new BadRequestException('搜索词不能超过 256 字符');
    const binding={clusterId,workspaceId:scope.workspaceId,workspaceRevision:scope.workspaceRevision,workspaceBinding:scope.binding,userId:actor.id,permissionVersion:await this.authz.permissionVersion(actor),type:options.type??null,state:options.state??null,search:options.search??null,size};
    let position:{createdAt:string;id:string}|null=null;
    if(options.cursor){
      try{
        const [encoded,signature,...extra]=options.cursor.split('.');
        const actual=Buffer.from(signature,'base64url'),expected=this.cursorSignature(encoded);
        if(extra.length||actual.length!==expected.length||!timingSafeEqual(actual,expected))throw new Error();
        const parsed=JSON.parse(Buffer.from(encoded,'base64url').toString('utf8'));
        if(JSON.stringify(parsed.binding)!==JSON.stringify(binding)||parsed.expiresAt<Date.now())throw new Error();
        position=parsed.position;
        if(!position||!/^\d{4}-/.test(position.createdAt)||!/^[0-9a-f-]{36}$/i.test(position.id))throw new Error();
      }catch{throw new BadRequestException({code:'INVALID_CURSOR',message:'回收站分页游标无效或已过期'});}
    }
    const rows=await this.db.query<Entry>(`SELECT * FROM recycle_entries WHERE cluster_id=$1 AND state<>'purged'
      AND NOT EXISTS(SELECT 1 FROM configuration_recycle_components c WHERE c.cluster_id=recycle_entries.cluster_id AND c.recycle_entry_id=recycle_entries.id)
      AND (workspace_id=$8 OR workspace_id IS NULL)
      AND ($2::text IS NULL OR root_type=$2) AND ($3::text IS NULL OR state=$3)
      AND ($7::text IS NULL OR position(lower($7) in lower(root_name))>0 OR position(lower($7) in lower(original_id))>0)
      AND ($4::timestamptz IS NULL OR (created_at,id)<($4::timestamptz,$5::uuid)) ORDER BY created_at DESC,id DESC LIMIT $6`,
      [clusterId,options.type??null,options.state??null,position?.createdAt??null,position?.id??null,size+1,options.search??null,scope.workspaceId]);
    const page=rows.slice(0,size),items:any[]=[];let unavailable=0;
    for(const row of page){
      const graph=this.secrets.decrypt<RecycleGraph>(row.payload_secret!,`recycle:${row.id}`),root=graph.nodes.find(node=>node.key===graph.rootKey);
      if(!root)continue;
      try{await this.bindEntry(row,graph,actor,scope);await this.authorizeGraph(clusterId,actor,graph,'read',scope,true);}catch(error){if(error instanceof HttpException&&error.getStatus()===403)continue;
        // An entry whose live parent (e.g. the Service of a recycled Route) no longer exists cannot be
        // authorized against its parent. Skip it (fail closed: never expose it unauthorized) instead of
        // failing the whole page, and report only an aggregate count so operators know to restore parents first.
        if(error instanceof HttpException&&error.getStatus()===404){unavailable++;continue;}
        throw error;}
      const {payload_secret,...safe}=row;items.push(safe);
    }
    let nextCursor:string|null=null;
    if(rows.length>size&&page.length){
      const last=page[page.length-1];const encoded=Buffer.from(JSON.stringify({binding,position:{createdAt:new Date(last.created_at).toISOString(),id:last.id},expiresAt:Date.now()+3600000})).toString('base64url');
      nextCursor=`${encoded}.${this.cursorSignature(encoded).toString('base64url')}`;
    }
    if(await this.authz.permissionVersion(actor)!==binding.permissionVersion)throw new ForbiddenException({code:'PERMISSIONS_CHANGED'});
    return {items,nextCursor,size,total:null,...(unavailable?{unavailableCount:unavailable}:{})};
  }

  async restore(clusterId:string,id:string,actor:AuthUser,confirmation:Confirmation,request:{requestId?:string;ip?:string;idempotencyKey?:string;workspaceId?:string}={}):Promise<any>{
    const {entry,graph,scope}=await this.entry(clusterId,id,actor,'write',request.workspaceId);
    const recoveryEntryId=await this.completeRecoveryEntry(entry,actor,scope,'write');
    if(recoveryEntryId)throw new ConflictException({code:'RECYCLE_COMPONENT_RESTORE_REQUIRED',message:'请通过完整回收图恢复本批次对象及其依赖',recoveryEntryId});
    this.validateConfirmation(confirmation,entry.root_name);
    await this.authorizeGraph(clusterId,actor,graph,'write',scope,true);
    if(entry.state==='restored')return {entryId:id,state:'restored',restored:await this.db.query('SELECT entity_type AS type,original_id AS "originalId",restored_id AS "restoredId" FROM recycle_nodes WHERE entry_id=$1 AND affected=true',[id])};
    if(entry.state==='deleting')await this.reconcileConfigurationArchive(entry,graph,actor,scope.workspaceId,request);
    if(['deleting','restoring'].includes(entry.state))throw new ConflictException({code:'RECYCLE_BUSY',message:'此归档仍有正在执行或未确认的步骤，请先核验原配置作业'});
    const root=graph.nodes.find(node=>node.key===graph.rootKey)!;
    const result=await this.mutations.execute({clusterId,actor,entityType:entry.root_type,entityId:entry.original_id,action:'restore',
      before:root.data,payload:{entryId:id},impactNodes:graph.nodes,...request,workspaceId:scope.workspaceId},async()=>{
      // Reject moved shared dependencies before creating the first missing object.
      for(const node of graph.nodes.filter(item=>!item.affected)){
        const current=await this.read(clusterId,node.path);
        await this.membership(clusterId,scope,graph,node,current,true);
        await this.authz.assertEntity(actor,clusterId,node.type,'read',current,scope.workspaceId);
      }
      await this.db.exec("UPDATE recycle_entries SET state='restoring',updated_at=now() WHERE id=$1",[id]);
      const restored:any[]=[];
      let restoredRoot:any;
      for(const node of graphOrder(graph)){
        try{
          if(!node.affected){
            const existing=await this.read(clusterId,node.path);
            await this.membership(clusterId,scope,graph,node,existing,true);
            await this.authz.assertEntity(actor,clusterId,node.type,'read',existing,scope.workspaceId);
            continue;
          }
          if(!node.restorable)throw new ConflictException({code:'OBJECT_NOT_RESTORABLE',message:node.reason??'此对象无法可靠恢复'});
          const status=await this.db.one<any>('SELECT restore_state,restored_id,delete_state FROM recycle_nodes WHERE entry_id=$1 AND node_key=$2',[id,node.key]);
          let existing:any=null;
          if(node.type==='targets')existing=await this.effectiveTarget(clusterId,node);
          else try{existing=await this.read(clusterId,node.path);}catch(error){if(!(error instanceof HttpException&&error.getStatus()===404))throw error;}
          if(node.type==='targets'&&existing&&status?.delete_state==='deleted'&&status?.restore_state!=='restored'&&status?.restore_state!=='uncertain'){
            throw new ConflictException({code:'RESTORE_TARGET_CONFLICT',message:'此地址已存在新的有效 Target，恢复已停止'});
          }
          let restoredObject:any;
          if(existing){
            await this.membership(clusterId,scope,graph,node,existing,true);
            const existingComparison=comparable(existing),desiredComparison=comparable(node.data);
            if(node.type==='targets'){delete existingComparison.id;delete desiredComparison.id;}
            if(node.type==='certificates'){delete existingComparison.snis;delete desiredComparison.snis;}
            if(this.secrets.fingerprint(existingComparison)!==this.secrets.fingerprint(desiredComparison)){
              throw new ConflictException({code:'RESTORE_ID_CONFLICT',message:`原 ID ${node.id} 已被不同配置占用，恢复已停止`});
            }
            restoredObject=existing;
          }else{
            await this.membership(clusterId,scope,graph,node,node.data,true);
            const body={...(node.restoreData??node.data)};
            delete body.created_at;delete body.updated_at;delete body.ttl;
            let originalTargetId:string|undefined;
            if(node.type==='targets'){
              const parent=this.owner(graph,node);
              // Deleting an Upstream removes its Target history. Preserve an
              // original ID only after the affected parent is restored and
              // that precise Target is genuinely absent. A single-Target
              // archive still appends a new immutable physical history row.
              if(parent?.affected){
                const currentParent=await this.read(clusterId,parent.path);
                if(currentParent.id!==parent.id||this.secrets.fingerprint(comparable(currentParent))!==this.secrets.fingerprint(comparable(parent.data))){
                  throw new ConflictException({code:'RESTORE_TARGET_PARENT_CHANGED',message:'恢复 Target 的原 Upstream 配置已变化'});
                }
                try{await this.read(clusterId,node.path);}
                catch(error){
                  if(!(error instanceof HttpException&&error.getStatus()===404))throw error;
                  originalTargetId=node.id;
                }
              }
              if(!originalTargetId)delete body.id;
              delete body.upstream;
              restoredObject=await this.kong.request(clusterId,'POST',node.path.replace(/\/[^/]+$/,''),body);
            }else restoredObject=await this.kong.request(clusterId,'POST',node.path.replace(/\/[^/]+$/,''),body);
            restoredObject=await this.read(clusterId,node.path.replace(/[^/]+$/,encodeURIComponent(restoredObject.id??node.id)));
            if(node.type==='targets'&&(originalTargetId&&restoredObject.id!==originalTargetId
              ||restoredObject.upstream?.id!==this.owner(graph,node)?.id||restoredObject.target!==node.data.target||restoredObject.weight!==node.data.weight)){
              throw new ConflictException({code:'RESTORE_TARGET_READBACK_MISMATCH',message:'恢复 Target 的原 ID、所属 Upstream、地址或权重不匹配'});
            }
          }
          await this.membership(clusterId,scope,graph,node,restoredObject,true);
          await this.authz.assertEntity(actor,clusterId,node.type,'write',restoredObject,scope.workspaceId);
          if(CREDENTIAL_KINDS.includes(node.type as any))await this.credentials.save(clusterId,node.data.consumer?.id??entry.parent_id!,node.type,restoredObject,node.restoreData??{});
          await this.db.transaction(async tx=>{
            await tx.exec("UPDATE recycle_nodes SET restore_state='restored',restored_id=$3,safe_error=NULL,updated_at=now() WHERE entry_id=$1 AND node_key=$2",[id,node.key,restoredObject.id??node.id]);
            await this.audit.append({actorId:actor.id,clusterId,workspaceId:scope.workspaceId,entityType:node.type,entityId:restoredObject.id??node.id,action:'restore',before:existing??null,after:restoredObject,
              result:'success',requestId:request.requestId,ip:request.ip,scopeHints:nativeAuditScope({type:node.type,id:restoredObject.id??node.id,before:existing??null,after:restoredObject,beforeWorkspaceId:existing?scope.workspaceId:null,afterWorkspaceId:scope.workspaceId,parentId:this.owner(graph,node)?.id,credentialKind:CREDENTIAL_KINDS.includes(node.type as any)?node.type:undefined})},tx);
          });
          restored.push({type:node.type,originalId:node.id,restoredId:restoredObject.id??node.id});
          await this.indexChange(clusterId,node,restoredObject);
          if(node.key===graph.rootKey)restoredRoot=restoredObject;
        }catch(error:any){
          const uncertain=!(error instanceof HttpException)||error.getStatus()>=500;
          await this.db.transaction(async tx=>{
            await tx.exec('UPDATE recycle_nodes SET restore_state=$3,safe_error=$4,updated_at=now() WHERE entry_id=$1 AND node_key=$2',[id,node.key,uncertain?'uncertain':'failed','恢复失败或结果待核验']);
            await tx.exec("UPDATE recycle_entries SET state='partially_restored',updated_at=now() WHERE id=$1",[id]);
            await this.audit.append({actorId:actor.id,clusterId,workspaceId:scope.workspaceId,entityType:node.type,entityId:node.id,action:'restore',result:uncertain?'uncertain':'failed',
              requestId:request.requestId,ip:request.ip},tx);
          });
          throw new ServiceUnavailableException({code:'RECYCLE_RESTORE_INCOMPLETE',message:'部分对象未恢复，已完成步骤保留；修复依赖后可继续恢复',entryId:id,restored,
            cause:error instanceof HttpException?(error.getResponse() as any)?.code:'RESTORE_FAILED'});
        }
      }
      await this.db.exec("UPDATE recycle_entries SET state='restored',restored_at=now(),updated_at=now() WHERE id=$1",[id]);
      return {entryId:id,state:'restored',restored,entity:restoredRoot};
    });
    return this.secrets.redact(result);
  }

  /** Reconcile only authenticated SQL receipt facts after execution ended.
   * This never sends a gateway request or converts an unknown native outcome
   * into success; active leases and unresolved steps keep restoration blocked. */
  private async reconcileConfigurationArchive(entry:Entry,graph:RecycleGraph,actor:AuthUser,wid:string,request:{requestId?:string;ip?:string}):Promise<void>{
    await this.db.transaction(async tx=>{
      const g=await tx.one<any>(`SELECT g.*,e.state AS execution_state,e.expires_at,j.lease_expires_at FROM configuration_recycle_graphs g
        JOIN configuration_executions e ON e.cluster_id=g.cluster_id AND e.workspace_id=g.workspace_id AND e.id=g.execution_id
        JOIN configuration_jobs j ON j.cluster_id=g.cluster_id AND j.workspace_id=g.workspace_id AND j.id=g.job_id
        WHERE g.cluster_id=$1 AND g.object_workspace_id=$2 AND g.recycle_entry_id=$3`,[entry.cluster_id,wid,entry.id]);
      if(!g)return;if(g.graph_hmac!==this.secrets.fingerprint(graph))throw new ConflictException({code:'RECYCLE_GRAPH_INVALID'});
      const expired=Date.parse(g.expires_at)<Date.now()-5000&&Date.parse(g.lease_expires_at)<Date.now()-5000;
      if(['claimed','executing'].includes(g.execution_state)&&!expired)return;
      const unresolved=await tx.one<any>("SELECT 1 FROM configuration_job_steps WHERE job_id=$1 AND execution_id=$2 AND object_workspace_id=$3 AND state IN('running','uncertain') LIMIT 1",[g.job_id,g.execution_id,wid]);if(unresolved)return;
      const completed=await tx.query<any>(`SELECT s.id,s.receipt_operation_id,s.recycle_entry_id,r.root_type,r.credential_kind,r.parent_id,r.original_id
        FROM configuration_job_steps s JOIN recycle_entries r ON r.cluster_id=s.cluster_id AND r.id=s.recycle_entry_id
        JOIN mutation_operations m ON m.cluster_id=s.cluster_id AND m.id=s.receipt_operation_id
        WHERE s.cluster_id=$1 AND s.workspace_id=$2 AND s.job_id=$3 AND s.execution_id=$4 AND s.object_workspace_id=$5 AND s.state='succeeded'
        AND m.actor_id=$6 AND m.state='succeeded' AND m.remote_completed AND m.action='delete'`,[g.cluster_id,g.workspace_id,g.job_id,g.execution_id,wid,g.actor_id]);
      for(const r of completed){const key=`${r.credential_kind??r.root_type}:${r.parent_id?`${r.parent_id}:`:''}${r.original_id}`;
        if(!graph.nodes.some(n=>n.key===key&&n.affected))throw new ConflictException({code:'RECYCLE_GRAPH_INVALID'});
        await tx.exec(`INSERT INTO configuration_recycle_components(cluster_id,workspace_id,graph_id,step_id,recycle_entry_id,operation_id)
          VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(cluster_id,recycle_entry_id) DO NOTHING`,[g.cluster_id,g.workspace_id,g.id,r.id,r.recycle_entry_id,r.receipt_operation_id]);
        await tx.exec("UPDATE recycle_nodes SET delete_state='deleted',updated_at=now() WHERE entry_id=$1 AND node_key=$2 AND affected=true",[entry.id,key]);
      }
      const remaining=await tx.one<any>("SELECT count(*)::integer AS count FROM recycle_nodes WHERE entry_id=$1 AND affected=true AND delete_state<>'deleted'",[entry.id]);
      const next=remaining.count===0?'deleted':'partially_deleted';
      const changed=await tx.exec("UPDATE recycle_entries SET state=$2,updated_at=now() WHERE id=$1 AND state='deleting'",[entry.id,next]);
      if(changed){await this.audit.append({actorId:actor.id,clusterId:entry.cluster_id,workspaceId:wid,entityType:'recycle_entries',entityId:entry.id,action:'archive.configuration-graph.reconcile',requestId:request.requestId,ip:request.ip,before:{state:'deleting'},after:{state:next,remainingNodes:remaining.count,nativeWrites:0},result:'success'},tx);entry.state=next;}
    });
  }

  async purge(clusterId:string,id:string,actor:AuthUser,confirmation:Confirmation,request:{requestId?:string;ip?:string;idempotencyKey?:string;workspaceId?:string;revision?:number}={}):Promise<any>{
    const originalTx=this.controlBridge?.currentTransaction();
    if(originalTx)return this.approvedPurge(clusterId,id,actor,confirmation,request,originalTx);
    if(this.controlBridge){
      await this.authz.assertCluster(actor,clusterId,'recycle-bin','delete',request.workspaceId);
      const cluster=await this.db.one<any>('SELECT execution_mode FROM clusters WHERE id=$1 AND deleted_at IS NULL',[clusterId]);
      if(cluster?.execution_mode==='approval')throw new ConflictException({code:'APPROVAL_REQUIRED',message:'此集群的永久清除须提交审批工单'});
    }
    const {entry,graph,scope}=await this.entry(clusterId,id,actor,'delete',request.workspaceId);
    this.validateConfirmation(confirmation,entry.root_name);
    if(['deleting','restoring'].includes(entry.state))throw new ConflictException('此归档正在执行');
    const root=graph.nodes.find(node=>node.key===graph.rootKey)!;
    await this.authorizeGraph(clusterId,actor,graph,'delete',scope,true);
    return this.mutations.execute({clusterId,actor,entityType:'recycle_entries',entityId:id,action:'purge',before:{id,state:entry.state},payload:{confirmed:true,confirm_name:entry.root_name},...request,workspaceId:scope.workspaceId,archivedWorkspace:true},async()=>{
      await this.db.transaction(async tx=>{
        const current=await tx.one<any>('SELECT * FROM recycle_entries WHERE cluster_id=$1 AND id=$2 FOR UPDATE',[clusterId,id]);
        if(!current||current.revision!==entry.revision||current.state!==entry.state||current.payload_secret!==entry.payload_secret)throw new ConflictException({code:'RECYCLE_PURGE_CHANGED'});
        await this.assertControlPurgeSubject(clusterId,id,actor,'delete',scope.workspaceId,tx);
        if((await tx.one<any>('SELECT m11_recycle_purge_available($1,$2) AS eligible',[clusterId,id]))?.eligible!==true)throw new ConflictException({code:'RECYCLE_PURGE_REFERENCED'});
        if(await tx.exec("UPDATE recycle_entries SET state='purged',payload_secret=NULL,purged_at=now(),updated_at=now() WHERE cluster_id=$1 AND id=$2 AND workspace_id=$3 AND revision=$4 AND payload_secret=$5 AND state=$6",[clusterId,id,scope.workspaceId,current.revision,current.payload_secret,current.state])!==1)throw new ConflictException({code:'RECYCLE_PURGE_CHANGED'});
        await this.audit.append({actorId:actor.id,clusterId,workspaceId:scope.workspaceId,entityType:root.type,entityId:root.id,action:'purge_recycle',before:{entryId:id,rootType:entry.root_type,state:current.state,revision:current.revision,payloadHmac:this.secrets.fingerprint(current.payload_secret)},after:{entryId:id,state:'purged',revision:current.revision+1,payloadPresent:false},
          requestId:request.requestId,ip:request.ip},tx);
      });
      return {id,purged:true};
    });
  }
}
