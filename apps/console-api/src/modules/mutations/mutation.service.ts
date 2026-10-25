import { BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { AuthUser } from '../../common/auth';
import { DbService } from '../../infrastructure/db.service';
import { RedisService } from '../../infrastructure/redis.service';
import { SecretService } from '../../infrastructure/secret.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { AuditService } from '../audit/audit.service';
import { nativeAuditScope } from '../event-producers/native-audit-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService, WorkspaceFilter } from '../workspaces/workspace-resolver.service';
import { workspaceTag } from '../../infrastructure/kong/tags';
import { currentEffectiveTarget } from '../../infrastructure/kong/effective-target';
import { disabledTargetReadback } from '../../infrastructure/kong/disabled-target-readback';
import {readTargetHealthObservation,type TargetHealthObservation} from '../../infrastructure/kong/target-health-observation';
import type {TargetHealthTransportReceipt} from '../../infrastructure/kong/target-health-transport-receipt';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { grantMatchesEntity } from '../authorization/grant-policy';
import { deriveImpact, validImpact, impactOverlaps, mergeImpact, conservativeNativeImpact, MutationImpact } from './mutation-impact';
import type { ApprovedMutationBinding } from '../workflows/approved-execution.types';

export interface MutationContext {
  clusterId: string;
  workspaceId?: string;
  /** Trusted RecycleService purge context only; never accepted from an HTTP body. */
  archivedWorkspace?: boolean;
  actor: AuthUser;
  entityType: string;
  entityId?: string;
  action: string;
  idempotencyKey?: string;
  requestId?: string;
  ip?: string;
  before?: unknown;
  payload?: unknown;
  workflowId?: string;
  parentId?: string;
  credentialKind?: string;
  confirmName?: string;
  operationId?: string;
  /** Validated server graph only. Controllers never copy this field from JSON. */
  impactNodes?: ReadonlyArray<{type:string;id:string;data?:any}>;
  /** Fixed writer's original sealed health observation; a fact, not a permit. */
  targetHealthBefore?:Readonly<TargetHealthObservation>;
}

const nativeEntities = new Set(['services','routes','consumers','plugins','upstreams','certificates','ca_certificates','snis']);

@Injectable()
export class MutationService {
  constructor(private readonly db: DbService, private readonly redis: RedisService,
    private readonly secrets: SecretService, private readonly audit: AuditService,
    private readonly kong: KongService, private readonly authz: AuthorizationService,
    private readonly workspaces:WorkspaceResolverService,private readonly execution:KongExecutionContextService) {}

  private async contextWorkspace(context:MutationContext):Promise<void>{
    const archived=context.archivedWorkspace===true&&context.entityType==='recycle_entries'&&context.action==='purge'&&await this.authz.isPlatformAdmin(context.actor)&&!!context.workspaceId;
    const metadata=context.entityType==='workspaces'&&['update','restore','delete'].includes(context.action)&&!!context.workspaceId;
    if(metadata)await this.authz.assertCluster(context.actor,context.clusterId,'workspaces',context.action==='delete'?'delete':'write',context.workspaceId);
    const row=archived||metadata?await this.workspaces.get(context.clusterId,context.workspaceId!,true):await this.workspaces.resolve(context.clusterId,context.workspaceId);
    if(!archived&&!metadata&&row.status!=='active')throw new ConflictException({code:'WORKSPACE_DISABLED',message:'此工作区已停用，不可执行变更'});
    context.workspaceId=row.id;
  }

  /** Historical NULL scopes are bound only after examining the encrypted real entity. */
  private async operationWorkspace(operation:any,actor:AuthUser,workspaceId?:string,permission='read'):Promise<string>{
    const platform=!!workspaceId&&await this.authz.isPlatformAdmin(actor);
    const row=platform?await this.workspaces.get(operation.cluster_id,workspaceId!,true):await this.workspaces.resolve(operation.cluster_id,workspaceId);
    if(row.status!=='active'&&!platform)throw new ForbiddenException({code:'WORKSPACE_INACTIVE',message:'归档工作区需平台管理员显式选择'});
    if(operation.workspace_id){
      if(operation.workspace_id!==row.id)throw new ForbiddenException({code:'WORKSPACE_MISMATCH',message:'变更记录属于其他工作区'});
      return row.id;
    }
    let entity=operation.before_secret?this.secrets.decrypt<any>(operation.before_secret,`mutation:${operation.id}:before`):null;
    if(!entity&&operation.result_secret){const result=this.secrets.decrypt<any>(operation.result_secret,`mutation:${operation.id}:result`);entity=result?.entity??result;}
    if(!entity||!nativeEntities.has(operation.entity_type)){
      const archived=await this.db.one<any>('SELECT id,payload_secret FROM recycle_entries WHERE cluster_id=$1 AND mutation_id=$2 AND payload_secret IS NOT NULL',[operation.cluster_id,operation.id]);
      if(archived){
        const graph=this.secrets.decrypt<any>(archived.payload_secret,`recycle:${archived.id}`),root=graph.nodes?.find((node:any)=>node.key===graph.rootKey);
        entity=root?.data;
        if(root&&['targets','key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].includes(root.type))entity=graph.nodes?.find((node:any)=>root.dependencies.includes(node.key)&&node.type===(root.type==='targets'?'upstreams':'consumers'))?.data;
      }else if(entity&&(operation.entity_type==='targets'||operation.entity_type==='credentials')){
        const parent=operation.entity_type==='targets'?entity.upstream:entity.consumer;
        if(parent?.id)entity=await this.kong.request(operation.cluster_id,'GET',`/${operation.entity_type==='targets'?'upstreams':'consumers'}/${encodeURIComponent(parent.id)}`);else entity=null;
      }else entity=null;
    }
    if(!entity)throw new ForbiddenException({code:'LEGACY_SCOPE_UNVERIFIABLE',message:'历史变更缺少可核验的工作区对象，未绑定默认区'});
    if(row.status!=='active'){
      const scope:WorkspaceFilter={workspaceId:row.id,workspaceRevision:row.revision,mode:row.is_default?'default':'tag',workspaceTag:workspaceTag(row.code),requestedTags:[],tagOperator:'and',requiresPostFilter:true,binding:`archived:${row.id}:${row.revision}`};
      this.workspaces.assertMembership(scope,entity);
    }else{
      const classified=await this.workspaces.classify(operation.cluster_id,entity.tags);
      if(classified.state!=='resolved'||classified.workspace?.id!==row.id)throw new ForbiddenException({code:'WORKSPACE_MISMATCH',message:'历史变更所属工作区不匹配或无法核验'});
    }
    await this.authz.assertEntity(actor,operation.cluster_id,operation.credential_kind??operation.entity_type,permission,entity,row.id);
    const updated=await this.db.transaction(async tx=>{
      const count=await tx.exec('UPDATE mutation_operations SET workspace_id=$2 WHERE id=$1 AND workspace_id IS NULL',[operation.id,row.id]);
      if(count)await this.audit.append({actorId:actor.id,clusterId:operation.cluster_id,workspaceId:row.id,entityType:'mutation_operations',entityId:operation.id,action:'workspace_scope_bound',before:{workspace_id:null},after:{workspace_id:row.id},result:'success'},tx);
      return count;
    });
    if(updated===0){const current=await this.db.one<any>('SELECT workspace_id FROM mutation_operations WHERE id=$1',[operation.id]);if(current?.workspace_id!==row.id)throw new ForbiddenException({code:'WORKSPACE_MISMATCH',message:'变更工作区在核验期间变化'});}
    operation.workspace_id=row.id;
    return row.id;
  }

  private errorCode(error: any): string {
    const response = error instanceof HttpException ? error.getResponse() : null;
    return (typeof response === 'object' && response !== null && 'code' in response ? String(response.code) : error?.code) || 'MUTATION_FAILED';
  }

  private auditContext(context: MutationContext) {
    return { actorId: context.actor.id, clusterId: context.clusterId,workspaceId:context.workspaceId, entityType: context.entityType,
      entityId: context.entityId, requestId: context.requestId, ip: context.ip, workflowId: context.workflowId };
  }

  private requestHash(context:MutationContext,binding?:ApprovedMutationBinding|null):string{
    return this.secrets.fingerprint({ actor:context.actor.id,clusterId:context.clusterId,workspaceId:context.workspaceId??null,entityType:context.entityType,
      entityId:context.entityId??null,action:context.action,payload:context.payload??null,parentId:context.parentId??null,
      credentialKind:context.credentialKind??null,...(binding?{approvedWorkflow:binding}:{}) });
  }

  private annotationType(context:Pick<MutationContext,'entityType'|'entityId'|'payload'>):string|undefined{
    if(context.entityType!=='annotations')return undefined;
    const payload=context.payload as any;
    if(!payload||!nativeEntities.has(payload.entityType)||typeof payload.entityId!=='string'||payload.entityId!==context.entityId)
      throw new ForbiddenException({code:'ANNOTATION_SCOPE_UNVERIFIABLE',message:'实体备注缺少可核验的原对象范围'});
    return payload.entityType;
  }

  /** Metadata permissions never replace the real native object's permission. */
  private async assertResource(context:MutationContext,permission:string,entity:any):Promise<void>{
    const type=this.annotationType(context);
    if(!type){await this.authz.assertEntity(context.actor,context.clusterId,context.credentialKind??context.entityType,permission,entity,context.workspaceId);return;}
    if(entity?.id!==context.entityId)throw new ForbiddenException({code:'ANNOTATION_SCOPE_UNVERIFIABLE',message:'实体备注与原对象标识不一致'});
    await this.authz.assertEntity(context.actor,context.clusterId,type,permission,entity,context.workspaceId);
    const snapshot=await this.authz.snapshot(context.actor);
    if(!snapshot.user.superAdmin&&!snapshot.grants.some(grant=>grantMatchesEntity(grant,'annotations',permission as any,
      {clusterId:context.clusterId,workspaceId:context.workspaceId,entityType:type,entity})))
      throw new ForbiddenException({code:'PERMISSION_DENIED',message:'当前账号无此实体备注操作权限'});
  }

  private async nativeMembership(context:MutationContext,entity:any):Promise<void>{
    if(entity&&(nativeEntities.has(context.entityType)||this.annotationType(context)))this.workspaces.assertMembership(await this.workspaces.listScope(context.clusterId,context.workspaceId),entity);
  }

  private async legacyImpact(operation:any):Promise<MutationImpact>{
    try{
      const before=operation.before_secret?this.secrets.decrypt<any>(operation.before_secret,`mutation:${operation.id}:before`):null;
      const payload=operation.payload_secret?this.secrets.decrypt<any>(operation.payload_secret,`mutation:${operation.id}:payload`):null;
      const result=operation.result_secret?this.secrets.decrypt<any>(operation.result_secret,`mutation:${operation.id}:result`):null;
      const archived=await this.db.one<any>('SELECT id,payload_secret FROM recycle_entries WHERE cluster_id=$1 AND mutation_id=$2 AND payload_secret IS NOT NULL',[operation.cluster_id,operation.id]);
      let nodes:any[]=[];
      if(archived){const graph=this.secrets.decrypt<any>(archived.payload_secret,`recycle:${archived.id}`);if(!graph.complete||!Array.isArray(graph.nodes)||graph.nodes.length>10000)return conservativeNativeImpact();nodes=graph.nodes;}
      if(operation.entity_type==='workspace_migration'&&!nodes.length)return conservativeNativeImpact();
      if(!operation.workspace_id&&(nativeEntities.has(operation.entity_type)||['targets','credentials'].includes(operation.entity_type))){
        let entity=before??result?.entity??result;
        if(['targets','credentials'].includes(operation.entity_type)){
          const parent=operation.entity_type==='targets'?entity?.upstream:entity?.consumer;
          const parentId=typeof parent==='string'?parent:parent?.id;
          if(!parentId)return conservativeNativeImpact();
          entity=await this.execution.runInternalRead(operation.cluster_id,'operation-check',()=>this.kong.request(operation.cluster_id,'GET',`/${operation.entity_type==='targets'?'upstreams':'consumers'}/${encodeURIComponent(parentId)}`));
        }
        if(!entity||(await this.workspaces.classify(operation.cluster_id,entity.tags)).state!=='resolved')return conservativeNativeImpact();
      }
      if(!nativeEntities.has(operation.entity_type)&&!['targets','credentials','workspaces','workspace_migration','recycle_entries','annotations'].includes(operation.entity_type))return conservativeNativeImpact();
      return deriveImpact({entityType:operation.entity_type,entityId:operation.entity_id,action:operation.action,before,payload,result,nodes,
        parentId:payload?.parentId??before?.upstream?.id??before?.consumer?.id,credentialKind:payload?.credentialKind});
    }catch{return conservativeNativeImpact();}
  }

  private async assertNoUnresolved(context:MutationContext,transportScope:string,impact:MutationImpact,excludeId?:string):Promise<void>{
    const operations=await this.db.query<any>(`SELECT id,cluster_id,actor_id,workspace_id,entity_type,state,transport_scope FROM mutation_operations WHERE state IN ('running','uncertain')
      AND (transport_scope=$1 OR transport_scope IS NULL) AND ($2::uuid IS NULL OR id<>$2) ORDER BY created_at,id LIMIT 101`,[transportScope,excludeId??null]);
    if(operations.length>100)throw new ConflictException({code:'MUTATION_RECONCILIATION_REQUIRED',message:'存在未核验的变更，请先核验操作记录'});
    let bytes=0;
    for(const summary of operations){
      let operation=summary;
      let samePhysical=operation.transport_scope===transportScope;
      if(!operation.transport_scope){try{samePhysical=await this.kong.transportScope(operation.cluster_id)===transportScope;}catch{samePhysical=true;}}
      if(!samePhysical)continue;
      // Load one encrypted input/impact at a time instead of materializing 100 large payloads.
      operation=await this.db.one<any>("SELECT * FROM mutation_operations WHERE id=$1 AND state IN ('running','uncertain')",[summary.id]);
      if(!operation)continue;
      bytes+=Buffer.byteLength(JSON.stringify(operation),'utf8');
      if(bytes>32*1024*1024)throw new ConflictException({code:'MUTATION_RECONCILIATION_REQUIRED',message:'未核验变更的核验预算已耗尽，请先核验操作记录'});
      const oldImpact=validImpact(operation.impact)&&operation.impact.keyId===impact.keyId?operation.impact:await this.legacyImpact(operation);
      if(!impactOverlaps(impact,oldImpact))continue;
      let receiptId:string|undefined;
      if(operation.actor_id===context.actor.id&&operation.cluster_id===context.clusterId&&operation.workspace_id===context.workspaceId){
        try{await this.receipt(operation,context.actor,context.workspaceId);receiptId=operation.id;}catch{/* No receipt identifier without current read authorization. */}
      }
      throw new ConflictException({code:'MUTATION_RECONCILIATION_REQUIRED',message:'相关对象存在结果未确认的变更，请先核验操作记录',...(receiptId?{operationId:receiptId,state:operation.state}:{})});
    }
  }

  /** Extend a running operation to its complete server-captured closure before any graph write. */
  async claimGraphImpact(context:MutationContext,nodes:ReadonlyArray<{type:string;id:string;data?:any}>):Promise<void>{
    if(!context.operationId||this.execution.current().operation?.operationId!==context.operationId||nodes.length>10000)throw new ForbiddenException({code:'MUTATION_IMPACT_CONTEXT_INVALID',message:'对象图影响面缺少可信执行上下文'});
    await this.redis.assertLeaseOwnership();
    const operation=await this.db.one<any>("SELECT * FROM mutation_operations WHERE id=$1 AND actor_id=$2 AND cluster_id=$3 AND state='running'",[context.operationId,context.actor.id,context.clusterId]);
    if(!operation||operation.workspace_id!==context.workspaceId)throw new ForbiddenException({code:'MUTATION_IMPACT_CONTEXT_INVALID',message:'变更记录的作用域不匹配'});
    const impact=mergeImpact(validImpact(operation.impact)?operation.impact:deriveImpact(context),deriveImpact({...context,nodes}));
    const transportScope=await this.kong.transportScope(context.clusterId);
    await this.assertNoUnresolved(context,transportScope,impact,context.operationId);
    await this.redis.assertLeaseOwnership();
    await this.db.transaction(async tx=>{
      const count=await tx.exec("UPDATE mutation_operations SET impact=$2::jsonb WHERE id=$1 AND state='running' AND transport_scope=$3",[context.operationId,JSON.stringify(impact),transportScope]);
      if(count!==1)throw new ConflictException({code:'MUTATION_IMPACT_CHANGED',message:'变更影响面在确认期间变化'});
      await this.audit.append({...this.auditContext(context),entityType:'mutation_operations',entityId:context.operationId,action:'impact.claimed',after:{node_count:nodes.length},result:'success'},tx);
    });
  }

  /** Allows a completed DELETE to be replayed after its original object has gone. */
  async completed<T=any>(context:MutationContext):Promise<T|null>{
    if(!context.idempotencyKey)return null;
    if(!/^[a-zA-Z\d_.:-]{1,128}$/.test(context.idempotencyKey))throw new BadRequestException('幂等键格式无效');
    await this.contextWorkspace(context);
    await this.authz.assertCluster(context.actor,context.clusterId,context.credentialKind??context.entityType,context.action==='delete'?'delete':'write',context.workspaceId);
    const existing=await this.db.one<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND idempotency_key=$2',[context.clusterId,context.idempotencyKey]);
    if(!existing)return null;
    if(existing.actor_id!==context.actor.id||existing.action!==context.action||existing.entity_type!==context.entityType)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'幂等键已用于不同的变更请求'});
    await this.operationWorkspace(existing,context.actor,context.workspaceId,context.action==='delete'?'delete':'write');
    const before=this.secrets.decrypt<any>(existing.before_secret,`mutation:${existing.id}:before`);
    const aliases=[existing.entity_id,before?.id,before?.name,before?.username,before?.target].filter(value=>typeof value==='string');
    if(context.entityId&&!aliases.includes(context.entityId))throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'幂等键对应不同对象'});
    const canonical={...context,entityId:existing.entity_id??context.entityId};
    const binding=await this.execution.approvedMutationBinding({...canonical,before});
    if(this.requestHash(canonical,binding)!==existing.request_hash)throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'幂等键对应不同变更内容'});
    if(before!==null){await this.nativeMembership(context,before);await this.assertResource(context,context.action==='delete'?'delete':'write',before);}
    if(existing.state!=='succeeded'||!existing.result_secret)throw new ConflictException({code:'MUTATION_RESULT_UNCERTAIN',message:'此变更结果需要核验，不会重复执行',operationId:existing.id,state:existing.state});
    return this.projectHistoricalResult(this.secrets.decrypt<T>(existing.result_secret,`mutation:${existing.id}:result`),context.actor);
  }

  /** Trusted Engine recovery reads the original logical tuple. CREATE keeps
   * entityId null even after the gateway's UUID is recorded. No raw result,
   * secret, workflow capability or automatic retry is returned. */
  async inspectStepReceipt(context:MutationContext):Promise<{operationId:string;state:string;remoteStarted:boolean;remoteCompleted:boolean;entityId:string|null;safeResult:any}|null>{
    if(!context.idempotencyKey||!/^[a-zA-Z\d_.:-]{1,128}$/.test(context.idempotencyKey))throw new BadRequestException({code:'INVALID_IDEMPOTENCY_KEY',message:'幂等键格式无效'});
    return this.execution.runMutationActor(context,async()=>{
      await this.contextWorkspace(context);
      const action=context.action==='delete'?'delete':'write';
      await this.authz.assertCluster(context.actor,context.clusterId,context.credentialKind??context.entityType,action,context.workspaceId);
      if(context.before!=null){await this.nativeMembership(context,context.before);await this.assertResource(context,action,context.before);}
      const existing=await this.db.one<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND idempotency_key=$2',[context.clusterId,context.idempotencyKey]);
      if(!existing)return null;
      await this.operationWorkspace(existing,context.actor,context.workspaceId,action);
      // This reconstructs only a historical receipt hash. A DB tuple is never
      // passed to bindApprovedOperation and never becomes execution authority.
      const binding:ApprovedMutationBinding|null=existing.configuration_execution_id!=null?{version:2,workflowId:existing.workflow_id,configurationJobId:existing.configuration_job_id,
        configurationExecutionId:existing.configuration_execution_id,configurationStepId:existing.configuration_step_id,configurationPlanRevision:existing.configuration_plan_revision,
        configurationPlanHash:existing.configuration_plan_hash,beforeHmac:this.secrets.fingerprint(this.secrets.decrypt(existing.before_secret,`mutation:${existing.id}:before`))}:existing.workflow_execution_id!=null?{workflowId:existing.workflow_id,executionId:existing.workflow_execution_id,
        planRevision:existing.workflow_plan_revision,planHash:existing.workflow_plan_hash,stepId:existing.workflow_step_id,
        beforeHmac:this.secrets.fingerprint(this.secrets.decrypt(existing.before_secret,`mutation:${existing.id}:before`))}:null;
      if(existing.actor_id!==context.actor.id||existing.request_hash!==this.requestHash(context,binding)
        ||this.secrets.fingerprint(context.before??null)!==this.secrets.fingerprint(this.secrets.decrypt(existing.before_secret,`mutation:${existing.id}:before`)))throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'原步骤回执对应不同变更内容'});
      if(existing.entity_id&&context.action==='create'){
        const sealedId=(context.payload as any)?.id;
        if(!sealedId||existing.entity_id!==sealedId)throw new ConflictException({code:'MUTATION_RESULT_ID_MISMATCH',message:'原步骤对象标识与封存计划不一致'});
      }
      if(existing.entity_id&&nativeEntities.has(context.entityType)&&context.action!=='delete'){
        const path=`/${context.entityType}/${encodeURIComponent(existing.entity_id)}`;
        const actual=await this.execution.runInternalRead(context.clusterId,'operation-check',()=>this.kong.request(context.clusterId,'GET',path),{paths:[path],maxCalls:1});
        await this.nativeMembership(context,actual);await this.assertResource(context,action,actual);
      }
      if(existing.entity_id&&['credentials','targets'].includes(context.entityType)&&context.action!=='delete'){
        const parentId=context.parentId,kind=context.entityType==='targets'?'targets':context.credentialKind;
        if(!parentId||!kind)throw new ForbiddenException({code:'LEGACY_SCOPE_UNVERIFIABLE',message:'原步骤缺少可核验父对象'});
        const path=`/${context.entityType==='targets'?'upstreams':'consumers'}/${encodeURIComponent(parentId)}/${kind}/${encodeURIComponent(existing.entity_id)}`;
        const actual=await this.execution.runInternalRead(context.clusterId,'operation-check',()=>this.kong.request(context.clusterId,'GET',path),{paths:[path],maxCalls:1});
        await this.nativeMembership(context,actual);await this.assertResource(context,action,actual);
      }
      return {operationId:existing.id,state:existing.state,remoteStarted:existing.remote_started===true,remoteCompleted:existing.remote_completed===true,
        entityId:existing.entity_id??null,safeResult:await this.projectHistoricalResult(existing.safe_result??null,context.actor)};
    });
  }

  async execute<T>(context: MutationContext, fn: () => Promise<T>): Promise<T> {
    return this.execution.runMutationActor(context,()=>this.executeScoped(context,fn));
  }

  private async executeScoped<T>(context: MutationContext, fn: () => Promise<T>): Promise<T> {
    await this.contextWorkspace(context);
    const permission = context.action === 'delete' || context.action === 'purge' ? 'delete' : 'write';
    await this.authz.assertCluster(context.actor,context.clusterId,context.entityType,permission,context.workspaceId);
    if (context.before !== undefined){await this.nativeMembership(context,context.before);await this.assertResource(context,permission,context.before);}
    const idempotencyKey = context.idempotencyKey ?? randomUUID();
    if (!/^[a-zA-Z\d_.:-]{1,128}$/.test(idempotencyKey)) throw new BadRequestException({code:'INVALID_IDEMPOTENCY_KEY',message:'幂等键格式无效'});
    let operationIdForLock:string|undefined;
    const transportScope=await this.kong.transportScope(context.clusterId);
    try{return await this.redis.withLock(`mutation:${transportScope}`,async () => {
      await this.contextWorkspace(context);
      const cluster = await this.db.one<any>('SELECT id,execution_mode,version FROM clusters WHERE id=$1 AND deleted_at IS NULL',[context.clusterId]);
      if (!cluster) throw new NotFoundException({code:'CLUSTER_NOT_FOUND',message:'集群不存在'});
      const binding=await this.execution.approvedMutationBinding(context);
      const requestHash=this.requestHash(context,binding);
      if (cluster.execution_mode === 'approval'&&!binding) {
        await this.audit.append({...this.auditContext(context),action:context.action,before:context.before,after:context.payload,result:'blocked_approval_required'});
        throw new ConflictException({code:'APPROVAL_REQUIRED',message:'此集群需审批工单，当前阶段禁止直接执行变更'});
      }
      if (!/^1\.5\.\d+$/.test(cluster.version ?? '')) throw new ConflictException({code:'KONG_VERSION_INCOMPATIBLE',message:'仅允许已探测的 Kong OSS 1.5.x 集群变更'});
      const existing = await this.db.one<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND idempotency_key=$2',[context.clusterId,idempotencyKey]);
      if (existing) {
        await this.operationWorkspace(existing,context.actor,context.workspaceId,permission);
        if (existing.request_hash !== requestHash || existing.actor_id !== context.actor.id) {
          throw new ConflictException({code:'IDEMPOTENCY_CONFLICT',message:'幂等键已用于不同的变更请求'});
        }
        if (existing.state === 'succeeded' && existing.result_secret){
          const result=this.secrets.decrypt<T>(existing.result_secret,`mutation:${existing.id}:result`),entity=(result as any)?.entity??result;
          if(context.entityType==='annotations'){
            const type=this.annotationType(context)!,path=`/${type}/${encodeURIComponent(context.entityId!)}`;
            const current=await this.execution.runInternalRead(context.clusterId,'operation-check',()=>this.kong.request(context.clusterId,'GET',path),{paths:[path],maxCalls:1});
            await this.nativeMembership(context,current);await this.assertResource(context,permission,current);
          }
          if(entity&&typeof entity==='object'&&entity.id&&nativeEntities.has(context.entityType)){
            const current=await this.kong.request(context.clusterId,'GET',`/${context.entityType}/${encodeURIComponent(entity.id)}`);
            await this.nativeMembership(context,current);
            await this.assertResource(context,'read',current);
          }
          return this.projectHistoricalResult(result,context.actor);
        }
        throw new ConflictException({code:existing.state==='uncertain'||existing.state==='running'?'MUTATION_RESULT_UNCERTAIN':'MUTATION_ALREADY_ATTEMPTED',
          message:existing.state==='uncertain'||existing.state==='running'?'变更结果需要核验；相同幂等键不会重复执行':'此变更已经尝试执行，请核验后使用新的幂等键',operationId:existing.id,state:existing.state});
      }
      const impact=deriveImpact(context);
      await this.assertNoUnresolved(context,transportScope,impact);
      await this.execution.runInternalRead(context.clusterId,'operation-check',()=>this.assertUnchanged(context));
      const targetHealth=context.entityType==='targets'&&['mark_healthy','mark_unhealthy'].includes(context.action);
      if(targetHealth&&typeof this.kong.consumeTargetHealthTransportReceipt!=='function')throw new ServiceUnavailableException({code:'TARGET_HEALTH_TRANSPORT_BRIDGE_UNAVAILABLE',message:'原健康置位响应桥尚未安装，变更未执行'});
      // Observed node state is separate from the target configuration and
      // never demonstrates the previous manual override's recoverability.
      const healthBefore=targetHealth?await this.observeTargetHealth(context):undefined;
      if(context.targetHealthBefore!==undefined&&(!targetHealth||this.secrets.fingerprint(context.targetHealthBefore)!==this.secrets.fingerprint(healthBefore)))
        throw new ConflictException({code:'TARGET_HEALTH_BASELINE_CHANGED',message:'当前节点健康观察与原基线不同，未发送网关变更'});
      const operationId = randomUUID();
      context.operationId=operationId;
      operationIdForLock=operationId;
      await this.db.transaction(async tx => {
        if(binding)await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
        const v2=binding&&'version'in binding&&binding.version===2?binding:null,v1=binding&&!('version'in binding)?binding:null,
          v3=binding&&'version'in binding&&binding.version===3?binding:null;
        await tx.exec(`INSERT INTO mutation_operations(id,cluster_id,actor_id,action,idempotency_key,request_hash,state,
          workflow_id,request_id,entity_type,entity_id,before_secret,payload_secret,workspace_id,transport_scope,impact,parent_id,credential_kind,
          workflow_execution_id,workflow_plan_revision,workflow_plan_hash,workflow_step_id,
          configuration_job_id,configuration_execution_id,configuration_step_id,configuration_plan_revision,configuration_plan_hash,
          entity_change_source_id,entity_change_baseline_id,entity_change_attempt_id,entity_change_packet_key)
          VALUES($1,$2,$3,$4,$5,$6,'running',$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30)`,
          [operationId,context.clusterId,context.actor.id,context.action,idempotencyKey,requestHash,binding?.workflowId??context.workflowId??null,
            context.requestId??null,context.entityType,context.entityId??v3?.nativeId??null,
            this.secrets.encrypt(context.before??null,`mutation:${operationId}:before`),
            this.secrets.encrypt(context.payload??null,`mutation:${operationId}:payload`),context.workspaceId,transportScope,JSON.stringify(impact),context.parentId??null,context.credentialKind??null,
            v1?.executionId??null,v1?.planRevision??null,v1?.planHash??null,v1?.stepId??null,
            v2?.configurationJobId??null,v2?.configurationExecutionId??null,v2?.configurationStepId??null,v2?.configurationPlanRevision??null,v2?.configurationPlanHash??null,
            v3?.sourceId??null,v3?.baselineId??null,v3?.attemptId??null,v3?.packetKey??null]);
        if(binding){await this.execution.bindApprovedOperation(context,binding,operationId,tx);context.workflowId=binding.workflowId;}
        await this.audit.append({...this.auditContext(context),action:`${context.action}.requested`,before:context.before,after:context.payload,result:'pending'},tx);
      });
      let callbackReturned = false;
      let callbackResult: T | undefined;
      let healthTransport:Readonly<TargetHealthTransportReceipt>|undefined,healthRawRecorded=false;
      try {
        await this.db.exec('UPDATE mutation_operations SET remote_started=true,updated_at=now() WHERE id=$1',[operationId]);
        const result = nativeEntities.has(context.entityType)||['targets','credentials','workspace_migration'].includes(context.entityType)
          ?await this.execution.runOperation({...context,workspaceId:context.workspaceId!,operationId},async()=>{
            const originalFrame=this.execution.current();
            try{return await fn();}
            finally{if(targetHealth)healthTransport=this.kong.consumeTargetHealthTransportReceipt(originalFrame);}
          }):await fn();
        callbackResult = result;
        callbackReturned = true;
        if(targetHealth&&(!healthTransport||!healthTransport.contractValid||healthTransport.nativeStatus!==204||!healthTransport.emptyBody||healthTransport.responseBytes!==0
          ||healthTransport.clusterId!==context.clusterId||healthTransport.operationId!==operationId||healthTransport.upstreamId!==context.parentId
          ||healthTransport.targetId!==context.entityId||healthTransport.action!==context.action||healthTransport.rawResponse!==null
          ||healthTransport.responseHmac!==this.secrets.fingerprint(null)||result!==null))
          throw new ConflictException({code:'TARGET_HEALTH_NATIVE_RESPONSE_INVALID',message:'健康置位必须保留原204空响应和原传输观察，不能替换成实体'});
        const entityId = (result as any)?.entity?.id ?? (result as any)?.id ?? context.entityId ?? null;
        const recorded=await this.db.exec(`UPDATE mutation_operations SET remote_completed=true,entity_id=$2,result_secret=$3,updated_at=now() WHERE id=$1
          AND (entity_id IS NULL OR entity_id IS NOT DISTINCT FROM $2 OR entity_type='targets')`,
          [operationId,entityId,this.secrets.encrypt(result??null,`mutation:${operationId}:result`)]);
        if(recorded!==1)throw new ConflictException({code:'MUTATION_RESULT_ID_MISMATCH',message:'网关返回的对象标识与已记录结果不一致'});
        healthRawRecorded=targetHealth;
        // ConfigurationNative deliberately retains its callback envelope.
        // Observe the original native entity without rewriting result_secret.
        const nativeResult=context.entityType==='targets'&&(result as any)?.entity!==undefined?(result as any).entity:result;
        const disabledTarget=context.entityType==='targets'&&context.parentId&&(nativeResult as any)?.weight===0;
        const healthAfter=targetHealth?await this.observeTargetHealth(context):undefined;
        if(healthBefore&&healthAfter&&healthBefore.nodeId!==healthAfter.nodeId)throw new ConflictException({code:'TARGET_HEALTH_NODE_CHANGED',message:'健康置位后节点身份发生变化，请核验原操作，勿重新提交'});
        const observed = targetHealth?healthAfter:await this.execution.runInternalRead(context.clusterId,'operation-check',()=>disabledTarget
          ?disabledTargetReadback(this.kong,this.secrets,{clusterId:context.clusterId,upstreamId:context.parentId!,approvedBody:context.payload,nativeResult})
          :this.readBack(context,result),disabledTarget?{
          paths:[`/upstreams/${encodeURIComponent(context.parentId!)}/targets/all`,`/upstreams/${encodeURIComponent(context.parentId!)}/targets`],workspaceId:context.workspaceId,
          maxCalls:100,maxPages:100,maxRecords:10000,maxBytes:32*1024*1024,timeoutMs:120000}:{});
        // Kong 1.5 can prune a zero-weight tombstone and all older records in
        // clean_history(). Keep the real POST result in its original cipher;
        // an absent current object remains null, never a fabricated GET row.
        const after=disabledTarget?(observed as any).observedTarget:observed;
        const safeResult=targetHealth?{kind:'target-health-acknowledgement',nativeResult:null,nativeStatus:healthTransport!.nativeStatus,responseHmac:healthTransport!.responseHmac,responseBytes:healthTransport!.responseBytes,
          requestedState:context.action==='mark_healthy'?'healthy':'unhealthy',
          nodeScope:'current_admin_node',healthBefore,healthAfter,overrideRecovery:'unavailable'}:this.secrets.redact(result??null);
        if(disabledTarget&&safeResult&&typeof safeResult==='object')safeResult._kongpilotReadback={
          historyRetention:(observed as any).historyRetention,currentEffectiveAbsent:true,nativeHistoryRecordObserved:after!==null,
          originalResponseHmac:this.secrets.fingerprint(nativeResult),observation:'kong-1.5-disabled-target'};
        if (after && nativeEntities.has(context.entityType)){await this.nativeMembership(context,after);await this.assertResource(context,'write',after);}
        await this.db.transaction(async tx => {
          await this.audit.append({...this.auditContext(context),entityId:entityId??undefined,action:context.action,
            before:targetHealth?{target:context.before,healthObservation:healthBefore}:context.before,
            after:targetHealth?{nativeResult:null,nativeStatus:healthTransport!.nativeStatus,responseHmac:healthTransport!.responseHmac,
              requestedState:context.action==='mark_healthy'?'healthy':'unhealthy',healthObservation:healthAfter,nodeScope:'current_admin_node',overrideRecovery:'unavailable'}:after,
            result:'success',scopeHints:nativeAuditScope({type:context.entityType,id:entityId??'',before:context.before,after:targetHealth?context.before:after,beforeWorkspaceId:context.workspaceId??null,afterWorkspaceId:context.workspaceId??null,parentId:context.parentId,credentialKind:context.credentialKind})},tx);
          await tx.exec("UPDATE mutation_operations SET state='succeeded',safe_result=$2::jsonb,error_code=NULL,updated_at=now() WHERE id=$1",
            [operationId,JSON.stringify(safeResult)]);
        });
        return result;
      } catch (error: any) {
        const code = this.errorCode(error);
        const status = error instanceof HttpException ? error.getStatus() : 503;
        const uncertain = callbackReturned || status >= 500 || ['ETIMEDOUT','ECONNRESET','KONG_WRITE_RESULT_UNKNOWN','LOCK_LOST'].includes(code);
        const state = uncertain ? 'uncertain' : 'failed';
        // The original error remains authoritative; persistence failure must never trigger a retry.
        await this.db.transaction(async tx => {
          // A received response with a failed 204 contract remains an
          // observed original response, never a completed successful change.
          if(targetHealth&&healthTransport&&!healthRawRecorded)await tx.exec('UPDATE mutation_operations SET result_secret=$2,updated_at=now() WHERE id=$1 AND result_secret IS NULL',
            [operationId,this.secrets.encrypt(healthTransport.rawResponse,`mutation:${operationId}:result`)]);
          await tx.exec('UPDATE mutation_operations SET state=$2,error_code=$3,safe_result=$4::jsonb,updated_at=now() WHERE id=$1',
            [operationId,state,code,JSON.stringify({code,state,...(targetHealth&&healthTransport?{nativeStatus:healthTransport.nativeStatus,responseHmac:healthTransport.responseHmac,responseBytes:healthTransport.responseBytes,contractValid:healthTransport.contractValid}:{})})]);
          await this.audit.append({...this.auditContext(context),action:context.action,before:context.before,
            after:targetHealth?{nativeStatus:healthTransport?.nativeStatus??null,responseHmac:healthTransport?.responseHmac??null,
              requestedState:context.action==='mark_healthy'?'healthy':'unhealthy',healthReadbackComplete:false,nodeScope:'current_admin_node',overrideRecovery:'unavailable'}:callbackReturned?callbackResult:null,result:state},tx);
        }).catch(() => undefined);
        if(callbackReturned){
          throw new ServiceUnavailableException({code:'MUTATION_RESULT_UNCERTAIN',message:'变更可能已完成，但结果或授权核验失败；请查看原操作记录，不要重新提交',operationId,state:'uncertain'});
        }
        throw error;
      }
    });}catch(error:any){
      if(operationIdForLock&&this.errorCode(error)==='LOCK_LOST'){
        await this.db.exec("UPDATE mutation_operations SET state='uncertain',error_code='LOCK_LOST',updated_at=now() WHERE id=$1",[operationIdForLock]).catch(()=>undefined);
        await this.audit.append({...this.auditContext(context),action:context.action,before:context.before,result:'uncertain_lock_lost'}).catch(()=>undefined);
      }
      throw error;
    }
  }

  private async readBack<T>(context: MutationContext,result: T): Promise<unknown> {
    if (context.action==='delete'||context.action==='purge') return null;
    if ((result as any)?.entity) return (result as any).entity;
    const id = (result as any)?.id;
    if (!id) return result??null;
    if (nativeEntities.has(context.entityType)) return this.kong.request(context.clusterId,'GET',`/${context.entityType}/${encodeURIComponent(id)}`);
    if (context.entityType==='targets' && context.parentId) {
      if((result as any).weight===0)return(await disabledTargetReadback(this.kong,this.secrets,{clusterId:context.clusterId,upstreamId:context.parentId,approvedBody:context.payload,nativeResult:result})).observedTarget;
      return this.kong.request(context.clusterId,'GET',`/upstreams/${encodeURIComponent(context.parentId)}/targets/${encodeURIComponent(id)}`);
    }
    if (context.credentialKind && context.parentId) return this.kong.request(context.clusterId,'GET',`/consumers/${encodeURIComponent(context.parentId)}/${context.credentialKind}/${encodeURIComponent(id)}`);
    return result;
  }
  private async observeTargetHealth(context:MutationContext):Promise<Readonly<TargetHealthObservation>>{
    if(!context.parentId||!context.entityId||!context.before||typeof context.before!=='object'
      ||(context.before as any).id!==context.entityId||(context.before as any).upstream?.id!==context.parentId
      ||(context.payload as any)?.state!==(context.action==='mark_healthy'?'healthy':'unhealthy'))throw new ConflictException({code:'TARGET_HEALTH_CONTEXT_INVALID'});
    await this.authz.assertCluster(context.actor,context.clusterId,'targets','write',context.workspaceId);
    await this.nativeMembership(context,context.before);await this.assertResource(context,'write',context.before);
    const observation=await this.execution.runInternalRead(context.clusterId,'operation-check',()=>readTargetHealthObservation(this.kong,this.secrets,
      {clusterId:context.clusterId,upstreamId:context.parentId!,target:context.before as Record<string,unknown>}),
      {paths:['/',`/upstreams/${context.parentId}/health`],workspaceId:context.workspaceId,maxCalls:22,maxPages:20,maxRecords:2000,maxBytes:4*1024*1024,timeoutMs:30000});
    await this.nativeMembership(context,context.before);await this.assertResource(context,'write',context.before);
    await this.authz.assertCluster(context.actor,context.clusterId,'targets','write',context.workspaceId);
    return observation;
  }

  private async assertUnchanged(context:MutationContext):Promise<void>{
    if(!context.entityId||context.before===undefined||['create','restore','purge'].includes(context.action))return;
    let path:string|undefined,current:any;
    const actualType=this.annotationType(context)??context.entityType;
    if(nativeEntities.has(actualType))path=`/${actualType}/${encodeURIComponent(context.entityId)}`;
    else if(context.entityType==='targets'&&context.parentId){
      const address=(context.before as any)?.target;
      if(typeof address!=='string'||!address)throw new BadRequestException({code:'INVALID_TARGET_ADDRESS',message:'Target 缺少可核验的地址'});
      current=(await currentEffectiveTarget(this.kong,context.clusterId,context.parentId,address)).target;
      if(!current||current.id!==context.entityId)throw new ConflictException({code:'ENTITY_CHANGED',message:'Target 已停用或产生新的有效记录，请刷新后重新提交'});
    }
    else if(context.credentialKind&&context.parentId)path=`/consumers/${encodeURIComponent(context.parentId)}/${context.credentialKind}/${encodeURIComponent(context.entityId)}`;
    if(path)current=await this.kong.request(context.clusterId,'GET',path);
    if(current===undefined)return;
    if(this.secrets.fingerprint(current)!==this.secrets.fingerprint(context.before))throw new ConflictException({code:'ENTITY_CHANGED',message:'对象在提交前已发生变化，请刷新后重新提交'});
    await this.nativeMembership(context,current);
    await this.assertResource(context,context.action==='delete'?'delete':'write',current);
  }

  async operation(clusterId: string,id: string,actor: AuthUser,workspaceId?:string): Promise<any> {
    const operation = await this.db.one<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND id=$2',[clusterId,id]);
    if (!operation) throw new NotFoundException('变更记录不存在');
    if (operation.actor_id!==actor.id&&!await this.authz.isPlatformAdmin(actor)) throw new NotFoundException('变更记录不存在');
    return this.receipt(operation,actor,workspaceId);
  }

  /** A lost HTTP response is reconciled with the original key, never by starting another write. */
  async operationByKey(clusterId:string,idempotencyKey:string,actor:AuthUser,workspaceId?:string):Promise<any>{
    if(!/^[a-zA-Z\d_.:-]{1,128}$/.test(idempotencyKey))throw new BadRequestException({code:'INVALID_IDEMPOTENCY_KEY',message:'幂等键格式无效'});
    // A key receipt is private to its submitting actor, including when the caller is an administrator.
    const operation=await this.db.one<any>('SELECT * FROM mutation_operations WHERE cluster_id=$1 AND idempotency_key=$2 AND actor_id=$3',
      [clusterId,idempotencyKey,actor.id]);
    if(!operation||operation.actor_id!==actor.id)throw new NotFoundException('变更记录不存在');
    return this.receipt(operation,actor,workspaceId);
  }

  private async receipt(operation:any,actor:AuthUser,workspaceId?:string):Promise<any>{
    const permission=operation.action==='delete'||operation.action==='purge'?'delete':'write';
    let read=true;
    try{await this.authz.assertCluster(actor,operation.cluster_id,'mutations','read',workspaceId);}
    catch(error){if(!(error instanceof HttpException&&error.getStatus()===403)||operation.actor_id!==actor.id)throw error;read=false;await this.authz.assertCluster(actor,operation.cluster_id,operation.entity_type,permission,workspaceId);}
    const wid=await this.operationWorkspace(operation,actor,workspaceId,read?'read':permission);
    const before=operation.before_secret?this.secrets.decrypt<any>(operation.before_secret,`mutation:${operation.id}:before`):null;
    const payload=operation.entity_type==='annotations'&&operation.payload_secret?this.secrets.decrypt<any>(operation.payload_secret,`mutation:${operation.id}:payload`):undefined;
    const receiptContext:MutationContext={clusterId:operation.cluster_id,workspaceId:wid,actor,entityType:operation.entity_type,
      entityId:operation.entity_id,credentialKind:operation.credential_kind,action:operation.action,payload};
    if(operation.entity_type==='annotations'){
      const type=this.annotationType(receiptContext)!;
      const path=`/${type}/${encodeURIComponent(operation.entity_id)}`;
      const current=await this.execution.runInternalRead(operation.cluster_id,'operation-check',()=>this.kong.request(operation.cluster_id,'GET',path),{paths:[path],maxCalls:1});
      await this.nativeMembership(receiptContext,current);await this.assertResource(receiptContext,read?'read':permission,current);
    }else if(before!==null)await this.assertResource(receiptContext,read?'read':permission,before);
    if(operation.result_secret){
      const result=this.secrets.decrypt<any>(operation.result_secret,`mutation:${operation.id}:result`);
      const entity=result?.entity??result;
      if(operation.entity_type!=='annotations'&&entity&&typeof entity==='object'&&entity.id)await this.assertResource(receiptContext,read?'read':permission,entity);
    }
    const {id,cluster_id,actor_id,action,entity_type,entity_id,state,remote_started,remote_completed,error_code,created_at,updated_at}=operation;
    return {id,cluster_id,workspace_id:wid,actor_id,action,entity_type,entity_id,state,remote_started,remote_completed,error_code,
      safe_result:await this.projectHistoricalResult(read?this.secrets.redact(operation.safe_result??null):this.safeReceiptResult(operation.safe_result),actor),created_at,updated_at};
  }

  /** Historical child identifiers need stronger disclosure rights than the
   * authorized root receipt. Deleted parents cannot be reliably read back. */
  private async projectHistoricalResult<T>(value:T,actor:AuthUser):Promise<T>{
    if(!value||typeof value!=='object'||Array.isArray(value))return value;
    const result=value as any,keys=['deleted','restored'].filter(key=>Array.isArray(result[key]));
    if(!keys.length||await this.authz.isPlatformAdmin(actor))return value;
    const projected:any={...result};
    for(const key of keys){projected[`${key}_count`]=result[key].length;delete projected[key];}
    return projected as T;
  }

  private safeReceiptResult(value:any):any{
    if(!value||typeof value!=='object')return null;
    const result:any={};for(const key of ['id','entryId','state'])if(typeof value[key]==='string'&&value[key].length<=128)result[key]=value[key];
    if(typeof value.entity?.id==='string')result.entity={id:value.entity.id};
    for(const key of ['deleted','restored'])if(Array.isArray(value[key]))result[key]=value[key].slice(0,10000).map((node:any)=>Object.fromEntries(['type','id','originalId','restoredId'].filter(field=>typeof node?.[field]==='string').map(field=>[field,node[field]])));
    return result;
  }
}
