import { BadRequestException, ConflictException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import { KongService } from '../../infrastructure/kong/kong.service';
import { AuditService, type AuditEvent, type AuditOutboxReceipt } from '../audit/audit.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { entityType, identifier, type EntityActor, type EntityType } from '../entities/entities.types';
import { MutationService } from '../mutations/mutation.service';
import { WorkspaceResolverService, type WorkspaceFilter } from './workspace-resolver.service';
import { KongActorScope } from '../../infrastructure/kong/actor-scope';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { grantMatchesEntity } from '../authorization/grant-policy';
import type {AnnotationBusinessBridge,AnnotationBusinessMutation,AnnotationOriginalSource} from '../annotations/entity-annotation-workflow.types';

export interface EntityAnnotationRow {
  cluster_id: string;
  entity_type: EntityType;
  kong_id: string;
  description: string;
  owner_user_id: string | null;
  metadata: Record<string, unknown>;
  revision: number;
  status: 'active' | 'deleted';
  deleted_at: Date | string | null;
  retention_until: Date | string | null;
  created_at: Date | string | null;
  updated_at: Date | string | null;
}

export interface SetEntityAnnotationInput {
  revision: number;
  description?: string;
  owner_user_id?: string | null;
  metadata?: Record<string, unknown>;
}

export interface ConfirmEntityAnnotationInput {
  revision: number;
  confirmed: true;
  confirm_name: string;
}

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const columns = 'cluster_id,entity_type,kong_id,description,owner_user_id,metadata,revision,status,deleted_at,retention_until,created_at,updated_at';
const conflict = () => new ConflictException({ code: 'ANNOTATION_REVISION_CONFLICT', message: '实体备注已变化，请刷新后重新提交' });

/** Console metadata is deliberately separate from Kong's versioned entity schema. */
@Injectable()
export class EntityAnnotationsService {
  private annotationBridge?:Readonly<AnnotationBusinessBridge>;
  private get db():DbService{return this.annotationBridge?.currentTransaction()??this.storageDb;}
  constructor(private readonly storageDb: DbService, private readonly kong: KongService,
    private readonly authz: AuthorizationService, private readonly mutations: MutationService,
    private readonly audit: AuditService, private readonly resolver: WorkspaceResolverService,
    private readonly execution: KongExecutionContextService) {}

  /** Server-only original-source installation. No HTTP route accepts a
   * bridge, transaction, approved handle or permission projection. */
  installAnnotationBusinessBridge(bridge:AnnotationBusinessBridge):Readonly<AnnotationOriginalSource>{
    const methods=['currentTransaction','execute','appendAudit']as const;
    if(this.annotationBridge||!bridge||methods.some(k=>typeof bridge[k]!=='function')||Object.keys(bridge).some(k=>!methods.includes(k as any)))throw new Error('One complete fixed annotation business bridge is required');
    this.annotationBridge=Object.freeze({currentTransaction:bridge.currentTransaction.bind(bridge),execute:bridge.execute.bind(bridge),appendAudit:bridge.appendAudit.bind(bridge)});
    return Object.freeze({
      observe:async(cid:string,type:EntityType,id:string,actor:EntityActor,action:'read'|'write'|'delete',workspaceId:string)=>this.execution.runActor({actor:actor.user,clusterId:cid,workspaceId,module:'annotations',action,requestId:actor.requestId},async()=>{
        const current=await this.authorize(cid,entityType(type),id,actor,action,workspaceId);
        if(current.scope.workspaceId!==workspaceId)throw new ForbiddenException({code:'ANNOTATION_ORIGINAL_SCOPE_CHANGED'});
        return {entity:current.entity,workspaceId};
      }),
      readAnnotation:(cid:string,type:EntityType,id:string,tx:DbService)=>this.row(tx,cid,entityType(type),id),
    });
  }
  private appendAudit(event:AuditEvent,tx:DbService):Promise<AuditOutboxReceipt>{return this.annotationBridge?this.annotationBridge.appendAudit(event,tx):this.audit.append(event,tx);}
  private business<T>(mutation:AnnotationBusinessMutation,inspect:(tx:DbService)=>Promise<EntityAnnotationRow|null>,apply:(tx:DbService,before:EntityAnnotationRow|null)=>Promise<T>,direct:()=>Promise<T>):Promise<T>{
    return this.annotationBridge?this.annotationBridge.execute(mutation,inspect,apply,direct):direct();
  }

  private inputObject(input: unknown, permitted: readonly string[]): Record<string, unknown> {
    if (!input || typeof input !== 'object' || Array.isArray(input)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) {
      throw new BadRequestException({ code: 'INVALID_ANNOTATION_INPUT', message: '实体备注必须为 JSON 对象' });
    }
    for (const field of Object.keys(input)) if (!permitted.includes(field)) {
      throw new BadRequestException({ code: 'INVALID_ANNOTATION_FIELD', message: '实体备注包含不支持的字段' });
    }
    const value = input as Record<string, unknown>;
    if (!Number.isSafeInteger(value.revision) || Number(value.revision) < 0 || Number(value.revision) >= 2147483647) {
      throw new BadRequestException({ code: 'INVALID_ANNOTATION_REVISION', message: '请提供有效的实体备注版本号' });
    }
    return value;
  }

  private validateMetadata(value: unknown): asserts value is Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new BadRequestException({ code: 'INVALID_ANNOTATION_METADATA', message: 'metadata 必须为 JSON 对象' });
    }
    const visited = new WeakSet<object>();
    const visit = (node: unknown, depth: number): void => {
      if (depth > 20) throw new BadRequestException({ code: 'ANNOTATION_METADATA_TOO_DEEP', message: 'metadata 嵌套不得超过 20 层' });
      if (node === null || typeof node === 'string' || typeof node === 'boolean') return;
      if (typeof node === 'number' && Number.isFinite(node)) return;
      if (typeof node !== 'object' || visited.has(node)) throw new BadRequestException({ code: 'INVALID_ANNOTATION_METADATA', message: 'metadata 必须为有效 JSON 数据' });
      if (!Array.isArray(node) && ![Object.prototype, null].includes(Object.getPrototypeOf(node))) {
        throw new BadRequestException({ code: 'INVALID_ANNOTATION_METADATA', message: 'metadata 必须为有效 JSON 数据' });
      }
      visited.add(node);
      for (const [key, child] of Object.entries(node)) {
        if (['__proto__', 'prototype', 'constructor'].includes(key)) throw new BadRequestException({ code: 'INVALID_ANNOTATION_METADATA_KEY', message: 'metadata 包含保留属性名' });
        visit(child, depth + 1);
      }
      visited.delete(node);
    };
    visit(value, 0);
    if (Buffer.byteLength(JSON.stringify(value), 'utf8') > 65536) {
      throw new BadRequestException({ code: 'ANNOTATION_METADATA_TOO_LARGE', message: 'metadata 不得超过 64 KiB' });
    }
  }

  private setInput(input: unknown): SetEntityAnnotationInput {
    const value = this.inputObject(input, ['revision', 'description', 'owner_user_id', 'metadata']);
    if (Object.hasOwn(value, 'description') && (typeof value.description !== 'string' || value.description.length > 8192)) {
      throw new BadRequestException({ code: 'INVALID_ANNOTATION_DESCRIPTION', message: '备注描述不得超过 8192 个字符' });
    }
    if (Object.hasOwn(value, 'owner_user_id') && value.owner_user_id !== null
      && (typeof value.owner_user_id !== 'string' || !uuid.test(value.owner_user_id))) {
      throw new BadRequestException({ code: 'INVALID_ANNOTATION_OWNER', message: '负责人 ID 无效' });
    }
    if (Object.hasOwn(value, 'metadata')) this.validateMetadata(value.metadata);
    return structuredClone(value) as unknown as SetEntityAnnotationInput;
  }

  private confirmation(input: unknown, entity: any): ConfirmEntityAnnotationInput {
    const value = this.inputObject(input, ['revision', 'confirmed', 'confirm_name']);
    const expected = String(entity.name || entity.username || entity.id);
    if (value.confirmed !== true || value.confirm_name !== expected) {
      throw new BadRequestException({ code: 'CONFIRMATION_REQUIRED', message: `请二次确认并输入 ${expected}` });
    }
    return value as unknown as ConfirmEntityAnnotationInput;
  }

  private retentionDays(): number {
    const days = Number(process.env.RECYCLE_RETENTION_DAYS ?? 30);
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
      throw new BadRequestException({ code: 'INVALID_RECYCLE_RETENTION', message: '回收保留期必须为 1–3650 天' });
    }
    return days;
  }

  private effectiveWorkspace(actor: EntityActor, workspaceId?: string): string | undefined {
    if (workspaceId && actor.workspaceId && workspaceId !== actor.workspaceId) {
      throw new BadRequestException({ code: 'WORKSPACE_CONTEXT_MISMATCH', message: '请求工作区上下文不一致' });
    }
    return workspaceId ?? actor.workspaceId;
  }

  private async authorize(cid: string, type: EntityType, id: string, actor: EntityActor,
    action: 'read' | 'write' | 'delete', workspaceId?: string): Promise<{ entity: any; scope: WorkspaceFilter }> {
    const selectedWorkspace = this.effectiveWorkspace(actor, workspaceId);
    await this.authz.assertCluster(actor.user, cid, 'annotations', action, selectedWorkspace);
    const scope = await this.resolver.listScope(cid, selectedWorkspace);
    const path=`/${type}/${identifier(id)}`;
    // Write/delete does not imply public native-read permission. Inspect only
    // this exact identity privately, then independently enforce both grants.
    const entity = action==='read' ? await this.kong.request(cid,'GET',path)
      : await this.execution.runInternalRead(cid,'entity-preflight',()=>this.kong.request(cid,'GET',path),
        {paths:[path],workspaceId:scope.workspaceId,maxCalls:1,maxPages:1,maxRecords:1,maxBytes:2*1024*1024,timeoutMs:5000});
    if (!entity || typeof entity.id !== 'string' || !uuid.test(entity.id) || uuid.test(id) && entity.id!==id) {
      throw new ConflictException({ code: 'INVALID_KONG_ENTITY', message: '网关未返回有效的实体 ID' });
    }
    await this.authz.assertEntity(actor.user, cid, type, action, entity, scope.workspaceId);
    await this.resolver.assertMembership(scope, entity);
    await this.annotationGrant(cid,type,entity,scope.workspaceId,actor,action);
    return { entity, scope };
  }

  private async annotationGrant(cid:string,type:EntityType,entity:any,workspaceId:string|undefined,actor:EntityActor,action:'read'|'write'|'delete'):Promise<void>{
    const snapshot=await this.authz.snapshot(actor.user);
    if(!snapshot.user.superAdmin&&!snapshot.grants.some(grant=>grantMatchesEntity(grant,'annotations',action,
      {clusterId:cid,workspaceId,entityType:type,entity}))) {
      throw new ForbiddenException({code:'PERMISSION_DENIED',message:'当前账号无此实体备注操作权限'});
    }
  }

  private empty(cid: string, type: EntityType, id: string): EntityAnnotationRow {
    return { cluster_id: cid, entity_type: type, kong_id: id, description: '', owner_user_id: null, metadata: {},
      revision: 0, status: 'active', deleted_at: null, retention_until: null, created_at: null, updated_at: null };
  }

  private row(db: DbService, cid: string, type: EntityType, id: string, lock = false): Promise<EntityAnnotationRow | null> {
    return db.one<EntityAnnotationRow>(`SELECT ${columns} FROM entity_annotations WHERE cluster_id=$1 AND entity_type=$2 AND kong_id=$3${lock ? ' FOR UPDATE' : ''}`, [cid, type, id]);
  }

  @KongActorScope({module:'annotations',action:'read',actorArg:3,workspaceArg:4})
  async get(cid: string, rawType: string, id: string, actor: EntityActor, workspaceId?: string): Promise<EntityAnnotationRow> {
    const type = entityType(rawType);
    const { entity } = await this.authorize(cid, type, id, actor, 'read', workspaceId);
    return await this.row(this.db, cid, type, entity.id) ?? this.empty(cid, type, entity.id);
  }

  /** Called only with authoritative, workspace-filtered entities from a bounded list page. */
  @KongActorScope({module:'annotations',action:'read',actorArg:3,workspaceArg:4})
  async getMany(cid: string, rawType: string, authorizedEntities: any[], actor: EntityActor, workspaceId?: string): Promise<Record<string, EntityAnnotationRow>> {
    const type = entityType(rawType);
    if (!Array.isArray(authorizedEntities) || authorizedEntities.length > 100) {
      throw new BadRequestException({ code: 'ANNOTATION_PAGE_TOO_LARGE', message: '每次最多读取 100 个实体备注' });
    }
    const selectedWorkspace = this.effectiveWorkspace(actor, workspaceId);
    await this.authz.assertCluster(actor.user, cid, 'annotations', 'read', selectedWorkspace);
    const scope = await this.resolver.listScope(cid, selectedWorkspace);
    const ids: string[] = [];
    for (const entity of authorizedEntities) {
      if (!entity || typeof entity.id !== 'string' || !uuid.test(entity.id)) {
        throw new BadRequestException({ code: 'INVALID_ENTITY_ID', message: '实体 ID 无效' });
      }
      await this.authz.assertEntity(actor.user, cid, type, 'read', entity, scope.workspaceId);
      await this.resolver.assertMembership(scope, entity);
      await this.annotationGrant(cid,type,entity,scope.workspaceId,actor,'read');
      if (!ids.includes(entity.id)) ids.push(entity.id);
    }
    const result: Record<string, EntityAnnotationRow> = Object.create(null);
    if (!ids.length) return result;
    const rows = await this.db.query<EntityAnnotationRow>(`SELECT ${columns} FROM entity_annotations
      WHERE cluster_id=$1 AND entity_type=$2 AND kong_id=ANY($3::uuid[])`, [cid, type, ids]);
    for (const id of ids) result[id] = this.empty(cid, type, id);
    for (const row of rows) if (ids.includes(row.kong_id) && row.cluster_id === cid && row.entity_type === type) result[row.kong_id] = row;
    return result;
  }

  @KongActorScope({module:'annotations',action:'write',actorArg:4,workspaceArg:5})
  async set(cid: string, rawType: string, id: string, input: SetEntityAnnotationInput,
    actor: EntityActor, workspaceId?: string): Promise<EntityAnnotationRow> {
    const type = entityType(rawType), value = this.setInput(input);
    const { entity, scope } = await this.authorize(cid, type, id, actor, 'write', workspaceId);
    const inspect=async(tx:DbService):Promise<EntityAnnotationRow|null>=>{
        const before = await this.row(tx, cid, type, entity.id, true);
        if ((before?.revision ?? 0) !== value.revision) throw conflict();
        if (before?.status === 'deleted') throw new ConflictException({ code: 'ANNOTATION_DELETED', message: '实体备注已进入回收状态，请显式恢复' });
        if (value.owner_user_id && !await tx.one("SELECT id FROM users WHERE id=$1 AND status='active' FOR SHARE", [value.owner_user_id])) {
          throw new BadRequestException({ code: 'ANNOTATION_OWNER_UNAVAILABLE', message: '负责人不存在或已禁用' });
        }
        return before;
    };
    const apply=async(tx:DbService,before:EntityAnnotationRow|null):Promise<EntityAnnotationRow>=>{
        const description = value.description ?? before?.description ?? '';
        const owner = Object.hasOwn(value, 'owner_user_id') ? value.owner_user_id : before?.owner_user_id ?? null;
        const metadata = value.metadata ?? before?.metadata ?? {};
        const after = before
          ? await tx.one<EntityAnnotationRow>(`UPDATE entity_annotations SET description=$4,owner_user_id=$5,metadata=$6::jsonb,
              revision=revision+1,updated_at=now() WHERE cluster_id=$1 AND entity_type=$2 AND kong_id=$3 AND revision=$7 AND status='active' RETURNING ${columns}`,
              [cid, type, entity.id, description, owner, JSON.stringify(metadata), value.revision])
          : await tx.one<EntityAnnotationRow>(`INSERT INTO entity_annotations(cluster_id,entity_type,kong_id,description,owner_user_id,metadata)
              VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(cluster_id,entity_type,kong_id) DO NOTHING RETURNING ${columns}`,
              [cid, type, entity.id, description, owner, JSON.stringify(metadata)]);
        if (!after) throw conflict();
        await this.appendAudit({ actorId: actor.user.id, clusterId: cid, workspaceId: scope.workspaceId,
          entityType: type, entityId: entity.id, action: before ? 'annotation.metadata.updated' : 'annotation.metadata.created',
          before, after, requestId: actor.requestId, ip: actor.ip }, tx);
        return after;
    };
    return this.business({clusterId:cid,workspaceId:scope.workspaceId!,entityType:type,entityId:entity.id,operation:'set',action:'write',actor,input:value as unknown as Record<string,unknown>,entity,retentionDays:null},inspect,apply,
      ()=>this.mutations.execute({ clusterId: cid, workspaceId: scope.workspaceId, actor: actor.user, entityType: 'annotations', entityId: entity.id,
        action: 'update', before: entity, payload: { entityType: type, entityId: entity.id, workspaceId: scope.workspaceId, input: value },
        requestId: actor.requestId, ip: actor.ip, idempotencyKey: actor.idempotencyKey }, async () => {
        await this.authorize(cid, type, entity.id, actor, 'write', scope.workspaceId);
        return this.db.transaction(async tx=>apply(tx,await inspect(tx)));
      }));
  }

  @KongActorScope({module:'annotations',action:'delete',actorArg:4,workspaceArg:5})
  async remove(cid: string, rawType: string, id: string, input: ConfirmEntityAnnotationInput,
    actor: EntityActor, workspaceId?: string): Promise<EntityAnnotationRow> {
    return this.changeStatus(cid, rawType, id, input, actor, workspaceId, 'deleted');
  }

  @KongActorScope({module:'annotations',action:'write',actorArg:4,workspaceArg:5})
  async restore(cid: string, rawType: string, id: string, input: ConfirmEntityAnnotationInput,
    actor: EntityActor, workspaceId?: string): Promise<EntityAnnotationRow> {
    return this.changeStatus(cid, rawType, id, input, actor, workspaceId, 'active');
  }

  private async changeStatus(cid: string, rawType: string, id: string, input: ConfirmEntityAnnotationInput,
    actor: EntityActor, workspaceId: string | undefined, status: 'active' | 'deleted'): Promise<EntityAnnotationRow> {
    const type = entityType(rawType), action = status === 'deleted' ? 'delete' : 'restore';
    const { entity, scope } = await this.authorize(cid, type, id, actor, status === 'deleted' ? 'delete' : 'write', workspaceId);
    const value = this.confirmation(input, entity), days = status === 'deleted' ? this.retentionDays() : null;
    const inspect=async(tx:DbService):Promise<EntityAnnotationRow|null>=>{
        const before = await this.row(tx, cid, type, entity.id, true);
        if (!before) throw new NotFoundException({ code: 'ANNOTATION_NOT_FOUND', message: '实体备注不存在' });
        if (before.revision !== value.revision) throw conflict();
        const expected = status === 'deleted' ? 'active' : 'deleted';
        if (before.status !== expected) throw new ConflictException({ code: 'ANNOTATION_STATE_CONFLICT', message: status === 'deleted' ? '实体备注已删除' : '实体备注未处于可恢复状态' });
        return before;
    };
    const apply=async(tx:DbService,before:EntityAnnotationRow|null):Promise<EntityAnnotationRow>=>{
        const after = await tx.one<EntityAnnotationRow>(status === 'deleted'
          ? `UPDATE entity_annotations SET status='deleted',deleted_at=now(),retention_until=now()+($5::int*interval '1 day'),
              revision=revision+1,updated_at=now() WHERE cluster_id=$1 AND entity_type=$2 AND kong_id=$3 AND revision=$4 AND status='active' RETURNING ${columns}`
          : `UPDATE entity_annotations SET status='active',deleted_at=NULL,retention_until=NULL,revision=revision+1,updated_at=now()
              WHERE cluster_id=$1 AND entity_type=$2 AND kong_id=$3 AND revision=$4 AND status='deleted' RETURNING ${columns}`,
          status === 'deleted' ? [cid, type, entity.id, value.revision, days] : [cid, type, entity.id, value.revision]);
        if (!after) throw conflict();
        await this.appendAudit({ actorId: actor.user.id, clusterId: cid, workspaceId: scope.workspaceId,
          entityType: type, entityId: entity.id, action: status === 'deleted' ? 'annotation.metadata.deleted' : 'annotation.metadata.restored',
          before, after, requestId: actor.requestId, ip: actor.ip }, tx);
        return after;
    };
    return this.business({clusterId:cid,workspaceId:scope.workspaceId!,entityType:type,entityId:entity.id,operation:status==='deleted'?'remove':'restore',action:status==='deleted'?'delete':'write',actor,input:value as unknown as Record<string,unknown>,entity,retentionDays:days},inspect,apply,
      ()=>this.mutations.execute({ clusterId: cid, workspaceId: scope.workspaceId, actor: actor.user, entityType: 'annotations', entityId: entity.id,
        action, before: entity, payload: { entityType: type, entityId: entity.id, workspaceId: scope.workspaceId, input: value },
        requestId: actor.requestId, ip: actor.ip, idempotencyKey: actor.idempotencyKey }, async () => {
        const current = await this.authorize(cid, type, entity.id, actor, status === 'deleted' ? 'delete' : 'write', scope.workspaceId);
        this.confirmation(value, current.entity);
        return this.db.transaction(async tx=>apply(tx,await inspect(tx)));
      }));
  }
}
