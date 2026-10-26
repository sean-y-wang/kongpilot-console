import { BadRequestException, ForbiddenException, HttpException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { isIP } from 'node:net';
import { X509Certificate } from 'node:crypto';
import { KongService } from '../../infrastructure/kong/kong.service';
import { decodeTag, encodeTag } from '../../infrastructure/kong/tags';
import { filteredList } from '../../infrastructure/kong/filtered-list';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { KongActorScope } from '../../infrastructure/kong/actor-scope';
import { stripSensitiveSchemaDefaults } from '../../infrastructure/kong/schema-secrets';
import { SecretService } from '../../infrastructure/secret.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { MutationService } from '../mutations/mutation.service';
import { RecycleService } from '../recycle-bin/recycle.service';
import { CredentialStoreService } from '../credentials/credential-store.service';
import { AuditService } from '../audit/audit.service';
import { inspectCertificate } from './certificates';
import { EntityIndexService } from './entity-index.service';
import { WorkspaceResolverService, WorkspaceFilter } from '../workspaces/workspace-resolver.service';
import { confirmed, credentialKind, CREDENTIAL_KINDS, CREDENTIAL_SCHEMAS, EntityActor, entityType, identifier, ListQuery, objectBody, pageSize } from './entities.types';
import type { EntityMutationPreparation, EntityPreparationReference } from './entity-change.types';
import { entityReferenceId, normalizeEntityAuthorizationView } from './entity-reference';

const propagation = { state: 'pending', message: '配置生效中；Kong DB 模式传播可能需要数秒，请通过代理请求验证' };

@Injectable()
export class EntityService {
  private readonly logger = new Logger(EntityService.name);
  constructor(private readonly kong: KongService, private readonly authz: AuthorizationService, private readonly mutations: MutationService, private readonly recycle: RecycleService, private readonly credentialsStore: CredentialStoreService, private readonly secrets: SecretService, private readonly audit: AuditService, private readonly index: EntityIndexService, private readonly workspaces: WorkspaceResolverService, private readonly execution: KongExecutionContextService) {}

  private async scoped(clusterId: string, actor: EntityActor, workspaceId = actor.workspaceId, module = 'entities', action = 'read'): Promise<EntityActor> {
    await this.authz.assertCluster(actor.user, clusterId, module, action, workspaceId);
    const workspace = await this.workspaces.resolve(clusterId, workspaceId);
    return { ...actor, workspaceId: workspace.id };
  }
  private async scope(clusterId: string, actor: EntityActor, tags?: string, module = 'entities'): Promise<WorkspaceFilter> {
    const authorizedTags = await this.authz.scopeTags(actor.user, clusterId, actor.workspaceId, tags, module);
    return this.workspaces.listScope(clusterId, actor.workspaceId, authorizedTags);
  }
  private async visible(clusterId: string, type: string, actor: EntityActor, scope: WorkspaceFilter, items: any[]): Promise<any[]> {
    return this.authz.filterEntities(actor.user, clusterId, type, items.filter(item => this.workspaces.matches(scope, item)), actor.workspaceId);
  }
  private async subject(actor: EntityActor, scope: WorkspaceFilter, suffix = ''): Promise<string> {
    return `${actor.user.id}:${await this.authz.permissionVersion(actor.user)}:${scope.binding}:${suffix}`;
  }
  private assertParentField(payload: any, field: 'consumer' | 'upstream', parentId: string): void {
    if (payload[field] !== undefined && (!payload[field] || typeof payload[field] !== 'object' || Array.isArray(payload[field]) || payload[field].id !== parentId || Object.keys(payload[field]).some(name => name !== 'id'))) throw new BadRequestException({ code: 'PARENT_REFERENCE_IMMUTABLE', message: '子对象不能变更所属父对象，请在目标父对象下创建新对象' });
    // The nested Admin route supplies this relation; omit duplicate wire fields.
    delete payload[field];
  }
  private globalPlugin(type: string, entity: any, actor: EntityActor): void {
    if (type === 'plugins' && !['service', 'route', 'consumer'].some(field => entityReferenceId(entity[field])) && !actor.user.superAdmin) throw new ForbiddenException({ code: 'GLOBAL_PLUGIN_PLATFORM_PERMISSION_REQUIRED', message: '全局插件影响整个集群，只有平台管理员可以创建或修改' });
  }

  private async indexResult(clusterId: string, type: string, entity: any): Promise<void> { try { await this.index.upsert(clusterId, type, entity); } catch { this.logger.warn(JSON.stringify({ event: 'entity_index_update_failed', clusterId, entityType: type, entityId: entity?.id })); } }

  private context(clusterId: string, type: string, action: string, actor: EntityActor, id?: string, before?: unknown, payload?: unknown, extra: Record<string, any> = {}) {
    return { clusterId, workspaceId: actor.workspaceId, actor: actor.user, entityType: type, entityId: id, action, before, payload, idempotencyKey: actor.idempotencyKey, requestId: actor.requestId, ip: actor.ip, ...extra };
  }
  private async preflight(clusterId: string, path: string, actor: EntityActor): Promise<any> {
    return this.execution.runInternalRead(clusterId, 'entity-preflight', () => this.kong.request(clusterId, 'GET', path), { paths: [path], workspaceId: actor.workspaceId, maxCalls: 4 });
  }
  private async parentIdentity(clusterId: string, type: 'consumers' | 'upstreams', id: string, childType: string, action: string, actor: EntityActor, child?: any): Promise<any> {
    const parent = await this.preflight(clusterId, `/${type}/${identifier(id)}`, actor);
    this.workspaces.assertMembership(await this.workspaces.listScope(clusterId, actor.workspaceId), parent);
    await this.authz.assertNestedParentScope(actor.user, clusterId, type, parent, childType, action, actor.workspaceId, child);
    return parent;
  }
  private async raw(clusterId: string, type: string, id: string, action: string, actor: EntityActor): Promise<any> {
    entityType(type);
    await this.authz.assertCluster(actor.user, clusterId, type, action, actor.workspaceId);
    const path = `/${type}/${identifier(id)}`;
    const entity = await this.preflight(clusterId, path, actor);
    this.workspaces.assertMembership(await this.workspaces.listScope(clusterId, actor.workspaceId), entity);
    await this.authz.assertEntity(actor.user, clusterId, type, action, entity, actor.workspaceId);
    return entity;
  }
  private display(entity: any, reveal = false): any {
    if (!entity) return entity;
    const result = structuredClone(reveal ? entity : this.secrets.redact(entity));
    if (Array.isArray(result.tags)) result.tags = result.tags.map(decodeTag);
    if (result.name && !result.service?.id && !result.route?.id && !result.consumer?.id && Object.hasOwn(result, 'config')) result.console_scope_notice = '标签只隔离管理视图；全局插件仍会在整个集群运行并影响其他工作区';
    return result;
  }
  private input(body: unknown): Record<string, any> {
    const input = objectBody(body);
    if (input.tags != null) {
      if (!Array.isArray(input.tags) || input.tags.some((tag: unknown) => typeof tag !== 'string')) throw new BadRequestException({ code: 'INVALID_TAGS', message: 'tags 必须为字符串数组' });
      input.tags = [...new Set(input.tags.map(encodeTag))];
    }
    return input;
  }
  private queryTags(tags?: string): string | undefined {
    if (!tags) return undefined;
    if (tags.length > 2048) throw new BadRequestException({ code: 'INVALID_TAGS', message: '标签过滤过长' });
    if (tags.includes('/') && tags.includes(',')) throw new BadRequestException({ code: 'INVALID_TAG_EXPRESSION', message: '标签过滤不能混合 AND 逗号和 OR 斜线' });
    const delimiter = tags.includes('/') ? '/' : ',';
    return tags.split(delimiter).map(tag => encodeTag(tag.trim())).join(delimiter);
  }
  private matchesTags(entity: any, tags?: string): boolean {
    if (!tags) return true;
    const actual = new Set(entity.tags || []);
    return tags.includes('/') ? tags.split('/').some(tag => actual.has(tag)) : tags.split(',').every(tag => actual.has(tag));
  }
  private wantsReveal(query: ListQuery): boolean { return query.reveal === true || query.reveal === 'true'; }
  private async authorizeReveal(clusterId: string, actor: EntityActor, type: string, entity: any, parent?: any): Promise<void> {
    await this.authz.assertSecretRead(actor.user, clusterId, type, entity, actor.workspaceId);
    if (parent) await this.authz.assertNestedParentScope(actor.user, clusterId, 'consumers', parent, type, 'read', actor.workspaceId, entity);
  }
  private async reveal(clusterId: string, actor: EntityActor, query: ListQuery, type: string, entity: any, parent?: any): Promise<boolean> {
    if (!this.wantsReveal(query)) return false;
    await this.authorizeReveal(clusterId, actor, type, entity, parent);
    await this.audit.append({ actorId: actor.user.id, clusterId, workspaceId: actor.workspaceId, entityType: type, entityId: entity.id, action: 'reveal_secret', after: { authorized: true }, requestId: actor.requestId, ip: actor.ip });
    return true;
  }

  @KongActorScope({ moduleArg: 1 })
  async schema(clusterId: string, type: string, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId, (CREDENTIAL_KINDS as readonly string[]).includes(type) ? 'consumers' : type, 'read');
    const credential = (CREDENTIAL_KINDS as readonly string[]).includes(type);
    if (!credential && type !== 'targets') entityType(type);
    await this.authz.assertCluster(actor.user, clusterId, credential ? 'consumers' : type, 'read', actor.workspaceId);
    const schema = stripSensitiveSchemaDefaults(await this.kong.schema(clusterId, credential ? CREDENTIAL_SCHEMAS[credentialKind(type)] : type), this.secrets);
    if (type === 'certificates' && Array.isArray(schema.fields)) return { ...schema, fields: [...schema.fields, { snis: { type: 'set', elements: { type: 'string' }, default: [], description: 'SNI 名称关联（Kong 1.5 Certificate Admin 路由）', console_relation: true } }] };
    return schema;
  }

  @KongActorScope({ module: 'plugins' })
  async pluginSchema(clusterId: string, name: string, actor: EntityActor): Promise<any> { actor = await this.scoped(clusterId, actor, actor.workspaceId, 'plugins', 'read'); await this.authz.assertCluster(actor.user, clusterId, 'plugins', 'read', actor.workspaceId); return stripSensitiveSchemaDefaults(await this.kong.pluginSchema(clusterId, name), this.secrets); }

  private async revealedCredential(clusterId: string, consumerId: string, kind: string, entity: any): Promise<any> {
    if (kind !== 'basic-auth') return entity;
    const known = await this.credentialsStore.get(clusterId, consumerId, kind, entity.id);
    const valid = known?.credential.password === entity.password && typeof known?.rawInput.password === 'string';
    return { ...entity, password: valid ? known!.rawInput.password : null, recovery_capability: valid ? 'complete' : 'requires-secret-input' };
  }

  @KongActorScope({ moduleArg: 1, queryArg: 2 })
  async list(clusterId: string, type: string, query: ListQuery, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, query.workspaceId, type, 'read');
    entityType(type);
    await this.authz.assertCluster(actor.user, clusterId, type, 'read', actor.workspaceId);
    const size = pageSize(query.size);
    const scope = await this.scope(clusterId, actor, this.queryTags(query.tags), type);
    const reveal = this.wantsReveal(query);
    if (reveal) await this.authz.assertCluster(actor.user, clusterId, 'secrets', 'read', actor.workspaceId);
    if (query.search || query.sort) {
      const result = await this.index.search(clusterId, type, { ...query, workspaceId: actor.workspaceId, size, tags: this.queryTags(query.tags) }, actor.user);
      const items = reveal ? await Promise.all(result.items.map(item => this.raw(clusterId, type, item.id, 'read', actor))) : result.items;
      if (reveal) for (const item of items) await this.reveal(clusterId, actor, query, type, item);
      return { ...result, items: items.map(item => this.display(item, reveal)) };
    }
    const params = { size, ...(scope.nativeTags ? { tags: scope.nativeTags } : {}) };
    const result = await filteredList(this.kong, clusterId, `/${type}`, params, query.cursor, await this.subject(actor, scope), items => this.visible(clusterId, type, actor, scope, items));
    if (reveal) for (const item of result.items) await this.reveal(clusterId, actor, query, type, item);
    return { ...result, items: result.items.map(item => this.display(item, reveal)), workspace_id: actor.workspaceId };
  }

  @KongActorScope({ moduleArg: 1, queryArg: 3 })
  async get(clusterId: string, type: string, id: string, query: ListQuery, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, query.workspaceId, type, 'read');
    const permissionVersion = await this.authz.permissionVersion(actor.user);
    const entity = await this.raw(clusterId, type, id, 'read', actor);
    const reveal = await this.reveal(clusterId, actor, query, type, entity);
    const relations: Record<string, any> = {};
    if (type === 'services') {
      [relations.routes, relations.plugins] = await Promise.all([this.optionalRelation(() => this.relation(clusterId, type, id, 'routes', {}, actor), true), this.optionalRelation(() => this.relation(clusterId, type, id, 'plugins', {}, actor), true)]);
    } else if (type === 'routes') {
      relations.plugins = await this.optionalRelation(() => this.relation(clusterId, type, id, 'plugins', {}, actor), true);
      if (entity.service?.id) relations.service = await this.optionalRelation(async () => this.display(await this.raw(clusterId, 'services', entity.service.id, 'read', actor)), false);
    } else if (type === 'consumers') relations.plugins = await this.optionalRelation(() => this.relation(clusterId, type, id, 'plugins', {}, actor), true);
    else if (type === 'certificates') relations.snis = await this.optionalRelation(() => this.relation(clusterId, type, id, 'snis', {}, actor), true);
    else if (type === 'snis' && entity.certificate?.id) relations.certificate = await this.optionalRelation(async () => this.display(await this.raw(clusterId, 'certificates', entity.certificate.id, 'read', actor)), false);
    else if (type === 'plugins') {
      for (const [field, target] of Object.entries({ service: 'services', route: 'routes', consumer: 'consumers' })) if (entity[field]?.id) relations[field] = await this.optionalRelation(async () => this.display(await this.raw(clusterId, target, entity[field].id, 'read', actor)), false);
    }
    let certificate: any;
    if (['certificates', 'ca_certificates'].includes(type)) { try { certificate = inspectCertificate(entity.cert, type === 'certificates' ? entity.key : undefined); } catch { certificate = { valid: false, message: '证书解析失败，请检查 PEM 内容' }; } }
    if (await this.authz.permissionVersion(actor.user) !== permissionVersion) throw new ForbiddenException({ code: 'PERMISSIONS_CHANGED', message: '查询期间授权已变更，请重新加载' });
    await this.authz.assertEntity(actor.user, clusterId, type, 'read', entity, actor.workspaceId);
    if (reveal) await this.authorizeReveal(clusterId, actor, type, entity);
    if (await this.authz.permissionVersion(actor.user) !== permissionVersion) throw new ForbiddenException({ code: 'PERMISSIONS_CHANGED', message: '查询期间授权已变更，请重新加载' });
    return { entity: this.display(entity, reveal), relations, ...(certificate ? { certificate } : {}) };
  }

  /** Batch-resolve referenced entity IDs to readable labels in one browser
   * round-trip. Each reference goes through the same scoped read authorization
   * as GET /entities/:type/:id; anything the actor may not read (or that no
   * longer exists) comes back as { visible:false } with only its ID. */
  async resolveReferences(clusterId: string, body: unknown, query: ListQuery, actor: EntityActor): Promise<{ items: EntityReferenceLabel[] }> {
    const refs = (body as any)?.refs;
    if (!Array.isArray(refs) || refs.length > 100) throw new BadRequestException({ code: 'ENTITY_REFERENCES_INVALID', message: '一次最多解析 100 个引用' });
    const allowed = new Set(['services', 'routes', 'consumers', 'certificates', 'ca_certificates', 'snis', 'upstreams', 'plugins']);
    const unique = new Map<string, { type: string; id: string }>();
    for (const ref of refs) {
      if (!ref || typeof ref.type !== 'string' || typeof ref.id !== 'string' || !allowed.has(ref.type) || !/^[A-Za-z0-9._~-]{1,128}$/.test(ref.id)) throw new BadRequestException({ code: 'ENTITY_REFERENCES_INVALID', message: '引用格式无效' });
      unique.set(`${ref.type}:${ref.id}`, { type: ref.type, id: ref.id });
    }
    const scopedByType = new Map<string, EntityActor | null>();
    for (const type of new Set([...unique.values()].map(ref => ref.type))) scopedByType.set(type, await this.scoped(clusterId, actor, query.workspaceId, type, 'read').catch(() => null));
    const queue = [...unique.values()], items: EntityReferenceLabel[] = [];
    const worker = async () => { for (let ref = queue.shift(); ref; ref = queue.shift()) {
      const scoped = scopedByType.get(ref.type);
      if (!scoped) { items.push({ ...ref, visible: false }); continue; }
      try { items.push({ ...ref, visible: true, ...referenceLabel(ref.type, await this.raw(clusterId, ref.type, ref.id, 'read', scoped)) }); }
      catch { items.push({ ...ref, visible: false }); }
    } };
    await Promise.all(Array.from({ length: Math.min(6, queue.length) }, worker));
    return { items };
  }

  private async optionalRelation(load: () => Promise<any>, collection: boolean): Promise<any> {
    try { return await load(); }
    catch (error) {
      if (!(error instanceof HttpException) || ![403, 404].includes(error.getStatus())) throw error;
      const availability = error.getStatus() === 403 ? 'forbidden' : 'missing';
      // The primary entity's own permission is checked again before return.
      // Explicit relationship endpoints retain their original authorization.
      return collection ? { availability, items: [], total: null } : { availability, reason: availability === 'forbidden' ? 'permission_denied' : 'not_found' };
    }
  }

  @KongActorScope({ moduleArg: 1, queryArg: 4 })
  async relation(clusterId: string, type: string, id: string, relation: string, query: ListQuery, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, query.workspaceId, type, 'read');
    const parent = await this.raw(clusterId, type, id, 'read', actor);
    const size = pageSize(query.size);
    const scope = await this.scope(clusterId, actor, this.queryTags(query.tags), relation);
    const subject = await this.subject(actor, scope, `relation:${type}:${parent.id}:${relation}`);
    const params = { size, ...(scope.nativeTags ? { tags: scope.nativeTags } : {}) };
    if ((type === 'services' && relation === 'routes') || (type === 'certificates' && relation === 'snis')) {
      const result = await filteredList(this.kong, clusterId, `/${type}/${identifier(parent.id)}/${relation}`, params, query.cursor, subject, items => this.visible(clusterId, relation, actor, scope, items));
      return { ...result, items: result.items.map(item => this.display(item)) };
    }
    if (relation !== 'plugins' || !['services', 'routes', 'consumers'].includes(type)) throw new BadRequestException({ code: 'UNKNOWN_RELATION', message: '不支持的实体关系' });
    const binding = ({ services: 'service', routes: 'route', consumers: 'consumer' } as Record<string, string>)[type];
    const result = await filteredList(this.kong, clusterId, '/plugins', params, query.cursor, subject, items => this.visible(clusterId, 'plugins', actor, scope, items.filter(plugin => plugin[binding]?.id === parent.id)));
    return { ...result, items: result.items.map(item => this.display(item)) };
  }

  private async references(clusterId: string, type: string, body: any, actor: EntityActor): Promise<EntityPreparationReference[]> {
    const evidence: EntityPreparationReference[] = [];
    const bindings: Record<string, string> = type === 'plugins' ? { service: 'services', route: 'routes', consumer: 'consumers' } : type === 'routes' ? { service: 'services' } : type === 'snis' ? { certificate: 'certificates' } : type === 'services' ? { client_certificate: 'certificates' } : {};
    for (const [field, target] of Object.entries(bindings)) {
      const referenceId = entityReferenceId(body[field]);
      if (!referenceId) continue;
      let referenced: any, permissionAction: 'read' | 'write' = 'read';
      try { referenced = await this.raw(clusterId, target, referenceId, 'read', actor); }
      catch (error) {
        // The caller already proved the complete child write. A writer can use
        // only this private parent identity; no parent configuration is exposed.
        const inheritedParent = type === 'routes' && target === 'services' || type === 'plugins' && ['services', 'routes', 'consumers'].includes(target);
        if (!inheritedParent || !(error instanceof HttpException) || error.getStatus() !== 403) throw error;
        referenced = await this.raw(clusterId, target, referenceId, 'write', actor); permissionAction = 'write';
      }
      evidence.push({ type: target, path: `/${target}/${identifier(referenced.id)}`, before: referenced, permissionAction });
      if (type === 'plugins' && target === 'routes' && entityReferenceId(referenced.service)) {
        // Plugin permissions may inherit through Route -> Service. Freeze the
        // real second-level parent now; historical review must not invent it
        // by querying a potentially different live Route after execution.
        evidence.push(...await this.references(clusterId, 'routes', referenced, actor));
      }
    }
    if (type === 'services' && body.ca_certificates != null) {
      if (!Array.isArray(body.ca_certificates) || body.ca_certificates.length > 1000) throw new BadRequestException({ code: 'INVALID_CA_CERTIFICATES', message: 'CA 证书引用必须为不超过 1000 项的数组' });
      for (const value of body.ca_certificates) {
        const caId = entityReferenceId(value);
        if (!caId) throw new BadRequestException({ code: 'INVALID_CA_CERTIFICATES', message: 'CA 证书引用必须包含有效 ID' });
        const referenced = await this.raw(clusterId, 'ca_certificates', caId, 'read', actor);
        evidence.push({ type: 'ca_certificates', path: `/ca_certificates/${identifier(referenced.id)}`, before: referenced, permissionAction: 'read' });
      }
    }
    if (type === 'services' && typeof body.host === 'string' && !isIP(body.host.replace(/^\[|\]$/g, ''))) {
      // An ordinary DNS host is valid. Only an actually registered Upstream
      // creates a scoped reference; never reject DNS just for lacking a DAO row.
      // Literal IPs cannot be Upstream names in 1.5; querying one returns 400.
      let upstream: any;
      try { upstream = await this.preflight(clusterId, `/upstreams/${identifier(body.host)}`, actor); }
      catch (error) { if (!(error instanceof HttpException && error.getStatus() === 404)) throw error; }
      if (upstream) {
        this.workspaces.assertMembership(await this.workspaces.listScope(clusterId, actor.workspaceId), upstream);
        await this.authz.assertEntity(actor.user, clusterId, 'upstreams', 'read', upstream, actor.workspaceId);
        evidence.push({ type: 'upstreams', path: `/upstreams/${identifier(upstream.id)}`, before: upstream, permissionAction: 'read' });
      } else {
        evidence.push({ type: 'upstreams', path: `/upstreams/${identifier(body.host)}`, before: null, permissionAction: 'read', absent: true });
      }
    }
    if (type === 'certificates' && body.snis !== undefined) {
      if (!Array.isArray(body.snis) || body.snis.length > 1000 || body.snis.some((name: unknown) => typeof name !== 'string' || !name.length || name.length > 253)) throw new BadRequestException({ code: 'INVALID_SNIS', message: 'SNI 关联必须为不超过 1000 项的有效名称数组' });
      for (const name of body.snis) {
        await this.authz.assertCluster(actor.user, clusterId, 'snis', 'write', actor.workspaceId);
        try { const sni = await this.raw(clusterId, 'snis', name, 'write', actor); evidence.push({ type: 'snis', path: `/snis/${identifier(name)}`, before: sni, permissionAction: 'write' }); }
        catch (error) { if (!(error instanceof HttpException && error.getStatus() === 404)) throw error; evidence.push({ type: 'snis', path: `/snis/${identifier(name)}`, before: null, permissionAction: 'write', absent: true }); }
      }
    }
    return evidence;
  }

  private async certificateAssociations(clusterId: string, certificateId: string | undefined, payload: any, actor: EntityActor): Promise<void> {
    if (payload.snis === undefined || !certificateId) return;
    const wanted = new Set(payload.snis);
    const scope = await this.workspaces.listScope(clusterId, actor.workspaceId);
    let cursor: string | undefined;
    // Certificate association writes can implicitly delete omitted SNIs. Read
    // all existing associations within a fixed budget before allowing a replace.
    for (let page = 0; page < 10; page++) {
      const path = `/certificates/${identifier(certificateId)}/snis`;
      const result = await this.execution.runInternalRead(clusterId, 'entity-preflight', () => this.kong.list(clusterId, path, { size: 100 }, cursor, `sni-associations:${actor.user.id}:${actor.workspaceId}:${certificateId}`), { paths: [path], workspaceId: actor.workspaceId, maxCalls: 4 });
      for (const sni of result.items) {
        this.workspaces.assertMembership(scope, sni);
        await this.authz.assertEntity(actor.user, clusterId, 'snis', 'write', sni, actor.workspaceId);
        if (!wanted.has(sni.name)) throw new HttpException({ code: 'SNI_RECYCLE_REQUIRED', message: '替换证书关联会删除现有 SNI；请先通过 SNI 回收站删除，再编辑关联' }, 409);
      }
      if (!result.nextCursor) return;
      cursor = result.nextCursor;
    }
    throw new HttpException({ code: 'SNI_ASSOCIATION_SCAN_INCOMPLETE', message: 'SNI 关联超出核验预算，请分批处理后重试' }, 409);
  }

  private async stampCertificateSnis(clusterId: string, certificate: any, payload: any, actor: EntityActor): Promise<void> {
    if (payload.snis === undefined) return;
    try {
      for (const name of payload.snis) {
        const before = await this.preflight(clusterId, `/snis/${identifier(name)}`, actor);
        if (before.certificate?.id !== certificate.id) throw new HttpException({ code: 'SNI_ASSOCIATION_CHANGED', message: '证书写入后 SNI 关联不一致，需要核验本次变更' }, 409);
        const prepared = await this.workspaces.prepareCreate(clusterId, 'snis', { tags: before.tags }, actor.workspaceId);
        if (JSON.stringify(prepared.tags) === JSON.stringify(before.tags)) continue;
        const after = await this.kong.request(clusterId, 'PATCH', `/snis/${identifier(before.id)}`, { tags: prepared.tags });
        await this.audit.append({ actorId: actor.user.id, clusterId, workspaceId: actor.workspaceId, entityType: 'snis', entityId: before.id, action: 'workspace_stamp', before, after, requestId: actor.requestId, ip: actor.ip });
        await this.indexResult(clusterId, 'snis', after);
      }
    } catch {
      // The certificate write already occurred. Do not describe a subsequent
      // association/stamp failure as a safely retryable validation error.
      throw new HttpException({ code: 'SNI_STAMP_RESULT_UNCERTAIN', message: '证书已提交，但 SNI 工作区绑定未完成核验；请根据变更回执检查关联，勿重复提交' }, 503);
    }
  }

  /** Shared preparation for direct execution and a sealed change compiler.
   * This method performs no business mutation, audit, index or credential write.
   * Read policies may maintain their existing observation caches. */
  @KongActorScope({ moduleArg: 1, action: 'write' })
  async prepareCore(clusterId: string, type: string, action: 'create' | 'update', id: string | undefined, body: unknown, actor: EntityActor): Promise<EntityMutationPreparation> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId, type, 'write');
    entityType(type);
    if (!['create', 'update'].includes(action)) throw new BadRequestException({ code: 'INVALID_ENTITY_CHANGE_ACTION' });
    const before = action === 'update' ? await this.raw(clusterId, type, id!, 'write', actor) : null;
    const payload = before
      ? await this.workspaces.prepareUpdate(clusterId, type, before, this.input(body), actor.workspaceId)
      : await this.workspaces.prepareCreate(clusterId, type, this.input(body), actor.workspaceId);
    if (before && type === 'plugins' && payload.config !== undefined) payload.config = this.mergeConfig(before.config, payload.config);
    if (before && type === 'routes' && payload.headers !== undefined) payload.headers = await this.preserveHiddenNative(clusterId, type, before, before.headers, payload.headers, actor, 'headers');
    if (before && type === 'upstreams' && payload.healthchecks !== undefined) payload.healthchecks = await this.preserveHiddenNative(clusterId, type, before, before.healthchecks, payload.healthchecks, actor, 'healthchecks');
    const effective = { ...before, ...payload };
    this.globalPlugin(type, effective, actor);
    await this.authz.assertEntity(actor.user, clusterId, type, 'write', normalizeEntityAuthorizationView(type, effective), actor.workspaceId);
    const capturedReferences = [...(before ? await this.references(clusterId, type, before, actor) : []), ...await this.references(clusterId, type, effective, actor)];
    const referenceMap = new Map<string, EntityPreparationReference>();
    for (const reference of capturedReferences) {
      const prior = referenceMap.get(reference.path);
      if (prior && this.secrets.fingerprint(prior.before) !== this.secrets.fingerprint(reference.before)) throw new HttpException({ code: 'ENTITY_REFERENCE_CHANGED', message: '捕获期间依赖配置发生变化，请重新规划' }, 409);
      referenceMap.set(reference.path, prior?.permissionAction === 'write' ? prior : reference);
    }
    const references = [...referenceMap.values()];
    if (['plugins', 'routes'].includes(type) && references.length > 8) throw new HttpException({ code: 'ENTITY_AUTHORIZATION_CLOSURE_LIMIT', message: '授权父对象闭包超出安全预算' }, 409);
    if (before && type === 'certificates') await this.certificateAssociations(clusterId, before.id, payload, actor);
    if (type === 'certificates') inspectCertificate(effective.cert, effective.key);
    if (type === 'ca_certificates') inspectCertificate(effective.cert);
    return { actor, type, action, nativeId: before?.id ?? payload.id, before, payload, references,
      ...(type === 'certificates' && payload.snis !== undefined ? { certificateSnis: references.filter(reference => reference.type === 'snis') } : {}) };
  }

  @KongActorScope({ moduleArg: 1, queryArg: 3, action: 'write' })
  async create(clusterId: string, type: string, body: unknown, query: ListQuery, actor: EntityActor): Promise<any> {
    const prepared = await this.prepareCore(clusterId, type, 'create', undefined, body, { ...actor, workspaceId: query.workspaceId ?? actor.workspaceId });
    ({ actor } = prepared); const { payload } = prepared;
    const reveal = this.wantsReveal(query);
    if (reveal) await this.authorizeReveal(clusterId, actor, type, payload);
    const entity = await this.mutations.execute(this.context(clusterId, type, 'create', actor, undefined, undefined, payload), async () => {
      await this.references(clusterId, type, payload, actor);
      const result = await this.kong.request(clusterId, 'POST', `/${type}`, payload);
      if (type === 'certificates') await this.stampCertificateSnis(clusterId, result, payload, actor);
      return result;
    });
    await this.indexResult(clusterId, type, entity);
    if (reveal) await this.reveal(clusterId, actor, query, type, entity);
    return { entity: this.display(entity, reveal), propagation };
  }
  @KongActorScope({ moduleArg: 1, queryArg: 4, action: 'write' })
  async update(clusterId: string, type: string, id: string, body: unknown, query: ListQuery, actor: EntityActor): Promise<any> {
    const prepared = await this.prepareCore(clusterId, type, 'update', id, body, { ...actor, workspaceId: query.workspaceId ?? actor.workspaceId });
    ({ actor } = prepared); const { before, payload } = prepared;
    const reveal = this.wantsReveal(query);
    if (reveal) await this.authorizeReveal(clusterId, actor, type, { ...before, ...payload });
    const entity = await this.mutations.execute(this.context(clusterId, type, 'update', actor, before.id, before, payload), async () => {
      await this.references(clusterId, type, { ...before, ...payload }, actor);
      if (type === 'certificates') await this.certificateAssociations(clusterId, before.id, payload, actor);
      const result = await this.kong.request(clusterId, 'PATCH', `/${type}/${identifier(before.id)}`, payload);
      if (type === 'certificates') await this.stampCertificateSnis(clusterId, result, payload, actor);
      return result;
    });
    await this.indexResult(clusterId, type, entity);
    if (reveal) await this.reveal(clusterId, actor, query, type, entity);
    return { entity: this.display(entity, reveal), propagation };
  }
  @KongActorScope({ moduleArg: 1, action: 'delete' })
  async delete(clusterId: string, type: string, id: string, body: unknown, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId, type, 'delete');
    entityType(type);
    const replay = await this.deleteReplay(clusterId, type, id, body, actor);
    if (replay !== null) return replay;
    const before = await this.raw(clusterId, type, id, 'delete', actor);
    confirmed(body, before);
    return this.recycle.archiveAndDelete({ ...this.context(clusterId, type, 'delete', actor, before.id, before), confirmName: objectBody(body).confirm_name }, true);
  }

  private async deleteReplay(clusterId: string, type: string, id: string, body: unknown, actor: EntityActor, extra: Record<string, any> = {}): Promise<any | null> {
    identifier(id);
    await this.authz.assertCluster(actor.user, clusterId, type, 'delete', actor.workspaceId);
    const input = objectBody(body);
    if (input.confirmed !== true || typeof input.confirm_name !== 'string' || !input.confirm_name.length) throw new BadRequestException({ code: 'CONFIRMATION_REQUIRED', message: '删除需要二次确认和准确对象名称' });
    const payload = { confirmed: true, confirm_name: input.confirm_name, parentId: extra.parentId, credentialKind: extra.credentialKind };
    return this.mutations.completed(this.context(clusterId, type, 'delete', actor, id, undefined, payload, extra));
  }

  private mergeConfig(original: any, patch: any): any {
    if (typeof patch === 'string' && patch.startsWith('[REDACTED:')) {
      if (this.secrets.redact({ secret: original }).secret !== patch) throw new BadRequestException({ code: 'INVALID_SECRET_MARKER', message: '脱敏占位符不匹配，不能当作配置值提交' });
      return original;
    }
    if (patch === null || typeof patch !== 'object') return patch;
    if (Array.isArray(patch)) {
      return patch.map((item, index) => {
        const previous = original?.[index];
        if (item && previous && typeof item === 'object' && !Array.isArray(item)) {
          const sameIdentity = ['id', 'name', 'key'].some(field => item[field] !== undefined && item[field] === previous[field]);
          const hadSecrets = JSON.stringify(this.secrets.redact(previous)) !== JSON.stringify(previous);
          if (hadSecrets && !sameIdentity) {
            for (const [field, value] of Object.entries(previous)) if (item[field] === undefined && JSON.stringify(this.secrets.redact({ [field]: value })) !== JSON.stringify({ [field]: value })) throw new BadRequestException({ code: 'SECRET_ARRAY_AMBIGUOUS', message: '数组记录含隐去的秘密，请授权查看并重新填写秘密后修改数组' });
          }
          return this.mergeConfig(sameIdentity ? previous : undefined, item);
        }
        return this.mergeConfig(previous, item);
      });
    }
    const result = Object.assign(Object.create(null), original && typeof original === 'object' && !Array.isArray(original) ? original : {});
    for (const [field, value] of Object.entries(patch)) result[field] = this.mergeConfig(original && Object.hasOwn(original, field) ? original[field] : undefined, value);
    return result;
  }

  /** Native maps replace public entries, but a redacted form cannot erase hidden
   * matches just by omitting them. Explicit null/empty sensitive arrays require
   * scoped secret-read access. Markers only restore their original bound value. */
  private async preserveHiddenNative(clusterId: string, type: string, entity: any, original: any, patch: any, actor: EntityActor, rootPath: string): Promise<any> {
    let secretReadChecked = false;
    const requireSecretRead = async () => {
      if (!secretReadChecked) { await this.authz.assertSecretRead(actor.user, clusterId, type, entity, actor.workspaceId); secretReadChecked = true; }
    };
    const safe = (value: any, key?: string) => key === undefined ? this.secrets.redact(value) : this.secrets.redact({ [key]: value })[key];
    const hasHidden = (value: any, key?: string) => JSON.stringify(value) !== JSON.stringify(safe(value, key));
    const marker = (value: any) => typeof value === 'string' && value.startsWith('[REDACTED');
    const containsMarker = (value: any): boolean => marker(value) || !!value && typeof value === 'object' && Object.values(value).some(containsMarker);
    const equal = (left: any, right: any) => JSON.stringify(left) === JSON.stringify(right);
    const ambiguous = () => new BadRequestException({ code: 'SECRET_ARRAY_AMBIGUOUS', message: '数组含隐藏值，不能按过滤或重排后的数组覆盖；请保留完整值，或显式清空后重新设置' });
    const merge = async (previous: any, incoming: any, path: string, key?: string): Promise<any> => {
      const redacted = safe(previous, key), hidden = hasHidden(previous, key);
      if (marker(incoming)) {
        if (!marker(redacted) || incoming !== redacted) throw new BadRequestException({ code: 'INVALID_SECRET_MARKER', message: '脱敏占位符不属于当前字段，不能提交为配置值' });
        return structuredClone(previous);
      }
      if (incoming === null) { if (hidden) await requireSecretRead(); return null; }
      if (!incoming || typeof incoming !== 'object') {
        if (hidden && incoming === '') await requireSecretRead();
        return incoming;
      }
      if (Array.isArray(incoming)) {
        if (!Array.isArray(previous)) { if (containsMarker(incoming)) throw new BadRequestException({ code: 'INVALID_SECRET_MARKER', message: '数组包含没有原值的脱敏占位符' }); return incoming; }
        if (!hidden) { if (containsMarker(incoming)) throw new BadRequestException({ code: 'INVALID_SECRET_MARKER', message: '公开数组不能提交脱敏占位符' }); return incoming; }
        if (equal(previous, incoming)) return incoming;
        if (!incoming.length) { await requireSecretRead(); return []; }
        if (marker(redacted)) {
          if (containsMarker(incoming)) throw ambiguous();
          // A whole concealed header array can only be replaced deliberately;
          // the editor omits that map entry when its value was never visible.
          await requireSecretRead(); return incoming;
        }
        const indices = previous.map((item: any, index: number) => hasHidden(item) ? index : -1).filter((index: number) => index >= 0);
        for (const index of indices) {
          // Never transfer a hidden value merely because an array index happens
          // to exist after filtering or sorting. An exact bound value is needed.
          if (index >= incoming.length || !equal(incoming[index], previous[index]) && !equal(incoming[index], redacted[index])) throw ambiguous();
        }
        const result: any[] = [];
        for (let index = 0; index < incoming.length; index++) {
          if (containsMarker(incoming[index])) {
            if (!equal(incoming[index], redacted[index])) throw ambiguous();
            result.push(structuredClone(previous[index]));
          } else result.push(incoming[index]);
        }
        return result;
      }
      const prior = previous && typeof previous === 'object' && !Array.isArray(previous) ? previous : Object.create(null);
      const result = Object.create(null);
      const headerMap = path === 'headers' || path.endsWith('.headers');
      const originalNames: Record<string, string> = Object.create(null);
      const incomingNames = new Set<string>();
      for (const name of Object.keys(prior)) {
        const normalized = headerMap ? name.toLowerCase() : name;
        if (Object.hasOwn(originalNames, normalized)) throw new BadRequestException({ code: 'AMBIGUOUS_HEADER_NAME', message: '原请求头配置含大小写重复名称，请先核对完整配置' });
        originalNames[normalized] = name;
      }
      for (const [name, value] of Object.entries(incoming)) {
        const normalized = headerMap ? name.toLowerCase() : name;
        if (incomingNames.has(normalized)) throw new BadRequestException({ code: 'AMBIGUOUS_HEADER_NAME', message: '请求头名称不能仅以大小写区分' });
        incomingNames.add(normalized);
        const originalName = originalNames[normalized];
        result[name] = await merge(originalName === undefined ? undefined : prior[originalName], value, `${path}.${name}`, name);
      }
      for (const [name, value] of Object.entries(prior)) if (!incomingNames.has(headerMap ? name.toLowerCase() : name) && hasHidden(value, name)) result[name] = structuredClone(value);
      return result;
    };
    return merge(original, patch, rootPath);
  }

  @KongActorScope({ module: 'upstreams', queryArg: 2 })
  async targets(clusterId: string, upstreamId: string, query: ListQuery, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, query.workspaceId, 'upstreams', 'read');
    const upstream = await this.parentIdentity(clusterId, 'upstreams', upstreamId, 'targets', 'read', actor);
    const tags = this.queryTags(query.tags), scope = await this.scope(clusterId, actor, tags, 'targets');
    const result = await filteredList(this.kong, clusterId, `/upstreams/${identifier(upstream.id)}/targets`, { size: pageSize(query.size) }, query.cursor, await this.subject(actor, scope, `targets:${upstream.id}`), async items => this.authz.filterEntities(actor.user, clusterId, 'targets', items.filter(item => (!item.upstream?.id || item.upstream.id === upstream.id) && this.matchesTags(item, tags)), actor.workspaceId));
    return { ...result, items: result.items.map(item => this.display(item)), effective_workspace_id: actor.workspaceId, workspace_inheritance: 'upstream', historical_tags_may_differ: true };
  }
  /** Read-only history is not a current Target selection or a write permit.
   * Keep old row tags intact for current per-row authorization. The current
   * parent owns workspace membership; historical child tags may be stale. */
  @KongActorScope({ module: 'upstreams', queryArg: 2 })
  async targetHistory(clusterId: string, upstreamId: string, query: ListQuery, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, query.workspaceId, 'upstreams', 'read');
    const upstream = await this.parentIdentity(clusterId, 'upstreams', upstreamId, 'targets', 'read', actor);
    const tags = this.queryTags(query.tags), scope = await this.scope(clusterId, actor, tags, 'targets');
    const result = await filteredList(this.kong, clusterId, `/upstreams/${identifier(upstream.id)}/targets/all`,
      { size: pageSize(query.size) }, query.cursor, await this.subject(actor, scope, `target-history:${upstream.id}`),
      async items => this.authz.filterEntities(actor.user, clusterId, 'targets',
        items.filter(item => item?.upstream?.id === upstream.id && this.matchesTags(item, tags)), actor.workspaceId));
    return { ...result, items: result.items.map(item => this.display(item)), effective_workspace_id: actor.workspaceId,
      workspace_inheritance: 'upstream', historical_tags_may_differ: true, selection: 'history', current_selection: false };
  }
  @KongActorScope({ module: 'upstreams' })
  async health(clusterId: string, upstreamId: string, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId, 'upstreams', 'read');
    const upstream = await this.parentIdentity(clusterId, 'upstreams', upstreamId, 'targets', 'read', actor);
    const result = await this.kong.request(clusterId, 'GET', `/upstreams/${identifier(upstream.id)}/health`);
    return { ...result, node_scope: 'current_admin_node', message: '健康状态来自当前 Admin 节点；其他节点可能不同' };
  }
  @KongActorScope({ module: 'upstreams', action: 'write' })
  async prepareTarget(clusterId: string, upstreamId: string, action: 'create' | 'update' | 'health', targetId: string | undefined, body: unknown, actor: EntityActor): Promise<EntityMutationPreparation> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId, 'upstreams', 'write');
    if (!['create', 'update', 'health'].includes(action)) throw new BadRequestException({ code: 'INVALID_ENTITY_CHANGE_ACTION' });
    const existing = action === 'create' ? null : await this.target(clusterId, upstreamId, targetId!, 'write', actor);
    const upstream = existing?.upstream ?? await this.parentIdentity(clusterId, 'upstreams', upstreamId, 'targets', 'write', actor);
    const before = existing?.target ?? null;
    const input = this.input(body);
    this.assertParentField(input, 'upstream', upstream.id);
    if (before && input.target !== undefined && input.target !== before.target) throw new BadRequestException({ code: 'TARGET_ADDRESS_IMMUTABLE', message: '修改地址请创建新 Target 并将旧 Target 移入回收站' });
    if (action === 'health' && (!['healthy', 'unhealthy'].includes(input.state) || Object.keys(input).some(key => key !== 'state'))) throw new BadRequestException({ code: 'INVALID_HEALTH_STATE', message: '无效的健康状态' });
    const prepared = action === 'health' ? input : before
      ? await this.workspaces.prepareInheritedUpdate(clusterId, 'targets', upstream, before, input, actor.workspaceId)
      : await this.workspaces.prepareInheritedCreate(clusterId, 'targets', upstream, input, actor.workspaceId);
    const payload = action === 'update' ? { ...prepared, target: before.target, weight: input.weight ?? before.weight } : prepared;
    return { actor, type: 'targets', action, nativeId: before?.id ?? payload.id, before, payload,
      parent: { type: 'upstreams', before: upstream }, references: [{ type: 'upstreams', path: `/upstreams/${identifier(upstream.id)}`, before: upstream, permissionAction: 'write', purpose: 'private-parent' }] };
  }
  @KongActorScope({ module: 'upstreams', action: 'write' })
  async createTarget(clusterId: string, upstreamId: string, body: unknown, actor: EntityActor): Promise<any> {
    const prepared = await this.prepareTarget(clusterId, upstreamId, 'create', undefined, body, actor);
    ({ actor } = prepared); const { payload } = prepared, upstream = prepared.parent!.before;
    const entity = await this.mutations.execute(this.context(clusterId, 'targets', 'create', actor, undefined, undefined, payload, { parentId: upstream.id }), async () => {
      await this.parentIdentity(clusterId, 'upstreams', upstream.id, 'targets', 'write', actor, { ...payload, upstream: { id: upstream.id } });
      return this.kong.request(clusterId, 'POST', `/upstreams/${identifier(upstream.id)}/targets`, payload);
    });
    return { entity: this.display(entity), propagation };
  }
  private async target(clusterId: string, upstreamId: string, targetId: string, action: string, actor: EntityActor): Promise<{ upstream: any; target: any }> {
    const target = await this.preflight(clusterId, `/upstreams/${identifier(upstreamId)}/targets/${identifier(targetId)}`, actor);
    const upstream = await this.parentIdentity(clusterId, 'upstreams', upstreamId, 'targets', action, actor, target);
    if (target.upstream?.id && target.upstream.id !== upstream.id) throw new NotFoundException({ code: 'TARGET_NOT_FOUND', message: 'Target 不属于此 Upstream' });
    await this.authz.assertEntity(actor.user, clusterId, 'targets', action, target, actor.workspaceId);
    return { upstream, target };
  }
  @KongActorScope({ module: 'upstreams', action: 'write' })
  async updateTarget(clusterId: string, upstreamId: string, targetId: string, body: unknown, actor: EntityActor): Promise<any> {
    const prepared = await this.prepareTarget(clusterId, upstreamId, 'update', targetId, body, actor);
    ({ actor } = prepared); const { before, payload } = prepared, upstream = prepared.parent!.before;
    const entity = await this.mutations.execute(this.context(clusterId, 'targets', 'update', actor, before.id, before, payload, { parentId: upstream.id }), async () => {
      await this.target(clusterId, upstream.id, before.id, 'write', actor);
      return this.kong.request(clusterId, 'POST', `/upstreams/${identifier(upstream.id)}/targets`, payload);
    });
    return { entity: this.display(entity), original_id: before.id, effective_id: entity.id, propagation, message: 'Kong 1.5 权重修改追加 Target 历史，新记录成为有效配置' };
  }
  @KongActorScope({ module: 'upstreams', action: 'delete' })
  async deleteTarget(clusterId: string, upstreamId: string, targetId: string, body: unknown, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId, 'upstreams', 'delete');
    const canonicalParent = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(upstreamId) ? upstreamId : (await this.preflight(clusterId, `/upstreams/${identifier(upstreamId)}`, actor)).id;
    const replay = await this.deleteReplay(clusterId, 'targets', targetId, body, actor, { parentId: canonicalParent });
    if (replay !== null) return replay;
    const { upstream, target } = await this.target(clusterId, upstreamId, targetId, 'delete', actor);
    confirmed(body, target);
    return this.recycle.archiveAndDelete({ ...this.context(clusterId, 'targets', 'delete', actor, target.id, target, undefined, { parentId: upstream.id }), confirmName: objectBody(body).confirm_name }, true);
  }
  @KongActorScope({ module: 'upstreams', action: 'write' })
  async setHealth(clusterId: string, upstreamId: string, targetId: string, state: string, actor: EntityActor): Promise<any> {
    const prepared = await this.prepareTarget(clusterId, upstreamId, 'health', targetId, { state }, actor);
    ({ actor } = prepared); const upstream = prepared.parent!.before, target = prepared.before;
    await this.mutations.execute(this.context(clusterId, 'targets', `mark_${state}`, actor, target.id, target, { state }, { parentId: upstream.id }), async () => {
      await this.target(clusterId, upstream.id, target.id, 'write', actor);
      return this.kong.request(clusterId, 'POST', `/upstreams/${identifier(upstream.id)}/targets/${identifier(target.id)}/${state}`);
    });
    return { target_id: target.id, state, node_scope: 'current_admin_node', message: '已提交当前节点健康置位，请刷新健康状态核验' };
  }

  @KongActorScope({ module: 'consumers', queryArg: 3 })
  async credentials(clusterId: string, consumerId: string, kindValue: string, query: ListQuery, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, query.workspaceId, 'consumers', 'read');
    const kind = credentialKind(kindValue);
    const consumer = await this.parentIdentity(clusterId, 'consumers', consumerId, kind, 'read', actor);
    const reveal = this.wantsReveal(query);
    const tags = this.queryTags(query.tags), scope = await this.scope(clusterId, actor, tags, kind);
    const result = await filteredList(this.kong, clusterId, `/consumers/${identifier(consumer.id)}/${kind}`, { size: pageSize(query.size) }, query.cursor, await this.subject(actor, scope, `credentials:${consumer.id}:${kind}`), async items => this.authz.filterEntities(actor.user, clusterId, kind, items.filter(item => (!item.consumer?.id || item.consumer.id === consumer.id) && this.matchesTags(item, tags)), actor.workspaceId));
    const items = await Promise.all(result.items.map(async item => {
      if (reveal) await this.reveal(clusterId, actor, query, kind, item, consumer);
      return this.display(reveal ? await this.revealedCredential(clusterId, consumer.id, kind, item) : item, reveal);
    }));
    return { ...result, items, effective_workspace_id: actor.workspaceId, workspace_inheritance: 'consumer' };
  }
  private async credential(clusterId: string, consumerId: string, kind: string, id: string, action: string, actor: EntityActor): Promise<{ consumer: any; entity: any }> {
    credentialKind(kind);
    const entity = await this.preflight(clusterId, `/consumers/${identifier(consumerId)}/${kind}/${identifier(id)}`, actor);
    const consumer = await this.parentIdentity(clusterId, 'consumers', consumerId, kind, action, actor, entity);
    if (entity.consumer?.id && entity.consumer.id !== consumer.id) throw new NotFoundException({ code: 'CREDENTIAL_NOT_FOUND', message: '凭证不属于此 Consumer' });
    await this.authz.assertEntity(actor.user, clusterId, kind, action, entity, actor.workspaceId);
    return { consumer, entity };
  }
  @KongActorScope({ module: 'consumers', queryArg: 4 })
  async getCredential(clusterId: string, consumerId: string, kind: string, id: string, query: ListQuery, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, query.workspaceId, 'consumers', 'read');
    const { consumer, entity } = await this.credential(clusterId, consumerId, kind, id, 'read', actor);
    const reveal = await this.reveal(clusterId, actor, query, kind, entity, consumer);
    const raw = reveal ? await this.revealedCredential(clusterId, consumer.id, kind, entity) : entity;
    return { entity: this.display(raw, reveal) };
  }
  @KongActorScope({ module: 'consumers', action: 'write' })
  async prepareCredential(clusterId: string, consumerId: string, kindValue: string, action: 'create' | 'update', id: string | undefined, body: unknown, actor: EntityActor): Promise<EntityMutationPreparation> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId, 'consumers', 'write');
    const kind = credentialKind(kindValue);
    if (!['create', 'update'].includes(action)) throw new BadRequestException({ code: 'INVALID_ENTITY_CHANGE_ACTION' });
    const existing = action === 'create' ? null : await this.credential(clusterId, consumerId, kind, id!, 'write', actor);
    const consumer = existing?.consumer ?? await this.parentIdentity(clusterId, 'consumers', consumerId, kind, 'write', actor);
    const before = existing?.entity ?? null, input = this.input(body);
    this.assertParentField(input, 'consumer', consumer.id);
    const payload = before
      ? await this.workspaces.prepareInheritedUpdate(clusterId, 'credentials', consumer, before, input, actor.workspaceId)
      : await this.workspaces.prepareInheritedCreate(clusterId, 'credentials', consumer, input, actor.workspaceId);
    return { actor, type: kind, action, nativeId: before?.id ?? payload.id, before, payload,
      parent: { type: 'consumers', before: consumer }, references: [{ type: 'consumers', path: `/consumers/${identifier(consumer.id)}`, before: consumer, permissionAction: 'write', purpose: 'private-parent' }] };
  }
  /** Freeze trustworthy plaintext now; a mutable credential_refs row cannot
   * replace this evidence when the approved intent is executed or rolled back. */
  @KongActorScope({ module: 'consumers', action: 'write' })
  async prepareCredentialRecovery(clusterId: string, consumerId: string, kindValue: string, id: string, actor: EntityActor): Promise<{ restorePayload?: unknown; sourceHashHmac?: string; blockerCodes: string[] }> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId, 'consumers', 'write');
    const kind = credentialKind(kindValue), { consumer, entity } = await this.credential(clusterId, consumerId, kind, id, 'write', actor);
    if (entity.ttl !== undefined && entity.ttl !== null) return { blockerCodes: ['NATIVE_TTL_EXPIRY_UNKNOWN'] };
    try {
      const restorePayload = await this.credentialsStore.getRestorePayload(clusterId, consumer.id, kind, entity.id, entity);
      return { restorePayload, ...(kind === 'basic-auth' ? { sourceHashHmac: this.secrets.fingerprint(entity.password) } : {}),
        blockerCodes: kind === 'oauth2' ? ['OAUTH_CLIENT_ONLY_NO_TOKENS'] : [] };
    } catch (error) {
      if (!(error instanceof HttpException) || error.getStatus() !== 409) throw error;
      return { blockerCodes: [kind === 'basic-auth' ? 'BASIC_AUTH_NOT_RECOVERABLE' : 'CREDENTIAL_SECRET_NOT_RECOVERABLE'] };
    }
  }
  @KongActorScope({ module: 'consumers', queryArg: 4, action: 'write' })
  async createCredential(clusterId: string, consumerId: string, kindValue: string, body: unknown, query: ListQuery, actor: EntityActor): Promise<any> {
    const prepared = await this.prepareCredential(clusterId, consumerId, kindValue, 'create', undefined, body, { ...actor, workspaceId: query.workspaceId ?? actor.workspaceId });
    ({ actor } = prepared); const { payload } = prepared, consumer = prepared.parent!.before, kind = credentialKind(kindValue);
    const reveal = this.wantsReveal(query);
    if (reveal) await this.authorizeReveal(clusterId, actor, kind, { ...payload, consumer: { id: consumer.id } }, consumer);
    const entity = await this.mutations.execute(this.context(clusterId, 'credentials', 'create', actor, undefined, undefined, payload, { parentId: consumer.id, credentialKind: kind }), async () => {
      await this.parentIdentity(clusterId, 'consumers', consumer.id, kind, 'write', actor, { ...payload, consumer: { id: consumer.id } });
      const result = await this.kong.request(clusterId, 'POST', `/consumers/${identifier(consumer.id)}/${kind}`, payload);
      await this.credentialsStore.save(clusterId, consumer.id, kind, result, payload);
      return result;
    });
    if (reveal) await this.reveal(clusterId, actor, query, kind, entity, consumer);
    return { entity: this.display(reveal && kind === 'basic-auth' ? { ...entity, password: payload.password } : entity, reveal), propagation };
  }
  @KongActorScope({ module: 'consumers', queryArg: 5, action: 'write' })
  async updateCredential(clusterId: string, consumerId: string, kind: string, id: string, body: unknown, query: ListQuery, actor: EntityActor): Promise<any> {
    const prepared = await this.prepareCredential(clusterId, consumerId, kind, 'update', id, body, { ...actor, workspaceId: query.workspaceId ?? actor.workspaceId });
    ({ actor } = prepared); const { before, payload } = prepared, consumer = prepared.parent!.before;
    const reveal = this.wantsReveal(query);
    if (reveal) await this.authorizeReveal(clusterId, actor, kind, { ...before, ...payload }, consumer);
    const entity = await this.mutations.execute(this.context(clusterId, 'credentials', 'update', actor, before.id, before, payload, { parentId: consumer.id, credentialKind: kind }), async () => {
      await this.credential(clusterId, consumer.id, kind, before.id, 'write', actor);
      const result = await this.kong.request(clusterId, 'PATCH', `/consumers/${identifier(consumer.id)}/${kind}/${identifier(before.id)}`, payload);
      await this.credentialsStore.save(clusterId, consumer.id, kind, result, payload);
      return result;
    });
    if (reveal) await this.reveal(clusterId, actor, query, kind, entity, consumer);
    return { entity: this.display(reveal ? await this.revealedCredential(clusterId, consumer.id, kind, entity) : entity, reveal), propagation };
  }
  @KongActorScope({ module: 'consumers', action: 'delete' })
  async deleteCredential(clusterId: string, consumerId: string, kind: string, id: string, body: unknown, actor: EntityActor): Promise<any> {
    actor = await this.scoped(clusterId, actor, actor.workspaceId, 'consumers', 'delete');
    credentialKind(kind);
    const canonicalParent = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(consumerId) ? consumerId : (await this.preflight(clusterId, `/consumers/${identifier(consumerId)}`, actor)).id;
    const replay = await this.deleteReplay(clusterId, 'credentials', id, body, actor, { parentId: canonicalParent, credentialKind: kind });
    if (replay !== null) return replay;
    const { consumer, entity } = await this.credential(clusterId, consumerId, kind, id, 'delete', actor);
    confirmed(body, entity);
    return this.recycle.archiveAndDelete({ ...this.context(clusterId, 'credentials', 'delete', actor, entity.id, entity, undefined, { parentId: consumer.id, credentialKind: kind }), confirmName: objectBody(body).confirm_name }, true);
  }
}

export interface EntityReferenceLabel { type: string; id: string; visible: boolean; label?: string; detail?: string; expires_at?: string; expired?: boolean }
/** Human label for a reference; secrets (keys, cert PEM) never leave the server. */
export function referenceLabel(type: string, e: any): Pick<EntityReferenceLabel, 'label' | 'detail' | 'expires_at' | 'expired'> {
  if (type === 'certificates' || type === 'ca_certificates') {
    try {
      const leaf = new X509Certificate(String(e?.cert ?? '').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)?.[0] ?? '');
      const cn = /(?:^|\n)CN=([^\n]+)/.exec(leaf.subject)?.[1];
      const sans = (leaf.subjectAltName ?? '').split(/,\s*/).filter(Boolean).map(v => v.replace(/^DNS:/, '')).slice(0, 5);
      const expiresAt = new Date(leaf.validTo).toISOString();
      return { label: cn ?? sans[0] ?? e?.id, detail: sans.length ? `SAN: ${sans.join(', ')}` : undefined, expires_at: expiresAt, expired: Date.parse(expiresAt) < Date.now() };
    } catch { return { label: e?.id }; }
  }
  if (type === 'consumers') return { label: e?.username ?? e?.custom_id ?? e?.id, detail: e?.username && e?.custom_id ? `custom_id: ${e.custom_id}` : undefined };
  if (type === 'services') return { label: e?.name ?? e?.host ?? e?.id, detail: e?.host ? `${e.protocol ?? 'http'}://${e.host}${e.port ? `:${e.port}` : ''}${e.path ?? ''}` : undefined };
  if (type === 'routes') return { label: e?.name || [...(e?.hosts ?? []), ...(e?.paths ?? [])].slice(0, 2).join(' ') || e?.id, detail: [...(e?.hosts ?? []), ...(e?.paths ?? [])].slice(0, 4).join(' · ') || undefined };
  if (type === 'plugins') return { label: e?.name ?? e?.id };
  return { label: e?.name ?? e?.id };
}
