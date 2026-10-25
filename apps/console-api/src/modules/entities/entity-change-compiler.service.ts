import { BadRequestException, ConflictException, ForbiddenException, HttpException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { randomBytes, randomUUID } from 'node:crypto';
import { KongService } from '../../infrastructure/kong/kong.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { KongActorScope } from '../../infrastructure/kong/actor-scope';
import { immutableJson } from '../../infrastructure/kong/immutable-json';
import { assertKongPath } from '../../infrastructure/kong/policy';
import { currentEffectiveTarget } from '../../infrastructure/kong/effective-target';
import { SecretService } from '../../infrastructure/secret.service';
import { AuthorizationService } from '../authorization/authorization.service';
import { WorkspaceResolverService } from '../workspaces/workspace-resolver.service';
import { deriveImpact, mergeImpact } from '../mutations/mutation-impact';
import { assertTransferJson, generatedFieldsMissing, normalizeSchema, schemaFields, UUID } from '../config-transfer/schema-normalization';
import {ConfigTransferError} from '../config-transfer/transfer.types';
import { EntityService } from './entities.service';
import { CREDENTIAL_KINDS, EntityActor, identifier } from './entities.types';
import { entityChangeInput } from './entity-change-input';
import { entityReferenceId, normalizeEntityAuthorizationView } from './entity-reference';
import type { EntityChangeInput, EntityChangeOperation, EntityChangePacket, EntityChangePrerequisite, EntityChangePreparationBoundary, EntityChangeReview, EntityMutationPreparation, EntityWriteSchemaMaterial, PreparedEntityChange, StoredEntitySubjectAction, StoredEntityRevalidationPhase } from './entity-change.types';

const unavailable = () => new ServiceUnavailableException({ code: 'ENTITY_CHANGE_PREPARATION_POLICY_UNAVAILABLE', message: '变更准备策略尚未安装，未执行任何网关变更' });
const changed = (code = 'ENTITY_CHANGE_BASELINE_CHANGED') => new ConflictException({ code, message: '原对象、依赖或能力已变化，请基于当前配置重新规划' });
type Draft = Pick<PreparedEntityChange, 'prerequisites' | 'schemas' | 'packets' | 'metadataObligations' | 'recovery'>;

/** A fixed, zero-native-write compiler. Nothing in this provider creates a
 * job, approval, claim or permit. Root enables submission/execution separately
 * after the durable-intent and recovery-baseline storage gates pass. */
@Injectable()
export class EntityChangeCompilerService {
  private boundary?: Readonly<EntityChangePreparationBoundary>;
  constructor(private readonly entities: EntityService, private readonly kong: KongService, private readonly authz: AuthorizationService,
    private readonly workspaces: WorkspaceResolverService, private readonly secrets: SecretService, private readonly execution: KongExecutionContextService) {}

  installPreparationBoundary(boundary: EntityChangePreparationBoundary): void {
    if (this.boundary || !boundary || typeof boundary.assertPacket !== 'function'
      || boundary.prepareRecycle !== undefined && typeof boundary.prepareRecycle !== 'function'
      || boundary.assertRecycleCurrent !== undefined && typeof boundary.assertRecycleCurrent !== 'function'
      || boundary.assertStoredSubject !== undefined && typeof boundary.assertStoredSubject !== 'function') throw new ConflictException({ code: 'ENTITY_CHANGE_PREPARATION_POLICY_ALREADY_INSTALLED' });
    this.boundary = Object.freeze({ assertPacket: boundary.assertPacket.bind(boundary),
      ...(boundary.prepareRecycle ? { prepareRecycle: boundary.prepareRecycle.bind(boundary) } : {}),
      ...(boundary.assertRecycleCurrent ? { assertRecycleCurrent: boundary.assertRecycleCurrent.bind(boundary) } : {}),
      ...(boundary.assertStoredSubject ? { assertStoredSubject: boundary.assertStoredSubject.bind(boundary) } : {}) });
  }
  private policy(): Readonly<EntityChangePreparationBoundary> { if (!this.boundary) throw unavailable(); return this.boundary; }
  private explicitWorkspace(actor: EntityActor): string {
    if (typeof actor?.workspaceId !== 'string' || !UUID.test(actor.workspaceId)) throw new BadRequestException({ code: 'ENTITY_CHANGE_WORKSPACE_REQUIRED', message: '规划变更必须选择已存在的工作区' });
    return actor.workspaceId;
  }
  private read(cid: string, path: string, actor: EntityActor): Promise<any> {
    assertKongPath('GET', path);
    return this.execution.runInternalRead(cid, 'entity-preflight', () => this.kong.request(cid, 'GET', path), { paths: [path], workspaceId: actor.workspaceId, maxCalls: 4 });
  }
  private async absent(cid: string, path: string, type: string, actor: EntityActor, draft: Draft, nativeId?: string, parentId?: string): Promise<void> {
    try { await this.read(cid, path, actor); throw changed('ENTITY_CHANGE_ID_OR_NAME_OCCUPIED'); }
    catch (error) { if (!(error instanceof HttpException) || error.getStatus() !== 404) throw error; }
    draft.prerequisites.push({ type, path, nativeId, parentId, before: null, absent: true, fingerprint: this.secrets.fingerprint(null), permissionAction: 'write' });
  }
  private evidence(prepared: EntityMutationPreparation, draft: Draft, canonicalPath: string): void {
    if (prepared.before) draft.prerequisites.push({ type: prepared.type, path: canonicalPath, nativeId: prepared.before.id,
      parentId: prepared.parent?.before.id, before: prepared.before, absent: false, fingerprint: this.secrets.fingerprint(prepared.before), permissionAction: 'write' });
    for (const reference of prepared.references) draft.prerequisites.push({ type: reference.type, path: reference.path,
      nativeId: reference.before?.id, before: reference.before, absent: reference.before === null,
      fingerprint: this.secrets.fingerprint(reference.before), permissionAction: reference.permissionAction, ...(reference.purpose ? { purpose: reference.purpose } : {}) });
  }
  private packet(draft: Draft, values: Omit<EntityChangePacket, 'key' | 'order' | 'bodyHmac' | 'beforeHmac'>): EntityChangePacket {
    assertKongPath(values.method, values.canonicalPath);
    if (values.body !== undefined) assertTransferJson(values.body);
    if (!UUID.test(values.nativeId)) throw new ConflictException({ code: 'ENTITY_CHANGE_CANONICAL_ID_REQUIRED' });
    const packet = { ...values, key: `packet-${draft.packets.length + 1}`, order: draft.packets.length + 1,
      bodyHmac: this.secrets.fingerprint(values.body ?? null), beforeHmac: this.secrets.fingerprint(values.before) };
    draft.packets.push(packet); return packet;
  }
  private generateCredentialDefaults(kind: string, payload: Record<string, any>, schema: unknown): void {
    const fields = schemaFields(schema), names = kind === 'key-auth' ? ['key'] : kind === 'jwt' ? ['key', 'secret'] : kind === 'oauth2' ? ['client_id', 'client_secret'] : kind === 'hmac-auth' ? ['secret'] : [];
    for (const name of names) if (!Object.hasOwn(payload, name) && fields[name]?.type === 'string') payload[name] = name === 'client_id' || name === 'key' && kind === 'jwt' ? randomUUID() : randomBytes(32).toString('hex');
    if (generatedFieldsMissing(payload, schema).length) throw new BadRequestException({ code: 'ENTITY_CHANGE_GENERATED_FIELD_REQUIRED', message: '此凭证需要显式提供无法预先固定的自动生成字段' });
  }
  private validationInput(value: unknown, schema: unknown): any {
    const visit = (input: any, definition: any): any => {
      if (input === undefined && (definition?.type === 'boolean' && typeof definition.default === 'boolean'
        || ['number', 'integer'].includes(definition?.type) && typeof definition.default === 'number')) input = definition.default;
      if (!input || typeof input !== 'object') return input;
      if (Array.isArray(input)) return input.map(item => visit(item, definition?.elements));
      if (definition?.type === 'map') return Object.fromEntries(Object.entries(input).map(([name, item]) => [name, visit(item, definition.values)]));
      if (!definition?.fields) return structuredClone(input);
      const result = structuredClone(input), fields = schemaFields(definition);
      for (const [name, field] of Object.entries(fields)) { const child = visit(result[name], field); if (child !== undefined) result[name] = child; }
      return result;
    };
    // Literal booleans/numbers cannot be credentials, even when an option's
    // name contains "authorization". Never copy string/record secret defaults
    // or change the approved wire payload when evaluating required fields.
    return visit(value, { fields: schemaFields(schema) });
  }
  private async schema(cid: string, packet: EntityChangePacket, draft: Draft): Promise<EntityWriteSchemaMaterial> {
    const material = await this.kong.prepareSchema(cid, packet.canonicalPath, packet.body);
    if (material.payloadHmac !== packet.bodyHmac || material.clusterId !== cid || material.canonicalPath !== packet.canonicalPath) throw changed('ENTITY_CHANGE_SCHEMA_BINDING_INVALID');
    if (packet.body !== undefined) {
      // Validate known scalar/enum/range constraints with the already shared
      // M8 checker. Evaluate create defaults, but keep the exact supplied wire
      // body; server-generated credential values were frozen beforehand.
      let validationBody=packet.body;
      // Kong's nested Admin routes supply the DAO foreign key from their
      // server-resolved parent. Validate that required field in a private
      // view without adding it to the approved wire payload or its HMAC.
      const fields=schemaFields(material.schemaMaterial.entity.schema);
      if(fields.consumer?.type==='foreign'&&fields.consumer.reference==='consumers'&&packet.credentialKind&&packet.nativeType===packet.credentialKind&&packet.parentId&&UUID.test(packet.parentId)
        &&packet.canonicalPath===`/consumers/${packet.parentId}/${packet.credentialKind}${packet.mutationAction==='create'?'':`/${packet.nativeId}`}`){
        validationBody={...packet.body,consumer:{id:packet.parentId}};
      }else if(fields.upstream?.type==='foreign'&&fields.upstream.reference==='upstreams'&&packet.nativeType==='targets'&&packet.parentId&&UUID.test(packet.parentId)&&packet.canonicalPath===`/upstreams/${packet.parentId}/targets`){
        validationBody={...packet.body,upstream:{id:packet.parentId}};
      }
      try {
        normalizeSchema(this.validationInput(validationBody, material.schemaMaterial.entity.schema), material.schemaMaterial.entity.schema, { defaults: packet.mutationAction === 'create', required: packet.mutationAction === 'create' });
        if (material.schemaMaterial.plugin && packet.body.config !== undefined) {
          normalizeSchema(this.validationInput(packet.body.config, material.schemaMaterial.plugin.schema), material.schemaMaterial.plugin.schema, { defaults: packet.mutationAction === 'create', required: packet.mutationAction === 'create', path: 'config' });
          if (generatedFieldsMissing(packet.body.config as Record<string, unknown>, material.schemaMaterial.plugin.schema).length) throw new BadRequestException({ code: 'ENTITY_CHANGE_GENERATED_FIELD_REQUIRED', message: '插件含未固定的自动生成字段，请显式设置后再提交' });
        }
      } catch(error) {
        if(error instanceof ConfigTransferError)throw new BadRequestException({code:'ENTITY_CHANGE_SCHEMA_INVALID',message:'配置不符合当前 Kong schema',
          fields:error.path&&/^[A-Za-z0-9_.\[\]-]{1,160}$/.test(error.path)?{[error.path]:error.code}:undefined});
        throw error;
      }
    }
    draft.schemas.push(material); return material;
  }
  private async effectiveTarget(cid: string, upstreamId: string, address: string, actor: EntityActor): Promise<any | null> {
    const path = `/upstreams/${identifier(upstreamId)}/targets`;
    return this.execution.runInternalRead(cid, 'entity-preflight', async () => (await currentEffectiveTarget(this.kong, cid, upstreamId, address)).target,
      { paths: [path], workspaceId: actor.workspaceId, maxCalls: 100, maxPages: 100, maxRecords: 10_000, maxBytes: 32 * 1024 * 1024, timeoutMs: 120_000 });
  }
  private async ordinary(cid: string, operation: Exclude<EntityChangeOperation, { kind: 'recycle' }>, actor: EntityActor, draft: Draft): Promise<void> {
    let prepared: EntityMutationPreparation, nativeId: string, path: string, method: 'POST' | 'PATCH', body: Record<string, any>, originalNativeId: string | undefined;
    if (operation.kind === 'entity') {
      const generatedId = operation.action === 'create' ? randomUUID() : undefined;
      prepared = await this.entities.prepareCore(cid, operation.entityType, operation.action, operation.action === 'update' ? operation.entityId : undefined,
        { ...operation.body, ...(generatedId ? { id: generatedId } : {}) }, actor);
      nativeId = prepared.before?.id ?? generatedId!; body = { ...prepared.payload };
      path = operation.action === 'create' ? `/${operation.entityType}` : `/${operation.entityType}/${identifier(nativeId)}`;
      method = operation.action === 'create' ? 'POST' : 'PATCH';
      this.evidence(prepared, draft, `/${operation.entityType}/${identifier(nativeId)}`);
      if (operation.action === 'create') {
        await this.absent(cid, `/${operation.entityType}/${identifier(nativeId)}`, operation.entityType, actor, draft, nativeId);
        const name = operation.entityType === 'consumers' ? body.username : ['services', 'routes', 'snis', 'upstreams'].includes(operation.entityType) ? body.name : undefined;
        if (typeof name === 'string' && name) await this.absent(cid, `/${operation.entityType}/${identifier(name)}`, operation.entityType, actor, draft);
      } else {
        const field = operation.entityType === 'consumers' ? 'username' : ['services', 'routes', 'snis', 'upstreams'].includes(operation.entityType) ? 'name' : undefined;
        if (field && typeof body[field] === 'string' && body[field] !== prepared.before[field]) await this.absent(cid, `/${operation.entityType}/${identifier(body[field])}`, operation.entityType, actor, draft);
      }
    } else if (operation.kind === 'credential') {
      const generatedId = operation.action === 'create' ? randomUUID() : undefined;
      prepared = await this.entities.prepareCredential(cid, operation.consumerId, operation.credentialKind, operation.action,
        operation.action === 'update' ? operation.credentialId : undefined, { ...operation.body, ...(generatedId ? { id: generatedId } : {}) }, actor);
      nativeId = prepared.before?.id ?? generatedId!; body = { ...prepared.payload };
      const parentId = prepared.parent!.before.id, collection = `/consumers/${identifier(parentId)}/${operation.credentialKind}`;
      path = operation.action === 'create' ? collection : `${collection}/${identifier(nativeId)}`; method = operation.action === 'create' ? 'POST' : 'PATCH';
      this.evidence(prepared, draft, `${collection}/${identifier(nativeId)}`);
      if (operation.action === 'create') {
        await this.absent(cid, `${collection}/${identifier(nativeId)}`, operation.credentialKind, actor, draft, nativeId, parentId);
        const initial = await this.kong.prepareSchema(cid, path, body);
        this.generateCredentialDefaults(operation.credentialKind, body, initial.schemaMaterial.entity.schema);
      }
    } else {
      prepared = await this.entities.prepareTarget(cid, operation.upstreamId, operation.action === 'weight' ? 'update' : operation.action,
        operation.action === 'create' ? undefined : operation.targetId, operation.action === 'health' ? { state: operation.state } : operation.body, actor);
      const parentId = prepared.parent!.before.id, collection = `/upstreams/${identifier(parentId)}/targets`;
      originalNativeId = operation.action === 'weight' ? prepared.before.id : undefined;
      nativeId = operation.action === 'health' ? prepared.before.id : randomUUID(); body = { ...prepared.payload, ...(operation.action !== 'health' ? { id: nativeId } : {}) };
      path = operation.action === 'health' ? `${collection}/${identifier(nativeId)}/${operation.state}` : collection; method = 'POST';
      this.evidence(prepared, draft, `${collection}/${identifier(prepared.before?.id ?? nativeId)}`);
      if (operation.action !== 'health') await this.absent(cid, `${collection}/${identifier(nativeId)}`, 'targets', actor, draft, nativeId, parentId);
      const effective = await this.effectiveTarget(cid, parentId, prepared.before?.target ?? body.target, actor);
      if (prepared.before && effective?.id !== prepared.before.id) throw changed('ENTITY_CHANGE_TARGET_NOT_EFFECTIVE');
      if (effective && !prepared.before) draft.prerequisites.push({ type: 'targets', path: `${collection}/${identifier(effective.id)}`, nativeId: effective.id, parentId,
        before: effective, absent: false, fingerprint: this.secrets.fingerprint(effective), permissionAction: 'write' });
      draft.recovery.blockerCodes.push(operation.action === 'health' ? 'TARGET_HEALTH_OVERRIDE_ROLLBACK_UNAVAILABLE' : 'TARGET_RESTORE_APPENDS_HISTORY');
    }
    if (operation.kind === 'entity' && operation.entityType === 'plugins' && operation.action === 'create') {
      // Kong's oauth2 provision_key is generated by Lua on a normal create.
      // Freeze the same kind of secret in the exact approved payload instead
      // of approving an as-yet unknown value. Other auto fields stay explicit.
      body.config = body.config ?? {};
      const initial = await this.kong.prepareSchema(cid, path, body), plugin = initial.schemaMaterial.plugin;
      if (plugin) {
        const fields = schemaFields(plugin.schema);
        if (fields.provision_key?.auto === true && fields.provision_key.type === 'string' && !Object.hasOwn(body.config, 'provision_key')) body.config = { ...body.config, provision_key: randomBytes(32).toString('hex') };
      }
    }
    const snis = prepared.type === 'certificates' ? prepared.certificateSnis : undefined;
    if (snis) delete body.snis;
    const packet = this.packet(draft, { method, canonicalPath: path, nativeType: prepared.type, nativeId, parentId: prepared.parent?.before.id,
      ...(operation.kind === 'credential' ? { credentialKind: operation.credentialKind } : {}), dependencies: [],
      permissionAction: 'write', mutationAction: operation.kind === 'target' && operation.action === 'health' ? `mark_${operation.state}` : prepared.action === 'health' ? 'update' : prepared.action,
      ...(operation.kind === 'target' && operation.action === 'health' ? {} : { body }), before: prepared.before, ...(originalNativeId ? { originalNativeId } : {}) });
    await this.schema(cid, packet, draft);
    if (operation.kind === 'credential') {
      draft.metadataObligations.push({ kind: 'credential-remember', packetKey: packet.key, consumerId: prepared.parent!.before.id, credentialKind: operation.credentialKind, rawInput: body });
      if (prepared.before) draft.recovery.objects.push({ type: prepared.type, nativeId: prepared.before.id, parentId: prepared.parent!.before.id,
        ...await this.entities.prepareCredentialRecovery(cid, prepared.parent!.before.id, operation.credentialKind, prepared.before.id, actor) });
    } else if (operation.kind === 'entity') {
      draft.metadataObligations.push({ kind: 'entity-index', packetKey: packet.key, entityType: operation.entityType });
      if (prepared.before) { const restorePayload = { ...prepared.before }; delete restorePayload.created_at; delete restorePayload.updated_at; delete restorePayload.ttl; delete restorePayload.snis;
        draft.recovery.objects.push({ type: prepared.type, nativeId: prepared.before.id, restorePayload, blockerCodes: [] }); }
    }
    if (snis) for (const reference of snis) {
      const existing = reference.before, sniId = existing?.id ?? randomUUID(), name = existing?.name ?? decodeURIComponent(reference.path.slice('/snis/'.length));
      const tags = await this.workspaces.prepareCreate(cid, 'snis', { tags: existing?.tags ?? prepared.payload.tags }, actor.workspaceId);
      const sniBody = existing ? { certificate: { id: nativeId }, tags: tags.tags } : { id: sniId, name, certificate: { id: nativeId }, tags: tags.tags };
      await this.authz.assertEntity(actor.user, cid, 'snis', 'write', { ...existing, ...sniBody }, actor.workspaceId);
      if (!existing) await this.absent(cid, `/snis/${identifier(sniId)}`, 'snis', actor, draft, sniId);
      const sniPacket = this.packet(draft, { method: existing ? 'PATCH' : 'POST', canonicalPath: existing ? `/snis/${identifier(sniId)}` : '/snis', nativeType: 'snis', nativeId: sniId,
        dependencies: [packet.key], permissionAction: 'write', mutationAction: existing ? 'update' : 'create', body: sniBody, before: existing });
      await this.schema(cid, sniPacket, draft); draft.metadataObligations.push({ kind: 'entity-index', packetKey: sniPacket.key, entityType: 'snis' });
      if (existing) draft.recovery.objects.push({ type: 'snis', nativeId: sniId, restorePayload: existing, blockerCodes: [] });
    }
  }

  @KongActorScope({ module: 'workflows', action: 'write' })
  async prepare(cid: string, input: unknown, actor: EntityActor): Promise<PreparedEntityChange> {
    const policy = this.policy(), workspaceId = this.explicitWorkspace(actor), request = entityChangeInput(input), workspace = await this.workspaces.get(cid, workspaceId);
    if (workspace.status !== 'active') throw changed('WORKSPACE_DISABLED');
    const permissionVersion = await this.authz.permissionVersion(actor.user), transportScope = await this.kong.transportScope(cid);
    const draft: Draft = { prerequisites: [], schemas: [], packets: [], metadataObligations: [], recovery: { state: 'baseline-required', blockerCodes: ['EXECUTION_BASELINE_REQUIRED'], objects: [] } };
    const operations = request.kind === 'batch' ? request.operations : [request];
    for (const operation of operations) {
      if (operation.kind === 'recycle') {
        if (!policy.prepareRecycle || !policy.assertRecycleCurrent) throw unavailable();
        const prepared = await policy.prepareRecycle(cid, operation, actor);
        if (prepared.graph.complete !== true || prepared.graph.purpose === 'migration' || !prepared.graph.nodes.length) throw changed('ENTITY_CHANGE_RECYCLE_GRAPH_INVALID');
        // The Root-owned recycle preparer freezes exact packet IDs and order;
        // rekey only local DAG identifiers when combining independent graphs.
        const prefix = `graph-${draft.packets.length + 1}:`, keys = new Map(prepared.packets.map(packet => [packet.key, `${prefix}${packet.key}`]));
        for (const value of prepared.packets) { assertKongPath(value.method, value.canonicalPath); if (!UUID.test(value.nativeId) || value.dependencies.some(key => !keys.has(key))) throw changed('ENTITY_CHANGE_RECYCLE_GRAPH_INVALID');
          draft.packets.push({ ...value, key: keys.get(value.key)!, order: draft.packets.length + 1, dependencies: value.dependencies.map(key => keys.get(key)!), bodyHmac: this.secrets.fingerprint(value.body ?? null), beforeHmac: this.secrets.fingerprint(value.before) }); }
        draft.prerequisites.push(...prepared.prerequisites);
        draft.metadataObligations.push(...prepared.metadataObligations.map(obligation => 'packetKeys' in obligation ? { ...obligation, packetKeys: obligation.packetKeys.map(key => keys.get(key)!) } : { ...obligation, packetKey: keys.get(obligation.packetKey)! }));
        for (const packet of draft.packets.filter(packet => packet.key.startsWith(prefix))) {
          const schema = prepared.schemas.find(item => item.clusterId === cid && item.canonicalPath === packet.canonicalPath && item.payloadHmac === packet.bodyHmac);
          if (!schema) throw changed('ENTITY_CHANGE_RECYCLE_SCHEMA_REQUIRED'); draft.schemas.push(schema);
        }
      } else await this.ordinary(cid, operation, actor, draft);
      if (draft.packets.length > 1000 || Buffer.byteLength(JSON.stringify(draft)) > 16 * 1024 * 1024) throw new ConflictException({ code: 'ENTITY_CHANGE_PLAN_BUDGET' });
    }
    const schema = draft.schemas[0]; if (!schema) throw changed('ENTITY_CHANGE_EMPTY_PLAN');
    if (draft.schemas.some(item => item.clusterRevision !== schema.clusterRevision || item.kongVersion !== schema.kongVersion || item.adapter !== schema.adapter)) throw changed('ENTITY_CHANGE_CAPABILITIES_CHANGED');
    const seen = new Set<string>();
    for (const packet of draft.packets) { const identity = `${packet.nativeType}:${packet.parentId ?? ''}:${packet.originalNativeId ?? packet.nativeId}`;
      if (seen.has(identity)) throw new ConflictException({ code: 'ENTITY_CHANGE_DUPLICATE_OBJECT', message: '同一对象不能在一个批次中重复变更' }); seen.add(identity);
      const payload = packet.body as any, effective = { ...(packet.before as any), ...payload };
      const unique = packet.nativeType === 'targets' ? ['target', packet.parentId, effective.target]
        : packet.nativeType === 'plugins' ? ['plugin-binding', effective.name, entityReferenceId(effective.service) ?? null, entityReferenceId(effective.route) ?? null, entityReferenceId(effective.consumer) ?? null]
        : packet.nativeType === 'consumers' && typeof effective.username === 'string' ? ['consumer-name', effective.username]
        : ['services', 'routes', 'snis', 'upstreams'].includes(packet.nativeType) && typeof effective.name === 'string' ? [packet.nativeType, effective.name] : null;
      if (unique) { const uniqueKey = this.secrets.fingerprint(unique); if (seen.has(uniqueKey)) throw new ConflictException({ code: 'ENTITY_CHANGE_DUPLICATE_OBJECT', message: '同一名称、插件绑定或 Target 地址不能在一个批次中重复变更' }); seen.add(uniqueKey); }
      await policy.assertPacket({ clusterId: cid, workspaceId, transportScope, packet, actor, phase: 'prepare' }); }
    const prerequisiteMap = new Map<string, EntityChangePrerequisite>();
    for (const prerequisite of draft.prerequisites) { const prior = prerequisiteMap.get(prerequisite.path); if (prior && prior.fingerprint !== prerequisite.fingerprint) throw changed();
      prerequisiteMap.set(prerequisite.path, prior?.purpose === 'private-parent' && prerequisite.purpose !== 'private-parent' ? prerequisite
        : prior && prior.purpose !== 'private-parent' && prerequisite.purpose === 'private-parent' ? prior
        : prior?.permissionAction === 'write' || prior?.permissionAction === 'delete' ? prior : prerequisite); }
    draft.prerequisites = [...prerequisiteMap.values()].sort((left, right) => left.path.localeCompare(right.path));
    draft.recovery.blockerCodes = [...new Set(draft.recovery.blockerCodes)].sort();
    const impact = mergeImpact(...draft.packets.map(packet => deriveImpact({ entityType: packet.credentialKind ? 'credentials' : packet.nativeType,
      entityId: packet.originalNativeId ?? packet.nativeId, parentId: packet.parentId, credentialKind: packet.credentialKind, action: packet.mutationAction, before: packet.before, payload: packet.body })));
    const material = { version: 1 as const, clusterId: cid, workspaceId, requesterId: actor.user.id, permissionVersion,
      scope: { transportScope, clusterRevision: schema.clusterRevision, workspaceRevision: workspace.revision, kongVersion: schema.kongVersion, adapter: schema.adapter }, request, ...draft, impact };
    const sealed = immutableJson({ ...material, changeDigest: this.secrets.fingerprint(material) });
    await this.assertCurrent(sealed, actor, 'prepare'); return sealed;
  }
  private verifyMaterial(material: PreparedEntityChange): void {
    if (!material || material.version !== 1 || !Array.isArray(material.packets) || !material.packets.length || material.packets.length > 1000) throw changed('ENTITY_CHANGE_MATERIAL_INVALID');
    const { changeDigest, ...payload } = material;
    if (this.secrets.fingerprint(payload) !== changeDigest) throw changed('ENTITY_CHANGE_MATERIAL_INVALID');
  }
  async assertCurrent(material: PreparedEntityChange, actor: EntityActor, phase: 'prepare' | 'execute'): Promise<void> {
    const frozen = immutableJson(material);
    this.verifyMaterial(frozen);
    if (!['prepare', 'execute'].includes(phase)) throw changed('ENTITY_CHANGE_PHASE_INVALID');
    return this.execution.runActor({ actor: actor.user, clusterId: frozen.clusterId, workspaceId: actor.workspaceId, module: 'workflows', action: 'write', requestId: actor.requestId },
      () => this.verifyCurrent(frozen, actor, phase));
  }
  private async verifyCurrent(material: PreparedEntityChange, actor: EntityActor, phase: 'prepare' | 'execute', stored?: { action: StoredEntitySubjectAction; permissionVersion: string }): Promise<void> {
    this.verifyMaterial(material); const policy = this.policy(), wid = this.explicitWorkspace(actor);
    if (wid !== material.workspaceId) throw new ForbiddenException({ code: 'ENTITY_CHANGE_SCOPE_MISMATCH' });
    const workspace = await this.workspaces.get(material.clusterId, wid);
    if (workspace.status !== 'active' || workspace.revision !== material.scope.workspaceRevision || await this.kong.transportScope(material.clusterId) !== material.scope.transportScope) throw changed('ENTITY_CHANGE_SCOPE_CHANGED');
    if (!stored && actor.user.id === material.requesterId && await this.authz.permissionVersion(actor.user) !== material.permissionVersion) throw changed('ENTITY_CHANGE_PERMISSIONS_CHANGED');
    for (const prerequisite of material.prerequisites) {
      let current: any = null;
      try { current = await this.read(material.clusterId, prerequisite.path, actor); }
      catch (error) { if (!(error instanceof HttpException) || error.getStatus() !== 404 || !prerequisite.absent) throw error; }
      if (prerequisite.absent ? current !== null : current === null || this.secrets.fingerprint(current) !== prerequisite.fingerprint) throw changed();
      if (!stored && current && prerequisite.purpose === 'private-parent') {
        const children = material.packets.filter(packet => packet.parentId === prerequisite.nativeId && (prerequisite.type === 'consumers' ? !!packet.credentialKind : packet.nativeType === 'targets'));
        if (!children.length || !['consumers', 'upstreams'].includes(prerequisite.type)) throw changed('ENTITY_CHANGE_PRIVATE_PARENT_INVALID');
        for (const child of children) {
          const effective = normalizeEntityAuthorizationView(child.nativeType, { ...(child.before as any), ...child.body,
            id: child.originalNativeId ?? child.nativeId, [prerequisite.type === 'consumers' ? 'consumer' : 'upstream']: { id: prerequisite.nativeId } });
          await this.authz.assertNestedParentScope(actor.user, material.clusterId, prerequisite.type, current, child.nativeType, child.permissionAction, wid, effective);
        }
      } else if (!stored && current && !CREDENTIAL_KINDS.includes(prerequisite.type as any) && prerequisite.type !== 'targets') await this.authz.assertEntity(actor.user, material.clusterId, prerequisite.type, prerequisite.permissionAction, current, wid);
    }
    for (const packet of material.packets) {
      const recyclePacket = packet.mutationAction === 'delete' || packet.mutationAction === 'restore';
      const effective = { ...(packet.before as any), ...packet.body, ...(packet.parentId ? { [packet.nativeType === 'targets' ? 'upstream' : 'consumer']: { id: packet.parentId } } : {}) };
      // Keep the real before/after authorization rules used by direct changes.
      // Root's fixed subject policy verifies the complete sealed packet tuple.
      // Archived child authorization needs the complete genuine graph when a
      // Consumer/Upstream is currently absent; Root's fixed recycle verifier
      // checks it together with every fresh schema below. This is not a native
      // permit and cannot be selected by a user's ordinary change DTO.
      if (!recyclePacket) {
        if (!stored) {
          if (packet.before) await this.authz.assertEntity(actor.user, material.clusterId, packet.nativeType, packet.permissionAction, normalizeEntityAuthorizationView(packet.nativeType, packet.before), wid);
          await this.authz.assertEntity(actor.user, material.clusterId, packet.nativeType, packet.permissionAction,
            normalizeEntityAuthorizationView(packet.nativeType, { ...effective, ...(packet.originalNativeId ? { id: packet.originalNativeId } : {}) }), wid);
        }
        const schema = await this.kong.prepareSchema(material.clusterId, packet.canonicalPath, packet.body), frozen = material.schemas.find(item => item.canonicalPath === packet.canonicalPath && item.payloadHmac === packet.bodyHmac);
        if (!frozen || schema.clusterRevision !== material.scope.clusterRevision || schema.kongVersion !== material.scope.kongVersion || schema.adapter !== material.scope.adapter || this.secrets.fingerprint(schema) !== this.secrets.fingerprint(frozen)) throw changed('ENTITY_CHANGE_SCHEMA_CHANGED');
      } else if (!policy.assertRecycleCurrent) throw unavailable();
      if (!recyclePacket && packet.nativeType === 'targets') { const before = packet.before as any, address = before?.target ?? packet.body?.target;
        if (address) { const effectiveTarget = await this.effectiveTarget(material.clusterId, packet.parentId!, address, actor);
          const prior = material.prerequisites.find(item => item.type === 'targets' && !item.absent && item.parentId === packet.parentId && (item.before as any)?.target === address);
          if ((effectiveTarget?.id ?? null) !== (prior?.nativeId ?? null)) throw changed('ENTITY_CHANGE_TARGET_NOT_EFFECTIVE'); } }
      await policy.assertPacket({ clusterId: material.clusterId, workspaceId: wid, transportScope: material.scope.transportScope, packet, actor, phase: 'revalidate', ...(stored ? { action: stored.action } : {}) });
    }
    for (const operation of material.request.kind === 'batch' ? material.request.operations : [material.request]) if (operation.kind === 'recycle') {
      if (!policy.assertRecycleCurrent) throw unavailable(); await policy.assertRecycleCurrent(material.clusterId, operation, material, actor, { action: stored?.action ?? 'write', mode: 'fresh' }); }
    if ((stored || actor.user.id === material.requesterId) && await this.authz.permissionVersion(actor.user) !== (stored?.permissionVersion ?? material.permissionVersion)) throw changed('ENTITY_CHANGE_PERMISSIONS_CHANGED');
    if (phase === 'execute') throw new ConflictException({ code: 'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED', message: '此准备材料不是执行权限；需通过已验收的意图、审批与执行前快照链路' });
  }
  /** Long-lived intent validity belongs to the durable envelope. This method
   * proves fresh facts using the current real caller; it never renews an old
   * SID, reallocates a native UUID/secret, changes the material or mints a job. */
  async revalidateStored(material: PreparedEntityChange, actor: EntityActor, action: StoredEntitySubjectAction, phase: StoredEntityRevalidationPhase): Promise<void> {
    const frozen = immutableJson(material); this.verifyMaterial(frozen);
    if (!['read', 'write', 'approve'].includes(action) || !['review', 'submit', 'approve', 'claim'].includes(phase)
      || phase === 'review' && action !== 'read' || phase === 'submit' && action !== 'write' || phase === 'approve' && action !== 'approve' || phase === 'claim' && action !== 'write') throw changed('ENTITY_CHANGE_PHASE_INVALID');
    return this.withStoredSubject(frozen, actor, action, 'fresh', async permissionVersion => {
      await this.verifyCurrent(frozen, actor, 'prepare', { action, permissionVersion });
    });
  }
  /** Authorization only: immutable historical bytes stay readable under
   * current explicit read/approve grants after objects change or disappear. */
  async assertStoredScope(material: PreparedEntityChange, actor: EntityActor, action: StoredEntitySubjectAction): Promise<void> {
    const frozen = immutableJson(material); this.verifyMaterial(frozen);
    await this.withStoredSubject(frozen, actor, action, 'historical', async () => undefined);
  }
  private async withStoredSubject<T>(material: PreparedEntityChange, actor: EntityActor, action: StoredEntitySubjectAction, mode: 'historical' | 'fresh', fn: (permissionVersion: string) => Promise<T>): Promise<T> {
    if (!['read', 'write', 'approve'].includes(action) || this.explicitWorkspace(actor) !== material.workspaceId) throw new ForbiddenException({ code: 'ENTITY_CHANGE_SCOPE_MISMATCH' });
    const policy = this.policy(); if (!policy.assertStoredSubject) throw unavailable();
    return this.execution.runActor({ actor: actor.user, clusterId: material.clusterId, workspaceId: actor.workspaceId, module: 'workflows', action, requestId: actor.requestId }, async () => {
      const permissionVersion = await this.authz.permissionVersion(actor.user);
      await policy.assertStoredSubject!({ material, actor, action, mode });
      const result = await fn(permissionVersion);
      await policy.assertStoredSubject!({ material, actor, action, mode });
      if (await this.authz.permissionVersion(actor.user) !== permissionVersion) throw changed('ENTITY_CHANGE_PERMISSIONS_CHANGED');
      return result;
    });
  }
  /** Read-only facts projection, not pre-send validation. It calls no Kong
   * endpoint and never returns a private graph, schema, credential or permit. */
  async projectStored(material: PreparedEntityChange, actor: EntityActor, action: 'read' | 'approve'): Promise<EntityChangeReview> {
    const frozen = immutableJson(material); this.verifyMaterial(frozen);
    return this.withStoredSubject(frozen, actor, action, 'historical', async () => this.safeProjection(frozen));
  }
  private safeProjection(material: PreparedEntityChange): EntityChangeReview {
    return immutableJson({ version: 1 as const, clusterId: material.clusterId, workspaceId: material.workspaceId, changeDigest: material.changeDigest,
      changes: material.packets.map(packet => ({ entityType: packet.nativeType, nativeId: packet.nativeId, ...(packet.originalNativeId ? { originalNativeId: packet.originalNativeId } : {}),
        action: packet.mutationAction, before: this.secrets.redact(packet.before), after: this.secrets.redact(packet.body ?? null) })),
      impact: { changedObjects: material.packets.length, nativePackets: material.packets.length, traffic: null, trafficAvailability: 'unavailable' as const,
        globalPlugin: material.packets.some(packet => packet.nativeType === 'plugins' && !['service', 'route', 'consumer'].some(field => entityReferenceId({ ...(packet.before as any), ...packet.body }[field]))) },
      recovery: { state: material.recovery.state, blockerCodes: material.recovery.blockerCodes } });
  }
  /** Public review does not return transport paths, schemas or private graphs. */
  async project(material: PreparedEntityChange, actor: EntityActor): Promise<EntityChangeReview> {
    material = immutableJson(material);
    await this.assertCurrent(material, actor, 'prepare');
    return this.safeProjection(material);
  }
}
