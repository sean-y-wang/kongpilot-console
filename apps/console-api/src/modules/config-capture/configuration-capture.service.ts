import { isSupportedKong } from '../../infrastructure/kong/kong-capabilities';
import { ConflictException, ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { isIP } from 'node:net';
import { KongService } from '../../infrastructure/kong/kong.service';
import { readCursor } from '../../infrastructure/kong/cursor';
import { GLOBAL_CREDENTIAL_PATHS } from '../../infrastructure/kong/policy';
import { stripSensitiveSchemaDefaults } from '../../infrastructure/kong/schema-secrets';
import { SecretService, canonicalJson } from '../../infrastructure/secret.service';
import { WorkspaceResolverService, WorkspaceFilter } from '../workspaces/workspace-resolver.service';
import { CREDENTIAL_SCHEMAS } from '../entities/entities.types';
import {
  CONFIGURATION_ACCESS, CONFIGURATION_CAPTURE_REPOSITORY,
  ConfigurationAccessHandle, ConfigurationAccessPolicy, ConfigurationCaptureRepository,
  ConfigurationScope, ConfigurationEntityType, ConfigurationCredentialKind,
  CaptureFence, CaptureGraph, CaptureObject, CaptureCollection, CaptureStage,
  CaptureReadBudget, CapturedSchemaBundle, SnapshotSummary,
} from '../configuration/configuration.types';
import { CAPTURE_LIMITS, CaptureBudget, CORE_COLLECTIONS, CREDENTIAL_COLLECTIONS, captureJson,
  captureLimit, foreignUuid, invalidCapture, nativeUuid, schemaFields, validateCapturedSchema } from './capture-validation';

const KEY_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;
export interface ConfigurationCaptureOptions {requiredPluginSchemas?:readonly string[];}
const clone = <T>(value: T): T => structuredClone(value);
const entityKey = (type: ConfigurationEntityType, id: string, parentId?: string, kind?: ConfigurationCredentialKind): string =>
  type === 'credentials' ? `credentials:${kind}:${parentId}:${id}` : type === 'targets' ? `targets:${parentId}:${id}` : `${type}:${id}`;

/** Only a current Root-owned capability can reach raw Kong configuration. */
@Injectable()
export class ConfigurationCaptureService {
  constructor(
    private readonly kong: KongService,
    private readonly secrets: SecretService,
    private readonly workspaces: WorkspaceResolverService,
    @Inject(CONFIGURATION_ACCESS) private readonly access: ConfigurationAccessPolicy,
    @Inject(CONFIGURATION_CAPTURE_REPOSITORY) private readonly repository: ConfigurationCaptureRepository,
  ) {}

  async capture(handle: ConfigurationAccessHandle, stage: CaptureStage, scope: ConfigurationScope, options:ConfigurationCaptureOptions={}): Promise<SnapshotSummary> {
    const names=options.requiredPluginSchemas??[];
    if(!Array.isArray(names)||names.length>10000||names.some(name=>typeof name!=='string'||!KEY_PATTERN.test(name))||new Set(names).size>200||Object.keys(options).some(key=>key!=='requiredPluginSchemas'))invalidCapture('CONFIGURATION_CAPTURE_SCHEMA_REQUIREMENTS_INVALID');
    for (const id of [stage.jobId, stage.snapshotId, stage.versionId, stage.materialId, scope.clusterId, scope.workspaceId]) nativeUuid(id);
    if (!Number.isInteger(stage.leaseGeneration) || stage.leaseGeneration < 1 || !/^[a-f\d]{64}$/.test(scope.transportScope)
      || !['cluster', 'workspace', 'services'].includes(scope.kind) || !Array.isArray(scope.rootIds)
      || scope.rootIds.length > 100 || scope.kind === 'services' && !scope.rootIds.length
      || scope.kind !== 'services' && scope.rootIds.length || new Set(scope.rootIds).size !== scope.rootIds.length) invalidCapture('CONFIGURATION_INVALID_CAPTURE_BINDING');
    for (const id of scope.rootIds) nativeUuid(id);
    const runner = new CaptureRunner(this.kong, this.secrets, this.workspaces, this.access, this.repository, handle, clone(stage), clone(scope),Object.freeze([...new Set(names)].sort()));
    // Empty paths selects Root's narrow, fixed configuration read whitelist;
    // it never grants arbitrary Kong, HTTP or native-write access.
    return this.access.runRead(handle, [], usage => runner.run(usage));
  }
}

class CaptureRunner {
  private readonly budget = new CaptureBudget();
  private readonly objects = new Map<string, CaptureObject>();
  private readonly collections: CaptureCollection[] = [];
  private readonly requiredCollections = new Set<string>();
  private readonly entitySchemas: Record<string, unknown> = Object.create(null);
  private readonly pluginSchemas: Record<string, unknown> = Object.create(null);
  private readonly rawSchemas: Record<string, unknown> = Object.create(null);
  private readonly warnings = new Set<string>();
  private readonly nativeParents = new Map<string, string>();
  private firstFence!: CaptureFence;
  private workspaceFilter!: WorkspaceFilter;
  private usage!: () => CaptureReadBudget;
  private rootIdentity!: { version: string; nodeId?: string };
  private readonly observedFrom = new Date().toISOString();

  constructor(private readonly kong: KongService, private readonly secrets: SecretService,
    private readonly workspaces: WorkspaceResolverService, private readonly access: ConfigurationAccessPolicy,
    private readonly repository: ConfigurationCaptureRepository, private readonly handle: ConfigurationAccessHandle,
    private readonly stage: CaptureStage, private readonly scope: ConfigurationScope,private readonly requiredPluginSchemas:readonly string[]) {}

  private assertBudget(): CaptureReadBudget {
    this.budget.check();
    const usage = this.usage();
    if (!usage || ![usage.calls, usage.pages, usage.records, usage.bytes, usage.startedAt].every(Number.isFinite)
      || [usage.calls, usage.pages, usage.records, usage.bytes].some(value => !Number.isInteger(value) || value < 0)) invalidCapture('CONFIGURATION_READ_METER_INVALID');
    if (usage.calls > CAPTURE_LIMITS.calls || usage.pages > CAPTURE_LIMITS.pages || usage.records > CAPTURE_LIMITS.records
      || usage.bytes > CAPTURE_LIMITS.bytes || Date.now() - usage.startedAt >= CAPTURE_LIMITS.timeoutMs) captureLimit();
    return usage;
  }

  private async current(phase: 'capture-page' | 'seal' | 'read' = 'capture-page'): Promise<CaptureFence> {
    this.assertBudget();
    const fence = await this.access.assertCurrent(this.handle, { phase, jobId: this.stage.jobId, scope: this.scope });
    if (!isSupportedKong(fence.kongVersion) || canonicalJson(fence.scope) !== canonicalJson(this.scope)
      || fence.jobId !== undefined && fence.jobId !== this.stage.jobId
      || fence.leaseGeneration !== undefined && fence.leaseGeneration !== this.stage.leaseGeneration) invalidCapture('CONFIGURATION_CAPTURE_SCOPE_CHANGED');
    if (this.firstFence) {
      const identity = (value: CaptureFence) => ({ actorId: value.actorId, permissionVersion: value.permissionVersion,
        credentialEpoch: value.credentialEpoch, clusterRevision: value.clusterRevision, workspaceRevision: value.workspaceRevision,
        captureEpoch: value.captureEpoch, kongVersion: value.kongVersion, nodeId: value.nodeId ?? null,
        adapterVersion: value.adapterVersion, enabledPlugins: [...value.enabledPlugins].sort() });
      if (canonicalJson(identity(fence)) !== canonicalJson(identity(this.firstFence))) throw new ConflictException({ code: 'CONFIGURATION_CAPTURE_CHANGED', message: '捕获期间权限、连接、版本或配置栅栏发生变化，快照未发布' });
    }
    this.assertBudget();
    return fence;
  }

  private async get(path: string): Promise<any> {
    await this.current(); this.budget.request();
    const value = await this.kong.request<any>(this.scope.clusterId, 'GET', path);
    this.budget.response(value); await this.current(); return value;
  }

  private root(value: any): { version: string; nodeId?: string } {
    if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.version !== 'string'
      || !isSupportedKong(value.version) || value.version !== this.firstFence.kongVersion) invalidCapture('CONFIGURATION_KONG_VERSION_CHANGED');
    const nodeId = value.node_id === undefined || value.node_id === null ? undefined : nativeUuid(value.node_id);
    if (this.firstFence.nodeId !== undefined && nodeId !== this.firstFence.nodeId) invalidCapture('CONFIGURATION_KONG_NODE_CHANGED');
    return { version: value.version, ...(nodeId ? { nodeId } : {}) };
  }

  async run(usage: () => CaptureReadBudget): Promise<SnapshotSummary> {
    this.usage = usage;
    this.firstFence = clone(await this.current('read'));
    this.workspaceFilter = await this.workspaces.listScope(this.scope.clusterId, this.scope.workspaceId);
    if (this.workspaceFilter.workspaceRevision !== this.firstFence.workspaceRevision) invalidCapture('CONFIGURATION_WORKSPACE_CHANGED');
    this.rootIdentity = this.root(await this.get('/'));
    for (const type of [...CORE_COLLECTIONS, 'targets', ...Object.values(CREDENTIAL_SCHEMAS)]) await this.schema(type);
    if(this.requiredPluginSchemas.length){await this.actualEnabledPlugins();for(const name of this.requiredPluginSchemas)await this.pluginSchema(name);}
    // Order makes Service-root predicates depend only on already captured rows.
    for (const type of ['services', 'routes', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis', 'consumers'] as const) {
      const query = { size: 100, ...(this.scope.kind !== 'cluster' && this.workspaceFilter.nativeTags ? { tags: this.workspaceFilter.nativeTags } : {}) };
      await this.collection(type, `/${type}`, type, query, async raw => {
        if (!this.inScope(type, raw)) return false;
        await this.add(type, raw, false); return true;
      });
    }
    if (this.scope.kind === 'services' && this.scope.rootIds.some(id => !this.objects.has(`services:${id}`))) invalidCapture('CONFIGURATION_SERVICE_ROOT_MISSING');
    // Capture parents/references before credentials and targets. Reference rows
    // do not recursively widen the affected scope or emit their own child sets.
    await this.closeReferences();
    // Credentials: Kong 1.5 global paged collections cost ceil(n/100) pages per kind instead of
    // one page per Consumer and kind. Fall back to per-Consumer lists when the actor/context is
    // not allowed to read a global collection (403 before anything is staged).
    const capturedConsumers = new Map([...this.objects.values()].filter(object => !object.referenceOnly && object.entityType === 'consumers').map(object => [object.nativeId, object]));
    const globalCredentials = capturedConsumers.size > 1 && await this.globalCredentials(capturedConsumers);
    for (const parent of [...this.objects.values()]) {
      if (parent.referenceOnly) continue;
      if (parent.entityType === 'consumers' && !globalCredentials) {
        for (const kind of CREDENTIAL_COLLECTIONS) await this.collection(`credentials:${kind}:${parent.nativeId}`,
          `/consumers/${parent.nativeId}/${kind}`, 'credentials', { size: 100 }, async raw => {
            await this.add('credentials', raw, false, parent, kind); return true;
          }, parent, kind);
      } else if (parent.entityType === 'upstreams') await this.targets(parent);
    }
    this.assertDag();
    // Transfer plans bind every object to the complete captured schema bundle,
    // including plugin and child schemas discovered while closing references.
    // Freeze this after collection EOF and before staging immutable objects.
    const schemas = this.schemaBundle();
    for (const node of this.objects.values()) {
      node.schemaHmac = schemas.schemaHmac;
      await this.current();
      await this.repository.stageObject(this.handle, { jobId: this.stage.jobId, object: node, leaseGeneration: this.stage.leaseGeneration });
    }
    // Re-read actual roots and reference configuration, never use current tags
    // to rewrite the recorded historical ownership.
    for (const node of this.objects.values()) if (node.referenceOnly || this.scope.kind === 'services' && node.entityType === 'services' && this.scope.rootIds.includes(node.nativeId)) {
      const fresh = captureJson(await this.get(`/${node.entityType}/${node.nativeId}`));
      if (this.secrets.fingerprint(fresh) !== node.beforeHmac) invalidCapture('CONFIGURATION_REFERENCE_CHANGED');
    }
    if (canonicalJson(this.root(await this.get('/'))) !== canonicalJson(this.rootIdentity)) invalidCapture('CONFIGURATION_KONG_NODE_CHANGED');
    if(this.requiredPluginSchemas.length)await this.actualEnabledPlugins();
    await this.current('seal');
    const meter = this.assertBudget();
    const graph: CaptureGraph = {
      scope: clone(this.scope), objects: [...this.objects.values()].map(clone), collections: this.collections.map(clone),
      completeness: 'complete', consistency: 'console_fenced_best_effort', kongVersion: this.firstFence.kongVersion,
      adapterVersion: this.firstFence.adapterVersion, schemaHmac: schemas.schemaHmac, permissionVersion: this.firstFence.permissionVersion,
      captureEpoch: this.firstFence.captureEpoch, observedFrom: this.observedFrom, observedUntil: new Date().toISOString(),
      pageCount: Math.max(meter.pages, this.budget.pages), recordCount: Math.max(meter.records, this.budget.records),
      byteCount: Math.max(meter.bytes, this.budget.bytes), nativeCallCount: Math.max(meter.calls, this.budget.calls), warningCodes: [...this.warnings].sort(),
      requiredCollections: [...this.requiredCollections].sort(), schemas, credentialEpoch: this.firstFence.credentialEpoch,
      clusterRevision: this.firstFence.clusterRevision, workspaceRevision: this.firstFence.workspaceRevision,
      ...(this.rootIdentity.nodeId ? { nodeId: this.rootIdentity.nodeId } : {}), ...this.stage,
    };
    if (Buffer.byteLength(canonicalJson(graph), 'utf8') > CAPTURE_LIMITS.bytes) captureLimit();
    // Repository repeats current authority/lease/physical epoch in its short
    // seal transaction under the shared physical native-send fence.
    return this.repository.sealSnapshot(this.handle, { jobId: this.stage.jobId, graph, leaseGeneration: this.stage.leaseGeneration });
  }

  private async schema(name: string): Promise<unknown> {
    if (Object.hasOwn(this.rawSchemas, name)) return this.rawSchemas[name];
    const schema = await this.get(`/schemas/${name}`); schemaFields(schema);
    this.rawSchemas[name] = schema;
    this.entitySchemas[name] = stripSensitiveSchemaDefaults(schema, this.secrets);
    return schema;
  }
  private async pluginSchema(name: string): Promise<unknown> {
    if (!KEY_PATTERN.test(name) || !this.firstFence.enabledPlugins.includes(name)) invalidCapture('CONFIGURATION_PLUGIN_CAPABILITY_MISSING');
    if (Object.hasOwn(this.pluginSchemas, name)) return this.pluginSchemas[name];
    const schema = await this.get(`/plugins/schema/${name}`); schemaFields(schema);
    this.pluginSchemas[name] = stripSensitiveSchemaDefaults(schema, this.secrets); return schema;
  }
  private async actualEnabledPlugins():Promise<void>{
    const value=await this.get('/plugins/enabled'),names=value?.enabled_plugins;
    if(!Array.isArray(names)||names.length>200||names.some(name=>typeof name!=='string'||!KEY_PATTERN.test(name))||new Set(names).size!==names.length||canonicalJson([...names].sort())!==canonicalJson([...this.firstFence.enabledPlugins].sort()))invalidCapture('CONFIGURATION_KONG_ENABLED_PLUGINS_CHANGED');
  }
  private schemaBundle(): CapturedSchemaBundle {
    const bundle = { entities: clone(this.entitySchemas), plugins: clone(this.pluginSchemas), enabledPlugins: [...this.firstFence.enabledPlugins].sort(),
      kongVersion: this.firstFence.kongVersion, adapterVersion: this.firstFence.adapterVersion };
    return { ...bundle, schemaHmac: this.secrets.fingerprint(bundle) };
  }

  private inScope(type: typeof CORE_COLLECTIONS[number], raw: Record<string, unknown>): boolean {
    if (this.scope.kind !== 'cluster' && !this.workspaces.matches(this.workspaceFilter, raw)) {
      if (Array.isArray(raw.tags) && (raw.tags as unknown[]).filter(tag => typeof tag === 'string' && tag.startsWith('kos-ws-')).length > 1) invalidCapture('CONFIGURATION_AMBIGUOUS_WORKSPACE');
      return false;
    }
    if (this.scope.kind !== 'services') return true;
    const present = (entity: string, id: string | null) => id !== null && this.objects.has(`${entity}:${id}`);
    if (type === 'services') return this.scope.rootIds.includes(nativeUuid(raw.id));
    if (type === 'routes') return this.scope.rootIds.includes(foreignUuid(raw.service) ?? '');
    if (type === 'plugins') return this.scope.rootIds.includes(foreignUuid(raw.service) ?? '') || present('routes', foreignUuid(raw.route));
    if (type === 'upstreams') return [...this.objects.values()].some(node => node.entityType === 'services' && node.payload.host === raw.name);
    if (type === 'certificates') return [...this.objects.values()].some(node => node.entityType === 'services' && foreignUuid(node.payload.client_certificate) === raw.id);
    if (type === 'ca_certificates') return [...this.objects.values()].some(node => node.entityType === 'services' && Array.isArray(node.payload.ca_certificates) && node.payload.ca_certificates.some(id => id === raw.id));
    if (type === 'snis') return present('certificates', foreignUuid(raw.certificate));
    return [...this.objects.values()].some(node => node.entityType === 'plugins' && foreignUuid(node.payload.consumer) === raw.id);
  }

  /** Returns false only when the first global collection is denied before any page was staged. */
  private async globalCredentials(consumers: ReadonlyMap<string, CaptureObject>): Promise<boolean> {
    let first = true;
    for (const kind of CREDENTIAL_COLLECTIONS) {
      const key = `credentials:${kind}`;
      try {
        await this.collection(key, GLOBAL_CREDENTIAL_PATHS[kind], 'credentials', { size: 100 }, async raw => {
          const parent = consumers.get(foreignUuid(raw.consumer) ?? '');
          if (!parent) return false; // another scope's Consumer: never staged
          await this.add('credentials', raw, false, parent, kind); return true;
        }, undefined, kind);
      } catch (error) {
        if (first && error instanceof ForbiddenException && !this.collections.some(collection => collection.collectionKey === key)) {
          this.requiredCollections.delete(key); return false;
        }
        throw error;
      }
      first = false;
    }
    return true;
  }

  private async collection(key: string, path: string, type: ConfigurationEntityType, query: Record<string, string | number>,
    accept: (record: Record<string, unknown>) => Promise<boolean>, parent?: CaptureObject, kind?: ConfigurationCredentialKind): Promise<CaptureCollection> {
    this.requiredCollections.add(key);
    if (this.collections.some(collection => collection.collectionKey === key)) invalidCapture('CONFIGURATION_DUPLICATE_COLLECTION');
    const subject = this.secrets.fingerprint({ jobId: this.stage.jobId, actorId: this.firstFence.actorId, permissionVersion: this.firstFence.permissionVersion,
      scope: this.scope, parentId: parent?.nativeId ?? null, kind: kind ?? null, key, query });
    const queryHmac = this.secrets.fingerprint({ path, query, subject });
    const seenPositions = new Set<string>(), seenIds = new Set<string>();
    const cursorChain: string[] = [], coverage: string[] = [];
    let cursor: string | undefined, pages = 0, records = 0;
    do {
      await this.current(); this.budget.request(true);
      const page = await this.kong.list(this.scope.clusterId, path, query, cursor, subject);
      if (!Array.isArray(page?.items) || page.items.length > 100 || page.size !== 100 || page.console_permission_projection
        || page.nextCursor !== null && (typeof page.nextCursor !== 'string' || !page.nextCursor)) invalidCapture('CONFIGURATION_NATIVE_PAGE_INVALID');
      const bytes = this.budget.response(page.items, page.items.length);
      const persisted: Record<string, unknown>[] = [];
      for (const entry of page.items) {
        const raw = captureJson(entry), id = nativeUuid(raw.id);
        if (seenIds.has(id)) invalidCapture('CONFIGURATION_DUPLICATE_NATIVE_ID');
        seenIds.add(id);
        if (parent) {
          const actual = foreignUuid(raw[type === 'targets' ? 'upstream' : 'consumer']);
          if (actual !== parent.nativeId) invalidCapture('CONFIGURATION_NATIVE_PARENT_MISMATCH');
          const typedIdentity = `${type}:${kind ?? ''}:${id}`, previous = this.nativeParents.get(typedIdentity);
          if (previous !== undefined && previous !== parent.nativeId) invalidCapture('CONFIGURATION_NATIVE_PARENT_MISMATCH');
          this.nativeParents.set(typedIdentity, parent.nativeId);
        } else if (type === 'credentials' || type === 'targets') {
          // Global credential collection: every row must carry a real parent reference.
          const actual = foreignUuid(raw[type === 'targets' ? 'upstream' : 'consumer']);
          if (!actual) invalidCapture('CONFIGURATION_NATIVE_PARENT_MISMATCH');
          const typedIdentity = `${type}:${kind ?? ''}:${id}`, previous = this.nativeParents.get(typedIdentity);
          if (previous !== undefined && previous !== actual) invalidCapture('CONFIGURATION_NATIVE_PARENT_MISMATCH');
          this.nativeParents.set(typedIdentity, actual!);
        }
        if (await accept(raw)) { persisted.push(raw); coverage.push(this.secrets.fingerprint(raw)); records++; }
      }
      await this.current();
      const cursorHmac = this.secrets.fingerprint(cursor ?? null);
      if (page.nextCursor) {
        // KongService emits a newly timestamped signed token each time. Compare
        // its verified native offset so a repeated offset cannot hide in a new signature.
        const position = this.secrets.fingerprint(readCursor(page.nextCursor, this.scope.clusterId, path, query, subject));
        if (seenPositions.has(position)) invalidCapture('CONFIGURATION_PAGINATION_LOOP');
        seenPositions.add(position); cursorChain.push(position);
      }
      pages++;
      await this.repository.stagePage(this.handle, { jobId: this.stage.jobId, collectionKey: key, pageNo: pages, queryHmac,
        cursorHmac, nextCursor: page.nextCursor, records: persisted, terminalObserved: page.nextCursor === null, byteCount: bytes,
        leaseGeneration: this.stage.leaseGeneration });
      cursor = page.nextCursor ?? undefined;
    } while (cursor);
    const collection: CaptureCollection = { collectionKey: key, entityType: type, ...(parent ? { parentId: parent.nativeId } : {}),
      ...(kind ? { credentialKind: kind } : {}), queryHmac, pageSize: 100, pageCount: pages, recordCount: records,
      terminalObserved: true, cursorChainHmac: this.secrets.fingerprint(cursorChain), coverageHmac: this.secrets.fingerprint(coverage) };
    await this.current();
    await this.repository.collectionEOF(this.handle, { jobId: this.stage.jobId, collection, leaseGeneration: this.stage.leaseGeneration });
    this.collections.push(collection); return collection;
  }

  private async add(type: ConfigurationEntityType, raw: Record<string, unknown>, referenceOnly: boolean, parent?: CaptureObject,
    kind?: ConfigurationCredentialKind): Promise<CaptureObject> {
    const id = nativeUuid(raw.id), key = entityKey(type, id, parent?.nativeId, kind);
    if (this.objects.has(key)) invalidCapture('CONFIGURATION_DUPLICATE_NATIVE_ID');
    if (type === 'credentials' && (!parent || parent.entityType !== 'consumers' || !kind)
      || type === 'targets' && (!parent || parent.entityType !== 'upstreams')) invalidCapture('CONFIGURATION_NATIVE_PARENT_MISMATCH');
    const schemaName = type === 'credentials' ? CREDENTIAL_SCHEMAS[kind!] : type;
    const schema = await this.schema(schemaName);
    const plugin = type === 'plugins' ? await this.pluginSchema(String(raw.name)) : undefined;
    validateCapturedSchema(raw, schema, plugin, type);
    const ownership = await this.access.resolveOwnership(this.handle, { entityType: type, nativeId: id, payload: raw,
      parent, parentId: parent?.nativeId, credentialKind: kind, referenceOnly });
    if (this.scope.kind !== 'cluster' && !referenceOnly && ownership.workspaceId !== this.scope.workspaceId) invalidCapture('CONFIGURATION_CAPTURE_SCOPE_CHANGED');
    const observedAt = new Date().toISOString();
    // A DAO TTL is a remaining duration, not proof of an absolute expiration.
    // Stop before asking the existing helper to strip it or read remembered
    // plaintext. Capturing the original encrypted evidence remains permitted.
    if (raw.ttl !== undefined && raw.ttl !== null && (!Number.isFinite(raw.ttl) || typeof raw.ttl !== 'number' || raw.ttl < 0)) invalidCapture('CONFIGURATION_INVALID_TTL');
    const recovery = raw.ttl !== undefined && raw.ttl !== null
      ? { state: 'nonrestorable' as const, blockerCodes: ['NATIVE_TTL_EXPIRY_UNKNOWN'], absoluteExpiresAt: null }
      : clone(await this.access.freezeRecovery(this.handle, { entityType: type, nativeId: id, payload: raw,
        parentId: parent?.nativeId, credentialKind: kind, observedAt }));
    if (recovery.absoluteExpiresAt !== undefined && recovery.absoluteExpiresAt !== null
      && (!Number.isFinite(Date.parse(recovery.absoluteExpiresAt)) || Date.parse(recovery.absoluteExpiresAt) <= Date.now())) {
      recovery.state = 'nonrestorable'; recovery.blockerCodes = [...new Set([...recovery.blockerCodes, 'NATIVE_TTL_EXPIRED'])];
    }
    if (type === 'credentials' && kind === 'basic-auth' && recovery.state === 'complete'
      && (typeof recovery.restorePayload?.password !== 'string' || !recovery.sourceHashHmac)) invalidCapture('CONFIGURATION_BASIC_RECOVERY_UNPROVEN');
    const dependencies = this.dependencyKeys(type, raw, parent);
    const node: CaptureObject = { objectKey: key, entityType: type, nativeId: id,
      ...(parent ? { parentType: parent.entityType, parentId: parent.nativeId } : {}), ...(kind ? { credentialKind: kind } : {}),
      objectWorkspaceId: ownership.workspaceId, workspaceRevision: ownership.workspaceRevision,
      ownershipTags: [...ownership.physicalTags], affected: !referenceOnly, referenceOnly, dependencies,
      payload: clone(raw), beforeHmac: this.secrets.fingerprint(raw), schemaHmac: this.secrets.fingerprint(schema), observedAt,
      recovery: clone(recovery), managedBoundary: ownership.managedBoundary ?? 'none',
      ...(type === 'credentials' && recovery.state === 'complete' && recovery.restorePayload ? { secretCopies: [{ kind: kind!, consumerId: parent!.nativeId,
        nativeId: id, restorePayload: clone(recovery.restorePayload), verifiedAt: observedAt,
        ...(recovery.sourceCredentialRefId ? { sourceCredentialRefId: recovery.sourceCredentialRefId } : {}),
        ...(recovery.sourceHashHmac ? { sourceHashHmac: recovery.sourceHashHmac } : {}) }] } : {}),
    };
    this.budget.object(); this.objects.set(key, node);
    for (const blocker of recovery.blockerCodes) this.warnings.add(blocker);
    await this.current();
    return node;
  }

  private dependencyKeys(type: ConfigurationEntityType, raw: Record<string, unknown>, parent?: CaptureObject): string[] {
    const dependencies = new Set<string>();
    if (parent) dependencies.add(parent.objectKey);
    const foreign = (field: string, entity: ConfigurationEntityType) => { const id = foreignUuid(raw[field]); if (id) dependencies.add(`${entity}:${id}`); };
    if (type === 'services') {
      foreign('client_certificate', 'certificates');
      if (raw.ca_certificates !== undefined && raw.ca_certificates !== null) {
        if (!Array.isArray(raw.ca_certificates)) invalidCapture();
        for (const id of raw.ca_certificates) dependencies.add(`ca_certificates:${nativeUuid(id)}`);
      }
      for (const node of this.objects.values()) if (node.entityType === 'upstreams' && node.payload.name === raw.host) dependencies.add(node.objectKey);
    }
    if (type === 'routes') foreign('service', 'services');
    if (type === 'snis') foreign('certificate', 'certificates');
    if (type === 'plugins') { foreign('service', 'services'); foreign('route', 'routes'); foreign('consumer', 'consumers'); }
    return [...dependencies].sort();
  }

  private async closeReferences(): Promise<void> {
    const queue = [...this.objects.values()];
    for (let index = 0; index < queue.length; index++) {
      const node = queue[index];
      if (node.entityType === 'services' && typeof node.payload.host === 'string') {
        const known = [...this.objects.values()].find(candidate => candidate.entityType === 'upstreams' && candidate.payload.name === node.payload.host);
        if (known) node.dependencies = [...new Set([...node.dependencies, known.objectKey])].sort();
        else if (!isIP(node.payload.host) && /^[a-zA-Z\d._-]{1,253}$/.test(node.payload.host)) {
          try {
            const raw = captureJson(await this.get(`/upstreams/${encodeURIComponent(node.payload.host)}`));
            if (raw.name !== node.payload.host) invalidCapture('CONFIGURATION_REFERENCE_CHANGED');
            const reference = await this.add('upstreams', raw, true); queue.push(reference);
            node.dependencies = [...new Set([...node.dependencies, reference.objectKey])].sort();
          } catch (error) {
            if (!(error instanceof Error) || !('getStatus' in error) || typeof error.getStatus !== 'function' || error.getStatus() !== 404) throw error;
          }
        }
      }
      for (const dependency of node.dependencies) {
        if (this.objects.has(dependency)) continue;
        const [type, id, extra] = dependency.split(':');
        if (extra || !CORE_COLLECTIONS.includes(type as any)) invalidCapture('CONFIGURATION_INVALID_DEPENDENCY');
        const raw = captureJson(await this.get(`/${type}/${nativeUuid(id)}`));
        if (nativeUuid(raw.id) !== id) invalidCapture('CONFIGURATION_REFERENCE_CHANGED');
        queue.push(await this.add(type as ConfigurationEntityType, raw, true));
      }
      // Edges discovered after an initial stage are stored only in the sealed
      // authoritative graph; repositories compare every staged payload by HMAC.
    }
  }

  private async targets(parent: CaptureObject): Promise<void> {
    const historical = new Map<string, Record<string, unknown>>();
    await this.collection(`targets-history:${parent.nativeId}`, `/upstreams/${parent.nativeId}/targets/all`, 'targets', { size: 100 }, async raw => {
      validateCapturedSchema(raw, this.rawSchemas.targets);
      await this.access.resolveOwnership(this.handle, { entityType: 'targets', nativeId: nativeUuid(raw.id), payload: raw,
        parent, parentId: parent.nativeId, referenceOnly: true });
      historical.set(nativeUuid(raw.id), raw); return true;
    }, parent);
    const active = new Map<string, string>(), addresses = new Set<string>();
    await this.collection(`targets:${parent.nativeId}`, `/upstreams/${parent.nativeId}/targets`, 'targets', { size: 100 }, async raw => {
      if (typeof raw.target !== 'string' || !raw.target || !Number.isInteger(raw.weight) || (raw.weight as number) <= 0 || (raw.weight as number) > 1000 || addresses.has(raw.target)) invalidCapture('CONFIGURATION_EFFECTIVE_TARGET_INVALID');
      const history = historical.get(nativeUuid(raw.id));
      if (!history || this.secrets.fingerprint(history) !== this.secrets.fingerprint(raw)) invalidCapture('CONFIGURATION_TARGET_HISTORY_CHANGED');
      addresses.add(raw.target); active.set(nativeUuid(raw.id), this.secrets.fingerprint(raw));
      await this.add('targets', raw, false, parent); return true;
    }, parent);
    const verified = new Map<string, string>();
    await this.collection(`targets-verify:${parent.nativeId}`, `/upstreams/${parent.nativeId}/targets`, 'targets', { size: 100 }, async raw => {
      verified.set(nativeUuid(raw.id), this.secrets.fingerprint(raw)); return false;
    }, parent);
    if (canonicalJson([...active].sort()) !== canonicalJson([...verified].sort())) invalidCapture('CONFIGURATION_EFFECTIVE_TARGET_CHANGED');
  }

  private assertDag(): void {
    const done = new Set<string>(), visiting = new Set<string>();
    const visit = (key: string, depth: number): void => {
      if (depth > 100 || visiting.has(key)) invalidCapture('CONFIGURATION_DEPENDENCY_CYCLE');
      if (done.has(key)) return;
      const node = this.objects.get(key); if (!node) invalidCapture('CONFIGURATION_DEPENDENCY_MISSING');
      visiting.add(key); for (const dependency of node.dependencies) visit(dependency, depth + 1);
      visiting.delete(key); done.add(key);
    };
    for (const key of this.objects.keys()) visit(key, 0);
    if (this.requiredCollections.size !== this.collections.length || this.collections.some(collection => !collection.terminalObserved)) invalidCapture('CONFIGURATION_COLLECTION_INCOMPLETE');
  }
}
