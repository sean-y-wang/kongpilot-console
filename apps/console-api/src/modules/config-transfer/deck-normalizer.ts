import type { CaptureGraph, CapturedSchemaBundle, ConfigurationEntityType, ConfigurationCredentialKind } from '../configuration/configuration.types';
import { CREDENTIAL_SCHEMAS } from '../entities/entities.types';
import { decodeTag, encodeTag, workspaceTag } from '../../infrastructure/kong/tags';
import { assertTransferJson, nativeId, normalizeEntityPayload, rejectReadOnlyInput, schemaFields, entitySchema, writableCapturedPayload } from './schema-normalization';
import type { NormalizeOptions, NormalizedTransferGraph, ParsedDeckDocument, TransferObject } from './transfer.types';
import { transferFail } from './transfer.types';

const credentialFields = Object.fromEntries(Object.entries(CREDENTIAL_SCHEMAS).map(([kind, key]) => [key, kind])) as Record<string, ConfigurationCredentialKind>;
const rootTypes = ['certificates', 'ca_certificates', 'upstreams', 'services', 'routes', 'consumers', 'plugins'] as const;
export function configurationObjectKey(type: ConfigurationEntityType, id: string, parentId?: string | null, kind?: ConfigurationCredentialKind | null): string {
  return type === 'credentials' ? `credentials:${kind}:${parentId}:${id}` : type === 'targets' ? `targets:${parentId}:${id}` : `${type}:${id}`;
}
export function configurationNativeIdentity(type: ConfigurationEntityType, id: string, kind?: ConfigurationCredentialKind | null): string {
  return type === 'credentials' ? `credentials:${kind}:${id}` : `${type}:${id}`;
}
function list(value: unknown, path: string): unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) transferFail('CONFIGURATION_INVALID_COLLECTION', path);
  return value;
}

/** Flatten decK nesting into real Kong objects. No names are guessed as foreign UUIDs. */
export function normalizeDeckDocument(parsed: ParsedDeckDocument, schemas: CapturedSchemaBundle, options: NormalizeOptions): NormalizedTransferGraph {
  if (!/^1\.5\./.test(schemas.kongVersion)) transferFail('CONFIGURATION_UNSUPPORTED_KONG_VERSION');
  assertTransferJson(parsed.document);
  if (parsed.document._format_version !== '1.1') transferFail('CONFIGURATION_FORMAT_VERSION');
  const codes = { ...options.workspaceCodesById, [options.scope.workspaceId]: options.workspaceCode };
  const workspaceByTag = new Map(Object.entries(codes).map(([id, code]) => [workspaceTag(code), id]));
  if (workspaceByTag.size !== Object.keys(codes).length) transferFail('CONFIGURATION_AMBIGUOUS_WORKSPACE');
  const objects: TransferObject[] = [], keys = new Set<string>(), nativeIds = new Set<string>();
  const references = new Map((options.references?.objects ?? []).map(object => [object.objectKey, object]));
  const add = (type: ConfigurationEntityType, input: unknown, path: string, parent?: TransferObject, kind?: ConfigurationCredentialKind): TransferObject => {
    if (type === 'snis' && typeof input === 'string') input = { name: input };
    if (!input || typeof input !== 'object' || Array.isArray(input)) transferFail('CONFIGURATION_INVALID_ENTITY', path);
    const value = structuredClone(input) as Record<string, unknown>;
    rejectReadOnlyInput(value, path);
    const nesting: Record<string, unknown> = Object.create(null);
    const nestedKeys = type === 'services' ? ['routes', 'plugins'] : type === 'routes' ? ['plugins'] : type === 'upstreams' ? ['targets'] : type === 'certificates' ? ['snis'] : type === 'consumers' ? ['plugins', ...Object.keys(credentialFields)] : [];
    for (const key of nestedKeys) if (Object.hasOwn(value, key)) { nesting[key] = value[key]; delete value[key]; }
    const id = nativeId(value.id ?? options.allocatedNativeIds?.[path], path); value.id = id;
    const objectKey = configurationObjectKey(type, id, parent?.nativeId, kind);
    const nativeIdentity = configurationNativeIdentity(type, id, kind);
    if (keys.has(objectKey) || nativeIds.has(nativeIdentity)) transferFail('CONFIGURATION_DUPLICATE_NATIVE_ID', path);
    keys.add(objectKey); nativeIds.add(nativeIdentity);
    const parentField = type === 'targets' ? 'upstream' : type === 'credentials' ? 'consumer' : type === 'snis' ? 'certificate' : type === 'routes' && parent ? 'service' : null;
    if (parent && parentField) {
      if (Object.hasOwn(value, parentField)) {
        const reference = value[parentField], actual = typeof reference === 'string' ? reference : reference && typeof reference === 'object' && !Array.isArray(reference) && Object.keys(reference).length === 1 ? (reference as any).id : null;
        if (actual !== parent.nativeId) transferFail('CONFIGURATION_PARENT_REFERENCE_MISMATCH', path);
      }
      value[parentField] = { id: parent.nativeId };
    }
    if (type === 'plugins' && parent) {
      const binding = parent.entityType === 'services' ? 'service' : parent.entityType === 'routes' ? 'route' : 'consumer';
      if (Object.hasOwn(value, binding) && (typeof value[binding] === 'string' ? value[binding] : (value[binding] as any)?.id) !== parent.nativeId) transferFail('CONFIGURATION_PARENT_REFERENCE_MISMATCH', path);
      value[binding] = { id: parent.nativeId };
    }
    let wid = parent?.objectWorkspaceId || references.get(objectKey)?.objectWorkspaceId || options.scope.workspaceId;
    if (Object.hasOwn(value, 'tags') && value.tags !== null) {
      if (!Array.isArray(value.tags) || value.tags.some(tag => typeof tag !== 'string')) transferFail('CONFIGURATION_INVALID_TAGS', path);
      const tags: string[] = value.tags.map(tag => {
        try {
          const physical = tag.startsWith('kos-ws-') || tag.startsWith('kos-tag-') ? encodeTag(decodeTag(tag)) : encodeTag(tag);
          if ((tag.startsWith('kos-ws-') || tag.startsWith('kos-tag-')) && physical !== tag) transferFail('CONFIGURATION_INVALID_TAGS', path);
          return physical;
        } catch { transferFail('CONFIGURATION_INVALID_TAGS', path); }
      });
      const reserved = [...new Set(tags.filter(tag => tag.startsWith('kos-ws-')))];
      if (reserved.length > 1 || reserved.length && !workspaceByTag.has(reserved[0])) transferFail('CONFIGURATION_UNKNOWN_WORKSPACE_TAG', path);
      if (reserved.length) wid = workspaceByTag.get(reserved[0])!;
      if (options.scope.kind !== 'cluster' && wid !== options.scope.workspaceId || parent && wid !== parent.objectWorkspaceId) transferFail('CONFIGURATION_WORKSPACE_MIGRATION_FORBIDDEN', path);
      value.tags = [...new Set(tags)];
    }
    if (options.scope.kind !== 'cluster' && wid !== options.scope.workspaceId || parent && wid !== parent.objectWorkspaceId) transferFail('CONFIGURATION_WORKSPACE_MIGRATION_FORBIDDEN', path);
    const payload = normalizeEntityPayload(value, schemas, type, kind);
    const deps = new Set<string>();
    const fields = schemaFields(entitySchema(schemas, type, kind));
    for (const [name, definition] of Object.entries(fields)) if (definition.type === 'foreign' && payload[name] !== undefined && payload[name] !== null) deps.add(configurationObjectKey(definition.reference, (payload[name] as any).id));
    if (parent) deps.add(parent.objectKey);
    const intent = kind === 'basic-auth' ? options.basicPasswordIntents?.[objectKey] ?? options.basicPasswordIntents?.[path] : undefined;
    if (kind === 'basic-auth' && Object.hasOwn(payload, 'password') && intent !== 'replace') transferFail('CONFIGURATION_BASIC_PASSWORD_INTENT_REQUIRED', path);
    if (intent === 'keep' && Object.hasOwn(payload, 'password') || intent === 'replace' && typeof payload.password !== 'string') transferFail('CONFIGURATION_BASIC_PASSWORD_INTENT_INVALID', path);
    const result: TransferObject = { objectKey, entityType: type, nativeId: id, ...(parent && parentField && type !== 'routes' ? { parentType: parent.entityType, parentId: parent.nativeId } : {}), ...(kind ? { credentialKind: kind } : {}), objectWorkspaceId: wid, payload, dependencies: [...deps].sort(), sourcePath: path, ...(intent ? { passwordIntent: intent } : {}) };
    objects.push(result);
    if (type === 'services') list(nesting.routes, `${path}.routes`).forEach((item, i) => add('routes', item, `${path}.routes[${i}]`, result));
    if (type === 'upstreams') list(nesting.targets, `${path}.targets`).forEach((item, i) => add('targets', item, `${path}.targets[${i}]`, result));
    if (type === 'certificates') list(nesting.snis, `${path}.snis`).forEach((item, i) => add('snis', item, `${path}.snis[${i}]`, result));
    if (type === 'consumers') for (const [field, credentialKind] of Object.entries(credentialFields)) list(nesting[field], `${path}.${field}`).forEach((item, i) => add('credentials', item, `${path}.${field}[${i}]`, result, credentialKind));
    if (Object.hasOwn(nesting, 'plugins')) list(nesting.plugins, `${path}.plugins`).forEach((item, i) => add('plugins', item, `${path}.plugins[${i}]`, result));
    return result;
  };
  for (const key of Object.keys(parsed.document)) if (key !== '_format_version' && !rootTypes.includes(key as any)) transferFail('CONFIGURATION_UNKNOWN_ROOT_FIELD');
  for (const type of rootTypes) list(parsed.document[type], type).forEach((entry, i) => add(type, entry, `${type}[${i}]`));
  const all = new Map(objects.map(object => [object.objectKey, object]));
  for (const ref of options.references?.objects ?? []) if (!all.has(ref.objectKey)) all.set(ref.objectKey, ref as any);
  // Service.host may name a captured or declared Upstream; an ordinary DNS host is legal.
  const upstreams = new Map([...all.values()].filter(object => object.entityType === 'upstreams').map(object => [object.payload.name, object.objectKey]));
  return { scope: structuredClone(options.scope), schemas, workspaceCodesById: codes, semantics: 'merge', objects: objects.map(object => {
    const dependencies = [...new Set([...object.dependencies, ...(object.entityType === 'services' && upstreams.has(object.payload.host) ? [upstreams.get(object.payload.host)!] : [])])].sort();
    for (const dependency of dependencies) if (!all.has(dependency)) transferFail('CONFIGURATION_REFERENCE_NOT_CAPTURED', object.sourcePath);
    return { ...object, dependencies };
  }) };
}

/** Snapshot rollback never passes through decK's nullable-field format projection. */
export function normalizeCaptureGraph(graph: CaptureGraph, workspaceCodesById: Readonly<Record<string, string>>): NormalizedTransferGraph {
  if (graph.completeness !== 'complete' || graph.consistency !== 'console_fenced_best_effort') transferFail('CONFIGURATION_CAPTURE_NOT_COMPLETE');
  const objects = graph.objects.filter(object => object.affected && !object.referenceOnly).map(object => {
    if (object.recovery.state !== 'complete') transferFail('CONFIGURATION_RECOVERY_NOT_COMPLETE');
    if (!workspaceCodesById[object.objectWorkspaceId]) transferFail('CONFIGURATION_UNKNOWN_WORKSPACE_TAG');
    if (object.credentialKind === 'basic-auth' && typeof object.recovery.restorePayload?.password !== 'string') transferFail('CONFIGURATION_BASIC_PASSWORD_UNAVAILABLE');
    const payload = normalizeEntityPayload(writableCapturedPayload(object.recovery.restorePayload ?? object.payload, object.entityType), graph.schemas, object.entityType, object.credentialKind);
    if (nativeId(payload.id) !== object.nativeId) transferFail('CONFIGURATION_RECOVERY_IDENTITY_MISMATCH');
    return { objectKey: object.objectKey, entityType: object.entityType, nativeId: object.nativeId, parentType: object.parentType ?? undefined, parentId: object.parentId ?? undefined, credentialKind: object.credentialKind ?? undefined, objectWorkspaceId: object.objectWorkspaceId, payload, dependencies: object.dependencies, sourcePath: 'snapshot', ...(object.credentialKind === 'basic-auth' ? { passwordIntent: 'replace' as const } : {}) };
  });
  return { scope: graph.scope, schemas: graph.schemas, objects, workspaceCodesById: { ...workspaceCodesById }, semantics: 'complete' };
}
