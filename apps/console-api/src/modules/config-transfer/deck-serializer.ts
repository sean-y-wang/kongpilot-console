import { isSupportedKong, kongCapabilities } from '../../infrastructure/kong/kong-capabilities';
import { stringify } from 'yaml';
import type { CaptureGraph, CaptureObject } from '../configuration/configuration.types';
import { CREDENTIAL_SCHEMAS } from '../entities/entities.types';
import { canonicalJson } from '../../infrastructure/secret.service';
import { nativeId, normalizeEntityPayload, writableCapturedPayload, schemaFields, entitySchema } from './schema-normalization';
import { configurationNativeIdentity, configurationObjectKey } from './deck-normalizer';
import { transferFail } from './transfer.types';
import type { Deck11Export, DeckFormatOmission } from './transfer.types';

export function assertCompleteCaptureGraph(graph: CaptureGraph): void {
  if (graph.completeness !== 'complete' || graph.consistency !== 'console_fenced_best_effort') transferFail('CONFIGURATION_CAPTURE_NOT_COMPLETE');
  if (!isSupportedKong(graph.kongVersion) || graph.schemas.kongVersion !== graph.kongVersion || graph.schemas.schemaHmac !== graph.schemaHmac) transferFail('CONFIGURATION_SCHEMA_BINDING_MISMATCH');
  // Kong < 1.4 credentials carry no tags, so workspace isolation cannot be proven.
  if (!kongCapabilities(graph.kongVersion).credentialTransfer && graph.objects.some(object => object.entityType === 'credentials')) transferFail('CONFIGURATION_CREDENTIALS_UNSUPPORTED_KONG_VERSION');
  const collections = new Map(graph.collections.map(collection => [collection.collectionKey, collection]));
  if (collections.size !== graph.collections.length || graph.requiredCollections.some(key => !collections.get(key)?.terminalObserved)) transferFail('CONFIGURATION_COLLECTION_NOT_COMPLETE');
  const objects = new Map<string, CaptureObject>();
  const ids = new Set<string>();
  for (const object of graph.objects) {
    const id = nativeId(object.nativeId);
    if (nativeId(object.payload.id) !== id || object.objectKey !== configurationObjectKey(object.entityType, id, object.parentId, object.credentialKind)
      || object.schemaHmac !== graph.schemaHmac || objects.has(object.objectKey) || ids.has(configurationNativeIdentity(object.entityType, id, object.credentialKind)) || object.referenceOnly && object.affected) transferFail('CONFIGURATION_INVALID_CAPTURE_IDENTITY');
    ids.add(configurationNativeIdentity(object.entityType, id, object.credentialKind)); objects.set(object.objectKey, object);
    if (object.entityType === 'credentials' && (!object.credentialKind || object.parentType !== 'consumers' || (object.payload.consumer as any)?.id !== object.parentId)
      || object.entityType === 'targets' && (object.parentType !== 'upstreams' || (object.payload.upstream as any)?.id !== object.parentId)) transferFail('CONFIGURATION_PARENT_REFERENCE_MISMATCH');
  }
  for (const object of graph.objects) for (const dependency of object.dependencies) if (!objects.has(dependency)) transferFail('CONFIGURATION_REFERENCE_NOT_CAPTURED');
}

/** A private full deployment graph or an explicitly redacted review; no DB or network. */
export function serializeDeck11WithReport(graph: CaptureGraph, options: { mode?: 'deployment' | 'review'; redact?: (value: unknown) => unknown } = {}): Deck11Export {
  const mode = options.mode ?? 'deployment';
  assertCompleteCaptureGraph(graph);
  if (mode === 'review' && !options.redact) transferFail('CONFIGURATION_REDACTOR_REQUIRED');
  const document: Record<string, unknown> = { _format_version: '1.1' };
  const exported = new Map<string, Record<string, unknown>>();
  const formatOmissions: DeckFormatOmission[] = [];
  const selected = graph.objects.filter(object => object.affected && !object.referenceOnly).sort((a, b) => a.objectKey < b.objectKey ? -1 : a.objectKey > b.objectKey ? 1 : 0);
  for (const object of selected) {
    if (mode === 'deployment' && object.recovery.state !== 'complete') transferFail('CONFIGURATION_RECOVERY_NOT_COMPLETE');
    if (mode === 'deployment' && (object.recovery.absoluteExpiresAt || object.payload.ttl !== undefined && object.payload.ttl !== null)) transferFail('CONFIGURATION_TTL_EXPORT_UNSUPPORTED');
    if (object.entityType === 'credentials' && object.credentialKind === 'basic-auth' && mode === 'deployment' && typeof object.recovery.restorePayload?.password !== 'string') transferFail('CONFIGURATION_BASIC_PASSWORD_UNAVAILABLE');
    const material = mode === 'deployment' ? object.recovery.restorePayload ?? object.payload : object.payload;
    if (nativeId(material.id) !== object.nativeId) transferFail('CONFIGURATION_RECOVERY_IDENTITY_MISMATCH');
    const payload = normalizeEntityPayload(writableCapturedPayload(material, object.entityType), graph.schemas, object.entityType, object.credentialKind);
    projectDeckOptionalNulls(payload, entitySchema(graph.schemas, object.entityType, object.credentialKind), object, formatOmissions);
    const fields = schemaFields(entitySchema(graph.schemas, object.entityType, object.credentialKind));
    for (const [key, definition] of Object.entries(fields)) if (definition.type === 'foreign' && payload[key] !== undefined && payload[key] !== null) payload[key] = (payload[key] as any).id;
    exported.set(object.objectKey, payload);
  }
  const append = (key: string, value: Record<string, unknown>): void => { (document[key] ??= [] as unknown[]); (document[key] as unknown[]).push(value); };
  const nested = (object: CaptureObject, parentKey: string, key: string, relation: string): void => {
    const parent = exported.get(parentKey), payload = exported.get(object.objectKey)!;
    if (!parent) transferFail('CONFIGURATION_EXPORT_PARENT_OUTSIDE_SCOPE');
    if (payload[relation] !== undefined && payload[relation] !== object.parentId && relation !== 'certificate') transferFail('CONFIGURATION_PARENT_REFERENCE_MISMATCH');
    delete payload[relation];
    (parent[key] ??= [] as unknown[]); (parent[key] as unknown[]).push(payload);
  };
  for (const object of selected) {
    const payload = exported.get(object.objectKey)!;
    if (object.entityType === 'targets') nested(object, `upstreams:${object.parentId}`, 'targets', 'upstream');
    else if (object.entityType === 'credentials') nested(object, `consumers:${object.parentId}`, CREDENTIAL_SCHEMAS[object.credentialKind!], 'consumer');
    else if (object.entityType === 'snis') {
      const parentId = (object.payload.certificate as any)?.id;
      if (!parentId) transferFail('CONFIGURATION_PARENT_REFERENCE_MISMATCH');
      nested(object, `certificates:${parentId}`, 'snis', 'certificate');
    } else if (object.entityType === 'routes' && typeof payload.service === 'string' && exported.has(`services:${payload.service}`)) {
      const parent = exported.get(`services:${payload.service}`)!; delete payload.service;
      (parent.routes ??= [] as unknown[]); (parent.routes as unknown[]).push(payload);
    } else append(object.entityType, payload);
  }
  const output = mode === 'review' ? options.redact!(document) : document;
  // Canonical key order plus fixed collections makes output reproducible across capture page order.
  const stable = JSON.parse(canonicalJson(output));
  const result = stringify(stable, { aliasDuplicateObjects: false, lineWidth: 0, defaultStringType: 'QUOTE_DOUBLE', defaultKeyType: 'PLAIN', sortMapEntries: true });
  if (Buffer.byteLength(result, 'utf8') > 8 * 1024 * 1024) transferFail('CONFIGURATION_DOCUMENT_TOO_LARGE');
  return { yaml: mode === 'review' ? '# KongPilot review: redacted values are not deployable.\n' + result : result, formatOmissions };
}

const pointer = (name: string): string => name.replace(/~/g, '~0').replace(/\//g, '~1');
/** decK1.1's typed entity fields reject null. The immutable graph remains
 * untouched, and its explicit null intent is recorded in a separate manifest.
 * Plugin config is unrestricted JSON in decK and retains its native nulls. */
function projectDeckOptionalNulls(payload: Record<string, unknown>, schema: unknown, object: CaptureObject, omissions: DeckFormatOmission[]): void {
  const visit = (value: any, definition: any, path: string): void => {
    if (!value || typeof value !== 'object') return;
    if (definition.type === 'array' || definition.type === 'set') {
      for (let i = 0; i < value.length; i++) {
        if (value[i] === null) transferFail('CONFIGURATION_DECK11_NULL_ELEMENT');
        visit(value[i], definition.elements || {}, `${path}/${i}`);
      }
      return;
    }
    if (definition.type === 'record' || definition.fields) {
      if (definition.abstract === true && !definition.fields) return;
      const fields = schemaFields(definition);
      for (const [name, child] of Object.entries(value)) {
        if (object.entityType === 'plugins' && path === '' && name === 'config') continue;
        const field = fields[name], childPath = `${path}/${pointer(name)}`;
        if (child === null) {
          if (!field || field.required === true || !['string', 'integer', 'number', 'boolean', 'array', 'set', 'record', 'map', 'foreign'].includes(field.type)) transferFail('CONFIGURATION_DECK11_NULL_NOT_REPRESENTABLE');
          delete value[name]; omissions.push({ objectKey: object.objectKey, jsonPointer: childPath, reason: 'deck11_optional_null' });
        } else visit(child, field || {}, childPath);
      }
    } else if (definition.type === 'map') {
      for (const [name, child] of Object.entries(value)) {
        if (child === null) transferFail('CONFIGURATION_DECK11_NULL_MAP_VALUE');
        visit(child, definition.values || {}, `${path}/${pointer(name)}`);
      }
    }
  };
  visit(payload, { type: 'record', fields: schemaFields(schema) }, '');
}

export function serializeDeck11(graph: CaptureGraph, options: { mode?: 'deployment' | 'review'; redact?: (value: unknown) => unknown } = {}): string {
  return serializeDeck11WithReport(graph, options).yaml;
}
