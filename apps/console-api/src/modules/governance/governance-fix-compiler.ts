import { stringify } from 'yaml';
import { normalizeSchema } from '../config-transfer/schema-normalization';
import { createGovernanceReferenceResolver, governanceFieldSupport } from './lint-engine';
import { GovernanceLintError, type GovernanceFixCode, type GovernanceLintContext, type GovernanceNativeType, type LintFinding, type LintObject } from './lint-types';

export type GovernanceFixInput =
  | { readonly action: 'owner_tag_add'; readonly values: { readonly ownerTag: string } }
  | { readonly action: 'route_https_only'; readonly values: { readonly protocols: readonly ('https' | 'grpcs' | 'tls')[] } }
  | { readonly action: 'service_timeouts_set'; readonly values: { readonly connectTimeout: number; readonly writeTimeout: number; readonly readTimeout: number } }
  | { readonly action: 'entity_rename'; readonly values: { readonly name: string } }
  | { readonly action: 'reference_replace_or_clear'; readonly values: { readonly operation: 'replace' | 'clear'; readonly replacementId?: string; readonly replacementIds?: readonly string[] } }
  | { readonly action: 'unused_certificate_archive'; readonly values: Record<string, never> }
  | { readonly action: 'baseline_plugin_configure'; readonly values: { readonly pluginName: string; readonly config: Readonly<Record<string, unknown>>; readonly ownerTag?: string } }
  | { readonly action: 'annotation_description_set'; readonly values: { readonly description: string } };
export interface GovernanceCompiledFix {
  readonly kind: 'configuration' | 'annotation' | 'archive';
  readonly document?: Readonly<Record<string, unknown>>;
  /** Server-to-M8 material; do not put secret-bearing plugin config in public receipt/audit. */
  readonly yaml?: string;
  readonly selectedObjects: readonly { readonly entityType: GovernanceNativeType; readonly nativeId: string }[];
  readonly blockerCodes: readonly string[];
  readonly annotation?: { readonly entityType: GovernanceNativeType; readonly nativeId: string; readonly description: string };
  readonly archive?: { readonly entityType: 'certificates'; readonly nativeId: string };
}
const forbidden = new Set(['__proto__', 'prototype', 'constructor', '$ref', '$include', '<<']);
const forbiddenMarker = /\[REDACTED(?:[:\]])|\[DEPTH_LIMIT\]|\[CIRCULAR\]|^\*{3,}$/;
const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
function fail(code: string): never { throw new GovernanceLintError(code); }
function data(value: unknown, key: string): unknown { if (!value || typeof value !== 'object') return undefined; const property = Object.getOwnPropertyDescriptor(value, key); return property && Object.hasOwn(property, 'value') ? property.value : undefined; }
function reference(value: unknown): string | null { const id = typeof value === 'string' ? value : data(value, 'id'); return typeof id === 'string' && id ? id : null; }
function safeInput(value: unknown): void {
  const seen = new WeakSet<object>(); let nodes = 0, bytes = 0;
  const visit = (item: unknown, depth: number): void => {
    if (++nodes > 4096 || depth > 16) fail('GOVERNANCE_FIX_INPUT_COMPLEXITY');
    if (typeof item === 'string') { bytes += Buffer.byteLength(item); if (bytes > 65_536 || forbiddenMarker.test(item)) fail('GOVERNANCE_FIX_SECRET_MARKER'); return; }
    if (item === null || typeof item === 'boolean' || typeof item === 'number' && Number.isFinite(item)) return;
    if (!item || typeof item !== 'object' || !Array.isArray(item) && ![Object.prototype, null].includes(Object.getPrototypeOf(item))) fail('GOVERNANCE_FIX_INVALID_INPUT');
    if (seen.has(item)) fail('GOVERNANCE_FIX_INVALID_INPUT'); seen.add(item);
    for (const key of Reflect.ownKeys(item)) {
      if (typeof key !== 'string') fail('GOVERNANCE_FIX_INVALID_INPUT');
      const property = Object.getOwnPropertyDescriptor(item, key)!;
      if (Array.isArray(item) && key === 'length') continue;
      if (forbidden.has(key) || !Object.hasOwn(property, 'value')) fail('GOVERNANCE_FIX_INVALID_INPUT'); bytes += Buffer.byteLength(key); visit(property.value, depth + 1);
    } seen.delete(item);
  }; visit(value, 0);
}
function exactKeys(value: unknown, allowed: readonly string[]): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) fail('GOVERNANCE_FIX_INVALID_INPUT');
}
function allowedAction(input: unknown): asserts input is GovernanceFixInput {
  safeInput(input); exactKeys(input, ['action', 'values']); const action = data(input, 'action'), values = data(input, 'values');
  switch (action) {
    case 'owner_tag_add': exactKeys(values, ['ownerTag']); break;
    case 'route_https_only': exactKeys(values, ['protocols']); break;
    case 'service_timeouts_set': exactKeys(values, ['connectTimeout', 'writeTimeout', 'readTimeout']); break;
    case 'entity_rename': exactKeys(values, ['name']); break;
    case 'reference_replace_or_clear': exactKeys(values, ['operation', 'replacementId', 'replacementIds']); break;
    case 'unused_certificate_archive': exactKeys(values, []); break;
    case 'baseline_plugin_configure': exactKeys(values, ['pluginName', 'config', 'ownerTag']); break;
    case 'annotation_description_set': exactKeys(values, ['description']); break;
    default: fail('GOVERNANCE_FIX_UNSUPPORTED_ACTION');
  }
}
function requireObject(context: GovernanceLintContext, finding: LintFinding): LintObject {
  const object = context.objects.find(item => item.entityType === finding.entityType && item.nativeId === finding.nativeId && !item.referenceOnly && item.selected !== false);
  if (!object || !uuid.test(object.nativeId)) fail('GOVERNANCE_FIX_OBJECT_UNAVAILABLE'); return object;
}
function ownerTag(value: unknown): string {
  if (typeof value !== 'string' || !/^owner:[A-Za-z0-9][A-Za-z0-9_.@-]{0,119}$/.test(value)) fail('GOVERNANCE_FIX_OWNER_REQUIRED'); return value;
}
function normalizedPatch(context: GovernanceLintContext, object: LintObject, patch: Record<string, unknown>): Record<string, unknown> {
  const schema = context.schemas?.[object.entityType]; if (!schema) fail('GOVERNANCE_FIX_SCHEMA_UNAVAILABLE');
  const identity = object.entityType === 'plugins' ? { name: data(object.payload, 'name') } : {};
  if (object.entityType === 'plugins' && (typeof identity.name !== 'string' || !context.enabledPlugins?.includes(identity.name))) fail('GOVERNANCE_FIX_PLUGIN_UNAVAILABLE');
  try { return normalizeSchema({ id: object.nativeId, ...identity, ...patch }, schema, { required: false, defaults: false }); }
  catch { fail('GOVERNANCE_FIX_SCHEMA_INVALID'); }
}
function configuration(context: GovernanceLintContext, object: LintObject, patch: Record<string, unknown>): GovernanceCompiledFix {
  const normalized = normalizedPatch(context, object, patch); let document: Record<string, unknown>;
  if (object.entityType === 'targets') {
    if (!object.parentId || !uuid.test(object.parentId)) fail('GOVERNANCE_FIX_PARENT_UNAVAILABLE');
    document = { _format_version: '1.1', upstreams: [{ id: object.parentId, targets: [normalized] }] };
  } else if (object.entityType === 'snis') {
    const certificateId = reference(Object.hasOwn(normalized, 'certificate') ? normalized.certificate : data(object.payload, 'certificate'));
    if (!certificateId || !uuid.test(certificateId) || createGovernanceReferenceResolver(context)('certificates', certificateId) !== 'present') fail('GOVERNANCE_FIX_PARENT_UNAVAILABLE');
    document = { _format_version: '1.1', certificates: [{ id: certificateId, snis: [normalized] }] };
  } else document = { _format_version: '1.1', [object.entityType]: [normalized] };
  return { kind: 'configuration', document, yaml: stringify(document), selectedObjects: [{ entityType: object.entityType, nativeId: object.nativeId }], blockerCodes: [] };
}
const actionRule: Readonly<Record<GovernanceFixCode, readonly string[]>> = {
  owner_tag_add: ['OWNER_MISSING'], route_https_only: ['builtin.route_https'], service_timeouts_set: ['builtin.service_timeouts'],
  entity_rename: ['builtin.naming', 'UNIQUE_FIELD_CONFLICT'], reference_replace_or_clear: ['PLUGIN_ORPHAN_REFERENCE', 'ROUTE_INVALID_SERVICE', 'SNI_INVALID_CERTIFICATE', 'SERVICE_INVALID_CLIENT_CERTIFICATE', 'SERVICE_INVALID_CA_CERTIFICATE'],
  unused_certificate_archive: ['CERTIFICATE_UNUSED'], baseline_plugin_configure: ['SECURITY_BASELINE_MISSING'], annotation_description_set: ['DESCRIPTION_MISSING'],
};
/** Fixed action compiler. It deliberately emits only supplied field deltas,
 * preserving secret/config/timestamp fields rather than copying redacted rows.
 * Caller must recapture/reevaluate and obtain a fresh actual M8 diff afterward. */
export function compileGovernanceFix(context: GovernanceLintContext, finding: LintFinding, input: unknown): GovernanceCompiledFix {
  allowedAction(input);
  if (finding.status !== 'confirmed' || !finding.fixCodes.includes(input.action)
    || !actionRule[input.action].some(code => code === finding.code || code === finding.ruleCode)) fail('GOVERNANCE_FIX_CURRENT_ISSUE_REQUIRED');
  const referenceState = createGovernanceReferenceResolver(context);
  if (input.action === 'baseline_plugin_configure') {
    if (finding.nativeId !== null || finding.entityType !== null || finding.ruleCode !== `builtin.security_baseline.${input.values.pluginName}`
      || context.scope?.kind !== 'cluster' || context.projection || !context.enabledPlugins?.includes(input.values.pluginName)) fail('GOVERNANCE_FIX_BASELINE_SCOPE_REQUIRED');
    if (context.completeness !== 'complete' || !context.collections.some(collection => collection.entityType === 'plugins' && collection.complete && collection.extent === 'cluster')) fail('GOVERNANCE_FIX_BASELINE_SCOPE_REQUIRED');
    if (context.objects.some(object => object.entityType === 'plugins' && data(object.payload, 'name') === input.values.pluginName && data(object.payload, 'enabled') !== false
      && ['service', 'route', 'consumer'].every(field => !reference(data(object.payload, field))))) fail('GOVERNANCE_FIX_ISSUE_RESOLVED');
    const pluginSchema = context.pluginSchemas?.[input.values.pluginName], entitySchema = context.schemas?.plugins;
    if (!pluginSchema || !entitySchema) fail('GOVERNANCE_FIX_SCHEMA_UNAVAILABLE');
    const disabledGlobals = context.objects.filter(object => object.entityType === 'plugins' && data(object.payload, 'name') === input.values.pluginName && data(object.payload, 'enabled') === false
      && ['service', 'route', 'consumer'].every(field => !reference(data(object.payload, field))));
    if (disabledGlobals.length > 1) fail('GOVERNANCE_FIX_BASELINE_AMBIGUOUS');
    let config: Record<string, unknown>, payload: Record<string, unknown>;
    try { config = normalizeSchema(input.values.config, pluginSchema, { required: disabledGlobals.length === 0, defaults: disabledGlobals.length === 0 });
      payload = normalizeSchema({ name: input.values.pluginName, enabled: true, config, ...(input.values.ownerTag ? { tags: [ownerTag(input.values.ownerTag)] } : {}) }, entitySchema, { required: false, defaults: false }); }
    catch { fail('GOVERNANCE_FIX_SCHEMA_INVALID'); }
    if (disabledGlobals.length === 1) {
      const existing = disabledGlobals[0];
      return configuration(context, existing, { enabled: true, config, ...(input.values.ownerTag ? { tags: [...(Array.isArray(data(existing.payload, 'tags')) ? data(existing.payload, 'tags') as string[] : []), ownerTag(input.values.ownerTag)] } : {}) });
    }
    const document = { _format_version: '1.1', plugins: [payload] };
    return { kind: 'configuration', document, yaml: stringify(document), selectedObjects: [], blockerCodes: [] };
  }
  const object = requireObject(context, finding);
  if (input.action === 'owner_tag_add') {
    const rawTags = data(object.payload, 'tags'), tags = rawTags === null || rawTags === undefined ? [] : rawTags;
    safeInput(tags);
    if (!Array.isArray(tags) || tags.some(tag => typeof tag !== 'string' || forbiddenMarker.test(tag))) fail('GOVERNANCE_FIX_TAGS_UNAVAILABLE');
    if (tags.some(tag => typeof tag === 'string' && tag.startsWith('owner:') && tag.slice(6).trim()) || object.annotations?.ownerUserId) fail('GOVERNANCE_FIX_ISSUE_RESOLVED');
    return configuration(context, object, { tags: [...tags, ownerTag(input.values.ownerTag)] });
  }
  if (input.action === 'route_https_only') {
    const protocols = input.values.protocols;
    if (object.entityType !== 'routes' || !Array.isArray(protocols) || !protocols.length || protocols.length > 3 || new Set(protocols).size !== protocols.length
      || !protocols.every(protocol => ['https', 'grpcs', 'tls'].includes(protocol))) fail('GOVERNANCE_FIX_PROTOCOLS_REQUIRED');
    const current = data(object.payload, 'protocols'); if (Array.isArray(current) && current.length && current.every(protocol => ['https', 'grpcs', 'tls'].includes(String(protocol)))) fail('GOVERNANCE_FIX_ISSUE_RESOLVED');
    return configuration(context, object, { protocols: [...protocols] });
  }
  if (input.action === 'service_timeouts_set') {
    if (object.entityType !== 'services' || [input.values.connectTimeout, input.values.writeTimeout, input.values.readTimeout]
      .some(value => !Number.isInteger(value) || value < 1 || value > 2_147_483_647)) fail('GOVERNANCE_FIX_TIMEOUTS_REQUIRED');
    if (['connect_timeout', 'write_timeout', 'read_timeout'].every(field => { const value = data(object.payload, field); return typeof value === 'number' && Number.isFinite(value) && value > 0; })) fail('GOVERNANCE_FIX_ISSUE_RESOLVED');
    return configuration(context, object, { connect_timeout: input.values.connectTimeout, write_timeout: input.values.writeTimeout, read_timeout: input.values.readTimeout });
  }
  if (input.action === 'entity_rename') {
    if (typeof input.values.name !== 'string' || !input.values.name.trim() || input.values.name.length > 255 || ['plugins', 'targets', 'certificates', 'ca_certificates'].includes(object.entityType)) fail('GOVERNANCE_FIX_NAME_REQUIRED');
    const field = object.entityType === 'consumers' ? finding.field === 'custom_id' ? 'custom_id' : 'username' : 'name';
    if (finding.code === 'UNIQUE_FIELD_CONFLICT' && finding.field !== field || governanceFieldSupport(context, object.entityType, field) !== 'supported') fail('GOVERNANCE_FIX_NAME_FIELD_UNSUPPORTED');
    if (data(object.payload, field) === input.values.name) fail('GOVERNANCE_FIX_ISSUE_RESOLVED');
    if (context.objects.some(candidate => candidate.entityType === object.entityType && candidate.nativeId !== object.nativeId && data(candidate.payload, field) === input.values.name)) fail('GOVERNANCE_FIX_NAME_CONFLICT');
    return configuration(context, object, { [field]: input.values.name });
  }
  if (input.action === 'reference_replace_or_clear') {
    const map: Partial<Record<GovernanceNativeType, Readonly<Record<string, GovernanceNativeType>>>> = {
      plugins: { service: 'services', route: 'routes', consumer: 'consumers' }, routes: { service: 'services' }, snis: { certificate: 'certificates' }, services: { client_certificate: 'certificates', ca_certificates: 'ca_certificates' },
    };
    const field = finding.field, type = field ? map[object.entityType]?.[field] : undefined;
    if (!field || !type || !['replace', 'clear'].includes(input.values.operation)) fail('GOVERNANCE_FIX_REFERENCE_REQUIRED');
    const current = data(object.payload, field), values = field === 'ca_certificates' ? Array.isArray(current) ? current : [] : [current];
    if (!values.some(value => { const id = reference(value); return !!id && referenceState(type, id) === 'absent'; })) fail('GOVERNANCE_FIX_CURRENT_ISSUE_REQUIRED');
    let replacement: unknown;
    if (input.values.operation === 'clear') { if (input.values.replacementId !== undefined || input.values.replacementIds !== undefined) fail('GOVERNANCE_FIX_REFERENCE_REQUIRED'); replacement = field === 'ca_certificates' ? [] : null; }
    else if (field === 'ca_certificates') {
      const ids = input.values.replacementIds; if (!Array.isArray(ids) || !ids.length || ids.length > 32 || input.values.replacementId !== undefined
        || new Set(ids).size !== ids.length || ids.some(id => !uuid.test(id) || referenceState(type, id) !== 'present')) fail('GOVERNANCE_FIX_REFERENCE_REQUIRED'); replacement = [...ids];
    } else {
      const id = input.values.replacementId; if (typeof id !== 'string' || !uuid.test(id) || input.values.replacementIds !== undefined || referenceState(type, id) !== 'present') fail('GOVERNANCE_FIX_REFERENCE_REQUIRED'); replacement = { id };
    }
    return configuration(context, object, { [field]: replacement });
  }
  if (input.action === 'annotation_description_set') {
    if (object.annotations?.state === 'not_authorized' || !object.annotations || object.annotations.description?.trim()) fail('GOVERNANCE_FIX_CURRENT_ISSUE_REQUIRED');
    if (typeof input.values.description !== 'string' || !input.values.description.trim() || input.values.description.length > 2000 || /-----BEGIN .*PRIVATE KEY-----|^(?:Bearer|Basic)\s+\S+/i.test(input.values.description)) fail('GOVERNANCE_FIX_DESCRIPTION_REQUIRED');
    return { kind: 'annotation', annotation: { entityType: object.entityType, nativeId: object.nativeId, description: input.values.description },
      selectedObjects: [{ entityType: object.entityType, nativeId: object.nativeId }], blockerCodes: [] };
  }
  if (input.action === 'unused_certificate_archive') {
    if (object.entityType !== 'certificates' || context.scope?.kind !== 'cluster' || context.projection || context.completeness !== 'complete'
      || !['snis', 'services'].every(type => context.collections.some(collection => collection.entityType === type && collection.complete && collection.extent === 'cluster'))
      || context.objects.some(candidate => candidate.entityType === 'snis' && reference(data(candidate.payload, 'certificate')) === object.nativeId
        || candidate.entityType === 'services' && reference(data(candidate.payload, 'client_certificate')) === object.nativeId)) fail('GOVERNANCE_FIX_CURRENT_ISSUE_REQUIRED');
    return { kind: 'archive', archive: { entityType: 'certificates', nativeId: object.nativeId }, selectedObjects: [{ entityType: object.entityType, nativeId: object.nativeId }], blockerCodes: [] };
  }
  return fail('GOVERNANCE_FIX_UNSUPPORTED_ACTION');
}
