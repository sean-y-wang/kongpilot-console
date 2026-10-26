import { isSupportedKong } from '../../infrastructure/kong/kong-capabilities';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../../infrastructure/secret.service';
import { decodeTag } from '../../infrastructure/kong/tags';
import { entitySchema, schemaFields, UUID } from '../config-transfer/schema-normalization';
import { comparisonFail, comparisonSchemas } from './comparison-types';
import type { ComparisonInventory, ComparisonObject, ComparisonPolicy, FieldExclusion, FieldExclusionReason, LogicalGraph, LogicalObject, ComparisonIssue } from './comparison-types';

const reserved = new Set(['__proto__', 'prototype', 'constructor', '$ref', '$include', '<<']);
const metadata = new Set(['id', 'created_at', 'updated_at', 'ttl']);
const builtinPlugins = new Set(['key-auth','jwt','oauth2','hmac-auth','basic-auth','ldap-auth','acl','cors','ip-restriction','rate-limiting','response-ratelimiting','request-size-limiting','request-transformer','response-transformer','request-termination','proxy-cache','grpc-gateway','degraphql','prometheus','zipkin','datadog','statsd','syslog','file-log','http-log','tcp-log','udp-log','kafka-log','aws-lambda','pre-function','post-function','correlation-id','bot-detection','session']);
const anonymousConsumerPlugins=new Set(['key-auth','jwt','oauth2','hmac-auth','basic-auth','ldap-auth']);
export const authenticationAnonymousConsumerPlugin=(name:unknown):boolean=>typeof name==='string'&&anonymousConsumerPlugins.has(name);
const publicSecretNames = new Set(['keyname','keynames','keyid','keyids','secretisbase64','enablepasswordgrant','tokenexpiration','tokenexpirationtime','tokentype','tokenendpoint']);
const environmental: Readonly<Record<string, readonly string[]>> = {
  services: ['host','port','client_certificate','ca_certificates'],
  routes: ['hosts','snis','sources','destinations'],
  upstreams: ['healthchecks.active.https_sni','healthchecks.active.http_path'],
  targets: ['target'],
  snis: ['name'],
  credentials: ['redirect_uris'],
};

/** No getters, prototypes, aliases, scripts or unbounded trees are evaluated. */
export function assertComparisonJson(value: unknown): void {
  let nodes = 0, bytes = 0;
  const seen = new WeakSet<object>();
  const visit = (item: unknown, depth: number): void => {
    if (++nodes > 100_000 || depth > 32) comparisonFail('GOVERNANCE_COMPARISON_COMPLEXITY');
    if (item === null || typeof item === 'boolean') return;
    if (typeof item === 'string') { bytes += Buffer.byteLength(item); if (bytes > 32 * 1024 * 1024) comparisonFail('GOVERNANCE_COMPARISON_TOO_LARGE'); return; }
    if (typeof item === 'number' && Number.isFinite(item)) return;
    if (!item || typeof item !== 'object') comparisonFail('GOVERNANCE_COMPARISON_INVALID_JSON');
    if (seen.has(item) || !Array.isArray(item) && ![Object.prototype, null].includes(Object.getPrototypeOf(item))) comparisonFail('GOVERNANCE_COMPARISON_INVALID_JSON');
    seen.add(item);
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(item))) {
      if (Array.isArray(item) && key === 'length') continue;
      if (reserved.has(key) || !('value' in descriptor) || !descriptor.enumerable) comparisonFail('GOVERNANCE_COMPARISON_INVALID_JSON');
      visit(descriptor.value, depth + 1);
    }
    seen.delete(item);
  };
  visit(value, 0);
}

export const objectIdentity = (object: Pick<ComparisonObject, 'entityType' | 'nativeId' | 'parentId' | 'credentialKind'>): string =>
  object.entityType === 'credentials' ? `credentials:${object.credentialKind}:${object.parentId}:${object.nativeId}`
    : object.entityType === 'targets' ? `targets:${object.parentId}:${object.nativeId}` : `${object.entityType}:${object.nativeId}`;
export const pointerSegment = (value: string): string => value.replace(/~/g, '~0').replace(/\//g, '~1');
export const secretMarker = (value: unknown): boolean => typeof value === 'string' && /^(?:\[REDACTED(?:[:\]])|\[DEPTH_LIMIT\]|\[CIRCULAR\]|\*{3,}$)/.test(value);

function secretName(name: string): boolean {
  const compact = name.replace(/[^a-z\d]/gi, '').toLowerCase();
  if (publicSecretNames.has(compact)) return false;
  return ['key','keys','token','tokens','pwd','passwd','authorization','proxyauthorization','cookie','setcookie','credentials','jwt','headervalue','awsaccesskeyid','accesskeyid'].includes(compact)
    || /password|secret|privatekey|apikey|accesstoken|refreshtoken|idtoken|csrftoken|signingkey|provisionkey|clientkey/.test(compact);
}
function secretString(value: unknown): boolean {
  if(typeof value !== 'string')return false;
  let secretQuery=false;
  if(/^[a-z][a-z\d+.-]*:\/\//i.test(value))try{const url=new URL(value);secretQuery=!!url.username||!!url.password||[...url.searchParams.keys()].some(secretName);}catch{/* Not parsed as a network address. */}
  return secretQuery || (/-----BEGIN [^-]*PRIVATE KEY-----/.test(value) || /^(?:Bearer|Basic)\s+\S+/i.test(value)
    || /(?:^|[\s:])(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\s*[:=]/i.test(value)
    || /^[a-z][a-z\d+.-]*:\/\/[^/\s]*@/i.test(value));
}
const namedKey = (type: string, value: string): string => `${type}:${encodeURIComponent(value)}`;
const digest = (value: unknown): string => createHash('sha256').update(canonicalJson(value)).digest('hex');
const referenceId = (value: unknown): string | null => typeof value === 'string' ? value : value && typeof value === 'object' && !Array.isArray(value) && typeof (value as any).id === 'string' ? (value as any).id : null;
const sameReferenceType = (type: string, id: string): string => `${type}:${id.toLowerCase()}`;

export function assertComparisonPolicy(policy: ComparisonPolicy): void {
  assertComparisonJson({ ...policy, identityAliases: policy.identityAliases ?? {} });
  for (const flag of ['includeEnvironmentFields','includeSecrets','includeCredentials'] as const) if (policy[flag] !== undefined && typeof policy[flag] !== 'boolean') comparisonFail('GOVERNANCE_COMPARISON_INVALID_POLICY');
  if (Object.keys(policy.identityAliases ?? {}).length > 10_000) comparisonFail('GOVERNANCE_COMPARISON_INVALID_POLICY');
  for (const alias of Object.values(policy.identityAliases ?? {})) if (typeof alias !== 'string' || !/^[\p{L}\p{N}_.: /-]{1,128}$/u.test(alias) || secretString(alias)) comparisonFail('GOVERNANCE_COMPARISON_INVALID_ALIAS');
  if(policy.credentialKinds!==undefined&&(!policy.includeCredentials||!Array.isArray(policy.credentialKinds)||!policy.credentialKinds.length||policy.credentialKinds.length>6||new Set(policy.credentialKinds).size!==policy.credentialKinds.length||policy.credentialKinds.some(kind=>!['key-auth','basic-auth','jwt','oauth2','hmac-auth','acls'].includes(kind))))comparisonFail('GOVERNANCE_COMPARISON_INVALID_CREDENTIAL_KINDS');
}

/** All logical keys are independent of native UUIDs. Ambiguities block complete comparisons. */
export function normalizeLogicalGraph(inventory: ComparisonInventory, policy: ComparisonPolicy = {}): LogicalGraph {
  assertComparisonPolicy(policy);
  if (!Array.isArray(inventory.objects) || inventory.objects.length > 10_000) comparisonFail('GOVERNANCE_COMPARISON_OBJECT_LIMIT');
  assertComparisonJson(inventory.schemas); assertComparisonJson(inventory.pluginSchemas);
  const issues: ComparisonIssue[] = [], exclusions: FieldExclusion[] = [], bundle = comparisonSchemas(inventory);
  if (!isSupportedKong(inventory.version)) issues.push({ code: 'GOVERNANCE_KONG_VERSION_UNSUPPORTED' });
  if (inventory.completeness !== 'complete' || inventory.projection || inventory.consistency && inventory.consistency !== 'console_fenced_best_effort') issues.push({ code: 'GOVERNANCE_COMPARISON_INCOMPLETE' });
  const source = new Map<string, ComparisonObject>(), names = new Map<string, { key: string; kind: LogicalObject['identityKind'] }>();
  const existingLogical = new Map<string, string>();
  const originals = new Map<string, string>();
  let payloadBytes=0;
  for (const object of inventory.objects) {
    assertComparisonJson(object.payload);
    payloadBytes+=Buffer.byteLength(canonicalJson(object.payload));if(payloadBytes>32*1024*1024)comparisonFail('GOVERNANCE_COMPARISON_TOO_LARGE');
    if (!UUID.test(object.nativeId) || object.payload.id !== undefined && object.payload.id !== object.nativeId) comparisonFail('GOVERNANCE_COMPARISON_NATIVE_ID');
    if (object.parentId && !UUID.test(object.parentId)) comparisonFail('GOVERNANCE_COMPARISON_PARENT_ID');
    if(object.parentId&&['targets','credentials'].includes(object.entityType)&&referenceId(object.payload[object.entityType==='targets'?'upstream':'consumer'])!==object.parentId)comparisonFail('GOVERNANCE_COMPARISON_PARENT_ID');
    const native = sameReferenceType(object.entityType, object.nativeId);
    if (source.has(native)) comparisonFail('GOVERNANCE_COMPARISON_DUPLICATE_ID');
    source.set(native, object); originals.set(native, objectIdentity(object));
    if (object.sensitiveFields?.some((path: string) => typeof path !== 'string' || path.length > 512 || !path.startsWith('/'))) comparisonFail('GOVERNANCE_COMPARISON_SENSITIVE_POINTER');
  }
  const assign = (object: ComparisonObject, key: string, kind: LogicalObject['identityKind']): void => {
    const native = sameReferenceType(object.entityType, object.nativeId), previous = existingLogical.get(key);
    names.set(native, { key, kind });
    if (previous && previous !== native) issues.push({ code: 'GOVERNANCE_LOGICAL_IDENTITY_AMBIGUOUS', objectKey: objectIdentity(object) });
    else existingLogical.set(key, native);
  };
  const alias = (object: ComparisonObject): boolean => {
    const value = policy.identityAliases?.[objectIdentity(object)];
    if (value === undefined) return false;
    assign(object, namedKey(object.entityType, `alias:${value}`), 'alias'); return true;
  };
  const identity = (type: string, id: string | null): string | null => id ? names.get(sameReferenceType(type, id))?.key ?? null : null;
  for (const object of inventory.objects) {
    if (alias(object)) continue;
    const p = object.payload, type = object.entityType;
    if (['services','upstreams','snis'].includes(type) && typeof p.name === 'string' && p.name.length) assign(object, namedKey(type, p.name), 'named');
    else if (type === 'consumers' && (typeof p.username === 'string' && p.username.length || typeof p.custom_id === 'string' && p.custom_id.length)) assign(object, namedKey(type, typeof p.username === 'string' && p.username.length ? `username:${p.username}` : `custom_id:${p.custom_id}`), 'named');
    else if ((type === 'certificates' || type === 'ca_certificates') && typeof object.certificate?.fingerprint === 'string' && /^[a-f\d:]{64,95}$/i.test(object.certificate.fingerprint)) assign(object, `${type}:sha256:${object.certificate.fingerprint.replace(/:/g,'').toLowerCase()}`, 'certificate_fingerprint');
    else if ((type === 'certificates' || type === 'ca_certificates') && typeof p.cert === 'string' && !secretMarker(p.cert)) assign(object, `${type}:sha256:${digest(p.cert.replace(/\r\n/g, '\n').trim())}`, 'certificate_fingerprint');
  }
  for (const object of inventory.objects.filter(item => item.entityType === 'routes')) {
    if (names.has(sameReferenceType(object.entityType, object.nativeId))) continue;
    if (typeof object.payload.name === 'string' && object.payload.name.length) { assign(object, namedKey('routes', object.payload.name), 'named'); continue; }
    const service = identity('services', referenceId(object.payload.service));
    if (object.payload.service && !service) continue;
    const signature: Record<string, unknown> = { service };
    for (const field of ['protocols','methods','paths','snis','hosts','headers','sources','destinations']) {
      if (!policy.includeEnvironmentFields && ['snis','hosts','headers','sources','destinations'].includes(field)) continue;
      const value = object.payload[field];
      if (value !== undefined) signature[field] = Array.isArray(value) ? [...value].sort((a,b) => canonicalJson(a).localeCompare(canonicalJson(b))) : value;
    }
    if (Object.keys(signature).length === 1) continue;
    assign(object, `routes:anonymous:${digest(signature)}`, 'anonymous_signature');
  }
  for (const object of inventory.objects) {
    const native = sameReferenceType(object.entityType, object.nativeId);
    if (names.has(native)) continue;
    const p = object.payload;
    if (object.entityType === 'plugins' && typeof p.name === 'string') {
      const bindings: Record<string, string | null> = {}, valid = ['service','route','consumer'].every(field => {
        const id = referenceId(p[field]); bindings[field] = identity(`${field}s`, id); return !id || !!bindings[field];
      });
      if (valid) assign(object, `plugins:${encodeURIComponent(p.name)}:${digest(bindings)}`, 'binding');
    } else if (object.entityType === 'targets' && policy.includeEnvironmentFields && typeof p.target === 'string') {
      const parent = identity('upstreams', object.parentId ?? referenceId(p.upstream));
      if (parent) assign(object, `${parent}/targets:${encodeURIComponent(p.target)}`, 'binding');
    } else if (object.entityType === 'credentials' && policy.includeCredentials) {
      const parent = identity('consumers', object.parentId ?? referenceId(p.consumer)), label = p.username ?? (object.credentialKind === 'acls' ? p.group : object.credentialKind === 'oauth2' ? p.name : undefined);
      if (parent && typeof label === 'string' && !secretString(label) && !secretMarker(label)) assign(object, `${parent}/credentials:${object.credentialKind}:${encodeURIComponent(label)}`, 'binding');
    }
  }
  const included = (object: ComparisonObject): FieldExclusionReason | null => {
    if (object.managedBoundary && object.managedBoundary !== 'none') return 'managed_boundary';
    if (object.entityType === 'credentials' && !policy.includeCredentials) return 'credential';
    if(object.entityType==='credentials'&&policy.credentialKinds&&!policy.credentialKinds.includes(object.credentialKind!))return 'credential';
    if (['certificates','ca_certificates'].includes(object.entityType) && !policy.includeSecrets) return 'certificate_material';
    if (['targets','snis'].includes(object.entityType) && !policy.includeEnvironmentFields) return 'environment';
    return null;
  };
  const output: LogicalObject[] = [];
  for (const object of inventory.objects) {
    const objectKey = objectIdentity(object), exclusion = included(object);
    if (exclusion) { exclusions.push({ objectKey, field: '', reason: exclusion }); continue; }
    const logical = names.get(sameReferenceType(object.entityType, object.nativeId));
    if (!logical) { issues.push({ code: 'GOVERNANCE_LOGICAL_IDENTITY_REQUIRED', objectKey }); continue; }
    if(object.entityType==='plugins'&&!inventory.enabledPlugins.includes(String(object.payload.name)))issues.push({code:'GOVERNANCE_PLUGIN_UNAVAILABLE',objectKey});
    let fields: Record<string, any>;
    try { fields = schemaFields(entitySchema(bundle, object.entityType, object.credentialKind)); }
    catch { issues.push({ code: 'GOVERNANCE_SCHEMA_UNAVAILABLE', objectKey }); continue; }
    const refs: Record<string, string | readonly string[]> = {}, sensitive = new Set<string>(object.sensitiveFields ?? []);
    const exclude = (path: string, reason: FieldExclusionReason): undefined => { exclusions.push({ objectKey, field: path, reason }); return undefined; };
    const visit = (value: unknown, definition: any, path: string, name: string): unknown => {
      const dot = path.slice(1).split('/').map(part => part.replace(/~1/g,'/').replace(/~0/g,'~')).join('.');
      const isSecret = sensitive.has(path) || secretName(name) || definition?.encrypted === true || definition?.sensitive === true || secretString(value)
        || name === 'headers' || name === 'functions' || name === 'lua' || name === 'code';
      if (isSecret) sensitive.add(path);
      if (isSecret && !policy.includeSecrets) return exclude(path, 'secret');
      if (secretMarker(value)) { if (policy.includeSecrets) issues.push({ code: 'GOVERNANCE_SECRET_MATERIAL_UNAVAILABLE', objectKey, field: path }); return exclude(path, 'secret'); }
      const env = environmental[object.entityType]?.includes(dot) || object.entityType === 'plugins' && (/(?:^|_)(?:host|hosts|port|ports|url|uri|endpoint|endpoints|address|addresses|region|socket|path)$/.test(name)
        || typeof value === 'string' && /^[a-z][a-z\d+.-]*:\/\//i.test(value));
      if (env && !policy.includeEnvironmentFields) return exclude(path, 'environment');
      // 1.5 authentication plugins expose this Consumer FK as a UUID string,
      // rather than a schema foreign record. Native source UUIDs cannot cross
      // environments unchanged merely because the field is typed as string.
      if(object.entityType==='plugins'&&path==='/config/anonymous'&&authenticationAnonymousConsumerPlugin(object.payload.name)&&value!==null&&value!==undefined){
        const ref=typeof value==='string'?identity('consumers',value):null;
        if(!ref){issues.push({code:'GOVERNANCE_REFERENCE_UNRESOLVED',objectKey,field:path});return undefined;}
        refs[path]=ref;return{logical_ref:ref};
      }
      if (definition?.type === 'foreign' && value !== null) {
        const ref = identity(definition.reference, referenceId(value));
        if (!ref) { issues.push({ code: 'GOVERNANCE_REFERENCE_UNRESOLVED', objectKey, field: path }); return undefined; }
        refs[path] = ref; return { logical_ref: ref };
      }
      if (Array.isArray(value)) {
        const result: unknown[] = [];
        for (let index = 0; index < value.length; index++) {
          const child = visit(value[index], definition?.elements ?? {}, `${path}/${index}`, name);
          // A partially excluded array is not a valid deployment value.
          if (child === undefined) return undefined;
          result.push(child);
        }
        if (definition?.type === 'set') return result.sort((a,b) => canonicalJson(a).localeCompare(canonicalJson(b)));
        return result;
      }
      if (value && typeof value === 'object') {
        const result: Record<string, unknown> = {}, childFields = definition?.fields ? schemaFields(definition) : null;
        for (const [key, child] of Object.entries(value)) {
          const normalized = visit(child, childFields?.[key] ?? definition?.values ?? {}, `${path}/${pointerSegment(key)}`, key);
          if (normalized !== undefined) result[key] = normalized;
        }
        return result;
      }
      return value;
    };
    const payload: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(object.payload)) {
      const path = `/${pointerSegment(name)}`;
      if (metadata.has(name) || object.entityType === 'certificates' && name === 'snis') { exclude(path, 'metadata'); continue; }
      if (!Object.hasOwn(fields, name)) { issues.push({ code: 'GOVERNANCE_SCHEMA_UNKNOWN_FIELD', objectKey, field: path }); continue; }
      if (name === 'tags') {
        if (value !== null && (!Array.isArray(value) || value.some(tag => typeof tag !== 'string'))) comparisonFail('GOVERNANCE_INVALID_TAGS');
        const tags = (value as string[] | null ?? []).map(decodeTag).filter(tag => {
          if (!tag.startsWith('workspace:')) return true;
          exclude(path, 'workspace_tag'); return false;
        });
        payload.tags = [...new Set(tags)].sort(); continue;
      }
      let definition = fields[name];
      if (object.entityType === 'plugins' && name === 'config') {
        if (!builtinPlugins.has(String(object.payload.name))) { exclude(path, 'unknown_plugin'); continue; }
        const plugin = inventory.pluginSchemas[String(object.payload.name)];
        if (!plugin) { issues.push({ code: 'GOVERNANCE_PLUGIN_SCHEMA_UNAVAILABLE', objectKey }); continue; }
        definition = { type: 'record', fields: schemaFields(plugin) };
      }
      const projected = visit(value, definition, path, name);
      if (projected !== undefined) payload[name] = projected;
    }
    if(object.entityType==='services'&&typeof payload.host==='string'){
      const upstream=inventory.objects.find(candidate=>candidate.entityType==='upstreams'&&candidate.payload.name===payload.host);
      if(upstream){const key=identity('upstreams',upstream.nativeId);if(key)refs['/host']=key;}
    }
    const parentType = object.entityType === 'targets' ? 'upstreams' : object.entityType === 'credentials' ? 'consumers' : null;
    const parent = parentType ? identity(parentType, object.parentId ?? referenceId(object.payload[parentType === 'upstreams' ? 'upstream' : 'consumer'])) : null;
    output.push({ logicalKey: logical.key, objectKey, nativeId: object.nativeId, entityType: object.entityType, credentialKind: object.credentialKind,
      identityKind: logical.kind, ...(parent ? { parentLogicalKey: parent } : {}), payload, referenceFields: refs, sensitiveFields: [...sensitive].sort() });
  }
  return { scope: structuredClone(inventory.scope), objects: output.sort((a,b) => a.logicalKey.localeCompare(b.logicalKey)), exclusions, issues,
    identities:Object.fromEntries([...names.entries()].map(([native,logical])=>[originals.get(native)!,logical.key])),
    complete: issues.length === 0 && inventory.completeness === 'complete' && !inventory.projection };
}

/** Redaction is conservative even if a caller mistakenly supplies raw secrets. */
export function safeComparisonValue(value: unknown, path = '', sensitiveFields: readonly string[] = []): unknown {
  const sensitive = sensitiveFields.some(pointer => path === pointer || path.startsWith(`${pointer}/`));
  if (sensitive || secretString(value) || secretMarker(value)) return '[REDACTED]';
  if (Array.isArray(value)) return value.map((child,index) => safeComparisonValue(child, `${path}/${index}`, sensitiveFields));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key,child]) => [key, secretName(key) || key === 'headers' || key === 'functions' ? '[REDACTED]' : safeComparisonValue(child, `${path}/${pointerSegment(key)}`, sensitiveFields)]));
  return value;
}
