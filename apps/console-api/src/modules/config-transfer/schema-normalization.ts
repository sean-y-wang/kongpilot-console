import type { CapturedSchemaBundle, ConfigurationEntityType, ConfigurationCredentialKind } from '../configuration/configuration.types';
import { CREDENTIAL_SCHEMAS } from '../entities/entities.types';
import { canonicalJson } from '../../infrastructure/secret.service';
import { transferFail } from './transfer.types';
import { validatePluginBindings, validatePluginConfiguration } from '../plugin-center/plugin-validation';

export const UUID = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;
const forbidden = new Set(['__proto__', 'prototype', 'constructor', '$ref', '$include', '<<']);
const metadata = new Set(['created_at', 'updated_at', 'ttl']);
type Definition = Record<string, any>;

export function nativeId(value: unknown, path?: string): string {
  if (typeof value !== 'string' || !UUID.test(value)) transferFail('CONFIGURATION_NATIVE_ID_REQUIRED', path);
  return value.toLowerCase();
}
export function schemaFields(schema: unknown): Record<string, Definition> {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) transferFail('CONFIGURATION_INVALID_SCHEMA');
  const fields = (schema as Definition).fields;
  if (!fields || typeof fields !== 'object') transferFail('CONFIGURATION_INVALID_SCHEMA');
  const output: Record<string, Definition> = Object.create(null);
  const entries = Array.isArray(fields) ? fields.flatMap(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).length !== 1) transferFail('CONFIGURATION_INVALID_SCHEMA');
    return Object.entries(item);
  }) : Object.entries(fields);
  for (const [key, definition] of entries) {
    if (forbidden.has(key) || Object.hasOwn(output, key) || !definition || typeof definition !== 'object' || Array.isArray(definition)) transferFail('CONFIGURATION_INVALID_SCHEMA');
    output[key] = definition as Definition;
  }
  return output;
}
export function entitySchema(bundle: CapturedSchemaBundle, type: ConfigurationEntityType, kind?: ConfigurationCredentialKind | null): unknown {
  const key = type === 'credentials' ? kind && CREDENTIAL_SCHEMAS[kind] : type;
  if (!key || !Object.hasOwn(bundle.entities, key)) transferFail('CONFIGURATION_SCHEMA_UNAVAILABLE');
  return bundle.entities[key];
}

/** Never put captured generated secret defaults into deployment or an import plan. */
function secretDefault(name: string): boolean {
  const compact = name.replace(/[^a-z\d]/gi, '').toLowerCase();
  if (['keyname', 'keynames', 'keyid', 'keyids', 'secretisbase64', 'enablepasswordgrant', 'tokenexpiration'].includes(compact)) return false;
  return compact === 'key' || compact === 'keys' || compact === 'token' || compact === 'credentials' || /password|secret|privatekey|apikey|accesstoken|authorization|cookie/.test(compact);
}
function containsSecretDefault(value: unknown): boolean {
  if (typeof value === 'string' && (/-----BEGIN .*PRIVATE KEY-----/.test(value) || /^(?:Bearer|Basic)\s+\S+/i.test(value))) return true;
  return !!value && typeof value === 'object' && Object.entries(value).some(([key, item]) => secretDefault(key) && item !== null || containsSecretDefault(item));
}
export function generatedFieldsMissing(payload: Record<string, unknown>, schema: unknown): readonly string[] {
  return Object.entries(schemaFields(schema)).filter(([key, definition]) => !metadata.has(key) && key !== 'id' && definition.auto === true && !Object.hasOwn(payload, key)).map(([key]) => key);
}
export function assertTransferJson(value: unknown): void {
  let count = 0; const seen = new WeakSet<object>();
  const visit = (item: unknown, depth: number): void => {
    if (++count > 50_000 || depth > 32) transferFail('CONFIGURATION_DOCUMENT_COMPLEXITY');
    if (item === undefined || typeof item === 'bigint' || typeof item === 'function' || typeof item === 'symbol' || typeof item === 'number' && !Number.isFinite(item)) transferFail('CONFIGURATION_INVALID_SCALAR');
    if (typeof item === 'string' && /^(?:\[REDACTED(?:[:\]])|\[DEPTH_LIMIT\]|\[CIRCULAR\]|\*{3,}$)/.test(item)) transferFail('CONFIGURATION_SECRET_MARKER');
    if (!item || typeof item !== 'object') return;
    if (seen.has(item)) transferFail('CONFIGURATION_CYCLIC_DOCUMENT'); seen.add(item);
    if (!Array.isArray(item) && ![Object.prototype, null].includes(Object.getPrototypeOf(item))) transferFail('CONFIGURATION_INVALID_OBJECT');
    if (Array.isArray(item)) { for (const child of item) visit(child, depth + 1); }
    else for (const [key, child] of Object.entries(item)) { if (forbidden.has(key)) transferFail('CONFIGURATION_RESERVED_KEY'); visit(child, depth + 1); }
    seen.delete(item);
  };
  visit(value, 0);
}

/** Normalize only supplied values unless the caller explicitly freezes create defaults. */
export function normalizeSchema(value: unknown, schema: unknown, options: { defaults?: boolean; required?: boolean; path?: string } = {}): Record<string, unknown> {
  assertTransferJson(value);
  const path = options.path || '';
  const normalize = (input: unknown, definition: Definition, name: string, current: string): unknown => {
    if (input === undefined) {
      if (options.defaults && Object.hasOwn(definition, 'default') && !secretDefault(name) && !containsSecretDefault(definition.default)) input = structuredClone(definition.default);
      // Kong 1.5 handle_missing_field expands a required concrete record on
      // insert so its children can supply defaults. Keep this create-only;
      // optional/abstract records and blocked secret defaults stay absent.
      else if (options.defaults && definition.type === 'record' && definition.required === true
        && definition.abstract !== true && !Object.hasOwn(definition, 'default')) input = {};
      else { if (options.required && definition.required === true) transferFail('CONFIGURATION_REQUIRED_FIELD', current); return undefined; }
    }
    if (input === null) { if (definition.required === true) transferFail('CONFIGURATION_REQUIRED_FIELD', current); return null; }
    const type = definition.type;
    if (type === 'foreign') {
      if (typeof input === 'string') return { id: nativeId(input, current) };
      if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 1 || !Object.hasOwn(input, 'id')) transferFail('CONFIGURATION_INVALID_REFERENCE', current);
      return { id: nativeId((input as any).id, current) };
    }
    if (type === 'string' && typeof input !== 'string' || type === 'boolean' && typeof input !== 'boolean'
      || type === 'integer' && !Number.isInteger(input) || type === 'number' && (typeof input !== 'number' || !Number.isFinite(input))) transferFail('CONFIGURATION_SCHEMA_VALUE', current);
    if (definition.uuid === true) input = nativeId(input, current);
    const choices = definition.one_of || definition.enum;
    if (Array.isArray(choices) && !choices.some(choice => canonicalJson(choice) === canonicalJson(input))) transferFail('CONFIGURATION_SCHEMA_ENUM', current);
    if (Array.isArray(definition.between) && typeof input === 'number' && (input < definition.between[0] || input > definition.between[1])) transferFail('CONFIGURATION_SCHEMA_RANGE', current);
    if (typeof input === 'number' && (definition.gt !== undefined && input <= definition.gt || definition.gte !== undefined && input < definition.gte || definition.lt !== undefined && input >= definition.lt || definition.lte !== undefined && input > definition.lte)) transferFail('CONFIGURATION_SCHEMA_RANGE', current);
    if (typeof input === 'string' && typeof definition.starts_with === 'string' && !input.startsWith(definition.starts_with)) transferFail('CONFIGURATION_SCHEMA_VALUE', current);
    if (typeof input === 'string' || Array.isArray(input)) {
      const length=typeof input==='string'?Buffer.byteLength(input,'utf8'):input.length;
      const minimum=typeof input==='string'&&type==='string'&&!Object.hasOwn(definition,'len_min')?1:definition.len_min;
      if (minimum !== undefined && length < minimum || definition.len_max !== undefined && length > definition.len_max || definition.len_eq !== undefined && length !== definition.len_eq) transferFail('CONFIGURATION_SCHEMA_LENGTH', current);
    }
    if (type === 'array' || type === 'set') {
      if (!Array.isArray(input)) transferFail('CONFIGURATION_SCHEMA_VALUE', current);
      const result = input.map((child, i) => normalize(child, definition.elements || {}, name, `${current}[${i}]`));
      if (Array.isArray(definition.mutually_exclusive_subsets) && !definition.mutually_exclusive_subsets.some((subset: unknown[]) => result.every(item => subset.some(allowed => canonicalJson(item) === canonicalJson(allowed))))) transferFail('CONFIGURATION_SCHEMA_SUBSET', current);
      if (type === 'set') return [...new Map(result.map(item => [canonicalJson(item), item])).entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, item]) => item);
      return result;
    }
    if (type === 'record' || type === 'map' || definition.fields) {
      if (!input || typeof input !== 'object' || Array.isArray(input)) transferFail('CONFIGURATION_SCHEMA_VALUE', current);
      if (type === 'map') {
        if (definition.len_min !== undefined && Object.keys(input).length < definition.len_min || definition.len_max !== undefined && Object.keys(input).length > definition.len_max) transferFail('CONFIGURATION_SCHEMA_LENGTH', current);
        const output: Record<string, unknown> = Object.create(null);
        for (const [key, child] of Object.entries(input)) output[key] = normalize(child, definition.values || {}, key, `${current}.${key}`);
        return output;
      }
      // Plugins' abstract config is checked separately against its old-style schema.
      if (definition.abstract === true && !definition.fields) return structuredClone(input);
      const fields = schemaFields(definition), output: Record<string, unknown> = Object.create(null);
      for (const key of Object.keys(input)) if (!Object.hasOwn(fields, key)) transferFail('CONFIGURATION_UNKNOWN_FIELD', `${current}.${key}`);
      for (const [key, child] of Object.entries(fields)) {
        const entry = normalize((input as any)[key], child, key, current ? `${current}.${key}` : key);
        if (entry !== undefined) output[key] = entry;
      }
      for (const rule of definition.entity_checks ?? []) {
        const present = (field: string): boolean => { const value = field.split('.').reduce<any>((item, part) => item && Object.hasOwn(item, part) ? item[part] : undefined, output); return value !== undefined && value !== null && !(typeof value === 'string' && !value.length) && !(typeof value === 'object' && !Object.keys(value).length); };
        if (Array.isArray(rule.at_least_one_of) && !rule.at_least_one_of.some(present)) transferFail('CONFIGURATION_SCHEMA_ENTITY_CHECK', current);
        if (Array.isArray(rule.only_one_of) && rule.only_one_of.filter(present).length > 1) transferFail('CONFIGURATION_SCHEMA_ENTITY_CHECK', current);
      }
      return output;
    }
    return structuredClone(input);
  };
  return normalize(value, { type: 'record', fields: schemaFields(schema) }, '', path) as Record<string, unknown>;
}

export function writableCapturedPayload(payload: Record<string, unknown>, entityType?: ConfigurationEntityType): Record<string, unknown> {
  const value = structuredClone(payload);
  for (const key of metadata) delete value[key];
  // The Certificate Admin response's names are an observed relation. Export
  // and restore use individually captured SNI IDs/ownership, never these names
  // to create or change a potentially foreign workspace's SNI association.
  if (entityType === 'certificates') delete value.snis;
  return value;
}
export function rejectReadOnlyInput(payload: Record<string, unknown>, path: string): void {
  for (const key of metadata) if (Object.hasOwn(payload, key)) transferFail('CONFIGURATION_READ_ONLY_FIELD', `${path}.${key}`);
}

export function normalizeEntityPayload(payload: Record<string, unknown>, bundle: CapturedSchemaBundle, type: ConfigurationEntityType, kind?: ConfigurationCredentialKind | null, defaults = false): Record<string, unknown> {
  const normalized = normalizeSchema(payload, entitySchema(bundle, type, kind), { defaults, required: defaults });
  if (type === 'plugins') {
    const name = normalized.name;
    if (typeof name !== 'string' || !bundle.enabledPlugins.includes(name) || !Object.hasOwn(bundle.plugins, name)) transferFail('CONFIGURATION_PLUGIN_UNAVAILABLE');
    if (Object.hasOwn(normalized, 'config') || defaults) normalized.config = normalizeSchema(normalized.config ?? {}, bundle.plugins[name], { defaults, required: defaults, path: 'config' });
    try { validatePluginBindings(name, normalized); validatePluginConfiguration(name, normalized.config ?? {}, bundle.plugins[name]); }
    catch { transferFail('CONFIGURATION_PLUGIN_CONSTRAINT'); }
  }
  return normalized;
}
