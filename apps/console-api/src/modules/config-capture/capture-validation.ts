import { BadGatewayException, ConflictException } from '@nestjs/common';
import { validateKnownFields } from '../../infrastructure/kong/schema';

export const CAPTURE_LIMITS = Object.freeze({ pages: 100, records: 10_000, objects: 10_000, bytes: 32 * 1024 * 1024, calls: 500, timeoutMs: 120_000, pageSize: 100 });
export const CORE_COLLECTIONS = Object.freeze(['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis'] as const);
export const CREDENTIAL_COLLECTIONS = Object.freeze(['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'] as const);
const uuid = /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i;

export function invalidCapture(code = 'CONFIGURATION_INVALID_NATIVE_GRAPH'): never {
  throw new BadGatewayException({ code, message: '网关返回的配置或关联无法证明完整，捕获已停止' });
}
export function captureLimit(): never {
  throw new ConflictException({ code: 'CONFIGURATION_CAPTURE_LIMIT', message: '配置捕获超过 100 页、10000 条记录、32 MiB、500 次原生请求或 120 秒，未发布完整快照' });
}
export function nativeUuid(value: unknown): string {
  if (typeof value !== 'string' || !uuid.test(value)) invalidCapture();
  return value.toLowerCase();
}
export function foreignUuid(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => key !== 'id')) invalidCapture();
  return nativeUuid((value as Record<string, unknown>).id);
}
export function captureJson(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalidCapture();
  let count = 0;
  const visit = (item: unknown, depth: number): void => {
    if (++count > 50_000 || depth > 32) invalidCapture('CONFIGURATION_NATIVE_JSON_LIMIT');
    if (item === undefined || typeof item === 'function' || typeof item === 'symbol' || typeof item === 'bigint' || typeof item === 'number' && !Number.isFinite(item)) invalidCapture();
    if (!item || typeof item !== 'object') return;
    if (Object.getPrototypeOf(item) !== Object.prototype && Object.getPrototypeOf(item) !== null && !Array.isArray(item)) invalidCapture();
    if (Array.isArray(item)) { for (const child of item) visit(child, depth + 1); return; }
    for (const [key, child] of Object.entries(item)) {
      if (['__proto__', 'prototype', 'constructor'].includes(key)) invalidCapture('CONFIGURATION_NATIVE_RESERVED_KEY');
      visit(child, depth + 1);
    }
  };
  visit(value, 0);
  nativeUuid((value as Record<string, unknown>).id);
  return structuredClone(value) as Record<string, unknown>;
}
export function schemaFields(schema: unknown): Record<string, any> {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) invalidCapture('CONFIGURATION_INVALID_SCHEMA');
  const fields = (schema as any).fields;
  if (!fields || typeof fields !== 'object') invalidCapture('CONFIGURATION_INVALID_SCHEMA');
  const result: Record<string, any> = Object.create(null);
  const entries = Array.isArray(fields) ? fields.flatMap(field => {
    if (!field || typeof field !== 'object' || Array.isArray(field) || Object.keys(field).length !== 1) invalidCapture('CONFIGURATION_INVALID_SCHEMA');
    return Object.entries(field);
  }) : Object.entries(fields);
  for (const [name, definition] of entries) {
    if (Object.hasOwn(result, name) || ['__proto__', 'prototype', 'constructor'].includes(name) || !definition || typeof definition !== 'object') invalidCapture('CONFIGURATION_INVALID_SCHEMA');
    result[name] = definition;
  }
  return result;
}
/** Validate observed values while preserving null, omission, false, zero and arrays. */
export function validateCapturedSchema(payload: Record<string, unknown>, schema: unknown, pluginSchema?: unknown, entityType?: string): void {
  const fields = schemaFields(schema), config = { ...payload };
  // Kong 1.5's Certificate Admin route adds SNI names to its DAO response.
  // Keep the original observation, but validate this one route relation
  // separately: it is not a writable DAO field or an unknown-field exception
  // for other entities. Typed SNI rows remain the authoritative graph edges.
  if (entityType === 'certificates' && Object.hasOwn(config, 'snis') && !Object.hasOwn(fields, 'snis')) {
    const names = config.snis;
    if (!Array.isArray(names) || names.length > CAPTURE_LIMITS.objects
      || names.some(name => typeof name !== 'string' || !name.length || name.length > 253)
      || new Set(names).size !== names.length) invalidCapture('CONFIGURATION_SCHEMA_VALUE_MISMATCH');
    delete config.snis;
  }
  // DAO timestamps and TTL metadata are captured separately; they are never
  // promoted to a writable configuration field or silently treated as restorable.
  for (const metadata of ['created_at', 'updated_at', 'ttl']) delete config[metadata];
  try { validateKnownFields(config, schema); }
  catch { invalidCapture('CONFIGURATION_SCHEMA_FIELD_MISMATCH'); }
  const value = (entry: unknown, definition: any): void => {
    if (entry === null) { if (definition.required === true) invalidCapture('CONFIGURATION_SCHEMA_VALUE_MISMATCH'); return; }
    if (entry === undefined) { if (definition.required === true) invalidCapture('CONFIGURATION_SCHEMA_VALUE_MISMATCH'); return; }
    const type = definition.type;
    if (type === 'string' && typeof entry !== 'string' || type === 'boolean' && typeof entry !== 'boolean'
      || type === 'integer' && (!Number.isInteger(entry)) || type === 'number' && (typeof entry !== 'number' || !Number.isFinite(entry))) invalidCapture('CONFIGURATION_SCHEMA_VALUE_MISMATCH');
    if (type === 'foreign') foreignUuid(entry);
    if (type === 'array' || type === 'set') {
      if (!Array.isArray(entry)) invalidCapture('CONFIGURATION_SCHEMA_VALUE_MISMATCH');
      for (const child of entry) value(child, definition.elements ?? {});
    }
    if (type === 'record' || type === 'map') {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) invalidCapture('CONFIGURATION_SCHEMA_VALUE_MISMATCH');
      if (type === 'map') for (const child of Object.values(entry)) value(child, definition.values ?? {});
      else if (definition.fields) {
        const nested = schemaFields(definition);
        for (const [name, child] of Object.entries(entry)) value(child, nested[name] ?? {});
      }
    }
    const choices = definition.one_of ?? definition.enum;
    if (Array.isArray(choices) && !choices.some(choice => JSON.stringify(choice) === JSON.stringify(entry))) invalidCapture('CONFIGURATION_SCHEMA_VALUE_MISMATCH');
  };
  for (const [name, definition] of Object.entries(fields)) if (definition.required === true && !Object.hasOwn(config, name)
    && !['created_at', 'updated_at', 'ttl'].includes(name)) invalidCapture('CONFIGURATION_SCHEMA_VALUE_MISMATCH');
  for (const [name, entry] of Object.entries(config)) value(entry, fields[name]);
  if (pluginSchema !== undefined && Object.hasOwn(config, 'config')) {
    try { validateKnownFields(config.config, pluginSchema, 'config'); }
    catch { invalidCapture('CONFIGURATION_SCHEMA_FIELD_MISMATCH'); }
    const pluginFields = schemaFields(pluginSchema);
    if (!config.config || typeof config.config !== 'object' || Array.isArray(config.config)) invalidCapture('CONFIGURATION_SCHEMA_VALUE_MISMATCH');
    for (const [name, entry] of Object.entries(config.config)) value(entry, pluginFields[name] ?? {});
  }
}

export class CaptureBudget {
  private readonly startedAt: number;
  pages = 0; records = 0; objects = 0; bytes = 0; calls = 0;
  constructor(private readonly clock: () => number = Date.now) { this.startedAt = clock(); }
  check(): void { if (this.clock() - this.startedAt >= CAPTURE_LIMITS.timeoutMs) captureLimit(); }
  request(page = false): void {
    this.check();
    if (this.calls >= CAPTURE_LIMITS.calls || page && (this.pages >= CAPTURE_LIMITS.pages || this.records + CAPTURE_LIMITS.pageSize > CAPTURE_LIMITS.records)) captureLimit();
    this.calls++; if (page) this.pages++;
  }
  response(value: unknown, records = 0): number {
    this.check();
    const bytes = Buffer.byteLength(JSON.stringify(value), 'utf8');
    if (!Number.isFinite(bytes) || this.bytes + bytes > CAPTURE_LIMITS.bytes || this.records + records > CAPTURE_LIMITS.records) captureLimit();
    this.bytes += bytes; this.records += records; return bytes;
  }
  object(): void { this.check(); if (this.objects >= CAPTURE_LIMITS.objects) captureLimit(); this.objects++; }
}
