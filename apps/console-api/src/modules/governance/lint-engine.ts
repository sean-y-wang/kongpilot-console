import { Worker } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';
import {
  GOVERNANCE_NATIVE_TYPES, GovernanceLintError, type GovernanceAnalysisOptions, type GovernanceAnalysisResult,
  type GovernanceLintContext, type GovernanceLintRule, type GovernanceNativeType, type LintFinding,
  type LintObject, type LintPredicate, type LintRuleResult, type LintScalar,
} from './lint-types';

const reserved = new Set(['__proto__', 'prototype', 'constructor', '$ref', '$include', '<<']);
const marker = /\[REDACTED(?:[:\]])|\[DEPTH_LIMIT\]|\[CIRCULAR\]|-----BEGIN .*PRIVATE KEY-----|^(?:Bearer|Basic)\s+\S+/i;
const maxRules = 200, maxObjects = 10_000, regexBytesLimit = 2 * 1024 * 1024;
const missing = Symbol('governance-missing');
type Value = unknown | typeof missing;
type Verdict = { state: 'pass' | 'fail' | 'unknown'; field?: string; reason?: string };
type PathPart = string | '*';
type RegexCase = { pattern: string; value: string };
const regexWorkerSource = `const { parentPort, workerData } = require('node:worker_threads');
const compiled = new Map(); const output = [];
for (const item of workerData) { try { let regex = compiled.get(item.pattern);
  if (!regex) { regex = new RegExp(item.pattern); compiled.set(item.pattern, regex); }
  output.push(regex.test(item.value)); } catch { output.push(null); } }
parentPort.postMessage(output);`;
let activeWorkers = 0;

/** Fixed worker source; user patterns are data, never executable source. The
 * whole run shares one 250ms worker budget, rather than 250ms per object. */
async function runRegexBatch(cases: readonly RegexCase[], timeoutMs: number): Promise<readonly (boolean | null)[]> {
  if (!cases.length) return [];
  if (activeWorkers >= 4 || timeoutMs <= 0) return cases.map(() => null);
  activeWorkers++;
  return new Promise(resolve => {
    const started = performance.now();
    let worker: Worker;
    try { worker = new Worker(regexWorkerSource, { eval: true, workerData: cases,
      resourceLimits: { maxOldGenerationSizeMb: 16, maxYoungGenerationSizeMb: 4, stackSizeMb: 1 } }); }
    catch { activeWorkers--; resolve(cases.map(() => null)); return; }
    let settled = false, executionTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (output: readonly (boolean | null)[]) => {
      if (settled) return; settled = true; clearTimeout(startupTimer); if (executionTimer) clearTimeout(executionTimer);
      void worker.terminate().then(() => { activeWorkers--; }, () => { activeWorkers--; }); resolve(output);
    };
    // Node startup competes with builds/test workers. It has a separate bounded
    // 1s watchdog inside the same run deadline; regex execution remains 250ms.
    const startupTimer = setTimeout(() => finish(cases.map(() => null)), Math.min(1000, timeoutMs));
    worker.once('online', () => { clearTimeout(startupTimer); const remaining = timeoutMs - (performance.now() - started);
      if (remaining <= 0) finish(cases.map(() => null)); else executionTimer = setTimeout(() => finish(cases.map(() => null)), Math.min(250, remaining)); });
    worker.once('message', output => finish(Array.isArray(output) && output.length === cases.length
      && output.every(item => item === true || item === false || item === null) ? output : cases.map(() => null)));
    worker.once('error', () => finish(cases.map(() => null))); worker.once('exit', () => finish(cases.map(() => null)));
  });
}

function fail(code: string, path?: string): never { throw new GovernanceLintError(code, path); }
function plain(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
/** Avoid invoking getters while validating untrusted in-memory values too. */
function assertJson(value: unknown, maxNodes = 128, maxDepth = 16): void {
  const seen = new WeakSet<object>(); let nodes = 0, bytes = 0;
  const visit = (item: unknown, depth: number): void => {
    if (++nodes > maxNodes || depth > maxDepth) fail('GOVERNANCE_RULE_COMPLEXITY');
    if (item === null || typeof item === 'boolean') return;
    if (typeof item === 'number') { if (!Number.isFinite(item)) fail('GOVERNANCE_RULE_INVALID_SCALAR'); return; }
    if (typeof item === 'string') { bytes += Buffer.byteLength(item); if (bytes > 16_384 || marker.test(item)) fail('GOVERNANCE_RULE_UNSAFE_VALUE'); return; }
    if (!item || typeof item !== 'object' || !Array.isArray(item) && !plain(item)) fail('GOVERNANCE_RULE_INVALID_OBJECT');
    if (seen.has(item)) fail('GOVERNANCE_RULE_CYCLIC'); seen.add(item);
    for (const key of Reflect.ownKeys(item)) {
      if (typeof key !== 'string') fail('GOVERNANCE_RULE_RESERVED_PROPERTY');
      const descriptor = Object.getOwnPropertyDescriptor(item, key)!;
      if (Array.isArray(item) && key === 'length') continue;
      if (reserved.has(key) || !Object.hasOwn(descriptor, 'value')) fail('GOVERNANCE_RULE_RESERVED_PROPERTY');
      bytes += Buffer.byteLength(key); visit(descriptor.value, depth + 1);
    }
    seen.delete(item);
  }; visit(value, 0);
}
function keys(value: Record<string, unknown>, allowed: readonly string[]): void {
  if (Object.keys(value).some(key => !allowed.includes(key))) fail('GOVERNANCE_RULE_UNKNOWN_PROPERTY');
}
function scalar(value: unknown): value is LintScalar { return value === null || ['string', 'boolean', 'number'].includes(typeof value) && (typeof value !== 'number' || Number.isFinite(value)); }
export function parseLintPath(path: string): readonly PathPart[] {
  if (!path || path.length > 256) fail('GOVERNANCE_RULE_INVALID_PATH');
  const parts: PathPart[] = []; let remaining = path;
  while (remaining.length) {
    const field = /^[A-Za-z_][A-Za-z0-9_-]*/.exec(remaining);
    if (!field || reserved.has(field[0])) fail('GOVERNANCE_RULE_INVALID_PATH');
    const compact = field[0].replace(/[^a-z\d]/gi, '').toLowerCase();
    if (!['keyname', 'keynames', 'keyid', 'keyids', 'secretisbase64', 'enablepasswordgrant', 'tokenexpiration', 'keyclaimname'].includes(compact)
      && (compact === 'key' || compact === 'keys' || /password|secret|privatekey|apikey|accesstoken|refreshtoken|authorization|cookie/.test(compact))) fail('GOVERNANCE_RULE_INVALID_PATH');
    parts.push(field[0]); remaining = remaining.slice(field[0].length);
    while (remaining.startsWith('[*]')) { parts.push('*'); remaining = remaining.slice(3); }
    if (remaining.length) { if (!remaining.startsWith('.') || remaining.length === 1) fail('GOVERNANCE_RULE_INVALID_PATH'); remaining = remaining.slice(1); }
    if (parts.length > 16) fail('GOVERNANCE_RULE_INVALID_PATH');
  }
  return parts;
}
function validatePredicate(input: unknown): asserts input is LintPredicate {
  if (!plain(input)) fail('GOVERNANCE_RULE_INVALID_PREDICATE');
  if (Object.hasOwn(input, 'all') || Object.hasOwn(input, 'any')) {
    const key = Object.hasOwn(input, 'all') ? 'all' : 'any'; keys(input, [key]);
    const children = input[key]; if (!Array.isArray(children) || !children.length || children.length > 32) fail('GOVERNANCE_RULE_INVALID_BOOLEAN');
    children.forEach(validatePredicate); return;
  }
  if (Object.hasOwn(input, 'not')) { keys(input, ['not']); validatePredicate(input.not); return; }
  if (input.path !== undefined) { if (typeof input.path !== 'string') fail('GOVERNANCE_RULE_INVALID_PATH'); parseLintPath(input.path); }
  const base = ['path', 'op'];
  switch (input.op) {
    case 'required': case 'https_only': keys(input, base); return;
    case 'exists': keys(input, [...base, 'value']); if (input.value !== undefined && typeof input.value !== 'boolean') fail('GOVERNANCE_RULE_INVALID_VALUE'); return;
    case 'type': keys(input, [...base, 'value']); if (!['string', 'number', 'integer', 'boolean', 'array', 'record', 'null'].includes(String(input.value))) fail('GOVERNANCE_RULE_INVALID_VALUE'); return;
    case 'enum': keys(input, [...base, 'values']); if (!Array.isArray(input.values) || !input.values.length || input.values.length > 64 || !input.values.every(scalar)) fail('GOVERNANCE_RULE_INVALID_VALUE'); return;
    case 'equals': case 'includes': keys(input, [...base, 'value']); if (!scalar(input.value)) fail('GOVERNANCE_RULE_INVALID_VALUE'); return;
    case 'min': case 'max': keys(input, [...base, 'value']); if (typeof input.value !== 'number' || !Number.isFinite(input.value)) fail('GOVERNANCE_RULE_INVALID_VALUE'); return;
    case 'length': keys(input, [...base, 'min', 'max']); if (input.min === undefined && input.max === undefined
      || [input.min, input.max].some(value => value !== undefined && (!Number.isInteger(value) || Number(value) < 0 || Number(value) > 1_000_000))
      || input.min !== undefined && input.max !== undefined && Number(input.min) > Number(input.max)) fail('GOVERNANCE_RULE_INVALID_VALUE'); return;
    case 'tags_contains': keys(input, [...base, 'value', 'match']); if (typeof input.value !== 'string' || !input.value.length || input.value.length > 256
      || input.match !== undefined && !['exact', 'prefix'].includes(String(input.match))) fail('GOVERNANCE_RULE_INVALID_VALUE'); return;
    case 'reference_exists': keys(input, [...base, 'entityType', 'by']); if (!(GOVERNANCE_NATIVE_TYPES as readonly unknown[]).includes(input.entityType)
      || input.by !== undefined && !['id', 'name'].includes(String(input.by))) fail('GOVERNANCE_RULE_INVALID_VALUE'); return;
    case 'matches': keys(input, [...base, 'pattern']); if (typeof input.pattern !== 'string' || !input.pattern.length || input.pattern.length > 1024) fail('GOVERNANCE_RULE_INVALID_VALUE'); return;
    default: fail('GOVERNANCE_RULE_UNKNOWN_PREDICATE');
  }
}
/** Validates and freezes rule copies, so mutating a caller object cannot change
 * a running analysis. No eval, JSONPath function, SQL or network fetch exists. */
export function validateLintRules(input: unknown): readonly GovernanceLintRule[] {
  if (!Array.isArray(input) || input.length > maxRules) fail('GOVERNANCE_RULE_LIMIT');
  if (Reflect.ownKeys(input).some(key => typeof key !== 'string')) fail('GOVERNANCE_RULE_RESERVED_PROPERTY');
  for (const [key, property] of Object.entries(Object.getOwnPropertyDescriptors(input))) if (key !== 'length'
    && (!/^\d+$/.test(key) || !Object.hasOwn(property, 'value'))) fail('GOVERNANCE_RULE_RESERVED_PROPERTY');
  const seen = new Set<string>();
  for (const rule of input) {
    assertJson(rule); if (Buffer.byteLength(JSON.stringify(rule)) > 16_384 || !plain(rule)) fail('GOVERNANCE_RULE_COMPLEXITY');
    keys(rule, ['code', 'given', 'then', 'severity', 'description', 'enabled']);
    if (typeof rule.code !== 'string' || !/^[a-z][a-z0-9_.-]{0,95}$/.test(rule.code) || seen.has(rule.code)) fail('GOVERNANCE_RULE_INVALID_CODE'); seen.add(rule.code);
    if (!['error', 'warn', 'info'].includes(String(rule.severity)) || typeof rule.description !== 'string' || !rule.description.trim()
      || rule.description.length > 500 || typeof rule.enabled !== 'boolean' || !plain(rule.given)) fail('GOVERNANCE_RULE_INVALID_VALUE');
    keys(rule.given, ['entityTypes', 'path', 'where']);
    if (!Array.isArray(rule.given.entityTypes) || !rule.given.entityTypes.length || rule.given.entityTypes.length > GOVERNANCE_NATIVE_TYPES.length
      || new Set(rule.given.entityTypes).size !== rule.given.entityTypes.length || !rule.given.entityTypes.every(value => (GOVERNANCE_NATIVE_TYPES as readonly unknown[]).includes(value))) fail('GOVERNANCE_RULE_INVALID_ENTITY');
    if (rule.given.path !== undefined) { if (typeof rule.given.path !== 'string') fail('GOVERNANCE_RULE_INVALID_PATH'); parseLintPath(rule.given.path); }
    if (rule.given.where !== undefined) validatePredicate(rule.given.where); validatePredicate(rule.then);
  }
  const freeze = (value: any): any => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
  return freeze(structuredClone(input)) as readonly GovernanceLintRule[];
}

export class AnalysisMeter {
  readonly started = performance.now(); readonly operationLimit: number; readonly deadlineMs: number;
  readonly findingLimit: number; readonly regexCaseLimit: number; operations = 0; regexCases = 0; exhausted = false;
  constructor(options: GovernanceAnalysisOptions = {}) {
    const bounded = (value: number | undefined, fallback: number, maximum: number) => value === undefined ? fallback
      : Number.isInteger(value) && value > 0 && value <= maximum ? value : fail('GOVERNANCE_ANALYSIS_INVALID_BUDGET');
    this.operationLimit = bounded(options.operationLimit, 100_000, 200_000); this.deadlineMs = bounded(options.deadlineMs, 2000, 5000);
    this.findingLimit = bounded(options.findingLimit, 10_000, 10_000); this.regexCaseLimit = bounded(options.regexCaseLimit, 10_000, 10_000);
  }
  spend(amount = 1): boolean { this.operations += amount; if (this.operations > this.operationLimit || performance.now() - this.started >= this.deadlineMs) this.exhausted = true; return !this.exhausted; }
  snapshot() { return { operationLimit: this.operationLimit, operations: this.operations, deadlineMs: this.deadlineMs,
    findingLimit: this.findingLimit, regexCaseLimit: this.regexCaseLimit, regexCases: this.regexCases, exhausted: this.exhausted }; }
}
function own(value: unknown, key: string): Value {
  if (!value || typeof value !== 'object' || reserved.has(key)) return missing;
  const descriptor = Object.getOwnPropertyDescriptor(value, key); return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : missing;
}
function valuesAt(value: Value, path: string | undefined, meter: AnalysisMeter): readonly Value[] {
  if (!path) return [value]; let current: readonly Value[] = [value];
  for (const part of parseLintPath(path)) {
    const next: Value[] = [];
    for (const item of current) {
      if (!meter.spend()) return [missing];
      if (part === '*') {
        if (!Array.isArray(item)) { next.push(missing); continue; }
        if (item.length > 256 || next.length + item.length > 256) { meter.exhausted = true; return [missing]; }
        for (let i = 0; i < item.length; i++) next.push(own(item, String(i)));
      } else next.push(own(item, part));
    }
    current = next;
  }
  return current;
}
export function governanceFieldSupport(context: GovernanceLintContext, type: GovernanceNativeType, field: string): 'supported' | 'not_supported' | 'unknown' {
  const schema = context.schemas?.[type]; if (!plain(schema)) return 'unknown'; const fields = own(schema, 'fields');
  if (Array.isArray(fields)) return fields.some(item => !!item && typeof item === 'object' && Object.hasOwn(item, field)) ? 'supported' : 'not_supported';
  if (plain(fields)) return Object.hasOwn(fields, field) ? 'supported' : 'not_supported'; return 'unknown';
}
function pathSupport(context: GovernanceLintContext, object: LintObject, path: string): 'supported' | 'not_supported' | 'unknown' {
  const parts = parseLintPath(path); let definition: unknown = context.schemas?.[object.entityType];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part === '*') { definition = own(definition, 'elements'); if (definition === missing) return 'unknown'; continue; }
    if (i === 1 && parts[0] === 'config' && object.entityType === 'plugins') {
      const name = own(object.payload, 'name'); definition = typeof name === 'string' ? context.pluginSchemas?.[name] : undefined;
    }
    if (!plain(definition)) return 'unknown';
    if (own(definition, 'type') === 'map') { definition = own(definition, 'values'); continue; }
    if (own(definition, 'type') === 'foreign') { if (part === 'id' && i === parts.length - 1) return 'supported'; return 'not_supported'; }
    const fields = own(definition, 'fields');
    if (Array.isArray(fields)) { const found = fields.find(item => plain(item) && Object.hasOwn(item, part)); if (!found) return 'not_supported'; definition = own(found, part); }
    else if (plain(fields)) { if (!Object.hasOwn(fields, part)) return 'not_supported'; definition = own(fields, part); }
    else return 'unknown';
  }
  return 'supported';
}
export function createGovernanceReferenceResolver(context: GovernanceLintContext) {
  const present = new Set<string>(), absentTypes = new Set<GovernanceNativeType>();
  for (const object of context.objects) { present.add(`${object.entityType}:id:${object.nativeId}`); const name = own(object.payload, 'name'); if (typeof name === 'string') present.add(`${object.entityType}:name:${name}`); }
  const direct = new Map((context.referenceObservations ?? []).map(observation => [`${observation.entityType}:${observation.nativeId}`, observation]));
  if (context.completeness === 'complete' && !context.projection) for (const collection of context.collections)
    if (collection.extent === 'cluster' && collection.complete && !collection.parentId) absentTypes.add(collection.entityType);
  return (type: GovernanceNativeType, id: string, by: 'id' | 'name' = 'id'): 'present' | 'absent' | 'unknown' => {
    if (present.has(`${type}:${by}:${id}`)) return 'present'; const observation = by === 'id' ? direct.get(`${type}:${id}`) : undefined;
    if (observation?.state === 'present') return 'present'; if (observation?.state === 'absent' && observation.authoritative) return 'absent';
    if (observation?.state === 'forbidden' || observation?.state === 'unavailable') return 'unknown'; return absentTypes.has(type) ? 'absent' : 'unknown';
  };
}
export function governanceReferenceState(context: GovernanceLintContext, type: GovernanceNativeType, id: string, by: 'id' | 'name' = 'id') { return createGovernanceReferenceResolver(context)(type, id, by); }
function combine(results: readonly Verdict[], mode: 'all' | 'any'): Verdict {
  if (mode === 'all') return results.find(result => result.state === 'fail') ?? results.find(result => result.state === 'unknown') ?? { state: 'pass' };
  return results.find(result => result.state === 'pass') ?? results.find(result => result.state === 'unknown') ?? results[0] ?? { state: 'fail' };
}
function potentialSecret(value: unknown): boolean { return typeof value === 'string' && marker.test(value); }
function regexSupported(pattern: string): boolean { return !/\\[AZzKgNQERXCGpPhHvV]|\[\[(?::|=|\.)|\(\?>|\(\?\(|\(\?[imsx-]|\(\?P|\(\?\||(?:\*|\+|\?|\})\+/.test(pattern); }
type WorkItem = { rule: GovernanceLintRule; object: LintObject; value: Value; unsupported?: string };

export async function evaluateLintRules(context: GovernanceLintContext, input: unknown, options: GovernanceAnalysisOptions = {}, sharedMeter?: AnalysisMeter): Promise<GovernanceAnalysisResult> {
  const rules = validateLintRules(input), meter = sharedMeter ?? new AnalysisMeter(options), findings: LintFinding[] = [], reasonCodes = new Set<string>();
  if (context.objects.length > maxObjects) fail('GOVERNANCE_INVENTORY_OBJECT_LIMIT');
  const byType = new Map<GovernanceNativeType, LintObject[]>();
  const sensitive = new WeakMap<LintObject, readonly string[] | null>();
  for (const object of context.objects) { if (!meter.spend()) break; if (!(GOVERNANCE_NATIVE_TYPES as readonly string[]).includes(object.entityType)
      || typeof object.nativeId !== 'string' || !/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(object.nativeId) || !plain(object.payload)) fail('GOVERNANCE_INVENTORY_INVALID_OBJECT');
    const paths = object.sensitiveFields ?? [];
    sensitive.set(object, paths.length > 256 || paths.some(path => typeof path !== 'string' || path.length > 256) ? null
      : paths.map(path => path.replace(/^\//, '').replace(/\//g, '.')));
    if (!object.referenceOnly && object.selected !== false) { const list = byType.get(object.entityType) ?? []; list.push(object); byType.set(object.entityType, list); } }
  const referenceState = createGovernanceReferenceResolver(context);
  const results = new Map<string, { ruleCode: string; evaluatedObjects: number; failedObjects: number; notEvaluatedObjects: number; skippedObjects: number; state: LintRuleResult['state'] }>();
  const cases: RegexCase[] = [], caseIndex = new Map<string, number>(); let regexBytes = 0;
  const keyFor = (pattern: string, value: string) => JSON.stringify([pattern, value]);
  const collect = (predicate: LintPredicate, value: Value): void => {
    if (!meter.spend()) return;
    if ('all' in predicate) { predicate.all.forEach(child => collect(child, value)); return; }
    if ('any' in predicate) { predicate.any.forEach(child => collect(child, value)); return; }
    if ('not' in predicate) { collect(predicate.not, value); return; }
    if (predicate.op !== 'matches') return;
    for (const item of valuesAt(value, predicate.path, meter)) if (typeof item === 'string' && item.length <= 1024 && !potentialSecret(item) && regexSupported(predicate.pattern)) {
      const key = keyFor(predicate.pattern, item); if (caseIndex.has(key)) continue;
      if (cases.length >= meter.regexCaseLimit || regexBytes + Buffer.byteLength(key) > regexBytesLimit) { reasonCodes.add('REGEX_CASE_BUDGET_EXHAUSTED'); continue; }
      regexBytes += Buffer.byteLength(key); caseIndex.set(key, cases.length); cases.push({ pattern: predicate.pattern, value: item });
    }
  };
  const work: WorkItem[] = [];
  for (const rule of rules) {
    const result = { ruleCode: rule.code, evaluatedObjects: 0, failedObjects: 0, notEvaluatedObjects: 0, skippedObjects: 0, state: rule.enabled ? 'evaluated' : 'disabled' } as const;
    results.set(rule.code, { ...result }); if (!rule.enabled) continue;
    for (const type of rule.given.entityTypes) for (const object of byType.get(type) ?? []) {
      if (!meter.spend()) break;
      const support = rule.given.path ? pathSupport(context, object, rule.given.path) : 'supported';
      const selected = valuesAt(object.payload, rule.given.path, meter);
      for (const value of selected) { if (!meter.spend()) break; work.push({ rule, object, value, unsupported: support !== 'supported' ? support === 'not_supported' ? 'FIELD_NOT_SUPPORTED_BY_SCHEMA' : 'SCHEMA_SUPPORT_UNAVAILABLE' : undefined }); if (rule.given.where) collect(rule.given.where, value); collect(rule.then, value); }
    }
  }
  meter.regexCases = cases.length;
  const regexResults = await runRegexBatch(cases, meter.deadlineMs - (performance.now() - meter.started));
  const evaluate = (predicate: LintPredicate, value: Value, object: LintObject, nested = false): Verdict => {
    if (!meter.spend()) return { state: 'unknown', reason: 'ANALYSIS_BUDGET_EXHAUSTED' };
    if ('all' in predicate) return combine(predicate.all.map(child => evaluate(child, value, object, nested)), 'all');
    if ('any' in predicate) return combine(predicate.any.map(child => evaluate(child, value, object, nested)), 'any');
    if ('not' in predicate) { const result = evaluate(predicate.not, value, object, nested); return { ...result, state: result.state === 'unknown' ? 'unknown' : result.state === 'pass' ? 'fail' : 'pass' }; }
    if (!nested && predicate.path) { const supported = pathSupport(context, object, predicate.path);
      if (supported !== 'supported') return { state: 'unknown', field: predicate.path, reason: supported === 'not_supported' ? 'FIELD_NOT_SUPPORTED_BY_SCHEMA' : 'SCHEMA_SUPPORT_UNAVAILABLE' }; }
    const maskedPaths = sensitive.get(object);
    if (predicate.path && (maskedPaths === null || !meter.spend(maskedPaths?.length ?? 0)
      || maskedPaths?.some(field => field === predicate.path || predicate.path!.startsWith(field + '.')))) return { state: 'unknown', field: predicate.path, reason: 'FIELD_MASKED' };
    const values = valuesAt(value, predicate.path, meter);
    return combine(values.map(item => {
      const field = predicate.path, pass = (ok: boolean): Verdict => ({ state: ok ? 'pass' : 'fail', field });
      const unknown = (reason: string): Verdict => ({ state: 'unknown', field, reason });
      if (potentialSecret(item)) return unknown('FIELD_MASKED');
      if (typeof item === 'string' && item.length > 16_384 && !['length', 'exists', 'type', 'equals', 'enum'].includes(predicate.op)) return unknown('FIELD_INPUT_LIMIT');
      if (Array.isArray(item) && ['includes', 'tags_contains', 'https_only'].includes(predicate.op)) {
        if (!meter.spend(item.length) || item.length > 10_000) return unknown('ANALYSIS_BUDGET_EXHAUSTED');
        for (let index = 0; index < item.length; index++) { const property = Object.getOwnPropertyDescriptor(item, String(index));
          if (!property || !Object.hasOwn(property, 'value')) return unknown('FIELD_INVALID_OBJECT'); }
      }
      if (predicate.op === 'exists') return pass((item !== missing) === (predicate.value ?? true));
      if (predicate.op === 'required') return pass(item !== missing && item !== null && item !== undefined && !(typeof item === 'string' && !item.trim()) && !(Array.isArray(item) && !item.length));
      if (item === missing) return unknown('FIELD_MISSING');
      switch (predicate.op) {
        case 'type': return pass(predicate.value === 'null' ? item === null : predicate.value === 'array' ? Array.isArray(item) : predicate.value === 'record' ? plain(item)
          : predicate.value === 'integer' ? Number.isInteger(item) : typeof item === predicate.value && (predicate.value !== 'number' || Number.isFinite(item)));
        case 'enum': return pass(predicate.values.some(value => Object.is(value, item)));
        case 'equals': return pass(Object.is(item, predicate.value));
        case 'includes': return Array.isArray(item) ? pass(item.some(value => Object.is(value, predicate.value))) : typeof item === 'string' && typeof predicate.value === 'string' ? pass(item.includes(predicate.value)) : pass(false);
        case 'min': return pass(typeof item === 'number' && item >= predicate.value);
        case 'max': return pass(typeof item === 'number' && item <= predicate.value);
        case 'length': { const length = typeof item === 'string' || Array.isArray(item) ? item.length : null; return pass(length !== null && (predicate.min === undefined || length >= predicate.min) && (predicate.max === undefined || length <= predicate.max)); }
        case 'tags_contains': return pass(Array.isArray(item) && item.some(value => typeof value === 'string' && (predicate.match === 'prefix' ? value.startsWith(predicate.value) && value.length > predicate.value.length : value === predicate.value)));
        case 'https_only': return pass(Array.isArray(item) && item.length > 0 && item.every(protocol => typeof protocol === 'string' && ['https', 'grpcs', 'tls'].includes(protocol)));
        case 'reference_exists': { const id = typeof item === 'string' ? item : own(item, 'id'); if (typeof id !== 'string' || !id) return item === null ? pass(true) : unknown('REFERENCE_VALUE_INVALID');
          const state = referenceState(predicate.entityType, id, predicate.by); return state === 'unknown' ? unknown('REFERENCE_EXISTENCE_UNPROVEN') : pass(state === 'present'); }
        case 'matches': { if (typeof item !== 'string') return pass(false); if (item.length > 1024 || !regexSupported(predicate.pattern)) return unknown('REGEX_UNSUPPORTED_OR_INPUT_LIMIT');
          const index = caseIndex.get(keyFor(predicate.pattern, item)), match = index === undefined ? null : regexResults[index]; return match === true || match === false ? pass(match) : unknown('REGEX_UNAVAILABLE_OR_TIMEOUT'); }
      }
    }), 'all');
  };
  for (const item of work) {
    const result = results.get(item.rule.code)!;
    if (meter.exhausted) { result.notEvaluatedObjects++; result.state = 'partial'; continue; }
    const nested = !!item.rule.given.path;
    if (item.rule.given.where && !item.unsupported) { const where = evaluate(item.rule.given.where, item.value, item.object, nested); if (where.state === 'fail') { result.skippedObjects++; continue; }
      if (where.state === 'unknown') { result.notEvaluatedObjects++; result.state = 'partial'; reasonCodes.add(where.reason ?? 'FILTER_NOT_EVALUATED'); continue; } }
    const verdict = item.unsupported ? { state: 'unknown' as const, field: item.rule.given.path, reason: item.unsupported } : evaluate(item.rule.then, item.value, item.object, nested);
    if (verdict.state === 'pass') { result.evaluatedObjects++; continue; }
    if (verdict.state === 'fail') { result.evaluatedObjects++; result.failedObjects++; } else { result.notEvaluatedObjects++; result.state = 'partial'; reasonCodes.add(verdict.reason ?? 'RULE_NOT_EVALUATED'); }
    if (findings.length >= meter.findingLimit) { meter.exhausted = true; continue; }
    findings.push({ code: 'LINT_ASSERTION', ruleCode: item.rule.code, severity: item.rule.severity, status: verdict.state === 'fail' ? 'confirmed' : 'not_evaluated',
      entityType: item.object.entityType, nativeId: item.object.nativeId, field: verdict.field ?? item.rule.given.path ?? null,
      description: item.rule.description, reasonCodes: verdict.reason ? [verdict.reason] : [], fixCodes: [] });
  }
  if (meter.exhausted) reasonCodes.add('ANALYSIS_BUDGET_EXHAUSTED');
  if (context.completeness !== 'complete') reasonCodes.add('INVENTORY_INCOMPLETE'); if (context.projection) reasonCodes.add('AUTHORIZED_PROJECTION');
  return { findings, ruleResults: [...results.values()], complete: !meter.exhausted && context.completeness === 'complete' && !context.projection
    && ![...results.values()].some(result => result.state === 'partial'), reasonCodes: [...reasonCodes], budget: meter.snapshot() };
}
