import {
  GOVERNANCE_NATIVE_TYPES, type GovernanceAnalysisOptions, type GovernanceAnalysisResult, type GovernanceFixCode,
  type GovernanceLintContext, type GovernanceLintRule, type GovernanceNativeType, type LintFinding, type LintObject,
} from './lint-types';
import { AnalysisMeter, createGovernanceReferenceResolver, evaluateLintRules, governanceFieldSupport, validateLintRules } from './lint-engine';

export const GOVERNANCE_ENGINE_VERSION = 'kong-1.5-governance-v1';
export const BUILTIN_LINT_RULES: readonly GovernanceLintRule[] = [
  { code: 'builtin.route_https', given: { entityTypes: ['routes'] }, then: { path: 'protocols', op: 'https_only' }, severity: 'error', description: 'Route 应仅使用 HTTPS、GRPCS 或 TLS 安全协议。', enabled: true },
  { code: 'builtin.service_timeouts', given: { entityTypes: ['services'] }, then: { all: ['connect_timeout', 'write_timeout', 'read_timeout'].map(path => ({ all: [{ path, op: 'required' as const }, { path, op: 'min' as const, value: 1 }] })) }, severity: 'warn', description: 'Service 应具有有效的连接、写入和读取超时配置。', enabled: true },
  { code: 'builtin.naming', given: { entityTypes: ['services', 'routes', 'upstreams'], where: { path: 'name', op: 'required' } }, then: { path: 'name', op: 'matches', pattern: '^[a-z][a-z0-9._-]{0,62}$' }, severity: 'warn', description: '建议对象名称使用小写字母、数字、点、下划线或连字符，且不超过 63 字符。', enabled: true },
];
export interface GovernanceInspectionOptions extends GovernanceAnalysisOptions {
  readonly rules?: readonly GovernanceLintRule[];
  readonly builtinRules?: readonly GovernanceLintRule[];
  readonly namingPattern?: string;
  /** Explicit cluster policy; no assertion that every gateway must use global auth. */
  readonly securityBaselinePlugins?: readonly string[];
  readonly includeBuiltins?: boolean;
}
function data(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object') return undefined; const property = Object.getOwnPropertyDescriptor(value, key);
  return property && Object.hasOwn(property, 'value') ? property.value : undefined;
}
function ref(value: unknown): string | null { const id = typeof value === 'string' ? value : data(value, 'id'); return typeof id === 'string' && id.length ? id : null; }
function strings(value: unknown): string[] {
  if (!Array.isArray(value)) return []; const result: string[] = [];
  for (let i = 0; i < Math.min(256, value.length); i++) { const item = data(value, String(i)); if (typeof item === 'string') result.push(item); } return result;
}
function completeCluster(context: GovernanceLintContext, type: GovernanceNativeType): boolean {
  return context.completeness === 'complete' && !context.projection && context.collections.some(collection => collection.entityType === type && !collection.parentId && collection.complete && collection.extent === 'cluster');
}
function uniqueFields(schema: unknown): string[] {
  const fields = data(schema, 'fields'); const entries = Array.isArray(fields) ? fields.flatMap(item => item && typeof item === 'object' ? Object.entries(item) : [])
    : fields && typeof fields === 'object' ? Object.entries(fields) : [];
  return entries.filter(([name, definition]) => name !== 'id' && data(definition, 'unique') === true).map(([name]) => name);
}
function compatible(a: string[], b: string[]): boolean { return !a.length || !b.length || a.some(value => b.includes(value)); }
function hostOverlap(a: string, b: string): boolean {
  if (a === b) return true; if (!a.includes('*') && !b.includes('*')) return false;
  if (a.startsWith('*.') && !b.includes('*')) return b.endsWith(a.slice(1));
  if (b.startsWith('*.') && !a.includes('*')) return a.endsWith(b.slice(1));
  if (a.endsWith('.*') && !b.includes('*')) return b.startsWith(a.slice(0, -1));
  if (b.endsWith('.*') && !a.includes('*')) return a.startsWith(b.slice(0, -1)); return true;
}
/** An overlap is a routing review hint. Kong accepts overlapping routes; this
 * never labels a host/path/method overlap as a database409. */
function mayOverlap(a: LintObject, b: LintObject): boolean {
  if (!compatible(strings(data(a.payload, 'protocols')), strings(data(b.payload, 'protocols')))
    || !compatible(strings(data(a.payload, 'methods')), strings(data(b.payload, 'methods')))) return false;
  const ah = strings(data(a.payload, 'hosts')).map(value => value.toLowerCase()), bh = strings(data(b.payload, 'hosts')).map(value => value.toLowerCase());
  if (ah.length && bh.length && !ah.some(left => bh.some(right => hostOverlap(left, right)))) return false;
  const ap = strings(data(a.payload, 'paths')), bp = strings(data(b.payload, 'paths'));
  const plain = /^[a-zA-Z0-9.\-_~/%]*$/;
  if (ap.length && bp.length && !ap.some(left => bp.some(right => !plain.test(left) || !plain.test(right) || left.startsWith(right) || right.startsWith(left)))) return false;
  return true;
}

export async function inspectGovernanceInventory(context: GovernanceLintContext, options: GovernanceInspectionOptions = {}): Promise<GovernanceAnalysisResult> {
  const meter = new AnalysisMeter(options), selected = context.objects.filter(object => !object.referenceOnly && object.selected !== false);
  const effectiveRules = new Map(validateLintRules(options.includeBuiltins === false ? [] : options.builtinRules ?? BUILTIN_LINT_RULES).map(rule => [rule.code, rule]));
  for (const rule of validateLintRules(options.rules ?? [])) effectiveRules.set(rule.code, rule);
  if (options.includeBuiltins !== false && options.namingPattern && !(options.rules ?? []).some(rule => rule.code === 'builtin.naming')) effectiveRules.set('builtin.naming', { ...BUILTIN_LINT_RULES[2], then: { path: 'name', op: 'matches', pattern: options.namingPattern }, description: '对象名称不符合当前集群命名规范。' });
  const rules = [...effectiveRules.values()];
  // References remain available to structural checks but are not ordinary selected lint targets.
  const lint = await evaluateLintRules(context, rules, options, meter);
  const unchangedBuiltin = (code: string) => { const effective = rules.find(rule => rule.code === code), builtin = BUILTIN_LINT_RULES.find(rule => rule.code === code);
    return !!effective && !!builtin && JSON.stringify(effective.then) === JSON.stringify(builtin.then) && JSON.stringify(effective.given) === JSON.stringify(builtin.given); };
  const namingRule = rules.find(rule => rule.code === 'builtin.naming');
  const safeNamingFix = !!namingRule && 'op' in namingRule.then && namingRule.then.op === 'matches' && namingRule.then.path === 'name'
    && JSON.stringify(namingRule.given) === JSON.stringify(BUILTIN_LINT_RULES[2].given);
  const findings: LintFinding[] = lint.findings.map(finding => ({ ...finding, fixCodes: finding.status !== 'confirmed' ? []
    : finding.ruleCode === 'builtin.route_https' && unchangedBuiltin(finding.ruleCode) ? ['route_https_only'] : finding.ruleCode === 'builtin.service_timeouts' && unchangedBuiltin(finding.ruleCode) ? ['service_timeouts_set']
      : finding.ruleCode === 'builtin.naming' && safeNamingFix ? ['entity_rename'] : [] }));
  const reasons = new Set(lint.reasonCodes), referenceState = createGovernanceReferenceResolver(context);
  const usedCertificates = new Set<string>();
  for (const object of context.objects) { if (!meter.spend()) break;
    const id = object.entityType === 'snis' ? ref(data(object.payload, 'certificate')) : object.entityType === 'services' ? ref(data(object.payload, 'client_certificate')) : null;
    if (id) usedCertificates.add(id); }
  const push = (object: LintObject | null, code: string, description: string, details: { field?: string; severity?: 'error' | 'warn' | 'info'; status?: LintFinding['status']; reason?: string; fixCodes?: GovernanceFixCode[]; related?: LintObject[]; ruleCode?: string } = {}) => {
    if (!meter.spend() || findings.length >= meter.findingLimit) { meter.exhausted = true; return; }
    const status = details.status ?? 'confirmed'; if (status === 'not_evaluated') reasons.add(details.reason ?? 'STRUCTURAL_CHECK_NOT_EVALUATED');
    findings.push({ code, ruleCode: details.ruleCode ?? `builtin.${code.toLowerCase()}`, severity: details.severity ?? 'warn', status,
      entityType: object?.entityType ?? null, nativeId: object?.nativeId ?? null, field: details.field ?? null, description,
      reasonCodes: details.reason ? [details.reason] : [], fixCodes: status === 'confirmed' ? details.fixCodes ?? [] : [],
      ...(details.related ? { relatedObjects: details.related.slice(0, 8).map(item => ({ entityType: item.entityType, nativeId: item.nativeId })) } : {}) });
  };
  const checkRef = (object: LintObject, field: string, type: GovernanceNativeType, value: unknown, code: string) => {
    if (!meter.spend()) return; if (governanceFieldSupport(context, object.entityType, field) !== 'supported') return;
    const id = ref(value); if (!id) return; const state = referenceState(type, id);
    if (state === 'absent') push(object, code, '引用的对象不存在。', { field, severity: 'error', reason: 'AUTHORITATIVE_REFERENCE_ABSENT', fixCodes: ['reference_replace_or_clear'] });
    else if (state === 'unknown') push(object, code, '当前采集范围不能证明引用对象是否存在。', { field, status: 'not_evaluated', reason: 'REFERENCE_EXISTENCE_UNPROVEN' });
  };
  for (const object of selected) {
    if (!meter.spend()) break;
    const rawTags = data(object.payload, 'tags'), annotation = object.annotations;
    let taggedOwner = false, tagsUnknown = false;
    if (Array.isArray(rawTags)) {
      if (rawTags.length > 10_000 || !meter.spend(rawTags.length)) tagsUnknown = true;
      else for (let i = 0; i < rawTags.length; i++) { const tag = data(rawTags, String(i));
        if (typeof tag !== 'string') { tagsUnknown = true; break; }
        if (tag.startsWith('owner:') && tag.slice(6).trim().length > 0) { taggedOwner = true; break; } }
    } else if (rawTags !== null && rawTags !== undefined) tagsUnknown = true;
    if (!taggedOwner && !annotation?.ownerUserId) {
      if (tagsUnknown) push(object, 'OWNER_MISSING', '标签集合未能完整检查，未判断是否缺少负责人。', { field: 'tags', status: 'not_evaluated', reason: 'TAG_COLLECTION_NOT_EVALUATED' });
      else if (annotation?.state === 'not_authorized' || !annotation) push(object, 'OWNER_MISSING', '负责人信息不可见，未判断是否缺少负责人。', { field: 'tags', status: 'not_evaluated', reason: 'ANNOTATION_NOT_AUTHORIZED' });
      else push(object, 'OWNER_MISSING', '对象未设置 owner 标签或控制台负责人。', { field: 'tags', fixCodes: ['owner_tag_add'] });
    }
    if (annotation?.state === 'not_authorized' || !annotation) push(object, 'DESCRIPTION_MISSING', '描述信息不可见，未判断是否缺少描述。', { status: 'not_evaluated', reason: 'ANNOTATION_NOT_AUTHORIZED' });
    else if (!annotation.description?.trim()) push(object, 'DESCRIPTION_MISSING', '对象未设置控制台描述。', { severity: 'info', fixCodes: ['annotation_description_set'] });
    if (object.entityType === 'plugins') for (const [field, type] of [['service', 'services'], ['route', 'routes'], ['consumer', 'consumers']] as const)
      checkRef(object, field, type, data(object.payload, field), 'PLUGIN_ORPHAN_REFERENCE');
    if (object.entityType === 'routes') checkRef(object, 'service', 'services', data(object.payload, 'service'), 'ROUTE_INVALID_SERVICE');
    if (object.entityType === 'snis') checkRef(object, 'certificate', 'certificates', data(object.payload, 'certificate'), 'SNI_INVALID_CERTIFICATE');
    if (object.entityType === 'services') {
      checkRef(object, 'client_certificate', 'certificates', data(object.payload, 'client_certificate'), 'SERVICE_INVALID_CLIENT_CERTIFICATE');
      const cas = data(object.payload, 'ca_certificates'); if (Array.isArray(cas)) for (const value of cas.slice(0, 256)) checkRef(object, 'ca_certificates', 'ca_certificates', value, 'SERVICE_INVALID_CA_CERTIFICATE');
      // A DNS/IP Service.host is valid. Upstream-name policy is opt-in through a custom reference_exists rule.
    }
    if (object.entityType === 'certificates') {
      const used = usedCertificates.has(object.nativeId);
      if (!used && completeCluster(context, 'snis') && completeCluster(context, 'services')) push(object, 'CERTIFICATE_UNUSED', '证书未被 SNI 或 Service 客户端证书引用。', { severity: 'info', fixCodes: ['unused_certificate_archive'] });
      else if (!used) push(object, 'CERTIFICATE_UNUSED', '缺少完整的 SNI 与客户端证书引用覆盖，未判断证书是否闲置。', { status: 'not_evaluated', reason: 'REFERENCE_COLLECTION_INCOMPLETE' });
    }
  }
  {
    for (const type of GOVERNANCE_NATIVE_TYPES) for (const field of uniqueFields(context.schemas?.[type])) {
      const seen = new Map<unknown, LintObject>();
      for (const object of context.objects) {
        if (!meter.spend()) break; if (object.entityType !== type) continue; const value = data(object.payload, field);
        if (typeof value !== 'string' || !value.length) continue; const previous = seen.get(value);
        if (previous && (!object.referenceOnly && object.selected !== false || !previous.referenceOnly && previous.selected !== false))
          push(object, 'UNIQUE_FIELD_CONFLICT', '当前 schema 标记为 unique 的字段出现重值，会阻止相同配置写入。', { field, severity: 'error', reason: 'SCHEMA_UNIQUE_CONFLICT', related: [previous], fixCodes: ['entity_rename'] });
        else seen.set(value, object);
      }
    }
    const bindings = new Map<string, LintObject>();
    for (const object of context.objects) {
      if (!meter.spend()) break; if (object.entityType !== 'plugins') continue;
      const name = data(object.payload, 'name'); if (typeof name !== 'string') continue;
      const key = JSON.stringify([name, ...['service', 'route', 'consumer'].map(field => ref(data(object.payload, field)))]), previous = bindings.get(key);
      if (previous) push(object, 'PLUGIN_BINDING_DUPLICATE', '同名插件使用相同绑定范围，需复核重复实例。', { field: 'name', status: 'potential', reason: 'BINDING_TUPLE_OVERLAP', related: [previous] }); else bindings.set(key, object);
    }
    const routes = selected.filter(object => object.entityType === 'routes' && ['protocols', 'methods', 'hosts', 'paths'].every(field => {
      const value = data(object.payload, field); if (Array.isArray(value) && value.length > 256) {
        push(object, 'ROUTE_POTENTIAL_OVERLAP', 'Route 匹配条件超过有界检查预算，未判断其重叠关系。', { field, status: 'not_evaluated', reason: 'ROUTE_CONDITION_BUDGET_EXHAUSTED' }); return false; } return true;
    }));
    outer: for (let i = 0; i < routes.length; i++) for (let j = i + 1; j < routes.length; j++) {
      const complexity = ['protocols', 'methods', 'hosts', 'paths'].reduce((sum, field) => { const a = data(routes[i].payload, field), b = data(routes[j].payload, field);
        return sum + Math.max(1, Array.isArray(a) ? a.length : 0) * Math.max(1, Array.isArray(b) ? b.length : 0); }, 1);
      if (!meter.spend(complexity)) break outer;
      if (mayOverlap(routes[i], routes[j])) push(routes[j], 'ROUTE_POTENTIAL_OVERLAP', 'Route 的协议、host、path、method 可能重叠；这不是必然的 409 冲突。', { status: 'potential', reason: 'MATCH_CONDITIONS_OVERLAP', related: [routes[i]] });
    }
    for (const name of options.securityBaselinePlugins ?? []) {
      if (!meter.spend()) break;
      if (!/^[a-z][a-z0-9-]{0,95}$/.test(name)) continue;
      if (!completeCluster(context, 'plugins')) { push(null, 'SECURITY_BASELINE_MISSING', '未取得集群完整插件覆盖，不能判断全局安全基线。', { status: 'not_evaluated', reason: 'PLUGIN_COLLECTION_NOT_CLUSTER_COMPLETE', ruleCode: `builtin.security_baseline.${name}` }); continue; }
      if (!context.enabledPlugins?.includes(name)) { push(null, 'SECURITY_BASELINE_MISSING', `当前集群未提供安全基线插件 ${name}。`, { status: 'not_evaluated', reason: 'PLUGIN_NOT_ENABLED_ON_GATEWAY', ruleCode: `builtin.security_baseline.${name}` }); continue; }
      const enabledGlobal = context.objects.some(object => object.entityType === 'plugins' && data(object.payload, 'name') === name && data(object.payload, 'enabled') !== false
        && ['service', 'route', 'consumer'].every(field => !ref(data(object.payload, field))));
      if (!enabledGlobal) push(null, 'SECURITY_BASELINE_MISSING', `未启用全局安全基线插件 ${name}。`, { severity: 'error', ruleCode: `builtin.security_baseline.${name}`, fixCodes: ['baseline_plugin_configure'] });
    }
  }
  if (meter.exhausted) reasons.add('ANALYSIS_BUDGET_EXHAUSTED');
  return { findings, ruleResults: lint.ruleResults, complete: lint.complete && !meter.exhausted && !findings.some(finding => finding.status === 'not_evaluated'),
    reasonCodes: [...reasons], budget: meter.snapshot() };
}
