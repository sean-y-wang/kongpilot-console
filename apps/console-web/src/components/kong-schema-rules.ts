/** Declarative Kong 1.x rules only. Lua validators are never executed in the browser. */
export type RulePath = (string | number)[];
export interface RuleSchema {
  type?: string; fields?: Record<string, RuleSchema>[] | Record<string, RuleSchema>; elements?: RuleSchema;
  keys?: RuleSchema; values?: RuleSchema; required?: boolean; auto?: boolean; default?: unknown;
  entity_checks?: Record<string, any>[]; [name: string]: any;
}
export interface SchemaIssue { path: RulePath; code: string; message: string; }
export interface FieldHint { required: boolean; constraints: Record<string, any>; messages: string[]; }
export interface SchemaAnalysis {
  issues: SchemaIssue[]; hints: Record<string, FieldHint>; remote_authoritative: true; unsupportedValidators: string[];
}
export const rulePathKey = (path: RulePath): string => JSON.stringify(path);
export function schemaFieldEntries(schema: RuleSchema): [string, RuleSchema][] {
  const fields = schema.fields ?? [];
  return Array.isArray(fields) ? fields.flatMap(entry => Object.entries(entry)) : Object.entries(fields);
}
const present = (value: any) => value !== undefined && value !== null;
const nonempty = (value: any) => present(value) && !(typeof value === 'string' && !value.length) && !(typeof value === 'object' && !Object.keys(value).length);
const own = (value: any, key: string) => value && typeof value === 'object' && Object.hasOwn(value, key) ? value[key] : undefined;
const segments = (name: string): RulePath => name.split('.').filter(Boolean);
const lookup = (value: any, path: RulePath): any => path.reduce((item, name) => own(item, String(name)), value);
export function isSensitiveSchemaName(name: string, valueType?: string): boolean {
  const compact = name.replace(/[^a-z\d]/gi, '').toLowerCase();
  if (['keynames', 'keyname', 'keyid', 'keyids', 'keyversion', 'credentialtype', 'credentialid', 'credentialids',
    'secretid', 'secretids', 'tokenexpiration', 'tokenendpoint', 'tokentype', 'tokenexp', 'tokenexpirationtime', 'refreshtokenttl',
    'secretisbase64', 'enablepasswordgrant'].includes(compact)) return false;
  if (compact === 'credentials') return valueType !== 'boolean';
  return ['key', 'keys', 'pwd', 'passwd', 'token', 'tokens', 'authorization', 'proxyauthorization', 'cookie', 'setcookie',
    'awskey', 'awsaccesskey', 'awsaccesskeyid', 'accesskey', 'accesskeyid', 'jwt', 'jwtkey', 'clientkey', 'headervalue'].includes(compact)
    || /password|secret|privatekey|apikey|accesstoken|refreshtoken|idtoken|provisionkey|signingkey/.test(compact);
}
/** Rule evaluation gets defaults; this does not change the submitted payload. */
function withDefaults(value: any, schema: RuleSchema, root = false): any {
  if (!present(value) && Object.hasOwn(schema, 'default')) value = structuredClone(schema.default);
  if (schema.type === 'record' || schema.fields) {
    // 1.5 expands absent required records; optional records remain unset.
    if (!present(value) && !root && schema.required !== true) return value;
    if (!present(value)) value = {};
    if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
    const result = Object.assign(Object.create(null), value);
    for (const [name, field] of schemaFieldEntries(schema)) result[name] = withDefaults(own(value, name), field);
    return result;
  }
  if (['array', 'set'].includes(schema.type ?? '') && Array.isArray(value)) return value.map(item => withDefaults(item, schema.elements ?? {}));
  if (schema.type === 'map' && value && typeof value === 'object' && !Array.isArray(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, withDefaults(item, schema.values ?? {})]));
  return value;
}
const constraints = new Set(['required', 'eq', 'ne', 'one_of', 'enum', 'len_min', 'len_max', 'between', 'gt', 'gte', 'lt', 'lte']);
function length(value: any): number | undefined {
  if (typeof value === 'string') return new TextEncoder().encode(value).length;
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === 'object') return Object.keys(value).length;
  return undefined;
}
function failures(value: any, definition: Record<string, any>): [string, string][] {
  const errors: [string, string][] = [];
  if (definition.required === true && !present(value)) errors.push(['required', '当前条件下必须填写']);
  if (Object.hasOwn(definition, 'eq') && (definition.eq === null ? present(value) : value !== definition.eq)) errors.push(['eq', `当前条件要求值为 ${JSON.stringify(definition.eq)}`]);
  if (Object.hasOwn(definition, 'ne') && (definition.ne === null ? !present(value) : value === definition.ne)) errors.push(['ne', `不能为 ${JSON.stringify(definition.ne)}`]);
  if (!present(value)) return errors;
  const choices = definition.one_of ?? definition.enum;
  if (Array.isArray(choices) && !choices.includes(value)) errors.push(['one_of', `请选择允许的值：${choices.map(String).join('、')}`]);
  const len = length(value);
  if (definition.len_min !== undefined && (len === undefined || len < definition.len_min)) errors.push(['len_min', `长度 / 项数至少为 ${definition.len_min}`]);
  if (definition.len_max !== undefined && (len === undefined || len > definition.len_max)) errors.push(['len_max', `长度 / 项数最多为 ${definition.len_max}`]);
  if (definition.between && (typeof value !== 'number' || value < definition.between[0] || value > definition.between[1])) errors.push(['between', `数值范围为 ${definition.between.join('–')}`]);
  for (const operator of ['gt', 'gte', 'lt', 'lte']) if (definition[operator] !== undefined) {
    const limit = definition[operator];
    const ok = typeof value === 'number' && (operator === 'gt' ? value > limit : operator === 'gte' ? value >= limit : operator === 'lt' ? value < limit : value <= limit);
    if (!ok) errors.push([operator, `数值必须 ${operator === 'gt' ? '大于' : operator === 'gte' ? '不小于' : operator === 'lt' ? '小于' : '不大于'} ${limit}`]);
  }
  return errors;
}

export function analyzeKongSchema(schema: RuleSchema, payload: any, options: { editing?: boolean } = {}): SchemaAnalysis {
  const report: SchemaAnalysis = { issues: [], hints: Object.create(null), remote_authoritative: true, unsupportedValidators: [] };
  const values = withDefaults(payload, schema, true);
  const issue = (path: RulePath, code: string, message: string) => {
    if (!report.issues.some(item => rulePathKey(item.path) === rulePathKey(path) && item.message === message)) report.issues.push({ path, code, message });
  };
  const unsupported = (path: RulePath, validator: string) => {
    const text = `${path.map(String).join('.') || '(root)'}: ${validator}`;
    if (!report.unsupportedValidators.includes(text)) report.unsupportedValidators.push(text);
  };
  const hint = (path: RulePath, definition: Record<string, any>, message?: string) => {
    const item = report.hints[rulePathKey(path)] ??= { required: false, constraints: Object.create(null), messages: [] };
    if (definition.required) item.required = true;
    Object.assign(item.constraints, definition);
    if (message && !item.messages.includes(message)) item.messages.push(message);
  };
  const visit = (value: any, field: RuleSchema, path: RulePath, depth: number) => {
    if (depth > 40) { unsupported(path, 'depth_limit'); return; }
    const name = String(path.at(-1) ?? '');
    const retainedSecret = options.editing && isSensitiveSchemaName(name, field.type) && !present(value);
    const checks = { ...field, required: !!field.required && !field.auto && !retainedSecret };
    hint(path, checks.required ? { required: true } : {});
    for (const [code, message] of failures(value, checks)) issue(path, code, message);
    for (const key of ['custom_validator', 'match', 'is_regex', 'uuid', 'contains', 'unique', 'not_match', 'match_all', 'match_none']) if (field[key] !== undefined) unsupported(path, key);
    if (!present(value)) return;
    if (field.type === 'boolean' && typeof value !== 'boolean') issue(path, 'type', '请输入布尔值');
    if (field.type === 'string' && typeof value !== 'string') issue(path, 'type', '请输入文本');
    if (['number', 'integer'].includes(field.type ?? '') && (typeof value !== 'number' || !Number.isFinite(value) || (field.type === 'integer' && !Number.isInteger(value)))) issue(path, 'type', field.type === 'integer' ? '请输入整数' : '请输入有限数值');
    const record = field.type === 'record' || !!field.fields;
    if ((record || field.type === 'map' || field.type === 'foreign') && (typeof value !== 'object' || Array.isArray(value))) { issue(path, 'type', '请输入对象'); return; }
    if (['array', 'set'].includes(field.type ?? '') && !Array.isArray(value)) { issue(path, 'type', '请输入列表'); return; }
    for (const rule of field.entity_checks ?? []) for (const [kind, condition] of Object.entries(rule)) {
      if (['at_least_one_of', 'only_one_of', 'mutually_required'].includes(kind) && Array.isArray(condition)) {
        const names = condition as string[], count = names.filter(key => nonempty(lookup(value, segments(key)))).length;
        if (kind === 'at_least_one_of' && count === 0) issue(path, kind, `至少填写一项：${names.join('、')}`);
        if (kind === 'only_one_of' && count !== 1) issue(path, kind, `必须且只能填写一项：${names.join('、')}`);
        if (kind === 'mutually_required' && count > 0) for (const key of names) {
          const target = [...path, ...segments(key)]; hint(target, { required: true }, `与 ${names.join('、')} 一同填写`);
          if (!nonempty(lookup(value, segments(key)))) issue(target, kind, '相关字段必须一同填写');
        }
      } else if (kind === 'conditional' && condition && typeof condition === 'object') {
        const current = condition as any;
        if (typeof current.if_field !== 'string' || typeof current.then_field !== 'string') { unsupported(path, kind); continue; }
        const match = current.if_match ?? {};
        if (current.else_match !== undefined) unsupported(path, 'conditional.else_match');
        if (Object.keys(match).some(key => !constraints.has(key))) { unsupported(path, 'conditional.if_match'); continue; }
        const ifValue = lookup(value, segments(current.if_field));
        if (!present(ifValue)) continue;
        const active = failures(ifValue, match).length === 0;
        // Kong 1.5 conditional has no else branch; unknown extensions stay remote.
        const requirement = active ? current.then_match : undefined;
        if (!requirement || typeof requirement !== 'object') continue;
        if (Object.keys(requirement).some(key => !constraints.has(key))) unsupported(path, 'conditional.then_match');
        const target = [...path, ...segments(current.then_field)];
        const supported = Object.fromEntries(Object.entries(requirement).filter(([key]) => constraints.has(key)));
        if (options.editing && isSensitiveSchemaName(String(target.at(-1))) && !present(lookup(value, segments(current.then_field)))) delete supported.required;
        hint(target, supported, `当 ${current.if_field} ${active ? '满足' : '不满足'}条件时${supported.required ? '必填' : '需满足取值约束'}`);
        for (const [code, message] of failures(lookup(value, segments(current.then_field)), supported)) issue(target, code, message);
      } else unsupported(path, kind);
    }
    if (record) for (const [key, child] of schemaFieldEntries(field)) visit(own(value, key), child, [...path, key], depth + 1);
    if (['array', 'set'].includes(field.type ?? '') && Array.isArray(value)) value.forEach((item, index) => visit(item, field.elements ?? {}, [...path, index], depth + 1));
    if (field.type === 'map') for (const [key, item] of Object.entries(value)) {
      for (const [code, message] of failures(key, field.keys ?? {})) issue([...path, key], code, `键名：${message}`);
      visit(item, field.values ?? {}, [...path, key], depth + 1);
    }
  };
  visit(values, schema, [], 0);
  return report;
}

/** Map the payload's map keys back to Ant Design Form.List row indexes. */
export function payloadPathToForm(schema: RuleSchema, formValues: any, path: RulePath): RulePath {
  const result: RulePath = []; let field = schema, value = formValues;
  for (const part of path) {
    if (field.type === 'map' && Array.isArray(value)) {
      const index = value.findIndex(row => row?.key === String(part));
      if (index < 0) { result.push(part); value = undefined; }
      else { result.push(index, 'value'); value = value[index]?.value; }
      field = field.values ?? {};
    } else if (['array', 'set'].includes(field.type ?? '')) { result.push(part); value = value?.[part]; field = field.elements ?? {}; }
    else { result.push(part); value = own(value, String(part)); field = Object.fromEntries(schemaFieldEntries(field))[part] ?? {}; }
  }
  return result;
}
