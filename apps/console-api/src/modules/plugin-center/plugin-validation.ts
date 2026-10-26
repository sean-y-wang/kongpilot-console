import { BadRequestException } from '@nestjs/common';
import { pluginMetadata, pluginRules } from './plugin-metadata';

function fieldsOf(schema: any): Record<string, any> { return Array.isArray(schema?.fields) ? Object.assign(Object.create(null), ...schema.fields) : schema?.fields || Object.create(null); }
function lookup(value: any, path: string): any { return path.split('.').reduce((entry, field) => entry && Object.hasOwn(entry, field) ? entry[field] : undefined, value); }
function present(value: any): boolean { return value !== undefined && value !== null; }
function nonempty(value: any): boolean { return present(value) && !(typeof value === 'string' && !value.length) && !(typeof value === 'object' && !Object.keys(value).length); }
function match(value: any, constraint: any): boolean | null {
  // Lua functions and unsupported predicates remain remote checks. Treating them
  // as true would incorrectly require conditionally optional custom fields.
  if (!constraint || typeof constraint !== 'object' || Object.keys(constraint).some(name => !['required', 'eq', 'one_of', 'len_min'].includes(name))) return null;
  if (constraint?.required && !present(value)) return false;
  if (Object.hasOwn(constraint || {}, 'eq') && value !== constraint.eq) return false;
  if (constraint?.one_of && !constraint.one_of.includes(value)) return false;
  if (constraint?.len_min !== undefined && (typeof value !== 'string' && !Array.isArray(value) || value.length < constraint.len_min)) return false;
  return true;
}
/** Apply defaults for rule evaluation only; never send generated values or compile Lua. */
export function ruleValues(value: any, schema: any): any {
  if (!present(value)) { if (Object.hasOwn(schema || {}, 'default')) value = structuredClone(schema.default); else if (schema?.type === 'record' || schema?.fields) value = {}; else return value; }
  if ((schema?.type === 'record' || schema?.fields) && value && typeof value === 'object' && !Array.isArray(value)) {
    const result = Object.assign(Object.create(null), value);
    for (const [name, definition] of Object.entries(fieldsOf(schema))) result[name] = ruleValues(Object.hasOwn(value, name) ? value[name] : undefined, definition);
    return result;
  }
  if (['array', 'set'].includes(schema?.type) && Array.isArray(value)) return value.map(item => ruleValues(item, schema.elements));
  if (schema?.type === 'map' && value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, ruleValues(item, schema.values)]));
  return value;
}
export function validatePluginConfiguration(name: string, config: any, schema: any): void {
  const values = ruleValues(config, schema), errors: Record<string, string> = Object.create(null);
  const check = (value: any, definition: any, path: string, extra: any[] = []) => {
    if (!present(value)) return;
    for (const rule of [...(definition?.entity_checks || []), ...extra]) {
      if (rule.at_least_one_of && !rule.at_least_one_of.some((field: string) => nonempty(lookup(value, field)))) errors[path] = `至少填写一项：${rule.at_least_one_of.join(', ')}`;
      if (rule.only_one_of && rule.only_one_of.filter((field: string) => nonempty(lookup(value, field))).length > 1) errors[path] = `只能填写一项：${rule.only_one_of.join(', ')}`;
      if (rule.conditional) {
        const condition = rule.conditional;
        if (match(lookup(value, condition.if_field), condition.if_match) === true && match(lookup(value, condition.then_field), condition.then_match) === false) errors[`${path}.${condition.then_field}`] = '不满足当前条件下的必填或取值约束';
      }
    }
    if ((definition?.type === 'record' || definition?.fields) && typeof value === 'object' && !Array.isArray(value)) for (const [field, child] of Object.entries(fieldsOf(definition))) check(value[field], child, `${path}.${field}`);
    if (['array', 'set'].includes(definition?.type) && Array.isArray(value)) value.forEach((item, i) => check(item, definition.elements, `${path}[${i}]`));
    if (definition?.type === 'map' && typeof value === 'object') for (const [field, item] of Object.entries(value)) check(item, definition.values, `${path}.${field}`);
  };
  const rules = pluginRules(name);
  check(values, schema, 'config', rules.schema_checks);
  for (const rule of rules.semantic) {
    if (rule.kind === 'at_least_one_true' && !rule.fields.some((field: string) => lookup(values, field) === true)) errors.config = rule.description;
    if (rule.kind === 'ordered_period_limits') {
      const targets = rule.path === 'limits.*' ? Object.entries(values?.limits || {}).map(([field, value]) => [`config.limits.${field}`, value] as const) : [['config', values] as const];
      for (const [path, target] of targets) for (let i = 0; i < rule.fields.length; i++) for (let j = i + 1; j < rule.fields.length; j++) {
        const lower = lookup(target, rule.fields[i]), upper = lookup(target, rule.fields[j]);
        if (typeof lower === 'number' && typeof upper === 'number' && upper < lower) errors[`${path}.${rule.fields[j]}`] = rule.description;
      }
    }
  }
  if (Object.keys(errors).length) throw new BadRequestException({ code: 'PLUGIN_CONDITION_FAILED', message: '插件配置不满足 Kong 条件规则', fields: errors });
}
export function validatePluginBindings(name: string, plugin: any): void {
  const metadata = pluginMetadata(name);
  if (!metadata.known) return;
  for (const binding of ['consumer', 'service', 'route'] as const) if (plugin[binding]?.id && !metadata.constraints[binding]) throw new BadRequestException({ code: 'PLUGIN_BINDING_NOT_SUPPORTED', message: `${name} 在 Kong 不支持 ${binding} 绑定`, fields: { [binding]: '此绑定范围不可用' } });
  if (Array.isArray(plugin.protocols) && plugin.protocols.some((protocol: string) => !metadata.constraints.protocols.includes(protocol))) throw new BadRequestException({ code: 'PLUGIN_PROTOCOL_NOT_SUPPORTED', message: '插件不支持所选协议', fields: { protocols: '协议必须符合安装版本的插件限制' } });
}
