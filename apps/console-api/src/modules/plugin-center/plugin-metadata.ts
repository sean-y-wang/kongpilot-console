/** These rules describe the bundled OSS 1.5.1 Lua source, not newer Kong releases.
 * The installed Admin API schema remains authoritative, including custom plugins. */
export const METADATA_SOURCE = 'kong-oss-1.5.1-source';
export const BINDING_SCOPES = ['consumer-route-service', 'consumer-route', 'consumer-service', 'route-service', 'consumer', 'route', 'service', 'global'] as const;
export type BindingScope = typeof BINDING_SCOPES[number];
export const PRECEDENCE = BINDING_SCOPES.map((scope, index) => ({ scope, rank: index + 1, label: ['Consumer + Route + Service', 'Consumer + Route', 'Consumer + Service', 'Route + Service', 'Consumer', 'Route', 'Service', '全局'][index] }));
export const PERIODS = ['second', 'minute', 'hour', 'day', 'month', 'year'];
type Category = 'authentication' | 'security' | 'traffic' | 'transformation' | 'logging' | 'serverless' | 'observability';
type Definition = { category: Category; priority: number; noConsumer?: boolean; globalOnly?: boolean; http?: boolean };
const definitions: Record<string, Definition> = {
  acl: { category: 'security', priority: 950, noConsumer: true, http: true },
  'aws-lambda': { category: 'serverless', priority: 750, http: true },
  'azure-functions': { category: 'serverless', priority: 749 },
  'basic-auth': { category: 'authentication', priority: 1001, noConsumer: true, http: true },
  'bot-detection': { category: 'security', priority: 2500, noConsumer: true, http: true },
  'correlation-id': { category: 'transformation', priority: 1, http: true },
  cors: { category: 'security', priority: 2000, noConsumer: true, http: true },
  datadog: { category: 'observability', priority: 10, http: true },
  'file-log': { category: 'logging', priority: 9, http: true },
  'hmac-auth': { category: 'authentication', priority: 1000, noConsumer: true, http: true },
  'http-log': { category: 'logging', priority: 12, http: true },
  'ip-restriction': { category: 'security', priority: 990, http: true },
  jwt: { category: 'authentication', priority: 1005, http: true },
  'key-auth': { category: 'authentication', priority: 1003, noConsumer: true, http: true },
  'kubernetes-sidecar-injector': { category: 'transformation', priority: 1006, globalOnly: true },
  'ldap-auth': { category: 'authentication', priority: 1002, noConsumer: true, http: true },
  loggly: { category: 'logging', priority: 6, http: true },
  oauth2: { category: 'authentication', priority: 1004, noConsumer: true, http: true },
  'post-function': { category: 'serverless', priority: -1000, noConsumer: true },
  'pre-function': { category: 'serverless', priority: Infinity, noConsumer: true },
  prometheus: { category: 'observability', priority: 13 },
  'proxy-cache': { category: 'traffic', priority: 100 },
  'rate-limiting': { category: 'traffic', priority: 901, http: true },
  'request-size-limiting': { category: 'traffic', priority: 951, http: true },
  'request-termination': { category: 'traffic', priority: 2, http: true },
  'request-transformer': { category: 'transformation', priority: 801 },
  'response-ratelimiting': { category: 'traffic', priority: 900, http: true },
  'response-transformer': { category: 'transformation', priority: 800, http: true },
  session: { category: 'authentication', priority: 1900, noConsumer: true },
  statsd: { category: 'observability', priority: 11, http: true },
  syslog: { category: 'logging', priority: 4, http: true },
  'tcp-log': { category: 'logging', priority: 7, http: true },
  'udp-log': { category: 'logging', priority: 8, http: true },
  zipkin: { category: 'observability', priority: 100000 },
};

export function pluginMetadata(name: string) {
  const value = Object.hasOwn(definitions, name) ? definitions[name] : undefined;
  return {
    name, known: !!value, category: value?.category ?? 'unknown',
    priority: value && Number.isFinite(value.priority) ? value.priority : null,
    ...(value?.priority === Infinity ? { priority_label: '∞' } : {}),
    constraints: { known: !!value, consumer: value ? !value.noConsumer && !value.globalOnly : null, route: value ? !value.globalOnly : null, service: value ? !value.globalOnly : null, protocols: value ? (value.http ? ['http', 'https', 'grpc', 'grpcs'] : ['http', 'https', 'grpc', 'grpcs', 'tcp', 'tls']) : [] },
    source: value ? METADATA_SOURCE : 'installed-plugin-schema',
  };
}
export function executionPriority(name: string): number | null { return Object.hasOwn(definitions, name) ? definitions[name].priority : null; }
export function bindingScope(plugin: any): BindingScope {
  const c = !!plugin.consumer?.id, r = !!plugin.route?.id, s = !!plugin.service?.id;
  return c ? r ? s ? 'consumer-route-service' : 'consumer-route' : s ? 'consumer-service' : 'consumer' : r ? s ? 'route-service' : 'route' : s ? 'service' : 'global';
}

function redisChecks(): any[] {
  return ['redis_host', 'redis_port', 'redis_timeout'].map(field => ({ conditional: { if_field: 'policy', if_match: { eq: 'redis' }, then_field: field, then_match: { required: true } } }));
}
export function pluginRules(name: string) {
  let schema_checks: any[] = [], semantic: any[] = [];
  const notes = ['Kong 1.5 Admin API 执行最终校验；Lua 自定义校验器不会在控制台执行。'];
  if (['acl', 'ip-restriction'].includes(name)) schema_checks = [{ only_one_of: ['whitelist', 'blacklist'] }, { at_least_one_of: ['whitelist', 'blacklist'] }];
  if (name === 'rate-limiting') {
    schema_checks = [{ at_least_one_of: PERIODS }, ...redisChecks()];
    semantic.push({ kind: 'ordered_period_limits', fields: PERIODS, description: '较长时间段限额不能低于较短时间段限额' });
  }
  if (name === 'response-ratelimiting') {
    schema_checks = redisChecks();
    semantic.push({ kind: 'ordered_period_limits', path: 'limits.*', fields: PERIODS, description: '各 limits 记录的较长时间段限额不能低于较短时间段限额' });
  }
  if (name === 'oauth2') {
    schema_checks = [{ conditional: { if_field: 'mandatory_scope', if_match: { eq: true }, then_field: 'scopes', then_match: { required: true } } }];
    semantic.push({ kind: 'at_least_one_true', fields: ['enable_authorization_code', 'enable_implicit_grant', 'enable_client_credentials', 'enable_password_grant'], description: '至少启用一种 OAuth2 授权流程' });
  }
  if (name === 'proxy-cache') notes.push('memory.dictionary_name 必须存在于目标 Kong 的共享字典；控制台无法替代远端检查。');
  if (['pre-function', 'post-function'].includes(name)) notes.push('functions 数组由 Kong 编译为 Lua；保存配置不会在控制台执行代码。');
  if (!Object.hasOwn(definitions, name)) notes.push('自定义插件未纳入固定版本元规则；绑定和执行顺序由安装的插件决定。');
  return { source: Object.hasOwn(definitions, name) ? METADATA_SOURCE : 'installed-plugin-schema', schema_checks, semantic, notes };
}

export function augmentFormSchema(name: string, wireSchema: any): any {
  const schema = structuredClone(wireSchema), rules = pluginRules(name);
  schema.entity_checks = [...(schema.entity_checks || []), ...structuredClone(rules.schema_checks)];
  schema.console_metadata_source = rules.source;
  return schema;
}
