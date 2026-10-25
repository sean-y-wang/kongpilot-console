// Pure fixture producer derived from live-m2.mjs configurations() only.
// Never imports or executes that historical environment/Auth/runtime entry.
export const PRODUCTION_ENTITY_TYPES = Object.freeze(['certificates', 'ca_certificates', 'upstreams', 'services', 'consumers', 'snis', 'routes', 'plugins']);
export function productionPluginConfigurations(secret) {
  return {
    'correlation-id': [{ header_name: 'X-M2-Initial' }, { header_name: 'X-M2-Updated' }],
    'pre-function': [{ functions: ['return'] }, { functions: ['local fixture = 1; return'] }],
    cors: [{ origins: ['https://example.invalid'] }, { origins: ['https://updated.invalid'], max_age: 60, credentials: true }],
    'ldap-auth': [{ ldap_host: '198.51.100.1', ldap_port: 389, base_dn: 'dc=example,dc=invalid', attribute: 'uid' }, { timeout: 1001 }],
    loggly: [{ key: secret('m2-loggly'), host: '198.51.100.1', port: 9 }, { tags: ['m2-fixture'] }],
    'hmac-auth': [{}, { clock_skew: 100 }],
    zipkin: [{ http_endpoint: 'http://198.51.100.1:9/ignored' }, { sample_ratio: 0.01 }],
    'request-size-limiting': [{ allowed_payload_size: 10 }, { allowed_payload_size: 11 }],
    'azure-functions': [{ appname: 'kongos-fixture', functionname: 'disabled', apikey: secret('m2-azure') }, { timeout: 1001 }],
    'request-transformer': [{ remove: {}, rename: {}, replace: {}, add: {}, append: {} }, { add: { headers: ['X-M2-Fixture:updated'] } }],
    oauth2: [{ provision_key: secret('m2-oauth-provision'), enable_client_credentials: true }, { token_expiration: 7201, enable_password_grant: true }],
    'response-transformer': [{ remove: {}, rename: {}, replace: {}, add: {}, append: {} }, { add: { headers: ['X-M2-Fixture:updated'] } }],
    'ip-restriction': [{ whitelist: ['127.0.0.1'] }, { whitelist: ['127.0.0.1', '127.0.0.2'] }],
    statsd: [{ host: '198.51.100.1', port: 9, metrics: [{ name: 'request_count', stat_type: 'counter', sample_rate: 1 }] }, { prefix: 'm2-updated' }],
    jwt: [{}, { run_on_preflight: false, secret_is_base64: true }],
    'proxy-cache': [{ strategy: 'memory', memory: {} }, { cache_ttl: 301 }],
    'basic-auth': [{}, { hide_credentials: true }],
    'key-auth': [{}, { hide_credentials: true }],
    'http-log': [{ http_endpoint: 'http://198.51.100.1:9/ignored' }, { timeout: 1001 }],
    datadog: [{ host: '198.51.100.1', port: 9 }, { prefix: 'm2-updated' }],
    'tcp-log': [{ host: '198.51.100.1', port: 9 }, { timeout: 1001 }],
    'rate-limiting': [{ minute: 10, policy: 'local' }, { minute: 11 }],
    'post-function': [{ functions: ['return'] }, { functions: ['local fixture = 1; return'] }],
    prometheus: [{}, {}],
    acl: [{ whitelist: ['m2-fixture'] }, { hide_groups_header: true }],
    'kubernetes-sidecar-injector': [{}, { imagePullPolicy: 'Never' }],
    syslog: [{}, { log_level: 'notice' }],
    'file-log': [{ path: '/tmp/kongos-m2-disabled.log' }, { reopen: true }],
    'udp-log': [{ host: '198.51.100.1', port: 9 }, { timeout: 1001 }],
    'response-ratelimiting': [{ limits: { fixture: { minute: 10 } }, policy: 'local' }, { limits: { fixture: { minute: 11 } } }],
    'aws-lambda': [{ aws_key: secret('m2-aws-key'), aws_secret: secret('m2-aws-secret'), aws_region: 'us-east-1', function_name: 'kongos-disabled-fixture' }, { timeout: 1001 }],
    session: [{ secret: secret('m2-session') }, { cookie_name: 'm2_updated' }],
    'bot-detection': [{}, { blacklist: ['m2-fixture-bot'] }],
    'request-termination': [{ status_code: 418, message: 'M2 initial' }, { status_code: 419, message: 'M2 updated' }],
  };
}

export const PRODUCTION_PLUGIN_NAMES = Object.freeze(Object.keys(productionPluginConfigurations(label => `source-only-${label}`)));
export const PRODUCTION_UI_CORE_ACTIONS = Object.freeze([
  'carrier.create',
  ...PRODUCTION_ENTITY_TYPES.map(type => `entity.${type}.create`),
  ...PRODUCTION_ENTITY_TYPES.map(type => `entity.${type}.edit`),
  ...[...PRODUCTION_ENTITY_TYPES].reverse().map(type => `entity.${type}.archive`),
  ...PRODUCTION_ENTITY_TYPES.map(type => `entity.${type}.restore`),
  ...PRODUCTION_PLUGIN_NAMES.flatMap(name => [`plugin.${name}.create`, `plugin.${name}.edit`, `plugin.${name}.archive`, `plugin.${name}.restore`]),
  'cleanup.carrier.archive',
]);
export const PRODUCTION_UI_BINDING_ACTIONS=Object.freeze(['bindings.route.create','bindings.consumer.create','bindings.global.create','bindings.service.enable','bindings.service.disable','bindings.route.archive','bindings.consumer.archive','bindings.global.archive']);
export const PRODUCTION_UI_ACTIONS=Object.freeze([...PRODUCTION_UI_CORE_ACTIONS.slice(0,-1),...PRODUCTION_UI_BINDING_ACTIONS,PRODUCTION_UI_CORE_ACTIONS.at(-1)]);
export const PRODUCTION_ENTITY_LABELS = Object.freeze({services:'Services',routes:'Routes',consumers:'Consumers',plugins:'Plugins',upstreams:'Upstreams',certificates:'Certificates',ca_certificates:'CA Certificates',snis:'SNIs'});
export function productionEntityInput(type, {tag, actorId, bindings, pem}) {
  const tags = [tag, `owner:${actorId}`];
  switch (type) {
    case 'certificates': return {cert:pem.certificate,key:pem.privateKey,tags};
    case 'ca_certificates': return {cert:pem.caCertificate,tags};
    case 'upstreams': return {name:`${tag}-upstream`,algorithm:'round-robin',tags};
    case 'services': return {name:`${tag}-isolated`,protocol:'https',host:bindings.upstreams.entity.name,port:9,client_certificate:{id:bindings.certificates.id},tags};
    case 'consumers': return {username:`${tag}-consumer`,custom_id:`${tag}-initial`,tags};
    case 'snis': return {name:`${tag}.invalid`,certificate:{id:bindings.certificates.id},tags};
    case 'routes': return {name:`${tag}-route`,service:{id:bindings.carrier.id},hosts:[`${tag}.invalid`],paths:[`/${tag}`],protocols:['https'],tags};
    case 'plugins': return {name:'rate-limiting',service:{id:bindings.carrier.id},route:{id:bindings.routes.id},consumer:{id:bindings.consumers.id},enabled:false,config:{minute:10,policy:'local'},tags};
    default: throw Error('PRODUCTION_ENTITY_NOT_ALLOWED');
  }
}
export function productionEntityEdit(type, tag) {
  const changes = {tags:[tag,`${tag}-edited`]};
  if (type === 'services') changes.read_timeout = 61001;
  if (type === 'consumers') changes.custom_id = `${tag}-updated`;
  if (type === 'routes') changes.preserve_host = true;
  if (type === 'upstreams') { changes.algorithm = 'consistent-hashing';changes.hash_on='header';changes.hash_on_header='X-KongOS-Acceptance'; }
  if (type === 'plugins') { changes.enabled=false; changes.config={minute:11}; }
  return changes;
}
