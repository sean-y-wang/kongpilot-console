import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { analyzeKongSchema, payloadPathToForm, rulePathKey } from '../../apps/console-web/src/components/kong-schema-rules';
import { formPayload, prepareFormValues, redactedValue, sensitiveField } from '../../apps/console-web/src/components/KongSchemaForm';
import { augmentFormSchema } from '../../apps/console-api/src/modules/plugin-center/plugin-metadata';
import { redactForDisplay } from '../../apps/console-web/src/api/redaction';
const load = (name: string) => JSON.parse(readFileSync(new URL(`../fixtures/kong-1.5.1/plugin-schema-${name}.json`, import.meta.url), 'utf8'));
const wrapped = (schema: any) => ({ fields: [{ config: { ...schema, type: 'record' } }] });
const paths = (report: ReturnType<typeof analyzeKongSchema>) => report.issues.map(issue => issue.path.join('.'));

describe('M2 declarative form rules against recorded Kong 1.5 schemas', () => {
  it('preserves OAuth refresh-token lifetime defaults while clearing actual token material',()=>{
    const schema=load('oauth2'),values=prepareFormValues(schema,{});
    expect(values.refresh_token_ttl).toBe(1209600);expect(sensitiveField('refresh_token_ttl',{type:'number'})).toBe(false);
    expect(sensitiveField('refresh_token',{type:'string'})).toBe(true);
    expect(redactForDisplay({refresh_token_ttl:1209600,refresh_token:'synthetic-private-token'})).toEqual({refresh_token_ttl:1209600,refresh_token:'[REDACTED]'});
    expect(formPayload(schema,values).refresh_token_ttl).toBe(1209600);
  });
  it('accepts all 34 built-in plugins recorded valid configurations without mutating payloads', () => {
    const examples = JSON.parse(readFileSync(new URL('../fixtures/plugin-validation-examples.json', import.meta.url), 'utf8'));
    for (const [name, configs] of Object.entries(examples)) for (const config of configs as any[]) {
      const original = structuredClone(config);
      const report = analyzeKongSchema(augmentFormSchema(name, load(name)), config);
      expect(report.issues, `${name}: ${JSON.stringify(report.issues)}`).toEqual([]);
      expect(config).toEqual(original);
      expect(report.remote_authoritative).toBe(true);
    }
  });
  it('finds StatsD conditional errors in the exact array record, leaving its sibling valid', () => {
    const schema = wrapped(load('statsd'));
    const report = analyzeKongSchema(schema, { config: { metrics: [
      { name: 'request_count', stat_type: 'counter', sample_rate: 1 },
      { name: 'unique_users', stat_type: 'counter', sample_rate: 1 },
    ] } });
    expect(paths(report)).toEqual(['config.metrics.1.stat_type', 'config.metrics.1.consumer_identifier']);
    expect(report.hints[rulePathKey(['config', 'metrics', 1, 'consumer_identifier'])].required).toBe(true);
    expect(report.hints[rulePathKey(['config', 'metrics', 0, 'consumer_identifier'])].required).toBe(false);
    expect(analyzeKongSchema(schema, { config: { metrics: [
      { name: 'request_count', stat_type: 'counter', sample_rate: 1 },
      { name: 'unique_users', stat_type: 'set', consumer_identifier: 'custom_id' },
    ] } }).issues).toEqual([]);
  });
  it('re-evaluates conditional sample rate when a sibling stat type changes', () => {
    const schema = wrapped(load('datadog'));
    const invalid = analyzeKongSchema(schema, { config: { metrics: [{ name: 'latency', stat_type: 'gauge' }] } });
    expect(paths(invalid)).toContain('config.metrics.0.sample_rate');
    const valid = analyzeKongSchema(schema, { config: { metrics: [{ name: 'latency', stat_type: 'timer' }] } });
    expect(valid.issues).toEqual([]);
    expect(valid.hints[rulePathKey(['config', 'metrics', 0, 'sample_rate'])].required).toBe(false);
  });
  it('rejects zero sample rate without mistaking it for a missing field', () => {
    const report = analyzeKongSchema(load('statsd'), { metrics: [{ name: 'request_count', stat_type: 'counter', sample_rate: 0 }] });
    expect(report.issues).toEqual([expect.objectContaining({ path: ['metrics', 0, 'sample_rate'], code: 'gt' })]);
  });
  it('validates each map value and maps its logical key to a Form.List row', () => {
    const schema = wrapped(load('response-ratelimiting'));
    const form = { config: { limits: [{ key: 'good', value: { minute: 10 } }, { key: 'bad', value: {} }] } };
    const payload = formPayload(schema, form);
    expect(payload.config.limits).toEqual({ good: { minute: 10 }, bad: {} });
    const report = analyzeKongSchema(schema, payload);
    expect(report.issues).toEqual([expect.objectContaining({ path: ['config', 'limits', 'bad'], code: 'at_least_one_of' })]);
    expect(payloadPathToForm(schema, form, report.issues[0].path)).toEqual(['config', 'limits', 1, 'value']);
    expect(payloadPathToForm(schema, form, ['config', 'limits', 'good', 'minute'])).toEqual(['config', 'limits', 0, 'value', 'minute']);
  });
  it('makes an empty required map fail its minimum length instead of sending an empty configuration', () => {
    const schema = wrapped(load('response-ratelimiting'));
    expect(analyzeKongSchema(schema, formPayload(schema, { config: { limits: [] } })).issues).toContainEqual(expect.objectContaining({ path: ['config', 'limits'], code: 'len_min' }));
  });
  it('uses root source rules for Redis and defaults without changing the submitted payload', () => {
    const schema = augmentFormSchema('rate-limiting', load('rate-limiting'));
    const config = { second: 10, policy: 'redis' };
    expect(paths(analyzeKongSchema(schema, config))).toEqual(['redis_host']);
    expect(analyzeKongSchema(schema, { ...config, redis_host: 'redis' }).issues).toEqual([]);
    expect(config).toEqual({ second: 10, policy: 'redis' });
  });
  it('preserves explicit false and zero while evaluating required, enum and conditional checks', () => {
    const schema = { fields: [{ flag: { type: 'boolean', required: true, default: true } }, { count: { type: 'integer', required: true, default: 9, one_of: [0, 9] } }, { reason: { type: 'string' } }], entity_checks: [{ conditional: { if_field: 'flag', if_match: { eq: false }, then_field: 'reason', then_match: { required: true } } }] };
    expect(formPayload(schema, { flag: false, count: 0 })).toEqual({ flag: false, count: 0 });
    expect(paths(analyzeKongSchema(schema, { flag: false, count: 0 }))).toEqual(['reason']);
    expect(analyzeKongSchema(schema, { flag: false, count: 0, reason: 'disabled' }).issues).toEqual([]);
  });
  it('checks mutually required fields and exact one-of nonempty choices including false and zero', () => {
    const schema = { fields: [{ a: { type: 'number' } }, { b: { type: 'boolean' } }], entity_checks: [{ mutually_required: ['a', 'b'] }] };
    const missing = analyzeKongSchema(schema, { a: 0 });
    expect(paths(missing)).toEqual(['b']);
    expect(missing.hints[rulePathKey(['a'])].required).toBe(true);
    expect(analyzeKongSchema(schema, { a: 0, b: false }).issues).toEqual([]);
    const exclusive = { ...schema, entity_checks: [{ only_one_of: ['a', 'b'] }] };
    expect(analyzeKongSchema(exclusive, { b: false }).issues).toEqual([]);
    expect(analyzeKongSchema(exclusive, { a: 0, b: false }).issues[0].code).toBe('only_one_of');
  });
  it('checks array length, enum, integer and nested types at exact paths', () => {
    const schema = { fields: [{ items: { type: 'array', len_min: 1, len_max: 2, elements: { type: 'record', fields: [{ value: { type: 'integer', enum: [1, 2], required: true } }] } } }] };
    expect(analyzeKongSchema(schema, { items: [] }).issues[0].code).toBe('len_min');
    expect(analyzeKongSchema(schema, { items: [{ value: 3 }] }).issues).toContainEqual(expect.objectContaining({ path: ['items', 0, 'value'], code: 'one_of' }));
    expect(analyzeKongSchema(schema, { items: [{ value: 1.5 }] }).issues).toContainEqual(expect.objectContaining({ path: ['items', 0, 'value'], code: 'type' }));
    expect(analyzeKongSchema(schema, { items: [{ value: 1 }, { value: 2 }, { value: 1 }] }).issues[0].code).toBe('len_max');
  });
  it('handles nested map/array combinations and UTF-8 Lua string lengths', () => {
    const schema = { fields: [{ map: { type: 'map', values: { type: 'array', elements: { type: 'string', len_max: 2 } } } }] };
    const values = { map: [{ key: 'team:pay', value: ['中'] }] };
    const report = analyzeKongSchema(schema, formPayload(schema, values));
    expect(report.issues).toContainEqual(expect.objectContaining({ path: ['map', 'team:pay', 0], code: 'len_max' }));
    expect(payloadPathToForm(schema, values, report.issues[0].path)).toEqual(['map', 0, 'value', 0]);
  });
  it('never invokes custom or Lua-pattern validators and explicitly flags remote authority', () => {
    const lua = vi.fn(() => { throw new Error('must never run in the browser'); });
    const schema = { fields: [{ value: { type: 'string', custom_validator: lua, match: '^%d+$' } }, { conditional: { type: 'string' } }], entity_checks: [{ conditional: { if_field: 'value', if_match: { custom_validator: lua }, then_field: 'conditional', then_match: { required: true } } }] };
    const report = analyzeKongSchema(schema, { value: 'accepted-for-remote-check' });
    expect(lua).not.toHaveBeenCalled();
    expect(report.issues).toEqual([]);
    expect(report.remote_authoritative).toBe(true);
    expect(report.unsupportedValidators).toEqual(expect.arrayContaining(['value: custom_validator', 'value: match', '(root): conditional.if_match']));
  });
  it('does not invent an else branch for the Kong 1.5 conditional checker', () => {
    const schema = { fields: [{ enabled: { type: 'boolean' } }, { mode: { type: 'string' } }], entity_checks: [{ conditional: { if_field: 'enabled', if_match: { eq: true }, then_field: 'mode', then_match: { eq: 'active' }, else_match: { eq: 'disabled' } } }] };
    const report = analyzeKongSchema(schema, { enabled: false, mode: 'active' });
    expect(report.issues).toEqual([]);
    expect(report.unsupportedValidators).toContain('(root): conditional.else_match');
    expect(paths(analyzeKongSchema(schema, { enabled: true, mode: 'disabled' }))).toEqual(['mode']);
  });
  it('leaves absent optional records unset but expands required records using their defaults', () => {
    const child = { type: 'record', fields: [{ value: { type: 'string', required: true } }] };
    const optional = { fields: [{ optional: child }] };
    expect(analyzeKongSchema(optional, {}).issues).toEqual([]);
    expect(analyzeKongSchema(optional, { optional: null }).issues).toEqual([]);
    expect(paths(analyzeKongSchema(optional, { optional: {} }))).toEqual(['optional.value']);
    expect(paths(analyzeKongSchema({ fields: [{ needed: { ...child, required: true } }] }, {}))).toEqual(['needed.value']);
    expect(analyzeKongSchema({ fields: [{ needed: { ...child, required: true, fields: [{ value: { type: 'string', required: true, default: 'ready' } }] } }] }, {}).issues).toEqual([]);
  });
  it('does not mark then fields required when the conditional source is missing', () => {
    const schema = load('statsd');
    const report = analyzeKongSchema(schema, { metrics: [{}] });
    expect(paths(report)).toEqual(['metrics.0.name', 'metrics.0.stat_type']);
    expect(report.hints[rulePathKey(['metrics', 0, 'sample_rate'])].required).toBe(false);
  });
});

describe('M2 form preparation keeps credentials out of edits and preserves controls', () => {
  it('does not materialize unset optional Route sources/destinations in an HTTP CREATE payload', () => {
    const schema = JSON.parse(readFileSync(new URL('../fixtures/kong-1.5.1/schema-routes.json', import.meta.url), 'utf8'));
    const values = prepareFormValues(schema, { name: 'http-route', protocols: ['http'], paths: ['/orders'] });
    expect(values.sources).toEqual([]);
    expect(values.destinations).toEqual([]);
    const payload = formPayload(schema, values);
    expect(payload).toMatchObject({ name: 'http-route', protocols: ['http'], paths: ['/orders'] });
    expect(payload).not.toHaveProperty('sources');
    expect(payload).not.toHaveProperty('destinations');
    expect(analyzeKongSchema(schema, payload).issues).toEqual([]);
    values.sources = [{ ip: '127.0.0.1', port: 1234 }];
    expect(formPayload(schema, values).sources).toEqual([{ ip: '127.0.0.1', port: 1234 }]);
  });
  it('keeps explicit empty defaults, required collections and minimum-length failures in CREATE', () => {
    const schema = { fields: [
      { optional: { type: 'array', default: null, elements: { type: 'string' } } },
      { map: { type: 'map', default: null, values: { type: 'string' } } },
      { explicit: { type: 'array', default: [], elements: { type: 'string' } } },
      { required: { type: 'array', required: true, len_min: 1, elements: { type: 'string' } } },
      { bounded: { type: 'array', len_min: 1, elements: { type: 'string' } } },
    ] };
    const payload = formPayload(schema, { optional: [], map: [], explicit: [], required: [], bounded: [] });
    expect(payload).toEqual({ explicit: [], required: [], bounded: [] });
    expect(paths(analyzeKongSchema(schema, payload))).toEqual(['required', 'bounded']);
    expect(formPayload(schema, { optional: [], map: [] }, true)).toEqual({ optional: [], map: {} });
  });
  it('keeps all 34 built-in valid examples valid through CREATE form preparation and serialization', () => {
    const examples = JSON.parse(readFileSync(new URL('../fixtures/plugin-validation-examples.json', import.meta.url), 'utf8'));
    for (const [name, configs] of Object.entries(examples)) for (const config of configs as any[]) {
      const schema = wrapped(augmentFormSchema(name, load(name)));
      const values = prepareFormValues(schema, { config });
      // Existing/revealed secrets are never copied into controls; create inputs
      // receive only the explicitly supplied fixture credentials here.
      for (const [key, value] of Object.entries(config)) if (sensitiveField(key)) values.config[key] = value;
      const payload = formPayload(schema, values);
      expect(analyzeKongSchema(schema, payload).issues, name).toEqual([]);
    }
  });
  it('preserves recorded JWT/OAuth2/CORS switches and false values on both create and edit', () => {
    const cases: [string, string, boolean][] = [['jwt', 'secret_is_base64', false], ['oauth2', 'enable_password_grant', true], ['cors', 'credentials', false]];
    for (const [name, field, value] of cases) {
      const schema = wrapped(load(name));
      for (const editing of [false, true]) {
        const prepared = prepareFormValues(schema, { config: { [field]: value } }, editing);
        expect(prepared.config[field], `${name}/${field}/${editing}`).toBe(value);
        expect(formPayload(schema, prepared, editing).config[field]).toBe(value);
      }
      expect(redactForDisplay({ config: { [field]: value } })).toEqual({ config: { [field]: value } });
    }
  });
  it('keeps AWS Lambda and OAuth2 required credential inputs hidden on edit without clearing them', () => {
    for (const [name, field] of [['aws-lambda', 'aws_key'], ['aws-lambda', 'aws_secret'], ['oauth2', 'provision_key']]) {
      const schema = wrapped(load(name));
      expect(prepareFormValues(schema, { config: { [field]: 'test-credential-material' } }, true).config[field]).toBeUndefined();
      expect(formPayload(schema, { config: { [field]: '' } }, true).config[field]).toBeUndefined();
      expect(formPayload(schema, { config: { [field]: 'replacement-credential' } }, true).config[field]).toBe('replacement-credential');
      expect(sensitiveField(field)).toBe(true);
    }
  });
  it('masks credential aliases recursively in entity details, recycle and receipt display data', () => {
    const config = { provision_key: 'oauth-provision-material', aws_key: 'aws-access-material', aws_secret: 'aws-secret-material',
      aws_access_key_id: 'aws-id-material', access_key: 'generic-access-material', private_secret: 'private-material',
      secret_is_base64: false, enable_password_grant: true, credentials: false, retry_count: 0, key_names: ['apikey'], rsa_public_key: 'public-key-material' };
    const safe: any = redactForDisplay({ entity: { config }, graph: [{ data: { config } }], safe_result: { config }, credentials: { provision_key: 'boxed-secret' } });
    for (const record of [safe.entity.config, safe.graph[0].data.config, safe.safe_result.config]) {
      for (const field of ['provision_key', 'aws_key', 'aws_secret', 'aws_access_key_id', 'access_key', 'private_secret']) expect(record[field]).toBe('[REDACTED]');
      expect(record).toMatchObject({ secret_is_base64: false, enable_password_grant: true, credentials: false, retry_count: 0, key_names: ['apikey'], rsa_public_key: 'public-key-material' });
    }
    expect(safe.credentials).toBe('[REDACTED]');
    const json = JSON.stringify(safe);
    for (const secret of ['oauth-provision-material', 'aws-access-material', 'aws-secret-material', 'aws-id-material', 'generic-access-material', 'private-material', 'boxed-secret']) expect(json).not.toContain(secret);
  });
  it('masks unlabelled bearer/header and private PEM material while preserving public keys', () => {
    expect(redactForDisplay({ config: { values: ['Bearer test-value', 'Authorization: test-value', '-----BEGIN RSA PRIVATE KEY-----\\nsecret'], public_key: '-----BEGIN PUBLIC KEY-----\\npublic' } })).toEqual({ config: { values: ['[REDACTED]', '[REDACTED]', '[REDACTED]'], public_key: '-----BEGIN PUBLIC KEY-----\\npublic' } });
  });
  it('omits all redaction markers and nested passwords while preserving configurable public key names', () => {
    const schema = { fields: [{ config: { type: 'record', fields: [{ redis_password: { type: 'string' } }, { key_names: { type: 'array', elements: { type: 'string' } } }, { secret: { type: 'string' } }, { enabled: { type: 'boolean' } }, { redis_database: { type: 'integer' } }] } }] };
    const existing = { config: { redis_password: '[REDACTED:012345]', secret: 'existing-cleartext-must-not-reach-input', key_names: ['apikey'], enabled: false, redis_database: 0 } };
    expect(prepareFormValues(schema, existing, true)).toEqual({ config: { key_names: ['apikey'], enabled: false, redis_database: 0 } });
    expect(formPayload(schema, { config: { redis_password: '', secret: '[REDACTED:012345]', enabled: false, redis_database: 0 } }, true)).toEqual({ config: { enabled: false, redis_database: 0 } });
    expect(redactedValue('[REDACTED:012345]')).toBe(true);
    expect(sensitiveField('redis_password')).toBe(true);
    expect(sensitiveField('key_names')).toBe(false);
  });
  it('allows preserving an existing required secret on edit while requiring it on create', () => {
    const schema = { fields: [{ config: { type: 'record', fields: [{ client_secret: { type: 'string', required: true } }] } }] };
    expect(analyzeKongSchema(schema, { config: {} }, { editing: true }).issues).toEqual([]);
    expect(paths(analyzeKongSchema(schema, { config: {} }))).toEqual(['config.client_secret']);
    expect(formPayload(schema, { config: { client_secret: 'new-secret' } }, true)).toEqual({ config: { client_secret: 'new-secret' } });
  });
  it('preserves all ten recorded metric defaults and ordered user array edits', () => {
    const schema = wrapped(load('datadog'));
    const initial = prepareFormValues(schema);
    expect(initial.config.metrics).toHaveLength(10);
    initial.config.metrics[0].sample_rate = 0.5;
    initial.config.metrics[0].tags = ['team:pay', 'env:dev'];
    const payload = formPayload(schema, initial);
    expect(payload.config.metrics).toHaveLength(10);
    expect(payload.config.metrics[0]).toMatchObject({ sample_rate: 0.5, tags: ['team:pay', 'env:dev'] });
    expect(analyzeKongSchema(schema, payload).issues).toEqual([]);
  });
  it('keeps malformed types visible to validation instead of throwing or silently replacing them', () => {
    const schema = { fields: [{ config: { type: 'record', fields: [{ values: { type: 'array', elements: { type: 'string' } } }] } }] };
    expect(paths(analyzeKongSchema(schema, formPayload(schema, { config: 'invalid-json-object' })))).toEqual(['config']);
    expect(paths(analyzeKongSchema(schema, formPayload(schema, { config: { values: 'not-an-array' } })))).toEqual(['config.values']);
  });
});
