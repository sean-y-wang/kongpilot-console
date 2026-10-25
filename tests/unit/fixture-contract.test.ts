import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { assertKongPath, ENTITIES, validateQuery } from '../../apps/console-api/src/infrastructure/kong/policy';
import { validateKnownFields } from '../../apps/console-api/src/infrastructure/kong/schema';
import { decodeTag, encodeTag, workspaceTag } from '../../apps/console-api/src/infrastructure/kong/tags';

type Recorded = { path: string; filename: string; source: string; recordedAt: string };
type Schema = { fields?: Array<Record<string, any>>; [key: string]: any };
const directory = fileURLToPath(new URL('../fixtures/kong-1.5.1/', import.meta.url));
const load = <T = any>(filename: string): T => JSON.parse(readFileSync(`${directory}${filename}`, 'utf8'));
const manifest = load<{ version: string; recorded: Recorded[] }>('manifest.json');
const pluginNames = load<{ enabled_plugins: string[] }>('plugins-enabled.json').enabled_plugins;
const fields = (schema: Schema): Record<string, any> => Object.assign({}, ...schema.fields!);
const entitySchema = (entity: string): Schema => load(`schema-${entity}.json`);

// These are offline checks of captured response shapes and our adapter against them.
// They do not send requests or prove live CRUD, credential restoration, or pagination.
describe('recorded Kong OSS 1.5.1 wire contracts', () => {
  it('keeps every captured response traceable to a unique path, file and timestamp', () => {
    expect(manifest.version).toBe('1.5.1');
    expect(manifest.recorded.length).toBeGreaterThanOrEqual(54);
    expect(new Set(manifest.recorded.map(record => record.path)).size).toBe(manifest.recorded.length);
    expect(new Set(manifest.recorded.map(record => record.filename)).size).toBe(manifest.recorded.length);
    for (const record of manifest.recorded) {
      expect(record.source).toBe('real Kong OSS 1.5.1 Docker image');
      expect(Number.isNaN(Date.parse(record.recordedAt))).toBe(false);
      expect(record.filename).toMatch(/^[a-z0-9_-]+\.json$/);
      expect(load(record.filename)).toBeTypeOf('object');
    }
    expect(readdirSync(directory).filter(name => name.endsWith('.json')).sort()).toEqual([
      'manifest.json', ...manifest.recorded.map(record => record.filename),
    ].sort());
  });

  it('reads the version from root and discovers endpoints separately', () => {
    const root = load('root.json');
    const endpoints = load<{ data: string[] }>('endpoints.json').data;
    expect(root.version).toBe(manifest.version);
    expect(root).not.toHaveProperty('endpoints');
    expect(endpoints).toContain('/endpoints');
    expect(endpoints).toContain('/plugins/schema/{name}');
    // Kong 1.5 already exposes the newer alias; this product deliberately forbids it.
    expect(endpoints).toContain('/schemas/plugins/{name}');
    expect(() => assertKongPath('GET', '/schemas/plugins/key-auth')).toThrow();
  });

  it('restricts native feature boundaries even when endpoint discovery is available', () => {
    const endpoints = load<{ data: string[] }>('endpoints.json').data;
    for (const path of ['/workspaces', '/rbac', '/vitals', '/vaults', '/keys', '/key-sets', '/event-hooks', '/clustering']) {
      expect(endpoints).not.toContain(path);
      expect(() => assertKongPath('GET', path)).toThrow();
    }
    expect(endpoints).toContain('/metrics');
    expect(() => assertKongPath('GET', '/metrics')).toThrow();
    expect(() => assertKongPath('GET', '/metrics', true)).not.toThrow();
  });

  it('has a captured config schema for every actually enabled plugin', () => {
    expect(pluginNames).toHaveLength(34);
    expect(new Set(pluginNames).size).toBe(pluginNames.length);
    const captures = manifest.recorded.filter(record => record.path.startsWith('/plugins/schema/'));
    expect(captures.map(record => record.path.slice('/plugins/schema/'.length)).sort()).toEqual([...pluginNames].sort());
    const rootAvailable = Object.keys(load('root.json').plugins.available_on_server);
    expect(rootAvailable.sort()).toEqual([...pluginNames].sort());
    for (const record of captures) {
      const schema = load<Schema>(record.filename);
      expect(Array.isArray(schema.fields)).toBe(true);
      expect(schema.fields!.every(field => Object.keys(field).length === 1)).toBe(true);
      expect(schema).not.toHaveProperty('config');
      expect(() => assertKongPath('GET', record.path)).not.toThrow();
    }
    for (const absent of ['grpc-gateway', 'degraphql', 'kafka-log']) expect(pluginNames).not.toContain(absent);
    for (const available of ['post-function', 'loggly', 'azure-functions', 'kubernetes-sidecar-injector']) expect(pluginNames).toContain(available);
  });

  it('omits the session schema generated secret default without losing its definition', () => {
    const field = fields(load('plugin-schema-session.json')).secret;
    expect(field.type).toBe('string');
    expect(field).not.toHaveProperty('default');
  });

  it.each(ENTITIES)('accepts the real terminal cursor response for %s without inventing totals or offsets', entity => {
    const path = `/${entity}?size=2`;
    expect(manifest.recorded).toContainEqual(expect.objectContaining({ path, filename: `list-${entity}-empty.json` }));
    const response = load(`list-${entity}-empty.json`);
    expect(response).toEqual({ data: [], next: null });
    expect(() => assertKongPath('GET', `/${entity}`)).not.toThrow();
    expect(() => validateQuery({ size: 2 })).not.toThrow();
  });

  it('prevents unsupported service TLS fields and universal enabled flags reaching Kong', () => {
    const service = entitySchema('services');
    for (const field of ['tls_verify', 'tls_verify_depth', 'ca_certificates', 'enabled']) {
      expect(fields(service)).not.toHaveProperty(field);
      expect(() => validateKnownFields({ [field]: true }, service)).toThrow(expect.objectContaining({ status: 400 }));
    }
    for (const entity of ENTITIES.filter(entity => entity !== 'plugins')) {
      expect(fields(entitySchema(entity))).not.toHaveProperty('enabled');
      expect(() => validateKnownFields({ enabled: false }, entitySchema(entity))).toThrow();
    }
    expect(() => validateKnownFields({ enabled: false }, entitySchema('plugins'))).not.toThrow();
    expect(fields(entitySchema('plugins')).enabled).toEqual({ default: true, type: 'boolean' });
  });

  it('preserves the real route defaults and rejects expression-router fields', () => {
    const route = entitySchema('routes');
    expect(fields(route).path_handling).toMatchObject({ default: 'v1', one_of: ['v0', 'v1'] });
    expect(fields(route).protocols.mutually_exclusive_subsets).toEqual([['http', 'https'], ['tcp', 'tls'], ['grpc', 'grpcs']]);
    for (const field of ['expression', 'priority']) expect(() => validateKnownFields({ [field]: 'true' }, route)).toThrow();
  });

  it('encodes logical tags into the character set recorded by every entity schema', () => {
    for (const entity of ENTITIES) {
      expect(fields(entitySchema(entity)).tags).toMatchObject({ type: 'set', elements: { match: '^[%w%.%-%_~]+$' } });
    }
    // Explicit translation of this captured Lua pattern; JavaScript cannot execute Lua patterns.
    const physicalPattern = /^[A-Za-z0-9._~-]+$/;
    expect('workspace:pay').not.toMatch(physicalPattern);
    expect('team:pay').not.toMatch(physicalPattern);
    for (const logical of ['workspace:pay', 'team:pay', '负责人:支付团队', 'ordinary-tag', 'kos-ws-pay', 'kos-tag-dGVhbTpwYXk']) {
      const physical = encodeTag(logical);
      expect(physical).toMatch(physicalPattern);
      expect(decodeTag(physical)).toBe(logical);
    }
    expect(workspaceTag('pay')).toBe(encodeTag('workspace:pay'));
    expect(encodeTag('kos-ws-pay')).not.toBe(workspaceTag('pay'));
  });

  it('validates nested upstream healthcheck fields against the captured schema', () => {
    const schema = entitySchema('upstreams');
    const healthchecks = fields(schema).healthchecks;
    expect(fields(fields(healthchecks).active).healthy.default.interval).toBe(0);
    expect(fields(schema).algorithm.one_of).toEqual(['consistent-hashing', 'least-connections', 'round-robin']);
    expect(() => validateKnownFields({ healthchecks: { active: { healthy: { interval: 10, successes: 2 } } } }, schema)).not.toThrow();
    expect(() => validateKnownFields({ healthchecks: { active: { healthy: { expression: 'unsupported' } } } }, schema)).toThrow();
  });

  it.each(['sources', 'destinations'])('checks unknown fields inside the captured Route %s set of records', name => {
    const schema = entitySchema('routes');
    expect(fields(schema)[name]).toMatchObject({ type: 'set', elements: { type: 'record' } });
    expect(() => validateKnownFields({ [name]: [{ ip: '127.0.0.1', port: 443 }] }, schema)).not.toThrow();
    expect(() => validateKnownFields({ [name]: [{ expression: 'unsupported' }] }, schema)).toThrow(expect.objectContaining({ status: 400 }));
  });

  it('validates plugin arrays of records using the real statsd schema', () => {
    const schema = load<Schema>('plugin-schema-statsd.json');
    const metrics = fields(schema).metrics;
    expect(metrics).toMatchObject({ type: 'array', elements: { type: 'record' } });
    expect(metrics.elements.entity_checks).toContainEqual(expect.objectContaining({ conditional: expect.objectContaining({ if_field: 'stat_type', then_field: 'sample_rate' }) }));
    expect(() => validateKnownFields({ metrics: [{ name: 'request_count', stat_type: 'counter', sample_rate: 1 }] }, schema, 'config')).not.toThrow();
    expect(() => validateKnownFields({ metrics: [{ unexpected: true }] }, schema, 'config')).toThrow();
  });

  it('validates map values as records instead of treating arbitrary plugin configuration as opaque JSON', () => {
    const schema = load<Schema>('plugin-schema-response-ratelimiting.json');
    expect(fields(schema).limits).toMatchObject({ type: 'map', values: { type: 'record' } });
    expect(() => validateKnownFields({ limits: { downloads: { second: 5, minute: 100 } } }, schema, 'config')).not.toThrow();
    expect(() => validateKnownFields({ limits: { downloads: { unexpected: true } } }, schema, 'config')).toThrow();
  });

  it('keeps an empty prometheus config valid and denies modern metric switches', () => {
    const schema = load<Schema>('plugin-schema-prometheus.json');
    expect(schema).toEqual({ fields: [] });
    expect(() => validateKnownFields({}, schema, 'config')).not.toThrow();
    for (const field of ['consumer_metrics', 'latency_metrics', 'bandwidth_metrics']) {
      expect(() => validateKnownFields({ [field]: true }, schema, 'config')).toThrow();
    }
  });
});
