import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { stripSensitiveSchemaDefaults } from '../../apps/console-api/src/infrastructure/kong/schema-secrets';

describe('M1 schema response secret-default removal', () => {
  let secrets: SecretService;
  beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)); secrets = new SecretService(); });
  afterEach(() => vi.unstubAllEnvs());
  it('removes sensitive defaults without removing the schema definition or mutating the raw schema', () => {
    const schema = { fields: [{ secret: { type: 'string', required: false, default: 'actual-worker-secret' } }, { cookie_name: { type: 'string', default: 'session' } }, { password: { type: 'string', default: 'password' } }, { key: { type: 'string', default: 'api-key' } }] };
    const result = stripSensitiveSchemaDefaults(schema, secrets);
    expect(result.fields[0].secret).toEqual({ type: 'string', required: false, default_redacted: true });
    expect(result.fields[1].cookie_name.default).toBe('session');
    expect(result.fields[2].password.default).toBeUndefined();
    expect(result.fields[3].key.default).toBeUndefined();
    expect(schema.fields[0].secret!.default).toBe('actual-worker-secret');
    expect(JSON.stringify(result)).not.toContain('actual-worker-secret');
  });
  it('cleans nested record defaults and nested array/map field definitions', () => {
    const schema = { fields: [{ options: { type: 'record', default: { enabled: true, password: 'hidden', nested: { token: 'hidden-token', visible: 'keep' } }, fields: [{ enabled: { type: 'boolean', default: true } }] } }, { records: { type: 'array', elements: { type: 'record', fields: [{ private_key: { type: 'string', default: 'hidden-key' } }] } } }, { mapping: { type: 'map', values: { type: 'record', fields: [{ key: { type: 'string', default: 'hidden-map-key' } }] } } }] };
    const result = stripSensitiveSchemaDefaults(schema, secrets);
    expect(result.fields[0].options.default).toEqual({ enabled: true, nested: { visible: 'keep' } });
    expect(result.fields[0].options.default_redacted).toBe(true);
    expect(result.fields[1].records.elements.fields[0].private_key.default).toBeUndefined();
    expect(result.fields[2].mapping.values.fields[0].key.default).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain('hidden');
  });
});
