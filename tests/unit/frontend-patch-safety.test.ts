import { describe, expect, it } from 'vitest';
import { formPayload, prepareFormValues, type KongSchema } from '../../apps/console-web/src/components/KongSchemaForm';
import { omitUnchangedHiddenMaps } from '../../apps/console-web/src/components/schema-patch';

const schema: KongSchema = { fields: [{ name: { type: 'string' } }, { headers: { type: 'map', values: { type: 'array', elements: { type: 'string' } } } }] };
const original = { name: 'secure-route', headers: { authorization: '[REDACTED:canary]', 'x-team': ['pay'] } };

describe('PATCH safety for redacted Route header maps', () => {
  it('omits an unchanged hidden map when another Route field is edited', () => {
    const values = prepareFormValues(schema, original, true);
    values.name = 'renamed-route';
    const payload = formPayload(schema, values, true);
    expect(omitUnchangedHiddenMaps(schema, payload, original)).toEqual({ name: 'renamed-route' });
    expect(payload).toHaveProperty('headers');
  });
  it('retains public header edits without recreating a redacted match', () => {
    const values = prepareFormValues(schema, original, true);
    values.headers.find((row: any) => row.key === 'x-team').value = ['ledger'];
    const patch = omitUnchangedHiddenMaps(schema, formPayload(schema, values, true), original);
    expect(patch.headers['x-team']).toEqual(['ledger']);
    expect(JSON.stringify(patch)).not.toContain('REDACTED');
  });
  it('does not interpret removing a hidden-only row as authorization to clear a secret', () => {
    const source = { headers: { authorization: '[REDACTED:canary]' } };
    expect(omitUnchangedHiddenMaps(schema, { headers: {} }, source)).not.toHaveProperty('headers');
  });
  it('keeps explicit null for an intentional map clear', () => {
    expect(omitUnchangedHiddenMaps(schema, { headers: null }, original)).toEqual({ headers: null });
  });
});

describe('PATCH safety for unset optional arrays', () => {
  const routeSchema: KongSchema = { fields: [{ name: { type: 'string' } }, { sources: { type: 'array', elements: { type: 'record', fields: [{ ip: { type: 'string' } }] } } }, { methods: { type: 'set', elements: { type: 'string' } } }] };
  it('does not turn null HTTP-only Route source fields into empty arrays', () => {
    const original = { name: 'http-route', sources: null, methods: null };
    const values = prepareFormValues(routeSchema, original, true);
    values.name = 'renamed-http-route';
    expect(omitUnchangedHiddenMaps(routeSchema, formPayload(routeSchema, values, true), original)).toEqual({ name: 'renamed-http-route' });
  });
  it('submits explicit additions and clearing a previously configured collection', () => {
    expect(omitUnchangedHiddenMaps(routeSchema, { sources: [{ ip: '127.0.0.1' }], methods: [] }, { sources: null, methods: ['GET'] })).toEqual({ sources: [{ ip: '127.0.0.1' }], methods: [] });
  });
  it('preserves unset nested arrays while retaining another nested edit', () => {
    const nestedSchema: KongSchema = { fields: [{ config: { type: 'record', fields: [{ enabled: { type: 'boolean' } }, { optional: { type: 'array', elements: { type: 'string' } } }] } }] };
    expect(omitUnchangedHiddenMaps(nestedSchema, { config: { enabled: false, optional: [] } }, { config: { enabled: true, optional: null } })).toEqual({ config: { enabled: false } });
  });
});
