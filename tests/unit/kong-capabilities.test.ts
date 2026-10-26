import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { isSupportedKong, kongCapabilities, stripUnsupportedFields } from '../../apps/console-api/src/infrastructure/kong/kong-capabilities';

describe('Kong capability table', () => {
  it('keeps the contracts mirror byte-identical to the API source', () => {
    expect(readFileSync('packages/contracts/src/kong-capabilities.ts', 'utf8')).toBe(readFileSync('apps/console-api/src/infrastructure/kong/kong-capabilities.ts', 'utf8'));
  });
  it.each(['1.3.0', '1.4.3', '1.5.1'])('supports %s', v => expect(isSupportedKong(v)).toBe(true));
  it.each(['1.2.4', '2.8.0', '1.5', '1.5.1-enterprise', '', null, undefined])('rejects %s', v => expect(isSupportedKong(v as any)).toBe(false));
  it('marks only 1.5 as full support and hides credential features below 1.4', () => {
    expect(kongCapabilities('1.5.1')).toMatchObject({ full: true, credentialTags: true, portalCredentials: true, routeSimulation: true, unsupportedFields: {} });
    expect(kongCapabilities('1.4.3')).toMatchObject({ full: false, credentialTags: true, portalCredentials: true, routeSimulation: false, unsupportedFields: { routes: ['path_handling'] } });
    expect(kongCapabilities('1.3.0')).toMatchObject({ line: '1.3', full: false, read: true, write: true, credentialTags: false, portalCredentials: false, credentialTransfer: false, routeSimulation: false, unsupportedFields: { routes: ['path_handling'], upstreams: ['host_header'] } });
    expect(kongCapabilities('2.8.0')).toMatchObject({ supported: false, read: false, write: false });
  });
  it('strips fields the target line does not know and leaves other lines untouched', () => {
    expect(stripUnsupportedFields('routes', { name: 'r', path_handling: 'v0' }, '1.3.0')).toEqual({ name: 'r' });
    expect(stripUnsupportedFields('upstreams', { name: 'u', host_header: 'h' }, '1.3.0')).toEqual({ name: 'u' });
    expect(stripUnsupportedFields('upstreams', { name: 'u', host_header: 'h' }, '1.4.0')).toEqual({ name: 'u', host_header: 'h' });
    expect(stripUnsupportedFields('routes', { name: 'r', path_handling: 'v1' }, '1.5.1')).toEqual({ name: 'r', path_handling: 'v1' });
  });
});
