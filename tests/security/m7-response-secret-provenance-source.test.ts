// @ts-nocheck -- real remember method, no constructor/env/files/runtime.
import { describe, expect, it } from 'vitest';
import { M7Harness } from './lib/m7-harness.mjs';
import { m7CapturedSecrets } from './lib/m7-secret-scan-policy.mjs';
const marker = '[REDACTED:0123456789abcdef]';
function harness() { const h = Object.create(M7Harness.prototype); h.state = { secrets: [] }; return h; }
describe('exact trusted response redaction marker provenance', () => {
  it('nested trusted responses exclude only the exact marker while real credentials remain captured', () => {
    const h = harness(); h.remember({ entity: { key: marker, config: [{ password: 'SyntheticResponseCredential' }, { token: '[REDACTED:not-a-valid-digest]' }] } }, true);
    expect(h.state.secrets).toEqual(['SyntheticResponseCredential', '[REDACTED:not-a-valid-digest]']);
  });
  it('request input preserves a marker-shaped real value and earlier captures are never deleted', () => {
    const h = harness(); h.remember({ config: [{ key: marker }] }); h.remember({ key: marker }, true); expect(h.state.secrets).toEqual([marker]);
  });
  it('collector trusts a successful packet response marker but never its request body', () => {
    const s = { version: 1, milestone: 'M7', testTag: 'synthetic', secrets: ['SyntheticRaw'], requests: [{ state: 'response_observed', status: 201, body: { key: 'SyntheticRaw' }, responseData: { entity: { key: marker } } }] };
    expect(m7CapturedSecrets(s)).toEqual(['SyntheticRaw']); s.requests[0].body.key = marker; expect(() => m7CapturedSecrets(s)).toThrow('INCOMPLETE');
  });
  it('request body cannot mint a trusted response context through attacker-named aggregate fields', () => {
    const s = { version: 1, milestone: 'M7', testTag: 'synthetic', secrets: ['SyntheticRaw'], requests: [{ state: 'response_observed', status: 201, body: { version: 1, milestone: 'M7', testTag: 'synthetic', producerAcceptance: { key: marker }, responseData: { token: marker } } }] };
    expect(() => m7CapturedSecrets(s)).toThrow('INCOMPLETE');
  });
  it('the same subtree in response and request retains separate effective provenance contexts', () => {
    const shared = { token: marker }, s = { version: 1, milestone: 'M7', testTag: 'synthetic', secrets: ['SyntheticRaw'], requests: [{ state: 'response_observed', status: 201, body: shared, responseData: shared }] };
    expect(() => m7CapturedSecrets(s)).toThrow('INCOMPLETE');
  });
});
