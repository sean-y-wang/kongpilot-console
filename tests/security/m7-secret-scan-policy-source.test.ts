// @ts-nocheck -- synthetic scanner references only; no environment/private/runtime.
import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { m7CapturedSecrets, m7SecretForms, m7KnownWritePacket, assertFinalM7Evidence } from './lib/m7-secret-scan-policy.mjs';
function reference() {
  const secret = 'SyntheticPrivateTokenOnly', key = randomUUID(), requestId = randomUUID(), cid = randomUUID(), wid = randomUUID();
  const packet = { index: 0, key, method: 'POST', path: '/api/v1/clusters/' + cid + '/events/channels', bodySha256: 'synthetichash', state: 'response_observed', status: 201, requestId, clusterId: cid, workspaceId: wid, responseData: { handler: 'event.channel.save' }, body: { endpoint: 'https://public-local-provider.test/hook', auth: { token: secret } } };
  return { version: 1, milestone: 'M7', secrets: [secret], requests: [packet], eventOperations: [{ key, handler: 'event.channel.save', cid, wid }], sessions: {}, phase: 'cleanup-complete', inFlight: null, providerControls: [], samplingIntents: [], cleanup: { businessCompleted: true }, producersComplete: true };
}
describe('fresh M7 final private capture and evidence policy', () => {
  it('keeps provider URL and exact original public packet key out of secret values', () => {
    const s = reference(), values = m7CapturedSecrets(s);
    expect(values).toEqual(s.secrets); expect(values).not.toContain(s.requests[0].key); expect(values).not.toContain(s.requests[0].body.endpoint);
  });
  it('older cloned history cannot silently lose a credential from the cumulative registry', () => {
    const s = reference(); s.history = { original: structuredClone(s) }; s.history.original.secrets.push('SyntheticOldCredential');
    expect(() => m7CapturedSecrets(s)).toThrow('INCOMPLETE'); s.secrets.push('SyntheticOldCredential'); expect(m7CapturedSecrets(s)).toContain('SyntheticOldCredential');
  });
  it('protected body key is not exempt merely because it equals a public packet UUID', () => {
    const s = reference(); s.requests[0].body.key = s.requests[0].key;
    expect(() => m7CapturedSecrets(s)).toThrow('INCOMPLETE'); s.secrets.push(s.requests[0].key); expect(m7CapturedSecrets(s)).toContain(s.requests[0].key);
  });
  it('same-key rollback retry binds its own index and full identity while body keys remain protected', () => {
    const s=reference(),original=s.requests[0];
    s.requests.push({...structuredClone(original),index:1,status:200});
    expect(m7CapturedSecrets(s)).toEqual(s.secrets);
    s.history={requests:[{...structuredClone(s.requests[1]),actorId:'foreign-actor'}]};
    expect(()=>m7CapturedSecrets(s)).toThrow('INCOMPLETE');
    delete s.history;s.requests[1].body.key=original.key;
    expect(()=>m7CapturedSecrets(s)).toThrow('INCOMPLETE');
  });
  it('foreign event key context cannot gain the verified packet metadata exemption', () => {
    const s = reference(); s.eventOperations[0].wid = randomUUID(); expect(() => m7CapturedSecrets(s)).toThrow('INCOMPLETE');
  });
  it('both HTTP headers and browser cookie objects verify every captured generation', () => {
    const s = reference(); s.requests[0].responseCookies = ['kongos_access=SyntheticAccessCookie; HttpOnly', 'kongos_refresh=SyntheticRefreshCookie; Path=/api'];
    expect(() => m7CapturedSecrets(s)).toThrow('INCOMPLETE'); s.secrets.push('SyntheticAccessCookie', 'SyntheticRefreshCookie');
    s.browser = { responseCookies: [{ name: 'kongos_csrf', value: 'SyntheticBrowserCSRF' }] };
    expect(() => m7CapturedSecrets(s)).toThrow('INCOMPLETE'); s.secrets.push('SyntheticBrowserCSRF'); expect(m7CapturedSecrets(s)).toHaveLength(4);
  });
  it('raw escaped percent and base64 forms all remain covered', () => {
    const value = 'Synthetic\nSecret/+"'; const values = m7SecretForms([value]);
    expect(values).toContain(value); expect(values).toContain(JSON.stringify(value).slice(1, -1)); expect(values).toContain(encodeURIComponent(value)); expect(values).toContain(Buffer.from(value).toString('base64'));
  });
  it('manual succeeded state requires original complete journal and exact immutable tuple', () => {
    const s = reference(), a = { ...s.requests[0], state: 'succeeded', receiptRequestId: randomUUID(), receiptData: { state: 'succeeded' }, actorId: randomUUID(), sessionId: randomUUID(), query: '?workspaceId=' + s.requests[0].workspaceId };
    const packet = { ...a, source: 'manual-ui', manualIndex: 0 }; s.manualUiJournal = { phase: 'complete', inFlight: null, attempts: [a] };
    expect(m7KnownWritePacket(s, packet)).toBe(true);
    for (const field of ['key', 'requestId', 'bodySha256', 'actorId', 'sessionId', 'query', 'workspaceId']) expect(m7KnownWritePacket(s, { ...packet, [field]: 'changed' })).toBe(false);
    s.manualUiJournal.phase = 'stopped-without-replay'; expect(m7KnownWritePacket(s, packet)).toBe(false);
  });
  it('any unknown or incomplete final checkpoint refuses private removal eligibility', () => {
    const s = reference(), ok = { allPassed: true, failed: 0, testTag: 'synthetic' }; s.testTag = 'synthetic';
    const evidence = { http: ok, producers: ok, manual: ok, cleanup: { ...ok, auditWriteCoverage: { allCovered: true, coveredWrites: 1, successfulWrites: 1 } } };
    expect(assertFinalM7Evidence(s, evidence)).toBe(true);
    s.requests[0].state = 'response_unknown'; expect(() => assertFinalM7Evidence(s, evidence)).toThrow('UNKNOWN');
    s.requests[0].state = 'response_observed'; evidence.cleanup.auditWriteCoverage.coveredWrites = 0; expect(() => assertFinalM7Evidence(s, evidence)).toThrow('INCOMPLETE');
  });
});
