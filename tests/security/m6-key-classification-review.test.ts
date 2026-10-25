import { describe, expect, it } from 'vitest';
import { capturedPrivateSecrets } from './lib/m6-fixture-runs.mjs';

const key = '10000000-0000-4000-8000-000000000111';
const attempt = { method: 'POST', path: '/api/v1/clusters/known/workflows/known/execute', state: 'uncertain', key };
describe('M6 independent scanner diagnostic-key classification', () => {
  it('excludes only journal-linked originalRequest/originalExecution metadata keys', () => {
    const reference = { writeAttempts: [attempt], diagnostic: { originalRequest: { key }, originalExecution: { key } }, other: { key: 'SyntheticAPIKeyCanary' } };
    const actual = capturedPrivateSecrets(reference);
    expect(actual).not.toContain(key); expect(actual).toContain('SyntheticAPIKeyCanary');
  });
  it.each([
    ['unlinked key', { writeAttempts: [], originalRequest: { key } }],
    ['read-only pseudo journal', { writeAttempts: [{ ...attempt, method: 'GET' }], originalExecution: { key } }],
    ['foreign path journal', { writeAttempts: [{ ...attempt, path: '/foreign/metadata' }], originalRequest: { key } }],
    ['missing state journal', { writeAttempts: [{ method: 'POST', path: attempt.path, key }], originalExecution: { key } }],
    ['unrecognized diagnostic owner', { writeAttempts: [attempt], arbitraryDiagnostic: { key } }],
  ])('still scans %s as a possible credential', (_name, reference) => {
    expect(capturedPrivateSecrets(reference)).toContain(key);
  });
  it('retains UUID-valued real keys and secrets even when equal to a recognized idempotency key', () => {
    expect(capturedPrivateSecrets({ writeAttempts: [attempt], originalRequest: { key }, credential: { key }, secrets: [key] })).toContain(key);
    expect(capturedPrivateSecrets({ writeAttempts: [attempt], originalExecution: { key }, secrets: [key] })).toContain(key);
  });
  it('keeps canonical token and cookie values covered and permits only explicitly linked manual-write metadata', () => {
    const token = 'SyntheticCollectorTokenForClassification2026', cookie = 'SyntheticAccessCookieForClassification2026';
    const reference = { manualWriteAttempts: [attempt], originalExecution: { key }, tokens: [{ purpose: 'collector_ingest', token }],
      portalCookie: `kongos_portal_access=${cookie}; Path=/; HttpOnly` };
    const actual = capturedPrivateSecrets(reference);
    expect(actual).not.toContain(key); expect(actual).toContain(token); expect(actual).toContain(cookie);
    expect(actual).toContain(`Basic ${Buffer.from(`kongos:${token}`).toString('base64')}`);
  });
});
