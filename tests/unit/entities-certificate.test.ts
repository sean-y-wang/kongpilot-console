import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { inspectCertificate } from '../../apps/console-api/src/modules/entities/certificates';

describe('M1 real X509 certificate inspection', () => {
  let directory: string, cert: string, key: string, mismatchedKey: string;
  beforeAll(() => {
    directory = mkdtempSync(join(tmpdir(), 'kongos-x509-test-'));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem'), '-days', '10', '-subj', '/CN=kongos-test'], { stdio: 'ignore' });
    execFileSync('openssl', ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', join(directory, 'other-key.pem')], { stdio: 'ignore' });
    cert = readFileSync(join(directory, 'cert.pem'), 'utf8'); key = readFileSync(join(directory, 'key.pem'), 'utf8'); mismatchedKey = readFileSync(join(directory, 'other-key.pem'), 'utf8');
  });
  afterAll(() => { if (directory) rmSync(directory, { recursive: true, force: true }); });
  it('extracts expiry and identity and verifies matching public keys', () => {
    const details = inspectCertificate(cert, key);
    expect(details.subject).toContain('kongos-test');
    expect(details.expiring_soon).toBe(true); expect(details.expired).toBe(false);
    expect(details.days_remaining).toBeGreaterThanOrEqual(9); expect(details.days_remaining).toBeLessThanOrEqual(10);
    expect(details.key_matches).toBe(true);
    expect(JSON.stringify(details)).not.toContain('PRIVATE KEY');
  });
  it('rejects mismatched keys and malformed PEM', () => {
    expect(() => inspectCertificate(cert, mismatchedKey)).toThrow();
    expect(() => inspectCertificate('invalid certificate', key)).toThrow();
  });
});
