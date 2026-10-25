import { createHash } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { collectCurrentScanMaterial, currentScanMaterialFailureMetadata, runCurrentSecretScan,
  writeCurrentScanPrivateMaterialReview } from '../security/m11-current-secret-scan.mjs';

const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
const failure = (ledger: unknown, environment: unknown = {}) => {
  try { collectCurrentScanMaterial([ledger], [environment]); } catch (error: any) {
    expect(error.message).toBe('SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW');
    expect(error.scanCode).toBe('SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW');
    return { error, metadata: currentScanMaterialFailureMetadata(error) };
  }
  throw Error('Expected the unchanged short-secret fail-closed gate');
};

describe('M11 exact short-material diagnostic preserves rejection and hides values', () => {
  it('locates a credential packet key without disclosing its value', () => {
    const { error, metadata } = failure({ requests: [{ path: '/consumers/u/key-auth', body: { key: 'x!7' } }] });
    expect(metadata).toMatchObject({ inputRole: 'ledger/0', path: ['ledger', '0', 'requests', '0', 'body', 'key'],
      field: 'key', fieldNameSha256: hash('key'), kind: 'api-key', classification: 'credential-descendant-key',
      inheritedCredentialSource: ['ledger', '0', 'requests', '0', 'body'], configurationKeyContext: false,
      utf16Length: 3, characterLength: 3, byteCount: 3 });
    expect(metadata).not.toHaveProperty('valueSha256');
    expect(JSON.stringify({ error, metadata })).not.toContain('x!7');
    expect(JSON.stringify(metadata)).not.toContain(hash('x!7'));
  });

  it('distinguishes inherited config.config.key context but still rejects the same short value', () => {
    const { metadata } = failure({ credentials: { config: { config: { key: 'iss' } } } });
    expect(metadata).toMatchObject({ path: ['ledger', '0', 'credentials', 'config', 'config', 'key'],
      classification: 'credential-descendant-key', inheritedCredentialSource: ['ledger', '0', 'credentials'],
      configurationKeyContext: true, characterLength: 3 });
    expect(metadata).not.toHaveProperty('excluded');
    expect(JSON.stringify(metadata)).not.toContain('iss');
  });

  it.each([
    ['issued-key', { issuedKey: 's!7' }, {}, 'explicit-api-key', 'api-key'],
    ['password', { password: 's!7' }, {}, 'explicit-password', 'password'],
    ['plugin-secret', { plugins: [{ config: { secret: 's!7' } }] }, {}, 'explicit-secret', 'secret'],
    ['cookie-member', { cookie: 'kongpilot_access=s!7' }, {}, 'cookie-member', 'cookie'],
    ['named-cookie', { name: 'kongpilot_csrf', value: 's!7' }, {}, 'named-cookie-value', 'csrf'],
    ['csrf', { csrf: 's!7' }, {}, 'explicit-csrf', 'csrf'],
    ['bearer-value', { headers: { Authorization: 'Bearer s!7' } }, {}, 'authorization-value', 'authorization'],
    ['fixture-key', { fixtureKeys: { account: 's!7' } }, {}, 'fixture-api-key', 'api-key'],
    ['environment-value', {}, { API_KEY: 's!7' }, 'environment-secret', 'environment-secret'],
    ['url-password', {}, { DATABASE_URL: 'postgres://user:s%217@db.invalid/db' }, 'environment-url-password', 'environment-secret'],
  ] as const)('retains exact %s short-secret classification', (_name, ledger, environment, classification, kind) => {
    const { metadata } = failure(ledger, environment);
    expect(metadata).toMatchObject({ classification, kind, characterLength: 3, byteCount: 3 });
    expect(JSON.stringify(metadata)).not.toContain('s!7');
    expect(JSON.stringify(metadata)).not.toContain(hash('s!7'));
    expect(metadata.inputRole).toBe(classification.startsWith('environment-') ? 'environment/0' : 'ledger/0');
  });

  it('retains YAML input provenance and exact credential field without echoing YAML bytes', () => {
    const { metadata } = failure({ rawResponseText: '_format_version: "1.1"\nconsumers:\n - keyauth_credentials:\n   - key: y!7\n' });
    expect(metadata).toMatchObject({ inputRole: 'ledger/0', path: ['ledger', '0', 'rawResponseText', 'export', 'consumers', '0', 'keyauth_credentials', '0', 'key'],
      classification: 'credential-descendant-key', characterLength: 3 });
    expect(JSON.stringify(metadata)).not.toContain('y!7');
    expect(JSON.stringify(metadata)).not.toContain('_format_version');
  });

  it('hashes dynamic object keys and reports character and byte lengths separately', () => {
    const dynamic = 'DynamicMapPrivateName!Synthetic', value = 'é😀';
    const { metadata } = failure({ credentials: { [dynamic]: { key: value } } });
    expect(metadata.path).toContain(`[field-sha256:${hash(dynamic)}]`);
    expect(metadata).toMatchObject({ utf16Length: 3, characterLength: 2, byteCount: 6 });
    const output = JSON.stringify(metadata);
    expect(output).not.toContain(dynamic); expect(output).not.toContain(value); expect(output).not.toContain(hash(value));
  });

  it('does not trust arbitrary thrown metadata or permit mutation of stored diagnostic metadata', () => {
    expect(currentScanMaterialFailureMetadata(Object.assign(Error('SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW'), { scanCode: 'SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW', materialReview: { value: 'never' } }))).toBeUndefined();
    const { error, metadata } = failure({ credentials: { key: 'x!7' } });
    metadata.path.push('changed'); metadata.field = 'changed';
    expect(currentScanMaterialFailureMetadata(error).path).not.toContain('changed');
    expect(currentScanMaterialFailureMetadata(error).field).toBe('key');
  });

  it('stops before enumeration and writes a separate opt-in 0600 private digest with original files untouched', () => {
    // Every byte is generated here; no actual ledger, environment or Git is read.
    const root = mkdtempSync(resolve(tmpdir(), 'kongpilot-short-diagnostic-synthetic-'));
    try {
      const repository = resolve(root, 'repository'), privateRoot = resolve(root, 'private'), inputRoot = resolve(privateRoot, 'inputs'), buildRoot = resolve(root, 'build');
      for (const path of [repository, privateRoot, inputRoot, buildRoot]) mkdirSync(path, { mode: 0o700 });
      const ledgerPath = resolve(privateRoot, 'ledger.json'), envPath = resolve(privateRoot, 'lab.env');
      const ledgerBytes = JSON.stringify({ credentials: { config: { config: { key: 's!7' } } } }), envBytes = 'CONSOLE_ENCRYPTION_KEY=SyntheticEnvironmentOnlyKey\n';
      writeFileSync(ledgerPath, ledgerBytes, { mode: 0o600 }); writeFileSync(envPath, envBytes, { mode: 0o600 });
      const rows = [{ file: 'own.log', kind: 'owned-container-log', complete: true, ownContainer: true, stdout: true, stderr: true, clipped: false },
        { file: 'audit.json', kind: 'actual-audit-json', complete: true, actualAudit: true }].map(row => {
        const bytes = row.file === 'own.log' ? 'synthetic own log' : '[{"action":"synthetic"}]';
        writeFileSync(resolve(inputRoot, row.file), bytes, { mode: 0o600 }); return { ...row, byteCount: Buffer.byteLength(bytes), sha256: hash(bytes) };
      });
      writeFileSync(resolve(inputRoot, 'manifest.json'), JSON.stringify({ version: 1, complete: true, capturedAt: '2026-10-15T00:00:00Z', files: rows }), { mode: 0o600 });
      const config = { repository, privateRoot, inputRoot, buildRoot, ledgerPaths: [ledgerPath], environmentPaths: [envPath] };
      let enumerations = 0;
      const report = runCurrentSecretScan(config, { enumerateRepository: () => { enumerations++; throw Error('MUST_NOT_ENUMERATE'); } });
      expect(report).toMatchObject({ passed: false, findingCount: 0, actualSecretCount: 0, byteCount: 0,
        failure: { code: 'SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW', materialReview: { inputSha256: hash(ledgerBytes), inputByteCount: Buffer.byteLength(ledgerBytes), configurationKeyContext: true } } });
      expect(enumerations).toBe(0); expect(report.files).toEqual([]);
      const output = JSON.stringify(report); expect(output).not.toContain('s!7'); expect(output).not.toContain(hash('s!7'));
      expect(() => writeCurrentScanPrivateMaterialReview(config, report)).toThrow('SCAN_PRIVATE_DIAGNOSTIC_OPT_IN_REQUIRED');
      const opted = { ...config, privateMaterialDiagnostic: true };
      expect(writeCurrentScanPrivateMaterialReview(opted, { ...report })).toBeNull();
      const diagnostic = writeCurrentScanPrivateMaterialReview(opted, report)!;
      const path = resolve(privateRoot, diagnostic.name), bytes = readFileSync(path), stat = lstatSync(path), parsed = JSON.parse(bytes.toString('utf8'));
      expect(stat.mode & 0o777).toBe(0o600); expect(stat.isFile()).toBe(true); expect(stat.nlink).toBe(1);
      expect(diagnostic).toMatchObject({ privateOnly: true, byteCount: bytes.length });
      expect(diagnostic).not.toHaveProperty('sha256');
      expect(JSON.stringify(diagnostic)).not.toContain(hash('s!7'));
      expect(parsed).toMatchObject({ privateDiagnosticOnly: true, scanPassed: false, originalFailureCode: 'SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW',
        materialReview: { valueSha256: hash('s!7'), characterLength: 3, configurationKeyContext: true } });
      expect(bytes.toString('utf8')).not.toContain('s!7');
      expect(readFileSync(ledgerPath, 'utf8')).toBe(ledgerBytes); expect(readFileSync(envPath, 'utf8')).toBe(envBytes);
      expect(report.passed).toBe(false); expect(report.findingCount).toBe(0);
      chmodSync(privateRoot, 0o755);
      expect(() => writeCurrentScanPrivateMaterialReview(opted, report)).toThrow('SCAN_PRIVATE_DIRECTORY_REQUIRED');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

describe('M11 parsed decK Kong Upstream public cookie-path classification', () => {
  const yaml = (path = '/', version = '"1.1"') => `_format_version: ${version}\nupstreams:\n - name: source-only-upstream\n   hash_on_cookie_path: ${JSON.stringify(path)}\n   hash_on_cookie: null\n`;
  const base = () => ({
    requests: [{ path: '/consumers/source-only/key-auth', body: { key: 'SyntheticApiKey!SourceOnly' }, headers: { 'X-CSRF-Token': 'SyntheticCsrf!SourceOnly' } }],
    sessions: { admin: { password: 'SyntheticPassword!SourceOnly', cookie: 'kongpilot_access=SyntheticSession!SourceOnly' } },
  });
  const env = { CONSOLE_ENCRYPTION_KEY: 'SyntheticEnvironmentKey!SourceOnly' };

  it.each(['/', '/public-cookie-path-source-only'])('does not collect the exact public Upstream path %s while retaining every real secret kind', publicPath => {
    const ledger = { ...base(), requests: [...base().requests, { rawResponseText: yaml(publicPath) }] };
    const before = JSON.stringify(ledger), material = collectCurrentScanMaterial([ledger], [env]);
    expect(material.some((row: any) => row.value === publicPath)).toBe(false);
    for (const kind of ['api-key', 'password', 'cookie', 'csrf', 'environment-secret'])
      expect(material.some((row: any) => row.kinds.includes(kind))).toBe(true);
    expect(JSON.stringify(ledger)).toBe(before);
  });

  it('still collects the same long path when separately present as an actual credential', () => {
    const value = '/public-cookie-path-source-only';
    const material = collectCurrentScanMaterial([{ ...base(), rawResponseText: yaml(value), credentials: { key: value } }], [env]);
    expect(material.find((row: any) => row.value === value)?.kinds).toContain('api-key');
  });

  it.each([
    ['JSON-only entity shape', { upstreams: [{ name: 'source-only', hash_on_cookie_path: '/' }] }],
    ['different format version', { rawResponseText: yaml('/', '"3.0"') }],
    ['numeric format version', { rawResponseText: yaml('/', '1.1') }],
    ['missing upstream name', { rawResponseText: '_format_version: "1.1"\nupstreams:\n - hash_on_cookie_path: /\n' }],
    ['different property case', { rawResponseText: '_format_version: "1.1"\nupstreams:\n - name: source-only\n   HASH_ON_COOKIE_PATH: /\n' }],
    ['nested config', { rawResponseText: '_format_version: "1.1"\nupstreams:\n - name: source-only\n   config:\n     hash_on_cookie_path: /\n' }],
    ['nested credentials', { rawResponseText: '_format_version: "1.1"\nupstreams:\n - name: source-only\n   credentials:\n     hash_on_cookie_path: /\n' }],
    ['credential-named export ancestor', { credentials: { rawResponseText: yaml() } }],
    ['same row also aliases outside Upstreams', { rawResponseText: '_format_version: "1.1"\nupstreams: &rows\n - name: source-only\n   hash_on_cookie_path: /\nelsewhere: *rows\n' }],
    ['other entity field', { rawResponseText: '_format_version: "1.1"\nconsumers:\n - username: source-only\n   hash_on_cookie_path: /\n' }],
    ['actual short session cookie', { rawResponseText: yaml(), sessions: { cookie: '/' } }],
    ['actual short HTTP Cookie', { rawResponseText: yaml(), headers: { Cookie: '/' } }],
    ['actual short Set-Cookie member', { rawResponseText: yaml(), headers: { 'Set-Cookie': 'kongpilot_access=/' } }],
    ['actual short credential', { rawResponseText: yaml(), credentials: { key: '/' } }],
    ['actual short password', { rawResponseText: yaml(), password: '/' }],
    ['actual short token', { rawResponseText: yaml(), token: '/' }],
  ] as const)('retains fail-closed rejection for %s', (_name, extra) => {
    expect(() => collectCurrentScanMaterial([{ ...base(), ...extra }], [env])).toThrow('SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW');
  });
});
