import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { collectCurrentScanMaterial, runCurrentSecretScan } from '../security/m11-current-secret-scan.mjs';

const checkpoint = 'checkpoint-api-key-not-issued';
const key = 'SyntheticIssuedApiKey!ProfileOnly';
const environment = { CONSOLE_ENCRYPTION_KEY: 'SyntheticEnvironmentKey!ProfileOnly' };
const ledger = () => ({ sessions: { account: { password: 'SyntheticPassword!ProfileOnly',
  cookie: 'kongpilot_access=SyntheticAccessCookie!ProfileOnly', csrf: 'SyntheticCsrf!ProfileOnly' } } });
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

function syntheticScan(fn: (f: any) => void) {
  const root = mkdtempSync(resolve(tmpdir(), 'kongpilot-scan-profile-synthetic-'));
  try {
    const repository = resolve(root, 'repository'), privateRoot = resolve(root, 'private'), inputRoot = resolve(privateRoot, 'inputs'), buildRoot = resolve(root, 'build');
    for (const path of [repository, privateRoot, inputRoot, buildRoot]) mkdirSync(path, { mode: 0o700 });
    const write = (path: string, value: string) => writeFileSync(path, value, { mode: 0o600 });
    const sourcePath = resolve(repository, 'public.txt'); write(sourcePath, 'synthetic clean public source');
    for (const group of ['console-api', 'console-web', 'portal-web']) { const path = resolve(buildRoot, group); mkdirSync(path, { mode: 0o700 }); write(resolve(path, 'output.bin'), 'synthetic clean build'); }
    const ledgerPath = resolve(privateRoot, 'ledger.json'), envPath = resolve(privateRoot, 'lab.env');
    const setLedger = (value: unknown) => write(ledgerPath, JSON.stringify(value)); setLedger(ledger());
    write(envPath, `CONSOLE_ENCRYPTION_KEY=${environment.CONSOLE_ENCRYPTION_KEY}\n`);
    const files = [{ file: 'own.log', kind: 'owned-container-log', complete: true, ownContainer: true, stdout: true, stderr: true, clipped: false },
      { file: 'audit.json', kind: 'actual-audit-json', complete: true, actualAudit: true }].map(row => {
      const bytes = row.file === 'own.log' ? 'synthetic own stdout and stderr' : '[{"action":"synthetic"}]';
      write(resolve(inputRoot, row.file), bytes); return { ...row, sha256: hash(bytes), byteCount: Buffer.byteLength(bytes) };
    });
    write(resolve(inputRoot, 'manifest.json'), JSON.stringify({ version: 1, complete: true, capturedAt: '2026-10-15T00:00:00Z', files }));
    const config = { repository, privateRoot, inputRoot, buildRoot, ledgerPaths: [ledgerPath], environmentPaths: [envPath] };
    let enumerations = 0;
    const run = (profile?: unknown) => runCurrentSecretScan({ ...config, ...(profile === undefined ? {} : { profile }) }, { enumerateRepository: () => { enumerations++; return ['public.txt']; } });
    fn({ config, sourcePath, ledgerPath, envPath, setLedger, write, run, enumerationCount: () => enumerations });
  } finally { rmSync(root, { recursive: true, force: true }); }
}

describe('M11 fixed explicit scanner profiles preserve actual material extraction', () => {
  it('retains strict five-kind coverage by default and when explicitly selected', () => {
    for (const profile of [undefined, 'credential-complete'])
      expect(() => collectCurrentScanMaterial([ledger()], [environment], profile)).toThrow('SCAN_REQUIRED_MATERIAL_KINDS_MISSING');
    const complete = { ...ledger(), credentials: { key } };
    const values = collectCurrentScanMaterial([complete], [environment]);
    expect(values.some((row: any) => row.value === key && row.kinds.includes('api-key'))).toBe(true);
    expect(values).toEqual(collectCurrentScanMaterial([complete], [environment], checkpoint));
  });

  it('allows exactly the actual four kinds at a checkpoint without inventing an API key', () => {
    const values = collectCurrentScanMaterial([ledger()], [environment], checkpoint);
    expect(values.filter((row: any) => row.kinds.includes('api-key'))).toEqual([]);
    for (const kind of ['password', 'cookie', 'csrf', 'environment-secret'])
      expect(values.some((row: any) => row.kinds.includes(kind))).toBe(true);
  });

  it.each(['password', 'cookie', 'csrf', 'environment-secret'])('still rejects a checkpoint missing %s', kind => {
    const value: any = ledger();
    if (kind !== 'environment-secret') delete value.sessions.account[kind];
    expect(() => collectCurrentScanMaterial([value], kind === 'environment-secret' ? [{}] : [environment], checkpoint)).toThrow('SCAN_REQUIRED_MATERIAL_KINDS_MISSING');
  });

  it('does not bypass the short-key gate when API key material is optional', () => {
    expect(() => collectCurrentScanMaterial([{ ...ledger(), credentials: { key: 'x!7' } }], [environment], checkpoint)).toThrow('SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW');
  });

  it('collects nested new Portal-case API keys with identical values and matching coverage under both profiles', () => {
    const value = { ...ledger(), currentPortalNaturalCases: { 'ledger-fix-20261015': { g: { issuedKey: key },
      portalPackets: [{ path: '/consumers/u/credentials/key-auth', body: { key } }] } } };
    const complete = collectCurrentScanMaterial([value], [environment]), current = collectCurrentScanMaterial([value], [environment], checkpoint);
    expect(current).toEqual(complete);
    expect(current.filter((row: any) => row.kinds.includes('api-key'))).toEqual([expect.objectContaining({ value: key })]);
  });

  it.each(['', 'unknown', 'checkpoint', '__proto__', 'constructor', null, [], ['password'], { requiredKinds: [] }])('rejects invalid or arbitrary kind-list profile %j', profile => {
    expect(() => collectCurrentScanMaterial([ledger()], [environment], profile)).toThrow('SCAN_PROFILE_INVALID');
  });
});

describe('M11 synthetic full scanner reports checkpoint scope truthfully', () => {
  it('completes all scan groups for actual four-kind checkpoint while the same input fails default complete coverage', () => syntheticScan(f => {
    const before = hash(readFileSync(f.ledgerPath)), complete = f.run();
    expect(complete).toMatchObject({ passed: false, profile: 'credential-complete', finalCredentialComplete: false,
      apiKeyIssuanceAcceptance: false, exactAPIKeyMaterials: null, failure: { code: 'SCAN_REQUIRED_MATERIAL_KINDS_MISSING' } });
    expect(f.enumerationCount()).toBe(0);
    const report = f.run(checkpoint);
    expect(report).toMatchObject({ passed: true, profile: checkpoint, scope: 'checkpoint-without-api-key-issuance-acceptance',
      requiredMaterialKinds: ['password', 'cookie', 'csrf', 'environment-secret'], exactAPIKeyMaterials: 0,
      apiKeyIssuanceAcceptance: false, finalCredentialComplete: false, findingCount: 0 });
    expect(Object.values(report.groups).every((count: any) => count > 0)).toBe(true);
    expect(f.enumerationCount()).toBe(2); expect(hash(readFileSync(f.ledgerPath))).toBe(before);
    expect(JSON.stringify(report)).not.toContain(environment.CONSOLE_ENCRYPTION_KEY);
  }));

  it('keeps checkpoint scope narrow with an existing real-key material and scans that key for findings', () => syntheticScan(f => {
    f.setLedger({ ...ledger(), currentPortalNaturalCases: { current: { g: { issuedKey: key } } } });
    const clean = f.run(checkpoint);
    expect(clean).toMatchObject({ passed: true, exactAPIKeyMaterials: 1, apiKeyIssuanceAcceptance: false, finalCredentialComplete: false });
    f.write(f.sourcePath, Buffer.from(key).toString('base64'));
    const leaked = f.run(checkpoint);
    expect(leaked).toMatchObject({ passed: false, exactAPIKeyMaterials: 1, apiKeyIssuanceAcceptance: false, finalCredentialComplete: false,
      failure: { code: 'SCAN_SECRET_FINDINGS_REQUIRE_REVIEW' } });
    expect(leaked.findings.some((item: any) => item.kinds.includes('api-key'))).toBe(true);
    expect(JSON.stringify(leaked)).not.toContain(key);
  }));

  it('marks complete scan material coverage only after a full default-profile pass without claiming issuance acceptance', () => syntheticScan(f => {
    f.setLedger({ ...ledger(), credentials: { key } });
    expect(f.run()).toMatchObject({ passed: true, profile: 'credential-complete', scope: 'credential-complete-current-material-scan',
      exactAPIKeyMaterials: 1, finalCredentialComplete: true, apiKeyIssuanceAcceptance: false,
      requiredMaterialKinds: ['password', 'api-key', 'cookie', 'csrf', 'environment-secret'] });
  }));

  it('rejects unknown runner profile before any filesystem or Git use', () => {
    let called = false;
    const result = runCurrentSecretScan({ profile: 'not-a-profile' }, { enumerateRepository: () => { called = true; throw Error('MUST_NOT_RUN'); } });
    expect(result).toMatchObject({ passed: false, profile: null, scope: 'unvalidated', exactAPIKeyMaterials: null,
      apiKeyIssuanceAcceptance: false, finalCredentialComplete: false, failure: { code: 'SCAN_PROFILE_INVALID' } });
    expect(called).toBe(false); expect(result.files).toEqual([]); expect(result.materialFiles).toEqual([]);
  });

  it('rejects an unknown main environment profile without reading any handoff file', () => {
    const prefix = 'KONGPILOT_SECRET_SCAN_';
    const vars = Object.fromEntries(Object.entries({ READY: 'true', INPUTS_FROZEN: 'true', PROFILE: 'unknown',
      LEDGER_PATHS_JSON: '["/synthetic-never-read/ledger"]', ENV_PATHS_JSON: '["/synthetic-never-read/env"]' }).map(([name, value]) => [prefix + name, value]));
    const child = spawnSync(process.execPath, [resolve('tests/security/m11-current-secret-scan.mjs')], {
      cwd: resolve('.'), env: { PATH: process.env.PATH, ...vars }, encoding: 'utf8', timeout: 10000,
    });
    expect(child.error).toBeUndefined(); expect(child.status).toBe(1);
    expect(JSON.parse(child.stdout)).toEqual({ passed: false, failure: { code: 'SCAN_PROFILE_INVALID' } });
    expect(child.stderr).toBe('');
  });
});
