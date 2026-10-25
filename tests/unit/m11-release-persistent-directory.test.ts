// @ts-nocheck -- real local filesystem fixtures; no lab secret, network or DB access.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync,
  renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ReleaseHarness } from '../security/lib/release-harness.mjs';
import { selectReleasePrivateDirectory, selectReleaseReportDirectory } from '../security/lib/release-private-directory.mjs';

let root, directory, reportDirectory;
const ledger = () => join(directory, 'm11-harness.json');
const syntheticEnv = path => writeFileSync(join(path, 'lab.env'), 'LAB_BOOTSTRAP_USER=synthetic-unused\nLAB_BOOTSTRAP_PASSWORD=SyntheticUnusedOnly\n', { mode: 0o600 });
const privateDir = name => { const path = join(root, name); mkdirSync(path, { mode: 0o700 }); syntheticEnv(path); return path; };
const unknownPacket = () => ({ label: 'original-unknown', method: 'POST', path: '/synthetic-never-sent',
  key: randomUUID(), body: { synthetic: true }, bodyHash: createHash('sha256').update(JSON.stringify({ synthetic: true })).digest('hex'), actorId: null, sessionId: null,
  state: 'response_unknown', startedAt: '2026-10-15T00:00:00.000Z' });

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'kongpilot-private-selector-synthetic-'));
  directory = privateDir('run');
  reportDirectory = resolve('artifacts/M11/runs', `synthetic-directory-${randomUUID()}`);
  vi.stubEnv('RELEASE_LAB_READY', 'true');
  vi.stubEnv('RELEASE_LAB_PRIVATE_DIR', directory);
  vi.stubEnv('RELEASE_LAB_REPORT_DIRECTORY', reportDirectory);
  vi.stubGlobal('fetch', vi.fn(() => { throw Error('SYNTHETIC_TEST_MUST_NEVER_SEND'); }));
});
afterEach(() => {
  vi.unstubAllGlobals(); vi.unstubAllEnvs();
  rmSync(root, { recursive: true, force: true });
  rmSync(reportDirectory, { recursive: true, force: true });
});

describe('operator-selected private release directory', () => {
  it('creates a separate version 1 ledger with owner-only bytes and same-directory resume', () => {
    const a = new ReleaseHarness('M11');
    const bytes = readFileSync(ledger()), b = new ReleaseHarness('M11', { resume: true });
    expect(a.directory).toBe(directory); expect(b.state).toEqual(a.state);
    expect(a.state.privateStorageBinding).toEqual({ directory, device: statSync(directory).dev, inode: statSync(directory).ino });
    expect(statSync(ledger()).mode & 0o777).toBe(0o600);
    expect(readFileSync(ledger())).toEqual(bytes); expect(fetch).not.toHaveBeenCalled();
  });

  it.each(['relative', 'parent-segment', 'trailing-slash', 'empty', 'backslash', 'missing'])('rejects a %s selector before ledger creation', variant => {
    const value = { relative: 'synthetic/run', 'parent-segment': `${directory}/../run`, 'trailing-slash': `${directory}/`,
      empty: '', backslash: `${directory}\\other`, missing: join(root, 'not-created') }[variant];
    vi.stubEnv('RELEASE_LAB_PRIVATE_DIR', value);
    expect(() => selectReleasePrivateDirectory()).toThrow('RELEASE_LEDGER_PRIVATE_DIRECTORY_INVALID');
    expect(existsSync(ledger())).toBe(false); expect(fetch).not.toHaveBeenCalled();
  });

  it.each([0o755, 0o750, 0o770, 0o777])('rejects a private directory with mode %i', mode => {
    chmodSync(directory, mode);
    expect(() => new ReleaseHarness('M11')).toThrow('RELEASE_LEDGER_PRIVATE_DIRECTORY_INVALID');
    expect(existsSync(ledger())).toBe(false);
  });

  it.each(['leaf', 'ancestor'])('rejects a symlink at the %s without following private files', variant => {
    const alias = join(root, 'alias'); symlinkSync(directory, alias);
    let selector = alias;
    if (variant === 'ancestor') { mkdirSync(join(directory, 'child'), { mode: 0o700 }); syntheticEnv(join(directory, 'child')); selector = join(alias, 'child'); }
    vi.stubEnv('RELEASE_LAB_PRIVATE_DIR', selector);
    expect(() => new ReleaseHarness('M11')).toThrow('RELEASE_LEDGER_PRIVATE_DIRECTORY_INVALID');
    expect(existsSync(ledger())).toBe(false);
  });

  it.each(['public-mode', 'symlink', 'hardlink'])('rejects an unsafe lab.env (%s) without loading a ledger', variant => {
    const env = join(directory, 'lab.env'), victim = join(root, 'synthetic-env-victim');
    if (variant === 'public-mode') chmodSync(env, 0o644);
    if (variant === 'symlink') { renameSync(env, victim); symlinkSync(victim, env); }
    if (variant === 'hardlink') linkSync(env, victim);
    expect(() => new ReleaseHarness('M11')).toThrow('RELEASE_LAB_PRIVATE_ENV_REQUIRED');
    expect(existsSync(ledger())).toBe(false); expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects a changed environment selector before sending or changing original bytes', async () => {
    const h = new ReleaseHarness('M11'), bytes = readFileSync(ledger());
    vi.stubEnv('RELEASE_LAB_PRIVATE_DIR', privateDir('other'));
    await expect(h.request(null, '/synthetic-never-sent', 'POST', {})).rejects.toThrow('RELEASE_LEDGER_SAVE_PATH_INVALID');
    expect(readFileSync(ledger())).toEqual(bytes); expect(fetch).not.toHaveBeenCalled();
  });

  it.each(['directory', 'path', 'storage-binding'])('rejects a tampered %s without replacing the ledger', variant => {
    const h = new ReleaseHarness('M11'), bytes = readFileSync(ledger());
    if (variant === 'directory') h.directory = privateDir('other');
    if (variant === 'path') h.privatePath = join(directory, 'm10-harness.json');
    if (variant === 'storage-binding') h.state.privateStorageBinding.inode++;
    expect(() => h.save()).toThrow(variant === 'storage-binding' ? 'RELEASE_LEDGER_STORAGE_BINDING_INVALID' : 'RELEASE_LEDGER_SAVE_PATH_INVALID');
    expect(readFileSync(ledger())).toEqual(bytes); expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects replacement of a previously selected directory even with correct new permissions', () => {
    const h = new ReleaseHarness('M11'), bytes = readFileSync(ledger()), original = join(root, 'original');
    renameSync(directory, original); mkdirSync(directory, { mode: 0o700 }); syntheticEnv(directory);
    expect(() => h.save()).toThrow('RELEASE_LEDGER_PRIVATE_DIRECTORY_INVALID');
    expect(readFileSync(join(original, 'm11-harness.json'))).toEqual(bytes); expect(existsSync(ledger())).toBe(false);
  });

  it('does not permit a different selected run to adopt a copied ledger or old credentials', () => {
    new ReleaseHarness('M11'); const original = readFileSync(ledger()), other = privateDir('other');
    copyFileSync(ledger(), join(other, 'm11-harness.json')); chmodSync(join(other, 'm11-harness.json'), 0o600);
    vi.stubEnv('RELEASE_LAB_PRIVATE_DIR', other);
    expect(() => new ReleaseHarness('M11', { resume: true })).toThrow('RELEASE_LEDGER_STORAGE_BINDING_INVALID');
    expect(readFileSync(ledger())).toEqual(original); expect(readFileSync(join(other, 'm11-harness.json'))).toEqual(original);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('does not import a historical default RAM-format ledger into a custom run', () => {
    const original = JSON.stringify({ version: 1, milestone: 'M11', requests: [unknownPacket()], sessions: { original: 'synthetic' } });
    writeFileSync(ledger(), original, { mode: 0o600 });
    expect(() => new ReleaseHarness('M11', { resume: true })).toThrow('RELEASE_LEDGER_STORAGE_BINDING_INVALID');
    expect(readFileSync(ledger(), 'utf8')).toBe(original); expect(fetch).not.toHaveBeenCalled();
  });

  it('retains an unknown original packet after resume and forbids a new-key replay', async () => {
    const h = new ReleaseHarness('M11'); h.state.requests.push(unknownPacket()); h.save();
    const original = readFileSync(ledger()), resumed = new ReleaseHarness('M11', { resume: true });
    expect(readFileSync(ledger())).toEqual(original);
    await expect(resumed.request(null, '/synthetic-never-sent', 'POST', { synthetic: true }, { key: randomUUID() }))
      .rejects.toThrow('ORIGINAL_UNRESOLVED_RELEASE_WRITE_NO_REPLAY');
    expect(readFileSync(ledger())).toEqual(original); expect(fetch).not.toHaveBeenCalled();
  });

  it('keeps failed once receipts non-replayable after selecting persistent storage', async () => {
    const h = new ReleaseHarness('M11'), packet = unknownPacket(); h.state.requests.push(packet); h.save();
    const original = readFileSync(ledger());
    await expect(h.once(packet.label, null, packet.path, packet.method, packet.body)).rejects.toThrow('ORIGINAL_FIXTURE_RECEIPT_NOT_SUCCESSFUL_NO_REPLAY');
    expect(readFileSync(ledger())).toEqual(original); expect(fetch).not.toHaveBeenCalled();
  });

  it('keeps stale resumed instances unable to overwrite the first writer', () => {
    const a = new ReleaseHarness('M11'), b = new ReleaseHarness('M11', { resume: true });
    a.state.requests.push(unknownPacket()); a.save(); const original = readFileSync(ledger());
    b.state.phase = 'stale'; expect(() => b.save()).toThrow('RELEASE_LEDGER_STALE_SNAPSHOT');
    expect(readFileSync(ledger())).toEqual(original);
  });
});

describe('isolated append-only release report location', () => {
  it('creates the selected run directory and leaves existing milestone reports untouched', () => {
    const h = new ReleaseHarness('M11'), legacyPath = resolve('artifacts/M11/native-verification.json');
    const legacy = existsSync(legacyPath) ? readFileSync(legacyPath) : null;
    expect(h.reportPath).toBe(join(reportDirectory, 'native-verification.json'));
    h.report(false, 'SYNTHETIC_SOURCE_ONLY');
    expect(JSON.parse(readFileSync(h.reportPath, 'utf8'))).toMatchObject({ passed: false, milestone: 'M11', productionDeployment: false });
    expect(existsSync(legacyPath) ? readFileSync(legacyPath) : null).toEqual(legacy);
  });

  it('preserves the first custom report exactly and refuses overwriting it', () => {
    const h = new ReleaseHarness('M11'); h.report(false, 'SYNTHETIC_FIRST'); const original = readFileSync(h.reportPath);
    expect(() => h.report(true)).toThrow('ORIGINAL_RELEASE_REPORT_PRESENT_NO_OVERWRITE');
    expect(readFileSync(h.reportPath)).toEqual(original);
  });

  it.each(['outside-runs', 'same-milestone-root', 'wrong-milestone', 'parent-segment', 'trailing-slash'])('rejects a %s report selector', variant => {
    const selector = { 'outside-runs': join(root, 'reports'), 'same-milestone-root': 'artifacts/M11',
      'wrong-milestone': 'artifacts/M10/runs/synthetic', 'parent-segment': 'artifacts/M11/runs/synthetic/../other',
      'trailing-slash': `${reportDirectory}/` }[variant];
    vi.stubEnv('RELEASE_LAB_REPORT_DIRECTORY', selector);
    expect(() => selectReleaseReportDirectory('M11')).toThrow('RELEASE_REPORT_DIRECTORY_INVALID');
  });

  it.each(['symlink', 'group-writable'])('rejects an unsafe %s report directory before writing', variant => {
    const h = new ReleaseHarness('M11'); mkdirSync(resolve(reportDirectory, '..'), { recursive: true });
    if (variant === 'symlink') symlinkSync(root, reportDirectory);
    else { mkdirSync(reportDirectory); chmodSync(reportDirectory, 0o775); }
    expect(() => h.report(false)).toThrow('RELEASE_REPORT_DIRECTORY_INVALID');
    expect(existsSync(join(root, 'native-verification.json'))).toBe(false);
  });

  it.each(['environment', 'object'])('rejects a changed %s report selector', variant => {
    const h = new ReleaseHarness('M11');
    if (variant === 'environment') vi.stubEnv('RELEASE_LAB_REPORT_DIRECTORY', `${reportDirectory}-changed`);
    else h.reportPath = resolve('artifacts/M11/native-verification.json');
    expect(() => h.report(false)).toThrow('RELEASE_REPORT_SAVE_PATH_INVALID');
    expect(existsSync(join(reportDirectory, 'native-verification.json'))).toBe(false);
  });

  it('does not follow an existing report symlink or overwrite its target', () => {
    const h = new ReleaseHarness('M11'), victim = join(root, 'report-victim.json');
    mkdirSync(reportDirectory, { recursive: true }); writeFileSync(victim, 'SyntheticOriginalReport'); symlinkSync(victim, h.reportPath);
    expect(() => h.report(false)).toThrow('ORIGINAL_RELEASE_REPORT_PRESENT_NO_OVERWRITE');
    expect(readFileSync(victim, 'utf8')).toBe('SyntheticOriginalReport');
  });
});
