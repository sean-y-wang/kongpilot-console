import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { collectCurrentScanMaterial, currentScanGitPaths, currentScanPublishablePath, parseCurrentScanEnvironment, runCurrentSecretScan } from '../m11-current-secret-scan.mjs';

/** All bytes originate in this test's fresh own temporary directory. No actual
 * repository enumeration, private ledger, service or credential is accessed. */
export function runCurrentScannerSyntheticSelfTest() {
  const root = mkdtempSync(resolve(tmpdir(), 'kongpilot-m11-secret-synthetic-')); let checks = 0;
  const hash = bytes => createHash('sha256').update(bytes).digest('hex');
  const write = (path, value) => writeFileSync(path, value, { mode: 0o600 });
  try {
    const repository = resolve(root, 'repository'), privateRoot = resolve(root, 'private'), inputRoot = resolve(privateRoot, 'inputs'), buildRoot = resolve(root, 'build');
    for (const path of [repository, privateRoot, inputRoot, buildRoot, ...['console-api', 'console-web', 'portal-web'].map(name => resolve(buildRoot, name))]) mkdirSync(path, { mode: 0o700 });
    const apiKey = `SyntheticApi!${randomUUID()}`, password = `SyntheticPassword!${randomUUID()}`, cookie = `SyntheticCookie!${randomUUID()}`, csrf = `SyntheticCsrf!${randomUUID()}`;
    const credentialUUID = randomUUID(), publicUUID = randomUUID(), environmentSecret = randomUUID().replaceAll('-', '') + randomUUID().replaceAll('-', '');
    const ledgerPath = resolve(privateRoot, 'ledger.json'), envPath = resolve(privateRoot, 'lab.env');
    const ledger = { requests: [{ key: publicUUID, path: '/clusters/c/consumers/u/credentials/key-auth', body: { key: apiKey }, headers: { 'X-CSRF-Token': csrf } }],
      sessions: { admin: { password, cookie: `kongpilot_access=${cookie}; kongpilot_csrf=${csrf}` } },
      currentPortal: { issuedKey: credentialUUID } };
    write(ledgerPath, JSON.stringify(ledger)); write(envPath, `CONSOLE_ENCRYPTION_KEY=${environmentSecret}\n`);
    const source = resolve(repository, 'public.txt'); write(source, `safe source and public idempotency ${publicUUID}`);
    for (const name of ['console-api', 'console-web', 'portal-web']) write(resolve(buildRoot, name, 'asset.bin'), Buffer.from([1, 2, 3, 0, 255]));
    write(resolve(inputRoot, 'console-api.log'), 'current complete own stdout and stderr\n');
    write(resolve(inputRoot, 'audit.json'), JSON.stringify([{ action: 'source-only', before: null, after: { key: '[REDACTED]' } }]));
    const capture = { version: 1, complete: true, capturedAt: '2026-10-15T00:00:00Z', files: [
      { file: 'console-api.log', kind: 'owned-container-log', complete: true, ownContainer: true, stdout: true, stderr: true, clipped: false },
      { file: 'audit.json', kind: 'actual-audit-json', complete: true, actualAudit: true },
    ].map(row => { const bytes = readFileSync(resolve(inputRoot, row.file)); return { ...row, sha256: hash(bytes), byteCount: bytes.length }; }) };
    const manifestPath = resolve(inputRoot, 'manifest.json'); write(manifestPath, JSON.stringify(capture));
    const config = { repository, privateRoot, inputRoot, buildRoot, ledgerPaths: [ledgerPath], environmentPaths: [envPath] };
    const originalLedgerHash = hash(readFileSync(ledgerPath));
    const enumerateRepository = () => ['public.txt'];
    const run = () => runCurrentSecretScan(config, { enumerateRepository });
    let report = run(); assert.equal(report.passed, true); assert(Object.values(report.groups).every(value => value > 0)); checks++;
    assert.equal(hash(readFileSync(ledgerPath)), originalLedgerHash); checks++;
    const output = JSON.stringify(report); for (const secret of [apiKey, password, cookie, csrf, credentialUUID, environmentSecret]) assert(!output.includes(secret)); checks++;
    write(source, Buffer.from(apiKey).toString('base64')); report = run(); assert.equal(report.passed, false); assert(report.findings.some(item => item.kinds.includes('api-key'))); checks++;
    write(source, credentialUUID); report = run(); assert.equal(report.failure.code, 'SCAN_SECRET_FINDINGS_REQUIRE_REVIEW'); assert(report.findingCount > 0); checks++;
    write(source, 'clean'); const binary = resolve(buildRoot, 'console-web', 'asset.bin'); write(binary, Buffer.concat([Buffer.from([0, 255]), Buffer.from(password)]));
    report = run(); assert(report.findings.some(item => item.path.startsWith('build/console-web/') && item.kinds.includes('password'))); checks++;
    write(binary, 'clean');
    const privateBefore = hash(readFileSync(ledgerPath)); let calls = 0;
    report = runCurrentSecretScan(config, { enumerateRepository: () => { if (++calls === 2) write(ledgerPath, JSON.stringify({ ...ledger, extra: true })); return ['public.txt']; } });
    assert.equal(report.failure.code, 'SCAN_PRIVATE_INPUT_CHANGED'); assert.notEqual(hash(readFileSync(ledgerPath)), privateBefore); checks++;
    write(ledgerPath, JSON.stringify(ledger));
    chmodSync(ledgerPath, 0o644); report = run(); assert.equal(report.failure.code, 'SCAN_PRIVATE_FILE_REQUIRED'); checks++; chmodSync(ledgerPath, 0o600);
    const linked = resolve(repository, 'linked.txt'); symlinkSync(ledgerPath, linked);
    report = runCurrentSecretScan(config, { enumerateRepository: () => ['linked.txt', 'public.txt'] }); assert.equal(report.failure.code, 'SCAN_REPOSITORY_REGULAR_FILE_REQUIRED'); checks++; unlinkSync(linked);
    const innerLink = resolve(buildRoot, 'console-api', 'private-link'); symlinkSync(ledgerPath, innerLink); report = run(); assert.equal(report.failure.code, 'SCAN_SYMLINK_REFUSED'); checks++; unlinkSync(innerLink);
    const hardlink = resolve(repository, 'hardlink.txt'); linkSync(source, hardlink);
    report = run(); assert.equal(report.failure.code, 'SCAN_REGULAR_SINGLE_LINK_FILE_REQUIRED'); checks++; unlinkSync(hardlink);
    const corrupted = structuredClone(capture); corrupted.files[0].sha256 = '0'.repeat(64); write(manifestPath, JSON.stringify(corrupted)); report = run();
    assert.equal(report.failure.code, 'SCAN_CAPTURE_HASH_OR_SIZE_MISMATCH'); checks++; write(manifestPath, JSON.stringify(capture));
    write(resolve(inputRoot, 'unlisted.log'), 'unlisted'); report = run(); assert.equal(report.failure.code, 'SCAN_UNLISTED_CAPTURE_INPUT'); checks++; unlinkSync(resolve(inputRoot, 'unlisted.log'));
    const incomplete = structuredClone(capture); incomplete.files[0].clipped = true; write(manifestPath, JSON.stringify(incomplete)); report = run();
    assert.equal(report.failure.code, 'SCAN_CAPTURE_MANIFEST_INVALID'); checks++; write(manifestPath, JSON.stringify(capture));
    for (const path of ['../private/ledger.json', '/outside', 'a\\b', 'a/../b', 'a\nb']) assert.throws(() => currentScanPublishablePath(path)); checks++;
    for (const path of ['node_modules/package/a.js', 'apps/console-api/dist/main.js', 'deploy/private/file', '.kongpilot-private/ledger.json']) assert.equal(currentScanPublishablePath(path), false);
    for (const path of ['artifacts/M11/audit-verification.json', 'tests/unit/file.test.ts', '.env.example']) assert.equal(currentScanPublishablePath(path), true); checks++;
    const commands = [], selected = currentScanGitPaths(repository, args => { commands.push(args);
      assert.equal(args[0], 'ls-files'); return { status: 0, stdout: Buffer.from(args.includes('--cached')
        ? 'tracked-ignored.log\0artifacts/M11/audit-verification.json\0apps/console-api/dist/old.js\0'
        : 'untracked-public.txt\0artifacts/M11/new-audit.json\0') }; });
    assert.deepEqual(commands, [['ls-files', '--cached', '-z'], ['ls-files', '--others', '--exclude-standard', '-z']]);
    assert.deepEqual(selected, ['artifacts/M11/audit-verification.json', 'artifacts/M11/new-audit.json', 'tracked-ignored.log', 'untracked-public.txt']); checks++;
    report = runCurrentSecretScan(config, { enumerateRepository: () => ['missing-tracked-file'] }); assert.equal(report.failure.code, 'SCAN_LISTED_FILE_MISSING'); checks++;
    assert.deepEqual({ ...parseCurrentScanEnvironment(Buffer.from('A="literal\\nvalue"\nB=unquoted\nC=\'single value\'\n')) }, { A: 'literal\nvalue', B: 'unquoted', C: 'single value' });
    assert.throws(() => parseCurrentScanEnvironment(Buffer.from('A=one\nA=two\n'))); checks++;
    assert.throws(() => parseCurrentScanEnvironment(Buffer.from('PASSWORD=actualvalue #comment\n')), /SCAN_ENVIRONMENT_AMBIGUOUS_LITERAL/); checks++;
    const nestedKey = `SyntheticNestedKey!${randomUUID()}`, yamlKey = `SyntheticYamlKey!${randomUUID()}`, urlPassword = `SyntheticURL!${randomUUID()}@part`;
    const cipherShapedKey = 'v1.actualApiKeyShape.randomIvPart.actualAuthTag';
    const pluginSecret = 'v1.actualPluginSecret.ivPart.authPart', privateKey = '-----BEGIN PRIVATE KEY-----\nSyntheticOnlyPrivatePemBytes\n-----END PRIVATE KEY-----';
    const bareAuthorization = 'v1.actualAuthorization.ivPart.authPart';
    const extra = { ...ledger, nested: { packets: [{ path: '/clusters/c/consumers/u/credentials/key-auth', body: { key: nestedKey } }] },
      exportPacket: { rawResponseText: `_format_version: "1.1"\nconsumers:\n  - username: source-only\n    keyauth_credentials:\n      - key: ${yamlKey}\n` },
      credentials: { key: cipherShapedKey }, plugin: { config: { secret: pluginSecret } }, certificate: { key: privateKey },
      anotherPacket: { headers: { Authorization: `Bearer ${bareAuthorization}` } }, emptyJar: { cookie: '' } };
    const collected = collectCurrentScanMaterial([extra], [{ CONSOLE_ENCRYPTION_KEY: environmentSecret, DATABASE_URL: `postgres://user:${encodeURIComponent(urlPassword)}@db.invalid/console` }]);
    for (const secret of [nestedKey, yamlKey, urlPassword, cipherShapedKey, pluginSecret, privateKey, bareAuthorization]) assert(collected.some(row => row.value === secret)); checks += 7;
    write(ledgerPath, JSON.stringify(extra)); write(envPath, `CONSOLE_ENCRYPTION_KEY=${environmentSecret}\nDATABASE_URL=postgres://user:${encodeURIComponent(urlPassword)}@db.invalid/console\n`);
    for (const secret of [nestedKey, yamlKey, urlPassword, cipherShapedKey, pluginSecret, privateKey, bareAuthorization]) { write(source, secret); report = run(); assert(report.findingCount > 0); }
    checks++; write(source, 'clean'); write(ledgerPath, JSON.stringify(ledger)); write(envPath, `CONSOLE_ENCRYPTION_KEY=${environmentSecret}\n`);
    assert.throws(() => collectCurrentScanMaterial([{ ...ledger, credentials: { key: 'short' } }], [{ CONSOLE_ENCRYPTION_KEY: environmentSecret }]), /SCAN_SHORT_EXPLICIT_SECRET_REQUIRES_REVIEW/); checks++;
    assert.throws(() => collectCurrentScanMaterial([{ password: 'x'.repeat(16385) }], [{}]), /SECRET_MATERIAL_SIZE_BUDGET/); checks++;
    assert.throws(() => collectCurrentScanMaterial([{}], [{}]), /SCAN_ACTUAL_SECRET_MATERIAL_REQUIRED/); checks++;
    assert.throws(() => collectCurrentScanMaterial([{ password }], [{}]), /SCAN_REQUIRED_MATERIAL_KINDS_MISSING/); checks++;
    report = run(); assert.equal(report.passed, true); assert.equal(hash(readFileSync(ledgerPath)), originalLedgerHash); checks++;
    return { passed: true, checks, actualPrivateMaterialsRead: false, actualGitInvoked: false };
  } finally { rmSync(root, { recursive: true, force: true }); }
}
