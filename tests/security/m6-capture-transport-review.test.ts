import { afterEach, describe, expect, it } from 'vitest';
import { createCipheriv } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CAPTURE_TRANSFER_PROGRAM, captureTransferAAD, cleanupCapturePath, decryptCaptureTransfer,
  publishCaptureReference, validateCaptureAck, validateCaptureBundle,
} from '../../deploy/scripts/capture-existing-metrics-test-reference.mjs';

// Only fabricated test material. This suite never invokes docker, the capture
// CLI, a deployed container, current environment or the real reference path.
const directories: string[] = [];
const cid = '10000000-0000-4000-8000-000000000001';
const captureId = '10000000-0000-4000-8000-000000000002';
const key = Buffer.alloc(32, 0x73);
const purposes = [['native_scrape', 'bff'], ['collector_scrape', 'collector'], ['collector_catalog', 'bff'], ['collector_ingest', 'collector']];
const fakeBundle = () => {
  const tokens = purposes.map(([purpose, audience], index) => ({ clusterId: cid, generation: 4, purpose, audience, token: String.fromCharCode(65 + index).repeat(43) }));
  return { tokens, secrets: tokens.map(row => row.token), users: [] };
};
const baseAck = () => ({ captureId, path: '/dev/shm/kongos-metrics-capture-aB12cD/capture.json', clusterIds: [cid], generations: { [cid]: 4 }, count: 4 });
function captureFile(contents = JSON.stringify(fakeBundle())) {
  const directory = mkdtempSync('/dev/shm/kongos-metrics-capture-'); directories.push(directory); chmodSync(directory, 0o700);
  const path = join(directory, 'capture.json'); writeFileSync(path, contents, { mode: 0o600 }); chmodSync(path, 0o600);
  return { directory, path, ack: { ...baseAck(), path } };
}
function transfer(ack: any, extras: any = {}, timeout = 2500) {
  return spawnSync(process.execPath, ['-e', CAPTURE_TRANSFER_PROGRAM], {
    input: JSON.stringify({ ack, key: key.toString('hex'), ...extras }), encoding: 'utf8', timeout, maxBuffer: 131072,
  });
}
function encrypted(plaintext: string, ack = baseAck()) {
  const iv = Buffer.alloc(12, 0x26), cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(captureTransferAAD(ack)));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return { version: 1, iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), ciphertext: ciphertext.toString('base64') };
}
function refused(result: ReturnType<typeof transfer>) {
  expect(result.error).toBeUndefined(); expect(result.status).toBe(2); expect(result.stdout).toBe('');
  expect(result.stderr).toBe('METRICS_CAPTURE_TRANSFER_FAILED\n');
}
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });

describe('M6 independently executed encrypted tmpfs transfer', () => {
  it('emits only authenticated ciphertext from an actual private inode, with no token/key stdout or stderr', () => {
    const file = captureFile(), result = transfer(file.ack); expect(result.error).toBeUndefined(); expect(result.status).toBe(0); expect(result.stderr).toBe('');
    const envelope = JSON.parse(result.stdout); expect(Object.keys(envelope).sort()).toEqual(['ciphertext', 'iv', 'tag', 'version']);
    for (const value of [...fakeBundle().secrets, key.toString('hex')]) expect(result.stdout.includes(value)).toBe(false);
    expect(CAPTURE_TRANSFER_PROGRAM.includes(key.toString('hex'))).toBe(false);
    expect(validateCaptureBundle(decryptCaptureTransfer(envelope, file.ack, key), file.ack)).toEqual(fakeBundle());
    expect(lstatSync(file.path).mode & 0o777).toBe(0o600);
  });
  it.each([0o644, 0o640, 0o700])('rejects capture file mode %s without emitting plaintext or ciphertext', mode => {
    const file = captureFile(); chmodSync(file.path, mode); refused(transfer(file.ack));
  });
  it('rejects non-private parent mode before opening the file', () => {
    const file = captureFile(); chmodSync(file.directory, 0o755); refused(transfer(file.ack));
  });
  it('rejects a final file symlink and a parent directory symlink', () => {
    const actual = captureFile(), alias = captureFile(); rmSync(alias.path); symlinkSync(actual.path, alias.path); refused(transfer(alias.ack));
    rmSync(alias.directory, { recursive: true }); symlinkSync(actual.directory, alias.directory); refused(transfer(alias.ack));
  });
  it('rejects a hard-linked private file', () => {
    const file = captureFile(); linkSync(file.path, join(file.directory, 'extra-link')); refused(transfer(file.ack));
  });
  it.each([0, 65537])('rejects file byte size %s', size => {
    const file = captureFile('x'.repeat(size)); refused(transfer(file.ack));
  });
  it('rejects directory and FIFO capture targets promptly rather than blocking before fstat', () => {
    const file = captureFile(); rmSync(file.path); mkdirSync(file.path, { mode: 0o600 }); refused(transfer(file.ack)); rmSync(file.path, { recursive: true });
    // A local synthetic FIFO checks O_NONBLOCK. A timeout is a test failure,
    // not a substitute for the production regular-file guard.
    execFileSync('mkfifo', ['-m', '600', file.path]); refused(transfer(file.ack));
  });
  it.each(['extra', 'wrong-key', 'oversize'])('rejects malformed request %s with fixed output only', variant => {
    const file = captureFile(), extras = variant === 'extra' ? { command: 'not-permitted' } : variant === 'wrong-key' ? { key: 'bad' } : { extra: 'x'.repeat(2049) };
    refused(transfer(file.ack, extras));
  });
  it.each(['/tmp/capture.json', '/dev/shm/kongos-metrics-capture-aB12cD/../capture.json', '/dev/shm/kongos-metrics-capture-aB12cD/capture.json\n'])('rejects non-fixed path %s before any read', path => {
    refused(transfer({ ...baseAck(), path }));
  });
});

describe('M6 authenticated protocol and family rejection', () => {
  it.each(['capture-id', 'path', 'generation', 'cluster'])('binds AAD to original acknowledgement %s', change => {
    const original = baseAck(), envelope = encrypted(JSON.stringify(fakeBundle()), original), substituted: any = structuredClone(original);
    if (change === 'capture-id') substituted.captureId = '10000000-0000-4000-8000-000000000003';
    if (change === 'path') substituted.path = '/dev/shm/kongos-metrics-capture-zZ98yY/capture.json';
    if (change === 'generation') substituted.generations[cid] = 5;
    if (change === 'cluster') { const other = '10000000-0000-4000-8000-000000000004'; substituted.clusterIds = [other]; substituted.generations = { [other]: 4 }; }
    expect(() => decryptCaptureTransfer(envelope, substituted, key)).toThrow('METRICS_CAPTURE_TRANSFER_INVALID');
  });
  it.each(['tag', 'ciphertext', 'key'])('rejects tampered %s before JSON can be accepted', change => {
    const envelope = encrypted(JSON.stringify(fakeBundle())), altered: any = { ...envelope }, wrong = Buffer.from(key);
    if (change === 'tag') altered.tag = (envelope.tag.startsWith('0') ? '1' : '0') + envelope.tag.slice(1);
    if (change === 'ciphertext') { const bytes = Buffer.from(envelope.ciphertext, 'base64'); bytes[0] ^= 1; altered.ciphertext = bytes.toString('base64'); }
    if (change === 'key') wrong[0] ^= 1;
    expect(() => decryptCaptureTransfer(altered, baseAck(), wrong)).toThrow('METRICS_CAPTURE_TRANSFER_INVALID');
  });
  it.each(['version', 'extra', 'iv', 'tag', 'noncanonical-base64', 'empty', 'too-large'])('rejects malformed ciphertext envelope %s', variant => {
    const value: any = encrypted(JSON.stringify(fakeBundle()));
    if (variant === 'version') value.version = 2;
    if (variant === 'extra') value.debug = 'must-not-be-used';
    if (variant === 'iv') value.iv = 'f'.repeat(22);
    if (variant === 'tag') value.tag = 'f'.repeat(34);
    if (variant === 'noncanonical-base64') value.ciphertext += '\n';
    if (variant === 'empty') value.ciphertext = '';
    if (variant === 'too-large') value.ciphertext = 'A'.repeat(87388);
    expect(() => decryptCaptureTransfer(value, baseAck(), key)).toThrow('METRICS_CAPTURE_TRANSFER_INVALID');
  });
  it('returns only the fixed error code for authenticated malformed JSON, and refuses a different decrypted token family', () => {
    expect(() => decryptCaptureTransfer(encrypted('private fabricated malformed JSON'), baseAck(), key)).toThrow('METRICS_CAPTURE_TRANSFER_INVALID');
    const wrong = fakeBundle(); wrong.tokens[0].generation = 5;
    const clear = decryptCaptureTransfer(encrypted(JSON.stringify(wrong)), baseAck(), key);
    expect(() => validateCaptureBundle(clear, baseAck())).toThrow('METRICS_CAPTURE_BUNDLE_INVALID');
  });
});

describe('M6 failure cleanup selection and atomic private host publication', () => {
  it('preserves strictly safe cleanup path even if acknowledgement family metadata is invalid', () => {
    const malformed = { ...baseAck(), count: 3 };
    expect(() => validateCaptureAck(malformed, [cid])).toThrow('METRICS_CAPTURE_ACK_INVALID');
    expect(cleanupCapturePath(malformed)).toBe(baseAck().path);
  });
  it.each([{}, { path: '/dev/shm' }, { path: '/tmp/capture.json' }, { path: '/dev/shm/kongos-metrics-capture-aB12cD/../capture.json' }, { path: baseAck().path + '\n' }])('never permits arbitrary cleanup target %#', ack => {
    expect(cleanupCapturePath(ack)).toBeNull();
  });
  it('publishes a new0600 regular reference with no temporary files and refuses overwriting existing data', () => {
    const directory = mkdtempSync(join(tmpdir(), 'm6-cipher-reference-test-')); directories.push(directory);
    const target = join(directory, 'synthetic-reference.json'); publishCaptureReference(target, fakeBundle());
    expect(lstatSync(target).isFile()).toBe(true); expect(lstatSync(target).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(target, 'utf8'))).toEqual(fakeBundle());
    const original = readFileSync(target, 'utf8'); expect(() => publishCaptureReference(target, { fabricated: 'different' })).toThrow();
    expect(readFileSync(target, 'utf8')).toBe(original); expect(readdirSync(directory)).toEqual(['synthetic-reference.json']);
  });
  it('refuses an existing symlink destination without touching the linked file', () => {
    const directory = mkdtempSync(join(tmpdir(), 'm6-cipher-reference-test-')); directories.push(directory);
    const existing = join(directory, 'existing'), target = join(directory, 'synthetic-reference.json'); writeFileSync(existing, 'untouched'); symlinkSync(existing, target);
    expect(() => publishCaptureReference(target, fakeBundle())).toThrow(); expect(readFileSync(existing, 'utf8')).toBe('untouched');
    expect(lstatSync(target).isSymbolicLink()).toBe(true); expect(readdirSync(directory).sort()).toEqual(['existing', 'synthetic-reference.json']);
  });
});
