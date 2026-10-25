// @ts-nocheck -- actual ESM helpers, isolated synthetic files/processes only.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { runInNewContext } from 'node:vm';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const isolation = vi.hoisted(() => ({
  active: false, files: new Map(), directories: new Map(), descriptors: new Map(), nextFd: 100,
  operations: [], spawn: undefined, stderrLeak: '', reportSyncFailure: false,
  hashOverrides: new Map(), roots: [], originalArgv: [], originalExitCode: undefined,
  manualPrerequisite: undefined,
}));

// An active finalizer can access only RAM-backed synthetic paths. Any unexpected
// path fails closed; none of the fixed current/legacy private paths are opened.
vi.mock('node:fs', async importOriginal => {
  const actual = await importOriginal();
  const stat = (entry, directory = false) => ({
    size: entry.size ?? entry.bytes?.length ?? 0, mode: entry.mode ?? (directory ? 0o40700 : 0o100600),
    uid: entry.uid ?? process.getuid(), nlink: entry.nlink ?? 1,
    isFile: () => !directory, isDirectory: () => directory, isSymbolicLink: () => entry.symlink === true,
  });
  const file = path => {
    const entry = isolation.files.get(path);
    if (!entry) throw Error('SYNTHETIC_PATH_NOT_AVAILABLE');
    return entry;
  };
  const descriptor = fd => {
    const entry = isolation.descriptors.get(fd);
    if (!entry) throw Error('SYNTHETIC_DESCRIPTOR_NOT_AVAILABLE');
    return entry;
  };
  const wrappers = {
    existsSync: path => isolation.files.has(String(path)) || isolation.directories.has(String(path)),
    lstatSync: path => isolation.directories.has(String(path))
      ? stat(isolation.directories.get(String(path)), true) : stat(file(String(path))),
    openSync: (path, flags, mode) => {
      path = String(path); isolation.operations.push({ op: 'open', path });
      if (flags === 'wx') {
        if (isolation.files.has(path)) throw Error('SYNTHETIC_EXCLUSIVE_CREATE');
        isolation.files.set(path, { bytes: Buffer.alloc(0), mode: 0o100000 | mode });
      }
      const entry = isolation.directories.get(path) ?? file(path);
      if (entry.symlink && (typeof flags === 'number' && flags & actual.constants.O_NOFOLLOW)) throw Error('SYNTHETIC_NOFOLLOW');
      const fd = isolation.nextFd++; isolation.descriptors.set(fd, { path, directory: isolation.directories.has(path) }); return fd;
    },
    closeSync: fd => { descriptor(fd); isolation.descriptors.delete(fd); },
    fstatSync: fd => { const d = descriptor(fd); return d.directory ? stat(isolation.directories.get(d.path), true) : stat(file(d.path)); },
    readFileSync: (path, encoding) => {
      const name = typeof path === 'number' ? descriptor(path).path : String(path);
      isolation.operations.push({ op: 'read', path: name });
      const bytes = Buffer.from(file(name).bytes); return typeof encoding === 'string' ? bytes.toString(encoding) : bytes;
    },
    writeFileSync: (path, bytes, options) => {
      const name = typeof path === 'number' ? descriptor(path).path : String(path);
      isolation.operations.push({ op: 'write', path: name });
      isolation.files.set(name, { bytes: Buffer.from(bytes), mode: file(name).mode ?? options?.mode ?? 0o100600 });
    },
    mkdirSync: path => { isolation.directories.set(String(path), { mode: 0o40700 }); },
    readdirSync: (path, options) => {
      path = String(path);
      if (!isolation.directories.has(path)) throw Error('SYNTHETIC_DIRECTORY_NOT_AVAILABLE');
      const prefix = path === '.' ? '' : `${path}/`;
      const names = [...new Set([...isolation.files.keys(), ...isolation.directories.keys()]
        .filter(name => name.startsWith(prefix) && name !== path).map(name => name.slice(prefix.length).split('/')[0]))];
      return options?.withFileTypes ? names.map(name => ({ name, isSymbolicLink: () => false,
        isDirectory: () => isolation.directories.has(prefix + name), isFile: () => isolation.files.has(prefix + name) })) : names;
    },
    fsyncSync: fd => {
      const d = descriptor(fd); isolation.operations.push({ op: 'fsync', path: d.path });
      if (isolation.reportSyncFailure && d.path.startsWith('artifacts/M7/runtime-secret-artifact-scan.json')) throw Error('SYNTHETIC_REPORT_DURABILITY_FAILURE');
    },
    renameSync: (from, to) => { isolation.operations.push({ op: 'rename', path: String(to) }); isolation.files.set(String(to), file(String(from))); isolation.files.delete(String(from)); },
    rmSync: path => { isolation.operations.push({ op: 'remove', path: String(path) }); isolation.files.delete(String(path)); isolation.directories.delete(String(path)); },
    rmdirSync: path => { isolation.operations.push({ op: 'remove-directory', path: String(path) }); isolation.directories.delete(String(path)); },
  };
  return { ...actual, ...Object.fromEntries(Object.entries(wrappers).map(([name, fake]) =>
    [name, (...args) => isolation.active ? fake(...args) : actual[name](...args)])) };
});
vi.mock('node:crypto', async importOriginal => {
  const actual = await importOriginal();
  return { ...actual, createHash: algorithm => {
    const real = actual.createHash(algorithm), chunks = [];
    return { update(value) { chunks.push(Buffer.from(value)); real.update(value); return this; },
      digest(format) { return isolation.hashOverrides.get(Buffer.concat(chunks).toString()) ?? real.digest(format); } };
  } };
});
vi.mock('node:child_process', () => ({
  spawn: vi.fn((...args) => {
    if (!isolation.spawn) throw Error('SYNTHETIC_PROCESS_NOT_PERMITTED');
    return isolation.spawn(...args);
  }),
  execFileSync: vi.fn((command, args, options) => {
    if (!isolation.active) throw Error('SYNTHETIC_COMMAND_NOT_PERMITTED');
    isolation.operations.push({ op: 'command', command, args, options });
    if (command === 'git') return '';
    if (command !== 'docker') throw Error('SYNTHETIC_COMMAND_NOT_PERMITTED');
    if (args.includes('inspect')) return 'synthetic_project';
    if (args.includes('ps')) return 'a'.repeat(12);
    if (args.includes('exec') && args.at(-1).includes('hmacs')) {
      const input = JSON.parse(options.input);
      return JSON.stringify({ hmacs: input.confirmed.map(() => 'e'.repeat(64)), stoppedValidated: input.stopped.length });
    }
    if (args.includes('exec') && args.at(-1).includes('rmSync')) return '';
    throw Error('SYNTHETIC_DOCKER_COMMAND_NOT_PERMITTED');
  }),
  spawnSync: vi.fn((command, args) => {
    if (!isolation.active || command !== 'docker' || args[0] !== 'logs') throw Error('SYNTHETIC_LOG_COMMAND_NOT_PERMITTED');
    isolation.operations.push({ op: 'logs', command, args });
    return { status: 0, stdout: '', stderr: isolation.stderrLeak };
  }),
}));

// This layer exercises secret collection/receipts/logs/durable deletion. The
// exact manual-inheritance predicate has its own 35 independent cases. Model
// only its already-validated prerequisite here; never read the actual old UI
// artifact or weaken the production predicate to satisfy a synthetic fixture.
vi.mock('./lib/m7-manual-final-evidence.mjs', async importOriginal => ({
  ...await importOriginal(),
  readM7ManualFinalEvidence: vi.fn((reference, manual, reader) => {
    const expected = isolation.manualPrerequisite;
    if (!isolation.active || !expected || reference.testTag !== expected.testTag || reference.phase !== 'cleanup-complete'
      || JSON.stringify(manual) !== expected.manualJson || typeof reader !== 'function') throw Error('SYNTHETIC_MANUAL_PREREQUISITE_NOT_CONFIGURED');
    isolation.operations.push({ op: 'validated-manual-prerequisite', syntheticDependencyOnly: true });
    return structuredClone(expected.proof);
  }),
}));

import { M7_LEGACY_HISTORY, readM7PrivateHistories, validateM7HistoryDescriptors } from './lib/m7-private-history.mjs';
import { observationSequence } from './lib/m7-producer-acceptance.mjs';
import { m7CapturedSecrets } from './lib/m7-secret-scan-policy.mjs';
import { readM7Reference } from './lib/m7-harness.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const rootState = () => ({ version: 1, milestone: 'M7', testTag: 'synthetic-only', requests: [], secrets: ['SyntheticHistoryCredential!47'] });
const descriptor = (name, bytes) => ({ file: `${name}-${randomUUID()}.json`, bytes: Buffer.byteLength(bytes), sha256: sha(bytes), provenance: 'exact-M7-current-journal-before-window' });
function realHistory() {
  const root = mkdtempSync(join(tmpdir(), 'm7-aux-independent-')); chmodSync(root, 0o700); isolation.roots.push(root);
  const original = rootState(), bytes = JSON.stringify(original), ref = descriptor('independent', bytes);
  writeFileSync(join(root, ref.file), bytes, { mode: 0o600 });
  return { root, original, ref, state: { ...rootState(), privateHistoryRefs: [ref] } };
}
function sampler() {
  const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.kill = vi.fn(() => true);
  const snapshots = [], h = { state: { samplingIntents: [], phase: 'producer-observation' },
    check: (value, name) => { if (!value) throw Error(name); },
    save: extra => { Object.assign(h.state, extra); snapshots.push(structuredClone(h.state)); },
  };
  const area = { cid: randomUUID(), wid: randomUUID() }, id = randomUUID();
  isolation.spawn = (command, args) => {
    expect(command).toBe('docker'); expect(snapshots.at(-1).samplingIntents[0]).toMatchObject({ ...area, type: 'upstreams', id, state: 'prepared' });
    const intent = snapshots.at(-1).samplingIntents[0]; expect(args.at(-1)).toBe(intent.keys.join(','));
    expect(args).toContain(`EVENT_OBSERVATION_TEST_SCOPE=${area.cid}:upstreams:${id}`); return child;
  };
  const emit = (index, patch = {}) => child.stdout.emit('data', Buffer.from(JSON.stringify({ status: 'confirmed', samplingKey: h.state.samplingIntents[0].keys[index],
    observationId: randomUUID(), quality: 'verified', observedAt: new Date().toISOString(), reconciled: false, ...patch }) + '\n'));
  return { h, child, snapshots, area, id, emit };
}
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };

beforeEach(() => {
  vi.clearAllMocks(); isolation.active = false; isolation.files.clear(); isolation.directories.clear(); isolation.descriptors.clear();
  isolation.operations = []; isolation.spawn = undefined; isolation.stderrLeak = ''; isolation.reportSyncFailure = false;
  isolation.manualPrerequisite = undefined;
  isolation.hashOverrides.clear(); isolation.originalArgv = [...process.argv]; isolation.originalExitCode = process.exitCode;
});

const STOPPED_RECEIPT_KEYS = ['e381165a-366f-4bc3-a4d7-869ae6c9645e', '1d9ada11-58f0-4aba-8684-f2ec9722b79e',
  '440fb6a4-d729-4314-96b0-b9bb25fe6684', 'bd498586-dd27-46fe-99ec-89df45ef89fd', 'c097f362-b66c-4887-9dc6-a2142cf1df2f'];
const SECOND_STOPPED_RECEIPT_KEYS = ['be9f8242-775d-4bb7-a818-902cfa5fb562', 'cdd72d04-e4a8-452e-9c2d-a0aa6f483c93',
  'cb7e9b29-cf3d-4ffc-a603-31cd571203bf', '7e5af08b-acca-4e30-b56f-51ac54f915cc', '40dad785-c30d-4061-82da-832466495b39'];
function stoppedReceiptFixture(secondGroup = false) {
  const scope = { clusterId: 'dff45535-ed8d-4851-b7a6-6376feac7f59', subjectType: 'certificates', subjectId: '9abfa5b8-d34b-4920-88e2-f4058a4ab2dd' };
  const input = { confirmed: Array.from({ length: 10 }, () => ({ key: randomUUID(), observationId: randomUUID(), clusterId: randomUUID(), subjectType: 'certificates', subjectId: randomUUID() })),
    stopped: STOPPED_RECEIPT_KEYS.map((key, originalKeyIndex) => ({ key, originalKeyIndex, originalIntentIndex: 0, ...scope })) };
  const receipts = new Map(input.confirmed.map(tuple => [tuple.key, { value: { version: 1, state: 'ready', samplingKey: tuple.key, observationId: tuple.observationId,
    clusterId: tuple.clusterId, subjectType: tuple.subjectType, subjectId: tuple.subjectId, observationHmac: 'f'.repeat(64) }, mode: 0o600 }]));
  receipts.set(STOPPED_RECEIPT_KEYS[0], { value: { version: 1, state: 'reserved', samplingKey: STOPPED_RECEIPT_KEYS[0], ...scope }, mode: 0o600 });
  if (secondGroup) {
    const secondScope = { ...scope, subjectId: 'dc480bde-b580-4744-89e8-4c1d9f317ab2' };
    input.stopped.push(...SECOND_STOPPED_RECEIPT_KEYS.map((key, originalKeyIndex) => ({ key, originalKeyIndex, originalIntentIndex: 1, ...secondScope })));
    receipts.set(SECOND_STOPPED_RECEIPT_KEYS[0], { value: { version: 1, state: 'reserved', samplingKey: SECOND_STOPPED_RECEIPT_KEYS[0], ...secondScope }, mode: 0o600 });
  }
  return { input, receipts };
}
function runReceiptCode(code, fixture) {
  const stdin = new EventEmitter(), output = [], opens = [], closes = [], descriptors = new Map(); let nextFd = 500;
  const processMock = { stdin, getuid: () => process.getuid(), stdout: { write: value => output.push(value) }, exitCode: undefined,
    exit: () => { throw Error('SYNTHETIC_VM_EXIT'); } };
  const fs = { constants: { O_RDONLY: 0, O_NOFOLLOW: 131072 },
    lstatSync: path => { expect(path).toBe('/tmp/kongos-m7-observation-receipts'); return { isDirectory: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode: 0o700 }; },
    openSync: (path, flags) => {
      expect(path.startsWith('/tmp/kongos-m7-observation-receipts/')).toBe(true); expect(flags & 131072).toBe(131072);
      const key = path.split('/').at(-1).replace(/\.json$/, ''); opens.push(key); const entry = fixture.receipts.get(key);
      if (!entry) throw Object.assign(Error('SYNTHETIC_MISSING_RECEIPT'), { code: 'ENOENT' });
      if (entry.symlink) throw Object.assign(Error('SYNTHETIC_SYMLINK'), { code: 'ELOOP' });
      const fd = nextFd++; descriptors.set(fd, entry); return fd;
    },
    fstatSync: fd => { const entry = descriptors.get(fd); return { isFile: () => true, size: Buffer.byteLength(JSON.stringify(entry.value)),
      mode: entry.mode, uid: entry.uid ?? process.getuid() }; },
    readFileSync: fd => JSON.stringify(descriptors.get(fd).value),
    closeSync: fd => { closes.push(fd); descriptors.delete(fd); },
  };
  runInNewContext(code, { require: name => { expect(name).toBe('fs'); return fs; }, process: processMock });
  stdin.emit('data', JSON.stringify(fixture.input)); stdin.emit('end');
  return { exitCode: processMock.exitCode, output, opens, closes, descriptors };
}
async function actualReceiptCode() {
  finalizerFixture(); await invokeFinalizer();
  return isolation.operations.find(value => value.op === 'command' && value.args.includes('exec') && value.args.at(-1).includes('hmacs')).args.at(-1);
}

describe('actual finalizer inline stopped-receipt boundary, synthetic VM filesystem only', () => {
  it('returns ten exact confirmed HMACs plus five validated stopped keys with only the first reserved receipt present', async () => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture(), result = runReceiptCode(code, f);
    expect(result.exitCode).toBeUndefined(); expect(result.output).toHaveLength(1);
    expect(JSON.parse(result.output[0])).toEqual({ hmacs: Array(10).fill('f'.repeat(64)), stoppedValidated: 5 });
    expect(result.opens).toHaveLength(15); expect(result.closes).toHaveLength(11); expect(result.descriptors.size).toBe(0);
  });
  it.each(['ready', 'hmac', 'extra'])('rejects a stopped first receipt changed to %s without emitting any proof', async change => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture(), entry = f.receipts.get(STOPPED_RECEIPT_KEYS[0]);
    if (change === 'ready') entry.value.state = 'ready';
    else if (change === 'hmac') entry.value.observationHmac = 'a'.repeat(64);
    else entry.value.extra = true;
    const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.output).toEqual([]); expect(result.descriptors.size).toBe(0);
  });
  it('requires the original first reserved receipt rather than accepting ENOENT for all stopped keys', async () => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture(); f.receipts.delete(STOPPED_RECEIPT_KEYS[0]);
    const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.output).toEqual([]);
  });
  it('rejects any receipt present for the other four original stopped keys', async () => {
    const code = await actualReceiptCode();
    for (const key of STOPPED_RECEIPT_KEYS.slice(1)) {
      const f = stoppedReceiptFixture(); f.receipts.set(key, { ...f.receipts.get(STOPPED_RECEIPT_KEYS[0]) });
      const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.output).toEqual([]); expect(result.descriptors.size).toBe(0);
    }
  });
  it.each(['clusterId', 'subjectId', 'subjectType', 'originalKeyIndex', 'key'])('rejects a stopped %s outside the exact original tuple', async field => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture();
    f.input.stopped[0][field] = field === 'originalKeyIndex' ? 1 : field === 'subjectType' ? 'upstreams' : randomUUID();
    const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.output).toEqual([]);
  });
  it('rejects eleven confirmed tuples before accessing receipt files', async () => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture(); f.input.confirmed.push({ ...f.input.confirmed[0], key: randomUUID() });
    const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.opens).toEqual([]); expect(result.output).toEqual([]);
  });
  it.each(['mode', 'owner', 'symlink'])('rejects a stopped first receipt with unsafe %s', async change => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture(), entry = f.receipts.get(STOPPED_RECEIPT_KEYS[0]);
    if (change === 'mode') entry.mode = 0o644; else if (change === 'owner') entry.uid = process.getuid() + 1; else entry.symlink = true;
    const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.output).toEqual([]); expect(result.descriptors.size).toBe(0);
  });
  it('validates both exact stopped groups with only each original first reserved receipt and returns ten confirmed HMACs', async () => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture(true), result = runReceiptCode(code, f);
    expect(result.exitCode).toBeUndefined(); expect(result.output).toHaveLength(1);
    expect(JSON.parse(result.output[0])).toEqual({ hmacs: Array(10).fill('f'.repeat(64)), stoppedValidated: 10 });
    expect(result.opens).toHaveLength(20); expect(result.closes).toHaveLength(12); expect(result.descriptors.size).toBe(0);
  });
  it.each([0, 1])('rejects a wrong original intent index in stopped group %s', async group => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture(true); f.input.stopped[group * 5].originalIntentIndex = 1 - group;
    const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.output).toEqual([]);
  });
  it('rejects a second-group key substituted from the original first group', async () => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture(true); f.input.stopped[5].key = STOPPED_RECEIPT_KEYS[0];
    const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.output).toEqual([]);
  });
  it('rejects a ready receipt in the stopped second group', async () => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture(true); f.receipts.get(SECOND_STOPPED_RECEIPT_KEYS[0]).value.state = 'ready';
    const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.output).toEqual([]); expect(result.descriptors.size).toBe(0);
  });
  it('requires the second group original first reserved receipt instead of accepting ENOENT', async () => {
    const code = await actualReceiptCode(), f = stoppedReceiptFixture(true); f.receipts.delete(SECOND_STOPPED_RECEIPT_KEYS[0]);
    const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.output).toEqual([]);
  });
  it('rejects any receipt present for the second group other four original keys', async () => {
    const code = await actualReceiptCode();
    for (const key of SECOND_STOPPED_RECEIPT_KEYS.slice(1)) {
      const f = stoppedReceiptFixture(true); f.receipts.set(key, { ...f.receipts.get(SECOND_STOPPED_RECEIPT_KEYS[0]) });
      const result = runReceiptCode(code, f); expect(result.exitCode).toBe(2); expect(result.output).toEqual([]); expect(result.descriptors.size).toBe(0);
    }
  });
});
afterEach(() => {
  isolation.active = false; isolation.hashOverrides.clear(); vi.useRealTimers(); vi.unstubAllEnvs();
  process.argv = isolation.originalArgv; process.exitCode = isolation.originalExitCode;
  for (const root of isolation.roots.splice(0)) rmSync(root, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('independent private history bounds and original graph', () => {
  it('accepts exactly 32 descriptors but rejects ref 33 and cumulative bytes above 128 MiB', () => {
    const refs = Array.from({ length: 32 }, (_, i) => ({ file: `history${i}-${randomUUID()}.json`, sha256: 'a'.repeat(64), bytes: 4 * 1024 * 1024 }));
    expect(validateM7HistoryDescriptors(refs)).toBe(refs);
    expect(() => validateM7HistoryDescriptors([...refs, { ...refs[0], file: `extra-${randomUUID()}.json` }])).toThrow();
    expect(() => validateM7HistoryDescriptors(refs.map((ref, i) => i === 0 ? { ...ref, bytes: ref.bytes + 1 } : ref))).toThrow();
  });
  it('permits the 39 MiB legacy only with the exact hardcoded file/bytes/hash/provenance tuple', () => {
    expect(M7_LEGACY_HISTORY.bytes).toBeGreaterThan(32 * 1024 * 1024);
    expect(validateM7HistoryDescriptors([{ ...M7_LEGACY_HISTORY }])).toHaveLength(1);
    for (const change of [{ file: `untrusted-${randomUUID()}.json` }, { bytes: M7_LEGACY_HISTORY.bytes - 1 }, { sha256: 'f'.repeat(64) }, { provenance: 'claimed-same-owner' }])
      expect(() => validateM7HistoryDescriptors([{ ...M7_LEGACY_HISTORY, ...change }])).toThrow();
    expect(() => validateM7HistoryDescriptors([{ file: `untrusted-${randomUUID()}.json`, bytes: 32 * 1024 * 1024 + 1, sha256: 'a'.repeat(64) }])).toThrow();
  });
  it('reads two immutable, bounded originals and classifies every secret without hydrating current requests', () => {
    const f = realHistory(), oldSecret = 'SyntheticOldCookie!42', older = { ...rootState(), secrets: [oldSecret], before: { password: oldSecret } };
    const olderBytes = JSON.stringify(older), olderRef = descriptor('older', olderBytes); writeFileSync(join(f.root, olderRef.file), olderBytes, { mode: 0o600 });
    const original = { ...f.original, privateHistoryRefs: [olderRef] }, originalBytes = JSON.stringify(original);
    writeFileSync(join(f.root, f.ref.file), originalBytes); Object.assign(f.ref, { bytes: Buffer.byteLength(originalBytes), sha256: sha(originalBytes) });
    f.state.privateHistoryRefs.push(olderRef); f.state.secrets.push(oldSecret);
    f.state.beforeHistory = { externalReference: { ...f.ref, selector: null } };
    const before = JSON.stringify(f.state), histories = readM7PrivateHistories(f.state, f.root);
    expect(histories).toEqual([original, older]); expect(JSON.stringify(f.state)).toBe(before);
    expect(m7CapturedSecrets(f.state, histories)).toContain(oldSecret);
    f.state.secrets = f.state.secrets.filter(value => value !== oldSecret);
    expect(() => m7CapturedSecrets(f.state, histories)).toThrow('REGISTRY_INCOMPLETE');
  });
  it('rejects a cyclic original graph even when mocked content hashes match every descriptor', () => {
    const f = realHistory(); f.ref.sha256 = 'a'.repeat(64);
    let bytes = '';
    for (let i = 0; i < 4; i++) { bytes = JSON.stringify({ ...f.original, privateHistoryRefs: [f.ref] }); f.ref.bytes = Buffer.byteLength(bytes); }
    bytes = JSON.stringify({ ...f.original, privateHistoryRefs: [f.ref] });
    isolation.hashOverrides.set(bytes, f.ref.sha256); writeFileSync(join(f.root, f.ref.file), bytes);
    expect(() => readM7PrivateHistories(f.state, f.root)).toThrow('M7_PRIVATE_HISTORY_INVALID');
  });
});

describe('independent real sampler control flow with synthetic child processes', () => {
  it('durably reserves exact original keys and subject before one process, then consumes ordered fresh proofs', async () => {
    const f = sampler(), after = vi.fn(async () => undefined), result = observationSequence(f.h, f.area, 'upstreams', f.id, after, 2);
    f.emit(0); f.emit(1); f.child.emit('close', 0); const samples = await result;
    expect(samples).toHaveLength(2); expect(after.mock.calls.map(call => call[1])).toEqual([0, 1]);
    expect(f.snapshots[0].samplingIntents[0]).toMatchObject({ state: 'prepared', samples: [] }); expect(f.h.state.samplingIntents[0].state).toBe('completed');
  });
  it('rejects fractional sample counts before reserving a key or starting a process', async () => {
    const f = sampler(); await expect(observationSequence(f.h, f.area, 'upstreams', f.id, undefined, 1.5)).rejects.toThrow();
    expect(f.h.state.samplingIntents).toEqual([]); expect(f.child.kill).not.toHaveBeenCalled();
  });
  it('a synchronous spawn failure durably marks the same original intent unknown without a replay', async () => {
    const f = sampler(); isolation.spawn = vi.fn(() => { throw Error('SyntheticSpawnFailure'); });
    await expect(observationSequence(f.h, f.area, 'upstreams', f.id)).rejects.toThrow();
    expect(isolation.spawn).toHaveBeenCalledTimes(1); expect(f.h.state.samplingIntents[0].state).toBe('unknown');
    expect(f.h.state.phase).toBe('stopped-producer-unknown'); expect(f.h.state.samplingIntents[0].keys).toEqual(f.snapshots[0].samplingIntents[0].keys);
  });
  it('an unresolved subject cannot allocate replacement keys or invoke another sampler process', async () => {
    const f = sampler(), original = { cid: f.area.cid, wid: f.area.wid, type: 'upstreams', id: f.id, keys: [randomUUID()], state: 'unknown', samples: [] };
    f.h.state.samplingIntents.push(structuredClone(original)); isolation.spawn = vi.fn();
    await expect(observationSequence(f.h, f.area, 'upstreams', f.id)).rejects.toThrow('unresolved original');
    expect(f.h.state.samplingIntents).toEqual([original]); expect(isolation.spawn).not.toHaveBeenCalled(); expect(f.snapshots).toEqual([]);
  });
  it('waits for an already-running callback before persisting unknown and skips later queued callbacks after error', async () => {
    const f = sampler(); let release; const gate = new Promise(resolve => { release = resolve; });
    const callback = vi.fn(async () => { await gate; }); let settled = false;
    const result = observationSequence(f.h, f.area, 'upstreams', f.id, callback, 2).then(value => value, error => error).finally(() => { settled = true; });
    f.emit(0); await flush(); expect(callback).toHaveBeenCalledTimes(1);
    f.emit(1); f.child.emit('error', Error('SyntheticChildError')); f.child.emit('close', 1); await flush();
    expect(settled).toBe(false); expect(f.h.state.phase).not.toBe('stopped-producer-unknown');
    release(); expect(await result).toBeInstanceOf(Error); expect(callback).toHaveBeenCalledTimes(1);
    expect(f.h.state.samplingIntents[0].state).toBe('unknown'); expect(f.h.state.phase).toBe('stopped-producer-unknown');
  });
  it('an unresponsive over-budget process is escalated to SIGKILL and closes within a bounded deadline', async () => {
    vi.useFakeTimers(); const f = sampler(); let settled = false;
    const result = observationSequence(f.h, f.area, 'upstreams', f.id).then(value => value, error => error).finally(() => { settled = true; });
    f.child.stdout.emit('data', Buffer.alloc(16385, 65)); await flush(); expect(f.child.kill).toHaveBeenCalledWith('SIGTERM');
    await vi.advanceTimersByTimeAsync(1000); expect(f.child.kill).toHaveBeenCalledWith('SIGKILL');
    await vi.advanceTimersByTimeAsync(4000); expect(settled).toBe(true); expect(await result).toBeInstanceOf(Error);
    expect(f.h.state.samplingIntents[0].state).toBe('unknown');
  });
  it('the real-sequence deadline stops an otherwise silent process within the same original intent', async () => {
    vi.useFakeTimers(); const f = sampler(), result = observationSequence(f.h, f.area, 'upstreams', f.id).then(value => value, error => error);
    const originalKeys = [...f.h.state.samplingIntents[0].keys];
    await vi.advanceTimersByTimeAsync(150000); expect(f.child.kill).toHaveBeenCalledWith('SIGTERM');
    await vi.advanceTimersByTimeAsync(3000); expect(await result).toBeInstanceOf(Error); expect(f.child.kill).toHaveBeenCalledWith('SIGKILL');
    expect(f.h.state.samplingIntents[0]).toMatchObject({ keys: originalKeys, state: 'unknown' });
  });
  it('a stdout stream error stops the same intent without publishing raw process stderr', async () => {
    const f = sampler(), result = observationSequence(f.h, f.area, 'upstreams', f.id).then(value => value, error => error);
    f.child.stderr.emit('data', Buffer.from('SyntheticRawProviderSecret!47')); f.child.stdout.emit('error', Error('SyntheticStreamError'));
    f.child.emit('close', 1); const error = await result; expect(error).toBeInstanceOf(Error); expect(error.message).not.toContain('SyntheticRawProviderSecret');
    expect(f.child.kill).toHaveBeenCalledWith('SIGTERM'); expect(f.h.state.samplingIntents[0].state).toBe('unknown');
  });
  it('a stderr stream error is handled as unknown without an unhandled EventEmitter error', async () => {
    const f = sampler(), result = observationSequence(f.h, f.area, 'upstreams', f.id).then(value => value, error => error);
    expect(() => f.child.stderr.emit('error', Error('SyntheticStderrStreamError'))).not.toThrow();
    f.child.emit('close', 1); expect(await result).toBeInstanceOf(Error); expect(f.child.kill).toHaveBeenCalledWith('SIGTERM');
    expect(f.h.state.samplingIntents[0].state).toBe('unknown');
  });
  it.each([true, false])('persists only allowed failure projections (valid=%s) and ignores raw message or stack', async valid => {
    const f = sampler(), result = observationSequence(f.h, f.area, 'upstreams', f.id).then(value => value, error => error);
    f.emit(0, { status: 'uncertain', observationId: null, failureCode: valid ? 'SOURCE_UNAVAILABLE' : 'SyntheticRawCredential!47',
      failureKind: valid ? 'ForbiddenException' : 'SyntheticRawCredential!47', failureStage: valid ? 'source' : 'SyntheticRawCredential!47',
      message: 'SyntheticRawCredential!47', stack: 'SyntheticRawCredential!47' });
    await flush(); f.child.emit('close', 1); expect(await result).toBeInstanceOf(Error);
    const intent = f.h.state.samplingIntents[0], response = intent.receivedResponses[0];
    expect(response).toMatchObject({ status: 'uncertain', observationId: null, failureCode: valid ? 'SOURCE_UNAVAILABLE' : null,
      failureKind: valid ? 'ForbiddenException' : null, failureStage: valid ? 'source' : null });
    expect(response.responseSha256).toMatch(/^[a-f\d]{64}$/); expect(intent.state).toBe('unknown'); expect(intent.samples).toEqual([]);
    expect(JSON.stringify(f.snapshots)).not.toContain('SyntheticRawCredential!47');
  });
});

function finalizerFixture() {
  const privatePath = join(tmpdir(), 'kongos-m7-runtime-secrets.json'), historyRoot = join(tmpdir(), 'kongos-m7-journal-history');
  const secret = 'SyntheticHistoricalCredential!52', older = { ...rootState(), secrets: [secret], before: { password: secret } };
  const olderBytes = JSON.stringify(older), ref = descriptor('scanoriginal', olderBytes);
  isolation.files.set(join(historyRoot, ref.file), { bytes: Buffer.from(olderBytes), mode: 0o100600 });
  isolation.directories.set(historyRoot, { mode: 0o40700 }); isolation.directories.set('.', { mode: 0o40700 });
  isolation.directories.set('artifacts', { mode: 0o40700 }); isolation.directories.set('artifacts/M7', { mode: 0o40700 });
  const evidence = {}, reports = {};
  for (const name of ['http', 'producers', 'manual', 'cleanup']) {
    const path = `artifacts/M7/synthetic-${name}.json`, value = { allPassed: true, failed: 0, testTag: 'synthetic-only',
      ...(name === 'cleanup' ? { auditWriteCoverage: { allCovered: true, coveredWrites: 1, successfulWrites: 1 } } : {}) };
    const bytes = JSON.stringify(value); isolation.files.set(path, { bytes: Buffer.from(bytes), mode: 0o100644 });
    evidence[name] = { path, sha256: sha(bytes) }; reports[name] = value;
  }
  const current = { ...rootState(), phase: 'cleanup-complete', secrets: [...rootState().secrets, secret], privateHistoryRefs: [ref],
    beforeHistory: { version: 1, externalReference: { ...ref, selector: null } },
    requests: [{ index: 0, key: randomUUID(), method: 'POST', path: '/api/v1/synthetic', body: {}, state: 'response_observed', startedAt: '2026-10-11T01:00:00Z' }],
    providerControls: [], samplingIntents: [{ cid: randomUUID(), type: 'certificates', id: randomUUID(), keys: [randomUUID()], state: 'completed', samples: [{ observationId: randomUUID() }] }],
    producersComplete: true, cleanup: { businessCompleted: true }, privateMaterialDirectories: [],
    finalScanHandoff: { version: 1, phase: 'ready', testTag: 'synthetic-only', evidence },
  };
  isolation.manualPrerequisite = { testTag: current.testTag, manualJson: JSON.stringify(reports.manual),
    proof: { distinctReadOnlyGreenArtifact: true, originalRawUiFailureRetained: true,
      originalFailurePath: 'artifacts/M7/synthetic-prior-ui-failure.json', originalFailureSha256: sha('synthetic-prior-ui-failure'),
      originalTwelveWritesNotReplayed: true } };
  const persist = () => isolation.files.set(privatePath, { bytes: Buffer.from(JSON.stringify(current)), mode: 0o100600 }); persist();
  const readReport = () => JSON.parse(isolation.files.get('artifacts/M7/runtime-secret-artifact-scan.json').bytes.toString());
  return { current, persist, secret, ref, historyRoot, privatePath, reports, readReport };
}
async function invokeFinalizer() {
  vi.resetModules(); vi.stubEnv('M7_FINAL_SCAN_READY', 'true'); process.argv = [...isolation.originalArgv, '--evidence-complete'];
  vi.spyOn(console, 'log').mockImplementation(() => undefined); isolation.active = true;
  return import('./finalize-m7-secret-scan.mjs');
}

describe('independent finalizer end-to-end control flow in an exclusive RAM filesystem', () => {
  it('rejects a missing explicit handoff before any fixed private file or child process access', async () => {
    vi.resetModules(); isolation.active = true; vi.stubEnv('M7_FINAL_SCAN_READY', 'false');
    await expect(import('./finalize-m7-secret-scan.mjs')).rejects.toThrow('M7_EXCLUSIVE_FINAL_SCAN_HANDOFF_REQUIRED');
    expect(isolation.operations).toEqual([]);
  });
  it('the current reader retains its original 32 MiB limit without reading an oversized current journal', () => {
    const f = finalizerFixture(); isolation.files.get(f.privatePath).size = 32 * 1024 * 1024 + 1; isolation.active = true;
    expect(() => readM7Reference()).toThrow('M7_PRIVATE_REFERENCE_INVALID');
    expect(isolation.operations.some(value => value.op === 'read')).toBe(false);
  });
  it('scans every original context and both streams of all nine services, then durably reports zero leaks before exact private removals', async () => {
    const f = finalizerFixture(); await invokeFinalizer(); const report = f.readReport();
    expect(report).toMatchObject({ allPassed: true, currentAndHistoricalSecretsIncluded: true, privateObservationProofsIncluded: 1,
      privateReferenceRemoved: true, ephemeralPrivateMaterialsRemoved: true, rawLogsPublished: false });
    expect(report.manualInheritance).toEqual(isolation.manualPrerequisite.proof);
    expect(isolation.operations.filter(value => value.op === 'validated-manual-prerequisite')).toHaveLength(1);
    expect(report.runtimeLogs).toHaveLength(9); expect(report.runtimeLogs.every(value => value.freshStdoutAndStderr && !value.knownSecretDetected)).toBe(true);
    const firstRemoval = isolation.operations.findIndex(value => value.op === 'remove');
    const reportFsync = isolation.operations.findIndex(value => value.op === 'fsync' && value.path.startsWith('artifacts/M7/runtime-secret-artifact-scan.json'));
    expect(reportFsync).toBeGreaterThan(-1); expect(firstRemoval).toBeGreaterThan(reportFsync);
    expect(isolation.operations.filter(value => value.op === 'read' && value.path === join(f.historyRoot, f.ref.file))).toHaveLength(3);
    expect(isolation.files.has(f.privatePath)).toBe(false); expect(isolation.files.has(join(f.historyRoot, f.ref.file))).toBe(false);
  });
  it('an uncaptured historical secret stops before log collection and retains every exact private original', async () => {
    const f = finalizerFixture(); f.current.secrets = f.current.secrets.filter(value => value !== f.secret); f.persist();
    await invokeFinalizer(); expect(f.readReport()).toMatchObject({ allPassed: false, failureClassification: 'FINAL_SCAN_INCOMPLETE_PRIVATE_RETAINED', privateReferenceRemoved: false });
    expect(isolation.operations.some(value => value.op === 'logs' || value.op === 'remove')).toBe(false);
    expect(isolation.files.has(f.privatePath)).toBe(true); expect(isolation.files.has(join(f.historyRoot, f.ref.file))).toBe(true);
  });
  it('a credential present only in container stderr fails the scan and prevents all removals', async () => {
    const f = finalizerFixture(); isolation.stderrLeak = f.secret; await invokeFinalizer(); const report = f.readReport();
    expect(report.allPassed).toBe(false); expect(report.runtimeLogs.every(value => value.knownSecretDetected)).toBe(true);
    expect(isolation.operations.some(value => value.op === 'remove')).toBe(false); expect(isolation.files.has(f.privatePath)).toBe(true);
    expect(JSON.stringify(report)).not.toContain(f.secret);
  });
  it('a base64 historical credential in an artifact fails before deleting the original capture', async () => {
    const f = finalizerFixture(); isolation.files.set('artifacts/M7/synthetic-leak.txt', { bytes: Buffer.from(Buffer.from(f.secret).toString('base64')), mode: 0o100644 });
    await invokeFinalizer(); const report = f.readReport(); expect(report.allPassed).toBe(false);
    expect(report.leaks).toContain('artifacts/M7/synthetic-leak.txt'); expect(isolation.files.has(join(f.historyRoot, f.ref.file))).toBe(true);
    expect(isolation.operations.some(value => value.op === 'remove')).toBe(false);
  });
  it('changed evidence bytes fail before the one-shot marker, scans or removal', async () => {
    const f = finalizerFixture(); isolation.files.get('artifacts/M7/synthetic-http.json').bytes = Buffer.from(JSON.stringify({ ...f.reports.http, allPassed: false }));
    await expect(invokeFinalizer()).rejects.toThrow('M7_FINAL_EVIDENCE_HASH_CHANGED');
    expect(JSON.parse(isolation.files.get(f.privatePath).bytes.toString()).finalScanStarted).toBeUndefined();
    expect(isolation.operations.some(value => value.op === 'logs' || value.op === 'remove')).toBe(false);
  });
  it('a durable report write failure preserves the reference and all exact history files', async () => {
    const f = finalizerFixture(); isolation.reportSyncFailure = true;
    await expect(invokeFinalizer()).rejects.toThrow('SYNTHETIC_REPORT_DURABILITY_FAILURE');
    expect(isolation.operations.some(value => value.op === 'remove')).toBe(false); expect(isolation.files.has(f.privatePath)).toBe(true);
    expect(isolation.files.has(join(f.historyRoot, f.ref.file))).toBe(true);
  });
  it('the exact container proof code rejects a foreign/symlinked/nonprivate receipt directory before opening any receipt', async () => {
    finalizerFixture(); await invokeFinalizer();
    const command = isolation.operations.find(value => value.op === 'command' && value.args.includes('exec') && value.args.at(-1).includes('hmacs'));
    for (const change of [{ uid: process.getuid() + 1 }, { symlink: true }, { mode: 0o755 }]) {
      const stdin = new EventEmitter(), output = [], opens = vi.fn(), processMock = { stdin, getuid: () => process.getuid(), stdout: { write: value => output.push(value) }, exitCode: undefined };
      runInNewContext(command.args.at(-1), { require: name => {
        expect(name).toBe('fs'); return { lstatSync: () => ({ isDirectory: () => true, isSymbolicLink: () => change.symlink ?? false, uid: change.uid ?? process.getuid(), mode: change.mode ?? 0o700 }), openSync: opens };
      }, process: processMock });
      stdin.emit('data', command.options.input); stdin.emit('end');
      expect(opens).not.toHaveBeenCalled(); expect(processMock.exitCode).toBe(2); expect(output).toEqual([]);
    }
  });
  it('the exact fixed container cleanup code rejects foreign ownership without deleting that directory', async () => {
    finalizerFixture(); await invokeFinalizer();
    const command = isolation.operations.find(value => value.op === 'command' && value.args.includes('exec') && value.args.at(-1).includes('rmSync'));
    const remove = vi.fn(), exit = vi.fn(() => { throw Error('SYNTHETIC_CONTAINER_EXIT'); });
    expect(() => runInNewContext(command.args.at(-1), { require: name => {
      expect(name).toBe('fs'); return { existsSync: () => true, lstatSync: () => ({ isDirectory: () => true, isSymbolicLink: () => false, mode: 0o700, uid: process.getuid() + 1 }), rmSync: remove };
    }, process: { getuid: () => process.getuid(), exit } })).toThrow('SYNTHETIC_CONTAINER_EXIT');
    expect(exit).toHaveBeenCalledWith(2); expect(remove).not.toHaveBeenCalled();
  });
});
