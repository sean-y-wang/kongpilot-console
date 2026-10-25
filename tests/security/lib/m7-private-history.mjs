import { createHash, randomUUID } from 'node:crypto';
import { constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

export const M7_HISTORY_DIRECTORY = join(tmpdir(), 'kongos-m7-journal-history');
export const M7_LEGACY_HISTORY = Object.freeze({ file: 'pre-sharding-original.json', bytes: 39321715,
  sha256: 'fd91ca15045c0b7eb3fcc081e0d900672a6a28693eb2f155d177957ff237c4fc', provenance: 'exact-known-M7-pre-sharding-journal' });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const invalid = () => { throw new Error('M7_PRIVATE_HISTORY_INVALID'); };
const validFile = file => file === M7_LEGACY_HISTORY.file || /^[a-zA-Z][a-zA-Z0-9-]{0,80}-[a-f\d-]{36}\.json$/.test(file);
export function validateM7HistoryDescriptors(refs) {
  if (!Array.isArray(refs) || refs.length > 32) invalid();
  const seen = new Set(); let total = 0;
  for (const ref of refs) {
    const legacy = ref?.file === M7_LEGACY_HISTORY.file;
    if (!ref || !validFile(ref.file) || seen.has(ref.file) || !/^[a-f\d]{64}$/.test(ref.sha256 ?? '') || !Number.isSafeInteger(ref.bytes) || ref.bytes < 1 || ref.bytes > (legacy ? 64 : 32) * 1024 * 1024
      || legacy && (ref.sha256 !== M7_LEGACY_HISTORY.sha256 || ref.bytes !== M7_LEGACY_HISTORY.bytes || ref.provenance !== M7_LEGACY_HISTORY.provenance)) invalid();
    seen.add(ref.file); total += ref.bytes;
  }
  if (total > 128 * 1024 * 1024) invalid();
  return refs;
}
function directory(path, create = false) {
  if (create) mkdirSync(path, { recursive: true, mode: 0o700 });
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o700) invalid();
}
function writeExclusive(path, bytes) {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  const parent = openSync(M7_HISTORY_DIRECTORY, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { fsyncSync(parent); } finally { closeSync(parent); }
}
export function retainM7History(state, name) {
  if (state?.version !== 1 || state.milestone !== 'M7' || !/^[a-zA-Z][a-zA-Z0-9]{0,64}History$/.test(name) || Object.hasOwn(state, name)) invalid();
  directory(M7_HISTORY_DIRECTORY, true);
  const refs = state.privateHistoryRefs ?? [], bytes = Buffer.from(JSON.stringify(state, null, 2) + '\n');
  const ref = { file: `${name}-${randomUUID()}.json`, bytes: bytes.length, sha256: hash(bytes), provenance: 'exact-M7-current-journal-before-window' };
  validateM7HistoryDescriptors([...refs, ref]);
  writeExclusive(join(M7_HISTORY_DIRECTORY, ref.file), bytes);
  state.privateHistoryRefs = [...refs, ref];
  state[name] = { version: 1, externalReference: { ...ref, selector: null } };
  return ref;
}
export function archiveExactM7Legacy(bytes) {
  if (bytes.length !== M7_LEGACY_HISTORY.bytes || hash(bytes) !== M7_LEGACY_HISTORY.sha256) invalid();
  directory(M7_HISTORY_DIRECTORY, true);
  const state = JSON.parse(bytes);
  if (state.version !== 1 || state.milestone !== 'M7' || state.privateHistoryRefs) invalid();
  writeExclusive(join(M7_HISTORY_DIRECTORY, M7_LEGACY_HISTORY.file), bytes);
  const ref = { ...M7_LEGACY_HISTORY };
  for (const name of Object.keys(state).filter(key => /History$/.test(key))) {
    state[name] = { version: 1, externalReference: { ...ref, selector: name } };
  }
  state.privateHistoryRefs = [ref];
  return state;
}
/** Current references are small. Only the pinned original capture can use the
 * explicit legacy64MiB bound. Every referenced original remains byte exact. */
export function readM7PrivateHistories(state, root = M7_HISTORY_DIRECTORY) {
  const refs = validateM7HistoryDescriptors(state.privateHistoryRefs ?? []);
  if (!refs.length) return [];
  directory(root);
  const known = new Map(refs.map(ref => [ref.file, ref])), values = new Map();
  for (const ref of refs) {
    const fd = openSync(join(root, ref.file), constants.O_RDONLY | constants.O_NOFOLLOW);
    let bytes;
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600 || stat.size !== ref.bytes) invalid();
      bytes = readFileSync(fd);
    } finally { closeSync(fd); }
    if (bytes.length !== ref.bytes || hash(bytes) !== ref.sha256) invalid();
    const value = JSON.parse(bytes);
    if (value.version !== 1 || value.milestone !== 'M7' || value.testTag !== state.testTag) invalid();
    for (const child of validateM7HistoryDescriptors(value.privateHistoryRefs ?? [])) {
      const current = known.get(child.file);
      if (!current || JSON.stringify(child) !== JSON.stringify(current)) invalid();
    }
    values.set(ref.file, value);
  }
  const visiting = new Set(), visited = new Set();
  function visit(file) {
    if (visiting.has(file)) invalid();
    if (visited.has(file)) return;
    visiting.add(file);
    for (const child of values.get(file).privateHistoryRefs ?? []) visit(child.file);
    visiting.delete(file); visited.add(file);
  }
  refs.forEach(ref => visit(ref.file));
  for (const name of Object.keys(state).filter(key => /History$/.test(key))) {
    const ref = state[name]?.externalReference;
    if (!ref) continue;
    const knownRef = known.get(ref.file), original = values.get(ref.file);
    if (!knownRef || ref.sha256 !== knownRef.sha256 || ref.bytes !== knownRef.bytes || ref.provenance !== knownRef.provenance || ref.selector !== null && (!/^[a-zA-Z][a-zA-Z0-9]{0,64}History$/.test(ref.selector) || !Object.hasOwn(original, ref.selector))) invalid();
  }
  return [...values.values()];
}
