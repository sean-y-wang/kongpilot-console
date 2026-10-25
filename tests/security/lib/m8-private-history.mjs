import { createHash, randomUUID } from 'node:crypto';
import { constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

export const M8_HISTORY_DIRECTORY = join(tmpdir(), 'kongos-m8-journal-history');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const invalid = () => { throw new Error('M8_PRIVATE_HISTORY_INVALID'); };
const validFile = file => /^[a-zA-Z][a-zA-Z0-9-]{0,80}-[a-f\d-]{36}\.json$/.test(file);
export function validateM8HistoryDescriptors(refs) {
  if (!Array.isArray(refs) || refs.length > 32) invalid();
  const seen = new Set(); let total = 0;
  for (const ref of refs) {
    if (!ref || !validFile(ref.file) || seen.has(ref.file) || !/^[a-f\d]{64}$/.test(ref.sha256 ?? '') || !Number.isSafeInteger(ref.bytes) || ref.bytes < 1 || ref.bytes > 32 * 1024 * 1024) invalid();
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
  const parent = openSync(M8_HISTORY_DIRECTORY, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { fsyncSync(parent); } finally { closeSync(parent); }
}
export function retainM8History(state, name) {
  if (state?.version !== 1 || state.milestone !== 'M8' || !/^[a-zA-Z][a-zA-Z0-9]{0,64}History$/.test(name) || Object.hasOwn(state, name)) invalid();
  directory(M8_HISTORY_DIRECTORY, true);
  const refs = state.privateHistoryRefs ?? [], bytes = Buffer.from(JSON.stringify(state, null, 2) + '\n');
  const ref = { file: `${name}-${randomUUID()}.json`, bytes: bytes.length, sha256: hash(bytes), provenance: 'exact-M8-current-journal-before-window' };
  validateM8HistoryDescriptors([...refs, ref]);
  writeExclusive(join(M8_HISTORY_DIRECTORY, ref.file), bytes);
  state.privateHistoryRefs = [...refs, ref];
  state[name] = { version: 1, externalReference: { ...ref, selector: null } };
  return ref;
}
export function readM8PrivateHistories(state, root = M8_HISTORY_DIRECTORY) {
  const refs = validateM8HistoryDescriptors(state.privateHistoryRefs ?? []);
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
    if (value.version !== 1 || value.milestone !== 'M8' || value.testTag !== state.testTag) invalid();
    for (const child of validateM8HistoryDescriptors(value.privateHistoryRefs ?? [])) {
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
