// @ts-nocheck -- independent synthetic private files; no runtime references.
import { describe, it, expect } from 'vitest';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { M7_LEGACY_HISTORY, readM7PrivateHistories, validateM7HistoryDescriptors } from './lib/m7-private-history.mjs';
import { m7CapturedSecrets } from './lib/m7-secret-scan-policy.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
const rootState = () => ({ version: 1, milestone: 'M7', testTag: 'synthetic-only', requests: [], secrets: ['synthetic-private-value'] });
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'm7-history-synthetic-')); chmodSync(root, 0o700);
  const value = rootState(), bytes = JSON.stringify(value), ref = {file: `synthetic-${randomUUID()}.json`, bytes: Buffer.byteLength(bytes), sha256: hash(bytes), provenance: 'exact-M7-current-journal-before-window'};
  writeFileSync(join(root, ref.file), bytes, {mode: 0o600});
  return {root, value, ref, state: {...rootState(), privateHistoryRefs: [ref]}};
}
describe('bounded byte-exact M7 private history originals', () => {
  it('verifies current scoped original bytes without hydrating or changing current requests', () => {
    const f = fixture(); try { const before = JSON.stringify(f.state); expect(readM7PrivateHistories(f.state, f.root)).toEqual([f.value]); expect(JSON.stringify(f.state)).toBe(before); } finally {rmSync(f.root,{recursive:true});}
  });
  it('rejects mutated bytes and unrelated M7 scope before accepting a history', () => {
    for (const change of ['hash','scope']) {const f=fixture();try {if(change==='hash') f.state.privateHistoryRefs[0].sha256='a'.repeat(64);else {const bytes=JSON.stringify({...f.value,testTag:'foreign'});writeFileSync(join(f.root,f.ref.file),bytes);Object.assign(f.ref,{bytes:Buffer.byteLength(bytes),sha256:hash(bytes)});}expect(()=>readM7PrivateHistories(f.state,f.root)).toThrow();}finally{rmSync(f.root,{recursive:true});}}
  });
  it('rejects path escape, duplicate ref, arbitrary oversized file and unpinned legacy', () => {
    const f=fixture();try {for(const refs of [[{...f.ref,file:'../outside.json'}],[f.ref,f.ref],[{...f.ref,bytes:33*1024*1024}],[{...M7_LEGACY_HISTORY,sha256:'a'.repeat(64)}],Array.from({length:33},()=>f.ref)])expect(()=>validateM7HistoryDescriptors(refs)).toThrow();expect(validateM7HistoryDescriptors([M7_LEGACY_HISTORY])).toEqual([M7_LEGACY_HISTORY]);}finally{rmSync(f.root,{recursive:true});}
  });
  it('requires private owner directory,0600 files and no symlink following', () => {
    for(const change of ['directory','file','link']) {const f=fixture();try {if(change==='directory')chmodSync(f.root,0o755);else if(change==='file')chmodSync(join(f.root,f.ref.file),0o644);else{const original=join(f.root,'original');writeFileSync(original,JSON.stringify(f.value),{mode:0o600});rmSync(join(f.root,f.ref.file));symlinkSync(original,join(f.root,f.ref.file));}expect(()=>readM7PrivateHistories(f.state,f.root)).toThrow();}finally{rmSync(f.root,{recursive:true});}}
  });
  it('rejects foreign child reference and invalid original selector', () => {
    for(const change of ['child','selector']){const f=fixture();try{if(change==='child'){const bytes=JSON.stringify({...f.value,privateHistoryRefs:[{...f.ref,file:`other-${randomUUID()}.json`}]});writeFileSync(join(f.root,f.ref.file),bytes);Object.assign(f.ref,{bytes:Buffer.byteLength(bytes),sha256:hash(bytes)});}else f.state.beforeHistory={version:1,externalReference:{...f.ref,selector:'missingHistory'}};expect(()=>readM7PrivateHistories(f.state,f.root)).toThrow();}finally{rmSync(f.root,{recursive:true});}}
  });
  it('classifies external originals with the current cumulative registry and rejects dropped secrets', () => {
    const state=rootState(), history={...rootState(),before:{password:'synthetic-private-value'}};expect(m7CapturedSecrets(state,[history])).toContain('synthetic-private-value');history.before.password='uncaptured-history-secret';expect(()=>m7CapturedSecrets(state,[history])).toThrow('REGISTRY_INCOMPLETE');
  });
});
