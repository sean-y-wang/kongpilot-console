import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { assertFinalM6Evidence } from './lib/m6-final-scan-policy.mjs';

const reference = () => ({ phase: 'cleanup-complete', browserKeyScan: { phase: 'scanner-material-verified', credentialId: 'synthetic-source-only-credential' } });
const evidence = (manual: unknown) => ({ http: { passed: 1, failed: 0 }, browser: { passed: 1, failed: 0 }, manual, cleanup: { allPassed: true }, material: { allPassed: true, keyValuePublished: false, keyRetainedPrivately: true, audited: true, scannerRevealPosts: 1, nativeWrites: 0 } });
const marker = () => ({ sourceFailureSha256: 'eb7a57f7675f56ea5ebd1c6cc7dcba9c462b9a463e75ceb5189f7622d73d1f4b', originalPrivateHistoryRetained: true, originalZeroPacketAttemptExcludedFromSuccess: true });

describe('source-only final scanner compatibility with a future completed zero-packet continuation', () => {
  it('accepts additional continuation metadata on a synthetic complete new manual result without requiring old failure to become success', () => {
    // A type/shape compatibility fixture only; no actual completion is claimed.
    const manual = { allPassed: true, passed: 1, failed: 0, zeroPacketContinuation: marker(), writeBoundary: { complete: true, plannedWrites: 7, successfulPlannedWrites: 7 } };
    expect(() => assertFinalM6Evidence(reference(), evidence(manual))).not.toThrow();
  });
  it('rejects the immutable actual original preflight failure regardless of attached continuation metadata', () => {
    const original = JSON.parse(readFileSync('artifacts/M6/UI-review-pre-launch-attempt.json', 'utf8'));
    expect(original.allPassed).toBe(false); expect(original.passed).toBe(0); expect(() => assertFinalM6Evidence(reference(), evidence(original))).toThrow('FINAL_M6_EVIDENCE_INCOMPLETE');
    expect(() => assertFinalM6Evidence(reference(), evidence({ ...original, zeroPacketContinuation: marker() }))).toThrow('FINAL_M6_EVIDENCE_INCOMPLETE');
  });
  it('actual final runner reads only canonical new UI-review for manual completion and never the preserved initial failure archive', () => {
    const text = readFileSync('tests/security/finalize-m6-secret-scan.mjs', 'utf8'), tree = ts.createSourceFile('finalize-m6-secret-scan.mjs', text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS), manual = tree.statements.filter(ts.isVariableStatement).flatMap(node => node.declarationList.declarations).find(node => node.name.getText(tree) === 'manual');
    expect(manual?.initializer?.getText(tree)).toBe("read('UI-review')"); expect(text).not.toContain('UI-review-pre-launch-attempt');
  });
});
