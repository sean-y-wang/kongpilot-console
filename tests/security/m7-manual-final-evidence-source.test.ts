// @ts-nocheck -- immutable synthetic public report bytes only.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { sha256 } from './lib/m7-harness.mjs';
import { M7_POST_WRITE_UI_FAILURE, readM7ManualFinalEvidence as productionRead } from './lib/m7-manual-final-evidence.mjs';
const old = { stage: 'actual-manual-ui', testTag: 'm7-security-synthetic', allPassed: false, failed: 1, successfulUiWrites: 12, unknownUiWrites: 0, unresolvedUiWrites: 0, blockedBeforePacketAttempts: 0, inheritedBlockedBeforePacketAttempts: 1 };
const oldBytes = Buffer.from(JSON.stringify(old)), syntheticSha = sha256(oldBytes);
const ram = runInNewContext(readFileSync(new URL('./lib/m7-manual-final-evidence.mjs', import.meta.url), 'utf8').replace(/^import .*;\n/gm, '').replaceAll('export ', '').replaceAll(M7_POST_WRITE_UI_FAILURE.sha256, syntheticSha)
  + ';({readM7ManualFinalEvidence});', { sha256, readFileSync: () => { throw Error('UNEXPECTED_RUNTIME_READ'); } });
function fixture() {
  const reference = { testTag: old.testTag, manualUiHandoff: { securityReportPath: 'artifacts/M7/security-live-audit-download-continuation.json', securityReportSha256: '1'.repeat(64), producerReportPath: 'artifacts/M7/security-producers-cli-policy-continuation.json', producerReportSha256: '2'.repeat(64) } };
  const h = reference.manualUiHandoff;
  return { reference, manual: { stage: 'actual-manual-ui-readonly-closure', testTag: old.testTag, allPassed: true, failed: 0, successfulUiWrites: 12, unknownUiWrites: 0, unresolvedUiWrites: 0, blockedBeforePacketAttempts: 0, inheritedBlockedBeforePacketAttempts: 1,
    additionalBusinessWrites: 0, additionalLoginWrites: 0, additionalRefreshWrites: 0, newApprovalWrites: 0, loginWrites: 0, refreshWrites: 0, nativeTransportWrites: 0,
    inheritedHttpReportPath: h.securityReportPath, inheritedHttpSha256: h.securityReportSha256, inheritedProducerReportPath: h.producerReportPath, inheritedProducerSha256: h.producerReportSha256,
    originalPostWriteFailure: { path: M7_POST_WRITE_UI_FAILURE.path, sha256: syntheticSha } } };
}
describe('distinct M7 readonly green UI report preserves exact raw earlier failure', () => {
  it('accepts only explicitly inherited twelve successful original writes and unchanged old false artifact', () => {
    const { reference, manual } = fixture(); const proof = ram.readM7ManualFinalEvidence(reference, manual, () => oldBytes);
    expect(proof.originalRawUiFailureRetained).toBe(true); expect(proof.originalTwelveWritesNotReplayed).toBe(true); expect(() => productionRead(reference, manual, () => oldBytes)).toThrow('INHERITANCE');
  });
  for (const [field, value] of [['allPassed', false], ['successfulUiWrites', 11], ['unknownUiWrites', 1], ['additionalBusinessWrites', 1], ['additionalRefreshWrites', 1], ['inheritedBlockedBeforePacketAttempts', 0], ['inheritedProducerSha256', '9'.repeat(64)]]) {
    it(`rejects changed ${field} without treating old failure as success`, () => { const { reference, manual } = fixture(); manual[field] = value; expect(() => ram.readM7ManualFinalEvidence(reference, manual, () => oldBytes)).toThrow('INHERITANCE'); });
  }
  it('rejects modified or silently greened original raw failed report bytes', () => {
    const { reference, manual } = fixture(); expect(() => ram.readM7ManualFinalEvidence(reference, manual, () => Buffer.from(JSON.stringify({ ...old, allPassed: true })))).toThrow('OLD_FAILURE_CHANGED');
  });
});
