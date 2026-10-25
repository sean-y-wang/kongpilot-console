import { readFileSync } from 'node:fs';
import { sha256 } from './m7-harness.mjs';

export const M7_BLOCKED_OBSERVATION = Object.freeze({
  testTag: 'm7-security-b81047b2', packetCount: 267,
  packetSha256: '771925084a2e85602c3706a44e63844be0e3a744c41728ad40e71768ea703f51',
  intentSha256: '1c1d72273f0f17fcb680d96162480aa2066be0dad6e2bfd32ed7ecfb4b2dbbbc',
  cid: 'dff45535-ed8d-4851-b7a6-6376feac7f59', wid: '4f2f9544-e3f1-4ff9-93ca-4c3b3e5324e5',
  type: 'certificates', id: '9abfa5b8-d34b-4920-88e2-f4058a4ab2dd',
  keys: Object.freeze(['e381165a-366f-4bc3-a4d7-869ae6c9645e', '1d9ada11-58f0-4aba-8684-f2ec9722b79e', '440fb6a4-d729-4314-96b0-b9bb25fe6684', 'bd498586-dd27-46fe-99ec-89df45ef89fd', 'c097f362-b66c-4887-9dc6-a2142cf1df2f']),
  sources: Object.freeze([
    { path: 'artifacts/M7/security-producers-first-sampling-failure.json', sha256: '9719f854b5d1345241de86407eb8b8c97f8f8879f4b7104b07ed2f11d87a5a2c' },
    { path: 'artifacts/M7/producer-first-sampling-readonly-exact-diagnosis.json', sha256: '8b0d2ad53f3c09055d6ce0599fd2535db1f6f1e02a5615786b4a8e591f7910b1' },
    { path: 'artifacts/M7/producer-fence-parent-state-readonly-proof.json', sha256: 'd8bf2a659aa5dd6cbd3b79f0aca06fc7c3ee6f52777ae9c164131a3cf206ba52' },
    { path: 'artifacts/M7/producer-original-premint-readonly-proof.json', sha256: '6f8ad9355da780ef422098f30386905ccc536b2dd5f05d5829f41c66e2cf58c3' },
  ]),
});

function exactOriginal(reference, intent, expectedState) {
  const fixed = M7_BLOCKED_OBSERVATION;
  return reference?.version === 1 && reference.milestone === 'M7' && reference.testTag === fixed.testTag &&
    reference.samplingIntents?.[0] === intent && intent?.state === expectedState && intent.cid === fixed.cid &&
    intent.wid === fixed.wid && intent.type === fixed.type && intent.id === fixed.id &&
    JSON.stringify(intent.keys) === JSON.stringify(fixed.keys) && intent.samples?.length === 0 &&
    reference.requests.length >= fixed.packetCount && sha256(JSON.stringify(reference.requests.slice(0, fixed.packetCount))) === fixed.packetSha256 &&
    sha256(JSON.stringify({ ...intent, state: 'unknown' })) === fixed.intentSha256;
}
/** Only this stopped tuple with zero durable observations can be terminal.
 * The original stdout and in-memory result remain unknown, never rewritten. */
export function isKnownM7StoppedSamplingIntent(reference, intent) {
  if (isKnownM7StoppedCliSamplingIntent(reference, intent)) return true;
  const proof = reference?.producerBlockedObservationProof;
  return exactOriginal(reference, intent, 'stopped_without_durable_observation') && proof?.version === 1 && proof.state === 'completed' &&
    proof.priorState === 'unknown' && proof.originalIntentSha256 === M7_BLOCKED_OBSERVATION.intentSha256 &&
    proof.originalPacketSha256 === M7_BLOCKED_OBSERVATION.packetSha256 && proof.classification === 'stopped_without_durable_observation' &&
    proof.originalReceiptState === 'reserved' && proof.originalObservationId === null && proof.originalObservationHmacPresent === false &&
    proof.originalCliProcesses === 0 && proof.originalSqlObservationCount === 0 && proof.originalSqlDetectorStateCount === 0 &&
    proof.originalMemoryObservationUnknown === true && proof.originalFirstStdoutUnavailable === true &&
    JSON.stringify(proof.sources) === JSON.stringify(M7_BLOCKED_OBSERVATION.sources);
}

export function readM7BlockedObservationEvidence(reference) {
  const fixed = M7_BLOCKED_OBSERVATION, reports = fixed.sources.map(source => {
    const bytes = readFileSync(source.path);
    if (sha256(bytes) !== source.sha256) throw new Error('M7_BLOCKED_OBSERVATION_SOURCE_CHANGED');
    const report = JSON.parse(bytes);
    if (report.testTag !== reference.testTag) throw new Error('M7_BLOCKED_OBSERVATION_SCOPE_CHANGED');
    return report;
  });
  const [failure, diagnosis, parents, sqlClosure] = reports, receipt = diagnosis.receipts?.[0];
  if (failure.allPassed !== false || failure.passed !== 21 || failure.failed !== 1 || failure.successfulWrites !== 259 || failure.unknownWrites !== 0 ||
    diagnosis.allPassed !== true || diagnosis.nonOwnerReadOnly !== true || diagnosis.activeSamplerProcesses !== 0 || diagnosis.subjectState?.exists !== false ||
    diagnosis.receipts?.length !== 5 || receipt.index !== 0 || receipt.exists !== true || receipt.state !== 'reserved' || receipt.observationId !== null ||
    receipt.originalHmacAvailable !== false || receipt.observationExists !== false || diagnosis.receipts.slice(1).some((row, index) => row.index !== index + 1 || row.exists !== false) ||
    diagnosis.authorityMetadata?.unsettledFences !== 89 || diagnosis.authorityMetadata?.unfinishedMutations !== 0 ||
    parents.allPassed !== true || parents.nonOwnerReadOnly !== true || parents.originalPacketsUnchanged !== true || parents.totals?.total !== 89 ||
    parents.totals.missing_parent !== 0 || parents.totals.unresolved_parent !== 0 || parents.totals.mismatched_transport !== 0 ||
    parents.states?.length !== 2 || !parents.states.some(row => row.fence_state === 'pending' && row.parent_state === 'succeeded' && row.count === 87) ||
    !parents.states.some(row => row.fence_state === 'pending' && row.parent_state === 'failed' && row.count === 2) ||
    sqlClosure.allPassed !== true || sqlClosure.nonOwnerReadOnly !== true || sqlClosure.originalPacketsUnchanged !== true ||
    sqlClosure.typedObservationCount !== 0 || sqlClosure.typedDetectorStateCount !== 0 || sqlClosure.oldFenceOnlySnapshotGuardPresent !== true ||
    sqlClosure.authorityCompiledSha256 !== '52242835fe678d2ad0bdb8d4aa67d15f6f57f4e370efa4c7f3815ca51db89b44' ||
    [diagnosis, parents, sqlClosure].some(report => report.businessWrites !== 0 || report.authenticationWrites !== 0 || report.nativeTransportWrites !== 0)) {
    throw new Error('M7_BLOCKED_OBSERVATION_EVIDENCE_INVALID');
  }
  if (reference.producerCliPolicyStoppedObservationProof) readM7StoppedCliObservationEvidence(reference);
  return fixed.sources;
}

export const M7_CLI_POLICY_STOPPED_OBSERVATION = Object.freeze({
  packetCount: 270, packetSha256: 'f049783acb59e00dcdd6faae91293e2e8faf2dfc3599541a6eac65d026c06db1',
  intentSha256: 'bf9ca17c8c9d5e6826e724c96646c86d474f59b2048630fb9e98ea5e999aa6f9',
  cid: 'dff45535-ed8d-4851-b7a6-6376feac7f59', wid: '4f2f9544-e3f1-4ff9-93ca-4c3b3e5324e5', type: 'certificates',
  id: 'dc480bde-b580-4744-89e8-4c1d9f317ab2',
  keys: Object.freeze(['be9f8242-775d-4bb7-a818-902cfa5fb562', 'cdd72d04-e4a8-452e-9c2d-a0aa6f483c93', 'cb7e9b29-cf3d-4ffc-a603-31cd571203bf', '7e5af08b-acca-4e30-b56f-51ac54f915cc', '40dad785-c30d-4061-82da-832466495b39']),
  sources: Object.freeze([
    { path: 'artifacts/M7/security-producers-after-fence-repair-sampling-failure.json', sha256: '3ee3b78d6437edd3ff41a322dfe7e66bdb773c230ada609a4a5106a82ac3f589' },
    { path: 'artifacts/M7/producer-after-fence-repair-readonly-diagnosis.json', sha256: '4eea08cf87207401cf6fe8dcde8e0266e78dad15f13c668b035464f1f8f41646' },
    { path: 'artifacts/M7/producer-second-original-cli-policy-readonly-proof.json', sha256: 'bbbb5ea9ff86bdb34947df8038c2e058383a39c082b70ebcfc57589a64a3940b' },
  ]),
});
function exactStoppedCliOriginal(reference, intent, expectedState) {
  const fixed = M7_CLI_POLICY_STOPPED_OBSERVATION;
  return reference?.version === 1 && reference.milestone === 'M7' && reference.testTag === M7_BLOCKED_OBSERVATION.testTag &&
    reference.samplingIntents?.[1] === intent && intent?.state === expectedState && intent.cid === fixed.cid && intent.wid === fixed.wid &&
    intent.type === fixed.type && intent.id === fixed.id && JSON.stringify(intent.keys) === JSON.stringify(fixed.keys) && intent.samples?.length === 0 &&
    reference.requests.length >= fixed.packetCount && sha256(JSON.stringify(reference.requests.slice(0, fixed.packetCount))) === fixed.packetSha256 &&
    sha256(JSON.stringify({ ...intent, state: 'unknown' })) === fixed.intentSha256;
}
export function isKnownM7StoppedCliSamplingIntent(reference, intent) {
  const proof = reference?.producerCliPolicyStoppedObservationProof;
  return exactStoppedCliOriginal(reference, intent, 'stopped_without_cli_durable_observation') && proof?.version === 1 && proof.state === 'completed' &&
    proof.priorState === 'unknown' && proof.classification === 'stopped_without_cli_durable_observation' &&
    proof.originalIntentSha256 === M7_CLI_POLICY_STOPPED_OBSERVATION.intentSha256 && proof.originalPacketSha256 === M7_CLI_POLICY_STOPPED_OBSERVATION.packetSha256 &&
    proof.originalReceiptState === 'reserved' && proof.originalObservationId === null && proof.originalObservationHmacPresent === false &&
    proof.originalCliProcesses === 0 && proof.originalCliPolicyMissing === true && proof.originalMemoryObservationUnknown === true &&
    proof.originalSafeFirstResponseRetained === true && proof.backgroundObservationCountAtDiagnosis === 1 && proof.backgroundStateCountAtDiagnosis === 1 &&
    JSON.stringify(proof.sources) === JSON.stringify(M7_CLI_POLICY_STOPPED_OBSERVATION.sources);
}
export function readM7StoppedCliObservationEvidence(reference) {
  const fixed = M7_CLI_POLICY_STOPPED_OBSERVATION, reports = fixed.sources.map(source => {
    const bytes = readFileSync(source.path); if (sha256(bytes) !== source.sha256) throw new Error('M7_STOPPED_CLI_SOURCE_CHANGED');
    const report = JSON.parse(bytes); if (report.testTag !== reference.testTag) throw new Error('M7_STOPPED_CLI_SCOPE_CHANGED'); return report;
  });
  const [failure, diagnosis, compiled] = reports, receipt = diagnosis.receipts?.[0], response = diagnosis.originalFirstResponse;
  if (failure.allPassed !== false || failure.passed !== 29 || failure.failed !== 1 || failure.successfulWrites !== 262 || failure.unknownWrites !== 0 ||
    diagnosis.allPassed !== true || diagnosis.nonOwnerReadOnly !== true || diagnosis.originalPacketsUnchanged !== true || diagnosis.activeSamplerProcesses !== 0 ||
    diagnosis.typedObservationCount !== 1 || diagnosis.typedDetectorStateCount !== 1 || diagnosis.snapshotAccepted !== true || diagnosis.snapshotErrorCode !== null ||
    diagnosis.receipts?.length !== 5 || receipt.index !== 0 || receipt.exists !== true || receipt.state !== 'reserved' || receipt.observationId !== null || receipt.originalHmacAvailable !== false ||
    diagnosis.receipts.slice(1).some((row, index) => row.index !== index + 1 || row.exists !== false) ||
    response?.status !== 'uncertain' || response.samplingKeyMatches !== true || response.observationId !== null || response.responseSha256 !== '82609c0088f5ab24dd91e26936f779d3dae70a310d774fb30db000a698d7da7f' ||
    compiled.allPassed !== true || compiled.observedAfterFailureBeforeAuxRepair !== true || compiled.notPretendedSamplingTimeFreeze !== true ||
    compiled.cliInitializationPolicyMissing !== true || compiled.policyHasNoAutomaticModuleInit !== true || compiled.policyExplicitInstallMethodPresent !== true || compiled.contextRejectsMissingHooks !== true ||
    compiled.compiledFiles?.[0]?.sha256 !== 'a839408d8e14da5e6ac0f4badc46f5925c927c8a991af33b2d10377ef9ed0ef8' ||
    [diagnosis, compiled].some(report => report.businessWrites !== 0 || report.authenticationWrites !== 0 || report.nativeTransportWrites !== 0 || report.freshAuthorityObservations !== 0)) throw new Error('M7_STOPPED_CLI_EVIDENCE_INVALID');
  return fixed.sources;
}
export function classifySecondM7StoppedCliObservation(h) {
  const intent = h.state.samplingIntents[1];
  h.check(!h.state.producerCliPolicyStoppedObservationProof && exactStoppedCliOriginal(h.state, intent, 'unknown') &&
    isKnownM7StoppedSamplingIntent(h.state, h.state.samplingIntents[0]), 'second stopped tuple requires exact original packets, safe response and previously sealed first tuple');
  const sources = readM7StoppedCliObservationEvidence(h.state);
  h.state.producerCliPolicyStoppedObservationProof = { version: 1, state: 'completed', priorState: 'unknown', classifiedAt: new Date().toISOString(),
    classification: 'stopped_without_cli_durable_observation', originalIntentSha256: M7_CLI_POLICY_STOPPED_OBSERVATION.intentSha256, originalPacketSha256: M7_CLI_POLICY_STOPPED_OBSERVATION.packetSha256,
    originalReceiptState: 'reserved', originalObservationId: null, originalObservationHmacPresent: false, originalCliProcesses: 0, originalCliPolicyMissing: true,
    originalMemoryObservationUnknown: true, originalSafeFirstResponseRetained: true, backgroundObservationCountAtDiagnosis: 1, backgroundStateCountAtDiagnosis: 1, sources };
  intent.state = 'stopped_without_cli_durable_observation'; h.save();
  h.check(isKnownM7StoppedSamplingIntent(h.state, intent), 'original second CLI uncertainty and independent background observation remain distinct and durable');
  return { originalCertificateId: intent.id, originalSamplingKeysRetained: 5, classification: 'stopped_without_cli_durable_observation',
    originalMemoryObservationUnknown: true, originalSafeFirstResponseRetained: true, backgroundObservationCountAtDiagnosis: 1, originalObservationRetried: false, immutableEvidenceSources: sources };
}

export function classifyOriginalM7StoppedObservation(h) {
  const intent = h.state.samplingIntents[0];
  h.check(!h.state.producerBlockedObservationProof && exactOriginal(h.state, intent, 'unknown'),
    'only the exact stopped original unknown tuple is eligible for sealed no-durable-observation classification');
  const sources = readM7BlockedObservationEvidence(h.state);
  h.state.producerBlockedObservationProof = { version: 1, state: 'completed', priorState: 'unknown', classifiedAt: new Date().toISOString(),
    originalIntentSha256: M7_BLOCKED_OBSERVATION.intentSha256, originalPacketSha256: M7_BLOCKED_OBSERVATION.packetSha256,
    classification: 'stopped_without_durable_observation', originalReceiptState: 'reserved', originalObservationId: null,
    originalObservationHmacPresent: false, originalCliProcesses: 0, originalSqlObservationCount: 0, originalSqlDetectorStateCount: 0,
    originalMemoryObservationUnknown: true, originalFirstStdoutUnavailable: true, sources };
  intent.state = 'stopped_without_durable_observation'; h.save();
  h.check(isKnownM7StoppedSamplingIntent(h.state, intent), 'sealed stopped tuple retains all original unknown keys and packets without sampling or replay');
  return { originalCertificateId: intent.id, originalSamplingKeysRetained: 5, classification: 'stopped_without_durable_observation',
    originalUnknownReportRetained: true, originalMemoryObservationUnknown: true, originalObservationRetried: false, immutableEvidenceSources: sources };
}
