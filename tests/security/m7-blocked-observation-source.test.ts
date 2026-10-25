// @ts-nocheck -- synthetic RAM trust anchors only; no env/private/runtime.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { M7_BLOCKED_OBSERVATION, M7_CLI_POLICY_STOPPED_OBSERVATION, isKnownM7StoppedSamplingIntent } from './lib/m7-blocked-observation.mjs';

const sha256 = value => createHash('sha256').update(value).digest('hex');
function fixture() {
  const fixed = M7_BLOCKED_OBSERVATION;
  const requests = Array.from({ length: 267 }, (_, index) => ({ index, state: 'response_observed', requestId: `synthetic-${index}` }));
  const intent = { cid: fixed.cid, wid: fixed.wid, type: fixed.type, id: fixed.id, keys: [...fixed.keys], state: 'unknown', at: '2026-10-11T01:00:00Z', samples: [] };
  const reports = [
    { testTag: fixed.testTag, allPassed: false, passed: 21, failed: 1, successfulWrites: 259, unknownWrites: 0 },
    { testTag: fixed.testTag, allPassed: true, nonOwnerReadOnly: true, activeSamplerProcesses: 0, subjectState: { exists: false }, receipts: [
      { index: 0, exists: true, state: 'reserved', observationId: null, originalHmacAvailable: false, observationExists: false },
      ...[1, 2, 3, 4].map(index => ({ index, exists: false }))], authorityMetadata: { unsettledFences: 89, unfinishedMutations: 0 }, businessWrites: 0, authenticationWrites: 0, nativeTransportWrites: 0 },
    { testTag: fixed.testTag, allPassed: true, nonOwnerReadOnly: true, originalPacketsUnchanged: true, totals: { total: 89, missing_parent: 0, unresolved_parent: 0, mismatched_transport: 0 },
      states: [{ fence_state: 'pending', parent_state: 'succeeded', count: 87 }, { fence_state: 'pending', parent_state: 'failed', count: 2 }], businessWrites: 0, authenticationWrites: 0, nativeTransportWrites: 0 },
    { testTag: fixed.testTag, allPassed: true, nonOwnerReadOnly: true, originalPacketsUnchanged: true, typedObservationCount: 0, typedDetectorStateCount: 0, oldFenceOnlySnapshotGuardPresent: true,
      authorityCompiledSha256: '52242835fe678d2ad0bdb8d4aa67d15f6f57f4e370efa4c7f3815ca51db89b44', businessWrites: 0, authenticationWrites: 0, nativeTransportWrites: 0 },
  ];
  const files = new Map(fixed.sources.map((source, index) => [source.path, Buffer.from(JSON.stringify(reports[index]))]));
  // Replace only immutable trust anchors in RAM, never the actual module/file.
  let source = readFileSync(new URL('./lib/m7-blocked-observation.mjs',import.meta.url), 'utf8')
    .replace(/^import .*;$/gm, '').replace(/export /g, '')
    .replace(fixed.packetSha256, sha256(JSON.stringify(requests))).replaceAll(fixed.intentSha256, sha256(JSON.stringify(intent)));
  fixed.sources.forEach(value => { source = source.replaceAll(value.sha256, sha256(files.get(value.path))); });
  const reader = vi.fn(path => { if (!files.has(path)) throw Error('UNEXPECTED_READ'); return files.get(path); });
  const helper = new Function('readFileSync', 'sha256', source + '\nreturn {isKnownM7StoppedSamplingIntent,readM7BlockedObservationEvidence,classifyOriginalM7StoppedObservation};')(reader, sha256);
  const h = { state: { version: 1, milestone: 'M7', testTag: fixed.testTag, requests, samplingIntents: [intent] }, save: vi.fn(), check(value, message) { if (!value) throw Error(message); } };
  return { h, helper, reports, files, reader, intent, prefix: JSON.stringify(requests) };
}

describe('exact stopped original M7 sampler with retained uncertainty', () => {
  it('actual production anchor rejects a plausible synthetic stopped journal', () => {
    const f = fixture(); f.helper.classifyOriginalM7StoppedObservation(f.h);
    expect(isKnownM7StoppedSamplingIntent(f.h.state, f.intent)).toBe(false);
  });
  it('classifies only the exact original zero-durable tuple and keeps packets/keys/unknown provenance', () => {
    const f = fixture(), result = f.helper.classifyOriginalM7StoppedObservation(f.h);
    expect(result).toMatchObject({ classification: 'stopped_without_durable_observation', originalMemoryObservationUnknown: true, originalObservationRetried: false, originalSamplingKeysRetained: 5 });
    expect(f.h.state.producerBlockedObservationProof).toMatchObject({ priorState: 'unknown', originalObservationId: null, originalObservationHmacPresent: false, originalFirstStdoutUnavailable: true });
    expect(f.helper.isKnownM7StoppedSamplingIntent(f.h.state, f.intent)).toBe(true);
    expect(JSON.stringify(f.h.state.requests)).toBe(f.prefix); expect(f.intent.samples).toEqual([]); expect(f.h.save).toHaveBeenCalledTimes(1); expect(f.reader).toHaveBeenCalledTimes(4);
  });
  it.each(['foreign-scope', 'foreign-key', 'added-sample', 'changed-prefix', 'changed-at', 'other-index', 'already-classified'])('refuses %s before reading public evidence', defect => {
    const f = fixture();
    if (defect === 'foreign-scope') f.intent.wid = 'foreign'; if (defect === 'foreign-key') f.intent.keys[0] = f.intent.keys[1];
    if (defect === 'added-sample') f.intent.samples.push({}); if (defect === 'changed-prefix') f.h.state.requests[3].requestId = 'changed';
    if (defect === 'changed-at') f.intent.at = '2026-10-11T02:00:00Z'; if (defect === 'other-index') f.h.state.samplingIntents.unshift({ ...structuredClone(f.intent), wid: 'foreign' });
    if (defect === 'already-classified') f.h.state.producerBlockedObservationProof = {};
    expect(() => f.helper.classifyOriginalM7StoppedObservation(f.h)).toThrow(); expect(f.reader).not.toHaveBeenCalled(); expect(f.h.save).not.toHaveBeenCalled();
  });
  it.each([0, 1, 2, 3])('requires unchanged raw bytes of evidence %s', index => {
    const f = fixture(), path = M7_BLOCKED_OBSERVATION.sources[index].path; f.files.set(path, Buffer.concat([f.files.get(path), Buffer.from('\n')]));
    expect(() => f.helper.classifyOriginalM7StoppedObservation(f.h)).toThrow('SOURCE_CHANGED'); expect(f.h.save).not.toHaveBeenCalled();
  });
  it.each(['lost-proof', 'memory-known', 'stdout-known', 'sql-row', 'hmac-present', 'not-original-unknown', 'unknown-state'])('cannot become a general finalizer exemption with %s', defect => {
    const f = fixture(); f.helper.classifyOriginalM7StoppedObservation(f.h); const proof = f.h.state.producerBlockedObservationProof;
    if (defect === 'lost-proof') delete f.h.state.producerBlockedObservationProof; if (defect === 'memory-known') proof.originalMemoryObservationUnknown = false;
    if (defect === 'stdout-known') proof.originalFirstStdoutUnavailable = false; if (defect === 'sql-row') proof.originalSqlObservationCount = 1;
    if (defect === 'hmac-present') proof.originalObservationHmacPresent = true; if (defect === 'not-original-unknown') proof.priorState = 'confirmed';
    if (defect === 'unknown-state') f.intent.state = 'unknown';
    expect(f.helper.isKnownM7StoppedSamplingIntent(f.h.state, f.intent)).toBe(false);
  });
  it('reads frozen historical facts without requiring production later to stop observing the same native subject', () => {
    const f = fixture(); f.helper.classifyOriginalM7StoppedObservation(f.h);
    f.h.state.productionLaterObservations = [{ subjectId: f.intent.id, source: 'background' }];
    expect(f.helper.isKnownM7StoppedSamplingIntent(f.h.state, f.intent)).toBe(true);
    expect(f.helper.readM7BlockedObservationEvidence(f.h.state)).toHaveLength(4);
  });
});

function secondFixture() {
  const f = fixture(), fixed = M7_CLI_POLICY_STOPPED_OBSERVATION;
  f.helper.classifyOriginalM7StoppedObservation(f.h);
  f.h.state.requests.push(...[267, 268, 269].map(index => ({ index, state: 'response_observed', requestId: `synthetic-${index}` })));
  const intent = { cid: fixed.cid, wid: fixed.wid, type: fixed.type, id: fixed.id, keys: [...fixed.keys], state: 'unknown', at: '2026-10-11T02:00:00Z', samples: [],
    receivedResponses: [{ responseSha256: '82609c0088f5ab24dd91e26936f779d3dae70a310d774fb30db000a698d7da7f', status: 'uncertain', samplingKeyMatches: true, observationId: null, quality: null, disposition: null, reconciled: null }] };
  f.h.state.samplingIntents.push(intent);
  const reports = [
    { testTag: M7_BLOCKED_OBSERVATION.testTag, allPassed: false, passed: 29, failed: 1, successfulWrites: 262, unknownWrites: 0 },
    { testTag: M7_BLOCKED_OBSERVATION.testTag, allPassed: true, nonOwnerReadOnly: true, originalPacketsUnchanged: true, activeSamplerProcesses: 0,
      typedObservationCount: 1, typedDetectorStateCount: 1, snapshotAccepted: true, snapshotErrorCode: null, receipts: [
        { index: 0, exists: true, state: 'reserved', observationId: null, originalHmacAvailable: false }, ...[1, 2, 3, 4].map(index => ({ index, exists: false }))],
      originalFirstResponse: intent.receivedResponses[0], businessWrites: 0, authenticationWrites: 0, nativeTransportWrites: 0, freshAuthorityObservations: 0 },
    { testTag: M7_BLOCKED_OBSERVATION.testTag, allPassed: true, observedAfterFailureBeforeAuxRepair: true, notPretendedSamplingTimeFreeze: true,
      cliInitializationPolicyMissing: true, policyHasNoAutomaticModuleInit: true, policyExplicitInstallMethodPresent: true, contextRejectsMissingHooks: true,
      compiledFiles: [{ sha256: 'a839408d8e14da5e6ac0f4badc46f5925c927c8a991af33b2d10377ef9ed0ef8' }], businessWrites: 0, authenticationWrites: 0, nativeTransportWrites: 0, freshAuthorityObservations: 0 },
  ];
  fixed.sources.forEach((source, index) => f.files.set(source.path, Buffer.from(JSON.stringify(reports[index]))));
  let text = readFileSync(new URL('./lib/m7-blocked-observation.mjs',import.meta.url), 'utf8').replace(/^import .*;$/gm, '').replace(/export /g, '')
    .replace(M7_BLOCKED_OBSERVATION.packetSha256, sha256(JSON.stringify(f.h.state.requests.slice(0, 267))))
    .replaceAll(M7_BLOCKED_OBSERVATION.intentSha256, sha256(JSON.stringify({ ...f.h.state.samplingIntents[0], state: 'unknown' })))
    .replace(fixed.packetSha256, sha256(JSON.stringify(f.h.state.requests))).replaceAll(fixed.intentSha256, sha256(JSON.stringify(intent)));
  [...M7_BLOCKED_OBSERVATION.sources, ...fixed.sources].forEach(value => { text = text.replaceAll(value.sha256, sha256(f.files.get(value.path))); });
  const helper = new Function('readFileSync', 'sha256', text + '\nreturn {isKnownM7StoppedSamplingIntent,readM7BlockedObservationEvidence,classifySecondM7StoppedCliObservation};')(f.reader, sha256);
  f.h.save.mockClear(); f.reader.mockClear();
  return { ...f, helper, intent, prefix: JSON.stringify(f.h.state.requests) };
}
describe('second exact stopped CLI with a distinct real background observation', () => {
  it('retains background observation and captured uncertain response, without asserting globally zero observations', () => {
    const f = secondFixture(), result = f.helper.classifySecondM7StoppedCliObservation(f.h);
    expect(result).toMatchObject({ classification: 'stopped_without_cli_durable_observation', backgroundObservationCountAtDiagnosis: 1, originalMemoryObservationUnknown: true, originalObservationRetried: false });
    expect(f.intent.receivedResponses[0]).toMatchObject({ status: 'uncertain', observationId: null }); expect(f.intent.samples).toEqual([]);
    expect(f.helper.isKnownM7StoppedSamplingIntent(f.h.state, f.intent)).toBe(true); expect(JSON.stringify(f.h.state.requests)).toBe(f.prefix);
    expect(f.helper.readM7BlockedObservationEvidence(f.h.state)).toHaveLength(4); // also verifies all three second fixed files
    expect(f.h.save).toHaveBeenCalledTimes(1);
  });
  it('production hard-coded second journal anchors reject synthetic provenance', () => {
    const f = secondFixture(); f.helper.classifySecondM7StoppedCliObservation(f.h); expect(isKnownM7StoppedSamplingIntent(f.h.state, f.intent)).toBe(false);
  });
  it.each(['packet', 'first-seal', 'scope', 'key', 'sample', 'response', 'already-classified'])('rejects %s before second evidence or mutation', defect => {
    const f = secondFixture();
    if (defect === 'packet') f.h.state.requests[269].requestId = 'changed'; if (defect === 'first-seal') f.h.state.producerBlockedObservationProof.priorState = 'verified';
    if (defect === 'scope') f.intent.wid = 'foreign'; if (defect === 'key') f.intent.keys[1] = f.intent.keys[0]; if (defect === 'sample') f.intent.samples.push({});
    if (defect === 'response') f.intent.receivedResponses[0].status = 'confirmed'; if (defect === 'already-classified') f.h.state.producerCliPolicyStoppedObservationProof = {};
    expect(() => f.helper.classifySecondM7StoppedCliObservation(f.h)).toThrow(); expect(f.h.save).not.toHaveBeenCalled(); expect(f.reader).not.toHaveBeenCalled();
  });
  it.each([0, 1, 2])('cannot replace actual proof %s with client metadata', index => {
    const f = secondFixture(), path = M7_CLI_POLICY_STOPPED_OBSERVATION.sources[index].path; f.files.set(path, Buffer.from('{}'));
    expect(() => f.helper.classifySecondM7StoppedCliObservation(f.h)).toThrow('SOURCE_CHANGED'); expect(f.h.save).not.toHaveBeenCalled();
  });
  it.each(['background-zero', 'known-memory', 'no-policy-cause', 'missing-response', 'other-index'])('strict terminal exemption refuses %s', defect => {
    const f = secondFixture(); f.helper.classifySecondM7StoppedCliObservation(f.h); const proof = f.h.state.producerCliPolicyStoppedObservationProof;
    if (defect === 'background-zero') proof.backgroundObservationCountAtDiagnosis = 0; if (defect === 'known-memory') proof.originalMemoryObservationUnknown = false;
    if (defect === 'no-policy-cause') proof.originalCliPolicyMissing = false; if (defect === 'missing-response') proof.originalSafeFirstResponseRetained = false;
    if (defect === 'other-index') f.h.state.samplingIntents.push(f.h.state.samplingIntents.splice(1, 1)[0]); // same index requires extra sentinel
    if (defect === 'other-index') f.h.state.samplingIntents.splice(1, 0, { state: 'unknown' });
    expect(f.helper.isKnownM7StoppedSamplingIntent(f.h.state, f.intent)).toBe(false);
  });
});
