import { readFileSync } from 'node:fs';
import { M7Harness, sha256 } from './lib/m7-harness.mjs';
import { retainM7History } from './lib/m7-private-history.mjs';
import { M7_BLOCKED_OBSERVATION, M7_CLI_POLICY_STOPPED_OBSERVATION, isKnownM7StoppedSamplingIntent, readM7BlockedObservationEvidence } from './lib/m7-blocked-observation.mjs';
import { completeM7ExistingUpstreamProducer } from './lib/m7-upstream-producer-tail.mjs';
import { eventRead } from './lib/m7-event-acceptance.mjs';
import { auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_UPSTREAM_PRODUCER_CONTINUATION_READY !== 'true') throw new Error('M7_ORIGINAL_HEALTHY_TARGET_UNUSED_TAIL_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
try {
  const packetSha256 = 'bb5c3a9ee1e562a94024e26335ed6e56eb613b3fef5d3d49c0e3c02375b984ba';
  const sources = [
    { path: 'artifacts/M7/security-producers-cli-policy-health-mark-failure.json', sha256: '9ad2ebf6b4a16901e27f881bfc15f8ab3398baa90ebeca6ef0a32b8ff49f2c32' },
    { path: 'artifacts/M7/producer-upstream-first-health-readonly-diagnosis.json', sha256: 'dfbfc314430f5e5bfdb8597e320eb908e8432400f40996f73471e82e8ff0bcf2' },
    { path: 'artifacts/M7/producer-upstream-health-shape-readonly-proof.json', sha256: '3142e6d8556a8319e7fedeeafacae1663658b2da21f51ce1d07461477eeb0d0a' },
  ];
  const [failureReport, receiptProof, healthProof] = sources.map(source => { const bytes = readFileSync(source.path); h.check(sha256(bytes) === source.sha256, 'original health failure and two read-only proofs keep exact bytes'); return JSON.parse(bytes); });
  h.check(failureReport.passed === 47 && failureReport.failed === 1 && failureReport.allPassed === false && receiptProof.receipt?.state === 'failed' && receiptProof.receipt?.remoteCompleted === false &&
    healthProof.healthStatuses?.length === 1 && healthProof.healthStatuses[0].id === '4c92e70c-a2be-43bb-8b6b-f87f1d52a9bf' && healthProof.healthStatuses[0].health === 'HEALTHY',
    'original failed healthy operation stays failed while actual corrected shape proves current healthy baseline');
  h.check(h.state.phase === 'stopped-failure' && !h.state.producerUpstreamTailContinuation && h.state.producerCliPolicyContinuation?.state === 'prepared' && h.state.requests.length === 275 &&
    sha256(JSON.stringify(h.state.requests)) === packetSha256 && h.state.inFlight == null && h.state.requests.every(packet => packet.state === 'response_observed') &&
    h.state.samplingIntents.length === 3 && h.state.samplingIntents.slice(0, 2).every(intent => isKnownM7StoppedSamplingIntent(h.state, intent)) &&
    sha256(JSON.stringify(h.state.samplingIntents[2])) === '458adebf81490bb3ff0daff6e1638aa846e08501979dcd0fae74021995ec470b' && !h.state.producersComplete,
    'all original 275 packets and completed five certificate samples remain unchanged before unused health transition');
  readM7BlockedObservationEvidence(h.state);
  retainM7History(h.state, 'producerUpstreamTailContinuationHistory');
  h.state.producerUpstreamTailContinuation = { version: 1, state: 'prepared', originalPackets: 275, originalPacketSha256: packetSha256, sources,
    at: new Date().toISOString(), sourceFiles: ['tests/security/continue-m7-upstream-producer-checkpoint.mjs', 'tests/security/lib/m7-upstream-producer-tail.mjs'].map(path => ({ path, sha256: sha256(readFileSync(path)) })) }; h.save({ phase: 'original-Upstream-unused-health-transition-tail' });
  const actors = { admin: h.state.sessions.admin, approver: h.state.sessions.approver, ...h.state.scopes }, channelFixture = h.state.fixtures.find(row => row.type === 'channels' && row.name === `${h.state.testTag}-webhook` && row.cid === actors.direct.cid && row.wid === actors.direct.wid);
  h.check(channelFixture, 'unused tail retains the original local trusted event sink');
  const channel = await eventRead(h, actors.admin, actors.direct, `channels/${channelFixture.id}`);
  h.state.producerAcceptance = await completeM7ExistingUpstreamProducer(h, actors, channel); h.save();
  h.state.producerAuditWriteCoverage = await auditAllWritesCoverage(h, actors); h.save();
  h.check(sha256(JSON.stringify(h.state.requests.slice(0, 275))) === packetSha256, 'completed producers preserve the original failed healthy packet and every successful packet');
  for (const marker of ['producerWindow', 'producerContinuation', 'producerCliPolicyContinuation', 'producerUpstreamTailContinuation']) h.state[marker].state = 'completed'; h.save();
  h.public = { ...(h.public ?? {}), scope: 'sealed-original-CLI-policy-stops-and-new-real-producers', originalProducerFailureRetained: true, originalSuccessfulPacketsReplayed: false,
    originalBlockedSampling: { originalCertificateId: M7_BLOCKED_OBSERVATION.id, originalSamplingKeysRetained: 5, classification: 'stopped_without_durable_observation', originalUnknownReportRetained: true,
      originalMemoryObservationUnknown: true, originalObservationRetried: false, immutableEvidenceSources: M7_BLOCKED_OBSERVATION.sources },
    originalCliStoppedSampling: { originalCertificateId: M7_CLI_POLICY_STOPPED_OBSERVATION.id, originalSamplingKeysRetained: 5, classification: 'stopped_without_cli_durable_observation',
      originalMemoryObservationUnknown: true, originalSafeFirstResponseRetained: true, backgroundObservationCountAtDiagnosis: 1, originalObservationRetried: false, immutableEvidenceSources: M7_CLI_POLICY_STOPPED_OBSERVATION.sources },
    originalHealthyFailureRetained: true, failedHealthyPacketReplayed: false, healthyBaselineVerifiedReadOnly: true, completedCertificateSamplesReplayed: false,
    artificialObservationInputs: false, productionObserverEnabled: true, nativeTransportWritesOutsideBff: 0, terminalAuditWriteCoverage: h.state.producerAuditWriteCoverage };
} catch (error) { failure = error; }
// The previous 47/1 bytes are archived before this checkpoint is allowed to run.
process.exitCode = h.finish(failure, 'artifacts/M7/security-producers-cli-policy-continuation.json', 'producers-complete');
