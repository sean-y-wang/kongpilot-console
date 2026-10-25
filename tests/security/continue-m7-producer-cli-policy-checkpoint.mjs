import { readFileSync } from 'node:fs';
import { M7Harness, sha256 } from './lib/m7-harness.mjs';
import { retainM7History } from './lib/m7-private-history.mjs';
import { M7_BLOCKED_OBSERVATION, M7_CLI_POLICY_STOPPED_OBSERVATION, classifySecondM7StoppedCliObservation, isKnownM7StoppedSamplingIntent } from './lib/m7-blocked-observation.mjs';
import { producerAcceptance } from './lib/m7-producer-acceptance.mjs';
import { eventRead } from './lib/m7-event-acceptance.mjs';
import { auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_PRODUCER_CLI_POLICY_CONTINUATION_READY !== 'true') throw new Error('M7_REPAIRED_NATIVE_POLICY_AUXILIARY_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
try {
  const fixed = M7_CLI_POLICY_STOPPED_OBSERVATION;
  h.check(h.state.phase === 'stopped-failure' && h.state.producerContinuation?.state === 'prepared' && !h.state.producerCliPolicyContinuation &&
    h.state.inFlight == null && h.state.requests.length === fixed.packetCount && h.state.requests.every(packet => packet.state === 'response_observed') &&
    h.state.samplingIntents.length === 2 && h.state.samplingIntents[1].state === 'unknown' && isKnownM7StoppedSamplingIntent(h.state, h.state.samplingIntents[0]) &&
    !h.state.producersComplete && sha256(JSON.stringify(h.state.requests)) === fixed.packetSha256,
    'exact second stopped CLI checkpoint and all 270 original packets remain immutable before unused producer steps');
  retainM7History(h.state, 'producerCliPolicyContinuationHistory');
  h.state.producerCliPolicyContinuation = { version: 1, state: 'prepared', startedAt: new Date().toISOString(), originalPackets: fixed.packetCount,
    originalPacketsSha256: fixed.packetSha256, sourceFiles: ['tests/security/continue-m7-producer-cli-policy-checkpoint.mjs',
      'tests/security/lib/m7-blocked-observation.mjs', 'tests/security/lib/m7-producer-acceptance.mjs', 'tests/security/finalize-m7-secret-scan.mjs']
      .map(path => ({ path, sha256: sha256(readFileSync(path)) })) }; h.save();
  const stopped = classifySecondM7StoppedCliObservation(h);
  h.save({ phase: 'new-real-producer-after-native-policy-install-and-unused-upstream-tail' });
  const actors = { admin: h.state.sessions.admin, approver: h.state.sessions.approver, ...h.state.scopes };
  const fixture = h.state.fixtures.find(row => row.type === 'channels' && row.name === `${h.state.testTag}-webhook` && row.cid === actors.direct.cid && row.wid === actors.direct.wid);
  h.check(fixture, 'original local event receiver channel remains the producer sink');
  const channel = await eventRead(h, actors.admin, actors.direct, `channels/${fixture.id}`);
  h.check(channel.status === 'active' && channel.configured, 'trusted local producer receiver is currently active');
  h.state.producerAcceptance = await producerAcceptance(h, actors, channel, { expirySubscriptionSuffix: 'expiry-after-cli-policy-install' }); h.save();
  h.state.producerAuditWriteCoverage = await auditAllWritesCoverage(h, actors); h.save();
  h.check(sha256(JSON.stringify(h.state.requests.slice(0, fixed.packetCount))) === fixed.packetSha256,
    'actual producers and terminal audit preserve original 270 packets without replay');
  h.state.producerWindow.state = 'completed'; h.state.producerContinuation.state = 'completed'; h.state.producerCliPolicyContinuation.state = 'completed'; h.save();
  h.public = { ...(h.public ?? {}), scope: 'sealed-original-CLI-policy-stops-and-new-real-producers',
    originalBlockedSampling: { originalCertificateId: h.state.samplingIntents[0].id, originalSamplingKeysRetained: 5,
      classification: 'stopped_without_durable_observation', originalUnknownReportRetained: true, originalMemoryObservationUnknown: true,
      originalObservationRetried: false, immutableEvidenceSources: M7_BLOCKED_OBSERVATION.sources },
    originalCliStoppedSampling: stopped, originalProducerFailureRetained: true, originalSuccessfulPacketsReplayed: false,
    artificialObservationInputs: false, productionObserverEnabled: true, nativeTransportWritesOutsideBff: 0,
    terminalAuditWriteCoverage: h.state.producerAuditWriteCoverage };
} catch (error) { failure = error; }
process.exitCode = h.finish(failure, 'artifacts/M7/security-producers-cli-policy-continuation.json', 'producers-complete');
