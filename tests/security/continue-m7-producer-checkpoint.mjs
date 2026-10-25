import { readFileSync } from 'node:fs';
import { M7Harness, sha256 } from './lib/m7-harness.mjs';
import { retainM7History } from './lib/m7-private-history.mjs';
import { M7_BLOCKED_OBSERVATION, classifyOriginalM7StoppedObservation } from './lib/m7-blocked-observation.mjs';
import { producerAcceptance } from './lib/m7-producer-acceptance.mjs';
import { eventRead } from './lib/m7-event-acceptance.mjs';
import { auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_PRODUCER_CONTINUATION_READY !== 'true') throw new Error('M7_SEALED_BLOCKED_PRODUCER_AND_REPAIRED_RUNTIME_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
try {
  h.check(h.state.phase === 'stopped-failure' && h.state.producerWindow?.state === 'prepared' && !h.state.producerContinuation &&
    h.state.inFlight == null && h.state.requests.length === M7_BLOCKED_OBSERVATION.packetCount &&
    h.state.requests.every(packet => packet.state === 'response_observed') && h.state.samplingIntents.length === 1 &&
    h.state.samplingIntents[0].state === 'unknown' && !h.state.producersComplete && h.state.legacyWorkflowSubmissionAuditProof?.state === 'complete' &&
    sha256(JSON.stringify(h.state.requests)) === M7_BLOCKED_OBSERVATION.packetSha256,
    'producer continuation preserves the original 267 known packets and never restarts the original unknown sampling keys');
  retainM7History(h.state, 'producerContinuationHistory');
  h.state.producerContinuation = { version: 1, state: 'prepared', startedAt: new Date().toISOString(), originalPackets: 267,
    originalPacketsSha256: M7_BLOCKED_OBSERVATION.packetSha256,
    sourceFiles: ['tests/security/continue-m7-producer-checkpoint.mjs', 'tests/security/lib/m7-blocked-observation.mjs',
      'tests/security/lib/m7-producer-acceptance.mjs', 'tests/security/lib/m7-secret-scan-policy.mjs', 'tests/security/finalize-m7-secret-scan.mjs']
      .map(path => ({ path, sha256: sha256(readFileSync(path)) })) }; h.save();
  const blocked = classifyOriginalM7StoppedObservation(h);
  h.save({ phase: 'new-real-producer-subject-and-unused-upstream-tail' });
  const actors = { admin: h.state.sessions.admin, approver: h.state.sessions.approver, ...h.state.scopes };
  const fixture = h.state.fixtures.find(row => row.type === 'channels' && row.name === `${h.state.testTag}-webhook` && row.cid === actors.direct.cid && row.wid === actors.direct.wid);
  h.check(fixture, 'producer continuation retains the original configured local receiver channel');
  const channel = await eventRead(h, actors.admin, actors.direct, `channels/${fixture.id}`);
  h.check(channel.status === 'active' && channel.configured, 'trusted local producer receiver remains currently active');
  h.state.producerAcceptance = await producerAcceptance(h, actors, channel, { expirySubscriptionSuffix: 'expiry-after-fence-repair' }); h.save();
  h.state.producerAuditWriteCoverage = await auditAllWritesCoverage(h, actors); h.save();
  h.check(sha256(JSON.stringify(h.state.requests.slice(0, 267))) === M7_BLOCKED_OBSERVATION.packetSha256,
    'new subject and unused upstream tail preserve all original 267 packets including every failed attempt');
  h.state.producerWindow.state = 'completed'; h.state.producerContinuation.state = 'completed'; h.save();
  h.public = { ...(h.public ?? {}), scope: 'sealed-original-blocked-observation-and-new-real-producers',
    originalBlockedSampling: blocked, originalProducerFailureRetained: true, originalSuccessfulPacketsReplayed: false,
    artificialObservationInputs: false, productionObserverEnabled: true, nativeTransportWritesOutsideBff: 0,
    terminalAuditWriteCoverage: h.state.producerAuditWriteCoverage };
} catch (error) { failure = error; }
// Original producer and diagnosis failures remain at their original paths.
process.exitCode = h.finish(failure, 'artifacts/M7/security-producers-continuation.json', 'producers-complete');
