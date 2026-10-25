import { M7Harness } from './lib/m7-harness.mjs';
import { eventRead } from './lib/m7-event-acceptance.mjs';
import { producerAcceptance } from './lib/m7-producer-acceptance.mjs';
import { auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';
import { retainM7History } from './lib/m7-private-history.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_PRODUCERS_READY !== 'true') throw new Error('M7_EXCLUSIVE_PRODUCER_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
try {
  h.check(h.state.phase === 'http-complete' && !h.state.producerWindow && h.state.inFlight == null && h.state.requests.every(p => p.state === 'response_observed') && !h.state.manualUiJournal && !h.state.samplingIntents.length,
    'real producer verification begins once after complete original HTTP checkpoints');
  retainM7History(h.state, 'producerWindowHistory');
  h.state.producerWindow = { version: 1, state: 'prepared', startedAt: new Date().toISOString() }; h.save({ phase: 'producer-observation' });
  const actors = { admin: h.state.sessions.admin, approver: h.state.sessions.approver, ...h.state.scopes };
  const fixture = h.state.fixtures.find(f => f.type === 'channels' && f.name === `${h.state.testTag}-webhook` && f.cid === actors.direct.cid && f.wid === actors.direct.wid);
  h.check(fixture, 'trusted producer source uses the original local webhook channel');
  const channel = await eventRead(h, actors.admin, actors.direct, `channels/${fixture.id}`);
  h.check(channel.status === 'active' && channel.configured, 'original local webhook is currently active before producer subscriptions');
  h.state.producerAcceptance = await producerAcceptance(h, actors, channel); h.save();
  h.state.producerAuditWriteCoverage = await auditAllWritesCoverage(h, actors); h.save();
  h.state.producerWindow.state = 'completed'; h.save();
  Object.assign(h.public ??= {}, { scope: 'real-X509-expiry-and-Upstream-observer-producers', productionObserverEnabled: true, artificialObservationInputs: false, nativeTransportWritesOutsideBff: 0, terminalAuditWriteCoverage: h.state.producerAuditWriteCoverage });
} catch (error) { failure = error; }
process.exitCode = h.finish(failure, 'artifacts/M7/security-producers.json', 'producers-complete');
