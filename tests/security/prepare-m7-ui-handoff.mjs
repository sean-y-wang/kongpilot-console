import { M7Harness } from './lib/m7-harness.mjs';
import { prepareM7UiHandoff } from './lib/m7-ui-handoff.mjs';
import { auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_UI_HANDOFF_READY !== 'true') throw new Error('M7_ORIGINAL_SESSION_UI_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure;
try {
  const result = await prepareM7UiHandoff(h), actors = { admin: h.state.sessions.admin, ...h.state.scopes };
  const auditWriteCoverage = await auditAllWritesCoverage(h, actors); h.save();
  h.check(['admin', 'owner', 'read-only'].every(label => h.state.sessions[label].expiresAt > Date.now() + 300000), 'all original UI actors still have five minutes after actual audit reconciliation');
  h.public = { ...result, auditWriteCoverage, originalSidsPreserved: true, freshLoginPerformed: false, plannedManualWrites: 12,
    phase: 'producers-complete', sessions: ['admin', 'owner', 'read-only'].map(label => { const session = h.state.sessions[label]; return {
      label, actorId: session.user.id, sid: session.sid, sessionExpiresAt: new Date(session.expiresAt).toISOString(), remainingSeconds: Math.floor((session.expiresAt - Date.now()) / 1000) }; }) };
} catch (error) { failure = error; }
process.exitCode = h.finish(failure, 'artifacts/M7/manual-ui-original-session-handoff.json', 'producers-complete');
