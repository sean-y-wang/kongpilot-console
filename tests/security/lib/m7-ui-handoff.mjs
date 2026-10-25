import { readFileSync } from 'node:fs';
import { M7_UI_ACTIONS } from './m7-manual-journal.mjs';
import { sha256, rows } from './m7-harness.mjs';
import { retainM7History } from './m7-private-history.mjs';

/** Normal original-session maintenance for an already complete producer run.
 * No new login, identity, permission or native intent is introduced here. */
export async function prepareM7UiHandoff(h) {
  h.check(h.state.phase === 'producers-complete' && h.state.producersComplete === true && !h.state.manualUiHandoff && !h.state.manualUiJournal &&
    !h.state.uiHandoffPreparation && h.state.inFlight == null && h.state.requests.every(packet => packet.state === 'response_observed'),
    'UI handoff starts once from complete original producer and BFF receipts');
  const paths = { http: 'artifacts/M7/security-live-audit-download-continuation.json', producers: 'artifacts/M7/security-producers-cli-policy-continuation.json' };
  const evidence = Object.fromEntries(Object.entries(paths).map(([key, path]) => {
    const bytes = readFileSync(path), report = JSON.parse(bytes);
    h.check(report.allPassed === true && report.failed === 0 && report.testTag === h.state.testTag, 'handoff retains exact successful HTTP and producer evidence', { kind: key });
    return [key, { path, sha256: sha256(bytes) }];
  }));
  retainM7History(h.state, 'uiHandoffPreparationHistory');
  h.state.uiHandoffPreparation = { version: 1, state: 'prepared', at: new Date().toISOString(), evidence, authWrites: [] }; h.save();
  for (const label of ['admin', 'owner', 'read-only']) {
    const session = h.state.sessions[label], actorId = session?.user?.id, username = session?.user?.username, sid = session?.sid;
    h.check(session && typeof actorId === 'string' && typeof sid === 'string', 'named UI actor retains an original session', { label });
    if (session.expiresAt <= Date.now() + 420000) {
      const result = await h.request(session, '/auth/refresh', 'POST', {}, { expected: [201], renew: false }), data = h.data(result);
      h.check(data.user?.id === actorId && data.user?.username === username, 'normal UI session maintenance retains the original actor', { label });
      session.csrf = session.cookie.split('; ').find(value => value.startsWith('kongos_csrf='))?.slice(12); session.user = data.user;
      h.check(typeof session.csrf === 'string' && session.csrf.length > 0, 'normal UI session maintenance receives the current CSRF cookie', { label });
      h.updateSessionIdentity(session); h.cookies(session.cookie); h.remember({ csrfToken: session.csrf }); h.save();
      h.check(session.sid === sid, 'normal UI session maintenance retains the original SID', { label });
      h.state.uiHandoffPreparation.authWrites.push({ label, actorId, sid, requestId: result.requestId }); h.save();
    }
    const me = h.data(await h.request(session, '/auth/me', 'GET', undefined, { renew: false }));
    h.check(me.user?.id === actorId && session.sid === sid && session.expiresAt > Date.now() + 300000,
      'current protected UI session has the original actor and at least five minutes remaining', { label });
  }
  const actor = h.state.sessions.admin, clusters = rows(h.data(await h.request(actor, '/clusters', 'GET', undefined, { renew: false }))), area = h.state.scopes;
  const direct = clusters.find(row => row.id === area.direct.cid), approval = clusters.find(row => row.id === area.approval.cid);
  h.check(direct && approval && direct.execution_mode === 'direct' && approval.execution_mode === h.state.originalClusterModes[approval.id].mode,
    'original canonical cluster modes are restored before the UI window');
  const workspaces = h.state.fixtures.filter(row => row.type === 'workspaces'), workspaceName = scope => workspaces.find(row => row.id === scope.wid && row.cid === scope.cid)?.name;
  const workflow = h.state.eventOperations.find(row => row.approval === true && row.workflowId && row.cid === area.approval.cid && row.wid === area.approval.wid);
  h.check(workflow && [area.direct, area.foreign, area.approval].every(scope => typeof workspaceName(scope) === 'string'), 'UI scope and completed approval detail are original fresh M7 fixtures');
  const handoff = { version: 1, phase: 'ready', testTag: h.state.testTag, approvedActions: [...M7_UI_ACTIONS], securityReportPath: evidence.http.path,
    securityReportSha256: evidence.http.sha256, producerReportPath: evidence.producers.path, producerReportSha256: evidence.producers.sha256,
    direct: area.direct, directClusterLabel: `${direct.name} · ${direct.environment}`, directWorkspaceName: workspaceName(area.direct), foreignWorkspaceName: workspaceName(area.foreign),
    approvalClusterLabel: `${approval.name} · ${approval.environment}`, approvalWorkspaceName: workspaceName(area.approval), approvalWorkflowId: workflow.workflowId, approvalMode: 'completed-read-only' };
  h.state.uiHandoffPreparation = { ...h.state.uiHandoffPreparation, state: 'completed', atCompleted: new Date().toISOString() }; h.state.manualUiHandoff = handoff; h.save({ phase: 'producers-complete' });
  return { handoff, authenticationWrites: h.state.uiHandoffPreparation.authWrites.length, normalRenewalRequestIds: h.state.uiHandoffPreparation.authWrites.map(row => row.requestId), loginWrites: 0, nativeTransportWrites: 0 };
}
