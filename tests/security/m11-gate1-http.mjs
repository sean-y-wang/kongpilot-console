import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {ReleaseHarness, releasePassword, releaseScope} from './lib/release-harness.mjs';

// Root-only real HTTP acceptance. Original request packets and credentials stay
// in the owner-only RAM ledger. This runner never issues a native Kong write.
assert.equal(process.env.RELEASE_LAB_M11_GATE1_READY, 'true');
const h = new ReleaseHarness('M11', {resume: existsSync('/dev/shm/kongpilot-release-lab/m11-harness.json')});
const stage = process.argv[2] ?? 'fixtures';
try {
  const old = JSON.parse(readFileSync('/dev/shm/kongpilot-release-lab/m10-harness.json', 'utf8'));
  const admin = h.state.sessions.admin ?? await h.login('admin', old.sessions.admin.username, old.sessions.admin.password);
  h.state.cid ??= old.targetCid;
  const cid = h.state.cid;
  h.state.gate1 ??= {workflows: {}, accounts: {}};
  const g = h.state.gate1;
  const scope = suffix => releaseScope(cid, h.state.wid, suffix);
  const confirm = wf => ({revision: wf.revision, planHash: wf.planHash, confirmed: true, confirm_name: wf.kind});
  const get = async id => (await h.request(admin, scope(`workflows/${id}`))).data.entity;
  const deny = async (label, session, path, body, status) => {
    const prior = h.state.requests.find(p => p.label === label);
    if (prior) { assert.equal(prior.status, status); assert.equal(prior.state, 'response_observed'); return prior; }
    return h.once(label, session, path, 'POST', body, {expected: [status]});
  };
  if (stage === 'fixtures') {
    const cluster = (await h.request(admin, `/clusters/${cid}`)).data;
    g.originalMode ??= cluster.execution_mode;
    assert.equal(cluster.execution_mode, 'direct', 'fixture scope must already be direct');
    const ws = (await h.once('m11-workspace', admin, `/clusters/${cid}/workspaces`, 'POST',
      {code: `${h.state.tag}-approval`, name: `${h.state.tag} Approval`, owner_user_id: admin.user.id})).data;
    h.state.wid = ws.id; h.save();
    const role = (await h.once('m11-reviewer-role', admin, '/iam/roles', 'POST',
      {code: `${h.state.tag}-reviewer`, name: 'M11 acceptance reviewer', cluster_id: cid, workspace_id: ws.id})).data;
    g.roleId = role.id; h.save();
    const permissions = ['workflows', 'lint'].flatMap(module => ['read', 'approve'].map(action =>
      ({module, action, scope_type: 'workspace', scope_values: [ws.id], cluster_id: cid, workspace_id: ws.id})));
    await h.once('m11-reviewer-permissions', admin, `/iam/roles/${role.id}/permissions`, 'PUT', {revision: role.revision, permissions});
    const team = (await h.once('m11-final-review-team', admin, '/iam/teams', 'POST',
      {code: `${h.state.tag}-final`, name: 'M11 acceptance final reviewers'})).data;
    g.teamId = team.id; h.save();
    for (const label of ['a', 'b', 'c', 'd', 'e']) {
      const account = g.accounts[label] ??= {username: `${h.state.tag}-${label}`, initialPassword: releasePassword(), password: releasePassword()}; h.save();
      const user = (await h.once(`m11-user-${label}`, admin, '/iam/users', 'POST',
        {username: account.username, display_name: `M11 reviewer ${label.toUpperCase()}`, password: account.initialPassword})).data;
      account.id = user.id; h.save();
      if (!h.state.sessions[label]) {
        const initial = h.state.sessions[`${label}-initial`] ?? await h.login(`${label}-initial`, account.username, account.initialPassword);
        await h.once(`m11-password-${label}`, initial, '/auth/me/password', 'POST',
          {revision: initial.user.revision, current_password: account.initialPassword, new_password: account.password, confirmed: true});
        await h.login(label, account.username, account.password);
      }
      const binding = (await h.once(`m11-bind-${label}`, admin, `/iam/users/${user.id}/role-bindings`, 'POST',
        {role_id: role.id, cluster_id: cid, workspace_id: ws.id})).data;
      account.bindingId = binding.id; h.save();
      if (['d', 'e'].includes(label)) account.membership = (await h.once(`m11-member-${label}`, admin,
        `/iam/teams/${team.id}/members`, 'POST', {user_id: user.id})).data;
      h.save();
      assert.equal(h.state.sessions[label].user.superAdmin, false);
    }
    const now = (await h.request(admin, `/clusters/${cid}`)).data;
    g.approvalModeBody ??= {revision: now.revision, execution_mode: 'approval'}; h.save();
    await h.once('m11-cluster-approval', admin, `/clusters/${cid}`, 'PATCH', g.approvalModeBody);
    h.check(true, 'five genuine non-superadmin reviewers have only the new workspace read/approve grants');
  } else if (stage === 'bootstrap') {
    const input = {code: `${h.state.tag}-bootstrap`, name: 'M11 legacy approval', given: {entityTypes: ['services']}, then: {path: 'tags', op: 'required'}, severity: 'warn', enabled: true};
    const submission = (await h.once('m11-bootstrap-submit', admin, scope('governance/rules'), 'POST', input)).data;
    g.bootstrapWorkflowId = submission.workflowId; h.save();
    let wf = await get(submission.workflowId);
    assert.equal(wf.kind, 'governance-metadata'); assert.equal(wf.approval, undefined);
    if (wf.state === 'pending') await h.once('m11-bootstrap-approve', h.state.sessions.a, scope(`workflows/${wf.id}/approve`), 'POST', {...confirm(wf), execute: false});
    wf = await get(wf.id);
    if (wf.state === 'approved') await h.once('m11-bootstrap-execute', admin, scope(`workflows/${wf.id}/execute`), 'POST', confirm(wf));
    assert.equal((await get(wf.id)).state, 'succeeded');
    h.check(true, 'actual legacy V1 single governance workflow remains executable with a genuine distinct reviewer');
    const list = (await h.request(admin, scope('workflow-definitions'))).data;
    const definition = list.items.find(d => d.kind === 'governance-metadata'); assert(definition);
    g.definition = definition;
    g.policy ??= {version: 2, kind: 'governance-metadata', allowSelfApproval: false, distinctAcrossStages: true, intentTtlHours: 24,
      stages: [
        {level: 1, name: '初审', mode: 'any', threshold: 1, selector: {users: [g.accounts.a.id]}},
        {level: 2, name: '联合审批', mode: 'quorum', threshold: 2, selector: {users: [g.accounts.b.id, g.accounts.c.id]}},
        {level: 3, name: '最终会签', mode: 'all', threshold: null, selector: {teams: [g.teamId]}}
      ]}; h.save();
    g.policyBody ??= {revision: definition.revision, policy: g.policy, confirmed: true, confirm_name: definition.name}; h.save();
    const change = (await h.once('m11-policy-submit', admin, scope(`workflow-definitions/${definition.id}/versions`), 'POST', g.policyBody)).data;
    g.policyWorkflowId = change.workflowId; h.save();
    let policyWf = await get(change.workflowId);
    assert.equal(policyWf.kind, 'workflow-policy-metadata'); assert.equal(policyWf.approval, undefined);
    const before = (await h.request(admin, scope('workflow-definitions'))).data.items.find(d => d.id === definition.id);
    if (policyWf.state === 'pending') assert.equal(before.version, definition.version);
    if (policyWf.state === 'pending') await h.once('m11-policy-approve', h.state.sessions.a, scope(`workflows/${policyWf.id}/approve`), 'POST', {...confirm(policyWf), execute: false});
    policyWf = await get(policyWf.id);
    if (policyWf.state === 'approved') await h.once('m11-policy-execute', admin, scope(`workflows/${policyWf.id}/execute`), 'POST', confirm(policyWf));
    assert.equal((await get(policyWf.id)).state, 'succeeded');
    const after = (await h.request(admin, scope('workflow-definitions'))).data.items.find(d => d.id === definition.id);
    assert.equal(after.version, definition.version + 1); assert.equal(after.format, 2);
    assert.deepEqual(after.policy, g.policy);
    h.check(true, 'policy changes execute only after approval under the existing frozen administration policy');
  } else if (stage === 'approval') {
    const submit = async label => {
      const record = g.workflows[label] ??= {body: {code: `${h.state.tag}-${label}`, name: `M11 ${label}`, given: {entityTypes: ['services']}, then: {path: 'tags', op: 'required'}, severity: 'warn', enabled: true}}; h.save();
      const result = (await h.once(`m11-${label}-submit`, admin, scope('governance/rules'), 'POST', record.body)).data;
      record.id = result.workflowId; h.save(); return get(record.id);
    };
    for (const label of ['success', 'revoked']) {
      let wf = await submit(label);
      assert.equal(wf.approval.format, 2); assert.equal(wf.approval.stages.length, 3);
      assert.deepEqual(wf.approval.stages.map(s => [s.mode, s.threshold, s.candidateCount]), [['any', 1, 1], ['quorum', 2, 2], ['all', 2, 2]]);
      const voteBody = (current, level) => ({...confirm(current), execute: false, level,
        stageRevision: current.approval.stages.find(s => s.level === level).revision, candidateVersion: current.approval.candidateVersion});
      if (wf.state === 'pending' && wf.approval.stages[0].votes === 0) {
        await deny(`m11-${label}-self-denied`, admin, scope(`workflows/${wf.id}/approve`), voteBody(wf, 1), 403);
        await deny(`m11-${label}-noncandidate-denied`, h.state.sessions.b, scope(`workflows/${wf.id}/approve`), voteBody(wf, 1), 403);
        await deny(`m11-${label}-unapproved-execute-denied`, admin, scope(`workflows/${wf.id}/execute`), confirm(wf), 409);
      }
      for (const [reviewer, level, terminal] of [['a', 1, false], ['b', 2, false], ['c', 2, false], ['d', 3, false], ['e', 3, true]]) {
        wf = await get(wf.id);
        const voted = h.state.requests.some(p => p.label === `m11-${label}-vote-${reviewer}` && p.status < 300);
        if (!voted) await h.once(`m11-${label}-vote-${reviewer}`, h.state.sessions[reviewer], scope(`workflows/${wf.id}/approve`), 'POST', voteBody(wf, level));
        wf = await get(wf.id);
        assert.equal(wf.state, terminal ? 'approved' : 'pending');
        assert.equal(wf.approval.approvalSetId !== null, terminal);
      }
      h.check(true, `${label}: sequential any/quorum/all requires all five distinct genuine votes before sealing an approval set`, {workflowId: wf.id});
      if (label === 'success') {
        await deny('m11-foreign-executor-denied', h.state.sessions.a, scope(`workflows/${wf.id}/execute`), confirm(wf), 403);
        const result = (await h.once('m11-success-execute', admin, scope(`workflows/${wf.id}/execute`), 'POST', confirm(wf))).data;
        assert.equal(result.state, 'succeeded'); assert.equal(result.steps.length, 1);
        assert.equal(result.steps[0].operationId, null); assert.equal((await get(wf.id)).state, 'succeeded');
        h.check(true, 'V2 complete approval set permits the fixed zero-native metadata execution', {workflowId: wf.id});
      }
    }
    const pending = await submit('sql-pending');
    assert.equal(pending.state, 'pending'); assert(pending.approval.stages.every(s => s.votes === 0));
    g.sqlPendingWorkflowId = pending.id; g.sqlApprovedWorkflowId = g.workflows.success.id; h.save();
    const d = g.accounts.d;
    await h.once('m11-final-membership-revoke', admin, `/iam/teams/${g.teamId}/members/${d.id}`, 'DELETE',
      {revision: d.membership.revision, confirmed: true, confirm_name: d.username});
    const blocked = await get(g.workflows.revoked.id);
    await deny('m11-earlier-reviewer-revoked-execute-denied', admin, scope(`workflows/${blocked.id}/execute`), confirm(blocked), 403);
    const unchanged = await get(blocked.id); assert.equal(unchanged.state, 'approved');
    const cancelled = (await h.once('m11-approved-cancel', admin, scope(`workflows/${unchanged.id}/cancel`), 'POST',
      {revision: unchanged.revision, confirmed: true, confirm_name: unchanged.kind})).data;
    assert.equal(cancelled.entity.state, 'cancelled');
    const history = (await h.request(admin, scope(`workflows/${blocked.id}`))).data;
    assert.equal(history.decisions.length, 5); assert(history.entity.approval.stages.every(s => s.state === 'approved'));
    h.check(true, 'revoking an earlier final-stage reviewer blocks execution despite the last reviewer remaining eligible; cancellation retains all original votes', {workflowId: blocked.id});
  } else if (stage === 'finish-cancel') {
    const wf = await get(g.workflows.revoked.id);
    assert.equal(wf.state, 'approved');
    const result = (await h.once('m11-approved-cancel', admin, scope(`workflows/${wf.id}/cancel`), 'POST',
      {revision: wf.revision, confirmed: true, confirm_name: wf.kind})).data;
    assert.equal(result.entity.state, 'cancelled');
    const history = (await h.request(admin, scope(`workflows/${wf.id}`))).data;
    assert.equal(history.decisions.length, 5); assert(history.entity.approval.stages.every(s => s.state === 'approved'));
    h.check(true, 'revoking an earlier final-stage reviewer blocks execution despite the last reviewer remaining eligible; cancellation retains all original votes', {workflowId: wf.id});
  } else if (stage === 'cleanup') {
    const pending = await get(g.sqlPendingWorkflowId);
    if (pending.state === 'pending') await h.once('m11-sql-control-cancel', admin, scope(`workflows/${pending.id}/cancel`), 'POST',
      {revision: pending.revision, confirmed: true, confirm_name: pending.kind});
    assert.equal((await get(pending.id)).state, 'cancelled');
    const cluster = (await h.request(admin, `/clusters/${cid}`)).data;
    g.restoreModeBody ??= {revision: cluster.revision, execution_mode: g.originalMode}; h.save();
    if (cluster.execution_mode !== g.originalMode) await h.once('m11-restore-original-cluster-mode', admin, `/clusters/${cid}`, 'PATCH', g.restoreModeBody);
    assert.equal((await h.request(admin, `/clusters/${cid}`)).data.execution_mode, g.originalMode);
    h.check(true, 'SQL structural control was cancelled through its original workflow and the cluster execution mode restored after acceptance');
  } else throw Error('UNKNOWN_GATE1_STAGE');
  h.state.phase = `m11-gate1-${stage}-complete`; h.save(); h.report(true);
  console.log(JSON.stringify({passed: true, phase: h.state.phase, checks: h.state.checks.length, overallAcceptance: false}));
} catch (error) {
  h.state.phase = `m11-gate1-${stage}-stopped`; h.save(); h.report(false, 'M11_GATE1_HTTP_STOPPED');
  console.error(JSON.stringify({passed: false, message: String(error.message).slice(0, 500)})); process.exitCode = 1;
}
