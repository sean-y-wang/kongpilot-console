import { M7Harness, entity, rows, scope } from './lib/m7-harness.mjs';
import { eventRead, eventWrite, confirmation } from './lib/m7-event-acceptance.mjs';
import { restoreClusterMode } from './lib/m7-fixtures.mjs';
import { auditAllWritesCoverage } from './lib/m7-audit-acceptance.mjs';
import { m7KnownWritePacket } from './lib/m7-secret-scan-policy.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_CLEANUP_READY !== 'true') throw new Error('M7_EXCLUSIVE_CLEANUP_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }); let failure; const archived = [];
try {
  h.check(['http-complete', 'producers-complete', 'ui-complete'].includes(h.state.phase) && !h.state.cleanupStarted && h.state.inFlight == null && h.state.requests.every(v => m7KnownWritePacket(h.state, v)), 'cleanup begins once after known original successful writer checkpoints');
  h.check(!h.state.manualUiJournal || h.state.manualUiAuditClose?.state === 'completed' && h.state.manualUiAuditProof?.state === 'complete', 'cleanup retains completed original active-owner receipt and immutable terminal audit proof before disabling actors');
  h.save({ cleanupStarted: true, phase: 'cleanup-in-progress' });
  const actor = h.state.sessions.admin, approver = h.state.sessions.approver, bootstrap = h.state.sessions['bootstrap-provisioner'];
  const actors = { admin: actor, approver, direct: h.state.scopes.direct, approval: h.state.scopes.approval, foreign: h.state.scopes.foreign };
  h.check(Object.values(h.state.scopes).every(v => h.state.fixtures.some(f => f.type === 'workspaces' && f.id === v.wid && f.cid === v.cid && f.name.startsWith(h.state.testTag))), 'all cleanup workspaces belong to this exact fresh M7 fixture journal');
  // This restore is normally already complete after the HTTP flow. If a known
  // checkpoint explicitly retained approval mode, only its original mode is
  // eligible; it is never an arbitrary current registry edit.
  if (h.state.c2ModeChanged && !h.state.c2ModeRestored) await restoreClusterMode(h, actor, actors.approval);
  const readonly = h.state.readonlyPreferenceSetup;
  if (readonly) {
    const query = new URLSearchParams({ clusterId: readonly.cid, workspaceId: readonly.wid, status: 'revoked', size: '100' });
    const currentBinding = rows(h.data(await h.request(actor, `/iam/users/${readonly.userId}/role-bindings?${query}`))).find(v => v.id === readonly.bindingId);
    h.check(currentBinding?.role_id === readonly.roleId && currentBinding.status === 'revoked', 'temporary preference grant restore uses actual current original binding revision');
    const binding = h.data(await h.request(actor, `/iam/users/${readonly.userId}/role-bindings/${readonly.bindingId}/restore`, 'POST', { revision: currentBinding.revision, confirmed: true, confirm_name: readonly.roleName }));
    h.check(binding.status === 'active', 'exact known setup-only binding permits owner to soft remove its own read-only preference');
  }
  for (const fixture of h.state.fixtures.filter(v => v.type === 'preferences')) {
    const owner = h.state.sessions[fixture.actorLabel]; h.check(owner, 'preference cleanup uses original captured owner session');
    const current = h.data(await h.request(owner, `/notifications/preferences/${fixture.id}`));
    h.check(current.userId === owner.user.id && current.clusterId === fixture.cid && current.workspaceId === fixture.wid && current.name === fixture.name, 'owner preference cleanup confirms exact source journal identity');
    if (current.status !== 'deleted') await h.request(owner, `/notifications/preferences/${current.id}`, 'DELETE', confirmation(current));
    archived.push({ type: fixture.type, id: fixture.id });
  }
  // Disable delivery sources before recycling their native subjects. Immutable
  // event/audit/export/attempt history is retained without delete endpoints.
  for (const type of ['subscriptions', 'channels']) for (const fixture of h.state.fixtures.filter(v => v.type === type)) {
    const area = { cid: fixture.cid, wid: fixture.wid }, current = await eventRead(h, actor, area, `${type}/${fixture.id}`);
    h.check(current.name === fixture.name && current.clusterId === fixture.cid && current.workspaceId === fixture.wid, 'event cleanup confirms exact captured metadata scope');
    if (current.status !== 'deleted') await eventWrite(h, actor, approver, area, `${type}/${fixture.id}`, 'DELETE', confirmation(current), type === 'channels' ? 'event.channel.delete' : 'event.subscription.delete', false);
    archived.push({ type, id: fixture.id });
  }
  for (const fixture of h.state.fixtures.filter(v => v.type === 'entity_annotations')) {
    const current = h.data(await h.request(actor, scope(fixture.cid, fixture.wid, `entity-annotations/${fixture.entityType}/${fixture.id}`)));
    if (current.status !== 'deleted') await h.request(actor, scope(fixture.cid, fixture.wid, `entity-annotations/${fixture.entityType}/${fixture.id}`), 'DELETE', { revision: current.revision, confirmed: true, confirm_name: fixture.name });
    archived.push({ type: fixture.type, id: fixture.id });
  }
  const types = ['services', 'routes', 'plugins', 'consumers', 'upstreams', 'certificates', 'ca_certificates', 'snis'];
  for (const type of types) for (const fixture of h.state.fixtures.filter(v => v.type === type)) {
    const current = entity(h.data(await h.request(actor, scope(fixture.cid, fixture.wid, `entities/${type}/${fixture.id}`))));
    h.check(current.id === fixture.id && (!current.name || current.name === fixture.name), 'native recycling only uses exact captured M7 root identity');
    const result = h.data(await h.request(actor, scope(fixture.cid, fixture.wid, `entities/${type}/${fixture.id}`), 'DELETE', { confirmed: true, confirm_name: current.name ?? current.username ?? current.id }));
    h.check(result.entryId && result.state === 'deleted', 'native cleanup archives complete original object graph in recycle bin');
    archived.push({ type, id: fixture.id, recycleEntryId: result.entryId });
  }
  // Archive scoped IAM metadata while its own workspace is still active.
  for (const fixture of h.state.fixtures.filter(v => v.type === 'roles' && v.id !== h.state.accounts.find(v => v.label === 'admin').role.id)) {
    const current = h.data(await h.request(actor, `/iam/roles/${fixture.id}`));
    h.check(current.name === fixture.name && current.code.startsWith(h.state.testTag), 'role cleanup is bounded to fresh M7 role identity');
    if (current.status !== 'deleted') await h.request(actor, `/iam/roles/${current.id}`, 'DELETE', confirmation(current));
    archived.push({ type: fixture.type, id: fixture.id });
  }
  for (const fixture of h.state.fixtures.filter(v => v.type === 'users' && v.id !== actor.user.id)) {
    const current = h.data(await h.request(actor, `/iam/users/${fixture.id}`));
    h.check(current.username === fixture.name && current.username.startsWith(h.state.testTag), 'account cleanup cannot select another milestone or production account');
    if (current.status !== 'deleted') await h.request(actor, `/iam/users/${current.id}`, 'DELETE', { revision: current.revision, confirmed: true, confirm_name: current.username });
    archived.push({ type: fixture.type, id: fixture.id });
  }
  for (const fixture of h.state.fixtures.filter(v => v.type === 'workspaces')) {
    const current = h.data(await h.request(actor, `/clusters/${fixture.cid}/workspaces/${fixture.id}`));
    h.check(current.code.startsWith(h.state.testTag) && current.name === fixture.name && !current.is_default, 'workspace soft cleanup confirms fresh nondefault exact identity');
    await h.request(actor, `/clusters/${fixture.cid}/workspaces/${fixture.id}`, 'DELETE', confirmation(current)); archived.push({ type: fixture.type, id: fixture.id });
  }
  const adminAccount = h.state.accounts.find(v => v.label === 'admin');
  const currentAdmin = h.data(await h.request(bootstrap, `/iam/users/${actor.user.id}`));
  await h.request(bootstrap, `/iam/users/${currentAdmin.id}`, 'DELETE', { revision: currentAdmin.revision, confirmed: true, confirm_name: currentAdmin.username });
  const currentRole = h.data(await h.request(bootstrap, `/iam/roles/${adminAccount.role.id}`));
  await h.request(bootstrap, `/iam/roles/${currentRole.id}`, 'DELETE', confirmation(currentRole));
  const coverage = await auditAllWritesCoverage(h, { ...actors, admin: bootstrap });
  h.state.cleanup = { archived, auditWriteCoverage: coverage, businessCompleted: true }; h.save({ phase: 'cleanup-complete' });
  h.public = { scope: 'BFF-soft-cleanup-and-terminal-audit', archived, auditWriteCoverage: coverage, nativeTransportWritesOutsideBff: 0, immutableAuditEventHistoryRetained: true, productionActorsAndClustersRetained: true, privateReferenceRetained: true };
} catch (error) { failure = error; }
process.exitCode = h.finish(failure, 'artifacts/M7/security-cleanup.json', 'cleanup-complete');
