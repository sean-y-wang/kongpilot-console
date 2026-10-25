import { randomUUID } from 'node:crypto';
import { entity, scope, sha256 } from './m8-harness.mjs';
import { configurationWrite, assertConfigurationReceipt } from './m8-configuration-acceptance.mjs';

const uuid = value => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);
const identity = actor => ({ actorId: actor.user.id, sessionId: actor.sid });

function context(h, actors) {
  const { admin, owner, other } = actors, readonly = h.state.sessions?.['read-only'];
  const area = h.state.scopes?.direct, approval = h.state.scopes?.approval, foreign = h.state.scopes?.foreign, f = h.state.nativeFixture, b = h.state.baseline;
  h.check(h.state.version === 1 && h.state.milestone === 'M8' && typeof h.state.testTag === 'string'
    && [area, approval, foreign].every(value => uuid(value?.cid) && uuid(value?.wid))
    && area.cid === foreign.cid && area.wid !== foreign.wid && area.cid !== approval.cid
    && f?.area?.cid === area.cid && f.area.wid === area.wid && uuid(f.service?.id) && uuid(b?.snapshotId), 'M8 RBAC uses only its original typed native fixture and three exact scopes');
  h.check([admin, owner, other, readonly].every(actor => uuid(actor?.user?.id) && uuid(actor?.sid) && typeof actor.cookie === 'string' && actor.cookie.length > 0)
    && new Set([admin, owner, other, readonly].map(actor => actor.user.id)).size === 4
    && admin.label === 'admin' && owner.label === 'owner' && other.label === 'other-owner' && readonly.label === 'read-only'
    && h.state.sessions.admin?.sid === admin.sid && h.state.sessions.owner?.sid === owner.sid && h.state.sessions['other-owner']?.sid === other.sid,
  'M8 RBAC uses four distinct current named actors and their original real sessions');
  const account = h.state.accounts.find(value => value.label === 'owner' && value.userId === owner.user.id);
  h.check(account && account.username === owner.user.username && uuid(account.binding?.id) && uuid(account.role?.id)
    && account.cid === area.cid && account.wid === area.wid, 'M8 original owner account and scoped role binding are exact');
  return { admin, owner, other, readonly, area, approval, foreign, f, b, account };
}
function start(h, c) {
  h.assertWritable();
  h.check(!h.state.rbacJournal, 'M8 RBAC original journal cannot be replayed');
  const journal = { version: 1, testTag: h.state.testTag, phase: 'stable-running', inFlight: null, operations: [], denied: 0,
    originalIdentities: Object.fromEntries(['admin', 'owner', 'other', 'readonly'].map(name => [name, identity(c[name])])),
    originalScope: { ...c.area }, originalBindingId: c.account.binding.id, originalRoleId: c.account.role.id,
    identityPlan: { phase: 'not-started', action: 'revoke-and-restore-original-binding-then-normal-logout-login', after: ['direct-transfer', 'approval-transfer', 'actual-deck'],
      oldJobUse: 'safe-receipt-only; deny-original-job-deck-read-session; no-execute-or-decrypt-request' } };
  h.state.rbacJournal = journal; h.save(); return journal;
}
function prepare(h, j, actor, name, path, method, body) {
  h.assertWritable(); h.check(j.inFlight === null && !j.phase.startsWith('stopped'), 'M8 RBAC original unresolved operation prevents any further request');
  const operation = { index: j.operations.length, name, path, method, ...(actor ? identity(actor) : { actorId: null, sessionId: null }),
    idempotencyKey: ['GET', 'HEAD'].includes(method) ? null : randomUUID(), bodySha256: sha256(body === undefined ? 'null' : JSON.stringify(body)), state: 'prepared' };
  j.operations.push(operation); j.inFlight = operation.index; h.save(); return operation;
}
function observed(h, j, operation, result) {
  Object.assign(operation, { state: 'response_observed', status: result.status, requestId: result.requestId }); j.inFlight = null; h.save();
}
function stop(h, j) {
  if (j.inFlight !== null) j.operations[j.inFlight].state = 'response_unknown';
  j.phase = 'stopped-original-retained'; h.save({ phase: 'stopped-rbac-original-retained' });
  const error = new Error('M8_RBAC_ORIGINAL_REQUEST_STOP_NO_REPLAY'); error.safeEvidenceMessage = true; return error;
}
async function request(h, j, actor, name, path, method = 'GET', body, status = 200, { code, renew = true } = {}) {
  const operation = prepare(h, j, actor, name, path, method, body);
  const result = await h.request(actor, path, method, body, { expected: [status], ...(operation.idempotencyKey ? { key: operation.idempotencyKey } : {}), renew });
  h.check(result.status === status && uuid(result.requestId), 'M8 RBAC response has its exact expected status and original server request ID');
  if (status >= 400) {
    h.check(result.payload?.success !== true && result.payload?.data === undefined && typeof result.payload?.error?.code === 'string'
      && (!code || result.payload.error.code === code), 'M8 RBAC denial is a genuine exact endpoint denial, never a successful envelope');
    j.denied++;
  }
  observed(h, j, operation, result); return status >= 400 ? result : h.data(result);
}
async function currentSid(h, j, actor, name, expectedSid, excludedSid) {
  h.check(actor.sid === expectedSid && uuid(expectedSid), 'M8 RBAC retains the actual current actor SID');
  const me = await request(h, j, actor, `${name}-current-user`, '/auth/me');
  h.check(me.user?.id === actor.user.id && me.user.username === actor.user.username, 'M8 public current user is the exact named actor');
  const page = await request(h, j, actor, `${name}-current-session`, '/auth/me/sessions?size=100');
  h.check(Array.isArray(page.items) && page.items.length <= 100 && page.nextCursor === null && page.total === null
    && page.items.filter(row => row.current === true).length === 1 && page.items.some(row => row.id === expectedSid && row.current === true)
    && (!excludedSid || !page.items.some(row => row.id === excludedSid)), 'M8 public active-session page independently proves the current real SID');
}
function safeReceipt(h, receipt, c, original) {
  assertConfigurationReceipt(h, receipt, { actor: c.owner, area: c.area, key: original.idempotencyKey, jobId: original.jobId, kind: original.kind });
  const raw = JSON.stringify(receipt);
  h.check(receipt.state === 'succeeded' && receipt.executionCompleted === true && receipt.capabilities?.download === false
    && !/"(?:input_secret|payload_ciphertext|wrapped_key_secret|tokenSecret|yaml|manifest|document)"\s*:/.test(raw)
    && !(h.state.secrets ?? []).filter(value => typeof value === 'string' && value.length >= 8).some(value => raw.includes(value)),
  'original job projection contains only the safe durable receipt and no reusable secret or native input');
}
async function ownedWrite(h, j, c, name, path, body, kind) {
  const operation = prepare(h, j, c.owner, name, scope(c.area.cid, c.area.wid, path), 'POST', body), first = h.state.requests.length;
  const receipt = await configurationWrite(h, c.owner, c.area, path, body, { kind, key: operation.idempotencyKey });
  const packets = h.state.requests.slice(first).filter(packet => packet.key === receipt.idempotencyKey);
  h.check(packets.length === 1 && packets[0].method === 'POST' && packets[0].actorId === c.owner.user.id && packets[0].sessionId === c.owner.sid
    && packets[0].clusterId === c.area.cid && packets[0].workspaceId === c.area.wid && packets[0].bodySha256 === operation.bodySha256
    && packets[0].state === 'response_observed' && packets[0].status >= 200 && packets[0].status < 300 && uuid(packets[0].requestId),
  'owner metadata job retains exactly one original packet with its real actor, SID and unchanged private body');
  observed(h, j, operation, { status: packets[0].status, requestId: packets[0].requestId }); return receipt;
}
async function stable(h, j, c) {
  await currentSid(h, j, c.owner, 'original-owner', j.originalIdentities.owner.sessionId);
  await request(h, j, c.readonly, 'read-only-capture-denied', scope(c.area.cid, c.area.wid, 'snapshots'), 'POST', { scope: 'workspace', name: `${h.state.testTag} forbidden capture` }, 403);
  await request(h, j, c.readonly, 'read-only-native-write-denied', scope(c.area.cid, c.area.wid, `entities/services/${c.f.service.id}`), 'PATCH', { retries: c.f.service.retries ?? 0 }, 403);
  await request(h, j, c.readonly, 'read-only-deployment-secrets-denied', scope(c.area.cid, c.area.wid, `snapshots/${c.b.snapshotId}/export`), 'POST',
    { mode: 'deployment', confirmed: true, confirm_name: c.b.name }, 403);
  const credentialId = c.f.credentials?.['key-auth']?.id;
  h.check(uuid(credentialId) && uuid(c.f.consumer?.id), 'read-only secret test uses the original typed Consumer credential');
  await request(h, j, c.readonly, 'read-only-native-secret-reveal-denied', scope(c.area.cid, c.area.wid, `consumers/${c.f.consumer.id}/credentials/key-auth/${credentialId}`, { reveal: 'true' }), 'GET', undefined, 403);
  for (const [name, area] of [['cross-cluster', c.approval], ['cross-workspace', c.foreign]]) {
    await request(h, j, c.owner, `${name}-native-read-denied`, scope(area.cid, area.wid, 'entities/services', { size: 2 }), 'GET', undefined, 403);
    await request(h, j, c.owner, `${name}-snapshot-id-hidden`, scope(area.cid, area.wid, `snapshots/${c.b.snapshotId}`), 'GET', undefined, 404, { code: 'SNAPSHOT_NOT_FOUND' });
  }
  await request(h, j, c.owner, 'native-service-id-is-not-snapshot-id', scope(c.area.cid, c.area.wid, `snapshots/${c.f.service.id}`), 'GET', undefined, 404, { code: 'SNAPSHOT_NOT_FOUND' });
  const name = `${h.state.testTag} owner RBAC proof`, capture = await ownedWrite(h, j, c, 'owner-capture', 'snapshots', { scope: 'workspace', name }, 'capture');
  h.check(uuid(capture.snapshotId), 'owner successful job has its own exact sealed snapshot');
  const exported = await ownedWrite(h, j, c, 'owner-review-export', `snapshots/${capture.snapshotId}/export`, { mode: 'review' }, 'export');
  h.check(uuid(exported.exportId) && Number.isInteger(exported.exportRevision) && exported.capabilities?.download === true, 'owner review export has one genuine current artifact revision');
  j.resources = { capture, exported, snapshotName: name }; h.state.fixtures.push({ ...c.area, type: 'config_snapshots', id: capture.snapshotId, name }); h.save();
  const detail = entity(await request(h, j, c.owner, 'owner-job-detail', scope(c.area.cid, c.area.wid, `configuration/jobs/${capture.jobId}`)));
  safeReceipt(h, detail, c, capture);
  await request(h, j, c.other, 'same-workspace-other-job-detail-denied', scope(c.area.cid, c.area.wid, `configuration/jobs/${capture.jobId}`), 'GET', undefined, 403, { code: 'CONFIGURATION_JOB_ACCESS_DENIED' });
  await request(h, j, c.other, 'same-workspace-other-original-key-hidden', scope(c.area.cid, c.area.wid, `configuration/jobs/by-key/${capture.idempotencyKey}`), 'GET', undefined, 404, { code: 'CONFIGURATION_RECEIPT_NOT_FOUND' });
  await request(h, j, c.other, 'same-workspace-other-export-hidden', scope(c.area.cid, c.area.wid, `configuration/exports/${exported.exportId}/download`), 'POST', { revision: exported.exportRevision }, 404, { code: 'CONFIGURATION_EXPORT_NOT_FOUND' });
  await request(h, j, c.owner, 'service-id-is-not-job-id', scope(c.area.cid, c.area.wid, `configuration/jobs/${c.f.service.id}`), 'GET', undefined, 403, { code: 'CONFIGURATION_JOB_ACCESS_DENIED' });
  j.phase = 'stable-complete'; j.stableCompleted = true; h.save();
  return { complete: false, stableCompleted: true, readOnlyWritesDenied: true, deploymentSecretsDenied: true, crossScopeDenied: true, typedIdsRejected: true,
    sameWorkspaceOwnerOnlyJobs: true, sameWorkspaceOwnerOnlyExports: true, identityChanges: 0, deniedCases: j.denied };
}
/** May run before decK; this stage changes no account, role or session. */
export async function m8RbacStableAcceptance(h, actors) {
  const c = context(h, actors), j = start(h, c);
  try { const result = await stable(h, j, c); h.public ??= {}; h.public.rbacStable = result; h.save(); return result; }
  catch { throw stop(h, j); }
}
function executionsComplete(h) {
  h.check(h.state.directTransfer && h.state.approvalTransfer?.nativeSteps === 17 && h.state.deckAcceptance?.actualProxyCredentialKinds === 6,
    'M8 role/session changes occur only after original direct, approval and actual decK execution and authentication');
  h.assertWritable();
}
async function currentBinding(h, j, c, status) {
  const query = new URLSearchParams({ clusterId: c.area.cid, workspaceId: c.area.wid, status, size: '100' });
  const page = await request(h, j, c.admin, `owner-original-binding-${status}`, `/iam/users/${c.owner.user.id}/role-bindings?${query}`);
  h.check(Array.isArray(page.items) && page.items.length <= 100 && page.nextCursor === null && page.total === null, 'original scoped role-binding query is bounded and terminal');
  const matches = page.items.filter(row => row.id === j.originalBindingId);
  h.check(matches.length === 1 && (status !== 'active' || page.items.length === 1), 'only the exact original owner binding is selected without broad role changes');
  const row = matches[0];
  h.check(row.user_id === c.owner.user.id && row.role_id === j.originalRoleId && row.cluster_id === c.area.cid && row.workspace_id === c.area.wid
    && row.status === status && Number.isInteger(row.revision) && row.revision > 0 && row.role_name === c.account.role.name, 'original binding current scope, role, name and revision are exact');
  return row;
}
function bindingResult(h, c, j, row, expected, previousRevision) {
  h.check(row.id === j.originalBindingId && row.user_id === c.owner.user.id && row.role_id === j.originalRoleId && row.cluster_id === c.area.cid && row.workspace_id === c.area.wid
    && row.status === expected && row.revision === previousRevision + 1 && row.role_name === c.account.role.name, 'binding mutation acknowledges only the original scoped grant and next current revision');
  c.account.binding = row; h.save(); return row;
}
/** Full identity checks are deliberately last. A known stable stage can be
 * continued once; any prepared/unknown/failed original operation stops. */
export async function m8RbacAcceptance(h, actors) {
  executionsComplete(h); let c = context(h, actors), j = h.state.rbacJournal;
  if (!j) { await m8RbacStableAcceptance(h, actors); j = h.state.rbacJournal; }
  h.check(j.phase === 'stable-complete' && j.inFlight === null && j.stableCompleted === true && !j.identityCompleted
    && j.testTag === h.state.testTag && j.originalIdentities.owner.actorId === c.owner.user.id && j.originalIdentities.owner.sessionId === c.owner.sid
    && j.originalScope.cid === c.area.cid && j.originalScope.wid === c.area.wid && j.identityPlan.phase === 'not-started', 'only the exact completed stable stage may begin the original identity tail once');
  try {
    j.phase = 'identity-running'; j.identityPlan.phase = 'prepared'; j.identityPlan.originalOwnerSid = c.owner.sid; h.save();
    await currentSid(h, j, c.owner, 'pre-revoke-owner', c.owner.sid);
    const binding = await currentBinding(h, j, c, 'active'); j.identityPlan.originalBinding = structuredClone(binding); h.save();
    const path = `/iam/users/${c.owner.user.id}/role-bindings/${binding.id}`;
    const revoked = bindingResult(h, c, j, await request(h, j, c.admin, 'revoke-original-owner-binding', path, 'DELETE',
      { revision: binding.revision, confirmed: true, confirm_name: binding.role_name }), 'revoked', binding.revision);
    j.identityPlan.bindingRevoked = true; h.save();
    await currentSid(h, j, c.owner, 'revoked-owner-still-same-sid', j.identityPlan.originalOwnerSid);
    await request(h, j, c.owner, 'revoked-current-permission-job-denied', scope(c.area.cid, c.area.wid, `configuration/jobs/${j.resources.capture.jobId}`), 'GET', undefined, 403);
    await request(h, j, c.owner, 'revoked-current-permission-native-input-denied', scope(c.area.cid, c.area.wid, 'configuration/deck-sessions'), 'POST', { jobId: j.resources.capture.jobId, purpose: 'read' }, 403);
    const current = await currentBinding(h, j, c, 'revoked'); h.check(current.revision === revoked.revision, 'original revoked binding retains its actual current revision before restore');
    const restored = bindingResult(h, c, j, await request(h, j, c.admin, 'restore-original-owner-binding', `${path}/restore`, 'POST',
      { revision: current.revision, confirmed: true, confirm_name: current.role_name }, 201), 'active', current.revision);
    j.identityPlan.bindingRestored = true; j.identityPlan.restoredRevision = restored.revision; h.save();
    await currentSid(h, j, c.owner, 'restored-owner-original-sid', j.identityPlan.originalOwnerSid);
    const beforeLogout = entity(await request(h, j, c.owner, 'restored-original-safe-job', scope(c.area.cid, c.area.wid, `configuration/jobs/${j.resources.capture.jobId}`)));
    safeReceipt(h, beforeLogout, c, j.resources.capture);
    h.check(typeof c.account.password === 'string' && c.account.password.length > 0 && typeof h.login === 'function', 'normal owner login uses only the existing original M8 credential, never a fake SID');
    j.originalOwnerSession = structuredClone(c.owner); j.identityPlan.sessionBoundary = 'normal-logout-login-prepared'; h.save();
    const logout = await request(h, j, c.owner, 'normal-original-owner-logout', '/auth/logout', 'POST', {}, 201, { renew: false });
    h.check(logout.loggedOut === true, 'original owner normal logout is acknowledged');
    await request(h, j, j.originalOwnerSession, 'original-logged-out-session-rejected', '/auth/me', 'GET', undefined, 401, { renew: false });
    const operation = prepare(h, j, null, 'normal-existing-owner-login', '/auth/login', 'POST', { username: c.account.username, password: c.account.password });
    // login() owns its exact transport key and cookie/SID parsing. Do not
    // invent or inject that key or any SID into the production harness.
    operation.idempotencyKey = null; h.save(); const first = h.state.requests.length;
    const fresh = await h.login('owner', c.account.username, c.account.password);
    const logins = h.state.requests.slice(first).filter(packet => packet.path === '/api/v1/auth/login' && packet.method === 'POST');
    h.check(logins.length === 1 && logins[0].state === 'response_observed' && logins[0].status === 201 && uuid(logins[0].key) && uuid(logins[0].requestId)
      && logins[0].bodySha256 === operation.bodySha256 && fresh.user.id === j.originalIdentities.owner.actorId && fresh.user.username === c.account.username
      && uuid(fresh.sid) && fresh.sid !== j.identityPlan.originalOwnerSid && h.state.sessions.owner?.sid === fresh.sid,
    'normal login has one original credential packet and a genuinely new current SID for the same owner');
    operation.idempotencyKey = logins[0].key; observed(h, j, operation, { status: 201, requestId: logins[0].requestId });
    actors.owner = fresh; c = { ...c, owner: fresh }; j.identityPlan.newOwnerSid = fresh.sid; h.save();
    await currentSid(h, j, fresh, 'new-real-owner-session', fresh.sid, j.identityPlan.originalOwnerSid);
    const historical = await request(h, j, fresh, 'new-sid-original-safe-receipt', scope(c.area.cid, c.area.wid, `configuration/jobs/by-key/${j.resources.capture.idempotencyKey}`));
    safeReceipt(h, historical, c, j.resources.capture);
    await request(h, j, fresh, 'new-sid-cannot-reuse-old-native-input-job', scope(c.area.cid, c.area.wid, 'configuration/deck-sessions'), 'POST',
      { jobId: j.resources.capture.jobId, purpose: 'read' }, 403, { code: 'CONFIGURATION_JOB_ACCESS_DENIED' });
    j.phase = 'complete'; j.identityPlan.phase = 'complete'; j.identityCompleted = true; h.save();
    const result = { complete: true, stableCompleted: true, readOnlyWritesDenied: true, deploymentSecretsDenied: true, crossScopeDenied: true, typedIdsRejected: true,
      sameWorkspaceOwnerOnlyJobs: true, sameWorkspaceOwnerOnlyExports: true, currentPermissionRevocationDenied: true, originalBindingRestored: true,
      originalSidRetainedAcrossGrantChange: true, normalNewSidProved: true, oldJobSafeReceiptReadable: true, oldJobNativeReadSessionDenied: true,
      oldJobExecutionAttempted: false, fakeSidsUsed: 0, newAccountsCreated: 0, newWorkspacesCreated: 0, identityChanges: 4, deniedCases: j.denied,
      observedOperations: j.operations.filter(operation => operation.state === 'response_observed').length };
    h.state.rbacAcceptance = result; h.public ??= {}; h.public.rbacAcceptance = result; h.save(); return result;
  } catch { throw stop(h, j); }
}
