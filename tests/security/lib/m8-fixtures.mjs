import { randomUUID } from 'node:crypto';
import { M8_CLUSTERS, entity, rows, scope, strongPassword } from './m8-harness.mjs';

export const wsGrant = (cid, wid, module, action, scopeType = 'workspace', values = [wid]) => ({ module, action, scope_type: scopeType, cluster_id: cid, workspace_id: wid, scope_values: values });
export async function role(h, admin, label, permissions, cid = null, wid = null) {
  const value = h.data(await h.request(admin, '/iam/roles', 'POST', { code: `${h.state.testTag}-${label}`, name: `${h.state.testTag} ${label}`, description: 'M8 isolated acceptance fixture', cluster_id: cid, workspace_id: wid }));
  const result = h.data(await h.request(admin, `/iam/roles/${value.id}/permissions`, 'PUT', { revision: value.revision, permissions }));
  Object.assign(value, { revision: result.revision }); h.state.fixtures.push({ type: 'roles', id: value.id, name: value.name, cid, wid }); h.save(); return value;
}
export async function account(h, admin, label, assignedRole, cid = null, wid = null) {
  const username = `${h.state.testTag}-${label}`, password = strongPassword(); h.remember({ password }); h.save();
  const user = h.data(await h.request(admin, '/iam/users', 'POST', { username, password, display_name: username }));
  const binding = h.data(await h.request(admin, `/iam/users/${user.id}/role-bindings`, 'POST', { role_id: assignedRole.id, cluster_id: cid, workspace_id: wid }));
  const entry = { label, userId: user.id, username, password, role: assignedRole, binding, cid, wid }; h.state.accounts.push(entry); h.state.fixtures.push({ type: 'users', id: user.id, name: username }); h.save();
  let session = await h.login(label, username, password);
  if (user.force_password_change || session.user.force_password_change || session.user.forcePasswordChange) {
    const next = strongPassword(), current = h.data(await h.request(session, '/auth/me')).user;
    await h.request(session, '/auth/me/password', 'POST', { current_password: password, new_password: next, revision: current.revision, confirmed: true });
    entry.password = next; h.save(); session = await h.login(label, username, next);
  }
  h.check(session.user.id === user.id, 'new named actor has exact fresh M8 user identity', { label }); return session;
}
export async function createWorkspace(h, admin, cid, label) {
  const value = h.data(await h.request(admin, `/clusters/${cid}/workspaces`, 'POST', { code: `${h.state.testTag}-${label}`, name: `${h.state.testTag} ${label}`, description: 'M8 isolated acceptance workspace' }));
  h.state.fixtures.push({ type: 'workspaces', id: value.id, name: value.name, cid, wid: value.id }); h.save(); return value;
}
export async function bootstrapM8(h) {
  const bootstrap = await h.login('bootstrap-provisioner', process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', process.env.BOOTSTRAP_ADMIN_PASSWORD);
  const catalog = h.data(await h.request(bootstrap, '/iam/permissions/catalog'));
  h.check(Array.isArray(catalog.modules) && Array.isArray(catalog.actions) && catalog.actions.length === 4, 'live permission catalog freezes four operation dimensions');
  const permissions = catalog.modules.flatMap(module => catalog.actions.map(action => ({ module, action, scope_type: 'global', cluster_id: null, workspace_id: null, scope_values: [] })));
  const adminRole = await role(h, bootstrap, 'global-admin', permissions), admin = await account(h, bootstrap, 'admin', adminRole);
  const clusters = rows(h.data(await h.request(admin, '/clusters'))), direct = clusters.find(v => v.id === M8_CLUSTERS.direct), approval = clusters.find(v => v.id === M8_CLUSTERS.approval);
  h.check(direct?.execution_mode === 'direct' && approval && /^1\.5\.\d+$/.test(direct.version) && /^1\.5\.\d+$/.test(approval.version), 'canonical real Kong1.5 clusters are present and C1 is direct');
  h.state.originalClusterModes = { [direct.id]: { mode: direct.execution_mode, revision: direct.revision }, [approval.id]: { mode: approval.execution_mode, revision: approval.revision } }; h.save();
  const directWs = await createWorkspace(h, admin, direct.id, 'direct'), approvalWs = await createWorkspace(h, admin, approval.id, 'approval'), foreignWs = await createWorkspace(h, admin, direct.id, 'foreign');
  const c1 = { cid: direct.id, wid: directWs.id }, c2 = { cid: approval.id, wid: approvalWs.id }, foreign = { cid: direct.id, wid: foreignWs.id };
  const approverGrants = ['snapshots', 'gitops', 'workflows', 'services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis', 'secrets', 'recycle-bin'].flatMap(module => ['read', 'write', 'delete', 'approve'].map(action => wsGrant(c2.cid, c2.wid, module, action)));
  const approverRole = await role(h, admin, 'approver', approverGrants, c2.cid, c2.wid), approver = await account(h, admin, 'approver', approverRole, c2.cid, c2.wid);
  const readPermissions = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis', 'snapshots', 'gitops', 'audit', 'workflows', 'overview'].map(module => wsGrant(c1.cid, c1.wid, module, 'read'));
  const readonlyRole = await role(h, admin, 'read-only', readPermissions, c1.cid, c1.wid), readonly = await account(h, admin, 'read-only', readonlyRole, c1.cid, c1.wid);
  const ownerPermissions = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis', 'snapshots', 'gitops', 'workflows', 'secrets', 'recycle-bin', 'audit'].flatMap(module => ['read', 'write', 'delete'].map(action => wsGrant(c1.cid, c1.wid, module, action)));
  const ownerRole = await role(h, admin, 'configuration-owner', ownerPermissions, c1.cid, c1.wid), owner = await account(h, admin, 'owner', ownerRole, c1.cid, c1.wid);
  const other = await account(h, admin, 'other-owner', ownerRole, c1.cid, c1.wid);
  h.state.scopes = { direct: c1, approval: c2, foreign }; h.save();
  return { admin, bootstrap, approver, readonly, owner, other, direct: c1, approval: c2, foreign };
}
export async function setApprovalMode(h, admin, c2) {
  const current = rows(h.data(await h.request(admin, '/clusters'))).find(v => v.id === c2.cid);
  h.check(current && current.execution_mode === h.state.originalClusterModes[c2.cid].mode, 'approval mode change starts from durable original mode');
  if (current.execution_mode !== 'approval') {
    const changed = h.data(await h.request(admin, `/clusters/${c2.cid}`, 'PATCH', { revision: current.revision, execution_mode: 'approval' }));
    h.check(changed.execution_mode === 'approval', 'exact canonical C2 mode alone is changed through BFF'); h.state.c2ModeChanged = true; h.save();
  }
}
export async function restoreClusterMode(h, admin, c2) {
  if (!h.state.c2ModeChanged) return;
  const current = rows(h.data(await h.request(admin, '/clusters'))).find(v => v.id === c2.cid), original = h.state.originalClusterModes[c2.cid];
  h.check(current?.execution_mode === 'approval', 'C2 restore checks current mode and actual revision');
  const changed = h.data(await h.request(admin, `/clusters/${c2.cid}`, 'PATCH', { revision: current.revision, execution_mode: original.mode }));
  h.check(changed.execution_mode === original.mode, 'canonical C2 original mode restored through BFF'); h.state.c2ModeRestored = true; h.save();
}
export async function nativeCreate(h, actor, area, type, body) {
  const value = entity(h.data(await h.request(actor, scope(area.cid, area.wid, `entities/${type}`), 'POST', body)));
  h.check(typeof value?.id === 'string', 'native create returns durable exact object identity', { type });
  h.state.fixtures.push({ type, id: value.id, name: value.name ?? value.id, ...area }); h.save(); return value;
}
export const newKey = () => randomUUID();
