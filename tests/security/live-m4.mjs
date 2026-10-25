import { randomUUID } from 'node:crypto';
import { M4Harness, canonical, entity, rows, scope, strongPassword } from './lib/m4-harness.mjs';

// Do not run before the unified M4 deployment/005-migration handoff. All actors,
// grants, gateway objects and attack targets are disposable test-owned fixtures.
const h = new M4Harness();
let admin, c1, c2, pay, ops;
const nativeTypes = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis'];
const owned = {}, accounts = {};
function endpoint(cluster, workspace, type, value, extra = {}) { return scope(`/clusters/${cluster.id}/entities/${type}${value ? `/${typeof value === 'string' ? value : value.id}` : ''}`, workspace, extra); }
function g(module, action, scopeType = 'workspace', values = [pay.id], cluster = c1, workspace = pay) {
  return { module, action, scope_type: scopeType, ...(cluster ? { cluster_id: cluster.id } : {}), ...(workspace ? { workspace_id: workspace.id } : {}), scope_values: values };
}
function tagGrant(module, action, tags = ['team:pay'], workspace = pay) { return g(module, action, 'tag_group', tags, c1, workspace); }
function idGrant(module, action, type, id) { return g(module, action, 'entity', [{ entity_type: type, entity_id: id }]); }
function visibleContext() { return [g('clusters', 'read', 'global', [], c1, pay), g('workspaces', 'read')]; }
async function role(code, permissions, context = {}) {
  const created = h.ok(await h.request(admin, '/iam/roles', 'POST', { code: `${h.tag}-${code}`, name: `${h.tag}-${code}`, description: 'isolated M4 attack regression role', ...context }), 'A00', 'fixture role creation');
  const changed = h.ok(await h.request(admin, `/iam/roles/${created.id}/permissions`, 'PUT', { revision: created.revision, permissions }), 'A00', 'four-dimensional role permission assignment');
  return { ...created, ...(changed?.role ?? {}), permissions };
}
async function bindUser(user, value, context = {}) {
  return h.ok(await h.request(admin, `/iam/users/${user.id}/role-bindings`, 'POST', { role_id: value.id, ...context }), 'A00', 'explicit user role binding');
}
async function makeAccount(label, permissions, roleContext = {}, bindingContext = {}) {
  const password = strongPassword(); h.secrets.push(password);
  const user = h.ok(await h.request(admin, '/iam/users', 'POST', { username: `${h.tag}-${label}`, password, display_name: `M4 ${label}` }), 'A00', 'ordinary fixture account creation');
  // IAM global definitions are NULL/NULL. Ceilings are introduced by bindings,
  // never by rewriting the global definition or unioning independent dimensions.
  const groups = new Map();
  for (const permission of permissions) {
    const key = permission.scope_type === 'global' ? `global:${permission.cluster_id || ''}:${permission.workspace_id || ''}` : 'scoped';
    const group = groups.get(key) ?? { permissions: [], context: permission.scope_type === 'global' ? { ...(permission.cluster_id ? { cluster_id: permission.cluster_id } : {}), ...(permission.workspace_id ? { workspace_id: permission.workspace_id } : {}) } : bindingContext, global: permission.scope_type === 'global' };
    group.permissions.push(permission.scope_type === 'global' ? { ...permission, cluster_id: null, workspace_id: null } : permission); groups.set(key, group);
  }
  const roleBindings = [];
  for (const [index, group] of [...groups.values()].entries()) {
    const value = await role(`${label}${groups.size > 1 ? `-scope${index}` : ''}`, group.permissions, group.global ? {} : roleContext);
    roleBindings.push({ role: value, binding: await bindUser(user, value, group.context), global: group.global });
  }
  const primary = roleBindings.find(value => !value.global) ?? roleBindings[0];
  let session = await h.login(user.username, password);
  let currentPassword = password;
  if (user.force_password_change || session.user.forcePasswordChange || session.user.force_password_change) {
    currentPassword = strongPassword(); h.secrets.push(currentPassword);
    h.ok(await h.request(session, '/auth/me/password', 'POST', { current_password: password, new_password: currentPassword, revision: user.revision, confirmed: true }), 'A06', 'mandatory initial password rotation');
    session = await h.login(user.username, currentPassword);
  }
  h.users.push({ id: user.id, username: user.username, password: currentPassword, label });
  const current = h.ok(await h.request(admin, `/iam/users/${user.id}`), 'A00', 'current public fixture user');
  accounts[label] = { user: current, session, password: currentPassword, role: primary.role, binding: primary.binding, roleBindings };
  return accounts[label];
}
async function verifyDeniedState(account, type, value, body, id, label, statuses = [403]) {
  const original = await h.detail(admin, c1, pay, type, value, id, { reveal: true });
  await h.reject(account.session, endpoint(c1, pay, type, value), 'PATCH', body, id, label, statuses);
  await h.unchanged(admin, c1, pay, type, value, original, id, 'denied operation leaves the original native object unchanged');
}
async function collect(account, cluster, workspace, type, tags, size = 2) {
  const found = [], cursors = []; let cursor;
  for (let page = 0; page < 40; page++) {
    const response = h.ok(await h.request(account.session, endpoint(cluster, workspace, type, undefined, { tags, size, cursor })), 'R12', 'server-side authorized cursor page');
    found.push(...rows(response)); if (response.nextCursor) cursors.push(response.nextCursor);
    cursor = response.nextCursor; if (!cursor) return { found, cursors };
  }
  throw new Error('R12: fixture traversal exceeded bounded native cursor pages');
}

try {
  h.check(process.env.M4_DEPLOYMENT_READY === 'true', 'GATE', 'explicit unified M4 deployment handoff is required before live writes');
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!password) throw new Error('bootstrap password required');
  admin = await h.login(process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', password);
  const clusters = rows(h.ok(await h.request(admin, '/clusters'), 'A00', 'registered cluster discovery'));
  c1 = clusters.find(cluster => cluster.labels?.includes('bootstrap') && cluster.execution_mode === 'direct');
  c2 = clusters.find(cluster => cluster.admin_url?.replace(/\/$/, '') === 'http://kong-secondary:8001' && cluster.execution_mode === 'direct');
  h.check(c1 && c2 && c1.id !== c2.id && c1.admin_url !== c2.admin_url, 'R04', 'two genuinely independent registered Kong gateways are available');
  for (const cluster of [c1, c2]) {
    const probe = h.ok(await h.request(admin, `/clusters/${cluster.id}/probe`, 'POST'), 'R04', 'BFF exact-source ACL allows capability probe');
    h.check(probe.version === '1.5.1', 'R04', 'both real gateways are Kong OSS 1.5.1');
  }
  async function workspace(cluster, code) {
    return h.ok(await h.request(admin, `/clusters/${cluster.id}/workspaces`, 'POST', { code: `${h.tag.replace(/-/g, '_')}_${code}`, name: `${h.tag}-${code}-${cluster.id.slice(0, 6)}` }), 'A00', 'isolated fixture workspace');
  }
  pay = await workspace(c1, 'pay'); ops = await workspace(c1, 'ops');
  const pay2 = await workspace(c2, 'pay');
  h.public = { clusterId: c1.id, secondaryClusterId: c2.id, payWorkspace: { id: pay.id, code: pay.code, name: pay.name }, opsWorkspace: { id: ops.id, code: ops.code, name: ops.name }, secondaryPayWorkspaceId: pay2.id };
  const sharedServiceId = randomUUID(), sharedRouteId = randomUUID();
  owned.service = await h.create(admin, c1, pay, 'services', { id: sharedServiceId, name: `${h.tag}-same-service`, host: 'echo-upstream', port: 8081, tags: [h.tag, 'team:pay'] });
  owned.secondaryService = await h.create(admin, c2, pay2, 'services', { id: sharedServiceId, name: owned.service.name, host: 'echo-upstream', port: 8081, retries: 2, tags: [h.tag, 'team:pay'] });
  h.check(owned.service.id === owned.secondaryService.id && owned.service.name === owned.secondaryService.name, 'R04', 'same native UUID and natural name exist in two distinct gateways');
  owned.route = await h.create(admin, c1, pay, 'routes', { id: sharedRouteId, name: `${h.tag}-same-route`, service: { id: owned.service.id }, paths: [`/m4/${h.tag}/pay`], protocols: ['http'], tags: [h.tag, 'team:pay'] });
  owned.secondaryRoute = await h.create(admin, c2, pay2, 'routes', { id: sharedRouteId, name: owned.route.name, service: { id: owned.secondaryService.id }, paths: [`/m4/${h.tag}/secondary`], protocols: ['http'], tags: [h.tag, 'team:pay'] });
  owned.sharedRoute = await h.create(admin, c1, pay, 'routes', { name: `${h.tag}-shared-route`, service: { id: owned.service.id }, paths: [`/m4/${h.tag}/shared`], protocols: ['http'], tags: [h.tag, 'team:shared'] });
  owned.untaggedRoute = await h.create(admin, c1, pay, 'routes', { name: `${h.tag}-child-without-business-tag`, service: { id: owned.service.id }, paths: [`/m4/${h.tag}/untagged`], protocols: ['http'], tags: [h.tag] });
  owned.privateService = await h.create(admin, c1, pay, 'services', { name: `${h.tag}-private-service`, host: 'echo-upstream', port: 8081, tags: [h.tag, 'team:ops'] });
  owned.privateRoute = await h.create(admin, c1, pay, 'routes', { name: `${h.tag}-private-route`, service: { id: owned.privateService.id }, paths: [`/m4/${h.tag}/private`], tags: [h.tag, 'team:ops'] });
  owned.opsService = await h.create(admin, c1, ops, 'services', { name: `${h.tag}-ops-service`, host: 'echo-upstream', port: 8081, tags: [h.tag, 'team:pay'] });
  owned.consumer = await h.create(admin, c1, pay, 'consumers', { id: sharedServiceId, username: `${h.tag}-typed-consumer`, tags: [h.tag, 'team:pay'] });
  owned.otherConsumer = await h.create(admin, c1, pay, 'consumers', { username: `${h.tag}-other-consumer`, tags: [h.tag, 'team:ops'] });
  owned.opsConsumer = await h.create(admin, c1, ops, 'consumers', { username: `${h.tag}-ops-consumer`, tags: [h.tag, 'team:pay'] });
  owned.upstream = await h.create(admin, c1, pay, 'upstreams', { name: `${h.tag}-upstream`, tags: [h.tag, 'team:pay'] });
  owned.otherUpstream = await h.create(admin, c1, pay, 'upstreams', { name: `${h.tag}-other-upstream`, tags: [h.tag, 'team:ops'] });
  owned.servicePlugin = await h.create(admin, c1, pay, 'plugins', { name: 'correlation-id', service: { id: owned.service.id }, enabled: false, config: { header_name: 'X-M4-ID' }, tags: [h.tag, 'team:pay'] });
  owned.routePlugin = await h.create(admin, c1, pay, 'plugins', { name: 'correlation-id', route: { id: owned.route.id }, enabled: false, config: { header_name: 'X-M4-Route-ID' }, tags: [h.tag, 'team:pay'] });
  owned.noTagPlugin = await h.create(admin, c1, pay, 'plugins', { name: 'request-size-limiting', route: { id: owned.untaggedRoute.id }, enabled: false, config: { allowed_payload_size: 1 }, tags: [h.tag] });
  owned.comboPlugin = await h.create(admin, c1, pay, 'plugins', { name: 'request-termination', service: { id: owned.service.id }, route: { id: owned.route.id }, consumer: { id: owned.otherConsumer.id }, enabled: false, config: { status_code: 480 }, tags: [h.tag, 'team:pay'] });
  const tlsFixture = h.certificateFixture();
  owned.certificate = await h.create(admin, c1, pay, 'certificates', { id: sharedServiceId, ...tlsFixture, tags: [h.tag, 'team:pay'] });
  owned.caCertificate = await h.create(admin, c1, pay, 'ca_certificates', { id: sharedServiceId, cert: tlsFixture.cert, tags: [h.tag, 'team:pay'] });
  owned.sni = await h.create(admin, c1, pay, 'snis', { name: `${h.tag}.invalid`, certificate: { id: owned.certificate.id }, tags: [h.tag, 'team:pay'] });
  h.public.fixtureIds = Object.fromEntries(Object.entries(owned).map(([name, value]) => [name, value.id]));

  const support = visibleContext();
  await makeAccount('ordinary', support);
  await makeAccount('global-reader', [g('clusters', 'read', 'global', [], c1, null), g('workspaces', 'read', 'global', [], c1, null), ...nativeTypes.map(type => g(type, 'read', 'global', [], c1, null))]);
  await makeAccount('pay-reader', [...support, ...nativeTypes.map(type => g(type, 'read'))]);
  await makeAccount('tag-reader', [...support, tagGrant('services', 'read', ['team:pay', 'team:shared']), tagGrant('routes', 'read', ['team:pay', 'team:shared'])]);
  await makeAccount('tag-writer', [...support, ...['services', 'routes', 'plugins'].flatMap(type => [tagGrant(type, 'read'), tagGrant(type, 'write')])]);
  await makeAccount('route-reader', [...support, idGrant('routes', 'read', 'routes', owned.route.id)]);
  await makeAccount('service-writer', [...support, idGrant('services', 'read', 'services', owned.service.id), idGrant('services', 'write', 'services', owned.service.id)]);
  await makeAccount('service-deleter', [...support, idGrant('services', 'read', 'services', owned.service.id), idGrant('services', 'delete', 'services', owned.service.id)]);
  await makeAccount('secret-reader', [...support, tagGrant('consumers', 'read'), tagGrant('secrets', 'read')]);
  await makeAccount('tuple-mix', [...support, g('services', 'read'), g('routes', 'write', 'workspace', [ops.id], c1, ops)]);
  await makeAccount('workspace-admin', [...support, ...nativeTypes.flatMap(type => ['read', 'write', 'delete'].map(action => g(type, action))), g('users', 'write'), g('roles', 'write'), g('teams', 'write')]);
  await makeAccount('victim', [g('clusters', 'read', 'global', [], c1, null), g('users', 'read', 'global', [], null, null)]);
  h.public.accounts = Object.fromEntries(Object.entries(accounts).map(([label, account]) => [label, { id: account.user.id, username: account.user.username, role: { id: account.role.id, name: account.role.name }, binding: { id: account.binding.id, revision: account.binding.revision } }]));

  // Genuine ordinary-authenticated versions of the two Konga attack mechanisms.
  const ordinary = accounts.ordinary, victim = accounts.victim;
  const profileBefore = h.ok(await h.request(ordinary.session, '/auth/me'), 'A02', 'ordinary identity before privilege mass-assignment');
  const profileRevision = ordinary.user.revision;
  const profilePayloads = [
    { admin: 'true', password: ordinary.password, password_confirmation: ordinary.password },
    { super_admin: true }, { superAdmin: true }, { SuperAdmin: 'true' }, { roles: [accounts['workspace-admin'].role.id] },
    { permissions: [{ module: '*', action: 'write', scope_type: 'global' }] }, { scope: 'global' }, { status: 'active', id: victim.user.id },
    { user: { admin: true, permissions: ['*'] } }, { constructor: { prototype: { superAdmin: true } } },
    Object.fromEntries([['__proto__', { superAdmin: true }]]),
  ];
  for (const payload of profilePayloads) await h.reject(ordinary.session, '/auth/me/profile', 'PATCH', { revision: profileRevision, ...payload }, 'A02/A03', 'self-profile rejects privileged/unknown/nested/prototype fields', [400, 403]);
  const profileAfter = h.ok(await h.request(ordinary.session, '/auth/me'), 'A02', 'ordinary identity after rejected mass-assignment');
  h.check(profileAfter.user.id === profileBefore.user.id && !profileAfter.user.superAdmin && !profileAfter.user.super_admin, 'A02', 'ordinary authenticated actor never becomes a platform administrator');
  await h.reject(ordinary.session, `/iam/users/${victim.user.id}/reset-password`, 'POST', { revision: victim.user.revision, new_password: strongPassword(), confirmed: true }, 'A04/CVE-2023-26987', 'ordinary user cannot reset another user password');
  await h.reject(ordinary.session, `/iam/users/${admin.user.id}/reset-password`, 'POST', { revision: admin.user.revision ?? 1, new_password: strongPassword(), confirmed: true }, 'A04/CVE-2023-26987', 'ordinary authenticated user cannot reset the actual protected bootstrap administrator password');
  await h.reject(ordinary.session, `/iam/users/${victim.user.id}/status`, 'POST', { revision: victim.user.revision, status: 'disabled', confirmed: true, confirm_name: victim.user.username }, 'A04', 'ordinary user cannot disable target account');
  h.ok(await h.request(victim.session, '/auth/me'), 'A04', 'denied password-reset attack leaves original victim session active');
  await h.login(victim.user.username, victim.password, 'A04');
  h.ok(await h.request(admin, '/auth/me'), 'A04', 'denied cross-user reset leaves the actual platform administrator session active');
  const repeatedOrdinary = await h.login(ordinary.user.username, ordinary.password, 'A02');
  await h.reject(repeatedOrdinary, endpoint(c1, pay, 'services', owned.service), 'PATCH', { retries: 2 }, 'A02', 'relogin after mass-assignment retains ordinary denial');
  await h.reject(ordinary.session, '/iam/users', 'GET', undefined, 'A04', 'ordinary account enumeration denied');
  await h.reject(ordinary.session, '/auth/me/password', 'POST', { new_password: strongPassword(), revision: profileRevision, confirmed: true }, 'A06', 'self-password change without current password rejected', [400, 401, 403]);
  await h.reject(ordinary.session, '/auth/me/password', 'POST', { current_password: ordinary.password, new_password: strongPassword(), revision: profileRevision, confirmed: true, userId: victim.user.id }, 'A06', 'self-password cannot select another target', [400, 403]);
  await h.reject(accounts['workspace-admin'].session, `/iam/users/${victim.user.id}/reset-password`, 'POST', { revision: victim.user.revision, new_password: strongPassword(), confirmed: true }, 'A07', 'workspace-scoped users.write cannot authorize a global password reset');
  await h.reject(accounts['workspace-admin'].session, '/iam/roles', 'POST', { code: `${h.tag}-escalation`, name: 'escalation' }, 'A07', 'workspace role write cannot create an unscoped platform role');
  await h.reject(ordinary.session, `/iam/users/${ordinary.user.id}/role-bindings`, 'POST', { role_id: accounts['workspace-admin'].role.id }, 'A08', 'ordinary user cannot assign a role to itself');
  await h.reject(admin, '/iam/users', 'POST', { username: `${h.tag}-mass-create`, password: strongPassword(), super_admin: true }, 'A03', 'even authorized user creation rejects an injected platform flag', [400]);

  // Keep each complete module/action/scope tuple intact; no dimension union.
  await verifyDeniedState(accounts['tuple-mix'], 'services', owned.service, { retries: 3 }, 'R02', 'services.read/pay plus routes.write/ops cannot grant services.write/pay');
  await verifyDeniedState(accounts['pay-reader'], 'services', owned.service, { retries: 3 }, 'R01', 'read-only cannot PATCH Service');
  const everyCore = { services: owned.service, routes: owned.route, consumers: owned.consumer, plugins: owned.servicePlugin, upstreams: owned.upstream, certificates: owned.certificate, ca_certificates: owned.caCertificate, snis: owned.sni };
  for (const [type, value] of Object.entries(everyCore)) {
    const publicRead = await h.request(accounts['pay-reader'].session, endpoint(c1, pay, type, value));
    h.ok(publicRead, 'R01/All8', `read-only can view its authorized ${type} entity`);
    h.check(!publicRead.text.includes(tlsFixture.key), 'S01/All8', `${type} public response contains no synthetic TLS private key`);
    await verifyDeniedState(accounts['pay-reader'], type, value, { tags: [h.tag, 'team:pay', 'forbidden-read-only-write'] }, 'R01/All8', `read-only ${type} write is denied before changing actual native configuration`);
    await h.reject(accounts['pay-reader'].session, endpoint(c1, pay, type, value), 'DELETE', { confirmed: true, confirm_name: value.name ?? value.username ?? value.id }, 'R01/All8', `read-only cannot archive/delete ${type}`);
    await h.reject(accounts['pay-reader'].session, endpoint(c1, ops, type, value), 'GET', undefined, 'R05/All8', `known ${type} entity cannot be read through another workspace`);
  }
  await h.reject(accounts['pay-reader'].session, endpoint(c1, pay, 'services'), 'POST', { name: `${h.tag}-forbidden-create`, host: 'echo-upstream', port: 8081 }, 'R01', 'read-only cannot create Service');
  await h.reject(accounts['pay-reader'].session, endpoint(c1, pay, 'services', owned.service), 'DELETE', { confirmed: true, confirm_name: owned.service.name }, 'R01', 'read-only cannot delete Service');
  await h.reject(accounts['service-writer'].session, endpoint(c1, pay, 'services', owned.service), 'DELETE', { confirmed: true, confirm_name: owned.service.name }, 'R03', 'write alone does not grant delete');
  await h.reject(accounts['service-writer'].session, endpoint(c1, pay, 'services', owned.service, { reveal: true }), 'GET', undefined, 'R03/I02', 'write/read does not grant independent secrets.read');
  for (const account of [accounts['pay-reader'], accounts['route-reader'], accounts['service-writer']]) {
    await h.reject(account.session, endpoint(c2, pay2, 'services', owned.secondaryService), 'GET', undefined, 'R04/R11', 'same-ID/same-name Service in distinct C2 remains unauthorized');
    await h.reject(account.session, endpoint(c2, pay2, 'routes', owned.secondaryRoute), 'PATCH', { regex_priority: 1 }, 'R04/R11', 'same-ID Route in distinct C2 cannot be mutated');
  }
  h.ok(await h.request(accounts['global-reader'].session, endpoint(c1, ops, 'services', owned.opsService)), 'R04', 'global C1 module grant reads another workspace inside C1');
  await h.reject(accounts['global-reader'].session, endpoint(c2, pay2, 'services', owned.secondaryService), 'GET', undefined, 'R04', 'global scope constrained to C1 does not authorize C2');
  for (const value of [owned.service.id, owned.service.name]) await h.reject(accounts['pay-reader'].session, endpoint(c1, ops, 'services', value), 'GET', undefined, 'R05', 'UUID and name aliases cannot bypass workspace membership');
  await h.reject(accounts['pay-reader'].session, `/clusters/${c1.id}/entities/services`, 'GET', undefined, 'R06', 'omitted workspace never broadens a pay-only grant');
  await h.reject(accounts['pay-reader'].session, endpoint(c1, randomUUID(), 'services'), 'GET', undefined, 'R06', 'unknown workspace denied');
  await h.reject(accounts['pay-reader'].session, `/clusters/${c1.id}/entities/services?workspaceId=${pay.id}&workspaceId=${ops.id}`, 'GET', undefined, 'R06', 'repeated workspace parameters rejected', [400, 403]);
  await h.reject(accounts['service-writer'].session, endpoint(c1, pay, 'consumers', owned.consumer), 'GET', undefined, 'R11', 'same UUID in another entity type does not match Service whitelist');
  for (const [type, value] of [['certificates', owned.certificate], ['ca_certificates', owned.caCertificate]]) await h.reject(accounts['service-writer'].session, endpoint(c1, pay, type, value), 'GET', undefined, 'R11/S01', 'the Service UUID whitelist cannot expose the same UUID TLS entity of another type');
  await h.reject(accounts['route-reader'].session, endpoint(c1, pay, 'routes', owned.sharedRoute), 'GET', undefined, 'R11', 'Route ID whitelist cannot read sibling Route');

  // Service/Route inheritance and every nonempty Plugin binding are checked.
  h.ok(await h.request(accounts['route-reader'].session, endpoint(c1, pay, 'services', owned.service)), 'I01', 'single Route entity read grants necessary real parent Service read');
  const routeWriteOnly = await makeAccount('route-write-only', [idGrant('routes', 'write', 'routes', owned.route.id)]);
  const routeOnlyClusters = h.ok(await h.request(routeWriteOnly.session, '/clusters'), 'I01/Context', 'Route write-only actor can discover its mandatory cluster context');
  h.check(rows(routeOnlyClusters).some(value => value.id === c1.id) && !rows(routeOnlyClusters).some(value => value.id === c2.id), 'I01/Context', 'context selector contains only the genuinely authorized cluster');
  h.ok(await h.request(routeWriteOnly.session, endpoint(c1, pay, 'services', owned.service)), 'I01', 'exact Route write authority grants necessary parent Service read');
  await h.reject(routeWriteOnly.session, endpoint(c1, pay, 'routes', owned.route), 'GET', undefined, 'I01', 'necessary parent Service read does not invent Route read authority');
  await verifyDeniedState(routeWriteOnly, 'services', owned.service, { retries: 4 }, 'I01', 'Route write authority never grants parent Service write');
  const pureServiceWriter = await makeAccount('service-pure-writer', [idGrant('services', 'write', 'services', owned.service.id)]);
  await h.reject(pureServiceWriter.session, endpoint(c1, pay, 'services', owned.service), 'GET', undefined, 'I03/WriteOnly', 'Service write-only inheritance never grants public Service read');
  h.ok(await h.request(pureServiceWriter.session, endpoint(c1, pay, 'routes', owned.route), 'PATCH', { regex_priority: 1 }), 'I03/WriteOnly', 'pure Service write authority can patch its existing child Route');
  h.ok(await h.request(pureServiceWriter.session, endpoint(c1, pay, 'plugins', owned.servicePlugin), 'PATCH', { enabled: false }), 'I03/WriteOnly', 'pure Service write authority can patch an existing Service-bound Plugin');
  h.ok(await h.request(pureServiceWriter.session, endpoint(c1, pay, 'plugins', owned.routePlugin), 'PATCH', { enabled: false }), 'I03/WriteOnly', 'pure Service write authority can patch an existing Route-bound Plugin through the actual parent chain');
  await verifyDeniedState(pureServiceWriter, 'plugins', owned.comboPlugin, { enabled: true }, 'I03/WriteOnly', 'pure Service write still denies a Plugin with an unauthorized Consumer parent');
  await verifyDeniedState(accounts['route-reader'], 'services', owned.service, { retries: 4 }, 'I01', 'Route read never grants parent Service write');
  await h.reject(accounts['route-reader'].session, endpoint(c1, pay, 'services', owned.privateService), 'GET', undefined, 'I01', 'Route inheritance cannot read unrelated Service');
  h.ok(await h.request(accounts['service-writer'].session, endpoint(c1, pay, 'routes', owned.route), 'PATCH', { regex_priority: 1 }), 'I03', 'Service entity write grants actual child Route write');
  h.ok(await h.request(accounts['service-writer'].session, endpoint(c1, pay, 'plugins', owned.servicePlugin), 'PATCH', { enabled: false }), 'I03', 'Service entity write grants its bound Plugin write');
  await verifyDeniedState(accounts['tag-writer'], 'routes', owned.untaggedRoute, { regex_priority: 2 }, 'I04/R08', 'tag-group inheritance still requires target child business-tag intersection');
  await verifyDeniedState(accounts['tag-writer'], 'plugins', owned.noTagPlugin, { enabled: true }, 'I04/R08', 'tag-group Service/Route authority cannot mutate untagged child Plugin');
  await verifyDeniedState(accounts['service-writer'], 'plugins', owned.comboPlugin, { enabled: true }, 'I05', 'all Plugin parents required: authorized Service cannot control unauthorized Consumer binding');
  await verifyDeniedState(accounts['service-writer'], 'plugins', owned.servicePlugin, { service: null }, 'I06', 'authorized bound Plugin cannot be changed into a global Plugin');
  await verifyDeniedState(accounts['tag-writer'], 'services', owned.service, { tags: [h.tag, 'team:ops'] }, 'R09', 'tag-group writer cannot remove the last authorized business tag');
  await verifyDeniedState(accounts['tag-writer'], 'services', owned.service, { tags: [h.tag, 'team:pay', `workspace:${ops.code}`] }, 'R09', 'ordinary PATCH cannot change reserved workspace', [400, 403]);

  for (const name of ['pre-function', 'post-function']) await h.reject(accounts['workspace-admin'].session, endpoint(c1, pay, 'plugins'), 'POST', { name, service: { id: owned.service.id }, enabled: false, config: { functions: ['return'] }, tags: [h.tag, 'team:pay'] }, 'P01', 'workspace administrator cannot install arbitrary Lua execution plugins');
  await h.reject(accounts['workspace-admin'].session, endpoint(c1, pay, 'plugins'), 'POST', { name: 'file-log', service: { id: owned.service.id }, enabled: false, config: { path: '/tmp/kongos-m4-synthetic.log' }, tags: [h.tag, 'team:pay'] }, 'P01/File', 'workspace administrator cannot install a plugin that appends arbitrary local files');

  // Paging includes each tag_group branch while excluding the other workspace.
  const tagServices = [];
  for (let index = 0; index < 6; index++) tagServices.push(await h.create(admin, c1, pay, 'services', { name: `${h.tag}-page-${index}`, host: 'echo-upstream', port: 8081, tags: [h.tag, index % 2 ? 'team:shared' : 'team:pay'] }));
  const filtered = await collect(accounts['tag-reader'], c1, pay, 'services', h.tag);
  h.check(tagServices.every(value => filtered.found.some(item => item.id === value.id)) && !filtered.found.some(value => [owned.privateService.id, owned.opsService.id].includes(value.id)), 'R07/R12', '(pay workspace) AND (team:pay OR team:shared) survives second and later native pages');
  h.check(new Set(filtered.found.map(value => value.id)).size === filtered.found.length, 'R12', 'authorized paging has no duplicate IDs');
  await h.reject(accounts['tag-reader'].session, endpoint(c1, pay, 'services', owned.privateService), 'GET', undefined, 'R08', 'tag-group singleton read without authorized tag intersection denied');
  const indexed = h.ok(await h.request(accounts['tag-reader'].session, endpoint(c1, pay, 'services', undefined, { search: h.tag, sort: 'name:asc', size: 100 })), 'R12', 'indexed search re-authorizes actual objects');
  h.check(rows(indexed).every(value => value.tags.some(tag => ['team:pay', 'team:shared'].includes(tag))), 'R12', 'search index cannot leak unauthorized business-tag rows');
  if (filtered.cursors[0]) await h.reject(accounts['pay-reader'].session, endpoint(c1, pay, 'services', undefined, { tags: h.tag, size: 2, cursor: filtered.cursors[0] }), 'GET', undefined, 'R13', 'cursor cannot move to a different authenticated account', [400, 403]);

  // Six actual credential entities, actual Consumer parents, independent secret
  // permission, and tag intersection on the child as well as its parent.
  await makeAccount('consumer-reader', [...support, tagGrant('consumers', 'read')]);
  await makeAccount('consumer-writer', [...support, tagGrant('consumers', 'read'), tagGrant('consumers', 'write')]);
  await makeAccount('secret-only', [...support, tagGrant('secrets', 'read')]);
  const key = `m4-key-${randomUUID()}`, basicPassword = strongPassword(), jwtSecret = `m4-jwt-${randomUUID()}`, oauthSecret = `m4-oauth-${randomUUID()}`, hmacSecret = `m4-hmac-${randomUUID()}`;
  h.secrets.push(key, basicPassword, jwtSecret, oauthSecret, hmacSecret);
  const credentialInputs = {
    'key-auth': { key }, 'basic-auth': { username: `${h.tag}-basic`, password: basicPassword },
    jwt: { key: `${h.tag}-jwt`, secret: jwtSecret, algorithm: 'HS256' },
    oauth2: { name: `${h.tag}-app`, client_id: `${h.tag}-client`, client_secret: oauthSecret, redirect_uris: ['https://example.invalid/callback'] },
    'hmac-auth': { username: `${h.tag}-hmac`, secret: hmacSecret }, acls: { group: 'm4-private-group' },
  };
  const credentials = {}, foreignCredentials = {}, credentialPath = (consumer, kind, id, query = {}) => scope(`/clusters/${c1.id}/consumers/${consumer.id}/credentials/${kind}${id ? `/${id}` : ''}`, pay, query);
  for (const [kind, input] of Object.entries(credentialInputs)) {
    credentials[kind] = entity(h.ok(await h.request(admin, credentialPath(owned.consumer, kind), 'POST', { ...input, tags: [h.tag, 'team:pay'] }), 'I08', `${kind} fixture credential creation`));
    const wrongParent = entity(h.ok(await h.request(admin, credentialPath(owned.otherConsumer, kind), 'POST', { ...input, ...(input.key ? { key: `${input.key}-other` } : {}), ...(input.username ? { username: `${input.username}-other` } : {}), ...(input.client_id ? { client_id: `${input.client_id}-other` } : {}), tags: [h.tag, 'team:ops'] }), 'I08', `${kind} distinct Consumer fixture`));
    foreignCredentials[kind] = wrongParent;
    h.check(wrongParent.id !== credentials[kind].id, 'I08', 'two Consumer parents hold distinct credential identities');
    const original = entity(h.ok(await h.request(admin, credentialPath(owned.consumer, kind, credentials[kind].id, { reveal: true })), 'I08', `${kind} original authorized credential`));
    if (kind === 'basic-auth') h.secrets.push(original.password);
    const masked = await h.request(accounts['consumer-reader'].session, credentialPath(owned.consumer, kind, credentials[kind].id));
    h.ok(masked, 'S01', `${kind} authorized public credential read`);
    h.check(![key, basicPassword, jwtSecret, oauthSecret, hmacSecret].some(secret => masked.text.includes(secret)), 'S01', `${kind} default read hides all synthetic credential values`);
    await h.reject(accounts['consumer-reader'].session, credentialPath(owned.consumer, kind, credentials[kind].id, { reveal: true }), 'GET', undefined, 'S02', `${kind} public read does not grant secret reveal`);
    const revealed = entity(h.ok(await h.request(accounts['secret-reader'].session, credentialPath(owned.consumer, kind, credentials[kind].id, { reveal: true })), 'S02', `${kind} explicit secrets.read plus entity read is permitted`));
    h.check(revealed.id === original.id, 'S02', `${kind} secret reveal still refers to the authorized entity`);
    for (const [method, body] of [['GET', undefined], ['PATCH', { tags: [h.tag, 'team:pay', 'unauthorized-change'] }], ['DELETE', { confirmed: true, confirm_name: credentials[kind].username || credentials[kind].id }]]) {
      await h.reject(admin, credentialPath(owned.otherConsumer, kind, credentials[kind].id), method, body, 'I08', `${kind} actual credential ID cannot be used under another existing Consumer`, [404]);
      await h.reject(accounts['consumer-writer'].session, credentialPath(owned.otherConsumer, kind, credentials[kind].id), method, body, 'I08', `${kind} wrong-parent identity is denied or absent without configuration disclosure`, [403, 404]);
      const foreignBody = method === 'DELETE' ? { confirmed: true, confirm_name: wrongParent.username || wrongParent.id } : body;
      await h.reject(accounts['consumer-writer'].session, credentialPath(owned.otherConsumer, kind, wrongParent.id), method, foreignBody, 'I08', `${kind} existing foreign-tag credential is denied with HTTP 403`);
    }
    const after = entity(h.ok(await h.request(admin, credentialPath(owned.consumer, kind, credentials[kind].id, { reveal: true })), 'I08', `${kind} actual original state after IDOR attempts`));
    h.check(JSON.stringify(canonical(original)) === JSON.stringify(canonical(after)), 'I08', `${kind} wrong-parent attempts preserve the original configuration and secret`);
  }
  await h.reject(accounts['secret-only'].session, credentialPath(owned.consumer, 'key-auth', credentials['key-auth'].id, { reveal: true }), 'GET', undefined, 'S02', 'secrets.read alone does not grant entity/parent read');
  const foreignCollectionResponse = await h.request(accounts['secret-reader'].session, credentialPath(owned.otherConsumer, 'key-auth', undefined, { reveal: true }));
  const foreignCollection = h.ok(foreignCollectionResponse, 'S02', 'private parent lookup returns a filtered authorized collection');
  h.check(rows(foreignCollection).length === 0 && !foreignCollectionResponse.text.includes(foreignCredentials['key-auth'].id), 'S02', 'foreign-tag collection contains no unauthorized credential rows or IDs');
  h.check(!h.secrets.filter(Boolean).some(secret => foreignCollectionResponse.text.includes(secret)), 'S02', 'empty projected collection reveals no known credential or token');
  for (const [kind, credential] of Object.entries(foreignCredentials)) await h.reject(accounts['secret-reader'].session, credentialPath(owned.otherConsumer, kind, credential.id, { reveal: true }), 'GET', undefined, 'S02', `${kind} actual foreign-tag credential secret reveal is denied`);
  h.public.foreignCredentialIds = Object.fromEntries(Object.entries(foreignCredentials).map(([kind, value]) => [kind, value.id]));
  const childWithoutTag = entity(h.ok(await h.request(admin, credentialPath(owned.consumer, 'key-auth'), 'POST', { key: `m4-no-business-${randomUUID()}`, tags: [h.tag] }), 'I08', 'parent-visible credential without an authorized child business tag'));
  await h.reject(accounts['consumer-reader'].session, credentialPath(owned.consumer, 'key-auth', childWithoutTag.id), 'GET', undefined, 'I04/I08', 'Consumer tag permission still requires the credential child tag intersection');
  await makeAccount('credential-entity-reader', [...support, idGrant('consumers', 'read', 'key-auth', credentials['key-auth'].id)]);
  h.ok(await h.request(accounts['credential-entity-reader'].session, credentialPath(owned.consumer, 'key-auth', credentials['key-auth'].id)), 'R11/I08', 'typed credential whitelist reads its exact Consumer child');
  await h.reject(accounts['credential-entity-reader'].session, endpoint(c1, pay, 'consumers', owned.consumer), 'GET', undefined, 'R11/I08', 'pure typed credential grant does not expose parent Consumer configuration');
  await h.reject(accounts['credential-entity-reader'].session, credentialPath(owned.consumer, 'jwt', credentials.jwt.id), 'GET', undefined, 'R11/I08', 'typed key-auth credential ID grant never authorizes a different credential kind');
  await makeAccount('credential-entity-writer', [...support, idGrant('consumers', 'read', 'key-auth', credentials['key-auth'].id), idGrant('consumers', 'write', 'key-auth', credentials['key-auth'].id)]);
  h.ok(await h.request(accounts['credential-entity-writer'].session, credentialPath(owned.consumer, 'key-auth', credentials['key-auth'].id), 'PATCH', { tags: [h.tag, 'team:pay', 'typed-id-update'] }), 'R11/I08', 'typed credential write permits only its existing exact credential ID');
  await h.reject(accounts['credential-entity-writer'].session, credentialPath(owned.consumer, 'key-auth'), 'POST', { key: `m4-ungranted-${randomUUID()}`, tags: [h.tag, 'team:pay'] }, 'R11/I08', 'typed existing-ID credential write does not authorize creation of a new credential ID');
  await h.reject(accounts['credential-entity-writer'].session, credentialPath(owned.otherConsumer, 'key-auth', credentials['key-auth'].id), 'PATCH', { tags: [h.tag, 'team:pay'] }, 'R11/I08', 'typed credential grant cannot reparent the authorized ID', [403, 404]);
  await makeAccount('credential-entity-secret', [...support, idGrant('consumers', 'read', 'key-auth', credentials['key-auth'].id), idGrant('secrets', 'read', 'key-auth', credentials['key-auth'].id)]);
  const typedSecret = entity(h.ok(await h.request(accounts['credential-entity-secret'].session, credentialPath(owned.consumer, 'key-auth', credentials['key-auth'].id, { reveal: true })), 'S02/R11', 'independent typed secret grant reveals only its exact authorized credential'));
  h.check(typedSecret.key === key, 'S02/R11', 'typed secret reveal matches the original credential without exposing its parent configuration');
  await h.reject(accounts['credential-entity-secret'].session, credentialPath(owned.consumer, 'jwt', credentials.jwt.id, { reveal: true }), 'GET', undefined, 'S02/R11', 'typed credential secret grant cannot reveal a sibling credential kind');
  h.ok(await h.request(admin, credentialPath(owned.consumer, 'key-auth')), 'R11/Nav', 'admin observes actual credential-parent navigation without exposing secrets');
  const childDiscovery = h.ok(await h.request(accounts['credential-entity-reader'].session, scope(`/clusters/${c1.id}/authorization/children`, pay, { type: 'key-auth', size: 20 })), 'R11/Nav', 'pure credential-ID account discovers its authorized child without parent configuration permission');
  h.check(rows(childDiscovery).some(value => value.id === credentials['key-auth'].id && value.parent_id === owned.consumer.id) && rows(childDiscovery).every(value => value.id === credentials['key-auth'].id && value.type === 'key-auth'), 'R11/Nav', 'credential navigation returns only its exact authorized typed ID and required parent ID');
  await h.reject(accounts['credential-entity-reader'].session, scope(`/clusters/${c2.id}/authorization/children`, pay2), 'GET', undefined, 'R11/Nav', 'child discovery cannot cross to the genuine second cluster');
  h.public.credentialIds = Object.fromEntries(Object.entries(credentials).map(([kind, value]) => [kind, value.id]));

  // An actual global definition narrowed by C1/Pay binding keeps its workspace
  // ceiling; global scope does not mean that the effective binding is ignored.
  const boundedGlobal = await makeAccount('bounded-global', [g('clusters', 'read', 'global', [], c1, pay), g('workspaces', 'read', 'global', [], c1, pay), g('services', 'read', 'global', [], c1, pay)]);
  h.ok(await h.request(boundedGlobal.session, endpoint(c1, pay, 'services', owned.service)), 'R04/R06', 'global definition narrowed by C1/Pay binding reads only Pay');
  await h.reject(boundedGlobal.session, endpoint(c1, ops, 'services', owned.opsService), 'GET', undefined, 'R04/R06', 'global definition retains the mandatory Pay binding ceiling');
  const globalAdmin = await makeAccount('global-admin', [g('clusters', 'read', 'global', [], c1, null), g('workspaces', 'read', 'global', [], c1, null), ...nativeTypes.flatMap(type => ['read', 'write', 'delete'].map(action => g(type, action, 'global', [], c1, null)))]);
  await h.reject(globalAdmin.session, endpoint(c1, pay, 'plugins'), 'POST', { name: 'cors', enabled: false, config: {}, tags: [h.tag, 'team:pay'] }, 'P/GlobalPlugin', 'global module grants do not become platform-super privilege for an unbound cross-workspace Plugin');
  for (const name of ['pre-function', 'post-function']) {
    const lua = await h.create(admin, c1, pay, 'plugins', { name, service: { id: owned.privateService.id }, enabled: false, config: { functions: ['return'] }, tags: [h.tag, 'team:ops'] });
    await verifyDeniedState(accounts['workspace-admin'], 'plugins', lua, { enabled: true }, 'P/Lua', 'workspace administrator cannot enable an existing bound Lua Plugin');
  }
  const fileLog = await h.create(admin, c1, pay, 'plugins', { name: 'file-log', service: { id: owned.privateService.id }, enabled: false, config: { path: '/tmp/kongos-m4-synthetic.log' }, tags: [h.tag, 'team:ops'] });
  await verifyDeniedState(accounts['workspace-admin'], 'plugins', fileLog, { enabled: true }, 'P/File', 'workspace administrator cannot enable an existing local-file append Plugin');

  // Basic and API-key authentication remain usable after rejected attacks. The
  // safe echo upstream never reflects credentials or their query parameters.
  const keyRoute = await h.create(admin, c1, pay, 'routes', { name: `${h.tag}-key-route`, service: { id: owned.service.id }, paths: [`/m4/${h.tag}/key`], protocols: ['http'], tags: [h.tag, 'team:pay'] });
  const basicRoute = await h.create(admin, c1, pay, 'routes', { name: `${h.tag}-basic-route`, service: { id: owned.service.id }, paths: [`/m4/${h.tag}/basic`], protocols: ['http'], tags: [h.tag, 'team:pay'] });
  await h.create(admin, c1, pay, 'plugins', { name: 'key-auth', route: { id: keyRoute.id }, config: { key_names: ['apikey'], hide_credentials: true }, tags: [h.tag, 'team:pay'] });
  await h.create(admin, c1, pay, 'plugins', { name: 'basic-auth', route: { id: basicRoute.id }, config: { hide_credentials: true }, tags: [h.tag, 'team:pay'] });
  const basicHeader = `Basic ${Buffer.from(`${credentialInputs['basic-auth'].username}:${basicPassword}`).toString('base64')}`; h.secrets.push(basicHeader);
  await h.waitProxy(c1, `${keyRoute.paths[0]}/echo`, 401);
  await h.waitProxy(c1, `${keyRoute.paths[0]}/echo`, 200, { apikey: key });
  await h.waitProxy(c1, `${basicRoute.paths[0]}/echo`, 200, { Authorization: basicHeader });
  h.check(true, 'I08', 'unchanged key-auth and original Basic credentials work through the real gateway');

  // A query key is intentionally used only for this isolated logging test. The
  // output artifact records booleans, never query strings or captured log lines.
  const logStart = new Date(Date.now() - 1000).toISOString();
  await h.waitProxy(c1, `${keyRoute.paths[0]}/echo?apikey=${encodeURIComponent(key)}`, 200);
  const { execFileSync } = await import('node:child_process');
  const nativeLogs = execFileSync('docker', ['compose', 'logs', '--no-color', '--since', logStart, 'kong'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  h.check(!nativeLogs.includes(key) && !nativeLogs.includes(basicPassword), 'S09', 'actual Kong proxy logs do not expose a valid query API key or Basic password');
  h.public.proxyAuthentication = { apiKeyValid: true, originalBasicValid: true, queryKeyLogLeak: false };

  await makeAccount('upstream-reader', [...support, tagGrant('upstreams', 'read')]);
  await makeAccount('upstream-writer', [...support, tagGrant('upstreams', 'read'), tagGrant('upstreams', 'write')]);
  const targetPath = (upstream, id, state) => scope(`/clusters/${c1.id}/upstreams/${upstream.id}/targets${id ? `/${id}` : ''}${state ? `/${state}` : ''}`, pay);
  const target = entity(h.ok(await h.request(admin, targetPath(owned.upstream), 'POST', { target: 'echo-upstream:8081', weight: 100, tags: [h.tag, 'team:pay'] }), 'I07', 'authorized Target fixture'));
  await makeAccount('target-entity-writer', [...support, idGrant('upstreams', 'read', 'targets', target.id), idGrant('upstreams', 'write', 'targets', target.id)]);
  const typedTargets = h.ok(await h.request(accounts['target-entity-writer'].session, targetPath(owned.upstream)), 'R11/I07', 'pure Target-ID grant obtains only its actual child from a privately verified Upstream');
  h.check(rows(typedTargets).every(value => value.id === target.id) && rows(typedTargets).some(value => value.id === target.id), 'R11/I07', 'pure Target whitelist does not return unrelated Target history identities');
  const targetDiscovery = h.ok(await h.request(accounts['target-entity-writer'].session, scope(`/clusters/${c1.id}/authorization/children`, pay, { type: 'targets', size: 20 })), 'R11/Nav', 'pure Target-ID grant discovers its exact effective Target');
  h.check(rows(targetDiscovery).some(value => value.id === target.id && value.parent_id === owned.upstream.id) && rows(targetDiscovery).every(value => value.id === target.id), 'R11/Nav', 'Target navigation excludes siblings and parent configuration');
  await h.reject(accounts['target-entity-writer'].session, endpoint(c1, pay, 'upstreams', owned.upstream), 'GET', undefined, 'R11/I07', 'pure Target-ID grant never exposes parent Upstream configuration');
  await h.reject(accounts['target-entity-writer'].session, targetPath(owned.upstream), 'POST', { target: 'echo-upstream:8083', weight: 1, tags: [h.tag, 'team:pay'] }, 'R11/I07', 'pure existing Target-ID write cannot create a new Target history ID');
  await h.reject(accounts['target-entity-writer'].session, targetPath(owned.upstream, target.id), 'PATCH', { weight: 80 }, 'R11/I07', 'pure existing Target-ID write cannot append a new effective history ID');
  const foreignTarget = entity(h.ok(await h.request(admin, targetPath(owned.otherUpstream), 'POST', { target: 'echo-upstream:8081', weight: 100, tags: [h.tag, 'team:ops'] }), 'I07', 'different Upstream contains same Target address'));
  for (const [method, tail, body] of [['PATCH', undefined, { weight: 1 }], ['POST', 'unhealthy', undefined], ['DELETE', undefined, { confirmed: true, confirm_name: target.target }]]) {
    await h.reject(admin, targetPath(owned.otherUpstream, target.id, tail), method, body, 'I07', 'actual Target UUID cannot be mutated under another existing Upstream', [404]);
    await h.reject(accounts['upstream-writer'].session, targetPath(owned.otherUpstream, target.id, tail), method, body, 'I07', 'wrong-parent Target identity is denied or absent without disclosure', [403, 404]);
    await h.reject(accounts['upstream-writer'].session, targetPath(owned.otherUpstream, foreignTarget.id, tail), method, body, 'I07', 'actual existing foreign-tag Target rejects mutation with HTTP 403');
  }
  await h.reject(accounts['upstream-reader'].session, targetPath(owned.upstream, target.id, 'unhealthy'), 'POST', undefined, 'R01', 'read-only cannot manually set Target health');
  const targetsAfter = h.ok(await h.request(admin, targetPath(owned.upstream)), 'I07', 'real effective Targets after IDOR attempts');
  h.check(rows(targetsAfter).some(value => value.id === target.id && value.weight === 100), 'I07', 'wrong-parent attempts preserve the original effective Target ID/weight');
  const targetNoBusiness = entity(h.ok(await h.request(admin, targetPath(owned.upstream), 'POST', { target: 'echo-upstream:8082', weight: 1, tags: [h.tag] }), 'I04', 'Target child without authorized business tag'));
  await h.reject(accounts['upstream-writer'].session, targetPath(owned.upstream, targetNoBusiness.id), 'PATCH', { weight: 2 }, 'I04', 'authorized Upstream tag does not permit an untagged Target child');

  // Deletion inheritance is checked against a complete real object graph. A
  // forbidden shared Consumer binding blocks the original Service deletion.
  const dependencyBefore = await Promise.all([
    ['services', owned.service], ['routes', owned.route], ['plugins', owned.comboPlugin], ['plugins', owned.servicePlugin],
  ].map(async ([type, value]) => ({ type, value, before: await h.detail(admin, c1, pay, type, value, 'I10', { reveal: true }) })));
  await h.reject(accounts['service-deleter'].session, endpoint(c1, pay, 'services', owned.service), 'DELETE', { confirmed: true, confirm_name: owned.service.name }, 'I10', 'Service delete does not silently expand authority to an unauthorized Consumer-bound Plugin', [403, 409]);
  for (const sample of dependencyBefore) await h.unchanged(admin, c1, pay, sample.type, sample.value, sample.before, 'I10', 'rejected dependency deletion leaves the live original object intact');
  const cleanService = await h.create(admin, c1, pay, 'services', { name: `${h.tag}-clean-delete-service`, host: 'echo-upstream', port: 8081, tags: [h.tag, 'team:pay'] });
  const cleanRoute = await h.create(admin, c1, pay, 'routes', { name: `${h.tag}-clean-delete-route`, service: { id: cleanService.id }, paths: [`/m4/${h.tag}/clean-delete`], tags: [h.tag, 'team:pay'] });
  const cleanPlugin = await h.create(admin, c1, pay, 'plugins', { name: 'correlation-id', route: { id: cleanRoute.id }, enabled: false, config: { header_name: 'X-M4-Clean' }, tags: [h.tag, 'team:pay'] });
  const cleanDeleter = await makeAccount('clean-deleter', [...support, idGrant('services', 'read', 'services', cleanService.id), idGrant('services', 'delete', 'services', cleanService.id)]);
  h.ok(await h.request(cleanDeleter.session, endpoint(c1, pay, 'services', cleanService), 'DELETE', { confirmed: true, confirm_name: cleanService.name }), 'I03', 'exact Service delete grant cascades authorized Route and bound Plugin through recycle');
  for (const [type, value] of [['services', cleanService], ['routes', cleanRoute], ['plugins', cleanPlugin]]) await h.reject(admin, endpoint(c1, pay, type, value), 'GET', undefined, 'I03', 'authorized inherited deletion removes the real captured graph node', [404]);
  const cleanEntries = rows(h.ok(await h.request(admin, scope(`/clusters/${c1.id}/recycle-bin`, pay, { size: 100 })), 'I03', 'admin views the durable inherited-delete archive'));
  const cleanEntry = cleanEntries.find(value => value.original_id === cleanService.id && value.state !== 'restored');
  h.check(Boolean(cleanEntry) && cleanEntry.node_count >= 3, 'I03', 'Service inherited-delete archive contains root, Route and Plugin');
  for (const verb of ['restore', 'purge']) await h.reject(accounts['pay-reader'].session, scope(`/clusters/${c1.id}/recycle-bin/${cleanEntry.id}/${verb}`, pay), 'POST', { confirmed: true, confirm_name: cleanEntry.root_name }, 'R01', 'read-only cannot restore or permanently purge the archived graph');
  h.ok(await h.request(admin, scope(`/clusters/${c1.id}/recycle-bin/${cleanEntry.id}/restore`, pay), 'POST', { confirmed: true, confirm_name: cleanEntry.root_name }), 'I03', 'platform admin restores the inherited-delete graph without losing original IDs');
  await h.detail(admin, c1, pay, 'routes', cleanRoute, 'I03');
  await h.detail(admin, c1, pay, 'plugins', cleanPlugin, 'I03');

  // Permission revocation is exercised using existing access cookies. No
  // logout, login, Redis clear or browser-cache reset is needed for denial.
  const revoke = await makeAccount('revoked-binding', [...support, g('services', 'read')]);
  h.ok(await h.request(revoke.session, endpoint(c1, pay, 'services', owned.service)), 'A09', 'direct binding initially permits real Service read');
  const revokePages = await collect(revoke, c1, pay, 'services', h.tag);
  h.ok(await h.request(admin, `/iam/users/${revoke.user.id}/role-bindings/${revoke.binding.id}`, 'DELETE', { revision: revoke.binding.revision, confirmed: true, confirm_name: revoke.role.name }), 'A09', 'audited direct binding revocation');
  await h.reject(revoke.session, endpoint(c1, pay, 'services', owned.service), 'GET', undefined, 'A09', 'existing access JWT immediately loses revoked binding authority', [401, 403]);
  if (revokePages.cursors[0]) await h.reject(revoke.session, endpoint(c1, pay, 'services', undefined, { tags: h.tag, size: 2, cursor: revokePages.cursors[0] }), 'GET', undefined, 'R13', 'previous cursor cannot revive a revoked grant', [400, 401, 403]);

  const teamUser = await makeAccount('team-member', support);
  const team = h.ok(await h.request(admin, '/iam/teams', 'POST', { code: `${h.tag}-pay-team`, name: `${h.tag}-pay-team`, cluster_id: c1.id, workspace_id: pay.id }), 'A08', 'scoped team fixture');
  const teamRole = await role('team-role', [g('services', 'read')], { cluster_id: c1.id, workspace_id: pay.id });
  h.ok(await h.request(admin, `/iam/teams/${team.id}/role-bindings`, 'POST', { role_id: teamRole.id, cluster_id: c1.id, workspace_id: pay.id }), 'A08', 'explicit scoped team role binding');
  const membership = h.ok(await h.request(admin, `/iam/teams/${team.id}/members`, 'POST', { user_id: teamUser.user.id }), 'A08', 'admin assigns ordinary user to the scoped team');
  h.ok(await h.request(teamUser.session, endpoint(c1, pay, 'services', owned.service)), 'A09', 'existing session acquires actual team authorization');
  await h.reject(teamUser.session, `/iam/teams/${team.id}/members`, 'POST', { user_id: ordinary.user.id }, 'A08', 'ordinary team member cannot modify membership to self-escalate');
  h.ok(await h.request(admin, `/iam/teams/${team.id}/members/${teamUser.user.id}`, 'DELETE', { revision: membership.revision, confirmed: true, confirm_name: teamUser.user.username }), 'A09', 'audited team membership removal');
  await h.reject(teamUser.session, endpoint(c1, pay, 'services', owned.service), 'GET', undefined, 'A09', 'old access JWT immediately loses authorization after team removal', [401, 403]);

  const scopedRevoker = await makeAccount('scope-revoker', [...support, g('roles', 'delete')]);
  const scopedRevokee = await makeAccount('scope-revokee', [...support, g('services', 'read')], { cluster_id: c1.id, workspace_id: pay.id }, { cluster_id: c1.id, workspace_id: pay.id });
  const globalRevokee = await makeAccount('global-revokee', [g('services', 'read', 'global', [], null, null)]);
  const otherWorkspaceRevokee = await makeAccount('ops-revokee', [g('services', 'read', 'workspace', [ops.id], c1, ops)], { cluster_id: c1.id, workspace_id: ops.id }, { cluster_id: c1.id, workspace_id: ops.id });
  await h.reject(scopedRevoker.session, endpoint(c1, pay, 'services', owned.service), 'GET', undefined, 'A09/RoleDelete', 'roles.delete-only operator has no implied native Service configuration access');
  await h.reject(scopedRevoker.session, `/iam/users/${globalRevokee.user.id}/role-bindings/${globalRevokee.binding.id}`, 'DELETE', { revision: globalRevokee.binding.revision, confirmed: true, confirm_name: globalRevokee.role.name }, 'A09/RoleDelete', 'workspace roles.delete cannot revoke a platform-wide binding');
  await h.reject(scopedRevoker.session, `/iam/users/${otherWorkspaceRevokee.user.id}/role-bindings/${otherWorkspaceRevokee.binding.id}`, 'DELETE', { revision: otherWorkspaceRevokee.binding.revision, confirmed: true, confirm_name: otherWorkspaceRevokee.role.name }, 'A09/RoleDelete', 'workspace roles.delete cannot revoke another workspace binding');
  h.ok(await h.request(scopedRevokee.session, endpoint(c1, pay, 'services', owned.service)), 'A09/RoleDelete', 'scope-owned binding initially grants native read');
  h.ok(await h.request(scopedRevoker.session, `/iam/users/${scopedRevokee.user.id}/role-bindings/${scopedRevokee.binding.id}`, 'DELETE', { revision: scopedRevokee.binding.revision, confirmed: true, confirm_name: scopedRevokee.role.name }), 'A09/RoleDelete', 'own-workspace roles.delete revokes the exact binding without needing its broader native read grant');
  await h.reject(scopedRevokee.session, endpoint(c1, pay, 'services', owned.service), 'GET', undefined, 'A09/RoleDelete', 'old native session loses the role revoked by the scoped delete-only operator', [401, 403]);

  const disabled = await makeAccount('disabled-user', [...support, g('services', 'read')]);
  h.ok(await h.request(disabled.session, endpoint(c1, pay, 'services', owned.service)), 'A09', 'account initially active');
  const disableCurrent = h.ok(await h.request(admin, `/iam/users/${disabled.user.id}`), 'A09', 'fresh account revision before disabling');
  h.ok(await h.request(admin, `/iam/users/${disabled.user.id}/status`, 'POST', { revision: disableCurrent.revision, status: 'disabled', confirmed: true, confirm_name: disabled.user.username }), 'A09', 'audited account disabling');
  await h.reject(disabled.session, '/auth/me', 'GET', undefined, 'A09', 'old access session is rejected immediately after disabling', [401]);
  await h.reject(disabled.session, '/auth/refresh', 'POST', undefined, 'A09', 'old refresh session is rejected immediately after disabling', [401]);

  const reset = await makeAccount('reset-session', [...support, g('services', 'read')]);
  const resetCurrent = h.ok(await h.request(admin, `/iam/users/${reset.user.id}`), 'A06', 'fresh revision before authorized password reset');
  const replacementPassword = strongPassword(); h.secrets.push(replacementPassword);
  const resetResult = h.ok(await h.request(admin, `/iam/users/${reset.user.id}/reset-password`, 'POST', { revision: resetCurrent.revision, new_password: replacementPassword, confirmed: true }), 'A06', 'authorized reset delegates to central credential/session revocation');
  h.check(resetResult.sessionsRevoked === true && resetResult.forcePasswordChange === true, 'A06', 'reset reports session revocation and mandatory password change');
  await h.reject(reset.session, '/auth/me', 'GET', undefined, 'A06', 'authorized reset invalidates old access session', [401]);
  await h.reject(reset.session, '/auth/refresh', 'POST', undefined, 'A06', 'authorized reset invalidates old refresh session', [401]);
  await h.reject(null, '/auth/login', 'POST', { username: reset.user.username, password: reset.password }, 'A06', 'old account password no longer authenticates', [401]);
  await h.login(reset.user.username, replacementPassword, 'A06');
  h.users.find(user => user.id === reset.user.id).password = replacementPassword;

  // Session management uses the current actor and exact owner, not a client
  // session/user ID. All inspected values stay in memory and reports omit IDs.
  const ownSessions = h.ok(await h.request(ordinary.session, '/auth/me/sessions?size=1'), 'A/Session', 'ordinary account can inspect its own bounded sessions');
  h.check(rows(ownSessions).length === 1 && !JSON.stringify(ownSessions).match(/refresh_token_hash|csrf_token_hash|credential_epoch/), 'A/Session', 'session response omits credential/CSRF hashes and epoch internals');
  await h.reject(ordinary.session, `/auth/users/${victim.user.id}/sessions`, 'GET', undefined, 'A/Session', 'ordinary actor cannot enumerate another user sessions');
  const victimSessions = h.ok(await h.request(admin, `/auth/users/${victim.user.id}/sessions?size=1`), 'A/Session', 'platform actor privately locates a disposable victim session');
  const victimSessionId = rows(victimSessions)[0].id;
  await h.reject(ordinary.session, `/auth/me/sessions/${victimSessionId}/revoke`, 'POST', { confirmed: true, confirm_name: ordinary.user.username }, 'A/Session', 'another account session ID cannot be revoked through the self route', [404]);
  await h.reject(ordinary.session, `/auth/users/${victim.user.id}/sessions/${victimSessionId}/revoke`, 'POST', { confirmed: true, confirm_name: ordinary.user.username }, 'A/Session', 'ordinary actor cannot revoke another account session through the admin route');
  if (ownSessions.nextCursor) await h.reject(victim.session, `/auth/me/sessions?size=1&cursor=${encodeURIComponent(ownSessions.nextCursor)}`, 'GET', undefined, 'A/Session', 'session cursor cannot be transferred to another actor', [400, 403]);
  h.ok(await h.request(victim.session, '/auth/me'), 'A/Session', 'denied session-ID attacks preserve the original victim session');
  const sessionAccount = await makeAccount('session-revoke', support);
  const secondSession = await h.login(sessionAccount.user.username, sessionAccount.password, 'A/Session');
  await h.reject(sessionAccount.session, '/auth/me/sessions/revoke-all', 'POST', { confirmed: true, confirm_name: 'incorrect-typed-actor' }, 'A/Session', 'revoke-all requires exact current actor confirmation', [400]);
  h.ok(await h.request(sessionAccount.session, '/auth/me/sessions/revoke-all', 'POST', { confirmed: true, confirm_name: sessionAccount.user.username }), 'A/Session', 'ordinary user explicitly revokes all of its own sessions');
  for (const session of [sessionAccount.session, secondSession]) {
    await h.reject(session, '/auth/me', 'GET', undefined, 'A/Session', 'own all-session revocation invalidates an existing access cookie', [401]);
    await h.reject(session, '/auth/refresh', 'POST', undefined, 'A/Session', 'own all-session revocation invalidates an existing refresh cookie', [401]);
  }

  // Anonymous, header-forged and out-of-scope reads cannot reach management
  // endpoints, including metadata-like plugin schemas, receipts and inventory.
  const sensitiveReads = [endpoint(c1, pay, 'services', owned.service), scope(`/clusters/${c1.id}/schemas/services`, pay), scope(`/clusters/${c1.id}/plugin-schemas/key-auth`, pay), scope(`/clusters/${c1.id}/plugin-center/catalog`, pay), scope(`/clusters/${c1.id}/recycle-bin`, pay), scope(`/clusters/${c1.id}/inventory`, pay), '/iam/users'];
  for (const path of sensitiveReads) await h.reject(null, path, 'GET', undefined, 'A01', 'unauthenticated management read denied', [401]);
  await h.reject(ordinary.session, endpoint(c1, pay, 'services', owned.service), 'GET', undefined, 'A10/P04', 'client actor/system/skip flags cannot supply trusted execution identity', [403], { headers: { 'X-Actor-Id': admin.user.id, 'X-System': 'true', 'X-Skip-Authorization': 'true', 'X-Super-Admin': 'true' } });
  await h.reject(accounts['pay-reader'].session, '/clusters', 'POST', { name: `${h.tag}-forged-registration`, admin_url: 'http://kong:8001', execution_mode: 'direct' }, 'S04', 'workspace/entity read cannot register or modify connections');
  await h.reject(accounts['workspace-admin'].session, `/clusters/${c1.id}`, 'PATCH', { execution_mode: 'approval' }, 'S04', 'workspace administrator cannot change registry execution policy');

  // Endpoint-level destination validation plus network-level defenses. Legacy
  // unsafe routes are installed only by the explicitly controlled backend test
  // process, then removed via the normal audited BFF recycle path.
  for (const host of ['kong', 'kong-secondary', '127.0.0.1', 'localhost', '172.28.11.20', '172.28.12.20']) await h.reject(admin, endpoint(c1, pay, 'services'), 'POST', { name: `${h.tag}-blocked-${host.replace(/\./g, '-')}`, host, port: 8001, tags: [h.tag, 'team:pay'] }, 'P/Admin', 'BFF rejects a Service destination targeting a registered/local Admin listener', [400, 403]);
  for (const address of ['127.0.0.1:8001', 'kong:8001', '172.28.11.20:8001']) await h.reject(admin, targetPath(owned.upstream), 'POST', { target: address, weight: 100, tags: [h.tag, 'team:pay'] }, 'P/Admin', 'BFF rejects an Admin destination in an Upstream Target', [400, 403]);
  const physicalTags = [h.tag, `kos-ws-${pay2.code}`];
  const unsafeServiceResponse = h.native(c2, '/services', 'POST', { name: `${h.tag}-legacy-admin-direct`, protocol: 'http', host: '127.0.0.1', port: 8001, tags: physicalTags });
  h.check(unsafeServiceResponse.status === 201, 'P/Admin', 'controlled backend test process installs an isolated legacy Admin-loopback fixture');
  const unsafeService = unsafeServiceResponse.body;
  const unsafeRouteResponse = h.native(c2, '/routes', 'POST', { name: `${h.tag}-legacy-admin-route`, service: { id: unsafeService.id }, paths: [`/m4/${h.tag}/legacy-admin`], strip_path: true, protocols: ['http'], tags: physicalTags });
  h.check(unsafeRouteResponse.status === 201, 'P/Admin', 'isolated unsafe fixture has a unique proxy path');
  for (const headers of [{}, { 'X-Forwarded-For': '172.28.12.10', 'X-Real-IP': '172.28.12.10' }, { Forwarded: 'for=172.28.12.10', 'X-Forwarded-For': '172.28.12.10,127.0.0.1' }]) {
    await h.waitProxy(c2, `${unsafeRouteResponse.body.paths[0]}/status`, 403, headers);
    h.check(true, 'P/Admin', 'legacy self-proxy Admin request is denied even with spoofed BFF source headers');
  }
  const forbiddenNativeName = `${h.tag}-proxy-injected`;
  await h.waitProxy(c2, `${unsafeRouteResponse.body.paths[0]}/services`, 403, { 'X-Forwarded-For': '172.28.12.10' }, 'POST', { name: forbiddenNativeName, host: 'echo-upstream', port: 8081 });
  h.check(h.native(c2, `/services/${forbiddenNativeName}`).status === 404, 'P/Admin', 'denied proxy POST did not create its target native Service');
  const unsafeUpstreamResponse = h.native(c2, '/upstreams', 'POST', { name: `${h.tag}-legacy-admin-upstream`, tags: physicalTags });
  h.check(unsafeUpstreamResponse.status === 201, 'P/Admin', 'controlled legacy Admin-Upstream fixture');
  h.check(h.native(c2, `/upstreams/${unsafeUpstreamResponse.body.id}/targets`, 'POST', { target: '172.28.12.20:8001', weight: 100, tags: physicalTags }).status === 201, 'P/Admin', 'controlled legacy Target points to the exact Admin management IP');
  const unsafePooledService = h.native(c2, '/services', 'POST', { name: `${h.tag}-legacy-admin-pooled`, protocol: 'http', host: unsafeUpstreamResponse.body.name, port: 80, tags: physicalTags });
  h.check(unsafePooledService.status === 201, 'P/Admin', 'controlled legacy Service references Admin-bound Upstream');
  const unsafePooledRoute = h.native(c2, '/routes', 'POST', { name: `${h.tag}-legacy-admin-pooled-route`, service: { id: unsafePooledService.body.id }, paths: [`/m4/${h.tag}/legacy-admin-pooled`], strip_path: true, protocols: ['http'], tags: physicalTags });
  h.check(unsafePooledRoute.status === 201, 'P/Admin', 'controlled legacy pooled Admin proxy route');
  await h.waitProxy(c2, `${unsafePooledRoute.body.paths[0]}/status`, 403, { 'X-Real-IP': '172.28.12.10', 'X-Forwarded-For': '172.28.12.10' });
  h.check(h.native(c2, '/status').status === 200, 'P/Admin', 'the same real Admin endpoint remains reachable from the authorized console-api source');
  await h.archive(admin, c2, pay2, 'services', unsafeService, 'P/Cleanup');
  await h.archive(admin, c2, pay2, 'services', unsafePooledService.body, 'P/Cleanup');
  await h.archive(admin, c2, pay2, 'upstreams', unsafeUpstreamResponse.body, 'P/Cleanup');
  h.public.nativeAclProof = { trueSecondaryGateway: true, serviceLoopbackStatus: 403, targetAdminIpStatus: 403, spoofedSourceStatus: 403, authorizedBffStatus: 200, proxyPostCreatedObject: false, legacyFixturesArchivedViaBff: true };

  h.public.attackMechanisms = { konga2021: 'ordinary authenticated privileged-field mass assignment', konga2023: 'ordinary authenticated cross-user password reset', targetsAreOwnedFixtures: true };
  h.public.accounts = Object.fromEntries(Object.entries(accounts).map(([label, account]) => [label, { id: account.user.id, username: account.user.username, role: { id: account.role.id, name: account.role.name }, binding: { id: account.binding.id, revision: account.binding.revision } }]));
  h.public.nativeContextEvidence = { realProxyAcl: true, contextIsolationAndMutationFaults: 'Separate integration-mock/unit results; no real fault-injection claim' };
  h.verifyAuditCoverage();
  process.exitCode = await h.finish();
} catch (error) {
  process.exitCode = await h.finish(error);
}
