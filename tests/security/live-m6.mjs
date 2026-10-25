import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { M6Harness, M6_C1, M6_C2, cookieMerge, entity, rows, scope, portalScope, strongPassword, reservationFacts, releasedReservation } from './lib/m6-harness.mjs';
import { verifyM6RuntimeLogs } from './lib/m6-runtime-logs.mjs';
import { guardPublicationContinuation } from './lib/m6-publication-continuation.mjs';
import { assertRetiredKeyRestoreDenial, proveManagedConsumerIdentityDenied, captureHistoricalKeyCipherBeforeRetirement } from './lib/m6-retired-lifecycle-continuation.mjs';

const confirm = row => ({ revision: row.revision, confirmed: true, confirm_name: row.name ?? row.username });
const endpoint = (cluster, workspace, suffix) => scope(`/clusters/${cluster.id}/${suffix}`, workspace);
const wsGrant = (cluster, workspace, module, action) => ({ module, action, scope_type: 'workspace', cluster_id: cluster.id, workspace_id: workspace.id, scope_values: [workspace.id] });

async function consoleAccount(h, admin, cluster, workspace, label, permissions) {
  let password = strongPassword(); h.secrets.push(password); h.saveReference();
  const user = h.ok(await h.request(admin, '/iam/users', 'POST', { username: `${h.tag}-${label}`, password, display_name: `M6 ${label}` }), 'Setup/Actor', 'ordinary console actor creation');
  const role = h.ok(await h.request(admin, '/iam/roles', 'POST', { code: `${h.tag}-${label}`, name: `${h.tag}-${label}`, cluster_id: cluster.id, workspace_id: workspace.id }), 'Setup/Role', 'workspace-owned workflow role');
  h.ok(await h.request(admin, `/iam/roles/${role.id}/permissions`, 'PUT', { revision: role.revision, permissions }), 'Setup/Role', 'coherent four-dimensional workflow permissions');
  const binding = h.ok(await h.request(admin, `/iam/users/${user.id}/role-bindings`, 'POST', { role_id: role.id, cluster_id: cluster.id, workspace_id: workspace.id }), 'Setup/Role', 'explicit scoped workflow binding');
  let session = await h.login(user.username, password);
  if (user.force_password_change || session.user.forcePasswordChange) {
    const next = strongPassword(); h.secrets.push(next); h.saveReference();
    h.ok(await h.request(session, '/auth/me/password', 'POST', { current_password: password, new_password: next, revision: user.revision, confirmed: true }), 'Setup/Actor', 'mandatory initial password change');
    password = next; session = await h.login(user.username, password);
  }
  const account = { user, role, binding, session, password, label };
  h.users.push({ id: user.id, username: user.username, password, label });
  h.saveReference({ accounts: { ...(h.referenceData.accounts ?? {}), [label]: account } }); return account;
}
async function workflow(h, admin, cluster, workspace, id) {
  return entity(h.ok(await h.request(admin, endpoint(cluster, workspace, `workflows/${id}`)), 'Workflow/View', 'current immutable workflow view'));
}
export async function approveExecute(h, admin, approver, cluster, workspace, id, options = {}) {
  let view = await workflow(h, admin, cluster, workspace, id);
  h.check(view.state === 'pending' && view.approvalRequired === true, 'Workflow/Approval', 'credential plan is pending approval before any native mutation');
  const key = randomUUID();
  h.ok(await h.request(approver, endpoint(cluster, workspace, `workflows/${id}/approve`), 'POST', { revision: view.revision, planHash: view.planHash, confirmed: true, confirm_name: view.kind, execute: false }, { key }), 'Workflow/Approval', 'current approval-only actor records its decision');
  const decision = h.ok(await h.request(approver, endpoint(cluster, workspace, `workflows/receipts/by-key/${key}`)), 'Workflow/Receipt', 'original approval key resolves a durable receipt');
  h.check(decision.action === 'approve' && decision.decisionCompleted === true, 'Workflow/Receipt', 'approval receipt proves a decision without claiming execution');
  view = await workflow(h, admin, cluster, workspace, id);
  h.check(view.state === 'approved', 'Workflow/Approval', 'approved state does not create a native credential');
  if (options.approvalOnly !== false) await h.reject(approver, endpoint(cluster, workspace, `workflows/${id}/execute`), 'POST', { revision: view.revision, planHash: view.planHash, confirmed: true, confirm_name: view.kind }, 'Workflow/Separation', 'approval authority alone cannot execute native writes');
  const executeKey = randomUUID();
  const execution = h.ok(await h.request(admin, endpoint(cluster, workspace, `workflows/${id}/execute`), 'POST', { revision: view.revision, planHash: view.planHash, confirmed: true, confirm_name: view.kind }, { key: executeKey }), 'Workflow/Execute', 'current console executor applies the exact approved plan');
  const receipt = h.ok(await h.request(admin, endpoint(cluster, workspace, `workflows/receipts/by-key/${executeKey}`)), 'Workflow/Receipt', 'original execution key resolves all step outcomes');
  h.check(receipt.state === 'succeeded' && receipt.steps.every(step => ['succeeded', 'skipped_verified'].includes(step.state)), 'Workflow/Execute', 'all immutable plan steps completed without unknown outcomes');
  h.check(receipt.steps.filter(step => step.operationId).every(step => step.remoteCompleted === true), 'Workflow/Execute', 'every native step has a durable completed mutation receipt');
  return { execution, receipt };
}
async function register(h, admin, fixture, label) {
  const tenant = { clusterId: fixture.cluster.id, workspaceId: fixture.workspace.id }, username = `${h.tag}-${label}`, password = strongPassword();
  h.secrets.push(password); h.saveReference();
  let anonymous = await h.portalCsrf(tenant);
  const response = await h.portal(anonymous, '/auth/register', 'POST', { ...tenant, username, password, email: `${username}@example.invalid`, displayName: `M6 ${label}` });
  h.check(response.status === 202, 'Auth/Register', 'developer registration returns pending review, not an authenticated session');
  const listed = h.ok(await h.request(admin, endpoint(fixture.cluster, fixture.workspace, `portal/developers?status=pending&search=${username}`)), 'Auth/Review', 'current tenant developer review list');
  const developer = rows(listed).find(row => row.username === username); h.check(Boolean(developer), 'Auth/Review', 'pending developer exists only in its exact tenant');
  await h.portalReject(anonymous, '/auth/login', 'POST', { ...tenant, username, password }, 'Auth/Pending', 'pending developer cannot authenticate', [401, 403]);
  h.ok(await h.request(admin, endpoint(fixture.cluster, fixture.workspace, `portal/developers/${developer.id}/review`), 'POST', { revision: developer.revision, status: 'active', confirmed: true, confirm_name: username }), 'Auth/Review', 'current administrator reviews the scoped developer');
  const session = await h.portalLogin(tenant, username, password, label);
  const row = { id: developer.id, username, password, label, tenant, session };
  h.saveReference({ portalUsers: [...(h.referenceData.portalUsers ?? []), row] }); return row;
}
async function credentials(h, developer, app, grant) {
  return rows(h.ok(await h.portal(developer.session, portalScope(`/applications/${app.id}/grants/${grant.id}/credentials`, developer.tenant)), 'Credential/List', 'masked current credential history'));
}
async function reveal(h, developer, app, grant, credential) {
  const response = await h.portal(developer.session, `/applications/${app.id}/grants/${grant.id}/credentials/${credential.id}/reveal`, 'POST', { ...developer.tenant, revision: credential.revision });
  const data = h.ok(response, 'Credential/Reveal', 'explicit authorized current-generation reveal');
  h.check(/no-store/i.test(response.response.headers.get('cache-control') ?? ''), 'Credential/Reveal', 'reveal response cannot enter browser/proxy caches');
  h.check(typeof data.key === 'string' && data.key.length >= 32, 'Credential/Reveal', 'current generation has a strong generated key');
  h.secrets.push(data.key); h.saveReference(); return data.key;
}
async function submitGrant(h, fixture, developer, app, publication,initialRequest) {
  const key = initialRequest?.key??randomUUID(), response = await h.portal(developer.session, '/requests', 'POST', initialRequest?.body??{ ...developer.tenant, applicationId: app.id, publicationId: publication.id, reason: 'isolated real M6 security verification' }, { key });
  const request = h.ok(response, 'Credential/Request', 'developer submits a DB-only credential request');
  const id = request.workflowId ?? request.id;
  h.check(typeof id === 'string' && request.approvalRequired === true, 'Credential/Request', 'credential issue always requires a current console approval');
  const receipt = h.ok(await h.portal(developer.session, portalScope(`/operations/by-key/${key}`, developer.tenant)), 'Credential/Receipt', 'developer original key finds its own scoped request receipt');
  h.check(receipt.state === 'succeeded' && receipt.safeResult?.workflowId === id, 'Credential/Receipt', 'submission receipt names the existing workflow and does not replay a POST');
  await h.portalReject(developer.session, `/requests/${id}`, 'POST', { ...developer.tenant, approved: true, system: true }, 'Workflow/Private', 'developer cannot mint a console execution capability', [404, 405]);
  return { request, id };
}
async function requestGrant(h, admin, approver, fixture, developer, app, publication,initialRequest) {
  const { request, id } = await submitGrant(h, fixture, developer, app, publication,initialRequest);
  await approveExecute(h, admin, approver, fixture.cluster, fixture.workspace, id);
  return observeActivatedGrant(h,fixture,developer,app,publication,request.grant.id,id);
}
// Observe an already completed workflow without requesting/approving/executing
// it again. Metadata-only recovery uses this same normal Portal read/reveal path.
export async function observeActivatedGrant(h,fixture,developer,app,publication,grantId,id,expectedCredentialId) {
  const grant = rows(h.ok(await h.portal(developer.session, portalScope(`/applications/${app.id}/grants`, developer.tenant)), 'Credential/Grant', 'current successful grant')).find(row => row.id === grantId && row.publicationId === publication.id);
  h.check(grant?.state === 'active', 'Credential/Grant', 'grant is active only after parent and native steps succeed');
  const list = await credentials(h, developer, app, grant), credential = list.find(row => row.state === 'active');
  h.check(Boolean(credential) && list.every(row => row.maskedKey === '••••••••' && !('key' in row)), 'Credential/List', 'ordinary credential history only exposes a mask');
  if(expectedCredentialId)h.check(credential.id===expectedCredentialId,'MetadataRecovery/Identity','activated credential retains its original allocated UUID');
  const apiKey = await reveal(h, developer, app, grant, credential);
  const managed = h.consoleRead('SELECT g.consumer_id,g.acl_id,c.kong_id FROM portal_application_grants g JOIN portal_credentials c ON c.grant_id=g.id WHERE c.id=$1 AND g.id=$2', [credential.id, grant.id])[0];
  h.check(Boolean(managed), 'Credential/Identity', 'successful grant has exact trusted private native identities');
  const result = { app, grant, credential, apiKey, managed, workflowId: id };
  h.saveReference({ grants: [...(h.referenceData.grants ?? []), result] }); return result;
}
async function releaseAndReapply(h, admin, approver, fixture, developer, publication, action) {
  const app = entity(h.ok(await h.portal(developer.session, '/applications', 'POST', { ...developer.tenant, name: `${h.tag} ${action} retry application` }), 'Lifecycle/Application', 'separate owned application for a terminal unused reservation'));
  const initial = await submitGrant(h, fixture, developer, app, publication);
  const old = h.consoleRead('SELECT g.consumer_id,g.acl_id,c.kong_id FROM portal_application_grants g JOIN portal_credentials c ON c.grant_id=g.id WHERE g.id=$1', [initial.request.grant.id])[0];
  h.check(Boolean(old), 'Lifecycle/Reservation', 'unissued request records its generated historical IDs privately');
  if (action === 'cancel') {
    h.ok(await h.portal(developer.session, `/requests/${initial.id}/cancel`, 'POST', { ...developer.tenant, revision: initial.request.revision }), 'Lifecycle/Cancel', 'developer cancels its pending DB-only request once');
  } else {
    const view = await workflow(h, admin, fixture.cluster, fixture.workspace, initial.id);
    h.ok(await h.request(approver, endpoint(fixture.cluster, fixture.workspace, `workflows/${initial.id}/reject`), 'POST', { revision: view.revision, planHash: view.planHash, confirmed: true, confirm_name: view.kind, reason: 'Controlled unused reservation release test', execute: false }), 'Lifecycle/Reject', 'current scoped approver rejects the unexecuted request once');
  }
  const terminal = await workflow(h, admin, fixture.cluster, fixture.workspace, initial.id);
  h.check(terminal.state === (action === 'cancel' ? 'cancelled' : 'rejected'), 'Lifecycle/Terminal', 'unused original workflow is terminal without execution');
  const absent = await h.request(admin, endpoint(fixture.cluster, fixture.workspace, `entities/consumers/${old.consumer_id}`));
  h.check(absent.status === 404, 'Lifecycle/NoNative', 'unused original reservation never created a native Consumer');
  const fresh = await requestGrant(h, admin, approver, fixture, developer, app, publication);
  const historical = rows(h.ok(await h.portal(developer.session, portalScope(`/applications/${app.id}/grants`, developer.tenant)), 'Lifecycle/History', 'old and new grant metadata remain separately visible')).find(row => row.id === initial.request.grant.id);
  h.check(historical?.reservationReleased === true && historical.state === 'disabled' && historical.generation === 0, 'Lifecycle/History', 'public released flag describes an unissued disabled reservation, never a revoked key');
  const unusedCredentials = await credentials(h, developer, app, historical);
  h.check(unusedCredentials.every(row => row.maskedKey === '••••••••' && row.capabilities.reveal === false), 'Lifecycle/History', 'unused historical credentials expose only masks and cannot be revealed');
  const proof = reservationFacts(h, initial.request.grant.id);
  h.check(releasedReservation(proof), 'Lifecycle/Release', 'old reservation is disabled and SQL-proved terminal, unbound and never issued');
  h.check(fresh.grant.id !== initial.request.grant.id && ['consumer_id', 'acl_id', 'kong_id'].every(field => fresh.managed[field] !== old[field]), 'Lifecycle/FreshIDs', 'reapplication allocates a new grant, Consumer, ACL and key-auth UUID');
  await h.reject(admin, endpoint(fixture.cluster, fixture.workspace, 'entities/consumers'), 'POST', { id: old.consumer_id, username: `${h.tag}-forbidden-${action}`, tags: [h.tag] }, 'Lifecycle/ImmutableHistory', 'unused historical Consumer UUID cannot be recreated by ordinary CRUD', [403]);
  const route = fixture.routes.find(row => row.service?.id === publication.serviceId);
  h.check(await h.waitProxy(fixture.cluster, route.paths[0], 200, { apikey: fresh.apiKey }) === 200, 'Lifecycle/Proxy', 'approved reapplication key works on the actual published Service');
  h.public.lifecycle ??= [];
  h.public.lifecycle.push({ originalWorkflowId: initial.id, originalGrantId: initial.request.grant.id, terminalState: terminal.state, newGrantId: fresh.grant.id, noOriginalNativeConsumer: true, releasedFactsVerified: true, freshNativeIds: true, actualProxySuccess: true });
  h.saveReference({ releasedReservations: [...(h.referenceData.releasedReservations ?? []), { grantId: initial.request.grant.id, workflowId: initial.id, nativeIds: old }] }); return fresh;
}

export async function runM6(h, options = {}) {
  h.requireLive();
  if (!options.publicationContinuation) h.check(!h.referenceData.liveStartedAt, 'Gate/Fresh', 'initial live fixture phase has not already run; unknown writes require receipts, not a full rerun');
  const purposes = { native_scrape: 'bff', collector_catalog: 'bff', collector_scrape: 'collector', collector_ingest: 'collector' };
  const tokens = h.referenceData.tokens ?? [];
  for (const [clusterId, generation] of [[M6_C1, 2], [M6_C2, 1]]) {
    const family = tokens.filter(row => row.clusterId === clusterId);
    h.check(family.length === 4 && Object.entries(purposes).every(([purpose, audience]) => family.filter(row => row.purpose === purpose && row.audience === audience && row.generation === generation && typeof row.token === 'string' && /^[A-Za-z0-9_-]{43,128}$/.test(row.token)).length === 1), 'Gate/Continuity', 'trusted capture contains the unchanged current four-purpose family for its exact cluster');
  }
  h.check(tokens.length === 8 && new Set(tokens.map(row => row.token)).size === 8, 'Gate/Continuity', 'both genuine clusters retain distinct current materials without enrollment or rotation');
  h.public.retainedMonitoringFamilies = [{ clusterId: M6_C1, generation: 2, purposes: 4 }, { clusterId: M6_C2, generation: 1, purposes: 4 }];
  const targets=h.referenceData.portalTestTargets;
  const portalClusterIds=targets?[targets.primary.id,targets.secondary.id]:[M6_C1,M6_C2];
  const proxyOrigin=cluster=>targets?[targets.primary,targets.secondary].find(row=>row.id===cluster.id)?.proxyOrigin:(cluster.id===M6_C1?'http://127.0.0.1:8000':'http://127.0.0.1:9000');
  if(options.isolatedStart)h.check(h.referenceData.phase==='isolatedFixtureStart'&&targets&&h.referenceData.isolatedStart?.previousCheckpointSha256,'Isolation/Start','explicit guarded new fixture checkpoint is present');
  h.public.portalTestClusters=portalClusterIds;
  let admin, clusters, fixtures, primary, secondary, otherFixture, approver, secondaryApprover, legacy, legacyKeyAuth, first, originalPublicationAttempt;
  if (options.publicationContinuation) {
    ({ admin, clusters, fixtures, primary, secondary, otherFixture, approver, secondaryApprover, legacy, legacyKeyAuth, first, attempt: originalPublicationAttempt } = await guardPublicationContinuation(h, options.proof));
    h.public.continuation = { checkpoint: 'publication-known-not-sent', preservedInitialFailure: 'security-live-pre-fix-publication-boundary.json', originalKeyReused: true, bootstrapRepeated: false };
  } else {
  h.checkpoint('bootstrap', { liveStartedAt: new Date().toISOString() });
  admin = options.isolatedStart?h.referenceData.consoleAdministrator:await h.login(process.env.BOOTSTRAP_ADMIN_USERNAME ?? 'admin', process.env.BOOTSTRAP_ADMIN_PASSWORD);
  h.saveReference({ consoleAdministrator: admin });
  const registered = rows(h.ok(await h.request(admin, '/clusters?size=100'), 'Setup/Clusters', 'registered canonical cluster list'));
  clusters = portalClusterIds.map(id => registered.find(row => row.id === id));
  h.check(clusters.every(Boolean) && clusters.every(row => row.version?.startsWith('1.5.')) && new Set(clusters.map(row => row.admin_url)).size === 2, 'Setup/Clusters', 'two genuine Kong 1.5 nodes remain independently registered');
  fixtures = [];
  for (const [index, cluster] of clusters.entries()) {
    const workspace = h.ok(await h.request(admin, `/clusters/${cluster.id}/workspaces`, 'POST', { code: `${h.tag}-c${index + 1}`, name: `${h.tag} portal ${index + 1}`, description: 'isolated M6 portal verification' }), 'Setup/Workspace', 'dedicated portal workspace');
    const tenant = { clusterId: cluster.id, workspaceId: workspace.id }, slug = `${h.tag}-c${index + 1}`;
    const fixture = { cluster, workspace, tenant, slug, publications: [], services: [], routes: [] }; fixtures.push(fixture);
    h.saveReference({ fixtures });
    fixture.settings = h.metadataEntity(h.ok(await h.request(admin, endpoint(cluster, workspace, 'portal/settings'), 'POST', { slug, name: `${h.tag} Developer Portal ${index + 1}`, publicProxyOrigin: proxyOrigin(cluster), branding: { logoText: 'KongOS Portal', primaryColor: '#1677ff' }, registrationEnabled: true, published: true }), 'Setup/Tenant', 'explicitly published tenant settings'), 'Setup/ActualObject', 'initial tenant settings');
    for (const name of index ? ['C'] : ['A', 'B', 'legacy']) {
      const service = await h.create(admin, cluster, workspace, 'services', { name: `${h.tag}-${name}`, protocol: 'http', host: 'echo-upstream', port: 8081, tags: [h.tag] }, 'Setup/Native');
      const route = await h.create(admin, cluster, workspace, 'routes', { name: `${h.tag}-${name}`, service: { id: service.id }, paths: [`/m6/${h.tag}/${name}`], protocols: ['http'], strip_path: false, tags: [h.tag] }, 'Setup/Native');
      fixture.services.push(service); fixture.routes.push(route);
      if (name === 'legacy') continue;
      const publication = h.metadataEntity(h.ok(await h.request(admin, endpoint(cluster, workspace, 'portal/publications'), 'POST', { slug: `${h.tag}-${name.toLowerCase()}`, name: `${h.tag} API ${name}`, category: 'Security verification', description: 'This publication authorizes the complete Service.', serviceId: service.id, document: { openapi: '3.0.3', info: { title: `${h.tag} API ${name}`, version: '1.0.0' }, paths: { [route.paths[0]]: { get: { responses: { 200: { description: 'Success' } } } } } } }), 'Setup/Publication', 'scoped draft OpenAPI publication'), 'Setup/ActualObject', 'initial publication');
      fixture.publications.push(publication);
    }
    h.saveReference({ fixtures });
  }
  primary = fixtures[0]; secondary = fixtures[1];
  const otherWorkspace = h.ok(await h.request(admin, `/clusters/${primary.cluster.id}/workspaces`, 'POST', { code: `${h.tag}-other`, name: `${h.tag} other tenant` }), 'Setup/Tenant', 'real second workspace within C1');
  otherFixture = { cluster: primary.cluster, workspace: otherWorkspace, tenant: { clusterId: primary.cluster.id, workspaceId: otherWorkspace.id }, slug: `${h.tag}-other`, publications: [], services: [], routes: [] };
  fixtures.push(otherFixture); h.saveReference({ fixtures });
  otherFixture.settings = h.metadataEntity(h.ok(await h.request(admin, endpoint(primary.cluster, otherWorkspace, 'portal/settings'), 'POST', { slug: otherFixture.slug, name: `${h.tag} Other Tenant`, published: true, registrationEnabled: true, publicProxyOrigin: proxyOrigin(primary.cluster) }), 'Setup/Tenant', 'independently published second-workspace tenant'), 'Setup/ActualObject', 'initial second-workspace settings');
  const support = ['workflows'].flatMap(module => ['read', 'approve'].map(action => wsGrant(primary.cluster, primary.workspace, module, action)));
  approver = await consoleAccount(h, admin, primary.cluster, primary.workspace, 'approver-only', support);
  secondaryApprover = await consoleAccount(h, admin, secondary.cluster, secondary.workspace, 'approver-c2', ['read', 'approve'].map(action => wsGrant(secondary.cluster, secondary.workspace, 'workflows', action)));
  legacy = primary.services.find(row => row.name.endsWith('-legacy'));
  legacyKeyAuth = await h.create(admin, primary.cluster, primary.workspace, 'plugins', { name: 'key-auth', service: { id: legacy.id }, enabled: true, config: { key_names: ['apikey'], hide_credentials: true }, tags: [h.tag] }, 'Boundary/Legacy');
  first = primary.publications[0];
  for (const document of [
    { openapi: '3.0.3', info: { title: 'invalid external ref', version: '1' }, paths: {}, components: { schemas: { X: { $ref: 'http://169.254.169.254/latest/meta-data' } } } },
    'openapi: 3.0.3\ninfo: &x {title: example, version: "1"}\npaths: {}\nx-copy: *x\n',
  ]) await h.reject(admin, endpoint(primary.cluster, primary.workspace, `portal/publications/${first.id}/document`), 'POST', { revision: first.revision, document }, 'Document/Validation', 'unsafe external reference or YAML alias is rejected before publication', [400]);
  }
  const unsafe = await h.reject(admin, endpoint(primary.cluster, primary.workspace, `portal/publications/${first.id}/publish`), 'POST', originalPublicationAttempt?.body ?? confirm(first), 'Boundary/CompleteGraph', 'publication refuses an unrelated key-auth chain without ACL', [403, 409], originalPublicationAttempt ? { key: originalPublicationAttempt.key } : undefined);
  h.check(unsafe.payload?.error?.code === 'PORTAL_UNMANAGED_AUTH_BOUNDARY', 'Boundary/CompleteGraph', 'publication failure names the actual full-graph authentication boundary');
  const boundaryAttempt = h.writeAttempts.at(-1);
  const boundaryReceipt = h.ok(await h.request(admin, endpoint(primary.cluster, primary.workspace, `workflows/receipts/by-key/${boundaryAttempt.key}`)), 'Boundary/Receipt', 'rejected prospective authentication boundary has an original-key durable receipt');
  h.check(boundaryReceipt.state === 'failed' && boundaryReceipt.steps.every(step => step.remoteCompleted === false && !['running','uncertain','succeeded'].includes(step.state)), 'Boundary/Receipt', 'known rejected parent has no completed or unresolved native steps');
  const boundaryCounts = h.consoleRead(`SELECT count(*) FILTER(WHERE state IN('running','uncertain'))::int AS unresolved,count(*) FILTER(WHERE remote_completed OR state='succeeded')::int AS completed FROM mutation_operations WHERE cluster_id=$1 AND (workflow_id=$2 OR request_id=$3)`, [primary.cluster.id,boundaryReceipt.workflowId,boundaryAttempt.requestId])[0];
  h.check(boundaryCounts?.unresolved === 0 && boundaryCounts.completed === 0, 'Boundary/Receipt', 'independent mutation facts confirm the rejected publication did not complete a native change');
  h.public.boundaryRefusalProof = { workflowId: boundaryReceipt.workflowId, originalKey: boundaryAttempt.key, parentState: boundaryReceipt.state, steps: boundaryReceipt.steps.map(step => ({state:step.state,remoteCompleted:step.remoteCompleted,errorCode:step.errorCode})), mutationCounts: boundaryCounts };
  h.saveReference({ boundaryRefusalProof: h.public.boundaryRefusalProof });
  const legacyAcl = await h.create(admin, primary.cluster, primary.workspace, 'plugins', { name: 'acl', service: { id: legacy.id }, enabled: true, config: { whitelist: [`${h.tag}-legacy-only`], hide_groups_header: true }, tags: [h.tag] }, 'Boundary/Legacy');
  for (const fixture of fixtures) for (const publication of fixture.publications) {
    Object.assign(publication, entity(h.ok(await h.request(admin, endpoint(fixture.cluster, fixture.workspace, `portal/publications/${publication.id}`)), 'Publication/CAS', 'fresh publication revision after a known rejected plan')));
    h.ok(await h.request(admin, endpoint(fixture.cluster, fixture.workspace, `portal/publications/${publication.id}/publish`), 'POST', confirm(publication)), 'Publication/Publish', 'ACL then key-auth then successful publication metadata');
    const current = entity(h.ok(await h.request(admin, endpoint(fixture.cluster, fixture.workspace, `portal/publications/${publication.id}`)), 'Publication/Read', 'current published state'));
    h.check(current.status === 'published', 'Publication/Read', 'publication is public only after the terminal successful parent'); Object.assign(publication, current);
  }
  h.checkpoint('portal-publications-published', { fixtures });
  const plugins = rows(h.ok(await h.request(admin, endpoint(primary.cluster, primary.workspace, 'entities/plugins?size=100')), 'Boundary/ZeroKey', 'zero-key publication native plugin readback'));
  const protectedAcl = plugins.find(row => row.name === 'acl' && row.service?.id === primary.services[0].id);
  h.check(Boolean(protectedAcl), 'Boundary/ZeroKey', 'published zero-key API already has its ACL baseline');
  await h.reject(admin, endpoint(primary.cluster, primary.workspace, `entities/plugins/${protectedAcl.id}`), 'PATCH', { enabled: false }, 'Boundary/ZeroKey', 'generic mutation cannot remove a zero-key publication baseline', [403, 409]);
  const developer = await register(h, admin, primary, 'developer-a'), other = await register(h, admin, primary, 'developer-b'), c2Developer = await register(h, admin, secondary, 'developer-c2');
  for (const current of [developer, other, c2Developer]) {
    const refreshed = await h.portalCsrf(current.tenant, current.session);
    const response = await h.portal(refreshed, '/auth/refresh', 'POST', current.tenant);
    const data = h.ok(response, 'Auth/Reload', 'CSRF bootstrap plus scoped refresh works after memory reset');
    current.session = { ...refreshed, cookie: cookieMerge(refreshed.cookie, response.response.headers.getSetCookie()), csrf: data.csrfToken, developer: data.developer };
    h.rememberCookies(current.session.cookie); h.secrets.push(current.session.csrf); h.saveReference();
    const me = h.ok(await h.portal(current.session, portalScope('/auth/me', current.tenant)), 'Auth/Reload', 'refreshed portal cookie authenticates its unchanged developer');
    h.check(me.id === current.id, 'Auth/Reload', 'refresh never changes actor or tenant');
  }
  await h.portalReject(developer.session, portalScope('/auth/me', secondary.tenant), 'GET', undefined, 'Auth/Tenant', 'current developer JWT cannot escape to another cluster');
  await h.portalReject(developer.session, portalScope('/auth/me', otherFixture.tenant), 'GET', undefined, 'Auth/Tenant', 'current developer JWT cannot escape to another actual workspace');
  await h.portalReject({ cookie: admin.cookie, csrf: admin.csrf }, portalScope('/auth/me', primary.tenant), 'GET', undefined, 'Auth/Issuer', 'console access cookie cannot authenticate a portal developer', [401]);
  await h.reject({ cookie: developer.session.cookie, csrf: developer.session.csrf }, '/auth/me', 'GET', undefined, 'Auth/Issuer', 'portal access cookie cannot authenticate a console administrator', [401]);
  await h.portalReject(developer.session, '/applications', 'POST', { ...developer.tenant, name: 'forbidden', superAdmin: true }, 'Auth/StrictDTO', 'portal mass assignment cannot inject console authority', [400]);
  await h.portalReject(developer.session, '/applications', 'POST', { ...developer.tenant, name: 'forbidden' }, 'Auth/CSRF', 'portal writes reject a wrong CSRF value', [403], { headers: { 'X-Portal-CSRF': randomUUID() } });
  const app = entity(h.ok(await h.portal(developer.session, '/applications', 'POST', { ...developer.tenant, name: `${h.tag} Application A`, description: 'isolated key-per-publication test' }), 'Application/Create', 'developer creates its own application'));
  const c2App = entity(h.ok(await h.portal(c2Developer.session, '/applications', 'POST', { ...c2Developer.tenant, name: `${h.tag} Application C2` }), 'Application/Create', 'independent C2 developer application'));
  await h.portalReject(other.session, portalScope(`/applications/${app.id}`, other.tenant), 'GET', undefined, 'Application/IDOR', 'another developer cannot read an existing application', [404]);
  return finishM6CredentialFlow(h,{admin,fixtures,primary,secondary,otherFixture,approver,secondaryApprover,developer,other,c2Developer,app,c2App,legacyKeyAuth,legacyAcl});
}

export async function firstM6Grant(h,context){
  if(context.recoveredFirstGrant){
    const recovery=h.referenceData.metadataRecovery,a=context.recoveredFirstGrant;
    h.check(context.metadataRecoveryVerified===true&&recovery?.phase==='metadata-succeeded-original-execution'&&recovery.receiptState==='succeeded'&&a.workflowId===recovery.workflowId&&a.grant.id===recovery.grantId&&a.credential.id===recovery.credentialId&&a.app.id===context.app.id,'MetadataRecovery/Resume','first grant is observed from the original completed execution, never submitted or executed again');
    return a;
  }
  h.check(!h.referenceData.metadataRecovery&&!context.metadataRecoveryVerified,'MetadataRecovery/Replay','an interrupted metadata recovery cannot fall back to a new first request');
  return requestGrant(h,context.admin,context.approver.session,context.primary,context.developer,context.app,context.primary.publications[0],context.initialRequest);
}
export async function secondM6Grant(h,context){
  const recovery=h.referenceData.failedIssueContinuation;
  if(context.secondInitialRequest){
    const intended=context.secondInitialRequest;
    h.check(context.failedIssueRecoveryVerified===true&&recovery?.phase==='reservation-abandoned'&&recovery.certificateId&&recovery.newRequest?.state==='not_sent'&&recovery.newRequest.idempotencyKey===intended.key&&JSON.stringify(recovery.newRequest.body)===JSON.stringify(intended.body)&&intended.body.applicationId===context.app.id&&intended.body.publicationId===context.primary.publications[1].id&&intended.key!==recovery.originalExecutionKey,'FailedIssue/Resume','a new same-app second publication request is admitted only after certified closure, never by replaying the failed execution');
    const previouslyCaptured=new Set(h.secrets);
    h.saveReference({failedIssueContinuation:{...recovery,phase:'new-second-request-started',newRequest:{...recovery.newRequest,state:'started'}}});
    const result=await requestGrant(h,context.admin,context.approver.session,context.primary,context.developer,context.app,context.primary.publications[1],intended);
    h.check(result.grant.id!==recovery.grantId&&result.credential.id!==recovery.credentialId&&result.workflowId!==recovery.workflowId&&['consumer_id','acl_id','kong_id'].every(field=>!Object.values(context.before).includes(result.managed[field]))&&!previouslyCaptured.has(result.apiKey),'FailedIssue/Fresh','new approved issue uses entirely fresh allocated identities and generated Key');
    const consumer=entity(h.ok(await h.request(context.admin,endpoint(context.primary.cluster,context.primary.workspace,`entities/consumers/${result.managed.consumer_id}`)),'FailedIssue/CustomId','actual new app-publication Consumer readback'));
    h.check(consumer.custom_id===result.grant.id,'FailedIssue/CustomId','new Consumer custom_id is grant-unique instead of reusing the application ID');
    h.saveReference({failedIssueContinuation:{...h.referenceData.failedIssueContinuation,phase:'new-second-issue-complete',newWorkflowId:result.workflowId,newGrantId:result.grant.id,newCredentialId:result.credential.id}});
    return result;
  }
  h.check(!recovery&&!context.failedIssueRecoveryVerified,'FailedIssue/Replay','an interrupted failed-issue continuation cannot fall back to a duplicate new request');
  return requestGrant(h,context.admin,context.approver.session,context.primary,context.developer,context.app,context.primary.publications[1]);
}
export async function finishM6CredentialFlow(h,context){
  const {admin,fixtures,primary,secondary,otherFixture,approver,secondaryApprover,developer,other,c2Developer,app,c2App,legacyKeyAuth,legacyAcl,initialRequest}=context;
  const a = await firstM6Grant(h,context);
  const b = await secondM6Grant(h,context);
  const c = await requestGrant(h, admin, secondaryApprover.session, secondary, c2Developer, c2App, secondary.publications[0]);
  h.checkpoint('dual-cluster-approved-credentials');
  await h.reject(approver.session, endpoint(secondary.cluster, secondary.workspace, `workflows/${c.workflowId}`), 'GET', undefined, 'Workflow/Scope', 'C1 approval grant cannot read an actual C2 workflow');
  const pathA = primary.routes[0].paths[0], pathB = primary.routes[1].paths[0], pathLegacy = primary.routes[2].paths[0], pathC = secondary.routes[0].paths[0];
  h.check(a.apiKey !== b.apiKey && b.apiKey !== c.apiKey, 'Proxy/Independent', 'application-publication grants have independent generated keys');
  for (const [fixture, path, apiKey] of [[primary, pathA, a.apiKey], [primary, pathB, b.apiKey], [secondary, pathC, c.apiKey]]) h.check(await h.waitProxy(fixture.cluster, path, 200, { apikey: apiKey }) === 200, 'Proxy/Actual', 'approved credential authenticates only its published Service');
  for (const [cluster, path, apiKey] of [[primary.cluster, pathB, a.apiKey], [primary.cluster, pathA, b.apiKey], [primary.cluster, pathLegacy, a.apiKey], [primary.cluster, pathLegacy, b.apiKey]]) h.check(await h.waitProxy(cluster, path, 403, { apikey: apiKey }) === 403, 'Proxy/ACL', 'real Kong ACL denies another publication or legacy Service');
  for (const [cluster, path, apiKey] of [[secondary.cluster, pathC, a.apiKey], [primary.cluster, pathA, c.apiKey]]) h.check(await h.waitProxy(cluster, path, 401, { apikey: apiKey }) === 401, 'Proxy/Cluster', 'independent Kong cluster does not recognize another cluster credential');
  await h.portalReject(other.session, `/applications/${app.id}/grants/${a.grant.id}/credentials/${a.credential.id}/reveal`, 'POST', { ...other.tenant, revision: a.credential.revision }, 'Credential/IDOR', 'foreign developer cannot reveal an existing credential', [404]);
  const managed = h.consoleRead('SELECT consumer_id,kong_id FROM portal_credentials WHERE id=$1', [a.credential.id])[0];
  h.check(Boolean(managed), 'Boundary/Ownership', 'current grant has trusted private native identifiers');
  await h.reject(admin, endpoint(primary.cluster, primary.workspace, `consumers/${managed.consumer_id}/credentials/key-auth`), 'POST', { key: `Aa7!${randomUUID()}` }, 'Boundary/Ownership', 'generic credentials cannot mint a key on a managed Consumer', [403]);
  const duplicate = await h.reject(admin, '/clusters', 'POST', { name: `${h.tag}-duplicate-endpoint`, environment: 'security-test', admin_url: primary.cluster.admin_url, labels: [h.tag], execution_mode: 'direct' }, 'Boundary/Alias', 'registry rejects a second registration of the same physical endpoint', [409]);
  h.check(duplicate.payload?.error?.code === 'CLUSTER_ENDPOINT_EXISTS', 'Boundary/Alias', 'duplicate endpoint is rejected before an alias registry or workspace can exist');
  h.public.physicalAliasOwnershipProof = { duplicateRegistrationPrevented: true, duplicateStatus: duplicate.status, aliasCreated: false, actualManagedConsumerWriteDenied: true, independentPhysicalScopeCoverage: 'offline integration tests; no actual alias was created' };
  for (const body of [{ enabled: false, workflowId: a.workflowId }, { enabled: false, approved: true }, { enabled: false, handle: { approved: true }, system: true }]) await h.reject(approver.session, endpoint(primary.cluster, primary.workspace, `entities/plugins/${legacyKeyAuth.id}`), 'PATCH', body, 'Workflow/Private', 'raw HTTP identifiers and flags never mint an approved capability', [400, 403]);
  captureHistoricalKeyCipherBeforeRetirement(h,context,a);
  const rotation = h.ok(await h.portal(developer.session, `/applications/${app.id}/grants/${a.grant.id}/credentials/${a.credential.id}/rotate`, 'POST', { ...developer.tenant, revision: a.credential.revision, confirmed: true, confirm_name: `轮换 ${a.credential.id}` }), 'Credential/Rotate', 'rotation compiles a sealed new-key then old-key recycle plan');
  await approveExecute(h, admin, approver.session, primary.cluster, primary.workspace, rotation.workflowId ?? rotation.id);
  const rotated = (await credentials(h, developer, app, a.grant)).find(row => row.state === 'active');
  const newKey = await reveal(h, developer, app, a.grant, rotated);
  h.check(newKey !== a.apiKey && rotated.generation === a.credential.generation + 1, 'Credential/Rotate', 'new generation uses a different key without restoring the old ID');
  h.check(await h.waitProxy(primary.cluster, pathA, 401, { apikey: a.apiKey }) === 401, 'Credential/Rotate', 'retired generation fails actual Kong authentication after bounded propagation');
  h.check(await h.waitProxy(primary.cluster, pathA, 200, { apikey: newKey }) === 200, 'Credential/Rotate', 'new generation succeeds on the same published Service');
  const revocation = h.ok(await h.portal(developer.session, `/applications/${app.id}/grants/${a.grant.id}/credentials/${rotated.id}/revoke`, 'POST', { ...developer.tenant, revision: rotated.revision, confirmed: true, confirm_name: `吊销 ${rotated.id}`, retireConsumer: true }), 'Credential/Revoke', 'approved retirement archives key then ACL then its test-owned Consumer');
  await approveExecute(h, admin, approver.session, primary.cluster, primary.workspace, revocation.workflowId ?? revocation.id);
  const after = (await credentials(h, developer, app, a.grant)).find(row => row.id === rotated.id);
  h.check(after.state === 'revoked' && !after.capabilities.reveal, 'Credential/Revoke', 'revoked credential cannot be revealed or re-enabled');
  h.check(await h.waitProxy(primary.cluster, pathA, 401, { apikey: newKey }) === 401, 'Credential/Revoke', 'revoked key fails actual Kong authentication');
  const archived = h.consoleRead('SELECT recycle_entry_id FROM portal_credentials WHERE id=$1', [rotated.id])[0];
  const bin = h.ok(await h.request(admin, endpoint(primary.cluster, primary.workspace, `recycle-bin/${archived.recycle_entry_id}`)), 'Credential/Archive', 'revocation retains the encrypted historical archive');
  const deniedRestore = await h.request(admin, endpoint(primary.cluster, primary.workspace, `recycle-bin/${archived.recycle_entry_id}/restore`), 'POST', { confirmed: true, confirm_name: bin.entry.root_name });
  await assertRetiredKeyRestoreDenial(h, { ...context, a, b, c, rotated, newKey }, deniedRestore, archived.recycle_entry_id);
  return finishM6LifecycleTail(h, context, { a, b, c, rotated, newKey });
}
export async function finishM6LifecycleTail(h, context, settled) {
  const { admin, fixtures, primary, secondary, approver, developer, other, c2Developer, app, legacyKeyAuth, legacyAcl } = context;
  const { a, b, c, rotated, newKey } = settled;
  const pathA = primary.routes[0].paths[0];
  h.check(await h.waitProxy(primary.cluster, pathA, 401, { apikey: newKey }) === 401, 'Credential/History', 'denied restore leaves the historical key unusable');
  h.checkpoint('actual-proxy-isolation-rotation-retirement');
  const oldConsumerEntry = rows(h.ok(await h.request(admin, endpoint(primary.cluster, primary.workspace, 'recycle-bin?size=100')), 'Lifecycle/Archive', 'bounded historical Consumer archive discovery')).find(row => row.root_type === 'consumers' && row.original_id === a.managed.consumer_id);
  h.check(Boolean(oldConsumerEntry), 'Lifecycle/Archive', 'sealed retirement retains the old managed Consumer archive');
  const identityResponse = await h.request(admin, endpoint(primary.cluster, primary.workspace, 'entities/consumers'), 'POST', { id: a.managed.consumer_id, username: `${h.tag}-retired-consumer-identity`, tags: [h.tag] });
  await proveManagedConsumerIdentityDenied(h, { ...context, ...settled }, identityResponse);
  h.public.historicalConsumerProtection = { actualMethod: 'POST', actualEndpoint: 'entities/consumers', reusedManagedUUIDDenied: true, wholeConsumerRecycleRestoreExecuted: false, deferredAcceptance: 'M8 requires DB-only historical ownership preflight before recycle/import callbacks and real whole-graph restore denial.' };
  const reissued = await requestGrant(h, admin, approver.session, primary, developer, app, primary.publications[0]);
  h.check(reissued.grant.id !== a.grant.id && ['consumer_id', 'acl_id', 'kong_id'].every(field => reissued.managed[field] !== a.managed[field]) && reissued.apiKey !== a.apiKey && reissued.apiKey !== newKey, 'Lifecycle/Reissue', 'revoked grant permits a new grant with all-new IDs and key, preserving old history');
  h.check(await h.waitProxy(primary.cluster, pathA, 200, { apikey: reissued.apiKey }) === 200, 'Lifecycle/Reissue', 'approved fresh key works after normal retirement');
  for (const retiredKey of [a.apiKey, newKey]) h.check(await h.waitProxy(primary.cluster, pathA, 401, { apikey: retiredKey }) === 401, 'Lifecycle/Reissue', 'each old key remains rejected after a fresh grant is active');
  const cancelledRetry = await releaseAndReapply(h, admin, approver.session, primary, developer, primary.publications[0], 'cancel');
  const rejectedRetry = await releaseAndReapply(h, admin, approver.session, primary, developer, primary.publications[1], 'reject');
  h.public.fixturesForBrowser = { clusterId: primary.cluster.id, workspaceId: primary.workspace.id, tenantSlug: primary.slug, secondaryClusterId: secondary.cluster.id, secondaryWorkspaceId: secondary.workspace.id, secondaryTenantSlug: secondary.slug, applicationId: app.id, publicationId: primary.publications[0].id, activePublicationId: primary.publications[1].id, activeGrantId: b.grant.id, activeCredentialId: b.credential.id };
  h.public.portalDeveloperIds = [developer.id, other.id, c2Developer.id];
  h.checkpoint('HTTP-complete', { fixtures, grants: [a, b, c, reissued, cancelledRetry, rejectedRetry], legacyPlugins: [legacyKeyAuth, legacyAcl], browser: h.public.fixturesForBrowser });
  h.verifyAuditCoverage();
  h.verifyAppendOnlyStorage();
  h.public.runtimeLogRedaction = verifyM6RuntimeLogs(h);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.env.M6_DEPLOYMENT_READY !== 'true') throw new Error('M6_DEPLOYMENT_READY handoff is required; source-only phase performs no requests');
  const h = new M6Harness({ requireReference: true }); let failure;
  try { await runM6(h); } catch (error) { failure = error; }
  process.exitCode = await h.finish(failure);
}
