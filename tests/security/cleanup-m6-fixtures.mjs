import { writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { M6Harness, entity, rows, scope, portalScope, reservationFacts, releasedReservation } from './lib/m6-harness.mjs';
import { approveExecute } from './live-m6.mjs';
import { fixtureRuns } from './lib/m6-fixture-runs.mjs';
import { certifiedAbandonedReservation } from './lib/m6-abandoned-reservation-proof.mjs';
import { FAILED_ISSUE_TUPLE } from './lib/m6-failed-issue-key-capture.mjs';

// This tool has no native HTTP or SQL mutation exit. Root releases cleanup only
// after every browser/manual writer returns the sole window.
if (process.env.M6_CLEANUP_READY !== 'true' || process.env.M6_DEPLOYMENT_READY !== 'true') throw new Error('explicit M6 cleanup write-window handoff is required');
const h = new M6Harness({ requireReference: true });
const retained = [], archives = [], metadata = [], pendingWorkspaces = [];
let failure;
const endpoint = (fixture, path) => scope(`/clusters/${fixture.cluster.id}/${path}`, fixture.workspace);
async function pages(session, path, tenant, portal = false) {
  const result = []; let cursor;
  for (let page = 0; page < 100; page++) {
    const query = portal ? portalScope(path, tenant) : path, url = new URL(query, 'http://private.invalid');
    url.searchParams.set('size', '100'); if (cursor) url.searchParams.set('cursor', cursor);
    const response = portal ? await h.portal(session, url.pathname + url.search) : await h.request(session, url.pathname + url.search);
    const data = h.ok(response, 'Cleanup/Read', 'bounded authoritative cleanup discovery'); result.push(...rows(data));
    if (!data.nextCursor) return result; cursor = data.nextCursor;
  }
  h.check(false, 'Cleanup/Budget', 'cleanup discovery must complete inside its bounded page budget');
}
try {
  h.check(h.referenceData.phase === 'HTTP-complete' && Array.isArray(h.referenceData.fixtures), 'Cleanup/Guard', 'known real fixture checkpoint is present');
  const runs=fixtureRuns(h.referenceData);
  const fixtures=runs.flatMap(run=>run.fixtures.map(fixture=>({...fixture,ownedTestTag:run.testTag,ownedPortalUsers:run.portalUsers})));
  const accounts=[...new Map(runs.flatMap(run=>Object.values(run.accounts)).map(account=>[account.user.id,account])).values()];
  const aliases=[...new Map(runs.flatMap(run=>run.physicalAliases).map(alias=>[alias.cluster.id,alias])).values()];
  h.check(runs.length>=1,'Cleanup/History','all immutable prior and current test runs are included without changing their snapshots');
  const admin = await h.login(process.env.BOOTSTRAP_ADMIN_USERNAME ?? 'admin', process.env.BOOTSTRAP_ADMIN_PASSWORD);
  for (const fixture of fixtures) {
    // Only the explicit test-owned workspace is eligible. Canonical clusters,
    // monitoring providers, current settings and purpose materials are retained.
    h.check(fixture.workspace.code.startsWith(fixture.ownedTestTag), 'Cleanup/Ownership', 'workspace is explicitly owned by its captured M6 test attempt');
    const owners = fixture.ownedPortalUsers.filter(row => row.tenant.clusterId === fixture.cluster.id && row.tenant.workspaceId === fixture.workspace.id);
    for (const owner of owners) {
      const developers = await pages(admin, endpoint(fixture, `portal/developers?search=${encodeURIComponent(owner.username)}`));
      let developer = developers.find(row => row.id === owner.id);
      h.check(Boolean(developer), 'Cleanup/Developer', 'cleanup developer identity matches its captured owner');
      if (developer.status !== 'active') {
        h.ok(await h.request(admin, endpoint(fixture, `portal/developers/${developer.id}/review`), 'POST', { revision: developer.revision, status: 'active', confirmed: true, confirm_name: developer.username }), 'Cleanup/Developer', 'audited temporary activation permits its own retirement request');
      }
      const session = await h.portalLogin(owner.tenant, owner.username, owner.password, `${owner.label}-cleanup`);
      const apps = await pages(session, '/applications?state=all', owner.tenant, true);
      for (const app of apps) {
        if (app.state === 'archived') continue;
        const grants = await pages(session, `/applications/${app.id}/grants`, owner.tenant, true);
        for (const grant of grants) {
          if (grant.state === 'disabled') {
            h.check(grant.reservationReleased === true && grant.generation === 0, 'Cleanup/Release', 'API identifies a released unused reservation rather than arbitrary disabled state');
            if(grant.id===FAILED_ISSUE_TUPLE.grantId){
              const certified=await certifiedAbandonedReservation(h,admin,fixture,grant);
              metadata.push({type:'certified-failed-issue-history-retained',id:grant.id,certificateId:certified.certificateId});continue;
            }
            const proof = reservationFacts(h, grant.id);
            h.check(releasedReservation(proof), 'Cleanup/Release', 'disabled reservation is released only with exact no-execution/no-issued native facts');
            const absent = await h.request(admin, endpoint(fixture, `entities/consumers/${proof.consumer_id}`));
            h.check(absent.status === 404, 'Cleanup/Release', 'released reservation has no native Consumer to delete');
            metadata.push({ type: 'released-reservation-history-retained', id: grant.id }); continue;
          }
          h.check(!['pending', 'rotating', 'revoking'].includes(grant.state), 'Cleanup/Known', 'unfinished grant requires original receipt, not cleanup replay');
          if (grant.state === 'active') {
            const credentials = await pages(session, `/applications/${app.id}/grants/${grant.id}/credentials`, owner.tenant, true);
            const credential = credentials.find(row => row.state === 'active'); h.check(Boolean(credential), 'Cleanup/Retire', 'active grant has exactly its captured current generation');
            const key = randomUUID();
            const request = h.ok(await h.portal(session, `/applications/${app.id}/grants/${grant.id}/credentials/${credential.id}/revoke`, 'POST', { ...owner.tenant, revision: credential.revision, confirmed: true, confirm_name: `吊销 ${credential.id}`, retireConsumer: true, reason: 'Explicit approved retirement of the owned M6 verification fixture.' }, { key }), 'Cleanup/Retire', 'sealed retirement request archives Key, ACL and Consumer');
            await approveExecute(h, admin, admin, fixture.cluster, fixture.workspace, request.workflowId ?? request.id, { approvalOnly: false });
            archives.push({ type: 'portal-grant-retirement', grantId: grant.id, credentialId: credential.id });
          } else h.check(grant.state === 'revoked', 'Cleanup/Known', 'historical grant is terminal revoked');
          const native = h.consoleRead('SELECT consumer_id FROM portal_application_grants WHERE id=$1', [grant.id])[0];
          const absent = await h.request(admin, endpoint(fixture, `entities/consumers/${native.consumer_id}`));
          h.check(absent.status === 404, 'Cleanup/Retire', 'approved retirement removed the test Consumer; generic managed deletion was not used');
        }
        const current = entity(h.ok(await h.portal(session, portalScope(`/applications/${app.id}`, owner.tenant)), 'Cleanup/Application', 'fresh application revision'));
        h.ok(await h.portal(session, `/applications/${app.id}`, 'DELETE', { ...owner.tenant, revision: current.revision, confirmed: true, confirm_name: current.name }), 'Cleanup/Application', 'application is soft archived after all grants are revoked');
        metadata.push({ type: 'portal-application', id: app.id });
      }
      developer = (await pages(admin, endpoint(fixture, `portal/developers?search=${encodeURIComponent(owner.username)}`))).find(row => row.id === owner.id);
      h.ok(await h.request(admin, endpoint(fixture, `portal/developers/${owner.id}/review`), 'POST', { revision: developer.revision, status: 'disabled', confirmed: true, confirm_name: developer.username }), 'Cleanup/Developer', 'developer is disabled and sessions revoked while immutable history remains');
      metadata.push({ type: 'portal-developer-disabled', id: owner.id });
    }
    for (const publication of await pages(admin, endpoint(fixture, 'portal/publications'))) {
      let current = entity(h.ok(await h.request(admin, endpoint(fixture, `portal/publications/${publication.id}`)), 'Cleanup/Publication', 'fresh publication metadata'));
      if (current.status === 'published') {
        h.ok(await h.request(admin, endpoint(fixture, `portal/publications/${current.id}/unpublish`), 'POST', { revision: current.revision, confirmed: true, confirm_name: current.name }), 'Cleanup/Publication', 'publication is withdrawn after approved credential retirement');
        current = entity(h.ok(await h.request(admin, endpoint(fixture, `portal/publications/${current.id}`)), 'Cleanup/Publication', 'fresh withdrawn revision'));
      }
      h.ok(await h.request(admin, endpoint(fixture, `portal/publications/${current.id}`), 'DELETE', { revision: current.revision, confirmed: true, confirm_name: current.name }), 'Cleanup/Publication', 'publication metadata enters its console recycle state');
      metadata.push({ type: 'portal-publication', id: current.id });
    }
    for (const page of await pages(admin, endpoint(fixture, 'portal/pages'))) {
      const current = entity(h.ok(await h.request(admin, endpoint(fixture, `portal/pages/${page.id}`)), 'Cleanup/Page', 'fresh page metadata'));
      h.ok(await h.request(admin, endpoint(fixture, `portal/pages/${current.id}`), 'DELETE', { revision: current.revision, confirmed: true, confirm_name: current.title }), 'Cleanup/Page', 'owned Markdown page is soft archived');
      metadata.push({ type: 'portal-page', id: current.id });
    }
    const settings = h.ok(await h.request(admin, endpoint(fixture, 'portal/settings')), 'Cleanup/Settings', 'fresh owned portal settings').settings;
    h.ok(await h.request(admin, endpoint(fixture, 'portal/settings'), 'PATCH', { revision: settings.revision, published: false, registrationEnabled: false }), 'Cleanup/Settings', 'owned portal is hidden and closed to new registration');
    for (const service of fixture.services) {
      const exists = await h.request(admin, endpoint(fixture, `entities/services/${service.id}`));
      if (exists.status === 404) continue;
      const current = entity(h.ok(exists, 'Cleanup/Native', 'fresh owned Service'));
      const archived = await h.archive(admin, fixture.cluster, fixture.workspace, 'services', current, 'Cleanup/Native'); archives.push({ type: 'services', id: current.id, recycleEntryId: archived.id });
    }
    // Include other explicitly captured browser/manual native roots, while
    // avoiding duplicate deletes of children already captured in Service graphs.
    for (const root of h.journal.filter(row => row.clusterId === fixture.cluster.id && row.workspaceId === fixture.workspace.id && !['services', 'routes', 'plugins'].includes(row.type))) {
      const response = await h.request(admin, endpoint(fixture, `entities/${root.type}/${root.id}`)); if (response.status === 404) continue;
      const current = entity(h.ok(response, 'Cleanup/Native', 'fresh additional owned root'));
      archives.push({ type: root.type, id: root.id, recycleEntryId: (await h.archive(admin, fixture.cluster, fixture.workspace, root.type, current, 'Cleanup/Native')).id });
    }
    pendingWorkspaces.push({ cluster: fixture.cluster, workspace: fixture.workspace });
    retained.push({ clusterId: fixture.cluster.id, reason: 'Gateway infrastructure remains registered; canonical monitoring providers, plugins/settings and material generations remain active.' });
  }
  for (const account of accounts) {
    const bindings = rows(h.ok(await h.request(admin, `/iam/users/${account.user.id}/role-bindings?clusterId=${account.role.cluster_id}&workspaceId=${account.role.workspace_id}`), 'Cleanup/IAM', 'current scoped fixture bindings'));
    for (const binding of bindings.filter(row => row.status === 'active')) h.ok(await h.request(admin, `/iam/users/${account.user.id}/role-bindings/${binding.id}`, 'DELETE', { revision: binding.revision, confirmed: true, confirm_name: binding.role_name }), 'Cleanup/IAM', 'fixture binding is revoked with current revision');
    const user = h.ok(await h.request(admin, `/iam/users/${account.user.id}`), 'Cleanup/IAM', 'current ordinary user metadata');
    h.ok(await h.request(admin, `/iam/users/${user.id}`, 'DELETE', { revision: user.revision, confirmed: true, confirm_name: user.username }), 'Cleanup/IAM', 'ordinary console fixture user is soft deleted');
    const role = h.ok(await h.request(admin, `/iam/roles/${account.role.id}`), 'Cleanup/IAM', 'current ordinary role metadata');
    h.ok(await h.request(admin, `/iam/roles/${role.id}`, 'DELETE', { revision: role.revision, confirmed: true, confirm_name: role.name }), 'Cleanup/IAM', 'ordinary fixture role is soft deleted');
  }
  for (const alias of aliases) {
    const workspace = h.ok(await h.request(admin, `/clusters/${alias.cluster.id}/workspaces/${alias.workspace.id}`), 'Cleanup/Alias', 'fresh empty physical alias workspace');
    h.ok(await h.request(admin, `/clusters/${alias.cluster.id}/workspaces/${workspace.id}`, 'DELETE', { revision: workspace.revision, confirmed: true, confirm_name: workspace.name }), 'Cleanup/Alias', 'owned empty alias workspace is soft deleted');
    const cluster = h.ok(await h.request(admin, `/clusters/${alias.cluster.id}`), 'Cleanup/Alias', 'fresh alias registry metadata');
    h.ok(await h.request(admin, `/clusters/${alias.cluster.id}`, 'DELETE', { revision: cluster.revision, confirmed: true, confirm_name: cluster.name }), 'Cleanup/Alias', 'test alias is audited soft deleted without touching canonical Kong');
    metadata.push({ type: 'cluster-alias', id: cluster.id });
  }
  for (const item of pendingWorkspaces) {
    const workspace = h.ok(await h.request(admin, `/clusters/${item.cluster.id}/workspaces/${item.workspace.id}`), 'Cleanup/Workspace', 'fresh empty workspace metadata after IAM revocation');
    h.ok(await h.request(admin, `/clusters/${item.cluster.id}/workspaces/${workspace.id}`, 'DELETE', { revision: workspace.revision, confirmed: true, confirm_name: workspace.name }), 'Cleanup/Workspace', 'empty owned workspace is soft deleted');
    metadata.push({ type: 'workspace', id: workspace.id });
  }
  h.verifyAuditCoverage(); h.saveReference({ phase: 'cleanup-complete' });
} catch (error) { failure = error; h.saveReference(); }
const report = { performedAt: new Date().toISOString(), allPassed: !failure, passed: h.checks.filter(row => row.passed).length, failed: failure ? 1 : 0, checks: h.checks, archives, metadata, retainedInfrastructure: retained, auditCoverage: h.public.auditCoverage, nativeOrKongDatabaseCleanupUsed: false, ...(failure ? { failure: failure.safeEvidenceMessage ? failure.message : `Unexpected ${failure.name}; sensitive detail withheld`, lastHttpRequest: h.lastEvidenceRequest } : {}) };
writeFileSync('artifacts/M6/failed-fixture-cleanup.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ allPassed: report.allPassed, passed: report.passed, failed: report.failed, archivedRoots: archives.length, softMetadata: metadata.length }));
process.exitCode = report.allPassed ? 0 : 1;
