import { readFileSync, writeFileSync } from 'node:fs';
import { M4Harness, entity, rows, scope } from './lib/m4-harness.mjs';

// Root-authorized cleanup of failed M4 attempts only. Final successful fixtures
// remain available for the browser/manual gate; every native deletion is BFF
// archival, and IAM users are soft-deleted with current revisions.
const h = new M4Harness();
const reference = JSON.parse(readFileSync(h.reference, 'utf8'));
h.users = reference.users;
const archived = [], removedUsers = [], skippedAbsent = [];
let failure;
try {
  h.check(process.env.M4_DEPLOYMENT_READY === 'true', 'Cleanup', 'patched runtime handoff required');
  const reports = process.argv.slice(2).map(path => JSON.parse(readFileSync(path, 'utf8')));
  h.check(reports.length > 0 && reports.every(report => report.failed > 0 && /^m4-security-[\da-f]{8}$/.test(report.testTag)), 'Cleanup', 'only identified failed test-owned attempts may be cleaned');
  const admin = await h.login(process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', process.env.BOOTSTRAP_ADMIN_PASSWORD);
  const seen = new Set();
  const priority = ['services', 'consumers', 'upstreams', 'certificates', 'ca_certificates', 'snis', 'routes', 'plugins'];
  for (const report of reports) {
    const legacyFixtures = [];
    // A late failure can occur after controlled legacy fixtures were installed
    // but before their normal archival. Discover only the three exact owned
    // roots, through bounded BFF pages in that report's secondary workspace.
    if (report.secondaryClusterId && report.secondaryPayWorkspaceId && report.checks.some(check => check.passed && check.name.includes('controlled backend test process installs an isolated legacy'))) {
      const expected = new Set([`${report.testTag}-legacy-admin-direct`, `${report.testTag}-legacy-admin-pooled`, `${report.testTag}-legacy-admin-upstream`]);
      for (const type of ['services', 'upstreams']) {
        let cursor;
        for (let page = 0; page < 10; page++) {
          const response = h.ok(await h.request(admin, scope(`/clusters/${report.secondaryClusterId}/entities/${type}`, { id: report.secondaryPayWorkspaceId }, { tags: report.testTag, size: 20, cursor })), 'Cleanup', 'bounded exact failed-run legacy fixture discovery');
          for (const value of rows(response)) if (expected.has(value.name) && value.tags?.includes(report.testTag)) legacyFixtures.push({ clusterId: report.secondaryClusterId, workspaceId: report.secondaryPayWorkspaceId, type, id: value.id, name: value.name, createdThrough: 'controlled-legacy-fixture' });
          cursor = response.nextCursor;
          if (!cursor) break;
          h.check(page < 9, 'Cleanup', 'controlled legacy lookup stays within its page budget');
        }
      }
    }
    for (const fixture of [...report.fixtures, ...legacyFixtures].sort((a, b) => priority.indexOf(a.type) - priority.indexOf(b.type))) {
      const key = `${fixture.clusterId}:${fixture.type}:${fixture.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      h.check((fixture.createdThrough === 'BFF' || fixture.createdThrough === 'controlled-legacy-fixture' && legacyFixtures.includes(fixture)) && priority.includes(fixture.type), 'Cleanup', 'fixture journal or exact controlled-fixture discovery proves test ownership');
      const cluster = { id: fixture.clusterId }, workspace = { id: fixture.workspaceId };
      const result = await h.request(admin, scope(`/clusters/${cluster.id}/entities/${fixture.type}/${fixture.id}`, workspace));
      if (result.status === 404) { skippedAbsent.push(key); continue; }
      const actual = entity(h.ok(result, 'Cleanup', 'fresh exact failed-fixture identity'));
      h.check(actual.id === fixture.id && actual.tags?.includes(report.testTag), 'Cleanup', 'actual fixture still has the exact failed-run ownership tag');
      const entry = await h.archive(admin, cluster, workspace, fixture.type, actual, 'Cleanup');
      archived.push({ clusterId: cluster.id, workspaceId: workspace.id, type: fixture.type, id: actual.id, recycleEntryId: entry.id });
    }
    const users = [];
    let cursor;
    for (let page = 0; page < 20; page++) {
      const params = new URLSearchParams({ search: report.testTag, size: '20', ...(cursor ? { cursor } : {}) });
      const response = h.ok(await h.request(admin, `/iam/users?${params}`), 'Cleanup', 'bounded failed-run IAM fixture lookup');
      users.push(...rows(response));
      cursor = response.nextCursor;
      if (!cursor) break;
      h.check(page < 19, 'Cleanup', 'IAM cleanup lookup stays within its page budget');
    }
    // Collect the full cursor result before changing its permission epoch.
    for (const user of users) {
      h.check(user.username.startsWith(`${report.testTag}-`) && user.super_admin !== true, 'Cleanup', 'failed-run user is an ordinary exact-prefix test account');
      const current = h.ok(await h.request(admin, `/iam/users/${user.id}`), 'Cleanup', 'fresh IAM cleanup revision');
      h.ok(await h.request(admin, `/iam/users/${user.id}`, 'DELETE', { revision: current.revision, confirmed: true, confirm_name: current.username }), 'Cleanup', 'failed-run IAM fixture soft-delete and session revocation');
      removedUsers.push(user.id);
    }
  }
  h.verifyAuditCoverage();
} catch (error) { failure = error; }
writeFileSync(h.reference, JSON.stringify({ ...reference, secrets: h.secrets.filter(Boolean), users: reference.users }), { mode: 0o600 });
const safeFailure = failure ? failure.safeEvidenceMessage ? failure.message : `Unexpected ${failure.name}; runtime detail withheld` : undefined;
writeFileSync('artifacts/M4/failed-fixture-cleanup.json', JSON.stringify({ performedAt: new Date().toISOString(), allPassed: !failure, checks: h.checks, archived, softDeletedUsers: removedUsers, absentAfterCapturedCascade: skippedAbsent, auditCoverage: h.public.auditCoverage, ...(safeFailure ? { failure: safeFailure } : {}), finalSuccessfulFixturesRetained: true, directKongDatabaseWrites: 0, directNativeCleanupWrites: 0 }, null, 2) + '\n');
console.log(JSON.stringify({ allPassed: !failure, archived: archived.length, softDeletedUsers: removedUsers.length }));
process.exitCode = failure ? 1 : 0;
