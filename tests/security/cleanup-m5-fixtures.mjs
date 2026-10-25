import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { M5Harness, entity, rows, scope } from './lib/m5-harness.mjs';

const h = new M5Harness(), archived = [], softDeleted = [], revokedBindings = [], absent = [];
let failure;
try {
  h.check(process.env.M5_CLEANUP_READY === 'true', 'Cleanup/Gate', 'explicit completed HTTP/browser/manual sole cleanup handoff required');
  const final = JSON.parse(readFileSync('artifacts/M5/security-live.json'));
  const browser = JSON.parse(readFileSync('artifacts/M5/browser-verification.json'));
  const manual = JSON.parse(readFileSync('artifacts/M5/UI-review.json'));
  h.check(final.failed === 0 && browser.failed === 0 && manual.allPassed === true, 'Cleanup/Gate', 'all final real evidence passed before deleting test fixtures');
  const reports = readdirSync('artifacts/M5').filter(name => /^security-live(?:-[a-z\d-]+)?\.json$/.test(name)).map(name => JSON.parse(readFileSync(`artifacts/M5/${name}`))).filter(report => /^m5-security-[\da-f]{8}$/.test(report.testTag));
  h.check(reports.length >= 3 && reports.some(report => report.failed > 0), 'Cleanup/Gate', 'both preserved failed attempts and the final identified fixture journals are included');
  if (manual.fixtureJournal?.length) h.check(typeof manual.testTag === 'string' && /^m5-[a-z\d-]+$/.test(manual.testTag), 'Cleanup/Gate', 'manual fixture journal has a separate exact test ownership prefix');
  const ownerMap = new Map();
  for (const report of reports.sort((a, b) => Date.parse(a.performedAt) - Date.parse(b.performedAt))) {
    const prior = ownerMap.get(report.testTag)?.report;
    const fixtures = new Map([...(prior?.fixtures ?? []), ...(report.fixtures ?? [])].map(value => [`${value.clusterId}:${value.type}:${value.id}`, value]));
    ownerMap.set(report.testTag, { tag: report.testTag, report: { ...prior, ...report, fixtures: [...fixtures.values()] } });
  }
  const owners = [...ownerMap.values()];
  if (manual.fixtureJournal?.length) owners.push({ tag: manual.testTag, report: { fixtures: manual.fixtureJournal, workspaces: manual.workspaces ?? [] } });
  const clusters = new Set(reports.flatMap(report => [report.clusterId, report.secondaryClusterId]).filter(Boolean));
  const workspaces = new Map();
  for (const { tag, report } of owners) {
    for (const value of [report.payWorkspace, report.opsWorkspace, report.secondaryPayWorkspace, ...(report.workspaces ?? [])].filter(Boolean)) {
      const cid = value.cluster_id ?? value.clusterId;
      h.check(clusters.has(cid) && value.is_default !== true, 'Cleanup/Scope', 'only exact ordinary test workspace IDs enter cleanup');
      workspaces.set(`${cid}:${value.id}`, { ...value, clusterId: cid, tag });
    }
  }
  const admin = await h.login(process.env.BOOTSTRAP_ADMIN_USERNAME || 'admin', process.env.BOOTSTRAP_ADMIN_PASSWORD);
  const priority = ['services', 'consumers', 'upstreams', 'certificates', 'ca_certificates', 'snis', 'routes', 'plugins'], native = new Map();
  for (const { tag, report } of owners) for (const fixture of report.fixtures ?? []) {
    h.check(fixture.createdThrough === 'BFF' && clusters.has(fixture.clusterId) && priority.includes(fixture.type), 'Cleanup/Ownership', 'normal BFF fixture journal proves native test ownership');
    native.set(`${fixture.clusterId}:${fixture.type}:${fixture.id}`, { ...fixture, tag });
  }
  for (const fixture of [...native.values()].sort((a, b) => priority.indexOf(a.type) - priority.indexOf(b.type))) {
    const workspace = { id: fixture.workspaceId }, cluster = { id: fixture.clusterId };
    const response = await h.request(admin, scope(`/clusters/${cluster.id}/entities/${fixture.type}/${fixture.id}`, workspace));
    if (response.status === 404) { absent.push({ clusterId: cluster.id, type: fixture.type, id: fixture.id, reason: 'absent_after_captured_cascade' }); continue; }
    const actual = entity(h.ok(response, 'Cleanup/Native', 'fresh exact native fixture identity'));
    h.check(actual.id === fixture.id && actual.tags?.includes(fixture.tag), 'Cleanup/Ownership', 'fresh native identity retains its exact test ownership tag');
    h.check(!(fixture.type === 'plugins' && !actual.service?.id && !actual.route?.id && !actual.consumer?.id), 'Cleanup/Infrastructure', 'global monitoring infrastructure cannot enter native fixture cleanup');
    const entry = await h.archive(admin, cluster, workspace, fixture.type, actual, 'Cleanup/Native');
    archived.push({ clusterId: cluster.id, workspaceId: workspace.id, type: fixture.type, id: fixture.id, recycleEntryId: entry.id });
  }
  const contexts = [{}, ...[...clusters].map(clusterId => ({ clusterId })), ...[...workspaces.values()].map(value => ({ clusterId: value.clusterId, workspaceId: value.id }))];
  const pageAll = async (path, query) => {
    const result = []; let cursor;
    for (let page = 0; page < 20; page++) {
      const params = new URLSearchParams({ size: '20', ...query, ...(cursor ? { cursor } : {}) });
      const response = h.ok(await h.request(admin, `${path}?${params}`), 'Cleanup/Metadata', 'bounded exact-prefix metadata lookup');
      result.push(...rows(response)); cursor = response.nextCursor;
      if (!cursor) return result;
    }
    h.check(false, 'Cleanup/Budget', 'metadata lookup must complete within20cursor pages');
  };
  const userMap = new Map(), roleMap = new Map(), teamMap = new Map();
  for (const { tag } of owners) for (const status of ['active', 'disabled']) {
    for (const user of await pageAll('/iam/users', { search: tag, status })) {
      h.check(user.username.startsWith(`${tag}-`) && user.super_admin !== true, 'Cleanup/Ownership', 'ordinary user has the exact owned test prefix');
      userMap.set(user.id, user);
    }
    for (const context of contexts) for (const type of ['roles', 'teams']) for (const row of await pageAll(`/iam/${type}`, { ...context, search: tag, status })) {
      h.check(row.code.startsWith(`${tag}-`) && row.protected !== true && !row.builtin_kind, 'Cleanup/Ownership', 'ordinary IAM definition has the exact owned test prefix');
      (type === 'roles' ? roleMap : teamMap).set(row.id, row);
    }
  }
  for (const user of userMap.values()) {
    for (const context of contexts) for (const binding of await pageAll(`/iam/users/${user.id}/role-bindings`, context)) {
      h.check(roleMap.has(binding.role_id), 'Cleanup/Ownership', 'binding is to an identified test-owned role');
      h.ok(await h.request(admin, `/iam/users/${user.id}/role-bindings/${binding.id}`, 'DELETE', { revision: binding.revision, confirmed: true, confirm_name: binding.role_name }), 'Cleanup/Binding', 'explicit audited test role binding revocation');
      revokedBindings.push(binding.id);
    }
    const current = h.ok(await h.request(admin, `/iam/users/${user.id}`), 'Cleanup/Metadata', 'fresh user revision before soft deletion');
    h.ok(await h.request(admin, `/iam/users/${user.id}`, 'DELETE', { revision: current.revision, confirmed: true, confirm_name: current.username }), 'Cleanup/Metadata', 'test user soft-delete and session revocation');
    softDeleted.push({ type: 'users', id: user.id });
  }
  for (const [type, records] of [['teams', teamMap], ['roles', roleMap]]) for (const row of records.values()) {
    const current = h.ok(await h.request(admin, `/iam/${type}/${row.id}`), 'Cleanup/Metadata', 'fresh IAM definition revision before soft deletion');
    h.ok(await h.request(admin, `/iam/${type}/${row.id}`, 'DELETE', { revision: current.revision, confirmed: true, confirm_name: current.name }), 'Cleanup/Metadata', 'test IAM definition soft deletion');
    softDeleted.push({ type, id: row.id });
  }
  for (const workspace of workspaces.values()) {
    const current = h.ok(await h.request(admin, `/clusters/${workspace.clusterId}/workspaces/${workspace.id}`), 'Cleanup/Workspace', 'fresh workspace metadata and revision');
    h.check(current.is_default !== true && current.name.startsWith(`${workspace.tag}-`), 'Cleanup/Ownership', 'empty workspace has the exact owned test prefix');
    if (current.status === 'deleted') continue;
    h.ok(await h.request(admin, `/clusters/${workspace.clusterId}/workspaces/${workspace.id}`, 'DELETE', { revision: current.revision, confirmed: true, confirm_name: current.name }), 'Cleanup/Workspace', 'typed empty test workspace soft deletion');
    softDeleted.push({ type: 'workspaces', clusterId: workspace.clusterId, id: workspace.id });
  }
  h.verifyAuditCoverage();
  h.public.retainedInfrastructure = { originalC1SourcesPreserved: true, activeC2Sources: final.sources[final.secondaryClusterId], bothClustersGlobalMonitoringPluginsPreserved: true, reason: 'explicit persistent active observability infrastructure; not application test fixtures' };
} catch (error) { failure = error; }
h.persistReference();
const safeFailure = failure ? failure.safeEvidenceMessage ? failure.message : `Unexpected ${failure.name}; runtime detail withheld` : undefined;
writeFileSync('artifacts/M5/failed-fixture-cleanup.json', JSON.stringify({ performedAt: new Date().toISOString(), allPassed: !failure, checks: h.checks, archived, softDeleted, revokedBindings, absentAfterCapturedCascade: absent, auditCoverage: h.public.auditCoverage, retainedInfrastructure: h.public.retainedInfrastructure, directKongDatabaseWrites: 0, directNativeCleanupWrites: 0, ...(safeFailure ? { failure: safeFailure } : {}) }, null, 2) + '\n');
console.log(JSON.stringify({ allPassed: !failure, archived: archived.length, softDeleted: softDeleted.length, revokedBindings: revokedBindings.length }));
process.exitCode = failure ? 1 : 0;
