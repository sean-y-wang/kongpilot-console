import { readFileSync } from 'node:fs';
import { M8Harness, durableJson, sha256, scope } from './lib/m8-harness.mjs';
import { bootstrapM8 } from './lib/m8-fixtures.mjs';
import { createNativeFixture, sixCredentialProxyAcceptance, CREDENTIAL_KINDS } from './lib/m8-native-acceptance.mjs';
import { configurationWrite, boundedSnapshotObjects, downloadConfiguration } from './lib/m8-configuration-acceptance.mjs';

// A fresh invocation can only start after Root's exclusive actual handoff.
// Existing journals are rejected. There is no automatic whole-flow replay.
if (process.env.M8_RUNTIME_READY !== 'true' || process.env.M8_DEPLOYMENT_READY !== 'true') throw Error('M8_EXCLUSIVE_DEPLOYMENT_HANDOFF_REQUIRED');
const releasePath = 'artifacts/M8/root-core-runtime-release.json';
if (sha256(readFileSync(releasePath)) !== '166a39e3e1c440e3a40c7828c20639e91e9706c98c956c699ea153be8e61c9f9') throw Error('M8_EXACT_CORE_RUNTIME_RELEASE_REQUIRED');
const h = new M8Harness(); let failure;
try {
  h.state.sourceFiles = ['tests/security/live-m8.mjs', 'tests/security/lib/m8-harness.mjs', 'tests/security/lib/m8-fixtures.mjs', 'tests/security/lib/m8-native-acceptance.mjs', 'tests/security/lib/m8-configuration-acceptance.mjs', 'tests/security/lib/m8-private-history.mjs']
    .map(path => ({ path, sha256: sha256(readFileSync(path)) })); h.save({ phase: 'fresh-m8-bootstrap' });
  const actors = await bootstrapM8(h); h.save({ phase: 'real-kong15-schema-capture' });
  const schemas = {};
  for (const type of ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis', ...CREDENTIAL_KINDS]) {
    const schema = h.data(await h.request(actors.admin, scope(actors.direct.cid, actors.direct.wid, `schemas/${type}`)));
    h.check(Array.isArray(schema.fields) || Array.isArray(schema.schema?.fields), 'live BFF schema contains real Kong1.5 fields', { type }); schemas[type] = schema;
  }
  for (const name of ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acl']) schemas[`plugin:${name}`] = h.data(await h.request(actors.admin, scope(actors.direct.cid, actors.direct.wid, `plugin-schemas/${name}`)));
  // These are already BFF-sanitized schema defaults. A captured-secret match
  // prevents publication rather than silently altering the recorded response.
  const schemaBytes = JSON.stringify(schemas);
  h.check(!h.state.secrets.filter(v => v.length >= 8).some(v => schemaBytes.includes(v)), 'recorded live schemas contain no captured credential material');
  durableJson('artifacts/M8/kong15-bff-schema-recording.json', { milestone: 'M8', actual: true, testTag: h.state.testTag, source: 'protected-BFF-real-Kong1.5', schemas }, 0o644, true);
  h.save({ phase: 'six-real-credential-fixtures' });
  const fixture = await createNativeFixture(h, actors.admin, actors.direct);
  await sixCredentialProxyAcceptance(h, fixture, 'before-snapshot');
  h.save({ phase: 'complete-sealed-baseline' });
  const name = `${h.state.testTag} baseline`, captured = await configurationWrite(h, actors.admin, actors.direct, 'snapshots', { name, description: 'M8 actual six-credential baseline', scope: 'workspace' }, { kind: 'capture' });
  h.check(typeof captured.snapshotId === 'string', 'actual successful capture identifies its sealed snapshot');
  const graph = await boundedSnapshotObjects(h, actors.admin, actors.direct, captured.snapshotId);
  h.check(graph.summary.completeness === 'complete' && graph.summary.consistency === 'console_fenced_best_effort'
    && graph.objects.length === graph.summary.objectCount && graph.objects.every(o => o.recovery === 'complete'), 'actual sealed snapshot includes every object with complete recovery');
  for (const kind of CREDENTIAL_KINDS) h.check(graph.objects.some(o => o.credentialKind === kind && o.nativeId === fixture.credentials[kind].id && o.parentId === fixture.consumer.id), 'actual sealed snapshot includes original typed credential and Consumer', { kind });
  const exported = await configurationWrite(h, actors.admin, actors.direct, `snapshots/${captured.snapshotId}/export`, { mode: 'deployment', confirmed: true, confirm_name: name }, { kind: 'export' });
  const yaml = await downloadConfiguration(h, actors.admin, actors.direct, exported, name);
  // Raw deployment document remains exclusively in the 0600 private journal.
  h.state.baseline = { area: actors.direct, name, snapshotId: captured.snapshotId, captureJobId: captured.jobId, exportJobId: exported.jobId, yaml, yamlSha256: sha256(yaml) }; h.save();
  h.public = { ...(h.public ?? {}), actualM8Complete: false, phaseScope: 'fresh-fixtures-six-real-auth-and-complete-sealed-baseline', nativeAdminBypassRequests: 0,
    originalClusterModesChanged: false, snapshot: { id: captured.snapshotId, objectCount: graph.objects.length, pages: graph.pages, terminalObserved: graph.terminalObserved, completeness: graph.summary.completeness },
    remaining: ['five-class-recovery', 'imports-direct-apply-rollback', 'deck11-cli', 'V2-and-metadata-approval', 'current-RBAC-IDOR-session', 'full-audit-events', 'browser', 'soft-cleanup-secret-scan'] };
} catch (error) { failure = error; }
process.exitCode = h.finish(failure, 'artifacts/M8/security-live-initial.json');
