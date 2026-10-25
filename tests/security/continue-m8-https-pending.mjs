import { readFileSync } from 'node:fs';
import { M8Harness, readM8Reference, sha256 } from './lib/m8-harness.mjs';
import { retainM8History } from './lib/m8-private-history.mjs';
import { waitProxy, hmacAuthorization, CREDENTIAL_KINDS } from './lib/m8-native-acceptance.mjs';
import { configurationWrite, boundedSnapshotObjects, downloadConfiguration } from './lib/m8-configuration-acceptance.mjs';

if (process.env.M8_RUNTIME_READY !== 'true' || process.env.M8_DEPLOYMENT_READY !== 'true' || process.env.M8_HTTPS_PENDING_CONTINUATION_READY !== 'true') throw Error('M8_EXACT_KNOWN_HTTPS_CONTINUATION_REQUIRED');
const originalPath = 'artifacts/M8/security-live-initial.json', originalBytes = readFileSync(originalPath), original = JSON.parse(originalBytes), r = readM8Reference();
if (sha256(originalBytes) !== 'd6fa6ea7f144d6a7d55c2d983e2cbc7efc6b0edebeff3bab2d42e33bf0440cc2'
  || r.requests.length !== 53 || sha256(JSON.stringify(r.requests)) !== 'c12b7b65f7fbec0753862f85e652abbd8263067d23885dbd2829428e819c284c'
  || r.proxyChecks.length !== 4 || sha256(JSON.stringify(r.proxyChecks)) !== 'e63a342f82addc5b9307a7c88763e5a1ce8741e4e2848abdbff938435c8e7096'
  || r.phase !== 'stopped-failure' || r.httpsPendingContinuation || r.requests.some(p => p.state !== 'response_observed' || p.status < 200 || p.status >= 300)
  || r.proxyChecks.at(-1).status !== 400 || r.proxyChecks.at(-1).responseData?.error !== 'access_denied' || !/https/i.test(r.proxyChecks.at(-1).responseData?.error_description ?? '')
  || r.proxyChecks.at(-1).method !== 'POST' || original.unknownWrites !== 0 || original.failed !== 1 || r.baseline) throw Error('M8_ORIGINAL_53_KNOWN_HTTPS_CHECKPOINT_REQUIRED');
const h = new M8Harness({ resume: true, reference: r }); let failure;
try {
  const history = retainM8History(r, 'httpsPendingContinuationHistory');
  r.httpsPendingContinuation = { version: 1, state: 'started', originalFailurePath: originalPath, originalFailureSha256: sha256(originalBytes), originalPacketCount: 53, originalPacketSha256: sha256(JSON.stringify(r.requests)), history };
  h.checks = original.checks.filter(c => c.passed); h.save({ phase: 'https-pending-unused-tail', inFlight: null });
  const actor = r.sessions.admin, f = r.nativeFixture, date = new Date().toUTCString();
  await waitProxy(h, f.area, f.routes['hmac-auth'].proxyPath + '/echo', { expected: 200, consumerId: f.consumer.id, headers: { Date: date, Authorization: hmacAuthorization(f.inputs['hmac-auth'], date) } });
  await waitProxy(h, f.area, f.routes.acls.proxyPath + '/echo', { expected: 200, consumerId: f.consumer.id, headers: { apikey: f.inputs['key-auth'].key } });
  const name = `${r.testTag} baseline`, captured = await configurationWrite(h, actor, f.area, 'snapshots', { name, description: 'M8 actual complete baseline; OAuth TLS proxy pending', scope: 'workspace' }, { kind: 'capture' });
  const graph = await boundedSnapshotObjects(h, actor, f.area, captured.snapshotId);
  h.check(graph.summary.completeness === 'complete' && graph.objects.length === graph.summary.objectCount && graph.objects.every(o => o.recovery === 'complete'), 'actual snapshot seals all affected objects with complete recovery');
  for (const kind of CREDENTIAL_KINDS) h.check(graph.objects.some(o => o.credentialKind === kind && o.nativeId === f.credentials[kind].id && o.parentId === f.consumer.id), 'actual snapshot contains each original credential UUID', { kind });
  const exported = await configurationWrite(h, actor, f.area, `snapshots/${captured.snapshotId}/export`, { mode: 'deployment', confirmed: true, confirm_name: name }, { kind: 'export' });
  const yaml = await downloadConfiguration(h, actor, f.area, exported, name);
  r.baseline = { area: f.area, name, snapshotId: captured.snapshotId, captureJobId: captured.jobId, exportJobId: exported.jobId, yaml, yamlSha256: sha256(yaml) };
  r.httpsPendingContinuation.state = 'completed'; h.save();
  h.public = { actualM8Complete: false, originalFailureRetained: { path: originalPath, sha256: sha256(originalBytes), replayed: false },
    oauthTlsProxyComplete: false, nativeAdminBypassRequests: 0, fiveCredentialProxyComplete: true, sixCredentialSchemasCaptured: true,
    snapshot: { id: captured.snapshotId, objectCount: graph.objects.length, displayPages: graph.pages, displayTerminalObserved: graph.terminalObserved, completeness: graph.summary.completeness },
    phaseScope: 'five-credential-proxy-and-sealed-deployment-baseline-HTTPS-pending' };
} catch (error) { failure = error; }
process.exitCode = h.finish(failure, 'artifacts/M8/security-live-https-pending.json');
