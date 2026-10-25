import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { M7Harness, M7_COMPOSE, durableJson, sha256, scope, rows } from './lib/m7-harness.mjs';

if (process.env.M7_DEPLOYMENT_READY !== 'true' || process.env.M7_UPSTREAM_DIAGNOSIS_READY !== 'true') throw new Error('M7_ORIGINAL_HEALTH_MARK_READONLY_HANDOFF_REQUIRED');
const h = new M7Harness({ resume: true }), p = h.state.requests[274], reportPath = 'artifacts/M7/security-producers-cli-policy-continuation.json', bytes = readFileSync(reportPath);
if (sha256(bytes) !== '9ad2ebf6b4a16901e27f881bfc15f8ab3398baa90ebeca6ef0a32b8ff49f2c32' || h.state.requests.length !== 275 || p?.status !== 400 || p.errorCode !== 'KONG_VALIDATION_ERROR' ||
  p.path !== '/api/v1/clusters/dff45535-ed8d-4851-b7a6-6376feac7f59/upstreams/138c34c9-bdac-470c-a5fa-64564474aebe/targets/4c92e70c-a2be-43bb-8b6b-f87f1d52a9bf/healthy' || h.state.samplingIntents[2]?.state !== 'completed') throw new Error('M7_EXACT_ORIGINAL_HEALTH_MARK_FAILURE_REQUIRED');
const archive = 'artifacts/M7/security-producers-cli-policy-health-mark-failure.json'; durableJson(archive, JSON.parse(bytes), 0o644, true);
const originalDigest = sha256(JSON.stringify(h.state.requests)), actor = h.state.sessions.admin, area = h.state.scopes.direct;
let report;
try {
  const receiptResponse = await h.request(actor, `/clusters/${area.cid}/mutations/by-key/${p.key}?workspaceId=${area.wid}`, 'GET', undefined, { renew: false }), receipt = h.data(receiptResponse);
  const healthResponse = await h.request(actor, scope(area.cid, area.wid, 'upstreams/138c34c9-bdac-470c-a5fa-64564474aebe/health'), 'GET', undefined, { renew: false }), health = h.data(healthResponse);
  const echoIds = execFileSync('docker', [...M7_COMPOSE, 'ps', '-q', 'echo-upstream'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 }).trim().split('\n').filter(Boolean);
  const statuses = rows(health).map(row => ({ id: row.id, health: row.health }));
  report = { allPassed: true, receipt: { id: receipt.id, state: receipt.state, clusterId: receipt.cluster_id, workspaceId: receipt.workspace_id, actorId: receipt.actor_id,
    action: receipt.action, entityType: receipt.entity_type, entityId: receipt.entity_id, remoteStarted: receipt.remote_started, remoteCompleted: receipt.remote_completed, errorCode: receipt.error_code },
    healthStatuses: statuses, healthResponseRequestId: healthResponse.requestId, receiptResponseRequestId: receiptResponse.requestId, echoUpstreamContainerCount: echoIds.length };
} catch (error) { report = { allPassed: false, failureCode: error.safeEvidenceMessage ? error.message : 'READONLY_HEALTH_DIAGNOSTIC_UNAVAILABLE' }; }
const safe = { milestone: 'M7',testTag: h.state.testTag, performedAt: new Date().toISOString(), ...report, originalFailureArchive: archive,
  originalFailureSha256: sha256(bytes), originalPacketsUnchanged: sha256(JSON.stringify(h.state.requests)) === originalDigest, businessWrites: 0, authenticationWrites: 0, nativeTransportWrites: 0, freshAuthorityObservations: 0 };
const path = 'artifacts/M7/producer-upstream-first-health-readonly-diagnosis.json'; durableJson(path, safe, 0o644, true);
process.stdout.write(JSON.stringify({ path, sha256: sha256(readFileSync(path)), ...safe }) + '\n');process.exitCode = safe.allPassed ? 0 : 1;
