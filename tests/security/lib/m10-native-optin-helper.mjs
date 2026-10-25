import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { FRESH_DEFAULT_CYCLE_LABELS, actualDefaultCycleEvidence, successfulDefaultCycleDeployment, validateFreshDefaultCycle } from './m10-fresh-default-cycle.mjs';

const digest = body => createHash('sha256').update(JSON.stringify(body) ?? 'null').digest('hex');
const UUID = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
export const OPTIN_PHASES = ['key-auth', 'sensitive-plugin', 'stale-source', 'rollback'];
const DEFAULT_APPLY_LABELS = ['m10-promote-default-apply', 'm10-promote-default-apply-after-outer-origin-anchor', FRESH_DEFAULT_CYCLE_LABELS.applyLabel];

/** A failed legacy apply never becomes a success through a suffix or a new
 * fixture label. The whitelist selects one actually observed successful intent
 * and binds its full target/actor/path/body/job tuple before opt-in can start. */
export function assertOptinDefaultApplyGate(state, { actorId, clusterId, workspaceId, sourceClusterId, sourceWorkspaceId, proofBytes, failedDeploymentBytes, successfulDeploymentBytes, currentRuntimeSourceSha256 }) {
  const label = state.governanceFixtures?.promoteApplyLabel;
  assert(DEFAULT_APPLY_LABELS.includes(label), 'VERIFIED_DEFAULT_APPLY_FIXTURE_LABEL_REQUIRED');
  const matches = state.requests.filter(row => row.label === label); assert.equal(matches.length, 1, 'ONE_ACTUAL_DEFAULT_APPLY_PACKET_REQUIRED');
  const packet = matches[0], summary = state.acceptancePlanSummaries?.[label];
  assert(summary && UUID.test(summary.id ?? ''), 'ACTUAL_DEFAULT_PLAN_SUMMARY_REQUIRED');
  assert.equal(summary.clusterId, clusterId); assert.equal(summary.workspaceId, workspaceId); assert.equal(summary.executionMode, 'direct');
  assert.equal(packet.actorId, actorId); assert.equal(packet.method, 'POST');
  assert.equal(packet.path, `/clusters/${clusterId}/configuration/plans/${summary.id}/apply?${new URLSearchParams({ workspaceId })}`);
  assert.equal(packet.state, 'response_observed'); assert([200, 201].includes(packet.status), 'ACTUAL_DEFAULT_APPLY_SUCCESS_REQUIRED');
  assert.equal(packet.bodyHash, digest(packet.body)); assert.equal(packet.body?.confirmed, true);
  assert.equal(packet.body?.planHash, summary.planHash); assert.equal(packet.body?.planRevision, summary.planRevision); assert.equal(packet.body?.confirm_name, summary.name);
  const result = packet.responseData;
  assert(result && result.domain === 'configuration' && result.kind === 'apply');
  assert.equal(result.actorId, actorId); assert.equal(result.clusterId, clusterId); assert.equal(result.workspaceId, workspaceId); assert.equal(result.idempotencyKey, packet.key);
  assert.equal(result.state, 'succeeded'); assert.equal(result.executionCompleted, true); assert.equal(result.registrationCompleted, true);
  assert(UUID.test(result.executionId ?? ''), 'ACTUAL_DEFAULT_EXECUTION_ID_REQUIRED'); assert(UUID.test(result.jobId ?? ''), 'ACTUAL_DEFAULT_JOB_ID_REQUIRED');
  assert.equal(result.jobId, state.governanceFixtures.promoteApplyJobId);
  if (label === DEFAULT_APPLY_LABELS[1]) {
    const intent = state.freshDefaultApplyIntent; assert(intent && intent.label === label, 'VERIFIED_FRESH_DEFAULT_EXECUTION_INTENT_REQUIRED');
    assert.equal(intent.planId, summary.id); assert.equal(intent.bodyHash, packet.bodyHash);
    const originals = state.requests.filter(row => row.requestId === intent.originalRequestId); assert.equal(originals.length, 1);
    const original = originals[0]; assert.equal(original.state, 'response_observed'); assert.equal(original.status, 403);
    assert.equal(original.actorId, actorId); assert.equal(original.path, packet.path); assert.equal(original.method, 'POST');
    assert.equal(original.key, intent.originalKey); assert.equal(original.bodyHash, intent.bodyHash);
    assert.notEqual(packet.key, original.key, 'FRESH_DEFAULT_EXECUTION_MUST_NOT_REPLAY_FORBIDDEN_ORIGINAL');
  } else if(label===FRESH_DEFAULT_CYCLE_LABELS.applyLabel) {
    const intent=state.freshDefaultCycleIntent,original=state.requests.find(row=>row.requestId===intent?.originalRequestId);
    assert(/^[a-f\d]{64}$/.test(currentRuntimeSourceSha256),'ACTUAL_CURRENT_OPTIN_RUNTIME_REQUIRED');
    const successfulRuntimeSourceSha256=successfulDefaultCycleDeployment(state.governanceFixtures.defaultCycle,successfulDeploymentBytes);
    const validated=validateFreshDefaultCycle({intent,proofBytes,failedDeploymentBytes,originalPacket:original,actorId,sourceClusterId,sourceWorkspaceId,targetClusterId:clusterId,targetWorkspaceId:workspaceId,currentRuntimeSourceSha256:successfulRuntimeSourceSha256});
    const tuple=actualDefaultCycleEvidence(state,validated,{actorId,sourceClusterId,sourceWorkspaceId,targetClusterId:clusterId,targetWorkspaceId:workspaceId});
    assert.equal(tuple.runtimeSourceSha256,successfulRuntimeSourceSha256);assert.equal(tuple.planId,summary.id);assert.equal(tuple.applyJobId,result.jobId);
  }
  return { label, packet, summary };
}

export function optinPhase(argv) {
  const at = argv.indexOf('--phase');
  assert(at >= 0 && at === argv.lastIndexOf('--phase') && OPTIN_PHASES.includes(argv[at + 1]), 'ONE_EXPLICIT_OPTIN_PHASE_REQUIRED');
  assert.equal(argv.length, at + 2, 'UNEXPECTED_OPTIN_RUNNER_ARGUMENTS');
  assert.equal(at, 0, 'UNEXPECTED_OPTIN_RUNNER_ARGUMENTS');
  return argv[at + 1];
}

/** No automatic session refresh is requested by this runner. A genuinely issued
 * original session must remain current; Root can refresh it as a separate WAL
 * operation before resuming a phase. No fabricated SID or replacement user. */
export function assertOptinSession(session, now = Date.now()) {
  assert(session?.user?.id && UUID.test(session.user.id) && session.sid && session.cookie, 'ORIGINAL_LIVE_ADMIN_REQUIRED');
  const token = session.cookie.split('; ').find(pair => pair.startsWith('kongos_access='));
  assert(token, 'ORIGINAL_ACCESS_COOKIE_REQUIRED');
  let claims;
  try { claims = JSON.parse(Buffer.from(token.slice('kongos_access='.length).split('.')[1], 'base64url')); } catch { throw Error('ORIGINAL_ACCESS_COOKIE_INVALID'); }
  assert.equal(claims.sub, session.user.id, 'ORIGINAL_SESSION_ACTOR_CHANGED');
  assert.equal(claims.sid, session.sid, 'ORIGINAL_SESSION_SID_CHANGED');
  assert(Number.isSafeInteger(claims.exp) && claims.exp * 1000 > now + 95000, 'ROOT_MUST_REFRESH_ORIGINAL_SESSION_BEFORE_RESUME');
}

/** This ledger assigns the immutable key and body before the HTTP call and also
 * labels an observed denial/500 or unknown original in finally. An unsuccessful
 * original can never be retried under this label, even if the operator resumes. */
export function optinLedger(h) {
  h.state.optin ??= { version: 1, inputs: {}, phases: {}, checks: [], handoffs: {} };
  assert.equal(h.state.optin.version, 1, 'OPTIN_PRIVATE_LEDGER_VERSION_INVALID');
  const state = h.state.optin;
  const freeze = (label, factory) => {
    if (!Object.hasOwn(state.inputs, label)) { state.inputs[label] = structuredClone(factory()); h.save(); }
    return state.inputs[label];
  };
  function locate(label, session, path, method, body, key) {
    const matches = h.state.requests.filter(row => row.label === label || row.key === key && row.path === path && row.method === method && row.actorId === session.user.id && row.bodyHash === digest(body));
    assert(matches.length <= 1, 'DUPLICATE_ORIGINAL_OPTIN_PACKET');
    const original = matches[0];
    if (original) {
      assert.equal(original.path, path); assert.equal(original.method, method); assert.equal(original.actorId, session.user.id);
      assert.equal(original.key, key); assert.equal(original.bodyHash, digest(body));
      assert(!original.label || original.label === label, 'ORIGINAL_OPTIN_LABEL_CONFLICT');
      if (!original.label) { original.label = label; h.save(); }
    }
    return original;
  }
  async function onceExpected(label, session, path, method, body, expected = [200, 201]) {
    assert(!['GET', 'HEAD'].includes(method), 'OPTIN_ONCE_IS_FOR_WAL_WRITES_ONLY');
    const identity = freeze(`${label}:identity`, () => ({ path, method, actorId: session.user.id, bodyHash: digest(body), key: randomUUID() }));
    assert.equal(identity.path, path); assert.equal(identity.method, method); assert.equal(identity.actorId, session.user.id); assert.equal(identity.bodyHash, digest(body));
    const original = locate(label, session, path, method, body, identity.key);
    if (original) {
      assert.equal(original.state, 'response_observed', 'ORIGINAL_UNKNOWN_OPTIN_WRITE_NO_REPLAY');
      assert(expected.includes(original.status), 'ORIGINAL_UNSUCCESSFUL_OPTIN_WRITE_NO_REPLAY');
      assert(original.status < 500, 'ORIGINAL_SERVER_FAILURE_OPTIN_WRITE_NO_REPLAY');
      return { status: original.status, data: original.responseData, requestId: original.requestId };
    }
    assertOptinSession(session);
    try { return await h.request(session, path, method, body, { expected, key: identity.key }); }
    finally { locate(label, session, path, method, body, identity.key); }
  }
  const once = (label, session, path, method, body) => onceExpected(label, session, path, method, body, [200, 201]);
  const packet = label => { const matches = h.state.requests.filter(row => row.label === label); assert.equal(matches.length, 1, 'ONE_ORIGINAL_OPTIN_PACKET_REQUIRED'); return matches[0]; };
  const check = (phase, name, facts = {}) => {
    assert(OPTIN_PHASES.includes(phase));
    assert(!Object.keys(facts).some(key => /secret|key|hash|cookie|payload|body|config/i.test(key)), 'PUBLIC_OPTIN_FACTS_MUST_BE_MINIMAL');
    const row = { phase, name, passed: true, ...facts };
    if (!state.checks.some(old => old.phase === phase && old.name === name)) { state.checks.push(row); h.save(); }
    return row;
  };
  return { state, freeze, once, onceExpected, packet, check };
}

export function assertNoOptinSecrets(value, secrets) {
  // A legitimate observed denial has no success data. Normalize only that
  // scan input, preserving the original HTTP status/error/receipt unchanged.
  const bytes = value === undefined ? 'null' : JSON.stringify(value);
  assert.equal(typeof bytes, 'string', 'PUBLIC_OPTIN_RESPONSE_MUST_BE_JSON_OR_ABSENT');
  for (const secret of secrets.filter(value => typeof value === 'string' && value.length >= 8)) {
    for (const encoding of [secret, encodeURIComponent(secret), Buffer.from(secret).toString('base64'), Buffer.from(secret).toString('base64url')]) {
      assert(!bytes.includes(encoding), 'PUBLIC_OPTIN_RESPONSE_CONTAINS_ACTUAL_SECRET');
    }
  }
}

/** A fixture-only key-auth promote must allocate one fresh target credential.
 * This assertion refuses unrelated native changes or mutation of old keys. */
export function assertKeyAuthOptinPlan(plan, { clusterId, workspaceId, consumerId, sourceCredentialId, oldTargetCredentialId }) {
  assert.equal(plan.entity.clusterId, clusterId); assert.equal(plan.entity.workspaceId, workspaceId);
  assert.equal(plan.entity.executionMode, 'direct'); assert.equal(plan.entity.capabilities.apply, true);
  assert.equal(plan.entity.deleteCount, 0); assert.equal(plan.nextCursor, null);
  assert.equal(plan.items.length, 1, 'OPTIN_MUST_HAVE_EXACTLY_ONE_NATIVE_CREDENTIAL_CREATE');
  assert.equal(plan.entity.stepCount, 1);
  const step = plan.items[0];
  assert.equal(step.entityType, 'credentials'); assert.equal(step.credentialKind, 'key-auth');
  assert.equal(step.action, 'create'); assert.equal(step.parentId, consumerId);
  assert(UUID.test(step.allocatedNativeId ?? ''), 'SERVER_ALLOCATED_TARGET_CREDENTIAL_UUID_REQUIRED');
  assert.notEqual(step.allocatedNativeId, sourceCredentialId); assert.notEqual(step.allocatedNativeId, oldTargetCredentialId);
  return step;
}

export function assertSensitivePluginOptinPlan(plan, { clusterId, workspaceId, targetPluginId }) {
  assert.equal(plan.entity.clusterId, clusterId); assert.equal(plan.entity.workspaceId, workspaceId);
  assert.equal(plan.entity.executionMode, 'direct'); assert.equal(plan.entity.capabilities.apply, true);
  assert.equal(plan.entity.deleteCount, 0); assert.equal(plan.nextCursor, null);
  assert.equal(plan.items.length, 1, 'OPTIN_MUST_HAVE_EXACTLY_ONE_NATIVE_PLUGIN_UPDATE');
  assert.equal(plan.entity.stepCount, 1);
  const step = plan.items[0]; assert.equal(step.entityType, 'plugins'); assert.equal(step.action, 'update'); assert.equal(step.nativeId, targetPluginId);
  return step;
}

export function assertOptinSourceObject(page, { entityType, nativeId, workspaceId }) {
  assert(Array.isArray(page.items));
  const matches = page.items.filter(row => row.entityType === entityType && row.nativeId === nativeId);
  assert.equal(matches.length, 1, 'ONE_ACTUAL_SOURCE_DESCRIPTOR_REQUIRED');
  const row = matches[0];
  assert.equal(row.objectKey, `${entityType}:${nativeId}`);
  assert.equal(row.objectWorkspaceId, workspaceId); assert.equal(row.eligible, true); assert.equal(row.referenceOnly, false);
  assert(!['payload', 'nativeFingerprints', 'config', 'recovery', 'secret'].some(field => Object.hasOwn(row, field)), 'SOURCE_PICKER_MUST_BE_METADATA_ONLY');
  return row;
}

export function assertOptinOriginalReceipt(receipt, packet, { clusterId, workspaceId, kind, state }) {
  assert.equal(packet.state, 'response_observed');
  assert.equal(receipt.actorId, packet.actorId); assert.equal(receipt.clusterId, clusterId); assert.equal(receipt.workspaceId, workspaceId);
  assert.equal(receipt.idempotencyKey, packet.key); assert.equal(receipt.kind, kind); assert.equal(receipt.state, state);
  assert.equal(receipt.registrationCompleted, true);
  return receipt;
}

/** The actual receipt executionId comes from the server's executions JOIN.
 * Scoped job steps corroborate that ID; they never replace a missing receipt
 * field. The SQL observer independently verifies the same execution tuple. */
export function assertOptinExecutionSteps(page, expectedStepCount, expectedExecutionId) {
  assert(UUID.test(expectedExecutionId ?? ''), 'ACTUAL_RECEIPT_EXECUTION_ID_REQUIRED');
  assert(Array.isArray(page.items) && page.items.length > 0 && page.items.length === expectedStepCount, 'ALL_ACTUAL_NATIVE_STEPS_REQUIRED');
  assert.equal(page.nextCursor, null, 'ACTUAL_NATIVE_STEPS_MUST_REACH_EOF');
  const ids = new Set();
  for (const row of page.items) {
    assert.equal(row.state, 'succeeded'); assert.equal(row.verified, true);
    assert(UUID.test(row.operationId ?? ''), 'ACTUAL_NATIVE_OPERATION_ID_REQUIRED');
    assert(UUID.test(row.executionId ?? ''), 'ACTUAL_NATIVE_STEP_EXECUTION_ID_REQUIRED'); assert.equal(row.executionId, expectedExecutionId); ids.add(row.executionId);
  }
  assert.equal(ids.size, 1, 'ALL_ACTUAL_STEPS_MUST_SHARE_ONE_EXECUTION');
  return page.items[0].executionId;
}

export function assertOptinZeroNativeProof(proof, packet, { clusterId, workspaceId, runtimeSourceSha256 }) {
  assert.equal(proof.passed, true); assert.equal(proof.mode, 'no-native'); assert.equal(proof.consoleReadOnly, true);
  assert.equal(proof.requestId, packet.requestId); assert.equal(proof.actorId, packet.actorId);
  assert.equal(proof.clusterId, clusterId); assert.equal(proof.workspaceId, workspaceId);
  assert.equal(proof.runtimeSourceSha256, runtimeSourceSha256);
  assert.equal(proof.configurationJobCount, 0); assert.equal(proof.mutationCount, 0);
  assert.equal(proof.nativeStartedCount, 0); assert.equal(proof.nativeCompletedCount, 0);
  assert.equal(proof.migrationChecksumsMatched, true); assert.equal(proof.runtimeDistMatched, true);
  assert.equal(proof.independentWireLogClaim, false);
  return proof;
}

export function optinPublicReport(h, phase, passed, code) {
  const phases = Object.fromEntries(Object.entries(h.state.optin?.phases ?? {}).map(([name, row]) => [name, { state: row.state, nativeVerified: row.nativeVerified === true, startedAt: row.startedAt, completedAt: row.completedAt }]));
  const attempts = h.state.requests.filter(row => /^m10-optin-/.test(row.label ?? '')).map(row => ({
    label: row.label, method: row.method, path: row.path.split('?')[0], actorId: row.actorId,
    state: row.state, status: row.status, requestId: row.requestId, errorCode: row.errorCode,
    originalResponseRewritten: false, originalAttemptRetained: true,
  }));
  return { milestone: 'M10', phase, passed, phases, environment: 'isolated real Kong OSS 1.5.1 acceptance lab', productionDeployment: false,
    commercialAcceptance: false, originalServicesChanged: false, mainReleasePhasePreserved: true,
    nativeVerificationIsActualPhaseOnly: true, independentWireLogClaim: false,
    privateMaterialsPublished: false, checks: h.state.optin?.checks ?? [], attempts,
    limitations: ['Disabled AWS-lambda validates configuration transfer only; no AWS runtime integration is claimed.',
      'The stale-source phase changes source before apply; it does not demonstrate an in-flight beforeNativeSend race.'],
    ...(code ? { errorCode: code } : {}) };
}
