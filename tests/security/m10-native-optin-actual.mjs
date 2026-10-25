import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';
import { assertKeyAuthOptinPlan, assertNoOptinSecrets, assertOptinDefaultApplyGate, assertOptinExecutionSteps, assertOptinOriginalReceipt, assertOptinSession, assertOptinSourceObject,
  assertOptinZeroNativeProof, assertSensitivePluginOptinPlan, optinLedger, optinPhase, optinPublicReport } from './lib/m10-native-optin-helper.mjs';
import { observeOptinConsole, optinDistFingerprint } from './lib/m10-native-optin-observer.mjs';
import { validateFreshKeyAuthIntent } from './lib/m10-fresh-key-auth-intent.mjs';
import { validateFreshRollbackIntent } from './lib/m10-fresh-rollback-intent.mjs';

// Root is the only operator. This script neither creates replacement sessions
// nor retries an unknown write. A phase resume consumes observed exact receipts;
// each distinct proxy observation has its own immutable WAL intent.
const phase = optinPhase(process.argv.slice(2));
const h = new ReleaseHarness('M10', { resume: true }), ledger = optinLedger(h), mainPhase = h.state.phase;
let phaseState, reportPath;
let prefix = `m10-optin-${phase}`;
try {
  assert.equal(process.env.RELEASE_LAB_M10_DEPLOYED, 'true'); assert.equal(process.env.RELEASE_LAB_M10_OPTIN_READY, 'true');
  assert.equal(mainPhase, 'native-m10-core-passed', 'ACTUAL_DEFAULT_PROMOTE_ACCEPTANCE_REQUIRED');
  const runtime = JSON.parse(readFileSync('artifacts/M10/runtime-deployment.json', 'utf8'));
  assert.equal(runtime.apiBuildExit, 0); assert.equal(runtime.copyExit, 0); assert.equal(runtime.apiRestartExit, 0); assert.equal(runtime.readinessStatus, 200);
  assert(/^[a-f\d]{64}$/.test(runtime.apiSourceSha256));
  assert.equal(process.env.RELEASE_LAB_M10_RUNTIME_SOURCE_SHA, runtime.apiSourceSha256, 'ROOT_MUST_BIND_CURRENT_DEPLOYED_CANDIDATE');
  const runtimeDistSha256 = optinDistFingerprint('/dev/shm/kongos-production-ram-m08-20261012-a3/public/output/kongpilot-release-lab/context/apps/console-api/dist');
  const migrations = Object.fromEntries(runtime.migrations.filter(row => ['017_m10_governance.sql', '018_m10_configuration_origins.sql'].includes(row.name)).map(row => [row.name, row.checksum]));
  assert.equal(Object.keys(migrations).length, 2);
  const admin = h.state.sessions.admin, source = h.state.fixtures.source, target = h.state.fixtures.target;
  const cid = h.state.cid, wid = h.state.wid, targetCid = h.state.targetCid, targetWid = h.state.targetWid;
  assert(admin && source && target && cid !== targetCid && wid !== targetWid); assertOptinSession(admin);
  assertOptinDefaultApplyGate(h.state, { actorId: admin.user.id, clusterId: targetCid, workspaceId: targetWid, sourceClusterId: cid, sourceWorkspaceId: wid, currentRuntimeSourceSha256: runtime.apiSourceSha256,
    ...(h.state.freshDefaultCycleIntent ? { proofBytes: readFileSync('artifacts/M10/native-default-cycle-beforefix.json'), failedDeploymentBytes: readFileSync('artifacts/M10/runtime-deployment-before-m10-candidate-v6.json'),
      successfulDeploymentBytes: readFileSync('artifacts/M10/runtime-deployment-before-m10-candidate-v7.json') } : {}) });
  let freshKeyAuth;
  if(phase==='key-auth'&&h.state.freshKeyAuthIntent){
    const intent=h.state.freshKeyAuthIntent;
    freshKeyAuth=validateFreshKeyAuthIntent({intent,proofBytes:readFileSync('artifacts/M10/native-optin-key-auth-fresh-beforefix.json'),diagnosticBytes:readFileSync('artifacts/M10/native-optin-source-adapter-beforefix.json'),
      failedDeploymentBytes:readFileSync('artifacts/M10/runtime-deployment-before-m10-candidate-v7.json'),phaseState:ledger.state.phases['key-auth'],originalPacket:h.state.requests.find(row=>row.requestId===intent.originalRequestId),
      originalComparisonPacket:h.state.requests.find(row=>row.label==='m10-optin-key-auth-comparison'),actorId:admin.user.id,sourceClusterId:cid,sourceWorkspaceId:wid,targetClusterId:targetCid,targetWorkspaceId:targetWid,
      currentRuntimeSourceSha256:runtime.apiSourceSha256,sourceRoots:[['services',source.service.id],['routes',source.route.id],['routes',source.authRoute.id],['consumers',source.consumer.id],['plugins',source.plugin.id],['plugins',source.authPlugin.id]].map(([entityType,nativeId])=>({entityType,nativeId}))});
    prefix=freshKeyAuth.prefix;
  }
  let freshRollback;
  if(phase==='rollback'&&h.state.freshRollbackIntent){
    const intent=h.state.freshRollbackIntent;
    freshRollback=validateFreshRollbackIntent({intent,proofBytes:readFileSync('artifacts/M10/native-optin-rollback-fresh-beforefix.json'),diagnosticBytes:readFileSync('artifacts/M10/native-rollback-schema-beforefix.json'),
      failedDeploymentBytes:readFileSync('artifacts/M10/runtime-deployment-before-m10-candidate-v8.json'),phaseState:ledger.state.phases.rollback,originalPacket:h.state.requests.find(row=>row.requestId===intent.originalRequestId),
      priorKeyAuth:ledger.state.handoffs.keyAuth,actorId:admin.user.id,targetClusterId:targetCid,targetWorkspaceId:targetWid,currentRuntimeSourceSha256:runtime.apiSourceSha256});
    prefix=freshRollback.prefix;
  }
  h.assertWritable();
  const prerequisite = { 'sensitive-plugin': 'key-auth', 'stale-source': 'sensitive-plugin', rollback: 'stale-source' }[phase];
  if (prerequisite) assert.equal(ledger.state.phases[prerequisite]?.nativeVerified, true, 'PREVIOUS_ACTUAL_OPTIN_PHASE_REQUIRED');
  phaseState = ledger.state.phases[phase] ??= { state: 'prepared', nativeVerified: false, startedAt: new Date().toISOString(), attempts: [] };
  assert.notEqual(phaseState.state, 'passed', 'COMPLETED_ACTUAL_PHASE_MUST_NOT_BE_REEXECUTED');
  mkdirSync(resolve('artifacts/M10'), { recursive: true });
  reportPath = resolve(`artifacts/M10/native-optin-${phase}-attempt-${phaseState.attempts.length + 1}.json`);
  assert(!existsSync(reportPath), 'ORIGINAL_OPTIN_ARTIFACT_MUST_BE_RETAINED');
  phaseState.attempts.push({ startedAt: new Date().toISOString(), reportPath }); phaseState.state = 'running'; h.save();
  const src = (suffix, extra = {}) => releaseScope(cid, wid, suffix, extra), dst = (suffix, extra = {}) => releaseScope(targetCid, targetWid, suffix, extra);
  const gov = (suffix, extra = {}) => src(`governance/${suffix}`, extra);
  const sensitive = () => [source.key, target.key, ...Object.values(ledger.state.inputs).flatMap(value => value && typeof value === 'object' ? [value.aws_key, value.aws_secret, value.staleSecret] : [])];
  async function read(path, expected = [200]) { assertOptinSession(admin); return (await h.request(admin, path, 'GET', undefined, { expected })).data; }
  const safe = value => { assertNoOptinSecrets(value, sensitive()); return value; };
  async function pages(pathFactory) {
    const items = []; let cursor; const observed = new Set();
    for (let pageNumber = 0; pageNumber < 100; pageNumber++) {
      const page = safe(await read(pathFactory(cursor))); assert(Array.isArray(page.items)); items.push(...page.items);
      if (!page.nextCursor) return { ...page, items, nextCursor: null };
      assert(typeof page.nextCursor === 'string' && !observed.has(page.nextCursor), 'ACTUAL_CURSOR_MUST_ADVANCE'); observed.add(page.nextCursor); cursor = page.nextCursor;
    }
    throw Error('ACTUAL_OPTIN_COLLECTION_PAGE_BOUND_EXCEEDED');
  }
  async function comparison(label) {
    const body = ledger.freeze(`${label}:body`, () => ({ scope: 'workspace', target: { clusterId: targetCid, workspaceId: targetWid, scope: 'workspace', serviceIds: [] }, threshold: 0, includeEnvironmentFields: false }));
    const response = safe((await ledger.once(label, admin, gov('comparisons'), 'POST', body)).data); assert(response.entity?.id);
    const proof = safe(await read(gov(`operations/by-key/${ledger.packet(label).key}`)));
    assertOptinOriginalReceipt(proof, ledger.packet(label), { clusterId: cid, workspaceId: wid, kind: 'comparison', state: 'succeeded' }); assert.equal(proof.nativeExecutionRequested, false);
    const detail = await pages(cursor => gov(`comparisons/${response.entity.id}`, { size: '100', ...(cursor ? { cursor } : {}) }));
    assert.equal(detail.entity.id, response.entity.id); assert.equal(detail.entity.quality, 'complete'); assert.equal(detail.entity.source.clusterId, cid); assert.equal(detail.entity.target.clusterId, targetCid);
    return detail;
  }
  async function sourceObject(cmp, entityType, nativeId) {
    const page = await pages(cursor => gov(`comparisons/${cmp.entity.id}/source-objects`, { entityType, size: '100', ...(cursor ? { cursor } : {}) }));
    return assertOptinSourceObject(page, { entityType, nativeId, workspaceId: wid });
  }
  async function promote(label, cmp, descriptor, flags) {
    const body = ledger.freeze(`${label}:body`, () => ({ selectedObjectKeys: [descriptor.objectKey], includeEnvironmentFields: false, includeSecrets: true, includeCredentials: false, ...flags, confirmed: true, confirm_name: cmp.entity.confirmationName }));
    assert.equal(body.confirm_name, `PROMOTE ${cmp.entity.id}`);
    const response = safe((await ledger.once(label, admin, gov(`comparisons/${cmp.entity.id}/promote-plan`), 'POST', body)).data);
    const proof = safe(await read(gov(`operations/by-key/${ledger.packet(label).key}`)));
    assertOptinOriginalReceipt(proof, ledger.packet(label), { clusterId: cid, workspaceId: wid, kind: 'promotion-plan', state: 'ready' });
    assert.equal(proof.nativeExecutionRequested, false); assert.equal(proof.planId, response.planId); assert.equal(proof.jobId, response.jobId); assert(proof.planId && proof.jobId);
    let plan = ledger.state.inputs[`${label}:observed-plan`];
    if (!plan) { plan = await pages(cursor => dst(`configuration/plans/${proof.planId}`, { size: '100', ...(cursor ? { cursor } : {}) })); ledger.freeze(`${label}:observed-plan`, () => plan); }
    assert.equal(plan.entity.id, proof.planId); assert(plan.entity.baselineSnapshotId);
    return { promotionId: proof.id, sourceJobId: proof.jobId, plan, planId: proof.planId };
  }
  async function apply(label, prepared, expected = [200, 201], allowDeletes = false) {
    const plan = prepared.plan, body = ledger.freeze(`${label}:body`, () => ({ planRevision: plan.entity.planRevision, planHash: plan.entity.planHash, confirmed: true, confirm_name: plan.entity.name, ...(allowDeletes ? { confirm_deletes: true } : {}) }));
    assert(plan.entity.deleteCount === 0 || allowDeletes, 'ACTUAL_DELETES_REQUIRE_SEPARATE_CONFIRMATION');
    const response = safe((await ledger.onceExpected(label, admin, dst(`configuration/plans/${prepared.planId}/apply`), 'POST', body, expected)).data);
    if (expected.includes(409)) return response;
    const proof = safe(await read(dst(`configuration/jobs/by-key/${ledger.packet(label).key}`)));
    assertOptinOriginalReceipt(proof, ledger.packet(label), { clusterId: targetCid, workspaceId: targetWid, kind: allowDeletes ? 'rollback' : 'apply', state: 'succeeded' });
    assert.equal(proof.executionCompleted, true); assert.equal(proof.jobId, response.jobId); assert(proof.executionId);
    const steps = await pages(cursor => dst(`configuration/jobs/${proof.jobId}/steps`, { size: '100', ...(cursor ? { cursor } : {}) }));
    assertOptinExecutionSteps(steps, plan.entity.stepCount, proof.executionId);
    return { proof, steps, planId: prepared.planId, baselineSnapshotId: proof.baselineSnapshotId, baselineVersion: proof.baselineVersion };
  }
  async function proxy(label, side, credential, expectedStatus) {
    const fixture = side === 'source' ? source : target, path = side === 'source' ? src : dst;
    const current = safe(await read(path(`entities/routes/${fixture.authRoute.id}`))).entity;
    const body = ledger.freeze(`${label}:body`, () => ({ routeId: fixture.authRoute.id, input: { method: 'GET', url: `http://${current.hosts[0]}/${h.state.tag}/credential/live`, headers: { apikey: credential } }, confirmed: true, confirm_name: fixture.authRoute.name }));
    for (let observation = 0; observation < 80; observation++) {
      const result = safe((await ledger.once(`${label}:${observation}`, admin, path('toolbox/probes'), 'POST', body)).data);
      if (result.status === expectedStatus) return result;
      assert([200, 401, 403, 404, 502, 503, 504].includes(result.status), 'ONLY_OBSERVED_PROXY_RESPONSES_MAY_BE_POLLED');
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    throw Error('ACTUAL_OPTIN_PROXY_OBSERVATION_TIMED_OUT');
  }
  const credentialPage = () => pages(cursor => dst(`consumers/${target.consumer.id}/credentials/key-auth`, { size: '100', ...(cursor ? { cursor } : {}) }));
  const revealPlugin = id => read(dst(`entities/plugins/${id}`, { reveal: 'true' }));
  const observerInput = (mode, label) => ({ mode, actorId: admin.user.id, clusterId: targetCid, workspaceId: targetWid, key: ledger.packet(label).key, requestId: ledger.packet(label).requestId,
    runtimeSourceSha256: runtime.apiSourceSha256, runtimeDistSha256, migrations });

  if (phase === 'key-auth') {
    const cmp = await comparison(`${prefix}-comparison`), descriptor = await sourceObject(cmp, 'consumers', source.consumer.id);
    if(freshKeyAuth){assert.notEqual(cmp.entity.id,freshKeyAuth.originalComparisonId,'FRESH_KEY_AUTH_MUST_USE_A_NEW_COMPARISON');assert.notEqual(ledger.packet(`${prefix}-comparison`).key,freshKeyAuth.originalKey);}
    assert(!cmp.items.some(row => row.entityType === 'consumers' && row.sourceNativeId === source.consumer.id), 'CREDENTIAL_ONLY_PROMOTE_MUST_SELECT_UNCHANGED_CONSUMER');
    let before = ledger.state.inputs[`${prefix}:observed-before`];
    if (!before) { before = await credentialPage(); ledger.freeze(`${prefix}:observed-before`, () => before); }
    assert.equal(before.items.length, 1); assert.equal(before.items[0].id, target.credential.id);
    const prepared = await promote(`${prefix}-plan`, cmp, descriptor, { includeCredentials: true, credentialKinds: ['key-auth'] });
    if(freshKeyAuth){assert.notEqual(prepared.promotionId,freshKeyAuth.originalParentId,'FRESH_KEY_AUTH_MUST_NOT_REUSE_BLOCKED_PARENT');assert.notEqual(ledger.packet(`${prefix}-plan`).key,freshKeyAuth.originalKey);}
    const step = assertKeyAuthOptinPlan(prepared.plan, { clusterId: targetCid, workspaceId: targetWid, consumerId: target.consumer.id, sourceCredentialId: source.credential.id, oldTargetCredentialId: target.credential.id });
    const executed = await apply(`${prefix}-apply`, prepared); assert.equal(executed.steps.items[0].effectiveId, step.allocatedNativeId);
    assert.equal(executed.baselineSnapshotId, prepared.plan.entity.baselineSnapshotId); assert(Number.isSafeInteger(executed.baselineVersion) && executed.baselineVersion > 0);
    const actualProof = observeOptinConsole({ ...observerInput('origin', `${prefix}-apply`), promotionId: prepared.promotionId, jobId: executed.proof.jobId, planId: prepared.planId,
      baselineSnapshotId: executed.baselineSnapshotId, baselineVersion: executed.baselineVersion, executionId: executed.proof.executionId });
    ledger.state.handoffs.keyAuth = { ...prepared, executed, targetCredentialId: step.allocatedNativeId, exactBaselineProof: actualProof,...(freshKeyAuth?{freshIntentProofSha256:freshKeyAuth.proofSha256,originalBlockedParentId:freshKeyAuth.originalParentId,originalComparisonId:freshKeyAuth.originalComparisonId,prefix:freshKeyAuth.prefix}:{}) }; h.save();
    const after = await credentialPage(); assert.deepEqual(after.items.map(row => row.id).sort(), [target.credential.id, step.allocatedNativeId].sort());
    const raw = (await read(dst(`consumers/${target.consumer.id}/credentials/key-auth/${step.allocatedNativeId}`, { reveal: 'true' }))).entity;
    assert.equal(raw.id, step.allocatedNativeId); assert.equal(raw.key, source.key); assert.equal(raw.consumer.id, target.consumer.id);
    await proxy(`${prefix}-source-key-on-target`, 'target', source.key, 200); await proxy(`${prefix}-target-key-on-target`, 'target', target.key, 200); await proxy(`${prefix}-source-key-on-source`, 'source', source.key, 200);
    ledger.check(phase, 'unchanged Consumer selected from actual metadata cursor; only key-auth is copied to an independently allocated target UUID', { nativeStepCount: 1 });
    ledger.check(phase, 'actual target proxy accepts copied source credential and preserves its original credential');
    ledger.check(phase, 'actual console execution references the exact immutable preexecution target snapshot', { snapshotVersion: executed.baselineVersion });
  } else if (phase === 'sensitive-plugin') {
    for (const [side, fixture, path] of [['source', source, src], ['target', target, dst]]) {
      const secrets = ledger.freeze(`m10-optin-aws-${side}-secrets`, () => ({ aws_key: randomBytes(24).toString('hex'), aws_secret: randomBytes(32).toString('hex') }));
      const body = ledger.freeze(`${prefix}-${side}-fixture:body`, () => ({ name: 'aws-lambda', enabled: false, route: { id: fixture.route.id },
        config: { ...secrets, aws_region: 'us-east-1', function_name: `${h.state.tag}-disabled-acceptance`, invocation_type: 'DryRun' }, tags: [h.state.tag, 'team:m10-acceptance'] }));
      const plugin = safe((await ledger.once(`${prefix}-${side}-fixture`, admin, path('entities/plugins'), 'POST', body)).data).entity;
      assert(plugin?.id && plugin.enabled === false && plugin.name === 'aws-lambda');
      ledger.state.handoffs.aws ??= {}; ledger.state.handoffs.aws[side] = { pluginId: plugin.id, secrets }; h.save();
    }
    const aws = ledger.state.handoffs.aws; assert.notEqual(aws.source.pluginId, aws.target.pluginId); assert.notEqual(aws.source.secrets.aws_key, aws.target.secrets.aws_key); assert.notEqual(aws.source.secrets.aws_secret, aws.target.secrets.aws_secret);
    const cmp = await comparison(`${prefix}-comparison`), descriptor = await sourceObject(cmp, 'plugins', aws.source.pluginId);
    const prepared = await promote(`${prefix}-plan`, cmp, descriptor, { includeSecrets: true, includeCredentials: false });
    assertSensitivePluginOptinPlan(prepared.plan, { clusterId: targetCid, workspaceId: targetWid, targetPluginId: aws.target.pluginId });
    const executed = await apply(`${prefix}-apply`, prepared); const plugin = (await revealPlugin(aws.target.pluginId)).entity;
    assert.equal(plugin.id, aws.target.pluginId); assert.equal(plugin.enabled, false); assert.equal(plugin.route.id, target.route.id);
    assert.equal(plugin.config.aws_key, aws.source.secrets.aws_key); assert.equal(plugin.config.aws_secret, aws.source.secrets.aws_secret);
    safe(await read(dst(`entities/plugins/${aws.target.pluginId}`))); ledger.state.handoffs.aws.prepared = prepared; ledger.state.handoffs.aws.executed = executed; h.save();
    ledger.check(phase, 'disabled AWS-lambda secret configuration is transferred under explicit secret opt-in while target UUID and Route binding are preserved', { nativeStepCount: 1, pluginEnabled: false });
    ledger.check(phase, 'default plugin, comparison and plan projections contain neither actual AWS secret value');
  } else if (phase === 'stale-source') {
    const aws = ledger.state.handoffs.aws; assert(aws?.source && aws.target);
    // Set a separate, explicit target difference before the comparison. This
    // makes the sealed plan contain one actual update rather than an empty plan.
    await ledger.once(`${prefix}-target-difference`, admin, dst(`entities/plugins/${aws.target.pluginId}`), 'PATCH', ledger.freeze(`${prefix}-target-difference:body`, () => ({ config: { ...aws.target.secrets } })));
    const cmp = await comparison(`${prefix}-comparison`), descriptor = await sourceObject(cmp, 'plugins', aws.source.pluginId);
    const prepared = await promote(`${prefix}-plan`, cmp, descriptor, { includeSecrets: true, includeCredentials: false });
    assertSensitivePluginOptinPlan(prepared.plan, { clusterId: targetCid, workspaceId: targetWid, targetPluginId: aws.target.pluginId });
    const stale = ledger.freeze(`${prefix}-private-source-drift`, () => ({ staleSecret: randomBytes(32).toString('hex') }));
    await ledger.once(`${prefix}-source-drift`, admin, src(`entities/plugins/${aws.source.pluginId}`), 'PATCH', ledger.freeze(`${prefix}-source-drift:body`, () => ({ config: { aws_secret: stale.staleSecret } })));
    await apply(`${prefix}-apply-denied`, prepared, [409]);
    const original = ledger.packet(`${prefix}-apply-denied`); assert.equal(original.status, 409);
    assert(['CONFIGURATION_ORIGIN_SOURCE_CHANGED', 'CONFIGURATION_ORIGIN_PRIVATE_SOURCE_CHANGED'].includes(original.errorCode), 'EXACT_STALE_SOURCE_GUARD_REQUIRED');
    await read(dst(`configuration/jobs/by-key/${original.key}`), [404]);
    const proof = assertOptinZeroNativeProof(observeOptinConsole(observerInput('no-native', `${prefix}-apply-denied`)), original, { clusterId: targetCid, workspaceId: targetWid, runtimeSourceSha256: runtime.apiSourceSha256 });
    const current = (await revealPlugin(aws.target.pluginId)).entity; assert.equal(current.id, aws.target.pluginId); assert.equal(current.enabled, false);
    assert.equal(current.config.aws_key, aws.target.secrets.aws_key); assert.equal(current.config.aws_secret, aws.target.secrets.aws_secret);
    const keys = await credentialPage(); assert.deepEqual(keys.items.map(row => row.id).sort(), [target.credential.id, ledger.state.handoffs.keyAuth.targetCredentialId].sort());
    // Restoration is its own immutable intent. It never retries the denied apply.
    await ledger.once(`${prefix}-source-restore`, admin, src(`entities/plugins/${aws.source.pluginId}`), 'PATCH', ledger.freeze(`${prefix}-source-restore:body`, () => ({ config: { ...aws.source.secrets } })));
    const restored = (await read(src(`entities/plugins/${aws.source.pluginId}`, { reveal: 'true' }))).entity; assert.equal(restored.config.aws_secret, aws.source.secrets.aws_secret);
    ledger.state.handoffs.staleSource = { comparisonId: cmp.entity.id, planId: prepared.planId, originalApplyLabel: `${prefix}-apply-denied`, zeroNativeProof: proof, sourceRestored: true }; h.save();
    ledger.check(phase, 'changing actual source secret after sealing rejects generic target apply with 409', { originalStatus: 409 });
    ledger.check(phase, 'actual console read-only observation proves that the exact refused apply created no job or native mutation', { nativeStartedCount: 0, nativeCompletedCount: 0 });
    ledger.check(phase, 'source restoration is separately observed; the original refused apply and its immutable key are never replayed');
  } else {
    const prior = ledger.state.handoffs.keyAuth, snapshotId = prior?.executed?.baselineSnapshotId;
    assert(snapshotId && prior.exactBaselineProof?.actualBaselineSnapshotId === snapshotId && prior.exactBaselineProof?.actualBaselineVersion === prior.executed.baselineVersion, 'ACTUAL_PREEXECUTION_SNAPSHOT_PROOF_REQUIRED');
    if(freshRollback){assert.equal(snapshotId,freshRollback.snapshotId);assert.equal(prior.executed.baselineVersion,freshRollback.snapshotVersion);}
    const snapshot = safe(await read(dst(`snapshots/${snapshotId}`, { size: '100' })));
    assert.equal(snapshot.entity.id, snapshotId); assert.equal(snapshot.entity.state, 'ready'); assert.equal(snapshot.entity.capabilities.rollback, true);
    const body = ledger.freeze(`${prefix}-preview:body`, () => ({ revision: snapshot.entity.revision, confirmed: true, confirm_name: snapshot.entity.name, confirm_deletes: true }));
    const response = safe((await ledger.once(`${prefix}-preview`, admin, dst(`snapshots/${snapshotId}/rollback-plan`), 'POST', body)).data);
    if(freshRollback)assert.notEqual(ledger.packet(`${prefix}-preview`).key,freshRollback.originalKey,'FRESH_ROLLBACK_PREVIEW_MUST_NOT_REPLAY_ORIGINAL');
    const receipt = safe(await read(dst(`configuration/jobs/by-key/${ledger.packet(`${prefix}-preview`).key}`)));
    assertOptinOriginalReceipt(receipt, ledger.packet(`${prefix}-preview`), { clusterId: targetCid, workspaceId: targetWid, kind: 'compare', state: 'succeeded' }); assert.equal(receipt.planId, response.planId);
    if(freshRollback){assert.notEqual(receipt.jobId,freshRollback.failedCompareJobId);assert.notEqual(receipt.jobId,freshRollback.baselineCaptureJobId);}
    let plan = ledger.state.inputs[`${prefix}:observed-plan`];
    if (!plan) { plan = await pages(cursor => dst(`configuration/plans/${receipt.planId}`, { size: '100', ...(cursor ? { cursor } : {}) })); ledger.freeze(`${prefix}:observed-plan`, () => plan); }
    assert.equal(plan.entity.mode, 'rollback'); assert.equal(plan.entity.capabilities.apply, true); assert(plan.entity.deleteCount > 0);
    const credentialDelete = plan.items.filter(row => row.entityType === 'credentials' && row.credentialKind === 'key-auth' && row.nativeId === prior.targetCredentialId && row.action === 'delete'); assert.equal(credentialDelete.length, 1);
    assert(!plan.items.some(row => row.entityType === 'credentials' && row.nativeId === target.credential.id), 'ROLLBACK_MUST_PRESERVE_ORIGINAL_TARGET_CREDENTIAL');
    const executed = await apply(`${prefix}-apply`, { plan, planId: receipt.planId }, [200, 201], true);
    if(freshRollback)assert.notEqual(ledger.packet(`${prefix}-apply`).key,freshRollback.originalKey,'FRESH_ROLLBACK_APPLY_MUST_NOT_REPLAY_ORIGINAL');
    for (const step of executed.steps.items.filter(row => row.action === 'delete')) assert(step.recycleEntryId || step.completeRecycleEntryId, 'ROLLBACK_DELETIONS_MUST_ENTER_RECYCLE_BIN');
    const credentials = await credentialPage(); assert.deepEqual(credentials.items.map(row => row.id), [target.credential.id]);
    await read(dst(`consumers/${target.consumer.id}/credentials/key-auth/${prior.targetCredentialId}`), [404]);
    await proxy(`${prefix}-original-target-key`, 'target', target.key, 200); await proxy(`${prefix}-copied-source-key-revoked`, 'target', source.key, 401); await proxy(`${prefix}-source-key-still-valid`, 'source', source.key, 200);
    assert.equal(safe(await read(dst(`entities/consumers/${target.consumer.id}`))).entity.id, target.consumer.id);
    ledger.state.handoffs.rollback = { exactRestoredSnapshotId: snapshotId, exactRestoredSnapshotVersion: prior.executed.baselineVersion, previewPlanId: receipt.planId, executionJobId: executed.proof.jobId,
      ...(freshRollback?{freshIntentProofSha256:freshRollback.proofSha256,originalFailedCompareJobId:freshRollback.failedCompareJobId,prefix:freshRollback.prefix}:{}) }; h.save();
    ledger.check(phase, 'a newly confirmed M8 rollback plan restores the exact preexecution target snapshot and routes deletions through the recycle bin', { nativeStepCount: plan.entity.stepCount });
    ledger.check(phase, 'original target credential authenticates after rollback, copied source credential is rejected and source gateway credential remains usable');
  }
  assert.equal(h.state.phase, mainPhase, 'MAIN_RELEASE_PHASE_MUST_REMAIN_UNCHANGED');
  phaseState.state = 'passed'; phaseState.nativeVerified = true; phaseState.completedAt = new Date().toISOString(); h.save();
  const report = optinPublicReport(h, phase, true); assertNoOptinSecrets(report, sensitive()); writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  process.stdout.write(JSON.stringify({ passed: true, phase, phaseOnlyActualVerification: true, overallAcceptance: false, reportPath, checks: ledger.state.checks.filter(row => row.phase === phase).length }) + '\n');
} catch (error) {
  if (phaseState) { phaseState.state = 'stopped'; phaseState.nativeVerified = false; phaseState.privateFailure = { type: error.name, message: String(error.message), stack: String(error.stack ?? '') }; }
  assert.equal(h.state.phase, mainPhase); h.save();
  const report = optinPublicReport(h, phase, false, 'M10_NATIVE_OPTIN_PHASE_FAILED');
  if (reportPath) writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  process.stderr.write(JSON.stringify({ passed: false, phase, code: 'M10_NATIVE_OPTIN_PHASE_FAILED', mainReleasePhasePreserved: true, originalAttemptsRetained: true }) + '\n'); process.exitCode = 1;
}
