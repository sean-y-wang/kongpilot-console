import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { ReleaseHarness, releaseScope } from './lib/release-harness.mjs';
import { validateFreshInspectionIntent } from './lib/m10-fresh-inspection-intent.mjs';
import { validateComparisonAcknowledgementRecovery } from './lib/m10-comparison-ack-recovery.mjs';
import { FRESH_DEFAULT_CYCLE_LABELS, preserveM10TimerFixtures, validateFreshDefaultCycle } from './lib/m10-fresh-default-cycle.mjs';

// Prepared by the Web agent; Root is the only operator of these real requests.
// Every intent and response remains in the private WAL. Unknown results stop
// this run without replaying, recompiling, applying or choosing a replacement key.
const h = new ReleaseHarness('M10', { resume: true });
const digest = value => createHash('sha256').update(JSON.stringify(value) ?? 'null').digest('hex');
try {
  assert.equal(process.env.RELEASE_LAB_M10_DEPLOYED, 'true', 'DEPLOYED_M10_GATE_REQUIRED');
  assert(h.state.phase === 'native-fixtures-ready' || h.state.phase === 'native-m10-core-running' && h.state.nativeAcceptanceStarted === true, 'VERIFIED_TWO_GATEWAY_FIXTURES_REQUIRED');
  h.state.nativeAcceptanceStarted = true; h.state.phase = 'native-m10-core-running'; h.state.acceptanceInputs ??= {}; h.save();
  const admin = h.state.sessions.admin, reader = h.state.sessions.reader, cid = h.state.cid, wid = h.state.wid, targetCid = h.state.targetCid, targetWid = h.state.targetWid;
  assert(admin && reader && cid && wid && targetCid && targetWid && cid !== targetCid, 'EXACT_ORIGINAL_ACTOR_AND_TWO_CLUSTER_HANDOFF_REQUIRED');
  const source = h.state.fixtures.source, target = h.state.fixtures.target; assert(source && target);
  const src = suffix => releaseScope(cid, wid, suffix), dst = suffix => releaseScope(targetCid, targetWid, suffix), gov = suffix => src(`governance/${suffix}`);
  let staleTargetValidationLabel='m10-stale-target-env-promote-denied';
  let defaultApplyLabel='m10-promote-default-apply';
  let freshDefaultCycle;
  if(h.state.freshDefaultCycleIntent){
    const intent=h.state.freshDefaultCycleIntent,runtime=JSON.parse(readFileSync('artifacts/M10/runtime-deployment.json','utf8'));
    for(const key of ['apiBuildExit','copyExit','apiRestartExit'])assert.equal(runtime[key],0);assert.equal(runtime.readinessStatus,200);
    const old=h.state.requests.find(p=>p.requestId===intent.originalRequestId);
    freshDefaultCycle=validateFreshDefaultCycle({intent,proofBytes:readFileSync('artifacts/M10/native-default-cycle-beforefix.json'),failedDeploymentBytes:readFileSync('artifacts/M10/runtime-deployment-before-m10-candidate-v6.json'),originalPacket:old,
      actorId:admin.user.id,sourceClusterId:cid,sourceWorkspaceId:wid,targetClusterId:targetCid,targetWorkspaceId:targetWid,currentRuntimeSourceSha256:runtime.apiSourceSha256});
    freshDefaultCycle.runtimeSourceSha256=runtime.apiSourceSha256;
  }
  if(h.state.freshDefaultApplyIntent){
    const intent=h.state.freshDefaultApplyIntent,bytes=readFileSync('artifacts/M10/native-apply-origin-beforefix.json'),proof=JSON.parse(bytes.toString()),old=h.state.requests.find(p=>p.requestId===intent.originalRequestId);
    assert.equal(createHash('sha256').update(bytes).digest('hex'),intent.proofSha256);
    assert(old&&old.status===403&&old.errorCode==='KONG_EXECUTION_CONTEXT_EXPIRED'&&old.actorId===admin.user.id&&old.key===intent.originalKey&&old.bodyHash===intent.bodyHash);
    assert.equal(old.path,dst(`configuration/plans/${intent.planId}/apply`));
    for(const [key,value]of Object.entries({originalRequestId:old.requestId,originalKey:old.key,originalStatus:403,actorId:admin.user.id,targetClusterId:targetCid,targetWorkspaceId:targetWid,planId:intent.planId,originalBodyHash:old.bodyHash,originalResponseRewritten:false,nativeReplayed:false,newExecutionIntentLabel:'m10-promote-default-apply-after-outer-origin-anchor'}))assert.equal(proof[key],value);
    assert.equal(proof.actualZeroNative.passed,true);assert.equal(proof.actualZeroNative.actorId,old.actorId);assert.equal(proof.actualZeroNative.clusterId,targetCid);assert.equal(proof.actualZeroNative.workspaceId,targetWid);assert.equal(proof.actualZeroNative.requestId,old.requestId);
    for(const key of ['configurationJobCount','mutationCount','nativeStartedCount','nativeCompletedCount'])assert.equal(proof.actualZeroNative[key],0);
    assert.equal(intent.label,proof.newExecutionIntentLabel);defaultApplyLabel=intent.label;
  }
  if(h.state.staleTargetValidationIntent){
    const intent=h.state.staleTargetValidationIntent,bytes=readFileSync('artifacts/M10/native-target-planning-beforefix.json'),proof=JSON.parse(bytes.toString()),old=h.state.requests.find(p=>p.requestId===intent.originalRequestId);
    assert.equal(createHash('sha256').update(bytes).digest('hex'),intent.proofSha256);
    assert(old&&old.status===403&&old.errorCode==='KONG_ACTOR_SCOPE_MISMATCH'&&old.key===intent.originalKey&&old.actorId===admin.user.id);
    assert.equal(old.path,gov(`comparisons/${intent.comparisonId}/promote-plan`));
    for(const [key,value]of Object.entries({originalRequestId:old.requestId,originalKey:old.key,originalStatus:403,actorId:admin.user.id,sourceClusterId:cid,sourceWorkspaceId:wid,targetClusterId:targetCid,targetWorkspaceId:targetWid,comparisonId:intent.comparisonId,originalPromotionId:intent.originalPromotionId,originalState:'blocked',originalResponseRewritten:false,nativeReplayed:false,newValidationLabel:'m10-stale-target-env-promote-after-planning-bridge'}))assert.equal(proof[key],value);
    assert.equal(proof.actualZeroNative.passed,true);assert.equal(proof.actualZeroNative.actorId,old.actorId);assert.equal(proof.actualZeroNative.clusterId,targetCid);assert.equal(proof.actualZeroNative.workspaceId,targetWid);assert.equal(proof.actualZeroNative.requestId,old.requestId);
    for(const key of ['configurationJobCount','mutationCount','nativeStartedCount','nativeCompletedCount'])assert.equal(proof.actualZeroNative[key],0);
    assert.equal(intent.label,proof.newValidationLabel);staleTargetValidationLabel=intent.label;
  }
  const comparisonBody = { scope: 'workspace', target: { clusterId: targetCid, workspaceId: targetWid, scope: 'workspace', serviceIds: [] }, threshold: 0, includeEnvironmentFields: false };
  const failedComparisonPacket = h.state.requests.find(row => row.actorId === admin.user.id && row.method === 'POST' && row.path === gov('comparisons') && row.status === 403 && row.bodyHash === digest(comparisonBody) && (!h.state.comparisonAckRecovery || row.requestId === h.state.comparisonAckRecovery.originalRequestId && row.key === h.state.comparisonAckRecovery.originalKey));
  let comparisonAcknowledgement;
  if (failedComparisonPacket || h.state.comparisonAckRecovery || h.state.freshComparisonIntent) {
    const originalKey = h.state.comparisonAckRecovery?.originalKey;
    comparisonAcknowledgement = validateComparisonAcknowledgementRecovery({ recovery: h.state.comparisonAckRecovery, intent: h.state.freshComparisonIntent, proofBytes: readFileSync('artifacts/M10/native-comparison-original-ack.json'), originalPacket: failedComparisonPacket, actorId: admin.user.id, clusterId: cid, workspaceId: wid, targetClusterId: targetCid, targetWorkspaceId: targetWid, postPath: gov('comparisons'), receiptPath: gov(`operations/by-key/${originalKey}`), body: comparisonBody });
  }
  const inspectBody = { scope: 'workspace' }, originalFailedInspection = h.state.requests.find(row => row.label === 'm10-inspection-initial-failed-before-rule-projection');
  let initialInspectionLabel = 'm10-inspection-initial';
  if (originalFailedInspection || h.state.freshInspectionIntent) {
    const verified = validateFreshInspectionIntent({ intent: h.state.freshInspectionIntent, proofBytes: readFileSync('artifacts/M10/native-inspection-beforefix.json'), originalPacket: originalFailedInspection, actorId: admin.user.id, clusterId: cid, workspaceId: wid, path: gov('inspections'), body: inspectBody });
    const unchanged = (await h.request(admin, gov(`operations/by-key/${verified.originalKey}`))).data;
    assert.equal(unchanged.id, verified.originalRunId); assert.equal(unchanged.actorId, admin.user.id); assert.equal(unchanged.clusterId, cid); assert.equal(unchanged.workspaceId, wid); assert.equal(unchanged.idempotencyKey, verified.originalKey); assert.equal(unchanged.kind, 'inspection'); assert.equal(unchanged.domain, 'governance'); assert.equal(unchanged.state, 'uncertain'); assert.equal(unchanged.nativeExecutionRequested, false); assert.equal(unchanged.executionCompleted, false);
    initialInspectionLabel = verified.label;
  }
  const freeze = (label, factory) => { if (!Object.hasOwn(h.state.acceptanceInputs, label)) { h.state.acceptanceInputs[label] = structuredClone(factory()); h.save(); } return h.state.acceptanceInputs[label]; };
  function packet(label) { const row = h.state.requests.find(row => row.label === label); assert(row, 'ORIGINAL_PACKET_REQUIRED'); return row; }
  // Negative tests also have immutable labels. h.once intentionally only accepts
  // successful receipts, so observed denials use an exact-status sibling here.
  async function onceExpected(label, session, path, method, body, expected) {
    const old = h.state.requests.find(row => row.label === label);
    if (old) { assert.equal(old.path, path); assert.equal(old.method, method); assert.equal(old.actorId, session.user.id); assert.equal(old.bodyHash, digest(body)); assert.equal(old.state, 'response_observed'); assert(expected.includes(old.status), 'ORIGINAL_DENIAL_MUST_REMAIN_OBSERVED'); return { status: old.status, data: old.responseData, requestId: old.requestId }; }
    const originalKey = freeze(`${label}:key`, () => randomUUID()), result = await h.request(session, path, method, body, { expected, key: originalKey });
    const matches = h.state.requests.filter(row => row.key === originalKey && row.actorId === session.user.id && row.path === path && row.method === method && row.bodyHash === digest(body) && row.requestId === result.requestId);
    assert.equal(matches.length, 1, 'EXACT_ORIGINAL_DENIAL_PACKET_REQUIRED'); matches[0].label = label; h.save(); return result;
  }
  async function freshCycleOnce(label,path,body){
    assert(Object.values(FRESH_DEFAULT_CYCLE_LABELS).includes(label),'FIXED_NEW_CYCLE_LABEL_REQUIRED');
    const key=freeze(`${label}:original-key`,()=>randomUUID());
    try{return await h.once(label,admin,path,'POST',body,{key});}
    finally{const rows=h.state.requests.filter(p=>p.key===key&&p.path===path&&p.actorId===admin.user.id&&p.method==='POST'&&p.bodyHash===digest(body));assert(rows.length<=1);if(rows.length){assert(!rows[0].label||rows[0].label===label);rows[0].label=label;h.save();}}
  }
  async function receipt(label, clusterId, workspaceId, kind) {
    const original = packet(label), row = (await h.request(admin, releaseScope(clusterId, workspaceId, `governance/operations/by-key/${original.key}`))).data;
    assert.equal(row.actorId, admin.user.id); assert.equal(row.clusterId, clusterId); assert.equal(row.workspaceId, workspaceId); assert.equal(row.idempotencyKey, original.key); assert.equal(row.kind, kind); assert.equal(row.registrationCompleted, true); assert.equal(row.nativeExecutionRequested, false);
    assert(!['uncertain', 'partial', 'planning', 'running'].includes(row.state), 'ORIGINAL_GOVERNANCE_RESULT_NOT_YET_CONFIRMED');
    return row;
  }
  async function apply(label, clusterId, workspaceId, planId) {
    const path = suffix => releaseScope(clusterId, workspaceId, suffix), original = h.state.requests.find(row => row.label === label);
    h.state.acceptancePlanSummaries ??= {};
    const detail = original ? h.state.acceptancePlanSummaries[label] : (await h.request(admin, path(`configuration/plans/${planId}`))).data.entity;
    assert(detail && detail.id === planId, 'ORIGINAL_NATIVE_PLAN_SUMMARY_REQUIRED');
    if (!original) { h.state.acceptancePlanSummaries[label] = structuredClone(detail); h.save(); }
    assert.equal(detail.clusterId, clusterId); assert.equal(detail.workspaceId, workspaceId); assert.equal(detail.executionMode, 'direct'); assert.equal(detail.capabilities.apply, true); assert.equal(detail.deleteCount, 0);
    const body = freeze(label, () => ({ planRevision: detail.planRevision, planHash: detail.planHash, confirmed: true, confirm_name: detail.name }));
    const result = (await (label===FRESH_DEFAULT_CYCLE_LABELS.applyLabel ? freshCycleOnce(label,path(`configuration/plans/${planId}/apply`),body) : h.once(label, admin, path(`configuration/plans/${planId}/apply`), 'POST', body))).data;
    const proof = (await h.request(admin, path(`configuration/jobs/by-key/${packet(label).key}`))).data;
    assert.equal(proof.actorId, admin.user.id); assert.equal(proof.clusterId, clusterId); assert.equal(proof.workspaceId, workspaceId); assert.equal(proof.idempotencyKey, packet(label).key); assert.equal(proof.state, 'succeeded'); assert.equal(proof.executionCompleted, true);
    const jobId = proof.job?.id ?? result.job?.id ?? result.entity?.id; assert(jobId, 'ACTUAL_M8_EXECUTION_JOB_REQUIRED');
    const steps = (await h.request(admin, releaseScope(clusterId, workspaceId, `configuration/jobs/${jobId}/steps`, { size: '100' }))).data;
    assert(!steps.nextCursor && steps.items.length === detail.stepCount && steps.items.length > 0 && steps.items.every(step => step.state === 'succeeded'), 'ALL_FIXTURE_NATIVE_STEP_ACKNOWLEDGEMENTS_REQUIRED');
    return { jobId, plan: detail, proof, steps };
  }
  async function proxy(label, clusterId, workspaceId, authRoute, hosts, key, expectedStatus) {
    const body = freeze(`${label}:body`, () => ({ routeId: authRoute.id, input: { method: 'GET', url: `http://${hosts[0]}/${h.state.tag}/credential/live`, headers: { apikey: key } }, confirmed: true, confirm_name: authRoute.name }));
    for (let attempt = 0; attempt < 80; attempt++) { const row = (await h.once(`${label}:${attempt}`, admin, releaseScope(clusterId, workspaceId, 'toolbox/probes'), 'POST', body)).data; if (row.status === expectedStatus) return row; assert([200, 401, 403, 404, 502, 503, 504].includes(row.status), 'ONLY_OBSERVED_BUSINESS_RESPONSES_MAY_BE_POLLED'); await new Promise(resolve => setTimeout(resolve, 200)); }
    throw Error('ACTUAL_PROXY_CREDENTIAL_ASSERTION_TIMED_OUT');
  }
  const capability = (await h.request(admin, gov('capabilities'))).data; assert.equal(capability.adapterAvailable, true); assert.equal(capability.ruleWrite, true); assert.equal(capability.promotePlan, true);
  const catalog = (await h.request(admin, gov('catalog'))).data; assert(catalog.builtinRules.some(rule => rule.code === 'builtin.route_https'));
  h.check(true, 'actual 1.5 adapter and fixed typed governance catalog are available through BFF');

  const ruleBody = freeze('m10-custom-rule-create', () => ({ code: `acceptance.${h.state.tag}.retries`, name: `${h.state.tag} Retries`, description: 'Service retries must be at least one', severity: 'warn', given: { entityTypes: ['services'] }, then: { path: 'retries', op: 'min', value: 1 }, enabled: true }));
  const createdRule = (await h.once('m10-custom-rule-create', admin, gov('rules'), 'POST', ruleBody)).data; let rule = createdRule.entity; assert(rule?.id); h.state.governanceFixtures ??= {}; h.state.governanceFixtures.ruleId = rule.id; h.save();
  const createdProof = await receipt('m10-custom-rule-create', cid, wid, 'rule-change'); assert.equal(createdProof.domain, 'iam'); assert.equal(createdProof.configurationCommitted, true); assert.equal(createdProof.executionCompleted, true);
  const updateRuleBody = freeze('m10-custom-rule-update', () => ({ revision: rule.revision, severity: 'error', description: 'Version two: Service retries must be at least one' }));
  rule = (await h.once('m10-custom-rule-update', admin, gov(`rules/${rule.id}`), 'PATCH', updateRuleBody)).data.entity; assert.equal(rule.currentVersion, 2); assert.equal(rule.severity, 'error');
  await onceExpected('m10-rule-stale-cas', admin, gov(`rules/${rule.id}`), 'PATCH', freeze('m10-rule-stale-cas', () => ({ revision: updateRuleBody.revision, enabled: false })), [409]);
  const clone = (await h.once('m10-rule-clone', admin, gov(`rules/${rule.id}/clone`), 'POST', freeze('m10-rule-clone', () => ({ code: `${ruleBody.code}.clone`, name: `${ruleBody.name} Clone` })))).data.entity; assert(clone?.id && clone.id !== rule.id); assert.deepEqual(clone.then, rule.then);
  const archivedRule = (await h.once('m10-rule-archive', admin, gov(`rules/${rule.id}`), 'DELETE', freeze('m10-rule-archive', () => ({ revision: rule.revision, confirmed: true, confirm_name: rule.name })))).data.entity; assert.equal(archivedRule.state, 'deleted');
  rule = (await h.once('m10-rule-restore', admin, gov(`rules/${rule.id}/restore`), 'POST', freeze('m10-rule-restore', () => ({ revision: archivedRule.revision, confirmed: true, confirm_name: archivedRule.name })))).data.entity; assert.equal(rule.state, 'active'); assert(rule.currentVersion >= 4);
  await h.once('m10-clone-disable', admin, gov(`rules/${clone.id}`), 'PATCH', freeze('m10-clone-disable', () => ({ revision: clone.revision, enabled: false })));
  h.check(true, 'custom lint rule direct create/version/clone/archive/restore and stale revision denial use immutable real metadata receipts');

  const inspection = (await h.once(initialInspectionLabel, admin, gov('inspections'), 'POST', inspectBody)).data; assert(inspection.entity?.id); const reportId = inspection.entity.id;
  const initialReport = (await h.request(admin, gov(`reports/${reportId}`))).data; assert.equal(initialReport.entity.projection, false); assert.equal(initialReport.entity.quality, 'complete');
  await receipt(initialInspectionLabel, cid, wid, 'inspection');
  const firstFindings = (await h.request(admin, releaseScope(cid, wid, `governance/reports/${reportId}/findings`, { size: '1' }))).data; assert.equal(firstFindings.items.length, 1); assert(firstFindings.nextCursor); assert.equal(firstFindings.total, null);
  const secondFindings = (await h.request(admin, releaseScope(cid, wid, `governance/reports/${reportId}/findings`, { size: '1', cursor: firstFindings.nextCursor }))).data; assert(secondFindings.items.length > 0); assert.notEqual(secondFindings.items[0].id, firstFindings.items[0].id);
  const allFindings = (await h.request(admin, releaseScope(cid, wid, `governance/reports/${reportId}/findings`, { size: '100' }))).data; assert(!allFindings.nextCursor, 'ACCEPTANCE_FINDING_BUDGET_MUST_FIT_ONE_EXPLICIT_PAGE');
  assert(allFindings.items.some(finding => finding.ruleCode === ruleBody.code && finding.nativeId === source.service.id && finding.severity === 'error'), 'CUSTOM_RULE_MUST_EXECUTE_AGAINST_REAL_SOURCE_ZERO_RETRIES');
  const ownerFinding = allFindings.items.find(finding => finding.nativeId === source.service.id && finding.fixActions.includes('owner_tag_add')); assert(ownerFinding, 'ACTUAL_SOURCE_OWNER_FINDING_REQUIRED');
  h.check(true, 'actual bounded inspection detects source policy findings and signed finding cursor advances without full list retrieval');

  const fix = (await h.once('m10-owner-fix-plan', admin, gov(`reports/${reportId}/findings/${ownerFinding.id}/fix-plan`), 'POST', { action: 'owner_tag_add', values: { ownerTag: 'owner:m10-acceptance' } })).data;
  const fixProof = await receipt('m10-owner-fix-plan', cid, wid, 'fix-plan'); assert.equal(fixProof.jobId, fix.jobId); assert(fixProof.planId); assert.equal(fixProof.targetClusterId, cid); assert.equal(fixProof.targetWorkspaceId, wid);
  const fixed = await apply('m10-owner-fix-apply', cid, wid, fixProof.planId); h.state.governanceFixtures.fixApplyJobId = fixed.jobId; h.save();
  const sourceAfterFix = (await h.request(admin, src(`entities/services/${source.service.id}`))).data.entity; assert(sourceAfterFix.tags.includes('owner:m10-acceptance')); assert(sourceAfterFix.tags.includes(`workspace:${h.state.sourceWorkspace.code}`));
  const verifiedInspection = (await h.once('m10-inspection-after-fix', admin, gov('inspections'), 'POST', inspectBody)).data;
  const afterFindings = (await h.request(admin, releaseScope(cid, wid, `governance/reports/${verifiedInspection.entity.id}/findings`, { size: '100' }))).data;
  assert(!afterFindings.items.some(finding => finding.nativeId === source.service.id && finding.fixActions.includes('owner_tag_add')), 'OWNER_FINDING_MUST_DISAPPEAR_IN_NEW_NATIVE_OBSERVATION');
  h.state.governanceFixtures.reportId = verifiedInspection.entity.id; h.save();
  const reportPageOne = (await h.request(admin, releaseScope(cid, wid, 'governance/reports', { size: '1' }))).data; assert(reportPageOne.nextCursor); const reportPageTwo = (await h.request(admin, releaseScope(cid, wid, 'governance/reports', { size: '1', cursor: reportPageOne.nextCursor }))).data; assert.notEqual(reportPageOne.items[0].id, reportPageTwo.items[0].id);
  h.check(true, 'owner repair generates an actual M8 diff, applies acknowledged native steps and is resolved by a fresh independent inspection');

  const scheduleBody = freeze('m10-schedule-create', () => ({ name: `${h.state.tag} Inspection schedule`, kind: 'inspection', scope: 'workspace', serviceIds: [], ruleCodes: [ruleBody.code], intervalMinutes: 5, timezone: 'Asia/Shanghai', paused: false }));
  const scheduleCreated = (await h.once('m10-schedule-create', admin, gov('schedules'), 'POST', scheduleBody)).data; let schedule = scheduleCreated.entity; assert(schedule?.id); h.state.governanceFixtures.scheduleId = schedule.id; h.save();
  await receipt('m10-schedule-create', cid, wid, 'schedule-change');
  schedule = (await h.once('m10-schedule-pause', admin, gov(`schedules/${schedule.id}`), 'PATCH', freeze('m10-schedule-pause', () => ({ revision: schedule.revision, paused: true })))).data.entity; assert.equal(schedule.state, 'paused');
  schedule = (await h.once('m10-schedule-resume', admin, gov(`schedules/${schedule.id}`), 'PATCH', freeze('m10-schedule-resume', () => ({ revision: schedule.revision, paused: false })))).data.entity; assert.equal(schedule.state, 'active'); assert(schedule.currentVersion >= 3);
  const driftScheduleBody = freeze('m10-drift-schedule-create', () => ({ name: `${h.state.tag} Drift schedule`, kind: 'drift', scope: 'workspace', serviceIds: [], target: { clusterId: targetCid, workspaceId: targetWid, scope: 'workspace', serviceIds: [] }, intervalMinutes: 5, timezone: 'Asia/Shanghai', threshold: 0, includeEnvironmentFields: false, paused: false }));
  const driftSchedule = (await h.once('m10-drift-schedule-create', admin, gov('schedules'), 'POST', driftScheduleBody)).data.entity; assert(driftSchedule?.id); assert.equal(driftSchedule.state, 'active'); await receipt('m10-drift-schedule-create', cid, wid, 'schedule-change');
  const timerFixtures = preserveM10TimerFixtures(h.state.timerFixtures,{ sourceClusterId: cid, sourceWorkspaceId: wid, targetClusterId: targetCid, targetWorkspaceId: targetWid, inspectionScheduleId: schedule.id, driftScheduleId: driftSchedule.id, registeredAt: h.state.timerFixtures?.registeredAt ?? new Date().toISOString() },admin.user.id);
  h.state.timerFixtures = timerFixtures; h.state.governanceFixtures.driftScheduleId = driftSchedule.id; h.save();
  h.check(true, 'actual schedule metadata create/pause/resume persists immutable versions; due timer execution remains a separate acceptance gate');

  let compared, comparisonOriginalKey;
  if (comparisonAcknowledgement) { compared = comparisonAcknowledgement.originalReceipt; comparisonOriginalKey = comparisonAcknowledgement.originalKey; }
  else { compared = (await h.once('m10-logical-comparison', admin, gov('comparisons'), 'POST', comparisonBody)).data; comparisonOriginalKey = packet('m10-logical-comparison').key; }
  let comparisonId = compared.entity?.id; assert(comparisonId);
  let comparison = (await h.request(admin, releaseScope(cid, wid, `governance/comparisons/${comparisonId}`, { size: '100' }))).data; assert.equal(comparison.entity.quality, 'complete'); assert.equal(comparison.entity.source.clusterId, cid); assert.equal(comparison.entity.target.clusterId, targetCid); assert(comparison.entity.counts.modified >= 2); assert(comparison.items.some(change => change.entityType === 'services' && change.sourceNativeId === source.service.id && change.targetNativeId === target.service.id));
  assert(!JSON.stringify(comparison).includes(source.key) && !JSON.stringify(comparison).includes(target.key), 'PUBLIC_DRIFT_MUST_NOT_CONTAIN_REAL_KEYS'); if (!comparisonAcknowledgement) await receipt('m10-logical-comparison', cid, wid, 'comparison');
  if (comparisonAcknowledgement) {
    h.check(true, 'original forbidden comparison POST is retained while a separately observed GET acknowledges its sealed legacy analytical result; no POST is replayed');
    const fresh = (await h.once(comparisonAcknowledgement.freshLabel, admin, gov('comparisons'), 'POST', comparisonBody)).data;
    assert(fresh.entity?.id && fresh.entity.id !== comparisonAcknowledgement.legacyComparisonId, 'FRESH_V2_COMPARISON_IS_AN_INDEPENDENT_INTENT');
    comparisonId = fresh.entity.id; comparisonOriginalKey = packet(comparisonAcknowledgement.freshLabel).key;
    assert.notEqual(comparisonOriginalKey, comparisonAcknowledgement.originalKey, 'FRESH_V2_INTENT_MUST_NOT_REUSE_THE_FORBIDDEN_POST_KEY');
    await receipt(comparisonAcknowledgement.freshLabel, cid, wid, 'comparison');
    comparison = (await h.request(admin, releaseScope(cid, wid, `governance/comparisons/${comparisonId}`, { size: '100' }))).data; assert.equal(comparison.entity.quality, 'complete');
  }
  h.state.governanceFixtures.comparisonId = comparisonId; h.save(); h.check(true, 'two independent native gateways compare by logical identity across different UUIDs without exposing either credential');

  // Denials run before the positive apply, so before/after facts prove no change.
  await onceExpected('m10-reader-rule-write-denied', reader, gov('rules'), 'POST', ruleBody, [403]);
  await onceExpected('m10-reader-fix-plan-denied', reader, gov(`reports/${reportId}/findings/${ownerFinding.id}/fix-plan`), 'POST', { action: 'owner_tag_add', values: { ownerTag: 'owner:forbidden' } }, [403]);
  await onceExpected('m10-forged-proof-denied', admin, gov('comparisons'), 'POST', { ...comparisonBody, sourceProof: { approved: true } }, [400]);
  await h.request(admin, releaseScope(cid, targetWid, `governance/reports/${reportId}`), 'GET', undefined, { expected: [400, 403, 404] });
  await h.request(reader, releaseScope(targetCid, targetWid, `governance/comparisons/${comparisonId}`), 'GET', undefined, { expected: [400, 403, 404] });
  await h.request(reader, gov(`operations/by-key/${comparisonOriginalKey}`), 'GET', undefined, { expected: [403, 404] });
  h.check(true, 'read-only writes, forged DTO proofs, foreign report scope and another actor original-key receipt are rejected');

  await onceExpected('m10-reader-secret-optin-denied', reader, gov(`comparisons/${comparisonId}/promote-plan`), 'POST', { includeEnvironmentFields: false, includeSecrets: true, includeCredentials: true, confirmed: true, confirm_name: comparison.entity.confirmationName }, [403]);
  h.state.governanceFixtures.staleTargetComparisonId = comparisonId; h.save();
  const targetDriftBody = freeze('m10-target-env-host-drift', () => ({ host: `stage-drift.${h.state.tag}.invalid` }));
  await h.once('m10-target-env-host-drift', admin, dst(`entities/services/${target.service.id}`), 'PATCH', targetDriftBody);
  await onceExpected(staleTargetValidationLabel, admin, gov(`comparisons/${comparisonId}/promote-plan`), 'POST', { includeEnvironmentFields: false, includeSecrets: false, includeCredentials: false, confirmed: true, confirm_name: comparison.entity.confirmationName }, [409]);
  const deniedOrigin = (await h.request(admin, gov(`operations/by-key/${packet(staleTargetValidationLabel).key}`))).data;
  assert(!deniedOrigin.jobId && !deniedOrigin.planId && deniedOrigin.nativeExecutionRequested === false, 'STALE_TARGET_ENVIRONMENT_MUST_NOT_CREATE_NATIVE_APPLY_PLAN');
  await h.once('m10-target-env-host-restore', admin, dst(`entities/services/${target.service.id}`), 'PATCH', freeze('m10-target-env-host-restore', () => ({ host: target.service.host })));
  const freshComparison = (await h.once('m10-logical-comparison-after-target-env-restore', admin, gov('comparisons'), 'POST', comparisonBody)).data;
  comparisonId = freshComparison.entity.id; comparison = (await h.request(admin, releaseScope(cid, wid, `governance/comparisons/${comparisonId}`, { size: '100' }))).data;
  assert.equal(comparison.entity.quality, 'complete'); h.state.governanceFixtures.comparisonId = comparisonId; h.save();
  h.check(true, 'target Service environment drift after capture blocks the old Promote before any native plan; a fresh comparison follows explicit fixture restoration');
  const promotionBody = { includeEnvironmentFields: false, includeSecrets: false, includeCredentials: false, confirmed: true, confirm_name: comparison.entity.confirmationName };
  const promotion = (await h.once('m10-promote-default-plan', admin, gov(`comparisons/${comparisonId}/promote-plan`), 'POST', promotionBody)).data;
  const promotionProof = await receipt('m10-promote-default-plan', cid, wid, 'promotion-plan'); assert.equal(promotionProof.planId, promotion.planId); assert(promotionProof.planId); assert.equal(promotionProof.targetClusterId, targetCid); assert.equal(promotionProof.targetWorkspaceId, targetWid);
  const targetBefore = (await h.request(admin, dst(`entities/routes/${target.authRoute.id}`))).data.entity;
  const promotePlan = freshDefaultCycle ? h.state.acceptancePlanSummaries['m10-promote-default-apply-after-outer-origin-anchor'] : (await h.request(admin, dst(`configuration/plans/${promotionProof.planId}`))).data.entity;
  assert(promotePlan&&promotePlan.id===promotionProof.planId,'ORIGINAL_NEGATIVE_TEST_PLAN_SUMMARY_REQUIRED');
  if(freshDefaultCycle)for(const [label,status]of [['m10-reader-native-apply-denied',403],['m10-forged-native-apply-denied',400],['m10-promote-deck-bypass-denied',403]]){
    const cached=h.state.requests.filter(p=>p.label===label);assert.equal(cached.length,1,'ORIGINAL_NEGATIVE_RECEIPT_REQUIRED_NO_NEW_NEGATIVE');assert.equal(cached[0].state,'response_observed');assert.equal(cached[0].status,status);assert.equal(cached[0].path,dst(`configuration/plans/${promotionProof.planId}/apply`));
  }
  await onceExpected('m10-reader-native-apply-denied', reader, dst(`configuration/plans/${promotionProof.planId}/apply`), 'POST', { planRevision: promotePlan.planRevision, planHash: promotePlan.planHash, confirmed: true, confirm_name: promotePlan.name }, [403]);
  await onceExpected('m10-forged-native-apply-denied', admin, dst(`configuration/plans/${promotionProof.planId}/apply`), 'POST', { planRevision: promotePlan.planRevision, planHash: promotePlan.planHash, confirmed: true, confirm_name: promotePlan.name, approved: true }, [400]);
  await onceExpected('m10-promote-deck-bypass-denied', admin, dst(`configuration/plans/${promotionProof.planId}/apply`), 'POST', { planRevision: promotePlan.planRevision, planHash: promotePlan.planHash, confirmed: true, confirm_name: promotePlan.name, driver: 'deck' }, [403]);
  if(h.state.freshDefaultApplyIntent)assert.equal(promotionProof.planId,h.state.freshDefaultApplyIntent.planId);
  let finalDefaultPlanId=promotionProof.planId;
  if(freshDefaultCycle){
    const previousComparisonId=comparisonId,cycleComparison=(await freshCycleOnce(freshDefaultCycle.comparisonLabel,gov('comparisons'),freeze(`${freshDefaultCycle.comparisonLabel}:body`,()=>comparisonBody))).data;
    assert(cycleComparison.entity?.id&&cycleComparison.entity.id!==previousComparisonId,'NEW_DEFAULT_CYCLE_COMPARISON_REQUIRED');comparisonId=cycleComparison.entity.id;
    comparison=(await h.request(admin,releaseScope(cid,wid,`governance/comparisons/${comparisonId}`,{size:'100'}))).data;
    assert.equal(comparison.entity.quality,'complete');assert.equal(comparison.entity.source.clusterId,cid);assert.equal(comparison.entity.source.workspaceId,wid);assert.equal(comparison.entity.target.clusterId,targetCid);assert.equal(comparison.entity.target.workspaceId,targetWid);
    const comparisonReceipt=await receipt(freshDefaultCycle.comparisonLabel,cid,wid,'comparison');assert.equal(comparisonReceipt.state,'succeeded');
    const newBody=freeze(`${freshDefaultCycle.planLabel}:body`,()=>({includeEnvironmentFields:false,includeSecrets:false,includeCredentials:false,confirmed:true,confirm_name:comparison.entity.confirmationName}));
    const newPromotion=(await freshCycleOnce(freshDefaultCycle.planLabel,gov(`comparisons/${comparisonId}/promote-plan`),newBody)).data;
    const newReceipt=await receipt(freshDefaultCycle.planLabel,cid,wid,'promotion-plan');assert.equal(newReceipt.state,'ready');assert.equal(newReceipt.planId,newPromotion.planId);assert.equal(newReceipt.jobId,newPromotion.jobId);
    finalDefaultPlanId=newReceipt.planId;assert(finalDefaultPlanId&&finalDefaultPlanId!==freshDefaultCycle.inputPlanId&&finalDefaultPlanId!==freshDefaultCycle.copiedPlanId);defaultApplyLabel=freshDefaultCycle.applyLabel;
    h.state.governanceFixtures.defaultCycle={proofSha256:freshDefaultCycle.proofSha256,runtimeSourceSha256:freshDefaultCycle.runtimeSourceSha256,previousComparisonId,comparisonId,comparisonReceipt,promotionReceipt:newReceipt,promotionId:newReceipt.id,sourceJobId:newReceipt.jobId,planId:finalDefaultPlanId,applyLabel:defaultApplyLabel};h.state.governanceFixtures.comparisonId=comparisonId;h.save();
  }
  const promoted = await apply(defaultApplyLabel, targetCid, targetWid, finalDefaultPlanId); h.state.governanceFixtures.promoteApplyJobId = promoted.jobId;h.state.governanceFixtures.promoteApplyLabel=defaultApplyLabel;
  if(freshDefaultCycle)h.state.governanceFixtures.defaultCycle.applyJobId=promoted.jobId;h.save();
  const targetService = (await h.request(admin, dst(`entities/services/${target.service.id}`))).data.entity, targetRoute = (await h.request(admin, dst(`entities/routes/${target.authRoute.id}`))).data.entity, targetPlugin = (await h.request(admin, dst(`entities/plugins/${target.plugin.id}`))).data.entity;
  assert.equal(targetService.id, target.service.id); assert.equal(targetService.retries, source.service.retries); assert.equal(targetPlugin.config.status_code, source.plugin.config.status_code); assert.deepEqual(targetRoute.hosts, targetBefore.hosts);
  assert.equal((await h.request(admin, dst(`entities/consumers/${target.consumer.id}`))).data.entity.id, target.consumer.id);
  const targetCredentialPage = (await h.request(admin, releaseScope(targetCid, targetWid, `consumers/${target.consumer.id}/credentials/key-auth`, { size: '100' }))).data; assert(targetCredentialPage.items.some(item => item.id === target.credential.id));
  await proxy('m10-target-own-key-after-promote', targetCid, targetWid, target.authRoute, targetRoute.hosts, target.key, 200);
  await proxy('m10-source-key-rejected-by-target', targetCid, targetWid, target.authRoute, targetRoute.hosts, source.key, 401);
  h.check(true, 'generic target M8 apply preserves target native IDs, target Route environment hosts and target credentials while importing source safe configuration');
  h.check(true, 'actual target proxy accepts its original key and rejects source environment key after default Promote');

  h.state.remainingM10Acceptance = ['authorized secret/credential opt-in actual recovery and proxy authentication', 'due timer execution and owner revocation', 'metadata approval', 'source authority/config drift before each target native packet', 'snapshot rollback', 'storage/audit/secret and actual browser gates'];
  h.state.phase = 'native-m10-core-passed'; h.state.governanceFixtures.ruleName = rule.name; h.state.governanceFixtures.scheduleName = schedule.name; h.save(); h.report(true);
  console.log(JSON.stringify({ passed: true, phase: h.state.phase, checks: h.state.checks.length, commercialAcceptance: false, remainingGates: true }));
} catch (error) {
  h.state.phase = 'native-m10-core-stopped'; h.state.privateAcceptanceFailure = { errorType: error.name, message: String(error.message), stack: String(error.stack ?? '') }; h.save(); h.report(false, 'M10_NATIVE_CORE_ACCEPTANCE_FAILED');
  console.error(JSON.stringify({ passed: false, code: 'M10_NATIVE_CORE_ACCEPTANCE_FAILED', phase: h.state.phase, checks: h.state.checks.length, originalAttemptRetained: true })); process.exitCode = 1;
}
