import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { certifyTargetReconciliationHistory } from '../../apps/console-api/src/modules/workflows/entity-change-target-reconciliation-proof';
import { normalizeWorkflowApprovalPolicy } from '../../apps/console-api/src/modules/workflows/workflow-approval-policy';
import { entityBaselineAad } from '../../apps/console-api/src/modules/workflows/entity-change-execution-facts.service';
import { entityChangeIntentAad } from '../../apps/console-api/src/modules/workflows/entity-change-workflow';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';
import { targetReconciliationFixture } from './helpers/target-reconciliation-fixture';

type Stage = { mode: 'any' | 'quorum' | 'all'; candidates: number[]; threshold?: number; voters?: number[] };
const invalid = { response: { code: 'ENTITY_CHANGE_TARGET_RECONCILIATION_PROOF_INVALID' } };

/** Complete synthetic historical SELECT/AEAD/HMA fixture, re-sealed from the
 * chosen original policy. It contains no real HTTP status, frozen producer
 * witness, current authorization or native execution authority. */
function fixture(specs: Stage[] = [{ mode: 'any', candidates: [1] }], distinctAcrossStages = true) {
  const f = targetReconciliationFixture(), { plan, envelope, source } = f.input;
  const h = (value: unknown) => f.secrets.fingerprint(value), oldPlanHash = h(plan), oldMaterial = h(envelope);
  const users = new Map<number, string>(), user = (index: number) => { if (!users.has(index)) users.set(index, randomUUID()); return users.get(index)!; };
  const sorted = (values: number[]) => values.map(user).sort();
  const policy = normalizeWorkflowApprovalPolicy({ version: 2, kind: 'native-change', allowSelfApproval: false, distinctAcrossStages, intentTtlHours: 24,
    stages: specs.map((spec, index) => ({ level: index + 1, name: `Historical level ${index + 1}`, mode: spec.mode,
      threshold: spec.mode === 'all' ? null : spec.mode === 'any' ? 1 : spec.threshold ?? 2, selector: { users: sorted(spec.candidates) } })) }, 'native-change');
  plan.definition.policyHash = h(policy); envelope.definition.policyHash = h(policy);
  source.materialHmac = h(envelope);
  plan.steps[0].metadata.materialHmac = source.materialHmac;
  plan.steps[0].metadataPayloadHmac = h(plan.steps[0].metadata);
  source.workflowPlanHash = h(plan);
  for (const rows of Object.values(f.rows) as any[][]) for (const row of rows) {
    if (row.plan_hash === oldPlanHash) row.plan_hash = source.workflowPlanHash;
    if (row.workflow_plan_hash === oldPlanHash) row.workflow_plan_hash = source.workflowPlanHash;
    if (row.material_hmac === oldMaterial) row.material_hmac = source.materialHmac;
  }
  const bound = { cluster_id: plan.clusterId, workspace_id: plan.workspaceId, workflow_id: plan.workflowId, plan_revision: plan.planRevision, plan_hash: source.workflowPlanHash };
  const stages = specs.map((spec, index) => ({ level: index + 1, mode: spec.mode,
    threshold: spec.mode === 'all' ? spec.candidates.length : spec.mode === 'any' ? 1 : spec.threshold ?? 2,
    candidates: sorted(spec.candidates).map(userId => ({ userId, credentialEpoch: '1', provenance: [{ kind: 'user', selectorId: userId }] })) }));
  const manifest = { version: 1, clusterId: plan.clusterId, workspaceId: plan.workspaceId, workflowId: plan.workflowId, planRevision: plan.planRevision,
    planHash: source.workflowPlanHash, definitionId: plan.definition.id, definitionVersion: plan.definition.version, policyHash: plan.definition.policyHash, candidateVersion: 1, stages };
  const manifestHmac = h(manifest), w = f.rows.workflows[0], e = f.rows.workflow_executions[0];
  Object.assign(f.rows.workflow_definition_versions[0], { policy, policy_hash: h(policy) });
  f.rows.workflow_candidate_versions = [{ ...bound, manifest_hmac: manifestHmac, manifest }];
  f.rows.workflow_stages = stages.map(stage => ({ ...bound, level: stage.level, state: 'approved', approval_format: 2,
    candidate_version: 1, candidate_manifest_hmac: manifestHmac, stage_mode: stage.mode, required_approvals: stage.threshold }));
  f.rows.workflow_candidates = stages.flatMap(stage => stage.candidates.map(candidate => ({ ...bound, level: stage.level, user_id: candidate.userId,
    manifest_hmac: manifestHmac, credential_epoch: candidate.credentialEpoch, provenance: candidate.provenance })));
  f.rows.workflow_approvals = specs.flatMap((spec, index) => sorted(spec.voters ?? spec.candidates.slice(0, stages[index].threshold)).map(approver_id => ({
    ...bound, id: randomUUID(), level: index + 1, approver_id, decision: 'approve', candidate_version: 1, candidate_manifest_hmac: manifestHmac })));
  w.candidate_manifest_hmac = manifestHmac;
  w.approved_by = e.approved_by = f.rows.workflow_approvals.at(-1)?.approver_id;
  function resealVotes() {
    const reviewers = f.rows.workflow_approvals.map((vote: any) => ({ approvalId: vote.id, userId: vote.approver_id, level: vote.level, candidateVersion: vote.candidate_version }));
    const set = f.rows.workflow_approval_sets[0], material = { version: 1, clusterId: plan.clusterId, workspaceId: plan.workspaceId,
      workflowId: plan.workflowId, planRevision: plan.planRevision, planHash: source.workflowPlanHash, policyHash: plan.definition.policyHash,
      candidateVersion: 1, candidateManifestHmac: manifestHmac, reviewers }, setHmac = h(material);
    Object.assign(set, bound, { set_hmac: setHmac, manifest: material }); w.approval_set_hmac = e.approval_set_hmac = setHmac;
    f.rows.workflow_approval_set_members = reviewers.map((reviewer: any) => ({ ...bound, set_id: set.id, set_hmac: setHmac,
      approval_id: reviewer.approvalId, user_id: reviewer.userId, level: reviewer.level, candidate_version: reviewer.candidateVersion, candidate_manifest_hmac: manifestHmac }));
  }
  resealVotes();
  f.rows.entity_change_intent_versions[0].envelope_ciphertext = f.secrets.encrypt(envelope, entityChangeIntentAad(plan.clusterId, plan.workspaceId, envelope.intentId, envelope.revision));
  f.rows.workflow_versions[0].payload_secret = f.secrets.encrypt(plan, planAad(plan.clusterId, plan.workspaceId, plan.workflowId, plan.planRevision));
  const baseline = f.rows.entity_change_baselines[0], baselineHmac = h(f.baselineEnvelope);
  baseline.baseline_hmac = baselineHmac; baseline.material_ciphertext = f.secrets.encrypt(f.baselineEnvelope, entityBaselineAad(plan.clusterId, plan.workspaceId, baseline.id));
  f.rows.entity_change_baseline_pins[0].baseline_hmac = baselineHmac;
  const approvedWorkflow = { version: 3, workflowId: plan.workflowId, executionId: source.workflowExecutionId, planRevision: plan.planRevision,
    planHash: source.workflowPlanHash, stepId: plan.steps[0].id, sourceId: source.id, baselineId: baseline.id, attemptId: f.attempt.id,
    packetKey: f.packet.key, nativeId: f.newId, beforeHmac: f.packet.beforeHmac };
  f.mutation.request_hash = h({ actor: source.executionActorId, clusterId: plan.clusterId, workspaceId: plan.workspaceId, entityType: 'targets',
    entityId: f.oldId, action: 'update', payload: f.body, parentId: f.upstream, credentialKind: null, approvedWorkflow });
  return { ...f, policy, manifest, users, resealVotes };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'c3'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('Target zero-weight historical approval derives solely from the original sealed policy', () => {
  it.each([
    ['single any', [{ mode: 'any', candidates: [1] }]],
    ['two-stage', [{ mode: 'any', candidates: [1] }, { mode: 'any', candidates: [2] }]],
    ['three-stage legacy', [{ mode: 'any', candidates: [1] }, { mode: 'any', candidates: [2] }, { mode: 'any', candidates: [3] }]],
    ['four-stage', [1, 2, 3, 4].map(index => ({ mode: 'any', candidates: [index] }))],
    ['eight-stage', [1, 2, 3, 4, 5, 6, 7, 8].map(index => ({ mode: 'any', candidates: [index] }))],
    ['quorum two of four', [{ mode: 'quorum', candidates: [1, 2, 3, 4], threshold: 2 }]],
    ['quorum four of six', [{ mode: 'quorum', candidates: [1, 2, 3, 4, 5, 6], threshold: 4 }]],
    ['all four', [{ mode: 'all', candidates: [1, 2, 3, 4] }]],
    ['mixed quorum and all', [{ mode: 'quorum', candidates: [1, 2, 3], threshold: 2 }, { mode: 'all', candidates: [4, 5] }]],
  ] as Array<[string, Stage[]]>)('authenticates %s without changing historical native unknown facts', async (_name, specs) => {
    const f = fixture(specs), before = structuredClone(f.rows), result = await certifyTargetReconciliationHistory(f.input);
    expect(result).toMatchObject({ nativeAuthority: false, nativeWrites: 0, originalOutcome: 'sent-unknown', nativeStatusRecorded: null,
      requiresFrozenOriginalProducerAttestation: true, requiresFreshCurrentStateObservation: true });
    expect(result.approvalSetId).toBe(f.rows.workflow_approval_sets[0].id);
    expect(f.rows).toEqual(before); expect(f.tx.exec).not.toHaveBeenCalled(); expect(f.tx.transaction).not.toHaveBeenCalled();
    expect([...f.tx.one.mock.calls, ...f.tx.query.mock.calls].every(([sql]: any) => /^SELECT\s/.test(sql) && !/FROM (auth_sessions|users|roles)|FOR UPDATE/.test(sql))).toBe(true);
  });

  it('permits one genuine reviewer at separate levels only when the original policy permits it', async () => {
    const f = fixture([{ mode: 'any', candidates: [1] }, { mode: 'any', candidates: [1] }], false);
    expect(new Set(f.rows.workflow_approvals.map((vote: any) => vote.approver_id)).size).toBe(1);
    await expect(certifyTargetReconciliationHistory(f.input)).resolves.toMatchObject({ nativeWrites: 0 });
  });

  it.each([
    ['cross-stage reuse forbidden', [{ mode: 'any', candidates: [1] }, { mode: 'any', candidates: [1] }], true],
    ['same-stage duplicate with distinct off', [{ mode: 'quorum', candidates: [1, 2], threshold: 2, voters: [1, 1] }], false],
    ['insufficient quorum', [{ mode: 'quorum', candidates: [1, 2, 3], threshold: 2, voters: [1] }], true],
    ['extra quorum vote', [{ mode: 'quorum', candidates: [1, 2, 3], threshold: 2, voters: [1, 2, 3] }], true],
    ['missing all vote', [{ mode: 'all', candidates: [1, 2, 3, 4], voters: [1, 2, 3] }], true],
    ['foreign reviewer', [{ mode: 'any', candidates: [1], voters: [2] }], true],
  ] as Array<[string, Stage[], boolean]>)('rejects coherently sealed %s', async (_name, specs, distinct) => {
    const f = fixture(specs, distinct); await expect(certifyTargetReconciliationHistory(f.input)).rejects.toMatchObject(invalid); expect(f.tx.exec).not.toHaveBeenCalled();
  });

  it.each([
    ['duplicate approval ID', f => { f.rows.workflow_approvals[1].id = f.rows.workflow_approvals[0].id; f.resealVotes(); }],
    ['wrong candidate version', f => { f.rows.workflow_approvals[1].candidate_version = 2; f.resealVotes(); }],
    ['wrong candidate HMA', f => { f.rows.workflow_approvals[1].candidate_manifest_hmac = '0'.repeat(64); f.resealVotes(); }],
    ['self approval', f => { f.rows.workflow_approvals[1].approver_id = f.input.plan.requester.id; f.resealVotes(); }],
    ['rejected original vote', f => { f.rows.workflow_approvals[1].decision = 'reject'; f.resealVotes(); }],
    ['vote from nonexistent level', f => { f.rows.workflow_approvals[1].level = 2; f.resealVotes(); }],
    ['duplicate SQL candidate hiding an unused candidate', f => { f.rows.workflow_candidates[3] = structuredClone(f.rows.workflow_candidates[2]); }],
    ['missing candidate epoch', f => { f.rows.workflow_candidates[1].credential_epoch = '2'; }],
    ['candidate provenance', f => { f.rows.workflow_candidates[1].provenance = [{ kind: 'role', selectorId: randomUUID() }]; }],
    ['duplicate set member', f => { f.rows.workflow_approval_set_members[1] = structuredClone(f.rows.workflow_approval_set_members[0]); }],
    ['missing set member', f => { f.rows.workflow_approval_set_members.pop(); }],
    ['set member foreign scope', f => { f.rows.workflow_approval_set_members[0].workspace_id = randomUUID(); }],
    ['set member candidate version', f => { f.rows.workflow_approval_set_members[0].candidate_version = 2; }],
    ['set manifest tamper', f => { f.rows.workflow_approval_sets[0].manifest.reviewers.pop(); }],
    ['set HMA tamper', f => { f.rows.workflow_approval_sets[0].set_hmac = '0'.repeat(64); }],
    ['definition policy tamper', f => { f.rows.workflow_definition_versions[0].policy = { ...f.policy, distinctAcrossStages: false }; }],
    ['stage threshold tamper', f => { f.rows.workflow_stages[0].required_approvals = 1; }],
    ['unfinished stage', f => { f.rows.workflow_stages[0].state = 'active'; }],
    ['nonreviewer approved_by', f => { f.rows.workflows[0].approved_by = f.rows.workflow_executions[0].approved_by = randomUUID(); }],
  ] as Array<[string, (f: ReturnType<typeof fixture>) => void]>)('rejects %s despite the permitted policy headcount', async (_name, change) => {
    const f = fixture([{ mode: 'quorum', candidates: [1, 2, 3, 4], threshold: 2 }]); change(f);
    await expect(certifyTargetReconciliationHistory(f.input)).rejects.toMatchObject(invalid); expect(f.tx.exec).not.toHaveBeenCalled();
  });

  it('requires approved_by to be an actual final-stage voter', async () => {
    const f = fixture([{ mode: 'any', candidates: [1] }, { mode: 'any', candidates: [2] }]);
    f.rows.workflows[0].approved_by = f.rows.workflow_executions[0].approved_by = f.rows.workflow_approvals[0].approver_id;
    await expect(certifyTargetReconciliationHistory(f.input)).rejects.toMatchObject(invalid);
  });
});
