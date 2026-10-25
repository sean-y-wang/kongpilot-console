import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { WorkflowApprovalAuthorityService } from '../../apps/console-api/src/modules/workflows/workflow-approval-authority.service';
import { normalizeWorkflowApprovalPolicy } from '../../apps/console-api/src/modules/workflows/workflow-approval-policy';
import type { WorkflowPlanV1 } from '../../apps/console-api/src/modules/workflows/workflow.types';

/** Actual HMAC and authority service, SQL explicitly isolated. These tests are
 * not PostgreSQL constraint or native-permit acceptance evidence. */
function fixture() {
  const secrets = new SecretService(), users = [randomUUID(), randomUUID()], cid = randomUUID(), wid = randomUUID(), id = randomUUID(), definitionId = randomUUID();
  const policy = normalizeWorkflowApprovalPolicy({ version: 2, kind: 'portal-publication', allowSelfApproval: false, stages: users.map((user, index) => ({ level: index + 1, name: `阶段 ${index + 1}`, mode: 'any', threshold: 1, selector: { users: [user] } })) });
  const plan: WorkflowPlanV1 = { version: 1, clusterId: cid, workspaceId: wid, workflowId: id, planRevision: 1, kind: 'portal-publication', executionMode: 'approval', approvalRequired: true, subject: { type: 'portal_publications', id: randomUUID() }, requester: { type: 'console', id: randomUUID() }, definition: { id: definitionId, version: 2, policyHash: secrets.fingerprint(policy) }, issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 86400000).toISOString(), scope: { transportScope: 'a'.repeat(64), clusterRevision: 1, workspaceRevision: 1 }, prerequisites: [], steps: [] };
  const hash = secrets.fingerprint(plan), manifest: any = { version: 1, clusterId: cid, workspaceId: wid, workflowId: id, planRevision: 1, planHash: hash, definitionId, definitionVersion: 2, policyHash: plan.definition.policyHash, candidateVersion: 1, stages: users.map((userId, index) => ({ level: index + 1, mode: 'any', threshold: 1, candidates: [{ userId, credentialEpoch: '1', provenance: [{ kind: 'user', selectorId: userId }] }] })) }, manifestHmac = secrets.fingerprint(manifest);
  const decisions = users.map((approver_id, index) => ({ id: randomUUID(), approver_id, decision: 'approve', level: index + 1, plan_hash: hash, candidate_version: 1, candidate_manifest_hmac: manifestHmac }));
  const reviewers = decisions.map(vote => ({ approvalId: vote.id, userId: vote.approver_id, level: vote.level, candidateVersion: 1 }));
  const setMaterial = { version: 1, clusterId: cid, workspaceId: wid, workflowId: id, planRevision: 1, planHash: hash, policyHash: plan.definition.policyHash, candidateVersion: 1, candidateManifestHmac: manifestHmac, reviewers };
  const set = { id: randomUUID(), set_hmac: secrets.fingerprint(setMaterial), manifest: setMaterial }, executionId = randomUUID();
  const row: any = { id, plan_revision: 1, plan_hash: hash, definition_id: definitionId, definition_version: 2, approval_format: 2, approval_required: true, state: 'approved', approved_by: users[1], candidate_version: 1, candidate_manifest_hmac: manifestHmac, approval_set_id: set.id, approval_set_hmac: set.set_hmac };
  const stages = users.map((_, index) => ({ level: index + 1, plan_hash: hash, approval_format: 2, candidate_version: 1, candidate_manifest_hmac: manifestHmac, stage_mode: 'any', required_approvals: 1, revision: index + 2, state: 'approved' }));
  const members = decisions.map(vote => ({ cluster_id: cid, workspace_id: wid, workflow_id: id, plan_revision: 1, plan_hash: hash, set_hmac: set.set_hmac, approval_id: vote.id, user_id: vote.approver_id, level: vote.level, candidate_version: 1, candidate_manifest_hmac: manifestHmac }));
  const db: any = { one: vi.fn(async (sql: string) => {
    if (sql.includes('FROM iam_epoch')) return { version: 1 };
    if (sql.includes('FROM workflow_definition_versions')) return { approval_format: 2, mode: 'multi', allow_self_approval: false, policy_hash: plan.definition.policyHash, policy };
    if (sql.includes('FROM workflow_versions')) return { plan_hash: hash, approval_required: true, approval_format: 2 };
    if (sql.includes('FROM workflow_candidate_versions')) return { manifest, manifest_hmac: manifestHmac };
    if (sql.includes('FROM workflow_approval_sets')) return set;
    if (sql.includes('FROM workflow_executions')) return { approval_format: 2, approval_set_id: set.id, approval_set_hmac: set.set_hmac };
    if (sql.includes('FROM workflow_approval_invalidations')) return null;
    if (sql.includes('FROM workflows')) return row; throw new Error(`Unimplemented fixture query: ${sql}`);
  }), query: vi.fn(async (sql: string) => {
    if (sql.includes('FROM workflow_approvals')) return decisions;
    if (sql.includes('FROM workflow_stages')) return stages;
    if (sql.includes('FROM workflow_approval_set_members')) return members;
    if (sql.includes('FROM workflow_candidates')) return manifest.stages.flatMap((stage: any) => stage.candidates.map((candidate: any) => ({ plan_hash: hash, manifest_hmac: manifestHmac, level: stage.level, user_id: candidate.userId, credential_epoch: candidate.credentialEpoch, provenance: candidate.provenance }))); throw new Error(`Unimplemented fixture query: ${sql}`);
  }) };
  const candidates: any = { assertCurrent: vi.fn() }, service = new WorkflowApprovalAuthorityService(db, secrets, candidates), callback = vi.fn(async () => {});
  return { service, db, plan, users, row, manifest, stages, decisions, members, candidates, callback, executionId, install: () => service.installReviewerPolicy(plan.kind, { verifyCurrent: callback }) };
}
beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ad'.repeat(32))); afterEach(() => vi.unstubAllEnvs());
describe('M11 complete approval set current eligibility', () => {
  it('returns all real decisions and checks every reviewer, not only approved_by', async () => {
    const f = fixture(); f.install(); const set = await f.service.verifyApprovalSet(f.plan, { executionId: f.executionId, checkpoint: 'packet' });
    expect(set.reviewers.map(reviewer => reviewer.userId)).toEqual(f.users); expect(f.callback.mock.calls.map(call => call[0])).toEqual(f.users); expect(f.candidates.assertCurrent).toHaveBeenCalledTimes(2);
  });
  it('requires a fixed reviewer delegate for format 2', async () => {
    const f = fixture(); await expect(f.service.verifyApprovalSet(f.plan, { checkpoint: 'claim' })).rejects.toMatchObject({ response: { code: 'WORKFLOW_REVIEWER_POLICY_UNAVAILABLE' } });
  });
  it('blocks the set when an earlier reviewer loses current authority', async () => {
    const f = fixture(); f.callback.mockImplementation(async (id: string) => { if (id === f.users[0]) throw new ForbiddenException(); }); f.install();
    await expect(f.service.verifyApprovalSet(f.plan, { checkpoint: 'packet' })).rejects.toBeInstanceOf(ForbiddenException); expect(f.callback).toHaveBeenCalledTimes(1);
  });
  it('rejects substituted members and altered candidate manifests', async () => {
    const f = fixture(); f.install(); f.members[0].user_id = randomUUID(); await expect(f.service.verifyApprovalSet(f.plan, { checkpoint: 'claim' })).rejects.toMatchObject({ response: { code: 'WORKFLOW_APPROVAL_SET_INVALID' } });
    const g = fixture(); g.install(); g.manifest.stages[0].candidates[0].userId = randomUUID(); await expect(g.service.verifyApprovalSet(g.plan, { checkpoint: 'claim' })).rejects.toMatchObject({ response: { code: 'WORKFLOW_CANDIDATE_MANIFEST_INVALID' } });
  });
});
