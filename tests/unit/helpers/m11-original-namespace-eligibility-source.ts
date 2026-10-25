import { ConflictException, ForbiddenException } from '@nestjs/common';
import { immutableJson } from '../../../apps/console-api/src/infrastructure/kong/immutable-json';

/** In-memory pre-split eligibility body, retained from the original Source
 * before the configuration Namespace reader was added. Type annotations are
 * erased and private members are accessed through its actual service object.
 * This is a behavioral counterexample, never a runtime or authority adapter. */
export async function originalNamespaceEligibility(this: any, stored: any, tx: any, checkpoint: string): Promise<any> {
  const deny = (code: string) => new ForbiddenException({ code }), changed = (code: string) => new ConflictException({ code });
  if (this.eligibilityScope.getStore()) throw deny('WORKFLOW_SCHEDULE_APPROVAL_FACTS_REENTRANT');
  const { draft } = stored, plan = await this.currentPlan(stored, tx), d = draft.delegation;
  await this.scope(draft, plan, tx); await this.requester(draft, plan, tx);
  const principal = await this.principal(d.executorId, d.executorCredentialEpoch, tx);
  await this.policy(plan.kind).assertSubject(plan, d.executorId, 'write', checkpoint, tx);
  const approvalCheckpoint = checkpoint === 'claim' || checkpoint === 'inspect' ? 'claim' : checkpoint === 'capture' ? 'snapshot' : checkpoint === 'step' ? 'step' : 'packet';
  const frame = this.context.peek();
  const scope: any = frame === null ? { stored, plan, tx, checkpoint: approvalCheckpoint, active: true } : null;
  const verify = async () => {
    if (scope) this.assertEligibilityScope(scope);
    const approvalSet = scope ? await this.readApprovalFacts(scope) : await this.approvals.verifyApprovalSet(plan, { checkpoint: approvalCheckpoint }, tx);
    if (!approvalSet.reviewers.length || approvalSet.policyHash !== plan.definition.policyHash) throw changed('WORKFLOW_SCHEDULE_APPROVAL_REQUIRED');
    for (const reviewer of approvalSet.reviewers) {
      const user = await tx.one("SELECT id FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change", [reviewer.userId]);
      if (!user) throw deny('WORKFLOW_SCHEDULE_REVIEWER_REVOKED');
      await this.policy(plan.kind).assertReviewer(plan, reviewer.userId, checkpoint, tx);
      if (scope) this.assertEligibilityScope(scope);
    }
    if (scope && approvalSet.format === 2) {
      await this.scope(draft, plan, tx); await this.requester(draft, plan, tx);
      this.same(await this.readApprovalFacts(scope), approvalSet, 'WORKFLOW_SCHEDULE_APPROVAL_CHANGED');
    }
    if (stored.activation) this.same(stored.activation, this.activation(plan, approvalSet), 'WORKFLOW_SCHEDULE_APPROVAL_CHANGED');
    const current = await this.principal(d.executorId, d.executorCredentialEpoch, tx);
    if (current.version !== principal.version) throw deny('WORKFLOW_SCHEDULE_EXECUTOR_PERMISSIONS_CHANGED');
    if (scope) { await this.redis.assertLeaseOwnership(); this.assertEligibilityScope(scope); }
    return { draft: immutableJson(draft), plan: immutableJson(plan), approvalSet: immutableJson(approvalSet), principal: principal.user, permissionVersion: principal.version };
  };
  if (!scope) return verify();
  try { return await this.eligibilityScope.run(scope, verify); } finally { scope.active = false; }
}
