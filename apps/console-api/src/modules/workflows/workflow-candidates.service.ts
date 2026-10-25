import { ConflictException, ForbiddenException, Injectable } from '@nestjs/common';
import { DbService } from '../../infrastructure/db.service';
import type { WorkflowPlanV1 } from './workflow.types';
import type { WorkflowApprovalSelector, WorkflowCandidateProvenance, WorkflowFrozenCandidate } from './workflow-approval.types';

/** Resolves bounded, real IAM membership. Membership is only selection; the
 * registered subject reviewer policy still decides approval authority. */
@Injectable()
export class WorkflowCandidatesService {
  constructor(private readonly db: DbService) {}
  async resolve(plan: WorkflowPlanV1, selector: WorkflowApprovalSelector, verify: (userId: string) => Promise<void>, tx: DbService = this.db): Promise<WorkflowFrozenCandidate[]> {
    const provenance = new Map<string, WorkflowCandidateProvenance[]>();
    const add = (id: string, proof: WorkflowCandidateProvenance) => {
      if (id === plan.requester.id && plan.requester.type === 'console') return;
      const previous = provenance.get(id) ?? []; previous.push(proof); provenance.set(id, previous);
      if (provenance.size > 1000) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_SELECTOR_TOO_BROAD' });
    };
    for (const id of selector.users ?? []) add(id, { kind: 'user', selectorId: id });
    for (const teamId of selector.teams ?? []) {
      const rows = await tx.query<any>(`SELECT m.user_id FROM team_members m JOIN teams t ON t.id=m.team_id
        WHERE t.id=$1 AND t.status='active' AND t.deleted_at IS NULL AND m.status='active'
          AND(t.cluster_id IS NULL OR t.cluster_id=$2) AND(t.workspace_id IS NULL OR t.workspace_id=$3)
        ORDER BY m.user_id LIMIT 1001`, [teamId, plan.clusterId, plan.workspaceId]);
      if (rows.length > 1000) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_SELECTOR_TOO_BROAD' });
      for (const row of rows) add(row.user_id, { kind: 'team', selectorId: teamId });
    }
    for (const roleId of selector.roles ?? []) {
      const rows = await tx.query<any>(`SELECT DISTINCT g.user_id,g.binding_id,g.binding_source,
          CASE WHEN g.binding_source='team' THEN tb.team_id ELSE NULL END AS team_id
        FROM iam_effective_grants g LEFT JOIN team_role_bindings tb ON g.binding_source='team' AND tb.id=g.binding_id
          LEFT JOIN teams t ON t.id=tb.team_id
        WHERE g.role_id=$1 AND(g.cluster_id IS NULL OR g.cluster_id=$2) AND(g.workspace_id IS NULL OR g.workspace_id=$3)
          AND(g.binding_source='user' OR(t.status='active' AND t.deleted_at IS NULL AND(t.cluster_id IS NULL OR t.cluster_id=$2) AND(t.workspace_id IS NULL OR t.workspace_id=$3)))
        ORDER BY g.user_id,g.binding_id LIMIT 1001`, [roleId, plan.clusterId, plan.workspaceId]);
      if (rows.length > 1000) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_SELECTOR_TOO_BROAD' });
      for (const row of rows) add(row.user_id, { kind: 'role', selectorId: roleId, bindingId: row.binding_id, bindingSource: row.binding_source, ...(row.team_id ? { teamId: row.team_id } : {}) });
    }
    const output: WorkflowFrozenCandidate[] = [];
    for (const [userId, proofs] of [...provenance].sort(([left], [right]) => left.localeCompare(right))) {
      const user = await tx.one<any>("SELECT status,deleted_at,force_password_change,credential_epoch FROM users WHERE id=$1", [userId]);
      if (!user || user.status !== 'active' || user.deleted_at !== null || user.force_password_change) continue;
      try { await verify(userId); } catch (error) { if (error instanceof ForbiddenException) continue; throw error; }
      output.push(Object.freeze({ userId, credentialEpoch: String(user.credential_epoch), provenance: Object.freeze(proofs) }));
      if (output.length > 100) throw new ConflictException({ code: 'WORKFLOW_APPROVAL_CANDIDATE_LIMIT' });
    }
    return output;
  }
  async assertCurrent(plan: WorkflowPlanV1, candidate: WorkflowFrozenCandidate, tx: DbService = this.db): Promise<void> {
    const user = await tx.one<any>("SELECT status,deleted_at,force_password_change,credential_epoch FROM users WHERE id=$1", [candidate.userId]);
    if (!user || user.status !== 'active' || user.deleted_at !== null || user.force_password_change || String(user.credential_epoch) !== candidate.credentialEpoch
      || candidate.userId === plan.requester.id && plan.requester.type === 'console') throw new ForbiddenException({ code: 'WORKFLOW_APPROVER_NO_LONGER_ELIGIBLE' });
    for (const proof of candidate.provenance) {
      if (proof.kind === 'user' && proof.selectorId === candidate.userId) return;
      if (proof.kind === 'team') {
        const member = await tx.one<any>(`SELECT 1 FROM team_members m JOIN teams t ON t.id=m.team_id
          WHERE t.id=$1 AND m.user_id=$2 AND t.status='active' AND t.deleted_at IS NULL AND m.status='active'
            AND(t.cluster_id IS NULL OR t.cluster_id=$3) AND(t.workspace_id IS NULL OR t.workspace_id=$4)`, [proof.selectorId, candidate.userId, plan.clusterId, plan.workspaceId]);
        if (member) return;
      }
      if (proof.kind === 'role') {
        const member = await tx.one<any>(`SELECT 1 FROM iam_effective_grants g
          WHERE g.user_id=$1 AND g.role_id=$2 AND g.binding_id=$3 AND g.binding_source=$4
            AND(g.cluster_id IS NULL OR g.cluster_id=$5) AND(g.workspace_id IS NULL OR g.workspace_id=$6)
            AND($7::uuid IS NULL OR EXISTS(SELECT 1 FROM team_role_bindings b JOIN teams t ON t.id=b.team_id WHERE b.id=g.binding_id AND b.team_id=$7
              AND t.status='active' AND t.deleted_at IS NULL AND(t.cluster_id IS NULL OR t.cluster_id=$5) AND(t.workspace_id IS NULL OR t.workspace_id=$6))) LIMIT 1`,
        [candidate.userId, proof.selectorId, proof.bindingId, proof.bindingSource, plan.clusterId, plan.workspaceId, proof.teamId ?? null]);
        if (member) return;
      }
    }
    throw new ForbiddenException({ code: 'WORKFLOW_APPROVER_SELECTOR_REVOKED' });
  }
}
