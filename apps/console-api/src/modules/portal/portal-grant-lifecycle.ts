import { BadRequestException } from '@nestjs/common';
import type { DbService } from '../../infrastructure/db.service';
import { assertUnusedPortalCredentialChangeCancellation } from './portal-credential-lifecycle-contract';
import { portalId, requirePortalCas } from './portal-input';

/** SQL-only release of a never-executed reservation. History and allocated IDs
 * remain owned by Portal; this is neither credential revocation nor deletion. */
export async function releaseUnusedPortalReservations(tx:DbService,scope:{clusterId:string;workspaceId:string;applicationId?:string;publicationId?:string;developerId?:string}):Promise<number>{
  for(const id of [scope.clusterId,scope.workspaceId,...[scope.applicationId,scope.publicationId,scope.developerId].filter((value):value is string=>value!==undefined)])portalId(id);
  if(!scope.applicationId&&!scope.publicationId&&!scope.developerId)throw new BadRequestException({code:'PORTAL_RESERVATION_SCOPE_REQUIRED'});
  return tx.exec(`UPDATE portal_application_grants g SET state='disabled',reservation_released_at=now(),revision=revision+1,updated_at=now()
    WHERE g.cluster_id=$1 AND g.workspace_id=$2 AND ($3::uuid IS NULL OR g.application_id=$3) AND ($4::uuid IS NULL OR g.publication_id=$4) AND ($5::uuid IS NULL OR g.developer_id=$5)
    AND g.reservation_released_at IS NULL AND g.state IN ('pending','disabled') AND g.current_generation=0 AND g.current_credential_id IS NULL AND g.acl_credential_ref_id IS NULL
    AND EXISTS(SELECT 1 FROM workflows w WHERE w.id=g.workflow_id AND w.cluster_id=g.cluster_id AND w.workspace_id=g.workspace_id AND w.subject_type='portal_application_grants' AND w.subject_id=g.id AND w.kind='portal-credential-issue' AND w.state IN ('cancelled','rejected','expired'))
    AND NOT EXISTS(SELECT 1 FROM workflows w WHERE w.cluster_id=g.cluster_id AND w.workspace_id=g.workspace_id AND w.subject_type='portal_application_grants' AND w.subject_id=g.id AND (w.kind<>'portal-credential-issue' OR w.state NOT IN ('cancelled','rejected','expired')))
    AND NOT EXISTS(SELECT 1 FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id WHERE w.cluster_id=g.cluster_id AND w.workspace_id=g.workspace_id AND w.subject_type='portal_application_grants' AND w.subject_id=g.id)
    AND NOT EXISTS(SELECT 1 FROM mutation_operations m JOIN workflows w ON w.id=m.workflow_id WHERE w.cluster_id=g.cluster_id AND w.workspace_id=g.workspace_id AND w.subject_type='portal_application_grants' AND w.subject_id=g.id)
    AND NOT EXISTS(SELECT 1 FROM workflow_steps s JOIN workflows w ON w.id=s.workflow_id WHERE w.cluster_id=g.cluster_id AND w.workspace_id=g.workspace_id AND w.subject_type='portal_application_grants' AND w.subject_id=g.id AND (s.state<>'pending' OR s.operation_id IS NOT NULL OR s.receipt_secret IS NOT NULL OR s.safe_result<>'{}'::jsonb OR s.started_at IS NOT NULL OR s.completed_at IS NOT NULL OR s.after_fingerprint IS NOT NULL OR s.recycle_entry_id IS NOT NULL))
    AND NOT EXISTS(SELECT 1 FROM portal_credentials c WHERE c.grant_id=g.id AND (c.state<>'pending' OR c.credential_ref_id IS NOT NULL OR c.issue_operation_id IS NOT NULL OR c.revoke_workflow_id IS NOT NULL OR c.revoke_operation_id IS NOT NULL OR c.last_revealed_at IS NOT NULL OR c.recycle_entry_id IS NOT NULL OR c.revoked_at IS NOT NULL OR c.deleted_at IS NOT NULL OR c.retention_until IS NOT NULL OR NOT EXISTS(SELECT 1 FROM workflows w WHERE w.id=c.workflow_id AND w.cluster_id=g.cluster_id AND w.workspace_id=g.workspace_id AND w.subject_type='portal_application_grants' AND w.subject_id=g.id AND w.kind='portal-credential-issue' AND w.state IN ('cancelled','rejected','expired'))))
    AND NOT EXISTS(SELECT 1 FROM mutation_operations m WHERE m6_portal_scope_alias(m.cluster_id,g.transport_scope,g.cluster_id) AND ((m.entity_type='consumers' AND m.entity_id=g.consumer_id::text) OR (m.entity_type='credentials' AND (m.parent_id=g.consumer_id::text OR m.entity_id=g.acl_id::text OR m.entity_id IN(SELECT c.kong_id::text FROM portal_credentials c WHERE c.grant_id=g.id)))))
    AND NOT EXISTS(SELECT 1 FROM credential_refs r WHERE m6_portal_scope_alias(r.cluster_id,g.transport_scope,g.cluster_id) AND (r.consumer_id=g.consumer_id OR r.kong_id=g.acl_id OR r.kong_id IN(SELECT c.kong_id FROM portal_credentials c WHERE c.grant_id=g.id)))`,[scope.clusterId,scope.workspaceId,scope.applicationId??null,scope.publicationId??null,scope.developerId??null]);
}

/**
 * After an unused portal-credential-rotate / revoke workflow reaches
 * cancelled | rejected | expired: soft-delete never-activated pending
 * credentials created by that workflow, then CAS grant rotating|revoking → active.
 * Does not revoke live keys or release issue reservations.
 */
export async function restoreUnusedPortalCredentialChange(
  tx: DbService,
  input: Readonly<{
    clusterId: string;
    workspaceId: string;
    workflowId: string;
    kind: string;
    workflowTerminal: 'cancelled' | 'rejected' | 'expired';
  }>,
): Promise<'restored' | 'noop'> {
  for (const id of [input.clusterId, input.workspaceId, input.workflowId]) portalId(id);
  if (!['portal-credential-rotate', 'portal-credential-revoke'].includes(input.kind)) return 'noop';
  const grant = await tx.one<{
    id: string;
    revision: number;
    state: string;
    workflow_id: string;
  }>(
    `SELECT id, revision, state, workflow_id FROM portal_application_grants
     WHERE workflow_id=$1 AND cluster_id=$2 AND workspace_id=$3 FOR UPDATE`,
    [input.workflowId, input.clusterId, input.workspaceId],
  );
  if (!grant) return 'noop';
  if (!['rotating', 'revoking'].includes(grant.state)) return 'noop';
  assertUnusedPortalCredentialChangeCancellation({
    kind: input.kind,
    grantState: grant.state,
    workflowTerminal: input.workflowTerminal,
  });
  // Soft-delete unused pending credentials for this workflow only (no native evidence).
  await tx.exec(
    `UPDATE portal_credentials SET state='deleted', deleted_at=now(),
      retention_until=now() + interval '30 days', revision=revision+1, updated_at=now()
     WHERE grant_id=$1 AND workflow_id=$2 AND cluster_id=$3 AND workspace_id=$4
       AND state='pending'
       AND credential_ref_id IS NULL AND issue_operation_id IS NULL
       AND revoke_workflow_id IS NULL AND revoke_operation_id IS NULL
       AND recycle_entry_id IS NULL AND last_revealed_at IS NULL
       AND revoked_at IS NULL AND deleted_at IS NULL`,
    [grant.id, input.workflowId, input.clusterId, input.workspaceId],
  );
  requirePortalCas(
    await tx.exec(
      `UPDATE portal_application_grants SET state='active', revision=revision+1, updated_at=now()
       WHERE id=$1 AND revision=$2 AND state IN ('rotating','revoking') AND workflow_id=$3
         AND cluster_id=$4 AND workspace_id=$5`,
      [grant.id, grant.revision, input.workflowId, input.clusterId, input.workspaceId],
    ),
  );
  return 'restored';
}
