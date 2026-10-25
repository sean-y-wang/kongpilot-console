import { BadRequestException, ConflictException, ForbiddenException, Injectable, NotFoundException, OnModuleInit } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DbService } from '../../infrastructure/db.service';
import { SecretService } from '../../infrastructure/secret.service';
import { RedisService } from '../../infrastructure/redis.service';
import { KongExecutionContextService } from '../../infrastructure/kong/execution-context.service';
import { transportScopeFor } from '../../infrastructure/kong/transport-scope';
import { AuthorizationService } from '../authorization/authorization.service';
import { validGrant } from '../authorization/grant-policy';
import { IamMutationsService } from '../iam/iam-mutations.service';
import type { EntityActor } from '../entities/entities.types';
import { AuditService } from '../audit/audit.service';
import { PortalCursor, portalConfirm, portalObject, portalRevision, requirePortalCas } from '../portal/portal-input';
import { WorkflowPlansService } from './workflow-plans.service';
import { WorkflowRegistryService } from './workflow-registry.service';
import { ApprovedWorkflowExecutionService } from './approved-workflow-execution.service';
import { WorkflowApprovalAuthorityService } from './workflow-approval-authority.service';
import { normalizeWorkflowApprovalPolicy } from './workflow-approval-policy';
import { assertWorkflowPolicyMetadataPlan, workflowPolicyMetadataProjection, type WorkflowPolicyMetadataPayload } from './workflow-policy-metadata';
import { workflowId, workflowKey } from './workflow-validation';
import type { WorkflowHandlerInput, WorkflowPlanV1 } from './workflow.types';

interface PolicyRequest {
  id: string; clusterId: string; workspaceId: string; actorId: string; workflowId: string; definitionId: string;
  operation: 'version' | 'archive' | 'restore'; key: string; requestHmac: string; before: any; payload: Record<string, any>;
  scope: { transportScope: string; clusterRevision: number; workspaceRevision: number; executionMode: 'direct' | 'approval' };
}
@Injectable()
export class WorkflowDefinitionsService implements OnModuleInit {
  private readonly cursors = new PortalCursor();
  constructor(private readonly db: DbService, private readonly secrets: SecretService, private readonly redis: RedisService,
    private readonly authz: AuthorizationService, private readonly iam: IamMutationsService, private readonly audit: AuditService,
    private readonly plans: WorkflowPlansService, private readonly registry: WorkflowRegistryService, private readonly approved: ApprovedWorkflowExecutionService,
    private readonly authority: WorkflowApprovalAuthorityService, private readonly context: KongExecutionContextService) {}
  onModuleInit(): void {
    const delegate = Object.freeze({ verifyIntent: (plan: WorkflowPlanV1, tx?: DbService) => this.verifyIntent(plan, tx), verifyReviewer: (id: string, plan: WorkflowPlanV1, tx?: DbService) => this.verifyReviewer(id, plan, tx),
      assertSubject: (plan: WorkflowPlanV1, id: string, action: 'read' | 'write' | 'approve', tx?: DbService) => {
        const frame = this.context.current(); if (!frame.sessionId || frame.actor?.id !== id) throw new ForbiddenException({ code: 'WORKFLOW_POLICY_ACTOR_CONTEXT_REQUIRED' });
        return this.assertWorkflowSubject(plan, { user: frame.actor, workspaceId: plan.workspaceId, requestId: frame.requestId, ip: frame.ip }, action, tx);
      } });
    this.approved.installWorkflowPolicyMetadataDelegate(delegate); this.plans.installWorkflowPolicyMetadataDelegate(delegate);
    this.authority.installReviewerPolicy('workflow-policy-metadata', { verifyCurrent: (id, plan, tx) => this.verifyReviewer(id, plan, tx) });
    this.registry.register('workflow.policy', {
      authorize: (plan, actor, action) => this.assertWorkflowSubject(plan, actor, action),
      inspect: async (input, tx) => { const intent = await this.boundRequest(input.plan, tx), before = await this.target(intent, tx); return { before, revision: before.revision }; },
      apply: input => this.applyApproved(input)
    });
  }
  private async target(intent: PolicyRequest, tx = this.db, lock = false): Promise<any> {
    const row = await tx.one<any>(`SELECT d.id,d.code,d.name,d.kind,d.revision,d.current_version,d.status,d.deleted_at,d.retention_until,v.policy_hash,v.policy,v.approval_format
      FROM workflow_definitions d JOIN workflow_definition_versions v ON v.definition_id=d.id AND v.version=d.current_version AND v.cluster_id=d.cluster_id AND v.workspace_id=d.workspace_id
      WHERE d.id=$1 AND d.cluster_id=$2 AND d.workspace_id=$3${lock ? ' FOR UPDATE OF d' : ''}`, [intent.definitionId, intent.clusterId, intent.workspaceId]);
    if (!row) throw new NotFoundException({ code: 'WORKFLOW_DEFINITION_NOT_FOUND' }); return row;
  }
  private async scope(cid: string, wid: string, tx = this.db): Promise<PolicyRequest['scope']> {
    const row = await tx.one<any>(`SELECT c.admin_url,c.transport_scope,c.revision AS cluster_revision,c.execution_mode,c.status,c.version,w.revision AS workspace_revision,w.status AS workspace_status
      FROM clusters c JOIN workspaces w ON w.cluster_id=c.id WHERE c.id=$1 AND w.id=$2 AND c.deleted_at IS NULL`, [cid, wid]);
    if (!row || row.status === 'disabled' || row.workspace_status !== 'active' || !/^1\.5\.\d+$/.test(row.version ?? '')) throw new ConflictException({ code: 'WORKFLOW_POLICY_SCOPE_UNAVAILABLE' });
    return { transportScope: transportScopeFor(row.admin_url, row.transport_scope), clusterRevision: row.cluster_revision, workspaceRevision: row.workspace_revision, executionMode: row.execution_mode };
  }
  private async boundRequest(plan: WorkflowPlanV1, tx = this.db): Promise<PolicyRequest> {
    const step = assertWorkflowPolicyMetadataPlan(plan), metadata = step.metadata as WorkflowPolicyMetadataPayload;
    const row = await tx.one<any>('SELECT * FROM workflow_policy_requests WHERE id=$1 AND cluster_id=$2 AND workspace_id=$3', [plan.subject.id, plan.clusterId, plan.workspaceId]);
    if (!row) throw new ConflictException({ code: 'WORKFLOW_POLICY_REQUEST_UNAVAILABLE' });
    const intent = this.secrets.decrypt<PolicyRequest>(row.payload_secret, `workflow-policy:${row.id}`);
    if (intent.id !== row.id || intent.clusterId !== plan.clusterId || intent.workspaceId !== plan.workspaceId || intent.workflowId !== plan.workflowId || row.workflow_id !== plan.workflowId || intent.actorId !== plan.requester.id || row.actor_id !== intent.actorId
      || intent.definitionId !== metadata.definitionId || row.definition_id !== intent.definitionId || intent.operation !== metadata.operation || row.operation !== intent.operation || intent.key !== row.idempotency_key || intent.requestHmac !== row.request_hmac
      || this.secrets.fingerprint(intent) !== row.material_hmac || this.secrets.fingerprint(intent.payload) !== metadata.payloadHmac || this.secrets.fingerprint(metadata) !== step.metadataPayloadHmac || this.secrets.fingerprint(intent.before) !== step.metadataBeforeHmac || this.secrets.fingerprint(step.before) !== step.metadataBeforeHmac
      || intent.scope.executionMode !== 'approval' || intent.scope.transportScope !== plan.scope.transportScope || intent.scope.clusterRevision !== plan.scope.clusterRevision || intent.scope.workspaceRevision !== plan.scope.workspaceRevision) throw new ConflictException({ code: 'WORKFLOW_POLICY_REQUEST_BINDING_INVALID' });
    return intent;
  }
  async verifyIntent(plan: WorkflowPlanV1, tx = this.db): Promise<void> { await this.boundRequest(plan, tx); }
  async assertWorkflowSubject(plan: WorkflowPlanV1, actor: EntityActor, action: 'read' | 'write' | 'approve', tx = this.db): Promise<void> {
    const intent = await this.boundRequest(plan, tx);
    if (actor.workspaceId !== plan.workspaceId || action === 'write' && actor.user.id !== intent.actorId) throw new ForbiddenException({ code: 'WORKFLOW_POLICY_EXECUTOR_REQUIRED' });
    await this.authz.assertWholeWorkspace(actor.user, plan.clusterId, plan.workspaceId, 'workflows', action, tx);
    if (action === 'write' && intent.operation === 'archive') await this.authz.assertWholeWorkspace(actor.user, plan.clusterId, plan.workspaceId, 'workflows', 'delete', tx);
    if (action !== 'read') {
      if (this.secrets.fingerprint(await this.scope(plan.clusterId, plan.workspaceId, tx)) !== this.secrets.fingerprint(intent.scope)
        || this.secrets.fingerprint(await this.target(intent, tx)) !== this.secrets.fingerprint(intent.before)) throw new ConflictException({ code: 'WORKFLOW_POLICY_CHANGED' });
    }
  }
  async verifyReviewer(userId: string, plan: WorkflowPlanV1, tx = this.db): Promise<void> {
    const intent = await this.boundRequest(plan, tx), user = await tx.one<any>("SELECT id,super_admin FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND NOT force_password_change", [workflowId(userId)]);
    if (!user) throw new ForbiddenException({ code: 'WORKFLOW_POLICY_REVIEWER_INACTIVE' });
    const grants = (await tx.query<any>('SELECT * FROM iam_effective_grants WHERE user_id=$1', [userId])).filter(validGrant);
    if (!user.super_admin && !grants.some(grant => grant.module === 'workflows' && grant.action === 'approve' && (grant.cluster_id === null || grant.cluster_id === plan.clusterId) && (grant.workspace_id === null || grant.workspace_id === plan.workspaceId)
      && (grant.scope_type === 'global' || grant.scope_type === 'workspace' && grant.cluster_id === plan.clusterId && grant.workspace_id === plan.workspaceId && grant.scope_values.length === 1 && grant.scope_values[0] === plan.workspaceId))) throw new ForbiddenException({ code: 'WORKFLOW_POLICY_REVIEWER_SCOPE_DENIED' });
    if (this.secrets.fingerprint(await this.scope(plan.clusterId, plan.workspaceId, tx)) !== this.secrets.fingerprint(intent.scope)) throw new ConflictException({ code: 'WORKFLOW_POLICY_SCOPE_CHANGED' });
  }
  private async save(intent: PolicyRequest, tx: DbService): Promise<any> {
    const before = await this.target(intent, tx, true);
    if (this.secrets.fingerprint(before) !== this.secrets.fingerprint(intent.before)) throw new ConflictException({ code: 'WORKFLOW_POLICY_CHANGED' });
    if (intent.operation === 'version') {
      const policy = normalizeWorkflowApprovalPolicy(intent.payload.policy, before.kind), version = before.current_version + 1, hash = this.secrets.fingerprint(policy), mode = policy.stages.length > 1 ? 'multi' : policy.stages[0].mode === 'any' ? 'single' : 'quorum';
      await tx.exec(`INSERT INTO workflow_definition_versions(cluster_id,workspace_id,definition_id,version,mode,policy,policy_hash,created_by,approval_format) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,2)`, [intent.clusterId, intent.workspaceId, intent.definitionId, version, mode, JSON.stringify(policy), hash, intent.actorId]);
      for (const stage of policy.stages) await tx.exec(`INSERT INTO workflow_definition_stages(cluster_id,workspace_id,definition_id,definition_version,level,name,required_approvals,selector,approval_format,stage_mode) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,2,$9)`, [intent.clusterId, intent.workspaceId, intent.definitionId, version, stage.level, stage.name, stage.threshold, JSON.stringify(stage.selector), stage.mode]);
      requirePortalCas(await tx.exec("UPDATE workflow_definitions SET current_version=$2,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$3 AND status='active'", [intent.definitionId, version, before.revision]));
    } else if (intent.operation === 'archive') {
      if (before.kind === 'workflow-policy-metadata') throw new BadRequestException({ code: 'WORKFLOW_POLICY_ADMIN_DEFINITION_PROTECTED' });
      requirePortalCas(await tx.exec("UPDATE workflow_definitions SET status='deleted',deleted_at=now(),retention_until=now()+interval '30 days',revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND status='active'", [intent.definitionId, before.revision]));
    } else requirePortalCas(await tx.exec("UPDATE workflow_definitions SET status='active',deleted_at=NULL,retention_until=NULL,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND status='deleted'", [intent.definitionId, before.revision]));
    return this.target(intent, tx);
  }
  private async applyApproved(input: WorkflowHandlerInput): Promise<Record<string, unknown>> {
    const { plan, step, actor, executionId, transaction: tx } = input, intent = await this.boundRequest(plan, tx);
    await this.assertWorkflowSubject(plan, actor, 'write', tx);
    const fact = await tx.one<any>(`SELECT e.id FROM workflow_executions e JOIN workflows w ON w.id=e.workflow_id JOIN workflow_steps s ON s.workflow_id=w.id AND s.plan_revision=e.plan_revision AND s.plan_hash=e.plan_hash
      WHERE e.id=$1 AND e.cluster_id=$2 AND e.workspace_id=$3 AND e.workflow_id=$4 AND e.execution_actor_id=$5 AND e.state='executing' AND w.state='executing' AND s.id=$6 AND s.kind='metadata' AND s.handler='workflow.policy' AND s.state='running' AND s.native_requests='[]'::jsonb AND s.operation_id IS NULL`, [executionId, plan.clusterId, plan.workspaceId, plan.workflowId, actor.user.id, step.id]);
    if (!fact) throw new ForbiddenException({ code: 'WORKFLOW_POLICY_APPROVED_EXECUTION_REQUIRED' });
    const after = await this.save(intent, tx);
    await this.audit.append({ actorId: actor.user.id, clusterId: plan.clusterId, workspaceId: plan.workspaceId, entityType: 'workflow_definitions', entityId: intent.definitionId, workflowId: plan.workflowId, requestId: actor.requestId, ip: actor.ip, action: `workflow.policy.${intent.operation}`, before: workflowPolicyMetadataProjection(intent.before), after: workflowPolicyMetadataProjection(after), result: 'success', scopeHints: { quality: 'verified', module: 'workflows', subject: { type: 'workflow_definitions', id: intent.definitionId }, beforeExists: true, afterExists: true, beforeTags: [], afterTags: [], beforeWorkspaceId: plan.workspaceId, afterWorkspaceId: plan.workspaceId } }, tx);
    return { entity: this.view(after), definitionId: intent.definitionId, operation: intent.operation };
  }
  private view(row: any): Record<string, unknown> { return { id: row.id, code: row.code, name: row.name, kind: row.kind, revision: row.revision, version: row.current_version, status: row.status, format: row.approval_format, policyHash: row.policy_hash, policy: row.policy }; }
  async list(cid: string, query: Record<string, unknown>, actor: EntityActor): Promise<any> {
    portalObject(query, ['workspaceId', 'size', 'cursor']); const wid = workflowId(actor.workspaceId);
    await this.authz.assertWholeWorkspace(actor.user, cid, wid, 'workflows', 'read');
    const size = query.size === undefined ? 20 : Number(query.size); if (!Number.isInteger(size) || size < 1 || size > 100) throw new BadRequestException({ code: 'INVALID_PAGE_SIZE' });
    const version = await this.authz.permissionVersion(actor.user), binding = this.secrets.fingerprint({ cid, wid, actor: actor.user.id, version, size }), offset = this.cursors.decode(query.cursor, binding)?.offset ?? 0;
    const rows = await this.db.query<any>(`SELECT d.*,v.policy,v.policy_hash,v.approval_format FROM workflow_definitions d JOIN workflow_definition_versions v ON v.cluster_id=d.cluster_id AND v.workspace_id=d.workspace_id AND v.definition_id=d.id AND v.version=d.current_version WHERE d.cluster_id=$1 AND d.workspace_id=$2 ORDER BY d.code LIMIT $3 OFFSET $4`, [cid, wid, size, offset]);
    if (await this.authz.permissionVersion(actor.user) !== version) throw new ForbiddenException({ code: 'PERMISSIONS_CHANGED' });
    return { items: rows.map(row => this.view(row)), size, nextCursor: rows.length === size ? this.cursors.encode(binding, { offset: offset + size }) : null };
  }
  async mutate(cid: string, id: string, operation: PolicyRequest['operation'], raw: unknown, actor: EntityActor): Promise<any> {
    const wid = workflowId(actor.workspaceId), key = workflowKey(actor.idempotencyKey), definitionId = workflowId(id), input = portalObject(raw, operation === 'version' ? ['revision', 'policy', 'confirmed', 'confirm_name'] : ['revision', 'confirmed', 'confirm_name']);
    portalRevision(input.revision); await this.authz.assertWholeWorkspace(actor.user, cid, wid, 'workflows', operation === 'archive' ? 'delete' : 'write');
    const request = { definitionId, operation, input }, requestHmac = this.secrets.fingerprint(request);
    return this.redis.withLock(`workflow-policy-original:${actor.user.id}:${key}`, async () => {
      const old = await this.db.one<any>('SELECT * FROM workflow_policy_requests WHERE actor_id=$1 AND idempotency_key=$2', [actor.user.id, key]);
      if (old) { if (old.cluster_id !== cid || old.workspace_id !== wid || old.definition_id !== definitionId || old.request_hmac !== requestHmac) throw new ConflictException({ code: 'IDEMPOTENCY_CONFLICT' }); return { workflowId: old.workflow_id, submissionCompleted: true, nativeExecutionRequested: false }; }
      const prior = await this.db.one<any>('SELECT * FROM iam_operations WHERE actor_id=$1 AND idempotency_key=$2', [actor.user.id, key]);
      if (prior) {
        const payload = prior.payload_secret ? this.secrets.decrypt<any>(prior.payload_secret, `iam:${prior.id}:payload`) : null;
        if (prior.cluster_id !== cid || prior.workspace_id !== wid || prior.module !== 'workflows' || payload?.workflowPolicyRequestHmac !== requestHmac) throw new ConflictException({ code: 'IDEMPOTENCY_CONFLICT' });
        return { operationId: prior.id, state: prior.state, configurationCommitted: prior.state === 'succeeded', nativeExecutionRequested: false };
      }
      const scope = await this.scope(cid, wid), intent: PolicyRequest = { id: randomUUID(), clusterId: cid, workspaceId: wid, actorId: actor.user.id, workflowId: randomUUID(), definitionId, operation, key, requestHmac, scope, before: null, payload: {} };
      const before = await this.target(intent); portalConfirm(input, before.name);
      if (before.revision !== input.revision || (operation === 'restore' ? before.status !== 'deleted' : before.status !== 'active')) throw new ConflictException({ code: 'WORKFLOW_POLICY_CHANGED' });
      if (operation === 'archive' && before.kind === 'workflow-policy-metadata') throw new BadRequestException({ code: 'WORKFLOW_POLICY_ADMIN_DEFINITION_PROTECTED' });
      intent.before = before; intent.payload = operation === 'version' ? { policy: normalizeWorkflowApprovalPolicy(input.policy, before.kind) } : {};
      if (scope.executionMode === 'direct') return this.iam.execute({ module: 'workflows', action: operation === 'archive' ? 'delete' : 'write', targetId: definitionId, cluster_id: cid, workspace_id: wid, payload: { workflowPolicyRequestHmac: requestHmac, definitionId, operation, ...intent.payload }, actor }, async (tx, _operationId, businessAudit) => {
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE');
        if (this.secrets.fingerprint(await this.scope(cid, wid, tx)) !== this.secrets.fingerprint(scope)) throw new ConflictException({ code: 'WORKFLOW_POLICY_SCOPE_CHANGED' });
        const after = await this.save(intent, tx);
        businessAudit({ entityType: 'workflow_definitions', entityId: definitionId, before: workflowPolicyMetadataProjection(before), after: workflowPolicyMetadataProjection(after), scopeHints: { quality: 'verified', module: 'workflows', subject: { type: 'workflow_definitions', id: definitionId }, beforeExists: true, afterExists: true, beforeTags: [], afterTags: [], beforeWorkspaceId: wid, afterWorkspaceId: wid } });
        return { entity: this.view(after), nativeExecutionRequested: false };
      });
      await this.db.transaction(async tx => {
        await tx.one('SELECT version FROM iam_epoch WHERE singleton=true FOR SHARE'); await this.authz.assertWholeWorkspace(actor.user, cid, wid, 'workflows', 'write', tx);
        if (this.secrets.fingerprint(await this.scope(cid, wid, tx)) !== this.secrets.fingerprint(scope) || this.secrets.fingerprint(await this.target(intent, tx, true)) !== this.secrets.fingerprint(before)) throw new ConflictException({ code: 'WORKFLOW_POLICY_CHANGED' });
        await tx.exec(`INSERT INTO workflow_policy_requests(id,cluster_id,workspace_id,actor_id,definition_id,operation,workflow_id,idempotency_key,request_hmac,material_hmac,payload_secret) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [intent.id, cid, wid, actor.user.id, definitionId, operation, intent.workflowId, key, requestHmac, this.secrets.fingerprint(intent), this.secrets.encrypt(intent, `workflow-policy:${intent.id}`)]);
        await this.plans.definitions(cid, wid, actor.user.id, tx); const definition = await this.plans.definition(cid, wid, 'workflow-policy-metadata', tx), metadata: WorkflowPolicyMetadataPayload = { intentId: intent.id, definitionId, operation, payloadHmac: this.secrets.fingerprint(intent.payload) };
        const plan: WorkflowPlanV1 = { version: 1, kind: 'workflow-policy-metadata', clusterId: cid, workspaceId: wid, workflowId: intent.workflowId, planRevision: 1, executionMode: 'approval', approvalRequired: true, subject: { type: 'workflow_policy_requests', id: intent.id }, requester: { type: 'console', id: actor.user.id }, definition, issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 86400000).toISOString(), scope: { transportScope: scope.transportScope, clusterRevision: scope.clusterRevision, workspaceRevision: scope.workspaceRevision }, prerequisites: [], steps: [{ id: randomUUID(), key: 'workflow.policy', order: 1, kind: 'metadata', handler: 'workflow.policy', entityType: 'workflow_policy_requests', entityId: intent.id, permissionAction: operation === 'archive' ? 'delete' : 'write', dependencies: [], nativeRequests: [], before, metadataRevision: before.revision, metadataBeforeHmac: this.secrets.fingerprint(before), metadata, metadataPayloadHmac: this.secrets.fingerprint(metadata) }] };
        await this.plans.persist(plan, key, request, tx, { requestId: actor.requestId, ip: actor.ip }); await this.redis.assertLeaseOwnership();
      });
      return { workflowId: intent.workflowId, submissionCompleted: true, nativeExecutionRequested: false };
    });
  }
}
