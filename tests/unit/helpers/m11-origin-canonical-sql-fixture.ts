import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { expect, vi } from 'vitest';
import { preNamespaceApprovalFixture } from './workflow-pre-namespace-approval-fixture';
import { WorkflowBusinessCurrentIdentityService } from '../../../apps/console-api/src/modules/workflows/workflow-business-current-identity.service';
import { WorkflowScheduledConfigurationOriginService } from '../../../apps/console-api/src/modules/workflows/workflow-scheduled-configuration-origin.service';
import { immutableJson } from '../../../apps/console-api/src/infrastructure/kong/immutable-json';
import { workflowScheduleDraftAad } from '../../../apps/console-api/src/modules/workflows/workflow-schedule.repository';

/** Real Runtime factory, Authority, ApprovalAuthority, Candidates, Material AEAD,
 * Namespace/Context private maps and (for integration) actual Origin handles.
 * Only SQL rows, Namespace's initial issuer and SDK outbound transport are
 * controlled adapters. No canonical verifier/snapshot/Native guard is replaced. */
export async function originCanonicalSqlFixture(reviewerCount = 3, selector: 'user' | 'role' | 'team' = 'user') {
  const f = await preNamespaceApprovalFixture('configuration_v2', reviewerCount, selector, true), now = Date.now();
  const definition: any = { approval_format: 2, mode: 'multi', allow_self_approval: false, policy_hash: f.plan.definition.policyHash, policy: f.policy };
  const control: any = { dbNow: now, viewNow: now, beforeRead: undefined, afterRead: undefined, origin: undefined,
    nativeReady: undefined, fullInspection: undefined, wrapperId: randomUUID(), wrapperOriginId: randomUUID(), nested: null, nestedOrigin: null };
  // Actual active bindings give every raw effective row its complete original
  // provenance. The view timestamp is deliberately held across open/close.
  const bindings = new Map<string, any>(), parties = [f.actor, ...f.reviewers];
  f.tables.iam_effective_grants = [];
  for (const [index, userId] of parties.entries()) {
    const user = f.tables.users.find((row: any) => row.id === userId)!; user.super_admin = false;
    const role = randomUUID(), binding = { id: randomUUID(), user_id: userId, role_id: role, cluster_id: null, workspace_id: null,
      status: 'active', expires_at: new Date(now + 80_000).toISOString(), revision: 1, ...(index % 2 ? { team_id: randomUUID() } : {}) };
    const source = index % 2 ? 'team' : 'user'; bindings.set(binding.id, binding);
    for (const module of ['workflows', 'snapshots', 'services', 'secrets']) for (const action of ['read', 'write', 'approve'])
      f.tables.iam_effective_grants.push({ user_id: userId, role_id: role, role_code: `source-${index}`, permission_id: randomUUID(),
        binding_id: binding.id, binding_source: source, module, action, cluster_id: null, workspace_id: null, scope_type: 'global', scope_values: [] });
  }
  Object.assign(f.job, { state: 'running', lease_generation: 1, lease_owner_hash: '8'.repeat(64), lease_until: f.plan.expiresAt });
  f.cluster.status = 'healthy'; f.cluster.connection_secret = null;
  const rawView = (id: string) => f.tables.iam_effective_grants.filter((grant: any) => {
    const b = bindings.get(grant.binding_id); return grant.user_id === id && b?.status === 'active'
      && (b.expires_at == null || Date.parse(b.expires_at) > control.viewNow);
  });
  const oldOne = f.db.one.getMockImplementation()!, oldQuery = f.db.query.getMockImplementation()!;
  const scheduleRow = () => {
    const { draft: d, claim: c } = f.stored;
    return c && { id: d.scheduleId, kind: 'configuration_v2', executor_id: f.actor, owner_id: f.actor, workflow_id: f.plan.workflowId,
      workflow_plan_revision: f.plan.planRevision, workflow_plan_hash: d.binding.workflowPlanHash, executor_credential_epoch: '1', owner_credential_epoch: '1',
      subject_seal_hmac: d.delegation.subjectSealHmac, transport_scope: d.transportScope, occurrence_id: d.occurrenceId,
      window_start: d.spec.windowStart, not_before: d.spec.notBefore, window_end: d.spec.windowEnd, expires_at: d.delegation.expiresAt,
      created_at: new Date(now - 20_000).toISOString(), draft_ciphertext: f.secrets.encrypt(d, workflowScheduleDraftAad(f.cid, f.wid, d.scheduleId)),
      draft_hmac: f.secrets.fingerprint(d) };
  };
  const seenSql: string[] = [];
  const dispatchOne = async (sql: string, args: any[]) => {
    if (sql.includes('SELECT to_jsonb(j) AS job')) return { job: structuredClone(f.job), observed_at: new Date(control.dbNow).toISOString() };
    if (sql.includes('FROM workflow_definition_versions')) return definition;
    if (sql.includes('FROM workflow_schedules')) return scheduleRow();
    if (sql.includes('FROM workflow_schedule_claims')) { const c = f.stored.claim; return c && { id: c.id, schedule_id: c.scheduleId,
      occurrence_id: c.occurrenceId, generation: c.generation, worker_owner_hmac: c.workerOwnerHmac, workflow_id: c.workflowId,
      workflow_plan_revision: c.workflowPlanRevision, workflow_plan_hash: c.workflowPlanHash, issued_at: c.issuedAt, authority_expires_at: c.authorityExpiresAt }; }
    if (sql.includes('FROM workflow_schedule_progress')) return { claim_id: f.stored.claim?.id, state: f.stored.progress.state };
    if (sql.includes('FROM workflow_schedule_leases')) return { claim_id: f.stored.claim?.id, worker_owner_hmac: f.stored.claim?.workerOwnerHmac, lease_until: f.stored.latestLease?.leaseUntil };
    if (sql.includes('FROM workflow_execution_origins')) return { id: control.wrapperOriginId, claim_id: f.stored.claim?.id,
      schedule_id: f.draft.scheduleId, executor_id: f.actor, cluster_id: f.cid, workspace_id: f.wid, workflow_id: f.plan.workflowId,
      workflow_plan_revision: f.plan.planRevision, workflow_plan_hash: f.draft.binding.workflowPlanHash };
    if (sql.includes('FROM workflow_executions')) return { id: control.wrapperId, state: 'executing', execution_actor_id: f.actor,
      workflow_id: f.plan.workflowId, plan_revision: f.plan.planRevision, plan_hash: f.draft.binding.workflowPlanHash,
      cluster_id: f.cid, workspace_id: f.wid, expires_at: f.plan.expiresAt };
    if (sql.includes('FROM configuration_executions')) return control.nested;
    if (sql.includes('FROM workflow_configuration_execution_origins')) return control.nestedOrigin;
    if (sql.includes('FROM config_snapshot_versions')) return { completeness: 'complete', consistency: 'console_fenced_best_effort', manifest_hmac: f.nested.baselineManifestHmac };
    if (sql.includes('FROM workflow_approval_sets') && args.length === 1) return { ...f.set, workflow_id: f.plan.workflowId, plan_hash: f.draft.binding.workflowPlanHash };
    if (sql.includes('FROM workspaces WHERE cluster_id=$1 AND id=$2')) return f.tables.workspaces.find((row: any) => row.cluster_id === args[0] && row.id === args[1]);
    return oldOne(sql, args);
  };
  f.db.one.mockImplementation(async function (this: unknown, sql: string, args: any[] = []) {
    // A real DbService.one() must retain this when called through the fixed
    // observer; the row adapter enforces that binding independently.
    expect(this).toBe(f.db); seenSql.push(sql); await control.beforeRead?.(sql, args);
    const value = await dispatchOne(sql, args), result = value == null ? value : structuredClone(value);
    await control.afterRead?.(sql, args, result); return result;
  });
  f.db.query.mockImplementation(async function (this: unknown, sql: string, args: any[] = []) {
    expect(this).toBe(f.db); seenSql.push(sql); await control.beforeRead?.(sql, args); let value: any;
    if (sql.includes('SELECT to_jsonb(g) AS grant')) value = rawView(args[0]).map((grant: any) => {
      const binding = bindings.get(grant.binding_id)!;
      return { grant, binding, binding_expires_at: binding.expires_at,
        binding_current: binding.status === 'active' && (binding.expires_at == null || Date.parse(binding.expires_at) > control.dbNow),
        observed_at: new Date(control.dbNow).toISOString() };
    });
    else if (sql.includes('FROM iam_effective_grants')) value = rawView(args[0]);
    else if (sql.includes('FROM workflow_approvals WHERE cluster_id=')) value = f.votes.map((row: any) => ({ ...row, created_at: new Date(now - 5_000).toISOString() }));
    else if (sql.includes('FROM configuration_job_steps')) value = control.nested ? f.nested.steps.map((step: any) => ({ id: step.stepId,
      job_id: f.job.id, execution_id: control.nested.id, plan_revision: f.job.plan_revision, plan_hash: f.job.plan_hash, state: 'pending' })) : [];
    else if (sql.includes('FROM mutation_operations')) value = [];
    else value = await oldQuery(sql, args);
    const result = structuredClone(value); await control.afterRead?.(sql, args, result); return result;
  });
  // Match the real repository's immutable return contract; later row mutations
  // cannot mutate a prior observation through the controlled adapter's alias.
  f.repository.inspectStored.mockImplementation(async () => immutableJson(f.stored));
  const root = (f.runtime as any).configuration.installRootVerifier.mock.calls[0][0];
  for (const method of ['openClosedCheckpoint', 'assertClosedCheckpoint', 'assertClosedCheckpointLive', 'releaseClosedCheckpoint'])
    if (typeof root[method] !== 'function') throw Error(`ACTUAL_RUNTIME_FACTORY_METHOD_REQUIRED:${method}`);
  const identity = new WorkflowBusinessCurrentIdentityService(f.db, f.secrets, f.context, f.redis, f.repository, f.plans, f.canonicalCandidates, f.validation as any);
  // The reused Namespace fixture leaves this constructor dependency closed.
  // Supply the actual Identity service; no verification implementation is mocked.
  (f.runtime as any).identity = identity;
  const origin = new WorkflowScheduledConfigurationOriginService(f.db, f.secrets, f.redis, f.context, f.namespaces);
  // Forwarding spies retain the real installed Root implementation and expose
  // lifecycle evidence for combined Origin tests without substituting policy.
  const observedRoot = { ...root };
  for (const method of ['assertLiveMaterial', 'openClosedCheckpoint', 'assertClosedCheckpoint', 'assertClosedCheckpointLive', 'releaseClosedCheckpoint'])
    observedRoot[method] = vi.fn((...args: any[]) => root[method](...args));
  origin.installRootVerifier(observedRoot); control.origin = origin;
  const current = () => { const handle = f.context.requireWorkflowScheduledNamespaceHandle(); return { handle, proof: f.context.requireWorkflowScheduledCurrentPrincipal(handle).namespace }; };
  const withNamespace = <T>(fn: () => Promise<T>) => f.runInNamespace(async () => {
    f.tables.workflows[0].state = 'executing';
    return fn();
  });
  const withOrigin = <T>(fn: (job: any, execution: any) => Promise<T>) => withNamespace(async () => {
    const { handle, proof } = current();
    // Real fresh Authority eligibility is used for every subsequent Namespace
    // verification. Only initial issuance remains the explicit row adapter.
    const issuer: any = (f.namespaces as any).authority;
    issuer.verifyClaim.mockImplementation(async (_handle: object, phase: string) => {
      const eligible = await f.run(phase); return { version: 1, ...eligible, claim: f.stored.claim,
        leaseUntil: f.stored.latestLease.leaseUntil, authorityExpiresAt: f.stored.claim.authorityExpiresAt };
    });
    return origin.runOriginalJob(handle, control.wrapperId, f.job.id, async job => {
      control.nested = { id: randomUUID(), state: 'executing', execution_mode: 'approval', actor_id: f.actor, cluster_id: f.cid, workspace_id: f.wid,
        job_id: f.job.id, plan_id: f.job.plan_id, plan_revision: f.job.plan_revision, plan_hash: f.job.plan_hash, workflow_id: f.plan.workflowId,
        approved_version: f.plan.planRevision, workflow_plan_hash: f.draft.binding.workflowPlanHash, permission_version: proof.permissionVersion,
        claim_hash: '6'.repeat(64), lease_generation: 1, expires_at: proof.expiresAt, before_snapshot_id: randomUUID(), before_snapshot_version: 1 };
      control.nestedOrigin = { id: randomUUID(), wrapper_origin_id: control.wrapperOriginId, claim_id: proof.claim.id, workflow_execution_id: control.wrapperId,
        workflow_id: f.plan.workflowId, workflow_plan_revision: f.plan.planRevision, workflow_plan_hash: f.draft.binding.workflowPlanHash,
        configuration_job_id: f.job.id, configuration_plan_id: f.job.plan_id, configuration_plan_revision: f.job.plan_revision,
        configuration_plan_hash: f.job.plan_hash, cluster_id: f.cid, workspace_id: f.wid, workflow_step_id: f.plan.steps[0].id };
      return origin.runOriginalConfigurationExecution(job, control.nested.id, execution => fn(job, execution));
    });
  });
  const open = async (phase: 'step' | 'packet' | 'before-send' = 'packet', tx: any = f.db) => { const { handle, proof } = current(); return root.openClosedCheckpoint(handle, proof, phase, tx); };
  const close = (token: object, phase: 'step' | 'packet' | 'before-send' = 'packet', tx: any = f.db) => { const { handle, proof } = current(); return root.assertClosedCheckpoint(token, handle, proof, phase, tx); };
  const assertLive = (token: object, phase: 'step' | 'packet' | 'before-send' = 'packet', tx: any = f.db) => { const { handle, proof } = current(); root.assertClosedCheckpointLive(token, handle, proof, phase, tx); };
  const bindingFor = (userId: string) => bindings.get(f.tables.iam_effective_grants.find((row: any) => row.user_id === userId)!.binding_id)!;
  return { ...f, root, observedRoot, origin, identity, definition, control, bindings, rawView, seenSql, current, withNamespace, withOrigin, open, close, assertLive, bindingFor,
    release: (token: object) => root.releaseClosedCheckpoint(token) };
}

export function installOriginSqlOutbound(f: Awaited<ReturnType<typeof originCanonicalSqlFixture>>, outbound: any) {
  const sdk = { prepared: 0, before: 0, calls: 0 };
  outbound.mockImplementation(async (_base: unknown, path: string, method: string, _body: unknown, _query: unknown, _auth: unknown,
    _timeout: unknown, beforeSend: (() => void) | undefined, prepareSend: (() => Promise<void>) | undefined) => {
    if (method !== 'GET') throw Error('SOURCE_NO_NATIVE_MUTATION');
    if (typeof beforeSend !== 'function' || typeof prepareSend !== 'function') throw Error('ORIGINAL_SDK_GUARDS_REQUIRED');
    await prepareSend(); sdk.prepared++; beforeSend(); sdk.before++; sdk.calls++;
    const read: any = { path, actorId: f.context.current().actor!.id,
      response: path.startsWith('/schemas/') ? { fields: [] } : path.split('/').length === 3 ? { message: 'Not found' } : { data: [], next: null } };
    f.state.native.push({ path, actorId: read.actorId }); await f.state.callback?.(read);
    return { status: path.startsWith('/schemas/') || path.split('/').length === 2 ? 200 : 404, body: read.response, bytes: 32, jsonParsed: true };
  });
  return sdk;
}
