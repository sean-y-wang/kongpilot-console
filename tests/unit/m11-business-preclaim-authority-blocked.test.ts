import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException, ConflictException, ForbiddenException, HttpException, ServiceUnavailableException } from '@nestjs/common';
import { workflowScheduledFixture } from './helpers/workflow-scheduled-fixture';
import { WorkflowScheduleRepository, workflowDelegationAad, workflowScheduleDraftAad } from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import { planAad } from '../../apps/console-api/src/modules/workflows/workflow.types';

const kinds = ['configuration_v2', 'portal-credential-issue'] as const;
const reasons = ['WORKFLOW_BUSINESS_CONFIGURATION_OWNER_CHANGED', 'WORKFLOW_BUSINESS_SUBJECT_GRANT_REQUIRED',
  'WORKFLOW_SCHEDULE_EXECUTOR_PERMISSIONS_CHANGED'] as const;

/** Real Authority, original installed delegate/private proofs and real Repository
 * (including encrypted stored-material validation, lock, CAS, event and audit
 * call). Only SQL rows/transactions, fixed business policies and Root executor
 * are controlled adapters. No PostgreSQL trigger, runtime or Native acceptance. */
function fixture(kind: typeof kinds[number] = 'configuration_v2') {
  const f = workflowScheduledFixture(kind);
  f.install();
  const events: any[] = [], audit: any = { append: vi.fn(async () => ({ id: randomUUID() })) };
  const real = new WorkflowScheduleRepository(f.db, f.secrets, audit);
  real.installFixedDelegate(f.delegate());
  const originalRead = f.db.one.getMockImplementation()!, originalWrite = f.db.exec.getMockImplementation()!;
  let casMiss = false;
  const storedRow = () => {
    const { draft: d, progress: p } = f.state.stored, b = d.binding, x = d.delegation;
    return { id: d.scheduleId, cluster_id: b.clusterId, workspace_id: b.workspaceId, workflow_id: b.workflowId,
      workflow_plan_revision: b.workflowPlanRevision, workflow_plan_hash: b.workflowPlanHash, base_plan_hash: b.basePlanHash,
      kind: b.kind, version: 1, delegation_id: x.id, delegation_hmac: d.delegationHmac, spec_hmac: d.specHmac,
      spec: structuredClone(d.spec), not_before: d.spec.notBefore, window_start: d.spec.windowStart, window_end: d.spec.windowEnd,
      expires_at: x.expiresAt, occurrence_id: d.occurrenceId, transport_scope: d.transportScope,
      impact_hmac: d.impactHmac, impact: structuredClone(d.impact), draft_hmac: f.secrets.fingerprint(d),
      draft_ciphertext: f.secrets.encrypt(d, workflowScheduleDraftAad(b.clusterId, b.workspaceId, d.scheduleId)),
      owner_id: x.ownerId, executor_id: x.executorId, owner_credential_epoch: x.ownerCredentialEpoch,
      executor_credential_epoch: x.executorCredentialEpoch, requester_type: b.requester.type, requester_id: b.requester.id,
      requester_credential_epoch: b.requester.credentialEpoch, subject_seal_hmac: x.subjectSealHmac,
      definition_id: b.definitionId, definition_version: b.definitionVersion, policy_hash: b.policyHash,
      state: p.state, revision: p.revision, claim_id: p.claimId, reason_code: p.reasonCode,
      payload_secret: f.secrets.encrypt(f.plan, planAad(b.clusterId, b.workspaceId, b.workflowId, b.workflowPlanRevision)) };
  };
  f.db.one.mockImplementation(async (sql: string, values: any[] = []) => {
    const { draft: d, claim: c, latestLease: l, activation: a } = f.state.stored, b = d.binding, x = d.delegation;
    if (sql.includes('SELECT s.*,p.state')) return values[0] === f.scheduleId ? storedRow() : null;
    if (sql.includes('FROM workflow_executor_delegations')) return { id: x.id, version: 1, cluster_id: b.clusterId,
      workspace_id: b.workspaceId, workflow_id: b.workflowId, workflow_plan_revision: b.workflowPlanRevision,
      base_plan_hash: b.basePlanHash, kind: b.kind, subject_type: b.subjectType, subject_id: b.subjectId,
      requester_type: b.requester.type, requester_id: b.requester.id, requester_credential_epoch: b.requester.credentialEpoch,
      owner_id: x.ownerId, executor_id: x.executorId, owner_credential_epoch: x.ownerCredentialEpoch,
      executor_credential_epoch: x.executorCredentialEpoch, spec_hmac: d.specHmac, delegation_hmac: d.delegationHmac,
      policy_hash: b.policyHash, subject_seal_hmac: x.subjectSealHmac, issued_at: x.issuedAt, expires_at: x.expiresAt,
      delegation_ciphertext: f.secrets.encrypt(x, workflowDelegationAad(b.clusterId, b.workspaceId, x.id)) };
    if (sql.includes('FROM workflow_schedule_activations')) return a ? { cluster_id: b.clusterId, workspace_id: b.workspaceId,
      schedule_id: d.scheduleId, workflow_id: b.workflowId, workflow_plan_revision: b.workflowPlanRevision,
      workflow_plan_hash: b.workflowPlanHash, approval_format: a.approvalFormat, approval_required: a.approvalRequired,
      approval_set_id: a.approvalSetId, approval_set_hmac: a.approvalSetHmac, activation: structuredClone(a) } : null;
    if (sql.includes('FROM workflow_schedule_claims')) return c ? { id: c.id, cluster_id: b.clusterId, workspace_id: b.workspaceId,
      schedule_id: c.scheduleId, schedule_version: c.scheduleVersion, occurrence_id: c.occurrenceId, generation: c.generation,
      worker_owner_hmac: c.workerOwnerHmac, workflow_id: c.workflowId, workflow_plan_revision: c.workflowPlanRevision,
      workflow_plan_hash: c.workflowPlanHash, issued_at: c.issuedAt, authority_expires_at: c.authorityExpiresAt,
      initial_lease_until: c.initialLeaseUntil, claim: structuredClone(c) } : null;
    if (sql.includes('FROM workflow_schedule_leases')) return l ? { id: l.id, cluster_id: b.clusterId, workspace_id: b.workspaceId,
      claim_id: l.claimId, generation: l.generation, worker_owner_hmac: l.workerOwnerHmac, lease_version: l.version,
      previous_id: l.previousId, lease_until: l.leaseUntil } : null;
    return originalRead(sql, values);
  });
  f.db.exec.mockImplementation(async (sql: string, values: any[] = []) => {
    if (sql.startsWith('UPDATE workflow_schedule_progress')) {
      const p = f.state.stored.progress;
      if (casMiss || values[0] !== f.scheduleId || values[1] !== p.revision) return 0;
      Object.assign(p, { state: values[2], claimId: values[3] ?? p.claimId, reasonCode: values[4], revision: p.revision + 1 });
      return 1;
    }
    if (sql.startsWith('INSERT INTO workflow_schedule_events')) {
      events.push({ scheduleId: values[3], kind: values[4], actorId: values[5], claimId: values[6], reason: values[7] });
      return 1;
    }
    return originalWrite(sql, values);
  });
  f.db.transaction.mockImplementation(async (fn: any) => {
    const snapshot = structuredClone(f.state.stored), count = events.length;
    try { return await fn(f.db); } catch (error) { f.state.stored = snapshot; events.length = count; throw error; }
  });
  f.repository.inspectStored.mockImplementation((id: string, db?: any) => real.inspectStored(id, db));
  f.repository.appendBlocked.mockImplementation((id: string, reason: string, proof: object) => real.appendBlocked(id, reason, proof));
  return { ...f, real, events, audit, missCas: () => { casMiss = true; } };
}

beforeEach(() => {
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
  vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T20:00:00.000Z'));
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

function noPhysicalExecution(f: ReturnType<typeof fixture>) {
  expect(f.executor.executeClaim).not.toHaveBeenCalled();
  expect(f.state.stored.claim).toBeNull(); expect(f.state.stored.latestLease).toBeNull();
  expect(f.db.exec.mock.calls.every(([sql]: any[]) => sql.includes('pg_advisory_xact_lock')
    || sql.startsWith('UPDATE workflow_schedule_progress') || sql.startsWith('INSERT INTO workflow_schedule_events'))).toBe(true);
}

describe('M11 preclaim current business authority loss (Source-only fixed adapters)', () => {
  for (const kind of kinds) {
    for (const code of reasons.slice(0, 2)) {
      it.each(['executor', 'reviewer'] as const)(`${kind} preserves ${code} for %s without inventing reviewer attribution`, async role => {
        const f = fixture(kind), original = structuredClone(f.state.stored), error = new ForbiddenException({ code });
        (role === 'executor' ? f.policy.assertSubject : f.policy.assertReviewer).mockRejectedValueOnce(error);
        await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
        expect(f.state.stored.progress).toEqual({ state: 'blocked', revision: 2, claimId: null, reasonCode: code });
        expect(f.state.stored.draft).toEqual(original.draft); expect(f.state.stored.plan).toEqual(original.plan);
        expect(f.state.stored.activation).toEqual(original.activation);
        expect(f.events).toEqual([{ scheduleId: f.scheduleId, kind: 'blocked', actorId: f.owner, claimId: null, reason: code }]);
        expect(f.audit.append).toHaveBeenCalledTimes(1);
        expect(f.audit.append.mock.calls[0][0]).toMatchObject({ action: 'workflow.business-schedule.blocked', result: 'failed',
          after: { state: 'blocked', claimId: null, reasonCode: code } });
        expect(f.repository.appendDueClaim).not.toHaveBeenCalled(); noPhysicalExecution(f);
        // Restored fixed-policy authority does not revive the historical terminal.
        const checks = f.policy.assertSubject.mock.calls.length;
        await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
        expect(f.policy.assertSubject).toHaveBeenCalledTimes(checks); expect(f.repository.appendBlocked).toHaveBeenCalledTimes(1);
      });
    }
    it(`${kind} naturally detects the final real principal-version change before claim`, async () => {
      const f = fixture(kind);
      f.policy.assertReviewer.mockImplementationOnce(async () => { f.state.principalVersion = '2'; });
      await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
      expect(f.state.stored.progress.reasonCode).toBe(reasons[2]);
      expect(f.events).toHaveLength(1); expect(f.audit.append).toHaveBeenCalledTimes(1);
      expect(f.repository.appendDueClaim).not.toHaveBeenCalled(); noPhysicalExecution(f);
    });
  }

  const wrongClasses: [string, (code: string) => unknown][] = [
    ['400', code => new BadRequestException({ code })], ['409', code => new ConflictException({ code })],
    ['503', code => new ServiceUnavailableException({ code })], ['generic HTTP403', code => new HttpException({ code }, 403)],
    ['plain getResponse copy', code => ({ getResponse: () => ({ code }), status: 403 })],
    ['ordinary Error with response', code => Object.assign(new Error('controlled adapter failure'), { response: { code }, status: 403 })],
  ];
  for (const code of reasons) {
    it.each(wrongClasses)(`rethrows the original %s object carrying ${code}`, async (_label, make) => {
      const f = fixture(), error = make(code); f.policy.assertSubject.mockRejectedValueOnce(error);
      await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toBe(error);
      expect(f.state.stored.progress).toMatchObject({ state: 'active', revision: 1, claimId: null, reasonCode: null });
      expect(f.repository.appendBlocked).not.toHaveBeenCalled(); expect(f.events).toEqual([]);
      expect(f.audit.append).not.toHaveBeenCalled(); expect(f.repository.appendDueClaim).not.toHaveBeenCalled(); noPhysicalExecution(f);
    });
  }
  it.each(['WORKFLOW_BUSINESS_SUBJECT_GRANT_REQUIRED_EXTRA', 'WORKFLOW_BUSINESS_CONFIGURATION_OWNER_CHANGED_EXTRA',
    'WORKFLOW_SCHEDULE_EXECUTOR_PERMISSIONS_CHANGED_EXTRA', 'WORKFLOW_BUSINESS_MATERIAL_CHANGED', 'AUTHORIZATION_UNAVAILABLE'])
  ('does not terminalize an unknown or similar authorization code: %s', async code => {
    const f = fixture(), error = new ForbiddenException({ code }); f.policy.assertSubject.mockRejectedValueOnce(error);
    await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toBe(error);
    expect(f.repository.appendBlocked).not.toHaveBeenCalled(); expect(f.events).toEqual([]); noPhysicalExecution(f);
  });
  it.each([Object.assign(new Error('controlled read timeout'), { code: 'ETIMEDOUT' }),
    new ServiceUnavailableException({ code: 'READ_ADAPTER_UNAVAILABLE' })])('preserves infrastructure failure without a terminal write', async error => {
    const f = fixture(); f.policy.assertSubject.mockRejectedValueOnce(error);
    await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toBe(error);
    expect(f.repository.appendBlocked).not.toHaveBeenCalled(); expect(f.events).toEqual([]); noPhysicalExecution(f);
  });

  it.each(['WORKFLOW_APPROVER_NO_LONGER_ELIGIBLE', 'WORKFLOW_APPROVER_SELECTOR_REVOKED'])('retains the existing genuine selector mapping: %s', async code => {
    const f = fixture(); f.approvals.verifyApprovalSet.mockRejectedValueOnce(new ForbiddenException({ code }));
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
    expect(f.events[0].reason).toBe('WORKFLOW_SCHEDULE_REVIEWER_REVOKED'); noPhysicalExecution(f);
  });
  it('retains the existing canonical executor-revocation terminal', async () => {
    const f = fixture(); f.state.ownerActive = false;
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
    expect(f.events[0].reason).toBe('WORKFLOW_SCHEDULE_EXECUTOR_REVOKED'); noPhysicalExecution(f);
  });

  it.each(reasons.slice(0, 2))('blocks an exact denial at the second private claim verification with zero committed claim: %s', async code => {
    const f = fixture(); f.policy.assertSubject.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new ForbiddenException({ code }));
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
    expect(f.repository.appendDueClaim).toHaveBeenCalledTimes(1); expect(f.events[0].reason).toBe(code); noPhysicalExecution(f);
  });

  it('uses an original private blocked proof, rejects copies/foreign bindings and deletes it after use', async () => {
    const f = fixture(), code = reasons[1]; let original: object;
    f.policy.assertSubject.mockRejectedValueOnce(new ForbiddenException({ code }));
    f.repository.appendBlocked.mockImplementation(async (id: string, reason: string, proof: object) => {
      original = proof;
      for (const candidate of [{}, { ...proof }]) await expect(f.real.appendBlocked(id, reason, candidate))
        .rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_PROOF_REQUIRED' } });
      await expect(f.real.appendBlocked(id, reasons[0], proof)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_PROOF_REQUIRED' } });
      await expect(f.delegate().verifyBlocked(randomUUID(), reason, proof, f.db)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_PROOF_REQUIRED' } });
      return f.real.appendBlocked(id, reason, proof);
    });
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
    await expect(f.real.appendBlocked(f.scheduleId, code, original!)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_PROOF_REQUIRED' } });
    expect(f.events).toHaveLength(1); expect(f.audit.append).toHaveBeenCalledTimes(1); noPhysicalExecution(f);
  });
  it.each(['cancelled', 'blocked', 'expired'] as const)('does not overwrite a concurrently observed %s terminal', async state => {
    const f = fixture(); f.policy.assertSubject.mockRejectedValueOnce(new ForbiddenException({ code: reasons[1] }));
    f.repository.appendBlocked.mockImplementation(async (id: string, reason: string, proof: object) => {
      f.state.stored.progress.state = state;
      return f.real.appendBlocked(id, reason, proof);
    });
    await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_FACT_INVALID' } });
    expect(f.state.stored.progress.state).toBe(state); expect(f.events).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
    expect(f.db.exec.mock.calls.some(([sql]: any[]) => sql.startsWith('UPDATE workflow_schedule_progress'))).toBe(false); noPhysicalExecution(f);
  });
  it.each(['claimed', 'running', 'succeeded', 'partial', 'failed', 'uncertain'] as const)
  ('does not overwrite already-present %s claim facts at the real Repository guard', async state => {
    const f = fixture(), beforeClaim = structuredClone(f.state.stored);
    // Obtain the claim/lease through the original Authority/delegate, then model
    // a SQL race by switching the controlled read view after the older active
    // view fails eligibility. Never execute or replay the issued handle.
    const unusedHandle = await f.service.acquireDueClaim(f.scheduleId), alreadyClaimed = structuredClone(f.state.stored);
    expect(unusedHandle).not.toBeNull(); alreadyClaimed.progress.state = state;
    f.state.stored = beforeClaim; f.policy.assertSubject.mockRejectedValueOnce(new ForbiddenException({ code: reasons[1] }));
    f.repository.appendBlocked.mockImplementation(async (id: string, reason: string, proof: object) => {
      f.state.stored = structuredClone(alreadyClaimed);
      return f.real.appendBlocked(id, reason, proof);
    });
    await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_FACT_INVALID' } });
    expect(f.state.stored).toEqual(alreadyClaimed); expect(f.events).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled();
    expect(f.executor.executeClaim).not.toHaveBeenCalled(); expect(f.repository.appendDueClaim).toHaveBeenCalledTimes(1);
    expect(f.db.exec.mock.calls.some(([sql]: any[]) => sql.startsWith('UPDATE workflow_schedule_progress'))).toBe(false);
    await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull(); expect(f.repository.appendDueClaim).toHaveBeenCalledTimes(1);
  });
  it('refuses a missed real Repository CAS and consumes the original proof without emitting a terminal event', async () => {
    const f = fixture(); let proof: object;
    f.policy.assertSubject.mockRejectedValueOnce(new ForbiddenException({ code: reasons[0] })); f.missCas();
    f.repository.appendBlocked.mockImplementation((id: string, reason: string, value: object) => { proof = value; return f.real.appendBlocked(id, reason, value); });
    await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_STATE_CHANGED' } });
    expect(f.state.stored.progress).toMatchObject({ state: 'active', revision: 1, claimId: null, reasonCode: null });
    expect(f.events).toEqual([]); expect(f.audit.append).not.toHaveBeenCalled(); noPhysicalExecution(f);
    await expect(f.delegate().verifyBlocked(f.scheduleId, reasons[0], proof!, f.db)).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_ORIGINAL_PROOF_REQUIRED' } });
  });

  for (const code of reasons) {
    it(`preserves the existing postclaim known-zero failure path for ${code}`, async () => {
      const f = fixture(), handle = await f.service.acquireDueClaim(f.scheduleId), claim = structuredClone(f.state.stored.claim);
      expect(handle).not.toBeNull(); f.policy.assertSubject.mockRejectedValueOnce(new ForbiddenException({ code }));
      await expect(f.service.executeClaim(handle!)).rejects.toMatchObject({ response: { code } });
      expect(f.state.stored.progress).toMatchObject({ state: 'failed', claimId: claim.id });
      expect(f.state.stored.claim).toEqual(claim); expect(f.repository.appendBlocked).not.toHaveBeenCalled();
      expect(f.state.outcomeEvidence.provenance).toBe('callback-not-entered'); expect(f.executor.executeClaim).not.toHaveBeenCalled();
      expect(f.events).toEqual([]); await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
    });
    it(`keeps the original claim held after the fixed Root callback was entered: ${code}`, async () => {
      const f = fixture(), handle = await f.service.acquireDueClaim(f.scheduleId), claim = structuredClone(f.state.stored.claim);
      f.state.beforeExecute = async (original: object) => {
        f.policy.assertSubject.mockRejectedValueOnce(new ForbiddenException({ code }));
        await f.service.verifyClaim(original, 'before-send');
      };
      await expect(f.service.executeClaim(handle!)).rejects.toMatchObject({ response: { code } });
      expect(f.state.stored.progress).toMatchObject({ state: 'claimed', claimId: claim.id });
      expect(f.state.stored.claim).toEqual(claim); expect(f.repository.appendBlocked).not.toHaveBeenCalled();
      expect(f.repository.finishClaim).not.toHaveBeenCalled(); expect(f.events).toEqual([]);
      await expect(f.service.acquireDueClaim(f.scheduleId)).resolves.toBeNull();
    });
  }
});
