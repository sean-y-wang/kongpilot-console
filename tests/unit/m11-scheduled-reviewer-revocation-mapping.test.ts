import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException, ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { EntityScheduledAuthorityService } from '../../apps/console-api/src/modules/workflows/entity-scheduled-authority.service';
import { WorkflowCandidatesService } from '../../apps/console-api/src/modules/workflows/workflow-candidates.service';

// A focused failed-eligibility adapter, not actual SQL/native acceptance. It
// runs the real candidate validator and Authority's private blocked proof, but
// replaces the already-covered material reader/eligibility chain so no test
// invents a successful execution or authentic persisted scope/material fact.
function fixture(kind: 'password-reset' | 'selector-revoked') {
  const scheduleId = randomUUID(), cid = randomUUID(), wid = randomUUID(), reviewer = randomUUID(), owner = randomUUID(), team = randomUUID();
  const state = { progress: 'active', reason: null as string | null, forceChange: kind === 'password-reset', teamCurrent: false };
  const db: any = {
    one: vi.fn(async (sql: string) => {
      if (sql.includes('schema_migrations')) return { checksum: '3b918d1d7f328bfa4c1a5ffa72720ad755dc0aaa11cfa3393dd3b4b297f3955f' };
      if (sql.includes('iam_epoch')) return { version: '1' };
      if (sql.includes('FROM users')) return { status: 'active', deleted_at: null, force_password_change: state.forceChange, credential_epoch: state.forceChange ? '2' : '1' };
      if (sql.includes('FROM team_members')) return state.teamCurrent ? { member: true } : null;
      throw new Error('Unexpected revocation mapping domain read');
    }), exec: vi.fn(), transaction: vi.fn(async (fn: any) => fn(db)),
  };
  const reader = { schedule: vi.fn(async () => ({ row: { state: state.progress, claim_id: null, workflow_id: randomUUID() },
    envelope: { clusterId: cid, workspaceId: wid }, draft: {} })) };
  let policies: any;
  const repository: any = {
    installFixedDelegate: vi.fn((value: any) => { policies = value; }),
    appendDueClaim: vi.fn(async () => { throw new Error('Revoked eligibility must not add a claim'); }),
    appendBlocked: vi.fn(async (id: string, reason: string, proof: object) => { await policies.verifyBlocked(id, reason, proof, db); state.progress = 'blocked'; state.reason = reason; }),
  };
  const redis: any = { withLock: vi.fn(async (_key: string, fn: any) => fn()), assertLeaseOwnership: vi.fn() }, executor = { executeClaim: vi.fn(), verifyCompletion: vi.fn() };
  const service = new EntityScheduledAuthorityService(db, new SecretService(), redis, { peek: () => null } as any, {} as any, {} as any, repository, {} as any, {} as any);
  const candidates = new WorkflowCandidatesService(db), plan: any = { requester: { type: 'console', id: owner }, clusterId: cid, workspaceId: wid };
  const candidate: any = { userId: reviewer, credentialEpoch: '1', provenance: [{ kind: 'team', selectorId: team }] };
  // Only the actual failed server-side check is injected, never a caller DTO
  // or caller-reported revocation code. Reader/proof scope stays fixed here.
  (service as any).reader = reader;
  const eligibility = vi.spyOn(service as any, 'eligibility').mockImplementation(async () => candidates.assertCurrent(plan, candidate, db));
  service.installRepositoryPolicies(); service.installExecutor(executor);
  return { service, scheduleId, db, repository, executor, state, eligibility, policy: () => policies };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ce'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());
describe('M11 scheduled reviewer revocation reason mapping (source-only failed-check adapter)', () => {
  it.each(['password-reset', 'selector-revoked'] as const)('records canonical blocked state for the real %s candidate failure without a claim/native callback', async kind => {
    const f = fixture(kind);
    expect(await f.service.acquireDueClaim(f.scheduleId)).toBeNull();
    expect(f.state).toMatchObject({ progress: 'blocked', reason: 'ENTITY_CHANGE_REVIEWER_INACTIVE' });
    expect(f.repository.appendBlocked).toHaveBeenCalledTimes(1); expect(f.repository.appendDueClaim).not.toHaveBeenCalled(); expect(f.executor.executeClaim).not.toHaveBeenCalled(); expect(f.db.exec).not.toHaveBeenCalled();
    expect(await f.service.acquireDueClaim(f.scheduleId)).toBeNull(); expect(f.repository.appendBlocked).toHaveBeenCalledTimes(1);
    await expect(f.policy().verifyBlocked(f.scheduleId, 'ENTITY_CHANGE_REVIEWER_INACTIVE', {}, f.db)).rejects.toMatchObject({ response: { code: 'ENTITY_SCHEDULE_GENUINE_PROOF_REQUIRED' } });
  });
  it.each([
    new BadRequestException({ code: 'WORKFLOW_APPROVER_NO_LONGER_ELIGIBLE' }),
    new ServiceUnavailableException({ code: 'WORKFLOW_APPROVER_SELECTOR_REVOKED' }),
    new ForbiddenException({ code: 'WORKFLOW_APPROVAL_POLICY_HASH_CHANGED' }),
    new ForbiddenException({ code: 'FOREIGN_WORKSPACE_SCOPE_DENIED' }),
    { getResponse: () => ({ code: 'WORKFLOW_APPROVER_SELECTOR_REVOKED' }) },
  ])('does not classify another failure class, scope/policy error or copied code as reviewer revocation', async error => {
    const f = fixture('selector-revoked'); f.eligibility.mockRejectedValue(error);
    await expect(f.service.acquireDueClaim(f.scheduleId)).rejects.toBe(error);
    expect(f.state.progress).toBe('active'); expect(f.repository.appendBlocked).not.toHaveBeenCalled(); expect(f.repository.appendDueClaim).not.toHaveBeenCalled(); expect(f.executor.executeClaim).not.toHaveBeenCalled();
  });
});
