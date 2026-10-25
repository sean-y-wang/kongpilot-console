import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { GovernanceService } from '../../apps/console-api/src/modules/governance/governance.service';
import { GovernanceRepositoryService } from '../../apps/console-api/src/modules/governance/governance-repository.service';
import { governanceReceiptResult } from '../../apps/console-web/src/features/governance.model';

// Explicit synthetic SQL receipts. The real public service and shared Web
// recovery verifier run here; no gateway or deployment evidence is claimed.
function fixture() {
  const cid = randomUUID(), wid = randomUUID(), uid = randomUUID(), key = randomUUID();
  const id = randomUUID(), reportId = randomUUID(), findingId = randomUUID(), nativeId = randomUUID();
  const secrets = new SecretService();
  const actor = { user: { id: uid, username: 'independent-review', superAdmin: false }, workspaceId: wid, idempotencyKey: key };
  const fix = { id, actor_id: uid, cluster_id: cid, workspace_id: wid, idempotency_key: key,
    report_id: reportId, finding_id: findingId, target_workspace_id: wid, state: 'uncertain', configuration_job_id: null,
    plan_id: null, workflow_id: null };
  const state: { job: any; metadata: any; denied: boolean; permissionVersion: string } = {
    job: { id: randomUUID(), cluster_id: cid, workspace_id: wid, actor_id: uid,
      idempotency_key: `governance-fix-${id}`, kind: 'import', request_hmac: 'f'.repeat(64), state: 'succeeded',
      plan_id: randomUUID(), plan_revision: 1, plan_hash: 'e'.repeat(64) },
    metadata: null, denied: false, permissionVersion: '1',
  };
  const inventory = { scope: { kind: 'workspace', clusterId: cid, workspaceId: wid },
    objects: [{ entityType: 'services', nativeId, objectWorkspaceId: wid,
      payload: { id: nativeId, name: 'authorized-service', host: 'example.test', tags: [] } }] };
  const report = { id: reportId, cluster_id: cid, workspace_id: wid, run_state: 'succeeded',
    quality: 'complete', projection: false, object_count: 1, finding_count: 1,
    counts: { error: 0, warn: 1, info: 0 }, observed_from: new Date().toISOString(),
    observed_until: new Date().toISOString(), created_at: new Date().toISOString() };
  const db: any = {
    one: vi.fn(async (sql: string, params: any[]) => {
      if (sql.includes('FROM configuration_jobs')) {
        if (params[0] !== uid || params[1] !== cid || params[2] !== wid || params[3] !== `governance-fix-${id}`) return null;
        return state.job;
      }
      if (sql.includes('FROM governance_promotions')) return null;
      if (sql.includes('FROM governance_metadata_requests')) return null;
      if (sql.includes('FROM iam_operations')) return state.metadata ? { id: state.metadata.id,
        module: 'annotations', target_id: nativeId, payload_secret: secrets.encrypt({
          governanceResource: 'entity_annotations', resourceId: nativeId, operation: 'update',
          originalRequestHmac: 'f'.repeat(64),
        }, `iam:${state.metadata.id}:payload`) } : null;
      throw new Error(`Unexpected read in original-key fixture: ${sql}`);
    }),
    exec: vi.fn(async () => { throw new Error('GET original-key lookup must not write'); }),
    transaction: vi.fn(async () => { throw new Error('GET original-key lookup must not transact a closure'); }),
  };
  const authz: any = {
    assertCluster: vi.fn(async (user: any, cluster: string, _module: string, _action: string, workspace: string) => {
      if (user.id !== uid || cluster !== cid || workspace !== wid) throw new ForbiddenException({ code: 'PERMISSION_DENIED' });
    }),
    permissionVersion: vi.fn(async () => state.permissionVersion),
    assertScopedResource: vi.fn(async () => { if (state.denied) throw new ForbiddenException({ code: 'PERMISSION_DENIED' }); }),
    assertEntity: vi.fn(async () => { if (state.denied) throw new ForbiddenException({ code: 'PERMISSION_DENIED' }); }),
    hasWholeWorkspace: vi.fn(async () => false),
  };
  const repo: any = {
    runByKey: vi.fn(async () => null),
    fixByKey: vi.fn(async (userId: string, originalKey: string) => userId === uid && originalKey === key ? fix : null),
    report: vi.fn(async (requestedId: string, cluster: string, workspace: string) => {
      if (requestedId !== reportId || cluster !== cid || workspace !== wid) throw new Error('Foreign report read');
      return report;
    }),
    inventory: vi.fn(() => inventory),
    fixChild: (row: any) => new GovernanceRepositoryService(db, secrets).fixChild(row),
  };
  const metadata: any = { receipt: vi.fn(async () => state.metadata) };
  const configuration: any = { importDocument: vi.fn(), createToolboxBatchPlan: vi.fn(), createGovernancePromotionPlan: vi.fn() };
  const authority: any = { acquireActor: vi.fn(), acquireDueSchedule: vi.fn() }, capture: any = { captureActor: vi.fn(), capture: vi.fn() };
  const workspaces: any = { resolve: vi.fn(async (_cluster: string, workspace: string) => ({ id: workspace })), get: vi.fn() };
  const sealChild = (descriptor: Record<string, any>) => Object.assign(fix, {
    child_kind: descriptor.domain, child_request_hmac: descriptor.requestHmac,
    child_request_secret: secrets.encrypt(descriptor, `governance:fix-child:${id}`),
  });
  sealChild({ domain: 'configuration', kind: 'import', requestHmac: 'f'.repeat(64) });
  const service = new GovernanceService(db, {} as any, secrets, {} as any,
    authz, workspaces, authority, capture, repo, metadata, configuration, {} as any);
  const lookup = () => service.receipt(cid, key, actor);
  const reference = { actorId: uid, clusterId: cid, workspaceId: wid, idempotencyKey: key, kind: 'fix-plan' as const };
  const noExecution = () => {
    expect(db.exec).not.toHaveBeenCalled(); expect(db.transaction).not.toHaveBeenCalled();
    expect(configuration.importDocument).not.toHaveBeenCalled(); expect(configuration.createToolboxBatchPlan).not.toHaveBeenCalled();
    expect(configuration.createGovernancePromotionPlan).not.toHaveBeenCalled(); expect(authority.acquireActor).not.toHaveBeenCalled();
    expect(authority.acquireDueSchedule).not.toHaveBeenCalled(); expect(capture.captureActor).not.toHaveBeenCalled(); expect(capture.capture).not.toHaveBeenCalled();
  };
  return { cid, wid, uid, key, id, nativeId, actor, fix, state, service, lookup, reference, db, authz, repo, metadata, noExecution, sealChild };
}

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ce'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

describe('M10 independent original-key recovery and IDOR regression', () => {
  it('returns an actual known child plan link after parent completion was lost without relabeling or executing', async () => {
    const f = fixture(), receipt = await f.lookup();
    expect(receipt).toMatchObject({ actorId: f.uid, clusterId: f.cid, workspaceId: f.wid,
      idempotencyKey: f.key, state: 'uncertain', jobId: f.state.job.id, planId: f.state.job.plan_id,
      nativeExecutionRequested: false });
    expect(governanceReceiptResult(receipt, f.reference).complete).toBe(false);
    f.noExecution();
  });

  it('recognizes a committed description-only IAM fix using the real metadata domain and original governance key', async () => {
    const f = fixture(); f.state.job = null; f.fix.state = 'ready';
    f.sealChild({ domain: 'metadata', resourceType: 'entity_annotations', resourceId: f.nativeId,
      operation: 'update', requestHmac: 'f'.repeat(64) });
    f.state.metadata = { id: randomUUID(), actorId: f.uid, clusterId: f.cid, workspaceId: f.wid,
      idempotencyKey: `governance-fix-${f.id}`, domain: 'iam', kind: 'schedule-change', state: 'succeeded',
      registrationCompleted: true, submissionCompleted: false, executionCompleted: true,
      configurationCommitted: true, nativeExecutionRequested: false,
      entity: { id: randomUUID(), description: 'Human-authored description' } };
    const receipt = await f.lookup();
    expect(receipt).toMatchObject({ actorId: f.uid, clusterId: f.cid, workspaceId: f.wid, idempotencyKey: f.key,
      kind: 'fix-plan', domain: 'iam', state: 'succeeded', executionCompleted: true,
      configurationCommitted: true, nativeExecutionRequested: false });
    expect(receipt.jobId).toBeUndefined();
    expect(governanceReceiptResult(receipt, f.reference)).toMatchObject({ complete: true, success: true });
    f.noExecution();
  });

  it('rejects the old known receipt when current native subject read permission is revoked', async () => {
    const f = fixture(); f.state.denied = true;
    await expect(f.lookup()).rejects.toMatchObject({ status: 403 });
    expect(f.db.one).not.toHaveBeenCalled(); f.noExecution();
  });

  it('rejects a current user attempting the same original key under a different workspace', async () => {
    const f = fixture();
    await expect(f.service.receipt(f.cid, f.key, { ...f.actor, workspaceId: randomUUID() })).rejects.toMatchObject({ status: 403 });
    expect(f.repo.report).not.toHaveBeenCalled(); expect(f.repo.inventory).not.toHaveBeenCalled();
    expect(f.db.one).not.toHaveBeenCalled(); f.noExecution();
  });

  it.each(['kind', 'input', 'missing-descriptor', 'changed-descriptor'])('does not falsely close a finding with an unrelated deterministic-key child: %s', async kind => {
    const f = fixture();
    if (kind === 'kind') f.state.job.kind = 'export';
    if (kind === 'input') f.state.job.request_hmac = 'a'.repeat(64);
    if (kind === 'missing-descriptor') (f.fix as any).child_request_secret = null;
    if (kind === 'changed-descriptor') (f.fix as any).child_request_hmac = 'a'.repeat(64);
    await expect(f.lookup()).rejects.toMatchObject({ status: 409 });
    f.noExecution();
  });
});
