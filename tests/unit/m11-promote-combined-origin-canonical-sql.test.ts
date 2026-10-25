import 'reflect-metadata';
import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { outboundJson } from '../../apps/console-api/src/infrastructure/kong/outbound';
import { trackEnteredAsyncLocalStorage } from './helpers/release-async-local-storage';
import { promoteOriginCanonicalSqlFixture, installPromoteOriginSqlOutbound } from './helpers/m11-promote-origin-canonical-sql-fixture';

vi.mock('../../apps/console-api/src/infrastructure/kong/outbound', () => ({ outboundJson: vi.fn() }));
const outbound = vi.mocked(outboundJson);
let monotonic: number;
beforeEach(() => {
  vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'e3'.repeat(32)); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-15T20:00:00Z'));
  monotonic = 10_000; vi.spyOn(performance, 'now').mockImplementation(() => monotonic);
});
const releaseStorages = trackEnteredAsyncLocalStorage();
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllEnvs(); releaseStorages(); });
async function fixture() {
  const f = await promoteOriginCanonicalSqlFixture(3), sdk = installPromoteOriginSqlOutbound(f, outbound);
  return { ...f, sdk, sourceRaw: (f as any).sourceRaw };
}

/** Actual Material/dual AEAD lineage, canonical Approval/Candidates, Runtime
 * bootstrap, Origin and Context private references. SQL rows and SDK outbound
 * transport are controlled adapters. No runtime/PostgreSQL/write receipt. */
// Each case constructs the complete real Provider graph and combines canonical
// SQL with original Native source/target observations. Its 30_000ms test wall
// budget does not change Candidate TTL, worker W or any product deadline/budget.
describe('Promote combined original checkpoint and canonical SQL closure', () => {
  it.each(['step', 'packet', 'before-send'] as const)('retains original Native checks and closes real two-plan material at %s', async phase => {
    const f = await fixture(), material = vi.spyOn(f.compiler, 'promoteClosedSqlMaterial');
    await f.withOrigin(async (job: any, execution: any) => {
      const frame = f.context.current(), principal = f.context.requireWorkflowScheduledCurrentPrincipal(f.current().handle);
      f.state.native.length = 0; material.mockClear(); f.observedRoot.assertLiveMaterial.mockClear();
      const pair = await f.origin.verifyOriginalExecutionAndJob(job, execution, phase, f.db);
      expect(pair.execution.jobHandle).toBe(job); expect(pair.job.namespaceHandle).toBe(f.current().handle);
      expect(pair.execution.configurationPlanId).toBe(f.job.plan_id); expect(pair.execution.configurationPlanId).not.toBe(f.row.plan_id);
      expect(pair.job.expiresAt).toBe(pair.execution.expiresAt); expect(f.context.current()).toBe(frame);
      expect(f.context.requireWorkflowScheduledCurrentPrincipal(f.current().handle).namespace).toBe(principal.namespace);
      expect(f.observedRoot.assertLiveMaterial).toHaveBeenCalledOnce(); expect(material.mock.calls.length).toBeGreaterThanOrEqual(6);
      const evidence: any = await material.mock.results.at(-1)!.value;
      expect(evidence.configurationLineage.importJobId).toBe(f.originalJob.id);
      expect(evidence.configurationLineage.importPlanId).toBe(f.row.plan_id);
      expect(evidence.marker.id).toBe(f.row.id); expect(evidence.sourceOrigin).toEqual(f.m.sourceOrigin);
      expect(evidence.subjectSeal).toEqual(f.draft.binding.subjectSeal);
      expect(evidence.registries.map((r: any) => r.cluster.id)).toEqual([f.sourceCid, f.cid]);
      expect(evidence.deadlines.importAuthority).toBe(f.originalJob.authority_expires_at);
      for (const actorId of [f.actor, ...f.reviewers]) for (const clusterId of [f.sourceCid, f.cid])
        expect(f.state.native.some((read: any) => read.actorId === actorId && read.clusterId === clusterId)).toBe(true);
      expect(f.sdk.calls).toBe(f.sdk.prepared); expect(f.sdk.calls).toBe(f.sdk.before);
    });
    expect(f.db.exec).not.toHaveBeenCalled(); expect(f.context.peek()).toBeNull();
  }, 30_000);

  it.each(['executor', 'reviewer-0', 'reviewer-1', 'reviewer-2'])('compares the complete %s source secret grant even when PV/IAM epoch stay fixed', async party => {
    const f = await fixture(); await f.withNamespace(async () => {
      const token = await f.open(), userId = party === 'executor' ? f.actor : f.reviewers[Number(party.at(-1))];
      const row = f.tables.iam_effective_grants.find((g: any) => g.user_id === userId && g.module === 'secrets' && g.action === 'read' && g.cluster_id === f.sourceCid)!;
      row.scope_values = ['foreign-source-workspace'];
      expect(f.tables.iam_epoch[0].version).toBe('1'); const before = f.sdk.calls;
      await expect(f.close(token)).rejects.toBeDefined(); expect(() => f.assertLive(token)).toThrow();
      expect(f.sdk.calls).toBe(before); f.release(token);
    });
  }, 30_000);

  it.each(['executor', 'reviewer-0', 'reviewer-1', 'reviewer-2'])('rejects %s natural source grant binding expiry with held view-now', async party => {
    const f = await fixture(); await f.withNamespace(async () => {
      const userId = party === 'executor' ? f.actor : f.reviewers[Number(party.at(-1))];
      f.bindingFor(userId).expires_at = new Date(f.control.dbNow + 1000).toISOString(); const token = await f.open();
      f.control.dbNow += 1001;
      expect(f.rawView(userId).some((g: any) => g.cluster_id === f.sourceCid && g.module === 'secrets')).toBe(true);
      await expect(f.close(token)).rejects.toBeDefined(); expect(() => f.assertLive(token)).toThrow(); f.release(token);
    });
  }, 30_000);

  it.each(['source-endpoint', 'source-secret', 'source-revision', 'source-workspace', 'source-disabled', 'target-endpoint', 'target-secret'])
  ('rejects %s drift after Native without another Native observation', async cause => {
    const f = await fixture(); await f.withNamespace(async () => {
      const token = await f.open(), source = f.tables.clusters.find((c: any) => c.id === f.sourceCid)!;
      const workspace = f.tables.workspaces.find((w: any) => w.id === f.sourceWid)!;
      if (cause === 'source-endpoint') source.admin_url = 'http://changed-source:8001';
      if (cause === 'source-secret') source.connection_secret = 'changed-source-connection-ciphertext';
      if (cause === 'source-revision') source.revision++;
      if (cause === 'source-workspace') workspace.code = 'changed-source';
      if (cause === 'source-disabled') source.status = 'disabled';
      if (cause === 'target-endpoint') f.cluster.admin_url = 'http://changed-target:8001';
      if (cause === 'target-secret') f.cluster.connection_secret = 'changed-target-connection-ciphertext';
      const before = f.sdk.calls; await expect(f.close(token)).rejects.toBeDefined(); expect(f.sdk.calls).toBe(before); f.release(token);
    });
  }, 30_000);

  it('accepts eligible source and target probe metadata without changing registry identity', async () => {
    const f = await fixture(); await f.withNamespace(async () => {
      const token = await f.open();
      for (const cluster of f.tables.clusters) Object.assign(cluster, { status: 'unhealthy', last_probed_at: new Date().toISOString(), updated_at: new Date().toISOString() });
      f.job.lease_until = new Date(Date.parse(f.job.lease_until) + 1000).toISOString();
      await f.close(token); f.assertLive(token); f.release(token);
    });
  }, 30_000);

  it.each(['import-authority-shortened', 'import-job-shortened', 'import-plan', 'parent-job', 'parent-plan', 'apply-input', 'source-binding'])
  ('rejects changed authenticated %s material during canonical close', async cause => {
    const f = await fixture(); await f.withNamespace(async () => {
      const token = await f.open();
      if (cause === 'import-authority-shortened') f.originalJob.authority_expires_at = new Date(Date.parse(f.draft.spec.windowEnd) - 1).toISOString();
      if (cause === 'import-job-shortened') f.originalJob.expires_at = new Date(Date.parse(f.draft.spec.windowEnd) - 1).toISOString();
      if (cause === 'import-plan') f.parentVersion.expires_at = new Date(Date.parse(f.parentVersion.expires_at) + 1000).toISOString();
      if (cause === 'parent-job') f.row.configuration_job_id = f.job.id;
      if (cause === 'parent-plan') f.row.plan_id = f.job.plan_id;
      if (cause === 'apply-input') { f.applyInput.planId = f.job.plan_id; f.bindInput(); }
      if (cause === 'source-binding') f.tables.configuration_job_origin_bindings.find((b: any) => b.job_id === f.job.id)!.source_workspace_id = f.wid;
      await expect(f.close(token)).rejects.toBeDefined(); expect(() => f.assertLive(token)).toThrow(); f.release(token);
    });
  }, 30_000);

  it('retains DB-relative original material expiry through the final return continuation', async () => {
    const f = await fixture();
    for (const binding of f.bindings.values()) binding.expires_at = new Date(f.control.dbNow + 300_000).toISOString();
    await f.withOrigin(async (job: any, execution: any) => {
      f.observedRoot.assertClosedCheckpoint.mockImplementationOnce(async (...args: any[]) => {
        await f.root.assertClosedCheckpoint(...args);
        monotonic += Date.parse(f.originalJob.authority_expires_at) - f.control.dbNow + 1;
      });
      let published = false;
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db).then((pair: any) => { published = true; return pair; })).rejects.toBeDefined();
      expect(published).toBe(false);
    });
  }, 30_000);

  it('does not replace actual source raw fingerprint/membership checks with the SQL witness', async () => {
    const f = await fixture(); await f.withOrigin(async (job: any, execution: any) => {
      f.sourceRaw.host = 'changed-after-seal';
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'before-send', f.db)).rejects.toBeDefined();
    }); expect(f.db.exec).not.toHaveBeenCalled();
  }, 30_000);

  it.each(['executor', 'reviewer-0', 'reviewer-1', 'reviewer-2'])('still requires actual %s source READ before the SQL comparison can close', async party => {
    const f = await fixture(); await f.withOrigin(async (job: any, execution: any) => {
      const userId = party === 'executor' ? f.actor : f.reviewers[Number(party.at(-1))];
      // Change before opening: equal SQL observations alone must not turn
      // the now-unreadable raw source into authorized material.
      const grant = f.tables.iam_effective_grants.find((g: any) => g.user_id === userId && g.cluster_id === f.sourceCid && g.module === 'services' && g.action === 'read')!;
      grant.scope_type = 'entity'; grant.scope_values = [{ entity_type: 'services', entity_id: randomUUID() }];
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'packet', f.db)).rejects.toBeDefined();
    });
  }, 30_000);

  it.each(['membership', 'EOF'])('retains actual source %s rejection', async cause => {
    const f = await fixture(); await f.withOrigin(async (job: any, execution: any) => {
      if (cause === 'membership') f.state.sourceExtra = [{ id: randomUUID(), name: 'new-source-member', host: 'echo', tags: ['kos-ws-default'] }];
      else f.state.omitSourceEof = true;
      await expect(f.origin.verifyOriginalExecutionAndJob(job, execution, 'before-send', f.db)).rejects.toBeDefined();
    });
  }, 30_000);

  it('requires the fixed Promote evidence backend and complete returned evidence', async () => {
    const f = await fixture(); await f.withNamespace(async () => {
      const original = (f.authority as any).configurationOriginPromoteSql;
      (f.authority as any).configurationOriginPromoteSql = undefined;
      await expect(f.open()).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_SQL_UNAVAILABLE' } });
      (f.authority as any).configurationOriginPromoteSql = original;
      vi.spyOn(f.compiler, 'promoteClosedSqlMaterial').mockResolvedValueOnce(undefined as any);
      await expect(f.open()).rejects.toMatchObject({ response: { code: 'WORKFLOW_SCHEDULE_CONFIGURATION_PROMOTE_SQL_MATERIAL_REQUIRED' } });
    });
  }, 30_000);

  it('refuses copied private handles and mixed original transaction/checkpoint/proof/token references', async () => {
    const f = await fixture(); await f.withOrigin(async (job: any, execution: any) => {
      await expect(f.origin.verifyOriginalExecutionAndJob({ ...job }, execution, 'packet', f.db)).rejects.toBeDefined();
      await expect(f.origin.verifyOriginalExecutionAndJob(job, { ...execution }, 'packet', f.db)).rejects.toBeDefined();
      for (const reason of ['token', 'tx', 'phase', 'proof']) {
        const token = await f.open(), { handle, proof } = f.current();
        await expect(f.root.assertClosedCheckpoint(reason === 'token' ? { ...token } : token, handle,
          reason === 'proof' ? { ...proof } : proof, reason === 'phase' ? 'step' : 'packet', reason === 'tx' ? { ...f.db } : f.db)).rejects.toBeDefined();
        f.release(token); await expect(f.close(token)).rejects.toBeDefined();
      }
    });
  }, 30_000);
});
