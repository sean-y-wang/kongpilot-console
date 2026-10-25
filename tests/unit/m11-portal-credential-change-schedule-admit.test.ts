import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { workflowScheduledFixture } from './helpers/workflow-scheduled-fixture';
import { normalizeWorkflowScheduleDraft, assertWorkflowScheduledPlan } from '../../apps/console-api/src/modules/workflows/workflow-schedule.repository';
import { WorkflowScheduledNamespaceService } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-namespace.service';
import type { WorkflowScheduledContextRunner } from '../../apps/console-api/src/modules/workflows/workflow-scheduled-authority.types';
import { assertPortalCredentialScheduleKindSupported, isPortalCredentialScheduleKind } from '../../apps/console-api/src/modules/portal/portal-credential-lifecycle-contract';
import { WorkflowBusinessMaterialService } from '../../apps/console-api/src/modules/workflows/workflow-business-material.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';

function namespaceFixture(kind: 'portal-credential-rotate' | 'portal-credential-revoke') {
  const f = workflowScheduledFixture(kind);
  const service = new WorkflowScheduledNamespaceService(f.service, f.secrets, f.redis);
  let last: object | null = null;
  const runner: WorkflowScheduledContextRunner = {
    assertNoFrame: vi.fn(() => { if (f.state.frame !== null) throw new ForbiddenException({ code: 'ORIGINAL_EMPTY_ALS_REQUIRED' }); }),
    run: vi.fn(async <T>(handle: object, fn: () => Promise<T>): Promise<T> => {
      runner.assertNoFrame(); last = handle; f.state.frame = { originalNamespaceHandle: handle };
      try { await service.verifyHandle(handle, 'claim'); return await fn(); } finally { f.state.frame = null; }
    }),
  };
  const run = async (callback: () => Promise<any>) => {
    f.executor.executeClaim.mockImplementation(async (authority: object, begin) => {
      await service.runOriginalClaim(authority, async () => { f.beginCallback(begin, last!); return callback(); });
      return f.complete();
    });
    const authority = await f.service.acquireDueClaim(f.scheduleId);
    await f.service.executeClaim(authority!);
    return authority!;
  };
  return { ...f, namespace: service, runner, last: () => last!, run, install: () => { f.install(); service.installContextRunner(runner); } };
}

describe('KP-006 scheduled portal-credential rotate/revoke admit (fail-closed)', () => {
  beforeEach(() => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-13T20:00:00.000Z'));
  });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

  it.each(['portal-credential-rotate', 'portal-credential-revoke'] as const)('seals %s draft with matching driver and developer requester', kind => {
    expect(isPortalCredentialScheduleKind(kind)).toBe(true);
    expect(() => assertPortalCredentialScheduleKindSupported(kind)).not.toThrow();
    const f = workflowScheduledFixture(kind);
    expect(f.draft.binding.requester.type).toBe('developer');
    expect(f.draft.binding.subjectType).toBe('portal_application_grants');
    expect(f.draft.binding.subjectSeal.driver).toBe(kind);
    expect(() => normalizeWorkflowScheduleDraft(f.draft, f.secrets)).not.toThrow();
    expect(() => assertWorkflowScheduledPlan(f.plan, f.draft, f.secrets)).not.toThrow();
  });

  it('rejects rotate draft when driver / requester / subject diverge', () => {
    const f = workflowScheduledFixture('portal-credential-rotate');
    const badDriver = structuredClone(f.draft);
    badDriver.binding.subjectSeal.driver = 'portal-credential-issue';
    expect(() => normalizeWorkflowScheduleDraft(badDriver, f.secrets)).toThrow();
    const badRequester = structuredClone(f.draft);
    badRequester.binding.requester = { type: 'console', id: f.owner, credentialEpoch: '1' };
    badRequester.delegation.requester = badRequester.binding.requester;
    expect(() => normalizeWorkflowScheduleDraft(badRequester, f.secrets)).toThrow();
    const badSubject = structuredClone(f.draft);
    badSubject.binding.subjectType = 'configuration_jobs';
    badSubject.delegation.subjectType = 'configuration_jobs';
    expect(() => normalizeWorkflowScheduleDraft(badSubject, f.secrets)).toThrow();
  });

  it.each(['portal-credential-rotate', 'portal-credential-revoke'] as const)('mints original NULL-SID namespace for %s', async kind => {
    const f = namespaceFixture(kind);
    f.install();
    await f.run(async () => {
      const proof = await f.namespace.verifyHandle(f.last(), 'capture');
      expect(proof.origin).toBe('scheduled-workflow');
      expect(proof.sessionId).toBeNull();
      expect(proof.kind).toBe(kind);
      expect(proof.actor.id).toBe(f.owner);
      expect(proof.requester.type).toBe('developer');
      expect(proof.requester.id).toBe(f.developer);
    });
  });

  it('fail-closes portalChangeMaterial when grant is not rotating/revoking', async () => {
    const secrets = new SecretService();
    const f = workflowScheduledFixture('portal-credential-revoke');
    const meta = f.plan.steps.find((s: any) => s.kind === 'metadata')!.metadata as any;
    const db: any = {
      one: vi.fn(async (sql: string) => {
        if (sql.includes('FROM workflow_versions') || sql.includes('payload_secret') || sql.includes('FROM workflows')) {
          return { id: f.plan.workflowId, plan_hash: f.secrets.fingerprint(f.plan), state: 'approved', payload_secret: null };
        }
        if (sql.includes('FROM portal_application_grants')) {
          return {
            id: f.plan.subject.id, cluster_id: f.cid, workspace_id: f.wid, developer_id: f.developer, workflow_id: f.plan.workflowId,
            state: 'active', transport_scope: f.plan.scope.transportScope, consumer_id: meta.consumerId, acl_id: meta.aclId,
            application_id: f.plan.subject.id, publication_id: f.plan.subject.id, acl_group: 'g', reservation_released_at: null,
            revision: 1, created_at: new Date().toISOString(), current_credential_id: meta.credentialId, current_generation: 1,
          };
        }
        return null;
      }),
      query: vi.fn(async () => []),
      transaction: vi.fn(async (fn: any) => fn(db)),
    };
    const material = new WorkflowBusinessMaterialService(db, secrets);
    await expect(material.portalChangeMaterial(f.plan as any, db)).rejects.toBeInstanceOf(ForbiddenException);
  });
});
