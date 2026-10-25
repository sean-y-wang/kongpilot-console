import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { RequestMethod } from '@nestjs/common';
import { RecycleController } from '../../apps/console-api/src/modules/recycle-bin/recycle.controller';
import { EntitiesController } from '../../apps/console-api/src/modules/entities/entities.controller';
import { finishM6LifecycleTail } from './live-m6.mjs';
import {
  retiredLifecycleCheckpoint, guardRetiredLifecycleContinuation, beginRetiredLifecycleTail,
  proveRetiredParentRestore404, proveManagedConsumerIdentityDenied, RETIRED_KEY_ARCHIVE,
} from './lib/m6-retired-lifecycle-continuation.mjs';
import { retiredLifecycleReviewFixture, sha } from './m6-retired-lifecycle-review-fixture';
const apiRequire = createRequire(new URL('../../apps/console-api/package.json', import.meta.url));
const { PATH_METADATA, METHOD_METADATA } = apiRequire('@nestjs/common/constants');

function identityAttempt(f: ReturnType<typeof retiredLifecycleReviewFixture>) {
  const state: any = retiredLifecycleCheckpoint(f.r, f.evidence), key = randomUUID();
  const attempt = {
    path: `/api/v1/clusters/${state.primary.cluster.id}/entities/consumers`, method: 'POST', key,
    actorId: state.admin.user.id, state: 'response_observed', httpStatus: 403, requestId: randomUUID(),
    query: `?workspaceId=${state.primary.workspace.id}`, body: { id: state.a.managed.consumer_id },
  };
  f.h.referenceData.writeAttempts.push(attempt);
  const read = f.h.request.getMockImplementation()!;
  f.h.request.mockImplementation(async (...args: any[]) => args[1].includes(`/mutations/by-key/${key}`)
    ? { status: 200, payload: { data: { state: 'failed', remote_completed: false, error_code: 'PORTAL_MANAGED_OBJECT' } } }
    : read(...args));
  return { state, attempt, response: { status: 403, payload: { error: { code: 'PORTAL_MANAGED_OBJECT' } } } };
}

describe('independent retired lifecycle continuation: only unfinished intents', () => {
  it('binds the denial to actual Nest restore and Consumer create routes', () => {
    expect(Reflect.getMetadata(PATH_METADATA, RecycleController)).toBe('clusters/:clusterId/recycle-bin');
    expect(Reflect.getMetadata(PATH_METADATA, RecycleController.prototype.restore)).toBe(':id/restore');
    expect(Reflect.getMetadata(METHOD_METADATA, RecycleController.prototype.restore)).toBe(RequestMethod.POST);
    expect(Reflect.getMetadata(PATH_METADATA, EntitiesController)).toBe('clusters/:clusterId');
    const create = Object.getOwnPropertyNames(EntitiesController.prototype).map(key => (EntitiesController.prototype as any)[key])
      .find(fn => Reflect.getMetadata(PATH_METADATA, fn) === 'entities/:entityType' && Reflect.getMetadata(METHOD_METADATA, fn) === RequestMethod.POST);
    expect(create).toBeTypeOf('function');
  });

  it('uses fresh GET/SELECT facts, preserves all old attempts, and creates a separate once-only tail journal', async () => {
    const f = retiredLifecycleReviewFixture(), old = sha(f.r.writeAttempts), proof = sha(f.evidence);
    const state = await guardRetiredLifecycleContinuation(f.h, f.evidence);
    expect(sha(f.h.referenceData.writeAttempts)).toBe(old);
    expect(sha(f.evidence)).toBe(proof);
    expect(f.h.request.mock.calls.every((c: any) => (c[2] ?? 'GET') === 'GET')).toBe(true);
    expect(f.h.portal.mock.calls.every((c: any) => (c[2] ?? 'GET') === 'GET')).toBe(true);
    expect(f.h.consoleRead.mock.calls.every((c: any) => c[0].startsWith('SELECT'))).toBe(true);
    beginRetiredLifecycleTail(f.h, state);
    expect(f.h.referenceData.retiredLifecycleContinuation.phase).toBe('tail-actions-started');
    expect(() => beginRetiredLifecycleTail(f.h, state)).toThrow();
    expect(() => retiredLifecycleCheckpoint(f.h.referenceData, f.evidence)).toThrow();
  });

  for (const [label, change] of [
    ['an extra original restore attempt', (f: any) => f.r.writeAttempts.push(structuredClone(f.attempt))],
    ['the original restore key replaced', (f: any) => { f.attempt.key = randomUUID(); }],
    ['an altered 750-check failure', (f: any) => { f.report.failed = 0; }],
    ['a closed certificate represented as another POST', (f: any) => { f.r.abandonmentAcknowledgment.totalFormalPosts = 3; }],
    ['the old issue acknowledgment altered', (f: any) => { f.r.abandonmentAcknowledgment.originalAttempt.httpStatus = 201; }],
    ['an incomplete first metadata recovery', (f: any) => { f.r.metadataRecovery.phase = 'uncertain'; }],
    ['the different-cluster token family replaced', (f: any) => { f.r.tokens[4].generation++; }],
    ['retirement without Consumer deletion', (f: any) => { f.r.writeAttempts.find((a: any) => a.path.endsWith('/revoke')).body.retireConsumer = false; }],
  ] as const) it(`rejects ${label} before any outbound call`, () => {
    const f = retiredLifecycleReviewFixture(); change(f);
    expect(() => retiredLifecycleCheckpoint(f.r, f.evidence)).toThrow();
    expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.portal).not.toHaveBeenCalled();
  });

  for (const [label, mutate] of [
    ['current certificate count changes', (f: any) => { f.closed.certificates = 0; }],
    ['the released unused Key was revealed', (f: any) => { f.closed.last_revealed_at = '2026-10-11T00:00:00Z'; }],
    ['a late native receipt appears on the failed issue', (f: any) => { f.closed.native_operation_count = 2; }],
    ['a late native uncertain operation appears', (f: any) => { f.closed.native_unresolved = 1; }],
    ['the revoked original cipher changes', (f: any) => { f.row.original_key_cipher_sha = '0'.repeat(64); }],
    ['the current Key archive entered restoring', (f: any) => { f.bin.entry.state = 'restoring'; }],
    ['an archive node was actually restored', (f: any) => { f.bin.nodes[0].restored_id = randomUUID(); }],
    ['a stale retirement now has active credentials', (f: any) => { f.row.active_credential_refs = 1; }],
  ] as const) it(`halts read-only validation when ${label}`, async () => {
    const f = retiredLifecycleReviewFixture(); mutate(f);
    await expect(guardRetiredLifecycleContinuation(f.h, f.evidence)).rejects.toThrow();
    expect(f.h.referenceData.retiredLifecycleContinuation).toBeUndefined();
    expect(f.h.request.mock.calls.every((c: any) => (c[2] ?? 'GET') === 'GET')).toBe(true);
    expect(f.h.portal.mock.calls.every((c: any) => (c[2] ?? 'GET') === 'GET')).toBe(true);
  });

  it('does not accept a current wrong actor or wrong Portal tenant despite unchanged private fixtures', async () => {
    const f = retiredLifecycleReviewFixture(), read = f.h.portal.getMockImplementation()!;
    f.h.portal.mockImplementation(async (...args: any[]) => args[1].includes('/auth/me')
      ? { status: 200, payload: { data: { ...args[0].developer, clusterId: randomUUID() } } } : read(...args));
    await expect(guardRetiredLifecycleContinuation(f.h, f.evidence)).rejects.toThrow();
    expect(f.h.referenceData.retiredLifecycleContinuation).toBeUndefined();
  });

  it('fails current Consumer error provenance rather than counting any 404 as a missing native parent', async () => {
    const f = retiredLifecycleReviewFixture(), state = retiredLifecycleCheckpoint(f.r, f.evidence), read = f.h.request.getMockImplementation()!;
    f.h.request.mockImplementation(async (...args: any[]) => args[1].includes(`/entities/consumers/${state.a.managed.consumer_id}`)
      ? { status: 404, payload: { error: { code: 'NOT_FOUND' } } } : read(...args));
    await expect(proveRetiredParentRestore404(f.h, state, { status: 404, payload: { error: { code: 'KONG_VALIDATION_ERROR' } } }, RETIRED_KEY_ARCHIVE, f.attempt)).rejects.toThrow();
  });

  it('rejects an off-scope or stale application and never reveals old Keys to rebuild state', async () => {
    const f = retiredLifecycleReviewFixture(), read = f.h.portal.getMockImplementation()!;
    f.h.portal.mockImplementation(async (...args: any[]) => {
      const result = await read(...args);
      if (new URL(args[1], 'http://synthetic.invalid').pathname === `/applications/${f.a.app.id}`) result.payload.data.entity.revision++;
      return result;
    });
    await expect(guardRetiredLifecycleContinuation(f.h, f.evidence)).rejects.toThrow();
    expect(f.h.portal.mock.calls.every((c: any) => !c[1].includes('/reveal') && (c[2] ?? 'GET') === 'GET')).toBe(true);
  });

  it('checks both currently active dual-cluster Keys independently before admitting tail actions', async () => {
    const f = retiredLifecycleReviewFixture(), proxy = f.h.proxy.getMockImplementation()!;
    f.h.proxy.mockImplementation(async (...args: any[]) => args[4].apikey === f.c.apiKey ? 401 : proxy(...args));
    await expect(guardRetiredLifecycleContinuation(f.h, f.evidence)).rejects.toThrow();
    expect(f.h.referenceData.retiredLifecycleContinuation).toBeUndefined();
  });

  it('proves the ordinary managed-UUID create rejection using its own original mutation receipt', async () => {
    const f = retiredLifecycleReviewFixture(), { state, response } = identityAttempt(f);
    await proveManagedConsumerIdentityDenied(f.h, state, response);
    expect(f.h.request.mock.calls.every((c: any) => (c[2] ?? 'GET') === 'GET')).toBe(true);
    expect(f.h.portal).not.toHaveBeenCalled();
  });

  it('does not reinterpret the whole-Consumer restore 503 wrapper as the required ordinary-create ownership denial', async () => {
    const f = retiredLifecycleReviewFixture(), { state } = identityAttempt(f);
    await expect(proveManagedConsumerIdentityDenied(f.h, state, {
      status: 503, payload: { error: { code: 'RECYCLE_RESTORE_INCOMPLETE', details: { cause: 'PORTAL_MANAGED_OBJECT' } } },
    })).rejects.toThrow();
    expect(f.h.request).not.toHaveBeenCalled();
    expect(f.h.consoleRead).not.toHaveBeenCalled();
  });

  it('requires native error provenance for a missing current managed UUID after the create refusal', async () => {
    const f = retiredLifecycleReviewFixture(), { state, response } = identityAttempt(f), read = f.h.request.getMockImplementation()!;
    f.h.request.mockImplementation(async (...args: any[]) => args[1].includes(`/entities/consumers/${state.a.managed.consumer_id}`)
      ? { status: 404, payload: { error: { code: 'NOT_FOUND' } } } : read(...args));
    await expect(proveManagedConsumerIdentityDenied(f.h, state, response)).rejects.toThrow();
  });

  it('rejects a foreign console actor before any tenant topology reads or tail journal', async () => {
    const f = retiredLifecycleReviewFixture(), read = f.h.request.getMockImplementation()!;
    f.h.request.mockImplementation(async (...args: any[]) => args[1] === '/auth/me'
      ? { status: 200, payload: { data: { id: randomUUID() } } } : read(...args));
    await expect(guardRetiredLifecycleContinuation(f.h, f.evidence)).rejects.toThrow();
    expect(f.h.portal).not.toHaveBeenCalled(); expect(f.h.consoleRead).not.toHaveBeenCalled();
    expect(f.h.referenceData.retiredLifecycleContinuation).toBeUndefined();
  });

  for (const [label, mutate] of [
    ['uncertain state', (f: any) => { f.identity.state = 'uncertain'; }],
    ['a completed native result', (f: any) => { f.identity.remote_completed = true; }],
    ['a returned raw result', (f: any) => { f.identity.has_result = true; }],
    ['an unrelated native type', (f: any) => { f.identity.entity_type = 'plugins'; }],
    ['an unrelated denial code', (f: any) => { f.identity.error_code = 'KONG_VALIDATION_ERROR'; }],
  ] as const) it(`never treats Consumer create ${label} as the managed ownership proof`, async () => {
    const f = retiredLifecycleReviewFixture(), { state, response } = identityAttempt(f); mutate(f);
    await expect(proveManagedConsumerIdentityDenied(f.h, state, response)).rejects.toThrow();
  });

  it('the actual extracted lifecycle tail stops after one unknown new identity POST without calling old issue/rotation/revoke/closure paths', async () => {
    const f = retiredLifecycleReviewFixture(), state = await guardRetiredLifecycleContinuation(f.h, f.evidence);
    beginRetiredLifecycleTail(f.h, state);
    const read = f.h.request.getMockImplementation()!, oldAttempts = sha(f.attempt);
    f.h.request.mockImplementation(async (...args: any[]) => {
      if (args[2] === 'POST') {
        expect(args[1]).toContain('/entities/consumers?'); expect(args[3].id).toBe(state.a.managed.consumer_id);
        throw Error('SYNTHETIC_RESPONSE_LOSS');
      }
      return read(...args);
    });
    await expect(finishM6LifecycleTail(f.h, state, { a: state.a, b: state.b, c: state.c, rotated: state.rotated, newKey: state.newKey })).rejects.toThrow('SYNTHETIC_RESPONSE_LOSS');
    expect(f.h.request.mock.calls.filter((c: any) => c[2] === 'POST')).toHaveLength(1);
    expect(f.h.portal.mock.calls.some((c: any) => c[2] === 'POST')).toBe(false);
    expect(f.h.referenceData.retiredLifecycleContinuation.phase).toBe('tail-actions-started');
    expect(() => retiredLifecycleCheckpoint(f.h.referenceData, f.evidence)).toThrow();
    expect(sha(f.attempt)).toBe(oldAttempts);
  });

  it('the actual extracted tail reaches only a new reissue request after known Consumer denial, never restarting the completed credential flow', async () => {
    const f = retiredLifecycleReviewFixture(), state = await guardRetiredLifecycleContinuation(f.h, f.evidence);
    beginRetiredLifecycleTail(f.h, state);
    const read = f.h.request.getMockImplementation()!;
    f.h.request.mockImplementation(async (...args: any[]) => {
      if (args[2] === 'POST') {
        const key = randomUUID(); f.h.referenceData.writeAttempts.push({ path: `/api/v1/clusters/${state.primary.cluster.id}/entities/consumers`, method: 'POST', key, actorId: state.admin.user.id, state: 'response_observed', httpStatus: 403, body: args[3], requestId: randomUUID(), query: `?workspaceId=${state.primary.workspace.id}` });
        return { status: 403, payload: { error: { code: 'PORTAL_MANAGED_OBJECT' } } };
      }
      if (args[1].includes('/mutations/by-key/') && !args[1].endsWith(`${f.attempt.key}?workspaceId=${state.primary.workspace.id}`)) return { status: 200, payload: { data: { state: 'failed', remote_completed: false } } };
      return read(...args);
    });
    const portalRead = f.h.portal.getMockImplementation()!;
    f.h.portal.mockImplementation(async (...args: any[]) => {
      if (args[2] === 'POST') {
        expect(args[1]).toBe('/requests'); expect(args[3].applicationId).toBe(state.app.id); expect(args[3].publicationId).toBe(state.primary.publications[0].id);
        throw Error('STOP_BEFORE_NEW_REISSUE');
      }
      return portalRead(...args);
    });
    await expect(finishM6LifecycleTail(f.h, state, { a: state.a, b: state.b, c: state.c, rotated: state.rotated, newKey: state.newKey })).rejects.toThrow('STOP_BEFORE_NEW_REISSUE');
    expect(f.h.request.mock.calls.filter((c: any) => c[2] === 'POST')).toHaveLength(1);
    expect(f.h.portal.mock.calls.filter((c: any) => c[2] === 'POST')).toHaveLength(1);
    expect(f.h.request.mock.calls.some((c: any) => c[2] === 'POST' && /restore|execute|approve|abandon|reconcile/.test(c[1]))).toBe(false);
    expect(f.h.portal.mock.calls.some((c: any) => c[2] === 'POST' && /rotate|revoke|reveal/.test(c[1]))).toBe(false);
    expect(f.h.public.historicalConsumerProtection.wholeConsumerRecycleRestoreExecuted).toBe(false);
  });
});
