import { describe, expect, it, vi } from 'vitest';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';

const actor = { id: 'validated-user', username: 'user', superAdmin: false };
const cid = 'cluster';
const trustedKey = 'trusted-request-key';
const cluster = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct' };

describe('trusted HTTP idempotency correlation', () => {
  it('copies the trusted primitive once and inherits it through actor, internal, operation and archive frames', async () => {
    const contexts = new KongExecutionContextService();
    const options = { requestId: 'request', ip: '192.0.2.10', idempotencyKey: trustedKey };
    await contexts.runHttp(options, async () => {
      contexts.bindHttpActor(actor, 'validated-session');
      const close = contexts.captureHttpCloser();
      try {
        options.idempotencyKey = 'changed-options';
        await contexts.runActor({ actor, clusterId: cid, workspaceId: 'workspace', module: 'services', action: 'write' }, async () => {
          expect(contexts.peek()?.idempotencyKey).toBe(trustedKey);
          await contexts.runInternalRead(cid, 'entity-preflight', async () => {
            expect(contexts.peek()?.idempotencyKey).toBe(trustedKey);
            expect(contexts.peek()?.ip).toBe('192.0.2.10');
          }, { paths: ['/services'] });
          await contexts.runOperation({ actor, clusterId: cid, workspaceId: 'workspace', entityType: 'services', action: 'delete', operationId: 'durable-operation' }, async () => {
            expect(contexts.peek()?.idempotencyKey).toBe(trustedKey);
            await contexts.runArchiveDelete({ clusterId: cid, workspaceId: 'workspace', operationId: 'durable-operation', entryId: 'archive', nodes: [{ path: '/services/entity', type: 'services', id: 'entity' }] }, async () => {
              expect(contexts.peek()?.idempotencyKey).toBe(trustedKey);
              expect(() => Object.defineProperty(contexts.current(), 'idempotencyKey', { value: 'forged' })).toThrow();
            });
          });
        });
      } finally { close(); }
    });
  });
  it('does not accept correlation overrides from actor or operation options', async () => {
    const contexts = new KongExecutionContextService();
    await contexts.runHttp({ idempotencyKey: trustedKey }, async () => {
      contexts.bindHttpActor(actor); const close = contexts.captureHttpCloser();
      try {
        await contexts.runActor({ actor, clusterId: cid, idempotencyKey: 'untrusted-actor' } as any, async () => {
          await contexts.runOperation({ actor, clusterId: cid, entityType: 'services', operationId: 'operation', idempotencyKey: 'untrusted-operation' } as any, async () => {
            expect(contexts.peek()?.idempotencyKey).toBe(trustedKey);
          });
        });
      } finally { close(); }
    });
  });
  it('does not grant a native write capability merely because a trusted key is present', async () => {
    const contexts = new KongExecutionContextService();
    const authorizeRequest = vi.fn(async () => ({ platformAdmin: true }));
    contexts.installPolicy({ authorizeRequest, authorizeResponse: async (_ticket, result) => result });
    await contexts.runHttp({ idempotencyKey: trustedKey }, async () => {
      contexts.bindHttpActor(actor); const close = contexts.captureHttpCloser();
      try {
        await contexts.runActor({ actor, clusterId: cid }, async () => {
          await expect(contexts.authorizeRequest(cluster, 'PATCH', '/services/entity', { idempotencyKey: trustedKey }, {})).rejects.toMatchObject({ response: { code: 'KONG_NATIVE_OPERATION_REQUIRED' } });
        });
      } finally { close(); }
    });
    expect(authorizeRequest).not.toHaveBeenCalled();
  });
});
