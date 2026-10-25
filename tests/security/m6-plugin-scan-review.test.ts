import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { assertKongPath } from '../../apps/console-api/src/infrastructure/kong/policy';
import { PortalNativeService } from '../../apps/console-api/src/modules/portal/portal-native.service';
import { WorkflowService } from '../../apps/console-api/src/modules/workflows/workflow.service';
import { WorkflowRegistryService } from '../../apps/console-api/src/modules/workflows/workflow-registry.service';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'c7'.repeat(32)));
afterEach(() => vi.unstubAllEnvs());

// Actual bounded reader and snapshot compiler. Transport is an explicit fixture;
// no test substitutes a claimed successful graph for the production scan.
function fixture() {
  const cid = randomUUID(), wid = randomUUID(), consumer = randomUUID(), otherConsumer = randomUUID();
  const secrets = new SecretService(), actor: any = { user: { id: randomUUID(), superAdmin: false }, workspaceId: wid };
  const context: any = { runActor: vi.fn(async (_scope: any, fn: any) => fn()), runInternalRead: vi.fn(async (_cid: string, _purpose: string, fn: any) => fn()) };
  let scan: (path: string, query: any) => any = () => ({ data: [], next: null });
  const objects = new Map<string, any>();
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string, body: any, query: any) => {
    assertKongPath(method as any, path); expect(method).toBe('GET'); expect(body).toBeUndefined();
    return objects.has(path) ? objects.get(path) : scan(path, query);
  }) };
  const native = new PortalNativeService({} as any, secrets, kong, context, {} as any, {} as any);
  const entities: any = { delete: vi.fn(), deleteCredential: vi.fn(), create: vi.fn() };
  const engine = new WorkflowService({} as any, {} as any, secrets, kong, context, {} as any, {} as any, entities, {} as any,
    {} as any, {} as any, {} as any, new WorkflowRegistryService(), {} as any);
  const keyId = randomUUID(), aclId = randomUUID(), keyBefore = { id: keyId, key: 'synthetic-review-key', consumer: { id: consumer } };
  const aclBefore = { id: aclId, group: 'review-group', consumer: { id: consumer } };
  const keyStep = native.nativeStep(1, 'credentials', 'delete', { confirmed: true, confirm_name: keyId }, keyBefore,
    { id: keyId, parentId: consumer, credentialKind: 'key-auth', workflowId: randomUUID() });
  const aclStep = native.nativeStep(2, 'credentials', 'delete', { confirmed: true, confirm_name: aclId }, aclBefore,
    { id: aclId, parentId: consumer, credentialKind: 'acls', workflowId: randomUUID() });
  const terminal = native.metadataStep(3, 'portal.credential.revoke', 'portal_application_grants', randomUUID(), { revision: 1 },
    { retireConsumer: true, consumerId: consumer }, []);
  const plan: any = { version: 1, clusterId: cid, workspaceId: wid, workflowId: randomUUID(), planRevision: 1, steps: [keyStep, aclStep, terminal], prerequisites: [] };
  objects.set(keyStep.nativeRequests[0].canonicalPath, keyBefore); objects.set(aclStep.nativeRequests[0].canonicalPath, aclBefore);
  return { cid, wid, consumer, otherConsumer, actor, context, kong, native, engine, entities, plan, keyId, aclId, secrets,
    setScan: (fn: typeof scan) => { scan = fn; }, snapshot: () => (engine as any).snapshot(plan, randomUUID(), actor) };
}

describe('M6 independent global plugin scans and typed retirement closure', () => {
  it('keeps the reader on the authorized global path and fixed page size through the final page', async () => {
    const f = fixture(), first = { id: randomUUID(), consumer: { id: f.otherConsumer } }, last = { id: randomUUID(), service: { id: randomUUID() } };
    f.setScan((_path, query) => query.offset ? { data: [last], next: null } : { data: [first], next: '/plugins?size=100&offset=final-page' });
    expect(await f.native.collection(f.cid, '/plugins', f.actor)).toEqual([first, last]);
    expect(f.kong.request.mock.calls.map((call: any[]) => [call[2], call[4]])).toEqual([
      ['/plugins', { size: 100 }], ['/plugins', { size: 100, offset: 'final-page' }],
    ]);
    expect(f.context.runActor.mock.calls[0][0]).toMatchObject({ actor: f.actor.user, clusterId: f.cid, workspaceId: f.wid, module: 'portal', action: 'write' });
    expect(f.context.runInternalRead.mock.calls[0][3]).toMatchObject({ paths: ['/plugins'], maxCalls: 10, maxPages: 10, maxRecords: 1000, maxBytes: 2 * 1024 * 1024 });
  });

  it('returns no incomplete collection when the page budget is exhausted even with an early matching plugin', async () => {
    const f = fixture(); let page = 0;
    f.setScan(() => ({ data: page === 0 ? [{ id: randomUUID(), name: 'acl' }] : [], next: `/plugins?offset=p-${++page}` }));
    await expect(f.native.collection(f.cid, '/plugins', f.actor)).rejects.toMatchObject({ response: { code: 'PORTAL_PREFLIGHT_BUDGET' } });
    expect(f.kong.request).toHaveBeenCalledTimes(10); expect(f.entities.delete).not.toHaveBeenCalled();
  });

  it.each([{ data: null, next: null }, { data: [], next: '/plugins?size=100' }, { data: [], next: 'http://[' }])(
    'fails a malformed page without claiming a complete plugin collection', async page => {
      const f = fixture(); f.setScan(() => page);
      await expect(f.native.collection(f.cid, '/plugins', f.actor)).rejects.toMatchObject({ response: { code: 'PORTAL_NATIVE_RESPONSE_INVALID' } });
      expect(f.kong.request).toHaveBeenCalledOnce();
    });

  it.each(['consumer-only', 'route-consumer', 'service-consumer', 'service-route-consumer'])('detects a late unlisted %s plugin under the retired Consumer', async binding => {
    const f = fixture(), plugin: any = { id: randomUUID(), consumer: { id: f.consumer } };
    if (binding.includes('route')) plugin.route = { id: randomUUID() };
    if (binding.includes('service')) plugin.service = { id: randomUUID() };
    f.setScan((path, query) => path !== '/plugins' ? { data: [], next: null } : query.offset ? { data: [plugin], next: null } :
      { data: [{ id: randomUUID(), consumer: { id: f.otherConsumer } }], next: '/plugins?offset=last' });
    await expect(f.snapshot()).rejects.toMatchObject({ response: { code: 'PORTAL_RETIREMENT_UNLISTED_CHILDREN' } });
    expect(f.kong.request.mock.calls.filter((call: any[]) => call[2] === '/plugins')).toHaveLength(2);
    expect(f.entities.delete).not.toHaveBeenCalled(); expect(f.entities.deleteCredential).not.toHaveBeenCalled();
    expect(f.kong.request.mock.calls.some((call: any[]) => call[2] === `/consumers/${f.consumer}/plugins`)).toBe(false);
  });

  it.each(['keyId', 'aclId'] as const)('rejects a Consumer plugin whose UUID collides with the planned %s credential', async field => {
    const f = fixture(); f.setScan(path => ({ data: path === '/plugins' ? [{ id: f[field], consumer: { id: f.consumer } }] : [], next: null }));
    await expect(f.snapshot()).rejects.toMatchObject({ response: { code: 'PORTAL_RETIREMENT_UNLISTED_CHILDREN' } });
    expect(f.entities.deleteCredential).not.toHaveBeenCalled();
  });

  it.each(['wrong-kind', 'wrong-parent'])('rejects a credential UUID authorized only for a %s deletion', async mismatch => {
    const f = fixture();
    if (mismatch === 'wrong-parent') f.plan.steps[0].parentId = f.otherConsumer;
    f.setScan(path => ({ data: path.endsWith(mismatch === 'wrong-kind' ? '/basic-auth' : '/key-auth') ? [{ id: f.keyId }] : [], next: null }));
    await expect(f.snapshot()).rejects.toMatchObject({ response: { code: 'PORTAL_RETIREMENT_UNLISTED_CHILDREN' } });
  });

  it('accepts only the explicitly planned credential kinds while ignoring plugins bound to other Consumers', async () => {
    const f = fixture(); f.setScan(path => ({ data: path.endsWith('/key-auth') ? [{ id: f.keyId }] : path.endsWith('/acls') ? [{ id: f.aclId }] :
      path === '/plugins' ? [{ id: f.keyId, consumer: { id: f.otherConsumer }, route: { id: randomUUID() }, service: { id: randomUUID() } }] : [], next: null }));
    const snapshot = await f.snapshot(); expect(snapshot.objects).toHaveLength(2);
    expect(snapshot.objects.map((object: any) => object.id)).toEqual([f.keyId, f.aclId]);
    expect(f.kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
  });
});
