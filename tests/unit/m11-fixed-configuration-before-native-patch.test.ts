import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { NativeKongPolicyService } from '../../apps/console-api/src/modules/authorization/native-kong-policy.service';
import { DEFAULT_WORKSPACE_ID, workspaceTestResolver } from './workspace-test-helper';

beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
const denied = (code: string) => ({ response: { code } });

/** Component boundary: actual NativePolicy, SecretService, Context actor/
 * operation ALS and WorkspaceResolver. SQL/grants and the fixed observation
 * bridge are controlled adapters. This suite checks Native PATCH invariants;
 * it does not prove a genuine scheduled Approved capability, Root full-scope
 * read, claim, Native send, timer or runtime SQL. The independent capability
 * suite covers actual Approved mint/cleanup without seeding private registries. */
function fixture() {
  const context = new KongExecutionContextService(), secrets = new SecretService();
  const cid = randomUUID(), nativeId = randomUUID(), operationId = randomUUID(), actor = { id: randomUUID(), username: 'component-executor', superAdmin: true };
  const before: any = { id: nativeId, name: 'service', host: '127.0.0.1', retries: 5, tags: [] };
  const body: any = { retries: 4 }, cluster: any = { id: cid, admin_url: 'http://kong:8001', version: '1.5.1', execution_mode: 'direct' };
  const operation: any = { id: operationId, cluster_id: cid, actor_id: actor.id, workspace_id: DEFAULT_WORKSPACE_ID,
    state: 'running', remote_started: true, remote_completed: false, entity_type: 'services', entity_id: nativeId, action: 'update' };
  const db: any = { one: vi.fn(async (sql: string, params: any[]) => sql.includes('mutation_operations') && params[0] === operation.id ? operation : null), exec: vi.fn() };
  const authz: any = { snapshot: vi.fn(async () => ({ user: actor, grants: [], version: 'current-component-epoch' })),
    permissionVersion: vi.fn(async () => 'current-component-epoch'), assertEntity: vi.fn(async () => undefined),
    assertNestedParentScope: vi.fn(), assertCluster: vi.fn(), filterEntities: vi.fn() };
  const kong: any = { request: vi.fn(async () => { throw new NotFoundException(); }) };
  const workspaces = workspaceTestResolver(cid), policy = new NativeKongPolicyService(db, secrets, kong, context, authz, workspaces.resolver);
  policy.install();
  const bridge = vi.spyOn(context, 'readScheduledConfigurationNativeBefore').mockImplementation(async () => ({ before }));
  const seal = () => { operation.before_secret = secrets.encrypt(before, `mutation:${operationId}:before`); operation.payload_secret = secrets.encrypt(body, `mutation:${operationId}:payload`); };
  seal();
  const run = () => context.runHttp({}, () => {
    context.bindHttpActor(actor, randomUUID()); const close = context.captureHttpCloser();
    return context.runActor({ actor, clusterId: cid, workspaceId: DEFAULT_WORKSPACE_ID, module: 'services', action: 'write' },
      () => context.runOperation({ actor, clusterId: cid, workspaceId: DEFAULT_WORKSPACE_ID, operationId, entityType: 'services', entityId: nativeId, action: operation.action },
        () => context.authorizeRequest(cluster, 'PATCH', `/services/${nativeId}`, body, {}))).finally(close);
  });
  return { context, secrets, cid, nativeId, operationId, actor, before, body, cluster, operation, db, authz, kong, workspaces, policy, bridge, seal, run };
}

describe('fixed currentBefore observation retains independent Native PATCH policy', () => {
  it('consumes the exact bridge observation while keeping both workspace and write checks', async () => {
    const f = fixture(), membership = vi.spyOn(f.workspaces.resolver, 'assertMembership');
    await expect(f.run()).resolves.toBeDefined();
    expect(f.bridge).toHaveBeenCalledOnce(); expect(f.kong.request).not.toHaveBeenCalled();
    const [frame, cluster, method, path, body, query] = f.bridge.mock.calls[0];
    expect(frame.operation?.operationId).toBe(f.operationId); expect(cluster).toBe(f.cluster);
    expect([method, path, body, query]).toEqual(['PATCH', `/services/${f.nativeId}`, f.body, {}]);
    expect(membership).toHaveBeenCalledTimes(2);
    expect(f.authz.assertEntity).toHaveBeenNthCalledWith(1, f.actor, f.cid, 'services', 'write', f.before, DEFAULT_WORKSPACE_ID);
    expect(f.authz.assertEntity).toHaveBeenNthCalledWith(2, f.actor, f.cid, 'services', 'write', { ...f.before, ...f.body }, DEFAULT_WORKSPACE_ID);
  });

  it.each(['identifier', 'before-hmac', 'sealed-payload'] as const)('rejects %s mismatches despite a successful observation bridge', async reason => {
    const f = fixture();
    if (reason === 'identifier') f.before.id = randomUUID();
    if (reason === 'before-hmac') f.before.retries = 6;
    if (reason === 'sealed-payload') f.body.retries = 3;
    await expect(f.run()).rejects.toMatchObject(denied(reason === 'identifier' ? 'KONG_OPERATION_ID_MISMATCH'
      : reason === 'before-hmac' ? 'KONG_OPERATION_STATE_CHANGED' : 'KONG_OPERATION_PAYLOAD_MISMATCH'));
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.authz.assertEntity).not.toHaveBeenCalled();
  });

  it.each(['current', 'proposed'] as const)('keeps actual %s workspace membership checks even for super-admin', async reason => {
    const f = fixture();
    if (reason === 'current') f.before.tags = ['kos-ws-pay']; else f.body.tags = ['kos-ws-pay'];
    f.seal();
    await expect(f.run()).rejects.toMatchObject(denied('WORKSPACE_ENTITY_MISMATCH'));
    expect(f.bridge).toHaveBeenCalledOnce(); expect(f.kong.request).not.toHaveBeenCalled();
  });

  it.each([1, 2])('retains independent write authorization check %s after the observation', async which => {
    const f = fixture();
    if (which === 2) f.authz.assertEntity.mockResolvedValueOnce(undefined);
    f.authz.assertEntity.mockRejectedValueOnce(new ForbiddenException({ code: 'SOURCE_WRITE_REVOKED' }));
    await expect(f.run()).rejects.toMatchObject(denied('SOURCE_WRITE_REVOKED'));
    expect(f.authz.assertEntity).toHaveBeenCalledTimes(which); expect(f.kong.request).not.toHaveBeenCalled();
  });

  it('still reads and authorizes a proposed certificate reference after the fixed observation', async () => {
    const f = fixture(), certificateId = randomUUID(); f.body.client_certificate = { id: certificateId }; f.seal();
    const certificate = { id: certificateId, cert: 'component-certificate', tags: [] };
    f.kong.request.mockResolvedValueOnce(certificate);
    // The fixed observation owns the same-round reference GET. NativePolicy
    // consumes that current row and must not issue a legacy fallback read.
    f.bridge.mockImplementationOnce(async()=>({before:f.before,serviceReferences:[{entityType:'certificates',
      entity:await f.kong.request(f.cid,'GET',`/certificates/${certificateId}`)}]}));
    await expect(f.run()).resolves.toBeDefined();
    expect(f.kong.request).toHaveBeenCalledExactlyOnceWith(f.cid, 'GET', `/certificates/${certificateId}`);
    expect(f.authz.assertEntity).toHaveBeenLastCalledWith(f.actor, f.cid, 'certificates', 'read', certificate, DEFAULT_WORKSPACE_ID);
  });

  it('rejects a cross-workspace proposed reference and never treats the observation as a send permit', async () => {
    const f = fixture(), certificateId = randomUUID(); f.body.client_certificate = { id: certificateId }; f.seal();
    f.kong.request.mockResolvedValueOnce({ id: certificateId, tags: ['kos-ws-pay'] });
    f.bridge.mockImplementationOnce(async()=>({before:f.before,serviceReferences:[{entityType:'certificates',
      entity:await f.kong.request(f.cid,'GET',`/certificates/${certificateId}`)}]}));
    await expect(f.run()).rejects.toMatchObject(denied('WORKSPACE_ENTITY_MISMATCH'));
    expect(f.authz.assertEntity).toHaveBeenCalledTimes(2); expect(f.db.exec).not.toHaveBeenCalled();
  });

  it.each(['missing','wrong-id','wrong-type']as const)('rejects a %s same-round TLS reference without fallback GET',async reason=>{
    const f=fixture(),certificateId=randomUUID();f.body.client_certificate={id:certificateId};f.seal();
    const reference:any={entityType:reason==='wrong-type'?'ca_certificates':'certificates',entity:{id:reason==='wrong-id'?randomUUID():certificateId,tags:[]}};
    f.bridge.mockResolvedValueOnce({before:f.before,serviceReferences:reason==='missing'?[]:[reference]});
    await expect(f.run()).rejects.toMatchObject(denied('CONFIGURATION_SERVICE_TLS_REFERENCE_REQUIRED'));
    expect(f.kong.request).not.toHaveBeenCalled();expect(f.authz.assertEntity).toHaveBeenCalledTimes(2);expect(f.db.exec).not.toHaveBeenCalled();
  });

  it('propagates a failed fixed observation without issuing a fallback GET', async () => {
    const f = fixture(); f.bridge.mockRejectedValueOnce(new ForbiddenException({ code: 'SOURCE_FIXED_READ_FAILED' }));
    await expect(f.run()).rejects.toMatchObject(denied('SOURCE_FIXED_READ_FAILED'));
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.authz.assertEntity).not.toHaveBeenCalled();
  });

  it('retains the original fresh GET path when the bridge explicitly does not apply', async () => {
    const f = fixture(); f.bridge.mockResolvedValueOnce(null); f.kong.request.mockResolvedValueOnce(f.before);
    await expect(f.run()).resolves.toBeDefined();
    expect(f.kong.request).toHaveBeenCalledExactlyOnceWith(f.cid, 'GET', `/services/${f.nativeId}`);
    expect(f.authz.assertEntity).toHaveBeenCalledTimes(2);
  });
});
