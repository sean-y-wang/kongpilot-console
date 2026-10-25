import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { PortalAuthBoundaryService } from '../../apps/console-api/src/modules/portal-boundary/portal-auth-boundary.service';
import { assertPortalAuthenticationBoundary, effectivePortalPlugin } from '../../apps/console-api/src/modules/portal-boundary/auth-graph';
import { publicationProofAad } from '../../apps/console-api/src/modules/portal/portal-proof';
import { id, actor, cid, wid, physical } from './m6-approved-fixture';

// Actual 1.5.1 plugins_iterator.lua calls should_process_plugin() once per
// subsystem and load_configuration() never tests request.protocol. constants.lua
// places HTTP/HTTPS/gRPC/gRPCS in the same HTTP subsystem (public source hashes
// recorded in artifacts/M6/kong-1.5-plugin-applicability.json).
const pub = id(30), service = id(31), route = id(32), key = id(33), acl = id(34), otherService = id(35), otherRoute = id(36), override = id(37), consumer = id(38);
const group = `kos-portal-api-${pub}`;
const plugin = (pluginId: string, name: string, serviceId: string, config: any, protocols = ['http', 'https']) => ({ id: pluginId, name, service: { id: serviceId }, route: null, consumer: null,
  enabled: true, run_on: 'first', protocols, config, tags: ['kos-ws-pay'] });
function graph() {
  return { services: [{ id: service, protocol: 'http', tags: ['kos-ws-pay'] }, { id: otherService, protocol: 'http', tags: ['kos-ws-pay'] }],
    routes: [{ id: route, service: { id: service }, protocols: ['http'], tags: ['kos-ws-pay'] }, { id: otherRoute, service: { id: otherService }, protocols: ['http'], tags: ['kos-ws-pay'] }],
    plugins: [plugin(key, 'key-auth', service, { key_names: ['apikey'], anonymous: null }), plugin(acl, 'acl', service, { whitelist: [group], blacklist: null }),
      plugin(id(40), 'key-auth', otherService, { key_names: ['apikey'], anonymous: null }), plugin(id(41), 'acl', otherService, { whitelist: ['ordinary-team'], blacklist: null })] };
}
const publication = { id: pub, serviceId: service, aclGroup: group, keyAuthPluginId: key, aclPluginId: acl, established: true };

beforeEach(() => { vi.stubEnv('APP_SECRET', 'm6-boundary-review-hmac-secret-minimum-32'); vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ac'.repeat(32)); });
afterEach(() => vi.unstubAllEnvs());

function serviceFixture() {
  const secrets = new SecretService(), context = new KongExecutionContextService(), native = graph();
  const cluster = { id: cid, admin_url: 'http://kong:8001', transport_scope: physical, version: '1.5.1', execution_mode: 'direct' };
  const proof: any = { version: 1, clusterId: cid, workspaceId: wid, publicationId: pub, publicationRevision: 1, transportScope: physical,
    clusterRevision: 1, workspaceRevision: 1, executionMode: 'direct', workflowId: id(43), executionId: id(44), planRevision: 1, planHash: 'b'.repeat(64), verifiedAt: new Date().toISOString(),
    serviceId: service, aclGroup: group, aclPluginId: acl, keyAuthPluginId: key, service: native.services[0], aclPlugin: native.plugins[1], keyAuthPlugin: native.plugins[0], schemas: {}, definitions: {} };
  const publications: any[] = [{ id: pub, cluster_id: cid, workspace_id: wid, transport_scope: physical, service_id: service, acl_group: group, acl_plugin_id: acl, key_auth_plugin_id: key,
    published_revision: 1, state: 'published', publication_id: pub, publication_revision: 1,
    publication_proof_secret: secrets.encrypt(proof, publicationProofAad(cid, wid, pub, 1)), publication_proof_hmac: secrets.fingerprint(proof),
    proof_workflow_id: proof.workflowId, workflow_execution_id: proof.executionId, workflow_plan_revision: 1, workflow_plan_hash: proof.planHash,
    proof_execution_state: 'succeeded', proof_workflow_state: 'succeeded', proof_workflow_kind: 'portal-publication' }];
  const grants: any[] = [], credentials: any[] = [];
  const db: any = { query: vi.fn(async (sql: string, params: any[]) => {
    if (params[0] !== physical) return [];
    return sql.includes('FROM portal_publications') ? publications : sql.includes('FROM portal_application_grants') ? grants : sql.includes('FROM portal_credentials') ? credentials : [];
  }) };
  const kong: any = { list: vi.fn(async (_cid: string, path: string, query: any) => {
    context.assertPortalBoundaryRead(context.current());
    const ticket = await context.authorizeRequest(cluster, 'GET', path, undefined, query);
    const value = await context.authorizeResponse(ticket, { data: native[path.slice(1) as keyof typeof native] ?? [], next: null });
    return { items: value.data, nextCursor: null };
  }), schema: vi.fn(async (_cid: string, type: string) => {
    const ticket = await context.authorizeRequest(cluster, 'GET', `/schemas/${type}`, undefined, {});
    return context.authorizeResponse(ticket, { fields: type === 'plugins' ? [{ enabled: { type: 'boolean', default: true } }, { protocols: { type: 'set', default: ['http', 'https'] } }, { config: { type: 'record' } }]
      : type === 'routes' ? [{ protocols: { type: 'set', default: ['http', 'https'] } }] : [{ protocol: { type: 'string', default: 'http' } }] });
  }), pluginSchema: vi.fn(async (_cid: string, name: string) => {
    const ticket = await context.authorizeRequest(cluster, 'GET', `/plugins/schema/${name}`, undefined, {});
    return context.authorizeResponse(ticket, { fields: name === 'acl' ? [{ blacklist: { type: 'array', default: null } }] : [{ anonymous: { type: 'string', default: null } }, { key_names: { type: 'array', default: ['apikey'] } }] });
  }) };
  const workspace: any = { listScope: vi.fn(async () => ({ workspaceTag: 'kos-ws-pay' })), matches: (scope: any, row: any) => row.tags?.includes(scope.workspaceTag) };
  const approved: any = { assertNativeWrite: vi.fn(async () => { throw new ForbiddenException({ code: 'APPROVED_STEP_REQUIRED' }); }) };
  const boundary = new PortalAuthBoundaryService(db, secrets, kong, context, workspace, approved);
  context.installPolicy({ authorizeRequest: async () => ({}), authorizeResponse: async (_decision, value) => value,
    beforeNativeSend: async (_frame, _cluster, method, path, body, _query, _decision, permit) => {
      const pieces = path.split('/'), before = pieces.length > 2 ? native[pieces[1] as keyof typeof native]?.find((row: any) => row.id === pieces[2]) : undefined;
      await boundary.assertBeforeNativeSend({ clusterId: cid, workspaceId: wid, transportScope: physical, operationId: id(45), method, canonicalPath: path, body, before, mutationAction: method === 'DELETE' ? 'delete' : method === 'POST' ? 'create' : 'update' }, permit);
    } });
  const run = (method: string, path: string, body?: unknown) => context.runHttp({}, async () => {
    context.bindHttpActor(actor, 'boundary-review-session'); const close = context.captureHttpCloser();
    try { return await context.runActor({ actor, clusterId: cid, workspaceId: wid, module: path.split('/')[1], action: method === 'DELETE' ? 'delete' : 'write' }, () =>
      context.runOperation({ actor, clusterId: cid, workspaceId: wid, operationId: id(45), entityType: 'plugins', action: method === 'DELETE' ? 'delete' : 'create' }, async () => {
        const send = async () => { const ticket = await context.authorizeRequest(cluster, method, path, body, {}); await context.beforeNativeSend(ticket); };
        return method === 'DELETE' ? context.runArchiveDelete({ entryId: id(46), operationId: id(45), clusterId: cid, workspaceId: wid, nodes: [{ path, type: 'plugins', id: path.split('/')[2] }] }, send) : send();
      })); } finally { close(); }
  });
  return { context, secrets, native, publications, grants, credentials, approved, kong, db, run, boundary };
}

describe('M6 independent actual 1.5 Portal auth applicability', () => {
  it('rejects HTTPS-only ACL overriding an unrelated HTTP-only Route in the shared HTTP subsystem', () => {
    const g = graph(); g.plugins.push({ ...plugin(override, 'acl', otherService, { whitelist: [group], blacklist: null }, ['https']), service: null, route: { id: otherRoute } });
    expect(() => assertPortalAuthenticationBoundary(g, [publication], [])).toThrowError(expect.objectContaining({ response: expect.objectContaining({ code: 'PORTAL_UNMANAGED_AUTH_BOUNDARY' }) }));
  });
  it('protects HTTPS baselines with valid HTTP-only auth plugins because both run in the HTTP subsystem', () => {
    const g = graph(); for (const p of g.plugins) p.protocols = ['http'];
    expect(() => assertPortalAuthenticationBoundary(g, [publication], [])).not.toThrow();
  });
  it('includes gRPC-family plugin instances for HTTP while keeping stream plugins out of HTTP selection', () => {
    const candidate = plugin(override, 'request-termination', service, {}, ['grpc']);
    expect(effectivePortalPlugin([candidate], candidate.name, { serviceId: service, consumerId: consumer, protocol: 'http' })?.id).toBe(override);
    candidate.protocols = ['tls'];
    expect(effectivePortalPlugin([candidate], candidate.name, { serviceId: service, consumerId: consumer, protocol: 'http' })).toBeUndefined();
    expect(effectivePortalPlugin([candidate], candidate.name, { serviceId: service, consumerId: consumer, protocol: 'tcp' })?.id).toBe(override);
  });
  it('does not classify one plugin listing HTTP and HTTPS twice as ambiguous', () => {
    expect(() => assertPortalAuthenticationBoundary(graph(), [publication], [])).not.toThrow();
  });
});

describe('M6 independent actual final-send Portal boundary service', () => {
  it('continues protecting published plugins with zero keys and rejects ordinary recycle DELETE', async () => {
    const f = serviceFixture();
    await expect(f.run('DELETE', `/plugins/${key}`)).rejects.toMatchObject({ response: { code: 'PORTAL_UNMANAGED_AUTH_BOUNDARY' } });
    expect(f.kong.list).toHaveBeenCalledTimes(3);
  });
  it('uses actual create schema defaults and notices the new dangerous HTTP-family Route', async () => {
    const f = serviceFixture();
    f.native.plugins = f.native.plugins.filter(p => p.service?.id !== otherService || p.name === 'key-auth');
    // Without an existing unrelated route there is no previously reachable
    // unmanaged acceptance surface. A create without protocols must acquire
    // the actual default HTTP+HTTPS protocols before prospective validation.
    f.native.routes = f.native.routes.filter(row => row.id !== otherRoute);
    f.native.plugins.push(plugin(id(47), 'acl', otherService, { whitelist: [group], blacklist: null }));
    await expect(f.run('POST', '/routes', { id: otherRoute, service: { id: otherService }, tags: ['kos-ws-pay'] })).rejects.toMatchObject({ response: { code: 'PORTAL_UNMANAGED_AUTH_BOUNDARY' } });
    expect(f.kong.schema).toHaveBeenCalledWith(cid, 'routes');
  });
  it('uses actual enabled/protocol/config defaults when a new ACL instance omits all three', async () => {
    const f = serviceFixture();
    await expect(f.run('POST', '/plugins', { id: override, name: 'acl', route: { id: otherRoute }, config: { whitelist: [group] }, tags: ['kos-ws-pay'] })).rejects.toMatchObject({ response: { code: 'PORTAL_UNMANAGED_AUTH_BOUNDARY' } });
    expect(f.kong.pluginSchema).toHaveBeenCalledWith(cid, 'acl');
  });
  it('allows an ordinary harmless Service change while preserving its workspace and full protected chain', async () => {
    const f = serviceFixture(); await expect(f.run('PATCH', `/services/${service}`, { name: 'ordinary-safe-change' })).resolves.toBeUndefined();
    await expect(f.run('PATCH', `/services/${service}`, { tags: [] })).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLISHED_WORKSPACE_IMMUTABLE' } });
  });
  it('does not treat a pending publication without key-auth as established before ACL installation', async () => {
    const f = serviceFixture(); f.publications[0].published_revision = null; f.publications[0].state = 'pending';
    f.native.plugins = f.native.plugins.filter(p => p.service?.id !== service);
    await expect(f.run('POST', '/plugins', { id: acl, name: 'acl', service: { id: service }, config: { whitelist: [group] }, tags: ['kos-ws-pay'] })).resolves.toBeUndefined();
  });
  it('rejects reserved ACL group injection and historical credential reuse under an unmanaged Consumer before raw capture', async () => {
    const f = serviceFixture(); f.publications.length = 0;
    await expect(f.run('POST', `/consumers/${consumer}/acls`, { id: id(47), group })).rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    expect(f.kong.list).not.toHaveBeenCalled(); expect(f.approved.assertNativeWrite).toHaveBeenCalledTimes(1);
    f.grants.push({ consumer_id: id(48), acl_id: id(49), state: 'revoked' }); f.credentials.push({ kong_id: id(50) });
    await expect(f.run('POST', `/consumers/${consumer}/key-auth`, { id: id(50), key: 'private-test-canary' })).rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    await expect(f.run('POST', `/consumers/${consumer}/acls`, { id: id(49), group: 'ordinary-team' })).rejects.toMatchObject({ response: { code: 'PORTAL_MANAGED_OBJECT' } });
    expect(f.kong.list).not.toHaveBeenCalled();
  });
  it('rejects forged/corrupted publication proof and captured physical scope before native graph reads', async () => {
    const f = serviceFixture(); f.publications[0].transport_scope = 'b'.repeat(64);
    await expect(f.run('PATCH', `/services/${service}`, { name: 'safe-change' })).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_PROOF_INVALID' } });
    expect(f.kong.list).not.toHaveBeenCalled();
  });
  it('rejects ownership changes after the private capture await and incomplete captures instead of returning an empty proof', async () => {
    const f = serviceFixture(), original = f.kong.list.getMockImplementation()!; let calls = 0;
    f.kong.list.mockImplementation(async (...args: any[]) => { const page = await original(...args); if (++calls === 3) f.publications[0].revision = 2; return page; });
    await expect(f.run('PATCH', `/services/${service}`, { name: 'safe-change' })).rejects.toMatchObject({ response: { code: 'PORTAL_AUTH_GRAPH_CHANGED' } });
    const g = serviceFixture(); g.kong.list.mockResolvedValue({ items: undefined, nextCursor: null });
    await expect(g.run('PATCH', `/services/${service}`, { name: 'safe-change' })).rejects.toMatchObject({ response: { code: 'PORTAL_AUTH_GRAPH_INCOMPLETE' } });
  });
});
