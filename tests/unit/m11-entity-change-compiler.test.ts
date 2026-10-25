import 'reflect-metadata';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { EntityService } from '../../apps/console-api/src/modules/entities/entities.service';
import { EntityChangeCompilerService } from '../../apps/console-api/src/modules/entities/entity-change-compiler.service';
import { AuthorizationService } from '../../apps/console-api/src/modules/authorization/authorization.service';
import { KongExecutionContextService } from '../../apps/console-api/src/infrastructure/kong/execution-context.service';
import { entityChangeInput } from '../../apps/console-api/src/modules/entities/entity-change-input';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { entityForPath } from '../../apps/console-api/src/infrastructure/kong/policy';
import { validateKnownFields } from '../../apps/console-api/src/infrastructure/kong/schema';
import { workspaceTag } from '../../apps/console-api/src/infrastructure/kong/tags';
import { executionFixture } from './execution-test-fixture';
import { PAY_WORKSPACE_ID, workspaceTestResolver } from './workspace-test-helper';

const cid = '79f53e2f-4fe6-4cc7-b4a5-2b1d86b09ab6', uid = 'd65e16c9-0f15-49b9-b2b8-0813503c55a5';
const sid = '2b5a8e75-5088-457e-b8f8-653d653a0654', upstreamId = '0e260508-f289-4bdf-af13-66a1d0c688cf';
const targetId = '510ed8cd-bf58-44f0-862a-0b0ddc610529', consumerId = '6c8f9920-c181-4a4b-9665-c782e4a88c96';
const actor = { user: { id: uid, username: 'test', superAdmin: true }, workspaceId: PAY_WORKSPACE_ID, requestId: sid };
const recorded = (name: string) => JSON.parse(readFileSync(new URL(`../fixtures/kong-1.5.1/schema-${name}.json`, import.meta.url), 'utf8'));
const fields = (extra: Record<string, any>) => ({ fields: [{ id: { type: 'string', uuid: true, auto: true } }, { tags: { type: 'set', elements: { type: 'string' } } }, ...Object.entries(extra).map(([name, definition]) => ({ [name]: definition }))] });

function fixture() {
  const secrets = new SecretService(), workspace = workspaceTestResolver(cid), execution = executionFixture();
  const data = new Map<string, any>([
    [`/services/${sid}`, { id: sid, name: 'service', host: 'business.example', tags: [workspaceTag('pay')] }],
    [`/upstreams/${upstreamId}`, { id: upstreamId, name: 'pool', tags: [workspaceTag('pay')] }],
    [`/upstreams/${upstreamId}/targets/${targetId}`, { id: targetId, target: 'echo.example:8080', weight: 100, upstream: { id: upstreamId }, tags: [workspaceTag('pay')] }],
    [`/consumers/${consumerId}`, { id: consumerId, username: 'client', tags: [workspaceTag('pay')] }],
  ]);
  const schemas: Record<string, any> = { services: recorded('services'), routes: recorded('routes'), upstreams: recorded('upstreams'), certificates: recorded('certificates'), snis: recorded('snis'),
    plugins: recorded('plugins'),
    targets: fields({ target: { type: 'string', required: true }, weight: { type: 'integer', default: 100, between: [0, 1000] } }),
    keyauth_credentials: fields({ key: { type: 'string', auto: true, required: true } }),
    basicauth_credentials: fields({ username: { type: 'string', required: true }, password: { type: 'string', required: true } }),
    jwt_secrets: fields({ key: { type: 'string', required: true, auto: true }, secret: { type: 'string', auto: true }, algorithm: { type: 'string', default: 'HS256' } }),
    oauth2_credentials: fields({ name: { type: 'string', required: true }, client_id: { type: 'string', auto: true }, client_secret: { type: 'string', auto: true }, redirect_uris: { type: 'array', elements: { type: 'string' } } }),
    hmacauth_credentials: fields({ username: { type: 'string', required: true }, secret: { type: 'string', auto: true } }),
    acls: fields({ group: { type: 'string', required: true } }),
  };
  const kong: any = { request: vi.fn(async (_cid: string, method: string, path: string) => { if (method !== 'GET') throw new Error('Preparation attempted a native write'); const value = data.get(path); if (!value) throw new NotFoundException(); return structuredClone(value); }),
    list: vi.fn(async () => ({ items: [structuredClone(data.get(`/upstreams/${upstreamId}/targets/${targetId}`))], nextCursor: null, size: 100 })),
    transportScope: vi.fn(async () => 'aa'.repeat(32)),
    prepareSchema: vi.fn(async (_cid: string, path: string, body: unknown) => { const nativeType = entityForPath(path)!, schema = schemas[nativeType];
      if (!schema) throw new Error(`Unknown fixture schema ${nativeType}`); validateKnownFields(body, schema);
      const pluginName = (body as any)?.name ?? data.get(path)?.name;
      const plugin = nativeType === 'plugins' ? { name: pluginName, canonicalPath: `/plugins/schema/${pluginName}`, schema: JSON.parse(readFileSync(new URL(`../fixtures/kong-1.5.1/plugin-schema-${pluginName}.json`, import.meta.url), 'utf8')) } : undefined;
      return { version: 1, clusterId: cid, canonicalPath: path, nativeType, kongVersion: '1.5.1', adapter: 'kong-oss-1.5-v1', clusterRevision: 1,
        schemaMaterial: { entity: { name: nativeType, canonicalPath: `/schemas/${nativeType}`, schema }, ...(plugin ? { plugin } : {}) }, payloadHmac: secrets.fingerprint(body ?? null) }; }),
  };
  const authz: any = { assertCluster: vi.fn(), assertEntity: vi.fn(), assertNestedParentScope: vi.fn(), assertSecretRead: vi.fn(), permissionVersion: vi.fn(async () => 'permission-v1') };
  const mutations: any = { execute: vi.fn() }, audit: any = { append: vi.fn() }, index: any = { upsert: vi.fn() }, credentials: any = { save: vi.fn(), getRestorePayload: vi.fn() };
  const entities = new EntityService(kong, authz, mutations, {} as any, credentials, secrets, audit, index, workspace.resolver, execution);
  const compiler = new EntityChangeCompilerService(entities, kong, authz, workspace.resolver, secrets, execution), boundary = { assertPacket: vi.fn(), assertStoredSubject: vi.fn() };
  compiler.installPreparationBoundary(boundary);
  return { compiler, entities, kong, data, schemas, secrets, boundary, authz, mutations, audit, index, credentials };
}
function scopedFixture(f: ReturnType<typeof fixture>, initialGrants: any[]) {
  const execution = new KongExecutionContextService(), workspace = workspaceTestResolver(cid), sessionId = 'd51326f7-6f58-4858-8b04-c838c0f7e5a2';
  const scopedActor = { ...actor, user: { ...actor.user, superAdmin: false } }; let grants = initialGrants;
  const db: any = { one: vi.fn(async (sql: string) => sql.includes('FROM users') ? { id: uid, username: 'test', super_admin: false, permissions_epoch: 1, credential_epoch: 1, revision: 1 }
    : sql.includes('FROM auth_sessions') ? { id: sessionId } : sql.includes('FROM iam_epoch') ? { version: 1 } : sql.includes('FROM clusters') ? { id: cid } : null),
    query: vi.fn(async (sql: string) => sql.includes('iam_effective_grants') ? structuredClone(grants) : []) };
  const authz = new AuthorizationService(db, workspace.resolver, f.kong, execution);
  const entities = new EntityService(f.kong, authz, f.mutations, {} as any, f.credentials, f.secrets, f.audit, f.index, workspace.resolver, execution);
  const compiler = new EntityChangeCompilerService(entities, f.kong, authz, workspace.resolver, f.secrets, execution); compiler.installPreparationBoundary(f.boundary);
  const run = <T>(fn: () => Promise<T>) => execution.runHttp({}, async () => { execution.bindHttpActor(scopedActor.user, sessionId); const close = execution.captureHttpCloser(); try { return await fn(); } finally { close(); } });
  return { entities, compiler, scopedActor, run, revoke: () => { grants = []; } };
}
const scopedGrant = (module: string, action: string, entityType: string, entityId: string) => ({ module, action, scope_type: 'entity', cluster_id: cid, workspace_id: PAY_WORKSPACE_ID, scope_values: [{ entity_type: entityType, entity_id: entityId }] });

describe('M11 fixed entity compiler foundation (no execution capability)', () => {
  let directory: string, cert: string, key: string;
  beforeAll(() => {
    directory = mkdtempSync(join(tmpdir(), 'kongpilot-m11-compiler-')); chmodSync(directory, 0o700);
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem'), '-days', '2', '-subj', '/CN=compiler-unit.example'], { stdio: 'ignore' });
    cert = readFileSync(join(directory, 'cert.pem'), 'utf8'); key = readFileSync(join(directory, 'key.pem'), 'utf8');
  });
  afterAll(() => { if (directory) rmSync(directory, { recursive: true, force: true }); });
  beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'bc'.repeat(32)); vi.stubEnv('APP_SECRET', 'm11-unit-impact-secret-'.repeat(3)); });
  afterEach(() => vi.unstubAllEnvs());
  it('rejects arbitrary packet/proof fields, caller UUIDs and unconfirmed batches before preparation', () => {
    for (const value of [
      { kind: 'entity', action: 'create', entityType: 'services', body: { host: 'public.example' }, nativePath: '/services' },
      { kind: 'entity', action: 'create', entityType: 'services', body: { id: sid, host: 'public.example' } },
      { kind: 'entity', action: 'update', entityType: 'services', entityId: sid, body: {}, approved: true },
      { kind: 'batch', operations: [{ kind: 'entity', action: 'update', entityType: 'services', entityId: sid, body: {} }] },
      { kind: 'recycle', action: 'delete', entityType: 'services', entityId: sid, confirmed: false, confirm_name: 'service' },
    ]) expect(() => entityChangeInput(value)).toThrow();
    expect(entityChangeInput({ kind: 'entity', action: 'create', entityType: 'services', body: { host: 'public.example', path: '/valid-service-path' } })).toMatchObject({ body: { path: '/valid-service-path' } });
  });
  it('uses explicit existing workspace and refuses missing managed/recycle delegates', async () => {
    const f = fixture(), compiler = new EntityChangeCompilerService(f.entities, f.kong, f.authz, workspaceTestResolver(cid).resolver, f.secrets, executionFixture());
    await expect(compiler.prepare(cid, { kind: 'entity', action: 'update', entityType: 'services', entityId: sid, body: {} }, actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_PREPARATION_POLICY_UNAVAILABLE' } });
    await expect(f.compiler.prepare(cid, { kind: 'entity', action: 'update', entityType: 'services', entityId: sid, body: {} }, { ...actor, workspaceId: undefined })).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_WORKSPACE_REQUIRED' } });
    await expect(f.compiler.prepare(cid, { kind: 'recycle', action: 'delete', entityType: 'services', entityId: sid, confirmed: true, confirm_name: 'service' }, actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_PREPARATION_POLICY_UNAVAILABLE' } });
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled();
  });
  it('allocates UUID and seals the actual tag-scoped body with only GETs and no business writes', async () => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'entity', action: 'create', entityType: 'services', body: { name: 'new-service', host: 'public.example', tags: ['team:pay'] } }, actor);
    const packet = material.packets[0]; expect(packet).toMatchObject({ method: 'POST', canonicalPath: '/services', nativeType: 'services', mutationAction: 'create' });
    expect(packet.nativeId).toMatch(/^[a-f\d-]{36}$/); expect(packet.body).toMatchObject({ id: packet.nativeId, tags: expect.arrayContaining([workspaceTag('pay')]) });
    expect(material.scope).toMatchObject({ kongVersion: '1.5.1', transportScope: 'aa'.repeat(32) });
    expect(material).not.toHaveProperty('sessionId'); expect(material).not.toHaveProperty('jobId'); expect(Object.isFrozen(material.packets)).toBe(true);
    expect(f.kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
    for (const writer of [f.mutations.execute, f.audit.append, f.index.upsert, f.credentials.save]) expect(writer).not.toHaveBeenCalled();
    await expect(f.compiler.assertCurrent(material, actor, 'execute')).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_EXECUTION_ADAPTER_REQUIRED' } });
  });
  it('rejects forged sealed material, stale private before, schema changes and revoked permissions', async () => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'entity', action: 'update', entityType: 'services', entityId: sid, body: { retries: 3 } }, actor);
    const forged = structuredClone(material); forged.packets[0].body = { retries: 9 };
    await expect(f.compiler.project(forged, actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_MATERIAL_INVALID' } });
    f.data.get(`/services/${sid}`).connect_timeout = 300;
    await expect(f.compiler.project(material, actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_BASELINE_CHANGED' } });
    delete f.data.get(`/services/${sid}`).connect_timeout;
    f.schemas.services = { ...f.schemas.services, changed: true };
    await expect(f.compiler.project(material, actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_SCHEMA_CHANGED' } });
    f.schemas.services = recorded('services'); f.authz.permissionVersion.mockResolvedValue('permission-v2');
    await expect(f.compiler.project(material, actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_PERMISSIONS_CHANGED' } });
  });
  it('compiles weight as a new POST history UUID and verifies the entire effective collection', async () => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'target', action: 'weight', upstreamId, targetId, body: { weight: 50 } }, actor), packet = material.packets[0];
    expect(packet).toMatchObject({ method: 'POST', canonicalPath: `/upstreams/${upstreamId}/targets`, originalNativeId: targetId, body: { target: 'echo.example:8080', weight: 50 } });
    expect(packet.nativeId).not.toBe(targetId); expect(packet.body?.id).toBe(packet.nativeId); expect(material.recovery.blockerCodes).toContain('TARGET_RESTORE_APPENDS_HISTORY');
    f.kong.list.mockResolvedValue({ items: [], nextCursor: null, size: 100 });
    await expect(f.compiler.project(material, actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_TARGET_NOT_EFFECTIVE' } });
    expect(f.kong.request.mock.calls.some((call: any[]) => call[1] !== 'GET')).toBe(false);
  });
  it('keeps health node-local with no invented restore state and a bodyless native packet', async () => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'target', action: 'health', upstreamId, targetId, state: 'unhealthy' }, actor);
    expect(material.packets[0]).toMatchObject({ method: 'POST', canonicalPath: `/upstreams/${upstreamId}/targets/${targetId}/unhealthy`, mutationAction: 'mark_unhealthy' });
    expect(material.packets[0]).not.toHaveProperty('body'); expect(material.recovery.blockerCodes).toContain('TARGET_HEALTH_OVERRIDE_ROLLBACK_UNAVAILABLE');
  });
  it('freezes generated key-auth secrets privately, redacts review and defers credential metadata', async () => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'credential', action: 'create', consumerId, credentialKind: 'key-auth', body: {} }, actor), key = material.packets[0].body?.key;
    expect(key).toMatch(/^[a-f\d]{64}$/); expect(material.metadataObligations[0]).toMatchObject({ kind: 'credential-remember', consumerId, credentialKind: 'key-auth', rawInput: { key } });
    const review = await f.compiler.project(material, actor); expect(JSON.stringify(review)).not.toContain(key as string); expect(review.changes[0].after).toMatchObject({ key: expect.stringMatching(/^\[REDACTED:/) });
    expect(review).not.toHaveProperty('schemas'); expect(review).not.toHaveProperty('prerequisites'); expect(f.credentials.save).not.toHaveBeenCalled();
  });
  it('makes certificate SNI creates and reassociations explicit dependent packets', async () => {
    const f = fixture(), existingSniId = 'abcf0c49-1c46-4a29-b272-adb7eb619f4f', oldCertId = '9e5f3bd0-dbe9-469f-a940-6209d602c737';
    f.data.set('/snis/existing.example', { id: existingSniId, name: 'existing.example', certificate: { id: oldCertId }, tags: [workspaceTag('pay')] });
    const material = await f.compiler.prepare(cid, { kind: 'entity', action: 'create', entityType: 'certificates', body: { cert, key, snis: ['new.example', 'existing.example'] } }, actor);
    const [certificate, created, rebound] = material.packets;
    expect(certificate.body).not.toHaveProperty('snis'); expect(certificate.canonicalPath).toBe('/certificates');
    expect(created).toMatchObject({ method: 'POST', canonicalPath: '/snis', dependencies: [certificate.key], body: { name: 'new.example', certificate: { id: certificate.nativeId } } });
    expect(rebound).toMatchObject({ method: 'PATCH', canonicalPath: `/snis/${existingSniId}`, dependencies: [certificate.key], body: { certificate: { id: certificate.nativeId } }, before: { certificate: { id: oldCertId } } });
    const review = await f.compiler.project(material, actor); expect(JSON.stringify(review)).not.toContain('PRIVATE KEY');
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled();
  });
  it('freezes Basic plaintext provenance instead of copying the native hash', async () => {
    const f = fixture(), credentialId = '328c4064-eab0-4098-8bf6-48edff639fc8';
    f.data.set(`/consumers/${consumerId}/basic-auth/${credentialId}`, { id: credentialId, consumer: { id: consumerId }, username: 'basic-user', password: 'native-hash-unit-only', tags: [workspaceTag('pay')] });
    f.credentials.getRestorePayload.mockResolvedValue({ id: credentialId, username: 'basic-user', password: 'trusted-plaintext-unit-only', consumer: { id: consumerId } });
    const material = await f.compiler.prepare(cid, { kind: 'credential', action: 'update', consumerId, credentialKind: 'basic-auth', credentialId, body: { username: 'renamed-basic' } }, actor);
    expect(material.packets[0].body).not.toHaveProperty('password');
    expect(material.recovery.objects[0]).toMatchObject({ restorePayload: { password: 'trusted-plaintext-unit-only' }, sourceHashHmac: f.secrets.fingerprint('native-hash-unit-only') });
    f.credentials.getRestorePayload.mockClear(); await f.compiler.project(material, actor);
    expect(f.credentials.getRestorePayload).not.toHaveBeenCalled(); expect(f.credentials.save).not.toHaveBeenCalled();
  });
  it('treats plugin names as types rather than nonexistent name-key entity endpoints', async () => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'entity', action: 'create', entityType: 'plugins', body: { name: 'cors', service: { id: sid }, config: { origins: ['https://public.example'] } } }, actor);
    expect(material.packets[0]).toMatchObject({ canonicalPath: '/plugins', body: { name: 'cors', service: { id: sid } } });
    expect(f.kong.request.mock.calls.some((call: any[]) => call[2] === '/plugins/cors')).toBe(false);
    expect(material.schemas[0].schemaMaterial.plugin?.canonicalPath).toBe('/plugins/schema/cors');
  });
  it('prepares response-transformer nested defaults using the actual legacy schema without changing approved wire config', async () => {
    const f = fixture(), config = { add: { headers: ['X-KongPilot-Corpus:owned-marker'] } };
    const material = await f.compiler.prepare(cid, { kind: 'entity', action: 'create', entityType: 'plugins', body: { name: 'response-transformer', service: { id: sid }, config } }, actor);
    expect(material.packets[0].body?.config).toEqual(config);
    expect(material.schemas[0].schemaMaterial.plugin?.canonicalPath).toBe('/plugins/schema/response-transformer');
    expect(f.kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
    expect(f.mutations.execute).not.toHaveBeenCalled();
  });
  it('normalizes plugin configuration validation errors into readable 400 fields before any write', async () => {
    const f = fixture();
    await expect(f.compiler.prepare(cid, { kind: 'entity', action: 'create', entityType: 'plugins', body: { name: 'response-transformer', service: { id: sid }, config: { remove: {}, rename: {}, replace: {}, append: {}, add: { headers: [42] } } } }, actor))
      .rejects.toMatchObject({ status: 400, response: { code: 'ENTITY_CHANGE_SCHEMA_INVALID', fields: { 'config.add.headers[0]': 'CONFIGURATION_SCHEMA_VALUE' } } });
    expect(f.mutations.execute).not.toHaveBeenCalled();
  });
  it('checks and seals UUID-string foreign references with the same workspace and binding semantics', async () => {
    const f = fixture(), scopedActor = { ...actor, user: { ...actor.user, superAdmin: false } };
    const material = await f.compiler.prepare(cid, { kind: 'entity', action: 'create', entityType: 'plugins', body: { name: 'cors', service: sid, config: {} } }, scopedActor);
    expect(material.packets[0].body?.service).toBe(sid);
    expect(material.prerequisites).toContainEqual(expect.objectContaining({ type: 'services', nativeId: sid, path: `/services/${sid}`,
      fingerprint: f.secrets.fingerprint(f.data.get(`/services/${sid}`)), permissionAction: 'read' }));
    expect(f.authz.assertEntity).toHaveBeenCalledWith(scopedActor.user, cid, 'services', 'read', expect.objectContaining({ id: sid }), PAY_WORKSPACE_ID);
    expect((await f.compiler.project(material, scopedActor)).impact.globalPlugin).toBe(false);
    expect(f.mutations.execute).not.toHaveBeenCalled();
  });
  it('rejects a UUID-string reference to another workspace before compiler or direct business writes', async () => {
    const f = fixture(), foreignId = '51464555-ce56-4b2a-be74-16beee325edb';
    f.data.set(`/services/${foreignId}`, { id: foreignId, name: 'other-workspace', host: 'public.example', tags: [workspaceTag('ops')] });
    const body = { service: foreignId, paths: ['/pay'] };
    await expect(f.compiler.prepare(cid, { kind: 'entity', action: 'create', entityType: 'routes', body }, actor)).rejects.toMatchObject({ status: 403, response: { code: 'WORKSPACE_ENTITY_MISMATCH' } });
    await expect(f.entities.create(cid, 'routes', body, {}, actor)).rejects.toMatchObject({ status: 403, response: { code: 'WORKSPACE_ENTITY_MISMATCH' } });
    expect(f.kong.prepareSchema).not.toHaveBeenCalled();
    for (const writer of [f.mutations.execute, f.audit.append, f.index.upsert, f.credentials.save]) expect(writer).not.toHaveBeenCalled();
    expect(f.kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
  });
  it('freezes the actual oauth2 plugin automatic provision_key before approval', async () => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'entity', action: 'create', entityType: 'plugins', body: { name: 'oauth2', service: { id: sid }, config: { enable_client_credentials: true } } }, actor);
    const secret = (material.packets[0].body?.config as any).provision_key;
    expect(secret).toMatch(/^[a-f\d]{64}$/); expect(JSON.stringify(await f.compiler.project(material, actor))).not.toContain(secret);
  });
  it.each([
    ['key-auth', {}, 'key'], ['basic-auth', { username: 'user', password: 'unit-input-password' }, 'password'],
    ['jwt', { algorithm: 'HS256' }, 'secret'], ['oauth2', { name: 'client', redirect_uris: ['https://public.example/callback'] }, 'client_secret'],
    ['hmac-auth', { username: 'user' }, 'secret'], ['acls', { group: 'public-group' }, null],
  ] as const)('keeps %s under its actual Consumer and defers metadata until native success', async (credentialKind, body, secretField) => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'credential', action: 'create', consumerId, credentialKind, body }, actor), packet = material.packets[0];
    expect(packet).toMatchObject({ method: 'POST', canonicalPath: `/consumers/${consumerId}/${credentialKind}`, parentId: consumerId, credentialKind });
    expect(packet.body?.id).toBe(packet.nativeId); expect(material.metadataObligations[0]).toMatchObject({ kind: 'credential-remember', credentialKind });
    if (secretField) expect(JSON.stringify(await f.compiler.project(material, actor))).not.toContain(packet.body![secretField] as string);
    expect(f.credentials.save).not.toHaveBeenCalled(); expect(f.mutations.execute).not.toHaveBeenCalled();
  });
  it('rejects repeated changes and scalar violations before any execution', async () => {
    const f = fixture(), operation = { kind: 'entity', action: 'update', entityType: 'services', entityId: sid, body: { retries: 3 } };
    await expect(f.compiler.prepare(cid, { kind: 'batch', operations: [operation, operation], confirmed: true }, actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_DUPLICATE_OBJECT' } });
    await expect(f.compiler.prepare(cid, { ...operation, body: { retries: 'invalid' } }, actor)).rejects.toThrow();
    const create = { kind: 'entity', action: 'create', entityType: 'services', body: { name: 'same-name', host: 'public.example' } };
    await expect(f.compiler.prepare(cid, { kind: 'batch', operations: [create, create], confirmed: true }, actor)).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_DUPLICATE_OBJECT' } });
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled();
  });
  it('reads frozen historical facts with current read/approve grants after normal execution changes, without Kong reads', async () => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'entity', action: 'update', entityType: 'services', entityId: sid, body: { retries: 3 } }, actor), original = JSON.stringify(material);
    const reader = { ...actor, user: { ...actor.user, id: '9adf89e2-68f7-4133-a823-d1d9b24292c4', superAdmin: false } };
    f.data.delete(`/services/${sid}`); f.authz.permissionVersion.mockResolvedValue('permission-v2');
    f.kong.request.mockClear(); f.kong.prepareSchema.mockClear(); f.kong.transportScope.mockClear(); f.authz.assertEntity.mockClear();
    f.authz.assertEntity.mockRejectedValue(new ForbiddenException('Reader has no writer grant'));
    const review = await f.compiler.projectStored(material, reader, 'read');
    await f.compiler.assertStoredScope(material, reader, 'approve');
    expect(review.changes[0]).toMatchObject({ before: { id: sid, host: 'business.example' }, after: { retries: 3 } });
    expect(f.boundary.assertStoredSubject).toHaveBeenCalledWith(expect.objectContaining({ action: 'read', mode: 'historical', actor: reader }));
    expect(f.boundary.assertStoredSubject).toHaveBeenCalledWith(expect.objectContaining({ action: 'approve', mode: 'historical', actor: reader }));
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.kong.prepareSchema).not.toHaveBeenCalled(); expect(f.kong.transportScope).not.toHaveBeenCalled();
    expect(f.authz.assertEntity).not.toHaveBeenCalled(); expect(JSON.stringify(material)).toBe(original);
  });
  it('revalidates stored intent under current grants without renewing material or enforcing its old permission version', async () => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'entity', action: 'update', entityType: 'services', entityId: sid, body: { retries: 3 } }, actor), original = JSON.stringify(material);
    f.authz.permissionVersion.mockResolvedValue('permission-v2');
    await f.compiler.revalidateStored(material, actor, 'write', 'claim');
    const approver = { ...actor, user: { ...actor.user, id: 'ca3e6a85-0147-4eb5-b2cb-cf5f476d491f', superAdmin: false } };
    f.authz.assertEntity.mockClear(); f.authz.assertEntity.mockRejectedValue(new ForbiddenException('Approver has no writer grant'));
    await f.compiler.revalidateStored(material, approver, 'approve', 'approve');
    expect(f.authz.assertEntity).not.toHaveBeenCalled();
    expect(f.boundary.assertStoredSubject).toHaveBeenCalledWith(expect.objectContaining({ action: 'approve', mode: 'fresh', actor: approver }));
    expect(f.boundary.assertPacket).toHaveBeenCalledWith(expect.objectContaining({ action: 'approve', phase: 'revalidate' }));
    f.data.get(`/services/${sid}`).host = 'drift.example';
    await expect(f.compiler.revalidateStored(material, actor, 'write', 'claim')).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_BASELINE_CHANGED' } });
    expect(JSON.stringify(material)).toBe(original); expect(f.mutations.execute).not.toHaveBeenCalled();
  });
  it('fails closed on missing subject policy, revoked current scope and permission races during historical projection', async () => {
    const f = fixture(), material = await f.compiler.prepare(cid, { kind: 'entity', action: 'update', entityType: 'services', entityId: sid, body: { retries: 3 } }, actor);
    const compiler = new EntityChangeCompilerService(f.entities, f.kong, f.authz, workspaceTestResolver(cid).resolver, f.secrets, executionFixture());
    compiler.installPreparationBoundary({ assertPacket: vi.fn() });
    await expect(compiler.projectStored(material, actor, 'read')).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_PREPARATION_POLICY_UNAVAILABLE' } });
    f.boundary.assertStoredSubject.mockRejectedValueOnce(new ForbiddenException('Current subject grant revoked'));
    await expect(f.compiler.projectStored(material, actor, 'read')).rejects.toMatchObject({ status: 403 });
    f.authz.permissionVersion.mockResolvedValueOnce('before').mockResolvedValueOnce('after');
    await expect(f.compiler.projectStored(material, actor, 'read')).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_PERMISSIONS_CHANGED' } });
    await expect(f.compiler.revalidateStored(material, actor, 'read', 'claim')).rejects.toMatchObject({ response: { code: 'ENTITY_CHANGE_PHASE_INVALID' } });
  });
  it('preserves a real Service-write-only inheritance check for a UUID-string plugin binding without changing wire bytes', async () => {
    const f = fixture(), scoped = scopedFixture(f, [scopedGrant('services', 'write', 'services', sid)]);
    const body = { name: 'cors', service: sid, config: {} };
    await scoped.run(async () => {
      const prepared = await scoped.entities.prepareCore(cid, 'plugins', 'create', undefined, body, scoped.scopedActor);
      expect(prepared.payload.service).toBe(sid); expect(body.service).toBe(sid);
      expect(prepared.references).toContainEqual(expect.objectContaining({ type: 'services', permissionAction: 'write', before: { id: sid, name: 'service', host: 'business.example', tags: [workspaceTag('pay')] } }));
      scoped.revoke();
      await expect(scoped.entities.prepareCore(cid, 'plugins', 'create', undefined, body, scoped.scopedActor)).rejects.toMatchObject({ status: 403 });
    });
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.kong.request.mock.calls.every((call: any[]) => call[1] === 'GET')).toBe(true);
  });
  it('freezes both original/replacement bindings and Route-to-Service ancestry with real inherited authorization', async () => {
    const f = fixture(), otherService = '8e2b6b48-a6f2-43af-b224-fc4514f90a6f', pluginId = '88e8b9c0-3e34-4a15-a94c-b3a37b3deae3', routeId = '27e2b55e-c093-4eb1-ad4d-467536fb9a34';
    f.data.set(`/services/${otherService}`, { id: otherService, name: 'replacement', host: 'public.example', tags: [workspaceTag('pay')] });
    f.data.set(`/plugins/${pluginId}`, { id: pluginId, name: 'cors', service: { id: sid }, config: {}, tags: [workspaceTag('pay')] });
    f.data.set(`/routes/${routeId}`, { id: routeId, name: 'inherited-route', service: { id: otherService }, paths: ['/pay'], tags: [workspaceTag('pay')] });
    const scoped = scopedFixture(f, [scopedGrant('services', 'write', 'services', sid), scopedGrant('services', 'write', 'services', otherService)]);
    await scoped.run(async () => {
      const changedBinding = await scoped.compiler.prepare(cid, { kind: 'entity', action: 'update', entityType: 'plugins', entityId: pluginId, body: { service: otherService } }, scoped.scopedActor);
      expect(changedBinding.prerequisites).toEqual(expect.arrayContaining([expect.objectContaining({ type: 'services', nativeId: sid }), expect.objectContaining({ type: 'services', nativeId: otherService })]));
      const viaRoute = await scoped.compiler.prepare(cid, { kind: 'entity', action: 'create', entityType: 'plugins', body: { name: 'cors', route: routeId, config: {} } }, scoped.scopedActor);
      expect(viaRoute.prerequisites).toEqual(expect.arrayContaining([expect.objectContaining({ type: 'routes', nativeId: routeId }), expect.objectContaining({ type: 'services', nativeId: otherService })]));
      expect(viaRoute.prerequisites.filter(value => !value.absent).every(value => value.fingerprint === f.secrets.fingerprint(value.before))).toBe(true);
    });
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.audit.append).not.toHaveBeenCalled();
  });
  it('keeps credential entity-only parent observation private while allowing the original child write tuple', async () => {
    const f = fixture(), credentialId = '359646ca-eec1-4e8a-8a68-8e963171eb55';
    f.data.set(`/consumers/${consumerId}/key-auth/${credentialId}`, { id: credentialId, key: 'old-unit-key', consumer: { id: consumerId }, tags: [workspaceTag('pay')] });
    f.credentials.getRestorePayload.mockImplementation(async (_cid: string, _parent: string, _kind: string, _id: string, remote: any) => remote);
    const scoped = scopedFixture(f, [scopedGrant('consumers', 'write', 'key-auth', credentialId)]);
    await scoped.run(async () => {
      const material = await scoped.compiler.prepare(cid, { kind: 'credential', action: 'update', consumerId, credentialKind: 'key-auth', credentialId, body: { key: 'replacement-unit-key' } }, scoped.scopedActor);
      expect(material.prerequisites).toContainEqual(expect.objectContaining({ type: 'consumers', nativeId: consumerId, purpose: 'private-parent' }));
      const review = await scoped.compiler.project(material, scoped.scopedActor);
      expect(JSON.stringify(review)).not.toContain('client'); expect(JSON.stringify(review)).not.toContain('replacement-unit-key');
      scoped.revoke();
      await expect(scoped.compiler.assertCurrent(material, scoped.scopedActor, 'prepare')).rejects.toMatchObject({ status: 403 });
    });
    expect(f.mutations.execute).not.toHaveBeenCalled(); expect(f.credentials.save).not.toHaveBeenCalled();
  });
});
