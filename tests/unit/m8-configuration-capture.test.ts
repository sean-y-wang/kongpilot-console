import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { ConfigurationCaptureService } from '../../apps/console-api/src/modules/config-capture/configuration-capture.service';
import { CaptureBudget, CAPTURE_LIMITS, captureJson, validateCapturedSchema } from '../../apps/console-api/src/modules/config-capture/capture-validation';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { signCursor, readCursor } from '../../apps/console-api/src/infrastructure/kong/cursor';
import { CredentialStoreService } from '../../apps/console-api/src/modules/credentials/credential-store.service';
import { WorkspaceResolverService } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import { CREDENTIAL_SCHEMAS } from '../../apps/console-api/src/modules/entities/entities.types';
import type { CaptureGraph, CaptureObject, ConfigurationScope } from '../../apps/console-api/src/modules/configuration/configuration.types';

const uid = (value: number) => `00000000-0000-4000-8000-${String(value).padStart(12, '0')}`;
const shape = (extra: Record<string, any> = {}) => ({ fields: [{ id: { type: 'string', required: true } }, { tags: { type: 'set', elements: { type: 'string' } } },
  ...Object.entries(extra).map(([name, definition]) => ({ [name]: definition }))] });
const foreign = { type: 'foreign' }, string = { type: 'string' };

function fixture(options: { kind?: ConfigurationScope['kind']; defaultWorkspace?: boolean; services?: number } = {}) {
  const secrets = new SecretService(), tags = options.defaultWorkspace ? [] : ['kos-ws-team', 'team-pay'];
  const scope: ConfigurationScope = { clusterId: uid(900), workspaceId: uid(901), transportScope: 'a'.repeat(64), kind: options.kind ?? 'workspace', rootIds: options.kind === 'services' ? [uid(1)] : [] };
  const stage = { jobId: uid(902), snapshotId: uid(903), versionId: uid(904), materialId: uid(905), leaseGeneration: 1 };
  const handle: any = Object.freeze({});
  const row = { id: scope.workspaceId, cluster_id: scope.clusterId, code: options.defaultWorkspace ? 'default' : 'team', name: 'scope',
    status: 'active', is_default: options.defaultWorkspace === true, revision: 1, deleted_at: null };
  const wsDb: any = { exec: vi.fn(async () => 1), one: vi.fn(async (sql: string, params: any[]) => {
    if (sql.includes("code='default'")) return options.defaultWorkspace ? row : { ...row, code: 'default', is_default: true, id: uid(920) };
    if (params[1] === 'foreign' || params[1] === uid(919)) return { ...row, code: 'foreign', id: uid(919) };
    return row;
  }) };
  const workspaces = new WorkspaceResolverService(wsDb);
  const data: Record<string, any[]> = {
    '/services': Array.from({ length: options.services ?? 1 }, (_, index) => ({ id: uid(index === 0 ? 1 : 1000 + index), name: `service-${index}`, host: 'shop-upstream', path: null, tags: [...tags], client_certificate: { id: uid(6) } })),
    '/routes': [{ id: uid(2), name: 'route', service: { id: uid(1) }, protocols: ['http', 'https'], paths: ['/shop'], tags: [...tags] }],
    '/consumers': [{ id: uid(3), username: 'consumer', custom_id: null, tags: [...tags] }],
    '/plugins': [{ id: uid(4), name: 'cors', enabled: true, service: { id: uid(1) }, route: { id: uid(2) }, consumer: { id: uid(3) },
      config: { flag: false, limit: 0, nullable: null, list: [] }, tags: [...tags] }],
    '/upstreams': [{ id: uid(5), name: 'shop-upstream', algorithm: 'round-robin', slots: 10, tags: [...tags], healthchecks: { active: { healthy: { interval: 0 }, unhealthy: { interval: 0 } } } }],
    '/certificates': [{ id: uid(6), cert: 'public-test-pem', key: 'private-test-key', tags: [...tags] }],
    '/ca_certificates': [{ id: uid(7), cert: 'public-ca-pem', tags: [...tags] }],
    '/snis': [{ id: uid(8), name: 'shop.example', certificate: { id: uid(6) }, tags: [...tags] }],
  };
  const active = { id: uid(9), target: 'upstream.example:80', weight: 100, upstream: { id: uid(5) }, tags: [...tags], created_at: 1700 };
  data[`/upstreams/${uid(5)}/targets/all`] = [{ ...active, id: uid(10), target: 'old.example:80', weight: 0 }, active];
  data[`/upstreams/${uid(5)}/targets`] = [active];
  for (const [index, kind] of Object.keys(CREDENTIAL_SCHEMAS).entries()) data[`/consumers/${uid(3)}/${kind}`] = [{ id: uid(20 + index), consumer: { id: uid(3) }, tags: [...tags],
    ...(kind === 'key-auth' ? { key: 'key-original' } : kind === 'basic-auth' ? { username: 'login', password: 'kong-basic-hash' }
      : kind === 'jwt' ? { key: 'jwt-name', secret: 'jwt-original', algorithm: 'HS256' }
      : kind === 'oauth2' ? { name: 'oauth-client', client_id: 'client', client_secret: 'oauth-original', redirect_uris: ['https://example.test/cb'] }
      : kind === 'hmac-auth' ? { username: 'hmac-login', secret: 'hmac-original' } : { group: 'allowed' }) }];
  const schemas: Record<string, any> = {
    services: shape({ name: string, host: { ...string, required: true }, path: string, client_certificate: foreign }),
    routes: shape({ name: string, service: foreign, protocols: { type: 'set', elements: string }, paths: { type: 'array', elements: string } }),
    consumers: shape({ username: string, custom_id: string }),
    plugins: shape({ name: string, enabled: { type: 'boolean' }, service: foreign, route: foreign, consumer: foreign, config: { type: 'record' } }),
    upstreams: shape({ name: string, algorithm: string, slots: { type: 'integer' }, healthchecks: { type: 'record' } }),
    certificates: shape({ cert: string, key: string }), ca_certificates: shape({ cert: string }), snis: shape({ name: string, certificate: foreign }),
    targets: shape({ target: string, weight: { type: 'integer' }, upstream: { ...foreign, required: true } }),
  };
  const credentialFields = { consumer: { ...foreign, required: true }, key: string, username: string, password: string, secret: string, algorithm: string,
    name: string, client_id: string, client_secret: string, redirect_uris: { type: 'array', elements: string }, group: string };
  for (const name of Object.values(CREDENTIAL_SCHEMAS)) schemas[name] = shape(credentialFields);
  const pluginSchema = { fields: [{ flag: { type: 'boolean' } }, { limit: { type: 'number' } }, { nullable: string }, { list: { type: 'array', elements: string } }] };
  const packets: { method: string; path: string; query?: any }[] = [];
  const meter = { calls: 0, pages: 0, records: 0, bytes: 0, startedAt: Date.now() };
  const remote = (value: any, page: boolean) => {
    meter.calls++; if (page) { meter.pages++; meter.records += value.length; }
    meter.bytes += Buffer.byteLength(JSON.stringify(value)); return structuredClone(value);
  };
  let globalDenied = false;
  const kong: any = {
    request: vi.fn(async (_cid: string, method: string, path: string) => {
      packets.push({ method, path }); if (method !== 'GET') throw new Error('Native writes forbidden in capture');
      if (path === '/') return remote({ version: '1.5.1', node_id: uid(990) }, false);
      if (path.startsWith('/schemas/')) return remote(schemas[path.slice(9)], false);
      if (path === '/plugins/schema/cors') return remote(pluginSchema, false);
      const parts = path.split('/').filter(Boolean);
      const value = data[`/${parts[0]}`]?.find(record => record.id === parts[1] || record.name === parts[1]);
      if (!value) { const error: any = new Error('not found'); error.getStatus = () => 404; throw error; }
      return remote(value, false);
    }),
    list: vi.fn(async (cid: string, path: string, query: any, cursor?: string, subject?: string) => {
      packets.push({ method: 'GET', path, query: { ...query } });
      const offset = cursor ? Number(readCursor(cursor, cid, path, query, subject)) : 0;
      // Real Kong 1.5: a global credential collection is the union of every Consumer's rows.
      const globalKind = ({ '/key-auths': 'key-auth', '/basic-auths': 'basic-auth', '/jwts': 'jwt', '/oauth2': 'oauth2', '/hmac-auths': 'hmac-auth', '/acls': 'acls' } as Record<string, string>)[path];
      if (globalKind && globalDenied) { const error = new ForbiddenException({ code: 'KONG_GLOBAL_CREDENTIAL_LIST_FORBIDDEN' }); throw error; }
      const entries = globalKind ? Object.entries(data).filter(([key]) => new RegExp(`^/consumers/[^/]+/${globalKind}$`).test(key)).flatMap(([, rows]) => rows) : data[path] ?? [];
      const selected = entries.filter(entry => !query.tags || entry.tags.includes(query.tags));
      const items = remote(selected.slice(offset, offset + 100), true);
      const nextCursor = offset + 100 < selected.length ? signCursor({ clusterId: cid, path, query, subject, offset: String(offset + 100) }) : null;
      return { items, nextCursor, size: 100 };
    }),
  };
  const known = new Map<string, any>();
  const credentialDb: any = { one: vi.fn(async (_sql: string, params: any[]) => known.get(params[3]) ?? null), exec: vi.fn(async (_sql: string, params: any[]) => { known.set(params[4], { payload_secret: params[5] }); return 1; }) };
  const credentials = new CredentialStoreService(credentialDb, secrets);
  known.set(uid(21), { payload_secret: secrets.encrypt({ credential: data[`/consumers/${uid(3)}/basic-auth`][0], rawInput: { password: 'basic-original' } }, `credential:${scope.clusterId}:${uid(3)}:basic-auth:${uid(21)}`) });
  const fence: any = { actorId: uid(906), permissionVersion: 'permission-1', credentialEpoch: 1, scope, expiresAt: Date.now() + 300000,
    captureEpoch: '1', clusterRevision: 1, workspaceRevision: 1, kongVersion: '1.5.1', nodeId: uid(990), adapterVersion: 'kong-1.5',
    enabledPlugins: ['cors', 'key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acl'], jobId: stage.jobId, leaseGeneration: 1 };
  const access: any = {
    runRead: vi.fn(async (actual: any, _paths: any, callback: any) => { if (actual !== handle) throw new ForbiddenException(); return callback(() => ({ ...meter })); }),
    assertCurrent: vi.fn(async () => structuredClone(fence)),
    resolveOwnership: vi.fn(async (_handle: any, input: any) => {
      const parent = input.parent?.payload ?? input.payload;
      const owner = await workspaces.classify(scope.clusterId, parent.tags);
      if (!owner.workspace) throw new ForbiddenException();
      return { workspaceId: owner.workspace.id, workspaceRevision: owner.workspace.revision, physicalTags: input.payload.tags ?? [], managedBoundary: 'none' };
    }),
    freezeRecovery: vi.fn(async (_handle: any, input: any) => {
      if (input.entityType === 'credentials') {
        try { return { state: 'complete', blockerCodes: [], restorePayload: await credentials.getRestorePayload(scope.clusterId, input.parentId, input.credentialKind, input.nativeId, input.payload),
          ...(input.credentialKind === 'basic-auth' ? { sourceHashHmac: secrets.fingerprint(input.payload.password) } : {}) }; }
        catch { return { state: 'requires_secret_input', blockerCodes: ['BASIC_AUTH_NOT_RECOVERABLE'] }; }
      }
      const payload = structuredClone(input.payload); delete payload.created_at; delete payload.updated_at;
      return { state: 'complete', blockerCodes: [], restorePayload: payload };
    }),
  };
  const encryptedPages: string[] = [], encryptedObjects: string[] = [];
  let graph: CaptureGraph | null = null;
  const repository: any = {
    stagePage: vi.fn(async (_handle: any, input: any) => { encryptedPages.push(secrets.encrypt(input, `page:${input.collectionKey}:${input.pageNo}`)); }),
    stageObject: vi.fn(async (_handle: any, input: any) => { encryptedObjects.push(secrets.encrypt(input.object, `object:${input.object.objectKey}`)); }),
    collectionEOF: vi.fn(async () => {}),
    sealSnapshot: vi.fn(async (_handle: any, input: any) => { graph = structuredClone(input.graph); return { id: stage.snapshotId, state: 'ready', currentVersion: 1 }; }),
  };
  const service = new ConfigurationCaptureService(kong, secrets, workspaces, access, repository);
  return { scope, stage, handle, data, schemas, pluginSchema, packets, meter, kong, known, credentials, fence, access, repository, encryptedPages, encryptedObjects,
    secrets, service, denyGlobal: () => { globalDenied = true; }, graph: () => graph!, run: () => service.capture(handle, stage, scope) };
}

describe('M8 bounded configuration capture', () => {
  beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ba'.repeat(32)); vi.stubEnv('CURSOR_SIGNING_KEY', 'cursor-only-source-fixture-key-32-chars'); });
  afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks(); });

  it('streams a real signed second page, eight cores, six nested credential EOFs, target history and all actual FKs', async () => {
    const f = fixture({ services: 101 }); await expect(f.run()).resolves.toMatchObject({ state: 'ready' });
    const graph = f.graph();
    expect(graph.objects.filter(node => node.entityType === 'services')).toHaveLength(101);
    expect(graph.objects.filter(node => node.entityType === 'credentials')).toHaveLength(6);
    expect(graph.collections.find(collection => collection.collectionKey === 'services')).toMatchObject({ pageCount: 2, recordCount: 101, terminalObserved: true });
    for (const kind of Object.keys(CREDENTIAL_SCHEMAS)) expect(graph.collections.find(collection => collection.collectionKey === `credentials:${kind}:${uid(3)}`)).toMatchObject({ pageCount: 1, recordCount: 1, terminalObserved: true });
    expect(graph.objects.find(node => node.entityType === 'plugins')?.dependencies).toEqual([`consumers:${uid(3)}`, `routes:${uid(2)}`, `services:${uid(1)}`]);
    expect(graph.objects.find(node => node.entityType === 'services')?.dependencies).toEqual([`certificates:${uid(6)}`, `upstreams:${uid(5)}`]);
    expect(graph.schemas.entities).toHaveProperty('basicauth_credentials'); expect(graph.schemas.plugins).toHaveProperty('cors');
    expect(graph.objects.every(node => node.schemaHmac === graph.schemaHmac)).toBe(true);
    for (const [, packet] of f.repository.stageObject.mock.calls) expect(packet.object.schemaHmac).toBe(graph.schemaHmac);
    expect(graph.nativeCallCount).toBe(f.meter.calls);
    expect(f.packets.every(packet => packet.method === 'GET')).toBe(true);
    expect(f.packets.filter(packet => packet.query).every(packet => packet.query.size === 100)).toBe(true);
    expect(f.repository.sealSnapshot).toHaveBeenCalledTimes(1);
  });

  it('freezes trustworthy Basic plaintext separately from its remote hash; page and object callbacks hold ciphertext', async () => {
    const f = fixture(); await f.run();
    const basic = f.graph().objects.find(node => node.credentialKind === 'basic-auth')!;
    expect(basic.payload.password).toBe('kong-basic-hash');
    expect(basic.recovery.restorePayload?.password).toBe('basic-original');
    expect(basic.secretCopies?.[0].restorePayload.password).toBe('basic-original');
    const wire = JSON.stringify([...f.encryptedObjects, ...f.encryptedPages]);
    for (const secret of ['basic-original', 'kong-basic-hash', 'key-original', 'private-test-key', 'oauth-original']) expect(wire).not.toContain(secret);
    await f.credentials.save(f.scope.clusterId, uid(3), 'basic-auth', { id: uid(21), password: 'new-hash' }, { password: 'new-plaintext' });
    expect(basic.recovery.restorePayload?.password).toBe('basic-original');
  });
  it('loads historically required absent plugin schemas inside the same genuine capture, then binds their actual definitions to the new graph and all objects',async()=>{
    const f=fixture(),original=f.kong.request.getMockImplementation()!;
    f.kong.request.mockImplementation(async(...args:any[])=>{if(args[2]==='/plugins/enabled'){f.packets.push({method:args[1],path:args[2]});f.meter.calls++;return{enabled_plugins:[...f.fence.enabledPlugins]};}if(args[2]==='/plugins/schema/key-auth'){f.packets.push({method:args[1],path:args[2]});f.meter.calls++;return structuredClone(f.pluginSchema);}return original(...args);});
    await f.service.capture(f.handle,f.stage,f.scope,{requiredPluginSchemas:['key-auth',...Array.from({length:201},()=> 'cors'),'key-auth']});const result=f.graph();
    expect(Object.keys(result.schemas.plugins).sort()).toEqual(['cors','key-auth']);expect(f.packets.filter(p=>p.path==='/plugins/schema/key-auth')).toHaveLength(1);expect(f.packets.filter(p=>p.path==='/plugins/schema/cors')).toHaveLength(1);expect(f.packets.filter(p=>p.path==='/plugins/enabled')).toHaveLength(2);
    const bundle={entities:result.schemas.entities,plugins:result.schemas.plugins,enabledPlugins:result.schemas.enabledPlugins,kongVersion:result.schemas.kongVersion,adapterVersion:result.schemas.adapterVersion};
    expect(result.schemaHmac).toBe(f.secrets.fingerprint(bundle));expect(result.objects.every(o=>o.schemaHmac===result.schemaHmac)).toBe(true);expect(result.nativeCallCount).toBe(f.meter.calls);expect(f.access.runRead).toHaveBeenCalledTimes(1);expect(f.access.runRead.mock.calls[0][0]).toBe(f.handle);expect(f.repository.sealSnapshot).toHaveBeenCalledOnce();
  });
  it.each(['unavailable','capability-change','schema-404','revoked','budget']as const)('cannot seal a required restore schema after %s and never borrows old schema material',async change=>{
    const f=fixture(),original=f.kong.request.getMockImplementation()!;if(change==='unavailable')f.fence.enabledPlugins=f.fence.enabledPlugins.filter((name:string)=>name!=='key-auth');if(change==='budget')f.meter.calls=499;
    f.kong.request.mockImplementation(async(...args:any[])=>{if(args[2]==='/plugins/enabled'){f.meter.calls++;return{enabled_plugins:change==='capability-change'?[]:[...f.fence.enabledPlugins]};}if(args[2]==='/plugins/schema/key-auth'){if(change==='schema-404')throw new Error('actual fixture GET404');if(change==='revoked')f.access.assertCurrent.mockRejectedValue(new ForbiddenException());f.meter.calls++;return structuredClone(f.pluginSchema);}return original(...args);});
    await expect(f.service.capture(f.handle,f.stage,f.scope,{requiredPluginSchemas:['key-auth']})).rejects.toThrow();expect(f.repository.sealSnapshot).not.toHaveBeenCalled();expect(f.access.runRead).toHaveBeenCalledTimes(1);
  });
  it.each([['../schemas/plugins/enterprise'],Array.from({length:201},(_,i)=> `p-${i}`)])('rejects unbounded unique names or non-fixed internal requirements %j before an actual request',async names=>{
    const f=fixture();await expect(f.service.capture(f.handle,f.stage,f.scope,{requiredPluginSchemas:names})).rejects.toMatchObject({response:{code:'CONFIGURATION_CAPTURE_SCHEMA_REQUIREMENTS_INVALID'}});expect(f.kong.request).not.toHaveBeenCalled();expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
  });

  it('records external Basic rotations as requires_secret_input and never promotes the hash to restore password', async () => {
    const f = fixture(); f.data[`/consumers/${uid(3)}/basic-auth`][0].password = 'out-of-band-hash'; await f.run();
    const basic = f.graph().objects.find(node => node.credentialKind === 'basic-auth')!;
    expect(basic.recovery.state).toBe('requires_secret_input'); expect(basic.recovery.restorePayload).toBeUndefined(); expect(basic.secretCopies).toBeUndefined();
    expect(f.graph().warningCodes).toContain('BASIC_AUTH_NOT_RECOVERABLE');
  });

  it('preserves Certificate Admin SNI observations without inventing a DAO schema field', async () => {
    const f = fixture(); f.data['/certificates'][0].snis = ['shop.example'];
    await f.run();
    expect(f.graph().objects.find(node => node.entityType === 'certificates')?.payload.snis).toEqual(['shop.example']);
    expect(f.graph().objects.find(node => node.entityType === 'snis')?.dependencies).toEqual([`certificates:${uid(6)}`]);
    expect(JSON.stringify(f.graph().schemas.entities.certificates)).not.toContain('snis');
  });

  it('allows the actual empty Certificate Admin SNI relation', async () => {
    const f = fixture(); f.data['/certificates'][0].snis = [];
    await expect(f.run()).resolves.toMatchObject({ state: 'ready' });
    expect(f.graph().objects.find(node => node.entityType === 'certificates')?.payload.snis).toEqual([]);
  });

  it.each([null, 'shop.example', [{}], ['shop.example', 'shop.example'], [''], ['x'.repeat(254)]])(
    'rejects malformed Certificate Admin SNI relation %j before publishing a snapshot', async names => {
      const f = fixture(); f.data['/certificates'][0].snis = names;
      await expect(f.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_SCHEMA_VALUE_MISMATCH' } });
      expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
    });

  it('does not accept Certificate Admin relations or other unknown fields on unrelated entities', async () => {
    const f = fixture(); f.data['/services'][0].snis = [];
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_SCHEMA_FIELD_MISMATCH' } });
    const certificate = fixture(); certificate.data['/certificates'][0].unrecognized = true;
    await expect(certificate.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_SCHEMA_FIELD_MISMATCH' } });
  });

  it('checks native TTL before existing restore stripping and reports nonrestorable with original TTL intact', async () => {
    const f = fixture(); f.data[`/consumers/${uid(3)}/key-auth`][0].ttl = 300; await f.run();
    const key = f.graph().objects.find(node => node.credentialKind === 'key-auth')!;
    expect(key.payload.ttl).toBe(300); expect(key.recovery.state).toBe('nonrestorable'); expect(key.recovery.blockerCodes).toContain('NATIVE_TTL_EXPIRY_UNKNOWN');
    expect(key.secretCopies).toBeUndefined();
    expect(f.access.freezeRecovery.mock.calls.some((call: any[]) => call[1].nativeId === key.nativeId)).toBe(false);
  });

  it('preserves null, false, zero, empty arrays and physical tags without defaults or logical tag conversion', async () => {
    const f = fixture(); await f.run();
    expect(f.graph().objects.find(node => node.entityType === 'plugins')?.payload.config).toEqual({ flag: false, limit: 0, nullable: null, list: [] });
    expect(f.graph().objects.find(node => node.entityType === 'services')?.payload.path).toBeNull();
    expect(f.graph().objects.find(node => node.entityType === 'consumers')?.ownershipTags).toEqual(['kos-ws-team', 'team-pay']);
  });

  it('observes real EOF for every empty collection, including all six children of an empty-credential Consumer', async () => {
    const f = fixture(); for (const kind of Object.keys(CREDENTIAL_SCHEMAS)) f.data[`/consumers/${uid(3)}/${kind}`] = [];
    await f.run(); const graph = f.graph();
    expect(graph.objects.filter(node => node.entityType === 'credentials')).toHaveLength(0);
    for (const kind of Object.keys(CREDENTIAL_SCHEMAS)) expect(graph.collections.find(collection => collection.collectionKey === `credentials:${kind}:${uid(3)}`)).toMatchObject({ pageCount: 1, recordCount: 0, terminalObserved: true });
  });

  it('uses default negative membership and keeps unrelated foreign objects out of encrypted page records', async () => {
    const f = fixture({ defaultWorkspace: true }); f.data['/services'].push({ id: uid(111), name: 'foreign-secret-name', host: 'external.example', tags: ['kos-ws-foreign'] });
    await f.run(); expect(f.graph().objects.some(node => node.nativeId === uid(111))).toBe(false);
    const pages = f.repository.stagePage.mock.calls.map((call: any[]) => call[1]);
    expect(pages.flatMap((page: any) => page.records).some((record: any) => record.id === uid(111))).toBe(false);
    expect(f.packets.find(packet => packet.path === '/services' && packet.query)?.query).toEqual({ size: 100 });
  });

  it('captures cross-workspace parents as read-authorized referenceOnly without expanding their descendants', async () => {
    const f = fixture(); f.data['/certificates'][0].tags = ['kos-ws-foreign']; f.data['/snis'] = [];
    await f.run(); const certificate = f.graph().objects.find(node => node.entityType === 'certificates')!;
    expect(certificate).toMatchObject({ referenceOnly: true, affected: false, objectWorkspaceId: uid(919) });
    expect(f.access.resolveOwnership.mock.calls.some((call: any[]) => call[1].nativeId === uid(6) && call[1].referenceOnly === true)).toBe(true);
    expect(f.graph().objects.find(node => node.entityType === 'services')?.dependencies).toContain(certificate.objectKey);
  });

  it('bounds a Service-root capture to selected services, routes, plugins and actual shared dependencies', async () => {
    const f = fixture({ kind: 'services', services: 2 }); await f.run();
    expect(f.graph().objects.filter(node => node.entityType === 'services').map(node => node.nativeId)).toEqual([uid(1)]);
    expect(f.graph().objects.some(node => node.nativeId === uid(1001))).toBe(false);
    expect(f.graph().objects.some(node => node.entityType === 'ca_certificates')).toBe(false);
  });

  it.each(['permissionVersion', 'captureEpoch', 'clusterRevision', 'workspaceRevision', 'credentialEpoch'])('fails before seal after %s changes during a native await', async field => {
    const f = fixture(); const original = f.kong.list.getMockImplementation()!;
    f.kong.list.mockImplementation(async (...args: any[]) => { const result = await original(...args); f.fence[field] = typeof f.fence[field] === 'number' ? f.fence[field] + 1 : `${f.fence[field]}-changed`; return result; });
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_CAPTURE_CHANGED' } });
    expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
  });

  it('stops at current access denial, preserving encrypted original first-page evidence without publishing', async () => {
    const f = fixture({ services: 101 }); const original = f.access.resolveOwnership.getMockImplementation()!;
    f.access.resolveOwnership.mockImplementation(async (...args: any[]) => { if (args[1].nativeId === uid(1100)) throw new ForbiddenException('revoked'); return original(...args); });
    await expect(f.run()).rejects.toBeInstanceOf(ForbiddenException);
    expect(f.repository.stagePage).toHaveBeenCalledTimes(1); expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
  });

  it('charges hidden authorization requests in the trusted Root meter and refuses 501 total calls', async () => {
    const f = fixture(); const original = f.access.resolveOwnership.getMockImplementation()!;
    f.access.resolveOwnership.mockImplementation(async (...args: any[]) => { const result = await original(...args); f.meter.calls = 501; return result; });
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_CAPTURE_LIMIT' } });
    expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
  });

  it('rejects forged handles before the first native packet', async () => {
    const f = fixture(); await expect(f.service.capture({} as any, f.stage, f.scope)).rejects.toBeInstanceOf(ForbiddenException);
    expect(f.kong.request).not.toHaveBeenCalled(); expect(f.kong.list).not.toHaveBeenCalled();
  });

  it.each(['duplicate', 'parent', 'projection', 'unknown-field', 'unknown-plugin'])('refuses %s Native data before publishing a complete snapshot', async corruption => {
    const f = fixture();
    if (corruption === 'duplicate') f.data['/routes'].push(structuredClone(f.data['/routes'][0]));
    if (corruption === 'parent') f.data[`/consumers/${uid(3)}/key-auth`][0].consumer.id = uid(777);
    if (corruption === 'projection') { const original = f.kong.list.getMockImplementation()!; f.kong.list.mockImplementation(async (...args: any[]) => ({ ...await original(...args), console_permission_projection: true })); }
    if (corruption === 'unknown-field') f.data['/services'][0].expression = 'http.path == "/"';
    if (corruption === 'unknown-plugin') f.data['/plugins'][0].name = 'unavailable-plugin';
    await expect(f.run()).rejects.toMatchObject({ status: 502 }); expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
  });

  it('compares underlying signed offsets rather than regenerated cursor timestamps to stop a pagination loop', async () => {
    const f = fixture({ services: 101 }); const original = f.kong.list.getMockImplementation()!; let generation = 0;
    f.kong.list.mockImplementation(async (cid: string, path: string, query: any, cursor: any, subject: any) => {
      const page = await original(cid, path, query, cursor, subject);
      if (path !== '/services') return page;
      const spy = vi.spyOn(Date, 'now').mockReturnValue(Date.now() + ++generation);
      const nextCursor = signCursor({ clusterId: cid, path, query, subject, offset: '100' }); spy.mockRestore();
      return { ...page, nextCursor };
    });
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_PAGINATION_LOOP' } });
    expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
  });

  it('rejects a target whose historical UUID still exists but effective record changes during capture', async () => {
    const f = fixture(); const original = f.kong.list.getMockImplementation()!; let count = 0;
    f.kong.list.mockImplementation(async (...args: any[]) => {
      const page = await original(...args);
      if (args[1] === `/upstreams/${uid(5)}/targets` && ++count === 2) page.items[0].weight = 50;
      return page;
    });
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_EFFECTIVE_TARGET_CHANGED' } });
    expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
  });

  it('rejects one credential UUID presented under two actual Consumer parents even when each nested FK matches its path', async () => {
    const f = fixture(); f.denyGlobal(); f.data['/consumers'].push({ id: uid(112), username: 'second', tags: ['kos-ws-team'] });
    f.data[`/consumers/${uid(112)}/key-auth`] = [{ ...f.data[`/consumers/${uid(3)}/key-auth`][0], consumer: { id: uid(112) } }];
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_NATIVE_PARENT_MISMATCH' } });
    expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
  });

  it('rejects one credential UUID presented twice in a global credential collection', async () => {
    const f = fixture(); f.data['/consumers'].push({ id: uid(112), username: 'second', tags: ['kos-ws-team'] });
    f.data[`/consumers/${uid(112)}/key-auth`] = [{ ...f.data[`/consumers/${uid(3)}/key-auth`][0], consumer: { id: uid(112) } }];
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_DUPLICATE_NATIVE_ID' } });
    expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
  });

  it('captures credentials of many Consumers through Kong 1.5 global paged collections within the page budget', async () => {
    const f = fixture(); const kinds = Object.keys(CREDENTIAL_SCHEMAS);
    for (let index = 0; index < 150; index++) {
      const id = uid(5000 + index); f.data['/consumers'].push({ id, username: `bulk-${index}`, custom_id: null, tags: ['kos-ws-team', 'team-pay'] });
      f.data[`/consumers/${id}/key-auth`] = [{ id: uid(7000 + index), consumer: { id }, tags: ['kos-ws-team', 'team-pay'], key: `bulk-key-${index}` }];
    }
    // Another workspace's Consumer credential is in the global list but must never be staged.
    f.data[`/consumers/${uid(9999)}/acls`] = [{ id: uid(9998), consumer: { id: uid(9999) }, tags: ['kos-ws-other'], group: 'foreign' }];
    await f.run(); const graph = f.graph(); const paths = f.packets.map(packet => packet.path);
    expect(paths.filter(path => /^\/consumers\/[^/]+\/(key-auth|basic-auth|jwt|oauth2|hmac-auth|acls)$/.test(path))).toEqual([]);
    for (const path of ['/key-auths', '/basic-auths', '/jwts', '/oauth2', '/hmac-auths', '/acls']) expect(paths).toContain(path);
    expect(graph.objects.filter(object => object.entityType === 'credentials')).toHaveLength(150 + kinds.length);
    expect(graph.objects.some(object => object.nativeId === uid(9998))).toBe(false);
    expect(graph.collections.filter(collection => collection.entityType === 'credentials').map(collection => [collection.collectionKey, collection.parentId ?? null]))
      .toEqual(kinds.map(kind => [`credentials:${kind}`, null]));
    expect(graph.requiredCollections).toEqual(expect.arrayContaining(kinds.map(kind => `credentials:${kind}`)));
    expect(graph.pageCount).toBeLessThanOrEqual(20);
  });

  it('falls back to per-Consumer credential collections when the global collection is denied', async () => {
    const f = fixture(); f.denyGlobal(); f.data['/consumers'].push({ id: uid(112), username: 'second', tags: ['kos-ws-team'] });
    await f.run(); const graph = f.graph();
    expect(graph.requiredCollections.some(key => /^credentials:[^:]+$/.test(key))).toBe(false);
    expect(graph.collections.filter(collection => collection.entityType === 'credentials' && collection.parentId === uid(112))).toHaveLength(6);
  });

  it('never publishes when the final actual Kong node or version changes', async () => {
    const f = fixture(); const original = f.kong.request.getMockImplementation()!; let count = 0;
    f.kong.request.mockImplementation(async (...args: any[]) => { const result = await original(...args); if (args[2] === '/' && ++count === 2) result.node_id = uid(991); return result; });
    await expect(f.run()).rejects.toMatchObject({ response: { code: 'CONFIGURATION_KONG_NODE_CHANGED' } }); expect(f.repository.sealSnapshot).not.toHaveBeenCalled();
  });

  it('returns the repository durable seal result rather than fabricating ready after a SQL failure', async () => {
    const f = fixture(); f.repository.sealSnapshot.mockRejectedValue(new Error('seal transaction rolled back'));
    await expect(f.run()).rejects.toThrow('seal transaction rolled back'); expect(f.graph()).toBeNull();
  });
});

describe('capture protocol limits independent of repositories', () => {
  it('reserves a whole fixed-size next page and does not shrink its signed size near the limit', () => {
    const meter = new CaptureBudget(); meter.records = 9901; expect(() => meter.request(true)).toThrow(); expect(meter.pages).toBe(0);
  });
  it('bounds 500 calls, 100 pages, 10000 objects, bytes and actual elapsed time before the next request', () => {
    for (const [field, max] of [['calls', 500], ['pages', 100], ['objects', 10000]] as const) {
      const meter = new CaptureBudget(); meter[field] = max; expect(() => field === 'objects' ? meter.object() : meter.request(field === 'pages')).toThrow();
    }
    const bytes = new CaptureBudget(); bytes.bytes = CAPTURE_LIMITS.bytes; expect(() => bytes.response('x')).toThrow();
    let now = 0; const time = new CaptureBudget(() => now); now = 120000; expect(() => time.request()).toThrow();
  });
  it('rejects prototype keys, excessive nesting, missing typed UUIDs and schema-invalid null/foreign shapes', () => {
    expect(() => captureJson(JSON.parse(`{"id":"${uid(1)}","__proto__":{"admin":true}}`))).toThrow();
    expect(() => captureJson({ id: 'service-name' })).toThrow();
    expect(() => validateCapturedSchema({ id: uid(1), host: null }, shape({ host: { type: 'string', required: true } }))).toThrow();
    expect(() => validateCapturedSchema({ id: uid(1), service: { id: uid(2), name: 'injected' } }, shape({ service: foreign }))).toThrow();
  });
});
