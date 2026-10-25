// Isolated synthetic transport/storage fixture; the production capture runner and crypto are real.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { ConfigurationCaptureService } from '../../../apps/console-api/src/modules/config-capture/configuration-capture.service';
import { CaptureBudget, CAPTURE_LIMITS, captureJson, validateCapturedSchema } from '../../../apps/console-api/src/modules/config-capture/capture-validation';
import { SecretService } from '../../../apps/console-api/src/infrastructure/secret.service';
import { signCursor, readCursor } from '../../../apps/console-api/src/infrastructure/kong/cursor';
import { CredentialStoreService } from '../../../apps/console-api/src/modules/credentials/credential-store.service';
import { WorkspaceResolverService } from '../../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
import { CREDENTIAL_SCHEMAS } from '../../../apps/console-api/src/modules/entities/entities.types';
import type { CaptureGraph, CaptureObject, ConfigurationScope } from '../../../apps/console-api/src/modules/configuration/configuration.types';

const uid = (value: number) => `00000000-0000-4000-8000-${String(value).padStart(12, '0')}`;
const shape = (extra: Record<string, any> = {}) => ({ fields: [{ id: { type: 'string', required: true } }, { tags: { type: 'set', elements: { type: 'string' } } },
  ...Object.entries(extra).map(([name, definition]) => ({ [name]: definition }))] });
const foreign = { type: 'foreign' }, string = { type: 'string' };

export function configurationCaptureFixture(options: { kind?: ConfigurationScope['kind']; defaultWorkspace?: boolean; services?: number } = {}) {
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
    '/plugins': [{ id: uid(4), name: 'cors', enabled: true, service: { id: uid(1) }, route: { id: uid(2) }, consumer: null,
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
    plugins: shape({ name: string, enabled: { type: 'boolean' }, service: foreign, route: foreign, consumer: foreign, config: { type: 'record', abstract:true } }),
    upstreams: shape({ name: string, algorithm: string, slots: { type: 'integer' }, healthchecks: {"type":"record","fields":[{"active":{"type":"record","fields":[{"healthy":{"type":"record","fields":[{"interval":{"type":"integer"}}]}},{"unhealthy":{"type":"record","fields":[{"interval":{"type":"integer"}}]}}]}}]} }),
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
  const kong: any = {
    request: vi.fn(async (_cid: string, method: string, path: string) => {
      packets.push({ method, path }); if (method !== 'GET') throw new Error('Native writes forbidden in capture');
      if (path === '/plugins/enabled') return remote({enabled_plugins:['cors','key-auth','basic-auth','jwt','oauth2','hmac-auth','acl']}, false);
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
      const entries = data[path] ?? [];
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
    secrets, service, graph: () => graph!, run: () => service.capture(handle, stage, scope) };
}

