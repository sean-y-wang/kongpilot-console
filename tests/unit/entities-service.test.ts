import { executionFixture } from './execution-test-fixture';
import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from '../../apps/console-api/src/modules/entities/entities.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { validateKnownFields } from '../../apps/console-api/src/infrastructure/kong/schema';
import { readFileSync } from 'node:fs';
import { DEFAULT_WORKSPACE_ID, PAY_WORKSPACE_ID, workspaceTestResolver } from './workspace-test-helper';
import { credentialKind, entityType, identifier, pageSize } from '../../apps/console-api/src/modules/entities/entities.types';

const cid = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const actor = { user: { id: 'a35313a2-9968-4818-9f31-7b3066ce1728', username: 'admin', superAdmin: true }, requestId: 'm1-unit', idempotencyKey: 'm1-unit-operation' };

describe('M1 entity API authorization, paging, mutations and recovery delegation', () => {
  let kong: any, authz: any, mutations: any, recycle: any, credentials: any, audit: any, index: any;
  let service: EntityService;
  beforeEach(() => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
    kong = { request: vi.fn(), list: vi.fn(), schema: vi.fn(), pluginSchema: vi.fn() };
    authz = { assertNestedParentScope: vi.fn().mockResolvedValue(undefined), isPlatformAdmin: vi.fn().mockImplementation(async (u:any)=>!!u.superAdmin), assertCluster: vi.fn().mockResolvedValue(undefined), assertEntity: vi.fn().mockResolvedValue(undefined), assertSecretRead: vi.fn().mockResolvedValue(undefined), scopeTags: vi.fn().mockImplementation(async (_actor, _cid, _ws, tags) => tags), permissionVersion: vi.fn().mockResolvedValue('alice:permissions-v1'), filterEntities: vi.fn().mockImplementation(async (_actor, _cid, _type, items) => items) };
    mutations = { execute: vi.fn().mockImplementation(async (_context, fn) => fn()), completed: vi.fn().mockResolvedValue(null) };
    recycle = { archiveAndDelete: vi.fn().mockResolvedValue({ entryId: 'recycled', state: 'deleted' }) };
    credentials = { save: vi.fn().mockResolvedValue(undefined), get: vi.fn().mockResolvedValue(null) };
    audit = { append: vi.fn().mockResolvedValue(undefined) };
    index = { upsert: vi.fn().mockResolvedValue(undefined), search: vi.fn().mockResolvedValue({ items: [], nextCursor: null, size: 20, total: null, indexed: true, observed_at: 'now' }) };
    service = new EntityService(kong, authz, mutations, recycle, credentials, new SecretService(), audit, index, workspaceTestResolver(cid).resolver, executionFixture());
  });
  afterEach(() => vi.unstubAllEnvs());

  it('checks permission before any Kong read and never allows missing authorization to fall through', async () => {
    authz.assertCluster.mockRejectedValue(new ForbiddenException('denied'));
    await expect(service.list(cid, 'services', {}, actor)).rejects.toMatchObject({ status: 403 });
    expect(kong.list).not.toHaveBeenCalled();
    expect(kong.request).not.toHaveBeenCalled();
  });
  it('allows only the exact credential reveal without granting public Consumer configuration or sibling access', async () => {
    const childActor = { ...actor, user: { ...actor.user, superAdmin: false } };
    const parent = { id: 'c1', username: 'private-parent' };
    kong.request.mockImplementation(async (_cid: string, _method: string, path: string) => path === '/consumers/c1' ? parent : { id: path.endsWith('allowed-key') ? 'allowed-key' : 'sibling-key', key: 'authorized-child-value', consumer: { id: 'c1' } });
    authz.assertEntity.mockImplementation(async (_u: any, _cid: string, type: string, _action: string, entity: any) => { if (type === 'consumers' || entity.id !== 'allowed-key') throw new ForbiddenException(); });
    authz.assertNestedParentScope.mockImplementation(async (_u: any, _cid: string, type: string, actualParent: any, childType: string, _action: string, _wid: string, child: any) => { if (type !== 'consumers' || actualParent.id !== 'c1' || childType !== 'key-auth' || child?.id !== 'allowed-key') throw new ForbiddenException(); });
    authz.assertSecretRead.mockImplementation(async (_u: any, _cid: string, type: string, entity: any) => { if (type !== 'key-auth' || entity.id !== 'allowed-key') throw new ForbiddenException(); });
    await expect(service.getCredential(cid, 'c1', 'key-auth', 'allowed-key', { reveal: true }, childActor)).resolves.toMatchObject({ entity: { id: 'allowed-key', key: 'authorized-child-value' } });
    expect(authz.assertSecretRead.mock.calls.every((call: any[]) => call[2] === 'key-auth')).toBe(true);
    await expect(service.get(cid, 'consumers', 'c1', {}, childActor)).rejects.toMatchObject({ status: 403 });
    await expect(service.getCredential(cid, 'c1', 'key-auth', 'sibling-key', { reveal: true }, childActor)).rejects.toMatchObject({ status: 403 });
  });
  it('uses Kong cursor paging and does not forward BFF-only query parameters', async () => {
    kong.list.mockResolvedValue({ items: [{ id: 's1', tags: ['kos-ws-pay', 'kos-tag-dGVhbTpwYXk'], key: 'secret' }], nextCursor: 'signed-next', size: 20 });
    const result = await service.list(cid, 'services', { tags: 'team:pay', workspaceId: PAY_WORKSPACE_ID, cursor: 'cursor1' }, actor);
    expect(kong.list).toHaveBeenCalledWith(cid, '/services', { size: 20, tags: 'kos-tag-dGVhbTpwYXk,kos-ws-pay' }, 'cursor1', expect.stringContaining('alice:permissions-v1:'));
    expect(result.total).toBeNull();
    expect(result.items[0].tags).toEqual(['workspace:pay', 'team:pay']);
    expect(result.items[0].key).toMatch(/^\[REDACTED:/);
    expect(result.nextCursor).toBe('signed-next');
  });
  it('filters list permissions server-side and terminates at the scan budget', async () => {
    kong.list.mockResolvedValue({ items: [{ id: 'hidden' }], nextCursor: 'next', size: 20 });
    authz.filterEntities.mockResolvedValue([]);
    const result = await service.list(cid, 'services', {}, actor);
    expect(result.items).toEqual([]);
    expect(result.scan_budget_exhausted).toBe(true);
    expect(result.nextCursor).toBe('next');
    expect(kong.list).toHaveBeenCalledTimes(5);
  });
  it('delegates global search and sort to the realtime-validated background index', async () => {
    await service.list(cid, 'services', { search: 'pay', sort: 'name:desc', tags: 'team:pay', size: 10 }, actor);
    expect(index.search).toHaveBeenCalledWith(cid, 'services', expect.objectContaining({ search: 'pay', sort: 'name:desc', size: 10, tags: 'kos-tag-dGVhbTpwYXk' }), actor.user);
    expect(kong.list).not.toHaveBeenCalled();
  });
  it('encodes entity tags and persists writes through the central mutation service', async () => {
    kong.request.mockResolvedValue({ id: 'new', name: 'pay', host: 'example.com', tags: ['kos-ws-pay'] });
    const result = await service.create(cid, 'services', { name: 'pay', host: 'example.com', tags: ['workspace:pay'] }, { workspaceId: PAY_WORKSPACE_ID }, actor);
    expect(kong.request).toHaveBeenCalledWith(cid, 'POST', '/services', { name: 'pay', host: 'example.com', tags: ['kos-ws-pay'] });
    expect(mutations.execute).toHaveBeenCalledWith(expect.objectContaining({ clusterId: cid, action: 'create', actor: actor.user, idempotencyKey: actor.idempotencyKey }), expect.any(Function));
    expect(result.entity.tags).toEqual(['workspace:pay']);
    expect(result.propagation.state).toBe('pending');
    expect(index.upsert).toHaveBeenCalledWith(cid, 'services', expect.objectContaining({ id: 'new' }));
  });
  it('never turns an index-cache error into a false gateway write failure', async () => {
    kong.request.mockResolvedValue({ id: 'new', host: 'example.com' });
    index.upsert.mockRejectedValue(new Error('index unavailable'));
    await expect(service.create(cid, 'services', { host: 'example.com' }, {}, actor)).resolves.toMatchObject({ entity: { id: 'new' } });
  });
  it('requires confirmation and delegates every delete to durable recycle archiving', async () => {
    kong.request.mockResolvedValue({ id: 's1', name: 'pay' });
    await expect(service.delete(cid, 'services', 's1', { confirmed: true, confirm_name: 'wrong' }, actor)).rejects.toMatchObject({ status: 400 });
    expect(recycle.archiveAndDelete).not.toHaveBeenCalled();
    await service.delete(cid, 'services', 's1', { confirmed: true, confirm_name: 'pay' }, actor);
    expect(recycle.archiveAndDelete).toHaveBeenCalledWith(expect.objectContaining({ entityType: 'services', entityId: 's1', confirmName: 'pay' }), true);
    expect(kong.request.mock.calls.every((call: any[]) => call[1] !== 'DELETE')).toBe(true);
  });
  it('replays a successfully archived DELETE before reading the now-missing remote entity', async () => {
    const receipt = { entry_id: 'recycled', state: 'deleted' };
    mutations.completed.mockResolvedValue(receipt);
    const result = await service.delete(cid, 'services', 's1', { confirmed: true, confirm_name: 'pay' }, actor);
    expect(result).toEqual(receipt);
    expect(authz.assertCluster).toHaveBeenCalledWith(actor.user, cid, 'services', 'delete', DEFAULT_WORKSPACE_ID);
    expect(mutations.completed).toHaveBeenCalledWith(expect.objectContaining({ entityId: 's1', payload: { confirmed: true, confirm_name: 'pay', parentId: undefined, credentialKind: undefined } }));
    expect(kong.request).not.toHaveBeenCalled();
    expect(recycle.archiveAndDelete).not.toHaveBeenCalled();
  });
  it('canonicalizes an existing Consumer username before looking up a completed credential deletion', async () => {
    mutations.completed.mockResolvedValue({ entry_id: 'recycled', state: 'deleted' });
    kong.request.mockResolvedValue({ id: 'canonical-consumer', username: 'alice' });
    await service.deleteCredential(cid, 'alice', 'key-auth', 'key1', { confirmed: true, confirm_name: 'key1' }, actor);
    expect(mutations.completed).toHaveBeenCalledWith(expect.objectContaining({ parentId: 'canonical-consumer', credentialKind: 'key-auth', payload: expect.objectContaining({ parentId: 'canonical-consumer' }) }));
    expect(kong.request).toHaveBeenCalledTimes(1);
    expect(kong.request).toHaveBeenCalledWith(cid, 'GET', '/consumers/alice');
    expect(recycle.archiveAndDelete).not.toHaveBeenCalled();
  });
  it('preserves omitted nested plugin secrets while editing public configuration', async () => {
    const before = { id: 'p1', name: 'http-log', config: { http_endpoint: 'https://logs.example', secret: 'retained-secret', nested: { password: 'retained-password', public: 'old' } } };
    kong.request.mockImplementation(async (_cid: string, method: string, _path: string, body: any) => method === 'GET' ? before : { ...before, ...body });
    const result = await service.update(cid, 'plugins', 'p1', { config: { nested: { public: 'new' } } }, {}, actor);
    const write = kong.request.mock.calls.find((call: any[]) => call[1] === 'PATCH');
    expect(write[3].config).toEqual({ http_endpoint: 'https://logs.example', secret: 'retained-secret', nested: { password: 'retained-password', public: 'new' } });
    expect(JSON.stringify(result)).not.toContain('retained-secret');
    expect(JSON.stringify(result)).not.toContain('retained-password');
  });
  it('accepts only a matching redacted secret marker and rejects forged markers before writes', async () => {
    const secretService = new SecretService();
    const marker = secretService.redact({ secret: 'retained-secret' }).secret;
    kong.request.mockImplementation(async (_cid: string, method: string, _path: string, body: any) => method === 'GET' ? { id: 'p1', config: { secret: 'retained-secret' } } : { id: 'p1', ...body });
    await service.update(cid, 'plugins', 'p1', { config: { secret: marker } }, {}, actor);
    expect(kong.request.mock.calls.find((call: any[]) => call[1] === 'PATCH')[3].config.secret).toBe('retained-secret');
    mutations.execute.mockClear();
    await expect(service.update(cid, 'plugins', 'p1', { config: { secret: '[REDACTED:forged]' } }, {}, actor)).rejects.toMatchObject({ status: 400 });
    expect(mutations.execute).not.toHaveBeenCalled();
  });
  it('rejects ambiguous array edits containing omitted secrets instead of moving the secrets to another record', async () => {
    kong.request.mockResolvedValue({ id: 'p1', config: { records: [{ password: 'secret', public: 'old' }] } });
    await expect(service.update(cid, 'plugins', 'p1', { config: { records: [{ public: 'new' }] } }, {}, actor)).rejects.toMatchObject({ status: 400 });
    expect(mutations.execute).not.toHaveBeenCalled();
  });
  it('preserves hidden Route Authorization matches when a path and public header are edited, while replacing public header entries', async () => {
    const before = { id: 'r1', paths: ['/old'], headers: { Authorization: ['Bearer retained-routing-condition'], 'X-Public': ['old'], 'X-Remove': ['old'] } };
    kong.request.mockImplementation(async (_cid: string, method: string, _path: string, body: any) => method === 'GET' ? before : { ...before, ...body });
    const result = await service.update(cid, 'routes', 'r1', { paths: ['/new'], headers: { 'X-Public': ['new'] } }, {}, actor);
    const write = kong.request.mock.calls.find((call: any[]) => call[1] === 'PATCH');
    expect(write[3]).toEqual({ paths: ['/new'], headers: { Authorization: ['Bearer retained-routing-condition'], 'X-Public': ['new'] } });
    expect(write[3].headers).not.toHaveProperty('X-Remove');
    expect(authz.assertSecretRead).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain('retained-routing-condition');
  });
  it('treats an empty Route header map as public-entry replacement without implicitly clearing concealed matches', async () => {
    const before = { id: 'r1', headers: { Authorization: ['hidden'], 'X-Public': ['remove'] } };
    kong.request.mockImplementation(async (_cid: string, method: string, _path: string, body: any) => method === 'GET' ? before : { ...before, ...body });
    await service.update(cid, 'routes', 'r1', { headers: {} }, {}, actor);
    expect(kong.request.mock.calls.find((call: any[]) => call[1] === 'PATCH')[3].headers).toEqual({ Authorization: ['hidden'] });
    expect(authz.assertSecretRead).not.toHaveBeenCalled();
  });
  it('requires secret-read permission scoped to the actual Route for explicit full clear or sensitive-entry clear', async () => {
    const before = { id: 'r1', tags: ['team-pay'], headers: { Authorization: ['hidden'] } };
    kong.request.mockResolvedValue(before);
    authz.assertSecretRead.mockRejectedValue(new ForbiddenException('no scoped secret permission'));
    await expect(service.update(cid, 'routes', 'r1', { headers: null }, {}, actor)).rejects.toMatchObject({ status: 403 });
    expect(authz.assertSecretRead).toHaveBeenCalledWith(actor.user, cid, 'routes', before, DEFAULT_WORKSPACE_ID);
    expect(mutations.execute).not.toHaveBeenCalled();
    await expect(service.update(cid, 'routes', 'r1', { headers: { Authorization: [] } }, {}, actor)).rejects.toMatchObject({ status: 403 });
    expect(mutations.execute).not.toHaveBeenCalled();
    authz.assertSecretRead.mockResolvedValue(undefined);
    await service.update(cid, 'routes', 'r1', { headers: null }, {}, actor);
    expect(kong.request.mock.calls.find((call: any[]) => call[1] === 'PATCH')[3].headers).toBeNull();
  });
  it('restores only an exact Route field-bound marker and rejects a foreign marker before any mutation', async () => {
    const secrets = new SecretService(), before = { id: 'r1', headers: { Authorization: ['hidden'] } };
    kong.request.mockImplementation(async (_cid: string, method: string, _path: string, body: any) => method === 'GET' ? before : { ...before, ...body });
    const valid = secrets.redact(before.headers).Authorization;
    await service.update(cid, 'routes', 'r1', { headers: { authorization: valid } }, {}, actor);
    expect(kong.request.mock.calls.find((call: any[]) => call[1] === 'PATCH')[3].headers).toEqual({ authorization: ['hidden'] });
    mutations.execute.mockClear();
    const foreign = secrets.redact({ Authorization: ['foreign-value'] }).Authorization;
    await expect(service.update(cid, 'routes', 'r1', { headers: { Authorization: foreign } }, {}, actor)).rejects.toMatchObject({ status: 400, response: { code: 'INVALID_SECRET_MARKER' } });
    expect(mutations.execute).not.toHaveBeenCalled();
  });
  it('rejects filtered or reordered mixed sensitive arrays, but verifies stable bound markers when public entries change', async () => {
    const secrets = new SecretService(), before = { id: 'r1', headers: { 'X-Match': ['public', 'Bearer hidden-value'] } };
    kong.request.mockImplementation(async (_cid: string, method: string, _path: string, body: any) => method === 'GET' ? before : { ...before, ...body });
    const bound = secrets.redact(before.headers)['X-Match'][1];
    await service.update(cid, 'routes', 'r1', { headers: { 'X-Match': ['updated', bound] } }, {}, actor);
    expect(kong.request.mock.calls.find((call: any[]) => call[1] === 'PATCH')[3].headers['X-Match']).toEqual(['updated', 'Bearer hidden-value']);
    mutations.execute.mockClear();
    await expect(service.update(cid, 'routes', 'r1', { headers: { 'X-Match': ['updated'] } }, {}, actor)).rejects.toMatchObject({ status: 400, response: { code: 'SECRET_ARRAY_AMBIGUOUS' } });
    await expect(service.update(cid, 'routes', 'r1', { headers: { 'X-Match': [bound, 'updated'] } }, {}, actor)).rejects.toMatchObject({ status: 400, response: { code: 'SECRET_ARRAY_AMBIGUOUS' } });
    expect(mutations.execute).not.toHaveBeenCalled();
  });
  it('keeps public-only map replacement semantics and rejects duplicate header names differing only by case', async () => {
    const before = { id: 'r1', headers: { 'X-Remove': ['old'] } };
    kong.request.mockImplementation(async (_cid: string, method: string, _path: string, body: any) => method === 'GET' ? before : { ...before, ...body });
    await service.update(cid, 'routes', 'r1', { headers: { 'X-New': ['new'] } }, {}, actor);
    expect(kong.request.mock.calls.find((call: any[]) => call[1] === 'PATCH')[3].headers).toEqual({ 'X-New': ['new'] });
    expect(authz.assertSecretRead).not.toHaveBeenCalled();
    mutations.execute.mockClear();
    await expect(service.update(cid, 'routes', 'r1', { headers: { Authorization: ['a'], authorization: ['b'] } }, {}, actor)).rejects.toMatchObject({ status: 400, response: { code: 'AMBIGUOUS_HEADER_NAME' } });
    expect(mutations.execute).not.toHaveBeenCalled();
  });
  it('protects omitted secret-bearing nested record branches without introducing unsupported Kong 1.5 health-check headers', async () => {
    const original = { active: { http_path: '/old', headers: { Authorization: ['secret'] } }, passive: { unhealthy: { tcp_failures: 5 } } };
    // Future-compatible generic helper unit only: this is deliberately not a real
    // Kong 1.5 Upstream fixture or a claim that active.headers is supported.
    const result = await (service as any).preserveHiddenNative(cid, 'upstreams', { id: 'u1' }, original, { active: { http_path: '/new' } }, actor, 'healthchecks');
    expect(result).toEqual({ active: { http_path: '/new', headers: { Authorization: ['secret'] } } });
    const actual15 = JSON.parse(readFileSync(new URL('../fixtures/kong-1.5.1/schema-upstreams.json', import.meta.url), 'utf8'));
    expect(() => validateKnownFields({ healthchecks: { active: { headers: { Authorization: ['secret'] } } } }, actual15)).toThrow();
  });
  it('authorizes referenced parent objects before creating a Route', async () => {
    kong.request.mockImplementation(async (_cid: string, method: string, path: string) => method === 'GET' ? { id: 's1', name: 'service' } : { id: 'r1' });
    await service.create(cid, 'routes', { paths: ['/pay'], service: { id: 's1' } }, {}, actor);
    expect(authz.assertEntity).toHaveBeenCalledWith(actor.user, cid, 'services', 'read', expect.objectContaining({ id: 's1' }), DEFAULT_WORKSPACE_ID);
    expect(kong.request.mock.calls[0][1]).toBe('GET');
  });
  it('retrieves relation pages with the parent bound into the signed cursor subject', async () => {
    kong.request.mockResolvedValue({ id: 's1', name: 'service' });
    kong.list.mockResolvedValue({ items: [{ id: 'r1' }], nextCursor: 'next', size: 10 });
    await service.relation(cid, 'services', 's1', 'routes', { size: 10 }, actor);
    expect(kong.list).toHaveBeenCalledWith(cid, '/services/s1/routes', { size: 10 }, undefined, expect.stringContaining(':relation:services:s1:routes'));
  });
  it('updates Target weights by POSTing a new history row and records old/effective IDs', async () => {
    kong.request.mockImplementation(async (_cid: string, method: string, path: string, body: any) => method === 'POST' ? { id: 'new-target', ...body } : path === '/upstreams/u1' ? { id: 'u1' } : { id: 'old-target', target: 'echo:8081', weight: 100, upstream: { id: 'u1' } });
    const result = await service.updateTarget(cid, 'u1', 'old-target', { weight: 20 }, actor);
    expect(kong.request).toHaveBeenCalledWith(cid, 'POST', '/upstreams/u1/targets', expect.objectContaining({ target: 'echo:8081', weight: 20 }));
    expect(result.original_id).toBe('old-target'); expect(result.effective_id).toBe('new-target');
    expect(kong.request.mock.calls.some((call: any[]) => call[1] === 'PATCH')).toBe(false);
  });
  it('rejects cross-Consumer credential IDs before revealing their material', async () => {
    kong.request.mockImplementation(async (_cid: string, _method: string, path: string) => path === '/consumers/c1' ? { id: 'c1' } : { id: 'key1', key: 'secret', consumer: { id: 'another' } });
    await expect(service.getCredential(cid, 'c1', 'key-auth', 'key1', { reveal: true }, actor)).rejects.toMatchObject({ status: 404 });
    expect(audit.append).not.toHaveBeenCalled();
  });
  it('remembers original Basic password before API hashing and only reveals under a separate secret permission', async () => {
    kong.request.mockImplementation(async (_cid: string, method: string) => method === 'GET' ? { id: 'c1' } : { id: 'b1', username: 'alice', password: 'kong-password-hash', consumer: { id: 'c1' } });
    const result = await service.createCredential(cid, 'c1', 'basic-auth', { username: 'alice', password: 'original-password' }, { reveal: true }, actor);
    expect(credentials.save).toHaveBeenCalledWith(cid, 'c1', 'basic-auth', expect.objectContaining({ password: 'kong-password-hash' }), { username: 'alice', password: 'original-password', tags: ['kos-ws-default'] });
    expect(result.entity.password).toBe('original-password');
    expect(authz.assertSecretRead).toHaveBeenCalledWith(actor.user, cid, 'basic-auth', expect.objectContaining({ id: 'b1' }), DEFAULT_WORKSPACE_ID);
    expect(authz.assertSecretRead.mock.calls.every((call:any[])=>call[2]!=='consumers')).toBe(true);
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'reveal_secret' }));
  });
  it('does not reveal stale Basic plaintext after an external password change', async () => {
    kong.request.mockImplementation(async (_cid: string, _method: string, path: string) => path === '/consumers/c1' ? { id: 'c1' } : { id: 'b1', password: 'external-new-hash', consumer: { id: 'c1' } });
    credentials.get.mockResolvedValue({ credential: { password: 'old-hash' }, rawInput: { password: 'old-password' } });
    const result = await service.getCredential(cid, 'c1', 'basic-auth', 'b1', { reveal: true }, actor);
    expect(result.entity.password).toBeNull();
    expect(result.entity.recovery_capability).toBe('requires-secret-input');
  });
  it('reveals trusted Basic plaintext only while its stored hash matches the current Kong hash', async () => {
    kong.request.mockImplementation(async (_cid: string, _method: string, path: string) => path === '/consumers/c1' ? { id: 'c1' } : { id: 'b1', password: 'current-hash', consumer: { id: 'c1' } });
    credentials.get.mockResolvedValue({ credential: { password: 'current-hash' }, rawInput: { password: 'original-password' } });
    const result = await service.getCredential(cid, 'c1', 'basic-auth', 'b1', { reveal: true }, actor);
    expect(result.entity.id).toBe('b1');
    expect(result.entity.password).toBe('original-password');
    expect(result.entity).not.toHaveProperty('rawInput');
  });
  it('rejects unknown resource kinds, unsafe IDs and invalid page sizes', () => {
    expect(() => entityType('vaults')).toThrow();
    expect(() => credentialKind('keys')).toThrow();
    for (const value of ['../services', '%2e%2e', '..', 'id\\suffix', 'id\u0000']) expect(() => identifier(value)).toThrow();
    for (const value of [0, 101, 1.5, 'invalid']) expect(() => pageSize(value)).toThrow();
    expect(identifier('node.example:8081')).toBe('node.example%3A8081');
  });
});
