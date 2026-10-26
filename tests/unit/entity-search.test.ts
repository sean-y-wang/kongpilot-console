import 'reflect-metadata';
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { entityMatchesSearch, entitySearchSql, entitySearchValues } from '../../apps/console-api/src/modules/entities/entity-search';
import { EntityIndexService } from '../../apps/console-api/src/modules/entities/entity-index.service';
import { executionFixture } from './execution-test-fixture';
import { entitySearchPlaceholder } from '../../apps/console-web/src/features/EntitiesPage';

const service = { id: '9F2C1A00-aaaa-bbbb-cccc-000000000001', name: 'Order-API', host: 'order-upstream.internal', port: 8443 };
const route = { id: '11111111-2222-3333-4444-555555555555', name: null, hosts: ['Dev.IflyAICloud.com', 'api.example.cn'], paths: ['/api/V1/ocr', '/healthz'] };

describe('entity multi-dimension fuzzy search predicate', () => {
  it('matches services by name, id, port and upstream host, case-insensitive substring', () => {
    for (const q of ['order-a', 'ORDER-API', '9f2c1a', '844', '8443', 'upstream.INTERNAL', 'order-upstream']) expect(entityMatchesSearch('services', service, q)).toBe(true);
    for (const q of ['8080', 'payment', '/api']) expect(entityMatchesSearch('services', service, q)).toBe(false);
  });
  it('matches routes by any host, any path, name and id', () => {
    for (const q of ['iflyaicloud', 'API.EXAMPLE', '/api/v1', 'OCR', 'healthz', '22223333'.slice(0, 4), '11111111-2222']) expect(entityMatchesSearch('routes', route, q)).toBe(true);
    expect(entityMatchesSearch('routes', { ...route, name: 'ocr-route' }, 'ocr-ro')).toBe(true);
    for (const q of ['xfyun', '/v2/tts']) expect(entityMatchesSearch('routes', route, q)).toBe(false);
  });
  it('tolerates Kong 1.3 shapes: null/missing arrays and missing port', () => {
    expect(entityMatchesSearch('routes', { id: 'r1', hosts: null, paths: undefined }, 'r1')).toBe(true);
    expect(entityMatchesSearch('routes', { id: 'r1', hosts: null }, 'host')).toBe(false);
    expect(entitySearchValues('services', { id: 's1', name: 'x' })).toEqual(['x', 's1', '', '']);
    expect(entityMatchesSearch('services', service, '   ')).toBe(true);
  });
  it('keeps other entity types to name/id only', () => {
    expect(entityMatchesSearch('consumers', { id: 'c1', username: 'Alice', host: 'h' }, 'alice')).toBe(true);
    expect(entityMatchesSearch('consumers', { id: 'c1', username: 'Alice', host: 'zzz' }, 'zzz')).toBe(false);
  });
  it('emits a parameterized SQL predicate covering the same dimensions', () => {
    const s = entitySearchSql('services', '$3'), r = entitySearchSql('routes', '$3'), c = entitySearchSql('consumers', '$3');
    expect(s).toContain("document->>'port'"); expect(s).toContain("document->>'host'"); expect(s).not.toContain('hosts');
    expect(r).toContain("document->'hosts'"); expect(r).toContain("document->'paths'"); expect(r).toContain("jsonb_typeof(document->'hosts')='array'");
    expect(c).not.toContain('document'); for (const sql of [s, r, c]) { expect(sql.startsWith("($3='' OR")).toBe(true); expect(sql).toContain('lower(kong_id)'); }
  });
  it('lists the dimensions in the console placeholder', () => {
    expect(entitySearchPlaceholder('services')).toBe('搜索名称 / ID / 端口 / 上游主机');
    expect(entitySearchPlaceholder('routes')).toBe('搜索 Host / Path / 名称 / ID');
    expect(entitySearchPlaceholder('plugins')).toBe('搜索名称或 ID');
  });
});

describe('index search uses the multi-dimension predicate end to end', () => {
  const cid = '7476b4b8-e8ae-4b29-89be-fd1eeb3f388c', actor = { id: 'actor', username: 'test', superAdmin: false };
  let db: any, kong: any, index: EntityIndexService;
  beforeEach(() => {
    vi.stubEnv('APP_SECRET', 'test-index-signature-key-at-least-32-characters');
    db = { query: vi.fn(), one: vi.fn().mockResolvedValue({ completed_at: '2026-01-01' }), exec: vi.fn().mockResolvedValue(1) };
    kong = { request: vi.fn() };
    const authz = { assertCluster: vi.fn(), scopeTags: vi.fn(), permissionVersion: vi.fn().mockResolvedValue('v1'), filterEntities: vi.fn().mockImplementation(async (_a: any, _c: any, _t: any, rows: any) => rows) };
    const workspaces = { resolve: vi.fn().mockResolvedValue({ id: 'w', revision: 1 }), listScope: vi.fn().mockResolvedValue({ workspaceId: 'w', mode: 'default', workspaceTag: 'kos-ws-default', requestedTags: [], tagOperator: 'and', binding: 'w:1:' }), matches: vi.fn().mockReturnValue(true) };
    index = new EntityIndexService(db, { withLock: vi.fn() } as any, { redact: (v: any) => v } as any, kong, authz as any, workspaces as any, executionFixture());
  });
  afterEach(() => vi.unstubAllEnvs());
  it('returns routes matched by host and services matched by port after the live re-check', async () => {
    db.query.mockResolvedValue([{ kong_id: route.id, name: route.id }]); kong.request.mockResolvedValue(route);
    const r = await index.search(cid, 'routes', { search: ' IflyAI ', size: 20 }, actor);
    expect(r.items).toHaveLength(1); expect(db.query.mock.calls[0][0]).toContain("document->'hosts'"); expect(db.query.mock.calls[0][1][2]).toBe('IflyAI');
    db.query.mockResolvedValue([{ kong_id: service.id, name: service.name }]); kong.request.mockResolvedValue(service);
    expect((await index.search(cid, 'services', { search: '8443', size: 20 }, actor)).items).toHaveLength(1);
  });
  it('drops index candidates whose live object no longer matches (e.g. path changed)', async () => {
    db.query.mockResolvedValue([{ kong_id: route.id, name: route.id }]); kong.request.mockResolvedValue({ ...route, paths: ['/other'] });
    expect((await index.search(cid, 'routes', { search: '/api/v1', size: 20 }, actor)).items).toEqual([]);
  });
});
