import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { kongCapabilities, stripUnsupportedFields } from '../../apps/console-api/src/infrastructure/kong/kong-capabilities';
import { validateKnownFields } from '../../apps/console-api/src/infrastructure/kong/schema';

const dir = (v: string) => fileURLToPath(new URL(`../fixtures/kong-${v}/`, import.meta.url));
const load = (v: string, f: string) => JSON.parse(readFileSync(`${dir(v)}${f}`, 'utf8'));
const names = (schema: any): Set<string> => new Set(schema.fields.map((f: any) => Object.keys(f)[0]));

// Offline checks against responses recorded from a throwaway kong:1.3.0 (DB-less) container.
describe('recorded Kong OSS 1.3.0 wire contracts', () => {
  const manifest = load('1.3.0', 'manifest.json');
  it('is traceable to a real 1.3.0 image and complete', () => {
    expect(manifest.version).toBe('1.3.0');
    expect(load('1.3.0', 'root.json').version).toBe('1.3.0');
    for (const r of manifest.recorded) expect(r.source).toBe('real Kong OSS 1.3.0 Docker image');
    expect(readdirSync(dir('1.3.0')).filter(n => n.endsWith('.json')).sort()).toEqual(['manifest.json', ...manifest.recorded.map((r: any) => r.filename)].sort());
  });
  it('lacks exactly the entity fields the capability table declares unsupported', () => {
    const caps = kongCapabilities('1.3.0');
    for (const entity of ['services', 'routes', 'consumers', 'plugins', 'certificates', 'ca_certificates', 'snis', 'upstreams']) {
      const old = names(load('1.3.0', `schema-${entity}.json`)), cur = names(load('1.5.1', `schema-${entity}.json`));
      const missing = [...cur].filter(n => !old.has(n)).sort();
      expect(missing).toEqual([...(caps.unsupportedFields[entity] ?? [])].sort());
    }
  });
  it('accepts 1.5-shaped writes after stripping unsupported fields', () => {
    const routes = load('1.3.0', 'schema-routes.json');
    const body = stripUnsupportedFields('routes', { name: 'r', paths: ['/a'], path_handling: 'v1' }, '1.3.0');
    expect(() => validateKnownFields(body, routes)).not.toThrow();
    expect(() => validateKnownFields({ name: 'r', path_handling: 'v1' }, routes)).toThrow();
    const ups = load('1.3.0', 'schema-upstreams.json');
    expect(() => validateKnownFields(stripUnsupportedFields('upstreams', { name: 'u', host_header: 'x' }, '1.3.0'), ups)).not.toThrow();
    expect(() => validateKnownFields({ name: 'u', host_header: 'x' }, ups)).toThrow();
  });
  it('keeps the same paginated list envelope as 1.5.1', () => {
    for (const entity of ['services', 'routes', 'consumers', 'plugins', 'upstreams']) {
      const body = load('1.3.0', `list-${entity}-empty.json`);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body).toHaveProperty('next');
    }
  });
});
