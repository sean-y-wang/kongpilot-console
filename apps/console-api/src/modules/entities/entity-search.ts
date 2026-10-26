/**
 * Multi-dimension fuzzy search for entity lists (case-insensitive substring).
 * The SQL predicate (over the redacted index document) and the in-memory
 * predicate (over the live Kong object) must stay equivalent: the index narrows
 * candidates, the live re-check guarantees results are current.
 *
 * - services: name, id, port, host (host is also the upstream name when a
 *   service points at an upstream)
 * - routes:   name, id, any element of hosts[], any element of paths[]
 * - others:   name / username / custom_id, id
 */
export const ENTITY_SEARCH_DIMENSIONS: Record<string, string[]> = {
  services: ['name', 'id', 'port', 'host'],
  routes: ['hosts', 'paths', 'name', 'id'],
};

const text = (v: unknown) => (v === null || v === undefined ? '' : String(v));
const list = (v: unknown) => (Array.isArray(v) ? v.map(text) : []);

export function entitySearchValues(entityType: string, entity: any): string[] {
  const base = [text(entity?.name ?? entity?.username ?? entity?.custom_id ?? entity?.id), text(entity?.id)];
  if (entityType === 'services') return [...base, text(entity?.port), text(entity?.host)];
  if (entityType === 'routes') return [...base, ...list(entity?.hosts), ...list(entity?.paths)];
  return base;
}

export function entityMatchesSearch(entityType: string, entity: any, search: string): boolean {
  const needle = search.trim().toLowerCase();
  if (!needle) return true;
  return entitySearchValues(entityType, entity).some(v => v.toLowerCase().includes(needle));
}

/** SQL predicate; `p` is the placeholder holding the trimmed search string. */
export function entitySearchSql(entityType: string, p: string): string {
  const has = (expr: string) => `position(lower(${p}) in lower(${expr}))>0`;
  const any = (field: string) => `EXISTS (SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(document->'${field}')='array' THEN document->'${field}' ELSE '[]'::jsonb END) AS e(v) WHERE ${has('e.v')})`;
  const parts = [has('name'), has('kong_id')];
  if (entityType === 'services') parts.push(has(`coalesce(document->>'port','')`), has(`coalesce(document->>'host','')`));
  if (entityType === 'routes') parts.push(any('hosts'), any('paths'));
  return `(${p}='' OR ${parts.join(' OR ')})`;
}
