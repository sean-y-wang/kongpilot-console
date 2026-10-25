const forbidden = new Set(['__proto__', 'constructor', 'prototype']);
const secret = (name: string) => /^(?:password|passwd|secret|token|authorization|apikey|accesskey|awskey|provisionkey|clientsecret|privatekey|refreshtoken|accesstoken|apikey|awsaccesskeyid|signingkey)$/i.test(name.replace(/[-_ ]/g, ''));
export function safeMarkdownUrl(value: string, image = false): string | undefined {
  if (!value || /[\u0000-\u0020\u007f\\]/.test(value) || value.startsWith('//')) return undefined;
  if (image) return /^\/assets\/[a-zA-Z0-9/_-]+\.(?:png|jpe?g|webp|gif)$/i.test(value) && !value.includes('..') ? value : undefined;
  if (/^\/(?:apis|pages)(?:\/[a-zA-Z0-9_-]+)?(?:#[a-zA-Z0-9_-]*)?$/.test(value) || /^#[a-zA-Z0-9_-]*$/.test(value)) return value;
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : undefined; } catch { return undefined; }
}
export function sanitizeOpenApi(input: unknown): Record<string, any> {
  let bytes = 0; try { bytes = new TextEncoder().encode(JSON.stringify(input)).length; } catch { throw new Error('文档含循环数据结构，无法安全阅读。'); }
  if (bytes > 3 * 1024 * 1024 || !input || typeof input !== 'object' || Array.isArray(input)) throw new Error('文档格式或大小不受支持。');
  let nodes = 0, operations = 0;
  const walk = (value: any, depth: number, sensitive = false): any => {
    if (++nodes > 50_000 || depth > 32) throw new Error('文档超出安全解析预算。');
    if (value === null || typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map(child => walk(child, depth + 1, sensitive));
    sensitive ||= secret(String(value.name ?? '')) || value.format === 'password';
    const result: Record<string, unknown> = Object.create(null);
    for (const [key, child] of Object.entries(value)) {
      if (forbidden.has(key)) throw new Error('文档包含不允许的属性。');
      if (key === '$ref' && (typeof child !== 'string' || !child.startsWith('#/'))) throw new Error('文档引用只能指向本文件。');
      if (secret(key) && typeof child === 'string' || sensitive && ['default', 'example', 'examples', 'enum', 'value'].includes(key)) result[key] = '[REDACTED]';
      else result[key] = walk(child, depth + 1, sensitive || secret(key));
      if (/^(?:get|put|post|delete|patch|options|head|trace)$/.test(key) && ++operations > 2_000) throw new Error('文档操作数量超出安全预算。');
    }
    return result;
  };
  const document = walk(input, 0);
  if (!/^3\./.test(String(document.openapi ?? '')) && document.swagger !== '2.0') throw new Error('仅支持 OpenAPI 3.x 或 Swagger 2.0 文档。');
  if (document.info && (typeof document.info !== 'object' || Array.isArray(document.info) || ['title', 'version', 'description'].some(key => document.info[key] !== undefined && typeof document.info[key] !== 'string'))) throw new Error('文档信息格式无效。');
  if (document.paths !== undefined && (!document.paths || typeof document.paths !== 'object' || Array.isArray(document.paths))) throw new Error('接口路径格式无效。');
  for (const row of Object.values(document.paths ?? {}) as any[]) { if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error('接口路径定义无效。'); for (const [method, op] of Object.entries(row) as [string, any][]) if (/^(get|post|put|delete|patch|options|head|trace)$/.test(method)) { if (!op || typeof op !== 'object' || Array.isArray(op) || ['summary', 'description', 'operationId'].some(key => op[key] !== undefined && typeof op[key] !== 'string') || op.parameters !== undefined && !Array.isArray(op.parameters) || row.parameters !== undefined && !Array.isArray(row.parameters)) throw new Error('接口操作定义无效。'); } }
  return document;
}
export function localPointer(document: Record<string, any>, ref: string): any {
  if (!ref.startsWith('#/')) throw new Error('外部文档引用不受支持。');
  const parts = ref.slice(2).split('/'); if (parts.length > 32) throw new Error('引用层级超出预算。');
  let value: any = document;
  for (const part of parts) { if (/~(?![01])/g.test(part)) throw new Error('无效的 JSON Pointer。'); const key = part.replace(/~1/g, '/').replace(/~0/g, '~'); if (forbidden.has(key) || value === null || typeof value !== 'object' || !Object.prototype.hasOwnProperty.call(value, key)) throw new Error('文档引用未找到。'); value = value[key]; }
  return value;
}
export function expandSchema(document: Record<string, any>, schema: any, maxDepth = 12): any {
  let nodes = 0;
  const expand = (value: any, depth: number, refs: Set<string>): any => {
    if (++nodes > 2_000 || depth > maxDepth) return { description: '结构超出展开预算，已保留引用。' };
    if (value === null || typeof value !== 'object') return value;
    if (typeof value.$ref === 'string') { if (refs.has(value.$ref)) return { $ref: value.$ref, description: '循环引用，未重复展开。' }; const next = new Set(refs); next.add(value.$ref); return expand(localPointer(document, value.$ref), depth + 1, next); }
    if (Array.isArray(value)) return value.map(child => expand(child, depth + 1, refs));
    return Object.fromEntries(Object.entries(value).filter(([key]) => !forbidden.has(key)).map(([key, child]) => [key, expand(child, depth + 1, refs)]));
  };
  return expand(schema, 0, new Set());
}
export function operationId(method: string, path: string) { let hash = 2166136261; for (const char of path) { hash ^= char.charCodeAt(0); hash = Math.imul(hash, 16777619); } return `portal-openapi-operation-${method.toUpperCase()}-${(hash >>> 0).toString(16)}`; }
