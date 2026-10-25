import { isAlias, isMap, isScalar, isSeq, parseAllDocuments } from 'yaml';
import type { ParsedDeckDocument } from './transfer.types';
import { transferFail } from './transfer.types';

export const TRANSFER_LIMITS = Object.freeze({ bytes: 8 * 1024 * 1024, nodes: 50_000, depth: 32 });
const forbiddenKeys = new Set(['__proto__', 'prototype', 'constructor', '<<', '$ref', '$include']);
const standardTags = new Set(['tag:yaml.org,2002:str', 'tag:yaml.org,2002:int', 'tag:yaml.org,2002:float', 'tag:yaml.org,2002:bool', 'tag:yaml.org,2002:null', 'tag:yaml.org,2002:map', 'tag:yaml.org,2002:seq']);
const rootKeys = new Set(['_format_version', 'services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates']);

/** Parse YAML and JSON using the same AST safeguards, before any conversion to JS. */
export function parseDeckDocument(content: string, limits: Partial<typeof TRANSFER_LIMITS> = {}): ParsedDeckDocument {
  if (typeof content !== 'string') transferFail('CONFIGURATION_INVALID_DOCUMENT');
  const budget = { ...TRANSFER_LIMITS, ...limits };
  for (const name of ['bytes', 'nodes', 'depth'] as const) if (!Number.isInteger(budget[name]) || budget[name] < 1 || budget[name] > TRANSFER_LIMITS[name]) transferFail('CONFIGURATION_INVALID_PARSE_LIMIT');
  const bytes = Buffer.byteLength(content, 'utf8');
  if (bytes > budget.bytes) transferFail('CONFIGURATION_DOCUMENT_TOO_LARGE');
  let docs: ReturnType<typeof parseAllDocuments>;
  try { docs = parseAllDocuments(content, { version: '1.2', schema: 'core', uniqueKeys: true, strict: true, prettyErrors: false }); }
  catch { transferFail('CONFIGURATION_INVALID_YAML'); }
  if (docs.length !== 1) transferFail('CONFIGURATION_MULTIPLE_DOCUMENTS');
  const doc = docs[0];
  // Diagnostics may contain secret scalars; expose only our fixed error code.
  if (doc.errors.length || doc.warnings.length) transferFail('CONFIGURATION_INVALID_YAML');
  if (doc.directives?.yaml.version !== '1.2' || Object.entries(doc.directives?.tags ?? {}).some(([handle, prefix]) => handle !== '!!' || prefix !== 'tag:yaml.org,2002:')) transferFail('CONFIGURATION_YAML_DIRECTIVE');
  let nodes = 0;
  const walk = (node: any, depth: number): unknown => {
    if (++nodes > budget.nodes) transferFail('CONFIGURATION_DOCUMENT_NODE_LIMIT');
    if (depth > budget.depth) transferFail('CONFIGURATION_DOCUMENT_DEPTH_LIMIT');
    if (node === null) return null;
    if (!node || isAlias(node) || node.anchor) transferFail('CONFIGURATION_YAML_ALIAS_OR_ANCHOR');
    if (node.tag && !standardTags.has(node.tag)) transferFail('CONFIGURATION_YAML_TAG');
    if (isScalar(node)) {
      const value = node.value;
      if (typeof value === 'number' && !Number.isFinite(value) || typeof value === 'bigint' || value === undefined) transferFail('CONFIGURATION_INVALID_SCALAR');
      if (value !== null && !['string', 'number', 'boolean'].includes(typeof value)) transferFail('CONFIGURATION_INVALID_SCALAR');
      if (typeof value === 'string' && /^(?:\[REDACTED(?:[:\]])|\[DEPTH_LIMIT\]|\[CIRCULAR\]|\*{3,}$)/.test(value)) transferFail('CONFIGURATION_SECRET_MARKER');
      return value;
    }
    if (isSeq(node)) return node.items.map(child => walk(child, depth + 1));
    if (isMap(node)) {
      const output: Record<string, unknown> = Object.create(null);
      for (const pair of node.items) {
        if (!isScalar(pair.key) || typeof pair.key.value !== 'string') transferFail('CONFIGURATION_INVALID_MAP_KEY');
        const key = pair.key.value;
        if (++nodes > budget.nodes) transferFail('CONFIGURATION_DOCUMENT_NODE_LIMIT');
        if (pair.key.anchor || pair.key.tag && !standardTags.has(pair.key.tag)) transferFail('CONFIGURATION_YAML_TAG');
        if (forbiddenKeys.has(key)) transferFail('CONFIGURATION_RESERVED_KEY');
        if (Object.hasOwn(output, key)) transferFail('CONFIGURATION_DUPLICATE_KEY');
        output[key] = walk(pair.value, depth + 1);
      }
      return output;
    }
    transferFail('CONFIGURATION_INVALID_YAML');
  };
  const value = walk(doc.contents, 0);
  if (!value || typeof value !== 'object' || Array.isArray(value)) transferFail('CONFIGURATION_INVALID_DOCUMENT');
  const document = value as Record<string, unknown>;
  if (document._format_version !== '1.1') transferFail('CONFIGURATION_FORMAT_VERSION');
  for (const [key, entry] of Object.entries(document)) {
    if (!rootKeys.has(key)) transferFail('CONFIGURATION_UNKNOWN_ROOT_FIELD');
    if (key !== '_format_version' && !Array.isArray(entry)) transferFail('CONFIGURATION_INVALID_COLLECTION', key);
  }
  return { formatVersion: '1.1', document, bytes, nodes };
}
