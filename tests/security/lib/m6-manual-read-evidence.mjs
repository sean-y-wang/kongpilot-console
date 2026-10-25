import { manualUuid } from './m6-manual-journal.mjs';

const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
const keys = (value, required, optional = []) => object(value) && required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
const revision = value => Number.isInteger(value) && value > 0;
const date = value => typeof value === 'string' && Number.isFinite(Date.parse(value));
const text = value => typeof value === 'string';
const inScope = (row, expected) => row.clusterId === expected.clusterId && row.workspaceId === expected.workspaceId;
function fail() { throw new Error('M6_MANUAL_READ_EVIDENCE_INVALID'); }

export function manualReadContract(expected) {
  if (!manualUuid(expected?.clusterId) || !manualUuid(expected.workspaceId)) fail();
  const catalog = expected.kind === 'catalog', detail = ['developer', 'application'].includes(expected.kind);
  if (!catalog && !detail && !['grants', 'requests'].includes(expected.kind)) fail();
  if (!catalog && !manualUuid(expected.id)) fail();
  const origin = catalog ? 'http://127.0.0.1:8082' : 'http://127.0.0.1:8080';
  const path = catalog ? '/api/v1/portal/publications' : `/api/v1/clusters/${expected.clusterId}/portal/${expected.kind === 'developer' ? 'developers' : 'applications'}/${expected.id}${detail ? '' : `/${expected.kind}`}`;
  const query = { ...(catalog ? { clusterId: expected.clusterId } : {}), workspaceId: expected.workspaceId, ...(detail ? {} : { size: '20' }), ...(expected.search ? { search: expected.search } : {}), ...(expected.category ? { category: expected.category } : {}) };
  if (!catalog && (expected.search || expected.category)) fail();
  return { origin, path, query };
}
export function manualReadPacketMatches(packet, expected) {
  const contract = manualReadContract(expected);
  try {
    const url = new URL(packet.url), entries = [...url.searchParams];
    return packet.method === 'GET' && !url.username && !url.password && !url.hash && url.origin === contract.origin && url.pathname === contract.path
      && entries.length === Object.keys(contract.query).length && new Set(entries.map(([key]) => key)).size === entries.length && entries.every(([key, value]) => contract.query[key] === value);
  } catch { return false; }
}
export function validateManualReadEvidence(packet, status, payload, expected) {
  if (!manualReadPacketMatches(packet, expected) || !Number.isInteger(status) || status < 200 || status >= 300 || !manualUuid(payload?.meta?.requestId)) fail();
  const data = payload.data;
  if (expected.kind === 'developer' || expected.kind === 'application') {
    if (!keys(data, ['entity'])) fail();
    const row = data.entity, developer = expected.kind === 'developer';
    const fields = developer ? ['id', 'clusterId', 'workspaceId', 'username', 'email', 'displayName', 'status', 'revision', 'mustChangePassword', 'createdAt'] : ['id', 'clusterId', 'workspaceId', 'developerId', 'name', 'description', 'state', 'revision', 'createdAt', 'capabilities'];
    if (!keys(row, fields) || row.id !== expected.id || !inScope(row, expected) || !revision(row.revision) || !date(row.createdAt)) fail();
    if (developer ? row.username !== expected.username || row.status !== 'active' || !text(row.email) || !text(row.displayName) || typeof row.mustChangePassword !== 'boolean'
      : row.developerId !== expected.developerId || !text(row.name) || !text(row.description) || row.state !== 'active' || !keys(row.capabilities, ['readGrants', 'readRequests']) || row.capabilities.readGrants !== true || row.capabilities.readRequests !== true) fail();
    return { data, evidence: { kind: expected.kind, method: 'GET', path: manualReadContract(expected).path, requestId: payload.meta.requestId, clusterId: expected.clusterId, workspaceId: expected.workspaceId, entityId: row.id, safeDto: true } };
  }
  if (!keys(data, ['items', 'size', 'total', 'nextCursor'], expected.kind === 'catalog' ? ['scanIncomplete', 'searchedRows'] : []) || !Array.isArray(data.items) || data.size !== 20 || data.items.length > 20 || data.total !== null || !(data.nextCursor === null || text(data.nextCursor) && !!data.nextCursor) || new Set(data.items.map(row => row?.id)).size !== data.items.length) fail();
  for (const row of data.items) {
    if (!manualUuid(row?.id) || !revision(row.revision)) fail();
    if (expected.kind === 'catalog') {
      if (!keys(row, ['id', 'clusterId', 'workspaceId', 'name', 'slug', 'description', 'category', 'revision', 'documentRevision', 'status', 'auth']) || !inScope(row, expected) || !text(row.name) || !text(row.slug) || !text(row.description) || !(row.category === null || text(row.category)) || !revision(row.documentRevision) || row.status !== 'published'
        || !keys(row.auth, ['type', 'credentialScope', 'accessScope', 'keyNames']) || row.auth.type !== 'key-auth' || row.auth.credentialScope !== 'application_publication' || row.auth.accessScope !== 'whole_service' || !Array.isArray(row.auth.keyNames) || !row.auth.keyNames.length || !row.auth.keyNames.every(text)
        || expected.category && row.category !== expected.category || expected.search && !row.name.toLowerCase().includes(expected.search.toLowerCase())) fail();
    } else if (expected.kind === 'grants') {
      if (!keys(row, ['id', 'applicationId', 'publicationId', 'publicationName', 'state', 'generation', 'revision', 'reservationReleased', 'createdAt']) || row.applicationId !== expected.id || !manualUuid(row.publicationId) || !text(row.publicationName) || !['pending', 'active', 'partial', 'rotating', 'revoking', 'revoked', 'uncertain', 'disabled'].includes(row.state) || !Number.isInteger(row.generation) || row.generation < 0 || typeof row.reservationReleased !== 'boolean' || !date(row.createdAt)) fail();
    } else if (!keys(row, ['id', 'clusterId', 'workspaceId', 'applicationId', 'grantId', 'publicationId', 'kind', 'state', 'revision', 'executionMode', 'approvalRequired', 'createdAt', 'expiresAt']) || !inScope(row, expected) || row.applicationId !== expected.id || !manualUuid(row.grantId) || !manualUuid(row.publicationId) || !['portal-credential-issue', 'portal-credential-rotate', 'portal-credential-revoke'].includes(row.kind) || !['draft', 'pending', 'approved', 'executing', 'succeeded', 'partial', 'failed', 'uncertain', 'rejected', 'cancelled', 'expired'].includes(row.state) || !['direct', 'approval'].includes(row.executionMode) || typeof row.approvalRequired !== 'boolean' || !date(row.createdAt) || !date(row.expiresAt)) fail();
  }
  const targetId = expected.kind === 'catalog' ? expected.publicationId : expected.kind === 'grants' ? expected.grantId : expected.workflowId;
  if (!manualUuid(targetId)) fail();
  const target = data.items.find(row => row.id === targetId);
  if (!target || expected.kind !== 'catalog' && (target.publicationId !== expected.publicationId || expected.kind === 'grants' && target.state !== 'active' || expected.kind === 'requests' && (target.grantId !== expected.grantId || target.state !== 'succeeded'))) fail();
  if (expected.kind === 'catalog' && (data.scanIncomplete !== undefined && typeof data.scanIncomplete !== 'boolean' || data.searchedRows !== undefined && (!Number.isInteger(data.searchedRows) || data.searchedRows < 0 || data.searchedRows > 500))) fail();
  return { data, target, evidence: { kind: expected.kind, method: 'GET', path: manualReadContract(expected).path, requestId: payload.meta.requestId, clusterId: expected.clusterId, workspaceId: expected.workspaceId, ...(expected.kind === 'catalog' ? { filter: expected.category ? 'category' : expected.search ? 'search-all-categories' : 'all-categories', scanIncomplete: data.scanIncomplete === true } : { applicationId: expected.id }), targetId, returnedItems: data.items.length, safeDto: true, totalUnknown: data.total === null } };
}

/** Preserve all historical rows unchanged; append each actual successful manual request once. */
export function mergeManualWriteEvidence(existing, manual) {
  if (existing !== undefined && !Array.isArray(existing) || !Array.isArray(manual)) throw new Error('M6_MANUAL_WRITE_EVIDENCE_INVALID');
  const combined = [...(existing ?? [])], seen = new Map();
  for (const row of combined) if (row?.requestId) seen.set(row.requestId, [...(seen.get(row.requestId) ?? []), row]);
  for (const row of manual) {
    if (!object(row) || !manualUuid(row.requestId) || !['POST', 'DELETE'].includes(row.method) || !text(row.path) || !row.path.startsWith('/api/v1/') || row.path.includes('?') || !Number.isInteger(row.status) || row.status < 200 || row.status >= 300) throw new Error('M6_MANUAL_WRITE_EVIDENCE_INVALID');
    const previous = seen.get(row.requestId);
    if (previous) { if (previous.some(old => old.method !== row.method || old.path !== row.path || old.status !== undefined && old.status !== row.status)) throw new Error('M6_MANUAL_WRITE_EVIDENCE_CONFLICT'); continue; }
    combined.push(row); seen.set(row.requestId, [row]);
  }
  return combined;
}
