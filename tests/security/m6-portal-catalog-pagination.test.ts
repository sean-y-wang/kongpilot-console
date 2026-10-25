import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { PortalPublicService, PORTAL_CATALOG_SCAN_LIMITS } from '../../apps/console-api/src/modules/portal/portal-public.service';
import { publicationProofAad } from '../../apps/console-api/src/modules/portal/portal-proof';
import { PortalCursor } from '../../apps/console-api/src/modules/portal/portal-input';

beforeEach(() => { vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'a7'.repeat(32)); vi.stubEnv('CURSOR_SIGNING_KEY', 'offline-catalog-signing-key'); });
afterEach(() => vi.unstubAllEnvs());

/** SQL is a bounded candidate-store fixture; actual PostgreSQL CTE execution is
 * independently owned by Storage. The projection, AEAD/HMAC and cursor are real. */
function catalog(count: number, describeRow: (index: number) => { name?: string; category?: string; padding?: string } = () => ({})) {
  const cid = randomUUID(), wid = randomUUID(), secrets = new SecretService();
  let visible = true, afterQuery: (() => void) | undefined;
  const rows = Array.from({ length: count }, (_, index) => {
    const id = randomUUID(), workflow = randomUUID(), execution = randomUUID(), detail = describeRow(index);
    const proof: any = { version: 1, clusterId: cid, workspaceId: wid, publicationId: id, publicationRevision: 2,
      transportScope: 'a'.repeat(64), workflowId: workflow, executionId: execution, planRevision: 1, planHash: 'b'.repeat(64),
      publicationInfo: { name: detail.name ?? `Published ${index}`, slug: `publication-${index}`, description: 'Published description', category: detail.category ?? 'Other' },
      keyAuthPlugin: { config: { key_names: ['X-Partner-Key'] } }, service: { host: 'private-config-canary' }, padding: detail.padding };
    const proofRow: any = { cluster_id: cid, workspace_id: wid, publication_id: id, publication_revision: 2,
      transport_scope: proof.transportScope, workflow_id: workflow, workflow_execution_id: execution, workflow_plan_revision: 1, workflow_plan_hash: proof.planHash,
      publication_proof_secret: secrets.encrypt(proof, publicationProofAad(cid, wid, id, 2)), publication_proof_hmac: secrets.fingerprint(proof) };
    const row: any = { id, cluster_id: cid, workspace_id: wid, slug: proof.publicationInfo.slug, revision: 8, published_revision: 2,
      cursor_created_at: new Date(Date.UTC(2026, 9, 1) - index * 1000).toISOString().replace('.000Z', '.123456Z'),
      published_name: 'IMMUTABLE REVISION TITLE DIFFERS', published_description: 'Published description', category: 'PRIVATE DRAFT CATEGORY',
      publication_proof: proofRow, proof };
    row.row_bytes = Buffer.byteLength(proofRow.publication_proof_secret) + Buffer.byteLength(row.published_name) + Buffer.byteLength(row.published_description) + 2048;
    return row;
  });
  const db: any = { one: vi.fn(async () => visible ? { id: randomUUID() } : null), query: vi.fn(async (sql: string, parameters: any[]) => {
    if (!sql.startsWith('WITH candidates AS')) throw new Error('unexpected candidate query');
    const [queryCid, queryWid, stamp, id, candidateLimit, byteLimit] = parameters;
    const candidates = rows.filter(row => row.cluster_id === queryCid && row.workspace_id === queryWid
      && (stamp === null || row.cursor_created_at < stamp || row.cursor_created_at === stamp && row.id < id)).slice(0, candidateLimit);
    let bytes = 0;
    const selected = candidates.slice(0, candidateLimit - 1).flatMap((row, index) => {
      bytes += row.row_bytes;
      if (bytes > byteLimit && index !== 0) return [];
      return [{ ...row, candidate_count: String(candidates.length), byte_exhausted: bytes > byteLimit,
        publication_proof: bytes > byteLimit ? null : row.publication_proof }];
    });
    afterQuery?.();
    return selected;
  }) };
  return { cid, wid, rows, db, secrets, service: new PortalPublicService(db, secrets), query: { clusterId: cid, workspaceId: wid },
    setVisible: (value: boolean) => { visible = value; }, onQuery: (fn: () => void) => { afterQuery = fn; } };
}

describe('M6 real proof-authoritative catalog pagination', () => {
  it('fills a matching page across an unrelated first SQL batch rather than claiming no result', async () => {
    const f = catalog(52, index => ({ category: index === 51 ? 'Payments' : 'Other' }));
    const page = await f.service.publications({ ...f.query, category: 'Payments', size: 1 });
    expect(page).toMatchObject({ searchedRows: 52, scanIncomplete: false, nextCursor: null });
    expect(page.items.map((row: any) => row.id)).toEqual([f.rows[51].id]);
    expect(f.db.query).toHaveBeenCalledTimes(2);
  });
  it('anchors continuation at the last checked candidate, preserving the unprocessed fetched tail', async () => {
    const f = catalog(8, index => ({ category: [1, 2, 6].includes(index) ? 'Payments' : 'Other' }));
    const first = await f.service.publications({ ...f.query, category: 'Payments', size: 1 });
    const second = await f.service.publications({ ...f.query, category: 'Payments', size: 1, cursor: first.nextCursor });
    const third = await f.service.publications({ ...f.query, category: 'Payments', size: 1, cursor: second.nextCursor });
    expect([first.items[0].id, second.items[0].id, third.items[0].id]).toEqual([f.rows[1].id, f.rows[2].id, f.rows[6].id]);
    expect(f.db.query.mock.calls[1][1][2]).toBe(f.rows[1].cursor_created_at);
    expect(f.db.query.mock.calls[1][1][2]).toContain('.123456Z');
  });
  it('returns truthful incomplete search after 500 candidates and finds the later item on the next request', async () => {
    const f = catalog(501, index => ({ category: index === 500 ? 'Payments' : 'Other' }));
    const first = await f.service.publications({ ...f.query, category: 'Payments' });
    expect(first).toMatchObject({ items: [], searchedRows: 500, scanIncomplete: true });
    expect(first.nextCursor).toBeTruthy(); expect(f.db.query).toHaveBeenCalledTimes(10);
    const second = await f.service.publications({ ...f.query, category: 'Payments', cursor: first.nextCursor });
    expect(second.items.map((row: any) => row.id)).toEqual([f.rows[500].id]);
    expect(second).toMatchObject({ nextCursor: null, scanIncomplete: false, searchedRows: 1 });
  });
  it('ends a genuinely absent category at EOF without a phantom next page', async () => {
    const f = catalog(50), page = await f.service.publications({ ...f.query, category: 'Absent' });
    expect(page).toMatchObject({ items: [], nextCursor: null, scanIncomplete: false, searchedRows: 50 });
    expect(f.db.query).toHaveBeenCalledTimes(1);
  });
  it('keeps no-filter pagination to one bounded query with accurate lookahead', async () => {
    const f = catalog(3), page = await f.service.publications({ ...f.query, size: 2 });
    expect(page.items).toHaveLength(2); expect(page.nextCursor).toBeTruthy(); expect(f.db.query).toHaveBeenCalledTimes(1);
    const last = await f.service.publications({ ...f.query, size: 2, cursor: page.nextCursor });
    expect(last.items.map((row: any) => row.id)).toEqual([f.rows[2].id]); expect(last.nextCursor).toBeNull();
  });
  it('uses authenticated published names and categories, never draft or revision-title SQL filtering', async () => {
    const f = catalog(2, index => ({ name: index ? 'Partner PAYMENTS' : 'Other', category: 'Payments' }));
    const result = await f.service.publications({ ...f.query, search: 'partner payments', category: 'Payments' });
    expect(result.items.map((row: any) => row.id)).toEqual([f.rows[1].id]);
    expect(JSON.stringify(result)).not.toMatch(/PRIVATE DRAFT|private-config-canary|IMMUTABLE REVISION/);
    expect(f.db.query.mock.calls[0][0]).not.toMatch(/p\.category|ILIKE|safe_result/);
  });
  it('fails closed on a tampered proof even if its hidden category would not match the requested filter', async () => {
    const f = catalog(2); f.rows[0].publication_proof.publication_proof_hmac = '0'.repeat(64);
    await expect(f.service.publications({ ...f.query, category: 'Payments' })).rejects.toMatchObject({ response: { code: 'PORTAL_PUBLICATION_PROOF_INVALID' } });
  });
  it('retains immutable revision-only legacy descriptors without guessing a draft category', async () => {
    const f = catalog(1), row = f.rows[0]; delete row.proof.publicationInfo;
    row.publication_proof.publication_proof_secret = f.secrets.encrypt(row.proof, publicationProofAad(f.cid, f.wid, row.id, 2));
    row.publication_proof.publication_proof_hmac = f.secrets.fingerprint(row.proof);
    const result = await f.service.publications({ ...f.query, search: 'IMMUTABLE REVISION' });
    expect(result.items[0]).toMatchObject({ name: row.published_name, category: null });
    expect((await f.service.publications({ ...f.query, category: 'PRIVATE DRAFT CATEGORY' })).items).toEqual([]);
  });
  it.each(['category', 'search', 'size', 'workspaceId', 'clusterId'])('rejects a continuation reused with another %s', async field => {
    const f = catalog(2, () => ({ category: 'Payments' })), input: any = { ...f.query, category: 'Payments', size: 1 };
    const first = await f.service.publications(input);
    const different: any = { ...input, cursor: first.nextCursor, [field]: field === 'category' ? 'Other' : field === 'search' ? 'Other' : field === 'size' ? 2 : randomUUID() };
    await expect(f.service.publications(different)).rejects.toMatchObject({ response: { code: 'INVALID_CURSOR' } });
  });
  it('rejects a signed malformed keyset and rechecks publication after awaited candidate reads', async () => {
    const f = catalog(1), binding = f.secrets.fingerprint({ kind: 'publications', version: 2, scope: f.query, size: 20, search: '', category: null });
    const cursor = new PortalCursor().encode(binding, { createdAt: 'bad-date', id: f.rows[0].id });
    await expect(f.service.publications({ ...f.query, cursor })).rejects.toMatchObject({ response: { code: 'INVALID_CURSOR' } });
    expect(f.db.query).not.toHaveBeenCalled();
    f.onQuery(() => f.setVisible(false));
    await expect(f.service.publications(f.query)).rejects.toMatchObject({ response: { code: 'PORTAL_NOT_FOUND' } });
  });
  it('stops ciphertext growth at the request byte budget and resumes before the oversized tail', async () => {
    const f = catalog(19, index => ({ padding: 'x'.repeat(1_400_000), category: index === 18 ? 'Payments' : 'Other' }));
    const first = await f.service.publications({ ...f.query, category: 'Payments' });
    expect(first.items).toEqual([]); expect(first.scanIncomplete).toBe(true); expect(first.nextCursor).toBeTruthy();
    expect(first.searchedRows).toBeLessThan(19);
    expect(f.rows.slice(0, first.searchedRows).reduce((sum, row) => sum + row.row_bytes, 0)).toBeLessThanOrEqual(PORTAL_CATALOG_SCAN_LIMITS.bytes);
    const next = await f.service.publications({ ...f.query, category: 'Payments', cursor: first.nextCursor });
    expect(next.items.map((row: any) => row.id)).toEqual([f.rows[18].id]); expect(next.scanIncomplete).toBe(false);
  });
});
