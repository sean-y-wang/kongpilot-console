import 'reflect-metadata';
import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import { PortalAdminService } from '../../apps/console-api/src/modules/portal/portal-admin.service';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';

const cid = 'dff45535-ed8d-4851-b7a6-6376feac7f59', wid = '28329ea2-83a4-4b2c-b030-a209567d3276', id = '12491546-24cc-4f35-be68-bbe6f25da3b1';
describe('M7 Portal terminal metadata auditing', () => {
  beforeEach(() => vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32)));
  afterEach(() => vi.unstubAllEnvs());
  function fixture() {
    let row: any = { id, cluster_id: cid, workspace_id: wid, title: 'fixture', slug: 'fixture', state: 'draft', current_revision: 1, published_revision: null, revision: 1 };
    const audits: any[] = [], business: any[] = [];
    const tx: any = { one: vi.fn(async (_sql: string, params: any[]) => params[0] === row.id && (!params[1] || params[1] === row.cluster_id) && (!params[2] || params[2] === row.workspace_id) ? row : null),
      exec: vi.fn(async (sql: string, p: any[]) => {
        if (p[0] !== row.id) return 0;
        if (sql.includes('SET state=$2,published_revision=NULL')) { if (row.revision !== p[5]) return 0; row.state = p[1]; row.published_revision = null; row.deleted_at = p[2]; row.retention_until = p[3]; }
        else if (sql.includes('SET state=$2,published_revision=$3')) { if (row.revision !== p[4]) return 0; row.state = p[1]; row.published_revision = p[2]; }
        else throw new Error('unexpected mutation');
        row.revision++; return 1;
      }), transaction: vi.fn(async (fn: any) => { const before = structuredClone(row), length = audits.length; try { return await fn(tx); } catch (e) { row = before; audits.length = length; throw e; } }) };
    const audit: any = { append: vi.fn(async (event: any, db: any) => { expect(db).toBe(tx); audits.push(structuredClone(event)); return { id: 'audit' }; }) };
    const iam: any = { execute: vi.fn(async (_context: any, fn: any) => tx.transaction((db: any) => fn(db, 'operation-one', (context: any) => business.push(structuredClone(context))))) };
    const authz: any = { assertWholeWorkspace: vi.fn().mockResolvedValue(undefined) };
    const native: any = { scope: vi.fn().mockResolvedValue({ executionMode: 'direct' }), metadataStep: vi.fn((order: number, handler: string, table: string, target: string, before: any, payload: any) => ({ order, handler, entityType: table, entityId: target, before: structuredClone(before), metadata: payload })) };
    const service = new PortalAdminService(tx, new SecretService(), authz, audit, iam, {} as any, {} as any, {} as any, {} as any, {} as any, {} as any, native, {} as any);
    const actor: any = { user: { id: cid }, workspaceId: wid, idempotencyKey: 'original-one', requestId: 'request-one', ip: '192.0.2.1' };
    const mutate = (handler: string, payload: any = {}) => (service as any).metadataRequest(cid, wid, structuredClone(row), handler, payload, actor);
    return { mutate, get: () => row, audit, audits, business, authz, tx };
  }
  it('records actual locked before, fresh readback, source IP/request and IAM context without DTO leakage', async () => {
    const f = fixture(), result = await f.mutate('portal.page.publish');
    expect(result.entity).toMatchObject({ id, revision: 2, state: 'published' });
    expect(result).not.toHaveProperty('scopeHints'); expect(result).not.toHaveProperty('businessAudit');
    expect(f.audits).toHaveLength(1);
    expect(f.audits[0]).toMatchObject({ action: 'portal.page.publish', result: 'success', requestId: 'request-one', ip: '192.0.2.1', before: { revision: 1, state: 'draft' }, after: { revision: 2, state: 'published' }, scopeHints: { quality: 'verified', beforeWorkspaceId: wid, afterWorkspaceId: wid, subject: { type: 'portal_content', id } } });
    expect(f.business[0]).toMatchObject({ entityType: 'portal_content', entityId: id, before: { revision: 1 }, after: { revision: 2 } });
  });
  it('keeps archive and restore distinct and audits preserved before/after revisions', async () => {
    const f = fixture(); await f.mutate('portal.page.draft', { archive: true }); await f.mutate('portal.page.draft', { archive: false });
    expect(f.audits.map(e => e.action)).toEqual(['portal.metadata.archive', 'portal.metadata.restore']);
    expect(f.audits[0]).toMatchObject({ before: { state: 'draft', revision: 1 }, after: { state: 'deleted', revision: 2 } });
    expect(f.audits[1]).toMatchObject({ before: { state: 'deleted', revision: 2 }, after: { state: 'draft', revision: 3 } });
  });
  it('rolls metadata back when mandatory terminal audit insertion fails', async () => {
    const f = fixture(); f.audit.append.mockRejectedValueOnce(new Error('audit rejected'));
    await expect(f.mutate('portal.page.publish')).rejects.toThrow('audit rejected');
    expect(f.get()).toMatchObject({ state: 'draft', revision: 1 }); expect(f.business).toEqual([]);
  });
  it('fails closed if exact tenant row disappears before locked apply', async () => {
    const f = fixture(); f.tx.one.mockResolvedValueOnce(null);
    await expect(f.mutate('portal.page.publish')).rejects.toMatchObject({ status: 409 });
    expect(f.audits).toEqual([]); expect(f.tx.exec).not.toHaveBeenCalled();
  });
});
