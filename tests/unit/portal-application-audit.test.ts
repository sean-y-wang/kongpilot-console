import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { PortalCredentialsService } from '../../apps/console-api/src/modules/portal/portal-credentials.service';

function fixture() {
  const principal: any = { clusterId: randomUUID(), workspaceId: randomUUID(), developerId: randomUUID(), sessionId: randomUUID() };
  const state: any = { row: null, events: [], auditFailure: false };
  const db: any = {
    one: vi.fn(async (sql: string, p: any[]) => {
      if (sql.includes('FROM portal_applications')) {
        if (!state.row || state.row.id !== p[0] || p.length >= 4 && (p[1] !== principal.clusterId || p[2] !== principal.workspaceId || p[3] !== principal.developerId)) return null;
        return structuredClone(state.row);
      }
      return null;
    }),
    query: vi.fn(async () => []),
    exec: vi.fn(async (sql: string, p: any[]) => {
      if (sql.includes('INSERT INTO portal_applications')) state.row = { id: p[0], cluster_id: p[1], workspace_id: p[2], developer_id: p[3], name: p[4], description: p[5], status: 'active', revision: 1, created_at: new Date() };
      if (sql.includes('UPDATE portal_applications SET name')) {
        if (state.row.revision !== p[4]) return 0;
        Object.assign(state.row, { name: p[1], description: p[2], status: p[3], revision: state.row.revision + 1 });
      }
      if (sql.includes('UPDATE portal_applications SET status')) {
        if (state.row.revision !== p[4] || state.row.status !== p[5]) return 0;
        Object.assign(state.row, { status: p[1], revision: state.row.revision + 1 });
      }
      return 1;
    }),
  };
  const audit: any = { append: vi.fn(async (event: any, tx: any) => { expect(tx).toBe(db); if (state.auditFailure) throw Error('AUDIT_STORAGE_UNAVAILABLE'); state.events.push(event); }) };
  const auth: any = {
    assertCurrent: vi.fn(async () => ({ id: principal.developerId })),
    executeMetadata: vi.fn(async (_p: any, _m: any, fn: any) => {
      const before = structuredClone(state.row), length = state.events.length;
      try { return await fn(db, randomUUID()); } catch (e) { state.row = before; state.events.length = length; throw e; }
    }),
  };
  const service = new PortalCredentialsService(db, {} as any, {} as any, audit, auth, {} as any, {} as any, {} as any, {} as any, {} as any);
  const context = { requestId: randomUUID(), ip: '192.0.2.17', idempotencyKey: randomUUID() };
  return { service, principal, state, audit, db, context };
}

describe('Portal application terminal audit in the business transaction', () => {
  it('records actual before/after, developer identity and scope for create, update, archive and restore', async () => {
    const f = fixture(), created = await f.service.saveApplication(f.principal, undefined, { name: 'original' }, f.context);
    await f.service.saveApplication(f.principal, created.entity.id, { name: 'changed', revision: 1 }, f.context);
    await f.service.archiveApplication(f.principal, created.entity.id, { revision: 2, confirmed: true, confirm_name: 'changed' }, f.context);
    await f.service.archiveApplication(f.principal, created.entity.id, { revision: 3, confirmed: true, confirm_name: 'changed' }, f.context, true);
    expect(f.state.events.map((e: any) => e.action)).toEqual(['portal.application.create', 'portal.application.update', 'portal.application.delete', 'portal.application.restore']);
    expect(f.state.events[0].before).toBeNull();
    expect(f.state.events[1]).toMatchObject({ before: { name: 'original', revision: 1 }, after: { name: 'changed', revision: 2 } });
    expect(f.state.events[2]).toMatchObject({ before: { state: 'active' }, after: { state: 'archived' } });
    expect(f.state.events[3]).toMatchObject({ before: { state: 'archived' }, after: { state: 'disabled' } });
    for (const e of f.state.events) expect(e).toMatchObject({ actorType: 'developer', actorId: null, entityType: 'portal_applications', entityId: created.entity.id, clusterId: f.principal.clusterId, workspaceId: f.principal.workspaceId, result: 'success', requestId: f.context.requestId, ip: f.context.ip, after: { developerId: f.principal.developerId }, scopeHints: { quality: 'verified', subject: { type: 'portal_applications', id: created.entity.id } } });
  });
  it('propagates an audit failure to the enclosing transaction and does not report a committed application', async () => {
    const f = fixture(); f.state.auditFailure = true;
    await expect(f.service.saveApplication(f.principal, undefined, { name: 'never committed' }, f.context)).rejects.toThrow('AUDIT_STORAGE_UNAVAILABLE');
    expect(f.state.row).toBeNull(); expect(f.state.events).toEqual([]);
  });
  it('rejects stale or foreign application updates before recording success', async () => {
    const f = fixture(), created = await f.service.saveApplication(f.principal, undefined, { name: 'original' }, f.context);
    await expect(f.service.saveApplication(f.principal, created.entity.id, { name: 'stale', revision: 0 }, f.context)).rejects.toMatchObject({ status: 400 });
    await expect(f.service.saveApplication({ ...f.principal, developerId: randomUUID() }, created.entity.id, { name: 'foreign', revision: 1 }, f.context)).rejects.toMatchObject({ status: 404 });
    expect(f.state.events).toHaveLength(1); expect(f.state.row.name).toBe('original');
  });
});
