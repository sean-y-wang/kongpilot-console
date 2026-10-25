import { describe, expect, it } from 'vitest';
import { assertEntityChangeRecycleRestoreOrigin } from '../../apps/console-api/src/modules/workflows/entity-change-recycle-restore-origin';

const db = (row: any) => { const calls: any[] = []; return { calls, one: async (sql: string, params?: unknown[]) => { calls.push([sql, params]); return row; } }; };
const cid = '00000000-0000-4000-8000-000000000001', entryId = '00000000-0000-4000-8000-000000000002';

describe('M11 browser-E2E defect: legacy mutation-origin recycle restore is refused before sealing', () => {
  it('rejects a mutation-origin entry with a stable code (no intent, no approval spent)', async () => {
    const d = db({ mutation_id: '00000000-0000-4000-8000-000000000003' });
    await expect(assertEntityChangeRecycleRestoreOrigin(d, cid, { kind: 'recycle', action: 'restore', entryId, confirmed: true }))
      .rejects.toMatchObject({ response: { code: 'ENTITY_RECYCLE_LEGACY_ORIGIN_RESTORE_UNSUPPORTED' } });
    expect(d.calls).toEqual([['SELECT mutation_id FROM recycle_entries WHERE cluster_id=$1 AND id=$2', [cid, entryId]]]);
  });
  it('allows entity-change-origin entries (mutation_id NULL) and leaves missing rows to the compiler', async () => {
    await expect(assertEntityChangeRecycleRestoreOrigin(db({ mutation_id: null }), cid, { kind: 'recycle', action: 'restore', entryId })).resolves.toBeUndefined();
    await expect(assertEntityChangeRecycleRestoreOrigin(db(undefined), cid, { kind: 'recycle', action: 'restore', entryId })).resolves.toBeUndefined();
  });
  it('never queries for non-restore changes', async () => {
    for (const change of [{ kind: 'recycle', action: 'delete', entityType: 'services', entityId: entryId }, { kind: 'entity', action: 'update' }, null]) {
      const d = db({ mutation_id: 'x' }); await assertEntityChangeRecycleRestoreOrigin(d, cid, change); expect(d.calls).toEqual([]);
    }
  });
});
