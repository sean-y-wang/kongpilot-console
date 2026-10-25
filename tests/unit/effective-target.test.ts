import { describe, expect, it, vi } from 'vitest';
import { currentEffectiveTarget } from '../../apps/console-api/src/infrastructure/kong/effective-target';

const upstream = '0e609994-614d-4ae5-9430-aa66a3018fe5';
const row = (id: string, target = 'echo-upstream:8081', parent = upstream, weight = 100) => ({ id, target, upstream: { id: parent }, weight });
const page = (items: any[], nextCursor: string | null = null) => ({ items, nextCursor, size: 100 });
describe('Kong 1.5 effective Targets use scoped bounded collections', () => {
  it('ignores an ambiguous global address GET and resolves the exact current parent-scoped ID across pages', async () => {
    const current = row('fcbe1693-0ae6-44bd-a94d-d7477735784f');
    const kong = { request: vi.fn().mockResolvedValue(row('old-or-other-upstream', current.target, 'another-upstream')), list: vi.fn().mockResolvedValueOnce(page([row('other', 'echo-upstream:8082')], 'page-2')).mockResolvedValueOnce(page([current])) };
    const onPage = vi.fn();
    const result = await currentEffectiveTarget(kong, 'cluster', upstream, current.target, { onPage });
    expect(result.target).toEqual(current); expect(result.target.id).not.toBe('historical-id');
    expect(result.budget).toMatchObject({ pages: 2, records: 2 }); expect(result.budget.bytes).toBeGreaterThan(0);
    expect(kong.request).not.toHaveBeenCalled(); expect(onPage).toHaveBeenCalledTimes(2);
    expect(kong.list.mock.calls.map(call => call.slice(1, 4))).toEqual([[`/upstreams/${upstream}/targets`, { size: 100 }, undefined], [`/upstreams/${upstream}/targets`, { size: 100 }, 'page-2']]);
  });
  it('does not authorize a caller historical ID merely because its target address still exists', async () => {
    const old = row('old-id'), current = row('new-effective-id');
    const result = await currentEffectiveTarget({ list: vi.fn().mockResolvedValue(page([current])) }, 'cluster', upstream, old.target);
    expect(result.target?.id === old.id).toBe(false);
  });
  it('scans beyond a first match and rejects conflicting current addresses instead of choosing a winner', async () => {
    const kong = { list: vi.fn().mockResolvedValueOnce(page([row('one')], 'page-2')).mockResolvedValueOnce(page([row('two')])) };
    await expect(currentEffectiveTarget(kong, 'cluster', upstream, 'echo-upstream:8081')).rejects.toMatchObject({ response: { code: 'KONG_INVALID_TARGET_LIST' } });
    expect(kong.list).toHaveBeenCalledTimes(2);
  });
  it.each([row('wrong-parent', undefined, 'other'), row('retired', undefined, undefined, 0), row('bad-weight', undefined, undefined, -1)])('fails closed on foreign or retired effective data', async bad => {
    await expect(currentEffectiveTarget({ list: vi.fn().mockResolvedValue(page([bad])) }, 'cluster', upstream, 'echo-upstream:8081')).rejects.toMatchObject({ response: { code: 'KONG_INVALID_TARGET_LIST' } });
  });
  it('returns null only after a complete successful traversal', async () => {
    const result = await currentEffectiveTarget({ list: vi.fn().mockResolvedValue(page([row('other', 'echo-upstream:8082')])) }, 'cluster', upstream, 'echo-upstream:8081');
    expect(result.target).toBeNull(); expect(result.budget.pages).toBe(1);
  });
  it('refuses to claim a found target when further pages exceed a bounded lookup', async () => {
    const kong = { list: vi.fn().mockResolvedValue(page([row('found')], 'more')) };
    await expect(currentEffectiveTarget(kong, 'cluster', upstream, 'echo-upstream:8081', { maxPages: 1 })).rejects.toMatchObject({ response: { code: 'TARGET_LOOKUP_LIMIT' } });
    expect(kong.list).toHaveBeenCalledTimes(1);
  });
  it('keeps cursor-bound page sizes constant and stops before over-reserving the final record budget', async () => {
    const kong = { list: vi.fn().mockResolvedValue(page([row('found')], 'more')) };
    await expect(currentEffectiveTarget(kong, 'cluster', upstream, 'echo-upstream:8081', { maxRecords: 2, pageSize: 2 })).rejects.toMatchObject({ response: { code: 'TARGET_LOOKUP_LIMIT' } });
    expect(kong.list).toHaveBeenCalledTimes(1); expect(kong.list.mock.calls[0][2]).toEqual({ size: 2 });
  });
  it('bounds data bytes, pagination loops and remaining zero budgets without issuing further reads', async () => {
    const emptyBudget = { list: vi.fn() };
    await expect(currentEffectiveTarget(emptyBudget, 'cluster', upstream, 'echo-upstream:8081', { maxPages: 0 })).rejects.toMatchObject({ response: { code: 'TARGET_LOOKUP_LIMIT' } });
    expect(emptyBudget.list).not.toHaveBeenCalled();
    await expect(currentEffectiveTarget({ list: vi.fn().mockResolvedValue(page([row('one')])) }, 'cluster', upstream, 'echo-upstream:8081', { maxBytes: 1 })).rejects.toMatchObject({ response: { code: 'TARGET_LOOKUP_LIMIT' } });
    const cyclic = { list: vi.fn().mockResolvedValue(page([], 'repeat')) };
    await expect(currentEffectiveTarget(cyclic, 'cluster', upstream, 'echo-upstream:8081')).rejects.toMatchObject({ response: { code: 'TARGET_PAGINATION_LOOP' } });
    expect(cyclic.list).toHaveBeenCalledTimes(2);
  });
});
