import * as React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const state = vi.hoisted(() => ({ query: {} as any, options: {} as any }));
vi.mock('antd', () => ({ Alert: 'relation-alert', Button: 'relation-button', Table: 'relation-table', Tag: 'relation-tag', Typography: { Text: 'relation-text' } }));
vi.mock('@tanstack/react-query', () => ({ useQuery: (options: any) => { state.options = options; return state.query; } }));
vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }));
vi.mock('../../apps/console-web/src/app/ClusterContext', () => ({ useCluster: () => ({ clusterId: 'cluster-a' }) }));
vi.mock('../../apps/console-web/src/app/WorkspaceContext', () => ({ useWorkspace: () => ({ workspaceId: 'workspace-a', ready: true }) }));
vi.mock('../../apps/console-web/src/components/CursorPagination', () => ({ CursorPagination: 'relation-paginator', useCursorPages: () => ({ cursor: undefined }) }));
vi.mock('../../apps/console-web/src/components/Shared', () => ({ QueryError: 'relation-error' }));
import { EntityRelationList, relationUnavailableMessage } from '../../apps/console-web/src/components/EntityRelationList';

beforeEach(() => { vi.stubGlobal('React', React); state.query = {}; state.options = {}; });
afterEach(() => vi.unstubAllGlobals());
describe('M4 unavailable relationship projection remains distinct from zero objects', () => {
  it.each([['forbidden', '此关联范围未授权'], ['missing', '关联已不存在']] as const)('shows %s without a native fetch, row count or paginator', (availability, message) => {
    const view = EntityRelationList({ parentType: 'services', parentId: 'service-a', relation: 'plugins', initial: { availability, items: [], total: null } });
    expect(state.options.enabled).toBe(false); expect(state.options.initialData).toBeUndefined();
    expect(view.type).toBe('relation-alert'); expect(view.props.message).toBe(message);
    expect(view.props.description).toContain('不显示'); expect(view.props.children).toBeUndefined();
  });
  it('keeps a real authorized empty page available and its bounded cursor controls', () => {
    const initial = { items: [], nextCursor: null, size: 20, total: null } as const;
    state.query = { data: initial };
    const view = EntityRelationList({ parentType: 'services', parentId: 'service-a', relation: 'routes', initial: { ...initial, items: [] } });
    expect(state.options.enabled).toBe(true);
    const children = React.Children.toArray(view.props.children) as any[];
    expect(children[0].type).toBe('relation-table'); expect(children[1].type).toBe('relation-paginator'); expect(children[1].props.count).toBe(0);
  });
  it('suppresses cached relation rows after an explicit relationship query is denied', () => {
    state.query = { isError: true, error: new Error('denied'), data: { items: [{ id: 'former-readable-id' }] }, refetch: vi.fn() };
    const view = EntityRelationList({ parentType: 'services', parentId: 'service-a', relation: 'plugins' });
    expect(view.type).toBe('relation-error'); expect(view.props.error).toBe(state.query.error);
    expect(relationUnavailableMessage({ availability: 'forbidden' })).toBe('此关联范围未授权');
    expect(relationUnavailableMessage({ availability: 'missing' })).toBe('关联已不存在');
  });
});
