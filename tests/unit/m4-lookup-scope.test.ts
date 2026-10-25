import * as React from 'react';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
const state = vi.hoisted(() => ({ values: [] as any[], index: 0, effects: [] as (() => void)[], query: {} as any, version: 'epoch-a', actor: 'actor-a', queries: [] as any[] }));
vi.mock('react', async () => { const actual = await vi.importActual<any>('react'); return { ...actual, useState: (initial: any) => { const index = state.index++; if (!(index in state.values)) state.values[index] = typeof initial === 'function' ? initial() : initial; return [state.values[index], (next: any) => { state.values[index] = typeof next === 'function' ? next(state.values[index]) : next; }]; }, useEffect: (effect: () => void) => { state.effects.push(effect); } }; });
vi.mock('antd', () => ({ Button: 'lookup-button', Select: 'lookup-select' }));
vi.mock('@tanstack/react-query', () => ({ useQuery: (options: any) => { state.queries.push(options); return state.query; } }));
vi.mock('../../apps/console-web/src/app/Permissions', () => ({ usePermissions: () => ({ version: state.version }) }));
vi.mock('../../apps/console-web/src/app/AuthContext', () => ({ useAuth: () => ({ user: { id: state.actor } }) }));
vi.mock('../../apps/console-web/src/components/Shared', () => ({ QueryError: 'lookup-error' }));
import { IAMWorkspaceLookup, PagedIAMLookup, ScopedEntityLookup } from '../../apps/console-web/src/features/IAMLookups';
function select(element: any): any { if (element.type === 'lookup-select') return element; for (const child of React.Children.toArray(element.props?.children)) if (child && typeof child === 'object') { const found = select(child); if (found) return found; } }
function render(component: any, props: any) { state.index = 0; state.effects = []; return select(component(props)); }
function applyEffects() { state.effects.forEach(effect => effect()); }
beforeEach(() => { state.values = []; state.queries = []; state.query = {}; state.version = 'epoch-a'; state.actor = 'actor-a'; vi.stubGlobal('React', React); });
afterEach(() => vi.unstubAllGlobals());

describe('M4 bounded lookup visibility during scope transitions', () => {
  it.each([
    [PagedIAMLookup, { resource: 'roles', clusterId: 'cluster-a', workspaceId: 'workspace-a', label: 'role_id' }, { resource: 'roles', clusterId: 'cluster-b', workspaceId: 'workspace-b', label: 'role_id' }],
    [ScopedEntityLookup, { type: 'services', clusterId: 'cluster-a', workspaceId: 'workspace-a', label: 'entity_id' }, { type: 'services', clusterId: 'cluster-b', workspaceId: 'workspace-b', label: 'entity_id' }],
    [IAMWorkspaceLookup, { clusterId: 'cluster-a', label: 'workspace_id' }, { clusterId: 'cluster-b', label: 'workspace_id' }],
  ])('clears previous options before effects run after a cluster/workspace change', (component, before, after) => {
    state.query = { data: { items: [{ id: 'entity-a', name: 'only-authorized-in-a' }] } };
    render(component, before); applyEffects(); expect(render(component, before).props.options).toHaveLength(1);
    state.query = {};
    const changed = render(component, after);
    expect(changed.props.options).toEqual([]); expect(state.queries.at(-1).queryKey).toContain('cluster-b');
  });
  it('does not preserve previous options across a permissions epoch change', () => {
    state.query = { data: { items: [{ id: 'user-a', username: 'previously-authorized-user' }] } };
    const props = { label: 'owner_id', clusterId: 'cluster-a', workspaceId: 'workspace-a' };
    render(PagedIAMLookup, props); applyEffects(); expect(render(PagedIAMLookup, props).props.options).toHaveLength(1);
    state.version = 'epoch-b'; state.query = {};
    expect(render(PagedIAMLookup, props).props.options).toEqual([]);
  });
  it('does not send an unsupported server search for credential/Target child pages', () => {
    const field = render(ScopedEntityLookup, { type: 'key-auth', clusterId: 'cluster-a', workspaceId: 'workspace-a', parentId: 'consumer-a', label: 'entity_id' });
    expect(field.props.filterOption).toBe(true); expect(field.props.onSearch).toBeUndefined();
    expect(field.props.placeholder).toContain('分页');
  });
  it('emits only a Target from the current actor/parent authorized page and clears rows on actor switch', () => {
    const row = { id: 'target-a', target: 'echo.internal:80', weight: 100, upstream: { id: 'upstream-a' } }, selected = vi.fn(), changed = vi.fn();
    const props = { type: 'targets', clusterId: 'cluster-a', workspaceId: 'workspace-a', parentId: 'upstream-a', label: 'Target', onSelected: selected, onChange: changed };
    state.query = { data: { items: [row] } }; render(ScopedEntityLookup, props); applyEffects();
    const field = render(ScopedEntityLookup, props); field.props.onChange(row.id); expect(changed).toHaveBeenCalledWith(row.id); expect(selected).toHaveBeenCalledWith(row);
    field.props.onChange('not-in-loaded-pages'); expect(selected).toHaveBeenLastCalledWith(undefined);
    state.actor = 'actor-b'; state.query = {}; const next = render(ScopedEntityLookup, props);
    expect(next.props.options).toEqual([]); expect(state.queries.at(-1).queryKey).toContain('actor-b'); next.props.onChange(row.id); expect(selected).toHaveBeenLastCalledWith(undefined);
  });
});
