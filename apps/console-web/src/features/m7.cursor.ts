export interface M7Identity { actor?: string; version?: string; cid?: string; wid?: string; mode: 'workspace' | 'cluster' | 'global'; }
export interface CursorState { key: string; cursors: Array<string | undefined>; page: number; }
export function m7QueryIdentity(identity: M7Identity, resource: string, filters: Record<string, string>): string {
  return JSON.stringify([identity.actor, identity.version, identity.cid, identity.wid, identity.mode, resource, Object.entries(filters).sort(([a], [b]) => a.localeCompare(b))]);
}
export function currentCursor(state: CursorState, key: string): CursorState { return state.key === key ? state : { key, cursors: [undefined], page: 0 }; }
export function nextCursorPage(state: CursorState, next: string): CursorState { if (!next || next.length > 24576) throw new Error('分页游标无效。'); return { key: state.key, cursors: [...state.cursors.slice(0, state.page + 1), next], page: state.page + 1 }; }
export function sameM7Identity(a: M7Identity, b: M7Identity): boolean { return a.actor === b.actor && a.version === b.version && a.cid === b.cid && a.wid === b.wid && a.mode === b.mode; }
