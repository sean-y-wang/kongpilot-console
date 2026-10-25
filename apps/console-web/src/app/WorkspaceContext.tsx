import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { api, ApiError } from '../api/client';
import { canonicalId, recoveryStorageKey, safeRecoveryReferences, validRecoveryScope, workspaceSelectionForScope, type RecoveryReference } from '../api/workspace-scope';
import { useAuth } from './AuthContext';
import { useCluster } from './ClusterContext';

export interface Workspace { id: string; cluster_id: string; code: string; name: string; owner_user_id?: string | null; description?: string | null; status: 'active' | 'disabled' | 'deleted'; is_default: boolean; revision: number; deleted_at?: string | null; created_at: string; updated_at: string; }
export interface WorkspacePageData { items: Workspace[]; nextCursor: string | null; size: number; total: null; }
interface WorkspaceValue {
  workspaceId?: string; workspace?: Workspace; defaultWorkspaceId?: string; readonlyWorkspace: boolean; workspaces: Workspace[]; ready: boolean; loading: boolean; error?: unknown;
  selectionNotice?: string; selectWorkspace: (id: string) => void; selectScopeWorkspace: (clusterId: string, workspaceId: string) => void; refresh: () => Promise<unknown>; loadMore: () => Promise<unknown>; hasMore: boolean; loadingMore: boolean;
  references: RecoveryReference[]; writeBlocked: boolean; resolveReference: (reference: RecoveryReference) => void;
}
const WorkspaceContext = createContext<WorkspaceValue | null>(null);
function storageRead(actorId: string) { try { return safeRecoveryReferences(JSON.parse(sessionStorage.getItem(recoveryStorageKey) ?? '[]'), actorId); } catch { return []; } }

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const { clusterId, clusters } = useCluster();
  const { user } = useAuth();
  const [selected, setSelected] = useState<Record<string, string>>({});
  const [references, setReferences] = useState<RecoveryReference[]>(() => storageRead(user!.id));
  const preferred = clusterId ? selected[clusterId] ?? canonicalId(sessionStorage.getItem(`kongos.workspaceId.${clusterId}`)) : undefined;
  const list = useInfiniteQuery({ queryKey: ['workspace-options', clusterId, 'registry'], initialPageParam: undefined as string | undefined, queryFn: ({ pageParam }) => api<WorkspacePageData>(`/clusters/${clusterId}/workspaces?size=20${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ''}`), getNextPageParam: page => page.nextCursor ?? undefined, enabled: !!clusterId });
  const rows = useMemo(() => [...new Map((list.data?.pages.flatMap(page => page.items) ?? []).map(row => [row.id, row])).values()], [list.data]);
  const inOptions = rows.find(row => row.id === preferred);
  const preferredQuery = useQuery({ queryKey: ['workspace-selection', clusterId, preferred], queryFn: () => api<Workspace>(`/clusters/${clusterId}/workspaces/${preferred}`), enabled: !!clusterId && !!preferred && !inOptions });
  const preferredRow = inOptions ?? preferredQuery.data;
  const invalidSelection = !!preferred && (!!preferredRow && preferredRow.status === 'deleted' || preferredQuery.error instanceof ApiError && [403, 404, 410].includes(preferredQuery.error.status));
  const workspace = preferred && !invalidSelection ? preferredRow : rows.find(row => row.is_default) ?? rows[0];
  const workspaceId = canonicalId(workspace?.id);
  const workspaces = preferredRow && preferredRow.status !== 'deleted' && !inOptions ? [preferredRow, ...rows] : rows;
  useEffect(() => {
    if (clusterId && workspaceId) { sessionStorage.setItem(`kongos.workspaceId.${clusterId}`, workspaceId); if (invalidSelection) setSelected(values => ({ ...values, [clusterId]: workspaceId })); }
  }, [clusterId, workspaceId, invalidSelection]);
  useEffect(() => {
    const filtered = storageRead(user!.id); setReferences(filtered);
    const received = (event: Event) => {
      const detail = (event as CustomEvent<{ actorId?: string; error: ApiError }>).detail;
      if (!detail?.error || detail.actorId && detail.actorId !== user!.id) return;
      const recovery = detail.error.recovery;
      if (!recovery?.idempotencyKey || !validRecoveryScope({ ...recovery, cid: recovery.clusterId, wid: recovery.workspaceId })) return;
      const reference: RecoveryReference = { actor_id: user!.id, ...(recovery.domain === 'iam' ? { domain: 'iam' } : { cid: recovery.clusterId, wid: recovery.workspaceId, kind: recovery.kind, scope: recovery.scope }), idempotencyKey: recovery.idempotencyKey, operationId: recovery.operationId, ...(recovery.originalJobId ? { originalJobId: recovery.originalJobId, originalJobKey: recovery.originalJobKey, abandonmentIntent: recovery.abandonmentIntent } : {}), created_at: new Date().toISOString(), state: recovery.state ?? 'uncertain' };
      setReferences(values => {
        const old = values.find(item => item.idempotencyKey === reference.idempotencyKey && item.domain === reference.domain && item.kind === reference.kind && item.cid === reference.cid && item.wid === reference.wid);
        if (old) reference.created_at = old.created_at;
        return safeRecoveryReferences([...values.filter(item => item !== old), reference], user!.id);
      });
    };
    window.addEventListener('kongos:mutation-uncertain', received);
    return () => window.removeEventListener('kongos:mutation-uncertain', received);
  }, [user?.id]);
  useEffect(() => { if (references.length) sessionStorage.setItem(recoveryStorageKey, JSON.stringify(references)); else sessionStorage.removeItem(recoveryStorageKey); }, [references]);
  useEffect(() => { const timer = window.setInterval(() => setReferences(values => safeRecoveryReferences(values, user!.id)), 60_000); return () => window.clearInterval(timer); }, [user?.id]);
  function selectWorkspace(id: string) { const canonical = canonicalId(id); if (clusterId && canonical) { setSelected(values => ({ ...values, [clusterId]: canonical })); sessionStorage.setItem(`kongos.workspaceId.${clusterId}`, canonical); } }
  function selectScopeWorkspace(cid: string, wid: string) { const clusterIds = clusters.map(cluster => cluster.id), targetCid = canonicalId(cid)!, targetWid = canonicalId(wid)!; workspaceSelectionForScope({}, clusterIds, cid, wid); setSelected(values => workspaceSelectionForScope(values, clusterIds, cid, wid)); sessionStorage.setItem(`kongos.workspaceId.${targetCid}`, targetWid); }
  function resolveReference(reference: RecoveryReference) { setReferences(values => values.filter(item => !(item.actor_id === reference.actor_id && item.domain === reference.domain && item.kind === reference.kind && item.cid === reference.cid && item.wid === reference.wid && item.idempotencyKey === reference.idempotencyKey))); }
  const error = list.error ?? (!invalidSelection ? preferredQuery.error : undefined);
  return <WorkspaceContext.Provider value={{ workspaceId, workspace, defaultWorkspaceId: rows.find(row => row.is_default)?.id, readonlyWorkspace: workspace?.status === 'disabled', workspaces, ready: !!clusterId && !!workspaceId, loading: list.isLoading || !!preferred && !preferredRow && preferredQuery.isLoading, error, selectionNotice: invalidSelection ? preferredQuery.error instanceof ApiError && preferredQuery.error.status === 403 ? '原工作区已不可访问，已切换至当前可访问工作区。' : '原工作区已删除，已切换至当前可访问工作区。' : undefined, selectWorkspace, selectScopeWorkspace, refresh: async () => { await list.refetch(); if (preferred) await preferredQuery.refetch(); }, loadMore: () => list.fetchNextPage(), hasMore: !!list.hasNextPage, loadingMore: list.isFetchingNextPage, references, writeBlocked: references.some(item => item.cid === clusterId && item.wid === workspaceId), resolveReference }}>{children}</WorkspaceContext.Provider>;
}
export function useWorkspace() { const context = useContext(WorkspaceContext); if (!context) throw new Error('WorkspaceProvider is required'); return context; }
export function useOptionalWorkspace() { return useContext(WorkspaceContext); }
