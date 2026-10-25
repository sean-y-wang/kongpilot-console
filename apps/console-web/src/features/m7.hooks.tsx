import { useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Space, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { api, ApiError, getApiActorId } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { canonicalId, scopeQuery, type RecoveryKind } from '../api/workspace-scope';
import { useAuth } from '../app/AuthContext';
import { useCluster } from '../app/ClusterContext';
import { useWorkspace } from '../app/WorkspaceContext';
import { usePermissions } from '../app/Permissions';
import { currentCursor, m7QueryIdentity, nextCursorPage, sameM7Identity, type CursorState, type M7Identity } from './m7.cursor';
import { m7ReceiptPath, m7ReceiptResult, type M7Reference, type M7Result } from './m7.results';
import type { M7Page } from './m7.types';

export function useM7Scope(mode: M7Identity['mode'] = 'workspace') {
  const { user } = useAuth(), cluster = useCluster(), workspace = useWorkspace(), permission = usePermissions();
  const identity: M7Identity = { actor: user?.id, version: permission.version, mode, ...(mode !== 'global' ? { cid: canonicalId(cluster.clusterId) } : {}), ...(mode === 'workspace' ? { wid: canonicalId(workspace.workspaceId) } : {}) };
  const current = useRef(identity), mounted = useRef(true); current.current = identity;
  useEffect(() => { mounted.current = true; current.current = identity; return () => { mounted.current = false; current.current = { ...current.current, actor: undefined }; }; }, []);
  const ready = !!identity.actor && !!identity.version && (mode === 'global' || !!identity.cid && (mode === 'cluster' || !!identity.wid));
  function assertCurrent(captured = identity) { if (!mounted.current || getApiActorId() !== captured.actor || !sameM7Identity(current.current, captured)) throw new ApiError('账号、权限或范围已变化，请重新审阅。', 409, 'SCOPE_CHANGED'); }
  function whole(module: string, action: 'read' | 'write' | 'delete' = 'read', wholeCluster = false) { return !!user?.capabilities?.platformAdmin || !!user?.capabilities?.grants.some(grant => grant.module === module && grant.action === action && (!grant.cluster_id || grant.cluster_id === identity.cid) && (wholeCluster || mode === 'global' ? grant.scope_type === 'global' && !grant.workspace_id && (mode !== 'global' || !grant.cluster_id) : grant.scope_type === 'global' && (!grant.workspace_id || grant.workspace_id === identity.wid) || grant.scope_type === 'workspace' && grant.workspace_id === identity.wid && grant.scope_values.includes(identity.wid!))); }
  function path(resource: string, filters: Record<string, string> = {}) { const params = new URLSearchParams(filters); if (mode === 'global') return `${resource}${params.size ? `?${params}` : ''}`; if (mode === 'workspace') return scopeQuery(`/clusters/${identity.cid}/${resource}${params.size ? `?${params}` : ''}`, identity.cid, identity.wid); params.set('scope', 'cluster'); return `/clusters/${identity.cid}/${resource}?${params}`; }
  function personal(resource: string, filters: Record<string, string> = {}) { const params = new URLSearchParams(filters); if (identity.cid) params.set('clusterId', identity.cid); if (identity.wid) params.set('workspaceId', identity.wid); return `/notifications${resource ? `/${resource}` : ''}${params.size ? `?${params}` : ''}`; }
  return { ...identity, identity, current, ready, workspace, permission, assertCurrent, whole, path, personal };
}
export function useM7Page<T>(identity: M7Identity, resource: string, path: (filters: Record<string, string>) => string, filters: Record<string, string> = {}, enabled = true) {
  const key = m7QueryIdentity(identity, resource, filters), [stored, setStored] = useState<CursorState>({ key, cursors: [undefined], page: 0 }), state = currentCursor(stored, key), cursor = state.cursors[state.page];
  const query = useQuery({ queryKey: ['m7', key, cursor], queryFn: ({ signal }) => api<M7Page<T>>(path({ ...filters, size: '20', ...(cursor ? { cursor } : {}) }), { signal }), enabled, retry: false, gcTime: 0, staleTime: 0 });
  return { ...query, page: state.page + 1, previous: state.page ? () => setStored({ ...state, page: state.page - 1 }) : undefined, next: query.data?.nextCursor ? () => setStored(nextCursorPage(state, query.data!.nextCursor!)) : undefined };
}
export function M7Pager({ query }: { query: { page: number; previous?: () => void; next?: () => void; isFetching: boolean; data?: { scanIncomplete?: boolean; scanLimitReached?: boolean } } }) { return <><Space style={{ marginTop: 16 }}><Button disabled={!query.previous || query.isFetching} onClick={query.previous}>上一页</Button><Typography.Text>第 {query.page} 页</Typography.Text><Button disabled={!query.next || query.isFetching} onClick={query.next}>下一页</Button></Space>{(query.data?.scanIncomplete || query.data?.scanLimitReached) && <Alert style={{ marginTop: 12 }} type="warning" message="本页已达到扫描预算，请使用下一页或缩小过滤范围" />}</>; }
export function useM7Mutation(scope: ReturnType<typeof useM7Scope>) {
  const queryClient = useQueryClient(), [result, setResult] = useState<M7Result>(), [error, setError] = useState<unknown>(), [busy, setBusy] = useState(false), alive = useRef(true), running = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const blocked = scope.workspace.references.some(ref => ['events', 'notifications', 'audit-export', 'audit-global-export'].includes(ref.kind ?? '') && ref.cid === scope.cid && ref.wid === scope.wid);
  async function mutate(path: string, method: string, body: unknown, kind: RecoveryKind) {
    scope.assertCurrent(); if (running.current || blocked) throw new Error('请先核验当前范围的原操作回执。'); const captured = { ...scope.identity }, key = newIdempotencyKey(), url = new URL(path, 'https://console.invalid'), requestCid = canonicalId(url.searchParams.get('clusterId')) ?? canonicalId(url.pathname.match(/^\/clusters\/([^/]+)/)?.[1]), requestWid = canonicalId(url.searchParams.get('workspaceId'));
    const ref: M7Reference = { kind, clusterId: requestCid, workspaceId: requestWid, scope: requestWid ? 'workspace' : requestCid ? 'cluster' : 'global', idempotencyKey: key }; m7ReceiptPath(ref);
    if (scope.workspace.references.some(item => item.actor_id === captured.actor && isM7Reference(item.kind) && item.cid === ref.clusterId && item.wid === ref.workspaceId)) throw new Error('此原操作范围仍有未知结果，请先核验。');
    running.current = true; let acknowledged = false;
    setBusy(true); setError(undefined);
    try { const value = await api<unknown>(path, { method, body: JSON.stringify(body), headers: { 'X-Idempotency-Key': key } }); acknowledged = true; scope.assertCurrent(captured); const receipt = await api<unknown>(m7ReceiptPath(ref)); scope.assertCurrent(captured); const verified = m7ReceiptResult(receipt, ref);
      if (!verified.complete) { const unknown = new ApiError('请求已返回，但原回执尚未完整确认。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { ...ref, state: 'uncertain' }); window.dispatchEvent(new CustomEvent('kongos:mutation-uncertain', { detail: { actorId: captured.actor, error: unknown } })); throw unknown; }
      if (alive.current) setResult(verified); await queryClient.invalidateQueries({ predicate: query => query.queryKey[0] === 'm7' }); return { value, receipt, verified };
    } catch (e) { let raised = e; if (acknowledged && !(e instanceof ApiError && e.code === 'WRITE_RESULT_UNKNOWN')) { raised = new ApiError('请求已返回，原结果尚未核验；请勿重新提交。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { ...ref, state: 'uncertain' }); window.dispatchEvent(new CustomEvent('kongos:mutation-uncertain', { detail: { actorId: captured.actor, error: raised } })); } if (alive.current) setError(raised); throw raised; } finally { running.current = false; if (alive.current) setBusy(false); }
  }
  return { mutate, result, error, busy, blocked };
}
function isM7Reference(kind?: string) { return ['events', 'notifications', 'audit-export', 'audit-global-export'].includes(kind ?? ''); }
export function M7MutationNotice({ result, allowWorkflowLink = false }: { result?: M7Result; allowWorkflowLink?: boolean }) { return result ? <Alert style={{ marginBottom: 18 }} type={result.success ? 'success' : 'warning'} showIcon message={result.label} description={result.workflowId && allowWorkflowLink ? <Link to={`/workflows/${result.workflowId}`}>查看当前授权的工单详情</Link> : undefined} /> : null; }
