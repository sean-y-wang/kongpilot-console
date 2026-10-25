import { useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Space, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { api, ApiError, getApiActorId } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { useM7Scope } from './m7.hooks';
import { currentCursor, nextCursorPage, type CursorState } from './m7.cursor';
import { configurationPath, configurationQueryIdentity, configurationReceiptPath, configurationReceiptResult, sameConfigurationIdentity, configurationDetailEntity, configurationSelectionQuery, type ConfigurationReference } from './m8.model';
import type { ConfigurationIdentity, ConfigurationPage, ConfigurationSelection } from './m8.types';

export function useM8Scope() {
  const base = useM7Scope(), identity: ConfigurationIdentity = { actor: base.actor, version: base.version, cid: base.cid, wid: base.wid }, current = useRef(identity), mounted = useRef(true);
  current.current = identity;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  function assertCurrent(captured = identity) { if (!mounted.current || getApiActorId() !== captured.actor || !sameConfigurationIdentity(current.current, captured)) throw new ApiError('账号、权限或配置范围已变化，请重新审阅。', 409, 'SCOPE_CHANGED'); }
  return { ...base, identity, current, assertCurrent, path: (resource: string, filters: Record<string, string> = {}) => configurationPath(identity, resource, filters), writable: base.ready && !base.workspace.readonlyWorkspace };
}
export function useM8ListScope(scope: ReturnType<typeof useM8Scope>) {
  const key = configurationQueryIdentity(scope.identity, 'list-scope'), [stored, setStored] = useState<{ key: string; value: ConfigurationSelection }>({ key, value: { scope: 'workspace', serviceIds: [] } });
  const value: ConfigurationSelection = stored.key === key ? stored.value : { scope: 'workspace', serviceIds: [] };
  return { value, filters: configurationSelectionQuery(value), select: (selected: ConfigurationSelection) => { configurationSelectionQuery(selected); setStored({ key, value: selected }); } };
}
export function useM8Query<T>(scope: ReturnType<typeof useM8Scope>, resource: string, filters: Record<string, string> = {}, enabled = true) {
  const captured = { ...scope.identity };
  return useQuery({ queryKey: ['m8', configurationQueryIdentity(captured, resource, filters)], queryFn: async ({ signal }) => { const value = await api<T>(configurationPath(captured, resource, filters), { signal }); scope.assertCurrent(captured); return value; }, enabled: scope.ready && enabled, retry: false, staleTime: 0, gcTime: 0 });
}
export function useM8Detail<T extends { id: string; clusterId: string; workspaceId: string }>(scope: ReturnType<typeof useM8Scope>, resource: string, id?: string, enabled = true) {
  const captured = { ...scope.identity };
  return useQuery({ queryKey: ['m8', configurationQueryIdentity(captured, resource)], queryFn: async ({ signal }) => { const value = await api<unknown>(configurationPath(captured, resource), { signal }); scope.assertCurrent(captured); return configurationDetailEntity<T>(value, captured, id!); }, enabled: scope.ready && !!id && enabled, retry: false, staleTime: 0, gcTime: 0 });
}
export function useM8Page<T>(scope: ReturnType<typeof useM8Scope>, resource: string, filters: Record<string, string> = {}, enabled = true) {
  const key = configurationQueryIdentity(scope.identity, resource, filters), [stored, setStored] = useState<CursorState>({ key, cursors: [undefined], page: 0 }), state = currentCursor(stored, key), cursor = state.cursors[state.page];
  const query = useM8Query<ConfigurationPage<T>>(scope, resource, { ...filters, size: '20', ...(cursor ? { cursor } : {}) }, enabled);
  return { ...query, page: state.page + 1, previous: state.page ? () => setStored({ ...state, page: state.page - 1 }) : undefined, next: query.data?.nextCursor ? () => setStored(nextCursorPage(state, query.data!.nextCursor!)) : undefined };
}
export function M8Pager({ query }: { query: { page: number; previous?: () => void; next?: () => void; isFetching: boolean } }) { return <Space style={{ marginTop: 16 }}><Button disabled={!query.previous || query.isFetching} onClick={query.previous}>上一页</Button><Typography.Text>第 {query.page} 页</Typography.Text><Button disabled={!query.next || query.isFetching} onClick={query.next}>下一页</Button></Space>; }
export function useM8Mutation(scope: ReturnType<typeof useM8Scope>) {
  const client = useQueryClient(), [error, setError] = useState<unknown>(), [busy, setBusy] = useState(false), [result, setResult] = useState<{ identity: ConfigurationIdentity; proof: ReturnType<typeof configurationReceiptResult> }>(), alive = useRef(true), running = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const blocked = scope.workspace.writeBlocked || scope.workspace.references.some(ref => ref.kind === 'configuration' && ref.cid === scope.cid && ref.wid === scope.wid);
  async function mutate(resource: string, method: string, body: unknown) {
    scope.assertCurrent(); if (!scope.writable || running.current || blocked) throw new Error('当前范围不可写，或存在必须先核验的原作业。');
    const captured = { ...scope.identity }, key = newIdempotencyKey(), ref: ConfigurationReference = { kind: 'configuration', clusterId: captured.cid, workspaceId: captured.wid, idempotencyKey: key, actorId: captured.actor }, path = configurationPath(captured, resource);
    configurationReceiptPath(ref); running.current = true; setBusy(true); setError(undefined); let acknowledged = false;
    try {
      const value = await api<unknown>(path, { method, body: JSON.stringify(body), headers: { 'X-Idempotency-Key': key } }); acknowledged = true;
      const receipt = await api<unknown>(configurationReceiptPath(ref)); const verified = configurationReceiptResult(receipt, ref);
      if (!verified.complete) throw new ApiError(verified.label, verified.pending ? 202 : 0, verified.pending ? 'CONFIGURATION_EXECUTION_PENDING' : 'WRITE_RESULT_UNKNOWN', undefined, undefined, { ...ref, kind: 'configuration', scope: 'workspace', state: verified.pending ? 'running' : 'uncertain' });
      scope.assertCurrent(captured); if (alive.current) setResult({ identity: captured, proof: verified });
      await client.invalidateQueries({ predicate: query => query.queryKey[0] === 'm8' }); return { value, receipt, verified, key };
    } catch (caught) {
      let raised = caught;
      if (acknowledged && !(caught instanceof ApiError && ['WRITE_RESULT_UNKNOWN', 'CONFIGURATION_EXECUTION_PENDING'].includes(caught.code ?? ''))) raised = new ApiError('请求已返回，原范围结果仍须核验；不会重新提交。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { ...ref, kind: 'configuration', scope: 'workspace', state: 'uncertain' });
      if (raised instanceof ApiError && raised.recovery?.idempotencyKey && ['uncertain', 'partial', 'running'].includes(raised.recovery.state ?? '')) window.dispatchEvent(new CustomEvent('kongos:mutation-uncertain', { detail: { actorId: captured.actor, error: raised } }));
      if (alive.current && sameConfigurationIdentity(captured, scope.current.current)) setError(raised); throw raised;
    } finally { running.current = false; if (alive.current) setBusy(false); }
  }
  return { mutate, error, busy, blocked, result: result && sameConfigurationIdentity(result.identity, scope.identity) ? result.proof : undefined };
}
export function M8MutationNotice({ result, allowWorkflow = false }: { result?: ReturnType<typeof configurationReceiptResult>; allowWorkflow?: boolean }) { return result ? <Alert style={{ marginBottom: 18 }} type={result.success ? 'success' : 'warning'} showIcon message={result.label} description={<Space wrap>{result.jobId && <Link to={`/configuration/jobs/${result.jobId}`}>作业与逐对象结果</Link>}{result.workflowId && allowWorkflow && <Link to={`/workflows/${result.workflowId}`}>查看真实工单</Link>}</Space>} /> : null; }
