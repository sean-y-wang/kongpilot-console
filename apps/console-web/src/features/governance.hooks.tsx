import { useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, getApiActorId } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { governanceRead, governanceWrite } from '../api/governance-client';
import { useAuth } from '../app/AuthContext';
import { useM8Scope } from './m8.hooks';
import { currentCursor, nextCursorPage, type CursorState } from './m7.cursor';
import { governanceCan, governanceIdentityKey, governanceReceiptPath, governanceReceiptResult, sameGovernanceIdentity, type GovernanceIdentity, type GovernanceModule, type GovernanceOperationReference } from './governance.model';
import type { GovernanceOperationKind, GovernancePageResult } from './governance.types';

export function useGovernanceScope() {
  const base = useM8Scope(), { user } = useAuth(), identity: GovernanceIdentity = { ...base.identity };
  return { ...base, identity, user, can: (module: GovernanceModule, action: 'read' | 'write' | 'delete', whole = false) => governanceCan(user?.capabilities, module, action, { clusterId: identity.cid, workspaceId: identity.wid }, whole) };
}
export function useGovernanceQuery<T>(scope: ReturnType<typeof useGovernanceScope>, resource: string, filters: Record<string, string> = {}, enabled = true, requestIdentity?: GovernanceIdentity) {
  const captured = { ...scope.identity }, requested = { ...captured, ...requestIdentity, actor: captured.actor, version: captured.version };
  return useQuery({ queryKey: ['m10', governanceIdentityKey(captured, 'host'), governanceIdentityKey(requested, resource, filters)], queryFn: async ({ signal }) => { const value = await governanceRead<T>(requested, resource, filters, signal); scope.assertCurrent(captured); return value; }, enabled: scope.ready && enabled, retry: false, staleTime: 0, gcTime: 0 });
}
export function useGovernancePage<T>(scope: ReturnType<typeof useGovernanceScope>, resource: string, filters: Record<string, string> = {}, enabled = true, requestIdentity?: GovernanceIdentity) {
  const key = governanceIdentityKey({ ...scope.identity, ...requestIdentity }, resource, filters), [stored, setStored] = useState<CursorState>({ key, cursors: [undefined], page: 0 }), state = currentCursor(stored, key), cursor = state.cursors[state.page];
  const query = useGovernanceQuery<GovernancePageResult<T>>(scope, resource, { ...filters, size: '20', ...(cursor ? { cursor } : {}) }, enabled, requestIdentity);
  return { ...query, page: state.page + 1, previous: state.page ? () => setStored({ ...state, page: state.page - 1 }) : undefined, next: query.data?.nextCursor ? () => setStored(nextCursorPage(state, query.data!.nextCursor!)) : undefined };
}
export function useGovernanceMutation(scope: ReturnType<typeof useGovernanceScope>) {
  const queryClient = useQueryClient(), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(), [result, setResult] = useState<{ identity: GovernanceIdentity; proof: ReturnType<typeof governanceReceiptResult> }>(), [unresolved, setUnresolved] = useState<GovernanceOperationReference>(), running = useRef(false), mounted = useRef(true), controller = useRef<AbortController>();
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; controller.current?.abort(); }; }, []);
  const blocked = !!unresolved || scope.workspace.writeBlocked;
  async function mutate<T = unknown>(resource: string, method: 'POST' | 'PATCH' | 'DELETE', body: unknown, kind: GovernanceOperationKind, gate: () => boolean, requestIdentity?: GovernanceIdentity) {
    scope.assertCurrent(); if (running.current || blocked || !scope.writable || !gate()) throw new Error('当前范围不可操作，或存在待核验的原请求。');
    const captured = { ...scope.identity }, requested = { ...captured, ...requestIdentity, actor: captured.actor, version: captured.version }, reference: GovernanceOperationReference = { actorId: captured.actor!, clusterId: requested.cid!, workspaceId: requested.wid!, idempotencyKey: newIdempotencyKey(), kind }; governanceReceiptPath(reference);
    if (scope.workspace.references.some(ref => ref.cid === requested.cid && ref.wid === requested.wid)) throw new Error('此源环境存在必须核验的原请求。');
    controller.current = new AbortController(); running.current = true; setBusy(true); setError(undefined); setResult(undefined); let sent = false;
    try {
      scope.assertCurrent(captured); sent = true;
      const value = await governanceWrite<T>(requested, resource, method, body, reference.idempotencyKey, controller.current.signal);
      const receipt = await api<unknown>(governanceReceiptPath(reference), { signal: controller.current.signal }), proof = governanceReceiptResult(receipt, reference);
      if (!proof.complete) throw new ApiError(proof.label, 0, 'GOVERNANCE_RESULT_UNKNOWN');
      scope.assertCurrent(captured); if (mounted.current) setResult({ identity: captured, proof });
      await queryClient.invalidateQueries({ predicate: query => query.queryKey[0] === 'm10' }); return { value, proof, reference };
    } catch (caught) {
      const unknown = sent && (!(caught instanceof ApiError) || caught.status === 0 || caught.status >= 500 || ['INVALID_RESPONSE', 'SCOPE_CHANGED', 'SESSION_CHANGED'].includes(caught.code ?? ''));
      if (unknown) {
        window.dispatchEvent(new CustomEvent('kongos:mutation-uncertain', { detail: { actorId: reference.actorId, error: new ApiError('原治理请求结果待核验，不会自动重新提交。', 0, 'WRITE_RESULT_UNKNOWN', undefined, undefined, { kind: 'governance', scope: 'workspace', clusterId: reference.clusterId, workspaceId: reference.workspaceId, idempotencyKey: reference.idempotencyKey, state: 'uncertain' }) } }));
        if (mounted.current) setUnresolved(reference);
      }
      if (mounted.current && sameGovernanceIdentity(captured, scope.current.current)) setError(unknown ? new ApiError('原治理请求结果待核验，不会自动重新提交。', 0, 'GOVERNANCE_RESULT_UNKNOWN') : caught);
      throw caught;
    } finally { running.current = false; if (mounted.current) setBusy(false); }
  }
  async function observe() {
    const reference = unresolved; if (!reference || running.current) return; if (getApiActorId() !== reference.actorId) throw new Error('请使用原账号核验。');
    running.current = true; setBusy(true);
    try { const receipt = await api<unknown>(governanceReceiptPath(reference)), proof = governanceReceiptResult(receipt, reference); if (getApiActorId() !== reference.actorId) throw new Error('账号已切换。'); if (proof.complete) { const stored = scope.workspace.references.find(item => item.actor_id === reference.actorId && item.kind === 'governance' && item.cid === reference.clusterId && item.wid === reference.workspaceId && item.idempotencyKey === reference.idempotencyKey); if (stored) scope.workspace.resolveReference(stored); } if (mounted.current) { if (proof.complete) setUnresolved(undefined); setResult({ identity: { actor: reference.actorId, cid: reference.clusterId, wid: reference.workspaceId, version: scope.identity.version }, proof }); setError(undefined); } await queryClient.invalidateQueries({ predicate: query => query.queryKey[0] === 'm10' }); }
    catch (caught) { if (mounted.current) setError(caught); }
    finally { running.current = false; if (mounted.current) setBusy(false); }
  }
  return { mutate, observe, busy, error, blocked, unresolved, result: result && sameGovernanceIdentity(result.identity, scope.identity) ? result.proof : undefined };
}
