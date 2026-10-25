import { api, ApiError } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { workflowReceiptMatches, workflowReceiptProvesCompletion } from '../api/workflow-recovery';
import type { Session } from '../api/types';
import { normalizeEntityChangeIntent, targetHealthRollbackUnavailableReason, type EntityChangeIntent, type WorkflowIdentity } from './workflow-entity-change.model';

export type TargetWorkflowAction = 'create' | 'weight' | 'health' | 'delete';
export interface TargetWorkflowScope extends WorkflowIdentity { upstreamId: string; }
export interface TargetWorkflowSelection { action: TargetWorkflowAction; targetId?: string; healthState?: 'healthy' | 'unhealthy'; }
export interface TargetWorkflowAttempt extends TargetWorkflowScope, TargetWorkflowSelection {
  stage: 'prepare' | 'submit'; state: 'pending' | 'unknown' | 'failed' | 'prepared'; key: string;
  intentId?: string; revision?: number; materialHmac?: string;
}
const object = (value: unknown): value is Record<string, any> => !!value && typeof value === 'object' && !Array.isArray(value) && [null, Object.prototype].includes(Object.getPrototypeOf(value));
const id = (value: unknown): value is string => typeof value === 'string' && canonicalId(value) === value;
const hex = (value: unknown): value is string => typeof value === 'string' && /^[a-f\d]{64}$/.test(value);
const weight = (value: unknown): value is number => Number.isInteger(value) && Number(value) >= 0 && Number(value) <= 1000;
const address = (value: unknown): value is string => typeof value === 'string' && !!value.trim() && value.length <= 512 && !/[\u0000-\u0020\u007f]/.test(value);
function fail(message = 'Target 范围或原回执已变化，请重新读取。'): never { throw new ApiError(message, 409, 'TARGET_WORKFLOW_SCOPE_CHANGED'); }
export function targetWorkflowScope(value: TargetWorkflowScope): TargetWorkflowScope {
  if (![value.actor, value.cid, value.wid, value.upstreamId].every(id) || typeof value.version !== 'string' || !value.version || value.version.length > 256 || !['direct', 'approval'].includes(value.mode ?? '')) fail();
  return { actor: value.actor, version: value.version, cid: value.cid, wid: value.wid, mode: value.mode, upstreamId: value.upstreamId };
}
export function sameTargetWorkflowScope(a: TargetWorkflowScope, b: TargetWorkflowScope) {
  return ['actor', 'version', 'cid', 'wid', 'mode', 'upstreamId'].every(key => a[key as keyof TargetWorkflowScope] === b[key as keyof TargetWorkflowScope]);
}
function selectionValid(value: TargetWorkflowSelection): boolean {
  return ['create', 'weight', 'health', 'delete'].includes(value.action) && (value.action === 'create' ? value.targetId === undefined : id(value.targetId))
    && (value.action === 'health' ? ['healthy', 'unhealthy'].includes(value.healthState ?? '') : value.healthState === undefined);
}
export function targetWorkflowSelection(scope: TargetWorkflowScope, action: TargetWorkflowAction, row?: unknown, healthState?: 'healthy' | 'unhealthy'): TargetWorkflowSelection {
  targetWorkflowScope(scope);
  const selected = { action, ...(action === 'create' ? {} : { targetId: object(row) ? row.id : undefined }), ...(healthState ? { healthState } : {}) };
  if (!selectionValid(selected) || action === 'create' && row !== undefined || action !== 'create'
    && (!object(row) || !object(row.upstream) || row.upstream.id !== scope.upstreamId || !address(row.target) || !weight(row.weight))) fail('请选择当前 Upstream 下的有效 Target。');
  return selected;
}
export function targetWorkflowFormDefaults(row?: Record<string, any>) {
  return row ? { target: row.target, weight: row.weight, tags: (Array.isArray(row.tags) ? row.tags : []).filter((tag: unknown) => typeof tag === 'string' && !/^workspace:|^kos-ws-/i.test(tag)) }
    : { weight: 100, tags: [] };
}
/** Only a genuine current health row enables a manual override entry. Neither
 * an Upstream configuration nor a matching address can substitute its UUID. */
export function targetManualHealthAvailable(rows: unknown, target: unknown, upstreamId: string) {
  if (!Array.isArray(rows) || !object(target) || !id(target.id) || target.upstream?.id !== upstreamId) return false;
  const selected = rows.filter(row => object(row) && row.id === target.id);
  return selected.length === 1 && selected[0].target === target.target && selected[0].weight === target.weight && selected[0].upstream?.id === upstreamId && ['HEALTHY', 'UNHEALTHY'].includes(selected[0].health);
}
export function targetWorkflowChange(scope: TargetWorkflowScope, selection: TargetWorkflowSelection, body?: unknown, confirmation?: string) {
  targetWorkflowScope(scope); if (!selectionValid(selection)) fail();
  if (selection.action === 'health') {
    if (body !== undefined) fail('健康置位不接受 Target 配置。');
    return { kind: 'target', action: 'health', upstreamId: scope.upstreamId, targetId: selection.targetId!, state: selection.healthState! } as const;
  }
  if (selection.action === 'delete') {
    if (body !== undefined || !address(confirmation)) fail('删除 Target 需要输入原目标地址确认。');
    return { kind: 'recycle', action: 'delete', entityType: 'targets', entityId: selection.targetId!, parentId: scope.upstreamId, confirmed: true, confirm_name: confirmation } as const;
  }
  if (!object(body) || Object.keys(body).some(key => !['target', 'weight', 'tags'].includes(key))
    || selection.action === 'create' && !address(body.target) || body.target !== undefined && !address(body.target)
    || !weight(body.weight)
    || body.tags !== undefined && (!Array.isArray(body.tags) || body.tags.length > 1000 || body.tags.some((tag: unknown) => typeof tag !== 'string' || !tag || tag.length > 1024 || /^workspace:|^kos-ws-/i.test(tag)))) fail('请提供有效的目标地址、0–1000 权重和业务标签。');
  const encoded = JSON.stringify(body);
  if (encoded.length > 128 * 1024 || /\[REDACTED(?::[^\]]*)?\]/.test(encoded)) fail('Target 表单不完整，请重新填写。');
  return { kind: 'target', action: selection.action, upstreamId: scope.upstreamId,
    ...(selection.action === 'weight' ? { targetId: selection.targetId } : {}), body: JSON.parse(encoded) };
}
/** The immutable BFF subject proves parent/action. Review bodies alone never
 * prove that a Target belongs to the selected Upstream. */
export function normalizeTargetWorkflowIntent(raw: unknown, scope: TargetWorkflowScope, selection: TargetWorkflowSelection, submittedBody?: unknown): EntityChangeIntent {
  targetWorkflowScope(scope);
  if (!selectionValid(selection) || !object(raw) || !object(raw.targetSubject) || raw.targetSubject.upstreamId !== scope.upstreamId
    || raw.targetSubject.action !== selection.action || raw.targetSubject.targetId !== selection.targetId || raw.targetSubject.state !== selection.healthState
    || raw.nativeExecutionAvailable !== false || raw.schedule !== undefined || raw.executionMode !== 'approval'
    || raw.review?.clusterId !== scope.cid || raw.review?.workspaceId !== scope.wid) fail();
  const intent = normalizeEntityChangeIntent(raw);
  if (intent.review.changes.length !== 1 || intent.review.impact.nativePackets !== 1) fail();
  const change = intent.review.changes[0], before = change.before, after = change.after;
  if (change.entityType !== 'targets') fail();
  if (selection.action !== 'create' && (!object(before) || before.id !== selection.targetId || before.upstream?.id !== scope.upstreamId || !address(before.target) || !weight(before.weight))) fail();
  if (selection.action === 'create' || selection.action === 'weight') {
    if (change.action !== (selection.action === 'create' ? 'create' : 'update') || !object(after) || after.id !== change.nativeId || !address(after.target) || !weight(after.weight)
      || after.upstream !== undefined && after.upstream?.id !== scope.upstreamId
      || selection.action === 'create' && (before !== null || change.originalNativeId !== undefined)
      || selection.action === 'weight' && (change.originalNativeId !== selection.targetId || change.nativeId === selection.targetId || after.target !== (before as Record<string, any>).target)
      || object(submittedBody) && (submittedBody.target !== undefined && after.target !== submittedBody.target || submittedBody.weight !== undefined && after.weight !== submittedBody.weight)) fail('Target 历史追加预览与原选择不一致。');
  } else if (change.nativeId !== selection.targetId || change.originalNativeId !== undefined || after !== null
    || change.action !== (selection.action === 'health' ? `mark_${selection.healthState}` : 'delete')) fail();
  if (selection.action === 'health' && !intent.review.recovery.blockerCodes.includes(targetHealthRollbackUnavailableReason)) fail('健康置位缺少不可自动回滚提示。');
  return intent;
}
export function targetWorkflowStorageKey(scope: TargetWorkflowScope) {
  targetWorkflowScope(scope); return `kongpilot.target-workflow:${scope.actor}:${scope.cid}:${scope.wid}:${scope.upstreamId}`;
}
export function storeTargetWorkflowAttempt(value: TargetWorkflowAttempt, storage: Pick<Storage, 'setItem'> = sessionStorage) {
  const scope = targetWorkflowScope(value);
  if (!selectionValid(value) || !id(value.key) || !['prepare', 'submit'].includes(value.stage) || !['pending', 'unknown', 'failed', 'prepared'].includes(value.state)
    || (value.state === 'prepared' || value.stage === 'submit') && (!id(value.intentId) || !Number.isSafeInteger(value.revision) || Number(value.revision) < 1 || !hex(value.materialHmac))) fail();
  const safe: TargetWorkflowAttempt = { ...scope, action: value.action, stage: value.stage, state: value.state, key: value.key,
    ...(value.targetId ? { targetId: value.targetId } : {}), ...(value.healthState ? { healthState: value.healthState } : {}),
    ...(id(value.intentId) ? { intentId: value.intentId } : {}), ...(Number.isSafeInteger(value.revision) && Number(value.revision) > 0 ? { revision: value.revision } : {}),
    ...(hex(value.materialHmac) ? { materialHmac: value.materialHmac } : {}) };
  storage.setItem(targetWorkflowStorageKey(scope), JSON.stringify(safe));
}
export function readTargetWorkflowAttempt(scope: TargetWorkflowScope, storage: Pick<Storage, 'getItem'> = sessionStorage): TargetWorkflowAttempt | undefined {
  const text = storage.getItem(targetWorkflowStorageKey(scope)); if (text === null) return;
  let value: unknown; try { value = JSON.parse(text); } catch { fail('原 Target 请求记录损坏，请先核验。'); }
  if (!object(value) || ['actor', 'cid', 'wid', 'upstreamId'].some(key => value[key] !== scope[key as keyof TargetWorkflowScope])) fail();
  let result: TargetWorkflowAttempt | undefined;
  storeTargetWorkflowAttempt(value as TargetWorkflowAttempt, { setItem(_key, raw) { result = JSON.parse(raw); } }); return result;
}
export async function freshTargetWorkflowSession(scope: TargetWorkflowScope, transport: typeof api = api) {
  targetWorkflowScope(scope); const row = await transport<Session>('/auth/me', {}, true);
  if (!row || row.user?.id !== scope.actor || row.user.permissionsVersion !== scope.version || row.user.forcePasswordChange
    || typeof row.csrfToken !== 'string' || row.csrfToken.length < 16 || row.csrfToken.length > 128) fail('账号或会话权限已变化，请重新审阅。'); return row.csrfToken;
}
export function createTargetWorkflowClient(options: { scope: () => TargetWorkflowScope; assertCurrent: (scope: TargetWorkflowScope, writing: boolean) => void;
  transport?: typeof api; storage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>; key?: () => string; onChange?: () => void }) {
  const transport = options.transport ?? api, storage = options.storage ?? sessionStorage; let running = false, authoringCsrf: string | undefined;
  const path = (scope: TargetWorkflowScope, resource: string) => scopeQuery(`/clusters/${scope.cid}/${resource}`, scope.cid, scope.wid);
  const persist = (attempt: TargetWorkflowAttempt) => { storeTargetWorkflowAttempt(attempt, storage); options.onChange?.(); };
  const current = (scope: TargetWorkflowScope, writing: boolean) => { if (!sameTargetWorkflowScope(scope, targetWorkflowScope(options.scope()))) fail(); options.assertCurrent(scope, writing); if (writing && scope.mode !== 'approval') fail(); };
  const stored = (scope: TargetWorkflowScope, attempt: TargetWorkflowAttempt) => { const value = readTargetWorkflowAttempt(scope, storage);
    if (!value || ['actor', 'version', 'cid', 'wid', 'mode', 'upstreamId', 'action', 'targetId', 'healthState', 'intentId', 'revision', 'materialHmac', 'stage', 'key']
      .some(key => value[key as keyof TargetWorkflowAttempt] !== attempt[key as keyof TargetWorkflowAttempt])) fail(); return value; };
  const clear = (scope: TargetWorkflowScope, attempt: TargetWorkflowAttempt) => { stored(scope, attempt); storage.removeItem(targetWorkflowStorageKey(scope)); options.onChange?.(); };
  const session = async (scope: TargetWorkflowScope) => { current(scope, true); const csrf = await freshTargetWorkflowSession(scope, transport); current(scope, true);
    if (authoringCsrf !== undefined && authoringCsrf !== csrf) fail('原 Target 审批会话已变化，请按原键核验。'); authoringCsrf = csrf; return csrf; };
  const getIntent = async (scope: TargetWorkflowScope, attempt: TargetWorkflowAttempt) => {
    current(scope, false); if (!id(attempt.intentId)) fail(); const raw = await transport<unknown>(path(scope, `entity-changes/${attempt.intentId}`), {}, true); current(scope, false);
    const intent = normalizeTargetWorkflowIntent(raw, scope, attempt); if (intent.id !== attempt.intentId || intent.revision !== attempt.revision || intent.materialHmac !== attempt.materialHmac) fail(); return intent;
  };
  const write = async <T>(scope: TargetWorkflowScope, attempt: TargetWorkflowAttempt, csrf: string, resource: string, input: unknown, parse: (raw: unknown) => T | Promise<T>) => {
    current(scope, true); if (running) fail('原请求正在处理中。'); running = true;
    try { persist(attempt); const raw = await transport<unknown>(path(scope, resource), { method: 'POST', body: JSON.stringify(input), headers: { 'X-Idempotency-Key': attempt.key, 'X-CSRF-Token': csrf } }, true);
      current(scope, true); return await parse(raw);
    } catch (error) { const unknown = !(error instanceof ApiError) || error.status === 0 || error.status >= 500 || /UNKNOWN|UNCERTAIN|INVALID_RESPONSE|SCOPE_CHANGED|SESSION_CHANGED/.test(error.code ?? '');
      persist({ ...attempt, state: unknown ? 'unknown' : 'failed' }); throw new ApiError(unknown ? '原 Target 请求结果待核验，请按原请求键只读核验。' : 'Target 请求未完成，请核验原请求。', error instanceof ApiError ? error.status : 0, unknown ? 'TARGET_WORKFLOW_RESULT_UNKNOWN' : error.code);
    } finally { running = false; }
  };
  return {
    async prepare(selection: TargetWorkflowSelection, body?: unknown, confirmation?: string) {
      const scope = targetWorkflowScope(options.scope()); current(scope, true); if (running || readTargetWorkflowAttempt(scope, storage)) fail('已有 Target 请求待处理，不能重新提交。');
      const change = targetWorkflowChange(scope, selection, body, confirmation), csrf = await session(scope);
      if (running || readTargetWorkflowAttempt(scope, storage)) fail();
      const attempt: TargetWorkflowAttempt = { ...scope, ...selection, stage: 'prepare', state: 'pending', key: (options.key ?? newIdempotencyKey)() };
      return write(scope, attempt, csrf, 'entity-changes/prepare', { change }, raw => { const intent = normalizeTargetWorkflowIntent(raw, scope, selection, body);
        if (intent.workflowId) fail(); persist({ ...attempt, state: 'prepared', intentId: intent.id, revision: intent.revision, materialHmac: intent.materialHmac }); return intent; });
    },
    async inspect(attempt: TargetWorkflowAttempt) { return getIntent(targetWorkflowScope(options.scope()), attempt); },
    async discardPrepared(attempt: TargetWorkflowAttempt) { const scope = targetWorkflowScope(options.scope()); current(scope, false); const original = stored(scope, attempt);
      if (running || original.stage !== 'prepare' || original.state !== 'prepared') fail('未知请求不能放弃核验。');
      const intent = await getIntent(scope, original); if (intent.workflowId) fail('此预览已提交，请查看工单。'); current(scope, false); clear(scope, original); },
    async submit(attempt: TargetWorkflowAttempt, reviewed: EntityChangeIntent) {
      const scope = targetWorkflowScope(options.scope()); current(scope, true); const original = stored(scope, attempt);
      if (running || original.stage !== 'prepare' || original.state !== 'prepared' || !sameTargetWorkflowScope(original, scope)) fail();
      const csrf = await session(scope), fresh = await getIntent(scope, original); current(scope, true);
      if (fresh.id !== reviewed.id || fresh.revision !== reviewed.revision || fresh.materialHmac !== reviewed.materialHmac || fresh.workflowId || !fresh.capabilities.submit || Date.parse(fresh.expiresAt) <= Date.now()) fail('原 Target 预览或提交权限已变化。');
      const afterRead = stored(scope, original); if (running || afterRead.stage !== 'prepare' || afterRead.state !== 'prepared') fail();
      const next: TargetWorkflowAttempt = { ...original, stage: 'submit', state: 'pending', key: (options.key ?? newIdempotencyKey)() };
      return write(scope, next, csrf, `entity-changes/${fresh.id}/submit`, { revision: fresh.revision, materialHmac: fresh.materialHmac, confirmed: true, confirm_name: 'native-change' }, async raw => {
        if (!object(raw) || !id(raw.workflowId) || raw.submissionCompleted !== true || raw.nativeExecutionAvailable !== false) fail('原 Target 提交回执不完整。');
        const observed = await getIntent(scope, next); if (observed.workflowId !== raw.workflowId) fail(); current(scope, true); clear(scope, next); return raw.workflowId as string;
      });
    },
    async recover(attempt: TargetWorkflowAttempt): Promise<{ intent?: EntityChangeIntent; workflowId?: string; notObserved?: true }> {
      const scope = targetWorkflowScope(options.scope()); current(scope, false); if (running) fail('原请求仍在处理中，请等待原响应。'); const original = stored(scope, attempt);
      if (original.stage === 'prepare') {
        const raw = await transport<unknown>(path(scope, `entity-changes/by-prepare-key/${original.key}`), {}, true); current(scope, false);
        if (object(raw) && raw.state === 'not_prepared') {
          if (raw.clusterId !== scope.cid || raw.workspaceId !== scope.wid || raw.idempotencyKey !== original.key || raw.intentId !== null || raw.nativeExecutionAvailable !== false || raw.retryWriteAllowed !== false || raw.originalOutcome !== 'not_observed') fail();
          return { notObserved: true };
        }
        const intent = normalizeTargetWorkflowIntent(raw, scope, original); stored(scope, original);
        persist({ ...original, state: 'prepared', intentId: intent.id, revision: intent.revision, materialHmac: intent.materialHmac }); return { intent, ...(intent.workflowId ? { workflowId: intent.workflowId } : {}) };
      }
      const raw = await transport<unknown>(path(scope, `workflows/receipts/by-key/${original.key}`), {}, true); current(scope, false);
      const fresh = await getIntent(scope, original), reference = { clusterId: scope.cid, workspaceId: scope.wid, idempotencyKey: original.key, kind: 'workflow' as const };
      if (!workflowReceiptMatches(raw, reference) || !workflowReceiptProvesCompletion(raw, reference) || raw.action !== 'submit' || !id(raw.workflowId) || fresh.workflowId !== raw.workflowId) fail('原 Target 提交回执未闭环，不能重复提交。');
      current(scope, false); clear(scope, original); return { intent: fresh, workflowId: raw.workflowId };
    },
  };
}
