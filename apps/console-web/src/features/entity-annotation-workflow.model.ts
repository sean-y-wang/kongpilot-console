import { api, ApiError } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { redactForDisplay } from '../api/redaction';
import type { Session } from '../api/types';
import { workflowReceiptMatches, workflowReceiptProvesCompletion } from '../api/workflow-recovery';
import { hasHiddenValue } from '../components/schema-patch';

export const annotationEntityTypes = ['services', 'routes', 'consumers', 'plugins', 'upstreams', 'certificates', 'ca_certificates', 'snis'] as const;
export type AnnotationOperation = 'set' | 'remove' | 'restore';
export interface AnnotationWorkflowScope {
  actor: string; version: string; cid: string; wid: string; mode: 'direct' | 'approval'; entityType: string; entityId: string;
}
export interface AnnotationWorkflowSelection { operation: AnnotationOperation; annotationRevision: number; }
export interface AnnotationWorkflowAttempt extends AnnotationWorkflowScope, AnnotationWorkflowSelection {
  stage: 'prepare' | 'submit'; state: 'pending' | 'unknown' | 'failed' | 'prepared'; key: string;
  intentId?: string; materialHmac?: string;
}
export interface AnnotationWorkflowIntent extends AnnotationWorkflowSelection {
  intentId: string; clusterId: string; workspaceId: string; entityType: string; entityId: string;
  revision: number | null; planHash: string | null; materialHmac: string; state: string; workflowId: string | null; expiresAt: string;
  nativeRequestsSent: 0; nativeExecutionAvailable: false; capabilities: { submit: boolean };
  preview: { before: unknown; after: unknown; confirmationName: string; retentionDays?: number } | null;
}
type Store = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
const object = (v: unknown): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const id = (v: unknown): v is string => typeof v === 'string' && canonicalId(v) === v;
const revision = (v: unknown) => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) < 2147483647;
const hmac = (v: unknown): v is string => typeof v === 'string' && /^[a-f\d]{64}$/.test(v);
function fail(message = '实体说明的范围或原回执已变化，请重新读取。'): never { throw new ApiError(message, 409, 'ANNOTATION_WORKFLOW_SCOPE_CHANGED'); }
export function annotationWorkflowScope(value: AnnotationWorkflowScope): AnnotationWorkflowScope {
  if (![value.actor, value.cid, value.wid, value.entityId].every(id) || typeof value.version !== 'string' || !value.version || value.version.length > 256
    || !['direct', 'approval'].includes(value.mode) || !(annotationEntityTypes as readonly string[]).includes(value.entityType)) fail();
  return { actor: value.actor, version: value.version, cid: value.cid, wid: value.wid, mode: value.mode, entityType: value.entityType, entityId: value.entityId };
}
export function sameAnnotationWorkflowScope(a: AnnotationWorkflowScope, b: AnnotationWorkflowScope) {
  return ['actor', 'version', 'cid', 'wid', 'mode', 'entityType', 'entityId'].every(key => a[key as keyof AnnotationWorkflowScope] === b[key as keyof AnnotationWorkflowScope]);
}
function sameSubject(a: AnnotationWorkflowScope, b: AnnotationWorkflowScope) {
  return ['actor', 'cid', 'wid', 'entityType', 'entityId'].every(key => a[key as keyof AnnotationWorkflowScope] === b[key as keyof AnnotationWorkflowScope]);
}
/** Keep the exact original annotation CAS. Entity identity and retention policy
 * are server owned; an omitted metadata property remains omitted. */
export function annotationWorkflowRequest(scope: AnnotationWorkflowScope, selection: AnnotationWorkflowSelection, input: unknown, confirmationName?: string) {
  annotationWorkflowScope(scope);
  if (!['set', 'remove', 'restore'].includes(selection.operation) || !revision(selection.annotationRevision) || !object(input)
    || input.revision !== selection.annotationRevision) fail('实体说明版本无效，请刷新后重试。');
  const permitted = selection.operation === 'set' ? ['revision', 'description', 'owner_user_id', 'metadata'] : ['revision', 'confirmed', 'confirm_name'];
  if (Object.keys(input).some(key => !permitted.includes(key))) fail('实体说明包含不支持的字段。');
  const visit = (node: unknown, depth: number, seen: Set<object>): void => {
    if (depth > 20) fail('扩展元数据嵌套超过 20 层。');
    if (node === null || typeof node === 'string' || typeof node === 'boolean' || typeof node === 'number' && Number.isFinite(node)) return;
    if (typeof node !== 'object' || seen.has(node) || !Array.isArray(node) && !object(node)) fail('扩展元数据必须为 JSON 对象。');
    seen.add(node);
    for (const [key, child] of Object.entries(node)) { if (['__proto__', 'constructor', 'prototype'].includes(key)) fail(); visit(child, depth + 1, seen); }
    seen.delete(node);
  };
  if (selection.operation === 'set') {
    if (Object.hasOwn(input, 'description') && (typeof input.description !== 'string' || input.description.length > 8192)
      || Object.hasOwn(input, 'owner_user_id') && input.owner_user_id !== null && !id(input.owner_user_id)
      || Object.hasOwn(input, 'metadata') && (!object(input.metadata) || hasHiddenValue(input.metadata))) fail('请重新填写说明、负责人或本次更新的元数据。');
    if (Object.hasOwn(input, 'metadata')) {
      visit(input.metadata, 0, new Set());
      if (new TextEncoder().encode(JSON.stringify(input.metadata)).byteLength > 65536) fail('扩展元数据不得超过 64 KiB。');
    }
  } else if (!selection.annotationRevision || typeof confirmationName !== 'string' || !confirmationName || confirmationName.length > 256
    || input.confirmed !== true || input.confirm_name !== confirmationName) fail('删除或恢复说明需要输入实体名称确认。');
  return { entityType: scope.entityType, entityId: scope.entityId, operation: selection.operation, input: structuredClone(input) };
}

/** Public projection only: native objects, sealed captures and arbitrary server
 * fields cannot enter the review or tab journal. */
export function normalizeAnnotationWorkflowIntent(raw: unknown, scope: AnnotationWorkflowScope, selection: AnnotationWorkflowSelection): AnnotationWorkflowIntent {
  annotationWorkflowScope(scope);
  if (!['set', 'remove', 'restore'].includes(selection.operation) || !revision(selection.annotationRevision)
    || !object(raw) || !id(raw.intentId) || raw.clusterId !== scope.cid || raw.workspaceId !== scope.wid
    || raw.entityType !== scope.entityType || raw.entityId !== scope.entityId || raw.operation !== selection.operation
    || raw.annotationRevision !== selection.annotationRevision || !hmac(raw.materialHmac)
    || raw.nativeRequestsSent !== 0 || raw.nativeExecutionAvailable !== false || !['prepared', 'pending', 'approved', 'rejected', 'cancelled', 'executing', 'uncertain', 'partial', 'succeeded', 'failed', 'expired'].includes(raw.state)
    || raw.workflowId !== null && !id(raw.workflowId) || typeof raw.expiresAt !== 'string' || !Number.isFinite(Date.parse(raw.expiresAt))
    || !object(raw.capabilities) || typeof raw.capabilities.submit !== 'boolean'
    || raw.workflowId === null && (raw.revision !== null || raw.planHash !== null || raw.state !== 'prepared')
    || raw.workflowId !== null && (!revision(raw.revision) || raw.revision < 1 || !hmac(raw.planHash) || raw.state === 'prepared')) fail('实体说明审批回执不完整，请保留原请求键核验。');
  let preview: AnnotationWorkflowIntent['preview'] = null;
  if (raw.preview !== null) {
    if (!object(raw.preview) || !Object.hasOwn(raw.preview, 'before') || !Object.hasOwn(raw.preview, 'after')
      || typeof raw.preview.confirmationName !== 'string' || !raw.preview.confirmationName || raw.preview.confirmationName.length > 256
      || raw.preview.retentionDays != null && (!Number.isInteger(raw.preview.retentionDays) || raw.preview.retentionDays < 1 || raw.preview.retentionDays > 3650)) fail();
    const before = raw.preview.before, after = raw.preview.after;
    if (before !== null && (!object(before) || before.cluster_id !== scope.cid || before.entity_type !== scope.entityType || before.kong_id !== scope.entityId
      || before.revision !== selection.annotationRevision || typeof before.description !== 'string' || before.owner_user_id !== null && !id(before.owner_user_id)
      || !object(before.metadata) || !['active', 'deleted'].includes(before.status))
      || before === null && selection.annotationRevision !== 0
      || !object(after) || after.entityType !== scope.entityType || after.entityId !== scope.entityId || after.operation !== selection.operation
      || !object(after.input) || after.input.revision !== selection.annotationRevision) fail('实体说明预览与原对象不一致。');
    const publicBefore = before === null ? null : { description: before.description, owner_user_id: before.owner_user_id,
      metadata: before.metadata, revision: before.revision, status: before.status };
    const names = selection.operation === 'set' ? ['revision', 'description', 'owner_user_id', 'metadata'] : ['revision', 'confirmed', 'confirm_name'];
    const publicAfter = { entityType: scope.entityType, entityId: scope.entityId, operation: selection.operation,
      input: Object.fromEntries(names.filter(key => Object.hasOwn(after.input, key)).map(key => [key, after.input[key]])) };
    preview = { before: redactForDisplay(publicBefore), after: redactForDisplay(publicAfter), confirmationName: raw.preview.confirmationName,
      ...(raw.preview.retentionDays == null ? {} : { retentionDays: raw.preview.retentionDays }) };
  }
  if (raw.state === 'prepared' && !preview) fail();
  return { intentId: raw.intentId, clusterId: raw.clusterId, workspaceId: raw.workspaceId, entityType: raw.entityType, entityId: raw.entityId,
    operation: raw.operation, annotationRevision: raw.annotationRevision, revision: raw.revision, planHash: raw.planHash, materialHmac: raw.materialHmac, state: raw.state,
    workflowId: raw.workflowId, expiresAt: raw.expiresAt, nativeRequestsSent: 0, nativeExecutionAvailable: false, capabilities: { submit: raw.capabilities.submit }, preview };
}
export function annotationWorkflowStorageKey(scope: AnnotationWorkflowScope) {
  annotationWorkflowScope(scope); return `kongpilot.annotation-workflow:${scope.actor}:${scope.cid}:${scope.wid}:${scope.entityType}:${scope.entityId}`;
}
export function storeAnnotationWorkflowAttempt(value: AnnotationWorkflowAttempt, storage: Pick<Storage, 'setItem'> = sessionStorage) {
  const scope = annotationWorkflowScope(value);
  if (!id(value.key) || !['prepare', 'submit'].includes(value.stage) || !['pending', 'unknown', 'failed', 'prepared'].includes(value.state)
    || !['set', 'remove', 'restore'].includes(value.operation) || !revision(value.annotationRevision)
    || (value.stage === 'submit' || value.state === 'prepared') && (!id(value.intentId) || !hmac(value.materialHmac))) fail();
  const safe: AnnotationWorkflowAttempt = { ...scope, operation: value.operation, annotationRevision: value.annotationRevision,
    stage: value.stage, state: value.state, key: value.key,
    ...(id(value.intentId) ? { intentId: value.intentId } : {}),
    ...(hmac(value.materialHmac) ? { materialHmac: value.materialHmac } : {}) };
  storage.setItem(annotationWorkflowStorageKey(scope), JSON.stringify(safe));
}
export function readAnnotationWorkflowAttempt(scope: AnnotationWorkflowScope, storage: Pick<Storage, 'getItem'> = sessionStorage): AnnotationWorkflowAttempt | undefined {
  const text = storage.getItem(annotationWorkflowStorageKey(scope)); if (text === null) return;
  let value: unknown; try { value = JSON.parse(text); } catch { fail('原实体说明请求记录损坏，请先核验。'); }
  if (!object(value) || !sameSubject(value as AnnotationWorkflowAttempt, scope)) fail();
  let result: AnnotationWorkflowAttempt | undefined;
  storeAnnotationWorkflowAttempt(value as AnnotationWorkflowAttempt, { setItem(_key, raw) { result = JSON.parse(raw); } }); return result;
}
export async function freshAnnotationSession(scope: AnnotationWorkflowScope, transport: typeof api = api): Promise<string> {
  annotationWorkflowScope(scope);
  const row = await transport<Session>('/auth/me', {}, true);
  if (!row || row.user?.id !== scope.actor || row.user.permissionsVersion !== scope.version || row.user.forcePasswordChange
    || typeof row.csrfToken !== 'string' || row.csrfToken.length < 16 || row.csrfToken.length > 128) fail('登录会话或权限已变化，请重新审阅。');
  return row.csrfToken;
}
export function createAnnotationWorkflowClient(options: {
  scope: () => AnnotationWorkflowScope; assertCurrent: (captured: AnnotationWorkflowScope, writing: boolean) => void;
  transport?: typeof api; storage?: Store; key?: () => string; onChange?: () => void;
}) {
  const transport = options.transport ?? api, storage = options.storage ?? sessionStorage;
  let running = false, authoringCsrf: string | undefined;
  const path = (scope: AnnotationWorkflowScope, resource: string) => scopeQuery(`/clusters/${scope.cid}/${resource}`, scope.cid, scope.wid);
  const current = (scope: AnnotationWorkflowScope, writing: boolean) => {
    if (!sameAnnotationWorkflowScope(scope, annotationWorkflowScope(options.scope()))) fail();
    options.assertCurrent(scope, writing); if (writing && scope.mode !== 'approval') fail();
  };
  const persist = (attempt: AnnotationWorkflowAttempt) => { storeAnnotationWorkflowAttempt(attempt, storage); options.onChange?.(); };
  const clear = (attempt: AnnotationWorkflowAttempt) => {
    const stored = readAnnotationWorkflowAttempt(attempt, storage);
    if (!stored || stored.key !== attempt.key || stored.stage !== attempt.stage) fail();
    storage.removeItem(annotationWorkflowStorageKey(attempt)); options.onChange?.();
  };
  const sameStored = (scope: AnnotationWorkflowScope, attempt: AnnotationWorkflowAttempt) => {
    const stored = readAnnotationWorkflowAttempt(scope, storage);
    if (!stored || stored.key !== attempt.key || stored.stage !== attempt.stage) fail('原实体说明请求记录已变化。'); return stored;
  };
  const getIntent = async (scope: AnnotationWorkflowScope, attempt: AnnotationWorkflowAttempt) => {
    current(scope, false); if (!id(attempt.intentId)) fail();
    const raw = await transport<unknown>(path(scope, `annotation-changes/${attempt.intentId}`), {}, true); current(scope, false);
    const row = normalizeAnnotationWorkflowIntent(raw, scope, attempt);
    if (row.intentId !== attempt.intentId || row.materialHmac !== attempt.materialHmac) fail(); return row;
  };
  const session = async (scope: AnnotationWorkflowScope) => {
    current(scope, true); const csrf = await freshAnnotationSession(scope, transport); current(scope, true);
    if (authoringCsrf !== undefined && authoringCsrf !== csrf) fail('原审批会话已变化，请由原会话只读核验。');
    authoringCsrf = csrf; return csrf;
  };
  const write = async <T>(scope: AnnotationWorkflowScope, attempt: AnnotationWorkflowAttempt, csrf: string, resource: string, body: unknown, parse: (raw: unknown) => T | Promise<T>) => {
    current(scope, true); if (running) fail('原请求正在处理中。'); running = true;
    try {
      persist(attempt);
      const raw = await transport<unknown>(path(scope, resource), { method: 'POST', body: JSON.stringify(body),
        headers: { 'X-Idempotency-Key': attempt.key, 'X-CSRF-Token': csrf } }, true);
      current(scope, true); return await parse(raw);
    } catch (error) {
      const unknown = !(error instanceof ApiError) || error.status === 0 || error.status >= 500 || /UNKNOWN|UNCERTAIN|INVALID_RESPONSE|SCOPE_CHANGED|SESSION_CHANGED/.test(error.code ?? '');
      persist({ ...attempt, state: unknown ? 'unknown' : 'failed' });
      throw new ApiError(unknown ? '原实体说明请求结果待核验，请按原请求键只读核验。' : '实体说明请求未完成，请核验原请求。',
        error instanceof ApiError ? error.status : 0, unknown ? 'ANNOTATION_WORKFLOW_RESULT_UNKNOWN' : error.code);
    } finally { running = false; }
  };
  return {
    async prepare(selection: AnnotationWorkflowSelection, input: unknown, confirmationName?: string) {
      const scope = annotationWorkflowScope(options.scope()); current(scope, true);
      if (running || readAnnotationWorkflowAttempt(scope, storage)) fail('已有实体说明请求待处理，不能重新提交。');
      const request = annotationWorkflowRequest(scope, selection, input, confirmationName), csrf = await session(scope);
      if (running || readAnnotationWorkflowAttempt(scope, storage)) fail('原请求状态已变化。');
      const attempt: AnnotationWorkflowAttempt = { ...scope, ...selection, stage: 'prepare', state: 'pending', key: (options.key ?? newIdempotencyKey)() };
      return write(scope, attempt, csrf, 'annotation-changes/prepare', request, raw => {
        const intent = normalizeAnnotationWorkflowIntent(raw, scope, selection);
        if (intent.state !== 'prepared' || intent.workflowId !== null) fail();
        persist({ ...attempt, state: 'prepared', intentId: intent.intentId, materialHmac: intent.materialHmac }); return intent;
      });
    },
    async inspect(attempt: AnnotationWorkflowAttempt) { return getIntent(annotationWorkflowScope(options.scope()), attempt); },
    async discardPrepared(attempt: AnnotationWorkflowAttempt) {
      const scope = annotationWorkflowScope(options.scope()); current(scope, false);
      const stored = sameStored(scope, attempt);
      if (running || stored.stage !== 'prepare' || stored.state !== 'prepared') fail('未知请求不能放弃核验。');
      const fresh = await getIntent(scope, stored);
      if (fresh.workflowId !== null || fresh.state !== 'prepared') fail('此预览已提交或状态已变化。');
      current(scope, false); sameStored(scope, stored); clear(stored);
    },
    async submit(attempt: AnnotationWorkflowAttempt, reviewed: AnnotationWorkflowIntent) {
      const scope = annotationWorkflowScope(options.scope()); current(scope, true);
      const stored = sameStored(scope, attempt);
      if (running || stored.stage !== 'prepare' || stored.state !== 'prepared' || !sameAnnotationWorkflowScope(stored, scope)) fail();
      const csrf = await session(scope), fresh = await getIntent(scope, stored); current(scope, true);
      if (fresh.intentId !== reviewed.intentId || fresh.revision !== reviewed.revision || fresh.materialHmac !== reviewed.materialHmac
        || !fresh.preview || fresh.state !== 'prepared' || fresh.workflowId !== null || !fresh.capabilities.submit || Date.parse(fresh.expiresAt) <= Date.now()) fail('原实体说明预览或当前提交权限已变化。');
      const afterRead = sameStored(scope, stored);
      if (running || afterRead.stage !== 'prepare' || afterRead.state !== 'prepared') fail();
      const next: AnnotationWorkflowAttempt = { ...stored, stage: 'submit', state: 'pending', key: (options.key ?? newIdempotencyKey)() };
      return write(scope, next, csrf, `annotation-changes/${fresh.intentId}/submit`, { confirmed: true, materialHmac: fresh.materialHmac }, async raw => {
        const receipt = normalizeAnnotationWorkflowIntent(raw, scope, stored);
        if (receipt.intentId !== fresh.intentId || receipt.materialHmac !== fresh.materialHmac || !id(receipt.workflowId)) fail();
        const observed = await getIntent(scope, next); if (observed.workflowId !== receipt.workflowId) fail();
        current(scope, true); clear(next); return receipt.workflowId;
      });
    },
    async recover(attempt: AnnotationWorkflowAttempt): Promise<{ intent?: AnnotationWorkflowIntent; workflowId?: string; notObserved?: true }> {
      const scope = annotationWorkflowScope(options.scope()); current(scope, false);
      if (running) fail('原请求仍在处理中，请等待其结果后核验。');
      const stored = sameStored(scope, attempt);
      if (stored.stage === 'prepare') {
        const raw = await transport<unknown>(path(scope, `annotation-changes/by-key/${stored.key}`), {}, true); current(scope, false);
        if (object(raw) && raw.state === 'not_prepared') {
          if (raw.clusterId !== scope.cid || raw.workspaceId !== scope.wid || raw.idempotencyKey !== stored.key || raw.intentId !== null
            || raw.retryWriteAllowed !== false || raw.originalOutcome !== 'not_observed' || raw.nativeRequestsSent !== 0) fail();
          return { notObserved: true };
        }
        const intent = normalizeAnnotationWorkflowIntent(raw, scope, stored); sameStored(scope, stored);
        persist({ ...stored, state: 'prepared', intentId: intent.intentId, materialHmac: intent.materialHmac });
        return { intent, ...(intent.workflowId ? { workflowId: intent.workflowId } : {}) };
      }
      const raw = await transport<unknown>(path(scope, `workflows/receipts/by-key/${stored.key}`), {}, true); current(scope, false);
      const fresh = await getIntent(scope, stored), reference = { clusterId: scope.cid, workspaceId: scope.wid, idempotencyKey: stored.key, kind: 'workflow' as const };
      if (!workflowReceiptMatches(raw, reference) || !workflowReceiptProvesCompletion(raw, reference) || raw.action !== 'submit' || !id(raw.workflowId)
        || fresh.workflowId !== raw.workflowId) fail('原提交回执未闭环，请继续核验，不能重复提交。');
      current(scope, false); clear(stored); return { intent: fresh, workflowId: raw.workflowId };
    },
  };
}
