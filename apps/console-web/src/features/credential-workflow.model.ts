import { ApiError, api } from '../api/client';
import { newIdempotencyKey } from '../api/idempotency';
import { canonicalId, scopeQuery } from '../api/workspace-scope';
import { workflowReceiptMatches, workflowReceiptProvesCompletion } from '../api/workflow-recovery';
import { normalizeEntityChangeIntent, type EntityChangeIntent, type WorkflowIdentity } from './workflow-entity-change.model';

export const credentialWorkflowKinds = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'] as const;
export type CredentialWorkflowKind = typeof credentialWorkflowKinds[number];
export type CredentialWorkflowAction = 'create' | 'update' | 'delete';
export interface CredentialWorkflowScope extends WorkflowIdentity { consumerId: string; credentialKind: CredentialWorkflowKind; }
export interface CredentialWorkflowSelection { action: CredentialWorkflowAction; credentialId?: string; }
/** Strip console-owned workspace labels from form defaults only. Explicit
 * submitted labels still pass through the strict ownership check below. */
export function credentialWorkflowFormDefaults(values: Record<string, unknown>): Record<string, unknown> {
  return { ...values, ...(Array.isArray(values.tags) ? { tags: values.tags.filter(tag => typeof tag === 'string' && !/^workspace:|^kos-ws-/i.test(tag)) } : {}) };
}
export interface CredentialWorkflowAttempt extends CredentialWorkflowScope, CredentialWorkflowSelection {
  stage: 'prepare' | 'submit'; state: 'pending' | 'unknown' | 'failed' | 'prepared'; key: string;
  intentId?: string; revision?: number; materialHmac?: string;
}
const object = (v: unknown): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);
const id = (v: unknown): v is string => typeof v === 'string' && canonicalId(v) === v;
function fail(message = '凭证操作范围或原回执不完整，请重新读取。'): never { throw new ApiError(message, 409, 'CREDENTIAL_WORKFLOW_SCOPE_CHANGED'); }
export function credentialWorkflowScope(value: CredentialWorkflowScope): CredentialWorkflowScope {
  if (![value.actor, value.cid, value.wid, value.consumerId].every(id) || !value.version || value.version.length > 256
    || !['direct', 'approval'].includes(value.mode ?? '') || !(credentialWorkflowKinds as readonly string[]).includes(value.credentialKind)) fail();
  return { actor: value.actor, cid: value.cid, wid: value.wid, version: value.version, mode: value.mode,
    consumerId: value.consumerId, credentialKind: value.credentialKind };
}
export function sameCredentialWorkflowScope(a: CredentialWorkflowScope, b: CredentialWorkflowScope) {
  return ['actor', 'cid', 'wid', 'version', 'mode', 'consumerId', 'credentialKind'].every(key => a[key as keyof CredentialWorkflowScope] === b[key as keyof CredentialWorkflowScope]);
}
export function credentialWorkflowSelection(scope: CredentialWorkflowScope, action: CredentialWorkflowAction, row?: unknown): CredentialWorkflowSelection {
  credentialWorkflowScope(scope);
  if (!['create', 'update', 'delete'].includes(action)) fail();
  if (action === 'create') { if (row !== undefined) fail(); return { action }; }
  if (!object(row) || !id(row.id) || !object(row.consumer) || row.consumer.id !== scope.consumerId) fail('凭证与当前 Consumer 不一致，请刷新列表。');
  return { action, credentialId: row.id };
}
export function credentialWorkflowChange(scope: CredentialWorkflowScope, selection: CredentialWorkflowSelection, body?: unknown, confirmation?: string) {
  credentialWorkflowScope(scope);
  if (!['create', 'update', 'delete'].includes(selection.action) || selection.action !== 'create' && !id(selection.credentialId)
    ||selection.action==='create'&&selection.credentialId!==undefined) fail();
  if (selection.action === 'delete') {
    if (typeof confirmation !== 'string' || !confirmation || confirmation.length > 256) fail('删除凭证需要二次确认。');
    return { kind: 'recycle', action: 'delete', entityType: 'credentials', entityId: selection.credentialId!, parentId: scope.consumerId,
      credentialKind: scope.credentialKind, confirmed: true, confirm_name: confirmation } as const;
  }
  if (!object(body) || Object.keys(body).some(key => ['id', 'consumer', 'consumer_id', 'created_at', 'updated_at', 'ttl', '__proto__', 'constructor', 'prototype'].includes(key))) fail('凭证归属与标识由系统管理。');
  const encoded = JSON.stringify(body);
  if (encoded.length > 1024 * 1024 || /\[REDACTED(?::[^\]]*)?\]/.test(encoded)) fail('请保留秘密字段为空，或重新输入本次需要更新的值。');
  const payload = JSON.parse(encoded);
  if (Array.isArray(payload.tags) && payload.tags.some((tag: unknown) => typeof tag !== 'string' || /^workspace:|^kos-ws-/i.test(tag as string))) fail('工作区标签由系统管理。');
  return { kind: 'credential', action: selection.action, consumerId: scope.consumerId, credentialKind: scope.credentialKind,
    ...(selection.action === 'update' ? { credentialId: selection.credentialId } : {}), body: payload };
}
/** The BFF projects this tuple from its immutable original prepared request.
 * A credential-looking before/after body alone never proves its parent. */
export function normalizeCredentialWorkflowIntent(raw: unknown, scope: CredentialWorkflowScope, selection: CredentialWorkflowSelection): EntityChangeIntent {
  if (!object(raw) || !object(raw.credentialSubject) || raw.credentialSubject.consumerId !== scope.consumerId
    || raw.credentialSubject.credentialKind !== scope.credentialKind || raw.credentialSubject.action !== selection.action
    || raw.credentialSubject.credentialId !== selection.credentialId || raw.nativeExecutionAvailable !== false || raw.schedule !== undefined
    || !object(raw.review) || raw.review.clusterId !== scope.cid || raw.review.workspaceId !== scope.wid || raw.executionMode !== 'approval') fail();
  const intent = normalizeEntityChangeIntent(raw);
  if (intent.review.changes.length !== 1 || intent.review.impact.nativePackets !== 1) fail();
  const change = intent.review.changes[0];
  if (change.entityType !== scope.credentialKind || change.action !== selection.action
    || selection.credentialId !== undefined && change.nativeId !== selection.credentialId) fail();
  return intent;
}
export function credentialWorkflowStorageKey(scope: CredentialWorkflowScope) {
  credentialWorkflowScope(scope);
  return `kongpilot.credential-workflow:${scope.actor}:${scope.cid}:${scope.wid}:${scope.consumerId}:${scope.credentialKind}`;
}
/** Only public tuple, original request key and immutable revision references
 * enter tab storage. Bodies, names, keys, passwords and review JSON do not. */
export function storeCredentialWorkflowAttempt(value: CredentialWorkflowAttempt, storage: Pick<Storage, 'setItem'> = sessionStorage) {
  const scope = credentialWorkflowScope(value);
  if (!id(value.key) || !['prepare', 'submit'].includes(value.stage) || !['pending', 'unknown', 'failed', 'prepared'].includes(value.state)
    || !['create', 'update', 'delete'].includes(value.action) || value.action !== 'create' && !id(value.credentialId)
    || (value.state==='prepared'||value.stage==='submit')&&(!id(value.intentId)||!Number.isSafeInteger(value.revision)||value.revision!<1||!/^[a-f\d]{64}$/.test(value.materialHmac??''))) fail();
  const safe: CredentialWorkflowAttempt = { ...scope, action: value.action, stage: value.stage, state: value.state, key: value.key,
    ...(value.credentialId ? { credentialId: value.credentialId } : {}), ...(id(value.intentId) ? { intentId: value.intentId } : {}),
    ...(Number.isSafeInteger(value.revision) && value.revision! > 0 ? { revision: value.revision } : {}),
    ...(/^[a-f\d]{64}$/.test(value.materialHmac ?? '') ? { materialHmac: value.materialHmac } : {}) };
  storage.setItem(credentialWorkflowStorageKey(scope), JSON.stringify(safe));
}
export function readCredentialWorkflowAttempt(scope: CredentialWorkflowScope, storage: Pick<Storage, 'getItem'> = sessionStorage): CredentialWorkflowAttempt | undefined {
  const text = storage.getItem(credentialWorkflowStorageKey(scope)); if (!text) return;
  let raw: unknown; try { raw = JSON.parse(text); } catch { fail('原凭证请求记录损坏，请先核验，不能重新提交。'); }
  if (!object(raw) || ['actor', 'cid', 'wid', 'consumerId', 'credentialKind'].some(key => raw[key] !== scope[key as keyof CredentialWorkflowScope])) fail();
  const capture: { value?: CredentialWorkflowAttempt } = {};
  storeCredentialWorkflowAttempt(raw as CredentialWorkflowAttempt, { setItem(_key, value) { capture.value = JSON.parse(value); } });
  return capture.value;
}
export function clearCredentialWorkflowAttempt(value: CredentialWorkflowAttempt, storage: Pick<Storage, 'getItem' | 'removeItem'> = sessionStorage) {
  const stored = readCredentialWorkflowAttempt(value, storage);
  if (!stored || stored.key !== value.key || stored.stage !== value.stage) fail('原请求记录已变化，请重新核验。');
  storage.removeItem(credentialWorkflowStorageKey(value));
}
type Transport = typeof api;
export function createCredentialWorkflowClient(options: { scope: () => CredentialWorkflowScope; assertCurrent: (captured: CredentialWorkflowScope, writing: boolean) => void;
  transport?: Transport; storage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>; key?: () => string; onChange?: () => void }) {
  const transport = options.transport ?? api, storage = options.storage ?? sessionStorage; let running = false;
  const path = (scope: CredentialWorkflowScope, resource: string) => scopeQuery(`/clusters/${scope.cid}/${resource}`, scope.cid, scope.wid);
  const persist = (value: CredentialWorkflowAttempt) => { storeCredentialWorkflowAttempt(value, storage); options.onChange?.(); };
  const clear = (value: CredentialWorkflowAttempt) => { clearCredentialWorkflowAttempt(value, storage); options.onChange?.(); };
  const current = (scope: CredentialWorkflowScope, writing: boolean) => {
    if (!sameCredentialWorkflowScope(scope, credentialWorkflowScope(options.scope()))) fail(); options.assertCurrent(scope, writing);
    if (writing && scope.mode !== 'approval') fail();
  };
  const getIntent = async (scope: CredentialWorkflowScope, attempt: CredentialWorkflowAttempt) => {
    current(scope, false); if (!id(attempt.intentId)) fail();
    const raw = await transport<unknown>(path(scope, `entity-changes/${attempt.intentId}`)); current(scope, false);
    const intent = normalizeCredentialWorkflowIntent(raw, scope, attempt);
    if (intent.id !== attempt.intentId || intent.revision !== attempt.revision || intent.materialHmac !== attempt.materialHmac) fail('原凭证变更预览已变化。');
    return intent;
  };
  const write = async <T>(scope: CredentialWorkflowScope, attempt: CredentialWorkflowAttempt, resource: string, payload: unknown, parse: (raw: unknown) => Promise<T> | T) => {
    current(scope, true); if (running) fail('原请求正在处理中。'); running = true; persist(attempt);
    try {
      // retried=true deliberately disables the shared client's 401 POST replay.
      const raw = await transport<unknown>(path(scope, resource), { method: 'POST', body: JSON.stringify(payload), headers: { 'X-Idempotency-Key': attempt.key } }, true);
      current(scope, true); return await parse(raw);
    } catch (error) {
      const unknown = !(error instanceof ApiError) || error.status === 0 || error.status >= 500 || /UNKNOWN|UNCERTAIN|INVALID_RESPONSE|SCOPE_CHANGED|SESSION_CHANGED/.test(error.code ?? '');
      persist({ ...attempt, state: unknown ? 'unknown' : 'failed' });
      throw new ApiError(unknown ? '原凭证请求结果待核验，请使用原请求键只读核验。' : '凭证请求未完成，请核验权限与原请求。',
        error instanceof ApiError ? error.status : 0, unknown ? 'CREDENTIAL_WORKFLOW_RESULT_UNKNOWN' : error.code);
    } finally { running = false; }
  };
  return {
    async prepare(selection: CredentialWorkflowSelection, body?: unknown, confirmation?: string) {
      const scope = credentialWorkflowScope(options.scope()); current(scope, true);
      if (running || readCredentialWorkflowAttempt(scope, storage)) fail('已有原凭证请求待处理，不能重新提交。');
      const change=credentialWorkflowChange(scope,selection,body,confirmation);
      const attempt: CredentialWorkflowAttempt = { ...scope, ...selection, stage: 'prepare', state: 'pending', key: (options.key ?? newIdempotencyKey)() };
      return write(scope, attempt, 'entity-changes/prepare', { change }, raw => {
        const intent = normalizeCredentialWorkflowIntent(raw, scope, selection);
        persist({ ...attempt, state: 'prepared', intentId: intent.id, revision: intent.revision, materialHmac: intent.materialHmac }); return intent;
      });
    },
    async inspect(attempt: CredentialWorkflowAttempt) { return getIntent(credentialWorkflowScope(options.scope()), attempt); },
    async discardPrepared(attempt:CredentialWorkflowAttempt) {
      const scope=credentialWorkflowScope(options.scope());current(scope,false);
      const stored=readCredentialWorkflowAttempt(scope,storage);
      if(running||!stored||stored.stage!=='prepare'||stored.state!=='prepared'||stored.key!==attempt.key)fail('未知请求不能放弃核验。');
      const fresh=await getIntent(scope,stored);if(fresh.workflowId)fail('此预览已提交工单，请在工单中查看。');
      current(scope,false);clear(stored);
    },
    async submit(attempt: CredentialWorkflowAttempt, reviewed: EntityChangeIntent) {
      const scope = credentialWorkflowScope(options.scope()); current(scope, true);
      const stored = readCredentialWorkflowAttempt(scope, storage);
      if (running || !stored || stored.state !== 'prepared' || stored.stage !== 'prepare' || stored.key !== attempt.key) fail();
      const fresh = await getIntent(scope, stored); current(scope, true);
      if (fresh.id !== reviewed.id || fresh.revision !== reviewed.revision || fresh.materialHmac !== reviewed.materialHmac || fresh.workflowId
        || fresh.capabilities.submit !== true || Date.parse(fresh.expiresAt) <= Date.now()) fail('原凭证预览或当前提交权限已变化。');
      const afterRead=readCredentialWorkflowAttempt(scope,storage);
      if(running||!afterRead||afterRead.stage!=='prepare'||afterRead.state!=='prepared'||afterRead.key!==stored.key)fail('原请求状态已变化。');
      const next: CredentialWorkflowAttempt = { ...stored, ...scope, stage: 'submit', state: 'pending', key: (options.key ?? newIdempotencyKey)() };
      return write(scope, next, `entity-changes/${fresh.id}/submit`, { revision: fresh.revision, materialHmac: fresh.materialHmac, confirmed: true, confirm_name: 'native-change' }, async raw => {
        if (!object(raw) || !id(raw.workflowId) || raw.submissionCompleted !== true || raw.nativeExecutionAvailable !== false) fail('提交回执不完整，请核验原请求。');
        const observed = await getIntent(scope, next); if (observed.workflowId !== raw.workflowId) fail();
        current(scope, true); clear(next); return raw.workflowId as string;
      });
    },
    async recover(attempt: CredentialWorkflowAttempt): Promise<{ intent?: EntityChangeIntent; workflowId?: string; notPrepared?: true }> {
      const scope = credentialWorkflowScope(options.scope()); current(scope, false);
      if(running)fail('原请求仍在处理中，请等待其结果后核验。');
      const stored = readCredentialWorkflowAttempt(scope, storage); if (!stored || stored.key !== attempt.key || stored.stage !== attempt.stage) fail();
      if (stored.stage === 'prepare') {
        const raw = await transport<unknown>(path(scope, `entity-changes/by-prepare-key/${stored.key}`)); current(scope, false);
        if (object(raw) && raw.state === 'not_prepared') {
          if (raw.clusterId !== scope.cid || raw.workspaceId !== scope.wid || raw.idempotencyKey !== stored.key || raw.intentId !== null || raw.nativeExecutionAvailable !== false
            ||raw.retryWriteAllowed!==false||raw.originalOutcome!=='not_observed') fail();
          // Current absence is not an instruction to repeat an unknown POST.
          return { notPrepared: true };
        }
        const intent = normalizeCredentialWorkflowIntent(raw, scope, stored);
        persist({ ...stored, state: 'prepared', intentId: intent.id, revision: intent.revision, materialHmac: intent.materialHmac }); return { intent, ...(intent.workflowId ? { workflowId: intent.workflowId } : {}) };
      }
      const raw = await transport<unknown>(path(scope, `workflows/receipts/by-key/${stored.key}`)); current(scope, false);
      const fresh = await getIntent(scope, stored);
      const reference = { clusterId: scope.cid, workspaceId: scope.wid, idempotencyKey: stored.key, kind: 'workflow' as const };
      if (!workflowReceiptMatches(raw, reference) || !workflowReceiptProvesCompletion(raw, reference) || raw.action !== 'submit' || !id(raw.workflowId)
        || fresh.workflowId !== raw.workflowId) fail('原提交回执未闭环，不能重复提交。');
      clear(stored); return { intent: fresh, workflowId: raw.workflowId };
    },
  };
}
