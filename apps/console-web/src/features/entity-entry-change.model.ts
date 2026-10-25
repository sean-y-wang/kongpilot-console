import { canonicalId } from '../api/workspace-scope';
import { isEntityType } from './entities';
import type { WorkflowIdentity } from './workflow-entity-change.model';

export type EntityEntryChange =
  | { kind: 'entity'; action: 'create' | 'update'; entityType: string; body: Record<string, unknown>; entityId?: string }
  | { kind: 'recycle'; action: 'delete'; entityType: string; entityId: string; confirmed: true; confirm_name: string }
  | { kind: 'recycle'; action: 'restore'; entryId: string; confirmed: true; confirm_name: string };

export function entityEntryPreparationBody(change: EntityEntryChange) {
  if (!change || !['entity', 'recycle'].includes(change.kind)) throw new Error('不支持的变更对象类别。');
  if (change.kind === 'entity') {
    if (!isEntityType(change.entityType) || !change.body || typeof change.body !== 'object' || Array.isArray(change.body)
      || !['create', 'update'].includes(change.action) || change.action === 'update' && !canonicalId(change.entityId)
      || change.action === 'create' && change.entityId !== undefined) throw new Error('请选择有效的网关对象与变更操作。');
    return { change: { kind: change.kind, action: change.action, entityType: change.entityType,
      ...(change.action === 'update' ? { entityId: change.entityId } : {}), body: change.body } };
  }
  if (change.confirmed !== true || typeof change.confirm_name !== 'string' || !change.confirm_name.trim() || change.confirm_name.length > 1024) throw new Error('请确认当前对象名称。');
  if (change.action === 'restore') {
    if (!canonicalId(change.entryId)) throw new Error('回收站记录标识无效。');
    return { change: { kind: 'recycle', action: 'restore', entryId: change.entryId, confirmed: true, confirm_name: change.confirm_name } };
  }
  if (change.action !== 'delete' || !isEntityType(change.entityType) || !canonicalId(change.entityId)) throw new Error('删除对象标识无效。');
  return { change: { kind: 'recycle', action: 'delete', entityType: change.entityType, entityId: change.entityId, confirmed: true, confirm_name: change.confirm_name } };
}

export function entityEntryIntentHref(intentId: string) {
  if (!canonicalId(intentId)) throw new Error('变更预览标识无效。');
  return `/workflows?tab=changes&intent=${encodeURIComponent(intentId)}`;
}

export function entityEntryScopeReady(identity: WorkflowIdentity) {
  return !!canonicalId(identity.actor) && !!canonicalId(identity.cid) && !!canonicalId(identity.wid) && typeof identity.version === 'string' && !!identity.version;
}
