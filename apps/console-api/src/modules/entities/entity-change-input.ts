import { BadRequestException } from '@nestjs/common';
import { credentialKind, entityType, identifier, objectBody } from './entities.types';
import type { EntityChangeInput, EntityChangeOperation } from './entity-change.types';

const invalid = () => new BadRequestException({ code: 'INVALID_ENTITY_CHANGE_INPUT', message: '变更意图必须使用受支持的固定对象与操作' });
function fields(value: Record<string, any>, allowed: string[]): void { if (Object.keys(value).some(key => !allowed.includes(key))) throw invalid(); }
function id(value: unknown): string { if (typeof value !== 'string') throw invalid(); identifier(value); return value; }
function body(value: unknown, create: boolean): Record<string, unknown> {
  const result = objectBody(value);
  if (Object.hasOwn(result, 'id') || ['created_at', 'updated_at', 'ttl'].some(field => Object.hasOwn(result, field))) throw new BadRequestException({ code: 'ENTITY_CHANGE_SERVER_FIELD', message: '对象 ID 与系统时间由服务器生成；工单不接受 TTL 配置' });
  return result;
}
function operation(input: unknown): EntityChangeOperation {
  const value = objectBody(input);
  if (value.kind === 'entity') {
    if (!['create', 'update'].includes(value.action)) throw invalid();
    fields(value, ['kind', 'action', 'entityType', ...(value.action === 'update' ? ['entityId'] : []), 'body']);
    const type = entityType(value.entityType), payload = body(value.body, value.action === 'create');
    return value.action === 'create' ? { kind: 'entity', action: 'create', entityType: type, body: payload }
      : { kind: 'entity', action: 'update', entityType: type, entityId: id(value.entityId), body: payload };
  }
  if (value.kind === 'target') {
    if (!['create', 'weight', 'health'].includes(value.action)) throw invalid();
    fields(value, ['kind', 'action', 'upstreamId', ...(value.action !== 'create' ? ['targetId'] : []), ...(value.action === 'health' ? ['state'] : ['body'])]);
    const upstreamId = id(value.upstreamId);
    if (value.action === 'health') {
      if (!['healthy', 'unhealthy'].includes(value.state)) throw invalid();
      return { kind: 'target', action: 'health', upstreamId, targetId: id(value.targetId), state: value.state };
    }
    const payload = body(value.body, true);
    return value.action === 'create' ? { kind: 'target', action: 'create', upstreamId, body: payload }
      : { kind: 'target', action: 'weight', upstreamId, targetId: id(value.targetId), body: payload };
  }
  if (value.kind === 'credential') {
    if (!['create', 'update'].includes(value.action)) throw invalid();
    fields(value, ['kind', 'action', 'consumerId', 'credentialKind', ...(value.action === 'update' ? ['credentialId'] : []), 'body']);
    const consumerId = id(value.consumerId), kind = credentialKind(value.credentialKind), payload = body(value.body, value.action === 'create');
    return value.action === 'create' ? { kind: 'credential', action: 'create', consumerId, credentialKind: kind, body: payload }
      : { kind: 'credential', action: 'update', consumerId, credentialKind: kind, credentialId: id(value.credentialId), body: payload };
  }
  if (value.kind === 'recycle') {
    if (!['delete', 'restore'].includes(value.action)) throw invalid();
    fields(value, ['kind', 'action', 'confirmed', 'confirm_name', ...(value.action === 'restore' ? ['entryId'] : ['entityType', 'entityId', 'parentId', 'credentialKind'])]);
    if (value.confirmed !== true || typeof value.confirm_name !== 'string' || !value.confirm_name || value.confirm_name.length > 256) throw new BadRequestException({ code: 'CONFIRMATION_REQUIRED', message: '删除与恢复需要二次确认和准确对象名称' });
    if (value.action === 'restore') return { kind: 'recycle', action: 'restore', entryId: id(value.entryId), confirmed: true, confirm_name: value.confirm_name };
    const type = value.entityType === 'targets' || value.entityType === 'credentials' ? value.entityType : entityType(value.entityType);
    if ((type === 'targets' || type === 'credentials') !== (value.parentId !== undefined) || type === 'credentials' !== (value.credentialKind !== undefined)) throw invalid();
    return { kind: 'recycle', action: 'delete', entityType: type, entityId: id(value.entityId), confirmed: true, confirm_name: value.confirm_name,
      ...(value.parentId !== undefined ? { parentId: id(value.parentId) } : {}), ...(value.credentialKind !== undefined ? { credentialKind: credentialKind(value.credentialKind) } : {}) };
  }
  throw invalid();
}
export function entityChangeInput(input: unknown): EntityChangeInput {
  const value = objectBody(input);
  if (value.kind !== 'batch') return operation(value);
  fields(value, ['kind', 'operations', 'confirmed']);
  if (value.confirmed !== true) throw new BadRequestException({ code: 'CONFIRMATION_REQUIRED', message: '批量变更需要二次确认' });
  if (!Array.isArray(value.operations) || !value.operations.length || value.operations.length > 100) throw invalid();
  return { kind: 'batch', operations: value.operations.map(operation), confirmed: true };
}
