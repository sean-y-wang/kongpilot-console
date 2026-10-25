import { BadRequestException } from '@nestjs/common';
import type { AuthUser } from '../../common/auth';
import { ENTITIES } from '../../infrastructure/kong/policy';

export type EntityType = typeof ENTITIES[number];
export const CREDENTIAL_KINDS = ['key-auth', 'basic-auth', 'jwt', 'oauth2', 'hmac-auth', 'acls'] as const;
export type CredentialKind = typeof CREDENTIAL_KINDS[number];
export const CREDENTIAL_SCHEMAS: Record<CredentialKind, string> = { 'key-auth': 'keyauth_credentials', 'basic-auth': 'basicauth_credentials', jwt: 'jwt_secrets', oauth2: 'oauth2_credentials', 'hmac-auth': 'hmacauth_credentials', acls: 'acls' };
export type EntityActor = { user: AuthUser; requestId?: string; ip?: string; idempotencyKey?: string; workspaceId?: string };
export type ListQuery = { size?: string | number; cursor?: string; tags?: string; workspaceId?: string; search?: string; sort?: string; reveal?: string | boolean };

export function entityType(value: string): EntityType {
  if (!(ENTITIES as readonly string[]).includes(value)) throw new BadRequestException({ code: 'UNKNOWN_ENTITY_TYPE', message: '不支持的 Kong 实体类型' });
  return value as EntityType;
}
export function credentialKind(value: string): CredentialKind {
  if (!(CREDENTIAL_KINDS as readonly string[]).includes(value)) throw new BadRequestException({ code: 'UNKNOWN_CREDENTIAL_TYPE', message: '不支持的凭证类型' });
  return value as CredentialKind;
}
export function identifier(value: string): string {
  if (typeof value !== 'string' || !value.length || value.length > 256 || /[%\/\\\u0000-\u001f]/.test(value) || value === '.' || value === '..') throw new BadRequestException({ code: 'INVALID_ENTITY_ID', message: '实体标识无效' });
  return encodeURIComponent(value);
}
export function pageSize(value: unknown): number {
  const size = value === undefined ? 20 : Number(value);
  if (!Number.isInteger(size) || size < 1 || size > 100) throw new BadRequestException({ code: 'INVALID_PAGE_SIZE', message: '每页大小必须在 1–100 之间' });
  return size;
}
export function objectBody(value: unknown): Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new BadRequestException({ code: 'INVALID_BODY', message: '配置必须为 JSON 对象' });
  if (Buffer.byteLength(JSON.stringify(value)) > 2 * 1024 * 1024) throw new BadRequestException({ code: 'BODY_TOO_LARGE', message: '实体配置超过 2 MiB 限制' });
  const check = (entry: unknown, depth = 0): void => {
    if (depth > 50) throw new BadRequestException({ code: 'BODY_TOO_DEEP', message: '配置嵌套超过 50 层' });
    if (!entry || typeof entry !== 'object') return;
    for (const [name, child] of Object.entries(entry)) {
      if (['__proto__', 'prototype', 'constructor'].includes(name)) throw new BadRequestException({ code: 'INVALID_OBJECT_KEY', message: '配置包含保留的对象属性名' });
      check(child, depth + 1);
    }
  };
  check(value);
  return structuredClone(value) as Record<string, any>;
}
export function confirmed(body: unknown, entity: any): boolean {
  const value = objectBody(body);
  const expected = String(entity.name || entity.username || entity.target || entity.client_id || entity.id);
  if (value.confirmed !== true || value.confirm_name !== expected) throw new BadRequestException({ code: 'CONFIRMATION_REQUIRED', message: `请二次确认并输入 ${expected}` });
  return true;
}
