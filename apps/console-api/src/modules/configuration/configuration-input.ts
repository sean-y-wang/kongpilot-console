import { BadRequestException } from '@nestjs/common';
import type { ConfigurationScopeKind } from './configuration.types';

export const CONFIGURATION_UUID = /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i;
export const CONFIGURATION_HEX = /^[a-f\d]{64}$/;
const invalid = (code = 'INVALID_CONFIGURATION_INPUT') => new BadRequestException({code, message: '配置操作参数无效，请重新核对'});
export function configurationId(value: unknown): string {
  if (typeof value !== 'string' || !CONFIGURATION_UUID.test(value)) throw invalid('INVALID_CONFIGURATION_ID');
  return value.toLowerCase();
}
export function configurationKey(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z\d._:-]{8,128}$/.test(value)) throw invalid('IDEMPOTENCY_KEY_REQUIRED');
  return value;
}
export function configurationObject(value: unknown, allowed: readonly string[]): Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.keys(value).some(k => !allowed.includes(k))) throw invalid();
  return value as Record<string, any>;
}
export function configurationScopeInput(value: Record<string, any>): {kind: ConfigurationScopeKind; rootIds: string[]} {
  const kind = value.scope ?? 'workspace';
  if (!['cluster', 'workspace', 'services'].includes(kind)) throw invalid('INVALID_CONFIGURATION_SCOPE');
  const roots = value.serviceIds ?? [];
  if (!Array.isArray(roots) || roots.length > 100 || (kind === 'services') !== (roots.length > 0)) throw invalid('INVALID_CONFIGURATION_SCOPE');
  const rootIds = roots.map(configurationId);
  if (new Set(rootIds).size !== rootIds.length) throw invalid('DUPLICATE_CONFIGURATION_ROOT');
  return {kind, rootIds};
}
export function configurationConfirm(value: Record<string, any>, name: string, deletes = false): void {
  if (value.confirmed !== true || value.confirm_name !== name || deletes && value.confirm_deletes !== true)
    throw invalid('CONFIRMATION_REQUIRED');
}
export function configurationPage(value: Record<string, unknown>): {size: number; cursor?: string} {
  const size = value.size === undefined ? 20 : Number(value.size);
  if (!Number.isInteger(size) || size < 1 || size > 100 || value.cursor !== undefined && (typeof value.cursor !== 'string' || value.cursor.length > 4096))
    throw invalid('INVALID_CONFIGURATION_PAGE');
  return {size, ...(value.cursor ? {cursor: value.cursor as string} : {})};
}
export function safeConfigurationError(error: unknown): string {
  const response = error && typeof error === 'object' && 'getResponse' in error && typeof error.getResponse === 'function' ? error.getResponse() : null;
  const code = response && typeof response === 'object' && 'code' in response ? response.code : error && typeof error === 'object' && 'code' in error ? error.code : null;
  return typeof code === 'string' && /^[A-Z\d_]{1,128}$/.test(code) ? code : 'CONFIGURATION_OPERATION_FAILED';
}
