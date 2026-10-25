import { ApiError } from './client';

export function connectionAddressFields(field: 'admin_url' | 'base_url', value: unknown, editing: boolean): Partial<Record<'admin_url' | 'base_url', string>> {
  const address = typeof value === 'string' ? value.trim() : '';
  if (address) return { [field]: address };
  if (editing) return {};
  throw new ApiError('新增连接必须提供地址。', 400, 'CONNECTION_ADDRESS_REQUIRED', { [field]: '请输入连接地址' });
}
