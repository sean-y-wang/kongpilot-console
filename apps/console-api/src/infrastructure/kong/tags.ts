import { BadRequestException } from '@nestjs/common';

const SAFE_TAG = /^[a-zA-Z0-9._~-]+$/;

export function workspaceTag(code: string): string {
  if (!/^[a-z][a-z0-9_-]{0,47}$/.test(code)) {
    throw new BadRequestException({ code: 'INVALID_WORKSPACE_CODE', message: '工作区编码须为小写字母开头的字母、数字、下划线或连字符，最多 48 位' });
  }
  return `kos-ws-${code}`;
}

/** Kong 1.5 tag characters cannot contain ':'. Reserved physical prefixes never collide with user tags. */
export function encodeTag(logical: string): string {
  if (typeof logical !== 'string' || !logical.length) throw new BadRequestException({ code: 'INVALID_TAG', message: '标签不能为空' });
  if (logical.startsWith('workspace:')) return workspaceTag(logical.slice(10));
  if (SAFE_TAG.test(logical) && !logical.startsWith('kos-ws-') && !logical.startsWith('kos-tag-')) return logical;
  const value = `kos-tag-${Buffer.from(logical, 'utf8').toString('base64url')}`;
  if (value.length > 128) throw new BadRequestException({ code: 'INVALID_TAG', message: '标签编码后超过 128 字符' });
  return value;
}

export function decodeTag(physical: string): string {
  if (physical.startsWith('kos-ws-')) return `workspace:${physical.slice(7)}`;
  if (physical.startsWith('kos-tag-')) {
    const encoded = physical.slice(8);
    const decoded = Buffer.from(encoded, 'base64url').toString('utf8');
    if (Buffer.from(decoded, 'utf8').toString('base64url') === encoded) return decoded;
  }
  return physical;
}
