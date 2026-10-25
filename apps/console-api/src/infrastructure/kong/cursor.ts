import { BadRequestException } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';

type CursorData = { clusterId: string; path: string; query: Record<string, string | number>; offset: string; expires: number; subject?: string };

function secret(): string {
  const value = process.env.CURSOR_SIGNING_KEY || process.env.APP_SECRET;
  if (!value || value.length < 32) throw new Error('CURSOR_SIGNING_KEY or APP_SECRET must contain at least 32 characters');
  return value;
}
function canonical(query: Record<string, string | number>): string { return JSON.stringify(Object.fromEntries(Object.entries(query).filter(([key]) => key !== 'offset').sort(([a], [b]) => a.localeCompare(b)))); }

export function signCursor(data: Omit<CursorData, 'expires'>): string {
  const encoded = Buffer.from(JSON.stringify({ ...data, expires: Date.now() + 30 * 60 * 1000 })).toString('base64url');
  return `${encoded}.${createHmac('sha256', secret()).update(encoded).digest('base64url')}`;
}

export function readCursor(token: string, clusterId: string, path: string, query: Record<string, string | number>, subject?: string): string {
  try {
    const [encoded, signature, extra] = token.split('.');
    if (extra || !encoded || !signature || token.length > 16384) throw new Error('invalid cursor');
    const expected = createHmac('sha256', secret()).update(encoded).digest();
    const actual = Buffer.from(signature, 'base64url');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error('invalid signature');
    const data: CursorData = JSON.parse(Buffer.from(encoded, 'base64url').toString());
    if (data.clusterId !== clusterId || data.path !== path || data.expires < Date.now() || canonical(data.query) !== canonical(query) || data.subject !== subject || typeof data.offset !== 'string') throw new Error('invalid scope');
    return data.offset;
  } catch { throw new BadRequestException({ code: 'INVALID_CURSOR', message: '分页游标无效、已过期或属于其他查询' }); }
}
