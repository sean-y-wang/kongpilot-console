import { BadRequestException, ConflictException } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { workflowId, workflowKey } from '../workflows/workflow-validation';
export { workflowId as portalId, workflowKey as portalKey };
export function portalObject(value: unknown, allowed?: string[], maximum = 2 * 1024 * 1024): Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Buffer.byteLength(JSON.stringify(value)) > maximum) throw new BadRequestException({ code: 'INVALID_PORTAL_BODY' });
  const visit = (entry: any, depth = 0): void => { if (depth > 32) throw new BadRequestException({ code: 'PORTAL_DEPTH_LIMIT' }); if (entry && typeof entry === 'object') for (const [key, child] of Object.entries(entry)) { if (['__proto__', 'constructor', 'prototype'].includes(key)) throw new BadRequestException({ code: 'INVALID_OBJECT_KEY' }); visit(child, depth + 1); } };
  visit(value);
  if (allowed && Object.keys(value).some(key => !allowed.includes(key))) throw new BadRequestException({ code: 'UNKNOWN_PORTAL_FIELD' });
  return structuredClone(value) as Record<string, any>;
}
export function portalText(value: unknown, maximum: number, required = true): string {
  if (value === undefined && !required) return '';
  if (typeof value !== 'string' || value.length > maximum || required && !value.trim() || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) throw new BadRequestException({ code: 'INVALID_PORTAL_TEXT' }); return value.trim();
}
export function portalRevision(value: unknown): number { if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) throw new BadRequestException({ code: 'INVALID_PORTAL_REVISION' }); return value; }
export function portalConfirm(body: any, name: string): void { if (body.confirmed !== true || body.confirm_name !== name) throw new BadRequestException({ code: 'CONFIRMATION_REQUIRED', message: '请二次确认并输入对象名称' }); }
export function requirePortalCas(count: number): void { if (count !== 1) throw new ConflictException({ code: 'REVISION_CONFLICT', message: '对象已变化，请核验原回执并刷新' }); }
export class PortalCursor {
  private sign(value: string): Buffer { return createHmac('sha256', process.env.CURSOR_SIGNING_KEY || process.env.APP_SECRET || '').update(value).digest(); }
  encode(binding: string, after: unknown): string { const data = Buffer.from(JSON.stringify({ binding, after, expiry: Date.now() + 900000 })).toString('base64url'); return data + '.' + this.sign(data).toString('base64url'); }
  decode(value: unknown, binding: string): any {
    if (value === undefined) return null;
    if (typeof value !== 'string' || value.length > 8192) throw new BadRequestException({ code: 'INVALID_CURSOR' });
    try { const [data, signature, extra] = value.split('.'), supplied = Buffer.from(signature, 'base64url'), actual = this.sign(data); if (extra || supplied.length !== actual.length || !timingSafeEqual(supplied, actual)) throw new Error(); const decoded = JSON.parse(Buffer.from(data, 'base64url').toString()); if (decoded.binding !== binding || decoded.expiry <= Date.now()) throw new Error(); return decoded.after; } catch { throw new BadRequestException({ code: 'INVALID_CURSOR' }); }
  }
}
