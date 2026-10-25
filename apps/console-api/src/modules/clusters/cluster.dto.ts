import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

export const connectionAuthSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('none') }).strict(),
  z.object({ type: z.literal('bearer'), token: z.string().min(1).max(8192).refine(v => !/[\r\n]/.test(v)) }).strict(),
  z.object({ type: z.literal('basic'), username: z.string().min(1).max(256).refine(v => !/[:\r\n]/.test(v)), password: z.string().min(1).max(8192).refine(v => !/[\r\n]/.test(v)) }).strict(),
  z.object({ type: z.literal('header'), header_name: z.string().regex(/^[A-Za-z0-9-]{1,128}$/), header_value: z.string().min(1).max(8192).refine(v => !/[\r\n]/.test(v)) }).strict(),
]);
const fields = {
  name: z.string().trim().min(1).max(128), environment: z.string().trim().min(1).max(64),
  admin_url: z.string().trim().url().max(2048), labels: z.array(z.string().min(1).max(128)).max(50),
  execution_mode: z.enum(['direct', 'approval']), connection_auth: connectionAuthSchema.nullable(),
  proxy_origin: z.string().trim().url().max(2048).nullable().optional(),
};
export const createClusterSchema = z.object({ ...fields, environment: fields.environment.default('default'), labels: fields.labels.default([]), execution_mode: fields.execution_mode.default('direct'), connection_auth: fields.connection_auth.optional() }).strict();
export const updateClusterSchema = z.object(fields).partial().extend({ revision: z.number().int().positive() }).strict().refine(v => Object.keys(v).length > 1, '请至少提交一个修改字段');
export const deactivateSchema = z.object({ confirm: z.literal(true), confirm_name: z.string().min(1), revision: z.number().int().positive() }).strict();

export function parseDto<T>(schema: z.ZodType<T>, body: unknown): T {
  const result = schema.safeParse(body);
  if (!result.success) throw new BadRequestException({ code: 'VALIDATION_ERROR', message: '请求字段校验失败', fields: Object.fromEntries(result.error.issues.map(issue => [issue.path.join('.') || '_', issue.message])) });
  return result.data;
}
