import { z } from 'zod';
import { connectionAuthSchema } from '../clusters/cluster.dto';

const fields = { name: z.string().trim().min(1).max(128), type: z.enum(['prometheus', 'loki']), base_url: z.string().trim().url().max(2048), auth: connectionAuthSchema.nullable(), enabled: z.boolean() };
export const createDataSourceSchema = z.object({ ...fields, auth: fields.auth.optional(), enabled: fields.enabled.default(true) }).strict();
export const updateDataSourceSchema = z.object(fields).partial().extend({ revision: z.number().int().positive() }).strict().refine(v => Object.keys(v).length > 1, '请至少提交一个修改字段');
