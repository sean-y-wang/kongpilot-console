import { BadRequestException } from '@nestjs/common';

function fieldsOf(schema: any): Record<string, any> | null {
  if (!schema?.fields) return null;
  if (!Array.isArray(schema.fields)) return schema.fields;
  return Object.assign(Object.create(null), ...schema.fields);
}

/** Reject unknown fields at every record level. Kong remains authoritative for value validation. */
export function validateKnownFields(value: any, schema: any, path = ''): void {
  if (value == null) return;
  const fields = fieldsOf(schema);
  if (fields && value && typeof value === 'object' && !Array.isArray(value)) {
    const errors: Record<string, string> = Object.create(null);
    for (const [name, entry] of Object.entries(value)) {
      const fieldPath = path ? `${path}.${name}` : name;
      if (!Object.hasOwn(fields, name)) errors[fieldPath] = '当前 Kong 版本不支持此字段';
      else validateKnownFields(entry, fields[name], fieldPath);
    }
    if (Object.keys(errors).length) throw new BadRequestException({ code: 'KONG_UNKNOWN_FIELD', message: '配置包含当前 Kong 版本不支持的字段', fields: errors });
  } else if (['array', 'set'].includes(schema?.type) && Array.isArray(value)) {
    value.forEach((entry, i) => validateKnownFields(entry, schema.elements, `${path}[${i}]`));
  } else if (schema?.type === 'map' && value && typeof value === 'object') {
    Object.entries(value).forEach(([name, entry]) => validateKnownFields(entry, schema.values, `${path}.${name}`));
  } else if (schema?.type === 'foreign' && value && typeof value === 'object' && !Array.isArray(value)) {
    if (Object.keys(value).some(key => key !== 'id')) throw new BadRequestException({ code: 'KONG_UNKNOWN_FIELD', message: '实体引用仅接受 id', fields: { [path]: '仅接受 { id } 引用' } });
  }
}

export function flattenKongFields(fields: any, path = '', result: Record<string, string> = Object.create(null)): Record<string, string> {
  if (fields == null) return result;
  if (typeof fields === 'string') result[path || '_'] = fields;
  else if (Array.isArray(fields)) fields.forEach((entry, i) => flattenKongFields(entry, `${path}[${i}]`, result));
  else if (typeof fields === 'object') Object.entries(fields).forEach(([key, entry]) => flattenKongFields(entry, path ? `${path}.${key}` : key, result));
  else result[path || '_'] = String(fields);
  return result;
}
