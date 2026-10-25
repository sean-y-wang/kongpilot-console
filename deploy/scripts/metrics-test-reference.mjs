import { existsSync, lstatSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

export const testReferencePath = '/tmp/kongos-m5-runtime-secrets.json';
export function readTestReference(path = testReferencePath) {
  if (!existsSync(path)) return { tokens: [], secrets: [], users: [] };
  const stat = lstatSync(path);
  if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || stat.uid !== process.getuid?.() || stat.size > 512 * 1024) throw new Error('METRICS_TEST_REFERENCE_UNSAFE');
  const value = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(value.tokens) || !Array.isArray(value.secrets) || value.tokens.length > 4096 || value.secrets.length > 4096) throw new Error('METRICS_TEST_REFERENCE_INVALID');
  return value;
}
export function captureTestMaterial(material, path = testReferencePath) {
  const value = readTestReference(path);
  for (const row of material.enrollment.credentials) {
    value.tokens.push({ clusterId: material.enrollment.clusterId, generation: material.enrollment.generation, ...row });
    value.secrets.push(row.token);
  }
  value.secrets = [...new Set(value.secrets)];
  const temporary = `${path}.${randomUUID()}.pending`;
  writeFileSync(temporary, JSON.stringify(value), { flag: 'wx', mode: 0o600 });
  renameSync(temporary, path);
}
