import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

export const M6_REFERENCE = join(tmpdir(), 'kongos-m6-runtime-secrets.json');
export function privateReference(path = M6_REFERENCE, required = false) {
  if (!existsSync(path)) {
    if (required) throw new Error('private M6 reference is required');
    return {};
  }
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600 || stat.uid !== process.getuid() || stat.size > 16 * 1024 * 1024) throw new Error('private M6 reference ownership, mode or size is invalid');
  const value = JSON.parse(readFileSync(path, 'utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('private M6 reference shape is invalid');
  return value;
}
