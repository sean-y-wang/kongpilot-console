import { randomBytes } from 'node:crypto';
import { lstatSync, openSync, closeSync, constants, fstatSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function generatePortalAcceptanceEnvironment(path = '.env.portal-acceptance') {
  const target = resolve(path), parent = lstatSync(dirname(target));
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid?.() || (parent.mode & 0o022) !== 0) throw new Error('PORTAL_ACCEPTANCE_ENV_PARENT_INVALID');
  const fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    const metadata = fstatSync(fd);
    if (!metadata.isFile() || metadata.uid !== process.getuid?.() || (metadata.mode & 0o777) !== 0o600 || metadata.nlink !== 1) throw new Error('PORTAL_ACCEPTANCE_ENV_FILE_INVALID');
    writeFileSync(fd, `KONG_PORTAL_DATABASE_PASSWORD=${randomBytes(32).toString('hex')}\n`);
  } finally { closeSync(fd); }
  return { path: target, mode: '0600', overwritten: false, existingMaterialsModified: false };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length > 3) throw new Error('PORTAL_ACCEPTANCE_ENV_ARGUMENTS_INVALID');
    const result = generatePortalAcceptanceEnvironment(process.argv[2]);
    console.log(JSON.stringify(result));
  } catch { console.error('PORTAL_ACCEPTANCE_ENV_GENERATION_FAILED; no credential values recorded.'); process.exitCode = 1; }
}
