import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { inflateRawSync } from 'node:zlib';
import { pathToFileURL } from 'node:url';

function zipEntries(bytes) {
  const entries = [];
  // Read central-directory sizes because local headers can use data descriptors.
  for (let offset = 0; offset + 46 <= bytes.length; offset++) {
    if (bytes.readUInt32LE(offset) !== 0x02014b50) continue;
    const method = bytes.readUInt16LE(offset + 10);
    const size = bytes.readUInt32LE(offset + 20);
    const nameSize = bytes.readUInt16LE(offset + 28);
    const extraSize = bytes.readUInt16LE(offset + 30);
    const commentSize = bytes.readUInt16LE(offset + 32);
    const localOffset = bytes.readUInt32LE(offset + 42);
    if (offset + 46 + nameSize > bytes.length || localOffset + 30 > bytes.length) continue;
    const name = bytes.subarray(offset + 46, offset + 46 + nameSize).toString('utf8');
    const start = localOffset + 30 + bytes.readUInt16LE(localOffset + 26) + bytes.readUInt16LE(localOffset + 28);
    if (start + size > bytes.length) continue;
    const compressed = bytes.subarray(start, start + size);
    const payload = method === 8 ? inflateRawSync(compressed, { maxOutputLength: 25 * 1024 * 1024 }) : method === 0 ? compressed : null;
    if (payload) entries.push({ name, payload });
    offset += 45 + nameSize + extraSize + commentSize;
  }
  return entries;
}

function artifactFiles(directory) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = `${directory}/${entry.name}`;
    return entry.isDirectory() ? artifactFiles(path) : [path];
  });
}

export function findSecretArtifacts(secrets, additionalPaths = []) {
  const tokens = secrets.filter(Boolean).flatMap(value => [value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value)]).map(value => Buffer.from(value));
  const tracked = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
  const paths = [...new Set([...tracked, ...artifactFiles('artifacts'), ...additionalPaths])].filter(path => existsSync(path));
  const leaks = [];
  let embeddedFiles = 0;
  const contains = payload => tokens.some(token => payload.includes(token));
  for (const path of paths) {
    const bytes = readFileSync(path);
    if (contains(bytes)) leaks.push(path);
    const archives = [];
    if (path.endsWith('.zip')) archives.push(bytes);
    if (path.endsWith('.html')) {
      for (const match of bytes.toString('utf8').matchAll(/data:application\/zip;base64,([A-Za-z0-9+/=]+)/g)) archives.push(Buffer.from(match[1], 'base64'));
    }
    for (const archive of archives) {
      for (const { name, payload } of zipEntries(archive)) {
        embeddedFiles++;
        if (contains(payload)) leaks.push(`${path}::${name}`);
      }
    }
  }
  return { scannedFiles: paths.length, embeddedFiles, leaks };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (existsSync('.env')) process.loadEnvFile('.env');
  const values = Object.entries(process.env).filter(([key]) => /PASSWORD|APP_SECRET|ENCRYPTION_KEY/.test(key)).map(([, value]) => value);
  const result = findSecretArtifacts(values);
  await mkdir('artifacts/M0', { recursive: true });
  await writeFile('artifacts/M0/secret-artifact-scan.json', `${JSON.stringify({ performedAt: new Date().toISOString(), ...result }, null, 2)}\n`);
  console.log(JSON.stringify({ scannedFiles: result.scannedFiles, embeddedFiles: result.embeddedFiles, leaks: result.leaks }));
  if (result.leaks.length) process.exitCode = 1;
}
