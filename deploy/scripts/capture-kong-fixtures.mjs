import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createFixtureSanitizer } from './fixture-sanitization.mjs';

if (existsSync('.env')) process.loadEnvFile('.env');
const { sanitizeBody, sanitizeSchema } = createFixtureSanitizer();
// KONG_FIXTURE_VERSION selects the expected release (default 1.5.1).
// KONG_FIXTURE_ADMIN_URL records directly from a throwaway local Kong
// container (loopback only); never point it at a shared/real gateway.
const expectedVersion = process.env.KONG_FIXTURE_VERSION || '1.5.1';
const directAdmin = process.env.KONG_FIXTURE_ADMIN_URL;
if (directAdmin && !/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?\/?$/.test(directAdmin)) throw new Error('KONG_FIXTURE_ADMIN_URL must be a loopback throwaway Kong');
const destination = resolve(`tests/fixtures/kong-${expectedVersion}`);
mkdirSync(destination, { recursive: true });
async function directRequest(path) {
  const r = await fetch(directAdmin.replace(/\/$/, '') + path, { redirect: 'manual', signal: AbortSignal.timeout(10000) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error('Fixture read failed; response body suppressed');
  return r.json();
}
function request(path) {
  // Admin ACL permits the BFF management source, including trusted offline tests.
  // Raw JSON stays inside this recorder and is sanitized before any file is written.
  const code = "(async()=>{const p=process.argv[1];const r=await fetch(process.env.DEFAULT_KONG_ADMIN_URL.replace(/\\/$/,'')+p,{redirect:'manual',signal:AbortSignal.timeout(10000)});if(!r.ok)process.exit(2);console.log(JSON.stringify(await r.json()));})().catch(()=>process.exit(3));";
  try {
    return JSON.parse(execFileSync('docker', ['compose', 'exec', '-T', 'console-api', 'node', '-e', code, path], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  } catch {
    throw new Error('Fixture read failed through the BFF management network; response body suppressed');
  }
}
const recorded = [];
async function capture(path, filename, optional = false) {
  const body = directAdmin ? await directRequest(path) : request(path);
  if (body === null) { if (optional) return null; throw new Error(`Missing ${path}`); }
  const safe = path.startsWith('/schemas/') || path.startsWith('/plugins/schema/') ? sanitizeSchema(body) : sanitizeBody(body);
  writeFileSync(resolve(destination, filename), JSON.stringify(safe, null, 2) + '\n');
  recorded.push({ path, filename, source: `real Kong OSS ${expectedVersion} Docker image`, recordedAt: new Date().toISOString() });
  return body;
}
const root = await capture('/', 'root.json');
if (root.version !== expectedVersion) throw new Error(`Unexpected Kong version ${root.version}`);
await capture('/status', 'status.json');
await capture('/endpoints', 'endpoints.json', true);
const plugins = await capture('/plugins/enabled', 'plugins-enabled.json');
for (const entity of ['services', 'routes', 'consumers', 'plugins', 'certificates', 'ca_certificates', 'snis', 'upstreams']) {
  await capture(`/schemas/${entity}`, `schema-${entity}.json`);
  await capture(`/${entity}?size=2`, `list-${entity}-empty.json`);
}
for (const plugin of plugins.enabled_plugins) await capture(`/plugins/schema/${plugin}`, `plugin-schema-${plugin}.json`);
writeFileSync(resolve(destination, 'manifest.json'), JSON.stringify({ version: root.version, schemaSecretDefaultsRemoved: true, allResponseBodiesRedacted: true, sanitizer: 'compiled BFF SecretService/schema-secrets', recorded }, null, 2) + '\n');
console.log(`Recorded ${recorded.length} real Kong ${root.version} fixtures; sensitive configuration and schema defaults removed.`);
