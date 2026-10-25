import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { collectEnvironmentSecrets } from './collect-environment-secrets.mjs';

// Offline regression: transient random values never enter output or artifacts.
const password = randomBytes(24).toString('hex');
const appSecret = randomBytes(32).toString('hex');
const portalSecret = randomBytes(32).toString('hex');
const encryption = randomBytes(32).toString('hex');
const bind = randomBytes(24).toString('base64url');
const client = randomBytes(24).toString('base64url');
const clientId = 'offline/client';
const providers = [{ type: 'ldap', bind_password: bind }, { type: 'oidc', client_id: clientId, client_secret: client }];
const values = collectEnvironmentSecrets({ CONSOLE_APP_PASSWORD: password, APP_SECRET: appSecret, PORTAL_SECRET: portalSecret, CONSOLE_ENCRYPTION_KEY: encryption,
  AUTH_PROVIDERS_JSON: JSON.stringify(providers), PUBLIC_ORIGINS: 'https://console.example.test' });
const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(client)}`).toString('base64');
function rejects(value) {
  try { collectEnvironmentSecrets({ AUTH_PROVIDERS_JSON: value }); return false; }
  catch (error) { return error.message === 'INVALID_PROVIDER_CONFIGURATION_FOR_SECRET_SCAN'; }
}
const checks = [
  ['primary deployment password included', values.includes(password)],
  ['session secret included', values.includes(appSecret)],
  ['independent Portal signing secret included', values.includes(portalSecret)],
  ['encryption key included', values.includes(encryption)],
  ['nested LDAP bind password included', values.includes(bind)],
  ['nested OIDC client secret included', values.includes(client)],
  ['encoded OIDC HTTP Basic credential included', values.includes(basic)],
  ['public origin is not treated as a credential', !values.includes('https://console.example.test')],
  ['duplicate deployment values deduplicated', collectEnvironmentSecrets({ FIRST_PASSWORD: password, SECOND_PASSWORD: password }).length === 1],
  ['disabled providers accepted', collectEnvironmentSecrets({ AUTH_PROVIDERS_JSON: '[]' }).length === 0],
  ['malformed provider JSON fails closed', rejects('{')],
  ['non-list provider configuration fails closed', rejects('{}')],
  ['invalid provider entries fail closed', rejects('[null]')],
].map(([name, passed]) => ({ name, passed: Boolean(passed) }));
const result = { checkedAt: new Date().toISOString(), validation: 'offline-random-secret-collection', secretValuesRecorded: false,
  allPassed: checks.every(check => check.passed), checks };
const stage=process.argv[2]||'M4';
if(!/^M(?:[0-9]|1[01])$/.test(stage)){console.error('ENVIRONMENT_SECRET_COLLECTION_STAGE_INVALID');process.exit(2);}
mkdirSync(`artifacts/${stage}`, { recursive: true });
writeFileSync(`artifacts/${stage}/environment-secret-collection.json`, JSON.stringify({...result,stage}, null, 2) + '\n');
console.log(`${checks.filter(check => check.passed).length}/${checks.length} offline environment secret collection checks passed; no values recorded.`);
if (!result.allPassed) process.exitCode = 1;
